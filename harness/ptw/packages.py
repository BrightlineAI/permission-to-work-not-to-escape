"""Brokered package installs share policy, identity and escalation with file controls."""
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
import time
import concurrent.futures
import tarfile

from .package_evidence import EvidenceError, PyPIEvidence, evaluate, pins, severity
from .package_install import file_manifest, install_wheels, target_environment, validate_wheels
from .policy import Invalid, OutsideScope, canonical, digest


def mounted_set(store, db, actor, identity, *, definition=None, snapshot=None, assessment=True):
    if not isinstance(identity, str) or not re.fullmatch(r"pkg_[0-9a-f]{24}", identity):
        raise OutsideScope("Invalid package set identity")
    row = db.execute("SELECT * FROM package_sets WHERE id=? AND project=?", (identity, actor["project"])).fetchone()
    if row is None or not set(json.loads(row["names"])) <= set(json.loads(actor["packages"])):
        raise OutsideScope("Package set outside session scope")
    _, bundle = store.project(db, actor['project'])
    from .dependency_binding import verify_inputs
    verify_inputs(bundle)
    if row['ecosystem'] == 'npm':
        from .dependency_binding import verify_local_sources
        verify_local_sources(bundle, actor, definition)
    if row['local_source'] is not None:
        from .python_local import receipt_sources, reuse_source, verify_native_reuse
        from .workspace import scan
        receipt = json.loads(row['local_source'])
        from .python_lock import verify_source_lock
        parts = receipt_sources(receipt)
        if len(parts) > 1 and [p['source_id'] for p in parts] != [
                s['id'] for s in bundle['policy']['project']['python_dependencies'].get('sources', [])]:
            raise Invalid('Combined installation source bindings differ from review')
        for part in parts:
            source = reuse_source(bundle, actor, part['source_id'], definition, snapshot)
            verify_source_lock(bundle, source, part)
            current = scan(bundle['inventory'], source['resources'])
            reuse_source(bundle, actor, part['source_id'], definition, current)
            verify_native_reuse(bundle, source, part, snapshot)
            verify_native_reuse(bundle, source, part, current)
    if row['policy_sha256'] is not None and row['policy_sha256'] != bundle['approval']['sha256']:
        raise Invalid('Package set belongs to an obsolete policy revision')
    runtime = bundle['policy']['project'].get('python_runtime')
    if runtime:
        from .python_runtime import verify
        verify(runtime)
        if row['policy_sha256'] is None:
            raise Invalid('Legacy package set lacks reviewed runtime binding; install again')
    directory = store.directory / "package-sets" / identity
    if file_manifest(directory) != json.loads(row["manifest"]):
        raise Invalid("Package set integrity check failed")
    if assessment:
        from .reassessment import cached
        cached(row, bundle['policy']['project']['packages'])
    return directory


class PackageControl:
    def __init__(self, store, *, provider=None):
        self.store = store
        # Dependency injection is for tests, not a CLI flag or agent-supplied setting.
        self.provider = provider

    def install(self, token, event, specs, *, ecosystem="pypi"):
        if not isinstance(event, str) or not 1 <= len(event) <= 128:
            raise Invalid("Stable event ID required, 1 to 128 characters")
        if ecosystem not in ("pypi", "npm"):
            raise Invalid("Supported registries are pypi and npm")
        plan, extras = None, {}
        if ecosystem == "npm":
            from .npm import installation_plan
            plan = installation_plan(specs)
            from .dependency_binding import verify_npm
            with self.store.locked() as db:
                actor = self.store.session(db, token)
                _, bundle = self.store.project(db, actor['project'])
                verify_npm(bundle, specs)
            selected = plan.selected
            request_lock = plan.original_lock if specs.get('manager') in ('pnpm', 'yarn') else plan.lock
        else:
            selected = pins(specs, extras=extras)
        request = {"action": "package_install", "resource": ecosystem,
                   "content": canonical(request_lock if plan else {"pins": selected, "extras": extras} if extras else selected)}
        request_hash = digest(request)
        try:
            with self.store.operation(token, event):
                return self._install(token, event, selected, request, request_hash, plan=plan, extras=extras)
        finally:
            from .supervisor import Supervisor
            Supervisor(self.store).reconcile()

    def inspect(self, db, token, event, selected, request, request_hash):
        actor = self.store.session(db, token)
        project, bundle = self.store.project(db, actor["project"])
        prior = db.execute("SELECT * FROM events WHERE session=? AND event=?", (actor["id"], event)).fetchone()
        if prior and prior['state'] == 'pending' and self.store.owns_pending(actor['id'], event):
            if prior['request_hash'] != request_hash:
                raise Invalid('Package operation request changed')
            prior = None
        if prior:
            if prior["request_hash"] != request_hash:
                raise Invalid("Event ID reused with different request")
            response = (json.loads(prior["response"]) if prior["state"] == "complete" else
                        {"allowed": False, "effect": "unknown", "level": "stop", "reason": "Interrupted package publication"})
            if response.get('allowed') and response.get('package_set'):
                try:
                    mounted_set(self.store, db, actor, response['package_set'])
                except Invalid as exc:
                    response = {'allowed': False, 'effect': 'none', 'level': 'blocked',
                                'reason': str(exc), 'violation_counted': False}
            return actor, project, bundle, {**response, "replayed": True}
        if project["stopped"]:
            response = {"allowed": False, "effect": "none", "level": "stop", "reason": "project stopped"}
            self.store.record(db, actor["id"], event, request_hash, request, response)
            return actor, project, bundle, response
        names = self.scope_names(selected, request["resource"], bundle["policy"]["version"])
        if request['resource'] == 'npm':
            from .dependency_binding import verify_local_sources
            try:
                verify_local_sources(bundle, actor)
            except OutsideScope as exc:
                response = self.store.deny(db, actor, project, bundle, event, request_hash, request, str(exc))
                return actor, project, bundle, response
        if (not bundle["policy"]["project"].get("packages") or
                (request["resource"] == "npm" and bundle["policy"]["version"] < 3) or
                not names <= set(json.loads(actor["packages"]))):
            response = self.store.deny(db, actor, project, bundle, event, request_hash, request,
                                       "Package installation outside project, task or delegated scope")
            return actor, project, bundle, response
        return actor, project, bundle, None

    @staticmethod
    def scope_names(selected, ecosystem, version):
        names = {x.rsplit("@", 1)[0] for x in selected} if ecosystem == "npm" else set(selected)
        return {ecosystem + ":" + x for x in names} if version >= 3 else names

    def _install(self, token, event, selected, request, request_hash, plan=None, extras=None):
        with self.store.locked() as db:
            _, _, bundle, result = self.inspect(db, token, event, selected, request, request_hash)
            if result is not None:
                return result
        rules = bundle["policy"]["project"]["packages"]
        from .dependency_binding import verify_artifacts, verify_inputs, verify_selection
        verify_inputs(bundle)
        if request['resource'] == 'pypi':
            verify_selection(bundle, selected, extras)
        runtime = bundle['policy']['project'].get('python_runtime')
        python = '/usr/bin/python3'
        if runtime:
            from .python_runtime import verify
            python = verify(runtime)
        extended = bundle["policy"]["version"] >= 3
        if extras and not extended:
            raise Invalid("Python extras require a reviewed version 3 policy")
        ecosystem = request["resource"]
        if ecosystem == "npm":
            from .registry import provider_for
            provider = self.provider or provider_for(self.store, bundle)
            from .yarn import YarnEvidence, YarnPlan
            if isinstance(plan, YarnPlan):
                provider = YarnEvidence(provider, plan)
        else:
            from .registry import provider_for
            provider = self.provider or provider_for(self.store, bundle, 'pypi')
        evidence, reasons, error, target = [], [], None, None
        # Durable preparation intent precedes registry/build effects. The lease
        # spans preparation; the controller lock remains free for stops.
        with self.store.locked() as db:
            actor, _, _, result = self.inspect(db, token, event, selected, request, request_hash)
            if result is not None:
                return result
            self.store.begin(db, actor['id'], event, request_hash, request)
        with tempfile.TemporaryDirectory(prefix="package-stage-", dir=self.store.directory) as temporary:
            staging = Path(temporary)
            try:
                def assess(pair):
                    name, version = pair
                    actual_name = name.rsplit("@", 1)[0] if plan else name
                    record = provider.assess(actual_name, version)
                    if record.get("name") != actual_name or record.get("version") != version:
                        raise EvidenceError("Evidence identity mismatch")
                    return record
                if extended:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                        records = list(pool.map(assess, selected.items()))
                else:
                    records = map(assess, selected.items())
                for record in records:
                    evidence.append(record)
                    reasons.extend(evaluate(record, rules))
                if not plan:
                    verify_artifacts(bundle, evidence)
                else:
                    from .dependency_binding import verify_npm
                    verify_npm(bundle, plan.original_lock, evidence)
                if not reasons:
                    wheelhouse = staging / "wheels"
                    wheelhouse.mkdir(mode=0o700)
                    wheels = {}
                    download_bytes = 0
                    for record in evidence:
                        filename = record["filename"]
                        if (not isinstance(filename, str) or Path(filename).name != filename or
                                not re.fullmatch(r"[A-Za-z0-9_.+-]+\.(?:whl|tgz|tar\.gz|zip)", filename)):
                            raise EvidenceError("Unsafe wheel filename")
                        destination = wheelhouse / filename
                        provider.download(record, destination)
                        download_bytes += destination.stat().st_size
                        if download_bytes > (512 if bundle["policy"]["version"] >= 3 else 100) * 1024 * 1024:
                            raise EvidenceError("Package set exceeds download size limit")
                        wheels[record["name"]] = destination
                    target = staging / "site"
                    if plan:
                        from .package_build import run_build
                        plan.install(wheelhouse, target, evidence,
                            {x[4:] for x in rules.get("build_packages", []) if x.startswith("npm:")},
                            lambda cmd: run_build(self.store, token, cmd, target))
                    else:
                        from .python_build import build_sources
                        if any(e.get("artifact_kind") == "sdist" and "pypi:" + e["name"] not in rules.get("build_packages", [])
                               for e in evidence):
                            raise EvidenceError("Python source build needs explicit policy authority")
                        install_evidence = build_sources(self.store, token, wheelhouse, evidence, selected,
                            allow_native=rules.get("allow_native_wheels", False), python=python)
                        wheels = {e["name"]: wheelhouse / e["filename"] for e in install_evidence}
                        validate_wheels(wheels, selected, environment=target_environment(python), extended=extended, extras=extras)
                        install_wheels(wheelhouse, target, install_evidence,
                                       **({'python': python} if runtime else {}), **({"extended": True} if extended else {}))
                    manifest = file_manifest(target)
            except (EvidenceError, OSError, ValueError, tarfile.TarError) as exc:
                error = str(exc)
            with self.store.locked() as db:
                actor, project, current, result = self.inspect(db, token, event, selected, request, request_hash)
                if result is not None:
                    return result
                if current['approval']['sha256'] != bundle['approval']['sha256']:
                    error = 'Policy changed during dependency preparation; retry under the current revision'
                try:
                    verify_inputs(current)
                except Invalid as exc:
                    error = str(exc)
                if runtime:
                    try:
                        verify(runtime)
                    except Invalid as exc:
                        error = str(exc)
                try:
                    reasons = [e["name"] + "==" + e["version"] + ": " + r
                               for e in evidence for r in evaluate(e, current["policy"]["project"]["packages"])]
                    from .reassessment import validate_publication
                    if not reasons:
                        validate_publication(db, actor['project'], ecosystem, evidence)
                except EvidenceError as exc:
                    error = str(exc)
                if error:
                    response = {"allowed": False, "effect": "none", "level": "blocked",
                                "reason": error, "violation_counted": False}
                    self.store.record(db, actor["id"], event, request_hash, request, response)
                    return response
                if reasons:
                    return self.store.deny(db, actor, project, current, event, request_hash, request,
                                           "; ".join(sorted(set(reasons))))
                if target is None or len(evidence) != len(selected):
                    raise Invalid("Incomplete installation cannot be published")
                identity = "pkg_" + secrets.token_hex(12)
                sets = self.store.directory / "package-sets"
                sets.mkdir(mode=0o700, exist_ok=True)
                self.store.begin(db, actor['id'], event, request_hash, request)
                try:
                    response = {"allowed": True, "effect": "installed", "level": "allow",
                                "package_set": identity, "packages": selected, "ecosystem": ecosystem,
                                "manifest_sha256": digest(manifest), "policy_sha256": current["approval"]["sha256"],
                                "evidence": [{**{k: e[k] for k in ("name", "version", "sha256", "published_at", "checked_at")},
                                    **({"built_wheel": e["built_wheel"]} if "built_wheel" in e else {}),
                                    "advisories": [{"id": v["id"], "cvss_base": severity(v),
                                                   "withdrawn": v.get("withdrawn")} for v in e["vulnerabilities"]]}
                                    for e in evidence]}
                    db.execute("BEGIN IMMEDIATE")
                    db.execute("INSERT INTO package_sets(id,project,names,manifest,created,ecosystem,policy_sha256) VALUES(?,?,?,?,?,?,?)",
                               (identity, actor["project"],
                                canonical(sorted(self.scope_names(selected, ecosystem, current["policy"]["version"]))),
                                canonical(manifest), time.time(), ecosystem, current['approval']['sha256']))
                    from .reassessment import seed
                    seed(db, identity, evidence, actor=actor)
                    # Keep the durable preparation intent outside this transaction.
                    # Account for the full package/assessment rows alongside its
                    # completion reservation before publishing filesystem effects.
                    from .evidence_storage import admit
                    admit(db, actor['project'], 0)
                    os.rename(target, sets / identity)
                    # Mounts are read only. Make accidental operator writes difficult too.
                    for path in (sets / identity).rglob("*"):
                        if not path.is_symlink():
                            path.chmod(0o555 if path.is_dir() or path.stat().st_mode & 0o111 else 0o444)
                    (sets / identity).chmod(0o555)
                    self.store.complete(db, actor['id'], event, response)
                    db.commit()
                    return response
                except Exception:
                    self.store.capture_fault(db, actor['project'])
                    # The operation's existing recovery marks uncertainty only
                    # after persisting the stop. A failed stop write must leave
                    # intent pending, not falsely report durable closure.
                    return {"allowed": False, "effect": "unknown", "level": "stop",
                            "reason": "Package publication failed; outcome uncertain; operator review required"}
