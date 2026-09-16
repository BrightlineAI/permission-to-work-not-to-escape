"""Brokered package installs share policy, identity and escalation with file controls."""
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
import time

from .package_evidence import EvidenceError, PyPIEvidence, evaluate, pins
from .package_install import file_manifest, install_wheels, validate_wheels
from .policy import Invalid, canonical, digest


def mounted_set(store, db, actor, identity):
    if not re.fullmatch(r"pkg_[0-9a-f]{24}", identity):
        raise Invalid("Invalid package set identity")
    row = db.execute("SELECT * FROM package_sets WHERE id=? AND project=?", (identity, actor["project"])).fetchone()
    if row is None or not set(json.loads(row["names"])) <= set(json.loads(actor["packages"])):
        raise Invalid("Package set outside session scope")
    directory = store.directory / "package-sets" / identity
    if file_manifest(directory) != json.loads(row["manifest"]):
        raise Invalid("Package set integrity check failed")
    return directory


class PackageControl:
    def __init__(self, store, *, provider=None):
        self.store = store
        # Dependency injection is for tests, not a CLI flag or agent-supplied setting.
        self.provider = provider if provider is not None else PyPIEvidence()

    def install(self, token, event, specs):
        if not isinstance(event, str) or not 1 <= len(event) <= 128:
            raise Invalid("Stable event ID required, 1 to 128 characters")
        selected = pins(specs)
        request = {"action": "package_install", "resource": "pypi", "content": canonical(selected)}
        request_hash = digest(request)
        try:
            return self._install(token, event, selected, request, request_hash)
        finally:
            from .supervisor import Supervisor
            Supervisor(self.store).reconcile()

    def inspect(self, db, token, event, selected, request, request_hash):
        actor = self.store.session(db, token)
        project, bundle = self.store.project(db, actor["project"])
        prior = db.execute("SELECT * FROM events WHERE session=? AND event=?", (actor["id"], event)).fetchone()
        if prior:
            if prior["request_hash"] != request_hash:
                raise Invalid("Event ID reused with different request")
            response = (json.loads(prior["response"]) if prior["state"] == "complete" else
                        {"allowed": False, "effect": "unknown", "level": "stop", "reason": "Interrupted package publication"})
            return actor, project, bundle, {**response, "replayed": True}
        if project["stopped"]:
            response = {"allowed": False, "effect": "none", "level": "stop", "reason": "project stopped"}
            self.store.record(db, actor["id"], event, request_hash, request, response)
            return actor, project, bundle, response
        if (not bundle["policy"]["project"].get("packages") or
                not set(selected) <= set(json.loads(actor["packages"]))):
            response = self.store.deny(db, actor, project, bundle, event, request_hash, request,
                                       "Package installation outside project, task or delegated scope")
            return actor, project, bundle, response
        return actor, project, bundle, None

    def _install(self, token, event, selected, request, request_hash):
        with self.store.locked() as db:
            _, _, bundle, result = self.inspect(db, token, event, selected, request, request_hash)
            if result is not None:
                return result
        rules = bundle["policy"]["project"]["packages"]
        evidence, reasons, error, target = [], [], None, None
        # Slow, fallible preparation holds neither the project lock nor a pending
        # effect. Concurrent stops can proceed, and no agent sees staging files.
        with tempfile.TemporaryDirectory(prefix="package-stage-", dir=self.store.directory) as temporary:
            staging = Path(temporary)
            try:
                for name, version in selected.items():
                    record = self.provider.assess(name, version)
                    if record.get("name") != name or record.get("version") != version:
                        raise EvidenceError("Evidence identity mismatch")
                    evidence.append(record)
                    reasons.extend(evaluate(record, rules))
                if not reasons:
                    wheelhouse = staging / "wheels"
                    wheelhouse.mkdir(mode=0o700)
                    wheels = {}
                    for record in evidence:
                        filename = record["filename"]
                        if (not isinstance(filename, str) or Path(filename).name != filename or
                                not re.fullmatch(r"[A-Za-z0-9_.+-]+\.whl", filename)):
                            raise EvidenceError("Unsafe wheel filename")
                        destination = wheelhouse / filename
                        self.provider.download(record, destination)
                        wheels[record["name"]] = destination
                    validate_wheels(wheels, selected)
                    target = staging / "site"
                    install_wheels(wheelhouse, target, evidence)
                    manifest = file_manifest(target)
            except (EvidenceError, OSError, ValueError) as exc:
                error = str(exc)
            with self.store.locked() as db:
                actor, project, current, result = self.inspect(db, token, event, selected, request, request_hash)
                if result is not None:
                    return result
                try:
                    reasons = [r for e in evidence for r in evaluate(e, current["policy"]["project"]["packages"])]
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
                db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?)",
                           (actor["id"], event, request_hash, self.store.metadata(request), None, "pending", time.time()))
                os.rename(target, sets / identity)
                # Mounts are read only. Make accidental operator writes difficult too.
                for path in (sets / identity).rglob("*"):
                    path.chmod(0o555 if path.is_dir() else 0o444)
                (sets / identity).chmod(0o555)
                response = {"allowed": True, "effect": "installed", "level": "allow",
                            "package_set": identity, "packages": selected,
                            "manifest_sha256": digest(manifest), "policy_sha256": current["approval"]["sha256"],
                            "evidence": [{k: e[k] for k in ("name", "version", "sha256", "published_at", "checked_at")} for e in evidence]}
                db.execute("BEGIN IMMEDIATE")
                db.execute("INSERT INTO package_sets VALUES(?,?,?,?,?)",
                           (identity, actor["project"], canonical(sorted(selected)), canonical(manifest), time.time()))
                db.execute("UPDATE events SET response=?,state='complete' WHERE session=? AND event=?",
                           (canonical(response), actor["id"], event))
                db.commit()
                return response
