"""Frozen Yarn authority and bounded native resolution for reviewed revisions."""
import hashlib
from pathlib import Path
import re
import time

from . import yarn_tool
from .dependency_resolution import ResolutionError
from .npm import NpmEvidence
from .npm_resolution import MetadataView
from .package_evidence import EvidenceError, evaluate
from .policy import Invalid, save
from .yarn import YarnEvidence, YarnPlan, read_inputs


class YarnMetadataView(MetadataView):
    """Retain the registry's SHA1 field used by Classic's resolved URL fragment.

    SHA512 remains the required artifact integrity; SHA1 is never substituted.
    The final installer verifies both against the downloaded archive bytes.
    """
    def __init__(self, provider, excluded, deadline, origins):
        super().__init__(provider, excluded, deadline)
        self.origins = origins

    def document(self, name):
        result = super().document(name)
        for version, record in result['versions'].items():
            shasum = self.cache[name]['versions'][version]['dist'].get('shasum')
            if not isinstance(shasum, str) or not re.fullmatch('[0-9a-f]{40}', shasum):
                raise EvidenceError('Yarn registry metadata lacks a canonical SHA1 URL fragment')
            record['dist']['shasum'] = shasum
            record['dist']['tarball'] = self.origins.url(name, version, record['dist']['tarball'])
        return result


def resolve_yarn(root, stage, rules, *, provider=None, update=False,
                 max_rounds=8, max_assessments=256, seconds=180):
    """Yarn chooses from original ranges; policy excludes exact unsafe versions.

    Frozen imports never re-resolve. Missing evidence is an error, not a reason
    to choose an unassessed alternative. Only final independently checked native
    locks can be returned for review; nothing here publishes an installation.
    """
    from .onboarding import data
    stage = Path(stage)
    stage.mkdir(parents=True, exist_ok=True)
    started, inputs, attempts, outcome = time.monotonic(), {}, [], 'invalid'
    try:
        if (type(max_rounds) is not int or not 1 <= max_rounds <= 8 or
                type(max_assessments) is not int or not 1 <= max_assessments <= 256 or
                type(seconds) not in (int, float) or not 0 < seconds <= 180):
            raise Invalid('Resolution budgets may only narrow the fixed limits')
        files, _ = read_inputs(root)
        inputs = {n: hashlib.sha256(t.encode()).hexdigest() for n, t in files.items()}
        original = YarnPlan(files, updating=update)
        provider = provider or NpmEvidence()
        evidence = YarnEvidence(provider, original)
        deadline, excluded, cache = started + seconds, set(), {}
        if hasattr(provider, 'deadline'):
            provider.deadline = deadline
        for index in range(max_rounds):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ResolutionError('budget_exhausted', 'Yarn resolution deadline reached')
            attempt = {'round': index + 1, 'outcome': 'running',
                       'excluded': sorted([list(p) for p in excluded])}
            attempts.append(attempt)
            resolved = files
            if update:
                folder = stage / ('round-' + str(index + 1))
                folder.mkdir()
                for name, text in files.items():
                    if name == 'yarn.lock':
                        continue
                    path = folder / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(text)
                view = YarnMetadataView(provider, excluded, deadline, evidence)
                with view as endpoint:
                    proc = yarn_tool.resolve_lock(folder, endpoint, timeout=remaining)
                if view.error:
                    raise EvidenceError(view.error)
                attempt.update(returncode=proc.returncode,
                    stdout_sha256=hashlib.sha256(proc.stdout.encode()).hexdigest(),
                    stderr_sha256=hashlib.sha256(proc.stderr.encode()).hexdigest())
                if proc.returncode:
                    conflict = any(s in proc.stdout + proc.stderr for s in (
                        "Couldn't find any versions", "Couldn't find package", 'No versions available'))
                    raise ResolutionError('unsatisfiable' if conflict else 'unavailable',
                        'Native Yarn could not resolve original declarations under policy')
                resolved = {n: data(folder / n, 8 * 1024 * 1024) for n in files}
                if any(resolved[n] != text for n, text in files.items() if n != 'yarn.lock'):
                    raise Invalid('Native Yarn changed authoritative declarations')
            plan = YarnPlan(resolved) if update else original
            records, rejected = [], set()
            for identity, version in plan.selected.items():
                key = (identity.rsplit('@', 1)[0], version)
                if time.monotonic() >= deadline or (key not in cache and len(cache) >= max_assessments):
                    raise ResolutionError('budget_exhausted', 'Yarn candidate assessment budget exhausted')
                if key not in cache:
                    cache[key] = evidence.assess(*key)
                record = cache[key]
                if time.monotonic() >= deadline:
                    raise ResolutionError('budget_exhausted', 'Yarn evidence deadline reached')
                if (record.get('name'), record.get('version')) != key:
                    raise EvidenceError('Yarn candidate evidence identity mismatch')
                if evaluate(record, rules):
                    rejected.add(key)
                records.append(record)
            plan.bind_evidence(records)
            # An unchanged identity cannot silently migrate to another origin.
            for key in original.registry.keys() & plan.registry.keys():
                if (original.registry[key]['integrity'] != plan.registry[key]['integrity'] or
                        original.registry[key]['resolved'].split('#')[0] !=
                        plan.registry[key]['resolved'].split('#')[0]):
                    raise EvidenceError('Yarn revision substituted an existing artifact identity')
            attempt.update(selected=plan.selected, rejected=sorted([list(p) for p in rejected]),
                output_inputs={n: hashlib.sha256(t.encode()).hexdigest() for n, t in resolved.items()})
            if read_inputs(root)[0] != files:
                raise Invalid('Yarn inputs changed during assessment')
            if not rejected:
                outcome = attempt['outcome'] = 'resolved'
                return {'lock': plan.original_lock, 'files': resolved, 'inputs': attempt['output_inputs'],
                        'artifacts': [{k: r[k] for k in ('name', 'version', 'url', 'integrity')} for r in records],
                        'sources': sorted(plan.locals), 'authority': 'yarn', 'attempts': attempts}
            attempt['outcome'] = 'policy_exclusion'
            if not update or rejected <= excluded:
                raise ResolutionError('unsatisfiable', 'Frozen or exact Yarn lock violates policy; review a compatible update')
            excluded |= rejected
        raise ResolutionError('budget_exhausted', 'Yarn candidate retry limit reached')
    except ResolutionError as exc:
        outcome = exc.outcome
        raise
    except EvidenceError:
        outcome = 'unavailable_evidence'
        raise
    finally:
        if attempts and attempts[-1]['outcome'] == 'running':
            attempts[-1]['outcome'] = outcome
        save(stage / 'resolution.json', {'outcome': outcome, 'inputs': inputs,
             'attempts': attempts, 'elapsed_seconds': time.monotonic() - started})
