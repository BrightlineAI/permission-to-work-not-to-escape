"""Native pnpm import and bounded reviewed re-resolution of original ranges."""
import hashlib
from pathlib import Path
import re
import subprocess
import time

from . import pnpm_tool
from .dependency_resolution import ResolutionError
from .npm import NpmEvidence
from .npm_resolution import MetadataView
from .package_evidence import EvidenceError, evaluate
from .pnpm import PnpmPlan, mapping, read_inputs
from .policy import Invalid, save


def resolve_pnpm(root, stage, rules, *, provider=None, update=False,
                 max_rounds=8, max_assessments=256, seconds=180):
    """Import is frozen. Only an explicit dependency review may select a new lock.

    pnpm selects compatible candidates. Confirmed policy failures remove exact
    candidates from the existing metadata view, never rewrite declared ranges.
    Every final artifact is independently assessed and bound to its native lock.
    """
    from .onboarding import data
    stage = Path(stage)
    stage.mkdir(parents=True, exist_ok=True)
    started, attempts, outcome, inputs = time.monotonic(), [], 'invalid', {}
    try:
        if (type(max_rounds) is not int or not 1 <= max_rounds <= 8 or
                type(max_assessments) is not int or not 1 <= max_assessments <= 256 or
                not isinstance(seconds, (int, float)) or not 0 < seconds <= 180):
            raise Invalid('Resolution budgets may only narrow the fixed limits')
        files, _ = read_inputs(root)
        inputs = {n: hashlib.sha256(t.encode()).hexdigest() for n, t in files.items()}
        provider = provider or NpmEvidence()
        deadline, excluded, cache = started + seconds, set(), {}
        if hasattr(provider, 'deadline'):
            provider.deadline = deadline
        # Admission of manifest/source configuration precedes native execution.
        # For updates only, omit stale declaration comparisons on the old lock.
        PnpmPlan(files, updating=update)
        for index in range(max_rounds):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ResolutionError('budget_exhausted', 'pnpm resolution deadline reached')
            attempt = {'round': index + 1, 'outcome': 'running',
                       'excluded': sorted([list(p) for p in excluded])}
            attempts.append(attempt)
            folder = stage / ('round-' + str(index + 1))
            folder.mkdir()
            for name, text in files.items():
                if update and name == 'pnpm-lock.yaml':
                    continue
                path = folder / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            try:
                if update:
                    view = MetadataView(provider, excluded, deadline)
                    with view as endpoint:
                        proc = pnpm_tool.resolve_lock(folder, endpoint,
                            age_minutes=rules['min_release_age_days'] * 1440, timeout=remaining)
                    if view.error:
                        raise EvidenceError(view.error)
                else:
                    proc = pnpm_tool.run(['install', '--lockfile-only', '--frozen-lockfile'],
                                         cwd=folder, timeout=remaining)
            except subprocess.TimeoutExpired as exc:
                raise ResolutionError('budget_exhausted', 'native pnpm timed out') from exc
            attempt.update(returncode=proc.returncode,
                stdout_sha256=hashlib.sha256(proc.stdout.encode()).hexdigest(),
                stderr_sha256=hashlib.sha256(proc.stderr.encode()).hexdigest(),
                error_codes=sorted(set(re.findall(r'ERR_PNPM_[A-Z_]+', proc.stdout + proc.stderr))))
            if proc.returncode:
                conflict = any(c in attempt['error_codes'] for c in (
                    'ERR_PNPM_NO_MATCHING_VERSION', 'ERR_PNPM_NO_MATCHING_VERSION_INSIDE_WORKSPACE',
                    'ERR_PNPM_OUTDATED_LOCKFILE'))
                raise ResolutionError('unsatisfiable' if conflict else 'unavailable',
                    'Native pnpm could not resolve the original declarations under policy')
            resolved = {n: data(folder / n, 8 * 1024 * 1024) for n in files}
            attempt['output_inputs'] = {n: hashlib.sha256(t.encode()).hexdigest()
                                        for n, t in resolved.items()}
            if any(resolved[n] != t for n, t in files.items() if n != 'pnpm-lock.yaml'):
                raise Invalid('Native pnpm changed authoritative declarations')
            if not update:
                # pnpm 10.23 serializes even a frozen lockfile-only stage.
                # Accept formatting only, never a repaired graph or origin.
                # Keep both copies as evidence and return the original bytes.
                if mapping(resolved['pnpm-lock.yaml']) != mapping(files['pnpm-lock.yaml']):
                    raise Invalid('Native pnpm changed the frozen lock')
                resolved['pnpm-lock.yaml'] = files['pnpm-lock.yaml']
            plan = PnpmPlan(resolved)
            records, rejected = [], set()
            for identity, version in plan.selected.items():
                key = (identity.rsplit('@', 1)[0], version)
                if time.monotonic() >= deadline or (key not in cache and len(cache) >= max_assessments):
                    raise ResolutionError('budget_exhausted', 'pnpm candidate assessment budget exhausted')
                if key not in cache:
                    cache[key] = provider.assess(*key)
                record = cache[key]
                if time.monotonic() >= deadline:
                    raise ResolutionError('budget_exhausted', 'pnpm evidence deadline reached')
                if (record.get('name'), record.get('version')) != key:
                    raise EvidenceError('pnpm candidate evidence identity mismatch')
                if evaluate(record, rules):
                    rejected.add(key)
                records.append(record)
            plan.bind_evidence(records)
            attempt.update(selected=plan.selected, rejected=sorted([list(p) for p in rejected]))
            if not rejected:
                outcome = attempt['outcome'] = 'resolved'
                return {'lock': plan.original_lock, 'files': resolved,
                    'inputs': {n: hashlib.sha256(t.encode()).hexdigest() for n, t in resolved.items()},
                    'artifacts': [{k: r[k] for k in ('name', 'version', 'url', 'integrity')} for r in records],
                    'sources': sorted(plan.locals), 'authority': 'pnpm', 'attempts': attempts}
            attempt['outcome'] = 'policy_exclusion'
            if not update or rejected <= excluded:
                raise ResolutionError('unsatisfiable', 'Frozen or exact pnpm lock violates policy; review a compatible update')
            excluded |= rejected
        raise ResolutionError('budget_exhausted', 'pnpm candidate retry limit reached')
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
