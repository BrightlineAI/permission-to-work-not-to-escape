"""Native PEP 621 edits and bounded uv lock updates in operator staging only."""
import copy
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import shutil
import secrets
import subprocess
import time
import tomllib

from packaging.utils import canonicalize_name

from .dependency_resolution import (ResolutionError, checked_requirement, metadata,
    python_inputs, resolver_environment, run_metadata)
from .package_evidence import EvidenceError, PyPIEvidence, evaluate
from .policy import Invalid, save
from .python_lock import export_lock, static_lock_project
from .python_runtime import select


def edit_project(root, operation, specs, *, group=None, python, runner=None):
    """uv preserves TOML comments; the parsed result must match the requested edit."""
    root = Path(root)
    original = tomllib.loads(metadata(root, 'pyproject.toml', {}))
    static_lock_project(original)
    python_inputs(root, source='pyproject.toml')
    expected = copy.deepcopy(original)
    if group and group.startswith('extra:'):
        table, key = expected['project'].setdefault('optional-dependencies', {}), group[6:]
        flags = ['--optional', key]
    elif group:
        table, key = expected.setdefault('dependency-groups', {}), group
        flags = ['--group', key]
    else:
        table, key, flags = expected['project'], 'dependencies', []
    entries = table.setdefault(key, [])
    if not isinstance(entries, list):
        raise Invalid('Selected dependency group must be an array')
    wanted = {}
    for value in specs:
        req = checked_requirement(value)
        name = canonicalize_name(req.name)
        if name in wanted or req.marker or req.extras or (operation == 'update' and not req.specifier):
            raise Invalid('Use distinct plain names and explicit update ranges or pins')
        if operation == 'remove' and req.specifier:
            raise Invalid('Remove takes package names, not version constraints')
        wanted[name] = value
    found = set()
    output = []
    for entry in entries:
        name = canonicalize_name(checked_requirement(entry).name) if isinstance(entry, str) else None
        if name not in wanted:
            output.append(entry)
            continue
        if name in found or operation == 'add':
            raise Invalid('Duplicate dependency or existing add; select its direct group and use update')
        found.add(name)
        if operation == 'update':
            output.append(wanted[name])
    if operation != 'add' and found != set(wanted):
        raise Invalid('Dependency is absent from the selected direct group')
    if operation == 'add':
        output.extend(wanted.values())
    table[key] = output
    tool = shutil.which('uv')
    if not tool:
        raise ResolutionError('unavailable', 'uv is required for PEP 621 edits')
    argv = [tool, '--no-config', '--offline', '--no-python-downloads',
        'remove' if operation == 'remove' else 'add', '--frozen',
        '--python', python, *flags, *([] if operation == 'remove' else ['--raw']), *specs]
    proc = (runner or run_metadata)(argv, cwd=root, env=resolver_environment(root),
        capture_output=True, text=True, timeout=30)
    save(root / ('edit-receipt-' + secrets.token_hex(8) + '.json'), {'tool_sha256': hashlib.sha256(Path(tool).resolve().read_bytes()).hexdigest(),
        'returncode': proc.returncode, 'stderr_sha256': hashlib.sha256(proc.stderr.encode()).hexdigest()})
    if proc.returncode:
        raise ResolutionError('unavailable', 'Native uv declaration edit failed')
    actual = tomllib.loads(metadata(root, 'pyproject.toml', {}))
    # uv can sort the edited array, but it cannot change other groups/settings.
    actual_table = (actual['project'].get('optional-dependencies', {}) if flags[:1] == ['--optional'] else
                    actual.get('dependency-groups', {}) if flags[:1] == ['--group'] else actual['project'])
    if sorted(map(repr, actual_table.get(key, []))) != sorted(map(repr, output)):
        raise Invalid('Native edit changed the requested dependency declarations')
    actual_table[key] = output
    if actual != expected:
        raise Invalid('Native edit changed unrelated project metadata')


def update_uv_lock(root, stage, rules, *, executable, groups=('dev', 'test'), extras=(),
                   upgrade=(), provider=None, runner=None, seconds=180, max_rounds=8, max_assessments=256):
    """Use uv add's constraint input, with no added requirements, to re-lock.

    Excluded packages are explicitly unlocked. Other lock entries remain native
    preferences. Neither original declarations nor exact pins are overridden.
    """
    if (type(max_rounds) is not int or not 1 <= max_rounds <= 8 or
            type(max_assessments) is not int or not 1 <= max_assessments <= 256 or
            not isinstance(seconds, (int, float)) or not 0 < seconds <= 180):
        raise Invalid('Resolution budgets may only narrow the fixed limits')
    root, stage = Path(root), Path(stage)
    if getattr(provider, 'routes', None):
        raise Invalid('Private Python native lock updates need reviewed source routing')
    stage.mkdir(parents=True, exist_ok=True)
    started, attempts, excluded, cache, outcome = time.monotonic(), [], set(), {}, 'invalid'
    try:
        inputs = {}
        manifest = metadata(root, 'pyproject.toml', inputs)
        document = tomllib.loads(manifest)
        static_lock_project(document)
        python_inputs(root, source='pyproject.toml', groups=groups, extras=extras)
        if (root / 'poetry.lock').exists():
            raise Invalid('uv updates cannot replace Poetry authority')
        for name in ('pyproject.toml', 'uv.lock', '.python-version'):
            if (root / name).exists():
                (stage / name).write_text(metadata(root, name, inputs))
        runtime = select(document['project'].get('requires-python', ''), executable,
            (stage / '.python-version').read_text().strip() if (stage / '.python-version').exists() else None)
        tool = shutil.which('uv')
        if not tool:
            raise ResolutionError('unavailable', 'uv is required for native lock updates')
        cutoff = datetime.fromtimestamp(time.time() - rules['min_release_age_days'] * 86400, timezone.utc).isoformat()
        save(stage / 'resolver-tool.json', {'path': str(Path(tool).resolve()),
            'sha256': hashlib.sha256(Path(tool).resolve().read_bytes()).hexdigest(), 'runtime': runtime, 'inputs': inputs})
        provider = provider or PyPIEvidence(native=rules.get('allow_native_wheels', False), python=executable)
        if isinstance(provider, PyPIEvidence):
            provider.deadline = started + seconds
        rejected = set()

        class Evidence:
            def assess(self, name, version):
                key = name, version
                if key not in cache:
                    if len(cache) >= max_assessments or time.monotonic() >= started + seconds:
                        raise ResolutionError('budget_exhausted', 'uv candidate assessment budget exhausted')
                    cache[key] = provider.assess(name, version)
                record = cache[key]
                if record.get('name') != name or record.get('version') != version:
                    raise EvidenceError('Candidate evidence identity mismatch')
                if evaluate(record, rules):
                    rejected.add(key)
                return record

        (stage / 'empty.txt').write_text('')
        for index in range(max_rounds):
            remaining = started + seconds - time.monotonic()
            if remaining <= 0:
                raise ResolutionError('budget_exhausted', 'uv lock update deadline reached')
            (stage / 'constraints.txt').write_text(''.join(n + '!=' + v + '\n' for n, v in sorted(excluded)))
            argv = [tool, '--no-config', '--no-python-downloads', '--cache-dir', str(stage / 'cache'),
                'add', '--no-sync', '--raw', '--no-build', '--no-sources', '--python', executable,
                '--default-index', 'https://pypi.org/simple', '--exclude-newer', cutoff,
                '--constraints', str(stage / 'constraints.txt'), '--requirements', str(stage / 'empty.txt'),
                *[a for n in sorted(set(upgrade) | {n for n, _ in excluded}) for a in ('--upgrade-package', n)]]
            attempt = {'round': index + 1, 'excluded': sorted(excluded), 'outcome': 'running'}
            attempts.append(attempt)
            proc = (runner or run_metadata)(argv, cwd=stage, env=resolver_environment(stage),
                capture_output=True, text=True, timeout=remaining)
            attempt['returncode'] = proc.returncode
            if proc.returncode:
                attempt['stderr_sha256'] = hashlib.sha256(proc.stderr.encode()).hexdigest()
                raise ResolutionError('unsatisfiable' if 'No solution found' in proc.stderr else 'unavailable',
                    'Native uv could not update the original declarations under policy')
            if tomllib.loads(metadata(stage, 'pyproject.toml', {})) != document:
                raise Invalid('Native lock update changed original declarations')
            (stage / 'pyproject.toml').write_text(manifest)
            rejected.clear()
            remaining = started + seconds - time.monotonic()
            if remaining <= 0:
                raise ResolutionError('budget_exhausted', 'uv export deadline reached')
            try:
                result = export_lock(stage, stage / ('export-' + str(index)), rules, executable=executable,
                    groups=groups, extras=extras, provider=Evidence(), runner=runner, seconds=remaining)
            except ResolutionError as exc:
                if exc.outcome != 'unsatisfiable' or not rejected:
                    raise
                attempt['outcome'] = 'policy_exclusion'
                if rejected <= excluded:
                    raise ResolutionError('unsatisfiable', 'Native uv retained an excluded version')
                excluded |= rejected
                continue
            result['files'] = {'uv.lock': metadata(stage, 'uv.lock', {})}
            outcome = attempt['outcome'] = 'resolved'
            return result
        raise ResolutionError('budget_exhausted', 'uv candidate retry limit reached')
    except subprocess.TimeoutExpired as exc:
        outcome = 'budget_exhausted'
        raise ResolutionError(outcome, 'Native uv lock update timed out') from exc
    except ResolutionError as exc:
        outcome = exc.outcome
        raise
    except EvidenceError:
        outcome = 'unavailable_evidence'
        raise
    finally:
        if attempts and attempts[-1]['outcome'] == 'running':
            attempts[-1]['outcome'] = outcome
        save(stage / 'resolution.json', {'outcome': outcome, 'attempts': attempts,
            'elapsed_seconds': time.monotonic() - started})
