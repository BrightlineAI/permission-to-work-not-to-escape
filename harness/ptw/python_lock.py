"""Import authoritative Python locks through their native, metadata-only exporters."""
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import time
import tomllib

from packaging.utils import canonicalize_name

from .package_evidence import EvidenceError, PyPIEvidence, evaluate, pins
from .policy import Invalid, save
from .python_runtime import select, verify


def export_lock(root, stage, rules, *, executable=None, source=None, groups=('dev', 'test'),
                extras=(), provider=None, runner=None, seconds=180):
    """Frozen import never repairs a stale or forbidden lock behind the review.

    Export hashes are constraints on independently fetched registry artifacts.
    Local roots are omitted from registry assessment, not labelled PyPI releases.
    Executable local installation is a separate preparation operation.
    """
    from .dependency_resolution import (ResolutionError, checked_requirement, compiled_pins,
        metadata, python_inputs, requirement_lines, resolver_environment, run_metadata)
    from .package_install import target_environment
    root, stage = Path(root), Path(stage)
    stage.mkdir(parents=True, exist_ok=True)
    started, attempts, outcome = time.monotonic(), [], 'invalid'
    inputs = {}
    try:
        if not isinstance(seconds, (int, float)) or not 0 < seconds <= 180:
            raise Invalid('Resolution budgets may only narrow the fixed limits')
        locks = [name for name in ('uv.lock', 'poetry.lock') if (root / name).exists()]
        if len(locks) != 1:
            raise Invalid('Select one authoritative Python lock; uv.lock and poetry.lock are ambiguous')
        lock_name = locks[0]
        if not (root / 'pyproject.toml').is_file():
            raise Invalid('An authoritative lock requires its pyproject.toml')
        if source not in (None, 'pyproject.toml', lock_name):
            raise Invalid('An authoritative lock cannot be replaced by another Python source')
        manifest_text = metadata(root, 'pyproject.toml', inputs)
        document = tomllib.loads(manifest_text)
        lock_text = metadata(root, lock_name, inputs)
        locked = tomllib.loads(lock_text)
        project = document.get('project', {})
        if not isinstance(project, dict):
            raise Invalid('Malformed project table')
        requirement = project.get('requires-python', '')
        declarations, constraints = [], []
        if lock_name == 'uv.lock':
            # This validator rejects URL/path/source overrides before uv sees them.
            declarations, constraints, _, _ = python_inputs(root, source='pyproject.toml', groups=groups, extras=extras)
            for package in locked.get('package', []):
                origin = package.get('source', {})
                if origin not in ({'virtual': '.'}, {'editable': '.'}, {'registry': 'https://pypi.org/simple'}):
                    raise Invalid('uv lock source needs approved local/private source preparation')
            selected_groups = [g for g in groups if g in document.get('dependency-groups', {})]
            tool = shutil.which('uv')
        else:
            poetry = document.get('tool', {}).get('poetry', {})
            if not isinstance(poetry, dict) or poetry.get('source') or poetry.get('requires-plugins'):
                raise Invalid('Poetry sources and project plugins require explicit trusted tooling')
            for package in locked.get('package', []):
                if package.get('source'):
                    raise Invalid('Poetry source needs approved local/private source preparation')
            # PEP 621 is preferred. The native Poetry lock retains its normalized
            # Python constraint; do not guess how Poetry caret syntax translates.
            requirement = requirement or locked.get('metadata', {}).get('python-versions', '')
            selected_groups = [g for g in groups if g in poetry.get('group', {})]
            tool = shutil.which('poetry')
        if groups != ('dev', 'test') and set(selected_groups) != set(groups):
            raise Invalid('Selected Python group is missing')
        version_request = metadata(root, '.python-version', inputs).strip() if (root / '.python-version').exists() else None
        runtime = select(requirement, executable, version_request)
        if not tool:
            raise ResolutionError('unavailable', 'Install the native ' + ('uv' if lock_name == 'uv.lock' else
                'Poetry with poetry-plugin-export') + ' tool in the trusted toolchain')
        tool_path = Path(tool).resolve()
        if lock_name == 'poetry.lock' and not tool_path.is_relative_to('/usr'):
            raise ResolutionError('unavailable', 'Poetry must be provisioned in the trusted /usr runtime')
        save(stage / 'resolver-tool.json', {'path': str(tool_path),
            'sha256': hashlib.sha256(tool_path.read_bytes()).hexdigest(), 'runtime': runtime, 'inputs': inputs})
        (stage / 'pyproject.toml').write_text(manifest_text)
        (stage / lock_name).write_text(lock_text)
        output = stage / 'exported.txt'
        if lock_name == 'uv.lock':
            commands = [[tool, '--no-config', '--no-python-downloads', '--cache-dir', str(stage / 'cache'),
                'export', '--locked', '--no-build', '--no-sources', '--python', runtime['executable'],
                '--no-emit-project', '--no-default-groups', '--no-header', '--no-annotate',
                *[x for g in selected_groups for x in ('--group', g)],
                *[x for e in extras for x in ('--extra', e)], '--output-file', str(output)]]
        else:
            commands = [[tool, '--no-interaction', 'check', '--lock'],
                [tool, '--no-interaction', 'export', '--format=requirements.txt', '--output', str(output),
                 *[x for g in selected_groups for x in ('--with', g)],
                 *[x for e in extras for x in ('--extras', e)]]]
        run = runner or run_metadata
        env = resolver_environment(stage)
        env.update(POETRY_VIRTUALENVS_CREATE='false', POETRY_KEYRING_ENABLED='false')
        for argv in commands:
            remaining = seconds - (time.monotonic() - started)
            if remaining <= 0:
                raise ResolutionError('budget_exhausted', 'lock export deadline reached')
            attempt = {'command': 'export' if 'export' in argv else 'check', 'outcome': 'running'}
            attempts.append(attempt)
            try:
                proc = run(argv, cwd=stage, env=env, capture_output=True, text=True, timeout=remaining)
            except subprocess.TimeoutExpired as exc:
                raise ResolutionError('budget_exhausted', 'native lock export timed out') from exc
            attempt['returncode'] = proc.returncode
            if proc.returncode:
                attempt['stderr_sha256'] = hashlib.sha256(proc.stderr.encode()).hexdigest()
                raise ResolutionError('unavailable', 'Native lock check/export failed; check consistency and installed tooling')
            attempt['outcome'] = 'exported'
        if (stage / lock_name).read_text() != lock_text or (stage / 'pyproject.toml').read_text() != manifest_text:
            raise Invalid('Locked export unexpectedly changed authoritative inputs')
        exported = metadata(stage, output.name, {})
        environment = target_environment(runtime['executable'])
        resolved = compiled_pins(exported, environment)
        selected = pins(resolved, extras={}) if resolved else {}
        for line in [*declarations, *constraints]:
            declaration = checked_requirement(line)
            if declaration.marker and not declaration.marker.evaluate(environment):
                continue
            name = canonicalize_name(declaration.name)
            if ((name in selected and not declaration.specifier.contains(selected[name], prereleases=True)) or
                    (line in declarations and name not in selected)):
                raise Invalid('Locked export violates an original dependency constraint')
        hashes = {}
        for line in requirement_lines(exported):
            declaration = checked_requirement(line)
            if declaration.marker and not declaration.marker.evaluate(environment):
                continue
            values = set(re.findall(r'--hash=sha256:([0-9a-fA-F]{64})', line))
            if not values:
                raise Invalid('Native lock export omitted required artifact hashes')
            hashes[canonicalize_name(declaration.name)] = {v.lower() for v in values}
        provider = provider or PyPIEvidence(native=rules.get('allow_native_wheels', False), python=runtime['executable'])
        records = []
        for name, version in selected.items():
            remaining = seconds - (time.monotonic() - started)
            if remaining <= 0:
                raise ResolutionError('budget_exhausted', 'locked evidence deadline reached')
            if isinstance(provider, PyPIEvidence):
                provider.deadline = started + seconds
            record = provider.assess(name, version)
            if time.monotonic() - started >= seconds:
                raise ResolutionError('budget_exhausted', 'locked evidence deadline reached')
            if (record.get('name') != name or record.get('version') != version or
                    record.get('sha256') not in hashes[name]):
                raise EvidenceError('Registry identity or artifact digest differs from authoritative lock')
            if evaluate(record, rules):
                raise ResolutionError('unsatisfiable', 'Frozen lock contains a forbidden version; explicitly review a native lock update')
            records.append({k: record[k] for k in ('name', 'version', 'url', 'sha256')})
        verify(runtime)
        outcome = 'resolved'
        return {'pins': resolved, 'runtime': runtime, 'inputs': inputs, 'artifacts': records,
                'attempts': attempts, 'authority': lock_name}
    except ResolutionError as exc:
        outcome = exc.outcome
        raise
    except EvidenceError:
        outcome = 'unavailable_evidence'
        raise
    except Invalid:
        raise
    except (ValueError, TypeError, AttributeError) as exc:
        raise Invalid('Malformed native Python lock metadata') from exc
    finally:
        if attempts and attempts[-1]['outcome'] == 'running':
            attempts[-1]['outcome'] = outcome
        save(stage / 'resolution.json', {'outcome': outcome, 'inputs': inputs, 'attempts': attempts,
            'elapsed_seconds': time.monotonic() - started})
