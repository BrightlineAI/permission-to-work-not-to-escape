"""Import authoritative Python locks through their native, metadata-only exporters."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import tomllib

from packaging.utils import canonicalize_name

from .package_evidence import EvidenceError, PyPIEvidence, evaluate, pins
from .policy import Invalid, OutsideScope, canonical, save
from .python_runtime import select, verify


def static_lock_project(document):
    """Native lock operations may inspect first-party metadata despite --no-build.

    Never let a resolver discover that metadata by invoking repository code on
    the network-enabled metadata path. Executable preparation is separate.
    """
    project = document.get('project', {})
    if not isinstance(project, dict) or project.get('dynamic'):
        raise Invalid('Dynamic project metadata needs approved offline source preparation before native locking')
    if project and ('name' not in project or 'version' not in project):
        raise Invalid('Native locking requires a static project name and version')
    tool = document.get('tool', {})
    if not isinstance(tool, dict):
        raise Invalid('Malformed project tool table')
    poetry = tool.get('poetry', {})
    if not isinstance(poetry, dict) or poetry.get('plugins') or poetry.get('requires-plugins'):
        raise Invalid('Project-selected Poetry plugins cannot run during metadata preparation')


OFFLINE_LOCK = r'''
import json,os,pathlib,shutil,subprocess,sys,tempfile,time
config = json.loads(sys.argv[1])
deadline = time.monotonic() + config['seconds']
root = pathlib.Path('/work/source') / config['path']
def omit(directory, names):
    return ['pyproject.toml', 'uv.lock'] if pathlib.Path(directory) == pathlib.Path('/input') / config['path'] else []
shutil.copytree('/input', '/work/source', dirs_exist_ok=True, ignore=omit)
shutil.copytree('/metadata-cache', '/tmp/uv-cache')
uv = ['/uv', '--no-config', '--offline', '--no-python-downloads', '--cache-dir', '/tmp/uv-cache']
def run(step, arguments):
    # Isolate each subprocess's diagnostics. Successful venv/install chatter
    # must not be mistaken for the cause of an export failure. Keep both ends
    # of a failing tool's output within run_build's 2,000-byte diagnostic tail.
    with tempfile.TemporaryFile() as diagnostic:
        try:
            subprocess.run(uv + arguments, cwd=root, check=True,
                           stdout=diagnostic, stderr=subprocess.STDOUT,
                           env={**os.environ, 'UV_PROJECT_ENVIRONMENT': '/tmp/build-env'},
                           timeout=max(.001, deadline-time.monotonic()))
        except (OSError, subprocess.SubprocessError) as exc:
            diagnostic.seek(0, 2)
            size = diagnostic.tell()
            diagnostic.seek(0)
            output = diagnostic.read(750)
            if size > 1500:
                diagnostic.seek(-750, 2)
                output += b'\n[tool output truncated]\n'
            output += diagnostic.read(750)
            if output:
                sys.stderr.write(output.decode('utf-8', 'ignore') + '\n')
            failure = ('timeout' if isinstance(exc, subprocess.TimeoutExpired) else
                       'exit' if isinstance(exc, subprocess.CalledProcessError) else 'launch')
            print('PTW_OFFLINE_LOCK_ERROR=' + failure, file=sys.stderr, flush=True)
            print('PTW_OFFLINE_LOCK_STEP=' + step, file=sys.stderr, flush=True)
            raise SystemExit(1) from None
run('venv', ['venv', '--python', config['python'], '/tmp/build-env'])
run('install', ['pip', 'install', '--python', '/tmp/build-env/bin/python', '--no-deps', '--no-index',
     '--no-build', '--require-hashes', '--link-mode', 'copy', '-r', '/artifacts/install.txt'])
# Project export discovers UV_PROJECT_ENVIRONMENT, unlike uv pip's --python.
# Keep the reviewed base interpreter as the compatibility constraint; without
# a project environment uv searches for a system interpreter, excluding venvs.
run('export', ['export', '--locked', '--no-build-isolation', '--no-sources',
     *[arg for name in config['no_build_packages'] for arg in ('--no-build-package', name)],
     '--python', config['python'], '--no-emit-project', '--no-default-groups',
     '--no-header', '--no-annotate', *config['selection'], '--output-file', '/target/exported.txt'])
'''


def source_lock_required(bundle, source):
    descriptor = bundle['policy']['project'].get('python_dependencies', {})
    path = (source['path'] + '/' if source['path'] else '') + 'uv.lock'
    return bool(source.get('dynamic_metadata')) and path in descriptor.get('inputs', {})


def verify_source_lock(bundle, source, receipt):
    """Candidate-only resolution cannot produce a reusable local installation."""
    if not source_lock_required(bundle, source):
        return
    descriptor = bundle['policy']['project']['python_dependencies']
    validation = receipt.get('lock_validation')
    prefix = source['path'] + '/' if source['path'] else ''
    from .dependency_binding import source_graph
    expected = [{k: r[k] for k in ('name', 'version', 'sha256')}
                for r in source_graph(descriptor, source['id'])['artifacts']]
    if (not isinstance(validation, dict) or validation.get('version') != 1 or
            validation.get('source_id') != source['id'] or
            validation.get('source_sha256') != source['snapshot_sha256'] or
            validation.get('policy_sha256') != bundle['approval']['sha256'] or
            validation.get('runtime') != bundle['policy']['project']['python_runtime'] or
            validation.get('dependencies') != expected or
            validation.get('groups') != descriptor.get('groups', ['dev', 'test']) or
            validation.get('extras') != source.get('extras', []) or
            validation.get('uv_sha256') != receipt.get('uv_sha256') or
            validation.get('runner_sha256') != hashlib.sha256(OFFLINE_LOCK.encode()).hexdigest() or
            not isinstance(validation.get('inputs'), dict) or
            any(validation['inputs'].get(name) != descriptor['inputs'].get(prefix + name)
                for name in ('pyproject.toml', 'uv.lock')) or
            any(descriptor['inputs'].get(prefix + name) != value
                for name, value in validation['inputs'].items()) or
            not isinstance(validation.get('artifacts'), list) or
            any(r not in descriptor['artifacts'] for r in validation['artifacts']) or
            not isinstance(validation.get('export_sha256'), str) or
            not re.fullmatch('[0-9a-f]{64}', validation['export_sha256'])):
        raise Invalid('Dynamic lock validation receipt is missing or differs from the approved installation')


def validate_source_lock(store, token, identity, *, provider=None, groups=('dev', 'test'), seconds=180):
    """Validate dynamic uv metadata only under approved, pending source authority.

    Frozen export identifies candidates; it never certifies freshness. Registry
    cache population sees only exact assessed pins, never executable source. The
    original manifest and lock are read-only during the supervised offline check.
    This returns evidence, not installation authority or a published package set.
    """
    from .dependency_resolution import (ResolutionError, compiled_pins, metadata, resolver_failure_signals,
        python_inputs, requirement_lines, checked_requirement, resolve_python)
    from .package_install import target_environment
    from .python_local import authorized_snapshot, assessed_artifacts, run_source_build
    from .registry import provider_for
    from .supervisor import runtime_namespace
    from .workspace import materialize

    if type(seconds) not in (int, float) or not 0 < seconds <= 180:
        raise Invalid('Lock validation budgets may only narrow the fixed limit')
    started = time.monotonic()
    def remaining():
        value = seconds - (time.monotonic() - started)
        if value <= 0:
            raise ResolutionError('budget_exhausted', 'offline lock validation deadline reached')
        return value

    source, entries, python, approval = authorized_snapshot(store, token, identity)
    with store.locked() as db:
        actor = store.session(db, token, preparation=True)
        project, bundle = store.project(db, actor['project'])
        if (not project['setup_pending'] or actor['preparation_source'] != identity or
                source['mode'] == 'discovery' or not source.get('dynamic_metadata')):
            raise OutsideScope('Lock validation requires reviewed metadata and pending source preparation')
    descriptor = bundle['policy']['project']['python_dependencies']
    prefix = source['path'] + '/' if source['path'] else ''
    for name in ('pyproject.toml', 'uv.lock'):
        entry = entries.get(prefix + name, {})
        if (entry.get('kind') != 'file' or descriptor['inputs'].get(prefix + name) !=
                hashlib.sha256(entry['data']).hexdigest()):
            raise Invalid('Offline lock validation requires explicitly bound manifest and uv.lock')
    uv = os.environ.get('PTW_UV') or shutil.which('uv')
    if not uv or not Path(uv).is_file():
        raise EvidenceError('uv is required; no offline lock fallback')
    uv = Path(uv).resolve()
    tool_hash = hashlib.sha256(uv.read_bytes()).hexdigest()
    rules = bundle['policy']['project']['packages']
    provider = provider or provider_for(store, bundle, 'pypi')
    if getattr(provider, 'routes', None):
        raise Invalid('Offline dynamic locks currently require public registry origins')
    if isinstance(provider, PyPIEvidence):
        provider.deadline = started + seconds
    with tempfile.TemporaryDirectory(prefix='local-lock-', dir=store.directory) as temporary:
        stage = Path(temporary)
        seed, output, artifacts = stage / 'input', stage / 'result', stage / 'artifacts'
        seed.mkdir()
        output.mkdir()
        artifacts.mkdir()
        materialize(entries, seed)
        candidates = export_lock(seed / source['path'], stage / 'candidates', rules,
            executable=python, groups=groups, extras=source.get('extras', ()), provider=provider,
            candidate_only=True, seconds=remaining())
        if verify(candidates['runtime']) != python:
            raise Invalid('Locked candidates selected another runtime')
        approved = {r['name']: r for r in descriptor['artifacts']}
        if any(approved.get(r['name']) != r for r in candidates['artifacts']):
            raise Invalid('Locked candidates differ from the approved graph')
        if len(candidates['artifacts']) * 2 + len(approved) > 256:
            raise ResolutionError('budget_exhausted', 'offline lock assessment limit reached')
        # uv owns its cache format. Populate a NEW registry-only cache through
        # the existing resolver, preserving the original public registry origin.
        registry = stage / 'registry'
        registry.mkdir()
        (registry / 'requirements.in').write_text(''.join(
            r['name'] + '==' + r['version'] + ' --hash=sha256:' + r['sha256'] + '\n'
            for r in candidates['artifacts']))
        warm = resolve_python(registry, stage / 'metadata', rules, executable=python,
            source='requirements.in', provider=provider, seconds=remaining(),
            max_assessments=max(1, 256 - len(candidates['artifacts']) - len(approved)))
        if sorted(warm['artifacts'], key=lambda r: r['name']) != sorted(candidates['artifacts'], key=lambda r: r['name']):
            raise Invalid('Offline cache candidates differ from the lock')
        cache = stage / 'metadata/cache'
        cache.mkdir(exist_ok=True)
        _, records = assessed_artifacts(store, token, artifacts, python, provider=provider, identity=identity)
        (artifacts / 'install.txt').write_text(''.join(
            r['name'] + ' @ file:///artifacts/' + r['filename'] + ' --hash=sha256:' + r['sha256'] + '\n'
            for r in records))
        document = tomllib.loads(entries[prefix + 'pyproject.toml']['data'].decode())
        # uv 0.12.15 also applies --no-build to a named editable root's
        # metadata. Only this explicitly approved root may build here. Keep
        # every registry identity (including unselected lock groups) binary-only.
        locked = tomllib.loads(entries[prefix + 'uv.lock']['data'].decode())
        no_build_packages = set(approved)
        for package in locked.get('package', []):
            if package.get('source', {}).get('registry'):
                try:
                    no_build_packages.add(canonicalize_name(package['name'], validate=True))
                except (KeyError, TypeError, ValueError) as exc:
                    raise Invalid('Malformed locked registry identity') from exc
        if source['name'] in no_build_packages:
            raise Invalid('Local source conflicts with a locked registry identity')
        selection = [x for g in groups if g in document.get('dependency-groups', {}) for x in ('--group', g)]
        selection += [x for e in source.get('extras', ()) for x in ('--extra', e)]
        command = runtime_namespace() + [
            '--ro-bind', str(uv), '/uv', '--ro-bind', str(seed), '/input',
            '--ro-bind', str(cache), '/metadata-cache', '--ro-bind', str(artifacts), '/artifacts',
            '--bind', str(output), '/target']
        for name in ('pyproject.toml', 'uv.lock'):
            command += ['--ro-bind', str(seed / source['path'] / name), '/work/source/' + prefix + name]
        config = dict(path=source['path'], python=python, selection=selection, seconds=remaining(),
                      no_build_packages=sorted(no_build_packages))
        command += ['--', python, '-I', '-S', '-c', OFFLINE_LOCK, canonical(config)]
        current = authorized_snapshot(store, token, identity)
        if current[0] != source or current[3] != approval:
            raise Invalid('Lock validation approval changed; no backend executed')
        try:
            run_source_build(store, token, identity, command, output)
        except EvidenceError as exc:
            signals = ','.join(resolver_failure_signals(str(exc))) or 'unclassified'
            steps = [step for step in ('venv', 'install', 'export')
                     if 'PTW_OFFLINE_LOCK_STEP=' + step in str(exc)]
            raise EvidenceError('Confined offline lock validation failed; lock unchanged and no installation published; '
                                'step=' + (','.join(steps) or 'unknown') + '; signals=' + signals) from None
        remaining()
        exported = metadata(output, 'exported.txt', {})
        environment = target_environment(python)
        resolved = compiled_pins(exported, environment)
        if ((pins(resolved, extras={}) if resolved else {}) !=
                (pins(candidates['pins'], extras={}) if candidates['pins'] else {})):
            raise EvidenceError('Validated export differs from assessed locked candidates')
        for line in requirement_lines(exported):
            requirement = checked_requirement(line)
            if requirement.marker and not requirement.marker.evaluate(environment):
                continue
            record = approved[canonicalize_name(requirement.name)]
            if record['sha256'] not in re.findall(r'--hash=sha256:([0-9a-f]{64})', line):
                raise EvidenceError('Validated export omitted an approved artifact hash')
        # Independently compare discovered requirements to the locked runtime.
        declarations, constraints, _, _ = python_inputs(seed / source['path'], source='pyproject.toml',
            groups=groups, extras=source.get('extras', ()), dynamic_metadata=source['dynamic_metadata'])
        from .python_local import project_metadata
        from .dependency_resolution import expand_local_requirements
        project_metadata_value, _ = project_metadata(entries, source['path'], source['dynamic_metadata'])
        selected = pins(resolved, extras={}) if resolved else {}
        declarations = expand_local_requirements(project_metadata_value, declarations, environment)
        for line in declarations + constraints:
            requirement = checked_requirement(line)
            if requirement.marker and not requirement.marker.evaluate(environment):
                continue
            name = canonicalize_name(requirement.name)
            if ((name in selected and not requirement.specifier.contains(selected[name], prereleases=True)) or
                    (line in declarations and name not in selected)):
                raise EvidenceError('Discovered metadata conflicts with the locked runtime')
        current = authorized_snapshot(store, token, identity)
        if current[0] != source or current[3] != approval or hashlib.sha256(uv.read_bytes()).hexdigest() != tool_hash:
            raise Invalid('Lock validation inputs or tool changed; result discarded')
        with store.locked() as db:
            actor = store.session(db, token, preparation=True)
            project, current_bundle = store.project(db, actor['project'])
            if project['stopped'] or current_bundle['approval']['sha256'] != approval:
                raise Invalid('Lock validation approval is no longer active')
            import json
            if not {'pypi:' + r['name'] for r in records} <= set(json.loads(actor['packages'])):
                raise OutsideScope('Lock validation dependencies exceed session package grants')
            if any(evaluate(r, current_bundle['policy']['project']['packages']) for r in records):
                raise EvidenceError('Lock validation evidence no longer permits publication')
        return dict(version=1, source_id=identity, source_sha256=source['snapshot_sha256'],
            policy_sha256=approval, inputs=candidates['inputs'], runtime=bundle['policy']['project']['python_runtime'],
            groups=list(groups), extras=source.get('extras', []),
            uv_sha256=tool_hash, runner_sha256=hashlib.sha256(OFFLINE_LOCK.encode()).hexdigest(),
            dependencies=[{k: r[k] for k in ('name', 'version', 'sha256')} for r in records],
            pins=resolved, artifacts=candidates['artifacts'], export_sha256=hashlib.sha256(exported.encode()).hexdigest())


def export_lock(root, stage, rules, *, executable=None, source=None, groups=('dev', 'test'),
                extras=(), provider=None, runner=None, seconds=180, max_assessments=256,
                candidate_only=False):
    """Locked import never repairs a stale or forbidden lock behind the review.

    Export hashes are constraints on independently fetched registry artifacts.
    Local roots are omitted from registry assessment, not labelled PyPI releases.
    Executable local installation is a separate preparation operation.
    Candidate-only frozen export is data for assessment, with no authority field
    and no freshness claim. It requires a later approved offline locked check.
    """
    from .dependency_resolution import (ResolutionError, checked_requirement, compiled_pins,
        metadata, python_inputs, requirement_lines, resolver_environment, resolver_failure_signals, run_metadata)
    from .package_install import target_environment
    root, stage = Path(root), Path(stage)
    stage.mkdir(parents=True, exist_ok=True)
    started, attempts, outcome = time.monotonic(), [], 'invalid'
    inputs = {}
    try:
        if type(candidate_only) is not bool:
            raise Invalid('Candidate export selection must be a boolean')
        if not isinstance(seconds, (int, float)) or not 0 < seconds <= 180:
            raise Invalid('Resolution budgets may only narrow the fixed limits')
        if type(max_assessments) is not int or not 1 <= max_assessments <= 256:
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
        if candidate_only:
            if lock_name != 'uv.lock':
                raise Invalid('Candidate export is supported only for uv locks')
        else:
            static_lock_project(document)
        lock_text = metadata(root, lock_name, inputs)
        locked = tomllib.loads(lock_text)
        project = document.get('project', {})
        if not isinstance(project, dict):
            raise Invalid('Malformed project table')
        requirement = project.get('requires-python', '')
        declarations, constraints = [], []
        if lock_name == 'uv.lock':
            # This validator rejects URL/path/source overrides before uv sees them.
            declarations, constraints, _, _ = python_inputs(root, source='pyproject.toml', groups=groups,
                                                           extras=extras, discovery=candidate_only)
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
            from .poetry_tool import verified
            poetry_directory, poetry_receipt = verified()
            tool = poetry_receipt['runtime']['executable']
        version_request = metadata(root, '.python-version', inputs).strip() if (root / '.python-version').exists() else None
        (stage / 'pyproject.toml').write_text(manifest_text)
        (stage / lock_name).write_text(lock_text)
        if lock_name == 'poetry.lock':
            from .poetry_export import selection
            remaining = seconds - (time.monotonic() - started)
            if remaining <= 0:
                raise ResolutionError('budget_exhausted', 'lock export deadline reached')
            try:
                runtime, available_groups = selection(stage, executable=executable,
                    version_request=version_request, timeout=remaining, directory=poetry_directory)
            except subprocess.TimeoutExpired as exc:
                raise ResolutionError('budget_exhausted', 'native Poetry inspection timed out') from exc
            selected_groups = [g for g in groups if canonicalize_name(g) in available_groups]
        else:
            runtime = select(requirement, executable, version_request)
        if groups != ('dev', 'test') and set(selected_groups) != set(groups):
            raise Invalid('Selected Python group is missing')
        if not tool:
            raise ResolutionError('unavailable', 'Install the native ' + ('uv' if lock_name == 'uv.lock' else
                'Poetry with poetry-plugin-export') + ' tool in the trusted toolchain')
        tool_path = Path(tool).resolve()
        save(stage / 'resolver-tool.json', {'path': str(tool_path),
            'sha256': hashlib.sha256(tool_path.read_bytes()).hexdigest(), 'runtime': runtime, 'inputs': inputs,
            **({'poetry_tool': poetry_receipt} if lock_name == 'poetry.lock' else {})})
        output = stage / 'exported.txt'
        if lock_name == 'uv.lock':
            # uv rejects --frozen together with --no-sources. Candidate export
            # never resolves or certifies freshness; source tables and lock
            # origins were independently rejected above. Keep --no-sources on
            # the authoritative locked path, including offline validation.
            commands = [[tool, '--no-config', '--no-python-downloads', '--cache-dir', str(stage / 'cache'),
                'export', *(['--frozen', '--offline'] if candidate_only else ['--locked', '--no-sources']),
                '--no-build', '--python', runtime['executable'],
                '--no-emit-project', '--no-default-groups', '--no-header', '--no-annotate',
                *[x for g in selected_groups for x in ('--group', g)],
                *[x for e in extras for x in ('--extra', e)], '--output-file', str(output)]]
        else:
            commands = [['poetry-native-export']]
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
                if lock_name == 'poetry.lock':
                    from .poetry_tool import run as run_poetry
                    from .poetry_export import EXPORT
                    proc = run_poetry(EXPORT, {'runtime': runtime,
                        'groups': ['main', *selected_groups], 'extras': list(extras)},
                        cwd=stage, timeout=remaining, directory=poetry_directory)
                else:
                    proc = run(argv, cwd=stage, env=env, capture_output=True, text=True, timeout=remaining)
            except subprocess.TimeoutExpired as exc:
                raise ResolutionError('budget_exhausted', 'native lock export timed out') from exc
            attempt['returncode'] = proc.returncode
            if proc.returncode:
                attempt['stderr_sha256'] = hashlib.sha256(proc.stderr.encode()).hexdigest()
                attempt['signals'] = resolver_failure_signals(proc.stderr)
                raise ResolutionError('unavailable', 'Native lock check/export failed; check consistency and installed tooling; '
                                      'signals=' + (','.join(attempt['signals']) or 'unclassified'))
            attempt['outcome'] = 'exported'
        if lock_name == 'poetry.lock':
            declarations = json.loads(metadata(stage, 'declarations.json', {}))
            if not isinstance(declarations, list) or len(declarations) > 1024:
                raise Invalid('Malformed native Poetry declarations')
        if (stage / lock_name).read_text() != lock_text or (stage / 'pyproject.toml').read_text() != manifest_text:
            raise Invalid('Locked export unexpectedly changed authoritative inputs')
        exported = metadata(stage, output.name, {})
        environment = target_environment(runtime['executable'])
        resolved = compiled_pins(exported, environment)
        selected_extras = {}
        selected = pins(resolved, extras=selected_extras) if resolved else {}
        roots = set() if lock_name == 'poetry.lock' else None
        if roots is not None:
            # Exported extras are lock-controlled and cannot create authority.
            selected_extras = {}
        for line in [*declarations, *constraints]:
            declaration = checked_requirement(line)
            if declaration.marker and not any(declaration.marker.evaluate({**environment, 'extra': e})
                                                for e in ('', *extras)):
                continue
            name = canonicalize_name(declaration.name)
            if line in declarations:
                selected_extras.setdefault(name, []).extend(declaration.extras)
                if roots is not None:
                    roots.add(name)
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
        records, wheels, downloaded = [], {}, 0
        for name, version in selected.items():
            if len(records) >= max_assessments:
                raise ResolutionError('budget_exhausted', 'locked candidate assessment limit reached')
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
            if lock_name == 'poetry.lock':
                from .poetry_resolution import wheel_metadata
                wheel = stage / ('locked-artifact-' + str(len(records)) + '.whl')
                provider.download(record, wheel)
                downloaded += wheel.stat().st_size
                if downloaded > 512 * 1024 * 1024:
                    raise ResolutionError('budget_exhausted', 'Poetry locked download budget exhausted')
                if time.monotonic() - started >= seconds:
                    raise ResolutionError('budget_exhausted', 'Poetry locked download deadline reached')
                wheel_metadata(wheel, record)
                wheels[name] = wheel
            records.append({k: record[k] for k in ('name', 'version', 'url', 'sha256')})
        if lock_name == 'poetry.lock':
            from .package_install import validate_wheels
            # Lock metadata and exporter output are untrusted declarations.
            # Require the actual checked wheels to close their dependency graph,
            # including extras that the exporter strips from exact pins.
            validate_wheels(wheels, selected, environment, extended=True,
                            extras=selected_extras, roots=roots)
            if time.monotonic() - started >= seconds:
                raise ResolutionError('budget_exhausted', 'Poetry locked validation deadline reached')
            for name, sha in inputs.items():
                if hashlib.sha256(metadata(root, name, {}).encode()).hexdigest() != sha:
                    raise Invalid('Poetry inputs changed during locked export')
        verify(runtime)
        outcome = 'resolved'
        return {'pins': resolved, 'runtime': runtime, 'inputs': inputs, 'artifacts': records,
                'attempts': attempts,
                **({'candidate_lock': lock_name, 'validation': 'candidate-only'} if candidate_only else
                   {'authority': lock_name})}
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
