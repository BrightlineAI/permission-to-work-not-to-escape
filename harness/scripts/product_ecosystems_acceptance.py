#!/usr/bin/env python3
"""Native dependency journeys, with explicit coverage and no model calls."""
import argparse
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import zipfile
from types import SimpleNamespace
from unittest.mock import patch
from evidence_io import capture, reference, verify_wheel_identity

from ptw import onboarding
from ptw.monitor import ensure, remove
from ptw.policy import load, save
from ptw.store import Store
from ptw.supervisor import Supervisor
from ptw.workflow import dispatch
from ptw.workspace import request


CASES = ('new-python', 'existing-python', 'new-node', 'existing-node',
         'new-typescript', 'existing-typescript', 'existing-mixed-python-node', 'existing-workspace')

PROBES = {
    'private-npm': ('PrivateRegistryTests.test_local_authenticated_fixture_install_build_and_wrong_credentials', 'protected authenticated install/build/import'),
    'private-python': ('PrivatePythonTests.test_native_private_python_resolution_install_import_and_bad_credentials', 'protected authenticated resolve/install/import'),
    'narrow-workspace': ('WorkspaceSourceTests.test_native_narrower_workspace_import_and_excluded_source', 'protected narrower import/edit/import and unrelated-process control'),
    'uv-lock': ('NativeLockTests.test_actual_uv_locked_export_and_stale_manifest', 'native metadata export and stale-lock rejection'),
    'uv-update': ('DependencyRevisionTests.test_native_uv_constraint_only_update_can_downgrade', 'native metadata resolution with synthetic wheel evidence'),
    'revision-pty': ('DependencyRevisionTests.test_dependency_review_real_pty_rejection_and_approval', 'real review PTY with mocked native integrations'),
}


def terminal_setup(repo, state, args, out, *, refusals=()):
    """Drive the real CLI review; only the account-login check is replaced.

    Answers are scripted operator actions on synthetic projects. Resolution,
    publication, controller services and subsequent commands remain native.
    """
    from terminal_driver import Terminal
    script = ('from unittest.mock import patch\nfrom ptw.cli import main\n'
              'with patch("ptw.codex.require_login"):\n    main()\n')
    argv = [sys.executable, '-B', '-c', script, 'codex', '--repo', str(repo),
            '--language', args.language, '--goal', args.goal, '--editable', args.editable,
            '--files', args.files, '--setup-only']
    original = {str(p.relative_to(repo)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in repo.rglob('*') if p.is_file()}
    reviews = []
    for answer in (*refusals, 'yes'):
        terminal = Terminal(argv, out / ('review-' + answer),
                            env={'PTW_USER_STATE': str(state)})
        try:
            terminal.expect('Approve exactly this policy?', 180)
            terminal.send('details')
            terminal.expect('Approve exactly this policy? Type yes, customize, reject or cancel', 10)
            if answer == 'eof':
                os.write(terminal.fd, b'\x04')
            else:
                terminal.send(answer)
            terminal.wait(lambda: terminal.exited, 60)
        finally:
            code = terminal.close(graceful=False)
            reviews.append({'answer': answer, 'exit_code': code})
            save(terminal.folder / 'result.json', reviews[-1])
        expected = 0 if answer == 'yes' else 130 if answer == 'eof' else 2
        if code != expected:
            raise AssertionError('Terminal review failed; inspect ' + str(terminal.folder))
        if answer != 'yes':
            current = {str(p.relative_to(repo)): hashlib.sha256(p.read_bytes()).hexdigest()
                       for p in repo.rglob('*') if p.is_file()}
            if current != original or (repo / '.ptw').exists():
                raise AssertionError('Unapproved setup changed project files')
    save(out / 'reviews.json', reviews)
    with patch.dict(os.environ, {'PTW_USER_STATE': str(state)}):
        return load(onboarding.private_directory(repo) / 'project.json')


def revision(out, record, repo, state, *, ecosystem, root, source, operation, spec, group=None, refusals=()):
    """Native operator revision plus useful work under the replacement approval."""
    from terminal_driver import Terminal
    from ptw.python_local import prepared_sets
    from ptw.policy import Invalid
    store = Store(record['state'])
    previous = store.register(record['project'], 'work')
    with store.locked() as db:
        _, before = store.project(db, record['project'])
    history = store.status(record['project'])['violations']
    original = {str(p.relative_to(repo)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in repo.rglob('*') if p.is_file()}
    argv = [sys.executable, '-B', '-m', 'ptw', 'deps', operation, spec,
            '--repo', str(repo), '--ecosystem', ecosystem, '--root', root, '--source', source]
    if group:
        argv += ['--group', group]
    reviews = []
    for answer in (*refusals, 'yes'):
        terminal = Terminal(argv, out / ('review-' + answer), env={'PTW_USER_STATE': str(state)})
        try:
            terminal.expect('Approve dependency revision?', 180)
            terminal.send('details')
            terminal.expect('Approve exactly this dependency revision?', 10)
            if answer == 'eof':
                os.write(terminal.fd, b'\x04')
            else:
                terminal.send(answer)
            terminal.wait(lambda: terminal.exited, 180)
        finally:
            code = terminal.close(graceful=False)
            reviews.append({'answer': answer, 'exit_code': code})
            save(terminal.folder / 'result.json', reviews[-1])
        if code != (0 if answer == 'yes' else 130 if answer == 'eof' else 2):
            raise AssertionError('Dependency terminal failed; inspect ' + str(terminal.folder))
        if answer != 'yes':
            if original != {str(p.relative_to(repo)): hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in repo.rglob('*') if p.is_file()}:
                raise AssertionError('Unapproved dependency revision changed files')
    with store.locked() as db:
        _, current = store.project(db, record['project'])
        try:
            store.session(db, previous['token'])
        except Invalid:
            pass
        else:
            raise AssertionError('Prior session survived revision')
    opposite = 'npm_dependencies' if ecosystem == 'pypi' else 'python_dependencies'
    for key in (opposite, 'python_runtime', 'commands', 'grants', 'escalation'):
        if current['policy']['project'].get(key) != before['policy']['project'].get(key):
            raise AssertionError('Revision changed unrelated authority: ' + key)
    if store.status(record['project'])['violations'] != history:
        raise AssertionError('Revision reset violation history')
    actor = store.register(record['project'], 'work')
    sets = [r['package_set'] for r in prepared_sets(store, actor['token'])]
    local = bool(current['policy']['project'].get('python_dependencies', {}).get('sources'))
    installs, commands = [], []
    for resource, entry in current['inventory']['resources'].items():
        name = Path(entry['path']).name
        if name not in ('ptw-requirements.txt', 'package-lock.json') or name == 'ptw-requirements.txt' and local:
            continue
        result = dispatch(store, actor, 'revision-install-' + resource,
            request('install', resource, content='pypi' if name == 'ptw-requirements.txt' else 'npm'))
        installs.append(result)
        if not result.get('allowed'):
            raise AssertionError('Revised installation failed: ' + result.get('reason', 'unknown'))
        sets.append(result['package_set'])
    for command in sorted(current['policy']['project']['commands'], key=lambda c: ('test' in c['id'], c['id'])):
        result = dispatch(store, actor, 'revision-command-' + command['id'],
            request('run', command['id'], content=json.dumps({'package_sets': sets})))
        commands.append({'command': command['id'], 'result': result})
        if not result.get('allowed') or result.get('exit_code') != 0:
            raise AssertionError('Revised command failed: ' + command['id'])
    result = {'reviews': reviews, 'installs': installs, 'commands': commands,
              'local_prepared': local and bool(sets), 'violations': history,
              'policy_sha256': current['approval']['sha256']}
    save(out / 'revision.json', result)
    return result


def journey(out, case, *, terminal=False, revisions=False, installed_python=None):
    fixture = Path(__file__).resolve().parents[1] / 'examples/product-ecosystems'
    repo = out / 'repo'
    repo.mkdir(parents=True)
    language = 'mixed' if 'mixed' in case else case.split('-', 1)[1]
    roots = [('python', 'backend'), ('typescript', 'frontend')] if language == 'mixed' else [(language, '')]
    editable = []
    pending_sources = []
    for kind, root in roots:
        if case.startswith('new-'):
            # New project starts with declarations only. Application sources are
            # created through the broker after setup, not written around it.
            for path in (fixture / kind).iterdir():
                if path.is_file():
                    shutil.copyfile(path, repo / path.name)
            pending_sources = [p for p in (fixture / kind).rglob('*') if p.is_file() and p.parent != fixture / kind]
        else:
            shutil.copytree(fixture / kind, repo / root, dirs_exist_ok=True)
            if kind == 'typescript':
                (repo / root / 'dist').mkdir()
        editable.extend(str(Path(root) / name) for name in
                        (('src', 'tests') if kind == 'python' else ('src', 'dist') if kind == 'typescript' else
                         ('src', 'packages/math/src') if kind == 'workspace' else ('src',)))
    sensitive = repo / '.env'
    sensitive.write_text('SYNTHETIC_PRIVATE_FIXTURE_DO_NOT_READ\n')
    original = hashlib.sha256(sensitive.read_bytes()).hexdigest()
    (repo / 'README.md').write_text('Existing project history\n' if case.startswith('existing-') else 'New fixture\n')
    args = SimpleNamespace(language='javascript' if language in ('node', 'workspace') else language,
        goal='Run addition imports/tests/builds; never access .env', editable=','.join(editable), files='',
        warn_at=None, stop_at=None, history=None, model_proposal=False)
    state = out / 'operator'
    state.mkdir(mode=0o700)
    transcript = io.StringIO()
    started = time.monotonic()
    # This tests the real typed setup and controller. Only login and human input
    # are replaced: no model is invoked, and approval applies to these fixtures.
    if terminal:
        record = terminal_setup(repo, state, args, out,
            refusals=('reject', 'cancel', 'eof') if language == 'mixed' else ())
    else:
        with patch('ptw.codex.require_login'), patch('sys.stdin.isatty', return_value=True), \
                patch('builtins.input', return_value='yes'), redirect_stdout(transcript):
            record = onboarding.setup(repo, state, args)
        (out / 'review.txt').write_text(transcript.getvalue())
    store = Store(record['state'])
    results = {'setup_seconds': time.monotonic() - started, 'installs': [], 'commands': [],
               'review_mode': 'real PTY with scripted answers' if terminal else 'scripted input fixture'}
    unrelated = subprocess.Popen(['/usr/bin/sleep', '600'])
    try:
        ensure(store)
        if installed_python is not None:
            from ptw.monitor import call, unit_for
            pid = int(call('show', unit_for(store.directory), '--property=MainPID', '--value'))
            command = Path('/proc', str(pid), 'cmdline').read_bytes().split(b'\0')
            if command[:4] != [os.fsencode(installed_python), b'-B', b'-m', b'ptw.monitor']:
                raise AssertionError('Detached monitor does not use the tested wheel interpreter')
            results['monitor_python'] = os.fsdecode(command[0])
        session = store.register(record['project'], 'work')
        bundle = load(record['bundle'])
        inv = bundle['inventory']
        results['source_creates'] = []
        mapping = {entry['path']: resource for resource, entry in inv['resources'].items()}
        for index, path in enumerate(pending_sources):
            local = path.relative_to(fixture / language)
            resource = mapping[local.parts[0]]
            result = dispatch(store, session, 'create-' + str(index),
                              request('create', resource, str(Path(*local.parts[1:])), content=path.read_text()))
            results['source_creates'].append(result)
            if not result.get('allowed'):
                raise AssertionError('Protected source creation failed')
        results['edits'] = []
        for index, (kind, root) in enumerate(roots):
            filename = 'app.py' if kind == 'python' else 'app.ts' if kind == 'typescript' else 'app.mjs'
            resource = mapping[str(Path(root) / 'src')]
            current = dispatch(store, session, 'read-' + str(index), request('read', resource, filename))
            if not current.get('allowed'):
                raise AssertionError('Protected source read failed')
            content = current['content'] + ('\n#' if kind == 'python' else '\n//') + ' Protected acceptance edit\n'
            changed = dispatch(store, session, 'edit-' + str(index), request('write', resource, filename,
                content=content, expected=current['sha256']))
            results['edits'].append(changed)
            if not changed.get('allowed') or (repo / root / 'src' / filename).read_text() != content:
                raise AssertionError('Protected source edit did not produce the requested bytes')
        sets = []
        for resource, entry in inv['resources'].items():
            name = Path(entry['path']).name
            if name in ('ptw-requirements.txt', 'package-lock.json'):
                ecosystem = 'pypi' if name == 'ptw-requirements.txt' else 'npm'
                result = dispatch(store, session, 'install-' + resource, request('install', resource, content=ecosystem))
                results['installs'].append(result)
                if not result.get('allowed'):
                    raise AssertionError('Dependency installation failed: ' + result.get('reason', 'unknown'))
                sets.append(result['package_set'])
        # Build precedes test; Python also performs an actual nonempty unittest run.
        commands = sorted(bundle['policy']['project']['commands'], key=lambda c: ('test' in c['id'], c['id']))
        for command in commands:
            result = dispatch(store, session, 'command-' + command['id'],
                              request('run', command['id'], content=json.dumps({'package_sets': sets})))
            results['commands'].append({'command': command['id'], 'result': result})
            if not result.get('allowed') or result.get('exit_code') != 0:
                raise AssertionError('Protected command failed: ' + command['id'])
        if not any('test' in c['command'] for c in results['commands']):
            raise AssertionError('No useful test command ran')
        outputs = '\n'.join(c['result'].get('output', '') for c in results['commands'])
        for kind, _ in roots:
            marker = {'python': 'Ran 2 tests', 'node': 'NODE_IMPORT_OK 42',
                      'typescript': 'TYPESCRIPT_BUILD_OK 42',
                      'workspace': 'Workspace ESM and CommonJS imports passed'}[kind]
            if marker not in outputs:
                raise AssertionError('Useful execution output missing: ' + marker)
        if revisions:
            results['revisions'] = []
            for ecosystem, root, source, spec in (
                    ('pypi', 'backend', 'pyproject.toml', 'six>=1.16,<2'),
                    ('npm', 'frontend', 'package.json', 'typescript@>=5.8 <6')):
                results['revisions'].append(revision(out / ('revision-' + ecosystem), record, repo, state,
                    ecosystem=ecosystem, root=root, source=source, operation='update', spec=spec,
                    group='devDependencies' if ecosystem == 'npm' else None))
            session = store.register(record['project'], 'work')
        denied = dispatch(store, session, 'outside', request('read', '.env'))
        results['denial'] = denied
        if denied.get('allowed') or hashlib.sha256(sensitive.read_bytes()).hexdigest() != original:
            raise AssertionError('Forbidden resource was exposed or changed')
        for kind, root in roots:
            if kind == 'typescript' and not (repo / root / 'dist/app.js').is_file():
                raise AssertionError('No compiled TypeScript artifact was published')
        results['passed'] = True
    finally:
        try:
            store.stop(record['project'])
            Supervisor(store).reconcile()
            results['unrelated_process_alive_after_stop'] = unrelated.poll() is None
            if not results['unrelated_process_alive_after_stop']:
                results['passed'] = False
                raise AssertionError('Unrelated process did not survive project stop')
            remove(store)
        finally:
            unrelated.terminate()
            unrelated.wait(timeout=5)
            save(out / 'journey.json', results)
    return results


# Test-only wheel installation uses the release builder's source inventory and
# hashed build prerequisite. It neither builds a release nor installs Codex.
IDENTITY_PROBE = '''import hashlib, importlib.metadata, json, os, pathlib, ptw, sys
root = pathlib.Path(ptw.__file__).parent
distribution = importlib.metadata.distribution('permission-to-work-harness')
print(json.dumps({'path': str(root), 'prefix': sys.prefix,
    'pythonpath_present': 'PYTHONPATH' in os.environ,
    'direct_url': json.loads(distribution.read_text('direct_url.json') or '{}'),
    'hashes': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.glob('*.py')}}))
'''


def wheel_step(argv, out, env, *, cwd=None, timeout=120):
    """Retain private diagnostics; expose only their hashes in the receipt."""
    receipt = {'argv': [str(a) for a in argv], 'passed': False}
    started = time.monotonic()
    try:
        folder = out.with_suffix('.process')
        process = capture(argv, folder, env=env, cwd=cwd, timeout=timeout)
        receipt.update(exit_code=process.returncode,
            stdout_sha256=hashlib.sha256(process.stdout).hexdigest(),
            stderr_sha256=hashlib.sha256(process.stderr).hexdigest())
        receipt['probe'] = reference(out.parent, folder / 'process.json')
        # Preserve the existing diagnostic paths as well as streamed originals.
        out.with_suffix('.stdout').write_bytes(process.stdout)
        out.with_suffix('.stderr').write_bytes(process.stderr)
        if process.returncode:
            raise AssertionError('Wheel acceptance step failed; inspect ' + str(out))
        receipt['passed'] = True
        return process.stdout.decode()
    except BaseException as exc:
        receipt['error_type'] = type(exc).__name__
        raise
    finally:
        folder = out.with_suffix('.process')
        if (folder / 'process.json').is_file():
            receipt['probe'] = reference(out.parent, folder / 'process.json')
            for name in ('stdout', 'stderr'):
                if (folder / name).is_file():
                    data = (folder / name).read_bytes()
                    out.with_suffix('.' + name).write_bytes(data)
                    receipt[name + '_sha256'] = hashlib.sha256(data).hexdigest()
        receipt['seconds'] = time.monotonic() - started
        save(out, receipt)


def build_test_wheel(out):
    from build_product_release import BUILD_PIN, source_files
    from product_install import clean_env, validate_wheel
    out.mkdir(parents=True, exist_ok=False)
    _, sources = source_files(Path(__file__).resolve().parents[2])
    hashes = {Path(n).name: hashlib.sha256(data).hexdigest()
              for n, data in sources.items() if n.startswith('harness/ptw/')
              and len(Path(n).parts) == 3 and n.endswith('.py')}
    save(out / 'inputs.json', {'hashes': {n: hashlib.sha256(data).hexdigest()
                                        for n, data in sources.items()},
                             'build_lock_sha256': hashlib.sha256(BUILD_PIN.encode()).hexdigest()})
    env = clean_env(out)
    uv = shutil.which('uv')
    if not uv:
        raise AssertionError('Provision uv on PATH before wheel acceptance')
    save(out / 'tools.json', {'uv': str(Path(uv).resolve()),
        'uv_sha256': hashlib.sha256(Path(uv).read_bytes()).hexdigest(), 'python': sys.version})
    python = out / 'builder/bin/python'
    wheel_step([uv, '--no-config', 'venv', '--no-python-downloads', '--python', sys.executable,
                out / 'builder'], out / 'venv.json', env)
    (out / 'build.lock').write_text(BUILD_PIN)
    wheel_step([uv, '--no-config', 'pip', 'install', '--python', python, '--require-hashes',
                '--only-binary', ':all:', '--index-url', 'https://pypi.org/simple',
                '-r', out / 'build.lock'], out / 'prerequisites.json', env)
    source = out / 'source'
    for name, data in sources.items():
        if name == 'harness/pyproject.toml' or name.startswith('harness/ptw/'):
            target = source / name.removeprefix('harness/')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    wheels = out / 'wheels'
    wheels.mkdir()
    wheel_step([python, '-I', '-B', '-c',
        'import setuptools.build_meta,sys; setuptools.build_meta.build_wheel(sys.argv[1])', wheels],
        out / 'build.json', env, cwd=source)
    paths = list(wheels.glob('*.whl'))
    if len(paths) != 1:
        raise AssertionError('Expected exactly one application wheel')
    wheel = paths[0]
    import tomllib
    validate_wheel(wheel.read_bytes(), tomllib.loads(sources['harness/pyproject.toml'].decode())['project']['version'])
    with zipfile.ZipFile(wheel) as archive:
        recursive = {n: hashlib.sha256(archive.read(n)).hexdigest()
                     for n in archive.namelist() if n.startswith('ptw/')}
        actual = {Path(n).name: hashlib.sha256(archive.read(n)).hexdigest()
                  for n in archive.namelist() if n.startswith('ptw/') and n.endswith('.py')
                  and len(Path(n).parts) == 2}
    if actual != hashes:
        raise AssertionError('Built wheel differs from current source')
    expected = {n.removeprefix('harness/'): hashlib.sha256(data).hexdigest()
                for n, data in sources.items() if n.startswith('harness/ptw/')}
    if recursive != expected:
        raise AssertionError('Built wheel recursive runtime/package data differs from source')
    save(out / 'wheel.json', {'sha256': hashlib.sha256(wheel.read_bytes()).hexdigest(), 'modules': hashes})
    return wheel, hashes


def installed_journey(out, case, wheel, hashes):
    """Fresh wheel environment per case, including real detached-service import."""
    from product_install import clean_env
    out.mkdir(parents=True, exist_ok=False)
    env = clean_env(out)
    uv = shutil.which('uv')
    installation = out / 'installation'
    python = installation / 'bin/python'
    wheel_step([uv, '--no-config', 'venv', '--no-python-downloads', '--python', sys.executable,
                installation], out / 'venv.json', env)
    source = Path(__file__).resolve().parents[1]
    wheel_step([uv, '--no-config', 'pip', 'sync', '--python', python, '--require-hashes',
        '--only-binary', ':all:', '--index-url', 'https://pypi.org/simple',
        source / 'requirements.lock'], out / 'dependencies.json', env)
    wheel_step([uv, '--no-config', 'pip', 'install', '--python', python, '--no-deps', wheel],
               out / 'install.json', env)
    env['PATH'] = str(installation / 'bin') + os.pathsep + env.get('PATH', '')
    for mode in ('foreground', 'detached'):
        argv = [python, '-I', '-B', '-c', IDENTITY_PROBE]
        if mode == 'detached':
            # Match the real monitor's startup flags and service environment.
            # An inherited PYTHONPATH must fail identity validation, not be hidden
            # by an isolated probe that the real monitor does not use.
            unit = 'ptw-wheel-' + hashlib.sha256(str(out).encode()).hexdigest()[:24]
            argv = ['systemd-run', '--user', '--wait', '--pipe', '--collect', '--quiet',
                    '--unit=' + unit, python, '-B', '-c', IDENTITY_PROBE]
        identity = json.loads(wheel_step(argv, out / (mode + '-step.json'), env))
        save(out / (mode + '-identity.json'), identity)
        verify_wheel_identity(identity, installation, hashes)
    # Only the driver directory is on sys.path, never harness or its tests.
    script = ('import sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); '
              'from product_ecosystems_acceptance import journey; '
              'journey(Path(sys.argv[2]),sys.argv[3],terminal=True,installed_python=sys.executable)')
    wheel_step([python, '-I', '-B', '-c', script, str(source / 'scripts'),
                str(out / 'journey'), case], out / 'journey-step.json', env, cwd=out, timeout=360)
    identity = json.loads(wheel_step([python, '-I', '-B', '-c', IDENTITY_PROBE],
                                     out / 'after-step.json', env))
    verify_wheel_identity(identity, installation, hashes)
    save(out / 'after-identity.json', identity)
    result = load(out / 'journey/journey.json')
    if not result['passed'] or result.get('monitor_python') != str(python):
        raise AssertionError('Installed journey or monitor identity failed')
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--case', choices=CASES, action='append')
    parser.add_argument('--probe', choices=PROBES, action='append', help='Repeat to select native support probes; default all')
    args = parser.parse_args()
    out = args.out.absolute()
    out.mkdir(parents=True, mode=0o700, exist_ok=False)
    source = Path(__file__).resolve().parents[1]
    measured_sources = [*sorted((source / 'ptw').glob('*.py')),
        source / 'scripts/product_ecosystems_acceptance.py', source / 'tests/test_product_ecosystems.py',
        source / 'scripts/terminal_driver.py',
        source / 'tests/test_packages.py', source / 'tests/test_ecosystems.py',
        *sorted(p for p in (source / 'examples/product-ecosystems').rglob('*') if p.is_file())]
    report = {'passed': False, 'kind': 'scripted native dependency journeys; no model trajectories',
        'task_acceptance_complete': False,
        'not_covered': ['Adapter-specific checks live in the approved unittest suites',
                        'Fresh-wheel journeys and revision composition run through test_product_ecosystems',
                        'No live Codex conversation or first-install timing certification'],
        'source_hashes': {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in measured_sources}, 'cases': [], 'probes': []}
    for case in args.case or CASES:
        started = time.monotonic()
        try:
            result = journey(out / case, case, terminal=True)
        except Exception as exc:
            result = {'passed': False, 'error_type': type(exc).__name__, 'error': str(exc)}
        report['cases'].append({'case': case, 'elapsed_seconds': time.monotonic() - started, **result})
        save(out / ('case-' + case + '.json'), report['cases'][-1])
    for name in args.probe or PROBES:
        test, kind = PROBES[name]
        argv = [sys.executable, '-B', '-c',
            "import sys,unittest; sys.path.insert(0,sys.argv[1]); suite=unittest.defaultTestLoader.loadTestsFromName(sys.argv[2]); "
            "result=unittest.TextTestRunner(verbosity=2).run(suite); sys.exit(0 if result.wasSuccessful() and not result.skipped else 1)",
            str(source / 'tests'), 'test_product_ecosystems.' + test]
        started = time.monotonic()
        with (out / (name + '.log')).open('w') as log:
            try:
                proc = subprocess.run(argv, env={**os.environ, 'PTW_LINUX_TESTS': '1'},
                    stdout=log, stderr=subprocess.STDOUT, timeout=180)
                result = {'passed': proc.returncode == 0, 'exit_code': proc.returncode}
            except subprocess.TimeoutExpired:
                result = {'passed': False, 'error': 'Native probe exceeded 180 seconds'}
        report['probes'].append({'name': name, 'kind': kind, 'argv': argv,
            'elapsed_seconds': time.monotonic() - started, 'log': name + '.log', **result})
        save(out / ('probe-' + name + '.json'), report['probes'][-1])
    report['passed'] = all(c['passed'] for c in [*report['cases'], *report['probes']])
    save(out / 'result.json', report)
    print(json.dumps({'passed': report['passed'], 'task_acceptance_complete': False, 'evidence': str(out)}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
