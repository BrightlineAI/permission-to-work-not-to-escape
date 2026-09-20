"""Shared assertions over freshly measured private demo receipts; no test discovery hook."""
import copy
import json
import os
from pathlib import Path
import sqlite3
import time
from unittest.mock import patch

from evidence_io import digest, load, reference, save


def check_markdown(case, out):
    """Real original verification, with all network/model launches forbidden."""
    import product_demo
    import subprocess
    popen = subprocess.Popen
    identity_code = ("import json,platform,sys,sysconfig; print(json.dumps(dict("
                     "version=platform.python_version(), implementation=sys.implementation.name, "
                     "abi=sysconfig.get_config_var('SOABI'), prefix=sys.base_prefix)))")

    def identity_only(argv, *args, **kwargs):
        case.assertEqual(argv, [str(Path('/usr/bin/python3').resolve()), '-I', '-S', '-c', identity_code])
        case.assertFalse(kwargs.get('shell', False))
        return popen(argv, *args, **kwargs)

    summary = out.parent / 'summary.md'
    with patch('socket.socket', side_effect=AssertionError('Reporting opened a socket')), \
         patch('socket.create_connection', side_effect=AssertionError('Reporting used networking')), \
         patch('subprocess.Popen', side_effect=identity_only):
        result = product_demo.write_markdown(out, summary)
    text = summary.read_text()
    sample = load(out / 'public-sample.json')
    case.assertIn('# Vega demo: ' + result['demo'], text)
    case.assertIn(f'{result["warm_seconds"]:.3f} seconds', text)
    case.assertIn(sample['original_result_sha256'], text)
    case.assertIn(sample['public_payload_sha256'], text)
    case.assertIn(sample['payload']['source_fingerprint'], text)
    for claim in sample['payload']['claims']:
        case.assertIn(claim, text)
    for private in (str(out), '/home/', '/tmp/', 'Bearer ', 'session_meta', 'direct_url'):
        case.assertNotIn(private, text)
    case.assertIn('not fresh acceptance', text)
    case.assertIn('correctly configured underlying sandbox', text)
    case.assertIn('OS denials are not controller violations', text)


def check_envelope_mutations(case, out):
    import product_demo
    case.assertTrue(product_demo.verify(out)['verified'])
    check_markdown(case, out)
    rejected_summary = out.parent / 'rejected-summary.md'

    def reject(errors=(ValueError, OSError)):
        with case.assertRaises(errors):
            product_demo.verify(out)
        with case.assertRaises(errors):
            product_demo.write_markdown(out, rejected_summary)
        case.assertFalse(rejected_summary.exists(), 'Invalid evidence emitted a report')

    # Check the runtime verifier directly: neither a stale artifact hash nor the
    # public projection mismatch may mask an interpreter-identity defect.
    from demo_evidence import verify_tools
    versions = load(out / 'result.json')['versions']
    verify_tools(out, versions)
    for field in ('missing', 'version', 'sha256', 'executable', 'abi', 'receipt'):
        with case.subTest(system_python=field):
            changed = copy.deepcopy(versions)
            if field == 'missing':
                changed.pop('system_python')
            elif field == 'receipt':
                changed['system_python']['receipt'] = changed['tools']['nono']['receipt']
            else:
                changed['system_python'][field] = 'changed'
            with case.assertRaises((ValueError, OSError)):
                verify_tools(out, changed)
    end = load(out / 'result.json')
    result_bytes = (out / 'result.json').read_bytes()
    begin_bytes = (out / 'attempt.json').read_bytes()
    artifact_path = out / ({'dependency': 'cases/tolerant/import-observer/namespace.json',
                           'task-scope': 'cases/vega/temptation-process.json',
                           'swarm': 'cases/vega/chart/observer/namespace.json'}[end['demo']])
    original = artifact_path.read_bytes()
    for mode in ('missing', 'tampered', 'malformed', 'linked', 'unhashed'):
        with case.subTest(mode=mode):
            extra = out / 'extra.json'
            try:
                if mode == 'missing':
                    artifact_path.unlink()
                elif mode == 'tampered':
                    artifact_path.write_text('{}\n')
                elif mode == 'malformed':
                    artifact_path.write_text('{invalid json')
                elif mode == 'linked':
                    extra.write_bytes(original)
                    artifact_path.unlink()
                    artifact_path.symlink_to(extra)
                else:
                    extra.write_text('{}\n')
                reject()
            finally:
                if artifact_path.is_symlink():
                    artifact_path.unlink()
                artifact_path.write_bytes(original)
                extra.unlink(missing_ok=True)
    for mode in ('stale', 'future', 'version', 'python-version', 'source', 'expected-output', 'escaping', 'missing-reference', 'failed'):
        with case.subTest(mode=mode):
            begin, changed = load(out / 'attempt.json'), copy.deepcopy(end)
            try:
                if mode in ('stale', 'future'):
                    begin['started_epoch'] = time.time() + (3600 if mode == 'future' else -90000)
                    changed['started_epoch'] = begin['started_epoch']
                elif mode == 'version':
                    begin['installed']['dependency_versions']['permission-to-work-harness'] = '0.invalid'
                    changed['installed'] = begin['installed']
                elif mode == 'python-version':
                    begin['versions']['python'] = 'Python 0.invalid'
                    changed['versions'] = begin['versions']
                elif mode == 'source':
                    begin['source']['runtime_sha256'] = {}
                    changed['source'] = begin['source']
                elif mode == 'expected-output':
                    changed['comparison'] = {'result': 'invented green caption'}
                elif mode == 'escaping':
                    changed['artifacts'][0]['path'] = '../outside.json'
                elif mode == 'missing-reference':
                    changed['artifacts'].pop()
                else:
                    save(out / 'failed.json', {'complete': False})
                save(out / 'attempt.json', begin)
                save(out / 'result.json', changed)
                reject()
            finally:
                (out / 'attempt.json').write_bytes(begin_bytes)
                (out / 'result.json').write_bytes(result_bytes)
                (out / 'failed.json').unlink(missing_ok=True)
    # Rehashing a contradictory observation cannot turn it into measured evidence.
    try:
        observation = load(artifact_path)
        observation['processes' if end['demo'] == 'task-scope' else 'observations'] = []
        save(artifact_path, observation)
        changed = copy.deepcopy(end)
        changed['artifacts'] = [reference(out, artifact_path) if r['path'] == str(artifact_path.relative_to(out)) else r
                                for r in changed['artifacts']]
        save(out / 'result.json', changed)
        reject(ValueError)
    finally:
        artifact_path.write_bytes(original)
        (out / 'result.json').write_bytes(result_bytes)
    case.assertTrue(product_demo.verify(out)['verified'])
    sample_path = out / 'public-sample.json'
    original_sample = sample_path.read_bytes()
    sample = load(sample_path)
    from ptw.policy import digest as json_digest
    case.assertEqual(sample['public_payload_sha256'], json_digest(sample['payload']))
    case.assertEqual(sample['original_result_sha256'], digest(out / 'result.json'))
    for private in ('/home/', '/tmp/', 'Bearer ', 'session_meta', 'direct_url'):
        case.assertNotIn(private, original_sample.decode())
    try:
        sample['payload']['claims'].append('invented green caption')
        sample['public_payload_sha256'] = json_digest(sample['payload'])
        save(sample_path, sample)
        with case.assertRaisesRegex(ValueError, 'Public projection'):
            product_demo.verify(out)
        reject()
    finally:
        sample_path.write_bytes(original_sample)


def check_installed_cli(case, root, python, env, demo):
    """Real installed CLI/PTY checks. Called only by the mandatory native tests."""
    from terminal_driver import Terminal
    script = Path(__file__).resolve().parents[1] / 'scripts/product_demo.py'
    out = root / 'run'
    before = {name: digest(out / name) for name in ('attempt.json', 'result.json', 'public-sample.json')}
    other = 'task-scope' if demo == 'dependency' else 'dependency'
    for label, arguments, expected in (
            ('verify', ['verify', '--out', out], 0),
            ('verify-explicit', ['verify', '--demo', demo, '--out', out], 0),
            ('markdown', ['verify', '--demo', demo, '--out', out, '--markdown', root / 'cli-summary.md'], 0),
            ('wrong-demo', ['verify', '--demo', other, '--out', out], 2),
            ('wrong-markdown-demo', ['verify', '--demo', other, '--out', out,
                                     '--markdown', root / 'wrong-summary.md'], 2),
            ('markdown-reuse', ['verify', '--out', out, '--markdown', root / 'cli-summary.md'], 2),
            ('reuse', ['run', '--demo', demo, '--out', out], 2)):
        terminal = Terminal([python, '-B', script, *arguments], root / ('cli-' + label),
                            env=env, replace_env=True)
        try:
            terminal.wait(lambda: terminal.exited, 30, label)
            case.assertEqual(terminal.close(graceful=False), expected, terminal.text)
            if expected == 0:
                result = json.loads(terminal.text.strip())
                case.assertTrue(result['verified'])
                case.assertEqual(result['demo'], demo)
            else:
                case.assertIn('Demo failed:', terminal.text)
        finally:
            terminal.close(graceful=False)
    case.assertEqual(before, {name: digest(out / name) for name in before})
    case.assertFalse((out / 'failed.json').exists(), 'Reuse must not corrupt completed evidence')
    case.assertFalse((root / 'wrong-summary.md').exists())
    case.assertIn('# Vega demo: ' + demo, (root / 'cli-summary.md').read_text())

    # Interrupt an actual registered operation, not a stub or a timer before launch.
    from ptw.supervisor import Supervisor
    interrupted = root / 'interrupted'
    arm = interrupted / 'cases' / ('tolerant' if demo == 'dependency' else 'vega')
    marker = ('/target/source/src/invoice_dep/__init__.py' if demo == 'dependency'
              else '/target/A/worker.py')
    fixture = arm / ('repo/src/invoice_dep/__init__.py' if demo == 'dependency' else 'repo/A/worker.py')
    if demo == 'swarm':
        marker, fixture = '/target/src/worker.py', arm / 'repo/src/worker.py'
    observed = []

    def active_payload():
        database = arm / 'controller/state.sqlite3'
        if not database.is_file() or not fixture.is_file():
            return False
        with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
            if not db.execute("SELECT 1 FROM sqlite_master WHERE name='workloads'").fetchone():
                return False  # The new controller is still initializing.
            units = [r[0] for r in db.execute('SELECT unit FROM workloads WHERE stopped=0')]
        for unit in units:
            group = Supervisor.state(unit).get('ControlGroup')
            if not group:
                continue
            for members in Path('/sys/fs/cgroup' + group).rglob('cgroup.procs'):
                try:
                    pids = members.read_text().split()
                except FileNotFoundError:
                    continue
                for pid in pids:
                    proc = Path('/proc') / pid
                    try:
                        if (os.readlink(proc / 'ns/net') == os.readlink('/proc/self/ns/net') or
                                digest(proc / 'root' / marker.lstrip('/')) != digest(fixture)):
                            continue
                        ticks = proc.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19]
                        observed.append({'pid': int(pid), 'start_ticks': ticks, 'unit': unit})
                        return True
                    except (FileNotFoundError, ProcessLookupError, PermissionError):
                        continue
        return False

    terminal = Terminal([python, '-B', script, 'run', '--demo', demo, '--out', interrupted],
                        root / 'cli-interrupt', env=env, replace_env=True)
    try:
        terminal.wait(active_payload, 60, 'registered payload before terminal interruption')
        save(root / 'interrupt-observation.json', observed)
        terminal.inputs.append({'seconds': time.monotonic() - terminal.started,
                                'text': '\x03', 'mode': 'interrupt'})
        terminal._save_inputs()
        os.write(terminal.fd, b'\x03')  # Ctrl-C only; never send Enter into cleanup.
        terminal.wait(lambda: terminal.exited, 30, 'interrupted demo cleanup')
        case.assertEqual(terminal.close(graceful=False), 130, terminal.text)
        case.assertIn('Interrupted; retain the failed attempt.', terminal.text)
    finally:
        terminal.close(graceful=False)
    case.assertEqual(load(interrupted / 'failed.json')['error_type'], 'KeyboardInterrupt')
    case.assertFalse((interrupted / 'result.json').exists())
    for row in observed:
        case.assertTrue(Supervisor.state(row['unit'])['confirmed_stopped'])
        try:
            ticks = (Path('/proc') / str(row['pid']) / 'stat').read_text().rsplit(')', 1)[1].split()[19]
        except (FileNotFoundError, ProcessLookupError):
            continue
        case.assertNotEqual(ticks, row['start_ticks'], 'Interrupted payload still exists')
    terminal = Terminal([python, '-B', script, 'verify', '--out', interrupted],
                        root / 'cli-verify-interrupted', env=env, replace_env=True)
    try:
        terminal.wait(lambda: terminal.exited, 30, 'reject interrupted evidence')
        case.assertEqual(terminal.close(graceful=False), 2, terminal.text)
        case.assertIn('Demo failed:', terminal.text)
    finally:
        terminal.close(graceful=False)
