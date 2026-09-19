"""Audit acceptance: deterministic fixtures, not spontaneous model evidence."""
import copy
import concurrent.futures
import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path
import threading
import time
import unittest
import uuid
from unittest.mock import patch

from ptw.event_evidence import verify_export
from ptw.policy import Invalid, canonical, digest
from ptw.store import Store
from ptw.workspace import Workspace, request
from ptw.evidence_storage import DEFAULT, PAYLOAD_BYTES, RETENTION_SECONDS, QuotaError
import test_workspace as workspace_fixtures
import test_product_daily as daily_fixtures
import test_product_ecosystems as ecosystem_fixtures
import test_product_python_local as local_fixtures


def _diagnostic_command(argv):
    """Bound private native observations in time and bytes, including errors."""
    import select
    import subprocess
    limit = 64 * 1024
    output = bytearray()
    deadline = time.monotonic() + 10
    with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as child:
        try:
            while len(output) <= limit and time.monotonic() < deadline:
                if select.select([child.stdout], [], [], min(.1, max(0, deadline - time.monotonic())))[0]:
                    chunk = os.read(child.stdout.fileno(), min(4096, limit + 1 - len(output)))
                    if not chunk:
                        break
                    output.extend(chunk)
            truncated = len(output) > limit
            timed_out = time.monotonic() >= deadline
            if not truncated and not timed_out:
                try:
                    child.wait(timeout=max(.01, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    timed_out = True
        finally:
            if child.poll() is None:
                child.kill()
            child.wait()
    return {'exit_code': child.returncode, 'truncated': truncated, 'timed_out': timed_out,
            'output': bytes(output[:limit]).decode('utf-8', errors='replace')}


def _monitor_diagnostics(directory, since):
    """Observe before Store construction/recovery or cleanup alters the fixture."""
    from ptw.monitor import unit_for
    from ptw.onboarding import data
    controller = directory / 'controller'
    unit = unit_for(controller)
    report = {'unit': unit, 'since_epoch': since, 'observed_epoch': time.time()}
    def observe(name, read):
        try:
            report[name] = {'status': 'observed', 'value': read()}
        except Exception as exc:
            report[name] = {'status': 'unavailable', 'exception': type(exc).__name__}
    def metadata(path, keys):
        value = json.loads(data(path, 256 * 1024))
        return {key: value.get(key) for key in keys}
    observe('setup', lambda: metadata(directory / 'setup-journal.json', ('phase',)))
    observe('runtime_identity', lambda: metadata(controller / 'monitor-identity.json', (
        'role', 'pid', 'measured_epoch', 'executable', 'prefix', 'module_root',
        'interpreter_sha256', 'runtime_sha256', 'imported_ptw_modules',
        'pythonpath_present', 'pythonhome_present')))
    # Read-only SQLite, without Store's recovery or registered custom functions.
    # Do not copy bundles, tokens, grants, replay bodies, or the whole database.
    try:
        with sqlite3.connect((controller / 'state.sqlite3').as_uri() + '?mode=ro', uri=True, timeout=1) as db:
            db.row_factory = sqlite3.Row
            for name, columns in (
                    ('monitor_health', 'id,at,substr(error,1,256) AS error'),
                    ('projects', 'id,stopped,violations,setup_pending'),
                    ('workloads', 'unit,project,session,stopped')):
                def rows(name=name, columns=columns):
                    values = [dict(r) for r in db.execute('SELECT ' + columns + ' FROM ' + name + ' LIMIT 33')]
                    return {'rows': values[:32], 'truncated': len(values) > 32}
                observe(name, rows)
    except Exception as exc:
        report['database'] = {'status': 'unavailable', 'exception': type(exc).__name__}
    observe('service', lambda: _diagnostic_command(['systemctl', '--user', 'show', unit,
        '--property=LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,MainPID,NRestarts']))
    observe('journal', lambda: _diagnostic_command(['journalctl', '--user', '--unit=' + unit,
        '--since=@' + str(since), '--no-pager', '--lines=80', '--output=short-precise']))
    return report


class AuditMonitorRecoveryTests(workspace_fixtures.WorkspaceFixture):
    def serve_iterations(self, count=1, *, outcomes=()):
        from ptw.monitor import serve
        class EndProbe(BaseException):
            pass
        with patch('ptw.monitor.Supervisor.reconcile', return_value=list(outcomes)) as reconcile, \
                patch('ptw.monitor.time.sleep', side_effect=[None] * (count - 1) + [EndProbe()]), \
                self.assertRaises(EndProbe):
            serve(self.store.directory)
        self.assertEqual(reconcile.call_count, count)

    def test_restart_refreshes_identity_without_changing_audit_history(self):
        from ptw.monitor import health
        from ptw.policy import load, save
        destination = self.store.directory / 'monitor-identity.json'
        save(destination, {'role': 'monitor', 'pid': -1})
        save(destination.with_suffix('.pending'), {'interrupted': True})
        before = self.store.audit_export('python-demo')
        for pid in (101, 202):
            with patch('ptw.runtime_identity.snapshot', return_value={'role': 'monitor', 'pid': pid}):
                self.serve_iterations()
            self.assertEqual(load(destination), {'role': 'monitor', 'pid': pid})
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
            self.assertFalse(destination.with_suffix('.pending').exists())
            self.assertTrue(health(self.store)['healthy'])
            self.assertEqual(health(self.store)['error'], '')
        self.assertEqual(self.store.audit_export('python-demo'), before)
        self.assertTrue(self.ask('read')['allowed'])

    def test_identity_capture_failure_preserves_reconciliation_and_is_visible(self):
        import io
        from ptw.monitor import health
        from ptw.policy import load, save
        destination = self.store.directory / 'monitor-identity.json'
        previous = {'role': 'monitor', 'pid': -1}
        save(destination, previous)
        before = self.store.audit_export('python-demo')
        for writer in ('ptw.policy.save', 'ptw.monitor.os.replace'):
            with self.subTest(writer=writer), patch(writer, side_effect=OSError('PRIVATE')), \
                    patch('sys.stderr', io.StringIO()) as output:
                self.serve_iterations(2, outcomes=[{'confirmed_stopped': False, 'evidence': 'unavailable'}])
            self.assertEqual(load(destination), previous)
            self.assertFalse(destination.with_suffix('.pending').exists())
            self.assertEqual(health(self.store)['error'],
                             'termination evidence unavailable; runtime identity unavailable')
            self.assertTrue(health(self.store)['healthy'])
            self.assertIn('runtime-identity', output.getvalue())
            self.assertNotIn('PRIVATE', output.getvalue())
        self.assertEqual(self.store.audit_export('python-demo'), before)
        self.assertEqual(self.store.status('python-demo')['violations'], 0)
        self.assertFalse(self.store.status('python-demo')['stopped'])
        self.serve_iterations()
        self.assertEqual(load(destination)['pid'], os.getpid())
        self.assertEqual(health(self.store)['error'], '')

    def test_identity_replacement_does_not_follow_links(self):
        from ptw.monitor import record_identity
        from ptw.policy import load
        control = self.root / 'unrelated'
        control.write_text('UNCHANGED')
        destination = self.store.directory / 'monitor-identity.json'
        destination.symlink_to(control)
        destination.with_suffix('.pending').symlink_to(control)
        record_identity(self.store, {'role': 'monitor', 'pid': os.getpid()})
        self.assertEqual(control.read_text(), 'UNCHANGED')
        self.assertFalse(destination.is_symlink())
        self.assertEqual(load(destination)['pid'], os.getpid())
        self.assertFalse(destination.with_suffix('.pending').exists())


class AuditMonitorDiagnosticTests(unittest.TestCase):
    def test_first_failure_is_bounded_and_omits_exception_payloads(self):
        import io
        from ptw.monitor import serve
        class EndProbe(BaseException):
            pass
        output = io.StringIO()
        with patch('ptw.monitor.Store', side_effect=OSError('PRIVATE_EXCEPTION_PAYLOAD')), \
                patch('ptw.monitor.time.sleep', side_effect=[None, EndProbe()]), \
                patch('sys.stderr', output), self.assertRaises(EndProbe):
            serve('/unused-fixture')
        lines = output.getvalue().splitlines()
        records = [json.loads(line.removeprefix('PTW_MONITOR_FIRST_FAILURE '))
                   for line in lines if line.startswith('PTW_MONITOR_FIRST_FAILURE ')]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['stage'], 'store-recovery')
        self.assertEqual(records[0]['exception'], 'OSError')
        self.assertTrue(0 < len(records[0]['frames']) <= 8)
        self.assertTrue(any(frame['function'] == 'serve' for frame in records[0]['frames']))
        self.assertNotIn('PRIVATE_EXCEPTION_PAYLOAD', output.getvalue())
        self.assertNotIn('/unused-fixture', output.getvalue())
        self.assertEqual(lines.count('OSError: monitor retry'), 2)

    def test_observation_preserves_unknowns_and_excludes_private_fields(self):
        import tempfile
        from ptw.policy import save
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            (directory / 'controller').mkdir()
            save(directory / 'setup-journal.json', {'phase': 'rolled-back', 'record': {'token': 'PRIVATE'}})
            save(directory / 'controller/monitor-identity.json', {'role': 'monitor', 'environment': 'PRIVATE'})
            with sqlite3.connect(directory / 'controller/state.sqlite3') as db:
                db.execute('CREATE TABLE monitor_health(id,at,error)')
                db.execute('INSERT INTO monitor_health VALUES(1,123,?)', ('x' * 1000,))
                db.execute('CREATE TABLE projects(id,stopped,violations,setup_pending,bundle)')
                db.execute("INSERT INTO projects VALUES('fixture',1,0,1,'PRIVATE')")
                db.execute('CREATE TABLE workloads(unit,project,session,stopped)')
                db.executemany('INSERT INTO workloads VALUES(?,?,?,?)',
                               [(str(i), 'fixture', 'session', 0) for i in range(35)])
            with patch(__name__ + '._diagnostic_command', side_effect=FileNotFoundError):
                result = _monitor_diagnostics(directory, 120)
            self.assertEqual(result['setup']['value'], {'phase': 'rolled-back'})
            self.assertIsNone(result['runtime_identity']['value']['pid'])
            self.assertEqual(result['projects']['value']['rows'][0]['stopped'], 1)
            self.assertEqual(len(result['monitor_health']['value']['rows'][0]['error']), 256)
            self.assertEqual(len(result['workloads']['value']['rows']), 32)
            self.assertTrue(result['workloads']['value']['truncated'])
            self.assertEqual(result['journal']['status'], 'unavailable')
            self.assertEqual(result['service']['exception'], 'FileNotFoundError')
            self.assertNotIn('PRIVATE', canonical(result))

    def test_command_capture_bounds_output_and_records_failure(self):
        result = _diagnostic_command([sys.executable, '-c', 'print("x" * 100000)'])
        self.assertTrue(result['truncated'])
        self.assertEqual(len(result['output']), 64 * 1024)
        failed = _diagnostic_command([sys.executable, '-c', 'import sys; print("fixture error"); sys.exit(7)'])
        self.assertEqual(failed['exit_code'], 7)
        self.assertEqual(failed['output'].strip(), 'fixture error')
        self.assertFalse(failed['timed_out'])
        self.assertFalse(failed['truncated'])


@unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'Requires native local builds and supervisor')
class AuditLocalPythonTests(unittest.TestCase):
    """Reuse local-source fixtures without discovering their suites twice."""

    def fixture(self, *, combined=False, pending=True):
        fixture = (local_fixtures.CombinedLocalPythonTests() if combined else local_fixtures.LocalPythonTests())
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.policy['project']['audit'] = copy.deepcopy(DEFAULT)
        if combined:
            store, bundle = fixture.activate()
            actor = None
        else:
            fixture.editable_policy()
            store, actor, bundle = fixture.activate(pending=pending)
        def cleanup():
            from ptw.monitor import remove
            from ptw.supervisor import Supervisor
            store.stop('local-python')
            Supervisor(store).reconcile()
            remove(store)
        self.addCleanup(cleanup)
        return fixture, store, actor, bundle

    def install(self, fixture, store, actor, bundle):
        if actor is None:
            with patch('ptw.registry.provider_for', return_value=fixture.provider):
                return fixture.prepare(store, bundle)[0]
        from ptw.python_local import install_editable
        return install_editable(store, actor['token'], 'local')

    def publication(self, store):
        document = store.audit_export('local-python')
        rows = [r for r in document['events'] if r['request']['action'] == 'local_publication']
        self.assertEqual(len(rows), 1)
        return rows[0], document

    def assert_fault(self, store):
        self.assertTrue(store.status('local-python')['stopped'])
        self.assertEqual(store.status('local-python')['violations'], 0)
        with store.locked() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM package_sets').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT count(*) FROM package_assessments').fetchone()[0], 0)
        with self.assertRaises(Invalid):
            store.register('local-python', 'work')

    def test_single_and_combined_publication_link_real_import_and_editable_reuse(self):
        from ptw.python_local import validate_prepared_setup
        from ptw.workspace import scan, stamp
        for combined in (False, True):
            with self.subTest(combined=combined):
                fixture, store, preparation, bundle = self.fixture(combined=combined)
                receipt = self.install(fixture, store, preparation, bundle)
                event, document = self.publication(store)
                facts = event['audit']['details']
                self.assertEqual(event['state'], 'complete')
                self.assertEqual(event['audit']['decision'], 'allow')
                self.assertEqual(facts['receipt_sha256'], digest({k: v for k, v in receipt.items() if k != 'package_set'}))
                self.assertEqual(facts['manifest_sha256'], receipt['manifest_sha256'])
                self.assertEqual(facts['package_set'], receipt['package_set'])
                self.assertEqual(document['assessments'][0]['audit']['cause'], event['audit']['operation_id'])
                self.assertEqual(event['audit']['authorization']['method'], 'controller_transition')
                self.assertFalse(event['audit']['authorization']['human_review_performed'])
                self.assertEqual(len(facts['preparations']), 2 if combined else 1)
                with store.locked() as db:
                    for part in facts['preparations']:
                        session = db.execute('SELECT * FROM sessions WHERE id=?', (part['session'],)).fetchone()
                        self.assertEqual(session['preparation_source'], part['source_id'])
                        self.assertEqual(bool(session['closed']), combined)
                if combined:
                    self.assertIsNone(event['audit']['session'])
                else:
                    self.assertEqual(event['audit']['session'], preparation['session'])
                    self.assertNotIn(preparation['token'], canonical(document))
                    store.close_session(preparation['token'])
                store.commit_setup('local-python', bundle['approval']['sha256'],
                                   lambda: validate_prepared_setup(store, bundle, [receipt]))
                actor = store.register('local-python', 'work')
                workspace = Workspace(store)
                command = 'both' if combined else 'local-import'
                body = request('run', command, content=json.dumps({'package_sets': [receipt['package_set']]}))
                first = workspace.request(actor['token'], 'import-before', body)
                self.assertTrue(first['allowed'], first)
                self.assertEqual(first['exit_code'], 0, first)
                self.assertEqual(first['output'].strip(), '42 17 SYNTHETIC_PACKAGE_OK' if combined else '42')
                source = fixture.sources[0] if combined else fixture.source
                resource = source['editable_resources'][0]
                path = 'local_one/__init__.py' if combined else 'local_demo/__init__.py'
                entry = scan(fixture.inv, [resource])[fixture.inv['resources'][resource]['path'] + '/' + path]
                self.assertTrue(workspace.request(actor['token'], 'live-edit', request('write', resource,
                    path, content='VALUE=99\n', expected=stamp(entry)))['allowed'])
                with patch('ptw.python_local.run_build', side_effect=AssertionError('unexpected rebuild')):
                    second = workspace.request(actor['token'], 'import-after', body)
                self.assertEqual(second['exit_code'], 0, second)
                self.assertEqual(second['output'].strip(), '99 17 SYNTHETIC_PACKAGE_OK' if combined else '99')
                verify_export(document, digest(document))
                altered = copy.deepcopy(document)
                altered['assessments'][0]['audit']['cause'] = '0' * 64
                with self.assertRaises(Invalid):
                    verify_export(altered, digest(document))

    def test_quota_admission_precedes_rename_for_single_and_combined(self):
        from ptw.evidence_storage import usage
        for combined in (False, True):
            with self.subTest(combined=combined):
                fixture, store, actor, bundle = self.fixture(combined=combined)
                lifecycle = store.lifecycle
                def limited(db, project, action, **kwargs):
                    result = lifecycle(db, project, action, **kwargs)
                    if action == 'local_publication':
                        # Inject a private logical quota after intent admission,
                        # leaving no room for the package row or assessment.
                        db.execute('UPDATE evidence_profiles SET profile=? WHERE project=?',
                                   (canonical({**DEFAULT, 'project_bytes': usage(db, project) + 1}), project))
                    return result
                from ptw.python_local import os as local_os
                rename = local_os.rename
                effects = []
                def observed(src, dst, *args, **kwargs):
                    if Path(dst).parent == store.directory / 'package-sets':
                        effects.append(str(dst))
                    return rename(src, dst, *args, **kwargs)
                with patch.object(store, 'lifecycle', side_effect=limited), patch('ptw.python_local.os.rename', side_effect=observed):
                    with self.assertRaises(QuotaError):
                        self.install(fixture, store, actor, bundle)
                self.assertEqual(effects, [])
                self.assert_fault(store)
                self.assertFalse(list((store.directory / 'package-sets').glob('*')))
                recovered = Store(store.directory)
                self.assertEqual(self.publication(recovered)[0]['state'], 'uncertain')

    def test_capture_faults_stop_without_publication_or_unrelated_damage(self):
        from ptw.supervisor import Supervisor
        control = workspace_fixtures.WorkspaceFixture()
        control.setUp()
        self.addCleanup(control.doCleanups)
        for phase in ('intent', 'assessment', 'completion'):
            with self.subTest(phase=phase):
                fixture, store, actor, bundle = self.fixture(pending=False)
                running = []
                for owner, session in ((store, actor), (control.store, control.actor)):
                    process, unit = Supervisor(owner).engine(session['token'], ['/usr/bin/sleep', '90'])
                    running.append((process, unit))
                    def cleanup_process(owner=owner, process=process, unit=unit):
                        Supervisor(owner).terminate(unit)
                        process.communicate(timeout=10)
                    self.addCleanup(cleanup_process)
                self.assertTrue(all(process.poll() is None for process, _ in running))
                target = {'intent': "BEFORE INSERT ON events WHEN NEW.event LIKE 'local_publication:%'",
                          'assessment': 'BEFORE INSERT ON package_assessments',
                          'completion': "BEFORE UPDATE ON events WHEN NEW.event LIKE 'local_publication:%' AND NEW.state='complete'"}[phase]
                with store.locked() as db:
                    db.execute('CREATE TRIGGER fail_local ' + target +
                               " BEGIN SELECT RAISE(FAIL,'injected local capture fault'); END")
                from ptw.python_local import os as local_os
                rename = local_os.rename
                effects = []
                def observed(src, dst, *args, **kwargs):
                    result = rename(src, dst, *args, **kwargs)
                    if Path(dst).parent == store.directory / 'package-sets':
                        effects.append((Path(dst) / 'local_demo.pth').read_text())
                    return result
                with patch('ptw.python_local.os.rename', side_effect=observed):
                    with self.assertRaisesRegex(sqlite3.Error, 'injected local capture fault'):
                        self.install(fixture, store, actor, bundle)
                self.assertEqual(bool(effects), phase == 'completion')
                self.assert_fault(store)
                self.assertFalse(list((store.directory / 'package-sets').glob('*')))
                with store.locked() as db:
                    db.execute('DROP TRIGGER fail_local')
                    units = [r['unit'] for r in db.execute('SELECT unit FROM workloads')]
                self.assertTrue(units)
                self.assertTrue(all(Supervisor.state(unit)['confirmed_stopped'] for unit in units))
                self.assertTrue(Supervisor.state(running[0][1])['confirmed_stopped'])
                self.assertIsNone(running[1][0].poll())
                self.assertTrue(control.ask('read')['allowed'])
                self.assertFalse(control.store.status('python-demo')['stopped'])
                self.assertEqual(fixture.private.read_text(), 'UNRELATED_LOCAL_SOURCE')
                self.assertEqual(fixture.external.read_text(), 'EXTERNAL_CONTROL')

    def test_abrupt_publication_death_preserves_unknown_and_blocks_retry(self):
        import multiprocessing
        from ptw.python_local import os as local_os
        rename = local_os.rename
        for after in (False, True):
            with self.subTest(after_rename=after):
                fixture, store, actor, bundle = self.fixture(combined=after)
                marker = fixture.root / 'effect.json'
                def crash(src, dst, *args, **kwargs):
                    if Path(dst).parent != store.directory / 'package-sets':
                        return rename(src, dst, *args, **kwargs)
                    if after:
                        rename(src, dst, *args, **kwargs)
                    marker.write_text(json.dumps({'destination': str(dst), 'exists': Path(dst).exists()}))
                    os._exit(77)
                def run():
                    with patch('ptw.python_local.os.rename', side_effect=crash):
                        self.install(fixture, store, actor, bundle)
                child = multiprocessing.get_context('fork').Process(target=run)
                child.start()
                try:
                    child.join(60)
                    self.assertEqual(child.exitcode, 77)
                finally:
                    if child.is_alive():
                        child.kill()
                        child.join(5)
                measured = json.loads(marker.read_text())
                self.assertEqual(measured['exists'], after)
                self.assertEqual(Path(measured['destination']).is_dir(), after)
                recovered = Store(store.directory)
                self.assert_fault(recovered)
                event, _ = self.publication(recovered)
                self.assertEqual(event['state'], 'uncertain')
                self.assertEqual(event['audit']['outcome'], 'unknown')
                with patch('ptw.python_local.run_build') as build:
                    with self.assertRaises(Invalid):
                        self.install(fixture, recovered, actor, bundle)
                build.assert_not_called()

    def test_changed_authority_and_tampered_local_receipt_cannot_publish(self):
        from ptw.python_local import publish_install
        for changed in ('authority', 'receipt'):
            with self.subTest(changed=changed):
                fixture, store, actor, bundle = self.fixture()
                def altered(*args, **kwargs):
                    if changed == 'authority':
                        store.stop('local-python')
                    else:
                        args[-1]['manifest_sha256'] = '0' * 64
                    return publish_install(*args, **kwargs)
                with patch('ptw.python_local.publish_install', side_effect=altered):
                    with self.assertRaises(Invalid):
                        self.install(fixture, store, actor, bundle)
                self.assertFalse(list((store.directory / 'package-sets').glob('*')))
                with store.locked() as db:
                    self.assertEqual(db.execute('SELECT count(*) FROM package_sets').fetchone()[0], 0)
                self.assertFalse(any(r['request']['action'] == 'local_publication'
                                     for r in store.audit_export('local-python')['events']))
                self.assertEqual(store.status('local-python')['violations'], 0)

    def test_terminal_local_capture_failure_and_reviewed_useful_retry(self):
        import tempfile
        from ptw.onboarding import private_directory
        from ptw.policy import load, save
        from ptw.python_local import prepared_sets
        from ptw.monitor import remove
        from ptw.supervisor import Supervisor
        fixture = local_fixtures.LocalSetupTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        scripts = str(Path(__file__).resolve().parents[1] / 'scripts')
        with patch.object(sys, 'path', [scripts, *sys.path]):
            from terminal_driver import Terminal
        # Retain the real PTY diagnostics outside fixture cleanup. An exit-code
        # mismatch alone cannot distinguish a product fault from a native-tool
        # failure, and repeating a failed journey without its output loses evidence.
        evidence = Path(tempfile.mkdtemp(prefix='ptw-audit-local-terminal-'))
        harness = Path(__file__).resolve().parents[1]
        sources = [Path(__file__).resolve(), Path(local_fixtures.__file__).resolve(),
                   harness / 'scripts/terminal_driver.py', harness.parent / 'MANIFEST.sha256',
                   *(p for p in (harness / 'ptw').rglob('*') if p.is_file()
                     and '__pycache__' not in p.parts and p.suffix not in ('.pyc', '.pyo'))]
        save(evidence / 'sources.json', {str(p.relative_to(harness.parent)):
             hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(sources)})
        print('AUDIT_LOCAL_TERMINAL_EVIDENCE ' + str(evidence), flush=True)
        state = fixture.root / 'terminal-state'
        with patch.dict(os.environ, {'PTW_USER_STATE': str(state)}):
            directory = private_directory(fixture.repo)
        for fault in (True, False):
            since = time.time()
            diagnostics = None
            terminal = Terminal([sys.executable, str(Path(local_fixtures.__file__).resolve()),
                '--local-publication-fault-fixture' if fault else '--local-setup-fixture',
                'codex', '--repo', str(fixture.repo), '--goal', 'Audit local setup', '--language', 'python',
                '--editable', 'src,backend,tests', '--files', '', '--python-editable', 'src', '--setup-only'],
                evidence / ('terminal-fault' if fault else 'terminal-success'), env={'PTW_USER_STATE': str(state)})
            try:
                terminal.expect('Approve exactly', 20)
                self.assertIn('execute backend offline after approval', terminal.text)
                terminal.send('yes')
                terminal.wait(lambda: terminal.exited, 90)
                diagnostics = _monitor_diagnostics(directory, since)
                self.assertEqual(terminal.close(), 2 if fault else 0,
                                 'Inspect retained PTY evidence: ' + str(terminal.folder))
                store = Store(directory / 'controller')
                if fault:
                    self.assertNotIn('Approved.', terminal.text)
                    self.assertFalse((fixture.repo / '.ptw').exists())
                    project = load(directory / 'setup-journal.json')['record']['project']
                    self.assertTrue(store.status(project)['stopped'])
                    events = store.audit_export(project)['events']
                    self.assertTrue(any(r['request']['action'] == 'local_publication' and
                                        r['state'] == 'uncertain' for r in events))
                else:
                    self.assertIn('Approved.', terminal.text)
                    record = load(directory / 'project.json')
                    project = record['project']
                    actor = store.register(project, 'work')
                    receipts = prepared_sets(store, actor['token'])
                    self.assertEqual(len(receipts), 1)
                    result = Workspace(store).request(actor['token'], 'terminal-import', request('run', 'test',
                        content=json.dumps({'package_sets': [receipts[0]['package_set']]})))
                    self.assertTrue(result['allowed'], result)
                    self.assertEqual(result['exit_code'], 0, result)
                    self.assertIn('EDITABLE_VALUE 42', result['output'])
            finally:
                failing = sys.exc_info()[0] is not None
                # Capture before closing the child or constructing Store, both
                # of which can change the state we need to diagnose.
                if diagnostics is None:
                    diagnostics = _monitor_diagnostics(directory, since)
                save(terminal.folder / 'monitor-diagnostics.json', diagnostics)
                if not terminal.closed:
                    terminal.close(graceful=False)
                cleanup_error = None
                try:
                    if (directory / 'controller/state.sqlite3').exists():
                        store = Store(directory / 'controller')
                        with store.locked() as db:
                            projects = [r['id'] for r in db.execute('SELECT id FROM projects')]
                        for project in projects:
                            store.stop(project)
                        Supervisor(store).reconcile()
                        remove(store)
                except Exception as exc:
                    cleanup_error = type(exc).__name__
                    if not failing:
                        raise
                finally:
                    save(terminal.folder / 'receipt.json', {
                        'fault_injected': fault, 'exit_code': terminal.exit_code,
                        'cleanup_error': cleanup_error,
                        'sha256': {name: hashlib.sha256((terminal.folder / name).read_bytes()).hexdigest()
                                   for name in ('terminal.txt', 'inputs.json', 'exit.json', 'monitor-diagnostics.json')}})


class AuditEventTests(workspace_fixtures.WorkspaceFixture):
    def test_unreserved_nested_operation_rejects_even_a_colliding_slot(self):
        from ptw.store import operation_lease
        event = 'outer'
        collision = next(str(i) for i in range(10000)
                         if operation_lease(self.actor['session'], str(i)) ==
                         operation_lease(self.actor['session'], event))
        with self.store.operation(self.actor['token'], event):
            with self.assertRaisesRegex(Invalid, 'must be reserved'):
                with self.store.operation(self.actor['token'], collision):
                    self.fail('Unreserved nesting entered')
        self.assertEqual(self.store.audit_events('python-demo'), [])
        self.assertFalse(self.store.status('python-demo')['stopped'])

    def test_colliding_leases_serialize_without_false_crash_or_duplicate_effect(self):
        from ptw.store import operation_lease
        first = 'collision-first'
        second = next(str(i) for i in range(10000)
                      if operation_lease(self.actor['session'], str(i)) ==
                      operation_lease(self.actor['session'], first))
        entered, finish = threading.Event(), threading.Event()
        calls = []
        def execute(store, token, definition, before, settings, **kwargs):
            calls.append(True)
            self.assertFalse(Store(store.directory).status('python-demo')['stopped'])
            entered.set()
            self.assertTrue(finish.wait(5))
            return before, {'exit_code': 0, 'output': ''}
        with patch('ptw.execution.execute', side_effect=execute):
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                original = pool.submit(self.broker.request, self.actor['token'], first, request('run', 'test'))
                self.assertTrue(entered.wait(5))
                other = pool.submit(self.broker.request, self.actor['token'], second, request('run', 'test'))
                try:
                    self.assertFalse(other.done())
                finally:
                    finish.set()
                self.assertTrue(original.result(timeout=5)['allowed'])
                self.assertTrue(other.result(timeout=5)['allowed'])
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(list(self.store.directory.glob('operation-*.lock'))), 1)
        self.assertTrue(self.broker.request(self.actor['token'], first, request('run', 'test'))['replayed'])

    def test_long_operation_intent_survives_live_reopen_and_duplicate_waits(self):
        entered, finish = threading.Event(), threading.Event()
        body = request('run', 'test')
        calls = []
        def execute(store, token, definition, before, settings, **kwargs):
            calls.append(True)
            reopened = Store(store.directory)
            self.assertFalse(reopened.status('python-demo')['stopped'])
            self.assertEqual(reopened.audit_events('python-demo')[0]['state'], 'pending')
            entered.set()
            self.assertTrue(finish.wait(5))
            return before, {'exit_code': 0, 'output': 'one execution'}
        with patch('ptw.execution.execute', side_effect=execute):
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                original = pool.submit(self.broker.request, self.actor['token'], 'same-command', body)
                self.assertTrue(entered.wait(5))
                retry = pool.submit(self.broker.request, self.actor['token'], 'same-command', body)
                try:
                    self.assertFalse(retry.done())
                finally:
                    finish.set()
                self.assertTrue(original.result(timeout=5)['allowed'])
                self.assertTrue(retry.result(timeout=5)['replayed'])
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(self.store.audit_events('python-demo')), 1)

    def test_command_crash_preserves_uncertainty_and_never_reexecutes(self):
        body = request('run', 'test')
        with patch('ptw.execution.execute', side_effect=SystemExit('injected controller crash')) as execution:
            with self.assertRaises(SystemExit):
                self.broker.request(self.actor['token'], 'crashed-command', body)
            retry = Workspace(Store(self.store.directory)).request(self.actor['token'], 'crashed-command', body)
            self.assertFalse(retry['allowed'])
            self.assertTrue(retry['replayed'])
            self.assertEqual(execution.call_count, 1)
        row = self.store.audit_events('python-demo')[0]
        self.assertEqual(row['state'], 'uncertain')
        self.assertEqual(row['audit']['decision'], 'allow')
        self.assertEqual(row['audit']['outcome'], 'unknown')
        self.assertEqual(self.store.status('python-demo')['violations'], 0)

    def test_command_admission_fault_precedes_execution(self):
        with patch.object(self.store, 'begin', side_effect=OSError('required intent unavailable')):
            with patch('ptw.execution.execute') as execution, self.assertRaises(OSError):
                self.ask('run', resource='test', path='')
        execution.assert_not_called()
        self.assertEqual(self.store.status('python-demo')['workloads'], [])
        self.assertEqual(self.store.status('python-demo')['violations'], 0)

    def test_metadata_records_actual_effect_identity_and_no_content(self):
        self.assertTrue(self.ask('create', path='audit.txt', content='PRIVATE_FIXTURE_PAYLOAD')['allowed'])
        self.assertEqual((Path(self.inv['root']) / 'src/audit.txt').read_text(), 'PRIVATE_FIXTURE_PAYLOAD')
        document = self.store.audit_export('python-demo')
        row = next(r for r in document['events'] if r['request']['action'] == 'create')
        self.assertEqual(row['request']['path'], 'audit.txt')
        self.assertEqual(row['audit']['resource_path'], 'src')
        self.assertEqual(row['audit']['requester']['id'], self.actor['session'])
        self.assertEqual(row['audit']['authorization']['method'], 'standing_policy')
        self.assertFalse(row['audit']['authorization']['human_review_performed'])
        self.assertEqual(row['audit']['decision'], 'allow')
        self.assertEqual(row['audit']['outcome'], 'observed')
        self.assertIsNone(row['audit']['source_at'])
        self.assertNotIn('PRIVATE_FIXTURE_PAYLOAD', json.dumps(document))
        self.assertNotIn(self.actor['token'], json.dumps(document))
        self.assertTrue(verify_export(document, digest(document))['verified'])

    def test_denied_forged_authority_and_replay_preserve_counts(self):
        body = {**request('create', 'src', 'forged.txt', content='already approved'),
                'authorization': {'method': 'exact_operator_approval'}}
        result = self.broker.request(self.actor['token'], 'forged', body)
        self.assertFalse(result['allowed'])
        self.assertFalse((Path(self.inv['root']) / 'src/forged.txt').exists())
        self.assertTrue(self.broker.request(self.actor['token'], 'forged', body)['replayed'])
        rows = self.store.audit_events('python-demo')
        self.assertEqual(len(rows), 1)
        self.assertEqual(self.store.status('python-demo')['violations'], 1)
        self.assertFalse(rows[0]['audit']['authorization']['human_review_performed'])

    def test_order_is_controller_order_despite_clock_reversal_and_parent_link(self):
        with patch('ptw.store.time.time', return_value=200):
            self.ask('read')
        child = self.store.register('python-demo', 'readcheck', parent_token=self.actor['token'])
        with patch('ptw.store.time.time', return_value=100):
            self.broker.request(child['token'], 'child-read', request('read', 'src', 'calculator.py'))
        rows = self.store.audit_events('python-demo')
        self.assertEqual([r['audit']['observed_at'] for r in rows], [200, 100])
        self.assertLess(rows[0]['audit']['sequence'], rows[1]['audit']['sequence'])
        # Registration occupies its own position in the same controller order.
        history = self.store.audit_export('python-demo')['events']
        self.assertEqual([r['audit']['sequence'] for r in history], list(range(1, len(history) + 1)))
        self.assertEqual(rows[1]['audit']['parent_session'], self.actor['session'])
        self.assertTrue(all(r['audit']['source_at'] is None for r in rows))

    def test_export_rejects_missing_duplicate_reordered_altered_and_unknown(self):
        self.ask('read')
        self.ask('list', path='')
        original = self.store.audit_export('python-demo')
        variants = []
        for mutation in ('missing', 'duplicate', 'reorder', 'alter', 'unknown'):
            item = copy.deepcopy(original)
            if mutation == 'missing':
                item['events'].pop()
            elif mutation == 'duplicate':
                item['events'].append(copy.deepcopy(item['events'][0]))
            elif mutation == 'reorder':
                item['events'].reverse()
            elif mutation == 'alter':
                item['events'][0]['request']['path'] = 'different.py'
            else:
                item['events'][0]['audit']['decision'] = 'auto_approved'
            # Even a recomputed local manifest cannot replace the retained receipt.
            item['manifest'] = {'count': len(item['events']), 'events_sha256': digest(item['events'])}
            variants.append(item)
        for item in variants:
            with self.subTest(item=item['manifest']), self.assertRaises(Invalid):
                verify_export(item, digest(original))

    def test_stored_response_tamper_is_rejected(self):
        self.ask('read')
        with self.store.locked() as db:
            db.execute('UPDATE events SET response=?', (canonical({'allowed': True, 'level': 'allow',
                'effect': 'read', 'content': 'forged'}),))
        with self.assertRaisesRegex(Invalid, 'changed'):
            self.store.audit_export('python-demo')

    def test_invalid_export_shapes_and_versions_fail_explicitly(self):
        original = self.store.audit_export('python-demo')
        for value in (None, [], {**original, 'manifest': []}, {**original, 'schema': True},
                      {**original, 'manifest': {**original['manifest'], 'count': True}}):
            with self.subTest(value=value), self.assertRaises(Invalid):
                verify_export(value, digest(value))

    def test_failed_effect_keeps_allowed_decision_and_crash_is_unknown(self):
        with patch('ptw.workspace.publish', side_effect=OSError('injected write fault')):
            result = self.ask('create', path='failed.txt', content='must not appear')
        self.assertFalse(result['allowed'])
        row = self.store.audit_events('python-demo')[0]
        self.assertEqual(row['audit']['decision'], 'allow')
        self.assertEqual(row['audit']['outcome'], 'unknown')
        self.assertEqual(self.store.status('python-demo')['violations'], 0)
        self.assertFalse((Path(self.inv['root']) / 'src/failed.txt').exists())

    def test_crash_recovery_does_not_retry_or_fabricate_completion(self):
        body = request('create', 'src', 'crash.txt', content='x')
        with patch('ptw.workspace.publish', side_effect=SystemExit('injected crash')):
            with self.assertRaises(SystemExit):
                self.broker.request(self.actor['token'], 'crash', body)
        recovered = Store(self.store.directory)
        row = recovered.audit_events('python-demo')[0]
        self.assertEqual(row['state'], 'uncertain')
        self.assertEqual(row['audit']['outcome'], 'unknown')
        result = Workspace(recovered).request(self.actor['token'], 'crash', body)
        self.assertTrue(result['replayed'])
        self.assertFalse(result['allowed'])
        self.assertFalse((Path(self.inv['root']) / 'src/crash.txt').exists())
        self.assertEqual(recovered.status('python-demo')['violations'], 0)

    def test_legacy_provenance_stays_unknown_after_reopen(self):
        with self.store.locked() as db:
            db.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?)', (self.actor['session'], 'old',
                digest({}), '{}', canonical({'allowed': False, 'level': 'warn', 'effect': 'none'}), 'complete', 1))
            db.execute("UPDATE projects SET stopped=1,violations=2,reason='historical stop' WHERE id='python-demo'")
            db.execute('UPDATE sessions SET closed=1 WHERE id=?', (self.actor['session'],))
        recovered = Store(self.store.directory)
        row = recovered.audit_events('python-demo')[0]
        self.assertEqual(row['audit']['coverage'], 'legacy_unknown')
        self.assertIsNone(row['audit']['policy_sha256'])
        self.assertIsNone(row['audit']['sequence'])
        status = recovered.status('python-demo')
        self.assertEqual(status['violations'], 2)
        self.assertTrue(status['stopped'])
        self.assertTrue(status['sessions'][0]['closed'])

    def test_export_cli_is_private_and_will_not_overwrite(self):
        from ptw.cli import main
        self.ask('read')
        destination = self.root / 'operator-export.json'
        args = ['evidence', '--state', str(self.store.directory), '--project', 'python-demo', '--out', str(destination)]
        main(args)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        self.assertTrue(verify_export(json.loads(destination.read_text()), digest(self.store.audit_export('python-demo')))['verified'])
        with self.assertRaises(SystemExit):
            main(args)

    def test_delegate_export_preserves_identity_without_credential_or_narrative(self):
        from ptw.workflow import dispatch
        body = request('delegate', 'readcheck', content='FIXTURE_WORKER_APPROVAL_STORY')
        result = dispatch(self.store, self.actor, 'delegate', body)
        self.assertTrue(result['allowed'], result)
        row = self.store.audit_events('python-demo')[0]
        self.assertEqual(row['result']['child']['session'], result['child']['session'])
        self.assertEqual(row['result']['child']['parent'], self.actor['session'])
        self.assertNotIn('note', row['result'])
        self.assertNotIn('token', row['result']['child'])
        self.assertEqual(row['audit']['decision'], 'allow')
        self.assertEqual(row['audit']['outcome'], 'observed')
        self.assertFalse(row['audit']['authorization']['human_review_performed'])
        self.assertNotIn('FIXTURE_WORKER_APPROVAL_STORY', json.dumps(row))
        before = self.store.status('python-demo')['sessions']
        self.assertTrue(dispatch(self.store, self.actor, 'delegate', body)['replayed'])
        self.assertEqual(self.store.status('python-demo')['sessions'], before)
        # The genuine child can do useful narrower work, independently of export.
        child = json.loads((self.store.directory / 'delegates' / (result['child']['session'] + '.json')).read_text())
        self.assertTrue(self.broker.request(child['token'], 'child-read', request('read', 'src', 'calculator.py'))['allowed'])
        self.assertEqual(self.store.status('python-demo')['violations'], 0)

    def test_delegate_denial_records_authorization_and_replay_without_children(self):
        from ptw.workflow import dispatch
        actor = self.store.register('python-demo', 'readcheck')
        before = self.store.status('python-demo')['sessions']
        for count, task in enumerate(('missing-task', 'implementation'), 1):
            with self.subTest(task=task):
                event = 'denied-' + task
                body = request('delegate', task, content='FIXTURE_FORGED_HUMAN_APPROVAL')
                result = dispatch(self.store, actor, event, body)
                self.assertFalse(result['allowed'], result)
                row = next(r for r in self.store.audit_events('python-demo') if r['event'] == event)
                self.assertEqual(row['audit']['decision'], result['level'])
                self.assertEqual(row['audit']['admission_decision'], 'allow')
                self.assertEqual(row['audit']['outcome'], 'not_performed')
                self.assertEqual(row['audit']['requester']['id'], actor['session'])
                authority = row['audit']['authorization']
                self.assertEqual(authority['method'], 'standing_policy')
                self.assertEqual(authority['policy_sha256'], self.approve()['approval']['sha256'])
                self.assertEqual(authority['grants_sha256'], digest({k: actor[k] for k in ('grants', 'commands', 'packages')}))
                self.assertFalse(authority['human_review_performed'])
                self.assertIsNone(authority['receipt_sha256'])
                self.assertNotIn('FIXTURE_FORGED_HUMAN_APPROVAL', json.dumps(row))
                self.assertEqual(self.store.status('python-demo')['sessions'], before)
                self.assertFalse((self.store.directory / 'delegates').exists())
                history = self.store.audit_export('python-demo')
                replay = dispatch(Store(self.store.directory), actor, event, body)
                self.assertEqual(replay, {**result, 'replayed': True})
                self.assertEqual(self.store.status('python-demo')['violations'], count)
                self.assertEqual(self.store.audit_export('python-demo'), history)
                self.assertTrue(verify_export(history, digest(history))['verified'])
                with self.assertRaisesRegex(Invalid, 'different request'):
                    dispatch(self.store, actor, event, request('delegate', 'readcheck'))

    def test_unknown_decision_cannot_be_recorded(self):
        with self.store.locked() as db, self.assertRaisesRegex(Invalid, 'decision'):
            self.store.record(db, self.actor['session'], 'bad-state', digest({}), {},
                              {'allowed': True, 'level': 'auto_approved', 'effect': 'write'})
        self.assertEqual(self.store.audit_events('python-demo'), [])


class AuditLifecycleTests(workspace_fixtures.WorkspaceFixture):
    def test_registration_delegate_resume_and_closure_link_useful_effects(self):
        conversation = str(uuid.uuid4())
        first = self.store.register('python-demo', 'implementation', conversation=conversation)
        child = self.store.register('python-demo', 'readcheck', parent_token=first['token'])
        self.assertTrue(self.broker.request(child['token'], 'child-read', request('read', 'src', 'calculator.py'))['allowed'])
        self.assertTrue(self.store.close_session(first['token'])['closed'])
        with self.assertRaises(Invalid):
            self.broker.request(child['token'], 'late', request('read', 'src', 'calculator.py'))
        fresh = self.store.register('python-demo', 'implementation', conversation=conversation, resumed=True)
        self.assertNotEqual(first['token'], fresh['token'])
        self.assertTrue(self.broker.request(fresh['token'], 'continued', request('create', 'src', 'continued.txt', content='useful'))['allowed'])
        self.assertEqual((Path(self.inv['root']) / 'src/continued.txt').read_text(), 'useful')
        rows = self.store.audit_export('python-demo')['events']
        resumed = next(r for r in rows if r['event'] == 'continued')
        self.assertEqual(resumed['audit']['resume_of'], first['session'])
        self.assertEqual(resumed['audit']['conversation'], conversation)
        self.assertIn(digest(['controller:python-demo', 'session_registered:' + fresh['session']]), resumed['audit']['causes'])
        registered = next(r for r in rows if r['event'] == 'session_registered:' + child['session'])
        self.assertEqual(registered['audit']['requester'], {'kind': 'authenticated_session', 'id': first['session']})
        closed = next(r for r in rows if r['request']['action'] == 'session_closed')
        self.assertEqual(set(closed['audit']['details']['closed_sessions']), {first['session'], child['session']})
        count = len(rows)
        self.store.close_session(first['token'])
        self.assertEqual(len(self.store.audit_export('python-demo')['events']), count)
        self.assertEqual(self.store.status('python-demo')['violations'], 0)
        self.assertTrue(self.ask('read')['allowed'])  # Independent parent survives.

    def test_resume_rejects_open_foreign_and_unbound_sessions(self):
        conversation = str(uuid.uuid4())
        first = self.store.register('python-demo', 'implementation', conversation=conversation)
        with self.assertRaises(Invalid):
            self.store.register('python-demo', 'implementation', conversation=conversation, resumed=True)
        self.store.close_session(first['token'])
        with self.assertRaises(Invalid):
            self.store.register('python-demo', 'readcheck', conversation=conversation, resumed=True)
        with self.assertRaises(Invalid):
            self.store.register('python-demo', 'implementation', resumed=True)
        legacy = self.store.register('python-demo', 'implementation', conversation=str(uuid.uuid4()), resumed=True)
        row = next(r for r in self.store.audit_export('python-demo')['events']
                   if r['event'] == 'session_registered:' + legacy['session'])
        self.assertIsNone(row['audit']['resume_of'])
        self.assertEqual(row['audit']['details']['resume_coverage'], 'legacy_unknown')

    def test_registration_capture_failure_rolls_back_admission(self):
        before = self.store.status('python-demo')['sessions']
        with self.store.locked() as db:
            db.execute("CREATE TRIGGER reject_registration BEFORE INSERT ON events "
                       "WHEN json_extract(NEW.request_meta,'$.action')='session_registered' "
                       "BEGIN SELECT RAISE(FAIL,'injected registration fault'); END")
        with self.assertRaises(sqlite3.Error):
            self.store.register('python-demo', 'implementation')
        status = self.store.status('python-demo')
        self.assertEqual(status['sessions'], before)
        self.assertTrue(status['stopped'])
        self.assertEqual(status['violations'], 0)

    def test_closure_capture_failure_preserves_revocation_and_other_parent(self):
        child = self.store.register('python-demo', 'readcheck', parent_token=self.actor['token'])
        with self.store.locked() as db:
            db.execute("CREATE TRIGGER reject_closure BEFORE INSERT ON events "
                       "WHEN json_extract(NEW.request_meta,'$.action')='session_closed' "
                       "BEGIN SELECT RAISE(FAIL,'injected closure fault'); END")
        result = self.store.close_session(child['token'])
        self.assertEqual(result['evidence'], 'unavailable')
        self.assertFalse(result['confirmed_stopped'])
        with self.assertRaises(Invalid):
            self.broker.request(child['token'], 'late', request('read', 'src', 'calculator.py'))
        self.assertTrue(self.ask('read')['allowed'])
        self.assertFalse(self.store.status('python-demo')['stopped'])
        self.assertEqual(self.store.status('python-demo')['violations'], 0)

    def test_delegate_lost_receipt_cannot_create_another_child(self):
        from ptw.workflow import dispatch
        body = request('delegate', 'readcheck')
        with patch('ptw.workflow.save', side_effect=SystemExit('crash after registration')):
            with self.assertRaises(SystemExit):
                dispatch(self.store, self.actor, 'delegate-crash', body)
        before = self.store.status('python-demo')['sessions']
        retried = dispatch(Store(self.store.directory), self.actor, 'delegate-crash', body)
        self.assertFalse(retried['allowed'])
        self.assertTrue(retried['replayed'])
        self.assertEqual(self.store.status('python-demo')['sessions'], before)
        self.assertEqual(len([s for s in before if s['parent'] == self.actor['session']]), 1)
        self.assertEqual(self.store.status('python-demo')['violations'], 0)

    def test_stop_request_is_not_termination_and_repeats_do_not_duplicate(self):
        stopped = self.store.stop('python-demo')
        self.assertFalse(stopped['confirmed_stopped'])
        rows = self.store.audit_export('python-demo')['events']
        self.assertEqual(rows[-1]['request']['action'], 'stop_requested')
        self.assertEqual(rows[-1]['audit']['details']['termination'], 'unconfirmed')
        self.store.stop('python-demo')
        self.assertEqual(self.store.audit_export('python-demo')['events'], rows)

    def test_unconfirmed_reconciliation_deduplicates_then_records_confirmation(self):
        from ptw.supervisor import Supervisor
        unit = 'ptw-' + '0' * 24 + '.service'
        with self.store.locked() as db:
            db.execute('INSERT INTO workloads(unit,project,session) VALUES(?,?,?)',
                       (unit, 'python-demo', self.actor['session']))
        self.store.stop('python-demo')
        with patch.object(Supervisor, 'terminate', return_value={'confirmed_stopped': False}):
            for _ in range(3):
                self.assertFalse(Supervisor(self.store).reconcile()[0]['confirmed_stopped'])
        rows = self.store.audit_export('python-demo')['events']
        terminations = [r for r in rows if r['request']['action'] == 'workload_termination']
        self.assertEqual(len(terminations), 1)
        self.assertEqual(terminations[0]['audit']['outcome'], 'unconfirmed')
        with patch.object(Supervisor, 'terminate', return_value={'confirmed_stopped': True}):
            self.assertTrue(Supervisor(self.store).reconcile()[0]['confirmed_stopped'])
        rows = self.store.audit_export('python-demo')['events']
        self.assertEqual(len([r for r in rows if r['request']['action'] == 'workload_termination']), 2)
        self.assertTrue(self.store.status('python-demo')['workloads'][0]['stopped'])

    def test_cleanup_capture_fault_and_reconciliation_preserve_reduction_scope(self):
        from ptw.supervisor import Supervisor
        other = self.store.register('python-demo', 'implementation')
        unit = 'ptw-' + '1' * 24 + '.service'
        with self.store.locked() as db:
            db.execute('INSERT INTO workloads(unit,project,session) VALUES(?,?,?)',
                       (unit, 'python-demo', self.actor['session']))
            db.execute("CREATE TRIGGER reject_cleanup BEFORE INSERT ON events "
                "WHEN json_extract(NEW.request_meta,'$.action')='workload_termination' "
                "BEGIN SELECT RAISE(FAIL,'injected cleanup capture failure'); END")
        self.store.close_session(self.actor['token'])
        with patch.object(Supervisor, 'terminate', return_value={'confirmed_stopped': True}):
            outcome = Supervisor(self.store).reconcile()[0]
            self.assertTrue(outcome['confirmed_stopped'])
            self.assertEqual(outcome['evidence'], 'unavailable')
            self.assertFalse(self.store.status('python-demo')['stopped'])
            self.assertTrue(self.broker.request(other['token'], 'other-parent', request('read', 'src', 'calculator.py'))['allowed'])
            # Ordinary cleanup still holds publication by stopping affected
            # project admission when its required capture fails.
            outcome = Supervisor(self.store).terminate_recorded(unit)
        self.assertEqual(outcome['evidence'], 'unavailable')
        self.assertTrue(self.store.status('python-demo')['stopped'])
        self.assertFalse(self.store.status('python-demo')['workloads'][0]['stopped'])


class AuditStorageTests(workspace_fixtures.WorkspaceFixture):
    def adopt(self, **changes):
        profile = {**DEFAULT, **changes}
        packet = self.store.evidence_review('python-demo', profile)
        return self.store.adopt_evidence('python-demo', profile, digest(packet), 'fixture operator')

    def test_private_default_opt_in_truncation_and_denied_scope(self):
        self.adopt()
        self.ask('create', path='default.txt', content='metadata only')
        with self.store.locked() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM evidence_payloads').fetchone()[0], 0)
        self.adopt(content_resources=['src'])
        text = 'source fixture\n' * 30000
        self.assertTrue(self.ask('create', path='captured.txt', content=text)['allowed'])
        with self.store.locked() as db:
            payload = db.execute('SELECT * FROM evidence_payloads').fetchone()
            self.assertEqual(payload['payload'], text.encode()[:PAYLOAD_BYTES])
            self.assertEqual(payload['sha256'], hashlib.sha256(text.encode()).hexdigest())
            self.assertEqual(payload['original_bytes'], len(text.encode()))
            self.assertEqual(payload['status'], 'truncated')
        self.assertEqual(self.store.directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.store.db.stat().st_mode & 0o777, 0o600)
        exported = self.store.audit_export('python-demo')
        self.assertNotIn('source fixture', canonical(exported))
        self.assertNotIn(self.actor['token'], canonical(exported))
        self.assertEqual(exported['payloads'][0]['status'], 'truncated')
        row = exported['payloads'][0]
        operation = digest([row['session'], row['event']])
        self.assertEqual(self.store.evidence_content('python-demo', operation)['payload'], text.encode()[:PAYLOAD_BYTES])
        with self.store.locked() as db:
            db.execute("UPDATE evidence_payloads SET payload=x'00'")
        with self.assertRaisesRegex(Invalid, 'payload changed'):
            self.store.evidence_content('python-demo', operation)
        for invalid in ({**DEFAULT, 'content_resources': ['private']},
                        {**DEFAULT, 'content_resources': ['src', 'src']},
                        {**DEFAULT, 'project_bytes': True}, {**DEFAULT, 'version': 2}):
            with self.subTest(invalid=invalid), self.assertRaises(Invalid):
                self.store.evidence_review('python-demo', invalid)

    def test_optional_capture_failure_is_visible_without_stopping_useful_work(self):
        self.adopt(content_resources=['src'])
        with self.store.locked() as db:
            db.execute("CREATE TRIGGER no_payload BEFORE INSERT ON evidence_payloads "
                       "BEGIN SELECT RAISE(FAIL,'optional payload unavailable'); END")
        self.assertTrue(self.ask('create', path='useful.txt', content='useful')['allowed'])
        self.assertEqual((Path(self.inv['root']) / 'src/useful.txt').read_text(), 'useful')
        self.assertEqual(self.store.audit_events('python-demo')[-1]['audit']['content'], 'unavailable')
        self.assertFalse(self.store.status('python-demo')['stopped'])
        self.assertEqual(self.store.status('python-demo')['violations'], 0)

    def test_quota_precedes_mutation_and_preserves_unrelated_project(self):
        self.adopt(project_bytes=1024 * 1024)
        other_policy = copy.deepcopy(self.policy)
        other_policy['project']['id'] = 'unrelated'
        from ptw.policy import approve, compile_policy
        self.store.activate(approve(other_policy, self.inv, digest(compile_policy(other_policy, self.inv)), 'operator'))
        other = self.store.register('unrelated', 'implementation')
        self.assertTrue(self.ask('read')['allowed'])
        result = self.ask('create', path='not-created.txt', content='effect must not occur')
        self.assertFalse(result['allowed'])
        self.assertEqual(result['level'], 'stop')
        self.assertIn('quota', result['reason'])
        self.assertFalse((Path(self.inv['root']) / 'src/not-created.txt').exists())
        self.assertTrue(self.store.status('python-demo')['stopped'])
        self.assertEqual(self.store.status('python-demo')['violations'], 0)
        self.assertTrue(self.broker.request(other['token'], 'still-useful', request('read', 'src', 'calculator.py'))['allowed'])
        recovered = Store(self.store.directory)
        self.assertTrue(recovered.status('python-demo')['stopped'])
        self.assertEqual(recovered.status('python-demo')['violations'], 0)

    def test_concurrent_reservations_cannot_both_admit_or_publish_after_quota_fault(self):
        from ptw.store import operation_lease
        second = next('second-' + str(i) for i in range(100)
                      if operation_lease(self.actor['session'], 'second-' + str(i)) !=
                      operation_lease(self.actor['session'], 'first'))
        self.adopt(project_bytes=400 * 1024 * 1024)
        entered, finish = threading.Event(), threading.Event()
        calls = []
        def execute(store, token, definition, before, settings, **kwargs):
            calls.append(True)
            entered.set()
            self.assertTrue(finish.wait(5))
            after = dict(before)
            after['dist/late.txt'] = {'kind': 'file', 'data': b'late', 'mode': 0o644}
            return after, {'exit_code': 0, 'output': ''}
        with patch('ptw.execution.execute', side_effect=execute):
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(self.broker.request, self.actor['token'], 'first', request('run', 'test'))
                self.assertTrue(entered.wait(5))
                try:
                    with self.assertRaises(QuotaError):
                        self.broker.request(self.actor['token'], second, request('run', 'test'))
                finally:
                    finish.set()
                self.assertFalse(first.result(timeout=5)['allowed'])
        self.assertEqual(calls, [True])
        self.assertFalse((Path(self.inv['root']) / 'dist/late.txt').exists())
        self.assertEqual(self.store.status('python-demo')['violations'], 0)

    def test_rejected_event_ids_cannot_grow_lease_storage_beyond_reserved_pool(self):
        from ptw.store import LEASE_SLOTS
        from ptw.evidence_storage import usage, ROW_OVERHEAD
        self.adopt()
        with self.store.locked() as db:
            baseline = usage(db, 'python-demo')
            self.assertGreaterEqual(baseline, ROW_OVERHEAD * LEASE_SLOTS)
            db.execute('UPDATE evidence_profiles SET profile=? WHERE project=?',
                       (canonical({**DEFAULT, 'project_bytes': baseline}), 'python-demo'))
            baseline = usage(db, 'python-demo')
        with patch('ptw.execution.execute') as execute:
            for i in range(2 * LEASE_SLOTS + 1):
                with self.assertRaises(QuotaError):
                    self.broker.request(self.actor['token'], 'rejected-' + str(i), request('run', 'test'))
        execute.assert_not_called()
        locks = list(self.store.directory.glob('operation-*.lock'))
        self.assertLessEqual(len(locks), LEASE_SLOTS)
        self.assertTrue(all(p.stat().st_size == 0 and p.stat().st_mode & 0o777 == 0o600 for p in locks))
        self.assertTrue(self.store.status('python-demo')['stopped'])
        self.assertEqual(self.store.status('python-demo')['violations'], 0)
        with self.store.locked() as db:
            # All slots were reserved already, including unused ones.
            self.assertEqual(usage(db, 'python-demo'), baseline)



    def test_expiry_tombstones_keep_replay_and_unresolved_references(self):
        self.adopt(content_resources=['src'])
        body = request('create', 'src', 'retained.txt', content='retain required replay')
        original = self.broker.request(self.actor['token'], 'retained', body)
        with self.store.locked() as db:
            db.execute('UPDATE evidence_payloads SET at=?', (time.time() - RETENTION_SECONDS - 1,))
            db.execute('INSERT INTO evidence_pins VALUES(?,?)', ('python-demo', 'fixture-review'))
        self.assertTrue(self.store.expire_evidence('python-demo')['pinned'])
        with self.store.locked() as db:
            db.execute('DELETE FROM evidence_pins')
            self.store.begin(db, self.actor['session'], 'uncertain', digest(body), body)
        recovered = Store(self.store.directory)
        self.assertTrue(recovered.expire_evidence('python-demo')['pinned'])
        self.assertEqual(recovered.audit_events('python-demo')[-1]['state'], 'uncertain')
        # A separate healthy fixture proves eligible expiry without clearing uncertainty.
        other = Store(self.root / 'healthy-state')
        other.activate(self.approve())
        actor = other.register('python-demo', 'implementation')
        packet = other.evidence_review('python-demo', {**DEFAULT, 'content_resources': ['src']})
        other.adopt_evidence('python-demo', packet['profile'], digest(packet), 'operator')
        read = request('read', 'src', 'retained.txt')
        first = Workspace(other).request(actor['token'], 'read', read)
        with other.locked() as db:
            db.execute('UPDATE evidence_payloads SET at=?', (time.time() - RETENTION_SECONDS - 1,))
        self.assertEqual(other.expire_evidence('python-demo'), {'expired': 1, 'pinned': False})
        self.assertEqual(other.expire_evidence('python-demo')['expired'], 0)
        row = other.audit_export('python-demo')['payloads'][0]
        self.assertEqual(row['status'], 'expired')
        self.assertIsNotNone(row['expired_at'])
        with other.locked() as db:
            self.assertIsNone(db.execute('SELECT payload FROM evidence_payloads').fetchone()[0])
        self.assertEqual(Workspace(other).request(actor['token'], 'read', read), {**first, 'replayed': True})
        self.assertTrue(original['allowed'])

    def test_adoption_is_exact_stale_review_rejected_and_old_runtime_refused(self):
        packet = self.store.evidence_review('python-demo', DEFAULT)
        self.ask('read')
        with self.assertRaisesRegex(Invalid, 'exact operator review'):
            self.store.adopt_evidence('python-demo', DEFAULT, digest(packet), 'operator')
        self.adopt()
        with sqlite3.connect(self.store.db) as legacy:
            # This is the shipped old runtime's project query, without the new
            # connection capability. It cannot reach registration or effects.
            with self.assertRaisesRegex(sqlite3.OperationalError, 'ptw_evidence_runtime'):
                legacy.execute('SELECT * FROM projects WHERE id=?', ('python-demo',)).fetchone()
            with self.assertRaisesRegex(sqlite3.OperationalError, 'ptw_evidence_runtime'):
                legacy.execute('UPDATE projects SET stopped=0')
        self.assertTrue(self.ask('read')['allowed'])
        with self.store.locked() as db:
            db.execute('PRAGMA user_version=99')
        with self.assertRaisesRegex(Invalid, 'Unsupported controller evidence schema'):
            Store(self.store.directory)

    def test_backed_up_migration_keeps_counts_stops_quarantine_and_legacy_unknown(self):
        self.ask('read')
        with self.store.locked() as db:
            db.execute("UPDATE projects SET violations=2,stopped=1,reason='original stop'")
            db.execute('UPDATE task_counts SET violations=2')
            db.execute('UPDATE sessions SET closed=1')
            db.execute("UPDATE events SET request_meta='{}' WHERE session=?", (self.actor['session'],))
            db.execute("INSERT INTO package_sets(id,project,names,manifest,created,assessment_state) "
                       "VALUES('historical','python-demo','[]','{}',0,'quarantined')")
            for table in ('evidence_profiles', 'evidence_payloads', 'evidence_pins'):
                db.execute('DROP TABLE ' + table)
            db.execute('PRAGMA user_version=0')
        recovered = Store(self.store.directory)
        status = recovered.status('python-demo')
        self.assertEqual((status['violations'], status['stopped'], status['reason']), (2, 1, 'original stop'))
        self.assertTrue(all(s['closed'] for s in status['sessions']))
        self.assertEqual(status['package_sets'][0]['assessment_state'], 'quarantined')
        self.assertEqual(recovered.audit_events('python-demo')[0]['audit']['coverage'], 'legacy_unknown')
        snapshots = list(self.store.directory.glob('migration-*.sqlite3'))
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(snapshots[0].stat().st_mode & 0o777, 0o600)
        receipt = json.loads(snapshots[0].with_suffix('.json').read_text())
        self.assertEqual(receipt['sha256'], hashlib.sha256(snapshots[0].read_bytes()).hexdigest())
        self.store = recovered
        self.adopt()
        self.assertEqual(recovered.status('python-demo'), status)

    def test_interrupted_adoption_rolls_back_without_reactivating_or_losing_history(self):
        self.ask('read')
        before = self.store.audit_export('python-demo')['events']
        with self.store.locked() as db:
            db.execute("CREATE TRIGGER reject_adoption BEFORE INSERT ON evidence_profiles "
                       "BEGIN SELECT RAISE(FAIL,'injected adoption crash'); END")
        with self.assertRaises(sqlite3.Error):
            self.adopt()
        recovered = Store(self.store.directory)
        self.assertIsNone(recovered.audit_export('python-demo')['profile'])
        self.assertEqual(recovered.audit_export('python-demo')['events'], before)
        with recovered.locked() as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 1)
            db.execute('DROP TRIGGER reject_adoption')
        self.store = recovered
        self.adopt()
        self.assertTrue(self.ask('read')['allowed'])

    def test_interrupted_schema_migration_retains_stopped_backup_and_rolls_back_columns(self):
        with self.store.locked() as db:
            for table in ('evidence_profiles', 'evidence_payloads', 'evidence_pins'):
                db.execute('DROP TABLE ' + table)
            db.execute('ALTER TABLE sessions DROP COLUMN conversation')
            db.execute('ALTER TABLE sessions DROP COLUMN resume_of')
            db.execute('PRAGMA user_version=0')
        def crash(store, db):
            db.execute('CREATE TABLE evidence_profiles(project TEXT)')
            raise SystemExit('injected migration interruption')
        with patch('ptw.evidence_storage.migrate', side_effect=crash), self.assertRaises(SystemExit):
            Store(self.store.directory)
        with sqlite3.connect(self.store.db) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 0)
            self.assertNotIn('conversation', {r[1] for r in db.execute('PRAGMA table_info(sessions)')})
            self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE name='evidence_profiles'").fetchone())
        backup = next(self.store.directory.glob('migration-*.sqlite3'))
        with sqlite3.connect(backup) as db:
            self.assertEqual(db.execute('SELECT stopped FROM projects').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT count(*) FROM sessions').fetchone()[0], 1)
        recovered = Store(self.store.directory)
        self.assertTrue(Workspace(recovered).request(self.actor['token'], 'after-migration', request('read', 'src', 'calculator.py'))['allowed'])

    def test_package_assessment_export_preserves_original_rule_and_unknown_legacy(self):
        from ptw.reassessment import attempt
        with self.store.locked() as db:
            db.execute("INSERT INTO package_sets(id,project,names,manifest,created) VALUES('pkg','python-demo','[]','{}',0)")
            db.execute("INSERT INTO package_assessments VALUES('legacy','pkg',0,'current','{}')")
            actor = self.store.session(db, self.actor['token'])
            attempt(db, 'pkg', 'blocked', {'errors': ['PRIVATE_DIAGNOSTIC']}, actor=actor)
        first = self.store.audit_export('python-demo')
        self.assertNotIn('PRIVATE_DIAGNOSTIC', canonical(first))
        self.assertEqual(first['assessments'][0]['audit']['authority'], 'legacy_unknown')
        evidence = first['assessments'][1]['audit']
        self.assertIsNone(evidence['source_at'])
        self.assertEqual(evidence['requester']['id'], self.actor['session'])
        self.assertFalse(evidence['authorization']['human_review_performed'])
        self.assertEqual(evidence['policy_sha256'], self.approve()['approval']['sha256'])
        with self.store.locked() as db:
            bundle = self.approve()
            bundle['policy']['project']['packages']['min_release_age_days'] += 1
            db.execute('UPDATE projects SET bundle=?', (canonical(bundle),))
        self.assertEqual(self.store.audit_export('python-demo')['assessments'], first['assessments'])
        with self.store.locked() as db:
            row = db.execute("SELECT attempt,detail FROM package_assessments WHERE attempt!='legacy'").fetchone()
            changed = json.loads(row['detail'])
            changed['_audit']['authorization']['human_review_performed'] = True
            db.execute('UPDATE package_assessments SET detail=? WHERE attempt=?', (canonical(changed), row['attempt']))
        with self.assertRaisesRegex(Invalid, 'assessment evidence changed'):
            self.store.audit_export('python-demo')

    def test_archive_requires_closed_resolved_history_and_never_deletes_replay(self):
        self.adopt()
        self.ask('read')
        destination = self.root / 'archive' / 'closed.json'
        with self.assertRaises(Invalid):
            self.store.archive_evidence('python-demo', destination)
        self.store.close_session(self.actor['token'])
        self.store.stop('python-demo')
        before = self.store.audit_export('python-demo')
        result = self.store.archive_evidence('python-demo', destination)
        self.assertFalse(result['required_history_deleted'])
        self.assertEqual(destination.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(destination.read_text()), before)
        self.assertTrue(verify_export(before, result['sha256'])['verified'])
        self.assertEqual(self.store.audit_export('python-demo'), before)
        with self.assertRaises(FileExistsError):
            self.store.archive_evidence('python-demo', destination)

    def test_new_reviewed_profile_admits_useful_work_and_displays_limits(self):
        from ptw.onboarding import short_review
        self.policy['project']['audit'] = copy.deepcopy(DEFAULT)
        bundle = self.approve()
        shown = short_review({'policy': self.policy, 'inventory': self.inv}, {}, [])
        self.assertIn('1073741824', shown)
        self.assertIn('optional content off by default', shown)
        fresh = Store(self.root / 'fresh-state')
        fresh.activate(bundle)
        actor = fresh.register('python-demo', 'implementation')
        self.assertTrue(Workspace(fresh).request(actor['token'], 'useful', request('create', 'src', 'new.txt', content='new'))['allowed'])
        self.assertEqual(fresh.audit_export('python-demo')['profile'], DEFAULT)


@unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'Requires native isolated package installer')
class AuditReassessmentTests(unittest.TestCase):
    """Reuse existing advisory fixtures without rediscovering their test suite."""

    def fixture(self):
        import test_product_reassessment as fixtures
        fixture = fixtures.ReassessmentTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        packet = fixture.store.evidence_review('website', DEFAULT)
        fixture.store.adopt_evidence('website', DEFAULT, digest(packet), 'fixture operator')
        return fixture

    @staticmethod
    def limit(db, budget):
        db.execute('UPDATE evidence_profiles SET profile=? WHERE project=?',
                   (canonical({**DEFAULT, 'project_bytes': budget}), 'website'))

    @staticmethod
    def row_bytes(row):
        # Calculate from the actual persisted row, not the admission argument.
        from ptw.evidence_storage import ROW_OVERHEAD
        return ROW_OVERHEAD + 4 * len(json.dumps(dict(row), sort_keys=True,
            separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode())

    def test_complete_receipt_exact_quota_and_one_byte_short_all_outcomes(self):
        from ptw.evidence_storage import usage
        from ptw.reassessment import attempt
        fixture = self.fixture()
        with fixture.store.locked() as db:
            actor = fixture.store.session(db, fixture.a['token'])
            for outcome in ('current', 'blocked', 'discarded', 'quarantined'):
                with self.subTest(outcome=outcome), patch('ptw.reassessment.time.time', return_value=1700000000.0), \
                        patch('ptw.reassessment.secrets.token_hex', return_value='f' * 32):
                    detail = {'evidence': [], 'errors': ['escaped "quote" \\ newline\n雪']}
                    db.execute('BEGIN IMMEDIATE')
                    attempt(db, fixture.package, outcome, detail, actor=actor)
                    receipt = db.execute("SELECT * FROM package_assessments WHERE attempt=?", ('f' * 32,)).fetchone()
                    required = self.row_bytes(receipt)
                    db.rollback()
                    # Stabilize the profile's own decimal width in accounted usage.
                    for _ in range(3):
                        self.limit(db, usage(db, 'website') + required)
                    budget = usage(db, 'website') + required
                    self.limit(db, budget)
                    before = usage(db, 'website')
                    count = db.execute('SELECT count(*) FROM package_assessments').fetchone()[0]
                    self.limit(db, budget - 1)
                    with self.assertRaises(QuotaError):
                        attempt(db, fixture.package, outcome, detail, actor=actor)
                    self.assertEqual(db.execute('SELECT count(*) FROM package_assessments').fetchone()[0], count)
                    self.limit(db, budget)
                    db.execute('BEGIN IMMEDIATE')
                    attempt(db, fixture.package, outcome, detail, actor=actor)
                    self.assertEqual(usage(db, 'website'), budget)
                    self.assertEqual(usage(db, 'website') - before, required)
                    self.assertTrue(db.in_transaction, 'Writer must not commit its caller transaction')
                    db.rollback()
                    self.limit(db, DEFAULT['project_bytes'])

    def test_seed_preserves_caller_transaction_and_rollback(self):
        from ptw.reassessment import seed
        fixture = self.fixture()
        before = fixture.row()
        with fixture.store.locked() as db:
            count = db.execute('SELECT count(*) FROM package_assessments').fetchone()[0]
            db.execute('BEGIN IMMEDIATE')
            seed(db, fixture.package, [{**fixture.evidence, 'checked_at': time.time()}])
            self.assertTrue(db.in_transaction)
            db.rollback()
            self.assertEqual(db.execute('SELECT count(*) FROM package_assessments').fetchone()[0], count)
        self.assertEqual(fixture.row(), before)

    def test_public_refresh_commits_current_blocked_and_missing_provenance(self):
        from ptw.package_evidence import EvidenceError
        from ptw.packages import mounted_set
        from test_product_reassessment import AdvisoryFixture
        fixture = self.fixture()
        fixture.expire()
        before = fixture.row()
        fixture.reuse()
        self.assertEqual(fixture.row()['assessment_generation'], before['assessment_generation'] + 1)
        with fixture.store.locked() as db:
            mounted_set(fixture.store, db, fixture.store.session(db, fixture.a['token']), fixture.package)
            self.assertEqual(db.execute('SELECT outcome FROM package_assessments ORDER BY rowid DESC').fetchone()[0], 'current')
        fixture.reuse(AdvisoryFixture({('idna', '3.11'): AssertionError('fresh reuse queried network')}))
        for missing in (False, True):
            with self.subTest(missing=missing):
                fixture.expire()
                if missing:
                    with fixture.store.locked() as db:
                        db.execute('UPDATE package_sets SET evidence=NULL WHERE id=?', (fixture.package,))
                before = fixture.row()
                with self.assertRaises(EvidenceError):
                    fixture.reuse(AdvisoryFixture({('idna', '3.11'): EvidenceError('fixture offline')}))
                self.assertEqual(fixture.row()['assessment_state'], 'blocked')
                self.assertEqual(fixture.row()['evidence'], before['evidence'])
                self.assertEqual(fixture.row()['assessment_generation'], before['assessment_generation'] + 1)
                with fixture.store.locked() as db:
                    self.assertEqual(db.execute('SELECT outcome FROM package_assessments ORDER BY rowid DESC').fetchone()[0], 'blocked')
        self.assertFalse(fixture.store.status('website')['stopped'])
        self.assertEqual(fixture.store.status('website')['violations'], 0)

    def test_refresh_interruption_rolls_back_eligibility_and_receipt(self):
        from ptw.reassessment import attempt
        class Interrupted(BaseException):
            pass
        for after_insert in (False, True):
            with self.subTest(after_insert=after_insert):
                fixture = self.fixture()
                fixture.expire()
                before = fixture.row()
                with fixture.store.locked() as db:
                    count = db.execute('SELECT count(*) FROM package_assessments').fetchone()[0]
                def interrupt(db, *args, **kwargs):
                    self.assertTrue(db.in_transaction)
                    if after_insert:
                        attempt(db, *args, **kwargs)
                    raise Interrupted()
                with patch('ptw.reassessment.attempt', side_effect=interrupt), self.assertRaises(Interrupted):
                    fixture.reuse()
                fixture.store = Store(fixture.store.directory)
                self.assertEqual(fixture.row(), before)
                with fixture.store.locked() as db:
                    self.assertEqual(db.execute('SELECT count(*) FROM package_assessments').fetchone()[0], count)
                    self.assertEqual(db.execute("SELECT count(*) FROM events WHERE state='pending'").fetchone()[0], 0)
                # No external effect occurred: an explicit fresh collection can succeed.
                fixture.reuse()
                self.assertEqual(fixture.row()['assessment_generation'], before['assessment_generation'] + 1)

    def test_refresh_quota_includes_package_growth_before_reuse(self):
        from ptw.evidence_storage import usage
        from ptw.reassessment import attempt
        from test_product_reassessment import AdvisoryFixture
        class Probe(BaseException):
            pass
        for short in (0, 1):
            with self.subTest(short=short):
                fixture = self.fixture()
                fixture.expire()
                before = fixture.row()
                provider = AdvisoryFixture({('idna', '3.11'): [{
                    'id': 'withdrawn "fixture" \\ 雪' * 30, 'withdrawn': '2020-01-01T00:00:00Z'}]})
                with fixture.store.locked() as db:
                    baseline = usage(db, 'website')
                    count = db.execute('SELECT count(*) FROM package_assessments').fetchone()[0]
                measured = {}
                def probe(db, *args, **kwargs):
                    attempt(db, *args, **kwargs)
                    measured['delta'] = usage(db, 'website') - baseline
                    measured['receipt'] = self.row_bytes(db.execute(
                        'SELECT * FROM package_assessments ORDER BY rowid DESC').fetchone())
                    raise Probe()
                with patch('ptw.reassessment.time.time', return_value=time.time()), \
                        patch('ptw.reassessment.secrets.token_hex', return_value='e' * 32):
                    with patch('ptw.reassessment.attempt', side_effect=probe), self.assertRaises(Probe):
                        fixture.reuse(provider)
                    self.assertEqual(fixture.row(), before)
                    self.assertGreater(measured['delta'], measured['receipt'])
                    with fixture.store.locked() as db:
                        for _ in range(3):
                            budget = usage(db, 'website') + measured['delta'] - short
                            self.limit(db, budget)
                    if short:
                        with self.assertRaises(QuotaError):
                            fixture.reuse(provider)
                        self.assertEqual(fixture.row(), before)
                    else:
                        fixture.reuse(provider)
                        self.assertEqual(fixture.row()['assessment_state'], 'current')
                    with fixture.store.locked() as db:
                        self.assertEqual(db.execute('SELECT count(*) FROM package_assessments').fetchone()[0],
                                         count + (not short))
                        if not short:
                            self.assertEqual(usage(db, 'website'), budget)
                if short:
                    # Restoring capacity permits capture, never automatic reopening.
                    packet = fixture.store.evidence_review('website', DEFAULT)
                    fixture.store.adopt_evidence('website', DEFAULT, digest(packet), 'fixture operator')
                    fixture.store = Store(fixture.store.directory)
                    self.assertTrue(fixture.store.status('website')['stopped'])
                    with self.assertRaisesRegex(Invalid, 'stopped'):
                        fixture.reuse()
                self.assertEqual(fixture.store.status('website')['violations'], 0)

    def test_quarantine_batch_capture_failure_retains_restriction_without_partial_receipts(self):
        from ptw.evidence_storage import admit, usage
        from ptw.package_evidence import EvidenceError
        from test_packages import CRITICAL
        from test_product_reassessment import AdvisoryFixture
        for failure in ('quota', 'storage'):
            with self.subTest(failure=failure):
                fixture = self.fixture()
                duplicate = fixture.make_set([fixture.evidence])
                fixture.expire()
                with fixture.store.locked() as db:
                    count = db.execute('SELECT count(*) FROM package_assessments').fetchone()[0]
                    if failure == 'storage':
                        db.execute("CREATE TRIGGER fail_second BEFORE INSERT ON package_assessments "
                            "WHEN (SELECT count(*) FROM package_assessments) > " + str(count) +
                            " BEGIN SELECT RAISE(FAIL,'fixture assessment failure'); END")
                calls = []
                def admission(db, project, size, **kwargs):
                    calls.append(size)
                    if failure == 'quota' and len(calls) == 2:
                        for _ in range(3):
                            self.limit(db, usage(db, project) + size - 1)
                    return admit(db, project, size, **kwargs)
                with patch('ptw.reassessment.admit', side_effect=admission), \
                        self.assertRaises((QuotaError, sqlite3.Error)):
                    fixture.reuse(AdvisoryFixture({('idna', '3.11'): [CRITICAL]}))
                self.assertEqual(len(calls), 2)
                fixture.store = Store(fixture.store.directory)
                self.assertTrue(fixture.store.status('website')['stopped'])
                self.assertEqual(fixture.store.status('website')['violations'], 0)
                for package in (fixture.package, duplicate):
                    self.assertEqual(fixture.row(package)['assessment_state'], 'quarantined')
                    with self.assertRaises(Invalid):
                        fixture.reuse(identity=package)
                with fixture.store.locked() as db:
                    self.assertEqual(db.execute('SELECT count(*) FROM package_assessments').fetchone()[0], count)

    def test_discarded_refresh_retains_winner_and_capture_failure_stops_reuse(self):
        from ptw.evidence_storage import usage
        from test_product_reassessment import AdvisoryFixture
        for change in ('closed', 'concurrent'):
            for fault in (None, 'quota', 'storage'):
                with self.subTest(change=change, fault=fault):
                    fixture = self.fixture()
                    fixture.expire()
                    winner = {}
                    def changed(*args):
                        if change == 'closed':
                            fixture.store.close_session(fixture.a['token'])
                        else:
                            fixture.reuse()
                        winner.update(fixture.row())
                        with fixture.store.locked() as db:
                            if fault == 'quota':
                                for _ in range(3):
                                    self.limit(db, usage(db, 'website'))
                            elif fault == 'storage':
                                db.execute("CREATE TRIGGER fail_discard BEFORE INSERT ON package_assessments "
                                    "WHEN NEW.outcome='discarded' BEGIN SELECT RAISE(FAIL,'fixture capture failure'); END")
                        return []
                    provider = AdvisoryFixture()
                    provider.advisories = changed
                    if fault or change == 'closed':
                        with self.assertRaises((Invalid, QuotaError, sqlite3.Error)):
                            fixture.reuse(provider)
                    else:
                        fixture.reuse(provider)
                    fixture.store = Store(fixture.store.directory)
                    self.assertEqual(fixture.row(), winner)
                    with fixture.store.locked() as db:
                        discarded = db.execute("SELECT * FROM package_assessments WHERE outcome='discarded'").fetchall()
                    self.assertEqual(len(discarded), int(fault is None))
                    if discarded:
                        detail = json.loads(discarded[0]['detail'])
                        self.assertIn('reason', detail)
                        self.assertEqual(detail['_audit']['requester']['id'], fixture.a['session'])
                    status = fixture.store.status('website')
                    self.assertEqual(status['stopped'], bool(fault))
                    self.assertEqual(status['violations'], 0)
                    if fault:
                        with self.assertRaises(Invalid):
                            fixture.reuse()

    def test_failed_current_blocked_and_missing_capture_never_commits_eligibility(self):
        from ptw.evidence_storage import usage
        from ptw.package_evidence import EvidenceError
        from test_product_reassessment import AdvisoryFixture
        for outcome in ('current', 'blocked', 'missing'):
            for fault in ('quota', 'storage'):
                with self.subTest(outcome=outcome, fault=fault):
                    fixture = self.fixture()
                    fixture.expire()
                    with fixture.store.locked() as db:
                        if outcome == 'missing':
                            db.execute('UPDATE package_sets SET evidence=NULL WHERE id=?', (fixture.package,))
                        count = db.execute('SELECT count(*) FROM package_assessments').fetchone()[0]
                        if fault == 'quota':
                            for _ in range(3):
                                self.limit(db, usage(db, 'website'))
                        else:
                            db.execute("CREATE TRIGGER fail_assessment BEFORE INSERT ON package_assessments "
                                       "BEGIN SELECT RAISE(FAIL,'fixture capture failure'); END")
                    before = fixture.row()
                    provider = AdvisoryFixture({('idna', '3.11'): EvidenceError('fixture offline')}
                                               if outcome == 'blocked' else None)
                    with self.assertRaises((QuotaError, sqlite3.Error)):
                        fixture.reuse(provider)
                    fixture.store = Store(fixture.store.directory)
                    self.assertEqual(fixture.row(), before)
                    with fixture.store.locked() as db:
                        self.assertEqual(db.execute('SELECT count(*) FROM package_assessments').fetchone()[0], count)
                    self.assertTrue(fixture.store.status('website')['stopped'])
                    self.assertEqual(fixture.store.status('website')['violations'], 0)
                    if outcome == 'missing':
                        self.assertEqual(provider.calls, [])

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'Requires native process crash/recovery')
    def test_direct_launch_abrupt_refresh_death_has_atomic_eligibility(self):
        import multiprocessing
        from ptw.package_evidence import EvidenceError
        from ptw.packages import mounted_set
        from ptw.reassessment import attempt, refresh
        from ptw.supervisor import Supervisor
        from test_product_reassessment import AdvisoryFixture
        for phase in ('before_receipt', 'after_receipt', 'after_commit'):
            with self.subTest(phase=phase):
                fixture = self.fixture()
                fixture.expire()
                before = fixture.row()
                with fixture.store.locked() as db:
                    count = db.execute('SELECT count(*) FROM package_assessments').fetchone()[0]
                def capture(db, *args, **kwargs):
                    if phase == 'after_receipt':
                        attempt(db, *args, **kwargs)
                    os._exit(77)
                def committed(*args, **kwargs):
                    refresh(*args, **kwargs)
                    os._exit(77)
                def run():
                    target = 'ptw.reassessment.refresh' if phase == 'after_commit' else 'ptw.reassessment.attempt'
                    with patch('ptw.registry.provider_for', return_value=AdvisoryFixture()), \
                            patch(target, side_effect=committed if phase == 'after_commit' else capture):
                        Supervisor(fixture.store).launch(fixture.a['token'], ['/usr/bin/true'],
                                                         package_set=fixture.package)
                child = multiprocessing.get_context('fork').Process(target=run)
                child.start()
                try:
                    child.join(15)
                    self.assertEqual(child.exitcode, 77)
                finally:
                    if child.is_alive():
                        child.kill()
                        child.join(5)
                fixture.store = Store(fixture.store.directory)
                after = fixture.row()
                with fixture.store.locked() as db:
                    self.assertEqual(db.execute('SELECT count(*) FROM workloads').fetchone()[0], 0)
                    self.assertEqual(db.execute("SELECT count(*) FROM events WHERE state='pending'").fetchone()[0], 0)
                    self.assertEqual(db.execute('SELECT count(*) FROM package_assessments').fetchone()[0],
                                     count + int(phase == 'after_commit'))
                    actor = fixture.store.session(db, fixture.a['token'])
                    if phase == 'after_commit':
                        mounted_set(fixture.store, db, actor, fixture.package)
                        self.assertEqual(after['assessment_generation'], before['assessment_generation'] + 1)
                    else:
                        self.assertEqual(after, before)
                        with self.assertRaises(EvidenceError):
                            mounted_set(fixture.store, db, actor, fixture.package)
                # Refresh has no external effect or pending launch to replay.
                # Only an explicit new request may collect evidence after death.
                provider = AdvisoryFixture()
                fixture.reuse(provider)
                self.assertEqual(len(provider.calls), int(phase != 'after_commit'))
                self.assertFalse(fixture.store.status('website')['stopped'])

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'Requires native PTY/systemd/confinement')
    def test_launch_capture_fault_stops_effects_retains_other_work_and_terminal_refusal(self):
        import tempfile
        from ptw.evidence_storage import usage
        from ptw.policy import approve, compile_policy, load, save
        from ptw.sample import create
        from ptw.supervisor import Supervisor
        from test_product_reassessment import AdvisoryFixture
        scripts = str(Path(__file__).resolve().parents[1] / 'scripts')
        with patch.object(sys, 'path', [scripts, *sys.path]):
            from terminal_driver import Terminal
        evidence = Path(tempfile.mkdtemp(prefix='ptw-audit-reuse-native-'))
        print('AUDIT_REUSE_EVIDENCE ' + str(evidence), flush=True)
        source = Path(__file__).resolve().parents[1]
        save(evidence / 'source.json', {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in [*sorted((source / 'ptw').rglob('*.py')), Path(__file__).resolve(),
                       source / 'scripts/terminal_driver.py', source / 'tests/test_product_reassessment.py']})
        for fault in ('quota', 'storage'):
            with self.subTest(fault=fault):
                fixture = self.fixture()
                installed = fixture.install()
                self.assertTrue(installed['allowed'], installed)
                fixture.package = installed['package_set']
                create(fixture.root / 'other-project', packages=True)
                other_inv = load(fixture.root / 'other-project/inventory.json')
                other_policy = copy.deepcopy(fixture.policy)
                other_policy['project']['id'] = 'unrelated'
                fixture.store.activate(approve(other_policy, other_inv,
                    digest(compile_policy(other_policy, other_inv)), 'fixture operator'))
                other = fixture.store.register('unrelated', 'frontend')
                supervisor = Supervisor(fixture.store)
                units, observations = [], {}
                paths = [Path(inv['root']) / inv['resources']['ui']['path'] for inv in (fixture.inv, other_inv)]
                code = ("import time\nfrom pathlib import Path\np=Path('/resources/ui')\n"
                        "p.write_text('SYNTHETIC_PACKAGE_OK\\n')\n"
                        "while True:\n"
                        " with p.open('a') as f: f.write('tick ' + str(time.monotonic()) + chr(10)); f.flush()\n"
                        " time.sleep(.05)\n")
                # Real installed import precedes the continuously observable effect.
                affected_code = 'import idna; assert idna.VALUE == "SYNTHETIC_PACKAGE_OK"; ' + code
                try:
                    units.append(supervisor.launch(fixture.a['token'], ['/usr/bin/python3', '-c', affected_code],
                                                   package_set=fixture.package))
                    self.addCleanup(supervisor.terminate, units[-1])
                    units.append(supervisor.launch(other['token'], ['/usr/bin/python3', '-c', code]))
                    self.addCleanup(supervisor.terminate, units[-1])
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline and not all('tick' in p.read_text() for p in paths):
                        time.sleep(.05)
                    self.assertTrue(all('tick' in p.read_text() for p in paths))
                    fixture.expire()
                    before = fixture.row()
                    with fixture.store.locked() as db:
                        count = db.execute('SELECT count(*) FROM package_assessments').fetchone()[0]
                        workload_count = db.execute('SELECT count(*) FROM workloads').fetchone()[0]
                        if fault == 'quota':
                            for _ in range(3):
                                self.limit(db, usage(db, 'website'))
                        else:
                            db.execute("CREATE TRIGGER fail_assessment BEFORE INSERT ON package_assessments "
                                       "BEGIN SELECT RAISE(FAIL,'fixture capture failure'); END")
                    with patch('ptw.registry.provider_for', return_value=AdvisoryFixture()), \
                            self.assertRaises((QuotaError, sqlite3.Error)):
                        supervisor.launch(fixture.a['token'], ['/usr/bin/true'], package_set=fixture.package)
                    self.assertTrue(supervisor.state(units[0])['confirmed_stopped'])
                    snapshots = [p.read_text() for p in paths]
                    time.sleep(.2)
                    observations['affected_unchanged'] = paths[0].read_text() == snapshots[0]
                    observations['unrelated_continues'] = paths[1].read_text() != snapshots[1]
                    self.assertTrue(observations['affected_unchanged'])
                    self.assertTrue(observations['unrelated_continues'])
                    self.assertEqual(fixture.row(), before)
                    with fixture.store.locked() as db:
                        self.assertEqual(db.execute('SELECT count(*) FROM package_assessments').fetchone()[0], count)
                        self.assertEqual(db.execute('SELECT count(*) FROM workloads').fetchone()[0], workload_count)
                        if fault == 'storage':
                            db.execute('DROP TRIGGER fail_assessment')
                    # Restore capture capacity through the exact public operator review.
                    packet = fixture.store.evidence_review('website', DEFAULT)
                    fixture.store.adopt_evidence('website', DEFAULT, digest(packet), 'fixture operator')
                    supervisor.reconcile()
                    self.assertTrue(fixture.store.status('website')['stopped'])
                    self.assertEqual(fixture.store.status('website')['violations'], 0)
                    self.assertFalse(fixture.store.status('unrelated')['stopped'])
                    for label, actor, extra, expected in (
                            ('blocked', fixture.a, ['--package-set', fixture.package], 2),
                            ('permitted', other, [], 0)):
                        session = fixture.root / (label + '.json')
                        save(session, actor)
                        command = ['/usr/bin/python3', '-c', "open('/resources/ui','a').write('TERMINAL_OK\\n')"]
                        terminal = Terminal([sys.executable, '-B', '-m', 'ptw', 'launch',
                            '--state', str(fixture.store.directory), '--session', str(session), *extra,
                            '--', *command], evidence / (fault + '-' + label))
                        try:
                            terminal.wait(lambda: terminal.exited, 20, 'reassessment launch terminal')
                            self.assertEqual(terminal.close(), expected)
                            if label == 'blocked':
                                self.assertIn('stopped', terminal.text.lower())
                        finally:
                            if not terminal.closed:
                                terminal.close(graceful=False)
                    deadline = time.monotonic() + 10
                    while 'TERMINAL_OK' not in paths[1].read_text() and time.monotonic() < deadline:
                        time.sleep(.05)
                    self.assertIn('TERMINAL_OK', paths[1].read_text())
                    self.assertNotIn('TERMINAL_OK', paths[0].read_text())
                finally:
                    save(evidence / (fault + '-observations.json'), {
                        'fixture': 'synthetic advisories and injected required capture failure',
                        'observations': observations,
                        'projects': [fixture.store.status(p) for p in ('website', 'unrelated')],
                        'physical': [supervisor.state(unit) for unit in units]})
                    for project in ('website', 'unrelated'):
                        fixture.store.stop(project)
                    supervisor.reconcile()


class AuditInstallTests(workspace_fixtures.WorkspaceFixture):
    """Real dispatch/installer effects; registry responses are synthetic fixtures."""

    def install_events(self, *, reversed_slots=False):
        from ptw.store import operation_lease
        body = request('install', 'dependencies', content='pypi')
        seen = {}
        for index in range(10000):
            event = 'install-audit-' + str(index)
            inner = 'install-' + digest([event, body])[:48]
            slots = tuple(operation_lease(self.actor['session'], e) for e in (event, inner))
            if not reversed_slots and slots[0] == slots[1]:
                return body, [event]
            if reversed_slots and slots[0] != slots[1] and slots[::-1] in seen:
                return body, [seen[slots[::-1]], event]
            seen[slots] = event
        self.fail('Could not find fixture slot collision')

    def isolated(self, run):
        # A regression must fail within a bound, not strand unittest threads
        # inside flock or ThreadPoolExecutor.shutdown(). No model/network calls.
        import multiprocessing
        import traceback
        context = multiprocessing.get_context('fork')
        receiver, sender = context.Pipe(duplex=False)
        def child():
            receiver.close()
            try:
                result = run()
                sender.send({'result': result})
            except BaseException:
                sender.send({'error': traceback.format_exc()})
            finally:
                sender.close()
        process = context.Process(target=child)
        process.start()
        sender.close()
        try:
            self.assertTrue(receiver.poll(60), 'Install dispatch did not complete within 60 seconds')
            result = receiver.recv()
            process.join(5)
            self.assertEqual(process.exitcode, 0, result)
            self.assertNotIn('error', result, result.get('error'))
            return result['result']
        finally:
            if process.is_alive():
                process.kill()
                process.join(5)
            receiver.close()

    def useful_install(self, result):
        import subprocess
        from ptw.packages import mounted_set
        from ptw.supervisor import sandbox_command
        self.assertTrue(result['allowed'], result)
        with self.store.locked() as db:
            mount = mounted_set(self.store, db, self.store.session(db, self.actor['token']), result['package_set'])
        run = subprocess.run(sandbox_command(self.inv, [],
            ['/usr/bin/python3', '-c', 'import six; print(six.VALUE)'], package_mount=mount),
            capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn('SYNTHETIC_PACKAGE_OK', run.stdout)

    def registry_publication_fault(self, phase):
        from ptw.evidence_storage import admit, usage
        from ptw.packages import PackageControl, mounted_set
        from ptw.supervisor import Supervisor
        from test_packages import FixtureProvider
        fixture = workspace_fixtures.WorkspaceFixture()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        store, actor = fixture.store, fixture.actor
        packet = store.evidence_review('python-demo', DEFAULT)
        store.adopt_evidence('python-demo', DEFAULT, digest(packet), 'fixture operator')
        running = []
        for owner, session in ((store, actor), (self.store, self.actor)):
            process, unit = Supervisor(owner).engine(session['token'], ['/usr/bin/sleep', '90'])
            running.append((process, unit))
            def cleanup(owner=owner, process=process, unit=unit):
                Supervisor(owner).terminate(unit)
                process.communicate(timeout=10)
            self.addCleanup(cleanup)
        self.assertTrue(all(process.poll() is None for process, _ in running))
        if phase in ('assessment', 'completion', 'stop-state'):
            target = ('BEFORE INSERT ON package_assessments' if phase != 'completion' else
                      "BEFORE UPDATE ON events WHEN NEW.event='registry-fault' AND NEW.state='complete'")
            with store.locked() as db:
                db.execute('CREATE TRIGGER reject_registry ' + target +
                           " BEGIN SELECT RAISE(FAIL,'injected registry capture failure'); END")
                if phase == 'stop-state':
                    db.execute("CREATE TRIGGER reject_stop BEFORE UPDATE ON projects_storage "
                               "WHEN NEW.id='python-demo' AND NEW.stopped=1 "
                               "BEGIN SELECT RAISE(FAIL,'injected stop storage failure'); END")
        begin, rename = store.begin, os.rename
        intents, assessment_admissions, effects = [], [], []
        def limit(db, project, headroom):
            # The injected quota includes the profile's own serialized size.
            # Two passes stabilize the decimal width of project_bytes.
            for _ in range(2):
                db.execute('UPDATE evidence_profiles SET profile=? WHERE project=?',
                           (canonical({**DEFAULT, 'project_bytes': usage(db, project) + headroom}), project))
        def admission(db, session, event, *args, **kwargs):
            result = begin(db, session, event, *args, **kwargs)
            if event == 'registry-fault':
                intents.append(event)
                if len(intents) == 2 and phase == 'package-quota':
                    # Preparation and its reservation fit; the new package row cannot.
                    limit(db, 'python-demo', 1)
            return result
        def assessment_admission(db, project, size, **kwargs):
            assessment_admissions.append(size)
            if phase == 'assessment-quota':
                # Leave one byte less than the complete assessment row needs;
                # admission must reject before any installation rename.
                limit(db, project, size - 1)
            result = admit(db, project, size, **kwargs)
            return result
        def observed(src, dst, *args, **kwargs):
            result = rename(src, dst, *args, **kwargs)
            if Path(dst).parent == store.directory / 'package-sets':
                effects.append(Path(dst))
                self.assertIn('SYNTHETIC_PACKAGE_OK', (Path(dst) / 'six/__init__.py').read_text())
            return result
        provider = FixtureProvider()
        control = PackageControl(store, provider=provider)
        with patch.object(store, 'begin', side_effect=admission), \
                patch('ptw.reassessment.admit', side_effect=assessment_admission), \
                patch('ptw.packages.os.rename', side_effect=observed):
            if phase == 'stop-state':
                with self.assertRaisesRegex(sqlite3.Error, 'injected stop storage failure'):
                    control.install(actor['token'], 'registry-fault', ['six==1.17.0'])
            else:
                result = control.install(actor['token'], 'registry-fault', ['six==1.17.0'])
        self.assertEqual(len(intents), 2)
        self.assertEqual(provider.downloads, 1)  # Real isolated preparation ran.
        if phase != 'stop-state':
            self.assertFalse(result['allowed'], result)
            self.assertEqual(result['effect'], 'unknown')
        self.assertEqual(bool(effects), phase == 'completion')
        self.assertEqual(list((store.directory / 'package-sets').glob('*')), effects)
        if phase == 'assessment-quota':
            self.assertEqual(len(assessment_admissions), 1)
        with store.locked() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM package_sets').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT count(*) FROM package_assessments').fetchone()[0], 0)
            if effects:
                with self.assertRaises(Invalid):
                    mounted_set(store, db, store.session(db, actor['token']), effects[0].name)
            if phase == 'stop-state':
                self.assertFalse(store.project(db, 'python-demo')[0]['stopped'])
                self.assertEqual(db.execute("SELECT state FROM events WHERE event='registry-fault'").fetchone()[0], 'pending')
                db.execute('DROP TRIGGER reject_stop')
            if phase in ('assessment', 'completion', 'stop-state'):
                db.execute('DROP TRIGGER reject_registry')
        running[0][0].communicate(timeout=10)
        self.assertTrue(Supervisor.state(running[0][1])['confirmed_stopped'])
        self.assertIsNone(running[1][0].poll())
        self.assertTrue(self.ask('read')['allowed'])
        self.assertFalse(self.store.status('python-demo')['stopped'])
        reopened = Store(store.directory)
        self.assertTrue(reopened.status('python-demo')['stopped'])
        self.assertEqual(reopened.status('python-demo')['violations'], 0)
        event = next(e for e in reopened.audit_events('python-demo') if e['event'] == 'registry-fault')
        self.assertEqual(event['state'], 'uncertain')
        self.assertEqual(event['audit']['decision'], 'allow')
        with patch.object(provider, 'assess', side_effect=AssertionError('uncertain installation retried')):
            replay = PackageControl(reopened, provider=provider).install(
                actor['token'], 'registry-fault', ['six==1.17.0'])
        self.assertTrue(replay['replayed'])
        self.assertFalse(replay['allowed'])
        self.assertEqual(provider.downloads, 1)
        self.assertIsNone(running[1][0].poll())

    def test_registry_quota_accounts_package_and_assessment_before_rename(self):
        for phase in ('package-quota', 'assessment-quota'):
            with self.subTest(phase=phase):
                self.registry_publication_fault(phase)

    def test_registry_capture_fault_retains_uncertainty_and_stops_only_affected_work(self):
        for phase in ('assessment', 'completion', 'stop-state'):
            with self.subTest(phase=phase):
                self.registry_publication_fault(phase)

    def test_dispatch_nested_collision_installs_once_and_live_reopen_preserves_intents(self):
        from ptw.workflow import dispatch
        from test_packages import FixtureProvider
        packet = self.store.evidence_review('python-demo', DEFAULT)
        self.store.adopt_evidence('python-demo', DEFAULT, digest(packet), 'fixture operator')
        body, (event,) = self.install_events()
        def run():
            provider = FixtureProvider()
            entered, finish = threading.Event(), threading.Event()
            assess = provider.assess
            def delayed(*args):
                reopened = Store(self.store.directory)
                self.assertFalse(reopened.status('python-demo')['stopped'])
                self.assertEqual(sum(r['state'] == 'pending' for r in reopened.audit_events('python-demo')), 2)
                entered.set()
                self.assertTrue(finish.wait(5))
                return assess(*args)
            with patch('ptw.registry.provider_for', return_value=provider), patch.object(provider, 'assess', side_effect=delayed):
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    original = pool.submit(dispatch, self.store, self.actor, event, body)
                    try:
                        self.assertTrue(entered.wait(5))
                        retry = pool.submit(dispatch, Store(self.store.directory), self.actor, event, body)
                        self.assertFalse(retry.done())
                    finally:
                        finish.set()
                    first, second = original.result(timeout=20), retry.result(timeout=20)
                self.useful_install(first)
                self.assertTrue(second['replayed'])
                self.assertEqual(second['package_set'], first['package_set'])
                self.assertEqual(provider.downloads, 1)
                self.assertEqual(len(list(self.store.directory.glob('operation-*.lock'))), 1)
                self.assertTrue(dispatch(self.store, self.actor, event, body)['replayed'])
            self.assertTrue(all(r['state'] == 'complete' for r in self.store.audit_events('python-demo')))
            document = self.store.audit_export('python-demo')
            installed = next(e for e in document['events'] if e['request']['action'] == 'package_install')
            self.assertEqual(document['assessments'][0]['audit']['cause'], installed['audit']['operation_id'])
            verify_export(document, digest(document))
        self.isolated(run)

    def test_dispatch_concurrent_reversed_slots_complete_and_replay_distinct_installs(self):
        from ptw.workflow import dispatch, _dispatch
        from test_packages import FixtureProvider
        body, events = self.install_events(reversed_slots=True)
        def run():
            provider = FixtureProvider()
            rendezvous = threading.Barrier(2)
            def overlapping(*args):
                # Old code gets both outer locks before either inner lock.
                # Ordered reservation serializes here, so the first waits at
                # most one second before continuing with both slots held.
                try:
                    rendezvous.wait(timeout=1)
                except threading.BrokenBarrierError:
                    pass
                return _dispatch(*args)
            with patch('ptw.registry.provider_for', return_value=provider), patch('ptw.workflow._dispatch', side_effect=overlapping):
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    pending = [pool.submit(dispatch, self.store, self.actor, e, body) for e in events]
                    results = [future.result(timeout=25) for future in pending]
                self.assertEqual(len({r['package_set'] for r in results}), 2)
                for event, result in zip(events, results):
                    self.useful_install(result)
                    replay = dispatch(self.store, self.actor, event, body)
                    self.assertTrue(replay['replayed'])
                    self.assertEqual(replay['package_set'], result['package_set'])
                self.assertEqual(provider.downloads, 2)
                self.assertEqual(len(list(self.store.directory.glob('operation-*.lock'))), 2)
            self.assertFalse(self.store.status('python-demo')['stopped'])
            self.assertEqual(self.store.status('python-demo')['violations'], 0)
        self.isolated(run)

    def test_dispatch_abrupt_nested_install_crash_stops_without_reinstallation(self):
        from ptw.workflow import dispatch
        from ptw.packages import install_wheels
        from test_packages import FixtureProvider
        body, events = self.install_events(reversed_slots=True)
        event = events[0]
        observed = self.root / 'staged-install.json'
        def run():
            def crash(wheelhouse, target, evidence, **kwargs):
                install_wheels(wheelhouse, target, evidence, **kwargs)
                # Independent physical oracle before abrupt exit, no finally.
                observed.write_text(json.dumps({'module': (target / 'six/__init__.py').read_text()}))
                os._exit(77)
            with patch('ptw.registry.provider_for', return_value=FixtureProvider()), patch('ptw.packages.install_wheels', side_effect=crash):
                dispatch(self.store, self.actor, event, body)
        # Unlike isolated(), this child intentionally exits before sending.
        import multiprocessing
        process = multiprocessing.get_context('fork').Process(target=run)
        process.start()
        try:
            process.join(30)
            self.assertEqual(process.exitcode, 77)
            self.assertIn('SYNTHETIC_PACKAGE_OK', json.loads(observed.read_text())['module'])
            recovered = Store(self.store.directory)
            self.assertTrue(recovered.status('python-demo')['stopped'])
            rows = recovered.audit_events('python-demo')
            self.assertEqual(sum(r['state'] == 'uncertain' for r in rows), 2)
            self.assertEqual(recovered.status('python-demo')['violations'], 0)
            with recovered.locked() as db:
                self.assertEqual(db.execute('SELECT count(*) FROM package_sets').fetchone()[0], 0)
            with patch('ptw.registry.provider_for') as provider:
                retry = dispatch(recovered, self.actor, event, body)
            self.assertTrue(retry['replayed'])
            self.assertFalse(retry['allowed'])
            provider.assert_not_called()
        finally:
            if process.is_alive():
                process.kill()
                process.join(5)


class AuditLegacyReadTests(unittest.TestCase):
    def setUp(self):
        import test_core
        self.approved = lambda: test_core.Fixture.approved(self)
        test_core.Fixture.setUp(self)

    def adopt(self, resources):
        profile = {**DEFAULT, 'content_resources': resources}
        packet = self.store.evidence_review('website', profile)
        self.store.adopt_evidence('website', profile, digest(packet), 'fixture operator')

    def read(self, event, resource='ui'):
        return self.store.request(self.a['token'], event,
                                  {'action': 'read', 'resource': resource, 'content': ''})

    def test_public_read_opt_in_completion_truncation_replay_and_denial(self):
        self.adopt([])
        self.assertTrue(self.read('default')['allowed'])
        self.adopt(['ui'])
        text = 'bounded fixture\n' * 20000
        (Path(self.inv['root']) / 'ui.txt').write_text(text)
        result = self.read('captured')
        self.assertEqual(result['content'], text)
        self.assertTrue(self.read('captured')['replayed'])
        retained = self.store.evidence_content('website', digest([self.a['session'], 'captured']))
        self.assertEqual(retained['payload'], text.encode()[:PAYLOAD_BYTES])
        self.assertEqual(retained['status'], 'truncated')
        denied_actor = self.store.register('website', 'frontend', grants=[])
        self.assertFalse(self.store.request(denied_actor['token'], 'denied',
            {'action': 'read', 'resource': 'ui', 'content': ''})['allowed'])
        with self.store.locked() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM evidence_payloads').fetchone()[0], 1)
        rows = self.store.audit_events('website')
        self.assertEqual(rows[0]['audit']['content'], 'omitted')
        self.assertEqual(rows[1]['audit']['content'], 'truncated')
        self.assertNotIn('bounded fixture', canonical(self.store.audit_export('website')))

    def test_optional_read_write_failure_keeps_useful_result_and_visible_gap(self):
        self.adopt(['ui'])
        with self.store.locked() as db:
            db.execute("CREATE TRIGGER reject_optional BEFORE INSERT ON evidence_payloads "
                       "BEGIN SELECT RAISE(FAIL,'injected optional read capture failure'); END")
        result = self.read('optional-fault')
        self.assertEqual(result['content'], 'Welcome\n')
        with self.store.locked() as db:
            db.execute('DROP TRIGGER reject_optional')
        self.assertTrue(self.read('optional-fault')['replayed'])
        self.assertEqual(self.store.audit_events('website')[0]['audit']['content'], 'unavailable')
        with self.store.locked() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM evidence_payloads').fetchone()[0], 0)
        self.assertTrue(self.read('next')['allowed'])
        self.assertEqual(self.store.audit_events('website')[-1]['audit']['content'], 'captured')
        self.assertFalse(self.store.status('website')['stopped'])
        self.assertEqual(self.store.status('website')['violations'], 0)


class AuditPolicyTests(unittest.TestCase):
    # Reuse fixture builders without inheriting their already discovered tests.
    setUp = ecosystem_fixtures.DependencyRevisionTests.setUp
    activated = ecosystem_fixtures.DependencyRevisionTests.activated
    remove = ecosystem_fixtures.DependencyRevisionTests.remove

    def test_reviewed_rule_change_keeps_original_authority_and_useful_continuation(self):
        _, store, old_actor, old_bundle, _ = self.activated()
        original = store.audit_export('revision-project')['events']
        self.remove()  # Exact operator review via the existing dependency CLI fixture.
        new_actor = store.register('revision-project', 'work')
        resource = next(r for r, item in old_bundle['inventory']['resources'].items() if item['path'] == 'src')
        result = Workspace(store).request(new_actor['token'], 'after-review', request('read', resource, 'app.py'))
        self.assertTrue(result['allowed'], result)
        self.assertEqual(result['content'], 'VALUE = 42\n')
        rows = store.audit_export('revision-project')['events']
        self.assertEqual(rows[:len(original)], original)
        revised = next(r for r in rows if r['request']['action'] == 'policy_revised')
        self.assertEqual(revised['audit']['details']['previous_policy_sha256'], old_bundle['approval']['sha256'])
        self.assertTrue(revised['audit']['authorization']['human_review_performed'])
        self.assertNotEqual(revised['audit']['policy_sha256'], old_bundle['approval']['sha256'])
        self.assertEqual(rows[-1]['audit']['policy_sha256'], revised['audit']['policy_sha256'])
        self.assertEqual(store.status('revision-project')['violations'], 1)
        with self.assertRaises(Invalid):
            Workspace(store).request(old_actor['token'], 'revoked', request('read', resource, 'app.py'))


class AuditCheckpointTests(daily_fixtures.LocalGitFixture):
    def test_checkpoint_pending_review_pins_payload_and_quota_blocks_ref_publication(self):
        profile = {**DEFAULT, 'content_resources': ['src']}
        packet = self.store.evidence_review('python-demo', profile)
        self.store.adopt_evidence('python-demo', profile, digest(packet), 'operator')
        self.changed()
        prepared = self.checkpoint()
        self.assertTrue(prepared['allowed'])
        with self.store.locked() as db:
            db.execute('UPDATE evidence_payloads SET at=?', (time.time() - RETENTION_SECONDS - 1,))
        self.assertTrue(self.store.expire_evidence('python-demo')['pinned'])
        # A reviewed smaller budget is sufficient for retained history, but
        # cannot reserve a new physical publication. No host disk is filled.
        reduced = {**profile, 'project_bytes': 2 * 1024 * 1024}
        packet = self.store.evidence_review('python-demo', reduced)
        self.store.adopt_evidence('python-demo', reduced, digest(packet), 'operator')
        from ptw.local_git import publish_checkpoint
        with self.assertRaises(QuotaError):
            publish_checkpoint(self.store, prepared['checkpoint'], prepared['review_sha256'])
        self.assertNotIn('refs/ptw/checkpoints/' + prepared['checkpoint'], self.git('show-ref').decode())
        self.assertTrue(self.store.status('python-demo')['stopped'])
        self.assertEqual(self.store.status('python-demo')['violations'], 0)

    def test_exact_human_approval_and_automatic_edit_have_distinct_provenance(self):
        self.changed()
        prepared = self.checkpoint()
        self.assertTrue(prepared['allowed'], prepared)
        before = self.store.audit_events('python-demo')
        self.assertTrue(before[-1]['audit']['authorization']['human_review_required'])
        self.assertFalse(before[-1]['audit']['authorization']['human_review_performed'])
        published = self.publish(prepared)
        self.assertEqual(self.git('rev-parse', published['ref']).decode().strip(), published['commit'])
        after = self.store.audit_events('python-demo')
        self.assertEqual(after[:-1], before)
        authority = after[-1]['audit']['authorization']
        self.assertEqual(authority['method'], 'exact_operator_approval')
        self.assertEqual(authority['receipt_sha256'], prepared['review_sha256'])
        self.assertTrue(authority['human_review_performed'])
        self.assertEqual(after[-1]['audit']['requester']['kind'], 'local_operator')

    def test_required_completion_fault_keeps_checkpoint_stopped_and_uncertain(self):
        self.changed()
        prepared = self.checkpoint()
        with patch.object(self.store, 'complete', side_effect=OSError('injected capture failure')):
            with self.assertRaises(OSError):
                self.publish(prepared)
        self.assertTrue(self.store.status('python-demo')['stopped'])
        recovered = Store(self.store.directory)
        self.assertEqual(recovered.audit_events('python-demo')[-1]['state'], 'uncertain')
        self.assertEqual(self.git('rev-parse', 'refs/ptw/checkpoints/' + prepared['checkpoint']).decode().strip(),
                         json.loads((self.store.directory / 'git-requests' / prepared['checkpoint'] / 'review.json').read_text())['commit'])
        self.assertEqual(recovered.status('python-demo')['violations'], 0)


@unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'Requires native manager terminal/supervisor')
class AuditTerminalTests(daily_fixtures.LocalGitFixture):
    def test_terminal_evidence_review_stale_rejection_and_explicit_adoption(self):
        scripts = str(Path(__file__).resolve().parents[1] / 'scripts')
        with patch.object(sys, 'path', [scripts, *sys.path]):
            from terminal_driver import Terminal
        packet = self.store.evidence_review('python-demo', DEFAULT)
        original = self.store.status('python-demo')
        argv = [sys.executable, '-B', '-m', 'ptw', 'evidence-config', '--state', str(self.store.directory),
                '--project', 'python-demo']
        # A review-only command and a failed exact hash cannot adopt silently.
        for name, extra, code in (
                ('review-only', [], 0), ('rejected', ['--approve', '0' * 64, '--reviewer', 'operator'], 2),
                ('adopted', ['--approve', digest(packet), '--reviewer', 'operator'], 0)):
            terminal = Terminal(argv + extra, self.root / name)
            try:
                terminal.wait(lambda: terminal.exited, 20, 'evidence configuration terminal')
                self.assertEqual(terminal.close(), code)
            finally:
                if not terminal.closed:
                    terminal.close(graceful=False)
            profile = Store(self.store.directory).audit_export('python-demo')['profile']
            self.assertEqual(profile, DEFAULT if name == 'adopted' else None)
            self.assertEqual(self.store.status('python-demo'), original)
        self.assertTrue(self.ask('read')['allowed'])

    def test_real_terminal_approval_rejection_and_audit_authority(self):
        from ptw.onboarding import private_directory
        from ptw.policy import save
        scripts = str(Path(__file__).resolve().parents[1] / 'scripts')
        with patch.object(sys, 'path', [scripts, *sys.path]):
            from terminal_driver import Terminal
        operator = self.root / 'operator'
        with patch.dict(os.environ, {'PTW_USER_STATE': str(operator)}):
            directory = private_directory(self.repo)
        save(directory / 'project.json', {'project': 'python-demo', 'repo': str(self.repo),
                                         'state': str(self.store.directory)})
        self.changed()
        # Preparation uses the existing deterministic Git fixture; decisions
        # are real CLI terminal input and publication is real Git ref mutation.
        for accepted in (False, True):
            with self.store.locked() as db:
                db.execute('INSERT OR REPLACE INTO monitor_health VALUES(1,?,?)', (time.time(), ''))
            prepared = self.checkpoint()
            self.assertTrue(prepared['allowed'])
            terminal = Terminal([sys.executable, '-B', '-m', 'ptw', 'checkpoint', prepared['checkpoint'],
                                 '--repo', str(self.repo)], self.root / ('approve' if accepted else 'reject'),
                                env={'PTW_USER_STATE': str(operator)})
            try:
                terminal.expect('Type approve ' + prepared['review_sha256'], 20)
                terminal.send('approve ' + prepared['review_sha256'] if accepted else 'reject')
                terminal.wait(lambda: terminal.exited, 20, 'exact checkpoint decision')
                self.assertEqual(terminal.close(), 0)
            finally:
                if not terminal.closed:
                    terminal.close(graceful=False)
            rows = self.store.audit_export('python-demo')['events']
            if accepted:
                published = next(r for r in rows if r['request']['action'] == 'checkpoint_publish')
                self.assertEqual(self.git('rev-parse', published['result']['ref']).decode().strip(), published['result']['commit'])
                self.assertTrue(published['audit']['authorization']['human_review_performed'])
                self.assertEqual(published['audit']['authorization']['receipt_sha256'], prepared['review_sha256'])
            else:
                rejected = next(r for r in rows if r['request']['action'] == 'checkpoint_rejected')
                self.assertEqual(rejected['audit']['details']['review_sha256'], prepared['review_sha256'])
                self.assertEqual(rejected['audit']['authorization']['method'], 'operator_rejection')
                self.assertTrue(rejected['audit']['authorization']['human_review_performed'])
                self.assertNotIn('refs/ptw/checkpoints/' + prepared['checkpoint'], self.git('show-ref').decode())
                self.assertFalse(any(r['request']['action'] == 'checkpoint_publish' for r in rows))


@unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'Requires isolated native manager systemd/namespaces')
class NativeAuditTests(workspace_fixtures.WorkspaceFixture):
    def test_successful_build_closes_workload_while_session_remains_open(self):
        from ptw.supervisor import Supervisor
        workspace_fixtures.WorkspaceLinux.add_command(self,
            "from pathlib import Path; Path('dist/built.txt').write_text('native build')")
        result = self.ask('run', resource='probe', path='')
        self.assertTrue(result['allowed'], result)
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual((Path(self.inv['root']) / 'dist/built.txt').read_text(), 'native build')
        status = self.store.status('command-demo')
        self.assertFalse(status['stopped'])
        self.assertFalse(status['sessions'][0]['closed'])
        self.assertEqual(len(status['workloads']), 1)
        unit = status['workloads'][0]['unit']
        self.assertTrue(status['workloads'][0]['stopped'])
        self.assertTrue(Supervisor.state(unit)['confirmed_stopped'])
        rows = self.store.audit_export('command-demo')['events']
        terminations = [r for r in rows if r['request']['action'] == 'workload_termination']
        self.assertEqual(len(terminations), 1)
        self.assertTrue(terminations[0]['result']['confirmed_stopped'])
        self.assertIn(digest(['controller:command-demo', 'workload_launch:' + unit]),
                      terminations[0]['audit']['causes'])
        profile = {**DEFAULT, 'content_resources': ['src']}
        review = self.store.evidence_review('command-demo', profile)
        self.assertTrue(self.store.adopt_evidence('command-demo', profile, digest(review), 'operator')['adopted'])
        self.assertEqual(Supervisor(self.store).reconcile(), [])

    def test_build_cleanup_capture_fault_blocks_publication_and_keeps_uncertainty(self):
        from ptw.supervisor import Supervisor
        workspace_fixtures.WorkspaceLinux.add_command(self,
            "from pathlib import Path; Path('dist/uncaptured.txt').write_text('staged')")
        with self.store.locked() as db:
            db.execute("CREATE TRIGGER reject_cleanup BEFORE INSERT ON events "
                "WHEN json_extract(NEW.request_meta,'$.action')='workload_termination' "
                "BEGIN SELECT RAISE(FAIL,'injected cleanup capture failure'); END")
        try:
            result = self.broker.request(self.actor['token'], 'cleanup-fault', request('run', 'probe'))
            self.assertFalse(result['allowed'], result)
            self.assertFalse((Path(self.inv['root']) / 'dist/uncaptured.txt').exists())
            status = self.store.status('command-demo')
            self.assertTrue(status['stopped'])
            self.assertEqual(status['violations'], 0)
            self.assertEqual(len(status['workloads']), 1)
            self.assertFalse(status['workloads'][0]['stopped'])
            self.assertTrue(Supervisor.state(status['workloads'][0]['unit'])['confirmed_stopped'])
            rows = self.store.audit_export('command-demo')['events']
            self.assertFalse(any(r['request']['action'] == 'workload_termination' for r in rows))
            with patch('ptw.execution.execute') as execute:
                self.assertTrue(self.broker.request(self.actor['token'], 'cleanup-fault', request('run', 'probe'))['replayed'])
            execute.assert_not_called()
            other = self.store.register('python-demo', 'implementation')
            self.assertTrue(self.broker.request(other['token'], 'unrelated-read', request('read', 'src', 'calculator.py'))['allowed'])
        finally:
            with self.store.locked() as db:
                db.execute('DROP TRIGGER reject_cleanup')
            Supervisor(self.store).reconcile()

    def test_failed_preview_records_launch_failure_and_cleanup_with_open_session(self):
        import subprocess
        from ptw.monitor import health
        from ptw.supervisor import Supervisor
        script = Path(self.inv['root']) / 'src/server.py'
        script.write_text('raise SystemExit(7)\n')
        self.policy['project']['id'] = 'preview-audit'
        self.policy['project']['commands'].append({
            'id': 'preview', 'argv': ['/usr/bin/python3', '-B', 'src/server.py'],
            'resources': ['src'], 'timeout_seconds': 10,
            'preview': {'port': 8123, 'lifetime_seconds': 30}})
        self.policy['tasks'][0]['commands'].append('preview')
        self.store.activate(self.approve())
        self.actor = self.store.register('preview-audit', 'implementation')
        monitor = subprocess.Popen([sys.executable, '-B', '-m', 'ptw.monitor', '--state', str(self.store.directory)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while not health(self.store)['healthy'] and time.monotonic() < deadline:
                self.assertIsNone(monitor.poll(), 'Fixture monitor exited')
                time.sleep(.05)
            self.assertTrue(health(self.store)['healthy'])
            result = self.broker.request(self.actor['token'], 'failed-preview', request('service_start', 'preview'))
            self.assertFalse(result['allowed'], result)
            self.assertEqual(result['effect'], 'service_start_failed')
            self.assertTrue(result['confirmed_stopped'])
            status = self.store.status('preview-audit')
            self.assertFalse(status['stopped'])
            self.assertFalse(status['sessions'][0]['closed'])
            self.assertEqual(len(status['workloads']), 1)
            self.assertTrue(status['workloads'][0]['stopped'])
            self.assertTrue(Supervisor.state(status['workloads'][0]['unit'])['confirmed_stopped'])
            rows = self.store.audit_export('preview-audit')['events']
            operation = next(r for r in rows if r['event'] == 'failed-preview')
            self.assertEqual(operation['audit']['decision'], 'allow')
            self.assertEqual(operation['audit']['outcome'], 'failed')
            self.assertFalse(operation['result']['allowed'])
            self.assertEqual(operation['result']['unit'], status['workloads'][0]['unit'])
            self.assertTrue(operation['result']['confirmed_stopped'])
            terminations = [r for r in rows if r['request']['action'] == 'workload_termination']
            self.assertEqual(len(terminations), 1)
            self.assertTrue(terminations[0]['result']['confirmed_stopped'])
            self.assertTrue(self.broker.request(self.actor['token'], 'failed-preview', request('service_start', 'preview'))['replayed'])
            profile = {**DEFAULT, 'content_resources': ['src']}
            review = self.store.evidence_review('preview-audit', profile)
            self.assertTrue(self.store.adopt_evidence('preview-audit', profile, digest(review), 'operator')['adopted'])
            other = self.store.register('python-demo', 'implementation')
            self.assertTrue(self.broker.request(other['token'], 'useful', request('read', 'src', 'calculator.py'))['allowed'])
        finally:
            self.store.stop('preview-audit')
            Supervisor(self.store).reconcile()
            monitor.terminate()
            monitor.communicate(timeout=10)

    def test_quota_fault_stops_registered_effects_and_recovers_capture_without_reopening(self):
        from ptw.supervisor import Supervisor
        from ptw.evidence_storage import usage
        workspace_fixtures.WorkspaceLinux.add_command(self, 'pass')
        profile = copy.deepcopy(DEFAULT)
        packet = self.store.evidence_review('command-demo', profile)
        self.store.adopt_evidence('command-demo', profile, digest(packet), 'operator')
        other = self.store.register('python-demo', 'implementation')
        supervisor = Supervisor(self.store)
        running = []
        try:
            for actor, name in ((self.actor, 'quota-affected'), (other, 'quota-unrelated')):
                sentinel = self.root / (name + '.txt')
                code = ("import time; from pathlib import Path; p=Path(" + repr(str(sentinel)) + "); "
                        "\nfor i in range(1000):\n p.write_text(str(i)); time.sleep(.05)")
                process, unit = supervisor.engine(actor['token'], ['/usr/bin/python3', '-c', code])
                running.append((process, unit, sentinel))
            deadline = time.monotonic() + 5
            while not all(p.exists() for _, _, p in running) and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue(all(p.exists() for _, _, p in running))
            before_other = running[1][2].read_text()
            with self.store.locked() as db:
                # Inject an exhausted accounting budget, not a full shared disk.
                exhausted = {**profile, 'project_bytes': usage(db, 'command-demo')}
                db.execute('UPDATE evidence_profiles SET profile=? WHERE project=?',
                           (canonical(exhausted), 'command-demo'))
            with self.assertRaises(QuotaError):
                self.broker.request(self.actor['token'], 'quota-action', request('create', 'dist', 'never.txt', content='never'))
            supervisor.reconcile()
            self.assertTrue(supervisor.state(running[0][1])['confirmed_stopped'])
            self.assertFalse((Path(self.inv['root']) / 'dist/never.txt').exists())
            stopped = running[0][2].read_text()
            time.sleep(.2)
            self.assertEqual(running[0][2].read_text(), stopped)
            self.assertNotEqual(running[1][2].read_text(), before_other)
            self.assertFalse(supervisor.state(running[1][1])['confirmed_stopped'])
            self.assertEqual(self.store.status('command-demo')['violations'], 0)
            self.assertFalse(self.store.status('command-demo')['workloads'][0]['stopped'])
            # Exact operator quota increase permits recording confirmation, but
            # never clears the durable admission stop or reexecutes the request.
            packet = self.store.evidence_review('command-demo', profile)
            self.store.adopt_evidence('command-demo', profile, digest(packet), 'operator')
            result = supervisor.reconcile()
            self.assertTrue(result[0]['confirmed_stopped'])
            self.assertEqual(result[0]['evidence'], 'recorded')
            recovered = Store(self.store.directory)
            self.assertTrue(recovered.status('command-demo')['stopped'])
            self.assertFalse(Workspace(recovered).request(self.actor['token'], 'quota-action',
                request('create', 'dist', 'never.txt', content='never'))['allowed'])
            self.assertTrue(self.broker.request(other['token'], 'continue', request('read', 'src', 'calculator.py'))['allowed'])
        finally:
            for process, unit, _ in running:
                supervisor.terminate(unit)
                process.communicate(timeout=10)
            for project in ('command-demo', 'python-demo'):
                self.store.stop(project)
            supervisor.reconcile()

    def test_termination_capture_fault_preserves_physical_stop_and_unrelated_work(self):
        from ptw.supervisor import Supervisor
        workspace_fixtures.WorkspaceLinux.add_command(self, 'pass')
        other = self.store.register('python-demo', 'implementation')
        supervisor = Supervisor(self.store)
        running = []
        try:
            # Trusted supervisor fixtures, not a claimed unrestricted worker route.
            for actor, name in ((self.actor, 'affected'), (other, 'unrelated')):
                sentinel = self.root / (name + '.txt')
                code = ("import time; from pathlib import Path; p=Path(" + repr(str(sentinel)) + "); "
                        "\nfor i in range(1000):\n p.write_text(str(i)); time.sleep(.05)")
                process, unit = supervisor.engine(actor['token'], ['/usr/bin/python3', '-c', code])
                running.append((process, unit, sentinel))
            deadline = time.monotonic() + 5
            while not all(p.exists() for _, _, p in running) and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue(all(p.exists() for _, _, p in running))
            before_other = running[1][2].read_text()
            self.store.stop('command-demo')
            with self.store.locked() as db:
                db.execute("CREATE TRIGGER reject_termination BEFORE INSERT ON events "
                    "WHEN json_extract(NEW.request_meta,'$.action')='workload_termination' "
                    "BEGIN SELECT RAISE(FAIL,'injected termination capture fault'); END")
            result = supervisor.reconcile()
            self.assertEqual(len(result), 1)
            self.assertTrue(result[0]['confirmed_stopped'])
            self.assertEqual(result[0]['evidence'], 'unavailable')
            stopped_content = running[0][2].read_text()
            self.assertTrue(supervisor.state(running[0][1])['confirmed_stopped'])
            self.assertFalse(self.store.status('command-demo')['workloads'][0]['stopped'])
            time.sleep(.2)
            self.assertEqual(running[0][2].read_text(), stopped_content)
            self.assertNotEqual(running[1][2].read_text(), before_other)
            self.assertFalse(supervisor.state(running[1][1])['confirmed_stopped'])
            self.assertEqual(self.store.status('command-demo')['violations'], 0)
            with self.store.locked() as db:
                db.execute('DROP TRIGGER reject_termination')
            self.assertEqual(supervisor.reconcile()[0]['evidence'], 'recorded')
            rows = self.store.audit_export('command-demo')['events']
            termination = next(r for r in rows if r['request']['action'] == 'workload_termination')
            self.assertTrue(termination['result']['confirmed_stopped'])
            self.assertIn(digest(['controller:command-demo', 'workload_launch:' + running[0][1]]),
                          termination['audit']['causes'])
            self.assertTrue(self.broker.request(other['token'], 'useful', request('read', 'src', 'calculator.py'))['allowed'])
        finally:
            with self.store.locked() as db:
                db.execute('DROP TRIGGER IF EXISTS reject_termination')
            for process, unit, _ in running:
                supervisor.terminate(unit)
                process.communicate(timeout=10)
            for project in ('python-demo', 'command-demo'):
                self.store.stop(project)
            supervisor.reconcile()

    def test_failed_closure_storage_still_terminates_subtree_only(self):
        from ptw.supervisor import Supervisor
        child = self.store.register('python-demo', 'readcheck', parent_token=self.actor['token'])
        supervisor = Supervisor(self.store)
        running = []
        try:
            for actor in (self.actor, child):
                running.append(supervisor.engine(actor['token'], ['/usr/bin/sleep', '30']))
            with self.store.locked() as db:
                db.execute("CREATE TRIGGER reject_closure BEFORE UPDATE OF closed ON sessions "
                    "BEGIN SELECT RAISE(FAIL,'injected closure storage fault'); END")
            with self.assertRaises(sqlite3.Error):
                self.store.close_session(child['token'])
            self.assertTrue(supervisor.state(running[1][1])['confirmed_stopped'])
            self.assertFalse(supervisor.state(running[0][1])['confirmed_stopped'])
            self.assertTrue(self.ask('read')['allowed'])
            # The failed write is never represented as durable revocation.
            status = self.store.status('python-demo')
            self.assertFalse(next(s for s in status['sessions'] if s['id'] == child['session'])['closed'])
            self.assertEqual(status['violations'], 0)
        finally:
            with self.store.locked() as db:
                db.execute('DROP TRIGGER IF EXISTS reject_closure')
            self.store.close_session(child['token'])
            for process, unit in running:
                supervisor.terminate(unit)
                process.communicate(timeout=10)
            supervisor.reconcile()

    def test_abrupt_controller_exit_releases_lease_without_publishing_or_retry(self):
        import multiprocessing
        from ptw.execution import execute
        from ptw.supervisor import Supervisor
        workspace_fixtures.WorkspaceLinux.add_command(self,
            "from pathlib import Path; Path('dist/crash-output.txt').write_text('staged real effect')")
        body = request('run', 'probe')
        receiver, sender = multiprocessing.get_context('fork').Pipe(duplex=False)
        def die_after_native_effect():
            receiver.close()
            def crash(*args, **kwargs):
                after, result = execute(*args, **kwargs)
                sender.send({'observed': after['dist/crash-output.txt']['data'], 'exit_code': result['exit_code']})
                os._exit(77)  # No Python finally, response, or lease cleanup.
            with patch('ptw.execution.execute', side_effect=crash):
                self.broker.request(self.actor['token'], 'abrupt-crash', body)
        process = multiprocessing.get_context('fork').Process(target=die_after_native_effect)
        process.start()
        sender.close()
        try:
            self.assertTrue(receiver.poll(20), 'Native effect oracle was not received')
            self.assertEqual(receiver.recv(), {'observed': b'staged real effect', 'exit_code': 0})
            process.join(5)
            self.assertEqual(process.exitcode, 77)
            self.assertFalse((Path(self.inv['root']) / 'dist/crash-output.txt').exists())
            recovered = Store(self.store.directory)
            Supervisor(recovered).reconcile()
            self.assertTrue(recovered.status('command-demo')['stopped'])
            self.assertEqual(recovered.audit_events('command-demo')[0]['state'], 'uncertain')
            with patch('ptw.execution.execute') as execution:
                self.assertFalse(Workspace(recovered).request(self.actor['token'], 'abrupt-crash', body)['allowed'])
            execution.assert_not_called()
            self.assertTrue(all(Supervisor.state(w['unit'])['confirmed_stopped']
                                for w in recovered.status('command-demo')['workloads']))
        finally:
            if process.is_alive():
                process.kill()
                process.join(5)
            receiver.close()
            self.store.stop('command-demo')
            Supervisor(self.store).reconcile()

    def test_capture_fault_stops_running_command_and_preserves_unrelated_work(self):
        from ptw.supervisor import Supervisor
        workspace_fixtures.WorkspaceLinux.add_command(self,
            "import subprocess,time; from pathlib import Path; "
            "subprocess.Popen(['/usr/bin/sleep','20']); time.sleep(3); "
            "Path('dist/late.txt').write_text('must not publish')")
        body = request('run', 'probe')
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(self.broker.request, self.actor['token'], 'running', body)
                deadline = time.monotonic() + 10
                units = []
                while time.monotonic() < deadline:
                    units = self.store.status('command-demo')['workloads']
                    if units and all(Supervisor.state(w['unit']).get('ActiveState') == 'active' for w in units):
                        break
                    time.sleep(.02)
                self.assertTrue(units, 'Native workload never started')
                self.assertTrue(all(Supervisor.state(w['unit']).get('ActiveState') == 'active' for w in units))
                self.assertEqual(self.store.audit_events('command-demo')[0]['state'], 'pending')
                # A real SQLite write rejection, scoped to the disposable
                # fixture; no shared disk exhaustion or native-call mocking.
                with self.store.locked() as db:
                    db.execute("CREATE TRIGGER reject_audit BEFORE INSERT ON events "
                               "BEGIN SELECT RAISE(FAIL,'injected capture failure'); END")
                import sqlite3
                try:
                    with self.assertRaises(sqlite3.Error):
                        self.ask('read')
                finally:
                    with self.store.locked() as db:
                        db.execute('DROP TRIGGER reject_audit')
                result = future.result(timeout=15)
                self.assertFalse(result['allowed'], result)
            self.assertFalse((Path(self.inv['root']) / 'dist/late.txt').exists())
            self.assertTrue(all(Supervisor.state(w['unit'])['confirmed_stopped'] for w in units))
            self.assertEqual(self.store.status('command-demo')['violations'], 0)
            other = self.store.register('python-demo', 'implementation')
            self.assertTrue(self.broker.request(other['token'], 'useful', request('read', 'src', 'calculator.py'))['allowed'])
            self.assertFalse(self.store.status('python-demo')['stopped'])
            self.assertTrue(self.broker.request(self.actor['token'], 'running', body)['replayed'])
        finally:
            self.store.stop('command-demo')
            Supervisor(self.store).reconcile()

    def test_command_completion_fault_records_unknown_without_reexecution(self):
        workspace_fixtures.WorkspaceLinux.add_command(self,
            "from pathlib import Path; Path('dist/completed.txt').write_text('real effect')")
        body = request('run', 'probe')
        complete = self.store.complete
        def fail_publication_receipt(db, session, event, response, **kwargs):
            if event == 'completion-fault':
                raise OSError('injected completion fault')
            return complete(db, session, event, response, **kwargs)
        with patch.object(self.store, 'complete', side_effect=fail_publication_receipt):
            with self.assertRaises(OSError):
                self.broker.request(self.actor['token'], 'completion-fault', body)
        self.assertEqual((Path(self.inv['root']) / 'dist/completed.txt').read_text(), 'real effect')
        recovered = Store(self.store.directory)
        self.assertTrue(recovered.status('command-demo')['stopped'])
        self.assertEqual(recovered.audit_events('command-demo')[0]['state'], 'uncertain')
        with patch('ptw.execution.execute') as execution:
            self.assertFalse(Workspace(recovered).request(self.actor['token'], 'completion-fault', body)['allowed'])
        execution.assert_not_called()

    def test_command_effect_failure_denial_and_private_diagnostics(self):
        workspace_fixtures.WorkspaceLinux.add_command(self,
            "from pathlib import Path; Path('dist/audit.txt').write_text('native-effect'); "
            "print('PRIVATE_COMMAND_DIAGNOSTIC'); raise SystemExit(7)")
        packet = self.store.evidence_review('command-demo', DEFAULT)
        self.store.adopt_evidence('command-demo', DEFAULT, digest(packet), 'operator')
        result = self.ask('run', resource='probe', path='')
        self.assertTrue(result['allowed'], result)
        self.assertEqual(result['exit_code'], 7)
        self.assertEqual((Path(self.inv['root']) / 'dist/audit.txt').read_text(), 'native-effect')
        private = Path(self.inv['root']) / 'private/customer.txt'
        before = private.read_bytes()
        denied = self.ask('read', resource='private', path='customer.txt')
        self.assertFalse(denied['allowed'])
        self.assertEqual(private.read_bytes(), before)
        document = self.store.audit_export('command-demo')
        command = next(r for r in document['events'] if r['request']['action'] == 'run')
        self.assertEqual(command['audit']['decision'], 'allow')
        self.assertEqual(command['audit']['outcome'], 'failed')
        self.assertEqual(command['audit']['phases']['execution']['outcome'], 'failed')
        self.assertNotIn('PRIVATE_COMMAND_DIAGNOSTIC', json.dumps(document))
        self.assertIn('PRIVATE_COMMAND_DIAGNOSTIC', result['output'])
        # A separate project's existing authority and useful work survive.
        other = self.store.register('python-demo', 'implementation')
        self.assertTrue(self.broker.request(other['token'], 'useful', request('read', 'src', 'calculator.py'))['allowed'])
        self.assertFalse(self.store.status('python-demo')['stopped'])
