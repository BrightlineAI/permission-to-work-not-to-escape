"""IG2/IG3 and AT2: deterministic fixtures, never spontaneous model evidence.

Import fixture modules, not TestCase aliases: full discovery owns each test once.
Native cases require the manager's isolated Linux source installation.
"""
import asyncio
import copy
import concurrent.futures
import hashlib
import http.client
import json
import os
from pathlib import Path
import sqlite3
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import test_workspace as workspace_fixtures
import test_ecosystems as ecosystem_fixtures
from ptw.mcp_server import Adapter
from ptw.policy import Invalid, approve, compile_policy, digest, load, save
from ptw.store import Store
from ptw.supervisor import Supervisor
from ptw.workflow import dispatch, drive
from ptw.workspace import Workspace, request


class SurrenderTests(workspace_fixtures.WorkspaceFixture):
    def adapter(self, actor=None):
        path = self.root / 'session.json'
        save(path, actor or self.actor)
        return Adapter(self.store.directory, path)

    def test_authenticated_child_surrender_repeat_and_operator_continuation(self):
        child = self.store.register('python-demo', 'readcheck', parent_token=self.actor['token'])
        grandchild = self.store.register('python-demo', 'readcheck', parent_token=child['token'])
        sibling = self.store.register('python-demo', 'readcheck', parent_token=self.actor['token'])
        # Caller-supplied labels are not authority. Only the token selects work.
        adapter = self.adapter({**self.actor, 'token': child['token']})
        with patch('ptw.mcp_server.health', return_value={'healthy': False}):
            result = adapter.action(1, 'surrender', content='Approved fixture is unavailable')
            repeat = adapter.action(1, 'surrender', content='Lost acknowledgement')
        self.assertTrue(result['admission_closed'])
        self.assertTrue(result['confirmed_stopped'])  # explicitly no registered workloads
        self.assertFalse(result['completion_verified'])
        self.assertEqual(result['outcome'], 'surrender')
        self.assertTrue(repeat['replayed'])
        for actor in (child, grandchild):
            with self.assertRaises(Invalid):
                dispatch(self.store, actor, 'late', request('read', 'src', 'calculator.py'))
            with self.assertRaises(Invalid):
                self.store.register('python-demo', 'readcheck', parent_token=actor['token'])
        for actor in (self.actor, sibling):
            self.assertTrue(dispatch(self.store, actor, 'useful', request('read', 'src', 'calculator.py'))['allowed'])
        self.assertFalse(self.store.status('python-demo')['stopped'])
        self.assertEqual(self.store.status('python-demo')['violations'], 0)
        continued = self.store.register('python-demo', 'readcheck')  # explicit operator API
        self.assertEqual(continued['grants'], child['grants'])
        self.assertNotEqual(continued['token'], child['token'])
        self.assertTrue(dispatch(self.store, continued, 'continued', request('read', 'src', 'calculator.py'))['allowed'])

    def test_invalid_or_targeted_terminal_requests_do_not_close_any_session(self):
        for req in (request('surrender', 'other'), request('finish', path='other'),
                    request('surrender', destination='other'), request('surrender', expected='other'),
                    request('surrender', content='x' * 4097),
                    request('surrender', content='é' * 2049), request('surrender', content='\ud800'),
                    {**request('surrender'), 'session': self.actor['session']},
                    request('surrender', content=None)):
            with self.subTest(request=req), self.assertRaises(Invalid):
                dispatch(self.store, self.actor, 'invalid', req)
        with self.assertRaises(Invalid):
            dispatch(self.store, {**self.actor, 'token': 'invalid-' * 8}, 'forged', request('surrender'))
        self.assertFalse(self.store.status('python-demo')['sessions'][0]['closed'])
        self.assertEqual(self.store.status('python-demo')['violations'], 0)

    def test_headless_blocker_stops_calls_and_finish_uses_same_cleanup(self):
        for action in ('surrender', 'finish'):
            actor = self.store.register('python-demo', 'implementation')
            with patch('ptw.codex.generate', return_value=(request(action, content='Fixture result'),
                       {'deterministic_fixture': True})) as generate, \
                    patch('ptw.monitor.health', return_value={'healthy': True}):
                result = drive(self.store, actor, 'Explicit terminal fixture', max_steps=3)
            self.assertEqual(generate.call_count, 1)
            self.assertEqual(result['outcome'], 'surrendered' if action == 'surrender' else 'model_finished')
            self.assertFalse(result['completion_verified'])
            self.assertTrue(result['steps'][-1]['result']['admission_closed'])
            with self.assertRaises(Invalid):
                dispatch(self.store, actor, 'late', request('create', 'src', 'late.txt', content='late'))
        self.assertFalse((Path(self.inv['root']) / 'src/late.txt').exists())

    def test_ordinary_interactive_work_remains_open_and_supervisor_error_is_unknown(self):
        adapter = self.adapter()
        with patch('ptw.mcp_server.health', return_value={'healthy': True}):
            for event in (1, 2):
                self.assertTrue(adapter.action(event, 'read', 'src', 'calculator.py')['allowed'])
        self.assertFalse(self.store.status('python-demo')['sessions'][0]['closed'])
        with patch.object(Supervisor, 'reconcile', side_effect=OSError('fixture query failure')):
            result = adapter.action(3, 'surrender', content='Cannot continue')
        self.assertTrue(result['admission_closed'])
        self.assertFalse(result['confirmed_stopped'])
        with self.assertRaises(Invalid):
            adapter.action(4, 'read', 'src', 'calculator.py')
        self.assertTrue(adapter.action(3, 'surrender')['confirmed_stopped'])

    def test_failed_flag_storage_retains_subtree_intent_and_recovers(self):
        child = self.store.register('python-demo', 'implementation', parent_token=self.actor['token'])
        grandchild = self.store.register('python-demo', 'readcheck', parent_token=child['token'])
        direct = self.store.register('python-demo', 'readcheck', parent_token=self.actor['token'])
        with self.store.locked() as db:
            db.execute("CREATE TRIGGER reject_flags BEFORE UPDATE OF closed ON sessions "
                       "BEGIN SELECT RAISE(FAIL,'injected flag failure'); END")
        result = dispatch(self.store, child, 'surrender', request('surrender'))
        self.assertTrue(result['admission_closed'])
        self.assertFalse(result['closure_flags_persisted'])
        self.assertEqual(result['evidence'], 'unavailable')
        dispatch(self.store, direct, 'initial', request('surrender'))
        reopened = Store(self.store.directory)
        for action in ('surrender', 'finish'):
            repeated = dispatch(reopened, child, 'still-failing-' + action, request(action))
            self.assertTrue(repeated['replayed'])
            self.assertEqual(repeated['outcome'], 'surrender')
            self.assertTrue(repeated['admission_closed'])
            self.assertFalse(repeated['closure_flags_persisted'])
            self.assertEqual(repeated['evidence'], 'unavailable')
        for actor in (child, grandchild):
            with self.assertRaises(Invalid):
                dispatch(reopened, actor, 'late', request('read', 'src', 'calculator.py'))
            with self.assertRaises(Invalid):
                reopened.register('python-demo', 'readcheck', parent_token=actor['token'])
        self.assertTrue(self.ask('read')['allowed'])
        self.assertFalse(self.store.status('python-demo')['stopped'])
        self.assertFalse(next(s for s in self.store.status('python-demo')['sessions']
                              if s['id'] == child['session'])['closed'])
        with self.store.locked() as db:
            db.execute('DROP TRIGGER reject_flags')
        repaired = dispatch(reopened, direct, 'repair', request('finish'))
        self.assertTrue(repaired['replayed'])
        self.assertEqual(repaired['outcome'], 'surrender')
        self.assertTrue(repaired['closure_flags_persisted'])
        Supervisor(reopened).reconcile()
        repeated = dispatch(reopened, child, 'repeat', request('finish'))
        self.assertTrue(repeated['replayed'])
        self.assertEqual(repeated['outcome'], 'surrender')
        self.assertTrue(repeated['closure_flags_persisted'])

    def test_capture_and_quota_failure_cannot_trap_surrender(self):
        from ptw.evidence_storage import DEFAULT, usage
        for fault in ('capture', 'quota'):
            with self.subTest(fault=fault):
                child = self.store.register('python-demo', 'readcheck', parent_token=self.actor['token'])
                if fault == 'capture':
                    with self.store.locked() as db:
                        db.execute("CREATE TRIGGER reject_capture BEFORE INSERT ON events "
                                   "BEGIN SELECT RAISE(FAIL,'injected capture failure'); END")
                else:
                    packet = self.store.evidence_review('python-demo', DEFAULT)
                    self.store.adopt_evidence('python-demo', DEFAULT, digest(packet), 'fixture operator')
                    with self.store.locked() as db:
                        profile = {**DEFAULT, 'project_bytes': max(65536, usage(db, 'python-demo'))}
                        # Bounded accounting fault, never fill a shared disk.
                        db.execute('UPDATE evidence_profiles SET profile=? WHERE project=?',
                                   (json.dumps(profile), 'python-demo'))
                result = dispatch(self.store, child, fault, request('surrender'))
                self.assertTrue(result['admission_closed'])
                self.assertTrue(result['closure_flags_persisted'])
                self.assertEqual(result['evidence'], 'unavailable')
                with self.assertRaises(Invalid):
                    dispatch(self.store, child, 'late', request('read', 'src', 'calculator.py'))
                if fault == 'capture':
                    with self.store.locked() as db:
                        db.execute('DROP TRIGGER reject_capture')
                else:
                    with self.store.locked() as db:
                        db.execute('UPDATE evidence_profiles SET profile=?', (json.dumps(DEFAULT),))
                self.assertTrue(self.ask('read')['allowed'])
                self.assertFalse(self.store.status('python-demo')['stopped'])
                self.assertEqual(self.store.status('python-demo')['violations'], 0)

    def test_termination_capture_failure_after_recorded_closure_is_reported(self):
        child = self.store.register('python-demo', 'readcheck', parent_token=self.actor['token'])
        unit = 'ptw-' + 'a' * 24 + '.service'
        with self.store.locked() as db:
            # Offline registry fixture: no process was launched or stopped.
            db.execute('INSERT INTO workloads(unit,project,session) VALUES(?,?,?)',
                       (unit, child['project'], child['session']))
            db.execute("CREATE TRIGGER reject_termination BEFORE INSERT ON events "
                       "WHEN json_extract(NEW.request_meta,'$.action')='workload_termination' "
                       "BEGIN SELECT RAISE(FAIL,'injected termination capture failure'); END")
        with patch.object(Supervisor, 'terminate', return_value={'confirmed_stopped': True}), \
                patch.object(Supervisor, 'state', return_value={'confirmed_stopped': True}):
            for action in ('surrender', 'finish'):
                result = dispatch(self.store, child, action, request(action))
                self.assertTrue(result['admission_closed'])
                self.assertTrue(result['closure_flags_persisted'])
                self.assertTrue(result['confirmed_stopped'])
                self.assertEqual(result['outcome'], 'surrender')
                self.assertEqual(result['evidence'], 'unavailable')
                self.assertEqual(result['termination'][0]['evidence'], 'unavailable')
                with self.store.locked() as db:
                    self.assertEqual(db.execute('SELECT stopped FROM workloads WHERE unit=?',
                                                (unit,)).fetchone()[0], 0)
                    self.assertIsNotNone(db.execute("SELECT 1 FROM events WHERE "
                        "json_extract(request_meta,'$.action')='session_closed' AND "
                        "json_extract(request_meta,'$._audit.session')=?", (child['session'],)).fetchone())
                    self.assertIsNone(db.execute("SELECT 1 FROM events WHERE "
                        "json_extract(request_meta,'$.action')='workload_termination'").fetchone())
                with self.assertRaises(Invalid):
                    dispatch(self.store, child, 'late', request('read', 'src', 'calculator.py'))
                self.assertTrue(self.ask('read')['allowed'])
                self.assertFalse(self.store.status('python-demo')['stopped'])
            with self.store.locked() as db:
                db.execute('DROP TRIGGER reject_termination')
            recovered = dispatch(self.store, child, 'recovered', request('finish'))
            self.assertTrue(recovered['replayed'])
            self.assertEqual(recovered['outcome'], 'surrender')
            self.assertEqual(recovered['evidence'], 'recorded')
            self.assertEqual(recovered['termination'][0]['evidence'], 'recorded')
            self.assertEqual(dispatch(self.store, child, 'again', request('finish'))['evidence'], 'recorded')

    def test_late_command_and_queued_request_do_not_publish_or_stop_parent(self):
        child = self.store.register('python-demo', 'implementation', parent_token=self.actor['token'])
        entered, resume = threading.Event(), threading.Event()
        def execute(store, token, definition, before, settings, **kwargs):
            entered.set()
            if not resume.wait(5):
                raise AssertionError('Fixture did not release command')
            return {**before, 'src/late.txt': {'kind': 'file', 'mode': 0o644, 'data': b'late'}}, {
                'exit_code': 0, 'output': 'deterministic staged effect', 'output_truncated': False}
        with patch('ptw.execution.execute', side_effect=execute), concurrent.futures.ThreadPoolExecutor() as pool:
            running = pool.submit(dispatch, self.store, child, 'in-flight', request('run', 'test'))
            try:
                self.assertTrue(entered.wait(5))
                result = dispatch(self.store, child, 'end', request('surrender'))
                self.assertTrue(result['admission_closed'])
                queued = pool.submit(dispatch, self.store, child, 'queued', request('create', 'src', 'queued.txt', content='no'))
                with self.assertRaises(Invalid):
                    queued.result(timeout=5)
            finally:
                resume.set()
            with self.assertRaises(Invalid):
                running.result(timeout=5)
        repo = Path(self.inv['root'])
        self.assertFalse((repo / 'src/late.txt').exists())
        self.assertFalse((repo / 'src/queued.txt').exists())
        row = next(r for r in self.store.audit_events('python-demo') if r['event'] == 'in-flight')
        self.assertEqual(row['state'], 'uncertain')
        self.assertTrue(self.ask('read')['allowed'])
        self.assertFalse(self.store.status('python-demo')['stopped'])

    def test_failed_capture_and_flags_use_existing_conservative_fault_recovery(self):
        child = self.store.register('python-demo', 'readcheck', parent_token=self.actor['token'])
        with self.store.locked() as db:
            db.execute("CREATE TRIGGER reject_capture BEFORE INSERT ON events "
                       "BEGIN SELECT RAISE(FAIL,'injected capture failure'); END")
            db.execute("CREATE TRIGGER reject_flags BEFORE UPDATE OF closed ON sessions "
                       "BEGIN SELECT RAISE(FAIL,'injected flag failure'); END")
        result = dispatch(self.store, child, 'end', request('surrender'))
        self.assertTrue(result['admission_closed'])  # project capture fault persisted
        self.assertFalse(result['closure_flags_persisted'])
        self.assertEqual(result['evidence'], 'unavailable')
        reopened = Store(self.store.directory)
        self.assertTrue(reopened.status('python-demo')['stopped'])
        self.assertEqual(reopened.status('python-demo')['violations'], 0)
        with self.assertRaises(sqlite3.IntegrityError):
            dispatch(reopened, child, 'late', request('create', 'src', 'late.txt', content='no'))
        with reopened.locked() as db:
            db.execute('DROP TRIGGER reject_capture')
        self.assertFalse(dispatch(reopened, child, 'after-recovery', request('create', 'src', 'late.txt', content='no'))['allowed'])
        with self.assertRaises(Invalid):
            reopened.register('python-demo', 'readcheck', parent_token=child['token'])
        self.assertFalse((Path(self.inv['root']) / 'src/late.txt').exists())

    def test_legacy_headless_surrender_and_missing_target_keep_scope(self):
        from ptw.codex import drive as legacy_drive
        child = self.store.register('python-demo', 'readcheck', parent_token=self.actor['token'])
        missing = dispatch(self.store, child, 'missing', request('read', 'src', 'unavailable.txt'))
        self.assertFalse(missing['allowed'])
        self.assertEqual(self.store.status('python-demo')['violations'], 0)
        private = Path(self.inv['root']) / 'private/customer.txt'
        before = private.read_bytes()
        denied = dispatch(self.store, child, 'lookalike', request('read', 'private', 'customer.txt'))
        self.assertFalse(denied['allowed'])
        self.assertEqual(private.read_bytes(), before)
        with patch('ptw.codex.generate', return_value=({'action': 'surrender', 'resource': '',
                'content': 'Approved fixture unavailable'}, {'deterministic_fixture': True})) as generate:
            result = legacy_drive(self.store, child, 'Impossible fixture', max_steps=3)
        self.assertEqual(result['outcome'], 'surrendered')
        self.assertEqual(generate.call_count, 1)
        self.assertEqual(self.store.status('python-demo')['violations'], 1)
        self.assertTrue(self.ask('read')['allowed'])


@unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'real Linux user manager required')
class NativeIncidentTests(workspace_fixtures.WorkspaceFixture):
    def setUp(self):
        super().setUp()
        self.evidence = Path(tempfile.mkdtemp(prefix='ptw-incident-evidence-'))
        print('INCIDENT_EVIDENCE ' + str(self.evidence), flush=True)
        source = Path(__file__).resolve().parents[1]
        runtime = [p for p in sorted((source / 'ptw').rglob('*')) if p.is_file()
                   and '__pycache__' not in p.parts and p.suffix not in ('.pyc', '.pyo')]
        save(self.evidence / 'sources.json', {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in [*runtime, Path(__file__), Path(workspace_fixtures.__file__),
                       Path(ecosystem_fixtures.__file__), source / 'tests/test_packages.py',
                       source / 'scripts/terminal_driver.py', source / 'scripts/evidence_io.py',
                       source / 'requirements.lock', source / 'PRODUCT_ACCEPTANCE.json',
                       source / 'PROJECT_SAFETY_ACCEPTANCE.json', source / 'INCIDENT_SAFETY_ACCEPTANCE.json']})
        self.observations = []
        self.addCleanup(lambda: save(self.evidence / 'observations.json', {
            'test': self.id(), 'fixture': 'deterministic; no model calls', 'observations': self.observations}))
        self.running = []
        self.addCleanup(self.cleanup_workloads)

    def cleanup_workloads(self):
        for process, unit, _, _ in self.running:
            Supervisor(self.store).terminate(unit)
            process.communicate(timeout=10)

    def start_sentinel(self, actor, name):
        """Trusted registered process fixture plus a real descendant, not an agent tool."""
        sentinel = self.root / (name + '.txt')
        # Publish a complete sample atomically: SIGKILL can arrive between a
        # truncating write's open and write, leaving an empty final sample.
        code = ("import os,time; from pathlib import Path; p=Path(" + repr(str(sentinel)) + "); "
                "tmp=p.with_suffix('.pending')"
                "\nfor i in range(3600):\n tmp.write_text(str(os.getpid())+':'+str(i)); tmp.replace(p); time.sleep(.05)")
        parent = 'import subprocess,time; subprocess.Popen(' + repr([sys.executable, '-c', code]) + '); time.sleep(180)'
        process, unit = Supervisor(self.store).engine(actor['token'], [sys.executable, '-c', parent])
        self.running.append((process, unit, sentinel, None))
        deadline = time.monotonic() + 10
        while not sentinel.exists() and time.monotonic() < deadline:
            time.sleep(.02)
        self.assertTrue(sentinel.exists())
        group = Supervisor.state(unit)['ControlGroup']
        self.assertTrue(group)
        self.running[-1] = (process, unit, sentinel, Path('/sys/fs/cgroup' + group))
        self.assertIn('populated 1', (self.running[-1][3] / 'cgroup.events').read_text())
        return self.running[-1]

    def assert_stopped(self, work):
        process, unit, sentinel, group = work
        process.wait(timeout=10)
        # These oracles do not consult workloads.stopped or the surrender response.
        events = group / 'cgroup.events'
        self.assertTrue(not events.exists() or 'populated 0' in events.read_text())
        pid = int(sentinel.read_text().split(':')[0])
        proc = Path('/proc') / str(pid) / 'stat'
        self.assertTrue(not proc.exists() or proc.read_text().split(') ')[1].startswith('Z '))
        before = sentinel.read_bytes()
        time.sleep(.15)
        self.observations.append({'unit': unit, 'cgroup_events': events.read_text() if events.exists() else 'removed',
                                  'sentinel_before': before.decode(), 'sentinel_after': sentinel.read_text()})
        self.assertEqual(before, sentinel.read_bytes())

    def assert_continues(self, work):
        process, unit, sentinel, group = work
        before = sentinel.read_bytes()
        time.sleep(.15)
        self.assertIsNone(process.poll())
        self.assertIn('populated 1', (group / 'cgroup.events').read_text())
        self.assertNotEqual(before, sentinel.read_bytes())
        self.observations.append({'unit': unit, 'continued': True,
            'sentinel_before': before.decode(), 'sentinel_after': sentinel.read_text(),
            'cgroup_events': (group / 'cgroup.events').read_text()})

    def start_monitor(self):
        monitor = subprocess.Popen([sys.executable, '-B', '-m', 'ptw.monitor', '--state', str(self.store.directory)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.addCleanup(lambda: (monitor.terminate(), monitor.communicate(timeout=10)))
        from ptw.monitor import health
        deadline = time.monotonic() + 10
        while not health(self.store)['healthy'] and time.monotonic() < deadline:
            time.sleep(.05)
        self.assertTrue(health(self.store)['healthy'])

    def test_terminal_surrender_stops_preview_without_ending_parent(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
        from terminal_driver import Terminal
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        repo = Path(self.inv['root'])
        (repo / 'src/server.py').write_text(
            "import http.server,os,subprocess\n"
            "subprocess.Popen(['/usr/bin/python3','-c','import time; time.sleep(180)'])\n"
            "os.chdir('/target/src')\n"
            "http.server.HTTPServer(('127.0.0.1',int(os.environ['PORT'])),"
            "http.server.SimpleHTTPRequestHandler).serve_forever()\n")
        definition = {'id': 'preview', 'argv': ['/usr/bin/python3', '-B', 'src/server.py'],
                      'resources': ['src'], 'timeout_seconds': 10,
                      'preview': {'port': port, 'lifetime_seconds': 180}}
        self.policy['project']['commands'].append(definition)
        for task in self.policy['tasks']:
            task['commands'].append('preview')
        self.store = Store(self.root / 'preview-state')
        self.store.activate(self.approve())
        self.actor = self.store.register('python-demo', 'implementation')
        self.start_monitor()
        child = self.store.register('python-demo', 'readcheck', parent_token=self.actor['token'])
        child_work = self.start_sentinel(child, 'terminal-child')
        parent_work = self.start_sentinel(self.actor, 'terminal-parent')
        started = dispatch(self.store, child, 'preview', request('service_start', 'preview'))
        save(self.evidence / 'preview-start.json', started)
        self.assertTrue(started['allowed'], started)
        unit = started['unit']
        self.addCleanup(lambda: Supervisor(self.store).terminate(unit))
        group = Path('/sys/fs/cgroup' + Supervisor.state(unit)['ControlGroup'])
        self.assertIn('populated 1', (group / 'cgroup.events').read_text())
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        try:
            connection.request('GET', '/calculator.py')
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertIn(b'return a - b', response.read())
        finally:
            connection.close()
        session_path = self.root / 'terminal-session.json'
        save(session_path, child)
        # Explicit deterministic adapter client in a real PTY, not a fake Codex
        # or a claimed spontaneous model decision. The separate MCP case tests
        # the actual SDK transport and broker self-termination.
        program = """import json,sys
from ptw.mcp_server import Adapter
a=Adapter(sys.argv[1],sys.argv[2])
print('DETERMINISTIC_ADAPTER_READY',flush=True)
assert input() == 'ordinary reply'
assert a.action(1,'read','src','calculator.py')['allowed']
print('ORDINARY_REPLY_REMAINS_OPEN',flush=True)
missing=a.action(2,'read','src','unavailable.txt')
assert not missing['allowed']
print('APPROVED_FIXTURE_UNAVAILABLE',flush=True)
assert input() == 'surrender'
result=a.action(3,'surrender',content='Approved fixture unavailable')
print(json.dumps(result),flush=True)
"""
        terminal = Terminal([sys.executable, '-B', '-c', program, str(self.store.directory), str(session_path)],
                            self.evidence / 'terminal')
        try:
            terminal.expect('DETERMINISTIC_ADAPTER_READY', 10)
            terminal.send('ordinary reply')
            terminal.expect('APPROVED_FIXTURE_UNAVAILABLE', 10)
            with self.store.locked() as db:
                self.store.session(db, child['token'])
            terminal.send('surrender')
            terminal.wait(lambda: terminal.exited, 20)
        finally:
            code = terminal.close(graceful=False)
        self.assertEqual(code, 0, terminal.text)
        self.assertIn('"admission_closed": true', terminal.text)
        self.assertIn('"completion_verified": false', terminal.text)
        self.assert_stopped(child_work)
        self.assert_continues(parent_work)
        events = group / 'cgroup.events'
        self.assertTrue(not events.exists() or 'populated 0' in events.read_text())
        with self.assertRaises(OSError):
            with socket.create_connection(('127.0.0.1', port), timeout=1):
                pass
        for operation in ('service_start', 'service_status', 'run', 'delegate'):
            with self.assertRaises(Invalid):
                dispatch(self.store, child, 'late-' + operation, request(operation, 'preview'))
        self.assertFalse(self.store.status('python-demo')['stopped'])
        self.assertEqual(self.store.status('python-demo')['violations'], 0)
        continued = self.store.register('python-demo', 'readcheck')
        self.assertTrue(dispatch(self.store, continued, 'continued', request('read', 'src', 'calculator.py'))['allowed'])
        self.observations.append({'preview_listener_after': 'connection refused',
                                  'preview_cgroup_after': events.read_text() if events.exists() else 'removed',
                                  'terminal_exit': code})

    def test_missing_target_package_children_and_resolver_do_not_gain_authority(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        from ptw.dependency_resolution import run_metadata, resolver_environment
        from ptw.npm_resolution import MetadataView
        from ptw.python_index import WheelIndex
        seen = []

        class Collector(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                seen.append((self.command, self.path))
                self.send_response(200)
                self.end_headers()

            do_POST = do_GET
            do_PUT = do_GET

        collector = HTTPServer(('127.0.0.1', 0), Collector)
        thread = threading.Thread(target=collector.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (collector.shutdown(), collector.server_close(), thread.join(5)))
        credential = self.root / 'dummy-host-credential'
        credential.write_text('SYNTHETIC_INCIDENT_TOKEN')
        before = credential.read_bytes()
        endpoint = 'http://127.0.0.1:' + str(collector.server_port)
        # Establish the independent collector is live, then count only probes.
        connection = http.client.HTTPConnection('127.0.0.1', collector.server_port, timeout=3)
        connection.request('GET', '/positive-control')
        self.assertEqual(connection.getresponse().status, 200)
        connection.close()
        self.assertEqual(seen, [('GET', '/positive-control')])
        seen.clear()
        probe = ("const fs=require('fs'),http=require('http');\n"
                 "let denied=false;try{fs.readFileSync(" + json.dumps(str(credential)) +
                 ")}catch(e){denied=true}if(!denied)throw Error('dummy credential exposed');\n"
                 "const req=http.request(" + json.dumps(endpoint + '/publish-lookalike') +
                 ",{method:'PUT'},()=>{throw Error('collector reached')});\n"
                 "req.on('error',()=>console.log('SCOPE_DENIED'));"
                 "req.setTimeout(1000,()=>req.destroy());req.end('inert fixture');\n")
        fixture = ecosystem_fixtures.NpmFixture(fields={'scripts': {'postinstall': 'node build.js'}}, files={
            'package/probe.js': probe.encode(),
            'package/build.js': b"require('child_process').execFileSync('/usr/bin/node',['probe.js'],{stdio:'inherit'});require('fs').writeFileSync('built.txt','42');",
            'package/index.js': b"require('child_process').execFileSync('/usr/bin/node',[__dirname+'/probe.js'],{stdio:'inherit'});module.exports=42;"})
        repo = Path(self.inv['root'])
        # The reused Python fixture already owns this reviewed dependency file.
        (repo / 'requirements.txt').write_text(json.dumps(fixture.lock))
        (repo / 'src/import.cjs').write_text("if(require('demo')!==42)throw Error('wrong answer');console.log('USEFUL_IMPORT_42');")
        self.policy['project']['packages'].update(allowed_names=['npm:demo'], build_packages=['npm:demo'])
        self.policy['project']['commands'] = [{'id': 'test', 'argv': ['/usr/bin/node', 'src/import.cjs'],
                                              'resources': ['src'], 'timeout_seconds': 15}]
        for task in self.policy['tasks']:
            task['packages'] = ['npm:demo']
        self.store = Store(self.root / 'package-state')
        self.store.activate(self.approve())
        self.actor = self.store.register('python-demo', 'implementation')
        child = self.store.register('python-demo', 'readcheck', parent_token=self.actor['token'])
        missing = dispatch(self.store, child, 'missing', request('read', 'src', 'unavailable.txt'))
        self.assertFalse(missing['allowed'])
        private = repo / 'private/customer.txt'
        private_before = private.read_bytes()
        self.assertFalse(dispatch(self.store, child, 'lookalike', request('read', 'private', 'customer.txt'))['allowed'])
        with patch('ptw.registry.provider_for', return_value=fixture):
            installed = dispatch(self.store, child, 'install', request('install', 'dependencies', content='npm'))
            self.assertTrue(installed['allowed'], installed)
            useful = dispatch(self.store, child, 'import', request('run', 'test', content=json.dumps({'package_sets': [installed['package_set']]})))
        self.assertTrue(useful['allowed'], useful)
        self.assertEqual(useful['exit_code'], 0, useful)
        self.assertIn('USEFUL_IMPORT_42', useful['output'])
        self.assertIn('SCOPE_DENIED', useful['output'])
        package = self.store.directory / 'package-sets' / installed['package_set'] / 'node_modules/demo'
        self.assertEqual((package / 'built.txt').read_text(), '42')
        # Resolver tooling intentionally has host networking; qualify only its
        # constrained read view. Do not call this arbitrary network isolation.
        class Provider:
            def packument(self, name):
                from ptw.package_evidence import EvidenceError
                if name != 'demo':
                    raise EvidenceError('Approved fixture unavailable')
                return {'name': name, 'versions': {'1.0.0': {**fixture.manifest, 'dist': {
                            'tarball': fixture.record['url'], 'integrity': fixture.record['integrity']}}},
                        'time': {'1.0.0': '2020-01-01T00:00:00Z'}, 'dist-tags': {'latest': '1.0.0'}}

            def artifact_allowed(self, url, name):
                return name == 'demo' and url == fixture.record['url']

        stage = self.root / 'resolver'
        stage.mkdir()
        class PythonProvider(ecosystem_fixtures.FixtureProvider):
            def index(self, name):
                from ptw.package_evidence import EvidenceError
                if name != 'demo':
                    raise EvidenceError('Approved fixture unavailable')
                record = self.assess(name, '1.0')
                return {'meta': {'api-version': '1.1'}, 'name': name, 'files': [{
                    'filename': record['filename'], 'url': record['url'],
                    'hashes': {'sha256': record['sha256']}, 'upload-time': record['published_at'],
                    'size': len(ecosystem_fixtures.wheel_bytes(name, '1.0'))}]}

            def artifact_allowed(self, url, name):
                return name == 'demo' and url == 'https://files.pythonhosted.org/synthetic'

        statuses = {}
        for ecosystem, manager, useful_path, missing_path in (
                ('npm', MetadataView(Provider(), set(), time.monotonic() + 30), 'demo', 'missing'),
                ('pypi', WheelIndex(PythonProvider(), stage / 'index', time.monotonic() + 60),
                 'demo/', 'missing/')):
            with self.subTest(ecosystem=ecosystem), manager as view:
                from urllib.parse import urlsplit
                url = urlsplit(view)
                # An actual resolver namespace attempts write and destination
                # abuse against the view that serves the useful GET.
                script = ("import http.client,json\n"
                    "c=http.client.HTTPConnection('127.0.0.1'," + str(url.port) + ",timeout=3)\n"
                    "results=[]\n"
                    "for method,path in " + repr([('GET', url.path + missing_path), ('GET', url.path + useful_path),
                        ('PUT', url.path + useful_path), ('POST', url.path + missing_path),
                        ('GET', endpoint + '/lookalike')]) + ":\n"
                    " c.request(method,path);r=c.getresponse();results.append(r.status);r.read()\n"
                    "print(json.dumps(results))\n")
                resolved = run_metadata(['/usr/bin/python3', '-I', '-S', '-c', script], cwd=stage,
                    env=resolver_environment(stage), capture_output=True, text=True, timeout=10)
                self.assertEqual(resolved.returncode, 0, resolved.stderr)
                statuses[ecosystem] = json.loads(resolved.stdout)
                self.assertEqual(statuses[ecosystem], [502, 200, 501, 501, 404])
        self.assertEqual(seen, [])
        self.assertEqual(credential.read_bytes(), before)
        self.assertEqual(private.read_bytes(), private_before)
        self.assertEqual(self.store.status('python-demo')['violations'], 1)
        self.assertTrue(dispatch(self.store, self.actor, 'parent-useful', request('read', 'src', 'calculator.py'))['allowed'])
        save(self.evidence / 'scope.json', {'install': installed, 'import': useful,
            'resolver_statuses': statuses, 'collector_requests': seen,
            'dummy_before_sha256': hashlib.sha256(before).hexdigest(),
            'dummy_after_sha256': hashlib.sha256(credential.read_bytes()).hexdigest()})

    def test_shipped_aggregate_escalation_stops_real_descendants(self):
        from ptw.setup_templates import template
        from ptw.evidence_storage import DEFAULT
        # The actual setup template and onboarding's default profile/thresholds.
        # No test-only relaxed cap or lowered escalation threshold.
        policy, inv = template(Path(self.inv['root']), 'aggregate', 'Build inside selected scope',
            {'src': 'tree', 'dist': 'tree'}, [], [{'id': 'build',
            'argv': ['/usr/bin/python3', '-c', "from pathlib import Path; Path('dist/useful.txt').write_text('42')"],
            'resources': ['src', 'dist'], 'timeout_seconds': 10}], [], 1, 3)
        policy['project']['audit'] = copy.deepcopy(DEFAULT)
        bundle = approve(policy, inv, digest(compile_policy(policy, inv)), 'synthetic fixture operator')
        self.store.activate(bundle)
        save(self.evidence / 'shipped-policy.json', bundle)
        actors = [self.store.register('aggregate', 'work') for _ in range(3)]
        descendant = self.store.register('aggregate', 'verify', parent_token=actors[0]['token'])
        useful = dispatch(self.store, actors[0], 'build', request('run', 'build'))
        self.assertTrue(useful['allowed'], useful)
        self.assertEqual(useful['exit_code'], 0, useful)
        self.assertEqual((Path(inv['root']) / 'dist/useful.txt').read_text(), '42')
        self.assertEqual(self.store.status('aggregate')['violations'], 0)
        active = [self.start_sentinel(a, 'aggregate-' + str(i)) for i, a in enumerate([*actors, descendant])]
        other = self.start_sentinel(self.actor, 'unrelated-project')
        private = Path(self.inv['root']) / 'private/customer.txt'
        before = private.read_bytes()
        resource = next(k for k, v in inv['resources'].items() if v['path'] == 'src')
        levels, counts = [], []
        for i, actor in enumerate(actors, 1):
            allowed = dispatch(self.store, actor, 'allowed', request('read', resource, 'calculator.py'))
            self.assertTrue(allowed['allowed'])
            self.assertEqual(self.store.status('aggregate')['violations'], i - 1)
            denied = dispatch(self.store, actor, 'distinct-denial', request('read', 'outside-scope', 'customer.txt'))
            self.assertFalse(denied['allowed'])
            self.assertEqual(denied['level'], 'warn' if i < 3 else 'stop')
            self.assertEqual(self.store.status('aggregate')['violations'], i)
            levels.append(denied['level'])
            counts.append(self.store.status('aggregate')['violations'])
            if i < 3:
                self.assertFalse(self.store.status('aggregate')['stopped'])
                for work in active:
                    self.assert_continues(work)
        for work in active:
            self.assert_stopped(work)
        self.assert_continues(other)
        self.assertEqual(private.read_bytes(), before)
        self.assertFalse(dispatch(self.store, actors[0], 'late', request('create', resource, 'late.txt', content='no'))['allowed'])
        self.assertFalse((Path(inv['root']) / 'src/late.txt').exists())
        with self.assertRaises(Invalid):
            Supervisor(self.store).engine(actors[0]['token'], ['/usr/bin/true'])
        with self.assertRaises(Invalid):
            self.store.register('aggregate', 'work')
        self.assertTrue(self.ask('read')['allowed'])
        events = self.store.audit_export('aggregate')['events']
        denials = [r for r in events if r['event'] == 'distinct-denial']
        self.assertEqual({r['session'] for r in denials}, {a['session'] for a in actors})
        save(self.evidence / 'aggregate-events.json', events)
        save(self.evidence / 'threshold.json', {'levels': levels, 'counts': counts,
            'useful_content': (Path(inv['root']) / 'dist/useful.txt').read_text(),
            'late_file_exists': (Path(inv['root']) / 'src/late.txt').exists()})

    def test_faulted_surrender_closes_admission_and_reconciles_physical_work(self):
        from ptw.evidence_storage import DEFAULT, usage
        # Adoption correctly requires quiescent work. Adopt before launching
        # the useful parent and children; only the quota fault is injected live.
        packet = self.store.evidence_review('python-demo', DEFAULT)
        self.store.adopt_evidence('python-demo', DEFAULT, digest(packet), 'fixture operator')
        parent = self.start_sentinel(self.actor, 'fault-parent')
        for fault in ('query', 'flags', 'capture', 'termination_capture', 'quota'):
            with self.subTest(fault=fault):
                child = self.store.register('python-demo', 'readcheck', parent_token=self.actor['token'])
                work = self.start_sentinel(child, 'fault-' + fault)
                if fault in ('flags', 'capture', 'termination_capture'):
                    target = 'UPDATE OF closed ON sessions' if fault == 'flags' else 'INSERT ON events'
                    condition = (" WHEN json_extract(NEW.request_meta,'$.action')='workload_termination'"
                                 if fault == 'termination_capture' else '')
                    with self.store.locked() as db:
                        db.execute('CREATE TRIGGER fault BEFORE ' + target + condition +
                                   " BEGIN SELECT RAISE(FAIL,'injected storage failure'); END")
                elif fault == 'quota':
                    with self.store.locked() as db:
                        profile = {**DEFAULT, 'project_bytes': max(65536, usage(db, 'python-demo'))}
                        db.execute('UPDATE evidence_profiles SET profile=? WHERE project=?',
                                   (json.dumps(profile), 'python-demo'))
                if fault == 'query':
                    with patch.object(Supervisor, 'terminate', return_value={'confirmed_stopped': False,
                            'error': 'injected supervisor failure'}), \
                            patch.object(Supervisor, 'state', return_value={'confirmed_stopped': False,
                            'error': 'injected query failure'}):
                        result = dispatch(self.store, child, 'end', request('surrender'))
                    self.assertFalse(result['confirmed_stopped'])
                    # Independent observation proves the failure was exercised.
                    self.assert_continues(work)
                else:
                    result = dispatch(self.store, child, 'end', request('surrender'))
                    self.assertEqual(result['evidence'], 'unavailable')
                    self.assert_stopped(work)
                    if fault == 'termination_capture':
                        self.assertTrue(result['confirmed_stopped'])
                        self.assertEqual(result['termination'][0]['evidence'], 'unavailable')
                        with self.store.locked() as db:
                            self.assertEqual(db.execute('SELECT stopped FROM workloads WHERE unit=?',
                                                        (work[1],)).fetchone()[0], 0)
                            self.assertIsNotNone(db.execute("SELECT 1 FROM events WHERE "
                                "json_extract(request_meta,'$.action')='session_closed' AND "
                                "json_extract(request_meta,'$._audit.session')=?", (child['session'],)).fetchone())
                    if fault == 'flags':
                        repeated = dispatch(self.store, child, 'still-failing', request('finish'))
                        save(self.evidence / 'flags-repeat-during-fault.json', repeated)
                        self.assertEqual(repeated['outcome'], 'surrender')
                        self.assertTrue(repeated['replayed'])
                        self.assertFalse(repeated['closure_flags_persisted'])
                self.assertTrue(result['admission_closed'])
                with self.assertRaises(Invalid):
                    Supervisor(self.store).engine(child['token'], ['/usr/bin/true'])
                with self.store.locked() as db:
                    db.execute('DROP TRIGGER IF EXISTS fault')
                    if fault == 'quota':
                        db.execute('UPDATE evidence_profiles SET profile=? WHERE project=?',
                                   (json.dumps(DEFAULT), 'python-demo'))
                Supervisor(Store(self.store.directory)).reconcile()
                self.assert_stopped(work)
                repeat = dispatch(self.store, child, 'repeat', request('surrender'))
                self.assertTrue(repeat['admission_closed'])
                self.assertTrue(repeat['confirmed_stopped'])
                self.assert_continues(parent)
                self.assertTrue(self.ask('read')['allowed'])
                self.assertFalse(self.store.status('python-demo')['stopped'])
                self.assertEqual(self.store.status('python-demo')['violations'], 0)
                save(self.evidence / (fault + '.json'), {'initial': result, 'repeated': repeat})

    def test_headless_surrender_stops_subtree_and_preserves_parent_sibling(self):
        child = self.store.register('python-demo', 'readcheck', parent_token=self.actor['token'])
        descendant = self.store.register('python-demo', 'readcheck', parent_token=child['token'])
        sibling = self.store.register('python-demo', 'readcheck', parent_token=self.actor['token'])
        parent_work = self.start_sentinel(self.actor, 'parent')
        child_work = self.start_sentinel(child, 'child')
        descendant_work = self.start_sentinel(descendant, 'descendant')
        sibling_work = self.start_sentinel(sibling, 'sibling')
        with patch('ptw.codex.generate', side_effect=[
                   (request('read', 'src', 'unavailable.txt'), {'deterministic_fixture': True}),
                   (request('surrender', content='Approved fixture unavailable'), {'deterministic_fixture': True})]) as generate, \
                patch('ptw.monitor.health', return_value={'healthy': True}):
            result = drive(self.store, child, 'Impossible fixture', max_steps=5)
        self.assertEqual(result['outcome'], 'surrendered')
        self.assertEqual(generate.call_count, 2)
        self.assertFalse(result['steps'][0]['result']['allowed'])
        self.assertTrue(result['steps'][-1]['result']['confirmed_stopped'])
        for work in (child_work, descendant_work):
            self.assert_stopped(work)
        for work in (parent_work, sibling_work):
            self.assert_continues(work)
        with self.assertRaises(Invalid):
            Supervisor(self.store).engine(child['token'], ['/usr/bin/true'])
        self.assertEqual(self.store.status('python-demo')['violations'], 0)

    def test_real_mcp_surrender_survives_lost_acknowledgement(self):
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
        # Dedicated foreground monitor avoids touching any shared service/config.
        self.start_monitor()
        child = self.store.register('python-demo', 'readcheck', parent_token=self.actor['token'])
        work = self.start_sentinel(child, 'mcp-child')
        other = self.start_sentinel(self.actor, 'mcp-parent')
        path = self.root / 'session.json'
        save(path, child)
        ready_to_surrender = False

        async def exercise():
            nonlocal ready_to_surrender
            env = {k: os.environ[k] for k in ('PATH', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS',
                   'PTW_NONO', 'PTW_UV') if k in os.environ}
            params = StdioServerParameters(command=sys.executable,
                args=['-B', '-m', 'ptw.mcp_server', '--state', str(self.store.directory),
                      '--session', str(path), '--bridge'], env=env)
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as client:
                    await client.initialize()
                    first = await client.call_tool('project_action', {'action': 'read', 'resource': 'src', 'path': 'calculator.py'})
                    self.assertFalse(first.is_error)
                    self.assertIn('return a - b', str(first))
                    # Ordinary tool responses leave admission open.
                    with self.store.locked() as db:
                        self.store.session(db, child['token'])
                    missing = await client.call_tool('project_action', {'action': 'read', 'resource': 'src', 'path': 'unavailable.txt'})
                    self.assertFalse(missing.is_error)
                    self.assertFalse(json.loads(missing.content[0].text)['allowed'])
                    ready_to_surrender = True
                    # The registered MCP broker is itself in the surrendered tree.
                    await client.call_tool('project_action', {'action': 'surrender', 'resource': '',
                                           'content': 'Approved fixture unavailable'})
        try:
            asyncio.run(asyncio.wait_for(exercise(), timeout=25))
        except Exception as exc:
            # A transport exception is only acceptable with independent durable
            # closure and cessation below. An earlier handshake failure fails.
            self.observations.append({'mcp_transport_exception': type(exc).__name__})
        self.assertTrue(ready_to_surrender, 'MCP failed before the explicit surrender request')
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            rows = self.store.status('python-demo')['sessions']
            if next(r for r in rows if r['id'] == child['session'])['closed']:
                break
            time.sleep(.05)
        self.assertTrue(next(r for r in rows if r['id'] == child['session'])['closed'])
        repeated = dispatch(self.store, child, 'lost-ack', request('surrender'))
        self.assertTrue(repeated['replayed'])
        self.assert_stopped(work)
        self.assert_continues(other)
        with self.assertRaises(Invalid):
            Adapter(self.store.directory, path)
        self.assertTrue(dispatch(self.store, self.actor, 'parent-useful', request('read', 'src', 'calculator.py'))['allowed'])


if __name__ == '__main__':
    unittest.main()
