"""Deterministic advisory transitions, not predictions or model trajectories."""
import concurrent.futures
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from ptw.package_evidence import EvidenceError, evaluate
from ptw.package_install import file_manifest
from ptw.packages import mounted_set
from ptw.policy import Invalid, OutsideScope, approve, canonical, compile_policy, digest, save
from ptw.reassessment import cached, refresh, seed, validate_binding, validate_publication
from ptw.store import Store
from ptw.supervisor import Supervisor
from test_packages import CRITICAL, FixtureProvider, PackageFixture
from test_workspace import WorkspaceFixture


def load_tests(loader, tests, pattern):
    from regression_timing import enable
    enable()
    return tests


class DiagnosticTimingTests(unittest.TestCase):
    def setUp(self):
        from regression_timing import Trace
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.trace = Trace(self.directory)

    def events(self):
        return [json.loads(line) for line in self.trace.path.read_text().splitlines()]

    def test_timings_preserve_order_results_and_cleanup(self):
        from regression_timing import instrument
        order = []

        class Fixture(unittest.TestCase):
            @classmethod
            def setUpClass(cls):
                order.append('class-setup')
                cls.addClassCleanup(order.append, 'class-cleanup')

            @classmethod
            def tearDownClass(cls):
                order.append('class-teardown')

            def setUp(self):
                order.append(self._testMethodName)
                self.addCleanup(order.append, 'cleanup')

            def test_ok(self):
                pass

            def test_failure(self):
                self.fail('private-payload-not-for-timing')

            def test_error(self):
                raise ValueError('private-payload-not-for-timing')

            def test_skip(self):
                self.skipTest('private-payload-not-for-timing')

        names = ('test_ok', 'test_failure', 'test_error', 'test_skip')
        selected = [Fixture(name) for name in names]
        originals = [test.run for test in selected]
        setup = Fixture.setUpClass
        result = unittest.TestResult()
        suite = unittest.TestSuite(selected)
        with instrument(suite, result, self.trace):
            suite.run(result)
        self.assertEqual([test.run for test in selected], originals)
        self.assertEqual(Fixture.setUpClass, setup)
        self.assertEqual(order, ['class-setup', 'test_ok', 'cleanup', 'test_failure', 'cleanup',
                                 'test_error', 'cleanup', 'test_skip', 'cleanup',
                                 'class-teardown', 'class-cleanup'])
        self.assertEqual((result.testsRun, len(result.failures), len(result.errors), len(result.skipped)),
                         (4, 1, 1, 1))
        events = self.events()
        ends = [e for e in events if e['event'] == 'end' and e['kind'] == 'test']
        self.assertEqual([e['outcome'] for e in ends], ['success', 'failures', 'errors', 'skipped'])
        for start, end in zip(events[::2], events[1::2]):
            self.assertEqual((start['event'], end['event']), ('start', 'end'))
            self.assertEqual(start['span'], end['span'])
            for key in ('monotonic_ns', 'cpu_self_user', 'cpu_self_system',
                        'cpu_children_user', 'cpu_children_system'):
                self.assertGreaterEqual(end[key], start[key])
        self.assertNotIn('private-payload', self.trace.path.read_text())

    def test_failed_class_setup_and_cleanup_are_retained(self):
        from regression_timing import instrument

        class Fixture(unittest.TestCase):
            @classmethod
            def setUpClass(cls):
                def fail_cleanup():
                    raise ValueError('private-cleanup')
                cls.addClassCleanup(fail_cleanup)
                raise ValueError('private-setup')

            def test_unused(self):
                self.fail('must not execute')

        result = unittest.TestResult()
        suite = unittest.TestSuite([Fixture('test_unused')])
        with instrument(suite, result, self.trace):
            suite.run(result)
        self.assertEqual(result.testsRun, 0)
        self.assertEqual(len(result.errors), 2)
        ends = [e for e in self.events() if e['event'] == 'end']
        self.assertEqual([e['outcome'] for e in ends], ['error', 'errors'])
        self.assertNotIn('private-', self.trace.path.read_text())

    def test_interruption_keeps_started_span_and_restores_hooks(self):
        from regression_timing import instrument

        class Fixture(unittest.TestCase):
            def test_interrupt(self):
                self.assert_started()
                raise KeyboardInterrupt('private-interruption')

        case = Fixture('test_interrupt')
        case.assert_started = lambda: self.assertEqual(self.events()[-1]['event'], 'start')
        original = case.run
        result = unittest.TestResult()
        suite = unittest.TestSuite([case])
        with self.assertRaises(KeyboardInterrupt), instrument(suite, result, self.trace):
            suite.run(result)
        self.assertEqual(case.run, original)
        self.assertEqual(self.events()[-1]['outcome'], 'interrupted')
        self.assertNotIn('private-interruption', self.trace.path.read_text())

    def test_phase_hooks_forward_calls_and_restore_after_failure(self):
        from regression_timing import YARN_TARGETS, yarn_phases
        from ptw import yarn_tool
        with patch.object(yarn_tool, 'verified', side_effect=Invalid('private-argument')) as original:
            with yarn_phases(self.trace, sorted(YARN_TARGETS)[0]):
                with self.assertRaises(Invalid):
                    yarn_tool.verified(directory='private-directory')
            self.assertIs(yarn_tool.verified, original)
            original.assert_called_once_with(directory='private-directory')
        self.assertEqual(self.events()[-1]['outcome'], 'error')
        self.assertNotIn('private-', self.trace.path.read_text())

    def test_terminal_child_uses_separate_trace_and_retains_failure(self):
        from regression_timing import YARN_TARGETS
        script = ('import sys\nfrom unittest.mock import patch\n'
                  'sys.path.insert(0, ' + repr(str(Path(__file__).parent)) + ')\n'
                  'from regression_timing import child_phases\n'
                  'from ptw import yarn_tool\n'
                  'with patch.object(yarn_tool, "verified", return_value="unchanged"):\n'
                  '    with child_phases(sys.argv[1], sys.argv[2]):\n'
                  '        assert yarn_tool.verified() == "unchanged"\n'
                  '        raise SystemExit(2)\n')
        with self.trace.span('test', 'synthetic-terminal'):
            result = subprocess.run([sys.executable, '-B', '-c', script, str(self.directory),
                                     sorted(YARN_TARGETS)[0]], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 2, result.stderr)
        files = list(self.directory.glob('timing-*.jsonl'))
        self.assertEqual(len(files), 2)
        child = next(p for p in files if p != self.trace.path)
        events = [json.loads(line) for line in child.read_text().splitlines()]
        self.assertEqual(events[0]['kind'], 'terminal')
        self.assertEqual(events[-1]['exception_type'], 'SystemExit')
        self.assertEqual(events[-1]['exit_code'], 2)
        self.assertTrue(any(e['kind'] == 'phase' and e.get('outcome') == 'completed' for e in events))

    def test_native_discovery_hook_keeps_runner_and_records_source(self):
        script = ('import os, sys, unittest\n'
                  'sys.path.insert(0, ' + repr(str(Path(__file__).parent)) + ')\n'
                  'from regression_timing import enable\n'
                  'os.environ["PTW_LINUX_TESTS"] = "1"\n'
                  'enable()\nenable()\n'
                  'class Fixture(unittest.TestCase):\n'
                  '    def test_ok(self): pass\n'
                  'suite = unittest.defaultTestLoader.loadTestsFromTestCase(Fixture)\n'
                  'result = unittest.TextTestRunner().run(suite)\n'
                  'assert result.wasSuccessful() and result.testsRun == 1\n')
        env = dict(os.environ, TMPDIR=str(self.directory))
        result = subprocess.run([sys.executable, '-B', '-c', script], env=env,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count('REGRESSION_TIMING_EVIDENCE '), 1)
        directories = list(self.directory.glob('ptw-regression-timing-*'))
        self.assertEqual(len(directories), 1)
        hashes = json.loads((directories[0] / 'source.json').read_text())
        self.assertEqual(hashes['tests/regression_timing.py'], hashlib.sha256(
            (Path(__file__).parent / 'regression_timing.py').read_bytes()).hexdigest())
        events = [json.loads(line) for line in next(directories[0].glob('timing-*.jsonl')).read_text().splitlines()]
        self.assertEqual(events[0]['kind'], 'suite')
        self.assertEqual(events[-1]['outcome'], 'success')
        self.assertEqual(events[-1]['tests_run'], 1)
        self.assertEqual(sum(e['kind'] == 'test' and e['event'] == 'end' for e in events), 1)


class AdvisoryFixture:
    def __init__(self, values=None):
        self.values = values or {}
        self.calls = []

    def advisories(self, ecosystem, name, version):
        self.calls.append((ecosystem, name, version))
        value = self.values.get((name, version), [])
        if isinstance(value, Exception):
            raise value
        return copy.deepcopy(value)


class ReassessmentTests(PackageFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.evidence = FixtureProvider().assess('idna', '3.11')
        self.package = self.make_set([self.evidence])

    def make_set(self, evidence, *, ecosystem='pypi', project='website'):
        identity = 'pkg_' + secrets.token_hex(12)
        directory = self.store.directory / 'package-sets' / identity
        directory.mkdir(parents=True)
        (directory / 'fixture').write_text('installed bytes')
        with self.store.locked() as db:
            _, bundle = self.store.project(db, project)
            names = sorted({r['name'] for r in evidence})
            db.execute('INSERT INTO package_sets(id,project,names,manifest,created,ecosystem,policy_sha256) '
                       'VALUES(?,?,?,?,?,?,?)', (identity, project, canonical(names), canonical(file_manifest(directory)),
                        time.time(), ecosystem, bundle['approval']['sha256']))
            seed(db, identity, evidence)
        return identity

    def expire(self, identity=None):
        with self.store.locked() as db:
            row = db.execute('SELECT evidence FROM package_sets WHERE id=?', (identity or self.package,)).fetchone()
            evidence = json.loads(row['evidence'])
            for record in evidence:
                record['checked_at'] = time.time() - 1000
            db.execute('UPDATE package_sets SET evidence=? WHERE id=?', (canonical(evidence), identity or self.package))

    def row(self, identity=None):
        with self.store.locked() as db:
            return dict(db.execute('SELECT * FROM package_sets WHERE id=?', (identity or self.package,)).fetchone())

    def reuse(self, provider=None, identity=None, token=None):
        refresh(self.store, token or self.a['token'], identity or self.package,
                provider=provider or AdvisoryFixture())

    def test_fresh_offline_then_expired_clean_refresh_preserves_artifact(self):
        provider = AdvisoryFixture({('idna', '3.11'): EvidenceError('offline')})
        self.reuse(provider)
        self.assertEqual(provider.calls, [])
        self.expire()
        provider.values.clear()
        before = self.row()
        self.reuse(provider)
        self.assertEqual(provider.calls, [('PyPI', 'idna', '3.11')])
        after = self.row()
        old, new = json.loads(before['evidence'])[0], json.loads(after['evidence'])[0]
        self.assertEqual({k: v for k, v in old.items() if k != 'checked_at'},
                         {k: v for k, v in new.items() if k != 'checked_at'})
        self.assertGreater(new['checked_at'], old['checked_at'])
        self.assertEqual(after['assessment_state'], 'current')

    def test_critical_quarantines_duplicates_and_survives_restart_replay(self):
        duplicate = self.make_set([self.evidence])
        self.expire()
        with self.assertRaisesRegex(EvidenceError, 'quarantined'):
            self.reuse(AdvisoryFixture({('idna', '3.11'): [CRITICAL]}))
        self.store = Store(self.store.directory)
        for identity in (self.package, duplicate):
            self.assertEqual(self.row(identity)['assessment_state'], 'quarantined')
            with self.assertRaises(EvidenceError):
                self.reuse(identity=identity)
        self.assertEqual(self.store.status('website')['violations'], 0)
        replacement = self.make_set([FixtureProvider().assess('idna', '3.11')])
        self.reuse(identity=replacement)
        self.assertEqual(self.row()['assessment_state'], 'quarantined')

    def test_quarantine_during_registry_install_blocks_old_evidence_and_allows_retry(self):
        self.expire()

        def stage(wheelhouse, target, evidence, **kwargs):
            target.mkdir()
            (target / 'fixture').write_text('confined installer output')

        def quarantine_during_install(*args, **kwargs):
            stage(*args, **kwargs)
            with self.assertRaisesRegex(EvidenceError, 'quarantined'):
                self.reuse(AdvisoryFixture({('idna', '3.11'): [CRITICAL]}))

        with patch('ptw.packages.install_wheels', side_effect=quarantine_during_install):
            denied = self.install(event='racing-install')
        self.assertFalse(denied['allowed'], denied)
        self.assertFalse(denied['violation_counted'])
        self.assertIn('quarantined during installation', denied['reason'])
        status = self.store.status('website')
        self.assertEqual(len(status['package_sets']), 1)
        self.assertEqual(status['violations'], 0)
        self.assertFalse(status['stopped'])
        # A new request collects evidence after the finding; withdrawal/correction
        # can permit a replacement without reviving the old installation.
        with patch('ptw.packages.install_wheels', side_effect=stage):
            replacement = self.install(event='fresh-retry')
        self.assertTrue(replacement['allowed'], replacement)
        self.assertNotEqual(replacement['package_set'], self.package)
        self.assertEqual(self.row()['assessment_state'], 'quarantined')

    def test_local_publication_retains_staging_when_build_evidence_predates_quarantine(self):
        from ptw.python_local import publish_set
        self.expire()
        with self.assertRaisesRegex(EvidenceError, 'quarantined'):
            self.reuse(AdvisoryFixture({('idna', '3.11'): [CRITICAL]}))
        self.store = Store(self.store.directory)
        site = self.root / 'local-staging'
        site.mkdir()
        (site / 'fixture').write_text('built local wheel')
        with self.store.locked() as db:
            _, bundle = self.store.project(db, 'website')
            # No registry runtime names: this is retained local build evidence.
            with self.assertRaisesRegex(EvidenceError, 'quarantined during installation'):
                publish_set(self.store, db, 'website', bundle['approval']['sha256'], site,
                            set(), file_manifest(site), {}, [self.evidence])
            self.assertEqual(db.execute('SELECT COUNT(*) FROM package_sets').fetchone()[0], 1)
        self.assertEqual((site / 'fixture').read_text(), 'built local wheel')
        self.assertFalse(self.store.status('website')['stopped'])

    def test_publication_barrier_is_exact_identity_and_project_scoped(self):
        self.expire()
        with self.assertRaisesRegex(EvidenceError, 'quarantined'):
            self.reuse(AdvisoryFixture({('idna', '3.11'): [CRITICAL]}))
        with self.store.locked() as db:
            with self.assertRaises(EvidenceError):
                validate_publication(db, 'website', 'pypi', [self.evidence])
            validate_publication(db, 'unrelated', 'pypi', [self.evidence])
            validate_publication(db, 'website', 'npm', [self.evidence])
            validate_publication(db, 'website', 'pypi', [{**self.evidence, 'version': '3.10'}])
            validate_publication(db, 'website', 'pypi', [{**self.evidence, 'origin': 'https://private.invalid'}])

    def test_outage_unknown_severity_and_missing_evidence_block_without_misconduct(self):
        for response in (EvidenceError('offline'), None, [{'id': 'NO-SCORE'}],
                         [{'id': 'BAD', 'severity': [{'type': 'UNKNOWN', 'score': '10'}]}]):
            with self.subTest(response=response):
                self.expire()
                old = self.row()['evidence']
                with self.assertRaises(EvidenceError):
                    self.reuse(AdvisoryFixture({('idna', '3.11'): response}))
                self.assertEqual(self.row()['assessment_state'], 'blocked')
                self.assertEqual(self.row()['evidence'], old)
                self.assertEqual(self.store.status('website')['violations'], 0)
                self.reuse()
                self.assertEqual(self.row()['assessment_state'], 'current')

    def test_exact_freshness_boundary_and_invalid_collection_times(self):
        rules = self.policy['project']['packages']
        now = time.time()
        record = {**self.evidence, 'checked_at': now - rules['evidence_max_age_seconds']}
        self.assertEqual(evaluate(record, rules, now=now), [])
        for value in (record['checked_at'] - .01, now + 1, float('nan'), float('inf'), None, 'today', True):
            with self.subTest(value=value), self.assertRaises(EvidenceError):
                evaluate({**record, 'checked_at': value}, rules, now=now)

    def test_withdrawn_advisory_and_deadline(self):
        self.expire()
        self.reuse(AdvisoryFixture({('idna', '3.11'): [{**CRITICAL, 'withdrawn': '2020-01-01T00:00:00Z'}]}))
        self.expire()
        with patch('ptw.reassessment.BUDGET_SECONDS', 0), self.assertRaises(EvidenceError):
            self.reuse()
        self.assertEqual(self.row()['assessment_state'], 'blocked')

    def test_partial_uncertainty_cannot_hide_confirmed_transitive_critical(self):
        evidence = [self.evidence, FixtureProvider().assess('django', '3.2.0')]
        self.package = self.make_set(evidence)
        self.expire()
        values = {('idna', '3.11'): EvidenceError('offline'),
                  ('django', '3.2.0'): [{'id': 'UNKNOWN'}, CRITICAL]}
        with self.assertRaisesRegex(EvidenceError, 'quarantined'):
            self.reuse(AdvisoryFixture(values))
        self.assertEqual(self.row()['assessment_state'], 'quarantined')

    def test_npm_nested_versions_refresh_exact_identities(self):
        self.package = self.make_set([self.evidence, {**self.evidence, 'version': '3.10'}], ecosystem='npm')
        self.expire()
        provider = AdvisoryFixture({('idna', '3.10'): [CRITICAL]})
        with self.assertRaisesRegex(EvidenceError, 'quarantined'):
            self.reuse(provider)
        self.assertCountEqual(provider.calls, [('npm', 'idna', '3.11'), ('npm', 'idna', '3.10')])

    def test_private_origin_mismatch_is_operational(self):
        self.package = self.make_set([{**self.evidence, 'origin': 'https://private.invalid'}])
        self.expire()
        provider = AdvisoryFixture()
        with self.assertRaisesRegex(EvidenceError, 'origin'):
            self.reuse(provider)
        self.assertEqual(provider.calls, [])
        self.assertEqual(self.store.status('website')['violations'], 0)
        provider.routes = {'idna': {'registry': 'https://private.invalid'}}
        self.reuse(provider)
        self.assertEqual(self.row()['assessment_state'], 'current')

    def test_missing_provenance_and_tampering_never_reach_network(self):
        provider = AdvisoryFixture()
        with self.store.locked() as db:
            db.execute('UPDATE package_sets SET evidence=NULL WHERE id=?', (self.package,))
        with self.assertRaisesRegex(EvidenceError, 'provenance'):
            self.reuse(provider)
        (self.store.directory / 'package-sets' / self.package / 'fixture').write_text('tampered')
        with self.assertRaisesRegex(Invalid, 'integrity'):
            self.reuse(provider)
        self.assertEqual(provider.calls, [])

    def test_incomplete_identity_coverage_is_not_an_empty_clean_scan(self):
        with self.store.locked() as db:
            db.execute("UPDATE package_sets SET evidence='[]' WHERE id=?", (self.package,))
        with self.assertRaisesRegex(EvidenceError, 'provenance'):
            self.reuse()

    def test_parent_delegate_and_other_task_scope_checked_before_refresh(self):
        child = self.store.register('website', 'frontend', parent_token=self.a['token'], packages=[])
        self.expire()
        provider = AdvisoryFixture()
        for actor in (child, self.b):
            with self.assertRaises(OutsideScope):
                self.reuse(provider, token=actor['token'])
        self.assertEqual(provider.calls, [])

    def test_clean_refresh_cannot_overwrite_concurrent_quarantine(self):
        self.expire()
        entered, release = threading.Event(), threading.Event()
        provider = AdvisoryFixture()
        def paused(*args):
            entered.set()
            self.assertTrue(release.wait(5))
            return []
        provider.advisories = paused
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.reuse, provider)
            try:
                self.assertTrue(entered.wait(5))
                with self.assertRaises(EvidenceError):
                    self.reuse(AdvisoryFixture({('idna', '3.11'): [CRITICAL]}))
            finally:
                release.set()
            with self.assertRaises(EvidenceError):
                future.result(timeout=5)
        self.assertEqual(self.row()['assessment_state'], 'quarantined')

    def test_stop_close_scope_and_revision_during_fetch_discard_result(self):
        for mutation in ('stop', 'close', 'scope', 'revision', 'tamper'):
            with self.subTest(mutation=mutation):
                # Each environment is independent; retained failed attempts are not overwritten.
                self.store = self.activate('-' + mutation)
                self.a = self.store.register('website', 'frontend')
                self.package = self.make_set([self.evidence])
                self.expire()
                provider = AdvisoryFixture()
                def changed(*args):
                    with self.store.locked() as db:
                        if mutation == 'stop':
                            self.store.stop_from_db(db, 'website', 'test stop')
                        elif mutation == 'close':
                            db.execute('UPDATE sessions SET closed=1')
                        elif mutation == 'scope':
                            db.execute("UPDATE sessions SET packages='[]'")
                        elif mutation == 'revision':
                            db.execute("UPDATE package_sets SET policy_sha256='obsolete'")
                        else:
                            (self.store.directory / 'package-sets' / self.package / 'fixture').write_text('changed')
                    return []
                provider.advisories = changed
                with self.assertRaises(Invalid):
                    self.reuse(provider)
                self.assertEqual(self.row()['assessment_generation'], 1)
                with self.store.locked() as db:
                    self.assertEqual(db.execute('SELECT outcome FROM package_assessments ORDER BY at DESC').fetchone()[0], 'discarded')

    def test_quarantine_targets_only_bound_work_and_retries_failed_termination(self):
        affected, unaffected = ('ptw-' + secrets.token_hex(12) + '.service' for _ in range(2))
        with self.store.locked() as db:
            actor = self.store.session(db, self.a['token'])
            for unit in (affected, unaffected):
                db.execute('INSERT INTO workloads(unit,project,session) VALUES(?,?,?)', (unit, 'website', actor['id']))
            db.execute('INSERT INTO workload_packages VALUES(?,?)', (affected, self.package))
        self.expire()
        with patch.object(Supervisor, 'terminate', return_value={'confirmed_stopped': False}) as terminate:
            with self.assertRaises(EvidenceError):
                self.reuse(AdvisoryFixture({('idna', '3.11'): [CRITICAL]}))
            terminate.assert_called_once_with(affected)
        with patch.object(Supervisor, 'terminate', return_value={'confirmed_stopped': True}) as terminate:
            Supervisor(self.store).reconcile()
            terminate.assert_called_once_with(affected)
        status = self.store.status('website')
        self.assertEqual({w['unit']: w['stopped'] for w in status['workloads']}, {affected: 1, unaffected: 0})
        self.assertEqual(len(status['package_terminations']), 2)

    def test_admission_revalidates_before_process_creation(self):
        binding = {'approval': self.row()['policy_sha256'], 'definition': None,
                   'snapshot': None, 'package_sets': [self.package]}
        self.expire()
        with patch('ptw.supervisor.subprocess.Popen') as popen:
            with self.assertRaises(EvidenceError):
                Supervisor(self.store).engine(self.a['token'], ['unused'], binding=binding)
            popen.assert_not_called()
        self.reuse()
        with self.store.locked() as db:
            actor = self.store.session(db, self.a['token'])
            validate_binding(self.store, db, actor, binding)
            db.execute("UPDATE package_sets SET assessment_state='quarantined'")
            with self.assertRaises(EvidenceError):
                validate_binding(self.store, db, actor, binding)


class PublicationReassessmentTests(WorkspaceFixture):
    def test_quarantine_between_execution_and_publication_discards_outputs(self):
        from ptw.workspace import scan
        package = 'pkg_' + secrets.token_hex(12)
        directory = self.store.directory / 'package-sets' / package
        directory.mkdir(parents=True)
        (directory / 'six.py').write_text('VALUE = 42\n')
        evidence = FixtureProvider().assess('six', '1.17.0')
        with self.store.locked() as db:
            _, bundle = self.store.project(db, 'python-demo')
            db.execute('INSERT INTO package_sets(id,project,names,manifest,created,ecosystem,policy_sha256) '
                       'VALUES(?,?,?,?,?,?,?)', (package, 'python-demo', '["pypi:six"]', canonical(file_manifest(directory)),
                        time.time(), 'pypi', bundle['approval']['sha256']))
            seed(db, package, [evidence])
        before = scan(self.inv, ['src', 'tests'])
        after = copy.deepcopy(before)
        after['src/calculator.py']['data'] = b'NEVER_PUBLISH'
        def execute(*args, binding):
            binding['package_sets'] = [package]
            with self.store.locked() as db:
                db.execute("UPDATE package_sets SET assessment_state='quarantined' WHERE id=?", (package,))
            return after, {'exit_code': 0, 'output': '', 'output_truncated': False}
        with patch('ptw.execution.execute', side_effect=execute):
            result = self.ask('run', resource='test', path='', content=canonical({'package_sets': [package]}))
        self.assertFalse(result['allowed'], result)
        self.assertIn('quarantined', result['reason'])
        self.assertEqual((Path(self.inv['root']) / 'src/calculator.py').read_bytes(), before['src/calculator.py']['data'])
        self.assertEqual(self.store.status('python-demo')['violations'], 0)


class NativeEvidence:
    def setUp(self):
        super().setUp()
        self.evidence_directory = Path(tempfile.mkdtemp(prefix='ptw-reassessment-evidence-'))
        print('REASSESSMENT_EVIDENCE ' + str(self.evidence_directory), flush=True)
        source = Path(__file__).resolve().parents[1]
        save(self.evidence_directory / 'source.json', {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in [*sorted((source / 'ptw').glob('*.py')), Path(__file__).resolve()]})
        self.addCleanup(self.retain_evidence)

    def retain_evidence(self):
        with self.store.locked() as db:
            projects = [r[0] for r in db.execute('SELECT id FROM projects')]
            attempts = [dict(r) for r in db.execute('SELECT * FROM package_assessments ORDER BY at')]
        save(self.evidence_directory / 'state.json', {'test': self.id(), 'attempts': attempts,
             'projects': [self.store.status(p) for p in projects]})


@unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'Native isolated Linux VPS required')
class NativeReassessmentTests(NativeEvidence, PackageFixture, unittest.TestCase):
    def test_installed_import_quarantine_physical_stop_unrelated_and_terminal(self):
        result = self.install()
        self.assertTrue(result['allowed'], result)
        package = result['package_set']
        supervisor = Supervisor(self.store)
        self.addCleanup(self.store.stop, 'website')
        self.addCleanup(supervisor.reconcile)
        code = "import idna,time; open('/resources/ui','w').write(idna.VALUE); time.sleep(120)"
        unit = supervisor.launch(self.a['token'], ['/usr/bin/python3', '-c', code], package_set=package)
        policy = copy.deepcopy(self.policy)
        policy['project']['id'] = 'unrelated'
        self.store.activate(approve(policy, self.inv, digest(compile_policy(policy, self.inv)), 'fixture operator'))
        other = self.store.register('unrelated', 'frontend')
        unrelated = supervisor.launch(other['token'], ['/usr/bin/python3', '-c', 'import time; time.sleep(120)'])
        self.addCleanup(supervisor.terminate, unrelated)
        self.addCleanup(supervisor.terminate, unit)
        ui = Path(self.inv['root']) / self.inv['resources']['ui']['path']
        deadline = time.monotonic() + 10
        while 'SYNTHETIC_PACKAGE_OK' not in ui.read_text() and time.monotonic() < deadline:
            time.sleep(.05)
        self.assertIn('SYNTHETIC_PACKAGE_OK', ui.read_text())
        with self.store.locked() as db:
            row = db.execute('SELECT evidence FROM package_sets WHERE id=?', (package,)).fetchone()
            evidence = json.loads(row['evidence'])
            for record in evidence:
                record['checked_at'] -= 1000
            db.execute('UPDATE package_sets SET evidence=? WHERE id=?', (canonical(evidence), package))
        with self.assertRaises(EvidenceError):
            refresh(self.store, self.a['token'], package, provider=AdvisoryFixture({('idna', '3.11'): [CRITICAL]}))
        self.assertTrue(supervisor.state(unit)['confirmed_stopped'])
        self.assertEqual(supervisor.state(unrelated)['ActiveState'], 'active')
        self.assertEqual(self.store.status('website')['violations'], 0)
        # The real terminal-facing command returns an error and cannot replay authorization.
        session = self.root / 'session.json'
        save(session, self.a)
        terminal = subprocess.run([sys.executable, '-B', '-m', 'ptw', 'launch', '--state', str(self.store.directory),
            '--session', str(session), '--package-set', package, '--', '/usr/bin/true'],
            capture_output=True, text=True, timeout=15)
        self.assertNotEqual(terminal.returncode, 0)
        self.assertIn('quarantined', terminal.stdout + terminal.stderr)
        replay = self.install()
        self.assertFalse(replay['allowed'])
        self.assertFalse(replay['violation_counted'])
        replacement = self.install(event='recovery')
        self.assertTrue(replacement['allowed'], replacement)
        self.assertNotEqual(replacement['package_set'], package)


@unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'Native sockets, namespaces and systemd required')
class NativeWorkspaceReassessmentTests(NativeEvidence, WorkspaceFixture):
    def test_preview_and_running_command_stop_without_publishing_outputs(self):
        import socket
        from ptw.monitor import ensure, remove
        from ptw.packages import PackageControl
        from ptw.workspace import Workspace, request
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        definitions = [
            {'id': 'use', 'argv': ['/usr/bin/python3', '-c',
                "import six; from pathlib import Path; Path('dist/ok').write_text(six.VALUE); print(six.VALUE)"],
             'resources': ['src', 'dist'], 'timeout_seconds': 10},
            {'id': 'slow', 'argv': ['/usr/bin/python3', '-c',
                "import six,time; from pathlib import Path; time.sleep(60); Path('dist/late').write_text(six.VALUE)"],
             'resources': ['src', 'dist'], 'timeout_seconds': 90},
            {'id': 'preview', 'argv': ['/usr/bin/python3', '-B', 'src/server.py'],
             'resources': ['src'], 'timeout_seconds': 10,
             'preview': {'port': port, 'lifetime_seconds': 120}}]
        self.policy['project']['commands'].extend(definitions)
        self.policy['tasks'][0]['commands'].extend(c['id'] for c in definitions)
        self.store = Store(self.root / 'reassessment-native')
        self.store.activate(self.approve())
        self.actor = self.store.register('python-demo', 'implementation')
        self.broker = Workspace(self.store)
        repo = Path(self.inv['root'])
        (repo / 'src/server.py').write_text(
            "import os,six\nfrom http.server import BaseHTTPRequestHandler,HTTPServer\n"
            "class Handler(BaseHTTPRequestHandler):\n"
            " def do_GET(self):\n  self.send_response(200); self.end_headers(); self.wfile.write(six.VALUE.encode())\n"
            "HTTPServer(('127.0.0.1',int(os.environ['PORT'])),Handler).serve_forever()\n")
        provider = FixtureProvider()
        result = PackageControl(self.store, provider=provider).install(self.actor['token'], 'install', ['six==1.17.0'])
        self.assertTrue(result['allowed'], result)
        package = result['package_set']
        settings = canonical({'package_sets': [package]})
        def action(event, command, kind='run'):
            return self.broker.request(self.actor['token'], event, request(kind, command, content=settings))
        def cleanup_monitor():
            self.store.stop('python-demo')
            Supervisor(self.store).reconcile()
            remove(self.store)
        self.addCleanup(cleanup_monitor)
        ensure(self.store)
        useful = action('use', 'use')
        self.assertTrue(useful['allowed'], useful)
        self.assertEqual(useful['exit_code'], 0, useful)
        self.assertEqual((repo / 'dist/ok').read_text(), 'SYNTHETIC_PACKAGE_OK')
        preview = action('preview', 'preview', 'service_start')
        self.assertTrue(preview['allowed'], preview)
        from urllib.request import urlopen
        with urlopen(preview['url'], timeout=5) as response:
            self.assertEqual(response.read(), b'SYNTHETIC_PACKAGE_OK')
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            running = pool.submit(action, 'slow', 'slow')
            deadline = time.monotonic() + 15
            units = []
            while time.monotonic() < deadline:
                with self.store.locked() as db:
                    units = [r[0] for r in db.execute('SELECT w.unit FROM workloads w JOIN workload_packages wp '
                        'ON wp.unit=w.unit WHERE wp.package_set=? AND w.stopped=0 AND w.unit!=?', (package, preview['unit']))]
                # Completed commands remain registered until reconciled, so query physical state.
                units = [u for u in units if Supervisor.state(u).get('ActiveState') == 'active']
                if units:
                    break
                time.sleep(.05)
            self.assertTrue(units, 'Bound command did not become active')
            with self.store.locked() as db:
                row = db.execute('SELECT evidence FROM package_sets WHERE id=?', (package,)).fetchone()
                evidence = json.loads(row[0])
                for record in evidence:
                    record['checked_at'] -= 1000
                db.execute('UPDATE package_sets SET evidence=? WHERE id=?', (canonical(evidence), package))
            advisory = AdvisoryFixture({('six', '1.17.0'): [CRITICAL]})
            with patch('ptw.registry.provider_for', return_value=advisory):
                denied = action('critical-use', 'use')
            self.assertFalse(denied['allowed'], denied)
            self.assertIn('quarantined', denied['reason'])
            self.assertFalse(running.result(timeout=15)['allowed'])
        self.assertFalse((repo / 'dist/late').exists())
        self.assertTrue(Supervisor.state(preview['unit'])['confirmed_stopped'])
        self.assertTrue(all(Supervisor.state(u)['confirmed_stopped'] for u in units))
        self.assertEqual(self.store.status('python-demo')['violations'], 0)
        self.assertEqual(provider.downloads, 1, 'Reassessment must never download artifacts')
