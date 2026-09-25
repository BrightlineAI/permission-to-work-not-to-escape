"""Deterministic advisory transitions, not predictions or model trajectories."""
import concurrent.futures
from collections import Counter
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
from ptw.store import Store, operation_lease
from ptw.supervisor import Supervisor
from test_packages import CRITICAL, FixtureProvider, PackageFixture
from test_workspace import WorkspaceFixture


def load_tests(loader, tests, pattern):
    from regression_timing import enable
    enable()
    return tests


class DiscoveryTests(unittest.TestCase):
    """Inspect real suites without executing native fixtures or their setup."""

    @staticmethod
    def cases(suite):
        for test in suite:
            if isinstance(test, unittest.TestSuite):
                yield from DiscoveryTests.cases(test)
            else:
                yield test

    def discover(self, pattern):
        loader = unittest.TestLoader()
        suite = loader.discover(str(Path(__file__).parent), pattern=pattern)
        self.assertEqual(loader.errors, [])
        return list(self.cases(suite))

    def test_standalone_node_gate_retains_every_selected_case(self):
        import test_product_node_import as gate
        loader = unittest.TestLoader()
        expected = list(self.cases(loader.loadTestsFromTestCase(gate.NodeImportTests)))
        for case, methods in gate.REGRESSIONS.items():
            expected.extend(self.cases(loader.loadTestsFromNames(
                [case + '.' + method for method in methods])))
        self.assertEqual(loader.errors, [])
        self.assertEqual(len(expected), 57)
        for suite in (loader.loadTestsFromModule(gate),
                      self.discover('test_product_node_import.py')):
            # TestCase equality includes the class and method, preserving the
            # actual fixtures rather than merely matching printable IDs.
            self.assertEqual(list(self.cases(suite)), expected)
        self.assertEqual(loader.errors, [])

    def test_discovery_removes_only_selections_owned_by_discovered_modules(self):
        import test_product_node_import as gate

        def original_hook(loader, tests, pattern):
            for case, methods in gate.REGRESSIONS.items():
                tests.addTests(loader.loadTestsFromNames(
                    [case + '.' + method for method in methods]))
            return tests

        # Partial discovery must still import selections from excluded owners.
        for pattern in ('test*.py', 'test_product_[np]*.py'):
            with self.subTest(pattern=pattern):
                with patch.object(gate, 'load_tests', original_hook):
                    before = self.discover(pattern)
                after = self.discover(pattern)
                self.assertEqual(set(after), set(before))
                self.assertTrue(set(unittest.TestLoader().loadTestsFromTestCase(
                    gate.NodeImportTests)) <= set(after))
                before_counts, after_counts = Counter(before), Counter(after)
                selected = unittest.TestLoader().loadTestsFromNames([
                    case + '.' + method for case, methods in gate.REGRESSIONS.items()
                    for method in methods])
                duplicated = Counter(test for test in self.cases(selected)
                                     if before_counts[test] == 2)
                self.assertTrue(duplicated)
                self.assertEqual(after_counts + duplicated, before_counts)
                self.assertTrue(all(after_counts[test] == 1 for test in duplicated))
                if pattern == 'test*.py':
                    self.assertEqual(sum(duplicated.values()), 51)

    def test_missing_selection_and_owner_load_failure_remain_errors(self):
        import test_product_node_import as gate
        import test_product_pnpm as owner
        loader = unittest.TestLoader()
        with patch.dict(gate.REGRESSIONS, {
                'test_product_pnpm.PnpmNativeTests': ('test_missing_selection',)}, clear=True):
            suite = loader.loadTestsFromModule(gate)
        self.assertEqual(len(loader.errors), 1)
        self.assertIn('test_missing_selection', loader.errors[0])
        self.assertTrue(any(test.id().startswith('unittest.loader._FailedTest.')
                            for test in self.cases(suite)))

        loader = unittest.TestLoader()
        with patch.object(owner, 'load_tests', create=True,
                          side_effect=RuntimeError('synthetic owner loading failure')):
            suite = loader.discover(str(Path(__file__).parent), pattern='test*.py')
        self.assertEqual(len(loader.errors), 1)
        self.assertIn('synthetic owner loading failure', loader.errors[0])
        self.assertIn('unittest.loader._FailedTest.test_product_pnpm',
                      [test.id() for test in self.cases(suite)])


class DiagnosticTimingTests(unittest.TestCase):
    def setUp(self):
        from regression_timing import Trace
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.trace = Trace(self.directory)

    def events(self):
        return [json.loads(line) for line in self.trace.path.read_text().splitlines()]

    def test_editable_profile_separates_exclusive_work_and_wait_without_private_data(self):
        from regression_timing import EDITABLE_TARGET, editable_profile
        namespace = {}
        exec(compile('def private_function(value):\n return value\n',
                     '/private-profile-path', 'exec'), namespace)
        value = object()

        def production(depth, argument):
            if depth:
                return production(depth - 1, argument)
            return namespace['private_function'](argument)

        def fixture(argument):
            result = production(3, argument)
            subprocess.run([sys.executable, '-I', '-c', 'import time; time.sleep(.01)'],
                           check=True, capture_output=True)
            return result

        codes = {fixture.__code__: ('fixture', 'fixture'),
                 production.__code__: ('production', 'production')}
        with patch('regression_timing.profile_codes', return_value=codes):
            with editable_profile(self.trace, EDITABLE_TARGET):
                returned = fixture(value)
        self.assertIs(returned, value)
        self.assertIsNone(sys.getprofile())
        record, = self.events()
        self.assertTrue(record['completed'])
        self.assertEqual(record['scope'], 'current-thread-only')
        rows = {row['function']: row for row in record['functions']}
        self.assertEqual(rows['fixture']['calls'], 1)
        self.assertEqual(rows['production']['calls'], 4)
        self.assertEqual(rows['production']['recursive_calls'], 3)
        self.assertGreater(record['categories']['wait']['self_seconds'], 0)
        self.assertGreater(record['categories']['other']['calls'], 0)
        self.assertGreater(rows['fixture']['cumulative_seconds'], rows['fixture']['self_seconds'])
        self.assertLessEqual(sum(row['self_seconds'] for row in record['categories'].values()),
                             record['elapsed_seconds'])
        self.assertEqual(record['omitted_functions'], 0)
        self.assertNotIn('private', self.trace.path.read_text())
        self.assertNotIn(sys.executable, self.trace.path.read_text())

    def test_editable_profile_bounds_rows_and_accounts_for_unlisted_work(self):
        from types import SimpleNamespace
        from regression_timing import PROFILE_LIMIT, profile_summary
        codes, entries = {}, []
        # Distinct code objects, including an unknown dynamically supplied filename/name.
        for index in range(PROFILE_LIMIT + 7):
            code = compile('value = ' + str(index), '/private-' + str(index), 'exec')
            codes[code] = ('fixture', 'fixture.' + str(index))
            entries.append(SimpleNamespace(code=code, callcount=2, reccallcount=0,
                                          inlinetime=float(index), totaltime=float(index + 1), calls=None))
        entries.append(SimpleNamespace(code='private-unknown-builtin', callcount=3,
                                      reccallcount=0, inlinetime=9., totaltime=10., calls=None))
        summary = profile_summary(entries, codes)
        self.assertEqual(len(summary['functions']), PROFILE_LIMIT)
        self.assertEqual(summary['omitted_functions'], 7)
        self.assertEqual(summary['omitted_self_seconds'], sum(range(7)))
        self.assertEqual(summary['categories']['other'], dict(calls=3, functions=1, self_seconds=9.))
        self.assertEqual(sum(row['self_seconds'] for row in summary['functions']) +
                         summary['omitted_self_seconds'], summary['categories']['fixture']['self_seconds'])
        self.assertNotIn('private', json.dumps(summary))

    def test_editable_profile_retains_actual_subprocess_and_file_hash_callers(self):
        from regression_timing import EDITABLE_TARGET, editable_profile, profile_codes
        from ptw.policy import file_sha256
        source = self.directory / 'private-input'
        source.write_bytes(b'private-content')

        def first():
            for _ in range(2):
                self.assertEqual(subprocess.run([sys.executable, '-I', '-c', 'pass'],
                    capture_output=True, check=True).returncode, 0)
                self.assertEqual(file_sha256(source), hashlib.sha256(b'private-content').hexdigest())

        def second():
            return subprocess.run([sys.executable, '-I', '-c', 'raise SystemExit(7)'],
                                  capture_output=True, check=True)

        codes = profile_codes()
        codes.update({first.__code__: ('fixture', 'fixture.first'),
                      second.__code__: ('fixture', 'fixture.second')})
        with patch('regression_timing.profile_codes', return_value=codes):
            with editable_profile(self.trace, EDITABLE_TARGET):
                first()
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                with editable_profile(self.trace, EDITABLE_TARGET):
                    second()
        self.assertEqual(caught.exception.returncode, 7)
        self.assertIsNone(sys.getprofile())
        success, failure = self.events()
        self.assertTrue(success['completed'])
        self.assertFalse(failure['completed'])
        edges = {(row['caller'], row['callee']): row for row in success['caller_edges']}
        for pair in (('fixture.first', 'subprocess.run'),
                     ('fixture.first', 'ptw.policy.file_sha256'),
                     ('ptw.policy.file_sha256', 'hashlib.file_digest'),
                     ('hashlib.file_digest', 'hashlib.update')):
            self.assertEqual(edges[pair]['calls'], 2)
            self.assertEqual(edges[pair]['recursive_calls'], 0)
            self.assertGreaterEqual(edges[pair]['cumulative_seconds'], edges[pair]['self_seconds'])
        failed, = [row for row in failure['caller_edges'] if row['callee'] == 'subprocess.run']
        self.assertEqual((failed['caller'], failed['calls']), ('fixture.second', 1))
        self.assertNotIn('private', self.trace.path.read_text())
        self.assertNotIn(sys.executable, self.trace.path.read_text())

    def test_editable_profile_edges_share_bound_and_collapse_unknown_callers(self):
        from types import SimpleNamespace
        from regression_timing import PROFILE_LIMIT, PROFILE_EDGE_LIMIT, profile_summary
        codes, entries = {}, []
        for index in range(PROFILE_LIMIT + 7):
            code = compile('value = ' + str(index), '/private-' + str(index), 'exec')
            codes[code] = ('fixture', 'fixture.' + str(index))
            call = SimpleNamespace(code="<method 'update' of '_hashlib.HASH' objects>",
                callcount=3, reccallcount=1, inlinetime=float(index), totaltime=float(index + 1))
            entries.append(SimpleNamespace(code=code, callcount=2, reccallcount=0,
                inlinetime=float(index), totaltime=float(index + 1), calls=[call]))
        for index in range(2):
            code = compile('secret = ' + str(index), '/private-caller-' + str(index), 'exec')
            call = SimpleNamespace(code="<method 'update' of '_hashlib.HASH' objects>",
                callcount=4, reccallcount=0, inlinetime=100., totaltime=200.)
            unknown = SimpleNamespace(code='private-builtin', callcount=1,
                reccallcount=0, inlinetime=500., totaltime=500.)
            entries.append(SimpleNamespace(code=code, callcount=1, reccallcount=0,
                inlinetime=1., totaltime=2., calls=[call, unknown]))
        summary = profile_summary(entries, codes)
        self.assertEqual(len(summary['caller_edges']), PROFILE_EDGE_LIMIT)
        self.assertEqual(len(summary['functions']) + len(summary['caller_edges']), PROFILE_LIMIT)
        self.assertEqual(summary['omitted_edges'], len(codes) + 1 - PROFILE_EDGE_LIMIT)
        other, = [row for row in summary['caller_edges'] if row['caller'] == 'other']
        self.assertEqual(other, dict(caller='other', callee='hashlib.update', calls=8,
            recursive_calls=0, self_seconds=200., cumulative_seconds=400.))
        self.assertEqual(sum(row['calls'] for row in summary['caller_edges']) +
                         summary['omitted_edge_calls'], len(codes) * 3 + 8)
        self.assertEqual(sum(row['cumulative_seconds'] for row in summary['caller_edges']) +
                         summary['omitted_edge_cumulative_seconds'], sum(range(1, len(codes) + 1)) + 400.)
        self.assertEqual(sum(row['self_seconds'] for row in summary['functions']) +
                         summary['omitted_self_seconds'], summary['categories']['fixture']['self_seconds'])
        self.assertEqual(summary['categories']['other']['functions'], 2)
        self.assertNotIn('private', json.dumps(summary))
        self.assertEqual(profile_summary([], {}), dict(functions=[], categories={},
            omitted_functions=0, omitted_self_seconds=0, caller_edges=[], omitted_edges=0,
            omitted_edge_calls=0, omitted_edge_cumulative_seconds=0))

    def test_editable_profile_restores_on_errors_interrupts_and_record_failure(self):
        from regression_timing import EDITABLE_TARGET, editable_profile
        for error in (ValueError('private-error'), EOFError('private-eof'),
                      KeyboardInterrupt('private-interrupt'), SystemExit(2)):
            with self.subTest(error=type(error).__name__):
                with self.assertRaises(type(error)) as caught:
                    with editable_profile(self.trace, EDITABLE_TARGET):
                        raise error
                self.assertIs(caught.exception, error)
                self.assertIsNone(sys.getprofile())
                self.assertFalse(self.events()[-1]['completed'])
        self.assertNotIn('private', self.trace.path.read_text())
        with patch.object(self.trace, 'emit', side_effect=OSError('record failure')):
            with self.assertRaises(OSError):
                with editable_profile(self.trace, EDITABLE_TARGET):
                    pass
        self.assertIsNone(sys.getprofile())

    def test_editable_profile_exact_selection_source_labels_and_existing_hook(self):
        from regression_timing import EDITABLE_TARGET, editable_profile, profile_codes
        from ptw import python_runtime
        import test_product_python_local as local
        codes = profile_codes()
        self.assertEqual(codes[python_runtime.identify.__code__],
                         ('production', 'ptw.python_runtime.identify'))
        self.assertEqual(codes[local.CombinedEditableDiscoveryTests.setUp.__code__][0], 'fixture')
        def hook(*args):
            pass
        sys.setprofile(hook)
        try:
            with editable_profile(self.trace, EDITABLE_TARGET + '_other'):
                self.assertIs(sys.getprofile(), hook)
            with self.assertRaisesRegex(RuntimeError, 'unused profiling hook'):
                with editable_profile(self.trace, EDITABLE_TARGET):
                    self.fail('must not replace existing profiler')
            self.assertIs(sys.getprofile(), hook)
        finally:
            sys.setprofile(None)
        self.assertFalse(self.trace.path.exists())

    def test_pressure_counters_keep_only_bounded_numeric_totals(self):
        from regression_timing import pressure_totals
        path = self.directory / 'pressure'
        path.write_bytes(b'some avg10=1.25 total=123\nfull avg10=0.10 total=4\nprivate-extra secret\n')
        self.assertEqual(pressure_totals(path), {
            'status': 'available', 'total_us': {'some': 123, 'full': 4}})
        path.write_bytes(b'some total=0\n')  # System CPU may omit full.
        self.assertEqual(pressure_totals(path)['total_us'], {'some': 0})
        for raw in (b'', b'some total=-1', b'some total=NaN', b'some total=1.2',
                    b'some total=1 total=2', b'some total=1\nsome total=2',
                    b'full total=2', b'some total=\xff', b'x' * 4097):
            with self.subTest(raw=raw[:40]):
                path.write_bytes(raw)
                self.assertEqual(pressure_totals(path), {'status': 'unavailable'})
        path.unlink()
        self.assertEqual(pressure_totals(path), {'status': 'unavailable'})
        with patch.object(Path, 'open', side_effect=PermissionError('private-secret')):
            self.assertEqual(pressure_totals(path), {'status': 'unavailable'})

    def test_cpu_throttle_counters_are_bounded_numeric_and_require_all_fields(self):
        from regression_timing import cpu_throttle_totals
        path = self.directory / 'cpu.stat'
        valid = b'nr_periods 12\nnr_throttled 3\nthrottled_usec 456\n'
        path.write_bytes(valid + b'usage_usec 999\nprivate-field private-secret\n')
        self.assertEqual(cpu_throttle_totals(path), {'status': 'available', 'totals': {
            'nr_periods': 12, 'nr_throttled': 3, 'throttled_usec': 456}})
        path.write_bytes(b'nr_periods 0\nnr_throttled 0\nthrottled_usec 0\n')
        self.assertEqual(cpu_throttle_totals(path)['totals'], {
            'nr_periods': 0, 'nr_throttled': 0, 'throttled_usec': 0})
        invalid = [b'', b'usage_usec 123\n', valid.replace(b'nr_periods 12\n', b''),
                   valid + b'nr_throttled 3\n', b'x' * 4097]
        invalid += [valid.replace(b'throttled_usec 456', b'throttled_usec ' + value)
                    for value in (b'', b'-1', b'+1', b'NaN', b'1.2', b'1 2', b'\xff')]
        for raw in invalid:
            with self.subTest(raw=raw[:80]):
                path.write_bytes(raw)
                self.assertEqual(cpu_throttle_totals(path), {'status': 'unavailable'})
        path.unlink()
        self.assertEqual(cpu_throttle_totals(path), {'status': 'unavailable'})
        with patch.object(Path, 'open', side_effect=PermissionError('private-secret')):
            self.assertEqual(cpu_throttle_totals(path), {'status': 'unavailable'})

    def test_pressure_snapshot_binds_cgroup_without_exporting_paths(self):
        from io import BytesIO
        from regression_timing import pressure_snapshot
        opened = []
        def read(path, mode):
            self.assertEqual(mode, 'rb')
            opened.append(str(path))
            if str(path) == '/proc/self/cgroup':
                return BytesIO(b'0::/private-unit\n')
            if path.name == 'cpu.stat':
                return BytesIO(b'nr_periods 5\nnr_throttled 2\nthrottled_usec 30\n')
            return BytesIO(b'some avg10=0.00 total=21\nfull total=3\n')
        with patch.object(Path, 'open', read):
            result = pressure_snapshot()
        self.assertEqual(opened, ['/proc/pressure/cpu', '/proc/pressure/io', '/proc/self/cgroup',
            '/sys/fs/cgroup/private-unit/cpu.pressure', '/sys/fs/cgroup/private-unit/io.pressure',
            '/sys/fs/cgroup/private-unit/cpu.stat'])
        self.assertEqual(result['cgroup_id'], hashlib.sha256(b'/private-unit').hexdigest())
        for scope in ('system', 'cgroup'):
            self.assertEqual(set(result[scope]), {'cpu', 'io'} if scope == 'system' else
                             {'cpu', 'io', 'cpu_stat'})
            self.assertEqual(result[scope]['io']['total_us'], {'some': 21, 'full': 3})
        self.assertEqual(result['cgroup']['cpu_stat'], {'status': 'available', 'totals': {
            'nr_periods': 5, 'nr_throttled': 2, 'throttled_usec': 30}})
        self.assertNotIn('private-', json.dumps(result))
        self.assertNotIn('/proc', json.dumps(result))

    def test_unavailable_cpu_stat_preserves_pressure_and_group_identity(self):
        from io import BytesIO
        from regression_timing import pressure_snapshot
        def read(path, mode):
            if str(path) == '/proc/self/cgroup':
                return BytesIO(b'0::/private-unit\n')
            if path.name == 'cpu.stat':
                raise PermissionError('private-secret')
            return BytesIO(b'some total=2\n')
        with patch.object(Path, 'open', read):
            result = pressure_snapshot()
        self.assertEqual(result['cgroup']['cpu_stat'], {'status': 'unavailable'})
        self.assertEqual(result['cgroup']['cpu']['total_us'], {'some': 2})
        self.assertEqual(result['cgroup_id'], hashlib.sha256(b'/private-unit').hexdigest())
        self.assertNotIn('private-', json.dumps(result))

    def test_pressure_missing_invalid_or_denied_membership_does_not_escape(self):
        from io import BytesIO
        from regression_timing import pressure_snapshot
        for membership in (b'', b'1:cpu:/private', b'0::/../private', b'0::/a\n0::/b',
                           b'0::/\xff', b'x' * 4097, PermissionError('private-denied')):
            with self.subTest(membership=str(membership)[:40]):
                opened = []
                def read(path, mode):
                    opened.append(str(path))
                    if str(path) == '/proc/self/cgroup':
                        if isinstance(membership, Exception):
                            raise membership
                        return BytesIO(membership)
                    return BytesIO(b'some total=0')
                with patch.object(Path, 'open', read):
                    result = pressure_snapshot()
                self.assertEqual(result['cgroup'], {'status': 'unavailable'})
                self.assertNotIn('cgroup_id', result)
                self.assertEqual(len(opened), 3)
                self.assertNotIn('private', json.dumps(result))

    def test_pressure_sampling_is_only_at_suite_and_selected_test_boundaries(self):
        from regression_timing import EDITABLE_TARGET, POETRY_TARGET
        snapshot = {'system': {'cpu': {'status': 'unavailable'}}}
        with patch('regression_timing.pressure_snapshot', return_value=snapshot) as read:
            for target in (EDITABLE_TARGET, POETRY_TARGET):
                with self.assertRaisesRegex(EOFError, 'private-original'):
                    with self.trace.span('test', target):
                        with self.trace.span('phase', target + ':nested'):
                            raise EOFError('private-original')
            with self.trace.span('test', EDITABLE_TARGET + '_other'):
                pass
            with self.assertRaises(KeyboardInterrupt):
                with self.trace.span('suite', 'unittest'):
                    self.trace.emit(kind='suite', event='sample', name='unittest')
                    raise KeyboardInterrupt('private-interruption')
        self.assertEqual(read.call_count, 6)
        events = self.events()
        selected = [e for e in events if 'pressure' in e]
        self.assertEqual(len(selected), 6)
        self.assertEqual([e['event'] for e in selected], ['start', 'end'] * 3)
        self.assertTrue(all(e['pressure'] == snapshot for e in selected))
        self.assertEqual([e['kind'] for e in selected], ['test'] * 4 + ['suite'] * 2)
        self.assertEqual([e['outcome'] for e in selected if e['event'] == 'end'],
                         ['error', 'error', 'interrupted'])
        self.assertNotIn('private-', self.trace.path.read_text())

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
                        'cpu_children_user', 'cpu_children_system',
                        *(scope + '_' + name for scope in ('self', 'children')
                          for name in ('ru_inblock', 'ru_oublock', 'ru_minflt', 'ru_majflt',
                                       'ru_nvcsw', 'ru_nivcsw'))):
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

    def test_poetry_phases_preserve_native_wait_and_both_integrity_checks(self):
        from types import SimpleNamespace
        from regression_timing import POETRY_TARGET, Trace, poetry_phases
        from ptw import poetry_tool
        for mode in ('success', 'pre-tamper', 'post-tamper', 'timeout', 'interrupted'):
            with self.subTest(mode=mode):
                root = self.directory / mode
                payload = root / 'payload'
                payload.mkdir(parents=True)
                source = payload / 'tool.py'
                source.write_text('private-payload')
                lock = root / 'tools.lock'
                lock.write_text('private-lock')
                runtime = {'executable': '/usr/bin/python3'}
                (root / 'tool.json').write_text(json.dumps({
                    'outcome': 'ready', 'pins': poetry_tool.PINS, 'runtime': runtime,
                    'files': poetry_tool.payload(payload),
                    'lock_sha256': hashlib.sha256(lock.read_bytes()).hexdigest()}))
                if mode == 'pre-tamper':
                    source.write_text('changed')
                self.trace = Trace(root)
                result = subprocess.CompletedProcess(['private-command'], 7,
                                                     'private-output', 'private-error')
                error = (subprocess.TimeoutExpired('private-command', 1) if mode == 'timeout'
                         else KeyboardInterrupt('private-interruption'))
                calls = []

                def wait(*args, **kwargs):
                    calls.append((args, kwargs))
                    if mode in ('timeout', 'interrupted'):
                        raise error
                    if mode == 'post-tamper':
                        source.write_text('changed')
                    return result

                with patch.object(poetry_tool, 'identify', return_value=runtime) as identify, \
                     patch('ptw.supervisor.runtime_namespace', return_value=['fixture-boundary']), \
                     patch.object(poetry_tool, 'subprocess', SimpleNamespace(run=wait)):
                    originals = {name: getattr(poetry_tool, name) for name in
                                 ('verified', 'payload', 'identify', 'run', 'subprocess')}
                    ambient_run = subprocess.run
                    with poetry_phases(self.trace, POETRY_TARGET):
                        self.assertIs(subprocess.run, ambient_run)
                        call = lambda: poetry_tool.run('private-script', {'key': 'private-config'},
                                                       cwd=root, timeout=23, directory=root)
                        if mode == 'success':
                            self.assertIs(call(), result)  # Nonzero exits are not rewritten.
                        elif mode in ('pre-tamper', 'post-tamper'):
                            with self.assertRaises(Invalid):
                                call()
                        else:
                            with self.assertRaises(type(error)) as caught:
                                call()
                            self.assertIs(caught.exception, error)
                    for name, original in originals.items():
                        self.assertIs(getattr(poetry_tool, name), original)
                    self.assertEqual(identify.call_count, 0 if mode == 'pre-tamper' else
                                     2 if mode == 'success' else 1)
                self.assertEqual(len(calls), 0 if mode == 'pre-tamper' else 1)
                if calls:
                    args, kwargs = calls[0]
                    self.assertEqual(len(args), 1)
                    self.assertEqual(args[0][0], 'fixture-boundary')
                    self.assertTrue(args[0][-2].endswith('private-script'))
                    self.assertEqual(json.loads(args[0][-1]), {'key': 'private-config'})
                    self.assertEqual(kwargs, {'capture_output': True, 'text': True,
                                             'timeout': 23, 'env': {'PATH': '/usr/bin:/bin'}})
                events = self.events()
                starts = [e['name'].split(':ptw.poetry_tool.')[1]
                          for e in events if e['event'] == 'start']
                expected = ['run', 'verified', 'payload']
                if mode != 'pre-tamper':
                    expected += ['identify', 'subprocess.run']
                if mode in ('success', 'post-tamper'):
                    expected += ['verified', 'payload']
                if mode == 'success':
                    expected += ['identify']
                self.assertEqual(starts, expected)
                # Every nested phase unwinds in order, including failed waits.
                pending = []
                for event in events:
                    if event['event'] == 'start':
                        pending.append(event['span'])
                    elif event['event'] == 'end':
                        self.assertEqual(pending.pop(), event['span'])
                self.assertEqual(pending, [])
                self.assertEqual(events[-1]['outcome'], 'completed' if mode == 'success' else
                                 'interrupted' if mode == 'interrupted' else 'error')
                self.assertNotIn('private-', self.trace.path.read_text())

    def test_poetry_child_clocks_preserve_script_outputs_arguments_and_exit(self):
        from regression_timing import POETRY_TARGET, poetry_wait
        wait = poetry_wait(self.trace, POETRY_TARGET, subprocess.run)
        for mode, exit_code in (('success', 0), ('exit', 7), ('error', 1), ('abrupt', 9)):
            with self.subTest(mode=mode):
                script = ('import os,sys,json\n'
                    'print(json.dumps([sys.argv, __name__]))\n'
                    'sys.stderr.write("private-error-without-newline"); sys.stderr.flush()\n'
                    + {'success': '', 'exit': 'raise SystemExit(7)',
                       'error': 'raise ValueError("private-failure")',
                       'abrupt': 'os._exit(9)'}[mode])
                command = [sys.executable, '-I', '-S', '-B', '-c', script, 'private-config']
                result = wait(command, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.args, command)
                self.assertEqual(result.returncode, exit_code)
                if mode != 'abrupt':
                    self.assertEqual(json.loads(result.stdout), [['-c', 'private-config'], '__main__'])
                if mode == 'error':
                    self.assertIn('ValueError: private-failure', result.stderr)
                else:
                    self.assertEqual(result.stderr, 'private-error-without-newline')
                self.assertNotIn('PTW-CLOCK', result.stderr)
                rows = self.events()[-3:]
                start, child, end = rows
                self.assertEqual(start['call'], child['call'])
                self.assertEqual(start['call'], end['call'])
                self.assertEqual(child['status'], 'incomplete' if mode == 'abrupt' else 'complete')
                self.assertEqual([s['event'] for s in child['samples']],
                                 ['start'] if mode == 'abrupt' else ['start', 'end'])
                for sample in child['samples']:
                    self.assertLessEqual(start['monotonic_ns'], sample['monotonic_ns'])
                    self.assertLessEqual(sample['monotonic_ns'], end['monotonic_ns'])
                    self.assertGreater(sample['cpu_self_ns'], 0)
        self.assertNotIn('private-', self.trace.path.read_text())

    def test_poetry_child_missing_invalid_and_duplicate_samples_stay_incomplete(self):
        from regression_timing import POETRY_TARGET, poetry_wait
        # Exercise the real injected child code, then alter only its diagnostic
        # frames at the substituted wait boundary. Product outputs stay intact.
        import re
        pattern = re.compile(r'\x1ePTW-CLOCK-[0-9]+-[0-9]+:(?:start|end):[0-9]+:[0-9]+\x1f')
        command = [sys.executable, '-I', '-S', '-B', '-c',
                   'import sys; sys.stderr.write("private-output")', 'private-config']
        for mode in ('missing', 'duplicate', 'reversed', 'invalid', 'malformed-extra', 'decreasing'):
            with self.subTest(mode=mode):
                def run(copied, **kwargs):
                    result = subprocess.run(copied, **kwargs)
                    frames = pattern.findall(result.stderr)
                    self.assertEqual(len(frames), 2)
                    replacement = {'missing': '', 'duplicate': ''.join(frames * 2),
                        'reversed': ''.join(reversed(frames)),
                        'invalid': frames[0].replace(':start:', ':private-invalid:'),
                        'malformed-extra': ''.join(frames) + frames[0].replace(':start:', ':private-invalid:'),
                        'decreasing': frames[0] + re.sub(r':end:[0-9]+:[0-9]+', ':end:0:0', frames[1])}[mode]
                    result.stderr = 'private-output' + replacement
                    return result
                result = poetry_wait(self.trace, POETRY_TARGET, run)(
                    command, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0)
                self.assertTrue(result.stderr.startswith('private-output'))
                self.assertEqual(self.events()[-2]['status'], 'incomplete')
                self.assertLessEqual(len(self.events()[-2]['samples']), 3)
        self.assertNotIn('private-', self.trace.path.read_text())

    def test_poetry_child_operation_ids_use_only_known_scripts(self):
        from regression_timing import POETRY_TARGET, poetry_wait
        from ptw.poetry_export import EXPORT, INSPECT
        from ptw.poetry_resolution import SOLVE
        from ptw.poetry_revision import EDIT
        for name, script in (('inspect', INSPECT), ('export', EXPORT), ('solve', SOLVE),
                             ('edit', EDIT), ('other', 'private-script')):
            command = [sys.executable, '-I', '-S', '-B', '-c',
                       'import sys; sys.path.insert(0,"/poetry-tools");\n' + script, 'private-config']
            def run(copied, **kwargs):
                self.assertEqual(copied[:-2], command[:-2])
                self.assertTrue(copied[-2].endswith(command[-2]))
                self.assertEqual(copied[-1], command[-1])
                return subprocess.CompletedProcess(copied, 2, '', '')
            self.assertEqual(poetry_wait(self.trace, POETRY_TARGET, run)(command).returncode, 2)
            self.assertEqual([row['operation'] for row in self.events()[-3:]], [name] * 3)
            self.assertEqual(self.events()[-2]['status'], 'incomplete')
        self.assertNotIn('private-', self.trace.path.read_text())

    def test_poetry_child_timeout_bytes_and_changed_boundary_preserve_failure(self):
        from regression_timing import POETRY_TARGET, poetry_wait
        command = [sys.executable, '-I', '-S', '-B', '-c', 'pass', 'private-config']
        original_error = subprocess.TimeoutExpired(command, 23, output=b'private-stdout')
        def timeout(copied, **kwargs):
            result = subprocess.run(copied, capture_output=True, timeout=10)
            # An actual TimeoutExpired can retain bytes even with text=True.
            original_error.stderr = b'private-stderr' + result.stderr
            raise original_error
        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            poetry_wait(self.trace, POETRY_TARGET, timeout)(command, timeout=23, text=True)
        self.assertIs(caught.exception, original_error)
        self.assertEqual(original_error.cmd, command)
        self.assertEqual(original_error.output, b'private-stdout')
        self.assertEqual(original_error.stderr, b'private-stderr')
        self.assertEqual(self.events()[-1]['outcome'], 'error')
        with patch('subprocess.run') as native:
            with self.assertRaisesRegex(ValueError, 'command shape changed'):
                poetry_wait(self.trace, POETRY_TARGET, native)(['other-command'])
            native.assert_not_called()
        self.assertEqual(self.events()[-2]['status'], 'incomplete')
        self.assertNotIn('private-', self.trace.path.read_text())

    def test_poetry_phase_selection_is_exact_and_integrated_with_runner(self):
        from regression_timing import POETRY_TARGET, instrument, poetry_phases
        from ptw import poetry_tool
        with patch.object(poetry_tool, 'verified', return_value='unchanged') as original:
            with poetry_phases(self.trace, POETRY_TARGET + '_other'):
                self.assertIs(poetry_tool.verified, original)
            self.assertFalse(self.trace.path.exists())

            class Fixture(unittest.TestCase):
                def runTest(self):
                    self.assertEqual(poetry_tool.verified(directory='private-directory'), 'unchanged')

                def id(self):
                    return POETRY_TARGET

            result = unittest.TestResult()
            suite = unittest.TestSuite([Fixture()])
            with instrument(suite, result, self.trace):
                suite.run(result)
            self.assertTrue(result.wasSuccessful(), result.errors)
            self.assertEqual(result.testsRun, 1)
            self.assertIs(poetry_tool.verified, original)
            original.assert_called_once_with(directory='private-directory')
        self.assertEqual(sum(e['kind'] == 'phase' and e['event'] == 'start'
                             for e in self.events()), 1)
        self.assertNotIn('private-', self.trace.path.read_text())

    def test_editable_phases_forward_nested_calls_and_restore(self):
        from regression_timing import EDITABLE_TARGET, Trace, editable_phases
        from ptw import onboarding, policy, python_runtime
        from ptw.store import Store
        for error in (None, Invalid('private-rejection'), EOFError('private-eof'),
                      KeyboardInterrupt('private-interruption')):
            with self.subTest(error=type(error).__name__):
                directory = self.directory / type(error).__name__
                directory.mkdir()
                self.trace = Trace(directory)
                value = object()

                def compile_policy(*args, **kwargs):
                    return python_runtime.identify(*args, **kwargs)

                def setup(*args, **kwargs):
                    self.assertIs(onboarding.compile_policy(*args, **kwargs), value)
                    self.assertIs(policy.compile_policy(*args, **kwargs), value)
                    if error is not None:
                        raise error
                    return value

                with patch.object(onboarding, 'setup', side_effect=setup) as original_setup, \
                     patch.object(onboarding, 'compile_policy', side_effect=compile_policy) as alias, \
                     patch.object(policy, 'compile_policy', side_effect=compile_policy) as original_compile, \
                     patch.object(python_runtime, 'identify', return_value=value) as identify:
                    originals = [(onboarding, 'setup', original_setup),
                                 (onboarding, 'compile_policy', alias),
                                 (policy, 'compile_policy', original_compile),
                                 (python_runtime, 'identify', identify), (Store, 'locked', Store.locked)]
                    try:
                        with editable_phases(self.trace, EDITABLE_TARGET):
                            returned = onboarding.setup('private-input', option='private-option')
                    except BaseException as caught:
                        self.assertIs(caught, error)
                    else:
                        self.assertIsNone(error)
                        self.assertIs(returned, value)
                    for owner, name, original in originals:
                        self.assertIs(getattr(owner, name), original)
                    for original in (original_setup, alias, original_compile):
                        original.assert_called_once_with('private-input', option='private-option')
                    self.assertEqual(identify.call_args_list,
                        [unittest.mock.call('private-input', option='private-option')] * 2)
                events = self.events()
                self.assertEqual([e['name'].split(':')[1] for e in events if e['event'] == 'start'],
                    ['ptw.onboarding.setup', 'ptw.onboarding.compile_policy',
                     'ptw.python_runtime.identify', 'ptw.policy.compile_policy',
                     'ptw.python_runtime.identify'])
                pending = []
                for event in events:
                    if event['event'] == 'start':
                        pending.append(event['span'])
                    else:
                        self.assertEqual(pending.pop(), event['span'])
                self.assertEqual(pending, [])
                self.assertEqual(events[-1]['outcome'], 'completed' if error is None else
                    'interrupted' if isinstance(error, KeyboardInterrupt) else 'error')
                self.assertNotIn('private-', self.trace.path.read_text())

    def test_editable_runtime_callers_separate_selection_verification_and_failure(self):
        from regression_timing import EDITABLE_TARGET, editable_phases
        from ptw import python_runtime
        identity = {'executable': '/usr/bin/python3', 'version': '3.12.0',
                    'sha256': 'private-digest', 'implementation': 'cpython',
                    'abi': 'private-abi', 'prefix': '/usr'}
        runtime = {**identity, 'requires_python': '>=3.11'}
        interrupted = KeyboardInterrupt('private-interruption')
        with patch.object(python_runtime, 'identify', return_value=identity) as original:
            with editable_phases(self.trace, EDITABLE_TARGET):
                self.assertEqual(python_runtime.select('>=3.11', executable='/usr/bin/python3'), runtime)
                self.assertEqual(python_runtime.verify(runtime), '/usr/bin/python3')
                original.return_value = {**identity, 'sha256': 'private-changed'}
                with self.assertRaisesRegex(Invalid, 'runtime changed'):
                    python_runtime.verify(runtime)
                original.side_effect = Invalid('private-unavailable')
                with self.assertRaisesRegex(Invalid, 'Selected Python is unavailable'):
                    python_runtime.select(executable='/usr/bin/python3')
                original.side_effect = interrupted
                with self.assertRaises(KeyboardInterrupt) as caught:
                    python_runtime.verify(runtime)
                self.assertIs(caught.exception, interrupted)
            self.assertIs(python_runtime.identify, original)
            self.assertEqual(original.call_args_list, [unittest.mock.call('/usr/bin/python3')] * 5)
        events = self.events()
        starts = [e for e in events if e['event'] == 'start']
        ends = [e for e in events if e['event'] == 'end']
        self.assertEqual(len(starts), 5)
        self.assertEqual([e['callers'][0]['function'] for e in starts],
                         ['ptw.python_runtime.' + name for name in
                          ('select', 'verify', 'verify', 'select', 'verify')])
        # The mismatch is raised by verify after identify returns; this span
        # must not misreport successful identification as failed verification.
        self.assertEqual([e['outcome'] for e in ends],
                         ['completed', 'completed', 'completed', 'error', 'interrupted'])
        for start, end in zip(starts, ends):
            self.assertEqual(start['callers'], end['callers'])
            self.assertFalse(start['caller_scan_truncated'])
            self.assertGreater(end['monotonic_ns'], start['monotonic_ns'])
            self.assertTrue(all(type(c['line']) is int and c['line'] > 0 for c in start['callers']))
        self.assertNotIn('private-', self.trace.path.read_text())
        self.assertNotIn('/usr/bin/python3', self.trace.path.read_text())

    def test_runtime_caller_trace_is_bounded_and_ignores_unlisted_frames(self):
        from regression_timing import caller_fields

        def unlisted(private_value):
            return caller_fields(codes)

        def selected():
            first = unlisted('private-first')
            second = unlisted('private-second')
            return first, second

        codes = {selected.__code__: 'selected'}
        first, second = selected()
        self.assertEqual([c['function'] for c in first['callers']], ['selected'])
        self.assertEqual([c['function'] for c in second['callers']], ['selected'])
        self.assertNotEqual(first['callers'][0]['line'], second['callers'][0]['line'])
        self.assertFalse(first['caller_scan_truncated'])
        self.assertEqual(caller_fields({})['callers'], [])

        def recursive(depth):
            return recursive(depth - 1) if depth else caller_fields(codes)

        codes = {recursive.__code__: 'recursive'}
        bounded = recursive(40)
        self.assertTrue(bounded['caller_scan_truncated'])
        self.assertEqual(len(bounded['callers']), 32)
        self.assertEqual({c['function'] for c in bounded['callers']}, {'recursive'})
        self.assertNotIn('private-', json.dumps([first, second, bounded]))

    def test_editable_lock_preserves_entry_exit_errors_and_suppression(self):
        from regression_timing import EDITABLE_TARGET, Trace, editable_phases
        from ptw.store import Store
        # Entry errors must not call exit. Body exceptions must reach exit with
        # their original traceback; exit can suppress them or replace them.
        for mode in ('normal', 'entry', 'body', 'exit', 'replace', 'suppress', 'interrupt'):
            with self.subTest(mode=mode):
                directory = self.directory / mode
                directory.mkdir()
                self.trace = Trace(directory)
                calls = []
                value = object()
                error = (KeyboardInterrupt('private-interruption') if mode == 'interrupt'
                         else Invalid('private-lock'))
                exit_error = EOFError('private-exit')

                class Manager:
                    def __enter__(self):
                        calls.append('enter')
                        if mode == 'entry':
                            raise error
                        return value

                    def __exit__(self, *exc):
                        calls.append(exc)
                        if mode in ('exit', 'replace'):
                            raise exit_error
                        return mode == 'suppress'

                manager = Manager()
                actor = object.__new__(Store)

                def original_locked(instance, *args, **kwargs):
                    self.assertIs(instance, actor)
                    self.assertEqual(args, ('private-argument',))
                    self.assertEqual(kwargs, {'option': 'private-option'})
                    return manager

                with patch.object(Store, 'locked', original_locked):
                    expected = (exit_error if mode in ('exit', 'replace') else
                                error if mode in ('entry', 'body', 'interrupt') else None)
                    try:
                        with editable_phases(self.trace, EDITABLE_TARGET):
                            with actor.locked('private-argument', option='private-option') as entered:
                                self.assertIs(entered, value)
                                if mode in ('body', 'replace', 'suppress', 'interrupt'):
                                    raise error
                    except BaseException as caught:
                        self.assertIs(caught, expected)
                    else:
                        self.assertIsNone(expected)
                    self.assertIs(Store.locked, original_locked)
                self.assertEqual(calls[0], 'enter')
                self.assertEqual(len(calls), 1 if mode == 'entry' else 2)
                if mode in ('body', 'replace', 'suppress', 'interrupt'):
                    kind, caught, traceback = calls[1]
                    self.assertIs(kind, type(error))
                    self.assertIs(caught, error)
                    self.assertIs(traceback, error.__traceback__)
                elif mode != 'entry':
                    self.assertEqual(calls[1], (None, None, None))
                ends = [e for e in self.events() if e['event'] == 'end']
                self.assertEqual([e['name'].rsplit('.', 1)[1] for e in ends],
                                 ['enter'] if mode == 'entry' else ['enter', 'exit'])
                self.assertEqual([e['outcome'] for e in ends], ['error'] if mode == 'entry' else
                                 ['completed', 'error' if mode in ('exit', 'replace') else 'completed'])
                self.assertNotIn('private-', self.trace.path.read_text())

    def test_editable_phase_selection_is_exact_and_integrated_with_runner(self):
        from regression_timing import EDITABLE_TARGET, editable_phases, instrument
        from ptw import onboarding, policy, python_runtime
        from ptw.store import Store
        with patch.object(onboarding, 'setup', return_value='unchanged') as original:
            targets = ((onboarding, 'setup'), (onboarding, 'compile_policy'),
                       (policy, 'compile_policy'), (python_runtime, 'identify'), (Store, 'locked'))
            originals = [getattr(owner, name) for owner, name in targets]
            with editable_phases(self.trace, EDITABLE_TARGET + '_other'):
                self.assertEqual([getattr(owner, name) for owner, name in targets], originals)
                self.assertEqual(onboarding.setup('private-other'), 'unchanged')
            self.assertFalse(self.trace.path.exists())

            class Fixture(unittest.TestCase):
                def runTest(self):
                    self.assertEqual(onboarding.setup('private-input'), 'unchanged')

                def id(self):
                    return EDITABLE_TARGET

            result = unittest.TestResult()
            suite = unittest.TestSuite([Fixture()])
            with instrument(suite, result, self.trace):
                suite.run(result)
            self.assertTrue(result.wasSuccessful(), result.errors)
            self.assertEqual(result.testsRun, 1)
            self.assertEqual([getattr(owner, name) for owner, name in targets], originals)
            self.assertEqual(original.call_args_list,
                             [unittest.mock.call('private-other'), unittest.mock.call('private-input')])
        self.assertEqual(sum(e['kind'] == 'phase' and e['event'] == 'start' for e in self.events()), 1)
        self.assertEqual(sum(e['kind'] == 'profile' and e['name'] == EDITABLE_TARGET
                             for e in self.events()), 1)
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
        script = ('import io, os, sys, unittest\n'
                  'sys.path.insert(0, ' + repr(str(Path(__file__).parent)) + ')\n'
                  'from regression_timing import enable\n'
                  'os.environ["PTW_LINUX_TESTS"] = "1"\n'
                  'enable()\nenable()\n'
                  'class Nested(unittest.TestCase):\n'
                  '    def runTest(self): pass\n'
                  'class Fixture(unittest.TestCase):\n'
                  '    def test_ok(self):\n'
                  '        result = unittest.TextTestRunner(stream=io.StringIO()).run(unittest.TestSuite([Nested()]))\n'
                  '        assert result.wasSuccessful()\n'
                  'suite = unittest.defaultTestLoader.loadTestsFromTestCase(Fixture)\n'
                  'result = unittest.TextTestRunner().run(suite)\n'
                  'assert result.wasSuccessful() and result.testsRun == 1\n')
        env = dict(os.environ, TMPDIR=str(self.directory), XDG_STATE_HOME=str(self.directory / 'state'))
        result = subprocess.run([sys.executable, '-B', '-c', script], env=env,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count('REGRESSION_TIMING_EVIDENCE '), 1)
        self.assertEqual(result.stdout.count('NATIVE_SUITE_EVIDENCE '), 1)
        receipts = list((self.directory / 'state').rglob('complete.json'))
        self.assertEqual(len(receipts), 1)
        receipt = json.loads(receipts[0].read_text())
        self.assertTrue(receipt['passed'])
        self.assertEqual(receipt['tests_run'], 1)
        self.assertEqual(receipt['inventory'], ['__main__.Fixture.test_ok'])
        self.assertEqual((receipts[0].parent / 'unittest.log').read_text(), result.stderr)
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
        snapshots = [e for e in events if 'pressure' in e]
        self.assertEqual([(e['kind'], e['event']) for e in snapshots],
                         [('suite', 'start'), ('suite', 'end')])
        for event in snapshots:
            pressure = event['pressure']
            self.assertIn('system', pressure)
            if 'cgroup_id' in pressure:
                self.assertIn(pressure['cgroup']['cpu_stat']['status'], ('available', 'unavailable'))
            else:
                self.assertEqual(pressure['cgroup'], {'status': 'unavailable'})


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
                            set(), file_manifest(site), {}, [self.evidence], preparation_sessions=[])
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


def assert_quarantine_stop(case, observation):
    """Require targeted quarantine receipts and physical stop before natural exit."""
    elapsed = observation['stopped_monotonic'] - observation['started_monotonic']
    case.assertGreaterEqual(elapsed, 0)
    case.assertLess(elapsed, 60, 'Command could have completed its 60-second payload naturally')
    for unit in (observation['command_unit'], observation['preview_unit']):
        case.assertEqual(observation['before'][unit]['ActiveState'], 'active')
        case.assertIs(observation['after'][unit]['confirmed_stopped'], True)
        case.assertTrue(any(
            row['unit'] == unit and
            row['at'] >= observation['quarantine_requested_epoch'] and
            json.loads(row['outcome']).get('confirmed_stopped') is True
            for row in observation['package_terminations']),
            'Missing confirmed quarantine termination for ' + unit)


class QuarantineStopOracleTests(unittest.TestCase):
    def observation(self):
        # Synthetic oracle inputs only; physical evidence comes from the native test.
        units = ('command', 'preview')
        return {'command_unit': units[0], 'preview_unit': units[1],
                'started_monotonic': 10, 'stopped_monotonic': 15,
                'quarantine_requested_epoch': 100,
                'before': {u: {'ActiveState': 'active'} for u in units},
                'after': {u: {'confirmed_stopped': True} for u in units},
                'package_terminations': [
                    {'unit': u, 'at': 101, 'outcome': canonical({'confirmed_stopped': True})}
                    for u in units]}

    def test_confirmed_targeted_stop_before_payload_completion(self):
        assert_quarantine_stop(self, self.observation())

    def test_natural_completion_cannot_prove_quarantine_stop(self):
        for elapsed in (60, 61):
            with self.subTest(elapsed=elapsed):
                observation = self.observation()
                observation['stopped_monotonic'] = observation['started_monotonic'] + elapsed
                with self.assertRaisesRegex(AssertionError, 'naturally'):
                    assert_quarantine_stop(self, observation)

    def test_missing_wrong_stale_or_unconfirmed_termination_is_rejected(self):
        for target in ('command', 'preview'):
            for defect in ('missing', 'wrong-unit', 'stale', 'unconfirmed'):
                with self.subTest(target=target, defect=defect):
                    observation = self.observation()
                    row = next(r for r in observation['package_terminations'] if r['unit'] == target)
                    if defect == 'missing':
                        observation['package_terminations'].remove(row)
                    elif defect == 'wrong-unit':
                        row['unit'] = 'unrelated'
                    elif defect == 'stale':
                        row['at'] = 99
                    else:
                        row['outcome'] = canonical({'confirmed_stopped': False})
                    with self.assertRaisesRegex(AssertionError, 'Missing confirmed quarantine'):
                        assert_quarantine_stop(self, observation)

    def test_receipt_without_active_then_physically_stopped_work_is_rejected(self):
        for target in ('command', 'preview'):
            for phase in ('before', 'after'):
                with self.subTest(target=target, phase=phase):
                    observation = self.observation()
                    observation[phase][target] = {'ActiveState': 'inactive', 'confirmed_stopped': False}
                    with self.assertRaises(AssertionError):
                        assert_quarantine_stop(self, observation)


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
        # This fixture needs concurrent admission, not the separately tested
        # serialization of colliding leases. Keep real session registration.
        slow_slot = operation_lease(self.actor['session'], 'slow')
        critical_event = next('critical-use-' + str(i) for i in range(10000)
            if operation_lease(self.actor['session'], 'critical-use-' + str(i)) != slow_slot)
        self.assertNotEqual(slow_slot, operation_lease(self.actor['session'], critical_event))
        observation = {'slow_event': 'slow', 'critical_event': critical_event,
                       'slow_slot': slow_slot,
                       'critical_slot': operation_lease(self.actor['session'], critical_event),
                       'preview_unit': preview['unit']}
        self.addCleanup(save, self.evidence_directory / 'stop.json', observation)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            observation['started_monotonic'] = time.monotonic()
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
            self.assertEqual(len(units), 1, 'Expected exactly one active bound command')
            observation['command_unit'] = units[0]
            observation['before'] = {u: Supervisor.state(u) for u in (units[0], preview['unit'])}
            self.assertFalse(running.done(), 'Command finished before quarantine request')
            for state in observation['before'].values():
                self.assertEqual(state['ActiveState'], 'active')
            with self.store.locked() as db:
                row = db.execute('SELECT evidence FROM package_sets WHERE id=?', (package,)).fetchone()
                evidence = json.loads(row[0])
                for record in evidence:
                    record['checked_at'] -= 1000
                db.execute('UPDATE package_sets SET evidence=? WHERE id=?', (canonical(evidence), package))
            advisory = AdvisoryFixture({('six', '1.17.0'): [CRITICAL]})
            observation['quarantine_requested_epoch'] = time.time()
            with patch('ptw.registry.provider_for', return_value=advisory):
                denied = action(critical_event, 'use')
            self.assertFalse(denied['allowed'], denied)
            self.assertIn('quarantined', denied['reason'])
            self.assertFalse(running.result(timeout=15)['allowed'])
            observation['after'] = {u: Supervisor.state(u) for u in (units[0], preview['unit'])}
            observation['stopped_monotonic'] = time.monotonic()
            observation['package_terminations'] = self.store.status('python-demo')['package_terminations']
            assert_quarantine_stop(self, observation)
        self.assertFalse((repo / 'dist/late').exists())
        self.assertTrue(Supervisor.state(preview['unit'])['confirmed_stopped'])
        self.assertTrue(all(Supervisor.state(u)['confirmed_stopped'] for u in units))
        self.assertEqual(self.store.status('python-demo')['violations'], 0)
        self.assertEqual(provider.downloads, 1, 'Reassessment must never download artifacts')
