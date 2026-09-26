"""Bounded fixture ownership checks. Native effects are deterministic, not model work."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import product_fixture_lifecycle as lifetime
from ptw import monitor
from ptw.policy import approve, compile_policy, digest, load, save
from ptw.project_example import create
from ptw.store import Store
from ptw.supervisor import Supervisor


def controller(root):
    create(root / 'example', 'python')
    policy, inventory = load(root / 'example/policy.json'), load(root / 'example/inventory.json')
    store = Store(root / 'state')
    store.activate(approve(policy, inventory, digest(compile_policy(policy, inventory)), 'fixture owner'))
    return store


def partial_setup():
    """Exercise the real installed-safety fixture owners, failing after acquisition."""
    import test_product_artifact_review as artifacts
    import test_product_sequence_review as sequence
    paths = []
    for cls in (artifacts.NativeArtifactTests, sequence.NativeSequenceTests):
        case = cls('runTest')
        ensure = monitor.ensure
        acquired = []

        def fail(store):
            ensure(store)
            acquired.append(store)
            deadline = time.monotonic() + 10
            while not (store.directory / 'monitor-identity.json').is_file():
                if time.monotonic() >= deadline:
                    raise AssertionError('Native monitor identity was not recorded')
                time.sleep(.02)
            raise RuntimeError('injected setup interruption after native acquisition')

        try:
            with patch.object(monitor, 'ensure', side_effect=fail):
                try:
                    case.setUp()
                except RuntimeError as exc:
                    if str(exc) != 'injected setup interruption after native acquisition':
                        raise
                else:
                    raise AssertionError('Setup failure was not injected')
        finally:
            if not case.doCleanups():
                raise AssertionError('Native fixture setup cleanup failed')
        if len(acquired) != 1:
            raise AssertionError('Setup did not acquire exactly one native monitor')
        store = acquired[0]
        if lifetime.unit_path(store.directory).exists() or not store.status('python-demo')['stopped']:
            raise AssertionError('Partial setup leaked its monitor or project')
        if not store.db.is_file():
            raise AssertionError('Native evidence was deleted')
        identity = load(store.directory / 'monitor-identity.json') if (store.directory / 'monitor-identity.json').exists() else None
        paths.append({'state': str(store.directory), 'identity': identity})
    return paths


class CleanupFailureTests(unittest.TestCase):
    """Fault injection at external boundaries; these are not native stop evidence."""
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='ptw-fixture-fault-'))
        self.addCleanup(shutil.rmtree, self.root)
        self.store = controller(self.root)

    def offline_directory(self):
        directory = lifetime.FixtureDirectory(prefix='ptw-fixture-offline-')
        # Independent fallback also removes protected test data on assertion failure.
        self.addCleanup(tempfile.TemporaryDirectory._rmtree, directory.name)
        return directory, Path(directory.name)

    def test_offline_cleanup_removes_ordinary_and_readonly_trees_idempotently(self):
        for readonly in (False, True):
            with self.subTest(readonly=readonly):
                directory, root = self.offline_directory()
                package = root / 'package-sets/pkg/nested'
                package.mkdir(parents=True)
                payload = package / 'payload'
                payload.write_text('owned offline package')
                if readonly:
                    payload.chmod(0o444)
                    for path in (package, package.parent, package.parent.parent, root):
                        path.chmod(0o555)
                    if os.geteuid() != 0:
                        with self.assertRaises(PermissionError):
                            payload.unlink()
                directory.cleanup()
                self.assertTrue(directory.cleaned)
                self.assertFalse(root.exists())
                directory.cleanup()

    def test_offline_readonly_cleanup_preserves_outside_link_contents_and_modes(self):
        # Separate protected parents force permission recovery at each link.
        outside = self.root / 'outside'
        outside.mkdir()
        sentinel = outside / 'sentinel'
        sentinel.write_text('unrelated work')
        sentinel.chmod(0o444)
        outside.chmod(0o555)
        self.addCleanup(outside.chmod, 0o755)
        before = {path: path.stat().st_mode for path in (outside, sentinel)}
        directory, root = self.offline_directory()
        for name, target in (('directory', outside), ('file', sentinel),
                             ('dangling', outside / 'missing')):
            parent = root / name
            parent.mkdir()
            (parent / 'link').symlink_to(target)
            parent.chmod(0o555)
        root.chmod(0o555)
        directory.cleanup()
        self.assertTrue(directory.cleaned)
        self.assertFalse(root.exists())
        self.assertEqual(sentinel.read_text(), 'unrelated work')
        self.assertEqual({path: path.stat().st_mode for path in before}, before)
        self.assertEqual(list(outside.iterdir()), [sentinel])

    def test_offline_cleanup_rejects_replaced_linked_root(self):
        directory, root = self.offline_directory()
        root.rmdir()
        root.symlink_to(self.root, target_is_directory=True)
        self.addCleanup(root.unlink)
        before = self.root.stat().st_mode
        with self.assertRaisesRegex(RuntimeError, 'linked'):
            directory.cleanup()
        self.assertFalse(directory.cleaned)
        self.assertTrue(root.is_symlink())
        self.assertEqual(self.root.stat().st_mode, before)
        self.assertTrue(self.store.db.is_file())

    def test_offline_cleanup_propagates_unrecoverable_errors_and_allows_retry(self):
        for error_type in (PermissionError, OSError):
            with self.subTest(error=error_type.__name__):
                directory, root = self.offline_directory()
                payload = root / 'payload'
                payload.write_text('retained on deletion failure')
                original = AssertionError('original offline failure')
                failure = error_type('injected filesystem denial')
                # Inject at the filesystem boundary, including the permission
                # recovery retry, rather than replacing the deletion helper.
                with patch.object(os, 'unlink', side_effect=failure):
                    try:
                        try:
                            raise original
                        finally:
                            directory.cleanup()
                    except error_type as exc:
                        self.assertIs(exc, failure)
                        self.assertIs(exc.__context__, original)
                    else:
                        self.fail('Filesystem failure was hidden')
                self.assertFalse(directory.cleaned)
                self.assertEqual(payload.read_text(), 'retained on deletion failure')
                directory.cleanup()
                self.assertTrue(directory.cleaned)
                self.assertFalse(root.exists())

    def test_original_failure_and_each_cleanup_error_remain_visible(self):
        original = AssertionError('original assertion')
        other = controller(self.root / 'other')
        report = {'passed': True}
        with patch.object(lifetime, 'stop_controller', side_effect=[RuntimeError('remove failed'), {}]) as stop:
            try:
                try:
                    raise original
                finally:
                    lifetime.cleanup([self.store, other], report=report, destination=self.root / 'result.json')
            except BaseExceptionGroup as exc:
                self.assertIs(exc.exceptions[0], original)
                self.assertIn('remove failed', str(exc.exceptions[1]))
            else:
                self.fail('Cleanup failure became a pass')
        self.assertEqual(stop.call_args_list[1].args, (other,))
        self.assertFalse(load(self.root / 'result.json')['passed'])

    def test_unconfirmed_reconciliation_never_removes_monitor(self):
        with patch.object(Supervisor, 'reconcile', return_value=[{'confirmed_stopped': False}]), \
                patch.object(monitor, 'remove') as remove:
            with self.assertRaises(BaseExceptionGroup):
                lifetime.stop_controller(self.store)
        remove.assert_not_called()
        self.assertTrue(self.store.db.exists())

    def test_remove_failure_retains_directory_without_gc_deletion(self):
        directory = lifetime.FixtureDirectory(prefix='ptw-fixture-retain-')
        root = Path(directory.name)
        self.addCleanup(shutil.rmtree, root)
        store = controller(root)
        directory.own(store)
        with patch.object(monitor, 'remove', side_effect=RuntimeError('remove unavailable')):
            with self.assertRaises(BaseExceptionGroup):
                directory.cleanup()
        del directory
        self.assertTrue(store.db.is_file())
        self.assertFalse(load(root / 'fixture-cleanup-1.json')['passed'])

    def test_missing_controller_does_not_create_replacement_evidence(self):
        self.store.db.unlink()
        with patch.object(monitor, 'remove') as remove:
            with self.assertRaisesRegex(RuntimeError, 'disappeared'):
                lifetime.stop_controller(self.store)
        remove.assert_not_called()
        self.assertFalse(self.store.db.exists())

    def test_directory_owner_retains_missing_acquired_controller(self):
        directory = lifetime.FixtureDirectory(prefix='ptw-fixture-missing-')
        root = Path(directory.name)
        self.addCleanup(shutil.rmtree, root)
        store = controller(root)
        # Register before ensure, including an ensure that partially succeeds.
        with patch.object(monitor, 'ensure', side_effect=RuntimeError('partial start')):
            with self.assertRaisesRegex(RuntimeError, 'partial start'):
                directory.ensure(store)
        shutil.rmtree(store.directory)
        with patch.object(monitor, 'remove') as remove:
            with self.assertRaises(BaseExceptionGroup):
                directory.cleanup()
        remove.assert_not_called()
        self.assertFalse(directory.cleaned)
        self.assertFalse(store.db.exists())
        self.assertFalse(load(root / 'fixture-cleanup-1.json')['passed'])

    def test_directory_discovery_rejects_missing_database_with_surviving_unit(self):
        directory = lifetime.FixtureDirectory(prefix='ptw-fixture-discovery-')
        root = Path(directory.name)
        self.addCleanup(shutil.rmtree, root)
        store = controller(root)
        config = self.root / 'config'
        # Foreground declaration cannot exempt a real detached unit.
        directory.foreground.add(store.directory)
        with patch.dict(os.environ, {'XDG_CONFIG_HOME': str(config)}):
            unit = lifetime.unit_path(store.directory)
            unit.parent.mkdir(parents=True)
            unit.write_text(monitor.service_text(store.directory))
            store.db.unlink()
            with patch.object(monitor, 'remove') as remove:
                with self.assertRaises(BaseExceptionGroup):
                    directory.cleanup()
            remove.assert_not_called()
            self.assertTrue(unit.exists())
        self.assertFalse(directory.cleaned)
        self.assertFalse(store.db.exists())
        self.assertFalse(load(root / 'fixture-cleanup-1.json')['passed'])

    def test_directory_owner_checks_service_when_unit_file_is_missing(self):
        for state in ('active', 'activating', '', 'inactive'):
            with self.subTest(state=state):
                directory = lifetime.FixtureDirectory(prefix='ptw-fixture-unit-missing-')
                root = Path(directory.name)
                self.addCleanup(shutil.rmtree, root)
                store = controller(root)
                # Indirect child acquisitions leave identity even after removal
                # of the unit file. No direct own() registration in this case.
                save(store.directory / 'monitor-identity.json', {'role': 'monitor'})
                with patch.object(monitor, 'call', return_value=state) as call:
                    if state == 'inactive':
                        directory.cleanup()
                        self.assertTrue(directory.cleaned)
                    else:
                        with self.assertRaises(BaseExceptionGroup):
                            directory.cleanup()
                        self.assertFalse(directory.cleaned)
                        self.assertFalse(load(root / 'fixture-cleanup-1.json')['passed'])
                call.assert_called_once_with('show', monitor.unit_for(store.directory),
                                             '-p', 'ActiveState', '--value')
                self.assertTrue(store.db.is_file())

    def test_poetry_cleanup_failure_closes_child_and_retains_original_and_state(self):
        from test_product_poetry import PoetryBoundaryTests, PoetryNativeTests
        case = PoetryNativeTests('runTest')
        # Use its actual directory owner without provisioning a Poetry tool:
        # the failure is after controller/child acquisition, outside the solver.
        PoetryBoundaryTests.setUp(case)
        self.addCleanup(shutil.rmtree, case.root)
        store = controller(case.root)
        case.tmp.own(store)
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
        self.addCleanup(lambda: child.poll() is None and (child.kill(), child.wait()))
        original = AssertionError('original Poetry assertion')
        with patch.object(monitor, 'remove', side_effect=RuntimeError('injected removal failure')):
            try:
                try:
                    raise original
                finally:
                    case.cleanup_import(store, child)
            except BaseExceptionGroup as exc:
                self.assertIs(exc.exceptions[0], original)
            else:
                self.fail('Cleanup hid the body or removal failure')
            # The same callback used by activated_revision must not delete data
            # even when unittest continues its LIFO cleanup after an error.
            self.assertFalse(case.doCleanups())
        self.assertIsNotNone(child.poll())
        self.assertTrue(store.db.is_file())
        self.assertFalse(case.tmp.cleaned)
        self.assertFalse(load(case.root / 'fixture-cleanup-1.json')['passed'])
        self.assertFalse(load(case.root / 'import-cleanup.json')['passed'])

    def test_linked_root_is_rejected_and_closer_failure_does_not_skip_controller(self):
        link = self.root / 'link'
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, 'linked'):
            lifetime.owned_controllers(link)
        def fail():
            raise RuntimeError('terminal close failed')
        with patch.object(lifetime, 'stop_controller', return_value={}) as stop:
            with self.assertRaises(BaseExceptionGroup):
                lifetime.cleanup([self.store], closers=[fail])
        stop.assert_called_once_with(self.store)

    def test_ecosystem_setup_failure_cleans_partially_acquired_controller(self):
        import product_ecosystems_acceptance as ecosystems
        acquired = []
        def fail(repo, state, args):
            acquired.append(controller(state / 'partial'))
            raise AssertionError('onboarding failed after acquisition')
        with patch.object(ecosystems.onboarding, 'setup', side_effect=fail), \
                patch.object(ecosystems, 'owned_controllers', side_effect=lambda root: acquired), \
                patch.object(lifetime, 'stop_controller', return_value={}) as stop:
            with self.assertRaisesRegex(AssertionError, 'onboarding failed'):
                ecosystems.journey(self.root / 'journey', 'new-python')
        stop.assert_called_once_with(acquired[0])
        self.assertFalse(load(self.root / 'journey/journey.json')['passed'])

    def test_recovery_rejects_wrong_owner_before_touching_projects(self):
        with patch.object(lifetime, 'stop_controller') as stop:
            with self.assertRaisesRegex(RuntimeError, 'ownership'):
                lifetime.recover_inactive(self.store, 'unrelated.service')
        stop.assert_not_called()
        self.assertFalse(self.store.status('python-demo')['stopped'])

    def test_setup_child_is_closed_before_discovering_its_last_controller(self):
        acquired = []
        def close():
            # A setup child can publish its controller while the parent closes it.
            acquired.append(self.store)
        with patch.object(lifetime, 'stop_controller', return_value={}) as stop:
            lifetime.cleanup(lambda: list(acquired), closers=[close])
        stop.assert_called_once_with(self.store)


@unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'Requires manager native systemd environment')
class NativeFixtureLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='ptw-fixture-lifecycle-'))
        print('FIXTURE_LIFECYCLE_EVIDENCE=' + str(self.root), flush=True)
        source = Path(__file__).resolve().parents[1]
        paths = [Path(__file__), Path(lifetime.__file__), source / 'tests/test_product_poetry.py',
                 *sorted((source / 'ptw').rglob('*.py'))]
        save(self.root / 'sources.json', {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                                        for p in paths})
        self.stores = []
        self.addCleanup(lambda: lifetime.cleanup(self.stores, destination=self.root / 'final-cleanup.json'))
        self.before = self.monitors()

    def monitors(self):
        # Observation only. Never select cleanup targets from this inventory.
        return monitor.call('list-unit-files', '--no-legend', 'ptw-monitor-*.service').splitlines()

    def acquire(self, name):
        store = controller(self.root / name)
        self.stores.append(store)  # before ensure, including partial acquisition
        monitor.ensure(store)
        actor = store.register('python-demo', 'implementation')
        progress = store.directory / 'useful-progress'
        script = ('from pathlib import Path; import time; p=Path(' + repr(str(progress)) + ')\n'
                  'for n in range(3000):\n p.write_text(str(n)); time.sleep(.02)\n')
        unit = Supervisor(store).background(actor['token'], [sys.executable, '-B', '-c', script], service_seconds=90)
        self.await_progress(progress)
        history = store.audit_events('python-demo', include_lifecycle=True)
        self.assertTrue(history)
        save(store.directory / 'history-before-cleanup.json', history)
        return store, unit, progress

    def await_progress(self, path, previous=None):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            value = path.read_text() if path.exists() else ''
            if value and value != previous:
                return value
            time.sleep(.02)
        self.fail('Useful native work did not progress')

    def assert_removed(self, store, unit):
        self.assertFalse(lifetime.unit_path(store.directory).exists())
        self.assertIn(monitor.call('show', monitor.unit_for(store.directory), '-p', 'ActiveState', '--value'),
                      ('inactive', 'failed'))
        self.assertTrue(Supervisor.state(unit)['confirmed_stopped'])
        self.assertTrue(store.status('python-demo')['stopped'])
        # These operator/controller actions create lifecycle history, not broker
        # requests. Check its contents survive, rather than merely its existence.
        history = store.audit_events('python-demo', include_lifecycle=True)
        self.assertTrue(history)
        retained = {row['event']: row for row in history}
        for row in load(store.directory / 'history-before-cleanup.json'):
            self.assertEqual(retained.get(row['event']), row)
        self.assertIn('stop_requested', {row['request']['action'] for row in history})
        self.assertTrue(store.db.is_file())

    def repeated(self, failure, control=False):
        other = self.acquire('unrelated') if control else None
        owned = []
        for index in range(2):
            store, unit, progress = self.acquire('subject-' + str(index))
            owned.append(monitor.unit_for(store.directory))
            before = other[2].read_text() if other else None
            try:
                try:
                    if failure and (not control or index == 1):
                        raise AssertionError('injected body failure')
                finally:
                    lifetime.cleanup([store], destination=self.root / ('cleanup-' + str(index) + '.json'))
            except AssertionError as exc:
                self.assertTrue(failure)
                self.assertEqual(str(exc), 'injected body failure')
            self.assert_removed(store, unit)
            stopped = progress.read_text()
            time.sleep(1.2)  # exceeds monitor RestartSec; verify it stays removed
            self.assert_removed(store, unit)
            self.assertEqual(progress.read_text(), stopped)
            if other:
                self.await_progress(other[2], before)
                self.assertEqual(Supervisor.state(other[1])['ActiveState'], 'active')
                self.assertTrue(monitor.health(other[0])['healthy'])
                self.assertFalse(other[0].status('python-demo')['stopped'])
        after = self.monitors()
        save(self.root / 'monitor-inventory.json', {'before': self.before, 'after': after, 'owned': owned})
        self.assertFalse(any(unit in line for unit in owned for line in after))

    def test_repeated_success_removes_monitors_and_retains_history(self):
        self.repeated(False)

    def test_repeated_failure_removes_monitors_and_retains_history(self):
        self.repeated(True)
        save(self.root / 'partial-setup.json', partial_setup())

    def test_unrelated_live_work_survives_success_and_failure(self):
        self.repeated(True, control=True)

    def test_local_python_owner_cleans_indirect_monitor_before_retaining_data(self):
        import test_product_python_local as local
        case = local.LocalPythonTests('runTest')
        try:
            case.setUp()
            store, _, _ = case.activate()
            monitor.ensure(store)
        finally:
            self.assertTrue(case.doCleanups())
        self.assertFalse(lifetime.unit_path(store.directory).exists())
        self.assertTrue(store.db.is_file())
        self.assertTrue(store.status('local-python')['stopped'])
        save(self.root / 'local-python-owner.json', {'state': str(store.directory)})

    def test_poetry_owner_retains_failed_cleanup_and_reaps_child(self):
        from test_product_poetry import PoetryBoundaryTests, PoetryNativeTests
        case = PoetryNativeTests('runTest')
        PoetryBoundaryTests.setUp(case)
        store = controller(case.root)
        self.stores.append(store)
        case.tmp.ensure(store)
        other, other_unit, progress = self.acquire('unrelated-poetry-control')
        before = progress.read_text()
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
        self.addCleanup(lambda: child.poll() is None and (child.kill(), child.wait()))
        with patch.object(monitor, 'remove', side_effect=RuntimeError('injected native removal failure')):
            with self.assertRaises(BaseExceptionGroup):
                case.cleanup_import(store, child)
            self.assertFalse(case.doCleanups())
        self.assertIsNotNone(child.poll())
        self.assertFalse(case.tmp.cleaned)
        self.assertTrue(store.db.is_file())
        self.assertFalse(load(case.root / 'fixture-cleanup-1.json')['passed'])
        self.assertTrue(lifetime.unit_path(store.directory).is_file())
        self.await_progress(progress, before)
        self.assertEqual(Supervisor.state(other_unit)['ActiveState'], 'active')
        self.assertFalse(other.status('python-demo')['stopped'])
        case.tmp.cleanup()
        self.assertTrue(case.tmp.cleaned)
        self.assertTrue(store.db.is_file())
        self.assertFalse(lifetime.unit_path(store.directory).exists())
        self.assertIn(monitor.call('show', monitor.unit_for(store.directory), '-p', 'ActiveState', '--value'),
                      ('inactive', 'failed'))
        save(self.root / 'poetry-owner.json', {'state': str(store.directory), 'evidence': str(case.root)})

    def test_exact_owner_recovery_requires_inactive_work(self):
        store, unit, _ = self.acquire('interrupted')
        other, other_unit, progress = self.acquire('unrelated')
        with self.assertRaisesRegex(RuntimeError, 'active or unconfirmed'):
            lifetime.recover_inactive(store, monitor.unit_for(store.directory))
        self.assertFalse(store.status('python-demo')['stopped'])
        store.stop('python-demo', 'fixture owner ends work before recovery')
        Supervisor(store).reconcile()
        before = progress.read_text()
        result = lifetime.recover_inactive(store, monitor.unit_for(store.directory))
        save(self.root / 'recovery.json', result)
        self.assert_removed(store, unit)
        self.await_progress(progress, before)
        self.assertEqual(Supervisor.state(other_unit)['ActiveState'], 'active')
        self.assertFalse(other.status('python-demo')['stopped'])

    def test_installed_fixture_partial_setup_cleanup(self):
        from product_ecosystems_acceptance import build_test_wheel, wheel_step, IDENTITY_PROBE
        from evidence_io import verify_wheel_identity
        from product_install import clean_env
        wheel, hashes = build_test_wheel(self.root / 'build')
        env = clean_env(self.root)
        uv = shutil.which('uv')
        installation = self.root / 'installation'
        python = installation / 'bin/python'
        source = Path(__file__).resolve().parents[1]
        for name, argv in (
                ('venv', [uv, '--no-config', 'venv', '--no-python-downloads', '--python', sys.executable, installation]),
                ('dependencies', [uv, '--no-config', 'pip', 'sync', '--python', python, '--require-hashes',
                                  '--only-binary', ':all:', '--index-url', 'https://pypi.org/simple',
                                  source / 'requirements.lock']),
                ('install', [uv, '--no-config', 'pip', 'install', '--python', python, '--no-deps', wheel])):
            wheel_step(argv, self.root / (name + '.json'), env)
        identity = json.loads(wheel_step([python, '-I', '-B', '-c', IDENTITY_PROBE], self.root / 'identity.json', env))
        verify_wheel_identity(identity, installation, hashes)
        script = ('import sys; sys.path.insert(0,sys.argv[1]); '
                  'from test_product_fixture_lifecycle import partial_setup; '
                  'from ptw.policy import save; save(sys.argv[2], partial_setup())')
        wheel_step([python, '-I', '-B', '-c', script, source / 'tests', self.root / 'installed-cleanup.json'],
                   self.root / 'installed-step.json', env, timeout=120)
        results = load(self.root / 'installed-cleanup.json')
        self.assertEqual(len(results), 2)
        for result in results:
            identity = result['identity']
            self.assertEqual(identity['executable'], str(python))
            self.assertEqual(identity['prefix'], str(installation))
            self.assertFalse(identity['pythonpath_present'])
            self.assertEqual({Path(k).name: v for k, v in identity['runtime_sha256'].items()
                              if len(Path(k).parts) == 2 and k.endswith('.py')}, hashes)
        after = json.loads(wheel_step([python, '-I', '-B', '-c', IDENTITY_PROBE], self.root / 'after.json', env))
        verify_wheel_identity(after, installation, hashes)
