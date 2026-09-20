"""Staged native bridge acceptance; currently tests the prerequisite milestone.

No optional skips: native prerequisites fail if the approved runtime is absent.
These tests do not establish a completed adapter, scorer or benchmark result.
"""
import hashlib
import ast
import io
import json
import os
import shutil
from pathlib import Path
import sys
import tempfile
import concurrent.futures
import threading
import unittest
import struct
import subprocess
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import linuxarena_preflight as preflight
from evidence_io import load
from ptw.linuxarena_cgroup import ExecutionSubtree, container_group
from ptw.policy import Invalid
from ptw import linuxarena_lifecycle as lifecycle
from ptw.policy import approve, compile_policy, digest as policy_digest
from ptw.sample import create as create_sample
from ptw.store import Store
from ptw.supervisor import Supervisor
from ptw import linuxarena_namespace as namespace
import linuxarena_confinement as confinement
import linuxarena_loader_diagnostics as loader_diagnostics
import linuxarena_socket_probe as socket_probe


class BridgePrerequisiteTests(unittest.TestCase):
    def test_reopen_requires_original_inode_and_never_removes_a_replacement(self):
        import ptw.linuxarena_cgroup as cgroups
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            root = Path(directory)
            cid = 'a' * 64
            group = '/docker-' + cid + '.scope'
            leaf = root / group[1:] / ('ptw-' + 'b' * 24)
            leaf.mkdir(parents=True)
            (leaf / 'cgroup.type').write_text('domain\n')
            info = leaf.stat()
            identity = dict(container_id=cid, cgroup=group + '/' + leaf.name,
                            device=info.st_dev, inode=info.st_ino, boot_id=cgroups.boot_identity())
            with patch.object(cgroups, 'CGROUP_ROOT', root):
                opened = ExecutionSubtree.reopen(identity)
                opened.close(remove=False)
                self.assertTrue(leaf.is_dir())
                leaf.rename(leaf.with_name('retained-original'))
                leaf.mkdir()
                with self.assertRaisesRegex(Invalid, 'replaced'):
                    ExecutionSubtree.reopen(identity)
                self.assertTrue(leaf.is_dir())

    def test_reopen_rejects_boot_and_path_replacements_before_kernel_access(self):
        from ptw.linuxarena_cgroup import boot_identity
        cid = 'a' * 64
        identity = dict(container_id=cid, cgroup='/user.slice/docker-' + cid + '.scope/ptw-' + 'b' * 24,
                        device=2, inode=3, boot_id=boot_identity())
        with patch('os.open') as opened:
            with self.assertRaisesRegex(Invalid, 'stale'):
                ExecutionSubtree.reopen({**identity, 'boot_id': 'not-current-boot'})
            for group in ('/', identity['cgroup'] + '/child', '/user.slice/ptw-' + 'b' * 24):
                with self.subTest(group=group), self.assertRaises(Invalid):
                    ExecutionSubtree.reopen({**identity, 'cgroup': group})
            opened.assert_not_called()

    def test_only_exact_container_scope_is_admitted(self):
        cid = 'a' * 64
        scope = '/user.slice/session.slice/docker-' + cid + '.scope'
        self.assertEqual(str(container_group(scope, cid)), '/sys/fs/cgroup' + scope)
        for group, identity in (
            ('/', cid), ('/user.slice', cid), (scope + '/child', cid),
            (scope, 'b' * 64), (scope, 'short'), (scope, None),
            ('/user.slice/../' + Path(scope).name, cid), ('/' + scope, cid),
            (scope + '/', cid), (scope[1:], cid), (None, cid),
        ):
            with self.subTest(group=group, identity=identity), self.assertRaises(Invalid):
                container_group(group, identity)

    def test_revoked_subtree_rejects_admission_before_process_access(self):
        subtree = ExecutionSubtree.__new__(ExecutionSubtree)
        subtree.revoked, subtree.closed = True, False
        with patch('os.pidfd_open') as opened, self.assertRaises(Invalid):
            subtree.admit_stopped({'pid': os.getpid()})
        opened.assert_not_called()

    def test_actual_source_bytes_checked_against_pin(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            root = Path(directory)
            content = b'print("trusted source")\n'
            (root / 'module.py').write_bytes(content)
            oid = hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest()
            def command(argv):
                if 'rev-parse' in argv:
                    return (preflight.CT_PIN + '\n').encode()
                return b'100644 blob ' + oid.encode() + b'\tmodule.py\0'
            result = preflight.source_tree(root, preflight.CT_PIN, command)
            self.assertEqual(result['files_sha256']['module.py'], hashlib.sha256(content).hexdigest())
            # A clean-looking revision is insufficient, including staged bytes.
            (root / 'module.py').write_text('changed')
            with self.assertRaisesRegex(ValueError, 'content differs'):
                preflight.source_tree(root, preflight.CT_PIN, command)
            (root / 'module.py').unlink()
            (root / 'target').write_bytes(content)
            (root / 'module.py').symlink_to('target')
            with self.assertRaisesRegex(ValueError, 'changed type'):
                preflight.source_tree(root, preflight.CT_PIN, command)

    def test_credential_free_child_environment_and_closed_provider(self):
        with patch.dict(os.environ, {'OPENROUTER_API_KEY': 'must-not-propagate',
                                     'AWS_SECRET_ACCESS_KEY': 'must-not-propagate',
                                     'PYTHONPATH': '/attacker', 'DOCKER_HOST': 'tcp://untrusted'}):
            env = preflight.child_environment(Path('/retained'), Path('/receipts'))
        self.assertNotIn('AWS_SECRET_ACCESS_KEY', env)
        self.assertNotIn('PYTHONPATH', env)
        self.assertNotIn('DOCKER_HOST', env)
        self.assertEqual(env['OPENROUTER_BASE_URL'], 'http://127.0.0.1:1/api/v1')
        self.assertNotEqual(env['OPENROUTER_API_KEY'], 'must-not-propagate')
        self.assertEqual(env['HOME'], '/receipts/home')

    def test_output_rejects_reuse_links_and_checkout(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            root = Path(directory)
            destination = preflight.private_output(root / 'new')
            self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
            with self.assertRaises(FileExistsError):
                preflight.private_output(destination)
            (root / 'alias').symlink_to(destination, target_is_directory=True)
            with self.assertRaises(ValueError):
                preflight.private_output(root / 'alias/escape')
            (root / '.git').mkdir()
            (root / '.git/HEAD').write_text('ref: refs/heads/main\n')
            with self.assertRaisesRegex(ValueError, 'outside checkouts'):
                preflight.private_output(root / 'inside')
            self.assertFalse((root / 'inside').exists())

    def test_empty_git_sentinel_is_not_a_checkout(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            root = Path(directory)
            (root / '.git').mkdir()
            self.assertEqual(preflight.private_output(root / 'new'), root / 'new')
            # An empty nearer marker cannot hide a checkout ancestor.
            (root / 'new/.git').mkdir()
            (root / '.git/HEAD').write_text('ref: refs/heads/main\n')
            with self.assertRaisesRegex(ValueError, 'outside checkouts'):
                preflight.private_output(root / 'new/nested')
            self.assertFalse((root / 'new/nested').exists())

    def test_gitfiles_and_linked_metadata_rejected_before_creation(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            root = Path(directory)
            marker = root / '.git'
            # Worktree gitfiles, malformed files and even empty files remain
            # denied; only an actually empty directory is a sentinel.
            for content in ('gitdir: /not-followed\n', 'invalid', ''):
                with self.subTest(content=content):
                    marker.write_text(content)
                    with self.assertRaisesRegex(ValueError, 'outside checkouts'):
                        preflight.private_output(root / 'new')
                    self.assertFalse((root / 'new').exists())
                    marker.unlink()
            for target in (root / 'absent', root / 'empty'):
                (root / 'empty').mkdir(exist_ok=True)
                marker.symlink_to(target)
                with self.assertRaisesRegex(ValueError, 'outside checkouts'):
                    preflight.private_output(root / 'new')
                self.assertFalse((root / 'new').exists())
                marker.unlink()

    def test_source_checkout_rejected_even_with_masked_metadata(self):
        destination = SCRIPTS.parents[1] / 'must-not-create-receipts'
        with self.assertRaisesRegex(ValueError, 'outside checkouts'):
            preflight.private_output(destination)
        self.assertFalse(destination.exists())

    def test_missing_runtime_does_not_start_commands(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as directory, patch.object(preflight, 'Commands') as commands:
            with self.assertRaises(ValueError):
                preflight.run(Path(directory) / 'missing', Path(directory) / 'new')
            commands.assert_not_called()

    def test_failed_native_taskspace_is_retained_without_docker(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            root = Path(directory)
            runtime = root / 'runtime'
            runtime.mkdir()
            with patch.object(preflight, 'source_tree', return_value={'commit': 'test fixture'}), \
                    patch.object(preflight.Commands, '__call__', side_effect=ValueError('native import failure')), \
                    patch.object(preflight, 'daemon_environment') as docker:
                with self.assertRaisesRegex(ValueError, 'native import failure'):
                    preflight.run(runtime, root / 'attempt')
            docker.assert_not_called()
            receipt = load(root / 'attempt/attempt.json')
            self.assertEqual(receipt['status'], 'failed')
            self.assertEqual(receipt['error_type'], 'ValueError')
            self.assertEqual(receipt['paid_calls'], 0)
            self.assertIn('ended_epoch', receipt)


class BridgeLifecycleTests(unittest.TestCase):
    """Real controller persistence, mocked kernel boundary; not physical proof."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ptw-native-lifecycle-', dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        create_sample(self.root / 'fixture')
        policy = load(self.root / 'fixture/policy.json')
        inventory = load(self.root / 'fixture/inventory.json')
        self.store = Store(self.root / 'state')
        self.store.activate(approve(policy, inventory, policy_digest(compile_policy(policy, inventory)),
                                   'deterministic lifecycle test'))
        self.actor = self.store.register('website', 'frontend')
        self.other = self.store.register('website', 'operations')
        self.cid, self.nonce = 'a' * 64, 'b' * 24
        self.group = '/user.slice/docker-' + self.cid + '.scope'
        self.control = dict(pid=123, starttime=456, state='S', cgroup=self.group,
                            pid_namespace='pid:[1]', user_namespace='user:[2]')
        self.expected = dict(self.control, pid=124, state='T')
        self.kernel = unittest.mock.Mock()
        self.kernel.closed = self.kernel.revoked = False
        self.kernel.populated.return_value = False
        self.kernel.parent, self.kernel.name = container_group(self.group, self.cid), 'ptw-' + self.nonce
        self.kernel.identity = dict(container_id=self.cid, cgroup=self.group + '/ptw-' + self.nonce,
                                    device=2, inode=3, boot_id='fixture-boot')
        self.kernel.admit_stopped.return_value = dict(self.expected, cgroup=self.kernel.identity['cgroup'])
        self.kernel.terminate.return_value = {**self.kernel.identity, 'confirmed_stopped': True}
        for name, value in (('process_identity', lambda pid: self.control),
                            ('ExecutionSubtree.reopen', lambda identity: self.kernel)):
            mock = patch('ptw.linuxarena_lifecycle.' + name, side_effect=value)
            mock.start()
            self.addCleanup(mock.stop)
        self.unit = lifecycle.register(self.store, self.actor['token'], self.kernel,
                                       daemon_id='verified-fixture-daemon', control=self.control)

    def test_authenticated_reopen_preserves_intent_and_rejects_replay(self):
        store = Store(self.root / 'state')
        observed = lifecycle.admit(store, self.actor['token'], self.unit, self.expected)
        self.assertEqual(observed['cgroup'], self.kernel.identity['cgroup'])
        with self.assertRaisesRegex(Invalid, 'already attempted'):
            lifecycle.admit(store, self.actor['token'], self.unit, self.expected)
        self.assertEqual(self.kernel.admit_stopped.call_count, 1)
        events = store.audit_export('website')['events']
        launch = next(e for e in events if e['request']['action'] == 'workload_launch')
        self.assertEqual(launch['state'], 'complete')
        self.assertEqual(launch['result']['effect'], 'workload_started')
        self.assertNotIn(self.actor['token'], json.dumps(events))

    def test_forged_other_closed_and_stopped_sessions_never_release(self):
        for token in ('forged-' * 8, self.other['token']):
            with self.assertRaises(Invalid):
                lifecycle.admit(self.store, token, self.unit, self.expected)
        self.store.close_session(self.actor['token'], outcome='surrender')
        with self.assertRaises(Invalid):
            lifecycle.admit(self.store, self.actor['token'], self.unit, self.expected)
        self.kernel.admit_stopped.assert_not_called()
        outcomes = Supervisor(self.store).reconcile()
        self.assertTrue(outcomes[0]['confirmed_stopped'])
        self.assertFalse(self.store.status('website')['stopped'])

    def test_project_stop_and_reconcile_use_native_backend_without_systemd(self):
        self.assertFalse(Supervisor(self.store).observe(self.unit)['confirmed_stopped'])
        self.store.stop('website')
        with patch('ptw.supervisor.run') as systemd:
            result = Supervisor(Store(self.root / 'state')).reconcile()
        systemd.assert_not_called()
        self.assertTrue(result[0]['confirmed_stopped'])
        self.assertTrue(Supervisor(self.store).observe(self.unit)['confirmed_stopped'])
        with self.store.locked() as db:
            self.assertEqual(db.execute('SELECT revoked FROM native_workloads').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT stopped FROM workloads').fetchone()[0], 1)
        with self.assertRaises(Invalid):
            lifecycle.admit(self.store, self.actor['token'], self.unit, self.expected)
        self.kernel.admit_stopped.assert_not_called()

    def test_explicit_surrender_reobserves_native_work_and_preserves_sibling(self):
        from ptw.workflow import end_session
        for index in range(2):
            result = end_session(self.store, self.actor['token'], 'surrender')
            self.assertTrue(result['confirmed_stopped'])
            self.assertTrue(result['admission_closed'])
            self.assertFalse(result['completion_verified'])
        with self.store.locked() as db:
            self.assertEqual(self.store.session(db, self.other['token'])['id'], self.other['session'])
        self.assertFalse(self.store.status('website')['stopped'])

    def test_stop_serializes_against_launch_and_closes_next_admission(self):
        entered, release, stopping = threading.Event(), threading.Event(), threading.Event()
        def pending(expected):
            entered.set()
            if not release.wait(5):
                raise TimeoutError('Test did not release admission')
            return dict(expected, cgroup=self.kernel.identity['cgroup'])
        def stop():
            stopping.set()
            return self.store.stop('website')
        self.kernel.admit_stopped.side_effect = pending
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            launch = pool.submit(lifecycle.admit, self.store, self.actor['token'], self.unit, self.expected)
            try:
                self.assertTrue(entered.wait(5))
                stopped = pool.submit(stop)
                self.assertTrue(stopping.wait(5))
                with self.assertRaises(concurrent.futures.TimeoutError):
                    stopped.result(timeout=.05)
            finally:
                release.set()
            launch.result(timeout=5)
            self.assertTrue(stopped.result(timeout=5)['stopped'])
        self.assertTrue(Supervisor(self.store).reconcile()[0]['confirmed_stopped'])
        with self.assertRaises(Invalid):
            lifecycle.admit(self.store, self.actor['token'], self.unit, dict(self.expected, pid=125))

    def test_kernel_admission_failure_is_not_misconduct_and_never_replayed(self):
        self.kernel.admit_stopped.side_effect = OSError('injected native failure')
        with self.assertRaises(OSError):
            lifecycle.admit(self.store, self.actor['token'], self.unit, self.expected)
        self.assertEqual(self.store.status('website')['violations'], 0)
        self.assertTrue(self.store.status('website')['stopped'])
        self.kernel.terminate.assert_called()
        with self.assertRaises(Invalid):
            lifecycle.admit(Store(self.root / 'state'), self.actor['token'], self.unit, self.expected)
        self.assertEqual(self.kernel.admit_stopped.call_count, 1)

    def test_stale_runtime_or_authority_rejects_admission_but_can_stop(self):
        with patch.object(lifecycle, 'runtime_identity', return_value='changed-runtime'):
            with self.assertRaisesRegex(Invalid, 'runtime or approved authority changed'):
                lifecycle.admit(self.store, self.actor['token'], self.unit, self.expected)
        with self.store.locked() as db:
            db.execute("UPDATE sessions SET grants='[]' WHERE id=?", (self.actor['session'],))
        with self.assertRaisesRegex(Invalid, 'runtime or approved authority changed'):
            lifecycle.admit(self.store, self.actor['token'], self.unit, self.expected)
        self.assertTrue(Supervisor(self.store).terminate(self.unit)['confirmed_stopped'])
        self.kernel.admit_stopped.assert_not_called()

    def test_replaced_control_or_namespace_rejected(self):
        with patch.object(lifecycle, 'process_identity', return_value=dict(self.control, starttime=999)):
            with self.assertRaisesRegex(Invalid, 'control process changed'):
                lifecycle.admit(self.store, self.actor['token'], self.unit, self.expected)
        with self.assertRaisesRegex(Invalid, 'container namespace'):
            lifecycle.admit(self.store, self.actor['token'], self.unit,
                            dict(self.expected, user_namespace='user:[forged]'))
        self.kernel.admit_stopped.assert_not_called()

    def test_failed_launch_completion_revokes_and_retains_uncertainty(self):
        with patch.object(self.store, 'complete', side_effect=OSError('injected capture failure')):
            with self.assertRaises(OSError):
                lifecycle.admit(self.store, self.actor['token'], self.unit, self.expected)
        self.kernel.terminate.assert_called()
        recovered = Store(self.root / 'state')
        self.assertTrue(recovered.status('website')['stopped'])
        launches = [e for e in recovered.audit_export('website')['events']
                    if e['request']['action'] == 'workload_launch']
        self.assertEqual(launches[0]['state'], 'uncertain')
        with self.assertRaises(Invalid):
            lifecycle.admit(recovered, self.actor['token'], self.unit, self.expected)
        self.assertEqual(self.kernel.admit_stopped.call_count, 1)

    def test_failed_revocation_storage_still_attempts_physical_stop(self):
        with self.store.locked() as db:
            db.execute("CREATE TRIGGER fail_native_revoke BEFORE UPDATE ON native_workloads "
                       "BEGIN SELECT RAISE(FAIL,'injected revocation failure'); END")
        result = Supervisor(self.store).terminate_recorded(self.unit)
        self.kernel.terminate.assert_called()
        self.assertFalse(result['confirmed_stopped'])
        self.assertTrue(self.store.status('website')['stopped'])

    def test_missing_or_changed_binding_is_uncertain_never_new_target(self):
        with self.store.locked() as db:
            binding = json.loads(db.execute('SELECT binding FROM native_workloads').fetchone()[0])
            binding['subtree']['inode'] += 1
            db.execute('UPDATE native_workloads SET binding=?', (json.dumps(binding),))
        result = Supervisor(self.store).terminate_recorded(self.unit)
        self.assertFalse(result['confirmed_stopped'])
        self.kernel.terminate.assert_not_called()
        self.kernel.admit_stopped.assert_not_called()

class BridgeNamespaceTests(unittest.TestCase):
    @staticmethod
    def capability_fixture(setup=False):
        mask = namespace.CAPABILITY_MASK
        if setup:
            mask |= 1 << 8
        return dict(CapEff=mask, CapPrm=mask, CapInh=mask, CapBnd=mask,
                    CapAmb=mask, NoNewPrivs=1, Seccomp=2)

    def test_capability_reduction_drops_bounding_then_active_before_execution(self):
        before, after = self.capability_fixture(True), self.capability_fixture()
        before['CapBnd'] |= (1 << 21) | (1 << 29) | (1 << 40)
        libc = unittest.mock.Mock()
        calls = []
        def drop(option, bit, *zeros):
            calls.append(('drop', option, bit, zeros))
            return 0
        def capset(header, data):
            calls.append(('capset', list(header), list(data)))
            return 0
        libc.prctl.side_effect, libc.capset.side_effect = drop, capset
        with patch.object(namespace, 'capability_state', side_effect=[before, after]), \
                patch.object(namespace.ctypes, 'CDLL', return_value=libc), \
                patch.object(sys, 'stderr', io.StringIO()) as output:
            namespace.restrict_capabilities()
        self.assertEqual([entry[2] for entry in calls[:-1]], [8, 21, 29, 40])
        self.assertTrue(all(entry[1] == 24 and entry[3] == (0, 0, 0) for entry in calls[:-1]))
        self.assertEqual(calls[-1], ('capset', [0x20080522, 0],
                                    [namespace.CAPABILITY_MASK] * 3 + [0] * 3))
        self.assertEqual([json.loads(line) for line in output.getvalue().splitlines()],
                         [{'capabilities_before': before}, {'capabilities_after': after}])

    def test_capability_reduction_rejects_invalid_setup_without_syscalls(self):
        for key, value in (('CapEff', namespace.CAPABILITY_MASK), ('CapPrm', 0),
                           ('CapEff', (1 << 21) | namespace.CAPABILITY_MASK | (1 << 8)),
                           ('CapInh', 1 << 29), ('CapAmb', 1 << 37),
                           ('CapBnd', 0), ('NoNewPrivs', 0), ('Seccomp', 0)):
            before = {**self.capability_fixture(True), key: value}
            with self.subTest(key=key, value=value), \
                    patch.object(namespace, 'capability_state', return_value=before), \
                    patch.object(namespace.ctypes, 'CDLL') as library, \
                    patch.object(sys, 'stderr', io.StringIO()), \
                    self.assertRaisesRegex(RuntimeError, 'setup'):
                namespace.restrict_capabilities()
            library.assert_not_called()

    def test_capability_reduction_failure_never_executes(self):
        for failure in ('bounding', 'active', 'unconfirmed'):
            before, after = self.capability_fixture(True), self.capability_fixture()
            libc = unittest.mock.Mock()
            libc.prctl.return_value = -1 if failure == 'bounding' else 0
            libc.capset.return_value = -1 if failure == 'active' else 0
            if failure == 'unconfirmed':
                after['CapBnd'] |= 1 << 21
            with self.subTest(failure=failure), \
                    patch.object(namespace, 'capability_state', side_effect=[before, after]), \
                    patch.object(namespace.ctypes, 'CDLL', return_value=libc), \
                    patch.object(namespace.ctypes, 'get_errno', return_value=1), \
                    patch.object(sys, 'argv', ['launcher', '--drop-capabilities', '/nono', 'run']), \
                    patch.object(sys, 'stderr', io.StringIO()), \
                    patch.object(os, 'execv') as execute, \
                    self.assertRaises((OSError, RuntimeError)):
                namespace.main()
            execute.assert_not_called()
            if failure == 'bounding':
                libc.capset.assert_not_called()

    def test_capability_finalizer_executes_only_after_verified_reduction(self):
        with patch.object(namespace, 'restrict_capabilities') as reduce, \
                patch.object(sys, 'argv', ['launcher', '--drop-capabilities', '/nono', 'run']), \
                patch.object(os, 'execv') as execute, patch.object(os, 'kill') as stop:
            order = unittest.mock.Mock()
            order.attach_mock(reduce, 'reduce')
            order.attach_mock(execute, 'execute')
            namespace.main()
            self.assertEqual([entry[0] for entry in order.mock_calls], ['reduce', 'execute'])
            execute.assert_called_once_with('/nono', ['/nono', 'run'])
            stop.assert_not_called()

    """Specification, descriptor and verified-copy checks; not native proof."""
    def spec(self, **changes):
        return dict(read=['/public'], write=['/work'], cwd='/work',
                    argv=['/usr/bin/python3', '-c', 'print(1)'], connect_ports=[6379], **changes)

    @staticmethod
    def filter_result(nr, *args, arch=0xc000003e):
        # Interpret the actual serialized cBPF, not a Python copy of its policy.
        data = struct.pack('<IIQ6Q', nr & 0xffffffff, arch, 0,
                           *(list(args) + [0] * (6 - len(args))))
        rows = list(struct.iter_unpack('<HBBI', namespace.socket_filter()))
        pc, accumulator = 0, 0
        for _ in range(len(rows)):
            code, yes, no, value = rows[pc]
            if code == 0x20:
                accumulator = struct.unpack_from('<I', data, value)[0]
            elif code == 0x54:
                accumulator &= value
            elif code in (0x15, 0x35):
                matches = accumulator == value if code == 0x15 else accumulator >= value
                pc += yes if matches else no
            elif code == 0x06:
                return value
            else:
                raise AssertionError('Unexpected filter opcode')
            pc += 1
        raise AssertionError('Filter did not terminate')

    def test_socket_filter_preserves_baseline_and_only_adds_audit_tuple(self):
        allow, deny = 0x7fff0000, 0x50001
        for flags in (0, 0x800, 0x80000, 0x80800):
            for family in range(48):
                for kind in (0, 1, 2, 3, 5, 6, 10):
                    for protocol in (0, 6, 9, 16, 17, 132, 255):
                        expected = (family == 1 or
                                    family in (2, 10) and kind == 1 and protocol in (0, 6) or
                                    family == 16 and kind == 3 and protocol == 9)
                        self.assertEqual(self.filter_result(41, family, kind | flags, protocol),
                                         allow if expected else deny,
                                         (family, kind | flags, protocol))
                        self.assertEqual(self.filter_result(53, family, kind | flags, protocol),
                                         allow if family == 1 else deny)
        self.assertEqual(self.filter_result(425), deny)
        for nr in (0, 1, 3, 42, 59, 157, 444, 446):
            self.assertEqual(self.filter_result(nr), allow)
        for args in ((2, 0x10001, 6), (16, 0x10003, 9), (16, 3, 0xffffffff)):
            self.assertEqual(self.filter_result(41, *args), deny)

    def test_socket_filter_rejects_compat_abis_before_syscall_dispatch(self):
        for nr in (0, 41, 53, 102, 425, 0x40000029, 0xffffffff):
            for arch in (0x40000003, 0xc00000b7, 0, 0x8000003e):
                self.assertEqual(self.filter_result(nr, 1, 1, arch=arch), 0x50001)
        for nr in (0x40000000, 0x40000029, 0xffffffff):
            self.assertEqual(self.filter_result(nr, 1, 1), 0x50001)
        # Kernel socket arguments are ints: high register words must never
        # let a forbidden low-word family/protocol pass the filter.
        self.assertEqual(self.filter_result(41, (1 << 32) | 17, 1), 0x50001)
        self.assertEqual(self.filter_result(41, 2, 1, (1 << 32) | 17), 0x50001)
        with patch.object(namespace.platform, 'machine', return_value='aarch64'), \
                patch.object(os, 'memfd_create') as opened:
            with self.assertRaisesRegex(ValueError, 'x86_64'):
                namespace.filter_descriptor()
            opened.assert_not_called()

    def test_filter_descriptor_is_complete_sealed_and_inherited(self):
        import fcntl
        real_write = os.write
        # Short writes must still deliver the entire program from offset zero.
        with patch.object(os, 'write', side_effect=lambda fd, data: real_write(fd, data[:7])):
            fd = namespace.filter_descriptor()
        try:
            self.assertTrue(os.get_inheritable(fd))
            self.assertEqual(os.read(fd, 8192), namespace.socket_filter())
            self.assertEqual(fcntl.fcntl(fd, 1034), 0x000f)  # Linux F_GET_SEALS
            with self.assertRaises(OSError):
                os.write(fd, b'forged')
            with self.assertRaises(OSError):
                os.ftruncate(fd, 0)
        finally:
            os.close(fd)

    def test_filter_preparation_failure_closes_descriptors_without_exec(self):
        real_create = os.memfd_create
        opened = []
        def create(*args):
            fd = real_create(*args)
            opened.append(fd)
            return fd
        for target, replacement in (
                ('write', unittest.mock.Mock(return_value=0)),
                ('write', unittest.mock.Mock(side_effect=OSError('write failed'))),
                ('set_inheritable', unittest.mock.Mock(side_effect=OSError('inherit failed')))):
            with patch.object(os, 'memfd_create', side_effect=create), \
                    patch.object(os, target, replacement), self.assertRaises(OSError):
                namespace.filter_descriptor()
            with self.assertRaises(OSError):
                os.fstat(opened[-1])
        with patch.object(namespace.fcntl, 'fcntl', side_effect=OSError('seal failed')), \
                patch.object(os, 'memfd_create', side_effect=create), self.assertRaises(OSError):
            namespace.filter_descriptor()
        with self.assertRaises(OSError):
            os.fstat(opened[-1])
        fd = os.open('/usr', os.O_PATH | os.O_DIRECTORY)
        with patch.object(namespace, 'open_resource', side_effect=lambda _: os.dup(fd)), \
                patch.object(namespace, 'filter_descriptor', side_effect=OSError('filter failed')), \
                patch.object(os, 'execv') as execute, patch.object(os, 'kill') as stopped, \
                patch.object(sys, 'argv', ['launcher', json.dumps(self.spec())]):
            before = set(os.listdir('/proc/self/fd'))
            with self.assertRaisesRegex(OSError, 'filter failed'):
                namespace.main()
            self.assertEqual(set(os.listdir('/proc/self/fd')), before)
            execute.assert_not_called()
            stopped.assert_not_called()
        os.close(fd)

    def test_audit_probe_requires_matching_kernel_denial(self):
        for status in (1, 111):
            peer = unittest.mock.Mock()
            header = struct.pack('<IHHII', 36, 2, 0, 1001, 123)
            peer.recvfrom.return_value = (header + struct.pack('<i', -status) + bytes(16), (0, 0))
            self.assertEqual(socket_probe.audit_request(peer, 1001, bytes(44)), status)
            packet = peer.sendto.call_args.args[0]
            self.assertEqual(struct.unpack_from('<IHHII', packet), (60, 1001, 5, 1001, 0))
            self.assertEqual(packet[16:], bytes(44))  # No changed audit fields.
            self.assertEqual(peer.sendto.call_args.args[1], (0, 0))

    def test_audit_probe_rejects_success_malformed_peer_and_unknown_failure(self):
        reply = struct.pack('<IHHIIi', 36, 2, 0, 1000, 123, -1) + bytes(16)
        invalid = [
            (reply, (123, 0)), (reply[:19], (0, 0)),
            (struct.pack('<IHHIIi', 36, 2, 0, 1000, 123, 0) + bytes(16), (0, 0)),
            (struct.pack('<IHHIIi', 36, 2, 0, 1000, 123, -22) + bytes(16), (0, 0)),
            (struct.pack('<IHHIIi', 36, 2, 0, 1001, 123, -1) + bytes(16), (0, 0)),
            (struct.pack('<IHHIIi', 36, 1000, 0, 1000, 123, -1) + bytes(16), (0, 0)),
        ]
        for response in invalid:
            peer = unittest.mock.Mock()
            peer.recvfrom.return_value = response
            with self.subTest(response=response), self.assertRaises(AssertionError):
                socket_probe.audit_request(peer, 1000)
        peer.recvfrom.side_effect = TimeoutError('no response')
        with self.assertRaises(TimeoutError):
            socket_probe.audit_request(peer, 1000)

    def test_socket_probe_requires_effect_denial_not_absent_support(self):
        for error in (1, 13, 97):
            with self.subTest(errno=error):
                action = unittest.mock.Mock(side_effect=OSError(error, 'fixture'))
                if error == 1:
                    self.assertEqual(socket_probe.rejected(action), 1)
                else:
                    with self.assertRaises(AssertionError):
                        socket_probe.rejected(action)
        with self.assertRaisesRegex(AssertionError, 'succeeded'):
            socket_probe.rejected(lambda: None)

    def test_canonical_resources_and_arguments_do_not_select_authority(self):
        valid = self.spec()
        self.assertEqual(namespace.validate(valid), valid)
        for field, value in (
            ('read', ['/']), ('write', ['/etc']), ('write', ['/usr/bin']),
            ('read', ['/usr/libexec/sudo']),
            ('read', ['/etc/sudoers']), ('write', ['/etc/sudoers']),
            ('read', ['/etc/sudoers.d']), ('write', ['/etc/sudoers.d/forged']),
            ('read', ['/etc/pam.d']), ('write', ['/etc/pam.d/sudo']),
            ('write', ['/etc/pam.d/forged']),
            ('write', ['/usr/libexec/sudo/libsudo_util.so.0.0.0']),
            ('read', ['/proc/1/root']), ('write', ['/ptw-native-tools']),
            ('write', ['/ptw-native-state']), ('read', ['/ptw-native-state/.nono']),
            ('read', ['//public']), ('read', ['/public/../private']),
            ('read', ['/public/']), ('read', ['relative']),
            ('read', ['/work']), ('read', ['/work/child']),
            ('read', [False]), ('write', None), ('cwd', '/private'),
            ('cwd', '/work/../private'), ('cwd', '//work'),
            ('argv', []), ('argv', ['x\x00y']), ('argv', 'shell text'),
            ('connect_ports', [True]), ('connect_ports', [0]),
            ('connect_ports', [65536]), ('connect_ports', [6379, 6379]),
        ):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                namespace.validate({**valid, field: value})
        for extra in ('grants', 'user', 'daemon', 'service', 'env', 'token'):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                namespace.validate({**valid, extra: 'forged'})

    def test_descriptor_pin_rejects_links_and_survives_replacement(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root = Path(temporary)
            folder = root / 'source'
            folder.mkdir()
            (folder / 'file').write_text('original')
            fd = namespace.open_resource(str(folder / 'file'))
            try:
                (folder / 'file').rename(folder / 'retained')
                (folder / 'file').write_text('replacement')
                self.assertEqual(Path('/proc/self/fd/' + str(fd)).read_text(), 'original')
                self.assertTrue(os.get_inheritable(fd))
            finally:
                os.close(fd)
            (root / 'alias').symlink_to(folder, target_is_directory=True)
            (folder / 'link').symlink_to('file')
            for name in ('alias/file', 'source/link'):
                with self.subTest(name=name), self.assertRaises((ValueError, OSError)):
                    namespace.open_resource(str(root / name))
            with self.assertRaises(FileNotFoundError):
                namespace.open_resource(str(root / 'missing'))
            os.mkfifo(folder / 'fifo')
            with self.assertRaisesRegex(ValueError, 'regular'):
                namespace.open_resource(str(folder / 'fifo'))

    def test_namespace_uses_pinned_live_mounts_and_drops_admin_capabilities(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root = Path(temporary)
            (root / 'read').mkdir()
            (root / 'write').write_text('existing exact file')
            real_open = namespace.open_resource
            descriptors = []
            def opened(path):
                fd = real_open(str(root / ('write' if path == '/work' else 'read')))
                descriptors.append(fd)
                return fd
            with patch.object(namespace, 'open_resource', side_effect=opened):
                args, fds = namespace.command(self.spec())
            try:
                self.assertEqual(descriptors, fds[:-1])
                self.assertEqual(args[args.index('--seccomp') + 1], str(fds[-1]))
                self.assertEqual(os.read(fds[-1], 8192), namespace.socket_filter())
                self.assertEqual(args[args.index('--sandbox-policy') + 1], 'landlock')
                self.assertIn('--block-net', args)
                self.assertIn('--unshare-pid', args)
                self.assertIn('--unshare-cgroup', args)
                self.assertNotIn('--unshare-user', args)
                self.assertNotIn('--unshare-net', args)
                self.assertNotIn('--die-with-parent', args)
                self.assertNotIn('CAP_SYS_ADMIN', args)
                self.assertNotIn('CAP_SYS_PTRACE', args)
                for cap in ('CAP_AUDIT_CONTROL', 'CAP_AUDIT_READ', 'CAP_AUDIT_WRITE', 'CAP_NET_ADMIN'):
                    self.assertNotIn(cap, args)
                self.assertEqual(args[args.index('--cap-drop') + 1], 'ALL')
                self.assertIn('--bind-fd', args)
                self.assertIn('--ro-bind-fd', args)
                self.assertIn('--allow-file', args)
                self.assertIn('--allow-connect-port', args)
                self.assertNotIn('--allow-domain', args)
                # Sudo has exact runtime reads plus its fixed configuration
                # include directory. No /etc grant or runtime write qualifies.
                nono_args = args[args.index(namespace.TOOLS + '/bin/nono') + 1:]
                nono_args = nono_args[:nono_args.index('--')]
                grants = [(arg, nono_args[i + 1]) for i, arg in enumerate(nono_args)
                          if arg in ('--allow', '--read', '--allow-file', '--read-file')]
                self.assertEqual(grants, [
                    ('--allow', '/tmp'), ('--read', namespace.TOOLS),
                    ('--read-file', '/usr/libexec/sudo/libsudo_util.so.0.0.0'),
                    ('--read-file', '/usr/libexec/sudo/sudoers.so'),
                    ('--read-file', '/etc/sudoers'),
                    ('--read', '/etc/sudoers.d'),
                    ('--read', '/etc/pam.d'),
                    ('--read', '/public'), ('--allow-file', '/work')])
                pam = args.index('/etc/pam.d')
                self.assertEqual(args[pam - 2], '--ro-bind-fd')
                # Explicit namespace-only parents precede mounts. Inherited
                # umask must not make native user switching unusable.
                etc = args.index('/etc')
                self.assertEqual(args[etc - 3:etc], ['--perms', '0755', '--dir'])
                self.assertLess(etc, args.index('--ro-bind-fd'))
                tmpfs = args.index('--tmpfs')
                self.assertEqual(args[tmpfs - 2:tmpfs + 2],
                                 ['--perms', '1777', '--tmpfs', '/tmp'])
                usr = args.index('/usr')
                self.assertEqual(args[usr - 2], '--ro-bind-fd')
                sudoers = args.index('/etc/sudoers')
                self.assertEqual(args[sudoers - 2], '--ro-bind-fd')
                includes = args.index('/etc/sudoers.d')
                self.assertEqual(args[includes - 2], '--ro-bind-fd')
                self.assertEqual([args[i + 1] for i, arg in enumerate(args) if arg == '--cap-add'],
                                 ['CAP_SETUID', 'CAP_SETGID', 'CAP_DAC_OVERRIDE', 'CAP_CHOWN',
                                  'CAP_FOWNER', 'CAP_KILL', 'CAP_SETPCAP'])
                stage = args.index('--drop-capabilities')
                self.assertEqual(args[stage - 4:stage],
                                 ['/usr/bin/python3', '-I', '-S', namespace.TOOLS + '/launcher.py'])
                self.assertLess(args.index('--seccomp'), stage)
                self.assertLess(stage, args.index(namespace.TOOLS + '/bin/nono'))
                # nono protects HOME/.nono independently of XDG_STATE_HOME.
                # Temporary-file authority must never include that state root.
                home = args[args.index('HOME') + 1]
                self.assertEqual(home, namespace.STATE)
                self.assertFalse(Path(home).is_relative_to('/tmp'))
                self.assertIn(['--dir', home], [args[i:i + 2] for i in range(len(args) - 1)])
                for flag in ('--allow', '--read', '--allow-file', '--read-file'):
                    for i, arg in enumerate(args[:-1]):
                        if arg == flag:
                            self.assertFalse(Path(home).is_relative_to(args[i + 1]))
                self.assertEqual(args[-3:], self.spec()['argv'])
            finally:
                for fd in fds:
                    os.close(fd)

    def test_failed_mount_preparation_closes_every_descriptor(self):
        fd = os.open('/usr', os.O_PATH | os.O_DIRECTORY)
        with patch.object(namespace, 'open_resource', side_effect=[fd, OSError('missing')]):
            with self.assertRaisesRegex(OSError, 'missing'):
                namespace.command(self.spec())
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_stopped_launcher_executes_only_after_admission(self):
        with patch.object(sys, 'argv', ['launcher', json.dumps(self.spec())]), \
                patch.object(namespace, 'command', return_value=(['/loader', 'bwrap'], [123])) as compiled, \
                patch.object(os, 'kill') as stop, patch.object(os, 'execv') as execute, \
                patch.object(os, 'close') as close:
            order = unittest.mock.Mock()
            order.attach_mock(stop, 'stop')
            order.attach_mock(execute, 'execute')
            namespace.main()
            self.assertEqual([call[0] for call in order.mock_calls], ['stop', 'execute'])
            compiled.assert_called_once()
            close.assert_called_once_with(123)

    def test_missing_or_conflicting_tool_libraries_fail_without_fallback(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root = Path(temporary)
            with patch.dict(os.environ, {}, clear=True), patch.object(shutil, 'which', return_value=None):
                with self.assertRaisesRegex(ValueError, 'required'):
                    confinement.stage_tools(root, unittest.mock.Mock())
            binary = root / 'binary'
            binary.write_bytes(b'trusted fixture bytes, not executable')
            with patch.dict(os.environ, {}, clear=True), patch.object(shutil, 'which', return_value=str(binary)):
                with self.assertRaisesRegex(ValueError, 'shared library'):
                    confinement.stage_tools(root, lambda argv: b'libc.so.6 => not found\n')
            self.assertNotEqual(binary.stat().st_ino, (root / 'tools/bin/bwrap').stat().st_ino)

    def test_payload_exit_reports_failure_without_waiting_or_accepting_output(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root = Path(temporary)
            (root / 'probe').mkdir()
            (root / 'observer').mkdir()
            self.assertIsNone(confinement.payload_observation(root))
            (root / 'probe/observed.json').write_text('{"fixture": "observed"}')
            self.assertEqual(confinement.payload_observation(root), {'fixture': 'observed'})
            # Exit 0 is also invalid: this fixture must remain alive for stop.
            for code in ('0', '1', '137'):
                (root / 'observer/exit').write_text(code + '\n')
                with self.subTest(code=code), self.assertRaisesRegex(RuntimeError, 'status ' + code):
                    confinement.payload_observation(root)

    def test_loader_metadata_decodes_interpreter_dependencies_and_search_paths(self):
        # A minimal ELF with virtual addresses different from file offsets;
        # no compiler, external readelf, process execution or native socket.
        strings = b'\0libsudo_util.so.0\0$ORIGIN/lib\0/usr/lib/sudo\0'
        interpreter = b'/lib64/ld-linux-x86-64.so.2\0'
        dynamic = b''.join(struct.pack('<qQ', tag, value) for tag, value in
                           [(5, 0x400200), (10, len(strings)), (1, 1),
                            (15, 19), (29, 31), (0, 0)])
        data = bytearray(1024)
        data[:64] = struct.pack('<16sHHIQQQIHHHHHH', b'\x7fELF\x02\x01\x01',
                                3, 62, 1, 0, 64, 0, 0, 64, 56, 3, 0, 0, 0)
        for i, (kind, offset, va, size) in enumerate(
                [(1, 0, 0x400000, 1024), (2, 256, 0, len(dynamic)),
                 (3, 700, 0, len(interpreter))]):
            data[64 + i * 56:120 + i * 56] = struct.pack('<IIQQQQQQ', kind, 0, offset, va, 0, size, size, 8)
        data[256:256 + len(dynamic)] = dynamic
        data[512:512 + len(strings)] = strings
        data[700:700 + len(interpreter)] = interpreter
        result = loader_diagnostics.elf_metadata(bytes(data))
        self.assertEqual(result, {'interpreter': interpreter[:-1].decode(),
                                 'needed': ['libsudo_util.so.0'],
                                 'rpath': ['$ORIGIN/lib'], 'runpath': ['/usr/lib/sudo']})
        for invalid in (b'', bytes(data[:100]), b'not ELF' + bytes(data[7:]),
                        bytes(data[:512]) + b'x' * 512):
            with self.subTest(size=len(invalid)), self.assertRaises((ValueError, struct.error)):
                loader_diagnostics.elf_metadata(invalid)

    def test_loader_file_observation_distinguishes_missing_denied_link_and_invalid(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root = Path(temporary)
            target = root / 'library'
            target.write_bytes(b'not an ELF')
            link = root / 'link'
            link.symlink_to(target.name)
            result = loader_diagnostics.file_metadata(str(link))
            self.assertEqual(result['sha256'], hashlib.sha256(target.read_bytes()).hexdigest())
            self.assertEqual(result['resolved'], str(target))
            self.assertEqual(result['components'][-1]['target'], target.name)
            self.assertIn('elf_error', result)
            self.assertIsNone(result['open_errno'])
            info = target.stat()
            self.assertEqual(result['opened_mode'], oct(info.st_mode))
            self.assertEqual(result['opened_uid'], info.st_uid)
            self.assertEqual(result['opened_gid'], info.st_gid)
            self.assertNotIn('not an ELF', json.dumps(result))
            target.unlink()
            self.assertEqual(loader_diagnostics.file_metadata(str(link))['open_errno'], 2)
            with patch.object(os, 'open', side_effect=PermissionError(13, 'fixture denied')):
                denied = loader_diagnostics.file_metadata(str(link))
            self.assertEqual(denied['open_errno'], 13)
            self.assertNotIn('sha256', denied)
            os.mkfifo(target)
            self.assertIn('type/size limit', loader_diagnostics.file_metadata(str(target))['error'])

    def test_confined_loader_records_resolution_failures_without_fallback(self):
        inventory = {'files': [{'path': '/usr/bin/sudo', 'elf': {'interpreter': '/lib64/native-loader'}},
                               {'path': '/usr/libexec/sudo/libsudo_util.so.0'},
                               {'path': '/etc/sudoers'}]}
        with patch.object(loader_diagnostics, 'file_metadata', side_effect=lambda p, **kw: {'path': p, 'open_errno': 13}), \
                patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, b'', b'not found')) as run:
            result = loader_diagnostics.confined_record(inventory)
        self.assertEqual(result['loader_list']['returncode'], 1)
        self.assertEqual(result['loader_list']['stderr'], 'not found')
        self.assertEqual(result['files'][1]['open_errno'], 13)
        self.assertEqual(result['files'][2], {'path': '/etc/sudoers', 'open_errno': 13})
        self.assertEqual(run.call_args.args[0], ['/lib64/native-loader', '--list', '/usr/bin/sudo'])
        self.assertEqual(run.call_args.kwargs['env'], {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'LD_DEBUG': 'libs'})
        self.assertEqual(run.call_count, 1)
        with patch.object(subprocess, 'run', side_effect=subprocess.TimeoutExpired(['loader'], 5, stderr=b'timed out')):
            self.assertTrue(loader_diagnostics.process_record(['loader'])['timeout'])
        with patch.object(subprocess, 'run', side_effect=FileNotFoundError(2, 'absent')):
            self.assertEqual(loader_diagnostics.process_record(['loader'])['errno'], 2)
        with patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, b'x' * 40000, b'')):
            result = loader_diagnostics.process_record(['loader'])
            self.assertTrue(result['truncated'])
            self.assertEqual(len(result['stdout']), loader_diagnostics.MAX_OUTPUT)

    def test_sudo_include_directory_observes_entries_errors_and_limits(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root = Path(temporary)
            (root / 'fragment').write_text('configuration bytes must not be emitted')
            real_open = os.open
            descriptors = []
            def opened(name, flags):
                self.assertEqual(name, '/etc/sudoers.d')
                fd = real_open(root, flags)
                descriptors.append(fd)
                return fd
            with patch.object(os, 'open', side_effect=opened):
                result = loader_diagnostics.sudoers_directory_metadata()
                self.assertEqual(result['entries'], ['fragment'])
                self.assertIsNone(result['open_errno'])
                self.assertEqual(result['opened_uid'], root.stat().st_uid)
                self.assertNotIn('configuration bytes', json.dumps(result))
            for i in range(64):
                (root / str(i)).touch()
            with patch.object(os, 'open', side_effect=opened):
                limited = loader_diagnostics.sudoers_directory_metadata()
                self.assertTrue(limited['truncated'])
                self.assertEqual(len(limited['entries']), 64)
            for fd in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(fd)
            for code in (2, 13, 20, 40):
                with self.subTest(errno=code), \
                        patch.object(os, 'open', side_effect=OSError(code, 'fixture error')):
                    result = loader_diagnostics.sudoers_directory_metadata()
                self.assertEqual(result, {'path': '/etc/sudoers.d', 'open_errno': code})
            # Iteration failures remain explicit and still close the opened FD.
            with patch.object(os, 'open', side_effect=opened), \
                    patch.object(os, 'scandir', side_effect=PermissionError(13, 'fixture denied')):
                self.assertEqual(loader_diagnostics.sudoers_directory_metadata()['open_errno'], 13)
            with self.assertRaises(OSError):
                os.fstat(descriptors[-1])

    def test_sudo_plugin_inventory_retains_missing_and_denied_observations(self):
        # The plugin and configuration are absent from sudo's DT_NEEDED.
        # Inspect both even when the library scan finds no entries.
        paths = ('/usr/libexec/sudo/sudoers.so', '/etc/sudoers')
        with patch.object(os, 'walk', return_value=[]), \
                patch.object(loader_diagnostics, 'sudoers_directory_metadata',
                             return_value={'path': '/etc/sudoers.d', 'open_errno': 2}), \
                patch.object(loader_diagnostics, 'file_metadata',
                             side_effect=lambda p, **kw: {'path': p, 'open_errno': 2}):
            inventory = loader_diagnostics.image_inventory()
        self.assertEqual(inventory['sudoers_include_directory']['open_errno'], 2)
        for path in paths:
            self.assertIn({'path': path, 'open_errno': 2}, inventory['files'])
            self.assertEqual(len([r for r in inventory['files'] if r['path'] == path]), 1)
        with patch.object(loader_diagnostics, 'file_metadata',
                          side_effect=lambda p, **kw: {'path': p, 'open_errno': 13}), \
                patch.object(loader_diagnostics, 'sudoers_directory_metadata',
                             return_value={'path': '/etc/sudoers.d', 'open_errno': 13}), \
                patch.object(loader_diagnostics, 'process_record') as execute:
            confined = loader_diagnostics.confined_record(inventory)
        self.assertEqual(confined['sudoers_include_directory']['open_errno'], 13)
        for path in paths:
            self.assertIn({'path': path, 'open_errno': 13}, confined['files'])
        execute.assert_not_called()

    def test_probe_passes_image_inventory_through_policy_activation(self):
        # Exercise the real orchestration up to the native launch. Kernel and
        # Docker doubles supply no physical evidence; the saved payload must
        # contain the image inventory, never the subsequently loaded policy one.
        inventory = {'files': [{'path': '/usr/bin/sudo', 'elf': {
            'interpreter': '/lib64/native-loader'}}], 'scan_errors': [],
            'pam': {'files': [{'path': '/etc/pam.d/sudo'}, {'path': '/etc/pam.d/common-auth'}]},
            'pam_libraries': {'files': [{'path': '/lib/security/pam_unix.so', 'open_errno': 2}]},
            'packages': {'parsed': {'packages': {'sudo': {'Version': 'fixture-version'}}}}}
        cid = 'a' * 64
        daemon = {'cgroup': '/fixture.slice', 'daemon_id': 'fixture-daemon',
                  'image_id': 'sha256:' + 'b' * 64}
        control = {'cgroup': '/fixture.slice/docker-' + cid + '.scope'}
        launched = []
        class LaunchBoundary(Exception):
            pass
        def command(argv):
            if argv[:2] == ['docker', 'create']:
                return cid.encode()
            if argv[:2] in (['docker', 'start'], ['docker', 'rm']):
                return b''
            if argv[:2] == ['docker', 'inspect']:
                return b'{"Pid":123}'
            if argv[:3] == ['docker', 'exec', '--detach']:
                launched.append(json.loads(argv[-1]))
                raise LaunchBoundary()
            self.assertEqual(argv[-1], namespace.TOOLS + '/loader_diagnostics.py')
            return json.dumps(inventory).encode()
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            root = Path(directory)
            with patch.object(confinement, 'stage_tools', return_value=(root, {})), \
                    patch.object(preflight, 'wait_for', return_value=True), \
                    patch.object(confinement, 'process_identity', return_value=control), \
                    patch.object(confinement, 'ExecutionSubtree'), \
                    patch.object(lifecycle, 'register', return_value='fixture-unit'), \
                    self.assertRaises(LaunchBoundary):
                confinement.probe(command, root, daemon)
            self.assertEqual(len(launched), 1)
            self.assertEqual(launched[0], load(root / 'namespace-spec.json'))
            assignment = ast.parse(launched[0]['argv'][-1]).body[0]
            supplied = ast.literal_eval(assignment.value)
            self.assertEqual(supplied, {
                'files': inventory['files'], 'pam': inventory['pam'],
                'pam_libraries': {'files': [{'path': '/lib/security/pam_unix.so'}]}})
            self.assertEqual(inventory, load(root / 'namespace/loader-image.json'))
            self.assertNotEqual(supplied, load(root / 'namespace-project/inventory.json'))
            # Consume the actual diagnostic API, so a wrong-shaped inventory
            # fails here rather than only after a native launch.
            with patch.object(loader_diagnostics, 'file_metadata', side_effect=lambda p, **kw: {'path': p}), \
                    patch.object(loader_diagnostics, 'process_record', return_value={'fixture': True}):
                observed = loader_diagnostics.confined_record(supplied)
            self.assertEqual(observed['files'], [{'path': '/usr/bin/sudo'}])
            self.assertEqual(observed['pam'], inventory['pam'])
            self.assertEqual(observed['pam_libraries'], supplied['pam_libraries'])
            receipt = load(root / 'namespace-diagnostics.json')
            self.assertIn('namespace/loader-image.json', receipt['records'])
            self.assertIn('namespace/probe/sudo-exec.json', receipt['missing'])

    def test_pam_diagnostics_follow_bounded_image_includes_without_emitting_contents(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root = Path(temporary)
            (root / 'sudo').write_text('@include common-auth\nauth include common-auth\n'
                                      'session substack common-session\n')
            (root / 'other').write_text('auth required pam_deny.so\n')
            (root / 'common-auth').write_text('@include sudo\n'
                'auth [success=1 default=ignore] pam_unix.so private-module-option\n')
            (root / 'common-session').write_text('session required pam_permit.so\n')
            with patch.object(loader_diagnostics, 'PAM_ROOT', str(root)):
                inventory = loader_diagnostics.pam_inventory()
                self.assertFalse(inventory['file_limit_exceeded'])
                self.assertEqual({Path(r['path']).name for r in inventory['files']},
                                 {'sudo', 'other', 'common-auth', 'common-session'})
                self.assertEqual(len(inventory['files']), 4)  # Includes/cycles are deduplicated.
                for row in inventory['files']:
                    self.assertIsNone(row['open_errno'])
                    self.assertEqual(row['sha256'], hashlib.sha256(Path(row['path']).read_bytes()).hexdigest())
                    self.assertEqual(row['resolved'], row['path'])
                    self.assertEqual(row['opened_uid'], root.stat().st_uid)
                    self.assertEqual(row['parsed']['errors'], [])
                self.assertNotIn('private-module-option', json.dumps(inventory))
                common = next(r for r in inventory['files'] if r['path'].endswith('/common-auth'))
                self.assertEqual(common['parsed']['modules'],
                    [{'line': 2, 'type': 'auth', 'module': 'pam_unix.so'}])
                # Denied top-level access cannot erase trusted include paths.
                with patch.object(os, 'open', side_effect=PermissionError(13, 'denied')):
                    confined = loader_diagnostics.confined_record({'pam': inventory,
                        'files': [{'path': '/usr/bin/sudo'}]})
                self.assertEqual([r['path'] for r in confined['pam']['files']],
                                 [r['path'] for r in inventory['files']])
                self.assertTrue(all(r['open_errno'] == 13 for r in confined['pam']['files']))
                self.assertEqual([r['path'] for r in confined['hostname_configuration']],
                                 list(loader_diagnostics.HOST_FILES))

    def test_pam_diagnostics_retain_missing_malformed_and_limit_observations(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root = Path(temporary) / 'pam'
            root.mkdir()
            outside = Path(temporary) / 'synthetic-secret'
            outside.write_text('synthetic bytes must not be read')
            with patch.object(loader_diagnostics, 'PAM_ROOT', str(root)):
                missing = loader_diagnostics.pam_inventory()
                self.assertEqual([r['open_errno'] for r in missing['files']], [2, 2])
                (root / 'sudo').write_bytes(b'\xff')
                (root / 'other').write_bytes(b'x' * (loader_diagnostics.MAX_PAM_FILE + 1))
                invalid = loader_diagnostics.pam_inventory()
                self.assertIn('parse_error', invalid['files'][0])
                self.assertIn('type/size limit', invalid['files'][1]['error'])
                (root / 'sudo').write_text('@include first\n@include second\n')
                (root / 'other').write_text('@include third\n')
                with patch.object(loader_diagnostics, 'MAX_PAM_FILES', 3):
                    limited = loader_diagnostics.pam_inventory()
                self.assertTrue(limited['file_limit_exceeded'])
                self.assertEqual(len(limited['files']), 3)
                self.assertEqual(limited['files'][-1]['open_errno'], 2)
                # A symlink outside the selected config root is never opened.
                (root / 'sudo').unlink()
                (root / 'sudo').symlink_to(outside)
                real_open = os.open
                with patch.object(os, 'open', wraps=real_open) as opened:
                    linked = loader_diagnostics.file_metadata(str(root / 'sudo'),
                        parser=loader_diagnostics.pam_includes, beneath=str(root))
                opened.assert_not_called()
                self.assertIn('outside configuration root', linked['error'])
                self.assertNotIn('sha256', linked)
        parsed = loader_diagnostics.pam_includes(
            b'# @include ignored\n@include\n@include ../../shadow\n@include /etc/shadow\n'
            b'session substack\nunknown entry\n@include /etc/pam.d/common-auth\n'
            b'auth include \\\ncommon-account\n')
        self.assertEqual(parsed['includes'], ['/etc/pam.d/common-auth', '/etc/pam.d/common-account'])
        self.assertEqual(len(parsed['errors']), 5)
        self.assertNotIn('shadow', json.dumps(parsed))
        with patch.object(loader_diagnostics, 'MAX_PAM_FILES', 2):
            self.assertEqual(loader_diagnostics.pam_includes(b'@include a\n@include b\n')['errors'], [])
            parsed = loader_diagnostics.pam_includes(b'@include a\n@include b\n@include c\n')
        self.assertEqual(len(parsed['includes']), 2)
        self.assertEqual(parsed['errors'][-1]['error'], 'include limit')
        parsed = loader_diagnostics.pam_includes(b'# line\n' * 1025)
        self.assertEqual(parsed['errors'][-1]['error'], 'line limit')
        parsed = loader_diagnostics.pam_includes(b'@include\n' * 100)
        self.assertEqual(len(parsed['errors']), 33)
        self.assertEqual(parsed['errors'][-1]['error'], 'error limit')

    def test_pam_module_discovery_retains_types_without_arguments_or_execution(self):
        parsed = loader_diagnostics.pam_includes(
            b'account [success=1 new_authtok_reqd=done default=ignore] pam_unix.so secret-option\n'
            b'-session optional /lib/x86_64-linux-gnu/security/pam_systemd.so\n'
            b'auth required \\\npam_deny.so # comment\n'
            b'account include common-account\n')
        self.assertEqual(parsed['errors'], [])
        self.assertEqual(parsed['modules'], [
            {'line': 1, 'type': 'account', 'module': 'pam_unix.so'},
            {'line': 2, 'type': 'session', 'module': '/lib/x86_64-linux-gnu/security/pam_systemd.so'},
            {'line': 3, 'type': 'auth', 'module': 'pam_deny.so'}])
        self.assertEqual(parsed['includes'], ['/etc/pam.d/common-account'])
        self.assertNotIn('secret-option', json.dumps(parsed))
        for entry in ('account [success=1 pam_unix.so', 'account invented pam_unix.so',
                      'account required /etc/shadow', 'account required ../pam_unix.so',
                      'account required /lib/security/../pam_unix.so',
                      'account required pam_unix.so/secret', 'account required'):
            with self.subTest(entry=entry):
                invalid = loader_diagnostics.pam_includes(entry.encode())
                self.assertEqual(invalid['modules'], [])
                self.assertEqual(len(invalid['errors']), 1)
                self.assertNotIn('shadow', json.dumps(invalid))
        with patch.object(loader_diagnostics, 'MAX_PAM_MODULES', 1):
            limited = loader_diagnostics.pam_includes(
                b'account required pam_unix.so\naccount required pam_deny.so\n')
        self.assertEqual(len(limited['modules']), 1)
        self.assertEqual(limited['errors'][-1]['error'], 'module limit')

    def test_pam_library_inventory_retains_candidates_cycles_errors_and_limits(self):
        pam = {'files': [{'parsed': {'modules': [
            {'module': 'pam_unix.so'}, {'module': 'pam_unix.so'}]}}]}
        module = '/lib/x86_64-linux-gnu/security/pam_unix.so'
        dependency = '/lib/x86_64-linux-gnu/libpam.so.0'
        def metadata(path, **kwargs):
            self.assertEqual(kwargs['beneath'], ('/usr/lib', '/lib'))
            if path in (module, dependency):
                return {'path': path, 'sha256': 'a' * 64, 'open_errno': None,
                        'elf': {'needed': ['libpam.so.0', '/etc/shadow']}}
            return {'path': path, 'open_errno': 2}
        with patch.object(loader_diagnostics, 'file_metadata', side_effect=metadata), \
                patch.object(loader_diagnostics, 'process_record') as execute:
            result = loader_diagnostics.pam_library_inventory(pam)
            self.assertEqual(len(result['files']), 8)
            self.assertEqual(len({r['path'] for r in result['files']}), 8)
            self.assertEqual(sum(r.get('open_errno') == 2 for r in result['files']), 6)
            self.assertFalse(result['file_limit_exceeded'])
            self.assertEqual(len(result['errors']), 2)
            self.assertNotIn('shadow', json.dumps(result))
            with patch.object(loader_diagnostics, 'MAX_LIBRARY_FILES', 4):
                limited = loader_diagnostics.pam_library_inventory(pam)
            self.assertTrue(limited['file_limit_exceeded'])
            self.assertEqual(len(limited['files']), 4)
            execute.assert_not_called()
        # Confinement observes the image's full candidate list even if every
        # module is inaccessible. It cannot rediscover a smaller passing graph.
        with patch.object(loader_diagnostics, 'file_metadata',
                          side_effect=lambda p, **kw: {'path': p, 'open_errno': 13}), \
                patch.object(loader_diagnostics, 'process_record') as execute:
            confined = loader_diagnostics.confined_record({
                'files': [{'path': '/usr/bin/sudo'}], 'pam_libraries': result})
        self.assertEqual(confined['pam_libraries']['files'],
                         [{'path': r['path'], 'open_errno': 13} for r in result['files']])
        execute.assert_not_called()

    def test_pam_library_links_outside_runtime_are_not_opened(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root = Path(temporary)
            secret = root / 'synthetic-account-data'
            secret.write_text('must never read these bytes')
            link = root / 'pam_fixture.so'
            link.symlink_to(secret)
            with patch.object(os, 'open', wraps=os.open) as opened:
                row = loader_diagnostics.file_metadata(str(link), beneath=('/usr/lib', '/lib'))
            opened.assert_not_called()
            self.assertIn('outside configuration root', row['error'])
            self.assertNotIn('sha256', row)
            self.assertNotIn('must never read', json.dumps(row))

    def test_pam_inventory_launch_projection_stays_bounded_without_pruning_paths(self):
        inventory = {'files': [{'path': '/usr/bin/sudo', 'elf': {
            'interpreter': '/lib64/ld-linux-x86-64.so.2'}}],
            'pam_libraries': {'files': [
                {'path': '/usr/lib/x86_64-linux-gnu/' + 'x' * 120 + str(i),
                 'components': ['metadata' * 1024], 'open_errno': 13}
                for i in range(loader_diagnostics.MAX_LIBRARY_FILES)]}}
        before = json.dumps(inventory, sort_keys=True)
        projected = loader_diagnostics.confined_inventory(inventory)
        self.assertEqual([r['path'] for r in projected['pam_libraries']['files']],
                         [r['path'] for r in inventory['pam_libraries']['files']])
        self.assertEqual(projected['files'], inventory['files'])
        self.assertEqual(json.dumps(inventory, sort_keys=True), before)
        spec = {**self.spec(), 'argv': ['/usr/bin/python3', '-I', '-S', '-c',
            'LOADER_INVENTORY = ' + repr(projected) + '\n' + confinement.PAYLOAD]}
        namespace.validate(spec)
        self.assertLess(len(json.dumps(spec).encode()), 131072)

    def test_package_diagnostics_emit_only_selected_identity_fields(self):
        data = (b'Package: sudo\nStatus: install ok installed\nArchitecture: amd64\n'
                b'Version: 1.9.15p5-3ubuntu5.24.04.1\nDescription: private description\n\n'
                b'Package: libaudit1\nStatus: install ok installed\nArchitecture: amd64\n'
                b'Version: 1:3.0.7-1build1\nDescription: private description\n\n'
                b'Package: unrelated\nVersion: 999\nDescription: not selected\n\n')
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            path = Path(temporary) / 'status'
            path.write_bytes(data)
            row = loader_diagnostics.file_metadata(str(path), parser=loader_diagnostics.package_fields)
            self.assertEqual(row['sha256'], hashlib.sha256(data).hexdigest())
            self.assertEqual(row['parsed']['packages']['sudo']['Version'], '1.9.15p5-3ubuntu5.24.04.1')
            self.assertEqual(row['parsed']['packages']['libaudit1']['Version'], '1:3.0.7-1build1')
            self.assertEqual(row['parsed']['missing'],
                             sorted(set(loader_diagnostics.PACKAGES) - {'sudo', 'libaudit1'}))
            for omitted in ('private description', 'unrelated', 'not selected'):
                self.assertNotIn(omitted, json.dumps(row))
            for malformed in (data + data, b'\xff', b'Package: sudo\nVersion: missing-fields\n'):
                path.write_bytes(malformed)
                self.assertIn('parse_error', loader_diagnostics.file_metadata(
                    str(path), parser=loader_diagnostics.package_fields))
            path.unlink()
            self.assertEqual(loader_diagnostics.file_metadata(str(path),
                parser=loader_diagnostics.package_fields)['open_errno'], 2)
            with patch.object(os, 'open', side_effect=PermissionError(13, 'denied')):
                self.assertEqual(loader_diagnostics.file_metadata(str(path),
                    parser=loader_diagnostics.package_fields)['open_errno'], 13)

    def test_account_hook_refuses_visible_or_uncertain_store_without_loading_modules(self):
        # No real account files, PAM libraries or native modules are accessed.
        with patch.object(os, 'getuid', return_value=0), \
                patch.object(os, 'geteuid', return_value=0), \
                patch.object(loader_diagnostics.ctypes, 'CDLL') as load_module, \
                patch.object(sys, 'stderr', new_callable=io.StringIO) as progress, \
                patch('builtins.open') as opened:
            for error in (None, PermissionError(13, 'denied'), OSError(5, 'I/O')):
                with self.subTest(error=error), patch.object(os, 'lstat', side_effect=error) as metadata:
                    result = loader_diagnostics.pam_account_hook()
                self.assertIn('unavailable', result)
                self.assertNotIn('pam_start', result)
                metadata.assert_called_once_with('/etc/shadow')
            with patch.object(os, 'getuid', return_value=1000), patch.object(os, 'lstat') as metadata:
                self.assertIn('fixture root', loader_diagnostics.pam_account_hook()['unavailable'])
                metadata.assert_not_called()
            load_module.assert_not_called()
            opened.assert_not_called()
            self.assertEqual([json.loads(line) for line in progress.getvalue().splitlines()],
                             [{'pam_account_stage': 'entry'}] * 4)

    def test_account_hook_keeps_raw_status_refuses_conversations_and_ends_handle(self):
        import ctypes
        for start_status, account_status in ((0, 0), (0, 4), (0, 9), (0, 19), (4, None)):
            pam = unittest.mock.Mock(spec=['pam_start', 'pam_acct_mgmt', 'pam_end'])
            def start(service, user, conversation, handle):
                self.assertEqual((service, user), (b'sudo', b'root'))
                # Deliberately invalid message pointers must never be read.
                self.assertEqual(conversation._obj.conv(1, 1, 1, 1), 19)
                handle._obj.value = 123
                return start_status
            pam.pam_start.side_effect = start
            account_errno = 1 if account_status == 4 else 0
            def account(handle, flags):
                self.assertEqual(ctypes.get_errno(), 0)
                ctypes.set_errno(account_errno)
                return account_status
            def end(handle, status):
                ctypes.set_errno(22)  # Cleanup must not replace account errno.
                return 0
            pam.pam_end.side_effect = end
            pam.pam_acct_mgmt.side_effect = account
            with self.subTest(start=start_status, account=account_status), \
                    patch.object(os, 'getuid', return_value=0), \
                    patch.object(os, 'geteuid', return_value=0), \
                    patch.object(os, 'lstat', side_effect=FileNotFoundError(2, 'absent')), \
                    patch.object(ctypes, 'CDLL', return_value=pam) as loaded, \
                    patch.object(sys, 'stderr', new_callable=io.StringIO) as progress, \
                    patch('builtins.open') as opened:
                result = loader_diagnostics.pam_account_hook()
            rows = [json.loads(line) for line in progress.getvalue().splitlines()]
            stages = ['entry', 'libpam_load_before', 'libpam_load_after',
                      'pam_start_before', 'pam_start_after']
            if start_status == 0:
                stages += ['pam_account_before', 'pam_account_after',
                           'pam_end_before', 'pam_end_after',
                           'libaudit_load_before', 'libaudit_load_after']
            self.assertEqual([row['pam_account_stage'] for row in rows], stages)
            self.assertEqual([row['status'] for row in rows if 'status' in row],
                             [start_status, account_status, 0] if start_status == 0 else [start_status])
            self.assertLess(len(progress.getvalue()), 1024)
            self.assertEqual(result['pam_start'], start_status)
            self.assertEqual(result['conversations_refused'], 1)
            self.assertEqual(loaded.call_args_list, [unittest.mock.call(
                '/lib/x86_64-linux-gnu/libpam.so.0', use_errno=True)] +
                ([unittest.mock.call('/lib/x86_64-linux-gnu/libaudit.so.1', use_errno=True)]
                 if start_status == 0 else []))
            opened.assert_not_called()
            if start_status == 0:
                self.assertEqual(result['pam_account'], account_status)
                self.assertEqual(result['pam_account_errno'], account_errno)
                self.assertIn({'pam_account_stage': 'pam_account_after',
                               'status': account_status, 'errno': account_errno}, rows)
                args = pam.pam_acct_mgmt.call_args.args
                self.assertEqual(args[0].value, 123)
                self.assertEqual(args[1:], (0x8000,))
                self.assertEqual(pam.pam_end.call_args.args[1], account_status)
                self.assertIn('unavailable', result['audit'])
            else:
                self.assertNotIn('pam_account', result)
                self.assertNotIn('audit', result)
                pam.pam_acct_mgmt.assert_not_called()
                pam.pam_end.assert_not_called()
            self.assertNotIn('pam_authenticate', [c[0] for c in pam.mock_calls])

    def test_account_hook_library_errors_remain_diagnostic_failures(self):
        with patch.object(os, 'getuid', return_value=0), \
                patch.object(os, 'geteuid', return_value=0), \
                patch.object(sys, 'stderr', new_callable=io.StringIO) as progress, \
                patch.object(os, 'lstat', side_effect=FileNotFoundError(2, 'absent')):
            for error in (OSError('library absent'), AttributeError('symbol absent')):
                with self.subTest(error=error), \
                        patch.object(loader_diagnostics.ctypes, 'CDLL', side_effect=error):
                    result = loader_diagnostics.pam_account_hook()
                self.assertIn('unavailable', result)
                self.assertNotIn('pam_account', result)
            pam = unittest.mock.Mock(spec=['pam_start', 'pam_acct_mgmt', 'pam_end'])
            pam.pam_start.return_value = 0
            pam.pam_end.return_value = 4
            pam.pam_acct_mgmt.side_effect = OSError('fixture hook failure')
            with patch.object(loader_diagnostics.ctypes, 'CDLL', return_value=pam):
                result = loader_diagnostics.pam_account_hook()
            self.assertIn('unavailable', result)
            self.assertEqual(result['pam_end'], 4)
            pam.pam_end.assert_called_once()
            # A successful account return must survive cleanup failure too.
            progress.seek(0)
            progress.truncate()
            pam.pam_acct_mgmt.side_effect = None
            pam.pam_acct_mgmt.return_value = 0
            pam.pam_end.side_effect = OSError('fixture cleanup failure')
            with patch.object(loader_diagnostics.ctypes, 'CDLL', return_value=pam):
                result = loader_diagnostics.pam_account_hook()
            self.assertEqual(result['pam_account'], 0)
            self.assertIn('unavailable', result)
            self.assertNotIn('pam_end', result)
            self.assertEqual([json.loads(line) for line in progress.getvalue().splitlines()][-4:], [
                {'pam_account_stage': 'pam_account_after', 'status': 0, 'errno': 0},
                {'pam_account_stage': 'pam_end_before'},
                {'pam_account_stage': 'libaudit_load_before'},
                {'pam_account_stage': 'libaudit_load_after'}])

    def test_account_hook_observes_audit_open_and_closes_successful_descriptors(self):
        import ctypes
        for fd, audit_errno, close_errno in ((0, 0, None), (7, 0, None),
                                             (-1, 1, None), (7, 0, 5)):
            pam = unittest.mock.Mock(spec=['pam_start', 'pam_acct_mgmt', 'pam_end'])
            pam.pam_start.return_value = 0
            def account(*args):
                ctypes.set_errno(1)
                return 4
            pam.pam_acct_mgmt.side_effect = account
            pam.pam_end.return_value = 0
            audit = unittest.mock.Mock(spec=['audit_open'])
            def audit_open():
                self.assertEqual(ctypes.get_errno(), 0)
                pam.pam_end.assert_called_once()
                ctypes.set_errno(audit_errno)
                return fd
            audit.audit_open.side_effect = audit_open
            def close(opened_fd):
                self.assertEqual(opened_fd, fd)
                ctypes.set_errno(22)
                if close_errno is not None:
                    raise OSError(close_errno, 'fixture close failure')
            with self.subTest(fd=fd, error=audit_errno, close_error=close_errno), \
                    patch.object(os, 'getuid', return_value=0), \
                    patch.object(os, 'geteuid', return_value=0), \
                    patch.object(os, 'lstat', side_effect=FileNotFoundError(2, 'absent')), \
                    patch.object(ctypes, 'CDLL', side_effect=[pam, audit]) as loaded, \
                    patch.object(os, 'close', side_effect=close) as closed, \
                    patch.object(sys, 'stderr', new_callable=io.StringIO) as progress:
                result = loader_diagnostics.pam_account_hook()
            self.assertEqual(result['pam_account'], 4)
            self.assertEqual(result['pam_account_errno'], 1)
            self.assertEqual(result['pam_end'], 0)
            self.assertEqual(loaded.call_args_list, [unittest.mock.call(
                '/lib/x86_64-linux-gnu/libpam.so.0', use_errno=True), unittest.mock.call(
                '/lib/x86_64-linux-gnu/libaudit.so.1', use_errno=True)])
            audit.audit_open.assert_called_once_with()
            self.assertEqual(audit.audit_open.argtypes, [])
            self.assertIs(audit.audit_open.restype, ctypes.c_int)
            self.assertEqual(result['audit']['returncode'], fd)
            self.assertEqual(result['audit']['errno'], audit_errno)
            rows = [json.loads(line) for line in progress.getvalue().splitlines()]
            self.assertIn({'pam_account_stage': 'audit_open_after',
                           'status': fd, 'errno': audit_errno}, rows)
            if fd >= 0:
                closed.assert_called_once_with(fd)
                self.assertEqual(result['audit']['close_errno'], close_errno)
            else:
                closed.assert_not_called()
                self.assertNotIn('close_errno', result['audit'])
            self.assertLess(len(progress.getvalue()), 2048)

        # Missing audit library/symbol must preserve the completed PAM result.
        for error in (OSError('library absent'), AttributeError('symbol absent')):
            with self.subTest(error=error), patch.object(os, 'getuid', return_value=0), \
                    patch.object(os, 'geteuid', return_value=0), \
                    patch.object(os, 'lstat', side_effect=FileNotFoundError(2, 'absent')), \
                    patch.object(ctypes, 'CDLL', side_effect=[pam, error]), \
                    patch.object(os, 'close') as closed, \
                    patch.object(sys, 'stderr', new_callable=io.StringIO):
                result = loader_diagnostics.pam_account_hook()
            self.assertEqual(result['pam_account'], 4)
            self.assertEqual(result['pam_account_errno'], 1)
            self.assertIn('unavailable', result['audit'])
            self.assertNotIn('returncode', result['audit'])
            closed.assert_not_called()

    def test_account_progress_survives_child_timeout_and_exit(self):
        # Real pipes/termination, fake native calls only: no PAM, account stores,
        # Docker, sockets or namespace operations. Buffered stderr ensures this
        # tests explicit flushing, not Python's default line-buffered stderr.
        script = '''
import io, os, runpy, sys, time
from unittest.mock import Mock, patch
hook = runpy.run_path(sys.argv[1])['pam_account_hook']
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, line_buffering=False, write_through=False)
pam = Mock(spec=['pam_start', 'pam_acct_mgmt', 'pam_end'])
pam.pam_start.return_value = 0
pam.pam_acct_mgmt.return_value = 0
pam.pam_end.return_value = 0
audit = Mock(spec=['audit_open'])
if sys.argv[2] == 'timeout':
    pam.pam_acct_mgmt.side_effect = lambda *args: time.sleep(60)
elif sys.argv[2] == 'exit':
    pam.pam_end.side_effect = lambda *args: os._exit(23)
elif sys.argv[2] == 'audit-timeout':
    audit.audit_open.side_effect = lambda: time.sleep(60)
else:
    audit.audit_open.side_effect = lambda: os._exit(23)
with patch('os.getuid', return_value=0), patch('os.geteuid', return_value=0), \\
        patch('os.lstat', side_effect=FileNotFoundError(2, 'fixture absent')), \\
        patch('ctypes.CDLL', side_effect=[pam, audit]):
    hook()
'''
        for mode in ('timeout', 'exit', 'audit-timeout', 'audit-exit'):
            with self.subTest(mode=mode):
                result = loader_diagnostics.process_record(
                    [sys.executable, '-I', '-S', '-c', script,
                     loader_diagnostics.__file__, mode], loader_debug=False)
                self.assertEqual(result['stdout'], '')
                self.assertFalse(result['truncated'])
                rows = [json.loads(line) for line in result['stderr'].splitlines()]
                self.assertEqual(rows[0], {'pam_account_stage': 'entry'})
                self.assertIn({'pam_account_stage': 'pam_start_after', 'status': 0}, rows)
                if mode.endswith('timeout'):
                    self.assertTrue(result['timeout'])
                else:
                    self.assertEqual(result['returncode'], 23)
                if mode.startswith('audit-'):
                    self.assertIn({'pam_account_stage': 'pam_account_after',
                                   'status': 0, 'errno': 0}, rows)
                    self.assertIn({'pam_account_stage': 'pam_end_after', 'status': 0}, rows)
                    self.assertEqual(rows[-1], {'pam_account_stage': 'audit_open_before'})
                elif mode == 'timeout':
                    self.assertEqual(rows[-1], {'pam_account_stage': 'pam_account_before'})
                else:
                    self.assertEqual(rows[-2:], [
                        {'pam_account_stage': 'pam_account_after', 'status': 0, 'errno': 0},
                        {'pam_account_stage': 'pam_end_before'}])

    def test_account_process_is_bounded_and_retains_crash_timeout_and_missing_runtime(self):
        for status in (0, 1, -11):
            with self.subTest(status=status), patch.object(subprocess, 'run', return_value=
                    subprocess.CompletedProcess([], status, b'x' * 40000, b'y' * 40000)) as run:
                result = loader_diagnostics.account_process_record()
            self.assertEqual(result['returncode'], status)
            self.assertTrue(result['truncated'])
            self.assertEqual(len(result['stdout']), loader_diagnostics.MAX_OUTPUT)
            self.assertEqual(len(result['stderr']), loader_diagnostics.MAX_OUTPUT)
            self.assertEqual(run.call_args.args[0], ['/usr/bin/python3', '-I', '-S',
                '/ptw-native-tools/loader_diagnostics.py', '--pam-account-hook'])
            self.assertEqual(run.call_args.kwargs['timeout'], 5)
            self.assertEqual(run.call_args.kwargs['env'], {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        with patch.object(subprocess, 'run', side_effect=subprocess.TimeoutExpired(
                ['fixture'], 5, output=b'x' * 40000, stderr=b'timed out')):
            result = loader_diagnostics.account_process_record()
        self.assertTrue(result['timeout'])
        self.assertTrue(result['truncated'])
        self.assertEqual(len(result['stdout']), loader_diagnostics.MAX_OUTPUT)
        self.assertEqual(result['stderr'], 'timed out')
        with patch.object(subprocess, 'run', side_effect=subprocess.TimeoutExpired(['fixture'], 5)):
            result = loader_diagnostics.account_process_record()
        self.assertTrue(result['timeout'])
        self.assertFalse(result['truncated'])
        self.assertEqual((result['stdout'], result['stderr']), ('', ''))
        with patch.object(subprocess, 'run', side_effect=FileNotFoundError(2, 'absent')):
            self.assertEqual(loader_diagnostics.account_process_record()['errno'], 2)

    def test_sudo_failure_retains_diagnostics_before_unchanged_assertion(self):
        # Execute the actual diagnostic/sudo section with a failed process
        # double, never execute sudo or the native payload in the coding shell.
        section = confinement.PAYLOAD.split('diagnostics = ', 1)[1].split('with socket.', 1)[0]
        section = 'diagnostics = ' + section
        outputs = {}
        import io
        class Receipt(io.StringIO):
            def write(self, text):
                outputs[self.name] = json.loads(text)
                return super().write(text)
        def opened(name, mode):
            self.assertEqual(mode, 'w')
            stream = Receipt()
            stream.name = name
            return stream
        for error, account_failure in (
                ('unable to load /usr/libexec/sudo/sudoers.so: Permission denied', False),
                ('unable to open /etc/sudoers: Permission denied', False),
                ('/etc/sudoers.d: Permission denied', False),
                ('unable to initialize PAM: Critical error - immediate abort', False),
                ('a password is required', False),
                ('PAM account management error: Operation not permitted', True),
                ('account validation failure, is your account locked?', True),
                ('unable to resolve host fixture: Temporary failure in name resolution\n'
                 'sudo: account validation failure, is your account locked?\n'
                 'sudo: a password is required\n', True)):
            outputs.clear()
            account = unittest.mock.Mock(return_value={'returncode': 0, 'stdout': '{"pam_account": 9}'})
            failure = subprocess.CompletedProcess(['sudo'], 1, '', 'sudo: ' + error)
            with self.subTest(error=error), \
                    patch('runpy.run_path', return_value={
                        'confined_record': lambda _: {'fixture': 'diagnostic'},
                        'account_process_record': account}), \
                    patch.object(subprocess, 'run', return_value=failure), patch('builtins.open', side_effect=opened):
                with self.assertRaises(AssertionError) as raised:
                    exec(section, {'json': json, 'runpy': __import__('runpy'), 'subprocess': subprocess,
                                   'sys': sys, 'LOADER_INVENTORY': {}, 'observed': {}})
                self.assertEqual(str(raised.exception), failure.stderr)
            self.assertEqual(outputs['/probe/loader-confined.json'], {'fixture': 'diagnostic'})
            self.assertEqual(outputs['/probe/sudo-exec.json']['returncode'], 1)
            self.assertEqual(outputs['/probe/sudo-exec.json']['stderr'], failure.stderr)
            if account_failure:
                account.assert_called_once_with()
                self.assertEqual(outputs['/probe/pam-account-hook.json'], account.return_value)
            else:
                account.assert_not_called()
                self.assertNotIn('/probe/pam-account-hook.json', outputs)


class BridgeNativePrerequisiteTests(unittest.TestCase):
    def test_native_taskspace_and_container_subtree_stop(self):
        # The test has a local retained-artifact default; the public command takes
        # an explicit --runtime and does not depend on this machine layout.
        runtime = Path(os.environ.get('PTW_LINUXARENA_RUNTIME',
            str(Path.home() / 'hamal-projects/linuxarena-baseline/artifacts/runtime')))
        root = Path(tempfile.mkdtemp(prefix='ptw-linuxarena-prerequisite-', dir='/tmp'))
        print('LINUXARENA_PREREQUISITE_EVIDENCE ' + str(root), flush=True)
        result = preflight.run(runtime, root / 'run')
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(len(load(root / 'run/taskspace.json')['combinations']), 6)
        stop = load(root / 'run/subtree.json')
        self.assertTrue(stop['termination']['confirmed_stopped'])
        self.assertTrue(stop['control_process_preserved'])
        self.assertEqual(set(stop['effects_bytes']), {'parent', 'child', 'reopened-parent', 'reopened-child'})
        self.assertTrue(stop['unrelated_continued'])
        self.assertTrue(stop['late_admission_denied'])
        physical = load(root / 'run/namespace.json')
        self.assertTrue(physical['useful_work'])
        self.assertTrue(physical['tcp_unix_allowed'])
        self.assertTrue(physical['denied_collector_positive_control'])
        self.assertTrue(physical['termination']['confirmed_stopped'])
        self.assertNotEqual(physical['observed']['dev_uid'], 0)
        self.assertIn('state_write', physical['observed'])
        self.assertEqual(physical['observed']['etc_mode'], 0o755)
        self.assertEqual(physical['observed']['tmp_mode'], 0o1777)
        for name in ('pam_write', 'pam_include_write'):
            self.assertIn(physical['observed'][name], (1, 2, 13, 30))
        diagnostics = load(root / 'run/namespace-diagnostics.json')
        self.assertEqual(diagnostics['image_id'], load(root / 'run/daemon.json')['image_id'])
        for name, entry in diagnostics['tools'].items():
            self.assertEqual(diagnostics['staged_sha256'][name], entry['sha256'])
        for name in ('namespace/loader-image.json', 'namespace/probe/loader-confined.json',
                     'namespace/probe/sudo-exec.json'):
            self.assertIn(name, diagnostics['records'])
            self.assertNotIn(name, diagnostics['missing'])
        sudo = load(root / 'run/namespace/probe/sudo-exec.json')
        self.assertNotEqual(sudo['returncode'], 0)
        self.assertIn('private/secret', sudo['stderr'])
        socket_child = load(root / 'run/namespace/probe/socket-child.json')
        self.assertEqual(socket_child['returncode'], 0, socket_child['stderr'])
        expected_filter = hashlib.sha256(namespace.socket_filter()).hexdigest()
        self.assertEqual(physical['socket_filter_sha256'], expected_filter)
        self.assertEqual(diagnostics['socket_filter_sha256'], expected_filter)
        for route, result in (
                ('root', load(root / 'run/namespace/probe/socket-root.json')),
                ('child', json.loads(socket_child['stdout'])),
                ('sudo-dev', json.loads(sudo['stdout']))):
            with self.subTest(socket_route=route):
                self.assertEqual(result['filter_sha256'], expected_filter)
                self.assertEqual(result['uid'] != 0, route == 'sudo-dev')
                self.assertTrue(result['audit_open'])
                for mask in result['capabilities'].values():
                    self.assertEqual(mask & ~namespace.CAPABILITY_MASK, 0)
                self.assertTrue(result['unix_socketpair'])
                for field in ('audit_get_denied', 'audit_set_denied', 'audit_user_denied'):
                    self.assertIn(result[field], (1, 111))
                for field in ('audit_peer_denied', 'audit_multicast_denied', 'udp4', 'udp6',
                              'raw4', 'raw6', 'sctp', 'packet', 'route_netlink', 'generic_netlink',
                              'audit_datagram', 'io_uring_setup', 'x32_socket',
                              'socketpair_2', 'socketpair_10', 'socketpair_16'):
                    self.assertEqual(result[field], 1)
                self.assertEqual(result['audit_peer_empty'], 11)
                self.assertIn(result['tcp_port_denied'], (1, 13))
        image_files = load(root / 'run/namespace/loader-image.json')['files']
        confined_files = load(root / 'run/namespace/probe/loader-confined.json')['files']
        image_pam = load(root / 'run/namespace/loader-image.json')['pam']
        confined_pam = load(root / 'run/namespace/probe/loader-confined.json')['pam']
        self.assertFalse(image_pam['file_limit_exceeded'])
        self.assertTrue(image_pam['files'])
        self.assertEqual([row['path'] for row in confined_pam['files']],
                         [row['path'] for row in image_pam['files']])
        for original, confined in zip(image_pam['files'], confined_pam['files']):
            with self.subTest(pam=original['path']):
                self.assertIsNone(original['open_errno'])
                self.assertEqual(original['parsed']['errors'], [])
                self.assertIsNone(confined['open_errno'])
                self.assertEqual(confined['sha256'], original['sha256'])
        for path in ('/usr/libexec/sudo/sudoers.so', '/etc/sudoers'):
            with self.subTest(path=path):
                image_file = next(row for row in image_files if row['path'] == path)
                confined_file = next(row for row in confined_files if row['path'] == path)
                self.assertIsNone(image_file['open_errno'])
                self.assertIsNone(confined_file['open_errno'])
                for field in ('sha256', 'resolved', 'opened_uid', 'opened_gid', 'opened_mode'):
                    self.assertEqual(confined_file[field], image_file[field])

    def test_prerequisite_terminal_help_and_invalid_arguments(self):
        from terminal_driver import Terminal
        root = Path(tempfile.mkdtemp(prefix='ptw-linuxarena-terminal-', dir='/tmp'))
        print('LINUXARENA_TERMINAL_EVIDENCE ' + str(root), flush=True)
        env = {k: os.environ[k] for k in ('PATH', 'LANG') if k in os.environ}
        for name, args, code, expected in (
            ('help', ['--help'], 0, '--runtime'),
            ('missing', [], 2, 'required'),
            ('live', ['--authorize-paid'], 2, 'error:'),
        ):
            terminal = Terminal([sys.executable, '-B', SCRIPTS / 'linuxarena_preflight.py', *args],
                                root / name, env=env, replace_env=True)
            try:
                terminal.wait(lambda: terminal.exited, 20, 'prerequisite CLI exit')
                self.assertEqual(terminal.close(graceful=False), code, terminal.text)
                self.assertIn(expected, terminal.text)
            finally:
                terminal.close(graceful=False)


if __name__ == '__main__':
    unittest.main()
