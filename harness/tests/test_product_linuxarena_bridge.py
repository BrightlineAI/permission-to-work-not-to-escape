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
from contextlib import ExitStack
from types import SimpleNamespace
import threading
import unittest
import struct
import subprocess
import tarfile
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
import linuxarena_sudo_source as sudo_source
import linuxarena_sudo_gate as sudo_gate
import linuxarena_sudo_build as sudo_build
import linuxarena_sudo_inputs as sudo_inputs
import linuxarena_sudo_deps as sudo_deps
import linuxarena_taskspace as taskspace


class BridgeTrainInspectionTests(unittest.TestCase):
    def test_only_train_objects_resolved_and_all_pair_ids_checked(self):
        from types import SimpleNamespace
        class Space:
            def __init__(self):
                self.lookups = []
            def mains(self):
                return {main for main, side in taskspace.PAIRS}
            def sides(self):
                return {side for main, side in taskspace.PAIRS}
            def get(self, *, main_id, side_id):
                self.lookups.append((main_id, side_id))
                if main_id != 'file_integrity' or side_id not in (None, taskspace.PAIRS[0][1]):
                    raise AssertionError('Non-TRAIN task loaded')
                return SimpleNamespace(main_ids=frozenset([main_id]),
                                       side_ids=frozenset([side_id] if side_id else []),
                                       mode='attack' if side_id else 'honest')
            def __contains__(self, combo):
                return True
        space = Space()
        ids, combos = taskspace.inspect_combinations(space)
        self.assertEqual(len(ids), 3)
        self.assertEqual([x['mode'] for x in combos], ['honest', 'attack'])
        self.assertEqual(space.lookups, [('file_integrity', None), taskspace.PAIRS[0]])
        with patch.object(space, 'sides', return_value={taskspace.PAIRS[0][1]}):
            with self.assertRaisesRegex(ValueError, 'missing a planned'):
                taskspace.inspect_combinations(space)
        with patch.object(Space, '__contains__', return_value=False):
            with self.assertRaisesRegex(ValueError, 'exact TRAIN'):
                taskspace.inspect_combinations(space)

    def test_non_train_content_guard_covers_bytes_links_and_bytecode(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            root = Path(directory)
            taskspace.guard_task_content('open', (root / 'main_tasks/file_integrity/info.yml',))
            taskspace.guard_task_content('open', (root / 'side_tasks/access_secret_files_you_dont_own/scorer.py',))
            taskspace.guard_task_content('open', (4,))
            taskspace.guard_task_content('os.listdir', (root / 'main_tasks/stats',))
            heldout = root / 'main_tasks/stats'
            heldout.mkdir(parents=True)
            (root / 'alias').symlink_to(heldout, target_is_directory=True)
            for path in (heldout / 'info.yml', root / 'alias/scorer.py',
                         root / 'main_tasks/duplicate_detection/__pycache__/scorer.pyc',
                         root / 'side_tasks/authentication_bypass/instructions.md'):
                for name in (str(path), os.fsencode(path)):
                    with self.subTest(path=name), self.assertRaisesRegex(PermissionError, 'Non-TRAIN'):
                        taskspace.guard_task_content('open', (name,))


class BridgeSudoSourceTests(unittest.TestCase):
    """Archive validation only; no substitute for native authentication."""
    @staticmethod
    def archive(rows):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w:gz') as archive:
            for name, value, kind in rows:
                entry = tarfile.TarInfo(name)
                entry.type = kind
                entry.size = len(value)
                archive.addfile(entry, io.BytesIO(value))
        return output.getvalue()

    def upstream(self):
        return [('sudo-1.9.9/' + name, b'fixture source', tarfile.REGTYPE)
                for name in sudo_source.EXECUTION_FILES]

    def inspect(self, rows, *, debian=False):
        data = self.archive(rows)
        return sudo_source.source_members(data, hashlib.sha256(data).hexdigest(), debian=debian)

    def test_verified_sources_and_complete_distribution_series(self):
        self.assertEqual(len(self.inspect(self.upstream())), len(sudo_source.EXECUTION_FILES))
        rows = [('debian/changelog', ('sudo (' + sudo_source.VERSION + ') jammy; urgency=medium\n').encode(),
                 tarfile.REGTYPE), ('debian/rules', b'not executed', tarfile.REGTYPE),
                ('debian/patches/series', b'# retained\nfix.patch\n', tarfile.REGTYPE),
                ('debian/patches/fix.patch', b'not applied', tarfile.REGTYPE)]
        self.assertEqual(set(self.inspect(rows, debian=True)), {row[0] for row in rows})
        with self.assertRaisesRegex(ValueError, 'Missing or unsupported'):
            self.inspect(rows[:-1], debian=True)
        with self.assertRaisesRegex(ValueError, 'version mismatch'):
            self.inspect([('debian/changelog', b'sudo (wrong)\n', tarfile.REGTYPE), *rows[1:]], debian=True)

    def test_wrong_hash_missing_links_duplicates_and_traversal_rejected(self):
        rows = self.upstream()
        data = self.archive(rows)
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            sudo_source.source_members(data, '0' * 64, debian=False)
        for changed in (rows[:-1], rows + [rows[0]],
                        rows + [('../escape', b'data', tarfile.REGTYPE)],
                        [(rows[0][0], b'', tarfile.SYMTYPE), *rows[1:]]):
            with self.subTest(names=[row[0] for row in changed]), self.assertRaises(ValueError):
                self.inspect(changed)
        with patch.object(sudo_source, 'MAX_MEMBER', 4), self.assertRaisesRegex(ValueError, 'bounded'):
            self.inspect(rows)

    def test_download_has_no_retry_proxy_redirect_or_unverified_output(self):
        name = next(iter(sudo_source.ARCHIVES))
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            target = Path(directory) / name
            response = unittest.mock.MagicMock()
            response.__enter__.return_value = response
            response.status = 200
            response.geturl.return_value = sudo_source.SOURCE_URL + name
            response.read.side_effect = [b'corrupted archive', b'']
            opener = unittest.mock.Mock()
            opener.open.return_value = response
            with patch.object(sudo_source.urllib.request, 'build_opener', return_value=opener) as build:
                with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                    sudo_source.download(name, target)
                self.assertEqual(opener.open.call_args.args[0].full_url,
                    'https://snapshot.ubuntu.com/ubuntu/20250701T000000Z/pool/main/s/sudo/' + name)
                self.assertEqual(build.call_args.args[0].proxies, {})
                self.assertIsInstance(build.call_args.args[1], sudo_source.NoRedirect)
                self.assertEqual(opener.open.call_count, 1)
            self.assertEqual(target.read_bytes(), b'corrupted archive')
            with self.assertRaisesRegex(ValueError, 'redirect refused'):
                sudo_source.NoRedirect().redirect_request(None, None, 302, '', {}, 'http://invalid/')
            with self.assertRaisesRegex(ValueError, 'Unapproved'):
                sudo_source.download('other.tar.gz', Path(directory) / 'other')
            self.assertFalse((Path(directory) / 'other').exists())

    def test_download_success_size_limit_and_transport_failure_preserve_bytes(self):
        name = next(iter(sudo_source.ARCHIVES))
        body = b'synthetic source bytes'
        for chunks, limit, failure in (([body, b''], 100, None),
                                       ([body, body], len(body), ValueError),
                                       ([body, OSError('disconnected')], 100, OSError)):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(dir='/tmp') as directory:
                target = Path(directory) / name
                response = unittest.mock.MagicMock()
                response.__enter__.return_value = response
                response.status = 200
                response.geturl.return_value = sudo_source.SOURCE_URL + name
                response.read.side_effect = chunks
                opener = unittest.mock.Mock()
                opener.open.return_value = response
                with patch.object(sudo_source.urllib.request, 'build_opener', return_value=opener), \
                        patch.dict(sudo_source.ARCHIVES, {name: hashlib.sha256(body).hexdigest()}), \
                        patch.object(sudo_source, 'MAX_ARCHIVE', limit):
                    if failure:
                        with self.assertRaises(failure):
                            sudo_source.download(name, target)
                    else:
                        sudo_source.download(name, target)
                    self.assertEqual(opener.open.call_count, 1)
                self.assertEqual(target.read_bytes(), body)

    def test_unexpected_response_and_http_failure_do_not_retry_or_read_body(self):
        name = 'sudo_1.9.9-1ubuntu2.5.debian.tar.xz'
        url = sudo_source.SOURCE_URL + name
        for status, final_url in ((206, url), (200, 'https://unapproved.invalid/' + name),
                                  (404, url)):
            with self.subTest(status=status, url=final_url), tempfile.TemporaryDirectory(dir='/tmp') as directory:
                response = unittest.mock.MagicMock()
                response.__enter__.return_value = response
                response.status = status
                response.geturl.return_value = final_url
                opener = unittest.mock.Mock()
                opener.open.return_value = response
                error = ValueError
                if status == 404:
                    error = sudo_source.urllib.error.HTTPError
                    opener.open.side_effect = error(url, 404, 'Not Found', {}, None)
                target = Path(directory) / name
                with patch.object(sudo_source.urllib.request, 'build_opener', return_value=opener):
                    with self.assertRaises(error):
                        sudo_source.download(name, target)
                self.assertEqual(opener.open.call_count, 1)
                self.assertEqual(opener.open.call_args.args[0].full_url, url)
                response.read.assert_not_called()
                self.assertEqual(target.read_bytes(), b'')

    def test_http_failure_retains_archive_request_and_stops_downloads(self):
        names = list(sudo_source.ARCHIVES)
        for failed_name in names:
            with self.subTest(archive=failed_name), tempfile.TemporaryDirectory(dir='/tmp') as directory:
                root = Path(directory)
                runtime = root / 'runtime'
                runtime.mkdir()
                cid = 'a' * 64
                identity = {'version': sudo_source.VERSION, 'files_sha256': {
                    '/usr/bin/sudo': 'b' * 64, '/usr/libexec/sudo/sudoers.so': 'c' * 64}}
                command = unittest.mock.Mock(side_effect=[cid.encode(), json.dumps(identity).encode(), b''])
                def download(name, target):
                    target.write_bytes(b'' if name == failed_name else b'synthetic verified source')
                    if name == failed_name:
                        # The actual transport rejection is covered above; this
                        # double tests receipt/cleanup orchestration, not Docker.
                        raise sudo_source.urllib.error.HTTPError(
                            sudo_source.SOURCE_URL + name, 404, 'Not Found', {}, None)
                with patch.object(sudo_source, 'daemon_environment', return_value=({}, {})), \
                        patch.object(sudo_source, 'verify_daemon', return_value={
                            'cgroup': '/fixture.slice', 'image_id': 'sha256:' + 'd' * 64}), \
                        patch.object(sudo_source, 'Commands', return_value=command), \
                        patch.object(sudo_source, 'download', side_effect=download) as downloaded, \
                        patch.object(sudo_source, 'source_members', return_value={}):
                    with self.assertRaises(sudo_source.urllib.error.HTTPError):
                        sudo_source.run(runtime, root / 'attempt')
                receipt = load(root / 'attempt/attempt.json')
                self.assertEqual(receipt['status'], 'failed')
                self.assertEqual(receipt['error_type'], 'HTTPError')
                self.assertEqual(receipt['paid_calls'], 0)
                self.assertEqual(list(receipt['downloads']), sorted(names[:names.index(failed_name) + 1]))
                self.assertEqual(receipt['downloads'][failed_name], {
                    'url': sudo_source.SOURCE_URL + failed_name,
                    'expected_sha256': sudo_source.ARCHIVES[failed_name],
                    'status': 'failed', 'error_type': 'HTTPError', 'http_status': 404})
                for name in names[:names.index(failed_name)]:
                    self.assertEqual(receipt['downloads'][name]['status'], 'verified')
                self.assertEqual(downloaded.call_count, names.index(failed_name) + 1)
                self.assertEqual(receipt['records'][failed_name]['sha256'], hashlib.sha256(b'').hexdigest())
                self.assertFalse((root / 'attempt/source.json').exists())
                self.assertEqual(command.call_args.args[0], ['docker', 'rm', '--force', cid])

    def test_native_metadata_failure_retains_attempt_without_download(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            root = Path(directory)
            runtime = root / 'runtime'
            runtime.mkdir()
            with patch.object(sudo_source, 'daemon_environment', side_effect=ValueError('missing daemon')), \
                    patch.object(sudo_source, 'download') as download:
                with self.assertRaisesRegex(ValueError, 'missing daemon'):
                    sudo_source.run(runtime, root / 'attempt')
            download.assert_not_called()
            receipt = load(root / 'attempt/attempt.json')
            self.assertEqual(receipt['status'], 'failed')
            self.assertEqual(receipt['paid_calls'], 0)
            self.assertEqual(receipt['error_type'], 'ValueError')
            self.assertIn('ended_epoch', receipt)


class BridgePrerequisiteTests(unittest.TestCase):
    def resource_run(self, root, memory, disk, *, write_failure=None):
        """Real receipt/admission flow, synthetic readings and no native work."""
        runtime, out = root / 'runtime', root / 'run'
        runtime.mkdir()
        read_text, save = Path.read_text, preflight.save

        def reading(path, *args, **kwargs):
            if path == Path('/proc/meminfo'):
                if isinstance(memory, Exception):
                    raise memory
                return memory
            return read_text(path, *args, **kwargs)

        def write(path, value):
            if (path.name == write_failure or
                    (write_failure == 'reference' and path.name == 'attempt.json' and
                     value['status'] == 'incomplete' and 'resources' in value)):
                raise OSError('synthetic receipt write failure')
            save(path, value)

        def fixture(command, output, daemon):
            # Both fixtures must see the durable, hash-bound admission first.
            attempt = load(output / 'attempt.json')
            self.assertEqual(attempt['resources'], preflight.reference(output, output / 'resources.json'))
            self.assertTrue(load(output / 'resources.json')['admitted'])
            for name in ('subtree', 'lifecycle', 'namespace', 'namespace-spec',
                         'namespace-lifecycle', 'tools', 'namespace-diagnostics'):
                save(output / (name + '.json'), {'synthetic': True})

        with ExitStack() as stack:
            stack.enter_context(patch.object(preflight, 'source_tree', return_value={'synthetic': True}))
            stack.enter_context(patch.object(preflight.Commands, '__call__', return_value=json.dumps({
                'sandbox_module': str(runtime / 'control-tower/src/control_tower/sandbox/docker.py')
            }).encode()))
            stack.enter_context(patch.object(preflight, 'daemon_environment', return_value=({}, {})))
            stack.enter_context(patch.object(preflight, 'verify_daemon', return_value={'synthetic': True}))
            mem = stack.enter_context(patch.object(Path, 'read_text', autospec=True, side_effect=reading))
            usage = stack.enter_context(patch.object(preflight.shutil, 'disk_usage',
                **({'side_effect': disk} if isinstance(disk, Exception) else {'return_value': disk})))
            stack.enter_context(patch.object(preflight, 'save', side_effect=write))
            subtree = stack.enter_context(patch.object(preflight, 'subtree_probe', side_effect=fixture))
            namespace_probe = stack.enter_context(patch.object(confinement, 'probe', side_effect=fixture))
            error = None
            try:
                preflight.run(runtime, out)
            except (ValueError, OSError) as exc:
                error = exc
            self.assertEqual(sum(call.args[0] == Path('/proc/meminfo') for call in mem.call_args_list), 1)
            usage.assert_called_once_with(out)
            if error:
                subtree.assert_not_called()
                namespace_probe.assert_not_called()
            else:
                subtree.assert_called_once()
                namespace_probe.assert_called_once()
        attempt = load(out / 'attempt.json')
        self.assertEqual(attempt['status'], 'failed' if error else 'complete')
        self.assertEqual(attempt['paid_calls'], 0)
        return out, attempt, error

    def test_resource_admission_thresholds_and_independent_shortages(self):
        for memory, free in ((524289, 1073741825), (524288, 1073741824),
                             (524287, 1073741824), (524288, 1073741823),
                             (524287, 1073741823), (0, 0)):
            with self.subTest(memory=memory, free=free), tempfile.TemporaryDirectory(dir='/tmp') as directory:
                out, attempt, error = self.resource_run(Path(directory),
                    f'MemAvailable: {memory} kB\n', SimpleNamespace(free=free))
                resources = load(out / 'resources.json')
                expected = ([] if memory >= 524288 else ['memory_below_minimum']) + (
                    [] if free >= 1073741824 else ['filesystem_below_minimum'])
                self.assertEqual(resources['failure_reasons'], expected)
                self.assertEqual(resources['admitted'], not expected)
                self.assertEqual(error is not None, bool(expected))
                self.assertEqual(resources['memory']['observed'], memory)
                self.assertEqual(resources['memory']['minimum'], 524288)
                self.assertEqual(resources['memory']['unit'], 'KiB')
                self.assertEqual(resources['filesystem']['observed'], free)
                self.assertEqual(resources['filesystem']['minimum'], 1073741824)
                self.assertEqual(resources['filesystem']['unit'], 'bytes')
                self.assertEqual(resources['filesystem']['device'], out.stat().st_dev)
                self.assertEqual(resources['filesystem']['directory_inode'], out.stat().st_ino)
                self.assertEqual(resources['filesystem']['path'], str(out))
                self.assertLessEqual(attempt['started_epoch'], resources['sampled_epoch'])
                self.assertLessEqual(resources['sampled_epoch'], attempt['ended_epoch'])
                self.assertEqual(attempt['resources'], preflight.reference(out, out / 'resources.json'))
                if error:
                    for reason in expected:
                        self.assertIn(reason, str(error))

    def test_resource_invalid_or_missing_memory_retains_disk_measurement(self):
        for memory in ('', 'MemTotal: 999999 kB\n', 'MemAvailable: -1 kB\n',
                       'MemAvailable: 999999 bytes\n', 'MemAvailable: nan kB\n',
                       'MemAvailable: 999999 kB\nMemAvailable: 999999 kB\n',
                       OSError('synthetic unreadable meminfo')):
            with self.subTest(memory=memory), tempfile.TemporaryDirectory(dir='/tmp') as directory:
                out, attempt, error = self.resource_run(Path(directory), memory, SimpleNamespace(free=1))
                self.assertIsInstance(error, ValueError)
                resources = load(out / 'resources.json')
                self.assertEqual(resources['failure_reasons'],
                                 ['memory_reading_invalid', 'filesystem_below_minimum'])
                self.assertIsNone(resources['memory']['observed'])
                self.assertIn('error_type', resources['memory'])
                self.assertEqual(resources['filesystem']['observed'], 1)
                self.assertEqual(attempt['resources'], preflight.reference(out, out / 'resources.json'))

    def test_resource_invalid_or_missing_disk_retains_memory_measurement(self):
        for disk in (SimpleNamespace(free=-1), SimpleNamespace(free='1073741824'),
                     SimpleNamespace(free=True), SimpleNamespace(free=None),
                     SimpleNamespace(), OSError('synthetic unreadable filesystem')):
            with self.subTest(disk=disk), tempfile.TemporaryDirectory(dir='/tmp') as directory:
                out, attempt, error = self.resource_run(Path(directory), 'MemAvailable: 0 kB\n', disk)
                self.assertIsInstance(error, ValueError)
                resources = load(out / 'resources.json')
                self.assertEqual(resources['failure_reasons'],
                                 ['memory_below_minimum', 'filesystem_reading_invalid'])
                self.assertIsNone(resources['filesystem']['observed'])
                self.assertIn('error_type', resources['filesystem'])
                self.assertEqual(resources['memory']['observed'], 0)
                self.assertEqual(attempt['resources'], preflight.reference(out, out / 'resources.json'))

    def test_resource_receipt_or_reference_write_failure_prevents_both_fixtures(self):
        for failed in ('resources.json', 'reference'):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory(dir='/tmp') as directory:
                out, attempt, error = self.resource_run(Path(directory), 'MemAvailable: 524288 kB\n',
                    SimpleNamespace(free=1073741824), write_failure=failed)
                self.assertIsInstance(error, OSError)
                self.assertEqual(attempt['error_type'], 'OSError')
                if failed == 'resources.json':
                    self.assertNotIn('resources', attempt)
                    self.assertFalse((out / 'resources.json').exists())
                else:
                    self.assertEqual(attempt['resources'], preflight.reference(out, out / 'resources.json'))

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

    def test_continuation_kernel_boundary_pins_stopped_member_without_moving(self):
        subtree = ExecutionSubtree.__new__(ExecutionSubtree)
        subtree.revoked = subtree.closed = False
        subtree.group = '/container/owned'
        expected = dict(pid=123, state='T', starttime=10, cgroup=subtree.group,
                        pid_namespace='pid:[1]', user_namespace='user:[2]')
        with patch('ptw.linuxarena_cgroup.os.pidfd_open', return_value=99) as opened, \
                patch('ptw.linuxarena_cgroup.os.close') as close, \
                patch('ptw.linuxarena_cgroup.signal.pidfd_send_signal') as sent, \
                patch('ptw.linuxarena_cgroup.process_identity', return_value=expected) as identity, \
                patch.object(subtree, '_write') as moved:
            self.assertEqual(subtree.continue_stopped(expected), expected)
            opened.assert_called_once_with(123)
            sent.assert_called_once_with(99, __import__('signal').SIGCONT)
            close.assert_called_once_with(99)
            moved.assert_not_called()
            for replacement in (dict(expected, starttime=11), dict(expected, state='R'),
                                dict(expected, cgroup='/other')):
                sent.reset_mock(); close.reset_mock()
                identity.return_value = replacement
                with self.assertRaises(Invalid): subtree.continue_stopped(expected)
                sent.assert_not_called(); close.assert_called_once_with(99)
            identity.return_value = expected
            sent.side_effect = ProcessLookupError('exited after observation')
            close.reset_mock()
            with self.assertRaises(ProcessLookupError): subtree.continue_stopped(expected)
            close.assert_called_once_with(99)
            opened.reset_mock(); subtree.revoked = True
            with self.assertRaises(Invalid): subtree.continue_stopped(expected)
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


class BridgeFileScopeTests(unittest.TestCase):
    """Real controller authority and resource identities; no kernel proof."""
    def setUp(self):
        import linuxarena_sudo_admission as admission
        self.temp = tempfile.TemporaryDirectory(dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ('work', 'other'):
            (self.root / 'probe' / name).mkdir(parents=True)
        self.store, self.actor, self.frozen = admission.prepare_scope(self.root)
        self.spec = self.frozen['spec']
        self.resources = {'work': '/probe/work'}

    def freeze(self, **kwargs):
        return lifecycle.freeze_checkpoint_scope(self.store, kwargs.get('token', self.actor['token']),
            kwargs.get('resources', self.resources), kwargs.get('spec', self.spec))

    def verify(self, frozen=None):
        with self.store.locked() as db:
            actor = self.store.session(db, self.actor['token'])
            _, bundle = self.store.project(db, actor['project'])
            lifecycle.verify_checkpoint_scope(db, actor, bundle,
                                              {'file_scope': frozen or self.frozen})

    def test_frozen_scope_compiles_only_child_resources_and_copies_inputs(self):
        self.verify()
        header = sudo_build.landlock_header(placement=True, file_scope=self.frozen)
        self.assertIn('"/probe/work"', header)
        self.assertNotIn('"/probe/other"', header)
        self.assertIn('PTW_SCOPE_HELPER', header)
        with self.assertRaisesRegex(ValueError, 'requires namespace placement'):
            sudo_build.landlock_header(file_scope=self.frozen)
        self.assertNotIn(self.actor['token'], json.dumps(self.frozen))
        self.assertEqual([a['task'] for a in self.frozen['authority']], ['child', 'parent'])
        narrowed = dict(self.spec, read=['/probe/work'], write=[])
        frozen = self.freeze(spec=narrowed)
        self.assertEqual(frozen['resources']['work']['actions'], ['read'])
        narrowed['read'].clear()
        self.assertEqual(frozen['spec']['read'], ['/probe/work'])

    def test_scope_rejects_expansion_mapping_errors_and_unrepresentable_writes(self):
        for mapping, spec in (
                ({}, self.spec), ({'work': '/probe/other'}, self.spec),
                ({'work': []}, self.spec), ({'absent': '/probe/work'}, self.spec),
                ({'other': '/probe/work'}, self.spec),
                ({'work': '/probe/work'}, dict(self.spec, write=['/'])),
                ({'work': '/probe/work'}, dict(self.spec, cwd='/private'))):
            with self.subTest(mapping=mapping), self.assertRaises(ValueError):
                self.freeze(resources=mapping, spec=spec)
        with self.store.locked() as db:
            db.execute('UPDATE sessions SET grants=? WHERE id=?',
                (json.dumps([{'resource': 'work', 'actions': ['read', 'write', 'append', 'create']}]),
                 self.actor['session']))
        with self.assertRaisesRegex(Invalid, 'surviving file grants'):
            self.freeze()
        self.assertEqual(self.freeze(spec=dict(self.spec, read=['/probe/work'], write=[]))
                         ['resources']['work']['actions'], ['read'])

    def test_scope_rejects_parent_changes_closure_missing_and_cycles(self):
        parent = self.frozen['authority'][1]['session']
        for field, value in (('grants', '[]'), ('closed', 1), ('parent', self.actor['session']),
                             ('parent', 'missing'), ('task', 'missing')):
            with self.subTest(field=field), self.store.locked() as db:
                old = db.execute('SELECT ' + field + ' FROM sessions WHERE id=?', (parent,)).fetchone()[0]
                db.execute('UPDATE sessions SET ' + field + '=? WHERE id=?', (value, parent))
            try:
                with self.assertRaises(Invalid):
                    self.verify()
            finally:
                with self.store.locked() as db:
                    db.execute('UPDATE sessions SET ' + field + '=? WHERE id=?', (old, parent))
        self.verify()

    def test_scope_rejects_replaced_resource_forged_receipt_and_changed_policy(self):
        for mutate in (
                lambda f: f['resources']['work'].update(inode=0),
                lambda f: f['authority'][0].update(task='parent'),
                lambda f: f.update(resources={'work': None}),
                lambda f: f.update(extra='unrecognized')):
            frozen = json.loads(json.dumps(self.frozen))
            mutate(frozen)
            with self.assertRaises(Invalid): self.verify(frozen)
        (self.root / 'probe/work').rename(self.root / 'probe/old-work')
        (self.root / 'probe/work').mkdir()
        with self.assertRaisesRegex(Invalid, 'resource identity changed'): self.verify()
        (self.root / 'probe/work').rmdir()
        (self.root / 'probe/old-work').rename(self.root / 'probe/work')
        with self.store.locked() as db:
            _, bundle = self.store.project(db, 'checkpoint')
            bundle['policy']['tasks'][1]['grants'] = bundle['policy']['project']['grants']
            db.execute('UPDATE projects SET bundle=?', (json.dumps(bundle),))
        with self.assertRaisesRegex(Invalid, 'changed after approval'): self.verify()

    def test_scope_rejects_other_session_and_project_stop(self):
        other = self.store.register('checkpoint', 'child')
        with self.store.locked() as db:
            actor = self.store.session(db, other['token'])
            _, bundle = self.store.project(db, 'checkpoint')
            with self.assertRaisesRegex(Invalid, 'authority changed'):
                lifecycle.verify_checkpoint_scope(db, actor, bundle, {'file_scope': self.frozen})
        self.store.stop('checkpoint')
        with self.assertRaisesRegex(Invalid, 'Project stopped'): self.freeze()


class BridgeAdmissionTests(unittest.TestCase):
    """Transport doubles only; native socket behavior belongs to manager checks."""
    def test_constructor_binds_trusted_release_mode_scope_and_exact_header(self):
        import linuxarena_sudo_admission as admission
        # Exercise __init__, not just connection methods on an uninitialized
        # instance. Only native process/transport operations are doubled.
        failures = (None, 'missing_mode', 'opposite_mode', 'null_mode', 'integer_mode',
                    'string_mode', 'invalid_expected_mode', 'changed_scope',
                    'opposite_header', 'changed_header', 'missing_header')
        for release in (False, True):
            for failure in failures:
                with self.subTest(release=release, failure=failure), \
                        tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
                    root = Path(temporary)
                    for name in ('probe/work', 'probe/other', 'observer',
                                 'bundle/upstream/sudo-1.9.9/src', 'cgroup/fixture', 'proc/77'):
                        (root / name).mkdir(parents=True)
                    binding = admission.prepare_scope(root)
                    scope = binding[2]
                    header = root / 'bundle/upstream/sudo-1.9.9/src/linuxarena_sudo_landlock.h'
                    header.write_text(sudo_build.landlock_header(
                        placement=True, file_scope=scope,
                        release=not release if failure == 'opposite_header' else release))
                    source = {'file_scope': scope, 'requested_release': release}
                    if failure == 'missing_mode': source.pop('requested_release')
                    for case, value in (('opposite_mode', not release), ('null_mode', None),
                                        ('integer_mode', int(release)), ('string_mode', str(release))):
                        if failure == case: source['requested_release'] = value
                    if failure == 'changed_scope':
                        source['file_scope'] = dict(scope, spec=dict(scope['spec'], write=['/probe/other']))
                    if failure == 'changed_header': header.write_text(header.read_text() + '\n/* changed */\n')
                    if failure == 'missing_header': header.unlink()
                    admission.save(root / 'checkpoint-source.json', source)
                    (root / 'bundle/checkpoint-sudo').write_bytes(b'offline frontend identity')
                    (root / 'cgroup/fixture/cgroup.procs').write_text('77\n')
                    (root / 'proc/77/cmdline').write_bytes(
                        b'/usr/bin/python3\0-I\0-S\0/ptw-native-tools/placement.py\0--keeper\0')
                    def paths(value):
                        return {'/sys/fs/cgroup': root / 'cgroup', '/proc': root / 'proc'}.get(
                            str(value), Path(value))
                    stack.enter_context(patch.object(admission, 'Path', side_effect=paths))
                    identity = {'pid': 77, 'cgroup': '/fixture', 'pid_namespace': 'pid:[2]'}
                    stack.enter_context(patch.object(admission, 'process_identity', return_value=identity))
                    stack.enter_context(patch.object(admission.os, 'readlink', return_value='mnt:[3]'))
                    subtree = stack.enter_context(patch.object(admission, 'ExecutionSubtree'))
                    register = stack.enter_context(patch.object(lifecycle, 'register', return_value='unit'))
                    listener = stack.enter_context(patch.object(admission.socket, 'socket'))
                    thread = stack.enter_context(patch.object(admission.threading, 'Thread'))
                    command = unittest.mock.Mock(return_value=b'{"Pid":77}')
                    args = (root, command, 'fixture', {'daemon_id': 'daemon'}, {'pid': 2, 'mnt': 3}, binding)
                    options = {'release': int(release) if failure == 'invalid_expected_mode' else release}
                    if failure:
                        with self.assertRaises((ValueError, FileNotFoundError)):
                            admission.ClosedAdmission(*args, **options)
                        command.assert_not_called()
                        subtree.assert_not_called()
                        register.assert_not_called()
                        listener.assert_not_called()
                        thread.assert_not_called()
                    else:
                        # Keep the default closed-mode call compatible too.
                        gate = admission.ClosedAdmission(*args, **(options if release else {}))
                        self.assertEqual(gate.file_scope, scope)
                        self.assertEqual(gate.holder, identity)
                        register.assert_called_once_with(binding[0], binding[1]['token'],
                            subtree.return_value, daemon_id='daemon', control=identity)
                        listener.return_value.listen.assert_called_once_with(1)
                        thread.return_value.start.assert_called_once_with()

    def test_job_state_is_bounded_numeric_and_rejects_identity_drift(self):
        import linuxarena_sudo_admission as admission
        pin = dict(pid=124, starttime=999, cgroup='/fixture',
                   pid_namespace='pid:[2]', user_namespace='user:[3]', state='T')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proc = root / '124'
            proc.mkdir()
            fields = ['T', '123', '124', '123', '0', '124'] + ['0'] * 13 + ['999']
            original = '124 (name with ) parentheses) ' + ' '.join(fields)
            status = 'Name:\tDO_NOT_EXPORT\nNSpid:\t124 19\nNSpgid:\t124 19\nNSsid:\t123 0\n'
            for failure in (None, 'changed', 'stat', 'status', 'oversized', 'missing', 'namespace'):
                with self.subTest(failure=failure):
                    (proc / 'stat').write_text(original.replace('999', '888') if failure == 'stat' else original)
                    (proc / 'status').write_text('x' * 8193 if failure == 'oversized' else
                        status.replace('124 19', 'bad') if failure == 'status' else status)
                    if failure == 'missing': (proc / 'stat').unlink()
                    calls = [pin, dict(pin, starttime=888) if failure == 'changed' else pin]
                    def link(path):
                        return path.name + ':[' + ('bad' if failure == 'namespace' else '2') + ']'
                    with patch.object(admission, 'Path', return_value=root), \
                            patch.object(admission, 'process_identity', side_effect=calls), \
                            patch.object(admission.os, 'readlink', side_effect=link):
                        if failure:
                            with self.assertRaises((ValueError, OSError)):
                                admission.job_process(pin)
                        else:
                            row = admission.job_process(pin)
                            self.assertEqual(row['state'], ord('T'))
                            self.assertEqual(row['NSpid'], [124, 19])
                            self.assertEqual((row['ppid'], row['pgid'], row['sid'], row['fg']),
                                             (123, 124, 123, 124))
                            self.assertTrue(all(type(v) is int or isinstance(v, list) for v in row.values()))
                            self.assertNotIn('DO_NOT_EXPORT', json.dumps(row))

    def test_job_snapshot_follows_only_bound_ancestry_and_retains_failures(self):
        import linuxarena_sudo_admission as admission
        for failure in (None, 'multiple', 'unrelated', 'frontend', 'missing', 'replaced'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                children = root / '124/task/124/children'
                children.parent.mkdir(parents=True)
                children.write_text('125 126' if failure == 'multiple' else '125')
                pins = {pid: dict(pid=pid, starttime=pid, cgroup='/fixture',
                                  pid_namespace='pid:[2]', user_namespace='user:[3]', state='S')
                        for pid in (122, 123, 124, 125)}
                if failure == 'unrelated': pins[125]['cgroup'] = '/unrelated'
                gate = admission.ClosedAdmission.__new__(admission.ClosedAdmission)
                gate.frontend = 'a' * 64
                gate.records = [{'checkpoint': {'monitor': pins[123]}, 'moved': pins[124]}]
                second = False
                def observe(pin):
                    if second and failure == 'replaced' and pin['pid'] == 125:
                        raise ValueError('synthetic recycled PID')
                    if failure == 'missing' and pin['pid'] == 124:
                        raise FileNotFoundError(2, 'synthetic exited child')
                    return dict(pid=pin['pid'], ppid={122: 121, 123: 122, 124: 123, 125: 124}[pin['pid']],
                                state=ord('T') if pin['pid'] == 125 else ord('S'))
                with patch.object(admission, 'Path', return_value=root), \
                        patch.object(admission, 'job_process', side_effect=observe), \
                        patch.object(admission, 'process_identity', side_effect=lambda pid: pins[pid]) as identify, \
                        patch.object(admission, 'digest', return_value='b' * 64 if failure == 'frontend' else gate.frontend):
                    gate.observe_job(0, root / 'first.json')
                    identified = identify.call_count
                    second = True
                    gate.observe_job(0, root / 'second.json')
                    self.assertEqual(identify.call_count, identified)  # Never adopt a replacement.
                    self.assertTrue(all(call.args[0] in (122, 125) for call in identify.call_args_list))
                    rows = load(root / 'second.json')['processes']
                    self.assertEqual(len(rows), 4)
                    errors = [row for row in rows if row['error']]
                    self.assertEqual(bool(errors), failure is not None)
                    gate.observe_job(1, root / 'absent.json')
                    self.assertEqual(load(root / 'absent.json')['processes'], [{'role': 0, 'error': -1}])

    def test_kernel_peer_and_bounded_request_precede_controller_acknowledgement(self):
        import linuxarena_sudo_admission as admission
        gate = admission.ClosedAdmission.__new__(admission.ClosedAdmission)
        gate.store, gate.actor, gate.unit = object(), {'token': 'private'}, 'unit'
        gate.file_scope = {'fixture': 'closed file scope'}
        gate.holder, gate.frontend, gate.records = {'pid': 77}, 'a' * 64, []
        peer = unittest.mock.Mock()
        peer.getsockopt.return_value = struct.pack('3i', 123, os.geteuid(), 12345)
        monitor, child = {'pid': 123}, {'pid': 124}
        with tempfile.TemporaryDirectory() as folder:
            gate.out = Path(folder)
            for wire in (b'', b'123', b'12345', struct.pack('=I', 42)):
                peer.reset_mock()
                peer.recv.side_effect = [wire, b'']
                gate.records.clear()
                with patch.object(admission, 'process_identity', return_value=monitor) as identity, \
                        patch.object(admission, 'child_identity', return_value=child) as bound, \
                        patch.object(lifecycle, 'admit', return_value={'moved': True}) as admit:
                    if len(wire) != 4:
                        with self.assertRaises(ValueError): gate.connection(peer)
                        admit.assert_not_called()
                        peer.sendall.assert_not_called()
                    else:
                        def ack(data):
                            self.assertEqual(data, b'C')
                            self.assertEqual(load(gate.out / 'controller-admissions.json')[0]['child'], child)
                            admit.assert_called_once()
                        peer.sendall.side_effect = ack
                        gate.connection(peer)
                        identity.assert_called_once_with(123)
                        bound.assert_called_once_with(monitor, 42)
                        self.assertEqual(admit.call_args.kwargs['closed_checkpoint']['monitor'], monitor)
            peer.getsockopt.return_value = struct.pack('3i', 123, os.geteuid() + 1, 0)
            with self.assertRaisesRegex(ValueError, 'host UID'):
                gate.connection(peer)

    def test_lost_gate_or_failed_receipt_revokes_even_if_error_receipt_fails(self):
        import linuxarena_sudo_admission as admission
        for receipt_failure in (False, True):
            gate = admission.ClosedAdmission.__new__(admission.ClosedAdmission)
            gate.stop = threading.Event()
            gate.listener = unittest.mock.Mock()
            gate.listener.accept.return_value = (unittest.mock.MagicMock(), None)
            gate.store, gate.unit = unittest.mock.MagicMock(), 'unit'
            gate.out = Path('/unused')
            gate.connection = unittest.mock.Mock(side_effect=BrokenPipeError('lost peer'))
            with patch.object(admission, 'save', side_effect=OSError('receipt') if receipt_failure else None), \
                    patch.object(lifecycle, 'terminate') as terminate:
                if receipt_failure:
                    with self.assertRaises(OSError): gate.serve()
                else:
                    gate.serve()
                terminate.assert_called_once()
                self.assertIsInstance(gate.error, BrokenPipeError)

    def test_continuation_transport_requires_same_monitor_and_prior_admission(self):
        import linuxarena_sudo_admission as admission
        gate = admission.ClosedAdmission.__new__(admission.ClosedAdmission)
        gate.store, gate.actor, gate.unit = object(), {'token': 'private'}, 'unit'
        gate.file_scope = {'fixture': 'closed file scope'}
        monitor = {'pid': 123, 'state': 'R', 'starttime': 20}
        child = {'pid': 124, 'state': 'T', 'cgroup': '/container/owned'}
        initial = dict(child, cgroup='/container')
        context = {'monitor': dict(monitor, state='S'), 'holder': {'pid': 77}, 'frontend_sha256': 'a' * 64, 'file_scope': gate.file_scope}
        gate.holder, gate.frontend = context['holder'], context['frontend_sha256']
        peer = unittest.mock.Mock()
        peer.getsockopt.return_value = struct.pack('3i', 123, os.geteuid(), 0)
        with tempfile.TemporaryDirectory() as folder, \
                patch.object(admission, 'process_identity', return_value=monitor), \
                patch.object(admission, 'child_identity', return_value=child), \
                patch.object(lifecycle, 'continue_checkpoint', return_value=child) as resume, \
                patch.object(lifecycle, 'admit') as admit:
            gate.out = Path(folder)
            for case in ('missing', 'changed', 'replay', 'valid'):
                peer.reset_mock()
                peer.recv.side_effect = [struct.pack('=I', 42 | 0x80000000), b'']
                gate.records = [{'child': initial, 'moved': child, 'checkpoint': context}]
                if case == 'missing': gate.records = []
                if case == 'changed':
                    gate.records[0]['checkpoint'] = dict(context, monitor=dict(monitor, starttime=21))
                if case == 'replay': gate.records[0]['continued'] = child
                if case != 'valid':
                    with self.assertRaisesRegex(ValueError, 'Missing, changed or repeated'):
                        gate.connection(peer)
                    resume.assert_not_called()
                    peer.sendall.assert_not_called()
                else:
                    def ack(data):
                        self.assertEqual(data, b'C')
                        self.assertEqual(load(gate.out / 'controller-admissions.json')[0]['continued'], child)
                    peer.sendall.side_effect = ack
                    gate.connection(peer)
                    resume.assert_called_once_with(gate.store, 'private', 'unit', initial, child, context)
            admit.assert_not_called()

    def test_child_pid_uses_authenticated_monitor_depth_and_rejects_siblings(self):
        import linuxarena_sudo_admission as admission
        monitor, child = {'pid': 100}, {'pid': 200}
        rows = {'children': '200', 'parent': 'NSpid:\t100\t20\n',
                'child': 'NSpid:\t200\t42\t7\n'}
        def read(path, *args, **kwargs):
            return rows['children'] if path.name == 'children' else rows[
                'parent' if path.parent.name == '100' else 'child']
        with patch.object(Path, 'read_text', read), \
                patch.object(admission, 'process_identity', return_value=child):
            self.assertEqual(admission.child_identity(monitor, 42), child)
            for wrong in (7, 200, 0, -1, True, '42'):
                with self.subTest(pid=wrong), self.assertRaises(ValueError):
                    admission.child_identity(monitor, wrong)
            rows['children'] = '200 201'
            with self.assertRaisesRegex(ValueError, 'exactly one'):
                admission.child_identity(monitor, 42)


class BridgeLifecycleTests(unittest.TestCase):
    """Real controller persistence, mocked kernel boundary; not physical proof."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ptw-native-lifecycle-', dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        create_sample(self.root / 'fixture')
        policy = load(self.root / 'fixture/policy.json')
        inventory = load(self.root / 'fixture/inventory.json')
        # A real tree grant for checkpoint compilation; ordinary lifecycle cases
        # continue using the same sessions, persistence and kernel doubles.
        (self.root / 'fixture/resources/work').mkdir()
        inventory['resources']['work'] = {'path': 'work', 'kind': 'tree', 'description': 'Closed work'}
        policy['version'] = 4
        policy['project']['packages'] = {'allowed_names': [], 'build_packages': [],
            'allow_native_wheels': False, 'min_release_age_days': 3,
            'deny_cvss_at_or_above': 9, 'evidence_max_age_seconds': 900}
        work_grant = {'resource': 'work', 'actions': ['read', 'write', 'append', 'create', 'delete']}
        policy['project']['grants'].append(work_grant)
        policy['tasks'][0]['grants'].append(work_grant)
        for entry in (policy['project'], *policy['tasks']):
            entry['commands'] = []
        for task in policy['tasks']:
            task['packages'] = []
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

    def checkpoint_fixture(self):
        monitor = dict(self.control, pid=125)
        holder = dict(self.control, pid=126, pid_namespace='pid:[3]')
        child = dict(self.expected, pid_namespace=holder['pid_namespace'])
        context = {'monitor': monitor, 'holder': holder, 'frontend_sha256': 'a' * 64,
                   'file_scope': lifecycle.freeze_checkpoint_scope(self.store, self.actor['token'],
                       {'work': '/probe/work'}, {'read': [], 'write': ['/probe/work'],
                       'cwd': '/probe/work', 'connect_ports': [32001],
                       'argv': ['/ptw-native-tools/bin/closed', '--confined']})}
        processes = {p['pid']: p for p in (self.control, monitor, holder, child)}
        metadata = {pid: {'parent': 1, 'mount_namespace': 'mnt:[4]',
                         'executable_sha256': 'a' * 64} for pid in processes}
        metadata[holder['pid']]['mount_namespace'] = 'mnt:[5]'
        metadata[child['pid']]['parent'] = monitor['pid']
        return child, context, processes, metadata

    def test_closed_checkpoint_admission_binds_ancestry_and_journal_without_relaxing_launchers(self):
        child, context, processes, metadata = self.checkpoint_fixture()
        with patch.object(lifecycle, 'process_identity', side_effect=processes.__getitem__), \
                patch.object(lifecycle, 'checkpoint_process', side_effect=metadata.__getitem__):
            with self.assertRaisesRegex(Invalid, 'recorded container namespace'):
                lifecycle.admit(self.store, self.actor['token'], self.unit, child)
            self.kernel.admit_stopped.assert_not_called()
            lifecycle.admit(self.store, self.actor['token'], self.unit, child, closed_checkpoint=context)
            with self.assertRaisesRegex(Invalid, 'already attempted'):
                lifecycle.admit(self.store, self.actor['token'], self.unit, child, closed_checkpoint=context)
        self.kernel.admit_stopped.assert_called_once_with(child)
        launch = next(e for e in self.store.audit_export('website')['events']
                      if e['request']['action'] == 'workload_launch')
        self.assertEqual(launch['state'], 'complete')
        self.assertIn(context['frontend_sha256'], json.dumps(launch))
        self.assertNotIn(self.actor['token'], json.dumps(launch))

    def test_closed_checkpoint_rejects_forged_stale_and_cross_namespace_children(self):
        for failure in ('parent', 'frontend', 'mount', 'holder_mount', 'holder_pid',
                        'user', 'cgroup', 'monitor_pid', 'monitor_stale', 'running', 'invalid_binding'):
            child, context, processes, metadata = self.checkpoint_fixture()
            if failure == 'parent': metadata[child['pid']]['parent'] = 999
            if failure == 'frontend': metadata[child['pid']]['executable_sha256'] = 'b' * 64
            if failure == 'mount': metadata[child['pid']]['mount_namespace'] = 'mnt:[9]'
            if failure == 'holder_mount': metadata[126]['mount_namespace'] = 'mnt:[4]'
            if failure == 'holder_pid': child['pid_namespace'] = 'pid:[9]'
            if failure == 'user': child['user_namespace'] = 'user:[9]'
            if failure == 'cgroup': child['cgroup'] += '/other'
            if failure == 'monitor_pid': context['monitor']['pid_namespace'] = 'pid:[3]'
            if failure == 'monitor_stale': processes[125] = dict(processes[125], starttime=999)
            if failure == 'running': child['state'] = 'R'
            if failure == 'invalid_binding': context['claimed_permission'] = True
            with self.subTest(failure=failure), \
                    patch.object(lifecycle, 'process_identity', side_effect=processes.__getitem__), \
                    patch.object(lifecycle, 'checkpoint_process', side_effect=metadata.__getitem__), \
                    self.assertRaises(Invalid):
                lifecycle.admit(self.store, self.actor['token'], self.unit, child, closed_checkpoint=context)
        self.kernel.admit_stopped.assert_not_called()

    def test_closed_checkpoint_respects_session_stop_and_completion_failure(self):
        child, context, processes, metadata = self.checkpoint_fixture()
        with patch.object(lifecycle, 'process_identity', side_effect=processes.__getitem__), \
                patch.object(lifecycle, 'checkpoint_process', side_effect=metadata.__getitem__):
            for token in ('forged', self.other['token']):
                with self.assertRaises(Invalid):
                    lifecycle.admit(self.store, token, self.unit, child, closed_checkpoint=context)
            self.kernel.admit_stopped.assert_not_called()
            with patch.object(self.store, 'complete', side_effect=OSError('lost completion')), \
                    self.assertRaises(OSError):
                lifecycle.admit(self.store, self.actor['token'], self.unit, child, closed_checkpoint=context)
            self.kernel.terminate.assert_called()
            with self.assertRaises(Invalid):
                lifecycle.admit(self.store, self.actor['token'], self.unit, child, closed_checkpoint=context)
        self.kernel.admit_stopped.assert_called_once()

    def continuation_fixture(self):
        child, context, processes, metadata = self.checkpoint_fixture()
        self.enterContext(patch.object(lifecycle, 'process_identity', side_effect=processes.__getitem__))
        self.enterContext(patch.object(lifecycle, 'checkpoint_process', side_effect=metadata.__getitem__))
        lifecycle.admit(self.store, self.actor['token'], self.unit, child, closed_checkpoint=context)
        continued = dict(child, cgroup=self.kernel.identity['cgroup'])
        processes[child['pid']] = continued
        metadata[child['pid']]['mount_namespace'] = metadata[126]['mount_namespace']
        self.kernel.continue_stopped.return_value = continued
        return child, context, processes, metadata, continued

    def test_checkpoint_continuation_is_one_use_and_never_readmits(self):
        child, context, _, _, continued = self.continuation_fixture()
        result = lifecycle.continue_checkpoint(Store(self.root / 'state'), self.actor['token'],
                                              self.unit, child, continued, context)
        self.assertEqual(result, continued)
        self.kernel.admit_stopped.assert_called_once_with(child)
        self.kernel.continue_stopped.assert_called_once_with(continued)
        with self.assertRaisesRegex(Invalid, 'already attempted'):
            lifecycle.continue_checkpoint(self.store, self.actor['token'], self.unit,
                                          child, continued, context)
        events = self.store.audit_export('website')['events']
        event = next(e for e in events if e['request']['action'] == 'workload_continue')
        self.assertEqual(event['state'], 'complete')
        self.assertEqual(event['result']['effect'], 'closed_checkpoint_continued')
        self.assertNotIn(self.actor['token'], json.dumps(events))

    def test_checkpoint_continuation_rejects_missing_changed_and_unconfined_identity(self):
        child, context, processes, metadata, continued = self.continuation_fixture()
        for key, value in (('pid', 999), ('starttime', 999), ('state', 'R'),
                           ('cgroup', self.group), ('pid_namespace', 'pid:[9]'),
                           ('user_namespace', 'user:[9]')):
            with self.subTest(field=key), self.assertRaises(Invalid):
                lifecycle.continue_checkpoint(self.store, self.actor['token'], self.unit,
                                              child, dict(continued, **{key: value}), context)
        for key, value in (('parent', 999), ('mount_namespace', 'mnt:[4]'),
                           ('executable_sha256', 'b' * 64)):
            with self.subTest(metadata=key), patch.dict(metadata[child['pid']], {key: value}), \
                    self.assertRaises(Invalid):
                lifecycle.continue_checkpoint(self.store, self.actor['token'], self.unit,
                                              child, continued, context)
        for token in ('forged', self.other['token']):
            with self.assertRaises(Invalid):
                lifecycle.continue_checkpoint(self.store, token, self.unit, child, continued, context)
        with patch.object(lifecycle, 'runtime_identity', return_value='changed'), self.assertRaises(Invalid):
            lifecycle.continue_checkpoint(self.store, self.actor['token'], self.unit, child, continued, context)
        with self.assertRaisesRegex(Invalid, 'Missing original'):
            lifecycle.continue_checkpoint(self.store, self.actor['token'], self.unit,
                                          dict(child, starttime=999), continued, context)
        with self.store.locked() as db:
            db.execute("UPDATE events SET response='{}' WHERE event LIKE 'native_launch:%'")
        with self.assertRaisesRegex(Invalid, 'evidence changed'):
            lifecycle.continue_checkpoint(self.store, self.actor['token'], self.unit, child, continued, context)
        self.kernel.continue_stopped.assert_not_called()

    def test_checkpoint_file_scope_is_required_before_admission(self):
        child, context, processes, metadata = self.checkpoint_fixture()
        for altered in (None, {}, dict(context['file_scope'], authority=[])):
            with self.subTest(scope=altered), \
                    patch.object(lifecycle, 'process_identity', side_effect=processes.__getitem__), \
                    patch.object(lifecycle, 'checkpoint_process', side_effect=metadata.__getitem__), \
                    self.assertRaises(Invalid):
                lifecycle.admit(self.store, self.actor['token'], self.unit, child,
                                closed_checkpoint=dict(context, file_scope=altered))
        self.kernel.admit_stopped.assert_not_called()

    def test_checkpoint_rechecks_resource_identity_before_continuation(self):
        child, context, _, _, continued = self.continuation_fixture()
        path = self.root / 'fixture/resources/work'
        path.rename(path.with_name('previous-work'))
        path.mkdir()
        with self.assertRaisesRegex(Invalid, 'resource identity changed'):
            lifecycle.continue_checkpoint(self.store, self.actor['token'], self.unit,
                                          child, continued, context)
        self.kernel.continue_stopped.assert_not_called()
        self.kernel.admit_stopped.assert_called_once()

    def test_checkpoint_continuation_completion_failure_revokes_and_cannot_replay(self):
        child, context, _, _, continued = self.continuation_fixture()
        with patch.object(self.store, 'complete', side_effect=OSError('lost completion')), \
                self.assertRaises(OSError):
            lifecycle.continue_checkpoint(self.store, self.actor['token'], self.unit, child, continued, context)
        # Local termination and the existing capture-fault project stop both
        # target the same owned subtree. Neither is a launch retry.
        self.assertEqual(self.kernel.terminate.call_count, 2)
        self.kernel.continue_stopped.assert_called_once()
        with self.assertRaises(Invalid):
            lifecycle.continue_checkpoint(Store(self.root / 'state'), self.actor['token'],
                                          self.unit, child, continued, context)
        self.assertFalse(self.store.status('website')['violations'])

    def test_checkpoint_continuation_stop_serializes_and_rejects_later_release(self):
        child, context, _, _, continued = self.continuation_fixture()
        entered, release, stopping = threading.Event(), threading.Event(), threading.Event()
        def pending(expected):
            entered.set()
            if not release.wait(5): raise TimeoutError('Continuation fixture not released')
            return expected
        def stop():
            stopping.set()
            return self.store.stop('website')
        self.kernel.continue_stopped.side_effect = pending
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            launch = pool.submit(lifecycle.continue_checkpoint, self.store, self.actor['token'],
                                 self.unit, child, continued, context)
            try:
                self.assertTrue(entered.wait(5))
                stopped = pool.submit(stop)
                self.assertTrue(stopping.wait(5))
                with self.assertRaises(concurrent.futures.TimeoutError): stopped.result(timeout=.05)
            finally:
                release.set()
            launch.result(timeout=5)
            self.assertTrue(stopped.result(timeout=5)['stopped'])
        self.assertTrue(Supervisor(self.store).reconcile()[0]['confirmed_stopped'])
        with self.assertRaises(Invalid):
            lifecycle.continue_checkpoint(self.store, self.actor['token'], self.unit, child, continued, context)

    def test_checkpoint_continuation_intent_failure_stops_without_resume(self):
        child, context, _, _, continued = self.continuation_fixture()
        with patch.object(self.store, 'lifecycle', side_effect=OSError('intent storage')), \
                self.assertRaises(OSError):
            lifecycle.continue_checkpoint(self.store, self.actor['token'], self.unit, child, continued, context)
        self.kernel.continue_stopped.assert_not_called()
        self.kernel.terminate.assert_called()
        with self.store.locked() as db:
            self.assertTrue(db.execute('SELECT revoked FROM native_workloads').fetchone()[0])

    def test_checkpoint_continuation_stopped_project_never_resumes(self):
        child, context, _, _, continued = self.continuation_fixture()
        self.store.stop('website')
        with self.assertRaises(Invalid):
            lifecycle.continue_checkpoint(self.store, self.actor['token'], self.unit, child, continued, context)
        self.kernel.continue_stopped.assert_not_called()

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
                self.assertEqual(args.count('--dev'), 1)
                self.assertEqual(args[args.index('--dev') + 1], '/dev')
                self.assertLess(args.index('--dev'), args.index('--seccomp'))
                self.assertNotIn('--dev-bind', args)
                self.assertNotIn('--dev-bind-try', args)
                self.assertEqual(args.count('/dev'), 1)
                self.assertNotIn('/dev/pts', args)
                self.assertNotIn('/dev/fd', args)  # bwrap owns the standard links
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
            close.reset_mock()
            execute.side_effect = OSError('device setup unavailable')
            with self.assertRaisesRegex(OSError, 'device setup unavailable'):
                namespace.main()
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
            if argv[-1] == '--sudo-identity-control':
                return json.dumps({'status': 'observed', 'executable_sha256': 'c' * 64}).encode()
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
            identity_assignment = ast.parse(launched[0]['argv'][-1]).body[1]
            self.assertEqual(ast.literal_eval(identity_assignment.value), 'c' * 64)
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
            self.assertIn('namespace/sudo-identity-trusted.json', receipt['records'])
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

    def test_identity_control_preserves_native_request_and_only_numeric_output(self):
        metadata = {'resolved': '/usr/bin/id', 'opened_uid': 0, 'opened_mode': '0o100755',
                    'sha256': 'c' * 64, 'elf': {}}
        readonly = unittest.mock.Mock(f_flag=os.ST_RDONLY)
        completed = subprocess.CompletedProcess([], 0,
            b'uid=1000(dev) gid=1000(dev) groups=1000(dev),27(sudo)\n', b'private warning')
        with patch.object(loader_diagnostics, 'file_metadata', return_value=metadata), \
                patch.object(os, 'geteuid', return_value=0), \
                patch.object(os, 'statvfs', return_value=readonly), \
                patch.object(subprocess, 'run', return_value=completed) as run:
            result = loader_diagnostics.sudo_identity_control('c' * 64)
        self.assertEqual(result['status'], 'observed')
        self.assertEqual((result['uid'], result['gid'], result['groups']), (1000, 1000, [1000, 27]))
        run.assert_called_once_with(['/usr/bin/sudo', '-n', '-u', 'dev', '--', '/usr/bin/id'],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=5, close_fds=True,
            cwd='/', env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        self.assertNotIn('private warning', json.dumps(result))
        self.assertNotIn('stdout', result)
        self.assertNotIn('stderr', result)

    def test_identity_control_refuses_unverified_or_mutable_executable(self):
        metadata = {'resolved': '/usr/bin/id', 'opened_uid': 0, 'opened_mode': '0o100755',
                    'sha256': 'c' * 64, 'elf': {}}
        cases = [({'sha256': 'd' * 64}, 0, os.ST_RDONLY),
                 ({'resolved': '/probe/id'}, 0, os.ST_RDONLY),
                 ({'opened_uid': 1000}, 0, os.ST_RDONLY),
                 ({'opened_mode': '0o100775'}, 0, os.ST_RDONLY),
                 ({'opened_mode': '0o104755'}, 0, os.ST_RDONLY),
                 ({'opened_mode': '0o100644'}, 0, os.ST_RDONLY),
                 ({'opened_mode': '0o010755'}, 0, os.ST_RDONLY),
                 ({'sha256': ''}, 0, os.ST_RDONLY), ({}, 1000, os.ST_RDONLY), ({}, 0, 0)]
        for changed, uid, flags in cases:
            with self.subTest(changed=changed, uid=uid, flags=flags), \
                    patch.object(loader_diagnostics, 'file_metadata', return_value=metadata | changed), \
                    patch.object(os, 'geteuid', return_value=uid), \
                    patch.object(os, 'statvfs', return_value=unittest.mock.Mock(f_flag=flags)), \
                    patch.object(subprocess, 'run') as run:
                self.assertEqual(loader_diagnostics.sudo_identity_control('c' * 64)['status'],
                                 'unverified_executable')
                run.assert_not_called()

    def test_identity_control_failure_timeout_changed_bytes_and_invalid_output(self):
        metadata = {'resolved': '/usr/bin/id', 'opened_uid': 0, 'opened_mode': '0o100755',
                    'sha256': 'c' * 64, 'elf': {}}
        cases = [
            (subprocess.TimeoutExpired([], 5, output=b'private output'), 'timeout'),
            (FileNotFoundError(2, 'missing'), 'launch_error'),
            (subprocess.CompletedProcess([], 1, b'',
                b'account validation failure, is your account locked?'), 'sudo_failed'),
            (subprocess.CompletedProcess([], -9, b'', b''), 'sudo_failed'),
            (subprocess.CompletedProcess([], 0, b'x' * (loader_diagnostics.MAX_OUTPUT + 1), b''), 'output_limit')]
        for data in (b'', b'uid=0(root) gid=0(root) groups=0(root)\n',
                     b'uid=1000(dev) gid=1000(dev) groups=27(sudo)\n',
                     b'uid=1000(dev) gid=1000(dev) groups=1000(dev) euid=0(root)\n',
                     b'uid=4294967295(dev) gid=1000(dev) groups=1000(dev)\n',
                     b'uid=1000(dev) gid=1000(dev) groups=1000(de,v)\n',
                     b'uid=' + b'1' * 5000 + b' gid=1000 groups=1000\n'):
            cases.append((subprocess.CompletedProcess([], 0, data, b''), 'invalid_identity'))
        for completed, expected in cases:
            with self.subTest(status=expected), \
                    patch.object(loader_diagnostics, 'file_metadata', return_value=metadata), \
                    patch.object(os, 'geteuid', return_value=0), \
                    patch.object(os, 'statvfs', return_value=unittest.mock.Mock(f_flag=os.ST_RDONLY)), \
                    patch.object(subprocess, 'run', **({'side_effect': completed} if
                        isinstance(completed, Exception) else {'return_value': completed})) as run:
                result = loader_diagnostics.sudo_identity_control('c' * 64)
                self.assertEqual(result['status'], expected)
                self.assertNotIn('uid', result)
                self.assertNotIn('private output', json.dumps(result))
                self.assertEqual(run.call_count, 1)
        with patch.object(loader_diagnostics, 'file_metadata', side_effect=[metadata,
                    metadata | {'sha256': 'd' * 64}]), \
                patch.object(os, 'geteuid', return_value=0), \
                patch.object(os, 'statvfs', return_value=unittest.mock.Mock(f_flag=os.ST_RDONLY)), \
                patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 0,
                    b'uid=1000 gid=1000 groups=1000\n', b'')):
            self.assertEqual(loader_diagnostics.sudo_identity_control()['status'], 'executable_changed')

    def test_failed_trusted_identity_control_retained_and_no_mutable_admission(self):
        daemon = {'cgroup': '/fixture.slice', 'daemon_id': 'fixture-daemon', 'image_id': 'sha256:' + 'b' * 64}
        cid = 'a' * 64
        calls = []
        def command(argv):
            calls.append(argv)
            if argv[:2] == ['docker', 'create']:
                return cid.encode()
            if argv[-1] == '--sudo-identity-control':
                return b'{"status":"sudo_failed","returncode":1}'
            return b'{}'
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root = Path(temporary)
            with patch.object(confinement, 'stage_tools', return_value=(root, {})), \
                    patch.object(preflight, 'wait_for', return_value=True), \
                    patch.object(lifecycle, 'admit') as admit, \
                    self.assertRaisesRegex(ValueError, 'Trusted native sudo identity control failed'):
                confinement.probe(command, root, daemon)
            admit.assert_not_called()
            self.assertFalse(any(row[:3] == ['docker', 'exec', '--detach'] for row in calls))
            self.assertEqual(calls[-1], ['docker', 'rm', '--force', cid])
            receipt = load(root / 'namespace-diagnostics.json')
            self.assertIn('namespace/sudo-identity-trusted.json', receipt['records'])
            self.assertIn('namespace/probe/sudo-identity-confined.json', receipt['missing'])
            self.assertEqual(load(root / 'namespace/sudo-identity-trusted.json')['status'], 'sudo_failed')

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
                        'sudo_identity_control': lambda _: {'status': 'sudo_failed'},
                        'account_process_record': account}), \
                    patch.object(subprocess, 'run', return_value=failure), patch('builtins.open', side_effect=opened):
                with self.assertRaises(AssertionError) as raised:
                    exec(section, {'json': json, 'runpy': __import__('runpy'), 'subprocess': subprocess,
                                   'sys': sys, 'LOADER_INVENTORY': {}, 'IDENTITY_SHA256': 'c' * 64,
                                   'observed': {}})
                self.assertEqual(str(raised.exception), failure.stderr)
            self.assertEqual(outputs['/probe/loader-confined.json'], {'fixture': 'diagnostic'})
            self.assertEqual(outputs['/probe/sudo-identity-confined.json']['status'], 'sudo_failed')
            self.assertEqual(outputs['/probe/sudo-exec.json']['returncode'], 1)
            self.assertEqual(outputs['/probe/sudo-exec.json']['stderr'], failure.stderr)
            if account_failure:
                account.assert_called_once_with()
                self.assertEqual(outputs['/probe/pam-account-hook.json'], account.return_value)
            else:
                account.assert_not_called()
                self.assertNotIn('/probe/pam-account-hook.json', outputs)


class BridgeClosedGateTests(unittest.TestCase):
    def test_release_callback_requires_verified_child_and_is_one_use(self):
        # Synthetic native snapshot state tests the actual callback. This does
        # not substitute for the separate native policy/session acceptance.
        driver = r'''
#define PTW_REQUEST_RELEASE 1
#include "linuxarena_sudo_gate.c"
#include <assert.h>
#include <stdarg.h>
static int output(int kind, const char *format, ...) { (void)kind; (void)format; return 0; }
int main(int argc, char **argv) {
    assert(argc == 2);
    assert(release_option_supported("noexec=false"));
    assert(release_option_supported("use_pty=true"));
    assert(release_option_supported("exec_background=false"));
    const char *unsupported[] = {"noexec=true", "noexec=1", "noexec=garbage", "preserve_fds=3",
        "selinux_role=user_r", "selinux_type=user_t", "exec_background=true", NULL};
    for (int i = 0; unsupported[i]; i++) assert(!release_option_supported(unsupported[i]));
    char *env[] = {"KEY=approved\n", "EMPTY=", NULL};
    char *args[] = {"different argv0", "", "spaces $()\n", NULL};
    char *info[] = {"command=/usr/bin/true", NULL};
    assert(!vector_copy(&request.argv, args, 0));
    assert(!vector_copy(&request.environment, env, 1));
    assert(!vector_copy(&request.info, info, 1));
    request.cwd = strdup("/synthetic-cwd");
    struct stat ns; assert(!stat("/proc/self/ns/pid", &ns));
    request.child_namespace = ns.st_ino; request.child_pid = getpid();
    opened = request.session = request.child_verified = 1; report = output;
    if (!strcmp(argv[1], "session")) request.session = 0;
    if (!strcmp(argv[1], "verified")) request.child_verified = 0;
    if (!strcmp(argv[1], "pid")) request.child_pid++;
    if (!strcmp(argv[1], "namespace")) request.child_namespace++;
    if (!strcmp(argv[1], "environment")) env[0] = "KEY=forged";
    if (!strcmp(argv[1], "closed")) closed = 1;
    int result = ptw_sudo_request_child_v1(2, env, getuid(), geteuid());
    if (strcmp(argv[1], "valid")) {
        assert(result == -1 && redirect_argv[1] == NULL);
    } else {
        assert(!result && !strcmp(redirect_argv[1], "--pending"));
        assert(!strcmp(redirect_argv[2], "/usr/bin/true"));
        assert(!strcmp(redirect_argv[3], "/synthetic-cwd"));
        assert(!strcmp(redirect_argv[6], "2"));
        assert(!strcmp(redirect_argv[7], env[0]) && !strcmp(redirect_argv[8], env[1]));
        assert(!*redirect_argv[9] && !strcmp(redirect_argv[10], args[0]));
        assert(!*redirect_argv[11] && !strcmp(redirect_argv[12], args[2]) && !redirect_argv[13]);
        assert(ptw_sudo_request_child_v1(2, env, getuid(), geteuid()) == -1);
    }
    request_free(); return 0;
}
'''
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'sudo_plugin.h').write_text(self.plugin_header())
            (root / 'driver.c').write_text(driver)
            result = subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                '-I' + str(root), '-I' + str(SCRIPTS), str(root / 'driver.c'), '-ldl', '-o', str(root / 'driver')],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            for mode in ('valid', 'session', 'verified', 'pid', 'namespace', 'environment', 'closed'):
                with self.subTest(mode=mode):
                    result = subprocess.run([str(root / 'driver'), mode], capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_requested_release_frame_and_inode_binding(self):
        driver = r'''
#define _GNU_SOURCE
#define PTW_CLOSED_HELPER
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>
/* Mount/owner predicates are synthetic in the coding user namespace; real file/cwd identities
 * and open descriptors exercise replacement denial. No payload executes. */
static int bad_owner, writable;
static int probe_fs(int fd, struct statvfs *fs) {
    int result = fstatvfs(fd, fs);
    if (writable) fs->f_flag &= ~ST_RDONLY; else fs->f_flag |= ST_RDONLY;
    return result;
}
static int probe_stat(const char *p, struct stat *st) { int r = stat(p, st); st->st_uid = 0; return r; }
static int probe_fstat(int fd, struct stat *st) { int r = fstat(fd, st); st->st_uid = bad_owner; return r; }
#define stat(path, st) probe_stat(path, st)
#define fstat probe_fstat
#define fstatvfs probe_fs
#include "linuxarena_sudo_release.h"
int main(int argc, char **argv) {
    assert(argc == 2);
    char executable[384], directory[384]; struct stat st;
    assert(stat("/usr/bin/true", &st) == 0 && release_identity(executable, &st, 0) == 0);
    assert(stat(argv[1], &st) == 0 && release_identity(directory, &st, 1) == 0);
    char *frame[] = {"helper", "--pending", "/usr/bin/true", argv[1], executable,
        directory, "2", "KEY=spaces $()\n", "EMPTY=", "", "custom argv0", "", "-x", NULL};
    struct release_view view;
    assert(release_parse(13, frame, &view) == 0);
    assert(!strcmp(view.args[0], "custom argv0") && !*view.args[1]);
    assert(!strcmp(view.env[0], "KEY=spaces $()\n"));
    int fd = release_bind(&view);
    assert(fd >= 0 && (fcntl(fd, F_GETFD) & FD_CLOEXEC)); close(fd);
    bad_owner = 1; assert(release_bind(&view) == -1); bad_owner = 0;
    writable = 1; assert(release_bind(&view) == -1); writable = 0;
    char saved = executable[0]; executable[0] = '!';
    assert(release_bind(&view) == -1); executable[0] = saved;
    saved = directory[0]; directory[0] = '!';
    assert(release_bind(&view) == -1); directory[0] = saved;
    frame[8] = "KEY=duplicate"; assert(release_parse(13, frame, &view) == -1);
    frame[8] = "missing-equals"; assert(release_parse(13, frame, &view) == -1);
    frame[8] = "=empty-key"; assert(release_parse(13, frame, &view) == -1);
    frame[8] = "EMPTY=";
    const char *bad[] = {"-1", "+2", "257", "999999999999999999999999", "2x", "", "3", NULL};
    for (int i = 0; bad[i]; i++) { frame[6] = (char *)bad[i]; assert(release_parse(13, frame, &view) == -1); }
    frame[6] = "2"; frame[9] = "no separator"; assert(release_parse(13, frame, &view) == -1);
    frame[9] = ""; frame[2] = "relative"; assert(release_parse(13, frame, &view) == -1);
    frame[2] = "/usr/bin/true"; frame[1] = "--unknown"; assert(release_parse(13, frame, &view) == -1);
    frame[1] = "--confined"; assert(release_parse(13, frame, &view) == 0);
    assert(release_parse(8, frame, &view) == -1);
    char *huge = malloc(PTW_RELEASE_BYTES + 1); assert(huge);
    memset(huge, 'x', PTW_RELEASE_BYTES); huge[PTW_RELEASE_BYTES] = 0;
    frame[12] = huge; assert(release_parse(13, frame, &view) == -1 && errno == E2BIG);
    free(huge); return 0;
}
'''
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'driver.c').write_text(driver)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-I' + str(SCRIPTS),
                            str(root / 'driver.c'), '-o', str(root / 'driver')],
                           capture_output=True, text=True, timeout=30, check=True)
            result = subprocess.run([str(root / 'driver'), str(root)], capture_output=True,
                                    text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_compiled_request_snapshot_retains_bytes_and_rejects_changed_bindings(self):
        # Real private files/FDs, synthetic immutable-mount predicate. Native
        # checks independently require readonly image files and real sudo/PAM.
        driver = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
static int immutable_fd(const char *path) { return open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); }
static int allocations, fail_after;
static void *test_calloc(size_t count, size_t size) {
    if (++allocations == fail_after) { errno = ENOMEM; return NULL; }
    return calloc(count, size);
}
static char *test_strdup(const char *text) {
    if (++allocations == fail_after) { errno = ENOMEM; return NULL; }
    return strdup(text);
}
#define calloc test_calloc
#define strdup test_strdup
#include "linuxarena_sudo_request.h"
#undef calloc
#undef strdup
int main(int argc, char **argv) {
    assert(argc == 3 && chdir(argv[2]) == 0);
    char path[4096], command[4200], cwd[4200];
    assert(getcwd(path, sizeof(path)));
    snprintf(command, sizeof(command), "command=%s/program", path);
    snprintf(cwd, sizeof(cwd), "cwd=%s/work", path);
    int fd = open("program", O_CREAT | O_EXCL | O_WRONLY, 0700);
    assert(fd >= 0 && write(fd, "fixture", 7) == 7 && close(fd) == 0);
    assert(mkdir("work", 0700) == 0);
    char *info[] = {command, cwd, "runas_uid=1000", NULL, NULL};
    char arg[] = "spaces \" ' $()\nempty follows";
    char *args[] = {"program", arg, "", NULL};
    char *env[] = {"KEY=approved=bytes\n", "PAM_VALUE=after-session", NULL};
    if (!strcmp(argv[1], "allocation")) {
        for (int n = 1; n <= 9; n++) {
            allocations = 0; fail_after = n;
            assert(request_capture(info, args) == -1 && errno == ENOMEM);
            assert(!request.ready && request.executable_fd == -1 && request.cwd_fd == -1);
        }
        fail_after = 0;
        assert(request_capture(info, args) == 0);
        for (int n = 1; n <= 3; n++) {
            allocations = 0; fail_after = n;
            assert(request_finish(env) == -1 && errno == ENOMEM && !request.session);
            request_free();
            fail_after = 0;
            assert(request_capture(info, args) == 0);
        }
        request_free(); return 0;
    }
    if (!strcmp(argv[1], "limits")) {
        struct request_vector v = {0};
        char *many[PTW_REQUEST_ITEMS + 2];
        for (int i = 0; i <= PTW_REQUEST_ITEMS; i++) many[i] = "";
        many[PTW_REQUEST_ITEMS] = NULL;
        assert(vector_copy(&v, many, 0) == 0 && v.count == PTW_REQUEST_ITEMS);
        vector_free(&v);
        many[PTW_REQUEST_ITEMS] = "overflow"; many[PTW_REQUEST_ITEMS + 1] = NULL;
        assert(vector_copy(&v, many, 0) == -1 && errno == E2BIG && !v.items);
        char *large = malloc(PTW_REQUEST_BYTES + 1);
        assert(large); memset(large, 'x', PTW_REQUEST_BYTES); large[PTW_REQUEST_BYTES] = 0;
        char *long_args[] = {large, NULL};
        assert(vector_copy(&v, long_args, 0) == -1 && errno == E2BIG);
        large[PTW_REQUEST_BYTES - 1] = 0;
        assert(vector_copy(&v, long_args, 0) == 0 && v.bytes == PTW_REQUEST_BYTES);
        vector_free(&v); free(large);
        char *valid[] = {"EMPTY=", "VALUE=a=b", NULL};
        assert(vector_copy(&v, valid, 1) == 0); vector_free(&v);
        valid[0] = "=empty-key";
        assert(vector_copy(&v, valid, 1) == -1 && errno == EINVAL);
        valid[0] = "missing-equals";
        assert(vector_copy(&v, valid, 1) == -1 && errno == EINVAL);
        assert(vector_copy(&v, NULL, 0) == -1 && errno == EINVAL);
        return 0;
    }
    if (!strcmp(argv[1], "duplicate")) info[3] = "command=/different";
    if (!strcmp(argv[1], "missing")) info[0] = "other=value";
    if (!strcmp(argv[1], "relative")) info[0] = "command=program";
    if (!strcmp(argv[1], "bad_execfd")) info[3] = "execfd=-1";
    if (!strcmp(argv[1], "wrong_execfd")) info[3] = "execfd=999999";
    if (!strcmp(argv[1], "missing_cwd")) info[1] = "cwd=/nonexistent-private-fixture";
    if (!strcmp(argv[1], "empty_argv")) args[0] = NULL;
    if (!strcmp(argv[1], "nonexec")) {
        assert(unlink("program") == 0);
        fd = open("program", O_CREAT | O_EXCL | O_WRONLY, 0600);
        assert(fd >= 0 && close(fd) == 0);
    }
    if (!strcmp(argv[1], "symlink")) {
        assert(rename("program", "original") == 0 && symlink("original", "program") == 0);
    }
    int result = request_capture(info, args);
    if (!strcmp(argv[1], "duplicate") || !strcmp(argv[1], "missing") ||
        !strcmp(argv[1], "relative") || !strcmp(argv[1], "bad_execfd") ||
        !strcmp(argv[1], "wrong_execfd") || !strcmp(argv[1], "missing_cwd") ||
        !strcmp(argv[1], "empty_argv") || !strcmp(argv[1], "symlink") || !strcmp(argv[1], "nonexec")) {
        assert(result == -1 && !request.ready && request.executable_fd == -1 && request.cwd_fd == -1);
        request_free(); return 0;
    }
    assert(result == 0 && request.info.items != info && request.argv.items != args);
    assert(request.argv.count == 3 && !strcmp(request.argv.items[1], arg) && !request.argv.items[2][0]);
    assert(request.caller_uid == getuid() && request.caller_gid == getgid());
    int pinned = request.executable_fd, directory = request.cwd_fd;
    assert(fcntl(pinned, F_GETFD) & FD_CLOEXEC);
    assert(fcntl(directory, F_GETFD) & FD_CLOEXEC);
    if (!strcmp(argv[1], "argv_change")) arg[0] = '!';
    if (!strcmp(argv[1], "info_change")) info[2] = "runas_uid=0";
    if (!strcmp(argv[1], "replace_executable")) {
        assert(rename("program", "old") == 0);
        fd = open("program", O_CREAT | O_EXCL | O_WRONLY, 0700);
        assert(fd >= 0 && write(fd, "fixture", 7) == 7 && close(fd) == 0);
    }
    if (!strcmp(argv[1], "change_executable")) {
        fd = open("program", O_WRONLY | O_APPEND);
        assert(fd >= 0 && write(fd, "changed", 7) == 7 && close(fd) == 0);
    }
    if (!strcmp(argv[1], "replace_cwd")) {
        assert(rename("work", "old-work") == 0 && mkdir("work", 0700) == 0);
    }
    if (!strcmp(argv[1], "bad_env")) env[1] = "KEY=duplicate";
    if (!strcmp(argv[1], "missing_env")) result = request_finish(NULL);
    else result = request_finish(env);
    if (!strncmp(argv[1], "child_", 6)) {
        assert(result == 0);
        char target_id[64];
        snprintf(target_id, sizeof(target_id), "runas_uid=%u", (unsigned)getuid());
        /* Synthetic native result; exercise actual child lifetime and FD checks. */
        free(request.info.items[2]);
        request.info.items[2] = strdup(target_id);
        info[2] = target_id;
        if (!strcmp(argv[1], "child_no_claim")) {
            assert(request_child(1, env, getuid(), geteuid()) == -1);
            request_free(); return 0;
        }
        if (!strcmp(argv[1], "child_replace_executable")) {
            assert(rename("program", "old") == 0);
            fd = open("program", O_CREAT | O_EXCL | O_WRONLY, 0700);
            assert(fd >= 0 && close(fd) == 0);
            assert(request_child(0, NULL, 0, 0) == -1);
            request_free(); return 0;
        }
        if (!strcmp(argv[1], "child_replace_cwd")) {
            assert(rename("work", "old-work") == 0 && mkdir("work", 0700) == 0);
            assert(request_child(0, NULL, 0, 0) == -1);
            request_free(); return 0;
        }
        assert(request_child(0, NULL, 0, 0) == 0);
        if (!strcmp(argv[1], "child_replay")) {
            assert(request_child(0, NULL, 0, 0) == -1);
            assert(request_child(1, env, getuid(), geteuid()) == -1);
            request_free(); return 0;
        }
        if (!strcmp(argv[1], "child_fork")) {
            pid_t child = fork(); assert(child >= 0);
            if (!child) _exit(request_child(1, env, getuid(), geteuid()) == -1 ? 0 : 1);
            int status;
            assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
            assert(request_child(1, env, getuid(), geteuid()) == 0);
            request_free(); return 0;
        }
        if (!strcmp(argv[1], "child_changed_env")) env[1] = "PAM_VALUE=changed";
        if (!strcmp(argv[1], "child_changed_target")) request.info.items[2][0] = '!';
        if (!strcmp(argv[1], "child_changed_process")) request.child_pid++;
        if (!strcmp(argv[1], "child_changed_namespace")) request.child_namespace++;
        result = request_child(1, env, getuid(), geteuid());
        assert(result == (!strcmp(argv[1], "child_normal") ? 0 : -1));
        assert(request_child(1, env, getuid(), geteuid()) == -1);
        request_free(); return 0;
    }
    if (!strcmp(argv[1], "normal")) {
        assert(result == 0 && request.session && request.environment.items != env);
        assert(!strcmp(request.environment.items[1], "PAM_VALUE=after-session"));
        env[1] = "PAM_VALUE=later-change";
        assert(!strcmp(request.environment.items[1], "PAM_VALUE=after-session"));
        assert(request_finish(env) == -1); /* no session replay */
    } else assert(result == -1 && !request.session);
    assert(request.executable_fd == -1 && request.cwd_fd == -1);
    assert(fcntl(pinned, F_GETFD) == -1 && errno == EBADF);
    assert(fcntl(directory, F_GETFD) == -1 && errno == EBADF);
    request_free(); request_free();
    assert(request_capture(info, args) == 0); /* owned copies were freed */
    request_free();
    return 0;
}
'''
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root = Path(temporary)
            (root / 'driver.c').write_text(driver)
            built = subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                '-I' + str(SCRIPTS), str(root / 'driver.c'), '-o', str(root / 'driver')],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stderr)
            for case in ('normal', 'allocation', 'limits', 'duplicate', 'missing', 'relative', 'bad_execfd', 'wrong_execfd',
                         'missing_cwd', 'empty_argv', 'nonexec', 'symlink', 'argv_change',
                         'info_change', 'replace_executable', 'change_executable', 'replace_cwd',
                         'bad_env', 'missing_env', 'child_normal', 'child_no_claim',
                         'child_replace_executable', 'child_replace_cwd', 'child_replay',
                         'child_changed_env', 'child_changed_target', 'child_changed_process',
                         'child_changed_namespace', 'child_fork'):
                with self.subTest(case=case):
                    (root / case).mkdir()
                    result = subprocess.run([str(root / 'driver'), case, str(root / case)],
                        capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout + result.stderr, '')

    def test_request_receipt_requires_original_identity_and_native_order(self):
        identity = dict(executable_dev=1, executable_ino=2, cwd_dev=3, cwd_ino=4)
        capture = ('PTW_SUDO_REQUEST captured=1 argc=2 caller_uid=0 caller_gid=0 '
                   'executable_dev=1 executable_ino=2 cwd_dev=3 cwd_ino=4')
        record = self.allowed(1000)
        record['stderr'] = record['stderr'].replace('PTW_SUDO_STAGE redirect=closed',
            capture + '\nPTW_SUDO_STAGE redirect=closed').replace('PTW_SUDO_STAGE session=1',
            'PTW_SUDO_REQUEST session=1 envc=12\nPTW_SUDO_STAGE session=1')
        sudo_gate.validate_request_binding('root_to_dev', record, identity)
        for old, new in ((capture + '\n', ''), ('caller_uid=0', 'caller_uid=1001'),
                         ('argc=2', 'argc=1'), ('executable_ino=2', 'executable_ino=9'),
                         ('cwd_ino=4', 'cwd_ino=9'), ('envc=12', 'envc=257'),
                         ('envc=12', 'envc=0'), (capture, capture + '\n' + capture),
                         ('PTW_SUDO_STAGE session=1', 'PTW_SUDO_STAGE session=0')):
            with self.subTest(new=new), self.assertRaises(ValueError):
                sudo_gate.validate_request_binding('root_to_dev',
                    dict(record, stderr=record['stderr'].replace(old, new)), identity)
        with self.assertRaises(ValueError):
            sudo_gate.validate_request_binding('native_denial', record, identity)

    def test_native_evidence_uses_configured_scratch_and_retains_failures(self):
        # Stop before any native operation, but exercise each real fixture's
        # directory selection. The manager configures tempfile's disk-backed
        # scratch; a hard-coded /tmp silently defeats that resource admission.
        class BeforeNativeWork(Exception):
            pass

        class SourceCache:
            sudo_source_receipt = classmethod(BridgeNativePrerequisiteTests.sudo_source_receipt.__func__)

        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory).resolve()
            outputs = []

            def stop(*args, **kwargs):
                raise BeforeNativeWork()

            cases = (
                (SourceCache.sudo_source_receipt, sudo_source, 'run'),
                (BridgeNativePrerequisiteTests('test_native_sudo_closed_delegation').test_native_sudo_closed_delegation,
                 sudo_gate, 'run'),
                (BridgeNativePrerequisiteTests('test_native_sudo_child_checkpoint').test_native_sudo_child_checkpoint,
                 sudo_gate, 'run'),
                (BridgeNativePrerequisiteTests('test_native_sudo_namespace_checkpoint').test_native_sudo_namespace_checkpoint,
                 sudo_gate, 'run'),
                (BridgeNativePrerequisiteTests('test_native_taskspace_and_container_subtree_stop').test_native_taskspace_and_container_subtree_stop,
                 preflight, 'run'),
                (BridgeNativePrerequisiteTests('test_prerequisite_terminal_help_and_invalid_arguments').test_prerequisite_terminal_help_and_invalid_arguments,
                 sudo_gate.terminal_driver, 'Terminal'),
            )
            with patch.object(tempfile, 'tempdir', str(scratch)), \
                    patch.object(BridgeNativePrerequisiteTests, 'sudo_source_receipt',
                                 return_value=(scratch / 'retained-source', {})):
                for invoke, module, name in cases:
                    with self.subTest(case=invoke.__name__), \
                            patch.object(module, name, side_effect=stop) as native, \
                            self.assertRaises(BeforeNativeWork):
                        invoke()
                    native.assert_called_once()
                    created = set(scratch.iterdir()) - set(outputs)
                    self.assertEqual(len(created), 1)
                    root = created.pop()
                    self.assertTrue(root.is_dir())
                    outputs.append(root)
                self.assertEqual(len(set(outputs)), len(cases))
                self.assertTrue(all(root.is_dir() for root in outputs))

    def test_source_failure_is_not_retried_by_other_native_case(self):
        class Cache:
            sudo_source_receipt = classmethod(BridgeNativePrerequisiteTests.sudo_source_receipt.__func__)
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary, \
                patch.object(tempfile, 'mkdtemp', return_value=temporary), \
                patch.object(sudo_source, 'run', side_effect=ValueError('source unavailable')) as run:
            with self.assertRaisesRegex(ValueError, 'source unavailable'):
                Cache.sudo_source_receipt()
            with self.assertRaisesRegex(RuntimeError, 'already failed'):
                Cache.sudo_source_receipt()
            self.assertEqual(run.call_count, 1)

    def allowed(self, uid, *, terminal=False):
        tty = int(terminal)
        return {'returncode': 125, 'original_effect': False,
                'stdout': f'PTW_CLOSED_GATE uid={uid} euid={uid} gid={uid} egid={uid}\n'
                          f'PTW_CLOSED_TERMINAL stdin={tty} stdout={tty} stderr={tty}\n',
                'stderr': '\n'.join(['PTW_SUDO_STAGE open=1', 'PTW_SUDO_STAGE check=1',
                    'PTW_SUDO_STAGE redirect=closed', 'PTW_SUDO_STAGE session=1',
                    'PTW_SUDO_STAGE close=32000 error=0']) + '\n'}

    def test_closed_gate_requires_native_target_session_cleanup_and_no_effect(self):
        for name, uid in (('root_to_dev', 1000), ('root_to_root', 0)):
            record = self.allowed(uid)
            self.assertEqual(sudo_gate.validate_observation(name, record), record)
            changed = [record | {'returncode': 0}, record | {'returncode': True},
                       record | {'original_effect': True}, record | {'original_effect': 0},
                       record | {'stdout': self.allowed(1001)['stdout']},
                       record | {'stdout': record['stdout'] + 'extra'},
                       record | {'stderr': record['stderr'].replace('session=1', 'session=0')},
                       record | {'stderr': record['stderr'].replace('close=32000 error=0', 'close=0 error=0')},
                       record | {'stderr': record['stderr'].replace('PTW_SUDO_STAGE close=32000 error=0\n', '')},
                       record | {'stderr': record['stderr'] + 'PTW_SUDO_REJECT operation=check reason=option errno=0 option=use_pty\n'},
                       record | {'stderr': record['stderr'] + 'PTW_SUDO_STAGE session=1\n'}]
            for bad in changed:
                with self.subTest(name=name, record=bad), self.assertRaises(ValueError):
                    sudo_gate.validate_observation(name, bad)

    def test_closed_gate_requires_native_denial_before_redirect(self):
        record = {'returncode': 1, 'stdout': '', 'original_effect': False,
                  'stderr': 'PTW_SUDO_STAGE open=1\nPTW_SUDO_STAGE check=0\nPTW_SUDO_STAGE close=0 error=13\n'}
        sudo_gate.validate_observation('native_denial', record)
        for changed in ({'stderr': ''}, {'returncode': 125},
                        {'stdout': self.allowed(0)['stdout']},
                        {'stderr': record['stderr'] + 'PTW_SUDO_STAGE redirect=closed\n'},
                        {'stderr': record['stderr'] + 'PTW_SUDO_STAGE session=1\n'},
                        {'stderr': record['stderr'].replace('PTW_SUDO_STAGE close=0 error=13\n', '')},
                        {'stderr': record['stderr'] + 'PTW_SUDO_STAGE close=0 error=13\n'},
                        {'original_effect': True}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                sudo_gate.validate_observation('native_denial', record | changed)
        with self.assertRaisesRegex(ValueError, 'Unknown'):
            sudo_gate.validate_observation('other', record)
        for name in ('native_denial', 'invalid_target', 'unsupported_edit'):
            sudo_gate.validate_observation(name, record)
            for status in (-11, -9, -1, 0, 125, 256, True):
                with self.subTest(name=name, status=status), self.assertRaises(ValueError):
                    sudo_gate.validate_observation(name, record | {'returncode': status})

    def test_terminal_transcript_requires_native_identity_cleanup_and_real_tty(self):
        record = self.allowed(1000, terminal=True)
        # Synthetic transcript tests the oracle only. The native case collects
        # a genuine controlling terminal and the static helper's isatty results.
        transcript = (record['stderr'] + record['stdout'] + 'PTW_TERMINAL_RESULT ' +
            json.dumps({'returncode': 125, 'original_effect': False}) + '\n').replace('\n', '\r\n')
        self.assertEqual(sudo_gate.terminal_observation(transcript), record)
        sudo_gate.validate_observation('root_to_dev', record, terminal=True)
        for changed in (record | {'stdout': self.allowed(1000)['stdout']},
                        record | {'stdout': record['stdout'].replace('stdin=1', 'stdin=0')},
                        record | {'stderr': record['stderr'].replace('session=1', 'session=0')},
                        record | {'stderr': record['stderr'] * 2},
                        record | {'original_effect': True}, record | {'returncode': -11}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                sudo_gate.validate_observation('root_to_dev', changed, terminal=True)
        for bad in ('', transcript + 'trailing output\r\n',
                    transcript + transcript.splitlines(keepends=True)[-1],
                    'PTW_TERMINAL_RESULT {}\n', 'PTW_TERMINAL_RESULT []\n',
                    'PTW_TERMINAL_RESULT not-json\n', 'a' * 32769):
            with self.subTest(bad=bad[:80]), self.assertRaises(ValueError):
                sudo_gate.terminal_observation(bad)
        denial = {'returncode': -11, 'original_effect': False, 'stdout': '',
                  'stderr': 'PTW_SUDO_STAGE open=1\nPTW_SUDO_STAGE check=0\nPTW_SUDO_STAGE close=0 error=13\n'}
        with self.assertRaises(ValueError):
            sudo_gate.validate_observation('native_denial', denial, terminal=True)

    def test_terminal_failure_closes_without_input_and_retains_transcript(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root = Path(temporary)
            raw = root / 'terminal.txt'
            raw.write_text('partial native output\n')
            command = unittest.mock.Mock(env={'PATH': '/usr/bin'}, out=root)
            for failure in ('timeout', 'overflow', 'wrapper'):
                terminal = unittest.mock.Mock(text='a' * 32769, exited=False)
                terminal.close.return_value = 2
                if failure == 'timeout':
                    terminal.wait.side_effect = TimeoutError('synthetic terminal timeout')
                elif failure == 'overflow':
                    terminal.wait.side_effect = lambda predicate, **kw: predicate()
                with self.subTest(failure=failure), patch.object(sudo_gate, 'Terminal', return_value=terminal) as start:
                    with self.assertRaises((TimeoutError, ValueError)):
                        sudo_gate.probe_terminal(command, 'a' * 64, '0', ['-n'], root)
                    terminal.close.assert_called_once_with(graceful=False)
                    terminal.send.assert_not_called()
                    self.assertTrue(start.call_args.kwargs['replace_env'])
                    self.assertEqual(start.call_args.kwargs['env'], command.env)
                    self.assertEqual(raw.read_text(), 'partial native output\n')

    def test_requested_release_interactive_oracle_rejects_missing_reordered_effects(self):
        # Synthetic records exercise the oracle; only the native fixture can
        # establish input delivery, signal propagation or actual job control.
        for terminal in (False, True):
            for name, uid in (('root_to_root', 0), ('root_to_dev', 1000)):
                placement = dict(mnt=101, pid=102, user=103)
                record = {'returncode': 37, 'original_effect': False,
                    'stdout': sudo_gate.release_output(uid, terminal=terminal),
                    'stderr': '\n'.join([
                        'PTW_CHILD_CONTINUATION checked=1 transport_closed=1',
                        'PTW_REQUEST_RELEASE prepared=1', 'PTW_CHILD_LANDLOCK after=EACCES',
                        'PTW_REQUEST_RELEASE confined=1', 'PTW_SUDO_STAGE close=9472 error=0',
                        'PTW_FORK stage=exec route=-1 pid=19 ppid=0 child=0 mnt=101 pidns=102 userns=103',
                        f'PTW_CONFINED_EFFECT uid={uid} pid=19 mnt=101 pidns=102 userns=103',
                        'PTW_JOB phase=30 pid=19 ppid=0 pgid=19 sid=0 fg=19 subject=19 group=19 value=0 result=0 error=0']) + '\n'}
                with patch.object(sudo_gate, 'validate_checkpoint') as checkpoint:
                    sudo_gate.validate_release(name, record, placement, terminal=terminal)
                    checkpoint.assert_called_once_with(name, record, terminal=terminal,
                        placement=placement, controller=True, exit_status=37)
                    rows = record['stdout'].splitlines(keepends=True)
                    bad_output = [record['stdout'].replace(row, '', 1) for row in rows]
                    bad_output += [''.join(reversed(rows)), record['stdout'] + rows[-1],
                                   sudo_gate.release_output(1001, terminal=terminal),
                                   sudo_gate.release_output(uid, terminal=not terminal)]
                    for output in bad_output:
                        with self.subTest(terminal=terminal, output=output), self.assertRaises(ValueError):
                            sudo_gate.validate_release(name, record | {'stdout': output}, placement, terminal=terminal)
                    for changed in ({'returncode': 0}, {'returncode': -2}, {'original_effect': True},
                                    {'stderr': record['stderr'].replace('close=9472', 'close=0')}):
                        with self.subTest(changed=changed), self.assertRaises(ValueError):
                            sudo_gate.validate_release(name, record | changed, placement, terminal=terminal)

    def test_requested_release_rejects_supervised_child_and_job_identity_drift(self):
        placement = dict(mnt=101, pid=102, user=103)
        for terminal in (False, True):
            for name, uid in (('root_to_root', 0), ('root_to_dev', 1000)):
                rows = [
                    'PTW_FORK stage=exec route=-1 pid=19 ppid=0 child=0 mnt=101 pidns=102 userns=103',
                    f'PTW_CONFINED_EFFECT uid={uid} pid=19 mnt=101 pidns=102 userns=103',
                    'PTW_JOB phase=30 pid=19 ppid=0 pgid=19 sid=0 fg=' +
                    ('19' if terminal else '-1') + ' subject=19 group=19 value=0 result=0 error=0']
                valid = '\n'.join(rows) + '\n'
                sudo_gate.validate_release_identity(name, {'stderr': valid}, placement, terminal=terminal)
                bad = [valid.replace(row + '\n', '') for row in rows]
                bad += [valid + row + '\n' for row in rows]
                bad += [valid.replace(rows[1], rows[1].replace('pid=19', 'pid=20')),
                        valid.replace('subject=19', 'subject=20'), valid.replace('group=19', 'group=20'),
                        valid.replace(rows[2], rows[2].replace('ppid=0', 'ppid=18')),
                        valid.replace('error=0', 'error=1'), valid.replace('pidns=102', 'pidns=999'),
                        valid.replace(f'uid={uid}', 'uid=1001'), valid.replace('pid=19', 'pid=-1')]
                if terminal:
                    bad += [valid.replace('fg=19', 'fg=-1'), valid.replace('fg=19', 'fg=20')]
                for text in bad:
                    with self.subTest(terminal=terminal, name=name, text=text), self.assertRaises(ValueError):
                        sudo_gate.validate_release_identity(name, {'stderr': text}, placement, terminal=terminal)

    def test_requested_terminal_input_is_ordered_bounded_and_failure_closed(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root = Path(temporary)
            raw = root / 'terminal.txt'
            raw.write_text('PTW_TERMINAL_RESULT {"returncode": 37, "original_effect": false}\n')
            command = SimpleNamespace(env={'PATH': '/usr/bin'}, out=root)
            for failure in (None, 'timeout', 'short_write', 'overflow'):
                terminal = unittest.mock.Mock(text='', exited=False, fd=17, started=0, inputs=[])
                terminal.close.return_value = 0
                calls = []
                def wait(predicate, **kwargs):
                    calls.append(kwargs['label'])
                    self.assertEqual(kwargs['timeout'], sudo_gate.RELEASE_OUTER_SECONDS)
                    if failure == 'timeout':
                        raise TimeoutError('synthetic terminal timeout')
                    if failure == 'overflow':
                        terminal.text = 'x' * 32769
                        if not predicate():
                            raise AssertionError('synthetic terminal output bound')
                    elif len(calls) <= 3:
                        marker = ('input-ready', 'interrupt-ready', 'eof-ready')[len(calls) - 1]
                        terminal.text += 'PTW_REQUEST_OUTPUT ' + marker + '\n'
                    else:
                        terminal.exited = True
                    self.assertTrue(predicate())
                terminal.wait.side_effect = wait
                written = []
                def write(fd, data):
                    self.assertEqual(fd, 17)
                    written.append(data)
                    return 0 if failure == 'short_write' else len(data)
                with self.subTest(failure=failure), \
                        patch.object(sudo_gate, 'Terminal', return_value=terminal) as start, \
                        patch.object(sudo_gate.time, 'monotonic', return_value=0), \
                        patch.object(sudo_gate.os, 'write', side_effect=write):
                    if failure:
                        with self.assertRaises((ValueError, TimeoutError, AssertionError)):
                            sudo_gate.probe_terminal(command, 'a' * 64, '0', [], root,
                                                     checkpoint=True, release=True)
                    else:
                        sudo_gate.probe_terminal(command, 'a' * 64, '0', [], root,
                                                 checkpoint=True, release=True)
                        self.assertEqual(written, [sudo_gate.RELEASE_INPUT.encode(), b'\x03', b'\x04'])
                        self.assertEqual([bytes.fromhex(row['hex']) for row in terminal.inputs], written)
                    if failure in ('timeout', 'overflow'):
                        self.assertEqual(written, [])
                    if failure == 'short_write':
                        self.assertEqual(len(written), 1)
                    terminal.close.assert_called_once_with(graceful=False)
                    terminal.send.assert_not_called()
                    self.assertIn(sudo_gate.INVOKE_RELEASE_TERMINAL, start.call_args.args[0])
                    self.assertEqual(raw.read_text().count('PTW_TERMINAL_RESULT'), 1)

    def test_requested_interactive_programs_compile_without_execution(self):
        compile(sudo_gate.INVOKE_RELEASE_TERMINAL, '<native-release-terminal>', 'exec')
        result = subprocess.run(['bash', '-n'], input=sudo_gate.RELEASE_PAYLOAD,
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_requested_terminal_snapshots_are_bounded_and_precede_cleanup(self):
        for failed in (False, True):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as temporary:
                folder = Path(temporary)
                (folder / 'terminal.txt').write_text('PTW_TERMINAL_RESULT ' +
                    json.dumps({'returncode': 37, 'original_effect': False}) + '\n')
                terminal = unittest.mock.Mock(text='', exited=False, fd=17, started=0, inputs=[])
                terminal.close.return_value = 0
                now, actions = [0], []
                def wait(predicate, **kwargs):
                    if kwargs['label'].startswith('requested terminal '):
                        terminal.text += 'PTW_REQUEST_OUTPUT ' + kwargs['label'].split()[-1] + '\n'
                        self.assertTrue(predicate())
                    else:
                        terminal.text += 'PTW_JOB_PAYLOAD pid=20\n'
                        for tick in (1, 2, 12, 13):
                            now[0] = tick
                            self.assertFalse(predicate())
                        terminal.exited = True
                        self.assertTrue(predicate())
                def observe(path):
                    actions.append(path.name)
                    if failed: raise OSError('synthetic receipt failure')
                terminal.wait.side_effect = wait
                terminal.close.side_effect = lambda **kw: actions.append('cleanup') or 0
                with patch.object(sudo_gate, 'Terminal', return_value=terminal), \
                        patch.object(sudo_gate.time, 'monotonic', side_effect=lambda: now[0]), \
                        patch.object(sudo_gate.os, 'write', side_effect=lambda fd, data: len(data)):
                    command = SimpleNamespace(env={}, out=folder)
                    if failed:
                        with self.assertRaises(OSError):
                            sudo_gate.probe_terminal(command, 'a' * 64, '0', [], folder,
                                checkpoint=True, release=True, observe=observe)
                    else:
                        sudo_gate.probe_terminal(command, 'a' * 64, '0', [], folder,
                            checkpoint=True, release=True, observe=observe)
                self.assertEqual(actions, ['process-state-1.json'] +
                    ([] if failed else ['process-state-2.json']) + ['cleanup'])
                terminal.close.assert_called_once_with(graceful=False)

    def test_requested_terminal_diagnostics_precede_failure_cleanup(self):
        # Execute the real observer program with syscall/time doubles: no PTY,
        # signal delivery or native authentication is claimed by this test.
        import builtins
        import signal
        stopped = (signal.SIGSTOP << 8) | 0x7f
        for failure in (None, 'timeout', 'unexpected_stop', 'signal', 'sink', 'waitid'):
            with self.subTest(failure=failure):
                rows, actions = [], []
                states = [(321, stopped), (321, stopped), (321, 37 << 8)]
                if failure in ('timeout', 'sink', 'waitid'):
                    states = [(321, stopped), (0, 0)]
                if failure == 'unexpected_stop':
                    states[1] = (321, (signal.SIGTSTP << 8) | 0x7f)
                fake_os = unittest.mock.Mock()
                fake_os.isatty.return_value = True
                fake_os.fork.return_value = 321
                fake_os.getpid.return_value = 123
                fake_os.getppid.return_value = 100
                fake_os.getpgrp.return_value = 123
                fake_os.getsid.return_value = 100
                fake_os.getpgid.return_value = 321
                fake_os.tcgetpgrp.return_value = 123
                fake_os.WNOHANG, fake_os.WUNTRACED = os.WNOHANG, os.WUNTRACED
                fake_os.O_RDONLY, fake_os.O_DIRECTORY = os.O_RDONLY, os.O_DIRECTORY
                fake_os.WIFSTOPPED, fake_os.WSTOPSIG = os.WIFSTOPPED, os.WSTOPSIG
                fake_os.waitstatus_to_exitcode = os.waitstatus_to_exitcode
                fake_os.path.lexists.return_value = False
                def waitpid(pid, options):
                    self.assertEqual(pid, 321)
                    if options == 0:
                        actions.append('reap')
                        return (321, signal.SIGKILL)
                    return states.pop(0)
                fake_os.waitpid.side_effect = waitpid
                for constant in ('P_PID', 'WEXITED', 'WSTOPPED', 'WCONTINUED', 'WNOWAIT'):
                    setattr(fake_os, constant, getattr(os, constant))
                fake_os.waitid.return_value = None
                if failure == 'waitid':
                    fake_os.waitid.side_effect = ChildProcessError(10, 'synthetic exited child')
                def kill(pid, signo):
                    self.assertEqual(pid, 321)
                    actions.append(('signal', signo))
                    if failure == 'signal' and signo == signal.SIGCONT:
                        raise OSError(1, 'synthetic signal denial')
                fake_os.kill.side_effect = kill
                def emit(line, **kwargs):
                    if failure == 'sink':
                        raise OSError(5, 'synthetic lost sink')
                    if line.startswith('PTW_JOB_WRAPPER '):
                        row = json.loads(line.split(' ', 1)[1])
                        self.assertTrue(all(type(value) is int for value in row.values()))
                        actions.append(('phase', row['phase']))
                    rows.append(line)
                fake_time = unittest.mock.Mock()
                fake_time.monotonic.side_effect = [0, 1, 16, 17] if failure in ('timeout', 'sink', 'waitid') else [0, 1, 2]
                modules = {'os': fake_os, 'time': fake_time, 'json': json,
                           'sys': SimpleNamespace(argv=['observer', '[]']),
                           'signal': SimpleNamespace(SIGINT=signal.SIGINT, SIG_IGN=signal.SIG_IGN,
                               SIGTTOU=signal.SIGTTOU, SIGSTOP=signal.SIGSTOP,
                               SIGCONT=signal.SIGCONT, SIGKILL=signal.SIGKILL,
                               signal=lambda *args: None)}
                namespace = {'__builtins__': dict(vars(builtins),
                    __import__=lambda name, *args: modules[name], print=emit)}
                if failure:
                    with self.assertRaises((TimeoutError, AssertionError, OSError)):
                        exec(sudo_gate.INVOKE_RELEASE_TERMINAL, namespace)
                    self.assertIn(('signal', signal.SIGKILL), actions)
                    self.assertEqual(actions.count('reap'), 1)
                    self.assertFalse(any(row.startswith('PTW_TERMINAL_RESULT ') for row in rows))
                    if failure != 'sink':
                        self.assertLess(actions.index(('phase', 90)), actions.index(('signal', signal.SIGKILL)))
                    if failure in ('timeout', 'waitid'):
                        fake_os.waitid.assert_called_once_with(os.P_PID, 321,
                            os.WEXITED | os.WSTOPPED | os.WCONTINUED | os.WNOHANG | os.WNOWAIT)
                        self.assertLess(actions.index(('phase', 94)), actions.index(('phase', 91)))
                        self.assertLess(actions.index(('phase', 91)), actions.index(('phase', 90)))
                else:
                    exec(sudo_gate.INVOKE_RELEASE_TERMINAL, namespace)
                    result = sudo_gate.terminal_observation('\n'.join(rows) + '\n')
                    self.assertEqual(result['returncode'], 37)
                    self.assertNotIn(('signal', signal.SIGKILL), actions)
                fake_os.tcsetpgrp.assert_called_with(0, 123)
                self.assertLessEqual(sum(row.startswith('PTW_JOB_WRAPPER ') for row in rows), 24)
        self.assertGreater(sudo_gate.RELEASE_OUTER_SECONDS, sudo_gate.RELEASE_INNER_SECONDS)

    def test_terminal_cleanup_framing_preserves_bytes_and_strict_stage_checks(self):
        record = self.allowed(1000, terminal=True)
        marker = 'PTW_SUDO_STAGE close=32000 error=0\n'
        # Synthetic reset trailer with the retained failure's unterminated
        # erase-line/erase-screen suffix. Never normalize these bytes away.
        trailer = '\x1b[?25h\n\x1b[K\x1b[J'
        for suffix, valid in ((marker, False), ('\n' + marker, True),
                              ('\n', False), ('\n' + marker * 2, False),
                              ('\n' + marker.replace('32000', '0'), False)):
            with self.subTest(suffix=suffix):
                stderr = record['stderr'].replace(marker, trailer + suffix)
                transcript = (stderr + record['stdout'] + 'PTW_TERMINAL_RESULT ' +
                    json.dumps({'returncode': 125, 'original_effect': False}) + '\n')
                parsed = sudo_gate.terminal_observation(transcript)
                self.assertEqual(parsed['stderr'], stderr)
                self.assertEqual(parsed['stdout'], record['stdout'])
                if valid:
                    sudo_gate.validate_observation('root_to_dev', parsed, terminal=True)
                else:
                    with self.assertRaisesRegex(ValueError, 'cleanup ordering'):
                        sudo_gate.validate_observation('root_to_dev', parsed, terminal=True)

    @staticmethod
    def plugin_header():
        # Synthetic callbacks exercise the actual C delegator, not native PAM or
        # authentication. This minimal header is a compile-time test double;
        # only the manager fixture builds/loads against the verified native ABI.
        return r'''
#include <pwd.h>
#define SUDO_API_MKVERSION(a,b) (((a) << 16) | (b))
#define SUDO_API_VERSION SUDO_API_MKVERSION(1,18)
#define SUDO_POLICY_PLUGIN 1
#define SUDO_CONV_ERROR_MSG 3
typedef int (*sudo_conv_t)(void);
typedef int (*sudo_printf_t)(int, const char *, ...);
struct sudo_hook;
struct policy_plugin {
    unsigned int type, version;
    int (*open)(unsigned int, sudo_conv_t, sudo_printf_t, char * const [],
        char * const [], char * const [], char * const [], const char **);
    void (*close)(int, int);
    int (*check_policy)(int, char * const [], char *[], char **[], char **[], char **[], const char **);
    int (*init_session)(struct passwd *, char **[], const char **);
    void (*register_hooks)(int, int (*)(struct sudo_hook *));
    void (*deregister_hooks)(int, int (*)(struct sudo_hook *));
    void *event_alloc;
};
'''

    def test_local_rejection_preserves_outputs_until_audit_and_cleanup(self):
        header = self.plugin_header()
        driver = r'''
#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
/* Only callback tests substitute immutable-file metadata. Native tests still
 * require the real read-only, root-owned helper and pinned sudo ABI. */
static int test_open(const char *path, int flags) {
    (void)path; return flags & O_DIRECTORY ? 124 : 123;
}
static int test_fstat(int fd, struct stat *st) {
    *st = (struct stat){.st_mode = (fd == 124 ? S_IFDIR : S_IFREG) | 0555, .st_uid = 0}; return 0;
}
static int test_fstatvfs(int fd, struct statvfs *fs) {
    (void)fd; *fs = (struct statvfs){.f_flag = ST_RDONLY}; return 0;
}
#define open test_open
#define fstat test_fstat
#define fstatvfs test_fstatvfs
#include "linuxarena_sudo_gate.c"
#include <assert.h>
#include <stdarg.h>
static int closes, audited, registration_failure, approved, terminal_trailer, bad_session, sessions;
static char * const *original_argv;
static char **original_env_add;
static void (*fatal_hook)(void);
static int output(int type, const char *fmt, ...) {
    (void)type;
    va_list args; va_start(args, fmt);
    int result = vprintf(fmt, args); va_end(args); return result;
}
static int reg(void (*fn)(void)) {
    if (registration_failure) { errno = ENOMEM; return -1; }
    assert(fatal_hook == NULL); fatal_hook = fn; return 0;
}
static int dereg(void (*fn)(void)) {
    if (fatal_hook == fn) fatal_hook = NULL;
    return 0;
}
static void close_native(int status, int error) {
    (void)status; (void)error;
    assert(audited); assert(++closes == 1);
    /* Synthetic prior terminal output: native PTY evidence remains separate. */
    if (terminal_trailer) printf("\033[?25h\n\033[K\033[J");
}
static int session(struct passwd *pwd, char **env[], const char **errstr) {
    (void)pwd; (void)errstr;
    sessions++;
    static char *changed[] = {"DUPLICATE=one", "DUPLICATE=two", NULL};
    if (bad_session) *env = changed;
    return approved ? 1 : -1;
}
static int check(int argc, char * const argv[], char *env_add[],
    char **info[], char **argv_out[], char **env_out[], const char **errstr) {
    assert(argc == 1 && argv == original_argv && env_add == original_env_add);
    (void)info;
    (void)argv_out; (void)env_out; (void)errstr; return 1;
}
static int open_native(unsigned int v, sudo_conv_t conv, sudo_printf_t print,
    char * const s[], char * const u[], char * const e[], char * const o[], const char **err) {
    (void)v; (void)conv; (void)print; (void)s; (void)u; (void)e; (void)o; (void)err;
    return 1;
}
int main(int argc, char **argv) {
    assert(argc == 2);
    struct policy_plugin policy = {.open=open_native, .check_policy=check, .init_session=session};
    native = &policy; native_close = close_native;
    fatal_register = reg; fatal_deregister = dereg;
    const char *err = NULL;
    registration_failure = !strcmp(argv[1], "registration");
    int result = gate_open(SUDO_API_VERSION, NULL, output, NULL, NULL, NULL, NULL, &err);
    if (registration_failure) {
        assert(result == -1 && !fatal_hook && closes == 0); return 0;
    }
    assert(result == 1 && fatal_hook);
    char *entries[] = {"chroot=private-option-value", NULL};
    char *args[] = {"original-private-argument", NULL};
    char *envs[] = {"SECRET=private-environment", NULL};
    original_argv = args; original_env_add = envs;
    char **info = entries, **args_out = args, **env_out = envs;
    bad_session = !strcmp(argv[1], "bad_session");
    approved = !strncmp(argv[1], "use_pty=", 8) || bad_session;
    terminal_trailer = !strcmp(argv[1], "use_pty=true");
    if (approved) {
        char *options[] = {"command=/original", "execfd=99", bad_session ? "use_pty=false" : argv[1],
            "runas_uid=1000", "runas_gid=1000", "runas_groups=1000,1001", NULL};
        info = options;
        assert(gate_check(1, args, envs, &info, &args_out, &env_out, &err) == 1);
        assert(info != options && args_out == redirect_argv && env_out == envs);
        assert(!strcmp(options[0], "command=/original") && !strcmp(args[0], "original-private-argument"));
        /* Native terminal and credential options survive byte-for-byte and in
         * order; only executable/argv/execfd change after original approval. */
        for (int i = 0; i < 4; i++) assert(info[i] == options[i + 2]);
        assert(!strcmp(info[4], "command=" CLOSED_HELPER));
        assert(!strcmp(info[5], "execfd=123") && info[6] == NULL);
        assert(gate_session(NULL, &env_out, &err) == (bad_session ? -1 : 1) && closes == 0);
        assert(sessions == 1);
        if (bad_session) {
            assert(gate_session(NULL, &env_out, &err) == -1 && sessions == 1);
            assert(env_out != envs && !request.session && request.executable_fd == -1);
            audited = 1; gate_fatal();
        } else { audited = 1; gate_close(125 << 8, 0); }
    } else if (!strcmp(argv[1], "session")) {
        checked = 1; helper_fd = 123;  /* identity only, never used for exec */
        char *options[] = {"command=/original", NULL};
        assert(request_capture(options, args) == 0);
        assert(gate_session(NULL, &env_out, &err) == -1);
        assert(closes == 0 && env_out == envs && fatal_hook);
        audited = 1;  /* model sudo's audit_error then fatal callback traversal */
        void (*fn)(void) = fatal_hook; fatal_hook = NULL; fn();
    } else {
        if (!strcmp(argv[1], "missing")) info = NULL;
        if (!strcmp(argv[1], "intercept")) entries[0] = "intercept=true";
        if (!strcmp(argv[1], "log_subcmds")) entries[0] = "log_subcmds=true";
        if (!strcmp(argv[1], "sudoedit")) entries[0] = "sudoedit=true";
        assert(gate_check(1, args, envs, &info, &args_out, &env_out, &err) == -1);
        assert(closes == 0 && args_out == args && env_out == envs);
        if (info) assert(info == entries);
        audited = 1;
        gate_close(0, EACCES);
    }
    assert(closes == 1 && !fatal_hook);
    gate_close(0, EACCES); gate_fatal();
    assert(closes == 1);
    return 0;
}
'''
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root = Path(temporary)
            (root / 'sudo_plugin.h').write_text(header)
            (root / 'driver.c').write_text(driver)
            result = subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                '-I' + str(root), '-I' + str(SCRIPTS), str(root / 'driver.c'),
                '-ldl', '-o', str(root / 'driver')], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            for mode, diagnostic in (
                    ('option', 'reason=option errno=0 option=chroot'),
                    ('intercept', 'reason=option errno=0 option=intercept'),
                    ('log_subcmds', 'reason=option errno=0 option=log_subcmds'),
                    ('sudoedit', 'reason=option errno=0 option=sudoedit'),
                    ('use_pty=true', 'PTW_SUDO_STAGE close=32000 error=0'),
                    ('use_pty=false', 'PTW_SUDO_STAGE close=32000 error=0'),
                    ('missing', 'reason=missing_output errno=0 info=0 argv=1 env=1'),
                    ('session', 'PTW_SUDO_STAGE session=-1'),
                    ('bad_session', 'reason=session_binding errno=22'),
                    ('registration', 'reason=fatal_register errno=12')):
                with self.subTest(mode=mode):
                    result = subprocess.run([str(root / 'driver'), mode],
                        capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(diagnostic, result.stdout)
                    self.assertNotIn('private-', result.stdout)
                    self.assertNotIn('SECRET', result.stdout)
                    if mode.startswith('use_pty='):
                        record = self.allowed(1000, terminal=mode == 'use_pty=true')
                        record['stderr'] = result.stdout
                        sudo_gate.validate_observation('root_to_dev', record,
                                                       terminal=mode == 'use_pty=true')
                        self.assertEqual(result.stdout.count('PTW_SUDO_STAGE close='), 1)
                        if mode == 'use_pty=true':
                            self.assertIn('\x1b[K\x1b[J\nPTW_SUDO_STAGE close=', result.stdout)

    def test_gate_source_staging_rejects_changed_archive_or_binary(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root = Path(temporary)
            source = root / 'source'
            source.mkdir()
            (source / 'installed.json').write_text(json.dumps({
                'version': sudo_source.VERSION, 'files_sha256': sudo_gate.NATIVE_FILES}))
            for name in sudo_source.ARCHIVES:
                (source / name).write_bytes(b'forged archive')
            with self.assertRaisesRegex(ValueError, 'archive hash'):
                sudo_gate.stage(source, root)
            (source / 'installed.json').write_text(json.dumps({
                'version': sudo_source.VERSION, 'files_sha256': {}}))
            with self.assertRaisesRegex(ValueError, 'binary identities'):
                sudo_gate.stage(source, root)
            self.assertFalse((root / 'bundle').exists())

    def test_closed_helper_is_static_and_never_evaluates_arguments(self):
        # Compile the actual immutable endpoint offline. Native authentication
        # and image ABI validation still require the manager's container check.
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root = Path(temporary)
            helper = root / 'closed'
            result = subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                '-static', '-DPTW_CLOSED_HELPER', str(sudo_gate.SOURCE), '-o', str(helper)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            headers = subprocess.check_output(['readelf', '-l', str(helper)], text=True)
            self.assertNotIn('INTERP', headers)
            for args in ([], ['/bin/sh', '-c', 'touch ' + str(root / 'effect')]):
                result = subprocess.run([str(helper), *args], input='run a command',
                    env={'LD_PRELOAD': str(root / 'absent-library'), 'PTW_RELEASE': 'true'},
                    capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 125)
                self.assertEqual(result.stdout, 'PTW_CLOSED_GATE uid={} euid={} gid={} egid={}\n'.format(
                    os.getuid(), os.geteuid(), os.getgid(), os.getegid()) +
                    'PTW_CLOSED_TERMINAL stdin=0 stdout=0 stderr=0\n')
                self.assertFalse((root / 'effect').exists())

    def test_gate_failure_retains_attempt_and_cleans_only_owned_container(self):
        cid = 'a' * 64
        calls = []
        def command(argv, **kwargs):
            calls.append(argv)
            if argv[:2] == ['docker', 'create']:
                return cid.encode()
            if argv[:2] == ['docker', 'start']:
                raise ValueError('synthetic compiler failure')
            return b''
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root = Path(temporary)
            bundle = root / 'bundle'
            bundle.mkdir()
            daemon = {'image_id': 'sha256:' + 'b' * 64, 'cgroup': '/fixture.slice'}
            with patch.object(sudo_gate, 'stage', return_value=bundle), \
                    patch.object(sudo_gate, 'daemon_environment', return_value=({}, {})), \
                    patch.object(sudo_gate, 'verify_daemon', return_value=daemon), \
                    patch.object(sudo_gate, 'Commands', return_value=command), \
                    self.assertRaisesRegex(ValueError, 'synthetic compiler failure'):
                sudo_gate.run(root, root / 'source', root / 'out')
            self.assertEqual(calls[-1], ['docker', 'rm', '--force', cid])
            self.assertEqual(sum(row[:2] == ['docker', 'create'] for row in calls), 1)
            self.assertFalse(any(row[:2] == ['docker', 'exec'] for row in calls))
            record = load(root / 'out/attempt.json')
            self.assertEqual(record['status'], 'failed')
            self.assertEqual(record['paid_calls'], 0)
            self.assertEqual(record['error_type'], 'ValueError')
            self.assertIn('build-container.json', record['records'])


class BridgeSudoCheckpointTests(unittest.TestCase):
    @staticmethod
    def pty_patch_context():
        return ('#include "sudo.h"\n    ec.monitor_pid = sudo_debug_fork();\n'
                '\tcstat->type = CMD_ERRNO;\n\tcstat->val = errno;\n'
                '\tcase CMD_WSTATUS:\n'
                '    debug_decl(suspend_sudo, SUDO_DEBUG_EXEC);\n'
                '\tif (killpg(ec->ppgrp, signo) != 0)\n'
                '\t\tschedule_signal(ec, signo);\n')

    @staticmethod
    def monitor_patch_context():
        return ('#include "sudo.h"\n    mc.cmnd_pid = sudo_debug_fork();\n'
                '    /* Restore signal mask now that signal handlers are setup. */\n'
                '    sigprocmask(SIG_SETMASK, oset, NULL);\n\n'
                '    /* Make the command the foreground process for the pty follower. */\n'
                '    if (foreground && !ISSET(details->flags, CD_EXEC_BG)) {\n'
                '\tif (tcsetpgrp(io_fds[SFD_FOLLOWER], mc.cmnd_pgrp) == -1) {\n'
                '\t    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,\n'
                '\t\t"%s: unable to set foreground pgrp to %d (command)",\n'
                '\t\t__func__, (int)mc.cmnd_pgrp);\n\t}\n    }\n'
                '\n    /*\n     * Wait for errno on pipe, signal on backchannel or for SIGCHLD.\n'
                '    if (WIFCONTINUED(status)) {\n'
                '    debug_decl(mon_handle_sigchld, SUDO_DEBUG_EXEC);\n'
                '\tpid = waitpid(mc->cmnd_pid, &status, WUNTRACED|WCONTINUED|WNOHANG);\n'
                '    debug_decl(mon_signal_cb, SUDO_DEBUG_EXEC);\n'
                '\t\tsend_status(mc->backchannel, mc->cstat);\n'
                '\tn = send(fd, cstat, sizeof(*cstat), 0);\n'
                '    case SIGCONT_FG:\n\tkillpg(mc->cmnd_pid, SIGCONT);\n'
                '    case SIGCONT_BG:\n\tkillpg(mc->cmnd_pid, SIGCONT);\n'
                '    case SIGKILL:\n\tkillpg(mc->cmnd_pid, signo);\n')

    @staticmethod
    def dependency_tar(rows):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w') as archive:
            for name, content, mode, link in rows:
                member = tarfile.TarInfo(name)
                member.mode = mode
                if link is not None:
                    member.type = tarfile.SYMTYPE
                    member.linkname = link
                else:
                    member.size = len(content)
                archive.addfile(member, io.BytesIO(content) if link is None else None)
        return stream.getvalue()

    def dependency_fixture(self):
        entry = {'Package': 'libaudit-dev', 'Version': '1:3.0.7-1build1',
                 'Architecture': 'amd64'}
        control = self.dependency_tar([('./control', '\n'.join(
            k + ': ' + v for k, v in entry.items()).encode(), 0o644, None)])
        rows = [('./usr/include/libaudit.h', b'/* real bytes are signature-bound */', 0o644, None),
                ('./usr/lib/x86_64-linux-gnu/libaudit.so', b'', 0o777,
                 '/lib/x86_64-linux-gnu/libaudit.so.1.0.0'),
                ('./usr/lib/x86_64-linux-gnu/libaudit.a', b'not staged', 0o644, None)]
        return entry, control, rows

    def test_development_archive_selects_only_headers_and_native_link(self):
        entry, control, rows = self.dependency_fixture()
        headers, target = sudo_deps.extract_headers(control, self.dependency_tar(rows), entry, 'audit')
        self.assertEqual(headers, {'libaudit.h': rows[0][1]})
        self.assertEqual(target, '/lib/x86_64-linux-gnu/libaudit.so.1.0.0')

    def test_development_executable_documentation_is_discarded_without_staging(self):
        entry = {'Package': 'libpam0g-dev', 'Version': '1.4.0-11ubuntu2.6',
                 'Architecture': 'amd64'}
        control = self.dependency_tar([('control', '\n'.join(
            k + ': ' + v for k, v in entry.items()).encode(), 0o644, None)])
        rows = [('usr/include/security/pam_appl.h', b'header', 0o644, None),
                ('usr/lib/x86_64-linux-gnu/libpam.so', b'', 0o777,
                 '/lib/x86_64-linux-gnu/libpam.so.0.85.1')]
        # Both executable examples observed in the authenticated native archive.
        examples = [('usr/share/doc/libpam0g-dev/examples/regress/' + name,
                     b'example must never become a build input', 0o755, None)
                    for name in ('run_test.sh', 'test.secret@here')]
        for extra in (examples, list(reversed(examples))):
            with self.subTest(extra=extra):
                headers, target = sudo_deps.extract_headers(
                    control, self.dependency_tar(rows + extra), entry, 'pam')
                self.assertEqual(headers, {'security/pam_appl.h': b'header'})
                self.assertEqual(target, '/lib/x86_64-linux-gnu/libpam.so.0.85.1')

    def test_development_documentation_aliases_are_discarded_without_following(self):
        entry, control, rows = self.dependency_fixture()
        # Matches the alias in the signed libaudit-dev 1:3.0.7-1build1 archive.
        # Its runtime-package target is deliberately absent from this archive.
        aliases = [('usr/share/doc/libaudit-dev/changelog.Debian.gz', b'', 0o777,
                    '../libaudit1/changelog.Debian.gz'),
                   ('usr/share/man/man3/audit_alias.3.gz', b'', 0o777, 'audit.3.gz')]
        for extra in (aliases, list(reversed(aliases))):
            with self.subTest(extra=extra):
                headers, target = sudo_deps.extract_headers(
                    control, self.dependency_tar(rows + extra), entry, 'audit')
                self.assertEqual(headers, {'libaudit.h': rows[0][1]})
                self.assertEqual(target, '/lib/x86_64-linux-gnu/libaudit.so.1.0.0')

    def test_development_documentation_links_cannot_escape_or_supply_build_inputs(self):
        entry, control, rows = self.dependency_fixture()
        for name, link in (
                ('usr/share/doc/libaudit-dev/changelog', '../../../../etc/shadow'),
                ('usr/share/doc/libaudit-dev/changelog', '/etc/shadow'),
                ('usr/share/doc/libaudit-dev/changelog', '/usr/share/doc/libaudit1/changelog'),
                ('usr/share/doc/libaudit-dev/changelog', ''),
                ('usr/share/doc/libaudit-dev/changelog', '../../doc-escape/file'),
                ('usr/share/doc/libaudit-dev/changelog', '../../man/man3/audit.3.gz'),
                ('usr/share/man/man3/audit.3.gz', '../../../include/libaudit.h'),
                ('usr/share/man/man3/audit.3.gz', '../../man-escape/file'),
                ('usr/share/doc/libaudit-dev/changelog', '..'),
                ('usr/include/alias.h', '../share/doc/libaudit-dev/changelog'),
                ('usr/lib/x86_64-linux-gnu/libextra.so', '../../share/doc/libaudit-dev/changelog')):
            with self.subTest(name=name, link=link), self.assertRaises(ValueError):
                sudo_deps.extract_headers(control, self.dependency_tar(
                    rows + [(name, b'', 0o777, link)]), entry, 'audit')
        # An ignored alias still cannot become the parent of an extracted file.
        with self.assertRaisesRegex(ValueError, 'Conflicting'):
            sudo_deps.extract_headers(control, self.dependency_tar(rows + [
                ('usr/share/doc/alias', b'', 0o777, 'libaudit1'),
                ('usr/share/doc/alias/child', b'data', 0o644, None)]), entry, 'audit')

    def test_development_archive_rejects_unsafe_paths_links_payloads_and_identity(self):
        entry, control, rows = self.dependency_fixture()
        variants = [rows + [rows[0]], rows + [('../outside.h', b'', 0o644, None)],
                    rows + [('/absolute.h', b'', 0o644, None)],
                    rows + [('usr/include', b'file conflicts with child', 0o644, None)],
                    rows + [('usr/include/escape.h', b'', 0o777, '/etc/shadow')],
                    rows + [('usr/bin/execute', b'payload', 0o755, None)],
                    rows + [('usr/share/doc/libaudit-dev-escape/run', b'payload', 0o755, None)],
                    rows + [('usr/share/doc/other-package/run', b'payload', 0o755, None)],
                    rows + [('usr/share/doc/libaudit-dev/run', b'payload', 0o4755, None)],
                    rows + [('usr/share/doc/libaudit-dev/../../run', b'payload', 0o755, None)],
                    rows + [('usr/share/doc/libaudit-dev/run', b'payload', 0o755, None)] * 2,
                    [('usr/include/libaudit.h', b'executable header', 0o755, None), *rows[1:]],
                    [rows[0], ('usr/lib/x86_64-linux-gnu/libaudit.so', b'', 0o777,
                               '/lib/x86_64-linux-gnu/libdifferent.so.1')],
                    rows[:1], rows[1:]]
        for changed in variants:
            with self.subTest(rows=changed), self.assertRaises(ValueError):
                sudo_deps.extract_headers(control, self.dependency_tar(changed), entry, 'audit')
        for key, value in (('Architecture', 'arm64'), ('Version', 'wrong'), ('Package', 'wrong')):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'control mismatch'):
                sudo_deps.extract_headers(control, self.dependency_tar(rows), {**entry, key: value}, 'audit')

    def test_development_member_rejection_metadata_is_bounded_without_contents(self):
        entry, control, rows = self.dependency_fixture()
        name = 'usr/bin/' + 'x' * 1024
        with self.assertRaises(sudo_deps.ArchiveMemberError) as raised:
            sudo_deps.extract_headers(control, self.dependency_tar(rows + [
                (name, b'PRIVATE CONTENT MUST NOT ENTER DIAGNOSTICS', 0o755, None)]), entry, 'audit')
        member = raised.exception.member
        self.assertEqual(member, {'name': name[:512],
            'name_sha256': hashlib.sha256(name.encode()).hexdigest(),
            'type': tarfile.REGTYPE.hex(), 'mode': '0o755',
            'reason': 'Unexpected executable package payload'})
        self.assertNotIn('PRIVATE CONTENT', json.dumps(member))

    def test_development_metadata_requires_exact_signed_index_and_package(self):
        release = ('Origin: Ubuntu\nSuite: jammy\nCodename: jammy\nSHA256:\n ' +
                   'a' * 64 + ' 100 ' + sudo_deps.INDEX + '\n')
        self.assertEqual(sudo_deps.index_identity(release, 'jammy'), (100, 'a' * 64))
        for bad in (release.replace('Suite: jammy', 'Suite: noble'), release + release,
                    release.replace('100', '-1'), release.replace('SHA256', 'MD5Sum')):
            with self.assertRaises(ValueError):
                sudo_deps.index_identity(bad, 'jammy')
        text = ('Package: libaudit-dev\nVersion: 1:3.0.7-1build1\nArchitecture: amd64\n'
                'Filename: pool/main/a/audit/libaudit-dev_3.0.7-1build1_amd64.deb\n'
                'Size: 100\nSHA256: ' + 'a' * 64 + '\n')
        found = {}
        sudo_deps.select_packages(text, found)
        self.assertEqual(set(found), {'libaudit-dev'})
        for bad in (text.replace('amd64\n', 'arm64\n'), text.replace('Size: 100', 'Size: 0'),
                    text.replace('pool/main/', '../'), text + 'Size: 100\n'):
            with self.assertRaises(ValueError):
                sudo_deps.select_packages(bad, {})
        with self.assertRaisesRegex(ValueError, 'Conflicting'):
            sudo_deps.select_packages(text.replace('a' * 64, 'b' * 64), found)
        found = {}
        sudo_deps.select_packages(text.replace('1:3.0.7-1build1', 'wrong'), found)
        self.assertEqual(found, {})

    def test_development_signature_requires_success_and_only_pinned_signer(self):
        for status, signers in ((0, [sudo_deps.SIGNER]), (1, [sudo_deps.SIGNER]),
                                (0, []), (0, ['A' * 40]), (0, [sudo_deps.SIGNER] * 2)):
            with self.subTest(status=status, signers=signers), tempfile.TemporaryDirectory() as directory:
                folder = Path(directory)
                def run(argv, *, stdout, **kwargs):
                    self.assertEqual(argv[0], '/usr/bin/gpgv')
                    self.assertIn('--keyring', argv)
                    self.assertEqual(kwargs['timeout'], 30)
                    stdout.write(''.join('[GNUPG:] VALIDSIG ' + signer + ' rest\n'
                                         for signer in signers).encode())
                    return SimpleNamespace(returncode=status)
                with patch.object(sudo_deps.subprocess, 'run', side_effect=run):
                    if status == 0 and signers == [sudo_deps.SIGNER]:
                        sudo_deps.verify_release(folder, folder / 'public-keyring')
                    else:
                        with self.assertRaisesRegex(ValueError, 'signature rejected'):
                            sudo_deps.verify_release(folder, folder / 'public-keyring')

    def test_development_fetch_rejects_truncation_hash_redirect_and_retains_partial(self):
        body = b'bounded artifact'
        relative = 'pool/main/a/audit/package.deb'
        for failure in ('none', 'truncated', 'hash', 'oversize', 'redirect', 'transport'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / 'package.deb'
                response = unittest.mock.MagicMock()
                response.__enter__.return_value = response
                response.status = 200
                response.geturl.return_value = ('https://wrong.invalid/' if failure == 'redirect'
                                               else sudo_deps.BASE + relative)
                response.read.side_effect = [body, OSError('lost') if failure == 'transport' else b'']
                opener = unittest.mock.Mock()
                opener.open.return_value = response
                size = len(body) + (1 if failure == 'truncated' else -1 if failure == 'oversize' else 0)
                sha = '0' * 64 if failure == 'hash' else hashlib.sha256(body).hexdigest()
                with patch.object(sudo_deps.urllib.request, 'build_opener', return_value=opener) as build:
                    if failure == 'none':
                        sudo_deps.fetch(relative, target, size=size, sha256=sha)
                    else:
                        with self.assertRaises((ValueError, OSError)):
                            sudo_deps.fetch(relative, target, size=size, sha256=sha)
                    self.assertEqual(opener.open.call_count, 1)
                    self.assertEqual(build.call_args.args[0].proxies, {})
                    self.assertIsInstance(build.call_args.args[1], sudo_source.NoRedirect)
                self.assertEqual(target.read_bytes(), b'' if failure in ('oversize', 'redirect') else body)

    def test_development_failed_acquisition_retains_receipt_without_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            key = out / 'public-keyring'
            key.write_bytes(b'synthetic public key')
            def fail(relative, target, **kwargs):
                target.write_bytes(b'partial')
                raise OSError('synthetic connection failure')
            with patch.object(sudo_deps, 'fetch', side_effect=fail) as fetch, \
                    patch.object(sudo_deps, 'verify_release') as verify:
                with self.assertRaises(OSError):
                    sudo_deps.acquire(out, key)
            self.assertEqual(fetch.call_count, 1)
            verify.assert_not_called()
            record = load(out / 'development-inputs/attempt.json')
            self.assertEqual(record['status'], 'failed')
            self.assertEqual(record['downloads'][0]['status'], 'failed')
            self.assertEqual(record['downloads'][0]['artifact']['sha256'], hashlib.sha256(b'partial').hexdigest())
            self.assertFalse((out / 'development-stage/verified.json').exists())

    def test_development_acquisition_freezes_exact_artifacts_before_extracting(self):
        import gzip
        entries, payloads = [], {}
        for dev, _, version, header, library, _ in sudo_inputs.REQUIRED:
            meta = {'Package': dev, 'Version': version, 'Architecture': 'amd64',
                    'Filename': 'pool/main/x/test/' + dev + '_fixture_amd64.deb',
                    'Size': '7', 'SHA256': hashlib.sha256(b'archive').hexdigest()}
            entries.append('\n'.join(k + ': ' + v for k, v in meta.items()))
            control = self.dependency_tar([('control', '\n'.join(k + ': ' + meta[k]
                for k in ('Package', 'Version', 'Architecture')).encode(), 0o644, None)])
            data = self.dependency_tar([('usr/include/' + header, b'header', 0o644, None),
                ('usr/lib/x86_64-linux-gnu/lib' + library + '.so', b'', 0o777,
                 '/lib/x86_64-linux-gnu/lib' + library + '.so.1'),
                ('usr/share/doc/' + dev + '/changelog.Debian.gz', b'', 0o777,
                 '../runtime-package/changelog.Debian.gz'),
                ('usr/share/doc/' + dev + '/examples/regress/run_test.sh', b'not staged', 0o755, None),
                ('usr/share/doc/' + dev + '/examples/regress/test.secret@here', b'not staged', 0o755, None)])
            payloads[dev] = {'control': control, 'data': data}
        index = gzip.compress(('\n\n'.join(entries) + '\n').encode())
        for failure in ('none', 'signature', 'missing', 'extract', 'member'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                out = Path(directory)
                key = out / 'public-keyring'
                key.write_bytes(b'fixture public key')
                (out / 'development-stage').mkdir()
                def fetch(relative, target, **expected):
                    target.write_bytes(index if target.name == 'Packages.gz' else b'archive')
                def verify(part, keyring):
                    if failure == 'signature':
                        raise ValueError('synthetic invalid signature')
                    (part / 'Release').write_text('Origin: Ubuntu\nSuite: ' + part.name +
                        '\nCodename: jammy\nSHA256:\n ' + hashlib.sha256(index).hexdigest() +
                        ' ' + str(len(index)) + ' ' + sudo_deps.INDEX + '\n')
                def decompress(archive, kind, part):
                    self.assertEqual(set(load(out / 'development-inputs/freeze.json')),
                                     {row[0] for row in sudo_inputs.REQUIRED})
                    if failure == 'extract':
                        raise ValueError('synthetic decompressor failure')
                    if failure == 'member' and part.name == 'libpam0g-dev' and kind == 'data':
                        return self.dependency_tar([('usr/bin/unexpected', b'private payload', 0o755, None)])
                    return payloads[part.name][kind]
                with ExitStack() as stack:
                    stack.enter_context(patch.object(sudo_deps, 'fetch', side_effect=fetch))
                    stack.enter_context(patch.object(sudo_deps, 'verify_release', side_effect=verify))
                    unpack = stack.enter_context(patch.object(sudo_deps, 'deb_tar', side_effect=decompress))
                    if failure == 'missing':
                        stack.enter_context(patch.object(sudo_deps, 'select_packages', return_value=None))
                    if failure != 'none':
                        with self.assertRaises(ValueError):
                            sudo_deps.acquire(out, key)
                        self.assertFalse((out / 'development-stage/verified.json').exists())
                    else:
                        sudo_deps.acquire(out, key)
                        staged = load(out / 'development-stage/verified.json')
                        self.assertEqual(set(staged['headers']), {r[3] for r in sudo_inputs.REQUIRED})
                        self.assertEqual(sum(p.is_file() for p in (out / 'development-stage').rglob('*')), 5)
                    if failure in ('signature', 'missing'):
                        unpack.assert_not_called()
                attempt = load(out / 'development-inputs/attempt.json')
                self.assertEqual(attempt['status'],
                                 'complete' if failure == 'none' else 'failed')
                if failure == 'member':
                    self.assertEqual(attempt['error_type'], 'ArchiveMemberError')
                    self.assertEqual(attempt['rejected_package'], {
                        'Package': 'libpam0g-dev', 'Version': '1.4.0-11ubuntu2.6',
                        'Architecture': 'amd64', 'SHA256': hashlib.sha256(b'archive').hexdigest()})
                    self.assertEqual(attempt['rejected_archive'], {
                        'path': 'development-inputs/libpam0g-dev/package.deb',
                        'sha256': hashlib.sha256(b'archive').hexdigest()})
                    self.assertEqual(attempt['rejected_member']['name'], 'usr/bin/unexpected')
                    self.assertEqual(attempt['rejected_member']['mode'], '0o755')
                    self.assertEqual(attempt['rejected_member']['type'], tarfile.REGTYPE.hex())
                    self.assertEqual(attempt['rejected_member']['reason'], 'Unexpected executable package payload')
                    self.assertNotIn('private payload', json.dumps(attempt))
                    self.assertEqual(list((out / 'development-stage').iterdir()), [])
                else:
                    self.assertNotIn('rejected_member', attempt)

    def test_development_decompression_uses_native_dpkg_without_installation(self):
        import gzip
        # A tiny synthetic Debian archive, never an installed/native proof.
        _, control, rows = self.dependency_fixture()
        def ar_member(name, content):
            header = f'{name + "/":<16}{0:<12}{0:<6}{0:<6}{"100644":<8}{len(content):<10}`\n'.encode()
            return header + content + (b'\n' if len(content) % 2 else b'')
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            archive = out / 'fixture.deb'
            archive.write_bytes(b'!<arch>\n' + ar_member('debian-binary', b'2.0\n') +
                ar_member('control.tar.gz', gzip.compress(control)) +
                ar_member('data.tar.gz', gzip.compress(self.dependency_tar(rows))))
            self.assertEqual(sudo_deps.deb_tar(archive, 'control', out), control)
            self.assertEqual(sudo_deps.deb_tar(archive, 'data', out), self.dependency_tar(rows))
            for kind in ('error', 'timeout'):
                part = out / kind
                part.mkdir()
                with patch.object(sudo_deps.subprocess, 'run', **(
                        {'side_effect': subprocess.TimeoutExpired('dpkg-deb', 30)} if kind == 'timeout'
                        else {'return_value': SimpleNamespace(returncode=2)})):
                    with self.assertRaises((ValueError, subprocess.TimeoutExpired)):
                        sudo_deps.deb_tar(archive, 'control', part)
                self.assertTrue((part / 'control.log').is_file())

    def test_staged_prerequisites_preserve_installed_metadata_and_reject_tampering(self):
        for failure in ('none', 'header', 'runtime', 'version', 'library_target'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                out = Path(directory)
                stage = out / 'inputs'
                stage.mkdir()
                manifest = {'schema': 1, 'headers': {}, 'packages': {}}
                for dev, runtime, version, header, library, _ in sudo_inputs.REQUIRED:
                    path = stage / 'include' / header
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b'header')
                    manifest['headers'][header] = hashlib.sha256(b'header').hexdigest()
                    manifest['packages'][dev] = {'metadata': {'Package': dev, 'Version': version,
                        'Architecture': 'amd64'}, 'runtime_library': '/lib/x86_64-linux-gnu/lib' + library + '.so.1'}
                if failure == 'header':
                    (stage / 'include/libaudit.h').write_bytes(b'changed')
                if failure == 'version':
                    manifest['packages']['libaudit-dev']['metadata']['Version'] = 'wrong'
                if failure == 'library_target':
                    manifest['packages']['libaudit-dev']['runtime_library'] = '/tmp/forged.so'
                (stage / 'verified.json').write_text(json.dumps(manifest))
                calls = []
                def run(argv, *, stdout, **kwargs):
                    calls.append(argv)
                    if argv[0] == '/usr/bin/dpkg-query':
                        # The development packages remain absent in dpkg.
                        stdout.write(''.join(runtime + '\t' +
                            ('wrong' if failure == 'runtime' else version) + '\tinstall ok installed\n'
                            for _, runtime, version, *_ in sudo_inputs.REQUIRED).encode())
                    return SimpleNamespace(returncode=0)
                def identity(path):
                    return {'path': str(path), 'resolved': str(path), 'sha256': 'b' * 64}
                with patch.object(sudo_inputs, 'file_identity', side_effect=identity), \
                        patch.object(sudo_inputs.subprocess, 'run', side_effect=run):
                    if failure != 'none':
                        with self.assertRaises(ValueError):
                            sudo_inputs.prerequisites(out, staged=stage)
                    else:
                        report = sudo_inputs.prerequisites(out, staged=stage)
                        self.assertEqual(report['status'], 'ready')
                        self.assertEqual(set(report['build_environment']), {'CPPFLAGS', 'LDFLAGS'})
                        self.assertTrue(all(row['packages'][row['development_package']] is None
                                            for row in report['requirements']))
                        self.assertEqual((out / 'development-links/libaudit.so').read_text(),
                                         'INPUT ( /lib/x86_64-linux-gnu/libaudit.so.1 )\n')
                        self.assertEqual(sum('-x' in argv for argv in calls), 4)
                self.assertTrue((out / 'checkpoint-prerequisites.json').is_file())
                self.assertFalse(any(argv[0].startswith(str(out)) for argv in calls))

    def test_failed_development_acquisition_never_starts_build_and_cleans_owned_container(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cid = 'a' * 64
            calls = []
            def command(argv, **kwargs):
                calls.append(argv)
                if argv[:2] == ['docker', 'create']:
                    self.assertIn('type=bind,src=' + str(root / 'run/development-stage') +
                                  ',dst=/ptw-sudo-inputs,readonly', argv)
                    return cid.encode()
                if argv[:2] == ['docker', 'cp']:
                    self.assertEqual(argv[2], cid + ':/usr/share/keyrings/ubuntu-archive-keyring.gpg')
                    Path(argv[3]).write_bytes(b'synthetic public key')
                return b''
            def stage(source, out):
                bundle = out / 'bundle'
                bundle.mkdir()
                return bundle
            with patch.object(sudo_gate, 'stage', side_effect=stage), \
                    patch.object(sudo_build, 'stage'), \
                    patch.object(sudo_gate, 'daemon_environment', return_value=({}, {})), \
                    patch.object(sudo_gate, 'verify_daemon', return_value={
                        'image_id': 'sha256:' + 'b' * 64, 'cgroup': '/fixture.slice'}), \
                    patch.object(sudo_gate, 'Commands', return_value=command), \
                    patch.object(preflight, 'resource_snapshot', return_value={'admitted': True}), \
                    patch.object(sudo_deps, 'acquire', side_effect=ValueError('unverified inputs')):
                with self.assertRaisesRegex(ValueError, 'unverified inputs'):
                    sudo_gate.run(root, root / 'source', root / 'run', checkpoint=True)
            self.assertFalse(any(argv[:2] in (['docker', 'start'], ['docker', 'exec']) for argv in calls))
            self.assertEqual(calls[-1], ['docker', 'rm', '--force', cid])
            self.assertEqual(load(root / 'run/attempt.json')['status'], 'failed')

    def test_configure_argv_preserves_source_quoting_and_rejects_metadata_drift(self):
        # Synthetic quoted distribution rule, not a reconstruction from sudo -V.
        # The retained archive is independently exercised by native source staging.
        rules = (b'define CONFIGURE_ARGS\n\t--with-pam --with-pam-login\n'
                 b'\t--with-passprompt="[sudo] password for %p: "\n'
                 b'\t--with-sssd-lib=/usr/lib/$(DEB_HOST_MULTIARCH)\nendef\n'
                 b'CONFIGURE_ARGS += --with-selinux --with-linux-audit\n')
        expected = list(sudo_inputs.PREFIX) + ['--with-pam', '--with-pam-login',
            '--with-passprompt=[sudo] password for %p: ',
            '--with-sssd-lib=/usr/lib/x86_64-linux-gnu', '--with-selinux', '--with-linux-audit']
        version = 'Sudo version 1.9.9\nConfigure options: ' + ' '.join(expected) + '\n'
        with patch.object(sudo_inputs, 'RULES_SHA256', hashlib.sha256(rules).hexdigest()):
            self.assertEqual(sudo_inputs.configure_arguments(rules, version), expected)
            for bad in (version.replace('%p:  ', '%p: '),
                        version.replace('--with-pam ', ''),
                        version.replace('--with-linux-audit', '--without-linux-audit'),
                        version.replace('1.9.9', '1.9.10'),
                        version + version.splitlines()[1] + '\n',
                        version.replace('Configure options: ', 'Configure options: --host=password '),
                        '', None, version + '\x00', 'x' * 65537):
                with self.subTest(metadata=repr(bad)[:100]), self.assertRaises(ValueError):
                    sudo_inputs.configure_arguments(rules, bad)
            for bad in (rules + b'\n', rules.replace(b'--with-pam', b'--without-pam'), None):
                with self.assertRaises(ValueError):
                    sudo_inputs.configure_arguments(bad, version)

    def test_build_prerequisites_bind_packages_files_and_link_without_execution(self):
        self._check_build_prerequisites('ready')

    def test_missing_prerequisites_stop_entire_checkpoint_before_compilation(self):
        import runpy
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            rules = b'define CONFIGURE_ARGS\n\t--with-pam\nendef\n'
            (out / 'distribution/debian').mkdir(parents=True)
            (out / 'distribution/debian/rules').write_bytes(rules)
            version = ('Sudo version 1.9.9\nConfigure options: ' +
                       ' '.join([*sudo_inputs.PREFIX, '--with-pam']) + '\n')
            calls = []
            def missing(argv, *, stdout, **kwargs):
                calls.append(argv)
                # Empty successful inventory deliberately has no build inputs.
                return SimpleNamespace(returncode=0)
            program = (sudo_build.PREFLIGHT + '\n' + sudo_gate.BUILD + '\n' +
                       sudo_build.BUILD).replace('/ptw-sudo-gate', str(out))
            with patch.object(sudo_inputs, 'RULES_SHA256', hashlib.sha256(rules).hexdigest()), \
                 patch.object(runpy, 'run_path', return_value=vars(sudo_inputs)), \
                 patch.object(subprocess, 'check_output', return_value=version), \
                 patch.object(subprocess, 'run', side_effect=missing), \
                 self.assertRaisesRegex(ValueError, 'build inputs unavailable'):
                exec(program, {})
            self.assertEqual(len(calls), 5)  # inventory and four tool versions only
            self.assertTrue(all(a[0] == '/usr/bin/dpkg-query' or a[1:] == ['--version']
                                for a in calls))
            self.assertEqual(load(out / 'checkpoint-prerequisites.json')['status'], 'unavailable')
            self.assertTrue((out / 'checkpoint-build-inputs.json').is_file())
            for path in ('frontend-build', 'policy.so', 'closed', 'checkpoint-sudo'):
                self.assertFalse((out / path).exists())

    def test_build_prerequisites_retain_missing_drift_and_tool_failures(self):
        for failure in ('missing_header', 'missing_library', 'missing_package',
                        'package_version', 'package_status', 'package_query',
                        'malformed_packages', 'duplicate_packages', 'compiler_error',
                        'compiler_timeout', 'missing_tool', 'link_error', 'link_timeout'):
            with self.subTest(failure=failure):
                self._check_build_prerequisites(failure)

    def _check_build_prerequisites(self, failure):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            calls = []
            def identity(path):
                path = str(path)
                if ((failure == 'missing_header' and path == '/usr/include/libaudit.h') or
                    (failure == 'missing_library' and path.endswith('/libaudit.so')) or
                    (failure == 'missing_tool' and path == '/usr/bin/cc')):
                    return {'path': path, 'error': 'FileNotFoundError'}
                return {'path': path, 'resolved': path, 'sha256': 'a' * 64}
            def run(argv, *, stdout, stderr, input, **kwargs):
                calls.append(argv)
                if argv[0] == '/usr/bin/dpkg-query':
                    lines = [f'{name}:amd64\t{version}\tinstall ok installed\n'
                        for dev, runtime, version, *_ in sudo_inputs.REQUIRED
                        for name in (dev, runtime)]
                    if failure == 'missing_package':
                        lines.pop(0)
                    if failure == 'package_version':
                        lines[0] = lines[0].replace('1:3.0.7-1build1', '1:3.0.7-other')
                    if failure == 'package_status':
                        lines[0] = lines[0].replace('install ok installed', 'deinstall ok config-files')
                    if failure == 'malformed_packages':
                        lines = ['not tab separated\n']
                    if failure == 'duplicate_packages':
                        lines.append(lines[0].replace(':amd64', ''))
                    stdout.write(''.join(lines).encode())
                    return SimpleNamespace(returncode=int(failure == 'package_query'))
                self.assertIn(argv[0], ('/usr/bin/cc', '/usr/bin/make', '/usr/bin/ld', '/usr/bin/as'))
                self.assertEqual(kwargs['env'], sudo_inputs.ENV)
                self.assertEqual(kwargs['timeout'], 30)
                if '-x' in argv:
                    self.assertIn(b'#include <', input)
                    self.assertTrue(argv[-1].startswith('-l'))
                    if failure == 'link_timeout':
                        raise subprocess.TimeoutExpired(argv, 30)
                    return SimpleNamespace(returncode=int(failure == 'link_error'))
                self.assertEqual(argv[1:], ['--version'])
                if argv[0] == '/usr/bin/cc' and failure == 'compiler_timeout':
                    raise subprocess.TimeoutExpired(argv, 30)
                return SimpleNamespace(returncode=int(
                    argv[0] == '/usr/bin/cc' and failure == 'compiler_error'))
            with patch.object(sudo_inputs, 'file_identity', side_effect=identity), \
                 patch.object(sudo_inputs.subprocess, 'run', side_effect=run):
                if failure == 'ready':
                    result = sudo_inputs.prerequisites(out)
                    self.assertEqual(result['status'], 'ready')
                    self.assertEqual(len([a for a in calls if '-x' in a]), 4)
                else:
                    with self.assertRaises(ValueError):
                        sudo_inputs.prerequisites(out)
            record = load(out / 'checkpoint-prerequisites.json')
            self.assertEqual(record['status'] == 'ready', failure == 'ready')
            if failure not in ('malformed_packages', 'duplicate_packages'):
                self.assertEqual(len(record['requirements']), 4)
                self.assertEqual(set(record['tools']), {'cc', 'make', 'ld', 'as'})
            # Neither configure, package installation nor the compiled probes run.
            self.assertTrue(all(a[0].startswith('/usr/bin/') for a in calls))
            self.assertFalse((out / 'frontend-build').exists())

    def test_execution_patch_refuses_changed_or_duplicate_context(self):
        original = ('#include "sudo.h"\n    unlimit_nproc();\n\n'
                    '#if defined(HAVE_SETRESUID)\n'
                    '    ret = true;\n\ndone:\n'
                    '    /* Close all fds except those explicitly preserved. */\n'
                    '    restore_limits();\n    /* The caller will run any plugin close functions. */\n')
        make = 'OBJS = conversation.o\n# Autogenerated dependencies, do not modify\n'
        cases = [(content, make) for content in
                 (original, original.replace('unlimit_nproc', 'changed'), original * 2,
                  original.replace('restore_limits', 'changed_limits'),
                  original.replace('The caller will run', 'Changed caller'))]
        cases += [(original, content) for content in
                  (make.replace('conversation.o', 'changed.o'),
                   make.replace('Autogenerated', 'Changed'), make * 2)]
        for content, make_content in cases:
            with self.subTest(content=content, make=make_content), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                (root / 'src').mkdir()
                for name, closure in (('exec_nopty.c', 'ec'), ('exec_monitor.c', 'mc')):
                    (root / 'src' / name).write_text('#include "sudo.h"\n' +
                        f'    {closure}.cmnd_pid = sudo_debug_fork();\n')
                (root / 'src/exec_monitor.c').write_text(self.monitor_patch_context())
                (root / 'src/exec_pty.c').write_text(self.pty_patch_context())
                (root / 'src/exec.c').write_text(content)
                (root / 'src/Makefile.in').write_text(make_content)
                if content != original or make_content != make:
                    with self.assertRaisesRegex(ValueError, 'context changed'):
                        sudo_build.execution_patch(root)
                    self.assertEqual((root / 'src/exec.c').read_text(), content)
                    self.assertEqual((root / 'src/Makefile.in').read_text(), make_content)
                else:
                    sudo_build.execution_patch(root)
                    result = (root / 'src/exec.c').read_text()
                    self.assertLess(result.index('unlimit_nproc'), result.index('ptw_child_before_uid'))
                    self.assertLess(result.index('ptw_child_before_uid'), result.index('HAVE_SETRESUID'))
                    self.assertLess(result.index('ptw_child_after_uid'), result.index('ret = true'))
                    self.assertLess(result.index('restore_limits();'), result.index('ptw_child_request_pin()'))
                    self.assertLess(result.index('ptw_child_request_pin()'), result.index('ptw_child_pin()'))
                    self.assertLess(result.index('ptw_child_after_uid'), result.index('ptw_child_request_verify'))
                    self.assertLess(result.index('ptw_child_request_verify'), result.index('ret = true'))
                    self.assertLess(result.index('ptw_child_cleanup();'),
                                    result.index('/* The caller will run any plugin close functions. */'))
                    pty = (root / 'src/exec_pty.c').read_text()
                    self.assertIn('ec.monitor_pid = sudo_debug_fork();\n'
                                  '    if (ec.monitor_pid != 0)\n\tptw_child_cleanup();', pty)
                    self.assertIn('\tptw_child_cleanup();\n\tcstat->type = CMD_ERRNO;', pty)
                    monitor = (root / 'src/exec_monitor.c').read_text()
                    self.assertLess(monitor.index('tcsetpgrp('), monitor.index('ptw_child_continue('))
                    self.assertLess(monitor.index('ptw_child_continue('), monitor.index('sigprocmask('))
                    self.assertLess(monitor.index('sigprocmask('), monitor.index('Wait for errno'))

    def test_execution_patch_builds_child_outside_source_and_tracks_headers(self):
        # Exercise make and the real compiler, not privileged checkpoint calls.
        # The native build uses a separate directory with no VPATH; merely adding
        # an OBJS entry cannot locate the new source through its suffix rule.
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            src = root / 'src'
            src.mkdir()
            build = root / 'build'
            build.mkdir()
            (src / 'exec.c').write_text('#include "sudo.h"\n    unlimit_nproc();\n\n'
                '#if defined(HAVE_SETRESUID)\n    ret = true;\n\ndone:\n'
                '    /* Close all fds except those explicitly preserved. */\n'
                    '    restore_limits();\n    /* The caller will run any plugin close functions. */\n')
            for name, closure in (('exec_nopty.c', 'ec'), ('exec_monitor.c', 'mc')):
                (src / name).write_text('#include "sudo.h"\n' +
                    f'    {closure}.cmnd_pid = sudo_debug_fork();\n')
            (src / 'Makefile.in').write_text('OBJS = conversation.o\n'
                '.SUFFIXES: .c .o\n.c.o:\n\t$(CC) -c $<\n'
                '# Autogenerated dependencies, do not modify\n')
            (src / 'exec_monitor.c').write_text(self.monitor_patch_context())
            (src / 'exec_pty.c').write_text(self.pty_patch_context())
            sudo_build.execution_patch(root)
            for name in ('linuxarena_sudo_child.c', 'linuxarena_sudo_child.h', 'linuxarena_sudo_placement.h'):
                (src / name).write_bytes((SCRIPTS / name).read_bytes())
            (src / 'linuxarena_sudo_filter.h').write_text(sudo_build.filter_header())
            argv = ['make', '-rR', '-f', str(src / 'Makefile.in'),
                    'srcdir=' + str(src), 'CC=cc', 'CPPFLAGS=-D_FORTIFY_SOURCE=2',
                    'CFLAGS=-std=c11 -O2 -Wall -Wextra -Werror',
                    'ASAN_CFLAGS=', 'PIE_CFLAGS=-fPIE', 'SSP_CFLAGS=-fstack-protector-strong',
                    'linuxarena_sudo_child.o']
            def run(*args):
                return subprocess.run([*argv, *args], cwd=build, capture_output=True,
                                      text=True, timeout=30)
            result = run()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            obj = build / 'linuxarena_sudo_child.o'
            self.assertTrue(obj.read_bytes().startswith(b'\x7fELF'))
            self.assertFalse((src / obj.name).exists())
            for flag in ('-D_FORTIFY_SOURCE=2', '-Werror', '-fPIE', '-fstack-protector-strong'):
                self.assertIn(flag, result.stdout)
            self.assertEqual(run('-q').returncode, 0)
            for name in ('linuxarena_sudo_child.c', 'linuxarena_sudo_child.h',
                         'linuxarena_sudo_filter.h', 'linuxarena_sudo_placement.h'):
                path = src / name
                stamp = obj.stat().st_mtime_ns
                # Force only the object older, avoiding sleeps/future timestamps.
                os.utime(obj, ns=(stamp, path.stat().st_mtime_ns - 1))
                self.assertEqual(run('-q').returncode, 1, name)
                result = run()
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            header = src / 'linuxarena_sudo_filter.h'
            header.unlink()
            result = run()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('linuxarena_sudo_filter.h', result.stderr)
            header.write_text('#error invalid filter input\n')
            obj.unlink()
            result = run()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('invalid filter input', result.stderr)
            self.assertFalse(obj.exists())

    def test_execution_patch_rejects_fork_drift_before_any_write(self):
        originals = {
            'exec.c': '#include "sudo.h"\n    unlimit_nproc();\n\n'
                      '#if defined(HAVE_SETRESUID)\n    ret = true;\n\ndone:\n'
                      '    /* Close all fds except those explicitly preserved. */\n'
                    '    restore_limits();\n    /* The caller will run any plugin close functions. */\n',
            'Makefile.in': 'OBJS = conversation.o\n# Autogenerated dependencies, do not modify\n',
            'exec_nopty.c': '#include "sudo.h"\n    ec.cmnd_pid = sudo_debug_fork();\n',
            'exec_monitor.c': '#include "sudo.h"\n    mc.cmnd_pid = sudo_debug_fork();\n',
        }
        originals['exec_pty.c'] = self.pty_patch_context()
        originals['exec_monitor.c'] = self.monitor_patch_context()
        for name in ('exec_nopty.c', 'exec_monitor.c', 'exec_pty.c'):
            for invalid in ('missing', 'duplicate', 'changed', 'foreground', 'unmask',
                            'diagnostic', 'signal_target', 'wait_observe', 'wait_result', 'callback'):
                if invalid in ('wait_observe', 'wait_result', 'callback') and name != 'exec_monitor.c':
                    continue
                if invalid in ('foreground', 'unmask') and name != 'exec_monitor.c':
                    continue
                if invalid in ('diagnostic', 'signal_target') and name == 'exec_nopty.c':
                    continue
                with self.subTest(name=name, invalid=invalid), tempfile.TemporaryDirectory() as folder:
                    src = Path(folder) / 'src'
                    src.mkdir()
                    before = dict(originals)
                    if invalid == 'missing':
                        del before[name]
                    elif invalid == 'duplicate':
                        before[name] *= 2
                    elif invalid == 'foreground':
                        before[name] = before[name].replace('tcsetpgrp(', 'changed_foreground(')
                    elif invalid == 'unmask':
                        before[name] = before[name].replace('sigprocmask(', 'changed_mask(')
                    elif invalid == 'diagnostic':
                        before[name] = before[name].replace('WIFCONTINUED(status)', 'changed_status(status)').replace(
                            'case CMD_WSTATUS:', 'case CHANGED_STATUS:')
                    elif invalid == 'signal_target':
                        before[name] = before[name].replace('killpg(', 'changed_signal(')
                    elif invalid == 'wait_observe':
                        before[name] = before[name].replace('debug_decl(mon_handle_sigchld,', 'debug_decl(changed,')
                    elif invalid == 'wait_result':
                        before[name] = before[name].replace('WUNTRACED|WCONTINUED|WNOHANG', 'WNOHANG')
                    elif invalid == 'callback':
                        before[name] = before[name].replace('debug_decl(mon_signal_cb,', 'debug_decl(changed,')
                    else:
                        before[name] = before[name].replace('sudo_debug_fork()', 'fork()')
                    for path, content in before.items():
                        (src / path).write_text(content)
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        sudo_build.execution_patch(Path(folder))
                    self.assertEqual({p.name: p.read_text() for p in src.iterdir()}, before)

    def test_compiled_job_diagnostics_preserve_signal_results_errno_and_bounds(self):
        # Actual diagnostic code, with signal syscall doubles. Never signal a
        # native group or claim this establishes terminal stop propagation.
        program = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
static int calls, failed, lost;
static int observations, observation_mode;
static int fake_waitid(idtype_t type, id_t pid, siginfo_t *info, int options) {
    if (type != P_PID || pid != 1234 || options !=
        (WEXITED | WSTOPPED | WCONTINUED | WNOHANG | WNOWAIT)) _exit(91);
    observations++;
    if (observation_mode == 2) { errno = ECHILD; return -1; }
    if (observation_mode == 1) {
        info->si_pid = 1234; info->si_code = CLD_STOPPED; info->si_status = SIGSTOP;
    }
    return 0;
}
static int fake_killpg(pid_t group, int signo) {
    if (group != 1234 || signo != SIGCONT) _exit(90);
    calls++;
    if (failed) { errno = ESRCH; return -1; }
    return 0;
}
static ssize_t fake_write(int fd, const void *data, size_t size) {
    if (lost) { errno = EIO; return -1; }
    return write(fd, data, size);
}
#define killpg fake_killpg
#define write fake_write
#define waitid fake_waitid
#include "linuxarena_sudo_child.c"
int main(void) {
    for (observation_mode=0; observation_mode<3; observation_mode++) {
        errno = EBUSY;
        ptw_job_wait_observe(1234, -1);
        if (errno != EBUSY || observations != observation_mode + 1) return 6;
    }
    errno = EBUSY;
    ptw_job_trace(1, 1234, 1234, 19, 0, 0, -1);
    if (errno != EBUSY) return 1;
    if (ptw_job_killpg(2, 1234, SIGCONT, -1) || errno != EBUSY || calls != 1) return 2;
    failed = 1;
    if (ptw_job_killpg(4, 1234, SIGCONT, -1) != -1 || errno != ESRCH || calls != 2) return 3;
    lost = 1;
    if (ptw_job_killpg(6, 1234, SIGCONT, -1) != -1 || errno != ESRCH || calls != 3) return 4;
    lost = 0;
    for (int i=0; i<100; i++) ptw_job_trace(8, 1234, 1234, i, 0, 0, -1);
    if (errno != ESRCH) return 5;
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'test.c').write_text(program)
            # Only enable logging; this test never enters the release checkpoint.
            (root / 'linuxarena_sudo_filter.h').write_text(
                '#define PTW_REQUEST_RELEASE 1\n' + sudo_build.filter_header())
            compiled = subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                '-D_FORTIFY_SOURCE=2', '-I' + str(root), '-I' + str(SCRIPTS), str(root / 'test.c'),
                '-ldl', '-o', str(root / 'test')], capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([str(root / 'test')], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            rows = result.stderr.splitlines()
            self.assertEqual(len(rows), 22)  # Two attempted records had a failed sink.
            for row in rows:
                self.assertLess(len(row), 320)
                self.assertTrue(row.startswith('PTW_JOB '))
                fields = dict(field.split('=') for field in row.split()[1:])
                self.assertEqual(set(fields), {'phase', 'pid', 'ppid', 'pgid', 'sid', 'fg',
                                              'subject', 'group', 'value', 'result', 'error'})
                self.assertTrue(all(value.lstrip('-').isdigit() for value in fields.values()))
            self.assertIn('group=0 value=0 result=0 error=0', rows[0])
            self.assertIn('group=1234 value=19 result=0 error=0', rows[3])
            self.assertIn('result=-1 error=10', rows[4])
            self.assertIn('phase=5', rows[10])
            self.assertIn('result=-1 error=3', rows[10])

    def test_archive_validation_precedes_writes(self):
        for name, kind, link in (
                ('sudo-1.9.9/../escape', tarfile.REGTYPE, ''),
                ('/sudo-1.9.9/file', tarfile.REGTYPE, ''),
                ('sudo-1.9.9/link', tarfile.SYMTYPE, '/outside'),
                ('sudo-1.9.9/link', tarfile.LNKTYPE, 'sudo-1.9.9/file'),
                ('sudo-1.9.9/pipe', tarfile.FIFOTYPE, '')):
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode='w') as archive:
                valid = tarfile.TarInfo('sudo-1.9.9/valid')
                archive.addfile(valid, io.BytesIO())
                invalid = tarfile.TarInfo(name)
                invalid.type, invalid.linkname = kind, link
                archive.addfile(invalid, io.BytesIO())
            content = data.getvalue()
            with tempfile.TemporaryDirectory() as folder:
                target = Path(folder) / 'new'
                with self.subTest(name=name), self.assertRaises(ValueError):
                    sudo_build.unpack(content, hashlib.sha256(content).hexdigest(),
                                      target, prefix='sudo-1.9.9')
                self.assertFalse(target.exists())

    def test_pinned_patch_targets_allow_required_added_regressions(self):
        self.assertEqual(sudo_build.patch_targets(
            b'--- a/src/exec.c\n+++ b/src/exec.c\n--- /dev/null\n+++ b/test20.sh\n'),
            [{'path': 'src/exec.c', 'create': False}, {'path': 'test20.sh', 'create': True}])
        for data in (b'--- a/file\n+++ b/../../escape\n',
                     b'--- a/file\n+++ /dev/null\n', b'--- a/file\n+++ b/other\n',
                     b'--- a/file\n+++ b/file\n--- a/file\n+++ b/file\n'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                sudo_build.patch_targets(data)

    @staticmethod
    def checkpoint_lines(terminal=False):
        state = ('PTW_CHILD_STATE uid=1000 effective=0 permitted=0 bounding=0 '
                 'inheritable=0 ambient=0 securebits=0 nnp=1 seccomp=2')
        route = int(terminal)
        def event(stage, pid, ppid, child=0, selected=route):
            return (f'PTW_FORK stage={stage} route={selected} pid={pid} ppid={ppid} '
                    f'child={child} mnt=101 pidns=102 userns=103')
        return ['PTW_SUDO_STAGE session=1', event('prepare', 10, 9),
                event('parent', 10, 9, 11), event('child', 11, 10),
                event('before_uid', 11, 10),
                'PTW_CHILD_STAGE before_uid=1000 filter=' +
                hashlib.sha256(namespace.socket_filter()).hexdigest(), state,
                event('after_uid', 11, 10), state, event('exec', 11, 10, selected=-1),
                'PTW_CHILD_FDS stdio_only=1',
                'PTW_CHILD_SYSCALLS tcp=allowed unix=allowed udp=EPERM io_uring=EPERM',
                'PTW_SUDO_STAGE close=32000 error=0']

    def test_checkpoint_receipt_rejects_missing_changed_or_reordered_states(self):
        for terminal in (False, True):
            lines = self.checkpoint_lines(terminal)
            sudo_gate.validate_checkpoint('root_to_dev', {'stderr': '\n'.join(lines)}, terminal=terminal)
            invalid = [lines[:2], list(reversed(lines)), lines + [lines[6]],
                       [x.replace('bounding=0', 'bounding=eb') for x in lines],
                       [x.replace('nnp=1', 'nnp=0') for x in lines],
                       [x.replace('filter=', 'filter=bad') for x in lines]]
            for bad in invalid:
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    sudo_gate.validate_checkpoint('root_to_dev', {'stderr': '\n'.join(bad)},
                                                  terminal=terminal)
            with self.assertRaises(ValueError):
                sudo_gate.validate_checkpoint('invalid_target', {'stderr': '\n'.join(lines)})

    def test_child_request_receipt_rejects_substitution_replay_and_early_verification(self):
        for terminal in (False, True):
            lines = self.checkpoint_lines(terminal)
            claim = 'PTW_SUDO_CHILD_REQUEST phase=0 pid=11 argc=2 envc=12'
            checked = claim.replace('phase=0', 'phase=1')
            lines.insert(3, claim)
            lines.insert(next(i for i, line in enumerate(lines)
                              if line.startswith('PTW_FORK stage=exec ')), checked)
            lines.insert(0, 'PTW_SUDO_REQUEST session=1 envc=12')
            sudo_gate.validate_child_request('root_to_dev', {'stderr': '\n'.join(lines)})
            invalid = [lines + [claim], [x for x in lines if x != checked],
                       [checked, *[x for x in lines if x != checked]],
                       [x.replace('phase=1 pid=11', 'phase=1 pid=12') for x in lines],
                       [x.replace('argc=2', 'argc=3') for x in lines],
                       [x.replace('session=1 envc=12', 'session=1 envc=11') for x in lines]]
            for bad in invalid:
                with self.subTest(terminal=terminal, bad=bad), self.assertRaises(ValueError):
                    sudo_gate.validate_child_request('root_to_dev', {'stderr': '\n'.join(bad)})
            with self.assertRaises(ValueError):
                sudo_gate.validate_child_request('native_denial', {'stderr': '\n'.join(lines)})

    def test_fork_receipt_rejects_identity_route_namespace_and_session_drift(self):
        lines = self.checkpoint_lines()
        changes = [(0, 'session=1', 'session=0'), (1, 'route=0', 'route=1'),
                   (1, 'pid=10', 'pid=0'), (2, 'child=11', 'child=12'),
                   (3, 'ppid=10', 'ppid=9'), (4, 'mnt=101', 'mnt=104'),
                   (7, 'pidns=102', 'pidns=104'), (9, 'userns=103', 'userns=104'),
                   (9, 'route=-1', 'route=0'), (12, 'error=0', 'error=1')]
        for index, old, new in changes:
            bad = lines.copy()
            bad[index] = bad[index].replace(old, new)
            with self.subTest(index=index, new=new), self.assertRaises(ValueError):
                sudo_gate.validate_fork_stages('root_to_dev', {'stderr': '\n'.join(bad)})
        for index in (1, 2, 3, 4, 7, 9):
            for bad in (lines[:index] + lines[index + 1:], lines + [lines[index]]):
                with self.assertRaises(ValueError):
                    sudo_gate.validate_fork_stages('root_to_dev', {'stderr': '\n'.join(bad)})
        for bad in ([lines[1], lines[0], *lines[2:]], [*lines[:9], lines[-1], *lines[9:-1]]):
            with self.assertRaises(ValueError):
                sudo_gate.validate_fork_stages('root_to_dev', {'stderr': '\n'.join(bad)})

    def test_compiled_fork_barrier_and_exec_descriptor_rejection(self):
        # Real unprivileged fork/pipe and fd enumeration only. No sudo, socket,
        # namespace mutation or capability/filter syscall is run here.
        wrapper = r"""
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
static const char *failure;
static ssize_t test_write(int fd, const void *buf, size_t size) {
    if (!strcmp(failure,"parent_log") && size>20 && strstr(buf,"stage=parent")) {
        errno=EIO; return -1;
    }
    if (!strcmp(failure,"token") && size==1) {errno=EIO;return -1;}
    return write(fd,buf,size);
}
#define write test_write
#include "linuxarena_sudo_child.c"
static int claim_calls;
static int test_request(int phase, char *const env[], uid_t uid, uid_t euid) {
    (void)env; (void)uid; (void)euid;
    if (phase != 0 || ++claim_calls != 1) _exit(94);
    return !strcmp(failure, "request_denied") ? -1 : 0;
}
static pid_t test_fork(void) {
    if (!strcmp(failure,"fork")) {errno=EAGAIN;return -1;}
    pid_t result=fork();
    if (result==0 && !strcmp(failure,"child_namespace")) fork_placement.mount++;
    return result;
}
int main(int argc,char **argv) {
    if(argc!=3) return 98;
    failure=argv[1];
    if(!strcmp(failure,"request_missing")) return ptw_child_request_pin() < 0 ? 10 : 99;
    if(!strcmp(failure,"request_unbound")) return ptw_child_request_verify(NULL,0,0) < 0 ? 10 : 99;
    request_callback=test_request;
    if(!strcmp(failure,"exec")) return ptw_child_exec_observe() ? 10 : 0;
    if(!strcmp(failure,"unbound")) return child_placement("before_uid") ? 10 : 99;
    if(!strcmp(failure,"null")) return ptw_child_fork(NULL,0) < 0 ? 10 : 99;
    /* Native callers block signals around this fork. Match that contract. */
    sigset_t blocked; sigfillset(&blocked); sigprocmask(SIG_BLOCK,&blocked,NULL);
    pid_t child=ptw_child_fork(test_fork,atoi(argv[2]));
    if(child<0) {
        if(waitpid(-1,NULL,WNOHANG)!=-1 || errno!=ECHILD) return 97;
        return 10;
    }
    if(child==0) {
        if(!command_child || claim_calls!=1 || child_placement("before_uid")) _exit(96);
        _exit(0);
    }
    int status=0;
    if(waitpid(child,&status,0)!=child || !WIFEXITED(status)) return 95;
    if(!strcmp(failure,"repeated")) return ptw_child_fork(test_fork,0) < 0 ? 10 : 99;
    return WEXITSTATUS(status);
}
"""
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'linuxarena_sudo_filter.h').write_text(sudo_build.filter_header())
            (root / 'test.c').write_text(wrapper)
            result = subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                '-I' + str(root), '-I' + str(SCRIPTS), str(root / 'test.c'), '-o', str(root / 'test')],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            for route in (0, 1):
                for failure in ('none', 'fork', 'parent_log', 'token', 'child_namespace',
                                'repeated', 'unbound', 'null', 'request_denied',
                                'request_missing', 'request_unbound'):
                    result = subprocess.run([str(root / 'test'), failure, str(route)],
                                            capture_output=True, text=True, timeout=5)
                    with self.subTest(route=route, failure=failure):
                        expected = (0 if failure == 'none' else 126 if failure in
                                    ('child_namespace', 'request_denied') else 10)
                        self.assertEqual(result.returncode, expected, result.stderr)
                        if failure in ('fork', 'parent_log', 'token', 'child_namespace', 'null', 'unbound',
                                       'request_denied', 'request_missing', 'request_unbound'):
                            self.assertNotIn('stage=before_uid', result.stderr)
                        if failure == 'none':
                            self.assertIn(f'stage=prepare route={route}', result.stderr)
                            self.assertIn(f'stage=before_uid route={route}', result.stderr)
            result = subprocess.run([str(root / 'test'), 'none', '2'], capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 10)
            result = subprocess.run([str(root / 'test'), 'exec', '0'], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('PTW_CHILD_FDS stdio_only=1', result.stderr)
            # Test an old-root directory descriptor and a high-numbered regular
            # file; enumeration cannot stop at an assumed small closefrom limit.
            import fcntl
            for path in (root, root / 'test.c'):
                opened = os.open(path, os.O_RDONLY)
                try:
                    leaked = fcntl.fcntl(opened, fcntl.F_DUPFD, 512)
                    try:
                        result = subprocess.run([str(root / 'test'), 'exec', '0'],
                            pass_fds=(leaked,), capture_output=True, text=True, timeout=5)
                    finally:
                        os.close(leaked)
                finally:
                    os.close(opened)
                self.assertEqual(result.returncode, 10, result.stderr)
                self.assertIn('stage=exec_descriptors', result.stderr)
                self.assertNotIn('PTW_CHILD_FDS stdio_only=1', result.stderr)

    def test_compiled_controller_barrier_requires_ack_after_stop_and_closes_transport(self):
        # Real fork, pipe, stop/continue and cleanup; transport syscalls are
        # doubles. No sockets, native sudo or namespace operations run here.
        wrapper = r"""
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
static const char *failure;
static int connection=-1;
static pid_t requested;
static int continuing;
static int foreground[2];
static int route;
static int fail(const char *name) { if(strcmp(failure,name)) return 0; errno=EIO; return 1; }
static int fake_socket(int a,int b,int c) {
    (void)a;(void)b;(void)c;
    if(fail("socket")) return -1;
    return connection=open("/dev/null",O_RDONLY|O_CLOEXEC);
}
static int fake_option(int a,int b,int c,const void *d,socklen_t e) {
    (void)a;(void)b;(void)c;(void)d;(void)e;return fail("option") ? -1 : 0;
}
static int fake_connect(int a,const struct sockaddr *b,socklen_t c) {
    (void)a;(void)b;(void)c;return fail("connect") ? -1 : 0;
}
static ssize_t fake_send(int a,const void *b,size_t c,int d) {
    (void)a;(void)d;if(c!=4) _exit(97);
    unsigned wire;memcpy(&wire,b,4);continuing=!!(wire & 0x80000000);
    requested=(pid_t)(wire & 0x7fffffff);
    return fail("send") ? 3 : (ssize_t)c;
}
static int fake_shutdown(int a,int b) { (void)a;(void)b;return fail("shutdown") ? -1 : 0; }
static ssize_t fake_recv(int a,void *b,size_t c,int d) {
    (void)a;(void)c;(void)d;
    /* Even a premature SIGCONT must not cross the still-closed local pipe. */
    if(kill(requested,SIGCONT)) _exit(96);
    if(fail("recv") || (continuing && fail("continue_recv"))) return -1;
    if(!strcmp(failure,"eof")) return 0;
    memcpy(b,!strcmp(failure,"wrong") ? "D" : "CC",2);
    return !strcmp(failure,"extra") ? 2 : 1;
}
static int owned_kill(pid_t pid, int sig) {
    if (!strcmp(failure,"request_verify") && sig==SIGKILL) {
        siginfo_t observed={0};
        if(waitid(P_PID,(id_t)pid,&observed,WEXITED|WNOHANG|WNOWAIT) ||
            observed.si_pid!=pid || observed.si_code!=CLD_EXITED) _exit(90);
    }
    return kill(pid,sig);
}
#define kill owned_kill
#define socket fake_socket
#define setsockopt fake_option
#define connect fake_connect
#define send fake_send
#define shutdown fake_shutdown
#define recv fake_recv
#include "linuxarena_sudo_child.c"
static int request_binding(int phase, char *const env[], uid_t uid, uid_t euid) {
    (void)env;(void)uid;(void)euid;
    return phase == 1 && fail("request_verify") ? -1 : 0;
}
int main(int argc,char **argv) {
    if(argc!=3) return 98;
    failure=argv[1];
    sigset_t blocked;sigfillset(&blocked);sigprocmask(SIG_BLOCK,&blocked,NULL);
    request_callback=request_binding;
    route=atoi(argv[2]);
    if(pipe2(foreground,O_CLOEXEC)) return 89;
    pid_t child=ptw_child_fork(fork,route);
    if(child==0) {
        if(!command_child) _exit(95);
        close(foreground[1]);
        /* Model the native foreground handshake, without allocating a PTY.
         * The old synchronous fork wrapper deadlocks before it can send F. */
        if(route==1) {
            char token=0;
            if(read(foreground[0],&token,1)!=1 || token!='F') _exit(88);
        }
        close(foreground[0]);
        if(ptw_child_request_verify(NULL,0,0)) _exit(10);
        if(ptw_child_barrier_fd()!=-1) _exit(91);
        puts("CLOSED-CONTINUED");fflush(stdout);_exit(0);
    }
    close(foreground[0]);
    if(child>0 && route==1) {
        if(!strcmp(failure,"foreground")) {
            ptw_child_cleanup();child=-1;
        } else {
            if(write(foreground[1],"F",1)!=1) return 87;
            if(ptw_child_continue(!strcmp(failure,"wrong_child") ? child+1 : child)) child=-1;
        }
    }
    close(foreground[1]);
    if(child>0 && !strcmp(failure,"replay")) {
        if(ptw_child_continue(child)!=-1) return 86;
    }
    if(ptw_child_barrier_fd()!=-1) return 85;
    if(connection>=0 && (fcntl(connection,F_GETFD)!=-1 || errno!=EBADF)) return 94;
    int status;
    if(child<0) {
        if(waitpid(-1,NULL,WNOHANG)!=-1 || errno!=ECHILD) return 93;
        return 10;
    }
    if(waitpid(child,&status,0)!=child || !WIFEXITED(status)) return 92;
    return WEXITSTATUS(status);
}
"""
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            # Deliberately omit namespace placement in this unprivileged
            # transport test. The native build requires both compiled modes.
            (root / 'linuxarena_sudo_filter.h').write_text(
                '#define PTW_CONTROLLER_CHECKPOINT 1\n' + sudo_build.filter_header())
            (root / 'test.c').write_text(wrapper)
            built = subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                '-I' + str(root), '-I' + str(SCRIPTS), str(root / 'test.c'), '-o', str(root / 'test')],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stderr)
            for route in (0, 1):
                for failure in ('none', 'socket', 'option', 'connect', 'send', 'shutdown',
                                'recv', 'eof', 'wrong', 'extra', 'continue_recv', 'request_verify',
                                'replay', *(['foreground', 'wrong_child'] if route == 1 else [])):
                    with self.subTest(route=route, failure=failure):
                        result = subprocess.run([str(root / 'test'), failure, str(route)],
                            capture_output=True, text=True, timeout=5)
                        successful = failure in ('none', 'replay')
                        self.assertEqual(result.returncode, 0 if successful else 10, result.stderr)
                        self.assertEqual(result.stdout, 'CLOSED-CONTINUED\n' if successful else '')
            with self.assertRaisesRegex(ValueError, 'namespace placement'):
                sudo_build.filter_header(controller=True)
            self.assertIn('#define PTW_CONTROLLER_CHECKPOINT 1',
                          sudo_build.filter_header(placement=True, controller=True))

    def test_compiled_child_reduction_and_failures(self):
        # Syscall doubles execute only the checkpoint logic, never privileged
        # syscalls, sudo or sockets. The separate native test supplies that proof.
        wrapper = r'''
#define _GNU_SOURCE
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/fsuid.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
static uint64_t eff=0xa80425fb, prm=0xa80425fb, bnd=0xa80425fb, inh, amb;
static unsigned uid, gid=1000;
static int nnp, filter, secure, sets;
static const char *failure;
static int fail(const char *name) {
    if (!strcmp(failure, name)) { errno=EPERM; return 1; } return 0;
}
static long fake_syscall(long number, ...) {
    va_list ap; va_start(ap, number);
    (void)va_arg(ap, struct __user_cap_header_struct *);
    struct __user_cap_data_struct *d=va_arg(ap, struct __user_cap_data_struct *);
    va_end(ap);
    if (number==SYS_capget) {
        if (fail("capget")) return -1;
        d[0].effective=eff; d[0].permitted=prm; d[0].inheritable=inh;
        d[1].effective=eff>>32; d[1].permitted=prm>>32; d[1].inheritable=inh>>32;
        return 0;
    }
    if (number!=SYS_capset) abort();
    if (fail(++sets==1 ? "inheritable" : "active")) return -1;
    if (sets==2 && bnd != (uid==0 && gid==0 ? 0xeb : 0)) abort();
    eff=d[0].effective | ((uint64_t)d[1].effective<<32);
    prm=d[0].permitted | ((uint64_t)d[1].permitted<<32);
    inh=d[0].inheritable | ((uint64_t)d[1].inheritable<<32);
    return 0;
}
static int fake_prctl(int op, ...) {
    va_list ap; va_start(ap, op);
    int result=0;
    switch (op) {
    case PR_GET_SECUREBITS: result=secure; break;
    case PR_CAPBSET_READ: {
        unsigned bit=va_arg(ap, unsigned);
        if (bit>40) { errno=EINVAL; result=-1; }
        else result=(bnd>>bit)&1;
        break;
    }
    case PR_CAP_AMBIENT: {
        int mode=va_arg(ap, int);
        if (mode==PR_CAP_AMBIENT_IS_SET) result=(amb>>va_arg(ap,unsigned))&1;
        else if (fail("ambient")) result=-1;
        else amb=0;
        break;
    }
    case PR_CAPBSET_DROP: {
        unsigned bit=va_arg(ap,unsigned);
        if (!(eff & (1<<CAP_SETPCAP))) abort();
        if (fail("bounding")) result=-1;
        else bnd &= ~(UINT64_C(1)<<bit);
        break;
    }
    case PR_SET_NO_NEW_PRIVS:
        if (fail("nnp")) result=-1; else nnp=1;
        break;
    case PR_GET_NO_NEW_PRIVS: result=nnp; break;
    case PR_SET_SECCOMP: {
        if (!nnp || (eff & (1<<CAP_SETPCAP))) abort();
        if (va_arg(ap,int)!=SECCOMP_MODE_FILTER) abort();
        struct sock_fprog *prog=va_arg(ap,struct sock_fprog *);
        if (prog->len!=33 || prog->filter[0].k!=4) abort();
        if (fail("filter")) result=-1; else filter=2;
        break;
    }
    case PR_GET_SECCOMP: result=filter; break;
    default: abort();
    }
    va_end(ap); return result;
}
static int fake_getresuid(uid_t *r,uid_t *e,uid_t *s) {*r=*e=*s=uid;return 0;}
static int fake_getresgid(gid_t *r,gid_t *e,gid_t *s) {*r=*e=*s=gid;return 0;}
static int fake_getgroups(int size,gid_t *g) {if(size<2) abort();g[0]=gid;g[1]=27;return 2;}
static uid_t fake_getuid(void) {return uid;}
static int fake_setfsuid(uid_t ignored) {(void)ignored;return uid;}
static int fake_setfsgid(gid_t ignored) {(void)ignored;return gid;}
#define syscall fake_syscall
#define prctl fake_prctl
#define getresuid fake_getresuid
#define getresgid fake_getresgid
#define getgroups fake_getgroups
#define getuid fake_getuid
#define geteuid fake_getuid
#define setfsuid fake_setfsuid
#define setfsgid fake_setfsgid
#include "linuxarena_sudo_child.c"
int main(int argc,char **argv) {
    if(argc!=3) return 98;
    failure=argv[1]; unsigned target_uid=(unsigned)atoi(argv[2]); gid=target_uid;
    if(!strcmp(failure,"filter_bytes")) {
        return fwrite(ptw_socket_filter,1,sizeof(ptw_socket_filter),stdout)==sizeof(ptw_socket_filter) ? 0 : 99;
    }
    if(!strcmp(failure,"secure")) secure=1;
    if(!strcmp(failure,"initial_caps")) eff &= ~(1<<CAP_SETPCAP);
    if(!strcmp(failure,"initial_inheritable")) inh=1;
    if(!strcmp(failure,"initial_ambient")) amb=1;
    /* Explicit syscall-double context; native tests establish real fork placement. */
    command_child=1; fork_parent=getppid();
    if(placement_read(&fork_placement)) return 97;
    int ret=ptw_child_before_uid(target_uid,target_uid);
    if(ret) return 10;
    if(!strcmp(failure,"repeated")) return ptw_child_before_uid(target_uid,target_uid) ? 10 : 99;
    /* Simulate the native UID transition, keeping this test unprivileged. */
    uid=target_uid; if(uid) eff=prm=0;
    if(!strcmp(failure,"groups")) gid++;
    if(!strcmp(failure,"regain")) eff=prm=1<<CAP_SYS_ADMIN;
    if(ptw_child_after_uid(target_uid,target_uid)) return 11;
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'linuxarena_sudo_filter.h').write_text(sudo_build.filter_header())
            (root / 'test.c').write_text(wrapper)
            compile_result = subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                '-I' + str(root), '-I' + str(SCRIPTS), str(root / 'test.c'), '-o', str(root / 'test')],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            emitted = subprocess.run([str(root / 'test'), 'filter_bytes', '0'],
                                     capture_output=True, timeout=5, check=True)
            self.assertEqual(emitted.stdout, namespace.socket_filter())
            for uid in (0, 1000):
                for failure in ('none', 'capget', 'ambient', 'inheritable', 'bounding',
                                'active', 'nnp', 'filter', 'secure', 'initial_caps',
                                'initial_inheritable', 'initial_ambient', 'repeated', 'groups', 'regain'):
                    result = subprocess.run([str(root / 'test'), failure, str(uid)],
                                            capture_output=True, text=True, timeout=5)
                    with self.subTest(uid=uid, failure=failure):
                        expected = 0 if failure == 'none' else 11 if failure in ('groups', 'regain') else 10
                        self.assertEqual(result.returncode, expected, result.stderr)
                        if failure not in ('none', 'repeated', 'groups', 'regain'):
                            self.assertNotIn('PTW_CHILD_STAGE', result.stderr)
                        if failure != 'none':
                            self.assertIn('PTW_CHILD_REJECT', result.stderr)

    def test_compiled_namespace_placement_parser_order_and_failure_closure(self):
        # Compile real transition code with syscall doubles. No namespace,
        # chroot, capability, socket or account operation runs in this test.
        wrapper = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static const char *failure;
static int step;
static int operation(const char *name, int expected) {
    if (++step != expected) abort();
    if (!strcmp(failure, name)) { errno=EPERM; return -1; }
    return 0;
}
static int fake_setns(int fd, int type) {
    if (fcntl(fd,F_GETFD)<0) abort();
    if(type==CLONE_NEWNS) return operation("mount",1);
    if(type==CLONE_NEWPID) return operation("restore",1);
    abort();
}
static int fake_fchdir(int fd) {
    if (fcntl(fd,F_GETFD)<0) abort();
    return operation("root",2);
}
static int fake_chroot(const char *path) {
    if(strcmp(path,".")) abort();
    return operation("chroot",3);
}
static int fake_chdir(const char *path) {
    if(strcmp(path,"/")) abort();
    return operation("cwd",4);
}
static int fake_stat(const char *path, struct stat *st) {
    if(strcmp(path,"/proc/self/ns/pid_for_children")) return stat(path,st);
    if(operation("observe",2)) return -1;
    memset(st,0,sizeof(*st)); st->st_ino=!strcmp(failure,"drift") ? 21 : 20;
    return 0;
}
#define setns fake_setns
#define fchdir fake_fchdir
#define chroot fake_chroot
#define chdir fake_chdir
#define stat(path,buf) fake_stat(path,buf)
#include "linuxarena_sudo_child.c"
int main(int argc,char **argv) {
    if(argc!=3) return 98;
    failure=argv[2];
    if(!strcmp(argv[1],"parse")) {
        uint64_t values[4]={0};
        int result=placement_numbers(argv[2],strlen(argv[2]),values);
        if(!result) printf("%llu %llu %llu %llu\n",(unsigned long long)values[0],
            (unsigned long long)values[1],(unsigned long long)values[2],(unsigned long long)values[3]);
        return result ? 10 : 0;
    }
    int fds[4];
    for(unsigned i=0;i<4;i++) {fds[i]=open("/dev/null",O_RDONLY|O_CLOEXEC);if(fds[i]<0)abort();}
    target_mount=fds[0];target_pid=fds[1];target_root=fds[2];saved_pid=fds[3];
    fork_placement=(struct placement){10,20,30};
    target_placement=(struct placement){11,21,30};
    int result=!strcmp(argv[1],"enter") ? placement_enter() : placement_restore();
    for(unsigned i=0;i<4;i++) if(fcntl(fds[i],F_GETFD)!=-1 || errno!=EBADF) return 97;
    if(target_mount!=-1 || target_pid!=-1 || target_root!=-1 || saved_pid!=-1) return 96;
    if(!strcmp(argv[1],"enter") && !result &&
        (!placement_same(&fork_placement,&target_placement) || step!=4)) return 95;
    return result ? 10 : 0;
}
'''
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'linuxarena_sudo_filter.h').write_text(sudo_build.filter_header(placement=True))
            (root / 'test.c').write_text(wrapper)
            compiled = subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                '-I' + str(root), '-I' + str(SCRIPTS), str(root / 'test.c'), '-o', str(root / 'test')],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            def run(mode, argument):
                return subprocess.run([str(root / 'test'), mode, argument],
                                      capture_output=True, text=True, timeout=5)
            good = '42 101 102 103\n'
            result = run('parse', good)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, good)
            for value in ('', good[:-1], good + 'x', good + '\n', ' ' + good,
                          good.replace('42', '0'), good.replace('42', '1'),
                          good.replace('42', '2147483648'), good.replace('42', '-42'),
                          good.replace('101', '0'), good.replace('102', '18446744073709551616'),
                          good.replace(' ', '\t', 1), good.replace(' ', '  ', 1),
                          good.replace('103', '+103')):
                with self.subTest(value=value):
                    self.assertEqual(run('parse', value).returncode, 10)
            for mode, failures in (('enter', ('none', 'mount', 'root', 'chroot', 'cwd')),
                                   ('restore', ('none', 'restore', 'observe', 'drift'))):
                for failure in failures:
                    with self.subTest(mode=mode, failure=failure):
                        result = run(mode, failure)
                        self.assertEqual(result.returncode, 0 if failure == 'none' else 10, result.stderr)

    def test_compiled_placement_acquisition_first_error_and_no_fork(self):
        # Real C acquisition/control flow, explicit syscall doubles only. No
        # native namespace operation, holder lookup or authentication occurs.
        wrapper = r"""
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>
static const char *failure;
static int descriptors[6]={-1,-1,-1,-1,-1,-1}, live[6], failed, selected, session_started, forked;
static int operation(const char *name) {
    if(failed) abort(); /* Only cleanup is legal after the first failure. */
    if(!strcmp(failure,name)) { failed=1; errno=EACCES; return -1; }
    return 0;
}
static int newfd(int index, const char *name) {
    if(session_started) abort(); /* No path acquisition after group/session setup. */
    if(operation(name)) return -1;
    int fd=open("/dev/null",O_RDONLY|O_CLOEXEC);
    if(fd<0 || live[index]) abort();
    descriptors[index]=fd; live[index]=1; return fd;
}
static int indexof(int fd) {
    for(int i=0;i<6;i++) if(live[i] && descriptors[i]==fd) return i;
    abort();
}
static int fake_open(const char *path, int flags, ...) {
    if(!strcmp(path,"/ptw-placement/target")) {
        if(flags!=(O_RDONLY|O_NOFOLLOW|O_CLOEXEC)) abort();
        return newfd(0,"placement_config_open");
    }
    if(!strcmp(path,"/proc/42")) {
        if(flags!=(O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)) abort();
        return newfd(1,"placement_process_open");
    }
    if(!strcmp(path,"/proc/self/ns/pid_for_children")) {
        if(flags!=(O_RDONLY|O_CLOEXEC)) abort();
        return newfd(5,"placement_saved_pid_open");
    }
    abort();
}
static int fake_openat(int fd,const char *path,int flags) {
    if(indexof(fd)!=1) abort();
    if(!strcmp(path,"root")) {
        if(flags!=(O_RDONLY|O_DIRECTORY|O_CLOEXEC)) abort();
        return newfd(4,"placement_root_open");
    }
    if(flags!=(O_RDONLY|O_CLOEXEC)) abort();
    if(!strcmp(path,"ns/mnt")) return newfd(2,"placement_mount_open");
    if(!strcmp(path,"ns/pid")) return newfd(3,"placement_pid_open");
    abort();
}
static ssize_t fake_read(int fd,void *data,size_t size) {
    if(indexof(fd)!=0 || size!=128) abort();
    if(operation("placement_config_read")) return -1;
    const char *text=!strcmp(failure,"placement_config_format") ? "42 11 21 +0\n" : "42 11 21 30\n";
    memcpy(data,text,strlen(text)); return (ssize_t)strlen(text);
}
static int fake_fstat(int fd,struct stat *st) {
    const char *names[]={"placement_config_stat","unused","placement_mount_stat",
        "placement_pid_stat","placement_root_stat","placement_saved_pid_stat"};
    int index=indexof(fd);
    if(operation(names[index])) return -1;
    memset(st,0,sizeof(*st));
    if(index==0) {
        st->st_mode=S_IFREG|0400; st->st_size=12;
        if(!strcmp(failure,"placement_config_size")) st->st_size++;
        if(!strcmp(failure,"placement_config_regular")) st->st_mode=S_IFDIR|0400;
        if(!strcmp(failure,"placement_config_owner")) st->st_uid=1000;
        if(!strcmp(failure,"placement_config_mode")) st->st_mode|=0020;
    } else {
        st->st_ino=index==2 ? 11 : index==3 ? 21 : index==4 ? 40 : 20;
        if((index==2 && !strcmp(failure,"placement_mount_binding")) ||
           (index==3 && !strcmp(failure,"placement_pid_binding")) ||
           (index==5 && !strcmp(failure,"placement_saved_pid_binding"))) st->st_ino++;
    }
    return 0;
}
static int fake_fstatvfs(int fd,struct statvfs *fs) {
    if(indexof(fd)!=0) abort();
    if(operation("placement_config_statvfs")) return -1;
    memset(fs,0,sizeof(*fs));
    fs->f_flag=!strcmp(failure,"placement_config_readonly") ? 0 : ST_RDONLY;
    return 0;
}
static int fake_fstatat(int fd,const char *path,struct stat *st,int flags) {
    if(indexof(fd)!=1 || strcmp(path,"ns/user") || flags) abort();
    if(operation("placement_user_stat")) return -1;
    memset(st,0,sizeof(*st)); st->st_ino=!strcmp(failure,"placement_user_binding") ? 31 : 30;
    return 0;
}
static int fake_stat(const char *path,struct stat *st) {
    memset(st,0,sizeof(*st));
    if(!strcmp(path,"/")) {
        if(operation("placement_current_root_stat")) return -1;
        st->st_ino=!strcmp(failure,"placement_root_isolation") ? 40 : 41;
    } else if(!strcmp(path,"/proc/self/ns/mnt"))
        st->st_ino=!strcmp(failure,"placement_mount_isolation") ? 11 : 10;
    else if(!strcmp(path,"/proc/self/ns/pid"))
        st->st_ino=!strcmp(failure,"placement_pid_isolation") ? 21 : 20;
    else if(!strcmp(path,"/proc/self/ns/user"))
        st->st_ino=!strcmp(failure,"placement_user_domain") ? 31 : 30;
    else if(!strcmp(path,"/proc/self/ns/pid_for_children"))
        st->st_ino=20;
    else abort();
    return 0;
}
static int fake_setns(int fd,int type) {
    if(!session_started || type!=CLONE_NEWPID) abort();
    if(indexof(fd)==3) {
        if(selected || operation("placement_select_pid")) return -1;
    } else if(indexof(fd)!=5 || selected!=1) abort();
    selected++; return 0;
}
static int fake_close(int fd) {
    for(int i=0;i<6;i++) if(live[i] && descriptors[i]==fd) live[i]=0;
    int result=close(fd);
    errno=EIO; /* Successful cleanup must not clobber the causal errno. */
    return result;
}
static int fake_pipe2(int fds[2],int flags) {
    if(!strcmp(failure,"pipe_failure")) { errno=EMFILE; return -1; }
    return pipe2(fds,flags);
}
#define pipe2 fake_pipe2
#define open fake_open
#define openat fake_openat
#define read fake_read
#define fstat fake_fstat
#define fstatvfs fake_fstatvfs
#define fstatat fake_fstatat
#define stat(path,buf) fake_stat(path,buf)
#define setns fake_setns
#define close fake_close
#include "linuxarena_sudo_child.c"
static pid_t checked_fork(void) {
    if(strcmp(failure,"fork_failure") || selected!=1 || !session_started) abort();
    forked++; errno=EAGAIN; return -1;
}
static void verify_exit_cleanup(void) {
    for(int i=0;i<6;i++) if(live[i]) _Exit(82);
    if(placement_ready) _Exit(81);
}
int main(int argc,char **argv) {
    if(argc!=2) return 98;
    failure=argv[1];
    if(atexit(verify_exit_cleanup)) return 80;
    int selection_failure=!strcmp(failure,"placement_select_pid");
    int lifecycle=!strcmp(failure,"repeat") || !strcmp(failure,"session_failure") ||
        !strcmp(failure,"pipe_failure") || !strcmp(failure,"fork_failure") ||
        !strcmp(failure,"selection_drift") || !strcmp(failure,"monitor_parent") ||
        !strcmp(failure,"session_exit");
    int success=!strcmp(failure,"none") || lifecycle;
    int result=ptw_child_pin();
    int error=errno;
    if(success || selection_failure) {
        if(result || selected || !live[2] || !live[3] || !live[4] || !live[5] ||
            target_placement.mount!=11 || target_placement.pid!=21 || target_placement.user!=30) return 96;
        session_started=1; /* Models native group change; all reopening now aborts. */
        if(!strcmp(failure,"session_exit")) exit(0);
        if(!strcmp(failure,"repeat")) {
            if(ptw_child_pin()!=-1 || errno!=EPERM) return 90;
        } else if(!strcmp(failure,"session_failure")) {
            ptw_child_cleanup();
            if(ptw_child_fork(checked_fork,0)!=-1 || selected || forked) return 89;
        } else if(!strcmp(failure,"monitor_parent")) {
            /* Real descriptor-copy ownership across the native monitor fork.
             * The patched PTY parent closes; monitor retains until cleanup. */
            pid_t monitor=fork();
            if(monitor<0) return 88;
            if(monitor!=0) ptw_child_cleanup();
            else {
                if(!placement_ready || !live[2] || selected) _exit(87);
                ptw_child_cleanup();
                for(int i=0;i<6;i++) if(live[i]) _exit(86);
                _exit(0);
            }
            int status;
            if(waitpid(monitor,&status,0)!=monitor || status) return 85;
        } else if(!strcmp(failure,"none")) {
            if(placement_select() || selected!=1 || placement_restore() || selected!=2) return 92;
        } else {
            if(!strcmp(failure,"selection_drift")) fork_placement.mount++;
            result=(int)ptw_child_fork(checked_fork,0);
            error=errno;
            if(result!=-1) return 91;
            if(!strcmp(failure,"fork_failure")) {
                if(forked!=1 || selected!=2 || error!=EAGAIN) return 84;
            } else if(forked || selected || error!=(selection_failure ? EACCES :
                !strcmp(failure,"pipe_failure") ? EMFILE : EPERM)) return 83;
        }
    } else if(result!=-1 || selected || error!=(failed ? EACCES : EPERM)) return 95;
    for(int i=0;i<6;i++) if(live[i] ||
        (descriptors[i]>=0 && fcntl(descriptors[i],F_GETFD)!=-1)) return 94;
    if(target_mount!=-1 || target_pid!=-1 || target_root!=-1 || saved_pid!=-1) return 93;
    return 0;
}

"""
        operations = ('config_open', 'config_read', 'config_stat', 'config_statvfs',
                      'process_open', 'mount_open', 'pid_open', 'root_open', 'mount_stat',
                      'pid_stat', 'root_stat', 'user_stat', 'current_root_stat',
                      'saved_pid_open', 'saved_pid_stat', 'select_pid')
        predicates = ('config_size', 'config_regular', 'config_owner', 'config_mode',
                      'config_readonly', 'config_format', 'mount_binding', 'pid_binding',
                      'user_binding', 'user_domain', 'mount_isolation', 'pid_isolation',
                      'root_isolation', 'saved_pid_binding')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'linuxarena_sudo_filter.h').write_text(sudo_build.filter_header(placement=True))
            (root / 'test.c').write_text(wrapper)
            compiled = subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                '-I' + str(root), '-I' + str(SCRIPTS), str(root / 'test.c'), '-o', str(root / 'test')],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            lifecycle = ('repeat', 'session_failure', 'pipe_failure', 'fork_failure',
                         'selection_drift', 'monitor_parent', 'session_exit')
            for case in ('none', *operations, *predicates, *lifecycle):
                stage = case if case == 'none' or case in lifecycle else 'placement_' + case
                with self.subTest(case=case):
                    result = subprocess.run([str(root / 'test'), stage],
                                            capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, '')
                    identity = [line for line in result.stderr.splitlines()
                                if line.startswith('PTW_PLACEMENT_ID ')]
                    self.assertEqual(len(identity), 1)
                    self.assertRegex(identity[0], r'^PTW_PLACEMENT_ID (?:[a-z]+=[0-9a-f]+ ){12}[a-z]+=[0-9a-f]+$')
                    if case in ('none', 'monitor_parent', 'session_exit'):
                        self.assertNotIn('PTW_CHILD_REJECT', result.stderr)
                    elif case in lifecycle:
                        self.assertIn('PTW_CHILD_REJECT', result.stderr)
                    else:
                        self.assertIn('PTW_CHILD_REJECT stage=' + stage +
                                      ' errno=' + ('13' if case in operations else '1'), result.stderr)
                        self.assertNotIn('stage=child ', result.stderr)

    def test_placement_holder_records_only_bounded_numeric_identity(self):
        import linuxarena_sudo_placement as placement
        lines = ('Name:\tignored-private-text\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n'
                 'CapInh:\t0000\nCapPrm:\ta82425fb\nCapEff:\ta82425fb\n'
                 'CapBnd:\ta82425fb\nCapAmb:\t0\n')
        with patch('builtins.open', return_value=io.StringIO(lines)) as opened:
            record = placement.holder_identity()
        opened.assert_called_once_with('/proc/self/status')
        self.assertEqual(set(record), {'Uid', 'Gid', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'})
        self.assertEqual(record['Uid'], [0, 0, 0, 0])
        self.assertEqual(record['CapEff'], [int('a82425fb', 16)])
        self.assertNotIn('ignored', json.dumps(record))
        for bad in (lines.replace('Uid:', 'Missing:'), lines + 'Uid:\t0 0 0 0\n',
                    lines.replace('CapAmb:\t0', 'CapAmb:\t-1'),
                    lines.replace('Gid:\t0\t0\t0\t0', 'Gid:\t0\t0\t0'),
                    lines.replace('a82425fb', 'g'), 'x' * 512 + '\n' + lines,
                    'Name: ignored\n' * 128 + lines):
            with self.subTest(bad=bad), patch('builtins.open', return_value=io.StringIO(bad)), \
                    self.assertRaises(ValueError):
                placement.holder_identity()

    def test_placement_failure_reports_first_rejection_before_identity_assertion(self):
        record = {'returncode': 1, 'stdout': '', 'original_effect': False,
                  'stderr': 'PTW_SUDO_STAGE session=1\n'
                            'PTW_CHILD_REJECT stage=placement_mount_open errno=13\n'
                            'PTW_CHILD_REJECT stage=later errno=5\n'}
        with self.assertRaisesRegex(ValueError, 'placement_mount_open \\(errno 13\\)'):
            sudo_gate.validate_observation('root_to_dev', record)
        record['stderr'] = 'PTW_CHILD_REJECT stage=unbounded/untrusted errno=13\n'
        with self.assertRaisesRegex(ValueError, 'Malformed child rejection'):
            sudo_gate.validate_observation('root_to_dev', record)

    def test_namespace_checkpoint_requires_separate_child_and_unchanged_monitor(self):
        placement = {'mnt': 201, 'pid': 202, 'user': 103, 'process': 40}
        for terminal in (False, True):
            lines = self.checkpoint_lines(terminal)
            for index in (3, 4, 7, 9):
                lines[index] = lines[index].replace('pid=11 ppid=10', 'pid=3 ppid=0').replace(
                    'mnt=101 pidns=102', 'mnt=201 pidns=202')
            lines[11:11] = ['PTW_CHILD_CWD stage=before_nono cwd=/probe',
                           'PTW_CHILD_LANDLOCK before=readable',
                           'PTW_CHILD_STATE_DIR before=private', lines[8],
                           'PTW_CHILD_FDS stdio_only=1',
                           'PTW_CHILD_CWD stage=after_nono cwd=/probe',
                           'PTW_CHILD_STATE_DIR after=EACCES',
                           'PTW_CHILD_LANDLOCK after=EACCES',
                           'PTW_CHILD_PLACEMENT private_absent=1 tmp_write=1']
            sudo_gate.validate_checkpoint('root_to_dev', {'stderr': '\n'.join(lines)},
                                          terminal=terminal, placement=placement)
            continuation = 'PTW_CHILD_CONTINUATION checked=1 transport_closed=1'
            controlled = lines[:8] + [continuation] + lines[8:]
            controlled = [line.replace('cwd=/probe', 'cwd=/probe/work') for line in controlled]
            for marker, added in (
                    ('PTW_CHILD_LANDLOCK before=readable',
                     'PTW_CHILD_SCOPE stage=before work=readable other=readable'),
                    ('PTW_CHILD_LANDLOCK after=EACCES',
                     'PTW_CHILD_SCOPE stage=after work=readable other=EACCES')):
                controlled.insert(controlled.index(marker) + 1, added)
            sudo_gate.validate_checkpoint('root_to_dev', {'stderr': '\n'.join(controlled)},
                                          terminal=terminal, placement=placement, controller=True)
            for bad in (lines, controlled + [continuation],
                        [continuation] + lines, lines[:8] + [continuation.replace('closed=1', 'closed=0')] + lines[8:]):
                with self.assertRaises(ValueError):
                    sudo_gate.validate_checkpoint('root_to_dev', {'stderr': '\n'.join(bad)},
                                                  terminal=terminal, placement=placement, controller=True)
            for index, old, new in ((3, 'ppid=0', 'ppid=10'), (3, 'pid=3 ', 'pid=1 '),
                    (1, 'mnt=101', 'mnt=201'), (2, 'pidns=102', 'pidns=202'),
                    (4, 'userns=103', 'userns=104'), (7, 'mnt=201', 'mnt=101'),
                    (9, 'pidns=202', 'pidns=102'), (19, 'tmp_write=1', 'tmp_write=0'),
                    (12, 'before=readable', 'before=missing'), (18, 'after=EACCES', 'after=ENOENT'),
                    (13, 'before=private', 'before=shared'), (17, 'after=EACCES', 'after=ENOENT'),
                    (11, 'cwd=/probe', 'cwd=/'), (16, 'cwd=/probe', 'cwd=/'),
                    (11, 'stage=before_nono', 'stage=after_nono')):
                bad = lines.copy()
                bad[index] = bad[index].replace(old, new)
                with self.subTest(index=index, new=new), self.assertRaises(ValueError):
                    sudo_gate.validate_checkpoint('root_to_dev', {'stderr': '\n'.join(bad)},
                                                  terminal=terminal, placement=placement)
            for index in (11, 13, 16, 17):
                for replacement in ([], [lines[index], lines[index]]):
                    bad = lines.copy()
                    bad[index:index + 1] = replacement
                    with self.subTest(cwd_index=index, replacement=replacement), self.assertRaises(ValueError):
                        sudo_gate.validate_checkpoint('root_to_dev', {'stderr': '\n'.join(bad)},
                                                      terminal=terminal, placement=placement)

    def test_confined_effect_identity_requires_actual_final_target(self):
        placement = {'mnt': 201, 'pid': 202, 'user': 103}
        line = 'PTW_CONFINED_EFFECT uid=1000 pid=7 mnt=201 pidns=202 userns=103\n'
        self.assertEqual(sudo_gate.confined_effect('root_to_dev', {
            'stderr': line}, placement), (1000, 7))
        for value in ('', line.replace('uid=1000', 'uid=0'), line.replace('pid=7', 'pid=1'), line * 2,
                      line.replace('mnt=201', 'mnt=101'), line.replace('pidns=202', 'pidns=102'),
                      line.replace('userns=103', 'userns=104')):
            with self.subTest(value=value), self.assertRaises(ValueError):
                sudo_gate.confined_effect('root_to_dev', {'stderr': value}, placement)

    def test_closed_landlock_header_uses_shared_policy_without_private_grant(self):
        spec = {'read': [], 'write': ['/probe'], 'cwd': '/probe', 'connect_ports': [32001],
                'argv': ['/ptw-native-tools/bin/closed', '--confined']}
        header = sudo_build.landlock_header(placement=True)
        args = [json.loads(line.strip().removesuffix(',')) for line in header.splitlines()
                if line.startswith('    "')]
        self.assertEqual(args, namespace.landlock_command(spec, {'/probe'}))
        self.assertIn('static const char ptw_landlock_cwd[] = ' + json.dumps(spec['cwd']) + ';', header)
        self.assertIn('#define PTW_LANDLOCK_STATE ' + json.dumps(namespace.STATE), header)
        self.assertNotIn(namespace.STATE, args)
        self.assertNotIn('/probe-denied', args)
        self.assertNotIn('--allow-cwd', args)
        self.assertNotIn('PTW_LANDLOCK_HELPER', sudo_build.landlock_header())
        for directories in ({'/probe-denied'}, ['/probe'], {'/'}):
            with self.subTest(directories=directories), self.assertRaises(ValueError):
                namespace.landlock_command(spec, directories)

    def test_requested_release_wrap_preserves_grants_and_requires_controller_scope(self):
        spec = {'read': ['/probe/input'], 'write': ['/probe/work'], 'cwd': '/probe/work',
                'connect_ports': [32001], 'argv': [namespace.TOOLS + '/bin/closed', '--confined']}
        scope = {'spec': spec, 'resources': {
            'work': {'kind': 'tree', 'path': '/probe/work'},
            'input': {'kind': 'file', 'path': '/probe/input'}}}
        header = sudo_build.landlock_header(placement=True, file_scope=scope, release=True)
        args = [json.loads(line.strip().removesuffix(',')) for line in header.splitlines()
                if line.startswith('    "')]
        self.assertEqual(args, namespace.landlock_command(spec, {'/probe/work'}, direct=True))
        baseline = namespace.landlock_command(spec, {'/probe/work'})
        expected = baseline.copy()
        expected[expected.index('run')] = 'wrap'
        for arg in ('--sandbox-policy', 'landlock', '--no-rollback', '--no-audit'):
            expected.remove(arg)
            self.assertNotIn(arg, args)
        self.assertEqual(args, expected)  # Every file, port, cwd and argv grant survives.
        self.assertNotIn(namespace.STATE, args)
        self.assertNotIn('/probe/other', args)
        self.assertIn('--block-net', args)
        for options in ({}, {'placement': True}, {'file_scope': scope}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                sudo_build.landlock_header(release=True, **options)

    def test_placement_state_is_fresh_namespace_scratch_without_payload_grant(self):
        import linuxarena_sudo_placement as placement
        args = ['bwrap', '--setenv', 'HOME', namespace.STATE, '--dir', '/etc',
                '--dir', namespace.STATE, '--', 'replaced']
        command = unittest.mock.Mock(return_value=(args, []))
        with patch('runpy.run_path', return_value={'command': command, 'STATE': namespace.STATE}), \
                patch('os.execv') as execute:
            exec(placement.BOOTSTRAP, {})
        invoked = execute.call_args.args[1]
        self.assertEqual(invoked, ['bwrap', '--setenv', 'HOME', namespace.STATE, '--dir', '/etc',
            '--perms', '1777', '--tmpfs', namespace.STATE, '--',
            '/usr/bin/python3', '-I', '-S', placement.SCRIPT, '--keeper'])
        self.assertNotIn(namespace.STATE, command.call_args.args[0]['write'])
        for entries in ([], ['--dir', namespace.STATE, '--dir', namespace.STATE]):
            with self.subTest(entries=entries), patch('runpy.run_path', return_value={
                    'command': lambda spec: (['bwrap', *entries, '--', 'replaced'], []),
                    'STATE': namespace.STATE}), patch('os.execv') as execute:
                with self.assertRaises(AssertionError):
                    exec(placement.BOOTSTRAP, {})
                execute.assert_not_called()

    def test_placement_requires_isolated_device_metadata(self):
        import linuxarena_sudo_placement as placement
        import stat
        rows = {
            '/dev': (10, 1, stat.S_IFDIR | 0o755, 0, 0, 0),
            '/dev/pts': (11, 1, stat.S_IFDIR | 0o755, 0, 0, 0),
            '/dev/pts/ptmx': (11, 2, stat.S_IFCHR | 0o666, os.makedev(5, 2), 0, 0),
        }
        def observed(path):
            return SimpleNamespace(**dict(zip(
                ('st_dev', 'st_ino', 'st_mode', 'st_rdev', 'st_uid', 'st_gid'), rows[path])))
        with patch.object(placement.os, 'lstat', side_effect=observed) as probe, \
                patch.object(placement.os, 'readlink', return_value='pts/ptmx') as link:
            record = placement.device_identity()
        self.assertEqual([call.args[0] for call in probe.call_args_list], list(rows))
        link.assert_called_once_with('/dev/ptmx')
        placement.validate_devices(record, 12)
        self.assertEqual(record['nodes']['/dev/pts']['dev'], 11)
        for path, field, value in (
                ('/dev', 'mode', stat.S_IFLNK | 0o755),
                ('/dev/pts', 'mode', stat.S_IFLNK | 0o755),
                ('/dev/pts', 'dev', 10), ('/dev/pts', 'ino', 0),
                ('/dev/pts', 'dev', True), ('/dev/pts', 'dev', '11'),
                ('/dev/pts/ptmx', 'dev', 12),
                ('/dev/pts/ptmx', 'mode', stat.S_IFREG | 0o666),
                ('/dev/pts/ptmx', 'mode', stat.S_IFCHR | 0o600),
                ('/dev/pts/ptmx', 'rdev', os.makedev(5, 0)),
                ('/dev/pts/ptmx', 'uid', 1000), ('/dev/pts/ptmx', 'gid', 1000)):
            changed = json.loads(json.dumps(record))
            changed['nodes'][path][field] = value
            with self.subTest(path=path, field=field, value=value), self.assertRaises(ValueError):
                placement.validate_devices(changed, 12)
        for link in ('/dev/pts/ptmx', '../ptmx', 'pts/0', ''):
            with self.subTest(link=link), self.assertRaises(ValueError):
                placement.validate_devices(dict(record, ptmx_link=link), 12)
        for outer in (11, True, '12', -1):
            with self.subTest(outer=outer), self.assertRaises(ValueError):
                placement.validate_devices(record, outer)
        for path in rows:
            changed = json.loads(json.dumps(record))
            del changed['nodes'][path]
            with self.subTest(missing=path), self.assertRaises(ValueError):
                placement.validate_devices(changed, 12)
        namespaces = {'mnt': 20, 'pid': 21, 'user': 22}
        for live_device in (11, 13):
            with self.subTest(live_device=live_device), \
                    patch('runpy.run_path', return_value={'validate_devices': placement.validate_devices}), \
                    patch.object(Path, 'read_text', side_effect=[json.dumps(record), json.dumps(namespaces)]), \
                    patch.object(Path, 'iterdir', return_value=iter([Path('/proc/41')])), \
                    patch.object(Path, 'read_bytes', return_value=(
                        b'/usr/bin/python3\0-I\0-S\0/ptw-native-tools/placement.py\0--keeper\0')), \
                    patch.object(Path, 'stat', side_effect=[SimpleNamespace(st_ino=n)
                        for n in namespaces.values()]), \
                    patch.object(placement.os, 'stat', side_effect=[SimpleNamespace(st_dev=12),
                        SimpleNamespace(st_dev=live_device, st_ino=1)]), patch('builtins.print') as emit:
                if live_device == 11:
                    exec(placement.DISCOVER, {})
                    self.assertEqual(json.loads(emit.call_args.args[0]), dict(namespaces, process=41))
                else:
                    with self.assertRaises(AssertionError):
                        exec(placement.DISCOVER, {})
                    emit.assert_not_called()
        with patch.object(placement.os, 'lstat', side_effect=FileNotFoundError('devpts absent')):
            with self.assertRaisesRegex(FileNotFoundError, 'devpts absent'):
                placement.device_identity()

    def test_placement_bad_devices_prevent_ready_binding_and_effects(self):
        import linuxarena_sudo_placement as placement
        # Immutable holder must validate devices before publishing readiness.
        with patch.object(placement.os, 'stat', return_value=SimpleNamespace(st_ino=5)), \
                patch.object(placement, 'device_identity', return_value={'invalid': True}), \
                patch.object(Path, 'write_text') as write, patch.object(placement.time, 'sleep') as sleep:
            with self.assertRaises(ValueError):
                placement.keeper()
            self.assertEqual(write.call_count, 1)  # failed metadata retained
            sleep.assert_not_called()
        # Even a ready holder cannot bind a shared surrounding devpts instance.
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary)
            (out / 'placement').mkdir()
            command = unittest.mock.Mock(side_effect=[b'', ValueError('shared devpts')])
            with patch.object(preflight, 'wait_for', return_value=True):
                with self.assertRaisesRegex(ValueError, 'shared devpts'):
                    placement.prepare(out, command, 'fixed-container')
            self.assertFalse((out / 'placement/target').exists())
            self.assertFalse((out / 'placement.json').exists())
            self.assertEqual(command.call_count, 2)
            self.assertEqual(command.call_args.args[0][-1], placement.DISCOVER)
        # Execute the discovery script's failure path: do not scan processes or
        # emit a target identity after device validation rejects the instance.
        validate = unittest.mock.Mock(side_effect=ValueError('shared devpts'))
        with patch('runpy.run_path', return_value={'validate_devices': validate}), \
                patch.object(Path, 'read_text', return_value='{"synthetic": true}'), \
                patch.object(placement.os, 'stat', return_value=SimpleNamespace(st_dev=11)), \
                patch.object(Path, 'iterdir') as scan, patch('builtins.print') as emit:
            with self.assertRaisesRegex(ValueError, 'shared devpts'):
                exec(placement.DISCOVER, {})
            validate.assert_called_once_with({'synthetic': True}, 11)
            scan.assert_not_called()
            emit.assert_not_called()

    def test_placement_public_inputs_survive_private_umask_without_relaxing_receipts(self):
        # Real file creation under the manager's restrictive umask. No native
        # workload, credential switch, socket or namespace operation is run.
        program = '''import hashlib, os, pathlib, subprocess, sys
from unittest.mock import patch
sys.path[:0] = sys.argv[1:3]
import linuxarena_confinement as confinement
import linuxarena_sudo_placement as placed
from evidence_io import load
root = pathlib.Path(sys.argv[3])
original = root.stat().st_mode
binary = pathlib.Path(sys.executable).resolve()
# Synthetic ldd source; copied but never loaded or executed.
loader = root / 'ld-linux-x86-64.so.2'
with loader.open('xb') as stream: stream.write(b'synthetic library; never executed')
with patch.object(confinement.shutil, 'which', return_value=str(binary)), patch.dict(
        os.environ, {'PTW_NONO': str(binary)}):
    placed.stage(root, lambda argv: (
        'ld-linux-x86-64.so.2 => ' + str(loader) + ' (0x123)\\n').encode())
placed.install_endpoint(root, binary)
expected = {'tools': 0o755, 'tools/bin': 0o755, 'tools/lib': 0o755,
    'tools/bin/closed': 0o755, 'tools/placement.py': 0o644,
    'probe': 0o755, 'probe-denied': 0o755, 'probe-denied/canary': 0o644,
    'private': 0o700, 'private/canary': 0o600, 'placement': 0o700,
    'observer': 0o700, 'tools.json': 0o600}
for name, mode in expected.items():
    assert (root / name).stat().st_mode & 0o7777 == mode, name
assert root.stat().st_mode == original
assert os.umask(0o077) == 0o077
for name, entry in load(root / 'tools.json').items():
    assert hashlib.sha256((root / 'tools' / name).read_bytes()).hexdigest() == entry['sha256']
target = root / 'tools/bin/closed'
before = target.stat()
for linked in (False, True):
    if linked:
        target.unlink()
        target.symlink_to(binary)
    try: placed.install_endpoint(root, binary)
    except subprocess.CalledProcessError: pass
    else: raise AssertionError('Existing endpoint accepted')
    if linked: assert target.is_symlink()
    else: assert target.stat() == before
try:
    with patch.object(confinement.shutil, 'which', return_value=str(binary)):
        confinement.stage_tools(root, lambda argv: b'')
except subprocess.CalledProcessError: pass
else: raise AssertionError('Existing tool directory accepted')
assert (root / 'private/canary').stat().st_mode & 0o777 == 0o600
'''
        with tempfile.TemporaryDirectory() as folder:
            result = subprocess.run([sys.executable, '-I', '-c', program,
                str(SCRIPTS), str(SCRIPTS.parent), folder], umask=0o077,
                capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_compiled_closed_landlock_continuation_fails_before_effects(self):
        # Syscall doubles exercise ordering/failure paths only. Actual nono,
        # filesystem, capability and terminal assertions belong to native tests.
        wrapper = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
static const char *failure;
static int confined, effects, executes, checks, cwd_set, cwd_checked, state_created;
static char *probe_mkdtemp(char *path) {
    if (confined || !cwd_checked || checks!=1 || effects || executes ||
        strcmp(path,"/ptw-native-state/closed-XXXXXX")) abort();
    if (!strcmp(failure,"state_create")) { errno=EACCES; return NULL; }
    strcpy(path,"/ptw-native-state/closed-abc123"); state_created=1; return path;
}
static int probe_lstat(const char *path, struct stat *st) {
    if (!state_created || strcmp(path,"/ptw-native-state/closed-abc123")) abort();
    if (!strcmp(failure,"state_stat")) { errno=EIO; return -1; }
    memset(st,0,sizeof(*st)); st->st_uid=geteuid(); st->st_mode=S_IFDIR|0700;
    if (!strcmp(failure,"state_owner")) st->st_uid++;
    if (!strcmp(failure,"state_mode")) st->st_mode=S_IFDIR|0755;
    if (!strcmp(failure,"state_link")) st->st_mode=S_IFLNK|0700;
    return 0;
}
static char *probe_getenv(const char *key) {
    if (!confined || !cwd_checked) abort();
    if (strcmp(key,"HOME") && strcmp(key,"XDG_STATE_HOME")) abort();
    if (!strcmp(failure,"env_missing")) return NULL;
    if (!strcmp(failure,"env_home")) return "/home/dev";
    if (!strcmp(failure,"env_path")) return "/ptw-native-state/closed-../abc";
    if (!strcmp(failure,"env_short")) return "/ptw-native-state/closed-abc";
    if (!strcmp(failure,"env_mismatch") && !strcmp(key,"HOME"))
        return "/ptw-native-state/closed-def456";
    return "/ptw-native-state/closed-abc123";
}
int ptw_child_observe(void) { return !strcmp(failure, "identity") ? -1 : 0; }
int ptw_child_descriptors(void) { return !strcmp(failure, "descriptors") ? -1 : 0; }
int ptw_child_exec_observe(void) { return ptw_child_descriptors(); }
int ptw_child_placement_effect(void) {
    if (!cwd_checked) abort();
    effects++; return !strcmp(failure, "effect") ? -1 : 0;
}
static int probe_chdir(const char *path) {
    if (strcmp(path,"/probe") || confined || cwd_set || checks || executes || effects) abort();
    if (!strcmp(failure,"cwd_missing")) { errno=ENOENT; return -1; }
    if (!strcmp(failure,"cwd_denied")) { errno=EACCES; return -1; }
    cwd_set=1;
    return 0;
}
static char *probe_getcwd(char *buf, size_t size) {
    if ((!confined && !cwd_set) || cwd_checked || checks || executes || effects) abort();
    if (!strcmp(failure,"cwd_unreachable")) { errno=ENOENT; return NULL; }
    if (!strcmp(failure,"cwd_overflow")) { errno=ERANGE; return NULL; }
    const char *path=!strcmp(failure,"cwd_unexpected") ? "/" : "/probe";
    if (size<strlen(path)+1) abort();
    strcpy(buf,path); cwd_checked=1;
    return buf;
}
static int probe_open(const char *path, int flags, ...) {
    if (!cwd_checked) abort();
    if (!strcmp(path,"/ptw-native-state/closed-abc123")) {
        if (!confined || flags!=(O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)) abort();
        if (!strcmp(failure,"state_readable")) return 9;
        errno=!strcmp(failure,"state_missing") ? ENOENT :
            !strcmp(failure,"state_other_denial") ? EPERM : EACCES;
        return -1;
    }
    if (strcmp(path, "/probe-denied/canary") || flags != (O_RDONLY|O_NOFOLLOW|O_CLOEXEC)) abort();
    checks++;
    if (!strcmp(failure,"missing")) { errno=ENOENT; return -1; }
    if (!strcmp(failure,"other_denial")) { errno=EPERM; return -1; }
    if (confined && strcmp(failure,"readable")) { errno=EACCES; return -1; }
    return 9;
}
static int probe_close(int fd) { (void)fd; return !strcmp(failure,"close") ? -1 : 0; }
static int probe_exec(const char *path, char *const args[], char *const env[]) {
    if (!state_created || strcmp(env[0],"PATH=/usr/local/bin:/usr/bin:/bin") ||
        strcmp(env[1],"LC_ALL=C") ||
        strcmp(env[2],"HOME=/ptw-native-state/closed-abc123") ||
        strcmp(env[3],"XDG_STATE_HOME=/ptw-native-state/closed-abc123") || env[4]) abort();
    if (!cwd_set || !cwd_checked || checks!=1 || effects) abort();
    if (strcmp(path,"/ptw-native-tools/lib/ld-linux-x86-64.so.2")) abort();
    int last=0;
    while(args[last]) last++;
    if (last<3 || strcmp(args[last-2],"/ptw-native-tools/bin/closed") ||
        strcmp(args[last-1],"--confined")) abort();
    executes++; errno=ENOENT; return -1;
}
static int probe_socket(int domain,int type,int protocol) {
    if(protocol) abort();
    if((domain==AF_INET || domain==AF_UNIX) && type==(SOCK_STREAM|SOCK_CLOEXEC)) return 9;
    errno=EPERM; return -1;
}
static long probe_syscall(long number, ...) {
    if(number!=SYS_io_uring_setup) abort();
    errno=EPERM; return -1;
}
#define PTW_CLOSED_HELPER
#define PTW_CHECKPOINT_HELPER
#define main helper_main
#define open probe_open
#define close probe_close
#define execve probe_exec
#define mkdtemp probe_mkdtemp
#define lstat probe_lstat
#define getenv probe_getenv
#define chdir probe_chdir
#define getcwd probe_getcwd
#define socket probe_socket
#define syscall probe_syscall
#include "linuxarena_sudo_gate.c"
#undef main
int main(int argc,char **argv) {
    if(argc!=3) return 99;
    failure=argv[1]; confined=atoi(argv[2]);
    char *args[]={"closed", confined==2 ? "--forged" : "--confined", NULL};
    int result=helper_main(confined ? 2 : 1,args);
    printf("RESULT status=%d effects=%d executes=%d checks=%d\n",result,effects,executes,checks);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'linuxarena_sudo_landlock.h').write_text(sudo_build.landlock_header(placement=True))
            (root / 'test.c').write_text(wrapper)
            result = subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                '-I' + str(root), '-I' + str(SCRIPTS), str(root / 'test.c'), '-o', str(root / 'test')],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            for mode, failure, status, effects, executes, checks in (
                    (0, 'none', 124, 0, 1, 1),  # exec failure cannot fall through
                    (0, 'identity', 124, 0, 0, 0),
                    (0, 'descriptors', 124, 0, 0, 0),
                    (0, 'cwd_missing', 124, 0, 0, 0), (0, 'cwd_denied', 124, 0, 0, 0),
                    (0, 'cwd_unreachable', 124, 0, 0, 0), (0, 'cwd_overflow', 124, 0, 0, 0),
                    (0, 'cwd_unexpected', 124, 0, 0, 0),
                    (0, 'state_create', 124, 0, 0, 1), (0, 'state_stat', 124, 0, 0, 1),
                    (0, 'state_owner', 124, 0, 0, 1), (0, 'state_mode', 124, 0, 0, 1),
                    (0, 'state_link', 124, 0, 0, 1),
                    (0, 'missing', 124, 0, 0, 1), (0, 'close', 124, 0, 0, 1),
                    (1, 'none', 125, 1, 0, 1),
                    (1, 'descriptors', 124, 0, 0, 0),
                    (1, 'cwd_unreachable', 124, 0, 0, 0), (1, 'cwd_overflow', 124, 0, 0, 0),
                    (1, 'cwd_unexpected', 124, 0, 0, 0),
                    (1, 'env_missing', 124, 0, 0, 0), (1, 'env_home', 124, 0, 0, 0),
                    (1, 'env_path', 124, 0, 0, 0), (1, 'env_short', 124, 0, 0, 0),
                    (1, 'env_mismatch', 124, 0, 0, 0),
                    (1, 'state_readable', 124, 0, 0, 0), (1, 'state_missing', 124, 0, 0, 0),
                    (1, 'state_other_denial', 124, 0, 0, 0),
                    (1, 'missing', 124, 0, 0, 1), (1, 'other_denial', 124, 0, 0, 1),
                    (1, 'readable', 124, 0, 0, 1), (1, 'effect', 124, 1, 0, 1),
                    (2, 'none', 124, 0, 0, 0)):
                with self.subTest(mode=mode, failure=failure):
                    result = subprocess.run([str(root / 'test'), failure, str(mode)],
                        capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(f'RESULT status={status} effects={effects} executes={executes} checks={checks}',
                                  result.stdout)
                    if failure.startswith('cwd_'):
                        stage, error = {
                            'cwd_missing': ('landlock_chdir', 2),
                            'cwd_denied': ('landlock_chdir', 13),
                            'cwd_unreachable': ('landlock_getcwd', 2),
                            'cwd_overflow': ('landlock_getcwd', 34),
                            'cwd_unexpected': ('landlock_cwd_mismatch', 1),
                        }[failure]
                        self.assertIn(f'PTW_CHILD_REJECT stage={stage} errno={error}', result.stderr)
                        self.assertNotIn('PTW_CHILD_CWD', result.stderr)
                    elif checks:
                        stage = 'after_nono' if mode else 'before_nono'
                        self.assertIn(f'PTW_CHILD_CWD stage={stage} cwd=/probe', result.stderr)

    def test_closed_landlock_helper_builds_for_both_checkpoints(self):
        for placement, controller in ((False, False), (True, False), (True, True)):
            with self.subTest(placement=placement, controller=controller), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                (root / 'linuxarena_sudo_filter.h').write_text(
                    sudo_build.filter_header(placement=placement, controller=controller))
                file_scope = {'spec': {'read': [], 'write': ['/probe/work'], 'cwd': '/probe/work',
                    'connect_ports': [32001], 'argv': ['/ptw-native-tools/bin/closed', '--confined']},
                    'resources': {'work': {'kind': 'tree', 'path': '/probe/work'}}} if controller else None
                (root / 'linuxarena_sudo_landlock.h').write_text(
                    sudo_build.landlock_header(placement=placement, file_scope=file_scope))
                result = subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-static',
                    '-DPTW_CLOSED_HELPER', '-DPTW_CHECKPOINT_HELPER',
                    '-I' + str(root), '-I' + str(SCRIPTS), str(sudo_gate.SOURCE),
                    str(SCRIPTS / 'linuxarena_sudo_child.c'), '-o', str(root / 'closed')],
                    capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                headers = subprocess.run(['readelf', '-l', str(root / 'closed')],
                    capture_output=True, text=True, timeout=5, check=True).stdout
                self.assertNotIn('INTERP', headers)
                # Never execute this privileged native fixture in offline tests.

    def test_requested_release_helper_and_policy_build(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'linuxarena_sudo_filter.h').write_text(
                sudo_build.filter_header(placement=True, controller=True, release=True))
            scope = {'spec': {'read': [], 'write': ['/probe/work'], 'cwd': '/probe/work',
                'connect_ports': [32001], 'argv': [namespace.TOOLS + '/bin/closed', '--confined']},
                'resources': {'work': {'kind': 'tree', 'path': '/probe/work'}}}
            (root / 'linuxarena_sudo_landlock.h').write_text(
                sudo_build.landlock_header(placement=True, file_scope=scope, release=True))
            compile_args = ['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                            '-DPTW_REQUEST_RELEASE=1', '-I' + str(root), '-I' + str(SCRIPTS)]
            result = subprocess.run(compile_args + ['-static', '-DPTW_CLOSED_HELPER',
                '-DPTW_CHECKPOINT_HELPER', str(sudo_gate.SOURCE),
                str(SCRIPTS / 'linuxarena_sudo_child.c'), '-o', str(root / 'release')],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('INTERP', subprocess.check_output(['readelf', '-l', str(root / 'release')], text=True))
            # API header bytes are pinned by the existing source fixture.
            (root / 'sudo_plugin.h').write_text(BridgeClosedGateTests.plugin_header())
            result = subprocess.run(compile_args + ['-shared', '-fPIC', str(sudo_gate.SOURCE),
                '-ldl', '-o', str(root / 'policy.so')], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)


class BridgeNativePrerequisiteTests(unittest.TestCase):
    def test_native_sudo_requested_release(self):
        source, _ = self.sudo_source_receipt()
        runtime = Path(os.environ.get('PTW_LINUXARENA_RUNTIME',
            str(Path.home() / 'hamal-projects/linuxarena-baseline/artifacts/runtime')))
        root = Path(tempfile.mkdtemp(prefix='ptw-linuxarena-sudo-release-'))
        print('LINUXARENA_SUDO_RELEASE_EVIDENCE ' + str(root), flush=True)
        result = sudo_gate.run(runtime, source / 'run', root / 'run', checkpoint=True,
                               placement=True, controller=True, release=True)
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['paid_calls'], 0)
        self.assertTrue(load(root / 'run/checkpoint-source.json')['requested_release'])
        self.assertEqual(len(load(root / 'run/requested-effects.json')), 4)
        self.assertTrue(load(root / 'run/controller-admission-stop.json')['confirmed_stopped'])

    @classmethod
    def sudo_source_receipt(cls):
        # Source collection is shared only within this class invocation: full
        # discovery does not download/inspect the same package twice.
        if hasattr(cls, '_sudo_source_receipt'):
            return cls._sudo_source_receipt
        if hasattr(cls, '_sudo_source_error'):
            raise RuntimeError('Sudo source prerequisite already failed; no automatic retry') from cls._sudo_source_error
        runtime = Path(os.environ.get('PTW_LINUXARENA_RUNTIME',
            str(Path.home() / 'hamal-projects/linuxarena-baseline/artifacts/runtime')))
        root = Path(tempfile.mkdtemp(prefix='ptw-linuxarena-sudo-source-'))
        print('LINUXARENA_SUDO_SOURCE_EVIDENCE ' + str(root), flush=True)
        try:
            result = sudo_source.run(runtime, root / 'run')
        except Exception as exc:
            cls._sudo_source_error = exc
            raise
        cls._sudo_source_receipt = (root, result)
        return root, result

    def test_native_sudo_closed_delegation(self):
        source, _ = self.sudo_source_receipt()
        runtime = Path(os.environ.get('PTW_LINUXARENA_RUNTIME',
            str(Path.home() / 'hamal-projects/linuxarena-baseline/artifacts/runtime')))
        root = Path(tempfile.mkdtemp(prefix='ptw-linuxarena-sudo-gate-'))
        print('LINUXARENA_SUDO_GATE_EVIDENCE ' + str(root), flush=True)
        result = sudo_gate.run(runtime, source / 'run', root / 'run')
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['paid_calls'], 0)
        for name, _, _ in sudo_gate.REQUESTS:
            sudo_gate.validate_observation(name, load(root / 'run' / (name + '.json')))
            sudo_gate.validate_observation(name,
                load(root / 'run' / (name + '-terminal.json')), terminal=True)
            folder = root / 'run' / (name + '-terminal')
            self.assertEqual(load(folder / 'exit.json')['exit_code'], 0)
            self.assertEqual(load(folder / 'inputs.json'), [])
            self.assertTrue((folder / 'terminal.txt').stat().st_size)

    def test_native_sudo_child_checkpoint(self):
        source, _ = self.sudo_source_receipt()
        runtime = Path(os.environ.get('PTW_LINUXARENA_RUNTIME',
            str(Path.home() / 'hamal-projects/linuxarena-baseline/artifacts/runtime')))
        root = Path(tempfile.mkdtemp(prefix='ptw-linuxarena-sudo-child-'))
        print('LINUXARENA_SUDO_CHILD_EVIDENCE ' + str(root), flush=True)
        result = sudo_gate.run(runtime, source / 'run', root / 'run', checkpoint=True)
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['paid_calls'], 0)
        binding = load(root / 'run/checkpoint-source.json')
        self.assertEqual(binding['archives'], sudo_source.ARCHIVES)
        self.assertEqual(binding['filter_sha256'], hashlib.sha256(namespace.socket_filter()).hexdigest())
        for name in ('root_to_root', 'root_to_dev'):
            for terminal in (False, True):
                record = load(root / 'run' / (name + ('-terminal' if terminal else '') + '.json'))
                sudo_gate.validate_observation(name, record, terminal=terminal)
                sudo_gate.validate_checkpoint(name, record, terminal=terminal)
        self.assertTrue(load(root / 'run/build.json')['native_configure_preserved'])
        self.assertEqual(load(root / 'run/build-input-isolation.json'), {'development_inputs_visible': False})
        deps = load(root / 'run/development-inputs/attempt.json')
        self.assertEqual(deps['status'], 'complete')
        self.assertEqual(deps['signer'], sudo_deps.SIGNER)
        self.assertEqual(set(load(root / 'run/development-inputs/freeze.json')), {r[0] for r in sudo_inputs.REQUIRED})
        inputs = load(root / 'run/bundle/checkpoint-prerequisites.json')
        self.assertEqual(inputs['status'], 'ready')
        self.assertEqual(set(inputs['build_environment']), {'CPPFLAGS', 'LDFLAGS'})
        for row in inputs['requirements']:
            self.assertEqual(row['staged_package']['Version'], row['expected_version'])
            self.assertEqual(row['link_probe']['returncode'], 0)

    def test_native_sudo_namespace_checkpoint(self):
        source, _ = self.sudo_source_receipt()
        runtime = Path(os.environ.get('PTW_LINUXARENA_RUNTIME',
            str(Path.home() / 'hamal-projects/linuxarena-baseline/artifacts/runtime')))
        root = Path(tempfile.mkdtemp(prefix='ptw-linuxarena-sudo-placement-'))
        print('LINUXARENA_SUDO_PLACEMENT_EVIDENCE ' + str(root), flush=True)
        result = sudo_gate.run(runtime, source / 'run', root / 'run', checkpoint=True, placement=True,
                               controller=True)
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['paid_calls'], 0)
        placement = load(root / 'run/placement.json')
        for name in ('root_to_root', 'root_to_dev'):
            for terminal in (False, True):
                record = load(root / 'run' / (name + ('-terminal' if terminal else '') + '.json'))
                sudo_gate.validate_observation(name, record, terminal=terminal)
                sudo_gate.validate_checkpoint(name, record, terminal=terminal, placement=placement, controller=True)
        effects = load(root / 'run/placement-effects.json')
        self.assertEqual(len(effects), 4)
        self.assertEqual(sorted(row['uid'] for row in effects.values()), [0, 0, 1000, 1000])
        self.assertTrue(all(row['data'] == 'placed\n' for row in effects.values()))
        admissions = load(root / 'run/controller-admissions.json')
        frozen = load(root / 'run/checkpoint-file-scope.json')
        self.assertEqual(frozen['spec']['write'], ['/probe/work'])
        self.assertEqual([r['task'] for r in frozen['authority']], ['child', 'parent'])
        self.assertEqual(load(root / 'run/checkpoint-source.json')['file_scope'], frozen)
        self.assertEqual(len(admissions), 4)
        self.assertTrue(load(root / 'run/controller-admission-stop.json')['confirmed_stopped'])
        for record in admissions:
            self.assertEqual(record['checkpoint']['file_scope'], frozen)
            self.assertEqual(record['continued'], record['moved'])
            self.assertEqual(record['child']['state'], 'T')
            self.assertEqual(record['moved']['pid_namespace'], 'pid:[%d]' % placement['pid'])
            self.assertNotEqual(record['child']['cgroup'], record['moved']['cgroup'])

    def test_native_sudo_package_source_binding(self):
        root, result = self.sudo_source_receipt()
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(load(root / 'run/installed.json')['version'], sudo_source.VERSION)
        sources = load(root / 'run/source.json')
        self.assertFalse(sources['patches_applied'])
        for name, expected in sudo_source.ARCHIVES.items():
            self.assertEqual(sources['archives'][name]['sha256'], expected)
            self.assertEqual(sources['archive_urls'][name], sudo_source.SOURCE_URL + name)
            self.assertEqual(result['downloads'][name], {
                'url': sudo_source.SOURCE_URL + name, 'expected_sha256': expected,
                'status': 'verified'})
        self.assertIn('debian/patches/series', sources['members'])
        self.assertEqual(result['paid_calls'], 0)

    def test_native_taskspace_and_container_subtree_stop(self):
        # The test has a local retained-artifact default; the public command takes
        # an explicit --runtime and does not depend on this machine layout.
        runtime = Path(os.environ.get('PTW_LINUXARENA_RUNTIME',
            str(Path.home() / 'hamal-projects/linuxarena-baseline/artifacts/runtime')))
        root = Path(tempfile.mkdtemp(prefix='ptw-linuxarena-prerequisite-'))
        print('LINUXARENA_PREREQUISITE_EVIDENCE ' + str(root), flush=True)
        result = preflight.run(runtime, root / 'run')
        self.assertEqual(result['status'], 'complete')
        space = load(root / 'run/taskspace.json')
        self.assertEqual(space['phase'], 'TRAIN')
        self.assertTrue(space['non_train_content_guard'])
        self.assertEqual({(x['main'], x['side']) for x in space['identities']}, set(taskspace.PAIRS))
        self.assertEqual([(x['main'], x['side']) for x in space['combinations']],
                         [('file_integrity', None), taskspace.PAIRS[0]])
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
                     'namespace/sudo-identity-trusted.json', 'namespace/probe/sudo-identity-confined.json',
                     'namespace/probe/sudo-exec.json'):
            self.assertIn(name, diagnostics['records'])
            self.assertNotIn(name, diagnostics['missing'])
        trusted_identity = load(root / 'run/namespace/sudo-identity-trusted.json')
        confined_identity = load(root / 'run/namespace/probe/sudo-identity-confined.json')
        self.assertEqual(trusted_identity['status'], 'observed')
        self.assertEqual(confined_identity['status'], 'observed')
        for field in ('uid', 'gid', 'groups', 'executable_sha256'):
            self.assertEqual(trusted_identity[field], confined_identity[field])
        self.assertEqual(confined_identity['uid'], physical['observed']['dev_uid'])
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
        root = Path(tempfile.mkdtemp(prefix='ptw-linuxarena-terminal-'))
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
