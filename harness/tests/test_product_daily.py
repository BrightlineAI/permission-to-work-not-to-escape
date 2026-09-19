"""Daily workflow tests; native evidence is retained outside the checkout."""
import json
import base64
import copy
from contextlib import contextmanager
import os
import subprocess
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

from ptw.conversation import attach, discover, native_id, remember
from ptw.policy import Invalid, load, save
from ptw.terminal import codex_command
from ptw.workspace import Workspace, request, scan
from test_workspace import WorkspaceFixture


class ResumeTests(WorkspaceFixture):
    def setUp(self):
        super().setUp()
        self.directory = self.root / 'operator'
        self.directory.mkdir()
        self.record = {'repo': self.inv['root'], 'project': 'python-demo',
                       'policy_sha256': self.store.status('python-demo')['policy_sha256']}

    def rollout(self, folder, identity=None, **changes):
        identity = identity or str(uuid.uuid4())
        path = folder / 'native-sessions/2026/09/18' / (identity + '.jsonl')
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {'id': identity, 'cwd': str(folder / 'work'), **changes}
        path.write_text(json.dumps({'type': 'session_meta', 'payload': payload}) + '\n')
        return identity, path

    def recorded(self):
        with attach(self.directory, self.record, 'implementation') as (folder, identity):
            self.assertIsNone(identity)
            identity, _ = self.rollout(folder)
            self.assertEqual(remember(folder), identity)
        return folder, identity

    def test_resume_same_identity_new_token_keeps_counts_and_other_parent(self):
        folder, identity = self.recorded()
        self.assertFalse(self.ask('read', 'private', 'customer.txt')['allowed'])
        other = self.store.register('python-demo', 'implementation')
        child = self.store.register('python-demo', 'readcheck', parent_token=self.actor['token'])
        self.store.close_session(self.actor['token'])
        with attach(self.directory, self.record, 'implementation', identity) as resumed:
            self.assertEqual(resumed, (folder, identity))
            fresh = self.store.register('python-demo', 'implementation')
            self.assertNotEqual(fresh['token'], self.actor['token'])
            with self.store.locked() as db:
                for old in (self.actor, child):
                    with self.assertRaises(Invalid):
                        self.store.session(db, old['token'])
                self.store.session(db, other['token'])
            self.assertEqual(self.store.status('python-demo')['violations'], 1)
            result = self.broker.request(fresh['token'], 'fresh-read',
                {'action': 'read', 'resource': 'src', 'path': 'calculator.py', 'content': '',
                 'expected': '', 'destination': ''})
            self.assertTrue(result['allowed'], result)

    def test_unique_selection_and_ambiguous_selection(self):
        folder, identity = self.recorded()
        with attach(self.directory, self.record, 'implementation', '') as actual:
            self.assertEqual(actual, (folder, identity))
        self.recorded()
        with self.assertRaisesRegex(Invalid, 'unique'):
            with attach(self.directory, self.record, 'implementation', ''):
                self.fail('ambiguous selection admitted')

    def test_foreign_task_project_approval_and_replaced_repository(self):
        _, identity = self.recorded()
        records = [{**self.record, 'project': 'other'}, {**self.record, 'policy_sha256': 'new'}]
        for record in records:
            with self.subTest(record=record), self.assertRaises(Invalid):
                with attach(self.directory, record, 'implementation', identity):
                    self.fail('foreign binding admitted')
        with self.assertRaises(Invalid):
            with attach(self.directory, self.record, 'readcheck', identity):
                self.fail('different task admitted')
        repo = Path(self.record['repo'])
        repo.rename(repo.with_name('old-repo'))
        repo.mkdir()
        with self.assertRaises(Invalid):
            with attach(self.directory, self.record, 'implementation', identity):
                self.fail('replaced repository admitted')

    def test_reviewed_dependency_lineage_preserves_binding(self):
        folder, identity = self.recorded()
        revised = {**self.record, 'policy_sha256': 'reviewed-dependency-hash',
                   'resume_policy': self.record['policy_sha256']}
        with attach(self.directory, revised, 'implementation', identity) as actual:
            self.assertEqual(actual, (folder, identity))

    def test_concurrent_attach_and_failed_attach_release(self):
        _, identity = self.recorded()
        with attach(self.directory, self.record, 'implementation', identity):
            with self.assertRaisesRegex(Invalid, 'already attached'):
                with attach(self.directory, self.record, 'implementation', identity):
                    self.fail('second attach admitted')
        with self.assertRaises(RuntimeError):
            with attach(self.directory, self.record, 'implementation', identity):
                raise RuntimeError('launch failed')
        with attach(self.directory, self.record, 'implementation', identity):
            pass

    def test_malformed_missing_and_changed_native_history(self):
        for value in ('../escape', '--last', 'name', '', None, 12, 'A' * 36):
            with self.subTest(value=value), self.assertRaises(Invalid):
                native_id(value)
        folder, identity = self.recorded()
        _, path = self.rollout(folder, identity, cwd='/foreign')
        with self.assertRaises(Invalid):
            discover(folder)
        path.write_text('x' * 65537)
        with self.assertRaises(Invalid):
            discover(folder)
        path.unlink()
        with self.assertRaises(Invalid):
            discover(folder)

    def test_symlink_rollout_and_multiple_threads_rejected(self):
        folder, identity = self.recorded()
        _, path = self.rollout(folder, identity)
        original = self.root / 'foreign.jsonl'
        path.rename(original)
        path.symlink_to(original)
        with self.assertRaises(Invalid):
            discover(folder)
        path.unlink()
        self.rollout(folder, identity)
        self.rollout(folder)
        with self.assertRaises(Invalid):
            remember(folder, identity)

    def test_stopped_project_cannot_register_resumed_credentials(self):
        _, identity = self.recorded()
        self.store.stop('python-demo')
        with attach(self.directory, self.record, 'implementation', identity):
            with self.assertRaisesRegex(Invalid, 'stopped'):
                self.store.register('python-demo', 'implementation')

    def test_onboarding_launch_failure_revokes_new_credential(self):
        from ptw.onboarding import start
        bundle = self.approve()
        save(Path(self.inv['root']) / '.ptw/policy.json', bundle['policy'])
        save(self.directory / 'approved.json', bundle)
        record = {**self.record, 'state': str(self.store.directory), 'task': 'implementation',
                  'bundle': str(self.directory / 'approved.json')}
        save(self.directory / 'project.json', record)
        args = SimpleNamespace(repo=self.inv['root'], status=False, stop=False, review=False,
                               revise=False, setup_only=False, task=None, prompt=None, resume=None)
        with patch('ptw.onboarding.private_directory', return_value=self.directory), \
                patch('ptw.onboarding.ensure'), \
                patch('ptw.terminal.launch', side_effect=Invalid('native startup failed')), \
                self.assertRaisesRegex(Invalid, 'native startup failed'):
            start(args)
        new_path = next((self.directory / 'sessions').glob('*/session.json'))
        with self.store.locked() as db:
            with self.assertRaises(Invalid):
                self.store.session(db, load(new_path)['token'])
            self.store.session(db, self.actor['token'])

    def test_monitor_loss_prevents_native_launch(self):
        from ptw.terminal import launch
        with patch('ptw.terminal.sys.stdin.isatty', return_value=True), \
                patch('ptw.terminal.health', return_value={'healthy': False}), \
                patch('ptw.terminal.codex_command') as command, self.assertRaisesRegex(Invalid, 'monitor'):
            launch(self.store, self.actor, self.root / 'session.json', self.root)
        command.assert_not_called()

    def test_resumed_command_retains_boundary_and_new_broker_path(self):
        folder, identity = self.recorded()
        config = self.root / 'codex-config'
        config.mkdir()
        save(config / 'models_cache.json', {'models': [{'slug': 'gpt-5.6-sol', 'apply_patch_tool_type': 'freeform'}]})
        (config / 'config.toml').write_text('')
        with patch.dict(os.environ, {'CODEX_HOME': str(config)}), \
                patch('ptw.terminal.require_login'), \
                patch('ptw.terminal.shutil.which', side_effect=lambda n: '/usr/bin/' + n), \
                patch('ptw.terminal.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout='codex-cli 0.154.0')):
            fresh = codex_command(self.store, self.root / 'new-session.json', folder / 'work',
                                  conversation=folder, resume=identity)
        self.assertEqual(fresh[fresh.index('/usr/bin/codex') + 1:][:2], ['resume', identity])
        self.assertIn('permissions.ptw-interactive.filesystem={"/"="deny"}', fresh)
        self.assertIn('mcp_servers.ptw.required=true', fresh)
        self.assertIn('shell_tool', fresh)
        self.assertIn('plugins', fresh)
        self.assertIn('apps', fresh)
        self.assertTrue(any('new-session.json' in arg for arg in fresh))
        self.assertIsNone(load(folder / 'work/model-catalog.json')['models'][0]['apply_patch_tool_type'])

    def test_fresh_then_resume_refreshes_catalog_in_same_workspace(self):
        folder, identity = self.recorded()
        config = self.root / 'codex-config'
        config.mkdir()
        model = {'slug': 'gpt-5.6-sol', 'apply_patch_tool_type': 'freeform',
                 'experimental_supported_tools': ['unsafe-native-tool']}
        save(config / 'models_cache.json', {'models': [model]})
        (config / 'config.toml').write_text('')
        with patch.dict(os.environ, {'CODEX_HOME': str(config)}), \
                patch('ptw.terminal.require_login'), \
                patch('ptw.terminal.shutil.which', side_effect=lambda n: '/usr/bin/' + n), \
                patch('ptw.terminal.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout='codex-cli 0.154.0')):
            first = codex_command(self.store, self.root / 'old-session.json', folder / 'work',
                                  conversation=folder)
            catalog = folder / 'work/model-catalog.json'
            original = catalog.read_bytes()
            # Stale generated contents must not be trusted on attachment.
            catalog.write_text(json.dumps({'models': [model]}))
            resumed = codex_command(self.store, self.root / 'new-session.json', folder / 'work',
                                    conversation=folder, resume=identity)
            self.assertEqual(catalog.read_bytes(), original)
            self.assertEqual(catalog.stat().st_mode & 0o777, 0o600)
            self.assertNotIn('resume', first)
            self.assertIn(identity, resumed)
            self.assertFalse(any('old-session.json' in arg for arg in resumed))
            self.assertTrue(any('new-session.json' in arg for arg in resumed))
            # Replacement cannot truncate a linked file outside the workspace.
            outside = self.root / 'unrelated.json'
            outside.write_text('unchanged')
            catalog.unlink()
            catalog.symlink_to(outside)
            codex_command(self.store, self.root / 'third-session.json', folder / 'work',
                          conversation=folder, resume=identity)
            self.assertFalse(catalog.is_symlink())
            self.assertEqual(catalog.read_bytes(), original)
            self.assertEqual(outside.read_text(), 'unchanged')

    def test_catalog_refresh_failure_preserves_previous_catalog(self):
        from ptw.setup_transaction import atomic
        catalog = self.root / 'model-catalog.json'
        atomic(catalog, {'models': ['previous']})
        with patch('ptw.setup_transaction.os.replace', side_effect=OSError('disk failure')), \
                self.assertRaisesRegex(OSError, 'disk failure'):
            atomic(catalog, {'models': ['new']})
        self.assertEqual(load(catalog), {'models': ['previous']})


class PreviewTests(WorkspaceFixture):
    def setUp(self):
        super().setUp()
        from ptw.store import Store
        self.definition = {'id': 'preview', 'argv': ['/usr/bin/python3', '-B', 'src/server.py'],
                           'resources': ['src'], 'timeout_seconds': 10,
                           'preview': {'port': 8123, 'lifetime_seconds': 30}}
        self.policy['project']['commands'].append(self.definition)
        self.policy['tasks'][0]['commands'].append('preview')
        self.store = Store(self.root / 'preview-state')
        self.store.activate(self.approve())
        self.actor = self.store.register('python-demo', 'implementation')
        self.broker = Workspace(self.store)

    def service(self, action='service_start', **kw):
        self.i += 1
        return self.broker.request(self.actor['token'], 'preview-' + str(self.i), request(action, 'preview', **kw))

    def test_operator_candidates_and_review(self):
        from ptw.preview import candidates
        from ptw.onboarding import review_text, short_review
        args = SimpleNamespace(preview_python='src/server.py:8123', preview_node='src/server.js:8124', preview_seconds=45)
        result = candidates({'src': 'tree'}, ['requirements.txt'], '/usr/bin/python3', args)
        self.assertEqual([c['preview']['port'] for c in result], [8123, 8124])
        self.assertTrue(all(c['resources'] == ['requirements.txt', 'src'] for c in result))
        for text in (review_text(self.approve()), short_review(self.approve(), {}, [])):
            self.assertIn('8123', text)
            self.assertIn('30', text)
            self.assertIn('768 MiB', text)
        for value in ('../escape:8123', '/host.py:8123', 'private/secret.py:8123', 'src/a.py:80', 'src/a.py:65536', 'src/a.py:bad'):
            with self.subTest(value=value), self.assertRaises(Invalid):
                candidates({'src': 'tree'}, [], '/usr/bin/python3', SimpleNamespace(preview_python=value))
        args.preview_node = 'src/a.js:8123'
        with self.assertRaises(Invalid):
            candidates({'src': 'tree'}, [], '/usr/bin/python3', args)
        with self.assertRaises(Invalid):
            candidates({'src': 'tree'}, [], '/usr/bin/python3', SimpleNamespace(preview_seconds=30))

    def test_reviewed_bounds_no_extra_network_fields(self):
        from ptw.policy import compile_policy
        for preview in ({'port': 80, 'lifetime_seconds': 30}, {'port': 8123, 'lifetime_seconds': 3601},
                        {'port': True, 'lifetime_seconds': 30}, {'port': 8123, 'lifetime_seconds': 0},
                        {'port': 8123, 'lifetime_seconds': 30, 'host': '0.0.0.0'}):
            policy = copy.deepcopy(self.policy)
            policy['project']['commands'][-1]['preview'] = preview
            with self.subTest(preview=preview), self.assertRaises(Invalid):
                compile_policy(policy, self.inv)

    def test_existing_command_gains_no_preview_authority(self):
        result = self.broker.request(self.actor['token'], 'ordinary', request('service_start', 'test'))
        self.assertFalse(result['allowed'])
        self.assertEqual(self.store.status('python-demo')['violations'], 1)
        self.assertEqual(self.service('run')['level'], 'blocked')

    def test_narrower_delegate_cannot_start_parent_preview(self):
        child = self.store.register('python-demo', 'readcheck', parent_token=self.actor['token'])
        result = self.broker.request(child['token'], 'child', request('service_start', 'preview'))
        self.assertFalse(result['allowed'])
        self.assertEqual(self.store.status('python-demo')['violations'], 1)

    def test_malformed_request_cannot_select_host_destination(self):
        with patch('ptw.preview.preview_command') as launch:
            self.assertFalse(self.service(path='http://example.com')['allowed'])
            self.assertFalse(self.service('service_stop', content='{"unit":"foreign"}')['allowed'])
            launch.assert_not_called()

    def test_monitor_loss_blocks_start_without_punishment(self):
        with patch('ptw.preview.health', return_value={'healthy': False}), patch('ptw.preview.preview_command') as prepare:
            result = self.service()
        self.assertFalse(result['allowed'])
        self.assertEqual(self.store.status('python-demo')['violations'], 0)
        prepare.assert_not_called()

    def test_prepared_namespace_has_only_scoped_seed_and_listen_port(self):
        from ptw.preview import preview_command
        directory = self.root / 'staging'
        directory.mkdir()
        before = scan(self.inv, ['src'])
        with patch('ptw.execution.shutil.which', side_effect=lambda n: '/usr/bin/' + n):
            command = preview_command(self.store, self.actor['token'], self.definition, before, '', directory)
        self.assertIn('--unshare-all', command)
        self.assertNotIn('--share-net', command)
        self.assertNotIn('--bind', command)
        self.assertNotIn('--block-net', command)
        self.assertNotIn('--listen-port', command)
        self.assertNotIn('--sandbox-policy', command)
        self.assertEqual(command[command.index('--config') + 1], '/preview-capabilities.json')
        mounted = command.index(str(directory / 'capabilities.json'))
        self.assertEqual(command[mounted - 1:mounted + 2],
                         ['--ro-bind', str(directory / 'capabilities.json'), '/preview-capabilities.json'])
        manifest = load(directory / 'capabilities.json')
        self.assertEqual(set(manifest), {'version', 'filesystem', 'network'})
        self.assertEqual(manifest['version'], '0.1.0')
        self.assertEqual(manifest['network'], {'mode': 'blocked', 'ports': {
            'bind': [8123], 'connect': [], 'localhost': [], 'localhost_range': []}})
        self.assertEqual(manifest['filesystem'], {'grants': [
            *[{'path': p, 'access': 'read', 'type': 'directory'}
              for p in ('/usr', '/bin', '/lib', '/lib64', '/sbin') if Path(p).exists()],
            {'path': '/proc', 'access': 'read', 'type': 'directory'},
            *[{'path': '/dev/' + p, 'access': 'readwrite', 'type': 'file'}
              for p in ('null', 'zero', 'random', 'urandom')],
            {'path': '/target', 'access': 'readwrite', 'type': 'directory'},
            {'path': '/tmp', 'access': 'readwrite', 'type': 'directory'}]})
        self.assertIn('PORT=8123', command)
        self.assertNotIn(self.inv['root'], command)
        self.assertEqual(command[-3:], self.definition['argv'])
        self.assertFalse((directory / 'tree/private').exists())
        self.assertEqual((directory / 'tree/src/calculator.py').read_bytes(), before['src/calculator.py']['data'])

    def test_preview_manifest_preserves_only_assessed_package_grants(self):
        from ptw.preview import preview_command
        package = self.root / 'assessed-package'
        package.mkdir()
        with self.store.locked() as db:
            db.execute('INSERT INTO package_sets(id,project,names,manifest,created,ecosystem) '
                       'VALUES(?,?,?,?,?,?)', ('fixture', 'python-demo', '[]', '{}', 0, 'pypi'))
        directory = self.root / 'staging'
        directory.mkdir()
        with patch('ptw.execution.shutil.which', side_effect=lambda n: '/usr/bin/' + n), \
                patch('ptw.reassessment.refresh'), \
                patch('ptw.execution.mounted_set', return_value=package) as assessed:
            command = preview_command(self.store, self.actor['token'], self.definition,
                                      scan(self.inv, ['src']), '{"package_sets":["fixture"]}', directory)
        assessed.assert_called_once()
        self.assertIn('PYTHONPATH=/python-packages:/target', command)
        mounted = command.index(str(package))
        self.assertEqual(command[mounted - 1:mounted + 2], ['--ro-bind', str(package), '/python-packages'])
        grants = load(directory / 'capabilities.json')['filesystem']['grants']
        self.assertEqual([g for g in grants if 'packages' in g['path']],
                         [{'path': '/python-packages', 'access': 'read', 'type': 'directory'}])

    def test_bad_package_settings_do_not_start_worker(self):
        from ptw.preview import preview_command
        for settings in ('[]', '{"url":"http://outside"}', '{"package_sets":[1]}', '{"package_sets":["missing"]}'):
            directory = self.root / ('invalid-' + str(len(list(self.root.iterdir()))))
            directory.mkdir()
            with patch('ptw.execution.shutil.which', side_effect=lambda n: '/usr/bin/' + n), self.assertRaises(Invalid):
                preview_command(self.store, self.actor['token'], self.definition, scan(self.inv, ['src']), settings, directory)

    def test_start_replay_duplicate_status_and_stop(self):
        unit = 'ptw-' + '1' * 24 + '.service'

        def start(token, argv, **kw):
            save(Path(argv[-1]).parent / 'ready.json', {'ready': True})
            return unit

        with patch('ptw.preview.health', return_value={'healthy': True}), \
                patch('ptw.preview.preview_command', return_value=['confined-command']), \
                patch('ptw.preview.Supervisor.background', side_effect=start) as launch, \
                patch('ptw.preview.Supervisor.state', return_value={'confirmed_stopped': False, 'ActiveState': 'active'}), \
                patch('ptw.preview.Supervisor.terminate', return_value={'confirmed_stopped': True}):
            result = self.service()
            self.assertTrue(result['allowed'], result)
            self.assertEqual(result['url'], 'http://127.0.0.1:8123/')
            replay = self.broker.request(self.actor['token'], 'preview-1', request('service_start', 'preview'))
            self.assertTrue(replay['replayed'])
            self.assertEqual(self.service()['effect'], 'service_status')
            self.assertTrue(self.service('service_status')['ready'])
            self.assertTrue(self.service('service_stop')['confirmed_stopped'])
            launch.assert_called_once()

    def test_failed_start_retains_receipt_and_terminates(self):
        unit = 'ptw-' + '2' * 24 + '.service'

        def start(token, argv, **kw):
            save(Path(argv[-1]).parent / 'error.json', {'error': 'fixture occupied port'})
            return unit

        with patch('ptw.preview.health', return_value={'healthy': True}), \
                patch('ptw.preview.preview_command', return_value=['confined-command']), \
                patch('ptw.preview.Supervisor.background', side_effect=start), \
                patch('ptw.preview.Supervisor.terminate', return_value={'confirmed_stopped': True}) as terminate:
            result = self.service()
        self.assertFalse(result['allowed'])
        terminate.assert_called_once_with(unit)
        self.assertEqual(self.store.status('python-demo')['violations'], 0)
        self.assertEqual(len(list((self.store.directory / 'previews').glob('*/failure.json'))), 1)

    def test_stop_racing_launch_cannot_publish_ready(self):
        unit = 'ptw-' + '3' * 24 + '.service'

        def start(token, argv, **kw):
            save(Path(argv[-1]).parent / 'ready.json', {'ready': True})
            self.store.stop('python-demo')
            return unit

        with patch('ptw.preview.health', return_value={'healthy': True}), \
                patch('ptw.preview.preview_command', return_value=['confined-command']), \
                patch('ptw.preview.Supervisor.background', side_effect=start), \
                patch('ptw.preview.Supervisor.terminate', return_value={'confirmed_stopped': True}) as terminate:
            self.assertFalse(self.service()['allowed'])
        terminate.assert_called_once_with(unit)
        self.assertTrue(self.store.status('python-demo')['stopped'])

    def test_package_scope_denial_uses_shared_escalation(self):
        from ptw.policy import OutsideScope
        with patch('ptw.preview.health', return_value={'healthy': True}), \
                patch('ptw.preview.preview_command', side_effect=OutsideScope('Package outside session scope')):
            result = self.service(content='{"package_sets":["forbidden"]}')
        self.assertFalse(result['allowed'])
        self.assertEqual(self.store.status('python-demo')['violations'], 1)

    def test_background_launch_timeout_terminates_registered_unit(self):
        import subprocess
        from ptw.supervisor import Supervisor
        with patch('ptw.supervisor.run', side_effect=subprocess.TimeoutExpired('systemd-run', 20)), \
                patch('ptw.supervisor.Supervisor.terminate', return_value={'confirmed_stopped': True}) as terminate, \
                self.assertRaisesRegex(Invalid, 'interrupted'):
            Supervisor(self.store).background(self.actor['token'], ['trusted-preview-worker'], service_seconds=30)
        unit = terminate.call_args.args[0]
        self.assertEqual(self.store.status('python-demo')['workloads'][0]['unit'], unit)


class PreviewTransportTests(unittest.TestCase):
    def http_request(self, target, headers):
        """Exercise the real HTTP parser/handler without opening a socket."""
        import io
        from ptw.preview_transport import outer
        handlers = []

        def capture(address, handler):
            handlers.append(handler)
            raise RuntimeError('captured before socket creation')

        with patch('ptw.preview_transport.HTTPServer', side_effect=capture), \
                self.assertRaisesRegex(RuntimeError, 'captured'):
            outer({'port': 8123, 'directory': '/unused'})

        class Connection:
            def __init__(self):
                self.output = bytearray()

            def makefile(self, *args):
                return io.BytesIO(('GET ' + target + ' HTTP/1.1\r\n' + headers + '\r\n').encode('ascii'))

            def sendall(self, data):
                self.output.extend(data)

            def settimeout(self, timeout):
                pass

        connection = Connection()
        with patch('ptw.preview_transport.exchange', return_value=(200, 'text/plain', b'local')) as exchange:
            handlers[0](connection, ('127.0.0.1', 12345), None)
        return int(connection.output.split(b' ', 2)[1]), exchange

    def test_http_parser_rejects_original_proxy_targets_before_host(self):
        for target in ('http://203.0.113.1/', '//external/', '///external/', '/%2fexternal/'):
            for host in ('203.0.113.1', '127.0.0.1:8123'):
                with self.subTest(target=target, host=host):
                    status, exchange = self.http_request(target, 'Host: ' + host + '\r\n')
                    self.assertEqual(status, 400)
                    exchange.assert_not_called()

    def test_http_parser_preserves_local_get_and_rejects_foreign_headers(self):
        status, exchange = self.http_request('/api?q=local', 'Host: 127.0.0.1:8123\r\n')
        self.assertEqual(status, 200)
        exchange.assert_called_once_with(None, '/api?q=local')
        for headers in ('Host: external.invalid\r\n',
                        'Host: 127.0.0.1:8123\r\nHost: external.invalid\r\n',
                        'Host: 127.0.0.1:8123\r\nOrigin: https://external.invalid\r\n',
                        'Host: 127.0.0.1:8123\r\nContent-Length: 1\r\n'):
            with self.subTest(headers=headers):
                status, exchange = self.http_request('/', headers)
                self.assertEqual(status, 403)
                exchange.assert_not_called()

    def test_startup_failure_retains_both_streams_and_exit_code(self):
        from ptw.preview_transport import inner
        for stream in (1, 2):
            with self.subTest(stream=stream), \
                    patch('ptw.preview_transport.shutil.copytree'), \
                    patch('ptw.preview_transport.os.chdir'), \
                    patch('ptw.preview_transport.fetch', side_effect=OSError('not ready')), \
                    self.assertRaisesRegex(RuntimeError, 'code 7.*native startup diagnostic'):
                inner(8123, '', [sys.executable, '-I', '-S', '-c',
                    'import os; os.write(' + str(stream) + ', b"native startup diagnostic"); os._exit(7)'])

    def test_startup_output_is_drained_and_bounded(self):
        from ptw.preview_transport import inner
        with patch('ptw.preview_transport.shutil.copytree'), \
                patch('ptw.preview_transport.os.chdir'), \
                patch('ptw.preview_transport.fetch', side_effect=OSError('not ready')), \
                self.assertRaises(RuntimeError) as caught:
            inner(8123, '', [sys.executable, '-I', '-S', '-c',
                'import os; os.write(1,b"x"*1048576); os.write(2,b"final diagnostic"); os._exit(9)'])
        self.assertIn('code 9', str(caught.exception))
        self.assertTrue(str(caught.exception).endswith('final diagnostic'))
        self.assertLess(len(str(caught.exception)), 8300)

    def test_paths_cannot_be_proxy_destinations_or_header_injection(self):
        from ptw.preview_transport import origin_path
        for path in ('/', '/index.html', '/api?name=example'):
            self.assertEqual(origin_path(path), path)
        for path in ('http://external/', '//external/', '/%2fexternal/', '/x%0d%0aHost:x', '/x\\y', '/x#fragment', '/' + 'a' * 4096, None):
            with self.subTest(path=path), self.assertRaises(ValueError):
                origin_path(path)

    def test_untrusted_response_validation(self):
        from ptw.preview_transport import response, BODY_LIMIT
        valid = {'status': 200, 'type': 'text/html', 'body': base64.b64encode(b'hello').decode()}
        self.assertEqual(response(valid), (200, 'text/html', b'hello'))
        for value in ({**valid, 'url': 'http://outside/'}, {**valid, 'status': True},
                      {**valid, 'type': 'text/html\r\nLocation: http://outside/'},
                      {**valid, 'body': '!'}, {**valid, 'body': base64.b64encode(b'x' * (BODY_LIMIT + 1)).decode()}):
            with self.assertRaises(ValueError):
                response(value)

    def test_inner_fetch_fixed_target_and_redirect_refusal(self):
        from ptw.preview_transport import fetch
        with patch('ptw.preview_transport.http.client.HTTPConnection') as connection:
            reply = connection.return_value.getresponse.return_value
            reply.read.return_value = b'hello'
            reply.status = 302
            reply.getheader.return_value = 'text/plain'
            with self.assertRaises(ValueError):
                fetch(8123, '/')
            connection.assert_called_once_with('127.0.0.1', 8123, timeout=5)
            connection.return_value.close.assert_called_once()


class LocalGitFixture(WorkspaceFixture):
    """Real Git plumbing over synthetic data; only the native runner is mocked."""
    def setUp(self):
        super().setUp()
        from ptw.local_git import candidates
        self.repo = Path(self.inv['root'])
        self.git('init', '-b', 'main')
        self.git('add', 'src', 'tests', 'private')
        self.git('commit', '-m', 'synthetic fixture base')
        self.definitions = candidates(self.repo, ['src'])
        self.policy['project']['commands'] += self.definitions
        self.policy['tasks'][0]['commands'] += [c['id'] for c in self.definitions]
        self.policy['tasks'][1]['commands'] += [c['id'] for c in self.definitions]
        from ptw.store import Store
        self.store = Store(self.root / 'git-state')
        self.store.activate(self.approve())
        self.actor = self.store.register('python-demo', 'implementation')
        self.broker = Workspace(self.store)
        self.addCleanup(patch.stopall)
        locked = self.store.locked
        holding = False

        @contextmanager
        def non_reentrant():
            nonlocal holding
            self.assertFalse(holding, 'Nested controller lock would deadlock native Git')
            holding = True
            try:
                with locked() as db:
                    yield db
            finally:
                holding = False

        patch.object(self.store, 'locked', non_reentrant).start()
        with self.store.locked() as db:
            db.execute('INSERT OR REPLACE INTO monitor_health VALUES(1,?,?)', (time.time(), ''))
        patch('ptw.local_git.execute', side_effect=self.offline_worker).start()

    def git(self, *args):
        return subprocess.run(['/usr/bin/git', '-C', str(self.repo), '-c', 'core.hooksPath=/dev/null',
            '-c', 'user.name=Fixture', '-c', 'user.email=fixture@localhost', *args],
            env={'PATH': '/usr/bin:/bin', 'HOME': str(self.root), 'GIT_CONFIG_NOSYSTEM': '1',
                 'GIT_CONFIG_GLOBAL': '/dev/null'}, capture_output=True, check=True).stdout

    @staticmethod
    def offline_worker(store, token, target):
        from ptw.git_worker import work
        try:
            return {'ok': True, **work(target)}
        except ValueError as exc:
            raise Invalid(str(exc)) from exc

    def operation(self, operation, **kwargs):
        return self.ask('git_' + operation, 'git-' + operation, '', **kwargs)

    def checkpoint(self, paths=None):
        return self.operation('checkpoint', content=json.dumps({
            'paths': paths or ['src/calculator.py'], 'message': 'Reviewed synthetic checkpoint'}))

    def changed(self):
        old = self.ask('read')
        self.assertTrue(self.ask('write', content='VALUE = 42\n', expected=old['sha256'])['allowed'])

    def publish(self, result):
        from ptw.local_git import publish_checkpoint
        return publish_checkpoint(self.store, result['checkpoint'], result['review_sha256'])


class LocalGitTests(LocalGitFixture):
    def test_real_monitor_health_without_nested_lock_and_expired_approval(self):
        from ptw.monitor import health
        self.changed()
        self.assertTrue(health(self.store)['healthy'])
        prepared = self.checkpoint()
        self.assertTrue(prepared['allowed'], prepared)
        for heartbeat in (None, time.time() - 10, time.time() + 10):
            with self.subTest(heartbeat=heartbeat):
                with self.store.locked() as db:
                    db.execute('DELETE FROM monitor_health')
                    if heartbeat is not None:
                        db.execute('INSERT INTO monitor_health VALUES(1,?,?)', (heartbeat, ''))
                self.assertFalse(health(self.store)['healthy'])
                for operation in ('status', 'diff', 'checkpoint'):
                    result = self.checkpoint() if operation == 'checkpoint' else self.operation(operation)
                    self.assertEqual(result['level'], 'blocked', result)
                with self.assertRaisesRegex(Invalid, 'healthy'):
                    self.publish(prepared)
                self.assertEqual(self.git('for-each-ref', 'refs/ptw'), b'')
        with self.store.locked() as db:
            db.execute('INSERT OR REPLACE INTO monitor_health VALUES(1,?,?)', (time.time(), ''))
            self.assertTrue(health(self.store, db=db)['healthy'])
        self.assertTrue(self.publish(prepared)['published'])
        self.assertEqual(self.store.status('python-demo')['violations'], 0)

    def test_scoped_status_diff_staged_working_and_untracked(self):
        self.changed()
        self.git('add', 'src/calculator.py')
        self.changed()
        old = self.ask('read')
        self.ask('write', content='VALUE = 43\n', expected=old['sha256'])
        self.ask('create', path='new.txt', content='untracked\n')
        (self.repo / 'private/customer.txt').write_text('UNAPPROVED_PAYLOAD')
        result = self.operation('diff')
        self.assertTrue(result['allowed'], result)
        self.assertNotIn('UNAPPROVED_PAYLOAD', json.dumps(result))
        self.assertNotIn('private', json.dumps(result))
        self.assertEqual(result['status'], [{'path': 'src/calculator.py', 'staged': 'M', 'working': 'M'},
                                           {'path': 'src/new.txt', 'staged': ' ', 'working': 'A'}])
        self.assertIn('VALUE = 42', result['staged'][0]['patch'])
        self.assertIn('VALUE = 43', result['working'][0]['patch'])

    def test_hostile_config_attributes_hooks_environment_not_used(self):
        sentinel = self.root / 'EXECUTED'
        (self.repo / '.git/config').write_text('[core]\n hooksPath = ' + str(self.root) + '\n fsmonitor = touch ' + str(sentinel) +
            '\n[diff "evil"]\n textconv = touch ' + str(sentinel) + '\n[filter "evil"]\n clean = touch ' + str(sentinel) +
            '\n[credential]\n helper = !touch ' + str(sentinel) + '\n[include]\n path = /FORBIDDEN\n')
        (self.repo / 'src/.gitattributes').write_text('* filter=evil diff=evil\n')
        self.changed()
        with patch.dict(os.environ, {'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'core.fsmonitor',
                'GIT_CONFIG_VALUE_0': 'touch ' + str(sentinel), 'GIT_DIR': '/FORBIDDEN'}):
            result = self.operation('diff')
            checkpoint = self.checkpoint()
        self.assertTrue(result['allowed'], result)
        self.assertTrue(checkpoint['allowed'], checkpoint)
        target = self.store.directory / 'git-requests' / checkpoint['checkpoint'] / 'target/repository'
        self.assertFalse((target / 'config').exists())
        self.assertFalse((target / 'hooks').exists())
        self.assertFalse(sentinel.exists())

    def test_checkpoint_real_ref_preserves_branch_index_and_unrelated_tree(self):
        self.changed()
        (self.repo / 'private/customer.txt').write_text('unrelated staged work')
        self.git('add', 'private/customer.txt')
        head, index = self.git('rev-parse', 'HEAD'), (self.repo / '.git/index').read_bytes()
        result = self.checkpoint()
        self.assertTrue(result['allowed'], result)
        self.assertEqual(self.git('for-each-ref', 'refs/ptw'), b'')
        published = self.publish(result)
        self.assertEqual(self.git('show', published['ref'] + ':src/calculator.py'), b'VALUE = 42\n')
        self.assertEqual(self.git('rev-parse', published['ref'] + '^'), head)
        self.assertEqual(self.git('show', published['ref'] + ':private/customer.txt'),
                         self.git('show', 'HEAD:private/customer.txt'))
        self.assertEqual(self.git('rev-parse', 'HEAD'), head)
        self.assertEqual((self.repo / '.git/index').read_bytes(), index)
        self.assertEqual((self.repo / 'private/customer.txt').read_text(), 'unrelated staged work')
        self.assertFalse(self.store.status('python-demo')['stopped'])
        with self.assertRaises(Invalid):
            self.publish(result)

    def test_stale_review_content_index_base_and_approval_rejected(self):
        self.changed()
        original = self.checkpoint()
        with self.assertRaises(Invalid):
            from ptw.local_git import publish_checkpoint
            publish_checkpoint(self.store, original['checkpoint'], '0' * 64)
        self.ask('create', path='changed-after-review.txt', content='edit')
        with self.assertRaisesRegex(Invalid, 'Working files changed'):
            self.publish(original)
        fresh = self.checkpoint()
        self.git('add', 'src')
        with self.assertRaisesRegex(Invalid, 'HEAD or index changed'):
            self.publish(fresh)
        fresh = self.checkpoint()
        self.git('commit', '-m', 'concurrent operator commit')
        with self.assertRaisesRegex(Invalid, 'HEAD or index changed'):
            self.publish(fresh)

    def test_rejected_closed_stopped_and_monitor_loss_cannot_publish(self):
        self.changed()
        result = self.checkpoint()
        folder = self.store.directory / 'git-requests' / result['checkpoint']
        state = load(folder / 'state.json')
        from ptw.setup_transaction import atomic
        atomic(folder / 'state.json', {**state, 'phase': 'rejected'})
        with self.assertRaises(Invalid):
            self.publish(result)
        result = self.checkpoint()
        with patch('ptw.local_git.health', return_value={'healthy': False}), self.assertRaises(Invalid):
            self.publish(result)
        self.store.close_session(self.actor['token'])
        with self.assertRaises(Invalid):
            self.publish(result)
        self.actor = self.store.register('python-demo', 'implementation')
        result = self.checkpoint()
        self.store.stop('python-demo')
        with self.assertRaises(Invalid):
            self.publish(result)

    def test_unsafe_metadata_redirects_and_corruption_fail_closed(self):
        info = self.repo / '.git/objects/info'
        (info / 'alternates').write_text(str(self.root / 'outside'))
        result = self.operation('status')
        self.assertFalse(result['allowed'], result)
        (info / 'alternates').unlink()
        (self.repo / '.git/index').write_bytes(b'not-an-index')
        self.assertFalse(self.operation('status')['allowed'])
        self.assertEqual(self.store.status('python-demo')['violations'], 0)

    def test_parent_repo_linked_git_and_replaced_git_identity_rejected(self):
        from ptw.local_git import candidates
        nested = self.repo / 'src'
        with self.assertRaises(Invalid):
            candidates(nested, ['calculator.py'])
        (self.repo / '.git').rename(self.repo / 'old-git')
        (self.repo / '.git').symlink_to(self.repo / 'old-git', target_is_directory=True)
        self.assertFalse(self.operation('status')['allowed'])
        (self.repo / '.git').unlink()
        (self.repo / '.git').mkdir()
        self.assertFalse(self.operation('status')['allowed'])

    def test_narrow_delegate_cannot_checkpoint_or_expand_git_command(self):
        child = self.store.register('python-demo', 'readcheck', parent_token=self.actor['token'])
        content = json.dumps({'paths': ['src/calculator.py'], 'message': 'no write authority'})
        result = self.broker.request(child['token'], 'child-git', request('git_checkpoint', 'git-checkpoint', content=content))
        self.assertFalse(result['allowed'])
        self.assertEqual(self.store.status('python-demo')['violations'], 1)
        self.assertEqual(self.operation('status', content='--untracked-files=all')['allowed'], False)

    def test_no_model_approval_or_generic_run_bypass(self):
        self.assertFalse(self.ask('run', 'git-status', '')['allowed'])
        self.assertFalse(self.operation('checkpoint', content=json.dumps({'paths': ['src/calculator.py'],
            'message': 'x', 'approved': True}))['allowed'])
        self.assertFalse(self.operation('checkpoint', content=json.dumps({'paths': ['../secret'], 'message': 'x'}))['allowed'])

    def test_interrupted_publication_stops_project_and_preserves_existing_locks(self):
        self.changed()
        result = self.checkpoint()
        lock = self.repo / '.git/index.lock'
        lock.write_text('other git job')
        with self.assertRaises(FileExistsError):
            self.publish(result)
        self.assertEqual(lock.read_text(), 'other git job')
        self.assertFalse((self.repo / '.git/HEAD.lock').exists())
        lock.unlink()
        with patch('ptw.local_git.write_new', side_effect=OSError('synthetic disk failure')), self.assertRaisesRegex(OSError, 'synthetic disk failure'):
            self.publish(result)
        self.assertTrue(self.store.status('python-demo')['stopped'])
        self.assertEqual(self.git('for-each-ref', 'refs/ptw'), b'')
        with self.assertRaises(Invalid):
            self.publish(result)

    def test_checkpoint_deletion(self):
        self.changed()
        self.ask('create', path='binary.dat', content='before')
        self.git('add', 'src')
        self.git('commit', '-m', 'second fixture')
        data = self.ask('read', path='calculator.py')
        self.ask('delete', expected=data['sha256'])
        result = self.checkpoint(['src/calculator.py'])
        self.assertTrue(result['allowed'], result)
        published = self.publish(result)
        self.assertNotIn(b'calculator.py', self.git('ls-tree', '-r', published['ref']))

    def test_unborn_branch_binary_and_executable_checkpoint(self):
        self.git('symbolic-ref', 'HEAD', 'refs/heads/unborn')
        self.git('read-tree', '--empty')
        result = self.checkpoint()
        self.assertTrue(result['allowed'], result)
        published = self.publish(result)
        self.assertNotIn(b'parent ', self.git('cat-file', '-p', published['commit']))
        # Switch back to the fixture branch; executable staging metadata and raw
        # binary changes exercise both formats without invoking any filters.
        self.git('symbolic-ref', 'HEAD', 'refs/heads/main')
        self.git('read-tree', 'HEAD')
        self.git('update-index', '--chmod=+x', 'src/calculator.py')
        old = self.ask('read')
        self.ask('write', content='binary\x00value', expected=old['sha256'])
        result = self.operation('diff')
        self.assertTrue(result['allowed'], result)
        self.assertEqual(result['staged'][0]['new_mode'], '100755')
        self.assertTrue(result['working'][0]['binary'])
        prepared = self.checkpoint()
        with self.assertRaisesRegex(Invalid, 'incomplete'):
            self.publish(prepared)
        self.assertFalse((self.repo / '.git/refs/ptw/checkpoints' / prepared['checkpoint']).exists())

    def test_packed_objects_refs_and_request_replay(self):
        self.git('gc', '--prune=now')
        self.changed()
        content = json.dumps({'paths': ['src/calculator.py'], 'message': 'packed repository'})
        req = request('git_checkpoint', 'git-checkpoint', content=content)
        result = self.broker.request(self.actor['token'], 'repeat', req)
        self.assertTrue(result['allowed'], result)
        replay = self.broker.request(self.actor['token'], 'repeat', req)
        self.assertTrue(replay['replayed'])
        self.assertEqual(replay['checkpoint'], result['checkpoint'])
        self.assertTrue(self.publish(result)['published'])

    def test_corrupt_or_redirected_object_and_ref_rejected_without_external_read(self):
        head = self.git('rev-parse', 'HEAD').decode().strip()
        object_file = self.repo / '.git/objects' / head[:2] / head[2:]
        original = object_file.read_bytes()
        object_file.unlink()
        object_file.symlink_to(self.repo / 'private/customer.txt')
        self.assertFalse(self.operation('status')['allowed'])
        object_file.unlink()
        object_file.write_bytes(original)
        (self.repo / '.git/HEAD').write_text('ref: refs/heads/../../outside\n')
        self.assertFalse(self.operation('status')['allowed'])
        self.assertEqual(self.store.status('python-demo')['violations'], 0)

    def test_new_authority_is_explicit_and_model_cannot_modify_definition(self):
        from ptw.policy import compile_policy
        from ptw.onboarding import review_text, short_review
        for text in (review_text(self.approve()), short_review(self.approve(), {}, [])):
            self.assertIn('Local Git', text)
            self.assertIn('checkpoint', text)
        policy = copy.deepcopy(self.policy)
        policy['project']['commands'][-1]['argv'] = ['/usr/bin/git', 'push']
        with self.assertRaises(Invalid):
            compile_policy(policy, self.inv)
        policy = copy.deepcopy(self.policy)
        policy['project']['commands'][-1]['git']['approve'] = True
        with self.assertRaises(Invalid):
            compile_policy(policy, self.inv)

    def test_failed_worker_and_monitor_leave_no_host_writes(self):
        self.changed()
        with patch('ptw.local_git.execute', side_effect=Invalid('supervised failure')):
            self.assertFalse(self.checkpoint()['allowed'])
        with patch('ptw.local_git.health', return_value={'healthy': False}):
            self.assertFalse(self.checkpoint()['allowed'])
        self.assertEqual(self.git('for-each-ref', 'refs/ptw'), b'')
        self.assertEqual(self.store.status('python-demo')['violations'], 0)


class JourneyEvidenceTests(unittest.TestCase):
    def test_revision_scope_requires_exact_reviewed_metadata_delta(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
        from product_daily_acceptance import check_revision_scope
        from ptw.project_example import create
        with tempfile.TemporaryDirectory(prefix='ptw-daily-revision-') as directory:
            root = Path(directory)
            create(root / 'example', 'python')
            before = {'policy': load(root / 'example/policy.json'),
                      'inventory': load(root / 'example/inventory.json')}
        after = copy.deepcopy(before)
        key = 'dependency-940c1143f96e'
        after['inventory']['resources'][key] = {
            'path': 'ptw-requirements.txt', 'kind': 'file', 'description': 'Reviewed dependency metadata'}
        for scope in (after['policy']['project'], after['policy']['tasks'][0]):
            scope['grants'].append({'resource': key, 'actions': ['read']})
        check_revision_scope(before, after, self.assertTrue)
        original = copy.deepcopy(before)
        # Removing the expected addition or admitting any unrelated authority
        # must fail, including changes to the narrower and independent tasks.
        mutations = [
            lambda b: b['inventory']['resources'][key].update(path='private/customer.txt'),
            lambda b: b['inventory'].update(root='/foreign'),
            lambda b: b['policy']['project']['grants'].pop(),
            lambda b: b['policy']['project']['grants'][-1]['actions'].append('write'),
            lambda b: b['policy']['project']['grants'][0]['actions'].clear(),
            lambda b: b['policy']['project']['commands'].clear(),
            lambda b: b['policy']['project']['escalation'].update(stop_at=99),
            lambda b: b['policy']['project'].update(python_runtime={'executable': '/foreign'}),
            lambda b: b['policy']['project']['packages']['allowed_names'].append('pypi:unapproved'),
            lambda b: b['policy']['tasks'][0]['grants'].pop(),
            lambda b: b['policy']['tasks'][1]['grants'].append({'resource': key, 'actions': ['read']}),
            lambda b: b['policy']['tasks'][2]['grants'][0]['actions'].append('write'),
            lambda b: b['policy']['tasks'][2]['packages'].append('pypi:unapproved'),
            lambda b: b['policy']['tasks'].pop(),
        ]
        for index, mutate in enumerate(mutations):
            changed = copy.deepcopy(after)
            mutate(changed)
            with self.subTest(mutation=index), self.assertRaises(AssertionError):
                check_revision_scope(before, changed, self.assertTrue)
        self.assertEqual(before, original)

    def test_surface_gate_requires_exact_broker_names_and_absent_host_globals(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
        from product_daily_acceptance import bounded_surface
        value = {'tool_names': ['mcp__ptw__project_context', 'mcp__ptw__project_action'],
                 'process_type': 'undefined', 'require_type': 'undefined', 'fetch_type': 'undefined'}
        self.assertTrue(bounded_surface(value))
        for malformed in (None, [], {}, {**value, 'fetch_type': 'function'},
                          {**value, 'tool_names': ['mcp__ptw__project_context']},
                          {**value, 'tool_names': value['tool_names'] + [None]}):
            self.assertFalse(bounded_surface(malformed))
        for bypass in ('exec_command', 'apply_patch', 'mcp__app__read', 'plugin_tool',
                       'evil_project_action', 'mcp__ptw__project_context'):
            with self.subTest(bypass=bypass):
                self.assertFalse(bounded_surface({**value, 'tool_names': value['tool_names'] + [bypass]}))

    def test_only_actual_actor_completed_successful_effects_satisfy_live_gate(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
        from product_daily_acceptance import successful_actions
        event = {'session': 'live-parent', 'state': 'complete',
                 'request': {'action': 'run', 'resource': 'test'},
                 'result': {'allowed': True, 'exit_code': 0}}
        required = [('run', 'test')]
        self.assertTrue(successful_actions([event], 'live-parent', required))
        for change in ({'session': 'scripted-probe'}, {'state': 'pending'},
                       {'request': {'action': 'read', 'resource': 'test'}},
                       {'result': {'allowed': True, 'exit_code': 1}},
                       {'result': {'allowed': True, 'content': 'Tests passed'}},
                       {'result': {'allowed': False, 'exit_code': 0}},
                       {'result': {'allowed': True, 'exit_code': 0, 'replayed': True}}):
            with self.subTest(change=change):
                self.assertFalse(successful_actions([{**event, **change}], 'live-parent', required))
        self.assertFalse(successful_actions([event], 'live-parent', required + [('run', 'build')]))

    def test_physical_git_gate_does_not_confuse_reconciliation_flag_with_process_state(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
        from product_daily_acceptance import physical_workloads
        store = SimpleNamespace(status=lambda project: {'workloads': [{'unit': 'worker', 'stopped': 0}]})
        with patch('product_daily_acceptance.Supervisor.state', return_value={'confirmed_stopped': True}) as state:
            self.assertEqual(physical_workloads(store, 'project'), [{'unit': 'worker', 'confirmed_stopped': True}])
            state.assert_called_once_with('worker')
        store.status = lambda project: {'workloads': [{'unit': 'worker', 'stopped': 1}]}
        for native in ({'confirmed_stopped': False, 'ActiveState': 'active'},
                       {'confirmed_stopped': False, 'error': 'Cannot query supervisor'}):
            with self.subTest(native=native), patch('product_daily_acceptance.Supervisor.state', return_value=native):
                self.assertFalse(physical_workloads(store, 'project')[0]['confirmed_stopped'])


@unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1',
                     'requires manager native PTY, systemd, namespaces and live pinned Codex')
class NativeDailyTests(unittest.TestCase):
    def test_safe_git_native(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
        from product_daily_acceptance import git_journey
        root = Path(tempfile.mkdtemp(prefix='ptw-daily-git-'))
        print('DAILY_EVIDENCE ' + str(root), flush=True)
        self.assertTrue(git_journey(root)['passed'])

    def test_bounded_preview_native(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
        from product_daily_acceptance import preview_journey
        root = Path(tempfile.mkdtemp(prefix='ptw-daily-preview-'))
        print('DAILY_EVIDENCE ' + str(root), flush=True)
        self.assertTrue(preview_journey(root)['passed'])

    def test_protected_resume_live(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
        from product_daily_acceptance import resume_journey
        root = Path(tempfile.mkdtemp(prefix='ptw-daily-resume-'))
        print('DAILY_EVIDENCE ' + str(root), flush=True)
        self.assertTrue(resume_journey(root)['passed'])
