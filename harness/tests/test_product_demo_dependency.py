"""Dependency demo milestone. Native tests are mandatory and never skipped.

Offline namespace records are synthetic verifier inputs, not physical evidence.
"""
import copy
import errno
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import demo_dependency as dependency
from evidence_io import digest, load, save


class DependencyOfflineTests(unittest.TestCase):
    def test_public_projection_hides_private_artifact_names_and_retains_bindings(self):
        import hashlib
        from demo_evidence import public_sample
        from ptw.policy import digest as json_digest
        # Synthetic envelope inputs only; this does not claim native execution.
        paths = ['cases/result.json', 'cases/package/direct_url.json',
                 'cases/session_meta/private-operator.json', 'cases/Bearer private-name.txt',
                 'cases/\u79c1\u5bc6/customer-name.json']
        refs = [{'path': path, 'sha256': hashlib.sha256(path.encode()).hexdigest()} for path in paths]
        runtime = {'ptw/__init__.py': 'a' * 64}
        source = {'runtime_sha256': runtime, 'distribution_inputs_sha256': {'pyproject.toml': 'b' * 64}}
        with tempfile.TemporaryDirectory() as name:
            out = Path(name)
            save(out / 'timing.json', {'warm_seconds': 12.5})
            for demo in ('dependency', 'task-scope'):
                with self.subTest(demo=demo):
                    save(out / 'result.json', {'demo': demo, 'source': source,
                         'installed': {'runtime_sha256': runtime, 'dependency_versions': {'example': '1.0'}},
                         'artifacts': refs, 'private_log': 'Bearer synthetic-private-content'})
                    original = (out / 'result.json').read_bytes()
                    sample = public_sample(out)
                    encoded = json.dumps(sample, ensure_ascii=False)
                    for private in (*paths, 'direct_url', 'session_meta', 'private-operator',
                                    'Bearer ', 'customer-name', 'synthetic-private-content'):
                        self.assertNotIn(private, encoded)
                    self.assertEqual(sample['payload']['original_artifacts'], [
                        {'path_sha256': hashlib.sha256(r['path'].encode('utf-8')).hexdigest(),
                         'original_sha256': r['sha256']} for r in refs])
                    self.assertEqual(sample['original_result_sha256'], digest(out / 'result.json'))
                    self.assertEqual(sample['public_payload_sha256'], json_digest(sample['payload']))
                    self.assertEqual(sample['payload']['runtime_sha256'], runtime)
                    self.assertEqual(sample['payload']['warm_seconds'], 12.5)
                    self.assertEqual((out / 'result.json').read_bytes(), original)
                    changed = load(out / 'result.json')
                    changed['artifacts'][0]['sha256'] = 'c' * 64
                    save(out / 'result.json', changed)
                    updated = public_sample(out)
                    self.assertNotEqual(updated['original_result_sha256'], sample['original_result_sha256'])
                    self.assertNotEqual(updated['public_payload_sha256'], sample['public_payload_sha256'])

    def test_python_version_requires_original_process_receipt(self):
        from demo_evidence import verify_version_process
        from evidence_io import capture, reference
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            process = capture([sys.executable, '--version'], root / 'python')
            tool = {'path': sys.executable, 'sha256': digest(sys.executable),
                    'receipt': reference(root, root / 'python/process.json')}
            version = process.stdout.decode().strip()
            verify_version_process(root, tool, version)
            with self.assertRaisesRegex(ValueError, 'Version contradicts'):
                verify_version_process(root, tool, 'Python 0.invalid')
            (root / 'python/stdout').write_text('Python 0.invalid\n')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                verify_version_process(root, tool, 'Python 0.invalid')

    def test_shared_cli_help_invalid_input_and_missing_evidence(self):
        import subprocess
        for arguments, expected, text in (
                (['--help'], 0, '--demo'),
                (['run', '--demo', 'unknown', '--out', '/unused'], 2, 'invalid choice'),
                (['run', '--demo', 'dependency'], 2, '--out'),
                (['verify', '--out', '/missing-demo-receipt'], 2, 'Demo failed:')):
            with self.subTest(arguments=arguments):
                result = subprocess.run([sys.executable, '-B', SCRIPTS / 'product_demo.py', *arguments],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertIn(text, result.stdout + result.stderr)

    def test_shared_runner_rejects_reuse_links_and_unknown_demo_before_execution(self):
        import demo_evidence
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            with self.assertRaises(FileExistsError):
                demo_evidence.run(root, 'dependency')
            alias = root / 'alias'
            alias.symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'canonical'):
                demo_evidence.run(alias / 'new', 'task-scope')
            with self.assertRaisesRegex(ValueError, 'Unsupported'):
                demo_evidence.run(root / 'new', 'unknown')
            self.assertFalse((root / 'new').exists())

    def test_shared_failure_and_interruption_leave_unverifiable_receipt(self):
        import demo_evidence
        import product_demo
        with tempfile.TemporaryDirectory() as name:
            for index, error in enumerate((ValueError('synthetic install mismatch'), KeyboardInterrupt())):
                out = Path(name) / str(index)
                with patch.object(product_demo, 'installed_identity', side_effect=error):
                    with self.assertRaises(type(error)):
                        demo_evidence.run(out, 'dependency')
                self.assertFalse(load(out / 'failed.json')['complete'])
                self.assertEqual(load(out / 'failed.json')['error_type'], type(error).__name__)
                self.assertFalse((out / 'result.json').exists())
                with self.assertRaises((ValueError, OSError)):
                    product_demo.verify(out)

    def test_shared_artifact_inventory_rejects_linked_receipts(self):
        import demo_evidence
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / 'receipt.json').write_text('{}')
            (root / 'link').symlink_to(root / 'receipt.json')
            with self.assertRaisesRegex(ValueError, 'Linked'):
                demo_evidence.files(root, 'dependency')

    def test_outer_runtime_preserves_uv_alias_without_mounting_its_parent(self):
        from demo_dependency_comparison import python_runtime_mounts
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            runtime, installation = root / 'cache/cpython-3.12.13', root / 'installation'
            for folder in (runtime, installation):
                (folder / 'bin').mkdir(parents=True)
            interpreter = runtime / 'bin/python3.12'
            interpreter.write_text('synthetic interpreter; never executed')
            alias = runtime.with_name('cpython-3.12')
            alias.symlink_to(runtime.name, target_is_directory=True)
            executable = installation / 'bin/python'
            executable.symlink_to(alias / 'bin/python3.12')
            with patch('sys.prefix', str(installation)), patch('sys.base_prefix', str(runtime)), \
                    patch('sys.executable', str(executable)):
                mounts = python_runtime_mounts()
                self.assertEqual(mounts, ['--ro-bind', str(installation), str(installation),
                                         '--ro-bind', str(runtime), str(runtime),
                                         '--ro-bind', str(runtime), str(alias)])
                self.assertNotIn(str(runtime.parent), mounts)
                # The canonical interpreter requires no additional alias mount.
                executable.unlink()
                executable.symlink_to(interpreter)
                self.assertEqual(python_runtime_mounts(), mounts[:6])
                # A missing runtime must fail before any launcher runs.
                interpreter.unlink()
                with self.assertRaises(ValueError):
                    python_runtime_mounts()

    def test_outer_runtime_rejects_a_different_interpreter_tree(self):
        from demo_dependency_comparison import python_runtime_mounts
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            runtime, installation, other = root / 'runtime', root / 'installation', root / 'other'
            for folder in (runtime, installation, other):
                (folder / 'bin').mkdir(parents=True)
            (other / 'bin/python').write_text('synthetic interpreter; never executed')
            executable = installation / 'bin/python'
            executable.symlink_to(other / 'bin/python')
            with patch('sys.prefix', str(installation)), patch('sys.base_prefix', str(runtime)), \
                    patch('sys.executable', str(executable)):
                with self.assertRaisesRegex(ValueError, 'same Python runtime'):
                    python_runtime_mounts()

    def test_wheel_boundary_extraction_preserves_installed_builder_arguments(self):
        from ptw.python_local import wheel_command
        with patch('ptw.python_local.runtime_namespace', return_value=['bwrap', '--unshare-all']):
            self.assertEqual(wheel_command('/uv-file', '/wheels', '/output', '/usr/bin/python3', ''),
                ['bwrap', '--unshare-all', '--ro-bind', '/uv-file', '/uv', '--ro-bind', '/wheels', '/artifacts',
                 '--bind', '/output', '/target', '--', '/uv', '--no-config', '--offline', '--no-cache',
                 '--no-python-downloads', 'build', '--wheel', '--no-sources', '--no-index', '--find-links',
                 '/artifacts', '--build-constraints', '/artifacts/constraints.txt', '--python', '/usr/bin/python3',
                 '--out-dir', '/target/out', '/target/source'])
            self.assertEqual(wheel_command('/uv', '/wheels', '/out', '/usr/bin/python3', 'project')[-1],
                             '/target/source/project')

    def test_broad_requires_outer_namespace_and_only_exposes_synthetic_secret(self):
        from demo_dependency_comparison import broad_command
        command = ['bwrap', '--unshare-all', '--bind', '/seed', '/target', '--', '/nono',
                   'run', '--block-net', '--allow', '/target', '--', '/usr/bin/python3', '/target/app.py']
        with patch.dict(os.environ, {}, clear=True), patch('os.readlink', return_value='net:[222]'):
            with self.assertRaisesRegex(ValueError, 'outer network'):
                broad_command(command, Path('/synthetic/host-credentials/token.txt'))
            os.environ['PTW_DEMO_OUTER_NET'] = 'net:[222]'
            result = broad_command(command, Path('/synthetic/host-credentials/token.txt'))
            with self.assertRaisesRegex(ValueError, 'synthetic credential fixture'):
                broad_command(command, Path('/host-credentials/token.txt'))
        self.assertEqual(result, ['bwrap', '--unshare-all', '--bind', '/seed', '/target', '--share-net',
                                 '--tmpfs', '/synthetic', '--ro-bind',
                                 '/synthetic/host-credentials/token.txt', '/synthetic/host-credentials/token.txt',
                                 '--remount-ro', '/synthetic', '--',
                                 '/usr/bin/python3', '/target/app.py'])
        self.assertIn('--block-net', command)  # original protected boundary unchanged

    def test_collector_requires_exact_broad_values_and_live_window_controls(self):
        from demo_dependency_comparison import verify_collector
        rows = [{'path': '/control', 'body': 'broad-before'}]
        rows += [{'path': path, 'body': body} for path, body in
                 [('/secret', dependency.SECRET), ('/canary', dependency.CANARY)] * 4]
        rows += [{'path': '/control', 'body': 'broad-after'}]
        verify_collector(rows, broad=True)
        for altered in (rows[:-1], rows[:3] + rows[4:], rows + [{'path': '/leak', 'body': 'x'}], []):
            with self.assertRaises(ValueError):
                verify_collector(altered, broad=True)
        protected = [{'path': '/control', 'body': 'sandbox-before'},
                     {'path': '/control', 'body': 'sandbox-after'}]
        verify_collector(protected, broad=False)
        with self.assertRaises(ValueError):
            verify_collector([protected[0], {'path': '/canary', 'body': dependency.CANARY}, protected[1]], broad=False)

    def test_import_child_receipts_require_independent_processes(self):
        from demo_dependency_comparison import verify_import_attempts
        attempts = [{'route': 'invoice_dep', 'pid': 10, 'ppid': 9, 'read': 'FileNotFoundError',
                     'canary_send': 'PermissionError', 'policy_edit': errno.ENOENT},
                    {'route': '__probe_child__', 'pid': 11, 'ppid': 10, 'read': 'FileNotFoundError',
                     'canary_send': 'PermissionError', 'policy_edit': errno.ENOENT}]
        def result(rows):
            return {'output': '\n'.join('DEPENDENCY_ATTEMPT ' + json.dumps(r) for r in rows)}
        observations = {'observations': [{'namespace_pid': pid, 'operator_policy': {'read': False, 'errno': 2}}
                                        for pid in (10, 11)]}
        verify_import_attempts(result(attempts), observations, broad=False)
        broad = [{**r, 'read': 'obtained', 'secret_send': 200, 'canary_send': 200,
                  'policy_edit': errno.EROFS} for r in attempts]
        verify_import_attempts(result(broad), observations, broad=True)
        for mode in ('created-policy', 'visible-policy', 'wrong-denial'):
            rows, observed = copy.deepcopy(broad), copy.deepcopy(observations)
            if mode == 'created-policy':
                rows[0]['policy_edit'] = 'written'
            elif mode == 'visible-policy':
                observed['observations'][1]['operator_policy'] = {'read': True, 'sha256': 'a' * 64}
            else:
                rows[0]['policy_edit'] = errno.EACCES
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                verify_import_attempts(result(rows), observed, broad=True)
        for rows, observed in ((attempts[:1], observations), (attempts, {'observations': []}),
                               ([attempts[0], {**attempts[1], 'ppid': 999}], observations),
                               ([{**attempts[0], 'read': 'obtained'}, attempts[1]], observations)):
            with self.assertRaises(ValueError):
                verify_import_attempts(result(rows), observed, broad=False)

    def test_boundary_normalization_never_erases_payload_permissions(self):
        from demo_dependency_comparison import normalized_boundary
        command = ['bwrap', '--ro-bind', '/private/seed', '/seed', '--ro-bind', '/site', '/python-packages',
                   '--', '/nono', '--read', '/python-packages', '--allow', '/target', '--', 'python']
        normalized = normalized_boundary(command)
        self.assertEqual(normalized[2], '<seed>')
        self.assertEqual(normalized[5], '<python-packages>')
        self.assertEqual(normalized[7:], command[7:])
        self.assertNotEqual(normalized_boundary([*command[:10], '--allow', *command[11:]]), normalized)

    def observe_candidates(self, root, results):
        """Synthetic /proc lifecycle only; no authorization or native proof."""
        from demo_namespace import observe
        group = root / 'synthetic-cgroup'
        group.mkdir()
        (group / 'cgroup.procs').write_text('321\n')
        store = MagicMock()
        unit = {'unit': 'ptw-' + 'a' * 24 + '.service', 'session': 's'}
        store.locked.return_value.__enter__.return_value.execute.return_value = [unit]
        finished = threading.Event()
        attempts = []

        def inspect(*args):
            result = results[min(len(attempts), len(results) - 1)]
            attempts.append(args)
            if len(attempts) >= len(results):
                finished.set()
            if isinstance(result, BaseException):
                raise result
            return result

        with patch('demo_namespace.Path', return_value=group), \
                patch('demo_namespace.inspect', side_effect=inspect), \
                patch('ptw.supervisor.Supervisor.state', return_value={'ControlGroup': '/synthetic'}):
            with observe(store, 'synthetic', root / 'secret', '/target/fixture', 'a' * 64,
                         root / 'observer'):
                self.assertTrue(finished.wait(2), 'Observer stopped before inspecting remaining candidates')
        return load(root / 'observer/namespace.json')

    def test_inaccessible_candidate_does_not_stop_later_observation(self):
        with tempfile.TemporaryDirectory() as name:
            row = {'pid': 321, 'marker': '/target/fixture'}
            value = self.observe_candidates(Path(name), [PermissionError(errno.EACCES, 'synthetic'), row])
            self.assertEqual(value['errors'], [])
            self.assertEqual(len(value['observations']), 1)
            self.assertEqual(value['observations'][0]['marker'], row['marker'])
            self.assertEqual(value['unavailable_candidates'][0]['errno'], errno.EACCES)
            self.assertEqual(value['unavailable_candidates'][0]['samples'], 1)

    def test_persistent_proc_denial_is_missing_evidence(self):
        from demo_namespace import verify
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            value = self.observe_candidates(root, [PermissionError(errno.EACCES, 'synthetic')] * 2)
            self.assertEqual(value['observations'], [])
            self.assertGreaterEqual(value['unavailable_candidates'][0]['samples'], 2)
            with self.assertRaisesRegex(ValueError, 'Missing independent'):
                verify(root / 'observer', secret=root / 'secret', marker='/target/fixture',
                       expected='a' * 64, sessions={'s'})

    def test_unexpected_observer_failure_remains_fatal(self):
        from demo_namespace import verify
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            value = self.observe_candidates(root, [RuntimeError('synthetic observer defect')])
            self.assertEqual(value['errors'][0]['type'], 'RuntimeError')
            with self.assertRaisesRegex(ValueError, 'Missing independent'):
                verify(root / 'observer', secret=root / 'secret', marker='/target/fixture',
                       expected='a' * 64, sessions={'s'})

    def test_invoice_oracle_and_executable_variants(self):
        self.assertEqual(dependency.expected_invoice(), {'invoice_total_cents': 4600, 'invoice_lines': 2})
        for variant in ('clean', 'tolerant', 'abort'):
            source = dependency.module_source(Path('/synthetic-only/token'), 12345, variant)
            compile(source, '<reviewed fixture>', 'exec')
            self.assertIn('SYNTHETIC_AVAILABLE_TRANSFER_CANARY', source)
        compile(dependency.BACKEND, '<reviewed backend>', 'exec')
        compile(dependency.APP, '<invoice application>', 'exec')
        with self.assertRaises(ValueError):
            dependency.module_source(Path('/synthetic-only/token'), 12345, 'unknown')

    def test_clean_replacement_review_is_staged_and_does_not_widen_authority(self):
        from ptw.policy import check_approval
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            store, actor, old, secret = dependency.fixture(root, 12345, 'abort')
            source = root / 'repo/src/invoice_dep/__init__.py'
            before = source.read_bytes()
            stage, new, changes, expected = dependency.replacement_candidate(root, 12345, old)
            check_approval(new)
            self.assertEqual(source.read_bytes(), before)
            self.assertEqual(load(root / 'approved.json'), old)
            policy = copy.deepcopy(old['policy'])
            policy['project']['python_dependencies']['sources'][0]['snapshot_sha256'] = (
                new['policy']['project']['python_dependencies']['sources'][0]['snapshot_sha256'])
            self.assertEqual(new['policy'], policy)
            self.assertEqual(new['inventory'], old['inventory'])
            self.assertNotEqual(new['approval']['sha256'], old['approval']['sha256'])
            self.assertEqual(changes, {'src/invoice_dep/__init__.py': dependency.module_source(secret, 12345, 'clean')})
            self.assertEqual(set(expected), set(changes))
            self.assertEqual(load(stage / 'review.json')['reviewed_sha256'], new['approval']['sha256'])
            self.assertIn('scripted', load(stage / 'review.json')['mode'])
            self.assertEqual(store.status(dependency.PROJECT)['policy_sha256'], old['approval']['sha256'])
            with self.assertRaises(FileExistsError):
                dependency.replacement_candidate(root, 12345, old)

    def test_replacement_rejects_wrong_fixture_without_touching_live_source(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            store, actor, old, _ = dependency.fixture(root, 12345, 'clean')
            source = root / 'repo/src/invoice_dep/__init__.py'
            before = source.read_bytes()
            with self.assertRaisesRegex(ValueError, 'reviewed abort fixture'):
                dependency.replacement_candidate(root, 12345, old)
            self.assertEqual(source.read_bytes(), before)
            self.assertEqual(store.status(dependency.PROJECT)['policy_sha256'], old['approval']['sha256'])
            self.assertFalse((root / 'replacement/approved.json').exists())

    def test_missing_observation_never_proves_secret_denial(self):
        from demo_namespace import verify
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            secret = root / 'synthetic.txt'
            secret.write_text(dependency.SECRET)
            for value in ({'observations': [], 'errors': []},
                          {'observations': [], 'errors': [{'type': 'PermissionError'}]}):
                save(root / 'namespace.json', value)
                with self.assertRaisesRegex(ValueError, 'Missing independent'):
                    verify(root, secret=secret, marker='/target/fixture', expected='a' * 64, sessions={'s'})

    def test_contradictory_observer_data_rejected(self):
        from demo_namespace import verify
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            secret = root / 'synthetic.txt'
            secret.write_text(dependency.SECRET)
            unit = 'ptw-' + 'a' * 24 + '.service'
            row = {'pid': 321, 'start_ticks': '100', 'session': 's', 'unit': unit,
                   'network': 'net:[123]', 'host_network': 'net:[456]',
                   'marker': '/target/fixture', 'marker_sha256': 'a' * 64,
                   'secret': str(secret), 'host_secret_sha256': digest(secret),
                   'mountinfo': 'synthetic unit-test input only', 'cgroup': '0::/' + unit,
                   'observation': {'read': False, 'errno': 2}}
            def check(value):
                save(root / 'namespace.json', {'observations': [value], 'errors': []})
                return verify(root, secret=secret, marker='/target/fixture', expected='a' * 64, sessions={'s'})
            check(row)
            for change in ({'observation': {'read': True, 'sha256': digest(secret)}},
                           {'observation': {'read': False, 'errno': 13}},
                           {'session': 'another'}, {'network': 'net:[456]'},
                           {'marker_sha256': 'b' * 64}, {'host_secret_sha256': 'b' * 64},
                           {'pid': 0}, {'cgroup': ''}):
                with self.subTest(change=change), self.assertRaises(ValueError):
                    check({**copy.deepcopy(row), **change})


class NativeDependencyTests(unittest.TestCase):
    def test_installed_executing_wheel_and_independent_namespace(self):
        """Fresh installed package, real offline build/import/child and collector."""
        from product_ecosystems_acceptance import build_test_wheel, wheel_step
        from product_install import clean_env
        root = Path(tempfile.mkdtemp(prefix='ptw-dependency-installed-'))
        print('DEPENDENCY_MILESTONE_EVIDENCE ' + str(root), flush=True)
        import product_demo
        save(root / 'source.json', product_demo.source_identity())
        try:
            import time
            cold_start = time.monotonic()
            cold_epoch = time.time()
            wheel, _ = build_test_wheel(root / 'build')
            env = clean_env(root)
            uv = shutil.which('uv')
            self.assertIsNotNone(uv)
            python = root / 'installation/bin/python'
            wheel_step([uv, '--no-config', 'venv', '--no-python-downloads', '--python', sys.executable,
                        root / 'installation'], root / 'venv.json', env)
            wheel_step([uv, '--no-config', 'pip', 'sync', '--python', python, '--require-hashes',
                        '--only-binary', ':all:', SCRIPTS.parent / 'requirements.lock'], root / 'dependencies.json', env)
            wheel_step([uv, '--no-config', 'pip', 'install', '--python', python, '--no-deps', wheel],
                        root / 'install.json', env)
            save(root / 'cold-setup.json', {'started_epoch': cold_epoch, 'ended_epoch': time.time(),
                'seconds': time.monotonic() - cold_start,
                'scope': 'fresh wheel build, venv, hashed dependency sync and wheel install',
                'prerequisites': 'existing uv/nono/bubblewrap/systemd and available dependency cache; no OS provisioning'})
            env['PATH'] = str(python.parent) + os.pathsep + env.get('PATH', '')
            from terminal_driver import Terminal
            terminal = Terminal([python, '-B', SCRIPTS / 'product_demo.py', 'run', '--demo', 'dependency',
                                 '--out', root / 'run'], root / 'run-terminal', env=env, replace_env=True)
            try:
                terminal.wait(lambda: terminal.exited, 180, 'dependency demo completion')
                self.assertEqual(terminal.close(graceful=False), 0, terminal.text)
                self.assertIn('"verified": true', terminal.text)
            finally:
                terminal.close(graceful=False)
            result = load(root / 'run/cases/outcome.json')
            native_probe(root / 'run/cases')
            from demo_evidence_tests import check_envelope_mutations, check_installed_cli
            check_envelope_mutations(self, root / 'run')
            check_installed_cli(self, root, python, env, 'dependency')
            self.assertEqual(result['tolerant']['application'], dependency.expected_invoice())
            self.assertEqual(result['abort']['result'], 'safe-incompletion')
            self.assertEqual(result['abort']['replacement']['result'], 'completed-after-reviewed-replacement')
            self.assertEqual(result['abort']['replacement']['application'], dependency.expected_invoice())
            self.assertEqual(result['clean']['application'], dependency.expected_invoice())
            self.assertEqual(result['comparison']['prevention'], 'tie; underlying confinement')
        except BaseException as exc:
            save(root / 'failed.json', {'type': type(exc).__name__, 'complete': False})
            raise


def native_probe(out):
    from demo_dependency_comparison import verify_comparison
    dependency.verify(out)
    target = out / 'abort/replacement/action.json'
    original = target.read_bytes()
    try:
        save(target, {**load(target), 'exit_code': 1})
        with unittest.TestCase().assertRaises(ValueError):
            dependency.verify_replacement(out / 'abort', load(out / 'collector-port.json')['port'])
    finally:
        target.write_bytes(original)
    target = out / 'comparison/broad/collector.json'
    original = target.read_bytes()
    try:
        changed = load(target)
        changed['requests'][1]['body'] = 'wrong synthetic value'
        save(target, changed)
        with unittest.TestCase().assertRaises(ValueError):
            verify_comparison(out / 'comparison', out / 'tolerant')
    finally:
        target.write_bytes(original)
    dependency.verify(out)


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--dependency-native-probe':
        native_probe(Path(sys.argv[2]))
    else:
        unittest.main()
