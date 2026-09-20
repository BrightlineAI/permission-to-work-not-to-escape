"""Release artifacts and installed CLI behavior, not publication certification.

Offline mutation fixtures are explicitly synthetic. The native case retains the
real builder, installation and all demo originals outside the source checkout.
"""
import io
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import build_product_release as builder
import prepare_product_release as preparation
import product_install as installer
from evidence_io import capture, load, reference, save


class ReleaseArtifactTests(unittest.TestCase):
    def setUp(self):
        import test_product_install as fixtures
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(prefix='ptw-release-fixture-')))
        self.archive = fixtures.release_fixture()

    def fake_build(self, out, repo):
        """Real assembled source bytes; no claim of dependency installation."""
        out.mkdir()
        name = 'ptw-0.5.0-linux-x86_64.tar.gz'
        (out / name).write_bytes(self.archive)
        url = 'https://github.com/BrightlineAI/permission-to-work-not-to-escape/releases/download/harness-v0.5.0/' + name
        (out / 'install.sh').write_bytes(builder.bootstrap(
            (repo / 'harness/scripts/product_install.py').read_bytes(), installer.sha(self.archive), url))
        return {'archive': name, 'url': url}

    def test_prepare_emits_only_reviewed_assets_digests_and_matching_bootstrap(self):
        out = self.root / 'candidate'
        with patch.object(preparation, 'build', side_effect=self.fake_build):
            value = preparation.prepare(out)
        self.assertEqual(load(out / 'release.json'), value)
        self.assertEqual(value['tag'], 'harness-v0.5.0')
        self.assertEqual(value['status'], 'private-candidate-unvalidated')
        self.assertEqual({Path(a['path']).name for a in value['assets']},
                         {'ptw-0.5.0-linux-x86_64.tar.gz', 'install.sh', 'RELEASE.md', 'SHA256SUMS'})
        for asset in value['assets']:
            self.assertEqual(installer.sha(Path(asset['path']).read_bytes()), asset['sha256'])
        _, contents = installer.release_files(self.archive)
        self.assertEqual(set(contents) - {'permission_to_work_harness-0.5.0-py3-none-any.whl'},
                         {'requirements.lock', 'package.json', 'package-lock.json', 'product_install.py',
                          'INSTALL.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md'})
        notes = (out / 'RELEASE.md').read_text()
        for required in ('INCIDENT_SAFETY_ACCEPTANCE.json', 'original-only', 'AT1/AT3', 'AT2',
                         '<=30-second', 'eight-case/16-call', 'unvalidated', 'raw logs',
                         'ptw demo run --demo swarm', 'ptw-install uninstall'):
            self.assertIn(required, notes)
        for private in ('Bearer ', '/home/loon/', 'session_meta', 'customer@example'):
            self.assertNotIn(private, notes)

    def test_missing_contracts_demo_runtime_and_changed_source_are_rejected(self):
        from product_safety_evidence import candidate_payload
        from product_gate import tree
        _, original = installer.release_files(self.archive)
        wheel_name = 'permission_to_work_harness-0.5.0-py3-none-any.whl'
        for target in [*[installer.release_data_path(n) for n in installer.SAFETY_FILES],
                       'ptw/demo_support/product_demo.py', 'ptw/demo_support/demo_swarm.py',
                       'ptw/store.py']:
            with self.subTest(target=target):
                files = dict(original)
                wheel = io.BytesIO()
                with zipfile.ZipFile(io.BytesIO(files[wheel_name])) as old, zipfile.ZipFile(wheel, 'w') as new:
                    for member in old.namelist():
                        if member != target:
                            new.writestr(member, old.read(member))
                files[wheel_name] = wheel.getvalue()
                files['release.json'] = json.dumps({'format': 1, 'version': '0.5.0',
                    'files': {n: installer.sha(v) for n, v in files.items()}}).encode()
                path = self.root / 'tampered.tar.gz'
                path.write_bytes(builder.deterministic_tar(files))
                with self.assertRaises(ValueError):
                    candidate_payload(path, builder.REPO, tree(builder.REPO / 'harness'))

    def test_rehashed_private_or_unsafe_archive_entries_do_not_pass(self):
        original = installer.archive_files(self.archive)
        for name in ('auth.json', 'sessions/log.json', '../escape', '/absolute', 'state.sqlite3'):
            files = dict(original)
            manifest = json.loads(files.pop('release.json'))
            files[name] = b'SYNTHETIC PRIVATE MARKER'
            manifest['files'] = {n: installer.sha(v) for n, v in files.items()}
            files['release.json'] = json.dumps(manifest).encode()
            with self.subTest(name=name), self.assertRaises(installer.InstallError):
                installer.release_files(builder.deterministic_tar(files))

    def test_preparation_preserves_failures_and_refuses_existing_or_linked_destinations(self):
        out = self.root / 'candidate'
        def mismatch(out, repo):
            result = self.fake_build(out, repo)
            result['url'] = result['url'].replace('harness-v0.5.0', 'harness-v9.9.9')
            return result
        with patch.object(preparation, 'build', side_effect=mismatch), self.assertRaises(installer.InstallError):
            preparation.prepare(out)
        self.assertEqual(load(out / 'prepare-failed.json')['status'], 'failed')
        self.assertFalse((out / 'release.json').exists())
        self.assertTrue((out / 'install.sh').exists())
        with self.assertRaises(FileExistsError):
            preparation.prepare(out)
        linked = self.root / 'linked'
        linked.symlink_to(out, target_is_directory=True)
        with self.assertRaises(installer.InstallError):
            preparation.prepare(linked)
        with self.assertRaises(installer.InstallError):
            preparation.prepare(builder.REPO / 'release-output')

    def test_deterministic_assembly_and_recursive_wheel_source_equality(self):
        import test_product_install as fixtures
        from product_gate import tree
        self.assertEqual(fixtures.release_fixture(), self.archive)
        _, files = installer.release_files(self.archive)
        with zipfile.ZipFile(io.BytesIO(files['permission_to_work_harness-0.5.0-py3-none-any.whl'])) as wheel:
            actual = {n: installer.sha(wheel.read(n)) for n in wheel.namelist() if n.startswith('ptw/')}
        self.assertEqual(actual, tree(builder.REPO / 'harness'))

    def test_original_only_or_incident_evidence_omissions_fail_existing_gate(self):
        import test_product_gate as fixtures
        fixture = fixtures.ProductGateTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        self.assertTrue(fixture.verify()['passed'])
        extension_ref = fixture.report.pop('safety_extension')
        with self.assertRaises(ValueError):
            fixture.verify()
        original = load(fixture.out / extension_ref['path'])
        for name in ('IG1-authority', 'IG2-scope', 'IG3-surrender', 'IG4-review-facts', 'IG5-release',
                     'AT1', 'AT2', 'AT3'):
            changed = {**original, 'requirements': dict(original['requirements'])}
            changed['requirements'].pop(name)
            fixture.report['safety_extension'] = fixture.write(extension_ref['path'], changed)
            with self.subTest(id=name), self.assertRaises(ValueError):
                fixture.verify()


class ReleaseEvidenceTests(unittest.TestCase):
    def setUp(self):
        import test_product_gate as fixtures
        self.fixture = fixtures.ProductGateTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()

    def verify(self):
        import product_demo_evidence
        f = self.fixture
        return product_demo_evidence.verify(f.out, f.report, f.repo)

    def test_original_and_extensions_green_cannot_omit_installed_demos(self):
        f = self.fixture
        self.assertTrue(f.verify()['passed'])
        f.report.pop('demo_evidence')
        with self.assertRaisesRegex(ValueError, 'Missing artifact'):
            f.verify()

    def test_missing_stale_wrong_candidate_and_installation_fail(self):
        f = self.fixture
        ref = f.report['demo_evidence']
        original = load(f.out / ref['path'])
        self.assertTrue(self.verify()['demo_ready'])
        for mutate in (lambda v: v['demos'].pop('swarm'),
                       lambda v: v.update(ended_epoch=0),
                       lambda v: v.update(source_sha256={}),
                       lambda v: v.update(candidate_record=f.report['safety_extension']),
                       lambda v: v.update(installed_module_record=f.report['journeys'][0]['terminal_record']),
                       lambda v: v['demos']['dependency']['processes'].pop('verify'),
                       lambda v: v['demos']['dependency'].update(public_sample=v['demos']['swarm']['public_sample'])):
            changed = copy.deepcopy(original)
            mutate(changed)
            f.report['demo_evidence'] = f.write(ref['path'], changed)
            with self.assertRaises(ValueError):
                self.verify()

    def test_rehashed_wrong_installed_bytes_outcomes_and_processes_fail(self):
        f = self.fixture
        ref = f.report['demo_evidence']
        envelope = load(f.out / ref['path'])
        row = envelope['demos']['dependency']
        for key, mutations in (
                ('result', [lambda v: v.update(ended_epoch=0), lambda v: v.update(complete=False),
                            lambda v: v.update(demo='swarm'),
                            lambda v: v['source'].update(runtime_sha256={}),
                            lambda v: v['installed'].update(path=str(f.repo / 'harness/ptw')),
                            lambda v: v['installed'].update(dependency_versions={})]),
                ('process', [lambda v: v.update(exit_code=2), lambda v: v.update(complete=False),
                             lambda v: v.update(argv=['python', '-m', 'ptw', 'demo'])])):
            owner, field = (row, 'result') if key == 'result' else (row['processes'], 'run')
            original_ref = owner[field]
            original = load(f.out / original_ref['path'])
            for mutate in mutations:
                changed = copy.deepcopy(original)
                mutate(changed)
                owner[field] = f.write(original_ref['path'], changed)
                f.report['demo_evidence'] = f.write(ref['path'], envelope)
                with self.assertRaises(ValueError):
                    self.verify()
            owner[field] = f.write(original_ref['path'], original)

    def test_physical_and_public_projection_validation_is_required(self):
        import product_demo_evidence
        f = self.fixture
        with patch.object(product_demo_evidence, 'verify_originals', side_effect=ValueError('contradictory physical/public evidence')):
            with self.assertRaisesRegex(ValueError, 'physical/public'):
                self.verify()
        envelope = load(f.out / f.report['demo_evidence']['path'])
        sample = f.out / envelope['demos']['swarm']['public_sample']['path']
        sample.write_text('{"private": "SYNTHETIC TOKEN"}')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            self.verify()

    def test_published_candidate_cannot_reuse_local_demo_binding(self):
        f = self.fixture
        ref = f.report['candidate_record']
        value = load(f.out / ref['path'])
        f.report['candidate_record'] = f.write(ref['path'], {**value, 'origin': 'public-release',
            'release_tag': 'harness-v0.5.0'})
        with self.assertRaisesRegex(ValueError, 'substituted demo candidate'):
            self.verify()

    def test_failed_installed_cli_cannot_seal_demo_evidence(self):
        import product_demo_evidence as evidence
        from types import SimpleNamespace
        f = self.fixture
        out = f.root / 'failed-demo-collection'
        (out / 'new-python').mkdir(parents=True)
        installed = evidence.installation(f.out, f.report)
        save(out / 'new-python/driver.json', {'installed_root': str(f.root / 'installation')})
        def failed(argv, folder, **kwargs):
            self.assertEqual(argv, evidence.command(installed[2], 'run', 'dependency', out / 'demos/dependency'))
            self.assertNotIn('PYTHONPATH', kwargs['env'])
            folder.mkdir()
            save(folder / 'process.json', {'complete': True, 'exit_code': 2})
            return SimpleNamespace(returncode=2)
        with patch.object(evidence, 'installation', return_value=installed), \
             patch.object(evidence, 'capture', side_effect=failed), \
             self.assertRaisesRegex(ValueError, 'Installed demo failed'):
            evidence.collect(out, f.report, f.repo)
        self.assertFalse((out / 'demos/evidence.json').exists())
        self.assertEqual(load(out / 'demos/dependency-run/process.json')['exit_code'], 2)


class ReleaseDiscoveryTests(unittest.TestCase):
    def test_demo_verifier_never_executes_receipt_selected_python_or_site_hooks(self):
        import product_demo_evidence as evidence
        from types import SimpleNamespace
        identity = {'python': sys.version, 'executable': '/untrusted/receipt-python',
                    'distribution_metadata': ['/verified/site/pkg.dist-info/METADATA']}
        with patch('native_receipt.verify_environment') as checked, \
             patch.object(evidence.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stderr='')) as run:
            evidence.verify_originals([Path('/private/demo')], builder.REPO, identity)
        checked.assert_called_once_with(identity, builder.REPO)
        argv = run.call_args.args[0]
        self.assertEqual(argv[:5], [sys.executable, '-I', '-S', '-B', '-c'])
        self.assertNotIn(identity['executable'], argv)
        self.assertEqual(json.loads(argv[-2]), [str(builder.REPO / 'harness'),
                         str(builder.REPO / 'harness/scripts'), '/verified/site'])
        with patch('native_receipt.verify_environment'), \
             patch.object(evidence.subprocess, 'run', return_value=SimpleNamespace(returncode=1, stderr='failed')), \
             self.assertRaisesRegex(ValueError, 'original verification failed'):
            evidence.verify_originals([], builder.REPO, identity)

    def test_public_ci_partition_preserves_all_cases_and_native_gate(self):
        import native_receipt
        import offline_checks
        loader = unittest.TestLoader()
        full = loader.discover(str(SCRIPTS.parent / 'tests'))
        original = native_receipt.inventory(full)
        offline, mandatory = offline_checks.partition(full)
        selected, reserved = native_receipt.inventory(offline), native_receipt.inventory(mandatory)
        self.assertEqual(loader.errors, [])
        self.assertCountEqual(selected + reserved, original)
        self.assertEqual({n.rsplit('.', 1)[0] for n in reserved}, offline_checks.NATIVE_CLASSES)
        self.assertFalse(set(selected) & set(reserved))
        with patch.dict(os.environ, {'PTW_LINUX_TESTS': '1'}), self.assertRaises(ValueError):
            offline_checks.main()

    def test_normal_discovery_contains_all_required_cases_once(self):
        import native_receipt
        from product_demo_evidence import discovery, MODULES
        inventory = native_receipt.discovery_inventory(builder.REPO)
        discovery(inventory)
        for module in MODULES:
            selected = next(n for n in inventory if n.startswith(module + '.'))
            with self.subTest(module=module), self.assertRaises(ValueError):
                discovery([n for n in inventory if not n.startswith(module + '.')])
            with self.subTest(duplicate=selected), self.assertRaises(ValueError):
                discovery([*inventory, selected])


class NativeReleaseTests(unittest.TestCase):
    def test_candidate_installs_and_runs_bundled_cli(self):
        """Mandatory package-path proof, no checkout driver or model calls."""
        import native_receipt
        from product_gate import tree
        root = Path(tempfile.mkdtemp(prefix='ptw-release-native-'))
        print('RELEASE_EVIDENCE=' + str(root), flush=True)
        source = native_receipt.sources(builder.REPO)
        save(root / 'source.json', source)
        try:
            value = preparation.prepare(root / 'candidate')
            env = installer.clean_env(root)
            archive = next(Path(a['path']) for a in value['assets'] if a['path'].endswith('.tar.gz'))
            commands, installation = root / 'commands', root / 'installation'
            result = capture(['bash', root / 'candidate/install.sh', '--artifact', archive,
                              '--root', installation, '--bin-dir', commands], root / 'install-process',
                             env=env, cwd=root, timeout=600)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            state = load(installation / 'state.json')
            installed = installation / 'releases' / state['active']
            runtime = next((installed / 'venv/lib').glob('python*/site-packages'))
            self.assertEqual(tree(runtime), tree(builder.REPO / 'harness'))
            from terminal_driver import Terminal
            for label, arguments, expected in (
                    ('help', ['--help'], 0),
                    ('missing-evidence', ['verify', '--out', str(root / 'absent')], 2)):
                terminal = Terminal([str(commands / 'ptw'), 'demo', *arguments],
                                    root / ('terminal-' + label), env=env, replace_env=True, cwd=root)
                try:
                    terminal.wait(lambda: terminal.exited, 30, 'installed demo ' + label)
                finally:
                    code = terminal.close()
                self.assertEqual(code, expected)
            records = {}
            for demo in ('dependency', 'task-scope', 'swarm', 'report'):
                out = root / demo
                for action in ('run', 'verify'):
                    result = capture([commands / 'ptw', 'demo', action, '--demo', demo, '--out', out],
                                     root / (demo + '-' + action), env=env, cwd=root, timeout=300)
                    self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
                records[demo] = reference(root, out / 'result.json')
                self.assertEqual(load(out / 'result.json')['installed']['runtime_sha256'], tree(runtime))
            self.assertEqual(tree(runtime), tree(builder.REPO / 'harness'))
            self.assertEqual(source, native_receipt.sources(builder.REPO))
            save(root / 'result.json', {'passed': True, 'publication': 'not-performed',
                 'candidate': reference(root, root / 'candidate/release.json'), 'demos': records,
                 'source_sha256': source, 'runtime_sha256': tree(runtime)})
        except BaseException as exc:
            save(root / 'failed.json', {'passed': False, 'error_type': type(exc).__name__})
            raise


if __name__ == '__main__':
    unittest.main()
