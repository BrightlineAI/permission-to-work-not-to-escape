"""Release artifacts and installed CLI behavior, not publication certification.

Offline mutation fixtures are explicitly synthetic. The native case retains the
real builder, installation and all demo originals outside the source checkout.
"""
import io
import copy
from contextlib import chdir, redirect_stderr, redirect_stdout
import json
import os
from pathlib import Path
import sys
import tempfile
import tarfile
import unittest
from unittest.mock import patch
import zipfile

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import build_product_release as builder
import prepare_product_release as preparation
import product_install as installer
from evidence_io import artifact, capture, load, reference, save


class CIPrerequisiteTests(unittest.TestCase):
    """Synthetic executable/transport fixtures, with real integrity and PATH checks."""

    def setUp(self):
        import provision_ci_uv
        self.ci = provision_ci_uv
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(prefix='ptw-ci-fixture-')))
        self.path_file = self.root / 'github-path'
        self.path_file.write_text('')
        self.out = self.root / 'tools'
        self.version = installer.PINS['uv'][0]

    def executable(self, version=None):
        return ('#!/bin/sh\nprintf "%s\\n" "uv ' + (version or self.version) + ' (fixture)"\n').encode()

    def invoke(self, data, *, digest=None, failure=None):
        # Mock the transport only: the production download hash and archive
        # validators, executable invocation and PATH-file publication all run.
        with patch.dict(installer.PINS, {'uv': (self.version, installer.PINS['uv'][1],
                                               digest or installer.sha(data))}), \
                patch.object(installer.urllib.request.OpenerDirector, 'open',
                             side_effect=failure or (lambda *a, **k: io.BytesIO(data))) as opened, \
                patch.dict(os.environ, {'GITHUB_PATH': str(self.path_file), 'PATH': ''}), \
                patch.object(sys, 'argv', ['provision_ci_uv.py', '--out', str(self.out)]), \
                redirect_stderr(io.StringIO()):
            self.ci.main()
        self.assertEqual(opened.call_args.args[0], installer.PINS['uv'][1])

    def test_verified_tool_is_available_to_next_step_without_ambient_uv(self):
        import shutil
        data = builder.deterministic_tar({'uv-linux/uv': self.executable(), 'uv-linux/uvx': b'unused'})
        self.invoke(data)
        self.assertEqual(self.path_file.read_text(), str(self.out) + '\n')
        executable = shutil.which('uv', path=self.path_file.read_text().strip())
        self.assertEqual(executable, str(self.out / 'uv'))
        self.assertEqual(installer.run(['uv', '--version'], env={'PATH': str(self.out)}),
                         'uv ' + self.version + ' (fixture)')
        self.assertFalse((self.out / 'uvx').exists())
        # Selection must remain explicit even if a different ambient tool exists.
        ambient = self.root / 'ambient'
        ambient.mkdir()
        (ambient / 'uv').write_bytes(self.executable('0.0.0'))
        (ambient / 'uv').chmod(0o755)
        self.assertEqual(installer.run(['uv', '--version'], env={'PATH': str(self.out) + os.pathsep + str(ambient)}),
                         'uv ' + self.version + ' (fixture)')

    def test_invalid_download_archive_or_binary_never_updates_path(self):
        good = builder.deterministic_tar({'bin/uv': self.executable()})
        cases = [
            ('download', good, None, OSError('synthetic transport failure')),
            ('digest', good, '0' * 64, None),
            ('malformed', b'not a tar archive', None, None),
            ('missing', builder.deterministic_tar({'bin/uvx': b'unused'}), None, None),
            ('duplicate', builder.deterministic_tar({'a/uv': self.executable(), 'b/uv': self.executable()}), None, None),
            ('invalid-executable', builder.deterministic_tar({'bin/uv': b'not executable'}), None, None),
            ('nonzero', builder.deterministic_tar({'bin/uv': b'#!/bin/sh\nexit 1\n'}), None, None),
            ('wrong-version', builder.deterministic_tar({'bin/uv': self.executable('0.0.0')}), None, None),
            ('version-prefix', builder.deterministic_tar({'bin/uv': self.executable(self.version + '0')}), None, None),
        ]
        for name, data, digest, failure in cases:
            with self.subTest(case=name):
                self.out = self.root / name
                with self.assertRaises((installer.InstallError, tarfile.TarError)):
                    self.invoke(data, digest=digest, failure=failure)
                self.assertEqual(self.path_file.read_text(), '')

    def test_existing_destination_is_preserved_and_not_exported(self):
        self.out.mkdir()
        original = self.out / 'uv'
        original.write_bytes(b'previous attempt')
        with self.assertRaises(FileExistsError):
            self.invoke(builder.deterministic_tar({'bin/uv': self.executable()}))
        self.assertEqual(original.read_bytes(), b'previous attempt')
        self.assertEqual(self.path_file.read_text(), '')

    def test_workflow_provisions_before_offline_discovery_and_discovery_errors_fail(self):
        import offline_checks
        workflow = (builder.REPO / '.github/workflows/evidence.yml').read_text()
        provision = 'python harness/scripts/provision_ci_uv.py --out "$RUNNER_TEMP/ptw-ci-uv"'
        self.assertEqual(workflow.count(provision), 1)
        self.assertLess(workflow.index(provision), workflow.index('harness/scripts/offline_checks.py'))
        loader = unittest.TestLoader()
        loader.errors.append('synthetic import failure')
        with patch.dict(os.environ, {'PTW_LINUX_TESTS': '0'}), \
                patch.object(offline_checks.unittest, 'TestLoader', return_value=loader), \
                patch.object(loader, 'discover', return_value=unittest.TestSuite()), \
                patch.object(offline_checks, 'partition') as partition, \
                self.assertRaisesRegex(ValueError, 'Offline discovery failed'):
            offline_checks.main()
        partition.assert_not_called()


class ReleaseInstallerTimingTests(unittest.TestCase):
    def stages(self, stream):
        return [json.loads(line.removeprefix('PTW_INSTALL_STAGE '))
                for line in stream.getvalue().splitlines()]

    def test_stage_clock_and_failure_do_not_expose_exception_details(self):
        for error in (None, installer.InstallError('private fixture detail'), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__):
                stream = io.StringIO()
                with redirect_stderr(stream), patch.object(installer.time, 'monotonic', side_effect=[10., 12.5]):
                    if error is None:
                        with installer.install_stage('health'):
                            pass
                    else:
                        with self.assertRaises(type(error)) as raised:
                            with installer.install_stage('health'):
                                raise error
                        self.assertIs(raised.exception, error)
                self.assertEqual(self.stages(stream), [
                    {'stage': 'health', 'completed': error is None, 'seconds': 2.5}])
                self.assertNotIn('private fixture detail', stream.getvalue())

    def test_prepare_records_success_and_stops_at_failed_stage(self):
        import test_product_install as fixtures
        manifest, files = installer.release_files(fixtures.release_fixture())
        binary = builder.deterministic_tar({'bin/uv': b'fixture', 'bin/nono': b'fixture'})
        for failure in (None, 'download', 'python', 'npm', 'missing-platform'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root, stream, commands = Path(temporary), io.StringIO(), []

                def execute(command, **kwargs):
                    command = [str(x) for x in command]
                    commands.append(command)
                    if '--version' in command:
                        return installer.PINS[Path(command[0]).name][0]
                    if ((failure == 'python' and '--require-hashes' in command) or
                            (failure == 'npm' and command[0] == 'npm')):
                        raise installer.InstallError('private fixture command output')
                    if command[0] == 'npm' and failure != 'missing-platform':
                        target = root / 'codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex'
                        target.parent.mkdir(parents=True)
                        target.write_bytes(b'fixture')
                    return ''

                with redirect_stderr(stream), patch.object(installer, 'run', side_effect=execute), \
                        patch.object(installer, 'download', return_value=binary,
                            side_effect=installer.InstallError('private fixture download') if failure == 'download' else None):
                    if failure is None:
                        installer.prepare(root, files, manifest)
                    else:
                        with self.assertRaises(installer.InstallError):
                            installer.prepare(root, files, manifest)
                rows = self.stages(stream)
                expected = {'download-uv': True, 'download-nono': True,
                            'python-environment': failure != 'python',
                            'codex-environment': failure not in ('npm', 'missing-platform')}
                if failure == 'download':
                    expected = {'download-uv': False}
                    self.assertEqual(commands, [])
                else:
                    # Both independent preparations finish before return, even
                    # if one fails. Completion order is not an acceptance gate.
                    self.assertEqual([r['stage'] for r in rows[:2]], ['download-uv', 'download-nono'])
                    self.assertTrue(any(c[0] == 'npm' for c in commands))
                self.assertEqual(len(rows), len(expected))
                self.assertEqual({r['stage']: r['completed'] for r in rows}, expected)
                self.assertFalse(any('doctor' in c for c in commands))
                self.assertTrue(all(r['seconds'] >= 0 for r in rows))
                self.assertNotIn(temporary, stream.getvalue())
                self.assertNotIn('private fixture', stream.getvalue())

    def test_health_failure_retains_failed_candidate_without_activation(self):
        import test_product_install as fixtures
        with tempfile.TemporaryDirectory() as temporary:
            root, stream = Path(temporary), io.StringIO()
            archive = root / 'candidate.tgz'
            archive.write_bytes(fixtures.release_fixture())
            with redirect_stderr(stream), redirect_stdout(io.StringIO()), \
                    patch.object(installer, 'preflight'), patch.object(installer, 'in_use'), \
                    patch.object(installer, 'prepare', side_effect=fixtures.prepare_fixture), \
                    patch.object(installer, 'health', side_effect=installer.InstallError('private fixture health')):
                with installer.locked(root / 'installation', root / 'commands') as state:
                    with self.assertRaisesRegex(installer.InstallError, 'private fixture health'):
                        installer.install(root / 'installation', state, str(archive), installer.sha(archive.read_bytes()))
            state = load(root / 'installation/state.json')
            self.assertIsNone(state['active'])
            self.assertEqual([r['status'] for r in state['releases'].values()], ['failed'])
            rows = self.stages(stream)
            self.assertEqual([r['stage'] for r in rows],
                             ['preflight', 'release-archive', 'payload-snapshot', 'health'])
            self.assertFalse(rows[-1]['completed'])
            self.assertNotIn('private fixture health', stream.getvalue())
            self.assertFalse((root / 'commands/ptw').exists())


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
        self.assertEqual({a['path'] for a in value['assets']},
                         {'ptw-0.5.0-linux-x86_64.tar.gz', 'install.sh', 'RELEASE.md', 'SHA256SUMS'})
        for asset in value['assets']:
            self.assertEqual(artifact(out, asset), out / asset['path'])
        _, contents = installer.release_files(self.archive)
        self.assertEqual(set(contents) - {'permission_to_work_harness-0.5.0-py3-none-any.whl'},
                         {'requirements.lock', 'package.json', 'package-lock.json', 'product_install.py',
                          'INSTALL.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md'})
        notes = (out / 'RELEASE.md').read_text()
        for required in ('INCIDENT_SAFETY_ACCEPTANCE.json', 'original-only', 'AT1/AT3', 'AT2',
                         '<=60-second', 'eight-case/16-call', 'unvalidated', 'raw logs',
                         'ptw demo run --demo swarm', 'ptw-install uninstall'):
            self.assertIn(required, notes)
        for private in ('Bearer ', '/home/loon/', 'session_meta', 'customer@example'):
            self.assertNotIn(private, notes)

    def test_manifest_references_survive_relocation_and_unrelated_working_directory(self):
        out = self.root / 'candidate'
        with patch.object(preparation, 'build', side_effect=self.fake_build):
            preparation.prepare(out)
        original = (out / 'release.json').read_bytes()
        relocated = self.root / 'relocated'
        out.rename(relocated)
        elsewhere = self.root / 'working'
        elsewhere.mkdir()
        with chdir(elsewhere):
            value = load(relocated / 'release.json')
            for item in value['assets']:
                self.assertEqual(artifact(relocated, item), relocated / item['path'])
        self.assertEqual((relocated / 'release.json').read_bytes(), original)
        self.assertFalse(out.exists())

    def test_manifest_consumer_rejects_unsafe_missing_linked_and_changed_assets(self):
        out = self.root / 'candidate'
        with patch.object(preparation, 'build', side_effect=self.fake_build):
            value = preparation.prepare(out)
        item = next(a for a in value['assets'] if a['path'] == 'RELEASE.md')
        target = artifact(out, item)
        original = target.read_bytes()
        (self.root / 'outside.md').write_bytes(original)
        (out / 'linked.md').symlink_to(target)
        (out / 'linked-directory').symlink_to(self.root, target_is_directory=True)
        for name in (str(target), '../outside.md', 'missing.md', 'linked.md',
                     'linked-directory/outside.md'):
            with self.subTest(path=name), self.assertRaises(ValueError):
                artifact(out, {**item, 'path': name})
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            artifact(out, {**item, 'sha256': '0' * 64})
        target.write_bytes(original + b'\nChanged content\n')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            artifact(out, item)

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

    def test_amended_contract_is_bundled_and_old_rehashed_contract_is_rejected(self):
        from product_safety_evidence import CONTRACTS, candidate_payload
        from product_gate import tree
        amended = (builder.REPO / 'harness/PRODUCT_ACCEPTANCE.json').read_bytes()
        expected = '0204143234efbb96df3fb3a78aad6b13904e4e2c23c003db7fc18f07c14845c3'
        self.assertEqual(installer.sha(amended), expected)
        self.assertEqual(CONTRACTS['PRODUCT_ACCEPTANCE.json'], expected)
        _, files = installer.release_files(self.archive)
        wheel_name = 'permission_to_work_harness-0.5.0-py3-none-any.whl'
        target = installer.release_data_path('PRODUCT_ACCEPTANCE.json')
        old_contract = amended.replace(b'in 60 seconds or less', b'in 30 seconds or less').replace(
            b'Absolute maximum <=60s on declared developer-machine profile; aim for about 40s;',
            b'Target <=30s on declared developer-machine profile;')
        self.assertEqual(installer.sha(old_contract),
                         '196092b6a4c7c209c3968c886683210448c373f449daef8cb08685fd6a064468')
        wheel = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(files[wheel_name])) as original, zipfile.ZipFile(wheel, 'w') as changed:
            self.assertEqual(original.read(target), amended)
            for name in original.namelist():
                changed.writestr(name, old_contract if name == target else original.read(name))
        path = self.root / 'candidate.tar.gz'
        path.write_bytes(self.archive)
        runtime = tree(builder.REPO / 'harness')
        candidate_payload(path, builder.REPO, runtime)
        files[wheel_name] = wheel.getvalue()
        files['release.json'] = json.dumps({'format': 1, 'version': '0.5.0',
            'files': {n: installer.sha(v) for n, v in files.items() if n != 'release.json'}}).encode()
        path.write_bytes(builder.deterministic_tar(files))
        with self.assertRaisesRegex(ValueError, 'Candidate safety contracts/guides differ'):
            candidate_payload(path, builder.REPO, runtime)

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
            assets = [artifact(root / 'candidate', a) for a in value['assets']]
            archive = next(path for path in assets if path.name.endswith('.tar.gz'))
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
