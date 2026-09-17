"""pnpm fixtures. Native effects are manager-only, never mocked passes."""
import concurrent.futures
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

from ptw import pnpm_tool
from ptw.policy import Invalid, load, save
from ptw.pnpm import PnpmPlan, mapping, read_inputs
from ptw.package_evidence import EvidenceError
from ptw.dependency_resolution import ResolutionError
from ptw.setup_templates import RULES
from ptw.supervisor import runtime_namespace
from test_ecosystems import NpmFixture, tar_bytes


class PnpmRegistryFixture:
    """Synthetic registry evidence and real archive bytes, never a model trace."""
    def __init__(self, fixtures):
        self.fixtures = {(f.record['name'], f.record['version']): f for f in fixtures}
        self.overrides = {}
        self.assessments = []

    def packument(self, name):
        versions, times = {}, {}
        for (package, version), fixture in self.fixtures.items():
            if package != name:
                continue
            record = {**fixture.record, **self.overrides.get((name, version), {})}
            versions[version] = {**fixture.manifest, 'dist': {
                'tarball': record['url'], 'integrity': record['integrity']}}
            times[version] = record['published_at']
        return {'name': name, 'versions': versions, 'time': times,
                'dist-tags': {'latest': sorted(versions)[-1]} if versions else {}}

    def assess(self, name, version):
        self.assessments.append((name, version))
        fixture = self.fixtures[name, version]
        return {**fixture.assess(name, version), 'filename': name + '-' + version + '.tgz',
                **self.overrides.get((name, version), {})}

    def artifact_allowed(self, url, name):
        return any(f.record['name'] == name and f.record['url'] == url for f in self.fixtures.values())

    def download(self, record, destination):
        self.fixtures[record['name'], record['version']].download(record, destination)

    def write(self, path):
        save(path, [{'manifest': f.manifest, 'record': f.record,
                     'raw': base64.b64encode(f.raw).decode()} for f in self.fixtures.values()])

    @classmethod
    def read(cls, path):
        fixtures = []
        for row in load(path):
            fixture = NpmFixture.__new__(NpmFixture)
            fixture.manifest, fixture.record = row['manifest'], row['record']
            fixture.raw = base64.b64decode(row['raw'])
            fixtures.append(fixture)
        return cls(fixtures)


class PnpmToolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ptw-pnpm-unit-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def tool_archive(self):
        return tar_bytes({'package/package.json': json.dumps(
            {'name': 'pnpm', 'version': pnpm_tool.VERSION}).encode(),
            'package/bin/pnpm.cjs': b'// non-executable unit fixture\n'})

    def provision(self, root, *, raw=None, expected=None):
        raw = self.tool_archive() if raw is None else raw
        metadata = {'name': 'pnpm', 'version': pnpm_tool.VERSION, 'dist': {
            'tarball': pnpm_tool.URL, 'integrity': expected or pnpm_tool.integrity(raw)}}
        with patch.object(pnpm_tool.NpmEvidence, 'fetch', side_effect=[json.dumps(metadata).encode(), raw]):
            return pnpm_tool.provision(root)

    def test_tool_requires_explicit_provisioning_and_never_uses_corepack(self):
        with patch.dict(os.environ, {'PTW_PNPM_TOOL': ''}), \
                self.assertRaisesRegex(Invalid, 'no ambient fallback'):
            pnpm_tool.verified()
        with self.assertRaisesRegex(Invalid, 'Only frozen'):
            pnpm_tool.run(['exec', 'node', '-e', 'process.exit(0)'], cwd=self.root)

    def test_native_operation_allowlist_keeps_fetch_offline_and_scripts_disabled(self):
        directory = self.provision(self.root / 'tool')
        stage = self.root / 'stage'
        stage.mkdir()
        for arguments in (['fetch', '--offline=false'],
                          ['fetch', '--no-frozen-lockfile'],
                          ['fetch', '--config.frozen-lockfile=false'], ['install'],
                          ['store', 'add', '/resolution/artifacts/example.tgz']):
            with self.subTest(arguments=arguments), patch.object(pnpm_tool.subprocess, 'run') as run, \
                    self.assertRaisesRegex(Invalid, 'Only frozen'):
                pnpm_tool.run(arguments, cwd=stage, directory=directory)
            run.assert_not_called()
        with patch('ptw.supervisor.runtime_namespace', return_value=['namespace']), \
                patch.object(pnpm_tool.subprocess, 'run', return_value=
                    subprocess.CompletedProcess([], 0, '', '')) as run:
            pnpm_tool.run(['fetch'], cwd=stage, directory=directory)
        argv = run.call_args.args[0]
        for option in ('--config.offline=true', '--config.ignore-scripts=true',
                       '--config.frozen-lockfile=true',
                       '--config.ignore-pnpmfile=true', '--config.side-effects-cache=false',
                       '--config.verify-store-integrity=true', '--config.package-import-method=copy'):
            self.assertIn(option, argv)
        self.assertEqual(run.call_args.kwargs['env'], {'PATH': '/usr/bin:/bin'})

    def test_complete_payload_and_archive_and_runtime_are_bound(self):
        directory = self.provision(self.root / 'tool')
        self.assertEqual(pnpm_tool.verified(directory)[1]['outcome'], 'ready')
        extra = directory / 'payload/injected.cjs'
        extra.write_text('throw Error("injected")')
        with self.assertRaisesRegex(Invalid, 'tooling changed'):
            pnpm_tool.verified(directory)
        extra.unlink()
        with patch.object(pnpm_tool, 'node_identity', return_value={'sha256': 'changed'}), \
                self.assertRaisesRegex(Invalid, 'tooling changed'):
            pnpm_tool.verified(directory)
        (directory / 'tool.tgz').write_bytes(b'changed')
        with self.assertRaisesRegex(Invalid, 'tooling changed'):
            pnpm_tool.verified(directory)

    def test_bad_integrity_keeps_failure_receipt_without_extraction(self):
        directory = self.root / 'bad'
        with self.assertRaisesRegex(Invalid, 'integrity mismatch'):
            self.provision(directory, expected='sha512-invalid')
        self.assertEqual(load(directory / 'tool.json')['outcome'], 'failed')
        self.assertFalse((directory / 'payload').exists())
        with self.assertRaises(FileExistsError):
            self.provision(directory)

    def test_archive_traversal_links_and_duplicate_paths_fail_closed(self):
        for attack in ('traversal', 'symlink', 'hardlink', 'duplicate'):
            with self.subTest(attack=attack):
                stream = io.BytesIO()
                with tarfile.open(fileobj=stream, mode='w:gz') as archive:
                    item = tarfile.TarInfo('package/../escape' if attack == 'traversal' else 'package/entry')
                    if attack in ('symlink', 'hardlink'):
                        item.type = tarfile.SYMTYPE if attack == 'symlink' else tarfile.LNKTYPE
                        item.linkname = '/outside'
                    archive.addfile(item)
                    if attack == 'duplicate':
                        archive.addfile(item)
                with self.assertRaisesRegex(Invalid, 'Unsafe pnpm'):
                    pnpm_tool.unpack(stream.getvalue(), self.root / attack)
                self.assertFalse((self.root / 'escape').exists())

    def test_lock_reconstruction_retains_exact_release(self):
        directory = self.provision(self.root / 'first')
        # Use the actual retained artifact, including its gzip header.
        raw = (directory / 'tool.tgz').read_bytes()
        with patch.object(pnpm_tool.NpmEvidence, 'fetch', return_value=raw) as fetch:
            rebuilt = pnpm_tool.provision(self.root / 'rebuilt', lock=directory / 'tools.lock')
        fetch.assert_called_once_with(pnpm_tool.URL, limit=32 * 1024 * 1024)
        self.assertEqual(pnpm_tool.payload(directory / 'payload'), pnpm_tool.payload(rebuilt / 'payload'))
        lock = load(directory / 'tools.lock')
        lock['url'] = 'https://unapproved.invalid/pnpm.tgz'
        save(self.root / 'wrong.lock', lock)
        with patch.object(pnpm_tool.NpmEvidence, 'fetch') as fetch, self.assertRaisesRegex(Invalid, 'pinned release'):
            pnpm_tool.provision(self.root / 'wrong', lock=self.root / 'wrong.lock')
        fetch.assert_not_called()

    def test_build_uses_named_approval_and_supervision_without_broad_hook_authority(self):
        directory = self.provision(self.root / 'tool')
        target = self.root / 'target'
        target.mkdir()
        commands = []
        with patch.dict(os.environ, {'PTW_PNPM_TOOL': str(directory)}), \
                patch('ptw.supervisor.runtime_namespace', return_value=['namespace']):
            for names, runner in (([], commands.append), (['--all'], commands.append), (['demo'], None)):
                with self.assertRaisesRegex(Invalid, 'explicit package names'):
                    pnpm_tool.rebuild(target, names, runner)
            self.assertFalse(commands)
            pnpm_tool.rebuild(target, {'demo'}, commands.append)
        argv = commands[0]
        self.assertEqual(argv[argv.index('rebuild') + 1], 'demo')
        for option in ('--config.ignore-scripts=false', '--config.ignore-pnpmfile=true',
                       '--config.offline=true', '--config.side-effects-cache=false'):
            self.assertIn(option, argv)
        self.assertNotIn('--recursive', argv)
        self.assertEqual((self.root / 'target-build.npmrc').read_text(), 'only-built-dependencies[]=demo\n')

    def test_resolution_namespace_uses_only_metadata_broker_and_verified_tool(self):
        directory = self.provision(self.root / 'tool')
        stage = self.root / 'stage'
        stage.mkdir()
        with patch.dict(os.environ, {'PTW_PNPM_TOOL': str(directory)}), \
                patch('ptw.supervisor.runtime_namespace', return_value=['bwrap', '--unshare-all']), \
                patch.object(pnpm_tool.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')) as run:
            for endpoint in ('https://registry.npmjs.org/', 'http://host.invalid/a/', 'http://127.0.0.1:1/a/?x'):
                with self.assertRaisesRegex(Invalid, 'endpoint'):
                    pnpm_tool.resolve_lock(stage, endpoint, age_minutes=4320, timeout=30)
            run.assert_not_called()
            pnpm_tool.resolve_lock(stage, 'http://127.0.0.1:1234/abc123/', age_minutes=4320, timeout=30)
        argv = run.call_args.args[0]
        for option in ('--lockfile-only', '--no-frozen-lockfile', '--config.ignore-scripts=true',
                       '--config.ignore-pnpmfile=true', '--config.minimum-release-age=4320',
                       '--config.lockfile-include-tarball-url=true'):
            self.assertIn(option, argv)
        self.assertNotIn('--unshare-all', argv)
        self.assertEqual(run.call_args.kwargs['env'], {'PATH': '/usr/bin:/bin'})


class PnpmAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ptw-pnpm-admission-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixture = NpmFixture()
        self.manifest = {'name': 'root', 'version': '1.0.0', 'dependencies': {'demo': '^1.0.0'}}
        self.lock = {'lockfileVersion': '9.0',
            'settings': {'autoInstallPeers': True, 'excludeLinksFromLockfile': False},
            'importers': {'.': {'dependencies': {'demo': {'specifier': '^1.0.0', 'version': '1.0.0'}}}},
            'packages': {'demo@1.0.0': {'resolution': {'integrity': self.fixture.record['integrity'],
                                                    'tarball': self.fixture.record['url']}}},
            'snapshots': {'demo@1.0.0': {}}}

    def files(self):
        return {'package.json': json.dumps(self.manifest), 'pnpm-lock.yaml': json.dumps(self.lock)}

    def test_frozen_resolution_preserves_inputs_and_records_native_failure(self):
        from ptw.pnpm_resolution import resolve_pnpm
        for name, text in self.files().items():
            (self.root / name).write_text(text)
        original = read_inputs(self.root)[0]
        for mode in ('success', 'formatting', 'mutation', 'lock-mutation', 'origin-mutation',
                     'malformed-lock', 'native-failure'):
            def native(arguments, *, cwd, timeout):
                self.assertEqual(arguments, ['install', '--lockfile-only', '--frozen-lockfile'])
                if mode == 'mutation':
                    (cwd / 'package.json').write_text('{}')
                elif mode == 'formatting':
                    (cwd / 'pnpm-lock.yaml').write_text(json.dumps(self.lock, indent=4, sort_keys=True))
                elif mode in ('lock-mutation', 'origin-mutation'):
                    lock = json.loads(json.dumps(self.lock))
                    if mode == 'lock-mutation':
                        lock['importers']['.']['dependencies']['demo']['version'] = '1.1.0'
                    else:
                        lock['packages']['demo@1.0.0']['resolution']['tarball'] = 'https://other.invalid/demo.tgz'
                    (cwd / 'pnpm-lock.yaml').write_text(json.dumps(lock))
                elif mode == 'malformed-lock':
                    (cwd / 'pnpm-lock.yaml').write_text('lockfileVersion: [unterminated')
                return subprocess.CompletedProcess([], 1 if mode == 'native-failure' else 0, '',
                    'ERR_PNPM_OUTDATED_LOCKFILE' if mode == 'native-failure' else '')
            with patch.object(pnpm_tool, 'run', side_effect=native):
                if mode in ('success', 'formatting'):
                    result = resolve_pnpm(self.root, self.root / mode, RULES, provider=self.fixture)
                    self.assertEqual(result['files'], original)
                    self.assertEqual(result['lock'], {'manager': 'pnpm', 'files': original})
                else:
                    with self.assertRaises(Invalid):
                        resolve_pnpm(self.root, self.root / mode, RULES, provider=self.fixture)
            self.assertEqual(read_inputs(self.root)[0], original)
            self.assertEqual(load(self.root / mode / 'resolution.json')['outcome'],
                             {'success': 'resolved', 'formatting': 'resolved',
                              'native-failure': 'unsatisfiable'}.get(mode, 'invalid'))
            if mode == 'formatting':
                receipt = load(self.root / mode / 'resolution.json')
                self.assertEqual(result['inputs'], receipt['inputs'])
                self.assertNotEqual(receipt['attempts'][0]['output_inputs']['pnpm-lock.yaml'],
                                    receipt['inputs']['pnpm-lock.yaml'])

    def test_yaml_rejects_ambiguous_executable_recursive_and_excessive_data(self):
        for raw in ('a: 1\na: 2', 'a: &x [*x]', 'a: !!python/object:bad {}',
                    'a: !!str x', 'a: ' + '[' * 50 + '0' + ']' * 50,
                    '? [a, b]\n: x', 'a: 1\n---\nb: 2', 'a: {<<: {b: 1}}'):
            with self.subTest(raw=raw), self.assertRaises(Invalid):
                mapping(raw)
        self.assertEqual(mapping("lockfileVersion: '9.0'\na: true"), {'lockfileVersion': '9.0', 'a': 'true'})

    def test_file_directory_identity_is_source_bound_without_registry_evidence(self):
        self.manifest['dependencies']['local'] = 'file:packages/local'
        self.lock['importers']['.']['dependencies']['local'] = {
            'specifier': 'file:packages/local', 'version': 'file:packages/local'}
        self.lock['packages']['local@file:packages/local'] = {
            'resolution': {'directory': 'packages/local', 'type': 'directory'}}
        self.lock['snapshots']['local@file:packages/local'] = {}
        files = {**self.files(), 'packages/local/package.json': json.dumps({
            'name': 'local', 'version': '1.0.0', 'main': 'index.cjs'})}
        plan = PnpmPlan(files)
        self.assertEqual(plan.selected, {'demo@1.0.0': '1.0.0'})
        self.assertEqual(plan.local_packages, {'local@file:packages/local': 'packages/local'})
        plan.bind_evidence([self.fixture.record])
        for directory in ('../outside', '/outside', 'packages/substitute'):
            with self.subTest(directory=directory):
                lock = json.loads(files['pnpm-lock.yaml'])
                lock['packages']['local@file:packages/local']['resolution']['directory'] = directory
                with self.assertRaisesRegex(Invalid, 'source identity'):
                    PnpmPlan({**files, 'pnpm-lock.yaml': json.dumps(lock)})

    def test_file_directory_copies_reject_extra_bytes_and_wrong_locked_source(self):
        manifest = {'name': 'local', 'version': '1.0.0', 'main': 'index.cjs'}
        self.manifest['dependencies'] = {'local': 'file:packages/local'}
        self.lock['importers']['.']['dependencies'] = {'local': {
            'specifier': 'file:packages/local', 'version': 'file:packages/local'}}
        self.lock['packages'] = {'local@file:packages/local': {
            'resolution': {'directory': 'packages/local', 'type': 'directory'}}}
        self.lock['snapshots'] = {'local@file:packages/local': {}}
        files = {**self.files(), 'packages/local/package.json': json.dumps(manifest)}
        plan = PnpmPlan(files)
        target = self.root / 'local-only'
        plan.materialize(target)
        folder = target / 'node_modules/.pnpm/local_copy/node_modules/local'
        folder.mkdir(parents=True)
        origin = target / 'packages/local/package.json'
        copied = folder / 'package.json'
        os.link(origin, copied)
        link = target / 'node_modules/local'
        link.symlink_to(os.path.relpath(folder, link.parent))
        plan.archive_contents = {}
        with self.assertRaisesRegex(EvidenceError, 'link or special file'):
            plan.verify_installed(target, [])
        # The pinned directory fetcher overrides import-method=copy. Accept
        # only its complete internal metadata group, then retain strict checks.
        for alias, error in ((self.root / 'outside.json', 'outside alias'),
                             (target / 'unexpected.json', 'unexpected installed path')):
            os.link(origin, alias)
            with self.assertRaisesRegex(EvidenceError, error):
                plan.detach_local_metadata(target)
            self.assertEqual(copied.stat().st_ino, origin.stat().st_ino)
            alias.unlink()
        origin.write_text('{}')
        with self.assertRaisesRegex(EvidenceError, 'differs from reviewed source'):
            plan.detach_local_metadata(target)
        origin.write_text(files['packages/local/package.json'])
        plan.detach_local_metadata(target)
        self.assertEqual(origin.stat().st_nlink, 1)
        self.assertEqual(copied.stat().st_nlink, 1)
        self.assertNotEqual(origin.stat().st_ino, copied.stat().st_ino)
        self.assertEqual(copied.read_bytes(), origin.read_bytes())
        plan.verify_installed(target, [])
        self.assertEqual(plan.source_copies, {'packages/local': [str(folder.relative_to(target))]})
        (folder / 'unreviewed.cjs').write_text('throw Error("unreviewed source")')
        with self.assertRaisesRegex(EvidenceError, 'content differs'):
            plan.verify_installed(target, [])
        (folder / 'unreviewed.cjs').unlink()
        link.unlink()
        link.symlink_to('../packages/local')
        with self.assertRaisesRegex(EvidenceError, 'exact locked target'):
            plan.verify_installed(target, [])

    def test_metadata_detachment_does_not_normalize_registry_or_unknown_hardlinks(self):
        plan = PnpmPlan(self.files())
        target = self.root / 'untrusted-links'
        plan.materialize(target)
        first = target / 'node_modules/.pnpm/demo/node_modules/demo/index.js'
        first.parent.mkdir(parents=True)
        first.write_text('unreviewed')
        second = first.with_name('alias.js')
        os.link(first, second)
        with self.assertRaisesRegex(EvidenceError, 'unreviewed origin'):
            plan.detach_local_metadata(target)
        self.assertEqual(first.stat().st_nlink, 2)
        self.assertEqual(first.read_text(), 'unreviewed')

    def test_frozen_ranges_origin_and_integrity_remain_bound(self):
        files = self.files()
        plan = PnpmPlan(files)
        plan.bind_evidence([self.fixture.record])
        self.assertEqual(plan.files, files)
        self.assertEqual(plan.selected, {'demo@1.0.0': '1.0.0'})
        for key, value in (('url', 'https://other.invalid/demo.tgz'), ('integrity', pnpm_tool.integrity(b'other'))):
            with self.subTest(key=key), self.assertRaises(EvidenceError):
                plan.bind_evidence([{**self.fixture.record, key: value}])
        self.manifest['dependencies']['demo'] = '^2.0.0'
        with self.assertRaisesRegex(Invalid, 'stale'):
            PnpmPlan(self.files())

    def test_critical_young_and_unavailable_evidence_fail_without_install(self):
        from datetime import datetime, timezone
        from test_packages import CRITICAL
        plan = PnpmPlan(self.files())
        for changes in ({'vulnerabilities': [CRITICAL]},
                        {'published_at': datetime.now(timezone.utc).isoformat()}):
            with patch.object(self.fixture, 'assess', return_value={**self.fixture.record, **changes}), \
                    self.assertRaises(ResolutionError):
                plan.assess(self.fixture, RULES)
        with patch.object(self.fixture, 'assess', side_effect=EvidenceError('unavailable')), \
                self.assertRaises(EvidenceError):
            plan.assess(self.fixture, RULES)
        self.assertEqual(plan.assess(self.fixture, RULES)[0]['name'], 'demo')

    def test_lifecycle_requires_both_reviewed_name_and_supervisor_before_native_work(self):
        fixture = NpmFixture(fields={'scripts': {'postinstall': 'node build.js'}})
        self.lock['packages']['demo@1.0.0']['resolution']['integrity'] = fixture.record['integrity']
        record = {**fixture.record, 'filename': 'demo.tgz'}
        (self.root / 'demo.tgz').write_bytes(fixture.raw)
        for index, (names, runner) in enumerate(((set(), lambda cmd: None), ({'other'}, lambda cmd: None), ({'demo'}, None))):
            with self.subTest(names=names, supervised=runner is not None), \
                    patch.object(pnpm_tool, 'run') as native, \
                    self.assertRaisesRegex(EvidenceError, 'explicit controller approval'):
                PnpmPlan(self.files()).install(self.root, self.root / ('target-' + str(index)),
                                              [record], names, runner)
            native.assert_not_called()

    def test_shared_build_copy_preserves_links_and_export_still_rejects_escape(self):
        from ptw.package_build import WRAPPER, extract_result
        seed, target = self.root / 'seed', self.root / 'target'
        (seed / 'packages/demo').mkdir(parents=True)
        (seed / 'packages/demo/index.js').write_text('module.exports = 7;')
        (seed / 'node_modules').mkdir()
        (seed / 'node_modules/demo').symlink_to('../packages/demo')
        wrapper = WRAPPER.replace("'/seed'", repr(str(seed))).replace("'/target'", repr(str(target)))
        result = subprocess.run(['/usr/bin/python3', '-I', '-S', '-c', wrapper, '/usr/bin/true'],
                                capture_output=True, check=True)
        output = self.root / 'export'
        output.mkdir()
        extract_result(io.BytesIO(result.stdout), output)
        self.assertTrue((output / 'node_modules/demo').is_symlink())
        self.assertEqual((output / 'node_modules/demo/index.js').read_text(), 'module.exports = 7;')
        # External links remain inert during copying and are rejected at export.
        (seed / 'leak').symlink_to('/etc/passwd')
        shutil.rmtree(target)
        result = subprocess.run(['/usr/bin/python3', '-I', '-S', '-c', wrapper, '/usr/bin/true'],
                                capture_output=True, check=True)
        with self.assertRaisesRegex(EvidenceError, 'link escapes'):
            extract_result(io.BytesIO(result.stdout), self.root / 'rejected-export')

    def test_source_traversal_symlink_and_competing_authority_are_rejected(self):
        for name, text in self.files().items():
            (self.root / name).write_text(text)
        for pattern in ('../outside', '/outside', 'node_modules/*'):
            (self.root / 'pnpm-workspace.yaml').write_text(json.dumps({'packages': [pattern]}))
            with self.subTest(pattern=pattern), self.assertRaises(Invalid):
                read_inputs(self.root)
        (self.root / 'pnpm-workspace.yaml').write_text('packages: [packages/*]')
        (self.root / 'packages').symlink_to(self.root.parent, target_is_directory=True)
        with self.assertRaises((Invalid, OSError)):
            read_inputs(self.root)
        (self.root / 'pnpm-workspace.yaml').unlink()
        (self.root / 'package-lock.json').write_text('{}')
        with self.assertRaisesRegex(Invalid, 'Competing'):
            read_inputs(self.root)

    def test_configuration_and_unsupported_sources_cannot_change_native_authority(self):
        for value in ({'pnpm': {'overrides': {'demo': '2.0.0'}}},
                      {'packageManager': 'pnpm@9.0.0'}):
            files = self.files()
            files['package.json'] = json.dumps({**self.manifest, **value})
            with self.subTest(value=value), self.assertRaises(Invalid):
                PnpmPlan(files)
        files = self.files()
        files['pnpm-workspace.yaml'] = 'packages: []\nnodeLinker: hoisted\n'
        with self.assertRaises(Invalid):
            PnpmPlan(files)
        self.lock['packages']['demo@1.0.0']['resolution'] = {'directory': '../outside'}
        with self.assertRaises(Invalid):
            PnpmPlan(self.files())

    def test_artifact_path_substitution_is_rejected_before_native_execution(self):
        plan = PnpmPlan(self.files())
        for index, name in enumerate(('../outside.tgz', '/outside.tgz', 'nested/file.tgz')):
            with self.subTest(name=name), patch.object(pnpm_tool, 'run') as native, \
                    self.assertRaisesRegex(EvidenceError, 'filename'):
                plan.install(self.root, self.root / ('target-' + str(index)),
                             [{**self.fixture.record, 'filename': name}])
            native.assert_not_called()

    def synthetic_install(self, fixtures):
        """Disk-only verifier fixture. This does not establish native behavior."""
        plan = PnpmPlan(self.files())
        artifacts, target = self.root / 'artifacts', self.root / 'installed'
        artifacts.mkdir()
        records = []
        by_identity = {}
        for index, fixture in enumerate(fixtures):
            record = {**fixture.record, 'filename': str(index) + '.tgz'}
            records.append(record)
            (artifacts / record['filename']).write_bytes(fixture.raw)
            by_identity[record['name'] + '@' + record['version']] = fixture

        def install(arguments, *, cwd):
            if arguments == ['fetch']:
                (cwd / 'store').mkdir()
            else:
                self.assertEqual(arguments, ['install', '--frozen-lockfile'])
                locations = {}
                for context in self.lock['snapshots']:
                    identity = context.split('(', 1)[0]
                    fixture = by_identity[identity]
                    folder = cwd / 'node_modules/.pnpm' / context / 'node_modules' / fixture.record['name']
                    locations[context] = folder
                    folder.mkdir(parents=True)
                    with tarfile.open(fileobj=io.BytesIO(fixture.raw), mode='r:gz') as archive:
                        for member in archive:
                            path = folder / member.name.removeprefix('package/')
                            path.parent.mkdir(parents=True, exist_ok=True)
                            path.write_bytes(archive.extractfile(member).read())
                entries = [(cwd, self.lock['importers']['.'], True)] + [
                    (locations[c].parent.parent, e, False) for c, e in self.lock['snapshots'].items()]
                for folder, entry, importer in entries:
                    for field in ('dependencies', 'optionalDependencies'):
                        for name, ref in entry.get(field, {}).items():
                            reference = ref['version'] if importer else ref
                            link = folder / 'node_modules' / name
                            link.parent.mkdir(parents=True, exist_ok=True)
                            link.symlink_to(os.path.relpath(locations[name + '@' + reference], link.parent))
            return subprocess.CompletedProcess(arguments, 0, '', '')

        with patch.object(pnpm_tool, 'run', side_effect=install):
            plan.install(artifacts, target, records)
        return plan, target, records

    def test_installed_bytes_are_bound_to_archives_and_evidence(self):
        plan, target, records = self.synthetic_install([self.fixture])
        baseline = plan.verify_installed(target, records)
        folder = (target / 'node_modules/demo').resolve()
        original = (folder / 'index.js').read_bytes()
        for mode in ('changed', 'extra', 'missing', 'metadata'):
            with self.subTest(mode=mode):
                path = folder / ('package.json' if mode == 'metadata' else
                                 'extra.js' if mode == 'extra' else 'index.js')
                raw = path.read_bytes() if path.exists() else None
                if mode == 'missing':
                    path.unlink()
                else:
                    path.write_bytes((raw or b'') + b'\n')
                with self.assertRaisesRegex(EvidenceError, 'content differs'):
                    plan.verify_installed(target, records)
                if raw is None:
                    path.unlink()
                else:
                    path.write_bytes(raw)
        (folder / 'index.js').write_text('module.exports = "approved build";')
        plan.verify_installed(target, records, built={'demo'}, baseline=baseline)
        with self.assertRaisesRegex(EvidenceError, 'content differs'):
            plan.verify_installed(target, records, built={'unrelated'}, baseline=baseline)
        (folder / 'package.json').write_text(json.dumps({**self.fixture.manifest, 'main': 'extra.js'}))
        with self.assertRaisesRegex(EvidenceError, 'content differs'):
            plan.verify_installed(target, records, built={'demo'}, baseline=baseline)
        (folder / 'package.json').write_text(json.dumps(self.fixture.manifest))
        (folder / 'index.js').write_bytes(original)
        with self.assertRaisesRegex(EvidenceError, 'integrity'):
            plan.verify_installed(target, [{**records[0], 'integrity': pnpm_tool.integrity(b'changed')}])
        plan.verify_installed(target, records)

    def test_build_verifies_complete_tree_and_requires_trusted_baseline(self):
        plan, target, records = self.synthetic_install([self.fixture])
        folder = (target / 'node_modules/demo').resolve()
        shim = target / 'node_modules/.bin/demo'
        shim.parent.mkdir()
        shim.write_text('#!/bin/sh\nexit 0\n')
        modules = target / 'node_modules/.modules.yaml'
        modules.write_text('pendingBuilds: [demo@1.0.0]\n')
        baseline = plan.verify_installed(target, records)
        with self.assertRaisesRegex(EvidenceError, 'pre-build tree'):
            plan.verify_installed(target, records, built={'demo'})
        # Native named rebuild adds empty bookkeeping; archive output is useful.
        modules.write_text('pendingBuilds: [demo@1.0.0]\nignoredBuilds: []\n')
        (folder / 'dist').mkdir()
        (folder / 'dist/built.cjs').write_text('module.exports = 42;')
        plan.verify_installed(target, records, built={'demo'}, baseline=baseline)
        paths = [target / 'node_modules/demo.js', target / 'node_modules/unreviewed/index.js',
                 target / 'node_modules/.bin/unreviewed', folder.parent / 'demo.js',
                 folder / 'node_modules/demo.js', folder / 'dist/node_modules/demo/index.js',
                 folder / 'dist/package.json', folder / '.bin/unreviewed',
                 target / 'store/unreviewed.js', target / 'packages/unreviewed/index.js']
        for path in paths:
            with self.subTest(path=str(path.relative_to(target))):
                missing = []
                parent = path.parent
                while not parent.exists():
                    missing.append(parent)
                    parent = parent.parent
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('module.exports = 99;')
                with self.assertRaisesRegex(EvidenceError, 'protected installation tree'):
                    plan.verify_installed(target, records, built={'demo'}, baseline=baseline)
                path.unlink()
                for parent in missing:
                    parent.rmdir()
        for mode in ('content', 'executable', 'delete', 'link'):
            with self.subTest(shim=mode):
                raw, permissions = shim.read_bytes(), shim.stat().st_mode
                if mode == 'content':
                    shim.write_text('#!/bin/sh\nexit 42\n')
                elif mode == 'executable':
                    shim.chmod(0o700)
                else:
                    shim.unlink()
                    if mode == 'link':
                        shim.symlink_to('../demo/index.js')
                with self.assertRaisesRegex(EvidenceError, 'protected installation tree'):
                    plan.verify_installed(target, records, built={'demo'}, baseline=baseline)
                shim.unlink(missing_ok=True)
                shim.write_bytes(raw)
                shim.chmod(permissions)
        for path in (folder / 'redirect', target / 'node_modules/alias'):
            path.symlink_to(os.path.relpath(folder / 'index.js', path.parent))
            with self.assertRaisesRegex(EvidenceError, 'protected installation tree'):
                plan.verify_installed(target, records, built={'demo'}, baseline=baseline)
            path.unlink()
        modules.write_text('pendingBuilds: []\nignoredBuilds: []\n')
        with self.assertRaisesRegex(EvidenceError, 'protected installation tree'):
            plan.verify_installed(target, records, built={'demo'}, baseline=baseline)

    def test_exact_targets_and_peer_contexts_reject_compatible_substitution(self):
        newer = NpmFixture('demo', '1.1.0')
        peer = NpmFixture('peer', fields={'peerDependencies': {'demo': '^1.0.0'}})
        branch = NpmFixture('branch', fields={'dependencies': {'demo': '^1.0.0', 'peer': '^1.0.0'}})
        self.manifest['dependencies'].update(peer='^1.0.0', branch='^1.0.0')
        self.lock['importers']['.']['dependencies'].update(
            peer={'specifier': '^1.0.0', 'version': '1.0.0(demo@1.0.0)'},
            branch={'specifier': '^1.0.0', 'version': '1.0.0'})
        for fixture in (newer, peer, branch):
            self.lock['packages'][fixture.record['name'] + '@' + fixture.record['version']] = {
                'resolution': {'integrity': fixture.record['integrity'], 'tarball': fixture.record['url']}}
        self.lock['snapshots'].update({
            'demo@1.1.0': {},
            'peer@1.0.0(demo@1.0.0)': {'dependencies': {'demo': '1.0.0'}},
            'peer@1.0.0(demo@1.1.0)': {'dependencies': {'demo': '1.1.0'}},
            'branch@1.0.0': {'dependencies': {'demo': '1.1.0', 'peer': '1.0.0(demo@1.1.0)'}}})
        plan, target, records = self.synthetic_install([self.fixture, newer, peer, branch])
        for name, context in (('demo', 'demo@1.1.0'), ('peer', 'peer@1.0.0(demo@1.1.0)')):
            link = target / 'node_modules' / name
            original = os.readlink(link)
            link.unlink()
            link.symlink_to('.pnpm/' + context + '/node_modules/' + name)
            with self.subTest(name=name), self.assertRaisesRegex(EvidenceError, 'exact locked target|locked peer context'):
                plan.verify_installed(target, records)
            link.unlink()
            link.symlink_to(original)
        # A root/hoisted dependency must not hide an omitted locked peer edge.
        del plan.lock['snapshots']['peer@1.0.0(demo@1.0.0)']['dependencies']['demo']
        with self.assertRaisesRegex(EvidenceError, 'archive dependencies'):
            plan.verify_installed(target, records)

    def test_fetch_recipe_has_root_and_rejects_failure_or_mutation(self):
        plan = PnpmPlan(self.files())
        artifact = self.root / 'demo.tgz'
        artifact.write_bytes(self.fixture.raw)
        record = {**self.fixture.record, 'filename': artifact.name}
        for outcome in ('failure', 'mutation'):
            target = self.root / outcome

            def fetch(arguments, *, cwd):
                self.assertEqual(arguments, ['fetch'])
                recipe = load(cwd / 'pnpm-lock.yaml')
                self.assertEqual(recipe['importers']['.'], {})
                dependencies = [entry['dependencies'] for key, entry in recipe['importers'].items()
                                if key != '.']
                self.assertEqual(dependencies, [{'demo': {'specifier': '1.0.0', 'version': '1.0.0'}}])
                self.assertEqual(recipe['packages']['demo@1.0.0']['resolution']['integrity'], record['integrity'])
                if outcome == 'mutation':
                    # Even a semantically identical rewrite with exit zero is
                    # rejected. Do not weaken preservation to mask native repair.
                    with (cwd / 'pnpm-lock.yaml').open('a') as stream:
                        stream.write('\n')
                return subprocess.CompletedProcess(arguments, int(outcome == 'failure'), '', '')

            with self.subTest(outcome=outcome), patch.object(pnpm_tool, 'run', side_effect=fetch) as native, \
                    self.assertRaisesRegex(EvidenceError, 'without lock repair'):
                plan.install(self.root, target, [record])
            native.assert_called_once()
            self.assertFalse(target.exists(), 'failed preparation must not publish an installation')
            self.assertEqual(plan.files, self.files())


    def test_controller_dispatch_requires_exact_reviewed_input_and_origin_bindings(self):
        from ptw.dependency_binding import verify_npm
        from ptw.npm import installation_plan
        from ptw.policy import digest
        request = {'manager': 'pnpm', 'files': self.files()}
        self.assertIsInstance(installation_plan(request), PnpmPlan)
        with self.assertRaisesRegex(Invalid, 'reviewed authoritative'):
            verify_npm({'policy': {'project': {}}}, request)
        descriptor = {'lock_sha256': digest(request), 'inputs': {
            n: hashlib.sha256(text.encode()).hexdigest() for n, text in request['files'].items()},
            'artifacts': [{k: self.fixture.record[k] for k in ('name', 'version', 'url', 'integrity')}]}
        bundle = {'policy': {'project': {'npm_dependencies': descriptor}}}
        verify_npm(bundle, request, [self.fixture.record])
        with self.assertRaisesRegex(Invalid, 'origin or integrity'):
            verify_npm(bundle, request, [{**self.fixture.record, 'url': 'https://other.invalid/a.tgz'}])
        descriptor['inputs']['package.json'] = '0' * 64
        with self.assertRaisesRegex(Invalid, 'input bindings'):
            verify_npm(bundle, request)
        with self.assertRaisesRegex(Invalid, 'Malformed pnpm'):
            installation_plan({**request, 'unreviewed': True})


@unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'manager native pnpm checks required')
class PnpmNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = Path(tempfile.mkdtemp(prefix='ptw-pnpm-native-'))
        print('PNPM_TOOL_EVIDENCE ' + str(cls.evidence), flush=True)
        # Retained source hashes link every failed native attempt to this source.
        source = Path(__file__).resolve().parents[1]
        save(cls.evidence / 'source.json', {name: hashlib.sha256((source / name).read_bytes()).hexdigest()
             for name in ('ptw/pnpm_tool.py', 'ptw/pnpm.py', 'ptw/npm.py', 'ptw/packages.py',
                          'ptw/pnpm_resolution.py', 'ptw/onboarding.py', 'ptw/dependency_revision.py',
                          'ptw/cli.py', 'ptw/workflow.py', 'ptw/terminal.py', 'ptw/setup_templates.py',
                          'ptw/dependency_binding.py', 'ptw/execution.py', 'ptw/package_build.py',
                          'requirements.lock', 'tests/test_product_pnpm.py')})
        cls.tool = pnpm_tool.provision(cls.evidence / 'tool')

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix=self._testMethodName + '-', dir=self.evidence))
        self.repo = self.root / 'stage'
        self.repo.mkdir()
        self.enterContext(patch.dict(os.environ, {'PTW_PNPM_TOOL': str(self.tool)}))
        self.base = NpmFixture('ptw-base', files={'package/index.js': b'module.exports = 7;\n'})
        self.peer = NpmFixture('ptw-peer', fields={
            'peerDependencies': {'ptw-base': '^1.0.0'},
            'scripts': {'postinstall': 'node -e "require(\'fs\').writeFileSync(\'unapproved-build\',\'ran\')"'}},
            files={'package/index.js': b'module.exports = require("ptw-base") + 1;\n'})
        (self.repo / 'artifacts').mkdir()
        for fixture in (self.base, self.peer):
            (self.repo / 'artifacts' / (fixture.record['name'] + '.tgz')).write_bytes(fixture.raw)
        save(self.repo / 'package.json', {'name': 'ptw-root', 'version': '1.0.0', 'private': True,
            'packageManager': 'pnpm@' + pnpm_tool.VERSION,
            'dependencies': {'ptw-base': '^1.0.0', 'ptw-peer': '^1.0.0', 'ptw-math': 'workspace:*'},
            'scripts': {'postinstall': 'node -e "require(\'fs\').writeFileSync(\'root-build\',\'ran\')"'}})
        save(self.repo / 'packages/math/package.json', {'name': 'ptw-math', 'version': '1.0.0',
            'main': 'index.cjs', 'dependencies': {'ptw-base': '^1.0.0'}})
        (self.repo / 'packages/math/index.cjs').write_text('module.exports = require("ptw-base") * 2;\n')
        (self.repo / 'pnpm-workspace.yaml').write_text("packages:\n  - 'packages/*'\n")
        (self.repo / '.pnpmfile.cjs').write_text(
            'require("fs").writeFileSync("/resolution/pnpmfile-ran", "ran"); throw Error("hook ran");\n')
        # Synthetic authoritative v9 fixture, consumed by real pnpm. It is not
        # called a native resolution result and does not change registry URLs.
        (self.repo / 'pnpm-lock.yaml').write_text("""lockfileVersion: '9.0'
settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false
importers:
  .:
    dependencies:
      ptw-base:
        specifier: ^1.0.0
        version: 1.0.0
      ptw-peer:
        specifier: ^1.0.0
        version: 1.0.0(ptw-base@1.0.0)
      ptw-math:
        specifier: workspace:*
        version: link:packages/math
  packages/math:
    dependencies:
      ptw-base:
        specifier: ^1.0.0
        version: 1.0.0
packages:
  ptw-base@1.0.0:
    resolution: {integrity: 'BASE', tarball: 'BASE_URL'}
  ptw-peer@1.0.0:
    resolution: {integrity: 'PEER', tarball: 'PEER_URL'}
    peerDependencies:
      ptw-base: ^1.0.0
snapshots:
  ptw-base@1.0.0: {}
  ptw-peer@1.0.0(ptw-base@1.0.0):
    dependencies:
      ptw-base: 1.0.0
""".replace('BASE_URL', self.base.record['url']).replace('PEER_URL', self.peer.record['url'])
            .replace("'BASE'", repr(self.base.record['integrity']))
            .replace("'PEER'", repr(self.peer.record['integrity'])))
        self.before = self.inputs()
        save(self.root / 'inputs.json', {name: hashlib.sha256(raw).hexdigest() for name, raw in self.before.items()})

    def inputs(self):
        return {name: (self.repo / name).read_bytes() for name in
                ('package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml', 'packages/math/package.json')}

    def native(self, arguments, *, cwd=None):
        result = pnpm_tool.run(arguments, cwd=cwd or self.repo)
        # Safe labels diagnose the first causal error without publishing output.
        codes = sorted(set(re.findall(r'ERR_PNPM_[A-Z_]+', result.stdout + result.stderr)))
        self.assertEqual(result.returncode, 0, 'native pnpm failed: ' + ','.join(codes) + '; see hashed receipt')
        return result

    def seed(self):
        # A transport recipe, not a project lock or a resolver result. Native
        # fetch indexes content by registry identity AND integrity. Store-add
        # of a local filename instead indexes it by file: identity and cannot
        # satisfy the authoritative registry lock. Do not edit store internals.
        seed = self.root / 'seed'
        seed.mkdir()
        (seed / 'artifacts').mkdir()
        packages, sources, dependencies = {}, {}, {}
        for fixture in (self.base, self.peer):
            record = fixture.record
            key = record['name'] + '@' + record['version']
            filename = record['name'] + '.tgz'
            raw = (self.repo / 'artifacts' / filename).read_bytes()
            self.assertEqual(pnpm_tool.integrity(raw), record['integrity'])
            (seed / 'artifacts' / filename).write_bytes(raw)
            packages[key] = {'resolution': {'integrity': record['integrity'],
                                          'tarball': 'file:artifacts/' + filename}}
            dependencies[record['name']] = {'specifier': record['version'], 'version': record['version']}
            sources[key] = {'url': record['url'], 'integrity': record['integrity'],
                            'artifact_sha256': hashlib.sha256(raw).hexdigest()}
        # JSON is a YAML subset accepted by native pnpm. No project input is
        # parsed, converted, substituted or used for this generated recipe.
        save(seed / 'pnpm-lock.yaml', {'lockfileVersion': '9.0',
            'settings': {'autoInstallPeers': True, 'excludeLinksFromLockfile': False},
            'importers': {'.': {'dependencies': dependencies}},
            'packages': packages, 'snapshots': {key: {} for key in packages}})
        save(self.root / 'seed-sources.json', sources)
        return seed

    def fetch(self, seed):
        # Native fetch may rewrite its disposable recipe. Preserve both sides,
        # including failed attempts, without exposing native process output.
        before = (seed / 'pnpm-lock.yaml').read_bytes()
        (self.root / 'seed-before.yaml').write_bytes(before)
        report = {'before_sha256': hashlib.sha256(before).hexdigest()}
        try:
            result = pnpm_tool.run(['fetch'], cwd=seed)
            report.update(returncode=result.returncode, error_codes=sorted(set(
                re.findall(r'ERR_PNPM_[A-Z_]+', result.stdout + result.stderr))))
            return result
        finally:
            lock = seed / 'pnpm-lock.yaml'
            after = lock.read_bytes() if lock.exists() else None
            if after is not None:
                (self.root / 'seed-after.yaml').write_bytes(after)
            report['after_sha256'] = hashlib.sha256(after).hexdigest() if after is not None else None
            report['store_files'] = {str(path.relative_to(seed / 'store')):
                hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted((seed / 'store').rglob('*')) if path.is_file()}
            save(self.root / 'seed-fetch.json', report)

    def assert_populated(self, seed):
        # Observe pnpm's pinned native index format; never construct or repair it.
        # Both registry identity and archive integrity must name the index.
        for fixture, content in ((self.base, b'module.exports = 7;\n'),
                                 (self.peer, b'module.exports = require("ptw-base") + 1;\n')):
            digest = hashlib.sha512(fixture.raw).hexdigest()[:64]
            identity = fixture.record['name'] + '@' + fixture.record['version']
            indexes = list((seed / 'store').glob(
                '*/index/' + digest[:2] + '/' + digest[2:] + '-' + identity + '.json'))
            self.assertEqual(len(indexes), 1, 'missing native registry/integrity index: ' + identity)
            index = load(indexes[0])
            self.assertEqual(index['files']['index.js']['integrity'], pnpm_tool.integrity(content))
            digest = hashlib.sha512(content).hexdigest()
            suffix = '-exec' if index['files']['index.js']['mode'] & 0o111 else ''
            paths = list((seed / 'store').glob('*/files/' + digest[:2] + '/' + digest[2:] + suffix))
            self.assertEqual(len(paths), 1, 'missing native package content: ' + identity)
            self.assertEqual(paths[0].read_bytes(), content)

    def populate(self):
        seed = self.seed()
        result = self.fetch(seed)
        self.assertEqual(result.returncode, 0, 'native fetch failed; see seed-fetch.json')
        self.assert_populated(seed)
        # Only the native store crosses the boundary. The temporary recipe and
        # virtual store cannot replace the original project lock or its layout.
        (seed / 'store').rename(self.repo / 'store')
        shutil.rmtree(seed / 'artifacts')
        shutil.rmtree(self.repo / 'artifacts')
        self.assertEqual(self.inputs(), self.before)
        self.assertFalse((self.repo / 'node_modules').exists())

    def test_native_frozen_store_workspace_peer_import_and_hook_denial(self):
        self.populate()
        self.native(['install', '--frozen-lockfile'])
        self.assertEqual(self.inputs(), self.before)
        # Real imports, in a fresh offline namespace, are the positive oracle.
        code = 'const a=require("assert"); a.equal(require("ptw-peer"),8); a.equal(require("ptw-math"),14); console.log("PNPM_OK");'
        command = runtime_namespace() + ['--ro-bind', str(self.repo), '/target', '--chdir', '/target',
                                         '--', '/usr/bin/node', '-e', code]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30,
                                env={'PATH': '/usr/bin:/bin'})
        save(self.root / 'node-import.json', {'returncode': result.returncode,
            'stdout_sha256': hashlib.sha256(result.stdout.encode()).hexdigest(),
            'stderr_sha256': hashlib.sha256(result.stderr.encode()).hexdigest()})
        self.assertEqual(result.returncode, 0, 'confined Node import failed')
        self.assertEqual(result.stdout.strip(), 'PNPM_OK')
        self.assertTrue((self.repo / 'node_modules/ptw-peer').is_symlink())
        self.assertTrue((self.repo / 'node_modules/ptw-math').is_symlink())
        self.assertEqual((self.repo / 'node_modules/ptw-math').resolve(), self.repo / 'packages/math')
        self.assertFalse(list(self.repo.rglob('unapproved-build')))
        self.assertFalse((self.repo / 'root-build').exists())
        self.assertFalse((self.repo / 'pnpmfile-ran').exists())
        for path in (self.repo / 'node_modules/.pnpm').rglob('*.js'):
            self.assertEqual(path.stat().st_nlink, 1, 'installed content must not alias mutable store files')

    def test_native_lock_inspection_before_install(self):
        result = self.native(['list', '--recursive', '--json', '--long', '--depth', 'Infinity', '--lockfile-only'])
        graph = json.loads(result.stdout)
        self.assertIsInstance(graph, list)
        roots = {entry['name']: entry for entry in graph}
        self.assertIn('ptw-root', roots)
        self.assertIn('ptw-math', roots)
        self.assertEqual(roots['ptw-root']['dependencies']['ptw-base']['version'], '1.0.0')
        self.assertIn('ptw-peer', roots['ptw-root']['dependencies'])
        self.assertEqual(self.inputs(), self.before)
        self.assertFalse((self.repo / 'node_modules').exists())
        self.assertFalse((self.repo / 'pnpmfile-ran').exists())

    def test_native_stale_lock_fails_without_repair(self):
        self.populate()
        manifest = load(self.repo / 'package.json')
        manifest['dependencies']['ptw-base'] = '^2.0.0'
        (self.repo / 'package.json').write_text(json.dumps(manifest))
        before = self.inputs()
        result = pnpm_tool.run(['install', '--frozen-lockfile'], cwd=self.repo)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('ERR_PNPM_OUTDATED_LOCKFILE', result.stdout + result.stderr)
        self.assertEqual(self.inputs(), before)
        self.assertFalse((self.repo / 'node_modules/ptw-base').exists())

    def test_native_missing_store_cannot_download_or_run_hooks(self):
        result = pnpm_tool.run(['install', '--frozen-lockfile'], cwd=self.repo)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('ERR_PNPM_NO_OFFLINE_TARBALL', result.stdout + result.stderr)
        self.assertEqual(self.inputs(), self.before)
        self.assertFalse((self.repo / 'node_modules/ptw-peer/index.js').exists())
        self.assertFalse((self.repo / 'pnpmfile-ran').exists())
        self.assertFalse((self.repo / 'root-build').exists())

    def test_native_seed_wrong_integrity_cannot_supply_frozen_install(self):
        seed = self.seed()
        # Keep the expected package identity and integrity but supply bytes of
        # the other package. Native fetch must reject this before reuse.
        (seed / 'artifacts/ptw-base.tgz').write_bytes(self.peer.raw)
        before = (seed / 'pnpm-lock.yaml').read_bytes()
        result = self.fetch(seed)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('ERR_PNPM_TARBALL_INTEGRITY', result.stdout + result.stderr)
        self.assertEqual((seed / 'pnpm-lock.yaml').read_bytes(), before)
        (seed / 'store').rename(self.repo / 'store')
        result = pnpm_tool.run(['install', '--frozen-lockfile'], cwd=self.repo)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.inputs(), self.before)
        self.assertFalse((self.repo / 'node_modules/ptw-base/index.js').exists())
        self.assertFalse((self.repo / 'root-build').exists())
        self.assertFalse((self.repo / 'pnpmfile-ran').exists())

    def test_native_corrupt_store_cannot_supply_frozen_install(self):
        self.populate()
        matches = [path for path in (self.repo / 'store').rglob('*')
                   if path.is_file() and path.read_bytes() == b'module.exports = 7;\n']
        self.assertTrue(matches, 'native store must contain the base module')
        for path in matches:
            path.write_bytes(b'module.exports = 99;\n')
        result = pnpm_tool.run(['install', '--frozen-lockfile'], cwd=self.repo)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.inputs(), self.before)
        self.assertFalse((self.repo / 'node_modules/ptw-base/index.js').exists())
        self.assertFalse((self.repo / 'root-build').exists())

    def test_native_malformed_lock_is_not_ignored(self):
        (self.repo / 'pnpm-lock.yaml').write_text('lockfileVersion: [unterminated\n')
        before = self.inputs()
        result = pnpm_tool.run(['install', '--frozen-lockfile'], cwd=self.repo)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.inputs(), before)
        self.assertFalse((self.repo / 'node_modules/ptw-base').exists())

    def test_adapter_frozen_assessed_install_preserves_workspace_peer_graph(self):
        # Remove the fixture dependency's build requirement for this no-build
        # primitive. A separate test proves that requirement is denied.
        peer = NpmFixture('ptw-peer', fields={'peerDependencies': {'ptw-base': '^1.0.0'}},
            files={'package/index.js': b'module.exports = require("ptw-base") + 1;\n'})
        lock = self.repo / 'pnpm-lock.yaml'
        lock.write_text(lock.read_text().replace(self.peer.record['integrity'], peer.record['integrity']))
        files, _ = read_inputs(self.repo)
        original = dict(files)
        plan = PnpmPlan(files)
        graph = plan.inspect(self.root / 'inspect')
        self.assertEqual({n['name'] for n in graph}, {'ptw-root', 'ptw-math'})
        artifacts = self.root / 'broker-artifacts'
        artifacts.mkdir()
        records = []
        for index, fixture in enumerate((self.base, peer)):
            record = {**fixture.record, 'filename': str(index) + '.tgz'}
            (artifacts / record['filename']).write_bytes(fixture.raw)
            records.append(record)
        target = self.root / 'installed'
        plan.install(artifacts, target, records)
        self.assertEqual(read_inputs(self.repo)[0], original)
        self.assertEqual({n: (target / n).read_text() for n in files}, original)
        self.assertFalse((target / 'root-build').exists())
        self.assertFalse((target / 'packages/math/index.cjs').exists(), 'source is never copied into a package cache')
        self.assertEqual((target / 'node_modules/ptw-math').resolve(), target / 'packages/math')
        result = subprocess.run(runtime_namespace() + ['--ro-bind', str(target), '/target', '--chdir', '/target',
            '--', '/usr/bin/node', '-e', 'console.log(require("ptw-peer"))'],
            env={'PATH': '/usr/bin:/bin'}, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), '8')
        # A successful native exit alone is insufficient. Independently detect
        # a missing required link and an installed identity substitution.
        (target / 'node_modules/ptw-peer').unlink()
        with self.assertRaisesRegex(EvidenceError, 'required dependency'):
            plan.verify_installed(target, records)

    def test_adapter_denies_lifecycle_and_source_substitution_before_publication(self):
        files, _ = read_inputs(self.repo)
        plan = PnpmPlan(files)
        artifacts = self.root / 'assessed-artifacts'
        artifacts.mkdir()
        records = []
        for index, fixture in enumerate((self.base, self.peer)):
            record = {**fixture.record, 'filename': str(index) + '.tgz'}
            (artifacts / record['filename']).write_bytes(fixture.raw)
            records.append(record)
        with self.assertRaisesRegex(EvidenceError, 'explicit controller approval'):
            plan.install(artifacts, self.root / 'denied', records)
        self.assertFalse((self.root / 'denied').exists())
        self.assertFalse(list(self.root.rglob('unapproved-build')))
        records[0] = {**records[0], 'url': 'https://unreviewed.invalid/base.tgz'}
        with self.assertRaisesRegex(EvidenceError, 'origin'):
            plan.install(artifacts, self.root / 'substituted', records)
        self.assertFalse((self.root / 'substituted').exists())

    def resolution_provider(self):
        # No dependency hooks in the useful-work fixture. Other tests cover
        # explicit native hook approval and physical hook denial separately.
        peer = NpmFixture('ptw-peer', fields={'peerDependencies': {'ptw-base': '^1.0.0'}},
            files={'package/index.js': b'module.exports = require("ptw-base") + 1;\n'})
        lock = self.repo / 'pnpm-lock.yaml'
        lock.write_text(lock.read_text().replace(self.peer.record['integrity'], peer.record['integrity']))
        self.peer = peer
        return PnpmRegistryFixture([self.base, peer])

    def test_native_reviewed_resolution_excludes_critical_young_and_preserves_ranges(self):
        from datetime import datetime, timezone
        from test_packages import CRITICAL
        from ptw.pnpm_resolution import resolve_pnpm
        provider = self.resolution_provider()
        for version in ('1.1.0', '1.2.0'):
            provider.fixtures['ptw-base', version] = NpmFixture('ptw-base', version)
        provider.overrides['ptw-base', '1.1.0'] = {'vulnerabilities': [CRITICAL]}
        provider.overrides['ptw-base', '1.2.0'] = {'published_at': datetime.now(timezone.utc).isoformat()}
        original = read_inputs(self.repo)[0]
        result = resolve_pnpm(self.repo, self.root / 'review-resolution', RULES, provider=provider, update=True)
        self.assertEqual({r['name']: r['version'] for r in result['artifacts']},
                         {'ptw-base': '1.0.0', 'ptw-peer': '1.0.0'})
        self.assertIn(('ptw-base', '1.1.0'), provider.assessments)
        for name in original:
            if name != 'pnpm-lock.yaml':
                self.assertEqual(result['files'][name], original[name])
        self.assertEqual(read_inputs(self.repo)[0], original)
        PnpmPlan(result['files']).bind_evidence([provider.assess(r['name'], r['version']) for r in result['artifacts']])
        self.assertFalse(list(self.root.rglob('pnpmfile-ran')))
        self.assertFalse(list(self.root.rglob('root-build')))

    def test_native_reviewed_resolution_exact_pin_outage_and_budget_fail_closed(self):
        from test_packages import CRITICAL
        from ptw.pnpm_resolution import resolve_pnpm
        provider = self.resolution_provider()
        provider.fixtures['ptw-base', '1.1.0'] = NpmFixture('ptw-base', '1.1.0')
        manifest = load(self.repo / 'package.json')
        manifest['dependencies']['ptw-base'] = '1.1.0'
        (self.repo / 'package.json').write_text(json.dumps(manifest) + '\n')
        original = read_inputs(self.repo)[0]
        for mode in ('exact', 'outage', 'budget'):
            provider.overrides['ptw-base', '1.1.0'] = {
                'vulnerabilities': None if mode == 'outage' else [CRITICAL]}
            with self.subTest(mode=mode), self.assertRaises(Invalid):
                resolve_pnpm(self.repo, self.root / mode, RULES, provider=provider, update=True,
                             **({'max_assessments': 1} if mode == 'budget' else {}))
            self.assertEqual(read_inputs(self.repo)[0], original)
            self.assertEqual(load(self.root / mode / 'resolution.json')['outcome'],
                {'exact': 'unsatisfiable', 'outage': 'unavailable_evidence', 'budget': 'budget_exhausted'}[mode])

    def test_native_transitive_policy_selection_and_inactive_optional_preservation(self):
        from datetime import datetime, timezone
        from test_packages import CRITICAL
        from ptw.pnpm_resolution import resolve_pnpm
        provider = self.resolution_provider()
        provider.fixtures['ptw-base', '1.0.0'] = NpmFixture('ptw-base', fields={
            'dependencies': {'ptw-leaf': '^1.0.0'},
            'optionalDependencies': {'ptw-darwin': '1.0.0'}}, files={
                'package/index.js': b'module.exports = require("ptw-leaf");'})
        for version in ('1.0.0', '1.1.0', '1.2.0'):
            provider.fixtures['ptw-leaf', version] = NpmFixture('ptw-leaf', version,
                files={'package/index.js': b'module.exports = 7;'})
        provider.fixtures['ptw-darwin', '1.0.0'] = NpmFixture('ptw-darwin', fields={'os': ['darwin']},
            files={'package/index.js': b'throw Error("inactive optional package loaded");'})
        provider.overrides['ptw-leaf', '1.1.0'] = {'vulnerabilities': [CRITICAL]}
        provider.overrides['ptw-leaf', '1.2.0'] = {'published_at': datetime.now(timezone.utc).isoformat()}
        original = read_inputs(self.repo)[0]
        resolved = resolve_pnpm(self.repo, self.root / 'transitive-resolution', RULES,
                                provider=provider, update=True)
        plan = PnpmPlan(resolved['files'])
        self.assertEqual(plan.selected['ptw-leaf@1.0.0'], '1.0.0')
        self.assertNotIn('ptw-leaf@1.1.0', plan.selected)
        self.assertNotIn('ptw-leaf@1.2.0', plan.selected)
        self.assertIn(('ptw-leaf', '1.1.0'), provider.assessments)
        self.assertIn('ptw-darwin@1.0.0', plan.lock['packages'])
        self.assertEqual(read_inputs(self.repo)[0], original)
        records = [provider.assess(r['name'], r['version']) for r in resolved['artifacts']]
        artifacts, target = self.root / 'transitive-artifacts', self.root / 'transitive-install'
        artifacts.mkdir()
        for record in records:
            provider.download(record, artifacts / record['filename'])
        plan.install(artifacts, target, records)
        result = subprocess.run(runtime_namespace() + ['--ro-bind', str(target), '/target', '--chdir', '/target',
            '--', '/usr/bin/node', '-e', 'if(require("ptw-peer")!==8)throw Error("transitive graph");'
            'const base=require.resolve("ptw-base");let loaded=false;'
            'try{require.resolve("ptw-darwin",{paths:[base]});loaded=true}catch{}'
            'if(loaded)throw Error("inactive optional installed");console.log("TRANSITIVE_OK_OPTIONAL_ABSENT");'],
            env={'PATH': '/usr/bin:/bin'}, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('TRANSITIVE_OK_OPTIONAL_ABSENT', result.stdout)
        (self.repo / 'pnpm-lock.yaml').write_text(resolved['files']['pnpm-lock.yaml'])
        frozen = read_inputs(self.repo)[0]
        provider.overrides['ptw-leaf', '1.0.0'] = {'vulnerabilities': [CRITICAL]}
        with self.assertRaisesRegex(Invalid, 'violates policy'):
            resolve_pnpm(self.repo, self.root / 'forbidden-transitive', RULES, provider=provider)
        self.assertEqual(read_inputs(self.repo)[0], frozen)

    def test_native_exact_locked_targets_and_peer_context_substitution(self):
        from ptw.pnpm_resolution import resolve_pnpm
        provider = self.resolution_provider()
        provider.fixtures['ptw-base', '1.1.0'] = NpmFixture('ptw-base', '1.1.0',
            files={'package/index.js': b'module.exports = 17;\n'})
        # Native pnpm can prefer the member's exact 1.0.0 for a compatible
        # root range. Require distinct versions to exercise two peer contexts;
        # the peer's ^1.0.0 constraint still accepts either base version.
        root_manifest = load(self.repo / 'package.json')
        root_manifest['dependencies']['ptw-base'] = '1.1.0'
        (self.repo / 'package.json').write_text(json.dumps(root_manifest) + '\n')
        member = self.repo / 'packages/math/package.json'
        manifest = load(member)
        manifest['dependencies'] = {'ptw-base': '1.0.0', 'ptw-peer': '^1.0.0'}
        member.write_text(json.dumps(manifest) + '\n')
        original = read_inputs(self.repo)[0]
        resolved = resolve_pnpm(self.repo, self.root / 'resolve-contexts', RULES, provider=provider, update=True)
        plan = PnpmPlan(resolved['files'])
        contexts = [key for key in plan.lock['snapshots'] if key.startswith('ptw-peer@')]
        self.assertEqual(set(contexts), {'ptw-peer@1.0.0(ptw-base@1.0.0)',
                                         'ptw-peer@1.0.0(ptw-base@1.1.0)'})
        records = [provider.assess(r['name'], r['version']) for r in resolved['artifacts']]
        artifacts, target = self.root / 'assessed-artifacts', self.root / 'installed-contexts'
        artifacts.mkdir()
        for record in records:
            provider.download(record, artifacts / record['filename'])
        plan.install(artifacts, target, records)
        result = subprocess.run(runtime_namespace() + ['--ro-bind', str(target), '/target', '--chdir', '/target',
            '--', '/usr/bin/node', '-e', 'console.log(require("ptw-peer")); '
            'console.log(require("./packages/math/node_modules/ptw-peer"));'],
            env={'PATH': '/usr/bin:/bin'}, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ['18', '8'])
        self.assertEqual(read_inputs(self.repo)[0], original)
        changed = target / 'node_modules/ptw-base/index.js'
        content = changed.read_bytes()
        changed.write_text('module.exports = "substituted";')
        with self.assertRaisesRegex(EvidenceError, 'content differs'):
            plan.verify_installed(target, records)
        changed.write_bytes(content)
        peer_folder = (target / 'node_modules/ptw-peer').resolve()
        for link in (target / 'node_modules/ptw-base', target / 'node_modules/ptw-peer',
                     peer_folder.parent / 'ptw-base'):
            # The last replacement satisfies the archive's peer range but
            # violates the exact native lock edge, independently of root pins.
            destination = (target / 'packages/math/node_modules' / link.name).resolve()
            original_link = os.readlink(link)
            link.unlink()
            link.symlink_to(os.path.relpath(destination, link.parent))
            with self.subTest(link=str(link.relative_to(target))), self.assertRaisesRegex(
                    EvidenceError, 'exact locked target|locked peer context'):
                plan.verify_installed(target, records)
            link.unlink()
            link.symlink_to(original_link)
        plan.verify_installed(target, records)

    def test_native_setup_terminal_review_and_protected_build(self):
        self.setup_terminal_build(dependency_build=False)

    def test_native_setup_requires_explicit_dependency_build_review(self):
        self.setup_terminal_build(dependency_build=True)

    def setup_terminal_build(self, *, dependency_build):
        from test_product_onboarding import Terminal
        from ptw.onboarding import private_directory
        from ptw.store import Store
        from ptw.monitor import remove
        from ptw.supervisor import Supervisor
        from ptw.workflow import dispatch
        from ptw.workspace import request
        provider = (PnpmRegistryFixture([self.base, self.peer]) if dependency_build
                    else self.resolution_provider())
        registry = self.root / 'synthetic-registry.json'
        provider.write(registry)
        manifest = load(self.repo / 'package.json')
        manifest['scripts']['build'] = 'node src/build.cjs'
        (self.repo / 'package.json').write_text(json.dumps(manifest) + '\n')
        (self.repo / 'src').mkdir()
        (self.repo / 'src/build.cjs').write_text('const fs=require("fs");'
            'if(require("ptw-peer")!==8||require("ptw-math")!==14)throw Error("wrong graph");'
            'fs.writeFileSync("dist/result.txt","PNPM_TERMINAL_BUILD_OK");')
        original = read_inputs(self.repo)[0]
        self.enterContext(patch.dict(os.environ, {'PTW_USER_STATE': str(self.root / 'operator')}))
        script = ('import sys\nfrom unittest.mock import patch\n'
            'sys.path.insert(0,' + repr(str(Path(__file__).resolve().parent)) + ')\n'
            'from test_product_pnpm import PnpmRegistryFixture\nfrom ptw.cli import main\n'
            'provider=PnpmRegistryFixture.read(' + repr(str(registry)) + ')\n'
            'with patch("ptw.codex.require_login"), patch("ptw.pnpm_resolution.NpmEvidence", return_value=provider):\n'
            '    main()\n')
        # Login is not exercised, read or copied. Review, native pnpm, controller,
        # publication and protected work are real; registry evidence is synthetic.
        if dependency_build:
            terminal = Terminal([sys.executable, '-B', '-c', script, 'codex', '--repo', str(self.repo),
                '--goal', 'Reject local lifecycle authority', '--editable', 'src,dist',
                '--files', 'packages/math/index.cjs', '--setup-only', '--pnpm-build', 'ptw-math'],
                self.root / 'setup-invalid-build')
            try:
                terminal.wait(lambda: terminal.exited, 180)
            finally:
                code = terminal.close()
            self.assertEqual(code, 2, terminal.text[-2000:])
            self.assertIn('exact registry package names', terminal.text)
            self.assertNotIn('Approve exactly this policy?', terminal.text)
            self.assertFalse((self.repo / '.ptw').exists())
            self.assertFalse(list(self.root.rglob('unapproved-build')))
        for answer in ('reject', 'eof', 'interrupt', 'yes'):
            terminal = Terminal([sys.executable, '-B', '-c', script, 'codex', '--repo', str(self.repo),
                '--goal', 'Build the selected pnpm workspace', '--editable', 'src,dist',
                '--files', 'packages/math/index.cjs', '--setup-only'] +
                (['--pnpm-build', 'ptw-peer'] if dependency_build else []), self.root / ('setup-' + answer))
            try:
                terminal.expect('Approve exactly this policy?', 180)
                self.assertEqual(read_inputs(self.repo)[0], original)
                terminal.send('details')
                terminal.expect('Reviewed npm inputs and artifacts:', 5)
                self.assertIn('pnpm-lock.yaml', terminal.text)
                self.assertIn('build', terminal.text)
                self.assertIn('source builds ' + ('npm:ptw-peer' if dependency_build else 'none'), terminal.text)
                self.assertFalse(list(self.root.rglob('unapproved-build')))
                if answer in ('eof', 'interrupt'):
                    os.write(terminal.fd, b'\x04' if answer == 'eof' else b'\x03')
                else:
                    terminal.send(answer)
                terminal.wait(lambda: terminal.exited, 30)
            finally:
                code = terminal.close()
            self.assertEqual(code, 0 if answer == 'yes' else 130 if answer in ('eof', 'interrupt') else 2, terminal.text[-2000:])
            self.assertEqual(read_inputs(self.repo)[0], original)
            if answer != 'yes':
                self.assertFalse((self.repo / '.ptw').exists())
                self.assertFalse((self.repo / 'dist').exists())
        directory = private_directory(self.repo)
        record = load(directory / 'project.json')
        store = Store(record['state'])

        def cleanup():
            store.stop(record['project'])
            Supervisor(store).reconcile()
            remove(store)
        self.addCleanup(cleanup)
        bundle = load(record['bundle'])
        self.assertEqual(bundle['policy']['project']['packages']['build_packages'],
                         ['npm:ptw-peer'] if dependency_build else [])
        actor = store.register(record['project'], 'work')
        lock_id = next(r for r, v in bundle['inventory']['resources'].items() if v['path'] == 'pnpm-lock.yaml')
        with patch('ptw.registry.provider_for', return_value=provider):
            installed = dispatch(store, actor, 'terminal-install', request('install', lock_id, content='pnpm'))
        self.assertTrue(installed['allowed'], installed)
        package = store.directory / 'package-sets' / installed['package_set']
        self.assertEqual((package / 'node_modules/ptw-peer/unapproved-build').exists(), dependency_build)
        result = dispatch(store, actor, 'terminal-build', request('run', 'build',
            content=json.dumps({'package_sets': [installed['package_set']]})))
        self.assertTrue(result['allowed'], result)
        self.assertEqual(result['exit_code'], 0, result)
        self.assertEqual((self.repo / 'dist/result.txt').read_text(), 'PNPM_TERMINAL_BUILD_OK')
        self.assertFalse((self.repo / 'root-build').exists())
        self.assertFalse((self.repo / 'package-lock.json').exists())
        self.assertEqual(read_inputs(self.repo)[0], original)

    def test_native_revision_terminal_retains_grants_history_and_revokes_sessions(self):
        self.revision_terminal()

    def test_native_revision_concurrent_edit_preserves_current_policy_and_session(self):
        self.revision_terminal(failure='concurrent')

    def test_native_revision_failed_publication_recovers_without_reopening_sessions(self):
        self.revision_terminal(failure='publication')

    def revision_terminal(self, failure=None):
        from test_product_onboarding import Terminal
        from ptw.onboarding import private_directory
        from ptw.policy import approve, compile_policy, digest
        from ptw.store import Store
        from ptw.workspace import Workspace, request, scan, stamp
        from ptw.supervisor import Supervisor
        from ptw.monitor import remove
        from ptw.setup_templates import template
        from ptw.pnpm_resolution import resolve_pnpm
        from ptw.dependency_binding import verify_inputs
        from ptw.packages import PackageControl, mounted_set
        provider = self.resolution_provider()
        initial = resolve_pnpm(self.repo, self.root / 'initial', RULES, provider=provider)
        self.enterContext(patch.dict(os.environ, {'PTW_USER_STATE': str(self.root / 'operator')}))
        directory = private_directory(self.repo)
        (self.repo / 'dist').mkdir()
        (self.repo / '.ptw').mkdir()
        policy, inv = template(self.repo, 'pnpm-revision', 'Review pnpm dependencies',
            {'packages/math/index.cjs': 'file', 'dist': 'tree'}, list(initial['inputs']), [],
            ['npm:ptw-base', 'npm:ptw-peer', 'npm:unrelated'], 1, 3)
        resources = [r for r, v in inv['resources'].items() if v['path'].startswith('packages/math/')]
        snapshot = scan(inv, resources)
        policy['project']['npm_dependencies'] = {'root': '', 'inputs': initial['inputs'],
            'artifacts': initial['artifacts'], 'lock_sha256': digest(initial['lock']),
            'sources': [{'path': 'packages/math', 'resources': resources,
                         'snapshot_sha256': digest({p: [stamp(e), e.get('mode')] for p, e in snapshot.items()})}]}
        policy['project']['packages']['build_packages'] = ['npm:unrelated']
        old = approve(policy, inv, digest(compile_policy(policy, inv)), 'synthetic operator')
        save(directory / 'approved.json', old)
        save(self.repo / '.ptw/policy.json', policy)
        store = Store(directory / 'controller')
        store.activate(old)

        def cleanup():
            store.stop('pnpm-revision')
            Supervisor(store).reconcile()
            remove(store)
        self.addCleanup(cleanup)
        save(directory / 'project.json', dict(project='pnpm-revision', repo=str(self.repo), state=str(store.directory),
            bundle=str(directory / 'approved.json'), policy_sha256=old['approval']['sha256'], task='work',
            language='javascript', publication_sha256='synthetic-no-setup-publication'))
        actor = store.register('pnpm-revision', 'work')
        installed = PackageControl(store, provider=provider).install(actor['token'], 'old-install', initial['lock'], ecosystem='npm')
        self.assertTrue(installed['allowed'], installed)
        self.assertFalse(Workspace(store).request(actor['token'], 'retained', request('read', 'missing'))['allowed'])
        provider.fixtures['ptw-base', '1.1.0'] = NpmFixture('ptw-base', '1.1.0')
        registry = self.root / 'revision-registry.json'
        provider.write(registry)
        original = read_inputs(self.repo)[0]
        if failure:
            from types import SimpleNamespace
            from ptw import dependency_revision as revision
            args = SimpleNamespace(repo=str(self.repo), root='', ecosystem='npm', task='work',
                source=None, operation='update', specs=['ptw-base@^1.0.0'], group=None)
            calls = []
            move = revision.move

            def fail_once(source, destination):
                calls.append(str(destination))
                if len(calls) == 3:
                    raise OSError('synthetic interrupted pnpm publication')
                return move(source, destination)

            def answer(*args):
                if failure == 'concurrent':
                    (self.repo / 'package.json').write_text(original['package.json'] + '\n')
                return 'yes'

            with patch('ptw.onboarding.ask', side_effect=answer), \
                    patch('ptw.registry.provider_for', return_value=provider), \
                    patch.object(revision, 'move', side_effect=fail_once if failure == 'publication' else move):
                with self.assertRaisesRegex(OSError if failure == 'publication' else Invalid,
                        'interrupted pnpm publication' if failure == 'publication' else 'changed after review'):
                    revision.start(args)
            with store.locked() as db:
                row, current = store.project(db, 'pnpm-revision')
                self.assertEqual(current, old)
                self.assertFalse(row['setup_pending'])
                self.assertFalse(row['stopped'])
                self.assertEqual(row['violations'], 1)
                if failure == 'publication':
                    with self.assertRaisesRegex(Invalid, 'Session ended'):
                        store.session(db, actor['token'])
                else:
                    store.session(db, actor['token'])
            expected = {**original, **({'package.json': original['package.json'] + '\n'}
                                       if failure == 'concurrent' else {})}
            self.assertEqual(read_inputs(self.repo)[0], expected)
            if failure == 'publication':
                self.assertEqual(load(directory / 'dependency-journal.json')['phase'], 'rolled-back')
                verify_inputs(current)
                fresh = store.register('pnpm-revision', 'work')
                restored = PackageControl(store, provider=provider).install(
                    fresh['token'], 'rollback-install', initial['lock'], ecosystem='npm')
                self.assertTrue(restored['allowed'], restored)
            return
        script = ('import sys\nfrom unittest.mock import patch\n'
            'sys.path.insert(0,' + repr(str(Path(__file__).resolve().parent)) + ')\n'
            'from test_product_pnpm import PnpmRegistryFixture\nfrom ptw.cli import main\n'
            'with patch("ptw.registry.provider_for", return_value=PnpmRegistryFixture.read(' + repr(str(registry)) + ')):\n'
            '    main()\n')
        for answer in ('reject', 'cancel', 'eof', 'yes'):
            terminal = Terminal([sys.executable, '-B', '-c', script, 'deps', 'update', 'ptw-base@^1.0.0',
                '--repo', str(self.repo), '--ecosystem', 'npm'], self.root / ('revision-' + answer))
            try:
                terminal.expect('Approve dependency revision?', 180)
                self.assertEqual(read_inputs(self.repo)[0], original)
                terminal.send('details')
                terminal.expect('Approve exactly this dependency revision?', 5)
                self.assertIn('pnpm-lock.yaml', terminal.text)
                if answer == 'eof':
                    os.write(terminal.fd, b'\x04')
                else:
                    terminal.send(answer)
                terminal.wait(lambda: terminal.exited, 30)
            finally:
                code = terminal.close()
            self.assertEqual(code, 0 if answer == 'yes' else 130 if answer == 'eof' else 2, terminal.text[-2000:])
            self.assertEqual(store.status('pnpm-revision')['violations'], 1)
            if answer != 'yes':
                self.assertEqual(read_inputs(self.repo)[0], original)
                with store.locked() as db:
                    store.session(db, actor['token'])
        with store.locked() as db:
            _, current = store.project(db, 'pnpm-revision')
            with self.assertRaisesRegex(Invalid, 'Session ended'):
                store.session(db, actor['token'])
        verify_inputs(current)
        self.assertEqual(current['policy']['project']['grants'], old['policy']['project']['grants'])
        self.assertIn('npm:unrelated', current['policy']['project']['packages']['allowed_names'])
        self.assertEqual(current['policy']['project']['packages']['build_packages'], ['npm:unrelated'])
        self.assertEqual(current['policy']['project']['escalation'], old['policy']['project']['escalation'])
        self.assertIn(('ptw-base', '1.1.0'), {(r['name'], r['version']) for r in current['policy']['project']['npm_dependencies']['artifacts']})
        self.assertFalse((self.repo / 'package-lock.json').exists())
        new_actor = store.register('pnpm-revision', 'work')
        with store.locked() as db:
            actor_row = store.session(db, new_actor['token'])
            with self.assertRaisesRegex(Invalid, 'obsolete policy revision'):
                mounted_set(store, db, actor_row, installed['package_set'])
        current_lock = {'manager': 'pnpm', 'files': read_inputs(self.repo)[0]}
        installed = PackageControl(store, provider=provider).install(new_actor['token'], 'new-install', current_lock, ecosystem='npm')
        self.assertTrue(installed['allowed'], installed)

    def controller(self, *, lifecycle=False, approve_build=False, build_script=None):
        """Explicit synthetic operator approval, real controller and supervisor."""
        import copy
        from ptw.policy import approve, compile_policy, digest
        from ptw.store import Store
        from ptw.supervisor import Supervisor
        from ptw.workspace import scan, stamp
        if build_script is not None:
            peer = NpmFixture('ptw-peer', fields={
                'peerDependencies': {'ptw-base': '^1.0.0'},
                'scripts': {'postinstall': 'node build.cjs'}},
                files={'package/index.js': b'module.exports = require("ptw-base") + 1;\n',
                       'package/build.cjs': build_script.encode()})
            lock = self.repo / 'pnpm-lock.yaml'
            lock.write_text(lock.read_text().replace(self.peer.record['integrity'], peer.record['integrity']))
            self.peer = peer
            lifecycle = True
        if not lifecycle:
            peer = NpmFixture('ptw-peer', fields={'peerDependencies': {'ptw-base': '^1.0.0'}},
                files={'package/index.js': b'module.exports = require("ptw-base") + 1;\n'})
            lock = self.repo / 'pnpm-lock.yaml'
            lock.write_text(lock.read_text().replace(self.peer.record['integrity'], peer.record['integrity']))
            self.peer = peer
        files, _ = read_inputs(self.repo)
        self.specs = {'manager': 'pnpm', 'files': files}
        fixtures = {f.record['name']: f for f in (self.base, self.peer)}

        class Provider:
            def assess(self, name, version):
                fixture = fixtures[name]
                if version != fixture.record['version']:
                    raise EvidenceError('Unexpected fixture version')
                return {**fixture.assess(name, version), 'filename': name + '.tgz'}

            def download(self, record, destination):
                fixtures[record['name']].download(record, destination)

        self.provider = Provider()
        (self.repo / 'dist').mkdir()
        resources = {'input-' + str(i): {'path': name, 'kind': 'file', 'description': name}
                     for i, name in enumerate(files)}
        resources['source'] = {'path': 'packages/math/index.cjs', 'kind': 'file', 'description': 'local source'}
        resources['dist'] = {'path': 'dist', 'kind': 'tree', 'description': 'output'}
        inv = {'root': str(self.repo), 'resources': resources}
        local = [key for key, item in resources.items() if item['path'].startswith('packages/math/')]
        snap = scan(inv, local)
        names = ['npm:ptw-base', 'npm:ptw-peer']
        grants = [{'resource': key, 'actions': ['read', 'write', 'create', 'delete'] if key == 'dist' else ['read']}
                  for key in resources]
        escalation = {'warn_at': 1, 'stop_at': 3}
        commands = [
            {'id': 'use', 'resources': list(resources), 'timeout_seconds': 30,
             'argv': ['/usr/bin/node', '-e', 'const fs=require("fs");'
                'if(require("ptw-peer")!==8||require("ptw-math")!==14)throw Error("wrong graph");'
                'fs.writeFileSync("dist/result.txt","PROTECTED_PNPM_OK");']},
            {'id': 'narrow', 'resources': ['dist'], 'timeout_seconds': 30,
             'argv': ['/usr/bin/node', '-e', 'const fs=require("fs");'
                'if(require("ptw-peer")!==8)throw Error("registry graph");'
                'for(const p of ["/node-packages/packages/math/package.json",'
                '"/node-packages/node_modules/ptw-math/package.json",'
                '"/node-packages/packages/math/index.cjs",'
                '...Object.values(JSON.parse(fs.readFileSync("/node-packages/.ptw-pnpm-sources.json")))'
                '.flat().flatMap(p=>["/node-packages/"+p+"/package.json","/node-packages/"+p+"/index.cjs"])]){'
                'let read=false;try{fs.readFileSync(p);read=true}catch{}'
                'if(read)throw Error("excluded source readable");}'
                'let loaded=false;try{require("ptw-math");loaded=true}catch{}'
                'if(loaded)throw Error("excluded source imported");'
                'fs.writeFileSync("dist/narrow.txt","SOURCE_DENIED_REGISTRY_OK");']},
            {'id': 'partial', 'resources': ['source', 'dist'], 'timeout_seconds': 30,
             'argv': ['/usr/bin/node', '-e', 'require("fs").writeFileSync("dist/leak.txt",require("ptw-math"))']},
        ]
        descriptor = {'root': '', 'inputs': {n: hashlib.sha256(t.encode()).hexdigest() for n, t in files.items()},
            'lock_sha256': digest(self.specs),
            'artifacts': [{k: f.record[k] for k in ('name', 'version', 'url', 'integrity')} for f in fixtures.values()],
            'sources': [{'path': 'packages/math', 'resources': local,
                'snapshot_sha256': digest({p: [stamp(e), e.get('mode')] for p, e in snap.items()})}]}
        policy = {'version': 4, 'project': {'id': 'pnpm-fixture', 'description': 'Protected pnpm fixture',
            'grants': grants, 'commands': commands, 'escalation': escalation,
            'packages': {**RULES, 'allowed_names': names}, 'npm_dependencies': descriptor},
            'tasks': [{'id': 'work', 'description': 'approved work', 'grants': grants,
                'commands': [c['id'] for c in commands], 'packages': names, 'escalation': escalation},
                {'id': 'narrow', 'description': 'no local source authority',
                 'grants': [copy.deepcopy(g) for g in grants if g['resource'] not in local],
                 'commands': ['narrow'], 'packages': names, 'escalation': escalation}]}
        if approve_build:
            policy['project']['packages']['build_packages'] = ['npm:ptw-peer']
        self.store = Store(self.root / 'controller')
        bundle = approve(policy, inv, digest(compile_policy(policy, inv)), 'synthetic fixture operator')
        self.store.activate(bundle)
        self.actor = self.store.register('pnpm-fixture', 'work')
        self.narrow = self.store.register('pnpm-fixture', 'narrow')

        def stop():
            self.store.stop('pnpm-fixture')
            Supervisor(self.store).reconcile()
        self.addCleanup(stop)
        return files

    def controller_install(self, actor=None, event='install'):
        from ptw.packages import PackageControl
        return PackageControl(self.store, provider=self.provider).install(
            (actor or self.actor)['token'], event, self.specs, ecosystem='npm')

    def command(self, name, identity, actor=None):
        from ptw.workspace import Workspace, request
        return Workspace(self.store).request((actor or self.actor)['token'], 'command-' + name,
            request('run', name, content=json.dumps({'package_sets': [identity]})))

    def test_controller_protected_install_import_and_narrow_cached_source_denial(self):
        original = self.controller()
        installed = self.controller_install()
        self.assertTrue(installed['allowed'], installed)
        identity = installed['package_set']
        result = self.command('use', identity)
        self.assertTrue(result['allowed'], result)
        self.assertEqual(result['exit_code'], 0, result)
        self.assertEqual((self.repo / 'dist/result.txt').read_text(), 'PROTECTED_PNPM_OK')
        result = self.command('narrow', identity, self.narrow)
        self.assertTrue(result['allowed'], result)
        self.assertEqual(result['exit_code'], 0, result)
        self.assertEqual((self.repo / 'dist/narrow.txt').read_text(), 'SOURCE_DENIED_REGISTRY_OK')
        denied = self.controller_install(self.narrow, 'narrow-install')
        self.assertFalse(denied['allowed'], denied)
        denied = self.command('partial', identity)
        self.assertFalse(denied['allowed'], denied)
        self.assertFalse((self.repo / 'dist/leak.txt').exists())
        self.assertEqual(self.store.status('pnpm-fixture')['violations'], 2)
        self.assertEqual(read_inputs(self.repo)[0], original)
        self.assertFalse((self.store.directory / 'package-sets' / identity / 'packages/math/index.cjs').exists())
        self.assertFalse((self.repo / 'root-build').exists())

    def test_native_authenticated_registry_build_and_credential_confinement(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        from urllib.parse import unquote
        import threading
        from ptw.registry import RoutedNpmEvidence
        from ptw.pnpm_resolution import resolve_pnpm
        credential = self.root / 'synthetic-credential.json'
        token = 'Bearer SYNTHETIC_PNPM_FIXTURE_TOKEN'
        save(credential, {'authorization': token})
        peer = NpmFixture('ptw-peer', fields={'peerDependencies': {'ptw-base': '^1.0.0'},
            'scripts': {'postinstall': 'node build.cjs'}}, files={
            'package/index.js': b'module.exports = require("ptw-base") + require("./built.json");',
            'package/build.cjs': ('const fs=require("fs");'
                'if(Object.values(process.env).some(v=>v.includes("SYNTHETIC_PNPM")))throw Error("environment leak");'
                'let leaked=false;try{fs.readFileSync(' + json.dumps(str(credential)) + ');leaked=true}catch{}'
                'if(leaked)throw Error("credential file leak");fs.writeFileSync("built.json","1");').encode()})
        lock = self.repo / 'pnpm-lock.yaml'
        lock.write_text(lock.read_text().replace(self.peer.record['integrity'], peer.record['integrity']))
        self.peer = peer
        fixture = PnpmRegistryFixture([self.base, self.peer])
        seen = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, raw):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                valid = self.headers.get('Authorization') == token
                seen.append((self.path, valid))
                if not valid:
                    self.send_error(401)
                    return
                name = unquote(self.path[1:])
                if name.endswith('.tgz'):
                    self.reply(fixture.fixtures[name[:-4], '1.0.0'].raw)
                else:
                    self.reply(json.dumps(fixture.packument(name)).encode())

            def do_POST(self):
                valid = self.headers.get('Authorization') == token
                seen.append((self.path, valid))
                if not valid:
                    self.send_error(401)
                    return
                query = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                self.reply(json.dumps({'origin': endpoint, 'name': query['package']['name'],
                    'version': query['version'], 'coverage': 'complete', 'vulns': []}).encode())

        server = HTTPServer(('127.0.0.1', 0), Handler)
        endpoint = 'http://127.0.0.1:' + str(server.server_port)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for f in (self.base, self.peer):
                url = endpoint + '/' + f.record['name'] + '.tgz'
                lock.write_text(lock.read_text().replace(f.record['url'], url))
                f.record['url'] = url
            config = {'version': 1, 'packages': {name: {'registry': endpoint, 'advisories': endpoint,
                'credential_ref': str(credential)} for name in ('ptw-base', 'ptw-peer')}}
            provider = RoutedNpmEvidence(config, fixture=True)
            original = self.controller(lifecycle=True, approve_build=True)
            self.provider = provider
            # Real authenticated metadata reaches the native resolver only via
            # the existing metadata view, without headers or credential files.
            resolved = resolve_pnpm(self.repo, self.root / 'private-resolution', RULES,
                                    provider=provider, update=True)
            self.assertEqual({r['url'] for r in resolved['artifacts']},
                             {f.record['url'] for f in (self.base, self.peer)})
            installed = self.controller_install()
            self.assertTrue(installed['allowed'], installed)
            target = self.store.directory / 'package-sets' / installed['package_set']
            self.assertEqual(load(target / 'node_modules/ptw-peer/built.json'), 1)
            result = self.command('use', installed['package_set'])
            self.assertTrue(result['allowed'], result)
            self.assertEqual(result['exit_code'], 0, result)
            self.assertEqual((self.repo / 'dist/result.txt').read_text(), 'PROTECTED_PNPM_OK')
            self.assertNotIn(token, json.dumps([resolved, installed, result]))
            for directory in (target, self.root / 'private-resolution'):
                for path in directory.rglob('*'):
                    if path.is_file():
                        self.assertNotIn(token.encode(), path.read_bytes())
            self.assertTrue(any(path.endswith('.tgz') for path, _ in seen))
            self.assertTrue(all(valid for _, valid in seen))
            # A fresh install with wrong broker credentials cannot publish a set.
            before = {p.name for p in (self.store.directory / 'package-sets').iterdir()}
            for route in provider.routes.values():
                route['authorization'] = 'Bearer INVALID_SYNTHETIC_TOKEN'
            denied = self.controller_install(event='wrong-credential')
            self.assertFalse(denied['allowed'], denied)
            self.assertEqual({p.name for p in (self.store.directory / 'package-sets').iterdir()}, before)
            self.assertEqual(self.store.status('pnpm-fixture')['violations'], 0)
            self.assertEqual(read_inputs(self.repo)[0], original)
            save(self.root / 'private-effects.json', {'build': True, 'import': True,
                'authenticated_requests': sum(valid for _, valid in seen),
                'unauthorized_requests': sum(not valid for _, valid in seen),
                'credential_absent_from_exports': True})
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_native_file_directory_import_and_all_cached_source_copies_are_confined(self):
        from ptw.pnpm_resolution import resolve_pnpm
        from ptw.packages import mounted_set
        provider = self.resolution_provider()
        manifest = load(self.repo / 'package.json')
        manifest['dependencies']['ptw-math'] = 'file:packages/math'
        (self.repo / 'package.json').write_text(json.dumps(manifest) + '\n')
        (self.repo / 'pnpm-workspace.yaml').write_text('packages: []\n')
        result = resolve_pnpm(self.repo, self.root / 'file-resolution', RULES,
                              provider=provider, update=True)
        self.assertEqual(result['files']['package.json'], (self.repo / 'package.json').read_text())
        (self.repo / 'pnpm-lock.yaml').write_text(result['files']['pnpm-lock.yaml'])
        original = self.controller()
        installed = self.controller_install()
        self.assertTrue(installed['allowed'], installed)
        identity = installed['package_set']
        with self.store.locked() as db:
            actor = self.store.session(db, self.actor['token'])
            mount = mounted_set(self.store, db, actor, identity)
        copies = load(mount / '.ptw-pnpm-sources.json')['packages/math']
        self.assertTrue(copies, 'native file: installation must create a virtual-store copy')
        for location in copies:
            self.assertTrue(location.startswith('node_modules/.pnpm/'), location)
            self.assertEqual(sorted(p.name for p in (mount / location).iterdir()), ['package.json'])
            self.assertEqual((mount / location / 'package.json').stat().st_nlink, 1)
            self.assertEqual((mount / location / 'package.json').read_text(),
                             original['packages/math/package.json'])
        self.assertEqual((mount / 'packages/math/package.json').stat().st_nlink, 1)
        permitted = self.command('use', identity)
        self.assertTrue(permitted['allowed'], permitted)
        self.assertEqual(permitted['exit_code'], 0, permitted)
        self.assertEqual((self.repo / 'dist/result.txt').read_text(), 'PROTECTED_PNPM_OK')
        narrow = self.command('narrow', identity, self.narrow)
        self.assertTrue(narrow['allowed'], narrow)
        self.assertEqual(narrow['exit_code'], 0, narrow)
        self.assertEqual((self.repo / 'dist/narrow.txt').read_text(), 'SOURCE_DENIED_REGISTRY_OK')
        denied = self.controller_install(self.narrow, 'file-narrow-install')
        self.assertFalse(denied['allowed'], denied)
        self.assertFalse(self.command('partial', identity)['allowed'])
        self.assertFalse((self.repo / 'dist/leak.txt').exists())
        self.assertEqual(read_inputs(self.repo)[0], original)
        self.assertEqual(self.store.status('pnpm-fixture')['violations'], 2)

    def test_controller_denies_lifecycle_and_stale_inputs_without_publication(self):
        self.controller(lifecycle=True)
        result = self.controller_install()
        self.assertFalse(result['allowed'], result)
        self.assertIn('explicit controller approval', result['reason'])
        self.assertFalse(result['violation_counted'])
        self.assertFalse(list(self.root.rglob('unapproved-build')))
        self.assertFalse((self.store.directory / 'package-sets').exists())
        with (self.repo / 'pnpm-lock.yaml').open('a') as stream:
            stream.write('\n')
        with self.assertRaisesRegex(Invalid, 'input changed'):
            self.controller_install(event='stale')
        self.assertEqual(self.store.status('pnpm-fixture')['violations'], 0)

    def test_controller_approved_build_preserves_peer_links_and_confines_effects(self):
        original = self.controller(approve_build=True, build_script='''
const fs = require('fs');
if (fs.existsSync('/resources') || fs.existsSync('/home/loon')) throw Error('host visible');
if (require('ptw-base') !== 7) throw Error('peer graph changed');
fs.writeFileSync('built.cjs', 'module.exports = 42;');
fs.writeFileSync('index.js', 'module.exports = require("ptw-base") + require("./built.cjs") - 41;');
''')
        installed = self.controller_install()
        self.assertTrue(installed['allowed'], installed)
        target = self.store.directory / 'package-sets' / installed['package_set']
        self.assertEqual((target / 'node_modules/ptw-peer/built.cjs').read_text(), 'module.exports = 42;')
        self.assertTrue((target / 'node_modules/ptw-peer').is_symlink())
        result = self.command('use', installed['package_set'])
        self.assertTrue(result['allowed'], result)
        self.assertEqual(result['exit_code'], 0, result)
        result = self.command('narrow', installed['package_set'], self.narrow)
        self.assertTrue(result['allowed'], result)
        self.assertEqual(result['exit_code'], 0, result)
        self.assertEqual(read_inputs(self.repo)[0], original)
        self.assertFalse((target / 'root-build').exists())
        self.assertFalse((self.repo / 'root-build').exists())
        self.assertFalse((self.repo / 'pnpmfile-ran').exists())

    def test_controller_failed_approved_build_has_no_publication(self):
        self.controller(approve_build=True, build_script="require('fs').writeFileSync('partial', 'ran'); process.exit(3)")
        result = self.controller_install()
        self.assertFalse(result['allowed'], result)
        self.assertIn('Confined build failed', result['reason'])
        self.assertFalse(result['violation_counted'])
        self.assertFalse((self.store.directory / 'package-sets').exists())
        self.assertFalse((self.repo / 'partial').exists())

    def test_controller_approved_build_cannot_export_escape(self):
        self.controller(approve_build=True, build_script="require('fs').symlinkSync('/etc/passwd', 'leak')")
        result = self.controller_install()
        self.assertFalse(result['allowed'], result)
        self.assertIn('link escapes', result['reason'])
        self.assertFalse((self.store.directory / 'package-sets').exists())

    def test_controller_approved_build_cannot_redefine_package_metadata(self):
        self.controller(approve_build=True, build_script='''
const fs=require('fs'); const m=JSON.parse(fs.readFileSync('package.json'));
m.scripts={}; fs.writeFileSync('package.json', JSON.stringify(m));
''')
        result = self.controller_install()
        self.assertFalse(result['allowed'], result)
        self.assertIn('changed installed package metadata', result['reason'])
        self.assertFalse((self.store.directory / 'package-sets').exists())

    def test_controller_approved_build_cannot_change_unapproved_dependency(self):
        self.controller(approve_build=True, build_script='''
const fs=require('fs'); fs.appendFileSync(require.resolve('ptw-base'), '\\n// changed by a different package');
''')
        result = self.controller_install()
        self.assertFalse(result['allowed'], result)
        self.assertIn('content differs from assessed archive', result['reason'])
        self.assertFalse(result['violation_counted'])
        self.assertFalse((self.store.directory / 'package-sets').exists())

    def reject_build_tree_change(self, script):
        original = self.controller(approve_build=True, build_script=script)
        result = self.controller_install()
        self.assertFalse(result['allowed'], result)
        self.assertIn('protected installation tree', result['reason'])
        self.assertFalse(result['violation_counted'])
        self.assertFalse((self.store.directory / 'package-sets').exists())
        self.assertEqual(read_inputs(self.repo)[0], original)
        self.assertFalse((self.repo / 'root-build').exists())

    def test_controller_approved_build_cannot_shadow_top_level_dependency(self):
        self.reject_build_tree_change('''
const fs = require('fs');
fs.writeFileSync('/target/node_modules/ptw-base.js', 'module.exports = 99;');
if (require(require.resolve('ptw-base', {paths: ['/target']})) !== 99) throw Error('shadow failed');
''')

    def test_controller_approved_build_cannot_add_unreviewed_package(self):
        self.reject_build_tree_change('''
const fs = require('fs');
fs.mkdirSync('/target/node_modules/unreviewed');
fs.writeFileSync('/target/node_modules/unreviewed/index.js', 'module.exports = 99;');
if (require('unreviewed') !== 99) throw Error('addition failed');
''')

    def test_controller_approved_build_cannot_add_executable_shim(self):
        self.reject_build_tree_change('''
const fs = require('fs');
fs.mkdirSync('/target/node_modules/.bin', {recursive: true});
fs.writeFileSync('/target/node_modules/.bin/unreviewed', '#!/bin/sh\\nexit 0\\n', {mode: 0o700});
require('child_process').execFileSync('/target/node_modules/.bin/unreviewed');
''')

    def test_controller_approved_build_cannot_shadow_nested_dependency(self):
        self.reject_build_tree_change('''
const fs = require('fs');
fs.mkdirSync('node_modules', {recursive: true});
fs.writeFileSync('node_modules/ptw-base.js', 'module.exports = 99;');
if (require('ptw-base') !== 99) throw Error('nested shadow failed');
''')

    def test_controller_approved_build_cannot_add_lookup_link(self):
        self.reject_build_tree_change('''
const fs = require('fs');
fs.symlinkSync('ptw-base', '/target/node_modules/alias');
if (require('alias') !== 7) throw Error('alias failed');
''')

    def test_combined_parent_delegate_violations_stop_build_but_not_unrelated_job(self):
        from ptw.supervisor import Supervisor
        from ptw.workspace import Workspace, request
        self.controller(approve_build=True, build_script='setTimeout(() => {}, 60000);')
        child = self.store.register('pnpm-fixture', 'narrow', parent_token=self.narrow['token'])
        unrelated = subprocess.Popen(['/usr/bin/sleep', '60'])
        def cleanup():
            unrelated.terminate()
            unrelated.wait(timeout=5)
        self.addCleanup(cleanup)
        supervisor = Supervisor(self.store)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.controller_install)
            deadline, units = time.monotonic() + 20, []
            while time.monotonic() < deadline:
                with self.store.locked() as db:
                    units = [r[0] for r in db.execute('SELECT unit FROM workloads')]
                if units:
                    break
                if future.done():
                    self.fail('Build returned before supervision: ' + str(future.result()))
                time.sleep(.05)
            self.assertTrue(units, 'build never registered')
            first = self.controller_install(self.narrow, 'narrow-misuse')
            self.assertFalse(first['allowed'], first)
            self.assertEqual(first['level'], 'warn')
            second = Workspace(self.store).request(child['token'], 'child-misuse', request('read', 'source'))
            self.assertFalse(second['allowed'], second)
            third = self.controller_install(child, 'child-install-misuse')
            self.assertFalse(third['allowed'], third)
            self.assertEqual(third['level'], 'stop')
            supervisor.reconcile()
            result = future.result(timeout=20)
        self.assertFalse(result['allowed'], result)
        self.assertTrue(all(supervisor.state(unit)['confirmed_stopped'] for unit in units))
        self.assertEqual(self.store.status('pnpm-fixture')['violations'], 3)
        self.assertFalse((self.store.directory / 'package-sets').exists())
        later = self.controller_install(event='after-stop')
        self.assertFalse(later['allowed'], later)
        self.assertEqual(later['level'], 'stop')
        self.assertIsNone(unrelated.poll(), 'unrelated job was stopped')


if __name__ == '__main__':
    unittest.main()
