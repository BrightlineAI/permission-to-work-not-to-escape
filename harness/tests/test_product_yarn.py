"""Yarn milestone fixtures; native effects are manager-only, never mocked passes."""
import hashlib
import concurrent.futures
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import time
from unittest.mock import patch

from ptw import yarn_tool
from ptw.yarn import YarnEvidence, YarnPlan, build_order, read_inputs
from ptw.package_evidence import EvidenceError
from ptw.policy import Invalid, load, save
from ptw.supervisor import runtime_namespace
from test_ecosystems import NpmFixture, tar_bytes
from test_packages import CRITICAL
from test_product_pnpm import PnpmRegistryFixture
from ptw.setup_templates import RULES


def lock_text(fixture, spec='^1.0.0'):
    record = fixture.record
    result = ('# yarn lockfile v1\n\n' + json.dumps(record['name'] + '@' + spec) + ':\n'
            '  version ' + json.dumps(record['version']) + '\n'
            '  resolved ' + json.dumps(record['url'] + '#' + hashlib.sha1(fixture.raw).hexdigest()) + '\n'
            '  integrity ' + record['integrity'] + '\n')
    for field in ('dependencies', 'optionalDependencies'):
        if fixture.manifest.get(field):
            result += '  ' + field + ':\n' + ''.join('    ' + json.dumps(name) + ' ' + json.dumps(value) + '\n'
                for name, value in fixture.manifest[field].items())
    return result


class YarnRegistryFixture(PnpmRegistryFixture):
    def assess(self, name, version):
        return {**super().assess(name, version),
                'filename': hashlib.sha256((name + '@' + version).encode()).hexdigest() + '.tgz'}

    def packument(self, name):
        result = super().packument(name)
        for version, record in result['versions'].items():
            record['dist']['shasum'] = hashlib.sha1(self.fixtures[name, version].raw).hexdigest()
        return result


class YarnToolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ptw-yarn-unit-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def provision(self, *, expected=None):
        raw = tar_bytes({'package/package.json': json.dumps(
            {'name': 'yarn', 'version': yarn_tool.VERSION}).encode(),
            'package/bin/yarn.js': b'// non-executable unit fixture\n',
            'package/lib/cli.js': b'// non-executable unit fixture\n'})
        metadata = {'name': 'yarn', 'version': yarn_tool.VERSION, 'dist': {
            'tarball': yarn_tool.URL, 'integrity': expected or yarn_tool.integrity(raw)}}
        parser = tar_bytes({'package/package.json': json.dumps({'name': '@yarnpkg/lockfile',
                            'version': yarn_tool.PARSER_VERSION}).encode(),
                            'package/index.js': b'// non-executable unit fixture\n'})
        parser_metadata = {'name': '@yarnpkg/lockfile', 'version': yarn_tool.PARSER_VERSION,
                           'dist': {'tarball': yarn_tool.PARSER_URL, 'integrity': yarn_tool.integrity(parser)}}
        with patch.object(yarn_tool.NpmEvidence, 'fetch', side_effect=[json.dumps(metadata).encode(), raw,
                          json.dumps(parser_metadata).encode(), parser]):
            return yarn_tool.provision(self.root / 'tool')

    def stage(self):
        stage = self.root / 'stage'
        stage.mkdir()
        save(stage / 'package.json', {'private': True, 'dependencies': {'demo': '^1.0.0'}})
        (stage / 'yarn.lock').write_text(lock_text(NpmFixture()))
        return stage

    def test_explicit_bootstrap_integrity_and_no_ambient_fallback(self):
        with patch.dict(os.environ, {'PTW_YARN_TOOL': ''}), self.assertRaisesRegex(Invalid, 'no ambient fallback'):
            yarn_tool.verified()
        with self.assertRaisesRegex(Invalid, 'integrity mismatch'):
            self.provision(expected=yarn_tool.integrity(b'wrong archive'))
        self.assertEqual(load(self.root / 'tool/tool.json')['outcome'], 'failed')
        self.assertFalse((self.root / 'tool/payload').exists())

    def test_changed_payload_and_lock_invalidate_tool(self):
        tool = self.provision()
        yarn_tool.verified(tool)
        for path in (tool / 'payload/lib/cli.js', tool / 'tools.lock', tool / 'tool.tgz',
                     tool / 'parser.tgz', tool / 'payload/lock-parser/index.js'):
            original = path.read_bytes()
            path.write_bytes(original + b' ')
            with self.subTest(path=path.name), self.assertRaisesRegex(Invalid, 'tooling changed'):
                yarn_tool.verified(tool)
            path.write_bytes(original)
        (tool / 'payload/extra').symlink_to('/etc/passwd')
        with self.assertRaisesRegex(Invalid, 'link or special'):
            yarn_tool.verified(tool)

    def test_native_allowlist_configuration_and_environment(self):
        for args in (['install'], ['install', '--frozen-lockfile', '--ignore-scripts=false'],
                     ['run', 'build'], ['install', '--offline=false']):
            with self.subTest(args=args), patch.object(yarn_tool.subprocess, 'run') as native, \
                    self.assertRaisesRegex(Invalid, 'Only frozen'):
                yarn_tool.run(args, cwd=self.root)
            native.assert_not_called()
        tool, stage = self.provision(), self.stage()
        with patch('ptw.supervisor.runtime_namespace', return_value=['namespace']), \
                patch.dict(os.environ, {'NODE_OPTIONS': '--require=untrusted', 'YARN_IGNORE_SCRIPTS': '0'}), \
                patch.object(yarn_tool.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')) as native:
            yarn_tool.run(['install', '--frozen-lockfile'], cwd=stage, directory=tool)
        argv = native.call_args.args[0]
        for option in ('--offline', '--ignore-scripts', '--no-default-rc', '--non-interactive', '--disable-pnp'):
            self.assertIn(option, argv)
        self.assertNotIn('NODE_OPTIONS', argv)
        self.assertNotIn('YARN_IGNORE_SCRIPTS', argv)
        self.assertEqual(native.call_args.kwargs['env'], {'PATH': '/usr/bin:/bin'})
        self.assertEqual(len(list(stage.glob('native-*.json'))), 1)

    def test_resolution_boundary_and_metadata_do_not_supply_execution_authority(self):
        from ptw.yarn_resolution import YarnMetadataView
        tool, stage = self.provision(), self.stage()
        endpoint = 'http://127.0.0.1:12345/' + 'a' * 48 + '/'
        with patch.dict(os.environ, {'PTW_YARN_TOOL': str(tool), 'NODE_OPTIONS': '--require=untrusted'}), \
                patch('ptw.supervisor.runtime_namespace', return_value=['namespace', '--unshare-all']), \
                patch.object(yarn_tool.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')) as native:
            yarn_tool.resolve_lock(stage, endpoint, timeout=30)
        argv = native.call_args.args[0]
        for option in ('--ignore-scripts', '--no-default-rc', '--non-interactive', '--disable-pnp'):
            self.assertIn(option, argv)
        self.assertIn('/resolution-hook.cjs', argv)
        self.assertIn(endpoint, argv)
        self.assertNotIn('NODE_OPTIONS', argv)
        self.assertNotIn('--unshare-all', argv)
        self.assertEqual(native.call_args.kwargs['env'], {'PATH': '/usr/bin:/bin'})
        fixture = NpmFixture('ptw-value')
        provider = YarnRegistryFixture([fixture])
        from types import SimpleNamespace
        origins = YarnEvidence(provider, SimpleNamespace(registry={}))
        view = YarnMetadataView(provider, set(), time.monotonic() + 30, origins)
        dist = view.document('ptw-value')['versions']['1.0.0']['dist']
        self.assertEqual(dist, {'tarball': fixture.record['url'], 'integrity': fixture.record['integrity'],
                               'shasum': hashlib.sha1(fixture.raw).hexdigest()})
        view = YarnMetadataView(PnpmRegistryFixture([fixture]), set(), time.monotonic() + 30, origins)
        with self.assertRaisesRegex(EvidenceError, 'SHA1'):
            view.document('ptw-value')
        for endpoint in ('https://example.test/', 'http://127.0.0.1:12/no-secret', None):
            with self.subTest(endpoint=endpoint), self.assertRaises(Invalid):
                yarn_tool.resolve_lock(stage, endpoint, timeout=30)

    def test_native_failure_timeout_and_mutated_inputs_have_receipts(self):
        tool = self.provision()
        for mode in ('native_failure', 'timeout', 'mutated'):
            stage = self.root / mode
            stage.mkdir()
            save(stage / 'package.json', {'private': True})
            (stage / 'yarn.lock').write_text('# yarn lockfile v1\n')
            def native(*args, **kwargs):
                if mode == 'timeout':
                    raise subprocess.TimeoutExpired('yarn', 1)
                if mode == 'mutated':
                    (stage / 'package.json').write_text('{}')
                return subprocess.CompletedProcess([], 1 if mode == 'native_failure' else 0, '', 'synthetic secret')
            with patch('ptw.supervisor.runtime_namespace', return_value=['namespace']), \
                    patch.object(yarn_tool.subprocess, 'run', side_effect=native):
                if mode == 'native_failure':
                    self.assertEqual(yarn_tool.run(['install', '--frozen-lockfile'], cwd=stage, directory=tool).returncode, 1)
                else:
                    with self.assertRaises(Invalid):
                        yarn_tool.run(['install', '--frozen-lockfile'], cwd=stage, directory=tool)
            receipt = next(stage.glob('native-*.json'))
            self.assertNotIn('synthetic secret', receipt.read_text())
            self.assertEqual(load(receipt)['outcome'], {'mutated': 'failed'}.get(mode, mode))

    def test_original_metadata_and_sources_reject_escapes_and_competing_authorities(self):
        stage = self.stage()
        original = {p.name: p.read_text() for p in stage.iterdir()}
        self.assertEqual(read_inputs(stage)[0], original)
        for filename in ('package-lock.json', 'pnpm-lock.yaml', '.yarnrc', '.npmrc'):
            path = stage / filename
            path.write_text('{}')
            with self.subTest(filename=filename), self.assertRaises(Invalid):
                read_inputs(stage)
            path.unlink()
        outside = self.root / 'outside'
        outside.mkdir()
        save(outside / 'package.json', {'name': 'outside', 'version': '1.0.0'})
        (stage / 'linked').symlink_to(outside, target_is_directory=True)
        for spec in ('file:../outside', 'file:/outside', 'file:linked'):
            (stage / 'package.json').write_text(json.dumps({'dependencies': {'outside': spec}}))
            with self.subTest(spec=spec), self.assertRaises(Invalid):
                read_inputs(stage)
        self.assertEqual(load(outside / 'package.json')['name'], 'outside')

    def test_controller_request_requires_exact_reviewed_authority(self):
        from ptw.dependency_binding import verify_npm
        from ptw.npm import installation_plan
        from ptw.policy import digest
        stage = self.stage()
        request = {'manager': 'yarn', 'files': read_inputs(stage)[0]}
        fixture = NpmFixture()
        entry = {k: fixture.record[k] for k in ('version', 'integrity')}
        entry['resolved'] = fixture.record['url']
        descriptor = {'lock_sha256': digest(request), 'inputs': {
            n: hashlib.sha256(t.encode()).hexdigest() for n, t in request['files'].items()},
            'artifacts': [{k: fixture.record[k] for k in ('name', 'version', 'url', 'integrity')}]}
        bundle = {'policy': {'project': {'npm_dependencies': descriptor}}}
        with patch.object(yarn_tool, 'parse_lock', return_value={'demo@^1.0.0': entry}):
            self.assertIsInstance(installation_plan(request), YarnPlan)
            with self.assertRaisesRegex(Invalid, 'reviewed authoritative'):
                verify_npm({'policy': {'project': {}}}, request)
            verify_npm(bundle, request, [fixture.record])
            with self.assertRaisesRegex(Invalid, 'origin or integrity'):
                verify_npm(bundle, request, [{**fixture.record, 'url': 'https://outside.invalid/a.tgz'}])
            descriptor['inputs']['package.json'] = '0' * 64
            with self.assertRaisesRegex(Invalid, 'input bindings'):
                verify_npm(bundle, request)
            with self.assertRaisesRegex(Invalid, 'Malformed Yarn'):
                installation_plan({**request, 'unreviewed': True})

    def test_npm_resolution_cannot_convert_yarn_authority(self):
        from ptw.npm_resolution import resolve_npm
        stage = self.stage()
        original = read_inputs(stage)[0]
        with self.assertRaisesRegex(Invalid, 'native Yarn adapter'):
            resolve_npm(stage, self.root / 'resolution', RULES, provider=NpmFixture())
        self.assertEqual(read_inputs(stage)[0], original)
        self.assertFalse((stage / 'package-lock.json').exists())

    def test_public_origin_binding_preserves_urls_and_authenticated_routes_stay_exact(self):
        from types import SimpleNamespace
        from ptw.yarn_resolution import YarnMetadataView
        from ptw.npm import NpmEvidence
        for name in ('ptw-value', '@ptw/value'):
            fixture = NpmFixture(name)
            canonical = fixture.record['url']
            alias = canonical.replace(YarnEvidence.NPM, YarnEvidence.YARN)
            plan = SimpleNamespace(registry={name + '@1.0.0': {'resolved': alias}})
            provider = YarnRegistryFixture([fixture])
            # Use the production assessor with synthetic transport, not an
            # assessor that already returns the desired alias.
            public = NpmEvidence()
            with patch.object(public, 'packument', side_effect=provider.packument), \
                    patch.object(public, 'advisories', return_value=[]), \
                    patch.object(public, 'fetch', return_value=fixture.raw) as fetch:
                evidence = YarnEvidence(public, plan)
                record = evidence.assess(name, '1.0.0')
                self.assertEqual(record['url'], alias)
                destination = self.root / (hashlib.sha256(name.encode()).hexdigest() + '.tgz')
                evidence.download(record, destination)
                self.assertEqual(destination.read_bytes(), fixture.raw)
                self.assertEqual(fetch.call_args.args[0], canonical)
                view = YarnMetadataView(public, set(), time.monotonic() + 30, evidence)
                self.assertEqual(view.document(name)['versions']['1.0.0']['dist']['tarball'], alias)
                self.assertEqual(evidence.url(name, '1.1.0', canonical.replace('1.0.0', '1.1.0')),
                                 alias.replace('1.0.0', '1.1.0'))
                with patch.object(public, 'fetch', return_value=b'corrupt'), self.assertRaises(EvidenceError):
                    evidence.download(evidence.assess(name, '1.0.0'), self.root / 'corrupt.tgz')
                self.assertFalse((self.root / 'corrupt.tgz').exists())
                record = evidence.assess(name, '1.0.0')
                with self.assertRaises(EvidenceError):
                    evidence.download({**record, 'url': alias + '?substitute'}, self.root / 'changed.tgz')
            for bad in ('https://registry.yarnpkg.com.evil.invalid/x.tgz', alias + '?x',
                        alias.replace('/-/', '/wrong/'), alias.replace('https:', 'http:'),
                        alias.replace('registry.yarnpkg.com', 'registry.yarnpkg.com:444')):
                evidence = YarnEvidence(provider, SimpleNamespace(registry={name + '@1.0.0': {'resolved': bad}}))
                self.assertNotEqual(evidence.assess(name, '1.0.0')['url'], bad)
            provider.routes = {name: {'registry': YarnEvidence.NPM}}
            self.assertEqual(YarnEvidence(provider, plan).assess(name, '1.0.0')['url'], canonical)
            private = YarnEvidence(provider, SimpleNamespace(registry={name + '@1.0.0': {
                'resolved': 'https://private.invalid/package.tgz'}}))
            with self.assertRaisesRegex(EvidenceError, 'registry origin'):
                private.url(name, '1.1.0', canonical)

    def test_build_order_uses_dependency_locations_through_non_build_nodes(self):
        graph = {'node_modules/a-consumer': {'node_modules/m-middle'},
                 'node_modules/m-middle': {'node_modules/z-provider'},
                 'node_modules/z-provider': set(),
                 'node_modules/a-consumer/node_modules/z-provider': set()}
        order = build_order(graph)
        self.assertEqual(set(order), set(graph))
        self.assertLess(order.index('node_modules/z-provider'), order.index('node_modules/m-middle'))
        self.assertLess(order.index('node_modules/m-middle'), order.index('node_modules/a-consumer'))
        self.assertEqual(build_order({}), [])
        self.assertEqual(build_order({'a': {'b'}, 'b': {'a'}}), ['b', 'a'])


@unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'manager native Yarn checks required')
class YarnNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = Path(tempfile.mkdtemp(prefix='ptw-yarn-native-'))
        print('YARN_TOOL_EVIDENCE ' + str(cls.evidence), flush=True)
        source = Path(__file__).resolve().parents[1]
        save(cls.evidence / 'source.json', {n: hashlib.sha256((source / n).read_bytes()).hexdigest()
             for n in ('ptw/yarn_tool.py', 'ptw/yarn.py', 'ptw/yarn_resolution.py',
                       'ptw/npm.py', 'ptw/packages.py', 'ptw/dependency_binding.py', 'ptw/execution.py',
                       'ptw/workflow.py', 'ptw/onboarding.py', 'ptw/cli.py', 'ptw/supervisor.py',
                       'ptw/dependency_revision.py', 'ptw/registry.py', 'ptw/npm_resolution.py',
                       'requirements.lock', 'tests/test_product_yarn.py')})
        cls.tool = yarn_tool.provision(cls.evidence / 'tool')

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix=self._testMethodName + '-', dir=self.evidence))
        self.stage = self.root / 'stage'
        self.stage.mkdir()
        self.enterContext(patch.dict(os.environ, {'PTW_YARN_TOOL': str(self.tool)}))
        self.fixture = NpmFixture('ptw-value', fields={'scripts': {'postinstall':
            'node -e "require(\'fs\').writeFileSync(\'dependency-hook\',\'ran\')"'}},
            files={'package/index.js': b'module.exports = 7;\n'})
        save(self.stage / 'package.json', {'name': 'ptw-root', 'version': '1.0.0', 'private': True,
             'packageManager': 'yarn@' + yarn_tool.VERSION, 'dependencies': {'ptw-value': '^1.0.0'},
             'scripts': {'postinstall': 'node -e "require(\'fs\').writeFileSync(\'root-hook\',\'ran\')"'}})
        (self.stage / 'yarn.lock').write_text(lock_text(self.fixture))
        self.mirror = self.stage / '.ptw-yarn-mirror'
        self.mirror.mkdir()
        self.tarball = self.mirror / 'ptw-value-1.0.0.tgz'
        self.tarball.write_bytes(self.fixture.raw)

    def native(self):
        before, _ = read_inputs(self.stage)
        result = yarn_tool.run(['install', '--frozen-lockfile'], cwd=self.stage)
        self.assertEqual(read_inputs(self.stage)[0], before)
        self.assertFalse((self.stage / 'package-lock.json').exists())
        self.assertFalse((self.stage / 'root-hook').exists())
        self.assertFalse((self.stage / 'node_modules/ptw-value/dependency-hook').exists())
        return result

    def import_value(self, expression, expected):
        argv = runtime_namespace() + ['--ro-bind', str(self.stage), '/project', '--chdir', '/project',
                '--', '/usr/bin/node', '-e', 'console.log(' + expression + ')']
        result = subprocess.run(argv, env={'PATH': '/usr/bin:/bin'}, capture_output=True, text=True, timeout=30)
        save(self.root / 'import.json', {'returncode': result.returncode,
             'stdout_sha256': hashlib.sha256(result.stdout.encode()).hexdigest(),
             'stderr_sha256': hashlib.sha256(result.stderr.encode()).hexdigest()})
        self.assertEqual(result.returncode, 0, 'native Node import failed; see hashed receipt')
        self.assertEqual(result.stdout.strip(), expected)

    def test_frozen_offline_install_import_preserves_inputs_and_suppresses_scripts(self):
        result = self.native()
        self.assertEqual(result.returncode, 0, 'native Yarn failed; see hashed receipt')
        self.assertEqual((self.stage / 'node_modules/ptw-value/index.js').read_bytes(), b'module.exports = 7;\n')
        self.assertTrue(list((self.stage / '.ptw-yarn-cache').rglob('.yarn-metadata.json')))
        self.import_value('require("ptw-value")', '7')

    def test_missing_artifact_fails_without_network_or_install(self):
        self.tarball.unlink()
        self.assertNotEqual(self.native().returncode, 0)
        self.assertFalse((self.stage / 'node_modules/ptw-value/index.js').exists())

    def test_corrupted_artifact_fails_without_cache_repair(self):
        self.tarball.write_bytes(NpmFixture('ptw-value', files={'package/index.js': b'throw Error("substitution");'}).raw)
        self.assertNotEqual(self.native().returncode, 0)
        self.assertFalse((self.stage / 'node_modules/ptw-value/index.js').exists())

    def test_stale_lock_fails_without_rewriting_original_range(self):
        manifest = load(self.stage / 'package.json')
        manifest['dependencies']['ptw-value'] = '^2.0.0'
        (self.stage / 'package.json').write_text(json.dumps(manifest))
        self.assertNotEqual(self.native().returncode, 0)
        self.assertFalse((self.stage / 'node_modules/ptw-value/index.js').exists())

    def test_malformed_lock_is_rejected_without_install(self):
        (self.stage / 'yarn.lock').write_text('# yarn lockfile v1\n"ptw-value@^1.0.0":\n  version "unterminated\n')
        self.assertNotEqual(self.native().returncode, 0)
        self.assertFalse((self.stage / 'node_modules/ptw-value/index.js').exists())

    def test_native_workspace_links_keep_local_identity(self):
        manifest = load(self.stage / 'package.json')
        manifest['workspaces'] = ['packages/*']
        manifest['dependencies']['ptw-math'] = '^1.0.0'
        (self.stage / 'package.json').write_text(json.dumps(manifest))
        save(self.stage / 'packages/math/package.json', {'name': 'ptw-math', 'version': '1.0.0',
             'main': 'index.cjs', 'dependencies': {'ptw-value': '^1.0.0'}})
        # This primitive fixture supplies local bytes, not a controller source
        # overlay. Narrower-session source authority is a later integration gate.
        (self.stage / 'packages/math/index.cjs').write_text('module.exports = require("ptw-value") * 2;\n')
        self.assertEqual(self.native().returncode, 0, 'native Yarn workspace failed; see hashed receipt')
        link = self.stage / 'node_modules/ptw-math'
        self.assertTrue(link.is_symlink())
        self.assertEqual(link.resolve(), self.stage / 'packages/math')
        self.import_value('require("ptw-math")', '14')

    def assessed_install(self, *, approve=False, fixture=None):
        fixture = fixture or self.fixture
        plan = YarnPlan(read_inputs(self.stage)[0])
        artifacts = self.root / 'artifacts'
        artifacts.mkdir()
        record = fixture.assess(fixture.record['name'], fixture.record['version'])
        fixture.download(record, artifacts / record['filename'])
        target = self.root / 'installed'
        def build(command):
            proc = subprocess.run(command, env={'PATH': '/usr/bin:/bin'}, capture_output=True,
                                  text=True, timeout=30)
            save(self.root / ('build-' + str(len(list(self.root.glob('build-*.json')))) + '.json'),
                 {'returncode': proc.returncode, 'stdout_sha256': hashlib.sha256(proc.stdout.encode()).hexdigest(),
                  'stderr_sha256': hashlib.sha256(proc.stderr.encode()).hexdigest()})
            if proc.returncode:
                raise EvidenceError('Native supervised-boundary fixture build failed')
        plan.install(artifacts, target, [record], [fixture.record['name']] if approve else [], build)
        return plan, target, record

    def test_assessed_install_requires_explicit_build_authority(self):
        with self.assertRaisesRegex(EvidenceError, 'explicit controller approval'):
            self.assessed_install()
        self.assertFalse((self.root / 'installed/node_modules').exists())
        self.assertFalse(list(self.root.glob('build-*.json')))

    def test_assessed_native_install_and_exact_dependency_build(self):
        plan, target, record = self.assessed_install(approve=True)
        self.assertEqual((target / 'node_modules/ptw-value/dependency-hook').read_text(), 'ran')
        self.assertFalse((target / 'root-hook').exists())
        self.assertEqual((target / 'yarn.lock').read_bytes(), (self.stage / 'yarn.lock').read_bytes())
        self.assertFalse((target / 'package-lock.json').exists())
        self.stage = target
        self.import_value('require("ptw-value")', '7')

    def test_assessed_origin_and_stale_selector_fail_before_install(self):
        plan = YarnPlan(read_inputs(self.stage)[0])
        record = self.fixture.assess('ptw-value', '1.0.0')
        record['url'] = 'https://outside.example/ptw-value-1.0.0.tgz'
        with self.assertRaisesRegex(EvidenceError, 'origin or integrity'):
            plan.bind_evidence([record])
        files = read_inputs(self.stage)[0]
        manifest = json.loads(files['package.json'])
        manifest['dependencies']['ptw-value'] = '^2.0.0'
        files['package.json'] = json.dumps(manifest)
        with self.assertRaisesRegex(Invalid, 'stale'):
            YarnPlan(files)
        self.assertFalse((self.stage / 'node_modules').exists())

    def test_assessed_native_workspace_metadata_and_lookup(self):
        manifest = load(self.stage / 'package.json')
        manifest['workspaces'] = ['packages/*']
        manifest['dependencies']['ptw-math'] = '^1.0.0'
        (self.stage / 'package.json').write_text(json.dumps(manifest))
        save(self.stage / 'packages/math/package.json', {'name': 'ptw-math', 'version': '1.0.0',
             'dependencies': {'ptw-value': '^1.0.0'}})
        plan, target, record = self.assessed_install(approve=True)
        self.assertEqual((target / 'node_modules/ptw-math').resolve(), target / 'packages/math')
        self.assertEqual(plan.source_copies, {'packages/math': []})
        # A real source overlay is a controller gate. The cache has only metadata.
        self.assertEqual(sorted(p.name for p in (target / 'packages/math').iterdir()), ['package.json'])

    def test_assessed_installed_byte_substitution_and_shadowing_rejected(self):
        plan, target, record = self.assessed_install(approve=True)
        # Approved output is present, so capture the post-build tree explicitly.
        (target / 'node_modules/ptw-value/dependency-hook').unlink()
        baseline = plan.verify_installed(target, [record])
        original = (target / 'node_modules/ptw-value/index.js').read_bytes()
        (target / 'node_modules/ptw-value/index.js').write_text('module.exports = 99;')
        with self.assertRaisesRegex(EvidenceError, 'content differs'):
            plan.verify_installed(target, [record])
        (target / 'node_modules/ptw-value/index.js').write_bytes(original)
        (target / 'node_modules/ptw-value.js').write_text('module.exports = 99;')
        with self.assertRaisesRegex(EvidenceError, 'shadowing'):
            plan.verify_installed(target, [record], built=['ptw-value'], baseline=baseline)

    def test_assessed_failed_build_never_returns_installation(self):
        self.fixture = NpmFixture('ptw-value', fields={'scripts': {'postinstall': 'node -e "process.exit(23)"'}},
                                  files={'package/index.js': b'module.exports = 7;\n'})
        (self.stage / 'yarn.lock').write_text(lock_text(self.fixture))
        with self.assertRaisesRegex(EvidenceError, 'fixture build failed'):
            self.assessed_install(approve=True)
        self.assertFalse((self.root / 'installed/.ptw-yarn-sources.json').exists())

    def test_assessed_native_file_source_keeps_metadata_only_copy(self):
        manifest = load(self.stage / 'package.json')
        manifest['dependencies']['ptw-local'] = 'file:packages/local'
        (self.stage / 'package.json').write_text(json.dumps(manifest))
        save(self.stage / 'packages/local/package.json', {'name': 'ptw-local', 'version': '1.0.0'})
        with (self.stage / 'yarn.lock').open('a') as stream:
            stream.write('\n"ptw-local@file:packages/local":\n  version "1.0.0"\n')
        plan, target, record = self.assessed_install(approve=True)
        self.assertEqual(plan.source_copies, {'packages/local': ['node_modules/ptw-local']})
        self.assertFalse((target / 'node_modules/ptw-local').is_symlink())
        self.assertEqual((target / 'node_modules/ptw-local/package.json').read_bytes(),
                         (self.stage / 'packages/local/package.json').read_bytes())

    def controller(self, *, script=None, preinstall=None, approve_build=False, copied=False, fixture=None,
                   extra_fixtures=(), public_yarn=False):
        """Synthetic operator approval, real controller, installer and supervisor."""
        import copy
        from ptw.policy import approve, compile_policy, digest
        from ptw.store import Store
        from ptw.supervisor import Supervisor
        from ptw.workspace import scan, stamp
        hooks = {k: v for k, v in (('preinstall', preinstall), ('postinstall', script)) if v}
        self.fixture = fixture or NpmFixture('ptw-value', fields={'scripts': hooks} if hooks else {},
                                  files={'package/index.js': b'module.exports = 7;\n'})
        manifest = load(self.stage / 'package.json')
        manifest['dependencies']['ptw-local'] = 'file:packages/local' if copied else '^1.0.0'
        if not copied:
            manifest['workspaces'] = ['packages/*']
        (self.stage / 'package.json').write_text(json.dumps(manifest))
        save(self.stage / 'packages/local/package.json', {'name': 'ptw-local', 'version': '1.0.0',
             'main': 'index.cjs', 'dependencies': {'ptw-value': '^1.0.0'}})
        (self.stage / 'packages/local/index.cjs').write_text('module.exports = require("ptw-value") * 2;\n')
        fixtures = [self.fixture, *extra_fixtures]
        lock = ''.join(lock_text(f) for f in fixtures)
        if public_yarn:
            lock = lock.replace(YarnEvidence.NPM, YarnEvidence.YARN)
        (self.stage / 'yarn.lock').write_text(lock +
            ('\n"ptw-local@file:packages/local":\n  version "1.0.0"\n  dependencies:\n    ptw-value "^1.0.0"\n' if copied else ''))
        files, _ = read_inputs(self.stage)
        self.specs = {'manager': 'yarn', 'files': files}
        (self.stage / 'dist').mkdir()
        resources = {'input-' + str(i): {'path': n, 'kind': 'file', 'description': n} for i, n in enumerate(files)}
        resources['source'] = {'path': 'packages/local/index.cjs', 'kind': 'file', 'description': 'local source'}
        resources['dist'] = {'path': 'dist', 'kind': 'tree', 'description': 'output'}
        inv = {'root': str(self.stage), 'resources': resources}
        local = [k for k, v in resources.items() if v['path'].startswith('packages/local/')]
        snap = scan(inv, local)
        names = ['npm:' + f.record['name'] for f in fixtures]
        grants = [{'resource': k, 'actions': ['read', 'write', 'create', 'delete'] if k == 'dist' else ['read']}
                  for k in resources]
        escalation = {'warn_at': 1, 'stop_at': 3}
        commands = [
            {'id': 'use', 'resources': list(resources), 'timeout_seconds': 30,
             'argv': ['/usr/bin/node', '-e', 'const fs=require("fs");'
                'if(require("ptw-value")!==7||require("ptw-local")!==14)throw Error("wrong graph");'
                'fs.writeFileSync("dist/result.txt","PROTECTED_YARN_OK");']},
            {'id': 'narrow', 'resources': ['dist'], 'timeout_seconds': 30,
             'argv': ['/usr/bin/node', '-e', 'const fs=require("fs");'
                'if(require("ptw-value")!==7)throw Error("registry graph");'
                'const copies=Object.values(JSON.parse(fs.readFileSync("/node-packages/.ptw-yarn-sources.json"))).flat();'
                'for(const p of ["packages/local","node_modules/ptw-local",...copies]){'
                'for(const f of ["package.json","index.cjs"]){let read=false;'
                'try{fs.readFileSync("/node-packages/"+p+"/"+f);read=true}catch{}'
                'if(read)throw Error("source leak");}}'
                'let loaded=false;try{require("ptw-local");loaded=true}catch{}'
                'if(loaded)throw Error("source import");'
                'fs.writeFileSync("dist/narrow.txt","SOURCE_DENIED_REGISTRY_OK");']},
            {'id': 'partial', 'resources': ['source', 'dist'], 'timeout_seconds': 30,
             'argv': ['/usr/bin/node', '-e', 'require("fs").writeFileSync("dist/leak.txt",require("ptw-local"))']},
        ]
        descriptor = {'root': '', 'inputs': {n: hashlib.sha256(t.encode()).hexdigest() for n, t in files.items()},
            'lock_sha256': digest(self.specs),
            'artifacts': [{k: (f.record[k].replace(YarnEvidence.NPM, YarnEvidence.YARN)
                              if public_yarn and k == 'url' else f.record[k])
                           for k in ('name', 'version', 'url', 'integrity')} for f in fixtures],
            'sources': [{'path': 'packages/local', 'resources': local,
                'snapshot_sha256': digest({p: [stamp(e), e.get('mode')] for p, e in snap.items()})}]}
        policy = {'version': 4, 'project': {'id': 'yarn-fixture', 'description': 'Protected Yarn fixture',
            'grants': grants, 'commands': commands, 'escalation': escalation,
            'packages': {**RULES, 'allowed_names': names}, 'npm_dependencies': descriptor},
            'tasks': [{'id': 'work', 'description': 'approved work', 'grants': grants,
                'commands': [c['id'] for c in commands], 'packages': names, 'escalation': escalation},
                {'id': 'narrow', 'description': 'no local source authority',
                 'grants': [copy.deepcopy(g) for g in grants if g['resource'] not in local],
                 'commands': ['narrow'], 'packages': names, 'escalation': escalation}]}
        if approve_build:
            policy['project']['packages']['build_packages'] = names
        self.install_provider = YarnRegistryFixture(fixtures) if extra_fixtures else self.fixture
        self.store = Store(self.root / 'controller')
        self.bundle = approve(policy, inv, digest(compile_policy(policy, inv)), 'synthetic fixture operator')
        self.store.activate(self.bundle)
        self.actor = self.store.register('yarn-fixture', 'work')
        self.narrow = self.store.register('yarn-fixture', 'narrow')

        def stop():
            self.store.stop('yarn-fixture')
            Supervisor(self.store).reconcile()
        self.addCleanup(stop)
        return files

    def controller_install(self, actor=None, event='install'):
        from ptw.packages import PackageControl
        return PackageControl(self.store, provider=self.install_provider).install(
            (actor or self.actor)['token'], event, self.specs, ecosystem='npm')

    def command(self, name, identity, actor=None):
        from ptw.workspace import Workspace, request
        return Workspace(self.store).request((actor or self.actor)['token'], 'command-' + name,
            request('run', name, content=json.dumps({'package_sets': [identity]})))

    def protected_sources(self, *, copied=False):
        from ptw.workflow import dispatch
        from ptw.workspace import request
        original = self.controller(copied=copied)
        lock_id = next(r for r, v in self.bundle['inventory']['resources'].items() if v['path'] == 'yarn.lock')
        with patch('ptw.registry.provider_for', return_value=self.fixture):
            installed = dispatch(self.store, self.actor, 'install', request('install', lock_id, content='yarn'))
        self.assertTrue(installed['allowed'], installed)
        identity = installed['package_set']
        result = self.command('use', identity)
        self.assertTrue(result['allowed'], result)
        self.assertEqual(result['exit_code'], 0, result)
        self.assertEqual((self.stage / 'dist/result.txt').read_text(), 'PROTECTED_YARN_OK')
        result = self.command('narrow', identity, self.narrow)
        self.assertTrue(result['allowed'], result)
        self.assertEqual(result['exit_code'], 0, result)
        self.assertEqual((self.stage / 'dist/narrow.txt').read_text(), 'SOURCE_DENIED_REGISTRY_OK')
        self.assertFalse(self.controller_install(self.narrow, 'narrow-install')['allowed'])
        self.assertFalse(self.command('partial', identity)['allowed'])
        self.assertFalse((self.stage / 'dist/leak.txt').exists())
        self.assertEqual(self.store.status('yarn-fixture')['violations'], 2)
        self.assertEqual(read_inputs(self.stage)[0], original)
        target = self.store.directory / 'package-sets' / identity
        self.assertFalse((target / 'packages/local/index.cjs').exists())
        self.assertFalse((self.stage / 'root-hook').exists())
        self.assertFalse((self.stage / 'package-lock.json').exists())

    def test_controller_protected_workspace_install_import_and_narrow_cached_denial(self):
        self.protected_sources()

    def test_controller_protected_directory_copy_and_narrow_cached_denial(self):
        self.protected_sources(copied=True)

    def test_default_public_origin_frozen_import_and_protected_install(self):
        from ptw.yarn_resolution import resolve_yarn
        original = self.controller(public_yarn=True)
        result = resolve_yarn(self.stage, self.root / 'public-frozen', RULES, provider=self.fixture)
        self.assertEqual(result['files'], original)
        self.assertEqual(result['artifacts'], self.bundle['policy']['project']['npm_dependencies']['artifacts'])
        self.assertTrue(all(r['url'].startswith(YarnEvidence.YARN + '/') for r in result['artifacts']))
        installed = self.controller_install()
        self.assertTrue(installed['allowed'], installed)
        used = self.command('use', installed['package_set'])
        self.assertTrue(used['allowed'], used)
        self.assertEqual(used['exit_code'], 0, used)
        self.assertEqual((self.stage / 'dist/result.txt').read_text(), 'PROTECTED_YARN_OK')
        self.assertEqual(read_inputs(self.stage)[0], original)
        self.assertFalse((self.stage / 'root-hook').exists())
        # Alias recognition must not relax the independent archive digest check.
        published = set((self.store.directory / 'package-sets').iterdir())
        with patch.object(self.fixture, 'download', side_effect=lambda record, path: path.write_bytes(b'corrupt')):
            denied = self.controller_install(event='corrupt-public-artifact')
        self.assertFalse(denied['allowed'], denied)
        self.assertIn('integrity mismatch', denied['reason'])
        self.assertFalse(denied['violation_counted'])
        self.assertEqual(set((self.store.directory / 'package-sets').iterdir()), published)

    def test_controller_approved_builds_follow_dependency_order(self):
        provider = NpmFixture('z-provider', fields={'scripts': {'postinstall':
            'node -e "require(\'fs\').writeFileSync(\'built.json\',\'7\')"'}},
            files={'package/index.js': b'module.exports=require("./built.json");'})
        consumer = NpmFixture('ptw-value', fields={'dependencies': {'z-provider': '^1.0.0'},
            'scripts': {'postinstall': 'node -e "require(\'fs\').writeFileSync(\'built.json\','
                       'JSON.stringify(require(\'z-provider\')))"'}},
            files={'package/index.js': b'module.exports=require("./built.json");'})
        original = self.controller(fixture=consumer, extra_fixtures=[provider], approve_build=True)
        installed = self.controller_install()
        self.assertTrue(installed['allowed'], installed)
        target = self.store.directory / 'package-sets' / installed['package_set']
        for name in ('ptw-value', 'z-provider'):
            self.assertEqual((target / 'node_modules' / name / 'built.json').read_text(), '7')
        used = self.command('use', installed['package_set'])
        self.assertTrue(used['allowed'], used)
        self.assertEqual(used['exit_code'], 0, used)
        self.assertEqual((self.stage / 'dist/result.txt').read_text(), 'PROTECTED_YARN_OK')
        self.assertEqual(read_inputs(self.stage)[0], original)
        self.assertFalse((self.stage / 'root-hook').exists())

    def test_controller_policy_rejects_critical_young_and_missing_evidence(self):
        self.controller()
        for index, (changes, counted) in enumerate((
                ({'vulnerabilities': [CRITICAL]}, True),
                ({'published_at': datetime.now(timezone.utc).isoformat()}, True),
                ({'vulnerabilities': None}, False))):
            with self.subTest(changes=changes), patch.dict(self.fixture.record, changes):
                result = self.controller_install(event='policy-' + str(index))
            self.assertFalse(result['allowed'], result)
            self.assertEqual(result.get('violation_counted', True), counted, result)
            self.assertFalse((self.store.directory / 'package-sets').exists())
        self.assertEqual(self.store.status('yarn-fixture')['violations'], 2)

    def test_controller_unapproved_build_and_changed_inputs_do_not_publish(self):
        self.controller(script='node -e "require(\'fs\').writeFileSync(\'unapproved\',\'ran\')"')
        result = self.controller_install()
        self.assertFalse(result['allowed'], result)
        self.assertIn('explicit controller approval', result['reason'])
        self.assertFalse(result['violation_counted'])
        self.assertFalse((self.store.directory / 'package-sets').exists())
        self.assertFalse(list(self.root.rglob('unapproved')))
        with (self.stage / 'yarn.lock').open('a') as stream:
            stream.write('\n')
        with self.assertRaisesRegex(Invalid, 'input changed'):
            self.controller_install(event='changed')
        self.assertEqual(self.store.status('yarn-fixture')['violations'], 0)

    def test_controller_approved_multiple_hooks_and_protected_build(self):
        self.controller(script='node -e "require(\'fs\').writeFileSync(\'built\',require(\'fs\').readFileSync(\'before\'))"',
                        preinstall='node -e "require(\'fs\').writeFileSync(\'before\',\'ran\')"', approve_build=True)
        result = self.controller_install()
        self.assertTrue(result['allowed'], result)
        target = self.store.directory / 'package-sets' / result['package_set']
        self.assertEqual((target / 'node_modules/ptw-value/built').read_text(), 'ran')
        result = self.command('use', result['package_set'])
        self.assertTrue(result['allowed'], result)
        self.assertEqual(result['exit_code'], 0, result)
        self.assertFalse((target / 'root-hook').exists())
        self.assertFalse((self.stage / 'root-hook').exists())

    def test_assessed_multiple_lifecycle_hooks_complete(self):
        self.fixture = NpmFixture('ptw-value', fields={'scripts': {
            'preinstall': 'node -e "require(\'fs\').writeFileSync(\'before\',\'ran\')"',
            'postinstall': 'node -e "require(\'fs\').writeFileSync(\'after\',require(\'fs\').readFileSync(\'before\'))"'}},
            files={'package/index.js': b'module.exports = 7;\n'})
        (self.stage / 'yarn.lock').write_text(lock_text(self.fixture))
        _, target, _ = self.assessed_install(approve=True)
        self.assertEqual((target / 'node_modules/ptw-value/after').read_text(), 'ran')

    def test_controller_failed_approved_build_has_no_publication(self):
        self.controller(script='node -e "process.exit(23)"', approve_build=True)
        result = self.controller_install()
        self.assertFalse(result['allowed'], result)
        self.assertIn('Confined build failed', result['reason'])
        self.assertFalse(result['violation_counted'])
        self.assertFalse((self.store.directory / 'package-sets').exists())

    def test_controller_concurrent_input_change_blocks_publication(self):
        self.controller()
        download = self.fixture.download
        def changed(record, destination):
            download(record, destination)
            with (self.stage / 'yarn.lock').open('a') as stream:
                stream.write('\n')
        with patch.object(self.fixture, 'download', side_effect=changed):
            result = self.controller_install()
        self.assertFalse(result['allowed'], result)
        self.assertIn('input changed', result['reason'])
        self.assertFalse(result['violation_counted'])
        self.assertFalse((self.store.directory / 'package-sets').exists())

    def test_controller_build_shadowing_rejected(self):
        self.controller(script='node -e "require(\'fs\').writeFileSync(\'/target/node_modules/ptw-value.js\',\'module.exports=99\')"', approve_build=True)
        result = self.controller_install()
        self.assertFalse(result['allowed'], result)
        self.assertIn('shadowing', result['reason'])
        self.assertFalse((self.store.directory / 'package-sets').exists())

    def test_controller_build_export_escape_rejected(self):
        self.controller(script='node -e "require(\'fs\').symlinkSync(\'/etc/passwd\',\'leak\')"', approve_build=True)
        result = self.controller_install()
        self.assertFalse(result['allowed'], result)
        self.assertIn('link escapes', result['reason'])
        self.assertFalse((self.store.directory / 'package-sets').exists())

    def test_controller_combined_violations_stop_build_preserve_unrelated_job(self):
        from ptw.supervisor import Supervisor
        from ptw.workspace import Workspace, request
        self.controller(script='node -e "setTimeout(() => {},60000)"', approve_build=True)
        child = self.store.register('yarn-fixture', 'narrow', parent_token=self.narrow['token'])
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
            first = self.controller_install(self.narrow, 'parent-misuse')
            self.assertFalse(first['allowed'], first)
            self.assertEqual(first['level'], 'warn')
            second = Workspace(self.store).request(child['token'], 'child-read', request('read', 'source'))
            self.assertFalse(second['allowed'], second)
            third = self.controller_install(child, 'child-install')
            self.assertFalse(third['allowed'], third)
            self.assertEqual(third['level'], 'stop')
            supervisor.reconcile()
            result = future.result(timeout=20)
        self.assertFalse(result['allowed'], result)
        self.assertTrue(all(supervisor.state(unit)['confirmed_stopped'] for unit in units))
        self.assertEqual(self.store.status('yarn-fixture')['violations'], 3)
        self.assertFalse((self.store.directory / 'package-sets').exists())
        self.assertEqual(self.controller_install(event='after-stop')['level'], 'stop')
        self.assertIsNone(unrelated.poll(), 'unrelated job was stopped')

    def test_frozen_resolution_preserves_authority_and_rejects_policy_or_input_changes(self):
        from ptw.yarn_resolution import resolve_yarn
        from ptw.dependency_resolution import ResolutionError
        original = read_inputs(self.stage)[0]
        result = resolve_yarn(self.stage, self.root / 'resolution', RULES, provider=self.fixture)
        self.assertEqual(result['lock'], {'manager': 'yarn', 'files': original})
        self.assertEqual(read_inputs(self.stage)[0], original)
        self.assertFalse((self.stage / 'node_modules').exists())
        for mode, changes, error in (
                ('critical', {'vulnerabilities': [CRITICAL]}, ResolutionError),
                ('young', {'published_at': datetime.now(timezone.utc).isoformat()}, ResolutionError),
                ('missing', {'vulnerabilities': None}, EvidenceError),
                ('origin', {'url': 'https://outside.invalid/substitution.tgz'}, EvidenceError)):
            with self.subTest(mode=mode), patch.dict(self.fixture.record, changes), self.assertRaises(error):
                resolve_yarn(self.stage, self.root / mode, RULES, provider=self.fixture)
            self.assertNotEqual(load(self.root / mode / 'resolution.json')['outcome'], 'resolved')
        assess = self.fixture.assess
        def changed(name, version):
            with (self.stage / 'yarn.lock').open('a') as stream:
                stream.write('\n')
            return assess(name, version)
        with patch.object(self.fixture, 'assess', side_effect=changed), self.assertRaisesRegex(Invalid, 'changed during assessment'):
            resolve_yarn(self.stage, self.root / 'concurrent', RULES, provider=self.fixture)

    def resolution_provider(self):
        self.fixture = NpmFixture('ptw-value', files={'package/index.js': b'module.exports = 7;\n'})
        (self.stage / 'yarn.lock').write_text(lock_text(self.fixture))
        return YarnRegistryFixture([self.fixture])

    def test_native_reviewed_resolution_excludes_critical_young_and_preserves_ranges(self):
        from ptw.yarn_resolution import resolve_yarn
        provider = self.resolution_provider()
        for version in ('1.1.0', '1.2.0'):
            provider.fixtures['ptw-value', version] = NpmFixture('ptw-value', version)
        provider.overrides['ptw-value', '1.1.0'] = {'vulnerabilities': [CRITICAL]}
        provider.overrides['ptw-value', '1.2.0'] = {'published_at': datetime.now(timezone.utc).isoformat()}
        original = read_inputs(self.stage)[0]
        with patch.object(provider, 'download', side_effect=AssertionError('Resolution downloaded an artifact')):
            result = resolve_yarn(self.stage, self.root / 'compatible', RULES, provider=provider, update=True)
        self.assertEqual({r['name']: r['version'] for r in result['artifacts']}, {'ptw-value': '1.0.0'})
        self.assertEqual(set(provider.assessments), {('ptw-value', v) for v in ('1.0.0', '1.1.0', '1.2.0')})
        self.assertEqual(result['files']['package.json'], original['package.json'])
        self.assertEqual(read_inputs(self.stage)[0], original)
        self.assertEqual([a['outcome'] for a in result['attempts']],
                         ['policy_exclusion', 'policy_exclusion', 'resolved'])
        self.assertFalse(list((self.root / 'compatible').rglob('*.tgz')))
        self.assertFalse(list(self.root.rglob('root-hook')))
        self.assertFalse(list(self.root.rglob('dependency-hook')))
        YarnPlan(result['files']).bind_evidence([provider.assess('ptw-value', '1.0.0')])

    def test_native_reviewed_resolution_exact_pin_outage_and_budget_fail_closed(self):
        from ptw.yarn_resolution import resolve_yarn
        provider = self.resolution_provider()
        provider.fixtures['ptw-value', '1.1.0'] = NpmFixture('ptw-value', '1.1.0')
        manifest = load(self.stage / 'package.json')
        manifest['dependencies']['ptw-value'] = '1.1.0'
        (self.stage / 'package.json').write_text(json.dumps(manifest))
        original = read_inputs(self.stage)[0]
        for mode in ('exact', 'outage', 'budget'):
            provider.overrides['ptw-value', '1.1.0'] = {
                'vulnerabilities': None if mode == 'outage' else [CRITICAL]}
            with self.subTest(mode=mode), self.assertRaises(Invalid):
                resolve_yarn(self.stage, self.root / mode, RULES, provider=provider, update=True,
                             **({'max_rounds': 1} if mode == 'budget' else {}))
            self.assertEqual(read_inputs(self.stage)[0], original)
            self.assertEqual(load(self.root / mode / 'resolution.json')['outcome'],
                {'exact': 'unsatisfiable', 'outage': 'unavailable_evidence', 'budget': 'budget_exhausted'}[mode])

    def test_native_reviewed_resolution_transitive_optional_and_real_install(self):
        from ptw.yarn_resolution import resolve_yarn
        provider = self.resolution_provider()
        manifest = load(self.stage / 'package.json')
        manifest['dependencies']['ptw-parent'] = '^1.0.0'
        (self.stage / 'package.json').write_text(json.dumps(manifest))
        provider.fixtures['ptw-parent', '1.0.0'] = NpmFixture('ptw-parent', fields={
            'dependencies': {'ptw-leaf': '^1.0.0'}, 'optionalDependencies': {'ptw-darwin': '1.0.0'}},
            files={'package/index.js': b'module.exports = require("ptw-leaf");'})
        for version in ('1.0.0', '1.1.0', '1.2.0'):
            provider.fixtures['ptw-leaf', version] = NpmFixture('ptw-leaf', version,
                files={'package/index.js': b'module.exports = 9;'})
        provider.fixtures['ptw-darwin', '1.0.0'] = NpmFixture('ptw-darwin', fields={'os': ['darwin']},
            files={'package/index.js': b'throw Error("inactive optional package loaded");'})
        provider.overrides['ptw-leaf', '1.1.0'] = {'vulnerabilities': [CRITICAL]}
        provider.overrides['ptw-leaf', '1.2.0'] = {'published_at': datetime.now(timezone.utc).isoformat()}
        original = read_inputs(self.stage)[0]
        result = resolve_yarn(self.stage, self.root / 'transitive', RULES, provider=provider, update=True)
        plan = YarnPlan(result['files'])
        self.assertIn('ptw-leaf@1.0.0', plan.selected)
        self.assertNotIn('ptw-leaf@1.1.0', plan.selected)
        self.assertNotIn('ptw-leaf@1.2.0', plan.selected)
        self.assertIn('ptw-darwin@1.0.0', plan.selected)
        self.assertEqual(read_inputs(self.stage)[0], original)
        records = [provider.assess(r['name'], r['version']) for r in result['artifacts']]
        artifacts = self.root / 'resolved-artifacts'
        artifacts.mkdir()
        for record in records:
            provider.download(record, artifacts / record['filename'])
        target = self.root / 'resolved-install'
        plan.install(artifacts, target, records, [], None)
        self.assertFalse((target / 'node_modules/ptw-darwin').exists())
        self.assertFalse((target / 'root-hook').exists())
        self.stage = target
        self.import_value('require("ptw-parent") + require("ptw-value")', '16')

    def test_native_scoped_multiple_versions_peers_and_unapproved_build_changes(self):
        from ptw.yarn_resolution import resolve_yarn
        provider = self.resolution_provider()
        manifest = load(self.stage / 'package.json')
        manifest['dependencies']['@ptw/consumer'] = '^1.0.0'
        (self.stage / 'package.json').write_text(json.dumps(manifest))
        provider.fixtures['ptw-value', '2.0.0'] = NpmFixture('ptw-value', '2.0.0',
            files={'package/index.js': b'module.exports=20;'})
        provider.fixtures['ptw-inner', '1.0.0'] = NpmFixture('ptw-inner', fields={
            'dependencies': {'ptw-value': '^2.0.0'}},
            files={'package/index.js': b'module.exports=require("ptw-value");'})
        original = read_inputs(self.stage)[0]
        for mode in ('valid', 'peer-conflict', 'unapproved-change'):
            fields = {'dependencies': {'ptw-inner': '^1.0.0'},
                      'peerDependencies': {'ptw-value': '^3.0.0' if mode == 'peer-conflict' else '^1.0.0'}}
            if mode == 'unapproved-change':
                fields['scripts'] = {'postinstall': 'node -e "require(\'fs\').writeFileSync('
                    '\'/target/node_modules/ptw-value/index.js\',\'module.exports=99;\')"'}
            provider.fixtures['@ptw/consumer', '1.0.0'] = NpmFixture('@ptw/consumer', fields=fields,
                files={'package/index.js': b'module.exports=require("ptw-inner")+require("ptw-value");'})
            result = resolve_yarn(self.stage, self.root / (mode + '-resolution'), RULES,
                                  provider=provider, update=True)
            plan = YarnPlan(result['files'])
            self.assertIn('ptw-value@1.0.0', plan.selected)
            self.assertIn('ptw-value@2.0.0', plan.selected)
            records = [provider.assess(r['name'], r['version']) for r in result['artifacts']]
            artifacts = self.root / (mode + '-artifacts')
            artifacts.mkdir()
            for record in records:
                provider.download(record, artifacts / record['filename'])
            target = self.root / (mode + '-install')

            def build(argv):
                process = subprocess.run(argv, env={'PATH': '/usr/bin:/bin'}, capture_output=True,
                                         text=True, timeout=30)
                self.assertEqual(process.returncode, 0, 'synthetic build failed before validation')

            with self.subTest(mode=mode):
                if mode == 'valid':
                    plan.install(artifacts, target, records, [], None)
                    source = self.stage
                    self.stage = target
                    try:
                        self.import_value('require("@ptw/consumer")+require("ptw-value")', '34')
                    finally:
                        self.stage = source
                else:
                    with self.assertRaisesRegex(EvidenceError,
                            'violates original dependencies' if mode == 'peer-conflict' else 'content differs'):
                        plan.install(artifacts, target, records,
                                     ['@ptw/consumer'] if mode == 'unapproved-change' else [], build)
                    self.assertFalse((target / '.ptw-yarn-sources.json').exists())
            self.assertEqual(read_inputs(self.stage)[0], original)

    def test_native_reviewed_resolution_workspaces_and_directory_sources(self):
        from ptw.yarn_resolution import resolve_yarn
        provider = self.resolution_provider()
        manifest = load(self.stage / 'package.json')
        manifest['workspaces'] = ['packages/*']
        manifest['dependencies'].update({'ptw-local': '^1.0.0', 'ptw-copy': 'file:lib/copy'})
        (self.stage / 'package.json').write_text(json.dumps(manifest))
        for folder, name in (('packages/local', 'ptw-local'), ('lib/copy', 'ptw-copy')):
            save(self.stage / folder / 'package.json', {'name': name, 'version': '1.0.0',
                'dependencies': {'ptw-value': '^1.0.0'}})
        # The previous lock legitimately predates the proposed local manifest edit.
        original = read_inputs(self.stage)[0]
        result = resolve_yarn(self.stage, self.root / 'local-resolution', RULES, provider=provider, update=True)
        plan = YarnPlan(result['files'])
        self.assertEqual(plan.locals.keys(), {'packages/local', 'lib/copy'})
        self.assertEqual(plan.reference('', 'ptw-local', '^1.0.0'), ('local', 'packages/local'))
        self.assertEqual(plan.reference('', 'ptw-copy', 'file:lib/copy'), ('local', 'lib/copy'))
        self.assertEqual(result['files']['package.json'], original['package.json'])
        self.assertEqual(read_inputs(self.stage)[0], original)
        self.assertEqual(set(provider.assessments), {('ptw-value', '1.0.0')})

    def test_native_revision_terminal_retains_grants_history_and_revokes_sessions(self):
        self.revision_terminal()

    def test_default_public_origin_reviewed_update_and_protected_use(self):
        self.revision_terminal(public_yarn=True)

    def test_native_revision_concurrent_edit_preserves_current_policy_and_session(self):
        self.revision_terminal('concurrent')

    def test_native_revision_failed_publication_recovers_without_reopening_sessions(self):
        self.revision_terminal('publication')

    def revision_terminal(self, failure=None, *, public_yarn=False):
        from types import SimpleNamespace
        from test_product_onboarding import Terminal
        from ptw import dependency_revision as revision
        from ptw.onboarding import private_directory
        from ptw.policy import approve, compile_policy, digest
        from ptw.store import Store
        from ptw.workspace import Workspace, request, scan, stamp
        from ptw.supervisor import Supervisor
        from ptw.monitor import remove
        from ptw.setup_templates import template
        from ptw.yarn_resolution import resolve_yarn
        from ptw.dependency_binding import verify_inputs
        from ptw.packages import PackageControl, mounted_set
        provider = self.resolution_provider()
        if public_yarn:
            path = self.stage / 'yarn.lock'
            path.write_text(path.read_text().replace(YarnEvidence.NPM, YarnEvidence.YARN))
        manifest = load(self.stage / 'package.json')
        manifest['workspaces'] = ['packages/*']
        manifest['dependencies']['ptw-local'] = '^1.0.0'
        (self.stage / 'package.json').write_text(json.dumps(manifest))
        save(self.stage / 'packages/local/package.json', {'name': 'ptw-local', 'version': '1.0.0',
            'main': 'index.cjs', 'dependencies': {'ptw-value': '^1.0.0'}})
        (self.stage / 'packages/local/index.cjs').write_text('module.exports=require("ptw-value")*2;')
        initial = resolve_yarn(self.stage, self.root / 'initial', RULES, provider=provider)
        self.enterContext(patch.dict(os.environ, {'PTW_USER_STATE': str(self.root / 'operator')}))
        directory = private_directory(self.stage)
        (self.stage / 'dist').mkdir()
        (self.stage / '.ptw').mkdir()
        policy, inv = template(self.stage, 'yarn-revision', 'Review Yarn dependencies',
            {'packages/local/index.cjs': 'file', 'dist': 'tree'}, list(initial['inputs']), [],
            ['npm:ptw-value', 'npm:unrelated'], 1, 3)
        resources = [r for r, v in inv['resources'].items() if v['path'].startswith('packages/local/')]
        snapshot = scan(inv, resources)
        policy['project']['npm_dependencies'] = {'root': '', 'inputs': initial['inputs'],
            'artifacts': initial['artifacts'], 'lock_sha256': digest(initial['lock']),
            'sources': [{'path': 'packages/local', 'resources': resources,
                'snapshot_sha256': digest({p: [stamp(e), e.get('mode')] for p, e in snapshot.items()})}]}
        policy['project']['packages']['build_packages'] = ['npm:unrelated']
        policy['project']['commands'] = [{'id': 'use', 'resources': list(inv['resources']),
            'timeout_seconds': 30, 'argv': ['/usr/bin/node', '-e',
                'if(require("ptw-local")!==14)throw Error("wrong revised graph");'
                'require("fs").writeFileSync("dist/revised.txt","YARN_REVISION_OK");']}]
        policy['tasks'][0]['commands'] = ['use']
        old = approve(policy, inv, digest(compile_policy(policy, inv)), 'synthetic operator')
        save(directory / 'approved.json', old)
        save(self.stage / '.ptw/policy.json', policy)
        store = Store(directory / 'controller')
        store.activate(old)

        def cleanup():
            store.stop('yarn-revision')
            Supervisor(store).reconcile()
            remove(store)
        self.addCleanup(cleanup)
        save(directory / 'project.json', dict(project='yarn-revision', repo=str(self.stage), state=str(store.directory),
            bundle=str(directory / 'approved.json'), policy_sha256=old['approval']['sha256'], task='work',
            language='javascript', publication_sha256='synthetic-no-setup-publication'))
        actor = store.register('yarn-revision', 'work')
        installed = PackageControl(store, provider=provider).install(actor['token'], 'old-install', initial['lock'], ecosystem='npm')
        self.assertTrue(installed['allowed'], installed)
        self.assertFalse(Workspace(store).request(actor['token'], 'retained', request('read', 'missing'))['allowed'])
        provider.fixtures['ptw-value', '1.1.0'] = NpmFixture('ptw-value', '1.1.0',
            files={'package/index.js': b'module.exports=7;'})
        registry = self.root / 'revision-registry.json'
        provider.write(registry)
        original = read_inputs(self.stage)[0]
        args = SimpleNamespace(repo=str(self.stage), root='', ecosystem='npm', task='work',
            source=None, operation='update', specs=['ptw-value@^1.0.0'], group=None)
        if failure:
            calls, move = [], revision.move

            def fail_once(source, destination):
                calls.append(str(destination))
                if len(calls) == 3:
                    raise OSError('synthetic interrupted Yarn publication')
                return move(source, destination)

            def answer(*unused):
                if failure == 'concurrent':
                    (self.stage / 'package.json').write_text(original['package.json'] + '\n')
                return 'yes'

            with patch('ptw.onboarding.ask', side_effect=answer), \
                    patch('ptw.registry.provider_for', return_value=provider), \
                    patch.object(revision, 'move', side_effect=fail_once if failure == 'publication' else move):
                with self.assertRaisesRegex(OSError if failure == 'publication' else Invalid,
                        'interrupted Yarn publication' if failure == 'publication' else 'changed after review'):
                    revision.start(args)
            with store.locked() as db:
                row, current = store.project(db, 'yarn-revision')
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
            self.assertEqual(read_inputs(self.stage)[0], expected)
            if failure == 'publication':
                self.assertEqual(load(directory / 'dependency-journal.json')['phase'], 'rolled-back')
                verify_inputs(current)
                fresh = store.register('yarn-revision', 'work')
                restored = PackageControl(store, provider=provider).install(
                    fresh['token'], 'rollback-install', initial['lock'], ecosystem='npm')
                self.assertTrue(restored['allowed'], restored)
            return
        from regression_timing import active_directory
        script = ('import sys\nfrom unittest.mock import patch\n'
            'sys.path.insert(0,' + repr(str(Path(__file__).resolve().parent)) + ')\n'
            'from test_product_yarn import YarnRegistryFixture\nfrom ptw.cli import main\n'
            'from regression_timing import child_phases\n'
            'with child_phases(' + repr(active_directory()) + ', ' + repr(self.id()) + '):\n'
            '    with patch("ptw.registry.provider_for", return_value=YarnRegistryFixture.read(' + repr(str(registry)) + ')):\n'
            '        main()\n')
        for answer in ('reject', 'cancel', 'eof', 'yes'):
            terminal = Terminal([sys.executable, '-B', '-c', script, 'deps', 'update', 'ptw-value@^1.0.0',
                '--repo', str(self.stage), '--ecosystem', 'npm'], self.root / ('revision-' + answer))
            try:
                terminal.expect('Approve dependency revision?', 180)
                self.assertEqual(read_inputs(self.stage)[0], original)
                terminal.send('details')
                terminal.expect('Approve exactly this dependency revision?', 5)
                self.assertIn('yarn.lock', terminal.text)
                if answer == 'eof':
                    os.write(terminal.fd, b'\x04')
                else:
                    terminal.send(answer)
                terminal.wait(lambda: terminal.exited, 30)
            finally:
                code = terminal.close()
            self.assertEqual(code, 0 if answer == 'yes' else 130 if answer == 'eof' else 2, terminal.text[-2000:])
            self.assertEqual(store.status('yarn-revision')['violations'], 1)
            if answer != 'yes':
                self.assertEqual(read_inputs(self.stage)[0], original)
                with store.locked() as db:
                    store.session(db, actor['token'])
        with store.locked() as db:
            _, current = store.project(db, 'yarn-revision')
            with self.assertRaisesRegex(Invalid, 'Session ended'):
                store.session(db, actor['token'])
        verify_inputs(current)
        self.assertEqual(current['policy']['project']['grants'], old['policy']['project']['grants'])
        self.assertIn('npm:unrelated', current['policy']['project']['packages']['allowed_names'])
        self.assertEqual(current['policy']['project']['packages']['build_packages'], ['npm:unrelated'])
        self.assertEqual(current['policy']['project']['escalation'], old['policy']['project']['escalation'])
        if public_yarn:
            self.assertTrue(all(r['url'].startswith(YarnEvidence.YARN + '/')
                for r in current['policy']['project']['npm_dependencies']['artifacts']))
            self.assertNotIn(YarnEvidence.NPM, (self.stage / 'yarn.lock').read_text())
        self.assertIn(('ptw-value', '1.1.0'), {(r['name'], r['version']) for r in current['policy']['project']['npm_dependencies']['artifacts']})
        self.assertFalse((self.stage / 'package-lock.json').exists())
        new_actor = store.register('yarn-revision', 'work')
        with store.locked() as db:
            actor_row = store.session(db, new_actor['token'])
            with self.assertRaisesRegex(Invalid, 'obsolete policy revision'):
                mounted_set(store, db, actor_row, installed['package_set'])
        provider.fixtures['ptw-extra', '1.0.0'] = NpmFixture('ptw-extra')
        for operation, specs in (('add', ['ptw-extra@^1.0.0']), ('remove', ['ptw-extra'])):
            args.operation, args.specs = operation, specs
            with patch('ptw.onboarding.ask', return_value='yes'), patch('ptw.registry.provider_for', return_value=provider):
                result = revision.start(args)
            self.assertTrue(result['history_preserved'])
            self.assertTrue(result['sessions_revoked'])
            with store.locked() as db:
                _, current = store.project(db, 'yarn-revision')
            verify_inputs(current)
            rules = current['policy']['project']['packages']
            self.assertEqual('npm:ptw-extra' in rules['allowed_names'], operation == 'add')
            self.assertIn('npm:unrelated', rules['allowed_names'])
            self.assertEqual(rules['build_packages'], ['npm:unrelated'])
            self.assertEqual(current['policy']['project']['grants'], old['policy']['project']['grants'])
            for before, after in zip(old['policy']['tasks'], current['policy']['tasks']):
                for field in ('id', 'grants', 'commands', 'escalation'):
                    self.assertEqual(after[field], before[field])
                self.assertIn('npm:unrelated', after['packages'])
            self.assertEqual(store.status('yarn-revision')['violations'], 1)
        fresh = store.register('yarn-revision', 'work')
        current_lock = {'manager': 'yarn', 'files': read_inputs(self.stage)[0]}
        installed = PackageControl(store, provider=provider).install(fresh['token'], 'new-install', current_lock, ecosystem='npm')
        self.assertTrue(installed['allowed'], installed)
        result = Workspace(store).request(fresh['token'], 'revised-import', request('run', 'use',
            content=json.dumps({'package_sets': [installed['package_set']]})))
        self.assertTrue(result['allowed'], result)
        self.assertEqual(result['exit_code'], 0, result)
        self.assertEqual((self.stage / 'dist/revised.txt').read_text(), 'YARN_REVISION_OK')
        self.assertEqual((self.stage / 'packages/local/package.json').read_text(), original['packages/local/package.json'])
        self.assertFalse((self.stage / 'root-hook').exists())

    def test_native_authenticated_registry_build_and_credential_confinement(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        import ssl
        import threading
        from urllib.request import build_opener, HTTPSHandler, ProxyHandler
        from ptw.package_evidence import NoRedirect
        from ptw.registry import RoutedNpmEvidence
        from ptw.yarn_resolution import resolve_yarn
        from ptw.packages import PackageControl
        credential = self.root / 'synthetic-credential.json'
        token = 'Bearer SYNTHETIC_YARN_FIXTURE_TOKEN'
        save(credential, {'authorization': token})
        probe = ('const fs=require("fs");'
            'if(Object.values(process.env).some(v=>v.includes("SYNTHETIC_YARN")))throw Error("environment leak");'
            'let leaked=false;try{fs.readFileSync(' + json.dumps(str(credential)) + ');leaked=true}catch{}'
            'if(leaked)throw Error("credential file leak");')
        fixture = NpmFixture('ptw-value', fields={'scripts': {'postinstall': 'node build.cjs'}}, files={
            'package/index.js': (probe + 'module.exports=require("./built.json");').encode(),
            'package/build.cjs': (probe + 'fs.writeFileSync("built.json","7");').encode()})
        registry = YarnRegistryFixture([fixture])
        seen = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, raw):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(raw)

            def authenticated(self):
                valid = self.headers.get('Authorization') == token
                seen.append((self.path, valid))
                if not valid:
                    self.send_error(401)
                return valid

            def do_GET(self):
                if self.authenticated():
                    self.reply(fixture.raw if self.path.endswith('.tgz') else
                               json.dumps(registry.packument('ptw-value')).encode())

            def do_POST(self):
                if self.authenticated():
                    query = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                    self.reply(json.dumps({'origin': endpoint, 'name': query['package']['name'],
                        'version': query['version'], 'coverage': 'complete', 'vulns': []}).encode())

        # Keep production HTTPS admission intact. The broker explicitly trusts
        # this run's synthetic certificate; native Yarn never sees its key.
        certificate, key = self.root / 'fixture.crt', self.root / 'fixture.key'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1',
            '-keyout', str(key), '-out', str(certificate)], check=True, capture_output=True, timeout=30)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        server = HTTPServer(('127.0.0.1', 0), Handler)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        endpoint = 'https://127.0.0.1:' + str(server.server_port)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            fixture.record['url'] = endpoint + '/ptw-value-1.0.0.tgz'
            provider = RoutedNpmEvidence({'version': 1, 'packages': {'ptw-value': {
                'registry': endpoint, 'advisories': endpoint, 'credential_ref': str(credential)}}})
            provider.http = build_opener(ProxyHandler({}), NoRedirect(),
                HTTPSHandler(context=ssl.create_default_context(cafile=str(certificate))))
            original = self.controller(fixture=fixture, approve_build=True)
            resolved = resolve_yarn(self.stage, self.root / 'private-resolution', RULES,
                                    provider=provider, update=True)
            self.assertEqual({r['url'] for r in resolved['artifacts']}, {fixture.record['url']})
            installed = PackageControl(self.store, provider=provider).install(
                self.actor['token'], 'private-install', self.specs, ecosystem='npm')
            self.assertTrue(installed['allowed'], installed)
            target = self.store.directory / 'package-sets' / installed['package_set']
            self.assertEqual(load(target / 'node_modules/ptw-value/built.json'), 7)
            result = self.command('use', installed['package_set'])
            self.assertTrue(result['allowed'], result)
            self.assertEqual(result['exit_code'], 0, result)
            self.assertEqual((self.stage / 'dist/result.txt').read_text(), 'PROTECTED_YARN_OK')
            self.assertNotIn(token, json.dumps([resolved, installed, result]))
            for directory in (target, self.root / 'private-resolution'):
                for path in directory.rglob('*'):
                    if path.is_file():
                        self.assertNotIn(token.encode(), path.read_bytes())
                        self.assertNotIn(key.read_bytes(), path.read_bytes())
            self.assertTrue(any(path.endswith('.tgz') for path, _ in seen))
            self.assertTrue(all(valid for _, valid in seen))
            before = {p.name for p in (self.store.directory / 'package-sets').iterdir()}
            provider.routes['ptw-value']['authorization'] = 'Bearer INVALID_SYNTHETIC_TOKEN'
            denied = PackageControl(self.store, provider=provider).install(
                self.actor['token'], 'wrong-credential', self.specs, ecosystem='npm')
            self.assertFalse(denied['allowed'], denied)
            self.assertFalse(denied['violation_counted'], denied)
            self.assertEqual({p.name for p in (self.store.directory / 'package-sets').iterdir()}, before)
            self.assertTrue(any(not valid for _, valid in seen))
            self.assertEqual(self.store.status('yarn-fixture')['violations'], 0)
            self.assertEqual(read_inputs(self.stage)[0], original)
            save(self.root / 'private-effects.json', {'build': True, 'import': True,
                'authenticated_requests': sum(valid for _, valid in seen),
                'unauthorized_requests': sum(not valid for _, valid in seen),
                'credential_absent_from_exports': True})
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_native_terminal_setup_review_rejection_eof_and_protected_build(self):
        from test_product_onboarding import Terminal
        from test_product_pnpm import PnpmRegistryFixture
        from ptw.onboarding import private_directory
        from ptw.store import Store
        from ptw.monitor import remove
        from ptw.supervisor import Supervisor
        from ptw.workflow import dispatch
        from ptw.workspace import request
        manifest = load(self.stage / 'package.json')
        manifest['scripts']['build'] = 'node src/build.cjs'
        manifest['workspaces'] = ['packages/*']
        manifest['dependencies']['ptw-local'] = '^1.0.0'
        (self.stage / 'package.json').write_text(json.dumps(manifest))
        save(self.stage / 'packages/local/package.json', {'name': 'ptw-local', 'version': '1.0.0',
            'main': 'index.cjs', 'dependencies': {'ptw-value': '^1.0.0'}})
        (self.stage / 'packages/local/index.cjs').write_text('module.exports=require("ptw-value")*2;')
        (self.stage / 'src').mkdir()
        (self.stage / 'src/build.cjs').write_text('const fs=require("fs");'
            'if(require("ptw-value")!==7||require("ptw-local")!==14)throw Error("wrong graph");'
            'fs.writeFileSync("dist/result.txt","YARN_TERMINAL_BUILD_OK");')
        original = read_inputs(self.stage)[0]
        provider = PnpmRegistryFixture([self.fixture])  # Shared synthetic registry data helper only.
        registry = self.root / 'synthetic-registry.json'
        provider.write(registry)
        self.enterContext(patch.dict(os.environ, {'PTW_USER_STATE': str(self.root / 'operator')}))
        script = ('import sys\nfrom unittest.mock import patch\n'
            'sys.path.insert(0,' + repr(str(Path(__file__).resolve().parent)) + ')\n'
            'from test_product_pnpm import PnpmRegistryFixture\nfrom ptw.cli import main\n'
            'provider=PnpmRegistryFixture.read(' + repr(str(registry)) + ')\n'
            'with patch("ptw.codex.require_login"), patch("ptw.yarn_resolution.NpmEvidence", return_value=provider):\n'
            '    main()\n')
        base = [sys.executable, '-B', '-c', script, 'codex', '--repo', str(self.stage),
                '--goal', 'Build selected Yarn workspace', '--editable', 'src,dist',
                '--files', 'packages/local/index.cjs', '--setup-only']
        terminal = Terminal(base + ['--yarn-build', 'ptw-local'], self.root / 'setup-invalid-build')
        try:
            terminal.wait(lambda: terminal.exited, 180)
        finally:
            code = terminal.close()
        self.assertEqual(code, 2, terminal.text[-2000:])
        self.assertIn('exact registry package names', terminal.text)
        self.assertNotIn('Approve exactly this policy?', terminal.text)
        self.assertFalse((self.stage / '.ptw').exists())
        for answer in ('reject', 'eof', 'interrupt', 'yes'):
            terminal = Terminal(base + ['--yarn-build', 'ptw-value'], self.root / ('setup-' + answer))
            try:
                terminal.expect('Approve exactly this policy?', 180)
                terminal.send('details')
                terminal.expect('Reviewed npm inputs and artifacts:', 5)
                self.assertIn('yarn.lock', terminal.text)
                self.assertIn('source builds npm:ptw-value', terminal.text)
                self.assertEqual(read_inputs(self.stage)[0], original)
                self.assertFalse(list(self.root.rglob('dependency-hook')))
                if answer in ('eof', 'interrupt'):
                    os.write(terminal.fd, b'\x04' if answer == 'eof' else b'\x03')
                else:
                    terminal.send(answer)
                terminal.wait(lambda: terminal.exited, 30)
            finally:
                code = terminal.close()
            self.assertEqual(code, 0 if answer == 'yes' else 130 if answer in ('eof', 'interrupt') else 2, terminal.text[-2000:])
            self.assertEqual(read_inputs(self.stage)[0], original)
            if answer != 'yes':
                self.assertFalse((self.stage / '.ptw').exists())
                self.assertFalse((self.stage / 'dist').exists())
        record = load(private_directory(self.stage) / 'project.json')
        store = Store(record['state'])
        def cleanup():
            store.stop(record['project'])
            Supervisor(store).reconcile()
            remove(store)
        self.addCleanup(cleanup)
        bundle = load(record['bundle'])
        self.assertEqual(bundle['policy']['project']['packages']['build_packages'], ['npm:ptw-value'])
        actor = store.register(record['project'], 'work')
        lock_id = next(r for r, v in bundle['inventory']['resources'].items() if v['path'] == 'yarn.lock')
        with patch('ptw.registry.provider_for', return_value=provider):
            installed = dispatch(store, actor, 'terminal-install', request('install', lock_id, content='yarn'))
        self.assertTrue(installed['allowed'], installed)
        target = store.directory / 'package-sets' / installed['package_set']
        self.assertEqual((target / 'node_modules/ptw-value/dependency-hook').read_text(), 'ran')
        result = dispatch(store, actor, 'terminal-build', request('run', 'build',
            content=json.dumps({'package_sets': [installed['package_set']]})))
        self.assertTrue(result['allowed'], result)
        self.assertEqual(result['exit_code'], 0, result)
        self.assertEqual((self.stage / 'dist/result.txt').read_text(), 'YARN_TERMINAL_BUILD_OK')
        self.assertFalse((self.stage / 'root-hook').exists())
        self.assertFalse((self.stage / 'package-lock.json').exists())
        self.assertEqual(read_inputs(self.stage)[0], original)


if __name__ == '__main__':
    unittest.main()
