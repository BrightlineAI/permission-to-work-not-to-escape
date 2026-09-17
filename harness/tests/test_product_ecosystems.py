"""Product dependency tests. Synthetic evidence is not a live registry result."""
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from ptw.dependency_binding import verify_artifacts, verify_inputs, verify_selection
from ptw.dependency_resolution import (ResolutionError, compiled_pins, python_inputs,
    requirement_lines, resolve_python, resolver_environment, run_metadata)
from ptw.package_evidence import EvidenceError
from ptw.package_install import install_wheels, target_environment
from ptw.policy import Invalid, approve, compile_policy, digest, load
from ptw.python_runtime import identify, select, verify
from ptw.setup_templates import RULES, selected, template
from ptw.store import Store
from ptw import onboarding
from test_packages import CRITICAL, FixtureProvider, wheel_bytes


class ProductEcosystemTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ptw-product-deps-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.calls = []

    def resolve(self, text='demo>=1,<3', **options):
        (self.repo / 'requirements.txt').write_text(text + '\n')
        return resolve_python(self.repo, self.root / 'attempt', RULES, **options)

    def runner(self, graphs):
        graphs = iter(graphs)

        def run(argv, **kwargs):
            self.calls.append((argv, kwargs, (Path(kwargs['cwd']) / 'constraints.txt').read_text()))
            graph = next(graphs)
            if isinstance(graph, Exception):
                raise graph
            if graph is None:
                return SimpleNamespace(returncode=1, stderr='No solution found when resolving dependencies')
            Path(argv[argv.index('--output-file') + 1]).write_text(graph)
            return SimpleNamespace(returncode=0, stderr='')
        return run

    def provider(self, bad=(), young=(), malformed=()):
        fixture = FixtureProvider()

        def assess(name, version):
            result = fixture.assess(name, version)
            if (name, version) in bad:
                result['vulnerabilities'] = [CRITICAL]
            if (name, version) in young:
                result['published_at'] = datetime.now(timezone.utc).isoformat()
            if (name, version) in malformed:
                result.pop('vulnerabilities')
            return result
        return SimpleNamespace(assess=assess)

    def test_critical_latest_selects_older_by_additive_constraint(self):
        result = self.resolve(provider=self.provider(bad={('demo', '2.0')}),
                              runner=self.runner(['demo==2.0\n', 'demo==1.0\n']))
        self.assertEqual(result['pins'], ['demo==1.0'])
        self.assertIn('demo!=2.0', self.calls[1][2])
        self.assertNotIn('--override', self.calls[1][0])
        self.assertEqual((self.root / 'attempt/requirements.in').read_text(), 'demo>=1,<3\n')
        self.assertEqual(load(self.root / 'attempt/resolution.json')['attempts'][0]['outcome'], 'policy_exclusion')

    def test_age_filter_and_independent_age_check(self):
        result = self.resolve(provider=self.provider(young={('demo', '2.0')}),
                              runner=self.runner(['demo==2.0\n', 'demo==1.0\n']))
        self.assertEqual(result['pins'], ['demo==1.0'])
        for argv, _, _ in self.calls:
            self.assertIn('--exclude-newer', argv)
        self.assertEqual(self.calls[0][0][self.calls[0][0].index('--exclude-newer') + 1],
                         self.calls[1][0][self.calls[1][0].index('--exclude-newer') + 1])

    def test_transitive_exclusion_retains_parent_compatibility(self):
        result = self.resolve('parent==1.0', provider=self.provider(bad={('demo', '2.0')}),
            runner=self.runner(['parent==1.0\ndemo==2.0\n', 'parent==1.0\ndemo==1.0\n']))
        self.assertIn('parent==1.0', result['pins'])
        self.assertNotIn('parent', self.calls[1][2])

    def test_exact_pin_is_unsatisfiable_not_overridden(self):
        with self.assertRaises(ResolutionError) as raised:
            self.resolve('demo==2.0', provider=self.provider(bad={('demo', '2.0')}),
                         runner=self.runner(['demo==2.0\n', None]))
        self.assertEqual(raised.exception.outcome, 'unsatisfiable')
        self.assertEqual((self.root / 'attempt/requirements.in').read_text(), 'demo==2.0\n')

    def test_unavailable_evidence_never_becomes_exclusion(self):
        with self.assertRaises(EvidenceError):
            self.resolve(provider=self.provider(malformed={('demo', '2.0')}), runner=self.runner(['demo==2.0\n']))
        report = load(self.root / 'attempt/resolution.json')
        self.assertEqual(report['outcome'], 'unavailable_evidence')
        self.assertEqual(len(report['attempts']), 1)

    def test_round_and_candidate_limits(self):
        with self.assertRaises(ResolutionError) as raised:
            self.resolve(provider=self.provider(bad={('demo', '2.0')}), runner=self.runner(['demo==2.0\n']), max_rounds=1)
        self.assertEqual(raised.exception.outcome, 'budget_exhausted')
        with self.assertRaises(ResolutionError) as raised:
            resolve_python(self.repo, self.root / 'second', RULES, provider=self.provider(),
                           runner=self.runner(['demo==1.0\nother==1.0\n']), max_assessments=1)
        self.assertEqual(raised.exception.outcome, 'budget_exhausted')

    def test_timeout_is_not_unsatisfiable(self):
        with self.assertRaises(ResolutionError) as raised:
            self.resolve(provider=self.provider(), runner=self.runner([subprocess.TimeoutExpired('uv', 1)]))
        self.assertEqual(raised.exception.outcome, 'budget_exhausted')

    def test_native_transport_failure_is_not_constraint_conflict(self):
        with self.assertRaises(ResolutionError) as raised:
            self.resolve(provider=self.provider(), runner=lambda *a, **k: SimpleNamespace(returncode=1, stderr='connection refused'))
        self.assertEqual(raised.exception.outcome, 'unavailable')

    def test_candidate_identity_mismatch_blocks(self):
        fixture = FixtureProvider({'demo': {'name': 'other'}})
        with self.assertRaisesRegex(EvidenceError, 'identity mismatch'):
            self.resolve(provider=fixture, runner=self.runner(['demo==1.0\n']))

    def test_original_artifact_hash_is_enforced_after_resolution(self):
        with self.assertRaisesRegex(EvidenceError, 'original requirement hashes'):
            self.resolve('demo==1.0 --hash=sha256:' + 'f' * 64, provider=self.provider(),
                         runner=self.runner(['demo==1.0\n']))

    def test_wrong_native_pin_is_independently_rejected(self):
        with self.assertRaisesRegex(Invalid, 'original dependency constraint'):
            self.resolve('demo==1.0', provider=self.provider(), runner=self.runner(['demo==2.0\n']))

    def test_constraints_includes_hashes_and_markers_are_preserved(self):
        (self.repo / 'requirements.txt').write_text('-r requirements/base.txt\n-c constraints.txt\n')
        (self.repo / 'requirements').mkdir()
        declaration = 'demo==1.0; python_version >= "3.8" --hash=sha256:' + 'a' * 64
        (self.repo / 'requirements/base.txt').write_text(declaration + '\n')
        (self.repo / 'constraints.txt').write_text('demo<2\n')
        requirements, constraints, inputs, _ = python_inputs(self.repo)
        self.assertEqual(requirements, [declaration])
        self.assertEqual(constraints, ['demo<2'])
        self.assertEqual(len(inputs), 3)

    def test_include_cycles_traversal_symlinks_options_and_urls_fail(self):
        for line in ('-r requirements.txt', '-r ../outside.txt', '--index-url https://private.invalid',
                     'demo @ https://private.invalid/demo.whl', '-e ./local', 'demo==1 --hash=sha256:BAD'):
            (self.repo / 'requirements.txt').write_text(line)
            with self.subTest(line=line), self.assertRaises(Invalid):
                python_inputs(self.repo)
        (self.repo / 'linked.txt').symlink_to('/etc/passwd')
        (self.repo / 'requirements.txt').write_text('-r linked.txt')
        with self.assertRaises(Invalid):
            python_inputs(self.repo)

    def test_static_pyproject_runtime_groups_and_extras(self):
        (self.repo / 'pyproject.toml').write_text('''[project]
name = "sample"
version = "1.0"
requires-python = ">=3.10,<4"
dependencies = ["demo>=1,<3"]
[project.optional-dependencies]
web = ["web>=1"]
[dependency-groups]
common = ["tool>=1"]
test = [{include-group="common"}, "test>=1"]
''')
        requirements, _, _, runtime = python_inputs(self.repo, extras=['web'])
        self.assertEqual(runtime, '>=3.10,<4')
        self.assertEqual(requirements, ['demo>=1,<3', 'web>=1', 'tool>=1', 'test>=1'])

    def test_malformed_and_dynamic_pyproject(self):
        for content in ('[project]\ndynamic=["dependencies"]', '[project]\ndependencies="demo"',
                        '[project]\ndependencies=["demo"]\n[dependency-groups]\ndev=[{include-group="dev"}]'):
            (self.repo / 'pyproject.toml').write_text(content)
            with self.subTest(content=content), self.assertRaises(Invalid):
                python_inputs(self.repo)

    def test_compiled_markers_and_extras_select_target_environment(self):
        result = compiled_pins('demo[web]==1.0; python_version>="3.8"\nother==2; sys_platform=="win32"', target_environment())
        self.assertEqual(result, ['demo[web]==1.0'])
        with self.assertRaises(Invalid):
            compiled_pins('demo>=1', target_environment())

    def test_runtime_constraint_unavailable_and_changed(self):
        runtime = select('>=3,<4')
        self.assertEqual(verify(runtime), str(Path('/usr/bin/python3').resolve()))
        with self.assertRaisesRegex(Invalid, 'No installed system Python'):
            select('>=100')
        with self.assertRaises(Invalid):
            select('>=3', str(self.repo / 'python3'))
        with self.assertRaises(Invalid):
            verify({**runtime, 'sha256': 'a' * 64})

    def test_python_startup_hook_uses_its_actual_package_mount(self):
        artifacts = self.root / 'wheels'
        artifacts.mkdir()
        target = self.root / 'python-packages'
        with patch('ptw.package_install.subprocess.run', return_value=SimpleNamespace(returncode=0)):
            install_wheels(artifacts, target, [], extended=True)
        (target / 'vendor').mkdir()
        (target / 'vendor/companion.py').write_text('VALUE = 42\n')
        (target / 'vendor.pth').write_text('vendor\n')
        result = subprocess.run(['/usr/bin/python3', '-B', '-c', 'import companion; print(companion.VALUE)'],
            capture_output=True, text=True, timeout=10,
            env={'PATH': '/usr/bin:/bin', 'PYTHONPATH': str(target), 'PYTHONNOUSERSITE': '1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), '42')

    def test_python_version_is_a_request_not_an_executable(self):
        (self.repo / '.python-version').write_text('/private/python3')
        with self.assertRaisesRegex(Invalid, 'not a path'):
            resolve_python(self.repo, self.root / 'bad-runtime', RULES)
        version = identify('/usr/bin/python3')['version']
        (self.repo / '.python-version').write_text(version)
        result = resolve_python(self.repo, self.root / 'good-runtime', RULES)
        self.assertEqual(result['runtime']['version_request'], version)
        self.assertIn('.python-version', result['inputs'])

    def test_empty_project_has_reviewed_runtime_without_resolver(self):
        with patch('ptw.dependency_resolution.run_metadata', side_effect=AssertionError('no resolver needed')):
            result = resolve_python(self.repo, self.root / 'empty', RULES)
        self.assertEqual(result['pins'], [])
        self.assertIn('sha256', result['runtime'])

    def test_ambiguous_declarations_need_explicit_choice(self):
        (self.repo / 'requirements.txt').write_text('demo==1')
        (self.repo / 'pyproject.toml').write_text('[project]\ndependencies=["other==1"]')
        with self.assertRaisesRegex(Invalid, 'Both requirements'):
            python_inputs(self.repo)
        self.assertEqual(python_inputs(self.repo, source='requirements.txt')[0], ['demo==1'])

    def test_native_locks_require_their_authoritative_manifest(self):
        for filename in ('uv.lock', 'poetry.lock'):
            (self.repo / filename).write_text('version=1')
            with self.assertRaisesRegex(Invalid, 'authoritative lock'):
                resolve_python(self.repo, self.root / filename, RULES)
            (self.repo / filename).unlink()

    def test_resolver_environment_has_no_ambient_credentials_or_injection(self):
        with patch.dict(os.environ, {'TOKEN': 'SYNTHETIC_SECRET', 'NPM_TOKEN': 'SYNTHETIC_SECRET',
                                    'NODE_OPTIONS': '--require /private', 'PYTHONPATH': '/private',
                                    'HTTPS_PROXY': 'http://synthetic:secret@invalid'}):
            env = resolver_environment(self.root)
        self.assertNotIn('SYNTHETIC_SECRET', json.dumps(env))
        self.assertNotIn('NODE_OPTIONS', env)
        self.assertNotIn('HTTPS_PROXY', env)
        self.assertEqual(env['HOME'], str(self.root / 'resolver-home'))

    def test_metadata_namespace_mounts_only_staging_and_runtime(self):
        stage = self.root / 'stage'
        stage.mkdir()
        with patch('ptw.dependency_resolution.subprocess.run', return_value=SimpleNamespace(returncode=0)) as run:
            run_metadata(['/usr/local/bin/uv', 'pip', 'compile', str(stage / 'requirements.in')],
                         cwd=stage, env=resolver_environment(stage), capture_output=True, text=True, timeout=5)
        argv = run.call_args.args[0]
        self.assertIn('--unshare-user', argv)
        self.assertIn('--clearenv', argv)
        self.assertIn('/resolution/requirements.in', argv)
        self.assertNotIn(str(self.repo), argv)
        self.assertNotIn(str(Path.home()), argv)

    def test_bindings_reject_mutated_source_pins_and_origin(self):
        result = self.resolve(provider=self.provider(), runner=self.runner(['demo==1.0\n']))
        bundle = {'policy': {'project': {'python_dependencies': {k: result[k] for k in ('pins', 'inputs', 'artifacts')}}},
                  'inventory': {'root': str(self.repo)}}
        verify_inputs(bundle)
        verify_selection(bundle, {'demo': '1.0'}, {})
        verify_artifacts(bundle, result['artifacts'])
        with self.assertRaises(Invalid):
            verify_selection(bundle, {'demo': '2.0'}, {})
        with self.assertRaises(Invalid):
            verify_artifacts(bundle, [{**result['artifacts'][0], 'url': 'https://private.invalid/demo'}])
        (self.repo / 'requirements.txt').write_text('demo==2.0')
        with self.assertRaises(Invalid):
            verify_inputs(bundle)

    def test_mixed_detection_scoped_commands_and_cwd(self):
        for name in ('backend/src', 'frontend/src'):
            (self.repo / name).mkdir(parents=True)
        (self.repo / 'backend/pyproject.toml').write_text('[project]\ndependencies=[]')
        (self.repo / 'frontend/package.json').write_text('{"scripts":{"build":"node src/app.js"}}')
        self.assertEqual(onboarding.detect(self.repo), 'mixed')
        scope = selected(self.repo, ['backend/src', 'frontend/src'], [])
        command = {'id': 'frontend', 'argv': ['/usr/bin/node', 'src/app.js'],
                   'resources': ['frontend/src'], 'cwd': 'frontend', 'timeout_seconds': 5}
        policy, inventory = template(self.repo, 'mixed', 'Build frontend', scope, [], [command], [], 1, 3)
        compile_policy(policy, inventory)
        policy['project']['commands'][0]['cwd'] = '../outside'
        with self.assertRaises(Invalid):
            compile_policy(policy, inventory)

    def test_stale_npm_lock_and_missing_pnpm_adapter_are_rejected(self):
        from test_ecosystems import NpmFixture
        fixture = NpmFixture()
        (self.repo / 'package.json').write_text(json.dumps({'dependencies': {'demo': '^2'}}))
        (self.repo / 'package-lock.json').write_text(json.dumps(fixture.lock))
        with self.assertRaisesRegex(Invalid, 'disagree'):
            onboarding.resolve_npm(self.repo, self.root)
        (self.repo / 'package-lock.json').unlink()
        (self.repo / 'pnpm-lock.yaml').write_text('lockfileVersion: 9')
        with self.assertRaisesRegex(Invalid, 'authoritative lock'):
            onboarding.resolve_npm(self.repo, self.root / 'pnpm-attempt')

    def test_mixed_pty_review_denial_then_approval(self):
        from test_product_onboarding import Terminal
        for name in ('backend/src', 'frontend/src'):
            (self.repo / name).mkdir(parents=True)
        (self.repo / 'backend/pyproject.toml').write_text('[project]\nrequires-python=">=3.10,<4"\ndependencies=[]')
        (self.repo / 'frontend/package.json').write_text('{"scripts":{"test":"node src/app.mjs"}}')
        original = {str(p.relative_to(self.repo)): p.read_bytes() for p in self.repo.rglob('*') if p.is_file()}
        for index, reply in enumerate(('reject', 'yes')):
            terminal = Terminal([sys.executable, str(Path(__file__).with_name('test_product_onboarding.py')),
                '--fixture', 'codex', '--repo', str(self.repo), '--goal', 'Test both applications',
                '--language', 'mixed', '--editable', 'backend/src,frontend/src', '--files', '', '--setup-only'],
                self.root / ('terminal-' + str(index)), env={'PTW_USER_STATE': str(self.root / 'operator')})
            try:
                terminal.expect('Approve exactly', 15)
                self.assertIn('Python runtime:', terminal.text)
                self.assertIn('>=3.10,<4', terminal.text)
                self.assertIn('javascript-test', terminal.text)
                terminal.send('details')
                terminal.expect('Reviewed dependency inputs', 5)
                terminal.send(reply)
                terminal.wait(lambda: terminal.exited, 10)
            finally:
                terminal.close()
            if reply == 'reject':
                self.assertFalse((self.repo / '.ptw').exists())
            for path, content in original.items():
                self.assertEqual((self.repo / path).read_bytes(), content)
        policy = load(self.repo / '.ptw/policy.json')
        commands = {c['id']: c for c in policy['project']['commands']}
        self.assertEqual(commands['javascript-test']['cwd'], 'frontend')
        self.assertEqual(commands['python-syntax']['cwd'], 'backend')
        self.assertEqual(policy['project']['python_runtime']['requires_python'], '>=3.10,<4')

    def test_actual_uv_resolver_backtracks_compatible_transitive_versions(self):
        # Real installed uv over local wheel metadata. The transport seam removes
        # network and isolates its cache. This is tooling feasibility, not native
        # application confinement or live advisory evidence.
        wheelhouse = self.root / 'wheels'
        wheelhouse.mkdir()
        for name, version, requires in [('parent', '1.0', ['demo>=1,<3']), ('demo', '1.0', []), ('demo', '2.0', [])]:
            (wheelhouse / (name + '-' + version + '-py3-none-any.whl')).write_bytes(wheel_bytes(name, version, requires))

        def offline(argv, **kwargs):
            argv = list(argv)
            position = argv.index('--index-url')
            argv[position:position + 2] = ['--no-index', '--find-links', str(wheelhouse)]
            self.calls.append(argv)
            return subprocess.run(argv, **kwargs)
        result = self.resolve('parent==1.0', provider=self.provider(bad={('demo', '2.0')}), runner=offline)
        self.assertEqual(result['pins'], ['demo==1.0', 'parent==1.0'])
        self.assertEqual(len(self.calls), 2)


class NativeLockTests(unittest.TestCase):
    setUp = ProductEcosystemTests.setUp

    def test_actual_uv_locked_export_and_stale_manifest(self):
        manifest = self.repo / 'pyproject.toml'
        manifest.write_text('[project]\nname="sample"\nversion="1.0"\nrequires-python=">=3.11"\ndependencies=[]\n')
        import shutil
        uv = shutil.which('uv')
        proc = subprocess.run([uv, '--no-config', '--no-python-downloads', '--offline', 'lock'],
            cwd=self.repo, env=resolver_environment(self.root), capture_output=True, text=True, timeout=15)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        original = (self.repo / 'uv.lock').read_bytes()

        def offline(argv, **kwargs):
            return subprocess.run([argv[0], '--offline', *argv[1:]], **kwargs)

        result = resolve_python(self.repo, self.root / 'export', RULES, runner=offline)
        self.assertEqual(result['pins'], [])
        self.assertEqual(result['authority'], 'uv.lock')
        self.assertEqual((self.repo / 'uv.lock').read_bytes(), original)
        self.assertEqual(result['inputs']['uv.lock'], hashlib.sha256(original).hexdigest())
        manifest.write_text(manifest.read_text().replace('dependencies=[]', 'dependencies=["idna==3.10"]'))
        with self.assertRaisesRegex(ResolutionError, 'lock check/export failed'):
            resolve_python(self.repo, self.root / 'stale', RULES, runner=offline)
        self.assertEqual((self.repo / 'uv.lock').read_bytes(), original)

    def test_locked_hash_identity_age_and_cvss(self):
        from ptw.python_lock import export_lock
        (self.repo / 'pyproject.toml').write_text('[project]\nname="sample"\nversion="1"\ndependencies=["demo==1.0"]')
        (self.repo / 'uv.lock').write_text('version=1\n[[package]]\nname="demo"\nversion="1.0"\nsource={registry="https://pypi.org/simple"}\n')
        provider = FixtureProvider()
        record = provider.assess('demo', '1.0')

        def exporter(argv, **kwargs):
            self.assertIn('--locked', argv)
            self.assertIn('--no-build', argv)
            self.assertNotIn('--frozen', argv)
            Path(argv[argv.index('--output-file') + 1]).write_text('demo==1.0 --hash=sha256:' + record['sha256'] + '\n')
            return SimpleNamespace(returncode=0)

        result = export_lock(self.repo, self.root / 'allowed', RULES, provider=provider, runner=exporter)
        self.assertEqual(result['pins'], ['demo==1.0'])
        bad = FixtureProvider({'demo': {'vulnerabilities': [CRITICAL]}})
        with self.assertRaisesRegex(ResolutionError, 'Frozen lock contains a forbidden'):
            export_lock(self.repo, self.root / 'bad', RULES, provider=bad, runner=exporter)
        record['sha256'] = '0' * 64
        with self.assertRaisesRegex(EvidenceError, 'digest differs'):
            export_lock(self.repo, self.root / 'digest', RULES, provider=provider, runner=exporter)

    def test_dynamic_root_is_rejected_before_native_backend_execution(self):
        from ptw.python_lock import export_lock
        (self.repo / 'pyproject.toml').write_text('[project]\nname="sample"\ndynamic=["version"]\n'
            '[build-system]\nrequires=[]\nbuild-backend="malicious"\nbackend-path=["."]\n')
        (self.repo / 'uv.lock').write_text('version=1\n')
        with self.assertRaisesRegex(Invalid, 'offline source preparation'):
            export_lock(self.repo, self.root / 'dynamic', RULES,
                runner=lambda *a, **k: self.fail('Native backend must not be reached'))


class NpmResolutionTests(unittest.TestCase):
    setUp = ProductEcosystemTests.setUp

    def fixture(self):
        from test_ecosystems import NpmFixture
        self.versions = {v: NpmFixture(version=v) for v in ('1.0.0', '2.0.0')}
        self.views = []
        owner = self

        class View:
            def __init__(self, provider, excluded, deadline):
                self.error = None
                owner.views.append(set(excluded))

            def __enter__(self):
                return 'http://127.0.0.1:1/synthetic-test-only/'

            def __exit__(self, *args):
                pass

        self.view = View
        (self.repo / 'package.json').write_text(json.dumps({'dependencies': {'demo': '>=1 <3'}}))

    def run_resolution(self, graphs, bad=(), **kwargs):
        from ptw.npm_resolution import resolve_npm
        graphs = iter(graphs)

        def run(argv, **options):
            self.calls.append((argv, options))
            graph = next(graphs)
            if graph is None:
                return SimpleNamespace(returncode=1, stderr='npm error code ETARGET')
            lock = copy.deepcopy(self.versions[graph].lock)
            lock['packages'][''] = load(self.repo / 'package.json')
            (Path(options['cwd']) / 'package-lock.json').write_text(json.dumps(lock))
            return SimpleNamespace(returncode=0, stderr='')

        def assess(name, version):
            result = self.versions[version].assess(name, version)
            if version in bad:
                result['vulnerabilities'] = [CRITICAL]
            return result

        return resolve_npm(self.repo, self.root / ('attempt-' + str(len(self.views))), RULES,
            runner=run, provider=SimpleNamespace(assess=assess), view_factory=self.view, **kwargs)

    def test_npm_critical_newest_uses_original_ranges_and_exclusions(self):
        self.fixture()
        result = self.run_resolution(['2.0.0', '1.0.0'], bad={'2.0.0'})
        self.assertEqual(result['lock']['packages']['node_modules/demo']['version'], '1.0.0')
        self.assertEqual(self.views, [set(), {('demo', '2.0.0')}])
        self.assertEqual(load(self.repo / 'package.json')['dependencies']['demo'], '>=1 <3')
        for argv, opts in self.calls:
            self.assertTrue(any(a.startswith('--before=') for a in argv))
            self.assertIn('--ignore-scripts', argv)
            self.assertNotIn('NPM_TOKEN', opts['env'])
            self.assertNotIn('overrides', load(Path(opts['cwd']) / 'package.json'))

    def test_npm_exact_pin_conflict_and_frozen_lock(self):
        self.fixture()
        (self.repo / 'package.json').write_text('{"dependencies":{"demo":"2.0.0"}}')
        with self.assertRaises(ResolutionError) as raised:
            self.run_resolution(['2.0.0', None], bad={'2.0.0'})
        self.assertEqual(raised.exception.outcome, 'unsatisfiable')
        (self.repo / 'package-lock.json').write_text(json.dumps(self.versions['2.0.0'].lock))
        with self.assertRaisesRegex(ResolutionError, 'Frozen npm lock'):
            self.run_resolution([], bad={'2.0.0'})

    def test_npm_evidence_failure_and_budget_do_not_become_safe(self):
        self.fixture()
        self.versions['2.0.0'].record['vulnerabilities'] = None
        with self.assertRaises(EvidenceError):
            self.run_resolution(['2.0.0'])
        self.versions['2.0.0'].record['vulnerabilities'] = [CRITICAL]
        with self.assertRaises(ResolutionError) as raised:
            self.run_resolution(['2.0.0'], max_rounds=1)
        self.assertEqual(raised.exception.outcome, 'budget_exhausted')

    def test_npm_binds_inputs_lock_and_artifact_origin(self):
        from ptw.dependency_binding import verify_npm
        self.fixture()
        result = self.run_resolution(['1.0.0'])
        bundle = {'policy': {'project': {'npm_dependencies': {'inputs': result['inputs'],
            'lock_sha256': digest(result['lock']), 'artifacts': result['artifacts']}}},
            'inventory': {'root': str(self.repo)}}
        verify_inputs(bundle)
        verify_npm(bundle, result['lock'], result['artifacts'])
        changed = copy.deepcopy(result['lock'])
        changed['packages']['node_modules/demo']['integrity'] = 'sha512-forged'
        with self.assertRaisesRegex(Invalid, 'reviewed npm lock'):
            verify_npm(bundle, changed)
        with self.assertRaisesRegex(Invalid, 'origin or integrity'):
            verify_npm(bundle, result['lock'], [{**result['artifacts'][0], 'url': 'https://other.invalid/demo'}])
        (self.repo / 'package.json').write_text('{}')
        with self.assertRaisesRegex(Invalid, 'input changed'):
            verify_inputs(bundle)


class WorkspaceSourceTests(unittest.TestCase):
    setUp = ProductEcosystemTests.setUp

    def workspace(self):
        from ptw.policy import save
        save(self.repo / 'package.json', {'name': 'root', 'version': '1.0.0', 'private': True,
            'workspaces': ['packages/*'], 'dependencies': {'@fixture/math': '*'}})
        save(self.repo / 'packages/math/package.json', {'name': '@fixture/math', 'version': '1.0.0',
            'type': 'module', 'exports': './src/index.js'})
        (self.repo / 'packages/math/src').mkdir()
        (self.repo / 'packages/math/src/index.js').write_text('export const value = 42;\n')
        import shutil
        proc = subprocess.run([shutil.which('npm'), 'install', '--offline', '--package-lock-only',
            '--ignore-scripts', '--no-audit', '--no-fund', '--userconfig=/dev/null',
            '--globalconfig=' + str(self.root / 'empty-global'), '--cache=' + str(self.root / 'cache')],
            cwd=self.repo, env=resolver_environment(self.root), capture_output=True, text=True, timeout=15)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return load(self.repo / 'package-lock.json')

    def test_native_npm_workspace_lock_is_local_not_registry(self):
        from ptw.npm import NpmPlan
        from ptw.npm_resolution import resolve_npm
        lock = self.workspace()
        plan = NpmPlan(lock)
        self.assertEqual(plan.selected, {})
        self.assertEqual(plan.links, {'node_modules/@fixture/math': 'packages/math'})
        provider = SimpleNamespace(assess=lambda *a: self.fail('local source was assessed as registry'))
        result = resolve_npm(self.repo, self.root / 'resolution', RULES, provider=provider)
        self.assertEqual(result['artifacts'], [])
        self.assertEqual(result['sources'], ['packages/math'])
        self.assertIn('packages/math/package.json', result['inputs'])

    def test_workspace_setup_stages_nested_metadata_before_review(self):
        self.workspace()
        directory = self.root / 'setup-operator'
        directory.mkdir()
        args = SimpleNamespace(language='javascript', goal='Review local workspace source',
            editable='packages/math/src', files='', warn_at=None, stop_at=None,
            history=None, model_proposal=False)
        with patch('ptw.codex.require_login'), patch('ptw.monitor.ensure'), patch('ptw.onboarding.ensure'), \
                patch('sys.stdin.isatty', return_value=True), patch('builtins.input', return_value='yes'):
            record = onboarding.setup(self.repo, directory, args)
        bundle = load(record['bundle'])
        descriptor = bundle['policy']['project']['npm_dependencies']
        self.assertEqual(descriptor['sources'][0]['path'], 'packages/math')
        self.assertIn('packages/math/package.json', descriptor['inputs'])
        self.assertTrue(next(directory.glob('setup-*/metadata/packages/math/package.json')).is_file())

    def test_local_source_requires_descriptor_and_command_session_closure(self):
        from ptw.dependency_binding import verify_npm, verify_local_sources
        lock = self.workspace()
        bundle = {'policy': {'project': {}}}
        with self.assertRaisesRegex(Invalid, 'approved source descriptor'):
            verify_npm(bundle, lock)
        bundle['policy']['project']['npm_dependencies'] = {'lock_sha256': digest(lock), 'artifacts': [],
            'sources': [{'path': 'packages/math', 'resources': ['manifest', 'source']}], 'root': ''}
        verify_npm(bundle, lock, [])
        actor = {'grants': json.dumps([{'resource': key, 'actions': ['read']} for key in ('manifest', 'source')])}
        verify_local_sources(bundle, actor, {'resources': ['manifest', 'source']})
        with self.assertRaisesRegex(Invalid, 'command inputs'):
            verify_local_sources(bundle, actor, {'resources': ['manifest']})
        actor['grants'] = json.dumps([{'resource': 'manifest', 'actions': ['read']}])
        with self.assertRaisesRegex(Invalid, 'session read grants'):
            verify_local_sources(bundle, actor)

    def test_workspace_path_link_and_manifest_mutation_rejected(self):
        from ptw.npm_resolution import node_inputs, resolve_npm
        lock = self.workspace()
        manifest = self.repo / 'packages/math/package.json'
        manifest.write_text(manifest.read_text().replace('1.0.0', '2.0.0'))
        with self.assertRaisesRegex(Invalid, 'manifest and lock disagree'):
            resolve_npm(self.repo, self.root / 'stale', RULES)
        (self.repo / 'packages/linked').symlink_to(self.root)
        with self.assertRaises(Invalid):
            node_inputs(self.repo)
        from ptw.npm import NpmPlan
        lock['packages']['node_modules/@fixture/math']['resolved'] = '../../outside'
        with self.assertRaisesRegex(Invalid, 'in-project source'):
            NpmPlan(lock)

    def test_sibling_file_dependency_and_origin_confusion(self):
        from ptw.npm_resolution import node_inputs
        from ptw.npm import NpmPlan
        self.workspace()
        path = self.repo / 'packages/client'
        path.mkdir()
        (path / 'package.json').write_text(json.dumps({'name': 'client', 'version': '1.0.0',
            'dependencies': {'@fixture/math': 'file:../math'}}))
        manifests, inputs = node_inputs(self.repo)
        self.assertIn('packages/math', manifests)
        self.assertIn('packages/client/package.json', inputs)
        lock = load(self.repo / 'package-lock.json')
        lock['packages']['packages/client'] = manifests['packages/client']
        lock['packages']['node_modules/client'] = {'link': True, 'resolved': 'packages/client'}
        NpmPlan(lock)
        # Same version/name is insufficient: file: binds the exact local path.
        lock['packages']['packages/other'] = copy.deepcopy(lock['packages']['packages/math'])
        lock['packages']['node_modules/@fixture/math']['resolved'] = 'packages/other'
        with self.assertRaisesRegex(Invalid, 'different source identity'):
            NpmPlan(lock)
        (path / 'package.json').write_text(json.dumps({'dependencies': {'escape': 'file:../../../outside'}}))
        with self.assertRaisesRegex(Invalid, 'escapes project root'):
            node_inputs(self.repo)

    def test_file_source_parent_symlink_cannot_read_external_metadata(self):
        from ptw.npm_resolution import node_inputs
        (self.root / 'outside').mkdir()
        (self.root / 'outside/package.json').write_text('{"name":"outside","version":"1.0.0"}')
        (self.repo / 'link').symlink_to(self.root / 'outside', target_is_directory=True)
        (self.repo / 'package.json').write_text('{"dependencies":{"outside":"file:link"}}')
        with self.assertRaises((Invalid, OSError)):
            node_inputs(self.repo)

    def test_narrower_command_selects_only_its_complete_source_resources(self):
        from ptw.dependency_binding import verify_local_sources
        sources = [{'path': 'packages/frontend', 'resources': ['front-meta', 'front-src']},
                   {'path': 'packages/backend', 'resources': ['back-meta', 'back-src']}]
        bundle = {'policy': {'project': {'npm_dependencies': {'sources': sources}}}}
        actor = {'grants': json.dumps([{'resource': r, 'actions': ['read']}
                                     for r in sources[0]['resources']])}
        selected = verify_local_sources(bundle, actor, {'resources': sources[0]['resources']})
        self.assertEqual(selected['sources'], sources[:1])
        self.assertEqual(selected['excluded_sources'], ['packages/backend'])
        with self.assertRaisesRegex(Invalid, 'command inputs'):
            verify_local_sources(bundle, actor, {'resources': ['front-src']})
        with self.assertRaisesRegex(Invalid, 'session read grants'):
            verify_local_sources(bundle, actor, {'resources': sources[1]['resources']})

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires actual Linux confinement')
    def test_native_narrower_workspace_import_and_excluded_source(self):
        from ptw.policy import save
        from ptw.packages import PackageControl
        from ptw.monitor import ensure, remove
        from ptw.supervisor import Supervisor
        from ptw.workflow import dispatch
        from ptw.workspace import request
        lock = self.workspace()
        save(self.repo / 'packages/backend/package.json', {'name': 'backend', 'version': '1.0.0'})
        (self.repo / 'packages/backend/src').mkdir()
        hidden = self.repo / 'packages/backend/src/private.cjs'
        hidden.write_text("module.exports='UNRELATED_BACKEND_SOURCE';\n")
        lock['packages']['packages/backend'] = {'name': 'backend', 'version': '1.0.0'}
        lock['packages']['node_modules/backend'] = {'link': True, 'resolved': 'packages/backend'}
        files = ['package.json', 'packages/math/package.json', 'packages/backend/package.json']
        front = ['packages/math/package.json', 'packages/math/src']
        code = ("import {value} from '@fixture/math'; import fs from 'node:fs'; "
            "if(fs.existsSync('/node-packages/packages/backend/package.json') || "
            "fs.existsSync('/node-packages/packages/backend/src/private.cjs') || "
            "fs.existsSync('/node-packages/package-lock.json') || "
            "fs.existsSync('/node-packages/node_modules/.package-lock.json')) throw Error('source exposed'); console.log('VALUE='+value)")
        policy, inv = template(self.repo, 'narrow-workspace', 'Use frontend source only',
            {'packages/math/src': 'tree', 'packages/backend/src': 'tree'}, files,
            [{'id': 'test', 'argv': ['/usr/bin/node', '--input-type=module', '-e', code],
              'resources': front, 'cwd': 'packages/math', 'timeout_seconds': 15}], [], 1, 3)
        mapping = {v['path']: k for k, v in inv['resources'].items()}
        from ptw.workspace import scan, stamp
        sources = []
        for path in ('packages/math', 'packages/backend'):
            resources = [mapping[path + '/package.json'], mapping[path + '/src']]
            snapshot = scan(inv, resources)
            sources.append({'path': path, 'resources': resources,
                'snapshot_sha256': digest({p: [stamp(e), e.get('mode')] for p, e in snapshot.items()})})
        policy['project']['npm_dependencies'] = {'inputs': {}, 'lock_sha256': digest(lock),
            'artifacts': [], 'sources': sources, 'root': ''}
        store = Store(self.root / 'narrow-controller')
        store.activate(approve(policy, inv, digest(compile_policy(policy, inv)), 'synthetic fixture operator'))
        unrelated = subprocess.Popen(['/usr/bin/sleep', '90'])
        try:
            ensure(store)
            parent = store.register('narrow-workspace', 'work')
            installed = PackageControl(store).install(parent['token'], 'local-install', lock, ecosystem='npm')
            self.assertTrue(installed.get('allowed'), installed)
            child = store.register('narrow-workspace', 'work', parent_token=parent['token'],
                grants=[{'resource': mapping[p], 'actions': ['read']} for p in front])
            for index, value in enumerate((42, 43)):
                if index:
                    current = dispatch(store, parent, 'read-local', request('read',
                        mapping['packages/math/src'], 'index.js'))
                    self.assertTrue(current.get('allowed'), current)
                    changed = dispatch(store, parent, 'edit-local', request('write', mapping['packages/math/src'],
                        'index.js', content='export const value = 43;\n', expected=current['sha256']))
                    self.assertTrue(changed.get('allowed'), changed)
                result = dispatch(store, child, 'import-' + str(index), request('run', 'test',
                    content=json.dumps({'package_sets': [installed['package_set']]})))
                self.assertTrue(result.get('allowed'), result)
                self.assertEqual(result.get('exit_code'), 0, result)
                self.assertIn('VALUE=' + str(value), result['output'])
            self.assertEqual(hidden.read_text(), "module.exports='UNRELATED_BACKEND_SOURCE';\n")
            store.stop('narrow-workspace')
            Supervisor(store).reconcile()
            self.assertIsNone(unrelated.poll())
        finally:
            store.stop('narrow-workspace')
            Supervisor(store).reconcile()
            remove(store)
            unrelated.terminate()
            unrelated.wait(timeout=5)


class PrivateRegistryTests(unittest.TestCase):
    setUp = ProductEcosystemTests.setUp

    def provider(self, registry='https://private.invalid', *, fixture=False):
        from ptw.policy import save
        from ptw.registry import RoutedNpmEvidence
        credential = self.root / ('credential-' + str(len(list(self.root.glob('credential-*')))) + '.json')
        save(credential, {'authorization': 'Bearer SYNTHETIC_PRIVATE_FIXTURE_TOKEN'})
        config = {'version': 1, 'packages': {'demo': {'registry': registry, 'advisories': registry,
            'credential_ref': str(credential)}}}
        return RoutedNpmEvidence(config, fixture=fixture), config

    def test_private_credentials_are_only_on_scoped_broker_requests(self):
        import io
        from test_ecosystems import NpmFixture
        fixture = NpmFixture()
        provider, config = self.provider()
        url = 'https://private.invalid/demo/-/demo-1.0.0.tgz'
        document = {'versions': {'1.0.0': {'name': 'demo', 'version': '1.0.0',
            'dist': {'tarball': url, 'integrity': fixture.record['integrity']}}},
            'time': {'1.0.0': '2020-01-01T00:00:00Z'}}
        seen = []

        def opened(request, **kwargs):
            seen.append(request)
            self.assertEqual(request.get_header('Authorization'), 'Bearer SYNTHETIC_PRIVATE_FIXTURE_TOKEN')
            self.assertNotIn('SYNTHETIC_PRIVATE_FIXTURE_TOKEN', request.full_url)
            if request.full_url.endswith('/v1/query'):
                body = {'origin': 'https://private.invalid', 'name': 'demo', 'version': '1.0.0', 'coverage': 'complete', 'vulns': []}
            elif request.full_url == url:
                return io.BytesIO(fixture.raw)
            else:
                body = document
            return io.BytesIO(json.dumps(body).encode())

        with patch.object(provider.http, 'open', side_effect=opened):
            record = provider.assess('demo', '1.0.0')
            provider.download(record, self.root / 'download.tgz')
        self.assertEqual(len(seen), 3)
        self.assertEqual((self.root / 'download.tgz').read_bytes(), fixture.raw)
        self.assertNotIn('SYNTHETIC_PRIVATE_FIXTURE_TOKEN', json.dumps([record, config, resolver_environment(self.root)]))
        self.assertFalse(provider.artifact_allowed(fixture.record['url'], 'demo'))

    def test_private_missing_coverage_wrong_origin_echo_and_errors_fail_closed(self):
        import io
        provider, _ = self.provider()
        for response in ({'vulns': []}, {'origin': 'https://registry.npmjs.org', 'name': 'demo', 'version': '1',
                'coverage': 'complete', 'vulns': []}, {'echo': 'SYNTHETIC_PRIVATE_FIXTURE_TOKEN'}):
            with patch.object(provider.http, 'open', return_value=io.BytesIO(json.dumps(response).encode())):
                with self.assertRaises(EvidenceError) as raised:
                    provider.advisories('npm', 'demo', '1')
                self.assertNotIn('SYNTHETIC_PRIVATE_FIXTURE_TOKEN', str(raised.exception))
        with patch.object(provider.http, 'open', side_effect=OSError('SYNTHETIC_PRIVATE_FIXTURE_TOKEN')):
            with self.assertRaises(EvidenceError) as raised:
                provider.packument('demo')
            self.assertNotIn('SYNTHETIC_PRIVATE_FIXTURE_TOKEN', str(raised.exception))

    def test_credential_reference_cannot_be_project_source(self):
        from ptw.registry import outside_repository
        _, config = self.provider()
        outside_repository(config, self.repo)
        config['packages']['demo']['credential_ref'] = str(self.repo / 'src/token.json')
        with self.assertRaisesRegex(Invalid, 'outside project source'):
            outside_repository(config, self.repo)

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'local authenticated fixture requires native checks')
    def test_local_authenticated_fixture_install_build_and_wrong_credentials(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        import threading
        from test_ecosystems import NpmFixture
        fixture = NpmFixture(fields={'scripts': {'postinstall': 'node build.cjs'}}, files={
            'package/build.cjs': b"const fs=require('fs'); if(Object.values(process.env).some(v=>v.includes('SYNTHETIC_PRIVATE_'))) throw Error('credential leak'); fs.writeFileSync('built.json',JSON.stringify({answer:42}));",
            'package/index.js': b"module.exports=require('./built.json').answer;\n"})
        seen = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                seen.append(self.headers.get('Authorization'))
                if seen[-1] != 'Bearer SYNTHETIC_PRIVATE_FIXTURE_TOKEN':
                    self.send_error(401)
                    return
                if self.path.endswith('.tgz'):
                    raw = fixture.raw
                else:
                    raw = json.dumps({'versions': {'1.0.0': {'name': 'demo', 'version': '1.0.0',
                        'dist': {'tarball': endpoint + '/demo.tgz', 'integrity': fixture.record['integrity']}}},
                        'time': {'1.0.0': '2020-01-01T00:00:00Z'}}).encode()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                seen.append(self.headers.get('Authorization'))
                if seen[-1] != 'Bearer SYNTHETIC_PRIVATE_FIXTURE_TOKEN':
                    self.send_error(401)
                    return
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps({'origin': endpoint, 'name': 'demo', 'version': '1.0.0',
                    'coverage': 'complete', 'vulns': []}).encode())

        server = HTTPServer(('127.0.0.1', 0), Handler)
        endpoint = 'http://127.0.0.1:' + str(server.server_port)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            provider, _ = self.provider(endpoint, fixture=True)
            record = provider.assess('demo', '1.0.0')
            provider.download(record, self.root / 'authenticated.tgz')
            self.assertEqual((self.root / 'authenticated.tgz').read_bytes(), fixture.raw)
            self.assertEqual(len(seen), 3)
            # Exercise the actual broker -> checked archive -> supervised offline
            # install -> explicit lifecycle -> protected import path.
            from ptw.packages import PackageControl
            from ptw.monitor import ensure, remove
            from ptw.supervisor import Supervisor
            from ptw.workflow import dispatch
            from ptw.workspace import request
            from ptw.policy import save
            (self.repo / 'src').mkdir()
            (self.repo / 'src/app.cjs').write_text("if(require('demo')!==42) process.exit(1); console.log('PRIVATE_IMPORT_OK');\n")
            policy, inv = template(self.repo, 'private-native', 'Import checked private build', {'src': 'tree'}, [],
                [{'id': 'test', 'argv': ['/usr/bin/node', 'src/app.cjs'], 'resources': ['src'], 'timeout_seconds': 15}],
                ['npm:demo'], 1, 3)
            policy['project']['packages']['build_packages'] = ['npm:demo']
            lock = copy.deepcopy(fixture.lock)
            lock['packages']['node_modules/demo']['resolved'] = record['url']
            policy['project']['npm_dependencies'] = {'inputs': {}, 'lock_sha256': digest(lock),
                'artifacts': [{k: record[k] for k in ('name', 'version', 'url', 'integrity')}]}
            store = Store(self.root / 'private-controller')
            store.activate(approve(policy, inv, digest(compile_policy(policy, inv)), 'synthetic fixture operator'))
            try:
                ensure(store)
                actor = store.register('private-native', 'work')
                installed = PackageControl(store, provider=provider).install(actor['token'], 'private-install', lock, ecosystem='npm')
                self.assertTrue(installed.get('allowed'), installed)
                package = store.directory / 'package-sets' / installed['package_set']
                self.assertEqual(load(package / 'node_modules/demo/built.json'), {'answer': 42})
                result = dispatch(store, actor, 'private-import', request('run', 'test',
                    content=json.dumps({'package_sets': [installed['package_set']]})))
                self.assertTrue(result.get('allowed'), result)
                self.assertEqual(result.get('exit_code'), 0, result)
                self.assertIn('PRIVATE_IMPORT_OK', result['output'])
                self.assertNotIn('SYNTHETIC_PRIVATE_FIXTURE_TOKEN', json.dumps([installed, result]))
                for path in package.rglob('*'):
                    if path.is_file():
                        self.assertNotIn(b'SYNTHETIC_PRIVATE_FIXTURE_TOKEN', path.read_bytes())
                save(self.root / 'private-effects.json', {'built': True, 'imported': True,
                    'credential_absent_from_package_and_responses': True})
            finally:
                store.stop('private-native')
                Supervisor(store).reconcile()
                remove(store)
            provider.routes['demo']['authorization'] = 'Bearer INVALID_SYNTHETIC_TOKEN'
            with self.assertRaises(EvidenceError):
                provider.assess('demo', '1.0.0')
            self.assertNotIn('SYNTHETIC_PRIVATE_FIXTURE_TOKEN', json.dumps(record))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


class PrivatePythonTests(unittest.TestCase):
    setUp = ProductEcosystemTests.setUp

    def provider(self, endpoint='https://private.invalid', *, fixture=False):
        from ptw.registry import RoutedPyPIEvidence
        from ptw.policy import save
        credential = self.root / 'synthetic-credential.json'
        if not credential.exists():
            save(credential, {'authorization': 'Bearer SYNTHETIC_PYTHON_TOKEN'})
        config = {'version': 1, 'packages': {'demo': {'registry': endpoint, 'advisories': endpoint,
            'credential_ref': str(credential)}}}
        return RoutedPyPIEvidence(config, fixture=fixture), config

    def document(self, endpoint='https://private.invalid'):
        raw = wheel_bytes('demo', '1.0')
        item = {'filename': 'demo-1.0-py3-none-any.whl', 'url': endpoint + '/files/demo.whl',
            'digests': {'sha256': hashlib.sha256(raw).hexdigest()}, 'size': len(raw),
            'packagetype': 'bdist_wheel', 'yanked': False, 'upload_time_iso_8601': '2020-01-01T00:00:00Z',
            'requires_python': '>=3.8'}
        return {'info': {'name': 'demo', 'version': '1.0'}, 'urls': [item], 'releases': {'1.0': [item]}}, raw

    def index_document(self, endpoint='https://private.invalid'):
        release, raw = self.document(endpoint)
        item = release['urls'][0]
        return {'meta': {'api-version': '1.1'}, 'name': 'demo', 'files': [{
            'filename': item['filename'], 'url': item['url'], 'hashes': item['digests'],
            'size': len(raw), 'upload-time': item['upload_time_iso_8601'],
            'requires-python': item['requires_python'], 'yanked': False}]}, raw

    def test_private_python_assessment_download_and_origin(self):
        import io
        provider, config = self.provider()
        document, raw = self.document()
        seen = []

        def opened(request, **kwargs):
            seen.append(request)
            self.assertEqual(request.get_header('Authorization'), 'Bearer SYNTHETIC_PYTHON_TOKEN')
            if request.full_url.endswith('/v1/query'):
                self.assertEqual(json.loads(request.data)['package']['ecosystem'], 'PyPI')
                body = {'origin': 'https://private.invalid', 'name': 'demo', 'version': '1.0',
                    'coverage': 'complete', 'vulns': []}
            elif request.full_url.endswith('.whl'):
                return io.BytesIO(raw)
            else:
                body = document
            return io.BytesIO(json.dumps(body).encode())

        with patch.object(provider.http, 'open', side_effect=opened):
            record = provider.assess('demo', '1.0')
            provider.download(record, self.root / 'checked.whl')
        self.assertEqual(record['origin'], 'https://private.invalid')
        self.assertEqual((self.root / 'checked.whl').read_bytes(), raw)
        self.assertEqual(len(seen), 3)
        self.assertNotIn('SYNTHETIC_PYTHON_TOKEN', json.dumps([record, config]))
        self.assertFalse(provider.artifact_allowed('https://files.pythonhosted.org/demo.whl', 'demo'))
        for url in ('https://user:secret@private.invalid/demo.whl', 'https://private.invalid/demo.whl?token=x',
                    'https://elsewhere.invalid/demo.whl'):
            with self.subTest(url=url):
                self.assertFalse(provider.artifact_allowed(url, 'demo'))

    def test_private_python_coverage_and_credential_echo_fail_closed(self):
        import io
        provider, _ = self.provider()
        for response in ({'vulns': []}, {'origin': 'https://pypi.org', 'name': 'demo', 'version': '1.0',
                'coverage': 'complete', 'vulns': []}, {'echo': 'SYNTHETIC_PYTHON_TOKEN'}):
            with patch.object(provider.http, 'open', return_value=io.BytesIO(json.dumps(response).encode())):
                with self.assertRaises(EvidenceError) as error:
                    provider.advisories('PyPI', 'demo', '1.0')
                self.assertNotIn('SYNTHETIC_PYTHON_TOKEN', str(error.exception))
        with patch.object(provider.http, 'open', side_effect=OSError('SYNTHETIC_PYTHON_TOKEN')):
            with self.assertRaises(EvidenceError) as error:
                provider.release('demo')
            self.assertNotIn('SYNTHETIC_PYTHON_TOKEN', str(error.exception))

    def test_python_index_relative_links_and_source_archives(self):
        import io
        from ptw.python_index import WheelIndex
        provider, _ = self.provider()
        document, _ = self.index_document()
        document['files'][0]['url'] = '../../files/demo.whl'
        document['files'].append({'filename': 'demo-2.0.tar.gz', 'url': '/files/demo.tar.gz'})
        with patch.object(provider.http, 'open', return_value=io.BytesIO(json.dumps(document).encode())) as opened:
            result = provider.index('demo')
        req = opened.call_args.args[0]
        self.assertEqual(req.get_header('Accept'), 'application/vnd.pypi.simple.v1+json')
        self.assertEqual(req.get_header('Authorization'), 'Bearer SYNTHETIC_PYTHON_TOKEN')
        self.assertEqual(result['files'][0]['url'], 'https://private.invalid/files/demo.whl')
        view = WheelIndex(provider, self.root, time.monotonic() + 30)
        with patch.object(provider, 'index', return_value=result):
            self.assertEqual(len(view.document('demo')['files']), 1)

    def test_python_wheel_view_preserves_runtime_hash_age_and_checks_bytes(self):
        from ptw.python_index import WheelIndex
        provider, _ = self.provider()
        document, raw = self.index_document()
        view = WheelIndex(provider, self.root, time.monotonic() + 30)
        with patch.object(provider, 'index', return_value=document):
            result = view.document('demo')
        entry = result['files'][0]
        self.assertEqual(entry['requires-python'], '>=3.8')
        self.assertEqual(entry['upload-time'], '2020-01-01T00:00:00Z')
        self.assertEqual(entry['hashes']['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertNotIn('private.invalid', json.dumps(result))
        self.assertNotIn('SYNTHETIC_PYTHON_TOKEN', json.dumps(result))
        key = next(iter(view.artifacts))
        with patch.object(provider, 'download', side_effect=lambda record, path: path.write_bytes(raw)):
            self.assertEqual(view.artifact(key, entry['filename']), raw)
        (self.root / key).write_bytes(b'tampered')
        with self.assertRaisesRegex(EvidenceError, 'changed'):
            view.artifact(key, entry['filename'])
        with self.assertRaisesRegex(EvidenceError, 'Unknown'):
            view.artifact(key, 'different.whl')
        view.deadline = time.monotonic() - 1
        with self.assertRaisesRegex(EvidenceError, 'budget'):
            view.document('demo')

    def test_python_view_rejects_malformed_metadata_and_unapproved_origin(self):
        from ptw.python_index import WheelIndex
        provider, _ = self.provider()
        original, _ = self.index_document()
        for field, value in (('url', 'https://files.pythonhosted.org/demo.whl'), ('filename', '../bad.whl'),
                             ('hashes', {}), ('size', -1), ('upload-time', None)):
            with self.subTest(field=field):
                document = copy.deepcopy(original)
                document['files'][0][field] = value
                view = WheelIndex(provider, self.root, time.monotonic() + 30)
                with patch.object(provider, 'index', return_value=document), self.assertRaises(EvidenceError):
                    view.document('demo')

    def test_python_private_config_bound_in_provider_and_no_native_lock_fallback(self):
        from ptw.registry import provider_for
        from ptw.policy import save
        _, config = self.provider()
        store = Store(self.root / 'state')
        identity = digest(config)
        bundle = {'inventory': {'root': str(self.repo)}, 'policy': {'project': {'packages': RULES,
            'python_dependencies': {'registry_config_sha256': identity}}}}
        save(store.directory / ('pypi-registry-' + identity + '.json'), config)
        self.assertEqual(provider_for(store, bundle, 'pypi').routes['demo']['registry'], 'https://private.invalid')
        (store.directory / ('pypi-registry-' + identity + '.json')).write_text('{}')
        with self.assertRaisesRegex(EvidenceError, 'differs'):
            provider_for(store, bundle, 'pypi')
        (self.repo / 'uv.lock').write_text('version=1\n')
        with patch('ptw.dependency_resolution.run_metadata') as run, self.assertRaisesRegex(Invalid, 'Private Python native locks'):
            resolve_python(self.repo, self.root / 'lock-attempt', RULES, registry_config=config)
        run.assert_not_called()

    def test_python_registry_setup_reviews_hash_and_stores_only_external_reference(self):
        from contextlib import redirect_stdout
        import io
        from ptw.policy import save
        _, config = self.provider()
        config_path = self.root / 'routes.json'
        save(config_path, config)
        (self.repo / 'requirements.in').write_text('demo==1.0\n')
        (self.repo / 'src').mkdir()
        directory = self.root / 'operator'
        directory.mkdir()
        record = FixtureProvider().assess('demo', '1.0')
        plan = {'pins': ['demo==1.0'], 'runtime': select(),
            'inputs': {'requirements.in': hashlib.sha256((self.repo / 'requirements.in').read_bytes()).hexdigest()},
            'artifacts': [{k: record[k] for k in ('name', 'version', 'url', 'sha256')}]}
        args = SimpleNamespace(language='python', goal='Private wheel import', editable='src', files='',
            warn_at=None, stop_at=None, history=None, model_proposal=False, python_registry_config=str(config_path))
        transcript = io.StringIO()
        with patch('ptw.codex.require_login'), patch('ptw.monitor.ensure'), patch('ptw.onboarding.ensure'), \
                patch('sys.stdin.isatty', return_value=True), patch('builtins.input', return_value='yes'), \
                patch('ptw.dependency_resolution.resolve_python', return_value=plan) as resolve, redirect_stdout(transcript):
            registration = onboarding.setup(self.repo, directory, args)
        self.assertEqual(resolve.call_args.kwargs['registry_config'], config)
        bundle = load(registration['bundle'])
        identity = bundle['policy']['project']['python_dependencies']['registry_config_sha256']
        self.assertEqual(identity, digest(config))
        self.assertEqual(load(Path(registration['state']) / ('pypi-registry-' + identity + '.json')), config)
        self.assertNotIn('SYNTHETIC_PYTHON_TOKEN', transcript.getvalue() + json.dumps(bundle))
        self.assertNotIn(str(self.root / 'synthetic-credential.json'), json.dumps(bundle))

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires authenticated HTTP and native confinement')
    def test_native_private_python_resolution_install_import_and_bad_credentials(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        import threading
        from ptw.packages import PackageControl
        from ptw.monitor import ensure, remove
        from ptw.supervisor import Supervisor
        from ptw.workflow import dispatch
        from ptw.workspace import request
        seen = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def respond(self, raw):
                seen.append((self.path, self.headers.get('Authorization')))
                if seen[-1][1] != 'Bearer SYNTHETIC_PYTHON_TOKEN':
                    self.send_error(401)
                    return
                self.send_response(200)
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                self.respond(raw if self.path.endswith('.whl') else
                    json.dumps(index_document if self.path.startswith('/simple/') else document).encode())

            def do_POST(self):
                self.respond(json.dumps({'origin': endpoint, 'name': 'demo', 'version': '1.0',
                    'coverage': 'complete', 'vulns': []}).encode())

        server = HTTPServer(('127.0.0.1', 0), Handler)
        endpoint = 'http://127.0.0.1:' + str(server.server_port)
        document, raw = self.document(endpoint)
        index_document, _ = self.index_document(endpoint)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            provider, _ = self.provider(endpoint, fixture=True)
            (self.repo / 'requirements.in').write_text('demo>=1,<2\n')
            result = resolve_python(self.repo, self.root / 'resolution', RULES, provider=provider)
            self.assertEqual(result['pins'], ['demo==1.0'])
            (self.repo / 'src').mkdir()
            (self.repo / 'src/app.py').write_text("import demo, os; assert not any('SYNTHETIC_PYTHON_TOKEN' in v for v in os.environ.values()); print('PRIVATE_PYTHON_OK')\n")
            policy, inv = template(self.repo, 'private-python', 'Import authenticated wheel', {'src': 'tree'},
                ['requirements.in'], [{'id': 'test', 'argv': [result['runtime']['executable'], 'src/app.py'],
                'resources': ['src'], 'timeout_seconds': 15}], ['pypi:demo'], 1, 3)
            policy['project']['python_runtime'] = result['runtime']
            policy['project']['python_dependencies'] = {k: result[k] for k in ('inputs', 'pins', 'artifacts')}
            store = Store(self.root / 'controller')
            store.activate(approve(policy, inv, digest(compile_policy(policy, inv)), 'synthetic fixture operator'))
            try:
                ensure(store)
                actor = store.register('private-python', 'work')
                installed = PackageControl(store, provider=provider).install(actor['token'], 'install', result['pins'])
                self.assertTrue(installed.get('allowed'), installed)
                effect = dispatch(store, actor, 'import', request('run', 'test',
                    content=json.dumps({'package_sets': [installed['package_set']]})))
                self.assertTrue(effect.get('allowed'), effect)
                self.assertEqual(effect.get('exit_code'), 0, effect)
                self.assertIn('PRIVATE_PYTHON_OK', effect['output'])
                self.assertNotIn('SYNTHETIC_PYTHON_TOKEN', json.dumps([installed, effect, result]))
                for folder in (self.root / 'resolution', store.directory / 'package-sets'):
                    for path in folder.rglob('*'):
                        if path.is_file():
                            self.assertNotIn(b'SYNTHETIC_PYTHON_TOKEN', path.read_bytes())
            finally:
                store.stop('private-python')
                Supervisor(store).reconcile()
                remove(store)
            provider.routes['demo']['authorization'] = 'Bearer INVALID_SYNTHETIC_TOKEN'
            with self.assertRaises(EvidenceError):
                provider.assess('demo', '1.0')
            self.assertTrue(seen)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


class DependencyRevisionTests(unittest.TestCase):
    setUp = ProductEcosystemTests.setUp

    def activated(self, extra_package=False):
        from ptw.policy import save
        (self.repo / 'src').mkdir()
        (self.repo / 'src/app.py').write_text('VALUE = 42\n')
        (self.repo / 'requirements.txt').write_text('demo==1.0\n')
        (self.repo / 'ptw-requirements.txt').write_text('demo==1.0\n')
        (self.repo / '.ptw').mkdir()
        with patch.dict(os.environ, {'PTW_USER_STATE': str(self.root / 'operator')}):
            directory = onboarding.private_directory(self.repo)
        policy, inv = template(self.repo, 'revision-project', 'Review dependencies', {'src': 'tree'},
            ['requirements.txt', 'ptw-requirements.txt'], [], ['pypi:demo'], 1, 3)
        record = FixtureProvider().assess('demo', '1.0')
        policy['project']['python_runtime'] = select()
        policy['project']['python_dependencies'] = {'pins': ['demo==1.0'],
            'inputs': {p: hashlib.sha256((self.repo / p).read_bytes()).hexdigest()
                       for p in ('requirements.txt', 'ptw-requirements.txt')},
            'artifacts': [{k: record[k] for k in ('name', 'version', 'url', 'sha256')}]}
        # Preserve custom security settings, not template defaults.
        policy['project']['packages']['min_release_age_days'] = 20
        if extra_package:
            policy['project']['packages']['allowed_names'].append('pypi:unrelated')
            policy['tasks'][0]['packages'].append('pypi:unrelated')
        bundle = approve(policy, inv, digest(compile_policy(policy, inv)), 'synthetic test operator')
        save(directory / 'approved.json', bundle)
        save(self.repo / '.ptw/policy.json', policy)
        store = Store(directory / 'controller')
        store.activate(bundle)
        registration = {'project': policy['project']['id'], 'repo': str(self.repo), 'state': str(store.directory),
            'bundle': str(directory / 'approved.json'), 'policy_sha256': bundle['approval']['sha256'], 'task': 'work',
            'language': 'python', 'publication_sha256': 'synthetic-no-setup-publication'}
        save(directory / 'project.json', registration)
        session = store.register(registration['project'], 'work')
        from ptw.workspace import Workspace, request
        denied = Workspace(store).request(session['token'], 'retained-violation', request('read', 'missing'))
        self.assertFalse(denied['allowed'])
        return directory, store, session, bundle, registration

    def remove(self, **patches):
        from ptw.dependency_revision import start
        args = SimpleNamespace(repo=str(self.repo), root='', ecosystem='pypi', task='work',
            source='requirements.txt', operation='remove', specs=['demo'], group=None)
        with patch.dict(os.environ, {'PTW_USER_STATE': str(self.root / 'operator')}), \
                patch('ptw.onboarding.ask', return_value='yes'):
            return start(args)

    def test_remove_preserves_project_counters_thresholds_and_revokes_old_sessions(self):
        directory, store, session, bundle, registration = self.activated()
        result = self.remove()
        self.assertEqual(result['project'], registration['project'])
        status = store.status(result['project'])
        self.assertEqual(status['violations'], 1)
        self.assertFalse(status['stopped'])
        with store.locked() as db:
            _, current = store.project(db, result['project'])
            with self.assertRaisesRegex(Invalid, 'Session ended'):
                store.session(db, session['token'])
        self.assertEqual(current['policy']['project']['packages']['min_release_age_days'], 20)
        self.assertEqual(current['policy']['project']['grants'], bundle['policy']['project']['grants'])
        self.assertEqual(current['policy']['project']['python_dependencies']['pins'], [])
        self.assertEqual((self.repo / 'requirements.txt').read_text(), '')
        self.assertEqual((self.repo / 'src/app.py').read_text(), 'VALUE = 42\n')
        from ptw.setup_transaction import validate_registration
        validate_registration(load(directory / 'project.json'))
        self.assertEqual(len(store.audit_events(result['project'])), 1)
        self.assertTrue(store.register(result['project'], 'work')['token'])

    def test_failed_publication_rolls_back_without_reopening_sessions(self):
        from ptw import dependency_revision as revision
        directory, store, session, bundle, _ = self.activated()
        original = revision.move
        calls = []

        def fail_once(source, destination):
            calls.append(str(destination))
            if len(calls) == 3:
                raise OSError('synthetic interrupted rename')
            return original(source, destination)

        with patch.object(revision, 'move', side_effect=fail_once):
            with self.assertRaisesRegex(OSError, 'interrupted rename'):
                self.remove()
        self.assertEqual((self.repo / 'requirements.txt').read_text(), 'demo==1.0\n')
        self.assertEqual((self.repo / 'ptw-requirements.txt').read_text(), 'demo==1.0\n')
        with store.locked() as db:
            row, current = store.project(db, 'revision-project')
            self.assertEqual(current, bundle)
            self.assertFalse(row['setup_pending'])
            self.assertEqual(row['violations'], 1)
            with self.assertRaises(Invalid):
                store.session(db, session['token'])
        self.assertEqual(load(directory / 'dependency-journal.json')['phase'], 'rolled-back')

    def test_revision_preserves_unrelated_package_authority(self):
        _, store, _, _, _ = self.activated(extra_package=True)
        self.remove()
        with store.locked() as db:
            _, bundle = store.project(db, 'revision-project')
        self.assertEqual(bundle['policy']['project']['packages']['allowed_names'], ['pypi:unrelated'])
        self.assertIn('pypi:unrelated', bundle['policy']['tasks'][0]['packages'])
        self.assertEqual(store.status('revision-project')['violations'], 1)

    def test_stop_during_publication_survives_rollback(self):
        from ptw import dependency_revision as revision
        _, store, _, _, _ = self.activated()
        original = revision.atomic

        def stopped(path, journal):
            original(path, journal)
            if journal.get('phase') == 'publishing':
                store.stop('revision-project', 'synthetic concurrent operator stop')

        with patch.object(revision, 'atomic', side_effect=stopped), self.assertRaisesRegex(Invalid, 'Stop or concurrent'):
            self.remove()
        self.assertTrue(store.status('revision-project')['stopped'])
        self.assertEqual(store.status('revision-project')['violations'], 1)
        self.assertEqual((self.repo / 'requirements.txt').read_text(), 'demo==1.0\n')

    def test_requirement_edits_keep_unrelated_lines_and_require_explicit_update(self):
        from ptw.dependency_revision import edit_requirements
        original = '# Keep this explanation\ndemo==1.0\nother>=2 # local comment\n'
        self.assertEqual(edit_requirements(original, 'update', ['demo>=1,<2']),
            '# Keep this explanation\ndemo>=1,<2\nother>=2 # local comment\n')
        with self.assertRaises(Invalid):
            edit_requirements(original, 'update', ['demo'])
        with self.assertRaises(Invalid):
            edit_requirements(original, 'add', ['demo==2'])
        with self.assertRaises(Invalid):
            edit_requirements(original, 'remove', ['absent'])

    def test_native_pep621_edits_preserve_comments_runtime_and_other_groups(self):
        from ptw.python_revision import edit_project
        import tomllib
        manifest = self.repo / 'pyproject.toml'
        manifest.write_text('# retained explanation\n[project]\nname="sample"\nversion="1"\n'
            'requires-python=">=3.11"\ndependencies=["demo==1.0"]\n'
            '[project.optional-dependencies]\nweb=["other>=1"]\n'
            '[dependency-groups]\ntest=["pytest==8.0.0"]\n')
        for operation, specs, group in [('update', ['demo>=1,<3'], None),
                ('add', ['new-package==1'], 'extra:web'), ('remove', ['pytest'], 'test')]:
            edit_project(self.repo, operation, specs, group=group, python=select()['executable'], runner=subprocess.run)
        document = tomllib.loads(manifest.read_text())
        self.assertIn('# retained explanation', manifest.read_text())
        self.assertEqual(document['project']['requires-python'], '>=3.11')
        self.assertEqual(document['project']['dependencies'], ['demo>=1,<3'])
        self.assertEqual(set(document['project']['optional-dependencies']['web']), {'other>=1', 'new-package==1'})
        self.assertEqual(document['dependency-groups']['test'], [])
        self.assertFalse((self.repo / 'uv.lock').exists())
        self.assertFalse((self.repo / '.venv').exists())
        original = manifest.read_bytes()
        with self.assertRaises(Invalid):
            edit_project(self.repo, 'update', ['demo'], python=select()['executable'], runner=subprocess.run)
        self.assertEqual(manifest.read_bytes(), original)

    def test_uv_update_excludes_critical_version_without_changing_declarations(self):
        from ptw.python_revision import update_uv_lock
        manifest = '[project]\nname="sample"\nversion="1"\nrequires-python=">=3.11"\ndependencies=["demo>=1,<3"]\n'
        (self.repo / 'pyproject.toml').write_text(manifest)
        (self.repo / 'uv.lock').write_text('version=1\n')
        provider = FixtureProvider()
        attempts = []
        chosen = ['2.0']

        def run(argv, **kwargs):
            folder = Path(kwargs['cwd'])
            if 'add' in argv:
                constraints = (folder / 'constraints.txt').read_text()
                attempts.append(constraints)
                self.assertEqual((folder / 'empty.txt').read_text(), '')
                self.assertNotIn('--override', argv)
                chosen[0] = '1.0' if 'demo!=2.0' in constraints else '2.0'
                (folder / 'uv.lock').write_text('version=1\n[[package]]\nname="demo"\nversion="' +
                    chosen[0] + '"\nsource={registry="https://pypi.org/simple"}\n')
            else:
                record = provider.assess('demo', chosen[0])
                Path(argv[argv.index('--output-file') + 1]).write_text('demo==' + chosen[0] +
                    ' --hash=sha256:' + record['sha256'] + '\n')
            return SimpleNamespace(returncode=0, stderr='')

        def assess(name, version):
            record = provider.assess(name, version)
            if version == '2.0':
                record['vulnerabilities'] = [CRITICAL]
            return record

        result = update_uv_lock(self.repo, self.root / 'update', RULES, executable=select()['executable'],
            runner=run, provider=SimpleNamespace(assess=assess), upgrade=['demo'])
        self.assertEqual(result['pins'], ['demo==1.0'])
        self.assertEqual(attempts, ['', 'demo!=2.0\n'])
        self.assertEqual((self.repo / 'pyproject.toml').read_text(), manifest)
        self.assertEqual((self.repo / 'uv.lock').read_text(), 'version=1\n')
        self.assertEqual(load(self.root / 'update/resolution.json')['outcome'], 'resolved')

    def test_native_uv_constraint_only_update_can_downgrade(self):
        import shutil
        # Actual uv interface feasibility, using only generated wheel metadata.
        # This is not a protected install or live advisory measurement.
        wheels = self.root / 'wheels'
        wheels.mkdir()
        for version in ('1.0', '2.0'):
            (wheels / ('demo-' + version + '-py3-none-any.whl')).write_bytes(wheel_bytes('demo', version))
        (self.repo / 'pyproject.toml').write_text('[project]\nname="sample"\nversion="1"\n'
            'requires-python=">=3.11"\ndependencies=["demo>=1,<3"]\n')
        (self.repo / 'empty.txt').write_text('')
        constraint = self.repo / 'constraints.txt'
        common = [shutil.which('uv'), '--no-config', '--offline', '--no-python-downloads', 'add',
            '--no-sync', '--raw', '--no-build', '--no-index', '--find-links', str(wheels),
            '--constraints', str(constraint), '--requirements', str(self.repo / 'empty.txt'), '--upgrade-package', 'demo']
        import tomllib
        for exclusion, version in [('', '2.0'), ('demo!=2.0\n', '1.0')]:
            constraint.write_text(exclusion)
            proc = subprocess.run(common, cwd=self.repo, env=resolver_environment(self.root),
                capture_output=True, text=True, timeout=15)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            locked = tomllib.loads((self.repo / 'uv.lock').read_text())
            self.assertEqual(next(p['version'] for p in locked['package'] if p['name'] == 'demo'), version)
        manifest = self.repo / 'pyproject.toml'
        manifest.write_text(manifest.read_text().replace('demo>=1,<3', 'demo==2.0'))
        proc = subprocess.run(common, cwd=self.repo, env=resolver_environment(self.root),
            capture_output=True, text=True, timeout=15)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn('No solution found', proc.stderr)
        self.assertIn('demo==2.0', manifest.read_text())

    def test_dependency_review_real_pty_rejection_and_approval(self):
        from test_product_onboarding import Terminal
        directory, store, _, _, _ = self.activated()
        for index, reply in enumerate(('reject', 'yes')):
            terminal = Terminal([sys.executable, '-B', '-m', 'ptw', 'deps', 'remove', 'demo',
                '--repo', str(self.repo), '--ecosystem', 'pypi', '--source', 'requirements.txt'],
                self.root / ('dependency-terminal-' + str(index)), env={'PTW_USER_STATE': str(self.root / 'operator')})
            try:
                terminal.expect('Approve dependency revision?', 15)
                terminal.send('details')
                terminal.expect('Approve exactly this dependency revision?', 5)
                terminal.send(reply)
                terminal.wait(lambda: terminal.exited, 10)
            finally:
                terminal.close()
            self.assertEqual(store.status('revision-project')['violations'], 1)
            self.assertEqual((self.repo / 'requirements.txt').read_text(), 'demo==1.0\n' if reply == 'reject' else '')
        self.assertEqual(load(directory / 'project.json')['project'], 'revision-project')


if __name__ == '__main__':
    unittest.main()
