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

    def test_unimplemented_native_locks_are_not_silently_discarded(self):
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

    def test_stale_npm_lock_and_unimplemented_imports_are_rejected(self):
        from test_ecosystems import NpmFixture
        fixture = NpmFixture()
        (self.repo / 'package.json').write_text(json.dumps({'dependencies': {'demo': '^2'}}))
        (self.repo / 'package-lock.json').write_text(json.dumps(fixture.lock))
        with self.assertRaisesRegex(Invalid, 'disagree'):
            onboarding.resolve_npm(self.repo, self.root)
        (self.repo / 'package-lock.json').unlink()
        (self.repo / 'pnpm-lock.yaml').write_text('lockfileVersion: 9')
        with self.assertRaisesRegex(Invalid, 'authoritative lock'):
            onboarding.resolve_npm(self.repo, self.root)

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


if __name__ == '__main__':
    unittest.main()
