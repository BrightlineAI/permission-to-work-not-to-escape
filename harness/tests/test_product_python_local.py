"""Local preparation milestone. Native effects require the manager's Linux runner."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from contextlib import ExitStack

from ptw.package_evidence import EvidenceError
from ptw.policy import Invalid, approve, compile_policy, digest, load
from ptw.python_local import authorized_snapshot, build_wheel, describe_source, install_editable, install_wheel
from ptw.python_runtime import identify
from ptw.setup_templates import template
from ptw.store import Store
from test_packages import CRITICAL, FixtureProvider, wheel_bytes
from ptw.registry import RoutedPyPIEvidence


class HookIndexFixture(FixtureProvider, RoutedPyPIEvidence):
    """Synthetic evidence and real local WheelIndex transport for native uv."""
    def __init__(self, **kwargs):
        FixtureProvider.__init__(self)

    def assess(self, name, version):
        if name != 'builder' or version != '1.0':
            raise EvidenceError('Unknown synthetic hook dependency')
        return super().assess(name, version)

    def artifact_allowed(self, url, name):
        return name == 'builder' and url == 'https://files.pythonhosted.org/synthetic'

    def index(self, name):
        record = self.assess(name, '1.0')
        return {'meta': {'api-version': '1.1'}, 'name': name, 'files': [{
            'filename': record['filename'], 'url': record['url'],
            'hashes': {'sha256': record['sha256']}, 'size': len(wheel_bytes(name, '1.0')),
            'upload-time': record['published_at'], 'yanked': False}]}


BACKEND = r'''
import base64,hashlib,os,pathlib,zipfile
def get_requires_for_build_wheel(config_settings=None):
    return []
def build_wheel(wheel_directory, config_settings=None, metadata_directory=None, editable=False):
    assert not any('SYNTHETIC_LOCAL_INJECTION' in v for v in os.environ.values())
    for target in HOST_PATHS:
        try:
            pathlib.Path(target).read_bytes()
        except OSError:
            pass
        else:
            raise RuntimeError('unapproved host read succeeded')
        try:
            pathlib.Path(target).write_text('changed')
        except OSError:
            pass
        else:
            raise RuntimeError('unapproved host write succeeded')
    files = {
        'local_demo/__init__.py': pathlib.Path('src/local_demo/__init__.py').read_bytes(),
        'local_demo-1.0.dist-info/METADATA': b'Metadata-Version: 2.1\nName: local-demo\nVersion: 1.0\n\n',
        'local_demo-1.0.dist-info/WHEEL': b'Wheel-Version: 1.0\nGenerator: fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n',
    }
    if editable:
        del files['local_demo/__init__.py']
        files['local_demo.pth'] = str(pathlib.Path('src').resolve()).encode() + b'\n'
    record = ''.join(n + ',sha256=' + base64.urlsafe_b64encode(hashlib.sha256(b).digest()).decode().rstrip('=')
                     + ',' + str(len(b)) + '\n' for n,b in files.items())
    files['local_demo-1.0.dist-info/RECORD'] = (record + 'local_demo-1.0.dist-info/RECORD,,\n').encode()
    name = 'local_demo-1.0-py3-none-any.whl'
    with zipfile.ZipFile(pathlib.Path(wheel_directory) / name, 'w') as wheel:
        for n,b in files.items():
            wheel.writestr(n,b)
    return name
get_requires_for_build_editable = get_requires_for_build_wheel
def build_editable(wheel_directory, config_settings=None, metadata_directory=None):
    return build_wheel(wheel_directory, config_settings, metadata_directory, editable=True)
'''


def native_library_project(fixture, *, editable=False):
    """Real compiler input; compilation occurs only inside the supervised backend."""
    # Debian's cc alias traverses /etc/alternatives, outside runtime_namespace.
    # Bind the concrete system tool into the reviewed fixture, never mount /etc
    # or inherit CC/PATH from the operator environment to make the build work.
    compiler = Path('/usr/bin/cc').resolve(strict=True)
    if not compiler.is_relative_to('/usr') or not compiler.is_file():
        raise RuntimeError('Native fixture requires a system C compiler under /usr')
    (fixture.repo / 'src/local_demo/value.c').write_text('int local_value(void) { return 42; }\n')
    (fixture.repo / 'src/local_demo/__init__.py').write_text(
        'import ctypes,pathlib\n'
        'VALUE = ctypes.CDLL(str(pathlib.Path(__file__).with_name("value.so"))).local_value()\n')
    backend = fixture.repo / 'backend/backend.py'
    backend.write_text(backend.read_text().replace(
        '    files = {',
        '    import subprocess\n'
        '    subprocess.run([' + repr(str(compiler)) + ',"-shared","-fPIC","src/local_demo/value.c",'
        '"-o","value.so"],check=True)\n    files = {\n'
        '        "local_demo/value.so": pathlib.Path("value.so").read_bytes(),')
        .replace('Root-Is-Purelib: true', 'Root-Is-Purelib: false')
        .replace('py3-none-any', 'py3-none-linux_x86_64'))
    if editable:
        backend.write_text(backend.read_text().replace(
            '    if editable:', '    if editable:\n'
            '        pathlib.Path("src/local_demo/value.so").write_bytes(files.pop("local_demo/value.so"))'))


class LocalSetupTests(unittest.TestCase):
    """Exercise the actual setup transaction; native tests replace only login."""
    def setUp(self):
        LocalPythonTests.setUp(self)
        (self.repo / 'tests').mkdir()
        (self.repo / 'tests/test_import.py').write_text(
            'import unittest,local_demo,importlib.metadata as m,json\n'
            'class ImportTest(unittest.TestCase):\n'
            ' def test_import(self):\n'
            '  self.assertEqual(m.version("local-demo"), "1.0")\n'
            '  self.assertTrue(json.loads(m.distribution("local-demo").read_text("direct_url.json"))["dir_info"]["editable"])\n'
            '  self.assertTrue(local_demo.__file__.startswith("/target/src/"))\n'
            '  print("EDITABLE_VALUE",local_demo.VALUE)\n')
        self.state = self.root / 'operator'
        self.state.mkdir()

    def setup(self, **options):
        from ptw.onboarding import setup
        from test_product_onboarding import args
        return setup(self.repo, self.state, args(self.repo, **{
            'editable': 'src,backend,tests', 'python_editable': 'src', **options}))

    def offline(self):
        stack = self.enterContext(ExitStack())
        stack.enter_context(patch('ptw.codex.require_login'))
        stack.enter_context(patch('sys.stdin.isatty', return_value=True))
        stack.enter_context(patch('builtins.input', return_value='yes'))
        stack.enter_context(patch('builtins.print'))
        stack.enter_context(patch('ptw.monitor.ensure'))
        stack.enter_context(patch('ptw.supervisor.Supervisor.reconcile', return_value=[]))
        return stack

    def fake_build(self, store, token, command, target, **kwargs):
        self.assertTrue(kwargs.get('preparation'))
        with store.locked() as db:
            actor = store.session(db, token, preparation=True)
            self.assertTrue(db.execute('SELECT setup_pending FROM projects WHERE id=?', (actor['project'],)).fetchone()[0])
            self.assertEqual(actor['preparation_source'], 'python-project')
        with self.assertRaisesRegex(Invalid, 'pending recovery'):
            store.register(actor['project'], 'work')
        LocalPythonTests.fake_editable(self, store, token, command, target)

    def test_setup_approves_prepares_closes_and_exposes_scoped_receipt(self):
        self.offline()
        from ptw.python_local import prepared_sets
        with patch('ptw.python_local.run_build', side_effect=self.fake_build) as run:
            record = self.setup()
        run.assert_called_once()
        store = Store(record['state'])
        actor = store.register(record['project'], 'work')
        receipts = prepared_sets(store, actor['token'])
        self.assertEqual(len(receipts), 1)
        self.assertIn('test', receipts[0]['commands'])
        from ptw.mcp_server import Adapter
        from ptw.policy import save
        session_file = self.root / 'session.json'
        save(session_file, actor)
        with patch('ptw.mcp_server.health', return_value={'healthy': True}):
            context = Adapter(store.directory, session_file).context()
        self.assertEqual(context['prepared_package_sets'], receipts)
        self.assertNotIn(actor['token'], json.dumps(context))
        self.assertEqual(load(self.state / 'setup-journal.json')['phase'], 'committed')
        bundle = load(record['bundle'])
        source = bundle['policy']['project']['python_dependencies']['sources'][0]
        self.assertNotIn('unrelated.txt', [bundle['inventory']['resources'][r]['path'] for r in source['resources']])
        mutable = source['editable_resources']
        child = store.register(record['project'], 'work', parent_token=actor['token'], commands=[],
                               grants=[{'resource': mutable[0], 'actions': ['read']}])
        self.assertEqual(prepared_sets(store, child['token']), [])
        with store.locked() as db:
            self.assertFalse(db.execute('SELECT 1 FROM sessions WHERE preparation_source IS NOT NULL AND closed=0').fetchone())

    def test_root_requirements_setup_binds_includes_and_denies_mutation(self):
        self.offline()
        (self.repo / 'requirements.in').write_text('-r requirements-local.txt\n')
        included = self.repo / 'requirements-local.txt'
        included.write_text('-e .\n')
        with patch('ptw.python_local.run_build', side_effect=self.fake_build) as run:
            record = self.setup(python_source='requirements.in')
        run.assert_called_once()
        bundle = load(record['bundle'])
        descriptor = bundle['policy']['project']['python_dependencies']
        self.assertEqual(descriptor['pins'], [])
        self.assertEqual(descriptor['sources'][0]['mode'], 'editable')
        self.assertEqual(descriptor['inputs']['requirements-local.txt'],
                         hashlib.sha256(included.read_bytes()).hexdigest())
        self.assertEqual(load(Path(record['bundle']).parent / 'python-options.json')['local_mode'], 'editable')
        from ptw.dependency_binding import verify_inputs
        verify_inputs(bundle)
        included.write_text('-e ../outside\n')
        with self.assertRaises(Invalid):
            verify_inputs(bundle)

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_cli_root_editable_requirement_review_build_and_import(self):
        (self.repo / 'requirements.in').write_text('-r requirements-local.txt\n')
        (self.repo / 'requirements-local.txt').write_text('-e .\n')
        self.native_cli_flow(editable=True, requirements=True)

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_cli_root_wheel_requirement_review_build_and_import(self):
        (self.repo / 'requirements.in').write_text('.\n')
        path = self.repo / 'tests/test_import.py'
        path.write_text(path.read_text().replace(
            'self.assertTrue(json.loads(m.distribution("local-demo").read_text("direct_url.json"))["dir_info"]["editable"])',
            'self.assertIn("archive_info",json.loads(m.distribution("local-demo").read_text("direct_url.json")))')
            .replace('startswith("/target/src/")', 'startswith("/python-packages/")'))
        self.native_cli_flow(editable=False, requirements=True)

    def test_wheel_setup_retains_source_binding_and_build_receipt(self):
        self.offline()
        from ptw.python_local import prepared_sets
        def build(store, token, command, target, **kwargs):
            self.assertTrue(kwargs.get('preparation'))
            LocalPythonTests.fake_build(self, store, token, command, target)
        with patch('ptw.python_local.run_build', side_effect=build), \
                patch('ptw.python_local.install_wheels', side_effect=LocalPythonTests.fake_wheel_install):
            record = self.setup(python_editable=None, python_wheel=True)
        bundle = load(record['bundle'])
        source = bundle['policy']['project']['python_dependencies']['sources'][0]
        self.assertEqual(source['mode'], 'wheel')
        self.assertNotIn('editable_resources', source)
        store = Store(record['state'])
        actor = store.register(record['project'], 'work')
        receipt = prepared_sets(store, actor['token'])[0]
        with store.locked() as db:
            row = db.execute('SELECT * FROM package_sets WHERE id=?', (receipt['package_set'],)).fetchone()
        self.assertEqual(json.loads(row['names']), [])
        self.assertEqual(json.loads(row['local_source'])['wheel']['source_sha256'], source['snapshot_sha256'])
        self.assertEqual(load(self.state / 'setup-journal.json')['phase'], 'committed')
        # Argparse's default False must not be mistaken for a policy revision.
        from ptw.cli import main
        with patch('ptw.onboarding.private_directory', return_value=self.state), \
                patch('ptw.onboarding.ensure'), patch('ptw.python_local.run_build') as build:
            self.assertIsNone(main(['codex', '--repo', str(self.repo), '--setup-only']))
            build.assert_not_called()
        with patch('sys.stderr'), self.assertRaises(SystemExit) as error:
            main(['codex', '--python-wheel', '--python-editable', 'src'])
        self.assertEqual(error.exception.code, 2)

    def test_native_wheel_setup_is_explicit_and_bound_to_review(self):
        self.offline()
        def build(store, token, command, target, **kwargs):
            LocalPythonTests.fake_build(self, store, token, command, target)
        with patch('ptw.python_local.run_build', side_effect=build), \
                patch('ptw.python_local.install_wheels', side_effect=LocalPythonTests.fake_wheel_install):
            record = self.setup(python_editable=None, python_wheel=True, python_native_wheels=True)
        bundle = load(record['bundle'])
        self.assertTrue(bundle['policy']['project']['packages']['allow_native_wheels'])
        from ptw.onboarding import short_review
        self.assertIn('native wheels True', short_review(bundle, {}, []))
        from ptw.cli import main
        with patch('ptw.onboarding.private_directory', return_value=self.state), \
                patch('sys.stderr'), self.assertRaises(SystemExit) as error:
            main(['codex', '--repo', str(self.repo), '--python-native-wheels', '--setup-only'])
        self.assertEqual(error.exception.code, 2)

    def test_native_flag_without_local_mode_never_runs_backend(self):
        self.offline()
        with patch('ptw.python_local.run_build') as build, self.assertRaisesRegex(Invalid, 'requires --python-wheel'):
            self.setup(python_editable=None, python_native_wheels=True)
        build.assert_not_called()
        self.assertFalse((self.repo / '.ptw').exists())

    def test_native_editable_setup_requires_visible_policy_review(self):
        self.offline()
        with patch('ptw.python_local.run_build', side_effect=self.fake_build):
            record = self.setup(python_native_wheels=True)
        bundle = load(record['bundle'])
        self.assertTrue(bundle['policy']['project']['packages']['allow_native_wheels'])
        self.assertEqual(bundle['policy']['project']['python_dependencies']['sources'][0]['mode'], 'editable')

    def test_cli_setup_only_revision_review_failure_and_retry(self):
        self.offline()
        from ptw.cli import main
        from ptw.python_local import prepared_sets
        with patch('ptw.python_local.run_build', side_effect=self.fake_build):
            original = self.setup(python_native_wheels=True)
        store = Store(original['state'])
        actor = store.register(original['project'], 'work')
        original_policy = (self.repo / '.ptw/policy.json').read_bytes()
        argv = ['codex', '--repo', str(self.repo), '--revise', '--setup-only',
                '--goal', 'Rebuild explicitly reviewed source', '--language', 'python',
                '--editable', 'src,backend,tests', '--files', '',
                '--python-editable', 'src', '--python-native-wheels']
        with patch('ptw.onboarding.private_directory', return_value=self.state), \
                patch('ptw.onboarding.ensure'), patch('sys.stderr'):
            for reply in ('reject', 'cancel'):
                with self.subTest(reply=reply), patch('builtins.input', return_value=reply), \
                        patch('ptw.python_local.run_build') as build, self.assertRaises(SystemExit) as error:
                    main(argv)
                self.assertEqual(error.exception.code, 2)
                build.assert_not_called()
                self.assertEqual(load(self.state / 'project.json'), original)
                self.assertEqual((self.repo / '.ptw/policy.json').read_bytes(), original_policy)
                self.assertFalse(store.status(original['project'])['stopped'])
                self.assertEqual(len(prepared_sets(store, actor['token'])), 1)
            (self.repo / 'src/local_demo/__init__.py').write_text('VALUE = 99\n')
            with patch('ptw.python_local.run_build', side_effect=OSError('revision build failure')) as build, \
                    self.assertRaises(SystemExit) as error:
                main(argv)
            self.assertEqual(error.exception.code, 2)
            build.assert_called_once()
            self.assertEqual(load(self.state / 'project.json'), original)
            self.assertEqual((self.repo / '.ptw/policy.json').read_bytes(), original_policy)
            self.assertTrue(store.status(original['project'])['stopped'])
            failed = load(self.state / 'setup-journal.json')['record']['project']
            self.assertTrue(store.status(failed)['stopped'])
            with patch('ptw.python_local.run_build', side_effect=self.fake_build) as build:
                main(argv)
            build.assert_called_once()
        revised = load(self.state / 'project.json')
        self.assertNotIn(revised['project'], (original['project'], failed))
        self.assertTrue(store.status(original['project'])['stopped'])
        self.assertTrue(store.status(failed)['stopped'])
        self.assertEqual(store.status(original['project'])['violations'], 0)
        self.assertEqual(load(self.state / 'setup-journal.json')['phase'], 'committed')
        revised_actor = store.register(revised['project'], 'work')
        self.assertEqual(len(prepared_sets(store, revised_actor['token'])), 1)
        self.assertTrue(load(revised['bundle'])['policy']['project']['packages']['allow_native_wheels'])

    def test_cli_setup_only_preserves_conflicting_operation_denials(self):
        from ptw.cli import main
        for operation in ('--status', '--stop', '--review'):
            for other in ('--setup-only', '--revise'):
                with self.subTest(operation=operation, other=other), patch('sys.stderr'), \
                        patch('ptw.onboarding.start') as start, self.assertRaises(SystemExit) as error:
                    main(['codex', operation, other])
                self.assertEqual(error.exception.code, 2)
                start.assert_not_called()

    def test_setup_extra_selection_enters_source_approval(self):
        self.offline()
        metadata = self.repo / 'pyproject.toml'
        metadata.write_text(metadata.read_text() + '\n[project.optional-dependencies]\nfeature=[]\n')
        def build(store, token, command, target, **kwargs):
            self.fake_build(store, token, command, target, **kwargs)
            info = next((target / '.ptw-local-site').glob('*.dist-info'))
            (info / 'METADATA').write_text((info / 'METADATA').read_text() + 'Provides-Extra: feature\n')
        with patch('ptw.python_local.run_build', side_effect=build):
            record = self.setup(python_extras='Feature')
        bundle = load(record['bundle'])
        self.assertEqual(bundle['policy']['project']['python_dependencies']['sources'][0]['extras'], ['feature'])
        from ptw.onboarding import short_review
        self.assertIn('extras: feature', short_review(bundle, {}, []))

    def unknown_dynamic_project(self):
        metadata = self.repo / 'pyproject.toml'
        metadata.write_text(metadata.read_text().replace('version="1.0"', 'dynamic=["version", "dependencies"]'))

    def discovery_build(self, store, token, command, target, **kwargs):
        self.assertTrue(kwargs.get('preparation'))
        with store.locked() as db:
            actor = store.session(db, token, preparation=True)
            project, bundle = store.project(db, actor['project'])
            self.assertTrue(project['setup_pending'])
            self.assertEqual(actor['commands'], '[]')
            mode = bundle['policy']['project']['python_dependencies']['sources'][0]['mode']
        self.assertIn(mode, ('wheel', 'discovery'))
        from ptw.python_local import HOOK_REQUIREMENTS
        if HOOK_REQUIREMENTS in command:
            (target / 'requirements.json').write_text('[]')
            return
        LocalPythonTests.fake_build(self, store, token, command, target)

    def test_dynamic_setup_discovers_then_reviews_same_pending_identity(self):
        self.offline()
        self.unknown_dynamic_project()
        calls = []
        def reply(prompt):
            calls.append(prompt)
            if 'exactly' in prompt:
                store = Store(self.state / 'controller')
                identity = load(self.state / 'discovery-journal.json')['project']
                with self.assertRaisesRegex(Invalid, 'pending recovery'):
                    store.register(identity, 'work')
                with store.locked() as db:
                    self.assertEqual(db.execute('SELECT COUNT(*) FROM package_sets').fetchone()[0], 0)
                    db.execute('UPDATE projects SET violations=1 WHERE id=?', (identity,))
                    db.execute('UPDATE task_counts SET violations=1 WHERE project=? AND task=?', (identity, 'work'))
            return 'yes'
        with patch('builtins.input', side_effect=reply), \
                patch('ptw.python_local.run_build', side_effect=self.discovery_build) as build, \
                patch('ptw.python_local.install_wheels', side_effect=LocalPythonTests.fake_wheel_install):
            record = self.setup(python_editable=None, python_wheel=True)
        self.assertEqual(build.call_count, 3)
        self.assertEqual(len(calls), 2)
        self.assertIn('metadata discovery', calls[0])
        bundle = load(record['bundle'])
        stage = Path(record['bundle']).parent
        discovered = load(stage / 'discovery-approved.json')
        self.assertEqual(record['project'], discovered['policy']['project']['id'])
        self.assertNotIn('version', discovered['policy']['project']['python_dependencies']['sources'][0])
        source = bundle['policy']['project']['python_dependencies']['sources'][0]
        self.assertEqual(source['dynamic_metadata'], {'version': '1.0', 'dependencies': []})
        store = Store(record['state'])
        self.assertEqual(store.status(record['project'])['violations'], 1)
        from ptw.python_discovery import recover
        recover(self.state)
        self.assertFalse(store.status(record['project'])['stopped'])
        self.assertIsNotNone(store.register(record['project'], 'work'))

    def test_dynamic_setup_discovery_rejection_executes_nothing(self):
        self.offline()
        self.unknown_dynamic_project()
        for answer in ('reject', 'cancel', '', EOFError()):
            with self.subTest(answer=repr(answer)), patch('builtins.input', side_effect=[answer]), \
                    patch('ptw.python_local.run_build') as build:
                with self.assertRaises((Invalid, EOFError)):
                    self.setup(python_editable=None, python_wheel=True)
                build.assert_not_called()
                self.assertFalse((self.repo / '.ptw').exists())

    def test_requirements_dynamic_discovery_retains_authority_and_constraints(self):
        calls = self.hook_setup_fixture()
        (self.repo / 'requirements.in').write_text('-r requirements-local.txt\n-c constraints.txt\n')
        (self.repo / 'requirements-local.txt').write_text('.\n')
        (self.repo / 'constraints.txt').write_text('local-demo==1.0\nbuilder<2\n')
        record = self.setup(python_source='requirements.in', python_editable=None, python_wheel=True)
        self.assertEqual(calls, ['hook', 'wheel', 'wheel'])
        stage = Path(record['bundle']).parent
        initial = load(stage / 'discovery-approved.json')['policy']['project']['python_dependencies']
        final = load(record['bundle'])['policy']['project']['python_dependencies']
        self.assertEqual(final['authority'], 'requirements')
        self.assertEqual(final['pins'], ['builder==1.0'])
        self.assertEqual(final['sources'][0]['dynamic_metadata'], {'version': '1.0', 'dependencies': []})
        for name in ('requirements.in', 'requirements-local.txt', 'constraints.txt'):
            expected = hashlib.sha256((self.repo / name).read_bytes()).hexdigest()
            self.assertEqual(initial['inputs'][name], expected)
            self.assertEqual(final['inputs'][name], expected)
        self.assertEqual((stage / 'discovery-build-resolution/constraints.txt').read_text(), 'builder<2\n')

    def test_requirements_dynamic_incompatible_local_version_never_installs(self):
        calls = self.hook_setup_fixture(requirements=[])
        (self.repo / 'requirements.in').write_text('.\n-c constraints.txt\n')
        (self.repo / 'constraints.txt').write_text('local-demo==2\n')
        with patch('ptw.python_local.install_source') as install:
            with self.assertRaises(Invalid):
                self.setup(python_source='requirements.in', python_editable=None, python_wheel=True)
        install.assert_not_called()
        self.assertEqual(calls, ['hook', 'wheel'])
        self.assertFalse((self.repo / '.ptw').exists())

    def test_requirements_discovery_mutated_include_blocks_backend(self):
        calls = self.hook_setup_fixture(requirements=[])
        (self.repo / 'requirements.in').write_text('-r requirements-local.txt\n')
        included = self.repo / 'requirements-local.txt'
        included.write_text('.\n')
        def answer(prompt):
            self.assertIn('metadata discovery', prompt)
            included.write_text('.\nunapproved==1\n')
            return 'yes'
        with patch('builtins.input', side_effect=answer), self.assertRaises(Invalid):
            self.setup(python_source='requirements.in', python_editable=None, python_wheel=True)
        self.assertEqual(calls, [])
        self.assertFalse((self.repo / '.ptw').exists())
        self.assertIn('unapproved', included.read_text())

    def test_requirements_discovery_rejection_never_runs_hook(self):
        calls = self.hook_setup_fixture(requirements=[])
        (self.repo / 'requirements.in').write_text('.\n')
        for reply in ('reject', 'cancel', EOFError()):
            with self.subTest(reply=repr(reply)), patch('builtins.input', side_effect=[reply]):
                with self.assertRaises((Invalid, EOFError)):
                    self.setup(python_source='requirements.in', python_editable=None, python_wheel=True)
                self.assertEqual(calls, [])
                self.assertFalse((self.repo / '.ptw').exists())

    def hook_setup_fixture(self, requirements=None, *, dynamic=True, editable=False):
        """Test seams only for tools/evidence; real review, controller and journal."""
        self.offline()
        if dynamic:
            self.unknown_dynamic_project()
        from ptw.dependency_resolution import resolve_python
        from ptw.python_local import HOOK_REQUIREMENTS
        from types import SimpleNamespace
        requirements = ['builder>=1,<2'] if requirements is None else requirements
        calls = []
        def runner(argv, **kwargs):
            self.assertIn('builder', (Path(kwargs['cwd']) / 'requirements.in').read_text())
            Path(argv[argv.index('--output-file') + 1]).write_text('builder==1.0\n')
            return SimpleNamespace(returncode=0, stderr='')
        def resolve(*args, **kwargs):
            return resolve_python(*args, **kwargs, provider=FixtureProvider(), runner=runner)
        def build(store, token, command, target, **kwargs):
            calls.append('hook' if HOOK_REQUIREMENTS in command else 'wheel')
            with store.locked() as db:
                actor = store.session(db, token, preparation=True)
                _, bundle = store.project(db, actor['project'])
                mode = bundle['policy']['project']['python_dependencies']['sources'][0]['mode']
            if HOOK_REQUIREMENTS in command:
                self.assertEqual(json.loads(command[-1])['hook'], 'get_requires_for_build_' +
                                 ('editable' if mode == 'editable' else 'wheel'))
                proposed = requirements[mode] if isinstance(requirements, dict) else requirements
                (target / 'requirements.json').write_text(json.dumps(proposed))
            elif mode == 'editable':
                LocalPythonTests.fake_editable(self, store, token, command, target)
            else:
                self.discovery_build(store, token, command, target, **kwargs)
        self.enterContext(patch('ptw.dependency_resolution.resolve_python', side_effect=resolve))
        self.enterContext(patch('ptw.registry.provider_for', return_value=FixtureProvider()))
        self.enterContext(patch('ptw.python_local.install_wheels', side_effect=LocalPythonTests.fake_wheel_install))
        self.enterContext(patch('ptw.python_local.run_build', side_effect=build))
        return calls

    def test_dynamic_editable_reviews_distinct_hook_before_install_and_keeps_history(self):
        calls = self.hook_setup_fixture({'discovery': [], 'editable': ['builder>=1,<2']}, editable=True)
        prompts = []
        def answer(prompt):
            prompts.append(prompt)
            if 'build requirement discovery' in prompt:
                self.assertEqual(calls, ['hook', 'wheel'])
                identity = load(self.state / 'discovery-journal.json')['project']
                store = Store(self.state / 'controller')
                with store.locked() as db:
                    db.execute('UPDATE projects SET violations=1 WHERE id=?', (identity,))
                    db.execute('UPDATE task_counts SET violations=1 WHERE project=?', (identity,))
            if 'additional build' in prompt:
                self.assertEqual(calls, ['hook', 'wheel', 'hook'])
            return 'yes'
        with patch('builtins.input', side_effect=answer):
            record = self.setup()
        self.assertEqual(calls, ['hook', 'wheel', 'hook', 'wheel'])
        self.assertEqual(len(prompts), 4)
        stage = Path(record['bundle']).parent
        initial = load(stage / 'discovery-approved.json')
        final_discovery = load(stage / 'discovery-final-approved.json')
        bundle = load(record['bundle'])
        self.assertEqual(initial['policy']['project']['id'], record['project'])
        self.assertEqual(final_discovery['policy']['project']['id'], record['project'])
        self.assertEqual(bundle['policy']['project']['python_dependencies']['pins'], ['builder==1.0'])
        source = bundle['policy']['project']['python_dependencies']['sources'][0]
        self.assertEqual(source['mode'], 'editable')
        self.assertEqual(source['dynamic_metadata'], {'version': '1.0', 'dependencies': []})
        self.assertEqual(Store(record['state']).status(record['project'])['violations'], 1)

    def test_dynamic_editable_empty_hook_retains_wheel_requirement_constraints(self):
        calls = self.hook_setup_fixture({'discovery': ['builder>=1,<2'], 'editable': []}, editable=True)
        with patch('builtins.input', return_value='yes') as answer:
            record = self.setup()
        self.assertEqual(answer.call_count, 4)
        self.assertEqual(calls, ['hook', 'wheel', 'hook', 'wheel'])
        stage = Path(record['bundle']).parent
        self.assertEqual(load(stage / 'editable-discovery/discovery-result.json')['build_requirements'],
                         ['builder<2,>=1'])
        self.assertEqual(load(stage / 'python-options.json')['build_requirements'], ['builder<2,>=1'])

    def test_dynamic_editable_rejection_at_each_new_boundary_never_installs(self):
        calls = self.hook_setup_fixture({'discovery': [], 'editable': ['builder>=1,<2']}, editable=True)
        for answers in (['yes', 'reject'], ['yes', 'yes', 'cancel'],
                        ['yes', 'yes', 'yes', 'cancel'], ['yes', EOFError()]):
            calls.clear()
            with self.subTest(answers=repr(answers)), patch('builtins.input', side_effect=answers), \
                    self.assertRaises((Invalid, EOFError)):
                self.setup()
            self.assertEqual(calls, ['hook', 'wheel'] if len(answers) == 2 else ['hook', 'wheel', 'hook'])
            self.assertFalse((self.repo / '.ptw').exists())
            identity = load(self.state / 'discovery-journal.json')['project']
            store = Store(self.state / 'controller')
            self.assertTrue(store.status(identity)['stopped'])
            with store.locked() as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM package_sets').fetchone()[0], 0)

    def test_dynamic_editable_mutation_or_stop_during_hook_review_prevents_execution(self):
        calls = self.hook_setup_fixture({'discovery': [], 'editable': ['builder>=1,<2']}, editable=True)
        for effect in ('mutation', 'stop'):
            calls.clear()
            def answer(prompt):
                if 'build requirement discovery' in prompt:
                    if effect == 'mutation':
                        (self.repo / 'src/local_demo/__init__.py').write_text('VALUE = 99\n')
                    else:
                        identity = load(self.state / 'discovery-journal.json')['project']
                        Store(self.state / 'controller').stop(identity)
                return 'yes'
            with self.subTest(effect=effect), patch('builtins.input', side_effect=answer), self.assertRaises(Invalid):
                self.setup()
            self.assertEqual(calls, ['hook', 'wheel'])
            self.assertFalse((self.repo / '.ptw').exists())

    def test_dynamic_editable_unsafe_hook_requirement_is_not_resolved(self):
        calls = self.hook_setup_fixture({'discovery': [], 'editable': ['builder @ file:///outside.whl']}, editable=True)
        with self.assertRaisesRegex(EvidenceError, 'unsafe source'):
            self.setup()
        self.assertEqual(calls, ['hook', 'wheel', 'hook'])
        self.assertFalse((self.repo / '.ptw').exists())

    def test_dynamic_editable_hook_cannot_override_wheel_hook_constraints(self):
        calls = self.hook_setup_fixture({'discovery': ['builder==1.0'], 'editable': ['builder>=2']}, editable=True)
        with self.assertRaisesRegex(Invalid, 'original dependency constraint'):
            self.setup()
        self.assertEqual(calls, ['hook', 'wheel', 'hook'])
        self.assertFalse((self.repo / '.ptw').exists())

    def test_static_hook_review_preserves_source_and_history_for_both_modes(self):
        for editable in (False, True):
            with self.subTest(editable=editable), ExitStack() as contexts:
                # Each mode has its own complete setup and pending controller.
                fixture = LocalSetupTests()
                fixture.setUp()
                contexts.callback(fixture.doCleanups)
                calls = fixture.hook_setup_fixture(dynamic=False, editable=editable)
                prompts = []
                def answer(prompt):
                    prompts.append(prompt)
                    if 'additional build' in prompt:
                        self.assertEqual(calls, ['hook'])
                        identity = load(fixture.state / 'discovery-journal.json')['project']
                        store = Store(fixture.state / 'controller')
                        with store.locked() as db:
                            self.assertEqual(db.execute('SELECT COUNT(*) FROM package_sets').fetchone()[0], 0)
                            db.execute('UPDATE projects SET violations=1 WHERE id=?', (identity,))
                            db.execute('UPDATE task_counts SET violations=1 WHERE project=?', (identity,))
                    return 'yes'
                with patch('builtins.input', side_effect=answer):
                    record = fixture.setup(python_editable='src' if editable else None,
                        python_wheel=not editable, python_build_requirements=True)
                self.assertEqual(calls, ['hook', 'wheel'])
                self.assertEqual(len(prompts), 3)
                self.assertIn('build requirement discovery', prompts[0])
                bundle = load(record['bundle'])
                source = bundle['policy']['project']['python_dependencies']['sources'][0]
                self.assertEqual(source['mode'], 'editable' if editable else 'wheel')
                self.assertNotIn('dynamic_metadata', source)
                self.assertEqual(bundle['policy']['project']['python_dependencies']['pins'], ['builder==1.0'])
                store = Store(record['state'])
                self.assertEqual(store.status(record['project'])['violations'], 1)
                self.assertIsNotNone(store.register(record['project'], 'work'))

    def test_static_hook_rejection_at_each_review_never_installs(self):
        calls = self.hook_setup_fixture(dynamic=False, editable=True)
        for answers in (['reject'], ['yes', 'cancel'], ['yes', 'yes', 'cancel'], ['yes', EOFError()]):
            calls.clear()
            with self.subTest(answers=repr(answers)), patch('builtins.input', side_effect=answers), \
                    self.assertRaises((Invalid, EOFError)):
                self.setup(python_build_requirements=True)
            self.assertEqual(calls, [] if len(answers) == 1 else ['hook'])
            self.assertFalse((self.repo / '.ptw').exists())
            self.assertFalse((self.repo / 'ptw-requirements.txt').exists())
            with Store(self.state / 'controller').locked() as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM package_sets').fetchone()[0], 0)

    def test_static_hook_mutation_or_stop_denies_final_preparation(self):
        calls = self.hook_setup_fixture(dynamic=False, editable=True)
        for effect in ('mutation', 'stop'):
            calls.clear()
            def answer(prompt):
                if 'additional build' in prompt:
                    if effect == 'mutation':
                        (self.repo / 'src/local_demo/__init__.py').write_text('VALUE = 99\n')
                    else:
                        identity = load(self.state / 'discovery-journal.json')['project']
                        Store(self.state / 'controller').stop(identity)
                return 'yes'
            with self.subTest(effect=effect), patch('builtins.input', side_effect=answer), self.assertRaises(Invalid):
                self.setup(python_build_requirements=True)
            self.assertEqual(calls, ['hook'])
            self.assertFalse((self.repo / '.ptw').exists())

    def test_static_hook_empty_proposal_needs_final_review_without_resolution_expansion(self):
        calls = self.hook_setup_fixture([], dynamic=False, editable=True)
        with patch('builtins.input', side_effect=['yes', 'yes']) as answer:
            record = self.setup(python_build_requirements=True)
        self.assertEqual(calls, ['hook', 'wheel'])
        self.assertEqual(answer.call_count, 2)
        stage = Path(record['bundle']).parent
        self.assertFalse((stage / 'discovery-build-approved.json').exists())
        self.assertEqual(load(stage / 'discovery-result.json')['build_requirements'], [])

    def test_hook_review_flag_requires_static_local_preparation(self):
        self.offline()
        with patch('ptw.python_local.run_build') as build:
            with self.assertRaisesRegex(Invalid, 'requires local'):
                self.setup(python_editable=None, python_build_requirements=True)
            with self.assertRaisesRegex(Invalid, 'explicitly selected'):
                self.setup(python_editable='', python_build_requirements=True)
            self.unknown_dynamic_project()
            with self.assertRaisesRegex(Invalid, 'requires static'):
                self.setup(python_build_requirements=True)
            build.assert_not_called()

    def test_static_editable_hook_unsafe_requirement_never_enters_graph(self):
        calls = self.hook_setup_fixture(['builder @ file:///outside.whl'], dynamic=False, editable=True)
        with self.assertRaisesRegex(EvidenceError, 'unsafe source'):
            self.setup(python_build_requirements=True)
        self.assertEqual(calls, ['hook'])
        self.assertFalse((self.repo / '.ptw').exists())

    def test_dynamic_hook_additions_need_separate_approval_and_preserve_history(self):
        calls = self.hook_setup_fixture()
        prompts = []
        def reply(prompt):
            prompts.append(prompt)
            if 'additional build' in prompt:
                self.assertEqual(calls, ['hook'])
                identity = load(self.state / 'discovery-journal.json')['project']
                store = Store(self.state / 'controller')
                with store.locked() as db:
                    row, bundle = store.project(db, identity)
                    self.assertEqual(bundle['policy']['project']['python_dependencies']['pins'], [])
                    self.assertTrue(row['setup_pending'])
                    db.execute('UPDATE projects SET violations=1 WHERE id=?', (identity,))
                    db.execute('UPDATE task_counts SET violations=1 WHERE project=?', (identity,))
            return 'yes'
        with patch('builtins.input', side_effect=reply):
            record = self.setup(python_editable=None, python_wheel=True)
        self.assertEqual(calls, ['hook', 'wheel', 'wheel'])
        self.assertEqual(len(prompts), 3)
        stage = Path(record['bundle']).parent
        initial = load(stage / 'discovery-approved.json')
        refined = load(stage / 'discovery-build-approved.json')
        final = load(record['bundle'])
        self.assertEqual(initial['policy']['project']['id'], record['project'])
        self.assertEqual(refined['policy']['project']['id'], record['project'])
        self.assertEqual(final['policy']['project']['python_dependencies']['pins'], ['builder==1.0'])
        self.assertEqual(refined['policy']['project']['python_dependencies']['pins'], ['builder==1.0'])
        self.assertEqual(initial['policy']['project']['python_dependencies']['pins'], [])
        self.assertEqual(Store(record['state']).status(record['project'])['violations'], 1)
        self.assertEqual(load(stage / 'discovery-result.json')['policy_sha256'], refined['approval']['sha256'])

    def test_dynamic_hook_rejection_cancellation_and_eof_cannot_build(self):
        calls = self.hook_setup_fixture()
        for reply in ('reject', 'cancel', '', EOFError(), KeyboardInterrupt()):
            calls.clear()
            with self.subTest(reply=repr(reply)), patch('builtins.input', side_effect=['yes', reply]), \
                    self.assertRaises((Invalid, EOFError, KeyboardInterrupt)):
                self.setup(python_editable=None, python_wheel=True)
            self.assertEqual(calls, ['hook'])
            self.assertFalse((self.repo / '.ptw').exists())
            self.assertFalse((self.repo / 'ptw-requirements.txt').exists())
            identity = load(self.state / 'discovery-journal.json')['project']
            store = Store(self.state / 'controller')
            self.assertTrue(store.status(identity)['stopped'])
            with store.locked() as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM package_sets').fetchone()[0], 0)

    def test_dynamic_hook_mutation_or_stop_during_review_rejects_refinement(self):
        calls = self.hook_setup_fixture()
        for effect in ('mutation', 'stop'):
            calls.clear()
            def reply(prompt):
                if 'additional build' in prompt:
                    if effect == 'mutation':
                        (self.repo / 'src/local_demo/__init__.py').write_text('VALUE = 100\n')
                    else:
                        identity = load(self.state / 'discovery-journal.json')['project']
                        Store(self.state / 'controller').stop(identity)
                return 'yes'
            with self.subTest(effect=effect), patch('builtins.input', side_effect=reply), self.assertRaises(Invalid):
                self.setup(python_editable=None, python_wheel=True)
            self.assertEqual(calls, ['hook'])
            self.assertFalse((self.repo / '.ptw').exists())

    def test_dynamic_hook_conflicting_requirement_cannot_override_original_build_pin(self):
        calls = self.hook_setup_fixture(['builder>=2'])
        metadata = self.repo / 'pyproject.toml'
        metadata.write_text(metadata.read_text().replace('requires=[]', 'requires=["builder==1.0"]'))
        with self.assertRaisesRegex(Invalid, 'original dependency constraint'):
            self.setup(python_editable=None, python_wheel=True)
        self.assertEqual(calls, ['hook'])
        self.assertFalse((self.repo / '.ptw').exists())

    def test_dynamic_hook_unsafe_proposal_never_reaches_resolver_or_build(self):
        calls = self.hook_setup_fixture(['builder @ https://example.invalid/builder.whl'])
        with self.assertRaisesRegex(EvidenceError, 'unsafe source'):
            self.setup(python_editable=None, python_wheel=True)
        self.assertEqual(calls, ['hook'])
        self.assertFalse((self.repo / '.ptw').exists())

    def test_dynamic_final_cancellation_retains_stopped_history_without_install(self):
        self.offline()
        self.unknown_dynamic_project()
        with patch('builtins.input', side_effect=['yes', 'cancel']), \
                patch('ptw.python_local.run_build', side_effect=self.discovery_build) as build:
            with self.assertRaisesRegex(Invalid, 'Not activated'):
                self.setup(python_editable=None, python_wheel=True)
        self.assertEqual(build.call_count, 2)
        identity = load(self.state / 'discovery-journal.json')['project']
        store = Store(self.state / 'controller')
        self.assertTrue(store.status(identity)['stopped'])
        self.assertFalse((self.repo / '.ptw').exists())
        with store.locked() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM package_sets').fetchone()[0], 0)

    def test_dynamic_discovery_mutation_and_unexpected_url_fail_before_install(self):
        self.offline()
        self.unknown_dynamic_project()
        def mutate(*args, **kwargs):
            self.discovery_build(*args, **kwargs)
            (self.repo / 'src/local_demo/__init__.py').write_text('VALUE = 99\n')
        with patch('ptw.python_local.run_build', side_effect=mutate), \
                self.assertRaisesRegex(Invalid, 'changed since build review'):
            self.setup(python_editable=None, python_wheel=True)
        def url(store, token, command, target, **kwargs):
            from ptw.python_local import HOOK_REQUIREMENTS
            if HOOK_REQUIREMENTS in command:
                (target / 'requirements.json').write_text('[]')
                return
            (target / 'out').mkdir()
            (target / 'out/local_demo-1.0-py3-none-any.whl').write_bytes(
                wheel_bytes('local-demo', '1.0', requires=['unapproved @ https://example.invalid/file.whl']))
        with patch('ptw.python_local.run_build', side_effect=url), \
                patch('ptw.dependency_resolution.run_metadata') as resolve, self.assertRaises(EvidenceError):
            self.setup(python_editable=None, python_wheel=True)
        resolve.assert_not_called()
        self.assertFalse((self.repo / '.ptw').exists())

    def test_wheel_setup_rejection_never_executes_backend(self):
        self.offline()
        from test_product_onboarding import snapshot
        before = snapshot(self.repo)
        with patch('builtins.input', return_value='reject'), patch('ptw.python_local.run_build') as build:
            with self.assertRaises(Invalid):
                self.setup(python_editable=None, python_wheel=True)
            build.assert_not_called()
        self.assertEqual(snapshot(self.repo), before)

    def test_setup_rejection_cancellation_and_invalid_mutability_never_build(self):
        self.offline()
        from test_product_onboarding import snapshot
        before = snapshot(self.repo)
        with patch('ptw.python_local.run_build') as run:
            for reply in ('reject', 'cancel', '', EOFError(), KeyboardInterrupt()):
                with self.subTest(reply=repr(reply)), patch('builtins.input', side_effect=[reply]):
                    with self.assertRaises((Invalid, EOFError, KeyboardInterrupt)):
                        self.setup()
                    self.assertEqual(snapshot(self.repo), before)
            from ptw.onboarding import setup
            from test_product_onboarding import args
            for mutable in ('../outside', 'unrelated.txt', 'backend', 'pyproject.toml', 'src,src'):
                with self.subTest(mutable=mutable), self.assertRaises(Invalid):
                    setup(self.repo, self.state, args(self.repo, editable='src,backend,tests', python_editable=mutable))
            run.assert_not_called()

    def test_setup_failure_rolls_back_and_retry_uses_new_project(self):
        self.offline()
        from test_product_onboarding import snapshot
        before = snapshot(self.repo)
        with patch('ptw.python_local.run_build', side_effect=EvidenceError('fixture failed')):
            with self.assertRaisesRegex(EvidenceError, 'Confined editable'):
                self.setup()
        self.assertEqual(snapshot(self.repo), before)
        failed = load(self.state / 'setup-journal.json')['record']['project']
        store = Store(self.state / 'controller')
        self.assertTrue(store.status(failed)['stopped'])
        self.assertEqual(load(self.state / 'setup-journal.json')['phase'], 'rolled-back')
        self.assertFalse((self.state / 'project.json').exists())
        with patch('ptw.python_local.run_build', side_effect=self.fake_build):
            record = self.setup()
        self.assertNotEqual(failed, record['project'])
        self.assertTrue(store.status(failed)['stopped'])

    def test_mutation_after_preparation_rejects_commit_and_preserves_user_edit(self):
        self.offline()
        from ptw.python_local import prepare_setup
        def mutate(*args):
            receipts = prepare_setup(*args)
            (self.repo / 'src/local_demo/__init__.py').write_text('VALUE = 99\n')
            return receipts
        with patch('ptw.python_local.run_build', side_effect=self.fake_build), \
                patch('ptw.python_local.prepare_setup', side_effect=mutate):
            with self.assertRaisesRegex(Invalid, 'changed before setup commit'):
                self.setup()
        self.assertEqual((self.repo / 'src/local_demo/__init__.py').read_text(), 'VALUE = 99\n')
        self.assertFalse((self.state / 'project.json').exists())
        self.assertFalse((self.repo / '.ptw').exists())

    def test_unconfirmed_preparation_termination_blocks_readiness(self):
        self.offline()
        with patch('ptw.python_local.run_build', side_effect=self.fake_build), \
                patch('ptw.supervisor.Supervisor.reconcile', return_value=[{'confirmed_stopped': False}]):
            with self.assertRaisesRegex(Invalid, 'termination is unconfirmed'):
                self.setup()
        journal = load(self.state / 'setup-journal.json')
        self.assertEqual(journal['phase'], 'rolled-back')
        store = Store(self.state / 'controller')
        self.assertTrue(store.status(journal['record']['project'])['stopped'])
        self.assertFalse((self.state / 'project.json').exists())
        self.assertFalse((self.repo / '.ptw').exists())

    def test_build_requirements_enter_existing_resolution_without_backend_execution(self):
        from types import SimpleNamespace
        from ptw.dependency_resolution import resolve_python
        from ptw.setup_templates import RULES
        path = self.repo / 'pyproject.toml'
        path.write_text(path.read_text().replace('requires=[]', 'requires=["builder>=1,<2"]'))
        def runner(argv, **kwargs):
            self.assertIn('builder>=1,<2', (Path(kwargs['cwd']) / 'requirements.in').read_text())
            Path(argv[argv.index('--output-file') + 1]).write_text('builder==1.0\n')
            return SimpleNamespace(returncode=0, stderr='')
        with patch('ptw.python_local.run_build') as build:
            result = resolve_python(self.repo, self.root / 'resolve', RULES, local_build=True,
                                    runner=runner, provider=FixtureProvider())
            build.assert_not_called()
        self.assertEqual(result['pins'], ['builder==1.0'])
        self.assertEqual(result['inputs']['pyproject.toml'], hashlib.sha256(path.read_bytes()).hexdigest())
        path.write_text(path.read_text().replace('builder>=1,<2', 'builder @ https://example.com/a.whl'))
        with self.assertRaises(Invalid), patch('ptw.dependency_resolution.run_metadata') as run:
            resolve_python(self.repo, self.root / 'bad-resolve', RULES, local_build=True)
        run.assert_not_called()

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_cli_review_reject_failure_retry_and_editable_import(self):
        self.native_cli_flow(editable=True)

    def native_uv_lock(self):
        from ptw.dependency_resolution import run_metadata, resolver_environment
        stage = self.root / 'lock-inputs'
        stage.mkdir()
        metadata = self.repo / 'pyproject.toml'
        metadata.write_text(metadata.read_text().replace('version="1.0"',
            'version="1.0"\nrequires-python=">=3.11"'))
        backend = self.repo / 'backend/backend.py'
        backend.write_text(backend.read_text().replace('Version: 1.0\\n',
            'Version: 1.0\\nRequires-Python: >=3.11\\n'))
        (stage / 'pyproject.toml').write_bytes(metadata.read_bytes())
        # Only metadata enters this namespace, not the executable backend.
        proc = run_metadata([shutil.which('uv'), '--no-config', '--no-python-downloads',
            '--offline', 'lock', '--no-build', '--no-sources', '--python', '/usr/bin/python3'],
            cwd=stage, env=resolver_environment(stage), capture_output=True, text=True, timeout=20)
        self.assertEqual(proc.returncode, 0, 'Native static fixture lock generation failed')
        (self.repo / 'uv.lock').write_bytes((stage / 'uv.lock').read_bytes())

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_cli_uv_locked_editable_review_build_and_live_import(self):
        self.native_uv_lock()
        self.native_cli_flow(editable=True)

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_cli_uv_locked_wheel_review_build_and_import(self):
        self.native_uv_lock()
        self.test_native_cli_wheel_review_rollback_import_and_stale_rejection()

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_cli_wheel_review_rollback_import_and_stale_rejection(self):
        path = self.repo / 'tests/test_import.py'
        path.write_text(path.read_text().replace(
            'self.assertTrue(json.loads(m.distribution("local-demo").read_text("direct_url.json"))["dir_info"]["editable"])',
            'self.assertIn("archive_info",json.loads(m.distribution("local-demo").read_text("direct_url.json")))')
            .replace('startswith("/target/src/")', 'startswith("/python-packages/")'))
        self.native_cli_flow(editable=False)

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_cli_compiled_wheel_review_and_import(self):
        native_library_project(self)
        path = self.repo / 'tests/test_import.py'
        path.write_text(path.read_text().replace(
            'self.assertTrue(json.loads(m.distribution("local-demo").read_text("direct_url.json"))["dir_info"]["editable"])',
            'self.assertIn("archive_info",json.loads(m.distribution("local-demo").read_text("direct_url.json")))')
            .replace('startswith("/target/src/")', 'startswith("/python-packages/")'))
        self.native_cli_flow(editable=False, native_wheels=True)

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_cli_compiled_editable_review_and_inplace_import(self):
        native_library_project(self, editable=True)
        self.native_cli_flow(editable=True, native_wheels=True)

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_cli_extra_review_and_editable_import(self):
        metadata = self.repo / 'pyproject.toml'
        metadata.write_text(metadata.read_text() + '\n[project.optional-dependencies]\nfeature=[]\n')
        backend = self.repo / 'backend/backend.py'
        backend.write_text(backend.read_text().replace('Version: 1.0\\n\\n',
                                                      'Version: 1.0\\nProvides-Extra: feature\\n\\n'))
        self.native_cli_flow(editable=True, extras='feature')

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_cli_unknown_dynamic_discovery_build_and_import(self):
        self.unknown_dynamic_project()
        path = self.repo / 'tests/test_import.py'
        path.write_text(path.read_text().replace(
            'self.assertTrue(json.loads(m.distribution("local-demo").read_text("direct_url.json"))["dir_info"]["editable"])',
            'self.assertIn("archive_info",json.loads(m.distribution("local-demo").read_text("direct_url.json")))')
            .replace('startswith("/target/src/")', 'startswith("/python-packages/")'))
        self.native_cli_flow(editable=False, dynamic=True)

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_cli_requirements_dynamic_wheel_discovery_and_import(self):
        (self.repo / 'requirements.in').write_text('-r requirements-local.txt\n')
        (self.repo / 'requirements-local.txt').write_text('.\n')
        self.unknown_dynamic_project()
        path = self.repo / 'tests/test_import.py'
        path.write_text(path.read_text().replace(
            'self.assertTrue(json.loads(m.distribution("local-demo").read_text("direct_url.json"))["dir_info"]["editable"])',
            'self.assertIn("archive_info",json.loads(m.distribution("local-demo").read_text("direct_url.json")))')
            .replace('startswith("/target/src/")', 'startswith("/python-packages/")'))
        self.native_cli_flow(editable=False, dynamic=True, requirements=True)

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_cli_requirements_dynamic_editable_discovery_and_import(self):
        (self.repo / 'requirements.in').write_text('-r requirements-local.txt\n')
        (self.repo / 'requirements-local.txt').write_text('-e .\n')
        self.unknown_dynamic_project()
        self.native_cli_flow(editable=True, dynamic=True, requirements=True)

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_cli_dynamic_hook_requirement_review_retry_and_import(self):
        self.unknown_dynamic_project()
        backend = self.repo / 'backend/backend.py'
        backend.write_text(backend.read_text().replace('    return []', '    return ["builder>=1,<2"]')
            .replace('    files = {', '    import builder\n'
                     '    assert builder.VALUE == "SYNTHETIC_PACKAGE_OK"\n    files = {'))
        path = self.repo / 'tests/test_import.py'
        path.write_text(path.read_text().replace(
            'self.assertTrue(json.loads(m.distribution("local-demo").read_text("direct_url.json"))["dir_info"]["editable"])',
            'self.assertIn("archive_info",json.loads(m.distribution("local-demo").read_text("direct_url.json")))')
            .replace('startswith("/target/src/")', 'startswith("/python-packages/")') +
            '\nimport builder\nassert builder.VALUE == "SYNTHETIC_PACKAGE_OK"\n')
        self.native_cli_flow(editable=False, dynamic=True, hook_requirements=True)

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_cli_static_wheel_hook_review_build_and_import(self):
        self.native_static_hook_flow(editable=False)

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_cli_static_editable_hook_review_build_and_live_import(self):
        self.native_static_hook_flow(editable=True)

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_cli_dynamic_editable_distinct_hook_review_build_and_import(self):
        self.unknown_dynamic_project()
        backend = self.repo / 'backend/backend.py'
        backend.write_text(backend.read_text().replace(
            'get_requires_for_build_editable = get_requires_for_build_wheel',
            'def get_requires_for_build_editable(config_settings=None):\n'
            '    return ["builder>=1,<2"]').replace(
            '    if editable:', '    if editable:\n        import builder\n'
            '        assert builder.VALUE == "SYNTHETIC_PACKAGE_OK"'))
        path = self.repo / 'tests/test_import.py'
        path.write_text(path.read_text() + '\nimport builder\nassert builder.VALUE == "SYNTHETIC_PACKAGE_OK"\n')
        self.native_cli_flow(editable=True, dynamic=True, hook_requirements=True)

    def native_static_hook_flow(self, *, editable):
        backend = self.repo / 'backend/backend.py'
        backend.write_text(backend.read_text().replace('    return []', '    return ["builder>=1,<2"]')
            .replace('    files = {', '    import builder\n'
                     '    assert builder.VALUE == "SYNTHETIC_PACKAGE_OK"\n    files = {'))
        if editable:
            # The wheel hook must not substitute for the distinct editable hook.
            backend.write_text(backend.read_text().replace(
                'get_requires_for_build_editable = get_requires_for_build_wheel',
                'get_requires_for_build_editable = get_requires_for_build_wheel\n'
                'def get_requires_for_build_wheel(config_settings=None):\n'
                '    raise RuntimeError("wrong requirement hook")'))
        path = self.repo / 'tests/test_import.py'
        if not editable:
            path.write_text(path.read_text().replace(
                'self.assertTrue(json.loads(m.distribution("local-demo").read_text("direct_url.json"))["dir_info"]["editable"])',
                'self.assertIn("archive_info",json.loads(m.distribution("local-demo").read_text("direct_url.json")))')
                .replace('startswith("/target/src/")', 'startswith("/python-packages/")'))
        path.write_text(path.read_text() + '\nimport builder\nassert builder.VALUE == "SYNTHETIC_PACKAGE_OK"\n')
        self.native_cli_flow(editable=editable, hook_requirements=True)

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_cli_dynamic_discovery_with_static_self_referencing_extras(self):
        self.unknown_dynamic_project()
        metadata = self.repo / 'pyproject.toml'
        metadata.write_text(metadata.read_text() + '\n[project.optional-dependencies]\n'
                            'feature=["local-demo[base]==1.0"]\nbase=[]\n')
        backend = self.repo / 'backend/backend.py'
        backend.write_text(backend.read_text().replace('Version: 1.0\\n\\n',
            'Version: 1.0\\nProvides-Extra: feature\\nProvides-Extra: base\\n'
            'Requires-Dist: local-demo[base]==1.0; extra == "feature"\\n\\n'))
        path = self.repo / 'tests/test_import.py'
        path.write_text(path.read_text().replace(
            'self.assertTrue(json.loads(m.distribution("local-demo").read_text("direct_url.json"))["dir_info"]["editable"])',
            'self.assertIn("archive_info",json.loads(m.distribution("local-demo").read_text("direct_url.json")))')
            .replace('startswith("/target/src/")', 'startswith("/python-packages/")'))
        self.native_cli_flow(editable=False, dynamic=True, extras='feature')

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_cli_dynamic_optional_wheel_resolve_build_import(self):
        self.native_dynamic_optional(editable=False)

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_cli_dynamic_optional_editable_resolve_build_import(self):
        self.native_dynamic_optional(editable=True)

    def native_dynamic_optional(self, *, editable):
        metadata = self.repo / 'pyproject.toml'
        metadata.write_text(metadata.read_text().replace('version="1.0"',
            'version="1.0"\ndynamic=["optional-dependencies"]'))
        backend = self.repo / 'backend/backend.py'
        backend.write_text(backend.read_text().replace('Version: 1.0\\n\\n',
            'Version: 1.0\\nProvides-Extra: feature\\nProvides-Extra: empty\\n'
            'Provides-Extra: unused\\nRequires-Dist: builder>=1,<2; extra == "feature"\\n'
            'Requires-Dist: absent>=9; extra == "unused"\\n\\n'))
        path = self.repo / 'tests/test_import.py'
        if not editable:
            path.write_text(path.read_text().replace(
                'self.assertTrue(json.loads(m.distribution("local-demo").read_text("direct_url.json"))["dir_info"]["editable"])',
                'self.assertIn("archive_info",json.loads(m.distribution("local-demo").read_text("direct_url.json")))')
                .replace('startswith("/target/src/")', 'startswith("/python-packages/")'))
        path.write_text(path.read_text() + '\nimport builder\nassert builder.VALUE == "SYNTHETIC_PACKAGE_OK"\n')
        self.native_cli_flow(editable=editable, dynamic=True, extras='feature', registry_fixture=True)

    def native_cli_flow(self, *, editable, extras=None, dynamic=False, native_wheels=False,
                        hook_requirements=False, registry_fixture=False, requirements=False):
        from ptw.onboarding import private_directory
        from ptw.python_local import prepared_sets
        from ptw.workspace import Workspace, request
        from ptw.monitor import remove
        from ptw.supervisor import Supervisor
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
        from terminal_driver import Terminal
        with patch.dict(os.environ, {'PTW_USER_STATE': str(self.root / 'native-state')}):
            directory = private_directory(self.repo)
        original = (self.repo / 'backend/backend.py').read_text()
        unrelated = subprocess.Popen(['/usr/bin/sleep', '120'])
        try:
            for index, reply in enumerate(('reject', 'cancel', 'yes', 'yes')):
                if index == 2:
                    (self.repo / 'backend/backend.py').write_text('raise RuntimeError("deliberate backend failure")\n')
                if index == 3:
                    (self.repo / 'backend/backend.py').write_text(original)
                terminal = Terminal([sys.executable, str(Path(__file__).resolve()),
                    '--local-hook-setup-fixture' if hook_requirements or registry_fixture else '--local-setup-fixture',
                    'codex', '--repo', str(self.repo), '--goal', 'Develop the explicit local fixture',
                    '--language', 'python', '--editable', 'src,backend,tests', '--files', '',
                    *(['--python-editable', 'src'] if editable else ['--python-wheel']),
                    *(['--python-native-wheels'] if native_wheels else []),
                    *(['--python-build-requirements'] if hook_requirements and not dynamic else []),
                    *(['--python-source', 'requirements.in'] if requirements else []),
                    *(['--python-extras', extras] if extras else []), '--setup-only'], self.root / ('pty-' + str(index)),
                    env={'PTW_USER_STATE': str(self.root / 'native-state')})
                try:
                    if dynamic or hook_requirements:
                        terminal.expect('Approve ' + ('metadata discovery' if dynamic else 'build requirement discovery'), 20)
                        self.assertIn('second review is required', terminal.text)
                        self.assertFalse((self.repo / '.ptw').exists())
                        terminal.send('yes' if hook_requirements else reply)
                        if dynamic and editable and index != 2 and (hook_requirements or index == 3):
                            terminal.expect('Approve build requirement discovery', 90)
                            self.assertIn('offline editable requirement hook', terminal.text)
                            self.assertFalse((self.repo / '.ptw').exists())
                            terminal.send('yes')
                        if hook_requirements and index != 2:
                            terminal.expect('Approve additional build requirements', 90)
                            self.assertIn('builder<2,>=1', terminal.text)
                            self.assertFalse((self.repo / '.ptw').exists())
                            if index == 3:
                                terminal.send('details')
                                terminal.expect('Reviewed dependency inputs and artifacts', 5)
                                terminal.expect('Approve additional build requirements', 5)
                            terminal.send(reply)
                        if index != 3:
                            terminal.wait(lambda: terminal.exited, 90)
                            self.assertNotIn('Approved.', terminal.text)
                            self.assertFalse((self.repo / '.ptw').exists())
                            continue
                    terminal.expect('Approve exactly', 90 if dynamic or hook_requirements else 20)
                    self.assertIn('execute backend offline after approval', terminal.text)
                    self.assertIn('live edits: ' + ('src' if editable else 'none'), terminal.text)
                    self.assertIn('extras: ' + (extras or 'none'), terminal.text)
                    self.assertIn('native wheels ' + str(native_wheels), terminal.text)
                    self.assertFalse((self.repo / '.ptw').exists())
                    if index == 3:
                        terminal.send('details')
                        terminal.expect('Reviewed dependency inputs and artifacts', 5)
                        terminal.expect('Approve exactly', 5)
                    terminal.send(reply)
                    terminal.wait(lambda: terminal.exited, 90)
                    if index == 3:
                        self.assertIn('Approved.', terminal.text)
                    else:
                        self.assertNotIn('Approved.', terminal.text)
                        self.assertFalse((self.repo / '.ptw').exists())
                finally:
                    code = terminal.close()
                    if (dynamic or hook_requirements) and index != 3:
                        self.assertEqual(code, 2)
                        if index == 2:
                            failed = load(directory / 'discovery-journal.json')['project']
                            self.assertTrue(Store(directory / 'controller').status(failed)['stopped'])
                self.assertEqual(code, 0 if index == 3 else 2)
                if (directory / 'controller/state.sqlite3').exists():
                    store = Store(directory / 'controller')
                if index == 2:
                    failed = load(directory / 'setup-journal.json')['record']['project']
                    self.assertTrue(store.status(failed)['stopped'])
            record = load(directory / 'project.json')
            store = Store(directory / 'controller')
            bundle = load(record['bundle'])
            if (self.repo / 'uv.lock').exists():
                descriptor = bundle['policy']['project']['python_dependencies']
                self.assertEqual(descriptor['authority'], 'uv.lock')
                self.assertEqual(descriptor['inputs']['uv.lock'],
                                 hashlib.sha256((self.repo / 'uv.lock').read_bytes()).hexdigest())
            if requirements:
                descriptor = bundle['policy']['project']['python_dependencies']
                self.assertEqual(descriptor['authority'], 'requirements')
                self.assertEqual(descriptor['pins'], [])
                for path in self.repo.glob('requirements*'):
                    self.assertEqual(descriptor['inputs'][path.name], hashlib.sha256(path.read_bytes()).hexdigest())
            if registry_fixture:
                stage = Path(record['bundle']).parent
                self.assertEqual(load(stage / 'discovery-approved.json')['policy']['project']
                                 ['python_dependencies']['pins'], [])
                self.assertEqual(bundle['policy']['project']['python_dependencies']['pins'], ['builder==1.0'])
                optional = bundle['policy']['project']['python_dependencies']['sources'][0]['dynamic_metadata']
                self.assertEqual(optional['optional-dependencies'],
                    {'feature': ['builder<2,>=1'], 'empty': [], 'unused': ['absent>=9']})
            if hook_requirements:
                stage = Path(record['bundle']).parent
                self.assertEqual(load(stage / 'discovery-approved.json')['policy']['project']
                                 ['python_dependencies']['pins'], [])
                if dynamic and editable:
                    self.assertEqual(load(stage / 'discovery-build-requirements.json')['requirements'], [])
                    stage = stage / 'editable-discovery'
                    self.assertEqual(load(stage / 'discovery-build-requirements.json')['hook'],
                                     'get_requires_for_build_editable')
                self.assertEqual(load(stage / 'discovery-build-approved.json')['policy']['project']
                                 ['python_dependencies']['pins'], ['builder==1.0'])
                self.assertEqual(bundle['policy']['project']['python_dependencies']['pins'], ['builder==1.0'])
                self.assertEqual(load(stage / 'discovery-build-requirements.json')['requirements'], ['builder<2,>=1'])
                self.assertTrue(load(stage / 'discovery-build-resolution/resolution.json')['attempts'])
            self.assertEqual(bundle['policy']['project']['python_dependencies']['sources'][0].get('extras', []),
                             [extras] if extras else [])
            actor = store.register(record['project'], 'work')
            prepared = prepared_sets(store, actor['token'])
            self.assertEqual(len(prepared), 1)
            workspace = Workspace(store)
            for value in (42, 99):
                if value == 99:
                    resource = next(r for r, v in bundle['inventory']['resources'].items() if v['path'] == 'src')
                    changed_path = 'local_demo/value.c' if editable and native_wheels else 'local_demo/__init__.py'
                    before = workspace.request(actor['token'], 'read', request('read', resource, path=changed_path))
                    changed = workspace.request(actor['token'], 'edit', request('write', resource, path=changed_path,
                        content='int local_value(void) { return 99; }\n' if editable and native_wheels else 'VALUE = 99\n',
                        expected=before['sha256']))
                    self.assertTrue(changed['allowed'], changed)
                result = workspace.request(actor['token'], 'test-' + str(value), request('run', 'test',
                    content=json.dumps({'package_sets': [prepared[0]['package_set']]})))
                # This synthetic dynamic backend can read every source input.
                # Its implementation edits require re-preparation even in editable mode.
                if (not editable or dynamic or native_wheels) and value == 99:
                    self.assertFalse(result['allowed'], result)
                    self.assertIn('configuration changed' if editable and dynamic else 'source changed', json.dumps(result))
                    continue
                self.assertTrue(result['allowed'], result)
                self.assertEqual(result['exit_code'], 0, result)
                self.assertIn('EDITABLE_VALUE ' + str(value), result['output'])
            self.assertEqual(store.status(record['project'])['policy_sha256'], bundle['approval']['sha256'])
            self.assertEqual(self.private.read_text(), 'UNRELATED_LOCAL_SOURCE')
            self.assertEqual(self.external.read_text(), 'EXTERNAL_CONTROL')
            self.assertIsNone(unrelated.poll())
            if editable and native_wheels:
                old = record
                terminal = Terminal([sys.executable, str(Path(__file__).resolve()), '--local-setup-fixture',
                    'codex', '--repo', str(self.repo), '--revise', '--goal', 'Rebuild reviewed local C change',
                    '--language', 'python', '--editable', 'src,backend,tests', '--files', '',
                    '--python-editable', 'src', '--python-native-wheels', '--setup-only'],
                    self.root / 'pty-rebuild', env={'PTW_USER_STATE': str(self.root / 'native-state')})
                try:
                    terminal.expect('Approve exactly', 20)
                    self.assertIn('Existing history is retained', terminal.text)
                    terminal.send('yes')
                    terminal.wait(lambda: terminal.exited, 90)
                    self.assertIn('Approved.', terminal.text)
                finally:
                    self.assertEqual(terminal.close(), 0)
                record = load(directory / 'project.json')
                self.assertNotEqual(record['project'], old['project'])
                self.assertTrue(store.status(old['project'])['stopped'])
                revised_actor = store.register(record['project'], 'work')
                revised_sets = prepared_sets(store, revised_actor['token'])
                self.assertEqual(len(revised_sets), 1)
                rebuilt = workspace.request(revised_actor['token'], 'test-rebuilt', request('run', 'test',
                    content=json.dumps({'package_sets': [revised_sets[0]['package_set']]})))
                self.assertTrue(rebuilt['allowed'], rebuilt)
                self.assertEqual(rebuilt['exit_code'], 0, rebuilt)
                self.assertIn('EDITABLE_VALUE 99', rebuilt['output'])
                self.assertFalse((self.repo / 'src/local_demo/value.so').exists())
                self.assertIsNone(unrelated.poll())
            print('LOCAL_PYTHON_CLI ' + json.dumps({'approved': True, 'rejected': True, 'cancelled': True,
                'failed_build_rolled_back': True, 'retry': True, 'mode': 'editable' if editable else 'wheel',
                'dynamic_discovery': dynamic,
                'additional_hook_requirements': hook_requirements,
                'compiled_library': native_wheels,
                'import_values': [42, 99] if editable and not dynamic and not native_wheels else [42],
                'compiled_edit_requires_preparation': native_wheels and editable,
                'compiled_reviewed_rebuild_value': 99 if native_wheels and editable else None,
                'stale_wheel_denied': not editable, 'dynamic_edit_requires_preparation': dynamic and editable,
                'source_sha256': bundle['policy']['project']['python_dependencies']['sources'][0]['snapshot_sha256'],
                'policy_sha256': bundle['approval']['sha256'], 'unrelated_alive': True,
                'test_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}), flush=True)
        finally:
            if (directory / 'controller/state.sqlite3').exists():
                store = Store(directory / 'controller')
                with store.locked() as db:
                    projects = [r['id'] for r in db.execute('SELECT id FROM projects')]
                for identity in projects:
                    store.stop(identity)
                Supervisor(store).reconcile()
                remove(store)
            unrelated.terminate()
            unrelated.wait(timeout=5)


class LocalPythonTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ptw-local-python-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        (self.repo / 'src/local_demo').mkdir(parents=True)
        (self.repo / 'backend').mkdir()
        self.private = self.repo / 'unrelated.txt'
        self.private.write_text('UNRELATED_LOCAL_SOURCE')
        self.external = self.root / 'external.txt'
        self.external.write_text('EXTERNAL_CONTROL')
        (self.repo / 'src/local_demo/__init__.py').write_text('VALUE = 42\n')
        (self.repo / 'backend/backend.py').write_text(
            'HOST_PATHS = ' + repr([str(self.private), str(self.external)]) + '\n' + BACKEND)
        (self.repo / 'pyproject.toml').write_text(
            '[project]\nname="local-demo"\nversion="1.0"\n'
            '[build-system]\nrequires=[]\nbuild-backend="backend"\nbackend-path=["backend"]\n')
        self.policy, self.inv = template(self.repo, 'local-python', 'Build explicit fixture source',
            {'src': 'tree', 'backend': 'tree'}, ['pyproject.toml'], [], [], 1, 3)
        self.resources = list(self.inv['resources'])
        self.source = describe_source(self.inv, self.resources, identity='local', allow_build=True)
        self.policy['project']['python_runtime'] = {**identify('/usr/bin/python3'), 'requires_python': ''}
        self.policy['project']['python_dependencies'] = {
            'inputs': {}, 'pins': [], 'artifacts': [], 'sources': [self.source]}

    def activate(self, policy=None, *, pending=False):
        policy = policy or self.policy
        store = Store(self.root / 'controller')
        bundle = approve(policy, self.inv, digest(compile_policy(policy, self.inv)), 'synthetic fixture operator')
        store.activate(bundle, setup_pending=pending)
        actor = (store.register_preparation('local-python', 'work', 'local', bundle['approval']['sha256'])
                 if pending else store.register('local-python', 'work'))
        return store, actor, bundle

    def test_root_requirement_modes_and_declarations_remain_separate_from_registry(self):
        from ptw.dependency_resolution import python_inputs
        metadata = self.repo / 'pyproject.toml'
        metadata.write_text(metadata.read_text().replace('version="1.0"',
            'version="1.0"\ndependencies=["builder>=1,<2"]\nrequires-python=">=3.11"'))
        for entry, mode in [('-e .', 'editable'), ('--editable=./', 'editable'),
                            ('--editable .', 'editable'), ('.', 'wheel'), ('./', 'wheel')]:
            with self.subTest(entry=entry):
                (self.repo / 'requirements.in').write_text(entry + '\nother==2\n')
                values, constraints, inputs, runtime = python_inputs(
                    self.repo, source='requirements.in', local_mode=mode)
                self.assertEqual(values, ['other==2', 'builder>=1,<2'])
                self.assertEqual(constraints, [])
                self.assertEqual(runtime, '>=3.11')
                self.assertEqual(set(inputs), {'pyproject.toml', 'requirements.in'})

    def test_root_requirement_extras_need_explicit_selection_and_preserve_constraints(self):
        from ptw.dependency_resolution import python_inputs
        metadata = self.repo / 'pyproject.toml'
        metadata.write_text(metadata.read_text() + '\n[project.optional-dependencies]\n'
            'feature=["builder>=1,<2"]\n[tool.uv]\nconstraint-dependencies=["builder<1.5"]\n')
        (self.repo / 'requirements.in').write_text('-e .[feature]\n')
        with self.assertRaisesRegex(Invalid, '--python-extras'):
            python_inputs(self.repo, local_mode='editable')
        values, constraints, _, _ = python_inputs(self.repo, local_mode='editable', extras=['feature'])
        self.assertEqual(values, ['builder>=1,<2'])
        self.assertEqual(constraints, ['builder<1.5'])
        for entry in ('-e .[missing]', '-e .[feature,feature]', '-e .[]', '-e .[${EXTRA}]'):
            (self.repo / 'requirements.in').write_text(entry + '\n')
            with self.subTest(entry=entry), self.assertRaises(Invalid):
                python_inputs(self.repo, local_mode='editable', extras=['feature'])

    def test_root_requirement_denies_unapproved_mismatched_duplicate_and_unsafe_paths(self):
        from ptw.dependency_resolution import resolve_python
        from ptw.setup_templates import RULES
        cases = [('-e .', None), ('-e .', 'wheel'), ('.', 'editable'),
                 ('-e .\n-e .', 'editable'), ('-e ../repo', 'editable'),
                 ('-e /tmp/source', 'editable'), ('-e ./src', 'editable'),
                 ('-e ${SOURCE}', 'editable'), ('-e . --config-settings=x=y', 'editable'),
                 ('local-demo @ file:///tmp/source', 'editable')]
        with patch('ptw.python_local.run_build') as build, patch('ptw.dependency_resolution.run_metadata') as run:
            for index, (entry, mode) in enumerate(cases):
                (self.repo / 'requirements.in').write_text(entry + '\n')
                with self.subTest(entry=entry, mode=mode), self.assertRaises(Invalid):
                    resolve_python(self.repo, self.root / ('invalid-' + str(index)), RULES,
                                   local_build=mode is not None, local_mode=mode)
            build.assert_not_called()
            run.assert_not_called()

    def test_root_requirement_constrained_include_and_symlink_are_denied(self):
        from ptw.dependency_resolution import python_inputs
        (self.repo / 'requirements.in').write_text('-c local.txt\n')
        child = self.repo / 'local.txt'
        child.write_text('-e .\n')
        with self.assertRaises(Invalid):
            python_inputs(self.repo, local_mode='editable')
        (self.repo / 'requirements.in').write_text('-r local.txt\n')
        child.unlink()
        child.symlink_to(self.external)
        with self.assertRaises(Invalid):
            python_inputs(self.repo, local_mode='editable')

    def test_root_requirement_only_registry_declarations_reach_native_resolver(self):
        from types import SimpleNamespace
        from ptw.dependency_resolution import resolve_python
        from ptw.setup_templates import RULES
        metadata = self.repo / 'pyproject.toml'
        metadata.write_text(metadata.read_text().replace('version="1.0"',
            'version="1.0"\ndependencies=["builder>=1,<2"]'))
        (self.repo / 'requirements.in').write_text('-e .\n')
        def runner(argv, **kwargs):
            self.assertEqual((Path(kwargs['cwd']) / 'requirements.in').read_text(), 'builder>=1,<2\n')
            self.assertIn('--no-build', argv)
            Path(argv[argv.index('--output-file') + 1]).write_text('builder==1.0\n')
            return SimpleNamespace(returncode=0, stderr='')
        with patch('ptw.python_local.run_build') as build:
            result = resolve_python(self.repo, self.root / 'root-requirement', RULES,
                source='requirements.in', local_build=True, local_mode='editable',
                runner=runner, provider=FixtureProvider())
        build.assert_not_called()
        self.assertEqual(result['pins'], ['builder==1.0'])
        self.assertNotIn('local-demo', json.dumps(result['artifacts']))

    def locked_local_fixture(self):
        metadata = self.repo / 'pyproject.toml'
        metadata.write_text(metadata.read_text().replace('version="1.0"',
            'version="1.0"\ndependencies=["builder>=1,<2"]'))
        (self.repo / 'uv.lock').write_text('version=1\n[[package]]\nname="local-demo"\n'
            'version="1.0"\nsource={editable="."}\n')
        return FixtureProvider().assess('builder', '1.0')['sha256']

    def resolve_locked_local(self, runner, **options):
        from ptw.dependency_resolution import resolve_python
        from ptw.setup_templates import RULES
        return resolve_python(self.repo, Path(tempfile.mkdtemp(prefix='locked-resolution-', dir=self.root)), RULES,
            local_build=True, local_mode='editable', runner=runner,
            provider=options.pop('provider', FixtureProvider()), **options)

    def locked_runner(self, checksum, *, compiled='builder==1.0', fail_export=False):
        from types import SimpleNamespace
        def run(argv, **kwargs):
            if 'export' in argv:
                self.assertIn('--locked', argv)
                self.assertIn('--no-emit-project', argv)
                if fail_export:
                    return SimpleNamespace(returncode=1, stderr='stale lock')
                output = 'builder==1.0 --hash=sha256:' + checksum
            else:
                self.assertIn('--no-build', argv)
                constraints = Path(argv[argv.index('--constraint') + 1]).read_text()
                self.assertIn('builder==1.0 --hash=sha256:' + checksum, constraints)
                self.assertNotIn('local-demo', (Path(kwargs['cwd']) / 'requirements.in').read_text())
                output = compiled
            Path(argv[argv.index('--output-file') + 1]).write_text(output + '\n')
            return SimpleNamespace(returncode=0, stderr='')
        return run

    def test_local_uv_lock_keeps_versions_hashes_and_separate_build_requirements(self):
        checksum = self.locked_local_fixture()
        path = self.repo / 'pyproject.toml'
        path.write_text(path.read_text().replace('requires=[]', 'requires=["build-helper==2"]'))
        with patch('ptw.python_local.run_build') as build:
            result = self.resolve_locked_local(self.locked_runner(checksum,
                compiled='builder==1.0\nbuild-helper==2'))
        build.assert_not_called()
        self.assertEqual(set(result['pins']), {'builder==1.0', 'build-helper==2'})
        self.assertEqual(result['authority'], 'uv.lock')
        self.assertEqual(result['inputs']['uv.lock'], hashlib.sha256((self.repo / 'uv.lock').read_bytes()).hexdigest())
        self.assertEqual(next(r['sha256'] for r in result['artifacts'] if r['name'] == 'builder'), checksum)

    def test_local_uv_lock_rejects_solver_substitution_and_missing_dependency(self):
        checksum = self.locked_local_fixture()
        for output in ('builder==1.5', ''):
            with self.subTest(output=output), self.assertRaisesRegex(Invalid, 'constraint|required dependency'):
                self.resolve_locked_local(self.locked_runner(checksum, compiled=output))

    def test_local_uv_lock_hash_change_between_export_and_resolution_denied(self):
        checksum = self.locked_local_fixture()
        provider = FixtureProvider()
        original = provider.assess
        calls = []
        def assess(name, version):
            record = original(name, version)
            calls.append(name)
            if len(calls) > 1:
                record['sha256'] = '0' * 64
            return record
        provider.assess = assess
        with self.assertRaisesRegex(EvidenceError, 'original requirement hashes'):
            self.resolve_locked_local(self.locked_runner(checksum), provider=provider)

    def test_local_uv_lock_stale_and_forbidden_exports_never_reach_build_resolution(self):
        checksum = self.locked_local_fixture()
        with self.assertRaisesRegex(Invalid, 'lock check/export failed'):
            self.resolve_locked_local(self.locked_runner(checksum, fail_export=True))
        with self.assertRaisesRegex(Invalid, 'forbidden version'):
            self.resolve_locked_local(self.locked_runner(checksum),
                provider=FixtureProvider(changes={'builder': {'vulnerabilities': [CRITICAL]}}))

    def test_local_uv_lock_dynamic_and_external_sources_never_invoke_tools(self):
        self.locked_local_fixture()
        path = self.repo / 'pyproject.toml'
        original = path.read_text()
        path.write_text(original.replace('version="1.0"', 'dynamic=["version"]'))
        with patch('ptw.dependency_resolution.run_metadata') as run:
            with self.assertRaisesRegex(Invalid, 'Dynamic project metadata'):
                self.resolve_locked_local(run, discovery=True)
            path.write_text(original)
            lock = self.repo / 'uv.lock'
            lock.write_text(lock.read_text().replace('editable="."', 'editable="../outside"'))
            with self.assertRaisesRegex(Invalid, 'approved local/private'):
                self.resolve_locked_local(run)
            run.assert_not_called()

    def test_local_uv_lock_shares_evidence_budget_with_build_resolution(self):
        checksum = self.locked_local_fixture()
        provider = FixtureProvider()
        with patch.object(provider, 'assess', wraps=provider.assess) as assess:
            with self.assertRaisesRegex(Invalid, 'assessment limit'):
                self.resolve_locked_local(self.locked_runner(checksum), provider=provider, max_assessments=1)
            self.assertEqual(assess.call_count, 1)

    def test_locked_preparation_binds_read_only_lock_and_denies_changed_inputs(self):
        from ptw.dependency_binding import verify_inputs
        checksum = self.locked_local_fixture()
        plan = self.resolve_locked_local(self.locked_runner(checksum))
        self.locked_install_policy(plan, editable=True)
        store, actor, bundle = self.activate()
        self.assertIn({'resource': 'local-lock', 'actions': ['read']},
                      bundle['policy']['project']['grants'])
        authorized_snapshot(store, actor['token'], 'local')
        verify_inputs(bundle)
        lock = self.repo / 'uv.lock'
        lock.write_text(lock.read_text() + '# changed after approval\n')
        with self.assertRaises(Invalid):
            verify_inputs(bundle)
        with patch('ptw.python_local.run_build') as build:
            with self.assertRaises(Invalid):
                install_editable(store, actor['token'], 'local', provider=FixtureProvider())
            build.assert_not_called()
        with store.locked() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM package_sets').fetchone()[0], 0)

    def locked_install_policy(self, plan, *, editable):
        self.inv['resources']['local-lock'] = {'path': 'uv.lock', 'kind': 'file', 'description': 'Reviewed lock'}
        self.resources.append('local-lock')
        self.policy['project']['grants'].append({'resource': 'local-lock', 'actions': ['read']})
        self.policy['tasks'][0]['grants'].append({'resource': 'local-lock', 'actions': ['read']})
        self.source = describe_source(self.inv, self.resources, identity='local', allow_build=True)
        self.policy['project']['python_runtime'] = plan['runtime']
        self.policy['project']['python_dependencies'] = {
            **{key: plan[key] for key in ('pins', 'artifacts', 'inputs', 'authority')}, 'sources': [self.source]}
        names = ['pypi:' + p.split('==')[0] for p in plan['pins']]
        self.policy['project']['packages']['allowed_names'] = names
        self.policy['tasks'][0]['packages'] = names
        command, narrow = self.editable_policy()
        if not editable:
            self.source = describe_source(self.inv, self.resources, identity='local', allow_build=True)
            self.policy['project']['python_dependencies']['sources'] = [self.source]
        return command, narrow

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_locked_runtime_and_build_graph_wheel_import(self):
        self.native_locked_install(editable=False)

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_locked_runtime_and_build_graph_editable_import(self):
        self.native_locked_install(editable=True)

    def native_locked_install(self, *, editable):
        from ptw.dependency_resolution import resolve_python, run_metadata, resolver_environment, ResolutionError
        from ptw.package_evidence import PyPIEvidence
        from ptw.setup_templates import RULES
        from ptw.monitor import ensure, remove
        from ptw.supervisor import Supervisor
        from ptw.workspace import Workspace, request
        # Actual upstream wheels and native resolution, with explicitly synthetic
        # age/advisory evidence. No public vulnerability status is asserted.
        provider = self.setuptools_project()
        public = PyPIEvidence()
        release = public.json('https://pypi.org/pypi/idna/3.10/json')
        artifact = next(r for r in release['urls'] if r['filename'] == 'idna-3.10-py3-none-any.whl')
        raw = public.fetch(artifact['url'], limit=20 * 1024 * 1024)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), artifact['digests']['sha256'])
        provider.wheels['idna'] = raw
        metadata = self.repo / 'pyproject.toml'
        metadata.write_text(metadata.read_text().replace('version="1.0"',
            'version="1.0"\nrequires-python=">=3.11"\ndependencies=["idna==3.10"]'))
        source = self.repo / 'src/local_demo/__init__.py'
        source.write_text('import idna\nassert idna.encode("example.org") == b"example.org"\nVALUE = 42\n')
        stage = self.root / 'lock-inputs'
        stage.mkdir()
        (stage / metadata.name).write_bytes(metadata.read_bytes())
        result = run_metadata([shutil.which('uv'), '--no-config', '--no-python-downloads',
            '--cache-dir', str(stage / 'cache'), 'lock', '--no-build', '--no-sources',
            '--index-url', 'https://pypi.org/simple', '--python', '/usr/bin/python3'],
            cwd=stage, env=resolver_environment(stage), capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, 'Native nonempty fixture lock generation failed')
        lock = self.repo / 'uv.lock'
        lock.write_bytes((stage / lock.name).read_bytes())
        original = {p.name: p.read_bytes() for p in (metadata, lock)}
        with patch('ptw.python_local.run_build') as build:
            with self.assertRaises(ResolutionError) as conflict:
                resolve_python(self.repo, self.root / 'locked-conflict', RULES,
                    local_build=True, build_requirements=['idna==0'], provider=provider)
            self.assertEqual(conflict.exception.outcome, 'unsatisfiable')
            bad = FixtureProvider(wheels=provider.wheels, changes={'idna': {'sha256': '0' * 64}})
            with self.assertRaisesRegex(EvidenceError, 'digest differs from authoritative lock'):
                resolve_python(self.repo, self.root / 'locked-hash', RULES, local_build=True, provider=bad)
            plan = resolve_python(self.repo, self.root / 'locked-valid', RULES, local_build=True, provider=provider)
            build.assert_not_called()
        self.assertEqual({p.name: p.read_bytes() for p in (metadata, lock)}, original)
        self.assertEqual(plan['authority'], 'uv.lock')
        self.assertEqual(set(plan['pins']), {'idna==3.10', *self.policy['project']['python_dependencies']['pins']})
        self.assertEqual(next(r['sha256'] for r in plan['artifacts'] if r['name'] == 'idna'),
                         artifact['digests']['sha256'])
        command, narrow = self.locked_install_policy(plan, editable=editable)
        command['argv'][-1] = ('import local_demo,idna,importlib.metadata as m; '
            'assert local_demo.VALUE == 42; assert idna.encode("example.org") == b"example.org"; '
            'assert m.version("local-demo") == "1.0"; assert m.version("idna") == "3.10"; '
            'print("LOCKED_LOCAL_OK")')
        store, actor, bundle = self.activate()
        unrelated = subprocess.Popen(['/usr/bin/sleep', '90'])
        try:
            ensure(store)
            install = install_editable if editable else install_wheel
            with patch.dict(os.environ, {'PYTHONPATH': 'SYNTHETIC_LOCAL_INJECTION',
                                          'UV_INDEX_URL': 'SYNTHETIC_LOCAL_INJECTION'}):
                receipt = install(store, actor['token'], 'local', provider=provider)
            workspace = Workspace(store)
            for definition in (command, narrow):
                result = workspace.request(actor['token'], definition['id'], request('run', definition['id'],
                    content=json.dumps({'package_sets': [receipt['package_set']]})))
                self.assertEqual(result['allowed'], definition is command, result)
                if definition is command:
                    self.assertEqual(result['exit_code'], 0, result)
                    self.assertEqual(result['output'].strip(), 'LOCKED_LOCAL_OK')
                else:
                    self.assertIn('command inputs', result['reason'])
            self.assertEqual(store.status('local-python')['policy_sha256'], bundle['approval']['sha256'])
            self.assertEqual({p.name: p.read_bytes() for p in (metadata, lock)}, original)
            self.assertEqual(self.private.read_text(), 'UNRELATED_LOCAL_SOURCE')
            self.assertEqual(self.external.read_text(), 'EXTERNAL_CONTROL')
            store.stop('local-python')
            Supervisor(store).reconcile()
            self.assertIsNone(unrelated.poll())
            print('LOCAL_PYTHON_LOCKED_GRAPH ' + json.dumps({
                'mode': self.source['mode'], 'pins': plan['pins'], 'inputs': plan['inputs'],
                'artifacts': plan['artifacts'], 'policy_sha256': bundle['approval']['sha256'],
                'import': True, 'conflict_denied': True, 'hash_denied': True, 'narrow_denied': True,
                'unrelated_alive': True,
                'test_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}), flush=True)
        finally:
            store.stop('local-python')
            Supervisor(store).reconcile()
            remove(store)
            unrelated.terminate()
            unrelated.wait(timeout=5)

    def test_requirements_preparation_without_root_entry_never_runs_tools(self):
        from ptw.dependency_resolution import resolve_python
        from ptw.setup_templates import RULES
        (self.repo / 'requirements.in').write_text('builder==1.0\n')
        metadata = self.repo / 'pyproject.toml'
        with patch('ptw.python_local.run_build') as build, patch('ptw.dependency_resolution.run_metadata') as run:
            for dynamic in (False, True):
                if dynamic:
                    metadata.write_text(metadata.read_text().replace('version="1.0"', 'dynamic=["version"]'))
                with self.subTest(dynamic=dynamic), self.assertRaisesRegex(Invalid, 'explicit root entry'):
                    resolve_python(self.repo, self.root / ('no-root-' + str(dynamic)), RULES,
                        source='requirements.in', local_build=True, local_mode='wheel', discovery=dynamic)
            run.assert_not_called()
            build.assert_not_called()

    def test_static_hook_refinement_cannot_change_source_mode_or_identity(self):
        import copy
        store, actor, bundle = self.activate(pending=True)
        store.close_session(actor['token'])
        for field, value in (('id', 'replacement'), ('version', '2.0'), ('allow_build', False)):
            changed = copy.deepcopy(self.policy)
            changed['project']['python_dependencies']['sources'][0][field] = value
            approval = approve(changed, self.inv, digest(compile_policy(changed, self.inv)), 'fixture operator')
            with self.subTest(field=field), self.assertRaisesRegex(Invalid, 'source binding'):
                store.activate(approval, setup_pending=True, discovery_sha256=bundle['approval']['sha256'])
            self.assertEqual(store.status('local-python')['policy_sha256'], bundle['approval']['sha256'])
        self.editable_policy()
        changed = approve(self.policy, self.inv, digest(compile_policy(self.policy, self.inv)), 'fixture operator')
        with self.assertRaisesRegex(Invalid, 'source binding'):
            store.activate(changed, setup_pending=True, discovery_sha256=bundle['approval']['sha256'])

    def test_pending_preparation_cannot_use_ordinary_tools_or_delegate(self):
        from ptw.supervisor import Supervisor
        from ptw.workspace import Workspace, request
        from ptw.packages import PackageControl
        store, actor, bundle = self.activate(pending=True)
        self.assertEqual(actor['commands'], [])
        self.assertTrue(all(g['actions'] == ['read'] for g in actor['grants']))
        source, entries, _, approval = authorized_snapshot(store, actor['token'], 'local')
        self.assertEqual(source, self.source)
        self.assertEqual(approval, bundle['approval']['sha256'])
        self.assertNotIn('unrelated.txt', entries)
        with patch('ptw.supervisor.subprocess.Popen') as launch, store.locked() as db:
            for action in (
                lambda: store.session(db, actor['token']),
                lambda: Workspace(store).inspect(db, actor['token'], 'read', request('read', resource=self.resources[0])),
                lambda: PackageControl(store).inspect(db, actor['token'], 'install', {}, {}, 'a' * 64),
            ):
                with self.assertRaisesRegex(Invalid, 'ordinary project actions'):
                    action()
            launch.assert_not_called()
        with patch('ptw.supervisor.subprocess.Popen') as launch:
            for action in (
                lambda: Supervisor(store).engine(actor['token'], ['/usr/bin/true']),
                lambda: Supervisor(store).engine(actor['token'], ['/usr/bin/true'], preparation=True, terminal=True),
                lambda: Supervisor(store).launch(actor['token'], ['/usr/bin/true']),
                lambda: store.register('local-python', 'work', parent_token=actor['token']),
                lambda: store.register('local-python', 'work'),
            ):
                with self.assertRaises(Invalid):
                    action()
            launch.assert_not_called()
        self.assertEqual(store.status('local-python')['violations'], 0)

    def test_preparation_requires_exact_pending_approval_and_task_scope(self):
        store, actor, bundle = self.activate()
        approval = bundle['approval']['sha256']
        with self.assertRaisesRegex(Invalid, 'pending setup'):
            store.register_preparation('local-python', 'work', 'local', approval)
        # A second independently approved pending project, with a narrower task.
        policy = copy.deepcopy(self.policy)
        policy['project']['id'] = 'pending-local'
        policy['tasks'][1]['grants'] = policy['tasks'][1]['grants'][:1]
        pending = approve(policy, self.inv, digest(compile_policy(policy, self.inv)), 'fixture operator')
        store.activate(pending, setup_pending=True)
        approval = pending['approval']['sha256']
        for task, identity, expected in [('work', 'local', '0' * 64), ('work', 'missing', approval),
                                         ('missing', 'local', approval), ('verify', 'local', approval)]:
            with self.subTest(task=task, identity=identity), self.assertRaises(Invalid):
                store.register_preparation('pending-local', task, identity, expected)
        preparation = store.register_preparation('pending-local', 'work', 'local', approval)
        with self.assertRaisesRegex(Invalid, 'active preparation'):
            store.register_preparation('pending-local', 'work', 'local', approval)
        with self.assertRaisesRegex(Invalid, 'another source'):
            authorized_snapshot(store, preparation['token'], 'missing')
        with patch('ptw.python_local.run_build') as run:
            from ptw.python_local import run_source_build
            with self.assertRaisesRegex(Invalid, 'another source'):
                run_source_build(store, preparation['token'], 'missing', [], self.root)
            run.assert_not_called()
        store.stop('pending-local')
        with self.assertRaisesRegex(Invalid, 'pending setup'):
            store.register_preparation('pending-local', 'work', 'local', approval)
        with self.assertRaisesRegex(Invalid, 'unstopped pending'):
            authorized_snapshot(store, preparation['token'], 'local')
        # The existing active project is independent.
        with store.locked() as db:
            self.assertEqual(store.session(db, actor['token'])['project'], 'local-python')

    def test_preparation_cannot_expand_package_task_scope_or_execute_unapproved_source(self):
        provider = FixtureProvider()
        self.registry_graph(provider)
        self.source['allow_build'] = False
        store = Store(self.root / 'controller')
        bundle = approve(self.policy, self.inv, digest(compile_policy(self.policy, self.inv)), 'fixture')
        store.activate(bundle, setup_pending=True)
        with self.assertRaisesRegex(Invalid, 'explicitly approved'):
            store.register_preparation('local-python', 'work', 'local', bundle['approval']['sha256'])
        policy = copy.deepcopy(self.policy)
        policy['project']['id'] = 'pending-local'
        policy['project']['python_dependencies']['sources'][0]['allow_build'] = True
        policy['tasks'][0]['packages'] = []
        bundle = approve(policy, self.inv, digest(compile_policy(policy, self.inv)), 'fixture')
        store.activate(bundle, setup_pending=True)
        with self.assertRaisesRegex(Invalid, 'package grants'):
            store.register_preparation('pending-local', 'work', 'local', bundle['approval']['sha256'])

    def test_commit_requires_closed_preparation_and_confirmed_termination(self):
        store, actor, bundle = self.activate(pending=True)
        approval = bundle['approval']['sha256']
        with self.assertRaisesRegex(Invalid, 'sessions must end'):
            store.commit_setup('local-python', approval, lambda: None)
        store.close_session(actor['token'])
        unit = 'ptw-' + '1' * 24 + '.service'
        with store.locked() as db:
            db.execute('INSERT INTO workloads(unit,project,session) VALUES(?,?,?)',
                       (unit, 'local-python', actor['session']))
        with self.assertRaisesRegex(Invalid, 'termination must be confirmed'):
            store.commit_setup('local-python', approval, lambda: None)
        with patch('ptw.supervisor.Supervisor.terminate', return_value={'confirmed_stopped': True}):
            from ptw.supervisor import Supervisor
            self.assertEqual(Supervisor(store).reconcile(), [{'unit': unit, 'confirmed_stopped': True}])
        store.commit_setup('local-python', approval, lambda: None)
        ordinary = store.register('local-python', 'work')
        with store.locked() as db:
            self.assertIsNone(store.session(db, ordinary['token'])['preparation_source'])
            with self.assertRaisesRegex(Invalid, 'Session ended'):
                store.session(db, actor['token'], preparation=True)
        with self.assertRaisesRegex(Invalid, 'pending setup'):
            store.register_preparation('local-python', 'work', 'local', approval)

    def test_reopened_controller_retains_pending_scope_and_stop_blocks_commit(self):
        store, actor, bundle = self.activate(pending=True)
        store = Store(store.directory)
        with self.assertRaisesRegex(Invalid, 'pending recovery'):
            store.register('local-python', 'work')
        with store.locked() as db:
            self.assertEqual(store.session(db, actor['token'], preparation=True)['preparation_source'], 'local')
        store.close_session(actor['token'])
        store.stop('local-python')
        with self.assertRaisesRegex(Invalid, 'Stopped'):
            store.commit_setup('local-python', bundle['approval']['sha256'], lambda: None)
        self.assertTrue(store.status('local-python')['stopped'])

    def test_root_location_only_snapshots_explicit_resources(self):
        store, actor, _ = self.activate()
        source, entries, _, _ = authorized_snapshot(store, actor['token'], 'local')
        self.assertEqual(source['path'], '')
        self.assertIn('backend/backend.py', entries)
        self.assertIn('src/local_demo/__init__.py', entries)
        self.assertNotIn('unrelated.txt', entries)
        self.assertNotIn('pypi:local-demo', self.policy['project']['packages']['allowed_names'])

    def test_unapproved_and_unknown_build_never_invoke_tool(self):
        self.source['allow_build'] = False
        store, actor, _ = self.activate()
        with patch('ptw.python_local.run_build') as run:
            for identity in ('local', 'unknown'):
                with self.subTest(identity=identity), self.assertRaisesRegex(Invalid, 'explicit approval'):
                    build_wheel(store, actor['token'], identity)
            run.assert_not_called()
        self.assertFalse(list(store.directory.glob('local-build-*')))

    def test_delegate_read_scope_and_revocation_are_required(self):
        store, actor, _ = self.activate()
        child = store.register('local-python', 'work', parent_token=actor['token'],
            grants=[{'resource': self.resources[0], 'actions': ['read']}], commands=[])
        with patch('ptw.python_local.run_build') as run:
            with self.assertRaisesRegex(Invalid, 'session read grants'):
                build_wheel(store, child['token'], 'local')
            store.close_session(actor['token'])
            with self.assertRaisesRegex(Invalid, 'Session ended'):
                build_wheel(store, actor['token'], 'local')
            run.assert_not_called()

    def test_traversal_unbound_backend_and_symlink_rejected(self):
        for path in ('../outside', '/absolute', 'src/../backend', 'src\\backend'):
            with self.subTest(path=path), self.assertRaises(Invalid):
                describe_source(self.inv, self.resources, identity='local', path=path)
        metadata = self.repo / 'pyproject.toml'
        original = metadata.read_text()
        for backend in ('../outside', '/absolute', 'missing'):
            metadata.write_text(original.replace('backend-path=["backend"]', 'backend-path=[' + json.dumps(backend) + ']'))
            with self.subTest(backend=backend), self.assertRaises(Invalid):
                describe_source(self.inv, self.resources, identity='local')
        metadata.write_text(original)
        (self.repo / 'src/link.py').symlink_to(self.external)
        with self.assertRaises(Invalid):
            describe_source(self.inv, self.resources, identity='local')

    def test_metadata_and_identity_ambiguity_fail_closed(self):
        for addition in ('dynamic=["description"]\n', 'dependencies=["demo @ https://example.invalid/demo.whl"]\n'):
            text = (self.repo / 'pyproject.toml').read_text()
            (self.repo / 'pyproject.toml').write_text(text.replace('[build-system]', addition + '[build-system]'))
            with self.subTest(addition=addition), self.assertRaises(Invalid):
                describe_source(self.inv, self.resources, identity='local')
            (self.repo / 'pyproject.toml').write_text(text)
        candidate = copy.deepcopy(self.policy)
        candidate['project']['python_dependencies']['sources'].append(copy.deepcopy(self.source))
        with self.assertRaisesRegex(Invalid, 'ambiguous'):
            compile_policy(candidate, self.inv)
        candidate = copy.deepcopy(self.policy)
        candidate['project']['python_dependencies'].update(pins=['local-demo==1.0'], artifacts=[{
            'name': 'local-demo', 'version': '1.0', 'url': 'https://example.invalid/demo.whl', 'sha256': 'a' * 64}])
        candidate['project']['packages']['allowed_names'] = ['pypi:local-demo']
        with self.assertRaisesRegex(Invalid, 'ambiguous'):
            compile_policy(candidate, self.inv)

    def test_mutation_before_build_rejected_without_execution(self):
        store, actor, _ = self.activate()
        (self.repo / 'src/local_demo/__init__.py').write_text('VALUE = 43\n')
        with patch('ptw.python_local.run_build') as run:
            with self.assertRaisesRegex(Invalid, 'changed since build review'):
                build_wheel(store, actor['token'], 'local')
            run.assert_not_called()

    def optional_project(self, extras=()):
        metadata = self.repo / 'pyproject.toml'
        metadata.write_text(metadata.read_text() + '\n[project.optional-dependencies]\n'
            'feature=["builder>=1,<2"]\n'
            'unused=["absent>=9; python_version < \'1\'"]\nempty=[]\n')
        self.source = describe_source(self.inv, self.resources, identity='local', allow_build=True, extras=extras)
        self.policy['project']['python_dependencies']['sources'] = [self.source]

    def test_local_extras_parse_resolve_and_bind_without_backend_execution(self):
        from ptw.dependency_resolution import python_inputs
        from ptw.python_local import static_metadata
        from ptw.workspace import scan
        self.optional_project(['Feature', 'empty'])
        with patch('ptw.python_local.run_build') as build:
            requirements, _, inputs, _ = python_inputs(self.repo, extras=['feature', 'empty'])
            self.assertEqual(requirements, ['builder>=1,<2'])
            self.assertEqual(self.source['extras'], ['empty', 'feature'])
            self.assertEqual(inputs['pyproject.toml'], hashlib.sha256((self.repo / 'pyproject.toml').read_bytes()).hexdigest())
            static_metadata(scan(self.inv, self.resources), '', selected={'builder': '1.0'}, extras=['feature'])
            static_metadata(scan(self.inv, self.resources), '', selected={}, extras=[])
            with self.assertRaisesRegex(Invalid, 'compatible resolution'):
                static_metadata(scan(self.inv, self.resources), '', selected={}, extras=['feature'])
            build.assert_not_called()

    def test_extra_selection_and_malformed_inactive_declarations_fail_closed(self):
        from ptw.dependency_resolution import optional_dependencies
        self.optional_project()
        with patch('ptw.python_local.run_build') as build:
            for extras in (['unknown'], ['feature', 'Feature'], 'feature', [None]):
                with self.subTest(extras=extras), self.assertRaises(Invalid):
                    describe_source(self.inv, self.resources, identity='local', extras=extras)
            for value in ({'a.b': [], 'a-b': []}, {'bad/name': []}, {'a': 'builder'},
                          {'a': [False]}, {'inactive': ['thing @ file:///tmp/thing.whl']}):
                with self.subTest(optional=value), self.assertRaises(Invalid):
                    optional_dependencies({'optional-dependencies': value})
            build.assert_not_called()

    def test_extra_metadata_cannot_drop_invent_or_activate_dependencies(self):
        from email.parser import BytesParser
        from ptw.python_local import validate_output_metadata
        from ptw.workspace import scan
        self.optional_project(['feature'])
        declarations = ('Provides-Extra: feature\nProvides-Extra: unused\nProvides-Extra: empty\n'
            'Requires-Dist: builder<2,>=1; extra == "feature"\n'
            'Requires-Dist: absent>=9; python_version < "1" and extra == "unused"\n')
        def metadata(text):
            return BytesParser().parsebytes(('Name: local-demo\nVersion: 1.0\n' + text).encode())
        entries = scan(self.inv, self.resources)
        validate_output_metadata(metadata(declarations), entries, self.source)
        for changed in (declarations.replace('Provides-Extra: empty\n', ''),
                        declarations + 'Provides-Extra: feature\n',
                        declarations.replace('extra == "feature"', 'extra == "empty"'),
                        declarations.replace('; extra == "feature"', ''),
                        declarations.replace('builder<2,>=1', 'builder>=1'),
                        declarations.replace('Requires-Dist: absent>=9; python_version < "1" and extra == "unused"\n', '')):
            with self.subTest(metadata=changed), self.assertRaises(EvidenceError):
                validate_output_metadata(metadata(changed), entries, self.source)

    def test_unreviewed_extra_graph_denies_build_and_editable_install(self):
        self.optional_project(['feature'])
        store, actor, _ = self.activate()
        with patch('ptw.python_local.run_build') as build:
            with self.assertRaisesRegex(Invalid, 'compatible resolution'):
                build_wheel(store, actor['token'], 'local')
            build.assert_not_called()
        with store.locked() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM package_sets').fetchone()[0], 0)

    def test_self_referencing_extra_never_resolves_local_name_as_public(self):
        from ptw.dependency_resolution import resolve_python
        from ptw.setup_templates import RULES
        self.optional_project()
        metadata = self.repo / 'pyproject.toml'
        metadata.write_text(metadata.read_text().replace('builder>=1,<2', 'local-demo[empty]'))
        with patch('ptw.dependency_resolution.run_metadata') as resolver, patch('ptw.python_local.run_build') as build:
            plan = resolve_python(self.repo, self.root / 'self-reference', RULES, local_build=True, extras=['feature'])
            self.assertEqual(plan['pins'], [])
            self.assertEqual(plan['artifacts'], [])
            resolver.assert_not_called()
            build.assert_not_called()

    def test_self_referencing_extra_closure_preserves_registry_constraints(self):
        from ptw.dependency_resolution import resolve_python
        from ptw.setup_templates import RULES
        from types import SimpleNamespace
        self.optional_project()
        metadata = self.repo / 'pyproject.toml'
        metadata.write_text(metadata.read_text() + 'all=["local-demo[feature,empty]==1.0"]\n')
        def runner(argv, **kwargs):
            self.assertEqual((Path(kwargs['cwd']) / 'requirements.in').read_text(), 'builder>=1,<2\n')
            Path(argv[argv.index('--output-file') + 1]).write_text('builder==1.0\n')
            return SimpleNamespace(returncode=0, stderr='')
        plan = resolve_python(self.repo, self.root / 'closure', RULES, local_build=True,
                              extras=['all'], provider=FixtureProvider(), runner=runner)
        self.assertEqual(plan['pins'], ['builder==1.0'])
        self.assertEqual([r['name'] for r in plan['artifacts']], ['builder'])
        from ptw.python_local import static_metadata
        from ptw.workspace import scan
        with self.assertRaisesRegex(Invalid, 'reviewed compatible resolution'):
            static_metadata(scan(self.inv, self.resources), '', selected={}, extras=['all'])
        static_metadata(scan(self.inv, self.resources), '', selected={'builder': '1.0'}, extras=['all'])

    def test_self_reference_cycles_markers_and_invalid_identity_fail_closed(self):
        from ptw.dependency_resolution import expand_local_requirements
        project = {'name': 'local-demo', 'version': '1.0', 'optional-dependencies': {
            'a': ['local-demo[b]', 'builder>=1,<2'], 'b': ['local-demo[a]']}}
        env = {'python_version': '3.12'}
        self.assertEqual(expand_local_requirements(project, ['LOCAL_demo[a]'], env), ['builder>=1,<2'])
        self.assertEqual(expand_local_requirements(project,
            ['local-demo[missing]>=99; python_version < "1"'], env), [])
        for raw in ('local-demo>=2', 'local-demo[missing]', 'local-demo @ file:///tmp/local.whl'):
            with self.subTest(raw=raw), self.assertRaises(Invalid):
                expand_local_requirements(project, [raw], env)
        with self.assertRaisesRegex(Invalid, 'Too many'):
            expand_local_requirements(project, ['local-demo'] * 1025, env)

    def test_local_build_requirement_never_substitutes_public_namesake(self):
        from ptw.dependency_resolution import resolve_python
        from ptw.setup_templates import RULES
        metadata = self.repo / 'pyproject.toml'
        metadata.write_text(metadata.read_text().replace('requires=[]', 'requires=["local-demo==1.0"]'))
        with patch('ptw.dependency_resolution.run_metadata') as resolver, patch('ptw.python_local.run_build') as build:
            for discovery in (False, True):
                with self.subTest(discovery=discovery), self.assertRaises(Invalid):
                    resolve_python(self.repo, self.root / str(discovery), RULES,
                                   local_build=True, discovery=discovery)
            with self.assertRaisesRegex(Invalid, 'Build requirement'):
                describe_source(self.inv, self.resources, identity='local')
            resolver.assert_not_called()
            build.assert_not_called()

    def test_local_constraints_check_source_version_without_public_lookup(self):
        from ptw.dependency_resolution import resolve_python
        from ptw.setup_templates import RULES
        metadata = self.repo / 'pyproject.toml'
        original = metadata.read_text()
        for index, constraint in enumerate(('local-demo==1.0', 'local-demo>=2', 'local-demo[feature]')):
            metadata.write_text(original + '\n[tool.uv]\nconstraint-dependencies=[' + json.dumps(constraint) + ']\n')
            with self.subTest(constraint=constraint), patch('ptw.dependency_resolution.run_metadata') as resolver:
                if index:
                    with self.assertRaises(Invalid):
                        resolve_python(self.repo, self.root / str(index), RULES, local_build=True)
                else:
                    self.assertEqual(resolve_python(self.repo, self.root / str(index), RULES,
                                                    local_build=True)['pins'], [])
                resolver.assert_not_called()

    def test_discovery_preserves_static_extras_and_rejects_changed_declarations(self):
        from email.parser import BytesParser
        from ptw.python_local import discovered_metadata
        from ptw.workspace import scan
        self.optional_project()
        metadata = self.repo / 'pyproject.toml'
        metadata.write_text(metadata.read_text().replace('version="1.0"', 'dynamic=["version","dependencies"]'))
        source = describe_source(self.inv, self.resources, identity='local', allow_build=True,
                                 discovery=True, extras=['feature'])
        entries = scan(self.inv, self.resources)
        raw = ('Name: local-demo\nVersion: 1.0\nProvides-Extra: feature\nProvides-Extra: unused\n'
               'Provides-Extra: empty\nRequires-Dist: base>=2\n'
               'Requires-Dist: Builder <2, >=1; extra == "feature"\n'
               'Requires-Dist: absent>=9; python_version < "1" and extra == "unused"\n\n')
        result = discovered_metadata(BytesParser().parsebytes(raw.encode()), entries, source, '1.0')
        self.assertEqual(result, {'version': '1.0', 'dependencies': ['base>=2']})
        for bad in (raw.replace('Builder <2, >=1', 'Builder>=2'),
                    raw.replace('Provides-Extra: unused\n', ''),
                    raw.replace('base>=2', 'base @ file:///tmp/unapproved.whl')):
            with self.subTest(bad=bad), self.assertRaises(EvidenceError):
                discovered_metadata(BytesParser().parsebytes(bad.encode()), entries, source, '1.0')

    def dynamic_optional_project(self, *, dynamic_dependencies=False):
        from ptw.workspace import scan
        metadata = self.repo / 'pyproject.toml'
        metadata.write_text(metadata.read_text().replace('version="1.0"',
            'version="1.0"\ndynamic=["optional-dependencies"' +
            (',"dependencies"' if dynamic_dependencies else '') + ']'))
        source = describe_source(self.inv, self.resources, identity='local', allow_build=True,
                                 discovery=True, extras=['feature'])
        raw = ('Name: local-demo\nVersion: 1.0\nProvides-Extra: feature\n'
               'Provides-Extra: empty\nProvides-Extra: unused\n'
               'Requires-Dist: builder>=1,<2; python_version >= "3" and extra == "feature"\n'
               'Requires-Dist: absent>=9; extra == "unused"\n\n')
        return source, scan(self.inv, self.resources), raw

    def test_dynamic_optional_discovery_preserves_inactive_empty_and_environment_markers(self):
        from email.parser import Parser
        from ptw.python_local import discovered_metadata, validate_output_metadata
        source, entries, raw = self.dynamic_optional_project()
        result = discovered_metadata(Parser().parsestr(raw), entries, source, '1.0')
        self.assertEqual(result, {'optional-dependencies': {
            'feature': ['builder<2,>=1; python_version >= "3"'], 'empty': [], 'unused': ['absent>=9']}})
        for mode in ('wheel', 'editable'):
            reviewed = {**source, 'mode': mode, 'dynamic_metadata': result}
            validate_output_metadata(Parser().parsestr(raw), entries, reviewed)
            with self.subTest(mode=mode), self.assertRaises(EvidenceError):
                validate_output_metadata(Parser().parsestr(raw.replace('builder>=1,<2', 'builder>=2')), entries, reviewed)

    def test_dynamic_optional_unknown_selection_waits_for_output_but_never_for_install(self):
        from email.parser import Parser
        from ptw.dependency_resolution import python_inputs
        from ptw.python_local import discovered_metadata
        source, entries, raw = self.dynamic_optional_project()
        self.assertEqual(python_inputs(self.repo, extras=['feature'], discovery=True)[0], [])
        for extras in (['feature', 'Feature'], ['bad/name'], [None]):
            with self.subTest(extras=extras), self.assertRaises(Invalid):
                python_inputs(self.repo, extras=extras, discovery=True)
        with self.assertRaises(Invalid):
            discovered_metadata(Parser().parsestr(raw), entries, {**source, 'extras': ['missing']}, '1.0')
        with self.assertRaises(Invalid):
            python_inputs(self.repo, extras=['feature'])

    def test_dynamic_optional_output_cannot_change_static_base_or_hide_unsafe_inactive_inputs(self):
        from email.parser import Parser
        from ptw.python_local import discovered_metadata
        source, entries, raw = self.dynamic_optional_project()
        invalid = [raw.replace('absent>=9', 'absent @ file:///outside.whl'),
                   raw.replace('Provides-Extra: empty', 'Provides-Extra: FEATURE'),
                   raw.replace('extra == "unused"', 'extra == "missing"'),
                   raw.replace('python_version >= "3" and extra', 'python_version >= "3" or extra'),
                   raw.replace('Requires-Dist: absent', 'Requires-Dist: unapproved-base\nRequires-Dist: absent'),
                   raw.replace('Provides-Extra: empty', 'Provides-Extra: invalid/name'),
                   raw.replace('Provides-Extra: empty', '\n'.join('Provides-Extra: e' + str(n) for n in range(65)))]
        for bad in invalid:
            with self.subTest(metadata=bad), self.assertRaises((EvidenceError, Invalid)):
                discovered_metadata(Parser().parsestr(bad), entries, source, '1.0')

    def test_dynamic_optional_and_base_discovery_remain_separate(self):
        from email.parser import Parser
        from ptw.python_local import discovered_metadata
        source, entries, raw = self.dynamic_optional_project(dynamic_dependencies=True)
        raw = raw.replace('Requires-Dist: builder', 'Requires-Dist: base>=2\nRequires-Dist: builder')
        result = discovered_metadata(Parser().parsestr(raw), entries, source, '1.0')
        self.assertEqual(result['dependencies'], ['base>=2'])
        self.assertEqual(set(result['optional-dependencies']), {'feature', 'empty', 'unused'})

    def test_dynamic_optional_resolver_and_source_review_bind_selected_graph(self):
        from email.parser import Parser
        from ptw.dependency_resolution import python_inputs
        from ptw.python_local import discovered_metadata, static_metadata
        source, entries, raw = self.dynamic_optional_project()
        result = discovered_metadata(Parser().parsestr(raw), entries, source, '1.0')
        requirements, _, _, _ = python_inputs(self.repo, extras=['feature'], dynamic_metadata=result)
        self.assertEqual(requirements, ['builder<2,>=1; python_version >= "3"'])
        self.assertEqual(python_inputs(self.repo, extras=['empty'], dynamic_metadata=result)[0], [])
        reviewed = describe_source(self.inv, self.resources, identity='local', allow_build=True,
                                   dynamic_metadata=result, extras=['feature'])
        self.policy['project']['python_dependencies']['sources'] = [reviewed]
        compile_policy(self.policy, self.inv)
        static_metadata(entries, '', selected={'builder': '1.0'}, extras=['feature'], dynamic_metadata=result)
        with self.assertRaisesRegex(Invalid, 'compatible resolution'):
            static_metadata(entries, '', selected={}, extras=['feature'], dynamic_metadata=result)
        result['optional-dependencies']['feature'].append('injected>=1')
        self.assertNotIn('injected>=1', reviewed['dynamic_metadata']['optional-dependencies']['feature'])

    def test_selected_extra_output_closure_is_checked_for_both_install_modes(self):
        from io import BytesIO
        import zipfile
        from ptw.python_local import validate_editable_install
        from ptw.workspace import scan
        self.optional_project(['feature'])
        requires = ['builder>=1,<2; extra == "feature"', 'absent>=9; python_version < "1" and extra == "unused"']
        raw = ('Name: local-demo\nVersion: 1.0\nProvides-Extra: feature\nProvides-Extra: unused\n'
               'Provides-Extra: empty\n' + ''.join('Requires-Dist: ' + r + '\n' for r in requires)).encode()
        wheel = wheel_bytes('local-demo', '1.0', extra={'local-demo-1.0.dist-info/METADATA': raw})
        provider = FixtureProvider()
        self.registry_graph(provider)
        store, actor, _ = self.activate()
        def build(store, token, command, output):
            (output / 'out').mkdir()
            (output / 'out/local_demo-1.0-py3-none-any.whl').write_bytes(wheel)
        with patch('ptw.python_local.run_build', side_effect=build):
            data, _ = build_wheel(store, actor['token'], 'local', provider=provider)
        self.assertEqual(data, wheel)
        site = self.root / 'editable-site'
        site.mkdir()
        with zipfile.ZipFile(BytesIO(wheel)) as archive:
            archive.extractall(site)
        (site / 'local-demo-1.0.dist-info/direct_url.json').write_text(
            json.dumps({'url': 'file:///target', 'dir_info': {'editable': True}}))
        source = {**self.source, 'mode': 'editable'}
        for selected in ({}, {'builder': '2.0'}):
            with self.assertRaisesRegex(EvidenceError, 'Missing, incompatible'):
                validate_editable_install(site, source, selected, '/usr/bin/python3', scan(self.inv, self.resources))
        validate_editable_install(site, source, {'builder': '1.0'}, '/usr/bin/python3', scan(self.inv, self.resources))

    def test_editable_added_dependency_extra_cannot_escape_combined_graph_check(self):
        import zipfile
        from io import BytesIO
        provider = FixtureProvider(wheels={'builder': wheel_bytes('builder', '1.0', extra={
            'builder-1.0.dist-info/METADATA': b'Name: builder\nVersion: 1.0\nProvides-Extra: child\n'
            b'Requires-Dist: missing>=1; extra == "child"\n'})})
        self.registry_graph(provider)
        self.editable_policy()
        store, actor, _ = self.activate()
        def build(store, token, command, target):
            self.fake_editable(store, token, command, target)
            info = next((target / '.ptw-local-site').glob('*.dist-info'))
            (info / 'METADATA').write_text((info / 'METADATA').read_text() + 'Requires-Dist: builder[child]>=1\n')
        def install(wheelhouse, site, records, **kwargs):
            site.mkdir()
            with zipfile.ZipFile(BytesIO(provider.wheels['builder'])) as archive:
                archive.extractall(site)
        with patch('ptw.python_local.run_build', side_effect=build), \
                patch('ptw.python_local.install_wheels', side_effect=install):
            with self.assertRaisesRegex(EvidenceError, 'Missing, incompatible.*missing'):
                install_editable(store, actor['token'], 'local', provider=provider)
        with store.locked() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM package_sets').fetchone()[0], 0)
        self.assertFalse(list(store.directory.glob('local-install-*')))

    def dynamic_project(self, expected=None):
        metadata = self.repo / 'pyproject.toml'
        metadata.write_text(metadata.read_text().replace('version="1.0"', 'dynamic=["version", "dependencies"]'))
        expected = expected if expected is not None else {'version': '1.0', 'dependencies': []}
        self.source = describe_source(self.inv, self.resources, identity='local', allow_build=True,
                                      dynamic_metadata=expected)
        self.policy['project']['python_dependencies']['sources'] = [self.source]
        return expected

    def test_dynamic_review_is_data_and_missing_or_unapproved_values_never_execute(self):
        expected = self.dynamic_project()
        with patch('ptw.python_local.run_build') as run:
            for values in (None, {}, {'version': '1.0'}, {'version': '1.0', 'dependencies': 'builder'}):
                with self.subTest(values=values), self.assertRaises(Invalid):
                    describe_source(self.inv, self.resources, identity='local', dynamic_metadata=values)
            expected['dependencies'].append('not-approved==1')
            self.assertEqual(self.source['dynamic_metadata']['dependencies'], [])
            self.source['allow_build'] = False
            store, actor, _ = self.activate()
            with self.assertRaisesRegex(Invalid, 'explicit approval'):
                build_wheel(store, actor['token'], 'local')
            run.assert_not_called()

    def test_dynamic_declarations_reject_conflicts_duplicates_and_urls(self):
        metadata = self.repo / 'pyproject.toml'
        original = metadata.read_text()
        for malformed in ('project=[]\n[build-system]\nrequires=[]\n',
                          'build-system=[]\n[project]\nname="local-demo"\nversion="1.0"\n'):
            metadata.write_text(malformed)
            with self.subTest(malformed=malformed), self.assertRaisesRegex(Invalid, 'must be tables'):
                describe_source(self.inv, self.resources, identity='local')
        for field in ('dynamic=["version"]', 'dynamic=["name"]', 'dynamic="version"',
                      'dynamic=["dependencies", "dependencies"]'):
            metadata.write_text(original.replace('[build-system]', field + '\n[build-system]'))
            with self.subTest(field=field), self.assertRaises(Invalid):
                describe_source(self.inv, self.resources, identity='local', dynamic_metadata={'version': '1.0'})
        metadata.write_text(original)
        with self.assertRaisesRegex(Invalid, 'URL dependencies'):
            self.dynamic_project({'version': '1.0', 'dependencies': ['builder @ file:///tmp/builder.whl']})

    def test_dynamic_output_must_match_reviewed_metadata_even_when_graph_is_compatible(self):
        self.dynamic_project({'version': '1.0', 'dependencies': ['builder>=1,<2']})
        provider = FixtureProvider()
        self.registry_graph(provider)
        store, actor, bundle = self.activate()
        def result(requirements, version='1.0'):
            def build(store, token, command, target):
                (target / 'out').mkdir()
                (target / ('out/local_demo-' + version + '-py3-none-any.whl')).write_bytes(
                    wheel_bytes('local-demo', version, requires=requirements))
            return build
        for requirements, version in (([], '1.0'), (['builder>=1'], '1.0'), (['builder>=1,<2'], '2.0')):
            with self.subTest(requirements=requirements, version=version), \
                    patch('ptw.python_local.run_build', side_effect=result(requirements, version)):
                with self.assertRaisesRegex(EvidenceError, 'metadata differs|unexpected identity'):
                    build_wheel(store, actor['token'], 'local', provider=provider)
            self.assertFalse(list(store.directory.glob('local-build-*')))
        with patch('ptw.python_local.run_build', side_effect=result(['builder <2, >=1'])):
            data, receipt = build_wheel(store, actor['token'], 'local', provider=provider)
        self.assertEqual(hashlib.sha256(data).hexdigest(), receipt['sha256'])
        self.assertEqual(receipt['policy_sha256'], bundle['approval']['sha256'])
        self.assertEqual(store.status('local-python')['violations'], 0)

    def test_dynamic_requirement_needs_reviewed_graph_before_hooks(self):
        self.dynamic_project({'version': '1.0', 'dependencies': ['builder>=1,<2']})
        store, actor, _ = self.activate()
        with patch('ptw.python_local.run_build') as run:
            with self.assertRaisesRegex(Invalid, 'reviewed compatible resolution'):
                build_wheel(store, actor['token'], 'local')
            run.assert_not_called()

    def test_dynamic_mutable_metadata_input_is_bound_and_new_files_invalidate_unknown_backend(self):
        from ptw.python_local import reuse_source
        from ptw.workspace import scan
        self.dynamic_project()
        mutable = next(r for r, v in self.inv['resources'].items() if v['path'] == 'src')
        self.source = describe_source(self.inv, self.resources, identity='local', allow_build=True,
            editable_resources=[mutable], dynamic_metadata={'version': '1.0', 'dependencies': []})
        self.policy['project']['python_dependencies']['sources'] = [self.source]
        store, actor, bundle = self.activate()
        with store.locked() as db:
            row = dict(store.session(db, actor['token']))
        definition = {'resources': self.resources}
        reuse_source(bundle, row, 'local', definition, scan(self.inv, self.resources))
        (self.repo / 'src/metadata.txt').write_text('2.0\n')
        with self.assertRaisesRegex(Invalid, 'build configuration changed'):
            reuse_source(bundle, row, 'local', definition, scan(self.inv, self.resources))

    def test_setuptools_dynamic_file_inside_mutable_tree_is_fixed_but_implementation_can_change(self):
        from ptw.python_local import reuse_source
        from ptw.workspace import scan
        metadata = self.repo / 'pyproject.toml'
        metadata.write_text('[project]\nname="local-demo"\ndynamic=["version"]\n'
            '[build-system]\nrequires=[]\nbuild-backend="setuptools.build_meta"\n'
            '[tool.setuptools.dynamic]\nversion={file=["src/version.txt"]}\n')
        (self.repo / 'src/version.txt').write_text('1.0\n')
        mutable = next(r for r, v in self.inv['resources'].items() if v['path'] == 'src')
        self.source = describe_source(self.inv, self.resources, identity='local', allow_build=True,
            editable_resources=[mutable], dynamic_metadata={'version': '1.0'})
        self.policy['project']['python_dependencies']['sources'] = [self.source]
        store, actor, bundle = self.activate()
        with store.locked() as db:
            row = dict(store.session(db, actor['token']))
        definition = {'resources': self.resources}
        (self.repo / 'src/local_demo/__init__.py').write_text('VALUE = 99\n')
        reuse_source(bundle, row, 'local', definition, scan(self.inv, self.resources))
        (self.repo / 'src/version.txt').write_text('2.0\n')
        with self.assertRaisesRegex(Invalid, 'build configuration changed'):
            reuse_source(bundle, row, 'local', definition, scan(self.inv, self.resources))

    def test_discovery_cannot_commit_install_or_use_ordinary_session(self):
        self.dynamic_project()
        self.source = describe_source(self.inv, self.resources, identity='local', allow_build=True, discovery=True)
        self.policy['project']['python_dependencies']['sources'] = [self.source]
        bundle = approve(self.policy, self.inv, digest(compile_policy(self.policy, self.inv)), 'fixture')
        store = Store(self.root / 'controller')
        with self.assertRaisesRegex(Invalid, 'pending setup'):
            store.activate(bundle)
        store.activate(bundle, setup_pending=True)
        actor = store.register_preparation('local-python', 'work', 'local', bundle['approval']['sha256'])
        with patch('ptw.python_local.run_build') as build:
            for install in (install_wheel, install_editable):
                with self.assertRaisesRegex(Invalid, 'explicit .* approval'):
                    install(store, actor['token'], 'local')
            build.assert_not_called()
        store.close_session(actor['token'])
        with self.assertRaisesRegex(Invalid, 'cannot make a project ready'):
            store.commit_setup('local-python', bundle['approval']['sha256'], lambda: None)
        store.stop('local-python')
        with self.assertRaisesRegex(Invalid, 'unstopped pending'):
            store.activate(bundle, setup_pending=True, discovery_sha256=bundle['approval']['sha256'])

    def test_discovered_requirements_enter_resolver_only_after_discovery(self):
        from ptw.dependency_resolution import resolve_python
        from ptw.setup_templates import RULES
        from types import SimpleNamespace
        self.dynamic_project()
        def runner(argv, **kwargs):
            self.assertEqual((Path(kwargs['cwd']) / 'requirements.in').read_text(), 'builder>=1,<2\n')
            Path(argv[argv.index('--output-file') + 1]).write_text('builder==1.0\n')
            return SimpleNamespace(returncode=0, stderr='')
        with patch('ptw.python_local.run_build') as build:
            initial = resolve_python(self.repo, self.root / 'initial', RULES, local_build=True,
                                     discovery=True, provider=FixtureProvider(), runner=runner)
            self.assertEqual(initial['pins'], [])
            final = resolve_python(self.repo, self.root / 'final', RULES, local_build=True,
                dynamic_metadata={'version': '1.0', 'dependencies': ['builder>=1,<2']},
                provider=FixtureProvider(), runner=runner)
            self.assertEqual(final['pins'], ['builder==1.0'])
            self.assertEqual(final['inputs']['pyproject.toml'], hashlib.sha256((self.repo / 'pyproject.toml').read_bytes()).hexdigest())
            build.assert_not_called()

    def test_output_cannot_drop_declared_python_runtime_requirement(self):
        from email.parser import BytesParser
        from ptw.python_local import validate_output_metadata
        from ptw.workspace import scan
        metadata = self.repo / 'pyproject.toml'
        metadata.write_text(metadata.read_text().replace('[build-system]', 'requires-python=">=3.10"\n[build-system]'))
        entries = scan(self.inv, self.resources)
        for value in ('', 'Requires-Python: >=3.9\n'):
            with self.subTest(value=value), self.assertRaisesRegex(EvidenceError, 'metadata differs'):
                validate_output_metadata(BytesParser().parsebytes(value.encode() + b'\n'), entries, self.source)
        validate_output_metadata(BytesParser().parsebytes(b'Requires-Python: >=3.10\n\n'), entries, self.source)

    def fake_build(self, store, token, command, target):
        (target / 'out').mkdir()
        (target / 'out/local_demo-1.0-py3-none-any.whl').write_bytes(wheel_bytes('local-demo', '1.0'))

    @staticmethod
    def fake_wheel_install(artifacts, target, records, **kwargs):
        """Unit seam for uv only. Native tests exercise the actual installer."""
        import zipfile
        target.mkdir()
        for record in records:
            with zipfile.ZipFile(artifacts / record['filename']) as wheel:
                wheel.extractall(target)
        (target / '.lock').write_bytes(b'')
        if kwargs.get('extended'):
            (target / 'sitecustomize.py').write_text('import site\n')

    def test_wheel_publication_reuse_needs_full_scope_and_unchanged_source(self):
        from ptw.packages import mounted_set
        from ptw.workspace import scan
        store, actor, bundle = self.activate()
        with patch('ptw.python_local.run_build', side_effect=self.fake_build), \
                patch('ptw.python_local.install_wheels', side_effect=self.fake_wheel_install):
            receipt = install_wheel(store, actor['token'], 'local')
        snapshot = scan(self.inv, self.resources)
        definition = {'resources': self.resources}
        child = store.register('local-python', 'work', parent_token=actor['token'],
                               grants=[{'resource': self.resources[0], 'actions': ['read']}])
        with store.locked() as db:
            row = store.session(db, actor['token'])
            installed = mounted_set(store, db, row, receipt['package_set'], definition=definition, snapshot=snapshot)
            self.assertTrue((installed / 'local-demo/__init__.py').is_file())
            self.assertEqual(receipt['wheel']['sha256'], hashlib.sha256(wheel_bytes('local-demo', '1.0')).hexdigest())
            for kwargs, who in (({}, row), ({'definition': {'resources': self.resources[:1]}, 'snapshot': snapshot}, row),
                                ({'definition': definition, 'snapshot': snapshot}, store.session(db, child['token']))):
                with self.assertRaises(Invalid):
                    mounted_set(store, db, who, receipt['package_set'], **kwargs)
            (self.repo / 'src/local_demo/__init__.py').write_text('VALUE = 99\n')
            with self.assertRaisesRegex(Invalid, 'source changed'):
                mounted_set(store, db, row, receipt['package_set'], definition=definition, snapshot=snapshot)
            with self.assertRaisesRegex(Invalid, 'source changed'):
                mounted_set(store, db, row, receipt['package_set'], definition=definition,
                            snapshot=scan(self.inv, self.resources))
        self.assertEqual(store.status('local-python')['policy_sha256'], bundle['approval']['sha256'])
        self.assertEqual(store.status('local-python')['violations'], 0)

    def test_wheel_install_failure_mutation_and_bad_output_never_publish(self):
        store, actor, _ = self.activate()
        source = self.repo / 'src/local_demo/__init__.py'
        original = source.read_bytes()
        def mutate(*args, **kwargs):
            self.fake_wheel_install(*args, **kwargs)
            source.write_text('VALUE = 99\n')
        def malformed(artifacts, target, records, **kwargs):
            self.fake_wheel_install(artifacts, target, records, **kwargs)
            (next(target.glob('*.dist-info')) / 'METADATA').write_text('Name: different\nVersion: 1.0\n')
        for effect in (EvidenceError('fixture install failed'), mutate, malformed):
            source.write_bytes(original)
            with self.subTest(effect=repr(effect)), patch('ptw.python_local.run_build', side_effect=self.fake_build), \
                    patch('ptw.python_local.install_wheels', side_effect=effect):
                with self.assertRaises(Invalid):
                    install_wheel(store, actor['token'], 'local')
            with store.locked() as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM package_sets').fetchone()[0], 0)
            self.assertFalse(list(store.directory.glob('local-install-*')))
        source.write_bytes(original)
        with patch('ptw.python_local.run_build', side_effect=self.fake_build), \
                patch('ptw.python_local.install_wheels', side_effect=self.fake_wheel_install), \
                patch('ptw.python_local.os.rename', side_effect=OSError('fixture publication failure')):
            with self.assertRaises(OSError):
                install_wheel(store, actor['token'], 'local')
        self.assertFalse(list((store.directory / 'package-sets').iterdir()))

    def test_wheel_and_registry_payloads_cannot_collide(self):
        provider = FixtureProvider()
        self.registry_graph(provider)
        store, actor, _ = self.activate()
        def collision(artifacts, target, records, **kwargs):
            self.fake_wheel_install(artifacts, target, records, **kwargs)
            if kwargs.get('extended'):
                (target / 'local-demo').mkdir()
                (target / 'local-demo/__init__.py').write_text('VALUE = 99\n')
        with patch('ptw.python_local.run_build', side_effect=self.fake_build), \
                patch('ptw.python_local.install_wheels', side_effect=collision):
            with self.assertRaisesRegex(EvidenceError, 'collide'):
                install_wheel(store, actor['token'], 'local', provider=provider)
        with store.locked() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM package_sets').fetchone()[0], 0)

    def test_editable_approval_cannot_authorize_wheel_installation(self):
        self.editable_policy()
        store, actor, _ = self.activate()
        with patch('ptw.python_local.run_build') as build, patch('ptw.python_local.install_wheels') as install:
            with self.assertRaisesRegex(Invalid, 'explicit wheel approval'):
                install_wheel(store, actor['token'], 'local')
            build.assert_not_called()
            install.assert_not_called()

    def test_mutation_during_build_discards_valid_output(self):
        store, actor, _ = self.activate()
        def mutate(*args):
            self.fake_build(*args)
            (self.repo / 'backend/backend.py').write_text('raise RuntimeError("changed")\n')
        with patch('ptw.python_local.run_build', side_effect=mutate):
            with self.assertRaisesRegex(Invalid, 'changed since build review'):
                build_wheel(store, actor['token'], 'local')
        self.assertFalse(list(store.directory.glob('local-build-*')))

    def test_failed_or_unexpected_build_output_publishes_nothing(self):
        store, actor, _ = self.activate()
        def unexpected(store, token, command, target):
            (target / 'out').mkdir()
            (target / 'out/local_demo-1.0-py3-none-any.whl').write_bytes(
                wheel_bytes('local-demo', '1.0', requires=['unapproved>=1']))
        for effect in (EvidenceError('SYNTHETIC_BACKEND_PRIVATE_LOG'), unexpected):
            with self.subTest(effect=type(effect).__name__), patch('ptw.python_local.run_build', side_effect=effect):
                with self.assertRaises(EvidenceError) as raised:
                    build_wheel(store, actor['token'], 'local')
                self.assertNotIn('SYNTHETIC_BACKEND_PRIVATE_LOG', str(raised.exception))
            self.assertFalse(list(store.directory.glob('local-build-*')))
        self.assertEqual(self.private.read_text(), 'UNRELATED_LOCAL_SOURCE')

    def registry_graph(self, provider, name='builder', version='1.0'):
        record = provider.assess(name, version)
        descriptor = self.policy['project']['python_dependencies']
        descriptor['pins'] = [name + '==' + version]
        descriptor['artifacts'] = [{k: record[k] for k in ('name', 'version', 'url', 'sha256')}]
        self.policy['project']['packages']['allowed_names'] = ['pypi:' + name]
        self.policy['tasks'][0]['packages'] = ['pypi:' + name]

    def require_builder(self, requirement='builder>=1,<2'):
        metadata = self.repo / 'pyproject.toml'
        metadata.write_text(metadata.read_text().replace('requires=[]', 'requires=[' + json.dumps(requirement) + ']'))
        self.source = describe_source(self.inv, self.resources, identity='local', allow_build=True)
        self.policy['project']['python_dependencies']['sources'] = [self.source]

    def test_build_requirements_need_compatible_reviewed_graph_before_execution(self):
        self.require_builder()
        store, actor, _ = self.activate()
        with patch('ptw.python_local.run_build') as run:
            with self.assertRaisesRegex(Invalid, 'reviewed compatible resolution'):
                build_wheel(store, actor['token'], 'local')
            run.assert_not_called()

    def test_assessed_build_artifact_and_command_constraints(self):
        provider = FixtureProvider()
        self.registry_graph(provider)
        self.require_builder()
        store, actor, _ = self.activate()
        def checked_build(store, token, command, target):
            self.assertIn('--offline', command)
            self.assertIn('--no-index', command)
            self.assertIn('--build-constraints', command)
            artifacts = target.parent / 'artifacts'
            self.assertEqual((artifacts / 'constraints.txt').read_text(), 'builder==1.0\n')
            self.assertEqual((artifacts / 'builder-1.0-py3-none-any.whl').read_bytes(), wheel_bytes('builder', '1.0'))
            self.assertTrue((target / 'source/pyproject.toml').is_file())
            self.fake_build(store, token, command, target)
        with patch('ptw.python_local.run_build', side_effect=checked_build):
            data, receipt = build_wheel(store, actor['token'], 'local', provider=provider)
        self.assertEqual(receipt['dependencies'][0]['name'], 'builder')
        self.assertEqual(hashlib.sha256(data).hexdigest(), receipt['sha256'])
        self.assertFalse(list(store.directory.glob('local-build-*')))

    def test_build_artifact_denials_precede_backend_and_publish_nothing(self):
        provider = FixtureProvider()
        self.registry_graph(provider)
        self.require_builder()
        store, actor, _ = self.activate()
        for changes in ({'vulnerabilities': [CRITICAL]}, {'published_at': '2099-01-01T00:00:00Z'},
                        {'vulnerabilities': None}, {'sha256': '0' * 64}, {'name': 'wrong'},
                        {'filename': '../escape.whl'}, {'filename': 'builder-2.0-py3-none-any.whl'}):
            with self.subTest(changes=changes), patch('ptw.python_local.run_build') as run:
                with self.assertRaises(Invalid):
                    build_wheel(store, actor['token'], 'local', provider=FixtureProvider(changes={'builder': changes}))
                run.assert_not_called()
                self.assertFalse(list(store.directory.glob('local-build-*')))
        child = store.register('local-python', 'work', parent_token=actor['token'], packages=[])
        with patch('ptw.python_local.run_build') as run:
            with self.assertRaisesRegex(Invalid, 'session package grants'):
                build_wheel(store, child['token'], 'local', provider=provider)
            run.assert_not_called()
        def corrupt(record, path):
            path.write_bytes(b'changed after assessment')
        with patch.object(provider, 'download', side_effect=corrupt), patch('ptw.python_local.run_build') as run:
            with self.assertRaisesRegex(Invalid, 'digest mismatch'):
                build_wheel(store, actor['token'], 'local', provider=provider)
            run.assert_not_called()
        self.assertEqual(store.status('local-python')['violations'], 0)

    def test_build_hook_cannot_add_unreviewed_dependency_output(self):
        provider = FixtureProvider()
        self.registry_graph(provider)
        self.require_builder()
        store, actor, _ = self.activate()
        def unexpected(store, token, command, target):
            self.fake_build(store, token, command, target)
            (target / 'out/local_demo-1.0-py3-none-any.whl').write_bytes(
                wheel_bytes('local-demo', '1.0', requires=['unreviewed>=1']))
        with patch('ptw.python_local.run_build', side_effect=unexpected):
            with self.assertRaisesRegex(Invalid, 'Missing, incompatible'):
                build_wheel(store, actor['token'], 'local', provider=provider)
        self.assertFalse(list(store.directory.glob('local-build-*')))

    def test_native_output_denied_by_default_and_approved_by_same_policy(self):
        def build(store, token, command, target):
            output = target / 'out'
            output.mkdir()
            (output / 'local_demo-1.0-py3-none-linux_x86_64.whl').write_bytes(wheel_bytes('local_demo', '1.0', extra={
                'local_demo-1.0.dist-info/WHEEL': b'Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: py3-none-linux_x86_64\n',
                'local_demo/value.so': b'\x7fELFsynthetic-format-test-only'}))
        store, actor, _ = self.activate()
        with patch('ptw.python_local.run_build', side_effect=build):
            with self.assertRaisesRegex(EvidenceError, 'native-wheel approval'):
                build_wheel(store, actor['token'], 'local')
        with store.locked() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM package_sets').fetchone()[0], 0)
        self.assertFalse(list(store.directory.glob('local-build-*')))
        self.assertEqual(store.status('local-python')['violations'], 0)
        # A separate explicitly approved fixture identity, not a policy edit in place.
        self.policy['project']['packages']['allow_native_wheels'] = True
        self.root = self.root / 'approved'
        self.root.mkdir()
        store, actor, bundle = self.activate()
        with patch('ptw.python_local.run_build', side_effect=build):
            data, receipt = build_wheel(store, actor['token'], 'local')
        self.assertTrue(data)
        self.assertEqual(receipt['policy_sha256'], bundle['approval']['sha256'])

    def test_compiler_fixture_uses_visible_tool_without_ambient_selection(self):
        import ast
        from ptw.supervisor import runtime_namespace
        injected = {key: 'SYNTHETIC_LOCAL_INJECTION' for key in ('CC', 'CFLAGS', 'LDFLAGS', 'PATH')}
        with patch.dict(os.environ, injected):
            native_library_project(self)
        backend = (self.repo / 'backend/backend.py').read_text()
        tree = ast.parse(backend)
        invocation = next(node for node in ast.walk(tree) if isinstance(node, ast.Call)
                          and isinstance(node.func, ast.Attribute) and node.func.attr == 'run')
        argv = ast.literal_eval(invocation.args[0])
        compiler = Path(argv[0])
        self.assertEqual(compiler, compiler.resolve(strict=True))
        self.assertTrue(compiler.is_relative_to('/usr'))
        self.assertEqual(argv[1:], ['-shared', '-fPIC', 'src/local_demo/value.c', '-o', 'value.so'])
        self.assertNotIn('SYNTHETIC_LOCAL_INJECTION', ' '.join(argv))
        with patch('ptw.supervisor.shutil.which', return_value='/usr/bin/bwrap'):
            namespace = runtime_namespace()
        self.assertIn('/usr', namespace)
        self.assertNotIn('/etc', namespace)
        self.assertFalse((self.repo / 'value.so').exists())

    def test_native_wheel_labels_and_runtime_cannot_bypass_validation(self):
        from packaging.tags import parse_tag
        from ptw.python_local import validate_local_wheel_tags
        path = self.root / 'candidate.whl'
        for payload in ({'local_demo/value.so': b'ordinary bytes'},
                        {'local_demo/blob': b'\x7fELFpayload'},
                        {'local_demo-1.0.dist-info/WHEEL': b'Root-Is-Purelib: false\nTag: py3-none-any\n'}):
            with self.subTest(payload=list(payload)):
                path.write_bytes(wheel_bytes('local_demo', '1.0', extra=payload))
                with self.assertRaisesRegex(EvidenceError, 'native-wheel approval'):
                    validate_local_wheel_tags(path, parse_tag('py3-none-any'), False)
        for header in (b'Root-Is-Purelib: true\nTag: py3-none-win32\n',
                       b'Root-Is-Purelib: true\nRoot-Is-Purelib: false\nTag: py3-none-any\n',
                       b'Root-Is-Purelib: true\nTag: malformed\n',
                       b'Root-Is-Purelib: true\n'):
            path.write_bytes(wheel_bytes('local_demo', '1.0', extra={'local_demo-1.0.dist-info/WHEEL': header}))
            with self.subTest(header=header), self.assertRaises(EvidenceError):
                validate_local_wheel_tags(path, parse_tag('py3-none-any'), True)
        self.policy['project']['packages']['allow_native_wheels'] = True
        store, actor, _ = self.activate()
        def wrong_runtime(store, token, command, target):
            output = target / 'out'
            output.mkdir()
            (output / 'local_demo-1.0-cp20-cp20-win32.whl').write_bytes(wheel_bytes('local_demo', '1.0'))
        with patch('ptw.python_local.run_build', side_effect=wrong_runtime), \
                self.assertRaisesRegex(EvidenceError, 'incompatible with reviewed runtime'):
            build_wheel(store, actor['token'], 'local')

    def editable_policy(self):
        mutable = [r for r, v in self.inv['resources'].items() if v['path'] == 'src']
        self.source = describe_source(self.inv, self.resources, identity='local', allow_build=True,
                                      editable_resources=mutable,
                                      dynamic_metadata=self.source.get('dynamic_metadata'),
                                      extras=self.source.get('extras', ()))
        self.policy['project']['python_dependencies']['sources'] = [self.source]
        python = self.policy['project']['python_runtime']['executable']
        script = ('import local_demo,importlib.metadata as m,json,os,pathlib; '
                  'assert not any("SYNTHETIC_LOCAL_INJECTION" in v for v in os.environ.values()); '
                  'assert local_demo.__file__.startswith("/target/src/"); '
                  'assert m.version("local-demo")=="1.0"; '
                  'assert json.loads(m.distribution("local-demo").read_text("direct_url.json"))'
                  '["dir_info"]["editable"] is True; print(local_demo.VALUE)')
        command = dict(id='local-import', argv=[python, '-s', '-c', script],
                       resources=self.resources, timeout_seconds=30)
        narrow = {**command, 'id': 'narrow-import', 'resources': mutable}
        self.policy['project']['commands'] = [command, narrow]
        self.policy['tasks'][0]['commands'] = [command['id'], narrow['id']]
        return command, narrow

    def fake_editable(self, store, token, command, target):
        import zipfile
        from io import BytesIO
        site = target / '.ptw-local-site'
        site.mkdir()
        with zipfile.ZipFile(BytesIO(wheel_bytes('local-demo', '1.0'))) as wheel:
            wheel.extractall(site)
        info = next(site.glob('*.dist-info'))
        (info / 'direct_url.json').write_text(json.dumps({'url': 'file:///target', 'dir_info': {'editable': True}}))
        (site / 'local_demo.pth').write_text('/target/src\n')

    def test_editable_scope_binds_backend_and_metadata_but_allows_implementation_edits(self):
        for mutable in ([r for r in self.resources if self.inv['resources'][r]['path'] == 'backend'],
                        [r for r in self.resources if self.inv['resources'][r]['path'] == 'pyproject.toml'], ['unknown']):
            with self.subTest(mutable=mutable), self.assertRaises(Invalid):
                describe_source(self.inv, self.resources, identity='local', editable_resources=mutable)
        command, _ = self.editable_policy()
        store, actor, bundle = self.activate()
        from ptw.python_local import reuse_source
        from ptw.workspace import scan
        (self.repo / 'src/local_demo/__init__.py').write_text('VALUE = 99\n')
        with store.locked() as db:
            row = store.session(db, actor['token'])
            reuse_source(bundle, row, 'local', command, scan(self.inv, self.resources))
        with self.assertRaisesRegex(Invalid, 'changed since build review'):
            install_editable(store, actor['token'], 'local')

    def fake_compiled_editable(self, store, token, command, target):
        self.fake_editable(store, token, command, target)
        (target / 'src/local_demo/value.so').write_bytes(b'\x7fELFformat-fixture-only')

    def declarative_extension(self):
        metadata = self.repo / 'pyproject.toml'
        metadata.write_text('[project]\nname="local-demo"\nversion="1.0"\n'
            '[build-system]\nrequires=["setuptools==1.0"]\nbuild-backend="setuptools.build_meta"\n'
            '[[tool.setuptools.ext-modules]]\nname="local_demo.value"\n'
            'sources=["src/local_demo/value.c"]\n')
        (self.repo / 'src/local_demo/value.c').write_text('int local_value(void) { return 42; }\n')
        provider = FixtureProvider(wheels={'setuptools': wheel_bytes('setuptools', '1.0')})
        self.registry_graph(provider, 'setuptools', '1.0')
        self.policy['project']['packages']['allow_native_wheels'] = True
        return provider

    def test_compiled_declarative_reuse_allows_python_but_binds_native_inputs_and_scope(self):
        from ptw.packages import mounted_set
        from ptw.workspace import scan
        provider = self.declarative_extension()
        command, narrow = self.editable_policy()
        store, actor, bundle = self.activate()
        with patch('ptw.python_local.run_build', side_effect=self.fake_compiled_editable), \
                patch('ptw.python_local.install_wheels', side_effect=self.fake_wheel_install):
            receipt = install_editable(store, actor['token'], 'local', provider=provider)
        self.assertIn('native_inputs_sha256', receipt)
        before = scan(self.inv, self.resources)
        (self.repo / 'src/local_demo/__init__.py').write_text('VALUE = 99\n')
        (self.repo / 'src/local_demo/new_module.py').write_text('VALUE = 100\n')
        with store.locked() as db:
            row = store.session(db, actor['token'])
            def mount(snapshot=None, definition=command):
                return mounted_set(store, db, row, receipt['package_set'], definition=definition,
                                   snapshot=snapshot or scan(self.inv, self.resources))
            mount()
            with self.assertRaisesRegex(Invalid, 'command inputs'):
                mount(definition=narrow)
            path = self.repo / 'src/local_demo/value.c'
            original = path.read_bytes()
            for operation in ('modify', 'delete', 'add-header'):
                with self.subTest(operation=operation):
                    path.write_bytes(original)
                    extra = self.repo / 'src/local_demo/new.h'
                    if operation == 'modify':
                        path.write_text('int local_value(void) { return 99; }\n')
                    elif operation == 'delete':
                        path.unlink()
                    else:
                        extra.write_text('#define VALUE 99\n')
                    with self.assertRaisesRegex(Invalid, 'Compiled editable source changed'):
                        mount()
                    # A command snapshot cannot conceal subsequent host mutation.
                    with self.assertRaisesRegex(Invalid, 'Compiled editable source changed'):
                        mount(snapshot=before)
                    extra.unlink(missing_ok=True)
            path.write_bytes(original)
            mount()
            # Nor can a clean host conceal mutation already in the command input.
            changed = copy.deepcopy(scan(self.inv, self.resources))
            changed['src/local_demo/value.c']['data'] = b'changed'
            with self.assertRaisesRegex(Invalid, 'Compiled editable source changed'):
                mount(snapshot=changed)
        self.assertEqual(store.status('local-python')['policy_sha256'], bundle['approval']['sha256'])
        self.assertEqual(store.status('local-python')['violations'], 0)

    def test_compiled_declared_python_dependency_is_not_live_source(self):
        from ptw.python_local import native_build_entries, snapshot_digest
        from ptw.workspace import scan
        self.declarative_extension()
        metadata = self.repo / 'pyproject.toml'
        metadata.write_text(metadata.read_text() + 'depends=["src/local_demo/__init__.py"]\n')
        self.editable_policy()
        before = native_build_entries(scan(self.inv, self.resources), self.inv, self.source)
        self.assertIn('src/local_demo/__init__.py', before)
        (self.repo / 'src/local_demo/__init__.py').write_text('VALUE = 99\n')
        after = native_build_entries(scan(self.inv, self.resources), self.inv, self.source)
        self.assertNotEqual(snapshot_digest(before), snapshot_digest(after))

    def test_compiled_custom_or_ambiguous_build_keeps_full_snapshot_binding(self):
        from ptw.python_local import native_build_entries
        from ptw.workspace import scan
        self.declarative_extension()
        metadata = self.repo / 'pyproject.toml'
        original = metadata.read_text()
        variants = [original.replace('setuptools.build_meta', 'custom.backend'),
            original.replace('requires=["setuptools==1.0"]', 'requires=["setuptools==1.0","custom-plugin"]'),
            original + '\n[tool.setuptools.cmdclass]\nbuild_ext="custom.Build"\n',
            original + 'depends=["src/*.py"]\n', original + 'depends=["../outside"]\n',
            original + 'depends=["src/local_demo/missing.py"]\n', original + 'depends="src"\n']
        for text in variants:
            with self.subTest(metadata=text):
                metadata.write_text(text)
                self.editable_policy()
                entries = scan(self.inv, self.resources)
                self.assertEqual(native_build_entries(entries, self.inv, self.source), entries)
        metadata.write_text(original)
        (self.repo / 'setup.py').write_text('raise RuntimeError("must not execute")\n')
        # Explicitly bind the additional build script before inspecting its data.
        self.inv['resources']['setup'] = {'path': 'setup.py'}
        self.resources.append('setup')
        self.editable_policy()
        entries = scan(self.inv, self.resources)
        self.assertEqual(native_build_entries(entries, self.inv, self.source), entries)

    def test_compiled_old_receipt_does_not_gain_live_edit_permission(self):
        from ptw.python_local import verify_native_reuse
        from ptw.workspace import scan
        self.declarative_extension()
        self.editable_policy()
        receipt = {'native_editable': True, 'source_sha256': self.source['snapshot_sha256']}
        bundle = {'inventory': self.inv}
        verify_native_reuse(bundle, self.source, receipt, scan(self.inv, self.resources))
        (self.repo / 'src/local_demo/__init__.py').write_text('VALUE = 99\n')
        with self.assertRaisesRegex(Invalid, 'Compiled editable source changed'):
            verify_native_reuse(bundle, self.source, receipt, scan(self.inv, self.resources))

    def test_compiled_editable_artifacts_need_native_approval_and_bind_all_sources(self):
        from ptw.packages import mounted_set
        from ptw.workspace import scan
        command, narrow = self.editable_policy()
        store, actor, _ = self.activate()
        with patch('ptw.python_local.run_build', side_effect=self.fake_compiled_editable), \
                self.assertRaisesRegex(EvidenceError, 'native-wheel approval'):
            install_editable(store, actor['token'], 'local')
        with store.locked() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM package_sets').fetchone()[0], 0)
        self.policy['project']['packages']['allow_native_wheels'] = True
        self.root = self.root / 'approved'
        self.root.mkdir()
        store, actor, bundle = self.activate()
        with patch('ptw.python_local.run_build', side_effect=self.fake_compiled_editable):
            receipt = install_editable(store, actor['token'], 'local')
        self.assertTrue(receipt['native_editable'])
        self.assertEqual(set(receipt['editable_artifacts']), {'src/local_demo/value.so'})
        self.assertFalse((self.repo / 'src/local_demo/value.so').exists())
        child = store.register('local-python', 'work', parent_token=actor['token'],
            grants=[{'resource': narrow['resources'][0], 'actions': ['read']}], commands=[])
        with store.locked() as db:
            row = store.session(db, actor['token'])
            snapshot = scan(self.inv, self.resources)
            mounted_set(store, db, row, receipt['package_set'], definition=command, snapshot=snapshot)
            with self.assertRaisesRegex(Invalid, 'command inputs'):
                mounted_set(store, db, row, receipt['package_set'], definition=narrow, snapshot=snapshot)
            with self.assertRaisesRegex(Invalid, 'session read grants'):
                mounted_set(store, db, store.session(db, child['token']), receipt['package_set'],
                            definition=command, snapshot=snapshot)
            (self.repo / 'src/local_demo/__init__.py').write_text('VALUE = 99\n')
            with self.assertRaisesRegex(Invalid, 'Compiled editable source changed'):
                mounted_set(store, db, row, receipt['package_set'], definition=command, snapshot=snapshot)
            (self.repo / 'src/local_demo/__init__.py').write_bytes(snapshot['src/local_demo/__init__.py']['data'])
            artifact = store.directory / 'package-sets' / receipt['package_set'] / '.ptw-editable-artifacts/src/local_demo/value.so'
            artifact.write_bytes(b'tampered')
            with self.assertRaisesRegex(Invalid, 'integrity'):
                mounted_set(store, db, row, receipt['package_set'], definition=command, snapshot=snapshot)
        self.assertEqual(store.status('local-python')['policy_sha256'], bundle['approval']['sha256'])
        self.assertEqual(store.status('local-python')['violations'], 0)

    def test_editable_native_tags_payload_and_runtime_are_independently_checked(self):
        from ptw.python_local import validate_editable_install
        from ptw.workspace import scan
        self.editable_policy()
        target = self.root / 'output'
        target.mkdir()
        self.fake_editable(None, None, None, target)
        site = target / '.ptw-local-site'
        header = next(site.glob('*.dist-info')) / 'WHEEL'
        def validate(approved=False):
            return validate_editable_install(site, self.source, {}, '/usr/bin/python3',
                                             scan(self.inv, self.resources), allow_native=approved)
        original = header.read_bytes()
        for raw in (original.replace(b'true', b'false'), original.replace(b'py3-none-any', b'py3-none-linux_x86_64')):
            header.write_bytes(raw)
            with self.assertRaisesRegex(EvidenceError, 'native-wheel approval'):
                validate()
            self.assertTrue(validate(True)[1])
        header.write_bytes(original)
        blob = site / 'opaque'
        blob.write_bytes(b'\x7fELFformat-fixture-only')
        with self.assertRaisesRegex(EvidenceError, 'native-wheel approval'):
            validate()
        self.assertTrue(validate(True)[1])
        blob.unlink()
        for raw in (b'Root-Is-Purelib: true\n', b'Root-Is-Purelib: false\nTag: invalid\n',
                    b'Root-Is-Purelib: true\nRoot-Is-Purelib: false\nTag: py3-none-any\n',
                    b'Root-Is-Purelib: false\nTag: cp20-cp20-win32\n'):
            header.write_bytes(raw)
            with self.subTest(header=raw), self.assertRaises(EvidenceError):
                validate(True)

    def test_editable_build_mutation_symlink_and_reserved_artifacts_publish_nothing(self):
        self.editable_policy()
        self.policy['project']['packages']['allow_native_wheels'] = True
        store, actor, _ = self.activate()
        for kind in ('mutation', 'symlink', 'reserved', 'unbound-parent'):
            def build(store, token, command, target):
                self.fake_editable(store, token, command, target)
                if kind == 'mutation':
                    (target / 'src/local_demo/__init__.py').write_text('changed')
                elif kind == 'symlink':
                    (target / 'src/local_demo/value.so').symlink_to('__init__.py')
                elif kind == 'reserved':
                    (target / '.ptw-local-site/.ptw-editable-artifacts').mkdir()
                else:
                    (target / 'src/new').mkdir()
                    (target / 'src/new/value.so').write_bytes(b'\x7fELFfixture')
            with self.subTest(kind=kind), patch('ptw.python_local.run_build', side_effect=build), \
                    self.assertRaises((Invalid, EvidenceError)):
                install_editable(store, actor['token'], 'local')
            with store.locked() as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM package_sets').fetchone()[0], 0)
        self.assertEqual((self.repo / 'src/local_demo/__init__.py').read_text(), 'VALUE = 42\n')

    def test_editable_artifacts_enter_only_disposable_commands_and_cannot_be_published(self):
        from ptw.execution import execute, RECEIPT
        from ptw.workspace import scan
        command, _ = self.editable_policy()
        self.policy['project']['packages']['allow_native_wheels'] = True
        store, actor, _ = self.activate()
        with patch('ptw.python_local.run_build', side_effect=self.fake_compiled_editable):
            receipt = install_editable(store, actor['token'], 'local')
        snapshot = scan(self.inv, self.resources)
        for mutate in (False, True):
            def run(store, token, argv, target):
                self.assertEqual((target / 'src/local_demo/value.so').read_bytes(), b'\x7fELFformat-fixture-only')
                if mutate:
                    (target / 'src/local_demo/value.so').write_bytes(b'changed')
                (target / RECEIPT).write_text(json.dumps({'exit_code': 0, 'output': '', 'output_truncated': False}))
            with patch('ptw.execution.run_build', side_effect=run), \
                    patch.dict(os.environ, {'PTW_NONO': '/usr/bin/true'}):
                if mutate:
                    with self.assertRaisesRegex(Invalid, 'changed a prepared editable'):
                        execute(store, actor['token'], command, snapshot, json.dumps({'package_sets': [receipt['package_set']]}))
                else:
                    after, _ = execute(store, actor['token'], command, snapshot,
                                       json.dumps({'package_sets': [receipt['package_set']]}))
                    self.assertEqual(after, snapshot)
        self.assertFalse((self.repo / 'src/local_demo/value.so').exists())

    def test_editable_publication_reuse_narrow_scope_and_cache_integrity(self):
        from ptw.packages import mounted_set
        from ptw.workspace import scan
        command, narrow = self.editable_policy()
        store, actor, _ = self.activate()
        with patch('ptw.python_local.run_build', side_effect=self.fake_editable):
            receipt = install_editable(store, actor['token'], 'local')
        package_id = receipt['package_set']
        child = store.register('local-python', 'work', parent_token=actor['token'],
            grants=[{'resource': narrow['resources'][0], 'actions': ['read']}], commands=[])
        with store.locked() as db:
            row = store.session(db, actor['token'])
            snapshot = scan(self.inv, self.resources)
            installed = mounted_set(store, db, row, package_id, definition=command, snapshot=snapshot)
            self.assertTrue((installed / 'local_demo.pth').is_file())
            with self.assertRaisesRegex(Invalid, 'workspace command snapshot'):
                mounted_set(store, db, row, package_id)
            with self.assertRaisesRegex(Invalid, 'command inputs'):
                mounted_set(store, db, row, package_id, definition=narrow, snapshot=snapshot)
            with self.assertRaisesRegex(Invalid, 'session read grants'):
                mounted_set(store, db, store.session(db, child['token']), package_id,
                            definition=command, snapshot=snapshot)
            (self.repo / 'backend/backend.py').write_text('CHANGED = True\n')
            with self.assertRaisesRegex(Invalid, 'configuration changed'):
                mounted_set(store, db, row, package_id, definition=command, snapshot=snapshot)
            (self.repo / 'backend/backend.py').write_bytes(snapshot['backend/backend.py']['data'])
            (installed / 'local_demo.pth').write_text('/host\n')
            with self.assertRaisesRegex(Invalid, 'integrity check failed'):
                mounted_set(store, db, row, package_id, definition=command, snapshot=snapshot)
        self.assertFalse(list(store.directory.glob('local-install-*')))

    def test_editable_output_metadata_and_mutation_fail_before_publication(self):
        self.editable_policy()
        store, actor, _ = self.activate()
        def bad_output(store, token, command, target):
            self.fake_editable(store, token, command, target)
            (next((target / '.ptw-local-site').glob('*.dist-info')) / 'METADATA').write_text(
                'Name: local-demo\nVersion: 1.0\nRequires-Dist: unreviewed>=1\n')
        def mutate(store, token, command, target):
            self.fake_editable(store, token, command, target)
            (self.repo / 'src/local_demo/__init__.py').write_text('VALUE = 99\n')
        for effect in (EvidenceError('SYNTHETIC_PRIVATE_BUILD_OUTPUT'), bad_output, mutate):
            with self.subTest(effect=type(effect).__name__), patch('ptw.python_local.run_build', side_effect=effect):
                with self.assertRaises(Invalid) as error:
                    install_editable(store, actor['token'], 'local')
                self.assertNotIn('SYNTHETIC_PRIVATE_BUILD_OUTPUT', str(error.exception))
                with store.locked() as db:
                    self.assertEqual(db.execute('SELECT COUNT(*) FROM package_sets').fetchone()[0], 0)
                self.assertFalse(list(store.directory.glob('local-install-*')))

    def test_editable_execution_requires_its_own_explicit_approval(self):
        store, actor, _ = self.activate()
        with patch('ptw.python_local.run_build') as run:
            with self.assertRaisesRegex(Invalid, 'editable approval'):
                install_editable(store, actor['token'], 'local')
            run.assert_not_called()

    def test_editable_registry_merge_accepts_only_empty_uv_target_lock(self):
        provider = FixtureProvider()
        self.registry_graph(provider)
        self.require_builder()
        self.editable_policy()
        store, actor, _ = self.activate()

        def local_install(store, token, command, target):
            self.fake_editable(store, token, command, target)
            (target / '.ptw-local-site/.lock').write_bytes(b'')

        def registry_install(wheelhouse, target, records, **kwargs):
            target.mkdir()
            (target / '.lock').write_bytes(b'')
            (target / 'builder.py').write_text('REGISTRY_VALUE = 7\n')
            (target / 'sitecustomize.py').write_text('import site\n')
            (target / 'builder-1.0.dist-info').mkdir()
            (target / 'builder-1.0.dist-info/METADATA').write_text('Name: builder\nVersion: 1.0\n')

        with patch('ptw.python_local.run_build', side_effect=local_install), \
                patch('ptw.python_local.install_wheels', side_effect=registry_install):
            receipt = install_editable(store, actor['token'], 'local', provider=provider)
        site = store.directory / 'package-sets' / receipt['package_set']
        self.assertEqual((site / '.lock').read_bytes(), b'')
        self.assertEqual((site / 'builder.py').read_text(), 'REGISTRY_VALUE = 7\n')
        self.assertEqual((site / 'local_demo.pth').read_text(), '/target/src\n')
        from ptw.package_install import file_manifest
        self.assertEqual(receipt['manifest_sha256'], digest(file_manifest(site)))

    def test_editable_registry_merge_rejects_payload_collisions_and_unsafe_locks(self):
        provider = FixtureProvider()
        self.registry_graph(provider)
        self.require_builder()
        self.editable_policy()
        store, actor, _ = self.activate()
        for conflict in ('identical-payload', 'local-lock-data', 'registry-lock-data', 'symlink-lock'):
            def local_install(store, token, command, target):
                self.fake_editable(store, token, command, target)
                site = target / '.ptw-local-site'
                if conflict == 'symlink-lock':
                    (site / '.lock').symlink_to('local_demo.pth')
                else:
                    (site / '.lock').write_bytes(b'payload' if conflict == 'local-lock-data' else b'')

            def registry_install(wheelhouse, target, records, **kwargs):
                target.mkdir()
                (target / '.lock').write_bytes(b'payload' if conflict == 'registry-lock-data' else b'')
                if conflict == 'identical-payload':
                    (target / 'local_demo.pth').write_text('/target/src\n')

            with self.subTest(conflict=conflict), \
                    patch('ptw.python_local.run_build', side_effect=local_install), \
                    patch('ptw.python_local.install_wheels', side_effect=registry_install):
                with self.assertRaises(EvidenceError):
                    install_editable(store, actor['token'], 'local', provider=provider)
                with store.locked() as db:
                    self.assertEqual(db.execute('SELECT COUNT(*) FROM package_sets').fetchone()[0], 0)
                self.assertFalse(list(store.directory.glob('local-install-*')))

    def test_editable_malformed_origin_hook_and_publication_failure_leave_no_set(self):
        self.editable_policy()
        store, actor, _ = self.activate()
        def outside_origin(store, token, command, target):
            self.fake_editable(store, token, command, target)
            info = next((target / '.ptw-local-site').glob('*.dist-info'))
            (info / 'direct_url.json').write_text('{"url":"file:///host","dir_info":{"editable":true}}')
        def startup_hook(store, token, command, target):
            self.fake_editable(store, token, command, target)
            (target / '.ptw-local-site/sitecustomize.py').write_text('raise RuntimeError("untrusted")\n')
        for effect in (outside_origin, startup_hook):
            with self.subTest(effect=effect.__name__), patch('ptw.python_local.run_build', side_effect=effect):
                with self.assertRaises(EvidenceError):
                    install_editable(store, actor['token'], 'local')
        with patch('ptw.python_local.run_build', side_effect=self.fake_editable), \
                patch('ptw.python_local.os.rename', side_effect=OSError('synthetic publication failure')):
            with self.assertRaises(OSError):
                install_editable(store, actor['token'], 'local')
        with store.locked() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM package_sets').fetchone()[0], 0)
        self.assertFalse(list((store.directory / 'package-sets').iterdir()))
        self.assertFalse(list(store.directory.glob('local-install-*')))
        self.assertEqual(store.status('local-python')['violations'], 0)

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_editable_import_after_protected_edit_and_narrow_scope_denial(self):
        self.native_editable_import()

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_pending_preparation_commits_before_editable_import(self):
        self.native_editable_import(pending=True)

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_stop_reaches_pending_backend_without_stopping_unrelated_work(self):
        from ptw.monitor import ensure, remove
        from ptw.supervisor import Supervisor
        backend = self.repo / 'backend/backend.py'
        backend.write_text(backend.read_text().replace(
            '    files = {', '    import sys,time\n    print("PENDING_BACKEND_STARTED", file=sys.stderr, flush=True)\n'
            '    time.sleep(120)\n    files = {'))
        self.source = describe_source(self.inv, self.resources, identity='local', allow_build=True)
        self.policy['project']['python_dependencies']['sources'] = [self.source]
        store, actor, bundle = self.activate(pending=True)
        unrelated = subprocess.Popen(['/usr/bin/sleep', '90'])
        logs, outcomes = [], []
        engine = Supervisor.engine

        def observed(supervisor, token, command, **kwargs):
            self.assertTrue(kwargs.get('preparation'))
            logs.append(kwargs['stderr'])
            return engine(supervisor, token, command, **kwargs)

        def build():
            try:
                outcomes.append(build_wheel(store, actor['token'], 'local'))
            except BaseException as exc:
                outcomes.append(exc)

        worker = threading.Thread(target=build, daemon=True)
        try:
            ensure(store)
            with patch.object(Supervisor, 'engine', observed):
                worker.start()
                deadline = time.monotonic() + 30
                reached = False
                while worker.is_alive() and time.monotonic() < deadline:
                    try:
                        if logs and b'PENDING_BACKEND_STARTED' in os.pread(logs[0].fileno(), 65536, 0):
                            reached = True
                            break
                    except (OSError, ValueError):
                        break  # Failed build closed its diagnostic stream.
                    time.sleep(.05)
                self.assertTrue(reached, 'Native backend did not reach the blocking fixture')
                with store.locked() as db:
                    units = [r['unit'] for r in db.execute('SELECT unit FROM workloads WHERE session=?',
                                                         (actor['session'],))]
                self.assertTrue(units)
                store.stop('local-python')
                Supervisor(store).reconcile()
                worker.join(timeout=20)
            self.assertFalse(worker.is_alive())
            self.assertEqual(len(outcomes), 1)
            self.assertIsInstance(outcomes[0], EvidenceError)
            self.assertTrue(all(Supervisor.state(unit)['confirmed_stopped'] for unit in units))
            self.assertIsNone(unrelated.poll())
            self.assertFalse(list(store.directory.glob('local-build-*')))
            with store.locked() as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM package_sets').fetchone()[0], 0)
            with self.assertRaisesRegex(Invalid, 'Stopped'):
                store.commit_setup('local-python', bundle['approval']['sha256'], lambda: None)
            self.assertEqual(self.private.read_text(), 'UNRELATED_LOCAL_SOURCE')
            self.assertEqual(self.external.read_text(), 'EXTERNAL_CONTROL')
            print('LOCAL_PYTHON_PENDING_STOP ' + json.dumps(dict(
                backend_reached=True, terminated=True, published=False, unrelated_alive=True,
                source_sha256=self.source['snapshot_sha256'], policy_sha256=bundle['approval']['sha256'],
                test_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())), flush=True)
        finally:
            store.stop('local-python')
            Supervisor(store).reconcile()
            if worker.ident is not None:
                worker.join(timeout=20)
            remove(store)
            unrelated.terminate()
            unrelated.wait(timeout=5)

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_setuptools_editable_import_after_protected_edit(self):
        self.native_editable_import(provider=self.setuptools_project())

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_setuptools_compiled_editable_inplace_import(self):
        provider = self.setuptools_project()
        metadata = self.repo / 'pyproject.toml'
        metadata.write_text(metadata.read_text().replace('build-backend="setuptools.build_meta"',
            'build-backend="backend"\nbackend-path=["backend"]') +
            '\n[[tool.setuptools.ext-modules]]\nname="local_demo.value"\nsources=["src/local_demo/value.c"]\n')
        compiler = str(Path('/usr/bin/cc').resolve(strict=True))
        (self.repo / 'backend/backend.py').write_text(
            'import os\nassert not any("SYNTHETIC_LOCAL_INJECTION" in v for v in os.environ.values())\n'
            'os.environ["CC"] = ' + repr(compiler) + '\n'
            'from setuptools.build_meta import *\n')
        (self.repo / 'src/local_demo/value.c').write_text('int local_value(void) { return 42; }\n')
        (self.repo / 'src/local_demo/__init__.py').write_text(
            'import ctypes,pathlib\n'
            'VALUE=ctypes.CDLL(str(next(pathlib.Path(__file__).parent.glob("value*.so")))).local_value()\n')
        self.policy['project']['packages']['allow_native_wheels'] = True
        self.native_editable_import(provider=provider, compiled=True)

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_declarative_compiled_editable_live_python_and_stale_c_denial(self):
        provider = self.setuptools_project()
        metadata = self.repo / 'pyproject.toml'
        metadata.write_text(metadata.read_text() +
            '\n[[tool.setuptools.ext-modules]]\nname="local_demo.value"\nsources=["src/local_demo/value.c"]\n')
        (self.repo / 'src/local_demo/value.c').write_text('int local_value(void) { return 42; }\n')
        (self.repo / 'src/local_demo/__init__.py').write_text(
            'import ctypes,pathlib\n'
            'VALUE=ctypes.CDLL(str(next(pathlib.Path(__file__).parent.glob("value*.so")))).local_value()\n')
        self.policy['project']['packages']['allow_native_wheels'] = True
        self.native_editable_import(provider=provider, compiled=True, live_compiled=True)

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_dynamic_setuptools_wheel_import(self):
        self.native_build_import(provider=self.dynamic_setuptools_project())

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_dynamic_setuptools_editable_import(self):
        self.native_editable_import(provider=self.dynamic_setuptools_project())

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_dynamic_hook_requirement_uses_only_explicit_assessed_graph(self):
        backend = self.repo / 'backend/backend.py'
        backend.write_text(backend.read_text().replace('return []', 'return ["builder==1.0"]')
                           .replace('    files = {',
                                    '    import builder\n    assert builder.VALUE == "SYNTHETIC_PACKAGE_OK"\n    files = {'))
        self.dynamic_project()
        provider = FixtureProvider()
        self.registry_graph(provider)
        self.native_build_import(provider=provider)

    def test_hook_proposal_validates_bounds_sources_and_preserves_constraints(self):
        from ptw.python_local import checked_hook_requirements
        values = ['builder[feature]>=1,<2; python_version >= "3.11"', 'builder!=1.5']
        result = checked_hook_requirements(values + values, 'local-demo')
        from packaging.requirements import Requirement
        self.assertEqual([str(Requirement(r)) for r in values], result)
        for invalid in (None, {}, 'builder', [False], [''], ['builder' * 1000],
                        ['builder'] * 65, ['--index-url=x'], ['builder @ file:///tmp/x.whl'],
                        ['builder @ https://example.invalid/x.whl'], ['LOCAL_demo==1'], ['builder\n']):
            with self.subTest(value=str(invalid)[:60]), self.assertRaises(EvidenceError):
                checked_hook_requirements(invalid, 'local-demo')

    def test_hook_discovery_requires_pending_source_authority(self):
        from ptw.python_local import discover_build_requirements
        store, actor, _ = self.activate()
        with patch('ptw.python_local.run_build') as run:
            with self.assertRaisesRegex(Invalid, 'pending source preparation'):
                discover_build_requirements(store, actor['token'], 'local')
            with self.assertRaisesRegex(Invalid, 'explicit approval'):
                discover_build_requirements(store, actor['token'], 'unknown')
            run.assert_not_called()

    def test_hook_discovery_returns_proposal_without_installing_unknown_package(self):
        from ptw.python_local import discover_build_requirements
        store, actor, bundle = self.activate(pending=True)
        def hook(store, token, command, target, **options):
            self.assertTrue(options['preparation'])
            self.assertIn('-I', command)
            self.assertIn('-S', command)
            config = json.loads(command[-1])
            self.assertEqual(config['hook'], 'get_requires_for_build_wheel')
            self.assertEqual(config['backend_path'], ['backend'])
            self.assertNotIn(str(self.repo), command)
            (target / 'requirements.json').write_text('["new-build-tool>=1,<2"]')
        with patch('ptw.python_local.run_build', side_effect=hook), \
                patch('ptw.python_local.install_wheels') as install:
            result = discover_build_requirements(store, actor['token'], 'local')
            install.assert_not_called()
        self.assertEqual(result['requirements'], ['new-build-tool<2,>=1'])
        self.assertEqual(result['policy_sha256'], bundle['approval']['sha256'])
        self.assertEqual(result['source_sha256'], self.source['snapshot_sha256'])
        self.assertEqual(result['requirements_sha256'], digest(result['requirements']))
        self.assertEqual(store.status('local-python')['policy_sha256'], bundle['approval']['sha256'])
        with store.locked() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM package_sets').fetchone()[0], 0)
            self.assertEqual(json.loads(store.session(db, actor['token'], preparation=True)['packages']), [])
        self.assertFalse(list(store.directory.glob('local-hooks-*')))

    def test_hook_discovery_editable_uses_distinct_hook_and_stale_source_denies(self):
        from ptw.python_local import discover_build_requirements
        self.editable_policy()
        store, actor, _ = self.activate(pending=True)
        def hook(store, token, command, target, **options):
            self.assertEqual(json.loads(command[-1])['hook'], 'get_requires_for_build_editable')
            (target / 'requirements.json').write_text('[]')
        with patch('ptw.python_local.run_build', side_effect=hook):
            self.assertEqual(discover_build_requirements(store, actor['token'], 'local')['requirements'], [])
        (self.repo / 'src/local_demo/__init__.py').write_text('VALUE = 99\n')
        with patch('ptw.python_local.run_build') as run:
            with self.assertRaisesRegex(Invalid, 'source changed'):
                discover_build_requirements(store, actor['token'], 'local')
            run.assert_not_called()

    def test_hook_failure_malformed_output_and_mutation_return_no_proposal(self):
        from ptw.python_local import discover_build_requirements
        store, actor, _ = self.activate(pending=True)
        def hook(store, token, command, target, **options):
            if self.hook_case == 'failure':
                raise EvidenceError('SYNTHETIC_PRIVATE_BACKEND_DIAGNOSTIC')
            if self.hook_case == 'missing':
                return
            result = target / 'requirements.json'
            if self.hook_case == 'symlink':
                result.symlink_to(target / 'source/pyproject.toml')
            elif self.hook_case == 'oversized':
                result.write_bytes(b' ' * (64 * 4096 + 1025))
            elif self.hook_case == 'mutation':
                result.write_text('[]')
                (self.repo / 'backend/backend.py').write_text('CHANGED = True\n')
            else:
                result.write_text('{invalid json')
        with patch('ptw.python_local.run_build', side_effect=hook):
            for self.hook_case in ('failure', 'missing', 'symlink', 'oversized', 'malformed', 'mutation'):
                with self.subTest(case=self.hook_case), self.assertRaises((Invalid, EvidenceError)) as caught:
                    discover_build_requirements(store, actor['token'], 'local')
                self.assertNotIn('SYNTHETIC_PRIVATE_BACKEND_DIAGNOSTIC', str(caught.exception))
                self.assertFalse(list(store.directory.glob('local-hooks-*')))
        with store.locked() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM package_sets').fetchone()[0], 0)

    def test_hook_discovery_stop_discards_output(self):
        from ptw.python_local import discover_build_requirements
        store, actor, _ = self.activate(pending=True)
        def hook(store, token, command, target, **options):
            (target / 'requirements.json').write_text('["new-build-tool"]')
            store.stop('local-python')
        with patch('ptw.python_local.run_build', side_effect=hook):
            with self.assertRaises(Invalid):
                discover_build_requirements(store, actor['token'], 'local')
        self.assertTrue(store.status('local-python')['stopped'])

    def test_hook_bootstrap_evidence_denials_precede_install_and_execution(self):
        from ptw.python_local import discover_build_requirements
        self.registry_graph(FixtureProvider())
        self.require_builder()
        store, actor, _ = self.activate(pending=True)
        for changes in ({'vulnerabilities': [CRITICAL]}, {'vulnerabilities': None},
                        {'published_at': '2099-01-01T00:00:00Z'}, {'sha256': '0' * 64},
                        {'name': 'wrong'}, {'filename': '../escape.whl'}):
            with self.subTest(changes=changes), patch('ptw.python_local.run_build') as run, \
                    patch('ptw.python_local.install_wheels') as install:
                with self.assertRaises(Invalid):
                    discover_build_requirements(store, actor['token'], 'local',
                        provider=FixtureProvider(changes={'builder': changes}))
                run.assert_not_called()
                install.assert_not_called()
                self.assertFalse(list(store.directory.glob('local-hooks-*')))
        self.assertEqual(store.status('local-python')['violations'], 0)

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_missing_optional_hook_returns_empty_proposal(self):
        from ptw.python_local import discover_build_requirements
        from ptw.monitor import ensure, remove
        from ptw.supervisor import Supervisor
        backend = self.repo / 'backend/backend.py'
        backend.write_text(backend.read_text() + '\ndel get_requires_for_build_wheel\n')
        self.source = describe_source(self.inv, self.resources, identity='local', allow_build=True)
        self.policy['project']['python_dependencies']['sources'] = [self.source]
        store, actor, _ = self.activate(pending=True)
        try:
            ensure(store)
            receipt = discover_build_requirements(store, actor['token'], 'local')
            self.assertEqual(receipt['requirements'], [])
            self.assertEqual(receipt['dependencies'], [])
            with store.locked() as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM package_sets').fetchone()[0], 0)
        finally:
            store.stop('local-python')
            Supervisor(store).reconcile()
            remove(store)

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_hook_discovery_collects_unknown_requirement_without_grant(self):
        from ptw.python_local import discover_build_requirements
        from ptw.monitor import ensure, remove
        from ptw.supervisor import Supervisor
        provider = FixtureProvider()
        self.registry_graph(provider)
        self.require_builder()
        backend = self.repo / 'backend/backend.py'
        backend.write_text(backend.read_text().replace('    return []',
            '    import builder,importlib.util,socket\n'
            '    assert builder.VALUE == "SYNTHETIC_PACKAGE_OK"\n'
            '    assert importlib.util.find_spec("new_build_tool") is None\n'
            '    assert not any("SYNTHETIC_LOCAL_INJECTION" in v for v in os.environ.values())\n'
            '    for target in HOST_PATHS:\n'
            '        assert not pathlib.Path(target).exists()\n'
            '    connection = socket.socket()\n'
            '    connection.settimeout(.2)\n'
            '    try:\n'
            '        connection.connect(("192.0.2.1", 80))\n'
            '    except OSError:\n'
            '        pass\n'
            '    else:\n'
            '        raise RuntimeError("network escaped")\n'
            '    finally:\n'
            '        connection.close()\n'
            '    return ["new-build-tool>=1,<2"]'))
        self.source = describe_source(self.inv, self.resources, identity='local', allow_build=True)
        self.policy['project']['python_dependencies']['sources'] = [self.source]
        store, actor, bundle = self.activate(pending=True)
        unrelated = subprocess.Popen(['/usr/bin/sleep', '90'])
        try:
            ensure(store)
            with patch.dict(os.environ, {k: 'SYNTHETIC_LOCAL_INJECTION' for k in
                    ('PYTHONPATH', 'PYTHONHOME', 'PIP_CONFIG_FILE', 'UV_INDEX_URL', 'FIXTURE_CREDENTIAL')}):
                receipt = discover_build_requirements(store, actor['token'], 'local', provider=provider)
            self.assertEqual(receipt['requirements'], ['new-build-tool<2,>=1'])
            self.assertEqual([r['name'] for r in receipt['dependencies']], ['builder'])
            # A returned name is still unavailable to uv under the same policy.
            with self.assertRaisesRegex(EvidenceError, 'Confined local build failed'):
                build_wheel(store, actor['token'], 'local', provider=provider)
            self.assertEqual(store.status('local-python')['policy_sha256'], bundle['approval']['sha256'])
            self.assertEqual(store.status('local-python')['violations'], 0)
            with store.locked() as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM package_sets').fetchone()[0], 0)
            self.assertEqual(self.private.read_text(), 'UNRELATED_LOCAL_SOURCE')
            self.assertEqual(self.external.read_text(), 'EXTERNAL_CONTROL')
            self.assertIsNone(unrelated.poll())
            print('LOCAL_HOOK_DISCOVERY ' + json.dumps({**receipt, 'unapproved_build_denied': True,
                'unknown_requirement_installed': False, 'unrelated_alive': True,
                'test_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}), flush=True)
        finally:
            store.stop('local-python')
            Supervisor(store).reconcile()
            remove(store)
            unrelated.terminate()
            unrelated.wait(timeout=5)

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_dynamic_identity_mismatch_publishes_nothing(self):
        from ptw.monitor import ensure, remove
        from ptw.supervisor import Supervisor
        self.dynamic_project({'version': '2.0', 'dependencies': []})
        store, actor, _ = self.activate()
        try:
            ensure(store)
            with self.assertRaisesRegex(EvidenceError, 'unexpected identity'):
                build_wheel(store, actor['token'], 'local')
            self.assertFalse(list(store.directory.glob('local-build-*')))
            with store.locked() as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM package_sets').fetchone()[0], 0)
            self.assertEqual(self.private.read_text(), 'UNRELATED_LOCAL_SOURCE')
            self.assertEqual(self.external.read_text(), 'EXTERNAL_CONTROL')
            self.assertEqual(store.status('local-python')['violations'], 0)
        finally:
            store.stop('local-python')
            Supervisor(store).reconcile()
            remove(store)

    def dynamic_setuptools_project(self):
        provider = self.setuptools_project()
        metadata = self.repo / 'pyproject.toml'
        metadata.write_text(metadata.read_text().replace('version="1.0"', 'dynamic=["version"]') +
                            '[tool.setuptools.dynamic]\nversion={file=["backend/version.txt"]}\n')
        (self.repo / 'backend/version.txt').write_text('1.0\n')
        self.source = describe_source(self.inv, self.resources, identity='local', allow_build=True,
                                      dynamic_metadata={'version': '1.0'})
        self.policy['project']['python_dependencies']['sources'] = [self.source]
        return provider

    def native_editable_import(self, *, provider=None, pending=False, compiled=False, live_compiled=False):
        from ptw.monitor import ensure, remove
        from ptw.supervisor import Supervisor
        from ptw.workspace import Workspace, request, scan, stamp
        command, narrow = self.editable_policy()
        store, actor, bundle = self.activate(pending=pending)
        unrelated = subprocess.Popen(['/usr/bin/sleep', '90'])
        try:
            ensure(store)
            injected = {key: 'SYNTHETIC_LOCAL_INJECTION' for key in (
                'PYTHONPATH', 'PYTHONHOME', 'UV_CONFIG_FILE', 'UV_INDEX_URL', 'PIP_CONFIG_FILE', 'PRIVATE_TOKEN',
                'CC', 'CFLAGS', 'LDFLAGS')}
            with patch.dict(os.environ, injected):
                receipt = install_editable(store, actor['token'], 'local', provider=provider)
            if compiled:
                self.assertTrue(receipt['native_editable'])
                self.assertEqual(len(receipt['editable_artifacts']), 1)
                self.assertFalse(list((self.repo / 'src/local_demo').glob('*.so')))
            if pending:
                with self.assertRaisesRegex(Invalid, 'pending recovery'):
                    store.register('local-python', 'work')
                with store.locked() as db:
                    units = [r['unit'] for r in db.execute('SELECT unit FROM workloads WHERE session=?',
                                                         (actor['session'],))]
                self.assertTrue(units)
                store.close_session(actor['token'])
                Supervisor(store).reconcile()
                self.assertTrue(all(Supervisor.state(unit)['confirmed_stopped'] for unit in units))
                store.commit_setup('local-python', bundle['approval']['sha256'], lambda: None)
                with store.locked() as db:
                    with self.assertRaisesRegex(Invalid, 'Session ended'):
                        store.session(db, actor['token'], preparation=True)
                actor = store.register('local-python', 'work')
            workspace = Workspace(store)
            def run(event, definition, session=actor):
                return workspace.request(session['token'], event, request('run', resource=definition['id'],
                    content=json.dumps({'package_sets': [receipt['package_set']]})))
            with patch.dict(os.environ, injected):
                first = run('editable-first', command)
            self.assertTrue(first['allowed'], first)
            self.assertEqual(first['exit_code'], 0, first)
            self.assertEqual(first['output'].strip(), '42')
            before = scan(self.inv, self.resources)['src/local_demo/__init__.py']
            edit = workspace.request(actor['token'], 'editable-change', request('write',
                resource=narrow['resources'][0], path='local_demo/__init__.py',
                content=before['data'].decode() + '\nVALUE += 57\n' if live_compiled else 'VALUE = 99\n',
                expected=stamp(before)))
            self.assertTrue(edit['allowed'], edit)
            # No reinstallation or backend execution between imports.
            with patch('ptw.python_local.run_build', side_effect=AssertionError('unexpected rebuild')):
                second = run('editable-second', command)
            if compiled and not live_compiled:
                self.assertFalse(second['allowed'], second)
                self.assertIn('Compiled editable source changed', second['reason'])
            else:
                self.assertTrue(second['allowed'], second)
                self.assertEqual(second['exit_code'], 0, second)
                self.assertEqual(second['output'].strip(), '99')
            if live_compiled:
                before_c = scan(self.inv, self.resources)['src/local_demo/value.c']
                edit_c = workspace.request(actor['token'], 'editable-c-change', request('write',
                    resource=narrow['resources'][0], path='local_demo/value.c',
                    content='int local_value(void) { return 100; }\n', expected=stamp(before_c)))
                self.assertTrue(edit_c['allowed'], edit_c)
                with patch('ptw.python_local.run_build', side_effect=AssertionError('unexpected rebuild')):
                    stale = run('editable-c-stale', command)
                self.assertFalse(stale['allowed'], stale)
                self.assertIn('Compiled editable source changed', stale['reason'])
            denied = run('editable-excluded', narrow)
            self.assertFalse(denied['allowed'], denied)
            self.assertIn('command inputs', denied['reason'])
            self.assertEqual(self.private.read_text(), 'UNRELATED_LOCAL_SOURCE')
            self.assertEqual(self.external.read_text(), 'EXTERNAL_CONTROL')
            self.assertEqual(store.status('local-python')['violations'], 1)
            self.assertEqual(store.status('local-python')['policy_sha256'], bundle['approval']['sha256'])
            store.stop('local-python')
            Supervisor(store).reconcile()
            self.assertIsNone(unrelated.poll())
            print('LOCAL_PYTHON_EDITABLE ' + json.dumps({**receipt, 'first_value': 42,
                'edited_value': None if compiled and not live_compiled else 99,
                'live_python_with_compiled_output': live_compiled, 'compiled_stale_reuse_denied': compiled,
                'no_reinstall': True, 'excluded_command_denied': True, 'unrelated_alive': True,
                'prepared_during_pending_setup': pending,
                'test_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}), flush=True)
        finally:
            store.stop('local-python')
            Supervisor(store).reconcile()
            remove(store)
            unrelated.terminate()
            unrelated.wait(timeout=5)

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_approved_uv_build_install_import_and_isolation(self):
        self.native_build_import()

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_standard_setuptools_build_and_import(self):
        provider = self.setuptools_project()
        self.native_build_import(provider=provider)
        self.assertFalse(list(self.repo.rglob('*.egg-info')))

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_selected_extra_wheel_import(self):
        self.native_extra_install(editable=False)

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_selected_extra_editable_import(self):
        self.native_extra_install(editable=True)

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_setuptools_self_referencing_extra_editable_import(self):
        self.native_extra_install(editable=True, self_reference=True)

    def native_extra_install(self, *, editable, self_reference=False):
        from ptw.monitor import ensure, remove
        from ptw.supervisor import Supervisor
        from ptw.workspace import Workspace, request
        provider = self.setuptools_project()
        self.optional_project(['feature', 'empty'])
        if self_reference:
            metadata = self.repo / 'pyproject.toml'
            metadata.write_text(metadata.read_text() + 'all=["local-demo[feature,empty]==1.0"]\n')
            self.source = describe_source(self.inv, self.resources, identity='local', allow_build=True, extras=['all'])
            self.policy['project']['python_dependencies']['sources'] = [self.source]
        descriptor = self.policy['project']['python_dependencies']
        record = provider.assess('builder', '1.0')
        descriptor['pins'].append('builder==1.0')
        descriptor['artifacts'].append({k: record[k] for k in ('name', 'version', 'url', 'sha256')})
        self.policy['project']['packages']['allowed_names'].append('pypi:builder')
        self.policy['tasks'][0]['packages'].append('pypi:builder')
        if editable:
            command, narrow = self.editable_policy()
        else:
            python = self.policy['project']['python_runtime']['executable']
            command = dict(id='local-import', argv=[python, '-s', '-c', ''], resources=self.resources, timeout_seconds=30)
            narrow = {**command, 'id': 'narrow-import', 'resources': [self.resources[0]]}
            self.policy['project']['commands'] = [command, narrow]
            self.policy['tasks'][0]['commands'] = ['local-import', 'narrow-import']
        command['argv'][-1] = (
            'import local_demo,builder,importlib.metadata as m,importlib.util as u; '
            'assert local_demo.VALUE == 42; assert builder.VALUE == "SYNTHETIC_PACKAGE_OK"; '
            'assert m.version("local-demo") == "1.0"; assert u.find_spec("absent") is None; '
            'assert set(m.metadata("local-demo").get_all("Provides-Extra")) == {"feature","unused","empty"}; '
            'print("LOCAL_EXTRA_OK")')
        if self_reference:
            command['argv'][-1] = command['argv'][-1].replace('{"feature","unused","empty"}',
                                                            '{"feature","unused","empty","all"}')
        store, actor, bundle = self.activate()
        unrelated = subprocess.Popen(['/usr/bin/sleep', '90'])
        try:
            ensure(store)
            install = install_editable if editable else install_wheel
            with patch.dict(os.environ, {'UV_EXTRA_INDEX_URL': 'SYNTHETIC_LOCAL_INJECTION',
                                          'PIP_EXTRA_INDEX_URL': 'SYNTHETIC_LOCAL_INJECTION'}):
                receipt = install(store, actor['token'], 'local', provider=provider)
            workspace = Workspace(store)
            def run(event, name):
                return workspace.request(actor['token'], event, request('run', name,
                    content=json.dumps({'package_sets': [receipt['package_set']]})))
            result = run('extra-import', 'local-import')
            self.assertTrue(result['allowed'], result)
            self.assertEqual(result['exit_code'], 0, result)
            self.assertEqual(result['output'].strip(), 'LOCAL_EXTRA_OK')
            denied = run('extra-narrow', 'narrow-import')
            self.assertFalse(denied['allowed'], denied)
            self.assertIn('command inputs', denied['reason'])
            self.assertEqual(store.status('local-python')['policy_sha256'], bundle['approval']['sha256'])
            self.assertEqual(self.private.read_text(), 'UNRELATED_LOCAL_SOURCE')
            self.assertEqual(self.external.read_text(), 'EXTERNAL_CONTROL')
            self.assertIsNone(unrelated.poll())
            print('LOCAL_PYTHON_EXTRAS ' + json.dumps({**receipt, 'mode': self.source['mode'],
                'imported_extra': 'builder', 'unselected_absent': True, 'narrow_denied': True,
                'unrelated_alive': True, 'test_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}), flush=True)
        finally:
            store.stop('local-python')
            Supervisor(store).reconcile()
            remove(store)
            unrelated.terminate()
            unrelated.wait(timeout=5)

    def setuptools_project(self):
        from ptw.package_evidence import PyPIEvidence
        # Use the release builder's existing pin and actual upstream artifact.
        # Advisory/age records below are explicitly synthetic fixture evidence,
        # not a claim about setuptools' current public vulnerability status.
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
        try:
            from build_product_release import BUILD_PIN
        finally:
            sys.path.pop(0)
        spec, expected = BUILD_PIN.strip().split(' --hash=sha256:')
        name, version = spec.split('==')
        public = PyPIEvidence()
        release = public.json('https://pypi.org/pypi/' + name + '/' + version + '/json')
        artifact = next(e for e in release['urls'] if e['digests']['sha256'] == expected)
        raw = public.fetch(artifact['url'], limit=20 * 1024 * 1024)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), expected)
        provider = FixtureProvider(wheels={name: raw})
        self.registry_graph(provider, name, version)
        (self.repo / 'pyproject.toml').write_text(
            '[project]\nname="local-demo"\nversion="1.0"\n'
            '[build-system]\nrequires=["setuptools==' + version + '"]\nbuild-backend="setuptools.build_meta"\n'
            '[tool.setuptools.packages.find]\nwhere=["src"]\n')
        self.source = describe_source(self.inv, self.resources, identity='local', allow_build=True)
        self.policy['project']['python_dependencies']['sources'] = [self.source]
        return provider

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_extra_backend_requirement_has_no_download_fallback(self):
        from ptw.monitor import ensure, remove
        from ptw.supervisor import Supervisor
        backend = self.repo / 'backend/backend.py'
        backend.write_text(backend.read_text().replace('return []', 'return ["unapproved-builder==1.0"]'))
        self.source = describe_source(self.inv, self.resources, identity='local', allow_build=True)
        self.policy['project']['python_dependencies']['sources'] = [self.source]
        store, actor, _ = self.activate()
        try:
            ensure(store)
            with self.assertRaisesRegex(EvidenceError, 'Confined local build failed'):
                build_wheel(store, actor['token'], 'local')
            self.assertFalse(list(store.directory.glob('local-build-*')))
            with store.locked() as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM package_sets').fetchone()[0], 0)
            self.assertEqual(self.private.read_text(), 'UNRELATED_LOCAL_SOURCE')
            self.assertEqual(self.external.read_text(), 'EXTERNAL_CONTROL')
        finally:
            store.stop('local-python')
            Supervisor(store).reconcile()
            remove(store)

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_compiled_output_without_native_approval_is_not_published(self):
        self.native_compiled_output_denial(editable=False)

    @unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager native confinement')
    def test_native_compiled_editable_without_native_approval_is_not_published(self):
        self.native_compiled_output_denial(editable=True)

    def native_compiled_output_denial(self, *, editable):
        from ptw.monitor import ensure, remove
        from ptw.supervisor import Supervisor
        native_library_project(self, editable=editable)
        self.source = describe_source(self.inv, self.resources, identity='local', allow_build=True)
        self.policy['project']['python_dependencies']['sources'] = [self.source]
        if editable:
            self.editable_policy()
        store, actor, _ = self.activate()
        try:
            ensure(store)
            injected = {key: 'SYNTHETIC_LOCAL_INJECTION' for key in ('CC', 'CFLAGS', 'LDFLAGS', 'PYTHONPATH')}
            with patch.dict(os.environ, injected), self.assertRaisesRegex(EvidenceError, 'native-wheel approval'):
                (install_editable if editable else install_wheel)(store, actor['token'], 'local')
            with store.locked() as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM package_sets').fetchone()[0], 0)
            self.assertFalse(list(store.directory.glob('local-build-*')))
            self.assertFalse(list(store.directory.glob('local-install-*')))
            self.assertEqual(self.private.read_text(), 'UNRELATED_LOCAL_SOURCE')
            self.assertEqual(self.external.read_text(), 'EXTERNAL_CONTROL')
            self.assertEqual(store.status('local-python')['violations'], 0)
        finally:
            store.stop('local-python')
            Supervisor(store).reconcile()
            remove(store)

    def native_build_import(self, *, provider=None):
        from ptw.monitor import ensure, remove
        from ptw.package_build import run_build
        from ptw.supervisor import Supervisor, runtime_namespace
        store, actor, bundle = self.activate()
        unrelated = subprocess.Popen(['/usr/bin/sleep', '90'])
        try:
            ensure(store)
            with self.assertRaisesRegex(Invalid, 'explicit approval'):
                build_wheel(store, actor['token'], 'unapproved-source')
            self.assertFalse(list(store.directory.glob('local-build-*')))
            injected = {key: 'SYNTHETIC_LOCAL_INJECTION' for key in (
                'PYTHONPATH', 'PYTHONHOME', 'UV_INDEX_URL', 'PIP_CONFIG_FILE', 'SYNTHETIC_CREDENTIAL')}
            with patch.dict(os.environ, injected):
                data, receipt = build_wheel(store, actor['token'], 'local', provider=provider)
            self.assertEqual(receipt['policy_sha256'], bundle['approval']['sha256'])
            self.assertEqual(receipt['sha256'], hashlib.sha256(data).hexdigest())
            target = self.root / 'native-install'
            target.mkdir()
            (target / receipt['filename']).write_bytes(data)
            python = self.policy['project']['python_runtime']['executable']
            uv = Path(os.environ.get('PTW_UV') or shutil.which('uv')).resolve()
            script = (
                'import pathlib,subprocess,sys\n'
                'subprocess.run(["/uv","--no-config","--offline","--no-cache","--no-python-downloads",'
                '"pip","install","--python",sys.executable,"--target","/target/site",'
                '"--no-deps","--no-index","--no-build","/target/' + receipt['filename'] + '"],check=True)\n'
                'sys.path.insert(0,"/target/site")\n'
                'import local_demo,importlib.metadata\n'
                'assert local_demo.VALUE == 42\n'
                'assert importlib.metadata.version("local-demo") == "1.0"\n'
                'pathlib.Path("/target/import.txt").write_text("LOCAL_IMPORT_OK")\n')
            command = runtime_namespace() + ['--ro-bind', str(uv), '/uv', '--bind', str(target), '/target',
                '--', python, '-I', '-S', '-c', script]
            run_build(store, actor['token'], command, target)
            self.assertEqual((target / 'import.txt').read_text(), 'LOCAL_IMPORT_OK')
            self.assertEqual(self.private.read_text(), 'UNRELATED_LOCAL_SOURCE')
            self.assertEqual(self.external.read_text(), 'EXTERNAL_CONTROL')
            self.assertEqual(store.status('local-python')['violations'], 0)
            store.stop('local-python')
            with self.assertRaisesRegex(Invalid, 'stopped'):
                build_wheel(store, actor['token'], 'local')
            Supervisor(store).reconcile()
            self.assertIsNone(unrelated.poll())
            print('LOCAL_PYTHON_BUILD ' + json.dumps({**receipt, 'import': True,
                'host_controls_unchanged': True, 'unrelated_alive': True,
                'test_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}), flush=True)
        finally:
            store.stop('local-python')
            Supervisor(store).reconcile()
            remove(store)
            unrelated.terminate()
            unrelated.wait(timeout=5)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] in ('--local-setup-fixture', '--local-hook-setup-fixture'):
        from ptw.cli import main
        # No model call or authentication access. Policy review, uv, monitoring,
        # transaction, controller and Linux confinement are the real path.
        with ExitStack() as fixtures:
            fixtures.enter_context(patch('ptw.codex.require_login'))
            if sys.argv[1] == '--local-hook-setup-fixture':
                # Synthetic registry evidence only. The actual uv resolver uses
                # the broker's HTTP wheel index; builds, prompts and imports are real.
                fixtures.enter_context(patch('ptw.dependency_resolution.PyPIEvidence', HookIndexFixture))
                fixtures.enter_context(patch('ptw.registry.PyPIEvidence', HookIndexFixture))
            try:
                print(json.dumps(main(sys.argv[2:])), flush=True)
            except (Invalid, EvidenceError, EOFError, KeyboardInterrupt) as exc:
                print(type(exc).__name__ + ': ' + str(exc), flush=True)
                sys.exit(2)
    else:
        unittest.main()
