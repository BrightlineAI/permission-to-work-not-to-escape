"""Poetry milestone: real native exports; synthetic wheel/advisory evidence."""
import hashlib
import json
import os
from pathlib import Path
from datetime import datetime, timezone
import subprocess
import sys
import tempfile
import tomllib
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from packaging.specifiers import SpecifierSet

from ptw import poetry_tool
from ptw.dependency_resolution import ResolutionError
from ptw.package_evidence import EvidenceError, PyPIEvidence
from ptw.policy import Invalid, approve, compile_policy, digest, load, save
from ptw.python_lock import export_lock
from ptw.python_runtime import identify
from ptw.setup_templates import RULES, template
from test_packages import CRITICAL, FixtureProvider, wheel_bytes


class ResolutionProvider(FixtureProvider):
    """Finite synthetic registry; the pinned Poetry solver does real selection."""
    def __init__(self):
        super().__init__()
        self.versions = {n: ['1.0', '1.5'] for n in ('demo', 'bonus', 'helper', 'unused', 'added', 'child')}
        self.requirements, self.overrides = {}, {}
        self.assessments = []

    def artifact_allowed(self, url, name):
        return url == 'https://files.pythonhosted.org/synthetic'

    def raw(self, name, version):
        return self.wheels.get((name, version), wheel_bytes(name, version,
            requires=self.requirements.get((name, version), ())))

    def assess(self, name, version):
        self.assessments.append((name, version))
        if version not in self.versions.get(name, []):
            raise EvidenceError('Unknown fixture release')
        result = super().assess(name, version)
        result.update(sha256=hashlib.sha256(self.raw(name, version)).hexdigest(), artifact_kind='bdist_wheel')
        result.update(self.overrides.get((name, version), {}))
        return result

    def download(self, evidence, path):
        self.downloads += 1
        path.write_bytes(self.raw(evidence['name'], evidence['version']))

    def index(self, name):
        return {'meta': {'api-version': '1.1'}, 'name': name, 'files': [
            {'filename': name + '-' + version + '-py3-none-any.whl',
             'url': 'https://files.pythonhosted.org/synthetic',
             'hashes': {'sha256': hashlib.sha256(self.raw(name, version)).hexdigest()},
             'size': len(self.raw(name, version)), 'upload-time': '2020-01-01T00:00:00Z',
             'requires-python': '>=3.11', 'yanked': False}
            for version in self.versions.get(name, [])]}


class CompatibilityProvider(ResolutionProvider, PyPIEvidence):
    """Synthetic endpoints with the real PyPI wheel selection and assessment."""
    def __init__(self):
        ResolutionProvider.__init__(self)
        PyPIEvidence.__init__(self)
        self.incompatible = {('demo', '1.5'), ('added', '1.5')}
        self.outage = None

    def index(self, name):
        if self.outage == 'index':
            raise EvidenceError('fixture index outage')
        document = ResolutionProvider.index(self, name)
        for item, version in zip(document['files'], self.versions.get(name, [])):
            if (name, version) in self.incompatible:
                item['filename'] = name + '-' + version + '-cp313-cp313-win_amd64.whl'
        return document

    def release(self, name, version):
        if self.outage == 'release':
            raise EvidenceError('fixture release outage')
        item = self.index(name)['files'][self.versions[name].index(version)]
        return {'info': {'name': name, 'version': version}, 'urls': [dict(item,
            packagetype='bdist_wheel', digests=item['hashes'], upload_time_iso_8601=item['upload-time'])]}

    def advisories(self, *args):
        if self.outage == 'advisory':
            raise EvidenceError('fixture advisory outage')
        return []

    def assess(self, name, version):
        self.assessments.append((name, version))
        return PyPIEvidence.assess(self, name, version)


class PoetryBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ptw-poetry-unit-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()

    def test_manifest_rooted_graph_empty_disconnected_and_extra_fixed_point(self):
        from email.parser import Parser
        from packaging.markers import default_environment
        from ptw.package_install import validate_dependencies

        def metadata(name, requirements=(), extras=()):
            return Parser().parsestr('Name: ' + name + '\nVersion: 1.0\n' +
                ''.join('Requires-Dist: ' + r + '\n' for r in requirements) +
                ''.join('Provides-Extra: ' + e + '\n' for e in extras))

        env = {**default_environment(), 'extra': ''}
        graph = {'demo': metadata('demo'), 'unused': metadata('unused', ['other']),
                 'other': metadata('other', ['unused'])}
        selected = {name: '1.0' for name in graph}
        # Closure alone accepts this disconnected component; root validation
        # must not let it authorize itself, even if the supplied extras say so.
        validate_dependencies(graph, selected, env)
        for roots in (set(), {'demo'}):
            with self.subTest(roots=roots), self.assertRaisesRegex(EvidenceError, 'outside selected manifest'):
                validate_dependencies(graph, selected, env, roots=roots, extras={'unused': []})
        validate_dependencies({}, {}, env, roots=set())
        with self.assertRaisesRegex(EvidenceError, 'Missing metadata'):
            validate_dependencies({}, selected, env, roots={'demo'})

        graph = {'demo': metadata('demo', ['helper', 'bonus; extra == "feature"'], ['feature']),
                 'helper': metadata('helper', ['demo[feature]']),
                 'bonus': metadata('bonus')}
        selected = {name: '1.0' for name in graph}
        # The cycle expands an already visited root's extras. Revisit it so its
        # newly active edge reaches bonus; insertion order must not affect this.
        for ordered in (graph, dict(reversed(list(graph.items())))):
            validate_dependencies(ordered, selected, env, roots={'demo'})
        graph['helper'] = metadata('helper', ['demo[feature]; python_version < "2"'])
        with self.assertRaisesRegex(EvidenceError, 'outside selected manifest.*bonus'):
            validate_dependencies(graph, selected, env, roots={'demo'})

    def test_candidate_tags_preserve_versions_and_evidence_failures(self):
        from ptw.poetry_resolution import compatible_versions
        from ptw.python_index import WheelIndex
        import time
        provider = CompatibilityProvider()
        listing = WheelIndex(provider, self.root, time.monotonic() + 30).document('demo')
        self.assertEqual(listing['versions'], ['1.0', '1.5'])
        self.assertEqual(compatible_versions(listing, {'py3-none-any'}), ['1.0'])
        self.assertEqual(compatible_versions(listing, {'cp313-cp313-win_amd64'}), ['1.5'])
        self.assertEqual(compatible_versions(listing, set()), [])
        # A version remains usable if any of its files has an admitted tag.
        listing['files'].append({**listing['files'][0], 'filename': 'demo-1.5-py2.py3-none-any.whl'})
        self.assertEqual(compatible_versions(listing, {'py3-none-any'}), ['1.0', '1.5'])
        with self.assertRaisesRegex(EvidenceError, 'No compatible wheel'):
            provider.assess('demo', '1.5')
        self.assertEqual(provider.assess('demo', '1.0')['version'], '1.0')
        provider.outage = 'advisory'
        with self.assertRaisesRegex(EvidenceError, 'fixture advisory outage'):
            provider.assess('demo', '1.0')
        provider.outage = 'index'
        with self.assertRaisesRegex(EvidenceError, 'fixture index outage'):
            WheelIndex(provider, self.root, time.monotonic() + 30).document('demo')

    def test_no_ambient_tool_fallback(self):
        with patch.dict(os.environ, {'PTW_POETRY_TOOL': ''}), self.assertRaisesRegex(Invalid, 'no ambient fallback'):
            poetry_tool.verified()

    def test_foreign_metadata_is_checked_data_not_install_assessment(self):
        import time
        from ptw.poetry_resolution import metadata_record, wheel_metadata
        from ptw.python_index import WheelIndex
        from ptw.package_evidence import evaluate
        provider = CompatibilityProvider()
        index = WheelIndex(provider, self.root, time.monotonic() + 30)
        record = metadata_record(index, 'demo', '1.5')
        self.assertEqual(record['filename'], 'demo-1.5-cp313-cp313-win_amd64.whl')
        self.assertEqual(provider.assessments, [])
        self.assertEqual(evaluate(record, RULES), [])
        wheel = self.root / 'foreign.whl'
        provider.download(record, wheel)
        self.assertEqual(wheel_metadata(wheel, record)['files'][0]['hash'], 'sha256:' + record['sha256'])
        wheel.write_bytes(b'changed')
        with self.assertRaisesRegex(EvidenceError, 'digest'):
            wheel_metadata(wheel, record)
        provider.outage = 'advisory'
        with self.assertRaisesRegex(EvidenceError, 'advisory outage'):
            metadata_record(index, 'demo', '1.5')
        with self.assertRaisesRegex(EvidenceError, 'No registry wheel'):
            metadata_record(index, 'demo', '9.0')

    def provision_fixture(self, directory, *, failure=None, lock=None):
        """Exercise real receipt/file handling without network or native tools."""
        def run(command, **kwargs):
            phase = 'compile' if 'compile' in command else 'install' if 'install' in command else 'version'
            if failure == phase + '-timeout':
                raise subprocess.TimeoutExpired(command, kwargs['timeout'])
            if failure == phase:
                return subprocess.CompletedProcess(command, 1, b'', b'fixture failure')
            if phase == 'compile':
                (directory / 'tools.lock').write_text('fixture hashed lock\n')
            elif phase == 'install':
                self.assertIn('--compile-bytecode', command)
                (directory / 'payload').mkdir()
                (directory / 'payload/module.py').write_text('pass\n')
            return subprocess.CompletedProcess(command, 0, b'', b'')

        with patch('ptw.poetry_tool.shutil.which', return_value='/usr/bin/true'), \
                patch('ptw.poetry_tool.identify', return_value={'executable': '/usr/bin/python3'}), \
                patch('ptw.poetry_tool.subprocess.run', side_effect=run):
            return poetry_tool.provision(directory, lock=lock)

    def test_provision_success_retains_one_verified_terminal_receipt(self):
        reviewed = self.root / 'reviewed.lock'
        reviewed.write_text('reviewed fixture lock\n')
        for name, lock in [('bootstrap', None), ('rebuild', reviewed)]:
            with self.subTest(name=name):
                directory = self.root / name
                self.assertEqual(self.provision_fixture(directory, lock=lock), directory)
                receipt = load(directory / 'tool.json')
                self.assertEqual(receipt['outcome'], 'ready')
                with patch('ptw.poetry_tool.identify', return_value=receipt['runtime']):
                    self.assertEqual(poetry_tool.verified(directory)[1], receipt)
                if lock:
                    self.assertEqual((directory / 'tools.lock').read_bytes(), lock.read_bytes())
                before = (directory / 'tool.json').read_bytes()
                with self.assertRaises(FileExistsError):
                    self.provision_fixture(directory, lock=lock)
                self.assertEqual((directory / 'tool.json').read_bytes(), before)

    def test_provision_failures_retain_failed_receipt_and_original_error(self):
        for phase in ('compile', 'install', 'version'):
            for timeout in (False, True):
                failure = phase + ('-timeout' if timeout else '')
                with self.subTest(failure=failure):
                    directory = self.root / failure
                    error = subprocess.TimeoutExpired if timeout else Invalid if phase == 'version' else ResolutionError
                    with self.assertRaises(error):
                        self.provision_fixture(directory, failure=failure)
                    receipt = load(directory / 'tool.json')
                    self.assertEqual(receipt['outcome'], 'failed')
                    with self.assertRaisesRegex(Invalid, 'provision a new tool directory'):
                        poetry_tool.verified(directory)

    def test_payload_link_and_content_changes_fail_closed(self):
        import py_compile
        tool = self.root / 'tool'
        (tool / 'payload').mkdir(parents=True)
        file = tool / 'payload/module.py'
        file.write_text('pass\n')
        bytecode = Path(py_compile.compile(str(file), doraise=True))
        compiled = bytecode.read_bytes()
        (tool / 'tools.lock').write_text('fixture\n')
        receipt = dict(outcome='ready', pins=poetry_tool.PINS, runtime=identify('/usr/bin/python3'),
            files=poetry_tool.payload(tool / 'payload'),
            lock_sha256=hashlib.sha256((tool / 'tools.lock').read_bytes()).hexdigest())
        (tool / 'tool.json').write_text(json.dumps(receipt))
        self.assertEqual(poetry_tool.verified(tool)[1], receipt)
        self.assertIn(str(bytecode.relative_to(tool / 'payload')), receipt['files'])
        for replacement in (b'changed bytecode', None):
            with self.subTest(bytecode=replacement):
                if replacement is None:
                    bytecode.unlink()
                else:
                    bytecode.write_bytes(replacement)
                with self.assertRaisesRegex(Invalid, 'changed'):
                    poetry_tool.verified(tool)
                bytecode.write_bytes(compiled)
        file.write_text('changed\n')
        with self.assertRaisesRegex(Invalid, 'changed'):
            poetry_tool.verified(tool)
        file.unlink()
        file.symlink_to('/usr/bin/python3')
        with self.assertRaisesRegex(Invalid, 'link'):
            poetry_tool.verified(tool)

    def test_payload_exact_recursive_bytes_and_uncached_changes(self):
        root = self.repo
        contents = {'z.py': b'print(1)\n', '.hidden': b'',
                    'a/nested/data': bytes(range(256)),
                    'a/__pycache__/module.pyc': b'compiled fixture',
                    'a.txt': b'sibling', 'space name/\u03bb.py': b'pass\n'}
        for name, data in contents.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        (root / 'empty-directory').mkdir()
        expected = {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()}
        self.assertEqual(poetry_tool.payload(root), expected)
        self.assertEqual(list(poetry_tool.payload(root)), sorted(expected))
        # Same size and restored mtime must not conceal modified content.
        changed = root / 'z.py'
        metadata = changed.stat()
        changed.write_bytes(b'print(2)\n')
        os.utime(changed, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        expected['z.py'] = hashlib.sha256(changed.read_bytes()).hexdigest()
        self.assertEqual(poetry_tool.payload(root), expected)
        changed.unlink()
        del expected['z.py']
        self.assertEqual(poetry_tool.payload(root), expected)
        changed.write_bytes(b'new file')
        expected['z.py'] = hashlib.sha256(b'new file').hexdigest()
        self.assertEqual(poetry_tool.payload(root), expected)

    def test_payload_invalid_entries_and_inspection_failures(self):
        with self.assertRaisesRegex(Invalid, 'empty'):
            poetry_tool.payload(self.repo)
        (self.repo / 'normal').write_bytes(b'valid control')
        entry = self.repo / 'invalid'
        for target in (self.repo / 'normal', self.repo, self.repo / 'missing'):
            with self.subTest(link=target):
                entry.symlink_to(target)
                try:
                    with self.assertRaisesRegex(Invalid, 'link'):
                        poetry_tool.payload(self.repo)
                finally:
                    entry.unlink()
        os.mkfifo(entry)
        try:
            with self.assertRaisesRegex(Invalid, 'special file'):
                poetry_tool.payload(self.repo)
        finally:
            entry.unlink()
        linked_root = self.root / 'linked-root'
        linked_root.symlink_to(self.repo)
        with self.assertRaisesRegex(Invalid, 'link'):
            poetry_tool.payload(linked_root)
        with self.assertRaises(FileNotFoundError):
            poetry_tool.payload(self.root / 'missing')
        nested = self.repo / 'nested'
        nested.mkdir()
        scan = os.scandir
        error = PermissionError('fixture inspection failure')
        def inspect(directory):
            if Path(directory) == nested:
                raise error
            return scan(directory)
        with patch('ptw.poetry_tool.os.scandir', side_effect=inspect), self.assertRaises(PermissionError) as caught:
            poetry_tool.payload(self.repo)
        self.assertIs(caught.exception, error)
        with patch('builtins.open', side_effect=error), self.assertRaises(PermissionError) as caught:
            poetry_tool.payload(self.repo)
        self.assertIs(caught.exception, error)

    def test_project_plugins_sources_and_dynamic_metadata_never_run(self):
        cases = [('[project]\nname="sample"\nversion="1"\ndynamic=["dependencies"]\n', 'package=[]\n'),
            ('[tool.poetry]\nname="sample"\nversion="1"\nrequires-plugins={evil="*"}\n', 'package=[]\n'),
            ('[tool.poetry]\nname="sample"\nversion="1"\n',
             '[[package]]\nname="demo"\nversion="1"\nsource={type="git",url="https://invalid.test/evil"}\n')]
        for index, (manifest, lock) in enumerate(cases):
            with self.subTest(index=index):
                (self.repo / 'pyproject.toml').write_text(manifest)
                (self.repo / 'poetry.lock').write_text(lock)
                with patch('ptw.poetry_tool.run', side_effect=AssertionError('native code reached')), self.assertRaises(Invalid):
                    export_lock(self.repo, self.root / str(index), RULES)

    def test_revision_plan_preserves_qualifiers_groups_extras_and_python(self):
        from ptw.poetry_revision import planned_edit
        original = tomllib.loads('''
[tool.poetry]
name="sample"
version="1"
[tool.poetry.dependencies]
python="^3.11"
demo={version="^1.0",markers="sys_platform == 'linux'",extras=["speed"]}
bonus={version="^1.0",optional=true}
[tool.poetry.extras]
one=["bonus"]
two=["bonus"]
[tool.poetry.group.test.dependencies]
helper="^1.0"
''')
        updated, _ = planned_edit(original, 'update', ['demo>=1.2,<2'])
        expected = tomllib.loads('''version=">=1.2,<2"''')['version']
        # Compare parsed specifiers: packaging intentionally normalizes order.
        from packaging.specifiers import SpecifierSet
        demo = updated['tool']['poetry']['dependencies']['demo']
        self.assertEqual(SpecifierSet(demo['version']), SpecifierSet(expected))
        demo['version'] = '^1.0'
        self.assertEqual(updated, original)
        removed, changes = planned_edit(original, 'remove', ['bonus'], 'extra:one')
        self.assertEqual(removed['tool']['poetry']['extras'], {'one': [], 'two': ['bonus']})
        self.assertEqual(removed['tool']['poetry']['dependencies'], original['tool']['poetry']['dependencies'])
        self.assertEqual(len(changes), 1)
        removed, _ = planned_edit(original, 'remove', ['helper'], 'test')
        self.assertEqual(removed['tool']['poetry']['group']['test']['dependencies'], {})
        self.assertEqual(removed['tool']['poetry']['dependencies'], original['tool']['poetry']['dependencies'])

    def test_revision_plan_pep621_markers_and_invalid_inputs(self):
        from ptw.poetry_revision import planned_edit
        document = tomllib.loads('''
[project]
name="sample"
version="1"
requires-python=">=3.11"
dependencies=["demo[speed]>=1; sys_platform == 'linux'"]
[project.optional-dependencies]
feature=["bonus==1"]
''')
        result, _ = planned_edit(document, 'update', ['demo>=1.5,<2'])
        from packaging.requirements import Requirement
        req = Requirement(result['project']['dependencies'][0])
        self.assertEqual(req.extras, {'speed'})
        self.assertEqual(str(req.marker), 'sys_platform == "linux"')
        self.assertEqual(result['project']['optional-dependencies'], {'feature': ['bonus==1']})
        for op, specs, group in [('add', ['demo==1'], None), ('update', ['missing==1'], None),
                ('remove', ['demo==1'], None), ('add', ['bad @ https://invalid.test/a.whl'], None),
                ('update', ['demo'], None), ('add', ['python==3.12'], None),
                ('add', ['a==1', 'A==2'], None), ('remove', ['bonus'], 'extra:'),
                ('add', [False], None), ('unknown', ['demo'], None)]:
            with self.subTest(op=op, specs=specs, group=group), self.assertRaises(Invalid):
                planned_edit(document, op, specs, group)

    def test_revision_group_owners_and_includes_are_preserved(self):
        from ptw.poetry_revision import planned_edit
        document = tomllib.loads('''
[tool.poetry]
name="sample"
version="1"
[tool.poetry.dev-dependencies]
helper={version="^1",extras=["speed"]}
[dependency-groups]
test=["demo>=1; sys_platform == 'linux'", {include-group="dev"}]
''')
        updated, _ = planned_edit(document, 'update', ['helper>=1.1,<2'], 'dev')
        dependency = updated['tool']['poetry']['dev-dependencies']['helper']
        self.assertEqual(dependency['extras'], ['speed'])
        dependency['version'] = '^1'
        self.assertEqual(updated, document)
        updated, _ = planned_edit(document, 'update', ['demo>=1.1,<2'], 'TEST')
        self.assertIn('sys_platform == "linux"', updated['dependency-groups']['test'][0])
        self.assertEqual(updated['dependency-groups']['test'][1], {'include-group': 'dev'})
        removed, _ = planned_edit(document, 'remove', ['demo'], 'test')
        self.assertEqual(removed['dependency-groups']['test'], [{'include-group': 'dev'}])
        self.assertEqual(removed['tool'], document['tool'])
        added, _ = planned_edit(document, 'add', ['added==1'], 'dev')
        self.assertEqual(added['tool']['poetry']['dev-dependencies']['added'], '==1')
        with self.assertRaisesRegex(Invalid, 'absent'):
            planned_edit(document, 'remove', ['helper'], 'test')
        document['dependency-groups']['dev'] = ['helper>=1']
        with self.assertRaisesRegex(Invalid, 'multiple group declarations'):
            planned_edit(document, 'remove', ['helper'], 'dev')

    def test_native_selection_response_validation_and_runtime_identity(self):
        from ptw.poetry_export import selection
        from ptw.python_runtime import select
        runtime = identify('/usr/bin/python3')
        for index, response in enumerate([
                {'python_ranges': ['>=3.99', '==' + runtime['version']], 'groups': ['dev', 'test']},
                {'python_ranges': ['>=3.99'], 'groups': []},
                {'python_ranges': [False], 'groups': []},
                {'python_ranges': '*', 'groups': []}, []]):
            def native(*args, **kwargs):
                (self.repo / 'project-selection.json').write_text(json.dumps(response))
                return subprocess.CompletedProcess([], 0, '', '')
            with self.subTest(index=index), patch('ptw.poetry_tool.run', side_effect=native):
                if index == 0:
                    selected, groups = selection(self.repo, executable='/usr/bin/python3')
                    self.assertEqual(selected, select('==' + runtime['version'], '/usr/bin/python3'))
                    self.assertEqual(groups, ['dev', 'test'])
                    with self.assertRaises(Invalid):
                        selection(self.repo, executable='/usr/bin/python3', version_request='3.99')
                else:
                    with self.assertRaises(Invalid):
                        selection(self.repo, executable='/usr/bin/python3')

    def test_revision_edit_failures_retain_receipts_and_reject_unrelated_changes(self):
        from ptw.poetry_revision import edit_project
        original = '[tool.poetry]\nname="sample"\nversion="1"\n[tool.poetry.dependencies]\ndemo="^1"\n'
        (self.repo / 'pyproject.toml').write_text(original)
        (self.repo / 'poetry.lock').write_text('package=[]\n')
        for mode in ('failure', 'timeout', 'unexpected'):
            def run(*args, **kwargs):
                if mode == 'timeout':
                    raise subprocess.TimeoutExpired('poetry', 30)
                if mode == 'unexpected':
                    (self.repo / 'pyproject.toml').write_text(original.replace('version="1"', 'version="2"'))
                return subprocess.CompletedProcess([], int(mode == 'failure'), '', 'fixture error')
            with self.subTest(mode=mode), patch('ptw.poetry_tool.run', side_effect=run), self.assertRaises(Invalid):
                edit_project(self.repo, 'update', ['demo>=1,<2'], python='/usr/bin/python3')
            (self.repo / 'pyproject.toml').write_text(original)
        receipts = [load(p) for p in self.repo.glob('edit-receipt-*.json')]
        self.assertEqual(len(receipts), 3)
        self.assertEqual(sorted(r['outcome'] for r in receipts), ['budget_exhausted', 'invalid', 'invalid'])

    def test_solver_wheel_metadata_identity_requirements_and_malformed_inputs(self):
        from ptw.poetry_resolution import wheel_metadata
        provider = ResolutionProvider()
        provider.requirements['demo', '1.0'] = ['child>=1; python_version >= "3.11"']
        record = provider.assess('demo', '1.0')
        wheel = self.root / 'demo.whl'
        provider.download(record, wheel)
        parsed = wheel_metadata(wheel, record)
        self.assertEqual(parsed['requires_dist'], ['child>=1; python_version >= "3.11"'])
        self.assertEqual(parsed['files'][0]['hash'], 'sha256:' + record['sha256'])
        for raw in (b'not a zip', wheel_bytes('wrong', '1.0'),
                wheel_bytes('demo', '1.0', requires=['child @ https://invalid.test/evil.whl']),
                wheel_bytes('demo', '1.0', requires=['child; unsupported_marker == "x"']),
                wheel_bytes('demo', '1.0', extra={'demo-1.0.dist-info/METADATA':
                    b'Metadata-Version: 99\nName: demo\nVersion: 1.0\n'}),
                wheel_bytes('demo', '1.0', extra={'other-1.0.dist-info/METADATA': b'Name: other\n'})):
            with self.subTest(digest=hashlib.sha256(raw).hexdigest()):
                wheel.write_bytes(raw)
                altered = {**record, 'sha256': hashlib.sha256(raw).hexdigest()}
                with self.assertRaises(Invalid):
                    wheel_metadata(wheel, altered)
        wheel.write_bytes(provider.raw('demo', '1.0'))
        with self.assertRaisesRegex(EvidenceError, 'digest'):
            wheel_metadata(wheel, {**record, 'sha256': '0' * 64})

    def test_solver_failures_are_receipted_without_input_changes(self):
        from ptw.poetry_resolution import update_poetry_lock
        (self.repo / 'pyproject.toml').write_text('[tool.poetry]\nname="sample"\nversion="1"\n')
        (self.repo / 'poetry.lock').write_text('package=[]\n[metadata]\npython-versions=">=3.11"\n')
        original = {p.name: p.read_bytes() for p in self.repo.iterdir()}
        for mode in ('tool', 'timeout', 'malformed', 'mutation', 'outage', 'origin', 'repeat'):
            stage = self.root / mode
            calls = []
            def run(*args, **kw):
                from ptw.poetry_export import INSPECT
                if args[0] == INSPECT:
                    (stage / 'project-selection.json').write_text(json.dumps(
                        {'python_ranges': ['>=3.11'], 'groups': []}))
                    return subprocess.CompletedProcess([], 0, '', '')
                calls.append(True)
                if mode == 'timeout':
                    raise subprocess.TimeoutExpired('poetry', 1)
                if mode == 'mutation':
                    (stage / 'pyproject.toml').write_text('changed')
                response = ({'outcome': 'need', 'kind': 'metadata', 'name': 'demo', 'version': '1.0'}
                    if mode in ('outage', 'origin', 'repeat') else {'outcome': 'unexpected'})
                (stage / 'solve-result.json').write_text(json.dumps(response))
                return subprocess.CompletedProcess([], int(mode == 'tool'), '', 'synthetic failure')
            provider = ResolutionProvider()
            if mode == 'outage':
                provider.assess = lambda *a: (_ for _ in ()).throw(EvidenceError('fixture outage'))
            if mode == 'origin':
                provider.requirements['demo', '1.0'] = ['child @ https://invalid.test/source.tar.gz']
            with self.subTest(mode=mode), patch('ptw.poetry_tool.verified', return_value=(self.root, {})), \
                    patch('ptw.poetry_tool.run', side_effect=run), self.assertRaises(Invalid) as caught:
                update_poetry_lock(self.repo, stage, RULES, executable='/usr/bin/python3', provider=provider)
            if mode == 'origin':
                self.assertNotIsInstance(caught.exception, EvidenceError)
                self.assertIn('Local and URL requirements', str(caught.exception.__cause__))
            receipt = load(stage / 'resolution.json')
            expected = {'tool': 'unavailable', 'timeout': 'budget_exhausted', 'outage': 'unavailable_evidence'}
            self.assertEqual(receipt['outcome'], expected.get(mode, 'invalid'))
            self.assertEqual(len(calls), 2 if mode == 'repeat' else 1)
            self.assertEqual({p.name: p.read_bytes() for p in self.repo.iterdir()}, original)

    def test_locked_export_checks_actual_wheel_graph_and_download_failures(self):
        (self.repo / 'pyproject.toml').write_text('[tool.poetry]\nname="sample"\nversion="1"\n')
        (self.repo / 'poetry.lock').write_text('package=[]\n[metadata]\npython-versions=">=3.11"\n')
        original = {p.name: p.read_bytes() for p in self.repo.iterdir()}
        runtime = identify('/usr/bin/python3')
        for mode in ('valid', 'missing', 'conflict', 'inactive', 'extra', 'digest', 'outage', 'mutation'):
            with self.subTest(mode=mode):
                requires = {'valid': ['helper>=1'], 'missing': ['child>=1'],
                    'conflict': ['helper>=2'], 'inactive': ['child; python_version < "2"'],
                    'extra': ['child; extra == "feature"']}.get(mode, [])
                provider = FixtureProvider(wheels={'demo': wheel_bytes('demo', '1.0', requires=requires,
                    extra={'demo-1.0.dist-info/METADATA': (
                        'Metadata-Version: 2.1\nName: demo\nVersion: 1.0\nProvides-Extra: feature\n' +
                        ''.join('Requires-Dist: ' + r + '\n' for r in requires)).encode()})})

                def native(*args, **kwargs):
                    stage = kwargs['cwd']
                    from ptw.poetry_export import INSPECT
                    if args[0] == INSPECT:
                        (stage / 'project-selection.json').write_text(json.dumps(
                            {'python_ranges': ['>=3.11'], 'groups': []}))
                        return subprocess.CompletedProcess([], 0, '', '')
                    (stage / 'declarations.json').write_text(json.dumps(
                        ['demo[feature]>=1' if mode == 'extra' else 'demo>=1', 'helper>=1']))
                    (stage / 'exported.txt').write_text(''.join(n + '==1.0 --hash=sha256:' +
                        provider.assess(n, '1.0')['sha256'] + '\n' for n in ('demo', 'helper')))
                    return subprocess.CompletedProcess([], 0, '', '')

                download = provider.download
                def fetch(record, path):
                    if mode == 'outage':
                        raise EvidenceError('synthetic download outage')
                    download(record, path)
                    if mode == 'digest':
                        path.write_bytes(b'changed artifact')
                    if mode == 'mutation':
                        (self.repo / 'pyproject.toml').write_text('# concurrent input change\n')

                with patch('ptw.poetry_tool.verified', return_value=(self.root, {'runtime': runtime})), \
                        patch('ptw.poetry_tool.run', side_effect=native), \
                        patch.object(provider, 'download', side_effect=fetch):
                    if mode in ('valid', 'inactive'):
                        result = export_lock(self.repo, self.root / mode, RULES, provider=provider)
                        self.assertEqual(result['pins'], ['demo==1.0', 'helper==1.0'])
                    else:
                        with self.assertRaisesRegex(Invalid, {'missing': 'dependency: child',
                                'conflict': 'dependency: helper', 'extra': 'dependency: child',
                                'digest': 'digest', 'outage': 'download outage',
                                'mutation': 'inputs changed'}[mode]):
                            export_lock(self.repo, self.root / mode, RULES, provider=provider)
                receipt = load(self.root / mode / 'resolution.json')
                self.assertEqual(receipt['outcome'], 'resolved' if mode in ('valid', 'inactive') else
                    'invalid' if mode == 'mutation' else 'unavailable_evidence')
                if mode == 'mutation':
                    self.assertEqual((self.repo / 'pyproject.toml').read_text(), '# concurrent input change\n')
                    (self.repo / 'pyproject.toml').write_bytes(original['pyproject.toml'])
                self.assertEqual({p.name: p.read_bytes() for p in self.repo.iterdir()}, original)


@unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'manager native Poetry checks required')
class PoetryNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # A new explicit tool environment, never an ambient Poetry installation.
        # Retain the hashed lock and failure receipt for manager review/rebuild.
        cls.evidence = Path(tempfile.mkdtemp(prefix='ptw-poetry-native-'))
        print('POETRY_TOOL_EVIDENCE ' + str(cls.evidence), flush=True)
        cls.tool = poetry_tool.provision(cls.evidence / 'tool',
            lock=Path(__file__).resolve().parents[1] / 'poetry-tools.lock')
        # Compilation happens only at explicit provisioning, and its output is
        # part of the verified, read-only tool payload used by every native call.
        _, receipt = poetry_tool.verified(cls.tool)
        if not any(name.startswith('poetry/__pycache__/factory.') and name.endswith('.pyc')
                   for name in receipt['files']):
            raise AssertionError('Provisioned Poetry factory bytecode is missing')
        cls.baseline = cls.evidence / 'baseline'
        cls.baseline.mkdir()
        cls.make_baseline(cls.baseline)
        cls.baseline_files = {name: (cls.baseline / name).read_bytes()
                              for name in ('pyproject.toml', 'poetry.lock')}

    def setUp(self):
        PoetryBoundaryTests.setUp(self)
        self.enterContext(patch.dict(os.environ, {'PTW_POETRY_TOOL': str(self.tool)}))
        self.provider = FixtureProvider()
        self.manifest = self.repo / 'pyproject.toml'
        for name, content in self.baseline_files.items():
            (self.repo / name).write_bytes(content)

    @classmethod
    def make_baseline(cls, root):
        # Serialize once with real Poetry per fresh suite environment. Each
        # test receives independent bytes; all exports/edits/solves stay native.
        (root / 'pyproject.toml').write_text('[tool.poetry]\nname="sample"\nversion="1.0"\npackage-mode=false\n'
            '[tool.poetry.dependencies]\npython="^3.11"\ndemo="^1.0"\n'
            'bonus={version="^1.0",optional=true}\n'
            '[tool.poetry.extras]\nfeature=["bonus"]\n'
            '[tool.poetry.group.test.dependencies]\nhelper="^1.0"\n'
            '[tool.poetry.group.unselected.dependencies]\nunused="^1.0"\n')
        # Poetry itself serializes the fixture lock and content hash. This is
        # native lock/export evidence, not a claim of native network resolution.
        script = '''
import json, sys
from pathlib import Path
from poetry.factory import Factory
from poetry.core.packages.package import Package
from poetry.packages.transitive_package_info import TransitivePackageInfo
from poetry.core.version.markers import parse_marker
config=json.loads(sys.argv[1])
poetry=Factory().create_poetry(Path.cwd(), disable_plugins=True)
packages={}
for name, group in [('demo','main'),('bonus','main'),('helper','test'),('unused','unselected')]:
    package=Package(name,'1.0')
    package.python_versions='>=3.11,<4'
    package.optional=name=='bonus'
    package.files=[{'file':name+'-1.0-py3-none-any.whl','hash':'sha256:'+config[name]}]
    marker=parse_marker('extra == "feature"' if name=='bonus' else '*')
    packages[package]=TransitivePackageInfo(0,{group},{group:marker})
poetry.locker.set_lock_data(poetry.package,packages)
'''
        provider = FixtureProvider()
        config = {n: provider.assess(n, '1.0')['sha256'] for n in ('demo', 'bonus', 'helper', 'unused')}
        result = poetry_tool.run(script, config, cwd=root, timeout=30, directory=cls.tool)
        if result.returncode:
            raise AssertionError(result.stderr[-2000:])

    def export(self, name='export', **options):
        return export_lock(self.repo, self.root / name, RULES, provider=self.provider, **options)

    def test_native_locked_export_selection_runtime_and_identity(self):
        original = {n: (self.repo / n).read_bytes() for n in ('pyproject.toml', 'poetry.lock')}
        result = self.export(extras=('feature',))
        self.assertEqual(set(result['pins']), {'demo==1.0', 'bonus==1.0', 'helper==1.0'})
        self.assertEqual(result['authority'], 'poetry.lock')
        self.assertEqual(result['runtime']['executable'], identify(result['runtime']['executable'])['executable'])
        for name, content in original.items():
            self.assertEqual(result['inputs'][name], hashlib.sha256(content).hexdigest())
            self.assertEqual((self.repo / name).read_bytes(), content)
        minimal = self.export('minimal', groups=(), extras=())
        self.assertEqual(minimal['pins'], ['demo==1.0'])

    def refresh_lock(self, helper_group='test'):
        result = poetry_tool.run('''
import json, sys
from pathlib import Path
from poetry.factory import Factory
from poetry.packages.transitive_package_info import TransitivePackageInfo
from poetry.core.version.markers import parse_marker
p=Factory().create_poetry(Path.cwd(),disable_plugins=True)
group=json.loads(sys.argv[1])['group']
packages={package: TransitivePackageInfo(info.depth,{group},{group:parse_marker('*')})
          if package.name=='helper' else info
          for package,info in p.locker.locked_packages().items()}
p.locker.set_lock_data(p.package,packages)
''', {'group': helper_group}, cwd=self.repo, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])

    def test_native_poetry_python_tilde_wildcard_and_invalid_constraints(self):
        original = self.manifest.read_text()
        runtime = identify('/usr/bin/python3')
        minor = '.'.join(runtime['version'].split('.')[:2])
        for index, constraint in enumerate(('~' + minor, '*')):
            with self.subTest(constraint=constraint):
                self.manifest.write_text(original.replace('python="^3.11"', 'python="' + constraint + '"'))
                self.refresh_lock()
                before = {n: (self.repo / n).read_bytes() for n in ('pyproject.toml', 'poetry.lock')}
                result = self.export('python-' + str(index), executable='/usr/bin/python3')
                self.assertEqual(result['runtime']['version'], runtime['version'])
                self.assertEqual(set(result['pins']), {'demo==1.0', 'helper==1.0'})
                for name, content in before.items():
                    self.assertEqual((self.repo / name).read_bytes(), content)
        for index, constraint in enumerate(('~3.99', 'not-a-python-version')):
            with self.subTest(constraint=constraint):
                self.manifest.write_text(original.replace('python="^3.11"', 'python="' + constraint + '"'))
                with self.assertRaises(Invalid):
                    self.export('invalid-python-' + str(index), executable='/usr/bin/python3')

    def test_native_legacy_and_pep735_group_import_and_revisions(self):
        from ptw.poetry_revision import planned_edit
        original = self.manifest.read_text()
        lock = (self.repo / 'poetry.lock').read_bytes()
        for form, group, declaration in [
                ('legacy', 'dev', '[tool.poetry.dev-dependencies]\nhelper="^1.0"\n'),
                ('pep735', 'test', '[dependency-groups]\ntest=["helper>=1,<2"]\n')]:
            with self.subTest(form=form):
                self.manifest.write_text(original.replace(
                    '[tool.poetry.group.test.dependencies]\nhelper="^1.0"\n', declaration))
                (self.repo / 'poetry.lock').write_bytes(lock)
                self.refresh_lock(group)
                self.provider = ResolutionProvider()
                before = self.manifest.read_bytes()
                imported = self.export(form + '-default')
                self.assertEqual(set(imported['pins']), {'demo==1.0', 'helper==1.0'})
                explicit = self.export(form + '-explicit', groups=(group,))
                self.assertEqual(imported['pins'], explicit['pins'])
                self.assertEqual(self.manifest.read_bytes(), before)
                for operation, specs in [('update', ['helper>=1,<2']),
                        ('remove', ['helper']), ('add', ['added>=1,<2'])]:
                    expected, _ = planned_edit(tomllib.loads(self.manifest.read_text()), operation, specs, group)
                    result = self.revise(form + '-' + operation, operation, specs, group=group)
                    self.assertEqual(tomllib.loads(self.manifest.read_text()), expected)
                    self.assertEqual(result['runtime'], imported['runtime'])
                    self.assertEqual(set(result['pins']), {'demo==1.0', *(
                        ['helper==1.5'] if operation == 'update' else
                        ['added==1.5'] if operation == 'add' else [])})
                    (self.repo / 'poetry.lock').write_text(result['files']['poetry.lock'])

    def test_native_stale_lock_and_unknown_selection_rejected(self):
        with self.assertRaises(Invalid):
            self.export('group', groups=('missing',))
        with self.assertRaises(ResolutionError):
            self.export('extra', extras=('missing',))
        self.manifest.write_text(self.manifest.read_text().replace('demo="^1.0"', 'demo="^2.0"'))
        with self.assertRaises(ResolutionError):
            self.export('stale')

    def test_native_missing_and_conflicting_lock_entries_rejected(self):
        original = (self.repo / 'poetry.lock').read_bytes()
        script = '''
import json, sys, tomlkit
from pathlib import Path
mode=json.loads(sys.argv[1])['mode']
path=Path('poetry.lock')
document=tomlkit.parse(path.read_text())
for index, package in enumerate(document['package']):
    if package['name']=='demo':
        if mode=='missing':
            del document['package'][index]
        else:
            package['version']='2.0'
        break
path.write_text(tomlkit.dumps(document))
'''
        for mode in ('missing', 'conflicting'):
            with self.subTest(mode=mode):
                (self.repo / 'poetry.lock').write_bytes(original)
                proc = poetry_tool.run(script, {'mode': mode}, cwd=self.repo, timeout=30)
                self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
                altered = (self.repo / 'poetry.lock').read_bytes()
                with self.assertRaises(Invalid):
                    self.export(mode)
                self.assertEqual(self.provider.downloads, 0)
                self.assertEqual((self.repo / 'poetry.lock').read_bytes(), altered)
                self.assertNotEqual(load(self.root / mode / 'resolution.json')['outcome'], 'resolved')

    def test_native_locked_wheel_dependency_closure(self):
        original = (self.repo / 'poetry.lock').read_text()
        old_digest = self.provider.assess('demo', '1.0')['sha256']
        for mode, requires in [('valid', ['helper>=1,<2']), ('missing', ['child>=1']),
                ('conflict', ['helper>=2']), ('inactive', ['child; python_version < "2"'])]:
            with self.subTest(mode=mode):
                self.provider = FixtureProvider(wheels={'demo': wheel_bytes('demo', '1.0', requires=requires)})
                new_digest = self.provider.assess('demo', '1.0')['sha256']
                # Valid upstream artifact hashes, but omitted/forged dependency
                # metadata in the lock. Freshness alone cannot detect this.
                altered = original.replace(old_digest, new_digest)
                (self.repo / 'poetry.lock').write_text(altered)
                if mode in ('valid', 'inactive'):
                    result = self.export(mode)
                    self.assertEqual(set(result['pins']), {'demo==1.0', 'helper==1.0'})
                else:
                    with self.assertRaisesRegex(EvidenceError, 'dependency: ' +
                            ('child' if mode == 'missing' else 'helper')):
                        self.export(mode)
                self.assertEqual(self.provider.downloads, 2)
                self.assertEqual((self.repo / 'poetry.lock').read_text(), altered)

    def test_native_manifest_reachability_rejects_forged_selection(self):
        manifest = self.manifest.read_bytes()
        lock_path = self.repo / 'poetry.lock'
        original = lock_path.read_bytes()
        original_hash = tomllib.loads(original.decode())['metadata']['content-hash']
        script = '''
import json, sys, tomlkit
from pathlib import Path
config=json.loads(sys.argv[1])
path=Path('poetry.lock')
document=tomlkit.parse(path.read_text())
for package in document['package']:
    name=package['name']
    if name in config['names']:
        package['groups']=['main']
        package['markers']='*'
        package['optional']=False
    if name in config['hashes']:
        package['files'][0]['hash']='sha256:'+config['hashes'][name]
path.write_text(tomlkit.dumps(document))
'''
        for mode in ('group', 'extra-marker', 'disconnected', 'transitive-extras'):
            with self.subTest(mode=mode):
                lock_path.write_bytes(original)
                names = ['unused'] if mode == 'group' else ['bonus']
                wheels = {}
                if mode == 'disconnected':
                    names = ['unused', 'helper']
                    wheels = {n: wheel_bytes(n, '1.0', requires=[d])
                              for n, d in [('unused', 'helper'), ('helper', 'unused')]}
                elif mode == 'transitive-extras':
                    names = ['helper', 'unused', 'bonus']
                    for name, requires, extra in [
                            ('demo', ['helper[feature]', 'bonus; extra == "again"'], 'again'),
                            ('helper', ['unused; extra == "feature"'], 'feature'),
                            ('unused', ['demo[again]'], None)]:
                        metadata = ('Metadata-Version: 2.1\nName: ' + name + '\nVersion: 1.0\n' +
                            ''.join('Requires-Dist: ' + r + '\n' for r in requires) +
                            ('Provides-Extra: ' + extra + '\n' if extra else '')).encode()
                        wheels[name] = wheel_bytes(name, '1.0', extra={
                            name + '-1.0.dist-info/METADATA': metadata})
                self.provider = FixtureProvider(wheels=wheels)
                hashes = {n: self.provider.assess(n, '1.0')['sha256'] for n in wheels}
                result = poetry_tool.run(script, {'names': names, 'hashes': hashes},
                                         cwd=self.repo, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr[-2000:])
                altered = lock_path.read_bytes()
                document = tomllib.loads(altered.decode())
                self.assertEqual(document['metadata']['content-hash'], original_hash)
                # All artifact hashes remain valid. Only wheel edges rooted in
                # demo can authorize additional exports when no groups/extras
                # are selected, regardless of the lock's labels and cycles.
                for package in document['package']:
                    self.assertEqual(package['files'][0]['hash'], 'sha256:' +
                                     self.provider.assess(package['name'], '1.0')['sha256'])
                if mode == 'transitive-extras':
                    exported = self.export(mode, groups=(), extras=())
                    self.assertEqual(set(exported['pins']),
                                     {'demo==1.0', 'helper==1.0', 'unused==1.0', 'bonus==1.0'})
                else:
                    with self.assertRaisesRegex(EvidenceError, 'outside selected manifest'):
                        self.export(mode, groups=(), extras=())
                    self.assertEqual(load(self.root / mode / 'resolution.json')['outcome'],
                                     'unavailable_evidence')
                self.assertEqual(self.manifest.read_bytes(), manifest)
                self.assertEqual(lock_path.read_bytes(), altered)

    def test_native_forged_hash_age_cvss_and_evidence_outage(self):
        for name, changes in [('digest', {'sha256': '0' * 64}),
                ('young', {'published_at': '2099-01-01T00:00:00Z'}),
                ('critical', {'vulnerabilities': [CRITICAL]}), ('missing', {'vulnerabilities': None})]:
            with self.subTest(name=name):
                self.provider.changes = {'demo': changes}
                with self.assertRaises((Invalid, EvidenceError)):
                    self.export(name)
        self.provider.changes = {}
        with patch.object(self.provider, 'assess', side_effect=EvidenceError('fixture unavailable')):
            with self.assertRaises(EvidenceError):
                self.export('outage')

    def test_native_manifest_python_constraint_cannot_be_forged_in_lock(self):
        # Alter both the manifest and native content hash, retaining a permissive
        # lock Python field. The actual manifest must still constrain execution.
        self.manifest.write_text(self.manifest.read_text().replace('python="^3.11"', 'python="^3.99"'))
        result = poetry_tool.run('''
from pathlib import Path
from poetry.factory import Factory
p=Factory().create_poetry(Path.cwd(),disable_plugins=True)
text=Path('poetry.lock').read_text()
old=p.locker.lock_data['metadata']['content-hash']
Path('poetry.lock').write_text(text.replace(old,p.locker._content_hash))
''', {}, cwd=self.repo, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        with self.assertRaises(ResolutionError):
            self.export()

    def test_native_staged_add_remove_update_preserve_poetry_authority(self):
        from ptw.poetry_revision import edit_project, planned_edit
        manifest, lock = self.manifest.read_bytes(), (self.repo / 'poetry.lock').read_bytes()
        for operation, specs, group in [('add', ['added>=1,<2'], None),
                ('update', ['demo>=1.1,<2'], None), ('remove', ['demo'], None),
                ('update', ['helper>=1.1,<2'], 'test'), ('remove', ['helper'], 'test'),
                ('add', ['added>=1,<2'], 'extra:feature'), ('remove', ['bonus'], 'extra:feature')]:
            with self.subTest(operation=operation, specs=specs, group=group):
                self.manifest.write_bytes(manifest)
                expected, _ = planned_edit(tomllib.loads(manifest.decode()), operation, specs, group)
                edit_project(self.repo, operation, specs, group=group, python='/usr/bin/python3')
                self.assertEqual(tomllib.loads(self.manifest.read_text()), expected)
                self.assertEqual((self.repo / 'poetry.lock').read_bytes(), lock)
                self.assertFalse((self.repo / 'uv.lock').exists())
                self.assertFalse((self.repo / 'requirements.txt').exists())

    def test_native_staged_pep621_and_hybrid_edits(self):
        from ptw.poetry_revision import edit_project, planned_edit
        manifests = [
            '[project]\nname="sample"\nversion="1"\nrequires-python=">=3.11,<4"\n'
            'dependencies=["demo>=1,<2; sys_platform == \'linux\'"]\n'
            '[project.optional-dependencies]\nfeature=["bonus>=1,<2"]\n'
            '[tool.poetry]\npackage-mode=false\n',
            '[project]\nname="sample"\nversion="1"\n'
            '[tool.poetry]\npackage-mode=false\n'
            '[tool.poetry.dependencies]\npython=">=3.11,<4"\ndemo="^1.0"\n']
        lock = (self.repo / 'poetry.lock').read_bytes()
        for index, manifest in enumerate(manifests):
            for operation, specs, group in [('update', ['demo>=1.1,<2'], None),
                    ('remove', ['demo'], None), ('add', ['added>=1,<2'], None)]:
                with self.subTest(index=index, operation=operation):
                    self.manifest.write_text(manifest)
                    (self.repo / 'poetry.lock').write_bytes(lock)
                    result = poetry_tool.run('''
from pathlib import Path
from poetry.factory import Factory
p=Factory().create_poetry(Path.cwd(),disable_plugins=True)
p.locker.set_lock_data(p.package,p.locker.locked_packages())
''', {}, cwd=self.repo, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr[-2000:])
                    before = (self.repo / 'poetry.lock').read_bytes()
                    expected, _ = planned_edit(tomllib.loads(manifest), operation, specs, group)
                    edit_project(self.repo, operation, specs, group=group, python='/usr/bin/python3')
                    self.assertEqual(tomllib.loads(self.manifest.read_text()), expected)
                    self.assertEqual((self.repo / 'poetry.lock').read_bytes(), before)

    def test_native_staged_edit_rejects_stale_lock(self):
        from ptw.poetry_revision import edit_project
        self.manifest.write_text(self.manifest.read_text().replace('demo="^1.0"', 'demo="^2.0"'))
        original = self.manifest.read_bytes()
        with self.assertRaises(ResolutionError):
            edit_project(self.repo, 'add', ['added==1'], python='/usr/bin/python3')
        self.assertEqual(self.manifest.read_bytes(), original)

    def revise(self, name, operation, specs, *, group=None, rules=None, **options):
        from ptw.poetry_revision import edit_project
        from ptw.poetry_resolution import update_poetry_lock
        edit_project(self.repo, operation, specs, group=group, python='/usr/bin/python3')
        return update_poetry_lock(self.repo, self.root / name, RULES if rules is None else rules, executable='/usr/bin/python3',
            provider=self.provider, upgrade=[s.split('>')[0].split('=')[0] for s in specs]
            if operation == 'update' else [], **options)

    def test_native_solver_add_remove_update_and_empty_graph(self):
        self.provider = ResolutionProvider()
        result = self.revise('add', 'add', ['added>=1,<2'], extras=('feature',))
        self.assertEqual(set(result['pins']), {'demo==1.0', 'bonus==1.0', 'helper==1.0', 'added==1.5'})
        self.assertEqual(result['authority'], 'poetry.lock')
        self.assertEqual(result['inputs']['poetry.lock'], hashlib.sha256(result['files']['poetry.lock'].encode()).hexdigest())
        locked = tomllib.loads(result['files']['poetry.lock'])
        self.assertEqual(locked['metadata']['python-versions'], '^3.11')
        self.assertEqual(next(p for p in locked['package'] if p['name'] == 'unused')['groups'], ['unselected'])
        self.assertEqual(locked['extras'], {'feature': ['bonus']})
        (self.repo / 'poetry.lock').write_text(result['files']['poetry.lock'])
        before = tomllib.loads(self.manifest.read_text())
        result = self.revise('update', 'update', ['demo>=1,<2'], extras=('feature',))
        self.assertIn('demo==1.5', result['pins'])
        after = tomllib.loads(self.manifest.read_text())
        after['tool']['poetry']['dependencies']['demo'] = before['tool']['poetry']['dependencies']['demo']
        self.assertEqual(before, after)
        (self.repo / 'poetry.lock').write_text(result['files']['poetry.lock'])
        result = self.revise('remove', 'remove', ['added'])
        self.assertNotIn('added', {p.split('==')[0] for p in result['pins']})
        (self.repo / 'poetry.lock').write_text(result['files']['poetry.lock'])
        result = self.revise('remove-main', 'remove', ['demo'], groups=(), extras=())
        self.assertEqual(result['pins'], [])
        self.assertEqual(result['artifacts'], [])
        self.assertEqual(set(result['files']), {'poetry.lock'})
        self.assertFalse((self.repo / 'uv.lock').exists())

    def test_native_solver_age_cvss_and_transitive_compatible_fallback(self):
        original = {p.name: p.read_bytes() for p in self.repo.iterdir() if p.is_file()}
        for reason in ('age', 'cvss', 'transitive'):
            with self.subTest(reason=reason):
                for name, raw in original.items():
                    (self.repo / name).write_bytes(raw)
                self.provider = ResolutionProvider()
                bad = {'published_at': datetime.now(timezone.utc).isoformat()}
                if reason != 'age':
                    bad = {'vulnerabilities': [CRITICAL]}
                self.provider.overrides['child' if reason == 'transitive' else 'demo', '1.5'] = bad
                if reason == 'transitive':
                    self.provider.requirements['demo', '1.5'] = ['child>=1,<2']
                result = self.revise(reason, 'update', ['demo>=1,<2'])
                self.assertIn('demo==1.5' if reason == 'transitive' else 'demo==1.0', result['pins'])
                if reason == 'transitive':
                    self.assertIn('child==1.0', result['pins'])
                    self.assertNotIn('child==1.5', result['pins'])
                receipt = load(self.root / reason / 'resolution.json')
                self.assertEqual(receipt['outcome'], 'resolved')
                self.assertTrue(any(a['outcome'] == 'policy_exclusion' for a in receipt['attempts']))
                self.assertEqual((self.repo / 'poetry.lock').read_bytes(), original['poetry.lock'])

    def test_native_solver_excludes_forbidden_lock_preference(self):
        self.provider = ResolutionProvider()
        self.provider.overrides['demo', '1.0'] = {'vulnerabilities': [CRITICAL]}
        result = self.revise('locked-exclusion', 'add', ['added>=1,<2'])
        self.assertIn('demo==1.5', result['pins'])
        self.assertNotIn('demo==1.0', result['pins'])
        self.assertIn('helper==1.0', result['pins'])

    def test_native_solver_wheel_compatibility_fallback(self):
        original = {p.name: p.read_bytes() for p in self.repo.iterdir() if p.is_file()}
        for mode in ('add', 'update', 'locked'):
            with self.subTest(mode=mode):
                for name, raw in original.items():
                    (self.repo / name).write_bytes(raw)
                self.provider = CompatibilityProvider()
                self.provider.native = mode == 'update'
                if mode == 'locked':
                    self.provider.incompatible = {('demo', '1.0')}
                result = self.revise('compatible-' + mode, 'update' if mode == 'update' else 'add',
                    ['demo>=1,<2'] if mode == 'update' else ['added>=1,<2'],
                    rules={**RULES, 'allow_native_wheels': self.provider.native})
                self.assertIn('demo==1.5' if mode == 'locked' else 'demo==1.0', result['pins'])
                if mode == 'add':
                    self.assertIn('added==1.0', result['pins'])
                self.assertFalse(set(self.provider.assessments) & self.provider.incompatible)
                self.assertEqual(result['runtime']['executable'], identify('/usr/bin/python3')['executable'])
                self.assertEqual((self.repo / 'poetry.lock').read_bytes(), original['poetry.lock'])
                self.assertEqual(load(self.root / ('compatible-' + mode) / 'resolution.json')['outcome'], 'resolved')

    def test_native_solver_incompatible_pin_and_real_evidence_outages(self):
        original = {p.name: p.read_bytes() for p in self.repo.iterdir() if p.is_file()}
        for mode in ('exact', 'index', 'release', 'advisory'):
            with self.subTest(mode=mode):
                for name, raw in original.items():
                    (self.repo / name).write_bytes(raw)
                self.provider = CompatibilityProvider()
                self.provider.outage = None if mode == 'exact' else mode
                with self.assertRaises(ResolutionError if mode == 'exact' else EvidenceError):
                    self.revise('compatibility-failure-' + mode, 'update',
                        ['demo==1.5'] if mode == 'exact' else ['demo>=1,<2'])
                receipt = load(self.root / ('compatibility-failure-' + mode) / 'resolution.json')
                self.assertEqual(receipt['outcome'], 'unsatisfiable' if mode == 'exact' else 'unavailable_evidence')
                self.assertFalse(set(self.provider.assessments) & self.provider.incompatible)
                self.assertEqual((self.repo / 'poetry.lock').read_bytes(), original['poetry.lock'])

    def platform_fixture(self, *, shared=False):
        self.provider = CompatibilityProvider()
        self.provider.incompatible = {('winonly', '1.0'), ('child', '1.5')}
        self.provider.versions['winonly'] = ['1.0']
        self.provider.requirements['winonly', '1.0'] = ['child>=1,<2']
        if shared:
            # Same child reached through both an inactive and an active parent.
            self.provider.requirements['added', '1.5'] = ['child>=1,<2']
        self.manifest.write_text(self.manifest.read_text().replace('demo="^1.0"',
            'demo="^1.0"\nwinonly={version="==1.0",markers="sys_platform == \'win32\'"}'))
        script = '''
import json, sys
from pathlib import Path
from poetry.factory import Factory
from poetry.core.packages.package import Package
from poetry.core.packages.dependency import Dependency
from poetry.core.version.markers import parse_marker
from poetry.packages.transitive_package_info import TransitivePackageInfo
config=json.loads(sys.argv[1])
poetry=Factory().create_poetry(Path.cwd(), disable_plugins=True)
packages=poetry.locker.locked_packages()
for name, version in [('winonly','1.0'),('child','1.5')]:
    package=Package(name, version)
    package.python_versions='>=3.11'
    package.files=config[name]
    if name == 'winonly':
        package.add_dependency(Dependency('child','>=1,<2'))
    packages[package]=TransitivePackageInfo(0, {'main'}, {'main':parse_marker('sys_platform == "win32"')})
poetry.locker.set_lock_data(poetry.package, packages)
'''
        files = {}
        for name, version in [('winonly', '1.0'), ('child', '1.5')]:
            item = self.provider.index(name)['files'][self.provider.versions[name].index(version)]
            files[name] = [{'file': item['filename'], 'hash': 'sha256:' + item['hashes']['sha256']}]
        result = poetry_tool.run(script, files, cwd=self.repo, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])

    def test_native_solver_preserves_inactive_platform_lock_and_transitives(self):
        self.platform_fixture()
        original_lock = (self.repo / 'poetry.lock').read_bytes()
        before = tomllib.loads(self.manifest.read_text())['tool']['poetry']['dependencies']['winonly']
        for operation, specs in [('add', ['added>=1,<2']), ('update', ['demo>=1,<2'])]:
            result = self.revise('platform-' + operation, operation, specs)
            self.assertEqual((self.repo / 'poetry.lock').read_bytes(), original_lock)
            self.assertNotIn('winonly', {p.split('==')[0] for p in result['pins']})
            self.assertNotIn('child', {p.split('==')[0] for p in result['pins']})
            packages = {p['name']: p for p in tomllib.loads(result['files']['poetry.lock'])['package']}
            self.assertEqual(packages['winonly']['version'], '1.0')
            self.assertEqual(packages['child']['version'], '1.5')
            self.assertIn('win32', str(packages['child']['markers']))
            self.assertEqual(SpecifierSet(packages['winonly']['dependencies']['child']), SpecifierSet('>=1,<2'))
            self.assertEqual(before, tomllib.loads(self.manifest.read_text())['tool']['poetry']['dependencies']['winonly'])
            self.assertFalse(set(self.provider.assessments) & self.provider.incompatible)
            (self.repo / 'poetry.lock').write_text(result['files']['poetry.lock'])
            original_lock = (self.repo / 'poetry.lock').read_bytes()

    def test_native_solver_shared_platform_path_requires_compatible_wheel(self):
        self.platform_fixture(shared=True)
        original_lock = (self.repo / 'poetry.lock').read_bytes()
        # Only added 1.5 requires child. A range permits Poetry to keep the
        # locked foreign child by choosing added 1.0, which never exercises
        # the shared active path. Require that path without relaxing assertions.
        result = self.revise('shared-platform', 'add', ['added==1.5'])
        self.assertIn('child==1.0', result['pins'])
        self.assertIn('added==1.5', result['pins'])
        self.assertNotIn('winonly==1.0', result['pins'])
        self.assertEqual((self.repo / 'poetry.lock').read_bytes(), original_lock)
        packages = {p['name']: p for p in tomllib.loads(result['files']['poetry.lock'])['package']}
        self.assertEqual(packages['winonly']['version'], '1.0')
        self.assertEqual(packages['child']['version'], '1.0')
        self.assertEqual(SpecifierSet(packages['winonly']['dependencies']['child']), SpecifierSet('>=1,<2'))
        self.assertEqual(SpecifierSet(packages['added']['dependencies']['child']), SpecifierSet('>=1,<2'))
        self.assertFalse(set(self.provider.assessments) & self.provider.incompatible)

    def test_native_solver_exact_pin_outage_and_budget_fail_closed(self):
        original = {p.name: p.read_bytes() for p in self.repo.iterdir() if p.is_file()}
        for mode in ('exact', 'outage', 'budget', 'malformed'):
            with self.subTest(mode=mode):
                for name, raw in original.items():
                    (self.repo / name).write_bytes(raw)
                self.provider = ResolutionProvider()
                self.provider.overrides['demo', '1.5'] = {'vulnerabilities': [CRITICAL]}
                if mode == 'outage':
                    self.provider.overrides['demo', '1.5'] = {'vulnerabilities': None}
                if mode == 'malformed':
                    self.provider.overrides.clear()
                    self.provider.requirements['demo', '1.5'] = ['child @ https://invalid.test/source.tar.gz']
                with self.assertRaises(Invalid):
                    self.revise(mode, 'update', ['demo==1.5'], **({'max_assessments': 1} if mode == 'budget' else {}))
                receipt = load(self.root / mode / 'resolution.json')
                self.assertEqual(receipt['outcome'], {'exact': 'unsatisfiable', 'outage': 'unavailable_evidence',
                    'budget': 'budget_exhausted', 'malformed': 'invalid'}[mode])
                self.assertEqual((self.repo / 'poetry.lock').read_bytes(), original['poetry.lock'])

    def activated_revision(self):
        from ptw.onboarding import private_directory
        from ptw.store import Store
        from ptw.workspace import Workspace, request
        from ptw.monitor import remove
        from ptw.supervisor import Supervisor
        self.provider = ResolutionProvider()
        result = self.export('initial-review', extras=('feature',))
        self.enterContext(patch.dict(os.environ, {'PTW_USER_STATE': str(self.root / 'operator')}))
        directory = private_directory(self.repo)
        (self.repo / 'src').mkdir()
        (self.repo / 'src/app.py').write_text('import demo, helper, bonus\n'
            'assert demo.VALUE == helper.VALUE == bonus.VALUE == "SYNTHETIC_PACKAGE_OK"\n'
            'print("POETRY_REVISION_IMPORT_OK")\n')
        (self.repo / 'ptw-requirements.txt').write_text('\n'.join(result['pins']) + '\n')
        (self.repo / '.ptw').mkdir()
        result['inputs']['ptw-requirements.txt'] = hashlib.sha256((self.repo / 'ptw-requirements.txt').read_bytes()).hexdigest()
        policy, inv = template(self.repo, 'poetry-revision', 'Review Poetry dependencies', {'src': 'tree'},
            list(result['inputs']), [{'id': 'test', 'argv': [result['runtime']['executable'], 'src/app.py'],
                'resources': ['src'], 'timeout_seconds': 15}],
            ['pypi:demo', 'pypi:helper', 'pypi:bonus', 'pypi:unrelated'], 1, 3)
        policy['project']['python_runtime'] = result['runtime']
        policy['project']['python_dependencies'] = {**{k: result[k] for k in ('inputs', 'pins', 'artifacts', 'authority')},
            'groups': ['test'], 'extras': ['feature']}
        policy['project']['packages']['min_release_age_days'] = 20
        bundle = approve(policy, inv, digest(compile_policy(policy, inv)), 'synthetic operator')
        save(directory / 'approved.json', bundle)
        save(self.repo / '.ptw/policy.json', policy)
        store = Store(directory / 'controller')
        store.activate(bundle)

        def cleanup():
            store.stop('poetry-revision')
            Supervisor(store).reconcile()
            remove(store)

        self.addCleanup(cleanup)
        save(directory / 'project.json', dict(project='poetry-revision', repo=str(self.repo), state=str(store.directory),
            bundle=str(directory / 'approved.json'), policy_sha256=bundle['approval']['sha256'], task='work',
            language='python', publication_sha256='synthetic-no-setup-publication'))
        actor = store.register('poetry-revision', 'work')
        denied = Workspace(store).request(actor['token'], 'retained-violation', request('read', 'missing'))
        self.assertFalse(denied['allowed'])
        return directory, store, actor, bundle

    def review_revision(self, operation='update', specs=('demo>=1,<2',), **options):
        from ptw.dependency_revision import start
        args = SimpleNamespace(**dict(repo=str(self.repo), root='', ecosystem='pypi', task='work',
            source='pyproject.toml', operation=operation, specs=list(specs), group=None, **options))
        with patch('ptw.registry.provider_for', return_value=self.provider):
            return start(args)

    def test_native_revision_terminal_decisions_and_protected_import(self):
        from test_product_onboarding import Terminal
        from ptw.monitor import ensure
        from ptw.packages import PackageControl
        from ptw.workflow import dispatch
        from ptw.workspace import request
        from ptw.dependency_binding import verify_inputs
        directory, store, actor, old = self.activated_revision()
        original = {n: (self.repo / n).read_bytes() for n in old['policy']['project']['python_dependencies']['inputs']}
        # Only registry evidence is synthetic. CLI parsing, PTY review, native
        # tool isolation, solving, publication, controller and install are real.
        script = ('import sys\nfrom unittest.mock import patch\n'
            'sys.path.insert(0, ' + repr(str(Path(__file__).resolve().parent)) + ')\n'
            'from test_product_poetry import ResolutionProvider\nfrom ptw.cli import main\n'
            'with patch("ptw.registry.provider_for", return_value=ResolutionProvider()):\n    main()\n')
        unrelated = subprocess.Popen(['/usr/bin/sleep', '600'])
        self.addCleanup(lambda: (unrelated.terminate(), unrelated.wait(timeout=5)))
        for index, answer in enumerate(('reject', 'cancel', 'eof', 'yes')):
            with self.subTest(answer=answer):
                terminal = Terminal([sys.executable, '-B', '-c', script, 'deps', 'update', 'demo>=1,<2',
                    '--repo', str(self.repo), '--ecosystem', 'pypi'], self.evidence / ('review-' + self.root.name + '-' + str(index)))
                try:
                    terminal.expect('Approve dependency revision?', 180)
                    self.assertEqual({n: (self.repo / n).read_bytes() for n in original}, original)
                    terminal.send('details')
                    terminal.expect('Approve exactly this dependency revision?', 5)
                    self.assertIn('poetry.lock', terminal.text)
                    if answer == 'eof':
                        os.write(terminal.fd, b'\x04')
                    else:
                        terminal.send(answer)
                    terminal.wait(lambda: terminal.exited, 30)
                finally:
                    code = terminal.close()
                self.assertEqual(code, 0 if answer == 'yes' else 130 if answer == 'eof' else 2, terminal.text[-2000:])
                self.assertEqual(store.status('poetry-revision')['violations'], 1)
                self.assertIsNone(unrelated.poll())
                if answer != 'yes':
                    self.assertEqual({n: (self.repo / n).read_bytes() for n in original}, original)
                    with store.locked() as db:
                        store.session(db, actor['token'])
                        self.assertEqual(store.project(db, 'poetry-revision')[1], old)
        with store.locked() as db:
            _, current = store.project(db, 'poetry-revision')
            with self.assertRaisesRegex(Invalid, 'Session ended'):
                store.session(db, actor['token'])
        verify_inputs(current)
        descriptor = current['policy']['project']['python_dependencies']
        self.assertEqual(descriptor['authority'], 'poetry.lock')
        self.assertEqual(descriptor['groups'], ['test'])
        self.assertEqual(descriptor['extras'], ['feature'])
        self.assertIn('demo==1.5', descriptor['pins'])
        self.assertEqual(current['policy']['project']['python_runtime'], old['policy']['project']['python_runtime'])
        self.assertEqual(current['policy']['project']['grants'], old['policy']['project']['grants'])
        self.assertEqual(current['policy']['tasks'], old['policy']['tasks'])
        self.assertEqual(current['policy']['project']['packages'], old['policy']['project']['packages'])
        self.assertEqual(load(directory / 'dependency-journal.json')['phase'], 'committed')
        ensure(store)
        actor = store.register('poetry-revision', 'work')
        installed = PackageControl(store, provider=self.provider).install(actor['token'], 'install', descriptor['pins'])
        self.assertTrue(installed.get('allowed'), installed)
        effect = dispatch(store, actor, 'import', request('run', 'test',
            content=json.dumps({'package_sets': [installed['package_set']]})))
        self.assertTrue(effect.get('allowed'), effect)
        self.assertEqual(effect.get('exit_code'), 0, effect)
        self.assertIn('POETRY_REVISION_IMPORT_OK', effect['output'])
        self.assertIsNone(unrelated.poll())
        self.assertEqual(store.status('poetry-revision')['violations'], 1)

    def test_native_revision_add_remove_and_stopped_project(self):
        from ptw.dependency_binding import verify_inputs
        _, store, _, old = self.activated_revision()
        for operation in ('add', 'remove'):
            actor = store.register('poetry-revision', 'work')
            with patch('ptw.onboarding.ask', return_value='yes'):
                self.review_revision(operation, ['added>=1,<2'] if operation == 'add' else ['added'])
            with store.locked() as db:
                _, current = store.project(db, 'poetry-revision')
                with self.assertRaisesRegex(Invalid, 'Session ended'):
                    store.session(db, actor['token'])
            verify_inputs(current)
            dependencies = current['policy']['project']['python_dependencies']
            self.assertEqual('added==1.5' in dependencies['pins'], operation == 'add')
            self.assertEqual(dependencies['authority'], 'poetry.lock')
            self.assertEqual(current['policy']['project']['python_runtime'], old['policy']['project']['python_runtime'])
            self.assertIn('pypi:unrelated', current['policy']['tasks'][0]['packages'])
            self.assertEqual(store.status('poetry-revision')['violations'], 1)
        store.stop('poetry-revision', 'synthetic prior stop')
        with patch('ptw.onboarding.ask') as ask, patch('ptw.poetry_revision.edit_project') as edit:
            with self.assertRaisesRegex(Invalid, 'Stopped or pending'):
                self.review_revision()
            ask.assert_not_called()
            edit.assert_not_called()
        self.assertTrue(store.status('poetry-revision')['stopped'])

    def test_native_revision_changed_review_inputs_and_publication_recovery(self):
        from ptw import dependency_revision as revision
        directory, store, actor, old = self.activated_revision()
        original = {n: (self.repo / n).read_bytes() for n in old['policy']['project']['python_dependencies']['inputs']}

        def changed(*args):
            self.manifest.write_bytes(original['pyproject.toml'] + b'# concurrent edit\n')
            return 'yes'

        with patch('ptw.onboarding.ask', side_effect=changed), self.assertRaisesRegex(Invalid, 'changed after review'):
            self.review_revision()
        self.assertTrue(self.manifest.read_bytes().endswith(b'# concurrent edit\n'))
        self.assertEqual((self.repo / 'poetry.lock').read_bytes(), original['poetry.lock'])
        self.manifest.write_bytes(original['pyproject.toml'])
        with store.locked() as db:
            store.session(db, actor['token'])
            self.assertEqual(store.project(db, 'poetry-revision')[1], old)
        move = revision.move
        calls = []

        def fail_once(source, destination):
            calls.append(destination)
            if len(calls) == 5:
                raise OSError('synthetic Poetry publication failure')
            return move(source, destination)

        with patch.object(revision, 'move', side_effect=fail_once), patch('ptw.onboarding.ask', return_value='yes'):
            with self.assertRaisesRegex(OSError, 'Poetry publication failure'):
                self.review_revision()
        revision.recover(directory)
        self.assertEqual(load(directory / 'dependency-journal.json')['phase'], 'rolled-back')
        self.assertEqual({n: (self.repo / n).read_bytes() for n in original}, original)
        with store.locked() as db:
            row, current = store.project(db, 'poetry-revision')
            self.assertEqual(current, old)
            self.assertFalse(row['setup_pending'])
            with self.assertRaisesRegex(Invalid, 'Session ended'):
                store.session(db, actor['token'])
        self.assertEqual(store.status('poetry-revision')['violations'], 1)
        atomic = revision.atomic

        def stop_during_publish(path, journal):
            atomic(path, journal)
            if journal.get('phase') == 'publishing':
                store.stop('poetry-revision', 'synthetic concurrent stop')

        with patch.object(revision, 'atomic', side_effect=stop_during_publish), patch('ptw.onboarding.ask', return_value='yes'):
            with self.assertRaisesRegex(Invalid, 'Stop or concurrent'):
                self.review_revision()
        self.assertTrue(store.status('poetry-revision')['stopped'])
        self.assertEqual(store.status('poetry-revision')['violations'], 1)
        self.assertEqual({n: (self.repo / n).read_bytes() for n in original}, original)

    def test_native_protected_import_and_unrelated_job(self):
        from ptw.monitor import ensure, remove
        from ptw.packages import PackageControl
        from ptw.store import Store
        from ptw.supervisor import Supervisor
        from ptw.workflow import dispatch
        from ptw.workspace import request
        result = self.export()
        (self.repo / 'src').mkdir()
        (self.repo / 'src/app.py').write_text('import demo, helper\n'
            'assert demo.VALUE == helper.VALUE == "SYNTHETIC_PACKAGE_OK"\nprint("POETRY_IMPORT_OK")\n')
        policy, inv = template(self.repo, 'poetry-native', 'Import Poetry locked dependencies', {'src': 'tree'},
            ['pyproject.toml', 'poetry.lock'], [{'id': 'test', 'argv': [result['runtime']['executable'], 'src/app.py'],
            'resources': ['src'], 'timeout_seconds': 15}], ['pypi:demo', 'pypi:helper'], 1, 3)
        policy['project']['python_runtime'] = result['runtime']
        policy['project']['python_dependencies'] = {k: result[k] for k in ('inputs', 'pins', 'artifacts')}
        store = Store(self.root / 'controller')
        bundle = approve(policy, inv, digest(compile_policy(policy, inv)), 'synthetic operator')
        store.activate(bundle)
        unrelated = subprocess.Popen(['/usr/bin/sleep', '120'])
        try:
            ensure(store)
            actor = store.register('poetry-native', 'work')
            installed = PackageControl(store, provider=self.provider).install(actor['token'], 'install', result['pins'])
            self.assertTrue(installed.get('allowed'), installed)
            effect = dispatch(store, actor, 'import', request('run', 'test',
                content=json.dumps({'package_sets': [installed['package_set']]})))
            self.assertTrue(effect.get('allowed'), effect)
            self.assertEqual(effect.get('exit_code'), 0, effect)
            self.assertIn('POETRY_IMPORT_OK', effect['output'])
            self.assertEqual(store.status('poetry-native')['violations'], 0)
            self.assertIsNone(unrelated.poll())
        finally:
            store.stop('poetry-native')
            Supervisor(store).reconcile()
            remove(store)
            self.assertIsNone(unrelated.poll())
            unrelated.terminate()
            unrelated.wait(timeout=5)
