"""Evidence plumbing tests. Synthetic receipts are never product user proof."""
from contextlib import redirect_stdout
import copy
import io
import inspect
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import native_receipt as native
from evidence_io import artifact, capture, digest, load, reference, save
from terminal_driver import Terminal
import product_gate as gate


class ProductGateTests(unittest.TestCase):
    """Deliberately synthetic schema fixtures, never retained as user evidence."""
    def setUp(self):
        import shutil
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.repo, self.out = self.root / 'source', self.root / 'evidence'
        (self.repo / 'harness/ptw/data').mkdir(parents=True)
        self.out.mkdir()
        (self.repo / 'harness/ptw/__init__.py').write_text('# synthetic runtime\n')
        (self.repo / 'harness/ptw/data/schema.json').write_text('{}\n')
        (self.repo / 'harness/pyproject.toml').write_text(
            '[project]\nname="permission-to-work-harness"\nversion="0.5.0"\n')
        (self.repo / 'harness/requirements.lock').write_text('fixture-dependency==1.0\n')
        shutil.copyfile(gate.REPO / 'harness/PRODUCT_ACCEPTANCE.json',
                        self.repo / 'harness/PRODUCT_ACCEPTANCE.json')
        import safety_evidence_fixtures as safety_fixture
        safety_fixture.prepare(self.repo, gate.REPO)
        self.source = native.sources(self.repo)
        self.epoch = time.time()
        self.runtime, self.inputs = gate.tree(self.repo / 'harness'), gate.inputs(self.repo)
        self.report = {'schema': 1, 'contract_sha256': digest(self.repo / 'harness/PRODUCT_ACCEPTANCE.json'),
            'source_sha256': self.source, 'runtime_sha256': self.runtime,
            'distribution_inputs_sha256': self.inputs, 'real_model': 'gpt-5.6-sol',
            'reasoning_effort': 'low', 'execution_host': 'algol-box-2', 'simulation': False,
            'started_epoch': self.epoch - 10, 'journeys': [], 'security_checks': [],
            'requirements': {}, 'unmet_requirements': [], 'auth_files_copied': False,
            'unknown_vulnerability_guarantee': False}
        assertion = [{'name': 'synthetic fixture only', 'expected': 'fixture', 'observed': 'fixture'}]
        for index, name in enumerate(sorted(gate.IDS)):
            row = {'id': name, 'passed': True, 'real_pty': True, 'fresh_application_install': True,
                'installed_runtime_sha256': self.runtime, 'checkout_imported': False,
                'first_setup_wall_seconds': 20., 'first_useful_action_wall_seconds': 25.,
                'timing_start': 'installer-invocation', 'timing_end': 'protected-codex-ready',
                'human_input_seconds': 1., 'human_input_mode': 'scripted-terminal',
                'preconditions': ['SYNTHETIC VALIDATOR FIXTURE'], 'cache_profile': 'cold' if index == 0 else 'warm',
                'unauthorized_effects': 0, 'private_before_sha256': 'f' * 64, 'private_after_sha256': 'f' * 64,
                'continued_work': True, 'protected_resume': True, 'dependency_admitted': True,
                'build_or_test_exit_code': 0}
            transcript = self.out / name / 'terminal.log'
            transcript.parent.mkdir()
            transcript.write_text('SYNTHETIC, not actual Codex evidence\n')
            row['terminal_record'] = self.write(name + '/terminal.json',
                {'id': name, 'real_pty': True, 'transcript': reference(self.out, transcript),
                 'resumed_transcript': reference(self.out, transcript),
                 'operator_reviews': [reference(self.out, transcript)] * (2 if 'mixed' in name else 1),
                 'model': 'gpt-5.6-sol', 'reasoning_effort': 'low'})
            row['action_record'] = self.write(name + '/actions.json',
                {**{k: row[k] for k in gate.ACTION_KEYS}, 'actions': [{'synthetic': True}], 'assertions': assertion})
            row['functional_oracle'] = self.write(name + '/oracle.json',
                {'id': name, 'build_or_test_exit_code': 0, 'assertions': assertion, 'output': reference(self.out, transcript)})
            row['timing_record'] = self.write(name + '/timing.json',
                {**{k: row[k] for k in gate.TIMING_KEYS}, 'start_monotonic': 100.,
                 'ready_monotonic': 120., 'first_action_monotonic': 125., 'full_elapsed_seconds': 100.,
                 'authentication': 'existing operator login; browser/MFA external and untested',
                 'cache_before': {} if index == 0 else {'release_archive': reference(self.out, transcript),
                     'tool_cache': 'empty private cache', 'uv_cache': 'empty private cache',
                     'npm_cache': 'empty private cache'}})
            prefix = self.out / name / 'install'
            module_root = prefix / 'lib/site-packages'
            module_root.mkdir(parents=True)
            shutil.copytree(self.repo / 'harness/ptw', module_root / 'ptw')
            declared = {'permission-to-work-harness': '0.5.0', 'fixture-dependency': '1.0'}
            for package, version in declared.items():
                metadata = module_root / (package + '-' + version + '.dist-info')
                metadata.mkdir()
                (metadata / 'METADATA').write_text('Name: ' + package + '\nVersion: ' + version + '\n')
            executable = prefix / 'bin/python'
            executable.parent.mkdir()
            executable.write_bytes(b'synthetic-interpreter-not-executable')
            processes = {}
            for pid, role in enumerate(('launcher', 'broker', 'monitor'), 10):
                processes[role] = self.write(name + '/' + role + '.json', {
                    'role': role, 'pid': pid, 'module_root': str(module_root), 'runtime_sha256': self.runtime,
                    'pythonpath_present': False, 'pythonhome_present': False, 'measured_epoch': self.epoch,
                    'executable': str(executable), 'prefix': str(prefix), 'interpreter_sha256': digest(executable),
                    'imported_ptw_modules': {'ptw': str(module_root / 'ptw/__init__.py')}})
            row['installed_module_record'] = self.write(name + '/installed.json', {
                'id': name, 'checkout_imported': False, 'distribution_inputs_sha256': self.inputs,
                'module_root': str(module_root), 'dependency_versions': declared, 'processes': processes})
            self.report['journeys'].append(row)
        for name in [*sorted(gate.SECURITY), 'local-git']:
            terminal_records, originals = {}, []
            if name == 'local-git':
                for decision in ('approval', 'rejection'):
                    folder = self.out / 'git' / decision
                    folder.mkdir(parents=True)
                    (folder / 'terminal.txt').write_text('SYNTHETIC: Type approve ' + 'a' * 64)
                    save(folder / 'inputs.json', [{'text': 'reject' if decision == 'rejection' else 'approve ' + 'a' * 64}])
                    save(folder / 'exit.json', {'exit_code': 0})
                    terminal_records[decision] = {p: reference(self.out, folder / p)
                        for p in ('terminal.txt', 'inputs.json', 'exit.json')}
                    originals.extend(terminal_records[decision].values())
            log = self.out / (name + '.log')
            response = self.write(name + '-response.json', {'synthetic': 'validator fixture only'})
            log.write_text(json.dumps({'response': response, 'measured_epoch': self.epoch}) + '\n' +
                json.dumps({'name': assertion[0]['name'], 'observed': 'fixture', 'measured_epoch': self.epoch}) + '\n')
            probe = self.write(name + '-probe.json', {'id': name, 'complete': True,
                'kind': 'injected-request', 'assertions': assertion, 'responses': [response], 'artifacts': originals,
                'output': reference(self.out, log)})
            row = {'id': name, 'passed': True, 'physical_effect_verified': True}
            row['record'] = self.write(name + '.json', {**row, 'assertions': assertion, 'probes': [probe]})
            if name == 'local-git':
                row['operator_terminals'] = terminal_records
                self.report['local_git'] = row
            else:
                self.report['security_checks'].append(row)
        archive, bootstrap = self.out / 'synthetic-candidate.tar.gz', self.out / 'install.sh'
        archive.write_bytes(safety_fixture.archive(self.repo))
        bootstrap.write_bytes(b'synthetic validator bootstrap; never executed')
        provenance = self.write('build.json', {'status': 'built-unpublished',
            'archive_sha256': digest(archive), 'bootstrap_sha256': digest(bootstrap)})
        self.report['candidate_record'] = self.write('candidate-evidence.json', {
            'origin': 'local-candidate', 'version': '0.5.0', 'publication': 'still-required',
            'archive': reference(self.out, archive), 'bootstrap': reference(self.out, bootstrap),
            'provenance': provenance, 'assertions': assertion})
        parent = self.root / 'native'
        suite = NativeReceiptTests.suite()
        suite.addTests(safety_fixture.suite())
        selected = native.inventory(suite)
        self.enterContext(patch.object(native, 'discover', return_value=selected))
        self.enterContext(patch.object(native, 'verify_environment'))
        self.enterContext(patch.object(native, 'receipt_parent', return_value=parent))
        with patch.object(native, 'environment', return_value={'native_enabled': True}), redirect_stdout(io.StringIO()):
            native.run_recorded(unittest.TextTestRunner(stream=io.StringIO(), verbosity=2), suite,
                                inspect.unwrap(unittest.TextTestRunner.run), repo=self.repo, parent=parent)
        self.report['native_suite'] = native.retain(self.out, repo=self.repo)
        safety_fixture.extension(self)
        safety_fixture.demos(self)
        from product_acceptance import map_requirements
        self.report['requirements'] = map_requirements(self.out, self.report)
        self.report['ended_epoch'] = time.time()
        self.flush()

    def write(self, name, value):
        path = self.out / name
        path.parent.mkdir(parents=True, exist_ok=True)
        save(path, {'source_sha256': self.source, 'ended_epoch': self.epoch, **value})
        return reference(self.out, path)

    def flush(self):
        save(self.out / 'completion-evidence.json', self.report)

    def verify(self):
        self.flush()
        return gate.verify(self.out, self.repo)

    def mutate(self, owner, key, change):
        value = record_value = load(self.out / owner[key]['path'])
        change(value)
        owner[key] = self.write(owner[key]['path'], record_value)

    def test_complete_synthetic_schema_is_candidate_not_completion(self):
        result = self.verify()
        self.assertTrue(result['passed'])
        self.assertFalse(result['complete'])
        self.assertEqual(result['publication'], 'still-required')

    def test_every_requirement_requires_exact_validated_supporting_records(self):
        for name, item in self.report['requirements'].items():
            ref = item['records'][0]
            original = load(artifact(self.out, ref))
            self.assertTrue(original['evidence'])
            for evidence in ([], original['evidence'][:-1],
                             [self.report['candidate_record']] * len(original['evidence'])):
                with self.subTest(contract=name, count=len(evidence)):
                    item['records'] = [self.write(ref['path'], {**original, 'evidence': evidence})]
                    with self.assertRaisesRegex(ValueError, 'coverage differs'):
                        self.verify()
            item['records'] = [self.write(ref['path'], original)]

    def test_local_git_and_candidate_cannot_be_omitted_or_substituted(self):
        original = copy.deepcopy(self.report)
        for change in (lambda r: r.pop('local_git'),
                       lambda r: r.update(local_git=r['security_checks'][0]),
                       lambda r: r.pop('candidate_record'),
                       lambda r: r.update(candidate_record=r['journeys'][0]['functional_oracle'])):
            self.report = copy.deepcopy(original)
            change(self.report)
            with self.assertRaises(ValueError):
                self.verify()
        self.report = original
        ref = self.report['candidate_record']
        candidate = load(artifact(self.out, ref))
        for field, value in (('version', '99.0.0'), ('publication', 'complete'),
                             ('origin', 'public-release')):
            self.report['candidate_record'] = self.write(ref['path'], {**candidate, field: value})
            with self.assertRaises(ValueError):
                self.verify()

    def test_exact_public_candidate_requires_original_download_receipts(self):
        ref = self.report['candidate_record']
        candidate = load(artifact(self.out, ref))
        archive = self.out / 'ptw-0.5.0-linux-x86_64.tar.gz'
        archive.write_bytes(artifact(self.out, candidate['archive']).read_bytes())
        bootstrap = artifact(self.out, candidate['bootstrap'])
        sums = self.out / 'SHA256SUMS'
        sums.write_text(digest(archive) + '  ' + archive.name + '\n' + digest(bootstrap) + '  install.sh\n')
        downloads = []
        for path in (sums, bootstrap, archive):
            downloads.append(self.write(path.name + '.download.json', {'complete': True,
                'url': gate.RELEASES + 'ptw-v0.5.0/' + path.name, 'artifact': reference(self.out, path)}))
        candidate.update(origin='public-release', release_tag='ptw-v0.5.0',
                         archive=reference(self.out, archive), provenance=reference(self.out, sums), downloads=downloads)
        self.report['candidate_record'] = self.write(ref['path'], candidate)
        self.report['ended_epoch'] = time.time()
        gate.candidate_record(self.out, self.report, self.repo)
        for change in (lambda c: c.update(release_tag='ptw-v0.5.1'),
                       lambda c: c.update(downloads=[]),
                       lambda c: c['downloads'].__setitem__(0, downloads[1])):
            altered = copy.deepcopy(candidate)
            change(altered)
            self.report['candidate_record'] = self.write(ref['path'], altered)
            with self.assertRaises(ValueError):
                gate.candidate_record(self.out, self.report, self.repo)

    def test_git_requires_both_original_operator_decisions(self):
        row = self.report['local_git']
        original = copy.deepcopy(row)
        for change in (lambda r: r.pop('operator_terminals'),
                       lambda r: r['operator_terminals'].pop('rejection'),
                       lambda r: r['operator_terminals'].__setitem__('approval', r['operator_terminals']['rejection'])):
            altered = copy.deepcopy(original)
            change(altered)
            with self.assertRaises(ValueError):
                gate.local_git_check(self.out, altered, self.report)
        ref = row['operator_terminals']['approval']['inputs.json']
        save(self.out / ref['path'], [{'text': 'approve ' + 'b' * 64}])
        with self.assertRaises(ValueError):
            gate.local_git_check(self.out, row, self.report)

    def test_missing_duplicate_and_unmet_contract_ids_rejected(self):
        original = copy.deepcopy(self.report)
        changes = [lambda r: r['journeys'].pop(),
            lambda r: r['journeys'].__setitem__(0, None),
            lambda r: r['journeys'].__setitem__(0, r['journeys'][1]),
            lambda r: r['security_checks'].pop(),
            lambda r: r['security_checks'].__setitem__(0, None),
            lambda r: r['security_checks'].__setitem__(0, r['security_checks'][1]),
            lambda r: r['requirements'].pop('everyday'),
            lambda r: r['requirements'].__setitem__('everyday', None),
            lambda r: r.update(native_suite=None),
            lambda r: r['requirements']['release'].update(status='passed'),
            lambda r: r.update(unmet_requirements=['first-setup'])]
        for change in changes:
            with self.subTest(change=change):
                self.report = copy.deepcopy(original)
                change(self.report)
                with self.assertRaises(ValueError):
                    self.verify()

    def test_invalid_timing_types_limits_and_arithmetic_rejected(self):
        row = self.report['journeys'][0]
        for value in (True, -1, 30.01, float('inf'), float('nan')):
            with self.subTest(value=value), self.assertRaises(ValueError):
                row['first_setup_wall_seconds'] = value
                self.verify()
        row['first_setup_wall_seconds'] = 20.
        self.mutate(row, 'timing_record', lambda v: v.update(ready_monotonic=119))
        with self.assertRaisesRegex(ValueError, 'arithmetic'):
            self.verify()

    def test_resume_review_cache_and_elapsed_cannot_be_summary_only(self):
        row = self.report['journeys'][1]
        for key, mutations in (
            ('terminal_record', [{'resumed_transcript': None}, {'operator_reviews': []},
                                 {'model': 'other'}, {'reasoning_effort': 'high'}]),
            ('timing_record', [{'cache_before': {}}, {'full_elapsed_seconds': 24.},
                               {'authentication': 'new-account OAuth tested'}])):
            original = load(self.out / row[key]['path'])
            for changes in mutations:
                with self.subTest(key=key, changes=changes):
                    row[key] = self.write(row[key]['path'], {**original, **changes})
                    with self.assertRaises(ValueError):
                        self.verify()
            row[key] = self.write(row[key]['path'], original)

    def test_stale_future_changed_sources_and_wrong_model_rejected(self):
        original = copy.deepcopy(self.report)
        for key, value in (('ended_epoch', time.time() - 86401), ('ended_epoch', time.time() + 20),
                           ('source_sha256', {}), ('runtime_sha256', {}), ('distribution_inputs_sha256', {}),
                           ('real_model', 'substituted'), ('simulation', True), ('auth_files_copied', True)):
            with self.subTest(key=key):
                self.report = dict(original, **{key: value})
                with self.assertRaises(ValueError):
                    self.verify()

    def test_each_supporting_record_is_parsed_and_bound_to_source(self):
        row = self.report['journeys'][0]
        for key in ('terminal_record', 'action_record', 'functional_oracle', 'timing_record', 'installed_module_record'):
            ref = row[key]
            original = load(self.out / ref['path'])
            for field, value in (('id', 'different'), ('source_sha256', {}), ('ended_epoch', self.epoch - 86401)):
                with self.subTest(key=key, field=field):
                    row[key] = self.write(ref['path'], dict(original, **{field: value}))
                    with self.assertRaises(ValueError):
                        self.verify()
            row[key] = self.write(ref['path'], original)

    def test_missing_modified_empty_and_linked_original_logs_rejected(self):
        row = self.report['journeys'][0]
        value = load(self.out / row['terminal_record']['path'])
        path = self.out / value['transcript']['path']
        original = path.read_bytes()
        path.write_text('altered')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            self.verify()
        path.write_bytes(b'')
        value['transcript'] = reference(self.out, path)
        row['terminal_record'] = self.write(row['terminal_record']['path'], value)
        with self.assertRaisesRegex(ValueError, 'Empty original PTY'):
            self.verify()
        path.unlink()
        outside = self.root / 'outside.log'
        outside.write_bytes(original)
        path.symlink_to(outside)
        value['transcript'] = reference(self.out, path)
        row['terminal_record'] = self.write(row['terminal_record']['path'], value)
        with self.assertRaisesRegex(ValueError, 'Linked artifact'):
            self.verify()

    def test_recursive_installed_data_and_distribution_metadata_rehashed(self):
        row = self.report['journeys'][0]
        value = load(self.out / row['installed_module_record']['path'])
        module_root = Path(value['module_root'])
        data = module_root / 'ptw/data/schema.json'
        data.write_text('{"changed":true}')
        with self.assertRaisesRegex(ValueError, 'package data'):
            self.verify()
        data.write_text('{}\n')
        metadata = next(module_root.glob('fixture-*.dist-info/METADATA'))
        metadata.write_text('Name: fixture-dependency\nVersion: 2.0\n')
        with self.assertRaisesRegex(ValueError, 'distribution inventory'):
            self.verify()

    def test_actual_process_import_contamination_rejected(self):
        row = self.report['journeys'][0]
        audit = load(self.out / row['installed_module_record']['path'])
        ref = audit['processes']['broker']
        original = load(self.out / ref['path'])
        for key, value in (('pythonpath_present', True), ('module_root', str(self.repo / 'harness')),
                           ('runtime_sha256', {}), ('imported_ptw_modules', {'ptw': '/outside/ptw/__init__.py'})):
            with self.subTest(key=key):
                audit['processes']['broker'] = self.write(ref['path'], dict(original, **{key: value}))
                row['installed_module_record'] = self.write(row['installed_module_record']['path'], audit)
                with self.assertRaises(ValueError):
                    self.verify()

    def test_security_probes_and_requirement_mapping_cannot_be_hash_only(self):
        row = self.report['security_checks'][0]
        ref = row['record']
        original = load(self.out / ref['path'])
        self.mutate(row, 'record', lambda v: v.update(probes=[]))
        with self.assertRaisesRegex(ValueError, 'security probes'):
            self.verify()
        row['record'] = self.write(ref['path'], original)
        item = self.report['requirements']['scope']
        item['records'] = [self.write('wrong-requirement.json', {'contract_ids': ['packages'],
            'assertions': [{'name': 'fixture', 'expected': 1, 'observed': 1}]})]
        with self.assertRaisesRegex(ValueError, 'wrong contract ID'):
            self.verify()

    def test_security_observations_cannot_be_replaced_by_consistent_summaries(self):
        row = self.report['security_checks'][0]
        summary_ref = row['record']
        summary = load(self.out / summary_ref['path'])
        probe_ref = summary['probes'][0]
        original = load(self.out / probe_ref['path'])
        for change in (
            lambda p: p.update(complete=False),
            lambda p: p.update(id='unrelated'),
            lambda p: p.update(responses=[]),
            lambda p: p['assertions'][0].update(expected='forged', observed='forged'),
            lambda p: p.update(artifacts=[{'path': 'missing-original', 'sha256': '0' * 64}]),
        ):
            with self.subTest(change=change):
                probe = copy.deepcopy(original)
                change(probe)
                summary['assertions'] = probe['assertions']
                summary['probes'] = [self.write(probe_ref['path'], probe)]
                row['record'] = self.write(summary_ref['path'], summary)
                with self.assertRaises(ValueError):
                    self.verify()

    def test_forged_native_counts_and_incomplete_outcomes_rejected(self):
        self.report['native_suite']['tests_run'] += 1
        with self.assertRaisesRegex(ValueError, 'Contradictory'):
            self.verify()
        self.report['native_suite']['tests_run'] -= 1
        path = self.out / 'native-suite/outcomes.jsonl'
        path.write_text('\n'.join(path.read_text().splitlines()[:-1]) + '\n')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            self.verify()

    def test_cli_missing_and_invalid_evidence_fails_without_native_execution(self):
        for args in ([], ['--evidence', str(self.root / 'absent')]):
            result = subprocess.run([sys.executable, '-B', str(gate.REPO / 'harness/scripts/product_gate.py'),
                                     *args], capture_output=True)
            self.assertNotEqual(result.returncode, 0)


class NativeReceiptTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.repo = self.root / 'source'
        (self.repo / 'harness').mkdir(parents=True)
        (self.repo / 'harness/input.py').write_text('# synthetic source\n')
        self.parent = self.root / 'receipts'
        self.identity = {'host': 'synthetic-test-host', 'native_enabled': True}

    def run_suite(self, suite, *, runner=None):
        runner = runner or unittest.TextTestRunner(stream=io.StringIO(), verbosity=2)
        with patch.object(native, 'environment', return_value=self.identity), redirect_stdout(io.StringIO()):
            result = native.run_recorded(runner, suite, inspect.unwrap(unittest.TextTestRunner.run),
                                         repo=self.repo, parent=self.parent)
        directory = max(self.parent.iterdir(), key=lambda p: load(p / 'attempt.json')['started_epoch'])
        return directory, result

    @staticmethod
    def suite(count=242):
        class Synthetic(unittest.TestCase):
            def runTest(self):
                with self.subTest(value='fixture'):
                    self.assertEqual(2 + 2, 4)
        return unittest.TestSuite(Synthetic() for _ in range(count))

    def passing(self):
        suite = self.suite()
        expected = native.inventory(suite)
        directory, result = self.run_suite(suite)
        self.assertTrue(result.wasSuccessful())
        return directory, expected

    def verify(self, directory, expected):
        return native.verify(directory, repo=self.repo, expected=expected, identity=self.identity)

    def test_real_runner_original_stream_inventory_and_subtests(self):
        suite = self.suite()
        expected = native.inventory(suite)
        stream = io.StringIO()
        runner = unittest.TextTestRunner(stream=stream, verbosity=2)
        original_stream = runner.stream
        directory, result = self.run_suite(suite, runner=runner)
        receipt = self.verify(directory, expected)
        self.assertEqual(receipt['tests_run'], result.testsRun)
        self.assertEqual((directory / 'unittest.log').read_text(), stream.getvalue())
        self.assertIs(runner.stream, original_stream)
        self.assertEqual(receipt['inventory'], expected)  # Preserve intentional multiplicities.
        events = [json.loads(s) for s in (directory / 'outcomes.jsonl').read_text().splitlines()]
        self.assertEqual(sum(e['event'] == 'addSubTest' for e in events), 242)
        self.assertNotIn('startTest', result.__dict__)  # Observation hooks restored.

    def test_synthetic_helpers_do_not_reenter_recorder_enabled_before_or_during_runner(self):
        original = inspect.unwrap(unittest.TextTestRunner.run)
        owner = self
        for when in ('before', 'during'):
            with self.subTest(when=when), patch.object(unittest.TextTestRunner, 'run', original), \
                    patch.object(native, '_enabled', False), patch.object(native, '_active', False), \
                    patch.dict(os.environ, {'PTW_LINUX_TESTS': '1'}), \
                    patch.object(native, 'run_recorded', wraps=native.run_recorded) as recording:
                class Outer(unittest.TestCase):
                    def runTest(self):
                        if when == 'during':
                            native.enable()
                        directory, expected = owner.passing()
                        owner.verify(directory, expected)
                        fixture = ProductGateTests('test_complete_synthetic_schema_is_candidate_not_completion')
                        result = unittest.TestResult()
                        fixture.run(result)
                        owner.assertTrue(result.wasSuccessful(), result.errors + result.failures)

                if when == 'before':
                    native.enable()
                result = original(unittest.TextTestRunner(stream=io.StringIO()), unittest.TestSuite([Outer()]))
                self.assertTrue(result.wasSuccessful(), result.errors + result.failures)
                self.assertEqual(recording.call_count, 2, 'Each synthetic helper records exactly once')

    def test_fail_skip_subtest_and_fixture_errors_cannot_pass(self):
        class Outcomes(unittest.TestCase):
            def test_failure(self):
                self.fail('actual failing fixture')

            def test_error(self):
                raise RuntimeError('actual error fixture')

            def test_skip(self):
                self.skipTest('actual skip fixture')

            def test_subtest(self):
                with self.subTest(value=1):
                    self.assertEqual(1, 2)

        class BrokenFixture(unittest.TestCase):
            @classmethod
            def setUpClass(cls):
                raise RuntimeError('fixture setup failed')

            def test_never_run(self):
                self.fail('must not execute')

        suite = unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(c)
                                   for c in (Outcomes, BrokenFixture)])
        directory, result = self.run_suite(suite)
        end = load(directory / 'complete.json')
        self.assertEqual((end['failures'], end['errors'], end['skipped']), (2, 2, 1))
        self.assertEqual(end['tests_run'], result.testsRun)
        self.assertFalse(end['passed'])
        text = (directory / 'outcomes.jsonl').read_text()
        self.assertIn('setUpClass', text)
        self.assertIn('"passed": false', text)

    def test_expected_failures_and_unexpected_successes_are_not_native_success(self):
        class Outcomes(unittest.TestCase):
            @unittest.expectedFailure
            def test_expected(self):
                self.fail('fixture')

            @unittest.expectedFailure
            def test_unexpected(self):
                pass

        directory, _ = self.run_suite(unittest.defaultTestLoader.loadTestsFromTestCase(Outcomes))
        record = load(directory / 'complete.json')
        self.assertEqual((record['expectedFailures'], record['unexpectedSuccesses']), (1, 1))
        self.assertFalse(record['passed'])

    def test_keyboard_interrupt_retains_attempt_and_partial_original_log(self):
        class Interrupted(unittest.TestCase):
            def runTest(self):
                raise KeyboardInterrupt()

        runner = unittest.TextTestRunner(stream=io.StringIO(), verbosity=2)
        original = runner.stream
        with self.assertRaises(KeyboardInterrupt):
            self.run_suite(unittest.TestSuite([Interrupted()]), runner=runner)
        directory = next(self.parent.iterdir())
        self.assertFalse((directory / 'complete.json').exists())
        self.assertTrue((directory / 'unittest.log').read_text())
        self.assertEqual(load(directory / 'interrupted.json')['error_type'], 'KeyboardInterrupt')
        self.assertIs(runner.stream, original)

    def test_source_drift_invalidates_receipt(self):
        target = self.repo / 'harness/input.py'

        class Changed(unittest.TestCase):
            def runTest(self):
                target.write_text('# changed during run\n')

        directory, _ = self.run_suite(unittest.TestSuite([Changed()]))
        self.assertFalse(load(directory / 'complete.json')['passed'])
        with self.assertRaisesRegex(ValueError, 'source drift'):
            self.verify(directory, native.inventory(self.suite()))

    def test_current_source_and_identity_must_match(self):
        directory, expected = self.passing()
        identity = dict(self.identity, host='different-host')
        with self.assertRaisesRegex(ValueError, 'environment'):
            native.verify(directory, repo=self.repo, expected=expected, identity=identity)
        (self.repo / 'harness/input.py').write_text('# subsequent change\n')
        with self.assertRaisesRegex(ValueError, 'source drift'):
            self.verify(directory, expected)

    def test_focused_inventory_and_missing_multiplicity_are_rejected(self):
        directory, expected = self.passing()
        for ids in (expected[:-1], expected + ['unknown.test'], list(set(expected))):
            with self.subTest(ids=len(ids)), self.assertRaisesRegex(ValueError, 'inventory'):
                self.verify(directory, ids)

    def test_stale_future_incomplete_and_contradictory_records_rejected(self):
        directory, expected = self.passing()
        original = load(directory / 'complete.json')
        for key, value in (('ended_epoch', time.time() - 86401), ('ended_epoch', time.time() + 60),
                           ('complete', False), ('inventory', []), ('tests_run', True),
                           ('errors', 1), ('passed', False)):
            with self.subTest(key=key, value=value):
                changed = copy.deepcopy(original)
                changed[key] = value
                save(directory / 'complete.json', changed)
                with self.assertRaises(ValueError):
                    self.verify(directory, expected)
        save(directory / 'complete.json', original)
        (directory / 'complete.json').unlink()
        with self.assertRaises(OSError):
            self.verify(directory, expected)

    def test_modified_or_forged_log_and_missing_outcomes_rejected(self):
        directory, expected = self.passing()
        original = load(directory / 'complete.json')
        log = directory / 'unittest.log'
        log.write_text('Ran 241 tests in 1.000s\n\nOK\n')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            self.verify(directory, expected)
        changed = dict(original, output=reference(directory, log))
        save(directory / 'complete.json', changed)
        with self.assertRaisesRegex(ValueError, 'log contradicts'):
            self.verify(directory, expected)
        log.write_text('Ran 242 tests in 1.000s\n\nOK\n')
        events = directory / 'outcomes.jsonl'
        events.write_text('\n'.join(events.read_text().splitlines()[:-1]) + '\n')
        save(directory / 'complete.json', dict(changed, output=reference(directory, log),
                                              outcomes=reference(directory, events)))
        with self.assertRaisesRegex(ValueError, 'Incomplete native outcomes'):
            self.verify(directory, expected)

    def test_later_failed_full_run_supersedes_success_but_focused_does_not(self):
        directory, expected = self.passing()
        self.run_suite(self.suite(1))
        selected, _ = native.latest(repo=self.repo, parent=self.parent,
                                    expected=expected, identity=self.identity)
        self.assertEqual(selected, directory)
        later, _ = self.run_suite(self.suite())
        end = load(later / 'complete.json')
        save(later / 'complete.json', dict(end, passed=False, errors=1))
        with self.assertRaisesRegex(ValueError, 'did not pass'):
            native.latest(repo=self.repo, parent=self.parent, expected=expected, identity=self.identity)
        (later / 'complete.json').unlink()
        with self.assertRaises(OSError):
            native.latest(repo=self.repo, parent=self.parent, expected=expected, identity=self.identity)

    def test_namespace_changes_with_checkout_and_maintained_source(self):
        with patch.dict(os.environ, {'XDG_STATE_HOME': str(self.root / 'state')}):
            first = native.receipt_parent(self.repo)
            (self.repo / 'harness/input.py').write_text('# changed\n')
            self.assertNotEqual(native.receipt_parent(self.repo), first)
            self.assertNotEqual(native.receipt_parent(self.root / 'different', {}), first)


class EvidenceCaptureTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def test_capture_passes_only_explicit_diagnostic_descriptors(self):
        reader, writer = os.pipe()
        try:
            os.write(writer, b'diagnostic fixture')
            code = 'import os,sys; print(os.read(int(sys.argv[1]),64).decode())'
            denied = capture([sys.executable, '-I', '-B', '-c', code, str(reader)], self.root / 'closed')
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn(b'Bad file descriptor', denied.stderr)
            passed = capture([sys.executable, '-I', '-B', '-c', code, str(reader)],
                             self.root / 'passed', pass_fds=(reader,))
            self.assertEqual(passed.returncode, 0)
            self.assertEqual(passed.stdout, b'diagnostic fixture\n')
        finally:
            os.close(reader)
            os.close(writer)

    def test_paste_preserves_partial_writes_and_records_single_submission(self):
        terminal = Terminal.__new__(Terminal)
        terminal.folder = self.root
        terminal.started = time.monotonic()
        terminal.inputs = []
        terminal.fd = 123456
        terminal.closed = terminal.exited = False
        terminal.bracketed_paste = True
        payload = 'Unicode café\n' + 'long prompt ' * 500
        received = bytearray()

        def partial(fd, data):
            self.assertEqual(fd, terminal.fd)
            count = min(13, len(data))
            received.extend(data[:count])
            return count

        with patch('terminal_driver.os.write', side_effect=partial), \
                patch.object(terminal, 'read', side_effect=lambda timeout: time.sleep(timeout)):
            terminal.paste(payload)
        self.assertEqual(received, b'\x1b[200~' + payload.encode() + b'\x1b[201~\r')
        rows = load(self.root / 'inputs.json')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['text'], payload)
        self.assertGreaterEqual(rows[0]['submitted_seconds'] - rows[0]['seconds'], .29)
        with patch('terminal_driver.os.write') as write:
            for invalid in ('', 'embedded\x1b[201~', 'quit\r', '\x03', '\x7f'):
                with self.subTest(invalid=repr(invalid)), self.assertRaises(ValueError):
                    terminal.paste(invalid)
            terminal.bracketed_paste = False
            with self.assertRaises(ValueError):
                terminal.paste('must not type into an onboarding prompt')
            write.assert_not_called()

    def test_paste_failure_retains_input_without_retrying_enter(self):
        terminal = Terminal.__new__(Terminal)
        terminal.folder = self.root
        terminal.started = time.monotonic()
        terminal.inputs = []
        terminal.fd = 123456
        terminal.closed = terminal.exited = False
        terminal.bracketed_paste = True
        with patch('terminal_driver.os.write', return_value=0) as write:
            with self.assertRaisesRegex(OSError, 'no prompt bytes'):
                terminal.paste('fixture prompt')
            self.assertEqual(write.call_count, 1)
        self.assertNotIn('submitted_seconds', load(self.root / 'inputs.json')[0])

    def test_terminal_failure_cleanup_never_types_and_bounds_termination(self):
        # Exercise teardown without requiring a sandbox PTY or sending signals.
        terminal = Terminal.__new__(Terminal)
        terminal.closed, terminal.exited = False, False
        terminal.pid, terminal.fd = 123456, 123457
        terminal.folder = self.root
        terminal.raw = io.BytesIO()
        terminal.inputs, terminal.argv = [], ['synthetic-terminal']
        terminal.started = time.monotonic()
        with patch.object(terminal, 'send') as send, \
                patch.object(terminal, 'wait', side_effect=AssertionError('fixture hung')), \
                patch('terminal_driver.os.kill') as kill, \
                patch('terminal_driver.os.waitpid', return_value=(terminal.pid, signal.SIGKILL)), \
                patch('terminal_driver.os.close'):
            self.assertEqual(terminal.close(graceful=False), -signal.SIGKILL)
            self.assertEqual(terminal.close(graceful=False), -signal.SIGKILL)
        send.assert_not_called()
        self.assertEqual(kill.call_args_list, [unittest.mock.call(terminal.pid, signal.SIGTERM),
                                              unittest.mock.call(terminal.pid, signal.SIGKILL)])
        self.assertEqual(load(self.root / 'inputs.json'), [])
        self.assertFalse(load(self.root / 'exit.json')['graceful_requested'])

    def test_real_nonzero_stdout_and_stderr_are_saved_before_assertions(self):
        folder = self.root / 'failure'
        script = self.root / 'failure.py'
        script.write_text('import os; os.write(1,b"original-out\\x00"); os.write(2,b"original-error"); exit(7)')
        result = capture([sys.executable, '-I', '-B', script], folder)
        self.assertEqual(result.returncode, 7)
        receipt = load(folder / 'process.json')
        self.assertTrue(receipt['complete'])
        self.assertEqual(artifact(folder, receipt['stdout']).read_bytes(), b'original-out\x00')
        self.assertEqual(artifact(folder, receipt['stderr']).read_bytes(), b'original-error')
        self.assertNotIn('original-error', (folder / 'process.json').read_text())

    def test_timeout_retains_partial_bytes_and_kills_own_process(self):
        folder = self.root / 'timeout'
        with self.assertRaises(subprocess.TimeoutExpired):
            capture([sys.executable, '-I', '-B', '-c',
                'import os,time; os.write(1,str(os.getpid()).encode()); os.write(2,b"partial"); time.sleep(60)'],
                folder, timeout=.5)
        receipt = load(folder / 'process.json')
        self.assertFalse(receipt['complete'])
        self.assertEqual(receipt['error_type'], 'TimeoutExpired')
        self.assertEqual(artifact(folder, receipt['stderr']).read_bytes(), b'partial')
        pid = int((folder / 'stdout').read_bytes())
        self.assertFalse(Path('/proc', str(pid)).exists())

    def test_launch_failure_and_existing_directory_are_not_overwritten(self):
        folder = self.root / 'failure'
        with self.assertRaises(FileNotFoundError):
            capture(['/nonexistent/fixture-executable'], folder)
        self.assertFalse(load(folder / 'process.json')['complete'])
        before = digest(folder / 'process.json')
        with self.assertRaises(FileExistsError):
            capture([sys.executable, '-V'], folder)
        self.assertEqual(before, digest(folder / 'process.json'))

    def test_observer_failure_retains_receipt_and_reaps_own_process(self):
        folder = self.root / 'observer-failure'
        seen = []

        def failed(pid):
            seen.append(pid)
            raise RuntimeError('synthetic observer startup failure')

        with self.assertRaisesRegex(RuntimeError, 'observer startup failure'):
            capture([sys.executable, '-I', '-B', '-c', 'import time; time.sleep(60)'],
                    folder, on_spawn=failed)
        receipt = load(folder / 'process.json')
        self.assertFalse(receipt['complete'])
        self.assertEqual(receipt['error_type'], 'RuntimeError')
        self.assertEqual(receipt['exit_code'], -signal.SIGKILL)
        self.assertFalse(Path('/proc', str(seen[0])).exists())
        for stream in ('stdout', 'stderr'):
            artifact(folder, receipt[stream])

    def test_unsafe_paths_symlinks_duplicate_keys_and_nonfinite_json_rejected(self):
        target = self.root / 'record'
        target.write_text('{}')
        for path in ('../record', str(target), 'missing'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                artifact(self.root, {'path': path, 'sha256': digest(target)})
        (self.root / 'link').symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'Linked'):
            artifact(self.root, {'path': 'link', 'sha256': digest(target)})
        for text in ('{"passed":true,"passed":false}', '{"seconds":NaN}'):
            target.write_text(text)
            with self.assertRaises(ValueError):
                load(target)


class ProductRunnerTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def test_git_interruption_keeps_original_terminal_and_incomplete_probe(self):
        from product_daily_acceptance import git_evidence

        def interrupted(root, *, probe):
            folder = root / 'rejection'
            folder.mkdir()
            (folder / 'terminal.txt').write_bytes(b'original partial operator prompt')
            probe.response('synthetic interrupted receipt', {'actual': 'unit test fixture'})
            raise KeyboardInterrupt()

        with patch('product_daily_acceptance.git_journey', side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):
                git_evidence(self.root, {'fixture': '0' * 64})
        probe = load(self.root / 'everyday/local-git/probe.json')
        self.assertFalse(probe['complete'])
        self.assertEqual(probe['error_type'], 'KeyboardInterrupt')
        self.assertFalse((self.root / 'local-git.json').exists())
        self.assertTrue(any(artifact(self.root, ref).read_bytes() == b'original partial operator prompt'
                            for ref in probe['artifacts']))
        with self.assertRaisesRegex(ValueError, 'fresh Git evidence'):
            git_evidence(self.root, {'fixture': '0' * 64})

    def test_completion_requires_gate_and_retains_failed_validation(self):
        import product_acceptance as runner
        for failed in (False, True):
            out = self.root / ('failed' if failed else 'completed')

            def independent(folder):
                save(folder / 'local-git.json', {'id': 'local-git'})
                for name in ('package', 'scope', 'lifecycle', 'resume'):
                    save(folder / (name + '-security.json'), {'security_checks': []})
                return []

            def validate(folder):
                value = load(folder / 'completion-evidence.json')
                self.assertEqual({row['id'] for row in value['journeys']}, gate.IDS)
                self.assertEqual(value['unmet_requirements'], [])
                self.assertIn('local_git', value)
                self.assertIn('requirements', value)
                self.assertEqual(value['demo_evidence'], {'fixture': 'synthetic demos'})
                if failed:
                    raise ValueError('synthetic final validation failure')
                return {'passed': True, 'complete': False,
                        'evidence_sha256': digest(folder / 'completion-evidence.json')}

            with patch.object(runner.platform, 'node', return_value='algol-box-2'), \
                 patch.object(runner.native_receipt, 'retain', return_value={'fixture': 'synthetic'}), \
                 patch.object(runner, 'candidate', return_value={'origin': 'synthetic'}), \
                 patch.object(runner, 'record_candidate', return_value={'path': 'synthetic'}), \
                 patch.object(runner, 'installed_journey', side_effect=lambda o, r, c: {'id': c, 'passed': True}), \
                 patch.object(runner, 'installed_security', side_effect=independent), \
                 patch('product_safety_evidence.collect', return_value={'fixture': 'synthetic'}), \
                 patch('product_demo_evidence.collect', return_value={'fixture': 'synthetic demos'}), \
                 patch.object(runner, 'map_requirements', return_value={'fixture': 'synthetic'}), \
                 patch.object(runner, 'verify', side_effect=validate) as verifier:
                if failed:
                    with self.assertRaisesRegex(ValueError, 'synthetic final validation'):
                        runner.acceptance(out)
                else:
                    result = runner.acceptance(out)
                    self.assertEqual(result['evidence_sha256'], digest(out / 'completion-evidence.json'))
                verifier.assert_called_once_with(out)
            value = load(out / 'completion-evidence.json')
            self.assertEqual(value['unmet_requirements'], ['evidence-validation'] if failed else [])
            self.assertEqual((out / 'gate.json').exists(), not failed)

    def test_compiled_native_boundary_rejects_changed_mounts_profile_and_payload(self):
        from native_boundary import compiled_command
        executable = '/installed/vendor/bin/codex'
        shell = '/installed/vendor/codex-resources/zsh/bin/zsh'
        profile = {'type': 'managed', 'file_system': {'type': 'restricted', 'entries': [
            {'path': {'type': 'path', 'path': '/'}, 'access': 'deny'},
            {'path': {'type': 'path', 'path': shell}, 'access': 'read'}]}, 'network': 'restricted'}
        requested = ['/usr/bin/python3', '-I', '-B', '-c', 'print("synthetic")']
        argv = ['bwrap', '--as-pid-1', '--new-session', '--die-with-parent', '--tmpfs', '/',
            '--dev', '/dev', '--ro-bind', shell, shell, '--unshare-user', '--unshare-pid',
            '--unshare-ipc', '--unshare-net', '--proc', '/proc', '--cap-drop', 'ALL',
            '--argv0', 'codex-linux-sandbox', '--', executable, '--sandbox-policy-cwd', '/work',
            '--command-cwd', '/work', '--permission-profile', json.dumps(profile),
            '--apply-seccomp-then-exec', '--', *requested]
        def record(args, executable='/installed/vendor/codex-resources/bwrap'):
            path = self.root / '0.cmdline'
            path.write_bytes(('\0'.join(args) + '\0').encode())
            (self.root / 'observations.jsonl').write_text(json.dumps(
                {'index': 0, 'cmdline_sha256': digest(path), 'executable': executable}) + '\n')
        record(argv)
        result, actual_shell = compiled_command(self.root, requested)
        self.assertEqual(result[1:], argv[1:])
        self.assertEqual(actual_shell, shell)
        for modified in ([a.replace('--tmpfs', '--bind') for a in argv],
                         argv[:8] + ['--ro-bind', '/', '/'] + argv[8:],
                         [a.replace('--unshare-net', '--share-net') for a in argv],
                         [a.replace('"deny"', '"read"') for a in argv],
                         argv[:-1] + ['changed payload']):
            with self.subTest(argv=modified), self.assertRaises(ValueError):
                record(modified)
                compiled_command(self.root, requested)
        record(argv, '/unexpected/bwrap')
        with self.assertRaisesRegex(ValueError, 'executable configuration'):
            compiled_command(self.root, requested)
        record(argv)
        (self.root / '0.cmdline').write_bytes(b'forged')
        with self.assertRaisesRegex(ValueError, 'Changed compiled'):
            compiled_command(self.root, requested)
        (self.root / 'observations.jsonl').unlink()
        with self.assertRaisesRegex(ValueError, 'Missing actual'):
            compiled_command(self.root, requested)

    def test_namespace_observation_rejects_staging_root_and_measures_real_file_effects(self):
        from native_boundary import identity, inspect_root, validate_targets
        proc = self.root / 'proc/123'
        (proc / 'root/bin').mkdir(parents=True)
        (proc / 'root/bin/shell').write_text('synthetic shell bytes')
        device = identity(proc.stat())['device']
        mount = '1 0 ' + device + ' / / rw - tmpfs tmpfs rw\n'
        (proc / 'mountinfo').write_text(mount + '2 1 0:2 / /oldroot rw - ext4 /dev/fixture rw\n')
        hosts = [self.root / 'present-parent/fixture', self.root / 'absent-parent/fixture',
                 self.root / 'exposed/fixture']
        for host in hosts:
            host.parent.mkdir()
            host.write_text('synthetic host fixture')
        targets = [str(p) for p in hosts]
        local = [proc / 'root' / name.lstrip('/') for name in targets]
        local[0].parent.mkdir(parents=True)
        local[2].parent.mkdir(parents=True)
        local[2].write_text('synthetic exposed fixture')
        before = {str(p): digest(p) for p in hosts}
        def path(value):
            return self.root / 'proc' if value == '/proc' else Path(value)
        with patch('native_boundary.Path', side_effect=path), \
                patch('native_boundary.os.readlink', side_effect=lambda p: str(p)):
            self.assertIsNone(inspect_root(123, targets, '/missing', '/bin/shell'))
            (proc / 'mountinfo').write_text(mount)
            result = inspect_root(123, targets, '/missing', '/bin/shell')
            created, absent, exposed = [result['targets'][name] for name in targets]
            for target in (created, absent):
                for operation in ('read', 'write'):
                    self.assertEqual(target[operation], {'succeeded': False, 'errno': 2})
            self.assertTrue(created['create']['succeeded'])
            self.assertEqual(created['create']['identity'], identity(local[0].stat()))
            self.assertEqual(created['create']['mount']['device'], device)
            self.assertEqual(local[0].read_text(), 'INDEPENDENT_NATIVE_ESCAPE')
            self.assertEqual(absent['create'], {'succeeded': False, 'errno': 2})
            self.assertTrue(exposed['read']['succeeded'])
            self.assertTrue(exposed['write']['succeeded'])
            self.assertEqual(local[2].read_text(), 'INDEPENDENT_NATIVE_ESCAPE')
            self.assertEqual(exposed['create'], {'succeeded': False, 'errno': 17})
            self.assertFalse(result['executable_visible'])
        self.assertEqual(before, {str(p): digest(p) for p in hosts})
        # The fake /proc tree is on the host filesystem. It must NOT establish
        # isolation, even though its synthetic mount text says tmpfs.
        with self.assertRaisesRegex(ValueError, 'identity'):
            validate_targets(result)
        synthetic = copy.deepcopy(result)
        del synthetic['targets'][targets[2]]
        synthetic['targets'][targets[0]]['host_identity']['device'] = '0:999999'
        self.assertTrue(validate_targets(synthetic))  # Validator fixture only.
        for change in ('identity', 'host_identity', 'mount', 'device', 'existing-read', 'existing-write'):
            changed = copy.deepcopy(synthetic)
            row = changed['targets'][targets[0]]
            if change == 'identity':
                del row['create']['identity']
            elif change == 'host_identity':
                del row['host_identity']
            elif change == 'mount':
                row['create']['mount']['type'] = 'ext4'
            elif change == 'device':
                row['create']['identity']['device'] = '0:999999'
            else:
                row[change.removeprefix('existing-')] = exposed[change.removeprefix('existing-')]
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_targets(changed)

    def test_resumed_native_probe_preserves_wrapper_and_exact_permission_overrides(self):
        from product_lifecycle import resumed_sandbox_command
        prefix = ['bwrap', '--die-with-parent', '--bind', '/', '/', '--ro-bind',
                  '/fixture/empty-config.toml', '/fixture/config.toml', '--']
        overrides = ['default_permissions="ptw-interactive"',
            'permissions.ptw-interactive.filesystem={"/"="deny"}',
            'permissions.ptw-interactive.network.enabled=false', 'model_reasoning_effort="low"']
        argv = prefix + ['/installed/codex', 'resume', 'synthetic-id', '-C', '/fixture/work']
        for value in overrides:
            argv += ['-c', value]
        command = resumed_sandbox_command({'argv': argv}, 'print("fixture")')
        self.assertEqual(command[:len(prefix)], prefix)
        self.assertEqual(command[len(prefix):len(prefix) + 6],
                         ['/installed/codex', 'sandbox', '-P', 'ptw-interactive', '-C', '/fixture/work'])
        self.assertEqual([command[i + 1] for i, a in enumerate(command[:-1]) if a == '-c'][:-1], overrides)
        self.assertEqual(command[-6:], ['--', '/usr/bin/python3', '-I', '-B', '-c', 'print("fixture")'])
        # The first positional command must be the probe, never a platform
        # token. Pinned CLI 0.154.0 has no `sandbox linux` subcommand.
        self.assertEqual(command[command.index('--', len(prefix)) + 1], '/usr/bin/python3')
        for invalid in (argv + ['-c', 'sandbox_mode="danger-full-access"'],
                        argv + ['-c', 'default_permissions="read-only"'],
                        [a.replace('"/"="deny"', '"/"="read"') for a in argv],
                        [a.replace('resume', 'exec') for a in argv]):
            with self.subTest(argv=invalid), self.assertRaises(ValueError):
                resumed_sandbox_command({'argv': invalid}, 'print("fixture")')

    def test_resume_probe_startup_failure_is_not_security_success(self):
        from product_lifecycle import resume_security
        session = self.root / 'session'
        session.mkdir()
        save(session / 'launch.json', {'argv': ['wrapper', '--', 'codex', 'resume', 'fixture', '-C', str(self.root)]})
        private, outside = self.root / 'private', self.root / 'outside'
        private.write_text('private fixture')
        outside.write_text('outside fixture')
        def failure(argv, folder, **kwargs):
            folder.mkdir()
            save(folder / 'process.json', {'complete': True, 'exit_code': 2})
            return subprocess.CompletedProcess(argv, 2, b'', b'could not start sandbox')
        with patch('product_lifecycle.resumed_sandbox_command', return_value=['fixture']), \
                patch('product_lifecycle.capture', side_effect=failure), \
                self.assertRaisesRegex(ValueError, 'actually executed'):
            resume_security(self.root, {'synthetic': 'fixture'}, session, private, outside, {})
        probe = load(self.root / 'security/resume-native-tools-denied/probe.json')
        self.assertFalse(probe['complete'])
        self.assertFalse((self.root / 'resume-security.json').exists())
        self.assertEqual(probe['assertions'][0]['observed'], 2)
        responses = {load(artifact(self.root, ref))['label']: load(artifact(self.root, ref))['value']
                     for ref in probe['responses']}
        self.assertEqual(responses['sensitive fixtures before native launch'],
                         responses['sensitive fixtures after native launch'])
        self.assertIn('original boundary trace.json', responses)
        self.assertIn('host executable identities before native launch', responses)
        self.assertIn('native compilation rejected', responses)

    def test_resume_probe_preserves_compilation_rejection_before_exit_assertion(self):
        from product_lifecycle import resume_security
        root, session, private, outside = self.resume_fixture('rejected-compilation')

        def failure(argv, folder, **kwargs):
            folder.mkdir()
            save(folder / 'process.json', {'complete': True, 'exit_code': 1, 'synthetic': True})
            return subprocess.CompletedProcess(argv, 1, b'', b'synthetic exec denial')

        reason = 'Missing or ambiguous actual compiled native boundary'
        with patch('product_lifecycle.resumed_sandbox_command',
                   return_value=['wrapper', '--', 'sandbox', '--', 'fixture']), \
                patch('product_lifecycle.capture', side_effect=failure), \
                patch('native_boundary.compiled_command', side_effect=ValueError(reason)), \
                patch('native_boundary.namespace_probe') as namespace, \
                self.assertRaisesRegex(ValueError, 'actually executed'):
            resume_security(root, {'synthetic': 'fixture'}, session, private, outside, {})
        namespace.assert_not_called()
        probe, responses = self.resume_records(root)
        self.assertFalse(probe['complete'])
        self.assertFalse((root / 'resume-security.json').exists())
        self.assertEqual(responses['native compilation rejected'], {'error_type': 'ValueError', 'reason': reason})
        events = [json.loads(line) for line in artifact(root, probe['output']).read_text().splitlines()]
        rejection = next(i for i, row in enumerate(events) if row.get('label') == 'native compilation rejected')
        assertion = next(i for i, row in enumerate(events) if row.get('name') == 'hostile command actually executed')
        self.assertLess(rejection, assertion)
        self.assertEqual(responses['sensitive fixtures before native launch'],
                         responses['sensitive fixtures after native launch'])

    def test_resume_probe_interruption_retains_changed_and_missing_fixtures(self):
        from product_lifecycle import resume_security
        session = self.root / 'session'
        session.mkdir()
        save(session / 'launch.json', {'argv': ['wrapper', '--', 'codex', 'resume', 'fixture', '-C', str(self.root)]})
        private, outside = self.root / 'private', self.root / 'outside'
        private.write_text('private fixture')
        outside.write_text('outside fixture')

        def interrupted(argv, folder, **kwargs):
            folder.mkdir()
            save(folder / 'process.json', {'complete': False, 'error_type': 'TimeoutExpired'})
            private.unlink()
            outside.write_text('synthetic changed fixture')
            raise subprocess.TimeoutExpired(argv, 30)

        with patch('product_lifecycle.resumed_sandbox_command', return_value=['fixture']), \
                patch('product_lifecycle.capture', side_effect=interrupted), \
                self.assertRaises(subprocess.TimeoutExpired):
            resume_security(self.root, {'synthetic': 'fixture'}, session, private, outside, {})
        probe = load(self.root / 'security/resume-native-tools-denied/probe.json')
        self.assertFalse(probe['complete'])
        self.assertEqual(probe['error_type'], 'TimeoutExpired')
        responses = {load(artifact(self.root, ref))['label']: load(artifact(self.root, ref))['value']
                     for ref in probe['responses']}
        self.assertEqual(responses['sensitive fixtures after native launch'],
                         {str(private): None, str(outside): digest(outside)})
        self.assertNotEqual(responses['sensitive fixtures before native launch'],
                            responses['sensitive fixtures after native launch'])
        self.assertIn('original sandbox process', responses)
        self.assertFalse((self.root / 'resume-security.json').exists())

    def resume_fixture(self, name):
        root = self.root / name
        session = root / 'session'
        session.mkdir(parents=True)
        save(session / 'launch.json', {'argv': ['wrapper', '--', 'codex', 'resume', 'fixture', '-C', str(root)]})
        private, outside = root / 'private', root / 'outside'
        private.write_text('private fixture')
        outside.write_text('outside fixture')
        return root, session, private, outside

    def resume_records(self, root):
        probe = load(root / 'security/resume-native-tools-denied/probe.json')
        responses = {load(artifact(root, ref))['label']: load(artifact(root, ref))['value']
                     for ref in probe['responses']}
        for ref in probe['artifacts']:
            artifact(root, ref)
        return probe, responses

    def test_resume_probe_retains_flat_and_nested_gap_originals(self):
        import errno
        from product_lifecycle import resume_security
        from sandbox_diagnostics import process_state
        base = Path('/proc') / str(os.getpid())
        live = process_state(base)
        read_bytes = Path.read_bytes
        for kind in ('flat', 'empty', 'partial', 'exit-race'):
            with self.subTest(kind=kind):
                root, session, private, outside = self.resume_fixture(kind)

                def synthetic_capture(argv, folder, **kwargs):
                    trace = kwargs['on_spawn'].__self__
                    trace.pid = os.getpid()
                    trace.sample(os.getpid())
                    if kind != 'flat':
                        def partial(path):
                            if path == base / 'cmdline':
                                return b''
                            if kind == 'partial' and path == base / 'mountinfo':
                                raise PermissionError(errno.EACCES, 'synthetic read failure')
                            return read_bytes(path)
                        after = dict(live, state='Z') if kind == 'exit-race' else live
                        with patch('sandbox_diagnostics.process_state', side_effect=[live, after]), \
                                patch.object(Path, 'read_bytes', partial):
                            trace.sample(os.getpid())
                    folder.mkdir()
                    save(folder / 'process.json', {'complete': True, 'exit_code': 0, 'synthetic': True})
                    output = {str(p): {'read': False, 'write': False} for p in (private, outside)}
                    return subprocess.CompletedProcess(argv, 0, json.dumps(output).encode(), b'')

                with patch('product_lifecycle.resumed_sandbox_command', return_value=['fixture']), \
                        patch('product_lifecycle.capture', side_effect=synthetic_capture):
                    resume_security(root, {'synthetic': 'fixture'}, session, private, outside, {})
                probe, responses = self.resume_records(root)
                self.assertTrue(probe['complete'], 'Synthetic consumer test, not native security proof')
                self.assertIn('original sandbox process', responses)
                self.assertEqual(responses['sensitive fixtures before native launch'],
                                 responses['sensitive fixtures after native launch'])
                trace = load(artifact(root, responses['original boundary trace.json']))
                self.assertEqual(trace['complete'], kind in ('flat', 'exit-race'))
                boundary = root / 'security/resume-native-tools-denied/boundary'
                retained = {label.removeprefix('original boundary ') for label in responses
                            if label.startswith('original boundary ')}
                self.assertEqual(retained, {str(p.relative_to(boundary)) for p in boundary.rglob('*') if p.is_file()})
                if kind != 'flat':
                    gap = load(artifact(root, responses['original boundary gap-0/observation.json']))
                    self.assertEqual(gap['classification'], 'exit-race' if kind == 'exit-race' else 'incomplete')
                    self.assertEqual(artifact(root, responses['original boundary gap-0/cmdline']).read_bytes(), b'')
                    self.assertEqual('mountinfo' in gap['sha256'], kind != 'partial')
                    for name, expected in gap['sha256'].items():
                        self.assertEqual(responses['original boundary gap-0/' + name]['sha256'], expected)

    def test_resume_probe_collection_errors_preserve_launch_failure_and_effects(self):
        from product_lifecycle import resume_security
        from sandbox_diagnostics import BoundaryTrace
        for kind in ('timeout', 'startup', 'denied', 'close'):
            with self.subTest(kind=kind):
                root, session, private, outside = self.resume_fixture(kind)

                def synthetic_capture(argv, folder, **kwargs):
                    trace = kwargs['on_spawn'].__self__
                    (trace.folder / 'unreadable').write_bytes(b'synthetic original')
                    folder.mkdir()
                    save(folder / 'process.json', {'complete': kind != 'timeout', 'synthetic': True})
                    if kind == 'timeout':
                        private.unlink()
                        outside.write_text('synthetic changed fixture')
                        raise subprocess.TimeoutExpired(argv, 30)
                    output = {str(p): {'read': False, 'write': False} for p in (private, outside)}
                    return subprocess.CompletedProcess(argv, 2 if kind == 'startup' else 0,
                        json.dumps(output).encode() if kind != 'startup' else b'', b'')

                def unreadable(evidence, path):
                    if path.name == 'unreadable':
                        raise PermissionError('synthetic hash failure')
                    return reference(evidence, path)

                close = BoundaryTrace.close
                def failed_close(trace):
                    close(trace)
                    if kind == 'close':
                        raise OSError('synthetic close failure')

                expected = subprocess.TimeoutExpired if kind == 'timeout' else ValueError
                with patch('product_lifecycle.resumed_sandbox_command', return_value=['fixture']), \
                        patch('product_lifecycle.capture', side_effect=synthetic_capture), \
                        patch('product_lifecycle.reference', side_effect=unreadable), \
                        patch.object(BoundaryTrace, 'close', failed_close), self.assertRaises(expected) as raised:
                    resume_security(root, {'synthetic': 'fixture'}, session, private, outside, {})
                probe, responses = self.resume_records(root)
                self.assertFalse(probe['complete'])
                self.assertEqual(probe['error_type'], expected.__name__)
                self.assertIn('original sandbox process', responses)
                self.assertIn('original boundary trace.json', responses)
                self.assertEqual(responses['sensitive fixtures after native launch'],
                    {str(private): None if kind == 'timeout' else digest(private), str(outside): digest(outside)})
                errors = responses['native diagnostic collection errors']
                self.assertEqual(len(errors), 2 if kind == 'close' else 1)
                self.assertEqual(errors[-1]['error_type'], 'PermissionError')
                self.assertNotIn('original boundary unreadable', responses)
                self.assertFalse((root / 'resume-security.json').exists())
                if kind == 'startup':
                    self.assertIn('actually executed', str(raised.exception))
                elif kind != 'timeout':
                    self.assertIn('diagnostic collection succeeded', str(raised.exception))

    def test_resume_probe_timing_write_failure_preserves_originals(self):
        from product_lifecycle import resume_security
        root, session, private, outside = self.resume_fixture('timing-write-failure')

        def failed_save(path, value):
            if path.name == 'timing.json':
                raise OSError('synthetic timing storage failure')
            save(path, value)

        def synthetic_capture(argv, folder, **kwargs):
            trace = kwargs['on_spawn'].__self__
            trace.pid = os.getpid()
            trace.sample(trace.pid)
            folder.mkdir()
            save(folder / 'process.json', {'complete': True, 'exit_code': 0, 'synthetic': True})
            output = {str(p): {'read': False, 'write': False} for p in (private, outside)}
            return subprocess.CompletedProcess(argv, 0, json.dumps(output).encode(), b'')

        with patch('product_lifecycle.resumed_sandbox_command', return_value=['fixture']), \
                patch('product_lifecycle.capture', side_effect=synthetic_capture), \
                patch('sandbox_diagnostics.save', side_effect=failed_save), \
                self.assertRaisesRegex(ValueError, 'diagnostic collection succeeded'):
            resume_security(root, {'synthetic': 'fixture'}, session, private, outside, {})
        probe, responses = self.resume_records(root)
        self.assertFalse(probe['complete'])
        self.assertIn('original sandbox process', responses)
        self.assertIn('original boundary 0.cmdline', responses)
        self.assertIn('original boundary 0.mountinfo', responses)
        self.assertFalse(load(artifact(root, responses['original boundary trace.json']))['complete'])
        self.assertEqual(responses['native diagnostic collection errors'][0]['error_type'], 'OSError')
        self.assertEqual(responses['sensitive fixtures before native launch'],
                         responses['sensitive fixtures after native launch'])

    def test_resume_probe_unreadable_fixture_does_not_hide_other_effects(self):
        from product_lifecycle import resume_security
        root, session, private, outside = self.resume_fixture('unreadable-fixture')
        launched = False

        def measured(path):
            if launched and Path(path) == private:
                raise PermissionError('synthetic fixture read failure')
            return digest(path)

        def synthetic_capture(argv, folder, **kwargs):
            nonlocal launched
            launched = True
            outside.write_text('synthetic changed fixture')
            folder.mkdir()
            save(folder / 'process.json', {'synthetic': True, 'complete': True})
            output = {str(p): {'read': False, 'write': False} for p in (private, outside)}
            return subprocess.CompletedProcess(argv, 0, json.dumps(output).encode(), b'')

        with patch('product_lifecycle.resumed_sandbox_command', return_value=['fixture']), \
                patch('product_lifecycle.capture', side_effect=synthetic_capture), \
                patch('product_lifecycle.digest', side_effect=measured), \
                self.assertRaisesRegex(ValueError, 'sensitive fixtures unchanged'):
            resume_security(root, {'synthetic': 'fixture'}, session, private, outside, {})
        probe, responses = self.resume_records(root)
        self.assertFalse(probe['complete'])
        self.assertEqual(responses['sensitive fixtures after native launch'],
                         {str(private): None, str(outside): digest(outside)})
        self.assertEqual(responses['native diagnostic collection errors'],
                         [{'path': str(private), 'error_type': 'PermissionError'}])
        self.assertIn('original sandbox process', responses)

    def test_resume_probe_rejects_linked_and_nonregular_boundary_artifacts(self):
        from product_lifecycle import resume_security
        for kind in ('file-link', 'directory-link', 'external-link', 'fifo'):
            with self.subTest(kind=kind):
                root, session, private, outside = self.resume_fixture(kind)
                def synthetic_capture(argv, folder, **kwargs):
                    boundary = kwargs['on_spawn'].__self__.folder
                    (boundary / 'regular').write_bytes(b'synthetic retained original')
                    bad = boundary / 'unsafe'
                    if kind == 'fifo':
                        os.mkfifo(bad)
                    else:
                        bad.symlink_to({'file-link': boundary / 'regular',
                                        'directory-link': session, 'external-link': self.root}[kind])
                    folder.mkdir()
                    save(folder / 'process.json', {'synthetic': True, 'complete': True})
                    output = {str(p): {'read': False, 'write': False} for p in (private, outside)}
                    return subprocess.CompletedProcess(argv, 0, json.dumps(output).encode(), b'')
                with patch('product_lifecycle.resumed_sandbox_command', return_value=['fixture']), \
                        patch('product_lifecycle.capture', side_effect=synthetic_capture), \
                        self.assertRaisesRegex(ValueError, 'diagnostic collection succeeded'):
                    resume_security(root, {'synthetic': 'fixture'}, session, private, outside, {})
                probe, responses = self.resume_records(root)
                self.assertFalse(probe['complete'])
                self.assertIn('original sandbox process', responses)
                self.assertIn('original boundary regular', responses)
                self.assertFalse(any(label.startswith('original boundary unsafe') for label in responses))
                self.assertEqual(responses['native diagnostic collection errors'], [{
                    'path': str(root / 'security/resume-native-tools-denied/boundary/unsafe'),
                    'error_type': 'ValueError'}])

    def test_boundary_diagnostics_retain_actual_descendants_without_enforcement_claim(self):
        from sandbox_diagnostics import BoundaryTrace, executable_identity
        # Keep original samples and process output even when an assertion fails.
        retained = Path(tempfile.mkdtemp(prefix='ptw-boundary-diagnostics-'))
        print('BOUNDARY_DIAGNOSTIC_EVIDENCE ' + str(retained), flush=True)
        save(retained / 'source.json', native.sources())
        trace = BoundaryTrace(retained / 'boundary')
        ready, release = retained / 'child-ready', retained / 'release'
        child = ('import os,sys,time; from pathlib import Path; '
                 'Path(sys.argv[1]).write_text(str(os.getpid()))\n'
                 'while not Path(sys.argv[2]).exists(): time.sleep(.01)\n')
        parent = ('import subprocess,sys; '
                  'subprocess.run([sys.executable,"-I","-B","-c",*sys.argv[1:]],check=True)')

        def observe(pid):
            # Hold both processes alive while asserting complete observations.
            # Exit/unknown states are tested separately and must remain explicit gaps.
            deadline = time.monotonic() + 5
            try:
                while not ready.exists():
                    if time.monotonic() >= deadline:
                        raise TimeoutError('diagnostic child did not become ready')
                    time.sleep(.01)
                trace.start(pid)
                while trace.samples < 2:
                    if time.monotonic() >= deadline:
                        raise TimeoutError('diagnostic descendants were not sampled')
                    trace.stop.wait(.01)
            finally:
                trace.close()
                release.write_text('sampling finished\n')

        try:
            result = capture([sys.executable, '-I', '-B', '-c', parent, child, str(ready), str(release)],
                             retained / 'process', on_spawn=observe)
        finally:
            trace.close()
        self.assertEqual(result.returncode, 0)
        receipt = load(trace.folder / 'trace.json')
        self.assertTrue(receipt['complete'], receipt)
        self.assertGreaterEqual(receipt['samples'], 2)
        self.assertIn('No enforcement verdict', receipt['limitation'])
        observations = [json.loads(line) for line in (trace.folder / 'observations.jsonl').read_text().splitlines()]
        self.assertGreaterEqual(len({r['pid'] for r in observations}), 2)
        self.assertIn(int(ready.read_text()), {r['pid'] for r in observations})
        timing = load(trace.folder / 'timing.json')
        self.assertLessEqual(timing['started_monotonic'], timing['start_requested_monotonic'])
        self.assertLessEqual(timing['start_requested_monotonic'], timing['collector_started_monotonic'])
        self.assertEqual(timing['rows_omitted'], 0)
        self.assertEqual(timing['children_omitted'], 0)
        edge = next(r for r in timing['rows'] if int(ready.read_text()) in r['children'])
        self.assertEqual(edge['pid'], receipt['root_pid'])
        self.assertIn('start_ticks', edge['before'])
        for row in timing['rows']:
            self.assertLessEqual(timing['collector_started_monotonic'], row['start_monotonic'])
            self.assertLessEqual(row['start_monotonic'], row['end_monotonic'])
            self.assertLessEqual(row['end_monotonic'], timing['collection_closed_monotonic'])
        for row in observations:
            for kind in ('cmdline', 'mountinfo'):
                path = trace.folder / (str(row['index']) + '.' + kind)
                context = f'{retained}: field={kind} index={row["index"]} pid={row["pid"]} state={row}'
                self.assertEqual(digest(path), row[kind + '_sha256'], context)
                self.assertGreater(path.stat().st_size, 0, context)
        for folder in trace.folder.glob('gap-*'):
            gap = load(folder / 'observation.json')
            self.assertEqual(gap['classification'], 'exit-race', gap)
            for kind, expected in gap['sha256'].items():
                self.assertEqual(digest(folder / kind), expected, gap)
        identities = load(trace.folder / 'executables.json')
        self.assertTrue(identities)
        self.assertTrue(all(p['sha256'] == digest(p['resolved']) for p in identities))
        self.assertEqual(executable_identity(self.root / 'missing')['error_type'], 'FileNotFoundError')

    def test_boundary_timing_separates_discovery_reads_and_persistence(self):
        from sandbox_diagnostics import BoundaryTrace
        trace = BoundaryTrace(self.root / 'timed')
        trace.pid = os.getpid()
        base = Path('/proc') / str(trace.pid)
        clock = [100.]
        iterdir, read_bytes, write_bytes = Path.iterdir, Path.read_bytes, Path.write_bytes

        def delayed_discovery(path):
            if path == base / 'task':
                clock[0] += 2
            return iterdir(path)

        def delayed_read(path):
            if path.parent == base:
                clock[0] += {'cmdline': 3, 'mountinfo': 5}[path.name]
            return read_bytes(path)

        def delayed_write(path, data):
            clock[0] += 7
            return write_bytes(path, data)

        # Synthetic clock delays isolate attribution without sleeping or claiming
        # measured native latency. Original bytes still come from this process.
        with patch('sandbox_diagnostics.time.monotonic', side_effect=lambda: clock[0]), \
                patch.object(Path, 'iterdir', delayed_discovery), \
                patch.object(Path, 'read_bytes', delayed_read), \
                patch.object(Path, 'write_bytes', delayed_write):
            trace.sample(trace.pid)
            trace.sample(trace.pid)
        trace.close()
        rows = load(trace.folder / 'timing.json')['rows']
        first, unchanged = rows
        self.assertEqual(first['discovery_end_monotonic'] - first['discovery_start_monotonic'], 2)
        self.assertEqual(first['read_end_monotonic'] - first['read_start_monotonic'], 8)
        self.assertEqual(first['persistence_end_monotonic'] - first['persistence_start_monotonic'], 14)
        self.assertEqual(first['end_monotonic'] - first['start_monotonic'], 24)
        self.assertEqual(first['observation'], 0)
        self.assertEqual(first['before']['start_ticks'], first['after']['start_ticks'])
        self.assertEqual(unchanged['classification'], 'unchanged')
        self.assertNotIn('persistence_start_monotonic', unchanged)
        self.assertTrue(load(trace.folder / 'trace.json')['complete'])
        sample = json.loads((trace.folder / 'observations.jsonl').read_text())
        self.assertEqual(digest(trace.folder / '0.cmdline'), sample['cmdline_sha256'])

    def test_boundary_timing_limits_disclose_omissions_without_changing_discovery(self):
        from sandbox_diagnostics import BoundaryTrace
        trace = BoundaryTrace(self.root / 'bounded')
        trace.pid = os.getpid()
        trace.MAX_TIMING_ROWS, trace.MAX_TIMING_CHILDREN = 2, 1
        read_text = Path.read_text

        def children(path, *args, **kwargs):
            if str(path).startswith('/proc/') and path.name == 'children':
                return '101 102 103'  # Synthetic descendant IDs, never traversed.
            return read_text(path, *args, **kwargs)

        with patch.object(Path, 'read_text', children):
            for _ in range(3):
                self.assertEqual(trace.sample(trace.pid), {101, 102, 103})
        trace.close()
        timing = load(trace.folder / 'timing.json')
        self.assertEqual(len(timing['rows']), 2)
        self.assertEqual(timing['rows_omitted'], 1)
        self.assertEqual(timing['children_omitted'], 6)
        self.assertTrue(all(r['children'] == [101] and r['children_omitted'] == 2 for r in timing['rows']))
        receipt = load(trace.folder / 'trace.json')
        self.assertEqual(receipt['timing_rows_omitted'], 1)
        self.assertEqual(receipt['timing_children_omitted'], 6)
        self.assertFalse(receipt['complete'])
        self.assertEqual(receipt['samples'], 1)

    def test_boundary_timing_retains_failed_discovery_and_persistence(self):
        from sandbox_diagnostics import BoundaryTrace
        for phase in ('discovery', 'persistence'):
            with self.subTest(phase=phase):
                trace = BoundaryTrace(self.root / phase)
                trace.pid = os.getpid()

                def denied(*args):
                    trace.stop.set()
                    raise PermissionError('synthetic ' + phase + ' failure')

                with patch.object(Path, 'iterdir' if phase == 'discovery' else 'write_bytes', denied):
                    trace.watch(trace.pid)
                trace.close()
                timing = load(trace.folder / 'timing.json')
                self.assertEqual(len(timing['rows']), 1)
                row = timing['rows'][0]
                self.assertEqual(row['error_type'], 'PermissionError')
                self.assertIn(phase + '_start_monotonic', row)
                self.assertNotIn(phase + '_end_monotonic', row)
                self.assertLessEqual(row['start_monotonic'], row['end_monotonic'])
                self.assertFalse(load(trace.folder / 'trace.json')['complete'])

    def test_boundary_empty_reads_require_observed_exit_and_retain_originals(self):
        import errno
        from sandbox_diagnostics import BoundaryTrace, process_state
        base = Path('/proc') / str(os.getpid())
        live = process_state(base)
        self.assertIn('start_ticks', live)
        missing = {'error_type': 'FileNotFoundError', 'errno': errno.ENOENT}
        unknown = {'error_type': 'PermissionError', 'errno': errno.EACCES}
        read_bytes = Path.read_bytes
        scenarios = [('live', live, live, False),
                     ('zombie', live, dict(live, state='Z'), True),
                     ('vanished', live, missing, True),
                     ('already-gone', missing, missing, True),
                     ('unknown-before', unknown, missing, False),
                     ('unknown-after', live, unknown, False),
                     ('reused', live, dict(live, state='Z', start_ticks=live['start_ticks'] + 1), False)]
        for kind in ('cmdline', 'mountinfo'):
            for name, before, after, exited in scenarios:
                with self.subTest(field=kind, state=name):
                    trace = BoundaryTrace(self.root / (kind + '-' + name))
                    trace.pid = os.getpid()
                    trace.sample(os.getpid())  # A genuine complete baseline observation.

                    def empty(path):
                        return b'' if path == base / kind else read_bytes(path)

                    with patch('sandbox_diagnostics.process_state', side_effect=[before, after]), \
                            patch.object(Path, 'read_bytes', empty):
                        trace.sample(os.getpid())
                    trace.close()
                    receipt = load(trace.folder / 'trace.json')
                    gap = load(trace.folder / 'gap-0/observation.json')
                    self.assertEqual(receipt['complete'], exited, gap)
                    self.assertEqual(receipt['exit_races'], int(exited), gap)
                    self.assertEqual(receipt['gaps'], 1)
                    self.assertEqual(receipt['samples'], 1, 'Empty reads cannot become usable samples')
                    self.assertEqual(gap['classification'], 'exit-race' if exited else 'incomplete')
                    self.assertEqual(gap['before'], before)
                    self.assertEqual(gap['after'], after)
                    self.assertEqual(gap['empty_fields'], [kind])
                    self.assertEqual((trace.folder / 'gap-0' / kind).read_bytes(), b'')
                    for field, expected in gap['sha256'].items():
                        self.assertEqual(digest(trace.folder / 'gap-0' / field), expected)

    def test_boundary_partial_reads_do_not_hide_permission_or_live_invalid_errors(self):
        import errno
        from sandbox_diagnostics import BoundaryTrace, process_state
        base = Path('/proc') / str(os.getpid())
        live = process_state(base)
        read_bytes = Path.read_bytes
        for code, exited in ((errno.EACCES, False), (errno.EINVAL, False), (errno.EINVAL, True)):
            with self.subTest(errno=code, exited=exited):
                trace = BoundaryTrace(self.root / f'partial-{code}-{exited}')
                trace.pid = os.getpid()
                trace.sample(os.getpid())

                def partial(path):
                    if path == base / 'cmdline':
                        return b''
                    if path == base / 'mountinfo':
                        raise OSError(code, 'synthetic proc error')
                    return read_bytes(path)

                after = dict(live, state='Z') if code == errno.EACCES or exited else live
                with patch('sandbox_diagnostics.process_state', side_effect=[live, after]), \
                        patch.object(Path, 'read_bytes', partial):
                    trace.sample(os.getpid())
                trace.close()
                gap = load(trace.folder / 'gap-0/observation.json')
                self.assertEqual(load(trace.folder / 'trace.json')['complete'], exited, gap)
                self.assertEqual(gap['read_errors']['mountinfo']['errno'], code)
                self.assertEqual((trace.folder / 'gap-0/cmdline').read_bytes(), b'')
                self.assertFalse((trace.folder / 'gap-0/mountinfo').exists())

    def test_boundary_process_state_retains_malformed_or_unreadable_stat(self):
        from sandbox_diagnostics import process_state
        with patch.object(Path, 'read_text', return_value='malformed stat'):
            state = process_state(self.root)
        self.assertEqual(state['raw'], 'malformed stat')
        self.assertEqual(state['error_type'], 'IndexError')
        with patch.object(Path, 'read_text', side_effect=PermissionError()):
            self.assertEqual(process_state(self.root)['error_type'], 'PermissionError')

    def test_boundary_diagnostics_disclose_unreadable_process_state(self):
        from sandbox_diagnostics import BoundaryTrace
        trace = BoundaryTrace(self.root / 'boundary')
        try:
            with patch.object(trace, 'sample', side_effect=PermissionError('synthetic proc denial')):
                trace.start(os.getpid())
                trace.stop.wait(.03)
                trace.close()
        finally:
            trace.close()
        receipt = load(trace.folder / 'trace.json')
        self.assertFalse(receipt['complete'])
        self.assertEqual(receipt['errors'], ['PermissionError: errno=None'])
        self.assertEqual(receipt['samples'], 0)

    def test_boundary_diagnostics_do_not_hide_live_invalid_mount_reads(self):
        import errno
        from sandbox_diagnostics import BoundaryTrace
        trace = BoundaryTrace(self.root / 'boundary')
        try:
            with patch.object(trace, 'sample', side_effect=OSError(errno.EINVAL, 'synthetic live proc error')):
                trace.start(os.getpid())
                trace.stop.wait(.03)
                trace.close()
        finally:
            trace.close()
        receipt = load(trace.folder / 'trace.json')
        self.assertFalse(receipt['complete'])
        self.assertEqual(receipt['errors'], ['OSError: errno=22'])
        self.assertEqual(receipt['exit_races'], 0)

    def test_lifecycle_failure_keeps_cancel_receipt_and_incomplete_other_probes(self):
        from product_lifecycle import lifecycle_security
        def cancelled(probe, *args):
            probe.response('synthetic cancellation fixture', {'exit_code': 2})
            probe.check('synthetic fixture only', 2, 2)
        with patch('product_lifecycle.cancellation', side_effect=cancelled), \
                patch('product_install_acceptance.acceptance', side_effect=RuntimeError('fixture failure')), \
                self.assertRaisesRegex(RuntimeError, 'fixture failure'):
            lifecycle_security(self.root, {}, {}, 'fixture', {})
        result = load(self.root / 'lifecycle-security.json')
        self.assertFalse(result['complete'])
        self.assertEqual([r['id'] for r in result['security_checks']], ['cancel-preserves-repo'])
        for name in ('installation-retry-preserves-data', 'upgrade-rollback-uninstall'):
            probe = load(self.root / 'security' / name / 'probe.json')
            self.assertFalse(probe['complete'])
            self.assertEqual(probe['error_type'], 'RuntimeError')

    def test_finite_project_matrix_autodetects_and_preserves_existing_work(self):
        from product_projects import CASES, commands, fixture, first_prompt, layout, resume_prompt
        from ptw.onboarding import detect
        self.assertEqual(set(CASES), gate.IDS)
        self.assertEqual(len(CASES), len(gate.IDS))
        for case in CASES:
            with self.subTest(case=case):
                repo = self.root / case
                record = fixture(repo, case)
                expected = 'mixed' if 'mixed' in case else case.split('-', 1)[1]
                self.assertEqual(detect(repo), 'javascript' if expected == 'node' else expected)
                self.assertEqual(bool(record['preserved']), case.startswith('existing-'))
                self.assertEqual(record['preserved'], {p: digest(repo / p) for p in record['preserved']})
                self.assertEqual(len(commands(case)), 4 if expected == 'mixed' else 2)
                self.assertIn('conversation-only', first_prompt(case, 'synthetic-nonce'))
                self.assertIn('synthetic-nonce', first_prompt(case, 'synthetic-nonce'))
                self.assertNotIn('synthetic-nonce', resume_prompt(case))
                for kind, root in layout(case):
                    self.assertFalse((repo / root / 'src/site.py').exists())
                    self.assertIn(str(Path(root) / 'src'), record['editable'])
                with self.assertRaisesRegex(ValueError, 'fresh fixture'):
                    fixture(repo, case)
        with self.assertRaisesRegex(ValueError, 'Unknown mandatory journey'):
            layout('invented-language')

    def test_warm_archive_profile_is_explicit_and_never_reuses_installation(self):
        from product_acceptance import installer_artifact
        archive = self.root / 'candidate.tar.gz'
        archive.write_bytes(b'synthetic archive bytes, never installed')
        folder = self.root / 'existing-node'
        folder.mkdir()
        release = {'artifact': str(archive), 'sha256': digest(archive), 'origin': 'local-candidate'}
        with installer_artifact(folder, release, 'warm') as (argv, cache):
            self.assertEqual(argv, [str(archive)])
            self.assertEqual(artifact(self.root, cache['release_archive']), archive)
            self.assertEqual(cache['npm_cache'], 'empty private cache')
            self.assertFalse((folder / 'installation').exists())
        archive.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'Candidate changed'), installer_artifact(folder, release, 'warm'):
            self.fail('tampered archive admitted')

    def test_pinned_launch_and_resume_disable_startup_updater(self):
        from ptw.terminal import codex_command
        config = self.root / 'synthetic-codex-config'
        config.mkdir()
        save(config / 'models_cache.json', {'models': [{'slug': 'gpt-5.6-sol'}]})
        (config / 'config.toml').write_text('# synthetic user configuration remains unchanged\n')
        before = digest(config / 'config.toml')
        conversation = self.root / 'conversation'
        conversation.mkdir()
        store = SimpleNamespace(directory=self.root / 'controller')
        with patch.dict(os.environ, {'CODEX_HOME': str(config)}), \
                patch('ptw.terminal.require_login'), \
                patch('ptw.terminal.shutil.which', side_effect=lambda name: '/usr/bin/' + name), \
                patch('ptw.terminal.subprocess.run', return_value=SimpleNamespace(
                    returncode=0, stdout='codex-cli 0.154.0')):
            for resume in (None, str(uuid.uuid4())):
                command = codex_command(store, self.root / 'session.json', self.root / 'work',
                                        conversation=conversation, resume=resume)
                self.assertIn('check_for_update_on_startup=false', command)
                self.assertIn('mcp_servers.ptw.required=true', command)
                self.assertIn('permissions.ptw-interactive.filesystem={"/"="deny"}', command)
                self.assertEqual(command[command.index('-m') + 1], 'gpt-5.6-sol')
                self.assertIn('model_reasoning_effort="low"', command)
        self.assertEqual(digest(config / 'config.toml'), before)

    def test_independent_oracle_accepts_spec_and_rejects_faulty_application(self):
        from product_journey import ORACLE
        (self.root / 'src').mkdir()
        (self.root / 'tests').mkdir()
        (self.root / 'tests/test_oracle.py').write_text(ORACLE)
        app = self.root / 'src/site.py'
        valid = ('import html\ndef render(items, category="all"):\n'
            '    if not isinstance(items, list): raise TypeError()\n'
            '    for item in items:\n'
            '        if not isinstance(item, dict) or not all(isinstance(item.get(k), str) for k in ("title", "category")): raise TypeError()\n'
            '    return "<ul>" + "".join("<li>" + html.escape(i["title"]) + "</li>" for i in items if category == "all" or i["category"] == category) + "</ul>"\n')
        for name, code, expected in (('correct', valid, 0),
                ('incorrect', 'def render(items, category="all"):\n    return "<ul></ul>"\n', 1)):
            app.write_text(code)
            result = capture([sys.executable, '-I', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-v'],
                self.root / name, cwd=self.root)
            self.assertEqual(result.returncode, expected)
            self.assertIn(b'Ran 4 tests', result.stderr)

    def test_release_tag_validation_and_missing_candidate_never_build_locally(self):
        import product_acceptance as runner
        for tag in ('latest', 'harness-v../1.0.0', 'ptw-v1.0.0'):
            out = self.root / str(len(list(self.root.iterdir())))
            out.mkdir()
            with patch.object(runner, 'capture') as build, patch.object(runner, 'fetch',
                    side_effect=OSError('fixture public candidate missing')):
                with self.assertRaises((ValueError, OSError)):
                    runner.candidate(out, tag)
                build.assert_not_called()

    def test_exact_release_tag_asset_hashes_and_origin(self):
        import product_acceptance as runner
        import hashlib
        data = {'install.sh': b'synthetic bootstrap, never executed',
                'ptw-1.2.3-linux-x86_64.tar.gz': b'synthetic artifact, never installed'}
        data['SHA256SUMS'] = ''.join(hashlib.sha256(body).hexdigest() + '  ' + name + '\n'
                                    for name, body in data.items()).encode()
        seen = []
        def fetch(url, path):
            seen.append(url)
            path.write_bytes(data[path.name])
        with patch.object(runner, 'fetch', side_effect=fetch), patch.object(runner, 'capture') as build:
            result = runner.candidate(self.root, 'ptw-v1.2.3')
            build.assert_not_called()
        self.assertEqual(result['origin'], 'public-release')
        self.assertEqual(result['release_tag'], 'ptw-v1.2.3')
        self.assertTrue(all('/ptw-v1.2.3/' in url for url in seen))
        self.assertEqual(result['sha256'], digest(result['artifact']))

    def test_partial_release_download_is_retained(self):
        import product_acceptance as runner
        from contextlib import nullcontext
        response = SimpleNamespace(url='https://synthetic.invalid/asset',
            read=unittest.mock.Mock(side_effect=[b'original partial bytes', OSError('interrupted fixture')]))
        target = self.root / 'asset'
        with patch.object(runner.urllib.request, 'urlopen', return_value=nullcontext(response)):
            with self.assertRaises(OSError):
                runner.fetch(response.url, target)
        self.assertEqual(target.read_bytes(), b'original partial bytes')
        receipt = load(self.root / 'asset.download.json')
        self.assertFalse(receipt['complete'])
        self.assertEqual(artifact(self.root, receipt['artifact']), target)

    def test_failure_manifest_preserved_and_missing_native_evidence_prevents_model_run(self):
        import product_acceptance as runner
        out = self.root / 'attempt'
        with patch.object(runner.platform, 'node', return_value='algol-box-2'), \
             patch.object(runner.native_receipt, 'retain', side_effect=ValueError('missing full native receipt')), \
             patch.object(runner, 'candidate') as candidate:
            with self.assertRaisesRegex(ValueError, 'missing full native receipt'):
                runner.acceptance(out)
            candidate.assert_not_called()
        report = load(out / 'completion-evidence.json')
        self.assertTrue(report['unmet_requirements'])
        self.assertEqual(report['journeys'], [])
        original = digest(out / 'completion-evidence.json')
        with self.assertRaisesRegex(ValueError, 'new evidence directory'):
            runner.acceptance(out)
        self.assertEqual(digest(out / 'completion-evidence.json'), original)


class SecurityProbeTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.source = {'synthetic-test-source': '0' * 64}
        self.started = time.time()

    def test_concurrent_assessments_keep_distinct_original_receipts(self):
        from concurrent.futures import ThreadPoolExecutor
        import threading
        from product_security import Probe, RecordedProvider
        probe = Probe(self.root, self.root / 'probe', 'old-compatible-selected', self.source)
        first_saved, release_first, second_started = (threading.Event() for _ in range(3))

        def paused_save(path, value):
            save(path, value)
            if value.get('value', {}).get('name') == 'first':
                first_saved.set()
                if not release_first.wait(5):
                    raise TimeoutError('test failed to release original receipt writer')

        def assess(name, version):
            if name == 'second':
                second_started.set()
            return {'name': name, 'version': version}

        provider = RecordedProvider(SimpleNamespace(assess=assess), probe)
        with ThreadPoolExecutor(max_workers=2) as pool, \
                patch('product_security.save', side_effect=paused_save):
            first = pool.submit(provider.assess, 'first', '1.0')
            try:
                self.assertTrue(first_saved.wait(5))
                second = pool.submit(provider.assess, 'second', '2.0')
                self.assertTrue(second_started.wait(5))
                # The second assessment has run, but may not overwrite the first
                # original while publication of its reference is still pending.
                from concurrent.futures import TimeoutError as FutureTimeout
                with self.assertRaises(FutureTimeout):
                    second.result(timeout=.1)
            finally:
                release_first.set()
            self.assertEqual(first.result(timeout=5), {'name': 'first', 'version': '1.0'})
            self.assertEqual(second.result(timeout=5), {'name': 'second', 'version': '2.0'})
        originals = [load(artifact(self.root, ref))['value'] for ref in probe.responses]
        self.assertEqual(originals, [{'name': 'first', 'version': '1.0'},
                                     {'name': 'second', 'version': '2.0'}])
        self.assertEqual(len({r['path'] for r in probe.responses}), 2)
        probe.check('distinct originals retained', 2, len(originals))
        row = probe.finish()
        gate.security_check(self.root, row, {'source_sha256': self.source,
            'started_epoch': self.started, 'ended_epoch': time.time()})

    def test_parallel_downloads_and_measurements_preserve_all_originals(self):
        from concurrent.futures import ThreadPoolExecutor
        import threading
        from product_security import Probe, RecordedProvider
        probe = Probe(self.root, self.root / 'probe', 'tampered-package-denied', self.source)
        barrier = threading.Barrier(8)

        def download(evidence, path):
            path.write_bytes(evidence['body'])
            barrier.wait(timeout=5)

        provider = RecordedProvider(SimpleNamespace(download=download), probe)

        def record(index):
            body = ('original bytes ' + str(index)).encode()
            provider.download({'body': body}, self.root / ('input-' + str(index)))
            probe.check('download ' + str(index), len(body), len(body))

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(record, range(8)))
        self.assertEqual(len(probe.responses), 8)
        self.assertEqual(len(probe.artifacts), 8)
        self.assertEqual(len({r['path'] for r in probe.artifacts}), 8)
        self.assertEqual({artifact(self.root, ref).read_bytes() for ref in probe.artifacts},
                         {('original bytes ' + str(i)).encode() for i in range(8)})
        self.assertFalse(list(probe.folder.glob('*.pending')))
        row = probe.finish()
        gate.security_check(self.root, row, {'source_sha256': self.source,
            'started_epoch': self.started, 'ended_epoch': time.time()})

    def test_concurrent_receipt_failure_retains_incomplete_attempt(self):
        from concurrent.futures import ThreadPoolExecutor
        from product_security import Probe
        probe = Probe(self.root, self.root / 'probe', 'old-compatible-selected', self.source)

        def failing_save(path, value):
            if value.get('label') == 'failed fixture response':
                raise OSError('synthetic receipt write failure')
            save(path, value)

        with ThreadPoolExecutor(max_workers=2) as pool, \
                patch('product_security.save', side_effect=failing_save):
            failed = pool.submit(probe.response, 'failed fixture response', {'name': 'failed'})
            succeeded = pool.submit(probe.response, 'retained fixture response', {'name': 'retained'})
            with self.assertRaisesRegex(OSError, 'synthetic receipt write failure'):
                failed.result(timeout=5)
            self.assertEqual(succeeded.result(timeout=5), {'name': 'retained'})
        probe.persist(OSError('synthetic receipt write failure'))
        receipt = load(probe.folder / 'probe.json')
        self.assertFalse(receipt['complete'])
        self.assertEqual(receipt['error_type'], 'OSError')
        self.assertEqual(len(receipt['responses']), 1)
        self.assertEqual(load(artifact(self.root, receipt['responses'][0]))['value'], {'name': 'retained'})
        self.assertFalse((probe.folder / 'security.json').exists())

    def test_original_measurements_and_responses_validate_and_detect_mutation(self):
        from product_security import Probe
        probe = Probe(self.root, self.root / 'probe', 'critical-direct-denied', self.source)
        probe.response('deterministic fixture response', {'allowed': False})
        probe.check('original denied response', False, False)
        row = probe.finish()
        report = {'source_sha256': self.source, 'started_epoch': self.started, 'ended_epoch': time.time()}
        gate.security_check(self.root, row, report)
        original = load(probe.folder / 'probe.json')
        original['assertions'][0]['expected'] = original['assertions'][0]['observed'] = True
        save(probe.folder / 'probe.json', original)
        summary = load(probe.folder / 'security.json')
        summary['assertions'] = original['assertions']
        summary['probes'] = [reference(self.root, probe.folder / 'probe.json')]
        save(probe.folder / 'security.json', summary)
        row['record'] = reference(self.root, probe.folder / 'security.json')
        with self.assertRaisesRegex(ValueError, 'Original security observation'):
            gate.security_check(self.root, row, report)

    def test_failed_assertion_and_interruption_preserve_incomplete_originals(self):
        from product_security import Probe
        probe = Probe(self.root, self.root / 'probe', 'fixture-failure', self.source)
        probe.response('partial operation', {'allowed': True})
        with self.assertRaises(ValueError):
            probe.check('must be denied', False, True)
        probe.persist(KeyboardInterrupt())
        receipt = load(probe.folder / 'probe.json')
        self.assertFalse(receipt['complete'])
        self.assertEqual(receipt['error_type'], 'KeyboardInterrupt')
        self.assertTrue(receipt['assertions'][0]['observed'])
        self.assertFalse((probe.folder / 'security.json').exists())
        with self.assertRaisesRegex(ValueError, 'Failed probe'):
            probe.finish()
        original = artifact(self.root, receipt['output']).read_text()
        self.assertIn('"observed": true', original)
        with self.assertRaises(FileExistsError):
            Probe(self.root, probe.folder, 'fixture-failure', self.source)

    def test_package_matrix_is_finite_and_partial_failure_is_not_completion(self):
        import product_security as security
        self.assertEqual(len(set(security.PACKAGE_IDS)), 9)
        self.assertLessEqual(set(security.PACKAGE_IDS), gate.SECURITY)
        with patch.object(security, 'denied_package', side_effect=RuntimeError('fixture failure')):
            with self.assertRaisesRegex(RuntimeError, 'fixture failure'):
                security.package_security(self.root, self.source)
        receipt = load(self.root / 'package-security.json')
        self.assertFalse(receipt['complete'])
        self.assertEqual(receipt['security_checks'], [])
        partial = load(self.root / 'security' / security.PACKAGE_IDS[0] / 'probe.json')
        self.assertFalse(partial['complete'])
        self.assertEqual(partial['error_type'], 'RuntimeError')

    def test_scope_matrix_retains_interrupted_observations_without_completion(self):
        import product_scope as scope
        from product_security import PACKAGE_IDS
        self.assertEqual(len(set(scope.SCOPE_IDS)), 7)
        self.assertLessEqual(set(scope.SCOPE_IDS), gate.SECURITY)
        self.assertFalse(set(scope.SCOPE_IDS) & set(PACKAGE_IDS))

        def interrupted(probes):
            probe = probes['private-file-denied']
            probe.response('synthetic unit-test response', {'allowed': False})
            probe.check('unit-test observation', False, False)
            raise KeyboardInterrupt()

        with patch.object(scope, 'scope_effects', side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):
                scope.scope_security(self.root, self.source)
        receipt = load(self.root / 'scope-security.json')
        self.assertFalse(receipt['complete'])
        self.assertEqual(receipt['security_checks'], [])
        for identity in scope.SCOPE_IDS:
            path = self.root / 'security' / identity
            probe = load(path / 'probe.json')
            self.assertFalse(probe['complete'])
            self.assertEqual(probe['error_type'], 'KeyboardInterrupt')
            self.assertFalse((path / 'security.json').exists())
        before = {str(p): digest(p) for p in self.root.rglob('*') if p.is_file()}
        with self.assertRaisesRegex(ValueError, 'previous attempts are immutable'):
            scope.scope_security(self.root, self.source)
        self.assertEqual(before, {str(p): digest(p) for p in self.root.rglob('*') if p.is_file()})

    def test_scope_failure_cannot_be_published_as_a_success(self):
        import product_scope as scope

        def failed(probes):
            probes['stop-kills-active-work'].check('actual unit must stop', True, False)

        with patch.object(scope, 'scope_effects', side_effect=failed):
            with self.assertRaisesRegex(ValueError, 'actual unit must stop'):
                scope.scope_security(self.root, self.source)
        receipt = load(self.root / 'scope-security.json')
        self.assertFalse(receipt['complete'])
        self.assertEqual(receipt['security_checks'], [])
        probe = load(self.root / 'security/stop-kills-active-work/probe.json')
        self.assertEqual(probe['assertions'][0]['observed'], False)
        self.assertIn('"observed": false', artifact(self.root, probe['output']).read_text())

    def test_scope_fixture_native_start_failure_preserves_controller_and_cleanup(self):
        import product_scope as scope
        from ptw.store import Store
        # No socket or service is started: this deliberately fails at the native
        # boundary after validating and activating the actual fixture policy.
        sockets = [SimpleNamespace(bind=lambda address: None,
                    getsockname=lambda port=port: ('127.0.0.1', port), close=lambda: None)
                   for port in range(32001, 32005)]
        with patch.object(scope.socket, 'socket', side_effect=sockets), \
                patch('ptw.monitor.ensure', side_effect=RuntimeError('native startup unavailable')), \
                patch('ptw.monitor.remove') as removed:
            with self.assertRaisesRegex(RuntimeError, 'native startup unavailable'):
                scope.scope_security(self.root, self.source)
        registration = next((self.root / 'scope-fixture/scope-project/operator-state').glob('*/project.json'))
        record = load(registration)
        bundle = load(record['bundle'])
        self.assertEqual(bundle['policy']['version'], 4)
        self.assertEqual(len(bundle['policy']['project']['commands']), 3)
        self.assertEqual(registration.parent.stat().st_mode & 0o077, 0)
        self.assertEqual(registration.parent.parent.stat().st_mode & 0o077, 0)
        store = Store(record['state'])
        self.assertTrue(store.status('scope-project')['stopped'])
        self.assertEqual(store.status('scope-project')['workloads'], [])
        self.assertEqual(removed.call_count, 1)
        self.assertEqual(removed.call_args.args[0].directory, store.directory)
        self.assertEqual(load(self.root / 'scope-fixture/scope-project-cleanup.json'), {'termination': []})
        self.assertFalse(load(self.root / 'scope-security.json')['complete'])

    def test_scope_http_invalid_and_interrupted_output_keeps_original_bytes(self):
        import product_scope as scope
        from product_security import Probe
        for label, body, error in [('invalid', b'not JSON', ValueError),
                                    ('interrupted', b'{"partial":', TimeoutError)]:
            with self.subTest(label=label):
                probe = Probe(self.root, self.root / label, 'private-file-denied', self.source)
                chunks = iter([body, TimeoutError('fixture timeout')] if label == 'interrupted' else [body, b''])

                def read(size):
                    item = next(chunks)
                    if isinstance(item, BaseException):
                        raise item
                    return item

                response = SimpleNamespace(status=200, getheaders=lambda: [('Content-Type', 'application/json')], read1=read)
                closed = []
                connection = SimpleNamespace(request=lambda *args: None, getresponse=lambda: response,
                                             close=lambda: closed.append(True))
                with patch.object(scope.http.client, 'HTTPConnection', return_value=connection):
                    with self.assertRaises(error):
                        scope.http_observation(probe, 32001)
                self.assertEqual(closed, [True])
                original = load(artifact(self.root, probe.responses[0]))['value']
                self.assertEqual(artifact(self.root, original).read_bytes(), body)
                transport = load(artifact(self.root, probe.responses[1]))['value']
                self.assertFalse(transport['complete'])
                self.assertEqual(transport['status'], 200)
                self.assertIn('error_type', transport)


class NativeEnvironmentTests(unittest.TestCase):
    def test_discovery_uses_verified_dependencies_without_site_hooks_or_test_execution(self):
        import shutil
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, site = root / 'repo', root / 'dependencies'
            scripts, tests = repo / 'harness/scripts', repo / 'harness/tests'
            scripts.mkdir(parents=True)
            tests.mkdir()
            site.mkdir()
            for name in ('native_receipt.py', 'evidence_io.py'):
                # evidence_io is a checkout compatibility wrapper. This minimal
                # repository needs its implementation, not a dangling wrapper.
                source = (Path(sys.modules[native.require.__module__].__file__) if name == 'evidence_io.py'
                          else Path(native.__file__))
                shutil.copyfile(source, scripts / name)
            (site / 'receipt_fixture_dependency.py').write_text('VALUE = 42\n')
            (site / 'unsafe.pth').write_text('import sys; sys.exit("site hook executed")\n')
            (tests / 'test_discovery_fixture.py').write_text(
                'import unittest\nfrom receipt_fixture_dependency import VALUE\n'
                'assert VALUE == 42\n'
                'def setUpModule():\n    raise AssertionError("fixture must not execute")\n'
                'class Definition(unittest.TestCase):\n'
                '    def test_case(self):\n        raise AssertionError("test must not execute")\n')
            identity = {'python': sys.version, 'executable': '/untrusted/never-execute',
                        'distribution_metadata': [str(site / 'fixture.dist-info/METADATA')]}
            with patch.object(native, 'verify_environment') as checked, \
                    patch.dict(os.environ, {'PYTHONPATH': '/untrusted/python', 'PYTHONHOME': '/untrusted/home'}):
                self.assertEqual(native.discover(repo, identity=identity),
                    ['test_discovery_fixture.Definition.test_case'])
                checked.assert_called_once_with(identity, repo)
                (site / 'receipt_fixture_dependency.py').unlink()
                with self.assertRaisesRegex(ValueError, 'Native discovery failed:.*'):
                    native.discover(repo, identity=identity)
            with patch.object(native, 'verify_environment', side_effect=ValueError('metadata changed')), \
                    patch.object(native.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'metadata changed'):
                    native.discover(repo, identity=identity)
                run.assert_not_called()
            with patch.object(native, 'verify_environment'), patch.object(native.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'same Python version'):
                    native.discover(repo, identity=dict(identity, python='different'))
                run.assert_not_called()

    def test_discovery_selects_current_receipt_environment_and_rejects_source_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, parent = root / 'repo', root / 'receipts'
            (repo / 'harness').mkdir(parents=True)
            identity = {'python': sys.version, 'distribution_metadata': []}
            for number in (1, 2):
                folder = parent / ('attempt-' + str(number))
                folder.mkdir(parents=True)
                save(folder / 'attempt.json', {'checkout': str(repo), 'started_epoch': number,
                    'source_before': native.sources(repo), 'environment': dict(identity, number=number)})
            with patch.object(native, 'receipt_parent', return_value=parent), \
                    patch.object(native, 'verify_environment') as checked, \
                    patch.object(native.subprocess, 'run', return_value=subprocess.CompletedProcess(
                        [], 0, '["fixture.test"]', '')):
                self.assertEqual(native.discover(repo), ['fixture.test'])
                self.assertEqual(checked.call_args.args[0]['number'], 2)
                (repo / 'harness/changed.py').write_text('# source drift\n')
                checked.reset_mock()
                with self.assertRaisesRegex(ValueError, 'source drift'):
                    native.discover(repo)
                checked.assert_not_called()

    def test_installed_environment_excludes_ambient_python_and_source_venv(self):
        from product_journey import child_environment
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'source-venv').mkdir()
            (root / 'source-venv/pyvenv.cfg').write_text('fixture')
            parent = {'HOME': str(root / 'home'), 'CODEX_HOME': str(root / 'existing-login-reference'),
                'PATH': str(root / 'source-venv/bin') + ':/usr/bin:/bin',
                'PYTHONPATH': '/contaminated/source', 'PYTHONHOME': '/contaminated/python',
                'BASH_ENV': '/untrusted/startup', 'NODE_OPTIONS': '--require=/untrusted.js',
                'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/synthetic/user-bus'}
            env = child_environment(parent, root / 'installed')
            self.assertTrue(env['PATH'].startswith(str(root / 'installed/venv/bin')))
            self.assertNotIn('source-venv', env['PATH'])
            self.assertEqual(env['CODEX_HOME'], parent['CODEX_HOME'])
            self.assertEqual(env['DBUS_SESSION_BUS_ADDRESS'], parent['DBUS_SESSION_BUS_ADDRESS'])
            for name in ('PYTHONPATH', 'PYTHONHOME', 'BASH_ENV', 'NODE_OPTIONS'):
                self.assertNotIn(name, env)

    def test_runtime_snapshot_records_actual_imports_without_environment_values(self):
        from ptw.runtime_identity import snapshot
        with patch.dict(os.environ, {'UNRELATED_SECRET_FIXTURE': 'must-not-be-recorded', 'PYTHONPATH': '/fixture'}):
            value = snapshot('launcher')
        self.assertEqual(value['pid'], os.getpid())
        self.assertEqual(value['runtime_sha256'], gate.tree(gate.REPO / 'harness'))
        self.assertTrue(value['pythonpath_present'])
        self.assertNotIn('must-not-be-recorded', json.dumps(value))
        self.assertEqual(Path(value['imported_ptw_modules']['ptw']), gate.REPO / 'harness/ptw/__init__.py')

    def test_collector_hashes_vendored_metadata_without_counting_it_as_installed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            own = Path('fixture-1.0.dist-info/METADATA')
            vendor = Path('fixture/_vendor/bundled-9.dist-info/METADATA')
            for name, text in ((own, 'Name: fixture\nVersion: 1.0\n'),
                               (vendor, 'Name: bundled\nVersion: 9\n')):
                (root / name).parent.mkdir(parents=True)
                (root / name).write_text(text)
            distribution = SimpleNamespace(metadata={'Name': 'fixture'}, version='1.0',
                files=[own, vendor], locate_file=lambda item: root / item)
            with patch.object(native.importlib.metadata, 'distributions', return_value=[distribution]):
                identity = native.environment()
            self.assertEqual(identity['distributions'], [['fixture', '1.0']])
            self.assertEqual(identity['distribution_metadata'], [str(root / own)])
            self.assertEqual(identity['metadata_sha256'],
                             {str(root / name): digest(root / name) for name in (own, vendor)})

    def test_retained_source_environment_is_rehashed_without_executing_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, prefix = root / 'repo', root / 'venv'
            (repo / 'harness').mkdir(parents=True)
            (repo / 'harness/requirements.lock').write_text('fixture-dependency==1.0\n')
            executable = prefix / 'bin/python'
            executable.parent.mkdir(parents=True)
            executable.write_text('synthetic non-executable file; validator must never run this')
            site = prefix / 'lib/site-packages'
            hashes = {}
            distributions = [['fixture-dependency', '1.0'], ['permission-to-work-harness', '0.5.0']]
            for name, version in distributions:
                path = site / (name + '.dist-info') / 'METADATA'
                path.parent.mkdir(parents=True)
                path.write_text('Name: ' + name + '\nVersion: ' + version + '\n')
                hashes[str(path)] = digest(path)
            identity = dict(host=platform.node(), platform=platform.platform(), native_enabled=True,
                ptw_file=str(repo / 'harness/ptw/__init__.py'), prefix=str(prefix),
                executable=str(executable), interpreter_sha256=digest(executable),
                metadata_sha256=hashes, distributions=distributions,
                distribution_metadata=sorted(hashes),
                tools={n: {'path': str(executable), 'sha256': digest(executable)} for n in
                       ('nono', 'bwrap', 'systemd-run', 'systemctl', 'uv', 'node', 'npm', 'codex')})
            native.verify_environment(identity, repo)
            vendor = site / 'fixture_dependency/_vendor/bundled.dist-info/METADATA'
            vendor.parent.mkdir(parents=True)
            vendor.write_text('Name: bundled\nVersion: 9\n')
            hashes[str(vendor)] = digest(vendor)
            native.verify_environment(identity, repo)
            vendor.write_text('Name: bundled\nVersion: 10\n')
            with self.assertRaisesRegex(ValueError, 'metadata changed'):
                native.verify_environment(identity, repo)
            hashes[str(vendor)] = digest(vendor)
            for key, value in (('tools', {}), ('ptw_file', '/other/ptw/__init__.py'),
                               ('native_enabled', False), ('interpreter_sha256', '0' * 64),
                               ('distribution_metadata', []),
                               ('distribution_metadata', identity['distribution_metadata'] * 2),
                               ('distribution_metadata', [str(site / 'unhashed.dist-info/METADATA')]),
                               ('distributions', distributions[:-1])):
                with self.subTest(key=key), self.assertRaises(ValueError):
                    native.verify_environment(dict(identity, **{key: value}), repo)
            added = site / 'unexpected.dist-info/METADATA'
            added.parent.mkdir()
            added.write_text('Name: unexpected\nVersion: 1\n')
            with self.assertRaisesRegex(ValueError, 'inventory incomplete'):
                native.verify_environment(identity, repo)
            added.unlink()
            Path(next(iter(hashes))).write_text('Name: fixture-dependency\nVersion: 2.0\n')
            with self.assertRaisesRegex(ValueError, 'metadata changed'):
                native.verify_environment(identity, repo)


@unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'requires manager Linux PTYs/user services')
class NativeEvidenceTests(unittest.TestCase):
    def setUp(self):
        # Retain all native attempts, including failures, outside the checkout.
        self.root = Path(tempfile.mkdtemp(prefix='ptw-evidence-native-'))
        print('PRODUCT_GATE_NATIVE_EVIDENCE ' + str(self.root), flush=True)

    def test_terminal_interrupt_ignores_launcher_signal_state(self):
        # Deterministic terminal fixture, not a model or installed-user journey.
        # Background launchers can ignore/block SIGINT across fork and exec.
        save(self.root / 'source.json', native.sources())
        script = '''import json, os, signal, sys
print('STATE=' + json.dumps({
    'ignored': signal.getsignal(signal.SIGINT) == signal.SIG_IGN,
    'blocked': signal.SIGINT in signal.pthread_sigmask(signal.SIG_BLOCK, []),
    'foreground': os.tcgetpgrp(0) == os.getpgrp()}), flush=True)
try:
    input('READY: ')
except KeyboardInterrupt:
    print('CANCELLED', flush=True)
    sys.exit(130)
sys.exit(23)
'''
        for label, ignored, blocked in (('normal', False, False), ('ignored', True, False),
                                        ('blocked', False, True), ('both', True, True)):
            with self.subTest(launcher=label):
                terminal = None
                handler = signal.getsignal(signal.SIGINT)
                mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
                try:
                    signal.signal(signal.SIGINT, signal.SIG_IGN if ignored else signal.default_int_handler)
                    expected_mask = (mask - {signal.SIGINT}) | ({signal.SIGINT} if blocked else set())
                    signal.pthread_sigmask(signal.SIG_SETMASK, expected_mask)
                    expected_handler = signal.getsignal(signal.SIGINT)
                    try:
                        terminal = Terminal([sys.executable, '-I', '-B', '-c', script], self.root / label)
                        self.assertEqual(signal.getsignal(signal.SIGINT), expected_handler)
                        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, []), expected_mask)
                    finally:
                        signal.signal(signal.SIGINT, handler)
                        signal.pthread_sigmask(signal.SIG_SETMASK, mask)
                    terminal.expect('READY: ', 10)
                    terminal.inputs.append({'control': 'interrupt',
                                            'seconds': time.monotonic() - terminal.started})
                    terminal._save_inputs()
                    os.write(terminal.fd, b'\x03')
                    terminal.wait(lambda: terminal.exited, 3, 'real Ctrl-C exit')
                    row = next(s for s in terminal.text.splitlines() if s.startswith('STATE='))
                    self.assertEqual(json.loads(row[6:]),
                                     {'ignored': False, 'blocked': False, 'foreground': True})
                    self.assertIn('CANCELLED', terminal.text)
                    self.assertNotIn('Traceback', terminal.text)
                finally:
                    if terminal is not None:
                        code = terminal.close(graceful=False)
                self.assertEqual(code, 130)
                self.assertEqual(load(terminal.folder / 'inputs.json'), terminal.inputs)
                self.assertEqual(load(terminal.folder / 'exit.json')['exit_code'], 130)

    def test_bracketed_paste_submits_long_multiline_prompt_once(self):
        # A deterministic protocol receiver, never a model trajectory or UI proof.
        script = '''import hashlib, os, select, tty
tty.setraw(0)
os.write(1, b'\\x1b[?2004hREADY')
data = b''
while b'\\x1b[201~' not in data:
    data += os.read(0, 7)
assert data.startswith(b'\\x1b[200~'), repr(data[:20])
body, suffix = data[6:].split(b'\\x1b[201~', 1)
assert (suffix or os.read(0, 1)) == b'\\r'
assert not select.select([0], [], [], .4)[0], 'duplicate submission'
os.write(1, b'RECEIVED=' + hashlib.sha256(body).hexdigest().encode())
'''
        payload = 'A multiline café prompt\n' + 'complete input ' * 500
        terminal = Terminal([sys.executable, '-I', '-B', '-c', script], self.root / 'paste')
        try:
            terminal.expect('READY', 10)
            terminal.paste(payload)
            terminal.wait(lambda: terminal.exited, 10)
            import hashlib
            self.assertIn('RECEIVED=' + hashlib.sha256(payload.encode()).hexdigest(), terminal.text)
        finally:
            code = terminal.close(graceful=False)
        self.assertEqual(code, 0)
        rows = load(terminal.folder / 'inputs.json')
        self.assertEqual([row['text'] for row in rows], [payload])
        self.assertEqual(rows[0]['mode'], 'bracketed-paste')

    def test_javascript_oracle_accepts_spec_and_rejects_broken_renderer(self):
        from product_projects import JS_ORACLE
        from shutil import which
        node = which('node')
        self.assertIsNotNone(node, 'Node is part of the declared developer profile')
        (self.root / 'src').mkdir()
        (self.root / 'tests').mkdir()
        oracle = self.root / 'tests/oracle.test.mjs'
        oracle.write_text(JS_ORACLE.replace('APPLICATION', '../src/site.mjs'))
        app = self.root / 'src/site.mjs'
        valid = '''export function render(items, category='all') {
          if (!Array.isArray(items)) throw new TypeError();
          for (const i of items) if (!i || typeof i.title !== 'string' || typeof i.category !== 'string') throw new TypeError();
          const escape = x => x.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');
          return '<ul>' + items.filter(i => category === 'all' || i.category === category)
            .map(i => '<li>' + escape(i.title) + '</li>').join('') + '</ul>';
        }'''
        for label, body, status in [('correct', valid, 0), ('incorrect',
                "export function render() { return '<ul></ul>'; }", 1)]:
            app.write_text(body)
            result = capture([node, '--test', oracle], self.root / label, cwd=self.root)
            self.assertEqual(result.returncode, status)
            self.assertIn(b'IndependentOracle', result.stdout, result.stderr.decode(errors='replace'))
            self.assertIn(b'# tests 4', result.stdout)

    def test_installed_live_first_journey(self):
        self.live_journey('new-python')

    def test_compiled_namespace_effects_are_observed_after_setup(self):
        from shutil import copyfile, which
        from native_boundary import namespace_probe
        from product_security import Probe
        private, outside = self.root / 'repo/private', self.root / 'outside'
        private.parent.mkdir()
        private.write_text('SYNTHETIC PRIVATE\n')
        outside.write_text('SYNTHETIC OUTSIDE\n')
        before = {str(p): digest(p) for p in (private, outside)}
        # Match installed Codex: the shell bind creates the shared ancestor of
        # outside, but not the private fixture's parent, in the new tmpfs.
        shell_file = self.root / 'installation/bin/sh'
        shell_file.parent.mkdir(parents=True)
        copyfile('/bin/sh', shell_file)
        shell, executable = str(shell_file), '/usr/bin/true'
        command = [which('bwrap'), '--as-pid-1', '--new-session', '--die-with-parent',
            '--tmpfs', '/', '--dev', '/dev', '--ro-bind', shell, shell,
            '--unshare-user', '--unshare-pid', '--unshare-ipc', '--unshare-net',
            '--proc', '/proc', '--cap-drop', 'ALL', '--argv0', 'synthetic-probe', '--', executable]
        probe = Probe(self.root, self.root / 'probe', 'synthetic-native-boundary', native.sources(),
                      fixture='synthetic standalone namespace check; not product journey evidence')
        try:
            namespace_probe(probe, command, shell, list(before), dict(os.environ), str(self.root))
            self.assertEqual(before, {str(p): digest(p) for p in (private, outside)})
            observations = [load(artifact(self.root, ref)) for ref in probe.responses]
            measured = next(r['value'] for r in observations
                            if r['label'] == 'post-setup namespace observations')['targets']
            self.assertTrue(measured[str(outside)]['create']['succeeded'])
            self.assertEqual(measured[str(private)]['create'], {'succeeded': False, 'errno': 2})
            probe.finish()
        except BaseException as exc:
            probe.persist(exc)
            raise

    def test_independent_native_lifecycle_security_matrix(self):
        from product_acceptance import candidate
        from product_journey import child_environment
        from product_lifecycle import LIFECYCLE_IDS, lifecycle_security
        started = time.time()
        source = native.sources()
        release = candidate(self.root)
        # Development source check; full product invokes this same driver with
        # the retained fresh wheel interpreter and command, never editable source.
        rows = lifecycle_security(self.root, source, release, str(Path(sys.executable).parent / 'ptw'),
                                  child_environment(os.environ))
        report = {'source_sha256': source, 'started_epoch': started, 'ended_epoch': time.time()}
        self.assertEqual({r['id'] for r in rows}, set(LIFECYCLE_IDS))
        for row in rows:
            gate.security_check(self.root, row, report)

    def test_independent_native_package_security_matrix(self):
        from product_security import PACKAGE_IDS, package_security
        started = time.time()
        source = native.sources()
        rows = package_security(self.root, source)
        report = {'source_sha256': source, 'started_epoch': started, 'ended_epoch': time.time()}
        self.assertEqual({r['id'] for r in rows}, set(PACKAGE_IDS))
        for row in rows:
            gate.security_check(self.root, row, report)
        self.assertTrue(load(self.root / 'package-security.json')['complete'])

    def test_independent_native_scope_security_matrix(self):
        from product_scope import SCOPE_IDS, scope_security
        started = time.time()
        source = native.sources()
        rows = scope_security(self.root, source)
        report = {'source_sha256': source, 'started_epoch': started, 'ended_epoch': time.time()}
        self.assertEqual({r['id'] for r in rows}, set(SCOPE_IDS))
        for row in rows:
            gate.security_check(self.root, row, report)
        self.assertTrue(load(self.root / 'scope-security.json')['complete'])

    def test_independent_native_git_evidence(self):
        from product_daily_acceptance import git_evidence
        source, started = native.sources(), time.time()
        row = git_evidence(self.root, source)
        self.assertEqual(row['id'], 'local-git')
        gate.local_git_check(self.root, row, {'source_sha256': source,
                            'started_epoch': started, 'ended_epoch': time.time()})
        self.assertEqual(load(self.root / 'local-git.json'), row)
        for decision in ('approval', 'rejection'):
            self.assertTrue((self.root / 'git-fixture' / decision / 'terminal.txt').stat().st_size)

    def test_installed_live_node_journey(self):
        self.live_journey('existing-node')

    def test_installed_live_typescript_journey(self):
        self.live_journey('new-typescript')

    def test_installed_live_mixed_journey(self):
        self.live_journey('existing-mixed-python-node')

    def live_journey(self, case):
        from product_acceptance import candidate, installed_journey
        release = candidate(self.root)
        row = installed_journey(self.root, release, case)
        self.assertTrue(row['passed'], 'Full installer-to-ready time exceeds 30 seconds; inspect retained timing')
        self.assertTrue(row['protected_resume'])
        self.assertTrue(row['dependency_admitted'])
        self.assertEqual(row['build_or_test_exit_code'], 0)
        config = load(self.root / case / 'driver.json')
        report = {'source_sha256': native.sources(), 'runtime_sha256': gate.tree(gate.REPO / 'harness'),
            'distribution_inputs_sha256': gate.inputs(gate.REPO),
            'real_model': 'gpt-5.6-sol', 'reasoning_effort': 'low',
            'started_epoch': load(self.root / case / 'start.json')['started_epoch'], 'ended_epoch': time.time()}
        gate.journey(self.root, row, report, gate.REPO)
        if case == 'new-python':
            receipt = load(self.root / 'resume-security.json')
            self.assertTrue(receipt['complete'])
            gate.security_check(self.root, receipt['security_checks'][0], report)
        self.assertEqual(config['source_sha256'], report['source_sha256'])

    def test_completed_turn_accepts_only_clean_finish(self):
        from product_journey import settle_work
        result = {'exit_code': 0, 'stopped': False, 'reason': None,
                  'closure': {'closed': True, 'outcome': 'finish'}}
        variants = [result, {**result, 'stopped': True}, {**result, 'exit_code': 1},
                    {**result, 'closure': {'closed': True, 'outcome': 'surrender'}},
                    {**result, 'closure': {'closed': False, 'outcome': 'finish'}}, None]
        for index, value in enumerate(variants):
            for code in (0, 1):
                with self.subTest(result=value, terminal_exit=code):
                    folder = self.root / ('finish-' + str(index) + '-' + str(code))
                    terminal = Terminal([sys.executable, '-I', '-B', '-c',
                        'print("Deterministic completed-turn fixture",flush=True); exit(' + str(code) + ')'], folder)
                    path = folder / 'result.json'
                    if value is not None:
                        save(path, value)
                    try:
                        if index == 0 and code == 0:
                            settle_work(terminal, path)
                            self.assertTrue(terminal.closed)
                        else:
                            with self.assertRaises((ValueError, OSError)):
                                settle_work(terminal, path)
                    finally:
                        terminal.close(graceful=False)
                    self.assertEqual(load(folder / 'inputs.json'), [])

    def test_failure_cleanup_does_not_accept_prompt_and_clean_quit_still_works(self):
        sentinel = self.root / 'unexpected-input'
        # Deterministic terminal fixture, never a Codex/model trajectory.
        script = ('import pathlib,sys; print("Update prompt fixture",flush=True); '
                  'input(); pathlib.Path(sys.argv[1]).write_text("unexpected approval")')
        terminal = Terminal([sys.executable, '-I', '-B', '-c', script, sentinel],
                            self.root / 'unknown-prompt')
        try:
            terminal.expect('Update prompt fixture', 10)
        finally:
            code = terminal.close(graceful=False)
        self.assertEqual(code, -signal.SIGTERM)
        self.assertFalse(sentinel.exists())
        self.assertEqual(load(terminal.folder / 'inputs.json'), [])
        self.assertIn('Update prompt fixture', (terminal.folder / 'terminal.txt').read_text())
        self.assertFalse(Path('/proc', str(terminal.pid)).exists())
        terminal = Terminal([sys.executable, '-I', '-B', '-c',
            'print("Ready fixture",flush=True); exit(0 if input() == "/quit" else 1)'],
            self.root / 'known-ready')
        try:
            terminal.expect('Ready fixture', 10)
            self.assertEqual(terminal.close(), 0)
        finally:
            terminal.close(graceful=False)
        self.assertEqual([row['text'] for row in load(terminal.folder / 'inputs.json')], ['/quit'])

    def test_terminal_replacement_excludes_contaminated_parent_and_merge_stays_compatible(self):
        script = ('import json,os; print("ENVIRONMENT="+json.dumps('
                  '{k:os.environ.get(k) for k in ("PYTHONPATH","PYTHONHOME","PTW_FIXTURE","TERM")}))')
        with patch.dict(os.environ, {'PYTHONPATH': '/synthetic/editable-source',
                                    'PYTHONHOME': '/synthetic/python', 'PTW_FIXTURE': 'parent'}):
            for replace in (True, False):
                terminal = Terminal([sys.executable, '-I', '-B', '-c', script],
                    self.root / str(replace), env={'PTW_FIXTURE': 'explicit'},
                    cwd=self.root, replace_env=replace)
                try:
                    terminal.wait(lambda: terminal.exited, timeout=10)
                finally:
                    code = terminal.close()
                self.assertEqual(code, 0)
                row = next(s for s in terminal.text.splitlines() if s.startswith('ENVIRONMENT='))
                value = json.loads(row.split('=', 1)[1])
                self.assertEqual(value['PYTHONPATH'], None if replace else '/synthetic/editable-source')
                self.assertEqual(value['PYTHONHOME'], None if replace else '/synthetic/python')
                self.assertEqual(value['PTW_FIXTURE'], 'explicit')
                self.assertEqual(value['TERM'], 'xterm-256color')
                self.assertTrue((terminal.folder / 'terminal.txt').stat().st_size)

    def test_terminal_probe_retains_original_failure_and_timeout_output(self):
        from product_install_acceptance import terminal_output
        from product_install import InstallError
        with self.assertRaises(InstallError):
            terminal_output([sys.executable, '-I', '-B', '-c',
                'print("ORIGINAL_FAILURE",flush=True); exit(19)'], {}, self.root,
                evidence=self.root / 'failed')
        self.assertIn(b'ORIGINAL_FAILURE', (self.root / 'failed/terminal.txt').read_bytes())
        self.assertEqual(load(self.root / 'failed/process.json')['exit_code'], 19)
        with self.assertRaises(subprocess.TimeoutExpired):
            terminal_output([sys.executable, '-I', '-B', '-c',
                'import time; print("ORIGINAL_PARTIAL",flush=True); time.sleep(60)'], {}, self.root,
                timeout=.5, evidence=self.root / 'timeout')
        self.assertIn(b'ORIGINAL_PARTIAL', (self.root / 'timeout/terminal.txt').read_bytes())
        self.assertFalse(load(self.root / 'timeout/process.json')['complete'])

    def test_native_receipt_identity_matches_actual_detached_source_import(self):
        identity = native.environment()
        save(self.root / 'source-environment.json', identity)
        native.verify_environment(identity, native.REPO)
        script = ('import json,ptw,sys; from pathlib import Path; '
                  'print(json.dumps({"ptw_file":str(Path(ptw.__file__).resolve()),'
                  '"prefix":sys.prefix,"executable":sys.executable}))')
        result = capture(['systemd-run', '--user', '--wait', '--pipe', '--collect', '--quiet',
            '--unit=ptw-receipt-' + uuid.uuid4().hex, sys.executable, '-B', '-c', script],
            self.root / 'detached', cwd=self.root)
        self.assertEqual(result.returncode, 0, 'Inspect private detached receipt')
        actual = json.loads(result.stdout)
        self.assertEqual(actual['ptw_file'], str(native.REPO / 'harness/ptw/__init__.py'))
        for key in ('ptw_file', 'prefix', 'executable'):
            self.assertEqual(actual[key], identity[key])

    def test_bare_consumer_discovers_exact_source_suite_without_running_it(self):
        identity = native.environment()
        save(self.root / 'source-environment.json', identity)
        # Reproduce the manager product consumer: base Python, no source venv,
        # site packages or editable hooks. Only the discovery child gets the
        # verified dependencies. No fixtures, sockets or model turns execute.
        script = ('import sys,json; sys.path.insert(0,sys.argv[1]); '
                  'from native_receipt import discover; from evidence_io import load; '
                  'print(json.dumps(discover(sys.argv[2],identity=load(sys.argv[3]))))')
        result = capture([sys._base_executable, '-I', '-S', '-B', '-c', script,
                          native.REPO / 'harness/scripts', native.REPO,
                          self.root / 'source-environment.json'], self.root / 'discovery', cwd=self.root)
        self.assertEqual(result.returncode, 0, 'Inspect retained discovery stderr')
        self.assertEqual(json.loads(result.stdout), native.discovery_inventory(native.REPO))
