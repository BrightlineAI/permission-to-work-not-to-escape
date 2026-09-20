"""Mandatory fresh-wheel extension journeys, included in ordinary discovery.

Run on the isolated native Linux test host. Missing tools/services fail rather
than skip. Installed fixtures are separate from editable source regression.
"""
from pathlib import Path
import copy
import hashlib
import sys
import tempfile
import time
import unittest


class InstalledIdentityTests(unittest.TestCase):
    def test_recursive_data_stale_identity_and_source_injection_are_rejected(self):
        scripts = str(Path(__file__).resolve().parents[1] / 'scripts')
        if scripts not in sys.path:
            sys.path.insert(0, scripts)
        from product_safety_acceptance import verify_identity
        from product_gate import tree
        with tempfile.TemporaryDirectory(prefix='ptw-safety-identity-') as directory:
            installation = Path(directory)
            root = installation / 'site-packages/ptw'
            (root / 'sub').mkdir(parents=True)
            (root / '__init__.py').write_text('')
            data = root / 'sub/policy.json'
            data.write_text('{"version":1}')
            hashes = {'__init__.py': hashlib.sha256(b'').hexdigest()}
            runtime = tree(root.parent)
            value = {'path': str(root), 'prefix': str(installation), 'hashes': hashes,
                     'pythonpath_present': False, 'pythonhome_present': False,
                     'direct_url': {'archive_info': {}}, 'runtime_sha256': runtime}
            verify_identity(value, installation, hashes, runtime)
            for changes in ({'pythonpath_present': True}, {'pythonhome_present': True},
                            {'prefix': str(installation.parent)},
                            {'direct_url': {'dir_info': {'editable': True}}},
                            {'runtime_sha256': {}}):
                with self.subTest(changes=changes), self.assertRaises(AssertionError):
                    verify_identity({**value, **changes}, installation, hashes, runtime)
            # The measured record still matches: independently rehash disk.
            for content in ('{"version":2}', None):
                if content is None:
                    data.unlink()
                else:
                    data.write_text(content)
                with self.subTest(content=content), self.assertRaises(AssertionError):
                    verify_identity(copy.deepcopy(value), installation, hashes, runtime)


class SafetyEvidenceTests(unittest.TestCase):
    """Synthetic mutation tests: hashes alone cannot satisfy additive evidence."""
    def setUp(self):
        import test_product_gate as fixtures
        # Reuse its synthetic schema builder, never execute its tests or native
        # fixtures. Keeping the module import avoids duplicate test discovery.
        self.fixture = fixtures.ProductGateTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()

    def verify(self):
        from product_safety_evidence import verify
        f = self.fixture
        return verify(f.out, f.report, f.repo)

    def test_complete_and_missing_stale_forged_extension_are_distinguished(self):
        from evidence_io import load
        f = self.fixture
        self.assertTrue(f.verify()['passed'])
        ref = f.report['safety_extension']
        original = load(f.out / ref['path'])
        del f.report['safety_extension']
        with self.assertRaises(ValueError):
            self.verify()
        for changes in ({'schema': 0}, {'bindings': {}}, {'requirements': {}}, {'journeys': {}},
                        {'source_sha256': {}}, {'ended_epoch': time.time() - 86401},
                        {'candidate_record': f.report['journeys'][0]['functional_oracle']}):
            with self.subTest(changes=changes):
                f.report['safety_extension'] = f.write(ref['path'], {**original, **changes})
                with self.assertRaises(ValueError):
                    self.verify()

    def test_rehashed_physical_observations_and_terminal_forgery_are_rejected(self):
        from evidence_io import load, save, reference
        f = self.fixture
        extension_ref = f.report['safety_extension']
        extension = load(f.out / extension_ref['path'])
        journey_ref = extension['journeys']['new']
        journey_path = f.out / journey_ref['path']
        journey = load(journey_path)
        result_path = journey_path.parent / journey['result']['path']
        result = load(result_path)
        changes = [(0, 'outcomes.json', lambda v: v['observations'][1].update(physical_ref_exists=True)),
                   (1, 'composition.json', lambda v: v['observations'][1].update(application=[True, False, False])),
                   (2, 'observations.json', lambda v: v.update(violations=1)),
                   (4, 'observations.json', lambda v: v['observations'][0].update(stopped=False)),
                   (4, 'observations.json', lambda v: v['observations'][0].pop('stopped')),
                   (4, 'observations.json', lambda v: v['observations'][0].update(parent_exit_code=None)),
                   (4, 'observations.json', lambda v: v['observations'][0].update(descendant_state='S')),
                   (4, 'observations.json', lambda v: v['observations'][1].update(sentinel_after='456:1')),
                   (4, 'observations.json', lambda v: v['observations'][1].update(cgroup_events='removed')),
                   (5, 'threshold.json', lambda v: v.update(counts=[1, 1, 1])),
                   (5, 'aggregate-events.json', lambda v: v[2]['result'].update(level='warn')),
                   (6, 'query.json', lambda v: v['initial'].update(confirmed_stopped=True)),
                   (8, 'scope.json', lambda v: v.update(collector_requests=['unauthorized publication']))]
        for index, name, change in changes:
            changed = copy.deepcopy(result)
            row = changed['tests'][index]
            ref = next(r for r in row['originals'] if Path(r['path']).name == name)
            path = result_path.parent / ref['path']
            old = load(path)
            forged = copy.deepcopy(old)
            change(forged)
            save(path, forged)
            row['originals'][row['originals'].index(ref)] = reference(result_path.parent, path)
            save(result_path, changed)
            save(journey_path, {**journey, 'result': reference(journey_path.parent, result_path)})
            altered = copy.deepcopy(extension)
            altered['journeys']['new'] = reference(f.out, journey_path)
            f.report['safety_extension'] = f.write(extension_ref['path'], altered)
            with self.subTest(observation=name), self.assertRaises(ValueError):
                self.verify()
            save(path, old)
        # Original terminal bytes are required even with self-consistent claims.
        save(result_path, result)
        save(journey_path, journey)
        f.report['safety_extension'] = f.write(extension_ref['path'], extension)
        terminal_ref = next(r for r in result['tests'][0]['originals'] if r['path'].endswith('/benign/terminal.txt'))
        (result_path.parent / terminal_ref['path']).unlink()
        with self.assertRaises(ValueError):
            self.verify()

    def test_upgrade_requires_original_lifecycle_outcomes_and_stopped_backups(self):
        from evidence_io import load, save, reference
        import sqlite3
        f = self.fixture
        extension_ref = f.report['safety_extension']
        extension = load(f.out / extension_ref['path'])
        journey_path = f.out / extension['journeys']['upgrade']['path']
        journey = load(journey_path)
        result_path = journey_path.parent / journey['result']['path']
        result = load(result_path)

        def reject(changed):
            save(result_path, changed)
            save(journey_path, {**journey, 'result': reference(journey_path.parent, result_path)})
            altered = copy.deepcopy(extension)
            altered['journeys']['upgrade'] = reference(f.out, journey_path)
            f.report['safety_extension'] = f.write(extension_ref['path'], altered)
            with self.assertRaises(ValueError):
                self.verify()

        for index in range(4):
            changed = copy.deepcopy(result)
            changed['tests'][index]['originals'] = []
            with self.subTest(missing_originals=index):
                reject(changed)
        changes = [(0, 'outcomes.json', lambda v: v.update(legacy_write_error='succeeded')),
                   (0, 'rejected.json', lambda v: v.update(events=[])),
                   (1, 'adopted.json', lambda v: v['status'].update(violations=0)),
                   (1, 'migrated.json', lambda v: v['status'].update(package_sets=[])),
                   (1, 'outcomes.json', lambda v: v.update(stopped_registration_error='allowed')),
                   (1, 'migration-0.json', lambda v: v.update(sha256='0' * 64)),
                   (2, 'rolled-back.json', lambda v: v.update(schema_version=2)),
                   (2, 'outcomes.json', lambda v: v.update(failure='')),
                   (3, 'useful.json', lambda v: v.update(physical_content='missing'))]
        # Native backups have random names; these are the explicitly synthetic
        # gate fixtures, whose original records are rehashed after each forgery.
        for index, name, change in changes:
            changed = copy.deepcopy(result)
            row = changed['tests'][index]
            ref = next(r for r in row['originals'] if Path(r['path']).name == name)
            path = result_path.parent / ref['path']
            previous = path.read_bytes()
            value = load(path)
            change(value)
            save(path, value)
            row['originals'][row['originals'].index(ref)] = reference(result_path.parent, path)
            with self.subTest(contradiction=name, case=index):
                reject(changed)
            path.write_bytes(previous)
        changed = copy.deepcopy(result)
        row = changed['tests'][2]
        backups = [r for r in row['originals'] if r['path'].endswith('.sqlite3')]
        row['originals'][row['originals'].index(backups[1])] = backups[0]
        reject(changed)
        # Matching hashes cannot turn a live backup into a stopped one.
        changed = copy.deepcopy(result)
        row = changed['tests'][0]
        ref = next(r for r in row['originals'] if r['path'].endswith('.sqlite3'))
        path = result_path.parent / ref['path']
        with sqlite3.connect(path) as db:
            db.execute('UPDATE projects SET stopped=0')
        row['originals'][row['originals'].index(ref)] = reference(result_path.parent, path)
        receipt = next(r for r in row['originals'] if Path(r['path']).name == path.with_suffix('.json').name)
        receipt_path = result_path.parent / receipt['path']
        save(receipt_path, {**load(receipt_path), 'sha256': reference(result_path.parent, path)['sha256']})
        row['originals'][row['originals'].index(receipt)] = reference(result_path.parent, receipt_path)
        reject(changed)

    def test_missing_contract_stale_guide_and_substituted_candidate_wheel_rejected(self):
        from product_install import archive_files, sha, release_data_path
        from build_product_release import deterministic_tar
        from product_safety_evidence import candidate_payload, CONTRACTS
        from evidence_io import load
        import json
        f = self.fixture
        candidate = load(f.out / f.report['candidate_record']['path'])
        path = f.out / candidate['archive']['path']
        original = archive_files(path.read_bytes())
        for name in (*CONTRACTS, 'PROJECT-SAFETY-SCENARIOS.md', 'permission_to_work_harness-0.5.0-py3-none-any.whl'):
            files = dict(original)
            manifest = json.loads(files.pop('release.json'))
            import io, zipfile
            wheel = io.BytesIO()
            wheel_name = 'permission_to_work_harness-0.5.0-py3-none-any.whl'
            target = release_data_path(name)
            with zipfile.ZipFile(io.BytesIO(files[wheel_name])) as old, zipfile.ZipFile(wheel, 'w') as package:
                for member in old.namelist():
                    if member == target and name in CONTRACTS:
                        continue
                    package.writestr(member, b'substituted' if name.endswith('.whl') or member == target
                                     else old.read(member))
            files[wheel_name] = wheel.getvalue()
            manifest['files'] = {n: sha(v) for n, v in files.items()}
            files['release.json'] = json.dumps(manifest).encode()
            path.write_bytes(deterministic_tar(files))
            with self.subTest(name=name), self.assertRaises(ValueError):
                candidate_payload(path, f.repo, f.runtime)

    def test_semantic_unavailability_cannot_be_promoted_and_native_cases_cannot_disappear(self):
        from evidence_io import load, save, reference
        import product_safety_evidence as safety
        f = self.fixture
        ref = f.report['safety_extension']
        value = load(f.out / ref['path'])
        path = f.out / value['semantic_record']['path']
        semantic = load(path)
        save(path, {**semantic, 'live_calls': 16, 'status': 'passed'})
        value['semantic_record'] = reference(f.out, path)
        f.report['safety_extension'] = f.write(ref['path'], value)
        with self.assertRaises(ValueError):
            self.verify()
        inventory = [p + 'case' for prefixes in safety.COVERAGE.values() for p in prefixes]
        for selected in ([], inventory, [n for n in set(inventory) if not n.startswith('test_product_incident_controls.')]):
            with self.assertRaises(ValueError):
                safety.coverage(selected, {}, {}, {}, {})

    def test_public_candidate_uses_the_same_additive_gate_and_exact_bindings(self):
        from evidence_io import digest, load, reference
        from product_gate import RELEASES, requirement_evidence
        f = self.fixture
        ref = f.report['candidate_record']
        candidate = load(f.out / ref['path'])
        archive = f.out / 'ptw-0.5.0-linux-x86_64.tar.gz'
        archive.write_bytes((f.out / candidate['archive']['path']).read_bytes())
        bootstrap = f.out / candidate['bootstrap']['path']
        sums = f.out / 'SHA256SUMS'
        sums.write_text(digest(archive) + '  ' + archive.name + '\n' + digest(bootstrap) + '  install.sh\n')
        downloads = [f.write(p.name + '.download.json', {'complete': True,
            'url': RELEASES + 'ptw-v0.5.0/' + p.name, 'artifact': reference(f.out, p)})
            for p in (sums, bootstrap, archive)]
        candidate.update(origin='public-release', release_tag='ptw-v0.5.0', downloads=downloads,
                         archive=reference(f.out, archive), provenance=reference(f.out, sums))
        f.report['candidate_record'] = f.write(ref['path'], candidate)
        # Correctly rebind all synthetic records to the exact public candidate.
        extension_ref = f.report['safety_extension']
        extension = load(f.out / extension_ref['path'])
        extension['candidate_record'] = f.report['candidate_record']
        for item in extension['requirements'].values():
            item['candidate_record'] = f.report['candidate_record']
        f.report['safety_extension'] = f.write(extension_ref['path'], extension)
        with self.assertRaisesRegex(ValueError, 'substituted demo candidate'):
            f.verify()
        demo_ref = f.report['demo_evidence']
        demo = load(f.out / demo_ref['path'])
        demo['candidate_record'] = f.report['candidate_record']
        f.report['demo_evidence'] = f.write(demo_ref['path'], demo)
        for name, evidence in requirement_evidence(f.report).items():
            item = f.report['requirements'][name]
            old = item['records'][0]
            value = load(f.out / old['path'])
            item['records'] = [f.write(old['path'], {**value, 'evidence': evidence})]
        self.assertTrue(f.verify()['passed'])
        del f.report['safety_extension']
        with self.assertRaises(ValueError):
            f.verify()


class InstalledSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scripts = str(Path(__file__).resolve().parents[1] / 'scripts')
        if scripts not in sys.path:
            sys.path.insert(0, scripts)
        from product_ecosystems_acceptance import build_test_wheel
        cls.evidence = Path(tempfile.mkdtemp(prefix='ptw-installed-safety-'))
        print('SAFETY_EVIDENCE=' + str(cls.evidence), flush=True)
        # Keep the build, failed steps, installs and private original receipts.
        cls.wheel, cls.hashes = build_test_wheel(cls.evidence / 'build')

    def journey(self, mode):
        from product_safety_acceptance import installed_case
        from product_safety_evidence import installed_journey
        from evidence_io import digest, reference
        from product_gate import tree, inputs
        import native_receipt
        repo = Path(__file__).resolve().parents[2]
        report = {'source_sha256': native_receipt.sources(repo), 'runtime_sha256': tree(repo / 'harness'),
                  'distribution_inputs_sha256': inputs(repo), 'started_epoch': time.time()}
        result = installed_case(self.evidence / mode, mode, self.wheel, self.hashes)
        self.assertTrue(result['passed'])
        self.assertEqual((result['failures'], result['errors'], result['skipped']), (0, 0, 0))
        self.assertFalse(result['checkout_imported'])
        report['ended_epoch'] = time.time()
        installed_journey(self.evidence, reference(self.evidence, self.evidence / mode / 'evidence.json'),
                          mode, report, repo, digest(self.wheel))

    def test_new_project_installed_review_and_incidents(self):
        self.journey('new')

    def test_existing_project_installed_review_and_incidents(self):
        self.journey('existing')

    def test_installed_upgrade_mismatch_and_rollback(self):
        self.journey('upgrade')
