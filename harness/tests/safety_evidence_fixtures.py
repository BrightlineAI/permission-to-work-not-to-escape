"""Synthetic validator inputs only. Never native or semantic acceptance evidence."""
import io
import copy
import json
from pathlib import Path
import shutil
import sqlite3
import unittest
import zipfile

from evidence_io import digest, load, reference, save
from product_install import SAFETY_FILES, RELEASE_DATA, DEMO_FILES, release_data_path, sha
from product_safety_acceptance import NATIVE, LIFECYCLE
import product_safety_evidence as safety


def prepare(repo, source):
    for name in SAFETY_FILES.values():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, path)
    for name, original in RELEASE_DATA.items():
        path = repo / 'harness' / release_data_path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(repo / original, path)
    for name in ['demo.py', *['demo_support/' + n + '.py' for n in DEMO_FILES]]:
        path = repo / 'harness/ptw' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('# Synthetic packaging fixture, never executable proof\n')


def archive(repo):
    from build_product_release import deterministic_tar
    wheel = io.BytesIO()
    with zipfile.ZipFile(wheel, 'w') as package:
        for path in sorted((repo / 'harness/ptw').rglob('*')):
            if path.is_file():
                package.writestr(str(path.relative_to(repo / 'harness')), path.read_bytes())
    files = {}
    files.update({'permission_to_work_harness-0.5.0-py3-none-any.whl': wheel.getvalue(),
                  'requirements.lock': (repo / 'harness/requirements.lock').read_bytes()})
    files.update({n: b'SYNTHETIC VALIDATOR FIXTURE' for n in
                  ('product_install.py', 'package.json', 'package-lock.json', 'INSTALL.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md')})
    import json
    files['release.json'] = json.dumps({'format': 1, 'version': '0.5.0',
                                       'files': {n: sha(v) for n, v in files.items()}}).encode()
    return deterministic_tar(files)


def suite():
    from product_demo_evidence import MODULES
    class Synthetic(unittest.TestCase):
        def __init__(self, name):
            super().__init__()
            self.name = name

        def id(self):
            return self.name

        def runTest(self):
            self.assertEqual(1, 1, 'Synthetic schema callback, never product proof')
    names = {p + 'synthetic_validator_fixture' for prefixes in safety.COVERAGE.values() for p in prefixes}
    names.update(m + '.synthetic_validator_fixture' for m in MODULES)
    names.update('test_product_safety_acceptance.InstalledSafetyTests.test_' + n for n in (
        'new_project_installed_review_and_incidents', 'existing_project_installed_review_and_incidents',
        'installed_upgrade_mismatch_and_rollback'))
    return unittest.TestSuite(Synthetic(n) for n in sorted(names))


def demos(f):
    """Synthetic envelope only; physical validators have their own native tests."""
    from unittest.mock import patch
    import product_demo_evidence as evidence
    f.enterContext(patch.object(evidence, 'verify_originals', return_value=None))
    installed_ref, audit, launcher = evidence.installation(f.out, f.report)
    rows = {}
    for name in evidence.DEMOS:
        out = f.out / 'demos' / name
        result = f.write('demos/' + name + '/result.json', {
            'demo': name, 'complete': True,
            'source': {'runtime_sha256': f.runtime, 'maintained_sha256': f.runtime,
                       'distribution_inputs_sha256': f.inputs},
            'installed': {'path': str(Path(audit['module_root']) / 'ptw'),
                          'prefix': launcher['prefix'], 'runtime_sha256': f.runtime,
                          'dependency_versions': audit['dependency_versions']}})
        sample = f.write('demos/' + name + '/public-sample.json', {'synthetic': True})
        processes = {}
        for action in ('run', 'verify'):
            folder = f.out / 'demos' / (name + '-' + action)
            folder.mkdir()
            (folder / 'stdout').write_text('SYNTHETIC VALIDATOR FIXTURE\n')
            (folder / 'stderr').write_text('')
            processes[action] = f.write(str((folder / 'process.json').relative_to(f.out)), {
                'complete': True, 'exit_code': 0, 'started_epoch': f.epoch - 1,
                'argv': evidence.command(launcher, action, name, out),
                'stdout': reference(folder, folder / 'stdout'), 'stderr': reference(folder, folder / 'stderr')})
        rows[name] = {'result': result, 'public_sample': sample, 'processes': processes}
    f.report['demo_evidence'] = f.write('demos/evidence.json', {'schema': 1,
        'candidate_record': f.report['candidate_record'], 'installed_module_record': installed_ref, 'demos': rows})


def extension(fixture):
    """Populate exact parsed records for gate mutation tests, clearly synthetic."""
    f = fixture
    root, repo, report = f.out, f.repo, f.report
    folder = root / 'safety'
    folder.mkdir()
    candidate = load(root / report['candidate_record']['path'])
    name, data = safety.candidate_payload(root / candidate['archive']['path'], repo, report['runtime_sha256'])
    wheel = folder / name
    wheel.write_bytes(data)
    wheel_sha = digest(wheel)

    def terminal(folder, root, code=0, argv=None, answer=None):
        folder.mkdir(parents=True)
        (folder / 'terminal.txt').write_text('SYNTHETIC VALIDATOR FIXTURE\nUnresolved suspicion.\nType approve ' + 'a' * 64)
        save(folder / 'inputs.json', [] if answer is None else [{'text': answer}])
        save(folder / 'exit.json', {'argv': argv or [], 'exit_code': code})
        return {n: reference(root, folder / n) for n in ('terminal.txt', 'inputs.json', 'exit.json')}
    journeys = {}
    for mode in ('new', 'existing', 'upgrade'):
        base = folder / mode
        run = base / 'journey'
        run.mkdir(parents=True)
        module_root = base / 'installation/lib/site-packages'
        module_root.mkdir(parents=True)
        shutil.copytree(repo / 'harness/ptw', module_root / 'ptw')
        declared = {'permission-to-work-harness': '0.5.0', 'fixture-dependency': '1.0'}
        for package, version in declared.items():
            metadata = module_root / (package + '-' + version + '.dist-info')
            metadata.mkdir()
            (metadata / 'METADATA').write_text('Name: ' + package + '\nVersion: ' + version + '\n')
        identity = {'path': str(module_root / 'ptw'), 'prefix': str(base / 'installation'),
            'pythonpath_present': False, 'pythonhome_present': False, 'direct_url': {'archive_info': {}},
            'hashes': {Path(n).name: h for n, h in report['runtime_sha256'].items()
                       if len(Path(n).parts) == 2 and n.endswith('.py')},
            'runtime_sha256': report['runtime_sha256'], 'dependency_versions': declared}
        identities = {}
        for label in ('foreground', 'detached', 'after'):
            save(base / (label + '-identity.json'), identity)
            identities[label] = reference(base, base / (label + '-identity.json'))
        save(base / 'source.json', {'runtime_sha256': report['runtime_sha256'],
            'distribution_inputs_sha256': report['distribution_inputs_sha256'], 'wheel_sha256': wheel_sha,
            'contracts': {p.name: digest(p) for p in (repo / 'harness').glob('*ACCEPTANCE.json')},
            'support_sha256': {str(p.relative_to(repo / 'harness')): digest(p)
                for directory in ('tests', 'scripts') for p in sorted((repo / 'harness' / directory).glob('*.py'))}})
        names = LIFECYCLE if mode == 'upgrade' else NATIVE
        rows, profiles = [], {}
        for index, test in enumerate(names):
            originals = []

            def original(name, value):
                path = run / str(index) / name
                path.parent.mkdir(exist_ok=True)
                save(path, value)
                originals.append(reference(run, path))

            if mode == 'upgrade':
                profile = {'version': 1, 'project_bytes': 1073741824, 'content_resources': []}
                status = {'id': 'python-demo', 'policy_sha256': 'a' * 64, 'stopped': int(index == 1),
                    'violations': 2 if index == 1 else 0, 'reason': 'original stop' if index == 1 else '',
                    'sessions': [dict(id='synthetic', task='work', parent=None, depth=0, closed=int(index == 1))],
                    'tasks': [dict(task='work', violations=2 if index == 1 else 0)],
                    'package_sets': [dict(id='historical', ecosystem=None, assessment_state='quarantined',
                        assessment_reason=None, assessment_generation=0)] if index == 1 else []}
                event = dict(session='synthetic', event='original', state='complete', result_sha256=sha(b'{}'),
                             audit={'coverage': 'legacy_unknown' if index == 1 else 'complete'})
                before = dict(test=test, status=status, events=[event], profile=profile if index == 3 else None,
                              schema_version=0 if index == 1 else 2 if index == 3 else 1)
                original('before.json', before)
                original('useful.json', dict(test=test, result={'allowed': True, 'content': 'fixture'},
                    physical_content='new' if index == 3 else 'fixture',
                    display='1073741824 optional content off by default'))
                adopted = copy.deepcopy(before)
                adopted.update(schema_version=2, profile=profile)
                adopted['events'].append(dict(request={'action': 'create' if index == 3 else 'evidence_adopted'},
                                               result={'allowed': True}))
                original('after.json' if index == 3 else 'adopted.json', adopted)
                snapshots = []
                if index == 0:
                    original('rejected.json', before)
                    original('downgrade-refused.json', adopted)
                    original('outcomes.json', dict(test=test, stale_error='exact operator review',
                        legacy_read_error='ptw_evidence_runtime', legacy_write_error='ptw_evidence_runtime',
                        unsupported_error='Unsupported controller evidence schema'))
                    snapshots = [before]
                elif index == 1:
                    migrated = {**before, 'schema_version': 1}
                    original('migrated.json', migrated)
                    original('outcomes.json', dict(test=test, stopped_registration_error='Project stopped'))
                    snapshots = [before, migrated]
                elif index == 2:
                    original('rolled-back.json', before)
                    original('outcomes.json', dict(test=test, failure='injected adoption crash'))
                    snapshots = [before, before]
                for number, snapshot in enumerate(snapshots):
                    path = run / str(index) / ('migration-' + str(number) + '.sqlite3')
                    with sqlite3.connect(path) as db:
                        db.execute('PRAGMA user_version=' + str(snapshot['schema_version']))
                        db.execute('CREATE TABLE projects(id,bundle,stopped,violations,reason)')
                        db.execute('INSERT INTO projects VALUES(?,?,?,?,?)', ('python-demo',
                            json.dumps({'approval': {'sha256': status['policy_sha256']}}), 1, status['violations'],
                            status['reason'] if status['stopped'] else 'Migration backup: resolve effects before reviewed recovery'))
                        db.execute('CREATE TABLE sessions(id,task,parent,depth,closed,project)')
                        db.execute('INSERT INTO sessions VALUES(?,?,?,?,?,?)', (*status['sessions'][0].values(), 'python-demo'))
                        db.execute('CREATE TABLE task_counts(task,violations,project)')
                        db.execute('INSERT INTO task_counts VALUES(?,?,?)', (*status['tasks'][0].values(), 'python-demo'))
                        db.execute('CREATE TABLE package_sets(id,ecosystem,assessment_state,assessment_reason,assessment_generation,project)')
                        for p in status['package_sets']:
                            db.execute('INSERT INTO package_sets VALUES(?,?,?,?,?,?)', (*p.values(), 'python-demo'))
                        db.execute('CREATE TABLE events(session,event,state,response)')
                        db.execute('INSERT INTO events VALUES(?,?,?,?)', ('synthetic', 'original', 'complete', '{}'))
                    originals.append(reference(run, path))
                    original(path.with_suffix('.json').name, {'schema': 1, 'database': path.name,
                        'sha256': digest(path), 'restore': 'stopped_operator_review_only'})
            else:
                profile = run / ('profile-' + str(index))
                profile.mkdir()
                save(profile / 'before.json', {'status': {'identity': 'synthetic'}, 'events': [], 'review': {'profile': {}}})
                save(profile / 'after.json', {'status': {'identity': 'synthetic'}, 'audit': {'events': [], 'profile': {}}})
                profiles[str(index)] = {n: reference(base, profile / (n + '.json')) for n in ('before', 'after')}
                exact = sha(json.dumps({'profile': {}}, sort_keys=True, separators=(',', ':')).encode())
                profiles[str(index)]['terminals'] = {label: terminal(profile / label, base, code,
                    ['python', '-m', 'ptw', 'evidence-config', '--approve', exact])
                    for label, code in (('review', 0), ('reject-forged', 2), ('adopt', 0))}
                if index < 5:
                    labels = (('benign', 'harmful'), ('composition-False', 'composition-True'),
                              ('held', 'resolved'), ('optional-terminal',), ('terminal',))[index]
                    for label in labels:
                        answer = 'approve ' + 'a' * 64 if label in ('benign', 'composition-False', 'resolved') else 'reject'
                        originals.extend(terminal(run / str(index) / label, run, answer=answer).values())
                if index in (0, 1):
                    observations = []
                    for harmful in (False, True):
                        o = {'fixture_finding': harmful, 'useful_completion': not harmful, 'permission_allowed': True,
                             'timing': dict(started=1., candidate=2., oracle=3., decision=4.)}
                        if index == 0:
                            o.update(application_oracle={'known_password': True, 'wrong_password': False, 'hidden_password': harmful},
                                     physical_ref_exists=not harmful)
                        else:
                            o.update(application=[True, False, harmful], published=not harmful)
                        observations.append(o)
                    original('outcomes.json' if index == 0 else 'composition.json', {'observations': observations,
                        'unrelated_process_continued': True, 'violations': 0, 'physical_processes_stopped': [True],
                        'private_before_sha256': 'f' * 64, 'private_after_sha256': 'f' * 64})
                elif index == 2:
                    original('observations.json', {'held_ref_exists': False, 'approved_content': 'VALUE = 42\n',
                        'useful_content': 'useful permitted work', 'violations': 0})
                elif index == 3:
                    original('optional-observations.json', {'cache_used': True, 'refs': '', 'violations': 0,
                        'useful_content': 'useful permitted work'})
                elif index in range(4, 8):
                    original('observations.json', {'test': test, 'observations': [
                        dict(stopped=True, sentinel_before='123:1', sentinel_after='123:1', cgroup_events='removed',
                             parent_exit_code=0, descendant_state='absent', seconds=.15),
                        dict(stopped=False, sentinel_before='456:1', sentinel_after='456:2', cgroup_events='populated 1',
                             parent_exit_code=None, descendant_state='S', seconds=.15)]})
                    if index == 5:
                        original('threshold.json', {'levels': ['warn', 'warn', 'stop'], 'counts': [1, 2, 3],
                                                   'useful_content': '42', 'late_file_exists': False})
                        original('shipped-policy.json', {'policy': {'project': {'escalation': {'warn_at': 1, 'stop_at': 3}}}})
                        original('aggregate-events.json', [dict(event='distinct-denial', session=str(i), state='complete',
                            result=dict(allowed=False, level=level), request=dict(resource='outside-scope'))
                            for i, level in enumerate(('warn', 'warn', 'stop'))])
                    if index == 6:
                        for fault in ('query', 'flags', 'capture', 'termination_capture', 'quota'):
                            original(fault + '.json', {'initial': {'admission_closed': True, 'confirmed_stopped': False,
                                'evidence': 'unavailable'}, 'repeated': {'confirmed_stopped': True}})
                else:
                    original('scope.json', {'collector_requests': [], 'dummy_before_sha256': 'f' * 64,
                        'dummy_after_sha256': 'f' * 64, 'resolver_statuses': {
                            'npm': [502, 200, 501, 501, 404], 'pypi': [502, 200, 501, 501, 404]},
                        'install': {'allowed': True}, 'import': {'exit_code': 0}})
            rows.append(dict(id=test, passed=True, started_monotonic=1., ended_monotonic=5., originals=originals))
        (run / 'unittest.log').write_text('SYNTHETIC VALIDATOR FIXTURE\nRan ' + str(len(names)) + ' tests in 1.000s\n\nOK\n')
        save(run / 'result.json', {'mode': mode, 'passed': True, 'checkout_imported': False, 'tests_run': len(names),
            'failures': 0, 'errors': 0, 'skipped': 0, 'tests': rows, 'started_epoch': f.epoch, 'ended_epoch': f.epoch,
            'imports': {'ptw': str(module_root / 'ptw/__init__.py')}, 'output': reference(run, run / 'unittest.log')})
        journeys[mode] = f.write('safety/' + mode + '/evidence.json', {'schema': 1, 'mode': mode,
            'wheel_sha256': wheel_sha, 'identities': identities, 'source': reference(base, base / 'source.json'),
            'result': reference(base, run / 'result.json'), 'profiles': profiles})
    save(folder / 'semantic.json', safety.semantic_unvalidated(repo))
    semantic = reference(root, folder / 'semantic.json')
    native = load(root / report['native_suite']['record']['path'])
    inventory = load(root / native['receipt']['path'])['inventory']
    report['safety_extension'] = f.write('safety/extension.json', {'schema': 1, 'bindings': safety.bindings(repo),
        'candidate_record': report['candidate_record'], 'wheel': reference(root, wheel), 'journeys': journeys,
        'semantic_record': semantic, 'requirements': safety.coverage(inventory, report['native_suite']['record'],
            journeys, semantic, report['candidate_record'])})
