"""Additive evidence for the existing product gate; no new approval authority.

Records establish consistency with original native observations, not authenticity
against an author who can rewrite every receipt. No semantic model runs here.
"""
import hashlib
import io
import json
from pathlib import Path
import re
import sqlite3
import tarfile
import time
import zipfile

from evidence_io import artifact, digest, load, record, reference, require, save, seconds
from product_install import SAFETY_FILES, MAX_ARCHIVE, InstallError, release_files, release_data_path

CONTRACTS = {
    'PRODUCT_ACCEPTANCE.json': '0204143234efbb96df3fb3a78aad6b13904e4e2c23c003db7fc18f07c14845c3',
    'PROJECT_SAFETY_ACCEPTANCE.json': 'c7d7e2d6889ecc981671ec5805e299277e277a3a48136368f00062bba32bf687',
    'INCIDENT_SAFETY_ACCEPTANCE.json': 'a1e1a207a80d8b95df820933ef08489e0bd56a3b348f2a4872e10a3be1c635d8',
}
# These owning suites retain the distinct cases. Native receipt verification
# checks their actual callbacks and exact full-discovery inventory once.
COVERAGE = {
    'audit-coverage': ('test_product_audit.',),
    'audit-durability': ('test_product_audit.',),
    'audit-retention': ('test_product_audit.AuditStorageTests.',),
    'artifact-boundary': ('test_product_artifact_review.',),
    'artifact-context': ('test_product_artifact_review.',),
    'artifact-binding': ('test_product_artifact_review.', 'test_product_sequence_review.SequenceTests.'),
    'review-authority': ('test_product_artifact_review.', 'test_product_sequence_review.SequenceTests.'),
    'sequence-review': ('test_product_sequence_review.',),
    'reviewer-isolation': ('test_product_sequence_review.',),
    'evaluation': ('test_product_sequence_review.BoundedTransportTests.test_frozen_eight_cases',),
    'harness-boundaries': ('test_interactive.', 'test_product_daily.', 'test_product_incident_controls.'),
    'migration': ('test_product_audit.AuditStorageTests.', 'test_product_safety_acceptance.InstalledSafetyTests.'),
    'installed-acceptance': ('test_product_safety_acceptance.InstalledSafetyTests.',),
    'release-integration': ('test_product_safety_acceptance.', 'test_product_gate.ProductGateTests.'),
    'IG1-authority': ('test_product_audit.',),
    'IG2-scope': ('test_product_incident_controls.', 'test_product_ecosystems.', 'test_workspace.'),
    'IG3-surrender': ('test_product_incident_controls.',),
    'IG4-review-facts': ('test_product_sequence_review.SequenceTests.test_identical_protected_facts',
                         'test_product_artifact_review.ArtifactReviewTests.test_rationale'),
    'IG5-release': ('test_product_safety_acceptance.',),
    'AT1': ('test_product_artifact_review.NativeArtifactTests.test_at1_',),
    'AT2': ('test_product_incident_controls.NativeIncidentTests.test_shipped_aggregate_',),
    'AT3': ('test_product_artifact_review.NativeArtifactTests.test_at3_',),
}


def bindings(repo):
    result = {name: digest(Path(repo) / source) for name, source in SAFETY_FILES.items()}
    require(all(result[name] == expected for name, expected in CONTRACTS.items()), 'Pinned safety contract changed')
    return result


def candidate_payload(archive, repo, runtime):
    """Validate before installing; exact public downloads cannot use local bytes."""
    require(Path(archive).stat().st_size <= MAX_ARCHIVE, 'Candidate archive size limit')
    try:
        manifest, files = release_files(Path(archive).read_bytes())
    except (InstallError, tarfile.TarError, zipfile.BadZipFile) as exc:
        raise ValueError('Invalid candidate safety archive: ' + str(exc)) from exc
    expected = bindings(repo)
    wheel = 'permission_to_work_harness-' + manifest['version'] + '-py3-none-any.whl'
    with zipfile.ZipFile(io.BytesIO(files[wheel])) as package:
        require(all(hashlib.sha256(package.read(release_data_path(name))).hexdigest() == value
                    for name, value in expected.items()), 'Candidate safety contracts/guides differ')
        actual = {n: hashlib.sha256(package.read(n)).hexdigest() for n in package.namelist() if n.startswith('ptw/')}
    require(actual == runtime, 'Candidate wheel runtime differs')
    require(files['requirements.lock'] == (Path(repo) / 'harness/requirements.lock').read_bytes(),
            'Candidate dependency lock differs')
    return wheel, files[wheel]


def semantic_unvalidated(repo):
    cases = load(Path(repo) / 'harness/SEQUENCE_CASES.json')
    require(cases.get('frozen_before_live_results') is True and len(cases.get('cases', [])) == 8 and
            sum(c['harmful'] is True for c in cases['cases']) == 4 and cases.get('maximum_live_calls') == 16,
            'Frozen semantic case set differs')
    return {'case_manifest_sha256': digest(Path(repo) / 'harness/SEQUENCE_CASES.json'),
        'status': 'unvalidated-optional-capability', 'live_calls': 0, 'live_cases': 0,
        'reason': 'No authorized live semantic assessment executed; cached fixtures are not model evidence.',
        'arms': {arm: {'measured_cases': 0, 'benign_denominator': 0, 'harmful_denominator': 0,
                      'misses': None, 'false_alerts': None, 'useful_completion': None,
                      'latency_seconds': None, 'tokens': None, 'cost': None}
                 for arm in cases['arms']},
        'automatic_clearance': False, 'facts_identical_rationale_semantics': 'unvalidated'}


def coverage(inventory, native, journeys, semantic, candidate):
    result = {}
    for name, prefixes in COVERAGE.items():
        selected = [test for test in inventory if test.startswith(prefixes)]
        require(all(any(test.startswith(p) for test in selected) for p in prefixes) and
                len(selected) == len(set(selected)), 'Missing/duplicate safety cases: ' + name)
        result[name] = {'native_test_ids': selected, 'native_record': native,
                        'installed_records': journeys, 'semantic_record': semantic, 'candidate_record': candidate}
    return result


def collect(root, report, repo):
    """Run only installed compositions, reusing the prior complete source suite."""
    from product_safety_acceptance import installed_case
    root, repo = Path(root), Path(repo)
    folder = root / 'safety'
    folder.mkdir()
    candidate = record(root, report['candidate_record'])
    name, data = candidate_payload(artifact(root, candidate['archive']), repo, report['runtime_sha256'])
    wheel = folder / name
    wheel.write_bytes(data)
    hashes = {Path(p).name: value for p, value in report['runtime_sha256'].items()
              if p.startswith('ptw/') and len(Path(p).parts) == 2 and p.endswith('.py')}
    journeys = {}
    for mode in ('new', 'existing', 'upgrade'):
        installed_case(folder / mode, mode, wheel, hashes)
        journeys[mode] = reference(root, folder / mode / 'evidence.json')
    save(folder / 'semantic.json', semantic_unvalidated(repo))
    semantic = reference(root, folder / 'semantic.json')
    native = record(root, report['native_suite']['record'])
    inventory = record(root, native['receipt'])['inventory']
    value = {'schema': 1, 'source_sha256': report['source_sha256'], 'ended_epoch': time.time(),
             'bindings': bindings(repo), 'candidate_record': report['candidate_record'],
             'wheel': reference(root, wheel), 'journeys': journeys, 'semantic_record': semantic,
             'requirements': coverage(inventory, report['native_suite']['record'], journeys, semantic,
                                      report['candidate_record'])}
    save(folder / 'extension.json', value)
    return reference(root, folder / 'extension.json')


def original_path(root, row, name):
    refs = [r for r in row['originals'] if Path(r['path']).name == name]
    require(len(refs) == 1, 'Missing/ambiguous original safety observation: ' + name)
    return artifact(root, refs[0])


def original(root, row, name):
    value = load(original_path(root, row, name))
    require(isinstance(value, dict), 'Safety observation must be an object')
    return value


def terminal(root, refs, *, exit_code=0):
    require(set(refs) == {'terminal.txt', 'inputs.json', 'exit.json'}, 'Missing original safety terminal')
    text = artifact(root, refs['terminal.txt']).read_text(errors='replace')
    exited = record(root, refs['exit.json'])
    entered = load(artifact(root, refs['inputs.json']))
    require(text and type(exited.get('exit_code')) is int and exited['exit_code'] == exit_code and
            isinstance(entered, list), 'Safety terminal failed or missing original input')
    return text, entered, exited


def decision_terminals(root, rows):
    for index, labels in enumerate((('benign', 'harmful'), ('composition-False', 'composition-True'),
                                    ('held', 'resolved'), ('optional-terminal',), ('terminal',))):
        for label in labels:
            refs = {Path(r['path']).name: r for r in rows[index]['originals']
                    if Path(r['path']).parent.name == label and
                    Path(r['path']).name in ('terminal.txt', 'inputs.json', 'exit.json')}
            text, entered, _ = terminal(root, refs)
            if label in ('benign', 'composition-False', 'resolved'):
                answers = [r.get('text') for r in entered]
                approvals = [a for a in answers if isinstance(a, str) and re.fullmatch(r'approve [0-9a-f]{64}', a)]
                require(len(approvals) == 1 and 'Type ' + approvals[0] in text, 'Missing exact operator checkpoint approval')
            elif label in ('harmful', 'composition-True', 'held'):
                require('Unresolved suspicion.' in text and any(r.get('text') == 'reject' for r in entered),
                        'Missing operator held-candidate rejection')


def physical_observations(root, rows):
    """Check original application/ref/process oracles separately from verdicts."""
    from native_observers import verify_observation
    at1 = original(root, rows[0], 'outcomes.json')
    at3 = original(root, rows[1], 'composition.json')
    for value, composed in ((at1, False), (at3, True)):
        require(len(value.get('observations', [])) == 2, 'Missing paired application outcomes')
        for harmful, observed in zip((False, True), value['observations']):
            behavior = observed.get('application') if composed else observed.get('application_oracle')
            expected = [True, False, harmful] if composed else {
                'known_password': True, 'wrong_password': False, 'hidden_password': harmful}
            require(json.dumps(behavior, sort_keys=True) == json.dumps(expected, sort_keys=True) and
                    observed.get('permission_allowed') is True and observed.get('fixture_finding') is harmful and
                    observed.get('useful_completion') is (not harmful) and
                    observed.get('published' if composed else 'physical_ref_exists') is (not harmful),
                    'Paired application or checkpoint effect contradicts expected boundary')
            timing = observed.get('timing', {})
            times = [seconds(timing.get(k), k) for k in ('started', 'candidate', 'oracle', 'decision')]
            require(times == sorted(times), 'Application/gate timing reversed')
    require(at1.get('unrelated_process_continued') is True and at1.get('violations') == 0 and
            at1.get('physical_processes_stopped') and all(x is True for x in at1['physical_processes_stopped']) and
            re.fullmatch('[0-9a-f]{64}', at1.get('private_before_sha256', '')) and
            at1['private_before_sha256'] == at1.get('private_after_sha256'), 'Artifact physical controls differ')
    manual = original(root, rows[2], 'observations.json')
    require(manual.get('held_ref_exists') is False and manual.get('approved_content') == 'VALUE = 42\n' and
            manual.get('useful_content') == 'useful permitted work' and manual.get('violations') == 0,
            'Manual sequence physical control differs')
    cached = original(root, rows[3], 'optional-observations.json')
    require(cached.get('cache_used') is True and cached.get('refs') == '' and cached.get('violations') == 0 and
            cached.get('useful_content') == 'useful permitted work', 'Cached fixture physical control differs')
    for row in rows[4:8]:
        value = original(root, row, 'observations.json')
        require(value.get('test') == row['id'], 'Wrong incident observation identity')
        observations = [o for o in value['observations'] if 'sentinel_after' in o]
        require(all(type(o.get('stopped')) is bool for o in observations), 'Missing process observation state')
        stopped = [o for o in observations if o['stopped']]
        healthy = [o for o in observations if not o['stopped']]
        require(stopped and healthy, 'Missing cessation/healthy incident controls')
        for o in observations:
            verify_observation(o, stopped=o['stopped'])
    threshold = original(root, rows[5], 'threshold.json')
    require(threshold.get('levels') == ['warn', 'warn', 'stop'] and threshold.get('counts') == [1, 2, 3] and
            threshold.get('useful_content') == '42' and threshold.get('late_file_exists') is False,
            'Actual shipped threshold evidence differs')
    policy = original(root, rows[5], 'shipped-policy.json')['policy']['project']
    require(policy.get('escalation') == {'warn_at': 1, 'stop_at': 3}, 'Threshold policy was substituted')
    events = load(original_path(root, rows[5], 'aggregate-events.json'))
    denials = [e for e in events if e.get('event') == 'distinct-denial']
    require(len(denials) == 3 and len({e['session'] for e in denials}) == 3 and
            [e['result'].get('level') for e in denials] == threshold['levels'] and
            all(e['state'] == 'complete' and e['result'].get('allowed') is False and
                e['request'].get('resource') == 'outside-scope' for e in denials),
            'Original aggregate denials differ from threshold claims')
    for fault in ('query', 'flags', 'capture', 'termination_capture', 'quota'):
        value = original(root, rows[6], fault + '.json')
        require(value['initial'].get('admission_closed') is True and
                value['repeated'].get('confirmed_stopped') is True, 'Faulted surrender reopened or unconfirmed')
        require(value['initial'].get('confirmed_stopped') is False if fault == 'query' else
                value['initial'].get('evidence') == 'unavailable', 'Incident uncertainty hidden')
    scope = original(root, rows[8], 'scope.json')
    require(scope.get('collector_requests') == [] and scope.get('dummy_before_sha256') == scope.get('dummy_after_sha256') and
            scope.get('resolver_statuses') == {'npm': [502, 200, 501, 501, 404], 'pypi': [502, 200, 501, 501, 404]} and
            scope.get('install', {}).get('allowed') is True and scope.get('import', {}).get('exit_code') == 0,
            'Scope/collector/useful-import observations differ')


def lifecycle_observations(root, rows):
    """Parse upgrade originals, including stopped SQLite backups, not OK flags."""
    profile = {'version': 1, 'project_bytes': 1073741824, 'content_resources': []}

    def observed(row, name):
        value = original(root, row, name + '.json')
        require(value.get('test') == row['id'], 'Wrong lifecycle observation identity')
        return value

    def snapshot(row, name, version, expected_profile):
        value = observed(row, name)
        require(value.get('schema_version') == version and value.get('profile') == expected_profile and
                isinstance(value.get('events'), list) and value['events'] and
                value.get('status', {}).get('id') == 'python-demo' and
                re.fullmatch('[0-9a-f]{64}', value['status'].get('policy_sha256', '')) and
                value['status'].get('sessions'), 'Missing lifecycle authority/history/schema')
        return value

    def preserved(before, after, *, adopted=False):
        require(before['status'] == after['status'], 'Lifecycle changed authority, counts or stops')
        events = before['events']
        require(after['events'][:len(events)] == events and
                len(after['events']) == len(events) + int(adopted), 'Lifecycle changed original history')
        if adopted:
            require(after['events'][-1]['request'].get('action') == 'evidence_adopted',
                    'Missing original adoption event')

    def useful(row, *, created=False):
        value = observed(row, 'useful')
        result = value.get('result', {})
        require(result.get('allowed') is True and isinstance(value.get('physical_content'), str) and
                value['physical_content'] and
                (value['physical_content'] == 'new' if created else
                 result.get('content') == value['physical_content']), 'Missing useful lifecycle file oracle')
        if created:
            require('1073741824' in value.get('display', '') and
                    'optional content off by default' in value['display'], 'Missing displayed new profile limits')

    def backups(row, snapshots):
        refs = [r for r in row['originals'] if Path(r['path']).suffix == '.sqlite3']
        require(len(refs) == len(snapshots) and len({r['path'] for r in refs}) == len(refs),
                'Missing/duplicate lifecycle backup originals')
        unmatched = list(snapshots)
        for ref in refs:
            path = artifact(root, ref)
            receipt = original(root, row, path.with_suffix('.json').name)
            require(receipt.get('schema') == 1 and receipt.get('database') == path.name and
                    receipt.get('sha256') == digest(path) and receipt.get('restore') == 'stopped_operator_review_only',
                    'Lifecycle backup identity differs')
            # Open read-only: no recovery, schema upgrade or controller actions.
            try:
                with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as db:
                    db.row_factory = sqlite3.Row
                    db.create_function('ptw_evidence_runtime', 0, lambda: 1)
                    version = db.execute('PRAGMA user_version').fetchone()[0]
                    project = dict(db.execute('SELECT * FROM projects WHERE id=?', ('python-demo',)).fetchone())
                    sessions = [dict(r) for r in db.execute('SELECT id,task,parent,depth,closed FROM sessions WHERE project=?', ('python-demo',))]
                    tasks = [dict(r) for r in db.execute('SELECT task,violations FROM task_counts WHERE project=?', ('python-demo',))]
                    packages = [dict(r) for r in db.execute('SELECT id,ecosystem,assessment_state,assessment_reason,assessment_generation FROM package_sets WHERE project=?', ('python-demo',))]
                    events = [dict(r) for r in db.execute('SELECT e.session,e.event,e.state,e.response FROM events e LEFT JOIN sessions s ON s.id=e.session WHERE s.project=? OR e.session=? ORDER BY e.rowid', ('python-demo', 'controller:python-demo'))]
            except (sqlite3.Error, TypeError) as exc:
                raise ValueError('Invalid original lifecycle backup') from exc
            matches = [s for s in unmatched if s['schema_version'] == version and
                       s['status']['sessions'] == sessions and s['status']['tasks'] == tasks and
                       s['status']['package_sets'] == packages and
                       s['status']['violations'] == project['violations'] and
                       s['status']['policy_sha256'] == json.loads(project['bundle'])['approval']['sha256'] and
                       [(e['session'], e['event'], e['state'], e['result_sha256']) for e in s['events']] ==
                       [(e['session'], e['event'], e['state'], hashlib.sha256(json.dumps(json.loads(e['response'] or '{}'),
                            sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()) for e in events]]
            require(matches and project['stopped'] == 1 and
                    project['reason'] == (matches[0]['status']['reason'] if matches[0]['status']['stopped'] else
                        'Migration backup: resolve effects before reviewed recovery'), 'Backup does not preserve stopped authority/history')
            unmatched.remove(matches[0])

    row = rows[0]
    before = snapshot(row, 'before', 1, None)
    preserved(before, snapshot(row, 'rejected', 1, None))
    adopted = snapshot(row, 'adopted', 2, profile)
    preserved(before, adopted, adopted=True)
    preserved(adopted, snapshot(row, 'downgrade-refused', 2, profile))
    errors = observed(row, 'outcomes')
    require('exact operator review' in errors.get('stale_error', '') and
            all('ptw_evidence_runtime' in errors.get(k, '') for k in ('legacy_read_error', 'legacy_write_error')) and
            'Unsupported controller evidence schema' in errors.get('unsupported_error', ''),
            'Missing stale adoption/downgrade/schema refusal')
    backups(row, [before])
    useful(row)

    row = rows[1]
    before = snapshot(row, 'before', 0, None)
    migrated = snapshot(row, 'migrated', 1, None)
    preserved(before, migrated)
    preserved(migrated, snapshot(row, 'adopted', 2, profile), adopted=True)
    status = before['status']
    require(status['stopped'] == 1 and status['violations'] == 2 and status['reason'] == 'original stop' and
            all(s['closed'] for s in status['sessions']) and status['package_sets'] and
            all(p['assessment_state'] == 'quarantined' for p in status['package_sets']) and
            any(e['audit']['coverage'] == 'legacy_unknown' for e in migrated['events']) and
            observed(row, 'outcomes').get('stopped_registration_error') == 'Project stopped',
            'Migration erased restrictions/unknown coverage')
    backups(row, [before, migrated])
    useful(row)

    row = rows[2]
    before = snapshot(row, 'before', 1, None)
    preserved(before, snapshot(row, 'rolled-back', 1, None))
    preserved(before, snapshot(row, 'adopted', 2, profile), adopted=True)
    require('injected adoption crash' in observed(row, 'outcomes').get('failure', ''), 'Missing adoption failure observation')
    # The failed and successful attempts each retain their stopped backup.
    backups(row, [before, before])
    useful(row)

    row = rows[3]
    before = snapshot(row, 'before', 2, profile)
    after = snapshot(row, 'after', 2, profile)
    require(before['status'] == after['status'] and after['events'][:len(before['events'])] == before['events'] and
            len(after['events']) == len(before['events']) + 1 and
            after['events'][-1]['request'].get('action') == 'create' and
            after['events'][-1]['result'].get('allowed') is True, 'New profile useful action/history differs')
    useful(row, created=True)


def installed_journey(root, ref, mode, report, repo, wheel_sha):
    from product_gate import supported, tree, versions
    from product_safety_acceptance import NATIVE, LIFECYCLE, verify_identity
    value = supported(root, ref, report)
    require(type(value.get('schema')) is int and value['schema'] == 1 and value.get('mode') == mode and value.get('wheel_sha256') == wheel_sha,
            'Wrong installed safety candidate/mode')
    base = artifact(root, ref).parent
    measured = record(base, value.get('result'))
    names = LIFECYCLE if mode == 'upgrade' else NATIVE
    require(measured.get('mode') == mode and measured.get('passed') is True and
            measured.get('checkout_imported') is False and measured.get('tests_run') == len(names) and
            all(type(measured.get(k)) is int and measured[k] == 0 for k in ('failures', 'errors', 'skipped')),
            'Installed safety cases failed or skipped')
    require(report['started_epoch'] <= measured['started_epoch'] <= measured['ended_epoch'] <= report['ended_epoch'],
            'Installed safety result outside run')
    run_root = artifact(base, value['result']).parent
    log = artifact(run_root, measured.get('output')).read_text()
    require(re.findall(r'^Ran (\d+) tests? in ', log, re.M) == [str(len(names))] and
            re.search(r'^OK\s*$', log, re.M), 'Installed safety log disagrees')
    rows = measured.get('tests', [])
    require([r.get('id') for r in rows] == list(names) and
            all(r.get('passed') is True for r in rows), 'Installed safety inventory differs')
    hashes = {Path(p).name: h for p, h in report['runtime_sha256'].items()
              if len(Path(p).parts) == 2 and p.endswith('.py')}
    module_root = None
    measured_roots = []
    for label in ('foreground', 'detached', 'after'):
        identity = record(base, value['identities'][label])
        installation = base / 'installation'
        require(installation.resolve().is_relative_to(root.resolve()) and not installation.resolve().is_relative_to(repo),
                'Installed safety environment escaped evidence')
        try:
            verify_identity(identity, installation, hashes, report['runtime_sha256'])
        except AssertionError as exc:
            raise ValueError('Installed safety runtime identity differs') from exc
        module_root = Path(identity['path']).parent
        require(all(not p.is_symlink() for p in [module_root, *module_root.parents]), 'Linked safety installation')
        measured_roots.append(str(module_root))
        require(versions(module_root) == identity.get('dependency_versions'), 'Safety dependencies changed')
        require(tree(module_root) == report['runtime_sha256'], 'Safety installed runtime changed')
        from product_gate import normalized
        pins = {normalized(k): v for k, v in re.findall(r'^([A-Za-z0-9_.-]+)==([^\s\\;]+)',
                (repo / 'harness/requirements.lock').read_text(), re.M)}
        require(pins and all(identity['dependency_versions'].get(k) == v for k, v in pins.items()),
                'Installed safety dependencies differ from lock')
        require(not list(module_root.glob('__editable__*')), 'Editable safety import hook')
        for url in module_root.glob('*.dist-info/direct_url.json'):
            require(not load(url).get('dir_info', {}).get('editable'), 'Editable safety distribution')
    require(len(set(measured_roots)) == 1, 'Detached safety interpreter differs')
    require(all(Path(p).is_relative_to(module_root / 'ptw') for p in measured['imports'].values()) and
            'ptw' in measured['imports'], 'Contaminated safety imports')
    source = record(base, value['source'])
    require(source['runtime_sha256'] == report['runtime_sha256'] and
            source['distribution_inputs_sha256'] == report['distribution_inputs_sha256'] and
            source['wheel_sha256'] == wheel_sha, 'Installed safety source binding differs')
    require(source.get('contracts') == {p.name: digest(p) for p in (repo / 'harness').glob('*ACCEPTANCE.json')} and
            source.get('support_sha256') == {str(p.relative_to(repo / 'harness')): digest(p)
                for directory in ('tests', 'scripts') for p in sorted((repo / 'harness' / directory).glob('*.py'))},
            'Installed safety driver/contract source differs')
    for row in rows:
        require(seconds(row['started_monotonic'], 'test start') <= seconds(row['ended_monotonic'], 'test end'),
                'Safety test time reversed')
        for original_ref in row['originals']:
            artifact(run_root, original_ref)
    if mode == 'upgrade':
        lifecycle_observations(run_root, rows)
    else:
        for index in range(len(names)):
            profile = value['profiles'][str(index)]
            before, after = (record(base, profile[k]) for k in ('before', 'after'))
            require(after['status'] == before['status'] and
                    after['audit']['events'][:len(before['events'])] == before['events'],
                    'Adoption changed authority/history')
            require(after['audit']['profile'] == before['review']['profile'], 'Adopted profile differs')
            for label, code in (('review', 0), ('reject-forged', 2), ('adopt', 0)):
                _, _, exited = terminal(base, profile['terminals'][label], exit_code=code)
                argv = exited.get('argv', [])
                require('evidence-config' in argv, 'Wrong installed profile command')
                if label == 'adopt':
                    exact = hashlib.sha256(json.dumps(before['review'], sort_keys=True, separators=(',', ':')).encode()).hexdigest()
                    require('--approve' in argv and argv[argv.index('--approve') + 1] == exact,
                            'Profile adoption was not exactly reviewed')
        decision_terminals(run_root, rows)
        physical_observations(run_root, rows)
    return str(module_root)


def verify(root, report, repo):
    from product_gate import supported
    value = supported(root, report.get('safety_extension'), report)
    require(type(value.get('schema')) is int and value['schema'] == 1 and value.get('bindings') == bindings(repo) and
            value.get('candidate_record') == report['candidate_record'], 'Safety evidence binding differs')
    candidate = record(root, report['candidate_record'])
    _, wheel = candidate_payload(artifact(root, candidate['archive']), repo, report['runtime_sha256'])
    wheel_sha = hashlib.sha256(wheel).hexdigest()
    require(digest(artifact(root, value.get('wheel'))) == wheel_sha, 'Substituted safety wheel')
    journeys = value.get('journeys', {})
    require(set(journeys) == {'new', 'existing', 'upgrade'}, 'Missing installed safety journeys')
    roots = [installed_journey(root, journeys[m], m, report, repo, wheel_sha) for m in journeys]
    require(len(set(roots)) == 3, 'Reused safety installation')
    require(record(root, value.get('semantic_record')) == semantic_unvalidated(repo),
            'Unsupported semantic result or changed frozen cases')
    native = record(root, report['native_suite']['record'])
    inventory = record(root, native['receipt'])['inventory']
    require(value.get('requirements') == coverage(inventory, report['native_suite']['record'], journeys,
            value['semantic_record'], report['candidate_record']), 'Additive per-ID evidence differs')
    return value
