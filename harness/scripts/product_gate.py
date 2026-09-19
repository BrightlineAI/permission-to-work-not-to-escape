#!/usr/bin/env python3
"""Offline consistency gate for original private product evidence, schema 1.

Passing means a candidate is ready for independent review and publication, not
that publication happened. Hashes do not authenticate an evidence author.
"""
import argparse
from email.parser import Parser
from pathlib import Path
import re
import sys
import json
import tomllib

from evidence_io import artifact, digest, fresh, load, record, require, seconds
import native_receipt

REPO = Path(__file__).resolve().parents[2]
IDS = {'new-python', 'existing-python', 'new-node', 'existing-node',
       'new-typescript', 'existing-typescript', 'existing-mixed-python-node'}
SECURITY = {'private-file-denied', 'critical-direct-denied', 'critical-transitive-denied',
    'young-release-denied', 'old-compatible-selected', 'tampered-package-denied',
    'evidence-outage-not-misconduct', 'new-advisory-quarantined', 'unapproved-build-script-denied',
    'approved-isolated-build-succeeded', 'parents-share-counts', 'child-scope-narrowed',
    'stop-kills-active-work', 'stop-rejects-resume', 'unrelated-project-survives',
    'cancel-preserves-repo', 'resume-native-tools-denied', 'policy-edit-does-not-expand',
    'installation-retry-preserves-data', 'upgrade-rollback-uninstall'}
TIMING_KEYS = ('id', 'timing_start', 'timing_end', 'human_input_seconds', 'human_input_mode',
               'preconditions', 'cache_profile')
ACTION_KEYS = ('id', 'unauthorized_effects', 'private_before_sha256', 'private_after_sha256',
               'continued_work', 'protected_resume', 'dependency_admitted')
RELEASES = 'https://github.com/BrightlineAI/permission-to-work-not-to-escape/releases/download/'


def requirement_evidence(report):
    """Finite coverage links, always to records independently validated by verify.

    Full native coverage supplies the accepted format/adapter and failure cases;
    the seven live journeys supply installed-user proof. Neither replaces the other.
    """
    journeys = sorted(report['journeys'], key=lambda row: row['id'])
    checks = {row['id']: row['record'] for row in report['security_checks']}
    native = [report['native_suite']['record']]
    candidate = [report['candidate_record']]

    def journey_records(*keys):
        return [row[key] for row in journeys for key in keys]

    def security(*names):
        return [checks[name] for name in names]

    return {
        'install': candidate + security('installation-retry-preserves-data', 'upgrade-rollback-uninstall') + native,
        'first-setup': journey_records('timing_record', 'terminal_record', 'action_record'),
        'policy': journey_records('terminal_record', 'action_record') + security('cancel-preserves-repo') + native,
        'ecosystems': journey_records('installed_module_record', 'functional_oracle', 'action_record') + native,
        'everyday': journey_records('action_record', 'functional_oracle', 'terminal_record') +
                    [report['local_git']['record']] + security('stop-kills-active-work'),
        'packages': security('critical-direct-denied', 'critical-transitive-denied', 'young-release-denied',
            'old-compatible-selected', 'tampered-package-denied', 'unapproved-build-script-denied',
            'approved-isolated-build-succeeded') + native,
        'reassessment': security('evidence-outage-not-misconduct', 'new-advisory-quarantined') + native,
        'scope': security('private-file-denied', 'parents-share-counts', 'child-scope-narrowed',
                         'resume-native-tools-denied', 'policy-edit-does-not-expand'),
        'escalation': security('parents-share-counts', 'stop-kills-active-work', 'stop-rejects-resume',
                              'unrelated-project-survives') + native,
        'acceptance': native + journey_records('terminal_record', 'functional_oracle', 'installed_module_record') +
                      security(*sorted(SECURITY)) + [report['local_git']['record']],
        'release': candidate + native,
    }


def candidate_record(root, report, repo):
    value = supported(root, report.get('candidate_record'), report)
    assertions(value)
    archive = artifact(root, value.get('archive'))
    bootstrap = artifact(root, value.get('bootstrap'))
    require(archive.stat().st_size > 0 and bootstrap.stat().st_size > 0, 'Empty candidate asset')
    version = tomllib.loads((repo / 'harness/pyproject.toml').read_text())['project']['version']
    require(value.get('version') == version and value.get('publication') == 'still-required',
            'Candidate version or publication claim differs')
    provenance = artifact(root, value.get('provenance'))
    if value.get('origin') == 'local-candidate':
        build = load(provenance)
        require(build.get('status') == 'built-unpublished' and
                build.get('archive_sha256') == digest(archive) and
                build.get('bootstrap_sha256') == digest(bootstrap), 'Candidate build provenance differs')
    else:
        tag = value.get('release_tag')
        require(value.get('origin') == 'public-release' and isinstance(tag, str) and
                tag in ('harness-v' + version, 'ptw-v' + version), 'Wrong public candidate tag')
        sums = {}
        for line in provenance.read_text().splitlines():
            match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_.-]+)', line)
            require(match is not None and match[2] not in sums, 'Invalid published checksums')
            sums[match[2]] = match[1]
        require(archive.name == 'ptw-' + version + '-linux-x86_64.tar.gz' and
                sums.get(archive.name) == digest(archive) and sums.get('install.sh') == digest(bootstrap),
                'Exact public candidate assets differ')
        downloads = value.get('downloads')
        require(isinstance(downloads, list) and len(downloads) == 3, 'Missing public download originals')
        for ref, target in zip(downloads, (provenance, bootstrap, archive)):
            download = record(root, ref)
            fresh(download.get('ended_epoch'))
            require(download.get('complete') is True and
                    download.get('url') == RELEASES + tag + '/' + target.name and
                    artifact(target.parent, download.get('artifact')) == target,
                    'Public download provenance differs')
    return value


def tree(root):
    root = Path(root)
    require(root.is_dir() and not root.is_symlink(), 'Missing or linked runtime root')
    files = sorted(p for p in (root / 'ptw').rglob('*')
                   if '__pycache__' not in p.parts and p.suffix not in ('.pyc', '.pyo'))
    require(files and all(not p.is_symlink() and p.resolve().is_relative_to(root.resolve())
                          for p in files), 'Missing or linked runtime content')
    return {str(p.relative_to(root)): digest(p) for p in files if p.is_file()}


def inputs(repo):
    return {n: digest(Path(repo) / 'harness' / n) for n in ('pyproject.toml', 'requirements.lock')}


def normalized(name):
    return re.sub(r'[-_.]+', '-', name).lower()


def versions(root):
    result = {}
    for path in Path(root).glob('*.dist-info/METADATA'):
        require(not path.is_symlink() and not path.parent.is_symlink() and
                path.stat().st_size < 4 * 1024 * 1024, 'Invalid distribution metadata')
        metadata = Parser().parsestr(path.read_text(), headersonly=True)
        require(metadata.get('Name') and metadata.get('Version'), 'Missing distribution identity')
        name = normalized(metadata['Name'])
        require(name not in result, 'Duplicate installed distribution')
        result[name] = metadata['Version']
    require(result, 'Missing installed distributions')
    return result


def same(value, row, keys):
    for key in keys:
        require(key in value and key in row and type(value[key]) is type(row[key]) and
                value[key] == row[key], 'Contradictory supporting field: ' + key)


def assertions(value):
    rows = value.get('assertions')
    require(isinstance(rows, list) and rows, 'Missing measured assertions')
    names = set()
    for check in rows:
        require(isinstance(check, dict) and isinstance(check.get('name'), str) and check['name'] and
                check['name'] not in names and 'expected' in check and 'observed' in check and
                type(check['expected']) is type(check['observed']) and
                check['expected'] == check['observed'], 'Measured assertion failed or duplicated')
        names.add(check['name'])


def supported(root, ref, report):
    value = record(root, ref)
    fresh(value.get('ended_epoch'))
    require(value.get('source_sha256') == report['source_sha256'], 'Supporting source drift')
    require(report['started_epoch'] <= value['ended_epoch'] <= report['ended_epoch'],
            'Supporting record outside run')
    return value


def installed(root, value, runtime, distribution_inputs, repo):
    require(value.get('checkout_imported') is False and
            value.get('distribution_inputs_sha256') == distribution_inputs, 'Contaminated installed audit')
    module_root = Path(value.get('module_root', ''))
    require(module_root.is_absolute() and module_root.is_dir() and
            module_root.resolve().is_relative_to(root.resolve()) and
            not module_root.resolve().is_relative_to(repo.resolve()), 'Installation must remain in evidence')
    require(all(not p.is_symlink() for p in [module_root, *module_root.parents]), 'Linked installation path')
    require(tree(module_root) == runtime, 'Installed runtime or package data differs')
    actual = versions(module_root)
    declared = value.get('dependency_versions')
    require(isinstance(declared, dict) and all(normalized(k) == k for k in declared) and
            actual == declared, 'Installed distribution inventory differs')
    pins = {normalized(k): v for k, v in re.findall(r'^([A-Za-z0-9_.-]+)==([^\s\\;]+)',
             (repo / 'harness/requirements.lock').read_text(), re.M)}
    require(pins and all(actual.get(k) == v for k, v in pins.items()) and
            'permission-to-work-harness' in actual, 'Installed distributions differ from lock')
    project = tomllib.loads((repo / 'harness/pyproject.toml').read_text())['project']
    require(actual.get(normalized(project['name'])) == project['version'], 'Installed application version differs')
    for path in module_root.glob('*.dist-info/direct_url.json'):
        require(not path.is_symlink() and not load(path).get('dir_info', {}).get('editable'),
                'Editable installed distribution')
    require(not list(module_root.glob('__editable__*')), 'Editable import hook in installation')
    processes = value.get('processes')
    require(isinstance(processes, dict) and set(processes) == {'launcher', 'broker', 'monitor'},
            'Missing actual protected-process identity')
    pids = set()
    for role, ref in processes.items():
        process = record(root, ref)
        fresh(process.get('measured_epoch'))
        require(process.get('role') == role and process.get('module_root') == str(module_root) and
                process.get('runtime_sha256') == runtime and process.get('pythonpath_present') is False and
                process.get('pythonhome_present') is False, 'Protected process imported wrong runtime')
        require(type(process.get('pid')) is int and process['pid'] > 0, 'Missing measured process identity')
        pids.add(process['pid'])
        executable, prefix = Path(process.get('executable', '')), Path(process.get('prefix', ''))
        require(executable.is_absolute() and prefix.is_absolute() and executable.is_relative_to(prefix) and
                module_root.is_relative_to(prefix) and prefix.is_relative_to(root), 'Process interpreter escaped installation')
        require(digest(executable) == process.get('interpreter_sha256'), 'Installed interpreter changed')
        modules = process.get('imported_ptw_modules')
        require(isinstance(modules, dict) and 'ptw' in modules and all(
            Path(p).is_relative_to(module_root / 'ptw') for p in modules.values()), 'Contaminated loaded modules')
    require(len(pids) == 3, 'Expected three independent protected processes')
    return str(module_root)


def journey(root, row, report, repo):
    require(isinstance(row, dict) and row.get('id') in IDS, 'Invalid journey')
    for key in ('passed', 'real_pty', 'fresh_application_install', 'continued_work',
                'protected_resume', 'dependency_admitted'):
        require(row.get(key) is True, 'Unmet journey: ' + key)
    require(row.get('checkout_imported') is False and row.get('installed_runtime_sha256') ==
            report['runtime_sha256'], 'Installed/source mismatch')
    total = seconds(row.get('first_setup_wall_seconds'), 'first setup')
    first = seconds(row.get('first_useful_action_wall_seconds'), 'first action')
    human = seconds(row.get('human_input_seconds'), 'human input')
    require(total <= 30 and first >= total and human <= total, 'First setup target or timing unmet')
    require(row.get('timing_start') == 'installer-invocation' and
            row.get('timing_end') == 'protected-codex-ready', 'Wrong timing boundary')
    require(row.get('human_input_mode') in ('real-user', 'scripted-terminal') and
            isinstance(row.get('preconditions'), list) and row['preconditions'] and
            row.get('cache_profile') in ('cold', 'warm'), 'Missing timing profile')
    require(type(row.get('unauthorized_effects')) is int and row['unauthorized_effects'] == 0 and
            isinstance(row.get('private_before_sha256'), str) and
            re.fullmatch('[0-9a-f]{64}', row['private_before_sha256']) and
            row['private_before_sha256'] == row.get('private_after_sha256'), 'Sensitive fixture changed')
    require(type(row.get('build_or_test_exit_code')) is int and row['build_or_test_exit_code'] == 0,
            'Functional oracle failed')
    terminal = supported(root, row.get('terminal_record'), report)
    same(terminal, row, ('id', 'real_pty'))
    require(artifact(root, terminal.get('transcript')).stat().st_size > 0, 'Empty original PTY')
    require(terminal.get('model') == report['real_model'] and
            terminal.get('reasoning_effort') == report['reasoning_effort'], 'Terminal model differs')
    require(artifact(root, terminal.get('resumed_transcript')).stat().st_size > 0,
            'Missing original resumed PTY')
    reviews = terminal.get('operator_reviews')
    require(isinstance(reviews, list) and len(reviews) == (2 if 'mixed' in row['id'] else 1),
            'Missing explicit dependency review')
    for ref in reviews:
        require(artifact(root, ref).stat().st_size > 0, 'Empty dependency review')
    actions = supported(root, row.get('action_record'), report)
    same(actions, row, ACTION_KEYS)
    require(isinstance(actions.get('actions'), list) and actions['actions'], 'No actual broker actions')
    assertions(actions)
    oracle = supported(root, row.get('functional_oracle'), report)
    same(oracle, row, ('id', 'build_or_test_exit_code'))
    assertions(oracle)
    require(artifact(root, oracle.get('output')).stat().st_size > 0, 'Missing original oracle output')
    timing = supported(root, row.get('timing_record'), report)
    same(timing, row, TIMING_KEYS)
    start = seconds(timing.get('start_monotonic'), 'start')
    ready = seconds(timing.get('ready_monotonic'), 'ready')
    useful = seconds(timing.get('first_action_monotonic'), 'useful')
    require(abs(ready - start - total) < .05 and abs(useful - start - first) < .05,
            'Timing arithmetic disagrees')
    elapsed = seconds(timing.get('full_elapsed_seconds'), 'full elapsed')
    require(elapsed >= first and timing.get('authentication') ==
            'existing operator login; browser/MFA external and untested', 'Missing elapsed/authentication disclosure')
    cache = timing.get('cache_before')
    require(isinstance(cache, dict), 'Missing measured cache inventory')
    if row['cache_profile'] == 'cold':
        require(cache == {}, 'Cold profile contains cached input')
    else:
        require(set(cache) == {'release_archive', 'tool_cache', 'uv_cache', 'npm_cache'} and
                all(cache[k] == 'empty private cache' for k in ('tool_cache', 'uv_cache', 'npm_cache')),
                'Warm profile must disclose exact cache scope')
        require(artifact(root, cache['release_archive']).stat().st_size > 0, 'Missing warm archive')
    audit = supported(root, row.get('installed_module_record'), report)
    same(audit, row, ('id',))
    return installed(root, audit, report['runtime_sha256'], report['distribution_inputs_sha256'], repo)


def security_check(root, check, report):
    require(check.get('passed') is True and check.get('physical_effect_verified') is True,
            'Unverified security effect')
    value = supported(root, check.get('record'), report)
    same(value, check, ('id', 'passed', 'physical_effect_verified'))
    assertions(value)
    require(isinstance(value.get('probes'), list) and value['probes'], 'Missing original security probes')
    observed_assertions = []
    for ref in value['probes']:
        probe = supported(root, ref, report)
        require(probe.get('id') == check['id'] and probe.get('complete') is True,
                'Wrong or incomplete security probe')
        assertions(probe)
        require(probe.get('kind') in ('injected-request', 'native-lifecycle'), 'Unlabeled independent probe')
        log = artifact(root, probe.get('output')).read_text()
        require(log, 'Empty original probe output')
        measurements, responses = {}, []
        for line in log.splitlines():
            event = json.loads(line)
            require(isinstance(event, dict), 'Invalid original probe observation')
            epoch = seconds(event.get('measured_epoch'), 'observation time')
            require(report['started_epoch'] <= epoch <= probe['ended_epoch'], 'Observation outside run')
            if 'response' in event:
                record(root, event['response'])
                responses.append(event['response'])
            else:
                name = event.get('name')
                require(isinstance(name, str) and name and name not in measurements and 'observed' in event,
                        'Missing or duplicate original measurement')
                measurements[name] = event['observed']
        require(responses and responses == probe.get('responses'), 'Missing or substituted probe responses')
        require(set(measurements) == {a['name'] for a in probe['assertions']}, 'Probe measurement coverage differs')
        for assertion in probe['assertions']:
            actual = measurements[assertion['name']]
            require(type(actual) is type(assertion['observed']) and actual == assertion['observed'],
                    'Original security observation contradicts assertion')
        artifacts = probe.get('artifacts')
        require(isinstance(artifacts, list), 'Missing original probe artifact inventory')
        for original in artifacts:
            path = artifact(root, original)
            if path.name == 'process.json':
                process = load(path)
                require(process.get('complete') is True and type(process.get('exit_code')) is int,
                        'Incomplete original probe process')
                for stream in ('stdout', 'stderr'):
                    artifact(path.parent, process.get(stream))
        observed_assertions.extend(probe['assertions'])
    require(value['assertions'] == observed_assertions, 'Security summary differs from original probes')


def local_git_check(root, row, report):
    require(isinstance(row, dict) and row.get('id') == 'local-git', 'Missing local Git evidence')
    security_check(root, row, report)
    terminals = row.get('operator_terminals')
    require(isinstance(terminals, dict) and set(terminals) == {'approval', 'rejection'},
            'Missing Git operator decisions')
    summary = record(root, row['record'])
    originals = [ref for p in summary['probes'] for ref in record(root, p)['artifacts']]
    for decision, refs in terminals.items():
        require(isinstance(refs, dict) and set(refs) == {'terminal.txt', 'inputs.json', 'exit.json'} and
                all(ref in originals for ref in refs.values()), 'Git operator records not in original probe')
        transcript = artifact(root, refs['terminal.txt']).read_text(errors='replace')
        entered = load(artifact(root, refs['inputs.json']))
        exited = record(root, refs['exit.json'])
        require(type(exited.get('exit_code')) is int and exited['exit_code'] == 0,
                'Git operator terminal failed')
        require(isinstance(entered, list) and len(entered) == 1 and isinstance(entered[0], dict) and
                isinstance(entered[0].get('text'), str), 'Missing exact Git operator input')
        text = entered[0]['text']
        require((text == 'reject' and 'Type approve ' in transcript) if decision == 'rejection' else
                re.fullmatch(r'approve [0-9a-f]{64}', text) is not None and 'Type ' + text in transcript,
                'Git operator input did not answer the exact review')


def verify(root, repo=REPO):
    root, repo = Path(root).absolute(), Path(repo).resolve()
    require(root.is_dir() and not root.is_symlink() and not root.resolve().is_relative_to(repo),
            'Use original private evidence outside checkout')
    report = load(root / 'completion-evidence.json')
    require(isinstance(report, dict), 'Completion evidence must be an object')
    require(type(report.get('schema')) is int and report['schema'] == 1, 'Unknown completion schema')
    contract_path = repo / 'harness/PRODUCT_ACCEPTANCE.json'
    contract = load(contract_path)
    require(report.get('contract_sha256') == digest(contract_path), 'Contract changed')
    require(report.get('source_sha256') == native_receipt.sources(repo), 'Maintained source changed')
    require(report.get('runtime_sha256') == tree(repo / 'harness') and
            report.get('distribution_inputs_sha256') == inputs(repo), 'Runtime/distribution source changed')
    require(report.get('real_model') == 'gpt-5.6-sol' and report.get('reasoning_effort') == 'low' and
            report.get('execution_host') == 'algol-box-2' and report.get('simulation') is False,
            'Missing genuine supported model/host')
    fresh(report.get('started_epoch'))
    fresh(report.get('ended_epoch'))
    require(report['started_epoch'] <= report['ended_epoch'], 'Run clock reversed')
    rows = report.get('journeys')
    require(isinstance(rows, list) and all(isinstance(r, dict) for r in rows) and len(rows) == len(IDS) and
            {r.get('id') for r in rows} == IDS, 'Seven distinct journeys required')
    roots = [journey(root, row, report, repo) for row in rows]
    require(len(set(roots)) == len(IDS), 'Application installations reused')
    require({r['cache_profile'] for r in rows} == {'cold', 'warm'}, 'Cold and warm profiles required')
    native = report.get('native_suite', {})
    require(isinstance(native, dict), 'Native summary must be an object')
    measured = record(root, native.get('record'))
    same(measured, native, ('passed', 'tests_run', 'failures', 'errors', 'skipped'))
    original = artifact(root, measured.get('receipt'))
    verified = native_receipt.verify(original.parent, repo=repo)
    same(verified, native, ('passed', 'tests_run', 'failures', 'errors', 'skipped'))
    require(artifact(root, measured.get('output')).read_bytes() ==
            artifact(original.parent, verified['output']).read_bytes(), 'Native output substituted')
    latest, _ = native_receipt.latest(repo=repo)
    require(digest(latest / 'complete.json') == digest(original), 'Native result superseded')
    checks = report.get('security_checks')
    require(isinstance(checks, list) and all(isinstance(c, dict) for c in checks) and len(checks) == len(SECURITY) and
            {c.get('id') for c in checks} == SECURITY, 'Exact security matrix required')
    for check in checks:
        security_check(root, check, report)
    local_git_check(root, report.get('local_git'), report)
    candidate_record(root, report, repo)
    required = {r['id'] for r in contract['requirements'] if r['mandatory']}
    coverage = report.get('requirements')
    require(isinstance(coverage, dict) and set(coverage) == required, 'Mandatory contract coverage incomplete')
    expected = requirement_evidence(report)
    require(set(expected) == required, 'Contract implementation drift')
    for name, item in coverage.items():
        require(isinstance(item, dict) and item.get('status') == ('ready-for-publication' if name == 'release' else 'passed') and
                isinstance(item.get('records'), list) and len(item['records']) == 1, 'Unmet requirement: ' + name)
        for ref in item['records']:
            value = supported(root, ref, report)
            require(value.get('contract_ids') == [name], 'Requirement record mapped to wrong contract ID')
            assertions(value)
            require(value.get('evidence') == expected[name], 'Requirement evidence coverage differs: ' + name)
            for original in value['evidence']:
                artifact(root, original)
    require(report.get('unmet_requirements') == [] and report.get('auth_files_copied') is False and
            report.get('unknown_vulnerability_guarantee') is False, 'Unmet requirement or unsupported claim')
    return {'passed': True, 'complete': False, 'publication': 'still-required',
            'journeys': len(rows), 'security_checks': len(checks), 'requirements': len(required),
            'evidence_sha256': digest(root / 'completion-evidence.json')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.evidence), sort_keys=True))
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(json.dumps({'passed': False, 'error': str(exc)}), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
