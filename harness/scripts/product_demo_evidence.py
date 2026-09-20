"""Bind the existing demo verifiers to the exact installed product candidate.

Private originals stay under acceptance output. Public projections are checked
against those originals, never bundled back into the already measured wheel.
"""
import os
import json
from pathlib import Path
import subprocess
import sys
import time

from evidence_io import artifact, capture, fresh, load, record, reference, require, save

DEMOS = ('dependency', 'task-scope', 'swarm', 'report')
MODULES = ('test_product_audit', 'test_product_artifact_review',
           'test_product_sequence_review', 'test_product_safety_acceptance',
           'test_product_incident_controls', 'test_product_demo',
           'test_product_demo_presentation', 'test_product_demo_dependency',
           'test_product_demo_task_scope', 'test_product_demo_swarm')


def discovery(inventory):
    """Assert owning modules, including installed safety, without rerunning them."""
    from collections import Counter
    counts = Counter(inventory)
    for module in MODULES:
        selected = [name for name in counts if name.startswith(module + '.')]
        require(selected and all(counts[name] == 1 for name in selected),
                'Missing or repeated required release module: ' + module)
    for case in ('new_project_installed_review_and_incidents',
                 'existing_project_installed_review_and_incidents',
                 'installed_upgrade_mismatch_and_rollback'):
        require(counts['test_product_safety_acceptance.InstalledSafetyTests.test_' + case] == 1,
                'Missing installed safety case: ' + case)


def installation(root, report):
    row = next(r for r in report['journeys'] if r['id'] == 'new-python')
    audit = record(root, row['installed_module_record'])
    launcher = record(root, audit['processes']['launcher'])
    return row['installed_module_record'], audit, launcher


def command(launcher, action, demo, out):
    return [launcher['executable'], '-I', '-B', '-m', 'ptw', 'demo', action,
            '--demo', demo, '--out', str(out)]


def collect(root, report, repo):
    from product_journey import child_environment
    root = Path(root)
    folder = root / 'demos'
    folder.mkdir()
    installed_ref, _, launcher = installation(root, report)
    config = load(root / 'new-python/driver.json')
    env = child_environment(os.environ, config['installed_root'])
    demos = {}
    for name in DEMOS:
        out = folder / name
        processes = {}
        for action in ('run', 'verify'):
            process = folder / (name + '-' + action)
            result = capture(command(launcher, action, name, out), process,
                             env=env, cwd=root, timeout=300)
            require(result.returncode == 0, 'Installed demo failed: ' + name + ' ' + action)
            processes[action] = reference(root, process / 'process.json')
        demos[name] = {'result': reference(root, out / 'result.json'),
                       'public_sample': reference(root, out / 'public-sample.json'),
                       'processes': processes}
    value = {'schema': 1, 'source_sha256': report['source_sha256'],
             'ended_epoch': time.time(), 'candidate_record': report['candidate_record'],
             'installed_module_record': installed_ref, 'demos': demos}
    save(folder / 'evidence.json', value)
    return reference(root, folder / 'evidence.json')


def verify_originals(folders, repo, identity):
    """Use verified source dependencies even from a bare gate interpreter.

    As in native_receipt.discover, never execute a receipt-selected interpreter
    or evaluate editable/site startup hooks. Only current verifier code runs.
    """
    import native_receipt
    native_receipt.verify_environment(identity, repo)
    require(identity.get('python') == sys.version, 'Demo verification requires the native Python version')
    roots = sorted({str(Path(p).parent.parent) for p in identity['distribution_metadata']})
    paths = [str(Path(repo) / 'harness'), str(Path(repo) / 'harness/scripts'), *roots]
    driver = ('import json,sys; from pathlib import Path; '
              'sys.path[:0]=json.loads(sys.argv[1]); from product_demo import verify; '
              '[verify(Path(p)) for p in json.loads(sys.argv[2])]')
    result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', driver,
                             json.dumps(paths), json.dumps([str(p) for p in folders])],
                            cwd=repo, capture_output=True, text=True, timeout=120)
    require(result.returncode == 0, 'Demo original verification failed: ' + result.stderr)


def verify(root, report, repo):
    root = Path(root)
    value = record(root, report.get('demo_evidence'))
    fresh(value.get('ended_epoch'))
    require(value.get('schema') == 1 and value.get('source_sha256') == report['source_sha256'] and
            value.get('candidate_record') == report['candidate_record'], 'Stale or substituted demo candidate')
    native = record(root, report['native_suite']['record'])
    receipt = record(root, native['receipt'])
    discovery(receipt['inventory'])
    installed_ref, audit, launcher = installation(root, report)
    require(value.get('installed_module_record') == installed_ref, 'Demo installation substituted')
    demos = value.get('demos')
    require(isinstance(demos, dict) and set(demos) == set(DEMOS), 'Required installed demos missing')
    folders = []
    for name, row in demos.items():
        require(isinstance(row, dict), 'Malformed demo references')
        result_path = artifact(root, row.get('result'))
        out = result_path.parent
        require(result_path.name == 'result.json', 'Wrong demo result')
        result = load(result_path)
        require(isinstance(result, dict), 'Malformed demo result')
        fresh(result.get('ended_epoch'))
        require(result.get('complete') is True and result.get('demo', 'report') == name,
                'Incomplete or wrong demo')
        source, installed = result.get('source', {}), result.get('installed', {})
        require(isinstance(source, dict) and isinstance(installed, dict), 'Malformed demo identity')
        require(source.get('runtime_sha256') == report['runtime_sha256'] and
                source.get('maintained_sha256') == report['runtime_sha256'] and
                source.get('distribution_inputs_sha256') == report['distribution_inputs_sha256'],
                'Demo runtime or distribution differs from candidate')
        require(installed.get('path') == str(Path(audit['module_root']) / 'ptw') and
                installed.get('prefix') == launcher['prefix'] and
                installed.get('runtime_sha256') == report['runtime_sha256'] and
                installed.get('dependency_versions') == audit['dependency_versions'],
                'Demo did not use the retained candidate installation')
        require(artifact(root, row.get('public_sample')) == out / 'public-sample.json',
                'Demo public projection substituted')
        processes = row.get('processes')
        require(isinstance(processes, dict) and set(processes) == {'run', 'verify'}, 'Demo CLI receipts missing')
        for action, ref in processes.items():
            path = artifact(root, ref)
            process = load(path)
            require(isinstance(process, dict), 'Malformed demo CLI receipt')
            fresh(process.get('started_epoch'))
            fresh(process.get('ended_epoch'))
            require(process.get('complete') is True and process.get('exit_code') == 0 and
                    process.get('argv') == command(launcher, action, name, out) and
                    process['started_epoch'] <= process['ended_epoch'], 'Installed demo CLI failed or substituted')
            require(artifact(path.parent, process.get('stdout')).stat().st_size > 0,
                    'Missing demo CLI output')
            artifact(path.parent, process.get('stderr'))
        # Recompute physical observations and the fixed-field public projection.
        # This verifies originals locally; it never executes recorded commands.
        folders.append(out)
    verify_originals(folders, repo, receipt['environment'])
    return {'demo_ready': True, 'demos': list(DEMOS)}
