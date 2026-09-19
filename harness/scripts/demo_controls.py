"""Executable limits: valid authority does not establish truth or operator intent."""
from pathlib import Path

from evidence_io import load, require, save

WRONG_REPORT = 'Synthetic asset report\nTotal cost: 0\nAnnual depreciation: 0\n'
PRIVATE = 'Synthetic private fixture; never publish.\n'


def run_controls(folder):
    from product_demo import fixture
    from ptw.policy import approve, compile_policy, digest
    from ptw.store import Store
    from ptw.workflow import dispatch
    from ptw.workspace import request
    from ptw.supervisor import Supervisor
    folder.mkdir()
    for name in ('wrong-output', 'wrong-grant'):
        root = folder / name
        root.mkdir()
        store, bundle, actors = fixture(root, 1)
        try:
            resource = next(k for k, v in bundle['inventory']['resources'].items() if v['path'] == 'out')
            if name == 'wrong-grant':
                # A NEW approval/activation, never repair the main demo's policy.
                for scope in [bundle['policy']['project'], *bundle['policy']['tasks']]:
                    scope['grants'].append({'actions': ['read'], 'resource': 'excluded'})
                bundle = approve(bundle['policy'], bundle['inventory'],
                    digest(compile_policy(bundle['policy'], bundle['inventory'])), 'scripted mistaken operator')
                save(root / 'mistaken-approved.json', bundle)
                store = Store(root / 'mistaken-controller')
                store.activate(bundle)
                actor = store.register('report-demo', 'work')
                req = request('read', 'excluded')
            else:
                actor = actors[0]
                req = request('create', resource, 'wrong-report.txt', content=WRONG_REPORT)
            result = dispatch(store, actor, name, req)
            save(root / 'action.json', {'event': name, 'session': actor['session'], 'request': req, 'result': result})
            save(root / 'audit.json', store.audit_export('report-demo'))
            save(root / 'status.json', store.status('report-demo'))
            require(result['allowed'] is True, 'Negative control was not executable')
        finally:
            store.stop('report-demo')
            Supervisor(store).reconcile()
    return verify_controls(folder)


def verify_controls(folder):
    from product_demo import expected_report
    from ptw.policy import check_approval, digest
    from ptw.event_evidence import verify_export
    folder = Path(folder)
    for name in ('wrong-output', 'wrong-grant'):
        root = folder / name
        bundle = load(root / ('mistaken-approved.json' if name == 'wrong-grant' else 'approved.json'))
        check_approval(bundle)
        row = load(root / 'action.json')
        status = load(root / 'status.json')
        audit = load(root / 'audit.json')
        verify_export(audit, digest(audit))
        require(row['event'] == name and row['result']['allowed'] is True and
                status['violations'] == 0 and not status['stopped'] and
                status['policy_sha256'] == bundle['approval']['sha256'], 'Negative control not admitted under its grant')
        events = [e for e in audit['events'] if e['session'] == row['session'] and e['event'] == name]
        require(len(events) == 1 and events[0]['state'] == 'complete' and
                events[0]['result_sha256'] == digest(row['result']) and
                events[0]['audit']['request_sha256'] == digest(row['request']), 'Negative control contradicts audit')
        if name == 'wrong-output':
            require((root / 'repo/out/wrong-report.txt').read_text() == WRONG_REPORT != expected_report() and
                    row['request']['content'] == WRONG_REPORT, 'Incorrect report control lost its physical effect')
        else:
            original = load(root / 'approved.json')
            for scope in [original['policy']['project'], *original['policy']['tasks']]:
                require({'actions': ['read'], 'resource': 'excluded'} not in scope['grants'], 'Original scope already granted target')
                scope['grants'].append({'actions': ['read'], 'resource': 'excluded'})
            require(original['policy'] == bundle['policy'] and original['inventory'] == bundle['inventory'],
                    'Mistaken grant changed unrelated authority')
            require(row['request']['resource'] == 'excluded' and row['result']['content'] ==
                    (root / 'repo/excluded.txt').read_text() == PRIVATE, 'Wrong-target read was not observed')
    return {'allowed_wrong_output': 'admitted; independent report oracle rejects it',
            'mistaken_local_grant': 'admitted; controller follows the approved wrong target',
            'remote_mistaken_grant': 'unmeasured; no generic publication integration'}
