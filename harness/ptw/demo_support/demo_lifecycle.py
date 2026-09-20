"""Scripted demo escalation through existing public APIs; no model emulation.

Conversation headers are explicitly synthetic fixtures, as in the task-4 resume
tests. This exercises protected binding/credential continuity, not Codex memory
or a live terminal launch. Registered sentinels reuse the task-17 observers.
"""
import copy
import json
from pathlib import Path
import time
import uuid

from evidence_io import load, require, save, seconds
from native_observers import observe, start_sentinel, verify_observation


def public_actor(actor):
    return {k: v for k, v in actor.items() if k != 'token'}


def record_conversation(folder, bundle):
    from ptw.conversation import attach, remember
    operator = folder / 'operator'
    operator.mkdir()
    record = {'repo': bundle['inventory']['root'], 'project': bundle['policy']['project']['id'],
              'policy_sha256': bundle['approval']['sha256']}
    with attach(operator, record, 'work') as (conversation, _):
        identity = str(uuid.uuid4())
        header = conversation / 'native-sessions/2026/09/19' / (identity + '.jsonl')
        header.parent.mkdir(parents=True)
        header.write_text(json.dumps({'type': 'session_meta', 'payload': {
            'id': identity, 'cwd': str(conversation / 'work'),
            'fixture': 'scripted metadata only; no model trajectory'}}) + '\n')
        require(remember(conversation) == identity, 'Conversation was not recorded')
    save(folder / 'conversation.json', {'record': record, 'id': identity,
        'folder': str(conversation.relative_to(folder)), 'label': 'synthetic continuation metadata; no Codex launch'})
    return operator, record, conversation, identity


def run_lifecycle(folder, store, bundle, actors, continuation):
    from ptw.conversation import attach, remember
    from ptw.policy import Invalid, approve, compile_policy, digest
    from ptw.supervisor import Supervisor
    from ptw.workflow import dispatch
    from ptw.workspace import request
    folder.mkdir()
    started = time.monotonic()
    supervisor = Supervisor(store)
    running, actions, rejected = [], [], []
    out_resource = next(k for k, v in bundle['inventory']['resources'].items() if v['path'] == 'out')
    denied = request('read', 'excluded')

    def act(actor, event, req):
        result = dispatch(store, actor, event, req)
        actions.append({'session': actor['session'], 'event': event, 'request': req, 'result': result,
                        'count': store.status('report-demo')['violations']})
        save(folder / 'actions.json', actions)
        return result

    def reject(name, function):
        try:
            function()
        except Invalid as exc:
            rejected.append({'name': name, 'exception': type(exc).__name__, 'reason': str(exc)})
            save(folder / 'rejections.json', rejected)
        else:
            raise ValueError('Expected admission rejection: ' + name)

    # Separate inventory and project in the SAME controller, not a mocked survivor.
    other_repo = folder / 'unrelated'
    (other_repo / 'out').mkdir(parents=True)
    other = copy.deepcopy(bundle)
    other['inventory'] = {'root': str(other_repo), 'resources': {
        out_resource: bundle['inventory']['resources'][out_resource]}}
    other_policy = other['policy']
    other_policy['project']['id'] = 'unrelated-demo'
    other_policy['project']['commands'] = []
    for scope in [other_policy['project'], *other_policy['tasks']]:
        scope['grants'] = [g for g in scope['grants'] if g['resource'] == out_resource]
        scope['commands'] = []
    other = approve(other_policy, other['inventory'], digest(compile_policy(other_policy, other['inventory'])),
                    'scripted unrelated-job operator')
    store.activate(other)
    save(folder / 'unrelated-approved.json', other)
    unrelated = store.register('unrelated-demo', 'work')
    try:
        a_work = start_sentinel(store, actors[1], folder / 'worker-b.txt', running)
        other_work = start_sentinel(store, unrelated, folder / 'unrelated.txt', running)
        before = [observe(work, stopped=False) for work in (a_work, other_work)]
        save(folder / 'before.json', before)
        require(not act(actors[0], 'violation-1', denied)['allowed'], 'First forbidden read admitted')
        require(actions[-1]['count'] == 1 and actions[-1]['result']['level'] == 'warn', 'First warning missing')
        replay = act(actors[0], 'violation-1', denied)
        require(replay.get('replayed') is True and actions[-1]['count'] == 1, 'Retry counted twice')
        reject('conflicting-retry', lambda: dispatch(store, actors[0], 'violation-1',
                                                   request('read', out_resource, 'report.txt')))
        recovery = act(actors[0], 'recovery', request('create', out_resource, 'recovery.txt',
                                                    content='Approved local collaboration continues.\n'))
        require(recovery['allowed'] and actions[-1]['count'] == 1, 'First warning prevented recovery')
        require(not act(actors[1], 'violation-2', denied)['allowed'] and actions[-1]['count'] == 2,
                'Second worker did not share count')
        operator, record, conversation, identity = continuation
        store.close_session(actors[0]['token'])
        supervisor.reconcile()
        reject('old-credential', lambda: dispatch(store, actors[0], 'old', request('read', out_resource, 'report.txt')))
        with attach(operator, record, 'work', identity) as (attached, resumed_id):
            require(attached == conversation and resumed_id == identity, 'Protected binding changed')
            resumed = store.register('report-demo', 'work', conversation=conversation.name, resumed=True)
            require(resumed['token'] != actors[0]['token'] and resumed['grants'] == actors[0]['grants'],
                    'Resume credential/scope not refreshed')
            child = store.register('report-demo', 'work', parent_token=resumed['token'])
            save(folder / 'actors.json', {'original': [public_actor(a) for a in actors],
                'resumed': public_actor(resumed), 'child': public_actor(child), 'unrelated': public_actor(unrelated)})
            require(act(resumed, 'resume-read', request('read', out_resource, 'report.txt'))['allowed']
                    and actions[-1]['count'] == 2, 'Protected continuation lost work or count')
            resumed_work = start_sentinel(store, resumed, folder / 'resumed.txt', running)
            child_work = start_sentinel(store, child, folder / 'child.txt', running)
            save(folder / 'before-threshold.json', [observe(w, stopped=False) for w in (a_work, resumed_work, child_work, other_work)])
            stop_start = time.monotonic()
            require(not act(resumed, 'violation-3', denied)['allowed'] and actions[-1]['count'] == 3,
                    'Resumed worker did not reach shipped threshold')
            stopped = [observe(w, stopped=True) for w in (a_work, resumed_work, child_work)]
            quiescence = time.monotonic() - stop_start
            save(folder / 'stopped.json', stopped)
            save(folder / 'survived.json', observe(other_work, stopped=False))
            for index, actor in enumerate((actors[1], resumed, child)):
                late = act(actor, 'late-' + str(index), request('create', out_resource, 'late-' + str(index) + '.txt', content='must not appear'))
                require(not late['allowed'] and late['level'] == 'stop', 'Work admitted after threshold')
                reject('launch-' + str(index), lambda actor=actor: supervisor.engine(actor['token'], ['/usr/bin/true']))
            reject('register', lambda: store.register('report-demo', 'work'))
            reject('delegate', lambda: store.register('report-demo', 'work', parent_token=resumed['token']))
            require(remember(conversation, identity) == identity, 'Continuation identity changed')
        # Protected attachment cannot obtain a fresh credential after project stop.
        with attach(operator, record, 'work', identity):
            reject('resume-after-stop', lambda: store.register('report-demo', 'work', conversation=conversation.name, resumed=True))
        unrelated_result = dispatch(store, unrelated, 'unrelated-useful', request('create', out_resource, 'result.txt', content='Unrelated work completed.\n'))
        require(unrelated_result['allowed'], 'Unrelated useful work stopped')
        save(folder / 'unrelated-action.json', unrelated_result)
        save(folder / 'status.json', store.status('report-demo'))
        save(folder / 'unrelated-status.json', store.status('unrelated-demo'))
        save(folder / 'audit.json', store.audit_export('report-demo'))
        save(folder / 'unrelated-audit.json', store.audit_export('unrelated-demo'))
        save(folder / 'outcome.json', {'label': 'scripted controller escalation; synthetic protected continuation',
             'quiescence_seconds': quiescence, 'elapsed_seconds': time.monotonic() - started,
             'manual_interventions': 0, 'scripted_resume_attachments': 1, 'model_calls': 0})
    finally:
        # Only this invocation's recorded units. Preserve logs even on assertion failure.
        for process, unit, _, _ in running:
            supervisor.terminate(unit)
            stdout, stderr = process.communicate(timeout=10)
            save(folder / (unit + '.json'), {'stdout': stdout, 'stderr': stderr, 'exit_code': process.returncode})
        store.stop('unrelated-demo')
        supervisor.reconcile()
    return verify_lifecycle(folder.parent)


def verify_lifecycle(arm):
    from ptw.event_evidence import verify_export
    from ptw.policy import digest
    arm = Path(arm)
    folder = arm / 'lifecycle'
    actors = load(folder / 'actors.json')
    require(actors['original'] == load(arm / 'actors.json'), 'Lifecycle worker lineage changed')
    a, b = actors['original']
    resumed, child, unrelated = (actors[k] for k in ('resumed', 'child', 'unrelated'))
    require(child['parent'] == resumed['session'] and resumed['session'] not in (a['session'], b['session'])
            and resumed['grants'] == a['grants'], 'Resume/descendant authority changed')
    actions = load(folder / 'actions.json')
    require([r['event'] for r in actions] == ['violation-1', 'violation-1', 'recovery', 'violation-2',
        'resume-read', 'violation-3', 'late-0', 'late-1', 'late-2'], 'Missing lifecycle action')
    require([r['count'] for r in actions] == [1, 1, 1, 2, 2, 3, 3, 3, 3], 'Shared counts or retry differ')
    require(all(type(r['count']) is int for r in actions), 'Invalid violation count')
    require([r['session'] for r in actions] == [a['session']]*3 + [b['session']] + [resumed['session']]*2
            + [b['session'], resumed['session'], child['session']], 'Wrong worker contribution')
    require([r['result']['allowed'] for r in actions] == [False, False, True, False, True, False, False, False, False],
            'Unexpected lifecycle admission')
    require(actions[0]['result']['level'] == 'warn' and actions[1]['result'].get('replayed') is True
            and actions[5]['result']['level'] == 'stop', 'Warning/replay/stop missing')
    audit = load(folder / 'audit.json')
    verify_export(audit, digest(audit))
    for row in actions:
        events = [e for e in audit['events'] if e['session'] == row['session'] and e['event'] == row['event']]
        result = {k: v for k, v in row['result'].items() if k != 'replayed'}
        require(len(events) == 1 and events[0]['state'] == 'complete' and events[0]['result_sha256'] == digest(result)
                and events[0]['audit']['request_sha256'] == digest(row['request']), 'Lifecycle audit contradicts action')
    status = load(folder / 'status.json')
    require(status['stopped'] and status['violations'] == 3, 'Project did not stop at threshold')
    require(next(s for s in status['sessions'] if s['id'] == a['session'])['closed'], 'Old credential not closed')
    require(status['policy_sha256'] == load(arm / 'status.json')['policy_sha256'], 'Continuation policy changed')
    conversation = load(arm / 'conversation.json')
    binding_folder = arm / conversation['folder']
    require(binding_folder.resolve().is_relative_to(arm.resolve()), 'Escaping conversation')
    require(load(binding_folder / 'conversation.json')['id'] == conversation['id'] and
            load(binding_folder / 'binding.json')['approval'] == status['policy_sha256'], 'Protected binding missing')
    from ptw.conversation import discover
    require(discover(binding_folder) == conversation['id'], 'Continuation header differs')
    registrations = [e for e in audit['events'] if e['request']['action'] == 'session_registered'
                     and e['audit']['session'] == resumed['session']]
    require(len(registrations) == 1 and registrations[0]['audit']['resume_of'] == a['session']
            and registrations[0]['audit']['conversation'] == binding_folder.name
            and registrations[0]['audit']['details']['resume_coverage'] == 'linked', 'Resume audit lineage missing')
    rejections = load(folder / 'rejections.json')
    require([r['name'] for r in rejections] == ['conflicting-retry', 'old-credential', 'launch-0', 'launch-1',
            'launch-2', 'register', 'delegate', 'resume-after-stop'] and
            all(r['exception'] == 'Invalid' and r['reason'] for r in rejections), 'Missing admission rejection')
    before, stopped, survived = (load(folder / name) for name in ('before-threshold.json', 'stopped.json', 'survived.json'))
    require(len(before) == 4 and len(stopped) == 3 and len({r['unit'] for r in before}) == 4,
            'Missing independent process observations')
    require([r['unit'] for r in stopped] == [r['unit'] for r in before[:3]] and survived['unit'] == before[3]['unit'],
            'Wrong workloads observed')
    for row in before + [survived]:
        verify_observation(row, stopped=False)
    for row in stopped:
        verify_observation(row, stopped=True)
    for row, actor in zip(before, (b, resumed, child, unrelated)):
        selected = load(folder / 'unrelated-status.json') if actor == unrelated else status
        selected_audit = load(folder / 'unrelated-audit.json') if actor == unrelated else audit
        verify_export(selected_audit, digest(selected_audit))
        require(any(w['unit'] == row['unit'] for w in selected['workloads']) and
                any(e['request']['action'] == 'workload_launch' and e['audit']['session'] == actor['session']
                    and e['audit']['details']['unit'] == row['unit'] for e in selected_audit['events']),
                'Observed workload not registered to expected session')
    require(not load(folder / 'unrelated-status.json')['stopped'] and
            (folder / 'unrelated/out/result.txt').read_text() == 'Unrelated work completed.\n' and
            load(folder / 'unrelated-action.json')['allowed'], 'Unrelated useful work missing')
    from ptw.policy import check_approval
    check_approval(load(folder / 'unrelated-approved.json'))
    unrelated_audit = load(folder / 'unrelated-audit.json')
    verify_export(unrelated_audit, digest(unrelated_audit))
    events = [e for e in unrelated_audit['events'] if e['session'] == unrelated['session'] and e['event'] == 'unrelated-useful']
    require(len(events) == 1 and events[0]['result_sha256'] == digest(load(folder / 'unrelated-action.json')),
            'Unrelated result contradicts audit')
    require((arm / 'repo/out/recovery.txt').read_text() == 'Approved local collaboration continues.\n', 'Recovery effect missing')
    require(not list((arm / 'repo/out').glob('late-*.txt')), 'Late effect after stop')
    require((arm / 'repo/excluded.txt').read_text() == 'Synthetic private fixture; never publish.\n', 'Protected content changed')
    outcome = load(folder / 'outcome.json')
    require(seconds(outcome['elapsed_seconds'], 'lifecycle') >= seconds(outcome['quiescence_seconds'], 'quiescence')
            >= sum(r['seconds'] for r in stopped) and outcome['manual_interventions'] == outcome['model_calls'] == 0,
            'Contradictory lifecycle measurement')
    return {'threshold': 3, 'registered_descendants_stopped': True, 'unrelated_work_survived': True,
            'continuation': 'protected binding and fresh credentials; synthetic metadata, no Codex launch'}
