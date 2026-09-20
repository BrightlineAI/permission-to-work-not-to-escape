"""Trusted file_indexing lifecycle seam for the existing Vega supervisor.

This admits only stopped *trusted launchers*, not arbitrary container processes.
The caller must establish confinement before executing mutable code. No agent
tool exposes these APIs; this module supplies neither exec nor file permission.
"""
import hashlib
import json
from pathlib import Path
import re
import sqlite3

from .linuxarena_cgroup import ExecutionSubtree, container_group, process_identity
from .policy import Invalid, canonical, digest


def runtime_identity():
    root = Path(__file__).parent
    return digest({str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in sorted(root.rglob('*')) if p.is_file() and
                   '__pycache__' not in p.parts and p.suffix != '.pyc'})


def authority(actor, bundle):
    return digest({'policy': bundle['approval']['sha256'], 'session': actor['id'],
                   'grants': json.loads(actor['grants']), 'commands': json.loads(actor['commands']),
                   'packages': json.loads(actor['packages'])})


def binding_row(db, unit):
    if not isinstance(unit, str) or not re.fullmatch(r'ptw-native-[0-9a-f]{24}', unit):
        raise Invalid('Invalid native workload identity')
    row = db.execute('SELECT n.*,w.project,w.session,w.stopped FROM native_workloads n '
                     'JOIN workloads w ON w.unit=n.unit WHERE n.unit=?', (unit,)).fetchone()
    if row is None:
        raise Invalid('Unknown native workload')
    try:
        binding = json.loads(row['binding'])
        if (not isinstance(binding, dict) or set(binding) !=
                {'subtree', 'control', 'daemon_id', 'runtime_sha256', 'authority_sha256'}):
            raise Invalid('Invalid native workload binding')
    except (ValueError, TypeError) as exc:
        raise Invalid('Invalid native workload binding') from exc
    from .event_evidence import seal
    event = db.execute('SELECT * FROM events WHERE session=? AND event=?',
                       ('controller:' + row['project'], 'native_workload_bound:' + unit)).fetchone()
    if event is None:
        raise Invalid('Missing native binding evidence')
    meta = json.loads(event['request_meta'])
    if (meta.get('_seal') != seal(meta, json.loads(event['response'] or '{}'), event['state']) or
            meta.get('_audit', {}).get('details', {}).get('binding_sha256') != digest(binding)):
        raise Invalid('Native workload binding evidence changed')
    return row, binding


def control_matches(expected):
    # State may legitimately alternate between sleeping and running. Every other
    # identity field, including namespace/starttime/cgroup, must remain exact.
    actual = process_identity(expected['pid'])
    if (actual['state'] in ('Z', 'X') or
            {k: v for k, v in actual.items() if k != 'state'} !=
            {k: v for k, v in expected.items() if k != 'state'}):
        raise Invalid('Native container control process changed')


def register(store, token, subtree, *, daemon_id, control):
    """Host-only registration of a new empty owned execution domain.

    daemon_id comes from the verified private runtime, never model arguments.
    Registration grants no new files/services and cannot move existing work.
    """
    if not isinstance(daemon_id, str) or not re.fullmatch('[a-zA-Z0-9:_.-]{1,128}', daemon_id):
        raise Invalid('Missing verified private daemon identity')
    with store.locked() as db:
        actor = store.session(db, token)
        project, bundle = store.project(db, actor['project'])
        if project['stopped'] or project['setup_pending']:
            raise Invalid('Project stopped or setup pending')
        if subtree.closed or subtree.revoked or subtree.populated():
            raise Invalid('Native registration requires a new empty execution domain')
        control_matches(control)
        if container_group(control['cgroup'], subtree.identity['container_id']) != subtree.parent:
            raise Invalid('Control process does not own execution domain')
        opened = ExecutionSubtree.reopen(subtree.identity)
        opened.close(remove=False)
        unit = 'ptw-native-' + subtree.name.removeprefix('ptw-')
        binding = {'subtree': subtree.identity, 'control': control, 'daemon_id': daemon_id,
                   'runtime_sha256': runtime_identity(), 'authority_sha256': authority(actor, bundle)}
        db.execute('BEGIN IMMEDIATE')
        try:
            db.execute('INSERT INTO workloads(unit,project,session) VALUES(?,?,?)',
                       (unit, actor['project'], actor['id']))
            db.execute('INSERT INTO native_workloads(unit,binding) VALUES(?,?)', (unit, canonical(binding)))
            store.lifecycle(db, actor['project'], 'native_workload_bound', session=actor['id'],
                            event='native_workload_bound:' + unit,
                            facts={'unit': unit, 'binding_sha256': digest(binding)})
            db.commit()
        except BaseException:
            db.rollback()
            raise
        return unit


def admit(store, token, unit, expected):
    """Serialize launch with stop; durable intent precedes SIGCONT.

    Reopening the same active binding supports controller process restarts.
    A stopped, closed, replaced or uncertain workload is never re-adopted.
    """
    if (not isinstance(expected, dict) or set(expected) !=
            {'pid', 'starttime', 'state', 'cgroup', 'pid_namespace', 'user_namespace'}):
        raise Invalid('Expected exact stopped launcher identity')
    with store.locked() as db:
        actor = store.session(db, token)
        project, bundle = store.project(db, actor['project'])
        row, binding = binding_row(db, unit)
        if (project['stopped'] or project['setup_pending'] or row['revoked'] or row['stopped'] or
                row['session'] != actor['id'] or row['project'] != actor['project']):
            raise Invalid('Native workload authority closed or belongs to another session')
        if binding['runtime_sha256'] != runtime_identity() or binding['authority_sha256'] != authority(actor, bundle):
            raise Invalid('Native runtime or approved authority changed')
        control_matches(binding['control'])
        if any(expected.get(k) != binding['control'][k] for k in ('pid_namespace', 'user_namespace', 'cgroup')):
            raise Invalid('Launcher is outside the recorded container namespace')
        subtree = ExecutionSubtree.reopen(binding['subtree'])
        event = 'native_launch:' + digest([unit, expected])
        try:
            if db.execute('SELECT 1 FROM events WHERE session=? AND event=?',
                          ('controller:' + actor['project'], event)).fetchone():
                raise Invalid('Native launch already attempted; no automatic replay')
            store.lifecycle(db, actor['project'], 'workload_launch', session=actor['id'], event=event,
                            facts={'unit': unit, 'launcher': expected, 'binding_sha256': digest(binding)}, pending=True)
            try:
                result = subtree.admit_stopped(expected)
                store.complete(db, 'controller:' + actor['project'], event,
                               {'allowed': True, 'level': 'allow', 'effect': 'workload_started', 'unit': unit})
                return result
            except BaseException:
                # Keep the pending intent. Recovery stops admission rather than
                # guessing whether the launch acted before acknowledgement failed.
                try:
                    terminate(db, unit)
                finally:
                    store.capture_fault(db, actor['project'])
                raise
        finally:
            subtree.close(remove=False)


def terminate(db, unit):
    """Supervisor backend. Persist revocation before touching the exact subtree.

    Runtime/policy changes cannot prevent stopping an already recorded domain.
    Even a failed database write still attempts physical termination, but never
    reports durable success. No Docker client, label or process-name targeting.
    """
    row, binding = binding_row(db, unit)
    error = None
    try:
        if db.in_transaction:
            raise sqlite3.OperationalError('Native revocation requires an autocommit controller connection')
        db.execute('UPDATE native_workloads SET revoked=1 WHERE unit=?', (unit,))
    except sqlite3.Error as exc:
        error = exc
    subtree = ExecutionSubtree.reopen(binding['subtree'])
    try:
        result = subtree.terminate()
    finally:
        subtree.close(remove=False)
    if error is not None:
        raise error
    return result


def state(db, unit):
    row, binding = binding_row(db, unit)
    subtree = ExecutionSubtree.reopen(binding['subtree'])
    try:
        populated = subtree.populated()
        return {**subtree.identity, 'populated': populated,
                'admission_closed': bool(row['revoked']),
                'confirmed_stopped': bool(row['revoked']) and not populated}
    finally:
        subtree.close(remove=False)
