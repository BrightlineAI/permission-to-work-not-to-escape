"""Trusted file_indexing lifecycle seam for the existing Vega supervisor.

This admits only stopped *trusted launchers*, not arbitrary container processes.
The caller must establish confinement before executing mutable code. No agent
tool exposes these APIs; this module supplies neither exec nor file permission.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3

from .linuxarena_cgroup import ExecutionSubtree, container_group, process_identity
from .policy import Invalid, canonical, digest, scope


def checkpoint_file_scope(db, actor, bundle, resources, spec):
    """Freeze/recheck filesystem authority for a CLOSED checkpoint only.

    Container paths are trusted adapter mappings, not request fields. This does
    not authorize commands, network access or recreation of inherited kernel
    restrictions. Native target-user DAC still applies after credential setup.
    """
    from .linuxarena_namespace import validate
    from .workspace_policy import resource_info
    from .store import Store
    validate(spec)
    if (not isinstance(resources, dict) or not resources or
            any(not isinstance(k, str) or not isinstance(v, str) for k, v in resources.items()) or
            set(resources.values()) != set(spec['read'] + spec['write']) or
            len(set(resources.values())) != len(resources)):
        raise Invalid('Checkpoint resource mapping differs from confinement')
    if bundle['approval']['sha256'] != digest({k: bundle[k] for k in ('policy', 'inventory')}):
        raise Invalid('Checkpoint policy changed after approval')
    allowed = scope(bundle['policy']['project']['grants'])
    chain, seen, current = [], set(), actor
    closing = Store.closing_sessions(db)
    while current is not None:
        if (current['id'] in seen or len(seen) >= 17 or current['closed'] or
                current['id'] in closing or current['project'] != actor['project'] or
                current['preparation_source'] is not None):
            raise Invalid('Checkpoint parent authority is not active')
        seen.add(current['id'])
        task = next((t for t in bundle['policy']['tasks'] if t['id'] == current['task']), None)
        if task is None:
            raise Invalid('Checkpoint task no longer exists')
        for grants in (task['grants'], json.loads(current['grants'])):
            ceiling = scope(grants)
            allowed = {name: actions & ceiling.get(name, set()) for name, actions in allowed.items()}
        chain.append({'session': current['id'], 'task': current['task'], 'parent': current['parent'],
                      'authority_sha256': authority(current, bundle)})
        parent = current['parent']
        current = db.execute('SELECT * FROM sessions WHERE id=?', (parent,)).fetchone() if parent else None
        if parent and current is None:
            raise Invalid('Checkpoint parent authority is missing')
    bound = {}
    for name, path in sorted(resources.items()):
        item = bundle['inventory']['resources'].get(name)
        if item is None:
            raise Invalid('Unknown checkpoint resource')
        needed = {'read'}
        if path in spec['write']:
            needed |= {'write', 'append'}
            if item.get('kind') == 'tree':
                needed |= {'create', 'delete'}
        if not needed <= allowed.get(name, set()):
            raise Invalid('Checkpoint confinement exceeds surviving file grants')
        info = resource_info(bundle['inventory'], name)
        original = db.execute('SELECT device,inode FROM bindings WHERE project=? AND resource=?',
                              (actor['project'], name)).fetchone()
        if info is None or original is None or (info.st_dev, info.st_ino) != tuple(original):
            raise Invalid('Checkpoint resource identity changed')
        bound[name] = {'path': path, 'kind': item.get('kind', 'file'),
                       'device': info.st_dev, 'inode': info.st_ino, 'actions': sorted(needed)}
    # Copy all request data; no caller-owned list can change a frozen snapshot.
    return json.loads(canonical({'authority': chain, 'resources': bound, 'spec': spec}))


def freeze_checkpoint_scope(store, token, resources, spec):
    with store.locked() as db:
        actor = store.session(db, token)
        project, bundle = store.project(db, actor['project'])
        if project['stopped'] or project['setup_pending']:
            raise Invalid('Project stopped or setup pending')
        return checkpoint_file_scope(db, actor, bundle, resources, spec)


def verify_checkpoint_scope(db, actor, bundle, checkpoint):
    frozen = checkpoint.get('file_scope') if isinstance(checkpoint, dict) else None
    if not isinstance(frozen, dict) or set(frozen) != {'authority', 'resources', 'spec'}:
        raise Invalid('Missing checkpoint file authority')
    try:
        resources = {name: entry['path'] for name, entry in frozen['resources'].items()}
        actual = checkpoint_file_scope(db, actor, bundle, resources, frozen['spec'])
    except (KeyError, TypeError, AttributeError) as exc:
        raise Invalid('Malformed checkpoint file authority') from exc
    if actual != frozen:
        raise Invalid('Checkpoint file authority changed')


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


def checkpoint_process(pid):
    """Bounded public kernel/code identity; never read authentication state."""
    root = Path('/proc') / str(pid)
    fields = (root / 'stat').read_text().rsplit(')', 1)[1].split()
    with (root / 'exe').open('rb') as stream:
        executable = stream.read(16 * 1024 ** 2 + 1)
    if not executable or len(executable) > 16 * 1024 ** 2:
        raise Invalid('Checkpoint executable exceeds bound')
    return {'parent': int(fields[1]), 'mount_namespace': os.readlink(root / 'ns/mnt'),
            'executable_sha256': hashlib.sha256(executable).hexdigest()}


def validate_checkpoint_child(expected, checkpoint, control):
    """Host-only CLOSED endpoint admission, not authorization of requested code.

    The kernel-authenticated native monitor stays in the control namespace.
    Its actual child has selected the prepared PID namespace but has not yet
    entered the mount namespace or run native credential setup. Never relax
    ordinary launcher admission to accommodate this distinct fork ordering.
    """
    if (not isinstance(checkpoint, dict) or set(checkpoint) !=
            {'monitor', 'holder', 'frontend_sha256', 'file_scope'} or
            not isinstance(checkpoint['frontend_sha256'], str) or
            not re.fullmatch('[0-9a-f]{64}', checkpoint['frontend_sha256'])):
        raise Invalid('Invalid closed checkpoint binding')
    monitor, holder = checkpoint['monitor'], checkpoint['holder']
    for process in (monitor, holder):
        if not isinstance(process, dict) or set(process) != set(expected):
            raise Invalid('Invalid checkpoint process identity')
        control_matches(process)
    if (len({expected['pid'], monitor['pid'], holder['pid'], control['pid']}) != 4 or
            expected['state'] != 'T' or
            any(process[k] != control[k] for process in (expected, monitor, holder)
                for k in ('user_namespace', 'cgroup')) or
            monitor['pid_namespace'] != control['pid_namespace'] or
            expected['pid_namespace'] != holder['pid_namespace'] or
            expected['pid_namespace'] == control['pid_namespace']):
        raise Invalid('Checkpoint child is outside its authenticated domain')
    parent = checkpoint_process(monitor['pid'])
    child = checkpoint_process(expected['pid'])
    outer = checkpoint_process(control['pid'])
    prepared = checkpoint_process(holder['pid'])
    if (child['parent'] != monitor['pid'] or
            child['executable_sha256'] != checkpoint['frontend_sha256'] or
            parent['executable_sha256'] != checkpoint['frontend_sha256'] or
            child['mount_namespace'] != parent['mount_namespace'] or
            parent['mount_namespace'] != outer['mount_namespace'] or
            prepared['mount_namespace'] == outer['mount_namespace']):
        raise Invalid('Checkpoint ancestry, frontend or mount identity changed')


def admit(store, token, unit, expected, *, closed_checkpoint=None):
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
        if closed_checkpoint is None:
            if any(expected.get(k) != binding['control'][k] for k in ('pid_namespace', 'user_namespace', 'cgroup')):
                raise Invalid('Launcher is outside the recorded container namespace')
        else:
            verify_checkpoint_scope(db, actor, bundle, closed_checkpoint)
            validate_checkpoint_child(expected, closed_checkpoint, binding['control'])
        subtree = ExecutionSubtree.reopen(binding['subtree'])
        event = 'native_launch:' + digest([unit, expected])
        try:
            if db.execute('SELECT 1 FROM events WHERE session=? AND event=?',
                          ('controller:' + actor['project'], event)).fetchone():
                raise Invalid('Native launch already attempted; no automatic replay')
            store.lifecycle(db, actor['project'], 'workload_launch', session=actor['id'], event=event,
                            facts={'unit': unit, 'launcher': expected, 'binding_sha256': digest(binding),
                                   **({'closed_checkpoint': closed_checkpoint}
                                      if closed_checkpoint is not None else {})}, pending=True)
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


def continue_checkpoint(store, token, unit, initial, expected, checkpoint):
    """One-use closed continuation after native credential/namespace setup.

    The original admission remains the authority: this cannot adopt a child,
    transfer membership, authorize requested code or recreate a launch intent.
    """
    from .event_evidence import export_row
    with store.locked() as db:
        actor = store.session(db, token)
        project, bundle = store.project(db, actor['project'])
        row, binding = binding_row(db, unit)
        if (project['stopped'] or project['setup_pending'] or row['revoked'] or row['stopped'] or
                row['session'] != actor['id'] or row['project'] != actor['project']):
            raise Invalid('Native continuation authority closed or belongs to another session')
        if (binding['runtime_sha256'] != runtime_identity() or
                binding['authority_sha256'] != authority(actor, bundle)):
            raise Invalid('Native runtime or approved authority changed')
        event = 'native_launch:' + digest([unit, initial])
        prior = db.execute('SELECT *, NULL AS task FROM events WHERE session=? AND event=?',
                           ('controller:' + actor['project'], event)).fetchone()
        if prior is None:
            raise Invalid('Missing original checkpoint admission')
        record = export_row(prior)  # Verify the existing journal seal and identity.
        facts = record['audit'].get('details', {})
        if (record['state'] != 'complete' or record['result'].get('effect') != 'workload_started' or
                record['result'].get('allowed') is not True or
                facts != {'unit': unit, 'launcher': initial, 'binding_sha256': digest(binding),
                          'closed_checkpoint': checkpoint}):
            raise Invalid('Original checkpoint admission changed or incomplete')
        if expected != dict(initial, cgroup=binding['subtree']['cgroup']):
            raise Invalid('Continuation child differs from admitted identity')
        verify_checkpoint_scope(db, actor, bundle, checkpoint)
        control_matches(binding['control'])
        for process in (checkpoint['monitor'], checkpoint['holder'], expected):
            control_matches(process)
        child = checkpoint_process(expected['pid'])
        monitor = checkpoint_process(checkpoint['monitor']['pid'])
        holder = checkpoint_process(checkpoint['holder']['pid'])
        outer = checkpoint_process(binding['control']['pid'])
        if (child['parent'] != checkpoint['monitor']['pid'] or
                child['executable_sha256'] != checkpoint['frontend_sha256'] or
                monitor['executable_sha256'] != checkpoint['frontend_sha256'] or
                child['mount_namespace'] != holder['mount_namespace'] or
                monitor['mount_namespace'] != outer['mount_namespace'] or
                child['mount_namespace'] == monitor['mount_namespace']):
            raise Invalid('Continuation ancestry, frontend or mount identity changed')
        continuation = 'native_continue:' + digest([unit, initial])
        if db.execute('SELECT 1 FROM events WHERE session=? AND event=?',
                      ('controller:' + actor['project'], continuation)).fetchone():
            raise Invalid('Native continuation already attempted; no automatic replay')
        subtree = ExecutionSubtree.reopen(binding['subtree'])
        try:
            # Intent failure cannot leave a resumed child. Completion failure
            # retains uncertainty and terminates the entire owned domain.
            try:
                store.lifecycle(db, actor['project'], 'workload_continue', session=actor['id'],
                                event=continuation, facts={'unit': unit, 'admission': event,
                                'child': expected, 'binding_sha256': digest(binding)}, pending=True)
                result = subtree.continue_stopped(expected)
                store.complete(db, 'controller:' + actor['project'], continuation,
                               {'allowed': True, 'level': 'allow',
                                'effect': 'closed_checkpoint_continued', 'unit': unit})
                return result
            except BaseException:
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
