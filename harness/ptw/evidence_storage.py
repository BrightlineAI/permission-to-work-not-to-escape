"""Bounded storage for existing controller evidence; no second action journal."""
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time

from .policy import Invalid, canonical, digest, save, scope

DEFAULT = {'version': 1, 'project_bytes': 1073741824, 'content_resources': []}
PAYLOAD_BYTES = 262144
RETENTION_SECONDS = 30 * 86400
# A workspace read can return 8 MiB with sixfold JSON escaping. Reserve that
# bound plus metadata and a conservative fourfold SQLite/journal allowance.
COMPLETION_BYTES = 256 * 1024 * 1024
ROW_OVERHEAD = 8192


class QuotaError(OSError):
    pass


def charge(value):
    return ROW_OVERHEAD + 4 * len(canonical(value).encode())


def event_charge(session, event, request_hash, meta, response, state, at):
    # Match usage()'s representation, including escaping of private replay JSON.
    return charge({'session': session, 'event': event, 'request_hash': request_hash,
                   'request_meta': canonical(meta), 'response': canonical(response) if response is not None else None,
                   'state': state, 'at': at})


def profile(value, bundle):
    if (not isinstance(value, dict) or set(value) != set(DEFAULT) or
            type(value['version']) is not int or value['version'] != 1 or
            type(value['project_bytes']) is not int or value['project_bytes'] < 65536 or
            not isinstance(value['content_resources'], list) or
            not all(isinstance(r, str) for r in value['content_resources']) or
            len(set(value['content_resources'])) != len(value['content_resources'])):
        raise Invalid('Unsupported evidence profile')
    readable = scope(bundle['policy']['project']['grants'])
    if any('read' not in readable.get(r, set()) for r in value['content_resources']):
        raise Invalid('Content capture requires an already reviewed readable resource')
    return copy.deepcopy(value)


def backup(store, db):
    """Keep a stopped snapshot, never a silently restorable live authority."""
    path = store.directory / ('migration-' + secrets.token_hex(12) + '.sqlite3')
    os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
    target = sqlite3.connect(path)
    target.create_function('ptw_evidence_runtime', 0, lambda: 1)
    try:
        db.backup(target)
        target.execute("UPDATE projects SET stopped=1,reason=CASE WHEN stopped=1 THEN reason "
                       "ELSE 'Migration backup: resolve effects before reviewed recovery' END")
        target.commit()
    finally:
        target.close()
    with path.open('rb') as handle:
        os.fsync(handle.fileno())
    save(path.with_suffix('.json'), {'schema': 1, 'database': path.name,
         'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'restore': 'stopped_operator_review_only'})
    fd = os.open(store.directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return path.name


def migrate(store, db):
    version = db.execute('PRAGMA user_version').fetchone()[0]
    if version not in (0, 1, 2):
        raise Invalid('Unsupported controller evidence schema; use the matching runtime')
    if version:
        return
    if not db.in_transaction:
        db.execute('BEGIN IMMEDIATE')
    try:
        db.execute('CREATE TABLE evidence_profiles(project TEXT PRIMARY KEY, profile TEXT NOT NULL, receipt TEXT NOT NULL)')
        db.execute('CREATE TABLE evidence_payloads(session TEXT, event TEXT, project TEXT NOT NULL, '
                   'at REAL NOT NULL, sha256 TEXT NOT NULL, captured_sha256 TEXT NOT NULL, original_bytes INTEGER NOT NULL, '
                   'payload BLOB, status TEXT NOT NULL, expired_at REAL, PRIMARY KEY(session,event))')
        db.execute('CREATE TABLE evidence_pins(project TEXT, reference TEXT, PRIMARY KEY(project,reference))')
        db.execute('PRAGMA user_version=1')
        db.commit()
    except BaseException:
        db.rollback()
        raise


def guard_runtime(db):
    """Old runtimes cannot read/admit through projects after extension adoption.

    A policy's unknown JSON field alone is insufficient: old live APIs did not
    recompile it. This compatibility view requires a pure connection-local
    capability, and preserves the existing table interface for current code.
    It is not protection against a trusted host deliberately editing the DB.
    """
    if db.execute('PRAGMA user_version').fetchone()[0] == 2:
        return
    columns = [r['name'] for r in db.execute('PRAGMA table_info(projects)')]
    names = ','.join(columns)
    db.execute('ALTER TABLE projects RENAME TO projects_storage')
    db.execute('CREATE VIEW projects(' + names + ') AS SELECT ' + names +
               ' FROM projects_storage WHERE ptw_evidence_runtime()=1')
    values = ','.join('coalesce(NEW.' + c + ',0)' if c in ('stopped', 'violations', 'setup_pending')
                      else 'NEW.' + c for c in columns)
    db.execute('CREATE TRIGGER evidence_project_insert INSTEAD OF INSERT ON projects BEGIN '
               'SELECT ptw_evidence_runtime(); INSERT INTO projects_storage(' + names + ') VALUES(' + values + '); END')
    db.execute('CREATE TRIGGER evidence_project_update INSTEAD OF UPDATE ON projects BEGIN '
               'UPDATE projects_storage SET ' + ','.join(c + '=NEW.' + c for c in columns) + ' WHERE id=OLD.id; END')
    db.execute('CREATE TRIGGER evidence_project_delete INSTEAD OF DELETE ON projects BEGIN '
               'DELETE FROM projects_storage WHERE id=OLD.id; END')
    db.execute('PRAGMA user_version=2')


def configuration(db, project):
    row = db.execute('SELECT profile FROM evidence_profiles WHERE project=?', (project,)).fetchone()
    return json.loads(row[0]) if row else None


def file_usage(folder):
    return sum(p.stat().st_size + 4096 for p in folder.rglob('*') if p.is_file())


def usage(db, project, *, excluding=None):
    from .store import LEASE_SLOTS
    # Charge the entire shared fixed lock pool conservatively to each project.
    # Retained pre-pool lease inodes also consume budget; never unlink live locks.
    database = db.execute('PRAGMA database_list').fetchone()[2]
    legacy = sum(1 for p in Path(database).parent.glob('operation-*.lock')
                 if len(p.name) == len('operation-') + 64 + len('.lock')) if database else 0
    total = ROW_OVERHEAD * (1 + LEASE_SLOTS + legacy)
    # Git review retains real seeds/objects as well as the small JSON packet.
    # Include failed attempts. Ownership comes from the controller request,
    # never a worktree file. These files are not optional expiring payloads.
    if database:
        # Earlier experimental reviewers wrote a shared flat cache without
        # ownership records. Retain it and conservatively charge each project;
        # new caches live in their already-accounted checkpoint directories.
        total += file_usage(Path(database).parent / 'review-cache')
        sessions = {r[0] for r in db.execute('SELECT id FROM sessions WHERE project=?', (project,))}
        for folder in (Path(database).parent / 'git-requests').glob('*'):
            request = folder / 'request.json'
            if request.is_file():
                record = json.loads(request.read_text())
                if record.get('session') in sessions:
                    total += max(file_usage(folder), record.get('reserved_bytes', 0))
    for row in db.execute('SELECT e.* FROM events e LEFT JOIN sessions s ON s.id=e.session '
                          'WHERE s.project=? OR e.session=?', (project, 'controller:' + project)):
        if excluding == (row['session'], row['event']):
            continue
        meta = json.loads(row['request_meta'])
        total += max(charge(dict(row)), meta.get('_audit', {}).get('reserved_bytes', 0)
                     if row['state'] == 'pending' else 0)
    for table, condition in (
            ('sessions', 'project=?'), ('task_counts', 'project=?'), ('bindings', 'project=?'),
            ('workloads', 'project=?'), ('package_sets', 'project=?'),
            ('package_assessments', 'package_set IN (SELECT id FROM package_sets WHERE project=?)'),
            ('package_terminations', 'unit IN (SELECT unit FROM workloads WHERE project=?)'),
            ('evidence_profiles', 'project=?'), ('evidence_pins', 'project=?')):
        for row in db.execute('SELECT * FROM ' + table + ' WHERE ' + condition, (project,)):
            total += charge(dict(row))
    for row in db.execute('SELECT * FROM evidence_payloads WHERE project=?', (project,)):
        total += charge({k: row[k] for k in row.keys() if k != 'payload'}) + 4 * len(row['payload'] or b'')
    return total


def admit(db, project, size, *, excluding=None):
    config = configuration(db, project)
    if config and usage(db, project, excluding=excluding) + size > config['project_bytes']:
        raise QuotaError('Required evidence quota exhausted; operator review required')


def optional_payload(db, actor, bundle, event, request, response):
    config = configuration(db, actor['project'])
    if not config or not isinstance(request, dict):
        return 'omitted'
    resource = request.get('resource')
    if resource not in config['content_resources']:
        return 'omitted'
    # Recheck current grants following policy revisions; no environment, output,
    # credentials, conversations or unreviewed paths are copied by this hook.
    if 'read' not in scope(bundle['policy']['project']['grants']).get(resource, set()):
        return 'omitted_scope_changed'
    if response is not None and not response['allowed']:
        return 'omitted_not_allowed'
    action = request.get('action')
    text = (response or {}).get('content') if action == 'read' else request.get('content') if action in ('write', 'append', 'create') else None
    if not isinstance(text, str):
        return 'omitted_unsupported'
    raw = text.encode()
    payload = raw[:PAYLOAD_BYTES]
    status = 'truncated' if len(raw) > len(payload) else 'captured'
    try:
        admit(db, actor['project'], ROW_OVERHEAD + 4 * len(payload))
        db.execute('INSERT INTO evidence_payloads VALUES(?,?,?,?,?,?,?,?,?,NULL)',
                   (actor['id'], event, actor['project'], time.time(), hashlib.sha256(raw).hexdigest(),
                    hashlib.sha256(payload).hexdigest(), len(raw), payload, status))
    except (OSError, sqlite3.Error):
        return 'unavailable'
    return status


def review_packet(store, db, project, value):
    row, bundle = store.project(db, project)
    value = profile(value, bundle)
    return {'schema': 1, 'project': project, 'policy_sha256': bundle['approval']['sha256'],
            'previous_profile': configuration(db, project), 'profile': value,
            'stopped': bool(row['stopped']), 'violations': row['violations'],
            'history_sha256': digest(store._audit_events(db, project, include_lifecycle=True)),
            'notice': 'Metadata required; replay retained privately. Optional content expires only when unpinned. No stop is cleared.'}


def review(store, project, value):
    with store.locked() as db:
        return review_packet(store, db, project, value)


def adopt(store, project, value, expected, reviewer):
    # The lock spans review equality, backup and transactional adoption. Avoid
    # nested flock by composing the same connection-level review below.
    with store.locked() as db:
        packet = review_packet(store, db, project, value)
        if not isinstance(reviewer, str) or not reviewer.strip() or digest(packet) != expected:
            raise Invalid('Evidence adoption requires exact operator review')
        previous = packet['previous_profile']
        increase_only = (previous is not None and value['version'] == previous['version'] and
                         value['content_resources'] == previous['content_resources'] and
                         value['project_bytes'] > previous['project_bytes'])
        if (not increase_only and
                db.execute('SELECT 1 FROM workloads WHERE project=? AND stopped=0', (project,)).fetchone()):
            raise Invalid('Confirm running work stopped before evidence adoption')
        if usage(db, project) + charge(packet) + 65536 > value['project_bytes']:
            raise Invalid('Evidence budget cannot hold existing history and adoption receipt')
        saved = backup(store, db) if db.execute('PRAGMA user_version').fetchone()[0] < 2 else None
        db.execute('BEGIN IMMEDIATE')
        try:
            guard_runtime(db)
            db.execute('INSERT OR REPLACE INTO evidence_profiles VALUES(?,?,?)',
                       (project, canonical(value), expected))
            store.lifecycle(db, project, 'evidence_adopted', approval=expected,
                            facts={'profile': value, 'backup': saved, 'reviewer_sha256': digest(reviewer)})
            db.commit()
        except BaseException:
            db.rollback()
            raise
    return {'adopted': True, 'review_sha256': expected, 'backup': saved}


def unresolved(db, project):
    return (db.execute("SELECT 1 FROM events e LEFT JOIN sessions s ON s.id=e.session WHERE "
            "(s.project=? OR e.session=?) AND e.state!='complete' LIMIT 1", (project, 'controller:' + project)).fetchone()
            or db.execute('SELECT 1 FROM evidence_pins WHERE project=?', (project,)).fetchone())


def expire(store, project):
    with store.locked() as db:
        store.project(db, project)
        # Conservative pins: any unresolved recovery or review holds all optional
        # payloads in this project. Required replay and metadata never expire.
        if unresolved(db, project):
            return {'expired': 0, 'pinned': True}
        db.execute('PRAGMA secure_delete=ON')
        if db.execute('PRAGMA secure_delete').fetchone()[0] != 1:
            raise Invalid('Optional payload expiry requires SQLite secure_delete')
        now = time.time()
        cursor = db.execute("UPDATE evidence_payloads SET payload=NULL,status='expired',expired_at=? "
                            'WHERE project=? AND payload IS NOT NULL AND at<?', (now, project, now - RETENTION_SECONDS))
        return {'expired': cursor.rowcount, 'pinned': False}


def archive(store, project, destination):
    with store.locked() as db:
        row, _ = store.project(db, project)
        if (not row['stopped'] or db.execute('SELECT 1 FROM sessions WHERE project=? AND closed=0', (project,)).fetchone()
                or db.execute('SELECT 1 FROM workloads WHERE project=? AND stopped=0', (project,)).fetchone()
                or db.execute('SELECT 1 FROM evidence_pins WHERE project=?', (project,)).fetchone()
                or any(r['state'] != 'complete' for r in store._audit_events(db, project, include_lifecycle=True))):
            raise Invalid('Archive requires closed history without unresolved effects or reviews')
        document = store._audit_export(db, project)
        # Deliberately export metadata only; exporting required replay would copy
        # session secrets and diagnostics. This is not a database restore image.
        private_export(destination, document)
        return {'archived': True, 'sha256': digest(document), 'events': document['manifest']['count'],
                'required_history_deleted': False, 'content': 'omitted'}


def private_export(destination, document):
    destination = Path(destination).absolute()
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if destination.parent.resolve() != destination.parent or destination.parent.stat().st_mode & 0o077:
        raise Invalid('Export directory must be canonical and private (0700)')
    save(destination, document)
