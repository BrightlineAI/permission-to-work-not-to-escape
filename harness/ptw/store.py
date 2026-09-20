"""Protected single host broker. Agents never open this database or supply identity."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import time

from .policy import Invalid, canonical, check_approval, data_directory, digest, open_resource, scope, subset

MAX_BYTES = 1_048_576
LEASE_SLOTS = 64
_operation = ContextVar('ptw_operation', default=None)


def operation_lease(session, event):
    # Fixed, never-unlinked inodes avoid both per-request growth and unlink races.
    return 'slot-' + str(int(digest([session, event]), 16) % LEASE_SLOTS)


class Store:
    def __init__(self, directory):
        self.directory = Path(directory).absolute()
        data_directory(self.directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.directory.resolve() != self.directory or self.directory.stat().st_mode & 0o077:
            raise Invalid("State directory must be canonical and private (mode 0700)")
        self.db = self.directory / "state.sqlite3"
        if not self.db.exists():
            try:
                os.close(os.open(self.db, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
            except FileExistsError:
                pass
        if self.db.is_symlink() or self.db.stat().st_mode & 0o077:
            raise Invalid("Database must be private and not a symlink")
        with self.locked() as db:
            if db.execute('PRAGMA user_version').fetchone()[0] not in (0, 1, 2):
                raise Invalid('Unsupported controller evidence schema; use the matching runtime')
            if (db.execute('PRAGMA user_version').fetchone()[0] == 0 and
                    db.execute("SELECT 1 FROM sqlite_master WHERE name='projects'").fetchone()):
                from .evidence_storage import backup
                backup(self, db)
            db.executescript("""
                CREATE TABLE IF NOT EXISTS projects(
                  id TEXT PRIMARY KEY, bundle TEXT NOT NULL, stopped INTEGER DEFAULT 0,
                  violations INTEGER DEFAULT 0, reason TEXT DEFAULT NULL);
                CREATE TABLE IF NOT EXISTS task_counts(
                  project TEXT, task TEXT, violations INTEGER DEFAULT 0, PRIMARY KEY(project,task));
                CREATE TABLE IF NOT EXISTS sessions(
                  id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, project TEXT NOT NULL,
                  task TEXT NOT NULL, parent TEXT, grants TEXT NOT NULL, depth INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS events(
                  session TEXT, event TEXT, request_hash TEXT NOT NULL, request_meta TEXT NOT NULL,
                  response TEXT, state TEXT NOT NULL, at REAL NOT NULL, PRIMARY KEY(session,event));
                CREATE TABLE IF NOT EXISTS bindings(
                  project TEXT, resource TEXT, device INTEGER, inode INTEGER,
                  PRIMARY KEY(project,resource));
                CREATE TABLE IF NOT EXISTS workloads(
                  unit TEXT PRIMARY KEY, project TEXT NOT NULL, session TEXT NOT NULL,
                  stopped INTEGER DEFAULT 0);
                CREATE TABLE IF NOT EXISTS package_sets(
                  id TEXT PRIMARY KEY, project TEXT NOT NULL, names TEXT NOT NULL,
                  manifest TEXT NOT NULL, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS monitor_health(
                  id INTEGER PRIMARY KEY, at REAL NOT NULL, error TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS previews(
                  session TEXT, command TEXT, unit TEXT NOT NULL, directory TEXT NOT NULL,
                  PRIMARY KEY(session,command));
                CREATE TABLE IF NOT EXISTS package_assessments(
                  attempt TEXT PRIMARY KEY, package_set TEXT NOT NULL, at REAL NOT NULL,
                  outcome TEXT NOT NULL, detail TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS workload_packages(
                  unit TEXT, package_set TEXT, PRIMARY KEY(unit,package_set));
                CREATE TABLE IF NOT EXISTS package_terminations(
                  unit TEXT, at REAL, outcome TEXT NOT NULL);
            """)
            db.execute('BEGIN IMMEDIATE')
            columns = {r[1] for r in db.execute('PRAGMA table_info(package_sets)')}
            for name, declaration in [('evidence', 'TEXT'), ('assessment_state', "TEXT NOT NULL DEFAULT 'blocked'"),
                                      ('assessment_reason', 'TEXT'), ('assessment_generation', 'INTEGER NOT NULL DEFAULT 0')]:
                if name not in columns:
                    db.execute('ALTER TABLE package_sets ADD COLUMN ' + name + ' ' + declaration)
            if "packages" not in {r[1] for r in db.execute("PRAGMA table_info(sessions)")}:
                db.execute("ALTER TABLE sessions ADD COLUMN packages TEXT NOT NULL DEFAULT '[]'")
            if "ecosystem" not in {r[1] for r in db.execute("PRAGMA table_info(package_sets)")}:
                db.execute("ALTER TABLE package_sets ADD COLUMN ecosystem TEXT NOT NULL DEFAULT 'pypi'")
            if "policy_sha256" not in {r[1] for r in db.execute("PRAGMA table_info(package_sets)")}:
                db.execute("ALTER TABLE package_sets ADD COLUMN policy_sha256 TEXT")
            if 'local_source' not in {r[1] for r in db.execute('PRAGMA table_info(package_sets)')}:
                db.execute("ALTER TABLE package_sets ADD COLUMN local_source TEXT")
            if 'dependency_revision' not in {r[1] for r in db.execute('PRAGMA table_info(projects)')}:
                db.execute('ALTER TABLE projects ADD COLUMN dependency_revision TEXT')
            if "commands" not in {r[1] for r in db.execute("PRAGMA table_info(sessions)")}:
                db.execute("ALTER TABLE sessions ADD COLUMN commands TEXT NOT NULL DEFAULT '[]'")
            if "closed" not in {r[1] for r in db.execute("PRAGMA table_info(sessions)")}:
                db.execute("ALTER TABLE sessions ADD COLUMN closed INTEGER NOT NULL DEFAULT 0")
            for name in ('conversation', 'resume_of'):
                if name not in {r[1] for r in db.execute('PRAGMA table_info(sessions)')}:
                    db.execute('ALTER TABLE sessions ADD COLUMN ' + name + ' TEXT')
            if 'preparation_source' not in {r[1] for r in db.execute('PRAGMA table_info(sessions)')}:
                db.execute('ALTER TABLE sessions ADD COLUMN preparation_source TEXT')
            if "setup_pending" not in {r[1] for r in db.execute("PRAGMA table_info(projects)")}:
                db.execute("ALTER TABLE projects ADD COLUMN setup_pending INTEGER NOT NULL DEFAULT 0")
            from .evidence_storage import migrate
            migrate(self, db)
            db.commit()
            # Lock spans intent commit, effect and completion. A pending row visible after
            # acquiring it means the previous operator died before recording completion.
            self.recover_pending(db)

    def recover_pending(self, db):
        for row in db.execute("SELECT e.*,coalesce(s.project,json_extract(e.request_meta,'$._audit.project')) AS project "
                              "FROM events e LEFT JOIN sessions s ON s.id=e.session "
                              "WHERE e.state='pending'").fetchall():
            lease = json.loads(row['request_meta']).get('_audit', {}).get('lease')
            fd = None
            try:
                if lease is not None:
                    if lease not in (digest([row['session'], row['event']]),
                                     operation_lease(row['session'], row['event'])):
                        raise Invalid('Invalid operation lease')
                    fd = os.open(self.directory / ('operation-' + lease + '.lock'),
                                 os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        continue  # The originating controller still owns this operation.
                meta = json.loads(row['request_meta'])
                sid = meta.get('_audit', {}).get('session') or row['session']
                session = db.execute('SELECT closed FROM sessions WHERE id=?', (sid,)).fetchone()
                # A surrendered operation still has an uncertain outcome, but
                # its authority is already revoked. Do not stop its siblings.
                if not (session and (session['closed'] or sid in self.closing_sessions(db))):
                    self.stop_from_db(db, row['project'], 'uncertain effect after interrupted request; operator review required')
                self.complete(db, row['session'], row['event'], None, state='uncertain')
            finally:
                if fd is not None:
                    os.close(fd)

    @contextmanager
    def operation(self, token, event, *, related_events=()):
        """Lease a long operation across controller-lock releases, never its effects.

        Reserve nested events together in slot order before any intent/effect.
        Nested calls reuse these descriptors; acquiring another slot while one
        is held could deadlock even when the two events hash to different slots.
        A dead process releases flock, allowing recovery to retain uncertainty.
        """
        if not isinstance(event, str) or not 1 <= len(event) <= 128:
            raise Invalid('Stable event ID required')
        with self.locked() as db:
            actor = self.session(db, token)
        events = (event, *related_events)
        if any(not isinstance(item, str) or not 1 <= len(item) <= 128 for item in events):
            raise Invalid('Stable event ID required')
        keys = {(actor['id'], item) for item in events}
        parent = _operation.get()
        if parent:
            if parent['directory'] != self.directory or not keys <= parent['held']['events']:
                raise Invalid('Nested operation must be reserved by its outer operation')
            held = parent['held']
        else:
            held = {'events': keys, 'started': False}
        fds = []
        marker = None
        context = {'directory': self.directory, 'session': actor['id'], 'event': event,
                   'started': False, 'held': held}
        try:
            if parent is None:
                for identity in sorted({operation_lease(*key) for key in keys}):
                    fd = os.open(self.directory / ('operation-' + identity + '.lock'),
                                 os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
                    fds.append(fd)
                    fcntl.flock(fd, fcntl.LOCK_EX)
            marker = _operation.set(context)
            yield
        finally:
            if marker is not None:
                _operation.reset(marker)
            for fd in reversed(fds):
                os.close(fd)
            # Completion can fail after an effect. Never leave that project
            # launchable until a later Store construction happens to recover it.
            if parent is None and held['started']:
                with self.locked() as db:
                    self.recover_pending(db)

    def owns_pending(self, session, event):
        active = _operation.get()
        return bool(active and active['directory'] == self.directory and
                    (active['session'], active['event']) == (session, event) and active['started'])

    def capture_fault(self, db, project):
        """Authority reduction must not depend on successful evidence storage.

        A failed durable update is not reported as closure or confirmation. The
        existing supervisor still gets a best-effort physical stop request.
        """
        db.rollback()
        try:
            # Do not recursively require an event to reduce authority when the
            # event writer itself failed. Missing capture remains an explicit gap.
            db.execute('UPDATE projects SET stopped=1,reason=? WHERE id=?',
                       ('required evidence capture failed; operator review required', project))
        except (OSError, sqlite3.Error):
            pass
        self.terminate_workloads(db, project=project)

    @contextmanager
    def locked(self):
        fd = os.open(self.directory / "controller.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        db = None
        try:
            db = sqlite3.connect(self.db, timeout=30, isolation_level=None)
            db.row_factory = sqlite3.Row
            db.create_function('ptw_evidence_runtime', 0, lambda: 1)
            db.execute("PRAGMA synchronous=FULL")
            yield db
        finally:
            if db is not None:
                db.close()
            os.close(fd)

    def activate(self, bundle, *, setup_pending=False, discovery_sha256=None):
        checked = check_approval(bundle)
        if not setup_pending and any(s['mode'] == 'discovery' for s in
                checked['policy']['project'].get('python_dependencies', {}).get('sources', [])):
            raise Invalid('Discovery requires pending setup')
        inv = checked["inventory"]
        root = Path(inv["root"])
        if self.directory == root or self.directory.is_relative_to(root) or root.is_relative_to(self.directory):
            raise Invalid("Resource root and protected state must be separate trees")
        project = checked["policy"]["project"]["id"]
        with self.locked() as db:
            existing = db.execute("SELECT 1 FROM projects WHERE id=?", (project,)).fetchone()
            if discovery_sha256 is not None:
                row, old = self.project(db, project)
                sources = old['policy']['project'].get('python_dependencies', {}).get('sources', [])
                if (not setup_pending or row['stopped'] or not row['setup_pending'] or
                        old['approval']['sha256'] != discovery_sha256 or not sources or
                        old['inventory']['root'] != inv['root'] or
                        {t['id'] for t in old['policy']['tasks']} != {t['id'] for t in checked['policy']['tasks']}):
                    raise Invalid('Discovery refinement requires the same unstopped pending project')
                if (db.execute('SELECT 1 FROM sessions WHERE project=? AND closed=0', (project,)).fetchone() or
                        db.execute('SELECT 1 FROM workloads WHERE project=? AND stopped=0', (project,)).fetchone()):
                    raise Invalid('Discovery sessions and workloads must end before refinement')
                from .workspace import Workspace, scan
                from .python_local import snapshot_digest
                Workspace(self).integrity(db, project, old)
                if db.execute('SELECT 1 FROM package_sets WHERE project=?', (project,)).fetchone():
                    raise Invalid('Discovery refinement cannot reuse a prepared installation')
                for source in sources:
                    if snapshot_digest(scan(old['inventory'], source['resources'])) != source['snapshot_sha256']:
                        raise Invalid('Source changed since discovery review')
                    if source['mode'] != 'discovery':
                        # Static hook discovery may refine packages, not source
                        # identity, build mode or mutability. Resource IDs can
                        # shift when final setup adds generated metadata files.
                        def binding(item, inventory):
                            value = dict(item)
                            # Explicit refinement may change this source's
                            # assessed build graph, but not its source authority.
                            value.pop('build_dependencies', None)
                            for field in ('resources', 'editable_resources'):
                                if field in value:
                                    value[field] = sorted(inventory['resources'][r]['path'] for r in value[field])
                            return value
                        candidates = checked['policy']['project'].get('python_dependencies', {}).get('sources', [])
                        if not any(binding(candidate, inv) == binding(source, old['inventory']) for candidate in candidates):
                            raise Invalid('Static hook review cannot change its approved source binding')
            elif existing:
                raise Invalid("Project identity already exists; approval cannot reset history")
            if ('audit' in checked['policy']['project'] and
                    db.execute('PRAGMA user_version').fetchone()[0] < 2 and
                    db.execute('SELECT 1 FROM projects LIMIT 1').fetchone()):
                from .evidence_storage import backup
                backup(self, db)
            db.execute("BEGIN IMMEDIATE")
            if discovery_sha256 is not None:
                db.execute('UPDATE projects SET bundle=? WHERE id=?', (canonical(bundle), project))
                db.execute('DELETE FROM bindings WHERE project=?', (project,))
            else:
                db.execute("INSERT INTO projects(id,bundle,setup_pending) VALUES(?,?,?)",
                           (project, canonical(bundle), int(setup_pending)))
                for task in checked["policy"]["tasks"]:
                    db.execute("INSERT INTO task_counts(project,task) VALUES(?,?)", (project, task["id"]))
            for name, resource in inv["resources"].items():
                if checked["policy"]["version"] == 4:
                    from .workspace_policy import resource_info
                    info = resource_info(inv, name)
                    db.execute("INSERT INTO bindings VALUES(?,?,?,?)",
                               (project, name, info.st_dev if info else 0, info.st_ino if info else 0))
                    continue
                fd = open_resource(inv, resource["path"], os.O_RDONLY)
                try:
                    info = os.fstat(fd)
                    db.execute("INSERT INTO bindings VALUES(?,?,?,?)", (project, name, info.st_dev, info.st_ino))
                finally:
                    os.close(fd)
            if checked["policy"]["version"] == 4:
                info = root.stat()
                db.execute("INSERT INTO bindings VALUES(?,?,?,?)", (project, "", info.st_dev, info.st_ino))
            if 'audit' in checked['policy']['project']:
                from .evidence_storage import guard_runtime, profile
                value = profile(checked['policy']['project']['audit'], bundle)
                guard_runtime(db)
                db.execute('INSERT OR REPLACE INTO evidence_profiles VALUES(?,?,?)',
                           (project, canonical(value), bundle['approval']['sha256']))
            self.lifecycle(db, project, 'policy_activated' if discovery_sha256 is None else 'policy_revised',
                           facts={'previous_policy_sha256': discovery_sha256},
                           approval=bundle['approval']['sha256'])
            db.commit()
        return {"project": project, "policy_sha256": bundle["approval"]["sha256"]}

    def commit_setup(self, project, policy_sha256, validate_artifacts):
        """The only onboarding launchability boundary, under the controller lock."""
        with self.locked() as db:
            row, bundle = self.project(db, project)
            if row["stopped"] or bundle["approval"]["sha256"] != policy_sha256:
                raise Invalid("Stopped or mismatched setup cannot commit")
            check_approval(bundle)
            if any(s['mode'] == 'discovery' for s in
                   bundle['policy']['project'].get('python_dependencies', {}).get('sources', [])):
                raise Invalid('Discovery approval cannot make a project ready')
            from .workspace import Workspace
            Workspace(self).integrity(db, project, bundle)
            validate_artifacts()
            if db.execute('SELECT 1 FROM sessions WHERE project=? AND preparation_source IS NOT NULL '
                          'AND closed=0', (project,)).fetchone():
                raise Invalid('Preparation sessions must end before setup can commit')
            if db.execute('SELECT 1 FROM workloads w JOIN sessions s ON w.session=s.id '
                          'WHERE w.project=? AND s.preparation_source IS NOT NULL AND w.stopped=0',
                          (project,)).fetchone():
                raise Invalid('Preparation termination must be confirmed before setup can commit')
            db.execute('BEGIN IMMEDIATE')
            db.execute("UPDATE projects SET setup_pending=0 WHERE id=?", (project,))
            self.lifecycle(db, project, 'setup_committed')
            db.commit()

    @staticmethod
    def session(db, token, *, preparation=False):
        if not isinstance(token, str) or len(token) < 20:
            raise Invalid("Unknown session credential")
        row = db.execute("SELECT * FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
        if row is None:
            raise Invalid("Unknown session credential")
        if row["closed"] or row['id'] in Store.closing_sessions(db):
            raise Invalid("Session ended; its credential and descendants are no longer active")
        if row['preparation_source'] is not None:
            if not preparation:
                raise Invalid('Preparation session cannot perform ordinary project actions')
            project = db.execute('SELECT stopped,setup_pending FROM projects WHERE id=?', (row['project'],)).fetchone()
            if project is None or project['stopped'] or not project['setup_pending']:
                raise Invalid('Preparation requires an unstopped pending setup')
        return row

    def register_preparation(self, project, task, identity, policy_sha256):
        """Trusted setup adapter only: one approved source, read-only, no delegation.

        Unlike ordinary registration, this credential cannot reach general tools.
        Its use must opt into the preparation boundary at every admission point.
        """
        with self.locked() as db:
            row, bundle = self.project(db, project)
            if row['stopped'] or not row['setup_pending'] or bundle['approval']['sha256'] != policy_sha256:
                raise Invalid('Preparation requires the exact approved pending setup')
            check_approval(bundle)
            descriptor = bundle['policy']['project'].get('python_dependencies', {})
            source = next((s for s in descriptor.get('sources', []) if s['id'] == identity), None)
            target = next((t for t in bundle['policy']['tasks'] if t['id'] == task), None)
            if source is None or not source['allow_build'] or target is None:
                raise Invalid('Preparation needs an explicitly approved source and task')
            allowed = scope(target['grants'])
            if any('read' not in allowed.get(r, set()) for r in source['resources']):
                raise Invalid('Preparation source exceeds task read grants')
            from .package_evidence import pins
            names = sorted('pypi:' + n for n in pins(descriptor['pins'], extras={})) if descriptor['pins'] else []
            from .dependency_binding import source_graph
            build = source_graph(descriptor, identity)
            names = sorted(set(names) | {'pypi:' + n for n in (pins(build['pins'], extras={}) if build['pins'] else {})})
            if not set(names) <= set(target.get('packages', [])):
                raise Invalid('Preparation dependencies exceed task package grants')
            if db.execute('SELECT 1 FROM sessions WHERE project=? AND preparation_source IS NOT NULL '
                          'AND closed=0', (project,)).fetchone():
                raise Invalid('Setup already has an active preparation session')
            sid, token = 'agent_' + secrets.token_hex(8), secrets.token_urlsafe(32)
            grants = [{'resource': r, 'actions': ['read']} for r in source['resources']]
            db.execute('BEGIN IMMEDIATE')
            db.execute('INSERT INTO sessions(id,token_hash,project,task,parent,grants,depth,packages,commands,preparation_source) '
                       'VALUES(?,?,?,?,NULL,?,0,?,?,?)',
                       (sid, hashlib.sha256(token.encode()).hexdigest(), project, task,
                        canonical(grants), canonical(names), '[]', identity))
            self.lifecycle(db, project, 'session_registered', session=sid,
                           event='session_registered:' + sid, facts={'preparation_source': identity})
            db.commit()
            return {'session': sid, 'token': token, 'project': project, 'task': task,
                    'parent': None, 'grants': grants, 'packages': names, 'commands': [],
                    'preparation_source': identity}

    @staticmethod
    def closing_sessions(db):
        """Existing lifecycle intent remains restrictive if flag storage fails."""
        return [r[0] for r in db.execute('''WITH RECURSIVE closing(id) AS (
            SELECT s.id FROM sessions s JOIN events e
              ON e.session='controller:' || s.project AND e.event='session_closing:' || s.id
              WHERE s.closed=0
            UNION SELECT s.id FROM sessions s JOIN closing c ON s.parent=c.id
            ) SELECT id FROM closing''')]

    def close_session(self, token, *, outcome='closed', note=''):
        """Revoke one session and its descendants without stopping other parents."""
        if not isinstance(token, str) or len(token) < 20:
            raise Invalid('Unknown session credential')
        with self.locked() as db:
            row = db.execute("SELECT * FROM sessions WHERE token_hash=?",
                             (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
            if row is None:
                raise Invalid("Unknown session credential")
            # Revocation is durable before capture: failure must not reopen it.
            tree = [r[0] for r in db.execute('''WITH RECURSIVE tree(id) AS (
                SELECT id FROM sessions WHERE id=?
                UNION ALL SELECT s.id FROM sessions s JOIN tree t ON s.parent=t.id
                ) SELECT id FROM tree''', (row['id'],))]
            if row['closed']:
                prior = db.execute("SELECT request_meta FROM events WHERE session=? AND "
                    "json_extract(request_meta,'$.action') IN ('session_closed','session_closing') AND "
                    "json_extract(request_meta,'$._audit.session')=? "
                    "ORDER BY json_extract(request_meta,'$.action')='session_closed' DESC,rowid LIMIT 1",
                    ('controller:' + row['project'], row['id'])).fetchone()
                facts = json.loads(prior[0])['_audit']['details'] if prior else {}
                return {'closed': True, 'confirmed_stopped': False, 'sessions': tree,
                        'outcome': facts.get('outcome', 'closed'), 'replayed': True,
                        'evidence': 'recorded' if prior and json.loads(prior[0])['action'] == 'session_closed' else 'unavailable'}
            event = 'session_closing:' + row['id']
            intent = db.execute('SELECT request_meta FROM events WHERE session=? AND event=?',
                                ('controller:' + row['project'], event)).fetchone()
            if intent:
                outcome = json.loads(intent[0])['_audit']['details']['outcome']
            else:
                # Reuse lifecycle storage, not an emergency journal. Even when
                # capture/quota fails, still attempt the authority reduction.
                self.lifecycle(db, row['project'], 'session_closing', session=row['id'], event=event,
                    facts={'outcome': outcome, 'note_sha256': digest(note),
                           'termination': 'unconfirmed'}, reduction=True)
            try:
                db.execute('BEGIN IMMEDIATE')
                db.executemany('UPDATE sessions SET closed=1 WHERE id=?', [(sid,) for sid in tree])
                db.commit()
                captured = self.lifecycle(db, row['project'], 'session_closed', session=row['id'],
                    facts={'closed_sessions': tree, 'termination': 'unconfirmed',
                           'outcome': outcome, 'note_sha256': digest(note)}, reduction=True)
            except (OSError, sqlite3.Error):
                db.rollback()
                if row['id'] not in self.closing_sessions(db):
                    # Both forms of subtree persistence failed. Existing capture
                    # recovery is conservative; never claim durable revocation.
                    self.capture_fault(db, row['project'])
                self.terminate_workloads(db, sessions=tree)
                raise
            if not captured:
                self.terminate_workloads(db, sessions=tree)
            return {'closed': True, 'confirmed_stopped': False, 'sessions': tree,
                    'outcome': outcome, 'replayed': bool(intent),
                    'evidence': 'recorded' if captured else 'unavailable'}

    def terminate_workloads(self, db, *, sessions=None, project=None):
        """Best effort only; no database success or physical cessation is inferred."""
        from .supervisor import Supervisor
        for row in db.execute('SELECT unit,session,project FROM workloads WHERE stopped=0').fetchall():
            if row['project'] != project and row['session'] not in (sessions or []):
                continue
            try:
                Supervisor(self).terminate(row['unit'])
            except (Invalid, OSError, subprocess.SubprocessError):
                pass

    @staticmethod
    def project(db, project):
        row = db.execute("SELECT * FROM projects WHERE id=?", (project,)).fetchone()
        if row is None:
            raise Invalid("Unknown project")
        return row, json.loads(row["bundle"])

    def register(self, project, task, *, parent_token=None, grants=None, packages=None, commands=None,
                 conversation=None, resumed=False):
        """Trusted operator registers parents; authenticated delegation may only narrow."""
        with self.locked() as db:
            row, bundle = self.project(db, project)
            if row["stopped"]:
                raise Invalid("Project stopped")
            if row["setup_pending"]:
                raise Invalid("Project setup is pending recovery; no sessions may start")
            target = next((t for t in bundle["policy"]["tasks"] if t["id"] == task), None)
            if target is None:
                raise Invalid("Unknown task")
            allowed = scope(target["grants"])
            package_names = target.get("packages", []) if packages is None else packages
            if (not isinstance(package_names, list) or not all(isinstance(x, str) for x in package_names)
                    or not set(package_names) <= set(target.get("packages", []))):
                raise Invalid("Session expands task package scope")
            requested = scope(grants) if grants is not None else allowed
            if not subset(requested, allowed):
                raise Invalid("Session expands task scope")
            command_names = target.get("commands", []) if commands is None else commands
            if (not isinstance(command_names, list) or not all(isinstance(x, str) for x in command_names)
                    or not set(command_names) <= set(target.get("commands", []))):
                raise Invalid("Session expands task command scope")
            definitions = {c["id"]: c for c in bundle["policy"]["project"].get("commands", [])}
            if any("read" not in requested.get(r, set()) for c in command_names for r in definitions[c]["resources"]):
                raise Invalid("Session command requires readable inputs")
            parent_id, depth = None, 0
            previous = None
            if conversation is not None:
                from .conversation import native_id
                native_id(conversation)
                if parent_token:
                    raise Invalid('Delegate cannot bind an operator conversation')
                previous = db.execute('SELECT * FROM sessions WHERE conversation=? ORDER BY rowid DESC LIMIT 1',
                                      (conversation,)).fetchone()
                if previous is not None and (not resumed or not previous['closed'] or
                        previous['project'] != project or previous['task'] != task):
                    raise Invalid('Conversation requires the same closed project/task session')
            elif resumed:
                raise Invalid('Resume requires a protected conversation binding')
            if parent_token:
                parent = self.session(db, parent_token)
                if parent["project"] != project or not subset(requested, scope(json.loads(parent["grants"]))):
                    raise Invalid("Delegate expands parent scope or changes project")
                if not set(package_names) <= set(json.loads(parent["packages"])):
                    raise Invalid("Delegate expands parent package scope")
                if not set(command_names) <= set(json.loads(parent["commands"])):
                    raise Invalid("Delegate expands parent command scope")
                parent_id, depth = parent["id"], parent["depth"] + 1
                if depth > 16:
                    raise Invalid("Maximum delegation depth reached")
            sid = "agent_" + secrets.token_hex(8)
            token = secrets.token_urlsafe(32)
            serialized = [{"resource": r, "actions": sorted(a)} for r, a in sorted(requested.items())]
            db.execute('BEGIN IMMEDIATE')
            db.execute("INSERT INTO sessions(id,token_hash,project,task,parent,grants,depth,packages,commands,conversation,resume_of) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                       (sid, hashlib.sha256(token.encode()).hexdigest(), project, task,
                        parent_id, canonical(serialized), depth, canonical(sorted(set(package_names))),
                        canonical(sorted(set(command_names))), conversation, previous['id'] if previous else None))
            self.lifecycle(db, project, 'session_registered', session=sid,
                           event='session_registered:' + sid,
                           facts={'resumed': resumed, 'resume_coverage':
                                  'linked' if previous else 'legacy_unknown' if resumed else 'new'})
            db.commit()
            return {"session": sid, "project": project, "task": task, "parent": parent_id,
                    "token": token, "grants": serialized, "packages": sorted(set(package_names)),
                    "commands": sorted(set(command_names))}

    @staticmethod
    def reason(request, allowed):
        if not isinstance(request, dict) or set(request) != {"action", "resource", "content"}:
            return "malformed request"
        action, resource, content = (request[k] for k in ["action", "resource", "content"])
        if not all(isinstance(v, str) for v in [action, resource, content]):
            return "malformed request"
        if action not in allowed.get(resource, set()):
            return "outside task or delegated scope"
        if action == "read" and content:
            return "read must not carry write content"
        try:
            size = len(content.encode())
        except UnicodeError:
            return "invalid text encoding"
        if size > MAX_BYTES:
            return "request too large"
        return None

    def request(self, token, event, request):
        result = self._request(token, event, request)
        # Durable denial precedes termination. Failed stop confirmation stays visible
        # and is retried by reconcile/watch, never mislabeled as a completed stop.
        from .supervisor import Supervisor
        outcomes = Supervisor(self).reconcile()
        if outcomes:
            result = {**result, "termination": outcomes}
        return result

    def _request(self, token, event, request):
        if not isinstance(event, str) or not 1 <= len(event) <= 128:
            raise Invalid("Stable event ID required, 1 to 128 characters")
        request_hash = digest(request)
        with self.locked() as db:
            actor = self.session(db, token)
            project, bundle = self.project(db, actor["project"])
            if bundle["policy"]["version"] == 4:
                raise Invalid("Use repository actions for version 4; legacy file requests lack edit preconditions")
            prior = db.execute("SELECT * FROM events WHERE session=? AND event=?", (actor["id"], event)).fetchone()
            if prior:
                if prior["request_hash"] != request_hash:
                    raise Invalid("Event ID reused with different request")
                if prior["state"] != "complete":
                    return {"allowed": False, "effect": "unknown", "level": "stop",
                            "reason": "Previous request outcome uncertain; do not retry"}
                return {**json.loads(prior["response"]), "replayed": True}
            reason = self.reason(request, scope(json.loads(actor["grants"])))
            if project["stopped"]:
                response = {"allowed": False, "effect": "none", "level": "stop", "reason": "project stopped"}
            elif reason:
                return self.deny(db, actor, project, bundle, event, request_hash, request, reason)
            else:
                # Intent is durable before an effect. Crash recovery stops this project,
                # rather than silently duplicating an append with an uncertain outcome.
                self.begin(db, actor['id'], event, request_hash, request)
                try:
                    response = self.effect(db, actor["project"], bundle["inventory"], request)
                except (OSError, Invalid, UnicodeError) as exc:
                    response = {"allowed": False, "effect": "unknown", "level": "stop", "reason": "resource failure: " + type(exc).__name__}
                    self.stop_from_db(db, actor['project'], 'resource integrity or execution failure')
                self.complete(db, actor['id'], event, response)
                return response
            self.record(db, actor["id"], event, request_hash, request, response)
            return response

    def deny(self, db, actor, project, bundle, event, request_hash, request, reason):
        """The same counter transition for every controlled effect."""
        pending = db.execute('SELECT request_hash,state FROM events WHERE session=? AND event=?',
                             (actor['id'], event)).fetchone()
        if pending and self.owns_pending(actor['id'], event):
            if pending['state'] != 'pending' or pending['request_hash'] != request_hash:
                raise Invalid('Operation intent changed')
        db.execute("BEGIN IMMEDIATE")
        db.execute("UPDATE projects SET violations=violations+1 WHERE id=?", (actor["project"],))
        tasks = {actor["task"]}
        parent_id = actor["parent"]
        while parent_id:
            ancestor = db.execute("SELECT task,parent FROM sessions WHERE id=?", (parent_id,)).fetchone()
            tasks.add(ancestor["task"])
            parent_id = ancestor["parent"]
        for task_id in tasks:
            db.execute("UPDATE task_counts SET violations=violations+1 WHERE project=? AND task=?", (actor["project"], task_id))
        total = project["violations"] + 1
        task_count = db.execute("SELECT violations FROM task_counts WHERE project=? AND task=?", (actor["project"], actor["task"])).fetchone()[0]
        pe = bundle["policy"]["project"]["escalation"]
        stop, warn = total >= pe["stop_at"], total >= pe["warn_at"]
        for task in bundle["policy"]["tasks"]:
            if task["id"] in tasks:
                count = db.execute("SELECT violations FROM task_counts WHERE project=? AND task=?", (actor["project"], task["id"])).fetchone()[0]
                stop = stop or count >= task["escalation"]["stop_at"]
                warn = warn or count >= task["escalation"]["warn_at"]
        if stop:
            db.execute("UPDATE projects SET stopped=1, reason=? WHERE id=?", ("violation threshold", actor["project"]))
        response = {"allowed": False, "effect": "none", "level": "stop" if stop else "warn" if warn else "deny",
                    "reason": reason, "project_violations": total, "task_violations": task_count}
        if pending and self.owns_pending(actor['id'], event):
            # This is a trusted authorization denial after preparation admission,
            # not an execution failure inferred from a response's allowed flag.
            self.complete(db, actor['id'], event, response, authorization_decision=response['level'])
        else:
            self.record(db, actor["id"], event, request_hash, request, response)
        if stop and not project['stopped']:
            self.lifecycle(db, actor['project'], 'admission_stopped', session=actor['id'],
                           facts={'cause': digest([actor['id'], event]), 'termination': 'unconfirmed'})
        db.commit()
        return response

    @staticmethod
    def metadata(request):
        if not isinstance(request, dict):
            return '{}'
        return canonical({**{k: request[k] for k in ('action', 'resource', 'path', 'destination', 'expected')
                             if k in request and isinstance(request[k], str)},
                          'content_sha256': digest(request.get('content'))})

    def begin(self, db, session, event, request_hash, request, *, response=None, authorization=None,
              _control=None):
        """Record authenticated provenance at admission, never from worker text.

        Short effects hold the controller lock. Long operations additionally
        hold their operation lease until their original response is recorded.
        """
        from .event_evidence import VERSION, outcome, seal, validate_response
        if response is not None:
            validate_response(response)
        prior = db.execute('SELECT * FROM events WHERE session=? AND event=?', (session, event)).fetchone()
        if prior is not None and self.owns_pending(session, event):
            if prior['state'] != 'pending' or prior['request_hash'] != request_hash:
                raise Invalid('Operation intent changed')
            if response is not None:
                self.complete(db, session, event, response)
            else:
                from .evidence_storage import admit
                project = json.loads(prior['request_meta'])['_audit']['project']
                try:
                    admit(db, project, 0)
                except OSError:
                    self.capture_fault(db, project)
                    raise
            return
        actor = (_control['actor'] if _control else
                 db.execute('SELECT * FROM sessions WHERE id=?', (session,)).fetchone())
        if actor is None:
            raise Invalid('Event requires an authenticated session')
        _, bundle = self.project(db, actor['project'])
        observed = time.time()
        meta = json.loads(self.metadata(request))
        resource = bundle['inventory']['resources'].get(meta.get('resource'))
        sequence = db.execute('SELECT coalesce(max(rowid),0)+1 FROM events').fetchone()[0]
        state = 'pending' if response is None else 'complete'
        authority = {'method': 'standing_policy', 'policy_sha256': bundle['approval']['sha256'],
                     'grants_sha256': digest({'grants': json.loads(actor['grants']),
                                             'commands': json.loads(actor['commands']),
                                             'packages': json.loads(actor['packages'])}),
                     'human_review_required': False, 'human_review_performed': False,
                     'receipt_sha256': None, 'exception': None}
        if authorization is not None:
            # Only trusted controller call sites (e.g. publish_checkpoint) use
            # this argument, after validating their exact operator receipt.
            if (set(authorization) != {'method', 'receipt_sha256'} or
                    authorization['method'] != 'exact_operator_approval' or
                    not isinstance(authorization['receipt_sha256'], str) or
                    len(authorization['receipt_sha256']) != 64):
                raise Invalid('Unsupported controller authorization')
            authority.update(authorization)
            authority.update(human_review_required=True, human_review_performed=True)
        elif response is not None and response.get('effect') == 'git_review':
            authority['human_review_required'] = True
        if _control and authorization is None:
            authority['method'] = ('standing_policy' if _control['requester']['kind'] in
                                   ('local_operator', 'authenticated_session') else 'controller_transition')
            if request.get('action') == 'checkpoint_rejected':
                authority.update(method='operator_rejection', human_review_required=True,
                                 human_review_performed=True,
                                 receipt_sha256=_control['facts']['review_sha256'])
        causes = []
        for source_session, source_event in ((actor['parent'], 'session_registered:' + str(actor['parent'])),
                                              (session, 'session_registered:' + session)):
            if source_session:
                prior_registration = db.execute('SELECT session,event FROM events WHERE session=? AND event=?',
                    ('controller:' + actor['project'], source_event)).fetchone()
                if prior_registration:
                    causes.append(digest(list(prior_registration)))
        active = _operation.get()
        if active and active['directory'] == self.directory and (active['session'], active['event']) != (session, event):
            causes.append(digest([active['session'], active['event']]))
        meta['_audit'] = {
            'schema': VERSION, 'operation_id': digest([session, event]),
            'sequence': sequence, 'project': actor['project'], 'task': actor['task'],
            'session': actor['id'], 'parent_session': actor['parent'], 'resume_of': actor['resume_of'],
            'conversation': actor['conversation'],
            'route': 'controller_lifecycle' if _control else 'supported_action',
            'requester': (_control['requester'] if _control else
                          {'kind': 'local_operator', 'uid': os.getuid()} if authorization else
                          {'kind': 'authenticated_session', 'id': session}),
            'enforcer': {'kind': 'local_controller', 'uid': os.getuid()},
            'policy_sha256': bundle['approval']['sha256'], 'authorization': authority,
            'request_sha256': request_hash, 'resource_path': resource['path'] if resource else None,
            'source_at': None, 'source_time_semantics': 'unknown',
            'observed_at': observed, 'recorded_at': time.time(),
            'completed_at': time.time() if response is not None else None,
            'decision': response['level'] if response is not None else 'allow',
            'outcome': outcome(response or {}, state), 'coverage': 'controller_metadata',
            'content': 'omitted', 'causes': list(dict.fromkeys(causes)),
        }
        if _control:
            meta['_audit']['details'] = _control['facts']
            unit = _control['facts'].get('unit')
            if unit and db.execute('SELECT 1 FROM events WHERE session=? AND event=?',
                                   ('controller:' + actor['project'], 'workload_launch:' + unit)).fetchone():
                meta['_audit']['causes'].append(digest(['controller:' + actor['project'], 'workload_launch:' + unit]))
        if active and active['directory'] == self.directory and (active['session'], active['event']) == (session, event):
            meta['_audit']['lease'] = operation_lease(session, event)
        from .evidence_storage import admit, charge, event_charge, COMPLETION_BYTES, configuration, optional_payload
        config = configuration(db, actor['project'])
        if config:
            meta['_audit']['profile_sha256'] = digest(config)
            meta['_audit']['reserved_bytes'] = (COMPLETION_BYTES if response is None else 0) + charge(meta)
        meta['_seal'] = seal(meta, response or {}, state)
        try:
            admit(db, actor['project'], max(event_charge(session, event, request_hash, meta, response, state, observed),
                                           meta['_audit'].get('reserved_bytes', 0)))
            db.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?)',
                       (session, event, request_hash, canonical(meta),
                        canonical(response) if response is not None else None, state, observed))
            if not _control:
                meta['_audit']['content'] = optional_payload(db, actor, bundle, event, request, response)
                meta['_seal'] = seal(meta, response or {}, state)
                db.execute('UPDATE events SET request_meta=? WHERE session=? AND event=?',
                           (canonical(meta), session, event))
        except (OSError, sqlite3.Error):
            if not (_control and _control.get('reduction')):
                self.capture_fault(db, actor['project'])
            raise
        if active and meta['_audit'].get('lease') and response is None:
            active['started'] = True
            active['held']['started'] = True

    def complete(self, db, session, event, response, *, state='complete', authorization_decision=None):
        from .event_evidence import outcome, seal, validate_response
        if state not in ('complete', 'uncertain') or (state == 'complete' and response is None):
            raise Invalid('Unsupported event completion')
        if response is not None:
            validate_response(response)
        if authorization_decision is not None and (
                state != 'complete' or authorization_decision != response['level'] or
                not self.owns_pending(session, event)):
            raise Invalid('Authorization completion requires the originating decision')
        row = db.execute('SELECT * FROM events WHERE session=? AND event=?', (session, event)).fetchone()
        if row is None or row['state'] != 'pending':
            raise Invalid('Event has no pending intent')
        meta = json.loads(row['request_meta'])
        if '_audit' in meta:
            if meta.get('_seal') != seal(meta, json.loads(row['response'] or '{}'), row['state']):
                raise Invalid('Pending event evidence changed')
            meta['_audit'].update(completed_at=time.time(), outcome=outcome(response or {}, state))
            if authorization_decision is not None:
                meta['_audit']['admission_decision'] = meta['_audit']['decision']
                meta['_audit']['decision'] = authorization_decision
            if response and response.get('effect') == 'git_review':
                meta['_audit']['authorization']['human_review_required'] = True
            meta['_seal'] = seal(meta, response or {}, state)
        try:
            from .evidence_storage import admit, event_charge
            project = meta.get('_audit', {}).get('project') or db.execute(
                'SELECT project FROM sessions WHERE id=?', (session,)).fetchone()[0]
            # Recovery may reduce a pending reservation even after quota loss.
            # It cannot claim a completed physical effect or clear the stop.
            if state != 'uncertain':
                admit(db, project, event_charge(session, event, row['request_hash'], meta, response, state, row['at']),
                      excluding=(session, event))
            if (state == 'complete' and '_audit' in meta and
                    meta['_audit']['route'] == 'supported_action' and meta.get('action') == 'read'):
                from .evidence_storage import optional_payload
                actor = db.execute('SELECT * FROM sessions WHERE id=?', (session,)).fetchone()
                _, bundle = self.project(db, project)
                meta['_audit']['content'] = optional_payload(db, actor, bundle, event, meta, response)
                meta['_seal'] = seal(meta, response or {}, state)
            db.execute('UPDATE events SET request_meta=?,response=?,state=? WHERE session=? AND event=?',
                       (canonical(meta), canonical(response) if response is not None else None, state, session, event))
        except (OSError, sqlite3.Error):
            project = meta['_audit']['project'] if '_audit' in meta else db.execute(
                'SELECT project FROM sessions WHERE id=?', (session,)).fetchone()[0]
            self.capture_fault(db, project)
            raise

    def observe(self, db, session, event, phase, response):
        """Attach a measured phase to existing intent; it is not authorization."""
        from .event_evidence import outcome, result_metadata, seal, validate_response
        if phase not in {'execution', 'preparation', 'termination'}:
            raise Invalid('Unsupported operation observation')
        validate_response(response)
        row = db.execute('SELECT * FROM events WHERE session=? AND event=?', (session, event)).fetchone()
        if row is None or row['state'] != 'pending' or not self.owns_pending(session, event):
            raise Invalid('Observation requires the originating pending operation')
        meta = json.loads(row['request_meta'])
        if meta.get('_seal') != seal(meta, json.loads(row['response'] or '{}'), 'pending'):
            raise Invalid('Pending event evidence changed')
        phases = meta['_audit'].setdefault('phases', {})
        if phase in phases:
            raise Invalid('Operation phase already observed')
        phases[phase] = {'observed_at': time.time(), 'outcome': outcome(response, 'complete'),
                         'result': result_metadata(response), 'result_sha256': digest(response)}
        meta['_seal'] = seal(meta, json.loads(row['response'] or '{}'), 'pending')
        try:
            db.execute('UPDATE events SET request_meta=? WHERE session=? AND event=?',
                       (canonical(meta), session, event))
        except (OSError, sqlite3.Error):
            project = db.execute('SELECT project FROM sessions WHERE id=?', (session,)).fetchone()[0]
            self.capture_fault(db, project)
            raise

    def record(self, db, session, event, request_hash, request, response):
        self.begin(db, session, event, request_hash, request, response=response)

    def lifecycle(self, db, project, action, *, session=None, event=None, facts=None,
                  approval=None, response=None, reduction=False, pending=False):
        """Trusted state transitions use the same event writer and export seal.

        Controller event IDs have their own namespace, not a usable credential.
        Callers transact admission-increasing changes together with this record.
        Authority reduction must survive missing evidence and reports the gap.
        """
        actor = db.execute('SELECT * FROM sessions WHERE id=? AND project=?', (session, project)).fetchone()
        if session is not None and actor is None:
            raise Invalid('Lifecycle session does not belong to project')
        if actor is None:
            actor = {'id': None, 'project': project, 'task': None, 'parent': None,
                     'grants': '[]', 'commands': '[]', 'packages': '[]',
                     'conversation': None, 'resume_of': None}
        event = event or action + ':' + secrets.token_hex(16)
        request = {'action': action, 'resource': project, 'content': ''}
        facts = facts or {}
        control = {'actor': actor, 'facts': facts, 'reduction': reduction,
                   'requester': {'kind': 'local_operator' if approval or action in ('stop_requested', 'checkpoint_rejected') else
                                'local_controller', 'uid': os.getuid()}}
        if action == 'session_registered':
            control['requester'] = ({'kind': 'authenticated_session', 'id': actor['parent']} if actor['parent']
                                    else {'kind': 'local_operator', 'uid': os.getuid()})
        elif action in ('session_closing', 'session_closed'):
            control['requester'] = {'kind': 'authenticated_session', 'id': actor['id']}
        try:
            self.begin(db, 'controller:' + project, event, digest([request, facts]), request,
                       response=None if pending else response or {'allowed': True, 'level': 'allow', 'effect': action},
                       authorization={'method': 'exact_operator_approval', 'receipt_sha256': approval}
                                     if approval else None, _control=control)
        except (OSError, sqlite3.Error):
            if not reduction:
                raise
            return False
        return True

    @staticmethod
    def effect(db, project, inv, request):
        resource, action = request["resource"], request["action"]
        flags = os.O_RDONLY if action == "read" else os.O_WRONLY
        fd = open_resource(inv, inv["resources"][resource]["path"], flags)
        try:
            info = os.fstat(fd)
            bound = db.execute("SELECT device,inode FROM bindings WHERE project=? AND resource=?", (project, resource)).fetchone()
            if (info.st_dev, info.st_ino) != tuple(bound):
                raise Invalid("Resource identity changed after activation")
            if info.st_size > MAX_BYTES:
                raise Invalid("Resource exceeds size limit")
            if action == "read":
                data = os.read(fd, MAX_BYTES + 1)
                if len(data) > MAX_BYTES:
                    raise Invalid("Resource exceeds size limit")
                return {"allowed": True, "effect": "read", "level": "allow", "content": data.decode("utf-8")}
            data = request["content"].encode()
            if action == "append":
                if info.st_size + len(data) > MAX_BYTES:
                    raise Invalid("Append exceeds size limit")
                os.lseek(fd, 0, os.SEEK_END)
            else:
                os.ftruncate(fd, 0)
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
            return {"allowed": True, "effect": action, "level": "allow", "bytes": len(data)}
        finally:
            os.close(fd)

    def stop(self, project, reason="operator stop"):
        with self.locked() as db:
            self.project(db, project)
            return self.stop_from_db(db, project, reason, operator=True)

    def stop_from_db(self, db, project, reason, *, operator=False):
        previous, _ = self.project(db, project)
        try:
            db.execute("UPDATE projects SET stopped=1,reason=? WHERE id=?", (reason, project))
        except (OSError, sqlite3.Error):
            self.terminate_workloads(db, project=project)
            raise
        # A repeated call cannot assert that an earlier failed write succeeded.
        captured = False
        if not previous['stopped']:
            captured = self.lifecycle(db, project, 'stop_requested' if operator else 'admission_stopped',
                                     facts={'reason_sha256': digest(reason), 'termination': 'unconfirmed'},
                                     reduction=True)
        if not captured and not previous['stopped']:
            self.terminate_workloads(db, project=project)
        return {'stopped': True, 'confirmed_stopped': False, 'evidence': 'recorded' if captured else 'unavailable'}

    def status(self, project):
        with self.locked() as db:
            row, bundle = self.project(db, project)
            result = {k: row[k] for k in ["id", "stopped", "violations", "reason"]}
            result["policy_sha256"] = bundle["approval"]["sha256"]
            result["sessions"] = [dict(r) for r in db.execute("SELECT id,task,parent,depth,closed FROM sessions WHERE project=?", (project,))]
            result["workloads"] = [dict(r) for r in db.execute("SELECT unit,stopped FROM workloads WHERE project=?", (project,))]
            result["tasks"] = [dict(r) for r in db.execute("SELECT task,violations FROM task_counts WHERE project=?", (project,))]
            result['package_sets'] = [dict(r) for r in db.execute(
                'SELECT id,ecosystem,assessment_state,assessment_reason,assessment_generation FROM package_sets WHERE project=?', (project,))]
            result['package_terminations'] = [dict(r) for r in db.execute(
                'SELECT t.* FROM package_terminations t JOIN workloads w ON w.unit=t.unit WHERE w.project=?', (project,))]
            return result

    def audit_events(self, project, *, include_lifecycle=False):
        with self.locked() as db:
            return self._audit_events(db, project, include_lifecycle=include_lifecycle)

    def _audit_events(self, db, project, *, include_lifecycle=False):
        from .event_evidence import export_row
        self.project(db, project)
        return [export_row(r) for r in db.execute(
                'SELECT e.*,s.task FROM events e LEFT JOIN sessions s ON s.id=e.session '
                'WHERE s.project=? OR (? AND e.session=?) ORDER BY e.rowid',
                (project, include_lifecycle, 'controller:' + project))]

    def audit_export(self, project):
        with self.locked() as db:
            return self._audit_export(db, project)

    def _audit_export(self, db, project):
        from .event_evidence import export_document, assessment_row
        from .evidence_storage import configuration, usage
        result = export_document(project, self._audit_events(db, project, include_lifecycle=True))
        result['profile'] = configuration(db, project)
        result['storage'] = {'accounted_bytes': usage(db, project), 'accounting': 'conservative_logical_with_journal_allowance'}
        result['payloads'] = [dict(r) for r in db.execute('SELECT session,event,at,sha256,captured_sha256,original_bytes,status,expired_at '
                                                       'FROM evidence_payloads WHERE project=? ORDER BY rowid', (project,))]
        result['assessments'] = [assessment_row(r) for r in db.execute(
            'SELECT a.* FROM package_assessments a JOIN package_sets p ON p.id=a.package_set '
            'WHERE p.project=? ORDER BY a.rowid', (project,))]
        result['manifest']['supporting_sha256'] = digest({k: result[k] for k in ('profile', 'payloads', 'assessments')})
        return result

    def evidence_review(self, project, profile):
        from .evidence_storage import review
        return review(self, project, profile)

    def adopt_evidence(self, project, profile, expected_hash, reviewer):
        from .evidence_storage import adopt
        return adopt(self, project, profile, expected_hash, reviewer)

    def expire_evidence(self, project):
        from .evidence_storage import expire
        return expire(self, project)

    def archive_evidence(self, project, destination):
        from .evidence_storage import archive
        return archive(self, project, destination)

    def evidence_content(self, project, operation_id):
        """Operator-only bounded original bytes; never infer omitted/expired text."""
        with self.locked() as db:
            self.project(db, project)
            for row in db.execute('SELECT * FROM evidence_payloads WHERE project=?', (project,)):
                if digest([row['session'], row['event']]) == operation_id:
                    if row['payload'] is not None and hashlib.sha256(row['payload']).hexdigest() != row['captured_sha256']:
                        raise Invalid('Optional evidence payload changed')
                    return dict(row)
        return {'status': 'omitted', 'payload': None}
