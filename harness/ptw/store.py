"""Protected single host broker. Agents never open this database or supply identity."""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time

from .policy import Invalid, canonical, check_approval, data_directory, digest, open_resource, scope, subset

MAX_BYTES = 1_048_576


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
            """)
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
            if 'preparation_source' not in {r[1] for r in db.execute('PRAGMA table_info(sessions)')}:
                db.execute('ALTER TABLE sessions ADD COLUMN preparation_source TEXT')
            if "setup_pending" not in {r[1] for r in db.execute("PRAGMA table_info(projects)")}:
                db.execute("ALTER TABLE projects ADD COLUMN setup_pending INTEGER NOT NULL DEFAULT 0")
            # Lock spans intent commit, effect and completion. A pending row visible after
            # acquiring it means the previous operator died before recording completion.
            rows = db.execute("SELECT DISTINCT s.project FROM events e JOIN sessions s ON s.id=e.session WHERE e.state=?", ("pending",)).fetchall()
            for row in rows:
                db.execute("UPDATE projects SET stopped=1, reason=? WHERE id=?",
                           ("uncertain effect after interrupted request; operator review required", row[0]))
            db.execute("UPDATE events SET state=? WHERE state=?", ("uncertain", "pending"))

    @contextmanager
    def locked(self):
        fd = os.open(self.directory / "controller.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        db = None
        try:
            db = sqlite3.connect(self.db, timeout=30, isolation_level=None)
            db.row_factory = sqlite3.Row
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
            db.execute("UPDATE projects SET setup_pending=0 WHERE id=?", (project,))

    @staticmethod
    def session(db, token, *, preparation=False):
        if not isinstance(token, str) or len(token) < 20:
            raise Invalid("Unknown session credential")
        row = db.execute("SELECT * FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
        if row is None:
            raise Invalid("Unknown session credential")
        if row["closed"]:
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
            db.execute('INSERT INTO sessions(id,token_hash,project,task,parent,grants,depth,packages,commands,preparation_source) '
                       'VALUES(?,?,?,?,NULL,?,0,?,?,?)',
                       (sid, hashlib.sha256(token.encode()).hexdigest(), project, task,
                        canonical(grants), canonical(names), '[]', identity))
            return {'session': sid, 'token': token, 'project': project, 'task': task,
                    'parent': None, 'grants': grants, 'packages': names, 'commands': [],
                    'preparation_source': identity}

    def close_session(self, token):
        """Revoke one session and its descendants without stopping other parents."""
        with self.locked() as db:
            row = db.execute("SELECT id FROM sessions WHERE token_hash=?",
                             (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
            if row is None:
                raise Invalid("Unknown session credential")
            db.execute("""WITH RECURSIVE tree(id) AS (
                SELECT id FROM sessions WHERE id=?
                UNION ALL SELECT s.id FROM sessions s JOIN tree t ON s.parent=t.id
                ) UPDATE sessions SET closed=1 WHERE id IN (SELECT id FROM tree)""", (row["id"],))

    @staticmethod
    def project(db, project):
        row = db.execute("SELECT * FROM projects WHERE id=?", (project,)).fetchone()
        if row is None:
            raise Invalid("Unknown project")
        return row, json.loads(row["bundle"])

    def register(self, project, task, *, parent_token=None, grants=None, packages=None, commands=None):
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
            db.execute("INSERT INTO sessions(id,token_hash,project,task,parent,grants,depth,packages,commands) VALUES(?,?,?,?,?,?,?,?,?)",
                       (sid, hashlib.sha256(token.encode()).hexdigest(), project, task,
                        parent_id, canonical(serialized), depth, canonical(sorted(set(package_names))),
                        canonical(sorted(set(command_names)))))
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
                db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?)", (actor["id"], event, request_hash,
                           self.metadata(request), None, "pending", time.time()))
                try:
                    response = self.effect(db, actor["project"], bundle["inventory"], request)
                except (OSError, Invalid, UnicodeError) as exc:
                    response = {"allowed": False, "effect": "unknown", "level": "stop", "reason": "resource failure: " + type(exc).__name__}
                    db.execute("UPDATE projects SET stopped=1, reason=? WHERE id=?", ("resource integrity or execution failure", actor["project"]))
                db.execute("UPDATE events SET response=?,state=? WHERE session=? AND event=?",
                           (canonical(response), "complete", actor["id"], event))
                return response
            self.record(db, actor["id"], event, request_hash, request, response)
            return response

    def deny(self, db, actor, project, bundle, event, request_hash, request, reason):
        """The same counter transition for every controlled effect."""
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
        self.record(db, actor["id"], event, request_hash, request, response)
        db.commit()
        return response

    @staticmethod
    def metadata(request):
        return canonical({"action": request.get("action"), "resource": request.get("resource"),
                          "content_sha256": digest(request.get("content"))}) if isinstance(request, dict) else "{}"

    def record(self, db, session, event, request_hash, request, response):
        db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?)", (session, event, request_hash,
                   self.metadata(request), canonical(response), "complete", time.time()))

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
            db.execute("UPDATE projects SET stopped=1,reason=? WHERE id=?", (reason, project))

    @staticmethod
    def stop_from_db(db, project, reason):
        db.execute("UPDATE projects SET stopped=1,reason=? WHERE id=?", (reason, project))

    def status(self, project):
        with self.locked() as db:
            row, bundle = self.project(db, project)
            result = {k: row[k] for k in ["id", "stopped", "violations", "reason"]}
            result["policy_sha256"] = bundle["approval"]["sha256"]
            result["sessions"] = [dict(r) for r in db.execute("SELECT id,task,parent,depth,closed FROM sessions WHERE project=?", (project,))]
            result["workloads"] = [dict(r) for r in db.execute("SELECT unit,stopped FROM workloads WHERE project=?", (project,))]
            result["tasks"] = [dict(r) for r in db.execute("SELECT task,violations FROM task_counts WHERE project=?", (project,))]
            return result

    def audit_events(self, project):
        with self.locked() as db:
            return [{"session": r["session"], "task": r["task"], "event": r["event"],
                     "request": json.loads(r["request_meta"]), "state": r["state"],
                     "result": {k: v for k, v in json.loads(r["response"] or "{}").items() if k != "content"},
                     "at": r["at"]} for r in db.execute(
                         "SELECT e.*,s.task FROM events e JOIN sessions s ON s.id=e.session WHERE s.project=? ORDER BY e.at", (project,))]
