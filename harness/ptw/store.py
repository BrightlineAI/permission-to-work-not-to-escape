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
            """)
            if "packages" not in {r[1] for r in db.execute("PRAGMA table_info(sessions)")}:
                db.execute("ALTER TABLE sessions ADD COLUMN packages TEXT NOT NULL DEFAULT '[]'")
            if "ecosystem" not in {r[1] for r in db.execute("PRAGMA table_info(package_sets)")}:
                db.execute("ALTER TABLE package_sets ADD COLUMN ecosystem TEXT NOT NULL DEFAULT 'pypi'")
            if "commands" not in {r[1] for r in db.execute("PRAGMA table_info(sessions)")}:
                db.execute("ALTER TABLE sessions ADD COLUMN commands TEXT NOT NULL DEFAULT '[]'")
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

    def activate(self, bundle):
        checked = check_approval(bundle)
        inv = checked["inventory"]
        root = Path(inv["root"])
        if self.directory == root or self.directory.is_relative_to(root) or root.is_relative_to(self.directory):
            raise Invalid("Resource root and protected state must be separate trees")
        project = checked["policy"]["project"]["id"]
        with self.locked() as db:
            if db.execute("SELECT 1 FROM projects WHERE id=?", (project,)).fetchone():
                raise Invalid("Project identity already exists; approval cannot reset history")
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT INTO projects(id,bundle) VALUES(?,?)", (project, canonical(bundle)))
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

    @staticmethod
    def session(db, token):
        if not isinstance(token, str) or len(token) < 20:
            raise Invalid("Unknown session credential")
        row = db.execute("SELECT * FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
        if row is None:
            raise Invalid("Unknown session credential")
        return row

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
            result["sessions"] = [dict(r) for r in db.execute("SELECT id,task,parent,depth FROM sessions WHERE project=?", (project,))]
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
