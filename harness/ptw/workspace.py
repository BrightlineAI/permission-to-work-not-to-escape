"""Repository capabilities: safe broker edits and checked disposable execution."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile
import time

from .policy import Invalid, canonical, digest, obj, scope, validate
from .workspace_policy import directory_fd, relative, resource_info

MAX_FILE = 8 * 1024 * 1024
MAX_TREE = 64 * 1024 * 1024
MAX_ENTRIES = 4096
ACTIONS = ["list", "read", "write", "append", "create", "delete", "rename",
           "mkdir", "rmdir", "install", "run", "delegate", "finish"]
REQUEST_SCHEMA = obj({key: {"type": "string"} for key in
                      ["action", "resource", "path", "destination", "content", "expected"]})
REQUEST_SCHEMA["properties"]["action"]["enum"] = ACTIONS


def request(action, resource="", path="", content="", expected="", destination=""):
    return dict(action=action, resource=resource, path=path, content=content,
                expected=expected, destination=destination)


def stamp(entry):
    if entry is None:
        return "absent"
    if entry["kind"] == "dir":
        return "directory"
    return hashlib.sha256(entry["data"]).hexdigest()


def same(a, b):
    return stamp(a) == stamp(b) and (a or {}).get("mode") == (b or {}).get("mode")


def entry_at(fd, name):
    try:
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if stat.S_ISDIR(info.st_mode):
        return {"kind": "dir"}
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise Invalid("Links and special files are not workspace resources")
    opened = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        actual = os.fstat(opened)
        if (actual.st_dev, actual.st_ino) != (info.st_dev, info.st_ino) or actual.st_nlink != 1:
            raise Invalid("Resource changed during read")
        if actual.st_size > MAX_FILE:
            raise Invalid("Workspace file exceeds 8 MiB")
        with os.fdopen(os.dup(opened), "rb") as handle:
            data = handle.read(MAX_FILE + 1)
        if len(data) > MAX_FILE:
            raise Invalid("Workspace file exceeds 8 MiB")
        return {"kind": "file", "data": data, "mode": 0o755 if actual.st_mode & 0o111 else 0o644}
    finally:
        os.close(opened)


@contextmanager
def parent_fd(inv, full):
    relative(full)
    fd = directory_fd(inv["root"])
    try:
        for part in full.split("/")[:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        yield fd, full.split("/")[-1]
    finally:
        os.close(fd)


def scan(inv, resources):
    """Read only authorized resource roots. No Path.rglob or followed links."""
    result, size = {}, 0

    def visit(fd, name, full):
        nonlocal size
        entry = entry_at(fd, name)
        if entry is None:
            return
        if len(result) >= MAX_ENTRIES:
            raise Invalid("Workspace exceeds 4096 entries")
        result[full] = entry
        if entry["kind"] == "file":
            size += len(entry["data"])
            if size > MAX_TREE:
                raise Invalid("Workspace exceeds 64 MiB")
        else:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                for item in sorted(os.listdir(child)):
                    relative(item)
                    visit(child, item, full + "/" + item)
            finally:
                os.close(child)

    for resource in resources:
        full = inv["resources"][resource]["path"]
        with parent_fd(inv, full) as (fd, name):
            visit(fd, name, full)
    return result


def materialize(entries, target):
    for path, entry in sorted(entries.items(), key=lambda x: (x[0].count("/"), x[0])):
        destination = target / path
        if entry["kind"] == "dir":
            destination.mkdir(parents=True, exist_ok=True)
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(entry["data"])
            destination.chmod(entry["mode"])


def owner(inv, full):
    for resource, item in inv["resources"].items():
        if full == item["path"] or (item.get("kind") == "tree" and full.startswith(item["path"] + "/")):
            return resource
    return None


def authorize_diff(inv, allowed, before, after):
    for full in sorted(before.keys() | after.keys()):
        old, new = before.get(full), after.get(full)
        if same(old, new):
            continue
        resource = owner(inv, full)
        needed = "create" if old is None else "delete" if new is None else "write"
        if needed not in allowed.get(resource, set()):
            return f"{needed} denied for {resource or 'unregistered output'}: {full}"
        if resource and inv["resources"][resource].get("kind") == "tree" and full == inv["resources"][resource]["path"]:
            return "A resource root cannot be removed or replaced"
        if old and new and old["kind"] != new["kind"]:
            return "Changing a file into a directory or a directory into a file needs separate operations"
    return None


def publish(inv, before, after):
    """Called under the project lock after full diff authorization/preflight."""
    changed = [p for p in before.keys() | after.keys() if not same(before.get(p), after.get(p))]
    for full in sorted(changed, key=lambda p: (-p.count("/"), p)):
        if full not in after:
            with parent_fd(inv, full) as (fd, name):
                (os.rmdir if before[full]["kind"] == "dir" else os.unlink)(name, dir_fd=fd)
                os.fsync(fd)
    for full in sorted(changed, key=lambda p: (p.count("/"), p)):
        entry = after.get(full)
        if entry is None:
            continue
        with parent_fd(inv, full) as (fd, name):
            if entry["kind"] == "dir":
                os.mkdir(name, 0o755, dir_fd=fd)
            else:
                temporary = ".ptw-" + secrets.token_hex(16)
                out = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
                try:
                    with os.fdopen(out, "wb") as handle:
                        handle.write(entry["data"])
                        os.fchmod(handle.fileno(), entry["mode"])
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
                finally:
                    try:
                        os.unlink(temporary, dir_fd=fd)
                    except FileNotFoundError:
                        pass
            os.fsync(fd)


class Workspace:
    def __init__(self, store):
        self.store = store

    def inspect(self, db, token, event, req):
        if not isinstance(event, str) or not 1 <= len(event) <= 128:
            raise Invalid("Stable event ID required")
        actor = self.store.session(db, token)
        project, bundle = self.store.project(db, actor["project"])
        if bundle["policy"]["version"] != 4:
            raise Invalid("Repository actions require a reviewed version 4 policy")
        prior = db.execute("SELECT * FROM events WHERE session=? AND event=?", (actor["id"], event)).fetchone()
        if prior:
            if prior["request_hash"] != digest(req):
                raise Invalid("Event ID reused with different request")
            response = (json.loads(prior["response"]) if prior["state"] == "complete" else
                        {"allowed": False, "level": "stop", "effect": "unknown", "reason": "Interrupted request; review before restarting"})
            return actor, project, bundle, {**response, "replayed": True}
        if project["stopped"]:
            return actor, project, bundle, self.record(db, actor, event, req, "stop", "project stopped")
        return actor, project, bundle, None

    def record(self, db, actor, event, req, level, reason, **extra):
        response = {"allowed": level == "allow", "effect": "none", "level": level, "reason": reason, **extra}
        self.store.record(db, actor["id"], event, digest(req), self.meta(req), response)
        return response

    @staticmethod
    def meta(req):
        return {"action": req.get("action"), "resource": req.get("resource"), "content": canonical(req)}

    def deny(self, db, actor, project, bundle, event, req, reason):
        return self.store.deny(db, actor, project, bundle, event, digest(req), self.meta(req), reason)

    def integrity(self, db, project, bundle):
        inv = bundle["inventory"]
        fd = directory_fd(inv["root"])
        try:
            info = os.fstat(fd)
        finally:
            os.close(fd)
        bound = db.execute("SELECT device,inode FROM bindings WHERE project=? AND resource=''", (project,)).fetchone()
        if tuple(bound) != (info.st_dev, info.st_ino):
            raise Invalid("Repository root identity changed")
        for resource, item in inv["resources"].items():
            info = resource_info(inv, resource)
            current = (info.st_dev, info.st_ino) if info else (0, 0)
            bound = db.execute("SELECT device,inode FROM bindings WHERE project=? AND resource=?", (project, resource)).fetchone()
            if tuple(bound) != current:
                raise Invalid("Resource identity changed outside the broker: " + resource)

    def commit(self, db, actor, bundle, event, req, before, after, **extra):
        db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?)",
                   (actor["id"], event, digest(req), self.store.metadata(self.meta(req)), None, "pending", time.time()))
        try:
            publish(bundle["inventory"], before, after)
            for resource, item in bundle["inventory"]["resources"].items():
                if item.get("kind", "file") == "file":
                    info = resource_info(bundle["inventory"], resource)
                    db.execute("UPDATE bindings SET device=?,inode=? WHERE project=? AND resource=?",
                               (info.st_dev if info else 0, info.st_ino if info else 0, actor["project"], resource))
            response = {"allowed": True, "effect": req["action"], "level": "allow",
                        "changed": sorted(p for p in before.keys() | after.keys() if not same(before.get(p), after.get(p))),
                        **extra}
        except (OSError, Invalid) as exc:
            db.execute("UPDATE projects SET stopped=1,reason=? WHERE id=?", ("uncertain workspace publication", actor["project"]))
            response = {"allowed": False, "effect": "unknown", "level": "stop",
                        "reason": "Publication interrupted; inspect files and review a new project version", "error": type(exc).__name__}
        db.execute("UPDATE events SET state='complete',response=? WHERE session=? AND event=?",
                   (canonical(response), actor["id"], event))
        return response

    def request(self, token, event, req):
        from .supervisor import Supervisor
        try:
            return self._request(token, event, req)
        finally:
            Supervisor(self.store).reconcile()

    def _request(self, token, event, req):
        with self.store.locked() as db:
            actor, project, bundle, prior = self.inspect(db, token, event, req)
            if prior is not None:
                return prior
            try:
                validate(REQUEST_SCHEMA, req)
                if len(req["content"].encode()) > MAX_FILE:
                    raise Invalid("Request exceeds size limit")
                if req["action"] not in ("run", "install", "delegate", "finish"):
                    relative(req["path"], empty=True)
            except (Invalid, UnicodeError):
                return self.deny(db, actor, project, bundle, event, req, "Malformed repository request")
            if req["action"] == "run":
                pass
            elif req["action"] in ("install", "delegate", "finish"):
                raise Invalid("Use the unified agent dispatcher for this action")
            else:
                return self.edit(db, actor, project, bundle, event, req)
        return self.command(token, event, req)

    def edit(self, db, actor, project, bundle, event, req):
        inv, allowed = bundle["inventory"], scope(json.loads(actor["grants"]))
        action, resource = req["action"], req["resource"]
        needed = {"list": "read", "read": "read", "write": "write", "append": "append",
                  "create": "create", "mkdir": "create", "delete": "delete", "rmdir": "delete", "rename": "delete"}[action]
        if resource not in inv["resources"] or needed not in allowed.get(resource, set()):
            return self.deny(db, actor, project, bundle, event, req, f"{needed} denied for resource {resource}")
        item = inv["resources"][resource]
        if item.get("kind", "file") == "file" and req["path"]:
            return self.deny(db, actor, project, bundle, event, req, "File resources do not accept child paths")
        full = item["path"] + ("/" + req["path"] if req["path"] else "")
        try:
            self.integrity(db, actor["project"], bundle)
            if action == "list":
                entries = scan(inv, [resource])
                return self.record(db, actor, event, req, "allow", "listed", effect="list",
                                   entries=[{"path": p[len(item["path"]):].lstrip("/"), "kind": e["kind"],
                                             "sha256": stamp(e)} for p, e in entries.items()
                                            if p == full or p.startswith(full + "/")])
            with parent_fd(inv, full) as (fd, name):
                old = entry_at(fd, name)
            if action == "read":
                if old is None or old["kind"] != "file":
                    return self.record(db, actor, event, req, "blocked", "Not an existing file; list first")
                return self.record(db, actor, event, req, "allow", "read", effect="read",
                                   content=old["data"].decode(), sha256=stamp(old))
            if action in ("create", "mkdir"):
                if old is not None:
                    return self.record(db, actor, event, req, "conflict", "Target already exists; read before replacing")
            elif req["expected"] != stamp(old) or old is None:
                return self.record(db, actor, event, req, "conflict", "Content changed or missing precondition; read and retry with a new event")
            before = {full: old} if old else {}
            after = dict(before)
            if action in ("write", "append", "create"):
                if old and old["kind"] != "file":
                    return self.record(db, actor, event, req, "blocked", "Not a regular file")
                data = (old["data"] if action == "append" else b"") + req["content"].encode()
                if len(data) > MAX_FILE:
                    return self.record(db, actor, event, req, "blocked", "File exceeds size limit")
                after[full] = {"kind": "file", "data": data, "mode": old["mode"] if old else 0o644}
            elif action == "mkdir":
                after[full] = {"kind": "dir"}
            elif action in ("delete", "rmdir"):
                if old["kind"] == "dir":
                    if action != "rmdir":
                        return self.record(db, actor, event, req, "blocked", "Use rmdir for an empty directory")
                    fd = directory_fd(Path(inv["root"]) / full)
                    try:
                        if os.listdir(fd):
                            return self.record(db, actor, event, req, "blocked", "Directory is not empty")
                    finally:
                        os.close(fd)
                elif action == "rmdir":
                    return self.record(db, actor, event, req, "blocked", "Not a directory")
                del after[full]
            elif action == "rename":
                # Destination uses resource:path, never an absolute host path.
                dest_resource, sep, dest_path = req["destination"].partition(":")
                relative(dest_path, empty=True)
                dest = inv["resources"].get(dest_resource)
                if not sep or dest is None or "create" not in allowed.get(dest_resource, set()):
                    return self.deny(db, actor, project, bundle, event, req, "Rename destination outside create scope")
                if dest.get("kind", "file") == "file" and dest_path:
                    return self.deny(db, actor, project, bundle, event, req, "File destination cannot have children")
                if old["kind"] != "file":
                    return self.record(db, actor, event, req, "blocked", "Rename files individually; directory rename is not implicit recursive authority")
                dest_full = dest["path"] + ("/" + dest_path if dest_path else "")
                with parent_fd(inv, dest_full) as (fd, name):
                    if entry_at(fd, name) is not None:
                        return self.record(db, actor, event, req, "conflict", "Rename will not overwrite an existing destination")
                del after[full]
                after[dest_full] = old
            reason = authorize_diff(inv, allowed, before, after)
            # Append permission never becomes general replacement permission.
            if action == "append" and reason and reason.startswith("write denied"):
                reason = None
            if reason:
                return self.deny(db, actor, project, bundle, event, req, reason)
            return self.commit(db, actor, bundle, event, req, before, after)
        except (FileNotFoundError, NotADirectoryError, UnicodeError):
            return self.record(db, actor, event, req, "blocked", "Missing parent/path or non-text file; list the resource first")
        except (Invalid, OSError) as exc:
            self.store.stop_from_db(db, actor["project"], "workspace integrity failure")
            return self.record(db, actor, event, req, "stop", str(exc))

    def command(self, token, event, req):
        from .execution import execute
        with self.store.locked() as db:
            actor, project, bundle, prior = self.inspect(db, token, event, req)
            if prior is not None:
                return prior
            name = req["resource"]
            if name not in json.loads(actor["commands"]):
                return self.deny(db, actor, project, bundle, event, req, "Command outside task or delegated scope: " + name)
            definition = next(c for c in bundle["policy"]["project"]["commands"] if c["id"] == name)
            try:
                self.integrity(db, actor["project"], bundle)
                before = scan(bundle["inventory"], definition["resources"])
            except (Invalid, OSError) as exc:
                return self.record(db, actor, event, req, "blocked", "Cannot snapshot command inputs: " + str(exc))
        try:
            after, outcome = execute(self.store, token, definition, before, req["content"])
        except (Invalid, OSError) as exc:
            with self.store.locked() as db:
                actor, project, bundle, prior = self.inspect(db, token, event, req)
                return prior or self.record(db, actor, event, req, "blocked", str(exc))
        with self.store.locked() as db:
            actor, project, bundle, prior = self.inspect(db, token, event, req)
            if prior is not None:
                return prior
            reason = authorize_diff(bundle["inventory"], scope(json.loads(actor["grants"])), before, after)
            if reason:
                return self.deny(db, actor, project, bundle, event, req, "Command output rejected: " + reason)
            try:
                self.integrity(db, actor["project"], bundle)
                current = scan(bundle["inventory"], definition["resources"])
            except (Invalid, OSError) as exc:
                return self.record(db, actor, event, req, "blocked", "Cannot validate publication: " + str(exc))
            if current.keys() != before.keys() or any(not same(current[p], before[p]) for p in before):
                return self.record(db, actor, event, req, "conflict", "Command inputs changed; no outputs published. Rerun with a new event")
            return self.commit(db, actor, bundle, event, req, before, after, **outcome)
