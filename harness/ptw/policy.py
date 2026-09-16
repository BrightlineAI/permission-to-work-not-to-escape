"""Typed proposals, strict compilation and content bound operator approval."""
from __future__ import annotations

import hashlib
import copy
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

from jsonschema import Draft202012Validator

ACTIONS = ["read", "write", "append"]
ID = {"type": "string", "pattern": "^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$"}


def obj(properties):
    return {"type": "object", "properties": properties,
            "required": list(properties), "additionalProperties": False}


GRANT = obj({"resource": ID, "actions": {"type": "array", "items": {"type": "string", "enum": ACTIONS},
                                               "minItems": 1, "uniqueItems": True}})
GRANTS = {"type": "array", "items": GRANT, "maxItems": 128}
ESCALATION = obj({"warn_at": {"type": "integer", "minimum": 1, "maximum": 1000},
                  "stop_at": {"type": "integer", "minimum": 1, "maximum": 1000}})
POLICY_SCHEMA = obj({
    "version": {"type": "integer", "const": 1},
    "project": obj({"id": ID, "description": {"type": "string", "minLength": 1, "maxLength": 8000},
                    "grants": GRANTS, "escalation": ESCALATION}),
    "tasks": {"type": "array", "minItems": 1, "maxItems": 64, "items": obj({
        "id": ID, "description": {"type": "string", "minLength": 1, "maxLength": 8000},
        "grants": GRANTS, "escalation": ESCALATION})},
})
PACKAGE_NAME = {"type": "string", "pattern": "^[a-z0-9]+(?:-[a-z0-9]+)*$", "maxLength": 128}
PACKAGE_NAMES = {"type": "array", "items": PACKAGE_NAME, "uniqueItems": True, "maxItems": 64}
PACKAGE_SCHEMA = copy.deepcopy(POLICY_SCHEMA)
PACKAGE_SCHEMA["properties"]["version"]["const"] = 2
PACKAGE_SCHEMA["properties"]["project"]["properties"]["packages"] = obj({
    "allowed_names": PACKAGE_NAMES,
    "min_release_age_days": {"type": "integer", "minimum": 0, "maximum": 36500},
    "deny_cvss_at_or_above": {"type": "number", "minimum": 0.1, "maximum": 10},
    "evidence_max_age_seconds": {"type": "integer", "minimum": 60, "maximum": 86400},
})
PACKAGE_SCHEMA["properties"]["project"]["required"].append("packages")
PACKAGE_SCHEMA["properties"]["tasks"]["items"]["properties"]["packages"] = PACKAGE_NAMES
PACKAGE_SCHEMA["properties"]["tasks"]["items"]["required"].append("packages")
INVENTORY_SCHEMA = obj({"root": {"type": "string", "minLength": 1}, "resources": {
    "type": "object", "minProperties": 1, "maxProperties": 128,
    "propertyNames": ID, "additionalProperties": obj({
        "path": {"type": "string", "minLength": 1},
        "description": {"type": "string", "maxLength": 2000}})}})


class Invalid(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def load(path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Invalid(f"Duplicate JSON field: {key}")
            result[key] = value
        return result
    return json.loads(Path(path).read_text(), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Invalid("Nonfinite JSON")))


def save(path, value):
    """New operator artifacts are private and never silently overwritten."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(value, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def validate(schema, value):
    try:
        canonical(value)
    except (ValueError, TypeError) as exc:
        raise Invalid("Policy and inventory must contain finite JSON values") from exc
    errors = sorted(Draft202012Validator(schema).iter_errors(value), key=lambda e: str(e.path))
    if errors:
        error = errors[0]
        raise Invalid(f"{list(error.path)}: {error.message}")


def scope(grants):
    result = {}
    for grant in grants:
        if grant["resource"] in result:
            raise Invalid("Duplicate resource grant")
        result[grant["resource"]] = set(grant["actions"])
    return result


def subset(child, parent):
    return all(actions <= parent.get(resource, set()) for resource, actions in child.items())


def data_directory(path):
    """Runtime mounts must never contain project resources or controller state."""
    resolved = Path(path).resolve()
    reserved = [Path(p) for p in ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/proc", "/sys", "/dev")]
    if resolved == Path("/") or any(resolved == p or resolved.is_relative_to(p) for p in reserved):
        raise Invalid("Use a data directory outside system runtime trees")


def inventory(value):
    validate(INVENTORY_SCHEMA, value)
    root = Path(value["root"])
    data_directory(root)
    if not root.is_absolute() or root != root.resolve() or not root.is_dir():
        raise Invalid("Inventory root must be an existing canonical absolute directory")
    paths = set()
    for resource in value["resources"].values():
        path = resource["path"]
        parsed = PurePosixPath(path)
        if (parsed.is_absolute() or not parsed.parts or any(p in (".", "..") for p in path.split("/"))
                or str(parsed) != path or "\x00" in path or "\\" in path):
            raise Invalid("Resource paths must be normalized relative paths, without traversal")
        if path in paths:
            raise Invalid("Two resources cannot alias the same path")
        paths.add(path)
        # Pin only ordinary files. Do not create targets implicitly during approval.
        fd = open_resource(value, path, os.O_RDONLY)
        os.close(fd)
    return value


def open_resource(inv, relative, flags):
    """Walk directory descriptors, rejecting links at every level including root."""
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in Path(inv["root"]).parts[1:]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        parts = PurePosixPath(relative).parts
        for part in parts[:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        target = os.open(parts[-1], flags | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        info = os.fstat(target)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            os.close(target)
            raise Invalid("Resource must be an ordinary file with exactly one link")
        return target
    finally:
        os.close(fd)


def compile_policy(proposal, inv):
    validate(PACKAGE_SCHEMA if isinstance(proposal, dict) and proposal.get("version") == 2 else POLICY_SCHEMA, proposal)
    inventory(inv)
    project = proposal["project"]
    parent = scope(project["grants"])
    if not set(parent) <= set(inv["resources"]):
        raise Invalid("Project names unknown resources")
    ids = set()
    for item in [project, *proposal["tasks"]]:
        escalation = item["escalation"]
        if escalation["warn_at"] > escalation["stop_at"]:
            raise Invalid("Warning threshold must not exceed stop threshold")
    for task in proposal["tasks"]:
        if proposal["version"] == 2 and not set(task["packages"]) <= set(project["packages"]["allowed_names"]):
            raise Invalid("Task package scope expands project scope")
        if task["id"] in ids:
            raise Invalid("Duplicate task ID")
        ids.add(task["id"])
        if not subset(scope(task["grants"]), parent):
            raise Invalid("Task " + task["id"] + " expands project scope")
        for key in ["warn_at", "stop_at"]:
            if task["escalation"][key] > project["escalation"][key]:
                raise Invalid("Task escalation cannot be weaker than project escalation")
    return {"policy": proposal, "inventory": inv}


def approve(proposal, inv, expected_hash, reviewer):
    compiled = compile_policy(proposal, inv)
    if not reviewer.strip() or digest(compiled) != expected_hash:
        raise Invalid("Approval requires reviewer and exact reviewed bundle hash")
    return {**compiled, "approval": {"reviewer": reviewer, "sha256": expected_hash}}


def check_approval(bundle):
    if set(bundle) != {"policy", "inventory", "approval"}:
        raise Invalid("Not an approved bundle")
    compiled = compile_policy(bundle["policy"], bundle["inventory"])
    approval = bundle["approval"]
    if (set(approval) != {"reviewer", "sha256"} or not approval["reviewer"]
            or approval["sha256"] != digest(compiled)):
        raise Invalid("Policy or inventory changed after approval")
    return compiled
