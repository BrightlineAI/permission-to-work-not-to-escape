from __future__ import annotations

import argparse
import json
import posixpath
from pathlib import Path
from typing import Any

from vega_core.models import policy_from_dict

RESOURCE_ACTIONS = {
    "read_file", "read_multiple_files", "write_file", "edit_file",
    "create_directory", "list_directory", "list_directory_with_sizes",
    "directory_tree", "search_files", "check_file_exists", "get_file_info",
    "delete_file", "delete_directory",
}
NO_SCOPE_ACTIONS = {"log_action", "get_logs", "clear_logs"}
ALL_ACTIONS = RESOURCE_ACTIONS | NO_SCOPE_ACTIONS | {"move_file"}
SAME_SCOPE_ACTIONS = {
    # These are two batching forms of the same content-read authority. Expanding
    # only the action while preserving the identical scope lets the agent choose
    # either API without gaining access to another object.
    "read_file": ("read_file", "read_multiple_files"),
    "read_multiple_files": ("read_file", "read_multiple_files"),
}
def canonical_scope(value: Any) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("scope must be a non-empty string without NUL")
    if not value.startswith("/") or any(part == ".." for part in value.split("/")):
        raise ValueError("scope must be absolute and may not contain '..'")
    if any(character in value for character in "?[]"):
        raise ValueError("scope may not contain '?', '[' or ']'")
    if any("**" in segment and segment != "**" for segment in value.split("/")):
        raise ValueError("'**' is allowed only as a complete path segment")
    if posixpath.normpath(value) != value:
        raise ValueError("scope must already be canonical")
    return value


def compile_requirements(requirements: dict[str, Any], *, job_id: str, principal: str = "alice") -> dict[str, Any]:
    if not isinstance(requirements, dict) or set(requirements) != {"operations"}:
        raise ValueError("requirements must contain only operations")
    operations = requirements["operations"]
    if not isinstance(operations, list) or not operations:
        raise ValueError("operations must be a non-empty list")

    grants: list[dict[str, Any]] = []
    seen: set[tuple[str, str | None, str | None]] = set()
    for index, operation in enumerate(operations):
        required = {"capability", "resource_scope"}
        allowed = required | {"destination_scope"}
        if not isinstance(operation, dict) or not required <= set(operation) or not set(operation) <= allowed:
            raise ValueError(f"operation {index} has invalid fields")
        action = operation["capability"]
        if action not in ALL_ACTIONS:
            raise ValueError(f"operation {index} has unsupported capability")
        resource, destination = operation["resource_scope"], operation.get("destination_scope")
        if action in RESOURCE_ACTIONS:
            resource = canonical_scope(resource)
            if destination is not None:
                raise ValueError(f"{action} may not have a destination")
        elif action == "move_file":
            resource, destination = canonical_scope(resource), canonical_scope(destination)
        else:
            if resource is not None or destination is not None:
                raise ValueError(f"{action} may not have path scopes")
        for compiled_action in SAME_SCOPE_ACTIONS.get(action, (action,)):
            key = (compiled_action, resource, destination)
            if key in seen:
                continue
            seen.add(key)
            grants.append({
                "tool": "OS-filesystem",
                "actions": [compiled_action],
                "resources": [] if resource is None else [resource],
                "recipients": [],
                "destinations": [] if destination is None else [destination],
            })

    policy = {
        "schema_version": 1,
        "policy_id": f"dtap-{job_id}",
        "job_id": job_id,
        "principal": principal,
        "allow": grants,
        "data_rules": {},
        "approval_rules": {},
        "delegation": {"max_depth": 0, "child_may_expand_authority": False},
    }
    policy_from_dict(policy)
    return policy


def validate_policy(policy: dict[str, Any]) -> None:
    parsed = policy_from_dict(policy)
    for index, grant in enumerate(parsed.allow):
        if grant.tool != "OS-filesystem" or len(grant.actions) != 1:
            raise ValueError(f"grant {index} must have one OS-filesystem action")
        action = grant.actions[0]
        if action not in ALL_ACTIONS or grant.recipients:
            raise ValueError(f"grant {index} has an unsupported action or recipient")
        resources = [canonical_scope(value) for value in grant.resources]
        destinations = [canonical_scope(value) for value in grant.destinations]
        if action in RESOURCE_ACTIONS and (not resources or destinations):
            raise ValueError(f"grant {index} has invalid resource/destination arity")
        if action == "move_file" and (not resources or not destinations):
            raise ValueError(f"grant {index} must bind source and destination")
        if action in NO_SCOPE_ACTIONS and (resources or destinations):
            raise ValueError(f"grant {index} must not have path scopes")
    if parsed.data_rules or parsed.approval_rules or parsed.delegation != {
        "max_depth": 0, "child_may_expand_authority": False
    }:
        raise ValueError("DTAP policy has unsupported contextual rules")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--requirements", required=True)
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--principal", default="alice")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = compile_requirements(
        json.loads(Path(args.requirements).read_text()), job_id=args.job_id, principal=args.principal
    )
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")


if __name__ == "__main__":
    main()
