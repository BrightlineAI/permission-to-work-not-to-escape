from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .canonical import canonical_hash

REQUEST_FIELDS = {
    "tool", "action", "resource", "recipient", "destination", "amount", "payload",
    "approval_handle",
}
POLICY_FIELDS = {
    "schema_version", "policy_id", "job_id", "principal", "allow", "data_rules",
    "approval_rules", "delegation",
}
ALLOW_FIELDS = {"tool", "actions", "resources", "recipients", "destinations"}


class SchemaError(ValueError):
    pass


def _exact_keys(value: dict[str, Any], expected: set[str], where: str) -> None:
    missing, extra = expected - value.keys(), value.keys() - expected
    if missing or extra:
        raise SchemaError(f"{where}: missing={sorted(missing)} extra={sorted(extra)}")


@dataclass(frozen=True)
class Grant:
    tool: str
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    recipients: tuple[str, ...]
    destinations: tuple[str, ...]


@dataclass(frozen=True)
class Policy:
    schema_version: int
    policy_id: str
    job_id: str
    principal: str
    allow: tuple[Grant, ...]
    data_rules: dict[str, dict[str, list[str]]]
    approval_rules: dict[str, dict[str, Any]]
    delegation: dict[str, Any]
    raw: dict[str, Any] = field(repr=False)
    policy_hash: str


@dataclass(frozen=True)
class Request:
    tool: str
    action: str
    resource: str | None
    recipient: str | None
    destination: str | None
    amount: str | None
    payload: str
    approval_handle: str | None

    def as_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in sorted(REQUEST_FIELDS)}


@dataclass(frozen=True)
class TrustedContext:
    job_id: str
    principal: str
    data_labels: tuple[str, ...] = ()
    approval: dict[str, Any] | None = None
    delegation_depth: int = 0
    child_expands_authority: bool = False
    missing: tuple[str, ...] = ()


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    policy_hash: str
    job_id: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "policy_hash": self.policy_hash,
            "job_id": self.job_id,
        }


def policy_from_dict(value: dict[str, Any]) -> Policy:
    if not isinstance(value, dict):
        raise SchemaError("policy must be an object")
    _exact_keys(value, POLICY_FIELDS, "policy")
    if value["schema_version"] != 1:
        raise SchemaError("unsupported schema_version")
    for name in ("policy_id", "job_id", "principal"):
        if not isinstance(value[name], str) or not value[name]:
            raise SchemaError(f"{name} must be a non-empty string")
    if not isinstance(value["allow"], list) or not value["allow"]:
        raise SchemaError("allow must be a non-empty list")
    grants = []
    for index, item in enumerate(value["allow"]):
        if not isinstance(item, dict):
            raise SchemaError(f"allow[{index}] must be an object")
        _exact_keys(item, ALLOW_FIELDS, f"allow[{index}]")
        if not isinstance(item["tool"], str) or not item["tool"]:
            raise SchemaError(f"allow[{index}].tool must be a non-empty string")
        for name in ALLOW_FIELDS - {"tool"}:
            if not isinstance(item[name], list) or not all(isinstance(x, str) for x in item[name]):
                raise SchemaError(f"allow[{index}].{name} must be a string list")
        grants.append(Grant(item["tool"], *(tuple(item[n]) for n in ("actions", "resources", "recipients", "destinations"))))
    for name in ("data_rules", "approval_rules", "delegation"):
        if not isinstance(value[name], dict):
            raise SchemaError(f"{name} must be an object")
    for label, rule in value["data_rules"].items():
        if not isinstance(label, str) or not label or not isinstance(rule, dict) or set(rule) != {"allowed_destinations"}:
            raise SchemaError("data_rules entries require one named allowed_destinations rule")
        destinations = rule["allowed_destinations"]
        if not isinstance(destinations, list) or not destinations or not all(isinstance(item, str) and item for item in destinations):
            raise SchemaError("data_rules allowed_destinations must be a non-empty string list")
    allowed_tools = {grant.tool for grant in grants}
    for tool, rule in value["approval_rules"].items():
        if tool not in allowed_tools or not isinstance(rule, dict) or set(rule) != {"required_issuer", "bind_fields"}:
            raise SchemaError("approval_rules must name an allowed tool and contain issuer/bind fields")
        if not isinstance(rule["required_issuer"], str) or not rule["required_issuer"]:
            raise SchemaError("approval required_issuer must be non-empty")
        if not isinstance(rule["bind_fields"], list) or not rule["bind_fields"] or not set(rule["bind_fields"]) <= {"resource", "amount"}:
            raise SchemaError("approval bind_fields must contain resource and/or amount")
    delegation = value["delegation"]
    if set(delegation) != {"max_depth", "child_may_expand_authority"}:
        raise SchemaError("delegation has invalid fields")
    if not isinstance(delegation["max_depth"], int) or delegation["max_depth"] < 0:
        raise SchemaError("delegation.max_depth must be a non-negative integer")
    if not isinstance(delegation["child_may_expand_authority"], bool):
        raise SchemaError("delegation.child_may_expand_authority must be boolean")
    return Policy(
        value["schema_version"], value["policy_id"], value["job_id"], value["principal"],
        tuple(grants), value["data_rules"], value["approval_rules"], delegation, value,
        canonical_hash(value),
    )


def load_policy(path: str | Path) -> Policy:
    return policy_from_dict(json.loads(Path(path).read_text()))


def normalize_tool_call(call: dict[str, Any]) -> Request:
    if not isinstance(call, dict):
        raise SchemaError("tool call must be an object")
    extra = call.keys() - REQUEST_FIELDS
    if extra:
        raise SchemaError(f"request has unknown fields: {sorted(extra)}")
    value = {name: call.get(name) for name in REQUEST_FIELDS}
    for name in ("tool", "action"):
        if not isinstance(value[name], str) or not value[name]:
            raise SchemaError(f"request.{name} must be a non-empty string")
    for name in REQUEST_FIELDS - {"tool", "action"}:
        if value[name] is not None and not isinstance(value[name], str):
            raise SchemaError(f"request.{name} must be string or null")
    value["payload"] = value["payload"] or ""
    return Request(**value)
