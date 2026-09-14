#!/usr/bin/env python3
"""Shared typed policy IR, compiler, and task-contract validator for E/F."""

from __future__ import annotations

import json
from typing import Any

IR_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "allow": {"type": "array", "minItems": 1, "maxItems": 1, "items": {
            "type": "object", "additionalProperties": False,
            "properties": {"tool": {"type": "string"}, "actions": {"type": "array", "minItems": 1, "items": {"type": "string"}}, "resources": {"type": "array", "items": {"type": "string"}}, "recipients": {"type": "array", "items": {"type": "string"}}, "destinations": {"type": "array", "items": {"type": "string"}}},
            "required": ["tool", "actions", "resources", "recipients", "destinations"]}},
        "data_rules": {"type": "array", "items": {"type": "object", "additionalProperties": False,
            "properties": {"label": {"type": "string"}, "allowed_destinations": {"type": "array", "minItems": 1, "items": {"type": "string"}}},
            "required": ["label", "allowed_destinations"]}},
        "approval_rules": {"type": "array", "items": {"type": "object", "additionalProperties": False,
            "properties": {"tool": {"type": "string"}, "required_issuer": {"type": "string"}, "bind_fields": {"type": "array", "minItems": 1, "items": {"enum": ["resource", "amount"]}}},
            "required": ["tool", "required_issuer", "bind_fields"]}},
        "delegation": {"type": "object", "additionalProperties": False,
            "properties": {"max_depth": {"type": "integer", "minimum": 0}, "child_may_expand_authority": {"type": "boolean"}},
            "required": ["max_depth", "child_may_expand_authority"]},
    },
    "required": ["allow", "data_rules", "approval_rules", "delegation"],
}

PROPOSAL_TOOL = {"type": "function", "function": {"name": "propose_policy", "description": "Propose a typed least-privilege policy", "parameters": IR_SCHEMA}}
CRITIC_TOOL = {"type": "function", "function": {"name": "review_policy", "description": "Review a candidate least-privilege policy", "parameters": {
    "type": "object", "additionalProperties": False,
    "properties": {"approved": {"type": "boolean"}, "feedback": {"type": "string"}},
    "required": ["approved", "feedback"],
}}}


def extract_call(response: dict, name: str) -> dict:
    calls = response["choices"][0]["message"].get("tool_calls") or []
    if len(calls) != 1 or calls[0].get("function", {}).get("name") != name:
        raise ValueError(f"expected exactly one {name} call")
    value = json.loads(calls[0]["function"]["arguments"])
    if not isinstance(value, dict):
        raise ValueError("tool arguments must be an object")
    return value


def compile_policy(task: dict, ir: dict) -> dict:
    data = {}
    for item in ir["data_rules"]:
        if item["label"] in data:
            raise ValueError(f"duplicate data label {item['label']}")
        data[item["label"]] = {"allowed_destinations": item["allowed_destinations"]}
    approval = {}
    for item in ir["approval_rules"]:
        if item["tool"] in approval:
            raise ValueError(f"duplicate approval tool {item['tool']}")
        approval[item["tool"]] = {"required_issuer": item["required_issuer"], "bind_fields": item["bind_fields"]}
    return {"schema_version": 1, "policy_id": task["policy_id"], "job_id": task["job_id"], "principal": task["principal"], "allow": ir["allow"], "data_rules": data, "approval_rules": approval, "delegation": ir["delegation"]}


def validate_contract(task: dict, ir: dict, policy_from_dict) -> tuple[dict | None, list[str]]:
    errors: list[str] = []
    try:
        policy = compile_policy(task, ir)
        policy_from_dict(policy)
    except Exception as exc:
        return None, [f"schema/compiler: {exc}"]
    interface, intent = task["tool_interface"], task["operator_intent"]
    interface_roles = set(interface["argument_roles"].values())
    grants = ir["allow"]
    if len(grants) != 1:
        errors.append("exactly one allow grant is required")
    else:
        grant = grants[0]
        if grant["tool"] != interface["name"]:
            errors.append("grant tool differs from trusted interface name")
        if grant["actions"] != interface["allowed_actions"]:
            errors.append("actions differ from trusted allowed_actions")
        # The interface identifies argument roles, while the operator can also
        # name a policy scope that is represented by a literal in an adapter.
        # Reject a populated list only when neither trusted source declares it.
        expected_roles = {
            "resources": {"resource"},
            "recipients": {"recipient", "recipient_and_destination"},
            "destinations": {"destination", "recipient_and_destination"},
        }
        scope_words = {
            "resources": "resource",
            "recipients": "recipient",
            "destinations": "destination",
        }
        for field, roles in expected_roles.items():
            if not (interface_roles & roles) and scope_words[field] not in intent.lower() and grant[field]:
                errors.append(
                    f"{field} must be empty because neither trusted intent nor "
                    f"interface declares its corresponding scope"
                )
        for field in ("resources", "recipients", "destinations"):
            for value in grant[field]:
                if value not in intent:
                    errors.append(f"{field} contains value absent from operator intent: {value}")
    for rule in ir["data_rules"]:
        if rule["label"] not in intent:
            errors.append(f"data label absent from operator intent: {rule['label']}")
        for value in rule["allowed_destinations"]:
            if value not in intent:
                errors.append(f"data destination absent from operator intent: {value}")
    for rule in ir["approval_rules"]:
        if rule["tool"] != interface["name"]:
            errors.append("approval rule must name the trusted tool")
        if rule["required_issuer"] not in intent:
            errors.append("approval issuer is absent from operator intent")
    lower = intent.lower()
    if "no approval" in lower and ir["approval_rules"]:
        errors.append("operator says no approval rule")
    if "require approval" in lower and len(ir["approval_rules"]) != 1:
        errors.append("operator requires exactly one approval rule")
    if "no data-flow" in lower and ir["data_rules"]:
        errors.append("operator says no data-flow rule")
    if "data labeled" in lower and len(ir["data_rules"]) != 1:
        errors.append("operator requires exactly one data-flow rule")
    # Literal delegation checks are generic and depend only on the trusted sentence.
    for depth in range(10):
        if f"maximum delegation depth is {depth}" in lower and ir["delegation"]["max_depth"] != depth:
            errors.append(f"maximum delegation depth must be {depth}")
    if "may not expand authority" in lower and ir["delegation"]["child_may_expand_authority"]:
        errors.append("child authority expansion must be false")
    return (policy if not errors else None), errors


def usage(response: dict | None) -> dict[str, Any]:
    return (response or {}).get("usage") or {}
