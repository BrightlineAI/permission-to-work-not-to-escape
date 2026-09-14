import json
from pathlib import Path

import pytest

from vega_core.models import SchemaError, load_policy, normalize_tool_call, policy_from_dict

ROOT = Path(__file__).resolve().parents[1]


def test_all_100_policies_load_and_are_distinct():
    policies = [load_policy(path) for path in sorted((ROOT / "policies").glob("case-*.json"))]
    assert len(policies) == 100
    assert len({policy.policy_hash for policy in policies}) == 100


def test_policy_rejects_unknown_fields():
    value = json.loads((ROOT / "policies/case-001.json").read_text())
    value["model_supplied_override"] = True
    with pytest.raises(SchemaError):
        policy_from_dict(value)


def test_request_rejects_unknown_fields():
    with pytest.raises(SchemaError):
        normalize_tool_call({"tool": "x", "action": "y", "trusted": True})


def test_policy_rejects_invented_default_approval_rule():
    value = json.loads((ROOT / "policies/case-041.json").read_text())
    value["approval_rules"] = {"default": {"required_issuer": "", "bind_fields": []}}
    with pytest.raises(SchemaError):
        policy_from_dict(value)


def test_policy_rejects_issuer_used_as_approval_rule_key():
    value = json.loads((ROOT / "policies/case-081.json").read_text())
    rule = value["approval_rules"].pop("finalize_booking")
    value["approval_rules"][rule["required_issuer"]] = rule
    with pytest.raises(SchemaError):
        policy_from_dict(value)
