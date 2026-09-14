import importlib.util
import json
from pathlib import Path

from vega_core.models import policy_from_dict


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "policy_pipeline", ROOT / "scripts/policy_pipeline.py"
)
PIPELINE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PIPELINE)


def test_destination_is_not_accepted_as_recipient():
    task = json.loads((ROOT / "e/trusted_tasks/case-001.json").read_text())
    proposal = {
        "allow": [{
            "tool": "github_mutation",
            "actions": ["upload_release"],
            "resources": ["org/assigned-01"],
            "recipients": ["release-01.tar.gz"],
            "destinations": ["release-01.tar.gz"],
        }],
        "data_rules": [],
        "approval_rules": [],
        "delegation": {"max_depth": 0, "child_may_expand_authority": False},
    }

    policy, errors = PIPELINE.validate_contract(task, proposal, policy_from_dict)

    assert policy is None
    assert any("recipients must be empty" in error for error in errors)


def test_operator_literal_resource_is_allowed_without_resource_argument():
    task = json.loads((ROOT / "e/trusted_tasks/case-021.json").read_text())
    proposal = {
        "allow": [{
            "tool": "send_email",
            "actions": ["send"],
            "resources": ["trip-01"],
            "recipients": ["owner-01@example.test"],
            "destinations": ["owner-01@example.test"],
        }],
        "data_rules": [],
        "approval_rules": [],
        "delegation": {"max_depth": 0, "child_may_expand_authority": False},
    }

    policy, errors = PIPELINE.validate_contract(task, proposal, policy_from_dict)

    assert errors == []
    assert policy is not None


def test_recipient_and_destination_role_populates_both_lists():
    task = json.loads((ROOT / "ef/trusted_tasks/case-101.json").read_text())
    proposal = {
        "allow": [{
            "tool": "publish_release",
            "actions": ["publish"],
            "resources": ["release-01-01"],
            "recipients": ["registry-01-01@example.test"],
            "destinations": ["registry-01-01@example.test"],
        }],
        "data_rules": [{
            "label": "confidential",
            "allowed_destinations": ["restricted-registry-01-01"],
        }],
        "approval_rules": [],
        "delegation": {"max_depth": 0, "child_may_expand_authority": False},
    }

    policy, errors = PIPELINE.validate_contract(task, proposal, policy_from_dict)

    assert errors == []
    assert policy is not None
