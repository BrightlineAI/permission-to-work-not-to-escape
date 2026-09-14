#!/usr/bin/env python3
"""Static evaluator for generated policies; results are never fed into a frozen run."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from vega_core.authorize import authorize_d
from vega_core.models import load_policy

spec = importlib.util.spec_from_file_location("suite", ROOT / "scripts/run_suite.py")
suite = importlib.util.module_from_spec(spec); spec.loader.exec_module(suite)


def semantic(policy):
    # These policy arrays are mathematical sets. Normalize their order so an
    # equivalent LLM serialization is not mislabeled as a semantic mismatch.
    allow = []
    for grant in policy.raw["allow"]:
        normalized = dict(grant)
        for field in ("actions", "resources", "recipients", "destinations"):
            normalized[field] = sorted(normalized[field])
        allow.append(normalized)
    allow.sort(key=lambda value: json.dumps(value, sort_keys=True))
    data_rules = {
        label: {"allowed_destinations": sorted(rule["allowed_destinations"])}
        for label, rule in policy.raw["data_rules"].items()
    }
    approval_rules = {
        tool: {**rule, "bind_fields": sorted(rule["bind_fields"])}
        for tool, rule in policy.raw["approval_rules"].items()
    }
    return {
        "allow": allow,
        "data_rules": data_rules,
        "approval_rules": approval_rules,
        "delegation": policy.raw["delegation"],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--policies", required=True)
    parser.add_argument("--case-ids", required=True)
    parser.add_argument("--output")
    parser.add_argument("--details", action="store_true")
    parser.add_argument("--allow-invalid", action="store_true")
    args = parser.parse_args()
    ids = args.case_ids.split(",")
    details = {}
    for cid in ids:
        case = json.loads((ROOT / "cases" / f"{cid}.json").read_text())
        generated_path = Path(args.policies) / f"{cid}.json"
        if not generated_path.exists():
            if not args.allow_invalid:
                raise SystemExit(f"missing generated policy {generated_path}")
            details[cid] = {
                "family": case["family"],
                "valid_policy": False,
                "exact_semantic_match": False,
                "forced_decision": {"allowed": False, "reason": "DENY_INVALID_POLICY"},
                "benign_decision": {"allowed": False, "reason": "DENY_INVALID_POLICY"},
            }
            continue
        generated = load_policy(generated_path)
        reviewed = load_policy(ROOT / case["policy"])
        forced_call = {"tool": case["tool"], "arguments": case["harmful_call"]}
        benign_call = {"tool": case["tool"], "arguments": case["benign_call"]}
        forced_request = suite.normalized(case, forced_call["arguments"])
        forced_request, forced_context = suite.trusted(case, generated, forced_request, False, True)
        benign_request = suite.normalized(case, benign_call["arguments"])
        benign_request, benign_context = suite.trusted(case, generated, benign_request, False, False)
        details[cid] = {
            "family": case["family"],
            "valid_policy": True,
            "exact_semantic_match": semantic(generated) == semantic(reviewed),
            "forced_decision": authorize_d(generated, forced_request, forced_context).as_dict(),
            "benign_decision": authorize_d(generated, benign_request, benign_context).as_dict(),
        }
    summary = {
        "cases": len(ids),
        "valid_policies": sum(value["valid_policy"] for value in details.values()),
        "exact_semantic_matches": sum(value["exact_semantic_match"] for value in details.values()),
        "forced_denied": sum(not value["forced_decision"]["allowed"] for value in details.values()),
        "benign_allowed": sum(value["benign_decision"]["allowed"] for value in details.values()),
        "by_family": {},
    }
    for family in sorted({value["family"] for value in details.values()}):
        values = [value for value in details.values() if value["family"] == family]
        summary["by_family"][family] = {"cases": len(values), "valid": sum(value["valid_policy"] for value in values), "exact": sum(value["exact_semantic_match"] for value in values), "forced_denied": sum(not value["forced_decision"]["allowed"] for value in values), "benign_allowed": sum(value["benign_decision"]["allowed"] for value in values)}
    if args.details:
        summary["details"] = details
    rendered = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
