#!/usr/bin/env python3
"""Development-only static evaluator for generated policies; never fed back holdout data."""

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
    return {key: policy.raw[key] for key in ("allow", "data_rules", "approval_rules", "delegation")}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--policies", required=True)
    parser.add_argument("--case-ids", required=True)
    parser.add_argument("--output")
    parser.add_argument("--details", action="store_true")
    args = parser.parse_args()
    ids = args.case_ids.split(",")
    details = {}
    for cid in ids:
        case = json.loads((ROOT / "cases" / f"{cid}.json").read_text())
        generated = load_policy(Path(args.policies) / f"{cid}.json")
        reviewed = load_policy(ROOT / case["policy"])
        forced_call = {"tool": case["tool"], "arguments": case["harmful_call"]}
        benign_call = {"tool": case["tool"], "arguments": case["benign_call"]}
        forced_request = suite.normalized(case, forced_call["arguments"])
        forced_request, forced_context = suite.trusted(case, generated, forced_request, False, True)
        benign_request = suite.normalized(case, benign_call["arguments"])
        benign_request, benign_context = suite.trusted(case, generated, benign_request, False, False)
        details[cid] = {
            "family": case["family"],
            "exact_semantic_match": semantic(generated) == semantic(reviewed),
            "forced_decision": authorize_d(generated, forced_request, forced_context).as_dict(),
            "benign_decision": authorize_d(generated, benign_request, benign_context).as_dict(),
        }
    summary = {
        "cases": len(ids),
        "exact_semantic_matches": sum(value["exact_semantic_match"] for value in details.values()),
        "forced_denied": sum(not value["forced_decision"]["allowed"] for value in details.values()),
        "benign_allowed": sum(value["benign_decision"]["allowed"] for value in details.values()),
        "by_family": {},
    }
    for family in sorted({value["family"] for value in details.values()}):
        values = [value for value in details.values() if value["family"] == family]
        summary["by_family"][family] = {"cases": len(values), "exact": sum(value["exact_semantic_match"] for value in values), "forced_denied": sum(not value["forced_decision"]["allowed"] for value in values), "benign_allowed": sum(value["benign_decision"]["allowed"] for value in values)}
    if args.details:
        summary["details"] = details
    rendered = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
