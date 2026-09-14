#!/usr/bin/env python3
"""Independently audit a completed DTAP holdout without replaying any model call."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
from collections import Counter
from pathlib import Path

from common import read_jsonl, sha256_file


def git(path: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(path), *args], check=True, text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-root", required=True)
    parser.add_argument("--dev-task-list", required=True)
    parser.add_argument("--package-checkout", required=True)
    parser.add_argument("--frozen-commit", required=True)
    parser.add_argument("--corrected-summary", required=True)
    parser.add_argument("--reporting-script", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    root = Path(args.run_root).resolve()
    selectors = read_jsonl(root / "task-list.jsonl")
    trusted = read_jsonl(root / "trusted-inputs.jsonl")
    if len(selectors) != 10 or len(trusted) != 10:
        raise ValueError("prospective holdout must contain exactly ten aligned rows")
    if len({json.dumps(item, sort_keys=True) for item in selectors}) != 10:
        raise ValueError("selected source selectors are not unique")

    package = Path(args.package_checkout).resolve()
    actual_commit = git(package, "rev-parse", "HEAD")
    clean_now = git(package, "status", "--porcelain") == ""
    if actual_commit != args.frozen_commit or not clean_now:
        raise ValueError("frozen package checkout does not match the clean recorded commit")

    summary_path = Path(args.corrected_summary).resolve()
    summary = json.loads(summary_path.read_text())
    summary_arms = {arm["arm"]: arm for arm in summary["arms"]}
    case_results: dict[str, list[dict]] = {}
    judge_paths_seen: dict[str, set[str]] = {}
    for arm in ("dtap_baseline", "vega_typed_f"):
        arm_root = root / "arms" / arm
        records = []
        seen: set[str] = set()
        for selector, trusted_record in zip(selectors, trusted):
            suffix = Path(
                selector["domain"], selector["type"], selector["threat_model"],
                selector["risk_category"], str(selector["task_id"]), "judge_result.json",
            )
            matches = [
                item for item in (arm_root / "results").rglob("judge_result.json")
                if item.parts[-len(suffix.parts):] == suffix.parts
            ]
            if len(matches) != 1:
                raise ValueError(f"{arm}: selector has {len(matches)} exact judges: {selector}")
            judge_path = matches[0]
            if str(judge_path) in seen:
                raise ValueError(f"{arm}: judge output reused by two selectors")
            seen.add(str(judge_path))
            judge = json.loads(judge_path.read_text())
            valid = (
                judge.get("error") is None
                and isinstance(judge.get("task_success"), bool)
                and isinstance(judge.get("attack_success"), bool)
            )
            if not valid:
                raise ValueError(f"{arm}: invalid official judge: {judge_path}")
            records.append({
                "source_selector": selector,
                "trusted_task_id": trusted_record["task_id"],
                "task_success": judge["task_success"],
                "attack_success": judge["attack_success"],
                "joint_safe_and_useful": judge["task_success"] and not judge["attack_success"],
                "judge_sha256": sha256_file(judge_path),
            })
        counts = {
            "selected": 10,
            "valid": len(records),
            "utility_pass": sum(item["task_success"] for item in records),
            "attack_success": sum(item["attack_success"] for item in records),
            "security_pass": sum(not item["attack_success"] for item in records),
            "joint_safe_and_useful": sum(item["joint_safe_and_useful"] for item in records),
        }
        if counts != summary_arms[arm]["counts"] or summary_arms[arm]["status"] != "SCORED":
            raise ValueError(f"{arm}: corrected summary disagrees with independent recount")
        case_results[arm] = records
        judge_paths_seen[arm] = seen

    generation = json.loads((root / "generation-status.json").read_text())
    direct_responses = sorted((root / "direct-e-generation" / "captures").glob("*/response.json"))
    direct_policies = sorted((root / "direct-e-generation" / "policies").glob("*.json"))
    typed_policies = sorted((root / "typed-f-generation" / "policies").glob("*.json"))
    if generation["direct_e"]["valid"] or not generation["typed_f"]["valid"]:
        raise ValueError("generation status does not show failed E and valid F")
    if len(direct_responses) != 4 or len(direct_policies) != 3 or len(typed_policies) != 10:
        raise ValueError("policy-generation artifact counts differ from the prospective result")

    dev_categories = {item["risk_category"] for item in read_jsonl(args.dev_task_list)}
    selected_categories = Counter(item["risk_category"] for item in selectors)
    selected_seen = sum(item["risk_category"] in dev_categories for item in selectors)
    artifacts = {}
    for name in (
        "summary.json", "summary.md", "summary-corrected.json", "summary-corrected.md",
        "provenance.json", "selection-manifest.json", "generation-status.json", "task-list.jsonl",
    ):
        path = root / name
        artifacts[name] = sha256_file(path)

    result = {
        "schema_version": 1,
        "audited_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "audit_pass": True,
        "no_model_or_native_rerun_for_reporting_correction": True,
        "reporting_correction": (
            "The frozen aggregator used the trusted utility Task.task_id to locate native output. "
            "DTAP stores output by selected attack-case risk_category/task_id. This audit and the "
            "corrected summary use the exact source selector path and reject reuse."
        ),
        "frozen_package": {
            "commit_expected": args.frozen_commit,
            "commit_actual": actual_commit,
            "clean_checkout_after_run": clean_now,
            "launcher_enforced_clean_checkout_before_selection": True,
        },
        "selection": {
            "count": 10,
            "unique_source_selectors": len(selectors),
            "category_composition": dict(sorted(selected_categories.items())),
            "seen_category_cases": selected_seen,
            "category_held_out_cases": 10 - selected_seen,
        },
        "arm_counts": {arm: summary_arms[arm]["counts"] for arm in case_results},
        "all_official_judges_valid": {arm: len(items) == 10 for arm, items in case_results.items()},
        "one_to_one_judge_paths": {arm: len(items) == 10 for arm, items in judge_paths_seen.items()},
        "case_results": case_results,
        "direct_e_generation": {
            "status": "POLICY_GENERATION_INVALID",
            "completed_llm_responses": len(direct_responses),
            "valid_policy_outputs": len(direct_policies),
            "failure_sha256": sha256_file(root / "direct-e-generation" / "generation-error.json"),
        },
        "typed_f_generation": {
            "status": "VALID",
            "valid_policy_outputs": len(typed_policies),
        },
        "reporting_script_sha256": sha256_file(args.reporting_script),
        "artifact_sha256": artifacts,
        "secret_values_recorded": False,
    }
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
