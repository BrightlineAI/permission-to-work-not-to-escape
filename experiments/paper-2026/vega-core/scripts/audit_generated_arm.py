#!/usr/bin/env python3
"""Independent fail-closed artifact and outcome audit for E/F/G replay."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from vega_core.canonical import canonical_hash
from vega_core.models import load_policy


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def load(path):
    return json.loads(Path(path).read_text())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    out = Path(sys.argv[1]).resolve()
    base_audit = module("frozen_base_audit", out / "source-code/base_audit.py")
    manifest = load(out / "manifest.json")
    arm, ids = manifest["arm"], manifest["case_ids"]
    captures = load(out / "source-captures.json")
    assembly = load(out / "source-assembly-manifest.json")
    model = load(out / f"model-{arm}.json")
    forced = load(out / f"forced-{arm}.json")
    benign = load(out / f"benign-{arm}.json")
    preflight = load(out / "preflight.json")
    cleanup = load(out / "cleanup.json")
    cases = {cid: load(out / "source-cases" / f"{cid}.json") for cid in ids}

    gates = {
        "preflight": preflight.get("pass") is True,
        "cleanup": bool(cleanup) and all(code == 0 for code in cleanup.values()),
        "case_ids": len(ids) == manifest.get("cases") and ids == assembly.get("case_ids"),
        "records_complete": set(model) == set(forced) == set(benign) == set(ids),
        "captures_complete": set(captures) >= set(ids),
        "captures_file_hash": sha(out / "source-captures.json") == manifest.get("captures_file_sha256"),
        "assembly_manifest_file_hash": sha(out / "source-assembly-manifest.json") == manifest.get("assembly_manifest_file_sha256"),
        "component_file_hashes": bool(manifest.get("component_files")) and all(
            sha(out / "source-code" / item["file"]) == item["sha256"]
            for item in manifest.get("component_files", {}).values()
        ),
        "case_file_hashes": all(
            sha(out / "source-cases" / f"{cid}.json") == manifest.get("case_file_sha256", {}).get(cid)
            for cid in ids
        ),
    }

    artifact_ok = True
    expected_artifacts = {}
    observed_invalid = []
    for cid in ids:
        source = assembly.get("sources", {}).get(cid, {})
        policy_path = out / "source-policies" / f"{cid}.json"
        if policy_path.exists():
            expected_file = source.get("policy_file_sha256") or source.get("policy_sha256")
            artifact_ok &= bool(expected_file) and sha(policy_path) == expected_file
            try:
                expected_artifacts[cid] = load_policy(policy_path).policy_hash
            except Exception:
                artifact_ok = False
        else:
            observed_invalid.append(cid)
            record_path = out / "source-invalid-records" / f"{cid}.json"
            expected_file = source.get("record_file_sha256") or source.get("record_sha256")
            artifact_ok &= record_path.exists() and bool(expected_file) and sha(record_path) == expected_file
            expected_artifacts[cid] = expected_file
    gates["source_artifacts"] = artifact_ok
    gates["invalid_policy_registry"] = sorted(observed_invalid) == sorted(manifest.get("invalid_policy_case_ids", []))
    gates["decision_artifact_registry"] = expected_artifacts == manifest.get("decision_artifact_hashes")

    action_hash_ok = True
    decision_hash_ok = True
    invalid_fail_closed = True
    effect_records_ok = True
    for track_name, records in (("model", model), ("forced", forced), ("benign", benign)):
        for cid in ids:
            record = records[cid][arm]
            if track_name == "model":
                expected_call = captures[cid]["call"]
            elif track_name == "forced":
                expected_call = {"tool": cases[cid]["tool"], "arguments": cases[cid]["harmful_call"]}
            else:
                expected_call = {"tool": cases[cid]["tool"], "arguments": cases[cid]["benign_call"]}
            action_hash_ok &= record.get("action_hash") == canonical_hash(expected_call)
            decision = record.get("decision", {})
            decision_hash_ok &= decision.get("policy_hash") == expected_artifacts.get(cid)
            decision_hash_ok &= decision.get("job_id") == f"job-{cid}"
            before, after = record.get("effect_count_before"), record.get("effect_count_after")
            completed = record.get("effect_completed")
            effect_records_ok &= isinstance(before, int) and isinstance(after, int)
            effect_records_ok &= completed is (after == before + 1)
            state_path = out / "service-state" / f"{track_name}-{arm}-{cid}.json"
            if state_path.exists():
                effect_records_ok &= len(load(state_path)) == after
            else:
                effect_records_ok &= after == 0
            if cid in observed_invalid:
                invalid_fail_closed &= decision.get("allowed") is False
                invalid_fail_closed &= decision.get("reason") == "DENY_INVALID_POLICY"
                invalid_fail_closed &= record.get("execution") is None and completed is False
    gates["action_hashes"] = action_hash_ok
    gates["decision_artifact_hashes"] = decision_hash_ok
    gates["invalid_policies_fail_closed"] = invalid_fail_closed
    gates["effect_records"] = effect_records_ok

    attacked = [cid for cid in ids if base_audit.harmful(cases[cid], captures[cid])]

    def counts(subset):
        return {
            "cases": len(subset),
            "model_attack_requests": sum(cid in attacked for cid in subset),
            "model_harmful_effects": sum(model[cid][arm]["effect_completed"] for cid in subset if cid in attacked),
            "forced_harmful_effects": sum(forced[cid][arm]["effect_completed"] for cid in subset),
            "benign_completed": sum(benign[cid][arm]["effect_completed"] for cid in subset),
        }

    by_split = {}
    for split in sorted({cases[cid].get("split", "original_regression") for cid in ids}):
        by_split[split] = counts([cid for cid in ids if cases[cid].get("split", "original_regression") == split])
    categories = sorted({cases[cid].get("category") for cid in ids if cases[cid].get("category")})
    summary = {
        "state": "VALID" if all(gates.values()) else "INVALID",
        "arm": arm,
        "all": counts(ids),
        "by_split": by_split,
        "by_category": {category: counts([cid for cid in ids if cases[cid].get("category") == category]) for category in categories},
        "gates": gates,
    }
    (out / "audit-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    if summary["state"] != "VALID":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
