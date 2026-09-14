#!/usr/bin/env python3
"""Generate E or proposer/critic F policies from trusted pre-job records only."""

from __future__ import annotations

import argparse
import concurrent.futures
import importlib.util
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src")); sys.path.insert(0, str(ROOT / "scripts"))
from vega_core.canonical import canonical_hash
from vega_core.models import policy_from_dict
from policy_pipeline import CRITIC_TOOL, PROPOSAL_TOOL, compile_policy, extract_call, usage, validate_contract

MODEL = "qwen/qwen3-14b"
PROPOSER = (ROOT / "ef/proposer_prompt.txt").read_text()
CRITIC = (ROOT / "ef/critic_prompt.txt").read_text()


def adapter_module():
    spec = importlib.util.spec_from_file_location("openrouter_adapter", ROOT / "adapters/openrouter.py")
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


def call(adapter, prompt, payload, tool):
    response = adapter.capture(MODEL, [{"role": "system", "content": prompt}, {"role": "user", "content": json.dumps(payload, sort_keys=True)}], [tool], "high")
    if response.get("model") != MODEL:
        raise RuntimeError(f"unexpected returned model {response.get('model')!r}")
    return response


def contract_guidance(task):
    roles = task["tool_interface"]["argument_roles"]
    return {
        "allow_grants_required": 1,
        "identifier_list_sources": {
            "resources": sorted(name for name, role in roles.items() if role == "resource"),
            "recipients": sorted(name for name, role in roles.items() if role in {"recipient", "recipient_and_destination"}),
            "destinations": sorted(name for name, role in roles.items() if role in {"destination", "recipient_and_destination"}),
        },
        "literal_scope_may_be_declared_in_operator_intent": True,
        "never_copy_an_identifier_to_another_role_without_an_explicit_declaration": True,
        "ordinary_allow_and_labeled_data_rule_are_distinct_layers": True,
    }


def generate_one(adapter, task, mode, max_rounds):
    started, transcript, candidate, feedback = time.monotonic(), [], None, []
    for round_number in range(1, max_rounds + 1):
        payload = {"trusted_operator_record": task, "deterministic_compiler_contract": contract_guidance(task)}
        if candidate is not None:
            payload.update({"candidate_to_revise": candidate, "review_feedback": feedback})
        try:
            response = call(adapter, PROPOSER, payload, PROPOSAL_TOOL)
            candidate = extract_call(response, "propose_policy")
            policy, validation = validate_contract(task, candidate, policy_from_dict)
            transcript.append({"round": round_number, "role": "proposer", "request": payload, "response": response, "candidate": candidate, "validation": validation})
        except Exception as exc:
            transcript.append({"round": round_number, "role": "proposer", "error": repr(exc)})
            feedback = [f"generation error: {exc}"]
            continue
        if mode == "E":
            if policy is not None:
                return result(task, mode, policy, candidate, transcript, None, started)
            feedback = validation
            continue
        critic_payload = {
            "trusted_operator_record": task,
            "deterministic_compiler_contract": contract_guidance(task),
            "candidate_policy": candidate,
            "deterministic_validation_findings": validation,
        }
        try:
            critic_response = call(adapter, CRITIC, critic_payload, CRITIC_TOOL)
            review = extract_call(critic_response, "review_policy")
            transcript.append({"round": round_number, "role": "critic", "request": critic_payload, "response": critic_response, "review": review})
        except Exception as exc:
            transcript.append({"round": round_number, "role": "critic", "error": repr(exc)})
            feedback = validation + [f"critic error: {exc}"]
            continue
        if review.get("approved") is True and policy is not None:
            return result(task, mode, policy, candidate, transcript, None, started)
        feedback = validation + [str(review.get("feedback", "critic rejected candidate"))]
    return result(task, mode, None, candidate, transcript, "round limit exhausted", started)


def result(task, mode, policy, ir, transcript, error, started):
    responses = [item.get("response") for item in transcript if item.get("response")]
    return {"task": task, "mode": mode, "model": MODEL, "critic_model": MODEL if mode == "F" else None,
            "policy": policy, "policy_sha256": canonical_hash(policy) if policy else None, "final_ir": ir,
            "error": error, "rounds": max((item["round"] for item in transcript), default=0), "transcript": transcript,
            "reported_cost_usd": sum(usage(x).get("cost", 0) or 0 for x in responses),
            "prompt_tokens": sum(usage(x).get("prompt_tokens", 0) for x in responses),
            "completion_tokens": sum(usage(x).get("completion_tokens", 0) for x in responses),
            "seconds": time.monotonic() - started}


def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True); path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["E", "F"], required=True)
    parser.add_argument("--split", choices=["development", "validation_1", "validation_2", "final_holdout", "original_regression"], required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--max-rounds", type=int)
    args = parser.parse_args()
    output = Path(args.output).resolve(); output.mkdir(parents=True, exist_ok=False)
    split_manifest = json.loads((ROOT / "ef/split_manifest.json").read_text())
    if args.split == "original_regression":
        ids = [f"case-{i:03}" for i in range(1, 101)]; task_root = ROOT / "e/trusted_tasks"
    else:
        ids = split_manifest["splits"][args.split]; task_root = ROOT / "ef/trusted_tasks"
    max_rounds = args.max_rounds or (3 if args.mode == "E" else 5)
    tasks = [json.loads((task_root / f"{cid}.json").read_text()) for cid in ids]
    manifest = {"created_at": datetime.now(timezone.utc).isoformat(), "mode": args.mode, "split": args.split, "case_ids": ids,
                "model": MODEL, "critic_model": MODEL if args.mode == "F" else None, "max_rounds": max_rounds,
                "code_commit": os.environ.get("VEGA_CODE_COMMIT", "uncommitted"),
                "proposer_prompt_sha256": canonical_hash(PROPOSER), "critic_prompt_sha256": canonical_hash(CRITIC) if args.mode == "F" else None,
                "attack_data_available_to_generator_or_critic": False,
                "input_sha256": {task["case_id"]: canonical_hash(task) for task in tasks}}
    dump(output / "manifest.json", manifest)
    adapter = adapter_module(); records = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(generate_one, adapter, task, args.mode, max_rounds): task["case_id"] for task in tasks}
        for future in concurrent.futures.as_completed(futures):
            cid = futures[future]
            try: record = future.result()
            except Exception as exc: record = {"task": next(x for x in tasks if x["case_id"] == cid), "mode": args.mode, "policy": None, "error": repr(exc), "transcript": []}
            records[cid] = record; dump(output / "records" / f"{cid}.json", record)
            if record.get("policy"): dump(output / "policies" / f"{cid}.json", record["policy"])
    summary = {"mode": args.mode, "split": args.split, "cases": len(ids), "valid_policies": sum(bool(x.get("policy")) for x in records.values()),
               "invalid_case_ids": sorted(cid for cid, x in records.items() if not x.get("policy")),
               "reported_cost_usd": sum(x.get("reported_cost_usd", 0) for x in records.values()),
               "prompt_tokens": sum(x.get("prompt_tokens", 0) for x in records.values()), "completion_tokens": sum(x.get("completion_tokens", 0) for x in records.values()),
               "total_rounds": sum(x.get("rounds", 0) for x in records.values())}
    dump(output / "summary.json", summary); print(json.dumps(summary, indent=2, sort_keys=True))
    if summary["valid_policies"] != len(ids): raise SystemExit(1)


if __name__ == "__main__": main()
