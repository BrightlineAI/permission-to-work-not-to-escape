#!/usr/bin/env python3
"""Generate final-arm E policies directly from trusted intent, with no compiler."""

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
sys.path.insert(0, str(ROOT / "src"))
from vega_core.canonical import canonical_hash
from vega_core.models import policy_from_dict


def load_adapter():
    spec = importlib.util.spec_from_file_location("openrouter_adapter", ROOT / "adapters/openrouter.py")
    adapter = importlib.util.module_from_spec(spec); spec.loader.exec_module(adapter)
    return adapter


MODEL = "qwen/qwen3-14b"
PROMPT = (ROOT / "e/policy_prompt.txt").read_text()
BODY_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "allow": {"type": "array", "minItems": 1, "items": {"type": "object", "additionalProperties": False,
            "properties": {"tool": {"type": "string"}, "actions": {"type": "array", "items": {"type": "string"}}, "resources": {"type": "array", "items": {"type": "string"}}, "recipients": {"type": "array", "items": {"type": "string"}}, "destinations": {"type": "array", "items": {"type": "string"}}},
            "required": ["tool", "actions", "resources", "recipients", "destinations"]}},
        "data_rules": {"type": "object", "additionalProperties": {"type": "object", "additionalProperties": False, "properties": {"allowed_destinations": {"type": "array", "items": {"type": "string"}}}, "required": ["allowed_destinations"]}},
        "approval_rules": {"type": "object", "additionalProperties": {"type": "object", "additionalProperties": False, "properties": {"required_issuer": {"type": "string"}, "bind_fields": {"type": "array", "items": {"type": "string"}}}, "required": ["required_issuer", "bind_fields"]}},
        "delegation": {"type": "object", "additionalProperties": False, "properties": {"max_depth": {"type": "integer", "minimum": 0}, "child_may_expand_authority": {"type": "boolean"}}, "required": ["max_depth", "child_may_expand_authority"]},
    }, "required": ["allow", "data_rules", "approval_rules", "delegation"],
}
TOOL = {"type": "function", "function": {"name": "emit_policy", "description": "Emit the least-privilege policy body", "parameters": BODY_SCHEMA}}


def generate(adapter, task):
    started = time.monotonic(); failures = []
    messages = [{"role": "system", "content": PROMPT}, {"role": "user", "content": json.dumps({"trusted_operator_record": task}, sort_keys=True)}]
    for attempt in range(1, 4):
        try:
            response = adapter.capture(MODEL, messages, [TOOL], "high")
            if response.get("model") != MODEL:
                raise RuntimeError("unexpected returned model")
            calls = response["choices"][0]["message"].get("tool_calls") or []
            if len(calls) != 1 or calls[0]["function"]["name"] != "emit_policy":
                return {"task": task, "response": response, "policy": None, "error": "expected one emit_policy call", "transport_failures": failures, "seconds": time.monotonic() - started}
            body = json.loads(calls[0]["function"]["arguments"])
            policy = {"schema_version": 1, "policy_id": task["policy_id"], "job_id": task["job_id"], "principal": task["principal"], **body}
            parsed = policy_from_dict(policy)
            return {"task": task, "response": response, "policy": parsed.raw, "policy_sha256": parsed.policy_hash, "error": None, "transport_failures": failures, "seconds": time.monotonic() - started}
        except (OSError, TimeoutError) as exc:
            failures.append({"attempt": attempt, "error": repr(exc)}); time.sleep(attempt)
        except Exception as exc:
            return {"task": task, "response": locals().get("response"), "policy": None, "error": repr(exc), "transport_failures": failures, "seconds": time.monotonic() - started}
    return {"task": task, "response": None, "policy": None, "error": "transport retries exhausted", "transport_failures": failures, "seconds": time.monotonic() - started}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--case-ids", help="explicit override; default is the complete cohort")
    parser.add_argument("--cohort", choices=["original", "second"], required=True)
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()
    output = Path(args.output).resolve(); output.mkdir(parents=True, exist_ok=False)
    default_range = range(1, 101) if args.cohort == "original" else range(101, 201)
    ids = args.case_ids.split(",") if args.case_ids else [f"case-{index:03}" for index in default_range]
    task_root = ROOT / ("e/trusted_tasks" if args.cohort == "original" else "ef/trusted_tasks")
    tasks = [json.loads((task_root / f"{cid}.json").read_text()) for cid in ids]
    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(), "mode": "E",
        "cohort": args.cohort, "case_ids": ids, "model": MODEL,
        "prompt_sha256": canonical_hash(PROMPT),
        "generator_file_sha256": canonical_hash({"bytes": Path(__file__).read_text()}),
        "final_policy_tool_schema_sha256": canonical_hash(TOOL),
        "code_commit": os.environ.get("VEGA_CODE_COMMIT", "uncommitted"),
        "direct_final_policy_schema": True,
        "typed_intermediate_representation": False,
        "semantic_contract_validator": False,
        "critic": False,
        "semantic_repair_rounds": 0,
        "syntax_and_type_validation": True,
        "runner_binds_protected_identity": True,
        "attack_data_available_to_generator": False,
        "input_sha256": {task["case_id"]: canonical_hash(task) for task in tasks},
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    adapter = load_adapter(); records = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(generate, adapter, task): task for task in tasks}
        for future in concurrent.futures.as_completed(futures):
            record = future.result(); cid = record["task"]["case_id"]; records[cid] = record
            (output / "records").mkdir(exist_ok=True)
            (output / "records" / f"{cid}.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
            if record["policy"]:
                (output / "policies").mkdir(exist_ok=True)
                (output / "policies" / f"{cid}.json").write_text(json.dumps(record["policy"], indent=2, sort_keys=True) + "\n")
    summary = {"mode": "E", "cohort": args.cohort, "cases": len(ids), "valid_policies": sum(record["policy"] is not None for record in records.values()), "invalid_policies": {cid: record["error"] for cid, record in records.items() if record["policy"] is None}, "reported_cost_usd": sum(((record.get("response") or {}).get("usage") or {}).get("cost", 0) or 0 for record in records.values()), "prompt_tokens": sum(((record.get("response") or {}).get("usage") or {}).get("prompt_tokens", 0) for record in records.values()), "completion_tokens": sum(((record.get("response") or {}).get("usage") or {}).get("completion_tokens", 0) for record in records.values()), "aggregate_seconds": sum(record.get("seconds", 0) for record in records.values())}
    (output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    # Invalid direct drafts are experimental outcomes. The replay path fails them
    # closed and measures the corresponding benign-utility loss.


if __name__ == "__main__":
    main()
