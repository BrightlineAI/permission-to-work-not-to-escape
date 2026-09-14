#!/usr/bin/env python3
"""Generate direct-E policies or typed-F requirements from trusted records only."""

from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from common import MODEL, REASONING_EFFORT, canonical_hash, read_jsonl, sha256_file
from compile_requirements import compile_requirements, validate_policy

API_URL = "https://openrouter.ai/api/v1/chat/completions"


def _post(body: dict[str, Any], timeout: int) -> dict[str, Any]:
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        raise RuntimeError("OPENROUTER_API_KEY is required")
    request = urllib.request.Request(
        API_URL,
        data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        method="POST",
    )
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read())
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = exc
            if attempt < 2:
                time.sleep(2 ** attempt)
    raise RuntimeError(f"OpenRouter transport failed after 3 attempts: {type(last_error).__name__}")


def _tool_arguments(response: dict[str, Any], expected_name: str) -> dict[str, Any]:
    try:
        calls = response["choices"][0]["message"]["tool_calls"]
        call = calls[0]
        function = call["function"]
        if len(calls) != 1 or function["name"] != expected_name:
            raise ValueError("unexpected tool call count or name")
        value = json.loads(function["arguments"])
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("response did not contain one valid structured tool call") from exc
    if not isinstance(value, dict):
        raise ValueError("structured arguments must be an object")
    return value


def _direct_policy(body: dict[str, Any], task_id: str, principal: str) -> dict[str, Any]:
    if set(body) != {"allow", "data_rules", "approval_rules", "delegation"}:
        raise ValueError("direct policy body has invalid fields")
    policy = {
        "schema_version": 1,
        "policy_id": f"dtap-{task_id}",
        "job_id": task_id,
        "principal": principal,
        **body,
    }
    validate_policy(policy)
    return policy


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trusted-inputs", required=True)
    parser.add_argument("--mode", required=True, choices=["direct_e", "typed_f"])
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()

    package_root = Path(__file__).resolve().parents[1]
    prompt_path = package_root / ("policy_prompt.txt" if args.mode == "direct_e" else "typed_prompt.txt")
    schema_path = package_root / "schemas" / (
        "policy-body.schema.json" if args.mode == "direct_e" else "requirements.schema.json"
    )
    prompt, schema = prompt_path.read_text(), json.loads(schema_path.read_text())
    records = read_jsonl(args.trusted_inputs)
    if args.limit is not None:
        if args.limit < 1:
            raise ValueError("limit must be positive")
        records = records[:args.limit]
    output_root = Path(args.output_root)
    output_root.mkdir(parents=True, exist_ok=False)
    policies_root, captures_root = output_root / "policies", output_root / "captures"
    policies_root.mkdir()
    captures_root.mkdir()

    function_name = "emit_policy" if args.mode == "direct_e" else "emit_requirements"
    generation_started_at = datetime.now(timezone.utc)
    generation_started_monotonic = time.monotonic()
    summaries = []
    for record in records:
        task_id, principal = record["task_id"], record["principal"]
        trusted_payload = {
            key: record[key]
            for key in ("task_id", "principal", "domain", "operator_instruction", "tool_interface")
        }
        request_body = {
            "model": MODEL,
            "messages": [
                {"role": "system", "content": prompt},
                {"role": "user", "content": json.dumps(trusted_payload, ensure_ascii=False, sort_keys=True)},
            ],
            "tools": [{
                "type": "function",
                "function": {
                    "name": function_name,
                    "description": "Return the complete typed result.",
                    "parameters": schema,
                    "strict": True,
                },
            }],
            "tool_choice": {"type": "function", "function": {"name": function_name}},
            "reasoning_effort": REASONING_EFFORT,
        }
        case_root = captures_root / task_id
        case_root.mkdir()
        (case_root / "request.json").write_text(json.dumps(request_body, indent=2, sort_keys=True) + "\n")
        started = time.monotonic()
        response = _post(request_body, args.timeout)
        elapsed = time.monotonic() - started
        (case_root / "response.json").write_text(json.dumps(response, indent=2, sort_keys=True) + "\n")
        generated = _tool_arguments(response, function_name)
        try:
            if args.mode == "typed_f":
                (case_root / "requirements.json").write_text(json.dumps(generated, indent=2, sort_keys=True) + "\n")
                policy = compile_requirements(generated, job_id=task_id, principal=principal)
            else:
                policy = _direct_policy(generated, task_id, principal)
        except Exception as exc:
            (output_root / "generation-error.json").write_text(json.dumps({
                "task_id": task_id, "mode": args.mode, "error_type": type(exc).__name__,
                "error": str(exc), "failed_closed": True,
            }, indent=2, sort_keys=True) + "\n")
            raise
        policy_path = policies_root / f"{task_id}.json"
        policy_path.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n")
        usage = response.get("usage") if isinstance(response.get("usage"), dict) else {}
        summaries.append({
            "task_id": task_id,
            "mode": args.mode,
            "model_requested": MODEL,
            "model_returned": response.get("model"),
            "reasoning_effort_requested": REASONING_EFFORT,
            "response_id": response.get("id"),
            "provider": response.get("provider"),
            "usage": usage,
            "elapsed_seconds": elapsed,
            "trusted_record_hash": record["trusted_record_hash"],
            "request_sha256": sha256_file(case_root / "request.json"),
            "response_sha256": sha256_file(case_root / "response.json"),
            "policy_sha256": sha256_file(policy_path),
            "policy_canonical_hash": canonical_hash(policy),
        })
    generation_finished_at = datetime.now(timezone.utc)
    manifest = {
        "schema_version": 1,
        "mode": args.mode,
        "model": MODEL,
        "reasoning_effort": REASONING_EFFORT,
        "prompt_sha256": sha256_file(prompt_path),
        "schema_sha256": sha256_file(schema_path),
        "trusted_inputs_sha256": sha256_file(args.trusted_inputs),
        "generation_started_at": generation_started_at.isoformat(),
        "generation_finished_at": generation_finished_at.isoformat(),
        "generation_wall_seconds": time.monotonic() - generation_started_monotonic,
        "policy_generation_llm_calls": len(summaries),
        "cases": summaries,
    }
    (output_root / "generation-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
