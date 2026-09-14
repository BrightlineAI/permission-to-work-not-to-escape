#!/usr/bin/env python3
"""Replay the frozen 100 Qwen actions through LLM-drafted Vega policies (E)."""

from __future__ import annotations

import argparse
import concurrent.futures
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
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


suite = module("vega_run_suite", ROOT / "scripts/run_suite.py")


def sha(path: Path) -> str:
    return suite.sha(path)


def load(path: Path):
    return json.loads(path.read_text())


def policy_path(case_id: str, development: Path, holdout: Path) -> Path:
    return (development if int(case_id.split("-")[1]) <= 60 else holdout) / f"{case_id}.json"


def execute(case, policy, policy_artifact_hash, call, state_root, client, opa_binary, track, valid_approval=False):
    started = time.monotonic()
    request = suite.normalized(case, call["arguments"])
    if policy is None:
        decision = suite.Decision(False, "DENY_INVALID_POLICY", policy_artifact_hash, f"job-{case['case_id']}")
        opa = None
    else:
        request, decision, opa = suite.decision_for(
            "D", case, policy, request, opa_binary, valid_approval, track != "benign"
        )
    action_hash = canonical_hash(call)
    state_path = state_root / f"{track}-E-{case['case_id']}.json"
    before = load(state_path) if state_path.exists() else []
    execution = None
    if decision.allowed:
        execution = suite.post(
            f"http://127.0.0.1:39000/{track}/E/{case['case_id']}",
            {"action_hash": action_hash, "request": request.as_dict()},
            call["tool"], client, 39000,
        )
    after = load(state_path) if state_path.exists() else []
    return {
        "arm": "E", "request": request.as_dict(), "action_hash": action_hash,
        "decision": decision.as_dict(), "opa_decision": opa, "execution": execution,
        "effect_count_before": len(before), "effect_count_after": len(after),
        "effect_completed": len(after) == len(before) + 1,
        "total_seconds": time.monotonic() - started,
    }


def run_track(cases, captures, policies, artifact_hashes, state_root, client, opa_binary, track):
    records, jobs = {}, []
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        for case in cases:
            if track == "model":
                call = captures[case["case_id"]]["call"]
                if call is None:
                    continue
                valid = False
            elif track == "forced":
                call, valid = {"tool": case["tool"], "arguments": case["harmful_call"]}, False
            else:
                arguments = dict(case["benign_call"])
                valid = arguments.get("approval") == "__VALID_APPROVAL__"
                call = {"tool": case["tool"], "arguments": arguments}
            jobs.append((case["case_id"], pool.submit(
                execute, case, policies[case["case_id"]], artifact_hashes[case["case_id"]], call, state_root,
                client, opa_binary, track, valid,
            )))
        for case_id, future in jobs:
            records[case_id] = {"E": future.result()}
    return records


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--development-policies", required=True)
    parser.add_argument("--holdout-policies", required=True)
    parser.add_argument("--development-generation", required=True)
    parser.add_argument("--holdout-generation", required=True)
    parser.add_argument("--captures", required=True)
    parser.add_argument("--nono", required=True)
    parser.add_argument("--opa", required=True)
    parser.add_argument("--agentgateway", required=True)
    parser.add_argument("--case-ids", help="development-only integration smoke selection")
    parser.add_argument("--integration-smoke", action="store_true")
    args = parser.parse_args()

    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    state_root = output / "service-state"
    development, holdout = Path(args.development_policies), Path(args.holdout_policies)
    captures_path = Path(args.captures).resolve()
    captures = load(captures_path)
    shutil.copyfile(captures_path, output / "source-captures.json")
    case_paths = sorted((ROOT / "cases").glob("case-*.json"))
    if args.case_ids:
        if not args.integration_smoke:
            raise SystemExit("--case-ids is allowed only with --integration-smoke")
        selected = set(args.case_ids.split(","))
        case_paths = [path for path in case_paths if path.stem in selected]
        if {path.stem for path in case_paths} != selected:
            raise SystemExit("unknown case ID in --case-ids")
    cases = [load(path) for path in case_paths]
    policy_paths = {case["case_id"]: policy_path(case["case_id"], development, holdout) for case in cases}
    record_paths = {cid: path.parent.parent / "records" / f"{cid}.json" for cid, path in policy_paths.items()}
    policies = {cid: load_policy(path) if path.exists() else None for cid, path in policy_paths.items()}
    artifact_paths = {cid: policy_paths[cid] if policy_paths[cid].exists() else record_paths[cid] for cid in policy_paths}
    artifact_hashes = {cid: sha(path) for cid, path in artifact_paths.items()}
    invalid_policies = {cid: load(record_paths[cid]).get("error") for cid, policy in policies.items() if policy is None}
    ids = [case["case_id"] for case in cases]
    development_manifest = Path(args.development_generation).resolve()
    holdout_manifest = Path(args.holdout_generation).resolve()
    development_ids = [cid for cid in ids if int(cid.split("-")[1]) <= 60]
    holdout_ids = [cid for cid in ids if int(cid.split("-")[1]) > 60]
    manifest = {
        "experiment": "Vega E: LLM-drafted policy with frozen Vega enforcement",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "runner_commit": os.environ.get("VEGA_CODE_COMMIT", "uncommitted"),
        "generator_commit": load(development_manifest)["code_commit"],
        "cases": len(cases), "case_ids": ids, "integration_smoke": args.integration_smoke,
        "development_case_ids": development_ids, "holdout_case_ids": holdout_ids,
        "development_categories": sorted({case["family"] for case in cases if case["case_id"] in development_ids}),
        "holdout_categories": sorted({case["family"] for case in cases if case["case_id"] in holdout_ids}),
        "holdout_policy_generated_once_after_generator_freeze": True,
        "generator_never_received_attack_or_grader_data": True,
        "captures_sha256": sha(captures_path),
        "capture_action_sha256": {cid: canonical_hash(captures[cid]["call"]) for cid in ids},
        "development_generation_manifest_sha256": sha(development_manifest),
        "holdout_generation_manifest_sha256": sha(holdout_manifest),
        "policy_artifact_sha256": artifact_hashes,
        "valid_policy_count": sum(policy is not None for policy in policies.values()),
        "invalid_policies": invalid_policies,
        "code_sha256": {
            "runner": sha(Path(__file__)), "audit": sha(ROOT / "scripts/audit_e.py"),
            "generator": sha(ROOT / "scripts/generate_e.py"),
            "input_builder": sha(ROOT / "scripts/build_e_inputs.py"),
            "generator_prompt": sha(ROOT / "e/policy_prompt.txt"),
            "opa_policy": sha(ROOT / "gateway/baseline.rego"),
            "policy_schema": sha(ROOT / "schemas/policy.schema.json"),
        },
        "agentgateway_version": "1.5.0", "agentgateway_sha256": sha(Path(args.agentgateway)),
        "opa_version": "1.20.2", "opa_sha256": sha(Path(args.opa)),
        "nono_version": subprocess.run([args.nono, "--version"], text=True, capture_output=True).stdout.strip(),
        "nono_sha256": sha(Path(args.nono)),
        "limitations": [
            "E evaluates policy drafting from trusted operator intent, not intent discovery from untrusted task content.",
            "The LLM emits data only; schema validation and enforcement remain deterministic and fail closed.",
            "The 40-case holdout contains two benchmark-derived categories absent from generator development evaluation.",
        ],
    }
    suite.dump(output / "manifest.json", manifest)
    service_log = open(output / "synthetic-service.log", "w")
    gateway_log = open(output / "agentgateway.log", "w")
    clients = suite.start_clients(args.nono, f"e-{os.getpid()}")
    service = subprocess.Popen(
        [sys.executable, str(ROOT / "scripts/synthetic_service.py"), "--state-root", str(state_root)],
        stdout=service_log, stderr=subprocess.STDOUT,
    )
    gateway = subprocess.Popen(
        [args.agentgateway, "-f", str(ROOT / "gateway/agentgateway.yaml")],
        stdout=gateway_log, stderr=subprocess.STDOUT,
    )
    started = time.monotonic()
    try:
        suite.wait_http("http://127.0.0.1:39080/ready", service)
        suite.wait_http("http://127.0.0.1:39000/ready", gateway)
        suite.preflight(output, clients, args.opa)
        suite.dump(output / "model-E.json", run_track(cases, captures, policies, artifact_hashes, state_root, clients["D"], args.opa, "model"))
        suite.dump(output / "forced-E.json", run_track(cases, captures, policies, artifact_hashes, state_root, clients["D"], args.opa, "forced"))
        suite.dump(output / "benign-E.json", run_track(cases, captures, policies, artifact_hashes, state_root, clients["D"], args.opa, "benign"))
        suite.dump(output / "timing.json", {"execution_wall_seconds": time.monotonic() - started})
    finally:
        gateway.terminate(); service.terminate()
        gateway.wait(timeout=10); service.wait(timeout=10)
        cleanup = {arm: {"exit_code": result.returncode, "stdout": result.stdout.decode(errors="replace"), "stderr": result.stderr.decode(errors="replace")} for arm, container in clients.items() for result in [suite.docker("rm", "-f", container)]}
        suite.dump(output / "cleanup.json", cleanup)
        gateway_log.close(); service_log.close()
    subprocess.run([sys.executable, str(ROOT / "scripts/audit_e.py"), str(output)], check=True)


if __name__ == "__main__":
    main()
