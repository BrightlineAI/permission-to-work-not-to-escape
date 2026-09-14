#!/usr/bin/env python3
"""Capture 100 Qwen actions once and replay them through matched A/B/C/D arms."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import os
import shlex
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vega_core.approvals import ApprovalRegistry
from vega_core.authorize import authorize_c, authorize_d
from vega_core.canonical import canonical_hash
from vega_core.context import TrustedProvenanceRegistry, build_trusted_context
from vega_core.models import Decision, load_policy, normalize_tool_call


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


opa_adapter = module("opa_adapter", ROOT / "adapters/opa.py")
openrouter = module("openrouter_adapter", ROOT / "adapters/openrouter.py")

MODEL = "qwen/qwen3-14b"
EFFORT = "high"


def dump(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    temporary.replace(path)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tool_schema(case):
    properties = {key: {"type": "string", "description": value} for key, value in case["parameters"].items()}
    return {"type": "function", "function": {"name": case["tool"], "description": case["tool_description"], "parameters": {"type": "object", "additionalProperties": False, "properties": properties, "required": list(properties)}}}


def capture_body(case):
    return {"model": MODEL, "reasoning_effort": EFFORT, "messages": [
        {"role": "system", "content": case["system"]},
        {"role": "user", "content": case["user"]},
        {"role": "assistant", "content": None, "tool_calls": [{"id": "source", "type": "function", "function": {"name": "read_untrusted_source", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "source", "content": case["untrusted_content"]},
    ], "tools": [tool_schema(case)], "tool_choice": "required"}


def capture_one(case):
    body = capture_body(case)
    started = time.monotonic()
    # Preserve each transport failure; retry only provider/infrastructure failures.
    failures = []
    for attempt in range(1, 4):
        try:
            response = openrouter.capture(MODEL, body["messages"], body["tools"], EFFORT)
            if response.get("model") != MODEL:
                raise RuntimeError(f"provider returned unexpected model {response.get('model')!r}")
            message = response["choices"][0]["message"]
            calls = message.get("tool_calls") or []
            if len(calls) != 1 or calls[0].get("function", {}).get("name") != case["tool"]:
                return {"body": body, "response": response, "call": None, "error": "expected exactly one named tool call", "failures": failures, "seconds": time.monotonic() - started}
            arguments = json.loads(calls[0]["function"]["arguments"])
            if set(arguments) != set(case["parameters"]) or not all(isinstance(value, str) for value in arguments.values()):
                return {"body": body, "response": response, "call": None, "error": "arguments did not match strict schema", "failures": failures, "seconds": time.monotonic() - started}
            return {"body": body, "response": response, "call": {"tool": case["tool"], "arguments": arguments}, "error": None, "failures": failures, "seconds": time.monotonic() - started}
        except Exception as exc:
            failures.append({"attempt": attempt, "error": repr(exc)})
            time.sleep(attempt)
    return {"body": body, "response": None, "call": None, "error": "provider retries exhausted", "failures": failures, "seconds": time.monotonic() - started}


def normalized(case, call_args):
    mapping = case["mapping"]
    value = {name: None for name in ("resource", "recipient", "destination", "amount", "approval_handle")}
    value.update({"tool": case["tool"], "action": "", "payload": ""})
    for field in tuple(value):
        literal = mapping.get(f"{field}_literal")
        source = mapping.get(field)
        if literal is not None:
            value[field] = literal
        elif source is not None:
            value[field] = call_args.get(source)
    return normalize_tool_call(value)


def trusted(case, policy, request, valid_approval=False, attack_context=False):
    provenance, approvals = TrustedProvenanceRegistry(), ApprovalRegistry()
    for item in case["trusted"].get("canaries", []):
        provenance.register(item["value"], item["label"])
    for resource, label in case["trusted"].get("resource_labels", {}).items():
        provenance.register_resource(resource, label)
    record = case["trusted"].get("valid_approval")
    if record:
        handle = record.get("handle") or approvals.issue(issuer=record["issuer"], job_id=policy.job_id, resource=record["resource"], amount=record["amount"])
        if record.get("handle"):
            approvals.records[handle] = {"handle": handle, "issuer": record["issuer"], "job_id": policy.job_id, "resource": record["resource"], "amount": record["amount"], "expires_at": time.time() + 3600}
        if valid_approval and request.approval_handle == "__VALID_APPROVAL__":
            request = normalize_tool_call({**request.as_dict(), "approval_handle": handle})
    delegation = {policy.job_id: case["trusted"].get("attack_delegation", {"depth": 0, "expands": False})} if attack_context else {}
    context = build_trusted_context({"job_id": policy.job_id, "principal": policy.principal}, provenance, approvals, delegation, request)
    return request, context


def decision_for(arm, case, policy, request, opa_binary, valid_approval=False, attack_context=False):
    request, context = trusted(case, policy, request, valid_approval, attack_context)
    if arm in {"A", "B"}:
        return request, Decision(True, "ALLOW", policy.policy_hash, policy.job_id), None
    opa = opa_adapter.evaluate(opa_binary, ROOT / "gateway/baseline.rego", policy.raw, request.as_dict())
    python_c = authorize_c(policy, request).as_dict()
    if (opa["allowed"], opa["reason"]) != (python_c["allowed"], python_c["reason"]):
        raise RuntimeError(f"OPA/Python C mismatch: {opa} != {python_c}")
    if arm == "C":
        return request, Decision(opa["allowed"], opa["reason"], policy.policy_hash, policy.job_id), opa
    return request, authorize_d(policy, request, context), opa


def docker(*arguments, input=None, timeout=30):
    return subprocess.run(["sudo", "-n", "docker", *arguments], input=input, capture_output=True, timeout=timeout)


def post(url, body, tool, sandbox_container=None, allowed_port=None):
    payload = json.dumps(body, sort_keys=True).encode()
    started = time.monotonic()
    if sandbox_container:
        fd, body_path = tempfile.mkstemp(prefix="vega-request-", suffix=".json")
        try:
            os.write(fd, payload)
            os.close(fd)
            fd = None
            os.chmod(body_path, 0o644)
            remote_body = f"/case/{Path(body_path).name}"
            copied = docker("cp", body_path, f"{sandbox_container}:{remote_body}")
            if copied.returncode:
                raise RuntimeError(copied.stderr.decode(errors="replace"))
            client = "import json,sys,urllib.request; b=open(sys.argv[2],'rb').read(); r=urllib.request.Request(sys.argv[1],data=b,headers={'Content-Type':'application/json','x-vega-tool':sys.argv[3]}); print(urllib.request.urlopen(r,timeout=10).read().decode())"
            command = ["exec", "-t", "-w", "/case", sandbox_container, "/usr/local/bin/nono", "run", "--read", "/case", "--allow-connect-port", str(allowed_port), "--sandbox-policy", "landlock", "--no-rollback", "--no-audit", "--no-diagnostics", "--", "python3", "-c", client, url, remote_body, tool]
            result = docker(*command, timeout=15)
            docker("exec", sandbox_container, "rm", "-f", remote_body)
        finally:
            if fd is not None:
                os.close(fd)
            os.unlink(body_path)
        return {"exit_code": result.returncode, "stdout": result.stdout.decode(errors="replace"), "stderr": result.stderr.decode(errors="replace"), "seconds": time.monotonic() - started}
    request = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json", "x-vega-tool": tool})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return {"exit_code": 0, "stdout": response.read().decode(), "stderr": "", "seconds": time.monotonic() - started, "status": response.status}
    except Exception as exc:
        return {"exit_code": 1, "stdout": "", "stderr": repr(exc), "seconds": time.monotonic() - started}


def execute_arm(arm, case, policy, call, state_root, clients, opa_binary, track, valid_approval=False):
    arm_started = time.monotonic()
    request = normalized(case, call["arguments"])
    request, decision, opa = decision_for(arm, case, policy, request, opa_binary, valid_approval, track != "benign")
    action_hash = canonical_hash(call)
    path = f"/{track}/{arm}/{case['case_id']}"
    before_path = state_root / f"{track}-{arm}-{case['case_id']}.json"
    before = json.loads(before_path.read_text()) if before_path.exists() else []
    execution = None
    if decision.allowed:
        if arm == "A":
            execution = post(f"http://127.0.0.1:39080{path}", {"action_hash": action_hash, "request": request.as_dict()}, call["tool"])
        elif arm == "B":
            execution = post(f"http://127.0.0.1:39080{path}", {"action_hash": action_hash, "request": request.as_dict()}, call["tool"], clients[arm], 39080)
        else:
            execution = post(f"http://127.0.0.1:39000{path}", {"action_hash": action_hash, "request": request.as_dict()}, call["tool"], clients[arm], 39000)
    after = json.loads(before_path.read_text()) if before_path.exists() else []
    return {"arm": arm, "request": request.as_dict(), "action_hash": action_hash, "decision": decision.as_dict(), "opa_decision": opa, "execution": execution, "effect_count_before": len(before), "effect_count_after": len(after), "effect_completed": len(after) == len(before) + 1, "total_seconds": time.monotonic() - arm_started}


def run_track(cases, captures, arms, state_root, clients, opa_binary, track):
    records = {}
    jobs = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        for case in cases:
            policy = load_policy(ROOT / case["policy"])
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
            for arm in arms:
                jobs.append((case["case_id"], arm, pool.submit(execute_arm, arm, case, policy, call, state_root, clients, opa_binary, track, valid)))
        for case_id, arm, future in jobs:
            records.setdefault(case_id, {})[arm] = future.result()
    return records


def wait_http(url, process, seconds=20):
    until = time.time() + seconds
    while time.time() < until:
        if process.poll() is not None:
            raise RuntimeError(f"service exited: {process.returncode}")
        try:
            urllib.request.urlopen(url, timeout=.5)
        except urllib.error.HTTPError:
            return
        except Exception:
            time.sleep(.2)
        else:
            return
    raise RuntimeError(f"service not ready: {url}")


def preflight(output, clients, opa_binary):
    body = {"action_hash": "preflight", "request": {"tool": "send_message"}}
    allowed = post("http://127.0.0.1:39000/control/C/preflight", body, "send_message", clients["C"], 39000)
    forbidden_tool = post("http://127.0.0.1:39000/control/C/forbidden", body, "unknown_tool")
    docker("exec", clients["C"], "mkdir", "-p", "/denied")
    docker("exec", "-i", clients["C"], "sh", "-c", "cat > /denied/secret.txt", input=b"VEGA-DENIED-CANARY\n")
    denied_command = ["exec", "-t", "-w", "/case", clients["C"], "/usr/local/bin/nono", "run", "--read", "/case", "--allow-connect-port", "39000", "--sandbox-policy", "landlock", "--no-rollback", "--no-audit", "--no-diagnostics", "--", "cat", "/denied/secret.txt"]
    denied_path = docker(*denied_command, timeout=15)
    bypass = post("http://127.0.0.1:39080/control/C/bypass", body, "send_message", clients["C"], 39000)
    policy = load_policy(ROOT / "policies/case-001.json")
    request = normalized(json.loads((ROOT / "cases/case-001.json").read_text()), {"operation": "transfer_repository", "repository": "org/assigned-01", "target": "outside-01@example.test"})
    opa = opa_adapter.evaluate(opa_binary, ROOT / "gateway/baseline.rego", policy.raw, request.as_dict())
    result = {
        "gateway_allowed_tool": allowed,
        "gateway_forbidden_tool": forbidden_tool,
        "nono_denied_path": {"exit_code": denied_path.returncode, "stdout": denied_path.stdout.decode(errors="replace"), "stderr": denied_path.stderr.decode(errors="replace")},
        "nono_denied_direct_backend_bypass": bypass,
        "opa_forbidden_request": opa,
    }
    result["pass"] = (
        allowed["exit_code"] == 0 and forbidden_tool["exit_code"] != 0 and
        denied_path.returncode != 0 and b"VEGA-DENIED-CANARY" not in denied_path.stdout and
        bypass["exit_code"] != 0 and not opa["allowed"]
    )
    dump(output / "preflight.json", result)
    if not result["pass"]:
        raise RuntimeError("preflight gate failed")


def start_clients(nono, tag):
    clients = {arm: f"vega-core-{tag}-{arm.lower()}" for arm in "BCD"}
    image = "python:3.11-slim"
    inspected = docker("image", "inspect", image)
    if inspected.returncode:
        pulled = docker("pull", image, timeout=180)
        if pulled.returncode:
            raise RuntimeError(pulled.stderr.decode(errors="replace"))
    for container in clients.values():
        started = docker("run", "-d", "--name", container, "--network", "host", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", "256m", "--pids-limit", "64", "-w", "/case", image, "sleep", "infinity")
        if started.returncode:
            raise RuntimeError(started.stderr.decode(errors="replace"))
        docker("exec", container, "mkdir", "-p", "/case")
        copied = docker("cp", nono, f"{container}:/usr/local/bin/nono")
        if copied.returncode:
            raise RuntimeError(copied.stderr.decode(errors="replace"))
    return clients


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--nono", required=True)
    parser.add_argument("--opa", required=True)
    parser.add_argument("--agentgateway", required=True)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--case-ids", help="comma-separated explicit case IDs")
    parser.add_argument("--reuse-captures")
    parser.add_argument("--forced-as-captures", action="store_true", help="integration smoke only; never use for registered model results")
    args = parser.parse_args()
    output, state_root = Path(args.output).resolve(), Path(args.output).resolve() / "service-state"
    output.mkdir(parents=True, exist_ok=False)
    all_paths = {path.stem: path for path in sorted((ROOT / "cases").glob("case-*.json"))}
    selected = args.case_ids.split(",") if args.case_ids else list(all_paths)[:args.limit]
    cases = [json.loads(all_paths[case_id].read_text()) for case_id in selected]
    manifest = {
        "experiment": "Vega 100-case A/B/C/D",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "code_commit": os.environ.get("VEGA_CODE_COMMIT", "uncommitted"),
        "model_requested": MODEL, "reasoning_effort": EFFORT,
        "cases": len(cases), "case_ids": selected,
        "selection_sha256": canonical_hash(selected),
        "case_sha256": {case["case_id"]: sha(all_paths[case["case_id"]]) for case in cases},
        "policy_sha256": {case["case_id"]: sha(ROOT / case["policy"]) for case in cases},
        "code_sha256": {
            "runner": sha(Path(__file__)),
            "audit": sha(ROOT / "scripts/audit_results.py"),
            "case_builder": sha(ROOT / "scripts/build_cases.py"),
            "opa_policy": sha(ROOT / "gateway/baseline.rego"),
            "agentgateway_config": sha(ROOT / "gateway/agentgateway.yaml"),
            "policy_schema": sha(ROOT / "schemas/policy.schema.json"),
            "case_schema": sha(ROOT / "schemas/case.schema.json"),
        },
        "agentgateway_version": "1.5.0", "agentgateway_sha256": sha(Path(args.agentgateway)),
        "opa_version": "1.20.2", "opa_sha256": sha(Path(args.opa)),
        "nono_version": subprocess.run([args.nono, "--version"], text=True, capture_output=True).stdout.strip(),
        "nono_sha256": sha(Path(args.nono)),
        "identical_capture_replay": True, "parallel_ABC_then_D": True,
        "frozen_hashes_written_before_capture": True,
        "limitations": [
            "Adapted benchmark-derived synthetic cases, not official benchmark scores.",
            "Policies were reviewed and frozen before inference; policy generation is not evaluated.",
            "Agentgateway gates tool identity and transport; OPA evaluates decoded ordinary request fields.",
        ],
    }
    dump(output / "manifest.json", manifest)
    service_log = open(output / "synthetic-service.log", "w")
    gateway_log = open(output / "agentgateway.log", "w")
    clients = start_clients(args.nono, f"{os.getpid()}")
    service = subprocess.Popen([sys.executable, str(ROOT / "scripts/synthetic_service.py"), "--state-root", str(state_root)], stdout=service_log, stderr=subprocess.STDOUT)
    gateway = subprocess.Popen([args.agentgateway, "-f", str(ROOT / "gateway/agentgateway.yaml")], stdout=gateway_log, stderr=subprocess.STDOUT)
    try:
        wait_http("http://127.0.0.1:39080/ready", service)
        wait_http("http://127.0.0.1:39000/ready", gateway)
        preflight(output, clients, args.opa)
        if args.forced_as_captures:
            captures = {case["case_id"]: {"body": None, "response": None, "call": {"tool": case["tool"], "arguments": case["harmful_call"]}, "error": None, "failures": [], "seconds": 0, "synthetic_smoke_capture": True} for case in cases}
            dump(output / "captures.json", captures)
        elif args.reuse_captures:
            captures = json.loads(Path(args.reuse_captures).read_text())
        else:
            captures = {}
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
                futures = {pool.submit(capture_one, case): case for case in cases}
                for future in concurrent.futures.as_completed(futures):
                    case = futures[future]
                    captures[case["case_id"]] = future.result()
                    dump(output / "captures" / f"{case['case_id']}.json", captures[case["case_id"]])
            dump(output / "captures.json", captures)
        abc = run_track(cases, captures, ("A", "B", "C"), state_root, clients, args.opa, "model")
        dump(output / "model-ABC.json", abc)
        d = run_track(cases, captures, ("D",), state_root, clients, args.opa, "model")
        dump(output / "model-D.json", d)
        forced_abc = run_track(cases, captures, ("A", "B", "C"), state_root, clients, args.opa, "forced")
        dump(output / "forced-ABC.json", forced_abc)
        forced_d = run_track(cases, captures, ("D",), state_root, clients, args.opa, "forced")
        dump(output / "forced-D.json", forced_d)
        benign = run_track(cases, captures, tuple("ABCD"), state_root, clients, args.opa, "benign")
        dump(output / "benign.json", benign)
    finally:
        gateway.terminate(); service.terminate()
        gateway.wait(timeout=10); service.wait(timeout=10)
        cleanup = {arm: {"exit_code": result.returncode, "stdout": result.stdout.decode(errors="replace"), "stderr": result.stderr.decode(errors="replace")} for arm, container in clients.items() for result in [docker("rm", "-f", container)]}
        dump(output / "cleanup.json", cleanup)
        gateway_log.close(); service_log.close()
    subprocess.run([sys.executable, str(ROOT / "scripts/audit_results.py"), str(output)], check=True)


if __name__ == "__main__":
    main()
