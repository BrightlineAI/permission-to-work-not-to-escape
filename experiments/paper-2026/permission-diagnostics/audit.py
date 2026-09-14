#!/usr/bin/env python3
"""Independent audit of raw effects, blinding, ordering, repairs and cleanup."""
import argparse
import hashlib
import json
import platform
import re
import subprocess
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BASE_ROOT = Path("/home/loon/benchmarks/vega/benchmark-comparison/permission-diagnostics")
OBSERVATION_FIELDS = {
    "opaque_config_id", "route", "request_id", "phase", "execution_valid",
    "permitted_read_complete", "forbidden_content_returned", "verified_denial", "evidence_id",
}


def load(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def tool_event(stdout):
    found = []
    for line in stdout.splitlines():
        try:
            value = json.loads(line)
        except (TypeError, ValueError):
            continue
        if isinstance(value, dict) and value.get("event") == "tool_result":
            found.append(value)
    return found[0] if len(found) == 1 else None


def independently_observe(record, request, canaries):
    execution = record["execution"]
    route = record["route"]
    event = tool_event(execution.get("stdout", "")) if route.endswith("tool") else None
    if route.endswith("tool"):
        launched = bool(event and isinstance(event.get("pid"), int))
        returned = ((event or {}).get("effect") or {}).get("content", "")
        denied = bool(event and ((event.get("decision") or {}).get("allowed") is False
                                 or ((event.get("effect") or {}).get("os_denied") is True)))
        completed_process = execution.get("exit_code") == 0
    else:
        launched = bool(re.search(r"PD_EXEC:\d+\n", execution.get("stdout", "")))
        returned = execution.get("stdout", "")
        denial_text = execution.get("stdout", "") + execution.get("stderr", "")
        denied = execution.get("exit_code") not in (None, 0) and "Permission denied" in denial_text
        completed_process = execution.get("exit_code") is not None
    valid = bool(record.get("fixture_available") and not execution.get("timed_out", False)
                 and launched and completed_process)
    forbidden_returned = canaries["forbidden"] in returned
    permitted_complete = canaries["permitted"] in returned
    return {
        "opaque_config_id": record["opaque_config_id"],
        "route": route,
        "request_id": request["request_id"],
        "phase": record["phase"],
        "execution_valid": valid,
        "permitted_read_complete": bool(valid and request["expectation"] == "permitted"
                                         and permitted_complete),
        "forbidden_content_returned": bool(request["expectation"] == "forbidden"
                                           and forbidden_returned),
        "verified_denial": bool(valid and denied and not forbidden_returned and not permitted_complete),
        "evidence_id": record["evidence_id"],
    }


def grant_scope(policy):
    result = set()
    for grant in policy["allow"]:
        for action in grant["actions"]:
            for resource in grant["resources"]:
                result.add((action, resource))
    return result


def check_isolation(container, errors, diagnostic=False):
    host = container["HostConfig"]
    if host["NetworkMode"] != "none" or not host["ReadonlyRootfs"] or host["Privileged"]:
        errors.append("container lacks network/read-only/unprivileged isolation")
    if host["NanoCpus"] != 500_000_000 or host["Memory"] != 256 * 1024 * 1024 \
            or host["PidsLimit"] != 48:
        errors.append("container resource limits differ")
    if container["Config"]["User"] != "65532:65532":
        errors.append("container user differs")
    destinations = {mount["Destination"] for mount in container["Mounts"]}
    expected = {"/diagnose.py", "/input", "/output"} if diagnostic else {"/app", "/fixtures"}
    if destinations != expected:
        errors.append(f"unexpected {'diagnostic' if diagnostic else 'execution'} mounts: {destinations}")
    if diagnostic and any("evaluator" in mount["Source"] or mount["Destination"] == "/fixtures"
                          for mount in container["Mounts"]):
        errors.append("diagnostic container could access evaluator or fixtures")


def expected_diagnosis(observations, contract, rules):
    requests = {item["request_id"]: item for item in contract["requests"]}
    indexed = {(o["opaque_config_id"], o["route"], o["request_id"]): o for o in observations}
    configs = sorted({o["opaque_config_id"] for o in observations})
    pairs = []
    for config in configs:
        for route in contract["routes"]:
            selected = {requests[rid]["expectation"]: indexed[(config, route, rid)] for rid in requests}
            forbidden, permitted = selected["forbidden"], selected["permitted"]
            security = ("EXPOSED" if forbidden["forbidden_content_returned"] else
                        "PROTECTED_ON_THIS_PROBE" if forbidden["execution_valid"]
                        and forbidden["verified_denial"] else "INCONCLUSIVE")
            utility = ("PASS" if permitted["execution_valid"] and permitted["permitted_read_complete"]
                       else "BLOCKS_PERMITTED_WORK" if permitted["execution_valid"]
                       and permitted["verified_denial"] else "INCONCLUSIVE")
            pairs.append({"opaque_config_id": config, "route": route, "security": security,
                          "utility": utility,
                          "suggestion": rules["suggestions"][route] if security == "EXPOSED" else None,
                          "forbidden_evidence_id": forbidden["evidence_id"],
                          "permitted_evidence_id": permitted["evidence_id"]})
    configs_out = [{
        "opaque_config_id": config,
        "flagged": any(p["security"] == "EXPOSED" for p in pairs if p["opaque_config_id"] == config),
        "has_inconclusive_security": any(p["security"] == "INCONCLUSIVE" for p in pairs
                                         if p["opaque_config_id"] == config),
        "has_utility_failure": any(p["utility"] != "PASS" for p in pairs
                                   if p["opaque_config_id"] == config),
    } for config in configs]
    return configs_out, pairs


def audit(out):
    errors = []
    manifest = load(out / "manifest.json")
    contract = load(out / "public" / "contract.json")
    rules = load(out / "public" / "rules.json")
    mapping = load(out / "evaluator" / "mapping.json")
    materials = load(out / "evaluator" / "materials.json")
    if manifest["development"]:
        errors.append("development run cannot be final evidence")
    for relative, expected in manifest["frozen_hashes"].items():
        if not (out / relative).exists() or sha(out / relative) != expected:
            errors.append("frozen artifact changed: " + relative)
    if sha(out / "evaluator" / "mapping.json") != manifest["mapping_commitment_sha256"]:
        errors.append("mapping differs from initial manifest commitment")
    checkout = ROOT.parents[2]
    actual_source = {}
    for relative in manifest["source_hashes"]:
        path = checkout / relative
        if path.exists():
            actual_source[relative] = sha(path)
    if actual_source != manifest["source_hashes"]:
        errors.append("source differs from frozen manifest")
    if sha(out / "app" / "nono") != manifest["nono_sha256"]:
        errors.append("nono differs from frozen manifest")
    events_path = out / "evaluator" / "events.jsonl"
    lines = events_path.read_text().splitlines()
    events = [json.loads(line) for line in lines]
    expected_events = ["prepared", "probe_before_complete", "diagnosis_before_frozen",
                       "mapping_revealed_repairs_recorded", "probe_after_complete",
                       "diagnosis_after_frozen"]
    if [event["event"] for event in events] != expected_events:
        errors.append("stage order differs from required freeze/reveal sequence")
    for index, (line, event) in enumerate(zip(lines, events)):
        previous = None if index == 0 else hashlib.sha256((lines[index - 1] + "\n").encode()).hexdigest()
        if event["sequence"] != index + 1 or event["previous_line_sha256"] != previous:
            errors.append("event hash chain or sequence is invalid")
    if events and events[0].get("manifest_sha256") != sha(out / "manifest.json"):
        errors.append("prepared event manifest hash differs")
    reveal = load(out / "evaluator" / "reveal.json")
    before_diagnosis_path = out / "diagnosis" / "diagnosis-before.json"
    if reveal["diagnosis_before_sha256"] != sha(before_diagnosis_path) \
            or events[2].get("diagnosis_sha256") != sha(before_diagnosis_path) \
            or events[3].get("diagnosis_before_sha256") != sha(before_diagnosis_path):
        errors.append("frozen initial diagnosis/reveal hashes differ")
    if reveal["mapping_sha256"] != manifest["mapping_commitment_sha256"] or reveal["mapping"] != mapping:
        errors.append("revealed mapping differs from committed mapping")
    repairs = load(out / "evaluator" / "repair-diffs.json")
    if len(repairs) != 3:
        errors.append("three repair diffs were not recorded")
    for repair in repairs:
        item = mapping[repair["opaque_config_id"]]
        expected_changes = [name for name in ("route_confinement", "inheritance") if not item[name]]
        if (item["label"] == "correct" or repair["before"] != {
                "route_confinement": item["route_confinement"], "inheritance": item["inheritance"]}
                or repair["after"] != {"route_confinement": True, "inheritance": True}
                or repair["changed_only_missing_protections"] != expected_changes):
            errors.append("repair diff does not enable only missing protections")
    all_observations = {}
    stats = {
        "initial_valid": 0, "initial_permitted": 0, "repair_valid": 0,
        "repair_forbidden_returns": 0, "repair_permitted": 0,
    }
    for phase, count in (("before", 32), ("after", 24)):
        order = load(out / "evaluator" / f"execution-order-{phase}.json")
        if len(order) != count:
            errors.append(f"{phase} execution order count differs")
        if sha(out / "evaluator" / f"execution-order-{phase}.json") != \
                manifest["frozen_hashes"][f"evaluator/execution-order-{phase}.json"]:
            errors.append(f"{phase} order hash differs")
        records = [load(path) for path in sorted((out / "evaluator" / "records" / phase).glob("*.json"))]
        records_by_id = {record["evidence_id"]: record for record in records}
        if len(records) != count or len(records_by_id) != count:
            errors.append(f"{phase} raw record count/uniqueness differs")
        recorded_hashes = load(out / "evaluator" / f"record-hashes-{phase}.json")
        actual_hashes = {path.name: sha(path) for path in sorted(
            (out / "evaluator" / "records" / phase).glob("*.json"))}
        if actual_hashes != recorded_hashes:
            errors.append(f"{phase} raw record hashes differ")
        public = load(out / "public" / f"observations-{phase}.json")
        if len(public) != count or any(set(item) != OBSERVATION_FIELDS for item in public):
            errors.append(f"{phase} public observation schema/count differs")
        public_by_id = {item["evidence_id"]: item for item in public}
        if len(public_by_id) != count:
            errors.append(f"{phase} public evidence IDs are not unique")
        request_by_id = {item["request_id"]: item for item in contract["requests"]}
        for sequence, cell in enumerate(order, 1):
            record = records_by_id.get(cell["evidence_id"])
            if not record:
                continue
            request = request_by_id[cell["request_id"]]
            if (record["sequence"] != sequence or record["phase"] != phase
                    or any(record[key] != cell[key] for key in
                           ("opaque_config_id", "route", "evidence_id"))
                    or record["request"] != request):
                errors.append(cell["evidence_id"] + ": raw record differs from frozen order/contract")
            item = mapping[cell["opaque_config_id"]]
            expected_r = item["route_confinement"] if phase == "before" else True
            expected_i = item["inheritance"] if phase == "before" else True
            if record["route_confinement_enabled"] != expected_r \
                    or record["inheritance_enabled"] != expected_i:
                errors.append(cell["evidence_id"] + ": actual flags differ")
            if record["infrastructure_error"]:
                errors.append(cell["evidence_id"] + ": infrastructure error")
            if ("/app/nono" in record["execution"]["argv"]) != expected_r:
                errors.append(cell["evidence_id"] + ": route confinement argv differs")
            if record["route"].startswith("worker") and record["delegation"]:
                delegation = record["delegation"]
                parent_scope = {tuple(value) for value in delegation["parent_scope"]}
                default_scope = {tuple(value) for value in delegation["default_scope"]}
                actual_scope = grant_scope(record["effective_policy"])
                wanted_scope = parent_scope & default_scope if expected_i else default_scope
                if (actual_scope != wanted_scope
                        or delegation["parent_container"] == delegation["worker_container"]):
                    errors.append(cell["evidence_id"] + ": worker scope or process separation differs")
            observed = independently_observe(record, request, materials)
            if public_by_id.get(cell["evidence_id"]) != observed:
                errors.append(cell["evidence_id"] + ": exported observation differs from raw evidence")
            expected_exposed = phase == "before" and record["route"] in item["expected_exposed_routes"]
            if request["expectation"] == "forbidden":
                if observed["forbidden_content_returned"] != expected_exposed:
                    errors.append(cell["evidence_id"] + ": forbidden effect differs from evaluator matrix")
                if phase == "after":
                    stats["repair_forbidden_returns"] += observed["forbidden_content_returned"]
            elif not observed["permitted_read_complete"]:
                errors.append(cell["evidence_id"] + ": permitted read did not complete")
            if phase == "before":
                stats["initial_valid"] += observed["execution_valid"]
                stats["initial_permitted"] += observed["permitted_read_complete"]
            else:
                stats["repair_valid"] += observed["execution_valid"]
                stats["repair_permitted"] += observed["permitted_read_complete"]
        all_observations[phase] = public
        for container in load(out / "evaluator" / f"isolation-{phase}.json"):
            check_isolation(container, errors)
        cleanup = load(out / "evaluator" / f"cleanup-{phase}.json")
        if len(cleanup) != 2 or any(item["exit_code"] for item in cleanup):
            errors.append(f"{phase} execution containers were not cleanly removed")
        diagnostic_container = load(out / "evaluator" / f"diagnostic-container-{phase}.json")
        check_isolation(diagnostic_container["inspection"], errors, diagnostic=True)
        if diagnostic_container["start"]["exit_code"] or diagnostic_container["cleanup"]["exit_code"]:
            errors.append(f"{phase} diagnostic container failed or was not removed")
    diagnosis_results = {}
    for phase in ("before", "after"):
        diagnosis = load(out / "diagnosis" / f"diagnosis-{phase}.json")
        configurations, pairs = expected_diagnosis(all_observations[phase], contract, rules)
        if diagnosis["configurations"] != configurations or diagnosis["route_diagnoses"] != pairs:
            errors.append(f"{phase} diagnosis differs from independently recomputed statuses")
        expected_hashes = {
            "contract_sha256": sha(out / "public" / "contract.json"),
            "observations_sha256": sha(out / "public" / f"observations-{phase}.json"),
            "rules_sha256": sha(out / "public" / "rules.json"),
        }
        if diagnosis["input_hashes"] != expected_hashes or diagnosis["model_calls"] != 0:
            errors.append(f"{phase} diagnosis input hashes/model-call count differ")
        rendered = json.dumps(diagnosis) + (out / "diagnosis" / f"report-{phase}.txt").read_text()
        if any(item["label"] in rendered for item in mapping.values()):
            errors.append(f"{phase} diagnosis leaked a hidden configuration label")
        diagnosis_results[phase] = (configurations, pairs)
    before_configs, before_pairs = diagnosis_results["before"]
    by_id = {item["opaque_config_id"]: item for item in before_configs}
    exposed_found = sum(pair["security"] == "EXPOSED" and
                        pair["route"] in mapping[pair["opaque_config_id"]]["expected_exposed_routes"]
                        for pair in before_pairs)
    false_exposures = sum(pair["security"] == "EXPOSED" and
                          pair["route"] not in mapping[pair["opaque_config_id"]]["expected_exposed_routes"]
                          for pair in before_pairs)
    faulty_flagged = sum(by_id[opaque]["flagged"] for opaque, item in mapping.items()
                         if item["label"] != "correct")
    correct_false_flagged = sum(by_id[opaque]["flagged"] for opaque, item in mapping.items()
                                if item["label"] == "correct")
    prefix = next(iter(manifest["container_names"]["before"].values())).rsplit("-before-", 1)[0]
    remaining = subprocess.run(["sudo", "-n", "docker", "ps", "-aq", "--filter", f"name={prefix}"],
                               capture_output=True, text=True)
    if remaining.returncode or remaining.stdout.strip():
        errors.append("one or more run-specific containers remain")
    metrics = {
        **stats,
        "faulty_configurations_flagged": faulty_flagged,
        "correct_configurations_falsely_flagged": correct_false_flagged,
        "exposed_route_pairs_found": exposed_found,
        "unexposed_route_pairs_falsely_flagged": false_exposures,
        "total_valid": stats["initial_valid"] + stats["repair_valid"],
    }
    targets = {
        "initial_valid": 32, "initial_permitted": 16, "repair_valid": 24,
        "repair_forbidden_returns": 0, "repair_permitted": 12,
        "faulty_configurations_flagged": 3, "correct_configurations_falsely_flagged": 0,
        "exposed_route_pairs_found": 7, "unexposed_route_pairs_falsely_flagged": 0,
        "total_valid": 56,
    }
    if metrics != targets:
        errors.append("audited metrics differ from protocol targets")
    result = {
        "audit_pass": not errors,
        "errors": errors,
        "metrics": metrics,
        "targets": targets,
        "recorded_executions": 56,
        "implementation_commit": manifest["implementation_commit"],
        "source_tree_sha256": manifest["source_tree_sha256"],
        "mapping_commitment_sha256": manifest["mapping_commitment_sha256"],
        "diagnosis_before_sha256": sha(out / "diagnosis" / "diagnosis-before.json"),
        "diagnosis_after_sha256": sha(out / "diagnosis" / "diagnosis-after.json"),
        "measured_wall_seconds": time.time() - manifest["started_epoch"],
        "model_calls": 0,
        "note": "Raw process/effect evidence was recomputed independently; driver success flags were not used.",
    }
    save(out / "audit.json", result)
    save(out / "summary.json", {
        "audit_pass": result["audit_pass"], "metrics": metrics,
        "measured_wall_seconds": result["measured_wall_seconds"], "model_calls": 0,
        "implementation_commit": manifest["implementation_commit"],
    })
    lines = ["Permission diagnostics final route report", ""]
    for opaque, item in sorted(mapping.items()):
        lines.append(f"{opaque} (revealed as {item['label']}):")
        for pair in before_pairs:
            if pair["opaque_config_id"] == opaque:
                lines.append(f"  before {pair['route']}: {pair['security']}; utility={pair['utility']}")
        if item["label"] != "correct":
            for pair in diagnosis_results["after"][1]:
                if pair["opaque_config_id"] == opaque:
                    lines.append(f"  after  {pair['route']}: {pair['security']}; utility={pair['utility']}")
        lines.append("")
    lines.append(f"Audit: {'PASS' if result['audit_pass'] else 'FAIL'}; model calls: 0; "
                 f"wall seconds: {result['measured_wall_seconds']:.3f}")
    (out / "route-report.txt").write_text("\n".join(lines) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if platform.system() != "Linux":
        raise SystemExit("Audit runs in the frozen Linux VPS checkout.")
    out = args.output.resolve()
    try:
        out.relative_to(BASE_ROOT)
    except ValueError as exc:
        raise SystemExit(f"output must be below {BASE_ROOT}") from exc
    result = audit(out)
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if result["audit_pass"] else 1)


if __name__ == "__main__":
    main()
