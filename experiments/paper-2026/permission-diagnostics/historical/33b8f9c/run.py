#!/usr/bin/env python3
"""Staged VPS-only driver for the blinded permission-diagnostics experiment."""
import argparse
import hashlib
import json
import os
import platform
import random
import re
import secrets
import shutil
import subprocess
import time
from pathlib import Path

from observer import observe

ROOT = Path(__file__).resolve().parent
PP_ROOT = ROOT.parent / "permission-preservation"
BASE_ROOT = Path("/home/loon/benchmarks/vega/benchmark-comparison/permission-diagnostics")
ROUTES = ["parent_tool", "parent_shell", "worker_tool", "worker_shell"]
TRACKS = {
    "permitted": "/fixtures/diagnostic/project.txt",
    "forbidden": "/fixtures/diagnostic/private.txt",
}
REUSED = ["scope.py", "tool.py", "delegate.py"]


def load(path):
    return json.loads(path.read_text())


def save(path, value, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    path.chmod(mode)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def json_sha(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def command(argv, timeout=30):
    started = time.monotonic()
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return {
            "argv": argv,
            "exit_code": result.returncode,
            "stdout": result.stdout.replace("\r\n", "\n"),
            "stderr": result.stderr.replace("\r\n", "\n"),
            "timed_out": False,
            "seconds": time.monotonic() - started,
        }
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return {
            "argv": argv,
            "exit_code": None,
            "stdout": stdout.replace("\r\n", "\n"),
            "stderr": stderr.replace("\r\n", "\n"),
            "timed_out": True,
            "seconds": time.monotonic() - started,
        }


def docker(*args, check=True, timeout=45):
    result = command(["sudo", "-n", "docker", *args], timeout=timeout)
    if check and result["exit_code"]:
        raise RuntimeError(json.dumps(result, sort_keys=True))
    return result


def require_vps(out):
    if platform.system() != "Linux":
        raise SystemExit("Permission diagnostics execute only on the Linux VPS.")
    resolved = out.resolve()
    try:
        resolved.relative_to(BASE_ROOT)
    except ValueError as exc:
        raise SystemExit(f"output must be below {BASE_ROOT}") from exc
    return resolved


def source_files():
    files = []
    for path in sorted(ROOT.rglob("*")):
        if (path.is_file() and "evidence" not in path.parts and "__pycache__" not in path.parts
                and path.suffix != ".pyc"):
            files.append(path)
    for name in REUSED:
        files.append(PP_ROOT / name)
    files.extend(path for path in sorted((PP_ROOT / "vendor").rglob("*")) if path.is_file()
                 and "__pycache__" not in path.parts and path.suffix != ".pyc")
    return files


def source_hashes():
    checkout = ROOT.parents[2]
    return {str(path.relative_to(checkout)): sha(path) for path in source_files()}


def verify_source(out):
    manifest = load(out / "manifest.json")
    actual = source_hashes()
    if actual != manifest["source_hashes"]:
        missing = sorted(set(manifest["source_hashes"]) - set(actual))
        extra = sorted(set(actual) - set(manifest["source_hashes"]))
        changed = sorted(k for k in set(actual) & set(manifest["source_hashes"])
                         if actual[k] != manifest["source_hashes"][k])
        raise RuntimeError(f"frozen source changed; missing={missing}, extra={extra}, changed={changed}")
    if sha(out / "app" / "nono") != manifest["nono_sha256"]:
        raise RuntimeError("frozen nono binary changed")
    for filename, expected in manifest["frozen_hashes"].items():
        if sha(out / filename) != expected:
            raise RuntimeError("frozen artifact changed: " + filename)


def append_event(out, event, **values):
    path = out / "evaluator" / "events.jsonl"
    previous = None
    sequence = 1
    if path.exists():
        lines = path.read_text().splitlines()
        if lines:
            previous = hashlib.sha256((lines[-1] + "\n").encode()).hexdigest()
            sequence = json.loads(lines[-1])["sequence"] + 1
    record = {
        "sequence": sequence,
        "event": event,
        "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "previous_line_sha256": previous,
        **values,
    }
    with path.open("a") as handle:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    return record


def last_event(out):
    lines = (out / "evaluator" / "events.jsonl").read_text().splitlines()
    return json.loads(lines[-1]) if lines else None


def git_value(*args):
    result = command(["git", "-C", str(ROOT), *args])
    if result["exit_code"]:
        raise RuntimeError(result["stderr"])
    return result["stdout"].strip()


def create_order(mapping, contract, phase):
    ids = list(mapping)
    if phase == "after":
        ids = [opaque for opaque, item in mapping.items() if item["label"] != "correct"]
    cells = []
    for opaque in ids:
        for route in ROUTES:
            for request in contract["requests"]:
                cells.append({
                    "opaque_config_id": opaque,
                    "route": route,
                    "request_id": request["request_id"],
                    "evidence_id": "ev-" + secrets.token_hex(16),
                })
    random.SystemRandom().shuffle(cells)
    return cells


def prepare(args):
    out = require_vps(args.output)
    out.mkdir(parents=True, exist_ok=False)
    for directory in ("app/configs", "data/diagnostic", "evaluator/records/before",
                      "evaluator/records/after", "public", "diagnosis"):
        (out / directory).mkdir(parents=True)
    (out / "data").chmod(0o777)
    (out / "data" / "diagnostic").chmod(0o777)
    (out / "diagnosis").chmod(0o777)
    for name in REUSED:
        shutil.copy2(PP_ROOT / name, out / "app" / name)
    shutil.copytree(PP_ROOT / "vendor", out / "app" / "vendor",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copy2(args.nono.resolve(), out / "app" / "nono")
    (out / "app" / "nono").chmod(0o755)
    for name in ("policy.json", "worker-default.json", "rules.json", "evaluator-matrix.json"):
        target = out / ("public" if name == "rules.json" else "evaluator") / name
        shutil.copy2(ROOT / name, target)
    parent = load(ROOT / "policy.json")
    worker = load(ROOT / "worker-default.json")
    # Parse both policies through Appendix K's vendored Vega parser before freezing.
    sys_path = str(PP_ROOT)
    import sys
    sys.path.insert(0, sys_path)
    try:
        from scope import permissions
        permissions(parent)
        permissions(worker)
    finally:
        sys.path.remove(sys_path)
    contract = {
        "contract_version": "permission-diagnostics-v1",
        "policy_text": ("Read the project file; never read the private file; delegates receive "
                        "no broader permission."),
        "routes": ROUTES,
        "requests": [
            {"request_id": "req-" + secrets.token_hex(16), "expectation": track,
             "action": "read", "resource": resource}
            for track, resource in TRACKS.items()
        ],
    }
    save(out / "public" / "contract.json", contract)
    matrix = load(ROOT / "evaluator-matrix.json")
    opaque_ids = ["cfg-" + secrets.token_hex(16) for _ in matrix]
    labels = list(matrix)
    random.SystemRandom().shuffle(labels)
    mapping = {opaque: {"label": label, **matrix[label]}
               for opaque, label in zip(opaque_ids, labels)}
    save(out / "evaluator" / "mapping.json", mapping, 0o600)
    materials = {
        "permitted": "PD-PERMITTED-" + secrets.token_hex(24) + "\n",
        "forbidden": "PD-FORBIDDEN-" + secrets.token_hex(24) + "\n",
    }
    save(out / "evaluator" / "materials.json", materials, 0o600)
    for track, resource in TRACKS.items():
        target = out / "data" / resource.removeprefix("/fixtures/")
        target.write_text(materials[track])
        target.chmod(0o666)
    before_order = create_order(mapping, contract, "before")
    after_order = create_order(mapping, contract, "after")
    save(out / "evaluator" / "execution-order-before.json", before_order, 0o600)
    save(out / "evaluator" / "execution-order-after.json", after_order, 0o600)
    image = json.loads(docker("image", "inspect", "python:3.11-slim")["stdout"])[0]
    run_token = secrets.token_hex(6)
    container_names = {
        phase: {role: f"vega-pd-{run_token}-{phase}-{role}"
                for role in ("parent", "worker", "diagnostic")}
        for phase in ("before", "after")
    }
    implementation_commit = git_value("rev-parse", "HEAD")
    status = git_value("status", "--porcelain")
    if status and not args.development:
        raise RuntimeError("final preparation requires a clean committed checkout")
    frozen_paths = [
        "public/contract.json", "public/rules.json", "evaluator/policy.json",
        "evaluator/worker-default.json", "evaluator/evaluator-matrix.json",
        "evaluator/mapping.json", "evaluator/materials.json",
        "evaluator/execution-order-before.json", "evaluator/execution-order-after.json",
    ]
    manifest = {
        "protocol": "permission-diagnostics-v1",
        "development": args.development,
        "implementation_commit": implementation_commit,
        "git_status_at_prepare": status,
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "started_epoch": time.time(),
        "source_hashes": source_hashes(),
        "source_tree_sha256": json_sha(source_hashes()),
        "frozen_hashes": {path: sha(out / path) for path in frozen_paths},
        "mapping_commitment_sha256": sha(out / "evaluator" / "mapping.json"),
        "fixture_sha256": {track: sha(out / "data" / resource.removeprefix("/fixtures/"))
                            for track, resource in TRACKS.items()},
        "nono_sha256": sha(out / "app" / "nono"),
        "image_id": image["Id"],
        "image_repo_digests": image.get("RepoDigests", []),
        "container_names": container_names,
        "limits": {"network": "none", "read_only_root": True, "user": "65532:65532",
                   "cpus": 0.5, "memory": "256m", "pids": 48, "concurrency": 1},
        "planned_executions": {"before": 32, "after": 24, "total": 56},
        "model_calls": 0,
    }
    save(out / "manifest.json", manifest)
    append_event(out, "prepared", manifest_sha256=sha(out / "manifest.json"),
                 mapping_commitment_sha256=manifest["mapping_commitment_sha256"])
    print(json.dumps({"output": str(out), "implementation_commit": implementation_commit,
                      "development": args.development}, indent=2))


def invoke(container, raw_policy, route_enabled, executable):
    args = ["exec", "-t", "-w", "/app", container]
    if route_enabled:
        import sys
        sys.path.insert(0, str(PP_ROOT))
        try:
            from scope import nono_grants
            args += ["/app/nono", "run", *nono_grants(raw_policy), "--block-net",
                     "--sandbox-policy", "landlock", "--no-rollback", "--no-audit",
                     "--no-diagnostics", "--"]
        finally:
            sys.path.remove(str(PP_ROOT))
    return docker(*args, *executable, check=False)


def event_json(output, event):
    found = []
    for line in output.splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get("event") == event:
            found.append(value)
    if len(found) != 1:
        raise RuntimeError(f"expected one {event} event, found {len(found)}")
    return found[0]


def execute(out, containers, mapping_item, cell, request, phase):
    parent = load(out / "evaluator" / "policy.json")
    default = load(out / "evaluator" / "worker-default.json")
    route_enabled = mapping_item["route_confinement"] if phase == "before" else True
    inherit_enabled = mapping_item["inheritance"] if phase == "before" else True
    current = parent
    container = containers["parent"]
    delegation = None
    if cell["route"].startswith("worker"):
        dispatch = invoke(container, parent, route_enabled, [
            "python3", "/app/delegate.py", cell["route"], request["action"],
            request["resource"], "",
        ])
        envelope = event_json(dispatch["stdout"], "delegate")
        if dispatch["exit_code"] or set(envelope) != {
            "event", "parent_pid", "parent_uid", "route", "action", "resource", "payload"
        } or envelope["route"] != cell["route"] or envelope["action"] != request["action"] \
                or envelope["resource"] != request["resource"] or envelope["payload"] != "":
            raise RuntimeError("invalid parent delegation envelope")
        import sys
        sys.path.insert(0, str(PP_ROOT))
        try:
            from scope import inherited, permissions
            current = inherited(parent, default, "worker-diagnostic") if inherit_enabled else {
                **default, "principal": "worker-diagnostic", "job_id": parent["job_id"]
            }
            delegation = {
                "parent_container": container,
                "worker_container": containers["worker"],
                "parent_scope": sorted(permissions(parent)),
                "default_scope": sorted(permissions(default)),
                "effective_scope": sorted(permissions(current)),
                "inheritance_enabled": inherit_enabled,
                "request": dispatch,
                "envelope": envelope,
            }
        finally:
            sys.path.remove(str(PP_ROOT))
        container = containers["worker"]
    config = out / "app" / "configs" / (cell["evidence_id"] + ".json")
    save(config, current)
    if cell["route"].endswith("tool"):
        executable = ["python3", "/app/tool.py", "/app/configs/" + config.name,
                      request["action"], request["resource"], ""]
    else:
        executable = ["/bin/sh", "-c", 'printf "PD_EXEC:%s\\n" "$$"; cat -- "$1"',
                      "permission-diagnostic-read", request["resource"]]
    execution = invoke(container, current, route_enabled, executable)
    return {
        "route_confinement_enabled": route_enabled,
        "inheritance_enabled": inherit_enabled,
        "container": container,
        "effective_policy": current,
        "delegation": delegation,
        "execution": execution,
    }


def create_execution_containers(out, phase):
    manifest = load(out / "manifest.json")
    names = manifest["container_names"][phase]
    created = []
    try:
        for role in ("parent", "worker"):
            name = names[role]
            docker("run", "-d", "--name", name, "--network", "none", "--read-only",
                   "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                   "--user", "65532:65532", "--cpus", "0.5", "--memory", "256m",
                   "--pids-limit", "48", "--tmpfs", "/tmp:rw,nosuid,nodev,size=16m,mode=1777",
                   "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "HOME=/tmp",
                   "--mount", f"type=bind,src={out / 'app'},dst=/app,readonly",
                   "--mount", f"type=bind,src={out / 'data'},dst=/fixtures",
                   manifest["image_id"], "sleep", "infinity")
            created.append(name)
        inspection = json.loads(docker("inspect", *created)["stdout"])
        save(out / "evaluator" / f"isolation-{phase}.json", inspection)
        return {role: names[role] for role in ("parent", "worker")}, created
    except Exception:
        for name in created:
            docker("rm", "-f", name, check=False)
        raise


def probe(args):
    out = require_vps(args.output)
    verify_source(out)
    phase = args.phase
    expected_last = "prepared" if phase == "before" else "mapping_revealed_repairs_recorded"
    if last_event(out)["event"] != expected_last:
        raise RuntimeError(f"{phase} probe requires last event {expected_last}")
    if phase == "before" and (out / "evaluator" / "reveal.json").exists():
        raise RuntimeError("mapping was revealed before initial probe")
    mapping = load(out / "evaluator" / "mapping.json")
    contract = load(out / "public" / "contract.json")
    requests = {item["request_id"]: item for item in contract["requests"]}
    materials = load(out / "evaluator" / "materials.json")
    order = load(out / "evaluator" / f"execution-order-{phase}.json")
    records_dir = out / "evaluator" / "records" / phase
    if any(records_dir.iterdir()) or (out / "public" / f"observations-{phase}.json").exists():
        raise RuntimeError("phase output already exists; use a new run directory")
    observations = []
    containers, created = create_execution_containers(out, phase)
    try:
        for index, cell in enumerate(order, 1):
            request = requests[cell["request_id"]]
            fixture_available = all(
                (out / "data" / path.removeprefix("/fixtures/")).is_file()
                and (out / "data" / path.removeprefix("/fixtures/")).read_text() == materials[track]
                for track, path in TRACKS.items()
            )
            record = {
                "evidence_id": cell["evidence_id"],
                "sequence": index,
                "phase": phase,
                "opaque_config_id": cell["opaque_config_id"],
                "hidden_configuration_label": mapping[cell["opaque_config_id"]]["label"],
                "route": cell["route"],
                "request": request,
                "fixture_available": fixture_available,
                "infrastructure_error": None,
            }
            try:
                record.update(execute(out, containers, mapping[cell["opaque_config_id"]],
                                      cell, request, phase))
            except Exception as exc:
                record.update({
                    "route_confinement_enabled": None,
                    "inheritance_enabled": None,
                    "container": None,
                    "effective_policy": None,
                    "delegation": None,
                    "execution": {"argv": [], "exit_code": None, "stdout": "", "stderr": "",
                                  "timed_out": False, "seconds": 0},
                    "infrastructure_error": repr(exc),
                })
            observation = observe(record, request, materials)
            save(records_dir / (cell["evidence_id"] + ".json"), record, 0o600)
            observations.append(observation)
            print(f"{phase}: {index}/{len(order)}", flush=True)
    finally:
        cleanup = [docker("rm", "-f", name, check=False) for name in created]
        save(out / "evaluator" / f"cleanup-{phase}.json", cleanup)
    save(out / "public" / f"observations-{phase}.json", observations)
    record_hashes = {path.name: sha(path) for path in sorted(records_dir.glob("*.json"))}
    save(out / "evaluator" / f"record-hashes-{phase}.json", record_hashes)
    append_event(out, f"probe_{phase}_complete", count=len(observations),
                 observations_sha256=sha(out / "public" / f"observations-{phase}.json"),
                 records_manifest_sha256=sha(out / "evaluator" / f"record-hashes-{phase}.json"),
                 cleanup_sha256=sha(out / "evaluator" / f"cleanup-{phase}.json"))


def run_diagnostic_container(out, phase):
    manifest = load(out / "manifest.json")
    name = manifest["container_names"][phase]["diagnostic"]
    source = ROOT / "diagnose.py"
    public = out / "public"
    diagnosis = out / "diagnosis"
    output_name = f"diagnosis-{phase}.json"
    report_name = f"report-{phase}.txt"
    create = docker(
        "create", "--name", name, "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--user", "65532:65532", "--cpus", "0.5",
        "--memory", "256m", "--pids-limit", "48",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=16m,mode=1777",
        "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "HOME=/tmp",
        "--mount", f"type=bind,src={source},dst=/diagnose.py,readonly",
        "--mount", f"type=bind,src={public},dst=/input,readonly",
        "--mount", f"type=bind,src={diagnosis},dst=/output",
        manifest["image_id"], "python3", "/diagnose.py",
        "--contract", "/input/contract.json", "--observations", f"/input/observations-{phase}.json",
        "--rules", "/input/rules.json", "--output", f"/output/{output_name}",
        "--report", f"/output/{report_name}")
    container_id = create["stdout"].strip()
    inspection = json.loads(docker("inspect", name)["stdout"])[0]
    start = docker("start", "-a", name, check=False)
    logs = docker("logs", name, check=False)
    cleanup = docker("rm", "-f", name, check=False)
    save(out / "evaluator" / f"diagnostic-container-{phase}.json", {
        "container_id": container_id,
        "inspection": inspection,
        "start": start,
        "logs": logs,
        "cleanup": cleanup,
    })
    if start["exit_code"] or cleanup["exit_code"]:
        raise RuntimeError("diagnostic container failed or was not cleaned up")
    return diagnosis / output_name, diagnosis / report_name


def diagnose_stage(args):
    out = require_vps(args.output)
    verify_source(out)
    phase = args.phase
    expected_last = f"probe_{phase}_complete"
    if last_event(out)["event"] != expected_last:
        raise RuntimeError(f"{phase} diagnosis requires last event {expected_last}")
    if phase == "before" and (out / "evaluator" / "reveal.json").exists():
        raise RuntimeError("mapping was revealed before the initial diagnosis")
    diagnosis_path, report_path = run_diagnostic_container(out, phase)
    append_event(out, f"diagnosis_{phase}_frozen", diagnosis_sha256=sha(diagnosis_path),
                 report_sha256=sha(report_path), diagnostic_source_sha256=sha(ROOT / "diagnose.py"))
    print(report_path.read_text(), end="")


def reveal(args):
    out = require_vps(args.output)
    verify_source(out)
    event = last_event(out)
    if event["event"] != "diagnosis_before_frozen":
        raise RuntimeError("reveal requires a frozen initial diagnosis")
    diagnosis = out / "diagnosis" / "diagnosis-before.json"
    if sha(diagnosis) != event["diagnosis_sha256"]:
        raise RuntimeError("initial diagnosis changed before reveal")
    mapping = load(out / "evaluator" / "mapping.json")
    manifest = load(out / "manifest.json")
    if sha(out / "evaluator" / "mapping.json") != manifest["mapping_commitment_sha256"]:
        raise RuntimeError("hidden mapping differs from initial commitment")
    revealed = {
        "event": "mapping_revealed_after_frozen_diagnosis",
        "revealed_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "diagnosis_before_sha256": sha(diagnosis),
        "mapping_sha256": sha(out / "evaluator" / "mapping.json"),
        "mapping": mapping,
    }
    save(out / "evaluator" / "reveal.json", revealed, 0o600)
    repairs = []
    for opaque, item in sorted(mapping.items()):
        if item["label"] == "correct":
            continue
        repairs.append({
            "opaque_config_id": opaque,
            "hidden_configuration_label": item["label"],
            "before": {"route_confinement": item["route_confinement"],
                       "inheritance": item["inheritance"]},
            "after": {"route_confinement": True, "inheritance": True},
            "changed_only_missing_protections": [
                name for name, value in (("route_confinement", item["route_confinement"]),
                                         ("inheritance", item["inheritance"])) if not value
            ],
        })
    save(out / "evaluator" / "repair-diffs.json", repairs, 0o600)
    append_event(out, "mapping_revealed_repairs_recorded", reveal_sha256=sha(out / "evaluator" / "reveal.json"),
                 repairs_sha256=sha(out / "evaluator" / "repair-diffs.json"), repair_count=len(repairs),
                 diagnosis_before_sha256=sha(diagnosis))


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="stage", required=True)
    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("--output", type=Path, required=True)
    prepare_parser.add_argument("--nono", type=Path, required=True)
    prepare_parser.add_argument("--development", action="store_true")
    for name in ("probe", "diagnose"):
        stage = sub.add_parser(name)
        stage.add_argument("--output", type=Path, required=True)
        stage.add_argument("--phase", choices=("before", "after"), required=True)
    reveal_parser = sub.add_parser("reveal")
    reveal_parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.stage == "prepare":
        prepare(args)
    elif args.stage == "probe":
        probe(args)
    elif args.stage == "diagnose":
        diagnose_stage(args)
    else:
        reveal(args)


if __name__ == "__main__":
    main()
