#!/usr/bin/env python3
"""VPS-only, deterministic physical permission-preservation matrix."""
import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import time
import uuid
from collections import defaultdict
from pathlib import Path

from scope import inherited, nono_grants, permissions

ROOT = Path(__file__).resolve().parent
CONFIGS = {"tool_only": (False, False), "route_only": (True, False),
           "inherit_only": (False, True), "route_and_inherit": (True, True)}
ROUTES = ["parent_tool", "parent_shell", "worker_tool", "worker_shell"]


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    path.chmod(0o644)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(args, timeout=30):
    started = time.monotonic()
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    return dict(argv=args, exit_code=result.returncode, stdout=result.stdout.replace("\r\n", "\n"),
                stderr=result.stderr.replace("\r\n", "\n"), seconds=time.monotonic() - started)


def docker(*args, check=True):
    result = command(["sudo", "-n", "docker", *args])
    if check and result["exit_code"]:
        raise RuntimeError(json.dumps(result))
    return result


def policy(fid, action, allowed, forbidden, broad=False):
    grants = [dict(tool="file_access", actions=[action],
                   resources=[allowed, forbidden] if broad else [allowed],
                   recipients=[], destinations=[])]
    if action == "write":
        grants.append(dict(tool="file_access", actions=["read"], resources=[forbidden],
                           recipients=[], destinations=[]))
    return dict(schema_version=1, policy_id=f"{fid}-{'default' if broad else 'parent'}",
        job_id=f"job-{fid}", principal="worker-default" if broad else "parent",
        allow=grants, data_rules={}, approval_rules={},
        delegation=dict(max_depth=1, child_may_expand_authority=broad))


def fixtures(dev):
    records = []
    for operation, ids in [("read", range(61, 66)), ("write", range(136, 141))]:
        for index, number in enumerate(ids):
            if dev and index:
                continue
            fid = f"dev-{operation}" if dev else f"pp-{number:03}"
            source = ROOT / "sources" / f"case-{number:03}.json"
            original = json.loads(source.read_text())
            if operation == "read":
                allowed = original["benign_call"]["source"].replace("/case/", "/fixtures/", 1)
                forbidden = original["harmful_call"]["source"].replace("/case/", "/fixtures/", 1)
            else:
                resource = original["benign_call"]["resource"]
                allowed, forbidden = f"/fixtures/{resource}/staging.txt", f"/fixtures/{resource}/protected-config.txt"
            if dev:
                allowed, forbidden = f"/fixtures/{fid}/allowed.txt", f"/fixtures/{fid}/protected.txt"
            records.append(dict(id=fid, operation=operation, permitted=allowed, forbidden=forbidden,
                source_case=original["case_id"], source_sha256=digest(source), upstream=original["source"],
                adaptation="physical exact-path read permission" if operation == "read" else
                           "physical write permission; approval semantics are not replayed",
                policy=policy(fid, operation, allowed, forbidden),
                worker_default=policy(fid, operation, allowed, forbidden, True)))
    return records


def expected_access(route, route_enabled, inherit_enabled):
    if route == "parent_tool":
        return False
    if route == "parent_shell":
        return not route_enabled
    if route == "worker_tool":
        return not inherit_enabled
    return not (route_enabled and inherit_enabled)


def invoke(container, raw, route_enabled, executable):
    # nono's Linux system grants open /dev/tty. Allocate a container-local PTY;
    # this does not allocate or expose the host terminal.
    args = ["exec", "-t", "-w", "/app", container]
    if route_enabled:
        args += ["/app/nono", "run", *nono_grants(raw), "--block-net",
                 "--sandbox-policy", "landlock", "--no-rollback", "--no-audit",
                 "--no-diagnostics", "--"]
    return docker(*args, *executable, check=False)


def event_json(output, event):
    for line in reversed(output.splitlines()):
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get("event") == event:
            return value
    raise RuntimeError(f"missing {event} process output")


def execute(fixture, route, request, r_enabled, i_enabled, app, containers, run_id):
    parent = fixture["policy"]
    principal = f"worker-{fixture['id']}"
    current = parent
    delegation = None
    container = containers["parent"]
    if route.startswith("worker"):
        # An actual parent process submits the request; identity and scope cannot
        # be supplied in its message. The host dispatcher binds those independently.
        dispatch = invoke(container, parent, r_enabled, ["python3", "/app/delegate.py",
            route, request["action"], request["resource"], request["payload"]])
        if dispatch["exit_code"]:
            raise RuntimeError("parent dispatcher request failed: " + json.dumps(dispatch))
        message = event_json(dispatch["stdout"], "delegate")
        if set(message) != {"event", "parent_pid", "parent_uid", "route", "action", "resource", "payload"}:
            raise RuntimeError("unexpected delegation envelope")
        if message["event"] != "delegate" or message["route"] != route or any(
                message[field] != request[field] for field in ("action", "resource", "payload")):
            raise RuntimeError("delegation envelope differs from submitted request")
        default = fixture["worker_default"]
        current = inherited(parent, default, principal) if i_enabled else {
            **default, "principal": principal, "job_id": parent["job_id"]}
        actual_scope = permissions(current)
        delegation = dict(parent_container=container, worker_container=containers["worker"],
            root_job_id=parent["job_id"], parent_principal=parent["principal"], worker_principal=principal,
            depth=1, inheritance_enabled=i_enabled, parent_scope=sorted(permissions(parent)),
            default_scope=sorted(permissions(default)), effective_scope=sorted(actual_scope),
            expands_parent_scope=bool(actual_scope - permissions(parent)),
            parent_request=dispatch, request_envelope=message)
        container = containers["worker"]
    config = app / "configs" / (run_id + ".json")
    save(config, current)
    if route.endswith("tool"):
        executable = ["python3", "/app/tool.py", "/app/configs/" + config.name,
                      request["action"], request["resource"], request["payload"]]
    elif request["action"] == "read":
        executable = ["/bin/sh", "-c", 'printf "PP_EXEC:%s\\n" "$$"; cat -- "$1"',
                      "permission-read", request["resource"]]
    else:
        executable = ["/bin/sh", "-c", 'printf "PP_EXEC:%s\\n" "$$"; printf "%s" "$2" > "$1"',
                      "permission-write", request["resource"], request["payload"]]
    execution = invoke(container, current, r_enabled, executable)
    return dict(container=container, policy=current, effective_scope=sorted(permissions(current)),
                delegation=delegation, execution=execution)


def main():
    if platform.system() != "Linux":
        raise SystemExit("Tests are VPS/Linux only; no local execution.")
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--nono", type=Path, required=True)
    parser.add_argument("--dev", action="store_true")
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    app, data = out / "app", out / "data"
    app.mkdir(); data.mkdir(); data.chmod(0o777)
    for filename in ("scope.py", "tool.py", "delegate.py"):
        shutil.copy2(ROOT / filename, app / filename)
    shutil.copytree(ROOT / "vendor", app / "vendor", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copy2(args.nono, app / "nono")
    (app / "nono").chmod(0o755)
    (app / "configs").mkdir()
    selected = fixtures(args.dev)
    for fixture in selected:
        permissions(fixture["policy"]); permissions(fixture["worker_default"])
    save(out / "fixtures.json", selected)
    materials = {f["id"]: {"permitted": f"PP-permitted-{uuid.uuid4().hex}\n",
                           "forbidden": f"PP-forbidden-{uuid.uuid4().hex}\n",
                           "payload": f"PP-WRITE-{uuid.uuid4().hex}\n"} for f in selected}
    save(out / "materials.json", materials)
    expected = [dict(fixture=f["id"], route=route, configuration=name, track=track,
                     expected_effect=track == "permitted" or expected_access(route, *flags))
                for f in selected for route in ROUTES for name, flags in CONFIGS.items()
                for track in ("forbidden", "permitted")]
    save(out / "expected.json", expected)
    image = json.loads(docker("image", "inspect", "python:3.11-slim")["stdout"])[0]
    tag = "vega-pp-" + uuid.uuid4().hex[:10]
    containers = {name: f"{tag}-{name}" for name in ("parent", "worker")}
    source_hashes = {str(p.relative_to(ROOT)): digest(p) for p in sorted(ROOT.rglob("*"))
                     if p.is_file() and "evidence" not in p.parts and "__pycache__" not in p.parts
                     and p.suffix != ".pyc"}
    manifest = dict(protocol="permission-preservation-v1", development=args.dev,
        started_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        image_id=image["Id"], image_digests=image.get("RepoDigests", []),
        nono_sha256=digest(args.nono), source_hashes=source_hashes,
        fixture_hash=digest(out / "fixtures.json"), expected_hash=digest(out / "expected.json"),
        materials_hash=digest(out / "materials.json"),
        containers=containers, model_calls=0, planned_executions=len(expected),
        network="none", concurrency=1, cpu_limit_per_container=0.5)
    save(out / "manifest.json", manifest)
    created, rows = [], []
    try:
        for name in containers.values():
            docker("run", "-d", "--name", name, "--network", "none", "--read-only",
                   "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "65532:65532",
                   "--cpus", "0.5", "--memory", "256m", "--pids-limit", "48",
                   "--tmpfs", "/tmp:rw,nosuid,nodev,size=16m,mode=1777",
                   "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "HOME=/tmp",
                   "--mount", f"type=bind,src={app},dst=/app,readonly",
                   "--mount", f"type=bind,src={data},dst=/fixtures",
                   image["Id"], "sleep", "infinity")
            created.append(name)
        save(out / "isolation.json", json.loads(docker("inspect", *created)["stdout"]))
        versions = {"nono": docker("exec", containers["parent"], "/app/nono", "--version"),
                    "python": docker("exec", containers["parent"], "python3", "--version")}
        save(out / "versions.json", versions)
        for fixture in selected:
            for route in ROUTES:
                for config, (r_enabled, i_enabled) in CONFIGS.items():
                    for track in ("forbidden", "permitted"):
                        number = len(rows) + 1
                        record_id = f"{number:03}-{fixture['id']}-{route}-{config}-{track}"
                        targets = {}
                        for label in ("permitted", "forbidden"):
                            path = data / fixture[label].removeprefix("/fixtures/")
                            path.parent.mkdir(parents=True, exist_ok=True)
                            # Unconfined client can reach both; nono is the only OS treatment.
                            path.parent.chmod(0o777)
                            content = materials[fixture["id"]][label]
                            path.write_text(content); path.chmod(0o666)
                            targets[label] = dict(path=path, content=content)
                        payload = materials[fixture["id"]]["payload"]
                        request = dict(action=fixture["operation"], resource=fixture[track], payload=payload)
                        row = dict(id=record_id, fixture=fixture["id"], route=route, configuration=config,
                                   track=track, request=request, infrastructure_error=None)
                        try:
                            row.update(execute(fixture, route, request, r_enabled, i_enabled,
                                               app, containers, record_id))
                            result = row["execution"]
                            tool_result = None
                            if route.endswith("tool"):
                                if result["exit_code"]:
                                    raise RuntimeError("file tool failed to launch/complete: " + result["stderr"])
                                tool_result = event_json(result["stdout"], "tool_result")
                                row["tool_result"] = tool_result
                                content = (tool_result.get("effect") or {}).get("content", "")
                            else:
                                if not re.search(r"PP_EXEC:\d+\n", result["stdout"]):
                                    raise RuntimeError("shell did not start under requested confinement")
                                if result["exit_code"] and "Permission denied" not in result["stderr"] + result["stdout"]:
                                    raise RuntimeError("unexpected shell failure: " + result["stderr"])
                                content = result["stdout"]
                            before = targets[track]["content"]
                            after = targets[track]["path"].read_text()
                            row.update(before=before, after=after,
                                effect_completed=(before in content if request["action"] == "read" else
                                                  after != before if track == "forbidden" else after == payload),
                                expected_effect=track == "permitted" or expected_access(route, r_enabled, i_enabled),
                                non_target_unchanged=targets["permitted" if track == "forbidden" else "forbidden"]["path"].read_text()
                                    == targets["permitted" if track == "forbidden" else "forbidden"]["content"])
                            row["matches_expected"] = row["effect_completed"] == row["expected_effect"] and row["non_target_unchanged"]
                        except Exception as exc:
                            row.update(infrastructure_error=repr(exc), effect_completed=None, matches_expected=False)
                        rows.append(row)
                        save(out / "records" / (record_id + ".json"), row)
            print(f"completed {fixture['id']}: {len(rows)}/{len(expected)}", flush=True)
        groups = defaultdict(lambda: dict(forbidden=0, permitted=0, forbidden_effects=0,
                                          permitted_completions=0, errors=0))
        for row in rows:
            group = groups[row["configuration"] + "/" + row["route"]]
            group[row["track"]] += 1
            group["errors"] += bool(row["infrastructure_error"])
            if row["effect_completed"]:
                group["forbidden_effects" if row["track"] == "forbidden" else "permitted_completions"] += 1
        summary = dict(development=args.dev, planned=len(expected), recorded=len(rows), model_calls=0,
            infrastructure_errors=sum(bool(r["infrastructure_error"]) for r in rows),
            mismatches=sum(not r["matches_expected"] for r in rows), groups=dict(groups),
            pass_expected_matrix=len(rows) == len(expected) and all(r["matches_expected"] for r in rows))
        save(out / "summary.json", summary)
        print(json.dumps(summary, indent=2), flush=True)
        if not summary["pass_expected_matrix"]:
            raise SystemExit(1)
    finally:
        cleanup = [docker("rm", "-f", name, check=False) for name in created]
        save(out / "cleanup.json", cleanup)


if __name__ == "__main__":
    main()
