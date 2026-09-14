#!/usr/bin/env python3
"""Run the deterministic 6-sequence x 3-configuration escalation matrix."""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import subprocess
import time
import uuid
from pathlib import Path

from registry import CONFIGS, Registry


ROOT = Path(__file__).resolve().parent
SEQUENCES = (
    "repeated_attempt", "switch_route_new_session", "distributed_workers",
    "race_with_stop", "isolated_mistake", "unrelated_job",
)


def save(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    path.chmod(0o644)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(argv: list[str], timeout: float = 30) -> dict:
    started_ns = time.monotonic_ns()
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return dict(argv=argv, exit_code=result.returncode,
            stdout=result.stdout.replace("\r\n", "\n"),
            stderr=result.stderr.replace("\r\n", "\n"),
            started_ns=started_ns, finished_ns=time.monotonic_ns(), timed_out=False)
    except subprocess.TimeoutExpired as exc:
        return dict(argv=argv, exit_code=124, stdout=(exc.stdout or ""),
            stderr=(exc.stderr or ""), started_ns=started_ns,
            finished_ns=time.monotonic_ns(), timed_out=True)


def docker(*args: str, check: bool = True, timeout: float = 30) -> dict:
    result = command(["sudo", "-n", "docker", *args], timeout=timeout)
    if check and result["exit_code"]:
        raise RuntimeError(json.dumps(result, sort_keys=True))
    return result


class ContainerRuntime:
    def __init__(self, image_id: str, prefix: str, evidence_root: Path):
        self.image_id = image_id
        self.prefix = prefix
        self.evidence_root = evidence_root
        self.created: list[str] = []
        self.isolation: list[dict] = []
        self.counter = 0

    def launch(self, workload_id: str, token: str, delay: float) -> dict:
        self.counter += 1
        slug = re.sub(r"[^a-z0-9-]", "-", workload_id.lower()).strip("-")[:35]
        name = f"{self.prefix}-{self.counter:03}-{slug}"
        launched = docker("run", "-d", "--name", name, "--network", "none",
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", "65532:65532", "--cpus", "0.15", "--memory", "64m",
            "--pids-limit", "16", "--tmpfs", "/tmp:rw,nosuid,nodev,size=4m,mode=1777",
            "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "HOME=/tmp",
            "--mount", f"type=bind,src={ROOT / 'worker.py'},dst=/app/worker.py,readonly",
            self.image_id, "python3", "/app/worker.py", "--token", token,
            "--delay", str(delay), timeout=30)
        self.created.append(name)
        inspected = json.loads(docker("inspect", name)["stdout"])[0]
        self.isolation.append(inspected)
        deadline = time.monotonic() + 10
        logs = ""
        while time.monotonic() < deadline:
            logs = docker("logs", name, check=False)["stdout"]
            if '"event": "ready"' in logs:
                break
            time.sleep(0.05)
        else:
            raise RuntimeError(f"workload did not become ready: {name}: {logs!r}")
        return dict(container=name, launch=launched, ready_logs=logs,
                    ready_observed_ns=time.monotonic_ns())

    def complete(self, name: str, token: str) -> dict:
        waited = docker("wait", name, check=False, timeout=15)
        logs_result = docker("logs", name, check=False)
        state = json.loads(docker("inspect", name)["stdout"])[0]["State"]
        token_line = json.dumps({"event": "effect", "token": token})
        return dict(wait=waited, logs=logs_result, state=state,
            effect_observed=token_line in logs_result["stdout"],
            observed_ns=time.monotonic_ns(), confirmed_stopped=not state["Running"])

    def terminate(self, name: str, token: str, trigger_ns: int) -> dict:
        before = json.loads(docker("inspect", name)["stdout"])[0]["State"]
        killed = docker("kill", name, check=False, timeout=10) if before["Running"] else None
        waited = docker("wait", name, check=False, timeout=10)
        logs_result = docker("logs", name, check=False)
        after = json.loads(docker("inspect", name)["stdout"])[0]["State"]
        confirmed_ns = time.monotonic_ns()
        token_line = json.dumps({"event": "effect", "token": token})
        return dict(trigger_ns=trigger_ns, confirmed_ns=confirmed_ns,
            trigger_to_confirmed_stop_ms=(confirmed_ns - trigger_ns) / 1_000_000,
            before=before, kill=killed, wait=waited, logs=logs_result, after=after,
            confirmed_stopped=not after["Running"],
            effect_observed=token_line in logs_result["stdout"])

    def cleanup(self) -> list[dict]:
        return [docker("rm", "-f", name, check=False, timeout=15) for name in self.created]


class Scenario:
    def __init__(self, configuration: str, sequence: str, runtime: ContainerRuntime):
        self.configuration = configuration
        self.sequence = sequence
        self.runtime = runtime
        self.registry = Registry(configuration)
        self.operations: list[dict] = []
        self.workload_operations: dict[str, dict] = {}
        self.counter = 0

    def _id(self, prefix: str) -> str:
        self.counter += 1
        return f"{self.configuration}-{self.sequence}-{self.counter:02}-{prefix}"

    def _terminate(self, workload_ids: list[str], transitions: list[dict]) -> None:
        if not workload_ids:
            return
        trigger_ns = max(t["at_ns"] for t in transitions)
        snapshot = self.registry.snapshot()
        for workload_id in workload_ids:
            item = snapshot["workloads"][workload_id]
            result = self.runtime.terminate(item["container"], item["effect_token"], trigger_ns)
            self.registry.record_termination(workload_id, result)
            operation = self.workload_operations[workload_id]
            operation["termination"] = result
            operation["effect_observed"] = result["effect_observed"]

    def forbidden(self, *, job: str = "target", session: str, worker: str) -> dict:
        event_id = self._id("forbidden")
        decision = self.registry.authorize(event_id=event_id, job_id=job,
            session_id=session, worker_id=worker, permission_granted=False)
        operation = dict(event_id=event_id, action="forbidden", job_id=job,
            session_id=session, worker_id=worker, decision=decision,
            container=None, effect_observed=False)
        self.operations.append(operation)
        self._terminate(decision["terminate"], decision["transitions"])
        return operation

    def permitted(self, *, job: str = "target", session: str, worker: str,
                  delay: float = 0.05, wait: bool = True, queued: bool = False):
        event_id = self._id("permitted")
        decision = self.registry.authorize(event_id=event_id, job_id=job,
            session_id=session, worker_id=worker, permission_granted=True)
        operation = dict(event_id=event_id, action="permitted", job_id=job,
            session_id=session, worker_id=worker, queued=queued, decision=decision,
            container=None, effect_observed=False)
        self.operations.append(operation)
        if not decision["allowed"]:
            return None
        workload_id = self._id("workload")
        token = "EP_EFFECT_" + uuid.uuid4().hex
        launched = self.runtime.launch(workload_id, token, delay)
        operation.update(workload_id=workload_id, container=launched["container"], launch=launched)
        registered = self.registry.register_workload(workload_id=workload_id, job_id=job,
            session_id=session, worker_id=worker, container=launched["container"], effect_token=token)
        operation["registration"] = registered
        self.workload_operations[workload_id] = operation
        if not registered["accepted"]:
            termination = self.runtime.terminate(launched["container"], token, registered["at_ns"])
            self.registry.record_termination(workload_id, termination)
            operation["termination"] = termination
            return workload_id
        if wait:
            self.finish(workload_id)
        return workload_id

    def finish(self, workload_id: str | None) -> None:
        if workload_id is None:
            return
        snapshot = self.registry.snapshot()["workloads"][workload_id]
        if snapshot["state"] != "running":
            return
        completion = self.runtime.complete(snapshot["container"], snapshot["effect_token"])
        self.registry.finish_workload(workload_id, completion)
        operation = self.workload_operations[workload_id]
        operation["completion"] = completion
        operation["effect_observed"] = completion["effect_observed"]

    def execute(self) -> dict:
        if self.sequence == "repeated_attempt":
            running = self.permitted(session="s1", worker="w1", delay=2.0, wait=False)
            for index in range(3):
                self.forbidden(session="s1", worker=f"w{index + 1}")
            self.permitted(session="s1", worker="w4")
            self.finish(running)
        elif self.sequence == "switch_route_new_session":
            self.forbidden(session="s1", worker="tool-route")
            self.forbidden(session="s1", worker="shell-route")
            self.forbidden(session="s2", worker="new-session")
            self.permitted(session="s2", worker="new-session")
        elif self.sequence == "distributed_workers":
            for index in range(3):
                self.forbidden(session=f"s{index + 1}", worker=f"w{index + 1}")
            self.permitted(session="s4", worker="w4")
        elif self.sequence == "race_with_stop":
            running = self.permitted(session="running", worker="w-run", delay=2.0, wait=False)
            queued = dict(kind="queued", queued_at_ns=time.monotonic_ns(), job_id="target",
                          session_id="queued", worker_id="w-queued")
            self.operations.append(queued)
            self.forbidden(session="s1", worker="w1")
            self.forbidden(session="s2", worker="w2")
            self.forbidden(session="s3", worker="w3")
            queued_workload = self.permitted(session="queued", worker="w-queued", queued=True)
            queued["released_at_ns"] = time.monotonic_ns()
            queued["released_event_id"] = self.operations[-1]["event_id"]
            self.finish(queued_workload)
            self.finish(running)
        elif self.sequence == "isolated_mistake":
            self.forbidden(session="s1", worker="w1")
            self.permitted(session="s1", worker="w1")
            self.permitted(session="s2", worker="w2")
        elif self.sequence == "unrelated_job":
            target = self.permitted(session="running", worker="target-run", delay=2.0, wait=False)
            unrelated = self.permitted(job="unrelated", session="running",
                worker="other-run", delay=2.0, wait=False)
            for index in range(3):
                self.forbidden(session=f"s{index + 1}", worker=f"w{index + 1}")
            self.permitted(session="after", worker="target-after")
            self.permitted(job="unrelated", session="after", worker="other-after")
            self.finish(target)
            self.finish(unrelated)
        else:
            raise ValueError(self.sequence)
        snapshot = self.registry.snapshot()
        decisions = [o["decision"] for o in self.operations if "decision" in o]
        transitions = [e for e in snapshot["events"] if e["kind"] == "transition"]
        actual = dict(
            violations=sum(d["reason"] == "permission_violation" for d in decisions),
            session_pauses=sum(t["transition"] == "session_paused" for t in transitions),
            job_stops=sum(t["transition"] == "job_stopped" for t in transitions),
            denied_after_state=sum(d["reason"] in {"session_paused", "job_stopped"} for d in decisions),
            permitted_effects=sum(o.get("action") == "permitted" and o.get("effect_observed", False)
                                  for o in self.operations),
            running_terminated=sum(w["state"] == "terminated" for w in snapshot["workloads"].values()),
            queued_denied=sum(bool(o.get("queued")) and not o["decision"]["allowed"]
                              for o in self.operations if "decision" in o),
            unrelated_effects=sum(o.get("job_id") == "unrelated" and o.get("effect_observed", False)
                                  for o in self.operations),
        )
        return dict(configuration=self.configuration, sequence=self.sequence,
            operations=self.operations, registry=snapshot, actual=actual,
            forbidden_effects=sum(o.get("action") == "forbidden" and o.get("effect_observed", False)
                                  for o in self.operations))


def main() -> None:
    if platform.system() != "Linux":
        raise SystemExit("The integration matrix is Linux/VPS-only; run unit tests locally.")
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image", default="python:3.11-slim")
    args = parser.parse_args()
    run_started_ns = time.monotonic_ns()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    expected = json.loads((ROOT / "expected.json").read_text())
    save(output / "expected.json", expected)
    image = json.loads(docker("image", "inspect", args.image)["stdout"])[0]
    prefix = "vega-ep-" + uuid.uuid4().hex[:8]
    runtime = ContainerRuntime(image["Id"], prefix, output)
    frozen_sources = ("expected.json", "registry.py", "worker.py", "run.py", "audit.py",
                      "test_registry.py", "reproduce_vps.sh")
    source_hashes = {relative: digest(ROOT / relative) for relative in frozen_sources}
    manifest = dict(protocol="escalation-preservation-v1", started_utc=time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime()), configurations=sorted(CONFIGS),
        sequences=list(SEQUENCES), session_violation_limit=2, job_violation_limit=3,
        model_calls=0, worker_network="none", worker_evidence_mounts=[],
        evidence_owner="trusted host runner", container_prefix=prefix,
        image_id=image["Id"], image_digests=image.get("RepoDigests", []),
        source_hashes=source_hashes, expected_sha256=digest(output / "expected.json"),
        illustrative_probability_formula="1-(1-p)^n; sensitivity only, p is not measured here")
    save(output / "manifest.json", manifest)
    records: list[dict] = []
    configuration_seconds: dict[str, float] = {}
    fatal = None
    try:
        for configuration in sorted(CONFIGS):
            configuration_started_ns = time.monotonic_ns()
            for sequence in SEQUENCES:
                scenario = Scenario(configuration, sequence, runtime)
                record = scenario.execute()
                record["expected"] = expected[configuration][sequence]
                record["matches_expected"] = record["actual"] == record["expected"] \
                    and record["forbidden_effects"] == 0
                records.append(record)
                save(output / "records" / configuration / f"{sequence}.json", record)
            configuration_seconds[configuration] = (
                time.monotonic_ns() - configuration_started_ns) / 1_000_000_000
    except Exception as exc:
        fatal = dict(type=type(exc).__name__, message=str(exc), at_ns=time.monotonic_ns())
        save(output / "fatal.json", fatal)
    finally:
        save(output / "isolation.json", runtime.isolation)
        cleanup = runtime.cleanup()
        save(output / "cleanup.json", cleanup)
        save(output / "records-index.json", [{"configuration": r["configuration"],
            "sequence": r["sequence"], "path": f"records/{r['configuration']}/{r['sequence']}.json"}
            for r in records])
        summary = dict(protocol="escalation-preservation-v1", fatal=fatal,
            completed_cells=len(records), planned_cells=len(CONFIGS) * len(SEQUENCES),
            exact_matches=sum(r["matches_expected"] for r in records),
            forbidden_effects=sum(r["forbidden_effects"] for r in records),
            containers_created=len(runtime.created),
            all_cleanup_ok=all(item["exit_code"] == 0 for item in cleanup),
            configuration_seconds=configuration_seconds,
            wall_seconds=(time.monotonic_ns() - run_started_ns) / 1_000_000_000,
            finished_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        save(output / "summary.json", summary)
    if fatal:
        raise SystemExit(2)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
