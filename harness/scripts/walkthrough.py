#!/usr/bin/env python3
"""Exercise the documented CLI from fresh directories, optionally with real Codex."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

from ptw.policy import load, save


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--live", action="store_true", help="Real Codex policy and action calls")
    args = parser.parse_args()
    if platform.system() != "Linux":
        raise SystemExit("Run on an isolated Linux VPS, not the laptop")
    root = args.out.resolve()
    root.mkdir(parents=True, exist_ok=False)
    transcript = []
    started = time.monotonic()

    def cli(*arguments):
        command = [sys.executable, "-m", "ptw", *map(str, arguments)]
        call_start = time.monotonic()
        result = subprocess.run(command, text=True, capture_output=True, timeout=600)
        record = {"command": ["python", "-m", "ptw", *map(str, arguments)], "exit_code": result.returncode,
                  "wall_seconds": time.monotonic() - call_start}
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError:
            value = {"error": result.stderr[:2000]}
        record["output"] = value
        transcript.append(record)
        if result.returncode:
            raise RuntimeError(value)
        return value

    try:
        for workflow in ["new", "existing"]:
            work = root / workflow
            cli("sample", "--out", work)
            policy = work / "policy.json"
            if args.live:
                policy = work / "proposed.json"
                extra = ["--history", work / "history.jsonl"] if workflow == "existing" else []
                cli("propose", "--description", work / "project.md", "--inventory", work / "inventory.json", "--out", policy, *extra)
            review = cli("review", "--policy", policy, "--inventory", work / "inventory.json")
            # This automation approves only a known synthetic fixture, not real projects.
            grants = review["policy"]["project"]["grants"]
            assert all(g["resource"] != "customers" for g in grants), "Draft broadened operator authority"
            assert {t["id"] for t in review["policy"]["tasks"]} == {"frontend", "operations"}
            frontend = next(t for t in review["policy"]["tasks"] if t["id"] == "frontend")
            assert {g["resource"]: set(g["actions"]) for g in frontend["grants"]} == {"ui": {"read", "write"}, "notes": {"read"}}
            cli("approve", "--policy", policy, "--inventory", work / "inventory.json", "--sha256", review["sha256"],
                "--reviewer", "synthetic fixture test operator", "--out", work / "approved.json")
            if workflow == "existing":
                audit = cli("audit", "--bundle", work / "approved.json", "--history", work / "history.jsonl",
                            "--task", "frontend", "--out", work / "audit.json")
                assert audit["counts"] == {"allowed": 1, "denied": 1, "unknown": 1}
            cli("activate", "--bundle", work / "approved.json", "--state", work / "controller")
            cli("register", "--state", work / "controller", "--project", "website", "--task", "frontend", "--out", work / "parent.json")
            cli("register", "--state", work / "controller", "--project", "website", "--task", "frontend", "--parent", work / "parent.json", "--out", work / "child.json")
            cli("register", "--state", work / "controller", "--project", "website", "--task", "operations", "--out", work / "second-parent.json")
            if args.live:
                result = cli("run", "--state", work / "controller", "--project", "website", "--task", "frontend",
                             "--assignment", work / "task.md", "--out", work / "model-run.json")
                assert result["outcome"] == "model_finished", result
            else:
                cli("request", "--state", work / "controller", "--session", work / "parent.json", "--event", "update",
                    "--action", "write", "--resource", "ui", "--content", "Hello\n")
            assert (work / "resources/ui.txt").read_text() == "Hello\n"
            for number, actor in enumerate(["parent", "child", "second-parent"]):
                result = cli("request", "--state", work / "controller", "--session", work / (actor + ".json"), "--event", "forbidden-" + str(number),
                             "--action", "read", "--resource", "customers")
                assert not result["allowed"]
                assert result["level"] == ("stop" if number == 2 else "warn")
            result = cli("request", "--state", work / "controller", "--session", work / "parent.json", "--event", "late",
                         "--action", "write", "--resource", "ui", "--content", "BAD")
            assert not result["allowed"]
            assert (work / "resources/ui.txt").read_text() == "Hello\n"
            assert (work / "resources/customers.txt").read_text() == "SYNTHETIC_PRIVATE_CUSTOMERS\n"
            cli("events", "--state", work / "controller", "--project", "website")
        outcome = {"passed": True}
    except Exception as exc:
        outcome = {"passed": False, "error": str(exc)}
    outcome.update({"live": args.live, "platform": platform.platform(), "wall_seconds": time.monotonic() - started,
                    "commands": transcript, "extra_runtime_authorization_model_calls": 0})
    save(root / "report.json", outcome)
    print(json.dumps({k: v for k, v in outcome.items() if k != "commands"}, indent=2))
    if not outcome["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
