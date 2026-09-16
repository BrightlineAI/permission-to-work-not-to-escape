#!/usr/bin/env python3
"""Exercise documented CLI against real PyPI/OSV, with synthetic project files."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import time

from ptw.policy import load, save


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != "Linux":
        raise SystemExit("Use an isolated Linux VPS")
    root = args.out.absolute()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    calls, checks, units = [], {}, []
    started = time.monotonic()

    def cli(*args, exit_code=0):
        begin = time.monotonic()
        result = subprocess.run(["ptw", *map(str, args)], capture_output=True, text=True, timeout=180)
        try:
            value = json.loads(result.stdout or result.stderr)
        except ValueError:
            value = {"output": (result.stdout + result.stderr)[-1500:]}
        calls.append({"argv": list(map(str, args)), "exit_code": result.returncode,
                      "seconds": round(time.monotonic() - begin, 3), "result": value})
        if result.returncode != exit_code:
            raise AssertionError(f"CLI exit {result.returncode}, expected {exit_code}: {value}")
        return value

    def approve(policy, inventory, destination):
        reviewed = cli("review", "--policy", policy, "--inventory", inventory)
        cli("approve", "--policy", policy, "--inventory", inventory, "--sha256", reviewed["sha256"],
            "--reviewer", "synthetic walkthrough operator", "--out", destination)

    def install(directory, session, event, requirements, exit_code=0):
        return cli("package-install", "--state", directory / "controller", "--session", session,
                   "--event", event, "--requirements", requirements, exit_code=exit_code)

    def check(name, condition):
        checks[name] = bool(condition)
        if not condition:
            raise AssertionError(name)

    error = None
    try:
        check("doctor_ready", cli("doctor")["ready"])
        new = root / "new"
        cli("sample", "--packages", "--out", new)
        approve(new / "policy.json", new / "inventory.json", new / "approved.json")
        cli("activate", "--bundle", new / "approved.json", "--state", new / "controller")
        for name, task, parent in [("parent", "frontend", None), ("child", "frontend", "parent"), ("other", "operations", None)]:
            command = ["register", "--state", new / "controller", "--project", "website", "--task", task,
                       "--out", new / (name + ".json")]
            if parent:
                command += ["--parent", new / (parent + ".json")]
            cli(*command)
        receipt = install(new, new / "parent.json", "good", new / "requirements.txt")
        check("new_real_install_allowed", receipt["allowed"] and receipt["effect"] == "installed")
        unit = cli("launch", "--state", new / "controller", "--session", new / "parent.json",
            "--package-set", receipt["package_set"], "--", "/usr/bin/python3", "-c",
            "import idna,time; open('/resources/ui','w').write(idna.encode('bücher.de').decode()); time.sleep(60)")["unit"]
        units.append(unit)
        marker = new / "resources/ui.txt"
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and marker.read_text() != "xn--bcher-kva.de":
            time.sleep(.05)
        check("new_real_library_imported", marker.read_text() == "xn--bcher-kva.de")
        replay = install(new, new / "parent.json", "good", new / "requirements.txt")
        check("retry_did_not_reinstall", replay.get("replayed") and replay["package_set"] == receipt["package_set"])
        first = install(new, new / "parent.json", "bad1", new / "unsafe-requirements.txt", 1)
        check("live_critical_denied_with_warning", not first["allowed"] and first["level"] == "warn" and "CVSS 9." in first["reason"])
        install(new, new / "child.json", "bad2", new / "unsafe-requirements.txt", 1)
        third = install(new, new / "other.json", "bad3", new / "requirements.txt", 1)
        status = cli("status", "--state", new / "controller", "--project", "website")
        check("parent_child_other_share_stop", third["level"] == "stop" and status["violations"] == 3 and status["stopped"])
        from ptw.store import Store
        from ptw.supervisor import Supervisor
        check("running_package_work_stopped", Supervisor(Store(new / "controller")).state(unit)["confirmed_stopped"])
        check("denied_sets_not_published", len(list((new / "controller/package-sets").iterdir())) == 1)
        check("customer_file_unchanged", (new / "resources/customers.txt").read_text() == "SYNTHETIC_PRIVATE_CUSTOMERS\n")

        existing = root / "existing"
        cli("sample", "--out", existing)
        approve(existing / "policy.json", existing / "inventory.json", existing / "approved.json")
        cli("activate", "--bundle", existing / "approved.json", "--state", existing / "controller")
        cli("register", "--state", existing / "controller", "--project", "website", "--task", "frontend",
            "--out", existing / "old-session.json")
        cli("request", "--state", existing / "controller", "--session", existing / "old-session.json",
            "--event", "prior-work", "--action", "write", "--resource", "ui", "--content", "Existing user's content\n")
        before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (existing / "resources").iterdir()}
        cli("package-draft", "--policy", existing / "policy.json", "--project-id", "website-packages",
            "--task", "frontend", "--allow", "idna", "--out", existing / "package-draft.json")
        draft = load(existing / "package-draft.json")
        original = load(existing / "policy.json")
        check("existing_file_grants_preserved", draft["project"]["grants"] == original["project"]["grants"] and
              all(a["grants"] == b["grants"] and a["escalation"] == b["escalation"] for a, b in zip(draft["tasks"], original["tasks"])))
        approve(existing / "package-draft.json", existing / "inventory.json", existing / "package-approved.json")
        cli("stop", "--state", existing / "controller", "--project", "website")
        cli("activate", "--state", existing / "controller", "--bundle", existing / "package-approved.json")
        cli("register", "--state", existing / "controller", "--project", "website-packages", "--task", "frontend",
            "--out", existing / "new-session.json")
        second = install(existing, existing / "new-session.json", "existing-good", new / "requirements.txt")
        check("existing_project_install_allowed", second["allowed"])
        after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (existing / "resources").iterdir()}
        check("existing_files_unchanged_by_upgrade", before == after)
        check("old_project_history_retained", len(cli("events", "--state", existing / "controller", "--project", "website")) > 0)
        check("old_project_remains_stopped", cli("status", "--state", existing / "controller", "--project", "website")["stopped"])

        # Deterministic live age example: a deliberately strict 100-year policy,
        # not a claim that idna was uploaded yesterday. Normal 3-day boundaries
        # are independently exercised in the synthetic unit suite.
        cli("package-draft", "--policy", existing / "policy.json", "--project-id", "age-example",
            "--task", "frontend", "--allow", "idna", "--min-age-days", "36500", "--out", existing / "age-draft.json")
        approve(existing / "age-draft.json", existing / "inventory.json", existing / "age-approved.json")
        cli("activate", "--state", existing / "controller", "--bundle", existing / "age-approved.json")
        cli("register", "--state", existing / "controller", "--project", "age-example", "--task", "frontend",
            "--out", existing / "age-session.json")
        aged = install(existing, existing / "age-session.json", "age", new / "requirements.txt", 1)
        check("live_age_policy_denied", not aged["allowed"] and "younger" in aged["reason"])
        check("unrelated_project_not_stopped", not cli("status", "--state", existing / "controller", "--project", "website-packages")["stopped"])
    except Exception as exc:
        error = str(exc)
    finally:
        from ptw.supervisor import Supervisor
        for unit in units:
            Supervisor(None).terminate(unit)
        report = {"successful": error is None and all(checks.values()), "error": error,
                  "checks": checks, "wall_seconds": round(time.monotonic() - started, 3),
                  "network": "real PyPI release metadata, artifacts and OSV; no fixture provider",
                  "model_calls": 0, "commands": calls}
        save(root / "report.json", report)
        print(json.dumps({k: v for k, v in report.items() if k != "commands"}, indent=2))
    if error:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
