"""Exercise installed boundaries, not just dependency presence."""
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import time

from .policy import approve, compile_policy, digest, load
from .sample import create
from .store import Store
from .supervisor import Supervisor, sandbox_command


def check():
    if platform.system() != "Linux":
        return {"ready": False, "error": "Linux is required"}
    report = {"platform": platform.platform(), "checks": {}, "versions": {}}
    for name, command in {"nono": [os.environ.get("PTW_NONO") or shutil.which("nono") or "nono", "--version"],
                          "bubblewrap": ["bwrap", "--version"], "codex": ["codex", "--version"]}.items():
        try:
            result = subprocess.run(command, text=True, capture_output=True, timeout=10)
            report["versions"][name] = (result.stdout or result.stderr).strip()
        except OSError:
            report["versions"][name] = "not installed"
    try:
        auth = subprocess.run(["codex", "login", "status"], text=True, capture_output=True, timeout=10)
        report["codex_authenticated"] = auth.returncode == 0
    except OSError:
        report["codex_authenticated"] = False
    with tempfile.TemporaryDirectory(prefix="ptw-doctor-") as directory:
        root = Path(directory)
        create(root / "fixture")
        policy, inv = load(root / "fixture/policy.json"), load(root / "fixture/inventory.json")
        store = Store(root / "controller")
        store.activate(approve(policy, inv, digest(compile_policy(policy, inv)), "synthetic doctor fixture"))
        actor = store.register("website", "frontend")
        supervisor = Supervisor(store)
        unit = None
        try:
            allowed = sandbox_command(inv, actor["grants"], ["/usr/bin/python3", "-c", "assert open('/resources/ui').read() == 'Welcome\\n'"])
            result = subprocess.run(allowed, capture_output=True, timeout=15)
            report["checks"]["permitted_read"] = result.returncode == 0
            denied = sandbox_command(inv, actor["grants"], ["/usr/bin/python3", "-c", "open('/resources/customers').read()"])
            result = subprocess.run(denied, capture_output=True, timeout=15)
            report["checks"]["private_read_blocked"] = result.returncode != 0 and report["checks"]["permitted_read"]
            unit = supervisor.launch(actor["token"], ["/usr/bin/sleep", "30"])
            deadline = time.monotonic() + 5
            while True:
                state = supervisor.state(unit)
                if state.get("ActiveState") == "active" or state["confirmed_stopped"] or time.monotonic() >= deadline:
                    break
                time.sleep(.02)
            report["checks"]["supervised_work_running"] = state.get("ActiveState") == "active"
            store.stop("website")
            supervisor.reconcile()
            report["checks"]["project_stop_confirmed"] = supervisor.state(unit)["confirmed_stopped"]
        except Exception as exc:
            report["error"] = str(exc)
        finally:
            if unit:
                supervisor.terminate(unit)
    report["ready"] = len(report["checks"]) == 4 and all(report["checks"].values()) and "error" not in report
    return report
