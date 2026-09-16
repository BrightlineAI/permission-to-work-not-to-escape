"""Persistent systemd user reconciliation, no model access to service management."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from .policy import Invalid
from .store import Store
from .supervisor import Supervisor


def unit_for(directory):
    identity = hashlib.sha256(str(Path(directory).resolve()).encode()).hexdigest()[:24]
    return "ptw-monitor-" + identity + ".service"


def call(*arguments):
    result = subprocess.run(["systemctl", "--user", *arguments], capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise Invalid("User service manager failed: " + result.stderr.strip()[:300])
    return result.stdout.strip()


def quoted(text):
    # systemd specifiers and environment expansion must not alter reviewed paths.
    return '"' + str(text).replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$") + '"'


def service_text(directory, *, legacy=False):
    return "\n".join([
        "[Unit]", "Description=Permission to Work controller monitor", "",
        "[Service]", "Type=simple",
        "ExecStart=" + " ".join(quoted(x) for x in [sys.executable, *([] if legacy else ["-B"]), "-m", "ptw.monitor", "--state", str(directory)]),
        "Restart=always", "RestartSec=1", "UMask=0077", "NoNewPrivileges=yes", "",
        "[Install]", "WantedBy=default.target", ""])


def health(store):
    with store.locked() as db:
        row = db.execute("SELECT at,error FROM monitor_health WHERE id=1").fetchone()
    age = time.time() - row["at"] if row else None
    return {"unit": unit_for(store.directory), "healthy": age is not None and 0 <= age < 5,
            "heartbeat_age_seconds": round(age, 3) if age is not None else None,
            "error": row["error"] if row else "monitor has not started"}


def ensure(store):
    if os.environ.get("PTW_SYSTEMD_SCOPE", "user") != "user":
        raise Invalid("Repository workflow requires a systemd user manager")
    unit = unit_for(store.directory)
    base = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))) / "systemd" / "user"
    base.mkdir(parents=True, exist_ok=True)
    destination = base / unit
    text = service_text(store.directory)
    if destination.is_symlink():
        raise Invalid("Monitor unit must not be a symlink")
    if destination.exists():
        if destination.read_text() != text:
            raise Invalid("Monitor installation differs; stop it and use monitor remove before upgrading")
    else:
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        call("daemon-reload")
    call("enable", "--now", unit)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        result = health(store)
        if result["healthy"]:
            return result
        time.sleep(.1)
    raise Invalid("Monitor did not become healthy; inspect status and user journal")


def remove(store):
    with store.locked() as db:
        if db.execute("SELECT 1 FROM projects WHERE stopped=0").fetchone():
            raise Invalid("Stop every project in this controller before removing its monitor")
    outcomes = Supervisor(store).reconcile()
    if any(not r["confirmed_stopped"] for r in outcomes):
        raise Invalid("Pending termination prevents monitor removal")
    unit = unit_for(store.directory)
    base = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))) / "systemd" / "user"
    destination = base / unit
    # Permit removal of our exact previous unit format after projects stop.
    # ensure() still requires the new format before starting a monitor.
    owned_texts = {service_text(store.directory), service_text(store.directory, legacy=True)}
    if destination.is_symlink() or (destination.exists() and destination.read_text() not in owned_texts):
        raise Invalid("Refusing to remove an unexpected monitor unit")
    if destination.exists():
        call("disable", "--now", unit)
        destination.unlink()
        call("daemon-reload")
    with store.locked() as db:
        db.execute("DELETE FROM monitor_health")
    return {"removed": unit, "state_and_history_retained": True}


def serve(directory):
    while True:
        try:
            store = Store(directory)  # Includes recovery of interrupted effects.
            outcomes = Supervisor(store).reconcile()
            error = "termination pending" if any(not r["confirmed_stopped"] for r in outcomes) else ""
            with store.locked() as db:
                db.execute("INSERT OR REPLACE INTO monitor_health VALUES(1,?,?)", (time.time(), error))
        except Exception as exc:
            print(type(exc).__name__ + ": monitor retry", file=sys.stderr, flush=True)
        time.sleep(.25)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True)
    serve(parser.parse_args().state)
