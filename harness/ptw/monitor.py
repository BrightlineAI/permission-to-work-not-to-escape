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


def health(store, *, db=None):
    # Callers already holding the controller lock must reuse that connection.
    # flock on a separately opened descriptor is not reentrant.
    if db is None:
        with store.locked() as locked_db:
            return health(store, db=locked_db)
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


def record_identity(store, value):
    """Replace the current-process diagnostic, not append to audit history."""
    from .policy import save
    from .setup_transaction import sync
    destination = store.directory / 'monitor-identity.json'
    temporary = destination.with_suffix('.pending')
    # One reserved staging slot, including across interrupted restarts. The
    # controller lock serializes writers; replace never follows a target link.
    with store.locked():
        try:
            temporary.unlink(missing_ok=True)
            save(temporary, value)
            os.replace(temporary, destination)
            sync(store.directory)
        finally:
            temporary.unlink(missing_ok=True)


def serve(directory):
    from .runtime_identity import snapshot
    identity_recorded = False
    failure_recorded = False
    while True:
        stage = 'store-recovery'
        try:
            store = Store(directory)  # Includes recovery of interrupted effects.
            stage = 'runtime-identity'
            identity_failure = None
            if not identity_recorded:
                try:
                    record_identity(store, snapshot('monitor'))
                    identity_recorded = True
                except Exception as exc:
                    identity_failure = exc
            stage = 'supervisor-reconciliation'
            outcomes = Supervisor(store).reconcile()
            error = "termination pending" if any(not r["confirmed_stopped"] for r in outcomes) else ""
            if any(r.get('evidence') == 'unavailable' for r in outcomes):
                error = 'termination evidence unavailable'
            if identity_failure is not None:
                error = '; '.join(filter(None, (error, 'runtime identity unavailable')))
            stage = 'heartbeat'
            with store.locked() as db:
                db.execute("INSERT OR REPLACE INTO monitor_health VALUES(1,?,?)", (time.time(), error))
            if identity_failure is not None:
                # Optional diagnostics must not prevent authority reduction or
                # termination. Health records the loss; the journal has location
                # only, and a later iteration can retry this bounded snapshot.
                stage = 'runtime-identity'
                raise identity_failure
        except Exception as exc:
            if not failure_recorded:
                # One bounded location record per process. Never format the
                # exception, source lines, locals, paths or chained payloads.
                frames = []
                tb = exc.__traceback__
                while tb is not None:
                    code = tb.tb_frame.f_code
                    frames.append({'file': Path(code.co_filename).name[:80],
                                   'function': code.co_name[:80], 'line': tb.tb_lineno})
                    frames = frames[-8:]
                    tb = tb.tb_next
                print('PTW_MONITOR_FIRST_FAILURE ' + json.dumps({
                    'stage': stage, 'exception': type(exc).__name__[:80],
                    'frames': frames}), file=sys.stderr, flush=True)
                failure_recorded = True
            print(type(exc).__name__ + ": monitor retry", file=sys.stderr, flush=True)
        time.sleep(.25)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True)
    serve(parser.parse_args().state)
