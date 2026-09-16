"""Reuse Linux namespaces, nono and systemd instead of implementing a sandbox."""
from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import subprocess
import time

from .policy import Invalid, scope


def run(argv, **kwargs):
    return subprocess.run(argv, capture_output=True, text=True, timeout=20, **kwargs)


def sandbox_command(inv, grants, argv, nono=None):
    if not argv or not all(isinstance(v, str) and "\x00" not in v for v in argv):
        raise Invalid("Nonempty argument list required")
    bwrap = shutil.which("bwrap")
    nono = nono or os.environ.get("PTW_NONO") or shutil.which("nono")
    if not bwrap or not nono or not Path(nono).is_file():
        raise Invalid("bubblewrap and nono are required; no unsandboxed fallback")
    command = [bwrap, "--unshare-all", "--die-with-parent", "--new-session", "--clearenv",
               "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "HOME", "/home/agent",
               "--dir", "/home/agent",
               "--setenv", "XDG_STATE_HOME", "/nono-state", "--dir", "/nono-state",
               "--ro-bind", "/usr", "/usr"]
    for path in ["/bin", "/lib", "/lib64", "/sbin"]:
        if Path(path).is_symlink():
            command += ["--symlink", os.readlink(path), path]
        elif Path(path).exists():
            command += ["--ro-bind", path, path]
    command += ["--proc", "/proc", "--dir", "/dev"]
    # No controlling TTY in these services. Expose only required devices, rather
    # than creating /dev/tty that nono cannot open in a detached namespace.
    for device in ["null", "zero", "random", "urandom"]:
        command += ["--dev-bind", "/dev/" + device, "/dev/" + device]
    command += ["--symlink", "/proc/self/fd", "/dev/fd",
                "--tmpfs", "/tmp", "--tmpfs", "/work",
                "--dir", "/resources", "--ro-bind", str(Path(nono).resolve()), "/nono", "--chdir", "/work"]
    permissions = ["/nono", "run", "--sandbox-policy", "landlock", "--block-net", "--allow", "/tmp", "--allow", "/work",
                   "--no-rollback", "--no-audit", "--no-diagnostics"]
    for resource, actions in scope(grants).items():
        path = str(Path(inv["root"]) / inv["resources"][resource]["path"])
        target = "/resources/" + resource
        # Append only is a broker operation; do not turn it into arbitrary file writes.
        if "write" in actions:
            command += ["--bind", path, target]
            permissions += ["--allow-file" if "read" in actions else "--write-file", target]
        elif "read" in actions:
            command += ["--ro-bind", path, target]
            permissions += ["--read-file", target]
    return command + ["--"] + permissions + ["--"] + argv


class Supervisor:
    def __init__(self, store, nono=None):
        self.store, self.nono = store, nono

    def launch(self, token, argv):
        """Operator API for local workloads, not an unrestricted model tool."""
        with self.store.locked() as db:
            actor = self.store.session(db, token)
            project, bundle = self.store.project(db, actor["project"])
            if project["stopped"]:
                raise Invalid("Project stopped")
            unit = "ptw-" + secrets.token_hex(12) + ".service"
            command = sandbox_command(bundle["inventory"], json.loads(actor["grants"]), argv, self.nono)
            db.execute("INSERT INTO workloads(unit,project,session) VALUES(?,?,?)", (unit, actor["project"], actor["id"]))
            result = run(["sudo", "-n", "systemd-run", "--quiet", "--collect", "--unit=" + unit,
                          "--uid=" + pwd.getpwuid(os.getuid()).pw_name,
                          "--property=KillMode=control-group", "--property=NoNewPrivileges=yes",
                          "--property=ProtectControlGroups=yes", "--property=RestrictSUIDSGID=yes",
                          "--property=MemoryMax=256M", "--property=CPUQuota=50%", "--property=TasksMax=64",
                          "--property=RuntimeMaxSec=300", "--property=TimeoutStopSec=2", "--", *command])
            if result.returncode:
                db.execute("UPDATE workloads SET stopped=1 WHERE unit=?", (unit,))
                raise Invalid("Sandbox launch failed: " + result.stderr[:500])
            return unit

    def engine(self, token, command):
        """Trusted adapter only: start the configured Codex runtime, not model argv.

        Native tool permissions are fixed by codex.generate. The model cannot call
        this API, choose flags or gain a general host command tool.
        """
        with self.store.locked() as db:
            actor = self.store.session(db, token)
            project, _ = self.store.project(db, actor["project"])
            if project["stopped"]:
                raise Invalid("Project stopped")
            unit = "ptw-" + secrets.token_hex(12) + ".service"
            db.execute("INSERT INTO workloads(unit,project,session) VALUES(?,?,?)", (unit, actor["project"], actor["id"]))
            process = subprocess.Popen(["sudo", "-n", "systemd-run", "--quiet", "--collect", "--pipe", "--wait", "--unit=" + unit,
                "--uid=" + pwd.getpwuid(os.getuid()).pw_name, "--property=KillMode=control-group",
                "--property=MemoryMax=768M", "--property=CPUQuota=100%", "--property=TasksMax=128",
                "--property=RuntimeMaxSec=200", "--property=TimeoutStopSec=2", "--", *command],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            # Do not release the admission lock until systemd has created the unit.
            # Otherwise a concurrent stop could miss a launch still in flight.
            for _ in range(100):
                if self.state(unit).get("LoadState") == "loaded":
                    return process, unit
                if process.poll() is not None:
                    break
                time.sleep(.02)
            self.terminate(unit)
            process.kill()
            process.communicate(timeout=5)
            raise Invalid("Codex supervised launch did not become ready")

    @staticmethod
    def state(unit):
        if not re.fullmatch(r"ptw-[0-9a-f]{24}\.service", unit):
            raise Invalid("Invalid managed unit name")
        result = run(["sudo", "-n", "systemctl", "show", unit, "-p", "ActiveState", "-p", "ControlGroup", "-p", "LoadState"])
        if result.returncode:
            return {"confirmed_stopped": False, "error": "Cannot query supervisor"}
        values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        group = values.get("ControlGroup", "")
        populated = False
        if group:
            events = Path("/sys/fs/cgroup" + group) / "cgroup.events"
            populated = events.exists() and "populated 1" in events.read_text()
        return {**values, "confirmed_stopped": not populated and values.get("ActiveState") in ("inactive", "failed")}

    def terminate(self, unit):
        self.state(unit)  # Validate the exact target before any mutation.
        run(["sudo", "-n", "systemctl", "stop", unit])
        return self.state(unit)

    def reconcile(self):
        outcomes = []
        with self.store.locked() as db:
            rows = db.execute("SELECT w.unit FROM workloads w JOIN projects p ON p.id=w.project WHERE p.stopped=1 AND w.stopped=0").fetchall()
            for row in rows:
                state = self.terminate(row["unit"])
                if state["confirmed_stopped"]:
                    db.execute("UPDATE workloads SET stopped=1 WHERE unit=?", (row["unit"],))
                outcomes.append({"unit": row["unit"], **state})
        return outcomes
