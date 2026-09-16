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
import sys
import time

from .policy import Invalid, scope


def run(argv, **kwargs):
    return subprocess.run(argv, capture_output=True, text=True, timeout=20, **kwargs)


def manager(tool):
    mode = os.environ.get("PTW_SYSTEMD_SCOPE", "user")
    if mode == "user":
        return [tool, "--user"]
    if mode == "system":
        return ["sudo", "-n", tool]
    raise Invalid("PTW_SYSTEMD_SCOPE must be user or system")


def service_identity():
    return [] if os.environ.get("PTW_SYSTEMD_SCOPE", "user") == "user" else [
        "--uid=" + pwd.getpwuid(os.getuid()).pw_name]


def runtime_namespace():
    """Small shared filesystem and network boundary for workers and installer."""
    bwrap = shutil.which("bwrap")
    if not bwrap:
        raise Invalid("bubblewrap is required; no unsandboxed fallback")
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
    return command + ["--symlink", "/proc/self/fd", "/dev/fd",
                      "--tmpfs", "/tmp", "--tmpfs", "/work", "--chdir", "/work"]


def sandbox_command(inv, grants, argv, nono=None, resource_fds=None, package_mount=None, package_ecosystem="pypi"):
    if not argv or not all(isinstance(v, str) and "\x00" not in v for v in argv):
        raise Invalid("Nonempty argument list required")
    nono = nono or os.environ.get("PTW_NONO") or shutil.which("nono")
    if not nono or not Path(nono).is_file():
        raise Invalid("nono is required; no unsandboxed fallback")
    command = runtime_namespace() + ["--dir", "/resources", "--ro-bind", str(Path(nono).resolve()), "/nono"]
    permissions = ["/nono", "run", "--sandbox-policy", "landlock", "--block-net", "--allow", "/tmp", "--allow", "/work",
                   "--no-rollback", "--no-audit", "--no-diagnostics"]
    if package_mount:
        command += ["--ro-bind", str(package_mount), "/packages"]
        permissions += ["--read", "/packages"]
        # nono intentionally scrubs PYTHONPATH. Set this fixed, trusted path only
        # after entering its sandbox; never forward an operator/model value.
        argv = ["/usr/bin/env", "PYTHONPATH=/packages", "PYTHONNOUSERSITE=1", *argv]
        if package_ecosystem == "npm":
            command += ["--chdir", "/packages", "--symlink", "/packages/node_modules", "/node_modules"]
            argv = ["/usr/bin/env", "NODE_PATH=/packages/node_modules",
                    "PATH=/packages/node_modules/.bin:/usr/bin:/bin", *argv]
    for resource, actions in scope(grants).items():
        path = str(Path(inv["root"]) / inv["resources"][resource]["path"])
        target = "/resources/" + resource
        # Append only is a broker operation; do not turn it into arbitrary file writes.
        if "write" in actions:
            command += ["--bind-fd", str(resource_fds[resource]), target] if resource_fds is not None else ["--bind", path, target]
            permissions += ["--allow-file" if "read" in actions else "--write-file", target]
        elif "read" in actions:
            command += ["--ro-bind-fd", str(resource_fds[resource]), target] if resource_fds is not None else ["--ro-bind", path, target]
            permissions += ["--read-file", target]
    return command + ["--"] + permissions + ["--"] + argv


class Supervisor:
    def __init__(self, store, nono=None):
        self.store, self.nono = store, nono

    def launch(self, token, argv, package_set=None):
        """Operator API for local workloads, not an unrestricted model tool."""
        with self.store.locked() as db:
            actor = self.store.session(db, token)
            project, bundle = self.store.project(db, actor["project"])
            if project["stopped"]:
                raise Invalid("Project stopped")
            if bundle["policy"]["version"] == 4:
                raise Invalid("Use reviewed repository commands for version 4, not direct workload mounts")
            package_mount = None
            package_ecosystem = "pypi"
            if package_set:
                from .packages import mounted_set
                package_mount = mounted_set(self.store, db, actor, package_set)
                package_ecosystem = db.execute("SELECT ecosystem FROM package_sets WHERE id=?", (package_set,)).fetchone()[0]
            unit = "ptw-" + secrets.token_hex(12) + ".service"
            # Validate dependencies now. The trusted worker pins and revalidates
            # resource descriptors immediately before mounting them.
            sandbox_command(bundle["inventory"], json.loads(actor["grants"]), argv, self.nono,
                            package_mount=package_mount, package_ecosystem=package_ecosystem)
            bindings = {r["resource"]: [r["device"], r["inode"]] for r in db.execute(
                "SELECT resource,device,inode FROM bindings WHERE project=?", (actor["project"],))}
            config = {"inventory": bundle["inventory"], "grants": json.loads(actor["grants"]),
                      "bindings": bindings, "nono": self.nono or os.environ.get("PTW_NONO") or shutil.which("nono"),
                      "package_mount": str(package_mount) if package_mount else None, "package_ecosystem": package_ecosystem}
            # The user manager does not inherit the installer's bytecode setting.
            # Keep installed source/receipt immutable when this service imports it.
            command = [sys.executable, "-B", "-m", "ptw.worker", json.dumps(config), *argv]
            db.execute("INSERT INTO workloads(unit,project,session) VALUES(?,?,?)", (unit, actor["project"], actor["id"]))
            result = run(manager("systemd-run") + ["--quiet", "--collect", "--unit=" + unit, *service_identity(),
                          "--property=KillMode=control-group", "--property=NoNewPrivileges=yes",
                          "--property=ProtectControlGroups=yes",
                          "--property=MemoryMax=256M", "--property=CPUQuota=50%", "--property=TasksMax=64",
                          "--property=RuntimeMaxSec=300", "--property=TimeoutStopSec=2", "--", *command])
            if result.returncode:
                db.execute("UPDATE workloads SET stopped=1 WHERE unit=?", (unit,))
                raise Invalid("Sandbox launch failed: " + result.stderr[:500])
            return unit

    def engine(self, token, command, *, stderr=None, terminal=False, service_seconds=200):
        """Trusted adapter only: start a fixed model runtime or confined build.

        Native tool permissions are fixed by codex.generate. The model cannot call
        this API, choose flags or gain a general host command tool.
        """
        if not isinstance(service_seconds, int) or not 1 <= service_seconds <= 28800:
            raise Invalid("Trusted service lifetime must be 1 to 28800 seconds")
        with self.store.locked() as db:
            actor = self.store.session(db, token)
            project, _ = self.store.project(db, actor["project"])
            if project["stopped"]:
                raise Invalid("Project stopped")
            unit = "ptw-" + secrets.token_hex(12) + ".service"
            db.execute("INSERT INTO workloads(unit,project,session) VALUES(?,?,?)", (unit, actor["project"], actor["id"]))
            process = subprocess.Popen(manager("systemd-run") + ["--quiet", "--collect", "--pty" if terminal else "--pipe", "--wait", "--unit=" + unit,
                *service_identity(), "--property=KillMode=control-group",
                "--property=MemoryMax=768M", "--property=CPUQuota=100%", "--property=TasksMax=128",
                "--property=NoNewPrivileges=yes", "--property=LimitFSIZE=536870912",
                "--property=RuntimeMaxSec=" + ("28800" if terminal else str(service_seconds)), "--property=TimeoutStopSec=2", "--", *command],
                stdin=None if terminal else subprocess.PIPE, stdout=None if terminal else subprocess.PIPE,
                stderr=None if terminal else (stderr or subprocess.PIPE), text=stderr is None)
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
        result = run(manager("systemctl") + ["show", unit, "-p", "ActiveState", "-p", "ControlGroup", "-p", "LoadState"])
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
        run(manager("systemctl") + ["stop", unit])
        return self.state(unit)

    def reconcile(self):
        outcomes = []
        with self.store.locked() as db:
            rows = db.execute("""SELECT w.unit FROM workloads w
                JOIN projects p ON p.id=w.project JOIN sessions s ON s.id=w.session
                WHERE (p.stopped=1 OR s.closed=1) AND w.stopped=0""").fetchall()
            for row in rows:
                state = self.terminate(row["unit"])
                if state["confirmed_stopped"]:
                    db.execute("UPDATE workloads SET stopped=1 WHERE unit=?", (row["unit"],))
                outcomes.append({"unit": row["unit"], **state})
        return outcomes
