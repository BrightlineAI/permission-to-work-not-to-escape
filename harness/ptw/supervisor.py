"""Reuse Linux namespaces, nono and systemd instead of implementing a sandbox."""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import time

from .policy import Invalid, digest, scope


RUNTIME_HOST_PATHS = ("/usr", "/bin", "/lib", "/lib64", "/sbin")


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
               "--ro-bind", RUNTIME_HOST_PATHS[0], RUNTIME_HOST_PATHS[0]]
    for path in RUNTIME_HOST_PATHS[1:]:
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

    @contextmanager
    def admission(self, db, actor, unit, command):
        """A short locked intent covers creation of each actual native unit."""
        event = 'workload_launch:' + unit
        self.store.lifecycle(db, actor['project'], 'workload_launch', session=actor['id'],
                             event=event, facts={'unit': unit, 'command_sha256': digest(command)}, pending=True)
        try:
            yield
            self.store.complete(db, 'controller:' + actor['project'], event,
                                {'allowed': True, 'level': 'allow', 'effect': 'workload_started', 'unit': unit})
        except BaseException:
            # A failed completion may follow a successful launch. Preserve the
            # pending intent and stop the unit; recovery must not relaunch it.
            try:
                self.terminate(unit)
            finally:
                self.store.capture_fault(db, actor['project'])
            raise

    def launch(self, token, argv, package_set=None):
        """Operator API for local workloads, not an unrestricted model tool."""
        if package_set:
            from .reassessment import refresh
            refresh(self.store, token, package_set)
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
            if package_set:
                db.execute('INSERT INTO workload_packages VALUES(?,?)', (unit, package_set))
            with self.admission(db, actor, unit, command):
                result = run(manager("systemd-run") + ["--quiet", "--collect", "--unit=" + unit, *service_identity(),
                              "--property=KillMode=control-group", "--property=NoNewPrivileges=yes",
                              "--property=ProtectControlGroups=yes",
                              "--property=MemoryMax=256M", "--property=CPUQuota=50%", "--property=TasksMax=64",
                              "--property=RuntimeMaxSec=300", "--property=TimeoutStopSec=2", "--", *command])
                if result.returncode:
                    raise Invalid("Sandbox launch failed: " + result.stderr[:500])
            return unit

    def engine(self, token, command, *, stderr=None, terminal=False, service_seconds=200, preparation=False, binding=None):
        """Trusted adapter only: start a fixed model runtime or confined build.

        Native tool permissions are fixed by codex.generate. The model cannot call
        this API, choose flags or gain a general host command tool.
        """
        if not isinstance(service_seconds, int) or not 1 <= service_seconds <= 28800:
            raise Invalid("Trusted service lifetime must be 1 to 28800 seconds")
        with self.store.locked() as db:
            actor = self.store.session(db, token, preparation=preparation)
            if preparation and terminal:
                raise Invalid('Preparation cannot start an interactive runtime')
            project, _ = self.store.project(db, actor["project"])
            if project["stopped"]:
                raise Invalid("Project stopped")
            from .reassessment import validate_binding, bind_workload
            validate_binding(self.store, db, actor, binding)
            unit = "ptw-" + secrets.token_hex(12) + ".service"
            db.execute("INSERT INTO workloads(unit,project,session) VALUES(?,?,?)", (unit, actor["project"], actor["id"]))
            bind_workload(db, unit, binding)
            with self.admission(db, actor, unit, command):
                process = subprocess.Popen(manager("systemd-run") + ["--quiet", "--collect", "--pty" if terminal else "--pipe", "--wait", "--unit=" + unit,
                    *service_identity(), "--property=KillMode=control-group",
                    "--property=MemoryMax=768M", "--property=CPUQuota=100%", "--property=TasksMax=128",
                    "--property=NoNewPrivileges=yes", "--property=LimitFSIZE=536870912",
                    "--property=RuntimeMaxSec=" + ("28800" if terminal else str(service_seconds)), "--property=TimeoutStopSec=2", "--", *command],
                    stdin=None if terminal else subprocess.PIPE, stdout=None if terminal else subprocess.PIPE,
                    stderr=None if terminal else (stderr or subprocess.PIPE), text=stderr is None)
                # Hold admission until systemd creates the unit so a concurrent
                # stop cannot miss a launch still in flight.
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

    def background(self, token, command, *, service_seconds, binding=None):
        """Trusted bounded preview worker; all descendants share its cgroup."""
        if type(service_seconds) is not int or not 1 <= service_seconds <= 3620:
            raise Invalid('Preview service lifetime outside bounds')
        with self.store.locked() as db:
            actor = self.store.session(db, token)
            project, _ = self.store.project(db, actor['project'])
            if project['stopped']:
                raise Invalid('Project stopped')
            from .reassessment import validate_binding, bind_workload
            validate_binding(self.store, db, actor, binding)
            unit = 'ptw-' + secrets.token_hex(12) + '.service'
            db.execute('INSERT INTO workloads(unit,project,session) VALUES(?,?,?)',
                       (unit, actor['project'], actor['id']))
            bind_workload(db, unit, binding)
            with self.admission(db, actor, unit, command):
                try:
                    result = run(manager('systemd-run') + ['--quiet', '--collect', '--unit=' + unit,
                        *service_identity(), '--property=KillMode=control-group',
                        '--property=NoNewPrivileges=yes', '--property=ProtectControlGroups=yes',
                        '--property=MemoryMax=768M', '--property=CPUQuota=100%', '--property=TasksMax=128',
                        '--property=LimitFSIZE=536870912', '--property=StandardOutput=null',
                        '--property=StandardError=null', '--property=RuntimeMaxSec=' + str(service_seconds),
                        '--property=TimeoutStopSec=2', '--', *command])
                except (OSError, subprocess.SubprocessError) as exc:
                    raise Invalid('Preview supervisor launch interrupted') from exc
                if result.returncode:
                    raise Invalid('Preview supervisor launch failed')
            return unit

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

    def terminate(self, unit, *, db=None):
        if isinstance(unit, str) and unit.startswith('ptw-native-'):
            from .linuxarena_lifecycle import terminate
            if db is not None:
                return terminate(db, unit)
            with self.store.locked() as connection:
                return terminate(connection, unit)
        self.state(unit)  # Validate the exact target before any mutation.
        run(manager("systemctl") + ["stop", unit])
        return self.state(unit)

    def observe(self, unit):
        """Observe registered native work using protected controller identity.

        Keep the existing static systemd state API for its original callers.
        Container identities cannot be reconstructed from a unit name alone.
        """
        if isinstance(unit, str) and unit.startswith('ptw-native-'):
            from .linuxarena_lifecycle import state
            with self.store.locked() as db:
                return state(db, unit)
        return self.state(unit)

    def terminate_recorded(self, unit, *, db=None, reduce_on_failure=True):
        """Reduce authority first, then retain the same observation as reconcile.

        A capture fault must not prevent the physical attempt or claim durable
        closure. The raw terminate method remains available to fault recovery.
        """
        try:
            state = self.terminate(unit, db=db) if unit.startswith('ptw-native-') else self.terminate(unit)
        except (Invalid, OSError, sqlite3.Error, subprocess.SubprocessError):
            state = {'confirmed_stopped': False, 'error': 'Supervisor termination unavailable'}
        if db is not None:
            return self._record_termination(db, unit, state, reduce_on_failure)
        try:
            with self.store.locked() as connection:
                return self._record_termination(connection, unit, state, reduce_on_failure)
        except (OSError, sqlite3.Error):
            return {**state, 'evidence': 'unavailable'}

    def _record_termination(self, db, unit, state, reduce_on_failure):
        row = db.execute('SELECT unit,project,session FROM workloads WHERE unit=?', (unit,)).fetchone()
        if row is None:
            return {**state, 'evidence': 'unavailable'}
        try:
            db.execute('BEGIN IMMEDIATE')
            event = 'workload_termination:' + unit + ':' + str(state['confirmed_stopped'])
            if not db.execute('SELECT 1 FROM events WHERE session=? AND event=?',
                              ('controller:' + row['project'], event)).fetchone():
                if db.execute("SELECT 1 FROM workload_packages wp JOIN package_sets ps ON ps.id=wp.package_set "
                              "WHERE wp.unit=? AND ps.assessment_state='quarantined'", (unit,)).fetchone():
                    from .policy import canonical
                    db.execute('INSERT INTO package_terminations VALUES(?,?,?)',
                               (unit, time.time(), canonical(state)))
                captured = self.store.lifecycle(db, row['project'], 'workload_termination',
                    session=row['session'], event=event, facts={'unit': unit}, reduction=True,
                    response={'allowed': True, 'level': 'allow', 'effect': 'termination',
                              'unit': unit, 'confirmed_stopped': state['confirmed_stopped']})
                if not captured:
                    raise sqlite3.OperationalError('Required termination capture unavailable')
            if state['confirmed_stopped']:
                db.execute('UPDATE workloads SET stopped=1 WHERE unit=?', (unit,))
            db.commit()
            if reduce_on_failure and not state['confirmed_stopped']:
                self.store.stop_from_db(db, row['project'], 'Workload termination uncertain')
            return {**state, 'evidence': 'recorded'}
        except (OSError, sqlite3.Error):
            db.rollback()
            if reduce_on_failure:
                self.store.capture_fault(db, row['project'])
            return {**state, 'evidence': 'unavailable'}

    def reconcile(self):
        outcomes = []
        with self.store.locked() as db:
            closing = self.store.closing_sessions(db)
            if closing:
                try:
                    db.execute('BEGIN IMMEDIATE')
                    db.executemany('UPDATE sessions SET closed=1 WHERE id=?', [(sid,) for sid in closing])
                    db.commit()
                except (OSError, sqlite3.Error):
                    db.rollback()  # Intent still rejects admission; stop anyway.
            rows = db.execute("""SELECT w.unit,w.project,w.session FROM workloads w
                JOIN projects p ON p.id=w.project JOIN sessions s ON s.id=w.session
                WHERE (p.stopped=1 OR s.closed=1 OR s.id IN (SELECT value FROM json_each(?)) OR EXISTS (
                    SELECT 1 FROM workload_packages wp JOIN package_sets ps ON ps.id=wp.package_set
                    WHERE wp.unit=w.unit AND ps.assessment_state='quarantined')) AND w.stopped=0""",
                    (json.dumps(closing),)).fetchall()
            for row in rows:
                # Reconciliation already targets revoked authority. Do not
                # widen a closed session or quarantined set into a project stop.
                state = self.terminate_recorded(row['unit'], db=db, reduce_on_failure=False)
                outcomes.append({"unit": row["unit"], **state})
        return outcomes
