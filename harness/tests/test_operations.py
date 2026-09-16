import os
from pathlib import Path
import subprocess
import time
import unittest

from test_workspace import WorkspaceFixture
from ptw.monitor import ensure, health, remove
from ptw.policy import Invalid, load
from ptw.workflow import change


class ChangeTests(WorkspaceFixture):
    def test_change_is_a_draft_and_does_not_mutate_active_policy(self):
        change(self.store, "python-demo", "readcheck", "src", "write", "Explicit operator change",
               self.root / "change", "next")
        draft = load(self.root / "change/draft.json")
        self.assertEqual(draft["project"]["id"], "next")
        self.assertFalse(self.store.status("python-demo")["stopped"])
        reader = self.store.register("python-demo", "readcheck")
        with self.assertRaises(Invalid):
            self.store.register("python-demo", "implementation", parent_token=reader["token"])


@unittest.skipUnless(os.environ.get("PTW_LINUX_TESTS") == "1", "Explicit isolated VPS opt in")
class MonitorTests(WorkspaceFixture):
    def tearDown(self):
        self.store.stop("python-demo")
        remove(self.store)

    def test_auto_restart_after_kill(self):
        info = ensure(self.store)
        self.assertTrue(info["healthy"])
        old = subprocess.check_output(["systemctl", "--user", "show", info["unit"], "-p", "MainPID", "--value"], text=True)
        subprocess.run(["systemctl", "--user", "kill", "--signal=KILL", info["unit"]], check=True, capture_output=True)
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            pid = subprocess.check_output(["systemctl", "--user", "show", info["unit"], "-p", "MainPID", "--value"], text=True)
            if pid.strip() not in ("", "0") and pid != old and health(self.store)["healthy"]:
                break
            time.sleep(.1)
        self.assertNotEqual(pid, old)
        self.assertTrue(health(self.store)["healthy"])

    def test_remove_requires_stopped_projects(self):
        ensure(self.store)
        with self.assertRaises(Invalid):
            remove(self.store)

    def test_recovery_is_automatic_without_a_new_client(self):
        from ptw.policy import digest
        ensure(self.store)
        with self.store.locked() as db:
            db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?)",
                       (self.actor["session"], "interrupted", digest({}), "{}", None, "pending", time.time()))
        # status does not construct another Store; only the monitor detects intent.
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and not self.store.status("python-demo")["stopped"]:
            time.sleep(.1)
        self.assertTrue(self.store.status("python-demo")["stopped"])
        self.assertEqual(self.store.audit_events("python-demo")[-1]["state"], "uncertain")
