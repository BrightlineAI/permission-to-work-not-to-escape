import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

from ptw.policy import Invalid, approve, compile_policy, digest, load
from ptw.sample import create
from ptw.store import Store
from ptw.supervisor import Supervisor, sandbox_command


@unittest.skipUnless(os.environ.get("PTW_LINUX_TESTS") == "1", "Explicit isolated Linux VPS opt in required")
class LinuxIntegration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ptw-linux-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        create(self.root / "project")
        self.policy = load(self.root / "project/policy.json")
        self.inv = load(self.root / "project/inventory.json")
        self.store = Store(self.root / "state")
        self.store.activate(approve(self.policy, self.inv, digest(compile_policy(self.policy, self.inv)), "test operator"))
        self.a = self.store.register("website", "frontend")
        self.b = self.store.register("website", "operations")
        self.supervisor = Supervisor(self.store)
        self.units = []
        self.addCleanup(self.cleanup_units)

    def cleanup_units(self):
        for unit in self.units:
            self.supervisor.terminate(unit)

    def sandbox(self, code, actor=None):
        command = sandbox_command(self.inv, (actor or self.a)["grants"], ["/usr/bin/python3", "-c", code])
        return subprocess.run(command, capture_output=True, text=True, timeout=15)

    def test_real_sandbox_allowed_file(self):
        result = self.sandbox("print(open('/resources/ui').read())")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Welcome", result.stdout)

    def test_real_sandbox_forbidden_read_and_write(self):
        self.assertEqual(self.sandbox("print('READY')").returncode, 0, "Negative probes need a working positive control")
        result = self.sandbox("open('/resources/customers').read()")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("SYNTHETIC_PRIVATE_CUSTOMERS", result.stdout)
        result = self.sandbox("open('/resources/notes','w').write('bad')")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((Path(self.inv["root"]) / "notes.txt").read_text(), "Change the heading to Hello.\n")

    def test_real_sandbox_hides_controller_and_outside(self):
        self.assertEqual(self.sandbox("print('READY')").returncode, 0)
        for path in [self.root / "state/state.sqlite3", self.root / "project/outside.txt"]:
            result = self.sandbox("open(" + repr(str(path)) + ").read()")
            self.assertNotEqual(result.returncode, 0)
        result = self.sandbox("open('/proc/1/root" + str(self.root / "state/state.sqlite3") + "').read()")
        self.assertNotEqual(result.returncode, 0)

    def test_real_sandbox_descendant_inherits(self):
        result = self.sandbox("import subprocess; r=subprocess.run(['/usr/bin/python3','-c',\"open('/resources/customers').read()\"]); print('CHILD_EXIT',r.returncode)")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("CHILD_EXIT 1", result.stdout)

    def test_real_sandbox_network_blocked(self):
        self.assertEqual(self.sandbox("print('READY')").returncode, 0)
        result = self.sandbox("import socket; socket.create_connection(('1.1.1.1',443),timeout=.2)")
        self.assertNotEqual(result.returncode, 0)

    def test_real_sandbox_no_inherited_secret_environment(self):
        os.environ["PTW_TEST_SECRET"] = "SYNTHETIC_ONLY"
        try:
            result = self.sandbox("import os; assert 'PTW_TEST_SECRET' not in os.environ")
        finally:
            del os.environ["PTW_TEST_SECRET"]
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_stopping_multiple_parents_and_delegate(self):
        child = self.store.register("website", "frontend", parent_token=self.a["token"])
        other_policy = copy.deepcopy(self.policy)
        other_policy["project"]["id"] = "unrelated"
        self.store.activate(approve(other_policy, self.inv, digest(compile_policy(other_policy, self.inv)), "test operator"))
        other = self.store.register("unrelated", "operations")
        # Each service has an actual grandchild in a new session. No PID-only stop.
        for actor, marker, resource in [(self.a, "PARENT_A", "ui"), (self.b, "PARENT_B", "ops"),
                                        (child, "DELEGATE", "ui"), (other, "UNRELATED", "ops")]:
            writer = ("import os,time; os.setsid(); "
                      "f=open('/resources/" + resource + "','a',buffering=1)\n"
                      "for _ in range(1200): f.write(" + repr(marker + "\n") + "); time.sleep(.02)")
            code = "import subprocess,time; subprocess.Popen(['/usr/bin/python3','-c'," + repr(writer) + "]); time.sleep(120)"
            self.units.append(self.supervisor.launch(actor["token"], ["/usr/bin/python3", "-c", code]))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            text = (Path(self.inv["root"]) / "ui.txt").read_text() + (Path(self.inv["root"]) / "ops.txt").read_text()
            if all(marker in text for marker in ["PARENT_A", "PARENT_B", "DELEGATE", "UNRELATED"]):
                break
            time.sleep(.02)
        self.assertTrue(all(not self.supervisor.state(unit)["confirmed_stopped"] for unit in self.units))
        request = {"action": "read", "resource": "customers", "content": ""}
        first = self.store.request(self.a["token"], "first", request)
        self.assertEqual(first["level"], "warn")
        self.assertTrue(all(not self.supervisor.state(unit)["confirmed_stopped"] for unit in self.units))
        self.store.request(child["token"], "second", request)
        final = self.store.request(self.b["token"], "third", request)
        self.assertEqual(final["level"], "stop")
        self.assertTrue(all(self.supervisor.state(unit)["confirmed_stopped"] for unit in self.units[:3]), final)
        self.assertFalse(self.supervisor.state(self.units[3])["confirmed_stopped"])
        def counts():
            text = (Path(self.inv["root"]) / "ui.txt").read_text() + (Path(self.inv["root"]) / "ops.txt").read_text()
            return {marker: text.count(marker) for marker in ["PARENT_A", "PARENT_B", "DELEGATE", "UNRELATED"]}
        before = counts()
        self.assertTrue(all(value > 0 for value in before.values()), before)
        time.sleep(.2)
        after = counts()
        for marker in ["PARENT_A", "PARENT_B", "DELEGATE"]:
            self.assertEqual(before[marker], after[marker], "Stopped project still caused file effects")
        self.assertGreater(after["UNRELATED"], before["UNRELATED"])
        with self.assertRaises(Invalid):
            self.supervisor.launch(self.a["token"], ["/usr/bin/true"])
        self.assertTrue(self.store.request(other["token"], "still-works", {"action": "read", "resource": "ops", "content": ""})["allowed"])

    def test_supervised_replaced_resource_fails_closed(self):
        target = Path(self.inv["root"]) / "ui.txt"
        target.unlink()
        target.symlink_to("customers.txt")
        unit = self.supervisor.launch(self.a["token"], ["/usr/bin/python3", "-c", "open('/resources/ui','w').write('BAD')"])
        self.units.append(unit)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not self.supervisor.state(unit)["confirmed_stopped"]:
            time.sleep(.02)
        self.assertTrue(self.supervisor.state(unit)["confirmed_stopped"])
        self.assertEqual((Path(self.inv["root"]) / "customers.txt").read_text(), "SYNTHETIC_PRIVATE_CUSTOMERS\n")


if __name__ == "__main__":
    unittest.main()
