import copy
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ptw.policy import Invalid, approve, compile_policy, digest, load
from ptw.project_example import create
from ptw.store import Store
from ptw.workspace import Workspace, request


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ptw-workspace-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        create(self.root / "example")
        self.inv = load(self.root / "example/inventory.json")
        self.policy = load(self.root / "example/policy.json")
        self.store = Store(self.root / "state")
        self.store.activate(self.approve())
        self.actor = self.store.register("python-demo", "implementation")
        self.broker = Workspace(self.store)
        self.i = 0

    def approve(self):
        return approve(self.policy, self.inv, digest(compile_policy(self.policy, self.inv)), "fixture operator")

    def ask(self, action, resource="src", path="calculator.py", **kwargs):
        self.i += 1
        return self.broker.request(self.actor["token"], "event-" + str(self.i), request(action, resource, path, **kwargs))

    def test_read_and_atomic_write(self):
        old = self.ask("read")
        before = (Path(self.inv["root"]) / "src/calculator.py").stat().st_ino
        result = self.ask("write", content="VALUE = 42\n", expected=old["sha256"])
        self.assertTrue(result["allowed"], result)
        self.assertNotEqual(before, (Path(self.inv["root"]) / "src/calculator.py").stat().st_ino)
        self.assertEqual(self.ask("read")["content"], "VALUE = 42\n")

    def test_create_rename_delete(self):
        self.assertTrue(self.ask("create", path="new.txt", content="new")["allowed"])
        sha = self.ask("read", path="new.txt")["sha256"]
        self.assertTrue(self.ask("rename", path="new.txt", expected=sha, destination="src:moved.txt")["allowed"])
        self.assertFalse((Path(self.inv["root"]) / "src/new.txt").exists())
        self.assertTrue(self.ask("delete", path="moved.txt", expected=sha)["allowed"])

    def test_directory_lifecycle(self):
        self.assertTrue(self.ask("mkdir", path="newdir")["allowed"])
        self.assertTrue(self.ask("create", path="newdir/a.txt", content="x")["allowed"])
        self.assertEqual(self.ask("rmdir", path="newdir", expected="directory")["level"], "blocked")
        self.assertTrue(self.ask("delete", path="newdir/a.txt", expected=hashlib.sha256(b"x").hexdigest())["allowed"])
        self.assertTrue(self.ask("rmdir", path="newdir", expected="directory")["allowed"])

    def test_stale_edit_is_not_violation(self):
        old = self.ask("read")["sha256"]
        self.ask("write", content="first", expected=old)
        result = self.ask("write", content="second", expected=old)
        self.assertEqual(result["level"], "conflict")
        self.assertEqual(self.store.status("python-demo")["violations"], 0)

    def test_new_file_cannot_overwrite(self):
        self.assertEqual(self.ask("create", content="oops")["level"], "conflict")

    def test_read_only_task_cannot_write(self):
        self.actor = self.store.register("python-demo", "readcheck")
        self.assertEqual(self.ask("write", content="oops")["level"], "warn")

    def test_readonly_rename_destination(self):
        old = self.ask("read")["sha256"]
        result = self.ask("rename", expected=old, destination="tests:stolen.py")
        self.assertFalse(result["allowed"])
        self.assertTrue((Path(self.inv["root"]) / "src/calculator.py").exists())

    def test_project_root_cannot_be_deleted(self):
        result = self.ask("rmdir", resource="dist", path="", expected="directory")
        self.assertFalse(result["allowed"])

    def test_traversal(self):
        for path in ["../private/customer.txt", "/etc/passwd", "a//b", "a/./b", "a\\b"]:
            with self.subTest(path=path):
                self.assertFalse(self.ask("read", path=path)["allowed"])

    def test_symlink_and_hardlink(self):
        repo = Path(self.inv["root"])
        (repo / "src/link").symlink_to(repo / "private/customer.txt")
        result = self.ask("read", path="link")
        self.assertFalse(result["allowed"])
        self.assertNotIn("SYNTHETIC_CUSTOMER", str(result))

    def test_hardlink(self):
        repo = Path(self.inv["root"])
        os.link(repo / "private/customer.txt", repo / "src/link")
        self.assertFalse(self.ask("read", path="link")["allowed"])

    def test_same_event_returns_original(self):
        req = request("create", "src", "once.txt", "once")
        a = self.broker.request(self.actor["token"], "once", req)
        b = self.broker.request(self.actor["token"], "once", req)
        self.assertTrue(a["allowed"])
        self.assertTrue(b["replayed"])
        with self.assertRaises(Invalid):
            self.broker.request(self.actor["token"], "once", request("create", "src", "different"))

    def test_narrow_task_and_delegate_commands(self):
        with self.assertRaises(Invalid):
            self.store.register("python-demo", "readcheck", commands=["not-approved"])
        narrow = self.store.register("python-demo", "readcheck")
        with self.assertRaises(Invalid):
            self.store.register("python-demo", "implementation", parent_token=narrow["token"])

    def test_multiple_parents_and_child_share_stop(self):
        second = self.store.register("python-demo", "verification")
        child = self.store.register("python-demo", "readcheck", parent_token=self.actor["token"])
        for i, actor in enumerate([self.actor, second, child]):
            result = self.broker.request(actor["token"], "denied", request("read", "private", "customer.txt"))
            self.assertEqual(result["level"], "stop" if i == 2 else "warn")
        self.assertEqual(self.ask("read")["level"], "stop")
        with self.assertRaises(Invalid):
            self.store.register("python-demo", "implementation")

    def test_command_not_in_scope(self):
        self.assertEqual(self.ask("run", resource="unknown", path="")["level"], "warn")

    def test_invalid_policy_overlap(self):
        self.inv["resources"]["overlap"] = {"path": "src/calculator.py", "kind": "file", "description": "overlap"}
        with self.assertRaises(Invalid):
            compile_policy(self.policy, self.inv)

    def test_policy_cannot_expand_command_or_package(self):
        self.policy["tasks"][0]["commands"].append("unlisted")
        with self.assertRaises(Invalid):
            compile_policy(self.policy, self.inv)

    def test_crash_after_intent_stops_and_is_not_replayed(self):
        with patch("ptw.workspace.publish", side_effect=SystemExit("interrupted")):
            with self.assertRaises(SystemExit):
                self.ask("create", path="interrupted.txt", content="x")
        recovered = Store(self.root / "state")
        self.assertTrue(recovered.status("python-demo")["stopped"])
        self.assertFalse((Path(self.inv["root"]) / "src/interrupted.txt").exists())

    def test_failed_publication_stops(self):
        with patch("ptw.workspace.publish", side_effect=OSError("disk failure")):
            result = self.ask("create", path="failed.txt", content="x")
        self.assertEqual(result["level"], "stop")
        self.assertTrue(self.store.status("python-demo")["stopped"])


@unittest.skipUnless(os.environ.get("PTW_LINUX_TESTS") == "1", "Explicit isolated VPS opt in")
class WorkspaceLinux(WorkspaceTests):
    def add_command(self, code, resources=None):
        # New synthetic project per test; no mutation of an active policy.
        self.policy["project"]["id"] = "command-demo"
        self.policy["project"]["commands"].append({"id": "probe", "argv": ["/usr/bin/python3", "-c", code],
            "resources": resources or ["src", "tests", "dist"], "timeout_seconds": 5})
        self.policy["tasks"][0]["commands"].append("probe")
        self.store.activate(self.approve())
        self.actor = self.store.register("command-demo", "implementation")

    def test_real_command_edits_and_creates(self):
        self.add_command("from pathlib import Path; p=Path('src/calculator.py'); p.write_text('ANSWER=42\\n'); "
                         "Path('dist/output.txt').write_text('built'); print('REAL_COMMAND_OK')")
        result = self.ask("run", resource="probe", path="")
        self.assertTrue(result["allowed"], result)
        self.assertEqual(result["exit_code"], 0, result)
        self.assertIn("REAL_COMMAND_OK", result["output"])
        self.assertEqual((Path(self.inv["root"]) / "dist/output.txt").read_text(), "built")

    def test_forbidden_output_publishes_nothing(self):
        self.add_command("from pathlib import Path; Path('src/new.txt').write_text('ok'); Path('tests/forbidden.txt').write_text('no')")
        result = self.ask("run", resource="probe", path="")
        self.assertFalse(result["allowed"], result)
        self.assertFalse((Path(self.inv["root"]) / "src/new.txt").exists())
        self.assertFalse((Path(self.inv["root"]) / "tests/forbidden.txt").exists())

    def test_host_secrets_network_controller_hidden(self):
        self.add_command("import os,socket; from pathlib import Path; "
                         f"assert not Path({str(self.store.directory)!r}).exists(); "
                         "assert not Path('private/customer.txt').exists(); "
                         "assert 'PTW_SYNTHETIC_SECRET' not in os.environ; "
                         "\ntry: socket.create_connection(('1.1.1.1',443),.1)\nexcept OSError: print('BOUNDARY_OK')\nelse: raise Exception('network')")
        with patch.dict(os.environ, {"PTW_SYNTHETIC_SECRET": "PRIVATE"}):
            result = self.ask("run", resource="probe", path="")
        self.assertTrue(result["allowed"], result)
        self.assertEqual(result["exit_code"], 0, result)
        self.assertIn("BOUNDARY_OK", result["output"])

    def test_nonzero_test_exit_is_not_misconduct(self):
        self.add_command("print('EXPECTED_TEST_FAILURE'); raise SystemExit(7)")
        result = self.ask("run", resource="probe", path="")
        self.assertTrue(result["allowed"], result)
        self.assertEqual(result["exit_code"], 7)
        self.assertEqual(self.store.status("command-demo")["violations"], 0)

    def test_unknown_output_rejected(self):
        self.add_command("open('unregistered.txt','w').write('no')")
        self.assertFalse(self.ask("run", resource="probe", path="")["allowed"])

    def test_output_symlink_rejected(self):
        self.add_command("import os; os.symlink('/etc/passwd','src/leak')")
        result = self.ask("run", resource="probe", path="")
        self.assertFalse(result["allowed"], result)
        self.assertFalse((Path(self.inv["root"]) / "src/leak").exists())
