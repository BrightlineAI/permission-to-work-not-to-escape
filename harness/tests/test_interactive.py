import asyncio
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from ptw.mcp_server import Adapter, server
from ptw.onboarding import candidates, data, detect, private_directory, resolve_npm, review_text
from ptw.policy import Invalid, load, save
from test_workspace import WorkspaceFixture


class AdapterTests(WorkspaceFixture):
    def setUp(self):
        super().setUp()
        self.session_path = self.root / "session.json"
        save(self.session_path, self.actor)
        self.adapter = Adapter(self.store.directory, self.session_path)
        self.healthy = patch("ptw.mcp_server.health", return_value={"healthy": True})
        self.healthy.start()
        self.addCleanup(self.healthy.stop)

    def test_context_has_no_session_credential(self):
        context = self.adapter.context()
        self.assertNotIn(self.actor["token"], json.dumps(context))
        self.assertEqual(context["project"], "python-demo")
        self.assertNotIn("token", context)

    def test_file_effect_and_compare_and_swap(self):
        result = self.adapter.action("read", "read", "src", "calculator.py")
        changed = self.adapter.action("write", "write", "src", "calculator.py",
                                      content="VALUE = 42\n", expected=result["sha256"])
        self.assertTrue(changed["allowed"])
        self.assertEqual((Path(self.inv["root"]) / "src/calculator.py").read_text(), "VALUE = 42\n")
        conflict = self.adapter.action("stale", "write", "src", "calculator.py",
                                      content="stale", expected=result["sha256"])
        self.assertEqual(conflict["level"], "conflict")
        self.assertEqual(self.store.status("python-demo")["violations"], 0)

    def test_session_labels_cannot_expand_token_scope(self):
        child = self.store.register("python-demo", "readcheck", parent_token=self.actor["token"])
        tampered = {**self.actor, "token": child["token"]}
        self.session_path.write_text(json.dumps(tampered))
        adapter = Adapter(self.store.directory, self.session_path)
        self.assertEqual(adapter.session["task"], "readcheck")
        result = adapter.action(1, "write", "src", "calculator.py", content="bad")
        self.assertFalse(result["allowed"])

    def test_replayed_denial_counts_once(self):
        self.assertFalse(self.adapter.action(1, "read", "private", "customer.txt")["allowed"])
        self.assertTrue(self.adapter.action(1, "read", "private", "customer.txt")["replayed"])
        self.assertEqual(self.store.status("python-demo")["violations"], 1)

    def test_distinct_reconnect_keeps_shared_history(self):
        self.adapter.action(1, "read", "private", "customer.txt")
        second = Adapter(self.store.directory, self.session_path)
        second.action(1, "read", "private", "customer.txt")
        self.assertEqual(self.store.status("python-demo")["violations"], 2)

    def test_stopped_project_never_returns_context(self):
        self.store.stop("python-demo")
        with self.assertRaises(Invalid):
            self.adapter.context()
        with self.assertRaises(Invalid):
            self.adapter.action(1, "read", "src", "calculator.py")

    def test_monitor_loss_fails_closed(self):
        with patch("ptw.mcp_server.health", return_value={"healthy": False}), self.assertRaises(Invalid):
            self.adapter.action(1, "read", "src", "calculator.py")

    def test_delegate_registered_before_running(self):
        with patch("ptw.workflow.drive", return_value={"outcome": "model_finished", "steps": []}) as drive:
            result = self.adapter.action(1, "delegate", "readcheck", content="Read the calculator")
        self.assertTrue(result["allowed"])
        child = drive.call_args.args[1]
        self.assertEqual(child["task"], "readcheck")
        self.assertNotIn(child["token"], json.dumps(result))
        self.assertEqual(self.store.status("python-demo")["sessions"][-1]["parent"], self.actor["session"])

    def test_budget_and_body_bounds(self):
        self.adapter.delegates = 8
        with self.assertRaises(Invalid):
            self.adapter.action(1, "delegate", "readcheck")
        with self.assertRaises(Invalid):
            self.adapter.action(2, "create", "src", "large", content="x" * (8 * 1024 * 1024 + 1))

    def test_quit_revokes_children_but_not_another_parent(self):
        other = self.store.register("python-demo", "implementation")
        child = self.store.register("python-demo", "readcheck", parent_token=self.actor["token"])
        self.store.close_session(self.actor["token"])
        self.store.close_session(self.actor["token"])  # idempotent cleanup
        with self.store.locked() as db:
            self.assertEqual(self.store.session(db, other["token"])["closed"], 0)
            for token in (self.actor["token"], child["token"]):
                with self.assertRaises(Invalid):
                    self.store.session(db, token)
        with self.assertRaises(Invalid):
            self.store.register("python-demo", "readcheck", parent_token=self.actor["token"])
        self.assertFalse(self.store.status("python-demo")["stopped"])
        with self.assertRaises(Invalid):
            self.adapter.context()


class OnboardingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()

    def test_plain_javascript_needs_no_package_install(self):
        save(self.repo / "package.json", {"name": "plain", "scripts": {"test": "node --test"}})
        self.assertEqual(detect(self.repo), "javascript")
        with patch("subprocess.run") as run:
            self.assertIsNone(resolve_npm(self.repo, self.root))
        run.assert_not_called()

    def test_empty_npm_lock_needs_no_package_install(self):
        save(self.repo / "package.json", {"name": "plain"})
        save(self.repo / "package-lock.json", {"lockfileVersion": 3, "packages": {"": {"name": "plain"}}})
        self.assertIsNone(resolve_npm(self.repo, self.root))

    def test_npm_workspaces_not_silently_accepted(self):
        save(self.repo / "package.json", {"name": "plain", "workspaces": ["packages/*"]})
        with self.assertRaises(Invalid):
            resolve_npm(self.repo, self.root)

    def test_npm_external_sources_blocked_before_execution(self):
        for spec in ("git+https://example.invalid/project", "file:../outside", "https://example.invalid/tar"):
            (self.repo / "package.json").write_text(json.dumps({"dependencies": {"bad": spec}}))
            with patch("subprocess.run") as run, self.assertRaises(Invalid):
                resolve_npm(self.repo, self.root)
            run.assert_not_called()

    def test_metadata_symlink_not_read(self):
        (self.root / "outside").write_text("secret")
        (self.repo / "package.json").symlink_to(self.root / "outside")
        with self.assertRaises(Invalid):
            data(self.repo / "package.json")

    def test_state_not_inside_repository(self):
        with patch.dict(os.environ, {"PTW_USER_STATE": str(self.repo / "state")}), self.assertRaises(Invalid):
            private_directory(self.repo)

    def test_state_path_stable_and_private(self):
        with patch.dict(os.environ, {"PTW_USER_STATE": str(self.root / "state")}):
            first = private_directory(self.repo)
            self.assertEqual(first, private_directory(self.repo))
            self.assertEqual(first.stat().st_mode & 0o777, 0o700)

    def test_candidates_do_not_execute_package_scripts(self):
        save(self.repo / "package.json", {"scripts": {"test": "arbitrary reviewed script", "postinstall": "bad"}})
        with patch("subprocess.run") as run:
            commands = candidates(self.repo, "javascript", ["src"], ["package.json"])
        run.assert_not_called()
        self.assertEqual([c["id"] for c in commands], ["test"])
        self.assertIn("--ignore-scripts", commands[0]["argv"])


@unittest.skipUnless(os.environ.get("PTW_LINUX_TESTS") == "1", "real Linux user manager required")
class ProtocolTests(WorkspaceFixture):
    def test_real_sdk_stdio_bridge_positive_and_negative(self):
        from ptw.monitor import ensure, remove
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
        ensure(self.store)
        session_path = self.root / "session.json"
        save(session_path, self.actor)

        async def exercise():
            env = {k: os.environ[k] for k in ("PATH", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS") if k in os.environ}
            params = StdioServerParameters(command=sys.executable,
                args=["-m", "ptw.mcp_server", "--state", str(self.store.directory),
                      "--session", str(session_path), "--bridge"], env=env)
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as client:
                    await client.initialize()
                    tools = await client.list_tools()
                    self.assertEqual({t.name for t in tools.tools}, {"project_context", "project_action"})
                    context = await client.call_tool("project_context", {})
                    self.assertFalse(context.is_error)
                    self.assertNotIn(self.actor["token"], str(context))
                    read_result = await client.call_tool("project_action", {
                        "action": "read", "resource": "src", "path": "calculator.py"})
                    self.assertFalse(read_result.is_error)
                    self.assertIn("return a - b", str(read_result))
                    denied = await client.call_tool("project_action", {
                        "action": "read", "resource": "private", "path": "customer.txt"})
                    self.assertFalse(denied.is_error)
                    self.assertNotIn("SYNTHETIC_CUSTOMER", str(denied))
                    self.assertEqual(self.store.status("python-demo")["violations"], 1)
        try:
            asyncio.run(exercise())
        finally:
            self.store.stop("python-demo")
            remove(self.store)
