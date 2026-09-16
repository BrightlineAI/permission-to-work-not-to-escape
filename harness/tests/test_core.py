import concurrent.futures
import copy
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from ptw import audit
from ptw.policy import Invalid, approve, check_approval, compile_policy, digest, load, save
from ptw.sample import create
from ptw.store import Store


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ptw-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        create(self.root / "project")
        self.policy = load(self.root / "project/policy.json")
        self.inv = load(self.root / "project/inventory.json")
        self.bundle = self.approved()
        self.store = Store(self.root / "state")
        self.store.activate(self.bundle)
        self.a = self.store.register("website", "frontend")
        self.b = self.store.register("website", "operations")

    def approved(self):
        compiled = compile_policy(self.policy, self.inv)
        return approve(self.policy, self.inv, digest(compiled), "synthetic fixture operator")

    def request(self, resource="ui", action="read", content="", actor=None, event="e"):
        return self.store.request((actor or self.a)["token"], event,
                                  {"resource": resource, "action": action, "content": content})

    def test_read_permitted(self):
        self.assertEqual(self.request()["content"], "Welcome\n")

    def test_runtime_inventory_roots_rejected(self):
        for root in ["/", "/usr", "/usr/local/share", "/bin", "/lib", "/proc", "/sys", "/dev"]:
            with self.subTest(root=root), self.assertRaises(Invalid):
                inv = copy.deepcopy(self.inv)
                inv["root"] = root
                compile_policy(self.policy, inv)

    def test_runtime_controller_roots_rejected_before_creation(self):
        for root in ["/", "/usr/ptw-forbidden-state", "/proc/ptw-forbidden-state", "/dev/ptw-forbidden-state"]:
            with self.subTest(root=root), self.assertRaises(Invalid):
                Store(root)

    def test_write_permitted(self):
        self.assertTrue(self.request(action="write", content="Hello\n")["allowed"])
        self.assertEqual((Path(self.inv["root"]) / "ui.txt").read_text(), "Hello\n")

    def test_append_permitted(self):
        self.assertTrue(self.request("ops", "append", "added", actor=self.b)["allowed"])
        self.assertTrue((Path(self.inv["root"]) / "ops.txt").read_text().endswith("added"))

    def test_no_task_scope_expansion(self):
        self.assertFalse(self.request("ops", "write", "bad")["allowed"])

    def test_no_project_scope_expansion(self):
        self.assertEqual(self.request("customers")["level"], "warn")

    def test_unknown_resource(self):
        self.assertFalse(self.request("../../../etc/passwd")["allowed"])

    def test_unknown_action(self):
        self.assertFalse(self.request(action="execute")["allowed"])

    def test_deny_does_not_change_file(self):
        self.request("customers", "write", "BAD")
        self.assertEqual((Path(self.inv["root"]) / "customers.txt").read_text(), "SYNTHETIC_PRIVATE_CUSTOMERS\n")

    def test_foreign_credentials_do_not_count(self):
        with self.assertRaises(Invalid):
            self.store.request("x" * 50, "e", {})
        self.assertEqual(self.store.status("website")["violations"], 0)

    def test_spoofed_identity_field_rejected(self):
        response = self.store.request(self.a["token"], "e", {"resource": "ops", "action": "write", "content": "bad", "task": "operations"})
        self.assertFalse(response["allowed"])

    def test_malformed_fields(self):
        for index, request in enumerate([None, [], {"action": 42}, {"action": "read", "resource": [], "content": ""}]):
            result = self.store.request(self.a["token"], str(index), request)
            self.assertFalse(result["allowed"])

    def test_read_cannot_smuggle_write(self):
        self.assertFalse(self.request(content="smuggled")["allowed"])

    def test_large_request_denied(self):
        self.assertFalse(self.request(action="write", content="x" * 1_048_577)["allowed"])

    def test_invalid_unicode_request_denied(self):
        self.assertFalse(self.request(action="write", content="\ud800")["allowed"])

    def test_three_actors_share_stop(self):
        child = self.store.register("website", "frontend", parent_token=self.a["token"])
        self.assertEqual(self.request("customers", actor=self.a, event="a")["level"], "warn")
        self.assertEqual(self.request("customers", actor=child, event="c")["level"], "warn")
        self.assertEqual(self.request("customers", actor=self.b, event="b")["level"], "stop")
        self.assertFalse(self.request(actor=self.a, event="late")["allowed"])
        with self.assertRaises(Invalid):
            self.store.register("website", "frontend")

    def test_retry_does_not_count_twice(self):
        first = self.request("customers")
        second = self.request("customers")
        self.assertTrue(second["replayed"])
        self.assertEqual(first["project_violations"], second["project_violations"])

    def test_append_retry_does_not_repeat_effect(self):
        self.request("ops", "append", "ONCE", actor=self.b)
        self.request("ops", "append", "ONCE", actor=self.b)
        self.assertEqual((Path(self.inv["root"]) / "ops.txt").read_text().count("ONCE"), 1)

    def test_event_collision(self):
        self.request()
        with self.assertRaises(Invalid):
            self.request(action="write", content="bad")

    def test_same_event_different_actors(self):
        self.request("customers", actor=self.a)
        self.request("customers", actor=self.b)
        self.assertEqual(self.store.status("website")["violations"], 2)

    def test_restart_keeps_history(self):
        self.request("customers")
        restarted = Store(self.root / "state")
        self.assertEqual(restarted.status("website")["violations"], 1)

    def test_restart_keeps_stop(self):
        self.store.stop("website")
        self.assertTrue(Store(self.root / "state").status("website")["stopped"])

    def test_approval_cannot_reset_history(self):
        self.request("customers")
        with self.assertRaises(Invalid):
            self.store.activate(self.bundle)

    def test_narrow_delegation(self):
        child = self.store.register("website", "frontend", parent_token=self.a["token"], grants=[{"resource": "ui", "actions": ["read"]}])
        self.assertTrue(self.request(actor=child)["allowed"])
        self.assertFalse(self.request(action="write", content="bad", actor=child, event="write")["allowed"])

    def test_delegate_cannot_widen(self):
        with self.assertRaises(Invalid):
            self.store.register("website", "operations", parent_token=self.a["token"])

    def test_grandchild_cannot_regain(self):
        child = self.store.register("website", "frontend", parent_token=self.a["token"], grants=[{"resource": "ui", "actions": ["read"]}])
        with self.assertRaises(Invalid):
            self.store.register("website", "frontend", parent_token=child["token"])

    def test_unrelated_project_not_stopped(self):
        policy = copy.deepcopy(self.policy)
        policy["project"]["id"] = "unrelated"
        bundle = approve(policy, self.inv, digest(compile_policy(policy, self.inv)), "operator")
        self.store.activate(bundle)
        other = self.store.register("unrelated", "frontend")
        self.store.stop("website")
        self.assertTrue(self.request(actor=other)["allowed"])

    def test_cross_project_delegate_rejected(self):
        self.policy["project"]["id"] = "other"
        self.store.activate(self.approved())
        with self.assertRaises(Invalid):
            self.store.register("other", "frontend", parent_token=self.a["token"])

    def test_multiple_instances_concurrent_append(self):
        def append(index):
            store = Store(self.root / "state")
            return store.request(self.b["token"], str(index), {"action": "append", "resource": "ops", "content": "X"})
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(append, range(24)))
        self.assertTrue(all(r["allowed"] for r in results))
        self.assertEqual((Path(self.inv["root"]) / "ops.txt").read_text().count("X"), 24)

    def test_concurrent_denials_cannot_overrun_stop(self):
        def deny(index):
            return self.request("customers", event=str(index))
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(deny, range(24)))
        self.assertEqual(self.store.status("website")["violations"], 3)

    def test_pending_effect_recovery_stops(self):
        with self.store.locked() as db:
            db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?)", (self.a["session"], "pending", "hash", "{}", None, "pending", 0))
        restarted = Store(self.root / "state")
        self.assertTrue(restarted.status("website")["stopped"])

    def test_symlink_leaf_denied(self):
        target = Path(self.inv["root"]) / "ui.txt"
        target.unlink()
        target.symlink_to("customers.txt")
        self.assertFalse(self.request()["allowed"])
        self.assertTrue(self.store.status("website")["stopped"])

    def test_replaced_file_denied(self):
        target = Path(self.inv["root"]) / "ui.txt"
        replacement = target.with_suffix(".replacement")
        replacement.write_text("replacement")
        replacement.replace(target)
        self.assertFalse(self.request()["allowed"])

    def test_hard_link_denied(self):
        os.link(Path(self.inv["root"]) / "ui.txt", self.root / "alias")
        self.assertFalse(self.request()["allowed"])

    def test_symlink_root_denied(self):
        root = Path(self.inv["root"])
        root.rename(root.with_name("moved"))
        root.symlink_to(root.with_name("moved"))
        self.assertFalse(self.request()["allowed"])

    def test_resource_failure_not_mislabeled_attack(self):
        (Path(self.inv["root"]) / "ui.txt").unlink()
        result = self.request()
        self.assertFalse(result["allowed"])
        self.assertEqual(self.store.status("website")["violations"], 0)

    def test_scope_expansion_fails_compile(self):
        self.policy["tasks"][0]["grants"].append({"resource": "customers", "actions": ["read"]})
        with self.assertRaises(Invalid):
            compile_policy(self.policy, self.inv)

    def test_unknown_policy_field(self):
        self.policy["execute"] = "unsafe"
        with self.assertRaises(Invalid):
            compile_policy(self.policy, self.inv)

    def test_task_threshold_cannot_weaken(self):
        self.policy["tasks"][0]["escalation"] = {"warn_at": 1, "stop_at": 4}
        with self.assertRaises(Invalid):
            compile_policy(self.policy, self.inv)

    def test_threshold_order(self):
        self.policy["project"]["escalation"] = {"warn_at": 5, "stop_at": 3}
        with self.assertRaises(Invalid):
            compile_policy(self.policy, self.inv)

    def test_duplicate_task(self):
        self.policy["tasks"].append(self.policy["tasks"][0])
        with self.assertRaises(Invalid):
            compile_policy(self.policy, self.inv)

    def test_duplicate_resource_grant(self):
        self.policy["project"]["grants"].append(self.policy["project"]["grants"][0])
        with self.assertRaises(Invalid):
            compile_policy(self.policy, self.inv)

    def test_unknown_resource_compile(self):
        self.policy["project"]["grants"].append({"resource": "new", "actions": ["read"]})
        with self.assertRaises(Invalid):
            compile_policy(self.policy, self.inv)

    def test_path_traversal_rejected(self):
        self.inv["resources"]["ui"]["path"] = "../outside.txt"
        with self.assertRaises(Invalid):
            compile_policy(self.policy, self.inv)

    def test_approval_wrong_hash(self):
        with self.assertRaises(Invalid):
            approve(self.policy, self.inv, "wrong", "reviewer")

    def test_approval_mutation(self):
        self.bundle["policy"]["project"]["description"] = "changed"
        with self.assertRaises(Invalid):
            check_approval(self.bundle)

    def test_draft_not_activation(self):
        with self.assertRaises(Invalid):
            self.store.activate({"policy": self.policy, "inventory": self.inv})

    def test_private_state_required(self):
        target = self.root / "public-state"
        target.mkdir(mode=0o755)
        with self.assertRaises(Invalid):
            Store(target)

    def test_state_not_inside_resources(self):
        store = Store(Path(self.inv["root"]) / "state")
        with self.assertRaises(Invalid):
            store.activate(self.bundle)

    def test_json_duplicate_rejected(self):
        path = self.root / "dup.json"
        path.write_text("{\"version\":1,\"version\":2}")
        with self.assertRaises(Invalid):
            load(path)

    def test_save_never_overwrites(self):
        path = self.root / "saved.json"
        save(path, {})
        with self.assertRaises(FileExistsError):
            save(path, {})

    def test_audit_known_allowed_denied_unknown(self):
        result = audit.audit(self.root / "project/history.jsonl", self.policy, self.inv, "frontend")
        self.assertEqual(result["counts"], {"allowed": 1, "denied": 1, "unknown": 1})
        self.assertEqual(self.store.status("website")["violations"], 0)

    def test_audit_does_not_execute(self):
        file = self.root / "evil.jsonl"
        marker = self.root / "MUST_NOT_EXIST"
        file.write_text(json.dumps({"type": "response_item", "payload": {"type": "function_call", "name": "exec_command", "arguments": json.dumps({"cmd": "touch " + str(marker)})}}) + "\n")
        self.assertEqual(audit.audit(file, self.policy, self.inv, "frontend")["counts"]["unknown"], 1)
        self.assertFalse(marker.exists())

    def test_audit_malformed_unknown(self):
        file = self.root / "malformed.jsonl"
        file.write_text("{broken\n")
        self.assertEqual(audit.audit(file, self.policy, self.inv, "frontend")["counts"]["unknown"], 1)

    def test_audit_duplicate_fields_unknown(self):
        file = self.root / "ambiguous.jsonl"
        file.write_text('{"payload":{},"payload":{}}\n')
        self.assertEqual(audit.audit(file, self.policy, self.inv, "frontend")["counts"]["unknown"], 1)

    def test_history_is_untrusted(self):
        data = audit.history_context(self.root / "project/history.jsonl")
        self.assertIn("UNTRUSTED", data["trust"])

    def test_history_skips_native_boilerplate(self):
        file = self.root / "native.jsonl"
        file.write_text(json.dumps({"type": "session_meta", "payload": {"base_instructions": "X" * 30000}}) + "\n" +
                        json.dumps({"type": "response_item", "payload": {"type": "message", "role": "user", "content": "Important project goal"}}) + "\n")
        context = audit.history_context(file)
        self.assertIn("Important project goal", context["excerpt"])
        self.assertNotIn("XXXXX", context["excerpt"])

    def test_literal_code_mode_call(self):
        args = audit.literal_exec_arguments('const r = await tools.exec_command({cmd:"cat /tmp/a",workdir:"/tmp",yield_time_ms:10000});text(r.output);')
        self.assertEqual(args["cmd"], "cat /tmp/a")
        args = audit.literal_exec_arguments('text(await tools.exec_command({"cmd":"cat /tmp/a"}));')
        self.assertEqual(args["cmd"], "cat /tmp/a")

    def test_nonliteral_code_mode_stays_unknown(self):
        for source in ['const r = await tools.exec_command({cmd:"cat /tmp/a"+evil});text(r.output);',
                       'text(await tools.exec_command({cmd:"cat /tmp/a"}));doSomethingElse();',
                       'text(await tools.exec_command({cmd:"cat /tmp/a",cmd:"cat /tmp/b"}));',
                       'text(await tools.exec_command({cmd:secret}));']:
            with self.assertRaises(ValueError):
                audit.literal_exec_arguments(source)

    def test_event_export_has_no_contents_or_token(self):
        self.request()
        serialized = json.dumps(self.store.audit_events("website"))
        self.assertNotIn("Welcome", serialized)
        self.assertNotIn(self.a["token"], serialized)

    def test_delegate_cannot_reset_stricter_ancestor_threshold(self):
        self.policy["project"]["id"] = "stricter"
        self.policy["tasks"][0]["escalation"] = {"warn_at": 1, "stop_at": 2}
        self.policy["tasks"].append({"id": "review", "description": "Read only",
            "grants": [{"resource": "ui", "actions": ["read"]}],
            "escalation": {"warn_at": 1, "stop_at": 3}})
        self.store.activate(self.approved())
        parent = self.store.register("stricter", "frontend")
        child = self.store.register("stricter", "review", parent_token=parent["token"])
        self.assertEqual(self.request("customers", actor=child, event="1")["level"], "warn")
        self.assertEqual(self.request("customers", actor=child, event="2")["level"], "stop")
        counts = {r["task"]: r["violations"] for r in self.store.status("stricter")["tasks"]}
        self.assertEqual(counts["frontend"], 2)
        self.assertEqual(counts["review"], 2)

    def test_same_task_ancestry_counts_once(self):
        child = self.store.register("website", "frontend", parent_token=self.a["token"])
        grandchild = self.store.register("website", "frontend", parent_token=child["token"])
        self.request("customers", actor=grandchild)
        counts = {r["task"]: r["violations"] for r in self.store.status("website")["tasks"]}
        self.assertEqual(counts["frontend"], 1)


if __name__ == "__main__":
    unittest.main()
