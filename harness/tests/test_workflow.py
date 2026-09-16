import copy
from unittest.mock import patch

from test_workspace import WorkspaceFixture
from ptw.policy import Invalid, load, save
from ptw.workflow import drive, prepare
from ptw.workspace import request


class WorkflowTests(WorkspaceFixture):
    def test_operator_scope_failure_is_repaired_or_rejected_before_approval(self):
        draft = copy.deepcopy(self.policy)
        mapping = {"dist": "r1", "private": "r2", "dependencies": "r3", "src": "r4", "tests": "r5"}
        catalog = copy.deepcopy(draft["project"]["commands"])
        for command in catalog:
            command["resources"] = [self.inv["resources"][r]["path"] for r in command["resources"]]
        save(self.root / "commands.json", catalog)
        for layer in [draft["project"], *draft["tasks"]]:
            for grant in layer["grants"]:
                grant["resource"] = mapping[grant["resource"]]
        for command in draft["project"]["commands"]:
            command["resources"] = [mapping[r] for r in command["resources"]]
        def operator_scope(policy, inventory):
            raise Invalid("Operator scope requires a read-only verification task")
        with patch("ptw.codex.generate", return_value=(draft, {"test_double": True})) as generate, self.assertRaises(Invalid):
            prepare(self.inv["root"], "Read-only verification", self.root / "scoped-review",
                    commands=self.root / "commands.json",
                    requirements=self.root / "example/repo/requirements.txt",
                    validate_proposal=operator_scope)
        self.assertEqual(generate.call_count, 3)
        self.assertTrue(all("read-only verification" in r["error"]
                            for r in load(self.root / "scoped-review/attempts.json")))
        self.assertFalse((self.root / "scoped-review/draft.json").exists())

    def test_nested_model_loop_shares_budget_and_records_actual_effects(self):
        proposals = [request("delegate", "readcheck", content="Read the calculator"),
                     request("read", "src", "calculator.py"),
                     request("finish", content="Read complete"),
                     request("finish", content="Delegate completed")]
        with patch("ptw.codex.generate", side_effect=[(p, {"test_double": True}) for p in proposals]), \
                patch("ptw.monitor.health", return_value={"healthy": True}):
            result = drive(self.store, self.actor, "Delegate read", max_steps=4)
        self.assertEqual(result["remaining_shared_steps"], 0)
        self.assertEqual(result["outcome"], "model_finished")
        self.assertEqual(len(result["delegates"]), 1)
        self.assertEqual(result["delegates"][0]["steps"][0]["result"]["content"], "def add(a, b):\n    return a - b\n")
        self.assertNotIn("token", str(result))
        self.assertFalse(result["completion_verified"])

    def test_monitor_failure_starts_no_model_calls(self):
        with patch("ptw.codex.generate") as generate, patch("ptw.monitor.health", return_value={"healthy": False}):
            result = drive(self.store, self.actor, "Read")
        generate.assert_not_called()
        self.assertEqual(result["outcome"], "monitor_unavailable")

    def test_budget_applies_to_child(self):
        proposals = [request("delegate", "readcheck", content="Read"), request("read", "src", "calculator.py")]
        with patch("ptw.codex.generate", side_effect=[(p, {"test_double": True}) for p in proposals]) as generate, \
                patch("ptw.monitor.health", return_value={"healthy": True}):
            result = drive(self.store, self.actor, "Delegate read", max_steps=2)
        self.assertEqual(generate.call_count, 2)
        self.assertEqual(result["remaining_shared_steps"], 0)
        self.assertEqual(result["outcome"], "step_limit")

    def test_proposer_cannot_invent_command_candidates(self):
        # IDs match prepare's sorted inventory. The proposal is structurally valid
        # but introduces a command the operator did not supply.
        draft = copy.deepcopy(self.policy)
        mapping = {"dist": "r1", "private": "r2", "dependencies": "r3", "src": "r4", "tests": "r5"}
        for layer in [draft["project"], *draft["tasks"]]:
            for grant in layer["grants"]:
                grant["resource"] = mapping[grant["resource"]]
        for command in draft["project"]["commands"]:
            command["resources"] = [mapping[r] for r in command["resources"]]
        with patch("ptw.codex.generate", return_value=(draft, {"test_double": True})), self.assertRaises(Invalid):
            prepare(self.inv["root"], "Read only", self.root / "review",
                    requirements=self.root / "example/repo/requirements.txt")
        records = load(self.root / "review/attempts.json")
        self.assertEqual(len(records), 3)
        self.assertTrue(all("outside operator candidates" in r["error"] for r in records))
