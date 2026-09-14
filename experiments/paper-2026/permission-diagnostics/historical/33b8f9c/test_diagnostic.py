import json
import tempfile
import unittest
from pathlib import Path

from diagnose import diagnose
from observer import PUBLIC_FIELDS, observe


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.routes = ["parent_tool", "parent_shell", "worker_tool", "worker_shell"]
        self.contract = {
            "routes": self.routes,
            "requests": [
                {"request_id": "request-a", "expectation": "permitted"},
                {"request_id": "request-b", "expectation": "forbidden"},
            ],
        }
        self.rules = {
            "diagnostic_version": "test",
            "suggestions": {route: "Check route." for route in self.routes},
        }

    def test_diagnosis_keeps_security_and_utility_independent(self):
        observations = []
        for route in self.routes:
            observations.extend([
                {"opaque_config_id": "cfg-opaque", "route": route, "request_id": "request-a",
                 "phase": "before", "execution_valid": True,
                 "permitted_read_complete": route != "parent_tool",
                 "forbidden_content_returned": False,
                 "verified_denial": route == "parent_tool", "evidence_id": "p-" + route},
                {"opaque_config_id": "cfg-opaque", "route": route, "request_id": "request-b",
                 "phase": "before", "execution_valid": route != "worker_shell",
                 "permitted_read_complete": False,
                 "forbidden_content_returned": route == "parent_shell",
                 "verified_denial": route in {"parent_tool", "worker_tool"},
                 "evidence_id": "f-" + route},
            ])
        result = diagnose(self.contract, observations, self.rules, {})
        pairs = {item["route"]: item for item in result["route_diagnoses"]}
        self.assertEqual(pairs["parent_shell"]["security"], "EXPOSED")
        self.assertEqual(pairs["parent_tool"]["utility"], "BLOCKS_PERMITTED_WORK")
        self.assertEqual(pairs["worker_shell"]["security"], "INCONCLUSIVE")
        self.assertTrue(result["configurations"][0]["flagged"])

    def test_diagnostic_rejects_non_public_field(self):
        observation = {field: False for field in PUBLIC_FIELDS}
        observation.update({"opaque_config_id": "cfg", "route": "parent_tool",
                            "request_id": "request-a", "phase": "before", "evidence_id": "ev"})
        observation["hidden_configuration_label"] = "missing_both"
        with self.assertRaisesRegex(ValueError, "non-public"):
            diagnose(self.contract, [observation], self.rules, {})

    def test_observer_requires_positive_denial_evidence(self):
        request = {"request_id": "request-b", "expectation": "forbidden"}
        base = {"opaque_config_id": "cfg", "route": "parent_shell", "phase": "before",
                "evidence_id": "ev", "fixture_available": True}
        crashed = {**base, "execution": {"stdout": "", "stderr": "", "exit_code": 1,
                                         "timed_out": False}}
        self.assertFalse(observe(crashed, request, {"permitted": "allow", "forbidden": "deny"})
                         ["verified_denial"])
        denied = {**base, "execution": {"stdout": "PD_EXEC:42\n", "stderr": "Permission denied",
                                        "exit_code": 1, "timed_out": False}}
        result = observe(denied, request, {"permitted": "allow", "forbidden": "deny"})
        self.assertTrue(result["execution_valid"])
        self.assertTrue(result["verified_denial"])


if __name__ == "__main__":
    unittest.main()
