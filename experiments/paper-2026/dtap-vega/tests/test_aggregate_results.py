from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from aggregate_results import _find_judges, _generation_metrics


class AggregateResultTests(unittest.TestCase):
    def test_source_selector_locates_judge_not_underlying_task_id(self) -> None:
        selector = {
            "domain": "os-filesystem",
            "type": "malicious",
            "threat_model": "indirect",
            "risk_category": "source-risk",
            "task_id": 5,
        }
        source = Path("results/benchmark/agent/model/os-filesystem/malicious/indirect/source-risk/5/judge_result.json")
        misleading = Path("results/benchmark/agent/model/os-filesystem/malicious/indirect/utility-risk/7/judge_result.json")
        self.assertEqual(_find_judges([source, misleading], "utility-risk-007", selector), [source])

    def test_failed_generation_accounts_for_completed_response(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "direct-e-generation"
            capture = root / "captures" / "case"
            policy = root / "policies"
            capture.mkdir(parents=True)
            policy.mkdir()
            (policy / "prior.json").write_text("{}")
            (capture / "response.json").write_text(json.dumps({
                "model": "qwen/qwen3-14b", "provider": "provider",
                "usage": {
                    "prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30,
                    "cost": 0.01, "completion_tokens_details": {"reasoning_tokens": 4},
                },
            }))
            (root / "generation-error.json").write_text(json.dumps({
                "mode": "direct_e", "failed_closed": True,
                "error_type": "ValueError", "error": "invalid",
            }))
            result = _generation_metrics(Path(tmp), "direct-e-generation")
            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result["llm_calls"], 1)
            self.assertEqual(result["valid_policy_outputs"], 1)
            self.assertFalse(result["generation_valid"])
            self.assertEqual(result["prompt_tokens"], 10)
            self.assertEqual(result["completion_tokens"], 20)
            self.assertEqual(result["reasoning_tokens"], 4)
            self.assertEqual(result["reported_cost_usd"], 0.01)
            self.assertIsNone(result["wall_seconds"])


if __name__ == "__main__":
    unittest.main()
