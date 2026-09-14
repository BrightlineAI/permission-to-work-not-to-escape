from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from common import DEV10_SHA256, sha256_file
from compile_requirements import canonical_scope, compile_requirements, validate_policy
from select_blind_holdout import select


class CompilerTests(unittest.TestCase):
    def test_frozen_development_hash(self) -> None:
        self.assertEqual(sha256_file(ROOT / "frozen" / "dev10.jsonl"), DEV10_SHA256)

    def test_sealed_holdout_hash_without_parsing(self) -> None:
        # Integrity only: development tests must never parse holdout records.
        self.assertEqual(
            sha256_file(ROOT / "frozen" / "holdout50.jsonl"),
            "4f78cf08db72863c162b3d75b50c425cba7e866eb2830274f18b7eea3d9c1483",
        )

    def test_blind_selection_is_deterministic_and_opaque(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.jsonl"
            source.write_bytes(b"".join(f"opaque-row-{i}\n".encode() for i in range(50)))
            expected = sha256_file(source)
            outputs = []
            for suffix in ("a", "b"):
                folder = root / suffix
                select(source, folder / "selected.jsonl", folder / "manifest.json",
                       count=10, seed="fixed-test-seed", expected_source_hash=expected)
                outputs.append((folder / "selected.jsonl").read_bytes())
                manifest = json.loads((folder / "manifest.json").read_text())
                self.assertFalse(manifest["content_decoded_during_selection"])
                self.assertEqual(manifest["selected_count"], 10)
            self.assertEqual(outputs[0], outputs[1])
            self.assertEqual(len(outputs[0].splitlines()), 10)

    def test_compile_exact_and_tree(self) -> None:
        policy = compile_requirements({"operations": [
            {"capability": "search_files", "resource_scope": "/workspace"},
            {"capability": "read_file", "resource_scope": "/workspace/**"},
        ]}, job_id="case")
        validate_policy(policy)
        self.assertEqual(policy["job_id"], "case")
        read_grants = [grant for grant in policy["allow"] if grant["actions"][0].startswith("read")]
        self.assertEqual(
            {(grant["actions"][0], tuple(grant["resources"])) for grant in read_grants},
            {("read_file", ("/workspace/**",)), ("read_multiple_files", ("/workspace/**",))},
        )

    def test_read_route_equivalence_never_widens_scope(self) -> None:
        policy = compile_requirements({"operations": [
            {"capability": "read_multiple_files", "resource_scope": "/logs/app1.log"},
            {"capability": "read_multiple_files", "resource_scope": "/logs/app2.log"},
        ]}, job_id="case")
        validate_policy(policy)
        self.assertEqual(len(policy["allow"]), 4)
        self.assertEqual(
            {tuple(grant["resources"]) for grant in policy["allow"]},
            {("/logs/app1.log",), ("/logs/app2.log",)},
        )
        self.assertEqual(
            {grant["actions"][0] for grant in policy["allow"]},
            {"read_file", "read_multiple_files"},
        )

    def test_public_schemas_accept_safe_globs_and_reject_unsafe_syntax(self) -> None:
        direct = json.loads((ROOT / "schemas" / "policy-body.schema.json").read_text())
        typed = json.loads((ROOT / "schemas" / "requirements.schema.json").read_text())
        patterns = [
            direct["properties"]["allow"]["items"]["properties"]["resources"]["items"]["pattern"],
            typed["properties"]["operations"]["items"]["properties"]["resource_scope"]["pattern"],
        ]
        for pattern in patterns:
            self.assertIsNotNone(re.fullmatch(pattern, "/workspace/file.txt"))
            self.assertIsNotNone(re.fullmatch(pattern, "/workspace/**"))
            self.assertIsNotNone(re.fullmatch(pattern, "/workspace/**/*.txt"))
            self.assertIsNone(re.fullmatch(pattern, "/workspace/file?.txt"))
            self.assertIsNone(re.fullmatch(pattern, "/workspace/[ab].txt"))

    def test_move_requires_both_scopes(self) -> None:
        with self.assertRaises(ValueError):
            compile_requirements({"operations": [
                {"capability": "move_file", "resource_scope": "/workspace/a"}
            ]}, job_id="case")

    def test_unknown_field_and_dotdot_fail_closed(self) -> None:
        with self.assertRaises(ValueError):
            compile_requirements({"operations": [{
                "capability": "read_file", "resource_scope": "/workspace/a", "surprise": True
            }]}, job_id="case")
        with self.assertRaises(ValueError):
            canonical_scope("/workspace/../etc/shadow")
        self.assertEqual(canonical_scope("/workspace/**/*.txt"), "/workspace/**/*.txt")
        self.assertEqual(canonical_scope("/workspace/*.txt"), "/workspace/*.txt")
        for invalid in ("/workspace/file?.txt", "/workspace/[ab].txt", "/workspace/ab**cd"):
            with self.assertRaises(ValueError):
                canonical_scope(invalid)
        self.assertEqual(canonical_scope("/workspace/**"), "/workspace/**")

    def test_reviewed_control_compiles(self) -> None:
        reviewed = json.loads((ROOT / "reviewed" / "dev10-requirements.json").read_text())
        self.assertEqual(len(reviewed), 10)
        for task_id, requirements in reviewed.items():
            validate_policy(compile_requirements(requirements, job_id=task_id))


if __name__ == "__main__":
    unittest.main()
