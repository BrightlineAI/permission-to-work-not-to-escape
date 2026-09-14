#!/usr/bin/env python3
"""Local static preflight; the full runner performs live VPS enforcement probes."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vega_core.models import load_policy

policies = [load_policy(path) for path in sorted((ROOT / "policies").glob("case-*.json"))]
cases = [json.loads(path.read_text()) for path in sorted((ROOT / "cases").glob("case-*.json"))]
assert len(policies) == len(cases) == 100
assert len({policy.policy_hash for policy in policies}) == 100
subprocess.run([sys.executable, str(ROOT / "scripts/build_cases.py")], check=True)
print("static preflight passed: 100 cases, 100 distinct policy hashes")
