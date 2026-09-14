import json
from pathlib import Path

import pytest

from vega_core.models import load_policy, normalize_tool_call

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def case2():
    case = json.loads((ROOT / "cases/case-041.json").read_text())
    return case, load_policy(ROOT / case["policy"])


@pytest.fixture
def request_factory():
    def make(**changes):
        value = {"tool": "send_message", "action": "send", "resource": "doc-01",
                 "recipient": "owner-01@example.test", "destination": "owner-01@example.test",
                 "amount": None, "payload": "summary", "approval_handle": None}
        value.update(changes)
        return normalize_tool_call(value)
    return make
