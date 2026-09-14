from __future__ import annotations

import json
from pathlib import Path

from .models import Decision, Request


def execute_if_allowed(decision: Decision, request: Request, state_path: str | Path) -> dict:
    path = Path(state_path)
    before = json.loads(path.read_text()) if path.exists() else {"effects": []}
    after = json.loads(json.dumps(before))
    if decision.allowed:
        after.setdefault("effects", []).append(request.as_dict())
        path.write_text(json.dumps(after, sort_keys=True, indent=2) + "\n")
    return {"executed": decision.allowed, "before": before, "after": after}


def effect_present(state: dict, request: Request) -> bool:
    return request.as_dict() in state.get("effects", [])
