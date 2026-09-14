#!/usr/bin/env python3
"""Small OpenRouter capture adapter. It captures once; the runner replays the action."""

from __future__ import annotations

import json
import os
import urllib.request


def capture(model: str, messages: list[dict], tools: list[dict], reasoning_effort: str = "high", timeout: int = 120) -> dict:
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        raise RuntimeError("OPENROUTER_API_KEY is required")
    body = json.dumps({"model": model, "reasoning_effort": reasoning_effort, "messages": messages, "tools": tools, "tool_choice": "required"}).encode()
    request = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=body,
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)
