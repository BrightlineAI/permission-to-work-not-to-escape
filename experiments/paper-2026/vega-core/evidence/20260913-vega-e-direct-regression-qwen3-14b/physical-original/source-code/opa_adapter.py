#!/usr/bin/env python3
"""Pinned OPA adapter used by both C and D."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

OPA_VERSION = "1.20.2"
OPA_SHA256 = {
    "darwin-arm64": "54e7008e696d39e8e4f96594e2b71bcbe45fd9a4f838102bcf1240638bf3fbe1",
    "linux-amd64": "69da5179ee403d10fa11bab6cfb4ffb0d23dba5f9b682fa977db772a1da5670f",
}


def evaluate(opa: str, rego: str | Path, policy: dict, request: dict) -> dict:
    command = [opa, "eval", "--format", "json", "--data", str(rego), "--stdin-input", "data.vega.baseline.decision"]
    completed = subprocess.run(
        command,
        input=json.dumps({"policy": policy, "request": request}),
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"OPA failed closed: {completed.stderr.strip()}")
    document = json.loads(completed.stdout)
    try:
        return document["result"][0]["expressions"][0]["value"]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError("OPA returned no decision; fail closed") from exc
