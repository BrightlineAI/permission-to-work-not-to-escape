#!/usr/bin/env python3
from __future__ import annotations

import subprocess

NONO_VERSION = "0.77.0"


def command(binary: str, policy_args: list[str], tool_command: list[str]) -> list[str]:
    return [binary, "run", *policy_args, "--", *tool_command]


def version(binary: str) -> str:
    return subprocess.run([binary, "--version"], text=True, capture_output=True, check=True).stdout.strip()
