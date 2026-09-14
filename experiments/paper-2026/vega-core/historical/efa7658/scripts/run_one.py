#!/usr/bin/env python3
"""Run one named case through the same full runner."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if len(sys.argv) < 3:
    raise SystemExit(f"usage: {sys.argv[0]} CASE-ID ABSOLUTE-OUTPUT [runner options]")
subprocess.run([str(ROOT / "scripts/run_all_vps.sh"), sys.argv[2], "--case-ids", sys.argv[1], *sys.argv[3:]], check=True)
