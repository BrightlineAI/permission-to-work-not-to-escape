#!/usr/bin/env python3
"""Retain test outcomes, source hashes and versions on the isolated Linux host."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import time
import unittest

from ptw.policy import save


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--linux", action="store_true")
    args = parser.parse_args()
    if platform.system() != "Linux":
        raise SystemExit("Use the Linux VPS for validation")
    root = Path(__file__).resolve().parents[1]
    args.out.mkdir(parents=True, exist_ok=False)
    if args.linux:
        os.environ["PTW_LINUX_TESTS"] = "1"
    log = io.StringIO()
    start = time.monotonic()
    suite = unittest.defaultTestLoader.discover(str(root / "tests"))
    result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    versions = {"python": platform.python_version(), "kernel": platform.release()}
    for key, command in {"codex": ["codex", "--version"], "bubblewrap": ["bwrap", "--version"],
                         "uv": [os.environ.get("PTW_UV", "uv"), "--version"],
                         "nono": [os.environ.get("PTW_NONO", "nono"), "--version"],
                         "node": ["node", "--version"], "npm": ["npm", "--version"]}.items():
        try:
            process = subprocess.run(command, text=True, capture_output=True, timeout=10)
            versions[key] = (process.stdout or process.stderr).strip()
        except OSError:
            versions[key] = "not installed"
    hashes = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in root.rglob("*.py") if "__pycache__" not in p.parts}
    data = {"successful": result.wasSuccessful(), "tests_run": result.testsRun, "skipped": len(result.skipped),
            "failures": len(result.failures), "errors": len(result.errors), "wall_seconds": time.monotonic() - start,
            "versions": versions, "source_sha256": hashes, "log": log.getvalue()}
    save(args.out / "result.json", data)
    print(json.dumps({k: v for k, v in data.items() if k not in ("log", "source_sha256")}, indent=2))
    if not result.wasSuccessful():
        print(log.getvalue())
        raise SystemExit(1)


if __name__ == "__main__":
    main()
