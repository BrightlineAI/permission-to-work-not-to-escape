#!/usr/bin/env python3
"""Export a strict whitelist of synthetic acceptance artifacts, never raw sessions."""
import argparse
import hashlib
import json
from pathlib import Path
import re


parser = argparse.ArgumentParser()
parser.add_argument("--root", type=Path, required=True)
parser.add_argument("--out", type=Path, required=True)
args = parser.parse_args()
args.out.mkdir(parents=True, exist_ok=False)
origins = {}


def copy(source, name):
    data = source.read_text()
    if source.suffix == ".json":
        obj = json.loads(data)
        def inspect(value):
            if isinstance(value, dict):
                if any(k.lower() in {"token", "api_key", "access_token", "refresh_token", "authorization"} for k in value):
                    raise ValueError("Credential-shaped field in " + str(source))
                for v in value.values():
                    inspect(v)
            elif isinstance(value, list):
                for v in value:
                    inspect(v)
        inspect(obj)
    # Paths are synthetic but not useful to another user. Preserve originals'
    # hashes so retained private files can be matched to these sanitized records.
    clean = data.replace(str(args.root), "<VPS_RUN>").replace("/home/ptwux0916", "<FRESH_ACCOUNT>")
    target = args.out / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(clean)
    origins[name] = {"source_sha256": hashlib.sha256(data.encode()).hexdigest(),
                     "published_sha256": hashlib.sha256(clean.encode()).hexdigest()}


for case in ("final-new-ts", "final-existing-python", "final-existing-js", "final-existing-ts"):
    result = json.loads((args.root / case / "result.json").read_text())
    if not result["passed"]:
        raise ValueError("Do not export a failed acceptance as passed: " + case)
    for filename in ("result.json", "oracle-result.json", "events.json", "approved-policy.json"):
        copy(args.root / case / filename, case + "/" + filename)
    # Only the synthetic site and tests, not controller state, dependencies or logs.
    for part in ("src", "public", "tests", "dist"):
        for source in (args.root / case / "fixture/repo" / part).rglob("*"):
            if source.is_file() and not source.is_symlink() and source.suffix in (".py", ".js", ".ts", ".html"):
                copy(source, case + "/website/" + str(source.relative_to(args.root / case / "fixture/repo")))

for case, files in {
    "final-security": ("result.json", "surface.json", "events.json"),
    "final-lifecycle": ("result.json", "old-status.json", "new-status.json"),
    "fresh-account": ("install.json", "doctor.json", "install.log", "linux.json", "unauthenticated.json"),
}.items():
    for filename in files:
        copy(args.root / case / filename, case + "/" + filename)

for case in ("security-01",):
    copy(args.root / case / "result.json", "development/" + case + ".json")

(args.out / "artifact-hashes.json").write_text(json.dumps(origins, indent=2) + "\n")
print(json.dumps({"published_files": len(origins), "raw_terminals_published": False,
                  "session_credentials_published": False}))
