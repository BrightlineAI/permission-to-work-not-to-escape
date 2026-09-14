#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from common import MODEL, PINNED_DTAP_COMMIT, REASONING_EFFORT, sha256_file


def command(*args: str) -> str:
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE).stdout.strip()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package-root", required=True)
    parser.add_argument("--dtap-root", required=True)
    parser.add_argument("--task-list", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--selection-manifest")
    parser.add_argument("--frozen-code-commit")
    args = parser.parse_args()
    package = Path(args.package_root).resolve()
    source_hashes = {}
    for path in sorted(package.rglob("*")):
        if path.is_file() and not any(part in {"__pycache__", "install-evidence", "dev-inspection"} for part in path.parts):
            source_hashes[str(path.relative_to(package))] = sha256_file(path)
    image = "decodingtrustagent/os-filesystem:filesystem"
    try:
        image_id = command("sudo", "-n", "docker", "image", "inspect", image, "--format", "{{.Id}}")
        repo_digests = json.loads(command("sudo", "-n", "docker", "image", "inspect", image, "--format", "{{json .RepoDigests}}"))
    except Exception as exc:
        image_id, repo_digests = f"unavailable:{type(exc).__name__}", []
    result = {
        "schema_version": 1,
        "dtap_commit_expected": PINNED_DTAP_COMMIT,
        "dtap_commit_actual": command("git", "-C", args.dtap_root, "rev-parse", "HEAD"),
        "dtap_patch_sha256": {
            path.name: sha256_file(path) for path in sorted((package / "patches").glob("*.patch"))
        },
        "task_list_sha256": sha256_file(args.task_list),
        "model": MODEL,
        "reasoning_effort": REASONING_EFFORT,
        "max_turns": 30,
        "filesystem_image": image,
        "filesystem_image_id": image_id,
        "filesystem_repo_digests": repo_digests,
        "package_source_hashes": source_hashes,
        "secret_values_recorded": False,
    }
    if args.selection_manifest:
        result["selection_manifest_sha256"] = sha256_file(args.selection_manifest)
    if args.frozen_code_commit:
        result["frozen_code_commit"] = args.frozen_code_commit
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
