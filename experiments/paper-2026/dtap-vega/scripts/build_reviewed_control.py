#!/usr/bin/env python3
"""Compile the explicitly dev-only, hand-reviewed positive-control policies."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from common import read_jsonl
from compile_requirements import compile_requirements


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trusted-inputs", required=True)
    parser.add_argument("--requirements", required=True)
    parser.add_argument("--output-root", required=True)
    args = parser.parse_args()
    trusted = read_jsonl(args.trusted_inputs)
    requirements = json.loads(Path(args.requirements).read_text())
    ids = {record["task_id"] for record in trusted}
    if not ids or not ids <= set(requirements):
        raise ValueError("reviewed control is missing a selected trusted dev case")
    output = Path(args.output_root)
    output.mkdir(parents=True, exist_ok=False)
    for record in trusted:
        task_id = record["task_id"]
        policy = compile_requirements(requirements[task_id], job_id=task_id, principal=record["principal"])
        (output / f"{task_id}.json").write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
