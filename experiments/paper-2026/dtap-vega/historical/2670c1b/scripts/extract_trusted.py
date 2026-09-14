#!/usr/bin/env python3
"""Extract only runner-trusted policy inputs from the frozen development cases."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

from common import canonical_hash, read_jsonl, require_dev10, require_hash, sha256_file, task_directory, write_jsonl


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dtap-root", required=True)
    parser.add_argument("--task-list", required=True)
    parser.add_argument("--tool-interface", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--expected-task-list-sha256")
    args = parser.parse_args()

    task_list = (
        require_hash(args.task_list, args.expected_task_list_sha256)
        if args.expected_task_list_sha256 else require_dev10(args.task_list)
    )
    interface_path = Path(args.tool_interface).resolve()
    tool_interface = json.loads(interface_path.read_text())
    records = []
    selectors = read_jsonl(task_list)
    if args.limit is not None:
        if not 1 <= args.limit <= len(selectors):
            raise ValueError("limit is outside frozen development selection")
        selectors = selectors[:args.limit]
    for selector in selectors:
        task_dir = task_directory(args.dtap_root, selector)
        document = yaml.safe_load((task_dir / "config.yaml").read_text())
        task = document.get("Task")
        if not isinstance(task, dict):
            raise ValueError(f"{task_dir}: missing Task section")
        # Intentionally never read Attack, judge.py, setup.sh, or injected content.
        record = {
            "task_id": task.get("task_id"),
            "domain": task.get("domain"),
            "principal": "alice",
            "operator_instruction": task.get("task_instruction", task.get("original_instruction")),
            "tool_interface": tool_interface,
            "provenance": {
                "config_sha256": sha256_file(task_dir / "config.yaml"),
                "selector_sha256": canonical_hash(selector),
                "task_list_sha256": sha256_file(task_list),
                "tool_interface_sha256": sha256_file(interface_path),
                "attack_input_available_to_generator": False,
            },
        }
        if record["domain"] != "os-filesystem" or not record["task_id"] or not record["operator_instruction"]:
            raise ValueError(f"{task_dir}: invalid trusted Task record")
        record["trusted_record_hash"] = canonical_hash(record)
        records.append(record)
    write_jsonl(args.output, records)


if __name__ == "__main__":
    main()
