#!/usr/bin/env python3
from __future__ import annotations

import argparse

from common import read_jsonl, require_dev10, write_jsonl


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-list", required=True)
    parser.add_argument("--limit", required=True, type=int)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if not 1 <= args.limit <= 10:
        raise ValueError("development limit must be between 1 and 10")
    write_jsonl(args.output, read_jsonl(require_dev10(args.task_list))[:args.limit])


if __name__ == "__main__":
    main()
