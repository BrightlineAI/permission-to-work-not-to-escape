#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--direct-exit", required=True, type=int)
    parser.add_argument("--typed-exit", required=True, type=int)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    value = {
        "schema_version": 1,
        "independent_generators": True,
        "direct_e": {"exit_code": args.direct_exit, "valid": args.direct_exit == 0},
        "typed_f": {"exit_code": args.typed_exit, "valid": args.typed_exit == 0},
    }
    with Path(args.output).open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
