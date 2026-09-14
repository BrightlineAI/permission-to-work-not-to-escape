#!/usr/bin/env python3
"""Select frozen holdout rows by hash without decoding their contents."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from common import HOLDOUT50_SHA256, require_hash, sha256_file


def select(source: Path, output: Path, manifest_path: Path, *, count: int, seed: str,
           expected_source_hash: str = HOLDOUT50_SHA256) -> None:
    require_hash(source, expected_source_hash)
    rows = [line for line in source.read_bytes().splitlines(keepends=True) if line.strip()]
    if len(rows) != 50:
        raise ValueError(f"expected 50 sealed rows, got {len(rows)}")
    if len({row.rstrip(b"\r\n") for row in rows}) != len(rows):
        raise ValueError("sealed source contains duplicate raw rows")
    ranked = sorted(
        (hashlib.sha256(seed.encode() + b"\0" + row.rstrip(b"\r\n")).hexdigest(), row)
        for row in rows
    )
    chosen = ranked[:count]
    if not 1 <= count <= len(rows):
        raise ValueError("selection count is outside sealed source")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream:
        for _, row in chosen:
            stream.write(row if row.endswith(b"\n") else row + b"\n")
    manifest = {
        "schema_version": 1,
        "selection_method": "lowest SHA-256(seed || NUL || raw_row_without_newline)",
        "seed": seed,
        "source_sha256": sha256_file(source),
        "source_row_count": len(rows),
        "selected_count": count,
        "selected_row_hashes_in_rank_order": [
            hashlib.sha256(row.rstrip(b"\r\n")).hexdigest() for _, row in chosen
        ],
        "selected_task_list_sha256": sha256_file(output),
        "content_decoded_during_selection": False,
    }
    with manifest_path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument(
        "--seed",
        default=("vega-dtap-holdout10-v1|481c07fd60e2a50ddd7b51f89bc7cc9a032f447a|"
                 "4f78cf08db72863c162b3d75b50c425cba7e866eb2830274f18b7eea3d9c1483"),
    )
    args = parser.parse_args()
    if args.count != 10:
        raise ValueError("prospective protocol is frozen to exactly 10 rows")
    select(Path(args.source), Path(args.output), Path(args.manifest), count=args.count, seed=args.seed)


if __name__ == "__main__":
    main()
