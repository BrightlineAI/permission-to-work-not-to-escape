#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from common import sha256_file


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--generation-dir", choices=["typed-f-generation", "direct-e-generation"],
                        default="typed-f-generation")
    args = parser.parse_args()
    source, target = Path(args.source).resolve(), Path(args.target).resolve()
    source_manifest = source / args.generation_dir / "generation-manifest.json"
    target_manifest = target / args.generation_dir / "generation-manifest.json"
    if not source_manifest.is_file() or not target_manifest.is_file():
        raise FileNotFoundError(f"{args.generation_dir} manifest missing")
    if sha256_file(source_manifest) != sha256_file(target_manifest):
        raise ValueError("copied generation manifest differs from source")
    record = {
        "schema_version": 1,
        "source_iteration_root": str(source),
        "generation_directory": args.generation_dir,
        "generation_reused_without_new_llm_calls": True,
        "generation_manifest_sha256": sha256_file(target_manifest),
    }
    (target / "policy-reuse.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
