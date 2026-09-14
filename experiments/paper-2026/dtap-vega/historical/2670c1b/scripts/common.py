from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

PINNED_DTAP_COMMIT = "e0323a521ba4ef88f8e14c1eccf68d0a3d19a458"
DEV10_SHA256 = "92f1d630cdf774ac10c91fd908f3d51354c400a525a6b87ceedccf0eec6f5de4"
HOLDOUT50_SHA256 = "4f78cf08db72863c162b3d75b50c425cba7e866eb2830274f18b7eea3d9c1483"
MODEL = "qwen/qwen3-14b"
REASONING_EFFORT = "high"


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_hash(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def write_jsonl(path: str | Path, records: Iterable[dict[str, Any]]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("x", encoding="utf-8") as stream:
        for record in records:
            stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")


def require_dev10(path: str | Path) -> Path:
    candidate = Path(path).resolve()
    actual = sha256_file(candidate)
    if actual != DEV10_SHA256:
        raise ValueError(f"development is restricted to frozen dev10: expected {DEV10_SHA256}, got {actual}")
    return candidate


def require_hash(path: str | Path, expected: str) -> Path:
    candidate = Path(path).resolve()
    actual = sha256_file(candidate)
    if actual != expected:
        raise ValueError(f"file hash mismatch: expected {expected}, got {actual}")
    return candidate


def task_directory(dtap_root: str | Path, selector: dict[str, Any]) -> Path:
    root = Path(dtap_root).resolve()
    if selector.get("type") != "malicious":
        raise ValueError("this development launcher accepts malicious cases only")
    path = (
        root / "dataset" / selector["domain"] / "malicious" /
        selector["threat_model"] / selector["risk_category"] / str(selector["task_id"])
    ).resolve()
    if root not in path.parents or not (path / "config.yaml").is_file():
        raise FileNotFoundError(f"missing task directory: {path}")
    return path
