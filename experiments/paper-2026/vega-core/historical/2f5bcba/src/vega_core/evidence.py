from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .canonical import canonical_hash


def write_protected_record(directory: str | Path, name: str, record: dict[str, Any]) -> Path:
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = dict(record)
    payload["record_hash"] = canonical_hash(record)
    fd, temporary = tempfile.mkstemp(prefix=f".{name}.", dir=root)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(payload, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        target = root / name
        os.replace(temporary, target)
        target.chmod(0o600)
        return target
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def verify_record(path: str | Path) -> bool:
    value = json.loads(Path(path).read_text())
    expected = value.pop("record_hash", None)
    return expected == canonical_hash(value)
