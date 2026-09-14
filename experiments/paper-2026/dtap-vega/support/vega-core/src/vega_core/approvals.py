from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field


@dataclass
class ApprovalRegistry:
    records: dict[str, dict] = field(default_factory=dict)

    def issue(self, *, issuer: str, job_id: str, resource: str, amount: str, ttl: int = 300) -> str:
        handle = f"apr_{secrets.token_urlsafe(24)}"
        self.records[handle] = {
            "handle": handle, "issuer": issuer, "job_id": job_id, "resource": resource,
            "amount": amount, "expires_at": time.time() + ttl,
        }
        return handle

    def resolve(self, handle: str | None, now: float | None = None) -> dict | None:
        if not handle or handle not in self.records:
            return None
        record = dict(self.records[handle])
        record["valid"] = record["expires_at"] >= (time.time() if now is None else now)
        return record
