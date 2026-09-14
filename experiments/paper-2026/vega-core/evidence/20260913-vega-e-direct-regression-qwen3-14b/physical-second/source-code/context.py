from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .approvals import ApprovalRegistry
from .models import Request, TrustedContext


@dataclass
class TrustedProvenanceRegistry:
    values: dict[str, tuple[str, str]] = field(default_factory=dict)
    resources: dict[str, str] = field(default_factory=dict)

    def register(self, value: str, label: str) -> str:
        digest = hashlib.sha256(value.encode()).hexdigest()
        self.values[digest] = (value, label)
        return digest

    def labels_in(self, payload: str) -> tuple[str, ...]:
        # This benchmark uses exact synthetic canaries, not general semantic taint tracking.
        return tuple(sorted({label for value, label in self.values.values() if value and value in payload}))

    def register_resource(self, resource: str, label: str) -> None:
        self.resources[resource] = label

    def labels_for(self, request: Request) -> tuple[str, ...]:
        labels = set(self.labels_in(request.payload))
        if request.resource in self.resources:
            labels.add(self.resources[request.resource])
        return tuple(sorted(labels))


def build_trusted_context(
    runner_identity: dict,
    provenance_registry: TrustedProvenanceRegistry,
    approval_registry: ApprovalRegistry,
    delegation_registry: dict,
    request: Request,
) -> TrustedContext:
    missing = tuple(name for name in ("job_id", "principal") if not runner_identity.get(name))
    chain = delegation_registry.get(runner_identity.get("job_id"), {"depth": 0, "expands": False})
    return TrustedContext(
        job_id=runner_identity.get("job_id", ""),
        principal=runner_identity.get("principal", ""),
        data_labels=provenance_registry.labels_for(request),
        approval=approval_registry.resolve(request.approval_handle),
        delegation_depth=chain.get("depth", 0),
        child_expands_authority=chain.get("expands", False),
        missing=missing,
    )
