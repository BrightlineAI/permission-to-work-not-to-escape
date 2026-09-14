from __future__ import annotations

from .authorize import authorize_c, authorize_d
from .models import Decision, Policy, Request, TrustedContext


def decide(arm: str, policy: Policy, request: Request, context: TrustedContext | None = None) -> Decision:
    if arm in {"A", "B"}:
        return Decision(True, "ALLOW", policy.policy_hash, policy.job_id)
    if arm == "C":
        return authorize_c(policy, request)
    if arm == "D" and context is not None:
        return authorize_d(policy, request, context)
    return Decision(False, "DENY_MISSING_CONTEXT", policy.policy_hash, policy.job_id)
