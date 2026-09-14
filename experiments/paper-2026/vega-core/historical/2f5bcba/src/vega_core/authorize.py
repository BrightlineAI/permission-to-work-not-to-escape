from __future__ import annotations

from .models import Decision, Grant, Policy, Request, TrustedContext


def _decision(policy: Policy, allowed: bool, reason: str, job_id: str | None = None) -> Decision:
    return Decision(allowed, reason, policy.policy_hash, job_id or policy.job_id)


def _tool_grants(policy: Policy, request: Request) -> tuple[Grant, ...]:
    return tuple(grant for grant in policy.allow if grant.tool == request.tool)


def authorize_c(policy: Policy, request: Request) -> Decision:
    grants = _tool_grants(policy, request)
    if not grants or not any(request.action in grant.actions for grant in grants):
        return _decision(policy, False, "DENY_ACTION")
    grants = tuple(grant for grant in grants if request.action in grant.actions)
    for field, reason in (
        ("resource", "DENY_RESOURCE"),
        ("recipient", "DENY_DESTINATION"),
        ("destination", "DENY_DESTINATION"),
    ):
        value = getattr(request, field)
        if value is None:
            continue
        plural = "recipients" if field == "recipient" else f"{field}s"
        if not any(value in getattr(grant, plural) for grant in grants):
            return _decision(policy, False, reason)
        grants = tuple(grant for grant in grants if value in getattr(grant, plural))
    approval_rule = policy.approval_rules.get(request.tool)
    if approval_rule and not request.approval_handle:
        return _decision(policy, False, "DENY_APPROVAL")
    return _decision(policy, True, "ALLOW")


def authorize_d(policy: Policy, request: Request, context: TrustedContext) -> Decision:
    baseline = authorize_c(policy, request)
    if not baseline.allowed:
        return baseline
    if context.missing:
        return _decision(policy, False, "DENY_MISSING_CONTEXT", context.job_id)
    if context.job_id != policy.job_id or context.principal != policy.principal:
        return _decision(policy, False, "DENY_JOB", context.job_id)
    for label in context.data_labels:
        rule = policy.data_rules.get(label)
        if rule and request.destination not in rule.get("allowed_destinations", []):
            return _decision(policy, False, "DENY_DATA_FLOW", context.job_id)
    rule = policy.approval_rules.get(request.tool)
    if rule:
        approval = context.approval
        if not approval or approval.get("handle") != request.approval_handle:
            return _decision(policy, False, "DENY_APPROVAL", context.job_id)
        if approval.get("issuer") != rule.get("required_issuer") or approval.get("job_id") != context.job_id:
            return _decision(policy, False, "DENY_APPROVAL", context.job_id)
        for field in rule.get("bind_fields", []):
            if approval.get(field) != getattr(request, field, None):
                return _decision(policy, False, "DENY_APPROVAL", context.job_id)
        if not approval.get("valid", False):
            return _decision(policy, False, "DENY_APPROVAL", context.job_id)
    if context.delegation_depth > policy.delegation["max_depth"]:
        return _decision(policy, False, "DENY_DELEGATION", context.job_id)
    if context.child_expands_authority and not policy.delegation["child_may_expand_authority"]:
        return _decision(policy, False, "DENY_DELEGATION", context.job_id)
    return _decision(policy, True, "ALLOW", context.job_id)
