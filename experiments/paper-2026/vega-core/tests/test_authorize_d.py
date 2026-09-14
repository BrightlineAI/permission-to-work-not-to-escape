from vega_core.authorize import authorize_d
from vega_core.models import TrustedContext, policy_from_dict
from vega_core.context import TrustedProvenanceRegistry, build_trusted_context
from vega_core.approvals import ApprovalRegistry


def test_d_denies_confidential_payload_to_ordinary_allowed_destination(case2, request_factory):
    _, policy = case2
    request = request_factory(recipient="partner-01@example.test", destination="partner-01@example.test", payload="SYNTHETIC-S2-01-CANARY")
    context = TrustedContext(policy.job_id, policy.principal, data_labels=("confidential",))
    assert authorize_d(policy, request, context).reason == "DENY_DATA_FLOW"


def test_d_denies_trusted_label_without_exact_policy_rule(case2, request_factory):
    _, policy = case2
    raw = {**policy.raw, "data_rules": {}}
    policy_without_rule = policy_from_dict(raw)
    request = request_factory(recipient="partner-01@example.test", destination="partner-01@example.test")
    context = TrustedContext(policy.job_id, policy.principal, data_labels=("confidential",))
    assert authorize_d(policy_without_rule, request, context).reason == "DENY_DATA_FLOW"


def test_d_allows_benign_request(case2, request_factory):
    _, policy = case2
    context = TrustedContext(policy.job_id, policy.principal)
    assert authorize_d(policy, request_factory(), context).allowed


def test_resource_provenance_blocks_tool_that_reads_after_authorization(case2, request_factory):
    _, policy = case2
    registry = TrustedProvenanceRegistry()
    registry.register_resource("doc-01", "confidential")
    request = request_factory(recipient="partner-01@example.test", destination="partner-01@example.test", payload="")
    context = build_trusted_context({"job_id": policy.job_id, "principal": policy.principal}, registry, ApprovalRegistry(), {}, request)
    assert authorize_d(policy, request, context).reason == "DENY_DATA_FLOW"
