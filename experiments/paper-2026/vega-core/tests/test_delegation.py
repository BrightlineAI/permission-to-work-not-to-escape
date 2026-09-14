from vega_core.authorize import authorize_d
from vega_core.delegation import expands_authority
from vega_core.models import TrustedContext


def test_authority_subset():
    assert not expands_authority({"read", "write"}, {"read"})
    assert expands_authority({"read"}, {"read", "write"})


def test_excessive_delegate_denied(case2, request_factory):
    _, policy = case2
    context = TrustedContext(policy.job_id, policy.principal, delegation_depth=2, child_expands_authority=True)
    assert authorize_d(policy, request_factory(), context).reason == "DENY_DELEGATION"
