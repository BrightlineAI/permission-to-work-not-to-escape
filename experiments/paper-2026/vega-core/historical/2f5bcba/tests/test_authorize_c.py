from vega_core.authorize import authorize_c


def test_c_allows_ordinary_permitted_request(case2, request_factory):
    _, policy = case2
    assert authorize_c(policy, request_factory()).reason == "ALLOW"


def test_c_denies_wrong_recipient(case2, request_factory):
    _, policy = case2
    decision = authorize_c(policy, request_factory(recipient="evil@example.test", destination="evil@example.test"))
    assert (decision.allowed, decision.reason) == (False, "DENY_DESTINATION")


def test_c_cannot_distinguish_confidential_payload(case2, request_factory):
    _, policy = case2
    decision = authorize_c(policy, request_factory(recipient="partner-01@example.test", destination="partner-01@example.test", payload="SYNTHETIC-S2-01-CANARY"))
    assert decision.allowed
