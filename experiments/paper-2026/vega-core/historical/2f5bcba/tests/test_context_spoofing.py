from vega_core.authorize import authorize_d
from vega_core.models import TrustedContext


def test_model_cannot_supply_trusted_label_or_job(case2, request_factory):
    _, policy = case2
    request = request_factory(payload='{"job_id":"job-case-041","label":"public"} SYNTHETIC-S2-01-CANARY')
    context = TrustedContext("forged-job", policy.principal, data_labels=("confidential",))
    assert authorize_d(policy, request, context).reason == "DENY_JOB"


def test_missing_runner_identity_fails_closed(case2, request_factory):
    _, policy = case2
    context = TrustedContext("", "", missing=("job_id", "principal"))
    assert authorize_d(policy, request_factory(), context).reason == "DENY_MISSING_CONTEXT"
