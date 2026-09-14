# Policy schema

[typed-policy-v1.json](typed-policy-v1.json) is the typed proposal schema used by the evaluated core compiler. It is exported from `IR_SCHEMA` in [policy.py](../src/permission_to_work/policy.py).

It names one tool grant, resource/destination sets, data rules, genuine-approval requirements and delegation limits. Host-bound policy/job/principal identity comes from the trusted task record, not the proposal.

The schema describes structure. The constrained validator and human review address intent; execution probes check whether controls actually hold. Schema validity alone proves neither correct interpretation nor complete mediation.

Changes need an explicit schema version, compatibility notes, rejected and permitted examples, and an experiment showing their effect. Frozen study snapshots retain the old schema.
