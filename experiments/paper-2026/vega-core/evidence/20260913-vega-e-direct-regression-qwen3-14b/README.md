# Strengthened direct-E regression

This evidence bundle records the strengthened public E arm: Qwen3-14B directly
drafts the final policy from trusted pre-job records, with no typed intermediate
representation, semantic compiler, repair loop or critic. Both physical replays
passed every audit gate.

| Cohort | Valid / exact | Model harmful effects | Forced harmful effects | Benign completed |
| --- | ---: | ---: | ---: | ---: |
| Original 100 | 82 / 82 | 0/97 | 0/100 | 82/100 |
| Second 100 | 98 / 98 | 0/36 | 0/100 | 98/100 |
| **Combined** | **180 / 180** | **0/133** | **0/200** | **180/200** |

This is a regression on two previously observed cohorts, not a prospective
holdout. The prompt incorporates general lessons learned after the historical E
experiment and later F/G work.

All 20 utility failures were invalid policies and failed closed. Eighteen were
original WeClawArena-derived approval cases; two were second-cohort banking
approval cases. In each, Qwen supplied approval `bind_fields` outside the
normalized `resource`/`amount` vocabulary. No invalid policy was repaired or
reinterpreted.

Generation used commit `8a8371e`, prompt SHA-256
`82dc2d62dc6b9db4d9063db775d8fbc85391858462d3f8e2d76aaa8cc6b48270`,
`qwen/qwen3-14b`, and high reasoning effort. The physical replay used commit
`0e2196b`; the later changes were generic fail-closed/parity and preflight-gate
fixes made before scored replay, not changes to generated policies. Reported
generation cost was $0.03919152 for the original cohort and $0.02372856 for the
second cohort.

The complete generation records, final/invalid artifacts, frozen captures,
physical decisions, service effects, copied enforcement code and audit summaries
are in this directory. Re-audit either physical run from the matching frozen
source tree with:

```console
PYTHONPATH=src python3 scripts/audit_generated_arm.py \
  evidence/20260913-vega-e-direct-regression-qwen3-14b/physical-original
PYTHONPATH=src python3 scripts/audit_generated_arm.py \
  evidence/20260913-vega-e-direct-regression-qwen3-14b/physical-second
```
