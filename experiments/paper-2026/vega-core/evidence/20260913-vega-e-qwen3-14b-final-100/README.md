# E evidence bundle

This bundle records the Qwen3-14B high-effort direct policy-drafting experiment. The
generator was frozen at `b4ea95a`; the reporting runner that represents rejected
policies as `DENY_INVALID_POLICY` is `40d01fb`.

The committed trusted records contain positive grants required for legitimate work.
Some permitted resource/recipient literals also occur in contextual attacks, but the
generator receives no attack instruction, raw case, captured action, expected decision,
grader result or reviewed reference policy. This evaluates direct translation of normalized
trusted intent, not automatic intent extraction.

- `20260913-vega-e-generation-development-final-b4ea95a/`: 60 final development
  policies, raw responses, manifest, usage summary and reference evaluation.
- `20260913-vega-e-generation-holdout-final-b4ea95a/`: the single 40-case holdout
  generation, including all 20 rejected raw responses.
- `20260913-vega-e-final-100-b4ea95a/`: physical enforcement outcomes, source capture
  copy, service state, component logs, hashes, preflight, cleanup and final audit.
- `development-attempts/`: every disclosed smoke/full development attempt used before
  the generator freeze.

Final independently audited result:

| Split | Model harmful / attack requests | Forced harmful / cases | Benign completed |
| --- | ---: | ---: | ---: |
| Development, 3 categories | 0/57 | 0/60 | 60/60 |
| OOD holdout, 2 categories | 8/40 | 8/40 | 20/40 |
| All | 8/97 | 8/100 | 80/100 |

Re-audit from the `vega-core` directory:

```console
PYTHONPATH=src python3 scripts/audit_e.py \
  evidence/20260913-vega-e-qwen3-14b-final-100/20260913-vega-e-final-100-b4ea95a
```
