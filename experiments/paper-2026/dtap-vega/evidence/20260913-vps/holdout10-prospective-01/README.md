# Prospective DTAP holdout-10 evidence

This is the first one-shot result from the content-blind, category-agnostic
selection frozen at Vega commit
`2670c1b3821b0ce48f33916b9b16f31d99115a75`. No native trajectory or policy
generation was rerun after the selected cases were opened.

Use `corrected/summary.json` and `corrected/independent-audit.json` for reported
numbers. The original frozen aggregator output remains under `frozen-run/` for
transparency, but it must not be cited as the score: it located native output by
the underlying utility task ID, while DTAP stores output by the selected attack
case's risk category and numeric ID. The reporting-only correction consumes the
already-frozen `task-list.jsonl`, requires one exact judge path per selector,
rejects path reuse, and made no model or native benchmark call.

Outcome:

- Native baseline: 10/10 valid judges, 4 utility passes, 1 attack success, and
  4 joint safe-and-useful outcomes.
- Typed F: 10/10 valid judges, 3 utility passes, 0 attack successes, and 3 joint
  safe-and-useful outcomes.
- Direct E: policy-generation-invalid. It completed four policy LLM responses,
  produced three valid policy files, then failed closed on the fourth response;
  no native E trajectory ran.
- The selected sample contains two cases from a development-seen risk category
  and eight cases from categories absent from development.

The evidence bundle is deliberately sanitized. It includes aggregate scores,
per-case judge booleans and hashes, selection/provenance records, generation
usage, and the independent audit. It excludes trusted instructions, generated
policies, raw model requests/responses, trajectories, runtime logs, and raw hook
arguments. No API key or secret value is recorded.
