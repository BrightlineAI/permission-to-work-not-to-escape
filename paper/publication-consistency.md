# Publication consistency notes

## Source of truth

The release follows the 22-page `Apart Research hackathon submission (2).pdf`, published unchanged as [submission.pdf](submission.pdf). Its hash and the included and excluded file inventory are recorded in `provenance/publication.json` in the public export. Publication does not rerun experiments or alter scores.

The three main experiments are permission misuse, policy generation and shared escalation. All seven supporting experiment directories remain because the PDF also discusses native task completion, file restrictions, diagnostics and scripted escalation. Failed attempts, corrected analyses, historical policies and negative results within those experiments remain intact.

Earlier BashArena/secret-access pilots, exploratory packages, superseded manuscripts and authoring material are excluded from the public copy. They remain in the author's working archive. This removes unrelated presentation, not unfavorable outcomes from the reported experiments.

## Main result checks

| PDF result | Retained evidence checked by the release verifier |
|---|---|
| Table 1: A/B/C/D captured harmful effects 133/133, 133/133, 96/133, 0/133 | Both core cohorts' captures, matched replay hashes and raw effect records |
| Table 1: supplied harmful effects 200, 200, 160, 0; permitted completions 200 each | Raw forced and permitted request results for both cohorts |
| Table 2: strengthened E 0/200 harmful, 180/200 permitted; F/G 0/30 harmful, 30/30 permitted | Direct regression and frozen final-split physical results; different splits remain explicit |
| Table 3: separate counters 50/50 then 50/50, shared counters 50/49 then 0/0 | Individual native effect timestamps, observation windows and audits |

The raw second-cohort policy folders call public F **E**, and public G **F**. They are not renamed because that would break recorded provenance. The [core guide](../experiments/paper-2026/vega-core/README.md#policy-generation-e-f-g) maps those labels and preserves original direct E failures. Final F/G cases were not the same evaluation as strengthened E's known-data regression.

## PDF export omissions

The supplied PDF has five actual appendices: A, B, C, D and F. Its contents also list E (scripted escalation) and G (reproduction), but those sections are absent. Appendix D's contents title differs from its actual heading. Some appendix table bodies and links are missing, and old table/reference labels remain. The PDF is preserved rather than silently corrected.

Use these complete repository records instead of the missing table bodies:

- Appendix D, page 19: [native permission operations and repair](../experiments/paper-2026/native-delegation/README.md).
- Appendix F, pages 21–22: [native interruption/stop summary](../experiments/paper-2026/native-stop/evidence/20260914-vps/summary.json) and [shared-counter summary](../experiments/paper-2026/native-stop/evidence/20260914-warning/summary.json).
- Missing E/G references: [18 scripted escalation checks](../experiments/paper-2026/escalation-preservation/README.md) and [reproduction guide](../docs/reproduction.md).
- Appendix B's old R21/R26 labels: the [source index](research/index-final.md) identifies the two studies.

The Methods mention ten native assignments, but the final Results omit their numerical comparison. The [retained DTAP result](../experiments/paper-2026/dtap-vega/README.md) is still published: attacks fell from one to zero, while completed assignments fell from four to three. It is supporting evidence, not added to the three main tables.

## Interpretation

The incident review's 30/34 candidate intervention points are not an observed prevention rate. Supplied permitted actions are not complete autonomous tasks. Shared stopping is a tested mechanism toward swarm protection, not a test against adaptive swarms. The repository does not expand these claims beyond the paper's controlled experiments.
