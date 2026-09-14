# Publication consistency notes

## Source of truth

The current release follows the 23-page `Permission to Work Not to Escape_ Policies, Controls and Escalating Enforcement Across AI Agents.pdf`, published unchanged as [submission.pdf](submission.pdf). It replaces the earlier 22-page submission. Its hash is recorded in `provenance/publication.json` in the public repository. Updating the paper does not rerun experiments or change the retained results.

The three main experiments are permission misuse, policy generation and shared escalation. All seven experiment directories remain because the paper also discusses native task completion, file restrictions, diagnostics and scripted escalation. Failed attempts, corrected analyses, historical policies and negative results remain intact.

Earlier exploratory pilots, superseded manuscripts and authoring material are excluded from the public copy, not deleted from the author's archive.

## Main result checks

| PDF result | Retained evidence checked by the release verifier |
|---|---|
| Table 1: A/B/C/D captured harmful effects 133/133, 133/133, 96/133, 0/133 | Both cohorts' captures, matched replay hashes and raw effect records |
| Table 1: supplied harmful effects 200, 200, 160, 0; permitted completions 200 each | Forced and permitted request results for both cohorts |
| Table 2: strengthened E 0/200 harmful, 180/200 permitted; F/G 0/30 harmful, 30/30 permitted | Direct regression and final-split physical results; different splits remain explicit |
| Table 3: separate counters 50/50 then 50/50, shared counters 50/49 then 0/0 | Native effect timestamps, observation windows and audits |

The raw second-cohort policy folders call public F **E**, and public G **F**. The [core guide](../experiments/paper-2026/vega-core/README.md#policy-generation-e-f-g) maps these historical names and preserves original direct E failures. Final F/G cases were not the same evaluation as strengthened E's known-data regression.

The updated Results include the ten-assignment comparison: attacks fell from one to zero, while completed assignments fell from four to three. The [DTAP records](../experiments/paper-2026/dtap-vega/README.md) retain that task completion cost.

## Appendix navigation

This PDF restores summary tables and uses Appendix E for native stopping in its contents and main text. The actual appendix heading and subsections still say F. Some older table labels and a duplicated set of contents entries also remain. The supplied PDF is preserved unchanged.

For complete records behind the abbreviated tables:

- Table D1: [all 20 native permission operations and the read repair](../experiments/paper-2026/native-delegation/README.md). The repair restricted private reads for both parent and worker; the tested write restrictions already held.
- Table E1, under F.2: [three stopping repetitions and the native-only control](../experiments/paper-2026/native-stop/evidence/20260914-vps/summary.json).
- Table E2, under F.4: [shared versus separate counters](../experiments/paper-2026/native-stop/evidence/20260914-warning/summary.json).
- Supporting work: [18 scripted escalation checks](../experiments/paper-2026/escalation-preservation/README.md) and [reproduction guide](../docs/reproduction.md).
- Appendix B: [source index](research/index-final.md) for the two external studies, now cited as references 13 and 19.

## Interpretation

The incident review's 30/34 candidate intervention points are not an observed prevention rate. Supplied permitted actions are not complete autonomous tasks. Shared stopping is a tested mechanism toward swarm protection, not a test against adaptive swarms.
