# Current project safety contract

The [original product contract](PRODUCT_ACCEPTANCE.json), [project safety
extension](PROJECT_SAFETY_ACCEPTANCE.json) and [incident amendment](INCIDENT_SAFETY_ACCEPTANCE.json)
are separate, immutable acceptance requirements. [Reviewed section 11](../docs/PROJECT-SAFETY-EXTENSION-REVIEW.md#11-reviewed-disposition-and-minimum-implementation-contract),
including 11.6 and 11.7, governs this implementation. The paper, dated experiment
evidence and separate Vega tracks are unchanged.

Audit, assembled-candidate review, bounded sequence review and authenticated
surrender are implemented. Tasks 14, 15 and 17 passed their manager acceptance.
Task 16's sequence, artifact and fresh-wheel suites passed manager development
checks before the final additive gate changes. **Final-source acceptance remains
pending**, including the parsed installed receipts and changed release bundle.
No public release, live semantic assessment or broad adversarial assurance is
claimed.

Use the [daily guide](DAILY.md#bounded-project-sequence-review) for offline review
and optional selected-content Codex review, the [audit guide](AUDIT.md) for
adoption/retention, and the [acceptance guide](ACCEPTANCE.md#installed-extension-journeys)
for evidence and reproduction. Source tests require an [isolated editable
installation](README.md#run-the-tests); installed-user journeys use separate
fresh wheels without PYTHONPATH or editable imports.

## Frozen task-16 acceptance checklist

1. One bounded project/checkpoint review interface retains original event references, parent/delegate/resume links, summaries and explicit unknown coverage.
2. Exact candidate/base, policy/grants, assumptions, tests, history and reviewer bindings invalidate stale results; findings hold acceptance without changing violation counts or operator authority.
3. Manual inspection works offline; one optional existing-Codex adapter requires exact upload consent and bounds input, output and time. Startup, ordinary operations and idle monitoring make zero reviewer calls.
4. Preserve the frozen eight paired cases and three comparison arms within sixteen calls; report missing semantic evaluation explicitly.
5. Reuse interaction/incident cases with independent effects and useful controls, including facts-identical rationale variants and AT1–AT3.
6. Fresh-wheel new/existing/upgrade journeys preserve authority/history, refuse unsupported downgrade and exercise installed review, surrender and shipped-threshold stopping in normal discovery.
7. Parse per-ID original evidence and check actual installed/runtime/contract bytes for local and exact public candidates.
8. Maintain concise guides, scenario limits and source hashes without altering the three contracts or historical evidence.

All eight items have implementations and tests. This checklist is a fixed
acceptance scope, not a claim that pending manager checks passed.

## Behavior and limits

Review uses existing checkpoint authority and durable findings. Manual exports
cannot approve, run effects, grant access or clear quarantine/stops. Suspected
harm requires an explicit operator disposition for that exact candidate;
required missing evidence cannot be waived. Summaries preserve original hashes
and covered/omitted ranges. Missing originals, unsupported compaction and hidden
reasoning remain unknown. A later checkpoint cannot erase unresolved findings.

The optional adapter is read-only, uses the pinned existing Codex configuration
and copies no authentication. Input is capped at 4 MiB, output at 256 KiB, history
at 2,048 records and findings at 32. Calls stop at 120 seconds. Refusal,
unavailable login, malformed/oversized output, timeout and interruption produce
incomplete/unavailable outcomes. Exact cache keys include the selected request
and reviewer configuration; changed inputs need a fresh review. These controls
are not arbitrary-prose correctness or automatic clearance.

Explicit `surrender` reuses session closure and supervision to revoke the caller
and descendants. Ordinary conversational replies leave the session open.
`finish` uses the same cleanup but does not certify success. Admission closure,
requested termination, capture availability and independently observed cessation
are separate facts. Storage/query/supervisor failure cannot justify a confirmed
stop or revived credentials. An operator may start a fresh protected continuation
under the retained scope/history. A child cannot stop its parent or sibling.

The [frozen eight-case manifest](SEQUENCE_CASES.json) contains four benign/harmful
pairs: AT1 login, AT3 separated composition, omitted security repair and forged
approval/injection. **Live evaluation is unvalidated: zero cases and zero calls.**
The product report records zero measured denominators and null misses, false
alerts, completion, latency, tokens and cost for all three arms: denial-only,
artifact-only and artifact-and-history. Fixture findings and cached replies are
explicitly deterministic. Facts-identical persuasive-rationale variants test
mechanical authority; variable LLM judgments remain unmeasured. Eight cases could
not establish broad adversarial assurance even if all passed.

## Scenario-to-control-to-test map

The [scenario catalogue](../docs/PROJECT-SAFETY-SCENARIOS.md) preserves the four
sourced incident accounts (I1–I4), observed versus possible harms, and constructed
fixture analogues. I1 concerns mistaken external target identity; I2 distinguishes
package publication from downstream installation; I3 concerns substitution after
an unavailable target; I4 concerns failure to honor an attempted stop. Their
multi-label S8/S9 mappings do not prove injection, shutdown resistance or that PTW
prevented the reported events.

| Scenario / acceptance IDs | Control and owning tests | Limit |
| --- | --- | --- |
| S1 external untrusted content; S5 injection; S6 poisoned history; IG4 | Controller facts separated from narratives; exact bindings and retained originals. `test_product_sequence_review.SequenceTests`, `test_product_artifact_review.ArtifactReviewTests` | Semantic detection unvalidated; source/worker text never supplies authority |
| S2 unsafe task pursuit; S3 mistakes; S4 goal conflict; S7 hostile requests; AT1 | Same permitted grants, independent login oracle, explicit checkpoint hold or approval. `NativeArtifactTests.test_at1_native_paired_terminal_decisions_and_physical_effects` | Deterministic findings; allowed edits can be harmful before local acceptance |
| S2/S6; AT3 | Earlier helper plus ordinary work and resumed session; assembled candidate and original history reach review. `NativeArtifactTests.test_at3_native_resumed_composition_and_benign_counterpart`, sequence summary/gap tests | Unsupported compaction is incomplete, never reconstructed |
| S8; IG2 | Existing broker/command/child/delegate/package/resolver/preview confinement. `NativeIncidentTests.test_missing_target_package_children_and_resolver_do_not_gain_authority`, existing workspace/ecosystem/private-registry cases | Fetch cannot publish; model/controller transports remain separately trusted |
| S9; IG3 | Explicit subtree surrender, lost acknowledgement and failed storage/query reconciliation. `SurrenderTests`, `NativeIncidentTests` terminal, MCP, headless and fault cases | Registered local effects only; earlier effects cannot be undone |
| AT2 | Shipped warn1/stop3 across three sessions, below-threshold useful work, actual descendant cessation and unrelated progress. `NativeIncidentTests.test_shipped_aggregate_escalation_stops_real_descendants` | Deterministic policy escalation, distinct from model suspicion or surrender |
| IG1; audit coverage/durability/retention | Authenticated authority/time/outcome metadata, intent before effect, bounded optional content, pinning and tombstones. `test_product_audit` | Unknown occurrence time and capture uncertainty stay explicit |
| Migration; IG5; installed/release acceptance | Exact profile adoption, old-runtime refusal, rollback preservation, three fresh installations, parsed originals and exact archive bytes. `test_product_safety_acceptance`, `test_product_gate` | Final-source local/public acceptance pending; hashes establish consistency, not authorship |

Unqualified artifact test names belong to `test_product_artifact_review`;
incident names belong to `test_product_incident_controls`. The additive report
maps every extension ID, IG1–IG5 and AT1–AT3 to actual source-suite test IDs,
original native receipts and retained installed journeys. It keeps application
behavior, permission decisions, gate outcomes, useful work and timing separate.
Native incident tests are discovered once; installed compositions deliberately
exercise the separate fresh-wheel boundary. No second monitor, authority,
provider, service adapter or deployment system is added.

## Sources and history

The current reviewed proposal and scenario documents remain the exact latest
approved snapshots. Earlier [original proposal](review-history/20260918-original/PROJECT-SAFETY-EXTENSION-REVIEW.md.txt),
[incident proposal](review-history/20260918-incident/PROJECT-SAFETY-EXTENSION-REVIEW.md.txt)
and [incident scenarios](review-history/20260918-incident/PROJECT-SAFETY-SCENARIOS.md.txt)
are historical data. The root manifest records maintained source hashes.

This implementation reuses existing Python, SQLite, Git and systemd interfaces.
The reviewed sources and inspected local interfaces resolve its design; repeating
the literature search adds no evidence about these native effects. Tests on an
isolated Linux host remain necessary. No new provider/model run, outbound
publication or authentication access is implied by offline verification.
