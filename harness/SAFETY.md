# Current project safety contract

The original [product contract](PRODUCT_ACCEPTANCE.json) remains mandatory.
The reviewed [project safety extension](PROJECT_SAFETY_ACCEPTANCE.json) and
[incident amendment](INCIDENT_SAFETY_ACCEPTANCE.json) add requirements; they do
not retroactively change the paper or historical validation. The governing
design is [section 11 of the reviewed proposal](../docs/PROJECT-SAFETY-EXTENSION-REVIEW.md#11-reviewed-disposition-and-minimum-implementation-contract),
including sections 11.6 and 11.7 and the [scenario catalogue](../docs/PROJECT-SAFETY-SCENARIOS.md).

The extension is **partly implemented and not accepted**. Task 14's audit controls
provide versioned metadata, exact checkpoint approval provenance, lifecycle
linkage and durable intent across supported operations. Reviewed quota/content
profiles, retention/archive and transactional adoption preserve existing history.
Registry and local/editable publication admit complete package/assessment rows
before rename and bind capture to the original preparation authority. Reuse-time
refresh commits eligibility and its required assessment together. Capture failure
blocks affected admission and requests termination; quarantine remains restrictive
where storage permits. Crash recovery retains uncertain external effects and
blocks silent reinstallation. Optional diagnostic loss remains visible without
preventing supervisor reconciliation.

Focused manager checks passed the shared accounting/transaction repair and affected
publication controls. Added direct-launch crash, capture-failure, running-work and
terminal regressions await execution. Full task acceptance remains pending against
the final source; focused results do not establish acceptance.
Read the [audit guide and coverage matrix](AUDIT.md) before
using its exports. Artifact review, sequence review and surrender remain queued
work; copying their contract is not evidence of implementation.

## Frozen task-14 checklist

1. Install pinned contracts/current prose and preserve earlier snapshots; publish route coverage.
2. Version existing events and exports with causal/session/policy/authority/time/outcome identity; preserve unknown legacy fields.
3. Complete supported lifecycle admission, completion, resume and stop evidence without duplicate logging or replayed effects.
4. Add private bounded content opt-in, pre-admission accounting, eligible expiry/tombstones and explicit closed-history archive.
5. Make required capture failure block affected work/publication and reconcile running effects; distinguish optional evidence loss and uncertain termination.
6. Add reviewed adoption, transactional backed-up migration and fail-closed downgrade without resetting stops, counters, quarantine or pending work.
7. Finish public API/native/terminal fault tests and operator guides, with maintained source hashes and manager acceptance.

This finite checklist implements A1–A4 and task 14's IG1 delta. It does not
authorize sibling implementations or a new logger, gateway or model monitor.

## Incident and refined-case ownership

| Requirement | Control and evidence owner | Current status |
| --- | --- | --- |
| IG1 authority | Task 14: authenticated events; exact operator checkpoint receipt; `test_product_audit` | Implemented; full native acceptance pending |
| IG2 scope | Task 17: compose existing broker, command, package and preview boundaries | Existing boundaries; additive combinations untested |
| IG3 surrender | Task 17: connect adapters to existing session closure/supervisor | Adapter connection pending |
| IG4 review facts | Tasks 15/16: factual checkpoint/sequence inputs distinct from worker explanations | Pending |
| IG5 release | Tasks 16/7: installed additive acceptance and publication verification | Pending |
| AT1 same permissions, different harm | Tasks 15/16: paired fixture behavior and artifact review | Expected; unmeasured |
| AT2 aggregate escalation | Task 17: shipped thresholds and actual descendant cessation | Existing native controls; refinement unverified |
| AT3 separated harmful steps | Tasks 15/16: candidate plus linked prior evidence across sessions | Expected; unmeasured |

Fixture decisions are deterministic controls, not model detection evidence.
Semantic misses, false alerts and unavailable optional review must remain
separate from mechanical enforcement and useful completion. The frozen semantic
budget remains eight cases and at most sixteen calls; task 14 runs no models.

## Sources and history

The current reviewed documents are copied byte-for-byte from the latest approved
intake. Earlier [original proposal](review-history/20260918-original/PROJECT-SAFETY-EXTENSION-REVIEW.md.txt),
[incident proposal](review-history/20260918-incident/PROJECT-SAFETY-EXTENSION-REVIEW.md.txt)
and [incident scenarios](review-history/20260918-incident/PROJECT-SAFETY-SCENARIOS.md.txt)
are exact text snapshots, not current guides. Their original relative links are
preserved as historical data. Maintained source hashes are in the root manifest.

The proposal identifies the parent Vega strategy by its workspace-relative path;
that separate repository and its Bedrock track are not dependencies of these
public instructions. No changes to their status or claims are implied.
The implementation uses existing Python/SQLite/Git interfaces and dependencies.
The compatibility guard uses a pure connection-local function in the existing
project interface, verified against SQLite's primary documentation for
[views](https://www.sqlite.org/lang_createview.html),
[INSTEAD OF triggers](https://www.sqlite.org/lang_createtrigger.html) and
[connection-local functions](https://www.sqlite.org/c3ref/create_function.html).
These interfaces support the implementation; they do not prove effect isolation.
The remaining stable local interfaces did not require repeating the literature search.
