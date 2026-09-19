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

Task 14 passed its manager acceptance before the artifact-review changes.
Current-source regression and artifact native acceptance remain pending; earlier
results do not establish acceptance of the changed runtime.
Read the [audit guide and coverage matrix](AUDIT.md) before
using its exports. Assembled artifact review is implemented for development
validation through the [existing checkpoint workflow](DAILY.md#assembled-candidate-review).
Sequence review remains separate queued work. Explicit surrender is implemented
for manager acceptance as described below; native validation remains pending.

## Frozen task-17 checklist

1. Connect explicit authenticated `surrender` and completion cleanup across MCP and headless adapters; never infer a command from prose or accept a target identity.
2. Revoke the caller subtree, reject queued/late effects and old-token restart, preserve parent/sibling/unrelated work, and keep operator continuation explicit.
3. Distinguish requested termination, durable closure and observed cessation; qualify repeat/lost acknowledgement, supervisor/query and required capture/quota/storage failures using existing recovery.
4. Exercise public MCP, headless and terminal behavior with independent process/cgroup/listener/sentinel oracles and useful controls.
5. Compose only missing IG2/S8 cases across existing broker, command/child, delegate, package/resolver/build/import and preview boundaries.
6. Reach AT2 escalation under shipped policy/evidence settings across sessions; prove below-threshold useful work and real aggregate stopping without lowering thresholds.
7. Complete scenario/control/test coverage, user guidance, single discovery and maintained hashes; preserve all pinned contracts and historical evidence.

The implementation and guides are ready for manager acceptance. The focused
`test_product_incident_controls` module includes offline authentication, replay,
capture/quota/storage failure, queued admission and late command publication
tests. Native cases cover headless subtree closure, MCP lost acknowledgement,
fault recovery, a deterministic adapter client in a real PTY with an active
preview, missing-target package/resolver confinement, and shipped-policy AT2.
Native validation is pending; these fixtures are not measured model trajectories.

The new route uses `workflow.end_session`, `Store.close_session` and
`Supervisor.reconcile`. It verifies all registered subtree units separately
from the reconciliation return list; an empty list alone proves nothing.
Restrictive closure intent uses the existing lifecycle ledger. If flag storage
fails, admission consults that intent and supervision retries the flag update.
Required capture failure does not prevent revocation or best-effort termination.
Fault coverage includes successful closure capture followed by failed termination
capture, and changed terminal requests while flag writes continue to fail.
Responses preserve the original intent and report capture gaps separately from
independently observed cessation.
An ordinary reply leaves an interactive session open. `finish` is an explicit
completion declaration with the same cleanup and `completion_verified=false`.

The lifecycle relies on SQLite transactions for all-or-nothing subtree flag
updates and on systemd control-group stopping for registered descendants.
[SQLite transaction/error semantics](https://www.sqlite.org/lang_transaction.html)
and [systemd's primary kill documentation](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.kill.xml)
describe those interfaces; only native observations can establish actual cessation.
No new dependency or model call is required. Local routing/schema changes need
no additional external research.

### IG2/IG3 scenario and supported-route coverage

The rows below identify concrete checks, not a claim that the current native
suite passed. Existing cases stay in their owning modules; the incident module
imports fixture modules without importing their test classes into discovery.
Full regression must discover each incident case once. Source tests require the
[isolated editable installation](README.md#run-the-tests); fresh installed
qualification belongs to task 16 and must not reuse that environment.

| Scenario/control | Existing checks reused | Added composition and independent oracle | Boundary/limit |
| --- | --- | --- | --- |
| IG2/S8: broker resources and delegates | `test_workspace.WorkspaceTests` scope, traversal, identity and delegate cases; `test_interactive.AdapterTests.test_session_labels_cannot_expand_token_scope` | `SurrenderTests.test_legacy_headless_surrender_and_missing_target_keep_scope`: missing file then denied private lookalike; protected bytes unchanged and useful parent read | File-resource analogue, no remote-target adapter |
| IG2/S8: commands and descendants | `test_workspace.WorkspaceLinux.test_host_secrets_network_controller_hidden`; `test_ecosystems.EcosystemLinuxTests.test_npm_build_runs_only_in_disposable_namespace` | `NativeIncidentTests.test_missing_target_package_children_and_resolver_do_not_gain_authority`: inert package build/import spawns child probes; live collector receives no probe requests, dummy credential and private file unchanged, build produces 42 and import succeeds | Application namespaces; trusted host/runtime remain outside this boundary |
| IG2/S8: registry resolution and installation | `test_product_ecosystems` private Python/npm native install cases, resolver environment/origin/credential checks; `test_packages.PackagePolicyTests.test_unapproved_network_destination` | Same incident composition: missing metadata then useful read, refused resolver write/foreign target, no collector publication | Resolver tooling has host networking; only its constrained registry interface is read-only. Model/controller transports are separately trusted |
| IG2/IG3: previews and late effects | `test_product_daily.PreviewTests.test_stop_racing_launch_cannot_publish_ready`, `NativeDailyTests.test_bounded_preview_native`; `LocalGitTests.test_rejected_closed_stopped_and_monitor_loss_cannot_publish`; `test_product_audit` publication authority races | `NativeIncidentTests.test_terminal_surrender_stops_preview_without_ending_parent`: real preview GET before surrender; listener gone and cgroup empty afterward, parent sentinel continues; old token cannot restart | Snapshot preview and local checkpoint only; prior effects cannot be undone |
| IG3/S9: explicit terminal requests | `test_workflow.WorkflowTests`; `test_interactive.AdapterTests.test_quit_revokes_children_but_not_another_parent` | `SurrenderTests` plus `NativeIncidentTests.test_headless_surrender_stops_subtree_and_preserves_parent_sibling` and `test_real_mcp_surrender_survives_lost_acknowledgement`: actual process/descendant/cgroup/sentinel checks after impossible fixture | Explicit structured command, never inferred from prose; no automatic credential revival |
| IG3/S9: fault recovery | `test_product_audit.AuditLifecycleTests` and `NativeAuditTests.test_failed_closure_storage_still_terminates_subtree_only` | `SurrenderTests` capture/quota/flag/combined-fault cases and `NativeIncidentTests.test_faulted_surrender_closes_admission_and_reconciles_physical_work`: surviving process during injected query/stop failure, cessation after independent reconciliation | Lost storage or supervisor evidence stays unavailable/unconfirmed. Simultaneous failure of both closure persistence paths uses existing conservative project fault recovery |
| AT2: aggregate escalation | `test_workspace.WorkspaceLinux.test_actual_running_parents_child_stop_unrelated_survives` | `NativeIncidentTests.test_shipped_aggregate_escalation_stops_real_descendants`: shipped template warn1/stop3, default audit cap, one denial per registered session; below-threshold work, real descendants stop at third denial, unrelated project continues | Deterministic shared escalation, distinct from surrender or semantic suspicion; allowed operations do not increment counts |

All unqualified incident test names in this table belong to
`test_product_incident_controls`. Native receipts retain source hashes, measured
observations and original terminal output in unique private directories. Failed
attempts remain failures. Expected physical outcomes above remain unvalidated
until the manager runs them; optional semantic review is not exercised here.
No claim is made that PTW already prevented the reported external incidents,
that all host networking is offline, or that arbitrary malicious prose is detected.

## Frozen task-15 checklist

1. Extend the existing checkpoint packet/publication gate, keeping real terminal authority.
2. Include scoped assembled text and earlier context; hold required unavailable context.
3. Bind policy, candidate/base, assumptions, test inputs/outcomes, evidence and reviewer provenance.
4. Preserve original findings and require exact operator disposition; never waive mandatory gaps.
5. Exercise AT1 same-permission pairs, AT3 cross-session composition, injection and physical effects.
6. Preserve ordinary Git/preview/resume, audit recovery and unrelated resources; finish guides and hashes.

The checklist's implementation, guides and offline regressions are ready for
manager acceptance. Final native validation remains pending, including preview
compatibility, command output, snapshot reservations and resumed composition.
This is not acceptance or release readiness. No optional model adapter or
paid/model run is included in task 15.

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
| IG1 authority | Task 14: authenticated events; exact operator checkpoint receipt; `test_product_audit` | Task 14 accepted; current-source regression pending |
| IG2 scope | Task 17: compose existing broker, command, package and preview boundaries | Coverage mapped and compositions implemented; native qualification pending |
| IG3 surrender | Task 17: adapters, closure intent and existing supervisor | Implemented with failure/public-path tests; native qualification pending |
| IG4 review facts | Tasks 15/16: factual checkpoint/sequence inputs distinct from worker explanations | Checkpoint separation implemented; sequence consumer pending |
| IG5 release | Tasks 16/7: installed additive acceptance and publication verification | Pending |
| AT1 same permissions, different harm | Tasks 15/16: paired fixture behavior and artifact review | Offline fixture gate exercised; native/semantic assessment pending |
| AT2 aggregate escalation | Task 17: `NativeIncidentTests.test_shipped_aggregate_escalation_stops_real_descendants` | Template warn1/stop3 and default audit cap; native result pending |
| AT3 separated harmful steps | Tasks 15/16: candidate plus linked prior evidence across sessions | Candidate/context fixture implemented; native/semantic assessment pending |

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
