# Controller audit exports

This guide describes the implemented audit controls. Focused recovery checks
passed; full task acceptance against the final source remains pending.
The [current contract page](SAFETY.md) identifies the remaining requirements.

From a trusted operator terminal, export one project's controller metadata:

```sh
ptw evidence --state /private/controller --project PROJECT --out /private/exports/run-01.json
```

Use a private output directory outside the repository. New export files are
mode 0600 and cannot overwrite existing files. The command returns an export
digest and event count. Keep that receipt separately if you need to detect a
later missing, reordered, duplicate or altered export. Existing `ptw events`
and `Store.audit_events(project)` retain their action-only list for existing
consumers. The full `evidence` export includes controller lifecycle records;
Python callers can also select `audit_events(project, include_lifecycle=True)`.

The schema-1 document contains `events`, a count/digest `manifest` and explicit
coverage limits. Python operators can call `Store.audit_export(project)` and
`ptw.event_evidence.verify_export(document, retained_digest)`. Validation checks
controller order, duplicate identities, known states and the retained digest.
Local consistency hashes do not defend against a trusted host rewriting both
records and receipts. They do not establish completeness outside captured routes.

## Reading the evidence

Each newly recorded operation binds its stable session/event identity, controller
sequence, project/task/parent, authenticated requester, local enforcer, policy
digest, grant digest and resource/path. Source occurrence time is unknown;
observation and recording times are controller clocks. Sequence, not wall-clock
sorting, determines recorded order. Registration, delegation, closure and protected
resume retain session ancestry. New protected conversations link successive
session IDs through `resume_of`; a resumed legacy conversation with no prior
controller binding says `legacy_unknown`, without inventing a predecessor.
Lifecycle rows use a controller event namespace; `audit.session` identifies the
actual affected session, when known. Causal references link registration, nested
operation admission and workload launch/termination.

The authorization method is standing policy for ordinary operations. Trusted
controller transitions are identified separately. Policy activation and dependency
revision retain exact reviewed policy hashes; prior events retain their original
authority after a revision or rollback. Checkpoint
preparation says human review is required but not performed. Only the existing
exact operator publication path records `exact_operator_approval` with its review
receipt. A terminal rejection records `operator_rejection`, never approval.
Worker claims of approval never supply that authority. These records
do not verify a natural person's identity beyond the trusted local operator API.

`decision` describes authorization; `outcome` describes what the controller observed.
When preparation was admitted before a later trusted authorization denial (for
example, registration rejects an unknown or wider delegate task),
`admission_decision` preserves that earlier admission and `decision` records the
actual denial. Original policy and grant hashes remain bound to the request.
Replay returns the retained denial without creating a child or counting it again.
Execution failures alone do not replace the authorization decision.
Local Python publication uses the same event store. Before renaming either a
single-source or combined installation, it records a `local_publication` intent
binding the package/destination, manifest and receipt digests, policy and actual
preparation session/source IDs. Combined publication is a controller transition
after all preparations close; it does not impersonate an active session. The
assessment's `audit.cause` links to that publication's `operation_id`, so the
receipt/session facts need not be copied into another log. This transition does
not claim a new human review; the original reviewed policy remains its authority.

Both registry and local publication account for the full package and assessment
rows with the completion reservation before the rename. The shared assessment
writer charges the exact stored row, including identity, timestamps and escaped
detail. Their eligibility and the completion record commit together;
the durable intent remains outside that rollback transaction. Required capture
failure stops affected admission and requests physical termination. Local setup
discards the unpublished installation where possible. Registry post-rename
failure or abrupt death can leave an orphan directory, but no eligible package row. Reopening
retains unknown outcome and a stop, even if the directory exists. Do not retry an
uncertain installation or treat filesystem presence as successful publication.
Resolve the retained operation and measured effects through operator recovery.
If the stop-state write also fails, registry intent remains pending and the API
raises; best-effort physical termination does not claim durable closure. Existing
recovery must persist the stop before marking that operation uncertain.

Reuse-time refresh commits eligibility, generation and its required assessment
in one transaction, including changed package-row size in quota admission. This
also covers direct operator launch, which has no launch intent until refresh
succeeds. Interruption before commit retains the prior evidence; it cannot leave
fresh reusable evidence without its receipt. A captured blocked result commits
before the operational error is returned. Discarded concurrent or invalidated
results use the same complete-row admission.

Quarantine captures all matching installations as one batch. If required capture
fails, partial batch receipts roll back; restrictive quarantine is retained where
storage permits and the existing capture-fault handler stops affected project
admission and requests termination. Missing receipts are not reconstructed, and
best-effort stopping is not durable confirmation. Restoring quota cannot clear
the project stop or revive a quarantined installation.

An allowed command with nonzero exit status has outcome `failed`. An interrupted
publication has unknown outcome even if an independent file/ref observation
later finds an effect. Recovery preserves its stop and prevents silent replay.
Checkpoint completion-capture failure leaves the project stopped; a later reopen
marks the pending record uncertain. Do not treat a stop request as confirmed
physical termination.

Commands, package preparation, preview startup and Git preparation now record
intent before execution. A controller-held operation lease spans preparation
and publication while leaving the project lock available to stopping. A retry
waits for the original operation and returns its retained result. Recovery skips
live leases; an abandoned intent stops the affected project and remains uncertain.
Leases use 64 fixed lock slots per controller. Different operations hashing to
the same slot wait in sequence; no lock file is unlinked or recreated while a
waiter could still hold it. Fresh rejected event IDs cannot grow this pool.
Install dispatch reserves its own and its package operation's slots together in
sorted order before recording intent. Nested package calls reuse the held locks;
unreserved nesting is rejected. This prevents both same-slot and opposite-order
deadlocks without adding lock files or changing replay/recovery identities.
The locking rule follows Linux [flock(2)](https://man7.org/linux/man-pages/man2/flock.2.html):
separately opened descriptors can conflict within one process, and flock does
not detect deadlock. Dispatch collision, concurrent reversed-slot installation,
replay and abrupt-exit regressions require the manager's native environment.
Pre-existing per-event leases remain readable for interrupted-operation recovery.
Reopening does not silently repeat a command, package build or delegation.
Native workload creation also has a short durable launch intent. Command events
also retain an `execution` phase before publication: successful staging and
rejected publication are separate facts. The phase contains metadata and a
result hash, never command output.

Required event-write failure attempts durable project stopping and best-effort
termination through the existing supervisor. Physical termination is attempted
even if the stop-state write fails. That attempt does not establish durable
closure or confirmed termination. Session revocation precedes its evidence write;
capture failure still attempts to terminate that session's subtree without
revoking another parent. Reconciliation records physical confirmation separately
from durable capture. If capture fails, it returns `evidence: unavailable`, leaves
the workload pending reconciliation and reports the gap in monitor health.
Repeated unchanged unconfirmed observations do not add duplicate audit events.
Ordinary command/build cleanup and explicit or failed-preview cleanup use the
same termination writer as reconciliation. Confirmed, captured cleanup marks the
workload stopped while its session can remain open, permitting later evidence
profile review. A failed preview records its actual launched unit, startup failure
and termination observation rather than reporting that no effect occurred.
Missing build-cleanup capture blocks publication and stops affected admission;
physical cessation alone does not mark durable workload closure.
Terminal exit records expose missing conversation binding and uncaptured native
transcripts without treating optional diagnostics loss as misconduct.
Focused native lifecycle checks passed before the storage changes. The combined
quota, migration, detached-service and terminal paths require manager validation.

New exports omit file content, command output, diagnostic strings and worker
narratives, retaining hashes and an explicit metadata allowlist. Required private
responses retain bounded replay data, including file reads and tool results;
optional content expiry does not erase those required responses.
Legacy rows keep unknown policy, authority, chronology and coverage; reopening
cannot turn old records into newly witnessed actions. No historical counters,
stops, closures or package quarantine are reset by the export adapter.

## Adopt and configure bounded evidence

New interactive setup displays the version-1 audit profile before policy approval:
1 GiB per project, metadata plus hashes, optional content capture off. Existing
projects remain in basic mode until exact operator adoption. Review the profile
and its bound current policy/history in a trusted terminal:

```sh
ptw evidence-config --state /private/controller --project PROJECT
ptw evidence-config --state /private/controller --project PROJECT \
  --approve DISPLAYED_REVIEW_SHA256 --reviewer 'Operator name'
```

The first command only displays a review. Omitting approval, cancelling the
terminal or supplying a stale/wrong hash cannot adopt. No violation, stop,
closure, quarantine or uncertain operation is cleared. Adoption refuses running
registered work; a later exact quota increase with unchanged content selection
is allowed while termination capture is pending, so operators can restore
capture capacity without reopening admission.

To change the budget, add the same `--project-bytes N` to both commands. To opt
into content, repeat `--content-resource RESOURCE_ID` on both commands. Only
already reviewed readable resources qualify. This captures file read results or
write/create/append request bytes, at most 256 KiB per operation, with the original
byte count/hash and a truncation marker. It does not capture arbitrary environment,
provider authentication, command diagnostics or full conversations. A missing
optional payload is marked `unavailable`; that loss alone does not stop work.
For legacy file reads, capture occurs at completion when the read result exists.
A retry returns the original response and capture status without copying the
payload again or filling an earlier optional-capture gap retroactively.

Controller state is 0700, database/backup/export files are 0600. Metadata exports
include payload status and hashes, never payload bytes. A trusted Python operator
can use `Store.evidence_content(project, operation_id)` to obtain the retained
bounded bytes and status. `omitted`/`expired` returns no original payload; a
truncated byte prefix is not a reconstructed complete file or conversation.

Admission accounts for required event/replay data, session/control rows, stored
package assessments and optional payloads under the existing controller lock.
Accounting includes row overhead and a conservative fourfold SQLite/journal
allowance. It also reserves the whole fixed lease pool (512 KiB) for each project
and charges retained legacy lease files conservatively to each project. Pending
operations reserve 256 MiB plus their metadata, covering the
existing 8 MiB file-read limit and JSON escaping; completion releases the unused
reservation. Consequently, admission can stop before the database reaches the
configured budget, especially with concurrent commands. A quota failure closes
affected admission without misconduct counts, prevents publication, and asks the
existing supervisor to terminate affected work. Stop confirmation can remain
uncaptured until an operator restores capacity. Retrying cannot clear uncertainty.

This is an evidence accounting budget, not a host filesystem quota: package
installations, command staging, Git object workspaces, pre-existing native logs,
operator exports and migration backups have their existing separate bounds and
retention. The controller never fills shared storage as a test or silently deletes
required records to regain capacity. Keep operator exports and backup snapshots
on suitably provisioned private storage.

## Retention, archive and migration

```sh
ptw evidence-expire --state /private/controller --project PROJECT
ptw evidence-archive --state /private/controller --project PROJECT \
  --out /private/archives/closed-01.json
```

Expiry removes only optional bytes older than 30 days and retains their hash,
original size and expiry tombstone. Pending/uncertain effects or unresolved
checkpoint-review pins conservatively retain all optional project payloads.
Successful exact checkpoint publication or a captured rejection releases its pin.
Expiry is explicit maintenance; there is no background deletion of required history.
SQLite secure deletion overwrites the removed optional database values; it does
not erase copies retained in required replay, earlier backups or operator exports.
Archive requires a stopped project, closed sessions, confirmed workloads and no
unresolved effects/reviews. It writes a private metadata export and digest
manifest without deleting live history or exporting credentials/replay content.
Archive is not a restorable database image.

Metadata schema migration is transactional and retains a private, hashed,
stopped-state database backup. Legacy provenance remains unknown. First extension
adoption installs a compatibility guard at the existing project-table interface:
old connections without this runtime's capability fail before project admission,
including when they ignore unknown policy JSON. Downgrading a shared controller
therefore refuses its projects; it cannot silently disable an active profile.
This guard addresses accidental runtime downgrade, not a trusted host modifying
the database. Ordinary profile changes do not create redundant database backups.
There is no automatic backup restore or stop-clearing migration. Preserve the
current state and reconcile physical effects before any operator-reviewed restore;
backups themselves remain stopped and retain pending evidence.

The storage semantics follow SQLite's documented
[secure deletion and free-page reuse](https://www.sqlite.org/pragma.html#pragma_secure_delete).
Expiry can make pages reusable without shrinking the database file.

## Route coverage and verification

`enforced` means the existing controller gates the route; `observed` identifies
recorded facts; `disabled` means there is no supported worker route; `untested`
identifies remaining additive acceptance. These labels are bounded, not a claim
of every syscall, hidden reasoning or arbitrary-prose correctness.

| Route | Control / capture | Verification and remaining gap |
| --- | --- | --- |
| File/repository operations | Enforced; observed intent, result, policy and path | Existing `test_core`/`test_workspace`; new audit crash/replay/tamper fixtures |
| Command execution/publication | Enforced; observed pre-execution intent, execution phase, publication result, exit status and cleanup confirmation | Offline live-lease/crash/replay checks; native successful cleanup and capture-fault publication checks pending |
| Package preparation/publication | Enforced; observed preparation/publication intent, package-set/manifest/receipt identity and result; local assessments link to actual preparation sessions | Existing package/reassessment suites; `AuditInstallTests` covers dispatch collision, reversed-slot concurrency, replay and crash. `AuditLocalPythonTests` adds real local imports/live edits, single/combined quota, capture faults, abrupt death, changed authority, receipt tamper and terminal recovery; native verification pending |
| Policy activation/revision | Enforced exact operator review; old/new authority observed | Real dependency-revision fixture checks; no retrospective authority changes |
| Parent/delegate sessions | Enforced; registration, ancestry, actual authorization denial and closure observed | Focused manager checks passed for useful narrower delegation, nonexistent/wider-task rejection, unchanged replay/counts and lost receipts; full task acceptance pending |
| Protected resume | Enforced by existing conversation binding; predecessor and fresh session observed | Existing resume fixtures and linked useful-work checks; legacy predecessor stays unknown |
| Preview | Enforced fixed reviewed service route; startup intent, failed-start effect and cleanup/stop result observed | Existing native daily checks; failed-preview lifecycle and open-session adoption check pending native verification |
| Checkpoint preparation/publication | Enforced exact operator gate; preparation intent, receipt and outcome observed | Audit Git fixtures cover real refs with a fixture worker; native terminal acceptance pending |
| Stop/reconciliation | Enforced admission closure; requested/unconfirmed/confirmed states observed separately | Offline deduplication/fault checks; native sentinels and unrelated-work controls pending |
| Package quarantine | Enforced reassessment; atomic refresh eligibility/capture, full-row admission and restrictive quarantine on capture failure; stored rule/time/actor provenance and unknown legacy fields | Existing reassessment tests and audit export/rule-history checks; new recovery regressions pending manager verification |
| Optional transcripts/compaction | Observed only by existing selected-history adapters | Not captured in this export; absence never means misconduct |
| Worker native shell/hooks/network/service/deploy bypass | Disabled on supported adapter routes | Existing confinement tests; no outside deployment assurance |
| Quota, expiry, archive, adoption/downgrade | Enforced for reviewed profiles; reservations, optional tombstones, closed-history export and transactional migration | `AuditStorageTests`; native quota/terminal/service verification pending |

The frozen added cases are in `test_product_audit`: `AuditEventTests` covers
altered/missing/duplicate/reordered exports and interrupted/replayed effects;
`AuditLifecycleTests` covers parent/delegate/resume and uncertain stopping;
`AuditPolicyTests` preserves historical authority across genuine reviewed revisions;
`AuditStorageTests` covers quota concurrency, private opt-in, optional loss,
bounded rejected-request lease storage, expiry/archive, interrupted migration and
downgrade refusal. `AuditLegacyReadTests` covers public file-read capture,
truncation, replay and optional-write failure. `AuditCheckpointTests`
checks pinned reviews and real Git refs before/after quota or capture faults.
`AuditReassessmentTests` reuses advisory fixtures for exact quota/one-byte-short
boundaries across all outcomes, caller-owned seed rollback, public refresh,
package-row growth and all-or-none quarantine capture. Additional cases exercise
discarded concurrent/closed-session results and capture failures for current,
blocked and missing-provenance refresh. Direct operator launch is interrupted by
real process death before receipt insertion, after insertion and after commit;
reopening checks actual eligibility and absence of a launch. Native installed
imports and append sentinels test required quota/write failure while affected and
unrelated work run. Real PTYs then verify refusal after capacity restoration and
useful unrelated work. The native test prints `AUDIT_REUSE_EVIDENCE` for retained
private transcripts, source hashes and measured state/effects. These are synthetic
advisories and injected failures, not model trajectories. The accounting repair
passed focused manager checks; the added crash/workload/terminal cases remain
untested until final manager execution.
`AuditInstallTests` uses synthetic registry evidence with real confined installation
and import under an adopted profile, live-intent reopening, duplicate replay,
reversed-slot concurrency and abrupt-exit recovery through public dispatch.
Registry publication faults separately exercise insufficient package-row capacity,
assessment-row overhead, failed assessment capture and post-rename completion
capture, including simultaneous stop-state storage failure. Directory and database
observations check publication versus eligibility;
native workloads check affected stopping and unrelated-project survival. These
registry fault cases passed focused checks; full task acceptance remains pending.
Child-process deadlines bound lock
regressions without changing runtime retry or timeout behavior.
`AuditLocalPythonTests` reuses local-source fixture helpers without rediscovering
their suites. Native builds/imports and PTY setup use real tools; registry evidence
and injected capture/quota failures are labeled deterministic fixtures. Independent
directory, database, process and unrelated-project controls distinguish publication,
eligibility, stopping and uncertainty. These additions await manager execution.
The local setup PTY case prints a private `AUDIT_LOCAL_TERMINAL_EVIDENCE`
directory containing both attempts' original transcripts, input/exit records,
digest receipts and source hashes. Before recovery or cleanup, it also records
the exact monitor's service result, attempt-scoped journal (80 entries, at most
64 KiB), heartbeat, runtime identity, setup phase and up to 32 project/workload
rows. Missing or truncated diagnostics are explicit; no credentials, environment
values or full controller database are copied. The monitor emits one first-failure
location record per process, with stage, exception class and up to eight frames,
excluding exception payloads and locals. These diagnostics survive fixture
cleanup; keep them outside the public checkout. The local setup retry remains
in full native acceptance.
The monitor atomically replaces its private current-process identity snapshot
on restart using one reusable staging file; it does not overwrite audit history.
An identity-capture failure appears in monitor health and the bounded journal
diagnostic, while supervisor reconciliation continues. A retained snapshot can
describe an earlier process: check its PID/time and current health before using
it as runtime evidence. `AuditMonitorRecoveryTests` covers replacement, interrupted
staging, write failure and symlink isolation with local fixtures; the real PTY
retry remains part of manager acceptance.
`AuditTerminalTests` and `NativeAuditTests` require the native manager for exact
terminal decisions, real workloads, quota/capture faults and unrelated-work controls.
They reuse the existing workspace/daily/reassessment fixtures without duplicating
their entire discovered suites.

## Test reproduction

Use the [isolated source-test installation](README.md#run-the-tests) on a Linux
VPS before native tests so detached user services import this exact checkout.
An editable source install is necessary; `PYTHONPATH` alone is insufficient.
Fresh installed-user acceptance uses separate wheel installations, never that
editable environment. With the native prerequisites ready:

```sh
PTW_LINUX_TESTS=1 python -B -m unittest discover -s harness/tests -p test_product_audit.py -v
```

Native checks require systemd user services and namespace/confinement tools.
They have not been run in the coding sandbox. Synthetic faults use private
fixtures; do not exhaust shared disk space or run benchmark workloads on a laptop.
Full task acceptance still requires all finite checklist items, native cases with
zero failures/skips, and the manager's unchanged checks. This guide reports
behavior and limits, not future pass counts.
