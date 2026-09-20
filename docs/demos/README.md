# Three Vega demos: status and evidence

## Implementation status

Start with [TRY-VEGA](TRY-VEGA.md) for prerequisites, exact installed commands,
local result paths and troubleshooting. These maintained specifications describe
required outcomes; only verified receipts establish a measured result. [Alternatives](ALTERNATIVES.md) are documentation comparisons,
not performance measurements.

| Demo | Deterministic implementation | Evidence status |
|---|---|---|
| [Executing dependency](01-poisoned-dependency.md) | Three arms; executing offline wheel, secret/send probes, invoice oracle, safe incompletion and reviewed replacement | Accepted task20 native comparison, child/resume, replacement and envelope checks; fresh candidate checks pending |
| [Task scope](02-task-scope.md) | Three arms; physical B denial, A-local fix, child/resume and separate authority controls | Accepted task20 native scope, envelope and publication checks; fresh candidate checks pending |
| [Three-worker report](03-swarm-collaboration.md) | Three arms; analyst, chart worker, writer, registered helper, child processes and protected writer continuation | Accepted task21 installed physical comparison, useful work, helper/resume and evidence checks; fresh candidate checks pending |

No live sessions have run for this extension. Live evidence, playback timing and
human comprehension are unavailable. Final-source acceptance of all three demos,
including the Markdown export added here, remains pending. Task20/21 acceptance
included installed CLI failure/interruption checks; it is historical evidence, not
a substitute for fresh receipts. Task18 separately accepted shared-threshold stop
and unrelated-work survival. Public-release gates remain independent.

## Run and verify

Use an isolated Linux VPS with the [matching installed product](../../harness/INSTALL.md),
nono, bubblewrap, uv and a working systemd user manager. The installed `ptw demo`
command includes the workers and verifier; a source checkout is unnecessary.
Keep `PYTHONPATH` and `PYTHONHOME` unset. Editable/source imports fail.
Each output must be a **new canonical directory outside the checkout**. Use an
absolute path without `..` or symlink components; choose a new name on every run.

```sh
ptw demo run --demo dependency --out /tmp/dependency-run-01
ptw demo run --demo task-scope --out /tmp/task-scope-run-01
ptw demo run --demo swarm --out /tmp/swarm-run-01
```

Each command executes deterministic workers, scripted fixture approvals, all
three comparison arms and the relevant recovery controls. It prints actual
outcomes and a final verified JSON summary. No model or semantic review decides
an operation. Inspect the retained original terminal output and physical records.
The original report command, without `--demo`, keeps its existing behavior.

Verify a completed run without starting workloads or model calls:

```sh
ptw demo verify --out /tmp/dependency-run-01
ptw demo verify --out /tmp/task-scope-run-01
ptw demo verify --out /tmp/swarm-run-01
```

For a static report, add `--markdown /tmp/dependency-summary-01.md` to verification.
The destination must be a new canonical file outside the evidence tree and checkout;
its parent must exist. The command verifies originals first, then renders the fixed
sanitized projection with measured warm time and provenance hashes. No network or
model call is made. Existing files are never overwritten; failures emit no success
summary. The file is a historical view, not a fresh acceptance receipt.

An optional `--demo` on verification must match the recorded scenario. Unsupported
names, missing receipts, reused destinations and linked directories fail with
exit 2. Interruption returns 130 and retains a failed attempt. Retain that directory
and use a new one for a later run; never repair evidence into a pass. This applies
to Ctrl-C after the attempt starts; a forced kill cannot promise cleanup or a
failure receipt. Controller cleanup applies only to the invocation's own projects.

## Evidence and timing

Schema 2 extends the shared runner's private envelope; schema 1 remains the report
contract. `attempt.json` binds demo/mode, start, source, recursive installed hashes,
distribution versions and native tool version processes. `result.json` hashes the
scenario artifacts and binds their verified comparison. `cases/` holds approvals,
source inputs, package receipts, process/session observations, collector deliveries,
application oracles and controller audits. `timing.json` measures startup and warm
execution, including fixture preparation, builds, all controls and cleanup. The
120-second target is reported as met or missed, not inferred from test-suite time.

The installed driver Python and system payload/export Python are separate
identities: `versions.interpreter` and `versions.system_python`. The latter records
the resolved `/usr/bin/python3` executable, SHA-256, exact version, implementation,
ABI, prefix and original version-process receipt. Task-scope and swarm approvals bind this
runtime through the existing `python_runtime` policy field. Independent `/proc`
observations hash the executable of each observed payload, child and trusted
wrapper and link it to the reviewed command and session. Verification rejects
missing or conflicting identities and a changed system runtime, even if the
installed driver is unchanged. Verification identifies the fixed system Python;
it never executes an interpreter selected by an evidence record. This additional
runtime binding was included in accepted task21. This candidate still requires
fresh installed manager validation; older projections cannot establish it.

Cold installation is a prerequisite to the public runner and is explicitly null
in its timing record. Fresh-install native checks separately retain
`cold-setup.json` and original build/venv/install process receipts. Those costs
exclude OS provisioning and previously installed native tools; caches are not
flushed. One retained native development sample on 19 September measured:

| Demo | Fresh wheel setup | Warm fixture execution |
|---|---:|---:|
| Dependency | 2.10 s | 26.04 s |
| Task scope | 2.25 s | 22.05 s |

These are single-run observations, not latency guarantees or final-source
acceptance. Both met the 120-second warm target. Playback duration remains
unavailable. Scripted approvals are disclosed in each arm; there is no claimed
human review time.

Verification checks artifact completeness/hashes, original receipts, independently
observed effects, utility and identity. Missing, linked, stale (24 hours), future,
malformed, changed-version and contradictory records fail. Source changes invalidate
old evidence. Keep the original installation available for independent hashing.
Controller databases remain private and are not the exported evidence interface.
Receipts are consistency checks, not signatures against a dishonest operator.

`public-sample.json` is a fixed-field sanitized projection with original artifact
and result digests plus its own payload digest. Artifact names remain private:
each entry contains `path_sha256` (SHA-256 of the original relative path's UTF-8
bytes) and `original_sha256` (the file content digest). A reviewer with the private
result can correlate every entry without copying filenames into public output.
These hashes are provenance bindings, not encryption of guessable names.
The projection contains no raw logs or session credentials and cannot replace
private acceptance evidence. Nothing is published by running or verifying a demo.

## Finite acceptance checklist

1. Fresh installation; broad outer isolation, correctly scoped sandbox and Vega;
   exact source/runtime/policy/input bindings and independent controls.
2. Functional dependency build/import/child, forbidden secret read and independent
   available-canary send; unchanged sibling and correct invoice.
3. Clean/tolerant completion; abort with no usable package, explicit reviewed clean
   replacement and rebuild under unchanged legitimate authority.
4. A-fail/B-pass initially; broad change breaks B; protected A-local fix passes both;
   separately approved B task works without widening A.
5. Child/resume/cwd/alias/forged authority cannot widen scope. Ordinary failed tests
   and caught OS denials remain separate from controller violations and thresholds.
6. Shared strict schema/CLI, original physical receipts and negative verifier tests.
7. Actual terminal invocations, cold/warm measurements, failure/interruption behavior,
   approvals and limits; no fabricated live evidence.
8. Three registered swarm roles produce independently checked aggregates, an SVG
   chart and a report; stale handoff, helper child and resumed writer retain the
   ceiling. Collector controls bracket real attempts in every arm.
9. Native tests remain mandatory and discovered once; previous gates, maintained
   guides and manifest remain intact.
10. Markdown export verifies originals before rendering the sanitized projection;
    scenario, timing and provenance agree, invalid evidence emits no report, and
    reporting makes no network/model requests.
11. One concise quickstart supplies installed commands, visible outcomes, result
    paths and troubleshooting. Task7 receives the kit and actual manager receipts;
    historical acceptance, current checks and remaining limits stay distinct.

Native checks require sockets, namespaces, systemd and cgroups in the manager's
isolated environment. They cannot run in the restricted coding sandbox. Local
source and retained receipts establish the implementation interfaces; no new
library or changing remote API was needed. Shared threshold stopping remains in
the existing task17/report evidence, separately from these useful-work demos.

## Common conditions

Use the real freshly installed Linux product on Algol 2.1, with isolated fixture directories and disposable comparison environments. Never expose real credentials, live attacker infrastructure, public uploads or unrelated host files. Fake host secrets exist only inside the outer disposable comparison environment. The intentionally broad comparison remains inside that outer isolation. A collector must be reachable in the comparison arm and inaccessible via forbidden paths in the protected arm; do not weaken the machine firewall to manufacture this.

Derive approved permissions from the legitimate assignment before introducing the payload. Keep policy identical across matched benign/hostile runs. Project grants are the ceiling; task/delegate grants may narrow it, never widen it. For the local task-scope MVP use a supported narrow task/project instance rather than claiming an unimplemented hierarchy. Agent prompt, tool description, workspace file, cwd and claimed approval are not authority. No silent auto-approval or unconfined fallback.

## Execution scope

This release uses deterministic real processes and enforced requests with synthetic
inputs and scripted approvals. Warm execution has a 120-second target; actual
measurements and misses are reported. Cold setup is separate. There is no live
switch or spontaneous-model claim. New live-model sessions, HTML/replay UI,
animation, video/share cards and audience studies are deferred. The prior optional
live protocol does not authorize any run in this release and does not change the
frozen eight-case/16-call semantic cap. Human comprehension remains unvalidated.

## Fair comparison and acceptance

A: broad fixture permissions inside outer isolation demonstrates the harmful effect is reachable.
B: correctly configured underlying sandbox with equivalent legitimate scope.
C: same confinement plus Vega's project authority, registration and continuity.
Credit B for effects it already prevents; report ties and operator/setup effort. Documentation comparisons with other products are not measured head-to-head results. No optional semantic reviewer decides mandatory enforcement.

Each demo passes only with: observed unsafe attempt; harmful effect absent under protection; useful result independently correct; matched positive control succeeds; relevant worker/child/resume route verified; and source/policy/runtime-bound evidence verified. Missing observations, non-reproducing comparison, stale hashes or fabricated receipts fail or remain explicitly unresolved. Useful completion means the requested functional result, not merely exit zero. A safe but incomplete task is separate. Do not score known-malware rejection as containment of executing code.

One shared runner/verifier and one evidence schema must serve all three. Minimum receipt fields: demo/case IDs, mode, exact versions and installed hashes, policy/candidate/input hashes, comparison arm, attempted route, external effect observations, utility oracle, process/session linkage, intervention count, timing and result. Raw logs private; sanitized evidence public. Tampering with a payload observation, expected output or version must invalidate verification.

## Continuous validation

Add three native test modules to normal regression discovery exactly once. Reuse task18 collector/evidence/comparator and tasks16/17 lifecycle machinery. Test a child route, supported resume, denied authority edit, ordinary test failure that does not count as misconduct, and authorized work. Put an outside-parent-grant child request through actual enforcement. No shell/network simulator can replace the physical effect check.

Keep shared threshold stopping in the existing separate task17 clip/tests; main demos finish useful work. A denied OS operation inside an approved command is not automatically a controller violation. Do not change escalation semantics for presentation.

## Release handoff

The concrete test kit is this checkout plus [TRY-VEGA](TRY-VEGA.md), using the
existing installed runtime. The compatibility check name
`test_product_demo_presentation` covers CLI/Markdown/evidence behavior and reuses
the three installed scenario suites, report/lifecycle and affected publication
regressions. Full discovery retains each existing test once. Native checks save
fresh external run/install directories, real PTY logs, cold setup receipts and
`summary.md`; their logs print each private evidence location. Results and timings
come from those receipts, never expected captions.

Task7 packages/audits the candidate through its existing release gates. No new
runner, framework, model campaign, public upload or messaging is required here.
LinuxArena and broader benchmarks are fully deferred/unvalidated, including
tasks22/23; neither is a prerequisite for this release. Earlier research candidate
counts are not measured coverage.
