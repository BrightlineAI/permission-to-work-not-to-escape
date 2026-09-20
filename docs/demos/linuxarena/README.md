# Native LinuxArena bridge

The governing sequence is now [TRAIN → TEST → VALIDATE](TRAIN-TEST-VALIDATE.md):
task22 must obtain genuine protected honest `file_integrity` completion, then
finish every required adapter route. Task23 owns duplicate_detection testing and
separate frozen stats validation. The [authorized authentication boundary and
exposure ledger](AUTH-BOUNDARY-AND-HOLDOUTS.md) and [current gaps](DEVELOPMENT-GAPS.md)
distinguish this design from measured results. No qualifying TRAIN completion exists.

The owner authorized a bounded native `file_indexing` pilot. It supersedes the
earlier proposed-only benchmark status. Native TaskSpace and container execution-
subtree and controller lifecycle checks passed. A live-mount/process confinement
seam is implemented. Root/child capability and socket probes completed, but native
`sudo -u dev` still fails account validation before useful work. The bounded PAM
diagnostic records account status 7 with successful audit-socket creation.
Compatibility is blocked pending an authentication/confinement integration that
preserves the credential boundary and native semantics; the socket correction
alone is insufficient. See the [boundary and required probes](NATIVE-BOUNDARY.md).
**The enforcement adapter is not complete and
there are no new benchmark outcomes.**

The [PLAN](PLAN.md), [CRITIQUE](CRITIQUE.md) and [SOURCES](SOURCES.md) are unchanged
copies of the minimum-completion intake. Historical absolute artifact locations
in those snapshots are provenance, not required public installation paths.
Their relative references describe the intake layout; use the maintained
[three-demo contract](../README.md), [alternatives](../ALTERNATIVES.md) and
[all 46 incident source records](INCIDENTS.md) here. These records are context,
not additional required implementations or measured prevention coverage.

## What has been inspected

The read-only retained Git trees report Control Tower
`3d86b8db50c1d5ee8586a13976642fcbe4a34ca3` and file_indexing
`44e200685340997560e15997fd8c7973b6675a48`. Their tracked status was clean at
inspection. The new prerequisite verifies actual bytes against every pinned
Git blob before importing native code; clean Git status alone is insufficient.
It writes hashes to private receipts, not a copy of the benchmark repository.
It also checks the imported sandbox module location. Full installed dependency,
image/Compose/grader and final adapter-policy freeze checks remain required.

| Native route | Source-backed finding | Required boundary, not yet delivered |
|---|---|---|
| `LBDockerSandboxEnvironment.exec` | Applies `_exec_transform`; forwards user, cwd, environment and timeout | Authenticated external actor and confinement before arbitrary execution |
| `read_file`, diff-editor preview | Uses Compose copy independently of exec | Agent reads through confined file operations, including previews |
| Inherited `write_file` and connection APIs | Text/binary writes already call `self.exec`; connection exposes Docker attachment | Reuse writes through confined exec; reject unmediated connection/transfer routes |
| `deploy-indexer` | Copies mutable Python to `/opt/indexer`, synchronizes dependencies and starts persistent server/API processes | Agent-code authority, persistent state and required service network preserved |
| Entrypoint cron and `update_all_users.py` | Root cron can launch deployed code as root or another Unix user | Inherited project ceiling and revocable membership before mutable code executes |
| Redis, Chroma, LDAP | Required native stateful service interfaces | Preserve legitimate connectivity; do not expose service administration as agent authority |
| Setup and scoring | Host orchestration can invoke edited application code | Trusted orchestration separate; edited code still crosses the execution boundary |
| Vega supervisor | Native backend records exact container/cgroup/session identities and revokes admission before subtree termination | Native lifecycle development check passed; killing a Docker client is insufficient |

The rootless runtime supports the tested revocable subtree while retaining the
control process and filesystem. The lifecycle seam now uses Vega's controller
lock, authenticated session and existing event journal. Registration binds the
kernel boot, cgroup inode, immutable container ID, control-process namespaces,
runtime bytes and session grants. Each stopped trusted launcher has a durable
intent before release; interrupted launches cannot be automatically replayed.
Project stopping, session surrender and supervisor reconciliation share the
native termination backend. Missing or replaced identities remain unconfirmed.

Reopening an active controller binding does not create authority. Closed/stopped
sessions, changed runtime/grants and forged or unrelated credentials fail admission.
Revocation survives controller reconstruction; a failed storage write still
attempts physical termination and reports uncertainty. These APIs are trusted host
integration points, never model tools. The new [namespace seam](NATIVE-BOUNDARY.md)
pins live resources for bubblewrap and applies installed nono before mutable code.
It still needs a supported native user-switch correction and integration with authenticated exec/read/write,
service ceilings, scorer separation and protected conversation resume.

## Run the prerequisite without a model

On the isolated Linux VPS, use the existing source-test product environment and
the retained Control Tower Python environment. No installation, image download,
daemon creation, proxy change or credential access is performed. An explicit
retained runtime path is required; its sibling `docker/runtime.json` identifies
the already authorized private daemon and resource slice.

```sh
python -B harness/scripts/linuxarena_preflight.py \
  --runtime /absolute/retained/artifacts/runtime \
  --out /absolute/private/new-bridge-prerequisite
```

The output must be a new canonical directory outside Git. Empty `.git` directory
sentinels do not identify repositories; gitfiles, linked or nonempty metadata,
and this source checkout remain rejected. The command checks
source bytes and the three planned pairs' lazy ID membership via the pinned native
`task_space()` API. It resolves only TRAIN honest/attack task objects and refuses
non-TRAIN task-content reads in that inspector. It also verifies
actual rootless daemon identity, the existing aggregate one-CPU/5-GiB limit and
the already installed main image ID. Before either fixture, it samples available
memory and receipt-filesystem free space once. `resources.json` retains the timestamp,
filesystem path/device/directory inode, units, unchanged minima (524,288 KiB memory
and 1,073,741,824 bytes disk), readings and independent failure reasons. The attempt
links this receipt by hash, including on admission failure. Missing/malformed readings
or a receipt-write failure prevent launch. Resource admission is a snapshot, not a
reservation: later exhaustion can still fail the run. Inspect these private records
before arranging capacity; do not lower thresholds, delete retained evidence or
implicitly relocate output. A new authorized attempt requires a new directory.
It admits two sequential **deterministic
compatibility fixtures**, each using at most 0.25 CPU/256 MiB inside that existing
allocation, with no external network, no image pull and a read-only container root.
The native entrypoint,
cron, application, setup and graders are deliberately not run at this milestone.

The fixture's stopped launcher cannot fork or write before admission. The extended
check rejects forged/unrelated sessions, reconstructs the controller, and admits
parent/child heartbeat writers into its registered subtree. Project stop must end
those effects and reject later launches while an unrelated registered domain
continues. Explicitly finishing that unrelated session must also confirm stopping.
A distinct control process and trusted inspection retain access to fixture files.
This establishes only the tested lifecycle prerequisite;
it is neither an honest LLM trajectory nor a sleep/scorer result. The second fixture
tests live permitted and forbidden file effects, children, `sudo -u dev`, isolated
process visibility, permitted TCP/Unix-socket effects, a denied TCP send, and
physical child stopping. Its collector has an independent reachability control.
See the [boundary guide](NATIVE-BOUNDARY.md) for tool staging and isolation details.
These synthetic resources do not freeze permissions for a benchmark task.

Exit 0 means only that these prerequisites completed. Exit 2 reports invalid
inputs, missing resources or a failed prerequisite; Ctrl-C returns 130. Original
process output and an incomplete/failed attempt remain private. Cleanup addresses
only the immutable container ID created by that invocation; a failed cleanup
is an error, not permission for global Docker cleanup. There is no automatic
retry or live-run option. A later attempt needs a new output directory. Interruption
during daemon creation can leave an uncertain creation result in the process
receipt; forced termination can also leave an owned container. Reconciliation
must establish the immutable identity before cleanup; never adopt by name alone.

Normal discovery includes `test_product_linuxarena_bridge.py` once. The native
prerequisite and terminal tests do not skip missing infrastructure. The test has
a local retained-artifact default and accepts `PTW_LINUXARENA_RUNTIME` for other
hosts. Native evidence directories use Python's configured temporary directory
(including the manager's private disk-backed scratch), with a fresh retained
directory for each fixture. They do not override it with `/tmp` or automatically
switch filesystems after a failed admission. Direct CLI runs still use the exact
`--out` location. Native Docker sockets, cgroup mutation, systemd queries and PTYs belong in
the manager's environment; they are not run in the restricted coding sandbox.

## Finite task-22 completion checklist

Use the [finite acceptance checklist](TRAIN-TEST-VALIDATE.md#finite-task22-checklist).
The latest amendment supersedes the earlier task22 model-free-only and two-heldout
plans. Automatic checks stay model-free; explicitly authorized budgeted TRAIN runs
belong to task22 once the secure route and durable accounting are ready. Neither
is ready yet. The limits remain 20 steps per native phase, 900-second evaluation
and 300-second scorer limits, with six attempts reserved for each phase and at most
18 total. Missing cells and failed attempts must remain visible.

The new source-only native prerequisite retains the exact Ubuntu sudo package
sources for review before plugin implementation. See its
[operation and limitations](AUTH-BOUNDARY-AND-HOLDOUTS.md#source-prerequisite-and-current-measurement).
It does not rerun the unchanged failing namespace fixture or import task content.
The native receipt confirms TRAIN-only TaskSpace resolution. Tests use the manager's
configured disk-backed scratch; native resource admission now passes with unchanged
thresholds. The namespace fixture still fails account validation. The source-only
prerequisite passed. The
native comparison established that the same immutable identity command succeeds
before confinement and fails account validation inside it. The
[closed delegation prerequisite](AUTH-BOUNDARY-AND-HOLDOUTS.md#closed-delegation-prerequisite)
now tests native original-request/session callbacks while refusing all mutable
release. Native pipe and real-terminal development checks passed after preserving
`use_pty` metadata. The terminal cases
require actual terminal descriptors, exact identities, exit status and session
cleanup, while retaining raw private transcripts. No original command may run.
Neither diagnostic establishes
protected useful work. Prior all-pair exposure remains disclosed.

A separate [command-child checkpoint](AUTH-BOUNDARY-AND-HOLDOUTS.md#command-child-checkpoint-implemented-native-validation-pending)
now stages the complete distribution-patched sudo source and inserts capability
reduction/filter installation around the native UID transition. It remains closed
to requested work. The native build failed before exercising the checkpoint.
Configure arguments now preserve distribution quoting; a pre-build report refuses
missing or incompatible headers/libraries while preserving every security option.
The pinned image lacks the [required development inputs](AUTH-BOUNDARY-AND-HOLDOUTS.md#command-child-checkpoint-implemented-native-validation-pending);
verified compatible staging remains unavailable. Rebuilt-frontend pipe/PTY and
physical syscall validation must follow that infrastructure prerequisite. This checkpoint
must establish actual child state before namespace and controller release integration.

## Current access and claims

The owner's sanitized receipts dated 19 September show six successful unchanged
Sol/medium request checks through the permanent proxy: HTTP 200 with tool-call
responses, no tools executed, combined known cost $0.008724. This supersedes the
old HTTP 403 as the sole access blocker. It establishes request acceptance only,
not native task success, remaining budget or a completed pilot. Do not repeat
standalone probes. Preserve all unresolved reservations and the $49-accounted /
$50-user aggregate ceiling plus the stricter $25 additional allocation. New
denials or unknown costs halt the relevant work without automatic retries.

The original retained baseline remains incomplete; its old grades do not fill
new pilot cells. Useful work, physical effects, OS denials, controller decisions
and model refusals must remain separate. There is no complete-mediation or
arbitrary-prose-correctness claim.

Only a narrow primary-source check was needed: the kernel documents cgroup
inheritance and population observation in [cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html),
and inherited restrictions in [Landlock](https://docs.kernel.org/userspace-api/landlock.html).
Actual delegation and service compatibility require native tests. Neither source
establishes that this unfinished adapter implements those controls correctly.
No new dependency or repeated literature review was justified.
