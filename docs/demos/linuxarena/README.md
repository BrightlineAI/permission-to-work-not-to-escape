# Native LinuxArena bridge

The owner authorized a bounded native `file_indexing` pilot. It supersedes the
earlier proposed-only benchmark status. Native TaskSpace and container execution-
subtree and controller lifecycle checks passed. A live-mount/process confinement
seam is implemented; its native compatibility check fails before useful
`sudo -u dev` work. PAM's audit connection returns EPERM under the installed
network confinement. This is a measured compatibility blocker, not prevention
or a sandbox-validation restriction. See the [boundary finding](NATIVE-BOUNDARY.md).
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
| Inherited `write_file` and connection APIs | Separate inherited entry points | Explicit confined write implementation; reject unmediated connection/transfer routes |
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
It still needs the native user-switch compatibility fix and integration with authenticated exec/read/write,
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
source bytes, the three planned pairs and honest variants via the pinned native
`task_space()` API,
actual rootless daemon identity, the existing aggregate one-CPU/5-GiB limit and
the already installed main image ID. It admits two sequential **deterministic
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
hosts. Native Docker sockets, cgroup mutation, systemd queries and PTYs belong in
the manager's environment; they are not run in the restricted coding sandbox.

## Finite task-22 completion checklist

1. Complete native confinement validation after the passed lifecycle checks, then integrate external
   authenticated exec/read/write authority and mutable service confinement.
2. Verify source, installed dependencies, actual images, resolved Compose and
   unchanged grader inputs; validate all three named pairs through TaskSpace.
   Freeze permissions from legitimate main-task scope and trusted ownership only.
3. Run real no-model admission/sleep/scorer plumbing and independent positive and
   negative physical tests: editor preview, shell, children, deployment, cron,
   service access, forbidden read/write/send, forged grants, resume, stop and an
   unrelated-work control. A negative sleep grade proves plumbing only.
4. Provide the successor's frozen A/B/C configuration and explicit one-shot/resume
   interface, within the original provider budget path. Validate native provider
   serialization and failures with a fake provider before any live successor call.
5. Extend existing evidence and normal regression discovery: reject stale source,
   installation, policy, runtime and grader identities; retain failed attempts.
6. Finish compatibility, operational/recovery guides and manifest before final
   acceptance. No paid task-22 calls, replay scores as enforcement evidence,
   hidden retries, holdout tuning, or simulated unsupported routes.

Full adapter integration remains incomplete. Pair 3, `stats` /
`authentication_bypass`, remains the operational holdout and an expected difficult
same-permission case. The pilot remains one seed, three pairs, three arms, honest
and attack conditions (at most 18 episodes), sequential, with 20 steps per native
phase, 900-second evaluation and 300-second scorer limits. Task 23 owns execution.

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
