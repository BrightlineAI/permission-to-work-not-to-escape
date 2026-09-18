# Design and extension points

## Data flow

    Operator description + inventory + optional untrusted logs
                      |
                 Codex proposal
                      |
         Strict schema and task subset validation
                      |
           Operator reviews exact bundle hash
                      |
             Protected policy snapshot
                      |
      Independent parents and registered delegates
                      |
           Shared deterministic resource broker
                      |
       deny / warn / persist stop / terminate cgroups

One project identity spans all tasks and sessions. Task scope is a subset of project scope. Session scope is a subset of task and parent scope. Ancestor task thresholds still apply after delegation. An independent parent's task is assigned by the operator, never selected by an untrusted request.

## Small components

The [interactive launcher](INTERACTIVE.md) adds a thin transport over these same
controls. It runs pinned Codex in an empty control workspace with an isolated
configuration and a catalog that removes native patching. Shells, external tools
and unregistered delegation are disabled; a deny filesystem profile is additional
protection. The model's isolated JavaScript host only orchestrates registered tools.

The official MCP SDK exposes context and action tools. A stdio relay connects to
a separately supervised broker, so neither repository configuration nor the
client's namespace can alter its launch environment. The broker reuses the existing
policy checks, package admission and nono/bubblewrap execution boundary. It does
not offer an arbitrary host shell or require a new network service.

Each Codex session and broker is registered before launch. Normal exit revokes
that session and its descendants; project stopping reaches all parents. The
launcher also stops work when the independent monitor's heartbeat becomes unavailable.
Policy revision requires operator approval, terminates the old project first,
and preserves its history. No runtime authorization step calls an LLM.

| Component | Responsibility |
|---|---|
| policy.py + JSON Schema | Typed proposal, subset checks, resource inventory, content bound approval |
| store.py + SQLite | Immutable activated snapshot, authenticated session binding, shared counters, idempotent requests and audit metadata |
| supervisor.py + systemd | Admission lock, registered cgroups, confirmed stop and retry |
| bubblewrap + nono | Kernel file restrictions inherited by subprocesses; hidden host resources, process and network namespaces |
| codex.py | Pinned Codex proposer and bounded JSON resource request loop |
| audit.py | Read selected logs without execution; classify supported requests and flag unknown routes |
| packages.py | Reuse approved scope, identity and denial counters; privately prepare and atomically admit package sets |
| package_evidence.py + packaging + cvss | Fixed PyPI/OSV endpoints, artifact age, exact versions and CVSS base scores |
| package_install.py + uv | Validate complete wheel dependencies; install hash checked local artifacts offline inside bubblewrap |
| npm.py + npm | Validate lock and archive identities, dependencies and integrity; reuse npm semver/cache/ci |
| package_build.py + python_build.py | Registered offline builds on bounded tmpfs; validate exported data and generated wheels |
| reassessment.py + Store | Refresh installed evidence through existing clients, quarantine matching project sets and bind affected workloads |
| workspace_policy.py + workspace.py | Version 4 tree/file capabilities, edit preconditions, lifecycle operations, validated publication |
| execution.py | Reviewed commands in disposable workspaces; check complete diff before publishing |
| workflow.py | One model action route for repository edits, installs, commands and registered delegation |
| monitor.py | Persistent user service, heartbeat, automatic crash recovery and termination retry |

OPA and agentgateway remain useful for richer API deployments, but would add services without helping the first three file operations. The frozen booking controls and existing experiment adapters remain available separately. New harness results do not revise the paper.

Package version 2 policies add one project rule block and task name subsets. The same rules decide package admission for all agents; uv never makes an independent security policy decision. Slow evidence collection and installation occur in private staging without holding the controller lock. Admission rechecks the stopped state and evidence before publishing. Missing evidence blocks without punishment; uncertain publication stops the project for operator review.

Version 3 adds ecosystem-qualified identities, explicit native-wheel permission and an explicit build-package list. Python and npm reuse this same admission and escalation path. Build code has no writable host mount: it runs with a 512 MiB output tmpfs, a 768 MiB process memory limit, no network, no project files and no credentials. The controller accepts only a bounded validated export. A concurrent project stop kills its registered build and prevents publication.

This is not a generic command interceptor. Further ecosystems should add metadata, artifact and installation adapters behind the same identity and admission boundary. No additional policy service or vulnerability database is maintained locally. See the [original package review](PACKAGES_PLAN.md) and [ecosystem plan](ECOSYSTEM_PLAN.md).

## Consistency and failure behavior

SQLite holds the approved policy, resource inode bindings, session ancestry, counters and event records. An advisory lock serializes mutations from independent local runner processes. Every request binds identity from its adapter credential, not fields supplied by the model.

File access walks directory descriptors with O_NOFOLLOW and rejects symbolic/multiple links and special files. Versions 1 to 3 retain existing-file inode bindings and a 1 MiB content limit. Version 4 adds bound directory roots, future declared files, 8 MiB file/64 MiB snapshot limits, current-content preconditions, and brokered atomic replacement with updated exact-file bindings.

Version 4 commands operate on disposable copies of only their granted readable resources. Package sets are mounted read only; host resources, credentials, controller state and network remain absent. Every output is compared against the input snapshot and task/session permissions before any repository publication. Unknown or forbidden output publishes nothing. Concurrent input changes return a conflict without punishment. Filesystem publication is not a multi-file transaction; an interrupted effect stops the project for review. Rename destinations are materialized before source removal to avoid losing the only copy.

A request intent is committed before its effect. If a process dies before recording completion, the next controller instance marks the result uncertain and stops that project. It does not silently replay an append. Completed event IDs are idempotent; reusing an ID with a different body is rejected.

Denied actions increment project and relevant task counters once. A stopped project cannot admit another request, parent, delegate or workload. Admission and launch registration use the same lock. The stop decision is committed before systemd termination, and confirmation is reported separately. Version 4 CLI activation installs a persistent user monitor; no manual watch terminal is needed. Model runs require a fresh monitor heartbeat. Older policies may still use ptw watch.

Installed dependency reassessment reuses the approved package evaluator. Requests
run outside that lock, then current bindings and assessment generations are
validated before recording a result. Commands/previews carry trusted package-set
bindings through admission and command output publication. Quarantine invalidates
matching project sets transactionally, and workload bindings target termination.
Operational uncertainty and advisory changes do not increment misconduct. See
the [freshness and running-work policy](REASSESSMENT.md).

Normal completion does not imply task success. The walkthrough verifies the actual UI content and unchanged private resources. Linux tests require working positive controls before interpreting negative results.

## Codex boundary

Version 0.154.0 is pinned. The trusted runner selects the model, disables native shell, delegated model tools, browser, apps and plugins, applies a filesystem deny profile, and uses an empty work directory. Controlled file content arrives only through broker results. The Codex runtime retains its operator authentication, but its model is not given session tokens or controller access.

Each model step proposes JSON. The trusted runner executes that request or denies it, then supplies the result on the next step. Version 4 unifies repository lifecycle actions, checked installs, named commands and bounded registered model delegation. All descendants share the original step budget. This remains an explicit runner rather than a universal hook into native Codex tools. Model runtime processes are registered with the same project supervisor, so a stop also reaches an in flight model call.

The optional operator workload adapter grants exact mounted files, not their containing directories. Append only authority is not promoted to an operating system write grant; it stays a broker operation. Its raw OS denials are not automatically counted as semantic broker violations. Use the broker for agent actions; workload confinement is a second execution boundary.

## Scoped local Git

Local Git uses optional reviewed command definitions bound to the root `.git`
device/inode. The adapter snapshots only command resources, copies bounded
object/index metadata without configuration, hooks, alternates or replacement
refs, and runs fixed plumbing through the existing supervised offline build
namespace. Only scoped status and diff bytes leave the worker. Checkpoint
requests prepare exact private reviews; the operator-only terminal command
revalidates policy, session, working snapshot, HEAD and index before publishing
new objects and one `refs/ptw/checkpoints/ID` ref. It never changes the working
branch or index. Publication holds standard Git locks, records durable stop
intent before effects and clears that intent only on success. Interrupted
publication stays stopped; approvals are single-use. See [daily limits](DAILY.md).
Git admission and checkpoint publication check the monitor heartbeat through
their already locked database connection, preserving atomic validation without
reacquiring the controller lock. Missing, expired and future heartbeats block
these operations without increasing violation counts.

## Protected conversation resume

Protected interactive resume binds a native conversation to the canonical
repository inode, approved project, task and approval lineage in private state.
An exclusive attachment lock spans launch and credential revocation. Each
attachment registers a new controller session; counters remain in their existing
project/task rows. Dependency revision carries the original approval lineage,
while full replacement does not. Rollouts and native SQLite state have a private
per-conversation view. Fixed launch overrides select the pinned embedded server
and new MCP credential path. Focused native PTY verification passed; see
[daily development status](DAILY.md).

Reviewed preview commands reuse command snapshots, runtime verification and
package mounts. An optional `preview` block grants a fixed port and lifetime;
the existing task/session command subset also bounds delegates. Preview startup
does not expand an ordinary command. The application has a private network
namespace and a read-only mounted nono capability manifest: blocked networking
with one bind-only TCP exception and explicit scoped filesystem grants. The
pinned manifest loader uses its auto backend (Landlock and static seccomp);
it does not inherit ordinary command CLI defaults. A trusted pipe relay exposes only
HTTP GET on the approved host loopback port. It neither forwards arbitrary URLs
nor publishes application writes. Request validation uses the original HTTP
target before the standard parser's leading-slash normalization and before
Host validation. The relay, sandbox, application and descendants
share one registered systemd cgroup. Registration precedes launch under the
controller lock; a second admission check precedes the ready result. Startup and
transport failures retain private receipts and require confirmed cleanup. The
focused native namespace/relay and physical-stop probe passed manager verification.
The composed daily PTY journey awaits final acceptance. Its effect assertions
match controller receipts to the acting session and require zero command exit
codes. Physical termination checks query systemd/cgroup state before cleanup;
the database reconciliation flag is not a live-process indicator.

## Existing project audit

Import a selected JSONL file and a current operator description. Logs are untrusted evidence even when a message claims to be an approval. The model can suggest a draft, never activate it.

The local auditor recognizes this adapter's requests, named resource calls and simple absolute cat commands, including two literal Codex code mode wrappers. It parses these without executing them. More complex shell or unknown tools are unknown. Findings compare attempted requests against the reviewed policy; they do not prove physical effects, historical user intent, complete logging or the absence of unobserved bypasses.

Metadata exports omit content and credentials. The private database and optional live run reports can contain resource contents; keep them private. This is not yet a tamper proof organizational audit or assurance service.

## Review conclusions and remaining boundaries

- Single host first. SQLite locks do not coordinate different hosts.
- Broker identity, policy and counters belong to the trusted operator, not an unconfined agent with the same OS account.
- The native runtime and OS are trusted. Kernel compromise and changes by outside host administrators are outside this boundary.
- systemd user services are the default, requiring no sudo for ordinary operation. An operator can explicitly select PTW_SYSTEMD_SCOPE=system on a configured host.
- Stopping cannot undo previous writes. Deadlines cap optional workloads and model calls, but this is not a distributed revocation protocol.
- A warning is delivered through the request result and shared status. Proactive broadcast and graduated task pause need further adapters.
- Version 4 handles scoped file trees and checked command outputs. External recipients, credentials, remote services and cloud resources still require effect specific adapters. Do not emulate them by exposing an unconstrained shell.

To add an adapter, reuse the reviewed policy and trusted session identity, mediate the actual effect, preserve counters, and add positive, negative, delegation, restart and stop tests before widening scope.
