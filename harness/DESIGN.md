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

| Component | Responsibility |
|---|---|
| policy.py + JSON Schema | Typed proposal, subset checks, resource inventory, content bound approval |
| store.py + SQLite | Immutable activated snapshot, authenticated session binding, shared counters, idempotent requests and audit metadata |
| supervisor.py + systemd | Admission lock, registered cgroups, confirmed stop and retry |
| bubblewrap + nono | Kernel file restrictions inherited by subprocesses; hidden host resources, process and network namespaces |
| codex.py | Pinned Codex proposer and bounded JSON resource request loop |
| audit.py | Read selected logs without execution; classify supported requests and flag unknown routes |

OPA and agentgateway remain useful for richer API deployments, but would add services without helping the first three file operations. The frozen booking controls and existing experiment adapters remain available separately. New harness results do not revise the paper.

## Consistency and failure behavior

SQLite holds the approved policy, resource inode bindings, session ancestry, counters and event records. An advisory lock serializes mutations from independent local runner processes. Every request binds identity from its adapter credential, not fields supplied by the model.

File access walks directory descriptors with O_NOFOLLOW, rejects nonregular or multiply linked files, and checks the activated inode. Resource content is limited to 1 MiB. The initial adapter intentionally requires existing files; atomic editor replacement needs an explicit future resource lifecycle adapter.

A request intent is committed before its effect. If a process dies before recording completion, the next controller instance marks the result uncertain and stops that project. It does not silently replay an append. Completed event IDs are idempotent; reusing an ID with a different body is rejected.

Denied actions increment project and relevant task counters once. A stopped project cannot admit another request, parent, delegate or workload. Admission and launch registration use the same lock. The stop decision is committed before systemd termination, and confirmation is reported separately. Keep ptw watch running to retry failed terminations.

Normal completion does not imply task success. The walkthrough verifies the actual UI content and unchanged private resources. Linux tests require working positive controls before interpreting negative results.

## Codex boundary

Version 0.154.0 is pinned. The trusted runner selects the model, disables native shell, delegated model tools, browser, apps and plugins, applies a filesystem deny profile, and uses an empty work directory. Controlled file content arrives only through broker results. The Codex runtime retains its operator authentication, but its model is not given session tokens or controller access.

Each model step proposes JSON. The trusted runner executes that request or denies it, then supplies the result on the next step. This is deliberately a narrow first adapter rather than a universal hook into native Codex tools. Model runtime processes are registered with the same project supervisor, so a stop also reaches an in flight model call.

The optional operator workload adapter grants exact mounted files, not their containing directories. Append only authority is not promoted to an operating system write grant; it stays a broker operation. Its raw OS denials are not automatically counted as semantic broker violations. Use the broker for agent actions; workload confinement is a second execution boundary.

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
- General file trees, external recipients, credentials, remote services and cloud resources require effect specific adapters. Do not emulate them by exposing an unconstrained shell.

To add an adapter, reuse the reviewed policy and trusted session identity, mediate the actual effect, preserve counters, and add positive, negative, delegation, restart and stop tests before widening scope.
