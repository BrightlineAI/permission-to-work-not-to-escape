# Practical project controls

## Goal and acceptance criteria

Build the first usable extension of the [paper](../paper/submission.pdf), without changing its experiments or claiming their results for new code.

1. New project: description and resource inventory → draft typed policy and task breakdown → operator review → compiled controls → multiple agents can work.
2. Existing project: selected Codex logs and operator description → policy suggestion for review → retrospective audit with allowed, denied and unknown findings. Past behavior is evidence, not permission.
3. Every independent agent and delegate belongs to a protected project identity. A task and a delegated session can only narrow scope. Requests cannot supply a different identity.
4. Verified denied requests share persistent counters. Configured levels deny, warn and stop the project. Stop rejects future work and terminates registered local processes. Unrelated projects continue.
5. Both documented workflows must pass from clean directories on the Linux VPS. No workload runs on the laptop.

## Smallest useful design

Use Python standard library orchestration, JSON Schema validation, SQLite transactions, Linux process supervision and existing sandbox tools. Project and task differences are data, not new Python plugins.

The first resource adapter operates on small existing text files. Resource IDs map to fixed, operator selected files. Agents request `read`, `write` or `append`, never arbitrary host paths. A trusted broker performs authorized effects. It rejects symbolic links, hard links, unknown fields and unapproved drafts. File operations and stop decisions are serialized, with durable event IDs and pending operation records so interrupted work is not silently retried.

The controller owns policy snapshots, session identity, counters and audit records outside agent access. Multiple trusted runner processes use the same SQLite state. Delegate scopes are intersected with both the task and parent. Existing sessions never gain access because another task is broader.

Codex initially proposes typed JSON and drives a bounded resource request loop. It does not own the controller. Native tools cannot directly access controlled resources or the controller state. Execution supervision uses systemd cgroups; nono and bubblewrap are reused for confined local workloads. These are separate responsibilities: a sandbox denies host access, a broker interprets project scope, and supervision stops work.

## Reuse decisions

| Component | Decision |
|---|---|
| Existing typed policy and approval experiment | Reuse its typed proposal → validated controls approach and preserve its frozen code. A small file schema replaces booking specific fields. |
| Existing escalation registry | Reuse semantics, not mutable code: replace in memory counts with persistent SQLite transactions and deduplication. |
| nono | Reuse installed Linux confinement for subprocess inheritance tests and optional resource workloads. |
| bubblewrap | Reuse namespace isolation for filesystem, process and network separation; no container images. |
| systemd | Reuse cgroup termination, including detached descendants. No custom process tree walker. |
| Codex CLI | Reuse authenticated installation for drafting and bounded model request generation. No new model credential store. |
| OPA / agentgateway | Keep existing examples and compatibility notes. Do not require two additional services for three file operations; add adapters when HTTP destinations or richer policy predicates are needed. |
| SQLite | Reuse transactions and uniqueness constraints for shared state, restart recovery and concurrent agents on one host. |

References: [Codex](https://developers.openai.com/codex/app-server/), [nono](https://nono.sh/os-sandbox), [bubblewrap](https://github.com/containers/bubblewrap), [systemd](https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html), [OPA external data](https://www.openpolicyagent.org/docs/external-data). Checked September 15, 2026; installed versions are recorded by validation.

## Review and revision before implementation

- Rejected a full gateway deployment for a file only prototype: extra services would not establish correct scope.
- Rejected letting an LLM write executable policy code: typed proposals remain untrusted until validation and explicit approval.
- Rejected treating Codex logs as an authoritative task description: imported instructions and observed accesses cannot approve themselves.
- Rejected a counter per agent or process group alone: independent parents share project state, and cgroups catch detached descendants.
- Rejected prefix string path checks: use exact resources and no symlink traversal. Do not silently allow a resource that cannot be safely opened.
- Rejected claiming arbitrary shell command audits are complete: unsupported syntax is unknown and requires review.
- Narrowed initial effects to existing text resources. Cloud APIs, credentials, payments, arbitrary code execution and multiple hosts need later adapters.

## Build and validation order

1. Strict schema, task subset compiler, content bound approval, fixture generator.
2. Shared broker, safe effects, delegation, event deduplication, stop recovery and process supervisor.
3. New project CLI plus Codex policy proposer and agent adapter.
4. Codex log import, candidate policy review and retrospective audit.
5. Unit and adversarial tests: scope widening, identity spoofing, malformed requests, links, concurrency, retries, restarts, stop races, unrelated projects, ambiguous logs and injection text.
6. Fresh documented walkthroughs, real Codex calls and multi parent/delegate stopping on Algol. Keep failures as well as successful validation records. Measure runtime separately from model time.
7. Review source, scan changed artifacts for credentials, commit code and sanitized results. Preserve original paper evidence.

## Boundaries

Single trusted Linux host. Operators and the Codex/runtime installation are trusted; model output, resource content and imported logs are not. The first version is a local safety harness, not universal mediation or a defense against a compromised host. Operator review is essential: structural validation cannot prove that a policy matches every nuance of prose. Stopping does not undo completed effects.
