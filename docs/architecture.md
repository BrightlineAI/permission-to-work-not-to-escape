# Architecture

## The contract

A job receives explicit authority from a trusted operator. Tool access, possession of a credential, retrieved instructions and a worker's own claims cannot enlarge it.

The proposed boundary is the project, not just one parent and its children: every participating agent must stay within that scope. The native experiments exercise one parent and its workers. Multiple parent agents, nested task scopes no broader than their project, and persistent coordination across hosts remain extension work.

| Layer | Input | Responsibility | Current implementation |
|---|---|---|---|
| Policy | Trusted job description and tool interface | Name allowed actions, resources, destinations, approvals and delegation limits | Constrained typed compiler; model proposer and optional critic in the core experiment |
| Controls | Compiled policy, request, trusted context | Decide whether this particular request is authorized | `vega_core.authorize.authorize_d`; gateway and DTAP experiment adapters |
| Execution boundary | Authorized decision and bound process identity | Mediate effects through tools, shell and workers | nono/Linux confinement tests; native Codex permission tests; no universal adapter |
| Enforcement | Verified violations bound to a job/session | Deny requests, accumulate violations and stop registered work | `permission_to_work.escalation.Registry`; Docker/systemd adapters in experiments |
| Verification | Permitted/forbidden probes and external observations | Find exposed routes, preserve useful access, repeat after repair | `permission_to_work.diagnostic`; permission and native experiments |
| Audit | Logs, policy intent and incident history | Identify missing, conflicting or obsolete policies and controls | Planned |
| Assurance | Audit findings, owners, changes and retests | Show that a finding was resolved and remains resolved | Planned |

Controls are external to the acting agent. Their implementation can be public; protection must not depend on hiding source code.

## What is reusable now

- `src/permission_to_work/policy.py`: typed schema, deterministic compiler and the study's constrained contract validator. Extracted unchanged from the core experiment.
- `src/vega_core/`: request/policy parsing, contextual authorization, approval and provenance registries, delegation utilities, experimental gateway/executor.
- `src/permission_to_work/diagnostic.py`: route diagnosis from a public contract and complete paired observations. Produces `EXPOSED`, `PROTECTED_ON_THIS_PROBE` or `INCONCLUSIVE`; reports utility separately.
- `src/permission_to_work/escalation.py`: in-memory, thread-safe shared job state. Returns stop transitions and affected workload IDs. A trusted adapter must actually terminate them and record the outcome.
- The [booking example](../examples/booking/README.md) combines compilation, approval checking and shared violation counting without external effects.

The tool package and frozen experiment code are deliberately separate. Improving the library must not silently change the implementation behind a published result.

## Interfaces to preserve when adding adapters

1. Bind `job_id`, `principal`, ancestry and process/workload identity outside the model. Do not accept the model's claimed identity as evidence.
2. Resolve approvals from a trusted registry; bind issuer, resource, amount, validity and job. A nonempty string is not approval.
3. Intersect delegated scope with parent authority. A worker's working directory or choice of tool must not grant more access.
4. Check every item in a batched call. Constrain routes that bypass the mediated tool, including subprocesses and direct network clients.
5. Submit each verified violation once. The current registry does not deduplicate repeated `event_id` values, persist state across restarts, or coordinate multiple hosts.
6. At stop: revoke new admissions and terminate existing registered work. Check actual effects afterwards; a stop acknowledgement alone is insufficient.
7. Keep unrelated jobs usable. Test both denial and legitimate work.

## What validation does not establish

The core validator uses a narrow, template-like description and trusted tool fields. It is not a general semantic parser or a formal proof that prose and policy agree. A typed policy can still express the wrong intent. Human review and independent probes remain necessary.

Data-label tests use synthetic canaries, not general information-flow tracking. The DTAP hook checks lexical paths and has documented symlink/TOCTOU limits. The native stop adapter relies on Linux cgroup membership and the trusted host; it does not undo completed remote actions.

Equivalent policy engines, operating-system controls and process supervisors may enforce the same contract. The aim is interoperable policy and verification, not replacement of every existing control.
