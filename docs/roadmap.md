# Roadmap

The bounded [dependency and task-scope demos](demos/README.md) add executing-code
containment and useful local recovery to the existing report demo. Their finite
checklist and actual missing coverage are maintained there. The dependency native
prerequisite passed; the three-arm task-scope milestone awaits physical validation.
No complete new demo acceptance is claimed.

The owner-authorized [demo MVP plan](../harness/DEMO.md) adds a same-task sandbox
comparison and useful local report workflow, followed by separately scripted
worker/resume escalation. A [privacy-reviewed historical sample](../harness/validation/demo-20260919/README.md)
records paired completion and prevention, physical stopping, negative controls and
timing. Final-source task-18 acceptance and task-19 presentation/audience work remain
separate gates.

For the authorized single-host extension, the [current contract page](../harness/SAFETY.md)
and [reviewed section 11](PROJECT-SAFETY-EXTENSION-REVIEW.md#11-reviewed-disposition-and-minimum-implementation-contract)
govern current work. The broader roadmap below remains research direction and
does not replace those bounded requirements or claim completed verification.

The first release is a research prototype and an inspectable experiment archive. The newer [local harness](../harness/README.md) implements reviewed policy proposals, scoped repository operations, checked Python/npm installations, a unified Codex runner, narrower tasks, durable shared counters, automatic local stopping and retrospective log review. Broader deliverables below remain research and extension work.

| Stage | Deliverable | Acceptance evidence |
|---|---|---|
| 1. Repeatable evidence | Independently runnable experiments, local dependencies, case lists, raw results, hashes and audit commands | Fresh isolated run plus agreement between raw records and reported metrics |
| 2. Policy authoring | User-reviewed prose-to-typed policy workflow; contradiction and missing-scope checks | Held-out human-reviewed policies; invalid cases fail clearly; permitted work stays usable |
| 3. Runner adapters | Stable request/context interface; filesystem, credential broker and service adapters | Identical contract tested across tools, batch calls and native delegates |
| 4. Shared enforcement | Durable, deduplicated violation state; revoke admissions and terminate work across hosts | Retry/race/restart tests; no late effects; unrelated jobs unaffected |
| 5. Audit | Protected event export; periodic review of missing controls and policy conflicts | Auditors can reconstruct why an action was permitted, denied or missed |
| 6. Assurance | Findings, owners, deadlines, repairs and repeatable evidence of closure | A dashboard links each closed finding to a policy/control change and a passing retest |

The eventual workflow is: **write policy → review → apply controls → probe → repair → audit → verify closure**.

Broader coverage needs evidence, not just more integrations. Installation now checks known vulnerabilities and release age. Continuous rescanning, malware detection, external credential/service adapters, distributed stopping, protected audit export and assurance remain separate extensions.
