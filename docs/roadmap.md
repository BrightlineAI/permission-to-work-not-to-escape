# Roadmap

The first release is a research prototype and an inspectable experiment archive. The newer [local harness](../harness/README.md) implements a small part of the roadmap: reviewed policy proposals, a Codex file adapter, narrower tasks, durable shared counters, local stopping and retrospective log review. Broader deliverables below remain research and extension work.

| Stage | Deliverable | Acceptance evidence |
|---|---|---|
| 1. Repeatable evidence | Independently runnable experiments, local dependencies, case lists, raw results, hashes and audit commands | Fresh isolated run plus agreement between raw records and reported metrics |
| 2. Policy authoring | User-reviewed prose-to-typed policy workflow; contradiction and missing-scope checks | Held-out human-reviewed policies; invalid cases fail clearly; permitted work stays usable |
| 3. Runner adapters | Stable request/context interface; filesystem, credential broker and service adapters | Identical contract tested across tools, batch calls and native delegates |
| 4. Shared enforcement | Durable, deduplicated violation state; revoke admissions and terminate work across hosts | Retry/race/restart tests; no late effects; unrelated jobs unaffected |
| 5. Audit | Protected event export; periodic review of missing controls and policy conflicts | Auditors can reconstruct why an action was permitted, denied or missed |
| 6. Assurance | Findings, owners, deadlines, repairs and repeatable evidence of closure | A dashboard links each closed finding to a policy/control change and a passing retest |

The eventual workflow is: **write policy → review → apply controls → probe → repair → audit → verify closure**.

Start with one runner and one resource boundary. Broader coverage needs evidence, not just more integrations. Malware/version screening and post-access secret leakage are later extensions with their own threat models.
