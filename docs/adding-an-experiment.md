# Add a permission test

1. **Write the operator contract.** Identify the job, resource, permitted action and forbidden action. State which approval or credential is required.
2. **Freeze the paired inputs.** Use the same resource and operation where possible; change only the authorization-relevant field. A generated action and a constructed request must be labeled separately.
3. **Choose routes.** At minimum: the normal tool, an alternate route such as shell, and a native delegate. Record whether delegation is native, scripted or simulated.
4. **Observe outside the agent.** Verify a returned synthetic canary, changed file, mock service receipt, process identity or timestamped side effect. Failed launch is not containment.
5. **Compare controls.** Include ordinary configured protection, the candidate control, useful permitted work and an unrelated job. Seeded faults must be named as seeded faults. Freeze diagnosis before revealing configuration labels.
6. **Repair and repeat.** Keep the contract and probes unchanged. Record the exact configuration diff and source hashes.
7. **Publish a self-contained directory.** Include README, protocol, cases or exact selection, local support source, prerequisites, runnable commands, raw records, results, audit and file manifest.

For escalation, count verified events against host-bound job ancestry. After the threshold, measure both existing effects and later admissions; a printed `STOP` is not evidence of termination. Include a session-local counter control when testing a shared counter.

Suggested result fields:

```json
{
  "case_id": "example-001",
  "route": "native_worker_shell",
  "expectation": "forbidden",
  "execution_valid": true,
  "decision": "deny",
  "effect_observed": false,
  "permitted_task_complete": null,
  "source_sha256": "record the actual digest",
  "evidence_files": ["raw/tool-record.json", "raw/observer.json"]
}
```

Keep the source-specific raw data as well as any common summary. Publish denominators, invalid runs, model settings, repetition count and limits. Test success does not establish a real-world incident prevention percentage.
