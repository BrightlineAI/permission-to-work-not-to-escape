# Evidence and data availability

The archive preserves source, protocols, inputs, observations, summaries and failures. It is evidence readers can inspect and challenge, not independent certification that every run occurred as described.

## What is included

| Experiment | Exact input / case selection | Published observations | Known omissions or cautions |
|---|---|---|---|
| Core A–D | 200 case JSON files, operator/injection text, tool schemas, reviewed policies, source revisions | Model requests/responses, captured calls, replay hashes, permitted/forced/model results, service state, preflight and audits | Synthetic adapted requests; most permitted controls are constructed; not native benchmark scores |
| Policy E/F/G | Trusted records, split lists, prompts, candidate/compiled policies; historical source versions | Provider responses, validation errors, attempts, usage and physical evaluation | Older raw E/F labels mean public F/G. Splits/validators differ. Development/regression is not held-out evidence |
| DTAP | Frozen encoded input lists; deterministic ten-row selection; trusted inputs and policies | All 20 native judges, task trajectories/traces, hook/run logs, generation requests/responses, corrected summary and audit | Two trace files redact private-key-shaped fixture blocks. Full upstream environment/images are acquired separately |
| Permission preservation | Reused case IDs, fixture constructors, policies and four-route/configuration matrix | 320 executions, file effects, source/binary/image hashes and independent audit | Scripted workers, not native LLM delegates |
| Permission diagnostics | Public contract, opaque IDs, committed hidden mapping, reveal/repair records | 56 before/after probes, frozen diagnoses and audit | Deliberately seeded faults; rules-based suggestions |
| Scripted escalation | Six sequences × three configurations; threshold definitions | Registry events, real workload/container effects, timing and audit | Synthetic verified violations; no model calls |
| Native delegation | Exact prompts, commands, canary construction and native profile repair | 20 executed tool probes, selected actual tool records, ancestry, effects and audits | Full private Codex session histories and encrypted messages omitted; selected records retain the tested actions |
| Native stop / warning | Prompts, thresholds, source snapshots, measurement windows | Native calls, identity/cgroup evidence, per-worker timestamps, admission effects, registry state and audits | No full private sessions. Warning plaintext at workers is not inspected; first pilot excluded from confirmation totals |

The machine-readable [availability index](../provenance/data-availability.json) points to each experiment's files.

The [final paper map](../paper/README.md) distinguishes its three main experiments from supporting checks. Older exploratory pilots and manuscript drafts are excluded from the public export; relevant failures and historical variants inside each retained experiment are preserved.

## DTAP supplement

The original publication was summary-only. [supplemental-native-20260914](../experiments/paper-2026/dtap-vega/evidence/supplemental-native-20260914/) adds 169 files from the original VPS run, including all 20 judges. `EXPORT.json` records source path, original SHA-256, published SHA-256 and every redacted string location.

Two native trace files contain private-key-shaped benchmark fixture text. Those blocks are replaced with a visible marker. The remaining 167 files are unchanged. Do not use exported hashes as the original hashes for the two transformed files. Judge files and their recorded hashes are unchanged.

Use the **corrected** DTAP result directory for scores. The original erroneous aggregation is retained and labeled; the correction only re-read existing judge files.

## Source and integrity

- [source-files.json](../provenance/source-files.json): each original exported path, source commit and content hash. Historical source snapshots do not need the original repository's Git history.
- Root and per-experiment `MANIFEST.sha256`: published file inventory.
- Original per-run manifests and checksums remain beside their records.
- `prepare.py` writes a new portable-code revision and a full record of path/port adaptations before a fresh run.

The root verifier recalculates core model/forced/permitted counts from action/effect records; matches all DTAP judges to their hashes and summary; recounts native shared-warning timestamps; and re-scores the 320 permission-preservation records. Other supporting counts are checked against retained audits. It does not re-run every historical audit or reconstruct omitted private sessions.

## Reuse limits

Do not combine these studies into one harm rate. Do not count failed launches as blocked attacks. A zero observed failure count does not establish general security, a real-world prevention percentage or resilience against an adaptive swarm.

Model/API responses and Docker tags can change. A close replication records and, where possible, pins the original model, CLI, source, binary and image identities. Native reruns need the user's own authentication and retain new raw records locally; authentication itself must never enter the archive.
