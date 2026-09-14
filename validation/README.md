# Standalone export validation

These are **new packaging/reproduction checks**, run on `algol-box-2-1` in `/home/loon/benchmarks/permission-to-work-export-20260914`. They are not added to the original paper's denominators. Each environment had its own source copy, run directory, resource names and recorded preparation changes.

| Check | Result | Records |
|---|---|---|
| Tool workflow tests | 10 passed | [Test output](vps-20260914/validation/final-tool-unit.txt): booking authorization, wrong approval/job/amount, delegation expansion, shared versus session-local state |
| Core component tests | 24 passed | [Test output](vps-20260914/validation/core-unit.txt) |
| DTAP compiler/selection/aggregation tests | 11 passed | [Test output](vps-20260914/validation/dtap-unit.txt) |
| Diagnostic unit tests | 3 passed | [Test output](vps-20260914/validation/diagnostic-unit.txt) |
| Escalation unit tests | 6 passed | [Test output](vps-20260914/validation/escalation-unit.txt) |
| Permission-scope unit tests | 5 passed | [Test output](vps-20260914/validation/preservation-unit.txt) |
| Blinded diagnostic and repair | 56 probes; audit passed | [Raw run](vps-20260914/diagnostics-02/runs/final/) · [Audit](vps-20260914/validation/diagnostic-audit.json) |
| Scripted escalation | 18 cells; audit passed | [Raw run](vps-20260914/escalation-01/runs/final/) · [Audit](vps-20260914/validation/escalation-audit.json) |
| Core forced replay | Cases 001, 041, 081; audit valid; no model calls | [Raw run](vps-20260914/core-01/runs/smoke/) · [Audit](vps-20260914/validation/core-smoke-audit.json) |
| Permission preservation | 320 operations; audit passed | [Raw run](vps-20260914/preservation-01/runs/final/) · [Audit](vps-20260914/validation/preservation-audit.json) |
| Wheel packaging | Built offline; installed in a new environment; CLI demo worked from `/tmp` | [Build](vps-20260914/validation/wheel-build.txt) · [Demo](vps-20260914/validation/wheel-demo.json) |
| Published evidence | File integrity and selected raw-result recalculations passed | [Final export check](vps-20260914/validation/final-evidence-check.json) |
| Maintained documentation | 27 documents, 97 local links checked; no missing targets | [Link check](vps-20260914/validation/final-docs-check.txt) |

The original and new run manifests record actual source, image and nono hashes. Third-party binaries and Python environments are omitted from this validation archive; use their recorded identities and the experiment prerequisites to recreate them.

The five `.env` files under the recorded preservation run contain only generated synthetic canaries, verified against `materials.json`. They are test fixtures, not account credentials; the repository ignores other `.env` files.

No new paid/model trajectory was launched for these packaging checks. Native model experiments and the full DTAP model run are supported by the original evidence; only their preparation or unpaid component checks were repeated here.

## Review changes

1. **Evidence review:** separated adapted request replays, generated-policy splits, native tasks and prescribed native operations; retained failures and corrected DTAP scores. Added full available DTAP records with two explicit fixture redactions.
2. **Portability review:** added local support dependencies, historical source snapshots, unique working directories/ports, configurable CLI/session paths, and removal of the author's credential-manager fallback. The first diagnostic preparation refused to run because unignored Python caches dirtied its fresh checkout. That attempt executed zero probes. The preparer now supplies runtime ignore rules; the new `diagnostics-02` run passed without weakening the integrity guard.
3. **Reader/contributor review:** checked maintained documentation links, provided an effect-free policy example and installable package, and separated implemented primitives from the audit/assurance roadmap. The initial archive checker compared two differently named summary fields; it now re-scores the raw permission records using the independent auditor.

The archive hash check validates file identity and internal consistency, not independent certification of authorship, execution or general security. Re-run `scripts/verify_evidence.py` against the current release inventory; the copied validation report refers to the version it checked.
