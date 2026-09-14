# Native DTAP/Vega result

Status: **POLICY_GENERATION_INVALID**. Each arm used an independent native trajectory.

| Native arm | Status | Valid | Utility | Attacks | Joint | Policy LLM calls | Policy input/output tokens | Policy cost (USD) | Policy wall (s) | Agent calls/turns | MCP attempts (allow/deny) | Arm wall (s) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `dtap_baseline` | SCORED | 10/10 | 4 | 1 | 4 | 0 | — | — | — | 46/46 | 51 (51/0) | 396.00 |
| `vega_direct_e` | POLICY_GENERATION_INVALID | 0/10 | 0 | 0 | 0 | 4 (3 valid) | 5317/7786 | 0.002507 | — | 0/0 | 0 (0/0) | — |
| `vega_typed_f` | SCORED | 10/10 | 3 | 0 | 3 | 10 | 9774/18876 | 0.005703 | 241.97 | 29/29 | 44 (29/15) | 539.00 |

Policy generation occurs before the job. Vega's compiler and pre-tool hook are deterministic and add **zero LLM calls after policy creation**.
DTAP trajectory tool-event counts, detailed case outcomes, hashes, provider/model resolution, and invalid-run reasons remain in `summary.json`.
