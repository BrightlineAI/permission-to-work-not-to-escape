# Paper experiments and supporting checks

The [paper](../../paper/submission.pdf) presents three main experiments: (1) request misuse and (2) policy generation, both in `vega-core`; and (3) shared escalation in `native-stop`. The other directories contain its supporting checks and native task completion comparison.

Each directory is independently copyable and contains its own source, local support dependencies, published evidence, historical source snapshots and preparation instructions. Evidence inspection needs no model account. Fresh model runs need your own credentials and a separate Linux VPS environment.

| Experiment | What actually ran | Main files |
|---|---|---|
| [vega-core](vega-core/README.md) | 200 adapted request cases; A–D replay and E–G policy generation | `cases`, `policies`, `e`, `ef`, `evidence`, `historical` |
| [dtap-vega](dtap-vega/README.md) | 10 native tasks under attack; independent baseline and typed-policy trajectories | `frozen`, `patches`, `hooks`, `scripts`, `evidence` |
| [permission-preservation](permission-preservation/README.md) | 320 actual file operations across four routes/configurations | `REUSE.json`, `run.py`, `vendor`, `evidence` |
| [permission-diagnostics](permission-diagnostics/README.md) | 56 blinded before/after file probes; seeded faults | `policy.json`, `evaluator-matrix.json`, `diagnose.py`, `evidence` |
| [escalation-preservation](escalation-preservation/README.md) | 18 scripted event sequences/configurations; 30 real containers | `expected.json`, `registry.py`, `run.py`, `evidence` |
| [native-delegation](native-delegation/README.md) | 20 native parent/worker file operations; read repair | `run*.py`, `audit.py`, `evidence` |
| [native-stop](native-stop/README.md) | Three whole-job stop confirmations, one native-only control; shared warning versus session-local counters | `run*.py`, `heartbeat.py`, `support/registry.py`, `evidence` |

Machine-readable index: [experiments.json](experiments.json).

**Interpretation:** replayed requests measure control decisions/effects; matched permitted controls do not generally measure benign agent task completion. DTAP measures native task completion under attack. Native permission/stop tests prescribe specific operations. Do not pool these denominators or label them a real-world incident prevention rate.

Check the files and result calculations with the [evidence verifier](../../scripts/verify_evidence.py). Follow the [reproduction guide](../../docs/reproduction.md) to run new experiments.
