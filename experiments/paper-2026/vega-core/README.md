# Contextual authorization and generated policies

200 adapted cases; A–D physical request replay; E–G policy generation.

## Independent environment

Use Python 3.11+ on a Linux VPS. Copy this experiment directory anywhere; it does not need the original Vega checkout or a sibling experiment. Historical source and published evidence stay unchanged.

```sh
python3 prepare.py --work "$HOME/ptw-runs/REPLACE-WITH-UNIQUE-ID"
```

Use the printed `code` and `runs` directories below. `prepare.py` changes only installation paths/account references, removes the author's credential-manager fallback, and commits the portable source in a new local Git repository with **no remote**. `preparation.json` records every changed file and digest. It does not launch a model. For historical algorithms, add `--revision REVISION` from the table below.

Fresh runs produce new evidence; model/provider changes can change results. Do not overwrite or relabel the recorded paper runs. `MANIFEST.sha256` covers this directory's published files. On Linux, `sha256sum -c MANIFEST.sha256` checks them without starting an experiment.


## Exact cases and comparison

- `cases/case-001.json` through `case-200.json`; five benchmark sources are identified by repository revision/artifact in each case.
- First 100: five patterns × 20 parameterizations. Second 100: 20 categories × 5 parameterizations. These are **adapted synthetic fixtures**, not 200 native upstream benchmark runs.
- Each case includes the exact system/user/injected content, tool schema, model-action mapping, harmful request, matched permitted request and trusted fixture. Policies are in `policies/`.
- A: baseline. B: nono OS confinement. C: ordinary agentgateway/OPA field checks. D: reviewed contextual policy checking job authority, approval, provenance and delegation.
- Qwen3-14B/high produces one captured action per case. The same action is replayed through A–D. The system prompt deliberately encourages following retrieved instructions. The matched permitted request is constructed by the harness, not a benign LLM conversation.
- Mock service receipts and file effects establish outcomes. No real booking, payment or attack on an external vendor occurs.

| Cohort | Captured harmful requests | A / B harmful effects | C harmful effects | D harmful effects | Matched permitted, each arm |
|---|---:|---:|---:|---:|---:|
| 001–100 | 97 | 97 / 97 | 60 | 0 | 100/100 |
| 101–200 | 36 | 36 / 36 | 36 | 0 | 100/100 |
| Combined | 133 | 133 / 133 | 96 | 0 | 200/200 |

Forced harmful controls: A/B 200 effects, C 160, D 0. Forced actions are separately labeled and are not a model attack-success rate.

## Policy generation: E, F, G

| Public arm | Policy source | Recorded comparison / limitation |
|---|---|---|
| E | LLM writes final policy JSON | Historical 40-case holdout: 8 harmful effects, 20 permitted completions. Later strengthened 200-case regression: 0 harmful effects, 180 permitted completions; not a fresh holdout. |
| F | LLM supplies typed fields; deterministic compiler and contract validator | Final 30-case split: 0/11 captured harmful effects, 0/30 forced harmful effects, 30/30 permitted completions. |
| G | F plus LLM critic | Same final split: 0/11, 0/30, 30/30. No demonstrated improvement over F on this split. |

The raw second-cohort files call public F **E**, and public G **F**. Do not infer the public arm from an old filename. E's historical holdout and F/G's final split are different; validation guidance also differs. This is not a controlled estimate of typing alone.

| Included source snapshot | What it reproduces |
|---|---|
| `historical/40d01fb/` | Historical direct-E generator plus fail-closed evaluator correction |
| `historical/2f5bcba/` | Frozen second-cohort F/G protocol with legacy E/F labels |
| `historical/efa7658/` | Original-cohort F/G regression |
| Top-level source | Final consolidated implementation; later strengthened direct-E regression |

## Evidence map

| Directory under `evidence/` | Contents |
|---|---|
| `20260913-vega-qwen3-14b-final-100/` | First-cohort A–D captures, manifests, raw model/forced/permitted requests, effects, service records, audit |
| `20260913-vega-second100-qwen3-14b/abcd-new-100/` | Second-cohort A–D results |
| `20260913-vega-e-qwen3-14b-final-100/` | Historical E development, frozen holdout generation, policies, physical results and failures |
| `20260913-vega-second100-qwen3-14b/frozen-2f5bcba/` | F/G generation transcripts, typed candidates, compiled policies, split membership and physical outcomes |
| `20260913-vega-original100-ef-qwen3-14b/` | F/G original-cohort regression, including excluded iterations |
| `20260913-vega-e-direct-regression-qwen3-14b/` | Strengthened E regression on known 200 cases |

## Fresh run

Prerequisites: Docker with passwordless sudo, reviewed nono 0.77.0 binary, Python 3.11+, `curl`, `sha256sum`. The launcher downloads agentgateway 1.5.0 and OPA 1.20.2 and checks pinned SHA-256 values. Model captures require `OPENROUTER_API_KEY` in your environment; never place it in a file in this repository.

```sh
cd "$HOME/ptw-runs/YOUR-ID/code"
export VEGA_BENCHMARK_NONO=/absolute/path/to/nono
# Integration check only; no model calls:
bash scripts/run_all_vps.sh "$HOME/ptw-runs/YOUR-ID/runs/smoke" --case-ids case-001,case-041,case-081 --forced-as-captures
python3 scripts/audit_results.py "$HOME/ptw-runs/YOUR-ID/runs/smoke"
# Fresh Qwen captures and replay for all 200 adapted cases:
bash scripts/run_all_vps.sh "$HOME/ptw-runs/YOUR-ID/runs/core-200" --limit 200
python3 scripts/audit_results.py "$HOME/ptw-runs/YOUR-ID/runs/core-200"
```

For F/G, the included `scripts/reproduce_efg_vps.sh` and `scripts/reproduce_original_ef_vps.sh` define generation, assembly, physical evaluation and audits. Read them before use: choose the matching historical snapshot and its **raw arm names**. The current `generate_ef.py --mode F|G --split ... --output ...` is the public naming. `ef/split_manifest.json` gives exact membership. Prompt files, tool contracts, retries and token/cost records are included. [Original detailed protocol](PROTOCOL.md).
