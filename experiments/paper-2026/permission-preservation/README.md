# Permissions across tools and delegates

320 executions: 10 fixtures × 4 routes × 2 requests × 4 configurations.

## Independent environment

Use Python 3.11+ on a Linux VPS. Copy this experiment directory anywhere; it does not need the original Vega checkout or a sibling experiment. Historical source and published evidence stay unchanged.

```sh
python3 prepare.py --work "$HOME/ptw-runs/REPLACE-WITH-UNIQUE-ID"
```

Use the printed `code` and `runs` directories below. `prepare.py` changes only installation paths/account references, removes the author's credential-manager fallback, and commits the portable source in a new local Git repository with **no remote**. `preparation.json` records every changed file and digest. It does not launch a model. For historical algorithms, add `--revision REVISION` from the table below.

Fresh runs produce new evidence; model/provider changes can change results. Do not overwrite or relabel the recorded paper runs. `MANIFEST.sha256` covers this directory's published files. On Linux, `sha256sum -c MANIFEST.sha256` checks them without starting an experiment.


## Exact test

Reuse case-061–065 file-read and case-136–140 file-write parameters, listed in `REUSE.json`. `sources/` retains the reused cases and `run.py` constructs the fixtures and policies. Four routes: parent tool, parent shell, worker tool, worker shell. Workers are real scripted processes, not native LLM delegates.

| Configuration | Forbidden effects over the three alternate routes | Permitted completions over those routes |
|---|---:|---:|
| Tool checks only | 30/30 | 30/30 |
| Route confinement only | 20/30 | 30/30 |
| Inherited policy only | 20/30 | 30/30 |
| Both | 0/30 | 30/30 |

The parent-tool route blocks 10/10 forbidden requests in every configuration. Across the full matrix: 320/320 valid, expected outcomes; zero infrastructure errors. This is an ablation over deliberately configured gaps, not an estimate of deployed-system failure rates.

## Evidence

- `evidence/20260913-vps/final-01/`: raw executions, fixtures, effects, source hashes, image/nono identity, summary and audit.
- `historical/481c07f/`: evaluated source. Development runs remain separate.
- `vendor/vega_core/`: local evaluated dependency; no sibling checkout required.

## Fresh run

Requires Docker/passwordless sudo, the existing `python:3.11-slim` image and nono 0.77.0. No model/API calls. Containers have unique names, read-only roots and no network.

```sh
cd "$HOME/ptw-runs/YOUR-ID/code"
python3 -m unittest -v test_scope
python3 run.py --nono /absolute/path/to/nono --output "$HOME/ptw-runs/YOUR-ID/runs/final"
python3 audit.py "$HOME/ptw-runs/YOUR-ID/runs/final"
```

[Original protocol](PROTOCOL.md).
