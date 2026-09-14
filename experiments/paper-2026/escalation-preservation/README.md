# Shared job enforcement across scripted workers

18 sequence/configuration cells, 30 real workload containers.

## Independent environment

Use Python 3.11+ on a Linux VPS. Copy this experiment directory anywhere; it does not need the original Vega checkout or a sibling experiment. Historical source and published evidence stay unchanged.

```sh
python3 prepare.py --work "$HOME/ptw-runs/REPLACE-WITH-UNIQUE-ID"
```

Use the printed `code` and `runs` directories below. `prepare.py` changes only installation paths/account references, removes the author's credential-manager fallback, and commits the portable source in a new local Git repository with **no remote**. `preparation.json` records every changed file and digest. It does not launch a model. For historical algorithms, add `--revision REVISION` from the table below.

Fresh runs produce new evidence; model/provider changes can change results. Do not overwrite or relabel the recorded paper runs. `MANIFEST.sha256` covers this directory's published files. On Linux, `sha256sum -c MANIFEST.sha256` checks them without starting an experiment.


## Exact test

Six prescribed sequences compare block-only, session-local pause after two violations, and shared-job stop after three violations. A trusted driver supplies synthetic verified events; actual Docker processes establish workload/termination effects. This does not measure LLM evasion.

- 18/18 outcomes match the frozen expected matrix; 30 containers created and cleaned up.
- Shared stop terminates three already-running workloads; six later admissions are denied; two unrelated requests remain usable.
- Recorded stop-to-termination observations: 307.786–318.576 ms. This is the local adapter measurement, not end-to-end incident detection latency.
- No model calls; recorded run took 50.27 seconds.

`expected.json` defines the six sequences. `evidence/20260913-vps/final-003/` retains event streams, workload effects, process observations, summary and independent audit. `historical/3a41ac1/` is frozen source; development attempts remain separate.

## Fresh run

Requires Python 3.11+, Docker/passwordless sudo and the existing `python:3.11-slim` image. Unique containers, no network, bounded CPU/memory.

```sh
cd "$HOME/ptw-runs/YOUR-ID/code"
python3 -m unittest -v test_registry
python3 run.py --output "$HOME/ptw-runs/YOUR-ID/runs/final"
python3 audit.py "$HOME/ptw-runs/YOUR-ID/runs/final"
```

[Original protocol](PROTOCOL.md). For actual native LLM parent/worker violations, use the separately measured shared-warning experiment in `native-stop`; its two-violation threshold is different.
