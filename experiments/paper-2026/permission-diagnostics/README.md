# Find a missing permission control, repair it and retest

56 physical read probes; blinded diagnosis before configuration reveal.

## Independent environment

Use Python 3.11+ on a Linux VPS. Copy this experiment directory anywhere; it does not need the original Vega checkout or a sibling experiment. Historical source and published evidence stay unchanged.

```sh
python3 prepare.py --work "$HOME/ptw-runs/REPLACE-WITH-UNIQUE-ID"
```

Use the printed `code` and `runs` directories below. `prepare.py` changes only installation paths/account references, removes the author's credential-manager fallback, and commits the portable source in a new local Git repository with **no remote**. `preparation.json` records every changed file and digest. It does not launch a model. For historical algorithms, add `--revision REVISION` from the table below.

Fresh runs produce new evidence; model/provider changes can change results. Do not overwrite or relabel the recorded paper runs. `MANIFEST.sha256` covers this directory's published files. On Linux, `sha256sum -c MANIFEST.sha256` checks them without starting an experiment.


## Exact test

One public permitted/forbidden read contract; four routes; four opaque configurations. Three configurations contain seeded omissions. The diagnostic receives observed effects and public rules, not configuration labels. It freezes its diagnosis before the evaluator reveals the mapping; repairs are then applied and the probes repeated.

| Measurement | Recorded result |
|---|---:|
| Before: valid probes / permitted completions | 32 / 16 |
| Exposed route pairs identified | 7/7 |
| False alarms on protected route pairs | 0/9 |
| Faulty configurations identified | 3/3 |
| After repair: forbidden data returned | 0/12 |
| After repair: permitted reads completed | 12/12 |
| Total valid probes / model calls | 56 / 0 |

This identifies seeded configuration omissions. Suggestions are hypotheses about missing controls, not automatic root-cause proofs or automatic production repairs.

## Evidence

`evidence/20260913-vps/final-01/` includes the public contract, shuffled mapping commitment, raw before/after observations, frozen diagnoses, reveal/repair events and independent audit. `historical/33b8f9c/` is the evaluated source. `support/permission-preservation/` supplies the local route implementation.

## Fresh run

Requires Docker/passwordless sudo, `python:3.11-slim`, nono 0.77.0. No model calls. Preparation freezes a clean isolated code commit; do not edit it between phases.

```sh
cd "$HOME/ptw-runs/YOUR-ID/code"
python3 -m unittest -v test_diagnostic
python3 run.py prepare --nono /absolute/path/to/nono --output "$HOME/ptw-runs/YOUR-ID/runs/final"
python3 run.py probe --phase before --output "$HOME/ptw-runs/YOUR-ID/runs/final"
python3 run.py diagnose --phase before --output "$HOME/ptw-runs/YOUR-ID/runs/final"
python3 run.py reveal --output "$HOME/ptw-runs/YOUR-ID/runs/final"
python3 run.py probe --phase after --output "$HOME/ptw-runs/YOUR-ID/runs/final"
python3 run.py diagnose --phase after --output "$HOME/ptw-runs/YOUR-ID/runs/final"
python3 audit.py "$HOME/ptw-runs/YOUR-ID/runs/final"
```

[Original protocol](PROTOCOL.md).
