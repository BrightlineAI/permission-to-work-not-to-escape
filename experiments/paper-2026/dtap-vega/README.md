# Native DTAP tasks with generated authorization

10 content-blind selected tasks; fresh baseline and typed-policy trajectories.

## Independent environment

Use Python 3.11+ on a Linux VPS. Copy this experiment directory anywhere; it does not need the original Vega checkout or a sibling experiment. Historical source and published evidence stay unchanged.

```sh
python3 prepare.py --work "$HOME/ptw-runs/REPLACE-WITH-UNIQUE-ID"
```

Use the printed `code` and `runs` directories below. `prepare.py` changes only installation paths/account references, removes the author's credential-manager fallback, and commits the portable source in a new local Git repository with **no remote**. `preparation.json` records every changed file and digest. It does not launch a model. For historical algorithms, add `--revision REVISION` from the table below.

Fresh runs produce new evidence; model/provider changes can change results. Do not overwrite or relabel the recorded paper runs. `MANIFEST.sha256` covers this directory's published files. On Linux, `sha256sum -c MANIFEST.sha256` checks them without starting an experiment.


## Exact benchmark and selection

Upstream [DecodingTrust-Agent](https://github.com/AI-secure/DecodingTrust-Agent) revision `e0323a521ba4ef88f8e14c1eccf68d0a3d19a458`. Development: `frozen/dev10.jsonl`. Prospective selection: ten encoded rows from `frozen/holdout50.jsonl`, sorted by a published seeded SHA-256 rule before decoding. The retained `selection-manifest.json` records exact row hashes and the seed. No new random selection is needed to identify the tested tasks.

Qwen3-14B/high, temperature zero, maximum 30 turns, one fresh native trajectory per selected task and valid arm. Both arms receive tasks under attack; these are not separate benign and malicious task sets. The native benchmark's task and attack judges evaluate outcomes independently.

| Arm | Valid task judges | Task successes | Attack successes | Safe and useful |
|---|---:|---:|---:|---:|
| Native baseline | 10 | 4 | 1 | 4 |
| Typed F | 10 | 3 | 0 | 3 |
| Direct E | 0 | — | — | — |

Direct E failed policy generation on its fourth response after producing three valid policies; no E native task ran. The typed arm's reduced utility is retained. Ten tasks are too few for broad superiority claims.

## Evidence

- `frozen/`: exact development/reserved inputs and hashes; they are now public and cannot be treated as a fresh unseen holdout.
- `historical/2670c1b/`: prospective execution source.
- `evidence/20260913-vps/holdout10-prospective-01/corrected/`: authoritative summary and independent audit.
- The historical `frozen-run/summary.json` used the wrong lookup key for native judge paths. It is retained for transparency and **must not be cited as the result**. The reporting correction did not rerun a model.
- The [data availability record](../../../docs/evidence.md) identifies supplemental native records and remaining omissions.

## Fresh independent run

Use a **new** upstream clone and run root; the installer applies recorded patches and must not touch another user's checkout. Requires `git`, `uv`, Docker/passwordless sudo, sufficient memory, network access for reviewed dependencies/images, and an OpenRouter key. The experiment-local `support/vega-core` contains its own policy dependency.

```sh
cd "$HOME/ptw-runs/YOUR-ID/code"
git clone https://github.com/AI-secure/DecodingTrust-Agent.git "$HOME/ptw-runs/YOUR-ID/DecodingTrust-Agent"
git -C "$HOME/ptw-runs/YOUR-ID/DecodingTrust-Agent" checkout --detach e0323a521ba4ef88f8e14c1eccf68d0a3d19a458
export DTAP_ROOT="$HOME/ptw-runs/YOUR-ID/DecodingTrust-Agent"
export VEGA_DTAP_PACKAGE_ROOT="$PWD"
export VEGA_CORE_ROOT="$PWD/support/vega-core"
export VEGA_DTAP_RUN_ROOT="$HOME/ptw-runs/YOUR-ID/runs"
export VEGA_DTAP_FROZEN_COMMIT="$(git rev-parse HEAD)"
sh scripts/install_vps.sh
sh scripts/run_unpaid_tests.sh
# OPENROUTER_API_KEY must already be supplied securely in the environment.
sh scripts/run_holdout10_vps.sh replication-01
```

The isolated portable source is frozen before execution. New results record that source revision separately from the historical paper revision. Re-running the published cases is a replication on known cases, not a new prospective evaluation. Read [PROTOCOL.md](PROTOCOL.md) for judge semantics, failed development attempts and native integration constraints.

The hook's path matcher does not eliminate symlink/TOCTOU gaps. `execute_command` is blocked by this narrow policy interface. Do not represent the hook as complete filesystem confinement.
