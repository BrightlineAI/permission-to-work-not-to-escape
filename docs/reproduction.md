# Reproduce the paper experiments

Start with the [paper PDF](../paper/submission.pdf) or the [experiment catalog](../experiments/paper-2026/README.md). This guide covers checking published evidence and running new executions of the paper experiments. The separate test harness under `harness/` is unrelated to the paper and is not required here.

## Get the repository

Use Git and Python 3.11+. Run benchmark workloads on a separate Linux VPS; the small integration walkthrough below uses x86_64 Linux because its launcher downloads amd64 binaries.

```sh
git clone https://github.com/BrightlineAI/permission-to-work-not-to-escape.git
cd permission-to-work-not-to-escape
```

If already cloned, start from the repository root. Keep the published checkout unchanged and place new run directories outside it.

## Inspect the existing evidence

From the repository root:

```sh
python3 scripts/verify_evidence.py
```

This command checks published file hashes, source provenance, exact case counts, selected raw-result calculations and the data availability index. It makes no network request or model call and runs no recorded command. A hash confirms file identity, not independent third-party certification of an event.

Success prints JSON with `"passed": true` and exits with status 0. Missing files, changed hashes or inconsistent retained results cause a failure. This verifies the published artifacts; it does not execute a fresh benchmark.

Additional offline checks, also from the repository root:

```sh
python3 scripts/check_docs.py
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Each experiment also has a local `MANIFEST.sha256`: run `sha256sum -c MANIFEST.sha256` from that directory. Original `SHA256SUMS` and manifests remain with the evidence. Historical audits may refer to original VPS paths or unavailable full native sessions; the root verifier states which published records it can recompute.

## Run a small integration check

This three-case check exercises the A–D control configurations using supplied actions, without model calls. **It is an integration smoke test, not a reproduction of the paper's model-generated results.** It still starts real containers and local services, so use an isolated Linux VPS.

Before starting, provide:

- x86_64 Linux, Git, Bash, Python 3.11+, `curl` and `sha256sum`;
- Docker with passwordless `sudo -n docker` available to the test account;
- the reviewed **nono 0.77.0** executable on `PATH`, from the [pinned release](https://github.com/nolabs-ai/nono/releases/tag/v0.77.0). The `nono-v0.77.0-x86_64-unknown-linux-gnu.tar.gz` archive's recorded SHA-256 is `86bcf7a134d6f47e064ad0f2561f1be02b9fffc643708c3ec2dd4070e82b798e`; verify it before using the binary.

The launcher downloads OPA 1.20.2 and agentgateway 1.5.0, verifies their pinned hashes, and may download Docker images. Internet access and host/container resources are required even though the smoke test makes no model calls. It does not install or require the separate test harness.

In Bash, from the repository root:

```sh
set -eu
export VEGA_BENCHMARK_NONO="$(command -v nono)"
test -x "$VEGA_BENCHMARK_NONO"
sudo -n docker info >/dev/null

PTW_RUN="$HOME/ptw-runs/core-$(date -u +%Y%m%dT%H%M%SZ)-$$"
python3 experiments/paper-2026/vega-core/prepare.py --work "$PTW_RUN"
cd "$PTW_RUN/code"

bash scripts/run_all_vps.sh "$PTW_RUN/runs/smoke" \
  --case-ids case-001,case-041,case-081 --forced-as-captures
python3 scripts/audit_results.py "$PTW_RUN/runs/smoke"
```

Preparation prints the new `code` and `runs` paths, records adaptations in `$PTW_RUN/preparation.json`, and freezes the portable code in a new local Git repository with no remote. It does not start an experiment or model call. The smoke run writes only to its prepared environment and its own containers/services.

The audit must exit with status 0 and print `"state": "VALID"`, `"cases": 3` and true values for every audit gate. In `forced`, arm D must have zero harmful effects; in `benign`, each arm must complete all three supplied permitted actions. The authoritative output is `$PTW_RUN/runs/smoke/audit-summary.json`; captures, manifests and raw effect records are alongside it. Synthetic captures from this smoke run are not model behavior measurements.

If setup or an audit fails, retain the output and diagnose the failure. Do not disable audit gates, relabel the run as successful, overwrite earlier results or stop another job to free a port. Start a new prepared environment for a retry.

## Continue to the paper experiments

The following are separate from the smoke check. Fresh model calls require your own credentials and may incur charges; use the specified model rather than silently substituting another one. Results may differ from the published runs.

| Paper experiment | Source and commands | Requirements and outputs |
|---|---|---|
| 1. Misuse of granted access | [`vega-core` fresh-run instructions](../experiments/paper-2026/vega-core/README.md#fresh-run); the 200-case command below | Same Linux tools as the smoke check, plus `OPENROUTER_API_KEY`; captures and A–D effects in `runs/core-200`, audited by `audit_results.py` |
| 2. Policy generation | [`vega-core` policy generation](../experiments/paper-2026/vega-core/README.md#policy-generation-e-f-g); explicit E/F/G commands below | Fresh A–D captures from experiment 1 and `OPENROUTER_API_KEY`; each generated arm has its own policies, raw effects and audit |
| 3. Shared escalation | [`native-stop` fresh-run instructions](../experiments/paper-2026/native-stop/README.md#fresh-run) | Prepare this directory in its own new environment; Linux/systemd, passwordless sudo and authenticated Codex/native workers. Follow its commands for the shared-job and session-local comparison, then `audit_shared_warning.py` for each output directory |

### Experiment 1 and experiment 2 commands

Continue in the prepared `vega-core` environment above, with `PTW_RUN` and `VEGA_BENCHMARK_NONO` still set. Securely inject your own `OPENROUTER_API_KEY` into this shell using your credential manager; do not write it into the repository. The smoke captures are not reused for model results.

```sh
test -n "${OPENROUTER_API_KEY:-}"
cd "$PTW_RUN/code"

# Experiment 1: fresh Qwen3-14B/high captures and A-D replay on 200 cases.
bash scripts/run_all_vps.sh "$PTW_RUN/runs/core-200" --limit 200
python3 scripts/audit_results.py "$PTW_RUN/runs/core-200"

# Experiment 2: generate and audit E/F/G using those fresh captures.
bash scripts/reproduce_efg_vps.sh original \
  "$PTW_RUN/runs/policy-original" "$PTW_RUN/runs/core-200/captures.json"
bash scripts/reproduce_efg_vps.sh second \
  "$PTW_RUN/runs/policy-second" "$PTW_RUN/runs/core-200/captures.json"
```

The first audit must report `"state": "VALID"` and `"cases": 200`; its individual gates check opportunity, matched replay and permitted work. The E/F/G script generates policies, replays each arm sequentially, and runs `audit_generated_arm.py` for each arm. Each `policy-original/physical-{e,f,g}` and `policy-second/physical-{e,f,g}` output contains an `audit-summary.json` that must report `"state": "VALID"`. Validity establishes the run's integrity, not that new model outputs must match the old success rates. Generation uses concurrent model calls and has variable cost and latency.

These commands use the consolidated implementation and public E/F/G arm names. To select an included historical snapshot or reproduce a particular published split, follow the experiment's [source snapshot and evidence map](../experiments/paper-2026/vega-core/README.md#evidence-map); do not mix old raw arm names with the current commands. Inspect final-split results separately from development and regression results.

## Run a new experiment

1. Choose an experiment from the [catalog](../experiments/paper-2026/README.md). Read its exact prerequisites, comparison and limitations.
2. Copy that entire directory to a Linux VPS. It contains its own small local support dependencies. Install/review external tools or upstream benchmarks only where the README requires them.
3. Run `python3 prepare.py --work /absolute/new/path`. It creates separate `code/` and `runs/` directories, adapts author-specific paths and freezes the portable source in a local Git repository with no remote.
4. Use the experiment's fresh-run commands. Keep outputs outside `code/` so source-integrity checks remain meaningful.
5. Run its independent audit. Retain all attempts, the preparation manifest, model settings, actual image/binary identities, raw records and failures.

`--revision` selects an included historical code snapshot. Historical arm names and split membership must match that snapshot. A new execution is a replication, not the old recorded run and not a new unseen holdout.

The core comparison's preparer allocates separate local service ports and records the substitutions. Containers/services use unique names. Port availability can change between preparation and launch: if startup fails, retain that invalid run and prepare a new environment. Never stop an existing process to make room. Run physical replays sequentially within one environment.

## Reproducibility levels

| Level | What it establishes | Cost / requirements |
|---|---|---|
| File check | Published artifacts match their hashes | Standard library; no API |
| Result recalculation | Included raw observations agree with reported counts | Standard library; no API |
| Controlled replay | Supplied requests produce the tested effects under controls | Linux/Docker/nono; no model for forced controls |
| Fresh policy generation | New provider responses generate/reject policies under the same protocol | Model account; variable outputs/cost |
| Fresh native trajectories | Actual runner tools/workers execute the selected tasks | Upstream dependencies, model account, isolated environment |

Do not substitute one level for another. A policy-only unit test is not a native containment test. A permitted request is not necessarily a completed user task. A terminated process does not undo a remote effect that already happened.

## Model and dependency identity

- Core/DTAP: recorded `qwen/qwen3-14b`, high reasoning; exact requests, prompts, output usage and provider fields are retained where available.
- Native Codex: recorded CLI 0.154.0, `gpt-6-astra`, high reasoning, native workers, no permission escalation. Future CLI versions may change configuration or record formats.
- Core confinement: nono 0.77.0; OPA 1.20.2; agentgateway 1.5.0.
- DTAP upstream commit and patch files are pinned in its package. Docker image IDs/digests appear in execution manifests. Mutable tags may later resolve differently: use the recorded digest for closer replication where available.

The package does not ship credentials, Codex authentication, provider access, third-party binaries or container images. Full native session histories are omitted; selected tool records and independent observations are included. [Data availability](evidence.md).
