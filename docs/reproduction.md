# Reproduce and inspect

## Inspect the existing evidence

From the repository root, on your Linux development VPS:

```sh
python3 scripts/verify_evidence.py
```

This command checks published file hashes, source provenance, exact case counts, selected raw-result calculations and the data availability index. It makes no network request or model call and runs no recorded command. A hash confirms file identity, not independent third-party certification of an event.

Each experiment also has a local `MANIFEST.sha256`: run `sha256sum -c MANIFEST.sha256` from that directory. Original `SHA256SUMS` and manifests remain with the evidence. Historical audits may refer to original VPS paths or unavailable full native sessions; the root verifier states which published records it can recompute.

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
