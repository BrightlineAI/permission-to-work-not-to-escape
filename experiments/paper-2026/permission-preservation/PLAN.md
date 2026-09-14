# Permission preservation: execution plan

Status: built and run on the VPS. Final 320-execution matrix and independent evidence check passed. See [results](README.md#results-september-13-2026).

- **Question:** do fixed job permissions survive shell access and a separately dispatched worker?
- **Reuse:** `vega-core` schema/authorizer, nono 0.77.0, existing Python container image, source fixtures `case-061`–`065` and `case-136`–`140`.
- **Adaptation:** the first five supply project-file/credential context; the next five supply system-change context. Create actual read/write targets and explicit file permissions. Original sync/approval tasks and model outcomes are not replayed or rescored.
- **Cases:** five read pairs + five write pairs. Three alternate routes yield 30 paired scenarios. Include ten parent-tool references.
- **Controls:** route confinement off/on × inherited scope off/on. Normal tool authorization always enabled. Same requests, worker defaults and outer isolation throughout.
- **Count:** 40 route pairs × two requests × four configurations = 320 deterministic executions. No model calls. Ten fixtures in two related families, not 30 independent concepts.

## Build

1. Freeze copies of reused core and source cases in this package; record hashes.
2. Materialize synthetic fixtures, reviewed parent policies and broader worker defaults.
3. Add an executing file-tool adapter using the existing authorizer.
4. Add a trusted dispatcher that launches a separate worker and binds its identity, ancestry and effective scope. With inheritance enabled, compute parent ∩ worker default. Apply it to tool authorization and nono file grants.
5. Add shell execution and a matrix driver. The driver must not authorize a shell request before dispatch; nono must actually enforce it.
6. Score contents/state outside worker authority. Keep infrastructure failures separate from blocked requests.

## Run

- VPS only: unique run directory and container names under `permission-preservation`; no network or published ports; low concurrency and limited container resources.
- Do not modify or run the active DTAP integration, its sealed holdout, or any other agent's containers.
- First validate with separate development fixtures and unit checks on the VPS. Preserve failed attempts.
- Freeze implementation, fixtures, policies, expected outcomes and image/binary hashes before the full matrix.
- Reset file state per request. Retain real command, worker identity, effective permissions, decision, returned contents/state and timings.
- Report 320 outcomes, all missing/error records, and matched utility. Verify cleanup of only this run's containers.

## Claim

This tests concrete permission propagation and execution coverage. It does not test fresh policy generation, autonomous model behavior, service credential use, FORGE, or production failure rates. An intentionally disabled protection is an ablation, not a discovered production vulnerability.
