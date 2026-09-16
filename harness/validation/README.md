# VPS validation

This directory records the new harness implementation, separate from the paper's experiments.

The development suite currently passes 66 tests on Algol: policy review, task and parent scope, shared counters, duplicate events, concurrency, recovery, resource links, real Linux confinement and process stopping. The latest development run took 3.57 seconds. Both live Codex workflows also passed; combined time was 55.81 seconds.

The stopping test runs two independent parents and a delegate, each with a detached subprocess writing markers. At the shared threshold, their writes stop. An unrelated project's writer continues and later requests to the stopped project are rejected.

Run the checks yourself using [the instructions](../README.md#run-the-tests). The final clean installation acceptance record is added after that separate check completes.

[Development failures and corrections](DEVELOPMENT.md) are retained so setup failures are not mistaken for security successes.
