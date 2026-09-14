# Booking approval: an inspectable policy example

The job may finalize BK-01 at hotel-01 only with corporate approval bound to the booking and amount. This reuses the paper's actual case-081 values. All data are synthetic.

1. [task.json](task.json) is the trusted operator description and tool interface.
2. [candidate.json](candidate.json) is a supplied typed proposal. This quickstart makes no model call.
3. The compiler validates the constrained contract and keys the approval rule by tool, `finalize_booking`.
4. The control looks up approval in the trusted store: fake `approved-by-partner-01` is absent → deny; genuine `apr-valid-01` matches the job, issuer, resource and amount → allow.

From the repository root:

```sh
PYTHONPATH=src python3 -m permission_to_work demo
PYTHONPATH=src python3 -m permission_to_work compile --task examples/booking/task.json --candidate examples/booking/candidate.json --output /tmp/reviewed-booking-policy.json
```

The output path must not already exist. The command creates a policy file, not a live booking. Review intent before using a compiled policy in an execution adapter.

The demo also counts one parent violation and one worker violation against a shared two-violation threshold. It then denies a quiet worker's later request and allows an unrelated job. This demonstrates registry decisions, not process termination. The [native-stop experiment](../../experiments/paper-2026/native-stop/README.md) contains the real process evidence.

For actual LLM proposals and the original direct/typed/critic comparisons, see the [core experiment](../../experiments/paper-2026/vega-core/README.md#policy-generation-e-f-g). The validator is constrained; it does not prove arbitrary prose has been translated correctly.
