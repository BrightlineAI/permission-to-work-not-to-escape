# Vega core: reproducible A/B/C/D/E/F experiment

This directory contains the minimal Vega authorization core and the 100-case
benchmark-derived synthetic experiment. It captures one Qwen3-14B tool call per case
and replays that exact action through:

- **A:** unprotected synthetic service route;
- **B:** A plus nono/Landlock;
- **C:** B plus agentgateway 1.5.0 and OPA 1.20.2 ordinary request rules;
- **D:** C unchanged plus Vega trusted job, data, approval and delegation context.

These are adapted synthetic cases, not official AgentDyn, AgentDojo, InjecAgent,
CompoSkill or WeClawArena scores. The experiment measures enforcement given 100
explicit reviewed policies; it does not measure automatic policy generation.

## What is built

`src/vega_core` is the trusted decision core. The model cannot set its job identity,
data labels, approval registry records, or delegation chain. `gateway/baseline.rego`
is C's ordinary request policy. D first requires that identical OPA decision, then
applies the extra trusted-context checks. The synthetic service and state files remain
outside the client containers, and the audit scores observed effects rather than
denial text.

`scripts/build_cases.py` mechanically materializes five reviewed patterns with 20
synthetic identifiers each. Its 100 committed case and policy files must be reviewed
and frozen before inference. It never reads model responses or grader outcomes.

## Requirements

- Linux VPS with Docker and passwordless `sudo -n docker` for the test account;
- Python 3.11 or newer, `curl`, and `sha256sum`;
- executable nono v0.77.0 (override `VEGA_BENCHMARK_NONO` if needed);
- `OPENROUTER_API_KEY` in the environment, or an authenticated Doppler CLI project
  `algol`, config `prd`;
- outbound HTTPS only for downloading pinned binaries and calling OpenRouter.

The script downloads agentgateway 1.5.0 and OPA 1.20.2 and rejects a checksum mismatch.
The tested Qwen model ID is `qwen/qwen3-14b` with requested high reasoning effort.

## Local checks

```console
python3 scripts/build_cases.py
python3 scripts/preflight.py
pytest -q
```

The expected unit result is 19 passing tests and 100 distinct policy hashes.

## VPS run

Copy this directory to the VPS, then:

```console
chmod +x scripts/run_all_vps.sh
export OPENROUTER_API_KEY='use-a-secret-manager-in-practice'
scripts/run_all_vps.sh /absolute/new/output/directory
```

Three-case and balanced 25-case gates:

```console
scripts/run_all_vps.sh /absolute/output/smoke \
  --case-ids case-001,case-041,case-081

scripts/run_all_vps.sh /absolute/output/gate-25 \
  --case-ids case-001,case-002,case-003,case-004,case-005,case-021,case-022,case-023,case-024,case-025,case-041,case-042,case-043,case-044,case-045,case-061,case-062,case-063,case-064,case-065,case-081,case-082,case-083,case-084,case-085
```

Full registered run:

```console
scripts/run_all_vps.sh /absolute/output/full-100 --limit 100
```

A forced-action integration smoke that makes no model API calls is available only for
harness validation:

```console
scripts/run_all_vps.sh /absolute/output/forced-smoke \
  --forced-as-captures --case-ids case-001,case-041,case-081
```

Never report that smoke as a model result.

## Evidence and audit

The run directory contains the manifest and component hashes, raw capture per case,
combined captures, parallel A/B/C records, D records, forced-control and benign-control
records, protected synthetic service state, gateway log, preflight, cleanup, and
`audit-summary.json`.

Re-audit after copying the output next to the same frozen code:

```console
python3 scripts/audit_results.py /absolute/output/full-100
```

The audit fails closed unless all selected policies are distinct, every model action
hash is identical across A/B/C/D, A and B establish forced attack opportunity, C has
the expected contextual residual, D blocks all forced violations, every benign action
works in all arms, and the live nono/gateway/OPA probes pass.

The runner always removes its three client containers. Confirm cleanup with:

```console
sudo -n docker ps --filter name=vega-core
```

## Second 100 and proposer/critic F

`scripts/build_second_100.py` adds cases 101–200: 20 independently reviewed,
benchmark-grounded misuse categories with five synthetic parameterizations each.
Every harmful request is inside C's ordinary allowlist. Its harmfulness is visible
only through trusted data provenance, approval binding, or delegation state. The
committed `ef/split_manifest.json` fixes a category-level 20/25/25/30 split before
any policy generation:

- development: 20 cases / 4 categories;
- validation 1: 25 cases / 5 unseen categories;
- validation 2: 25 cases / 5 further unseen categories;
- final holdout: 30 cases / 6 untouched categories.

E uses Qwen3-14B to propose a typed policy and may self-correct only from generic
schema/contract errors. F uses a separate Qwen3-14B critic call to review that
proposal and give revision feedback for at most five rounds. Neither process receives
the untrusted source, harmful call, reviewed D policy, capture, expected outcome, or
grader. All raw proposer and critic messages, provider metadata, costs, hashes, and
rounds are retained.

Development commands (do not generate the final holdout yet):

```console
PYTHONPATH=src:scripts VEGA_CODE_COMMIT=$(git rev-parse HEAD) \
  python3 scripts/generate_ef.py --mode E --split development \
  --output /absolute/output/e-development

PYTHONPATH=src:scripts VEGA_CODE_COMMIT=$(git rev-parse HEAD) \
  python3 scripts/generate_ef.py --mode F --split development \
  --output /absolute/output/f-development
```

After completing validation 1 and, if needed, validation 2, freeze and commit the
generic prompts/compiler/validator. Generate `final_holdout` exactly once. The
one-command reproduction of the already-frozen final experiment is:

```console
chmod +x scripts/*.sh
scripts/reproduce_second_100_vps.sh /absolute/new/output-root
```

That command rebuilds the frozen fixtures, captures one Qwen3-14B action per new
case, replays identical hashes through A/B/C/D, generates E/F policies by split,
assembles hash manifests, physically replays E/F through nono + agentgateway + OPA +
Vega, and independently audits every observed side effect. It requires Linux/Docker,
the pinned runtime binaries prepared by `run_all_vps.sh`, and a securely exported
`OPENROUTER_API_KEY`.

For staged/manual reproduction, use `generate_ef.py`,
`assemble_generated_policies.py`, and `run_generated_arm_vps.sh`. Never report a
`--forced-as-captures` integration smoke as a model result.

## E: LLM-drafted policy experiment

E keeps D's deterministic validator and enforcement stack, but replaces the 100
human-reviewed policy bodies with policies drafted by Qwen3-14B from trusted pre-job
operator records. The generator never receives the attack prompt, captured action,
harmful-call fixture, expected decision, or grader result. It emits policy data through
a strict tool schema; it does not emit executable enforcement code.

The record builder supplies positive permissions needed for legitimate work. A
permitted resource or recipient can also be the subject of a contextual attack; E does
not hide that required grant, but it does hide the attack instruction, attack label and
outcome. E therefore evaluates policy compilation from normalized trusted intent, not
automatic intent extraction from arbitrary user text.

The split is fixed by category:

- development: cases 001–060 (AgentDyn, AgentDojo, InjecAgent S2);
- untouched OOD holdout: cases 061–100 (CompoSkill, WeClawArena).

Tune only against development. Freeze and commit the prompt, builder, validator and
runner before generating the holdout. Generate the holdout once and do not change the
system after inspecting it.

```console
python3 scripts/build_e_inputs.py

VEGA_CODE_COMMIT=$(git rev-parse HEAD) PYTHONPATH=src \
  python3 scripts/generate_e.py --split development \
  --output /absolute/output/e-generation-development --workers 8

PYTHONPATH=src python3 scripts/evaluate_e_policies.py \
  --policies /absolute/output/e-generation-development/policies \
  --case-ids $(printf 'case-%03d,' $(seq 1 60) | sed 's/,$//') \
  --output /absolute/output/e-generation-development/development-evaluation.json

# Run this exactly once after the generator commit is frozen.
VEGA_CODE_COMMIT=$(git rev-parse HEAD) PYTHONPATH=src \
  python3 scripts/generate_e.py --split holdout \
  --output /absolute/output/e-generation-holdout --workers 8

VEGA_CODE_COMMIT=$(git rev-parse HEAD) scripts/run_e_vps.sh \
  /absolute/output/e-final-100 \
  /absolute/output/e-generation-development/policies \
  /absolute/output/e-generation-holdout/policies \
  /absolute/output/e-generation-development/manifest.json \
  /absolute/output/e-generation-holdout/manifest.json \
  /absolute/output/full-100/captures.json
```

The E bundle includes the frozen source captures and can be independently re-audited:

```console
PYTHONPATH=src python3 scripts/audit_e.py /absolute/output/e-final-100
```

If a draft fails schema validation, E rejects the job before execution and records
`DENY_INVALID_POLICY` for model, forced, and benign tracks. This is secure fail-closed
behavior, but it counts as a benign utility failure; the runner never repairs a draft
from benchmark expectations.

## Interpretation limits

The exact-canary provenance mechanism is deliberately narrow. It is not general
semantic taint tracking. Policies are benchmark fixtures, and the strong forced-action
track measures enforcement rather than model susceptibility. Model-generated and
forced results must be reported separately. Local loopback services and synthetic
recipients prevent real-world effects; they do not reproduce production identity,
credential, or approval infrastructure.
