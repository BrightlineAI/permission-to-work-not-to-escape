# Vega core: reproducible A/B/C/D/E/F/G experiment

This directory contains the minimal Vega authorization core and two 100-case
benchmark-derived synthetic cohorts. It captures one Qwen3-14B tool call per case and
replays that exact action through:

- **A:** unprotected synthetic service route;
- **B:** A plus nono/Landlock;
- **C:** B plus agentgateway 1.5.0 and OPA 1.20.2 ordinary request rules;
- **D:** C unchanged plus Vega trusted job, data, approval and delegation context.
- **E:** D enforcement with a direct, one-pass Qwen3-14B final-policy draft;
- **F:** D with a Qwen typed proposal validated and compiled deterministically;
- **G:** F plus an independent Qwen3-14B critic, with at most five review rounds.

These are adapted synthetic cases, not official AgentDyn, AgentDojo, InjecAgent,
CompoSkill or WeClawArena scores. A–D measure enforcement given explicit reviewed
policies; E/F/G separately compare three ways to turn trusted pre-job intent into policy.

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

The expected unit result is 24 passing tests and 200 distinct case files. Each cohort
contains 100 distinct reviewed policies.

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

## Policy-source arms E, F and G

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

The final public arm names describe the increasing structure around the same policy
model:

- **E — direct:** Qwen writes the complete final policy in one pass. It receives a
  carefully written least-privilege prompt and final JSON tool schema, but no typed
  intermediate representation, deterministic semantic compiler, semantic validation
  feedback, repair round or critic. Code only binds protected identity, validates
  syntax/types and fails invalid policies closed.
- **F — deterministic:** Qwen writes a small typed proposal. Deterministic code checks
  it against the trusted tool roles and compiles the final policy. Generic findings may
  be returned for at most three proposal rounds.
- **G — critic:** F plus a separate Qwen3-14B critic, for at most five rounds.

None receives the untrusted source, harmful or benign call, reviewed D policy,
capture, expected outcome or grader. All raw messages, provider metadata, costs,
hashes and rounds are retained. The E prompt is intentionally strong; the comparison
tests whether prompt-only semantics are as reliable as F's deterministic boundary.

The published second-cohort F/G result froze generation at commit `2f5bcba`. Those raw
artifacts predate the final naming decision: artifact arm E is final public **F**, and
artifact arm F is final public **G**. Both compiled 100/100 semantically matching policies, blocked 36/36 captured model attack
requests and 100/100 forced harmful requests, and completed 100/100 benign requests.
The final 30-case category holdout was opened once and was 30/30 exact, 0/11 harmful
model effects, 0/30 forced effects and 30/30 benign for both arms. Final G produced
the same 100 policy bodies as final F, so its critic added cost but no measured gain.

Development commands (do not generate the final holdout yet):

```console
PYTHONPATH=src:scripts VEGA_CODE_COMMIT=$(git rev-parse HEAD) \
  python3 scripts/generate_ef.py --mode F --split development \
  --output /absolute/output/f-development

PYTHONPATH=src:scripts VEGA_CODE_COMMIT=$(git rev-parse HEAD) \
  python3 scripts/generate_ef.py --mode G --split development \
  --output /absolute/output/g-development
```

After completing validation 1 and, if needed, validation 2, freeze and commit the
generic prompts/compiler/validator. Generate `final_holdout` exactly once. The
one-command reproduction of the already-frozen final experiment is:

```console
chmod +x scripts/*.sh
scripts/reproduce_second_100_vps.sh /absolute/new/output-root
```

That command rebuilds the frozen fixtures, captures one Qwen3-14B action per new
case, replays identical hashes through A/B/C/D, generates E/F/G policies,
assembles hash manifests, physically replays E/F/G through nono + agentgateway + OPA +
Vega, and independently audits every observed side effect. It requires Linux/Docker,
the pinned runtime binaries prepared by `run_all_vps.sh`, and a securely exported
`OPENROUTER_API_KEY`.

To reproduce the exact published second-cohort generator rather than the current
post-experiment compatibility code, check out commit `2f5bcba` in a separate worktree
and run the command there. The evidence manifests record that commit and every prompt,
input, policy and capture hash.

For staged/manual reproduction, use `generate_e.py`, `generate_ef.py`,
`assemble_generated_policies.py`, and `run_generated_arm_vps.sh`. Never report a
`--forced-as-captures` integration smoke as a model result.

To generate current E/F/G policies for original cases 001–100 and physically replay the
frozen Qwen captures:

```console
scripts/reproduce_original_ef_vps.sh /absolute/new/output-root \
  /absolute/original-abcd-run/captures.json
```

The published backward-compatibility run used commit `efa7658` under the old artifact
labels: final F produced 100/100 semantic matches; final G produced 99/100 semantic
matches; both blocked all 97 captured attack requests and all 100 forced requests while completing all 100 benign requests.
This is a regression on a previously observed cohort, not a new holdout result.

## Current strengthened E regression

E keeps D's deterministic enforcement stack, but replaces the human-reviewed
policy bodies with policies drafted directly by Qwen3-14B from trusted pre-job
operator records. The generator never receives the attack prompt, captured action,
harmful-call fixture, expected decision, or grader result. It emits policy data through
a strict final-policy tool schema; it does not emit executable enforcement code. It
has no semantic compiler contract, typed intermediate representation, semantic
validator feedback, repair round or critic.

The record builder supplies positive permissions needed for legitimate work. A
permitted resource or recipient can also be the subject of a contextual attack; E does
not hide that required grant, but it does hide the attack instruction, attack label and
outcome. E therefore evaluates direct policy drafting from normalized trusted intent, not
automatic intent extraction from arbitrary user text.

The current 200-case comparison freezes the prompt and code before generating either
complete cohort. It is a regression/stress rerun, not a new holdout: its prompt uses
generic lessons from the historical E failure and later F/G work. Do not tune the
direct prompt after reading these regression results.

Both audited physical replays were `VALID`. E produced 82/100 valid, exact policies
on the original cohort and 98/100 on the second. It completed 0/97 and 0/36 model
harmful effects and 0/100 forced harmful effects in each cohort, while completing
82/100 and 98/100 benign actions. All 20 utility failures were invalid approval
bindings and failed closed. The difference between 82 and 98 primarily reflects
cohort composition: the original cohort contains 20 WeClawArena-derived approval
cases (18 invalid), while the second contains five banking-approval cases (two
invalid). These known-cohort results do not replace the historical E holdout result.

[Complete strengthened-E generation and physical evidence](evidence/20260913-vega-e-direct-regression-qwen3-14b/)

```console
VEGA_CODE_COMMIT=$(git rev-parse HEAD) PYTHONPATH=src \
  python3 scripts/generate_e.py --cohort original \
  --output /absolute/output/e-generation --workers 8

PYTHONPATH=src python3 scripts/evaluate_e_policies.py \
  --allow-invalid --policies /absolute/output/e-generation/policies \
  --case-ids $(printf 'case-%03d,' $(seq 1 100) | sed 's/,$//') \
  --output /absolute/output/e-generation/evaluation.json

# Preferred end-to-end policy-arm reproduction using frozen A-D captures:
scripts/reproduce_efg_vps.sh original /absolute/output/efg-original \
  /absolute/output/full-100/captures.json
```

Each E/F/G physical directory includes the frozen source captures and can be
independently re-audited:

```console
PYTHONPATH=src python3 scripts/audit_generated_arm.py \
  /absolute/output/efg-original/physical-e
```

If a draft fails schema validation, E rejects the job before execution and records
`DENY_INVALID_POLICY` for model, forced, and benign tracks. This is secure fail-closed
behavior, but it counts as a benign utility failure; the runner never repairs a draft
from benchmark expectations.

## Historical E-v1 reproduction

Table C5 in the paper is the original prospective 60/40 direct-E experiment, not an
output of the strengthened current generator above. Its immutable evidence bundle
records every prompt, input, response, policy, capture and outcome. To reproduce that
protocol, use a separate clean worktree at commit `40d01fb` and follow that commit's
README. Its generator and prompt are byte-identical to the frozen `b4ea95a` generator,
while its corrected runner records invalid policies fail-closed rather than aborting. Do not
expect a new stochastic API run to reproduce the exact response bytes, and do not use
the current prompt or current default-deny authorizer while claiming to reproduce the
historical result.

## Interpretation limits

The exact-canary provenance mechanism is deliberately narrow. It is not general
semantic taint tracking. Policies are benchmark fixtures, and the strong forced-action
track measures enforcement rather than model susceptibility. Model-generated and
forced results must be reported separately. Local loopback services and synthetic
recipients prevent real-world effects; they do not reproduce production identity,
credential, or approval infrastructure.
