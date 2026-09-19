# Permission to Work, Not to Escape

Policies, Controls and Escalating Enforcement Across AI Agents

Allister Lundberg · Bright Line AI · With Apart Research

All agents working on a project should stay within its scope, even when their technical access is broader. This project tests an approach that compiles project policies into executable controls, preserves restrictions across delegated workers, and escalates combined violations from warnings to a project wide stop.

[Read the paper](paper/submission.pdf) · [Experiments](experiments/paper-2026/README.md) · [Reproduction instructions](docs/reproduction.md)

The latest PDF is the source of truth for this project.

## Results

| Experiment | What the tests showed | Code and evidence |
|---|---|---|
| 1. Misuse of granted access | Across 200 adapted cases, project controls blocked all 133 captured unauthorized requests. Baseline and nono allowed all 133; ordinary request rules allowed 96. All four configurations completed the 200 scripted permitted actions. | [Request comparison](experiments/paper-2026/vega-core/README.md) |
| 2. Policy generation | Typed generation, with or without a critic, blocked all 30 unauthorized actions and allowed all 30 permitted actions in the final evaluation. Direct generation blocked unauthorized actions on 200 previously seen cases but also blocked 20 permitted actions. | [Policy generation](experiments/paper-2026/vega-core/README.md#policy-generation-e-f-g) |
| 3. Shared escalation | One parent violation triggered a warning; a second violation by a worker stopped the parent, both workers, and their running processes. Later launches were rejected while unrelated work continued. Separate counters did not trigger the stop. | [Native stopping](experiments/paper-2026/native-stop/README.md) |

Qwen3-14B through OpenRouter generated requests and policies for the first two experiments. GPT-6 Astra/high ran the native escalation tests. Runtime controls required no additional LLM calls.

The policy comparisons used different data splits and validation guidance. Scripted permitted actions are not complete assignments: in a separate ten-assignment comparison, protection reduced successful attacks from one to zero, but completed assignments fell from four to three. See the [native task results](experiments/paper-2026/dtap-vega/README.md).

These controlled tests support a mechanism toward swarm protection, not a demonstrated defense against adaptive swarms. Supporting file, worker, diagnostic and escalation checks are in the [experiment catalog](experiments/paper-2026/README.md).

## Run the checks

Python 3.11+. These commands inspect the evidence and run offline unit tests without model calls:

```sh
python3 scripts/verify_evidence.py
python3 scripts/check_docs.py
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

For a small booking-policy demo, run `PYTHONPATH=src python3 -m permission_to_work demo`. It rejects fake approval and accepts genuine approval without making a booking.

Run fresh benchmark workloads on an isolated Linux VPS using the [reproduction instructions](docs/reproduction.md) and each experiment's README.

## Build on the work

The [project safety harness](harness/README.md) adds reviewed policies, narrower tasks,
shared controls across agents, and auditing of selected Codex logs.
Use the [recoverable Linux installer](harness/INSTALL.md) from a compact, verified
application artifact. Local release building is available; an online release is
not yet published. With the [interactive quickstart](harness/INTERACTIVE.md), run
`ptw codex` in a new or existing repository. Review the policy, then work in
the normal Codex terminal. First setup uses typed templates without a model
roundtrip. For root files, use `ptw codex --editable src,tests --files README.md,app.py`.
Continue a protected conversation through
`ptw codex --resume ID`; see [current daily-work limits](harness/DAILY.md).
The review shows warn1/stop3 and package restrictions before explicit approval;
generated files are published recoverably afterward. Edits, packages, builds, tests and delegates use
shared controls underneath. [Python and npm package checks](harness/ECOSYSTEMS.md)
cover known vulnerabilities and release age. This prototype is separate from
the paper's frozen experiments.

Installed dependencies also undergo [bounded reassessment before reuse](harness/REASSESSMENT.md).
Outages block unsafe reuse without misconduct counts; confirmed forbidden
dependencies quarantine affected project sets and stop their registered work.

Dependency setup supports reviewed Python runtimes, mixed-project setup,
explicit source scopes and `ptw deps add/remove/update` reviews. For a local
Python project, run:

```sh
ptw codex --editable src,tests --python-editable src --setup-only
```

Review the source resources and offline backend execution, then run `ptw codex`.
Use `--python-wheel` for a fixed installation. Dynamic metadata and additional
build requirements need separate explicit reviews. `--python-native-wheels`
requests native output; changed compiled inputs need reviewed rebuilding.
Multiple local sources keep separate build environments and share one validated
runtime installation. Static and dynamic uv locks retain authoritative inputs.

See the [local setup guide](harness/ONBOARDING.md#local-python-preparation)
for live-edit limits, builds, rejection and recovery. Common formats include
requirements, PEP 621, uv/Poetry locks, npm workspaces, pnpm v9 and Yarn Classic v1.
Use the pinned tool setup in the [Poetry](harness/POETRY.md),
[pnpm](harness/PNPM.md) and [Yarn](harness/YARN.md) guides. Frozen imports preserve
their authority; dependency changes use explicit `ptw deps add/remove/update`
review. Lifecycle builds require named approval.

The accepted adapters and focused native journeys establish useful imports,
builds, compatible dependency selection and confined local/private sources.
The [bounded support matrix and validation status](harness/DEPENDENCY_STATUS.md)
distinguish these results from final integration acceptance. Manager checks passed
the source and fresh-wheel journey matrices; final-source integration acceptance,
complete product readiness and first-setup timing remain separate gates.
The [acceptance evidence guide](harness/ACCEPTANCE.md) provides the seven-journey
runner, strict evidence gate and reproduction commands. Full final-source product
acceptance and public installation remain pending manager validation.

The repository includes experimental policy, authorization, diagnostic and escalation components. See the [architecture](docs/architecture.md), [data availability](docs/evidence.md), [future work](docs/roadmap.md) and [contribution guide](CONTRIBUTING.md).

Original code is [MIT licensed](LICENSE). Third-party materials retain their [own terms](THIRD_PARTY_NOTICES.md). Use [CITATION.cff](CITATION.cff) to cite the work.
