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
The review shows warn1/stop3 and package restrictions before explicit approval;
generated files are published recoverably afterward. Edits, packages, builds, tests and delegates use
shared controls underneath. [Python and npm package checks](harness/ECOSYSTEMS.md)
cover known vulnerabilities and release age. This prototype is separate from
the paper's frozen experiments.

Current dependency work adds reviewed Python runtimes, mixed-project setup,
workspace source scopes and explicit `ptw deps add/remove/update` reviews.
For a local Python package, use
`ptw codex --editable src,tests --python-editable src --setup-only` and review the
source resources and offline backend execution. Pure-Python implementation edits
then appear in protected imports. Use `--python-wheel` for a fixed installation,
`--python-extras NAME` for optional dependencies, and
`--python-build-requirements` to review additional backend requirements.
Dynamic metadata uses separate discovery and installation reviews.
Add `--python-native-wheels` to request native output. Compiled inputs need
explicit `ptw codex --revise` re-preparation after changes. Current source also
permits live Python edits alongside declarative setuptools extensions; that new
path awaits native validation. Generated libraries remain private and scoped to
command inputs. Requirements containing `-e .` accept the same explicit editable
review with `--python-source requirements.in`. Static `uv.lock` projects retain
locked runtime versions and artifact hashes while resolving additional build
requirements. The manager passed all 162 preceding tests, including dynamic
metadata reviews, compiled imports/rebuilds, root requirements terminal flows
and combined locked runtime/build dependencies.
Broader local formats remain incomplete. See the [local setup flow](harness/ONBOARDING.md#local-python-preparation).
[Full ecosystem acceptance remains incomplete](harness/DEPENDENCY_STATUS.md);
the format matrix distinguishes implemented paths and pending native checks
from ordinary formats that still need implementation.

The repository includes experimental policy, authorization, diagnostic and escalation components. See the [architecture](docs/architecture.md), [data availability](docs/evidence.md), [future work](docs/roadmap.md) and [contribution guide](CONTRIBUTING.md).

Original code is [MIT licensed](LICENSE). Third-party materials retain their [own terms](THIRD_PARTY_NOTICES.md). Use [CITATION.cff](CITATION.cff) to cite the work.
