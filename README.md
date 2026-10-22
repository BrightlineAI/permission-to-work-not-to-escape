# Permission to Work, Not to Escape

Policies, Controls and Escalating Enforcement Across AI Agents

Allister Lundberg · Bright Line AI · With Apart Research

All agents working on a project should stay within its scope, even when their technical access is broader. This project tests an approach that compiles project policies into executable controls, preserves restrictions across delegated workers, and escalates combined violations from warnings to a project wide stop.

## Start here

| What you want to do | Where to start |
|---|---|
| Read the paper | [Paper PDF](paper/submission.pdf) |
| Inspect the experiments and published results | [Experiment catalog](experiments/paper-2026/README.md): experiments 1 and 2 are in `vega-core`; experiment 3 is in `native-stop` |
| Run the paper experiments | [Reproduction guide](docs/reproduction.md): setup, a small integration run, fresh experiment commands and audits |

The linked PDF is the reference for the research claims. The separate [test harness](#separate-test-harness) is unrelated to the paper and is not needed to inspect or reproduce its experiments.

### Check the published evidence

With Git and Python 3.11+, start from a fresh clone:

```sh
git clone https://github.com/BrightlineAI/permission-to-work-not-to-escape.git
cd permission-to-work-not-to-escape
python3 scripts/verify_evidence.py
```

Success prints JSON with `"passed": true`. This checks published files and selected result calculations; it does **not** rerun the experiments. It needs no model account, makes no network requests after cloning and incurs no model charges. For a new execution, follow the [Linux reproduction walkthrough](docs/reproduction.md#run-a-small-integration-check).

## Results

| Experiment | What the tests showed | Code and evidence |
|---|---|---|
| 1. Misuse of granted access | Across 200 adapted cases, project controls blocked all 133 captured unauthorized requests. Baseline and nono allowed all 133; ordinary request rules allowed 96. All four configurations completed the 200 scripted permitted actions. | [Request comparison](experiments/paper-2026/vega-core/README.md) |
| 2. Policy generation | Typed generation, with or without a critic, blocked all 30 unauthorized actions and allowed all 30 permitted actions in the final evaluation. Direct generation blocked unauthorized actions on 200 previously seen cases but also blocked 20 permitted actions. | [Policy generation](experiments/paper-2026/vega-core/README.md#policy-generation-e-f-g) |
| 3. Shared escalation | One parent violation triggered a warning; a second violation by a worker stopped the parent, both workers, and their running processes. Later launches were rejected while unrelated work continued. Separate counters did not trigger the stop. | [Native stopping](experiments/paper-2026/native-stop/README.md) |

Qwen3-14B through OpenRouter generated requests and policies for the first two experiments. GPT-6 Astra/high ran the native escalation tests. Runtime controls required no additional LLM calls.

The policy comparisons used different data splits and validation guidance. Scripted permitted actions are not complete assignments: in a separate ten-assignment comparison, protection reduced successful attacks from one to zero, but completed assignments fell from four to three. See the [native task results](experiments/paper-2026/dtap-vega/README.md).

These controlled tests support a mechanism toward swarm protection, not a demonstrated defense against adaptive swarms. Supporting file, worker, diagnostic and escalation checks are in the [experiment catalog](experiments/paper-2026/README.md).

## Additional offline checks

From the repository root, these check documentation links and core unit tests without model calls:

```sh
python3 scripts/check_docs.py
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The optional booking-policy demonstration is `PYTHONPATH=src python3 -m permission_to_work demo`. It rejects fake approval and accepts genuine approval without making a booking. This is a demonstration, not a paper experiment.

## Separate test harness

The [experimental test harness](harness/README.md) is **unrelated to the paper**. It is for trying project policies and agent controls; it was not used for the paper's experiments, and the paper's results do not validate it. You do not need to install it to read the paper, inspect results or reproduce the experiments.

If you specifically want to try the test harness, use its [installation guide](harness/INSTALL.md), [three-demo quickstart](docs/demos/TRY-VEGA.md) and [interactive quickstart](harness/INTERACTIVE.md). Its platform requirements and limitations are documented separately.

## Build on the research

The repository includes experimental policy, authorization, diagnostic and escalation components. See the [architecture](docs/architecture.md), [data availability](docs/evidence.md), [future work](docs/roadmap.md) and [contribution guide](CONTRIBUTING.md).

Original code is [MIT licensed](LICENSE). Third-party materials retain their [own terms](THIRD_PARTY_NOTICES.md). Use [CITATION.cff](CITATION.cff) to cite the work.
