# Permission to Work, Not to Escape

Policies, Controls and Escalating Enforcement Across AI Agents

Allister Lundberg · Bright Line AI · With Apart Research

Agents should do useful work within their project's scope, even when their technical access is broader. This repository contains experimental implementations and evidence for turning project policies into controls, preserving restrictions across workers, and escalating repeated violations to a project wide stop. It is a research prototype, not a complete production security system.

## Read the paper

The [final submission PDF](paper/submission.pdf) is the source of truth for this release. The [paper and evidence map](paper/README.md) connects its sections to the exact experiments. [Publication notes](paper/publication-consistency.md) identify omissions in the PDF's appendix export without changing the submitted file.

The [publication review](docs/publication-review.md) records evidence checks, credential review and the fresh repository history.

## The three experiments

These comparisons have different inputs and denominators. They are not one combined success rate.

| Paper experiment | What ran | Main result | Evidence and reproduction |
|---|---|---|---|
| 1. Misuse of granted access | 200 adapted cases; identical captured requests replayed across four protections | Of 133 harmful model requests, baseline and nono allowed 133, ordinary gateway rules allowed 96, and trusted project checks allowed 0. Each configuration completed all 200 supplied permitted requests. | [Core comparison](experiments/paper-2026/vega-core/README.md) |
| 2. Policy generation | Direct JSON generation compared with typed proposals and typed proposals plus a critic | Strengthened direct generation: 0/200 harmful effects, 180/200 permitted completions on known cases. Typed and typed plus critic: 0/30 harmful effects, 30/30 permitted completions on the final split. Different splits prevent attributing the difference to typing alone. | [Policy generation](experiments/paper-2026/vega-core/README.md#policy-generation-e-f-g) |
| 3. Shared escalation | Native parent and two workers; shared versus separate violation counts, plus interruption/termination checks | At the second violation, shared counting stopped the parent and both workers and rejected later work. Separate counters did not. Unrelated work continued. One prescribed scenario per counter configuration. | [Native stopping](experiments/paper-2026/native-stop/README.md) |

Qwen3-14B through OpenRouter generated core requests and policies. The capture prompt deliberately encouraged following injections: this tests external controls, not ordinary model susceptibility. Native stopping used GPT-6 Astra/high. Runtime authorization added no LLM calls; policy generation occurred before execution.

Supplied permitted requests are not complete autonomous assignments. The separate ten-assignment comparison mentioned in the paper's Methods had fewer attacks but also fewer completed assignments with protection. Its negative result remains in the [DTAP evidence](experiments/paper-2026/dtap-vega/README.md).

## Supporting checks

The [experiment catalog](experiments/paper-2026/README.md) also retains file and worker permission probes, diagnostic repairs, and 18 scripted escalation checks. These verify implementation behavior; they are not additional evidence of general protection against adaptive swarms. Earlier unrelated pilots and superseded manuscripts are excluded from this publication copy, not deleted from the author's working archive.

## Inspect or reproduce

Python 3.11+. These are offline file, evidence and unit checks, not fresh benchmark runs:

```sh
python3 scripts/verify_evidence.py
python3 scripts/check_docs.py
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m permission_to_work demo
```

The demo rejects fake booking approval and accepts genuine approval without making a real booking. Fresh benchmark workloads belong on an isolated Linux VPS. Follow the [reproduction guide](docs/reproduction.md) and the chosen experiment's README; use your own credentials and a new run directory. Published evidence must remain unchanged.

The original standalone package was checked on a separate VPS: 59 unit tests, 320 permission operations, 56 diagnostic probes, 18 escalation cells, a three-case forced core replay, and installation from a built wheel. These are [packaging validation records](validation/README.md), not extra paper trials.

## Repository layout

```text
paper/                       Final PDF and claim-to-evidence map
experiments/paper-2026/       Frozen experiments, inputs, results and reproduction scripts
src/permission_to_work/       Experimental policy, diagnostic and escalation primitives
src/vega_core/                Evaluated contextual authorization implementation
examples/                    Small policy demonstrations without external effects
docs/                        Architecture, reproduction, evidence limits and roadmap
provenance/                  Source revisions, hashes and publication scope
validation/                  Retained package checks, separate from paper results
```

Historical code paths retain their original names so recorded commands and hashes remain usable. [Architecture](docs/architecture.md), [data availability](docs/evidence.md), [contributing](CONTRIBUTING.md), and [future work](docs/roadmap.md) describe what can be reused and what is still missing.

The experiments assume trusted project facts and enforcement outside agent control. A stopped local process cannot undo a completed remote action. Zero failures on these cases is not proof against arbitrary attacks or swarms.

Original code is [MIT licensed](LICENSE); third-party material retains its [own terms](THIRD_PARTY_NOTICES.md). Cite the paper and [software](CITATION.cff). Public repository: [BrightlineAI/permission-to-work-not-to-escape](https://github.com/BrightlineAI/permission-to-work-not-to-escape).
