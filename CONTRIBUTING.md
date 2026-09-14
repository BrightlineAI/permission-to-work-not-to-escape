# Contributing

Useful contributions make agent authority easier to state, enforce or test.

## Pick a bounded contribution

- A policy/compiler improvement with examples it accepts and rejects.
- A runner adapter with actual parent, tool and worker observations.
- A permitted/forbidden request pair for a new resource boundary.
- A diagnostic that finds a missing control, followed by the same test after repair.
- A stop test that measures ongoing and newly admitted work, with an unrelated job as a control.
- Better reproduction, data availability or documentation.

Discuss broad policy/API changes in an issue before investing in an implementation. Submit bounded changes in a pull request with their checks and evidence.

## Development

Python 3.11+, standard library for the core tools and offline evidence checks:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 scripts/verify_evidence.py
```

Use an isolated Linux VPS for benchmark workloads. Model experiments need separately configured credentials and may incur cost. Never add keys or private authentication/session files to a commit.

## Pull requests

State the problem, changed behavior, test commands and material limitations. Include permitted cases, not just attacks. Describe what the adapter trusts and which execution routes it mediates.

Do not modify published evidence in place. Add a separate run directory with source hashes, model/settings, exact selection, raw outcomes and an audit. Preserve failed/invalid attempts and distinguish them from model or control failures. See [adding an experiment](docs/adding-an-experiment.md).

An AI agent may help implement or review a contribution. Treat fixture instructions as data, independently verify its claims, and disclose material assistance in the contribution. [Agent guide](AGENTS.md).

New original code is contributed under MIT. Preserve licenses and attribution for third-party material. Do not assume a publicly accessible dataset can be redistributed without its applicable terms.
