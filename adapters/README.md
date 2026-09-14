# Execution adapters

Adapters connect a validated policy to a real execution boundary. This directory is the extension point for reusable integrations; the existing study integrations remain beside their frozen experiments.

| Existing integration | Source | Boundary |
|---|---|---|
| Ordinary gateway and contextual decisions | [Core gateway](../experiments/paper-2026/vega-core/gateway/) and [core source](../src/vega_core/) | Request fields and trusted contextual authorization around a mock service |
| nono permissions across routes | [Permission preservation](../experiments/paper-2026/permission-preservation/README.md) | Tested files across tool/shell and parent/scripted-worker routes |
| Native DTAP pre-tool hook | [DTAP hooks](../experiments/paper-2026/dtap-vega/hooks/) | Narrow filesystem tool interface; documented lexical-path limits |
| Native whole-job stop | [Native stop](../experiments/paper-2026/native-stop/README.md) | Host-bound violation state, new admissions and actual systemd cgroup termination |

A reusable adapter should declare which resources/tools it mediates, how it binds trusted identity, how it handles batched/delegated calls, and how termination is verified. Supply an actual permitted task and forbidden-effect probe before calling it supported. See [architecture](../docs/architecture.md) and [adding an experiment](../docs/adding-an-experiment.md).
