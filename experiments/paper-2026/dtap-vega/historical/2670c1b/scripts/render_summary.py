#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


def _num(value, digits=2):
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    summary = json.loads(Path(args.summary).read_text())
    lines = [
        "# Native DTAP/Vega result",
        "",
        f"Status: **{summary['evaluation_status']}**. Each arm used an independent native trajectory.",
        "",
        "| Native arm | Valid | Utility | Attacks | Joint | Policy LLM calls | Policy input/output tokens | Policy cost (USD) | Policy wall (s) | Agent calls/turns | MCP attempts (allow/deny) | Arm wall (s) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for arm in summary.get("arms", []):
        c, o = arm["counts"], arm["overhead"]
        g = o["policy_generation"]
        tokens = (f"{g.get('prompt_tokens', 0)}/{g.get('completion_tokens', 0)}"
                  if "prompt_tokens" in g else "—")
        calls = g.get("llm_calls", 0)
        if g.get("reused_frozen_artifact"):
            calls = f"{calls} created; 0 rerun"
        lines.append(
            f"| `{arm['arm']}` | {c['valid']}/{c['selected']} | {c['utility_pass']} | "
            f"{c['attack_success']} | {c['joint_safe_and_useful']} | {calls} | {tokens} | "
            f"{_num(g.get('reported_cost_usd'), 6)} | {_num(g.get('wall_seconds'))} | "
            f"{o['agent_llm_calls']}/{o['agent_turns']} | "
            f"{o['mediated_mcp_tool_call_attempts']} ({o['hook_allows']}/{o['hook_denials']}) | "
            f"{_num(o.get('native_run_wall_seconds'))} |"
        )
    lines += [
        "",
        "Policy generation occurs before the job. Vega's compiler and pre-tool hook are deterministic and add **zero LLM calls after policy creation**.",
        "DTAP trajectory tool-event counts, detailed case outcomes, hashes, provider/model resolution, and invalid-run reasons remain in `summary.json`.",
        "",
    ]
    Path(args.output).write_text("\n".join(lines))


if __name__ == "__main__":
    main()
