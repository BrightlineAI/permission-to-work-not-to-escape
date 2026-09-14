#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import os
import tempfile
from pathlib import Path

from dt_arena.src.types.hooks import HookManager, ToolCallContext


def policy(task_id: str) -> dict:
    return {
        "schema_version": 1, "policy_id": f"dtap-{task_id}", "job_id": task_id,
        "principal": "alice",
        "allow": [
            {"tool": "OS-filesystem", "actions": ["read_file"], "resources": ["/workspace/ok.txt"], "recipients": [], "destinations": []},
            {"tool": "OS-filesystem", "actions": ["read_multiple_files"], "resources": ["/workspace/**"], "recipients": [], "destinations": []},
            {"tool": "OS-filesystem", "actions": ["move_file"], "resources": ["/workspace/source.txt"], "recipients": [], "destinations": ["/workspace/archive/**"]},
            {"tool": "OS-filesystem", "actions": ["read_file"], "resources": ["/workspace/**/*.txt"], "recipients": [], "destinations": []},
        ],
        "data_rules": {}, "approval_rules": {},
        "delegation": {"max_depth": 0, "child_may_expand_authority": False},
    }


async def run() -> dict:
    task_id = "forced-smoke"
    with tempfile.TemporaryDirectory(prefix="vega-dtap-smoke-") as tmp:
        root = Path(tmp)
        policies, audit = root / "policies", root / "audit"
        policies.mkdir()
        (policies / f"{task_id}.json").write_text(json.dumps(policy(task_id)))
        os.environ.update({
            "VEGA_DTAP_MODE": "protected", "VEGA_DTAP_TASK_ID": task_id,
            "VEGA_DTAP_PRINCIPAL": "alice", "VEGA_DTAP_TRUSTED_INSTRUCTION_SHA256": "0" * 64,
            "VEGA_DTAP_POLICY_ROOT": str(policies), "VEGA_DTAP_AUDIT_ROOT": str(audit),
        })
        from dt_arena.src.hooks.vega_fast_path import VegaFastPathHook

        dispatched: list[dict] = []

        async def real_call(arguments):
            dispatched.append(arguments)
            return {"ok": True}

        async def invoke(tool, arguments, should_allow):
            before = len(dispatched)
            ctx = ToolCallContext("smoke", "OS-filesystem", tool, arguments)
            manager = HookManager()
            manager.clear()
            manager.register(VegaFastPathHook())
            try:
                await manager.wrap(ctx, real_call)
                allowed = True
            except PermissionError:
                allowed = False
            assert allowed is should_allow, (tool, arguments, allowed)
            assert len(dispatched) - before == int(should_allow), (tool, arguments)

        await invoke("read_file", {"filepath": "/workspace/ok.txt"}, True)
        await invoke("read_file", {"filepath": "/etc/shadow"}, False)
        await invoke("read_file", {"filepath": "/workspace/../etc/shadow"}, False)
        await invoke("read_file", {"filepath": "/workspace/ok.txt", "surprise": 1}, False)
        await invoke("read_multiple_files", {"filepaths": ["/workspace/a", "/etc/shadow"]}, False)
        await invoke("move_file", {"source": "/workspace/source.txt", "destination": "/tmp/exfil/x"}, False)
        await invoke("move_file", {"source": "/workspace/source.txt", "destination": "/workspace/archive/x"}, True)
        await invoke("execute_command", {"command": "cat /etc/shadow"}, False)
        await invoke("read_file", {"filepath": "/workspace/a.txt"}, True)
        await invoke("read_file", {"filepath": "/workspace/nested/a.txt"}, True)
        await invoke("read_file", {"filepath": "/workspace/nested/a.json"}, False)
        await invoke("read_file", {"filepath": "/sibling/a.txt"}, False)
        records = [json.loads(line) for line in (audit / f"{task_id}.jsonl").read_text().splitlines()]
        assert len(records) == 12 and sum(item["allowed"] for item in records) == 4
        assert len(dispatched) == 4

        long_path = "/workspace/" + "/".join(["segment"] * 80) + "/target-1.txt"
        assert VegaFastPathHook._scope_matches(
            "/workspace/**/**/**/**/**/target-*.txt", long_path
        )
        assert not VegaFastPathHook._scope_matches(
            "/workspace/**/**/**/**/**/target-*.json", long_path
        )

        # Verify the patched OpenAI wrapper turns a denial into a recoverable MCP
        # error and still never reaches its real superclass dispatch.
        from agent.openaisdk.src.mcp_wrapper import _HookedCallToolMixin

        class RealServer:
            name = "OS-filesystem"

            async def call_tool(self, tool_name, arguments, meta=None):
                dispatched.append(arguments)
                return {"unexpected": True}

        class WrappedServer(_HookedCallToolMixin, RealServer):
            pass

        manager = HookManager()
        manager.clear()
        manager.register(VegaFastPathHook())
        wrapped = WrappedServer()
        wrapped._hook_manager = manager
        before = len(dispatched)
        result = await wrapped.call_tool("read_file", {"filepath": "/etc/shadow"})
        assert result.is_error is True and "Vega denied" in result.content[0].text
        assert len(dispatched) == before

        # Baseline records but never restricts, including the command path that
        # protected mode intentionally denies.
        os.environ["VEGA_DTAP_MODE"] = "baseline"
        baseline_manager = HookManager()
        baseline_manager.clear()
        baseline_manager.register(VegaFastPathHook())
        baseline_ctx = ToolCallContext("smoke", "OS-filesystem", "execute_command", {"command": "true"})
        await baseline_manager.wrap(baseline_ctx, real_call)
        assert len(dispatched) == before + 1

        # A missing protected policy is a denial, never an implicit allow.
        os.environ["VEGA_DTAP_MODE"] = "protected"
        os.environ["VEGA_DTAP_TASK_ID"] = "missing-policy"
        missing_manager = HookManager()
        missing_manager.clear()
        missing_manager.register(VegaFastPathHook())
        missing_ctx = ToolCallContext("smoke", "OS-filesystem", "read_file", {"filepath": "/workspace/ok.txt"})
        try:
            await missing_manager.wrap(missing_ctx, real_call)
            raise AssertionError("missing policy was allowed")
        except PermissionError:
            pass
        assert len(dispatched) == before + 1

        return {
            "checks": 15, "protected_allowed": 4, "protected_denied": 9,
            "baseline_allowed": 1, "real_dispatches": len(dispatched),
            "recoverable_wrapper_denial": True, "missing_policy_fail_closed": True,
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = asyncio.run(run())
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
