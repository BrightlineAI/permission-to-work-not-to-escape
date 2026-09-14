"""Fail-closed Vega pre-tool authorization for DTAP's OS-filesystem MCP."""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import threading
import time
from functools import lru_cache
from pathlib import Path
from typing import Any

from dt_arena.src.types.hooks import ToolCallContext, ToolCallResult
from vega_core import Request, TrustedContext, authorize_d, load_policy

SERVER = "OS-filesystem"
COMMON_ARGS = {"ask_for_permission", "user_original_request", "agent_explanation", "access_token"}
TOOL_ARGS = {
    "read_file": {"filepath", "head", "tail"},
    "read_multiple_files": {"filepaths"},
    "write_file": {"filepath", "content"},
    "edit_file": {"filepath", "old_text", "new_text", "dry_run"},
    "create_directory": {"dirpath"},
    "move_file": {"source", "destination"},
    "list_directory": {"dirpath", "show_hidden"},
    "list_directory_with_sizes": {"dirpath", "sort_by"},
    "directory_tree": {"dirpath", "max_depth"},
    "search_files": {"pattern", "search_path", "exclude_patterns"},
    "execute_command": {"command", "user", "workdir"},
    "check_file_exists": {"filepath"},
    "get_file_info": {"filepath"},
    "delete_file": {"filepath"},
    "delete_directory": {"dirpath", "recursive"},
    "log_action": {"action", "log_type", "details", "status", "result"},
    "get_logs": {"log_type", "limit"},
    "clear_logs": set(),
}
RESOURCE_ARG = {
    "read_file": "filepath", "write_file": "filepath", "edit_file": "filepath",
    "create_directory": "dirpath", "list_directory": "dirpath",
    "list_directory_with_sizes": "dirpath", "directory_tree": "dirpath",
    "search_files": "search_path", "check_file_exists": "filepath",
    "get_file_info": "filepath", "delete_file": "filepath",
    "delete_directory": "dirpath", "move_file": "source",
}
class VegaFastPathHook:
    def __init__(self) -> None:
        self.mode = os.getenv("VEGA_DTAP_MODE", "invalid")
        self.task_id = os.getenv("VEGA_DTAP_TASK_ID", "")
        self.principal = os.getenv("VEGA_DTAP_PRINCIPAL", "alice")
        self.trusted_hash = os.getenv("VEGA_DTAP_TRUSTED_INSTRUCTION_SHA256", "")
        self.audit_root = Path(os.getenv("VEGA_DTAP_AUDIT_ROOT", "")) if os.getenv("VEGA_DTAP_AUDIT_ROOT") else None
        self._lock = threading.Lock()
        self._sequence = 0
        self.policy = None
        self._configuration_error = None

        if self.mode not in {"baseline", "protected"}:
            self._configuration_error = "DENY_INVALID_MODE"
        elif not self.task_id or not self.trusted_hash or self.audit_root is None:
            self._configuration_error = "DENY_MISSING_CONTEXT"
        elif self.mode == "protected":
            try:
                policy_root = Path(os.environ["VEGA_DTAP_POLICY_ROOT"]).resolve()
                policy_path = (policy_root / f"{self.task_id}.json").resolve()
                if policy_root not in policy_path.parents:
                    raise ValueError("policy path escaped policy root")
                self.policy = load_policy(policy_path)
                if self.policy.job_id != self.task_id or self.policy.principal != self.principal:
                    raise ValueError("policy identity does not match runner context")
                self._validate_policy_scopes()
            except Exception as exc:
                self._configuration_error = f"DENY_POLICY:{type(exc).__name__}"

    @staticmethod
    def _canonical_path(value: Any, *, allow_scope: bool = False) -> str:
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ValueError("path must be a non-empty string without NUL")
        if not value.startswith("/") or any(part == ".." for part in value.split("/")):
            raise ValueError("path must be absolute and may not contain '..'")
        if any(character in value for character in "?[]"):
            raise ValueError("path may not contain '?', '[' or ']'")
        if not allow_scope and "*" in value:
            raise ValueError("runtime path may not contain wildcard syntax")
        if allow_scope and any("**" in segment and segment != "**" for segment in value.split("/")):
            raise ValueError("'**' is allowed only as a complete path segment")
        normalized = posixpath.normpath(value)
        if not normalized.startswith("/"):
            raise ValueError("invalid normalized path")
        if normalized != value:
            raise ValueError("path must already be canonical")
        return normalized

    def _validate_policy_scopes(self) -> None:
        assert self.policy is not None
        for grant in self.policy.allow:
            if grant.tool != SERVER:
                raise ValueError("unknown policy tool")
            if not grant.actions or any(action not in TOOL_ARGS or action == "execute_command" for action in grant.actions):
                raise ValueError("unknown or unsupported policy action")
            for scope in (*grant.resources, *grant.destinations):
                if self._canonical_path(scope, allow_scope=True) != scope:
                    raise ValueError("policy path is not canonical")
            if grant.recipients:
                raise ValueError("filesystem policy may not contain recipients")

    @staticmethod
    def _scope_matches(scope: str, actual: str) -> bool:
        pattern, value = scope.split("/")[1:], actual.split("/")[1:]

        @lru_cache(maxsize=None)
        def match(pattern_index: int, value_index: int) -> bool:
            if pattern_index == len(pattern):
                return value_index == len(value)
            segment = pattern[pattern_index]
            if segment == "**":
                return any(match(pattern_index + 1, candidate)
                           for candidate in range(value_index, len(value) + 1))
            if value_index == len(value):
                return False
            expression = re.escape(segment).replace(r"\*", "[^/]*")
            return bool(re.fullmatch(expression, value[value_index])) and match(
                pattern_index + 1, value_index + 1
            )

        return match(0, 0)

    def _policy_scope(self, actual: str, field: str, action: str) -> str:
        assert self.policy is not None
        attribute = "destinations" if field == "destination" else "resources"
        candidates = {
            scope
            for grant in self.policy.allow
            if grant.tool == SERVER and action in grant.actions
            for scope in getattr(grant, attribute)
            if self._scope_matches(scope, actual)
        }
        # Returning the longest matching declaration preserves exact-file grants
        # over a broader directory declaration when both exist.
        return max(candidates, key=len) if candidates else actual

    def _request(self, action: str, *, resource: str | None = None, destination: str | None = None) -> Request:
        if self.policy is not None:
            if resource is not None:
                resource = self._policy_scope(resource, "resource", action)
            if destination is not None:
                destination = self._policy_scope(destination, "destination", action)
        return Request(
            tool=SERVER, action=action, resource=resource, recipient=None,
            destination=destination, amount=None, payload="", approval_handle=None,
        )

    def _normalize_requests(self, ctx: ToolCallContext) -> list[Request]:
        if ctx.server != SERVER:
            raise ValueError("DENY_UNKNOWN_SERVER")
        action = ctx.tool_name
        if action not in TOOL_ARGS:
            raise ValueError("DENY_UNKNOWN_TOOL")
        unknown = set(ctx.arguments) - TOOL_ARGS[action] - COMMON_ARGS
        if unknown:
            raise ValueError("DENY_UNKNOWN_ARGUMENT")
        if ctx.arguments.get("access_token") not in {None, ""}:
            raise ValueError("DENY_TOKEN_OVERRIDE")
        if action == "execute_command":
            raise ValueError("DENY_UNTYPED_COMMAND")

        if action == "read_multiple_files":
            values = ctx.arguments.get("filepaths")
            if not isinstance(values, list) or not values:
                raise ValueError("DENY_MALFORMED_PATHS")
            return [self._request(action, resource=self._canonical_path(value)) for value in values]
        if action == "move_file":
            source = self._canonical_path(ctx.arguments.get("source"))
            destination = self._canonical_path(ctx.arguments.get("destination"))
            return [self._request(action, resource=source, destination=destination)]
        if action in RESOURCE_ARG:
            arg = RESOURCE_ARG[action]
            return [self._request(action, resource=self._canonical_path(ctx.arguments.get(arg)))]
        return [self._request(action)]

    def _audit(self, ctx: ToolCallContext, allowed: bool, reason: str, requests: list[Request]) -> None:
        if self.audit_root is None:
            return
        self.audit_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        args_hash = hashlib.sha256(
            json.dumps(ctx.arguments, sort_keys=True, separators=(",", ":"), default=str).encode()
        ).hexdigest()
        with self._lock:
            self._sequence += 1
            record = {
                "schema_version": 1,
                "sequence": self._sequence,
                "timestamp_ns": time.time_ns(),
                "mode": self.mode,
                "task_id": self.task_id,
                "trusted_instruction_sha256": self.trusted_hash,
                "server": ctx.server,
                "action": ctx.tool_name,
                "argument_names": sorted(ctx.arguments),
                "arguments_sha256": args_hash,
                "request_scopes": [
                    {"resource": request.resource, "destination": request.destination}
                    for request in requests
                ],
                "allowed": allowed,
                "reason": reason,
                "policy_hash": self.policy.policy_hash if self.policy is not None else None,
            }
            target = self.audit_root / f"{self.task_id}.jsonl"
            with target.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")

    async def on_pre_tool_call(self, ctx: ToolCallContext) -> ToolCallContext | None:
        requests: list[Request] = []
        try:
            if self._configuration_error:
                raise ValueError(self._configuration_error)
            if self.mode == "baseline":
                self._audit(ctx, True, "BASELINE_ALLOW", requests)
                return ctx
            requests = self._normalize_requests(ctx)
            assert self.policy is not None
            context = TrustedContext(job_id=self.task_id, principal=self.principal)
            decisions = [authorize_d(self.policy, request, context) for request in requests]
            denied = next((decision for decision in decisions if not decision.allowed), None)
            if denied is not None:
                self._audit(ctx, False, denied.reason, requests)
                raise PermissionError(
                    f"Vega denied {ctx.tool_name}: {denied.reason}. "
                    "Use only typed filesystem calls and paths authorized by the user's original task."
                )
            self._audit(ctx, True, "ALLOW", requests)
            return ctx
        except PermissionError:
            raise
        except Exception as exc:
            reason = str(exc) if str(exc).startswith("DENY_") else f"DENY_MALFORMED:{type(exc).__name__}"
            self._audit(ctx, False, reason, requests)
            raise PermissionError(
                f"Vega denied {ctx.tool_name}: {reason}. "
                "Use only a documented typed filesystem call with canonical authorized paths."
            ) from None

    async def on_post_tool_call(self, ctx: ToolCallContext, result: ToolCallResult) -> None:
        return None
