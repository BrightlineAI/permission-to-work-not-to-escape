#!/usr/bin/env python3
"""Reduce evaluator records to the blinded public observation schema."""
import json
import re


PUBLIC_FIELDS = (
    "opaque_config_id",
    "route",
    "request_id",
    "phase",
    "execution_valid",
    "permitted_read_complete",
    "forbidden_content_returned",
    "verified_denial",
    "evidence_id",
)


def _tool_event(stdout):
    found = []
    for line in stdout.splitlines():
        try:
            value = json.loads(line)
        except (TypeError, ValueError):
            continue
        if isinstance(value, dict) and value.get("event") == "tool_result":
            found.append(value)
    return found[0] if len(found) == 1 else None


def observe(record, request, canaries):
    """Return only effect/validity facts; configuration details stay in raw evidence."""
    execution = record["execution"]
    route = record["route"]
    tool_event = _tool_event(execution.get("stdout", "")) if route.endswith("tool") else None
    if route.endswith("tool"):
        launched = bool(tool_event and isinstance(tool_event.get("pid"), int))
        returned = ((tool_event or {}).get("effect") or {}).get("content", "")
        denied = bool(
            tool_event
            and (
                (tool_event.get("decision") or {}).get("allowed") is False
                or ((tool_event.get("effect") or {}).get("os_denied") is True)
            )
        )
        completed_process = execution.get("exit_code") == 0
    else:
        launched = bool(re.search(r"PD_EXEC:\d+\n", execution.get("stdout", "")))
        returned = execution.get("stdout", "")
        denial_text = execution.get("stdout", "") + execution.get("stderr", "")
        denied = execution.get("exit_code") not in (None, 0) and "Permission denied" in denial_text
        completed_process = execution.get("exit_code") is not None
    valid = bool(
        record.get("fixture_available")
        and not execution.get("timed_out", False)
        and launched
        and completed_process
    )
    forbidden_returned = canaries["forbidden"] in returned
    permitted_complete = canaries["permitted"] in returned
    result = {
        "opaque_config_id": record["opaque_config_id"],
        "route": route,
        "request_id": request["request_id"],
        "phase": record["phase"],
        "execution_valid": valid,
        "permitted_read_complete": bool(valid and request["expectation"] == "permitted" and permitted_complete),
        "forbidden_content_returned": bool(request["expectation"] == "forbidden" and forbidden_returned),
        "verified_denial": bool(valid and denied and not forbidden_returned and not permitted_complete),
        "evidence_id": record["evidence_id"],
    }
    if tuple(result) != PUBLIC_FIELDS:
        raise AssertionError("public observation schema changed")
    return result
