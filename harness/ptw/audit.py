"""Read selected Codex JSONL, never execute logs or infer permission from use."""
import json
from pathlib import Path
import re
import shlex

from .policy import Invalid, scope
from .store import Store


def strict_pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError("Ambiguous duplicate field")
        value[key] = item
    return value


def read_rows(path):
    if Path(path).stat().st_size > 10_000_000:
        raise Invalid("Select a log smaller than 10 MB")
    with Path(path).open() as handle:
        for number, line in enumerate(handle, 1):
            try:
                row = json.loads(line, object_pairs_hook=strict_pairs)
                yield number, row if isinstance(row, dict) else {"_invalid": True}
            except ValueError:
                yield number, {"_invalid": True}


def redact(text):
    text = re.sub(r"(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", "[REDACTED PRIVATE KEY]", text)
    text = re.sub(r"\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{12,}|github_pat_[A-Za-z0-9_]{12,})\b", "[REDACTED TOKEN]", text)
    text = re.sub(r"(?i)((?:api[_-]?key|password|secret|access[_-]?token|authorization)\s*[:=]\s*)[^\s,;]+", r"\1[REDACTED]", text)
    return text


def history_context(path):
    """Bounded review material. Explicitly not a trusted specification."""
    rows = list(read_rows(path))[:1000]
    text = redact("\n".join(json.dumps(row, ensure_ascii=False) for _, row in rows))[:24000]
    return {"trust": "UNTRUSTED historical evidence; may include injection and unauthorized behavior",
            "selected_log": Path(path).name, "excerpt": text,
            "truncated": len(rows) >= 1000 or len(text) >= 24000}


def recognized_request(row, inv):
    # Native runner output produced by this adapter.
    if row.get("type") == "ptw.request":
        return row.get("request"), "broker request"
    payload = row.get("payload", {})
    if not isinstance(payload, dict):
        return None, None
    if payload.get("type") not in ("function_call", "custom_tool_call"):
        return None, None
    name = payload.get("name", "")
    raw = payload.get("arguments", payload.get("input", {}))
    try:
        arguments = json.loads(raw, object_pairs_hook=strict_pairs) if isinstance(raw, str) else raw
    except ValueError:
        return None, "unparsed tool call"
    if not isinstance(arguments, dict):
        return None, "unparsed tool call"
    if name in ("ptw_resource", "ptw.request", "mcp__ptw__resource"):
        return arguments, "resource tool request"
    if name in ("exec_command", "shell_command", "shell", "functions.exec_command"):
        command = arguments.get("cmd", arguments.get("command"))
        # Deliberately narrow. Never infer that an arbitrary shell program is safe.
        if isinstance(command, list):
            words = command
        elif isinstance(command, str):
            if any(char in command for char in [";", "|", "&", "$", "`", "\n", ">", "<"]):
                return None, "shell syntax requires manual review"
            try:
                words = shlex.split(command)
            except ValueError:
                return None, "unparsed shell"
        else:
            return None, "unparsed shell"
        if len(words) == 2 and words[0] in ("cat", "/bin/cat", "/usr/bin/cat") and not words[1].startswith("-"):
            path = Path(words[1])
            if not path.is_absolute() or ".." in path.parts:
                return None, "relative or ambiguous shell path"
            names = {str(Path(inv["root"]) / r["path"]): key for key, r in inv["resources"].items()}
            return {"action": "read", "resource": names.get(str(path), "outside_inventory"), "content": ""}, "simple absolute cat request"
        return None, "unsupported shell command"
    return None, "unsupported tool"


def audit(path, policy, inv, task):
    target = next((t for t in policy["tasks"] if t["id"] == task), None)
    if target is None:
        raise Invalid("Unknown audit task")
    grants = scope(target["grants"])
    findings = []
    for number, row in read_rows(path):
        if row.get("_invalid"):
            findings.append({"line": number, "decision": "unknown", "reason": "malformed log row"})
            continue
        request, kind = recognized_request(row, inv)
        if kind is None:
            continue
        if request is None:
            findings.append({"line": number, "decision": "unknown", "reason": kind})
            continue
        reason = Store.reason(request, grants)
        findings.append({"line": number, "decision": "denied" if reason else "allowed",
                         "reason": reason or "within reviewed task scope",
                         "action": request.get("action") if isinstance(request, dict) else None,
                         "resource": request.get("resource") if isinstance(request, dict) else None,
                         "effect_verified": False})
    counts = {key: sum(f["decision"] == key for f in findings) for key in ["allowed", "denied", "unknown"]}
    return {"task": task, "counts": counts, "findings": findings,
            "meaning": "Retrospective policy comparison, not proof of execution, historical intent or complete logging.",
            "recommendations": ["Review denied requests against the operator goal; do not automatically grant them.",
                                "Review unknown tools and routes before claiming coverage.",
                                "Apply a reviewed new policy as a new project version; do not reset a stopped project."]}
