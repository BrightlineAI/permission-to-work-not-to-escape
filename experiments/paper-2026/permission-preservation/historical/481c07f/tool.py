"""Executing file tool. The checker lives here, not in the replay driver."""
import json
import os
import sys
from pathlib import Path

from scope import permissions
from vega_core.models import policy_from_dict, normalize_tool_call
from vega_core.authorize import authorize_c

raw = json.loads(Path(sys.argv[1]).read_text())
permissions(raw)
policy = policy_from_dict(raw)
action, resource, payload = sys.argv[2:5]
request = normalize_tool_call(dict(tool="file_access", action=action, resource=resource,
    recipient=None, destination=None, amount=None, payload=payload, approval_handle=None))
decision = authorize_c(policy, request)
record = dict(event="tool_result", pid=os.getpid(), uid=os.getuid(),
              principal=policy.principal, job_id=policy.job_id, policy_hash=policy.policy_hash,
              decision=decision.as_dict(), effect=None)
if decision.allowed:
    try:
        if action == "read":
            record["effect"] = dict(content=Path(resource).read_text())
        elif action == "write":
            Path(resource).write_text(payload)
            record["effect"] = dict(written=True)
    except PermissionError as exc:
        record["effect"] = dict(os_denied=True, error=str(exc))
print(json.dumps(record, sort_keys=True))
