"""Narrow file-grant adapter; reuse the existing Vega policy parser/authorizer."""
import copy
import sys
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).parent / "vendor"))
from vega_core.models import policy_from_dict


def permissions(raw):
    policy = policy_from_dict(raw)
    result = set()
    for grant in policy.allow:
        if grant.tool != "file_access" or grant.recipients or grant.destinations:
            raise ValueError("only explicit local file_access grants supported")
        if not grant.resources or not grant.actions or set(grant.actions) - {"read", "write"}:
            raise ValueError("explicit read/write file grants required")
        for resource in grant.resources:
            path = PurePosixPath(resource)
            if (not resource.startswith("/fixtures/") or ".." in path.parts
                    or str(path) != resource or any(c in resource for c in "*?[]")):
                raise ValueError("only canonical exact fixture paths supported")
            for action in grant.actions:
                result.add((action, resource))
    return result


def inherited(parent, worker_default, worker_principal):
    effective = permissions(parent) & permissions(worker_default)
    if not effective:
        raise ValueError("empty inherited scope; do not launch worker")
    result = copy.deepcopy(worker_default)
    result.update(job_id=parent["job_id"], principal=worker_principal,
                  policy_id=parent["policy_id"] + "-worker")
    result["allow"] = [dict(tool="file_access", actions=[action], resources=[resource],
                            recipients=[], destinations=[]) for action, resource in sorted(effective)]
    result["delegation"] = dict(max_depth=1, child_may_expand_authority=False)
    policy_from_dict(result)
    return result


def nono_grants(raw):
    flags = ["--read", "/app"]
    for action, path in sorted(permissions(raw)):
        flags += ["--read-file" if action == "read" else "--write-file", path]
    return flags
