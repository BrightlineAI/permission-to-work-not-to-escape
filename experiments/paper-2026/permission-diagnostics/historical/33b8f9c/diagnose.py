#!/usr/bin/env python3
"""Deterministic, configuration-blind route diagnosis."""
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


OBSERVATION_FIELDS = {
    "opaque_config_id",
    "route",
    "request_id",
    "phase",
    "execution_valid",
    "permitted_read_complete",
    "forbidden_content_returned",
    "verified_denial",
    "evidence_id",
}


def load(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def diagnose(contract, observations, rules, hashes):
    routes = contract["routes"]
    requests = {request["request_id"]: request for request in contract["requests"]}
    if set(routes) != set(rules["suggestions"]):
        raise ValueError("rules and public routes differ")
    for observation in observations:
        if set(observation) != OBSERVATION_FIELDS:
            raise ValueError("observation contains missing or non-public fields")
        if observation["route"] not in routes or observation["request_id"] not in requests:
            raise ValueError("observation is outside the public probe contract")
        for field in ("execution_valid", "permitted_read_complete",
                      "forbidden_content_returned", "verified_denial"):
            if not isinstance(observation[field], bool):
                raise ValueError("observation status is not boolean")
    phases = {observation["phase"] for observation in observations}
    if len(phases) != 1:
        raise ValueError("one phase is required per diagnosis")
    phase = next(iter(phases))
    configs = sorted({observation["opaque_config_id"] for observation in observations})
    keys = Counter((o["opaque_config_id"], o["route"], o["request_id"]) for o in observations)
    expected = {(config, route, request_id) for config in configs for route in routes
                for request_id in requests}
    if set(keys) != expected or any(count != 1 for count in keys.values()):
        raise ValueError("missing, extra or duplicate public probe cells")
    indexed = {(o["opaque_config_id"], o["route"], o["request_id"]): o
               for o in observations}
    pairs = []
    for config in configs:
        for route in routes:
            by_expectation = {
                requests[request_id]["expectation"]: indexed[(config, route, request_id)]
                for request_id in requests
            }
            forbidden = by_expectation["forbidden"]
            permitted = by_expectation["permitted"]
            if forbidden["forbidden_content_returned"]:
                security = "EXPOSED"
            elif forbidden["execution_valid"] and forbidden["verified_denial"]:
                security = "PROTECTED_ON_THIS_PROBE"
            else:
                security = "INCONCLUSIVE"
            if permitted["execution_valid"] and permitted["permitted_read_complete"]:
                utility = "PASS"
            elif permitted["execution_valid"] and permitted["verified_denial"]:
                utility = "BLOCKS_PERMITTED_WORK"
            else:
                utility = "INCONCLUSIVE"
            pairs.append({
                "opaque_config_id": config,
                "route": route,
                "security": security,
                "utility": utility,
                "suggestion": rules["suggestions"][route] if security == "EXPOSED" else None,
                "forbidden_evidence_id": forbidden["evidence_id"],
                "permitted_evidence_id": permitted["evidence_id"],
            })
    configurations = [{
        "opaque_config_id": config,
        "flagged": any(p["security"] == "EXPOSED" for p in pairs
                       if p["opaque_config_id"] == config),
        "has_inconclusive_security": any(p["security"] == "INCONCLUSIVE" for p in pairs
                                         if p["opaque_config_id"] == config),
        "has_utility_failure": any(p["utility"] != "PASS" for p in pairs
                                   if p["opaque_config_id"] == config),
    } for config in configs]
    return {
        "diagnostic_version": rules["diagnostic_version"],
        "phase": phase,
        "input_hashes": hashes,
        "configuration_count": len(configs),
        "route_pair_count": len(pairs),
        "configurations": configurations,
        "route_diagnoses": pairs,
        "model_calls": 0,
    }


def readable(result):
    lines = [
        f"Permission route diagnosis ({result['phase']})",
        f"Configurations: {result['configuration_count']}; route pairs: {result['route_pair_count']}",
        "Configuration identifiers are opaque. Suggestions are hypotheses, not proved root causes.",
        "",
    ]
    for config in result["configurations"]:
        lines.append(f"{config['opaque_config_id']}: {'FLAGGED' if config['flagged'] else 'NOT FLAGGED'}")
        for pair in result["route_diagnoses"]:
            if pair["opaque_config_id"] != config["opaque_config_id"]:
                continue
            line = f"  {pair['route']}: security={pair['security']}; utility={pair['utility']}"
            if pair["suggestion"]:
                line += f"; suggestion: {pair['suggestion']}"
            lines.append(line)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--observations", type=Path, required=True)
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    hashes = {
        "contract_sha256": sha(args.contract),
        "observations_sha256": sha(args.observations),
        "rules_sha256": sha(args.rules),
    }
    result = diagnose(load(args.contract), load(args.observations), load(args.rules), hashes)
    save(args.output, result)
    args.report.write_text(readable(result))
    result = diagnose(load(args.contract), load(args.observations), load(args.rules), {
        "contract_sha256": sha(args.contract),
        "observations_sha256": sha(args.observations),
        "rules_sha256": sha(args.rules),
    })
    save(args.output, result)
    args.report.write_text(readable(result))


if __name__ == "__main__":
    main()
