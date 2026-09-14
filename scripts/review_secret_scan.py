#!/usr/bin/env python3
"""Classify reviewed fixture/hash findings without printing secret values.

Input: an unredacted gitleaks JSON report kept OUTSIDE the publication tree.
This is a release review helper, not a general secret detector or allowlist.
Unrecognized findings fail the check and require manual review.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
from functools import lru_cache


@lru_cache(maxsize=1)
def fixture_canaries(root):
    values = set()
    for path in (root/'experiments/paper-2026/vega-core/cases').glob('case-*.json'):
        case = json.loads(path.read_text())
        values.update(x['value'] for x in case.get('trusted', {}).get('canaries', []))
    return values


def classify(item, root):
    path = Path(item['File']).resolve()
    name = str(path.relative_to(root))
    secret = item['Secret']; match = item['Match']; rule = item['RuleID']
    if rule == 'aws-access-token' and '/dtap-vega/evidence/' in name and 'EXAMPLE' in secret:
        return 'DTAP synthetic AWS EXAMPLE fixture identifiers'
    if rule != 'generic-api-key':
        return None
    if match.startswith('KEY=') and re.fullmatch('[0-9A-F]{40}', secret):
        line = path.read_text().splitlines()[item['StartLine']-1]
        if 'GPG_KEY=' + secret in line:
            return 'Container image public GPG key fingerprint'
    if re.match(r'authorize(?:_[cd])?\.py"', match) and re.fullmatch('[0-9a-f]{64}', secret):
        return 'Recorded source file SHA-256 digest'
    if match.startswith('token'):
        if ('/escalation-preservation/' in name or '/escalation-01/' in name) and re.fullmatch('EP_EFFECT_[0-9a-f]+', secret):
            return 'Scripted effect marker, not an authentication token'
        if '/native-stop/evidence/' in name and re.fullmatch('[0-9a-f]{31,40}', secret):
            return 'Native heartbeat correlation marker, not an authentication token'
        if '/vega-core/evidence/' in name and secret.rstrip('.') in fixture_canaries(root):
            return 'Synthetic core canary matched to its case fixture'
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args(); root = args.root.resolve()
    if root in args.report.resolve().parents:
        parser.error('Keep the unredacted scanner report outside the publication tree.')
    counts = Counter(); unresolved = []
    for item in json.loads(args.report.read_text()):
        kind = classify(item, root)
        if kind:
            counts[kind] += 1
        else:
            unresolved.append(dict(path=str(Path(item['File']).resolve().relative_to(root)),
                                   line=item['StartLine'], rule=item['RuleID']))
    print(json.dumps(dict(passed=not unresolved, classifications=dict(counts),
                          reviewed_findings=sum(counts.values()), unresolved=unresolved,
                          limitation='Classification of this scanner report, not proof that no secrets exist.'), indent=2))
    return bool(unresolved)


if __name__ == '__main__':
    raise SystemExit(main())
