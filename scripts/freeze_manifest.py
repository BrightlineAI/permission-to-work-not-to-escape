#!/usr/bin/env python3
"""Inventory a reviewed release. Never use this to hide a failed integrity check."""
from pathlib import Path
import hashlib
import sys

ROOT=Path(__file__).resolve().parents[1]
SKIP={'.git','__pycache__','.venv','.pytest_cache','build','dist','.runtime-tools'}


def inventory(base):
    lines=[]
    for p in sorted(base.rglob('*')):
        rel=p.relative_to(base)
        if not p.is_file() or p.name=='MANIFEST.sha256' or set(rel.parts)&SKIP:continue
        if any(x.endswith('.egg-info') for x in rel.parts) or p.suffix=='.pyc':continue
        if len(rel.parts)>=2 and rel.parts[:2]==('validation','local'):continue
        lines.append(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+str(rel))
    (base/'MANIFEST.sha256').write_text('\n'.join(lines)+'\n')
    return len(lines)


if __name__=='__main__':
    if sys.argv[1:]!=['--reviewed-release']:
        raise SystemExit('Usage: python3 scripts/freeze_manifest.py --reviewed-release\nReview changes and retain original evidence before renewing a release inventory.')
    for p in (ROOT/'experiments/paper-2026').iterdir():
        if p.is_dir():inventory(p)
    print(f'Inventoried {inventory(ROOT)} release files.')
