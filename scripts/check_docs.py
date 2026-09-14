#!/usr/bin/env python3
"""Check maintained Markdown links, excluding immutable historical write-ups."""
from pathlib import Path
import re
import sys
from urllib.parse import unquote

ROOT=Path(__file__).resolve().parents[1]


def main():
    documents=list(ROOT.glob('*.md'))+list((ROOT/'docs').glob('*.md'))
    documents+=[ROOT/'validation/README.md',ROOT/'schemas/README.md']
    documents+=list((ROOT/'examples').rglob('*.md'))+list((ROOT/'adapters').rglob('*.md'))
    documents+=list((ROOT/'paper').glob('publication*.md'))
    for name in ['index-final.md','2026-09-13-fg-novelty-review.md','2026-09-13-lab-incident-coverage.md','2026-09-13-vendor-incident-coverage.md']:
        documents.append(ROOT/'paper/research'/name)
    documents+=[ROOT/'paper/README.md',ROOT/'experiments/paper-2026/README.md']
    documents+=list((ROOT/'experiments/paper-2026').glob('*/README.md'))
    errors=[];links=0
    for doc in documents:
        for raw in re.findall(r'\]\(([^)]+)\)',doc.read_text()):
            target=raw.strip('<>');path=target.split('#',1)[0]
            if not path or re.match(r'[a-zA-Z][a-zA-Z0-9+.-]*:',path):continue
            links+=1
            if not (doc.parent/unquote(path)).exists():
                errors.append(f'{doc.relative_to(ROOT)}: missing {path}')
    if errors:print('\n'.join(errors),file=sys.stderr);return 1
    print(f'Checked {len(documents)} maintained documents and {links} local links; no missing targets.')
    return 0


if __name__=='__main__':raise SystemExit(main())
