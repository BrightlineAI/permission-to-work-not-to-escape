#!/usr/bin/env python3
"""Create a curated, fresh publication copy. No GitHub or benchmark actions."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
RESEARCH = {
    'index-final.md', '2026-09-13-fg-novelty-review.md',
    '2026-09-13-incident-coverage.csv', '2026-09-13-lab-incident-coverage.md',
    '2026-09-13-vendor-incident-coverage.md', 'advisory-snapshots.json',
    'GHSA-9wx4-h78v-vm56.json', 'MAL-2025-41439.json',
}
SKIP = {'.git', '__pycache__', '.venv', '.pytest_cache', 'build', 'dist', '.runtime-tools'}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def exclusion(path):
    parts = path.parts
    if set(parts) & SKIP or path.suffix == '.pyc' or path.name == '.DS_Store':
        return 'local tooling/cache, not publication evidence'
    if any(x.endswith('.egg-info') for x in parts) or parts[:2] == ('validation', 'local'):
        return 'local tooling/cache, not publication evidence'
    if parts[:2] == ('experiments', 'exploratory'):
        return 'earlier pilots outside the final paper experiments'
    if parts[0] == 'paper':
        if len(parts) == 2 and path.name in {'README.md', 'submission.pdf', 'publication-consistency.md'}:
            return None
        if len(parts) == 3 and parts[1] == 'research' and path.name in RESEARCH:
            return None
        return 'superseded manuscript, authoring material or unrelated pilot research'
    if path.as_posix() in {'provenance/paper-link-adaptations.json', 'provenance/export-scope.md',
                           'provenance/publication.json', 'provenance/publication-exclusions.json'}:
        return 'superseded publication metadata; regenerated for this export'
    return None


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path, help='New directory outside this package')
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or output == ROOT or ROOT in output.parents:
        parser.error('Output must not exist and must be outside the source package.')
    source = json.loads((ROOT/'provenance/source-files.json').read_text())
    # Never turn a source-integrity failure into a new clean manifest.
    for entry in source['files']:
        if sha(ROOT/entry['path']) != entry['sha256']:
            raise ValueError('Original evidence/source changed: ' + entry['path'])
    output.mkdir(parents=True)
    omitted = []
    for path in sorted(ROOT.rglob('*')):
        if path.is_symlink():
            raise ValueError('Review symlink before publication: ' + str(path.relative_to(ROOT)))
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        reason = exclusion(rel)
        if reason:
            if not (set(rel.parts) & SKIP) and path.suffix != '.pyc':
                omitted.append(dict(path=rel.as_posix(), sha256=sha(path), reason=reason))
            continue
        target = output/rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
    # Repair only the two navigation links to an excluded manuscript. Preserve
    # the source note in the author's archive and record the transformed hash.
    adaptations = []
    note = output/'paper/research/2026-09-13-fg-novelty-review.md'
    old = note.read_text()
    revised = old.replace('[submission Appendix J](../research-draft.md#appendix-j-prior-art-and-what-vega-adds)',
                          '[paper and evidence map](../README.md)')
    revised = revised.replace('[Submission](../research-draft.md)', '[Paper and evidence map](../README.md)')
    if revised != old:
        before = sha(note)
        note.write_text(revised)
        adaptations.append(dict(path=str(note.relative_to(output)), source_sha256=before,
                                published_sha256=sha(note), reason='Two links to the excluded draft now point to the final paper map.'))
    source['files'] = [entry for entry in source['files'] if (output/entry['path']).is_file()]
    for change in adaptations:
        entry = next(x for x in source['files'] if x['path'] == change['path'])
        entry['publication_source_sha256'] = entry['sha256']
        entry['sha256'] = change['published_sha256']
    write_json(output/'provenance/source-files.json', source)
    write_json(output/'provenance/publication-exclusions.json', omitted)
    commit = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
    publication = dict(
        repository='https://github.com/BrightlineAI/permission-to-work-not-to-escape',
        source_checkout_commit=commit,
        source_files='source-files.json',
        exclusions='publication-exclusions.json',
        source_working_tree='Maintained release files are inventoried by MANIFEST.sha256; the anchor commit alone is not their full identity.',
        paper=dict(path='paper/submission.pdf', sha256=sha(output/'paper/submission.pdf'),
                   source_filename='Permission to Work Not to Escape_ Policies, Controls and Escalating Enforcement Across AI Agents.pdf', pages=23),
        experiment_directories=sorted(p.name for p in (output/'experiments/paper-2026').iterdir() if p.is_dir()),
        preserved_source_files=len(source['files']), excluded_files=len(omitted),
        benchmark_runs_performed_by_export=0,
        navigation_adaptations=adaptations,
    )
    write_json(output/'provenance/publication.json', publication)
    subprocess.run([sys.executable, str(output/'scripts/freeze_manifest.py'), '--reviewed-release'], check=True)
    print(json.dumps(dict(output=str(output), **publication), indent=2))


if __name__ == '__main__':
    main()
