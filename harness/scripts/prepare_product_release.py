#!/usr/bin/env python3
"""Prepare a private installable candidate. This never publishes or certifies it."""
import argparse
import json
from pathlib import Path
import sys

from build_product_release import REPO, build, bootstrap
from product_install import InstallError, release_files, require, safe_path, sha


def prepare(out, repo=REPO):
    out = safe_path(out)
    require(not out.is_relative_to(Path(repo).resolve()), 'Keep release outputs outside the checkout')
    result = build(out, repo=repo)
    try:
        archive = out / result['archive']
        manifest, _ = release_files(archive.read_bytes())
        version = manifest['version']
        tag = 'harness-v' + version
        url = ('https://github.com/BrightlineAI/permission-to-work-not-to-escape/releases/download/' +
               tag + '/' + archive.name)
        require(result['url'] == url, 'Bootstrap tag differs from release tag')
        expected = bootstrap((Path(repo) / 'harness/scripts/product_install.py').read_bytes(), sha(archive.read_bytes()), url)
        require((out / 'install.sh').read_bytes() == expected, 'Bootstrap differs from reviewed source or candidate')
        notes = (Path(repo) / 'harness/RELEASE.md').read_bytes()
        require(tag.encode() in notes and archive.name.encode() in notes,
                'Release guide version differs from candidate')
        (out / 'RELEASE.md').write_bytes(notes)
        names = [archive.name, 'install.sh', 'RELEASE.md']
        (out / 'SHA256SUMS').write_text(''.join(sha((out / name).read_bytes()) + '  ' + name + '\n' for name in names))
        value = {'tag': tag, 'status': 'private-candidate-unvalidated',
                 'assets': [{'path': str(out / name), 'sha256': sha((out / name).read_bytes())}
                            for name in [*names, 'SHA256SUMS']],
                 'source_sha256': manifest['source_sha256'],
                 'pending': ['native installed candidate and demos', 'full final-source product acceptance',
                             'independent original-evidence and credential review', 'published installation and CI']}
        (out / 'release.json').write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
        return value
    except BaseException as exc:
        (out / 'prepare-failed.json').write_text(json.dumps({'status': 'failed', 'error_type': type(exc).__name__}) + '\n')
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.out), sort_keys=True))
    except (InstallError, OSError, ValueError) as exc:
        print('Release preparation failed: ' + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
