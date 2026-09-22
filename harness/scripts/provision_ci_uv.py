"""Provision the installer's pinned uv for Linux hosted CI, before test discovery."""
import argparse
import os
from pathlib import Path
import re

from product_install import PINS, archive_files, clean_env, download, require, run, safe_path


def provision(out):
    out = safe_path(out)
    out.mkdir()  # A failed or previous attempt must not be reused.
    version, url, digest = PINS['uv']
    files = archive_files(download(url, digest), directories=True)
    matches = [name for name in files if Path(name).name == 'uv']
    require(len(matches) == 1, 'Expected exactly one uv executable')
    binary = out / 'uv'
    binary.write_bytes(files[matches[0]])
    binary.chmod(0o755)
    observed = run([binary, '--version'], env=clean_env(out))
    require(re.fullmatch(r'uv ' + re.escape(version) + r'(?: \([^\r\n]*\))?', observed),
            'Unexpected CI uv version')
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    github_path = Path(os.environ['GITHUB_PATH'])
    directory = provision(args.out)
    require(not any(c in str(directory) for c in '\r\n'), 'Invalid CI PATH directory')
    # GitHub prepends this directory to PATH for subsequent steps only.
    with github_path.open('a', encoding='utf-8') as stream:
        stream.write(str(directory) + '\n')


if __name__ == '__main__':
    main()
