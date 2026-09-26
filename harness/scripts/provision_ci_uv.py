"""Provision the installer's pinned uv/nono for hosted CI before discovery."""
import argparse
import os
from pathlib import Path
import re

from product_install import PINS, archive_files, clean_env, download, require, run, safe_path


def provision(out, tool='uv'):
    require(tool in ('uv', 'nono'), 'Unsupported CI tool')
    out = safe_path(out)
    out.mkdir()  # A failed or previous attempt must not be reused.
    version, url, digest = PINS[tool]
    files = archive_files(download(url, digest), directories=True)
    matches = [name for name in files if Path(name).name == tool]
    require(len(matches) == 1, 'Expected exactly one ' + tool + ' executable')
    binary = out / tool
    binary.write_bytes(files[matches[0]])
    binary.chmod(0o755)
    observed = run([binary, '--version'], env=clean_env(out))
    require(re.fullmatch(re.escape(tool) + ' ' + re.escape(version) + r'(?: \([^\r\n]*\))?', observed),
            'Unexpected CI ' + tool + ' version')
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--tool', choices=('uv', 'nono'), default='uv')
    args = parser.parse_args()
    github_path = Path(os.environ['GITHUB_PATH'])
    directory = provision(args.out, args.tool)
    require(not any(c in str(directory) for c in '\r\n'), 'Invalid CI PATH directory')
    # GitHub prepends this directory to PATH for subsequent steps only.
    with github_path.open('a', encoding='utf-8') as stream:
        stream.write(str(directory) + '\n')


if __name__ == '__main__':
    main()
