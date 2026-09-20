"""Identity of the complete installed demo and runtime, including package data."""
from email.parser import Parser
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import sys

from evidence_io import digest, require, verify_wheel_identity

def tree(root):
    root = Path(root)
    require(root.is_dir() and not root.is_symlink(), 'Missing or linked runtime root')
    files = sorted(p for p in (root / 'ptw').rglob('*')
                   if '__pycache__' not in p.parts and p.suffix not in ('.pyc', '.pyo'))
    require(files and all(not p.is_symlink() and p.resolve().is_relative_to(root.resolve())
                          for p in files), 'Missing or linked runtime content')
    return {str(p.relative_to(root)): digest(p) for p in files if p.is_file()}


def normalized(name):
    return re.sub(r'[-_.]+', '-', name).lower()


def versions(root):
    result = {}
    for path in Path(root).glob('*.dist-info/METADATA'):
        require(not path.is_symlink() and not path.parent.is_symlink() and
                path.stat().st_size < 4 * 1024 * 1024, 'Invalid distribution metadata')
        metadata = Parser().parsestr(path.read_text(), headersonly=True)
        require(metadata.get('Name') and metadata.get('Version'), 'Missing distribution identity')
        name = normalized(metadata['Name'])
        require(name not in result, 'Duplicate installed distribution')
        result[name] = metadata['Version']
    require(result, 'Missing installed distributions')
    return result


def identity():
    import ptw
    root = Path(ptw.__file__).resolve().parent
    distribution = importlib.metadata.distribution('permission-to-work-harness')
    return {'path': str(root), 'prefix': sys.prefix,
            'pythonpath_present': 'PYTHONPATH' in os.environ,
            'pythonhome_present': 'PYTHONHOME' in os.environ,
            'direct_url': json.loads(distribution.read_text('direct_url.json') or '{}'),
            'hashes': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.glob('*.py')},
            'runtime_sha256': tree(root.parent), 'dependency_versions': versions(root.parent)}


def verify_identity(value, installation, hashes, runtime):
    verify_wheel_identity(value, installation, hashes)
    if value['pythonhome_present'] or value['runtime_sha256'] != runtime:
        raise AssertionError('Installed recursive runtime/package data differ or PYTHONHOME is set')
    if tree(Path(value['path']).parent) != runtime:
        raise AssertionError('Retained installed bytes differ from measured identity')


def source_identity():
    runtime = Path(__file__).resolve().parents[1]
    hashes = tree(runtime.parent)
    data = runtime / 'release_data'
    inputs = {name: digest(data / name) for name in ('pyproject.toml', 'requirements.lock')}
    # The final acceptance report separately binds all maintained source/tests.
    # This portable identity binds precisely the installed demo implementation.
    return {'maintained_sha256': hashes, 'runtime_sha256': hashes,
            'distribution_inputs_sha256': inputs}


def source_root():
    runtime = Path(__file__).resolve().parents[1]
    if runtime.parent.name == 'harness':
        return runtime.parent.parent
    return runtime


def verify_record(value, source):
    hashes = {Path(n).name: v for n, v in source['runtime_sha256'].items()
              if len(Path(n).parts) == 2 and n.endswith('.py')}
    require(not Path(value['path']).resolve().is_relative_to(source_root()) or
            source_root().name == 'ptw', 'Use the installed wheel, not source imports')
    verify_identity(value, Path(value['prefix']), hashes, source['runtime_sha256'])
    require(versions(Path(value['path']).parent) == value['dependency_versions'], 'Installed metadata changed')
