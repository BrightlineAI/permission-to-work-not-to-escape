"""Local provenance of the trusted process, without configuration or credentials."""
import hashlib
import os
from pathlib import Path
import sys
import time


def snapshot(role):
    root = Path(__file__).resolve().parent.parent
    return {'role': role, 'pid': os.getpid(), 'measured_epoch': time.time(),
            'executable': sys.executable, 'prefix': sys.prefix, 'module_root': str(root),
            'interpreter_sha256': hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
            'pythonpath_present': 'PYTHONPATH' in os.environ,
            'pythonhome_present': 'PYTHONHOME' in os.environ,
            'imported_ptw_modules': {name: str(Path(module.__file__).resolve())
                for name, module in tuple(sys.modules.items())
                if (name == 'ptw' or name.startswith('ptw.')) and getattr(module, '__file__', None)},
            'runtime_sha256': {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted((root / 'ptw').rglob('*')) if p.is_file() and
                '__pycache__' not in p.parts and p.suffix not in ('.pyc', '.pyo')}}
