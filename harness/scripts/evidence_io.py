"""Private acceptance receipts. Never publish these logs without separate review."""
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import time


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + '.pending')
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')
    temporary.replace(path)


def reference(root, path):
    return {'path': str(Path(path).relative_to(root)), 'sha256': digest(path)}


def artifact(root, ref):
    require(isinstance(ref, dict) and isinstance(ref.get('path'), str), 'Missing artifact reference')
    root = Path(root).absolute()
    relative = Path(ref['path'])
    require(not relative.is_absolute() and relative.parts and
            '..' not in relative.parts, 'Unsafe artifact path')
    path = root / relative
    require(all(not p.is_symlink() for p in [path, *path.parents] if p != root.parent),
            'Linked artifact path')
    require(path.is_file() and path.resolve().is_relative_to(root.resolve()), 'Missing or escaping artifact')
    require(digest(path) == ref.get('sha256'), 'Artifact hash mismatch: ' + str(relative))
    return path


def load(path):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate JSON key: ' + key)
            result[key] = value
        return result

    def constant(value):
        raise ValueError('Nonfinite JSON number: ' + value)

    return json.loads(Path(path).read_text(), object_pairs_hook=pairs, parse_constant=constant)


def record(root, ref):
    value = load(artifact(root, ref))
    require(isinstance(value, dict), 'Record must be an object')
    return value


def seconds(value, label):
    require(type(value) in (int, float) and math.isfinite(value) and value >= 0,
            'Invalid time: ' + label)
    return value


def fresh(value, *, now=None):
    now = time.time() if now is None else now
    require(0 <= now - seconds(value, 'epoch') < 86400, 'Stale or future evidence')


def capture(argv, folder, *, env=None, cwd=None, timeout=120, on_spawn=None, pass_fds=()):
    """Stream original bytes to disk, including incomplete and failed attempts.

    Return a CompletedProcess even on nonzero exit. Assertions belong to callers,
    after the receipt is saved. A timeout kills only this new process group.
    """
    folder = Path(folder)
    folder.mkdir(mode=0o700, parents=True, exist_ok=False)
    argv = [str(arg) for arg in argv]
    started = time.monotonic()
    receipt = {'argv': argv, 'cwd': str(Path(cwd or Path.cwd()).absolute()),
               'started_epoch': time.time(), 'start_monotonic': started,
               'complete': False, 'exit_code': None}
    save(folder / 'process.json', receipt)
    process = None
    try:
        with (folder / 'stdout').open('xb') as stdout, (folder / 'stderr').open('xb') as stderr:
            process = subprocess.Popen(argv, env=env, cwd=cwd, stdout=stdout, stderr=stderr,
                                       start_new_session=True, pass_fds=pass_fds)
            if on_spawn is not None:
                on_spawn(process.pid)
            process.wait(timeout=timeout)
        receipt['complete'] = True
        return subprocess.CompletedProcess(argv, process.returncode,
            (folder / 'stdout').read_bytes(), (folder / 'stderr').read_bytes())
    except BaseException as exc:
        receipt['error_type'] = type(exc).__name__
        raise
    finally:
        if process is not None:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
            receipt['exit_code'] = process.returncode
        receipt.update(ended_epoch=time.time(), seconds=time.monotonic() - started)
        for name in ('stdout', 'stderr'):
            if (folder / name).is_file():
                receipt[name] = reference(folder, folder / name)
        save(folder / 'process.json', receipt)
