"""Explicit operator tooling for the pinned Poetry API, never project plugins."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

from .policy import Invalid, load, save
from .python_runtime import identify


PINS = 'poetry==2.2.1\npoetry-plugin-export==1.9.0\n'
CUTOFF = '2026-09-16T00:00:00Z'


def payload(root):
    result = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise Invalid('Poetry tool payload contains a link or special file')
        if path.is_file():
            result[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    if not result:
        raise Invalid('Poetry tool payload is empty')
    return result


def provision(directory, *, executable='/usr/bin/python3', lock=None):
    """Fresh operator directory; retain failures and an exact hashed rebuild lock.

    Bootstrap resolution is explicit. Once reviewed, pass the retained lock on
    subsequent provisions. No credentials, ambient uv config or source builds.
    """
    from .dependency_resolution import resolver_environment, ResolutionError
    directory = Path(directory).absolute()
    directory.mkdir(parents=True, exist_ok=False)
    runtime = identify(executable)
    uv = shutil.which('uv')
    if not uv:
        raise Invalid('uv is required to provision the isolated Poetry tool')
    env = resolver_environment(directory)
    base = [uv, '--no-config', '--no-python-downloads', '--cache-dir', str(directory / 'cache')]
    receipt = {'outcome': 'running', 'runtime': runtime, 'pins': PINS,
               'uv_sha256': hashlib.sha256(Path(uv).resolve().read_bytes()).hexdigest()}
    try:
        (directory / 'tools.in').write_text(PINS)
        lock_path = directory / 'tools.lock'
        commands = []
        if lock is None:
            commands.append(base + ['pip', 'compile', '--index-url', 'https://pypi.org/simple',
                '--python', runtime['executable'], '--only-binary', ':all:', '--generate-hashes',
                '--exclude-newer', CUTOFF, '--no-header', '--no-annotate',
                str(directory / 'tools.in'), '-o', str(lock_path)])
        else:
            lock_path.write_bytes(Path(lock).read_bytes())
        commands.append(base + ['pip', 'install', '--python', runtime['executable'],
            '--target', str(directory / 'payload'), '--index-url', 'https://pypi.org/simple',
            '--only-binary', ':all:', '--require-hashes', '--no-deps', '--compile-bytecode',
            '-r', str(lock_path)])
        for command in commands:
            proc = subprocess.run(command, env=env, capture_output=True, timeout=180)
            if proc.returncode:
                receipt['diagnostic_sha256'] = hashlib.sha256(proc.stderr).hexdigest()
                raise ResolutionError('unavailable', 'Poetry tool provisioning failed; see private receipt')
        # Hash precompiled bytecode too. Repeated offline -B processes can read
        # it without recompiling the pinned tools or writing to their payload.
        receipt.update(files=payload(directory / 'payload'),
                       lock_sha256=hashlib.sha256(lock_path.read_bytes()).hexdigest())
        # Version checks use -S and an explicit path, so .pth/startup hooks never run.
        check = subprocess.run([runtime['executable'], '-I', '-S', '-B', '-c',
            'import sys; sys.path.insert(0,sys.argv[1]); from importlib.metadata import version; '
            'assert version("poetry")=="2.2.1"; assert version("poetry-plugin-export")=="1.9.0"',
            str(directory / 'payload')], env=env, capture_output=True, timeout=15)
        if check.returncode:
            raise Invalid('Poetry tool versions differ from the pinned API')
        receipt['outcome'] = 'ready'
        return directory
    except BaseException:
        receipt['outcome'] = 'failed'
        raise
    finally:
        # save intentionally refuses overwrites. Publish exactly one terminal
        # receipt, including failures, after all readiness checks finish.
        save(directory / 'tool.json', receipt)


def verified(directory=None):
    directory = directory or os.environ.get('PTW_POETRY_TOOL')
    if not directory:
        raise Invalid('Provision Poetry explicitly and set PTW_POETRY_TOOL; no ambient fallback')
    directory = Path(directory).resolve(strict=True)
    receipt = load(directory / 'tool.json')
    if (receipt.get('outcome') != 'ready' or receipt.get('pins') != PINS or
            receipt.get('files') != payload(directory / 'payload') or
            receipt.get('lock_sha256') != hashlib.sha256((directory / 'tools.lock').read_bytes()).hexdigest()):
        raise Invalid('Poetry tool payload or lock changed; provision a new tool directory')
    runtime = receipt['runtime']
    # identify records the tool interpreter independently of the project runtime.
    if identify(runtime['executable']) != runtime:
        raise Invalid('Poetry tool interpreter changed')
    return directory, receipt


def run(script, config, *, cwd, timeout, directory=None):
    """Offline native metadata operation. Only copied inputs and tools are visible."""
    from .dependency_resolution import resolver_environment
    from .supervisor import runtime_namespace
    directory, receipt = verified(directory)
    stage = Path(cwd).resolve()
    command = runtime_namespace() + ['--ro-bind', str(directory / 'payload'), '/poetry-tools',
        '--bind', str(stage), '/resolution', '--chdir', '/resolution']
    for key, value in resolver_environment(stage).items():
        command += ['--setenv', key, value.replace(str(stage), '/resolution')]
    command += ['--', receipt['runtime']['executable'], '-I', '-S', '-B', '-c',
        'import sys; sys.path.insert(0,"/poetry-tools");\n' + script, json.dumps(config)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                            env={'PATH': '/usr/bin:/bin'})
    if verified(directory)[1] != receipt:
        raise Invalid('Poetry tooling changed during native execution')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory')
    parser.add_argument('--python', default='/usr/bin/python3')
    parser.add_argument('--lock', help='Previously reviewed tools.lock for exact reconstruction')
    args = parser.parse_args()
    print(provision(args.directory, executable=args.python, lock=args.lock))


if __name__ == '__main__':
    main()
