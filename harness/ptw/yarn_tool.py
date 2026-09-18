"""Pinned Yarn Classic bootstrap and frozen, offline native boundary.

This internal primitive accepts disposable stages, not live projects. It does
not authorize packages or builds. Controller integration must assess the lock,
bind artifacts, and verify the installed graph before publishing any result.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid

from .dependency_resolution import ResolutionError, resolver_environment, resolver_failure_signals
from .npm import NpmEvidence
from .pnpm_tool import integrity, node_identity, unpack
from .policy import Invalid, load, parse_json, save


VERSION = '1.22.22'
URL = 'https://registry.npmjs.org/yarn/-/yarn-' + VERSION + '.tgz'
ENTRY = 'bin/yarn.js'
PARSER_VERSION = '1.1.0'
PARSER_URL = 'https://registry.npmjs.org/@yarnpkg/lockfile/-/lockfile-' + PARSER_VERSION + '.tgz'

# Yarn Classic's pinned, upstream experimentalYarnHooks extension point. Only
# preparation uses this hook: Yarn still resolves ranges and writes its lock.
# Installation never loads it and must fetch/link independently assessed bytes.
RESOLUTION_HOOK = '''
'use strict';
const skipped = new Set();
global.experimentalYarnHooks = Object.fromEntries(
  ['fetchStep', 'linkStep', 'buildStep'].map(name => [name, async () => { skipped.add(name); }])
);
process.on('exit', code => {
  if (code === 0 && skipped.size !== 3) process.exitCode = 2;
});
'''


def payload(root):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise Invalid('Yarn tool payload must be an ordinary directory')
    result = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise Invalid('Yarn tool payload contains a link or special file')
        if path.is_file():
            result[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    if not {ENTRY, 'lib/cli.js', 'package.json'} <= result.keys():
        raise Invalid('Incomplete Yarn tool payload')
    manifest = load(root / 'package.json')
    if manifest.get('name') != 'yarn' or manifest.get('version') != VERSION:
        raise Invalid('Yarn tool version differs from the pinned API')
    return result


def provision(directory, *, lock=None):
    """Explicit TLS bootstrap; a saved SRI lock supports exact reconstruction.

    No global install, shim, lifecycle, ambient credentials or proxy is used.
    Failed attempts remain in the new operator directory with a receipt.
    """
    directory = Path(directory).absolute()
    directory.mkdir(parents=True, exist_ok=False)
    receipt = {'outcome': 'failed', 'version': VERSION}
    try:
        provider = NpmEvidence()
        if lock is None:
            metadata = parse_json(provider.fetch('https://registry.npmjs.org/yarn/' + VERSION))
            if metadata.get('name') != 'yarn' or metadata.get('version') != VERSION:
                raise Invalid('Yarn bootstrap metadata identity mismatch')
            selected = {'version': VERSION, 'url': metadata['dist']['tarball'],
                        'integrity': metadata['dist']['integrity']}
        else:
            selected = load(lock)
        if (not isinstance(selected, dict) or set(selected) - {'version', 'url', 'integrity', 'parser'} or
                selected['version'] != VERSION or selected['url'] != URL or
                not isinstance(selected['integrity'], str)):
            raise Invalid('Yarn bootstrap lock differs from the pinned release')
        raw = provider.fetch(URL, limit=32 * 1024 * 1024)
        if integrity(raw) != selected['integrity']:
            raise Invalid('Yarn tool artifact integrity mismatch')
        (directory / 'tool.tgz').write_bytes(raw)
        # Reuse the existing bounded ordinary-file extractor, not npm install.
        unpack(raw, directory / 'payload')
        if lock is None:
            metadata = parse_json(provider.fetch('https://registry.npmjs.org/@yarnpkg%2flockfile/' + PARSER_VERSION))
            if metadata.get('name') != '@yarnpkg/lockfile' or metadata.get('version') != PARSER_VERSION:
                raise Invalid('Yarn parser bootstrap identity mismatch')
            selected['parser'] = {'version': PARSER_VERSION, 'url': metadata['dist']['tarball'],
                                  'integrity': metadata['dist']['integrity']}
        parser = selected.get('parser', {})
        if (set(parser) != {'version', 'url', 'integrity'} or parser['version'] != PARSER_VERSION
                or parser['url'] != PARSER_URL):
            raise Invalid('Yarn bootstrap requires the pinned upstream lock parser')
        parser_raw = provider.fetch(PARSER_URL, limit=32 * 1024 * 1024)
        if integrity(parser_raw) != parser['integrity']:
            raise Invalid('Yarn parser artifact integrity mismatch')
        unpack(parser_raw, directory / 'payload/lock-parser')
        manifest = load(directory / 'payload/lock-parser/package.json')
        if (manifest.get('name'), manifest.get('version')) != ('@yarnpkg/lockfile', PARSER_VERSION):
            raise Invalid('Yarn parser artifact identity mismatch')
        (directory / 'parser.tgz').write_bytes(parser_raw)
        save(directory / 'tools.lock', selected)
        receipt.update(files=payload(directory / 'payload'), node=node_identity(),
                       parser_sha256=hashlib.sha256(parser_raw).hexdigest(),
                       archive_sha256=hashlib.sha256(raw).hexdigest(),
                       lock_sha256=hashlib.sha256((directory / 'tools.lock').read_bytes()).hexdigest())
        receipt['outcome'] = 'ready'
        return directory
    finally:
        save(directory / 'tool.json', receipt)


def verified(directory=None):
    directory = directory or os.environ.get('PTW_YARN_TOOL')
    if not directory:
        raise Invalid('Provision Yarn explicitly and set PTW_YARN_TOOL; no ambient fallback')
    directory = Path(directory).resolve(strict=True)
    receipt = load(directory / 'tool.json')
    if (receipt.get('outcome') != 'ready' or receipt.get('version') != VERSION or
            receipt.get('files') != payload(directory / 'payload') or
            receipt.get('node') != node_identity() or
            receipt.get('parser_sha256') != hashlib.sha256((directory / 'parser.tgz').read_bytes()).hexdigest() or
            receipt.get('lock_sha256') != hashlib.sha256((directory / 'tools.lock').read_bytes()).hexdigest() or
            receipt.get('archive_sha256') != hashlib.sha256((directory / 'tool.tgz').read_bytes()).hexdigest()):
        raise Invalid('Yarn tooling changed; provision a new tool directory')
    return directory, receipt


def parse_lock(text):
    """Use the pinned upstream data parser, never import project JavaScript."""
    if not isinstance(text, str) or len(text.encode()) > 8 * 1024 * 1024:
        raise Invalid('Yarn lock exceeds input limit')
    directory, receipt = verified()
    script = """
const fs = require('node:fs');
const parser = require(process.argv[1]);
const result = parser.parse(fs.readFileSync(0, 'utf8'));
if (result.type !== 'success') process.exit(2);
process.stdout.write(JSON.stringify(result.object));
"""
    try:
        result = subprocess.run([receipt['node']['path'], '-e', script,
            str(directory / 'payload/lock-parser')], input=text, capture_output=True,
            text=True, timeout=15, check=True, cwd=directory,
            env={'PATH': '/usr/bin:/bin'})
        parsed = parse_json(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise Invalid('Malformed Yarn lock or unavailable upstream parser') from exc
    if verified(directory)[1] != receipt or not isinstance(parsed, dict) or len(parsed) > 2048:
        raise Invalid('Yarn parser changed or lock graph exceeds limit')
    return parsed


def run(arguments, *, cwd, timeout=90, directory=None):
    """Install a disposable stage offline, preserving its authoritative inputs.

    Only broker-supplied tarballs belong in .ptw-yarn-mirror. Native Yarn owns
    the empty private cache and all cache metadata. No hand-built cache records,
    project rc files, alternate executables or executable preparation are used.
    This function intentionally exposes no build or online installation switch.
    """
    from .supervisor import runtime_namespace
    from .yarn import read_inputs
    if arguments != ['install', '--frozen-lockfile']:
        raise Invalid('Only frozen Yarn installation is supported')
    if type(timeout) not in (int, float) or not 0 < timeout <= 180:
        raise Invalid('Invalid Yarn native timeout')
    directory, receipt = verified(directory)
    stage = Path(cwd).resolve(strict=True)
    if stage == directory or stage.is_relative_to(directory) or directory.is_relative_to(stage):
        raise Invalid('Yarn stage and tool payload must be separate')
    files, _ = read_inputs(stage)
    # Never reuse caller-controlled native cache metadata for this primitive.
    cache = stage / '.ptw-yarn-cache'
    cache.mkdir(exist_ok=False)
    config = stage / '.ptw-yarnrc'
    with config.open('x') as stream:
        stream.write('yarn-offline-mirror "/resolution/.ptw-yarn-mirror"\n'
                     'yarn-offline-mirror-pruning false\n'
                     'disable-self-update-check true\n')
    env = resolver_environment(stage)
    env.update(CI='true', YARN_IGNORE_PATH='1', COREPACK_ENABLE_NETWORK='0',
               COREPACK_ENABLE_PROJECT_SPEC='0')
    command = runtime_namespace() + ['--ro-bind', str(directory / 'payload'), '/yarn-tools',
        '--bind', str(stage), '/resolution', '--ro-bind', str(config), '/yarnrc',
        '--chdir', '/resolution']
    for key, value in env.items():
        command += ['--setenv', key, value.replace(str(stage), '/resolution')]
    command += ['--', receipt['node']['path'], '/yarn-tools/' + ENTRY, *arguments,
                '--offline', '--ignore-scripts', '--non-interactive', '--no-default-rc',
                '--use-yarnrc', '/yarnrc', '--cache-folder', '/resolution/.ptw-yarn-cache',
                '--global-folder', '/resolution/.ptw-yarn-global',
                '--link-folder', '/resolution/.ptw-yarn-links',
                '--production=false', '--disable-pnp', '--no-progress', '--json']
    report = {'outcome': 'failed', 'tool_sha256': receipt['archive_sha256'],
              'inputs': {n: hashlib.sha256(t.encode()).hexdigest() for n, t in files.items()}}
    start = time.monotonic()
    try:
        result = subprocess.run(command, env={'PATH': '/usr/bin:/bin'},
                                capture_output=True, text=True, timeout=timeout)
        report.update(returncode=result.returncode,
                      signals=resolver_failure_signals(result.stdout + result.stderr),
                      stdout_sha256=hashlib.sha256(result.stdout.encode()).hexdigest(),
                      stderr_sha256=hashlib.sha256(result.stderr.encode()).hexdigest())
        if verified(directory)[1] != receipt:
            raise Invalid('Yarn tooling changed during native execution')
        if any((stage / n).read_bytes() != text.encode() for n, text in files.items()):
            raise Invalid('Native Yarn changed authoritative inputs')
        report['outcome'] = 'completed' if result.returncode == 0 else 'native_failure'
        return result
    except subprocess.TimeoutExpired as exc:
        report['outcome'] = 'timeout'
        raise ResolutionError('budget_exhausted', 'native Yarn timed out') from exc
    finally:
        report['elapsed_seconds'] = time.monotonic() - start
        save(stage / ('native-' + uuid.uuid4().hex + '.json'), report)


def resolve_lock(stage, endpoint, *, timeout):
    """Native resolution and lock serialization, without fetching or execution.

    The pinned upstream hook omits fetch/link/build, not resolution. The only
    mounted project inputs are admitted metadata; no credential or source code
    is present. The metadata broker retains original artifact URLs. A resulting
    lock is only a candidate, never an install or a policy assessment.
    """
    from .supervisor import runtime_namespace
    if (not isinstance(endpoint, str) or not re.fullmatch(r'http://127\.0\.0\.1:[0-9]+/[a-f0-9]+/', endpoint)
            or type(timeout) not in (int, float) or not 0 < timeout <= 180):
        raise Invalid('Invalid Yarn metadata endpoint or budget')
    directory, receipt = verified()
    stage = Path(stage).resolve(strict=True)
    if stage == directory or stage.is_relative_to(directory) or directory.is_relative_to(stage):
        raise Invalid('Yarn stage and tool payload must be separate')
    hook = stage / '.ptw-yarn-resolution.cjs'
    with hook.open('x') as stream:
        stream.write(RESOLUTION_HOOK)
    env = resolver_environment(stage)
    env.update(CI='true', YARN_IGNORE_PATH='1', COREPACK_ENABLE_NETWORK='0',
               COREPACK_ENABLE_PROJECT_SPEC='0')
    command = runtime_namespace()
    index = command.index('--unshare-all')
    command[index:index + 1] = ['--unshare-user', '--unshare-pid', '--unshare-ipc', '--unshare-uts']
    command += ['--ro-bind', str(directory / 'payload'), '/yarn-tools',
                '--bind', str(stage), '/resolution', '--ro-bind', str(hook), '/resolution-hook.cjs',
                '--chdir', '/resolution']
    for key, value in env.items():
        command += ['--setenv', key, value.replace(str(stage), '/resolution')]
    command += ['--', receipt['node']['path'], '--require', '/resolution-hook.cjs',
        '/yarn-tools/' + ENTRY, 'install', '--ignore-scripts', '--non-interactive',
        '--no-default-rc', '--registry', endpoint, '--production=false', '--disable-pnp',
        '--cache-folder', '/resolution/.ptw-yarn-cache',
        '--global-folder', '/resolution/.ptw-yarn-global',
        '--link-folder', '/resolution/.ptw-yarn-links', '--no-progress', '--json',
        '--network-timeout', str(max(1, int(timeout * 1000)))]
    report = {'outcome': 'failed', 'tool_sha256': receipt['archive_sha256'],
              'hook_sha256': hashlib.sha256(RESOLUTION_HOOK.encode()).hexdigest()}
    start = time.monotonic()
    try:
        result = subprocess.run(command, env={'PATH': '/usr/bin:/bin'},
                                capture_output=True, text=True, timeout=timeout)
        report.update(returncode=result.returncode,
                      stdout_sha256=hashlib.sha256(result.stdout.encode()).hexdigest(),
                      stderr_sha256=hashlib.sha256(result.stderr.encode()).hexdigest())
        if verified(directory)[1] != receipt or hook.read_text() != RESOLUTION_HOOK:
            raise Invalid('Yarn resolution tooling changed')
        report['outcome'] = 'completed' if result.returncode == 0 else 'native_failure'
        return result
    except subprocess.TimeoutExpired as exc:
        report['outcome'] = 'timeout'
        raise ResolutionError('budget_exhausted', 'native Yarn resolution timed out') from exc
    finally:
        report['elapsed_seconds'] = time.monotonic() - start
        save(stage / ('native-' + uuid.uuid4().hex + '.json'), report)


def main():
    parser = argparse.ArgumentParser(description='Provision isolated Yarn Classic ' + VERSION)
    parser.add_argument('directory', help='New operator tool directory')
    parser.add_argument('--lock', help='Previously reviewed tools.lock for exact reconstruction')
    args = parser.parse_args()
    print(provision(args.directory, lock=args.lock))


if __name__ == '__main__':
    main()
