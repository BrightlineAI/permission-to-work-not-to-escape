"""Explicit pinned pnpm tooling and offline native operations on disposable stages.

This is an operator tool boundary, not a package authorization API. Callers must
supply validated copies and independently authorize/assess the resulting graph.
"""
import argparse
import base64
import hashlib
import io
import os
from pathlib import Path
import re
import subprocess
import tarfile
import time
import uuid

from .dependency_resolution import ResolutionError, resolver_environment
from .npm import NpmEvidence
from .policy import Invalid, file_sha256, load, parse_json, save


VERSION = '10.23.0'
URL = 'https://registry.npmjs.org/pnpm/-/pnpm-' + VERSION + '.tgz'
ENTRY = 'bin/pnpm.cjs'


def integrity(raw):
    return 'sha512-' + base64.b64encode(hashlib.sha512(raw).digest()).decode()


def unpack(raw, target):
    """Extract the published tool without executing npm or archive permissions."""
    target = Path(target)
    target.mkdir()
    seen, expanded = set(), 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        for member in archive:
            name = member.name.rstrip('/')
            parts = name.split('/')
            expanded += member.size
            if (len(seen) >= 20000 or expanded > 128 * 1024 * 1024 or
                    not parts or parts[0] != 'package' or '\\' in name or
                    any(p in ('', '.', '..') for p in parts) or name in seen or
                    not (member.isfile() or member.isdir())):
                raise Invalid('Unsafe pnpm tool archive')
            seen.add(name)
            path = target.joinpath(*parts[1:])
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open('xb') as output:
                    output.write(archive.extractfile(member).read())


def payload(root):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise Invalid('pnpm tool payload must be an ordinary directory')
    result = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise Invalid('pnpm tool payload contains a link or special file')
        if path.is_file():
            result[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    if ENTRY not in result or 'package.json' not in result:
        raise Invalid('Incomplete pnpm tool payload')
    manifest = load(root / 'package.json')
    if manifest.get('name') != 'pnpm' or manifest.get('version') != VERSION:
        raise Invalid('pnpm tool version differs from the pinned API')
    return result


def node_identity():
    # The declared manager platform supplies Node22 here. Corepack is never run.
    path = Path('/usr/bin/node').resolve(strict=True)
    if not path.is_relative_to('/usr') or not path.is_file():
        raise Invalid('pnpm requires a system Node runtime under /usr')
    return {'path': str(path), 'sha256': file_sha256(path)}


def provision(directory, *, lock=None):
    """Download one exact published tool. Rebuilds can require its saved SRI lock.

    Initial bootstrap trusts registry TLS and records its integrity. It does not
    claim an independently authenticated release signature. No ambient auth,
    proxy, global installation, lifecycle or package-manager shim is used.
    """
    directory = Path(directory).absolute()
    directory.mkdir(parents=True, exist_ok=False)
    receipt = {'outcome': 'failed', 'version': VERSION}
    try:
        provider = NpmEvidence()
        if lock is None:
            metadata = parse_json(provider.fetch('https://registry.npmjs.org/pnpm/' + VERSION))
            if metadata.get('name') != 'pnpm' or metadata.get('version') != VERSION:
                raise Invalid('pnpm bootstrap metadata identity mismatch')
            selected = {'version': VERSION, 'url': metadata['dist']['tarball'],
                        'integrity': metadata['dist']['integrity']}
        else:
            selected = load(lock)
        if (set(selected) != {'version', 'url', 'integrity'} or selected['version'] != VERSION or
                selected['url'] != URL or not isinstance(selected['integrity'], str)):
            raise Invalid('pnpm bootstrap lock differs from the pinned release')
        save(directory / 'tools.lock', selected)
        raw = provider.fetch(URL, limit=32 * 1024 * 1024)
        if integrity(raw) != selected['integrity']:
            raise Invalid('pnpm tool artifact integrity mismatch')
        (directory / 'tool.tgz').write_bytes(raw)
        unpack(raw, directory / 'payload')
        receipt.update(files=payload(directory / 'payload'), node=node_identity(),
                       archive_sha256=hashlib.sha256(raw).hexdigest(),
                       lock_sha256=hashlib.sha256((directory / 'tools.lock').read_bytes()).hexdigest())
        receipt['outcome'] = 'ready'
        return directory
    finally:
        save(directory / 'tool.json', receipt)


def verified(directory=None):
    directory = directory or os.environ.get('PTW_PNPM_TOOL')
    if not directory:
        raise Invalid('Provision pnpm explicitly and set PTW_PNPM_TOOL; no ambient fallback')
    directory = Path(directory).resolve(strict=True)
    receipt = load(directory / 'tool.json')
    if (receipt.get('outcome') != 'ready' or receipt.get('version') != VERSION or
            receipt.get('files') != payload(directory / 'payload') or
            receipt.get('node') != node_identity() or
            receipt.get('lock_sha256') != hashlib.sha256((directory / 'tools.lock').read_bytes()).hexdigest() or
            receipt.get('archive_sha256') != hashlib.sha256((directory / 'tool.tgz').read_bytes()).hexdigest()):
        raise Invalid('pnpm tooling changed; provision a new tool directory')
    return directory, receipt


def native_options():
    """Fixed configuration shared by offline import and supervised rebuild."""
    return ['--config.offline=true', '--config.ignore-scripts=true', '--config.ignore-pnpmfile=true',
            '--config.manage-package-manager-versions=false',
            '--config.package-manager-strict-version=true',
            '--config.side-effects-cache=false', '--config.package-import-method=copy',
            '--config.store-dir=/resolution/store', '--config.cache-dir=/resolution/cache',
            '--config.state-dir=/resolution/state', '--config.virtual-store-dir=node_modules/.pnpm',
            '--config.userconfig=/dev/null', '--config.globalconfig=/dev/null',
            '--config.update-notifier=false', '--config.verify-store-integrity=true',
            '--config.fetch-retries=0']


def rebuild(target, names, run_build):
    """Execute only archive-derived, policy-approved names via the supervisor.

    Named rebuild avoids pnpm's no-argument form, which also runs root hooks.
    The caller independently validates authoritative inputs and exported files.
    """
    from .npm import NAME
    from .supervisor import runtime_namespace
    if (not names or not callable(run_build) or
            any(not isinstance(n, str) or not re.fullmatch(NAME, n) for n in names)):
        raise Invalid('pnpm rebuild requires explicit package names and supervision')
    directory, receipt = verified()
    target = Path(target)
    config = target.with_name(target.name + '-build.npmrc')
    config.write_text(''.join('only-built-dependencies[]=' + name + '\n' for name in sorted(names)))
    options = [option for option in native_options() if option not in (
        '--config.ignore-scripts=true', '--config.userconfig=/dev/null')]
    options += ['--config.ignore-scripts=false', '--config.userconfig=/build.npmrc']
    command = runtime_namespace() + ['--ro-bind', str(directory / 'payload'), '/pnpm-tools',
        '--ro-bind', str(config), '/build.npmrc', '--bind', str(target), '/target',
        '--symlink', '/target', '/resolution', '--chdir', '/resolution',
        '--setenv', 'CI', 'true', '--setenv', 'COREPACK_ENABLE_NETWORK', '0',
        '--setenv', 'COREPACK_ENABLE_PROJECT_SPEC', '0',
        '--', receipt['node']['path'], '/pnpm-tools/' + ENTRY, 'rebuild', *sorted(names), *options]
    run_build(command)
    if verified(directory)[1] != receipt:
        raise Invalid('pnpm tooling changed during supervised build')


def run(arguments, *, cwd, timeout=90, directory=None):
    """No-network native call; cwd is a private disposable stage, never the repo.

    The production adapter must validate workspace configuration before this
    primitive. The primitive always disables executable preparation. It exposes
    no switch to turn off confinement or authorize a build.
    """
    from .supervisor import runtime_namespace
    if (not isinstance(arguments, list) or not arguments or
            any(not isinstance(a, str) or '\x00' in a for a in arguments) or
            not isinstance(timeout, (int, float)) or not 0 < timeout <= 180):
        raise Invalid('Invalid pnpm native operation or timeout')
    inspection = ['list', '--recursive', '--json', '--long', '--depth', 'Infinity', '--lockfile-only']
    if arguments not in (inspection, ['install', '--frozen-lockfile'],
                         ['install', '--lockfile-only', '--frozen-lockfile'], ['fetch']):
        raise Invalid('Only frozen install, lock inspection and offline fetch are supported')
    directory, receipt = verified(directory)
    stage = Path(cwd).resolve(strict=True)
    if stage == directory or stage.is_relative_to(directory) or directory.is_relative_to(stage):
        raise Invalid('pnpm stage and tool payload must be separate')
    env = resolver_environment(stage)
    env.update(CI='true', COREPACK_ENABLE_NETWORK='0', COREPACK_ENABLE_PROJECT_SPEC='0',
               PNPM_HOME='/resolution/resolver-home/pnpm')
    common = native_options()
    if arguments == ['fetch']:
        # Otherwise pnpm may recover from integrity errors by resolving again
        # against fetch's empty synthetic manifest and rewriting the recipe.
        common.append('--config.frozen-lockfile=true')
    command = runtime_namespace() + ['--ro-bind', str(directory / 'payload'), '/pnpm-tools',
        '--bind', str(stage), '/resolution', '--chdir', '/resolution']
    for key, value in env.items():
        command += ['--setenv', key, value.replace(str(stage), '/resolution')]
    command += ['--', receipt['node']['path'], '/pnpm-tools/' + ENTRY, *arguments, *common]
    report = {'outcome': 'failed', 'arguments_sha256': hashlib.sha256(
        '\0'.join(arguments).encode()).hexdigest(), 'tool_sha256': receipt['archive_sha256']}
    start = time.monotonic()
    try:
        result = subprocess.run(command, env={'PATH': '/usr/bin:/bin'},
                                capture_output=True, text=True, timeout=timeout)
        report.update(returncode=result.returncode,
            error_codes=sorted(set(re.findall(r'ERR_PNPM_[A-Z_]+', result.stdout + result.stderr))),
            stdout_sha256=hashlib.sha256(result.stdout.encode()).hexdigest(),
            stderr_sha256=hashlib.sha256(result.stderr.encode()).hexdigest())
        if verified(directory)[1] != receipt:
            raise Invalid('pnpm tooling changed during native execution')
        report['outcome'] = 'completed' if result.returncode == 0 else 'native_failure'
        return result
    except subprocess.TimeoutExpired as exc:
        report['outcome'] = 'timeout'
        raise ResolutionError('budget_exhausted', 'native pnpm timed out') from exc
    finally:
        report['elapsed_seconds'] = time.monotonic() - start
        save(stage / ('native-' + uuid.uuid4().hex + '.json'), report)


def resolve_lock(stage, endpoint, *, age_minutes, timeout):
    """Metadata-only native solver, against the broker's sanitized loopback view.

    Only the validated metadata stage and verified tool payload are mounted.
    This networking namespace is never used for installation or project code.
    """
    from .supervisor import runtime_namespace
    if (not re.fullmatch(r'http://127\.0\.0\.1:[0-9]+/[a-f0-9]+/', endpoint) or
            type(age_minutes) is not int or age_minutes < 0 or not 0 < timeout <= 180):
        raise Invalid('Invalid pnpm metadata endpoint or budget')
    directory, receipt = verified()
    stage = Path(stage).resolve(strict=True)
    env = resolver_environment(stage)
    env.update(CI='true', COREPACK_ENABLE_NETWORK='0', COREPACK_ENABLE_PROJECT_SPEC='0')
    options = [o for o in native_options() if o != '--config.offline=true']
    options += ['--config.offline=false', '--config.registry=' + endpoint,
                '--config.minimum-release-age=' + str(age_minutes),
                '--config.lockfile-include-tarball-url=true',
                '--config.fetch-timeout=' + str(max(1, int(timeout * 1000)))]
    command = runtime_namespace()
    index = command.index('--unshare-all')
    command[index:index + 1] = ['--unshare-user', '--unshare-pid', '--unshare-ipc', '--unshare-uts']
    command += ['--ro-bind', str(directory / 'payload'), '/pnpm-tools',
                '--bind', str(stage), '/resolution', '--chdir', '/resolution']
    for key, value in env.items():
        command += ['--setenv', key, value.replace(str(stage), '/resolution')]
    command += ['--', receipt['node']['path'], '/pnpm-tools/' + ENTRY,
                'install', '--lockfile-only', '--no-frozen-lockfile', *options]
    result = subprocess.run(command, env={'PATH': '/usr/bin:/bin'}, capture_output=True,
                            text=True, timeout=timeout)
    if verified(directory)[1] != receipt:
        raise Invalid('pnpm tooling changed during resolution')
    return result


def main():
    parser = argparse.ArgumentParser(description='Provision isolated pnpm ' + VERSION)
    parser.add_argument('directory', help='New operator tool directory')
    parser.add_argument('--lock', help='Previously reviewed tools.lock for exact reconstruction')
    args = parser.parse_args()
    print(provision(args.directory, lock=args.lock))


if __name__ == '__main__':
    main()
