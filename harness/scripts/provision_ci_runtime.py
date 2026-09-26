"""Prepare disposable hosted CI only; never run this on a shared development host."""
import argparse
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from product_install import clean_env, require, run, sha


def node_version(binary, env):
    version = run([binary, '--version'], env=env)
    require(re.fullmatch(r'v22\.\d+\.\d+', version), 'CI requires Node 22: ' + str(binary))
    return version


def install_node(source, usr=Path('/usr')):
    """Copy setup-node's selected bytes into the existing confined runtime tree."""
    source = source.resolve(strict=True)
    require(source.is_file(), 'Selected Node must be a regular executable')
    destination = usr / 'bin/node'
    require(destination.parent.resolve(strict=True).is_relative_to(usr.resolve(strict=True)),
            'CI Node destination escapes /usr')
    require(not destination.is_symlink() and (not destination.exists() or destination.is_file()),
            'CI Node destination must be absent or a regular file')
    # Replace an old regular executable atomically, without following links or
    # leaving a partially copied runtime if validation fails.
    with tempfile.TemporaryDirectory(prefix='.ptw-ci-node-', dir=destination.parent) as temporary:
        staging = Path(temporary)
        env = clean_env(staging)
        env['PATH'] = str(usr / 'bin') + ':/bin'
        version = node_version(source, env)
        expected = sha(source.read_bytes())
        candidate = staging / 'node'
        shutil.copy2(source, candidate)
        require(sha(candidate.read_bytes()) == expected, 'CI Node copy digest mismatch')
        require(node_version(candidate, env) == version, 'CI Node copy version mismatch')
        candidate.replace(destination)
    require(sha(destination.read_bytes()) == expected, 'Installed CI Node digest mismatch')
    return {'version': version, 'sha256': expected}


def verify(npm, usr=Path('/usr')):
    from ptw.supervisor import runtime_namespace

    node = usr / 'bin/node'
    require(node.resolve(strict=True).is_relative_to(usr.resolve(strict=True)),
            'CI Node executable escapes /usr')
    with tempfile.TemporaryDirectory(prefix='ptw-ci-runtime-') as temporary:
        directory = Path(temporary)
        env = clean_env(directory)
        env['PATH'] = str(usr / 'bin') + ':/bin'
        env['HOME'] = str(directory)
        version = node_version(node, env)
        require(run(['/usr/bin/env', 'node', '--version'], env=env) == version,
                'Node lookup differs under the confined PATH')
        for name in ('fish', 'zsh', 'bwrap'):
            executable = shutil.which(name, path=env['PATH'])
            require(executable, 'Missing CI prerequisite: ' + name)
            require(run([executable, '--version'], env=env), 'Empty CI version: ' + name)
        require(re.fullmatch(r'\d+\.\d+\.\d+', run([npm, '--version'], env=env, cwd=directory)),
                'Invalid CI npm version')
        # Exercise the product's actual namespace as the ordinary runner user.
        # An OS denial is a failed prerequisite, never permission to bypass it.
        probe = subprocess.run(runtime_namespace() + [str(node), '--version'],
                               env=env, capture_output=True, text=True, timeout=60)
        # This fixed, disposable-runner probe has no dependency/configuration
        # payload. Retain its bounded native denial instead of a generic exit.
        settings = {}
        if probe.returncode:
            for name in ('kernel/apparmor_restrict_unprivileged_userns',
                         'kernel/unprivileged_userns_clone', 'user/max_user_namespaces'):
                path = Path('/proc/sys') / name
                if path.is_file():
                    settings[name] = path.read_text().strip()[:40]
        require(probe.returncode == 0,
                f'CI namespace probe failed ({probe.returncode}): {probe.stderr.strip()[:2000]}; '
                f'namespace settings: {settings}')
        require(probe.stdout.strip() == version,
                'Node unavailable inside the product namespace')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--node-source', type=Path)
    mode.add_argument('--npm', type=Path)
    args = parser.parse_args()
    if args.node_source:
        print(install_node(args.node_source))
    else:
        verify(args.npm.resolve(strict=True))
        print('CI runtime prerequisites verified')


if __name__ == '__main__':
    main()
