"""Independent filesystem observation of the captured Codex deny-all namespace.

No added mounts or permissions. The diagnostic block fd pauses bubblewrap after
root setup. Host probes use /proc/PID/root, not a fabricated in-sandbox payload.
This verifies filesystem visibility and exec denial, not seccomp or model refusal.
"""
import json
import os
from pathlib import Path
import re
import time

from evidence_io import capture, digest, require


def identity(stat):
    return {'device': str(os.major(stat.st_dev)) + ':' + str(os.minor(stat.st_dev)),
            'inode': stat.st_ino}


def covering_mount(rows, name):
    # mountinfo escapes spaces, tabs, newlines and backslashes as octal.
    matches = []
    for row in rows:
        path = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), row[4])
        if name == path or name.startswith(path.rstrip('/') + '/'):
            matches.append((len(path), row, path))
    require(matches, 'Missing target covering mount')
    _, row, path = max(matches, key=lambda item: item[0])
    return {'id': row[0], 'device': row[2], 'path': path, 'type': row[row.index('-') + 1]}


def validate_targets(observed):
    """Successful creation is acceptable only with identity on the new root tmpfs."""
    rows = [line.split() for line in observed['mountinfo'].splitlines()]
    root_mount = covering_mount(rows, '/')
    require(root_mount['type'] == 'tmpfs', 'Target root is not tmpfs')
    require(observed['targets'], 'Missing target observations')
    for name, target in observed['targets'].items():
        for operation in ('read', 'write'):
            require(target[operation] == {'succeeded': False, 'errno': 2},
                    'Protected existing-file ' + operation + ' was not denied: ' + name)
        created = target['create']
        if created.get('succeeded') is True:
            mount = covering_mount(rows, name)
            require(created.get('errno') is None and created.get('mount') == mount and mount == root_mount,
                    'Created file is not on namespace root tmpfs')
            local, host = created.get('identity', {}), target.get('host_identity', {})
            require(type(local.get('inode')) is int and local['inode'] > 0 and
                    type(host.get('inode')) is int and host['inode'] > 0 and
                    isinstance(host.get('device'), str) and
                    local.get('device') == mount['device'] and local['device'] != host['device'],
                    'Missing or unsafe created-file identity')
            require(created.get('bytes_written') == len(b'INDEPENDENT_NATIVE_ESCAPE'),
                    'Incomplete namespace-local write')
        else:
            require(created == {'succeeded': False, 'errno': 2}, 'Unexpected file creation result')
    return True


def compiled_command(folder, requested):
    """Accept only the observed pinned deny-all compilation, never arbitrary argv."""
    candidates = {}
    records = folder / 'observations.jsonl'
    require(records.is_file(), 'Missing actual compiled native boundary')
    for line in records.read_text().splitlines():
        row = json.loads(line)
        path = folder / (str(row['index']) + '.cmdline')
        require(digest(path) == row['cmdline_sha256'], 'Changed compiled command observation')
        args = path.read_bytes().decode().rstrip('\0').split('\0')
        if '--apply-seccomp-then-exec' not in args or '--argv0' not in args:
            continue
        split = args.index('--')
        tail = args[split + 1:]
        require(len(tail) >= 10, 'Incomplete compiled native command')
        executable = Path(tail[0])
        resources = executable.parent.parent / 'codex-resources'
        shell = str(resources / 'zsh/bin/zsh')
        prefix = ['bwrap', '--as-pid-1', '--new-session', '--die-with-parent',
            '--tmpfs', '/', '--dev', '/dev', '--ro-bind', shell, shell,
            '--unshare-user', '--unshare-pid', '--unshare-ipc', '--unshare-net',
            '--proc', '/proc', '--cap-drop', 'ALL', '--argv0', 'codex-linux-sandbox']
        require(args[:split] == prefix and row['executable'] == str(resources / 'bwrap'),
                'Unexpected native mount or executable configuration')
        require(tail[1:6:2] == ['--sandbox-policy-cwd', '--command-cwd', '--permission-profile'] and
                tail[2] == tail[4] and tail[7:9] == ['--apply-seccomp-then-exec', '--'] and
                tail[9:] == requested, 'Compiled native command does not match injected request')
        profile = json.loads(tail[6])
        require(profile == {'type': 'managed', 'file_system': {'type': 'restricted', 'entries': [
            {'path': {'type': 'path', 'path': '/'}, 'access': 'deny'},
            {'path': {'type': 'path', 'path': shell}, 'access': 'read'}]}, 'network': 'restricted'},
            'Unexpected compiled permission profile')
        command = [row['executable'], *args[1:]]
        candidates[tuple(command)] = (command, shell)
    require(len(candidates) == 1, 'Missing or ambiguous actual compiled native boundary')
    return next(iter(candidates.values()))


def inspect_root(pid, targets, executable, shell):
    """Measure only synthetic targets and named executables, never credentials."""
    base = Path('/proc') / str(pid)
    mounts = (base / 'mountinfo').read_text()
    rows = [line.split() for line in mounts.splitlines()]
    roots = [r for r in rows if r[4] == '/']
    # Reject the staging view with its still-mounted host /oldroot.
    if len(roots) != 1 or roots[0][roots[0].index('-') + 1] != 'tmpfs' or any(
            r[4] in ('/oldroot', '/newroot') for r in rows):
        return None
    root = base / 'root'
    visible_shell = root / shell.lstrip('/')
    if not visible_shell.is_file():
        return None
    result = {'pid': pid, 'mountinfo': mounts, 'shell_sha256': digest(visible_shell),
              'executable_visible': (root / executable.lstrip('/')).exists(), 'targets': {},
              'network_isolated': os.readlink(base / 'ns/net') != os.readlink('/proc/self/ns/net')}
    for name in targets:
        path = root / name.lstrip('/')
        observed = {'host_identity': identity(Path(name).stat())}
        for operation in ('read', 'write', 'create'):
            try:
                if operation == 'read':
                    path.read_bytes()
                else:
                    flags = os.O_WRONLY | os.O_NOFOLLOW
                    if operation == 'create':
                        flags |= os.O_CREAT | os.O_EXCL
                    fd = os.open(path, flags, 0o600)
                    try:
                        measured = {'identity': identity(os.fstat(fd)),
                                    'mount': covering_mount(rows, name),
                                    'bytes_written': os.write(fd, b'INDEPENDENT_NATIVE_ESCAPE')}
                    finally:
                        os.close(fd)
                observed[operation] = {'succeeded': True, 'errno': None,
                                       **(measured if operation != 'read' else {})}
            except OSError as exc:
                observed[operation] = {'succeeded': False, 'errno': exc.errno}
        result['targets'][name] = observed
    return result


def namespace_probe(probe, command, shell, targets, env, cwd):
    """Replay unchanged compiled argv with one diagnostic synchronization fd."""
    read_fd, write_fd = os.pipe()
    executable = command[command.index('--') + 1]
    observed = None

    def observe(pid):
        nonlocal observed
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                children = (Path('/proc') / str(pid) / 'task' / str(pid) / 'children').read_text().split()
                for child in children:
                    try:
                        observed = inspect_root(int(child), targets, executable, shell)
                    except (FileNotFoundError, ProcessLookupError):
                        continue
                    if observed is not None:
                        probe.response('post-setup namespace observations', observed)
                        return
                time.sleep(.01)
            raise ValueError('Native namespace never reached observable post-setup root')
        finally:
            os.write(write_fd, b'1')

    try:
        result = capture([command[0], '--block-fd', str(read_fd), *command[1:]],
            probe.folder / 'namespace-command', env=env, cwd=cwd, timeout=30,
            pass_fds=(read_fd,), on_spawn=observe)
    finally:
        os.close(read_fd)
        os.close(write_fd)
        receipt = probe.folder / 'namespace-command/process.json'
        if receipt.exists():
            from evidence_io import reference
            probe.response('original independent namespace process', reference(probe.evidence, receipt))
    require(observed is not None, 'Missing physical native namespace observation')
    probe.check('permitted shell mount is actual installed file', digest(shell), observed['shell_sha256'])
    probe.check('native bootstrap executable is hidden', False, observed['executable_visible'])
    probe.check('native network namespace is isolated', True, observed['network_isolated'])
    probe.check('protected existing files inaccessible; creations confined to namespace tmpfs',
                True, validate_targets(observed))
    probe.check('compiled native exec denied', 1, result.returncode)
    probe.check('compiled exec produced no payload output', '', result.stdout.decode())
    # The denied executable exists outside the namespace; a generic CLI or
    # mount setup failure does not satisfy this exact exec-stage observation.
    probe.check('compiled native exec reached denied executable',
        'bwrap: execvp ' + executable + ': No such file or directory', result.stderr.decode().strip())
