"""Native file_indexing mount/process seam using installed bubblewrap and nono.

This is a trusted launcher, not an agent tool or a permission proposal. Its caller
must bind the immutable specification to approved authority, authenticate and
admit its stopped process through linuxarena_lifecycle before sending SIGCONT.
Only the native fixture integrates this seam until its compatibility is proven.
The standalone entry point also runs in the pinned container's system Python.
"""
import json
import os
from pathlib import PurePosixPath
import signal
import stat
import sys

TOOLS = '/ptw-native-tools'
STATE = '/ptw-native-state'
RUNTIME = ('/usr', '/etc/passwd', '/etc/group', '/etc/nsswitch.conf',
           '/etc/ld.so.cache', '/etc/pam.d', '/etc/login.defs',
           '/etc/sudoers', '/etc/sudoers.d')
# Keep the container's Unix-user mapping. A new single-user user namespace would
# break root cron's legitimate sudo -u path. No mount/ptrace/network/admin caps
# survive into mutable code. The separate PID namespace hides trusted observers.
CAPABILITIES = ('CAP_SETUID', 'CAP_SETGID', 'CAP_DAC_OVERRIDE', 'CAP_CHOWN',
                'CAP_FOWNER', 'CAP_KILL')


def validate(spec):
    if not isinstance(spec, dict) or set(spec) != {'read', 'write', 'argv', 'cwd', 'connect_ports'}:
        raise ValueError('Expected exact trusted native execution specification')
    paths = []
    for access in ('read', 'write'):
        entries = spec[access]
        if not isinstance(entries, list) or len(entries) > 64:
            raise ValueError('Invalid native mount list')
        for name in entries:
            if (not isinstance(name, str) or '\x00' in name or
                    not name.startswith('/') or name.startswith('//') or
                    str(PurePosixPath(name)) != name or '..' in PurePosixPath(name).parts):
                raise ValueError('Expected canonical absolute native resource path')
            path = PurePosixPath(name)
            protected = ('/proc', '/sys', '/dev', '/tmp', TOOLS, STATE, *RUNTIME,
                         '/bin', '/sbin', '/lib', '/lib64')
            if name == '/' or any(path.is_relative_to(p) or PurePosixPath(p).is_relative_to(path)
                                  for p in protected):
                raise ValueError('Native resource overlaps trusted runtime or private namespace')
            if any(path.is_relative_to(p) or p.is_relative_to(path) for p in paths):
                raise ValueError('Overlapping native resources')
            paths.append(path)
    if (not isinstance(spec['argv'], list) or not spec['argv'] or len(spec['argv']) > 256 or
            any(not isinstance(x, str) or '\x00' in x for x in spec['argv']) or
            sum(len(x) for x in spec['argv']) > 131072):
        raise ValueError('Invalid native argument vector')
    cwd = spec['cwd']
    if (not isinstance(cwd, str) or '\x00' in cwd or not cwd.startswith('/') or
            str(PurePosixPath(cwd)) != cwd or '..' in PurePosixPath(cwd).parts or
            not any(PurePosixPath(cwd).is_relative_to(p) for p in paths)):
        raise ValueError('Native cwd must be within a granted resource')
    ports = spec['connect_ports']
    if (not isinstance(ports, list) or len(ports) > 8 or
            any(type(p) is not int or not 1 <= p <= 65535 for p in ports) or
            len(set(ports)) != len(ports)):
        raise ValueError('Invalid native TCP ports')
    return spec


def open_resource(path):
    """Pin each component before privileged mounting; never follow agent links."""
    parts = PurePosixPath(path).parts
    if not parts or parts[0] != '/' or '..' in parts:
        raise ValueError('Expected absolute resource')
    fd = os.open('/', os.O_PATH | os.O_DIRECTORY)
    try:
        for part in parts[1:]:
            child = os.open(part, os.O_PATH | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            mode = os.fstat(fd).st_mode
            if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                raise ValueError('Native mounts require regular files/directories without links')
        os.set_inheritable(fd, True)
        return fd
    except BaseException:
        os.close(fd)
        raise


def command(spec):
    """Return bubblewrap argv and pinned FDs, to be closed on every failed exec.

    Resource roots must already exist. No ancestor is granted to make an absent
    exact file writable. Child-created files live only under writable roots.
    TCP destinations still require the episode's external network boundary;
    nono's allowed ports are not a destination or service authorization system.
    """
    validate(spec)
    loader = [TOOLS + '/lib/ld-linux-x86-64.so.2', '--library-path', TOOLS + '/lib']
    args = [*loader, TOOLS + '/bin/bwrap', '--unshare-pid', '--unshare-ipc',
            '--unshare-uts', '--unshare-cgroup', '--new-session', '--clearenv',
            '--setenv', 'PATH', '/usr/local/bin:/usr/bin:/bin',
            '--setenv', 'HOME', STATE, '--setenv', 'XDG_STATE_HOME', STATE,
            '--cap-drop', 'ALL']
    for cap in CAPABILITIES:
        args += ['--cap-add', cap]
    # Auto-created mount parents are private (0700). Native sudo children
    # need to traverse this synthetic parent; no host /etc is mounted here.
    args += ['--perms', '0755', '--dir', '/etc']
    fds = []
    try:
        for path in (*RUNTIME, TOOLS, *spec['read'], *spec['write']):
            fd = open_resource(path)
            fds.append(fd)
            args += ['--bind-fd' if path in spec['write'] else '--ro-bind-fd', str(fd), path]
        args += ['--symlink', 'usr/bin', '/bin', '--symlink', 'usr/sbin', '/sbin',
                 '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
                 '--proc', '/proc', '--dir', '/dev',
                 '--perms', '1777', '--tmpfs', '/tmp',
                 '--dir', STATE]
        for device in ('null', 'zero', 'random', 'urandom'):
            args += ['--dev-bind', '/dev/' + device, '/dev/' + device]
        args += ['--symlink', '/proc/self/fd', '/dev/fd', '--chdir', spec['cwd'], '--',
                 *loader, TOOLS + '/bin/nono', 'run', '--silent', '--sandbox-policy', 'auto',
                 '--block-net', '--allow', '/tmp', '--read', TOOLS,
                 '--no-rollback', '--no-audit', '--no-diagnostics']
        # The pinned image's sudo library, plugin and configuration have
        # demonstrated native read denials under nono's default policy.
        # Grant exact files in immutable mounts, never their parent directory or
        # an agent-selected runtime path. Missing files fail nono admission.
        for path in ('/usr/libexec/sudo/libsudo_util.so.0.0.0',
                     '/usr/libexec/sudo/sudoers.so', '/etc/sudoers'):
            args += ['--read-file', path]
        # sudo's includedir directive must enumerate and read the image's
        # configuration fragments. This fixed directory is already mounted
        # read-only; do not grant /etc or allow agent-selected configuration.
        args += ['--read', '/etc/sudoers.d']
        # The retained native receipt shows EACCES on sudo's PAM config and
        # every include. This fixed image configuration is already read-only;
        # it must remain available across legitimate Unix-user transitions.
        args += ['--read', '/etc/pam.d']
        for access, flag, file_flag in (('read', '--read', '--read-file'),
                                        ('write', '--allow', '--allow-file')):
            for path in spec[access]:
                # Use the already pinned inode, not another pathname lookup.
                fd = fds[(*RUNTIME, TOOLS, *spec['read'], *spec['write']).index(path)]
                args += [flag if stat.S_ISDIR(os.fstat(fd).st_mode) else file_flag, path]
        for port in spec['connect_ports']:
            args += ['--allow-connect-port', str(port)]
        return args + ['--', *spec['argv']], fds
    except BaseException:
        for fd in fds:
            os.close(fd)
        raise


def main():
    if len(sys.argv) != 2:
        raise ValueError('Trusted launcher requires one frozen specification')
    spec = validate(json.loads(sys.argv[1]))
    args, fds = command(spec)
    try:
        # No mutable code runs, including startup files or Python site imports,
        # before the external controller records and admits this process.
        os.kill(os.getpid(), signal.SIGSTOP)
        os.execv(args[0], args)
    finally:
        for fd in fds:
            os.close(fd)


if __name__ == '__main__':
    main()
