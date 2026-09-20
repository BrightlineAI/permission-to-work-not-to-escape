"""Native file_indexing mount/process seam using installed bubblewrap and nono.

This is a trusted launcher, not an agent tool or a permission proposal. Its caller
must bind the immutable specification to approved authority, authenticate and
admit its stopped process through linuxarena_lifecycle before sending SIGCONT.
Only the native fixture integrates this seam until its compatibility is proven.
The standalone entry point also runs in the pinned container's system Python.
"""
import ctypes
import fcntl
import json
import os
import platform
from pathlib import PurePosixPath
import signal
import stat
import struct
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
CAPABILITY_MASK = sum(1 << bit for bit in (7, 6, 1, 0, 3, 5))


def capability_state():
    with open('/proc/self/status') as stream:
        status = dict(line.split(':', 1) for line in stream)
    return {key: int(status[key].strip(), 16 if key.startswith('Cap') else 10)
            for key in ('CapEff', 'CapPrm', 'CapInh', 'CapBnd', 'CapAmb',
                        'NoNewPrivs', 'Seccomp')}


def restrict_capabilities():
    """Finish bubblewrap's capability drop without replacing the user mapping.

    Bwrap 0.12.0 only trims bounding capabilities on its userns paths. Keep
    SETPCAP from the existing container solely for this trusted reduction,
    then remove it from every set before nono or any mutable code starts.
    No syscall error is ignored; observations go to the private launch stderr.
    """
    before = capability_state()
    print(json.dumps({'capabilities_before': before}), file=sys.stderr, flush=True)
    setup_mask = CAPABILITY_MASK | (1 << 8)  # CAP_SETPCAP, never payload authority
    if (before['NoNewPrivs'] != 1 or before['Seccomp'] != 2 or
            before['CapEff'] != setup_mask or before['CapPrm'] != setup_mask or
            any(before[key] & ~setup_mask for key in ('CapInh', 'CapAmb')) or
            before['CapBnd'] & CAPABILITY_MASK != CAPABILITY_MASK):
        raise RuntimeError('Unexpected native capability setup: ' + repr(before))
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, *([ctypes.c_ulong] * 4)]
    libc.prctl.restype = ctypes.c_int
    for bit in range(64):
        if before['CapBnd'] & (1 << bit) and not CAPABILITY_MASK & (1 << bit):
            if libc.prctl(24, bit, 0, 0, 0) != 0:  # PR_CAPBSET_DROP
                error = ctypes.get_errno()
                raise OSError(error, 'Native bounding capability drop failed: ' + str(bit))
    # Linux capability ABI v3: header(version, pid), two E/P/I uint32 rows.
    header = (ctypes.c_uint32 * 2)(0x20080522, 0)
    data = (ctypes.c_uint32 * 6)(CAPABILITY_MASK, CAPABILITY_MASK,
                                before['CapInh'] & CAPABILITY_MASK, 0, 0, 0)
    libc.capset.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    libc.capset.restype = ctypes.c_int
    if libc.capset(header, data) != 0:
        error = ctypes.get_errno()
        raise OSError(error, 'Native active capability drop failed')
    # capset also intersects the ambient set with the new P/I sets.
    after = capability_state()
    print(json.dumps({'capabilities_after': after}), file=sys.stderr, flush=True)
    if (after['NoNewPrivs'] != 1 or after['Seccomp'] != 2 or
            any(after[key] != CAPABILITY_MASK for key in ('CapEff', 'CapPrm', 'CapBnd')) or
            any(after[key] & ~CAPABILITY_MASK for key in ('CapInh', 'CapAmb'))):
        raise RuntimeError('Native capability reduction unconfirmed: ' + repr(after))


def socket_filter():
    """Fixed x86_64 cBPF baseline, with only the native libaudit exception.

    Nono 0.77.0's TCP-only baseline also denies socketpair outside AF_UNIX,
    io_uring_setup and alternate syscall ABIs. Keep those denials. Landlock
    separately restricts TCP ports; this filter alone is not confinement.
    No user-supplied instructions or socket exceptions are accepted.
    """
    if sys.platform != 'linux' or platform.machine() != 'x86_64' or sys.byteorder != 'little':
        raise ValueError('Native socket filter requires Linux x86_64 little endian')
    allow, deny = 0x7fff0000, 0x00050001  # SECCOMP_RET_ALLOW / ERRNO(EPERM)
    # (opcode, true skip, false skip, constant). Offsets are seccomp_data:
    # nr=0, arch=4, args[0]=16, args[1]=24, args[2]=32 (low words).
    program = (
        (0x20, 0, 0, 4),             # 0: architecture
        (0x15, 1, 0, 0xc000003e),    # 1: AUDIT_ARCH_X86_64
        (0x06, 0, 0, deny),          # 2: reject compat architectures
        (0x20, 0, 0, 0),             # 3: syscall number
        (0x35, 0, 1, 0x40000000),    # 4: reject x32 and negative numbers
        (0x06, 0, 0, deny),          # 5
        (0x15, 4, 0, 41),            # 6: socket -> 11
        (0x15, 21, 0, 53),           # 7: socketpair -> 29
        (0x15, 0, 1, 425),           # 8: io_uring_setup
        (0x06, 0, 0, deny),          # 9
        (0x06, 0, 0, allow),         # 10: unrelated syscall
        (0x20, 0, 0, 16),            # 11: socket domain
        (0x15, 19, 0, 1),            # 12: AF_UNIX -> 32
        (0x15, 3, 0, 2),             # 13: AF_INET -> 17
        (0x15, 2, 0, 10),            # 14: AF_INET6 -> 17
        (0x15, 8, 0, 16),            # 15: AF_NETLINK -> 24
        (0x06, 0, 0, deny),          # 16: all other families
        (0x20, 0, 0, 24),            # 17: internet type
        (0x54, 0, 0, 0xfff7f7ff),    # 18: remove only NONBLOCK/CLOEXEC
        (0x15, 0, 11, 1),            # 19: SOCK_STREAM, otherwise -> 31
        (0x20, 0, 0, 32),            # 20: internet protocol
        (0x15, 10, 0, 0),            # 21: default TCP -> 32
        (0x15, 9, 0, 6),             # 22: IPPROTO_TCP -> 32
        (0x06, 0, 0, deny),          # 23
        (0x20, 0, 0, 24),            # 24: netlink type
        (0x54, 0, 0, 0xfff7f7ff),    # 25: remove only NONBLOCK/CLOEXEC
        (0x15, 0, 4, 3),             # 26: SOCK_RAW, otherwise -> 31
        (0x20, 0, 0, 32),            # 27: netlink protocol
        (0x15, 3, 2, 9),             # 28: NETLINK_AUDIT -> 32, else -> 31
        (0x20, 0, 0, 16),            # 29: socketpair domain
        (0x15, 1, 0, 1),             # 30: only AF_UNIX -> 32
        (0x06, 0, 0, deny),          # 31
        (0x06, 0, 0, allow),         # 32
    )
    return b''.join(struct.pack('<HBBI', *row) for row in program)


def filter_descriptor():
    """Seal immutable bytes before passing ownership to bubblewrap --seccomp."""
    data = socket_filter()  # Refuse unsupported architecture before opening.
    fd = os.memfd_create('ptw-native-socket-filter', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        remaining = memoryview(data)
        while remaining:
            written = os.write(fd, remaining)
            if written <= 0:
                raise OSError('Incomplete native socket filter write')
            remaining = remaining[written:]
        os.lseek(fd, 0, os.SEEK_SET)
        # Linux UAPI constants: some installed Python builds omit these names.
        # The platform gate above makes their numeric use unambiguous.
        fcntl.fcntl(fd, 1033, 0x000f)  # F_ADD_SEALS: WRITE|GROW|SHRINK|SEAL
        os.set_inheritable(fd, True)
        return fd
    except BaseException:
        os.close(fd)
        raise


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


def landlock_command(spec, directories, *, direct=False):
    """Shared pinned nono argv; resource types must come from pinned inodes.

    This assembles argv only. Namespace placement, native credentials, descriptor
    closure, syscall restrictions and controller admission remain prerequisites.
    """
    validate(spec)
    if not isinstance(directories, (set, frozenset)) or not directories <= set(spec['read'] + spec['write']):
        raise ValueError('Invalid pinned native resource types')
    loader = [TOOLS + '/lib/ld-linux-x86-64.so.2', '--library-path', TOOLS + '/lib']
    # Only the authenticated sudo continuation uses direct exec: its native
    # monitor must retain the command child for terminal job control. Wrap has
    # no supervisor and rejects run-only policy/rollback/audit flags. Its auto
    # backend adds static seccomp to Landlock; external cgroup limits, admission
    # and stopping are still required and no fallback is attempted on rejection.
    args = [*loader, TOOLS + '/bin/nono', 'wrap' if direct else 'run', '--silent']
    if not direct:
        args += ['--sandbox-policy', 'landlock']
    args += ['--block-net', '--allow', '/tmp', '--read', TOOLS]
    if not direct:
        args += ['--no-rollback', '--no-audit']
    args += ['--no-diagnostics']
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
            # Select file/directory flags from the already pinned inode type.
            args += [flag if path in directories else file_flag, path]
    for port in spec['connect_ports']:
        args += ['--allow-connect-port', str(port)]
    return args + ['--', *spec['argv']]


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
    for cap in (*CAPABILITIES, 'CAP_SETPCAP'):
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
                 # Pinned bwrap creates a fresh device tmpfs and devpts instance,
                 # including pts/ptmx and the standard fd links. Never bind the
                 # surrounding device tree or share its terminal namespace.
                 '--proc', '/proc', '--dev', '/dev',
                 '--perms', '1777', '--tmpfs', '/tmp',
                 '--dir', STATE]
        seccomp_fd = filter_descriptor()
        fds.append(seccomp_fd)
        args += ['--chdir', spec['cwd'],
                 '--seccomp', str(seccomp_fd), '--',
                 '/usr/bin/python3', '-I', '-S', TOOLS + '/launcher.py', '--drop-capabilities',
                 *landlock_command(spec, {path for path, fd in zip(
                     (*RUNTIME, TOOLS, *spec['read'], *spec['write']), fds)
                     if path in spec['read'] + spec['write'] and stat.S_ISDIR(os.fstat(fd).st_mode)})]
        return args, fds
    except BaseException:
        for fd in fds:
            os.close(fd)
        raise


def main():
    if len(sys.argv) > 2 and sys.argv[1] == '--drop-capabilities':
        # This stage is already admitted, in the new namespaces and fixed
        # seccomp filter. Reinvocation cannot restore dropped capabilities.
        restrict_capabilities()
        os.execv(sys.argv[2], sys.argv[2:])
        return
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
