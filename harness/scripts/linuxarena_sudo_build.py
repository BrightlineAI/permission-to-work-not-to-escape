"""Source-bound sudo frontend checkpoint and bounded requested-release build.

All distribution patches precede the small execution patch. Retained archives
are read only; derived sources/builds belong only to a fresh private fixture.
This does not install sudo or rebuild/replace its native policy/PAM plugin.
"""
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import struct
import subprocess
import tarfile

from evidence_io import digest, reference, require, save
from ptw import linuxarena_namespace as namespace
import linuxarena_sudo_source as source
import linuxarena_sudo_inputs as inputs

HERE = Path(__file__).resolve().parent


def unpack(data, expected, destination, *, prefix):
    """Create regular files only, after validating the complete pinned archive."""
    require(len(data) <= source.MAX_ARCHIVE and hashlib.sha256(data).hexdigest() == expected,
            'Sudo build archive hash or size mismatch')
    rows, names, total = [], set(), 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as archive:
        for member in archive:
            name = member.name.rstrip('/')
            path = PurePosixPath(name)
            require(name and str(path) == name and not path.is_absolute() and
                    '..' not in path.parts and path.parts[0] == prefix and name not in names,
                    'Unsafe or duplicate sudo build path')
            names.add(name)
            total += max(0, member.size)
            require(len(names) <= 10000 and total <= 64 * 1024 ** 2 and
                    0 <= member.size <= source.MAX_MEMBER and
                    (member.isdir() or member.isfile()) and not member.mode & 0o7000,
                    'Unsupported sudo build member')
            content = None
            if member.isfile():
                with archive.extractfile(member) as stream:
                    content = stream.read(source.MAX_MEMBER + 1)
                require(len(content) == member.size, 'Incomplete sudo build member')
            rows.append((path, member.mode, content))
    require(rows, 'Empty sudo build archive')
    # Reject file/child conflicts before creating anything.
    files = {p for p, _, content in rows if content is not None}
    require(not any(parent in files for p, _, _ in rows for parent in p.parents),
            'Conflicting sudo build member paths')
    destination.mkdir()  # must be fresh, never extract into retained source
    for path, mode, content in rows:
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        if content is None:
            target.mkdir(exist_ok=True)
        else:
            # Preserve executable source scripts at creation; no chmod/chown,
            # tar extraction hooks, links, set-ID bits or package installation.
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode & 0o755)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(content)


def patch_targets(data):
    old, new = [], []
    for line in data.decode('utf-8').splitlines():
        if line.startswith(('--- ', '+++ ')):
            name = line[4:].split()[0]
            if name == '/dev/null' and line.startswith('--- '):
                old.append(None)  # pinned distribution regressions add files
                continue
            path = PurePosixPath(name)
            require(not path.is_absolute() and '..' not in path.parts and
                    len(path.parts) > 1 and str(path) == name,
                    'Unexpected distribution patch target')
            (old if line.startswith('--- ') else new).append('/'.join(path.parts[1:]))
    require(old and len(old) == len(new) and len(new) == len(set(new)) and
            all(a is None or a == b for a, b in zip(old, new)),
            'Distribution patch must modify or add regular targets')
    return [{'path': b, 'create': a is None} for a, b in zip(old, new)]


def replace_once(text, before, after):
    require(text.count(before) == 1, 'Sudo execution patch context changed')
    return text.replace(before, after, 1)


def execution_patch(root):
    """Closed command fork/credential seams; validate every context before writes."""
    path = root / 'src/exec.c'
    text = path.read_text()
    text = replace_once(text, '#include "sudo.h"',
                        '#include "sudo.h"\n#include "linuxarena_sudo_child.h"')
    text = replace_once(text, '    /* Close all fds except those explicitly preserved. */',
        '    /* Private one-use continuation pipe; closed before exec. */\n'
        '    if (ptw_child_barrier_fd() >= 0)\n'
        '\tadd_preserved_fd(&details->preserved_fds, ptw_child_barrier_fd());\n\n'
        '    /* Close all fds except those explicitly preserved. */')
    text = replace_once(text, '    restore_limits();\n',
        '    restore_limits();\n\n'
        '    if (ptw_child_request_pin() || ptw_child_pin()) {\n'
        '\tcstat->type = CMD_ERRNO;\n\tcstat->val = errno;\n\tgoto done;\n    }\n')
    text = replace_once(text, '    /* The caller will run any plugin close functions. */',
        '    ptw_child_cleanup();\n'
        '    /* The caller will run any plugin close functions. */')
    text = replace_once(text, '    unlimit_nproc();\n\n#if defined(HAVE_SETRESUID)',
                        '    unlimit_nproc();\n\n'
                        '    if (ptw_child_before_uid(details->cred.uid, details->cred.euid))\n'
                        '\tgoto done;\n\n#if defined(HAVE_SETRESUID)')
    # Restore/cwd remain native; the post-check executes after both, just before
    # exec_setup returns success. Failure goes through sudo's existing errfd.
    text = replace_once(text, '    ret = true;\n\ndone:\n',
                        '    if (ptw_child_after_uid(details->cred.uid, details->cred.euid) ||\n'
                        '\tptw_child_request_verify(details->envp, details->cred.uid, details->cred.euid))\n'
                        '\tgoto done;\n\n    ret = true;\n\ndone:\n')
    forks = {}
    for name, closure, route in (('exec_nopty.c', 'ec', 0), ('exec_monitor.c', 'mc', 1)):
        fork = root / 'src' / name
        changed = replace_once(fork.read_text(), '#include "sudo.h"',
                               '#include "sudo.h"\n#include "linuxarena_sudo_child.h"')
        changed = replace_once(changed, f'    {closure}.cmnd_pid = sudo_debug_fork();',
            f'    {closure}.cmnd_pid = ptw_child_fork(sudo_debug_fork_v1, {route});')
        if route == 1:
            # Native foreground ownership must precede the child's exec_setup
            # checkpoint. Keep SIGCHLD blocked until its private stop is consumed;
            # native event dispatch must never mistake it for a terminal stop.
            unmask = ('    /* Restore signal mask now that signal handlers are setup. */\n'
                      '    sigprocmask(SIG_SETMASK, oset, NULL);\n\n')
            changed = replace_once(changed, unmask, '')
            start = '    /* Make the command the foreground process for the pty follower. */\n'
            end = '\n    /*\n     * Wait for errno on pipe, signal on backchannel or for SIGCHLD.\n'
            # Match the entire pinned native block, not a loose insertion marker.
            expected = (start +
                '    if (foreground && !ISSET(details->flags, CD_EXEC_BG)) {\n'
                '\tif (tcsetpgrp(io_fds[SFD_FOLLOWER], mc.cmnd_pgrp) == -1) {\n'
                '\t    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,\n'
                '\t\t"%s: unable to set foreground pgrp to %d (command)",\n'
                '\t\t__func__, (int)mc.cmnd_pgrp);\n\t}\n    }\n')
            changed = replace_once(changed, expected + end, expected + '\n'
                '    ptw_job_trace(10, mc.cmnd_pid, mc.cmnd_pgrp, 0, 0, 0, io_fds[SFD_FOLLOWER]);\n'
                '    if (ptw_child_continue(mc.cmnd_pid)) {\n'
                '\tmc.cmnd_pid = -1; /* Failed continuation reaped the owned child. */\n'
                '\tgoto bad;\n    }\n\n' + unmask + end)
            changed = replace_once(changed, '    if (WIFCONTINUED(status)) {',
                '    ptw_job_trace(11, mc->cmnd_pid, mc->cmnd_pgrp, status, 0, 0, io_fds[SFD_FOLLOWER]);\n'
                '    if (WIFCONTINUED(status)) {')
            changed = replace_once(changed, '    debug_decl(mon_handle_sigchld, SUDO_DEBUG_EXEC);',
                '    debug_decl(mon_handle_sigchld, SUDO_DEBUG_EXEC);\n'
                '    ptw_job_wait_observe(mc->cmnd_pid, io_fds[SFD_FOLLOWER]);')
            changed = replace_once(changed,
                '\tpid = waitpid(mc->cmnd_pid, &status, WUNTRACED|WCONTINUED|WNOHANG);',
                '\tpid = waitpid(mc->cmnd_pid, &status, WUNTRACED|WCONTINUED|WNOHANG);\n'
                '\tptw_job_trace(28, mc->cmnd_pid, mc->cmnd_pgrp, pid > 0 ? status : -1, '
                'pid, pid == -1 ? errno : 0, io_fds[SFD_FOLLOWER]);')
            changed = replace_once(changed, '    debug_decl(mon_signal_cb, SUDO_DEBUG_EXEC);',
                '    debug_decl(mon_signal_cb, SUDO_DEBUG_EXEC);\n'
                '    ptw_job_trace(25, mc->cmnd_pid, mc->cmnd_pgrp, signo, what, 0, io_fds[SFD_FOLLOWER]);')
            changed = replace_once(changed, '\t\tsend_status(mc->backchannel, mc->cstat);',
                '\t\tptw_job_trace(12, mc->cmnd_pid, mc->cmnd_pgrp, status, 0, 0, io_fds[SFD_FOLLOWER]);\n'
                '\t\tsend_status(mc->backchannel, mc->cstat);')
            changed = replace_once(changed, '\tn = send(fd, cstat, sizeof(*cstat), 0);',
                '\tn = send(fd, cstat, sizeof(*cstat), 0);\n'
                '\tptw_job_trace(13, 0, cstat->type, cstat->val, n, n == -1 ? errno : 0, io_fds[SFD_FOLLOWER]);')
            # These are the two distinct native foreground/background branches.
            for suffix, phase in (('SIGCONT_FG', 14), ('SIGCONT_BG', 16)):
                start = changed.index('    case ' + suffix + ':')
                finish = changed.index('\n    case ', start + 1)
                branch = changed[start:finish]
                revised = replace_once(branch, 'killpg(mc->cmnd_pid, SIGCONT);',
                    f'ptw_job_killpg({phase}, mc->cmnd_pid, SIGCONT, io_fds[SFD_FOLLOWER]);')
                changed = replace_once(changed, branch, revised)
            changed = replace_once(changed, '\tkillpg(mc->cmnd_pid, signo);',
                '\tptw_job_killpg(18, mc->cmnd_pid, signo, io_fds[SFD_FOLLOWER]);')
        forks[fork] = changed
    pty = root / 'src/exec_pty.c'
    changed = replace_once(pty.read_text(), '#include "sudo.h"',
                          '#include "sudo.h"\n#include "linuxarena_sudo_child.h"')
    changed = replace_once(changed, '    ec.monitor_pid = sudo_debug_fork();',
        '    ec.monitor_pid = sudo_debug_fork();\n'
        '    if (ec.monitor_pid != 0)\n\tptw_child_cleanup();')
    # The monitor normally _exits (kernel closure). Explicitly close its copy
    # on the error-return path as well, before the native status report.
    changed = replace_once(changed, '\tcstat->type = CMD_ERRNO;\n\tcstat->val = errno;',
        '\tptw_child_cleanup();\n\tcstat->type = CMD_ERRNO;\n\tcstat->val = errno;')
    changed = replace_once(changed, '\tcase CMD_WSTATUS:\n',
        '\tcase CMD_WSTATUS:\n'
        '\t    ptw_job_trace(20, ec->cmnd_pid, ec->ppgrp, cstat.val, 0, 0, io_fds[SFD_USERTTY]);\n')
    changed = replace_once(changed, '    debug_decl(suspend_sudo, SUDO_DEBUG_EXEC);',
        '    debug_decl(suspend_sudo, SUDO_DEBUG_EXEC);\n'
        '    ptw_job_trace(21, ec->monitor_pid, ec->ppgrp, signo, 0, 0, io_fds[SFD_USERTTY]);')
    changed = replace_once(changed, 'killpg(ec->ppgrp, signo)',
        'ptw_job_killpg(22, ec->ppgrp, signo, io_fds[SFD_USERTTY])')
    changed = replace_once(changed, '\t\tschedule_signal(ec, signo);',
        '\t\tptw_job_trace(24, ec->monitor_pid, ec->ppgrp, signo, 0, 0, io_fds[SFD_USERTTY]);\n'
        '\t\tschedule_signal(ec, signo);')
    forks[pty] = changed
    make = root / 'src/Makefile.in'
    make_text = replace_once(make.read_text(), 'OBJS = conversation.o',
                            'OBJS = linuxarena_sudo_child.o conversation.o')
    # Like the native objects, the new object needs an explicit source rule:
    # configure builds outside srcdir and the suffix rule cannot find this C file.
    # Preserve the native compile/hardening flags and track both private headers.
    marker = '# Autogenerated dependencies, do not modify\n'
    make_text = replace_once(make_text, marker,
        'linuxarena_sudo_child.o: $(srcdir)/linuxarena_sudo_child.c '
        '$(srcdir)/linuxarena_sudo_child.h $(srcdir)/linuxarena_sudo_filter.h '
        '$(srcdir)/linuxarena_sudo_placement.h\n'
        '\t$(CC) -c $(CPPFLAGS) $(CFLAGS) $(ASAN_CFLAGS) $(PIE_CFLAGS) '
        '$(SSP_CFLAGS) $(srcdir)/linuxarena_sudo_child.c\n\n'
        'exec.o exec_nopty.o exec_monitor.o exec_pty.o: $(srcdir)/linuxarena_sudo_child.h\n\n' + marker)
    # Reject drift in every file before changing any of them.
    path.write_text(text)
    make.write_text(make_text)
    for fork, changed in forks.items():
        fork.write_text(changed)


def filter_header(*, placement=False, controller=False, release=False):
    require(not controller or placement, 'Controller checkpoint requires namespace placement')
    require(not release or controller, 'Requested release requires controller admission')
    data = namespace.socket_filter()
    rows = '\n'.join('    {0x%x, %d, %d, 0x%x},' % row
                     for row in struct.iter_unpack('<HBBI', data))
    return (('#define PTW_REQUEST_RELEASE 1\n' if release else '') +
            ('#define PTW_NAMESPACE_CHECKPOINT 1\n' if placement else '') +
            ('#define PTW_CONTROLLER_CHECKPOINT 1\n' if controller else '') +
            '/* Generated from linuxarena_namespace.socket_filter(). */\n'
            '#define PTW_PAYLOAD_MASK UINT64_C(0x%x)\n' % namespace.CAPABILITY_MASK +
            '#define PTW_FILTER_SHA256 "%s"\n' % hashlib.sha256(data).hexdigest() +
            'static struct sock_filter ptw_socket_filter[] = {\n' + rows + '\n};\n')


def landlock_header(*, placement=False, file_scope=None, release=False):
    # Fixed synthetic resources only. Never compile agent request text into C.
    require(placement or file_scope is None, 'File authority requires namespace placement')
    require(not release or (placement and file_scope is not None),
            'Direct release requires placed controller file authority')
    if not placement:
        return '/* No Landlock continuation in the standalone child checkpoint. */\n'
    spec = {'read': [], 'write': ['/probe'], 'cwd': '/probe', 'connect_ports': [32001],
            'argv': [namespace.TOOLS + '/bin/closed', '--confined']}
    directories = {'/probe'}
    if file_scope is not None:
        require(placement and file_scope['spec']['argv'] == spec['argv'] and
                file_scope['spec']['connect_ports'] == spec['connect_ports'],
                'Only the fixed closed checkpoint may use this file binding')
        spec = file_scope['spec']
        directories = {entry['path'] for entry in file_scope['resources'].values()
                       if entry['kind'] == 'tree'}
    argv = namespace.landlock_command(spec, directories, direct=release)
    return (('#define PTW_SCOPE_HELPER 1\n' if file_scope is not None else '') +
            '/* Generated from the shared pinned nono invocation. */\n'
            '#define PTW_LANDLOCK_HELPER 1\n'
            '#define PTW_LANDLOCK_STATE ' + json.dumps(namespace.STATE) + '\n'
            'static const char ptw_landlock_cwd[] = ' + json.dumps(spec['cwd']) + ';\n'
            'static char *const ptw_landlock_argv[] = {\n' +
            ''.join('    ' + json.dumps(arg) + ',\n' for arg in argv) + '    NULL\n};\n')


def stage(source_receipt, out, bundle, *, placement=False, controller=False, file_scope=None, release=False):
    require(controller == (file_scope is not None), 'Controller build requires frozen file authority')
    original, debian = list(source.ARCHIVES)
    unpack((source_receipt / original).read_bytes(), source.ARCHIVES[original],
           bundle / 'upstream', prefix='sudo-1.9.9')
    unpack((source_receipt / debian).read_bytes(), source.ARCHIVES[debian],
           bundle / 'distribution', prefix='debian')
    root = bundle / 'upstream/sudo-1.9.9'
    patchdir = bundle / 'distribution/debian/patches'
    records = []
    for entry in (patchdir / 'series').read_text().splitlines():
        entry = entry.split('#', 1)[0].strip()
        if not entry:
            continue
        require(re.fullmatch(r'[A-Za-z0-9_.+-]+', entry) and
                entry not in {r['name'] for r in records}, 'Invalid distribution patch series')
        data = (patchdir / entry).read_bytes()
        targets = patch_targets(data)
        require(all(not (root / p['path']).is_symlink() and
                    ((not (root / p['path']).exists()) if p['create'] else
                     (root / p['path']).is_file()) for p in targets),
                'Distribution patch target missing')
        # Archive hashes fix the instructions. No shell or distro packaging hooks.
        command = ['patch', '--batch', '--forward', '--fuzz=0', '--no-backup-if-mismatch', '-p1']
        proc = subprocess.run(command, input=data, cwd=root, capture_output=True, timeout=30,
                              env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        log = out / ('distribution-patch-%02d.log' % len(records))
        log.write_bytes(proc.stdout + proc.stderr)
        records.append({'name': entry, 'sha256': hashlib.sha256(data).hexdigest(),
                        'targets': targets, 'argv': command, 'returncode': proc.returncode,
                        'log': reference(out, log)})
        save(out / 'distribution-patches.json', records)
        require(proc.returncode == 0 and not re.search(rb'with fuzz \d', proc.stdout + proc.stderr),
                'Distribution source patch failed')
    before = {p: digest(root / p) for p in
              ('src/exec.c', 'src/exec_nopty.c', 'src/exec_monitor.c', 'src/exec_pty.c', 'src/Makefile.in')}
    execution_patch(root)
    for name in ('linuxarena_sudo_child.c', 'linuxarena_sudo_child.h', 'linuxarena_sudo_placement.h'):
        (root / 'src' / name).write_bytes((HERE / name).read_bytes())
    (root / 'src/linuxarena_sudo_filter.h').write_text(
        filter_header(placement=placement, controller=controller, release=release))
    (root / 'src/linuxarena_sudo_landlock.h').write_text(
        landlock_header(placement=placement, file_scope=file_scope, release=release))
    checker = bundle / 'linuxarena_sudo_inputs.py'
    checker.write_bytes(Path(inputs.__file__).read_bytes())
    save(out / 'checkpoint-source.json', {
        'schema': 1, 'scope': ('closed authenticated child namespace placement' if placement else
                              'closed command-child capability/filter checkpoint only'),
        'archives': source.ARCHIVES, 'before_adapter_sha256': before,
        'driver_sha256': digest(__file__), 'namespace_sha256': digest(namespace.__file__),
        'file_scope': file_scope, 'requested_release': release,
        'build_input_checker': reference(out, checker),
        'filter_sha256': hashlib.sha256(namespace.socket_filter()).hexdigest(),
        'sources': {str(p.relative_to(root)): reference(out, p)
                    for p in sorted(root.rglob('*')) if p.is_file()},
        'distribution': {str(p.relative_to(bundle / 'distribution')): reference(out, p)
                         for p in sorted((bundle / 'distribution').rglob('*')) if p.is_file()}})


# Runs only in a fresh, offline private-daemon container. The native plugin,
# PAM stack and account/session handling stay installed and unmodified. Reuse
# the pinned distribution's configure arguments, and refuse absent build
# dependencies instead of disabling a configured security feature.
PREFLIGHT = r'''import hashlib, json, os, pathlib, runpy, subprocess
root = pathlib.Path('/ptw-sudo-gate/upstream/sudo-1.9.9')
out = pathlib.Path('/ptw-sudo-gate')
inputs = runpy.run_path(str(out / 'linuxarena_sudo_inputs.py'))
env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'LANG': 'C', 'HOME': '/tmp'}
version = subprocess.check_output(['/usr/bin/sudo', '-V'], env=env, text=True)
(out / 'native-version.txt').write_text(version)
args = inputs['configure_arguments']((out / 'distribution/debian/rules').read_bytes(), version)
binding = {'configure_argv': ['/bin/sh', str(root / 'configure'), *args],
    'rules_sha256': inputs['RULES_SHA256']}
(out / 'checkpoint-build-inputs.json').write_text(json.dumps(binding, indent=2))
staged = pathlib.Path('/ptw-sudo-inputs')
report = inputs['prerequisites'](out, staged=staged if staged.exists() else None)
env.update(report.get('build_environment', {}))
'''

BUILD = r'''
def run(argv, cwd, name):
    with (out / (name + '.log')).open('xb') as log:
        subprocess.run(argv, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
build = out / 'frontend-build'
build.mkdir()
run(binding['configure_argv'], build, 'configure')
for name in ('lib/util', 'lib/protobuf-c', 'src'):
    run(['/usr/bin/make', '-j1', '-C', name, 'sudo' if name == 'src' else 'all'],
        build, 'make-' + name.replace('/', '-'))
binary = build / 'src/.libs/sudo'
assert binary.is_file() and binary.read_bytes().startswith(b'\x7fELF')
with os.fdopen(os.open(out / 'checkpoint-sudo', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o755), 'wb') as f:
    f.write(binary.read_bytes())
# No chmod, set-ID bits or install into an image/host runtime path.
base = ['/usr/bin/cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-static',
        '-I' + str(root / 'src'), '-I/ptw-sudo-gate']
release = '#define PTW_REQUEST_RELEASE 1' in (root / 'src/linuxarena_sudo_filter.h').read_text()
if release:
    base += ['-DPTW_REQUEST_RELEASE=1']
    run(['/usr/bin/cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
        '-DPTW_REQUEST_RELEASE=1', '-I/ptw-sudo-gate', '-fPIC', '-shared',
        '-Wl,-z,relro,-z,now', '/ptw-sudo-gate/linuxarena_sudo_gate.c',
        '-ldl', '-o', '/ptw-sudo-gate/policy.so'], build, 'make-release-policy')
run(base + ['-DPTW_CLOSED_HELPER', '-DPTW_CHECKPOINT_HELPER',
    '/ptw-sudo-gate/linuxarena_sudo_gate.c', str(root / 'src/linuxarena_sudo_child.c'),
    '-o', '/ptw-sudo-gate/closed'], build, 'make-checkpoint-helper')
headers = subprocess.check_output(['/usr/bin/readelf', '-l', '/ptw-sudo-gate/closed'],
    env=env, text=True)
assert 'INTERP' not in headers
print(json.dumps({'helper_static': True, 'frontend_sha256':
    hashlib.sha256(binary.read_bytes()).hexdigest(), 'native_configure_preserved': True}))
'''
