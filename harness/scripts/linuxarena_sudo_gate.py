"""Native delegation fixtures; no benchmark task or model calls.

Only a fresh fixture's sudo.conf selects the plugin. Native sudoers/PAM and the
image account configuration remain unchanged. Default closed endpoints return
125. The separately compiled release fixture requests generic synthetic work;
neither fixture is an honest agent trajectory or task completion.
"""
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import time

from evidence_io import digest, load, reference, require, save
from linuxarena_preflight import (Commands, child_environment, daemon_environment,
                                 private_output, verify_daemon)
import linuxarena_sudo_source as sudo_source
from terminal_driver import Terminal
import terminal_driver

NATIVE_FILES = {
    '/usr/bin/sudo': '686287d80efa1400561301a1c9fc1d35e03b74adde29bd94e5178a36e7b0a6c8',
    '/usr/libexec/sudo/sudoers.so': '8c1e6c884c24ef28f6a70e026a988326a2d0c4dc0fc7580c0e10337c0abc35ba',
}
SOURCE = Path(__file__).with_suffix('.c')
ROOT = '/ptw-sudo-gate'
CONFIG = ('Plugin ptw_sudo_policy /ptw-sudo-gate/policy.so\n'
          'Plugin sudoers_io /usr/libexec/sudo/sudoers.so\n'
          'Plugin sudoers_audit /usr/libexec/sudo/sudoers.so\n')


def stage(source_receipt, out):
    """Reverify retained archives; do not trust a receipt's success booleans."""
    source_receipt = Path(source_receipt)
    require(source_receipt.is_absolute() and source_receipt.resolve() == source_receipt,
            'Expected canonical sudo source receipt')
    installed = load(source_receipt / 'installed.json')
    require(installed == {'version': sudo_source.VERSION, 'files_sha256': NATIVE_FILES},
            'Installed sudo differs from reviewed binary identities')
    originals = {}
    for name, expected in sudo_source.ARCHIVES.items():
        path = source_receipt / name
        require(not path.is_symlink() and path.is_file(), 'Missing regular sudo archive')
        originals.update(sudo_source.source_members(path.read_bytes(), expected,
                                                   debian='.debian.' in name))
    bundle = out / 'bundle'
    bundle.mkdir()
    (bundle / 'sudo_plugin.h').write_bytes(originals['sudo-1.9.9/include/sudo_plugin.h'])
    shutil.copyfile(SOURCE, bundle / SOURCE.name)
    require(digest(SOURCE) == digest(bundle / SOURCE.name), 'Gate source changed during staging')
    request_source = SOURCE.with_name('linuxarena_sudo_request.h')
    shutil.copyfile(request_source, bundle / request_source.name)
    require(digest(request_source) == digest(bundle / request_source.name),
            'Native request source changed during staging')
    release_source = SOURCE.with_name('linuxarena_sudo_release.h')
    shutil.copyfile(release_source, bundle / release_source.name)
    require(digest(release_source) == digest(bundle / release_source.name),
            'Native release source changed during staging')
    (bundle / 'sudo.conf').write_text(CONFIG)
    save(out / 'source-binding.json', {
        'source_receipt': str(source_receipt), 'native_files': NATIVE_FILES,
        'archives': sudo_source.ARCHIVES,
        'inputs': {p.name: reference(out, p) for p in bundle.iterdir()},
        'scope': 'closed delegation prototype, no mutable release'})
    return bundle


# Build only this reviewed C source against the verified header with the image's
# installed compiler. No package install, network, project hooks or build system.
BUILD = '''import hashlib, json, subprocess
base = ['/usr/bin/cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-I/ptw-sudo-gate']
subprocess.run(base + ['-fPIC', '-shared', '-Wl,-z,relro,-z,now',
    '/ptw-sudo-gate/linuxarena_sudo_gate.c', '-ldl', '-o', '/ptw-sudo-gate/policy.so'], check=True)
subprocess.run(base + ['-DPTW_CLOSED_HELPER', '-static',
    '/ptw-sudo-gate/linuxarena_sudo_gate.c', '-o', '/ptw-sudo-gate/closed'], check=True)
headers = subprocess.check_output(['/usr/bin/readelf', '-l', '/ptw-sudo-gate/closed'], text=True)
assert 'INTERP' not in headers and 'Requesting program interpreter' not in headers
print(json.dumps({'compiler': subprocess.check_output(['/usr/bin/cc', '--version'], text=True),
    'compiler_sha256': hashlib.sha256(open('/usr/bin/cc', 'rb').read()).hexdigest(),
    'helper_static': True}))
'''

REQUESTS = (
    ('root_to_dev', '0', ['-n', '-u', 'dev', '--', '/usr/bin/touch', '/tmp/original-effect']),
    ('root_to_root', '0', ['-n', '-u', 'root', '--', '/usr/bin/touch', '/tmp/original-effect']),
    ('native_denial', '1001', ['-n', '-u', 'root', '--', '/usr/bin/touch', '/tmp/original-effect']),
    ('invalid_target', '0', ['-n', '-u', '#4294967295', '--', '/usr/bin/touch', '/tmp/original-effect']),
    ('unsupported_edit', '0', ['-n', '-e', '/tmp/original-effect']),
)

# Generic useful/forbidden effects, never benchmark task content or a solution.
RELEASE_PAYLOAD = r'''set -eu
test "$PWD" = /probe/work
test "$1" = $'spaces $() "\n'
test "$2" = ''
test "$LC_ALL" = C
test "$SUDO_UID" = 0
test "$SUDO_USER" = root
test "$(/usr/bin/id -u)" = "$UID"
test "$(/usr/bin/id -g)" = "$UID"
test "$(/usr/bin/id -G)" = "$UID"
test "$(cat /probe/work/canary)" = 'synthetic scope control'
if cat /probe/other/canary 2>/dev/null; then exit 90; fi
if cat /probe-denied/canary 2>/dev/null; then exit 91; fi
for path in /private /observer /ptw-sudo-gate /etc/shadow; do test ! -e "$path"; done
tty=0; if test -t 0; then tty=1; fi
if test "$tty" = 1; then
    /usr/bin/python3 -I -S -c 'import os; assert os.tcgetpgrp(0) == os.getpgrp()'
fi
printf 'PTW_REQUEST_OUTPUT input-ready\n'
IFS= read -r line
test "$line" = 'literal input $() " spaces'
printf 'PTW_REQUEST_OUTPUT input-accepted\n'
if test "$tty" = 1; then
    interrupted=0
    trap 'interrupted=1' INT
    printf 'PTW_REQUEST_OUTPUT interrupt-ready\n'
    while test "$interrupted" = 0; do IFS= read -r -t 1 ignored || :; done
    trap - INT
    printf '\nPTW_REQUEST_OUTPUT interrupted\n'
fi
printf 'PTW_REQUEST_OUTPUT eof-ready\n'
if IFS= read -r ignored; then exit 92; fi
printf 'PTW_REQUEST_OUTPUT eof\n'
if test "$tty" = 1; then
    # Stop only our foreground job. The trusted wrapper observes native sudo's
    # propagated stop and resumes that exact child; no payload PID is trusted.
    /usr/bin/python3 -I -S -c 'import os; p=os.getppid(); print("PTW_JOB_PAYLOAD pid=%d ppid=%d pgid=%d sid=%d fg=%d" % (os.getpid(), p, os.getpgid(p), os.getsid(p), os.tcgetpgrp(0)), flush=True)'
    kill -STOP 0
    printf 'PTW_REQUEST_OUTPUT continued\n'
fi
printf 'native requested work\n' > "/tmp/requested-$UID-$tty"
printf 'PTW_REQUEST_OUTPUT uid=%s tty=%s\n' "$UID" "$tty"
exit 37
'''


def validate_release(name, record, placement, *, terminal=False):
    require(name in ('root_to_root', 'root_to_dev'), 'Unknown requested release case')
    uid = 0 if name == 'root_to_root' else 1000
    require(record['returncode'] == 37 and record['original_effect'] is False and
            record['stdout'] == release_output(uid, terminal=terminal),
            'Native requested work, terminal or exit status failed')
    lines = record['stderr'].splitlines()
    require(lines.count('PTW_REQUEST_RELEASE prepared=1') == 1 and
            lines.count('PTW_REQUEST_RELEASE confined=1') == 1 and
            lines.index('PTW_CHILD_CONTINUATION checked=1 transport_closed=1') <
            lines.index('PTW_REQUEST_RELEASE prepared=1') <
            lines.index('PTW_CHILD_LANDLOCK after=EACCES') <
            lines.index('PTW_REQUEST_RELEASE confined=1'), 'Requested release ordering failed')
    # Reuse the complete physical checkpoint contract with only its independent
    # native exit status changed. No checkpoint or syscall assertion is removed.
    require(lines.count('PTW_SUDO_STAGE close=9472 error=0') == 1,
            'Requested execution lost native session cleanup or exit status')
    validate_checkpoint(name, record, terminal=terminal, placement=placement,
                        controller=True, exit_status=37)
    validate_release_identity(name, record, placement, terminal=terminal)
    require(not any(line.startswith(('PTW_CHILD_REJECT ', 'PTW_SUDO_REJECT ')) for line in lines),
            'Requested release contains a boundary rejection')


def validate_release_identity(name, record, placement, *, terminal):
    """Require direct exec, using immutable helper observations in one PID namespace."""
    _, confined = confined_effect(name, record, placement)
    rows = re.findall(r'^PTW_FORK stage=exec route=-1 pid=(\d+) ppid=(\d+) child=0 '
                      r'mnt=(\d+) pidns=(\d+) userns=(\d+)$', record['stderr'], re.M)
    require(len(rows) == 1 and int(rows[0][0]) == confined and
            tuple(map(int, rows[0][2:])) == tuple(placement[k] for k in ('mnt', 'pid', 'user')),
            'Requested release replaced the native command child')
    jobs = re.findall(r'^PTW_JOB phase=30 pid=(\d+) ppid=(\d+) pgid=(\d+) sid=(-?\d+) '
                      r'fg=(-?\d+) subject=(\d+) group=(\d+) value=0 result=0 error=0$',
                      record['stderr'], re.M)
    require(len(jobs) == 1, 'Missing or duplicate requested execution job identity')
    pid, parent, group, session, foreground, subject, reported_group = map(int, jobs[0])
    require(pid == subject == confined and parent == int(rows[0][1]) and
            group == reported_group and group > 0 and
            (not terminal or foreground == group),
            'Requested execution lost native job identity or foreground ownership')


def release_output(uid, *, terminal):
    rows = ['input-ready', 'input-accepted']
    if terminal:
        rows += ['interrupt-ready', 'interrupted']
    rows += ['eof-ready', 'eof']
    if terminal:
        rows += ['stopped=19', 'continued']
    rows += [f'uid={uid} tty={int(terminal)}']
    return ''.join('PTW_REQUEST_OUTPUT ' + row + '\n' for row in rows)


# Only the release fixture uses interactive input. The closed/denied cases
# retain their original DEVNULL and terminal wrappers and cannot accept input.
RELEASE_INPUT = 'literal input $() " spaces\n'
# The container observer must report its own failure before host PTY cleanup.
RELEASE_INNER_SECONDS = 15
RELEASE_OUTER_SECONDS = 20

INVOKE_RELEASE_TERMINAL = '''import json, os, signal, sys, time
args = json.loads(sys.argv[1])
assert all(os.isatty(fd) for fd in (0, 1, 2))
os.chdir('/probe/work')
canary = os.open('/tmp', os.O_RDONLY | os.O_DIRECTORY)
foreground = os.tcgetpgrp(0)
child = os.fork()
if child == 0:
    os.setpgid(0, 0)
    # Wait for terminal ownership before native sudo can read it. Its native
    # suspend path stops the calling process group, so the observer must stay
    # outside that group just as an interactive shell would.
    os.kill(os.getpid(), signal.SIGSTOP)
    os.set_inheritable(canary, True)
    os.execve('/ptw-sudo-gate/checkpoint-sudo', ['checkpoint-sudo', *args],
        {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
    os._exit(127)
os.close(canary)
signal.signal(signal.SIGINT, signal.SIG_IGN)
signal.signal(signal.SIGTTOU, signal.SIG_IGN)
deadline, stops, started, returncode = time.monotonic() + INNER_SECONDS, 0, False, None
records, last_status = 0, -1
def trace(phase, status=-1, result=0, error=0):
    global records
    if records >= 24:
        return
    records += 1
    try:
        group = os.getpgid(child)
    except OSError:
        group = -1
    try:
        fg = os.tcgetpgrp(0)
    except OSError:
        fg = -1
    try:
        print('PTW_JOB_WRAPPER ' + json.dumps(dict(phase=phase, pid=os.getpid(),
            ppid=os.getppid(), pgid=os.getpgrp(), sid=os.getsid(0), fg=fg,
            child=child, child_pgid=group, status=status, result=result, error=error)), flush=True)
    except OSError:
        pass  # A lost diagnostic sink must not prevent owned-child cleanup.
def resume():
    trace(5, last_status)
    try:
        os.kill(child, signal.SIGCONT)
    except OSError as exc:
        trace(6, last_status, -1, exc.errno)
        raise
    trace(6, last_status)
try:
    trace(1)
    while True:
        pid, status = os.waitpid(child, os.WNOHANG | os.WUNTRACED)
        if pid:
            last_status = status
            trace(2, status, pid)
            if os.WIFSTOPPED(status):
                assert os.WSTOPSIG(status) == signal.SIGSTOP and stops == 0
                if not started:
                    assert os.getpgid(child) == child
                    os.tcsetpgrp(0, child)
                    trace(3, status)
                    started = True
                else:
                    stops += 1
                    print('PTW_REQUEST_OUTPUT stopped=19', flush=True)
                resume()
            else:
                returncode = os.waitstatus_to_exitcode(status)
                break
        if time.monotonic() >= deadline:
            try:
                observation = os.waitid(os.P_PID, child,
                    os.WEXITED | os.WSTOPPED | os.WCONTINUED | os.WNOHANG | os.WNOWAIT)
                trace(94, observation.si_status if observation else -1,
                    observation.si_pid if observation else 0,
                    observation.si_code if observation else 0)
            except OSError as exc:
                trace(94, -1, -1, exc.errno)
            trace(91, last_status)
            raise TimeoutError('Requested terminal work timed out')
        time.sleep(.01)
    assert stops == 1
    os.tcsetpgrp(0, foreground)
    trace(7, last_status)
    print('PTW_TERMINAL_RESULT ' + json.dumps({'returncode': returncode,
        'original_effect': os.path.lexists('/tmp/original-effect')}), flush=True)
except BaseException:
    trace(90, last_status)
    raise
finally:
    if returncode is None:
        trace(92, last_status)
        os.kill(child, signal.SIGKILL)
        waited, status = os.waitpid(child, 0)
        trace(93, status, waited)
    os.tcsetpgrp(0, foreground)
'''.replace('INNER_SECONDS', str(RELEASE_INNER_SECONDS))

# No requested command may execute, including approved touch and sudoedit. Only
# the immutable closed helper can run. Test output is fixed numeric metadata.
INVOKE = '''import json, os, subprocess, sys
args = json.loads(sys.argv[1])
canary = os.open('/tmp', os.O_RDONLY | os.O_DIRECTORY)
result = subprocess.run(['/usr/bin/sudo', *args], stdin=subprocess.DEVNULL,
    capture_output=True, close_fds=True, pass_fds=(canary,), timeout=5,
    env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
os.close(canary)
print(json.dumps({'returncode': result.returncode,
    'stdout': result.stdout.decode('utf-8', 'replace'),
    'stderr': result.stderr.decode('utf-8', 'replace'),
    'original_effect': os.path.lexists('/tmp/original-effect')}))
'''


# Inherit a real controlling terminal from docker exec -it. Record sudo's own
# return code (including signal death), not the Docker client's exit convention.
INVOKE_TERMINAL = '''import json, os, subprocess, sys
args = json.loads(sys.argv[1])
assert all(os.isatty(fd) for fd in (0, 1, 2))
canary = os.open('/tmp', os.O_RDONLY | os.O_DIRECTORY)
result = subprocess.run(['/usr/bin/sudo', *args], close_fds=True, pass_fds=(canary,), timeout=5,
    env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
os.close(canary)
print('PTW_TERMINAL_RESULT ' + json.dumps({'returncode': result.returncode,
    'original_effect': os.path.lexists('/tmp/original-effect')}), flush=True)
'''


def terminal_observation(transcript):
    """Decode a bounded raw transcript without dropping unknown terminal output."""
    require(isinstance(transcript, str) and len(transcript) <= 32768,
            'Invalid closed gate terminal transcript')
    lines = transcript.replace('\r\n', '\n').splitlines(keepends=True)
    marker = 'PTW_TERMINAL_RESULT '
    require(lines and lines[-1].startswith(marker) and
            sum(line.startswith(marker) for line in lines) == 1,
            'Missing or repeated terminal result')
    result = json.loads(lines.pop()[len(marker):])
    require(isinstance(result, dict) and set(result) == {'returncode', 'original_effect'},
            'Invalid terminal result')
    stdout, stderr = [], []
    for line in lines:
        (stdout if line.startswith(('PTW_CLOSED_GATE ', 'PTW_CLOSED_TERMINAL ', 'PTW_REQUEST_OUTPUT '))
         else stderr).append(line)
    return dict(result, stdout=''.join(stdout), stderr=''.join(stderr))


def probe_terminal(command, cid, user, args, folder, *, checkpoint=False, release=False,
                   observe=None):
    invoke = (INVOKE_TERMINAL.replace('/usr/bin/sudo', ROOT + '/checkpoint-sudo')
              if checkpoint else INVOKE_TERMINAL)
    if release:
        require(checkpoint, 'Interactive release requires the checkpoint frontend')
        invoke = INVOKE_RELEASE_TERMINAL
    terminal = Terminal(['docker', 'exec', '-it', '--user', user, cid,
        '/usr/bin/python3', '-I', '-S', '-c', invoke, json.dumps(args)],
        folder, env=command.env, cwd=command.out, replace_env=True)
    deadline = time.monotonic() + RELEASE_OUTER_SECONDS
    observations = set()
    try:
        if release:
            for marker, data in (('input-ready', RELEASE_INPUT.encode()),
                                 ('interrupt-ready', b'\x03'), ('eof-ready', b'\x04')):
                terminal.wait(lambda: len(terminal.text) <= 32768 and
                    'PTW_REQUEST_OUTPUT ' + marker in terminal.text,
                    timeout=max(0, deadline - time.monotonic()),
                    label='requested terminal ' + marker)
                terminal.inputs.append({'seconds': round(time.monotonic() - terminal.started, 3),
                                        'hex': data.hex(), 'mode': 'native-input'})
                terminal._save_inputs()
                require(os.write(terminal.fd, data) == len(data), 'Short native terminal input write')
        def finished():
            require(len(terminal.text) <= 32768, 'Closed gate terminal output exceeds bound')
            if release and observe is not None and not terminal.exited:
                # Two bounded read-only snapshots, before the inner cleanup.
                for phase, ready in ((1, 'PTW_JOB_PAYLOAD ' in terminal.text),
                                     (2, time.monotonic() >= deadline - RELEASE_OUTER_SECONDS + 12)):
                    if ready and phase not in observations:
                        observations.add(phase)
                        observe(folder / ('process-state-%d.json' % phase))
            return terminal.exited
        terminal.wait(finished, timeout=max(0, deadline - time.monotonic()) if release else 10,
                      label='sudo terminal exit')
    finally:
        code = terminal.close(graceful=False)
    require(code == 0, 'Closed gate terminal wrapper failed; retain original transcript')
    return terminal_observation((folder / 'terminal.txt').read_text())


def validate_observation(name, record, *, terminal=False):
    require(name in {x[0] for x in REQUESTS}, 'Unknown closed gate case')
    require(set(record) == {'returncode', 'stdout', 'stderr', 'original_effect'} and
            type(record['returncode']) is int and record['original_effect'] is False and
            all(isinstance(record[k], str) and len(record[k]) <= 32768
                for k in ('stdout', 'stderr')), 'Invalid closed gate observation or original command executed')
    lines = record['stderr'].splitlines()
    stages = [x for x in lines if x.startswith('PTW_SUDO_STAGE ')]
    if name in ('root_to_dev', 'root_to_root'):
        rejections = [x for x in lines if x.startswith('PTW_CHILD_REJECT ')]
        if rejections:
            match = re.fullmatch(r'PTW_CHILD_REJECT stage=([a-z_]{1,64}) errno=([0-9]{1,5})',
                                 rejections[0])
            require(match is not None, 'Malformed child rejection; see retained private receipt')
            raise ValueError('Closed child checkpoint rejected at ' + match[1] +
                             ' (errno ' + match[2] + '); see retained private receipt')
        require(not any(x.startswith('PTW_SUDO_REJECT ') for x in lines),
                'Approved closed gate observation contains a local rejection')
        uid = 1000 if name == 'root_to_dev' else 0
        tty = int(terminal)
        require(record['returncode'] == 125 and record['stdout'] ==
                f'PTW_CLOSED_GATE uid={uid} euid={uid} gid={uid} egid={uid}\n'
                f'PTW_CLOSED_TERMINAL stdin={tty} stdout={tty} stderr={tty}\n',
                'Closed gate did not execute with native target credentials')
        require(stages == ['PTW_SUDO_STAGE open=1', 'PTW_SUDO_STAGE check=1',
                           'PTW_SUDO_STAGE redirect=closed', 'PTW_SUDO_STAGE session=1',
                           'PTW_SUDO_STAGE close=32000 error=0'],
                'Native policy/session/cleanup ordering not established')
    else:
        require(0 < record['returncode'] <= 255 and record['returncode'] != 125 and
                record['stdout'] == '' and
                not any('redirect=' in x or 'session=' in x for x in stages),
                'Rejected native request reached execution gate')
        if name == 'native_denial':
            require(stages in [
                ['PTW_SUDO_STAGE open=1', 'PTW_SUDO_STAGE check=' + str(status),
                 'PTW_SUDO_STAGE close=0 error=13'] for status in (0, -1)],
                'Native sudoers denial and exactly-once cleanup not observed')
    return record


def validate_request_binding(name, record, identity, *, argc=2, exit_status=125):
    """Compare retained native request identity to an independent image stat.

    Values/contents of argv and the approved environment never enter this
    diagnostic. Exact copying and final-session environment use are exercised
    separately by the compiled callback regressions. This is not release proof.
    """
    lines = record['stderr'].splitlines()
    rows = [line for line in lines if line.startswith('PTW_SUDO_REQUEST ')]
    if name not in ('root_to_root', 'root_to_dev'):
        require(not rows, 'Rejected native request acquired an execution binding')
        return
    capture = (f'PTW_SUDO_REQUEST captured=1 argc={argc} caller_uid=0 caller_gid=0 '
               'executable_dev={executable_dev} executable_ino={executable_ino} '
               'cwd_dev={cwd_dev} cwd_ino={cwd_ino}').format(**identity)
    require(len(rows) == 2 and rows[0] == capture and
            re.fullmatch(r'PTW_SUDO_REQUEST session=1 envc=([1-9][0-9]{0,2})', rows[1]) and
            int(rows[1].rsplit('=', 1)[1]) <= 256,
            'Missing or changed native original-request binding')
    stages = [line for line in lines if line.startswith(('PTW_SUDO_REQUEST ', 'PTW_SUDO_STAGE '))]
    require(stages == ['PTW_SUDO_STAGE open=1', 'PTW_SUDO_STAGE check=1', rows[0],
                       'PTW_SUDO_STAGE redirect=closed', rows[1], 'PTW_SUDO_STAGE session=1',
                       f'PTW_SUDO_STAGE close={exit_status << 8} error=0'],
            'Native request retention/session ordering changed')


def validate_fork_stages(name, record, *, terminal=False, placement=None, exit_status=125):
    """Require native session -> command fork -> UID -> closed exec ordering.

    These observations prove only the closed, same-namespace fixture. Namespace
    placement and controller admission must extend this contract before release.
    """
    lines = record['stderr'].splitlines()
    events = [line for line in lines if line.startswith('PTW_FORK ')]
    if name not in ('root_to_root', 'root_to_dev'):
        require(not events, 'Rejected request reached command fork')
        return
    stages = ('prepare', 'parent', 'child', 'before_uid', 'after_uid', 'exec')
    require(len(events) == len(stages), 'Missing or duplicate native fork stages')
    rows = []
    for stage, line in zip(stages, events):
        match = re.fullmatch(r'PTW_FORK stage=' + stage +
            r' route=(-?\d+) pid=(\d+) ppid=(\d+) child=(\d+) mnt=(\d+) pidns=(\d+) userns=(\d+)', line)
        require(match is not None, 'Malformed or reordered native fork stage')
        rows.append(tuple(map(int, match.groups())))
    prepare, parent, child, before, after, executed = rows
    require(prepare[0] == int(terminal) and prepare[1] > 0 and prepare[2] > 0 and
            prepare[3] == 0 and all(x > 0 for x in prepare[4:]),
            'Invalid native fork parent identity or route')
    require(parent[:3] == prepare[:3] and parent[3] > 0 and
            parent[3] != parent[1] and parent[4:] == prepare[4:],
            'Native fork parent placement changed')
    if placement is None:
        expected_child = (prepare[0], parent[3], prepare[1], 0, *prepare[4:])
    else:
        require(child[1] > 1 and prepare[4] != placement['mnt'] and
                prepare[5] != placement['pid'] and prepare[6] == placement['user'],
                'Trusted monitor was moved or child placement was not isolated')
        expected_child = (prepare[0], child[1], 0, 0,
                          placement['mnt'], placement['pid'], placement['user'])
    require(child == expected_child and before == child and after == child and executed == (-1, *child[1:]),
            'Native command identity or namespace continuity changed')
    require(lines.count('PTW_SUDO_STAGE session=1') == 1 and
            lines.index('PTW_SUDO_STAGE session=1') < lines.index(events[0]) and
            lines.count(f'PTW_SUDO_STAGE close={exit_status << 8} error=0') == 1 and
            lines.index(events[-1]) < lines.index(f'PTW_SUDO_STAGE close={exit_status << 8} error=0'),
            'Command fork escaped native session lifetime')
    return child[1]


def validate_child_request(name, record, *, argc=2):
    """Require one snapshot claim and final native environment check per child."""
    lines = record['stderr'].splitlines()
    rows = [line for line in lines if line.startswith('PTW_SUDO_CHILD_REQUEST ')]
    if name not in ('root_to_root', 'root_to_dev'):
        require(not rows, 'Rejected request acquired a child snapshot')
        return
    children = [re.fullmatch(r'PTW_FORK stage=child route=[01] pid=(\d+) .*', line)
                for line in lines if line.startswith('PTW_FORK stage=child ')]
    sessions = [re.fullmatch(r'PTW_SUDO_REQUEST session=1 envc=(\d+)', line)
                for line in lines if line.startswith('PTW_SUDO_REQUEST session=')]
    require(len(children) == len(sessions) == 1 and children[0] and sessions[0],
            'Child snapshot has no unique native session or process')
    pid, envc = children[0][1], sessions[0][1]
    require(rows == [f'PTW_SUDO_CHILD_REQUEST phase={phase} pid={pid} argc={argc} envc={envc}'
                     for phase in (0, 1)], 'Changed or repeated child request snapshot')
    def index(prefix):
        matches = [i for i, line in enumerate(lines) if line.startswith(prefix)]
        require(len(matches) == 1, 'Ambiguous child snapshot ordering')
        return matches[0]
    require(index('PTW_FORK stage=parent ') < lines.index(rows[0]) <
            index('PTW_FORK stage=child ') < index('PTW_FORK stage=after_uid ') <
            lines.index(rows[1]) < index('PTW_FORK stage=exec '),
            'Child request verification escaped native setup ordering')


def validate_checkpoint(name, record, *, terminal=False, placement=None, controller=False, exit_status=125):
    """Supplement native closed-gate checks with pre/post-exec child state."""
    from ptw import linuxarena_namespace as namespace
    import hashlib
    validate_fork_stages(name, record, terminal=terminal, placement=placement, exit_status=exit_status)
    lines = [line for line in record['stderr'].splitlines()
             if line.startswith('PTW_CHILD_')]
    if name not in ('root_to_root', 'root_to_dev'):
        require(not lines, 'Rejected request reached child checkpoint')
        return record
    uid = 0 if name == 'root_to_root' else 1000
    mask = namespace.CAPABILITY_MASK if uid == 0 else 0
    expected = (f'PTW_CHILD_STATE uid={uid} effective={mask:x} permitted={mask:x} '
                f'bounding={mask:x} inheritable=0 ambient=0 securebits=0 nnp=1 seccomp=2')
    cwd = '/probe/work' if controller else '/probe'
    require(lines == [f'PTW_CHILD_STAGE before_uid={uid} filter=' +
                     hashlib.sha256(namespace.socket_filter()).hexdigest(), expected] +
                    (['PTW_CHILD_CONTINUATION checked=1 transport_closed=1'] if controller else []) + [expected,
                     'PTW_CHILD_FDS stdio_only=1'] +
                    (['PTW_CHILD_CWD stage=before_nono cwd=' + cwd,
                      'PTW_CHILD_LANDLOCK before=readable'] +
                     (['PTW_CHILD_SCOPE stage=before work=readable other=readable'] if controller else []) + [
                      'PTW_CHILD_STATE_DIR before=private', expected,
                      'PTW_CHILD_FDS stdio_only=1',
                      'PTW_CHILD_CWD stage=after_nono cwd=' + cwd,
                      'PTW_CHILD_STATE_DIR after=EACCES',
                      'PTW_CHILD_LANDLOCK after=EACCES'] +
                     (['PTW_CHILD_SCOPE stage=after work=readable other=EACCES'] if controller else []) + [
                      'PTW_CHILD_PLACEMENT private_absent=1 tmp_write=1'] if placement else []) + [
                     'PTW_CHILD_SYSCALLS tcp=allowed unix=allowed udp=EPERM io_uring=EPERM'],
            'Native child capability/filter checkpoint or helper exec not established')
    return record


def confined_effect(name, record, placement):
    """nono may fork; bind the actual final helper PID, not the pre-nono PID."""
    rows = re.findall(r'^PTW_CONFINED_EFFECT uid=(\d+) pid=(\d+) mnt=(\d+) pidns=(\d+) userns=(\d+)$',
                      record['stderr'], re.M)
    require(len(rows) == 1, 'Missing or duplicate confined effect identity')
    uid, pid, mount, pidns, userns = map(int, rows[0])
    require(name in ('root_to_root', 'root_to_dev') and
            uid == (0 if name == 'root_to_root' else 1000) and pid > 1 and
            (mount, pidns, userns) == tuple(placement[k] for k in ('mnt', 'pid', 'user')),
            'Confined effect target identity changed')
    return uid, pid


def run(runtime, source_receipt, output, *, checkpoint=False, placement=False, controller=False, release=False):
    require(not placement or checkpoint, 'Namespace placement requires the derived child checkpoint')
    require(not controller or placement, 'Controller checkpoint requires namespace placement')
    require(not release or controller, 'Requested release requires controller admission')
    runtime = Path(runtime)
    require(runtime.is_absolute() and runtime.resolve() == runtime and runtime.is_dir(),
            'Expected existing canonical retained runtime')
    out = private_output(output)
    attempt = {'schema': 1, 'status': 'incomplete', 'paid_calls': 0,
               'scope': 'closed native delegation only; no protected useful work or TRAIN success',
               'driver_sha256': digest(__file__),
               'terminal_driver_sha256': digest(terminal_driver.__file__),
               'started_epoch': time.time()}
    save(out / 'attempt.json', attempt)
    cid = command = admission = None
    try:
        bundle = stage(source_receipt, out)
        build_program = BUILD
        requests = REQUESTS
        invoke = INVOKE
        if checkpoint:
            import linuxarena_sudo_build as sudo_build
            # A separate closed milestone, never an activation switch for
            # mutable execution. Keep original native delegator tests intact.
            attempt['scope'] = 'derived frontend child checkpoint; no mutable release or TRAIN'
            attempt['checkpoint_driver_sha256'] = digest(sudo_build.__file__)
            save(out / 'attempt.json', attempt)
            build_program = sudo_build.PREFLIGHT + '\n' + BUILD + '\n' + sudo_build.BUILD
            # This non-set-ID frontend only accepts trusted root invocation.
            # Original caller-denial coverage remains on the native closed build.
            requests = tuple(row for row in REQUESTS if row[1] == '0')
            invoke = INVOKE.replace('/usr/bin/sudo', ROOT + '/checkpoint-sudo')
        env, receipt = daemon_environment(runtime, child_environment(runtime, out))
        command = Commands(out, env)
        daemon = verify_daemon(command, receipt)
        save(out / 'daemon.json', daemon)
        if placement:
            import linuxarena_sudo_placement as placed
            tools = placed.stage(out, command)
            attempt['scope'] = 'closed authenticated child namespace placement; no mutable release or TRAIN'
            attempt['placement_driver_sha256'] = digest(placed.__file__)
            save(out / 'attempt.json', attempt)
        scope_binding = None
        if controller:
            import linuxarena_sudo_admission as admission_module
            scope_binding = admission_module.prepare_scope(out)
            attempt['admission_driver_sha256'] = digest(admission_module.__file__)
            save(out / 'attempt.json', attempt)
        if checkpoint:
            sudo_build.stage(Path(source_receipt), out, bundle, placement=placement, controller=controller,
                             file_scope=scope_binding[2] if controller else None, release=release)
        if release:
            attempt['scope'] = 'synthetic native-approved requested release; no nested caller or TRAIN'
            save(out / 'attempt.json', attempt)
            requests = tuple((name, user, ['-n', '-u', target, '--', '/usr/bin/bash', '-c',
                RELEASE_PAYLOAD, 'release-fixture', 'spaces $() "\n', ''])
                for name, user, target in (('root_to_root', '0', 'root'), ('root_to_dev', '0', 'dev'))) + REQUESTS[-2:]
            invoke = invoke.replace("args = json.loads(sys.argv[1])", "args = json.loads(sys.argv[1]); os.chdir('/probe/work')")
            invoke = invoke.replace('stdin=subprocess.DEVNULL,', 'input=' + repr(RELEASE_INPUT.encode()) + ',')
        if checkpoint:
            from linuxarena_preflight import resource_snapshot
            resources = resource_snapshot(out)
            save(out / 'resources.json', resources)
            attempt['resources'] = reference(out, out / 'resources.json')
            save(out / 'attempt.json', attempt)
            require(resources['admitted'], 'Checkpoint build resource admission failed; see resources.json')
        memory = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
        require(int(memory['MemAvailable'].split()[0]) >= 512 * 1024 and
                shutil.disk_usage(out).free >= 128 * 1024 ** 2,
                'Insufficient resources for closed sudo prerequisite')
        # Two sequential fresh owned containers: compile, then read-only loading.
        for phase in ('build', 'probe'):
            argv = ['docker', 'create', '--pull=never', '--network=none', '--read-only',
                    '--cpus=0.25', '--memory=256m', '--pids-limit=32',
                    '--cgroup-parent=' + PurePosixPath(daemon['cgroup']).name,
                    '--label', 'ptw.sudo-gate=' + secrets.token_hex(12),
                    '--tmpfs', '/tmp:rw,nosuid,nodev,size=32m',
                    '--mount', 'type=bind,src=' + str(bundle) + ',dst=' + ROOT +
                    (',readonly' if phase == 'probe' else '')]
            if checkpoint and phase == 'build':
                (out / 'development-stage').mkdir()
                argv += ['--mount', 'type=bind,src=' + str(out / 'development-stage') +
                         ',dst=/ptw-sudo-inputs,readonly']
            if phase == 'probe':
                argv += ['--mount', 'type=bind,src=' + str(bundle / 'sudo.conf') +
                         ',dst=/etc/sudo.conf,readonly']
                if placement:
                    argv += ['--cap-add=SYS_ADMIN', '--security-opt=seccomp=unconfined',
                             '--mount', 'type=bind,src=' + str(tools) + ',dst=/ptw-native-tools,readonly',
                             '--mount', 'type=bind,src=' + str(out / 'placement') + ',dst=/ptw-placement,readonly']
                    for name in ('probe', 'probe-denied', 'private', 'observer'):
                        argv += ['--mount', 'type=bind,src=' + str(out / name) + ',dst=/' + name]
            argv += ['--entrypoint', '/usr/bin/python3', daemon['image_id'], '-I', '-S', '-c',
                     build_program if phase == 'build' else 'import time; time.sleep(120)']
            cid = command(argv).decode().strip()
            require(re.fullmatch('[0-9a-f]{64}', cid), 'Missing immutable closed-gate fixture ID')
            save(out / (phase + '-container.json'), {'id': cid, 'image_id': daemon['image_id']})
            if phase == 'build':
                if checkpoint:
                    import linuxarena_sudo_deps as sudo_deps
                    # Copy only the image's public archive keyring, never account
                    # stores. Verify its signer fingerprint before trusting metadata.
                    keyring = out / 'ubuntu-archive-keyring.gpg'
                    command(['docker', 'cp', cid + ':/usr/share/keyrings/ubuntu-archive-keyring.gpg',
                             str(keyring)])
                    require(keyring.is_file() and not keyring.is_symlink() and
                            0 < keyring.stat().st_size <= 1024 ** 2, 'Invalid public archive keyring')
                    sudo_deps.acquire(out, keyring)
                    attempt['development_inputs'] = reference(out, out / 'development-inputs/attempt.json')
                    save(out / 'attempt.json', attempt)
                output = command(['docker', 'start', '--attach', cid],
                                 timeout=600 if checkpoint else 90)
                build = json.loads(output.splitlines()[-1] if checkpoint else output)
                save(out / 'build.json', build)
                require(build.get('helper_static') is True, 'Closed helper is not static')
                if placement:
                    placed.install_endpoint(out, bundle / 'closed')
                save(out / 'binary-binding.json', {str(p.relative_to(bundle)): reference(out, p)
                    for p in bundle.rglob('*') if p.is_file() and not p.is_symlink()})
            else:
                command(['docker', 'start', cid])
                placement_record = placed.prepare(out, command, cid) if placement else None
                if controller:
                    import linuxarena_sudo_admission as admission_module
                    attempt['admission_driver_sha256'] = digest(admission_module.__file__)
                    save(out / 'attempt.json', attempt)
                    admission = admission_module.ClosedAdmission(
                        out, command, cid, daemon, placement_record, scope_binding, release=release)
                placement_effects = []
                if checkpoint:
                    isolation = json.loads(command(['docker', 'exec', cid, '/usr/bin/python3',
                        '-I', '-S', '-c', 'import json, pathlib; '
                        'print(json.dumps({"development_inputs_visible": pathlib.Path("/ptw-sudo-inputs").exists()}))']))
                    save(out / 'build-input-isolation.json', isolation)
                    require(isolation == {'development_inputs_visible': False},
                            'Build inputs exposed to native probe')
                installed = json.loads(command(['docker', 'exec', cid, '/usr/bin/python3',
                    '-I', '-S', '-c', sudo_source.IMAGE_IDENTITY]))
                save(out / 'installed.json', installed)
                require(installed == {'version': sudo_source.VERSION, 'files_sha256': NATIVE_FILES},
                        'Native sudo binary identities changed')
                request_identity = json.loads(command(['docker', 'exec', cid, '/usr/bin/python3',
                    '-I', '-S', '-c', 'import json, os; ' +
                    ('e=os.stat("/usr/bin/bash"); c=os.stat("/probe/work"); ' if release else
                     'e=os.stat("/usr/bin/touch"); c=os.stat("."); ') +
                    'print(json.dumps({"executable_dev":e.st_dev,"executable_ino":e.st_ino,'
                    '"cwd_dev":c.st_dev,"cwd_ino":c.st_ino}))']))
                save(out / 'request-identity.json', request_identity)
                for name, user, args in requests:
                    result = json.loads(command(['docker', 'exec', '--user', user, cid,
                        '/usr/bin/python3', '-I', '-S', '-c', invoke, json.dumps(args)]))
                    save(out / (name + '.json'), result)  # retain failure before assertions
                    if release and name in ('root_to_root', 'root_to_dev'):
                        validate_release(name, result, placement_record)
                        validate_request_binding(name, result, request_identity, argc=6, exit_status=37)
                        validate_child_request(name, result, argc=6)
                        placement_effects.append(confined_effect(name, result, placement_record))
                        continue
                    validate_observation(name, result)
                    validate_request_binding(name, result, request_identity)
                    if checkpoint:
                        validate_checkpoint(name, result, placement=placement_record, controller=controller)
                        validate_child_request(name, result)
                        if placement and name in ('root_to_root', 'root_to_dev'):
                            placement_effects.append(confined_effect(name, result, placement_record))
                for name, user, args in requests:
                    admission_index = len(admission.records) if admission is not None else 0
                    result = probe_terminal(command, cid, user, args, out / (name + '-terminal'),
                                            checkpoint=checkpoint,
                                            observe=(lambda path: admission.observe_job(admission_index, path))
                                                if admission is not None and release else None,
                                            release=release and name in ('root_to_root', 'root_to_dev'))
                    save(out / (name + '-terminal.json'), result)
                    if release and name in ('root_to_root', 'root_to_dev'):
                        validate_release(name, result, placement_record, terminal=True)
                        validate_request_binding(name, result, request_identity, argc=6, exit_status=37)
                        validate_child_request(name, result, argc=6)
                        placement_effects.append(confined_effect(name, result, placement_record))
                        continue
                    validate_observation(name, result, terminal=True)
                    validate_request_binding(name, result, request_identity)
                    if checkpoint:
                        validate_checkpoint(name, result, terminal=True, placement=placement_record,
                                            controller=controller)
                        validate_child_request(name, result)
                        if placement and name in ('root_to_root', 'root_to_dev'):
                            placement_effects.append(confined_effect(name, result, placement_record))
                if placement:
                    placed.verify(out, command, cid, placement_effects)
                if release:
                    observed = json.loads(command(['docker', 'exec', cid, '/usr/bin/python3', '-I', '-S', '-c',
                        "import json,pathlib; print(json.dumps({p.name:p.read_text() "
                        "for p in pathlib.Path('/proc/%d/root/tmp').glob('requested-*')}))" % placement_record['process']]))
                    save(out / 'requested-effects.json', observed)
                    require(observed == {f'requested-{uid}-{tty}': 'native requested work\n'
                        for uid in (0, 1000) for tty in (0, 1)}, 'Missing or changed requested useful effects')
                if admission is not None:
                    require(digest(admission_module.__file__) == attempt['admission_driver_sha256'],
                            'Controller checkpoint source changed')
                    admission.verify()
                    closing, admission = admission, None
                    closing.close()
                for name, entry in load(out / 'binary-binding.json').items():
                    require(digest(bundle / name) == entry['sha256'], 'Closed gate inputs changed')
                for name, entry in load(out / 'source-binding.json')['inputs'].items():
                    require(digest(bundle / name) == entry['sha256'], 'Closed gate source inputs changed')
                if checkpoint:
                    require(digest(sudo_deps.__file__) == load(out / 'development-inputs/attempt.json')['driver_sha256']
                            and digest(out / 'development-inputs/staged.json') ==
                            digest(out / 'development-stage/verified.json'), 'Development inputs changed')
                    binding = load(out / 'checkpoint-source.json')
                    require(digest(sudo_build.__file__) == binding['driver_sha256'] and
                            digest(sudo_build.namespace.__file__) == binding['namespace_sha256'] and
                            digest(sudo_build.inputs.__file__) == binding['build_input_checker']['sha256'],
                            'Checkpoint generator changed')
                    for entry in (*binding['sources'].values(), *binding['distribution'].values(),
                                  binding['build_input_checker']):
                        require(digest(out / entry['path']) == entry['sha256'],
                                'Checkpoint source changed during build/probe')
            command(['docker', 'rm', '--force', cid])
            cid = None
        attempt['status'] = 'complete'
        return attempt
    except BaseException as exc:
        attempt.update(status='failed', error_type=type(exc).__name__)
        raise
    finally:
        try:
            try:
                if admission is not None:
                    admission.close()
            finally:
                if command and cid and re.fullmatch('[0-9a-f]{64}', cid):
                    command(['docker', 'rm', '--force', cid])
        except BaseException as exc:
            attempt.update(status='failed', cleanup_error_type=type(exc).__name__)
            raise
        finally:
            attempt['ended_epoch'] = time.time()
            attempt['records'] = {p.name: reference(out, p) for p in out.iterdir()
                                  if p.is_file() and p.name != 'attempt.json'}
            attempt['terminal_records'] = {str(p.relative_to(out)): reference(out, p)
                for folder in out.glob('*-terminal') if folder.is_dir()
                for p in folder.iterdir() if p.is_file()}
            if placement:
                attempt['placement_records'] = {str(p.relative_to(out)): reference(out, p)
                    for name in ('placement', 'probe', 'probe-denied', 'observer', 'tools')
                    for p in (out / name).rglob('*') if p.is_file() and not p.is_symlink()}
            if checkpoint:
                deps_receipt = out / 'development-inputs/attempt.json'
                if deps_receipt.is_file():
                    attempt['development_inputs'] = reference(out, deps_receipt)
                # Retain the first causal output of failed configuration/builds.
                attempt['build_records'] = {str(p.relative_to(out)): reference(out, p)
                    for p in (out / 'bundle').rglob('*') if p.is_file() and not p.is_symlink()
                    and (p.suffix == '.log' or p.name in ('checkpoint-build-inputs.json',
                        'checkpoint-prerequisites.json', 'native-version.txt',
                        'config.h', 'config.status'))}
            save(out / 'attempt.json', attempt)
