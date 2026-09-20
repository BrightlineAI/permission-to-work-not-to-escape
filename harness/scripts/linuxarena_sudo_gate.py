"""Closed native delegation proof; never launches mutable work or model calls.

Only a fresh fixture's sudo.conf selects the plugin. Native sudoers/PAM and the
image account configuration remain unchanged. The static endpoint returns 125;
its successful invocation is NOT successful confinement or task completion.
"""
import json
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

# No requested command may execute, including approved touch and sudoedit. Only
# the immutable closed helper can run. Test output is fixed numeric metadata.
INVOKE = '''import json, os, subprocess, sys
args = json.loads(sys.argv[1])
result = subprocess.run(['/usr/bin/sudo', *args], stdin=subprocess.DEVNULL,
    capture_output=True, close_fds=True, timeout=5,
    env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
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
result = subprocess.run(['/usr/bin/sudo', *args], close_fds=True, timeout=5,
    env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
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
        (stdout if line.startswith(('PTW_CLOSED_GATE ', 'PTW_CLOSED_TERMINAL '))
         else stderr).append(line)
    return dict(result, stdout=''.join(stdout), stderr=''.join(stderr))


def probe_terminal(command, cid, user, args, folder):
    terminal = Terminal(['docker', 'exec', '-it', '--user', user, cid,
        '/usr/bin/python3', '-I', '-S', '-c', INVOKE_TERMINAL, json.dumps(args)],
        folder, env=command.env, cwd=command.out, replace_env=True)
    try:
        def finished():
            require(len(terminal.text) <= 32768, 'Closed gate terminal output exceeds bound')
            return terminal.exited
        terminal.wait(finished, timeout=10, label='closed sudo terminal exit')
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


def run(runtime, source_receipt, output):
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
    cid = command = None
    try:
        bundle = stage(source_receipt, out)
        env, receipt = daemon_environment(runtime, child_environment(runtime, out))
        command = Commands(out, env)
        daemon = verify_daemon(command, receipt)
        save(out / 'daemon.json', daemon)
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
            if phase == 'probe':
                argv += ['--mount', 'type=bind,src=' + str(bundle / 'sudo.conf') +
                         ',dst=/etc/sudo.conf,readonly']
            argv += ['--entrypoint', '/usr/bin/python3', daemon['image_id'], '-I', '-S', '-c',
                     BUILD if phase == 'build' else 'import time; time.sleep(120)']
            cid = command(argv).decode().strip()
            require(re.fullmatch('[0-9a-f]{64}', cid), 'Missing immutable closed-gate fixture ID')
            save(out / (phase + '-container.json'), {'id': cid, 'image_id': daemon['image_id']})
            if phase == 'build':
                build = json.loads(command(['docker', 'start', '--attach', cid], timeout=90))
                save(out / 'build.json', build)
                require(build.get('helper_static') is True, 'Closed helper is not static')
                save(out / 'binary-binding.json', {p.name: reference(out, p) for p in bundle.iterdir()})
            else:
                command(['docker', 'start', cid])
                installed = json.loads(command(['docker', 'exec', cid, '/usr/bin/python3',
                    '-I', '-S', '-c', sudo_source.IMAGE_IDENTITY]))
                save(out / 'installed.json', installed)
                require(installed == {'version': sudo_source.VERSION, 'files_sha256': NATIVE_FILES},
                        'Native sudo binary identities changed')
                for name, user, args in REQUESTS:
                    result = json.loads(command(['docker', 'exec', '--user', user, cid,
                        '/usr/bin/python3', '-I', '-S', '-c', INVOKE, json.dumps(args)]))
                    save(out / (name + '.json'), result)  # retain failure before assertions
                    validate_observation(name, result)
                for name, user, args in REQUESTS:
                    result = probe_terminal(command, cid, user, args, out / (name + '-terminal'))
                    save(out / (name + '-terminal.json'), result)
                    validate_observation(name, result, terminal=True)
                for name, entry in load(out / 'binary-binding.json').items():
                    require(digest(bundle / name) == entry['sha256'], 'Closed gate inputs changed')
                for name, entry in load(out / 'source-binding.json')['inputs'].items():
                    require(digest(bundle / name) == entry['sha256'], 'Closed gate source inputs changed')
            command(['docker', 'rm', '--force', cid])
            cid = None
        attempt['status'] = 'complete'
        return attempt
    except BaseException as exc:
        attempt.update(status='failed', error_type=type(exc).__name__)
        raise
    finally:
        try:
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
            save(out / 'attempt.json', attempt)
