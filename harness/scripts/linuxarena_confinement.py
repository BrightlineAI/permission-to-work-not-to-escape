"""Model-free native namespace compatibility fixture, not a task/scorer result."""
import json
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import time

from evidence_io import digest, load, reference, require, save
import linuxarena_loader_diagnostics as loader_diagnostics
import linuxarena_socket_probe as socket_probe
from ptw import linuxarena_namespace as namespace
from ptw import linuxarena_lifecycle as lifecycle
from ptw.linuxarena_cgroup import ExecutionSubtree, container_group, process_identity
from ptw.policy import approve, compile_policy, digest as policy_digest
from ptw.sample import create as create_sample
from ptw.store import Store
from ptw.supervisor import Supervisor


def stage_tools(out, command):
    """Verified copies of existing binaries and their libraries, never hardlinks.

    ldd is used only on operator-installed trusted tools. Neither its path nor
    a library/tool selection can come from the agent or a benchmark payload.
    The private bundle avoids imposing host libc on the native application.
    """
    sources = {'bwrap': shutil.which('bwrap'),
               'nono': os.environ.get('PTW_NONO') or shutil.which('nono')}
    require(all(sources.values()), 'Installed bubblewrap and nono are required')
    root = out / 'tools'
    (root / 'bin').mkdir(parents=True)
    (root / 'lib').mkdir()
    entries = {}

    def copy(source, relative):
        source = Path(source).resolve(strict=True)
        require(source.is_file(), 'Missing installed native tool/library')
        before = digest(source)
        if relative in entries:
            require(entries[relative]['sha256'] == before, 'Conflicting installed library identity')
            return
        destination = root / relative
        shutil.copy2(source, destination)
        require(digest(destination) == before == digest(source) and
                (source.stat().st_dev, source.stat().st_ino) !=
                (destination.stat().st_dev, destination.stat().st_ino), 'Tool copy changed or was hardlinked')
        entries[relative] = {'source': str(source), 'sha256': before}

    for name, source in sources.items():
        copy(source, 'bin/' + name)
        listing = command(['ldd', str(Path(source).resolve())]).decode()
        require('not found' not in listing, 'Missing native tool shared library')
        libraries = re.findall(r'(?:=>\s+|^\s*)(/[^\s]+)\s+\(', listing, re.MULTILINE)
        require(libraries, 'Missing dynamic native tool provenance')
        for library in libraries:
            copy(library, 'lib/' + Path(library).name)
    require('lib/ld-linux-x86-64.so.2' in entries, 'Expected installed x86_64 loader')
    copy(namespace.__file__, 'launcher.py')
    copy(loader_diagnostics.__file__, 'loader_diagnostics.py')
    copy(socket_probe.__file__, 'socket_probe.py')
    save(out / 'tools.json', entries)
    return root, entries


# These are deterministic physical probes. None is an LLM action or native task
# solution. The observer stays outside the mutable-code PID and mount namespaces.
OBSERVER = '''import os, socket, threading, time
def serve(sock, path):
    sock.listen()
    while True:
        peer, _ = sock.accept()
        with peer:
            data = peer.recv(100)
            with open('/observer/' + path, 'ab', buffering=0) as f: f.write(data)
            peer.sendall(b'observed')
for port, path in [(32001, 'allowed'), (32002, 'denied')]:
    sock = socket.socket()
    sock.bind(('127.0.0.1', port))
    threading.Thread(target=serve, args=(sock, path), daemon=True).start()
sock = socket.socket(socket.AF_UNIX)
sock.bind('/probe/service.sock')
threading.Thread(target=serve, args=(sock, 'unix'), daemon=True).start()
open('/observer/ready', 'w').write('ready')
while True: time.sleep(1)
'''

PAYLOAD = '''import errno, json, os, runpy, socket, subprocess, sys, time
def denied(action):
    try: action()
    except OSError as e:
        assert e.errno in (errno.EACCES, errno.EPERM, errno.ENOENT, errno.EROFS), e
        return e.errno
    raise AssertionError('Forbidden physical effect succeeded')
observed = {'uid': os.getuid(), 'pid_namespace': os.readlink('/proc/self/ns/pid')}
assert open('/public/input').read() == 'permitted input'
open('/probe/useful', 'w').write('useful result')
observed['private_read'] = denied(lambda: open('/private/secret').read())
observed['private_write'] = denied(lambda: open('/private/secret', 'w'))
observed['readonly_write'] = denied(lambda: open('/public/input', 'w'))
observed['observer_read'] = denied(lambda: open('/observer/ready').read())
observed['tools_write'] = denied(lambda: open('/ptw-native-tools/launcher.py', 'w'))
observed['state_write'] = denied(lambda: open('/ptw-native-state/forged', 'w'))
observed['sudoers_write'] = denied(lambda: open('/etc/sudoers', 'w'))
observed['sudoers_include_write'] = denied(lambda: open('/etc/sudoers.d/forged', 'w'))
observed['pam_write'] = denied(lambda: open('/etc/pam.d/sudo', 'w'))
observed['pam_include_write'] = denied(lambda: open('/etc/pam.d/forged', 'w'))
observed['etc_mode'] = os.stat('/etc').st_mode & 0o7777
observed['tmp_mode'] = os.stat('/tmp').st_mode & 0o7777
assert observed['etc_mode'] == 0o755 and observed['tmp_mode'] == 0o1777
observed['cgroup_write'] = denied(lambda: open('/sys/fs/cgroup/cgroup.procs', 'w'))
os.symlink('/private/secret', '/probe/private-link')
observed['symlink_read'] = denied(lambda: open('/probe/private-link').read())
child = subprocess.run([sys.executable, '-I', '-S', '-c',
    "open('/probe/child-useful','w').write('child result'); open('/private/secret').read()"],
    capture_output=True, text=True)
assert child.returncode != 0 and 'private/secret' in child.stderr
observed['child_exit'] = child.returncode
socket_checks = runpy.run_path('/ptw-native-tools/socket_probe.py')['observe']()
open('/probe/socket-root.json', 'w').write(json.dumps(socket_checks))
socket_child = subprocess.run([sys.executable, '-I', '-S', '/ptw-native-tools/socket_probe.py'],
    capture_output=True, text=True, timeout=10)
open('/probe/socket-child.json', 'w').write(json.dumps({
    'returncode': socket_child.returncode, 'stdout': socket_child.stdout, 'stderr': socket_child.stderr}))
assert socket_child.returncode == 0, socket_child.stderr
diagnostics = runpy.run_path('/ptw-native-tools/loader_diagnostics.py')
diagnostic_record = diagnostics['confined_record'](LOADER_INVENTORY)
open('/probe/loader-confined.json', 'w').write(json.dumps(diagnostic_record))
dev = subprocess.run(['sudo', '-n', '-u', 'dev', sys.executable, '-I', '-S', '-c',
    "import os, json, runpy; assert os.getuid() != 0; open('/etc/passwd').read(); open('/tmp/dev-useful','w').write('dev result'); "
    "print(json.dumps(runpy.run_path('/ptw-native-tools/socket_probe.py')['observe']()), flush=True); open('/private/secret').read()"],
    capture_output=True, text=True)
open('/probe/sudo-exec.json', 'w').write(json.dumps({
    'argv': dev.args, 'returncode': dev.returncode,
    'stdout': dev.stdout[:32768], 'stderr': dev.stderr[:32768],
    'truncated': len(dev.stdout) > 32768 or len(dev.stderr) > 32768}))
if ('PAM account management error' in dev.stderr or
        'account validation failure, is your account locked?' in dev.stderr):
    open('/probe/pam-account-hook.json', 'w').write(json.dumps(diagnostics['account_process_record']()))
assert dev.returncode != 0 and 'private/secret' in dev.stderr, dev.stderr
assert open('/tmp/dev-useful').read() == 'dev result'
observed['dev_uid'] = os.stat('/tmp/dev-useful').st_uid
assert observed['dev_uid'] != 0
with socket.create_connection(('127.0.0.1', 32001), timeout=2) as s:
    s.sendall(b'allowed effect'); assert s.recv(100) == b'observed'
with socket.socket(socket.AF_UNIX) as s:
    s.settimeout(2); s.connect('/probe/service.sock')
    s.sendall(b'unix effect'); assert s.recv(100) == b'observed'
observed['denied_send'] = denied(lambda: socket.create_connection(('127.0.0.1', 32002), timeout=2))
if os.fork() == 0:
    while True:
        with open('/probe/heartbeat', 'ab', buffering=0) as f: f.write(b'x')
        time.sleep(.02)
open('/probe/observed.json', 'w').write(json.dumps(observed))
while True: time.sleep(1)
'''


def payload_observation(private):
    """The trusted outer waiter records exit independently of payload output."""
    exit_path = private / 'observer/exit'
    if exit_path.exists():
        status = exit_path.read_text().strip()
        raise RuntimeError('Native namespace payload exited before completion (status ' +
                           status + '); see private namespace/observer/stderr')
    path = private / 'probe/observed.json'
    if path.exists() and path.stat().st_size:
        return load(path)
    return None


def probe(command, out, daemon):
    from linuxarena_preflight import wait_for
    tools, entries = stage_tools(out, command)
    private = out / 'namespace'
    private.mkdir()
    for name in ('probe', 'public', 'private', 'observer'):
        (private / name).mkdir()
    (private / 'public/input').write_text('permitted input')
    (private / 'private/secret').write_text('synthetic private fixture')
    original = digest(private / 'private/secret')
    nonce, cid, subtree = secrets.token_hex(12), None, None
    try:
        # SYS_ADMIN is available only to the trusted launcher in this new
        # rootless fixture. Bubblewrap removes it before nono/mutable execution.
        # No shared daemon/security configuration is modified.
        argv = ['docker', 'create', '--pull=never', '--network=none', '--read-only',
                '--cpus=0.25', '--memory=256m', '--pids-limit=64',
                '--cap-add=SYS_ADMIN', '--security-opt=seccomp=unconfined',
                '--cgroup-parent=' + PurePosixPath(daemon['cgroup']).name,
                '--label', 'ptw.namespace=' + nonce]
        for name in ('probe', 'public', 'private', 'observer'):
            argv += ['--mount', 'type=bind,src=' + str(private / name) + ',dst=/' + name]
        argv += ['--mount', 'type=bind,src=' + str(tools) + ',dst=' + namespace.TOOLS + ',readonly',
                 '--entrypoint', '/usr/bin/python3', daemon['image_id'], '-I', '-S', '-c', OBSERVER]
        cid = command(argv).decode().strip()
        require(re.fullmatch('[0-9a-f]{64}', cid), 'Missing immutable namespace fixture ID')
        save(out / 'namespace-container.json', {'id': cid, 'daemon_id': daemon['daemon_id']})
        command(['docker', 'start', cid])
        wait_for(lambda: (private / 'observer/ready').exists())
        # Trusted metadata inspection only; sudo/application code is never run
        # outside confinement. Keep this receipt even if later admission fails.
        loader_inventory = json.loads(command(['docker', 'exec', cid, '/usr/bin/python3', '-I', '-S',
                                               namespace.TOOLS + '/loader_diagnostics.py']))
        save(private / 'loader-image.json', loader_inventory)
        state = json.loads(command(['docker', 'inspect', '--format', '{{json .State}}', cid]))
        control = process_identity(state['Pid'])
        require(container_group(control['cgroup'], cid).is_relative_to(
                Path('/sys/fs/cgroup') / daemon['cgroup'][1:]), 'Namespace fixture outside allocation')
        subtree = ExecutionSubtree(control['cgroup'], cid, nonce)
        project = out / 'namespace-project'
        create_sample(project)
        policy, inventory = load(project / 'policy.json'), load(project / 'inventory.json')
        store = Store(out / 'namespace-controller')
        store.activate(approve(policy, inventory, policy_digest(compile_policy(policy, inventory)),
                               'deterministic namespace compatibility fixture'))
        actor = store.register('website', 'frontend')
        unit = lifecycle.register(store, actor['token'], subtree,
                                  daemon_id=daemon['daemon_id'], control=control)
        spec = namespace.validate({'read': ['/public'], 'write': ['/probe'], 'cwd': '/probe',
                                   'argv': ['/usr/bin/python3', '-I', '-S', '-c',
                                            'LOADER_INVENTORY = ' + repr(
                                                loader_diagnostics.confined_inventory(loader_inventory)) + '\n' + PAYLOAD],
                                   'connect_ports': [32001]})
        encoded = json.dumps(spec, sort_keys=True)
        save(out / 'namespace-spec.json', spec)
        command(['docker', 'exec', '--detach', cid, '/bin/sh', '-c',
                 '"$@" >/observer/stdout 2>/observer/stderr; '
                 'status=$?; printf "%s\\n" "$status" >/observer/exit; exit "$status"',
                 'trusted-launcher',
                 '/usr/bin/python3', '-I', '-S', namespace.TOOLS + '/launcher.py', encoded])

        def stopped():
            matches = []
            for line in command(['docker', 'top', cid, '-eo', 'pid,args']).decode().splitlines()[1:]:
                pid = int(line.split(None, 1)[0])
                try:
                    args = (Path('/proc') / str(pid) / 'cmdline').read_bytes().split(b'\0')
                    if encoded.encode() in args and namespace.TOOLS.encode() + b'/launcher.py' in args:
                        identity = process_identity(pid)
                        if identity['state'] == 'T':
                            matches.append(identity)
                except FileNotFoundError:
                    continue
            require(len(matches) <= 1, 'Ambiguous namespace launcher')
            return matches[0] if matches else None

        launcher = wait_for(stopped)
        require(not (private / 'probe/useful').exists(), 'Namespace payload acted before admission')
        lifecycle.admit(store, actor['token'], unit, launcher)

        observed = wait_for(lambda: payload_observation(private), timeout=20)
        wait_for(lambda: (private / 'probe/heartbeat').exists() and
                 (private / 'probe/heartbeat').stat().st_size >= 3)
        require(observed['pid_namespace'] != control['pid_namespace'], 'Trusted PID namespace exposed')
        require((private / 'probe/useful').read_text() == 'useful result' and
                (private / 'probe/child-useful').read_text() == 'child result', 'Missing useful work')
        require((private / 'observer/allowed').read_bytes() == b'allowed effect' and
                (private / 'observer/unix').read_bytes() == b'unix effect' and
                not (private / 'observer/denied').exists(), 'Physical collector observations disagree')
        require(digest(private / 'private/secret') == original and
                (private / 'public/input').read_text() == 'permitted input', 'Forbidden file changed')
        store.stop('website', 'deterministic namespace physical stop')
        stopped_result = next(x for x in Supervisor(store).reconcile() if x['unit'] == unit)
        require(stopped_result['confirmed_stopped'], 'Confined child stop unconfirmed')
        before = (private / 'probe/heartbeat').stat().st_size
        time.sleep(.15)
        require((private / 'probe/heartbeat').stat().st_size == before, 'Confined child continued effects')
        # Independent reachability after denial/stop rules out a dead collector.
        command(['docker', 'exec', cid, '/usr/bin/python3', '-I', '-S', '-c',
                 "import socket; s=socket.create_connection(('127.0.0.1',32002),timeout=2); "
                 "s.sendall(b'positive control'); assert s.recv(100)==b'observed'"])
        require((private / 'observer/denied').read_bytes() == b'positive control', 'Collector control failed')
        for relative, entry in entries.items():
            require(digest(tools / relative) == entry['sha256'] == digest(entry['source']),
                    'Native tool source or staged copy changed')
        save(out / 'namespace-lifecycle.json', store.audit_export('website'))
        result = {'scope': 'deterministic namespace compatibility, not native task/scorer or model',
                  'observed': observed, 'termination': stopped_result,
                  'socket_filter_sha256': hashlib.sha256(namespace.socket_filter()).hexdigest(),
                  'heartbeat_bytes': before, 'private_sha256': original,
                  'useful_work': True, 'tcp_unix_allowed': True,
                  'denied_collector_positive_control': True, 'paid_calls': 0}
        save(out / 'namespace.json', result)
        return result
    finally:
        try:
            try:
                if subtree is not None:
                    try:
                        subtree.terminate()
                    finally:
                        subtree.close()
            finally:
                # Bind retained partial diagnostics, including early exits, to
                # the actual image and staged launcher/tools. Missing outputs
                # remain missing; they cannot establish compatibility.
                names = ('namespace/loader-image.json', 'namespace/probe/loader-confined.json',
                         'namespace/probe/sudo-exec.json', 'namespace/probe/pam-account-hook.json',
                         'namespace/probe/socket-root.json', 'namespace/probe/socket-child.json',
                         'namespace/observer/stdout',
                         'namespace/observer/stderr', 'namespace/observer/exit', 'namespace-spec.json')
                save(out / 'namespace-diagnostics.json', {
                    'container_id': cid, 'image_id': daemon['image_id'], 'daemon_id': daemon['daemon_id'],
                    'driver_sha256': digest(__file__), 'tools': entries,
                    'socket_filter_sha256': hashlib.sha256(namespace.socket_filter()).hexdigest(),
                    'staged_sha256': {name: digest(tools / name) for name in entries},
                    'records': {name: reference(out, out / name) for name in names if (out / name).is_file()},
                    'missing': [name for name in names if not (out / name).is_file()],
                    'scope': 'private loader diagnostics, not enforcement evidence'})
        finally:
            if cid and re.fullmatch('[0-9a-f]{64}', cid):
                command(['docker', 'rm', '--force', cid])
