"""Controller admission for the closed sudo checkpoint, never a task broker.

The socket is visible only to trusted native monitors outside the prepared
namespace. Its sole input is a native child PID. It accepts no command, path,
project credential, UID assertion or permission proposal. The trusted invocation
binds either the closed endpoint or the requested-release fixture before admission.
"""
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import threading
import time

from evidence_io import digest, load, require, save
from ptw import linuxarena_lifecycle as lifecycle
from ptw.linuxarena_cgroup import ExecutionSubtree, process_identity
from ptw.policy import approve, compile_policy, digest as policy_digest
from ptw.store import Store


def prepare_scope(out):
    """Real reviewed synthetic task grants; no benchmark task or solution."""
    root = out / 'probe'
    require(all((root / name).is_dir() for name in ('work', 'other')),
            'Missing staged checkpoint resources')
    actions = ['read', 'write', 'append', 'create', 'delete']
    grants = [{'resource': name, 'actions': actions} for name in ('work', 'other')]
    escalation = {'warn_at': 1, 'stop_at': 3}
    policy = {'version': 4, 'project': {'id': 'checkpoint',
        'description': 'Closed synthetic child confinement', 'grants': grants,
        'escalation': escalation, 'commands': [], 'packages': {
            'allowed_names': [], 'build_packages': [], 'allow_native_wheels': False,
            'min_release_age_days': 3, 'deny_cvss_at_or_above': 9,
            'evidence_max_age_seconds': 900}}, 'tasks': [
        {'id': name, 'description': 'Synthetic ' + name, 'grants': selected,
         'escalation': escalation, 'commands': [], 'packages': []}
        for name, selected in (('parent', grants), ('child', grants[:1]))]}
    inventory = {'root': str(root), 'resources': {name: {
        'path': name, 'kind': 'tree', 'description': 'Synthetic resource'} for name in ('work', 'other')}}
    store = Store(out / 'admission-controller')
    store.activate(approve(policy, inventory, policy_digest(compile_policy(policy, inventory)),
                           'closed authentication-child admission fixture'))
    parent = store.register('checkpoint', 'parent')
    actor = store.register('checkpoint', 'child', parent_token=parent['token'])
    spec = {'read': [], 'write': ['/probe/work'], 'cwd': '/probe/work', 'connect_ports': [32001],
            'argv': ['/ptw-native-tools/bin/closed', '--confined']}
    frozen = lifecycle.freeze_checkpoint_scope(store, actor['token'], {'work': '/probe/work'}, spec)
    save(out / 'checkpoint-file-scope.json', frozen)
    return store, actor, frozen


def child_identity(monitor, local_pid):
    require(type(local_pid) is int and 1 < local_pid < 2 ** 31, 'Invalid native child PID')
    root = Path('/proc') / str(monitor['pid'])
    children = (root / 'task' / str(monitor['pid']) / 'children').read_text().split()
    require(len(children) == 1, 'Closed native monitor must have exactly one command child')
    child = process_identity(int(children[0]))
    # NSpid is listed from the host procfs domain inward. Select the monitor's
    # namespace depth, not the last number (the child's new PID namespace).
    def pids(pid):
        lines = (Path('/proc') / str(pid) / 'status').read_text().splitlines()
        rows = [line.split()[1:] for line in lines if line.startswith('NSpid:')]
        require(len(rows) == 1 and 0 < len(rows[0]) <= 32 and
                all(x.isdecimal() and int(x) > 0 for x in rows[0]), 'Invalid namespace PID identity')
        return [int(x) for x in rows[0]]
    parent_pids, child_pids = pids(monitor['pid']), pids(child['pid'])
    require(len(child_pids) == len(parent_pids) + 1 and
            child_pids[len(parent_pids) - 1] == local_pid,
            'Reported PID is not the authenticated monitor child')
    return child


def job_process(pin):
    """Read only bounded numeric state for an already pinned process."""
    def bounded(path):
        with path.open() as stream:
            value = stream.read(8193)
        require(len(value) <= 8192, 'Oversized process diagnostic')
        return value
    def same(actual):
        require(all(actual[k] == pin[k] for k in
                    ('pid', 'starttime', 'cgroup', 'pid_namespace', 'user_namespace')),
                'Process diagnostic identity changed')
    same(process_identity(pin['pid']))
    root = Path('/proc') / str(pin['pid'])
    fields = bounded(root / 'stat').rsplit(')', 1)[1].split()
    require(int(fields[19]) == pin['starttime'] and len(fields[0]) == 1,
            'Process diagnostic stat changed')
    row = dict(pid=pin['pid'], starttime=pin['starttime'], state=ord(fields[0]),
               ppid=int(fields[1]), pgid=int(fields[2]), sid=int(fields[3]), fg=int(fields[5]))
    status = bounded(root / 'status').splitlines()
    for key in ('NSpid', 'NSpgid', 'NSsid'):
        values = [line.split()[1:] for line in status if line.startswith(key + ':')]
        require(len(values) == 1 and 0 < len(values[0]) <= 32 and
                all(v.isdecimal() for v in values[0]), 'Invalid namespace diagnostic')
        row[key] = [int(v) for v in values[0]]
    for name in ('pid', 'mnt', 'user'):
        value = os.readlink(root / 'ns' / name)
        require(value.startswith(name + ':[') and value.endswith(']') and
                value[len(name) + 2:-1].isdecimal(), 'Invalid namespace inode')
        row[name + '_namespace'] = int(value[len(name) + 2:-1])
    same(process_identity(pin['pid']))
    return row


class ClosedAdmission:
    def __init__(self, out, command, cid, daemon, placement, scope_binding, *, release=False):
        self.out, self.records, self.error = out, [], None
        self.stop = threading.Event()
        self.listener = self.thread = self.subtree = None
        self.unit = None
        self.store = None
        # The trusted invocation selects the mode; build metadata cannot enable
        # requested execution. Check it before registration or socket creation.
        require(type(release) is bool, 'Invalid expected checkpoint release mode')
        source = load(out / 'checkpoint-source.json')
        require(type(source.get('requested_release')) is bool and
                source['requested_release'] is release, 'Compiled checkpoint release mode changed')
        self.store, self.actor, self.file_scope = scope_binding
        from linuxarena_sudo_build import landlock_header
        require(source['file_scope'] == self.file_scope and
                (out / 'bundle/upstream/sudo-1.9.9/src/linuxarena_sudo_landlock.h').read_text() ==
                landlock_header(placement=True, file_scope=self.file_scope, release=release),
                'Compiled checkpoint file authority changed')
        self.control = process_identity(json.loads(command(
            ['docker', 'inspect', '--format', '{{json .State}}', cid]))['Pid'])
        group = Path('/sys/fs/cgroup') / self.control['cgroup'][1:]
        holders = []
        for value in (group / 'cgroup.procs').read_text().split():
            try:
                identity = process_identity(int(value))
                if (identity['pid_namespace'] == 'pid:[%d]' % placement['pid'] and
                        os.readlink('/proc/%s/ns/mnt' % value) == 'mnt:[%d]' % placement['mnt'] and
                        (Path('/proc') / value / 'cmdline').read_bytes() ==
                        b'/usr/bin/python3\0-I\0-S\0/ptw-native-tools/placement.py\0--keeper\0'):
                    holders.append(identity)
            except FileNotFoundError:
                continue
        require(len(holders) == 1, 'Expected one pinned namespace holder')
        self.holder = holders[0]
        self.frontend = digest(out / 'bundle/checkpoint-sudo')
        try:
            self.subtree = ExecutionSubtree(self.control['cgroup'], cid, secrets.token_hex(12))
            self.unit = lifecycle.register(self.store, self.actor['token'], self.subtree,
                                           daemon_id=daemon['daemon_id'], control=self.control)
            self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            directory = os.open(out / 'observer', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                # AF_UNIX paths are short; bind through a pinned directory FD,
                # without relocating receipts or relying on an abstract socket.
                self.listener.bind('/proc/self/fd/%d/admission.sock' % directory)
            finally:
                os.close(directory)
            self.listener.listen(1)
            self.listener.settimeout(.1)
            self.thread = threading.Thread(target=self.serve, name='closed-sudo-admission', daemon=True)
            self.thread.start()
        except BaseException:
            self.close()
            raise

    def connection(self, peer):
        self.stage = 'peer_identity'
        peer.settimeout(3)
        pid, uid, _ = struct.unpack('3i', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(uid == os.geteuid(), 'Checkpoint monitor has an unexpected host UID')
        monitor = process_identity(pid)  # Kernel peer; no claimed parent identity.
        self.stage = 'request_frame'
        request = bytearray()
        deadline = time.monotonic() + 3
        while len(request) < 5:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Incomplete closed checkpoint request')
            peer.settimeout(remaining)
            data = peer.recv(5 - len(request))
            if not data:
                break
            request.extend(data)
        require(len(request) == 4, 'Expected exactly one closed checkpoint child PID')
        self.stage = 'child_identity'
        wire = struct.unpack('=I', request)[0]
        continuation, local_pid = bool(wire & 0x80000000), wire & 0x7fffffff
        child = child_identity(monitor, local_pid)
        context = {'monitor': monitor, 'holder': self.holder, 'frontend_sha256': self.frontend,
                   'file_scope': self.file_scope}
        self.stage = 'controller_admission'
        if continuation:
            prior = [r for r in self.records if r['child']['pid'] == child['pid']]
            require(len(prior) == 1 and 'continued' not in prior[0] and
                    {k: v for k, v in prior[0]['checkpoint']['monitor'].items() if k != 'state'} ==
                    {k: v for k, v in monitor.items() if k != 'state'},
                    'Missing, changed or repeated closed checkpoint admission')
            prior[0]['continued'] = lifecycle.continue_checkpoint(
                self.store, self.actor['token'], self.unit, prior[0]['child'], child,
                prior[0]['checkpoint'])
        else:
            moved = lifecycle.admit(self.store, self.actor['token'], self.unit, child,
                                    closed_checkpoint=context)
            self.records.append({'child': child, 'moved': moved, 'checkpoint': context})
        # Persist an independent private observation before acknowledging the
        # native monitor. Lost acknowledgement revokes this whole owned domain.
        self.stage = 'admission_receipt'
        save(self.out / 'controller-admissions.json', self.records)
        self.stage = 'acknowledgement'
        peer.sendall(b'C')

    def serve(self):
        self.stage = 'accept'
        try:
            while not self.stop.is_set():
                try:
                    peer, _ = self.listener.accept()
                except socket.timeout:
                    continue
                with peer:
                    self.connection(peer)
        except BaseException as exc:
            self.error = exc
            # A peer may have been resumed but still be blocked on its private
            # native barrier. Close its revocation domain on every uncertainty.
            try:
                save(self.out / 'controller-admission-error.json', {
                    'stage': self.stage, 'error_type': type(exc).__name__,
                    'errno': getattr(exc, 'errno', None), 'reason': str(exc)[:512]})
            finally:
                with self.store.locked() as db:
                    lifecycle.terminate(db, self.unit)

    def observe_job(self, index, path):
        """Two fixture snapshots; never grant authority or act on observed PIDs.

        Anchor in this invocation's authenticated admission, then follow only
        its monitor's parent and its command child's single direct descendant.
        Pin before reading; retain missing, changed and inaccessible identities.
        No arguments, environments, account files or process inventory.
        """
        pins = getattr(self, '_job_pins', {})
        self._job_pins = pins
        rows = []
        try:
            require(len(self.records) == index + 1, 'Missing or ambiguous job admission')
            record = self.records[index]
            if index not in pins:
                pins[index] = {1: record['checkpoint']['monitor'], 2: record['moved']}
                for role in (3, 4):
                    try:
                        parent = pins[index][1 if role == 3 else 2]
                        state = job_process(parent)
                        if role == 3:
                            pid = state['ppid']
                        else:
                            source = Path('/proc') / str(parent['pid']) / 'task' / str(parent['pid']) / 'children'
                            with source.open() as stream:
                                children = stream.read(257)
                            require(len(children) <= 256 and len(children.split()) == 1,
                                    'Missing or ambiguous payload descendant')
                            pid = int(children)
                        pin = process_identity(pid)
                        require(all(pin[k] == parent[k] for k in
                                    ('cgroup', 'pid_namespace', 'user_namespace')),
                                'Unrelated process diagnostic')
                        child_state = job_process(pin)
                        require((role == 3 and digest('/proc/%d/exe' % pid) == self.frontend) or
                                (role == 4 and child_state['ppid'] == parent['pid']),
                                'Unverified process diagnostic ancestry')
                        require(job_process(parent)['ppid'] == state['ppid'], 'Changed diagnostic ancestry')
                        job_process(pin)
                        pins[index][role] = pin
                    except (OSError, ValueError, IndexError) as exc:
                        pins[index][role] = {'error': getattr(exc, 'errno', None) or -1}
            for role, pin in pins[index].items():
                try:
                    if 'error' in pin:
                        rows.append({'role': role, **pin})
                    else:
                        rows.append({'role': role, 'error': 0, **job_process(pin)})
                except (OSError, ValueError, IndexError) as exc:
                    rows.append({'role': role, 'pid': pin['pid'],
                                 'error': getattr(exc, 'errno', None) or -1})
        except (OSError, ValueError, IndexError) as exc:
            rows.append({'role': 0, 'error': getattr(exc, 'errno', None) or -1})
        save(path, {'roles': {'monitor': 1, 'command': 2, 'frontend': 3, 'payload': 4},
                    'observed_monotonic': time.monotonic(), 'processes': rows})

    def close(self):
        self.stop.set()
        try:
            if self.thread is not None:
                self.thread.join(4)
                require(not self.thread.is_alive(), 'Closed admission thread did not stop')
        finally:
            if self.listener is not None:
                self.listener.close()
            if self.subtree is not None:
                try:
                    if self.unit is not None:
                        with self.store.locked() as db:
                            stopped = lifecycle.terminate(db, self.unit)
                        save(self.out / 'controller-admission-stop.json', stopped)
                        require(stopped['confirmed_stopped'], 'Checkpoint subtree stopping unconfirmed')
                    else:
                        self.subtree.terminate()
                finally:
                    self.subtree.close()

    def verify(self):
        require(self.error is None, 'Controller checkpoint failed; see private admission error')
        require(len(self.records) == 4, 'Expected four native controller admissions')
        require(len({r['child']['pid'] for r in self.records}) == 4,
                'Repeated controller checkpoint child')
        require(all(r.get('continued') == r['moved'] for r in self.records),
                'Missing closed checkpoint continuation')
