"""Read-only observations of registered or newly captured native workloads.

The observer never enters a worker namespace or modifies its authority. It reads
only registered cgroups or descendants of the captured comparator launcher, and
the named synthetic file. Losing /proc visibility is missing evidence, not a pass.
"""
from contextlib import contextmanager
import errno
import hashlib
import os
from pathlib import Path
import threading
import time

from evidence_io import digest, load, require, save


class MountInfoUnavailable(OSError):
    """Only the mountinfo read observed a disappearing process namespace."""


def process_image(pid):
    """Cheap sampling key: exec keeps the PID and start time, but changes argv."""
    proc = Path('/proc') / str(pid)
    return (proc.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19],
            digest(proc / 'cmdline'))


def inspect(pid, secret, marker, expected, *, isolated=True):
    proc = Path('/proc') / str(pid)
    root = proc / 'root'
    # Only observe the final payload namespace containing the reviewed snapshot.
    snapshot = root / marker.lstrip('/')
    if not snapshot.is_file() or digest(snapshot) != expected:
        return None
    network = os.readlink(proc / 'ns/net')
    host_network = os.readlink('/proc/self/ns/net')
    if isolated and network == host_network:
        return None  # bubblewrap may still be staging its mounts
    mountinfo = proc / 'mountinfo'
    try:
        mounts = mountinfo.read_text()
    except OSError as exc:
        # procfs mounts_open_common returns EINVAL if the task or its mount
        # namespace is gone. Do not generalize this to other inspection I/O.
        if exc.errno != errno.EINVAL:
            raise
        raise MountInfoUnavailable(exc.errno, exc.strerror, str(mountinfo)) from exc
    if any(row.split()[4] in ('/oldroot', '/newroot') for row in mounts.splitlines()):
        return None
    target = root / str(secret).lstrip('/')
    try:
        data = target.read_bytes()
        observation = {'read': True, 'sha256': hashlib.sha256(data).hexdigest()}
    except OSError as exc:
        observation = {'read': False, 'errno': exc.errno}
    policy_path = secret.parent.parent / 'approved.json'
    try:
        policy_observation = {'read': True, 'sha256': digest(root / str(policy_path).lstrip('/'))}
    except OSError as exc:
        policy_observation = {'read': False, 'errno': exc.errno}
    status = (proc / 'status').read_text()
    namespace_pid = int(next(line.split()[-1] for line in status.splitlines() if line.startswith('NSpid:')))
    cmdline = (proc / 'cmdline').read_bytes()
    return {'pid': pid, 'namespace_pid': namespace_pid,
            'parent_pid': int(proc.joinpath('stat').read_text().rsplit(')', 1)[1].split()[1]),
            'pid_namespace': os.readlink(proc / 'ns/pid'),
            'start_ticks': proc.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19],
            'cmdline_sha256': hashlib.sha256(cmdline).hexdigest(),
            'interpreter': {'path': os.readlink(proc / 'exe'), 'sha256': digest(proc / 'exe')},
            'argv': cmdline.decode('utf-8', 'replace').rstrip('\0').split('\0'),
            'cgroup': (proc / 'cgroup').read_text(),
            'mountinfo': mounts, 'network': network, 'host_network': host_network,
            'marker': marker, 'marker_sha256': expected, 'secret': str(secret),
            'host_secret_sha256': digest(secret), 'observation': observation,
            'operator_policy': policy_observation, 'epoch': time.time()}


@contextmanager
def observe(store, project, secret, marker, expected, folder, *, launcher=None, isolated=True):
    """Poll the bounded process set while the actual supported call runs."""
    from ptw.supervisor import Supervisor
    folder.mkdir()
    done = threading.Event()
    rows, errors = [], []
    groups, seen, unavailable, unavailable_memberships = {}, set(), {}, {}

    def receipt():
        return {'observations': rows, 'errors': errors,
                'unavailable_candidates': list(unavailable.values()),
                'unavailable_memberships': list(unavailable_memberships.values())}

    def watch():
        context = {}
        try:
            while not done.is_set():
                context = {'operation': 'list-workloads'}
                if launcher is None:
                    with store.locked() as db:
                        units = [dict(r) for r in db.execute(
                            'SELECT unit,session FROM workloads WHERE project=?', (project,))]
                else:
                    units = [{'unit': 'static-comparator', 'session': None}]
                for unit in units:
                    name = unit['unit']
                    context = {**unit, 'operation': 'locate-processes'}
                    if launcher is not None:
                        candidates = descendants(launcher['pid']) if launcher.get('pid') else []
                    elif name not in groups:
                        state = Supervisor.state(name)
                        group = state.get('ControlGroup')
                        if not group:
                            continue
                        groups[name] = Path('/sys/fs/cgroup' + group)
                    members_list = [None] if launcher is not None else groups[name].rglob('cgroup.procs')
                    for members in members_list:
                        context = {**unit, 'operation': 'read-membership', 'path': str(members)}
                        try:
                            pids = candidates if members is None else members.read_text().split()
                        except OSError as exc:
                            if members is None or exc.errno not in (errno.ENOENT, errno.ENODEV):
                                raise
                            # kernfs can return ENODEV after cgroup teardown,
                            # even for an already-open membership file. This is
                            # unavailable evidence, never a process observation.
                            key = (name, str(members), exc.errno)
                            entry = unavailable_memberships.setdefault(key, {
                                **context, 'errno': exc.errno,
                                'type': type(exc).__name__, 'samples': 0})
                            entry['samples'] += 1
                            continue
                        for pid in pids:
                            context = {**unit, 'operation': 'inspect-process', 'pid': int(pid)}
                            try:
                                identity = process_image(int(pid))
                                key = (name, pid, *identity)
                                if key in seen:
                                    continue
                                row = (inspect(int(pid), secret, marker, expected) if isolated else
                                       inspect(int(pid), secret, marker, expected, isolated=False))
                                if row is not None and (identity != (row['start_ticks'], row['cmdline_sha256'])
                                                        or process_image(int(pid)) != identity):
                                    continue  # exec/exit raced this sample; collect a complete one later
                            except (FileNotFoundError, ProcessLookupError, PermissionError,
                                    MountInfoUnavailable) as exc:
                                # Cgroup members include launchers and processes in
                                # exec/exit transitions. An inaccessible /proc root
                                # says nothing about the payload's secret access.
                                # Keep the diagnostic and continue sampling; only
                                # a complete inspect() result counts as evidence.
                                key = (name, pid, exc.errno)
                                entry = unavailable.setdefault(key, {
                                    **unit, 'pid': int(pid), 'errno': exc.errno,
                                    'type': type(exc).__name__, 'samples': 0})
                                if isinstance(exc, MountInfoUnavailable):
                                    entry.update(operation='read-mountinfo', path=exc.filename)
                                entry['samples'] += 1
                                continue
                            if row is not None:
                                rows.append({**unit, **row})
                                seen.add(key)
                                context = {**unit, 'operation': 'save-receipt'}
                                save(folder / 'namespace.json', receipt())
                done.wait(.02)
        except BaseException as exc:
            errors.append({**context, 'type': type(exc).__name__, 'message': str(exc),
                           'errno': getattr(exc, 'errno', None)})

    worker = threading.Thread(target=watch, name='demo-read-only-observer', daemon=True)
    worker.start()
    try:
        yield
    finally:
        done.set()
        worker.join(timeout=25)
        if worker.is_alive():
            errors.append({'type': 'TimeoutError', 'message': 'Namespace observer did not stop'})
        save(folder / 'namespace.json', receipt())
        # Let the original failure propagate; validation is explicit at the call site.


def descendants(pid):
    """Only descendants of the newly captured comparator process."""
    try:
        children = (Path('/proc') / str(pid) / 'task' / str(pid) / 'children').read_text().split()
    except (FileNotFoundError, ProcessLookupError):
        return []
    return [int(pid), *(p for child in children for p in descendants(int(child)))]


def verify(folder, *, secret, marker, expected, sessions, registered=True, isolated=True):
    value = load(Path(folder) / 'namespace.json')
    require(value['errors'] == [] and value['observations'], 'Missing independent namespace observation')
    for row in value['observations']:
        require((row['session'] in sessions and row['unit'].startswith('ptw-')) if registered else
                (row['session'] is None and row['unit'] == 'static-comparator'), 'Unlinked namespace observation')
        require(type(row['pid']) is int and row['pid'] > 0 and int(row['start_ticks']) > 0,
                'Missing physical process identity')
        require((row['network'] != row['host_network']) == isolated and row['network'].startswith('net:['),
                'Payload network namespace not isolated')
        require(row['marker'] == marker and row['marker_sha256'] == expected,
                'Observed another payload snapshot')
        require(row['secret'] == str(secret) and row['host_secret_sha256'] == digest(secret),
                'Synthetic secret identity changed')
        expected_read = {'read': False, 'errno': errno.ENOENT} if isolated else {'read': True, 'sha256': digest(secret)}
        require(row['observation'] == expected_read,
                'Synthetic host secret was visible or observation failed')
        require(row['mountinfo'] and (not registered or row['unit'] in row['cgroup']), 'Missing registered namespace linkage')
    return value
