"""Read-only host observations of this demo's registered native workloads.

The observer never enters a worker namespace or modifies its authority. It reads
only cgroups registered in the supplied disposable controller, and the explicitly
named synthetic file. Losing /proc visibility is missing evidence, not a pass.
"""
from contextlib import contextmanager
import errno
import hashlib
import os
from pathlib import Path
import threading
import time

from evidence_io import digest, load, require, save


def inspect(pid, secret, marker, expected):
    proc = Path('/proc') / str(pid)
    root = proc / 'root'
    # Only observe the final payload namespace containing the reviewed snapshot.
    snapshot = root / marker.lstrip('/')
    if not snapshot.is_file() or digest(snapshot) != expected:
        return None
    network = os.readlink(proc / 'ns/net')
    host_network = os.readlink('/proc/self/ns/net')
    if network == host_network:
        return None  # bubblewrap may still be staging its mounts
    mounts = (proc / 'mountinfo').read_text()
    if any(row.split()[4] in ('/oldroot', '/newroot') for row in mounts.splitlines()):
        return None
    target = root / str(secret).lstrip('/')
    try:
        data = target.read_bytes()
        observation = {'read': True, 'sha256': hashlib.sha256(data).hexdigest()}
    except OSError as exc:
        observation = {'read': False, 'errno': exc.errno}
    return {'pid': pid, 'start_ticks': proc.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19],
            'cmdline_sha256': digest(proc / 'cmdline'), 'cgroup': (proc / 'cgroup').read_text(),
            'mountinfo': mounts, 'network': network, 'host_network': host_network,
            'marker': marker, 'marker_sha256': expected, 'secret': str(secret),
            'host_secret_sha256': digest(secret), 'observation': observation, 'epoch': time.time()}


@contextmanager
def observe(store, project, secret, marker, expected, folder):
    """Poll only registered cgroup members while the actual supported call runs."""
    from ptw.supervisor import Supervisor
    folder.mkdir()
    done = threading.Event()
    rows, errors = [], []
    groups, seen = {}, set()

    def watch():
        try:
            while not done.is_set():
                with store.locked() as db:
                    units = [dict(r) for r in db.execute(
                        'SELECT unit,session FROM workloads WHERE project=?', (project,))]
                for unit in units:
                    name = unit['unit']
                    if name not in groups:
                        state = Supervisor.state(name)
                        group = state.get('ControlGroup')
                        if not group:
                            continue
                        groups[name] = Path('/sys/fs/cgroup' + group)
                    for members in groups[name].rglob('cgroup.procs'):
                        try:
                            pids = members.read_text().split()
                        except FileNotFoundError:
                            continue
                        for pid in pids:
                            if (name, pid) in seen:
                                continue
                            try:
                                row = inspect(int(pid), secret, marker, expected)
                            except (FileNotFoundError, ProcessLookupError):
                                continue
                            if row is not None:
                                rows.append({**unit, **row})
                                seen.add((name, pid))
                                save(folder / 'namespace.json', {'observations': rows, 'errors': errors})
                done.wait(.02)
        except BaseException as exc:
            errors.append({'type': type(exc).__name__, 'message': str(exc)})

    worker = threading.Thread(target=watch, name='demo-read-only-observer', daemon=True)
    worker.start()
    try:
        yield
    finally:
        done.set()
        worker.join(timeout=25)
        if worker.is_alive():
            errors.append({'type': 'TimeoutError', 'message': 'Namespace observer did not stop'})
        save(folder / 'namespace.json', {'observations': rows, 'errors': errors})
        # Let the original failure propagate; validation is explicit at the call site.


def verify(folder, *, secret, marker, expected, sessions):
    value = load(Path(folder) / 'namespace.json')
    require(value['errors'] == [] and value['observations'], 'Missing independent namespace observation')
    for row in value['observations']:
        require(row['session'] in sessions and row['unit'].startswith('ptw-'), 'Unlinked namespace observation')
        require(type(row['pid']) is int and row['pid'] > 0 and int(row['start_ticks']) > 0,
                'Missing physical process identity')
        require(row['network'] != row['host_network'] and row['network'].startswith('net:['),
                'Payload network namespace not isolated')
        require(row['marker'] == marker and row['marker_sha256'] == expected,
                'Observed another payload snapshot')
        require(row['secret'] == str(secret) and row['host_secret_sha256'] == digest(secret),
                'Synthetic secret identity changed')
        require(row['observation'] == {'read': False, 'errno': errno.ENOENT},
                'Synthetic host secret was visible or observation failed')
        require(row['mountinfo'] and row['unit'] in row['cgroup'], 'Missing registered namespace linkage')
    return value
