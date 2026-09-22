"""Read-only /proc sampling of one probe tree, never a security oracle.

No tracing dependency, environment reads, signals, or permission changes. Short
exec stages can be missed; absent observations cannot establish enforcement.
"""
import errno
import hashlib
import json
import os
from pathlib import Path
import threading
import time

from evidence_io import digest, save


def executable_identity(path):
    path = Path(path)
    value = {'path': str(path)}
    try:
        resolved = path.resolve(strict=True)
        value.update(resolved=str(resolved), sha256=digest(resolved),
                     executable=os.access(resolved, os.X_OK), size=resolved.stat().st_size)
    except OSError as exc:
        value['error_type'] = type(exc).__name__
    return value


def process_state(base):
    """Retain original stat text, including the start time that distinguishes PID reuse."""
    value = {'measured_epoch': time.time()}
    try:
        value['raw'] = (base / 'stat').read_text()
        fields = value['raw'].rsplit(')', 1)[1].split()
        value.update(state=fields[0], start_ticks=int(fields[19]))
    except (OSError, ValueError, IndexError) as exc:
        value.update(error_type=type(exc).__name__, errno=getattr(exc, 'errno', None))
    return value


class BoundaryTrace:
    """Retain actual cmdline/mountinfo bytes when a sampled descendant changes."""
    MAX_TIMING_ROWS = 4096
    MAX_TIMING_CHILDREN = 256

    def __init__(self, folder):
        self.folder = Path(folder)
        self.folder.mkdir()
        self.stop = threading.Event()
        self.thread = None
        self.seen, self.identities, self.errors = set(), set(), set()
        self.samples = 0
        self.gaps = 0
        self.exit_races = 0
        self.pid = None
        self.started = time.time()
        self.started_monotonic = time.monotonic()
        self.start_requested_monotonic = self.collector_started_monotonic = None
        self.timings = []
        self.timing_rows_omitted = self.timing_children_omitted = 0
        self.persist(False)

    def persist(self, complete):
        save(self.folder / 'trace.json', {'started_epoch': self.started,
            'ended_epoch': time.time(), 'complete': complete, 'samples': self.samples, 'root_pid': self.pid,
            'errors': sorted(self.errors), 'method': 'read-only proc descendant sampling',
            'exit_races': self.exit_races,
            'gaps': self.gaps,
            'timing_rows_omitted': self.timing_rows_omitted,
            'timing_children_omitted': self.timing_children_omitted,
            'limitation': 'Short-lived exec/mount stages may be missed. No enforcement verdict.'})

    def start(self, pid):
        self.pid = pid
        self.start_requested_monotonic = time.monotonic()
        self.thread = threading.Thread(target=self.watch, args=(pid,), daemon=True)
        self.thread.start()

    def sample(self, pid):
        timing = {'pid': pid, 'start_monotonic': time.monotonic()}
        try:
            return self._sample(pid, timing)
        except Exception as exc:
            timing.update(error_type=type(exc).__name__, errno=getattr(exc, 'errno', None))
            raise
        finally:
            timing['end_monotonic'] = time.monotonic()
            # Buffer only the new metadata. Original sample persistence and the
            # collection order stay unchanged while their costs are measured.
            if len(self.timings) < self.MAX_TIMING_ROWS:
                self.timings.append(timing)
            else:
                self.timing_rows_omitted += 1

    def _sample(self, pid, timing):
        base = Path('/proc') / str(pid)
        # Enumerate only descendants, including children created by worker threads.
        children = set()
        timing['discovery_start_monotonic'] = time.monotonic()
        for task in (base / 'task').iterdir():
            try:
                children.update(int(p) for p in (task / 'children').read_text().split())
            except FileNotFoundError:
                pass
        timing['discovery_end_monotonic'] = time.monotonic()
        timing['children'] = sorted(children)[:self.MAX_TIMING_CHILDREN]
        timing['children_omitted'] = max(0, len(children) - self.MAX_TIMING_CHILDREN)
        self.timing_children_omitted += timing['children_omitted']
        timing['read_start_monotonic'] = time.monotonic()
        before = process_state(base)
        payload, failures = {}, {}
        for name in ('cmdline', 'mountinfo', 'exe'):
            try:
                payload[name] = os.readlink(base / name) if name == 'exe' else (base / name).read_bytes()
            except OSError as exc:
                failures[name] = {'error_type': type(exc).__name__, 'errno': exc.errno}
        after = process_state(base)
        timing['read_end_monotonic'] = time.monotonic()
        # Child IDs are discoveries, not identities. Link them to a child's own
        # sampled start_ticks; never infer an unobserved exec or process lifetime.
        for label, state in (('before', before), ('after', after)):
            timing[label] = {key: state[key] for key in ('state', 'start_ticks', 'error_type', 'errno')
                             if key in state}
        empty = [name for name in ('cmdline', 'mountinfo') if payload.get(name) == b'']
        same_process = 'start_ticks' in before and before.get('start_ticks') == after.get('start_ticks')
        if empty or failures or not same_process or 'error_type' in before or 'error_type' in after:
            missing = ('FileNotFoundError', 'ProcessLookupError')
            exited = (before.get('error_type') in missing and after.get('error_type') in missing) or (
                'start_ticks' in before and 'error_type' not in before and (
                    after.get('error_type') in missing or
                    (same_process and after.get('state') in ('Z', 'X', 'x'))))
            exit_race = exited and all(row['errno'] in (errno.ENOENT, errno.ESRCH, errno.EINVAL)
                                       for row in failures.values())
            folder = self.folder / ('gap-' + str(self.gaps))
            timing.update(observation=folder.name, classification='exit-race' if exit_race else 'incomplete',
                          persistence_start_monotonic=time.monotonic())
            folder.mkdir()
            hashes = {}
            for name in ('cmdline', 'mountinfo'):
                if name in payload:
                    (folder / name).write_bytes(payload[name])
                    hashes[name] = digest(folder / name)
            save(folder / 'observation.json', {'pid': pid, 'index': self.gaps,
                'before': before, 'after': after, 'empty_fields': empty, 'read_errors': failures,
                'sha256': hashes, 'executable': payload.get('exe'),
                'classification': 'exit-race' if exit_race else 'incomplete'})
            timing['persistence_end_monotonic'] = time.monotonic()
            self.gaps += 1
            if exit_race:
                self.exit_races += 1
            else:
                self.errors.add('Incomplete process observation: ' + folder.name + ' pid=' + str(pid))
            return children if same_process else set()
        cmdline, mounts, executable = payload['cmdline'], payload['mountinfo'], payload['exe']
        key = (pid, before['start_ticks'], executable, hashlib.sha256(cmdline + b'\0' + mounts).hexdigest())
        if key not in self.seen:
            self.seen.add(key)
            index = self.samples
            timing.update(observation=index, classification='sample',
                          persistence_start_monotonic=time.monotonic())
            (self.folder / (str(index) + '.cmdline')).write_bytes(cmdline)
            (self.folder / (str(index) + '.mountinfo')).write_bytes(mounts)
            with (self.folder / 'observations.jsonl').open('a') as stream:
                stream.write(json.dumps({'pid': pid, 'executable': executable,
                    'measured_epoch': time.time(), 'index': index,
                    'before': before, 'after': after,
                    'cmdline_sha256': hashlib.sha256(cmdline).hexdigest(),
                    'mountinfo_sha256': hashlib.sha256(mounts).hexdigest()}) + '\n')
                stream.flush()
            timing['persistence_end_monotonic'] = time.monotonic()
            self.identities.add(executable)
            self.samples += 1
        else:
            timing['classification'] = 'unchanged'
        return children

    def watch(self, pid):
        self.collector_started_monotonic = time.monotonic()
        try:
            while not self.stop.is_set():
                pending, visited = [pid], set()
                while pending:
                    current = pending.pop()
                    if current in visited:
                        continue
                    visited.add(current)
                    try:
                        pending.extend(self.sample(current))
                    except (FileNotFoundError, ProcessLookupError):
                        self.exit_races += 1
                    except OSError as exc:
                        # Linux returns EINVAL for mountinfo after the task has
                        # lost its namespace at exit. Confirm the zombie state;
                        # an EINVAL on a live process remains an observation error.
                        try:
                            state = (Path('/proc') / str(current) / 'stat').read_text().rsplit(')', 1)[1].split()[0]
                        except FileNotFoundError:
                            state = 'X'
                        if exc.errno == errno.EINVAL and state in ('Z', 'X'):
                            self.exit_races += 1
                        else:
                            self.errors.add(type(exc).__name__ + ': errno=' + str(exc.errno))
                self.stop.wait(.002)
        except Exception as exc:
            self.errors.add(type(exc).__name__)

    def close(self):
        self.stop.set()
        if self.thread is not None:
            self.thread.join()
        save(self.folder / 'timing.json', {
            'started_monotonic': self.started_monotonic,
            'start_requested_monotonic': self.start_requested_monotonic,
            'collector_started_monotonic': self.collector_started_monotonic,
            'collection_closed_monotonic': time.monotonic(),
            'row_limit': self.MAX_TIMING_ROWS, 'children_per_row_limit': self.MAX_TIMING_CHILDREN,
            'rows_omitted': self.timing_rows_omitted, 'children_omitted': self.timing_children_omitted,
            'rows': self.timings})
        save(self.folder / 'executables.json',
             [executable_identity(p) for p in sorted(self.identities)])
        self.persist(self.pid is not None and self.samples > 0 and not self.errors and
                     not self.timing_rows_omitted and not self.timing_children_omitted)
