"""Lifetime of exclusively owned native test controllers, never service discovery."""
import os
import hashlib
from pathlib import Path
import sys
import tempfile

from ptw import monitor
from ptw.policy import save
from ptw.store import Store
from ptw.supervisor import Supervisor


def unit_path(directory):
    return (Path(os.environ.get('XDG_CONFIG_HOME', str(Path.home() / '.config'))) /
            'systemd/user' / monitor.unit_for(directory))


def stop_controller(store):
    """Caller owns the whole controller, including partially activated projects."""
    if not store.db.is_file():
        raise RuntimeError('Fixture controller disappeared: ' + str(store.directory))
    with store.locked() as db:
        projects = [r[0] for r in db.execute('SELECT id FROM projects')]
        units = [r[0] for r in db.execute('SELECT unit FROM workloads')]
    errors = []
    for project in projects:
        try:
            store.stop(project, 'fixture owner cleanup')
        except BaseException as exc:
            errors.append(exc)
    try:
        termination = Supervisor(store).reconcile()
        physical = {unit: Supervisor.state(unit) for unit in units}
        if (any(r.get('confirmed_stopped') is not True for r in termination) or
                any(r.get('confirmed_stopped') is not True for r in physical.values())):
            raise RuntimeError('Fixture termination is unconfirmed: ' + str(store.directory))
        removed = monitor.remove(store)
        # A loaded service can survive deletion of its unit file. remove() is
        # deliberately a no-op for that file, not proof that the service ended.
        state = monitor.call('show', monitor.unit_for(store.directory), '-p', 'ActiveState', '--value')
        if (unit_path(store.directory).exists() or unit_path(store.directory).is_symlink() or
                state not in ('inactive', 'failed')):
            raise RuntimeError('Fixture monitor removal is unconfirmed')
    except BaseException as exc:
        errors.append(exc)
    if errors:
        raise BaseExceptionGroup('Fixture controller cleanup failed', errors)
    return {'state': str(store.directory), 'projects': projects, 'termination': termination,
            'physical': physical, **removed}


def recover_inactive(store, expected_unit):
    """Exact-owner interrupted-fixture recovery, after receipt ownership review.

    Run in the fixture's original interpreter. No selection by prefix, age or
    service inventory, and no termination of active or unconfirmed work.
    """
    destination = unit_path(store.directory)
    if not store.db.is_file():
        raise RuntimeError('Fixture controller disappeared: ' + str(store.directory))
    if (expected_unit != monitor.unit_for(store.directory) or destination.is_symlink() or
            not destination.is_file() or destination.read_text() not in
            {monitor.service_text(store.directory), monitor.service_text(store.directory, legacy=True)}):
        raise RuntimeError('Interrupted fixture ownership or interpreter differs')
    with store.locked() as db:
        units = [r[0] for r in db.execute('SELECT unit FROM workloads')]
    if any(Supervisor.state(unit).get('confirmed_stopped') is not True for unit in units):
        raise RuntimeError('Interrupted fixture work is active or unconfirmed')
    return stop_controller(store)


def cleanup(controllers, *, closers=(), report=None, destination=None):
    """Attempt every owned resource; retain both the body and cleanup failures."""
    original = sys.exception()
    report = report if report is not None else {}
    report['cleanup_source_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    if original is not None:
        report.update(passed=False, body_error=type(original).__name__ + ': ' + str(original))
    errors = []
    for close in closers:
        try:
            close()
        except BaseException as exc:
            errors.append(exc)
    try:
        acquired = controllers() if callable(controllers) else controllers
    except BaseException as exc:
        errors.append(exc)
        acquired = []
    for store in acquired:
        try:
            if not isinstance(store, Store):
                directory = Path(store)
                database = directory / 'state.sqlite3'
                if not database.is_file() or database.resolve() != database:
                    raise RuntimeError('Fixture controller disappeared or is linked: ' + str(directory))
                store = Store(directory)
            report.setdefault('fixture_cleanup', []).append(stop_controller(store))
        except BaseException as exc:
            errors.append(exc)
    if errors:
        report['passed'] = False
        report['cleanup_errors'] = [str(exc) for exc in errors]
    try:
        if destination is not None:
            save(destination, report)
    except BaseException as exc:
        errors.append(exc)
    if errors:
        raise BaseExceptionGroup('Fixture cleanup failed; evidence retained',
                                 ([original] if original is not None else []) + errors)
    return report


def owned_controllers(root, *, foreground=()):
    """Only state inside a freshly allocated, exclusively owned fixture tree.

    Setup can create several discovery controllers before returning a record.
    Do not search systemd, follow links, or use this on borrowed evidence trees.
    """
    root = Path(root).absolute()
    if root.resolve() != root or not root.is_dir():
        raise RuntimeError('Fixture root is missing or linked')
    stores = set()
    for directory in [root, *sorted(p for p in root.rglob('*') if p.is_dir())]:
        # Offline fixtures also create databases and fake workload records.
        # Only native monitor acquisition establishes this cleanup obligation.
        if unit_path(directory).exists() or unit_path(directory).is_symlink():
            stores.add(directory)
    # A monitor identity is an acquisition record even if its database or unit
    # file has disappeared. Never use those files' absence as a release signal.
    stores.update(p.parent for p in root.rglob('monitor-identity.json') if p.parent not in foreground)
    return sorted(stores)


class FixtureDirectory:
    """TemporaryDirectory replacement for fixtures that can acquire monitors.

    No GC finalizer may delete live controller data. Native evidence is retained,
    including after an earlier explicit removal. Ordinary offline trees expire.
    """
    def __init__(self, *, prefix):
        self.name = tempfile.mkdtemp(prefix=prefix)
        self.retain = False
        self.cleaned = False
        self.attempt = 0
        self.controllers = set()
        # Explicit foreground owners reap their own child (or run a mocked
        # serve loop). Their identity file does not imply systemd acquisition.
        self.foreground = set()

    def own(self, store):
        """Register before native acquisition, independently of surviving files."""
        directory = store.directory.absolute()
        if not directory.is_relative_to(Path(self.name)) or directory.resolve() != directory:
            raise RuntimeError('Controller is outside fixture ownership')
        self.controllers.add(directory)
        self.retain = True

    def ensure(self, store):
        self.own(store)
        return monitor.ensure(store)

    def cleanup(self):
        root = Path(self.name)
        if self.cleaned:
            return
        if not root.exists():
            raise RuntimeError('Fixture directory disappeared before cleanup')
        self.controllers.update(owned_controllers(root, foreground=self.foreground))
        native = self.retain or bool(self.controllers) or any(root.rglob('monitor-identity.json'))
        if native:
            print('FIXTURE_EVIDENCE=' + self.name, flush=True)
            self.attempt += 1
            cleanup(sorted(self.controllers), destination=root / ('fixture-cleanup-' + str(self.attempt) + '.json'))
        else:
            # Reuse TemporaryDirectory's permission recovery for owned offline
            # package trees, without constructing its unsafe-for-native finalizer.
            # This private helper propagates unresolved errors and does not chmod
            # symlink targets. Keep the read-only/outside-link regression cases.
            tempfile.TemporaryDirectory._rmtree(str(root), ignore_errors=False)
        self.cleaned = True
