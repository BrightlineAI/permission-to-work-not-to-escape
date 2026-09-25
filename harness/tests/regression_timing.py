"""Private native-test diagnostics, never imported by the installed product.

Keep the runner, ordering, assertions and deadlines unchanged. Records contain
identifiers and resource counters, never call arguments, output or exception text.
"""
from contextlib import ExitStack, contextmanager
import cProfile
from functools import wraps
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import sys
import tempfile
import time
from types import CodeType, SimpleNamespace
import unittest
from unittest.mock import patch


YARN_TARGETS = frozenset('test_product_yarn.YarnNativeTests.' + name for name in (
    'test_controller_unapproved_build_and_changed_inputs_do_not_publish',
    'test_default_public_origin_reviewed_update_and_protected_use'))
POETRY_TARGET = ('test_product_poetry.PoetryNativeTests.'
                 'test_native_legacy_and_pep735_group_import_and_revisions')
EDITABLE_TARGET = ('test_product_python_local.CombinedEditableDiscoveryTests.'
                   'test_editable_discovery_reject_cancel_and_eof_never_publish')
_active = None
_enabled = False

# Fixed source modules and builtin identifiers, never names from executed data.
PROFILE_MODULES = {
    'production': tuple('ptw.' + name for name in (
        'dependency_resolution', 'onboarding', 'policy', 'python_local',
        'python_runtime', 'workspace_policy', 'store', 'workspace', 'packages',
        'package_install', 'package_evidence', 'reassessment', 'supervisor')),
    'fixture': ('test_product_python_local', 'test_packages', 'test_workspace'),
    'diagnostic': (__name__,),
    'subprocess': ('subprocess', 'selectors'),
    'stdlib': ('pathlib', 'shutil', 'tempfile', 'json', 'json.encoder', 'json.decoder'),
}
PROFILE_BUILTINS = {
    '<built-in method posix.waitpid>': ('wait', 'posix.waitpid'),
    "<method 'poll' of 'select.poll' objects>": ('wait', 'select.poll'),
    "<method 'poll' of 'select.epoll' objects>": ('wait', 'select.epoll'),
    '<built-in method select.select>': ('wait', 'select.select'),
    '<built-in method time.sleep>': ('wait', 'time.sleep'),
    **{'<built-in method posix.' + name + '>': ('io', 'posix.' + name)
       for name in ('read', 'write', 'fsync', 'fdatasync', 'stat', 'lstat',
                    'open', 'close', 'scandir', 'mkdir', 'unlink', 'rename')},
    '<built-in method fcntl.flock>': ('io', 'fcntl.flock'),
    **{"<method '" + name + "' of 'sqlite3.Connection' objects>":
       ('io', 'sqlite3.Connection.' + name)
       for name in ('execute', 'executescript', 'commit', 'close', '__exit__')},
    **{"<method '" + name + "' of '_io." + owner + "' objects>":
       ('io', 'io.' + owner + '.' + name)
       for owner in ('BufferedReader', 'BufferedWriter', 'TextIOWrapper')
       for name in ('read', 'readinto', 'write', 'flush', 'close')},
    "<method 'update' of '_hashlib.HASH' objects>": ('hash', 'hashlib.update'),
    '<built-in method _hashlib.openssl_sha256>': ('hash', 'hashlib.sha256'),
}
PROFILE_LIMIT = 96
PROFILE_EDGE_LIMIT = 32
PROFILE_EDGE_TARGETS = frozenset(('subprocess.run', 'ptw.policy.file_sha256'))


def profile_codes():
    codes = {}

    def collect(code, category, module):
        if code in codes:
            return
        codes[code] = (category, module + '.' + code.co_qualname)
        for constant in code.co_consts:
            if isinstance(constant, CodeType):
                collect(constant, category, module)

    for category, modules in PROFILE_MODULES.items():
        for name in modules:
            module = sys.modules.get(name)
            if module is None:
                continue
            for value in vars(module).values():
                if getattr(value, '__module__', None) != name:
                    continue
                members = vars(value).values() if isinstance(value, type) else (value,)
                for member in members:
                    if isinstance(member, (staticmethod, classmethod)):
                        member = member.__func__
                    # Include original generator bodies under contextmanager wrappers.
                    while callable(member):
                        code = getattr(member, '__code__', None)
                        if isinstance(code, CodeType) and member.__module__ == name:
                            collect(code, category, name)
                        member = getattr(member, '__wrapped__', None)
    # file_sha256 delegates its streaming loop here. Retain this exact source
    # identity rather than emitting names/filenames from unknown profile entries.
    codes[hashlib.file_digest.__code__] = ('hash', 'hashlib.file_digest')
    return codes


def profile_summary(entries, codes):
    def identity(code):
        return (codes.get(code) if isinstance(code, CodeType)
                else PROFILE_BUILTINS.get(code)) or ('other', None)

    rows, categories, edges = [], {}, {}
    for entry in entries:
        category, name = identity(entry.code)
        total = categories.setdefault(category, dict(calls=0, functions=0, self_seconds=0.0))
        total['calls'] += entry.callcount
        total['functions'] += 1
        total['self_seconds'] += entry.inlinetime
        if name is not None:
            rows.append(dict(category=category, function=name, calls=entry.callcount,
                recursive_calls=entry.reccallcount, self_seconds=entry.inlinetime,
                cumulative_seconds=entry.totaltime))
        for call in entry.calls or ():
            callee_category, callee = identity(call.code)
            if callee not in PROFILE_EDGE_TARGETS and callee_category != 'hash':
                continue
            # Unknown callers collapse to one bucket per target. Never export
            # their code object's filename/name or the builtin's raw label.
            edge = edges.setdefault((name or 'other', callee), dict(
                caller=name or 'other', callee=callee, calls=0, recursive_calls=0,
                self_seconds=0.0, cumulative_seconds=0.0))
            edge['calls'] += call.callcount
            edge['recursive_calls'] += call.reccallcount
            edge['self_seconds'] += call.inlinetime
            edge['cumulative_seconds'] += call.totaltime
    rows.sort(key=lambda row: (-row['self_seconds'], row['function']))
    edges = sorted(edges.values(), key=lambda row: (
        -row['cumulative_seconds'], row['caller'], row['callee']))
    retained_edges = edges[:PROFILE_EDGE_LIMIT]
    # Share the existing row budget; caller attribution does not enlarge it.
    function_limit = PROFILE_LIMIT - len(retained_edges)
    omitted_edges = edges[PROFILE_EDGE_LIMIT:]
    return dict(functions=rows[:function_limit], categories=categories,
                omitted_functions=len(rows[function_limit:]),
                omitted_self_seconds=sum(row['self_seconds'] for row in rows[function_limit:]),
                caller_edges=retained_edges, omitted_edges=len(omitted_edges),
                omitted_edge_calls=sum(row['calls'] for row in omitted_edges),
                omitted_edge_cumulative_seconds=sum(row['cumulative_seconds'] for row in omitted_edges))


@contextmanager
def editable_profile(trace, test_id):
    if test_id != EDITABLE_TARGET:
        yield
        return
    # Do not displace another profiler, including non-callable cProfile hooks.
    if sys.getprofile() is not None:
        raise RuntimeError('Editable diagnostic requires an unused profiling hook')
    codes = profile_codes()
    profiler = cProfile.Profile(subcalls=True)
    started = time.monotonic()
    completed = False
    try:
        profiler.enable()
        yield
        completed = True
    finally:
        profiler.disable()
        elapsed = time.monotonic() - started
        trace.emit(kind='profile', event='sample', name=test_id,
                   completed=completed, elapsed_seconds=elapsed,
                   scope='current-thread-only',
                   **profile_summary(profiler.getstats(), codes))


def pressure_totals(path):
    """Bounded Linux PSI totals in microseconds; no raw text in receipts."""
    try:
        with path.open('rb') as stream:
            raw = stream.read(4097)
        if len(raw) > 4096:
            raise ValueError('oversized counter file')
        totals = {}
        for line in raw.decode('ascii').splitlines():
            fields = line.split()
            if not fields or fields[0] not in ('some', 'full'):
                continue
            values = [field[6:] for field in fields[1:] if field.startswith('total=')]
            if (fields[0] in totals or len(values) != 1 or
                    not values[0].isascii() or not values[0].isdigit()):
                raise ValueError('invalid counter')
            totals[fields[0]] = int(values[0])
        if 'some' not in totals:
            raise ValueError('missing counter')
        return {'status': 'available', 'total_us': totals}
    except (OSError, ValueError):
        return {'status': 'unavailable'}


def cpu_throttle_totals(path):
    """Read only the fixed cgroup v2 bandwidth counters, not arbitrary fields."""
    wanted = {'nr_periods', 'nr_throttled', 'throttled_usec'}
    try:
        with path.open('rb') as stream:
            raw = stream.read(4097)
        if len(raw) > 4096:
            raise ValueError('oversized counter file')
        totals = {}
        for line in raw.decode('ascii').splitlines():
            fields = line.split()
            if not fields or fields[0] not in wanted:
                continue
            if (len(fields) != 2 or fields[0] in totals or
                    not fields[1].isascii() or not fields[1].isdigit()):
                raise ValueError('invalid counter')
            totals[fields[0]] = int(fields[1])
        if totals.keys() != wanted:
            raise ValueError('missing counters')
        return {'status': 'available', 'totals': totals}
    except (OSError, ValueError):
        return {'status': 'unavailable'}


def pressure_snapshot():
    # System counters include unrelated work. Current cgroup counters include
    # only its subtree, not detached services assigned to sibling cgroups.
    system = Path('/proc/pressure')
    result = {'system': {name: pressure_totals(system / name) for name in ('cpu', 'io')}}
    try:
        with Path('/proc/self/cgroup').open('rb') as stream:
            raw = stream.read(4097)
        if len(raw) > 4096:
            raise ValueError('oversized membership')
        groups = [line[3:] for line in raw.decode('ascii').splitlines() if line.startswith('0::/')]
        if len(groups) != 1 or '..' in Path(groups[0]).parts:
            raise ValueError('invalid membership')
        root = Path('/sys/fs/cgroup')
        group = (root / groups[0].lstrip('/')).resolve()
        if not group.is_relative_to(root):
            raise ValueError('escaping membership')
        result['cgroup'] = {name: pressure_totals(group / (name + '.pressure')) for name in ('cpu', 'io')}
        result['cgroup']['cpu_stat'] = cpu_throttle_totals(group / 'cpu.stat')
        # Bind paired observations without exporting operator/unit names.
        result['cgroup_id'] = hashlib.sha256(groups[0].encode()).hexdigest()
    except (OSError, ValueError):
        result['cgroup'] = {'status': 'unavailable'}
    return result


class Trace:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.sequence = itertools.count()
        # Separate files prevent terminal children from interleaving writes.
        self.path = self.directory / ('timing-' + str(os.getpid()) + '.jsonl')

    def emit(self, **fields):
        own = resource.getrusage(resource.RUSAGE_SELF)
        children = resource.getrusage(resource.RUSAGE_CHILDREN)
        record = dict(pid=os.getpid(), monotonic_ns=time.monotonic_ns(),
                      cpu_self_user=own.ru_utime, cpu_self_system=own.ru_stime,
                      cpu_children_user=children.ru_utime,
                      cpu_children_system=children.ru_stime, **fields)
        for scope, usage in (('self', own), ('children', children)):
            for name in ('ru_inblock', 'ru_oublock', 'ru_minflt', 'ru_majflt',
                         'ru_nvcsw', 'ru_nivcsw'):
                record[scope + '_' + name] = getattr(usage, name)
        if fields.get('event') in ('start', 'end') and (
                fields.get('kind') == 'suite' or
                fields.get('kind') == 'test' and fields.get('name') in (EDITABLE_TARGET, POETRY_TARGET)):
            record['pressure'] = pressure_snapshot()
        # Close each append so completed records survive process interruption.
        with self.path.open('a') as stream:
            stream.write(json.dumps(record, sort_keys=True) + '\n')

    @contextmanager
    def span(self, kind, name, **metadata):
        span = next(self.sequence)
        fields = dict(span=span, kind=kind, name=name, **metadata)
        self.emit(event='start', **fields)
        outcome = {'outcome': 'completed'}
        try:
            yield outcome
        except BaseException as exc:
            outcome = {'outcome': 'skipped' if isinstance(exc, unittest.SkipTest) else
                       'interrupted' if isinstance(exc, KeyboardInterrupt) else 'error',
                       'exception_type': type(exc).__name__}
            if isinstance(exc, SystemExit):
                outcome.update(outcome='exited', exit_code=0 if exc.code is None else
                               exc.code if type(exc.code) is int else 1)
            raise
        finally:
            self.emit(event='end', **fields, **outcome)


def counts(result):
    return {name: len(getattr(result, name, ())) for name in
            ('failures', 'errors', 'skipped', 'expectedFailures', 'unexpectedSuccesses')}


def caller_fields(codes):
    """Bounded source-code identities only; never format frames or read locals."""
    frame = sys._getframe(1)
    callers = []
    try:
        for _ in range(32):
            if frame is None:
                break
            if frame.f_code in codes:
                callers.append({'function': codes[frame.f_code], 'line': frame.f_lineno})
            frame = frame.f_back
        return {'callers': callers, 'caller_scan_truncated': frame is not None}
    finally:
        del frame


def measured(trace, kind, name, function, *, result=None, cleanup=None, caller_codes=None):
    @wraps(function)
    def run(*args, **kwargs):
        before = counts(result)
        metadata = caller_fields(caller_codes) if caller_codes is not None else {}
        with trace.span(kind, name, **metadata) as outcome:
            returned = function(*args, **kwargs)
            changes = {key: value - before[key] for key, value in counts(result).items()}
            if result is not None:
                outcome.update(result_counts=changes, outcome=next(
                    (key for key, value in changes.items() if value), 'success'))
            if cleanup is not None and getattr(cleanup, 'tearDown_exceptions', ()):
                outcome['outcome'] = 'errors'
            return returned
    return run


@contextmanager
def yarn_phases(trace, test_id):
    if test_id not in YARN_TARGETS:
        yield
        return
    from ptw import packages, yarn_tool
    with ExitStack() as stack:
        for owner, names in ((yarn_tool, ('verified', 'node_identity', 'payload', 'parse_lock', 'run')),
                             (packages.PackageControl, ('install',))):
            for name in names:
                label = owner.__name__ + '.' + name
                stack.enter_context(patch.object(owner, name,
                    measured(trace, 'phase', test_id + ':' + label, getattr(owner, name))))
        yield


@contextmanager
def poetry_phases(trace, test_id):
    if test_id != POETRY_TARGET:
        yield
        return
    from ptw import poetry_tool
    with ExitStack() as stack:
        for name in ('verified', 'payload', 'identify', 'run'):
            stack.enter_context(patch.object(poetry_tool, name,
                measured(trace, 'phase', test_id + ':ptw.poetry_tool.' + name,
                         getattr(poetry_tool, name))))
        # A module-local view leaves subprocess.run in interpreter identification
        # and other modules untouched. This span is just Poetry's native wait;
        # its two integrity checks remain separate nested spans inside run.
        stack.enter_context(patch.object(poetry_tool, 'subprocess', SimpleNamespace(
            run=poetry_wait(trace, test_id, poetry_tool.subprocess.run))))
        yield


def poetry_wait(trace, test_id, function):
    """Pair the existing native wait with child clocks, without new mounts/files.

    Only this diagnostic target's fixed Python -c boundary is instrumented.
    The original script is appended unchanged. A private atexit closure emits
    clocks through captured stderr, then the parent removes just those frames.
    This includes Python shutdown, not only the solver body, and is not proof
    of successful execution. Signals or os._exit can leave an incomplete pair.
    """
    from ptw.poetry_export import EXPORT, INSPECT
    from ptw.poetry_resolution import SOLVE
    from ptw.poetry_revision import EDIT
    scripts = {'import sys; sys.path.insert(0,"/poetry-tools");\n' + script: name
               for name, script in (('inspect', INSPECT), ('export', EXPORT),
                                    ('solve', SOLVE), ('edit', EDIT))}

    @wraps(function)
    def run(command, **kwargs):
        call = next(trace.sequence)
        operation = scripts.get(command[-2], 'other') if len(command) >= 2 else 'other'
        marker = '\x1ePTW-CLOCK-' + str(os.getpid()) + '-' + str(call) + ':'
        pattern = re.compile(re.escape(marker) + r'(start|end):([0-9]{1,20}):([0-9]{1,20})\x1f')
        samples = []
        malformed = False

        def collect(output):
            nonlocal malformed
            if output is None:
                return None
            binary = isinstance(output, bytes)
            value = output.decode('latin1') if binary else output
            def remove(match):
                # Retain at most three rows: a third makes duplication explicit.
                if len(samples) < 3:
                    samples.append(dict(event=match[1], monotonic_ns=int(match[2]),
                                        cpu_self_ns=int(match[3])))
                return ''
            cleaned, matched = pattern.subn(remove, value)
            malformed = value.count(marker) != matched
            return cleaned.encode('latin1') if binary else cleaned

        with trace.span('phase', test_id + ':ptw.poetry_tool.subprocess.run',
                        call=call, operation=operation):
            try:
                if command[-6:-2] != ['-I', '-S', '-B', '-c']:
                    # The known boundary is [..., -I, -S, -B, -c, script, config].
                    # Fail visibly if that interface changes; never run a fallback.
                    raise ValueError('Poetry diagnostic command shape changed')
                copied = list(command)
                header = ('import atexit, os, time\n'
                    'def emit(event):\n'
                    '    os.write(2, (' + repr(marker) + ' + event + ":" + '
                    'str(time.monotonic_ns()) + ":" + str(time.process_time_ns()) + "\\x1f").encode("ascii"))\n'
                    'atexit.register(emit, "end")\n'
                    'emit("start")\n')
                copied[-2] = 'exec(' + repr(header) + ', {})\n' + command[-2]
                result = function(copied, **kwargs)
                result.stderr = collect(result.stderr)
                result.args = command
                return result
            except subprocess.TimeoutExpired as exc:
                exc.stderr = collect(exc.stderr)
                exc.cmd = command
                raise
            finally:
                complete = (not malformed and [row['event'] for row in samples] == ['start', 'end'] and
                    all(samples[1][key] >= samples[0][key] for key in ('monotonic_ns', 'cpu_self_ns')))
                trace.emit(kind='child', event='sample', name=test_id + ':poetry-python',
                           call=call, operation=operation,
                           status='complete' if complete else 'incomplete', samples=samples)
    return run


@contextmanager
def editable_phases(trace, test_id):
    if test_id != EDITABLE_TARGET:
        yield
        return
    from ptw import (dependency_resolution, onboarding, policy, python_local,
                     python_runtime, workspace_policy)
    from ptw.packages import PackageControl
    from ptw.store import Store
    from ptw.workspace import Workspace
    original_locked = Store.locked
    # Capture exact code objects before installing wrappers. Labels come only
    # from this fixed source allowlist, not stack filenames, arguments or locals.
    codes = {}
    for module in (dependency_resolution, onboarding, policy, python_local,
                   python_runtime, workspace_policy):
        for name, function in vars(module).items():
            code = getattr(function, '__code__', None)
            if isinstance(code, CodeType) and function.__module__ == module.__name__:
                codes[code] = module.__name__ + '.' + name
    for function in (Store.activate, Store.register_preparation, Workspace.integrity,
                     PackageControl._install):
        codes[function.__code__] = function.__module__ + '.' + function.__qualname__

    @wraps(original_locked)
    def locked(*args, **kwargs):
        manager = original_locked(*args, **kwargs)

        class Lock:
            # Time acquisition and release separately, not the caller's body.
            # Forward the original exit result, including exception suppression.
            def __enter__(self):
                return measured(trace, 'phase', test_id + ':ptw.store.Store.locked.enter',
                                type(manager).__enter__)(manager)

            def __exit__(self, *exc):
                return measured(trace, 'phase', test_id + ':ptw.store.Store.locked.exit',
                                type(manager).__exit__)(manager, *exc)

        return Lock()

    with ExitStack() as stack:
        for owner, names in ((onboarding, ('setup', 'compile_policy')),
                             (policy, ('compile_policy',)), (python_runtime, ('identify',))):
            for name in names:
                stack.enter_context(patch.object(owner, name,
                    measured(trace, 'phase', test_id + ':' + owner.__name__ + '.' + name,
                             getattr(owner, name),
                             caller_codes=codes if owner is python_runtime else None)))
        stack.enter_context(patch.object(Store, 'locked', locked))
        yield


def active_directory():
    return str(_active.directory) if _active is not None else None


@contextmanager
def child_phases(directory, test_id):
    """Explicit hook in the synthetic terminal fixture, not an environment hook."""
    if directory is None or test_id not in YARN_TARGETS:
        yield
        return
    trace = Trace(directory)
    with trace.span('terminal', test_id), yarn_phases(trace, test_id):
        yield


def cases(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from cases(item)
        else:
            yield item


@contextmanager
def instrument(suite, result, trace):
    """Wrap selected instances and their fixtures; restore even on interruption."""
    selected = list(cases(suite))
    classes = dict.fromkeys(type(test) for test in selected)
    # Bind all originals before patching, including inherited fixture methods.
    fixtures = [(cls, name, getattr(cls, name)) for cls in classes
                for name in ('setUpClass', 'tearDownClass', 'doClassCleanups')]
    with ExitStack() as stack:
        for cls, name, original in fixtures:
            wrapped = measured(trace, 'fixture', cls.__module__ + '.' + cls.__qualname__ + '.' + name,
                               original, cleanup=cls if name == 'doClassCleanups' else None)

            def fixture(ignored_cls, method=wrapped):
                return method()

            stack.enter_context(patch.object(cls, name, classmethod(fixture)))
        for test in {id(test): test for test in selected}.values():
            original = test.run

            def run(result=None, original=original, test_id=test.id()):
                with yarn_phases(trace, test_id), poetry_phases(trace, test_id), \
                     editable_profile(trace, test_id), editable_phases(trace, test_id):
                    return measured(trace, 'test', test_id, original, result=result)(result)

            stack.enter_context(patch.object(test, 'run', run))
        yield


def source_receipt(directory):
    root = Path(__file__).resolve().parents[1]
    paths = [p for folder in ('ptw', 'tests', 'scripts') for p in (root / folder).rglob('*.py')]
    paths += [root / 'requirements.lock', root / 'PRODUCT_ACCEPTANCE.json']
    hashes = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}
    (directory / 'source.json').write_text(json.dumps(hashes, sort_keys=True, indent=2) + '\n')


def enable():
    """Activate at discovery; instrument the eventual full or focused root suite."""
    global _enabled
    if _enabled or os.environ.get('PTW_LINUX_TESTS') != '1':
        return
    scripts = str(Path(__file__).resolve().parents[1] / 'scripts')
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    from native_receipt import enable as enable_receipts
    enable_receipts()
    _enabled = True
    original = unittest.TestSuite.run

    @wraps(original)
    def run(suite, result, debug=False):
        global _active
        if _active is not None:
            return original(suite, result, debug)
        directory = Path(tempfile.mkdtemp(prefix='ptw-regression-timing-'))
        print('REGRESSION_TIMING_EVIDENCE ' + str(directory), flush=True)
        trace = Trace(directory)
        _active = trace
        try:
            with trace.span('suite', 'unittest') as outcome:
                source_receipt(directory)
                with instrument(suite, result, trace):
                    returned = original(suite, result, debug)
                outcome.update(outcome='success' if result.wasSuccessful() else 'failed',
                               result_counts=counts(result), tests_run=result.testsRun)
                return returned
        finally:
            _active = None

    unittest.TestSuite.run = run
