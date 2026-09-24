"""Private native-test diagnostics, never imported by the installed product.

Keep the runner, ordering, assertions and deadlines unchanged. Records contain
identifiers and resource counters, never call arguments, output or exception text.
"""
from contextlib import ExitStack, contextmanager
from functools import wraps
import hashlib
import itertools
import json
import os
from pathlib import Path
import resource
import sys
import tempfile
import time
from types import SimpleNamespace
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
        # Close each append so completed records survive process interruption.
        with self.path.open('a') as stream:
            stream.write(json.dumps(record, sort_keys=True) + '\n')

    @contextmanager
    def span(self, kind, name):
        span = next(self.sequence)
        fields = dict(span=span, kind=kind, name=name)
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


def measured(trace, kind, name, function, *, result=None, cleanup=None):
    @wraps(function)
    def run(*args, **kwargs):
        before = counts(result)
        with trace.span(kind, name) as outcome:
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
            run=measured(trace, 'phase', test_id + ':ptw.poetry_tool.subprocess.run',
                         poetry_tool.subprocess.run))))
        yield


@contextmanager
def editable_phases(trace, test_id):
    if test_id != EDITABLE_TARGET:
        yield
        return
    from ptw import onboarding, policy, python_runtime
    from ptw.store import Store
    original_locked = Store.locked

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
                             getattr(owner, name))))
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
                     editable_phases(trace, test_id):
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
