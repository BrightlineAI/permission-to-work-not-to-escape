"""Record the actual outer unittest runner; consume only exact full native suites.

No tests are executed by discovery/validation. Receipts are consistency evidence,
not signatures: an independent operator still has to establish their provenance.
"""
from collections import Counter
from contextlib import ExitStack
from functools import wraps
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from evidence_io import artifact, digest, fresh, load, reference, require, save, seconds

REPO = Path(__file__).resolve().parents[2]
_enabled = False
_active = False


def sources(repo=REPO):
    repo = Path(repo)
    excluded = {'validation', '__pycache__', '.pytest_cache', 'build', 'dist'}
    paths = [p for p in (repo / 'harness').rglob('*') if p.is_file() and
             not excluded.intersection(p.relative_to(repo).parts) and
             not any(part.endswith('.egg-info') for part in p.parts) and
             p.suffix not in ('.pyc', '.pyo')]
    paths += [repo / n for n in ('README.md', 'install.sh', 'MANIFEST.sha256') if (repo / n).is_file()]
    paths += [p for p in (repo / '.github/workflows').glob('*') if p.is_file()]
    require(all(not p.is_symlink() for p in paths), 'Linked maintained source')
    return {str(p.relative_to(repo)): digest(p) for p in sorted(paths)}


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def receipt_parent(repo=REPO, source=None):
    base = Path(os.environ.get('XDG_STATE_HOME', str(Path.home() / '.local/state')))
    require(base.is_absolute(), 'XDG_STATE_HOME must be absolute')
    return base / 'ptw/native-receipts' / fingerprint(str(Path(repo).resolve())) / fingerprint(
        sources(repo) if source is None else source)


def environment():
    import ptw
    tools = {}
    for name in ('nono', 'bwrap', 'systemd-run', 'systemctl', 'uv', 'node', 'npm', 'codex'):
        path = shutil.which(name)
        tools[name] = None if path is None else {'path': str(Path(path).resolve()), 'sha256': digest(path)}
    distributions = list(importlib.metadata.distributions())
    metadata = {}
    distribution_metadata = []
    for distribution in distributions:
        # Read distribution metadata and editable import hooks, never user configuration.
        for item in distribution.files or ():
            if str(item).endswith(('.dist-info/METADATA', '.dist-info/direct_url.json', '.pth')) or (
                    str(item).startswith('__editable__') and str(item).endswith('.py')):
                path = Path(distribution.locate_file(item)).absolute()
                metadata[str(path)] = digest(path)
                # Bundled vendors (notably setuptools) also ship METADATA.
                # Hash those files, but only count the distribution's own
                # top-level metadata as an installed distribution identity.
                if len(item.parts) == 2 and str(item).endswith('.dist-info/METADATA'):
                    distribution_metadata.append(str(path))
    return {'host': platform.node(), 'platform': platform.platform(),
            'python': sys.version, 'executable': str(Path(sys.executable).absolute()),
            'interpreter_sha256': digest(sys.executable), 'prefix': sys.prefix,
            'ptw_file': str(Path(ptw.__file__).resolve()),
            'distributions': sorted([d.metadata['Name'], d.version] for d in distributions),
            'distribution_metadata': sorted(distribution_metadata),
            'metadata_sha256': metadata,
            'tools': tools, 'native_enabled': os.environ.get('PTW_LINUX_TESTS') == '1'}


def verify_environment(identity, repo):
    """Consumer may use another interpreter; independently hash the retained source environment.

    Never execute an interpreter supplied by an evidence record. Runtime identity
    was measured by the original runner and is checked against retained files.
    """
    require(identity.get('host') == platform.node() and identity.get('platform') == platform.platform(),
            'Native execution host changed')
    require(identity.get('native_enabled') is True, 'Native checks were disabled')
    require(identity.get('ptw_file') == str(Path(repo).resolve() / 'harness/ptw/__init__.py'),
            'Native tests imported another checkout')
    prefix = Path(identity.get('prefix', ''))
    executable = Path(identity.get('executable', ''))
    require(prefix.is_absolute() and executable.is_absolute() and executable.is_relative_to(prefix),
            'Native source interpreter must be in its retained isolated environment')
    require(digest(executable) == identity.get('interpreter_sha256'), 'Native interpreter changed')
    metadata = identity.get('metadata_sha256')
    require(isinstance(metadata, dict) and metadata, 'Missing native installed metadata')
    for name, expected in metadata.items():
        path = Path(name)
        require(path.is_absolute() and path.resolve().is_relative_to(prefix.resolve()) and
                not path.is_symlink() and digest(path) == expected, 'Native installed metadata changed')
    from email.parser import Parser
    actual = []
    metadata_roots = set()
    identities = identity.get('distribution_metadata')
    require(isinstance(identities, list) and identities and
            len(identities) == len(set(identities)), 'Missing or duplicate native distribution metadata')
    for name in identities:
        require(name in metadata and name.endswith('.dist-info/METADATA'),
                'Native distribution metadata was not hashed')
        values = Parser().parsestr(Path(name).read_text(), headersonly=True)
        actual.append([values['Name'], values['Version']])
        metadata_roots.add(Path(name).parent.parent)
    require(sorted(actual) == identity.get('distributions'), 'Native distribution inventory changed')
    found = {str(p) for root in metadata_roots for p in root.glob('*.dist-info/METADATA')}
    require(found == set(identities),
            'Native distribution inventory incomplete')
    versions = {re.sub(r'[-_.]+', '-', name).lower(): version for name, version in actual}
    pins = re.findall(r'^([A-Za-z0-9_.-]+)==([^\s\\;]+)',
                      (Path(repo) / 'harness/requirements.lock').read_text(), re.M)
    require(pins and all(versions.get(re.sub(r'[-_.]+', '-', n).lower()) == v for n, v in pins),
            'Native dependencies differ from lock')
    require('permission-to-work-harness' in versions, 'Missing native source installation')
    tools = identity.get('tools', {})
    require(set(tools) == {'nono', 'bwrap', 'systemd-run', 'systemctl', 'uv', 'node', 'npm', 'codex'},
            'Native prerequisite inventory incomplete')
    for tool in tools.values():
        require(isinstance(tool, dict) and digest(tool['path']) == tool.get('sha256'),
                'Native prerequisite missing or changed')


def cases(suite):
    if isinstance(suite, unittest.TestSuite):
        for test in suite:
            yield from cases(test)
    else:
        yield suite


def inventory(suite):
    return [test.id() for test in cases(suite)]


def discovery_inventory(repo):
    """Import test definitions only; never run fixtures or the test runner."""
    loader = unittest.TestLoader()
    suite = loader.discover(str(Path(repo) / 'harness/tests'), pattern='test*.py')
    require(not loader.errors, 'Native discovery failed: ' + '\n'.join(loader.errors))
    return inventory(suite)


def discover(repo=REPO, *, identity=None):
    """Discover with retained source dependencies, even from a bare consumer Python.

    The executable is the caller's, never a path supplied by evidence. An isolated
    child imports the current checkout and verified source-environment package
    directories without evaluating their editable hooks or site startup files.
    Installed-user environments are not involved.
    """
    repo = Path(repo).resolve()
    if identity is None:
        attempts = [load(p / 'attempt.json') for p in receipt_parent(repo).glob('attempt-*')]
        require(attempts, 'No current full native receipt; run documented native discovery first')
        latest_attempt = max(attempts, key=lambda row: seconds(row.get('started_epoch'), 'native start'))
        require(latest_attempt.get('checkout') == str(repo) and
                latest_attempt.get('source_before') == sources(repo), 'Native source drift')
        identity = latest_attempt.get('environment', {})
    verify_environment(identity, repo)
    require(identity.get('python') == sys.version,
            'Native discovery requires the same Python version as the retained source environment')
    roots = sorted({str(Path(p).parent.parent) for p in identity['distribution_metadata']})
    driver = ('import json,sys; '
              'sys.path[:0]=json.loads(sys.argv[1]); '
              'from native_receipt import discovery_inventory; '
              'print(json.dumps(discovery_inventory(sys.argv[2])))')
    paths = [str(repo / 'harness'), str(repo / 'harness/scripts'), *roots]
    # -I -S excludes the consumer's site packages and all ambient Python paths.
    result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', driver,
                             json.dumps(paths), str(repo)], cwd=repo,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
    require(result.returncode == 0, 'Native discovery failed: ' + result.stderr)
    selected = json.loads(result.stdout)
    require(isinstance(selected, list) and selected and all(isinstance(n, str) and n for n in selected),
            'Invalid native discovery inventory')
    return selected


class Tee:
    def __init__(self, stream, log):
        self.stream, self.log = stream, log

    def write(self, text):
        self.log.write(text)
        self.log.flush()
        return self.stream.write(text)

    def flush(self):
        self.log.flush()
        return self.stream.flush()

    def writeln(self, text=''):
        self.write(text + '\n')

    def __getattr__(self, name):
        return getattr(self.stream, name)


def run_recorded(runner, suite, original, *, repo=REPO, parent=None):
    """Preserve the runner and its result object; observe result callbacks only."""
    before = sources(repo)
    parent = receipt_parent(repo, before) if parent is None else Path(parent)
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix='attempt-', dir=parent))
    selected = inventory(suite)
    attempt = {'schema': 1, 'complete': False, 'checkout': str(Path(repo).resolve()),
               'started_epoch': time.time(), 'source_before': before,
               'environment': environment(), 'inventory': selected}
    save(directory / 'attempt.json', attempt)
    print('NATIVE_SUITE_EVIDENCE ' + str(directory), flush=True)
    started = time.monotonic()
    make_result = runner._makeResult
    result = None
    with (directory / 'unittest.log').open('x') as log, (directory / 'outcomes.jsonl').open('x') as events:
        with ExitStack() as stack:
            stack.enter_context(patch.object(runner, 'stream', Tee(runner.stream, log)))

            def emit(event, test, **fields):
                events.write(json.dumps(dict(event=event, test_id=test.id(),
                    monotonic=time.monotonic(), **fields), sort_keys=True) + '\n')
                events.flush()

            def make():
                nonlocal result
                result = make_result()
                for name in ('startTest', 'stopTest', 'addSuccess', 'addFailure', 'addError',
                             'addSkip', 'addExpectedFailure', 'addUnexpectedSuccess', 'addSubTest'):
                    method = getattr(result, name)

                    def observed(test, *args, name=name, method=method):
                        fields = {}
                        if name == 'addSubTest':
                            fields = {'subtest_id': args[0].id(), 'passed': args[1] is None}
                        emit(name, test, **fields)
                        return method(test, *args)

                    stack.enter_context(patch.object(result, name, observed))
                return result

            stack.enter_context(patch.object(runner, '_makeResult', make))
            try:
                returned = original(runner, suite)
                require(returned is result, 'Runner replaced its result')
                log.flush()
                events.flush()
                after = sources(repo)
                counts = {name: len(getattr(result, name)) for name in
                          ('failures', 'errors', 'skipped', 'expectedFailures', 'unexpectedSuccesses')}
                complete = dict(attempt, complete=True, ended_epoch=time.time(),
                    seconds=time.monotonic() - started, source_after=after,
                    environment_after=environment(), tests_run=result.testsRun, **counts,
                    passed=result.wasSuccessful() and not any(counts.values()) and before == after,
                    output=reference(directory, directory / 'unittest.log'),
                    outcomes=reference(directory, directory / 'outcomes.jsonl'))
                save(directory / 'complete.json', complete)
                return returned
            except BaseException as exc:
                save(directory / 'interrupted.json', {'error_type': type(exc).__name__,
                     'ended_epoch': time.time(), 'seconds': time.monotonic() - started})
                raise


def enable():
    global _enabled
    if _enabled or os.environ.get('PTW_LINUX_TESTS') != '1':
        return
    _enabled = True
    original = unittest.TextTestRunner.run

    @wraps(original)
    def run(runner, suite):
        global _active
        if _active:
            return original(runner, suite)
        _active = True
        try:
            return run_recorded(runner, suite, original)
        finally:
            _active = False

    unittest.TextTestRunner.run = run


def verify(directory, *, repo=REPO, expected=None, identity=None, now=None):
    directory = Path(directory)
    require(not directory.is_symlink(), 'Linked native receipt')
    begin = load(directory / 'attempt.json')
    end = load(directory / 'complete.json')
    require(type(begin.get('schema')) is int and begin['schema'] == 1 and begin.get('complete') is False and
            end.get('complete') is True, 'Incomplete native receipt')
    for key, value in begin.items():
        if key != 'complete':
            require(end.get(key) == value, 'Native attempt contradicted: ' + key)
    fresh(begin.get('started_epoch'), now=now)
    fresh(end.get('ended_epoch'), now=now)
    require(begin['started_epoch'] <= end['ended_epoch'], 'Native clock reversed')
    require(seconds(end.get('seconds'), 'native duration') <= end['ended_epoch'] - begin['started_epoch'],
            'Native duration contradicts timestamps')
    require(end.get('checkout') == str(Path(repo).resolve()), 'Wrong native checkout')
    require(end.get('source_before') == end.get('source_after') == sources(repo), 'Native source drift')
    require(end.get('environment') == end.get('environment_after'), 'Native environment changed during run')
    if identity is None:
        verify_environment(end['environment'], repo)
    else:
        require(end.get('environment') == identity and identity.get('native_enabled') is True,
                'Native environment mismatch')
    expected = discover(repo, identity=end['environment']) if expected is None else expected
    require(Counter(end.get('inventory', [])) == Counter(expected), 'Incomplete native inventory')
    require(type(end.get('tests_run')) is int and end['tests_run'] == len(expected) and len(expected) >= 242,
            'Incomplete native execution')
    require(end.get('passed') is True and all(type(end.get(n)) is int and end[n] == 0 for n in
            ('failures', 'errors', 'skipped', 'expectedFailures', 'unexpectedSuccesses')), 'Native suite did not pass')
    log = artifact(directory, end.get('output')).read_text()
    summaries = re.findall(r'^Ran (\d+) tests? in [^\n]+\n\s*\n(OK|FAILED[^\n]*)\s*$', log, re.M)
    require(len(summaries) == 1 and summaries[0] == (str(len(expected)), 'OK') and
            log.rstrip().endswith('OK'), 'Native runner log contradicts counts')
    outcomes = [json.loads(line) for line in artifact(directory, end.get('outcomes')).read_text().splitlines()]
    # Zero skips/errors requires every selected occurrence to start, succeed, and stop.
    # Subtests may add successful events between start and success.
    started, succeeded, stopped = [], [], []
    active = None
    success = False
    previous = 0
    for event in outcomes:
        instant = seconds(event.get('monotonic'), 'native outcome')
        require(instant >= previous, 'Native outcome clock reversed')
        previous = instant
        kind, name = event.get('event'), event.get('test_id')
        if kind == 'startTest':
            require(active is None, 'Overlapping native test events')
            active, success = name, False
            started.append(name)
        elif kind == 'addSuccess':
            require(active == name and not success, 'Invalid native success event')
            success = True
            succeeded.append(name)
        elif kind == 'stopTest':
            require(active == name and success, 'Missing native success')
            stopped.append(name)
            active = None
        else:
            require(kind == 'addSubTest' and active == name and event.get('passed') is True,
                    'Failed or unexpected native outcome')
    require(active is None and started == succeeded == stopped == end['inventory'], 'Incomplete native outcomes')
    return end


def latest(*, repo=REPO, parent=None, expected=None, identity=None):
    """A later failed/incomplete full run supersedes an earlier pass."""
    parent = receipt_parent(repo) if parent is None else Path(parent)
    expected = discover(repo) if expected is None else expected
    candidates = []
    for directory in parent.glob('attempt-*'):
        begin = load(directory / 'attempt.json')
        if Counter(begin.get('inventory', [])) == Counter(expected):
            candidates.append((begin['started_epoch'], directory))
    require(candidates, 'No current full native receipt; run documented native discovery first')
    directory = max(candidates)[1]
    return directory, verify(directory, repo=repo, expected=expected, identity=identity)


def retain(out, *, repo=REPO):
    directory, receipt = latest(repo=repo)
    target = Path(out) / 'native-suite'
    shutil.copytree(directory, target, symlinks=False)
    verify(target, repo=repo)
    save(target / 'provenance.json', {'original_directory': str(directory),
         'original_complete_sha256': digest(directory / 'complete.json')})
    # References in the standalone original record stay unchanged. The summary
    # record has references relative to the full product evidence root.
    summary = {k: receipt[k] for k in ('passed', 'tests_run', 'failures', 'errors', 'skipped')}
    save(target / 'record.json', dict(summary,
         output=reference(out, target / receipt['output']['path']),
         receipt=reference(out, target / 'complete.json')))
    return dict(summary, record=reference(out, target / 'record.json'))
