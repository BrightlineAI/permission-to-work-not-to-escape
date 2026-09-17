#!/usr/bin/env python3
"""Native dependency subset journeys, with explicit coverage and no model calls."""
import argparse
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch

from ptw import onboarding
from ptw.monitor import ensure, remove
from ptw.policy import load, save
from ptw.store import Store
from ptw.supervisor import Supervisor
from ptw.workflow import dispatch
from ptw.workspace import request


CASES = ('new-python', 'existing-python', 'new-node', 'existing-node',
         'new-typescript', 'existing-typescript', 'existing-mixed-python-node', 'existing-workspace')


def journey(out, case):
    fixture = Path(__file__).resolve().parents[1] / 'examples/product-ecosystems'
    repo = out / 'repo'
    repo.mkdir(parents=True)
    language = 'mixed' if 'mixed' in case else case.split('-', 1)[1]
    roots = [('python', 'backend'), ('typescript', 'frontend')] if language == 'mixed' else [(language, '')]
    editable = []
    pending_sources = []
    for kind, root in roots:
        if case.startswith('new-'):
            # New project starts with declarations only. Application sources are
            # created through the broker after setup, not written around it.
            for path in (fixture / kind).iterdir():
                if path.is_file():
                    shutil.copyfile(path, repo / path.name)
            pending_sources = [p for p in (fixture / kind).rglob('*') if p.is_file() and p.parent != fixture / kind]
        else:
            shutil.copytree(fixture / kind, repo / root, dirs_exist_ok=True)
            if kind == 'typescript':
                (repo / root / 'dist').mkdir()
        editable.extend(str(Path(root) / name) for name in
                        (('src', 'tests') if kind == 'python' else ('src', 'dist') if kind == 'typescript' else
                         ('src', 'packages/math/src') if kind == 'workspace' else ('src',)))
    sensitive = repo / '.env'
    sensitive.write_text('SYNTHETIC_PRIVATE_FIXTURE_DO_NOT_READ\n')
    original = hashlib.sha256(sensitive.read_bytes()).hexdigest()
    (repo / 'README.md').write_text('Existing project history\n' if case.startswith('existing-') else 'New fixture\n')
    args = SimpleNamespace(language='javascript' if language in ('node', 'workspace') else language,
        goal='Run addition imports/tests/builds; never access .env', editable=','.join(editable), files='',
        warn_at=None, stop_at=None, history=None, model_proposal=False)
    state = out / 'operator'
    state.mkdir(mode=0o700)
    transcript = io.StringIO()
    started = time.monotonic()
    # This tests the real typed setup and controller. Only login and human input
    # are replaced: no model is invoked, and approval applies to these fixtures.
    with patch('ptw.codex.require_login'), patch('sys.stdin.isatty', return_value=True), \
            patch('builtins.input', return_value='yes'), redirect_stdout(transcript):
        record = onboarding.setup(repo, state, args)
    (out / 'review.txt').write_text(transcript.getvalue())
    store = Store(record['state'])
    results = {'setup_seconds': time.monotonic() - started, 'installs': [], 'commands': []}
    try:
        ensure(store)
        session = store.register(record['project'], 'work')
        bundle = load(record['bundle'])
        inv = bundle['inventory']
        results['source_creates'] = []
        mapping = {entry['path']: resource for resource, entry in inv['resources'].items()}
        for index, path in enumerate(pending_sources):
            local = path.relative_to(fixture / language)
            resource = mapping[local.parts[0]]
            result = dispatch(store, session, 'create-' + str(index),
                              request('create', resource, str(Path(*local.parts[1:])), content=path.read_text()))
            results['source_creates'].append(result)
            if not result.get('allowed'):
                raise AssertionError('Protected source creation failed')
        sets = []
        for resource, entry in inv['resources'].items():
            name = Path(entry['path']).name
            if name in ('ptw-requirements.txt', 'package-lock.json'):
                ecosystem = 'pypi' if name == 'ptw-requirements.txt' else 'npm'
                result = dispatch(store, session, 'install-' + resource, request('install', resource, content=ecosystem))
                results['installs'].append(result)
                if not result.get('allowed'):
                    raise AssertionError('Dependency installation failed: ' + result.get('reason', 'unknown'))
                sets.append(result['package_set'])
        # Build precedes test; Python also performs an actual nonempty unittest run.
        commands = sorted(bundle['policy']['project']['commands'], key=lambda c: ('test' in c['id'], c['id']))
        for command in commands:
            result = dispatch(store, session, 'command-' + command['id'],
                              request('run', command['id'], content=json.dumps({'package_sets': sets})))
            results['commands'].append({'command': command['id'], 'result': result})
            if not result.get('allowed') or result.get('exit_code') != 0:
                raise AssertionError('Protected command failed: ' + command['id'])
        if not any('test' in c['command'] for c in results['commands']):
            raise AssertionError('No useful test command ran')
        denied = dispatch(store, session, 'outside', request('read', '.env'))
        results['denial'] = denied
        if denied.get('allowed') or hashlib.sha256(sensitive.read_bytes()).hexdigest() != original:
            raise AssertionError('Forbidden resource was exposed or changed')
        for kind, root in roots:
            if kind == 'typescript' and not (repo / root / 'dist/app.js').is_file():
                raise AssertionError('No compiled TypeScript artifact was published')
        results['passed'] = True
    finally:
        try:
            store.stop(record['project'])
            Supervisor(store).reconcile()
            remove(store)
        finally:
            save(out / 'journey.json', results)
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--case', choices=CASES, action='append')
    args = parser.parse_args()
    out = args.out.absolute()
    out.mkdir(parents=True, mode=0o700, exist_ok=False)
    source = Path(__file__).resolve().parents[1]
    report = {'passed': False, 'kind': 'scripted native dependency subset; no model trajectories',
        'task_acceptance_complete': False,
        'not_covered': ['Python native lock import and editable packages', 'pnpm/Yarn migration',
                        'authenticated private registry', 'dependency revision', 'npm CVSS candidate backtracking',
                        'narrower workspace delegates and unrelated-job native controls'],
        'source_hashes': {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in sorted((source / 'ptw').glob('*.py'))}, 'cases': []}
    for case in args.case or CASES:
        try:
            result = journey(out / case, case)
        except Exception as exc:
            result = {'passed': False, 'error_type': type(exc).__name__, 'error': str(exc)}
        report['cases'].append({'case': case, **result})
    report['passed'] = all(c['passed'] for c in report['cases'])
    save(out / 'result.json', report)
    print(json.dumps({'passed': report['passed'], 'task_acceptance_complete': False, 'evidence': str(out)}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
