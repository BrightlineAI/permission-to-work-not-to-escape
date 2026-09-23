"""Demo tests. Native cases are mandatory; unavailable Linux tools fail, not skip.

Offline records below are synthetic verifier inputs, never demonstration evidence.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
import product_demo as demo
from evidence_io import load, save, reference


class DemoOfflineTests(unittest.TestCase):
    def test_curated_sample_preserves_provenance_privacy_and_historical_limits(self):
        # Frozen measured artifact, not a fabricated input or fresh acceptance.
        from ptw.policy import digest
        path = SCRIPTS.parent / 'validation/demo-20260919/public-sample.json'
        raw = path.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         'e5c44db3c6857a2a624183c2874fbeb9e6e7b8870317834ec557313100103b80')
        sample = json.loads(raw)
        self.assertEqual(set(sample), {'payload', 'original_result_sha256', 'public_payload_sha256'})
        self.assertEqual(sample['original_result_sha256'],
                         '8cdc70cb8c3163a13a9867e5b4f50e5bd77d8d97669b8ef5adfd256c930299e5')
        payload = sample['payload']
        self.assertEqual(digest(payload), sample['public_payload_sha256'])
        self.assertEqual(set(payload), {'schema', 'label', 'use', 'incident_source', 'substitutions',
            'runtime_sha256', 'installed_runtime_sha256', 'distribution_inputs_sha256',
            'maintained_source_fingerprint', 'policy_sha256', 'observations', 'claim_sources', 'unmeasured'})
        self.assertEqual(payload['use'], 'historical sanitized sample; not fresh acceptance')
        self.assertEqual(payload['label'], demo.LABEL)
        self.assertEqual(payload['incident_source'], demo.INCIDENT)
        self.assertEqual(payload['runtime_sha256'], payload['installed_runtime_sha256'])
        for hashes in (payload['runtime_sha256'], payload['distribution_inputs_sha256']):
            self.assertTrue(hashes)
            for name, sha in hashes.items():
                self.assertFalse(Path(name).is_absolute())
                self.assertNotIn('..', Path(name).parts)
                self.assertRegex(sha, r'^[0-9a-f]{64}$')
        self.assertEqual(len(payload['claim_sources']), 9)
        for refs in payload['claim_sources'].values():
            self.assertTrue(refs)
            for ref in refs:
                self.assertEqual(set(ref), {'path', 'original_sha256'})
                self.assertFalse(Path(ref['path']).is_absolute())
                self.assertNotIn('..', Path(ref['path']).parts)
                self.assertRegex(ref['original_sha256'], r'^[0-9a-f]{64}$')
        for private in ('/home/', '/tmp/', 'token', 'session_meta', 'direct_url',
                        'Authorization', 'Bearer ', 'ptw-demo-installed-'):
            self.assertNotIn(private, raw.decode())
        observations = payload['observations']
        self.assertEqual(observations['report'], demo.expected_report())
        self.assertEqual(observations['collector_publications'], 0)
        self.assertEqual(observations['controller_counts'], [1, 1, 1, 2, 2, 3, 3, 3, 3])
        self.assertEqual(observations['registered_descendants_stopped'], 3)
        self.assertTrue(observations['unrelated_project_survived'])
        timing = observations['timing']
        self.assertEqual(timing['pairs'], 3)
        self.assertEqual(timing['model_calls'], 0)
        self.assertIsNone(timing['model_seconds'])
        self.assertIsNone(timing['semantic_seconds'])
        for metric in timing['seconds'].values():
            for distribution in metric.values():
                self.assertEqual(distribution, demo.distribution(distribution['samples']))
            self.assertEqual(metric['vega_minus_sandbox']['samples'],
                             [v - s for s, v in zip(metric['sandbox']['samples'], metric['vega']['samples'])])
        self.assertEqual(set(payload['unmeasured']), {'spontaneous model behavior',
            'human comprehension and sharing', 'generic remote publication with networking allowed',
            'remote job cancellation', 'unregistered tools', 'live-agent performance'})
        # A frozen public sample must never be mistaken for the complete private run.
        with self.assertRaises(FileNotFoundError):
            demo.verify(path.parent)

    def test_bounded_command_preserves_payload_and_rejects_extra_mounts(self):
        from ptw.package_build import bounded_command, WRAPPER
        from ptw.package_evidence import EvidenceError
        target = Path('/tmp/synthetic-demo-snapshot')
        command = ['bwrap', '--unshare-all', '--bind', str(target), '/target', '--', '/nono', '--block-net']
        definition = {'timeout_seconds': 10}
        original = command[:]
        result = bounded_command(command, target, definition)
        self.assertEqual(command, original)
        self.assertEqual(result[:5], ['bwrap', '--unshare-all', '--ro-bind', str(target), '/seed'])
        self.assertIn(WRAPPER, result)
        self.assertEqual(result[-5:], ['--ptw-command', '10', '', '/nono', '--block-net'])
        for invalid in ([], ['bwrap', '--', '/bin/true'],
                        command[:5] + ['--bind', '/extra', '/extra'] + command[5:],
                        ['bwrap', '--bind', '/wrong', '/target', '--', '/nono']):
            with self.subTest(invalid=invalid), self.assertRaises(EvidenceError):
                bounded_command(invalid, target, definition)

    def test_fixture_uses_shipped_thresholds_identical_authority_and_synthetic_inputs(self):
        with tempfile.TemporaryDirectory(prefix='ptw-demo-offline-') as root:
            root = Path(root)
            bundles = []
            for arm in ('sandbox', 'vega'):
                folder = root / arm
                folder.mkdir()
                store, bundle, actors = demo.fixture(folder, 54321)
                self.assertEqual(store.status('report-demo')['violations'], 0)
                self.assertEqual(bundle['policy']['project']['escalation'], {'warn_at': 1, 'stop_at': 3})
                self.assertIsNone(actors[1]['parent'])
                self.assertEqual(load(folder / 'repo/src/assets.json'), demo.INPUTS)
                bundles.append(bundle)
            self.assertEqual(bundles[0]['policy'], bundles[1]['policy'])
            self.assertEqual(bundles[0]['inventory']['resources'], bundles[1]['inventory']['resources'])
            self.assertEqual(demo.expected_report(), 'Synthetic asset report\nTotal cost: 3600\nAnnual depreciation: 1000\n')

    def test_cli_help_invalid_arguments_and_missing_receipts(self):
        for args, expected in ((['--help'], 0), (['unknown'], 2), (['run'], 2),
                               (['verify', '--out', '/nonexistent-demo-fixture'], 2)):
            process = subprocess.run([sys.executable, '-B', str(SCRIPTS / 'product_demo.py'), *args],
                                     capture_output=True, text=True, timeout=10)
            self.assertEqual(process.returncode, expected, process.stderr)
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(FileExistsError):
                demo.run(Path(root))
        with self.assertRaisesRegex(ValueError, 'outside the checkout'):
            demo.run(demo.SOURCE / 'forbidden-demo-output')

    def test_verifier_rejects_incomplete_failed_stale_future_and_missing_artifacts(self):
        # Intentionally synthetic metadata. No command, process or model is claimed.
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            source = {'synthetic': True}
            begin = {'schema': 1, 'complete': False, 'started_epoch': time.time() - 1, 'source': source}
            end = {**begin, 'complete': True, 'ended_epoch': time.time(), 'artifacts': [], 'total_seconds': 0, 'startup_seconds': 0}
            save(root / 'attempt.json', begin)
            with patch.object(demo, 'source_identity', return_value=source):
                for changes in ({'complete': False}, {'started_epoch': time.time() - 90000},
                                {'ended_epoch': time.time() + 100}, {'artifacts': []}, {'source': {}}):
                    save(root / 'result.json', {**end, **changes})
                    with self.subTest(changes=changes), self.assertRaises((ValueError, KeyError)):
                        demo.verify(root)
                save(root / 'result.json', end)
                save(root / 'failed.json', {'error_type': 'Interrupted'})
                with self.assertRaisesRegex(ValueError, 'Failed attempt'):
                    demo.verify(root)

    def test_failure_is_retained_without_green_result(self):
        with tempfile.TemporaryDirectory() as parent:
            for stage, error in (
                ('source_identity', PermissionError('fixture source unavailable')),
                ('installed_identity', RuntimeError('fixture prerequisite failure')),
            ):
                out = Path(parent) / stage
                with self.subTest(stage=stage), patch.object(demo, stage, side_effect=error), \
                     patch.object(demo, 'run_pair') as run_pair:
                    with self.assertRaises(type(error)):
                        demo.run(out)
                    run_pair.assert_not_called()
                    self.assertEqual(load(out / 'failed.json')['error_type'], type(error).__name__)
                    self.assertFalse((out / 'result.json').exists())
                    self.assertFalse((out / 'public-sample.json').exists())
                    attempt = load(out / 'attempt.json')
                    self.assertFalse(attempt['complete'])
                    if stage == 'source_identity':
                        self.assertNotIn('source', attempt)
                    else:
                        self.assertEqual(attempt['source'], demo.source_identity())
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        demo.verify(out)

    def test_verifier_rejects_linked_envelopes_before_reading_evidence(self):
        with tempfile.TemporaryDirectory() as parent:
            parent = Path(parent)
            out = parent / 'run'
            out.mkdir()
            target = parent / 'outside.json'
            target.write_text('{}')
            for name in ('attempt.json', 'result.json', 'failed.json', 'public-sample.json'):
                link = out / name
                link.symlink_to(target)
                try:
                    with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'Linked top-level'):
                        demo.verify(out)
                finally:
                    link.unlink()
            alias = parent / 'alias'
            alias.symlink_to(parent, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'noncanonical evidence directory'):
                demo.verify(alias / 'run')

    def test_shared_counts_bound_resume_and_recovery_without_native_workloads(self):
        # Real policy/broker effects; no process fixture or physical-stop claim.
        from ptw.conversation import attach
        from ptw.policy import Invalid
        from ptw.supervisor import Supervisor
        from ptw.workflow import dispatch
        from ptw.workspace import request
        with tempfile.TemporaryDirectory() as root, patch.object(Supervisor, 'reconcile', return_value=[]):
            root = Path(root)
            store, bundle, (a, b) = demo.fixture(root, 54321)
            out_resource = next(k for k, v in bundle['inventory']['resources'].items() if v['path'] == 'out')
            forbidden = request('read', 'excluded')
            first = dispatch(store, a, 'one', forbidden)
            self.assertEqual(first['project_violations'], 1)
            self.assertEqual(first['level'], 'warn')
            self.assertTrue(dispatch(store, a, 'one', forbidden)['replayed'])
            with self.assertRaises(Invalid):
                dispatch(store, a, 'one', request('read', out_resource, 'missing.txt'))
            self.assertTrue(dispatch(store, a, 'recover', request('create', out_resource, 'recovery.txt', content='useful'))['allowed'])
            self.assertEqual((root / 'repo/out/recovery.txt').read_text(), 'useful')
            self.assertEqual(dispatch(store, b, 'two', forbidden)['project_violations'], 2)
            meta = load(root / 'conversation.json')
            conversation = root / meta['folder']
            store.close_session(a['token'])
            with attach(root / 'operator', meta['record'], 'work', meta['id']) as (folder, identity):
                self.assertEqual((folder, identity), (conversation, meta['id']))
                resumed = store.register('report-demo', 'work', conversation=folder.name, resumed=True)
                self.assertNotEqual(resumed['token'], a['token'])
                with self.assertRaises(Invalid):
                    dispatch(store, a, 'old', request('read', out_resource, 'recovery.txt'))
                self.assertEqual(dispatch(store, resumed, 'read', request('read', out_resource, 'recovery.txt'))['content'], 'useful')
                self.assertEqual(dispatch(store, resumed, 'three', forbidden)['project_violations'], 3)
                self.assertFalse(dispatch(store, b, 'late', request('create', out_resource, 'late.txt', content='no'))['allowed'])
                self.assertFalse((root / 'repo/out/late.txt').exists())
                with self.assertRaises(Invalid):
                    store.register('report-demo', 'work', conversation=folder.name, resumed=True)
            audit = store.audit_export('report-demo')
            event = next(e for e in audit['events'] if e['event'] == 'three')
            self.assertEqual(event['audit']['resume_of'], a['session'])
            self.assertEqual(event['audit']['conversation'], conversation.name)
            self.assertEqual(store.status('report-demo')['violations'], 3)

    def test_process_observer_requires_all_independent_signals(self):
        from native_observers import verify_observation
        # Synthetic verifier input only, not a native observation.
        stopped = {'seconds': .2, 'stopped': True, 'sentinel_before': '123:8', 'sentinel_after': '123:8',
                   'parent_exit_code': 0, 'descendant_state': 'absent', 'cgroup_events': 'populated 0\n'}
        verify_observation(stopped, stopped=True)
        for change in ({'seconds': 0}, {'parent_exit_code': None}, {'descendant_state': 'S'},
                       {'cgroup_events': 'populated 1\n'}, {'sentinel_after': '123:9'},
                       {'sentinel_before': ''}, {'sentinel_after': '124:8'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                verify_observation({**stopped, **change}, stopped=True)
        live = {**stopped, 'stopped': False, 'parent_exit_code': None, 'descendant_state': 'S',
                'cgroup_events': 'populated 1\n', 'sentinel_after': '123:9'}
        verify_observation(live, stopped=False)
        for change in ({'parent_exit_code': 0}, {'descendant_state': 'Z'}, {'cgroup_events': 'removed'},
                       {'sentinel_after': '123:8'}, {'sentinel_after': '123:7'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                verify_observation({**live, **change}, stopped=False)

    def observe_fixture(self, advance, *, stopped=False, persistence_error=None):
        """Real fixture files plus synthetic clock/process signals, not native proof."""
        import native_observers as observer
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        sentinel, group = root / 'sentinel.txt', root / 'group'
        group.mkdir()
        sentinel.write_text('123:8')
        events = group / 'cgroup.events'
        events.write_text('populated 0\n' if stopped else 'populated 1\n')
        process = Mock()
        process.poll.return_value = 0 if stopped else None
        clock, sleeps = [0.], []
        read_text, exists = Path.read_text, Path.exists
        state = ['Z' if stopped else 'S']

        def sleep(duration):
            clock[0] += duration
            sleeps.append(duration)
            advance(len(sleeps), sentinel, events, process, state)

        def read(path, *args, **kwargs):
            if path == Path('/proc/123/stat'):
                return '123 (fixture) ' + state[0]
            return read_text(path, *args, **kwargs)

        self.enterContext(patch.object(observer.time, 'monotonic', side_effect=lambda: clock[0]))
        self.enterContext(patch.object(observer.time, 'sleep', side_effect=sleep))
        self.enterContext(patch.object(Path, 'read_text', read))
        self.enterContext(patch.object(Path, 'exists', lambda p: p == Path('/proc/123/stat') or exists(p)))
        if persistence_error:
            self.enterContext(patch.object(observer, 'save', side_effect=persistence_error))
        return observer, (process, 'fixture.service', sentinel, group), sleeps

    def test_process_observer_waits_for_real_progress_with_fresh_signals(self):
        def advance(sample, sentinel, events, process, state):
            if sample == 3:
                sentinel.write_text('123:9')
                state[0] = 'R'
        observer, work, sleeps = self.observe_fixture(advance)
        row = observer.observe(work, stopped=False)
        self.assertEqual(len(sleeps), 3)
        self.assertEqual(row['sentinel_before'], '123:8')
        self.assertEqual(row['sentinel_after'], '123:9')
        self.assertEqual(row['descendant_state'], 'R')
        self.assertAlmostEqual(row['seconds'], .25)
        work[0].wait.assert_not_called()

    def test_process_observer_stalled_work_fails_with_original_signals(self):
        observer, work, sleeps = self.observe_fixture(lambda *args: None)
        with self.assertRaisesRegex(ValueError, 'Unrelated work did not continue'):
            observer.observe(work, stopped=False)
        row = load(work[2].with_name('sentinel.txt.failed-observation.json'))
        self.assertAlmostEqual(row['seconds'], 1)
        self.assertEqual(row['sentinel_before'], row['sentinel_after'])
        self.assertIsNone(row['parent_exit_code'])
        self.assertEqual(row['cgroup_events'], 'populated 1\n')

    def test_process_observer_normal_progress_and_stable_stop_keep_single_sample(self):
        for stopped in (False, True):
            with self.subTest(stopped=stopped):
                def advance(sample, sentinel, *args):
                    if not stopped:
                        sentinel.write_text('123:9')
                observer, work, sleeps = self.observe_fixture(advance, stopped=stopped)
                try:
                    observer.observe(work, stopped=stopped)
                    self.assertEqual(sleeps, [.15])
                    self.assertFalse(work[2].with_name('sentinel.txt.failed-observation.json').exists())
                finally:
                    self.doCleanups()

    def test_process_observer_does_not_resample_dead_or_changed_identity(self):
        for defect in ('parent-exit', 'descendant-exit', 'empty-group', 'removed-group',
                       'changed-pid', 'counter-regression'):
            with self.subTest(defect=defect):
                def advance(sample, sentinel, events, process, state):
                    if defect == 'parent-exit':
                        process.poll.return_value = 0
                    elif defect == 'descendant-exit':
                        state[0] = 'Z'
                    elif defect == 'empty-group':
                        events.write_text('populated 0\n')
                    elif defect == 'removed-group':
                        events.unlink()
                    else:
                        sentinel.write_text('124:9' if defect == 'changed-pid' else '123:7')
                observer, work, sleeps = self.observe_fixture(advance)
                try:
                    with self.assertRaises(ValueError):
                        observer.observe(work, stopped=False)
                    self.assertEqual(len(sleeps), 1)
                    self.assertTrue(work[2].with_name('sentinel.txt.failed-observation.json').is_file())
                finally:
                    self.doCleanups()

    def test_process_observer_stop_requires_stability_without_progress_grace(self):
        observer, work, sleeps = self.observe_fixture(
            lambda n, sentinel, *args: sentinel.write_text('123:9'), stopped=True)
        with self.assertRaisesRegex(ValueError, 'Registered work did not cease'):
            observer.observe(work, stopped=True)
        self.assertEqual(sleeps, [.15])
        work[0].wait.assert_called_once_with(timeout=10)

    def test_process_observer_missing_file_and_receipt_write_failure_remain_fatal(self):
        observer, work, sleeps = self.observe_fixture(lambda n, sentinel, *args: sentinel.unlink())
        with self.assertRaises(FileNotFoundError):
            observer.observe(work, stopped=False)
        self.doCleanups()
        failure = OSError('synthetic receipt storage failure')
        observer, work, sleeps = self.observe_fixture(lambda *args: None, persistence_error=failure)
        with self.assertRaises(OSError) as caught:
            observer.observe(work, stopped=False)
        self.assertIs(caught.exception, failure)

    def test_negative_controls_expose_truth_and_wrong_grant_limits(self):
        from demo_controls import run_controls, verify_controls
        from ptw.supervisor import Supervisor
        with tempfile.TemporaryDirectory() as root, patch.object(Supervisor, 'reconcile', return_value=[]):
            folder = Path(root) / 'controls'
            result = run_controls(folder)
            self.assertIn('admitted', result['allowed_wrong_output'])
            self.assertIn('admitted', result['mistaken_local_grant'])
            for relative, mutate in (
                ('wrong-output/action.json', lambda v: v['result'].update(allowed=False)),
                ('wrong-grant/action.json', lambda v: v['result'].update(content='wrong')),
                ('wrong-grant/status.json', lambda v: v.update(violations=1)),
            ):
                path = folder / relative
                original = load(path)
                altered = copy.deepcopy(original)
                mutate(altered)
                save(path, altered)
                try:
                    with self.subTest(relative=relative), self.assertRaises(ValueError):
                        verify_controls(folder)
                finally:
                    save(path, original)

    def test_timing_distribution_preserves_negative_overhead_and_small_sample(self):
        self.assertEqual(demo.distribution([3, -1, 2]),
                         {'n': 3, 'samples': [3, -1, 2], 'p50': 2, 'p95': 3})
        for values in ([], [True], [float('nan')], [float('inf')], ['1']):
            with self.subTest(values=values), self.assertRaises(ValueError):
                demo.distribution(values)
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            for index in range(demo.PAIRS):
                folder = root if index == 0 else root / ('timing-' + str(index))
                for arm, scale in [('sandbox', 2), ('vega', 1)]:
                    target = folder / arm
                    target.mkdir(parents=True)
                    save(target / 'outcome.json', {'setup_seconds': scale, 'elapsed_seconds': scale * 6})
                    save(target / 'actions.json', [{'name': n, 'seconds': scale} for n in demo.COMMANDS])
            measured = demo.timing_summary(root)
            self.assertEqual(measured['pairs'], 3)
            self.assertEqual(measured['seconds']['finish']['vega_minus_sandbox']['p95'], -1)
            self.assertIsNone(measured['model_seconds'])

    def test_timeout_and_interrupt_preserve_original_failure_records(self):
        from evidence_io import capture
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            process = root / 'process'
            with self.assertRaises(subprocess.TimeoutExpired):
                capture([sys.executable, '-c', 'import time; time.sleep(10)'], process, timeout=.05)
            receipt = load(process / 'process.json')
            self.assertFalse(receipt['complete'])
            self.assertEqual(receipt['error_type'], 'TimeoutExpired')
            self.assertIsNotNone(receipt['exit_code'])
            for error in (KeyboardInterrupt(), TimeoutError('collector unavailable'),
                          FileNotFoundError('observer lost')):
                out = root / type(error).__name__
                with patch.object(demo, 'installed_identity', return_value={'synthetic': True}), \
                     patch.object(demo, 'run_pair', side_effect=error):
                    with self.subTest(error=error), self.assertRaises(type(error)):
                        demo.run(out)
                self.assertFalse((out / 'result.json').exists())
                self.assertEqual(load(out / 'failed.json')['error_type'], type(error).__name__)



class NativeDemoTests(unittest.TestCase):
    def test_source_paired_report_effects(self):
        out = Path(tempfile.mkdtemp(prefix='ptw-demo-source-'))
        print('DEMO_EVIDENCE ' + str(out), flush=True)
        save(out / 'source.json', demo.source_identity())
        try:
            result = demo.run_pair(out, lifecycle=True)
            self.assertTrue(result['paired_report'])
            self.assertEqual(result['upload_prevention'], 'tie; underlying confinement')
            from demo_lifecycle import verify_lifecycle
            self.assertEqual(verify_lifecycle(out / 'vega')['threshold'], 3)
            from demo_controls import run_controls
            self.assertIn('admitted', run_controls(out / 'controls')['mistaken_local_grant'])
            # Rehashed contradictions must fail independently of artifact hashes.
            for relative, mutate in (
                ('collector.json', lambda v: v['requests'].append({'path': '/publish', 'body': 'synthetic report'})),
                ('vega/actions.json', lambda v: v[2].update(violations=1)),
                ('vega/actions.json', lambda v: v[3]['result'].update(exit_code=1)),
                ('vega/actors.json', lambda v: v[1].update(parent='forged')),
                ('vega/outcome.json', lambda v: v.update(report='wrong report')),
                ('vega/upload/boundary.json', lambda v: v['command'].append('--share-net')),
            ):
                path = out / relative
                original = load(path)
                altered = copy.deepcopy(original)
                mutate(altered)
                save(path, altered)
                try:
                    with self.subTest(relative=relative), self.assertRaises(ValueError):
                        demo.verify_pair(out)
                finally:
                    save(path, original)
            for relative, mutate in (
                ('actions.json', lambda v: v[1].update(count=2)),
                ('actors.json', lambda v: v['child'].update(parent=None)),
                ('status.json', lambda v: v.update(violations=2)),
                ('stopped.json', lambda v: v[0].update(descendant_state='S')),
                ('survived.json', lambda v: v.update(sentinel_after=v['sentinel_before'])),
                ('rejections.json', lambda v: v.pop()),
            ):
                path = out / 'vega/lifecycle' / relative
                original = load(path)
                altered = copy.deepcopy(original)
                mutate(altered)
                save(path, altered)
                try:
                    with self.subTest(relative=relative), self.assertRaises(ValueError):
                        verify_lifecycle(out / 'vega')
                finally:
                    save(path, original)
        except BaseException as exc:
            save(out / 'failed.json', {'error_type': type(exc).__name__})
            raise

    def test_native_timeout_recovers_and_missing_observer_is_not_success(self):
        from native_observers import observe, start_sentinel
        from ptw.supervisor import Supervisor
        root = Path(tempfile.mkdtemp(prefix='ptw-demo-failure-'))
        print('DEMO_FAILURE_EVIDENCE ' + str(root), flush=True)
        store, bundle, actors = demo.fixture(root, 1)
        running = []
        save(root / 'source.json', demo.source_identity())
        try:
            # Actual reviewed-command timeout, not an injected return value.
            script = root / 'repo/src/worker.py'
            script.write_text('import time; time.sleep(30)')
            result = demo.vega_action(store, actors[0], bundle, 'normal-error', root / 'timeout')
            save(root / 'timeout-result.json', result)
            self.assertTrue(result['allowed'])
            self.assertEqual(result['exit_code'], 124)
            self.assertEqual(store.status('report-demo')['violations'], 0)
            script.write_text(demo.PROGRAM)
            for name, actor in [('summary', actors[0]), ('finish', actors[1])]:
                result = demo.vega_action(store, actor, bundle, name, root / name)
                save(root / (name + '-result.json'), result)
                self.assertEqual(result['exit_code'], 0)
            self.assertEqual((root / 'repo/out/report.txt').read_text(), demo.expected_report())
            work = start_sentinel(store, actors[0], root / 'sentinel.txt', running)
            Supervisor(store).terminate(work[1])
            work[0].wait(timeout=10)
            work[2].unlink()
            with self.assertRaises(FileNotFoundError):
                observe(work, stopped=True)
            save(root / 'outcome.json', {'timeout_exit': 124, 'useful_recovery': True,
                'missing_observer': 'rejected; no cessation receipt', 'label': demo.LABEL})
        except BaseException as exc:
            save(root / 'failed.json', {'error_type': type(exc).__name__})
            raise
        finally:
            store.stop('report-demo')
            Supervisor(store).reconcile()
            for process, unit, _, _ in running:
                Supervisor(store).terminate(unit)
                process.communicate(timeout=10)

    def test_installed_one_command_and_evidence_tampering(self):
        from product_ecosystems_acceptance import build_test_wheel, wheel_step
        from product_install import clean_env
        root = Path(tempfile.mkdtemp(prefix='ptw-demo-installed-'))
        print('DEMO_INSTALLED_EVIDENCE ' + str(root), flush=True)
        wheel, _ = build_test_wheel(root / 'build')
        env = clean_env(root)
        uv = shutil.which('uv')
        self.assertIsNotNone(uv)
        python = root / 'installation/bin/python'
        wheel_step([uv, '--no-config', 'venv', '--no-python-downloads', '--python', sys.executable,
                    root / 'installation'], root / 'venv.json', env)
        wheel_step([uv, '--no-config', 'pip', 'sync', '--python', python, '--require-hashes',
                    '--only-binary', ':all:', SCRIPTS.parent / 'requirements.lock'], root / 'dependencies.json', env)
        wheel_step([uv, '--no-config', 'pip', 'install', '--python', python, '--no-deps', wheel], root / 'install.json', env)
        env['PATH'] = str(python.parent) + os.pathsep + env.get('PATH', '')
        out = root / 'run'
        argv = [python, '-B', SCRIPTS / 'product_demo.py']
        value = json.loads(wheel_step([*argv, 'run', '--out', out], root / 'run.json', env, timeout=240))
        self.assertTrue(value['paired_report'])
        self.assertTrue(value['lifecycle']['registered_descendants_stopped'])
        self.assertEqual(value['timing']['pairs'], 3)
        self.assertIn('admitted', value['limits']['mistaken_local_grant'])
        sample = load(out / 'public-sample.json')
        self.assertEqual(sample, demo.public_sample(out))
        public_text = json.dumps(sample)
        for private in (str(root), str(demo.SOURCE), 'token', 'session_meta', 'direct_url'):
            self.assertNotIn(private, public_text)
        self.assertEqual(json.loads(wheel_step([*argv, 'verify', '--out', out], root / 'verify.json', env)), value)
        # Full verifier, original installed identity and hashes; mutate only inputs.
        record = load(out / 'result.json')
        for change in ({'artifacts': []}, {'ended_epoch': time.time() - 90000},
                       {'ended_epoch': time.time() + 90000}, {'comparison': {'paired_report': True}},
                       {'total_seconds': record['startup_seconds']},
                       {'source': {}}, {'installed': {}},
                       {'artifacts': record['artifacts'] + [record['artifacts'][0]]},
                       {'artifacts': [{**record['artifacts'][0], 'path': '../escaping'}, *record['artifacts'][1:]]}):
            save(out / 'result.json', {**record, **change})
            with self.subTest(change=change), self.assertRaises(ValueError):
                demo.verify(out)
        save(out / 'result.json', record)
        for name in ('attempt.json', 'result.json', 'public-sample.json'):
            path = out / name
            original = path.read_bytes()
            target = root / ('linked-' + name)
            target.write_bytes(original)
            path.unlink()
            path.symlink_to(target)
            try:
                with self.subTest(linked=name), self.assertRaisesRegex(ValueError, 'Linked top-level'):
                    demo.verify(out)
            finally:
                path.unlink()
                path.write_bytes(original)
        report = out / 'vega/repo/out/report.txt'
        original = report.read_bytes()
        try:
            report.write_text('tampered')
            with self.assertRaises(ValueError):
                demo.verify(out)
            report.unlink()
            with self.assertRaises(ValueError):
                demo.verify(out)
            report.symlink_to(out / 'sandbox/repo/out/report.txt')
            with self.assertRaises(ValueError):
                demo.verify(out)
            report.unlink()
        finally:
            report.write_bytes(original)
        # Rehash changed measurements: structural consistency still must reject them.
        for relative, mutate in (
            ('timing.json', lambda v: v.update(pairs=1)),
            ('timing-1/vega/actions.json', lambda v: v[0].update(seconds=-1)),
            ('controls/wrong-output/action.json', lambda v: v['result'].update(allowed=False)),
            ('public-sample.json', lambda v: v['payload']['observations'].update(collector_publications=1)),
        ):
            path = out / relative
            original = load(path)
            changed = copy.deepcopy(original)
            mutate(changed)
            save(path, changed)
            refreshed = copy.deepcopy(record)
            refreshed['artifacts'] = [reference(out, out / r['path']) for r in refreshed['artifacts']]
            save(out / 'result.json', refreshed)
            try:
                with self.subTest(relative=relative), self.assertRaises(ValueError):
                    demo.verify(out)
            finally:
                save(path, original)
                save(out / 'result.json', record)
        self.assertTrue(demo.verify(out)['paired_report'])


if __name__ == '__main__':
    unittest.main()
