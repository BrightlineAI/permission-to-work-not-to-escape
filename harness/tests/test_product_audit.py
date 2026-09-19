"""Audit acceptance: deterministic fixtures, not spontaneous model evidence."""
import copy
import concurrent.futures
import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path
import threading
import time
import unittest
import uuid
from unittest.mock import patch

from ptw.event_evidence import verify_export
from ptw.policy import Invalid, canonical, digest
from ptw.store import Store
from ptw.workspace import Workspace, request
from ptw.evidence_storage import DEFAULT, PAYLOAD_BYTES, RETENTION_SECONDS, QuotaError
import test_workspace as workspace_fixtures
import test_product_daily as daily_fixtures
import test_product_ecosystems as ecosystem_fixtures


class AuditEventTests(workspace_fixtures.WorkspaceFixture):
    def test_unreserved_nested_operation_rejects_even_a_colliding_slot(self):
        from ptw.store import operation_lease
        event = 'outer'
        collision = next(str(i) for i in range(10000)
                         if operation_lease(self.actor['session'], str(i)) ==
                         operation_lease(self.actor['session'], event))
        with self.store.operation(self.actor['token'], event):
            with self.assertRaisesRegex(Invalid, 'must be reserved'):
                with self.store.operation(self.actor['token'], collision):
                    self.fail('Unreserved nesting entered')
        self.assertEqual(self.store.audit_events('python-demo'), [])
        self.assertFalse(self.store.status('python-demo')['stopped'])

    def test_colliding_leases_serialize_without_false_crash_or_duplicate_effect(self):
        from ptw.store import operation_lease
        first = 'collision-first'
        second = next(str(i) for i in range(10000)
                      if operation_lease(self.actor['session'], str(i)) ==
                      operation_lease(self.actor['session'], first))
        entered, finish = threading.Event(), threading.Event()
        calls = []
        def execute(store, token, definition, before, settings, **kwargs):
            calls.append(True)
            self.assertFalse(Store(store.directory).status('python-demo')['stopped'])
            entered.set()
            self.assertTrue(finish.wait(5))
            return before, {'exit_code': 0, 'output': ''}
        with patch('ptw.execution.execute', side_effect=execute):
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                original = pool.submit(self.broker.request, self.actor['token'], first, request('run', 'test'))
                self.assertTrue(entered.wait(5))
                other = pool.submit(self.broker.request, self.actor['token'], second, request('run', 'test'))
                try:
                    self.assertFalse(other.done())
                finally:
                    finish.set()
                self.assertTrue(original.result(timeout=5)['allowed'])
                self.assertTrue(other.result(timeout=5)['allowed'])
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(list(self.store.directory.glob('operation-*.lock'))), 1)
        self.assertTrue(self.broker.request(self.actor['token'], first, request('run', 'test'))['replayed'])

    def test_long_operation_intent_survives_live_reopen_and_duplicate_waits(self):
        entered, finish = threading.Event(), threading.Event()
        body = request('run', 'test')
        calls = []
        def execute(store, token, definition, before, settings, **kwargs):
            calls.append(True)
            reopened = Store(store.directory)
            self.assertFalse(reopened.status('python-demo')['stopped'])
            self.assertEqual(reopened.audit_events('python-demo')[0]['state'], 'pending')
            entered.set()
            self.assertTrue(finish.wait(5))
            return before, {'exit_code': 0, 'output': 'one execution'}
        with patch('ptw.execution.execute', side_effect=execute):
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                original = pool.submit(self.broker.request, self.actor['token'], 'same-command', body)
                self.assertTrue(entered.wait(5))
                retry = pool.submit(self.broker.request, self.actor['token'], 'same-command', body)
                try:
                    self.assertFalse(retry.done())
                finally:
                    finish.set()
                self.assertTrue(original.result(timeout=5)['allowed'])
                self.assertTrue(retry.result(timeout=5)['replayed'])
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(self.store.audit_events('python-demo')), 1)

    def test_command_crash_preserves_uncertainty_and_never_reexecutes(self):
        body = request('run', 'test')
        with patch('ptw.execution.execute', side_effect=SystemExit('injected controller crash')) as execution:
            with self.assertRaises(SystemExit):
                self.broker.request(self.actor['token'], 'crashed-command', body)
            retry = Workspace(Store(self.store.directory)).request(self.actor['token'], 'crashed-command', body)
            self.assertFalse(retry['allowed'])
            self.assertTrue(retry['replayed'])
            self.assertEqual(execution.call_count, 1)
        row = self.store.audit_events('python-demo')[0]
        self.assertEqual(row['state'], 'uncertain')
        self.assertEqual(row['audit']['decision'], 'allow')
        self.assertEqual(row['audit']['outcome'], 'unknown')
        self.assertEqual(self.store.status('python-demo')['violations'], 0)

    def test_command_admission_fault_precedes_execution(self):
        with patch.object(self.store, 'begin', side_effect=OSError('required intent unavailable')):
            with patch('ptw.execution.execute') as execution, self.assertRaises(OSError):
                self.ask('run', resource='test', path='')
        execution.assert_not_called()
        self.assertEqual(self.store.status('python-demo')['workloads'], [])
        self.assertEqual(self.store.status('python-demo')['violations'], 0)

    def test_metadata_records_actual_effect_identity_and_no_content(self):
        self.assertTrue(self.ask('create', path='audit.txt', content='PRIVATE_FIXTURE_PAYLOAD')['allowed'])
        self.assertEqual((Path(self.inv['root']) / 'src/audit.txt').read_text(), 'PRIVATE_FIXTURE_PAYLOAD')
        document = self.store.audit_export('python-demo')
        row = next(r for r in document['events'] if r['request']['action'] == 'create')
        self.assertEqual(row['request']['path'], 'audit.txt')
        self.assertEqual(row['audit']['resource_path'], 'src')
        self.assertEqual(row['audit']['requester']['id'], self.actor['session'])
        self.assertEqual(row['audit']['authorization']['method'], 'standing_policy')
        self.assertFalse(row['audit']['authorization']['human_review_performed'])
        self.assertEqual(row['audit']['decision'], 'allow')
        self.assertEqual(row['audit']['outcome'], 'observed')
        self.assertIsNone(row['audit']['source_at'])
        self.assertNotIn('PRIVATE_FIXTURE_PAYLOAD', json.dumps(document))
        self.assertNotIn(self.actor['token'], json.dumps(document))
        self.assertTrue(verify_export(document, digest(document))['verified'])

    def test_denied_forged_authority_and_replay_preserve_counts(self):
        body = {**request('create', 'src', 'forged.txt', content='already approved'),
                'authorization': {'method': 'exact_operator_approval'}}
        result = self.broker.request(self.actor['token'], 'forged', body)
        self.assertFalse(result['allowed'])
        self.assertFalse((Path(self.inv['root']) / 'src/forged.txt').exists())
        self.assertTrue(self.broker.request(self.actor['token'], 'forged', body)['replayed'])
        rows = self.store.audit_events('python-demo')
        self.assertEqual(len(rows), 1)
        self.assertEqual(self.store.status('python-demo')['violations'], 1)
        self.assertFalse(rows[0]['audit']['authorization']['human_review_performed'])

    def test_order_is_controller_order_despite_clock_reversal_and_parent_link(self):
        with patch('ptw.store.time.time', return_value=200):
            self.ask('read')
        child = self.store.register('python-demo', 'readcheck', parent_token=self.actor['token'])
        with patch('ptw.store.time.time', return_value=100):
            self.broker.request(child['token'], 'child-read', request('read', 'src', 'calculator.py'))
        rows = self.store.audit_events('python-demo')
        self.assertEqual([r['audit']['observed_at'] for r in rows], [200, 100])
        self.assertLess(rows[0]['audit']['sequence'], rows[1]['audit']['sequence'])
        # Registration occupies its own position in the same controller order.
        history = self.store.audit_export('python-demo')['events']
        self.assertEqual([r['audit']['sequence'] for r in history], list(range(1, len(history) + 1)))
        self.assertEqual(rows[1]['audit']['parent_session'], self.actor['session'])
        self.assertTrue(all(r['audit']['source_at'] is None for r in rows))

    def test_export_rejects_missing_duplicate_reordered_altered_and_unknown(self):
        self.ask('read')
        self.ask('list', path='')
        original = self.store.audit_export('python-demo')
        variants = []
        for mutation in ('missing', 'duplicate', 'reorder', 'alter', 'unknown'):
            item = copy.deepcopy(original)
            if mutation == 'missing':
                item['events'].pop()
            elif mutation == 'duplicate':
                item['events'].append(copy.deepcopy(item['events'][0]))
            elif mutation == 'reorder':
                item['events'].reverse()
            elif mutation == 'alter':
                item['events'][0]['request']['path'] = 'different.py'
            else:
                item['events'][0]['audit']['decision'] = 'auto_approved'
            # Even a recomputed local manifest cannot replace the retained receipt.
            item['manifest'] = {'count': len(item['events']), 'events_sha256': digest(item['events'])}
            variants.append(item)
        for item in variants:
            with self.subTest(item=item['manifest']), self.assertRaises(Invalid):
                verify_export(item, digest(original))

    def test_stored_response_tamper_is_rejected(self):
        self.ask('read')
        with self.store.locked() as db:
            db.execute('UPDATE events SET response=?', (canonical({'allowed': True, 'level': 'allow',
                'effect': 'read', 'content': 'forged'}),))
        with self.assertRaisesRegex(Invalid, 'changed'):
            self.store.audit_export('python-demo')

    def test_invalid_export_shapes_and_versions_fail_explicitly(self):
        original = self.store.audit_export('python-demo')
        for value in (None, [], {**original, 'manifest': []}, {**original, 'schema': True},
                      {**original, 'manifest': {**original['manifest'], 'count': True}}):
            with self.subTest(value=value), self.assertRaises(Invalid):
                verify_export(value, digest(value))

    def test_failed_effect_keeps_allowed_decision_and_crash_is_unknown(self):
        with patch('ptw.workspace.publish', side_effect=OSError('injected write fault')):
            result = self.ask('create', path='failed.txt', content='must not appear')
        self.assertFalse(result['allowed'])
        row = self.store.audit_events('python-demo')[0]
        self.assertEqual(row['audit']['decision'], 'allow')
        self.assertEqual(row['audit']['outcome'], 'unknown')
        self.assertEqual(self.store.status('python-demo')['violations'], 0)
        self.assertFalse((Path(self.inv['root']) / 'src/failed.txt').exists())

    def test_crash_recovery_does_not_retry_or_fabricate_completion(self):
        body = request('create', 'src', 'crash.txt', content='x')
        with patch('ptw.workspace.publish', side_effect=SystemExit('injected crash')):
            with self.assertRaises(SystemExit):
                self.broker.request(self.actor['token'], 'crash', body)
        recovered = Store(self.store.directory)
        row = recovered.audit_events('python-demo')[0]
        self.assertEqual(row['state'], 'uncertain')
        self.assertEqual(row['audit']['outcome'], 'unknown')
        result = Workspace(recovered).request(self.actor['token'], 'crash', body)
        self.assertTrue(result['replayed'])
        self.assertFalse(result['allowed'])
        self.assertFalse((Path(self.inv['root']) / 'src/crash.txt').exists())
        self.assertEqual(recovered.status('python-demo')['violations'], 0)

    def test_legacy_provenance_stays_unknown_after_reopen(self):
        with self.store.locked() as db:
            db.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?)', (self.actor['session'], 'old',
                digest({}), '{}', canonical({'allowed': False, 'level': 'warn', 'effect': 'none'}), 'complete', 1))
            db.execute("UPDATE projects SET stopped=1,violations=2,reason='historical stop' WHERE id='python-demo'")
            db.execute('UPDATE sessions SET closed=1 WHERE id=?', (self.actor['session'],))
        recovered = Store(self.store.directory)
        row = recovered.audit_events('python-demo')[0]
        self.assertEqual(row['audit']['coverage'], 'legacy_unknown')
        self.assertIsNone(row['audit']['policy_sha256'])
        self.assertIsNone(row['audit']['sequence'])
        status = recovered.status('python-demo')
        self.assertEqual(status['violations'], 2)
        self.assertTrue(status['stopped'])
        self.assertTrue(status['sessions'][0]['closed'])

    def test_export_cli_is_private_and_will_not_overwrite(self):
        from ptw.cli import main
        self.ask('read')
        destination = self.root / 'operator-export.json'
        args = ['evidence', '--state', str(self.store.directory), '--project', 'python-demo', '--out', str(destination)]
        main(args)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        self.assertTrue(verify_export(json.loads(destination.read_text()), digest(self.store.audit_export('python-demo')))['verified'])
        with self.assertRaises(SystemExit):
            main(args)

    def test_delegate_export_preserves_identity_without_credential_or_narrative(self):
        from ptw.workflow import dispatch
        result = dispatch(self.store, self.actor, 'delegate', request('delegate', 'readcheck'))
        self.assertTrue(result['allowed'], result)
        row = self.store.audit_events('python-demo')[0]
        self.assertEqual(row['result']['child']['session'], result['child']['session'])
        self.assertEqual(row['result']['child']['parent'], self.actor['session'])
        self.assertNotIn('note', row['result'])
        self.assertNotIn('token', row['result']['child'])

    def test_unknown_decision_cannot_be_recorded(self):
        with self.store.locked() as db, self.assertRaisesRegex(Invalid, 'decision'):
            self.store.record(db, self.actor['session'], 'bad-state', digest({}), {},
                              {'allowed': True, 'level': 'auto_approved', 'effect': 'write'})
        self.assertEqual(self.store.audit_events('python-demo'), [])


class AuditLifecycleTests(workspace_fixtures.WorkspaceFixture):
    def test_registration_delegate_resume_and_closure_link_useful_effects(self):
        conversation = str(uuid.uuid4())
        first = self.store.register('python-demo', 'implementation', conversation=conversation)
        child = self.store.register('python-demo', 'readcheck', parent_token=first['token'])
        self.assertTrue(self.broker.request(child['token'], 'child-read', request('read', 'src', 'calculator.py'))['allowed'])
        self.assertTrue(self.store.close_session(first['token'])['closed'])
        with self.assertRaises(Invalid):
            self.broker.request(child['token'], 'late', request('read', 'src', 'calculator.py'))
        fresh = self.store.register('python-demo', 'implementation', conversation=conversation, resumed=True)
        self.assertNotEqual(first['token'], fresh['token'])
        self.assertTrue(self.broker.request(fresh['token'], 'continued', request('create', 'src', 'continued.txt', content='useful'))['allowed'])
        self.assertEqual((Path(self.inv['root']) / 'src/continued.txt').read_text(), 'useful')
        rows = self.store.audit_export('python-demo')['events']
        resumed = next(r for r in rows if r['event'] == 'continued')
        self.assertEqual(resumed['audit']['resume_of'], first['session'])
        self.assertEqual(resumed['audit']['conversation'], conversation)
        self.assertIn(digest(['controller:python-demo', 'session_registered:' + fresh['session']]), resumed['audit']['causes'])
        registered = next(r for r in rows if r['event'] == 'session_registered:' + child['session'])
        self.assertEqual(registered['audit']['requester'], {'kind': 'authenticated_session', 'id': first['session']})
        closed = next(r for r in rows if r['request']['action'] == 'session_closed')
        self.assertEqual(set(closed['audit']['details']['closed_sessions']), {first['session'], child['session']})
        count = len(rows)
        self.store.close_session(first['token'])
        self.assertEqual(len(self.store.audit_export('python-demo')['events']), count)
        self.assertEqual(self.store.status('python-demo')['violations'], 0)
        self.assertTrue(self.ask('read')['allowed'])  # Independent parent survives.

    def test_resume_rejects_open_foreign_and_unbound_sessions(self):
        conversation = str(uuid.uuid4())
        first = self.store.register('python-demo', 'implementation', conversation=conversation)
        with self.assertRaises(Invalid):
            self.store.register('python-demo', 'implementation', conversation=conversation, resumed=True)
        self.store.close_session(first['token'])
        with self.assertRaises(Invalid):
            self.store.register('python-demo', 'readcheck', conversation=conversation, resumed=True)
        with self.assertRaises(Invalid):
            self.store.register('python-demo', 'implementation', resumed=True)
        legacy = self.store.register('python-demo', 'implementation', conversation=str(uuid.uuid4()), resumed=True)
        row = next(r for r in self.store.audit_export('python-demo')['events']
                   if r['event'] == 'session_registered:' + legacy['session'])
        self.assertIsNone(row['audit']['resume_of'])
        self.assertEqual(row['audit']['details']['resume_coverage'], 'legacy_unknown')

    def test_registration_capture_failure_rolls_back_admission(self):
        before = self.store.status('python-demo')['sessions']
        with self.store.locked() as db:
            db.execute("CREATE TRIGGER reject_registration BEFORE INSERT ON events "
                       "WHEN json_extract(NEW.request_meta,'$.action')='session_registered' "
                       "BEGIN SELECT RAISE(FAIL,'injected registration fault'); END")
        with self.assertRaises(sqlite3.Error):
            self.store.register('python-demo', 'implementation')
        status = self.store.status('python-demo')
        self.assertEqual(status['sessions'], before)
        self.assertTrue(status['stopped'])
        self.assertEqual(status['violations'], 0)

    def test_closure_capture_failure_preserves_revocation_and_other_parent(self):
        child = self.store.register('python-demo', 'readcheck', parent_token=self.actor['token'])
        with self.store.locked() as db:
            db.execute("CREATE TRIGGER reject_closure BEFORE INSERT ON events "
                       "WHEN json_extract(NEW.request_meta,'$.action')='session_closed' "
                       "BEGIN SELECT RAISE(FAIL,'injected closure fault'); END")
        result = self.store.close_session(child['token'])
        self.assertEqual(result['evidence'], 'unavailable')
        self.assertFalse(result['confirmed_stopped'])
        with self.assertRaises(Invalid):
            self.broker.request(child['token'], 'late', request('read', 'src', 'calculator.py'))
        self.assertTrue(self.ask('read')['allowed'])
        self.assertFalse(self.store.status('python-demo')['stopped'])
        self.assertEqual(self.store.status('python-demo')['violations'], 0)

    def test_delegate_lost_receipt_cannot_create_another_child(self):
        from ptw.workflow import dispatch
        body = request('delegate', 'readcheck')
        with patch('ptw.workflow.save', side_effect=SystemExit('crash after registration')):
            with self.assertRaises(SystemExit):
                dispatch(self.store, self.actor, 'delegate-crash', body)
        before = self.store.status('python-demo')['sessions']
        retried = dispatch(Store(self.store.directory), self.actor, 'delegate-crash', body)
        self.assertFalse(retried['allowed'])
        self.assertTrue(retried['replayed'])
        self.assertEqual(self.store.status('python-demo')['sessions'], before)
        self.assertEqual(len([s for s in before if s['parent'] == self.actor['session']]), 1)
        self.assertEqual(self.store.status('python-demo')['violations'], 0)

    def test_stop_request_is_not_termination_and_repeats_do_not_duplicate(self):
        stopped = self.store.stop('python-demo')
        self.assertFalse(stopped['confirmed_stopped'])
        rows = self.store.audit_export('python-demo')['events']
        self.assertEqual(rows[-1]['request']['action'], 'stop_requested')
        self.assertEqual(rows[-1]['audit']['details']['termination'], 'unconfirmed')
        self.store.stop('python-demo')
        self.assertEqual(self.store.audit_export('python-demo')['events'], rows)

    def test_unconfirmed_reconciliation_deduplicates_then_records_confirmation(self):
        from ptw.supervisor import Supervisor
        unit = 'ptw-' + '0' * 24 + '.service'
        with self.store.locked() as db:
            db.execute('INSERT INTO workloads(unit,project,session) VALUES(?,?,?)',
                       (unit, 'python-demo', self.actor['session']))
        self.store.stop('python-demo')
        with patch.object(Supervisor, 'terminate', return_value={'confirmed_stopped': False}):
            for _ in range(3):
                self.assertFalse(Supervisor(self.store).reconcile()[0]['confirmed_stopped'])
        rows = self.store.audit_export('python-demo')['events']
        terminations = [r for r in rows if r['request']['action'] == 'workload_termination']
        self.assertEqual(len(terminations), 1)
        self.assertEqual(terminations[0]['audit']['outcome'], 'unconfirmed')
        with patch.object(Supervisor, 'terminate', return_value={'confirmed_stopped': True}):
            self.assertTrue(Supervisor(self.store).reconcile()[0]['confirmed_stopped'])
        rows = self.store.audit_export('python-demo')['events']
        self.assertEqual(len([r for r in rows if r['request']['action'] == 'workload_termination']), 2)
        self.assertTrue(self.store.status('python-demo')['workloads'][0]['stopped'])

    def test_cleanup_capture_fault_and_reconciliation_preserve_reduction_scope(self):
        from ptw.supervisor import Supervisor
        other = self.store.register('python-demo', 'implementation')
        unit = 'ptw-' + '1' * 24 + '.service'
        with self.store.locked() as db:
            db.execute('INSERT INTO workloads(unit,project,session) VALUES(?,?,?)',
                       (unit, 'python-demo', self.actor['session']))
            db.execute("CREATE TRIGGER reject_cleanup BEFORE INSERT ON events "
                "WHEN json_extract(NEW.request_meta,'$.action')='workload_termination' "
                "BEGIN SELECT RAISE(FAIL,'injected cleanup capture failure'); END")
        self.store.close_session(self.actor['token'])
        with patch.object(Supervisor, 'terminate', return_value={'confirmed_stopped': True}):
            outcome = Supervisor(self.store).reconcile()[0]
            self.assertTrue(outcome['confirmed_stopped'])
            self.assertEqual(outcome['evidence'], 'unavailable')
            self.assertFalse(self.store.status('python-demo')['stopped'])
            self.assertTrue(self.broker.request(other['token'], 'other-parent', request('read', 'src', 'calculator.py'))['allowed'])
            # Ordinary cleanup still holds publication by stopping affected
            # project admission when its required capture fails.
            outcome = Supervisor(self.store).terminate_recorded(unit)
        self.assertEqual(outcome['evidence'], 'unavailable')
        self.assertTrue(self.store.status('python-demo')['stopped'])
        self.assertFalse(self.store.status('python-demo')['workloads'][0]['stopped'])


class AuditStorageTests(workspace_fixtures.WorkspaceFixture):
    def adopt(self, **changes):
        profile = {**DEFAULT, **changes}
        packet = self.store.evidence_review('python-demo', profile)
        return self.store.adopt_evidence('python-demo', profile, digest(packet), 'fixture operator')

    def test_private_default_opt_in_truncation_and_denied_scope(self):
        self.adopt()
        self.ask('create', path='default.txt', content='metadata only')
        with self.store.locked() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM evidence_payloads').fetchone()[0], 0)
        self.adopt(content_resources=['src'])
        text = 'source fixture\n' * 30000
        self.assertTrue(self.ask('create', path='captured.txt', content=text)['allowed'])
        with self.store.locked() as db:
            payload = db.execute('SELECT * FROM evidence_payloads').fetchone()
            self.assertEqual(payload['payload'], text.encode()[:PAYLOAD_BYTES])
            self.assertEqual(payload['sha256'], hashlib.sha256(text.encode()).hexdigest())
            self.assertEqual(payload['original_bytes'], len(text.encode()))
            self.assertEqual(payload['status'], 'truncated')
        self.assertEqual(self.store.directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.store.db.stat().st_mode & 0o777, 0o600)
        exported = self.store.audit_export('python-demo')
        self.assertNotIn('source fixture', canonical(exported))
        self.assertNotIn(self.actor['token'], canonical(exported))
        self.assertEqual(exported['payloads'][0]['status'], 'truncated')
        row = exported['payloads'][0]
        operation = digest([row['session'], row['event']])
        self.assertEqual(self.store.evidence_content('python-demo', operation)['payload'], text.encode()[:PAYLOAD_BYTES])
        with self.store.locked() as db:
            db.execute("UPDATE evidence_payloads SET payload=x'00'")
        with self.assertRaisesRegex(Invalid, 'payload changed'):
            self.store.evidence_content('python-demo', operation)
        for invalid in ({**DEFAULT, 'content_resources': ['private']},
                        {**DEFAULT, 'content_resources': ['src', 'src']},
                        {**DEFAULT, 'project_bytes': True}, {**DEFAULT, 'version': 2}):
            with self.subTest(invalid=invalid), self.assertRaises(Invalid):
                self.store.evidence_review('python-demo', invalid)

    def test_optional_capture_failure_is_visible_without_stopping_useful_work(self):
        self.adopt(content_resources=['src'])
        with self.store.locked() as db:
            db.execute("CREATE TRIGGER no_payload BEFORE INSERT ON evidence_payloads "
                       "BEGIN SELECT RAISE(FAIL,'optional payload unavailable'); END")
        self.assertTrue(self.ask('create', path='useful.txt', content='useful')['allowed'])
        self.assertEqual((Path(self.inv['root']) / 'src/useful.txt').read_text(), 'useful')
        self.assertEqual(self.store.audit_events('python-demo')[-1]['audit']['content'], 'unavailable')
        self.assertFalse(self.store.status('python-demo')['stopped'])
        self.assertEqual(self.store.status('python-demo')['violations'], 0)

    def test_quota_precedes_mutation_and_preserves_unrelated_project(self):
        self.adopt(project_bytes=1024 * 1024)
        other_policy = copy.deepcopy(self.policy)
        other_policy['project']['id'] = 'unrelated'
        from ptw.policy import approve, compile_policy
        self.store.activate(approve(other_policy, self.inv, digest(compile_policy(other_policy, self.inv)), 'operator'))
        other = self.store.register('unrelated', 'implementation')
        self.assertTrue(self.ask('read')['allowed'])
        result = self.ask('create', path='not-created.txt', content='effect must not occur')
        self.assertFalse(result['allowed'])
        self.assertEqual(result['level'], 'stop')
        self.assertIn('quota', result['reason'])
        self.assertFalse((Path(self.inv['root']) / 'src/not-created.txt').exists())
        self.assertTrue(self.store.status('python-demo')['stopped'])
        self.assertEqual(self.store.status('python-demo')['violations'], 0)
        self.assertTrue(self.broker.request(other['token'], 'still-useful', request('read', 'src', 'calculator.py'))['allowed'])
        recovered = Store(self.store.directory)
        self.assertTrue(recovered.status('python-demo')['stopped'])
        self.assertEqual(recovered.status('python-demo')['violations'], 0)

    def test_concurrent_reservations_cannot_both_admit_or_publish_after_quota_fault(self):
        from ptw.store import operation_lease
        second = next('second-' + str(i) for i in range(100)
                      if operation_lease(self.actor['session'], 'second-' + str(i)) !=
                      operation_lease(self.actor['session'], 'first'))
        self.adopt(project_bytes=400 * 1024 * 1024)
        entered, finish = threading.Event(), threading.Event()
        calls = []
        def execute(store, token, definition, before, settings, **kwargs):
            calls.append(True)
            entered.set()
            self.assertTrue(finish.wait(5))
            after = dict(before)
            after['dist/late.txt'] = {'kind': 'file', 'data': b'late', 'mode': 0o644}
            return after, {'exit_code': 0, 'output': ''}
        with patch('ptw.execution.execute', side_effect=execute):
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(self.broker.request, self.actor['token'], 'first', request('run', 'test'))
                self.assertTrue(entered.wait(5))
                try:
                    with self.assertRaises(QuotaError):
                        self.broker.request(self.actor['token'], second, request('run', 'test'))
                finally:
                    finish.set()
                self.assertFalse(first.result(timeout=5)['allowed'])
        self.assertEqual(calls, [True])
        self.assertFalse((Path(self.inv['root']) / 'dist/late.txt').exists())
        self.assertEqual(self.store.status('python-demo')['violations'], 0)

    def test_rejected_event_ids_cannot_grow_lease_storage_beyond_reserved_pool(self):
        from ptw.store import LEASE_SLOTS
        from ptw.evidence_storage import usage, ROW_OVERHEAD
        self.adopt()
        with self.store.locked() as db:
            baseline = usage(db, 'python-demo')
            self.assertGreaterEqual(baseline, ROW_OVERHEAD * LEASE_SLOTS)
            db.execute('UPDATE evidence_profiles SET profile=? WHERE project=?',
                       (canonical({**DEFAULT, 'project_bytes': baseline}), 'python-demo'))
            baseline = usage(db, 'python-demo')
        with patch('ptw.execution.execute') as execute:
            for i in range(2 * LEASE_SLOTS + 1):
                with self.assertRaises(QuotaError):
                    self.broker.request(self.actor['token'], 'rejected-' + str(i), request('run', 'test'))
        execute.assert_not_called()
        locks = list(self.store.directory.glob('operation-*.lock'))
        self.assertLessEqual(len(locks), LEASE_SLOTS)
        self.assertTrue(all(p.stat().st_size == 0 and p.stat().st_mode & 0o777 == 0o600 for p in locks))
        self.assertTrue(self.store.status('python-demo')['stopped'])
        self.assertEqual(self.store.status('python-demo')['violations'], 0)
        with self.store.locked() as db:
            # All slots were reserved already, including unused ones.
            self.assertEqual(usage(db, 'python-demo'), baseline)



    def test_expiry_tombstones_keep_replay_and_unresolved_references(self):
        self.adopt(content_resources=['src'])
        body = request('create', 'src', 'retained.txt', content='retain required replay')
        original = self.broker.request(self.actor['token'], 'retained', body)
        with self.store.locked() as db:
            db.execute('UPDATE evidence_payloads SET at=?', (time.time() - RETENTION_SECONDS - 1,))
            db.execute('INSERT INTO evidence_pins VALUES(?,?)', ('python-demo', 'fixture-review'))
        self.assertTrue(self.store.expire_evidence('python-demo')['pinned'])
        with self.store.locked() as db:
            db.execute('DELETE FROM evidence_pins')
            self.store.begin(db, self.actor['session'], 'uncertain', digest(body), body)
        recovered = Store(self.store.directory)
        self.assertTrue(recovered.expire_evidence('python-demo')['pinned'])
        self.assertEqual(recovered.audit_events('python-demo')[-1]['state'], 'uncertain')
        # A separate healthy fixture proves eligible expiry without clearing uncertainty.
        other = Store(self.root / 'healthy-state')
        other.activate(self.approve())
        actor = other.register('python-demo', 'implementation')
        packet = other.evidence_review('python-demo', {**DEFAULT, 'content_resources': ['src']})
        other.adopt_evidence('python-demo', packet['profile'], digest(packet), 'operator')
        read = request('read', 'src', 'retained.txt')
        first = Workspace(other).request(actor['token'], 'read', read)
        with other.locked() as db:
            db.execute('UPDATE evidence_payloads SET at=?', (time.time() - RETENTION_SECONDS - 1,))
        self.assertEqual(other.expire_evidence('python-demo'), {'expired': 1, 'pinned': False})
        self.assertEqual(other.expire_evidence('python-demo')['expired'], 0)
        row = other.audit_export('python-demo')['payloads'][0]
        self.assertEqual(row['status'], 'expired')
        self.assertIsNotNone(row['expired_at'])
        with other.locked() as db:
            self.assertIsNone(db.execute('SELECT payload FROM evidence_payloads').fetchone()[0])
        self.assertEqual(Workspace(other).request(actor['token'], 'read', read), {**first, 'replayed': True})
        self.assertTrue(original['allowed'])

    def test_adoption_is_exact_stale_review_rejected_and_old_runtime_refused(self):
        packet = self.store.evidence_review('python-demo', DEFAULT)
        self.ask('read')
        with self.assertRaisesRegex(Invalid, 'exact operator review'):
            self.store.adopt_evidence('python-demo', DEFAULT, digest(packet), 'operator')
        self.adopt()
        with sqlite3.connect(self.store.db) as legacy:
            # This is the shipped old runtime's project query, without the new
            # connection capability. It cannot reach registration or effects.
            with self.assertRaisesRegex(sqlite3.OperationalError, 'ptw_evidence_runtime'):
                legacy.execute('SELECT * FROM projects WHERE id=?', ('python-demo',)).fetchone()
            with self.assertRaisesRegex(sqlite3.OperationalError, 'ptw_evidence_runtime'):
                legacy.execute('UPDATE projects SET stopped=0')
        self.assertTrue(self.ask('read')['allowed'])
        with self.store.locked() as db:
            db.execute('PRAGMA user_version=99')
        with self.assertRaisesRegex(Invalid, 'Unsupported controller evidence schema'):
            Store(self.store.directory)

    def test_backed_up_migration_keeps_counts_stops_quarantine_and_legacy_unknown(self):
        self.ask('read')
        with self.store.locked() as db:
            db.execute("UPDATE projects SET violations=2,stopped=1,reason='original stop'")
            db.execute('UPDATE task_counts SET violations=2')
            db.execute('UPDATE sessions SET closed=1')
            db.execute("UPDATE events SET request_meta='{}' WHERE session=?", (self.actor['session'],))
            db.execute("INSERT INTO package_sets(id,project,names,manifest,created,assessment_state) "
                       "VALUES('historical','python-demo','[]','{}',0,'quarantined')")
            for table in ('evidence_profiles', 'evidence_payloads', 'evidence_pins'):
                db.execute('DROP TABLE ' + table)
            db.execute('PRAGMA user_version=0')
        recovered = Store(self.store.directory)
        status = recovered.status('python-demo')
        self.assertEqual((status['violations'], status['stopped'], status['reason']), (2, 1, 'original stop'))
        self.assertTrue(all(s['closed'] for s in status['sessions']))
        self.assertEqual(status['package_sets'][0]['assessment_state'], 'quarantined')
        self.assertEqual(recovered.audit_events('python-demo')[0]['audit']['coverage'], 'legacy_unknown')
        snapshots = list(self.store.directory.glob('migration-*.sqlite3'))
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(snapshots[0].stat().st_mode & 0o777, 0o600)
        receipt = json.loads(snapshots[0].with_suffix('.json').read_text())
        self.assertEqual(receipt['sha256'], hashlib.sha256(snapshots[0].read_bytes()).hexdigest())
        self.store = recovered
        self.adopt()
        self.assertEqual(recovered.status('python-demo'), status)

    def test_interrupted_adoption_rolls_back_without_reactivating_or_losing_history(self):
        self.ask('read')
        before = self.store.audit_export('python-demo')['events']
        with self.store.locked() as db:
            db.execute("CREATE TRIGGER reject_adoption BEFORE INSERT ON evidence_profiles "
                       "BEGIN SELECT RAISE(FAIL,'injected adoption crash'); END")
        with self.assertRaises(sqlite3.Error):
            self.adopt()
        recovered = Store(self.store.directory)
        self.assertIsNone(recovered.audit_export('python-demo')['profile'])
        self.assertEqual(recovered.audit_export('python-demo')['events'], before)
        with recovered.locked() as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 1)
            db.execute('DROP TRIGGER reject_adoption')
        self.store = recovered
        self.adopt()
        self.assertTrue(self.ask('read')['allowed'])

    def test_interrupted_schema_migration_retains_stopped_backup_and_rolls_back_columns(self):
        with self.store.locked() as db:
            for table in ('evidence_profiles', 'evidence_payloads', 'evidence_pins'):
                db.execute('DROP TABLE ' + table)
            db.execute('ALTER TABLE sessions DROP COLUMN conversation')
            db.execute('ALTER TABLE sessions DROP COLUMN resume_of')
            db.execute('PRAGMA user_version=0')
        def crash(store, db):
            db.execute('CREATE TABLE evidence_profiles(project TEXT)')
            raise SystemExit('injected migration interruption')
        with patch('ptw.evidence_storage.migrate', side_effect=crash), self.assertRaises(SystemExit):
            Store(self.store.directory)
        with sqlite3.connect(self.store.db) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 0)
            self.assertNotIn('conversation', {r[1] for r in db.execute('PRAGMA table_info(sessions)')})
            self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE name='evidence_profiles'").fetchone())
        backup = next(self.store.directory.glob('migration-*.sqlite3'))
        with sqlite3.connect(backup) as db:
            self.assertEqual(db.execute('SELECT stopped FROM projects').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT count(*) FROM sessions').fetchone()[0], 1)
        recovered = Store(self.store.directory)
        self.assertTrue(Workspace(recovered).request(self.actor['token'], 'after-migration', request('read', 'src', 'calculator.py'))['allowed'])

    def test_package_assessment_export_preserves_original_rule_and_unknown_legacy(self):
        from ptw.reassessment import attempt
        with self.store.locked() as db:
            db.execute("INSERT INTO package_sets(id,project,names,manifest,created) VALUES('pkg','python-demo','[]','{}',0)")
            db.execute("INSERT INTO package_assessments VALUES('legacy','pkg',0,'current','{}')")
            actor = self.store.session(db, self.actor['token'])
            attempt(db, 'pkg', 'blocked', {'errors': ['PRIVATE_DIAGNOSTIC']}, actor=actor)
        first = self.store.audit_export('python-demo')
        self.assertNotIn('PRIVATE_DIAGNOSTIC', canonical(first))
        self.assertEqual(first['assessments'][0]['audit']['authority'], 'legacy_unknown')
        evidence = first['assessments'][1]['audit']
        self.assertIsNone(evidence['source_at'])
        self.assertEqual(evidence['requester']['id'], self.actor['session'])
        self.assertFalse(evidence['authorization']['human_review_performed'])
        self.assertEqual(evidence['policy_sha256'], self.approve()['approval']['sha256'])
        with self.store.locked() as db:
            bundle = self.approve()
            bundle['policy']['project']['packages']['min_release_age_days'] += 1
            db.execute('UPDATE projects SET bundle=?', (canonical(bundle),))
        self.assertEqual(self.store.audit_export('python-demo')['assessments'], first['assessments'])
        with self.store.locked() as db:
            row = db.execute("SELECT attempt,detail FROM package_assessments WHERE attempt!='legacy'").fetchone()
            changed = json.loads(row['detail'])
            changed['_audit']['authorization']['human_review_performed'] = True
            db.execute('UPDATE package_assessments SET detail=? WHERE attempt=?', (canonical(changed), row['attempt']))
        with self.assertRaisesRegex(Invalid, 'assessment evidence changed'):
            self.store.audit_export('python-demo')

    def test_archive_requires_closed_resolved_history_and_never_deletes_replay(self):
        self.adopt()
        self.ask('read')
        destination = self.root / 'archive' / 'closed.json'
        with self.assertRaises(Invalid):
            self.store.archive_evidence('python-demo', destination)
        self.store.close_session(self.actor['token'])
        self.store.stop('python-demo')
        before = self.store.audit_export('python-demo')
        result = self.store.archive_evidence('python-demo', destination)
        self.assertFalse(result['required_history_deleted'])
        self.assertEqual(destination.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(destination.read_text()), before)
        self.assertTrue(verify_export(before, result['sha256'])['verified'])
        self.assertEqual(self.store.audit_export('python-demo'), before)
        with self.assertRaises(FileExistsError):
            self.store.archive_evidence('python-demo', destination)

    def test_new_reviewed_profile_admits_useful_work_and_displays_limits(self):
        from ptw.onboarding import short_review
        self.policy['project']['audit'] = copy.deepcopy(DEFAULT)
        bundle = self.approve()
        shown = short_review({'policy': self.policy, 'inventory': self.inv}, {}, [])
        self.assertIn('1073741824', shown)
        self.assertIn('optional content off by default', shown)
        fresh = Store(self.root / 'fresh-state')
        fresh.activate(bundle)
        actor = fresh.register('python-demo', 'implementation')
        self.assertTrue(Workspace(fresh).request(actor['token'], 'useful', request('create', 'src', 'new.txt', content='new'))['allowed'])
        self.assertEqual(fresh.audit_export('python-demo')['profile'], DEFAULT)


@unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'Requires native isolated package installer')
class AuditInstallTests(workspace_fixtures.WorkspaceFixture):
    """Real dispatch/installer effects; registry responses are synthetic fixtures."""

    def install_events(self, *, reversed_slots=False):
        from ptw.store import operation_lease
        body = request('install', 'dependencies', content='pypi')
        seen = {}
        for index in range(10000):
            event = 'install-audit-' + str(index)
            inner = 'install-' + digest([event, body])[:48]
            slots = tuple(operation_lease(self.actor['session'], e) for e in (event, inner))
            if not reversed_slots and slots[0] == slots[1]:
                return body, [event]
            if reversed_slots and slots[0] != slots[1] and slots[::-1] in seen:
                return body, [seen[slots[::-1]], event]
            seen[slots] = event
        self.fail('Could not find fixture slot collision')

    def isolated(self, run):
        # A regression must fail within a bound, not strand unittest threads
        # inside flock or ThreadPoolExecutor.shutdown(). No model/network calls.
        import multiprocessing
        import traceback
        context = multiprocessing.get_context('fork')
        receiver, sender = context.Pipe(duplex=False)
        def child():
            receiver.close()
            try:
                result = run()
                sender.send({'result': result})
            except BaseException:
                sender.send({'error': traceback.format_exc()})
            finally:
                sender.close()
        process = context.Process(target=child)
        process.start()
        sender.close()
        try:
            self.assertTrue(receiver.poll(60), 'Install dispatch did not complete within 60 seconds')
            result = receiver.recv()
            process.join(5)
            self.assertEqual(process.exitcode, 0, result)
            self.assertNotIn('error', result, result.get('error'))
            return result['result']
        finally:
            if process.is_alive():
                process.kill()
                process.join(5)
            receiver.close()

    def useful_install(self, result):
        import subprocess
        from ptw.packages import mounted_set
        from ptw.supervisor import sandbox_command
        self.assertTrue(result['allowed'], result)
        with self.store.locked() as db:
            mount = mounted_set(self.store, db, self.store.session(db, self.actor['token']), result['package_set'])
        run = subprocess.run(sandbox_command(self.inv, [],
            ['/usr/bin/python3', '-c', 'import six; print(six.VALUE)'], package_mount=mount),
            capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn('SYNTHETIC_PACKAGE_OK', run.stdout)

    def test_dispatch_nested_collision_installs_once_and_live_reopen_preserves_intents(self):
        from ptw.workflow import dispatch
        from test_packages import FixtureProvider
        body, (event,) = self.install_events()
        def run():
            provider = FixtureProvider()
            entered, finish = threading.Event(), threading.Event()
            assess = provider.assess
            def delayed(*args):
                reopened = Store(self.store.directory)
                self.assertFalse(reopened.status('python-demo')['stopped'])
                self.assertEqual(sum(r['state'] == 'pending' for r in reopened.audit_events('python-demo')), 2)
                entered.set()
                self.assertTrue(finish.wait(5))
                return assess(*args)
            with patch('ptw.registry.provider_for', return_value=provider), patch.object(provider, 'assess', side_effect=delayed):
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    original = pool.submit(dispatch, self.store, self.actor, event, body)
                    try:
                        self.assertTrue(entered.wait(5))
                        retry = pool.submit(dispatch, Store(self.store.directory), self.actor, event, body)
                        self.assertFalse(retry.done())
                    finally:
                        finish.set()
                    first, second = original.result(timeout=20), retry.result(timeout=20)
                self.useful_install(first)
                self.assertTrue(second['replayed'])
                self.assertEqual(second['package_set'], first['package_set'])
                self.assertEqual(provider.downloads, 1)
                self.assertEqual(len(list(self.store.directory.glob('operation-*.lock'))), 1)
                self.assertTrue(dispatch(self.store, self.actor, event, body)['replayed'])
            self.assertTrue(all(r['state'] == 'complete' for r in self.store.audit_events('python-demo')))
        self.isolated(run)

    def test_dispatch_concurrent_reversed_slots_complete_and_replay_distinct_installs(self):
        from ptw.workflow import dispatch, _dispatch
        from test_packages import FixtureProvider
        body, events = self.install_events(reversed_slots=True)
        def run():
            provider = FixtureProvider()
            rendezvous = threading.Barrier(2)
            def overlapping(*args):
                # Old code gets both outer locks before either inner lock.
                # Ordered reservation serializes here, so the first waits at
                # most one second before continuing with both slots held.
                try:
                    rendezvous.wait(timeout=1)
                except threading.BrokenBarrierError:
                    pass
                return _dispatch(*args)
            with patch('ptw.registry.provider_for', return_value=provider), patch('ptw.workflow._dispatch', side_effect=overlapping):
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    pending = [pool.submit(dispatch, self.store, self.actor, e, body) for e in events]
                    results = [future.result(timeout=25) for future in pending]
                self.assertEqual(len({r['package_set'] for r in results}), 2)
                for event, result in zip(events, results):
                    self.useful_install(result)
                    replay = dispatch(self.store, self.actor, event, body)
                    self.assertTrue(replay['replayed'])
                    self.assertEqual(replay['package_set'], result['package_set'])
                self.assertEqual(provider.downloads, 2)
                self.assertEqual(len(list(self.store.directory.glob('operation-*.lock'))), 2)
            self.assertFalse(self.store.status('python-demo')['stopped'])
            self.assertEqual(self.store.status('python-demo')['violations'], 0)
        self.isolated(run)

    def test_dispatch_abrupt_nested_install_crash_stops_without_reinstallation(self):
        from ptw.workflow import dispatch
        from ptw.packages import install_wheels
        from test_packages import FixtureProvider
        body, events = self.install_events(reversed_slots=True)
        event = events[0]
        observed = self.root / 'staged-install.json'
        def run():
            def crash(wheelhouse, target, evidence, **kwargs):
                install_wheels(wheelhouse, target, evidence, **kwargs)
                # Independent physical oracle before abrupt exit, no finally.
                observed.write_text(json.dumps({'module': (target / 'six/__init__.py').read_text()}))
                os._exit(77)
            with patch('ptw.registry.provider_for', return_value=FixtureProvider()), patch('ptw.packages.install_wheels', side_effect=crash):
                dispatch(self.store, self.actor, event, body)
        # Unlike isolated(), this child intentionally exits before sending.
        import multiprocessing
        process = multiprocessing.get_context('fork').Process(target=run)
        process.start()
        try:
            process.join(30)
            self.assertEqual(process.exitcode, 77)
            self.assertIn('SYNTHETIC_PACKAGE_OK', json.loads(observed.read_text())['module'])
            recovered = Store(self.store.directory)
            self.assertTrue(recovered.status('python-demo')['stopped'])
            rows = recovered.audit_events('python-demo')
            self.assertEqual(sum(r['state'] == 'uncertain' for r in rows), 2)
            self.assertEqual(recovered.status('python-demo')['violations'], 0)
            with recovered.locked() as db:
                self.assertEqual(db.execute('SELECT count(*) FROM package_sets').fetchone()[0], 0)
            with patch('ptw.registry.provider_for') as provider:
                retry = dispatch(recovered, self.actor, event, body)
            self.assertTrue(retry['replayed'])
            self.assertFalse(retry['allowed'])
            provider.assert_not_called()
        finally:
            if process.is_alive():
                process.kill()
                process.join(5)


class AuditLegacyReadTests(unittest.TestCase):
    def setUp(self):
        import test_core
        self.approved = lambda: test_core.Fixture.approved(self)
        test_core.Fixture.setUp(self)

    def adopt(self, resources):
        profile = {**DEFAULT, 'content_resources': resources}
        packet = self.store.evidence_review('website', profile)
        self.store.adopt_evidence('website', profile, digest(packet), 'fixture operator')

    def read(self, event, resource='ui'):
        return self.store.request(self.a['token'], event,
                                  {'action': 'read', 'resource': resource, 'content': ''})

    def test_public_read_opt_in_completion_truncation_replay_and_denial(self):
        self.adopt([])
        self.assertTrue(self.read('default')['allowed'])
        self.adopt(['ui'])
        text = 'bounded fixture\n' * 20000
        (Path(self.inv['root']) / 'ui.txt').write_text(text)
        result = self.read('captured')
        self.assertEqual(result['content'], text)
        self.assertTrue(self.read('captured')['replayed'])
        retained = self.store.evidence_content('website', digest([self.a['session'], 'captured']))
        self.assertEqual(retained['payload'], text.encode()[:PAYLOAD_BYTES])
        self.assertEqual(retained['status'], 'truncated')
        denied_actor = self.store.register('website', 'frontend', grants=[])
        self.assertFalse(self.store.request(denied_actor['token'], 'denied',
            {'action': 'read', 'resource': 'ui', 'content': ''})['allowed'])
        with self.store.locked() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM evidence_payloads').fetchone()[0], 1)
        rows = self.store.audit_events('website')
        self.assertEqual(rows[0]['audit']['content'], 'omitted')
        self.assertEqual(rows[1]['audit']['content'], 'truncated')
        self.assertNotIn('bounded fixture', canonical(self.store.audit_export('website')))

    def test_optional_read_write_failure_keeps_useful_result_and_visible_gap(self):
        self.adopt(['ui'])
        with self.store.locked() as db:
            db.execute("CREATE TRIGGER reject_optional BEFORE INSERT ON evidence_payloads "
                       "BEGIN SELECT RAISE(FAIL,'injected optional read capture failure'); END")
        result = self.read('optional-fault')
        self.assertEqual(result['content'], 'Welcome\n')
        with self.store.locked() as db:
            db.execute('DROP TRIGGER reject_optional')
        self.assertTrue(self.read('optional-fault')['replayed'])
        self.assertEqual(self.store.audit_events('website')[0]['audit']['content'], 'unavailable')
        with self.store.locked() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM evidence_payloads').fetchone()[0], 0)
        self.assertTrue(self.read('next')['allowed'])
        self.assertEqual(self.store.audit_events('website')[-1]['audit']['content'], 'captured')
        self.assertFalse(self.store.status('website')['stopped'])
        self.assertEqual(self.store.status('website')['violations'], 0)


class AuditPolicyTests(unittest.TestCase):
    # Reuse fixture builders without inheriting their already discovered tests.
    setUp = ecosystem_fixtures.DependencyRevisionTests.setUp
    activated = ecosystem_fixtures.DependencyRevisionTests.activated
    remove = ecosystem_fixtures.DependencyRevisionTests.remove

    def test_reviewed_rule_change_keeps_original_authority_and_useful_continuation(self):
        _, store, old_actor, old_bundle, _ = self.activated()
        original = store.audit_export('revision-project')['events']
        self.remove()  # Exact operator review via the existing dependency CLI fixture.
        new_actor = store.register('revision-project', 'work')
        resource = next(r for r, item in old_bundle['inventory']['resources'].items() if item['path'] == 'src')
        result = Workspace(store).request(new_actor['token'], 'after-review', request('read', resource, 'app.py'))
        self.assertTrue(result['allowed'], result)
        self.assertEqual(result['content'], 'VALUE = 42\n')
        rows = store.audit_export('revision-project')['events']
        self.assertEqual(rows[:len(original)], original)
        revised = next(r for r in rows if r['request']['action'] == 'policy_revised')
        self.assertEqual(revised['audit']['details']['previous_policy_sha256'], old_bundle['approval']['sha256'])
        self.assertTrue(revised['audit']['authorization']['human_review_performed'])
        self.assertNotEqual(revised['audit']['policy_sha256'], old_bundle['approval']['sha256'])
        self.assertEqual(rows[-1]['audit']['policy_sha256'], revised['audit']['policy_sha256'])
        self.assertEqual(store.status('revision-project')['violations'], 1)
        with self.assertRaises(Invalid):
            Workspace(store).request(old_actor['token'], 'revoked', request('read', resource, 'app.py'))


class AuditCheckpointTests(daily_fixtures.LocalGitFixture):
    def test_checkpoint_pending_review_pins_payload_and_quota_blocks_ref_publication(self):
        profile = {**DEFAULT, 'content_resources': ['src']}
        packet = self.store.evidence_review('python-demo', profile)
        self.store.adopt_evidence('python-demo', profile, digest(packet), 'operator')
        self.changed()
        prepared = self.checkpoint()
        self.assertTrue(prepared['allowed'])
        with self.store.locked() as db:
            db.execute('UPDATE evidence_payloads SET at=?', (time.time() - RETENTION_SECONDS - 1,))
        self.assertTrue(self.store.expire_evidence('python-demo')['pinned'])
        # A reviewed smaller budget is sufficient for retained history, but
        # cannot reserve a new physical publication. No host disk is filled.
        reduced = {**profile, 'project_bytes': 2 * 1024 * 1024}
        packet = self.store.evidence_review('python-demo', reduced)
        self.store.adopt_evidence('python-demo', reduced, digest(packet), 'operator')
        from ptw.local_git import publish_checkpoint
        with self.assertRaises(QuotaError):
            publish_checkpoint(self.store, prepared['checkpoint'], prepared['review_sha256'])
        self.assertNotIn('refs/ptw/checkpoints/' + prepared['checkpoint'], self.git('show-ref').decode())
        self.assertTrue(self.store.status('python-demo')['stopped'])
        self.assertEqual(self.store.status('python-demo')['violations'], 0)

    def test_exact_human_approval_and_automatic_edit_have_distinct_provenance(self):
        self.changed()
        prepared = self.checkpoint()
        self.assertTrue(prepared['allowed'], prepared)
        before = self.store.audit_events('python-demo')
        self.assertTrue(before[-1]['audit']['authorization']['human_review_required'])
        self.assertFalse(before[-1]['audit']['authorization']['human_review_performed'])
        published = self.publish(prepared)
        self.assertEqual(self.git('rev-parse', published['ref']).decode().strip(), published['commit'])
        after = self.store.audit_events('python-demo')
        self.assertEqual(after[:-1], before)
        authority = after[-1]['audit']['authorization']
        self.assertEqual(authority['method'], 'exact_operator_approval')
        self.assertEqual(authority['receipt_sha256'], prepared['review_sha256'])
        self.assertTrue(authority['human_review_performed'])
        self.assertEqual(after[-1]['audit']['requester']['kind'], 'local_operator')

    def test_required_completion_fault_keeps_checkpoint_stopped_and_uncertain(self):
        self.changed()
        prepared = self.checkpoint()
        with patch.object(self.store, 'complete', side_effect=OSError('injected capture failure')):
            with self.assertRaises(OSError):
                self.publish(prepared)
        self.assertTrue(self.store.status('python-demo')['stopped'])
        recovered = Store(self.store.directory)
        self.assertEqual(recovered.audit_events('python-demo')[-1]['state'], 'uncertain')
        self.assertEqual(self.git('rev-parse', 'refs/ptw/checkpoints/' + prepared['checkpoint']).decode().strip(),
                         json.loads((self.store.directory / 'git-requests' / prepared['checkpoint'] / 'review.json').read_text())['commit'])
        self.assertEqual(recovered.status('python-demo')['violations'], 0)


@unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'Requires native manager terminal/supervisor')
class AuditTerminalTests(daily_fixtures.LocalGitFixture):
    def test_terminal_evidence_review_stale_rejection_and_explicit_adoption(self):
        scripts = str(Path(__file__).resolve().parents[1] / 'scripts')
        with patch.object(sys, 'path', [scripts, *sys.path]):
            from terminal_driver import Terminal
        packet = self.store.evidence_review('python-demo', DEFAULT)
        original = self.store.status('python-demo')
        argv = [sys.executable, '-B', '-m', 'ptw', 'evidence-config', '--state', str(self.store.directory),
                '--project', 'python-demo']
        # A review-only command and a failed exact hash cannot adopt silently.
        for name, extra, code in (
                ('review-only', [], 0), ('rejected', ['--approve', '0' * 64, '--reviewer', 'operator'], 2),
                ('adopted', ['--approve', digest(packet), '--reviewer', 'operator'], 0)):
            terminal = Terminal(argv + extra, self.root / name)
            try:
                terminal.wait(lambda: terminal.exited, 20, 'evidence configuration terminal')
                self.assertEqual(terminal.close(), code)
            finally:
                if not terminal.closed:
                    terminal.close(graceful=False)
            profile = Store(self.store.directory).audit_export('python-demo')['profile']
            self.assertEqual(profile, DEFAULT if name == 'adopted' else None)
            self.assertEqual(self.store.status('python-demo'), original)
        self.assertTrue(self.ask('read')['allowed'])

    def test_real_terminal_approval_rejection_and_audit_authority(self):
        from ptw.onboarding import private_directory
        from ptw.policy import save
        scripts = str(Path(__file__).resolve().parents[1] / 'scripts')
        with patch.object(sys, 'path', [scripts, *sys.path]):
            from terminal_driver import Terminal
        operator = self.root / 'operator'
        with patch.dict(os.environ, {'PTW_USER_STATE': str(operator)}):
            directory = private_directory(self.repo)
        save(directory / 'project.json', {'project': 'python-demo', 'repo': str(self.repo),
                                         'state': str(self.store.directory)})
        self.changed()
        # Preparation uses the existing deterministic Git fixture; decisions
        # are real CLI terminal input and publication is real Git ref mutation.
        for accepted in (False, True):
            with self.store.locked() as db:
                db.execute('INSERT OR REPLACE INTO monitor_health VALUES(1,?,?)', (time.time(), ''))
            prepared = self.checkpoint()
            self.assertTrue(prepared['allowed'])
            terminal = Terminal([sys.executable, '-B', '-m', 'ptw', 'checkpoint', prepared['checkpoint'],
                                 '--repo', str(self.repo)], self.root / ('approve' if accepted else 'reject'),
                                env={'PTW_USER_STATE': str(operator)})
            try:
                terminal.expect('Type approve ' + prepared['review_sha256'], 20)
                terminal.send('approve ' + prepared['review_sha256'] if accepted else 'reject')
                terminal.wait(lambda: terminal.exited, 20, 'exact checkpoint decision')
                self.assertEqual(terminal.close(), 0)
            finally:
                if not terminal.closed:
                    terminal.close(graceful=False)
            rows = self.store.audit_export('python-demo')['events']
            if accepted:
                published = next(r for r in rows if r['request']['action'] == 'checkpoint_publish')
                self.assertEqual(self.git('rev-parse', published['result']['ref']).decode().strip(), published['result']['commit'])
                self.assertTrue(published['audit']['authorization']['human_review_performed'])
                self.assertEqual(published['audit']['authorization']['receipt_sha256'], prepared['review_sha256'])
            else:
                rejected = next(r for r in rows if r['request']['action'] == 'checkpoint_rejected')
                self.assertEqual(rejected['audit']['details']['review_sha256'], prepared['review_sha256'])
                self.assertEqual(rejected['audit']['authorization']['method'], 'operator_rejection')
                self.assertTrue(rejected['audit']['authorization']['human_review_performed'])
                self.assertNotIn('refs/ptw/checkpoints/' + prepared['checkpoint'], self.git('show-ref').decode())
                self.assertFalse(any(r['request']['action'] == 'checkpoint_publish' for r in rows))


@unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1', 'Requires isolated native manager systemd/namespaces')
class NativeAuditTests(workspace_fixtures.WorkspaceFixture):
    def test_successful_build_closes_workload_while_session_remains_open(self):
        from ptw.supervisor import Supervisor
        workspace_fixtures.WorkspaceLinux.add_command(self,
            "from pathlib import Path; Path('dist/built.txt').write_text('native build')")
        result = self.ask('run', resource='probe', path='')
        self.assertTrue(result['allowed'], result)
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual((Path(self.inv['root']) / 'dist/built.txt').read_text(), 'native build')
        status = self.store.status('command-demo')
        self.assertFalse(status['stopped'])
        self.assertFalse(status['sessions'][0]['closed'])
        self.assertEqual(len(status['workloads']), 1)
        unit = status['workloads'][0]['unit']
        self.assertTrue(status['workloads'][0]['stopped'])
        self.assertTrue(Supervisor.state(unit)['confirmed_stopped'])
        rows = self.store.audit_export('command-demo')['events']
        terminations = [r for r in rows if r['request']['action'] == 'workload_termination']
        self.assertEqual(len(terminations), 1)
        self.assertTrue(terminations[0]['result']['confirmed_stopped'])
        self.assertIn(digest(['controller:command-demo', 'workload_launch:' + unit]),
                      terminations[0]['audit']['causes'])
        profile = {**DEFAULT, 'content_resources': ['src']}
        review = self.store.evidence_review('command-demo', profile)
        self.assertTrue(self.store.adopt_evidence('command-demo', profile, digest(review), 'operator')['adopted'])
        self.assertEqual(Supervisor(self.store).reconcile(), [])

    def test_build_cleanup_capture_fault_blocks_publication_and_keeps_uncertainty(self):
        from ptw.supervisor import Supervisor
        workspace_fixtures.WorkspaceLinux.add_command(self,
            "from pathlib import Path; Path('dist/uncaptured.txt').write_text('staged')")
        with self.store.locked() as db:
            db.execute("CREATE TRIGGER reject_cleanup BEFORE INSERT ON events "
                "WHEN json_extract(NEW.request_meta,'$.action')='workload_termination' "
                "BEGIN SELECT RAISE(FAIL,'injected cleanup capture failure'); END")
        try:
            result = self.broker.request(self.actor['token'], 'cleanup-fault', request('run', 'probe'))
            self.assertFalse(result['allowed'], result)
            self.assertFalse((Path(self.inv['root']) / 'dist/uncaptured.txt').exists())
            status = self.store.status('command-demo')
            self.assertTrue(status['stopped'])
            self.assertEqual(status['violations'], 0)
            self.assertEqual(len(status['workloads']), 1)
            self.assertFalse(status['workloads'][0]['stopped'])
            self.assertTrue(Supervisor.state(status['workloads'][0]['unit'])['confirmed_stopped'])
            rows = self.store.audit_export('command-demo')['events']
            self.assertFalse(any(r['request']['action'] == 'workload_termination' for r in rows))
            with patch('ptw.execution.execute') as execute:
                self.assertTrue(self.broker.request(self.actor['token'], 'cleanup-fault', request('run', 'probe'))['replayed'])
            execute.assert_not_called()
            other = self.store.register('python-demo', 'implementation')
            self.assertTrue(self.broker.request(other['token'], 'unrelated-read', request('read', 'src', 'calculator.py'))['allowed'])
        finally:
            with self.store.locked() as db:
                db.execute('DROP TRIGGER reject_cleanup')
            Supervisor(self.store).reconcile()

    def test_failed_preview_records_launch_failure_and_cleanup_with_open_session(self):
        import subprocess
        from ptw.monitor import health
        from ptw.supervisor import Supervisor
        script = Path(self.inv['root']) / 'src/server.py'
        script.write_text('raise SystemExit(7)\n')
        self.policy['project']['id'] = 'preview-audit'
        self.policy['project']['commands'].append({
            'id': 'preview', 'argv': ['/usr/bin/python3', '-B', 'src/server.py'],
            'resources': ['src'], 'timeout_seconds': 10,
            'preview': {'port': 8123, 'lifetime_seconds': 30}})
        self.policy['tasks'][0]['commands'].append('preview')
        self.store.activate(self.approve())
        self.actor = self.store.register('preview-audit', 'implementation')
        monitor = subprocess.Popen([sys.executable, '-B', '-m', 'ptw.monitor', '--state', str(self.store.directory)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while not health(self.store)['healthy'] and time.monotonic() < deadline:
                self.assertIsNone(monitor.poll(), 'Fixture monitor exited')
                time.sleep(.05)
            self.assertTrue(health(self.store)['healthy'])
            result = self.broker.request(self.actor['token'], 'failed-preview', request('service_start', 'preview'))
            self.assertFalse(result['allowed'], result)
            self.assertEqual(result['effect'], 'service_start_failed')
            self.assertTrue(result['confirmed_stopped'])
            status = self.store.status('preview-audit')
            self.assertFalse(status['stopped'])
            self.assertFalse(status['sessions'][0]['closed'])
            self.assertEqual(len(status['workloads']), 1)
            self.assertTrue(status['workloads'][0]['stopped'])
            self.assertTrue(Supervisor.state(status['workloads'][0]['unit'])['confirmed_stopped'])
            rows = self.store.audit_export('preview-audit')['events']
            operation = next(r for r in rows if r['event'] == 'failed-preview')
            self.assertEqual(operation['audit']['decision'], 'allow')
            self.assertEqual(operation['audit']['outcome'], 'failed')
            self.assertFalse(operation['result']['allowed'])
            self.assertEqual(operation['result']['unit'], status['workloads'][0]['unit'])
            self.assertTrue(operation['result']['confirmed_stopped'])
            terminations = [r for r in rows if r['request']['action'] == 'workload_termination']
            self.assertEqual(len(terminations), 1)
            self.assertTrue(terminations[0]['result']['confirmed_stopped'])
            self.assertTrue(self.broker.request(self.actor['token'], 'failed-preview', request('service_start', 'preview'))['replayed'])
            profile = {**DEFAULT, 'content_resources': ['src']}
            review = self.store.evidence_review('preview-audit', profile)
            self.assertTrue(self.store.adopt_evidence('preview-audit', profile, digest(review), 'operator')['adopted'])
            other = self.store.register('python-demo', 'implementation')
            self.assertTrue(self.broker.request(other['token'], 'useful', request('read', 'src', 'calculator.py'))['allowed'])
        finally:
            self.store.stop('preview-audit')
            Supervisor(self.store).reconcile()
            monitor.terminate()
            monitor.communicate(timeout=10)

    def test_quota_fault_stops_registered_effects_and_recovers_capture_without_reopening(self):
        from ptw.supervisor import Supervisor
        from ptw.evidence_storage import usage
        workspace_fixtures.WorkspaceLinux.add_command(self, 'pass')
        profile = copy.deepcopy(DEFAULT)
        packet = self.store.evidence_review('command-demo', profile)
        self.store.adopt_evidence('command-demo', profile, digest(packet), 'operator')
        other = self.store.register('python-demo', 'implementation')
        supervisor = Supervisor(self.store)
        running = []
        try:
            for actor, name in ((self.actor, 'quota-affected'), (other, 'quota-unrelated')):
                sentinel = self.root / (name + '.txt')
                code = ("import time; from pathlib import Path; p=Path(" + repr(str(sentinel)) + "); "
                        "\nfor i in range(1000):\n p.write_text(str(i)); time.sleep(.05)")
                process, unit = supervisor.engine(actor['token'], ['/usr/bin/python3', '-c', code])
                running.append((process, unit, sentinel))
            deadline = time.monotonic() + 5
            while not all(p.exists() for _, _, p in running) and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue(all(p.exists() for _, _, p in running))
            before_other = running[1][2].read_text()
            with self.store.locked() as db:
                # Inject an exhausted accounting budget, not a full shared disk.
                exhausted = {**profile, 'project_bytes': usage(db, 'command-demo')}
                db.execute('UPDATE evidence_profiles SET profile=? WHERE project=?',
                           (canonical(exhausted), 'command-demo'))
            with self.assertRaises(QuotaError):
                self.broker.request(self.actor['token'], 'quota-action', request('create', 'dist', 'never.txt', content='never'))
            supervisor.reconcile()
            self.assertTrue(supervisor.state(running[0][1])['confirmed_stopped'])
            self.assertFalse((Path(self.inv['root']) / 'dist/never.txt').exists())
            stopped = running[0][2].read_text()
            time.sleep(.2)
            self.assertEqual(running[0][2].read_text(), stopped)
            self.assertNotEqual(running[1][2].read_text(), before_other)
            self.assertFalse(supervisor.state(running[1][1])['confirmed_stopped'])
            self.assertEqual(self.store.status('command-demo')['violations'], 0)
            self.assertFalse(self.store.status('command-demo')['workloads'][0]['stopped'])
            # Exact operator quota increase permits recording confirmation, but
            # never clears the durable admission stop or reexecutes the request.
            packet = self.store.evidence_review('command-demo', profile)
            self.store.adopt_evidence('command-demo', profile, digest(packet), 'operator')
            result = supervisor.reconcile()
            self.assertTrue(result[0]['confirmed_stopped'])
            self.assertEqual(result[0]['evidence'], 'recorded')
            recovered = Store(self.store.directory)
            self.assertTrue(recovered.status('command-demo')['stopped'])
            self.assertFalse(Workspace(recovered).request(self.actor['token'], 'quota-action',
                request('create', 'dist', 'never.txt', content='never'))['allowed'])
            self.assertTrue(self.broker.request(other['token'], 'continue', request('read', 'src', 'calculator.py'))['allowed'])
        finally:
            for process, unit, _ in running:
                supervisor.terminate(unit)
                process.communicate(timeout=10)
            for project in ('command-demo', 'python-demo'):
                self.store.stop(project)
            supervisor.reconcile()

    def test_termination_capture_fault_preserves_physical_stop_and_unrelated_work(self):
        from ptw.supervisor import Supervisor
        workspace_fixtures.WorkspaceLinux.add_command(self, 'pass')
        other = self.store.register('python-demo', 'implementation')
        supervisor = Supervisor(self.store)
        running = []
        try:
            # Trusted supervisor fixtures, not a claimed unrestricted worker route.
            for actor, name in ((self.actor, 'affected'), (other, 'unrelated')):
                sentinel = self.root / (name + '.txt')
                code = ("import time; from pathlib import Path; p=Path(" + repr(str(sentinel)) + "); "
                        "\nfor i in range(1000):\n p.write_text(str(i)); time.sleep(.05)")
                process, unit = supervisor.engine(actor['token'], ['/usr/bin/python3', '-c', code])
                running.append((process, unit, sentinel))
            deadline = time.monotonic() + 5
            while not all(p.exists() for _, _, p in running) and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue(all(p.exists() for _, _, p in running))
            before_other = running[1][2].read_text()
            self.store.stop('command-demo')
            with self.store.locked() as db:
                db.execute("CREATE TRIGGER reject_termination BEFORE INSERT ON events "
                    "WHEN json_extract(NEW.request_meta,'$.action')='workload_termination' "
                    "BEGIN SELECT RAISE(FAIL,'injected termination capture fault'); END")
            result = supervisor.reconcile()
            self.assertEqual(len(result), 1)
            self.assertTrue(result[0]['confirmed_stopped'])
            self.assertEqual(result[0]['evidence'], 'unavailable')
            stopped_content = running[0][2].read_text()
            self.assertTrue(supervisor.state(running[0][1])['confirmed_stopped'])
            self.assertFalse(self.store.status('command-demo')['workloads'][0]['stopped'])
            time.sleep(.2)
            self.assertEqual(running[0][2].read_text(), stopped_content)
            self.assertNotEqual(running[1][2].read_text(), before_other)
            self.assertFalse(supervisor.state(running[1][1])['confirmed_stopped'])
            self.assertEqual(self.store.status('command-demo')['violations'], 0)
            with self.store.locked() as db:
                db.execute('DROP TRIGGER reject_termination')
            self.assertEqual(supervisor.reconcile()[0]['evidence'], 'recorded')
            rows = self.store.audit_export('command-demo')['events']
            termination = next(r for r in rows if r['request']['action'] == 'workload_termination')
            self.assertTrue(termination['result']['confirmed_stopped'])
            self.assertIn(digest(['controller:command-demo', 'workload_launch:' + running[0][1]]),
                          termination['audit']['causes'])
            self.assertTrue(self.broker.request(other['token'], 'useful', request('read', 'src', 'calculator.py'))['allowed'])
        finally:
            with self.store.locked() as db:
                db.execute('DROP TRIGGER IF EXISTS reject_termination')
            for process, unit, _ in running:
                supervisor.terminate(unit)
                process.communicate(timeout=10)
            for project in ('python-demo', 'command-demo'):
                self.store.stop(project)
            supervisor.reconcile()

    def test_failed_closure_storage_still_terminates_subtree_only(self):
        from ptw.supervisor import Supervisor
        child = self.store.register('python-demo', 'readcheck', parent_token=self.actor['token'])
        supervisor = Supervisor(self.store)
        running = []
        try:
            for actor in (self.actor, child):
                running.append(supervisor.engine(actor['token'], ['/usr/bin/sleep', '30']))
            with self.store.locked() as db:
                db.execute("CREATE TRIGGER reject_closure BEFORE UPDATE OF closed ON sessions "
                    "BEGIN SELECT RAISE(FAIL,'injected closure storage fault'); END")
            with self.assertRaises(sqlite3.Error):
                self.store.close_session(child['token'])
            self.assertTrue(supervisor.state(running[1][1])['confirmed_stopped'])
            self.assertFalse(supervisor.state(running[0][1])['confirmed_stopped'])
            self.assertTrue(self.ask('read')['allowed'])
            # The failed write is never represented as durable revocation.
            status = self.store.status('python-demo')
            self.assertFalse(next(s for s in status['sessions'] if s['id'] == child['session'])['closed'])
            self.assertEqual(status['violations'], 0)
        finally:
            with self.store.locked() as db:
                db.execute('DROP TRIGGER IF EXISTS reject_closure')
            self.store.close_session(child['token'])
            for process, unit in running:
                supervisor.terminate(unit)
                process.communicate(timeout=10)
            supervisor.reconcile()

    def test_abrupt_controller_exit_releases_lease_without_publishing_or_retry(self):
        import multiprocessing
        from ptw.execution import execute
        from ptw.supervisor import Supervisor
        workspace_fixtures.WorkspaceLinux.add_command(self,
            "from pathlib import Path; Path('dist/crash-output.txt').write_text('staged real effect')")
        body = request('run', 'probe')
        receiver, sender = multiprocessing.get_context('fork').Pipe(duplex=False)
        def die_after_native_effect():
            receiver.close()
            def crash(*args, **kwargs):
                after, result = execute(*args, **kwargs)
                sender.send({'observed': after['dist/crash-output.txt']['data'], 'exit_code': result['exit_code']})
                os._exit(77)  # No Python finally, response, or lease cleanup.
            with patch('ptw.execution.execute', side_effect=crash):
                self.broker.request(self.actor['token'], 'abrupt-crash', body)
        process = multiprocessing.get_context('fork').Process(target=die_after_native_effect)
        process.start()
        sender.close()
        try:
            self.assertTrue(receiver.poll(20), 'Native effect oracle was not received')
            self.assertEqual(receiver.recv(), {'observed': b'staged real effect', 'exit_code': 0})
            process.join(5)
            self.assertEqual(process.exitcode, 77)
            self.assertFalse((Path(self.inv['root']) / 'dist/crash-output.txt').exists())
            recovered = Store(self.store.directory)
            Supervisor(recovered).reconcile()
            self.assertTrue(recovered.status('command-demo')['stopped'])
            self.assertEqual(recovered.audit_events('command-demo')[0]['state'], 'uncertain')
            with patch('ptw.execution.execute') as execution:
                self.assertFalse(Workspace(recovered).request(self.actor['token'], 'abrupt-crash', body)['allowed'])
            execution.assert_not_called()
            self.assertTrue(all(Supervisor.state(w['unit'])['confirmed_stopped']
                                for w in recovered.status('command-demo')['workloads']))
        finally:
            if process.is_alive():
                process.kill()
                process.join(5)
            receiver.close()
            self.store.stop('command-demo')
            Supervisor(self.store).reconcile()

    def test_capture_fault_stops_running_command_and_preserves_unrelated_work(self):
        from ptw.supervisor import Supervisor
        workspace_fixtures.WorkspaceLinux.add_command(self,
            "import subprocess,time; from pathlib import Path; "
            "subprocess.Popen(['/usr/bin/sleep','20']); time.sleep(3); "
            "Path('dist/late.txt').write_text('must not publish')")
        body = request('run', 'probe')
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(self.broker.request, self.actor['token'], 'running', body)
                deadline = time.monotonic() + 10
                units = []
                while time.monotonic() < deadline:
                    units = self.store.status('command-demo')['workloads']
                    if units and all(Supervisor.state(w['unit']).get('ActiveState') == 'active' for w in units):
                        break
                    time.sleep(.02)
                self.assertTrue(units, 'Native workload never started')
                self.assertTrue(all(Supervisor.state(w['unit']).get('ActiveState') == 'active' for w in units))
                self.assertEqual(self.store.audit_events('command-demo')[0]['state'], 'pending')
                # A real SQLite write rejection, scoped to the disposable
                # fixture; no shared disk exhaustion or native-call mocking.
                with self.store.locked() as db:
                    db.execute("CREATE TRIGGER reject_audit BEFORE INSERT ON events "
                               "BEGIN SELECT RAISE(FAIL,'injected capture failure'); END")
                import sqlite3
                try:
                    with self.assertRaises(sqlite3.Error):
                        self.ask('read')
                finally:
                    with self.store.locked() as db:
                        db.execute('DROP TRIGGER reject_audit')
                result = future.result(timeout=15)
                self.assertFalse(result['allowed'], result)
            self.assertFalse((Path(self.inv['root']) / 'dist/late.txt').exists())
            self.assertTrue(all(Supervisor.state(w['unit'])['confirmed_stopped'] for w in units))
            self.assertEqual(self.store.status('command-demo')['violations'], 0)
            other = self.store.register('python-demo', 'implementation')
            self.assertTrue(self.broker.request(other['token'], 'useful', request('read', 'src', 'calculator.py'))['allowed'])
            self.assertFalse(self.store.status('python-demo')['stopped'])
            self.assertTrue(self.broker.request(self.actor['token'], 'running', body)['replayed'])
        finally:
            self.store.stop('command-demo')
            Supervisor(self.store).reconcile()

    def test_command_completion_fault_records_unknown_without_reexecution(self):
        workspace_fixtures.WorkspaceLinux.add_command(self,
            "from pathlib import Path; Path('dist/completed.txt').write_text('real effect')")
        body = request('run', 'probe')
        complete = self.store.complete
        def fail_publication_receipt(db, session, event, response, **kwargs):
            if event == 'completion-fault':
                raise OSError('injected completion fault')
            return complete(db, session, event, response, **kwargs)
        with patch.object(self.store, 'complete', side_effect=fail_publication_receipt):
            with self.assertRaises(OSError):
                self.broker.request(self.actor['token'], 'completion-fault', body)
        self.assertEqual((Path(self.inv['root']) / 'dist/completed.txt').read_text(), 'real effect')
        recovered = Store(self.store.directory)
        self.assertTrue(recovered.status('command-demo')['stopped'])
        self.assertEqual(recovered.audit_events('command-demo')[0]['state'], 'uncertain')
        with patch('ptw.execution.execute') as execution:
            self.assertFalse(Workspace(recovered).request(self.actor['token'], 'completion-fault', body)['allowed'])
        execution.assert_not_called()

    def test_command_effect_failure_denial_and_private_diagnostics(self):
        workspace_fixtures.WorkspaceLinux.add_command(self,
            "from pathlib import Path; Path('dist/audit.txt').write_text('native-effect'); "
            "print('PRIVATE_COMMAND_DIAGNOSTIC'); raise SystemExit(7)")
        packet = self.store.evidence_review('command-demo', DEFAULT)
        self.store.adopt_evidence('command-demo', DEFAULT, digest(packet), 'operator')
        result = self.ask('run', resource='probe', path='')
        self.assertTrue(result['allowed'], result)
        self.assertEqual(result['exit_code'], 7)
        self.assertEqual((Path(self.inv['root']) / 'dist/audit.txt').read_text(), 'native-effect')
        private = Path(self.inv['root']) / 'private/customer.txt'
        before = private.read_bytes()
        denied = self.ask('read', resource='private', path='customer.txt')
        self.assertFalse(denied['allowed'])
        self.assertEqual(private.read_bytes(), before)
        document = self.store.audit_export('command-demo')
        command = next(r for r in document['events'] if r['request']['action'] == 'run')
        self.assertEqual(command['audit']['decision'], 'allow')
        self.assertEqual(command['audit']['outcome'], 'failed')
        self.assertEqual(command['audit']['phases']['execution']['outcome'], 'failed')
        self.assertNotIn('PRIVATE_COMMAND_DIAGNOSTIC', json.dumps(document))
        self.assertIn('PRIVATE_COMMAND_DIAGNOSTIC', result['output'])
        # A separate project's existing authority and useful work survive.
        other = self.store.register('python-demo', 'implementation')
        self.assertTrue(self.broker.request(other['token'], 'useful', request('read', 'src', 'calculator.py'))['allowed'])
        self.assertFalse(self.store.status('python-demo')['stopped'])
