import copy
import json
from importlib.resources import files
import unittest

from permission_to_work.cli import booking_example, compile_checked
from permission_to_work.escalation import Registry
from vega_core.authorize import authorize_d
from vega_core.models import policy_from_dict, Request, TrustedContext


class PolicyWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.example=json.loads(files('permission_to_work').joinpath('examples/booking.json').read_text())
        self.policy=policy_from_dict(compile_checked(self.example['task'],self.example['candidate']))

    def request(self,**changes):
        values=dict(tool='finalize_booking',action='create',resource='BK-01',recipient=None,
                    destination='hotel-01',amount='2001',payload='',approval_handle='apr-valid-01')
        values.update(changes);return Request(**values)

    def context(self,**changes):
        values=dict(job_id=self.policy.job_id,principal=self.policy.principal,
                    approval=copy.deepcopy(self.example['approvals']['apr-valid-01']))
        values.update(changes);return TrustedContext(**values)

    def test_correct_approval_preserves_work(self):
        self.assertTrue(authorize_d(self.policy,self.request(),self.context()).allowed)

    def test_unresolvable_approval_is_denied(self):
        d=authorize_d(self.policy,self.request(approval_handle='fake'),self.context(approval=None))
        self.assertEqual(d.reason,'DENY_APPROVAL')

    def test_real_approval_cannot_be_reused_for_different_amount(self):
        self.assertEqual(authorize_d(self.policy,self.request(amount='2002'),self.context()).reason,'DENY_APPROVAL')

    def test_request_cannot_select_other_job(self):
        self.assertEqual(authorize_d(self.policy,self.request(),self.context(job_id='other')).reason,'DENY_JOB')

    def test_delegate_cannot_expand_authority(self):
        self.assertEqual(authorize_d(self.policy,self.request(),self.context(child_expands_authority=True)).reason,'DENY_DELEGATION')

    def test_compiler_rejects_wrong_tool(self):
        candidate=copy.deepcopy(self.example['candidate'])
        candidate['approval_rules'][0]['tool']='corporate-approver'
        with self.assertRaises(ValueError):compile_checked(self.example['task'],candidate)

    def test_duplicate_approval_rules_are_rejected(self):
        candidate=copy.deepcopy(self.example['candidate'])
        candidate['approval_rules']*=2
        with self.assertRaises(ValueError):compile_checked(self.example['task'],candidate)

    def test_new_destination_is_not_invented(self):
        candidate=copy.deepcopy(self.example['candidate'])
        candidate['allow'][0]['destinations']=['attacker.example']
        with self.assertRaises(ValueError):compile_checked(self.example['task'],candidate)

    def test_demo_shares_counter_preserves_unrelated_job(self):
        result=booking_example()
        self.assertFalse(result['approval_decisions']['fake_approval']['allowed'])
        self.assertTrue(result['approval_decisions']['genuine_approval']['allowed'])
        events={x['event']:x for x in result['shared_escalation']}
        self.assertTrue(events['permitted_after_first']['allowed'])
        self.assertIn('job_stopped',events['worker_violation']['transitions'])
        self.assertFalse(events['quiet_worker_later']['allowed'])
        self.assertTrue(events['unrelated_later']['allowed'])

    def test_session_local_control_does_not_stop_at_one_violation_each(self):
        r=Registry('session_local',session_limit=2,job_limit=2)
        for s in ['parent','worker']:
            r.authorize(event_id=s,job_id='j',session_id=s,worker_id=s,permission_granted=False)
        d=r.authorize(event_id='later',job_id='j',session_id='quiet',worker_id='quiet',permission_granted=True)
        self.assertTrue(d['allowed'])


if __name__=='__main__':unittest.main()
