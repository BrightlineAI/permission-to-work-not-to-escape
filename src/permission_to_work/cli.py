"""Offline policy compilation and an effect-free approval/escalation example."""
import argparse
from dataclasses import asdict
from importlib.resources import files
import json
from pathlib import Path

from vega_core.authorize import authorize_d
from vega_core.models import policy_from_dict, Request, TrustedContext
from .policy import validate_contract
from .escalation import Registry


def compile_checked(task, candidate):
    policy, errors = validate_contract(task, candidate, policy_from_dict)
    if errors:
        raise ValueError('; '.join(errors))
    return policy


def booking_example():
    value=json.loads(files('permission_to_work').joinpath('examples/booking.json').read_text())
    policy=policy_from_dict(compile_checked(value['task'],value['candidate']))
    results={}
    for name,handle in [('fake_approval','approved-by-partner-01'),('genuine_approval','apr-valid-01')]:
        request=Request(tool='finalize_booking',action='create',resource='BK-01',destination='hotel-01',
                        amount='2001',approval_handle=handle,recipient=None,payload='')
        # The runner resolves approval in a trusted store. The acting model does
        # not supply these context fields or an assertion that its handle is valid.
        context=TrustedContext(job_id=policy.job_id,principal=policy.principal,
                               approval=value['approvals'].get(handle))
        results[name]=asdict(authorize_d(policy,request,context))
    registry=Registry('shared_job',session_limit=2,job_limit=2)
    events=[]
    for name,job,session,permitted in [
        ('parent_violation','job','parent',False),
        ('permitted_after_first','job','parent',True),
        ('worker_violation','job','worker-a',False),
        ('quiet_worker_later','job','worker-b',True),
        ('unrelated_later','other-job','worker-c',True),
    ]:
        event=registry.authorize(event_id=name,job_id=job,session_id=session,worker_id=session,
                                 permission_granted=permitted)
        events.append({'event':name,'allowed':event['allowed'],'reason':event['reason'],
                       'job_violations':event.get('job_violations'),
                       'transitions':[x['transition'] for x in event['transitions']]})
    return {'approval_decisions':results,'shared_escalation':events,
            'external_effects':False,'model_calls':0,
            'scope':'Supplied typed candidate; constrained validator; no live booking or process termination.'}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='command',required=True)
    sub.add_parser('demo',help='print approval and shared-counter decisions; no model or external effects')
    c=sub.add_parser('compile',help='validate and compile a supplied typed proposal')
    c.add_argument('--task',required=True,type=Path)
    c.add_argument('--candidate',required=True,type=Path)
    c.add_argument('--output',required=True,type=Path)
    args=p.parse_args()
    if args.command=='demo':
        print(json.dumps(booking_example(),indent=2));return
    try:
        value=compile_checked(json.loads(args.task.read_text()),json.loads(args.candidate.read_text()))
        # Never overwrite an existing reviewed policy by accident.
        with args.output.open('x') as f:f.write(json.dumps(value,indent=2,sort_keys=True)+'\n')
    except (ValueError,KeyError,TypeError,OSError) as exc:
        p.exit(2,f'Policy not written: {exc}\n')
    print(f'Compiled {args.output}; review intent and test the execution boundary before applying it.')


if __name__=='__main__':main()
