#!/usr/bin/env python3
"""Reuse Vega's existing read diagnostic on audited native-runner observations."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import platform


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('root',type=Path)
    parser.add_argument('--diagnostic',type=Path,required=True)
    args=parser.parse_args()
    if platform.system()!='Linux':raise SystemExit('Run on the VPS.')
    spec=importlib.util.spec_from_file_location('existing_diagnostic',args.diagnostic)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    before=args.root/'before'
    after=args.root/('after-v2' if (args.root/'after-v2').exists() else 'after')
    manifests=[json.loads((p/'manifest.json').read_text()) for p in [before,after]]
    unchanged={key:manifests[0][key]==manifests[1][key]
               for key in ['probes','workspace','fixture_hashes','prompt_sha256','contract_sha256','runner_version']}
    assert all(unchanged.values()),'Before/after inputs differ'
    contract={'routes':['parent_shell','worker_shell'],
              'requests':[{'request_id':k,'expectation':k} for k in ['permitted','forbidden']]}
    rules={'diagnostic_version':'native-adapter-existing-rules',
           'suggestions':{'parent_shell':'Check that the active profile denies this read.',
                          'worker_shell':'Check that the worker inherits the effective denied-read rule.'}}
    results={}
    for phase,directory in [('before',before),('after',after)]:
        audit=json.loads((directory/'audit.json').read_text())
        assert audit['all_four_valid'] and not audit['problems']
        observations=[]
        for probe in audit['probes']:
            actor,permission=probe['probe'].split('-')
            permitted=permission=='allowed'
            observations.append(dict(opaque_config_id='deployment-1',route=actor+'_shell',
                request_id='permitted' if permitted else 'forbidden',phase=phase,
                execution_valid=probe['execution_valid'],
                permitted_read_complete=permitted and probe['marker_observed'],
                forbidden_content_returned=not permitted and probe['marker_observed'],
                verified_denial=probe['verified_denial'],evidence_id=probe['probe']))
        result=module.diagnose(contract,observations,rules,{})
        for name,value in [('public-observations',observations),('diagnosis',result)]:
            (directory/(name+'.json')).write_text(json.dumps(value,indent=2)+'\n')
        results[phase]=result
    summary=dict(unchanged_inputs=unchanged,
        reused_diagnostic_sha256=hashlib.sha256(args.diagnostic.read_bytes()).hexdigest(),
        note='Counts are recomputed from audited observations; diagnosis is retrospective, not blinded before repair.')
    for phase,directory in [('before',before),('after',after)]:
        obs=json.loads((directory/'public-observations.json').read_text())
        summary['native_'+phase+'_forbidden_completed']=sum(o['forbidden_content_returned'] for o in obs)
        summary['native_'+phase+'_permitted_completed']=sum(o['permitted_read_complete'] for o in obs)
    (args.root/'diagnostic-reuse.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary,indent=2))


if __name__=='__main__':main()
