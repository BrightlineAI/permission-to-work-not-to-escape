#!/usr/bin/env python3
"""Publish only this synthetic shared-warning experiment's evidence."""
import hashlib
import json
from pathlib import Path
import platform
import shutil

if platform.system()!='Linux':raise SystemExit('Export on the VPS.')
base=Path('/home/loon/benchmarks/vega/native-stop');out=base/'publication-warning-20260914';out.mkdir(exist_ok=False)
summaries=[]
for name in ['20260914-warning-shared-01','20260914-warning-local-01']:
    src=base/name;dest=out/name;dest.mkdir()
    files=['manifest.json','prompt.txt','result.json','registry.json','audit.json','native-tool-evidence.json',
           'warning.json','warning-permitted.txt','unrelated-admission.txt','unrelated-effects.jsonl',
           'private/marker.txt','project/worker_a-effects.jsonl','project/worker_b-effects.jsonl']
    files += [f'late-{actor}.txt' for actor in ['parent','worker_a','worker_b'] if (src/f'late-{actor}.txt').exists()]
    for file in files:
        (dest/file).parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src/file,dest/file)
    audit=json.loads((src/'audit.json').read_text());assert audit['all_checks_passed']
    result=json.loads((src/'result.json').read_text())
    summaries.append(dict(run=name,mode=audit['mode'],counts=audit['counts'],
        violations_by_session={v['actor']:v['decision']['session_violations'] for v in [result['warning'],result['second_violation']]},
        job_violations=result['second_violation']['decision']['job_violations'],
        processes_after_warning=len(result['unit_after_warning']['pids']),processes_after_second=len(result['unit_after_second']['pids']),
        late_completed=sum(v['effect'] for v in result['late_requests'].values()),late_attempted=3,
        unrelated_request_completed=result['unrelated_request']['effect'],wall_seconds=result['wall_seconds'],audit_passed=True))
(out/'summary.json').write_text(json.dumps(dict(protocol='shared-warning-v1',frozen_revision='bdc0934',runs=summaries,
    scope='One prescribed native scenario in two configurations, not a population estimate.',
    audit_development='Initial auditor expected plaintext native notification bodies. Actual records encrypt those bodies. Final audit verifies the parent received the plaintext host notice and native message calls to both workers completed; it does not claim to inspect their plaintext.'),indent=2)+'\n')
files=sorted(f for f in out.rglob('*') if f.is_file())
(out/'SHA256SUMS').write_text(''.join(hashlib.sha256(f.read_bytes()).hexdigest()+'  '+str(f.relative_to(out))+'\n' for f in files))
print(json.dumps({'path':str(out),'files':len(files)+1}))
