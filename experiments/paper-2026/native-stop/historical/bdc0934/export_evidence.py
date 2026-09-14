#!/usr/bin/env python3
"""Copy an explicit allowlist of this experiment's records for publication."""
import hashlib
import json
from pathlib import Path
import platform
import shutil

if platform.system()!='Linux':raise SystemExit('Export on the VPS.')
base=Path('/home/loon/benchmarks/vega/native-stop')
out=base/'publication-20260914';out.mkdir(exist_ok=False)
names=['20260914-confirm-01','20260914-control-01','20260914-confirm-02','20260914-confirm-03']
table=[];source_hashes=set()
for name in names+['20260914-interrupt-01']:
    source=base/name;target=out/name;target.mkdir()
    files=['manifest.json','prompt.txt','result.json','registry.json','unrelated-effects.jsonl',
           'project/worker-effects.jsonl','private/marker.txt']
    if name in names:files+=['audit.json','native-tool-evidence.json']
    for label in ['late','unrelated']:
        if (source/(label+'-admission-effect.txt')).exists():files.append(label+'-admission-effect.txt')
    for file in files:
        (target/file).parent.mkdir(exist_ok=True,parents=True)
        shutil.copyfile(source/file,target/file)
    if name not in names:continue
    manifest=json.loads((source/'manifest.json').read_text())
    result=json.loads((source/'result.json').read_text())
    audit=json.loads((source/'audit.json').read_text())
    assert audit['all_record_checks_passed']
    source_hashes.add(manifest['source_sha256'])
    table.append(dict(run=name,mode=manifest['mode'],counts=audit['counts'],
        late_request_completed=result['late_physical_effect'],unrelated_request_completed=result['unrelated_physical_effect'],
        registered_job_pids_before=len(result['unit_before_treatment']['pids']),
        registered_job_pids_after=len(result['unit_after_treatment']['pids']),
        wall_seconds=result['wall_seconds'],audit_passed=True))
assert len(source_hashes)==1
(out/'summary.json').write_text(json.dumps(dict(
    protocol='native-stop-v2',frozen_revision='41be659',source_sha256=source_hashes.pop(),
    model='gpt-6-astra',reasoning_effort='high',cli_version='0.154.0',
    grace_seconds=1,window_seconds=5,runs=table,
    pilot='20260914-interrupt-01 retained separately: single-PID stop and unequal windows; not pooled.',
    unit_of_replication='Four runs of one prescribed scenario, not 200 independent security cases.',
    all_record_checks_passed=True),indent=2)+'\n')
files=sorted(p for p in out.rglob('*') if p.is_file())
(out/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+str(p.relative_to(out))+'\n' for p in files))
print(json.dumps({'path':str(out),'files':len(files)+1,'bytes':sum(p.stat().st_size for p in out.rglob('*') if p.is_file())}))
