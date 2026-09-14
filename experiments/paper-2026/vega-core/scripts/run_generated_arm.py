#!/usr/bin/env python3
"""Replay frozen captures through one E/F/G generated-policy arm on the VPS."""

from __future__ import annotations
import argparse, concurrent.futures, importlib.util, json, os, shutil, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/"src"))
from vega_core.canonical import canonical_hash
from vega_core.models import Decision, load_policy

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path); value=importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
suite=module("vega_run_suite",ROOT/"scripts/run_suite.py")
def load(path): return json.loads(Path(path).read_text())

def execute(arm,case,policy,artifact_hash,call,state_root,client,opa,track,valid=False):
    request=suite.normalized(case,call["arguments"])
    if policy is None:
        decision=Decision(False,"DENY_INVALID_POLICY",artifact_hash,f"job-{case['case_id']}"); opa_decision=None
    else:
        request,decision,opa_decision=suite.decision_for("D",case,policy,request,opa,valid,track!="benign")
    action_hash=canonical_hash(call); state_path=state_root/f"{track}-{arm}-{case['case_id']}.json"; before=load(state_path) if state_path.exists() else []
    execution=None
    if decision.allowed:
        execution=suite.post(f"http://127.0.0.1:39000/{track}/{arm}/{case['case_id']}",{"action_hash":action_hash,"request":request.as_dict()},call["tool"],client,39000)
    after=load(state_path) if state_path.exists() else []
    return {"arm":arm,"request":request.as_dict(),"action_hash":action_hash,"decision":decision.as_dict(),"opa_decision":opa_decision,"execution":execution,"effect_count_before":len(before),"effect_count_after":len(after),"effect_completed":len(after)==len(before)+1}

def track(arm,cases,captures,policies,artifact_hashes,state_root,client,opa,name):
    records={}
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        jobs={}
        for case in cases:
            if name=="model":
                call=captures[case["case_id"]]["call"]; valid=False
            elif name=="forced": call={"tool":case["tool"],"arguments":case["harmful_call"]}; valid=False
            else:
                args=dict(case["benign_call"]); call={"tool":case["tool"],"arguments":args}; valid=True
            jobs[case["case_id"]]=pool.submit(execute,arm,case,policies[case["case_id"]],artifact_hashes[case["case_id"]],call,state_root,client,opa,name,valid)
        for cid,job in jobs.items(): records[cid]={arm:job.result()}
    return records

def main():
    p=argparse.ArgumentParser(); p.add_argument("--arm",choices=["E","F","G"],required=True); p.add_argument("--output",required=True); p.add_argument("--assembly",required=True); p.add_argument("--captures",required=True); p.add_argument("--nono",required=True); p.add_argument("--opa",required=True); p.add_argument("--agentgateway",required=True); p.add_argument("--case-ids"); a=p.parse_args()
    out=Path(a.output).resolve(); out.mkdir(parents=True,exist_ok=False); state=out/"service-state"; assembly=Path(a.assembly).resolve(); assembled=load(assembly/"manifest.json")
    ids=a.case_ids.split(",") if a.case_ids else assembled["case_ids"]
    captures=load(a.captures); shutil.copyfile(a.captures,out/"source-captures.json")
    shutil.copyfile(assembly/"manifest.json",out/"source-assembly-manifest.json")
    shutil.copytree(assembly/"policies",out/"source-policies")
    if (assembly/"records").exists(): shutil.copytree(assembly/"records",out/"source-invalid-records")
    source_code=out/"source-code"; source_code.mkdir(); source_cases=out/"source-cases"; source_cases.mkdir()
    component_paths={
        "runner":Path(__file__), "audit":ROOT/"scripts/audit_generated_arm.py",
        "suite":ROOT/"scripts/run_suite.py", "base_audit":ROOT/"scripts/audit_results.py",
        "service":ROOT/"scripts/synthetic_service.py", "authorizer":ROOT/"src/vega_core/authorize.py",
        "models":ROOT/"src/vega_core/models.py", "canonical":ROOT/"src/vega_core/canonical.py",
        "context":ROOT/"src/vega_core/context.py", "approvals":ROOT/"src/vega_core/approvals.py",
        "delegation":ROOT/"src/vega_core/delegation.py", "opa_adapter":ROOT/"adapters/opa.py",
        "baseline_rego":ROOT/"gateway/baseline.rego", "gateway_config":ROOT/"gateway/agentgateway.yaml",
        "policy_schema":ROOT/"schemas/policy.schema.json", "case_schema":ROOT/"schemas/case.schema.json",
    }
    component_files={}
    for name,path in component_paths.items():
        copied=source_code/f"{name}{path.suffix}"; shutil.copyfile(path,copied)
        component_files[name]={"file":copied.name,"sha256":suite.sha(copied)}
    for cid in ids: shutil.copyfile(ROOT/"cases"/f"{cid}.json",source_cases/f"{cid}.json")
    case_file_hashes={cid:suite.sha(source_cases/f"{cid}.json") for cid in ids}
    cases=[load(ROOT/"cases"/f"{cid}.json") for cid in ids]
    policy_paths={cid:assembly/"policies"/f"{cid}.json" for cid in ids}
    policies={cid:load_policy(path) if path.exists() else None for cid,path in policy_paths.items()}
    artifact_hashes={}
    for cid,policy in policies.items():
        source=assembled["sources"][cid]
        if policy is not None:
            expected=source.get("policy_file_sha256") or source.get("policy_sha256")
            if not expected or suite.sha(policy_paths[cid]) != expected: raise RuntimeError(f"assembly policy hash mismatch: {cid}")
            artifact_hashes[cid]=policy.policy_hash
        else:
            record=assembly/"records"/f"{cid}.json"
            expected=source.get("record_file_sha256") or source.get("record_sha256")
            if not record.exists() or not expected or suite.sha(record) != expected: raise RuntimeError(f"assembly invalid-record hash mismatch: {cid}")
            artifact_hashes[cid]=expected
    invalid_ids=sorted(cid for cid,policy in policies.items() if policy is None)
    manifest={"experiment":f"Vega {a.arm} generated policy replay","created_at":datetime.now(timezone.utc).isoformat(),"code_commit":os.environ.get("VEGA_CODE_COMMIT","uncommitted"),"arm":a.arm,"case_ids":ids,"cases":len(ids),"assembly_manifest_file_sha256":suite.sha(assembly/"manifest.json"),"captures_file_sha256":suite.sha(Path(a.captures)),"component_files":component_files,"case_file_sha256":case_file_hashes,"identical_capture_replay":True,"model":"qwen/qwen3-14b","critic_model":"qwen/qwen3-14b" if a.arm=="G" else None,"invalid_policy_case_ids":invalid_ids,"decision_artifact_hashes":artifact_hashes}
    suite.dump(out/"manifest.json",manifest)
    service_log=open(out/"synthetic-service.log","w"); gateway_log=open(out/"agentgateway.log","w")
    clients=suite.start_clients(a.nono,f"{a.arm.lower()}-{os.getpid()}"); service=subprocess.Popen([sys.executable,str(ROOT/"scripts/synthetic_service.py"),"--state-root",str(state)],stdout=service_log,stderr=subprocess.STDOUT); gateway=subprocess.Popen([a.agentgateway,"-f",str(ROOT/"gateway/agentgateway.yaml")],stdout=gateway_log,stderr=subprocess.STDOUT)
    try:
        suite.wait_http("http://127.0.0.1:39080/ready",service); suite.wait_http("http://127.0.0.1:39000/ready",gateway); suite.preflight(out,clients,a.opa)
        for name in ("model","forced","benign"): suite.dump(out/f"{name}-{a.arm}.json",track(a.arm,cases,captures,policies,artifact_hashes,state,clients["D"],a.opa,name))
    finally:
        gateway.terminate(); service.terminate(); gateway.wait(timeout=10); service.wait(timeout=10)
        suite.dump(out/"cleanup.json",{k:suite.docker("rm","-f",v).returncode for k,v in clients.items()}); service_log.close(); gateway_log.close()
    subprocess.run([sys.executable,str(ROOT/"scripts/audit_generated_arm.py"),str(out)],check=True)
if __name__=="__main__": main()
