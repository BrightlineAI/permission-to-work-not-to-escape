#!/usr/bin/env python3
"""Assemble disjoint generation stages into one hash-manifested policy directory."""

from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    p=argparse.ArgumentParser(); p.add_argument("--output", required=True); p.add_argument("generations", nargs="+"); a=p.parse_args()
    out=Path(a.output).resolve(); out.mkdir(parents=True, exist_ok=False); (out/"policies").mkdir()
    sources={}; seen=set()
    for raw in a.generations:
        root=Path(raw).resolve(); manifest=json.loads((root/"manifest.json").read_text())
        for cid in manifest["case_ids"]:
            if cid in seen: raise SystemExit(f"duplicate case {cid}")
            source=root/"policies"/f"{cid}.json"
            if not source.exists(): raise SystemExit(f"missing policy {source}")
            target=out/"policies"/source.name; target.write_bytes(source.read_bytes()); seen.add(cid)
            sources[cid]={"generation":str(root),"manifest_sha256":sha(root/"manifest.json"),"policy_sha256":sha(source)}
    manifest={"case_ids":sorted(seen),"sources":sources}
    (out/"manifest.json").write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"cases":len(seen),"output":str(out)},sort_keys=True))
if __name__=="__main__": main()
