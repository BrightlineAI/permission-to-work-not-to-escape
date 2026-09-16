#!/usr/bin/env python3
"""Development TUI probe, using a supplied synthetic policy, not LLM drafting."""
import argparse
import os
from pathlib import Path
from ptw.monitor import ensure
from ptw.policy import approve, compile_policy, digest, load, save
from ptw.project_example import create
from ptw.store import Store
from ptw.terminal import launch


parser = argparse.ArgumentParser()
parser.add_argument("--out", type=Path, required=True)
parser.add_argument("--prompt", default="Call project_context, then read calculator.py from src and explain the bug. Do not edit yet.")
args = parser.parse_args()
args.out.mkdir(mode=0o700, parents=True, exist_ok=False)
example = args.out / "example"
create(example, "python")
policy, inv = load(example / "policy.json"), load(example / "inventory.json")
store = Store(args.out / "state")
ensure(store)
store.activate(approve(policy, inv, digest(compile_policy(policy, inv)), "synthetic probe operator"))
session = store.register("python-demo", "implementation")
session_file = args.out / "session.json"
save(session_file, session)
print("Development supplied-policy probe. Private output:", args.out, flush=True)
print(launch(store, session, session_file, args.out / "run", prompt=args.prompt), flush=True)
