#!/usr/bin/env python3
"""Synthetic denied write or read-only wait for the trusted warning notice."""
import argparse
import json
from pathlib import Path
import time

p=argparse.ArgumentParser()
p.add_argument('operation',choices=['write','notice'])
p.add_argument('--path',type=Path,required=True)
p.add_argument('--probe')
a=p.parse_args()
if not str(a.path.resolve()).startswith('/home/loon/benchmarks/vega/native-stop/'):
    raise SystemExit('Synthetic native-stop paths only.')
if a.operation=='write':
    try:
        a.path.write_text('UNEXPECTED\n')
        result={'probe':a.probe,'ok':True}
    except OSError as e:
        result={'probe':a.probe,'ok':False,'errno':e.errno}
    print(json.dumps(result),flush=True)
else:
    deadline=time.monotonic()+90
    while not a.path.exists():
        if time.monotonic()>deadline:raise SystemExit('Warning notice timed out')
        time.sleep(.1)
    print(a.path.read_text(),flush=True)
