#!/usr/bin/env python3
"""Finite synthetic workload: append a timestamp every 100ms, then exit."""
import argparse
import json
import os
from pathlib import Path
import time

parser=argparse.ArgumentParser()
parser.add_argument('--output',required=True)
parser.add_argument('--token',required=True)
args=parser.parse_args()
path=Path(args.output)
if not str(path.resolve()).startswith('/home/loon/benchmarks/vega/native-stop/'):
    raise SystemExit('Synthetic native-stop paths only.')
print(json.dumps({'ready':True,'pid_in_namespace':os.getpid()}),flush=True)
with path.open('a',buffering=1) as log:
    for sequence in range(900):
        log.write(json.dumps({'sequence':sequence,'at_ns':time.monotonic_ns(),'token':args.token})+'\n')
        time.sleep(.1)
