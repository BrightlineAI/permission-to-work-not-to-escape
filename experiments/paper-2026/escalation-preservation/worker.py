#!/usr/bin/env python3
"""Tiny process used only to make permitted work and termination observable."""
import argparse
import json
import os
import time

parser = argparse.ArgumentParser()
parser.add_argument("--token", required=True)
parser.add_argument("--delay", type=float, required=True)
args = parser.parse_args()

print(json.dumps({"event": "ready", "pid": os.getpid()}), flush=True)
time.sleep(args.delay)
print(json.dumps({"event": "effect", "token": args.token}), flush=True)
