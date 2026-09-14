#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 6 ]]; then
  echo "usage: $0 OUTPUT DEVELOPMENT_POLICIES HOLDOUT_POLICIES DEVELOPMENT_MANIFEST HOLDOUT_MANIFEST CAPTURES" >&2
  exit 2
fi

root=$(cd "$(dirname "$0")/.." && pwd)
tools_dir="$root/.runtime-tools"
nono=${VEGA_BENCHMARK_NONO:-/home/loon/benchmarks/vega/benchmark-comparison/20260912-basharena-nono/bin/nono}
test -x "$nono"
test -x "$tools_dir/opa-1.20.2"
test -x "$tools_dir/agentgateway-1.5.0"

PYTHONPATH="$root/src" python3 "$root/scripts/run_e.py" \
  --output "$1" --development-policies "$2" --holdout-policies "$3" \
  --development-generation "$4" --holdout-generation "$5" --captures "$6" \
  --nono "$nono" --opa "$tools_dir/opa-1.20.2" \
  --agentgateway "$tools_dir/agentgateway-1.5.0"
