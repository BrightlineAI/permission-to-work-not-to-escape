#!/usr/bin/env bash
set -euo pipefail
if [[ $# -lt 4 ]]; then
  echo "usage: $0 ARM OUTPUT ASSEMBLY CAPTURES [--case-ids comma,list]" >&2
  exit 2
fi
arm=$1 output=$2 assembly=$3 captures=$4; shift 4
root=$(cd "$(dirname "$0")/.." && pwd)
tools_dir="$root/.runtime-tools"
nono=${VEGA_BENCHMARK_NONO:-/home/loon/benchmarks/vega/benchmark-comparison/20260912-basharena-nono/bin/nono}
test -x "$nono"; test -x "$tools_dir/opa-1.20.2"; test -x "$tools_dir/agentgateway-1.5.0"
PYTHONPATH="$root/src" python3 "$root/scripts/run_generated_arm.py" --arm "$arm" \
  --output "$output" --assembly "$assembly" --captures "$captures" \
  --nono "$nono" --opa "$tools_dir/opa-1.20.2" \
  --agentgateway "$tools_dir/agentgateway-1.5.0" "$@"
