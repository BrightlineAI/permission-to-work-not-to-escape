#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 ABSOLUTE_OUTPUT_DIRECTORY [run_suite.py options]" >&2
  exit 2
fi

output=$1
shift

root=$(cd "$(dirname "$0")/.." && pwd)
tools_dir="$root/.runtime-tools"
mkdir -p "$tools_dir"

download() {
  local url=$1 path=$2 expected=$3
  if [[ ! -x "$path" ]]; then
    curl -fsSL "$url" -o "$path"
    chmod 700 "$path"
  fi
  printf '%s  %s\n' "$expected" "$path" | sha256sum -c -
}

download "https://github.com/open-policy-agent/opa/releases/download/v1.20.2/opa_linux_amd64_static" \
  "$tools_dir/opa-1.20.2" "69da5179ee403d10fa11bab6cfb4ffb0d23dba5f9b682fa977db772a1da5670f"
download "https://github.com/agentgateway/agentgateway/releases/download/v1.5.0/agentgateway-linux-amd64" \
  "$tools_dir/agentgateway-1.5.0" "daca5cda76e8c5ab0c1a75912fecf2d6365095403f810db72029c49d14a37e7b"

nono=${VEGA_BENCHMARK_NONO:-/home/loon/benchmarks/vega/benchmark-comparison/20260912-basharena-nono/bin/nono}
test -x "$nono"

run=(python3 "$root/scripts/run_suite.py" --output "$output" --nono "$nono"
  --opa "$tools_dir/opa-1.20.2" --agentgateway "$tools_dir/agentgateway-1.5.0" "$@")

if [[ -n ${OPENROUTER_API_KEY:-} || " $* " == *" --forced-as-captures "* ]]; then
  PYTHONPATH="$root/src" "${run[@]}"
else
  doppler run -p algol -c prd -- env PYTHONPATH="$root/src" "${run[@]}"
fi
