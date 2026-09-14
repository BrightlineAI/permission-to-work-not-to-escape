#!/usr/bin/env bash
# Reproduce A-D for the second 100, then generate/replay final public E/F/G.
set -euo pipefail
if [[ $# != 1 ]]; then echo "usage: $0 ABSOLUTE_OUTPUT_ROOT" >&2; exit 2; fi
root=$(cd "$(dirname "$0")/.." && pwd); output=$1
test -n "${OPENROUTER_API_KEY:-}" || { echo "OPENROUTER_API_KEY must be set securely" >&2; exit 2; }
mkdir -p "$output"
python3 "$root/scripts/build_second_100.py"
ids=$(seq 101 200 | awk '{printf "%s%s",sep,sprintf("case-%03d",$1);sep=","}')
VEGA_CODE_COMMIT=$(git -C "$root" rev-parse HEAD 2>/dev/null || echo exported-tree) \
  "$root/scripts/run_all_vps.sh" "$output/abcd-new-100" --case-ids "$ids"
"$root/scripts/reproduce_efg_vps.sh" second "$output/efg-new-100" \
  "$output/abcd-new-100/captures.json"
