#!/usr/bin/env bash
# Reproduce the final frozen second-100 A-F experiment. Run only after the
# development protocol is complete and the generator interface is committed.
set -euo pipefail
if [[ $# != 1 ]]; then echo "usage: $0 ABSOLUTE_OUTPUT_ROOT" >&2; exit 2; fi
root=$(cd "$(dirname "$0")/.." && pwd); output=$1
test -n "${OPENROUTER_API_KEY:-}" || { echo "OPENROUTER_API_KEY must be set securely" >&2; exit 2; }
mkdir -p "$output"
python3 "$root/scripts/build_second_100.py"
ids=$(seq 101 200 | awk '{printf "%s%s",sep,sprintf("case-%03d",$1);sep=","}')
VEGA_CODE_COMMIT=$(git -C "$root" rev-parse HEAD 2>/dev/null || echo exported-tree) \
  "$root/scripts/run_all_vps.sh" "$output/abcd-new-100" --case-ids "$ids"
for mode in E F; do
  for split in development validation_1 validation_2 final_holdout; do
    VEGA_CODE_COMMIT=$(git -C "$root" rev-parse HEAD 2>/dev/null || echo exported-tree) \
      PYTHONPATH="$root/src:$root/scripts" python3 "$root/scripts/generate_ef.py" \
      --mode "$mode" --split "$split" --output "$output/${mode,,}-generation-$split"
  done
  python3 "$root/scripts/assemble_generated_policies.py" \
    --output "$output/${mode,,}-assembly-new-100" \
    "$output/${mode,,}-generation-development" "$output/${mode,,}-generation-validation_1" \
    "$output/${mode,,}-generation-validation_2" "$output/${mode,,}-generation-final_holdout"
  VEGA_CODE_COMMIT=$(git -C "$root" rev-parse HEAD 2>/dev/null || echo exported-tree) \
    "$root/scripts/run_generated_arm_vps.sh" "$mode" "$output/${mode,,}-new-100" \
    "$output/${mode,,}-assembly-new-100" "$output/abcd-new-100/captures.json"
done
