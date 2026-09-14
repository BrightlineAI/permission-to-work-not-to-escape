#!/usr/bin/env bash
# Generate and replay the final public E/F/G policy-source arms for one cohort.
# E is direct final-policy drafting; F is typed deterministic compilation; G adds
# a same-model critic. A-D captures must already exist and remain unchanged.
set -euo pipefail
if [[ $# != 3 ]]; then
  echo "usage: $0 {original|second} ABSOLUTE_OUTPUT_ROOT ABSOLUTE_CAPTURES_JSON" >&2
  exit 2
fi
cohort=$1 output=$2 captures=$3
case "$cohort" in original|second) ;; *) echo "invalid cohort: $cohort" >&2; exit 2 ;; esac
root=$(cd "$(dirname "$0")/.." && pwd)
test -n "${OPENROUTER_API_KEY:-}" || { echo "OPENROUTER_API_KEY must be set securely" >&2; exit 2; }
test -f "$captures"
mkdir -p "$output"
if git -C "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if [[ -n $(git -C "$root" status --porcelain -- .) ]]; then
    echo "benchmark tree is dirty; commit or use a clean worktree before a recorded run" >&2
    exit 2
  fi
  commit=$(git -C "$root" rev-parse HEAD)
else
  commit=exported-tree
fi

VEGA_CODE_COMMIT="$commit" PYTHONPATH="$root/src:$root/scripts" \
  python3 "$root/scripts/generate_e.py" --cohort "$cohort" \
  --output "$output/e-generation" &
generation_pids=("$!")

if [[ "$cohort" == original ]]; then
  for mode in F G; do
    VEGA_CODE_COMMIT="$commit" PYTHONPATH="$root/src:$root/scripts" \
      python3 "$root/scripts/generate_ef.py" --mode "$mode" \
      --split original_regression --output "$output/${mode,,}-generation" &
    generation_pids+=("$!")
  done
else
  for mode in F G; do
    for split in development validation_1 validation_2 final_holdout; do
      VEGA_CODE_COMMIT="$commit" PYTHONPATH="$root/src:$root/scripts" \
        python3 "$root/scripts/generate_ef.py" --mode "$mode" --split "$split" \
        --output "$output/${mode,,}-generation-$split" &
      generation_pids+=("$!")
    done
  done
fi
for pid in "${generation_pids[@]}"; do wait "$pid"; done

ids=$(if [[ "$cohort" == original ]]; then seq 1 100; else seq 101 200; fi | \
  awk '{printf "%s%s",sep,sprintf("case-%03d",$1);sep=","}')

python3 "$root/scripts/assemble_generated_policies.py" --allow-invalid \
  --output "$output/e-assembly" "$output/e-generation"
PYTHONPATH="$root/src" python3 "$root/scripts/evaluate_e_policies.py" \
  --allow-invalid --policies "$output/e-assembly/policies" --case-ids "$ids" \
  --output "$output/e-generation/evaluation.json"

for mode in F G; do
  lower=${mode,,}
  if [[ "$cohort" == original ]]; then
    sources=("$output/$lower-generation")
  else
    sources=("$output/$lower-generation-development" "$output/$lower-generation-validation_1" \
      "$output/$lower-generation-validation_2" "$output/$lower-generation-final_holdout")
  fi
  python3 "$root/scripts/assemble_generated_policies.py" --allow-invalid \
    --output "$output/$lower-assembly" "${sources[@]}"
  PYTHONPATH="$root/src" python3 "$root/scripts/evaluate_e_policies.py" \
    --allow-invalid --policies "$output/$lower-assembly/policies" --case-ids "$ids" \
    --output "$output/$lower-assembly/evaluation.json"
done

# The service uses fixed loopback ports, so physical replays are deliberately
# sequential even though all independent model generations above run concurrently.
for mode in E F G; do
  lower=${mode,,}
  VEGA_CODE_COMMIT="$commit" "$root/scripts/run_generated_arm_vps.sh" "$mode" \
    "$output/physical-$lower" "$output/$lower-assembly" "$captures"
  PYTHONPATH="$root/src" python3 "$root/scripts/audit_generated_arm.py" \
    "$output/physical-$lower"
done
