#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: rerun_native_vps.sh NEW_LABEL SOURCE_ITERATION_ROOT" >&2
  exit 2
fi
: "${DTAP_ROOT:?set DTAP_ROOT}"
: "${VEGA_DTAP_PACKAGE_ROOT:?set VEGA_DTAP_PACKAGE_ROOT}"
: "${VEGA_DTAP_RUN_ROOT:?set VEGA_DTAP_RUN_ROOT}"
: "${OPENROUTER_API_KEY:?OPENROUTER_API_KEY must already be securely present}"
label=$1
case "$label" in *[!A-Za-z0-9._-]*|'') echo "invalid label" >&2; exit 2;; esac
source_root=$(realpath "$2")
target="$VEGA_DTAP_RUN_ROOT/$label"
test ! -e "$target"
test -f "$source_root/task-list.jsonl"
test -f "$source_root/trusted-inputs.jsonl"
test -f "$source_root/typed-f-generation/generation-manifest.json"
[ "$(find "$source_root/typed-f-generation/policies" -type f -name '*.json' | wc -l)" -eq 10 ]

mkdir -p "$target/typed-f-generation"
cp "$source_root/task-list.jsonl" "$target/task-list.jsonl"
cp "$source_root/trusted-inputs.jsonl" "$target/trusted-inputs.jsonl"
cp -R "$source_root/reviewed-policies" "$target/reviewed-policies"
cp -R "$source_root/typed-f-generation/policies" "$target/typed-f-generation/policies"
cp "$source_root/typed-f-generation/generation-manifest.json" \
  "$target/typed-f-generation/generation-manifest.json"
python="$DTAP_ROOT/.venv/bin/python"
"$python" "$VEGA_DTAP_PACKAGE_ROOT/scripts/record_policy_reuse.py" \
  --source "$source_root" --target "$target"
"$python" "$VEGA_DTAP_PACKAGE_ROOT/scripts/record_provenance.py" \
  --package-root "$VEGA_DTAP_PACKAGE_ROOT" --dtap-root "$DTAP_ROOT" \
  --task-list "$target/task-list.jsonl" --output "$target/provenance.json"

"$VEGA_DTAP_PACKAGE_ROOT/scripts/run_native_arm_vps.sh" \
  "$target" dtap_baseline "$target/task-list.jsonl"
"$VEGA_DTAP_PACKAGE_ROOT/scripts/run_native_arm_vps.sh" \
  "$target" vega_reviewed_control "$target/task-list.jsonl" "$target/reviewed-policies"
"$VEGA_DTAP_PACKAGE_ROOT/scripts/run_native_arm_vps.sh" \
  "$target" vega_typed_f "$target/task-list.jsonl" "$target/typed-f-generation/policies"
"$python" "$VEGA_DTAP_PACKAGE_ROOT/scripts/aggregate_results.py" \
  --iteration-root "$target" --trusted-inputs "$target/trusted-inputs.jsonl" \
  --output "$target/summary.json"
"$python" "$VEGA_DTAP_PACKAGE_ROOT/scripts/render_summary.py" \
  --summary "$target/summary.json" --output "$target/summary.md"
echo "completed native-only rerun: $target"
