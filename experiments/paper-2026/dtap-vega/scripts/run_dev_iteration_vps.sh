#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: run_dev_iteration_vps.sh LABEL [LIMIT]" >&2
  exit 2
fi
: "${DTAP_ROOT:?set DTAP_ROOT}"
: "${VEGA_DTAP_PACKAGE_ROOT:?set VEGA_DTAP_PACKAGE_ROOT}"
: "${VEGA_DTAP_RUN_ROOT:?set VEGA_DTAP_RUN_ROOT}"
: "${OPENROUTER_API_KEY:?OPENROUTER_API_KEY must already be securely present}"

label=$1
limit=${2:-10}
case "$label" in *[!A-Za-z0-9._-]*|'') echo "invalid label" >&2; exit 2;; esac
case "$limit" in *[!0-9]*|'') echo "invalid limit" >&2; exit 2;; esac
[ "$limit" -ge 1 ] && [ "$limit" -le 10 ]
iteration="$VEGA_DTAP_RUN_ROOT/$label"
test ! -e "$iteration"
mkdir -p "$iteration"
umask 077

python="$DTAP_ROOT/.venv/bin/python"
"$python" "$VEGA_DTAP_PACKAGE_ROOT/scripts/make_dev_subset.py" \
  --task-list "$VEGA_DTAP_PACKAGE_ROOT/frozen/dev10.jsonl" --limit "$limit" \
  --output "$iteration/task-list.jsonl"
"$python" "$VEGA_DTAP_PACKAGE_ROOT/scripts/extract_trusted.py" \
  --dtap-root "$DTAP_ROOT" \
  --task-list "$VEGA_DTAP_PACKAGE_ROOT/frozen/dev10.jsonl" \
  --tool-interface "$VEGA_DTAP_PACKAGE_ROOT/tool_interface.json" \
  --limit "$limit" --output "$iteration/trusted-inputs.jsonl"
"$python" "$VEGA_DTAP_PACKAGE_ROOT/scripts/build_reviewed_control.py" \
  --trusted-inputs "$iteration/trusted-inputs.jsonl" \
  --requirements "$VEGA_DTAP_PACKAGE_ROOT/reviewed/dev10-requirements.json" \
  --output-root "$iteration/reviewed-policies"
"$python" "$VEGA_DTAP_PACKAGE_ROOT/scripts/record_provenance.py" \
  --package-root "$VEGA_DTAP_PACKAGE_ROOT" --dtap-root "$DTAP_ROOT" \
  --task-list "$iteration/task-list.jsonl" --output "$iteration/provenance.json"

"$python" "$VEGA_DTAP_PACKAGE_ROOT/scripts/generate_policies.py" \
  --trusted-inputs "$iteration/trusted-inputs.jsonl" --mode typed_f \
  --limit "$limit" --output-root "$iteration/typed-f-generation"
if [ "${VEGA_DTAP_INCLUDE_DIRECT_E:-0}" = 1 ]; then
  "$python" "$VEGA_DTAP_PACKAGE_ROOT/scripts/generate_policies.py" \
    --trusted-inputs "$iteration/trusted-inputs.jsonl" --mode direct_e \
    --limit "$limit" --output-root "$iteration/direct-e-generation"
fi

"$VEGA_DTAP_PACKAGE_ROOT/scripts/run_native_arm_vps.sh" \
  "$iteration" dtap_baseline "$iteration/task-list.jsonl"
"$VEGA_DTAP_PACKAGE_ROOT/scripts/run_native_arm_vps.sh" \
  "$iteration" vega_reviewed_control "$iteration/task-list.jsonl" "$iteration/reviewed-policies"
"$VEGA_DTAP_PACKAGE_ROOT/scripts/run_native_arm_vps.sh" \
  "$iteration" vega_typed_f "$iteration/task-list.jsonl" "$iteration/typed-f-generation/policies"
if [ "${VEGA_DTAP_INCLUDE_DIRECT_E:-0}" = 1 ]; then
  "$VEGA_DTAP_PACKAGE_ROOT/scripts/run_native_arm_vps.sh" \
    "$iteration" vega_direct_e "$iteration/task-list.jsonl" "$iteration/direct-e-generation/policies"
fi
"$python" "$VEGA_DTAP_PACKAGE_ROOT/scripts/aggregate_results.py" \
  --iteration-root "$iteration" --trusted-inputs "$iteration/trusted-inputs.jsonl" \
  --task-list "$iteration/task-list.jsonl" \
  --output "$iteration/summary.json"
"$python" "$VEGA_DTAP_PACKAGE_ROOT/scripts/render_summary.py" \
  --summary "$iteration/summary.json" --output "$iteration/summary.md"
echo "completed development iteration: $iteration"
