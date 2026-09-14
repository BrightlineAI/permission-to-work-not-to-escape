#!/bin/sh
set -eu

: "${DTAP_ROOT:?set DTAP_ROOT}"
: "${VEGA_DTAP_PACKAGE_ROOT:?set VEGA_DTAP_PACKAGE_ROOT}"
: "${VEGA_DTAP_RUN_ROOT:?set VEGA_DTAP_RUN_ROOT}"
: "${OPENROUTER_API_KEY:?OPENROUTER_API_KEY must already be securely present}"
: "${VEGA_DTAP_FROZEN_COMMIT:?set to the pushed package commit before holdout selection}"
actual_commit=$(git -C "$VEGA_DTAP_PACKAGE_ROOT" rev-parse HEAD)
[ "$actual_commit" = "$VEGA_DTAP_FROZEN_COMMIT" ] || {
  echo "package commit mismatch: $actual_commit" >&2; exit 1;
}
[ -z "$(git -C "$VEGA_DTAP_PACKAGE_ROOT" status --porcelain)" ] || {
  echo "package checkout is not clean" >&2; exit 1;
}

label=${1:-holdout10-prospective-01}
case "$label" in *[!A-Za-z0-9._-]*|'') echo "invalid label" >&2; exit 2;; esac
iteration="$VEGA_DTAP_RUN_ROOT/$label"
test ! -e "$iteration"
mkdir -p "$iteration"
umask 077
python="$DTAP_ROOT/.venv/bin/python"

"$python" "$VEGA_DTAP_PACKAGE_ROOT/scripts/select_blind_holdout.py" \
  --source "$VEGA_DTAP_PACKAGE_ROOT/frozen/holdout50.jsonl" \
  --output "$iteration/task-list.jsonl" \
  --manifest "$iteration/selection-manifest.json" \
  --count 10 \
  --seed 'vega-dtap-holdout10-v1|481c07fd60e2a50ddd7b51f89bc7cc9a032f447a|4f78cf08db72863c162b3d75b50c425cba7e866eb2830274f18b7eea3d9c1483'
selected_hash=$("$python" -c 'import json,sys; print(json.load(open(sys.argv[1]))["selected_task_list_sha256"])' "$iteration/selection-manifest.json")
"$python" "$VEGA_DTAP_PACKAGE_ROOT/scripts/extract_trusted.py" \
  --dtap-root "$DTAP_ROOT" --task-list "$iteration/task-list.jsonl" \
  --expected-task-list-sha256 "$selected_hash" \
  --tool-interface "$VEGA_DTAP_PACKAGE_ROOT/tool_interface.json" \
  --output "$iteration/trusted-inputs.jsonl"
"$python" "$VEGA_DTAP_PACKAGE_ROOT/scripts/record_provenance.py" \
  --package-root "$VEGA_DTAP_PACKAGE_ROOT" --dtap-root "$DTAP_ROOT" \
  --task-list "$iteration/task-list.jsonl" --output "$iteration/provenance.json" \
  --selection-manifest "$iteration/selection-manifest.json" \
  --frozen-code-commit "$VEGA_DTAP_FROZEN_COMMIT"

# Both generators run independently, in disjoint directories, before any agent
# trajectory. A failure is preserved but never prevents the other arm or the
# baseline from being evaluated, and it must not be repaired from holdout data.
set +e
"$python" "$VEGA_DTAP_PACKAGE_ROOT/scripts/generate_policies.py" \
  --trusted-inputs "$iteration/trusted-inputs.jsonl" --mode direct_e \
  --output-root "$iteration/direct-e-generation" >"$iteration/direct-e-generation.log" 2>&1 &
direct_pid=$!
"$python" "$VEGA_DTAP_PACKAGE_ROOT/scripts/generate_policies.py" \
  --trusted-inputs "$iteration/trusted-inputs.jsonl" --mode typed_f \
  --output-root "$iteration/typed-f-generation" >"$iteration/typed-f-generation.log" 2>&1 &
typed_pid=$!
wait "$direct_pid"; direct_rc=$?
wait "$typed_pid"; typed_rc=$?
set -e
"$python" "$VEGA_DTAP_PACKAGE_ROOT/scripts/record_generation_status.py" \
  --direct-exit "$direct_rc" --typed-exit "$typed_rc" \
  --output "$iteration/generation-status.json"

"$VEGA_DTAP_PACKAGE_ROOT/scripts/run_native_arm_vps.sh" \
  "$iteration" dtap_baseline "$iteration/task-list.jsonl"
if [ "$direct_rc" -eq 0 ]; then
  "$VEGA_DTAP_PACKAGE_ROOT/scripts/run_native_arm_vps.sh" \
    "$iteration" vega_direct_e "$iteration/task-list.jsonl" "$iteration/direct-e-generation/policies"
else
  mkdir -p "$iteration/arms/vega_direct_e"
fi
if [ "$typed_rc" -eq 0 ]; then
  "$VEGA_DTAP_PACKAGE_ROOT/scripts/run_native_arm_vps.sh" \
    "$iteration" vega_typed_f "$iteration/task-list.jsonl" "$iteration/typed-f-generation/policies"
else
  mkdir -p "$iteration/arms/vega_typed_f"
fi
"$python" "$VEGA_DTAP_PACKAGE_ROOT/scripts/aggregate_results.py" \
  --iteration-root "$iteration" --trusted-inputs "$iteration/trusted-inputs.jsonl" \
  --task-list "$iteration/task-list.jsonl" \
  --output "$iteration/summary.json"
"$python" "$VEGA_DTAP_PACKAGE_ROOT/scripts/render_summary.py" \
  --summary "$iteration/summary.json" --output "$iteration/summary.md"
echo "completed prospective holdout10: $iteration"
