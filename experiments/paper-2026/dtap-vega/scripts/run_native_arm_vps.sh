#!/bin/sh
set -eu

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
  echo "usage: run_native_arm_vps.sh ITERATION_ROOT ARM TASK_LIST [POLICY_ROOT]" >&2
  exit 2
fi
: "${DTAP_ROOT:?set DTAP_ROOT}"
: "${OPENROUTER_API_KEY:?OPENROUTER_API_KEY must already be securely present}"

iteration_root=$(realpath "$1")
arm=$2
task_list=$(realpath "$3")
policy_root=${4:-}
case "$arm" in
  dtap_baseline) mode=baseline ;;
  vega_reviewed_control|vega_direct_e|vega_typed_f) mode=protected ;;
  *) echo "unknown descriptive arm: $arm" >&2; exit 2 ;;
esac
if [ "$mode" = protected ]; then
  test -n "$policy_root"
  policy_root=$(realpath "$policy_root")
fi

arm_root="$iteration_root/arms/$arm"
test ! -e "$arm_root"
mkdir -p "$arm_root/results" "$arm_root/audit"
umask 077
export OPENAI_API_KEY="$OPENROUTER_API_KEY"
export OPENAI_BASE_URL=https://openrouter.ai/api/v1
export OPENROUTER_REASONING_EFFORT=high
export VEGA_DTAP_MODE="$mode"
export VEGA_DTAP_PRINCIPAL=alice
export VEGA_DTAP_AUDIT_ROOT="$arm_root/audit"
export VEGA_DTAP_POLICY_ROOT="$policy_root"
export EVAL_RESULTS_ROOT="$arm_root/results"
export EVAL_TASK_TIMEOUT=900
export DTAP_SKIP_DATASET_DOWNLOAD=1
export DTAP_MEMORY_REQUIRED_GB=1
export DTAP_MEMORY_RESERVE_GB=2
export PATH="$(realpath "$(dirname "$0")/vps-bin"):$DTAP_ROOT/.venv/bin:$PATH"

started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
set +e
"$DTAP_ROOT/.venv/bin/python" "$DTAP_ROOT/eval/evaluation.py" \
  --task-list "$task_list" \
  --agent-type openaisdk \
  --model qwen/qwen3-14b \
  --temperature 0 \
  --max-turns 30 \
  --max-parallel 1 \
  --port-range 18000-21999 \
  --verbose > "$arm_root/run.log" 2>&1
rc=$?
set -e
finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
"$DTAP_ROOT/.venv/bin/python" - "$arm_root/run-metadata.json" "$arm" "$mode" "$started" "$finished" "$rc" <<'PY'
import json, sys
from pathlib import Path
path, arm, mode, started, finished, rc = sys.argv[1:]
Path(path).write_text(json.dumps({
    "arm": arm, "mode": mode, "model": "qwen/qwen3-14b",
    "reasoning_effort": "high", "temperature": 0, "max_turns": 30, "max_parallel": 1,
    "started_at": started, "finished_at": finished, "runner_exit_code": int(rc),
    "independent_native_trajectory": True,
}, indent=2, sort_keys=True) + "\n")
PY
echo "$arm finished with runner exit $rc; aggregate judge artifacts rather than treating rc as score"
