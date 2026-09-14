#!/bin/sh
set -eu

: "${DTAP_ROOT:?set DTAP_ROOT to the pinned DecodingTrust-Agent checkout}"
: "${VEGA_CORE_ROOT:?set VEGA_CORE_ROOT to new-v1/benchmarks/vega-core}"
: "${VEGA_DTAP_PACKAGE_ROOT:?set VEGA_DTAP_PACKAGE_ROOT to this dtap-vega directory}"

chmod 0700 "$VEGA_DTAP_PACKAGE_ROOT"/scripts/*.sh "$VEGA_DTAP_PACKAGE_ROOT"/scripts/*.py
chmod 0700 "$VEGA_DTAP_PACKAGE_ROOT/scripts/vps-bin/docker"

expected=e0323a521ba4ef88f8e14c1eccf68d0a3d19a458
actual=$(git -C "$DTAP_ROOT" rev-parse HEAD)
if [ "$actual" != "$expected" ]; then
  echo "refusing DTAP revision $actual; expected $expected" >&2
  exit 1
fi

patch_file="$VEGA_DTAP_PACKAGE_ROOT/patches/dtap-e0323a.patch"
if git -C "$DTAP_ROOT" apply --recount --check "$patch_file" 2>/dev/null; then
  git -C "$DTAP_ROOT" apply --recount "$patch_file"
elif ! git -C "$DTAP_ROOT" apply --recount --reverse --check "$patch_file" 2>/dev/null; then
  echo "DTAP patch is neither cleanly applicable nor already applied" >&2
  exit 1
fi

for extra_patch in \
  "$VEGA_DTAP_PACKAGE_ROOT/patches/dtap-vps-memory.patch" \
  "$VEGA_DTAP_PACKAGE_ROOT/patches/dtap-json-scope.patch"
do
  if git -C "$DTAP_ROOT" apply --check "$extra_patch" 2>/dev/null; then
    git -C "$DTAP_ROOT" apply "$extra_patch"
  elif ! git -C "$DTAP_ROOT" apply --reverse --check "$extra_patch" 2>/dev/null; then
    echo "extra patch is neither cleanly applicable nor already applied: $extra_patch" >&2
    exit 1
  fi
done

install -m 0644 "$VEGA_DTAP_PACKAGE_ROOT/hooks/vega_fast_path.py" \
  "$DTAP_ROOT/dt_arena/src/hooks/vega_fast_path.py"
install -m 0644 "$VEGA_DTAP_PACKAGE_ROOT/hooks/hooks.json" \
  "$DTAP_ROOT/dt_arena/src/hooks/hooks.json"

venv_python="$DTAP_ROOT/.venv/bin/python"
if [ ! -x "$venv_python" ]; then
  uv venv --python 3.12 "$DTAP_ROOT/.venv"
fi
uv pip install --python "$venv_python" -e "$DTAP_ROOT[pocketflow,openai]" -e "$VEGA_CORE_ROOT"
"$venv_python" -m py_compile \
  "$DTAP_ROOT/eval/evaluation.py" \
  "$DTAP_ROOT/eval/task_runner.py" \
  "$DTAP_ROOT/agent/openaisdk/src/agent.py" \
  "$DTAP_ROOT/agent/openaisdk/src/mcp_wrapper.py" \
  "$DTAP_ROOT/dt_arena/src/hooks/vega_fast_path.py"

mkdir -p "$VEGA_DTAP_PACKAGE_ROOT/install-evidence"
"$venv_python" - <<'PY' > "$VEGA_DTAP_PACKAGE_ROOT/install-evidence/model-settings.txt"
from agents import ModelSettings
value = ModelSettings(extra_body={"reasoning_effort": "high"})
print(value.extra_body)
PY
git -C "$DTAP_ROOT" diff --check
echo "installed Vega DTAP integration at pinned commit $actual"
