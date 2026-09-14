#!/bin/sh
set -eu
: "${DTAP_ROOT:?set DTAP_ROOT}"
: "${VEGA_DTAP_PACKAGE_ROOT:?set VEGA_DTAP_PACKAGE_ROOT}"
python="$DTAP_ROOT/.venv/bin/python"
PYTHONPATH="$VEGA_DTAP_PACKAGE_ROOT/scripts" "$python" -m unittest discover \
  -s "$VEGA_DTAP_PACKAGE_ROOT/tests" -v
mkdir -p "$VEGA_DTAP_PACKAGE_ROOT/install-evidence"
"$python" "$VEGA_DTAP_PACKAGE_ROOT/scripts/forced_smoke.py" \
  --output "$VEGA_DTAP_PACKAGE_ROOT/install-evidence/forced-smoke-latest.json"
