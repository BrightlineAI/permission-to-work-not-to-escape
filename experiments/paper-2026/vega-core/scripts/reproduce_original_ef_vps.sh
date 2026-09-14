#!/usr/bin/env bash
# Legacy filename retained for links. Generate final public E/F/G for cases
# 001-100 and replay already-captured Qwen actions. A-D run separately.
set -euo pipefail
if [[ $# != 2 ]]; then
  echo "usage: $0 ABSOLUTE_OUTPUT_ROOT ABSOLUTE_CAPTURES_JSON" >&2
  exit 2
fi
root=$(cd "$(dirname "$0")/.." && pwd)
exec "$root/scripts/reproduce_efg_vps.sh" original "$1" "$2"
