#!/bin/sh
set -eu

if [ "$(uname -s)" != Linux ]; then
  echo "This integration run requires a Linux host with rootless or passwordless-sudo Docker." >&2
  exit 2
fi

package_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
output=${1:-"$package_dir/evidence/run-$(date -u +%Y%m%dT%H%M%SZ)"}

python3 -m unittest -v "$package_dir/test_registry.py"
python3 "$package_dir/run.py" --output "$output"
python3 "$package_dir/audit.py" "$output" --write
echo "$output"
