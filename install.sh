#!/bin/sh
# Source checkout entry. Release builder embeds the same standalone implementation.
set -eu
exec python3 -I "$(dirname "$0")/harness/scripts/product_install.py" "$@"
