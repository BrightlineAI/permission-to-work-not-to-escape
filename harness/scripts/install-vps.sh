#!/usr/bin/env bash
# Fresh, private installation. No global packages or existing environments changed.
set -euo pipefail
if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
  echo "This first installer targets x86_64 Linux; other platforms are not supported yet." >&2
  exit 2
fi
ptw_codex=1
if [ "$#" -gt 0 ] && [ "$1" = "--no-codex" ]; then ptw_codex=0; shift; fi
if [ "$#" != 1 ]; then
  echo "Usage: bash harness/scripts/install-vps.sh [--no-codex] /absolute/new/install-directory" >&2
  exit 2
fi
ptw_install="$1"
case "$ptw_install" in /*) ;; *) echo "Use an absolute installation path" >&2; exit 2;; esac
if [ -e "$ptw_install" ]; then echo "Installation path already exists; use a new one" >&2; exit 2; fi
for ptw_command in python3 curl sha256sum bwrap systemd-run systemctl; do
  command -v "$ptw_command" >/dev/null || { echo "Missing prerequisite: $ptw_command" >&2; exit 2; }
done
if [ "$ptw_codex" = 1 ]; then
  for ptw_command in node npm; do command -v "$ptw_command" >/dev/null || { echo "Missing prerequisite: $ptw_command" >&2; exit 2; }; done
fi
ptw_source="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ptw_source"
mkdir -m 700 -p "$ptw_install"
mkdir "$ptw_install/bin"

download_binary() {
  local ptw_name="$1" ptw_url="$2" ptw_sha="$3"
  curl --fail --location --silent --show-error "$ptw_url" -o "$ptw_install/$ptw_name.tar.gz"
  echo "$ptw_sha  $ptw_install/$ptw_name.tar.gz" | sha256sum --check -
  python3 - "$ptw_install/$ptw_name.tar.gz" "$ptw_name" "$ptw_install/bin/$ptw_name" <<'PY'
import os, pathlib, sys, tarfile
archive, name, target = sys.argv[1:]
with tarfile.open(archive) as handle:
    members = [m for m in handle.getmembers() if m.isfile() and pathlib.PurePosixPath(m.name).name == name]
    if len(members) != 1:
        raise SystemExit("Unexpected archive layout")
    with handle.extractfile(members[0]) as source, open(target, "xb") as output:
        output.write(source.read())
os.chmod(target, 0o755)
PY
}

download_binary uv https://github.com/astral-sh/uv/releases/download/0.12.15/uv-x86_64-unknown-linux-gnu.tar.gz f97935763c04be3e692460a7aaeaaab8fc3b78fcf8b389da820b38ae7423a638
download_binary nono https://github.com/nolabs-ai/nono/releases/download/v0.77.0/nono-v0.77.0-x86_64-unknown-linux-gnu.tar.gz 86bcf7a134d6f47e064ad0f2561f1be02b9fffc643708c3ec2dd4070e82b798e
UV_CACHE_DIR="$ptw_install/cache" "$ptw_install/bin/uv" --no-config venv --python 3.12 "$ptw_install/venv"
UV_CACHE_DIR="$ptw_install/cache" "$ptw_install/bin/uv" --no-config pip install --python "$ptw_install/venv/bin/python" -r "$ptw_source/requirements.lock"
UV_CACHE_DIR="$ptw_install/cache" "$ptw_install/bin/uv" --no-config pip install --python "$ptw_install/venv/bin/python" --no-deps "$ptw_source"
if [ "$ptw_codex" = 1 ]; then
  npm install --prefix "$ptw_install/codex" --no-audit --no-fund @openai/codex@0.154.0
fi
echo "Installed. For this shell, set:"
echo "export PATH=\"$ptw_install/venv/bin:$ptw_install/bin:$ptw_install/codex/node_modules/.bin:\$PATH\""
echo "Next: ptw doctor. Package controls need no model login; authenticate Codex only for model tasks."
