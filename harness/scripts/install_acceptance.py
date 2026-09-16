#!/usr/bin/env python3
"""Follow the documented installer/doctor in a new directory; no credentials copied."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


parser = argparse.ArgumentParser()
parser.add_argument("--install", type=Path, required=True)
parser.add_argument("--out", type=Path, required=True)
parser.add_argument("--check-login-only", action="store_true")
args = parser.parse_args()
args.out.mkdir(mode=0o700, parents=True, exist_ok=False)
env = {**os.environ, "PATH": ":".join(str(args.install / suffix) for suffix in
       ("venv/bin", "bin", "codex/node_modules/.bin")) + ":" + os.environ["PATH"]}
if args.check_login_only:
    status = subprocess.run(["codex", "login", "status"], env=env, capture_output=True, text=True, timeout=20)
    if status.returncode == 0:
        raise SystemExit("This negative check requires a separate account with no Codex login.")
    project = args.out / "repo"
    project.mkdir()
    call = subprocess.run(["ptw", "codex", "--repo", str(project), "--setup-only"],
                          env=env, capture_output=True, text=True, timeout=30)
    message = (call.stdout + call.stderr).strip()
    result = {"exit_code": call.returncode, "message": message,
              "project_unchanged": not list(project.iterdir()),
              "passed": call.returncode == 2 and "codex login" in message and not list(project.iterdir())}
    (args.out / "result.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result), flush=True)
    raise SystemExit(0 if result["passed"] else 1)
repo = Path(__file__).resolve().parents[2]
started = time.monotonic()
install = subprocess.run(["bash", "harness/scripts/install-vps.sh", str(args.install)],
                         cwd=repo, capture_output=True, text=True, timeout=600)
(args.out / "install.log").write_text(install.stdout + install.stderr)
elapsed = round(time.monotonic() - started, 3)
if install.returncode:
    raise SystemExit("Documented installer failed; inspect install.log")
env = {**os.environ, "PATH": ":".join(str(args.install / suffix) for suffix in
       ("venv/bin", "bin", "codex/node_modules/.bin")) + ":" + os.environ["PATH"]}
doctor = subprocess.run(["ptw", "doctor"], env=env, capture_output=True, text=True, timeout=60)
if doctor.returncode:
    raise SystemExit("Installed doctor failed: " + doctor.stderr)
diagnostic = json.loads(doctor.stdout)
(args.out / "doctor.json").write_text(json.dumps(diagnostic, indent=2))
auth = subprocess.run(["codex", "login", "status"], env=env, capture_output=True, text=True, timeout=20)
python = args.install / "venv/bin/python"
module = subprocess.run([str(python), "-c", "import pathlib,ptw; print(pathlib.Path(ptw.__file__).parent)"],
                        env=env, capture_output=True, text=True, check=True)
installed = Path(module.stdout.strip())
hashes = {str(path.relative_to(repo / "harness/ptw")): hashlib.sha256(path.read_bytes()).hexdigest()
          for path in (repo / "harness/ptw").glob("*.py")}
matching = all((installed / name).is_file() and hashlib.sha256((installed / name).read_bytes()).hexdigest() == sha
               for name, sha in hashes.items())
result = {"installer_seconds": elapsed, "installed_modules": len(hashes), "source_match": matching,
          "doctor_ready": diagnostic["ready"], "codex_authenticated": auth.returncode == 0,
          "new_oauth_login_tested": False, "authentication_files_copied": False,
          "python": subprocess.check_output([str(python), "--version"], text=True).strip(),
          "passed": matching and diagnostic["ready"], "source_sha256": hashes}
(args.out / "result.json").write_text(json.dumps(result, indent=2))
print(json.dumps({k: v for k, v in result.items() if k != "source_sha256"}), flush=True)
if not result["passed"]:
    raise SystemExit(1)
