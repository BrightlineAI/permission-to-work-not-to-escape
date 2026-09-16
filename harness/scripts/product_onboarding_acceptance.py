#!/usr/bin/env python3
"""Manager-only cold installer + existing real Codex PTY journey, one outer clock.

Makes paid model calls. Requires the operator's existing login and native Linux
confinement. Never copies authentication, retries silently, or substitutes models.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time

from product_install import require, safe_path, sha, verify


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--bootstrap", type=Path, required=True, help="Operator-verified built release install.sh")
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--language", choices=("python", "javascript", "typescript"), default="python")
    parser.add_argument("--existing", action="store_true")
    args = parser.parse_args()
    out = safe_path(args.out)
    repo = Path(__file__).resolve().parents[2]
    require(out != repo and repo not in out.parents, "Evidence must be outside the checkout")
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {"passed": False, "timing_profile": "cold-install-first-setup", "new_oauth_tested": False,
              "authentication": "operator's existing login; no credential copies",
              "cache_profile": "new installation and private package caches; OS prerequisites already installed",
              "human_input": "scripted fixture review in a real PTY, including input delays",
              "source_sha256": {str(p.relative_to(repo)): sha(p.read_bytes()) for p in sorted((repo / "harness/ptw").glob("*.py"))}}
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    root, commands = out / "installation", out / "commands"
    attempted = time.monotonic()
    try:
        report["bootstrap_sha256"] = sha(args.bootstrap.read_bytes())
        report["artifact_sha256"] = sha(args.artifact.read_bytes())
        started = time.monotonic()
        install = subprocess.run(["bash", str(args.bootstrap.resolve()), "--artifact", str(args.artifact.resolve()),
            "--sha256", args.sha256, "--root", str(root), "--bin-dir", str(commands)], env=env,
            capture_output=True, timeout=600)
        report["installer"] = {"exit_code": install.returncode, "seconds": time.monotonic() - started,
                               "stdout_sha256": sha(install.stdout), "stderr_sha256": sha(install.stderr)}
        require(install.returncode == 0, "Real cold installation failed; attempt retained")
        state = json.loads((root / "state.json").read_text())
        installed = root / "releases" / state["active"]
        verify(installed, state["releases"][state["active"]]["receipt"])
        env["PATH"] = ":".join(str(installed / p) for p in ("venv/bin", "bin", "codex/node_modules/.bin")) + ":" + env.get("PATH", "")
        env["PTW_NONO"] = str(installed / "bin/nono")
        python = installed / "venv/bin/python"
        probe = "import json,pathlib,ptw,hashlib; p=pathlib.Path(ptw.__file__).parent; print(json.dumps({'path':str(p),'hashes':{f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in p.glob('*.py')}}))"
        identity = subprocess.run([python, "-I", "-B", "-c", probe], env=env, capture_output=True, text=True, check=True)
        report["installed_source"] = json.loads(identity.stdout)
        require(Path(report["installed_source"]["path"]).is_relative_to(installed), "Imported source is not installed")
        require(report["installed_source"]["hashes"] == {Path(n).name: h for n, h in report["source_sha256"].items()},
                "Installed source differs from this acceptance checkout")
        scripts = Path(__file__).resolve().parent
        driver = "import sys; sys.path.insert(0,sys.argv.pop(1)); import interactive_acceptance; interactive_acceptance.main()"
        result = subprocess.run([python, "-I", "-B", "-c", driver, str(scripts), "--out", str(out / "journey"),
            "--ptw", str(commands / "ptw"), "--language", args.language, "--journey-start", str(started),
            *(["--existing"] if args.existing else [])], env=env, capture_output=True, timeout=1000)
        report["journey_process"] = {"exit_code": result.returncode, "stdout_sha256": sha(result.stdout),
                                     "stderr_sha256": sha(result.stderr)}
        require(result.returncode == 0, "Native setup/action journey failed; inspect retained private journey")
        journey = json.loads((out / "journey/result.json").read_text())
        report["timing"] = journey["timing"]
        verify(installed, state["releases"][state["active"]]["receipt"])
        report["passed"] = journey["passed"] and journey["timing"]["first_setup_target_met"]
        require(report["passed"], "First-setup target unmet; full elapsed time retained")
    except BaseException as exc:
        report["error"] = type(exc).__name__ + ": " + str(exc)
        raise
    finally:
        report["full_attempt_seconds"] = time.monotonic() - attempted
        (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
