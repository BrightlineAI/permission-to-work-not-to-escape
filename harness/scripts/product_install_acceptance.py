#!/usr/bin/env python3
"""Manager-run real local-artifact install/doctor/lifecycle evidence. No model calls."""
import argparse
import contextlib
import http.server
import json
import os
from pathlib import Path
import pty
import select
import shlex
import subprocess
import sys
import threading
import time

from build_product_release import REPO, build, source_files
from product_install import require, safe_path, sha, verify


def source_identity_command(installed):
    probe = "import json,pathlib,ptw,hashlib; p=pathlib.Path(ptw.__file__).parent; print(json.dumps({'path':str(p),'hashes':{f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in p.glob('*.py')}}))"
    # -I ignores PYTHONDONTWRITEBYTECODE. This probe must not alter the receipt.
    return [installed / "venv/bin/python", "-I", "-B", "-c", probe]


def acceptance(out):
    out = safe_path(out)
    require(REPO != out and REPO not in out.parents, "Evidence must be outside the checkout")
    out.mkdir(parents=True, exist_ok=False)
    records = []
    result = {"passed": False, "model_calls": 0, "new_oauth_login_tested": False,
              "authentication_files_copied": False, "phases": records,
              "cache_profile": "new private install caches, host OS prerequisites preinstalled",
              "terminal_profile": "fresh interactive bash with documented explicit shell integration for custom bin directory"}
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    root, commands = out / "installation", out / "commands"
    sentinel = out / "project"
    sentinel.mkdir()
    for name, value in (("policy.json", "approved fixture policy"), ("history.jsonl", "retained fixture history"),
                        ("source.py", "print('project unchanged')\n")):
        (sentinel / name).write_text(value)
    sentinels = {str(path): sha(path.read_bytes()) for path in sentinel.iterdir()}
    unrelated_file = out / "unrelated.txt"
    unrelated_file.write_text("unrelated file")
    unrelated = subprocess.Popen(["sleep", "1200"], env=env, cwd=out)
    server = None

    def save():
        (out / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True))

    def call(label, command, *, expected=0, timeout=600, environment=env, contains=None):
        record = {"phase": label, "argv": [str(x) for x in command], "expected_exit": expected}
        records.append(record)
        started = time.monotonic()
        try:
            process = subprocess.run(record["argv"], env=environment, cwd=out, capture_output=True, text=True, timeout=timeout)
            record.update(exit_code=process.returncode, seconds=round(time.monotonic() - started, 3),
                          stdout_sha256=sha(process.stdout.encode()), stderr_sha256=sha(process.stderr.encode()))
            # Retain hashes and exit status, not potentially credential-bearing native output.
            require(process.returncode == expected, label + " failed; see phase exit status")
            require(contains is None or contains in process.stdout + process.stderr,
                    label + " failed for an unexpected reason")
            if contains:
                record["required_diagnostic"] = contains
            record["passed"] = True
            return process.stdout
        except BaseException as exc:
            record.update(passed=False, error=type(exc).__name__, seconds=round(time.monotonic() - started, 3))
            raise
        finally:
            save()

    try:
        started = time.monotonic()
        build_record = {"phase": "build", "passed": False}
        records.append(build_record)
        try:
            release = build(out / "release")
            build_record.update(passed=True, seconds=round(time.monotonic() - started, 3))
        finally:
            save()
        result["release"] = release
        artifact = out / "release" / release["archive"]
        entry = out / "release/install.sh"

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                if self.path == "/error":
                    self.send_error(503)
                    return
                data = artifact.read_bytes()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data[:len(data) // 2] if self.path == "/interrupted" else data)

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        url = "http://127.0.0.1:" + str(server.server_port)
        base = ["bash", entry, "--root", root, "--bin-dir", commands]
        for label, path, message in (("http-error", "/error", "503"), ("interrupted-download", "/interrupted", "Interrupted download")):
            call(label, [*base, "--artifact", url + path, "--test-loopback-http"], expected=2, contains=message)
        call("incorrect-hash", [*base, "--artifact", artifact, "--sha256", "0" * 64], expected=2, contains="SHA-256 mismatch")
        before_install = time.monotonic()
        call("cold-install-http-and-automatic-doctor", [*base, "--artifact", url + "/ok", "--test-loopback-http"])
        result["installer_through_doctor_seconds"] = round(time.monotonic() - before_install, 3)
        state = json.loads((root / "state.json").read_text())
        first = state["active"]
        installed = root / "releases" / first
        source_hashes = {name.removeprefix("harness/ptw/"): digest for name, digest in
                         release["manifest"]["source_sha256"].items() if name.startswith("harness/ptw/")}
        imported = json.loads(call("installed-source-identity", source_identity_command(installed)))
        verify(installed, state["releases"][first]["receipt"])
        require(str(installed) + "/" in imported["path"] + "/", "Import escaped installed environment")
        require(imported["hashes"] == source_hashes, "Installed source hashes differ")
        result["installed_source"] = imported
        doctor = json.loads(call("installed-doctor", [commands / "ptw", "doctor"], timeout=120))
        require(doctor.get("ready") is True, "Real installed doctor is not ready")
        result["doctor"] = doctor
        verify(installed, state["releases"][first]["receipt"])

        # A custom bin directory is intentionally outside normal OS discovery.
        # Exercise exactly the documented fallback in a fresh real interactive PTY.
        startup = out / "bashrc"
        startup.write_text("export PATH=" + shlex.quote(str(commands)) + ':"$PATH"\n')
        master, slave = pty.openpty()
        transcript = bytearray()
        terminal_record = {"phase": "fresh-terminal", "passed": False}
        records.append(terminal_record)
        try:
            terminal = subprocess.Popen(["bash", "--noprofile", "--rcfile", str(startup), "-ic",
                                         "ptw --version && ptw-install status"], env=env, cwd=out,
                                        stdin=slave, stdout=slave, stderr=slave)
            os.close(slave)
            slave = None
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if select.select([master], [], [], .1)[0]:
                    try:
                        transcript.extend(os.read(master, 65536))
                    except OSError:
                        break
                if terminal.poll() is not None:
                    break
            require(terminal.wait(timeout=5) == 0 and release["manifest"]["version"].encode() in transcript and
                    first.encode() in transcript, "Fresh terminal commands failed")
            terminal_record.update(passed=True, transcript_sha256=sha(transcript))
        finally:
            os.close(master)
            if slave is not None:
                os.close(slave)
            save()

        call("same-version-retry", [*base, "--artifact", artifact])
        require(json.loads((root / "state.json").read_text())["active"] == first, "Retry changed installation identity")
        empty_codex = out / "empty-codex-home"
        empty_codex.mkdir()
        missing_login = {**env, "CODEX_HOME": str(empty_codex)}
        call("missing-login", [commands / "ptw-codex", "login", "status"], expected=1,
             environment=missing_login, timeout=30, contains="Not logged in")

        # Upgrade fixture changes package version only in a separate allowlisted source copy.
        # This is NOT another published release and is explicitly recorded as a fixture.
        fixture = out / "upgrade-source"
        project, sources = source_files(REPO)
        major, minor, patch = (int(x) for x in project["version"].split("."))
        fixture_version = f"{major}.{minor}.{patch + 1}"
        for name, data in sources.items():
            target = fixture / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if name in ("harness/pyproject.toml", "harness/ptw/__init__.py"):
                data = data.replace(('"' + project["version"] + '"').encode(), ('"' + fixture_version + '"').encode())
            target.write_bytes(data)
        fixture_build_record = {"phase": "fixture-upgrade-build", "passed": False}
        records.append(fixture_build_record)
        try:
            upgrade = build(out / "upgrade-release", repo=fixture)
            fixture_build_record["passed"] = True
        finally:
            save()
        result["fixture_upgrade_version"] = fixture_version
        call("fixture-upgrade", ["bash", out / "upgrade-release/install.sh", "--artifact",
                                 out / "upgrade-release" / upgrade["archive"], "--root", root, "--bin-dir", commands])
        require(json.loads((root / "state.json").read_text())["previous"] == first, "Upgrade lost rollback selection")
        call("rollback-with-real-doctor", [commands / "ptw-install", "rollback"])
        require(json.loads((root / "state.json").read_text())["active"] == first, "Rollback did not restore first release")
        # Adding unowned data tests conservative removal on a real installation.
        extra = installed / "operator-note.txt"
        extra.write_text("retain unowned installation note")
        call("uninstall", [commands / "ptw-install", "uninstall"])
        call("repeated-uninstall", ["bash", entry, "uninstall", "--root", root])
        require(extra.read_text() == "retain unowned installation note", "Unowned note removed")
        require(all(sha(Path(name).read_bytes()) == digest for name, digest in sentinels.items()), "Project files changed")
        require(unrelated_file.read_text() == "unrelated file" and unrelated.poll() is None, "Unrelated work changed")
        require(not any((commands / name).exists() for name in ("ptw", "ptw-codex", "ptw-install")), "Owned launchers remain")
        result.update(passed=True, project_hashes_preserved=sentinels, unrelated_job_survived=True,
                      unowned_installation_file_retained=True, full_first_setup_target_measured=False)
    except BaseException as exc:
        result.update(error=type(exc).__name__ + ": " + str(exc))
        raise
    finally:
        save()
        if server:
            server.shutdown()
            server.server_close()
        unrelated.terminate()
        unrelated.wait(timeout=5)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = acceptance(args.out)
        print(json.dumps({"passed": report["passed"], "evidence": str(args.out)}))
    except Exception as exc:
        print(type(exc).__name__ + ": " + str(exc), file=sys.stderr)
        raise SystemExit(1)
