#!/usr/bin/env python3
"""Manager-run real local-artifact install/doctor/lifecycle evidence. No model calls."""
import argparse
import contextlib
import errno
import http.server
import json
import os
from pathlib import Path
import pty
import select
import shutil
import signal
import subprocess
import sys
import threading
import time

from build_product_release import REPO, build, source_files
from product_install import require, safe_path, sha, verify
from evidence_io import capture, reference, save as save_record


def terminal_output(argv, env, cwd, timeout=30, expected=0, *, evidence=None):
    """Bounded real PTY; never leave a fixture shell or its children on failure."""
    master, slave = pty.openpty()
    process = None
    transcript = bytearray()
    started = time.monotonic()
    receipt = {'argv': [str(arg) for arg in argv], 'complete': False,
               'started_epoch': time.time(), 'expected_exit': expected}
    log = None
    if evidence is not None:
        evidence = Path(evidence)
        evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
        save_record(evidence / 'process.json', receipt)
        log = (evidence / 'terminal.txt').open('xb')
    try:
        process = subprocess.Popen(argv, env=env, cwd=cwd, stdin=slave, stdout=slave,
                                   stderr=slave, start_new_session=True)
        os.close(slave)
        slave = None
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if select.select([master], [], [], min(.1, max(0, deadline - time.monotonic())))[0]:
                try:
                    data = os.read(master, 65536)
                except OSError as exc:
                    if exc.errno == errno.EIO:  # Linux PTY slave closed.
                        break
                    raise
                if not data:
                    break
                transcript.extend(data)
                if log is not None:
                    log.write(data)
                    log.flush()
                require(len(transcript) <= 1024 * 1024, "Terminal output limit exceeded")
            elif process.poll() is not None:
                break
        remaining = max(.001, deadline - time.monotonic())
        code = process.wait(timeout=remaining)
        receipt.update(exit_code=code, complete=True)
        require(code == expected, "Fresh terminal command failed")
        return bytes(transcript)
    except BaseException as exc:
        receipt['error_type'] = type(exc).__name__
        raise
    finally:
        if process is not None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        os.close(master)
        if slave is not None:
            os.close(slave)
        if log is not None:
            log.close()
            receipt.update(exit_code=process.returncode if process is not None else None,
                           seconds=time.monotonic() - started, ended_epoch=time.time(),
                           transcript=reference(evidence, evidence / 'terminal.txt'))
            save_record(evidence / 'process.json', receipt)


def terminal_environment(home, environment):
    """Only fixture startup files, no inherited source or shell configuration."""
    env = {k: v for k, v in environment.items() if k in ("PATH", "LANG") or k.startswith("LC_")}
    env.update(HOME=str(home), XDG_CONFIG_HOME=str(home / ".config"),
               XDG_DATA_HOME=str(home / ".local/share"), XDG_CACHE_HOME=str(home / ".cache"),
               HISTFILE="/dev/null", TERM="dumb")
    return env


def integration_line(guidance, prefix):
    lines = [line.strip() for line in guidance.splitlines() if line.startswith("  " + prefix)]
    require(len(lines) == 1, "Missing or ambiguous printed shell integration")
    return lines[0] + "\n"


def source_identity_command(installed):
    probe = "import json,pathlib,ptw,hashlib; p=pathlib.Path(ptw.__file__).parent; print(json.dumps({'path':str(p),'hashes':{str(f.relative_to(p)):hashlib.sha256(f.read_bytes()).hexdigest() for f in p.rglob('*') if f.is_file() and '__pycache__' not in f.parts and f.suffix not in ('.pyc','.pyo')}}))"
    # -I ignores PYTHONDONTWRITEBYTECODE. This probe must not alter the receipt.
    return [installed / "venv/bin/python", "-I", "-B", "-c", probe]


def acceptance(out, *, candidate=None):
    out = safe_path(out)
    require(REPO != out and REPO not in out.parents, "Evidence must be outside the checkout")
    out.mkdir(parents=True, exist_ok=False)
    records = []
    result = {"passed": False, "model_calls": 0, "new_oauth_login_tested": False,
              "authentication_files_copied": False, "phases": records,
              "cache_profile": "new private install caches, host OS prerequisites preinstalled",
              "terminal_profile": "normal startup discovery in isolated fixture homes; printed integration for custom bin directory"}
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    root, commands = out / "installation", out / "commands"
    sentinel = out / "project"
    sentinel.mkdir()
    for name, value in (("policy.json", "approved fixture policy"), ("history.jsonl", "retained fixture history"),
                        ("source.py", "print('project unchanged')\n")):
        (sentinel / name).write_text(value)
    sentinels = {str(path): sha(path.read_bytes()) for path in sentinel.iterdir()}
    result['project_before_sha256'] = sentinels
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
            folder = out / 'probes' / label
            process = capture(record["argv"], folder, env=environment, cwd=out, timeout=timeout)
            record['probe'] = reference(out, folder / 'process.json')
            stdout, stderr = process.stdout.decode(errors='replace'), process.stderr.decode(errors='replace')
            record.update(exit_code=process.returncode, seconds=round(time.monotonic() - started, 3),
                          stdout=reference(out, folder / 'stdout'), stderr=reference(out, folder / 'stderr'))
            record['preservation'] = {
                'project': {name: sha(Path(name).read_bytes()) for name in sentinels},
                'unrelated_file': unrelated_file.read_text(), 'unrelated_job_alive': unrelated.poll() is None}
            state_path = root / 'state.json'
            record['installation_state'] = json.loads(state_path.read_text()) if state_path.exists() else None
            require(record['preservation'] == {'project': sentinels, 'unrelated_file': 'unrelated file',
                    'unrelated_job_alive': True}, label + ' changed unrelated data/work')
            require(process.returncode == expected, label + " failed; see phase exit status")
            require(contains is None or contains in stdout + stderr,
                    label + " failed for an unexpected reason")
            if contains:
                record["required_diagnostic"] = contains
            record["passed"] = True
            return stdout
        except BaseException as exc:
            record.update(passed=False, error=type(exc).__name__, seconds=round(time.monotonic() - started, 3))
            raise
        finally:
            if (out / 'probes' / label / 'process.json').is_file():
                record['probe'] = reference(out, out / 'probes' / label / 'process.json')
            save()

    try:
        started = time.monotonic()
        build_record = {"phase": "build", "passed": False}
        records.append(build_record)
        try:
            if candidate is None:
                release = build(out / "release")
                artifact = out / "release" / release["archive"]
                entry = out / "release/install.sh"
            else:
                project, sources = source_files(REPO)
                release = {'manifest': {'version': project['version'],
                    'source_sha256': {n: sha(data) for n, data in sources.items()}},
                    'candidate': candidate}
                artifact, entry = Path(candidate['artifact']), Path(candidate['bootstrap'])
                require(sha(artifact.read_bytes()) == candidate['sha256'], 'Candidate changed')
            build_record.update(passed=True, seconds=round(time.monotonic() - started, 3))
        finally:
            save()
        result["release"] = release

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
        guidance = call("cold-install-http-and-automatic-doctor", [*base, "--artifact", url + "/ok", "--test-loopback-http"])
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

        # Read the actual bootstrap output, then use normal startup-file discovery.
        # Missing validation shells fail explicitly; they are not install dependencies.
        for shell, flags, profile in (("bash", "-lic", ".bash_profile"), ("bash", "-ic", ".bashrc"),
                                      ("zsh", "-lic", ".zprofile"), ("zsh", "-ic", ".zshrc"),
                                      ("fish", "-ic", "fish_variables")):
            terminal_record = {"phase": "fresh-terminal-" + shell + "-" + profile,
                               "shell": shell, "flags": flags, "startup_file": profile, "passed": False}
            records.append(terminal_record)
            try:
                executable = shutil.which(shell, path=env.get("PATH"))
                require(executable, "Validation prerequisite missing: " + shell)
                home = out / ("terminal-" + shell + "-" + profile)
                home.mkdir()
                terminal_env = terminal_environment(home, env)
                require(str(commands) not in terminal_env.get("PATH", "").split(":"), "Terminal inherited command PATH")
                startup_dir = home
                if shell == "zsh":
                    startup_dir = home / "custom-zdotdir"
                    startup_dir.mkdir()
                    terminal_env["ZDOTDIR"] = str(startup_dir)
                if shell == "fish":
                    terminal_output([executable, "-ic", integration_line(guidance, "fish_add_path ")], terminal_env, out,
                                    evidence=out / 'probes/fish-integration')
                    startup = home / ".config/fish/fish_variables"
                else:
                    startup = startup_dir / profile
                    startup.write_text(integration_line(guidance, "export PATH="))
                terminal_record["startup_path"] = str(startup)
                terminal_record["startup_sha256"] = sha(startup.read_bytes())
                # command -v works in all three shells and identifies both launchers.
                transcript = terminal_output([executable, flags,
                    "command -v ptw; command -v ptw-install; ptw --version && ptw-install status"], terminal_env, out,
                    evidence=out / 'probes' / terminal_record['phase'])
                require(all(value.encode() in transcript for value in (
                    str(commands / "ptw"), str(commands / "ptw-install"), release["manifest"]["version"], first)),
                    "Fresh terminal resolved unexpected commands")
                verify(installed, state["releases"][first]["receipt"])
                terminal_record.update(passed=True, transcript_sha256=sha(transcript))
            finally:
                probe = out / 'probes' / terminal_record['phase'] / 'process.json'
                if probe.is_file():
                    terminal_record['probe'] = reference(out, probe)
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
            if name in ("harness/pyproject.toml", "harness/ptw/__init__.py", "harness/ptw/release_data/pyproject.toml"):
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
        result['uninstall_effects'] = {'unowned_note': str(extra), 'unowned_note_sha256': sha(extra.read_bytes()),
            'owned_launchers': {name: (commands / name).exists() for name in ('ptw', 'ptw-codex', 'ptw-install')}}
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
