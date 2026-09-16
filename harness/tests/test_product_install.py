"""Installer effects and fault injection. Doubles below are NOT native doctor evidence."""
import contextlib
import hashlib
import http.server
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import signal
import shutil
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
import threading
import time
import unittest
import venv
from unittest.mock import patch
import zipfile

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import product_install as product
import build_product_release as builder
from product_install_acceptance import (integration_line, source_identity_command,
                                        terminal_environment, terminal_output)


def npm_fixture():
    package = {"name": "ptw-private-codex", "version": "1.0.0", "private": True,
               "dependencies": {"@openai/codex": product.CODEX}}
    packages = {"": dict(package)}
    for platform in (None, *product.CODEX_PLATFORMS):
        name = "node_modules/@openai/codex" + ("-" + platform if platform else "")
        version = product.CODEX + ("-" + platform if platform else "")
        packages[name] = {"version": version, "integrity": "sha512-" + "A" * 86 + "==",
                          "resolved": "https://registry.npmjs.org/@openai/codex/-/codex-" + version + ".tgz"}
    packages["node_modules/@openai/codex"]["optionalDependencies"] = {
        "@openai/codex-" + p: "npm:@openai/codex@" + product.CODEX + "-" + p for p in product.CODEX_PLATFORMS}
    return package, {"lockfileVersion": 3, "packages": packages}


def release_fixture(version="0.5.0"):
    """A packaging fixture with real source bytes, not an installable runtime wheel."""
    project, sources = builder.source_files(builder.REPO)
    project = {**project, "version": version}
    wheel = io.BytesIO()
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, data in sources.items():
            if name.startswith("harness/ptw/"):
                archive.writestr(zipfile.ZipInfo(name.removeprefix("harness/")), data)
    package, lock = npm_fixture()
    return builder.assemble(project, sources, wheel.getvalue(), package, lock)[0]


READY = {"ready": True, "codex_authenticated": False, "checks": {
    name: True for name in ("permitted_read", "private_read_blocked", "supervised_work_running", "project_stop_confirmed")}}


def prepare_fixture(candidate, files, manifest):
    """Small executable fixture; used only for lifecycle/terminal behavior."""
    (candidate / "payload").mkdir()
    (candidate / "payload/product_install.py").write_bytes(files["product_install.py"])
    (candidate / "venv/bin").mkdir(parents=True)
    ptw = candidate / "venv/bin/ptw"
    ptw.write_text("#!" + sys.executable + "\nimport os,sys\nprint(" + repr(manifest["version"]) + ")\n")
    ptw.chmod(0o755)
    (candidate / "venv/bin/python").symlink_to(sys.executable)


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ptw-install-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root, self.bin = self.base / "owned", self.base / "bin"
        self.patches = contextlib.ExitStack()
        self.addCleanup(self.patches.close)
        self.patches.enter_context(patch.object(product, "preflight"))
        self.real_in_use = product.in_use
        self.patches.enter_context(patch.object(product, "in_use"))
        self.patches.enter_context(patch.object(product, "prepare", side_effect=prepare_fixture))
        self.health = self.patches.enter_context(patch.object(product, "health", return_value=READY))
        self.patches.enter_context(contextlib.redirect_stdout(io.StringIO()))

    def artifact(self, version="0.5.0"):
        data = release_fixture(version)
        path = self.base / (version + ".tgz")
        path.write_bytes(data)
        return str(path), product.sha(data)

    def install(self, version="0.5.0"):
        artifact, digest = self.artifact(version)
        with product.locked(self.root, self.bin) as state:
            product.install(self.root, state, artifact, digest)
        return self.state()

    def state(self):
        return json.loads((self.root / "state.json").read_text())

    def test_fresh_retry_upgrade_rollback_uninstall_preserves_projects(self):
        project = self.base / "project"
        project.mkdir()
        (project / "policy.json").write_text("approved")
        (project / "history.jsonl").write_text("history")
        before = product.snapshot(project)
        first = self.install()
        retry = self.install()
        self.assertEqual(first["active"], retry["active"])
        self.assertEqual(len(retry["releases"]), 1)
        upgraded = self.install("0.5.1")
        self.assertEqual(upgraded["previous"], first["active"])
        with product.locked(self.root, self.bin) as state:
            product.rollback(self.root, state)
        self.assertEqual(self.state()["active"], first["active"])
        with product.locked(self.root, self.bin) as state:
            product.uninstall(self.root, state)
            product.uninstall(self.root, state)
        self.assertEqual(product.snapshot(project), before)
        self.assertFalse((self.bin / "ptw").exists())
        self.assertFalse((self.root / "releases").exists())

    def test_failed_doctor_upgrade_and_rollback_keep_active(self):
        first = self.install()
        self.health.side_effect = product.InstallError("doctor failed")
        with self.assertRaises(product.InstallError):
            self.install("0.5.1")
        self.assertEqual(self.state()["active"], first["active"])
        self.assertIn("failed", [r["status"] for r in self.state()["releases"].values()])
        self.health.side_effect = None
        second = self.install("0.5.1")
        self.health.side_effect = product.InstallError("doctor failed")
        with product.locked(self.root, self.bin) as state, self.assertRaises(product.InstallError):
            product.rollback(self.root, state)
        self.assertEqual(self.state()["active"], second["active"])

    def test_retry_upgrade_preserve_owned_launchers_across_python_paths(self):
        interpreters = []
        for name in ("original-python", "activated-python"):
            directory = self.base / name
            venv.EnvBuilder(with_pip=False).create(directory)
            interpreters.append(str(directory / "bin/python"))
        with patch.object(product.sys, "executable", interpreters[0]):
            first = self.install()
        wrappers = {p.name: p.read_bytes() for p in self.bin.iterdir()}
        with patch.object(product.sys, "executable", interpreters[1]):
            retry = self.install()
            self.assertEqual(retry["active"], first["active"])
            upgraded = self.install("0.5.1")
            self.assertEqual(upgraded["previous"], first["active"])
            self.assertEqual(upgraded["launchers"], first["launchers"])
            self.assertEqual({p.name: p.read_bytes() for p in self.bin.iterdir()}, wrappers)
            # Run the preserved shell wrappers through their actual interpreter.
            result = subprocess.run([self.bin / "ptw", "--version"], cwd=self.base,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "0.5.1")
            result = subprocess.run([self.bin / "ptw-install", "status"], cwd=self.base,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["active"], upgraded["active"])
            (self.bin / "ptw").write_text("unrelated replacement")
            with self.assertRaisesRegex(product.InstallError, "collision"):
                self.install()
            self.assertEqual(self.state()["active"], upgraded["active"])
            self.assertEqual((self.bin / "ptw").read_text(), "unrelated replacement")

    def test_partial_launcher_publication_recovers_with_different_python(self):
        publish = product.publish_file

        def interrupt(path, data, mode):
            if path.name == "ptw-codex":
                raise KeyboardInterrupt()
            publish(path, data, mode)

        with patch.object(product, "publish_file", side_effect=interrupt), self.assertRaises(KeyboardInterrupt):
            self.install()
        original = (self.bin / "ptw").read_bytes()
        python = self.base / "other-python"
        python.symlink_to(sys.executable)
        with patch.object(product.sys, "executable", str(python)):
            state = self.install()
        self.assertEqual((self.bin / "ptw").read_bytes(), original)
        for name, digest in state["launchers"].items():
            self.assertEqual(product.sha((self.bin / name).read_bytes()), digest)
        with product.locked(self.root, self.bin) as state:
            product.uninstall(self.root, state)
        self.assertEqual(list(self.bin.iterdir()), [])

    def test_stopped_monitor_escaped_paths_block_transitions_without_changes(self):
        from ptw import monitor

        config = self.base / "config"
        units = config / "systemd/user"
        units.mkdir(parents=True)
        unit = units / "ptw-monitor-fixture.service"
        for index, suffix in enumerate(('double"quote', 'back\\slash', 'dollar$sign',
                                        'percent%sign', 'all"\\$%')):
            with self.subTest(path=suffix):
                self.root = self.base / suffix
                self.bin = self.base / ("bin-" + str(index))
                first = self.install()
                self.install("0.5.1")
                interpreter = self.root / "releases" / first["active"] / "venv/bin/python"
                with patch.object(monitor.sys, "executable", str(interpreter)):
                    unit.write_text(monitor.service_text(self.base / "controller"))
                before = product.snapshot(self.root)
                commands = product.snapshot(self.bin)
                service = unit.read_bytes()
                artifact, digest = self.artifact("0.5.2")
                # Only a stopped unit file exists; no running process can mask a miss.
                with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(config)}), \
                        patch.object(product, "in_use", side_effect=self.real_in_use):
                    for action in (lambda state: product.install(self.root, state, artifact, digest),
                                   lambda state: product.rollback(self.root, state),
                                   lambda state: product.uninstall(self.root, state)):
                        with product.locked(self.root, self.bin) as state:
                            with self.assertRaisesRegex(product.InstallError, "referenced by a monitor"):
                                action(state)
                        self.assertEqual(product.snapshot(self.root), before)
                        self.assertEqual(product.snapshot(self.bin), commands)
                        self.assertEqual(unit.read_bytes(), service)

    def test_retry_and_rollback_verify_installed_integrity(self):
        first = self.install()
        target = self.root / "releases" / first["active"] / "venv/bin/ptw"
        target.write_text("tampered")
        calls = self.health.call_count
        with self.assertRaisesRegex(product.InstallError, "changed"):
            self.install()
        self.assertEqual(calls, self.health.call_count)
        self.install("0.5.1")
        with product.locked(self.root, self.bin) as state, self.assertRaisesRegex(product.InstallError, "changed"):
            product.rollback(self.root, state)

    def test_retry_and_rollback_reject_files_created_during_health(self):
        first = self.install()
        second = self.install("0.5.1")

        def mutate(candidate, version):
            (candidate / "unexpected.pyc").write_bytes(b"bytecode must not be ignored")
            return READY

        self.health.side_effect = mutate
        with self.assertRaisesRegex(product.InstallError, "Unexpected installed files"):
            self.install("0.5.1")
        self.assertEqual(self.state()["active"], second["active"])
        with product.locked(self.root, self.bin) as state, self.assertRaisesRegex(product.InstallError, "Unexpected installed files"):
            product.rollback(self.root, state)
        self.assertEqual(self.state()["active"], second["active"])
        self.assertEqual(self.state()["previous"], first["active"])

    def test_same_version_different_archive_refused(self):
        first = self.install()
        data = release_fixture() + b"changed"
        path = self.base / "different.tgz"
        path.write_bytes(data)
        with product.locked(self.root, self.bin) as state, self.assertRaisesRegex(product.InstallError, "different bytes"):
            product.install(self.root, state, str(path), product.sha(data))
        self.assertEqual(self.state()["active"], first["active"])

    def test_interrupted_prepare_retry_and_owned_cleanup(self):
        def interrupt(candidate, files, manifest):
            (candidate / "partial").write_text("partial")
            raise KeyboardInterrupt()
        with patch.object(product, "prepare", side_effect=interrupt), self.assertRaises(KeyboardInterrupt):
            self.install()
        self.assertIsNone(self.state()["active"])
        state = self.install()
        self.assertEqual(len(state["releases"]), 2)
        with product.locked(self.root, self.bin) as state:
            product.uninstall(self.root, state)
        self.assertFalse((self.root / "releases").exists())

    def test_hard_interruption_retains_unrecorded_candidate(self):
        with product.locked(self.root, self.bin) as state:
            identity = "a" * 32
            state["releases"][identity] = {"version": "0.5.0", "digest": self.artifact()[1], "status": "preparing", "receipt": {}}
            candidate = self.root / "releases" / identity
            candidate.mkdir(parents=True)
            (candidate / "unknown").write_text("keep after SIGKILL")
            product.atomic(self.root / "state.json", state)
        self.install()
        with product.locked(self.root, self.bin) as state:
            result = product.uninstall(self.root, state)
        self.assertIn(str(candidate), result["retained"])
        self.assertEqual((candidate / "unknown").read_text(), "keep after SIGKILL")

    def test_uninstall_preserves_modified_added_and_external_symlink_target(self):
        state = self.install()
        release = self.root / "releases" / state["active"]
        (release / "added").write_text("unrelated")
        (release / "venv/bin/ptw").write_text("modified")
        external = self.base / "external"
        external.write_text("do not delete")
        (release / "venv/bin/python").unlink()
        (release / "venv/bin/python").symlink_to(external)
        with product.locked(self.root, self.bin) as state:
            result = product.uninstall(self.root, state)
        self.assertTrue(result["retained"])
        self.assertEqual(external.read_text(), "do not delete")
        self.assertEqual((release / "added").read_text(), "unrelated")
        self.assertEqual((release / "venv/bin/ptw").read_text(), "modified")

    def test_uninstall_never_follows_replaced_parent(self):
        state = self.install()
        release = self.root / "releases" / state["active"]
        external = self.base / "external"
        (external / "bin").mkdir(parents=True)
        (external / "bin/ptw").write_text("sentinel")
        shutil.rmtree(release / "venv")
        (release / "venv").symlink_to(external)
        with product.locked(self.root, self.bin) as state:
            product.uninstall(self.root, state)
        self.assertEqual((external / "bin/ptw").read_text(), "sentinel")

    def test_collision_and_symlink_destinations(self):
        self.bin.mkdir()
        sentinel = self.bin / "ptw"
        sentinel.write_text("unrelated command")
        with self.assertRaisesRegex(product.InstallError, "collision"):
            self.install()
        self.assertIsNone(self.state()["active"])
        self.assertEqual(sentinel.read_text(), "unrelated command")
        other = self.base / "link"
        other.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(product.InstallError, "Symlink"):
            with product.locked(other, self.bin):
                pass

    def test_lock_excludes_concurrent_installer(self):
        with product.locked(self.root, self.bin):
            result = subprocess.run([sys.executable, "-I", str(SCRIPTS / "product_install.py"), "status", "--root", str(self.root)],
                                    capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("Another installer", result.stderr)

    def test_unrelated_install_directory_unchanged(self):
        self.root.mkdir()
        (self.root / "project.txt").write_text("preserve")
        before = product.snapshot(self.root)
        with self.assertRaisesRegex(product.InstallError, "unrelated"):
            with product.locked(self.root, self.bin):
                pass
        self.assertEqual(product.snapshot(self.root), before)

    def test_launcher_publication_failure_retry(self):
        original = product.launcher
        with patch.object(product, "publish_launchers", side_effect=OSError("disk full")), self.assertRaises(OSError):
            self.install()
        self.assertIsNone(self.state()["active"])
        self.assertFalse((self.bin / "ptw").exists())
        state = self.install()
        self.assertIsNotNone(state["active"])
        self.assertEqual((self.bin / "ptw").read_bytes(), original(self.root, "ptw"))

    def test_rollback_write_failure_keeps_selection(self):
        self.install()
        upgraded = self.install("0.5.1")
        with product.locked(self.root, self.bin) as state:
            with patch.object(product, "atomic", side_effect=OSError("disk full")), self.assertRaises(OSError):
                product.rollback(self.root, state)
            self.assertEqual(state["active"], upgraded["active"])
        self.assertEqual(self.state()["active"], upgraded["active"])

    def test_atomic_launcher_no_overwrite_or_partial_file(self):
        target = self.base / "new-command"
        with patch.object(product.os, "link", side_effect=OSError("injected publication failure")), self.assertRaises(OSError):
            product.publish_file(target, b"complete content", 0o755)
        self.assertFalse(target.exists())
        self.assertFalse(list(self.base.glob(".ptw-*.tmp")))
        target.write_text("unrelated")
        with self.assertRaises(FileExistsError):
            product.publish_file(target, b"complete content", 0o755)
        self.assertEqual(target.read_text(), "unrelated")

    def test_main_records_failed_attempt_and_prints_shell_fallback(self):
        path, digest = self.artifact()
        home = self.base / "fixture-home"
        home.mkdir()
        for name in (".profile", ".bash_profile", ".bashrc", ".zprofile", ".zshrc", ".config/fish/config.fish"):
            target = home / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("# operator configuration\n")
        before = product.snapshot(home)
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch.dict(os.environ, {"PATH": "/usr/bin:/bin", "HOME": str(home)}):
            code = product.main(["--artifact", path, "--sha256", digest, "--root", str(self.root), "--bin-dir", str(self.bin)])
        self.assertEqual(code, 0)
        self.assertIn(product.shell_guidance(self.bin), output.getvalue())
        self.assertIn("No shell startup files were edited", output.getvalue())
        self.assertEqual(product.snapshot(home), before)
        with contextlib.redirect_stderr(io.StringIO()):
            code = product.main(["--artifact", path, "--sha256", "0" * 64, "--root", str(self.root)])
        self.assertEqual(code, 2)
        self.assertEqual(self.state()["attempts"][-1]["status"], "failed")

    def terminal_fixture(self):
        self.bin = self.base / "commands ' quote \\\\ $literal $(touch injected) `touch injected` ; [x]"
        self.install()
        home = self.base / "terminal-home"
        home.mkdir()
        env = terminal_environment(home, {**os.environ, "PATH": "/usr/bin:/bin", "SHELL": "/wrong/shell"})
        return home, env, product.shell_guidance(self.bin)

    def check_terminal(self, shell, flags, env):
        executable = shutil.which(shell)
        self.assertIsNotNone(executable, "Validation prerequisite missing: " + shell)
        transcript = terminal_output([executable, flags,
            "command -v ptw; command -v ptw-install; ptw --version && ptw-install status"], env, self.base)
        for expected in (str(self.bin / "ptw"), str(self.bin / "ptw-install"), "0.5.0", self.state()["active"]):
            self.assertIn(expected.encode(), transcript)
        self.assertFalse((self.base / "injected").exists())
        selected = self.state()["releases"][self.state()["active"]]
        product.verify(self.root / "releases" / self.state()["active"], selected["receipt"])

    def test_printed_bash_login_profile_precedence_and_interactive_startup(self):
        home, env, guidance = self.terminal_fixture()
        line = integration_line(guidance, "export PATH=")
        # Each newly created higher-priority file must be the ONLY login file read.
        profiles = (".profile", ".bash_login", ".bash_profile")
        for index, name in enumerate(profiles):
            with self.subTest(profile=name):
                for lower in profiles[:index]:
                    (home / lower).write_text("exit 91\n")
                (home / name).write_text(line)
                self.check_terminal("bash", "-lic", env)
        (home / ".bashrc").write_text(line)
        self.check_terminal("bash", "-ic", env)
        # The integration preserves every inherited PATH entry, including spaces.
        env["PATH"] = "/unrelated tools/bin:/usr/bin:/bin"
        output = terminal_output(["bash", "-ic", 'printf "%s\\n" "$PATH"'], env, self.base)
        self.assertIn((str(self.bin) + ":" + env["PATH"]).encode(), output)

    def test_printed_sh_login_integration(self):
        home, env, guidance = self.terminal_fixture()
        (home / ".profile").write_text(integration_line(guidance, "export PATH="))
        self.check_terminal("sh", "-lic", env)

    def test_printed_zsh_login_interactive_and_zdotdir(self):
        self.assertIsNotNone(shutil.which("zsh"), "Validation prerequisite missing: zsh")
        home, env, guidance = self.terminal_fixture()
        line = integration_line(guidance, "export PATH=")
        (home / ".profile").write_text("exit 91\n")
        for custom in (False, True):
            with self.subTest(custom_zdotdir=custom):
                directory = home
                if custom:
                    directory = home / "custom dotfiles"
                    directory.mkdir()
                    env["ZDOTDIR"] = str(directory)
                    for name in (".zprofile", ".zshrc"):
                        (home / name).write_text("exit 92\n")
                (directory / ".zprofile").write_text(line)
                self.check_terminal("zsh", "-lic", env)
                (directory / ".zshrc").write_text(line)
                self.check_terminal("zsh", "-ic", env)
        env["PATH"] = "/unrelated tools/bin:/usr/bin:/bin"
        output = terminal_output(["zsh", "-ic", 'printf "%s\\n" "$PATH"'], env, self.base)
        self.assertIn((str(self.bin) + ":" + env["PATH"]).encode(), output)

    def test_printed_fish_persists_once_without_changing_other_paths(self):
        home, env, guidance = self.terminal_fixture()
        executable = shutil.which("fish")
        self.assertIsNotNone(executable, "Validation prerequisite missing: fish")
        line = integration_line(guidance, "fish_add_path ")
        env["PATH"] = "/unrelated tools/bin:/usr/bin:/bin"
        terminal_output([executable, "-ic", line], env, self.base)
        self.check_terminal("fish", "-ic", env)
        # Retry must not duplicate the persistent path or lose unrelated entries.
        # fish_add_path returns 1 when nothing needs adding (fish 4.0.2 source).
        terminal_output([executable, "-ic", line], env, self.base, expected=1)
        output = terminal_output([executable, "-ic", 'printf "%s\\n" $PATH'], env, self.base)
        paths = output.decode().splitlines()
        self.assertEqual(paths.count(str(self.bin)), 1)
        self.assertTrue(all(p in paths for p in env["PATH"].split(":")))
        # Also exercise the printed config-file alternative for a global setting.
        (home / ".config/fish/config.fish").write_text("set -g fish_user_paths /unrelated/global\n" + line)
        self.check_terminal("fish", "-ic", env)
        output = terminal_output([executable, "-ic", 'printf "%s\\n" $PATH'], env, self.base)
        self.assertIn(b"/unrelated/global", output)

    def test_normal_user_bin_discovery_with_distribution_profile(self):
        # The declared Debian/Ubuntu profile discovers ~/.local/bin by itself.
        # Copy the OS template unchanged; do not add an export to make this pass.
        profile = Path("/etc/skel/.profile")
        self.assertTrue(profile.is_file(), "Validation requires the distribution's default login profile")
        home = self.base / "normal-home"
        home.mkdir()
        (home / ".profile").write_bytes(profile.read_bytes())
        self.bin = home / ".local/bin"
        self.install()
        env = terminal_environment(home, {**os.environ, "PATH": "/usr/bin:/bin"})
        self.check_terminal("bash", "-lic", env)
        self.assertEqual((home / ".profile").read_bytes(), profile.read_bytes())

    def test_terminal_timeout_and_failure_are_not_passes(self):
        home = self.base / "timeout-home"
        home.mkdir()
        env = terminal_environment(home, os.environ)
        with self.assertRaisesRegex(product.InstallError, "command failed"):
            terminal_output(["bash", "-ic", "exit 19"], env, self.base)
        with self.assertRaises(subprocess.TimeoutExpired):
            terminal_output(["bash", "-ic", "echo $$ > shell.pid; exec sleep 30"], env, self.base, timeout=.5)
        pid = int((self.base / "shell.pid").read_text())
        self.assertFalse(Path("/proc", str(pid)).exists(), "Timed-out fixture process survived")

    def test_invalid_receipt_and_traversal_refused(self):
        self.install()
        state = self.state()
        state["releases"][state["active"]]["receipt"]["../../outside"] = {"sha256": "0" * 64}
        product.atomic(self.root / "state.json", state)
        with self.assertRaisesRegex(product.InstallError, "Unsafe path"):
            with product.locked(self.root, self.bin):
                pass

    def test_terminal_launchers_spaces_metacharacters_and_fresh_shell(self):
        self.root = self.base / "owned space $literal ' quote"
        self.install()
        env = {**os.environ, "PATH": str(self.bin) + ":/usr/bin:/bin", "PYTHONPATH": "/unrelated/source"}
        captured = terminal_output(["bash", "--noprofile", "--norc", "-ic", "ptw --version && ptw-install status"],
                                   env, self.base)
        self.assertIn(b"0.5.0", captured)
        self.assertIn(b'"active"', captured)

    def test_launcher_preserves_operator_state_but_not_runtime_overrides(self):
        state = self.install()
        candidate = self.root / "releases" / state["active"]
        # This executable fixture observes only named synthetic environment fields.
        (candidate / "venv/bin/ptw").write_text("#!" + sys.executable + "\nimport os,json\nprint(json.dumps({k:os.environ.get(k) for k in ['PTW_USER_STATE','PTW_NONO','PTW_FAKE','PYTHONPATH']}))\n")
        expected = str(self.base / "operator-state")
        run = subprocess.run([self.bin / "ptw"], capture_output=True, text=True,
            env={**os.environ, "PTW_USER_STATE": expected, "PTW_NONO": "/bad/tool", "PTW_FAKE": "bad", "PYTHONPATH": "/bad/source"})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout), {"PTW_USER_STATE": expected,
            "PTW_NONO": str(candidate / "bin/nono"), "PTW_FAKE": None, "PYTHONPATH": None})

    def test_bootstrap_help_and_missing_integrity_in_terminal(self):
        entry = self.base / "install.sh"
        entry.write_bytes(builder.bootstrap((SCRIPTS / "product_install.py").read_bytes(), "0" * 64, "https://example.org/v1/app.tgz"))
        result = subprocess.run(["sh", str(entry), "--help"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("rollback", result.stdout)
        result = subprocess.run([sys.executable, "-I", str(SCRIPTS / "product_install.py")], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("trusted --sha256", result.stderr)

    def test_legacy_cli_and_existing_directory_unchanged(self):
        legacy = SCRIPTS / "install-vps.sh"
        for arguments, expected in (([], "Usage:"), (["--no-codex", str(self.base)], "already exists"),
                                     (["relative"], "absolute")):
            result = subprocess.run(["bash", str(legacy), *arguments], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn(expected, result.stderr)
        self.assertEqual(list(self.base.iterdir()), [])


class ArchiveTests(unittest.TestCase):
    def test_nested_wheel_rejects_traversal_symlink_and_size_bomb(self):
        for name, mode in (("ptw/../bad.py", 0o100644), ("ptw/link.py", 0o120777)):
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                item = zipfile.ZipInfo(name)
                item.external_attr = mode << 16
                archive.writestr(item, b"payload")
            with self.assertRaises(product.InstallError):
                product.validate_wheel(buffer.getvalue(), "0.5.0")
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("ptw/large.py", b"payload")
        with patch.object(product, "MAX_ARCHIVE", 1), self.assertRaises(product.InstallError):
            product.validate_wheel(buffer.getvalue(), "0.5.0")
    def test_deterministic_compact_source_manifest(self):
        first, second = release_fixture(), release_fixture()
        self.assertEqual(first, second)
        manifest, files = product.release_files(first)
        self.assertLess(len(first), 500_000)
        self.assertTrue(manifest["source_sha256"])
        self.assertFalse(any("validation" in name or "experiments" in name for name in manifest["source_sha256"]))
        self.assertEqual(len(files), 8)

    def test_builder_rejects_linked_source_and_inconsistent_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, sources = builder.source_files(builder.REPO)
            for name, data in sources.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            init = root / "harness/ptw/__init__.py"
            init.write_text('__version__ = "9.9.9"')
            with self.assertRaisesRegex(product.InstallError, "version mismatch"):
                builder.source_files(root)
            init.unlink()
            init.symlink_to(builder.REPO / "harness/ptw/__init__.py")
            with self.assertRaisesRegex(product.InstallError, "Symlink"):
                builder.source_files(root)

    def test_rejects_unsafe_archive_members_before_writes(self):
        for name, kind in [("../outside", tarfile.REGTYPE), ("/absolute", tarfile.REGTYPE),
                           ("a/../b", tarfile.REGTYPE), ("a\\b", tarfile.REGTYPE),
                           ("link", tarfile.SYMTYPE), ("hard", tarfile.LNKTYPE),
                           ("fifo", tarfile.FIFOTYPE), ("dir", tarfile.DIRTYPE)]:
            with self.subTest(name=name, kind=kind):
                buffer = io.BytesIO()
                with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    member.linkname = "../../outside"
                    archive.addfile(member)
                with self.assertRaises(product.InstallError):
                    product.archive_files(buffer.getvalue())

    def test_duplicate_conflicting_paths_manifest_and_limits(self):
        for names in (("same", "same"), ("parent", "parent/child")):
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
                for name in names:
                    member = tarfile.TarInfo(name)
                    archive.addfile(member)
            with self.assertRaises(product.InstallError):
                product.archive_files(buffer.getvalue())
        with patch.object(product, "MAX_EXPANDED", 1), self.assertRaises(product.InstallError):
            product.archive_files(release_fixture())
        with self.assertRaises(product.InstallError):
            product.release_files(builder.deterministic_tar({"release.json": b'{"format":1,"version":"0.5.0","files":{}}', "surprise": b"x"}))

    def test_npm_strong_integrity_versions_sources_and_platform_required(self):
        package, original = npm_fixture()
        product.validate_npm(package, original)
        for mutation in ("missing", "hash", "source", "version", "script"):
            lock = json.loads(json.dumps(original))
            entry = lock["packages"]["node_modules/@openai/codex-linux-x64"]
            if mutation == "missing":
                del lock["packages"]["node_modules/@openai/codex-linux-x64"]
            if mutation == "hash": entry["integrity"] = "sha1-weak"
            if mutation == "source": entry["resolved"] = "https://evil.invalid/payload.tgz"
            if mutation == "version": entry["version"] = "9.9.9"
            if mutation == "script": entry["hasInstallScript"] = True
            with self.subTest(mutation=mutation), self.assertRaises(product.InstallError):
                product.validate_npm(package, lock)


class HealthTests(unittest.TestCase):
    def test_real_python_imports_and_service_commands_preserve_receipt(self):
        """Real private Python/source copy; service dispatch is captured, not native evidence."""
        from ptw import mcp_server, monitor, supervisor, terminal
        from ptw.policy import approve, compile_policy, digest, load
        from ptw.sample import create
        from ptw.store import Store

        with tempfile.TemporaryDirectory(prefix="ptw-bytecode-") as temporary:
            base = Path(temporary)
            candidate = base / "installed"
            venv.EnvBuilder(with_pip=False, system_site_packages=True).create(candidate / "venv")
            python = candidate / "venv/bin/python"
            env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
            site = Path(product.run([python, "-I", "-B", "-c",
                                     "import sysconfig; print(sysconfig.get_path('purelib'))"], env=env, cwd=base))
            # The runner may itself be a venv. Reuse only its dependency search
            # directory in this fixture; the real artifact acceptance installs locks.
            (site / "test-dependencies.pth").write_text(sysconfig.get_path("purelib") + "\n")
            package = site / "ptw"
            package.mkdir()
            for source in (builder.REPO / "harness/ptw").glob("*.py"):
                shutil.copyfile(source, package / source.name)
            receipt = product.snapshot(candidate)
            imported = json.loads(product.run(source_identity_command(candidate), env=env, cwd=base))
            self.assertEqual(Path(imported["path"]), package)
            self.assertEqual(imported["hashes"], {p.name: product.sha(p.read_bytes()) for p in package.glob("*.py")})
            product.verify(candidate, receipt)

            create(base / "project")
            policy, inv = load(base / "project/policy.json"), load(base / "project/inventory.json")
            store = Store(base / "controller")
            store.activate(approve(policy, inv, digest(compile_policy(policy, inv)), "bytecode fixture"))
            actor = store.register("website", "frontend")
            with patch.object(supervisor.sys, "executable", str(python)), \
                    patch.object(supervisor, "sandbox_command"), \
                    patch.object(supervisor, "run", return_value=subprocess.CompletedProcess([], 0)) as dispatch:
                supervisor.Supervisor(store).launch(actor["token"], ["/usr/bin/true"])
                unit = monitor.service_text(store.directory)
            argv = dispatch.call_args.args[0]
            worker = argv[argv.index("--") + 1:]
            # Execute real worker imports, then fail on deliberately invalid config.
            worker[worker.index("ptw.worker") + 1] = "invalid-json"
            result = subprocess.run(worker, env=env, cwd=base, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("JSONDecodeError", result.stderr)
            product.verify(candidate, receipt)
            monitor_argv = shlex.split(next(line.removeprefix("ExecStart=") for line in unit.splitlines()
                                          if line.startswith("ExecStart=")))
            result = subprocess.run([*monitor_argv, "--help"], env=env, cwd=base, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            product.verify(candidate, receipt)

            # Both the Codex-launched relay and its systemd broker filter env.
            # Capture their actual argv without login, model or service calls.
            session = base / "session.json"
            session.write_text(json.dumps({"token": "synthetic-fixture-token"}))
            with patch.object(supervisor.sys, "executable", str(python)), \
                    patch.object(supervisor.Supervisor, "engine", side_effect=RuntimeError("captured")) as engine:
                with self.assertRaisesRegex(RuntimeError, "captured"):
                    mcp_server.bridge(store.directory, session)
            broker = engine.call_args.args[1]
            broker = broker[broker.index(str(python)):]
            catalog = base / "empty-codex-config"
            catalog.mkdir()
            (catalog / "models_cache.json").write_text(json.dumps({"models": [{"slug": "gpt-5.6-sol"}]}))
            with patch.dict(os.environ, {"CODEX_HOME": str(catalog)}), \
                    patch.object(terminal.sys, "executable", str(python)), patch.object(terminal, "require_login"), \
                    patch.object(terminal.shutil, "which", side_effect=lambda name: "/fixture/" + name), \
                    patch.object(terminal.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "codex-cli 0.154.0")):
                codex = terminal.codex_command(store, session, base / "control")
            relay = json.loads(next(arg.split("=", 1)[1] for arg in codex if arg.startswith("mcp_servers.ptw.args=")))
            for command in (broker, [str(python), *relay]):
                result = subprocess.run([*command, "--help"], env=env, cwd=base, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                product.verify(candidate, receipt)
            self.assertFalse(list(package.rglob("*.pyc")))
            # Unexpected bytecode is still rejected, not excluded from integrity.
            (package / "unexpected.pyc").write_bytes(b"unowned bytecode")
            with self.assertRaisesRegex(product.InstallError, "Unexpected installed files"):
                product.verify(candidate, receipt)

    def test_old_monitor_unit_can_be_removed_but_modified_unit_cannot(self):
        from ptw import monitor
        from ptw.policy import Invalid
        from ptw.store import Store

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            store = Store(base / "controller")
            units = base / "systemd/user"
            units.mkdir(parents=True)
            unit = units / monitor.unit_for(store.directory)
            with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(base)}), patch.object(monitor, "call") as call:
                unit.write_text(monitor.service_text(store.directory, legacy=True) + "# unowned modification\n")
                with self.assertRaises(Invalid):
                    monitor.remove(store)
                call.assert_not_called()
                unit.write_text(monitor.service_text(store.directory, legacy=True))
                self.assertTrue(monitor.remove(store)["state_and_history_retained"])
                self.assertFalse(unit.exists())
                self.assertTrue(store.db.exists())

    def test_python_and_npm_failures_cannot_execute_candidate(self):
        data = release_fixture()
        manifest, files = product.release_files(data)
        binary = builder.deterministic_tar({"bin/uv": b"verified fixture uv", "bin/nono": b"verified fixture nono"})
        for failure in ("python", "npm", "missing-platform"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                candidate = Path(temporary)
                commands = []

                def execute(command, **kwargs):
                    command = [str(x) for x in command]
                    commands.append((command, kwargs))
                    if "--version" in command:
                        return "uv 0.12.15" if command[0].endswith("/uv") else "nono 0.77.0"
                    if (failure == "python" and "--require-hashes" in command) or (failure == "npm" and command[0] == "npm"):
                        raise product.InstallError("injected dependency failure")
                    return ""

                with patch.object(product, "download", return_value=binary), patch.object(product, "run", side_effect=execute), self.assertRaises(product.InstallError):
                    product.prepare(candidate, files, manifest)
                self.assertFalse(any("doctor" in cmd for cmd, _ in commands))
                venv, environment = next((cmd, kwargs) for cmd, kwargs in commands if "venv" in cmd)
                self.assertIn(sys.executable, venv)
                self.assertNotIn("3.12", venv)
                self.assertEqual(environment["env"]["UV_PYTHON_DOWNLOADS"], "never")
                self.assertTrue(any("--only-binary" in cmd for cmd, _ in commands))
                if failure != "python":
                    npm = next(cmd for cmd, _ in commands if cmd[0] == "npm")
                    self.assertIn("ci", npm)
                    self.assertIn("--ignore-scripts", npm)

    def test_corrupt_native_download_never_executes(self):
        manifest, files = product.release_files(release_fixture())
        with tempfile.TemporaryDirectory() as temporary, patch.object(product, "download", side_effect=product.InstallError("SHA-256 mismatch")), patch.object(product, "run") as run:
            with self.assertRaises(product.InstallError):
                product.prepare(Path(temporary), files, manifest)
            run.assert_not_called()

    def test_python_version_prerequisite_and_success_without_312(self):
        with patch.object(product.os, "geteuid", return_value=1000), patch.object(product.sys, "version_info", (3, 10)), self.assertRaisesRegex(product.InstallError, "Python"):
            product.preflight()
        with patch.object(product.os, "geteuid", return_value=1000), patch.object(product.sys, "version_info", (3, 11)), patch.object(product.shutil, "which", return_value="/provided/tool"), patch.object(product, "run", side_effect=["v22.0.0", "10.0.0", "bubblewrap 0.12.0", ""]):
            product.preflight()

    def test_health_requires_success_versions_and_all_doctor_probes(self):
        outputs = ["uv 0.12.15", "nono 0.77.0", "codex-cli 0.154.0", "0.5.0", json.dumps(READY)]
        with patch.object(product, "run", side_effect=outputs):
            self.assertTrue(product.health(Path("/fixture"), "0.5.0")["ready"])
        for index, bad in [(0, "uv 9.9.9"), (2, ""), (3, "0.5.01"), (4, "not json"),
                           (4, '{"ready":true,"checks":{}}')]:
            values = list(outputs)
            values[index] = bad
            with patch.object(product, "run", side_effect=values), self.assertRaises((product.InstallError, ValueError)):
                product.health(Path("/fixture"), "0.5.0")

    def test_process_failures_nonexecutable_and_timeout(self):
        with self.assertRaises(product.InstallError):
            product.run([sys.executable, "-c", "raise SystemExit(3)"])
        with self.assertRaises(product.InstallError):
            product.run([sys.executable, "-c", "import time; time.sleep(10)"], timeout=.01)
        with self.assertRaises(product.InstallError):
            product.run(["/does-not-exist"])
        with tempfile.NamedTemporaryFile() as file, self.assertRaises(product.InstallError):
            product.run([file.name])

    def test_platform_missing_prerequisites_and_no_python_downloads(self):
        with patch.object(product.platform, "system", return_value="Darwin"), self.assertRaisesRegex(product.InstallError, "Linux"):
            product.preflight()
        with patch.object(product.os, "geteuid", return_value=1000), patch.object(product.shutil, "which", return_value=None), self.assertRaisesRegex(product.InstallError, "Missing prerequisite"):
            product.preflight()
        with patch.dict(os.environ, {"UV_PYTHON_DOWNLOADS": "automatic", "PYTHONPATH": "/bad", "NPM_CONFIG_REGISTRY": "https://bad", "NODE_OPTIONS": "--require=bad"}):
            env = product.clean_env(Path("/private"))
        self.assertEqual(env["UV_PYTHON_DOWNLOADS"], "never")
        self.assertNotIn("PYTHONPATH", env)
        self.assertNotIn("NPM_CONFIG_REGISTRY", env)
        self.assertEqual(env["NODE_OPTIONS"], "")
        self.assertEqual(env["NETRC"], "/dev/null")
        self.assertEqual(env["UV_CREDENTIALS_DIR"], "/private/empty-uv-credentials")
        self.assertEqual(env["UV_KEYRING_PROVIDER"], "disabled")

    def test_monitor_guard_and_unrelated_process(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            unit = base / "systemd/user/ptw-monitor-fixture.service"
            unit.parent.mkdir(parents=True)
            unit.write_text("ExecStart=/owned/releases/old/venv/bin/python -m ptw.monitor")
            with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(base)}):
                with self.assertRaisesRegex(product.InstallError, "monitor"):
                    product.in_use(Path("/owned"))
                process = subprocess.Popen(["sleep", "10"])
                try:
                    product.in_use(base / "unrelated-install")
                    self.assertIsNone(process.poll())
                finally:
                    process.terminate()
                    process.wait()


class DownloadTests(unittest.TestCase):
    def test_deadline_interrupts_blocked_read_and_restores_signal_state(self):
        class Response(io.BytesIO):
            headers = {}

            def read(self, size):
                time.sleep(2)
                return b""

        response = Response()
        previous = signal.getsignal(signal.SIGALRM)
        started = time.monotonic()
        with patch.object(product.urllib.request.OpenerDirector, "open", return_value=response), \
                self.assertRaisesRegex(product.InstallError, "time limit"):
            product.download("https://example.com/artifact", "0" * 64, timeout=.05, attempts=1)
        self.assertLess(time.monotonic() - started, .8)
        self.assertTrue(response.closed)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0, 0))
        self.assertEqual(signal.getsignal(signal.SIGALRM), previous)

    def test_slow_drip_cannot_extend_wall_clock_deadline(self):
        """Actual loopback reads stay active below the socket inactivity timeout."""
        requests = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                requests.append(self.path)
                self.send_response(200)
                self.send_header("Content-Length", "100")
                self.end_headers()
                try:
                    for _ in range(100):
                        self.wfile.write(b"x")
                        self.wfile.flush()
                        time.sleep(.02)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            started = time.monotonic()
            with self.assertRaisesRegex(product.InstallError, "time limit"):
                product.download(f"http://127.0.0.1:{server.server_port}/drip", product.sha(b"x" * 100),
                                 loopback=True, timeout=.2, attempts=2)
            self.assertLess(time.monotonic() - started, 1.2)
            self.assertEqual(requests, ["/drip", "/drip"])
            self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0, 0))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_redirect_validation_and_download_bounds_without_socket(self):
        handler = product.Redirects(False)
        with self.assertRaises(product.InstallError):
            handler.redirect_request(None, None, 302, "", {}, "http://example.com/bad")
        with tempfile.NamedTemporaryFile() as stream:
            stream.write(b"too large")
            stream.flush()
            with patch.object(product, "MAX_ARCHIVE", 2), self.assertRaisesRegex(product.InstallError, "size limit"):
                product.download(stream.name, product.sha(b"too large"))

    def test_interrupted_stream_is_bounded_and_retried_without_execution(self):
        class Response(io.BytesIO):
            headers = {"Content-Length": "100"}
        class Opener:
            calls = 0
            def open(self, *args, **kwargs):
                self.calls += 1
                return Response(b"partial")
        opener = Opener()
        with patch.object(product.urllib.request, "build_opener", return_value=opener), self.assertRaisesRegex(product.InstallError, "Interrupted"):
            product.download("https://example.com/artifact", "0" * 64)
        self.assertEqual(opener.calls, 2)

    def test_local_hash_mismatch_never_reaches_archive(self):
        with tempfile.NamedTemporaryFile() as stream:
            stream.write(b"not executable")
            stream.flush()
            self.assertEqual(product.download(stream.name, product.sha(b"not executable")), b"not executable")
            with self.assertRaisesRegex(product.InstallError, "SHA-256 mismatch"):
                product.download(stream.name, "0" * 64)
        for url in ("http://example.com/file", "file:///tmp/file", "https://user:secret@example.com/file"):
            with self.assertRaises(product.InstallError):
                product.valid_url(url)

    def test_actual_loopback_download_errors_truncation_redirect_and_timeout(self):
        """Must run on manager host if sandbox denies bind; no skip or mock pass."""
        body = b"verified local artifact"
        counters = {}

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                counters[self.path] = counters.get(self.path, 0) + 1
                if self.path == "/error":
                    self.send_error(503)
                    return
                if self.path.startswith("/redirect"):
                    self.send_response(302)
                    self.send_header("Location", "/ok" if self.path == "/redirect" else "http://example.com/bad")
                    self.end_headers()
                    return
                if self.path == "/timeout":
                    time.sleep(.15)
                self.send_response(200)
                self.send_header("Content-Length", str(len(body) + (100 if self.path == "/truncated" else 0)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = "http://127.0.0.1:" + str(server.server_port)
            for endpoint in ("/ok", "/redirect"):
                self.assertEqual(product.download(base + endpoint, product.sha(body), loopback=True), body)
            for endpoint in ("/error", "/truncated", "/redirect-external", "/timeout"):
                with self.subTest(endpoint=endpoint), self.assertRaises(product.InstallError):
                    product.download(base + endpoint, product.sha(body), loopback=True, timeout=.05)
            self.assertEqual(counters["/error"], 2)
            with self.assertRaises(product.InstallError):
                product.download(base + "/ok", "0" * 64, loopback=True)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
