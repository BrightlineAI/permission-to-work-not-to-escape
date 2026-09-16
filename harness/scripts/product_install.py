#!/usr/bin/env python3
"""Standalone release installer. Only the standard library runs before verification."""
import argparse
import contextlib
import fcntl
import hashlib
import http.client
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import signal
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
import uuid
import zipfile

PINS = {
    "uv": ("0.12.15", "https://github.com/astral-sh/uv/releases/download/0.12.15/uv-x86_64-unknown-linux-gnu.tar.gz",
           "f97935763c04be3e692460a7aaeaaab8fc3b78fcf8b389da820b38ae7423a638"),
    "nono": ("0.77.0", "https://github.com/nolabs-ai/nono/releases/download/v0.77.0/nono-v0.77.0-x86_64-unknown-linux-gnu.tar.gz",
             "86bcf7a134d6f47e064ad0f2561f1be02b9fffc643708c3ec2dd4070e82b798e"),
}
CODEX = "0.154.0"
CODEX_PLATFORMS = ("linux-x64", "linux-arm64", "darwin-x64", "darwin-arm64", "win32-x64", "win32-arm64")
MAX_ARCHIVE = 256 * 1024 * 1024
MAX_EXPANDED = 768 * 1024 * 1024
OWNER = "permission-to-work-product-install-v1"
BOOTSTRAP_DIGEST = None  # Replaced only in a built version-specific bootstrap.
BOOTSTRAP_URL = None


class InstallError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise InstallError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def relative(name):
    require(isinstance(name, str) and name and "\\" not in name and
            not any(ord(c) < 32 for c in name), "Invalid relative path")
    path = PurePosixPath(name)
    require(not path.is_absolute() and all(x not in ("", ".", "..") for x in name.split("/")),
            "Unsafe path: " + name)
    return path


def safe_path(path):
    path = Path(os.path.abspath(path))
    for ancestor in [*reversed(path.parents), path]:
        require(not ancestor.is_symlink(), "Symlink destination: " + str(ancestor))
    return path


def atomic(path, value):
    safe_path(path)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex)
    with open(temporary, "x") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def valid_url(url, loopback=False):
    parsed = urllib.parse.urlsplit(url)
    require(not parsed.username and not parsed.password and not parsed.fragment,
            "URLs must not include credentials or fragments")
    require(parsed.scheme == "https" or
            (loopback and parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "::1")),
            "HTTPS required (explicit test mode permits literal loopback HTTP)")


class Redirects(urllib.request.HTTPRedirectHandler):
    max_redirections = 3
    max_repeats = 1

    def __init__(self, loopback):
        self.loopback = loopback

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        valid_url(newurl, self.loopback)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@contextlib.contextmanager
def download_deadline(seconds):
    """Linux CLI main-thread deadline, including DNS, headers and blocked reads.

    A socket timeout only bounds inactivity: a slow peer can otherwise keep a
    buffered read alive indefinitely. Raising from SIGALRM cancels that read.
    Do not take over a timer owned by an embedding caller.
    """
    require(seconds > 0, "Download timeout must be positive")
    require(signal.getitimer(signal.ITIMER_REAL) == (0, 0), "Download requires an unused real-time timer")

    def expired(signum, frame):
        raise InstallError("Download time limit exceeded")

    previous = signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, seconds)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def download(source, expected, *, loopback=False, timeout=30, attempts=2):
    require(isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected), "Expected SHA-256 is required")
    errors = []
    for attempt in range(attempts):
        try:
            with download_deadline(timeout):
                if "://" in source:
                    valid_url(source, loopback)
                    # No user proxy configuration or credential-bearing handlers.
                    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirects(loopback))
                    stream = opener.open(source, timeout=timeout)
                else:
                    path = safe_path(source)
                    require(path.is_file(), "Artifact must be a regular file")
                    stream = open(path, "rb")
                with stream:
                    length = stream.headers.get("Content-Length") if hasattr(stream, "headers") else None
                    if length is not None:
                        require(0 <= int(length) <= MAX_ARCHIVE, "Download size limit exceeded")
                    data = bytearray()
                    while True:
                        chunk = stream.read(65536)
                        if not chunk:
                            break
                        data.extend(chunk)
                        require(len(data) <= MAX_ARCHIVE, "Download size limit exceeded")
                    require(length is None or len(data) == int(length), "Interrupted download")
                    require(sha(data) == expected, "SHA-256 mismatch")
                    return bytes(data)
        except (OSError, ValueError, InstallError, http.client.HTTPException) as exc:
            errors.append(type(exc).__name__ + ": " + str(exc))
            print(f"Download attempt {attempt + 1}/{attempts} failed: {errors[-1]}", file=sys.stderr, flush=True)
    raise InstallError("Download failed; retry is safe. " + "; ".join(errors))


def archive_files(data, *, directories=False):
    """Validate ALL members before returning bytes; never use extract/extractall."""
    result, seen, total = {}, set(), 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive:
            name = member.name.rstrip("/") if member.isdir() else member.name
            relative(name)
            require(name not in seen and len(seen) < 10000, "Duplicate member or member limit")
            seen.add(name)
            require(member.isfile() or (directories and member.isdir()), "Archive links/special files are forbidden")
            require(not member.sparse and not member.pax_headers, "Unsupported archive extensions")
            total += member.size
            require(0 <= member.size <= MAX_ARCHIVE and total <= MAX_EXPANDED, "Expanded size limit exceeded")
            if member.isfile():
                result[name] = archive.extractfile(member).read()
        for name in seen:
            require(not any(str(p) in result for p in PurePosixPath(name).parents if str(p) != "."),
                    "Conflicting archive paths")
    return result


def release_files(data):
    files = archive_files(data)
    require("release.json" in files, "Missing release manifest")
    manifest = json.loads(files.pop("release.json"))
    require(manifest.get("format") == 1 and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", manifest.get("version", "")),
            "Invalid release version/format")
    require(manifest.get("files") == {name: sha(value) for name, value in files.items()}, "Release file manifest mismatch")
    wheel = f"permission_to_work_harness-{manifest['version']}-py3-none-any.whl"
    require(set(files) == {wheel, "requirements.lock", "package.json", "package-lock.json",
                           "product_install.py", "INSTALL.md", "LICENSE", "THIRD_PARTY_NOTICES.md"},
            "Unexpected application artifact contents")
    validate_wheel(files[wheel], manifest["version"])
    return manifest, files


def validate_wheel(data, version):
    total, names = 0, set()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for item in archive.infolist():
            relative(item.filename)
            require(item.filename not in names and len(names) < 1000, "Duplicate wheel member or limit")
            names.add(item.filename)
            require(item.filename.startswith(("ptw/", f"permission_to_work_harness-{version}.dist-info/")),
                    "Unexpected wheel path")
            kind = stat.S_IFMT(item.external_attr >> 16)
            require(kind in (0, stat.S_IFREG) and not item.is_dir(), "Wheel links/special files forbidden")
            total += item.file_size
            require(total <= MAX_ARCHIVE, "Wheel expansion limit")
            archive.read(item)  # CRC validation before handing the wheel to uv.
        require(not any(str(parent) in names for name in names for parent in PurePosixPath(name).parents),
                "Conflicting wheel paths")


def clean_env(directory):
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith(
        ("PYTHON", "UV_", "PIP_", "NPM_", "NODE_", "PTW_", "CODEX_"))}
    env.update(UV_PYTHON_DOWNLOADS="never", UV_CACHE_DIR=str(directory / "cache"),
               UV_NO_CONFIG="1", PYTHONDONTWRITEBYTECODE="1", TMPDIR=str(directory),
               NETRC="/dev/null", UV_CREDENTIALS_DIR=str(directory / "empty-uv-credentials"),
               UV_KEYRING_PROVIDER="disabled",
               NPM_CONFIG_USERCONFIG=str(directory / "empty.npmrc"),
               NPM_CONFIG_GLOBALCONFIG=str(directory / "empty-global.npmrc"),
               NPM_CONFIG_CACHE=str(directory / "npm-cache"), NODE_OPTIONS="")
    return env


def run(command, *, env=None, cwd=None, timeout=60):
    try:
        result = subprocess.run([str(x) for x in command], env=env, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InstallError(f"Command could not complete: {command[0]} ({type(exc).__name__})") from exc
    # Dependency output is not copied to public diagnostics (may include local configuration).
    require(result.returncode == 0, f"Command failed ({result.returncode}): {command[0]}")
    return result.stdout.strip()


def preflight():
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "Supported platform: Linux x86_64")
    require(os.geteuid() != 0, "Use an ordinary account, not root; installer never invokes sudo")
    require((3, 11) <= sys.version_info[:2] <= (3, 13), "Provide Python 3.11 to 3.13 on PATH; Python downloads are disabled")
    for name in ("node", "npm", "bwrap", "systemctl", "systemd-run"):
        require(shutil.which(name), "Missing prerequisite: " + name + "; ask your administrator, then retry")
    with tempfile.TemporaryDirectory(prefix="ptw-preflight-") as temporary:
        env = clean_env(Path(temporary))
        require(run(["node", "--version"], env=env).startswith("v22."), "Provide Node 22 and npm on PATH")
        run(["npm", "--version"], env=env, cwd=temporary)
        run(["bwrap", "--version"], env=env)
        run(["systemctl", "--user", "show-environment"], env=env)


def validate_npm(package, lock):
    require(package == {"name": "ptw-private-codex", "version": "1.0.0", "private": True,
                        "dependencies": {"@openai/codex": CODEX}}, "Unexpected Codex package specification")
    require(lock.get("lockfileVersion") == 3, "Expected npm lockfile version 3")
    packages = lock.get("packages", {})
    expected = {"", "node_modules/@openai/codex"} | {"node_modules/@openai/codex-" + p for p in CODEX_PLATFORMS}
    require(set(packages) == expected, "Unexpected Codex lock packages")
    require(packages[""].get("dependencies") == package["dependencies"], "Codex root lock mismatch")
    for name in expected - {""}:
        item = packages[name]
        version = CODEX if name.endswith("/codex") else CODEX + "-" + name.removeprefix("node_modules/@openai/codex-")
        require(item.get("version") == version, "Codex lock version mismatch")
        require(item.get("resolved") == "https://registry.npmjs.org/@openai/codex/-/codex-" + version + ".tgz",
                "Unexpected Codex registry source")
        require(re.fullmatch(r"sha512-[A-Za-z0-9+/]{86}==", item.get("integrity", "")), "Strong npm integrity required")
        require(not item.get("hasInstallScript"), "Unexpected Codex lifecycle script")
    require(packages["node_modules/@openai/codex"].get("optionalDependencies") == {
        "@openai/codex-" + p: "npm:@openai/codex@" + CODEX + "-" + p for p in CODEX_PLATFORMS},
        "Unexpected Codex optional dependency identities")


def prepare(candidate, files, manifest):
    payload = candidate / "payload"
    payload.mkdir()
    for name, value in files.items():
        (payload / name).write_bytes(value)
    (candidate / "bin").mkdir()
    for name, (_, url, expected) in PINS.items():
        contents = archive_files(download(url, expected), directories=True)
        matches = [value for path, value in contents.items() if PurePosixPath(path).name == name]
        require(len(matches) == 1, "Unexpected " + name + " archive layout")
        binary = candidate / "bin" / name
        with open(binary, "xb") as stream:
            stream.write(matches[0])
        binary.chmod(0o755)
    env = clean_env(candidate)
    (candidate / "empty.npmrc").touch()
    (candidate / "empty-global.npmrc").touch()
    for name, (expected, _, _) in PINS.items():
        output = run([candidate / "bin" / name, "--version"], env=env, cwd=candidate, timeout=15)
        require(re.search(r"(?<![\d.])" + re.escape(expected) + r"(?![\d.])", output), "Wrong pinned tool version: " + name)
    uv = candidate / "bin/uv"
    run([uv, "--no-config", "venv", "--no-python-downloads", "--python", sys.executable, candidate / "venv"], env=env)
    python = candidate / "venv/bin/python"
    run([uv, "--no-config", "pip", "install", "--python", python, "--require-hashes", "--only-binary", ":all:",
         "--index-url", "https://pypi.org/simple", "-r", payload / "requirements.lock"], env=env, cwd=payload, timeout=300)
    wheel = payload / f"permission_to_work_harness-{manifest['version']}-py3-none-any.whl"
    run([uv, "--no-config", "pip", "install", "--python", python, "--no-deps", wheel], env=env, cwd=payload)
    package, lock = (json.loads(files[name]) for name in ("package.json", "package-lock.json"))
    validate_npm(package, lock)
    codex = candidate / "codex"
    codex.mkdir()
    for name in ("package.json", "package-lock.json"):
        (codex / name).write_bytes(files[name])
    run(["npm", "ci", "--ignore-scripts", "--include=optional", "--no-audit", "--no-fund", "--registry=https://registry.npmjs.org"],
        env=env, cwd=codex, timeout=300)
    native = codex / "node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex"
    require(native.is_file() and not native.is_symlink(), "Required pinned Codex platform binary missing; no fallback permitted")
    for name in ("cache", "npm-cache"):
        shutil.rmtree(candidate / name, ignore_errors=True)


def candidate_env(candidate):
    env = clean_env(candidate)
    env["PATH"] = ":".join(str(candidate / p) for p in ("venv/bin", "bin", "codex/node_modules/.bin")) + ":" + env.get("PATH", "")
    env["PTW_NONO"] = str(candidate / "bin/nono")
    return env


def health(candidate, version):
    env = candidate_env(candidate)
    commands = [(candidate / "bin" / name, pin[0]) for name, pin in PINS.items()]
    commands += [(candidate / "codex/node_modules/.bin/codex", CODEX), (candidate / "venv/bin/ptw", version)]
    for path, expected in commands:
        output = run([path, "--version"], env=env, cwd=candidate, timeout=15)
        require(re.search(r"(?<![\d.])" + re.escape(expected) + r"(?![\d.])", output), "Wrong executable version: " + str(path))
    report = json.loads(run([candidate / "venv/bin/ptw", "doctor"], env=env, cwd=candidate, timeout=90))
    required = {"permitted_read", "private_read_blocked", "supervised_work_running", "project_stop_confirmed"}
    require(report.get("ready") is True and required <= report.get("checks", {}).keys() and
            all(report["checks"][name] is True for name in required), "Doctor did not establish readiness")
    return report


def snapshot(directory):
    result = {}
    for base, directories, files in os.walk(directory, followlinks=False):
        for name in directories + files:
            path = Path(base) / name
            key = str(path.relative_to(directory))
            if path.is_symlink():
                result[key] = {"link": os.readlink(path)}
            elif path.is_file():
                result[key] = {"sha256": sha(path.read_bytes())}
            elif path.is_dir():
                result[key] = {"directory": True}
            else:
                raise InstallError("Unexpected installed special file")
    return result


def matches(path, entry):
    # Never follow a changed parent, including one replaced with a symlink.
    safe_path(path.parent)
    if set(entry) == {"link"}:
        return path.is_symlink() and os.readlink(path) == entry["link"]
    if path.is_symlink():
        return False
    if set(entry) == {"directory"}:
        return path.is_dir()
    require(set(entry) == {"sha256"} and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]), "Invalid ownership entry")
    return path.is_file() and sha(path.read_bytes()) == entry["sha256"]


def verify(candidate, receipt):
    safe_path(candidate)
    require(candidate.is_dir(), "Installed release is missing")
    for name, entry in receipt.items():
        relative(name)
        require(matches(candidate / name, entry), "Installed file changed: " + name)
    require(set(snapshot(candidate)) == set(receipt), "Unexpected installed files; inspect before retry or rollback")


def in_use(root):
    config = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))) / "systemd/user"
    # Match ptw.monitor.quoted without its enclosing quotes: root is a prefix
    # of the interpreter path. Keep this standalone bootstrap stdlib-only.
    escaped = str(root).replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$")
    needles = (str(root), escaped)
    for unit in config.glob("ptw-monitor-*.service"):
        require(not unit.is_symlink(), "Inspect linked PTW monitor units before changing installation")
        require(not any(needle in unit.read_text() for needle in needles),
                "Installation referenced by a monitor. Stop its projects and run ptw monitor remove before switching/removing releases")
    ancestors = {os.getpid()}
    pid = os.getppid()
    while pid > 1 and pid not in ancestors:
        ancestors.add(pid)
        try:
            pid = int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError):
            break
    # Inspect only executable/argument paths, never process environments or auth.
    # Nothing from process arguments is retained or printed.
    for process in Path("/proc").glob("[0-9]*"):
        if int(process.name) in ancestors:
            continue
        try:
            if process.stat().st_uid != os.geteuid():
                continue
            executable = os.readlink(process / "exe")
            require(not executable.startswith(str(root) + "/"), "An installed executable is still running; quit it and retry")
            arguments = (process / "cmdline").read_bytes().split(b"\0")
            require(not any(arg.startswith(os.fsencode(root) + b"/") for arg in arguments),
                    "Installed work is still running; quit it and retry")
        except (OSError, PermissionError):
            continue


def launcher(root, target):
    # A shell wrapper supports installation paths containing spaces and metacharacters.
    return ("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " -I " +
            shlex.quote(str(root / "launcher.py")) + " " + shlex.quote(target) + ' "$@"\n').encode()


LAUNCHER = '''import json, os, pathlib, re, sys
root = pathlib.Path(__file__).parent
state = json.loads((root / "state.json").read_text())
if not state.get("active"):
    raise SystemExit("No active PTW installation; run the verified release installer")
if state.get("owner") != "permission-to-work-product-install-v1" or not re.fullmatch("[0-9a-f]{32}", state["active"]):
    raise SystemExit("Invalid PTW installation receipt")
release = root / "releases" / state["active"]
env = {k: v for k, v in os.environ.items() if not k.upper().startswith(("PYTHON", "PTW_", "NODE_"))}
env["PYTHONDONTWRITEBYTECODE"] = "1"
env["PATH"] = ":".join(str(release / p) for p in ("venv/bin", "bin", "codex/node_modules/.bin")) + ":" + env.get("PATH", "")
env["PTW_NONO"] = str(release / "bin/nono")
target = sys.argv[1]
if target == "ptw-install":
    command = [sys.executable, "-I", str(release / "payload/product_install.py"), *sys.argv[2:], "--root", str(root)]
else:
    command = [str(release / ("venv/bin/ptw" if target == "ptw" else "codex/node_modules/.bin/codex")), *sys.argv[2:]]
os.execve(command[0], command, env)
'''


@contextlib.contextmanager
def locked(root, bin_dir):
    safe_path(root)
    if not root.exists():
        root.mkdir(parents=True, mode=0o700)
    require(root.stat().st_uid == os.geteuid(), "Installation must be owned by this account")
    require(not (root.stat().st_mode & 0o022), "Installation directory must not be writable by other accounts")
    if not (root / "state.json").exists():
        require(set(p.name for p in root.iterdir()) <= {".lock"}, "Refusing unrelated installation directory")
    fd = os.open(root / ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise InstallError("Another installer is running; retry after it finishes") from exc
        state_path = safe_path(root / "state.json")
        if state_path.exists():
            state = json.loads(state_path.read_text())
            require(state.get("owner") == OWNER and state.get("root") == str(root), "Unrecognized installation receipt")
        else:
            require(set(p.name for p in root.iterdir()) == {".lock"}, "Refusing unrelated installation directory")
            state = {"owner": OWNER, "root": str(root), "bin": str(bin_dir), "active": None,
                     "previous": None, "releases": {}, "attempts": [], "launchers": {}}
            atomic(state_path, state)
        safe_path(state["bin"])
        for name, record in state["releases"].items():
            require(re.fullmatch(r"[0-9a-f]{32}", name), "Invalid release directory in receipt")
            for path in record.get("receipt", {}):
                relative(path)
        require(state["active"] is None or state["active"] in state["releases"], "Invalid active release")
        require(state["previous"] is None or state["previous"] in state["releases"], "Invalid previous release")
        require(set(state["launchers"]) <= {"ptw", "ptw-codex", "ptw-install"}, "Invalid owned launcher")
        yield state
    finally:
        os.close(fd)


def publish_launchers(root, state):
    bin_dir = safe_path(state["bin"])
    bin_dir.mkdir(parents=True, exist_ok=True)
    helper = root / "launcher.py"
    require(not helper.exists() or (not helper.is_symlink() and helper.read_text() == LAUNCHER), "Unrelated launcher helper")
    launchers = {}
    for name in ("ptw", "ptw-codex", "ptw-install"):
        path = bin_dir / name
        data = launcher(root, name)
        require(not path.is_symlink(), "Unrelated command collision: " + str(path))
        if path.exists():
            expected = state["launchers"].get(name)
            require(expected is not None and matches(path, {"sha256": expected}),
                    "Unrelated command collision: " + str(path))
            # An activated virtualenv may change sys.executable on retry/upgrade.
            # Preserve the verified wrapper and its original host interpreter.
            data = path.read_bytes()
        launchers[name] = data
    # Record intended ownership BEFORE writes so an interrupted publication is retryable.
    state["launchers"] = {name: sha(data) for name, data in launchers.items()}
    atomic(root / "state.json", state)
    if not helper.exists():
        publish_file(helper, LAUNCHER.encode(), 0o644)
    for name in state["launchers"]:
        path = bin_dir / name
        if not path.exists():
            publish_file(path, launchers[name], 0o755)


def publish_file(path, data, mode):
    """Publish a complete launcher without replacing an existing directory entry."""
    temporary = path.with_name(".ptw-" + uuid.uuid4().hex + ".tmp")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.link(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        temporary.unlink(missing_ok=True)


def select_release(root, state, identity):
    prior = state["active"], state["previous"]
    if state["active"] != identity:
        state["previous"], state["active"] = state["active"], identity
    try:
        atomic(root / "state.json", state)
    except BaseException:
        state["active"], state["previous"] = prior
        raise


def install(root, state, source, digest, loopback=False):
    preflight()
    manifest, files = release_files(download(source, digest, loopback=loopback))
    for identity, record in state["releases"].items():
        if record["version"] == manifest["version"]:
            require(record["digest"] == digest, "Release version already recorded with different bytes; choose a new version")
            if record["status"] == "ready":
                if state["active"] != identity:
                    in_use(root)
                candidate = root / "releases" / identity
                verify(candidate, record["receipt"])
                report = health(candidate, record["version"])
                verify(candidate, record["receipt"])
                publish_launchers(root, state)
                select_release(root, state, identity)
                return report
    in_use(root)
    identity = uuid.uuid4().hex
    candidate = safe_path(root / "releases" / identity)
    candidate.parent.mkdir(exist_ok=True)
    state["releases"][identity] = {"version": manifest["version"], "digest": digest,
                                   "status": "preparing", "receipt": {}}
    atomic(root / "state.json", state)
    candidate.mkdir()
    prior = state["active"], state["previous"]
    try:
        print("Installing verified candidate; current release remains active.", flush=True)
        prepare(candidate, files, manifest)
        receipt = snapshot(candidate)
        report = health(candidate, manifest["version"])
        verify(candidate, receipt)
        state["releases"][identity].update(status="ready", receipt=receipt, python=sys.executable)
        atomic(root / "state.json", state)
        publish_launchers(root, state)
        select_release(root, state, identity)
        return report
    except BaseException:
        state["active"], state["previous"] = prior
        state["releases"][identity].update(status="failed", receipt=snapshot(candidate))
        atomic(root / "state.json", state)
        raise


def rollback(root, state):
    preflight()
    in_use(root)
    identity = state["previous"]
    require(identity is not None, "No previous good release")
    record = state["releases"][identity]
    require(record["status"] == "ready", "Previous release is not ready")
    candidate = root / "releases" / identity
    verify(candidate, record["receipt"])
    report = health(candidate, record["version"])
    verify(candidate, record["receipt"])
    select_release(root, state, identity)
    return report


def uninstall(root, state):
    in_use(root)
    # Disable launch before removal. The locked receipt persists for safe repeated uninstall.
    state["active"] = state["previous"] = None
    atomic(root / "state.json", state)
    retained = []
    for identity, record in state["releases"].items():
        candidate = safe_path(root / "releases" / identity)
        for name, entry in sorted(record["receipt"].items(), key=lambda x: (x[0].count("/"), x[0]), reverse=True):
            path = candidate / name
            try:
                if matches(path, entry):
                    if entry.get("directory"):
                        path.rmdir()
                    else:
                        path.unlink()
                elif path.exists() or path.is_symlink():
                    retained.append(str(path))
            except (OSError, InstallError):
                retained.append(str(path))
        try:
            candidate.rmdir()
        except OSError:
            if candidate.exists():
                retained.append(str(candidate))
        record["status"] = "removed"
    for name, expected in state["launchers"].items():
        path = Path(state["bin"]) / name
        if matches(path, {"sha256": expected}):
            path.unlink()
        elif path.exists() or path.is_symlink():
            retained.append(str(path))
    helper = root / "launcher.py"
    if matches(helper, {"sha256": sha(LAUNCHER.encode())}):
        helper.unlink()
    try:
        (root / "releases").rmdir()
    except OSError:
        pass
    atomic(root / "state.json", state)
    return {"uninstalled": True, "retained": sorted(set(retained)), "receipt_retained": str(root / "state.json")}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Verified private Linux install; no sudo, login or project changes")
    parser.add_argument("action", nargs="?", choices=("install", "rollback", "uninstall", "status"), default="install")
    parser.add_argument("--artifact", default=BOOTSTRAP_URL)
    parser.add_argument("--sha256", default=BOOTSTRAP_DIGEST)
    parser.add_argument("--root", type=Path, default=Path.home() / ".local/share/permission-to-work")
    parser.add_argument("--bin-dir", type=Path, default=Path.home() / ".local/bin")
    parser.add_argument("--test-loopback-http", action="store_true")
    args = parser.parse_args(argv)
    def interrupted(signum, frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    started = time.monotonic()
    try:
        root, bin_dir = safe_path(args.root), safe_path(args.bin_dir)
        require(root != bin_dir and root not in bin_dir.parents and bin_dir not in root.parents,
                "Installation and command directories must be separate")
        if args.action == "install":
            require(args.artifact and args.sha256, "Use a built version-specific installer or provide --artifact and trusted --sha256")
        with locked(root, bin_dir) as state:
            attempt = {"action": args.action, "started": time.time(), "status": "running"}
            state["attempts"].append(attempt)
            atomic(root / "state.json", state)
            try:
                if args.action == "install":
                    result = install(root, state, args.artifact, args.sha256, args.test_loopback_http)
                elif args.action == "rollback":
                    result = rollback(root, state)
                elif args.action == "uninstall":
                    result = uninstall(root, state)
                else:
                    result = {"active": state["active"], "previous": state["previous"], "releases": {
                        k: {"version": v["version"], "status": v["status"]} for k, v in state["releases"].items()}}
                attempt.update(status="passed", seconds=round(time.monotonic() - started, 3))
            except BaseException as exc:
                attempt.update(status="failed", error=type(exc).__name__, message=str(exc)[:1000],
                               seconds=round(time.monotonic() - started, 3))
                raise
            finally:
                atomic(root / "state.json", state)
        print(json.dumps(result, sort_keys=True))
        if args.action in ("install", "rollback"):
            command = Path(state["bin"]) / "ptw"
            print("Ready. Run " + shlex.quote(str(command)) + " doctor. For model tasks: " +
                  shlex.quote(str(command.with_name("ptw-codex"))) + " login (your own account).")
            if str(command.parent) not in os.environ.get("PATH", "").split(os.pathsep):
                print("Open a fresh login terminal. If ptw is still absent, add this to ~/.profile (sh/bash/zsh login):\n" +
                      "  export PATH=" + shlex.quote(str(command.parent)) + ':"$PATH"\n' +
                      "For fish: fish_add_path " + shlex.quote(str(command.parent)) +
                      "\nNo shell startup files were edited; absolute commands work immediately.")
        return 0
    except (InstallError, OSError, ValueError, KeyError, TypeError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print("PTW install: " + str(exc), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("PTW install cancelled. Retry is safe; previous selection retained.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
