"""Validate wheel data; let uv install offline inside a disposable namespace."""
from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import zipfile

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version

from .package_evidence import EvidenceError
from .supervisor import runtime_namespace


def target_environment():
    result = subprocess.run(["/usr/bin/python3", "-I", "-S", "-c",
        "import json,sys,platform; v=sys.implementation.version; "
        "iv=f'{v.major}.{v.minor}.{v.micro}'; "
        "iv += '' if v.releaselevel == 'final' else "
        "{'alpha':'a','beta':'b','candidate':'rc'}[v.releaselevel]+str(v.serial); "
        "print(json.dumps(dict(python_version='.'.join(map(str,sys.version_info[:2])), "
        "python_full_version=platform.python_version(), implementation_name=sys.implementation.name, "
        "implementation_version=iv, platform_python_implementation=platform.python_implementation())))"],
        capture_output=True, text=True, timeout=5, check=True)
    env = default_environment()
    env.update(json.loads(result.stdout), extra="")
    return env


def validate_wheels(wheels, selected, environment=None):
    """No resolver, imports or build backend: the input must close its dependencies."""
    env = environment or target_environment()
    occupied, expanded = set(), 0
    for name, path in wheels.items():
        try:
            with zipfile.ZipFile(path) as wheel:
                members = wheel.infolist()
                expanded += sum(x.file_size for x in members)
                if expanded > 200 * 1024 * 1024:
                    raise EvidenceError("Package set exceeds expanded size limit")
                if len(members) > 5000 or sum(x.file_size for x in members) > 100 * 1024 * 1024:
                    raise EvidenceError("Wheel exceeds expanded size limit")
                seen, metadata = set(), []
                for item in members:
                    p = PurePosixPath(item.filename)
                    if (not item.filename or "\\" in item.filename or p.is_absolute() or
                            any(x in ("", ".", "..") for x in item.filename.rstrip("/").split("/")) or
                            item.filename in seen or stat.S_ISLNK(item.external_attr >> 16)):
                        raise EvidenceError("Unsafe or duplicate wheel member")
                    seen.add(item.filename)
                    if p.parts[0].endswith(".dist-info"):
                        identity = p.parts[0][:-10].rsplit("-", 1)
                        if (len(identity) != 2 or canonicalize_name(identity[0]) != name or
                                Version(identity[1]) != Version(selected[name])):
                            raise EvidenceError("Foreign distribution metadata in wheel")
                    # This narrow first version excludes relocation and startup hooks.
                    if (p.parts[0].endswith(".data") or p.suffix == ".pth" or
                            p.name in ("sitecustomize.py", "usercustomize.py")):
                        raise EvidenceError("Wheel uses unsupported relocation or startup hooks")
                    if not item.is_dir():
                        if item.filename in occupied:
                            raise EvidenceError("Package files collide")
                        occupied.add(item.filename)
                    if len(p.parts) == 2 and p.parts[0].endswith(".dist-info") and p.name == "METADATA":
                        metadata.append(item)
                if len(metadata) != 1 or metadata[0].file_size > 1024 * 1024:
                    raise EvidenceError("Exactly one bounded wheel metadata file required")
                meta = BytesParser().parsebytes(wheel.read(metadata[0]))
                if (len(meta.get_all("Name", [])) != 1 or len(meta.get_all("Version", [])) != 1 or
                        canonicalize_name(meta["Name"]) != name or Version(meta["Version"]) != Version(selected[name])):
                    raise EvidenceError("Wheel identity differs from approved pin")
                requires_python = meta.get_all("Requires-Python", [])
                if len(requires_python) > 1 or (requires_python and
                        not SpecifierSet(requires_python[0]).contains(env["python_full_version"])):
                    raise EvidenceError("Wheel does not support the confined Python interpreter")
                for raw in meta.get_all("Requires-Dist", []):
                    dep = Requirement(raw)
                    if dep.marker and not dep.marker.evaluate(env):
                        continue
                    dep_name = canonicalize_name(dep.name)
                    if dep.url or dep.extras:
                        raise EvidenceError("Active URL or extra dependency is not supported")
                    if dep_name not in selected or not dep.specifier.contains(selected[dep_name], prereleases=True):
                        raise EvidenceError("Missing or incompatible pinned dependency: " + dep_name)
        except (ValueError, KeyError, zipfile.BadZipFile, RuntimeError) as exc:
            if isinstance(exc, EvidenceError):
                raise
            raise EvidenceError("Invalid wheel metadata") from exc


def install_wheels(wheelhouse, target, evidence):
    uv = os.environ.get("PTW_UV") or shutil.which("uv")
    if not uv or not Path(uv).is_file():
        raise EvidenceError("uv is required; no installation fallback")
    target.mkdir(mode=0o700)
    requirements = wheelhouse / "install.txt"
    requirements.write_text("".join(
        e["name"] + " @ file:///wheels/" + e["filename"] + " --hash=sha256:" + e["sha256"] + "\n"
        for e in evidence))
    command = runtime_namespace() + [
        "--ro-bind", str(Path(uv).resolve()), "/uv",
        "--ro-bind", str(wheelhouse), "/wheels", "--bind", str(target), "/target",
        "--", "/uv", "--no-config", "--offline", "--no-cache", "--no-python-downloads",
        "pip", "install", "--python", "/usr/bin/python3", "--target", "/target",
        "--no-deps", "--no-index", "--no-build", "--require-hashes", "--link-mode", "copy",
        "-r", "/wheels/install.txt"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=90)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EvidenceError("Confined installer failed: " + type(exc).__name__) from exc
    if result.returncode:
        raise EvidenceError("Confined uv installation failed: " + result.stderr[-1200:])


def file_manifest(directory):
    if directory.is_symlink() or not directory.is_dir():
        raise EvidenceError("Package directory is missing or replaced")
    result = {}
    for path in sorted(directory.rglob("*")):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise EvidenceError("Installed package contains a link or special file")
        result[str(path.relative_to(directory))] = hashlib.sha256(path.read_bytes()).hexdigest()
    if not result:
        raise EvidenceError("Installer produced no package files")
    return result
