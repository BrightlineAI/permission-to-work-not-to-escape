#!/usr/bin/env python3
"""Build only the application, frozen npm lock, and authenticated bootstrap.

Build network trust: pinned uv binary digest, hashed setuptools wheel, exact npm
release identities over TLS. The generated npm lock is part of release review.
No repository code or npm lifecycle script runs during dependency resolution.
"""
import argparse
import gzip
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile

from product_install import (CODEX, PINS, SAFETY_FILES, archive_files, clean_env, download, require,
                             run, safe_path, sha, validate_npm, validate_wheel)

REPO = Path(__file__).resolve().parents[2]
BUILD_PIN = "setuptools==82.0.1 --hash=sha256:a59e362652f08dcd477c78bb6e7bd9d80a7995bc73ce773050228a348ce2e5bb\n"


def source_files(repo):
    names = ["harness/pyproject.toml", "harness/requirements.lock", "harness/INSTALL.md",
             "harness/scripts/product_install.py", "LICENSE", "THIRD_PARTY_NOTICES.md"]
    names += list(SAFETY_FILES.values())
    names += [str(path.relative_to(repo)) for path in sorted((repo / "harness/ptw").rglob("*"))
              if path.is_file() and '__pycache__' not in path.parts and path.suffix not in ('.pyc', '.pyo')]
    result = {}
    for name in names:
        path = safe_path(repo / name)
        require(path.is_file(), "Missing release source: " + name)
        result[name] = path.read_bytes()
    project = tomllib.loads(result["harness/pyproject.toml"].decode())["project"]
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", project["version"]), "Release needs a numeric version")
    require(('__version__ = "' + project["version"] + '"').encode() in result["harness/ptw/__init__.py"],
            "Source/metadata version mismatch")
    return project, result


def deterministic_tar(files):
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", filename="", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, data in sorted(files.items()):
                member = tarfile.TarInfo(name)
                member.size, member.mode = len(data), 0o644
                archive.addfile(member, io.BytesIO(data))
    return buffer.getvalue()


def assemble(project, sources, wheel, package, lock):
    validate_npm(package, lock)
    validate_wheel(wheel, project["version"])
    wheel_name = f"permission_to_work_harness-{project['version']}-py3-none-any.whl"
    with zipfile.ZipFile(io.BytesIO(wheel)) as archive:
        require(len(archive.namelist()) == len(set(archive.namelist())), "Duplicate wheel entries")
        for name in archive.namelist():
            require(name.startswith(("ptw/", f"permission_to_work_harness-{project['version']}.dist-info/")),
                    "Unexpected wheel member")
        for name, data in sources.items():
            if name.startswith("harness/ptw/"):
                require(archive.read(name.removeprefix("harness/")) == data, "Wheel/source mismatch")
    files = {wheel_name: wheel, "package.json": json.dumps(package, sort_keys=True).encode(),
             "package-lock.json": json.dumps(lock, sort_keys=True).encode()}
    for source, target in (("harness/requirements.lock", "requirements.lock"),
                           ("harness/scripts/product_install.py", "product_install.py"),
                           ("harness/INSTALL.md", "INSTALL.md"), ("LICENSE", "LICENSE"),
                           ("THIRD_PARTY_NOTICES.md", "THIRD_PARTY_NOTICES.md")):
        files[target] = sources[source]
    files.update({target: sources[source] for target, source in SAFETY_FILES.items()})
    manifest = {"format": 1, "version": project["version"],
                "files": {name: sha(value) for name, value in files.items()},
                "source_sha256": {name: sha(value) for name, value in sources.items()}}
    files["release.json"] = json.dumps(manifest, sort_keys=True).encode()
    return deterministic_tar(files), manifest


def bootstrap(source, digest, url):
    source = source.decode().replace("BOOTSTRAP_DIGEST = None", "BOOTSTRAP_DIGEST = " + repr(digest))
    source = source.replace("BOOTSTRAP_URL = None", "BOOTSTRAP_URL = " + repr(url))
    return ("#!/bin/sh\nset -eu\nexec python3 -I - \"$@\" <<'PTW_VERIFIED_PYTHON'\n" +
            source + "\nPTW_VERIFIED_PYTHON\n").encode()


def build(out, repo=REPO):
    project, sources = source_files(repo)
    out = safe_path(out)
    out.mkdir(parents=True, exist_ok=False)
    # Keep failed build evidence, including generated lock, in this unique output.
    attempt = {"source_sha256": {name: sha(data) for name, data in sources.items()}, "status": "building"}
    try:
        with tempfile.TemporaryDirectory(prefix="ptw-builder-", dir=out) as temporary:
            work = Path(temporary)
            env = clean_env(work)
            env["SOURCE_DATE_EPOCH"] = "315532800"
            env["PYTHONHASHSEED"] = "0"
            (work / "empty.npmrc").touch()
            (work / "empty-global.npmrc").touch()
            binary = archive_files(download(PINS["uv"][1], PINS["uv"][2]), directories=True)
            matches = [data for name, data in binary.items() if Path(name).name == "uv"]
            require(len(matches) == 1, "Unexpected uv archive")
            uv = work / "uv"
            uv.write_bytes(matches[0])
            uv.chmod(0o755)
            uv_version = run([uv, "--version"], env=env)
            require(uv_version.startswith("uv " + PINS["uv"][0]), "Unexpected builder uv version")
            attempt["tools"] = {"uv": uv_version, "python": sys.version,
                                "node": run(["node", "--version"], env=env),
                                "npm": run(["npm", "--version"], env=env, cwd=work)}
            run([uv, "--no-config", "venv", "--no-python-downloads", "--python", sys.executable, work / "venv"], env=env)
            (work / "build.lock").write_text(BUILD_PIN)
            run([uv, "--no-config", "pip", "install", "--python", work / "venv/bin/python", "--require-hashes",
                 "--only-binary", ":all:", "--index-url", "https://pypi.org/simple", "-r", work / "build.lock"], env=env)
            source = work / "source"
            source.mkdir()
            for name, data in sources.items():
                if name == "harness/pyproject.toml" or name.startswith("harness/ptw/"):
                    target = source / name.removeprefix("harness/")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(data)
            wheels = work / "wheels"
            wheels.mkdir()
            run([work / "venv/bin/python", "-I", "-c",
                 "import setuptools.build_meta,sys; setuptools.build_meta.build_wheel(sys.argv[1])", wheels],
                env=env, cwd=source, timeout=120)
            wheel_paths = list(wheels.glob("*.whl"))
            require(len(wheel_paths) == 1, "Expected one application wheel")
            package = {"name": "ptw-private-codex", "version": "1.0.0", "private": True,
                       "dependencies": {"@openai/codex": CODEX}}
            npm = work / "npm"
            npm.mkdir()
            (npm / "package.json").write_text(json.dumps(package))
            run(["npm", "install", "--package-lock-only", "--ignore-scripts", "--include=optional", "--no-audit",
                 "--no-fund", "--registry=https://registry.npmjs.org", "--lockfile-version=3"], env=env, cwd=npm, timeout=120)
            lock = json.loads((npm / "package-lock.json").read_text())
            # Exact versions plus TLS at build time establish the publisher's selected hashes.
            # Frozen hashes in the authenticated artifact establish install-time integrity.
            (out / "package-lock.json").write_text(json.dumps(lock, indent=2, sort_keys=True))
            archive, manifest = assemble(project, sources, wheel_paths[0].read_bytes(), package, lock)
        filename = f"ptw-{project['version']}-linux-x86_64.tar.gz"
        (out / filename).write_bytes(archive)
        url = "https://github.com/BrightlineAI/permission-to-work-not-to-escape/releases/download/harness-v" + project["version"] + "/" + filename
        entry = bootstrap(sources["harness/scripts/product_install.py"], sha(archive), url)
        (out / "install.sh").write_bytes(entry)
        (out / "SHA256SUMS").write_text(sha(archive) + "  " + filename + "\n" + sha(entry) + "  install.sh\n")
        attempt.update(status="built-unpublished", archive=filename, archive_sha256=sha(archive),
                       bootstrap_sha256=sha(entry), archive_bytes=len(archive), manifest=manifest,
                       builder_pin=BUILD_PIN.strip(), url=url)
        return attempt
    except BaseException as exc:
        attempt.update(status="failed", error=type(exc).__name__)
        raise
    finally:
        (out / "build.json").write_text(json.dumps(attempt, indent=2, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.out), sort_keys=True))
