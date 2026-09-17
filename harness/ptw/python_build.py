"""PEP 517 source builds using uv and only already assessed local artifacts."""
import hashlib
import os
from pathlib import Path
import shutil

from packaging.utils import parse_wheel_filename
from packaging.version import Version

from .package_build import run_build
from .package_evidence import EvidenceError
from .package_install import target_environment, target_tags, validate_wheels
from .supervisor import runtime_namespace


def build_sources(store, token, artifacts, evidence, selected, *, allow_native=False, python='/usr/bin/python3'):
    sources = [e for e in evidence if e.get("artifact_kind") == "sdist"]
    if not sources:
        return evidence
    uv = os.environ.get("PTW_UV") or shutil.which("uv")
    if not uv or not Path(uv).is_file():
        raise EvidenceError("uv is required for offline source builds")
    # No package registry, ambient config, host home or project resource is mounted.
    # uv's PEP 517 resolver can select only these prechecked, pinned artifacts.
    (artifacts / "build-pins.txt").write_text("".join(n + "==" + v + "\n" for n, v in selected.items()))
    wheel_records = [e for e in evidence if e not in sources]
    validate_wheels({e["name"]: artifacts / e["filename"] for e in wheel_records},
                    selected, environment=target_environment(python), extended=True)
    result = list(wheel_records)
    compatible = set(target_tags(python))
    for index, source in enumerate(sources):
        output = artifacts.parent / ("build-" + str(index))
        output.mkdir(mode=0o700)
        command = runtime_namespace() + [
            "--ro-bind", str(Path(uv).resolve()), "/uv", "--ro-bind", str(artifacts), "/artifacts",
            "--bind", str(output), "/target", "--", "/uv",
            "--no-config", "--offline", "--no-cache", "--no-python-downloads", "build",
            "--wheel", "--no-sources", "--no-index", "--find-links", "/artifacts",
            "--build-constraints", "/artifacts/build-pins.txt", "--python", python,
            "--out-dir", "/target/out", "/artifacts/" + source["filename"]]
        run_build(store, token, command, output)
        wheels = list((output / "out").glob("*.whl"))
        if len(wheels) != 1:
            raise EvidenceError("Source build must produce exactly one wheel")
        wheel = wheels[0]
        name, version, _, tags = parse_wheel_filename(wheel.name)
        if name != source["name"] or version != Version(source["version"]) or not any(str(t) in compatible for t in tags):
            raise EvidenceError("Source build produced a different identity or incompatible wheel")
        if not allow_native and not any(t.interpreter == "py3" and t.abi == "none" and t.platform == "any" for t in tags):
            raise EvidenceError("Built native wheel needs explicit native-wheel policy authority")
        validate_wheels({name: wheel}, selected, environment=target_environment(python), extended=True)
        destination = artifacts / wheel.name
        with wheel.open("rb") as reader, destination.open("xb") as writer:
            shutil.copyfileobj(reader, writer)
        built_hash = hashlib.sha256(destination.read_bytes()).hexdigest()
        source["built_wheel"] = {"filename": wheel.name, "sha256": built_hash}
        result.append({**source, "filename": wheel.name, "sha256": built_hash})
    return result
