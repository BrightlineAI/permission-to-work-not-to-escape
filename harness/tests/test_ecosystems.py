"""Ecosystem fixtures are synthetic; Linux tests execute real offline installers."""
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import time
import unittest
import concurrent.futures
import subprocess
from unittest.mock import patch

from ptw.npm import NpmPlan
from ptw.package_build import extract_result
from ptw.package_evidence import EvidenceError, PyPIEvidence, pins
from ptw.package_install import validate_wheels, file_manifest
from ptw.supervisor import Supervisor, sandbox_command
from ptw.packages import PackageControl
from ptw.policy import Invalid, compile_policy
from test_packages import PackageFixture, FixtureProvider, wheel_bytes, CRITICAL


def tar_bytes(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, raw in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            member.mode = 0o755 if name.endswith(".js") else 0o644
            archive.addfile(member, io.BytesIO(raw))
    return stream.getvalue()


class NpmFixture:
    def __init__(self, name="demo", version="1.0.0", fields=None, files=None):
        self.manifest = {"name": name, "version": version, **(fields or {})}
        self.raw = tar_bytes({"package/package.json": json.dumps(self.manifest).encode(),
            "package/index.js": b"module.exports = 'NPM_OK';\n", **(files or {})})
        self.record = {"name": name, "version": version, "filename": "fixture.tgz",
            "url": "https://registry.npmjs.org/" + name + "/-/" + name.rsplit("/", 1)[-1] + "-" + version + ".tgz",
            "integrity": "sha512-" + base64.b64encode(hashlib.sha512(self.raw).digest()).decode(),
            "sha256": hashlib.sha256(self.raw).hexdigest(), "published_at": "2020-01-01T00:00:00Z",
            "checked_at": time.time(), "vulnerabilities": []}
        entry = {k: self.record[k] for k in ("version", "integrity")}
        entry["resolved"] = self.record["url"]
        for field in ("dependencies", "optionalDependencies", "peerDependencies", "peerDependenciesMeta", "bin"):
            if field in self.manifest:
                entry[field] = self.manifest[field]
        self.lock = {"lockfileVersion": 3, "packages": {
            "": {"dependencies": {name: version}}, "node_modules/" + name: entry}}

    def assess(self, name, version):
        return {**self.record, "checked_at": time.time()}

    def download(self, evidence, destination):
        destination.write_bytes(self.raw)


class EcosystemFixture(PackageFixture):
    def setUp(self):
        super().setUp()
        self.policy["version"] = 3
        self.policy["project"]["packages"].update(
            allowed_names=["pypi:idna", "npm:demo", "npm:@fixture/demo"],
            allow_native_wheels=True, build_packages=[])
        self.policy["tasks"][0]["packages"] = ["pypi:idna", "npm:demo", "npm:@fixture/demo"]
        self.store = self.activate("-ecosystem")
        self.a = self.store.register("website", "frontend")
        self.b = self.store.register("website", "operations")

    def npm_install(self, fixture, event="npm"):
        return PackageControl(self.store, provider=fixture).install(
            self.a["token"], event, fixture.lock, ecosystem="npm")


class EcosystemTests(EcosystemFixture, unittest.TestCase):
    def test_qualified_policy_and_task_subset(self):
        compile_policy(self.policy, self.inv)
        self.policy["tasks"][1]["packages"] = ["npm:outside"]
        with self.assertRaises(Invalid):
            compile_policy(self.policy, self.inv)

    def test_build_scope_cannot_exceed_project(self):
        self.policy["project"]["packages"]["build_packages"] = ["npm:outside"]
        with self.assertRaises(Invalid):
            compile_policy(self.policy, self.inv)

    def test_npm_cannot_borrow_python_name(self):
        fixture = NpmFixture(name="idna")
        result = self.npm_install(fixture)
        self.assertFalse(result["allowed"])
        self.assertEqual(self.store.status("website")["violations"], 1)

    def test_child_cannot_expand_package_scope(self):
        with self.assertRaises(Invalid):
            self.store.register("website", "frontend", parent_token=self.b["token"], packages=["npm:demo"])

    def test_url_integrity_binding(self):
        fixture = NpmFixture()
        fixture.lock["packages"]["node_modules/demo"]["resolved"] = "https://attacker.invalid/x.tgz"
        with self.assertRaises(EvidenceError):
            NpmPlan(fixture.lock).bind_evidence([fixture.record])

    def test_alias_rejected(self):
        fixture = NpmFixture()
        fixture.lock["packages"]["node_modules/demo"]["name"] = "real-other-name"
        with self.assertRaises(Invalid):
            NpmPlan(fixture.lock)

    def test_missing_dependency_rejected(self):
        fixture = NpmFixture(fields={"dependencies": {"missing": "^1.0.0"}})
        with self.assertRaises(Invalid):
            NpmPlan(fixture.lock)

    def test_version_mismatch_rejected(self):
        fixture = NpmFixture()
        fixture.lock["packages"][""]["dependencies"]["demo"] = "^2.0.0"
        with self.assertRaises(Invalid):
            NpmPlan(fixture.lock)

    def test_nested_and_peer_dependencies(self):
        fixture = NpmFixture()
        entry = copy.deepcopy(fixture.lock["packages"]["node_modules/demo"])
        entry["dependencies"] = {"demo": "1.0.0"}
        entry["peerDependencies"] = {"demo": "^1"}
        fixture.lock["packages"]["node_modules/demo/node_modules/child"] = entry
        NpmPlan(fixture.lock)

    def test_lock_v2_accepted(self):
        fixture = NpmFixture()
        fixture.lock["lockfileVersion"] = 2
        self.assertEqual(NpmPlan(fixture.lock).lock["lockfileVersion"], 3)

    def test_optional_missing_peer_accepted(self):
        fixture = NpmFixture(fields={"peerDependencies": {"optional": "^1"},
            "peerDependenciesMeta": {"optional": {"optional": True}}})
        NpmPlan(fixture.lock)

    def test_absent_optional_url_not_silently_accepted(self):
        fixture = NpmFixture(fields={"optionalDependencies": {"absent": "git+https://outside.invalid/repo.git"}})
        with self.assertRaises(Invalid):
            NpmPlan(fixture.lock)

    def test_malformed_peer_metadata_rejected(self):
        fixture = NpmFixture(fields={"peerDependenciesMeta": {"missing": []}})
        with self.assertRaises(Invalid):
            NpmPlan(fixture.lock)

    def test_critical_npm_denied_before_download(self):
        fixture = NpmFixture()
        fixture.record["vulnerabilities"] = [CRITICAL]
        with patch.object(fixture, "download", side_effect=AssertionError("must not download")):
            result = self.npm_install(fixture)
        self.assertFalse(result["allowed"])
        self.assertEqual(self.store.status("website")["violations"], 1)

    def test_unknown_severity_does_not_accuse_agent(self):
        fixture = NpmFixture()
        fixture.record["vulnerabilities"] = [{"id": "UNKNOWN"}]
        result = self.npm_install(fixture)
        self.assertFalse(result["allowed"])
        self.assertEqual(self.store.status("website")["violations"], 0)

    def test_young_npm_denied(self):
        from datetime import datetime, timezone
        fixture = NpmFixture()
        fixture.record["published_at"] = datetime.now(timezone.utc).isoformat()
        result = self.npm_install(fixture)
        self.assertFalse(result["allowed"])
        self.assertEqual(self.store.status("website")["violations"], 1)

    def test_python_npm_and_file_share_counter(self):
        fixture = NpmFixture()
        fixture.record["vulnerabilities"] = [CRITICAL]
        self.npm_install(fixture)
        child = self.store.register("website", "frontend", parent_token=self.a["token"])
        control = PackageControl(self.store, provider=FixtureProvider({"idna": {"vulnerabilities": [CRITICAL]}}))
        control.install(child["token"], "bad-python", ["idna==3.11"])
        self.store.request(self.b["token"], "bad-file", {"action": "read", "resource": "customers", "content": ""})
        self.assertEqual(self.store.status("website")["violations"], 3)
        self.assertTrue(self.store.status("website")["stopped"])

    def test_python_extra_requires_its_dependency(self):
        wheel = self.root / "idna-3.11-py3-none-any.whl"
        wheel.write_bytes(wheel_bytes(extra={"idna-3.11.dist-info/METADATA":
            b"Metadata-Version: 2.1\nName: idna\nVersion: 3.11\nProvides-Extra: secure\nRequires-Dist: missing; extra == 'secure'\n"}))
        validate_wheels({"idna": wheel}, {"idna": "3.11"}, extended=True)
        with self.assertRaises(EvidenceError):
            validate_wheels({"idna": wheel}, {"idna": "3.11"}, extended=True, extras={"idna": ["secure"]})

    def test_python_unknown_extra_rejected(self):
        wheel = self.root / "idna-3.11-py3-none-any.whl"
        wheel.write_bytes(wheel_bytes())
        with self.assertRaises(EvidenceError):
            validate_wheels({"idna": wheel}, {"idna": "3.11"}, extended=True, extras={"idna": ["invented"]})

    def test_old_policy_does_not_gain_extras(self):
        self.policy["version"] = 2
        rules = self.policy["project"]["packages"]
        rules.pop("allow_native_wheels")
        rules.pop("build_packages")
        rules["allowed_names"] = ["idna"]
        self.policy["tasks"][0]["packages"] = ["idna"]
        old = self.activate("-old-version")
        actor = old.register("website", "frontend")
        with self.assertRaises(Invalid):
            PackageControl(old, provider=FixtureProvider()).install(actor["token"], "extra", ["idna[secure]==3.11"])
        with self.assertRaises(Invalid):
            pins(["idna[secure]==3.11"])

    def test_wheel_relocation_collision_rejected(self):
        wheel = self.root / "idna-3.11-py3-none-any.whl"
        wheel.write_bytes(wheel_bytes(extra={"idna-3.11.data/purelib/idna/__init__.py": b"collision"}))
        with self.assertRaises(EvidenceError):
            validate_wheels({"idna": wheel}, {"idna": "3.11"}, extended=True)

    def test_unapproved_python_source_blocked_by_broker(self):
        provider = FixtureProvider({"idna": {"artifact_kind": "sdist", "filename": "idna-3.11.tar.gz"}})
        result = PackageControl(self.store, provider=provider).install(self.a["token"], "source", ["idna==3.11"])
        self.assertFalse(result["allowed"])
        self.assertIn("explicit policy authority", result["reason"])

    def test_native_tag_selection_uses_target_not_controller(self):
        native = "idna-3.11-cp313-cp313-manylinux_2_28_x86_64.whl"
        pure = "idna-3.11-py3-none-any.whl"
        release = {"info": {"name": "idna", "version": "3.11"}, "urls": [
            {"filename": filename, "packagetype": "bdist_wheel", "yanked": False,
             "digests": {"sha256": "a" * 64}, "url": "https://files.pythonhosted.org/" + filename,
             "upload_time_iso_8601": "2020-01-01T00:00:00Z"} for filename in (pure, native)]}
        provider = PyPIEvidence(native=True)
        with patch.object(provider, "json", side_effect=[release, {}]), \
             patch("ptw.package_install.target_tags", return_value=["cp313-cp313-manylinux_2_28_x86_64", "py3-none-any"]):
            self.assertEqual(provider.assess("idna", "3.11")["filename"], native)
        provider = PyPIEvidence()
        with patch.object(provider, "json", side_effect=[release, {}]):
            self.assertEqual(provider.assess("idna", "3.11")["filename"], pure)

    def test_installed_link_cannot_escape(self):
        directory = self.root / "links"
        directory.mkdir()
        (directory / "bad").symlink_to("/etc/passwd")
        with self.assertRaises(EvidenceError):
            file_manifest(directory)

    def test_unapproved_lifecycle_blocked_before_execution(self):
        fixture = NpmFixture(fields={"scripts": {"postinstall": "node -e \"throw Error('must not run')\""}})
        result = self.npm_install(fixture)
        self.assertFalse(result["allowed"], result)
        self.assertIn("explicit policy authority", result["reason"])
        self.assertEqual(self.store.status("website")["violations"], 0)

    def test_hidden_dependency_in_archive_rejected(self):
        fixture = NpmFixture(fields={"dependencies": {"hidden": "^1"}})
        del fixture.lock["packages"]["node_modules/demo"]["dependencies"]
        result = self.npm_install(fixture)
        self.assertFalse(result["allowed"], result)
        self.assertIn("metadata differs", result["reason"])

    def test_export_traversal_and_external_links(self):
        for name, link in [("result/../escape", None), ("result/link", "/etc/passwd"),
                           ("result/link", "../../escape")]:
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w") as archive:
                m = tarfile.TarInfo(name)
                if link:
                    m.type, m.linkname = tarfile.SYMTYPE, link
                archive.addfile(m)
            stream.seek(0)
            with self.assertRaises(EvidenceError):
                extract_result(stream, self.root / "export")

    def test_export_internal_bin_link(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            m = tarfile.TarInfo("result/node_modules/demo/bin.js")
            m.size, m.mode = 2, 0o755
            archive.addfile(m, io.BytesIO(b"ok"))
            m = tarfile.TarInfo("result/node_modules/.bin/demo")
            m.type, m.linkname = tarfile.SYMTYPE, "../demo/bin.js"
            archive.addfile(m)
        stream.seek(0)
        destination = self.root / "export"
        destination.mkdir()
        extract_result(stream, destination)
        self.assertEqual((destination / "node_modules/.bin/demo").read_text(), "ok")


@unittest.skipUnless(os.environ.get("PTW_LINUX_TESTS") == "1", "requires actual Linux confinement")
class EcosystemLinuxTests(EcosystemFixture, unittest.TestCase):
    def native_command(self, receipt, argv):
        directory = self.store.directory / "package-sets" / receipt["package_set"]
        return subprocess.run(sandbox_command(self.inv, self.a["grants"], argv,
            package_mount=directory, package_ecosystem=receipt["ecosystem"]),
            capture_output=True, text=True, timeout=20)

    def authorize_build(self):
        self.policy["project"]["packages"]["build_packages"] = ["npm:demo"]
        self.store = self.activate("-build")
        self.a = self.store.register("website", "frontend")

    def test_npm_real_offline_install(self):
        result = self.npm_install(NpmFixture())
        self.assertTrue(result["allowed"], result)
        self.assertTrue((self.store.directory / "package-sets" / result["package_set"] / "node_modules/demo/index.js").is_file())
        output = self.native_command(result, ["/usr/bin/node", "-e", "console.log(require('demo'))"])
        self.assertEqual(output.returncode, 0, output.stderr)
        self.assertIn("NPM_OK", output.stdout)

    def test_npm_scoped_package(self):
        result = self.npm_install(NpmFixture(name="@fixture/demo"))
        self.assertTrue(result["allowed"], result)

    def test_npm_build_runs_only_in_disposable_namespace(self):
        self.authorize_build()
        script = """const fs=require('fs');
if(fs.existsSync('/home/loon') || fs.existsSync('/resources')) throw Error('host visible');
fs.writeFileSync('built.txt','BUILD_OK');
"""
        fixture = NpmFixture(fields={"scripts": {"postinstall": "node build.js"}},
            files={"package/build.js": script.encode()})
        result = self.npm_install(fixture)
        self.assertTrue(result["allowed"], result)
        self.assertEqual((self.store.directory / "package-sets" / result["package_set"] /
            "node_modules/demo/built.txt").read_text(), "BUILD_OK")

    def test_build_failure_cannot_publish_partial_set(self):
        self.authorize_build()
        fixture = NpmFixture(fields={"scripts": {"postinstall": "node -e \"process.exit(3)\""}})
        result = self.npm_install(fixture)
        self.assertFalse(result["allowed"])
        self.assertFalse((self.store.directory / "package-sets").exists())

    def test_build_hardlinks_become_independent_files(self):
        self.authorize_build()
        fixture = NpmFixture(fields={"scripts": {"postinstall": "node -e \"require('fs').linkSync('index.js','copy.js')\""}})
        result = self.npm_install(fixture)
        self.assertTrue(result["allowed"], result)
        directory = self.store.directory / "package-sets" / result["package_set"] / "node_modules/demo"
        self.assertEqual((directory / "copy.js").read_bytes(), (directory / "index.js").read_bytes())
        self.assertEqual((directory / "copy.js").stat().st_nlink, 1)

    def test_esm_resolution_from_work_directory(self):
        result = self.npm_install(NpmFixture())
        self.assertTrue(result["allowed"], result)
        program = "require('fs').writeFileSync('/work/app.mjs',\"import value from 'demo'; console.log(value)\");" \
            "require('child_process').execFileSync('/usr/bin/node',['/work/app.mjs'],{stdio:'inherit'});"
        proc = self.native_command(result, ["/usr/bin/node", "-e", program])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("NPM_OK", proc.stdout)

    def test_build_cannot_export_external_link(self):
        self.authorize_build()
        fixture = NpmFixture(fields={"scripts": {"postinstall": "node -e \"require('fs').symlinkSync('/etc/passwd','leak')\""}})
        result = self.npm_install(fixture)
        self.assertFalse(result["allowed"])
        self.assertIn("link escapes", result["reason"])

    def test_project_stop_kills_active_build_and_blocks_publication(self):
        self.authorize_build()
        fixture = NpmFixture(fields={"scripts": {"postinstall": "node -e \"setTimeout(()=>{},60000)\""}})
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.npm_install, fixture)
            deadline = time.monotonic() + 10
            units = []
            while time.monotonic() < deadline:
                with self.store.locked() as db:
                    units = [r[0] for r in db.execute("SELECT unit FROM workloads")]
                if units:
                    break
                time.sleep(.05)
            self.assertTrue(units, "build never registered")
            self.store.stop("website")
            Supervisor(self.store).reconcile()
            result = future.result(timeout=15)
        self.assertFalse(result["allowed"])
        self.assertEqual(result["level"], "stop")
        self.assertTrue(all(Supervisor(self.store).state(u)["confirmed_stopped"] for u in units))
        self.assertFalse((self.store.directory / "package-sets").exists())

    def test_wheel_data_and_extras_install(self):
        self.policy["project"]["packages"]["allowed_names"].append("pypi:other")
        self.policy["tasks"][0]["packages"].append("pypi:other")
        self.store = self.activate("-extras")
        self.a = self.store.register("website", "frontend")
        metadata = b"Metadata-Version: 2.1\nName: idna\nVersion: 3.11\nProvides-Extra: secure\nRequires-Dist: other==1.0; extra == 'secure'\n"
        provider = FixtureProvider(wheels={"idna": wheel_bytes(extra={
            "idna-3.11.dist-info/METADATA": metadata,
            "idna-3.11.data/purelib/relocated.py": b"VALUE='RELOCATED_OK'\n"})})
        result = PackageControl(self.store, provider=provider).install(self.a["token"], "extras", ["idna[secure]==3.11", "other==1.0"])
        self.assertTrue(result["allowed"], result)
        proc = self.native_command(result, ["/usr/bin/python3", "-c", "import relocated,other; print(relocated.VALUE)"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("RELOCATED_OK", proc.stdout)
