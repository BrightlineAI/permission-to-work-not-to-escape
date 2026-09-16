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

from ptw.npm import NpmPlan
from ptw.package_build import extract_result
from ptw.package_evidence import EvidenceError
from ptw.packages import PackageControl
from ptw.policy import Invalid, compile_policy
from test_packages import PackageFixture


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
    def test_npm_real_offline_install(self):
        result = self.npm_install(NpmFixture())
        self.assertTrue(result["allowed"], result)
        self.assertTrue((self.store.directory / "package-sets" / result["package_set"] / "node_modules/demo/index.js").is_file())

    def test_npm_scoped_package(self):
        result = self.npm_install(NpmFixture(name="@fixture/demo"))
        self.assertTrue(result["allowed"], result)

    def test_npm_build_runs_only_in_disposable_namespace(self):
        self.policy["project"]["packages"]["build_packages"] = ["npm:demo"]
        self.store = self.activate("-build")
        self.a = self.store.register("website", "frontend")
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
