"""Synthetic fault injection; Linux cases additionally execute the real installer."""
import base64
import concurrent.futures
import copy
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import zipfile

from ptw.package_evidence import EvidenceError, PyPIEvidence, evaluate, pins, severity
from ptw.package_install import file_manifest, validate_wheels
from ptw.packages import PackageControl, mounted_set
from ptw.policy import Invalid, approve, compile_policy, digest, load
from ptw.sample import create
from ptw.store import Store
from ptw.supervisor import Supervisor, sandbox_command

CRITICAL = {"id": "SYNTHETIC-CRITICAL", "severity": [
    {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}


def wheel_bytes(name="idna", version="3.11", requires=(), extra=None):
    directory = name + "-" + version + ".dist-info"
    contents = {
        name + "/__init__.py": b"VALUE = 'SYNTHETIC_PACKAGE_OK'\n",
        directory + "/WHEEL": b"Wheel-Version: 1.0\nGenerator: ptw-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        directory + "/METADATA": ("Metadata-Version: 2.1\nName: " + name + "\nVersion: " + version +
            "\n" + "".join("Requires-Dist: " + r + "\n" for r in requires)).encode()}
    contents.update(extra or {})
    record = "".join(path + ",sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=") +
                     "," + str(len(data)) + "\n" for path, data in contents.items())
    contents[directory + "/RECORD"] = (record + directory + "/RECORD,,\n").encode()
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for path, data in contents.items():
            archive.writestr(path, data)
    return stream.getvalue()


class FixtureProvider:
    def __init__(self, changes=None, wheels=None):
        self.changes, self.wheels = changes or {}, wheels or {}
        self.downloads = 0

    def assess(self, name, version):
        raw = self.wheels.get(name, wheel_bytes(name, version))
        result = {"name": name, "version": version, "filename": name + "-" + version + "-py3-none-any.whl",
                  "sha256": hashlib.sha256(raw).hexdigest(), "published_at": "2020-01-01T00:00:00Z",
                  "checked_at": time.time(), "vulnerabilities": [], "url": "https://files.pythonhosted.org/synthetic"}
        result.update(self.changes.get(name, {}))
        return result

    def download(self, evidence, path):
        self.downloads += 1
        path.write_bytes(self.wheels.get(evidence["name"], wheel_bytes(evidence["name"], evidence["version"])))


class PackageFixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ptw-packages-test-")
        self.root = Path(self.temp.name)
        self.addCleanup(self.cleanup)
        create(self.root / "project", packages=True)
        self.policy = load(self.root / "project/policy.json")
        self.inv = load(self.root / "project/inventory.json")
        self.store = self.activate()
        self.a = self.store.register("website", "frontend")
        self.b = self.store.register("website", "operations")
        self.provider = FixtureProvider()
        self.control = PackageControl(self.store, provider=self.provider)

    def cleanup(self):
        for path in self.root.rglob("*"):
            if path.is_dir() and not path.is_symlink():
                path.chmod(0o700)
        self.temp.cleanup()

    def activate(self, suffix=""):
        store = Store(self.root / ("state" + suffix))
        store.activate(approve(self.policy, self.inv, digest(compile_policy(self.policy, self.inv)), "test operator"))
        return store

    def install(self, specs=None, event="install", actor=None):
        return self.control.install((actor or self.a)["token"], event, specs or ["idna==3.11"])

    def no_effect(self, result, counted=False):
        self.assertFalse(result["allowed"], result)
        self.assertEqual(result["effect"], "none")
        with self.store.locked() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM package_sets").fetchone()[0], 0)
        self.assertEqual(self.store.status("website")["violations"], int(counted))


class PackagePolicyTests(PackageFixture, unittest.TestCase):
    def test_exact_pins_normalized(self):
        self.assertEqual(pins(["Django==3.2.0", "My_Package==1.0"]), {"django": "3.2.0", "my-package": "1.0"})

    def test_pin_bypass_forms_rejected(self):
        for spec in ["idna", "idna>=3", "idna==3.*", "idna[extra]==3.11", "idna @ https://example.com/a.whl",
                     "idna==3.11; python_version>'3'", "--index-url evil", "../local", "idna===3.11"]:
            with self.subTest(spec=spec), self.assertRaises(Invalid):
                pins([spec])

    def test_duplicate_names_rejected(self):
        with self.assertRaises(Invalid):
            pins(["my_package==1.0", "my-package==2.0"])

    def test_task_cannot_expand_names(self):
        self.policy["tasks"][1]["packages"] = ["outside"]
        with self.assertRaises(Invalid):
            compile_policy(self.policy, self.inv)

    def test_package_policy_changes_approval_hash(self):
        before = digest(compile_policy(self.policy, self.inv))
        self.policy["project"]["packages"]["min_release_age_days"] = 0
        self.assertNotEqual(before, digest(compile_policy(self.policy, self.inv)))

    def test_unknown_manager_setting_rejected(self):
        self.policy["project"]["packages"]["allow_source_builds"] = True
        with self.assertRaises(Invalid):
            compile_policy(self.policy, self.inv)

    def test_delegate_cannot_regain_packages(self):
        parent = self.store.register("website", "frontend", packages=["idna"])
        with self.assertRaises(Invalid):
            self.store.register("website", "frontend", parent_token=parent["token"])
        child = self.store.register("website", "frontend", parent_token=parent["token"], packages=[])
        self.no_effect(self.install(actor=child), counted=True)

    def test_old_file_policy_has_no_install_authority(self):
        self.policy["version"] = 1
        del self.policy["project"]["packages"]
        for task in self.policy["tasks"]:
            del task["packages"]
        self.store = self.activate("old")
        self.a = self.store.register("website", "frontend")
        self.control = PackageControl(self.store, provider=self.provider)
        self.no_effect(self.install(), counted=True)

    def test_foreign_token_does_not_count(self):
        with self.assertRaises(Invalid):
            self.control.install("x" * 40, "e", ["idna==3.11"])
        self.assertEqual(self.store.status("website")["violations"], 0)

    def test_task_denial_precedes_network(self):
        self.no_effect(self.install(actor=self.b), counted=True)
        self.assertEqual(self.provider.downloads, 0)

    def test_critical_blocks_before_download(self):
        self.provider.changes["idna"] = {"vulnerabilities": [CRITICAL]}
        self.no_effect(self.install(), counted=True)
        self.assertEqual(self.provider.downloads, 0)

    def test_unknown_severity_not_false_pass_or_attack(self):
        self.provider.changes["idna"] = {"vulnerabilities": [{"id": "UNKNOWN"}]}
        self.no_effect(self.install())

    def test_known_critical_not_hidden_by_unknown(self):
        self.provider.changes["idna"] = {"vulnerabilities": [{"id": "UNKNOWN"}, CRITICAL]}
        result = self.install()
        self.no_effect(result, counted=True)
        self.assertIn("SYNTHETIC-CRITICAL", result["reason"])

    def test_recent_artifact_denied(self):
        self.provider.changes["idna"] = {"published_at": datetime.fromtimestamp(time.time() - 2 * 86400, timezone.utc).isoformat()}
        self.no_effect(self.install(), counted=True)

    def test_optional_age_zero_uses_same_evaluator(self):
        evidence = self.provider.assess("idna", "3.11")
        evidence["published_at"] = datetime.fromtimestamp(time.time() - 60, timezone.utc).isoformat()
        rules = self.policy["project"]["packages"]
        self.assertTrue(evaluate(evidence, rules))
        self.assertEqual(evaluate(evidence, {**rules, "min_release_age_days": 0}), [])

    def test_cvss_threshold_comes_only_from_policy(self):
        evidence = self.provider.assess("idna", "3.11")
        evidence["vulnerabilities"] = [CRITICAL]
        rules = self.policy["project"]["packages"]
        self.assertTrue(evaluate(evidence, rules))
        self.assertEqual(evaluate(evidence, {**rules, "deny_cvss_at_or_above": 10}), [])

    def test_age_exact_boundary(self):
        e = self.provider.assess("idna", "3.11")
        e.update(checked_at=1_600_000_000, published_at=datetime.fromtimestamp(1_600_000_000 - 3 * 86400, timezone.utc).isoformat())
        rules = self.policy["project"]["packages"]
        self.assertEqual(evaluate(e, rules, now=1_600_000_000), [])

    def test_stale_evidence_blocks_without_count(self):
        self.provider.changes["idna"] = {"checked_at": time.time() - 901}
        self.no_effect(self.install())

    def test_missing_evidence_blocks_without_count(self):
        self.provider.changes["idna"] = {"vulnerabilities": None}
        self.no_effect(self.install())

    def test_future_or_missing_publication_blocks(self):
        for i, value in enumerate([None, "bad", "2020-01-01", "2999-01-01T00:00:00Z"]):
            self.provider.changes["idna"] = {"published_at": value}
            self.no_effect(self.install(event=str(i)))

    def test_provider_outage_blocks_without_count(self):
        with patch.object(self.provider, "assess", side_effect=EvidenceError("API unavailable")):
            self.no_effect(self.install())

    def test_event_retry_not_counted_twice(self):
        self.provider.changes["idna"] = {"vulnerabilities": [CRITICAL]}
        self.install()
        self.assertTrue(self.install()["replayed"])
        self.assertEqual(self.store.status("website")["violations"], 1)

    def test_event_reuse_different_pin_rejected(self):
        self.install(actor=self.b)
        with self.assertRaises(Invalid):
            self.install(["idna==3.10"], actor=self.b)

    def test_file_and_package_violations_share_project_stop(self):
        parent = self.store.register("website", "frontend")
        child = self.store.register("website", "frontend", parent_token=self.a["token"])
        self.provider.changes["idna"] = {"vulnerabilities": [CRITICAL]}
        self.assertEqual(self.install(actor=child)["level"], "warn")
        self.store.request(self.b["token"], "file", {"action": "read", "resource": "customers", "content": ""})
        self.assertEqual(self.install(actor=parent)["level"], "stop")
        self.assertEqual(self.store.status("website")["violations"], 3)
        self.assertFalse(self.store.request(self.a["token"], "after", {"action": "read", "resource": "ui", "content": ""})["allowed"])

    def test_concurrent_denials_do_not_overrun_threshold(self):
        self.provider.changes["idna"] = {"vulnerabilities": [CRITICAL]}
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda n: self.install(event=str(n)), range(16)))
        self.assertTrue(all(not r["allowed"] for r in results))
        self.assertEqual(self.store.status("website")["violations"], 3)

    def test_stop_while_provider_waits(self):
        original = self.provider.assess
        started, resume = threading.Event(), threading.Event()
        def delayed(name, version):
            started.set()
            self.assertTrue(resume.wait(5))
            return original(name, version)
        # Stop must not wait for metadata/download/installer locks.
        with patch.object(self.provider, "assess", side_effect=delayed), patch("ptw.packages.install_wheels", side_effect=EvidenceError("staging canceled")):
            with concurrent.futures.ThreadPoolExecutor() as pool:
                pending = pool.submit(self.install)
                self.assertTrue(started.wait(5))
                Store(self.store.directory).stop("website")
                resume.set()
                self.assertEqual(pending.result(timeout=5)["level"], "stop")
        self.assertEqual(self.store.status("website")["violations"], 0)

    def test_evidence_identity_mismatch(self):
        self.provider.changes["idna"] = {"name": "different"}
        self.no_effect(self.install())

    def test_unsafe_artifact_filename(self):
        self.provider.changes["idna"] = {"filename": "../../evil.whl"}
        self.no_effect(self.install())

    def test_missing_dependency_not_silently_skipped(self):
        self.provider.wheels["idna"] = wheel_bytes(requires=["missing>=1"])
        self.no_effect(self.install())

    def test_active_url_dependency_not_fetched(self):
        self.provider.wheels["idna"] = wheel_bytes(requires=["bad @ https://example.com/evil"])
        self.no_effect(self.install())

    def test_withdrawn_advisory(self):
        self.assertIsNone(severity({**CRITICAL, "withdrawn": "2020-01-01T00:00:00Z"}))
        with self.assertRaises(EvidenceError):
            severity({**CRITICAL, "withdrawn": "2999-01-01T00:00:00Z"})

    def test_cvss_four_and_two(self):
        self.assertEqual(severity({"id": "V2", "severity": [{"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:C/I:C/A:C"}]}), 10)
        self.assertGreaterEqual(severity({"id": "V4", "severity": [{"type": "CVSS_V4", "score":
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}]}), 9)

    def test_hash_mismatch_rejected(self):
        provider = PyPIEvidence()
        with patch.object(provider, "fetch", return_value=b"wrong"), self.assertRaises(EvidenceError):
            provider.download({"url": "https://files.pythonhosted.org/a", "sha256": "0" * 64}, self.root / "bad.whl")
        self.assertFalse((self.root / "bad.whl").exists())

    def test_unapproved_network_destination(self):
        for url in ["http://pypi.org", "https://example.com", "https://user:pass@pypi.org", "https://pypi.org:444"]:
            with self.subTest(url=url), self.assertRaises(EvidenceError):
                PyPIEvidence().fetch(url)

    def test_wheel_paths_and_hooks_rejected(self):
        for i, member in enumerate(["../escape.py", "/escape.py", "a/../escape.py", "a\\escape.py",
                                    "startup.pth", "sitecustomize.py", "idna-3.11.data/purelib/evil.py"]):
            path = self.root / ("test" + str(i) + ".whl")
            path.write_bytes(wheel_bytes(extra={member: b"pass"}))
            with self.subTest(member=member), self.assertRaises(EvidenceError):
                validate_wheels({"idna": path}, {"idna": "3.11"})


@unittest.skipUnless(os.environ.get("PTW_LINUX_TESTS") == "1", "Real isolated Linux installer opt in required")
class PackageLinuxTests(PackageFixture, unittest.TestCase):
    def test_real_install_import_and_immutable_mount(self):
        result = self.install()
        self.assertTrue(result["allowed"], result)
        with self.store.locked() as db:
            mount = mounted_set(self.store, db, self.store.session(db, self.a["token"]), result["package_set"])
        code = "import idna; print(idna.VALUE)"
        def execute(code):
            return subprocess.run(sandbox_command(self.inv, self.a["grants"],
                ["/usr/bin/python3", "-c", code], package_mount=mount), capture_output=True, text=True, timeout=10)
        run = execute(code)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("SYNTHETIC_PACKAGE_OK", run.stdout)
        self.assertNotEqual(execute("open('/packages/idna/__init__.py','w').write('BAD')").returncode, 0)
        self.assertNotEqual(execute("import socket; socket.create_connection(('pypi.org',443),timeout=.2)").returncode, 0)
        self.assertEqual(file_manifest(mount), json.loads(self._set(result)["manifest"]))
        self.assertTrue(self.install()["replayed"])
        self.assertEqual(self.provider.downloads, 1)

    def _set(self, result):
        with self.store.locked() as db:
            return dict(db.execute("SELECT * FROM package_sets WHERE id=?", (result["package_set"],)).fetchone())

    def test_real_complete_dependency_set(self):
        self.provider.wheels["idna"] = wheel_bytes(requires=["django==3.2.0"])
        result = self.install(["idna==3.11", "django==3.2.0"])
        self.assertTrue(result["allowed"], result)
        self.assertEqual(self.provider.downloads, 2)

    def test_transitive_critical_blocks_whole_set(self):
        self.provider.wheels["idna"] = wheel_bytes(requires=["django==3.2.0"])
        self.provider.changes["django"] = {"vulnerabilities": [CRITICAL]}
        self.no_effect(self.install(["idna==3.11", "django==3.2.0"]), counted=True)
        self.assertEqual(self.provider.downloads, 0)

    def test_package_set_cannot_cross_task_or_project(self):
        result = self.install()
        self.assertTrue(result["allowed"], result)
        self.policy["project"]["id"] = "other"
        self.store.activate(approve(self.policy, self.inv, digest(compile_policy(self.policy, self.inv)), "operator"))
        other = self.store.register("other", "frontend")
        for token in (self.b["token"], other["token"]):
            with self.store.locked() as db, self.assertRaises(Invalid):
                mounted_set(self.store, db, self.store.session(db, token), result["package_set"])

    def test_modified_package_set_cannot_launch(self):
        result = self.install()
        self.assertTrue(result["allowed"], result)
        path = self.store.directory / "package-sets" / result["package_set"] / "idna/__init__.py"
        path.chmod(0o600)
        path.write_text("MODIFIED")
        with self.assertRaises(Invalid):
            Supervisor(self.store).launch(self.a["token"], ["/usr/bin/true"], package_set=result["package_set"])

    def test_stale_after_installer_cannot_publish(self):
        from ptw.package_install import install_wheels
        def expiring(wheels, target, evidence):
            install_wheels(wheels, target, evidence)
            for e in evidence:
                e["checked_at"] -= 1000
        with patch("ptw.packages.install_wheels", side_effect=expiring):
            self.no_effect(self.install())

    def test_stop_after_installer_cannot_publish(self):
        from ptw.package_install import install_wheels
        def stopping(wheels, target, evidence):
            install_wheels(wheels, target, evidence)
            self.store.stop("website")
        with patch("ptw.packages.install_wheels", side_effect=stopping):
            self.no_effect(self.install())

    def test_registered_workload_uses_set_and_stops(self):
        result = self.install()
        self.assertTrue(result["allowed"], result)
        supervisor = Supervisor(self.store)
        unit = supervisor.launch(self.a["token"], ["/usr/bin/python3", "-c",
            "import idna,time; open('/resources/ui','w').write(idna.VALUE); time.sleep(30)"], package_set=result["package_set"])
        self.addCleanup(supervisor.terminate, unit)
        marker = Path(self.inv["root"]) / "ui.txt"
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and marker.read_text() != "SYNTHETIC_PACKAGE_OK":
            time.sleep(.02)
        self.assertEqual(marker.read_text(), "SYNTHETIC_PACKAGE_OK")
        self.provider.changes["idna"] = {"vulnerabilities": [CRITICAL]}
        for index in range(3):
            self.install(event=str(index))
        self.assertTrue(supervisor.state(unit)["confirmed_stopped"])


if __name__ == "__main__":
    unittest.main()
