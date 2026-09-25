import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
import concurrent.futures
import time
from unittest.mock import patch

from ptw.policy import Invalid, approve, compile_policy, digest, load, save
from ptw.project_example import create
from ptw.store import Store, operation_lease
from ptw.workspace import Workspace, request


def concurrent_events(actors):
    """This fixture needs admission overlap; collisions are tested separately."""
    used, events = set(), []
    for actor in actors:
        for i in range(10000):
            event = 'running-' + str(i)
            slot = operation_lease(actor['session'], event)
            if slot not in used:
                used.add(slot)
                events.append(event)
                break
        else:
            raise AssertionError('No distinct operation slot for concurrent fixture')
    return events


def process_identity(pid):
    try:
        fields = (Path('/proc') / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()
        return {'pid': int(pid), 'state': fields[0], 'parent': int(fields[1]), 'start_ticks': fields[19]}
    except (FileNotFoundError, ProcessLookupError):
        return {'pid': int(pid), 'state': 'absent'}


def running_payloads(state):
    """Observe exact executed fixture argv, not a wrapper containing that argv."""
    found = {}
    if state.get('ActiveState') != 'active' or not state.get('ControlGroup'):
        return found
    for membership in Path('/sys/fs/cgroup' + state['ControlGroup']).rglob('cgroup.procs'):
        try:
            pids = membership.read_text().split()
        except FileNotFoundError:
            continue
        for pid in pids:
            before = process_identity(pid)
            try:
                argv = (Path('/proc') / pid / 'cmdline').read_bytes().split(b'\0')[:-1]
            except (FileNotFoundError, ProcessLookupError):
                continue
            if (len(argv) == 4 and argv[:2] == [b'/usr/bin/python3', b'-c'] and
                    argv[3] in (b'ptw-stop-parent', b'ptw-stop-child', b'ptw-stop-unrelated')):
                after = process_identity(pid)
                if (before.get('start_ticks') == after.get('start_ticks') and
                        after['state'] not in ('absent', 'Z')):
                    found.setdefault(argv[3].decode(), []).append(after)
    return found


def unrelated_code(seconds=20):
    # The fixture operator releases this private snapshot only after observing
    # protected cessation. No new mount, capability or unconfined payload.
    return ("import time; from pathlib import Path; gate=Path('src/.release'); "
            f"deadline=time.monotonic()+{seconds!r}\n"
            "while not gate.exists():\n"
            " if time.monotonic() >= deadline: raise RuntimeError('Fixture release deadline')\n"
            " time.sleep(.02)\n"
            "gate.unlink(); Path('src/unrelated.txt').write_text(str(20+22)+'\\n'); "
            "print('UNRELATED_COMPLETED')")


def assert_shared_stop(case, observation, units):
    elapsed = observation['stopped_monotonic'] - observation['started_monotonic']
    case.assertGreaterEqual(elapsed, 0)
    case.assertLess(elapsed, 20, 'Protected payload could have completed naturally')
    for unit in units:
        case.assertIs(observation['after'][unit]['confirmed_stopped'], True)
        case.assertTrue(any(r['at'] >= observation['violations'][-1]['issued_epoch'] and
            r['response'].get('unit') == unit and r['response'].get('confirmed_stopped') is True
            for r in observation['terminations']), 'Missing original termination for ' + unit)
    case.assertEqual(len(observation['processes_after']), 2 * len(units))
    case.assertTrue(all(p['state'] in ('absent', 'Z') for p in observation['processes_after']))


class SharedStopFixtureTests(unittest.TestCase):
    def test_payload_readiness_excludes_wrappers_dead_and_missing_processes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            group = root / 'group'
            group.mkdir()
            (group / 'cgroup.procs').write_text('123\n124\n125\n126\n')
            for pid in (123, 124, 125):
                proc = root / 'proc' / str(pid)
                proc.mkdir(parents=True)
                fields = ['Z' if pid == 125 else 'S', '42', *['0'] * 17, '100']
                (proc / 'stat').write_text(str(pid) + ' (fixture) ' + ' '.join(fields))
                argv = ['/usr/bin/python3', '-c', 'fixture', 'ptw-stop-child']
                if pid == 124:
                    argv = ['launcher', '--', *argv]
                (proc / 'cmdline').write_bytes(('\0'.join(argv) + '\0').encode())
            path = Path
            def mapped(value):
                if value == '/proc': return root / 'proc'
                if value == '/sys/fs/cgroup/fixture': return group
                return path(value)
            with patch(__name__ + '.Path', side_effect=mapped):
                result = running_payloads({'ActiveState': 'active', 'ControlGroup': '/fixture'})
                self.assertEqual(result, {'ptw-stop-child': [
                    {'pid': 123, 'state': 'S', 'parent': 42, 'start_ticks': '100'}]})
                self.assertEqual(running_payloads({'ActiveState': 'inactive', 'ControlGroup': '/fixture'}), {})
                self.assertEqual(running_payloads({'ActiveState': 'active'}), {})

    def test_concurrent_events_avoid_real_collisions_and_bound_failure(self):
        actors = [{'session': 'fixture-' + str(i)} for i in range(4)]
        # Force every first candidate into an occupied slot, while subsequent
        # candidates still use the production mapping.
        lease = operation_lease
        def collide(session, event):
            return 'slot-first' if event == 'running-0' else lease(session, event)
        with patch(__name__ + '.operation_lease', side_effect=collide):
            events = concurrent_events(actors)
            self.assertEqual(len({collide(a['session'], e) for a, e in zip(actors, events)}), 4)
        with patch(__name__ + '.operation_lease', return_value='one-slot'), self.assertRaisesRegex(
                AssertionError, 'No distinct operation slot'):
            concurrent_events(actors)

    def test_unrelated_work_requires_release_and_completes_useful_output(self):
        import subprocess
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'src').mkdir()
            with subprocess.Popen(['/usr/bin/python3', '-c', unrelated_code(5)], cwd=root,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
                try:
                    time.sleep(.1)
                    self.assertIsNone(process.poll())
                    self.assertFalse((root / 'src/unrelated.txt').exists())
                    (root / 'src/.release').touch()
                    output, error = process.communicate(timeout=5)
                    self.assertEqual(process.returncode, 0, error)
                    self.assertEqual(output, 'UNRELATED_COMPLETED\n')
                    self.assertEqual((root / 'src/unrelated.txt').read_text(), '42\n')
                    self.assertFalse((root / 'src/.release').exists())
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate(timeout=5)

    def test_unreleased_unrelated_work_fails_without_useful_output(self):
        import subprocess
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'src').mkdir()
            result = subprocess.run(['/usr/bin/python3', '-c', unrelated_code(.1)], cwd=root,
                                    capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Fixture release deadline', result.stderr)
            self.assertNotIn('UNRELATED_COMPLETED', result.stdout)
            self.assertFalse((root / 'src/unrelated.txt').exists())

    def test_shared_stop_rejects_natural_exit_missing_receipts_and_live_processes(self):
        # Synthetic oracle inputs, not native stop evidence.
        units = ['parent-a', 'parent-b', 'delegate']
        original = {'started_monotonic': 10, 'stopped_monotonic': 15,
            'violations': [{'issued_epoch': 100}],
            'after': {u: {'confirmed_stopped': True} for u in units},
            'processes_after': [{'state': 'absent'} for _ in range(6)],
            'terminations': [{'at': 101, 'response': {'unit': u, 'confirmed_stopped': True}} for u in units]}
        assert_shared_stop(self, original, units)
        for defect in ('natural', 'negative-time', 'missing', 'stale', 'wrong-unit',
                       'unconfirmed-record', 'populated', 'live-child', 'missing-child'):
            with self.subTest(defect=defect):
                row = copy.deepcopy(original)
                if defect == 'natural': row['stopped_monotonic'] = 30
                if defect == 'negative-time': row['stopped_monotonic'] = 9
                if defect == 'missing': row['terminations'].pop()
                if defect == 'stale': row['terminations'][0]['at'] = 99
                if defect == 'wrong-unit': row['terminations'][0]['response']['unit'] = 'unrelated'
                if defect == 'unconfirmed-record': row['terminations'][0]['response']['confirmed_stopped'] = False
                if defect == 'populated': row['after'][units[0]]['confirmed_stopped'] = False
                if defect == 'live-child': row['processes_after'][-1]['state'] = 'S'
                if defect == 'missing-child': row['processes_after'].pop()
                with self.assertRaises(AssertionError):
                    assert_shared_stop(self, row, units)


class WorkspaceFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ptw-workspace-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        create(self.root / "example")
        self.inv = load(self.root / "example/inventory.json")
        self.policy = load(self.root / "example/policy.json")
        self.store = Store(self.root / "state")
        self.store.activate(self.approve())
        self.actor = self.store.register("python-demo", "implementation")
        self.broker = Workspace(self.store)
        self.i = 0

    def approve(self):
        return approve(self.policy, self.inv, digest(compile_policy(self.policy, self.inv)), "fixture operator")

    def ask(self, action, resource="src", path="calculator.py", **kwargs):
        self.i += 1
        return self.broker.request(self.actor["token"], "event-" + str(self.i), request(action, resource, path, **kwargs))


class WorkspaceTests(WorkspaceFixture):
    def test_workspace_compilation_checks_schema_once_and_rejects_invalid_inputs_before_probe(self):
        from ptw import policy, workspace_policy
        from ptw.python_runtime import identify
        self.policy['project']['python_runtime'] = {
            **identify('/usr/bin/python3'), 'requires_python': ''}
        with patch.object(policy, 'validate', wraps=policy.validate) as outer, \
             patch.object(workspace_policy, 'validate', wraps=workspace_policy.validate) as inner:
            compiled = compile_policy(self.policy, self.inv)
        self.assertEqual(compiled, {'policy': self.policy, 'inventory': self.inv})
        calls = outer.call_args_list + inner.call_args_list
        self.assertEqual(sum(call.args[0] is workspace_policy.WORKSPACE_SCHEMA for call in calls), 1)
        for target in ('policy', 'inventory'):
            with self.subTest(target=target):
                proposal, inv = copy.deepcopy(self.policy), copy.deepcopy(self.inv)
                if target == 'policy':
                    proposal['project']['commands'][0]['argv'] = []
                else:
                    inv['resources']['src']['kind'] = 'unreviewed'
                with patch('ptw.python_runtime.verify') as probe, self.assertRaises(Invalid):
                    compile_policy(proposal, inv)
                probe.assert_not_called()

    def test_compilation_rechecks_live_inventory_after_runtime_probe(self):
        from ptw.python_runtime import identify
        runtime = identify('/usr/bin/python3')
        self.policy['project']['python_runtime'] = {**runtime, 'requires_python': ''}
        source = Path(self.inv['root']) / 'src'
        replacement = self.root / 'unreviewed'
        replacement.mkdir()

        def changed(_):
            source.rename(source.with_name('original-src'))
            source.symlink_to(replacement, target_is_directory=True)
            return runtime['executable']

        with patch('ptw.python_runtime.verify', side_effect=changed) as probe, \
             self.assertRaises((Invalid, OSError)):
            compile_policy(self.policy, self.inv)
        probe.assert_called_once()

    def test_read_and_atomic_write(self):
        old = self.ask("read")
        before = (Path(self.inv["root"]) / "src/calculator.py").stat().st_ino
        result = self.ask("write", content="VALUE = 42\n", expected=old["sha256"])
        self.assertTrue(result["allowed"], result)
        self.assertNotEqual(before, (Path(self.inv["root"]) / "src/calculator.py").stat().st_ino)
        self.assertEqual(self.ask("read")["content"], "VALUE = 42\n")

    def test_create_rename_delete(self):
        self.assertTrue(self.ask("create", path="new.txt", content="new")["allowed"])
        sha = self.ask("read", path="new.txt")["sha256"]
        self.assertTrue(self.ask("rename", path="new.txt", expected=sha, destination="src:moved.txt")["allowed"])
        self.assertFalse((Path(self.inv["root"]) / "src/new.txt").exists())
        self.assertTrue(self.ask("delete", path="moved.txt", expected=sha)["allowed"])

    def test_directory_lifecycle(self):
        self.assertTrue(self.ask("mkdir", path="newdir")["allowed"])
        self.assertTrue(self.ask("create", path="newdir/a.txt", content="x")["allowed"])
        self.assertEqual(self.ask("rmdir", path="newdir", expected="directory")["level"], "blocked")
        self.assertTrue(self.ask("delete", path="newdir/a.txt", expected=hashlib.sha256(b"x").hexdigest())["allowed"])
        self.assertTrue(self.ask("rmdir", path="newdir", expected="directory")["allowed"])

    def test_directory_rename_preserves_files(self):
        self.ask("mkdir", path="first")
        self.ask("create", path="first/a.txt", content="preserved")
        result = self.ask("rename", path="first", expected="directory", destination="src:second")
        self.assertTrue(result["allowed"], result)
        self.assertEqual((Path(self.inv["root"]) / "src/second/a.txt").read_text(), "preserved")
        self.assertFalse((Path(self.inv["root"]) / "src/first").exists())

    def test_stale_edit_is_not_violation(self):
        old = self.ask("read")["sha256"]
        self.ask("write", content="first", expected=old)
        result = self.ask("write", content="second", expected=old)
        self.assertEqual(result["level"], "conflict")
        self.assertEqual(self.store.status("python-demo")["violations"], 0)

    def test_new_file_cannot_overwrite(self):
        self.assertEqual(self.ask("create", content="oops")["level"], "conflict")

    def test_read_only_task_cannot_write(self):
        self.actor = self.store.register("python-demo", "readcheck")
        self.assertEqual(self.ask("write", content="oops")["level"], "warn")

    def test_readonly_rename_destination(self):
        old = self.ask("read")["sha256"]
        result = self.ask("rename", expected=old, destination="tests:stolen.py")
        self.assertFalse(result["allowed"])
        self.assertTrue((Path(self.inv["root"]) / "src/calculator.py").exists())

    def test_project_root_cannot_be_deleted(self):
        result = self.ask("rmdir", resource="dist", path="", expected="directory")
        self.assertFalse(result["allowed"])

    def test_traversal(self):
        for path in ["../private/customer.txt", "/etc/passwd", "a//b", "a/./b", "a\\b"]:
            with self.subTest(path=path):
                self.assertFalse(self.ask("read", path=path)["allowed"])

    def test_symlink_and_hardlink(self):
        repo = Path(self.inv["root"])
        (repo / "src/link").symlink_to(repo / "private/customer.txt")
        result = self.ask("read", path="link")
        self.assertFalse(result["allowed"])
        self.assertNotIn("SYNTHETIC_CUSTOMER", str(result))

    def test_hardlink(self):
        repo = Path(self.inv["root"])
        os.link(repo / "private/customer.txt", repo / "src/link")
        self.assertFalse(self.ask("read", path="link")["allowed"])

    def test_same_event_returns_original(self):
        req = request("create", "src", "once.txt", "once")
        a = self.broker.request(self.actor["token"], "once", req)
        b = self.broker.request(self.actor["token"], "once", req)
        self.assertTrue(a["allowed"])
        self.assertTrue(b["replayed"])
        with self.assertRaises(Invalid):
            self.broker.request(self.actor["token"], "once", request("create", "src", "different"))

    def test_narrow_task_and_delegate_commands(self):
        with self.assertRaises(Invalid):
            self.store.register("python-demo", "readcheck", commands=["not-approved"])
        narrow = self.store.register("python-demo", "readcheck")
        with self.assertRaises(Invalid):
            self.store.register("python-demo", "implementation", parent_token=narrow["token"])

    def test_multiple_parents_and_child_share_stop(self):
        second = self.store.register("python-demo", "verification")
        child = self.store.register("python-demo", "readcheck", parent_token=self.actor["token"])
        for i, actor in enumerate([self.actor, second, child]):
            result = self.broker.request(actor["token"], "denied", request("read", "private", "customer.txt"))
            self.assertEqual(result["level"], "stop" if i == 2 else "warn")
        self.assertEqual(self.ask("read")["level"], "stop")
        with self.assertRaises(Invalid):
            self.store.register("python-demo", "implementation")

    def test_command_not_in_scope(self):
        self.assertEqual(self.ask("run", resource="unknown", path="")["level"], "warn")

    def test_invalid_policy_overlap(self):
        self.inv["resources"]["overlap"] = {"path": "src/calculator.py", "kind": "file", "description": "overlap"}
        with self.assertRaises(Invalid):
            compile_policy(self.policy, self.inv)

    def test_policy_cannot_expand_command_or_package(self):
        self.policy["tasks"][0]["commands"].append("unlisted")
        with self.assertRaises(Invalid):
            compile_policy(self.policy, self.inv)

    def test_crash_after_intent_stops_and_is_not_replayed(self):
        with patch("ptw.workspace.publish", side_effect=SystemExit("interrupted")):
            with self.assertRaises(SystemExit):
                self.ask("create", path="interrupted.txt", content="x")
        recovered = Store(self.root / "state")
        self.assertTrue(recovered.status("python-demo")["stopped"])
        self.assertFalse((Path(self.inv["root"]) / "src/interrupted.txt").exists())

    def test_failed_publication_stops(self):
        with patch("ptw.workspace.publish", side_effect=OSError("disk failure")):
            result = self.ask("create", path="failed.txt", content="x")
        self.assertEqual(result["level"], "stop")
        self.assertTrue(self.store.status("python-demo")["stopped"])

    def test_legacy_route_cannot_bypass_preconditions(self):
        with self.assertRaises(Invalid):
            self.store.request(self.actor["token"], "legacy", {"action": "write", "resource": "dependencies", "content": "x"})

    def test_dispatch_package_input_must_be_readable(self):
        from ptw.workflow import dispatch
        result = dispatch(self.store, self.actor, "install-private", request("install", "private", "customer.txt", content="pypi"))
        self.assertFalse(result["allowed"])
        self.assertEqual(self.store.status("python-demo")["violations"], 1)
        replay = dispatch(self.store, self.actor, "install-private", request("install", "private", "customer.txt", content="pypi"))
        self.assertTrue(replay["replayed"])
        self.assertEqual(self.store.status("python-demo")["violations"], 1)

    def test_dispatch_delegate_has_no_token_and_replays(self):
        from ptw.workflow import dispatch
        req = request("delegate", "readcheck", content="Review without writing")
        result = dispatch(self.store, self.actor, "delegate", req)
        self.assertTrue(result["allowed"], result)
        self.assertNotIn("token", result["child"])
        again = dispatch(self.store, self.actor, "delegate", req)
        self.assertEqual(result["child"]["session"], again["child"]["session"])
        self.assertEqual(len(self.store.status("python-demo")["sessions"]), 2)

    def test_delegate_scope_expansion_counts_once(self):
        from ptw.workflow import dispatch
        actor = self.store.register("python-demo", "readcheck")
        req = request("delegate", "implementation", content="Try wider access")
        result = dispatch(self.store, actor, "delegate", req)
        self.assertEqual(result["level"], "warn")
        self.assertEqual(self.store.status("python-demo")["violations"], 1)

    def test_new_declared_top_level_file(self):
        self.policy["project"]["id"] = "newfile"
        self.inv["resources"]["new"] = {"path": "NEW.md", "kind": "file", "description": "Future release note"}
        for item in [self.policy["project"], self.policy["tasks"][0]]:
            item["grants"].append({"resource": "new", "actions": ["read", "create", "write", "delete"]})
        self.store.activate(self.approve())
        self.actor = self.store.register("newfile", "implementation")
        self.assertTrue(self.ask("create", resource="new", path="", content="created")["allowed"])
        read = self.ask("read", resource="new", path="")
        self.assertEqual(read["content"], "created")
        self.assertTrue(self.ask("delete", resource="new", path="", expected=read["sha256"])["allowed"])
        self.assertTrue(self.ask("create", resource="new", path="", content="recreated")["allowed"])

    def test_command_conflict_does_not_publish(self):
        from ptw.workspace import scan
        before = scan(self.inv, ["src", "tests"])
        after = copy.deepcopy(before)
        after["src/calculator.py"]["data"] = b"stale"
        def execute(*args, **kwargs):
            path = Path(self.inv["root"]) / "src/calculator.py"
            path.write_text("concurrent operator edit")
            return after, {"exit_code": 0, "output": "", "output_truncated": False}
        with patch("ptw.execution.execute", side_effect=execute):
            result = self.ask("run", resource="test", path="")
        self.assertEqual(result["level"], "conflict")
        self.assertEqual((Path(self.inv["root"]) / "src/calculator.py").read_text(), "concurrent operator edit")

    def test_stop_during_command_prevents_publication(self):
        from ptw.workspace import scan
        after = scan(self.inv, ["src", "tests"])
        after["src/calculator.py"]["data"] = b"never publish"
        def execute(*args, **kwargs):
            self.store.stop("python-demo")
            return after, {"exit_code": 0, "output": "", "output_truncated": False}
        with patch("ptw.execution.execute", side_effect=execute):
            result = self.ask("run", resource="test", path="")
        self.assertEqual(result["level"], "stop")
        self.assertNotEqual((Path(self.inv["root"]) / "src/calculator.py").read_bytes(), b"never publish")


@unittest.skipUnless(os.environ.get("PTW_LINUX_TESTS") == "1", "Explicit isolated VPS opt in")
class WorkspaceLinux(WorkspaceFixture):
    def add_command(self, code, resources=None):
        # New synthetic project per test; no mutation of an active policy.
        self.policy["project"]["id"] = "command-demo"
        self.policy["project"]["commands"].append({"id": "probe", "argv": ["/usr/bin/python3", "-c", code],
            "resources": resources or ["src", "tests", "dist"], "timeout_seconds": 5})
        self.policy["tasks"][0]["commands"].append("probe")
        self.store.activate(self.approve())
        self.actor = self.store.register("command-demo", "implementation")

    def test_real_command_edits_and_creates(self):
        self.add_command("from pathlib import Path; p=Path('src/calculator.py'); p.write_text('ANSWER=42\\n'); "
                         "Path('dist/output.txt').write_text('built'); print('REAL_COMMAND_OK')")
        result = self.ask("run", resource="probe", path="")
        self.assertTrue(result["allowed"], result)
        self.assertEqual(result["exit_code"], 0, result)
        self.assertIn("REAL_COMMAND_OK", result["output"])
        self.assertEqual((Path(self.inv["root"]) / "dist/output.txt").read_text(), "built")

    def test_forbidden_output_publishes_nothing(self):
        self.add_command("from pathlib import Path; Path('src/new.txt').write_text('ok'); Path('tests/forbidden.txt').write_text('no')")
        result = self.ask("run", resource="probe", path="")
        self.assertFalse(result["allowed"], result)
        self.assertFalse((Path(self.inv["root"]) / "src/new.txt").exists())
        self.assertFalse((Path(self.inv["root"]) / "tests/forbidden.txt").exists())

    def test_host_secrets_network_controller_hidden(self):
        self.add_command("import os,socket; from pathlib import Path; "
                         f"assert not Path({str(self.store.directory)!r}).exists(); "
                         "assert not Path('private/customer.txt').exists(); "
                         "assert 'PTW_SYNTHETIC_SECRET' not in os.environ; "
                         "\ntry: socket.create_connection(('1.1.1.1',443),.1)\nexcept OSError: print('BOUNDARY_OK')\nelse: raise Exception('network')")
        with patch.dict(os.environ, {"PTW_SYNTHETIC_SECRET": "PRIVATE"}):
            result = self.ask("run", resource="probe", path="")
        self.assertTrue(result["allowed"], result)
        self.assertEqual(result["exit_code"], 0, result)
        self.assertIn("BOUNDARY_OK", result["output"])

    def test_nonzero_test_exit_is_not_misconduct(self):
        self.add_command("print('EXPECTED_TEST_FAILURE'); raise SystemExit(7)")
        result = self.ask("run", resource="probe", path="")
        self.assertTrue(result["allowed"], result)
        self.assertEqual(result["exit_code"], 7)
        self.assertEqual(self.store.status("command-demo")["violations"], 0)

    def test_unknown_output_rejected(self):
        self.add_command("open('unregistered.txt','w').write('no')")
        self.assertFalse(self.ask("run", resource="probe", path="")["allowed"])

    def test_output_symlink_rejected(self):
        self.add_command("import os; os.symlink('/etc/passwd','src/leak')")
        result = self.ask("run", resource="probe", path="")
        self.assertFalse(result["allowed"], result)
        self.assertEqual(result["level"], "warn")
        self.assertFalse((Path(self.inv["root"]) / "src/leak").exists())

    def test_foreign_package_set_counts_as_scope_violation(self):
        self.add_command("print('never run')")
        result = self.ask("run", resource="probe", path="", content='{"package_sets":["pkg_000000000000000000000000"]}')
        self.assertEqual(result["level"], "warn")

    def test_nested_file_command_scaffold_is_not_permission(self):
        self.inv["resources"].pop("src")
        self.inv["resources"]["code"] = {"path": "src/calculator.py", "kind": "file", "description": "one exact file"}
        for layer in [self.policy["project"], *self.policy["tasks"]]:
            for grant in layer["grants"]:
                if grant["resource"] == "src":
                    grant["resource"] = "code"
        for command in self.policy["project"]["commands"]:
            command["resources"] = ["code" if r == "src" else r for r in command["resources"]]
        self.add_command("p='src/calculator.py'; open(p,'w').write('ANSWER=42'); print('NESTED_OK')", ["code"])
        result = self.ask("run", resource="probe", path="")
        self.assertTrue(result["allowed"], result)
        self.assertEqual((Path(self.inv["root"]) / "src/calculator.py").read_text(), "ANSWER=42")

    def test_actual_running_parents_child_stop_unrelated_survives(self):
        from ptw.supervisor import Supervisor
        # Each command also starts an independent subprocess within its cgroup.
        descendant = ['/usr/bin/python3', '-c', 'import time; time.sleep(20)', 'ptw-stop-child']
        self.policy["project"]["commands"].append({"id": "wait", "argv": ["/usr/bin/python3", "-c",
            f"import subprocess,time; subprocess.Popen({descendant!r}); time.sleep(20)", 'ptw-stop-parent'],
            "resources": ["src"], "timeout_seconds": 30})
        for task in self.policy["tasks"]:
            task["commands"].append("wait")
        self.policy["project"]["id"] = "running"
        self.store.activate(self.approve())
        a = self.store.register("running", "implementation")
        b = self.store.register("running", "verification")
        child = self.store.register("running", "readcheck", parent_token=a["token"])
        self.policy["project"]["id"] = "unrelated"
        self.policy["project"]["commands"][-1]["argv"] = [
            "/usr/bin/python3", "-c", unrelated_code(), 'ptw-stop-unrelated']
        self.store.activate(self.approve())
        other = self.store.register("unrelated", "implementation")
        actors = [a, b, child, other]
        events = concurrent_events(actors)
        evidence = Path(tempfile.mkdtemp(prefix='ptw-workspace-stop-evidence-'))
        print('WORKSPACE_STOP_EVIDENCE ' + str(evidence), flush=True)
        source = Path(__file__).resolve().parents[1]
        save(evidence / 'source.json', {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in [*sorted((source / 'ptw').rglob('*.py')), Path(__file__).resolve()]})
        observation = {'launches': [{'session': actor['session'], 'project': actor['project'],
            'event': event, 'slot': operation_lease(actor['session'], event)} for actor, event in zip(actors, events)],
            'escalation': self.policy['project']['escalation'], 'violations': []}
        self.addCleanup(save, evidence / 'stop.json', observation)
        self.assertEqual(observation['escalation'], {'warn_at': 1, 'stop_at': 3})
        futures = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            try:
                observation['started_monotonic'] = time.monotonic()
                futures = [pool.submit(self.broker.request, actor['token'], event, request('run', 'wait'))
                           for actor, event in zip(actors, events)]
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    projects = {name: self.store.status(name) for name in ('running', 'unrelated')}
                    states = {w['unit']: Supervisor.state(w['unit']) for p in projects.values() for w in p['workloads']}
                    payloads = {u: running_payloads(s) for u, s in states.items()}
                    observation['readiness'] = {'projects': projects, 'states': states, 'payloads': payloads}
                    # A finished launch is failure, including a raised exception.
                    self.assertFalse(any(f.done() for f in futures), 'Work ended before concurrent readiness')
                    units = [w['unit'] for w in projects['running']['workloads']]
                    others = [w['unit'] for w in projects['unrelated']['workloads']]
                    if (len(units) == 3 and len(others) == 1 and
                            all(len(payloads[u].get(role, [])) == 1 for u in units
                                for role in ('ptw-stop-parent', 'ptw-stop-child')) and
                            len(payloads[others[0]].get('ptw-stop-unrelated', [])) == 1):
                        break
                    time.sleep(.05)
                else:
                    self.fail('Concurrent payload readiness deadline; inspect stop.json')
                observation['ready_monotonic'] = time.monotonic()
                for unit in units:
                    parent, desc = (payloads[unit][role][0] for role in ('ptw-stop-parent', 'ptw-stop-child'))
                    self.assertEqual(desc['parent'], parent['pid'])
                unrelated_pid = payloads[others[0]]['ptw-stop-unrelated'][0]['pid']
                for i, actor in enumerate([a, b, child], 1):
                    # Require actual concurrency immediately before each denial.
                    self.assertFalse(any(f.done() for f in futures))
                    live = {u: Supervisor.state(u) for u in states}
                    self.assertTrue(all(s.get('ActiveState') == 'active' for s in live.values()))
                    issued = time.time()
                    result = self.broker.request(actor['token'], 'forbidden', request('read', 'private', 'customer.txt'))
                    status = self.store.status('running')
                    observation['violations'].append({'issued_epoch': issued, 'result': result,
                                                      'status': status, 'before': live})
                    self.assertFalse(result['allowed'])
                    self.assertEqual(result['level'], 'stop' if i == 3 else 'warn')
                    self.assertEqual(status['violations'], i)
                    self.assertEqual(bool(status['stopped']), i == 3)
                for result in [f.result(timeout=15) for f in futures[:3]]:
                    self.assertFalse(result["allowed"], result)
                    self.assertEqual(result['level'], 'stop', result)
                observation['after'] = {u: Supervisor.state(u) for u in states}
                observation['processes_after'] = [process_identity(p['pid']) for u in units
                    for rows in payloads[u].values() for p in rows]
                observation['stopped_monotonic'] = time.monotonic()
                with self.store.locked() as db:
                    observation['terminations'] = [{'at': r['at'], 'response': json.loads(r['response'])}
                        for r in db.execute("SELECT at,response FROM events WHERE session='controller:running' "
                            "AND json_extract(request_meta,'$.action')='workload_termination'")]
                assert_shared_stop(self, observation, units)
                self.assertFalse(futures[3].done(), 'Unrelated work ended before protected cessation')
                self.assertEqual(observation['after'][others[0]]['ActiveState'], 'active')
                continued = running_payloads(observation['after'][others[0]]).get('ptw-stop-unrelated', [])
                observation['unrelated_after'] = continued
                self.assertEqual(len(continued), 1)
                for key in ('pid', 'start_ticks'):
                    self.assertEqual(continued[0][key], payloads[others[0]]['ptw-stop-unrelated'][0][key])
                # This is an operator fixture handshake inside the command's
                # existing disposable src tree, never a grant to the payload.
                (Path('/proc') / str(unrelated_pid) / 'root/target/src/.release').touch()
                unrelated = futures[3].result(timeout=15)
                observation['unrelated_result'] = unrelated
                self.assertTrue(unrelated["allowed"], unrelated)
                self.assertEqual(unrelated['exit_code'], 0, unrelated)
                self.assertIn("UNRELATED_COMPLETED", unrelated["output"])
                self.assertEqual((Path(self.inv['root']) / 'src/unrelated.txt').read_text(), '42\n')
                self.assertTrue(all(w["stopped"] for w in self.store.status("running")["workloads"]))
                self.assertFalse(self.store.status("unrelated")["stopped"])
                self.assertEqual(self.store.status('unrelated')['violations'], 0)
            except BaseException as exc:
                observation['failure_type'] = type(exc).__name__
                raise
            finally:
                # Run before executor shutdown waits, also after partial launch.
                # Keep the first failure; cleanup errors must still fail a pass.
                cleanup_errors = []
                for name in ('running', 'unrelated'):
                    try:
                        self.store.stop(name)
                    except Exception as exc:
                        cleanup_errors.append(type(exc).__name__)
                try:
                    Supervisor(self.store).reconcile()
                except Exception as exc:
                    cleanup_errors.append(type(exc).__name__)
                observation['cleanup_errors'] = cleanup_errors
                observation['futures'] = []
                for future in futures:
                    row = {'done': future.done()}
                    if row['done']:
                        error = future.exception()
                        row['error_type'] = type(error).__name__ if error else None
                        if error:
                            message = str(error)
                            for actor in actors:
                                message = message.replace(actor['token'], '[fixture-token]')
                            row['error'] = message[:400]
                        if not error:
                            result = future.result()
                            row.update({k: result[k] for k in ('allowed', 'level', 'exit_code') if k in result})
                    observation['futures'].append(row)
                if cleanup_errors and 'failure_type' not in observation:
                    self.fail('Fixture cleanup failed: ' + repr(cleanup_errors))
