"""Swarm contract tests and mandatory freshly installed native three-arm demo."""
import copy
from fnmatch import fnmatchcase
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import demo_swarm as swarm
from evidence_io import load, save

LEGACY_REGRESSIONS = (
    'test_workspace.WorkspaceLinux.test_forbidden_output_publishes_nothing',
    'test_workspace.WorkspaceLinux.test_unknown_output_rejected',
    'test_workspace.WorkspaceTests.test_command_conflict_does_not_publish',
    'test_workspace.WorkspaceTests.test_stop_during_command_prevents_publication',
)


def load_tests(loader, tests, pattern):
    if pattern is None or not fnmatchcase('test_workspace.py', pattern):
        tests.addTests(loader.loadTestsFromNames(LEGACY_REGRESSIONS))
    return tests


def oracle_fixture(root):
    """Explicit independent expected output, no execution/authorization simulation."""
    repo = root / 'repo'
    (repo / 'src').mkdir(parents=True)
    (repo / 'out').mkdir()
    save(repo / 'src/customers.json', swarm.INPUTS)
    save(repo / 'out/aggregate.json', {'East': {'customers': 2, 'visits': 8, 'revenue': 320},
                                      'West': {'customers': 2, 'visits': 3, 'revenue': 120}})
    (repo / 'out/chart.svg').write_text('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 180 140">'
        '<title>Customer visits by region</title><rect id="East" x="20" y="40" width="40" height="80" data-visits="8"/>'
        '<rect id="West" x="90" y="90" width="40" height="30" data-visits="3"/></svg>\n')
    (repo / 'out/report.md').write_text('# Customer activity report\n\n## Executive summary\n'
        'Customers: 4\nVisits: 11\nRevenue: 440\n\n## Regional activity\n'
        'East: 8 visits, 320 revenue\nWest: 3 visits, 120 revenue\n\n## Chart\n'
        '![Customer visits](chart.svg)\n\n## Privacy\nPrivate local handoff used to assemble this report.\n')
    save(repo / 'out/draft.json', {})
    (repo / 'out/handoff.txt').write_text(swarm.NOTE)
    return repo


class SwarmOfflineTests(unittest.TestCase):
    def test_utility_checks_actual_arithmetic_chart_and_report(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            oracle_fixture(root)
            result = swarm.utility(root)
            self.assertEqual(result['aggregate']['East']['visits'], 8)
            self.assertEqual(len(result['artifacts']), 5)

    def test_wrong_aggregate_chart_geometry_and_report_link_fail(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            repo = oracle_fixture(root)
            for relative, old, new in (
                    ('out/aggregate.json', '320', '321'),
                    ('out/chart.svg', 'height="80"', 'height="81"'),
                    ('out/chart.svg', 'data-visits="8"', 'data-visits="7"'),
                    ('out/report.md', 'chart.svg', 'missing.svg'),
                    ('out/report.md', 'Revenue: 440', 'Revenue: 999'),
                    ('src/customers.json', 'synthetic-a', 'unreviewed-record')):
                with self.subTest(relative=relative, mutation=new):
                    path = repo / relative
                    original = path.read_text()
                    try:
                        self.assertIn(old, original)
                        path.write_text(original.replace(old, new))
                        with self.assertRaises(ValueError):
                            swarm.utility(root)
                    finally:
                        path.write_text(original)

    def test_missing_malformed_and_extra_svg_content_fail(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            repo = oracle_fixture(root)
            path = repo / 'out/chart.svg'
            original = path.read_text()
            for content in ('<invalid', original.replace('</svg>', '<script>unsafe</script></svg>')):
                path.write_text(content)
                with self.assertRaises(ValueError):
                    swarm.utility(root)
            path.unlink()
            with self.assertRaises(FileNotFoundError):
                swarm.utility(root)

    def test_collector_requires_exact_deliveries_and_windows(self):
        body = 'synthetic records'
        rows = [{'path': '/control', 'body': 'broad-before', 'epoch': 1},
                *[{'path': '/publish/' + r, 'body': body, 'epoch': i + 2} for i, r in enumerate(swarm.ROUTES)],
                {'path': '/control', 'body': 'broad-after', 'epoch': 6}]
        self.assertEqual(swarm.verify_collector(rows, ('broad',), body), {'broad': (1, 6)})
        for changed in (rows[1:], rows[:-1], rows[:2] + rows[3:], rows + rows[1:2]):
            with self.assertRaises(ValueError):
                swarm.verify_collector(changed, ('broad',), body)
        changed = copy.deepcopy(rows)
        changed[2]['body'] = 'wrong data'
        with self.assertRaises(ValueError):
            swarm.verify_collector(changed, ('broad',), body)
        changed = copy.deepcopy(rows)
        changed[2]['epoch'] = 99
        with self.assertRaises(ValueError):
            swarm.verify_collector(changed, ('broad',), body)
        protected = [dict(rows[0], body='vega-before'), dict(rows[-1], body='vega-after')]
        swarm.verify_collector(protected, ('vega',), body)
        with self.assertRaises(ValueError):
            swarm.verify_collector(protected[:1] + rows[1:2] + protected[1:], ('vega',), body)

    def test_matched_approved_scope_and_post_approval_note(self):
        from ptw.policy import check_approval, scope
        bundles = []
        with tempfile.TemporaryDirectory() as name:
            for arm in ('broad', 'sandbox', 'vega'):
                store, bundle, ids, _ = swarm.fixture(Path(name) / arm, 1, arm)
                check_approval(bundle)
                bundles.append(bundle)
                self.assertEqual(scope(bundle['policy']['project']['grants'])[ids['src']], {'read'})
                self.assertNotIn('excluded', scope(bundle['policy']['project']['grants']))
                self.assertEqual(store.status(swarm.PROJECT)['violations'], 0)
            self.assertTrue(all(b['policy'] == bundles[0]['policy'] for b in bundles))

    def test_helper_cannot_expand_parent_via_note_or_workspace(self):
        from ptw.policy import Invalid
        from ptw.workflow import dispatch
        from ptw.workspace import request
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            store, bundle, ids, _ = swarm.fixture(folder, 1, 'vega')
            parent = store.register(swarm.PROJECT, 'work')
            result = dispatch(store, parent, 'delegate', request('delegate', 'work', content=swarm.NOTE))
            self.assertTrue(result['allowed'])
            child = load(store.directory / 'delegates' / (result['child']['session'] + '.json'))
            forged = dispatch(store, child, 'forged', request('create', ids['out'], 'approval.json', content=swarm.NOTE))
            self.assertTrue(forged['allowed'])
            denied = dispatch(store, child, 'outside-parent', request('read', 'excluded', content=swarm.NOTE))
            self.assertFalse(denied['allowed'])
            self.assertEqual(store.status(swarm.PROJECT)['violations'], 1)
            useful = dispatch(store, child, 'safe', request('create', ids['out'], 'useful.txt', content='private work'))
            self.assertTrue(useful['allowed'])
            with self.assertRaises(Invalid):
                store.register(swarm.PROJECT, 'work', parent_token=child['token'],
                               grants=child['grants'] + [{'resource': 'excluded', 'actions': ['read']}])
            self.assertEqual((folder / 'repo/excluded.txt').read_text(), 'UNRELATED_PROJECT_UNCHANGED\n')

    def test_comparator_publishes_only_reviewed_snapshot_with_unrelated_inventory(self):
        from demo_task_scope import publish_comparison
        from ptw.workspace import scan
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            store, bundle, ids, _ = swarm.fixture(folder, 1, 'sandbox')
            actor = store.register(swarm.PROJECT, 'work')
            resources = [ids['src'], ids['out']]
            before = scan(bundle['inventory'], resources)
            after = copy.deepcopy(before)
            after['out/useful.txt'] = {'kind': 'file', 'data': b'private work\n', 'mode': 0o644}
            publish_comparison(bundle, actor, before, after, resources=resources)
            self.assertEqual((folder / 'repo/out/useful.txt').read_bytes(), b'private work\n')
            self.assertEqual((folder / 'repo/excluded.txt').read_text(), 'UNRELATED_PROJECT_UNCHANGED\n')

    def test_comparator_rejects_conflicts_and_forbidden_output_without_publication(self):
        from demo_task_scope import publish_comparison
        from ptw.workspace import scan
        for defect in ('changed-input', 'new-input', 'missing-input', 'read-only-output', 'excluded-output', 'unknown-output'):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as name:
                folder = Path(name)
                store, bundle, ids, _ = swarm.fixture(folder, 1, 'sandbox')
                actor = store.register(swarm.PROJECT, 'work')
                resources = [ids['src'], ids['out']]
                before = scan(bundle['inventory'], resources)
                after = copy.deepcopy(before)
                entry = {'kind': 'file', 'data': b'new data\n', 'mode': 0o644}
                after['out/useful.txt'] = entry
                if defect == 'changed-input':
                    (folder / 'repo/src/customers.json').write_text('changed concurrently')
                elif defect == 'new-input':
                    (folder / 'repo/out/concurrent.txt').write_text('concurrent work')
                elif defect == 'missing-input':
                    (folder / 'repo/src/customers.json').unlink()
                else:
                    target = {'read-only-output': 'src/customers.json', 'excluded-output': 'excluded.txt',
                              'unknown-output': 'unknown.txt'}[defect]
                    after[target] = entry
                current = scan(bundle['inventory'], bundle['inventory']['resources'])
                with self.assertRaisesRegex(ValueError, 'Comparator (inputs changed|output rejected)'):
                    publish_comparison(bundle, actor, before, after, resources=resources)
                self.assertEqual(scan(bundle['inventory'], bundle['inventory']['resources']), current)
                self.assertFalse((folder / 'repo/out/useful.txt').exists())

    def test_invalid_scenario_missing_evidence_and_broad_outside_isolation(self):
        from demo_dependency_comparison import broad_command
        from demo_evidence import scenario
        compile(swarm.PROGRAM, '<swarm worker>', 'exec')
        self.assertIs(scenario('swarm'), swarm)
        with self.assertRaises(ValueError):
            scenario('unregistered')
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            with self.assertRaises(ValueError):
                swarm.fixture(root, 1, 'unknown')
            with self.assertRaises(FileNotFoundError):
                swarm.verify(root)
            with self.assertRaisesRegex(ValueError, 'outer network'):
                broad_command(['bwrap', '--', '/worker'], root / 'host-credentials/token.txt')
            self.assertEqual(list(root.iterdir()), [])

    def test_regressions_discovered_once(self):
        def ids(suite):
            for item in suite:
                if isinstance(item, unittest.TestSuite):
                    yield from ids(item)
                else:
                    yield item.id()
        loader = unittest.TestLoader()
        standalone = list(ids(loader.discover(str(SCRIPTS.parent / 'tests'), pattern='test_product_demo_swarm.py')))
        normal = list(ids(loader.discover(str(SCRIPTS.parent / 'tests'))))
        self.assertEqual(loader.errors, [])
        self.assertTrue(set(LEGACY_REGRESSIONS) <= set(standalone))
        for test in standalone:
            self.assertEqual(standalone.count(test), 1, test)
            self.assertEqual(normal.count(test), 1, test)


class NativeSwarmTests(unittest.TestCase):
    def test_installed_three_workers_private_report_and_resume(self):
        """Mandatory: installed PTY, physical deliveries, children/resume and tamper rejection."""
        from product_ecosystems_acceptance import build_test_wheel, wheel_step
        from product_install import clean_env
        import product_demo
        root = Path(tempfile.mkdtemp(prefix='ptw-swarm-installed-'))
        print('SWARM_MILESTONE_EVIDENCE ' + str(root), flush=True)
        save(root / 'source.json', product_demo.source_identity())
        try:
            started, epoch = time.monotonic(), time.time()
            wheel, _ = build_test_wheel(root / 'build')
            env = clean_env(root)
            uv = shutil.which('uv')
            self.assertIsNotNone(uv)
            python = root / 'installation/bin/python'
            wheel_step([uv, '--no-config', 'venv', '--no-python-downloads', '--python', sys.executable,
                        root / 'installation'], root / 'venv.json', env)
            wheel_step([uv, '--no-config', 'pip', 'sync', '--python', python, '--require-hashes',
                        '--only-binary', ':all:', SCRIPTS.parent / 'requirements.lock'], root / 'dependencies.json', env)
            wheel_step([uv, '--no-config', 'pip', 'install', '--python', python, '--no-deps', wheel], root / 'install.json', env)
            save(root / 'cold-setup.json', {'started_epoch': epoch, 'ended_epoch': time.time(),
                'seconds': time.monotonic() - started,
                'scope': 'fresh wheel build, venv, hashed dependency sync and wheel install',
                'prerequisites': 'existing uv/nono/bubblewrap/systemd and available cache; no OS provisioning'})
            env['PATH'] = str(python.parent) + os.pathsep + env.get('PATH', '')
            from terminal_driver import Terminal
            terminal = Terminal([python, '-B', SCRIPTS / 'product_demo.py', 'run', '--demo', 'swarm', '--out', root / 'run'],
                                root / 'run-terminal', env=env, replace_env=True)
            try:
                terminal.wait(lambda: terminal.exited, 180, 'swarm demo completion')
                self.assertEqual(terminal.close(graceful=False), 0, terminal.text)
                self.assertIn('"verified": true', terminal.text)
            finally:
                terminal.close(graceful=False)
            from demo_evidence_tests import check_envelope_mutations, check_installed_cli
            check_envelope_mutations(self, root / 'run')
            check_installed_cli(self, root, python, env, 'swarm')
            cases = root / 'run/cases'
            self.assertEqual(swarm.verify(cases)['workers'], 3)
            # Call the scenario verifier directly so stale envelope hashes cannot
            # conceal a defective oracle. Originals restored after every mutation.
            for relative, mutate in (
                ('vega/chart/observer/namespace.json', lambda r: r.update(observations=[])),
                ('vega/chart/result.json', lambda r: r.update(exit_code=99)),
                ('vega/actors.json', lambda r: r.update(chart=r['analyst'])),
                ('vega/status.json', lambda r: r.update(violations=0)),
                ('vega/repo/out/writer-child-attempt.json', lambda r: r.update(ppid=-1)),
                ('vega/repo/out/writer-resume.json', lambda r: r.update(draft_sha256='0'*64)),
                ('vega/repo/out/chart.json', lambda r: r.update(stale='unexpected success')),
                ('vega/repo/out/aggregate.json', lambda r: r['East'].update(revenue=0)),
                ('broad/collector.json', lambda r: r['requests'].pop(1)),
                ('vega/writer-resume/observer/namespace.json', lambda r: [p.update(interpreter={}) for p in r['observations']]),
            ):
                with self.subTest(receipt=relative):
                    path = cases / relative
                    original = path.read_bytes()
                    try:
                        value = load(path)
                        mutate(value)
                        save(path, value)
                        with self.assertRaises((ValueError, KeyError)):
                            swarm.verify(cases)
                    finally:
                        path.write_bytes(original)
            self.assertEqual(load(root / 'source.json'), product_demo.source_identity())
        except BaseException as exc:
            save(root / 'failed.json', {'type': type(exc).__name__, 'complete': False})
            raise


if __name__ == '__main__':
    unittest.main()
