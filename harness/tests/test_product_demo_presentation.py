"""CLI/Markdown acceptance; the historical check name remains compatible.

Native evidence comes from the existing installed demos and report lifecycle,
never from synthetic formatting fixtures. No presentation application is required.
"""
from fnmatch import fnmatchcase
import importlib
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import product_demo
from demo_evidence import LABEL, public_sample
from evidence_io import save

DEMO_MODULES = ('test_product_demo', 'test_product_demo_dependency',
                'test_product_demo_task_scope', 'test_product_demo_swarm')


def load_tests(loader, tests, pattern):
    # Include each existing suite once for this standalone gate. Full discovery
    # loads those modules itself. Their shared workspace regressions belong to
    # test_workspace; suppress nested selection and add them once below.
    for name in DEMO_MODULES:
        if pattern is None or not fnmatchcase(name + '.py', pattern):
            tests.addTests(loader.loadTestsFromModule(importlib.import_module(name), pattern='test*.py'))
    if pattern is None or not fnmatchcase('test_workspace.py', pattern):
        from test_product_demo_swarm import LEGACY_REGRESSIONS
        tests.addTests(loader.loadTestsFromNames(LEGACY_REGRESSIONS))
    return tests


class PresentationOfflineTests(unittest.TestCase):
    def test_gate_keeps_all_demos_and_security_regressions_once(self):
        def ids(suite):
            for item in suite:
                if isinstance(item, unittest.TestSuite):
                    yield from ids(item)
                else:
                    yield item.id()
        loader = unittest.TestLoader()
        standalone = list(ids(loader.discover(str(SCRIPTS.parent / 'tests'),
                                             pattern='test_product_demo_presentation.py')))
        normal = list(ids(loader.discover(str(SCRIPTS.parent / 'tests'))))
        self.assertEqual(loader.errors, [])
        self.assertEqual(len(standalone), len(set(standalone)))
        for name in standalone:
            self.assertEqual(normal.count(name), 1, name)
        for module in DEMO_MODULES:
            self.assertTrue(any(name.startswith(module + '.Native') for name in standalone), module)
        self.assertIn('test_workspace.WorkspaceLinux.test_forbidden_output_publishes_nothing', standalone)

    def test_cli_help_errors_and_no_report_for_invalid_evidence(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            evidence, summary = root / 'evidence', root / 'summary.md'
            evidence.mkdir()
            for content in (None, [], {'demo': 'swarm'}, {'demo': 'report'}):
                if content is not None:
                    save(evidence / 'attempt.json', content)
                for extra in ([], ['--demo', 'swarm']):
                    process = subprocess.run([sys.executable, '-B', SCRIPTS / 'product_demo.py',
                        'verify', '--out', evidence, '--markdown', summary, *extra],
                        capture_output=True, text=True, timeout=10)
                    self.assertEqual(process.returncode, 2, process.stderr)
                    self.assertNotIn('Traceback', process.stderr)
                    self.assertFalse(summary.exists())
            for arguments, status in ((['--help'], 0),
                    (['run', '--out', evidence, '--markdown', summary], 2),
                    (['verify', '--demo', 'unknown', '--out', evidence], 2)):
                process = subprocess.run([sys.executable, '-B', SCRIPTS / 'product_demo.py', *arguments],
                                         capture_output=True, text=True, timeout=10)
                self.assertEqual(process.returncode, status, process.stderr)
                if status == 0:
                    self.assertIn('--markdown', process.stdout)
                    self.assertIn('swarm', process.stdout)

    def test_stale_future_failed_and_missing_originals_cannot_export(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            out = root / 'run'
            out.mkdir()
            for demo in ('dependency', 'task-scope', 'swarm'):
                for mode in ('stale', 'future', 'failed', 'missing'):
                    with self.subTest(demo=demo, mode=mode):
                        begin = {'schema': 2, 'demo': demo, 'mode': 'deterministic', 'label': LABEL,
                                 'complete': False, 'started_epoch': time.time() +
                                 (3600 if mode == 'future' else -90000 if mode == 'stale' else -1)}
                        save(out / 'attempt.json', begin)
                        save(out / 'result.json', {**begin, 'complete': True, 'ended_epoch': time.time()})
                        if mode == 'failed':
                            save(out / 'failed.json', {'complete': False})
                        if mode == 'missing':
                            (out / 'result.json').unlink()
                        with self.assertRaises((ValueError, OSError)):
                            product_demo.write_markdown(out, root / 'summary.md')
                        self.assertFalse((root / 'summary.md').exists())
                        (out / 'failed.json').unlink(missing_ok=True)

    def test_formatting_binds_scenarios_measurements_and_preserves_destinations(self):
        # Synthetic projection tests formatting only. The native gate validates
        # all originals with networking and non-identity subprocesses forbidden.
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            out = root / 'run'
            out.mkdir()
            for demo in ('dependency', 'task-scope', 'swarm'):
                save(out / 'attempt.json', {'demo': demo})
                save(out / 'timing.json', {'warm_seconds': 125.25})
                save(out / 'result.json', {'demo': demo, 'artifacts': [],
                    'source': {'runtime_sha256': {}, 'distribution_inputs_sha256': {}},
                    'installed': {'runtime_sha256': {}, 'dependency_versions': {}},
                    'private': 'Bearer synthetic-private-log'})
                sample = public_sample(out)
                save(out / 'public-sample.json', sample)
                summary = root / (demo + '.md')
                with patch.object(product_demo, 'verify', return_value={'warm_target_met': False}) as verify:
                    product_demo.write_markdown(out, summary, demo=demo)
                    verify.assert_called_once_with(out)
                    text = summary.read_text()
                    self.assertIn('# Vega demo: ' + demo, text)
                    self.assertIn('125.250 seconds', text)
                    self.assertIn('target: missed', text)
                    self.assertIn(sample['original_result_sha256'], text)
                    self.assertIn(sample['public_payload_sha256'], text)
                    self.assertNotIn('Bearer', text)
                    with self.assertRaises(FileExistsError):
                        product_demo.write_markdown(out, summary)
                    self.assertEqual(summary.read_text(), text)
                    linked = root / 'linked.md'
                    linked.symlink_to(summary)
                    for destination in (linked, out / 'summary.md', product_demo.SOURCE / 'summary.md'):
                        with self.assertRaises(ValueError):
                            product_demo.write_markdown(out, destination)
                    linked.unlink()
                    with self.assertRaisesRegex(ValueError, 'another demo'):
                        product_demo.write_markdown(out, root / 'wrong.md', demo='report')
                    self.assertFalse((root / 'wrong.md').exists())


if __name__ == '__main__':
    unittest.main()
