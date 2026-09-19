"""Task-scope demo: offline contract tests and mandatory installed native effects."""
import copy
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import demo_task_scope as scope_demo
from evidence_io import load, save


class TaskScopeOfflineTests(unittest.TestCase):
    def test_matched_scope_and_independent_initial_oracle(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            bundles = []
            for arm in ('broad', 'sandbox', 'vega'):
                folder = root / arm
                folder.mkdir()
                store, bundle, actor, ids, _ = scope_demo.fixture(folder, arm)
                bundles.append(bundle)
                self.assertEqual(scope_demo.values(folder), {'A': 100, 'B': 100})
                grant = next(g for g in actor['grants'] if g['resource'] == ids['B'])
                self.assertEqual('write' in grant['actions'], arm == 'broad')
                self.assertEqual(store.status(scope_demo.PROJECT)['violations'], 0)
            self.assertEqual(bundles[1]['policy'], bundles[2]['policy'])
            self.assertEqual(bundles[1]['inventory']['resources'], bundles[2]['inventory']['resources'])

    def test_outside_parent_authority_cannot_be_registered(self):
        from ptw.policy import Invalid
        with tempfile.TemporaryDirectory() as name:
            store, bundle, actor, ids, _ = scope_demo.fixture(Path(name), 'vega')
            grants = copy.deepcopy(actor['grants'])
            next(g for g in grants if g['resource'] == ids['B'])['actions'].append('write')
            with self.assertRaises(Invalid):
                store.register(scope_demo.PROJECT, 'work', parent_token=actor['token'], grants=grants)
            self.assertEqual(store.status(scope_demo.PROJECT)['violations'], 0)

    def test_fixture_and_invalid_inputs(self):
        compile(scope_demo.PROGRAM, '<task-scope worker>', 'exec')
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            with self.assertRaisesRegex(ValueError, 'Unknown task-scope arm'):
                scope_demo.fixture(root, 'unexpected')
            with self.assertRaises(FileNotFoundError):
                scope_demo.verify(root)
            self.assertEqual(list(root.iterdir()), [])


class NativeTaskScopeTests(unittest.TestCase):
    def test_installed_three_arm_scope_child_and_resume(self):
        """No skip: actual fresh wheel, native processes, write effects and recovery."""
        from product_ecosystems_acceptance import build_test_wheel, wheel_step
        from product_install import clean_env
        import product_demo
        root = Path(tempfile.mkdtemp(prefix='ptw-task-scope-installed-'))
        print('TASK_SCOPE_MILESTONE_EVIDENCE ' + str(root), flush=True)
        save(root / 'source.json', product_demo.source_identity())
        try:
            wheel, _ = build_test_wheel(root / 'build')
            env = clean_env(root)
            uv = shutil.which('uv')
            self.assertIsNotNone(uv)
            python = root / 'installation/bin/python'
            wheel_step([uv, '--no-config', 'venv', '--no-python-downloads', '--python', sys.executable,
                        root / 'installation'], root / 'venv.json', env)
            wheel_step([uv, '--no-config', 'pip', 'sync', '--python', python, '--require-hashes',
                        '--only-binary', ':all:', SCRIPTS.parent / 'requirements.lock'], root / 'dependencies.json', env)
            wheel_step([uv, '--no-config', 'pip', 'install', '--python', python, '--no-deps', wheel],
                        root / 'install.json', env)
            env['PATH'] = str(python.parent) + os.pathsep + env.get('PATH', '')
            wheel_step([python, '-B', Path(__file__).resolve(), '--task-scope-native-probe', root / 'run'],
                       root / 'probe-process.json', env, timeout=180)
            self.assertEqual(scope_demo.verify(root / 'run')['demo'], 'task-scope')
            target = root / 'run/vega/repo/B/shared.txt'
            before = target.read_bytes()
            try:
                target.write_text(scope_demo.FIX)
                with self.assertRaisesRegex(ValueError, 'Contradictory task-scope output'):
                    scope_demo.verify(root / 'run')
            finally:
                target.write_bytes(before)
            self.assertEqual(load(root / 'source.json'), product_demo.source_identity())
        except BaseException as exc:
            save(root / 'failed.json', {'type': type(exc).__name__, 'complete': False})
            raise


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--task-scope-native-probe':
        import product_demo
        out = Path(sys.argv[2])
        installed = product_demo.installed_identity()
        result = scope_demo.run(out)
        save(out / 'installed.json', installed)
        save(out / 'result.json', result)
        print(result, flush=True)
    else:
        unittest.main()
