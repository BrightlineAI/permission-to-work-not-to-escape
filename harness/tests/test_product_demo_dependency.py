"""Dependency demo milestone. Native tests are mandatory and never skipped.

Offline namespace records are synthetic verifier inputs, not physical evidence.
"""
import copy
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import demo_dependency as dependency
from evidence_io import digest, load, save


class DependencyOfflineTests(unittest.TestCase):
    def test_invoice_oracle_and_executable_variants(self):
        self.assertEqual(dependency.expected_invoice(), {'invoice_total_cents': 4600, 'invoice_lines': 2})
        for variant in ('clean', 'tolerant', 'abort'):
            source = dependency.module_source(Path('/synthetic-only/token'), 12345, variant)
            compile(source, '<reviewed fixture>', 'exec')
            self.assertIn('SYNTHETIC_AVAILABLE_TRANSFER_CANARY', source)
        compile(dependency.BACKEND, '<reviewed backend>', 'exec')
        compile(dependency.APP, '<invoice application>', 'exec')
        with self.assertRaises(ValueError):
            dependency.module_source(Path('/synthetic-only/token'), 12345, 'unknown')

    def test_missing_observation_never_proves_secret_denial(self):
        from demo_namespace import verify
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            secret = root / 'synthetic.txt'
            secret.write_text(dependency.SECRET)
            for value in ({'observations': [], 'errors': []},
                          {'observations': [], 'errors': [{'type': 'PermissionError'}]}):
                save(root / 'namespace.json', value)
                with self.assertRaisesRegex(ValueError, 'Missing independent'):
                    verify(root, secret=secret, marker='/target/fixture', expected='a' * 64, sessions={'s'})

    def test_contradictory_observer_data_rejected(self):
        from demo_namespace import verify
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            secret = root / 'synthetic.txt'
            secret.write_text(dependency.SECRET)
            unit = 'ptw-' + 'a' * 24 + '.service'
            row = {'pid': 321, 'start_ticks': '100', 'session': 's', 'unit': unit,
                   'network': 'net:[123]', 'host_network': 'net:[456]',
                   'marker': '/target/fixture', 'marker_sha256': 'a' * 64,
                   'secret': str(secret), 'host_secret_sha256': digest(secret),
                   'mountinfo': 'synthetic unit-test input only', 'cgroup': '0::/' + unit,
                   'observation': {'read': False, 'errno': 2}}
            def check(value):
                save(root / 'namespace.json', {'observations': [value], 'errors': []})
                return verify(root, secret=secret, marker='/target/fixture', expected='a' * 64, sessions={'s'})
            check(row)
            for change in ({'observation': {'read': True, 'sha256': digest(secret)}},
                           {'observation': {'read': False, 'errno': 13}},
                           {'session': 'another'}, {'network': 'net:[456]'},
                           {'marker_sha256': 'b' * 64}, {'host_secret_sha256': 'b' * 64},
                           {'pid': 0}, {'cgroup': ''}):
                with self.subTest(change=change), self.assertRaises(ValueError):
                    check({**copy.deepcopy(row), **change})


class NativeDependencyTests(unittest.TestCase):
    def test_installed_executing_wheel_and_independent_namespace(self):
        """Fresh installed package, real offline build/import/child and collector."""
        from product_ecosystems_acceptance import build_test_wheel, wheel_step
        from product_install import clean_env
        root = Path(tempfile.mkdtemp(prefix='ptw-dependency-installed-'))
        print('DEPENDENCY_MILESTONE_EVIDENCE ' + str(root), flush=True)
        import product_demo
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
            wheel_step([python, '-B', Path(__file__).resolve(), '--dependency-native-probe', root / 'run'],
                       root / 'probe-process.json', env, timeout=180)
            result = load(root / 'run/outcome.json')
            self.assertEqual(result['tolerant']['application'], dependency.expected_invoice())
            self.assertEqual(result['abort']['result'], 'safe-incompletion')
            self.assertEqual(result['clean']['application'], dependency.expected_invoice())
        except BaseException as exc:
            save(root / 'failed.json', {'type': type(exc).__name__, 'complete': False})
            raise


def native_probe(out):
    import product_demo as demo
    out.mkdir()
    save(out / 'installed.json', demo.installed_identity())
    outcomes = {}
    with demo.collector(out) as (port, rows):
        for variant in ('tolerant', 'abort', 'clean'):
            demo.probe(port, variant + '-before')
            outcomes[variant] = dependency.run_protected(out / variant, port, variant)
            demo.probe(port, variant + '-after')
        expected = [v + suffix for v in ('tolerant', 'abort', 'clean') for suffix in ('-before', '-after')]
        if [row['body'] for row in rows] != expected or any(row['path'] != '/control' for row in rows):
            raise AssertionError('Unexpected delivery or missing collector positive control')
    save(out / 'outcome.json', outcomes)
    print(json.dumps({'milestone': 'protected-dependency-native-prerequisite', 'outcomes': outcomes}, sort_keys=True))


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--dependency-native-probe':
        native_probe(Path(sys.argv[2]))
    else:
        unittest.main()
