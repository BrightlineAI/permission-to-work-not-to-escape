"""Fresh installed extension journeys; deterministic fixtures, never model evidence.

Only drivers and fixture modules come from the checkout. Every ptw import,
terminal and detached service must use the retained wheel installation.
"""
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest
import zipfile

from evidence_io import reference, save, verify_wheel_identity
from product_gate import inputs, tree, versions


NATIVE = (
    'test_product_artifact_review.NativeArtifactTests.test_at1_native_paired_terminal_decisions_and_physical_effects',
    'test_product_artifact_review.NativeArtifactTests.test_at3_native_resumed_composition_and_benign_counterpart',
    'test_product_sequence_review.NativeSequenceTests.test_real_terminal_sequence_export_finding_hold_and_useful_control',
    'test_product_sequence_review.NativeSequenceTests.test_optional_selected_cached_fixture_uses_installed_terminal_and_holds',
    'test_product_incident_controls.NativeIncidentTests.test_terminal_surrender_stops_preview_without_ending_parent',
    'test_product_incident_controls.NativeIncidentTests.test_shipped_aggregate_escalation_stops_real_descendants',
    'test_product_incident_controls.NativeIncidentTests.test_faulted_surrender_closes_admission_and_reconciles_physical_work',
    'test_product_incident_controls.NativeIncidentTests.test_real_mcp_surrender_survives_lost_acknowledgement',
    'test_product_incident_controls.NativeIncidentTests.test_missing_target_package_children_and_resolver_do_not_gain_authority',
)
LIFECYCLE = tuple('test_product_audit.AuditStorageTests.' + name for name in (
    'test_adoption_is_exact_stale_review_rejected_and_old_runtime_refused',
    'test_backed_up_migration_keeps_counts_stops_quarantine_and_legacy_unknown',
    'test_interrupted_adoption_rolls_back_without_reactivating_or_losing_history',
    'test_new_reviewed_profile_admits_useful_work_and_displays_limits',
))


def identity():
    import ptw
    root = Path(ptw.__file__).resolve().parent
    distribution = importlib.metadata.distribution('permission-to-work-harness')
    return {'path': str(root), 'prefix': sys.prefix,
            'pythonpath_present': 'PYTHONPATH' in os.environ,
            'pythonhome_present': 'PYTHONHOME' in os.environ,
            'direct_url': json.loads(distribution.read_text('direct_url.json') or '{}'),
            'hashes': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.glob('*.py')},
            'runtime_sha256': tree(root.parent), 'dependency_versions': versions(root.parent)}


def verify_identity(value, installation, hashes, runtime):
    verify_wheel_identity(value, installation, hashes)
    if value['pythonhome_present'] or value['runtime_sha256'] != runtime:
        raise AssertionError('Installed recursive runtime/package data differ or PYTHONHOME is set')
    if tree(Path(value['path']).parent) != runtime:
        raise AssertionError('Retained installed bytes differ from measured identity')


def adopt_fixture(case, mode, folder):
    """Real CLI profile review/adoption before native effects, with exact binding."""
    from ptw.evidence_storage import DEFAULT
    from ptw.policy import digest
    from ptw.store import Store
    from terminal_driver import Terminal
    project = 'python-demo'
    case.assertEqual(case.store.audit_export(project)['profile'], DEFAULT if mode == 'new' else None)
    if mode == 'existing':
        # Original useful activity exists before opting the project in.
        case.assertTrue(case.ask('read')['allowed'])
    original = case.store.status(project)
    history = case.store.audit_export(project)['events']
    packet = case.store.evidence_review(project, DEFAULT)
    save(folder / 'before.json', {'status': original, 'events': history, 'review': packet})
    argv = [sys.executable, '-B', '-m', 'ptw', 'evidence-config',
            '--state', str(case.store.directory), '--project', project]
    for label, extra, expected in (
            ('review', [], 0),
            ('reject-forged', ['--approve', '0' * 64, '--reviewer', 'fixture operator'], 2),
            ('adopt', ['--approve', digest(packet), '--reviewer', 'fixture operator'], 0)):
        terminal = Terminal(argv + extra, folder / label)
        try:
            terminal.wait(lambda: terminal.exited, 30, 'installed evidence review')
            code = terminal.close()
            case.assertEqual(code, expected, terminal.text)
        finally:
            if not terminal.closed:
                terminal.close(graceful=False)
        current = Store(case.store.directory)
        case.assertEqual(current.status(project), original)
        events = current.audit_export(project)['events']
        case.assertEqual(events[:len(history)], history)
        case.assertEqual(len(events), len(history) + (label == 'adopt'))
        case.assertEqual(current.audit_export(project)['profile'],
                         DEFAULT if mode == 'new' or label == 'adopt' else None)
    save(folder / 'after.json', {'status': current.status(project),
                                'audit': current.audit_export(project)})
    # These fixtures start the actual persistent monitor in setUp. Check that
    # service too, not just the independent detached identity probe.
    if case.__class__.__module__ in ('test_product_artifact_review', 'test_product_sequence_review'):
        from ptw.monitor import call, unit_for
        pid = int(call('show', unit_for(case.store.directory), '--property=MainPID', '--value'))
        argv = Path('/proc', str(pid), 'cmdline').read_bytes().split(b'\0')
        case.assertEqual(argv[:4], [os.fsencode(sys.executable), b'-B', b'-m', b'ptw.monitor'])
        save(folder / 'monitor.json', {'pid': pid, 'argv': [os.fsdecode(a) for a in argv if a]})


def run_installed(out, source, mode):
    """Run explicitly selected original cases once in this installed environment.

    New mode includes the profile in the initial operator-approved policy;
    existing mode retains prior activity then adopts through the installed CLI.
    No source ptw directory is added to sys.path, and skips are failures.
    """
    from ptw.evidence_storage import DEFAULT
    if mode not in ('new', 'existing', 'upgrade'):
        raise ValueError('Unknown installed extension journey')
    out, source = Path(out), Path(source)
    out.mkdir()
    tempfile.tempdir = str(out)  # Retained native receipts stay below evidence.
    sys.path.insert(0, str(source / 'tests'))
    names = LIFECYCLE if mode == 'upgrade' else NATIVE
    suite = unittest.TestSuite()
    for index, name in enumerate(names):
        selected = unittest.defaultTestLoader.loadTestsFromName(name)
        if selected.countTestCases() != 1:
            raise AssertionError('Expected exactly one original case: ' + name)
        case, = selected
        if mode != 'upgrade':
            folder = out / ('profile-' + str(index))
            folder.mkdir()
            if mode == 'new':
                approve = case.approve

                def reviewed(approve=approve, case=case):
                    case.policy['project']['audit'] = dict(DEFAULT)
                    return approve()
                case.approve = reviewed
            setup = case.setUp

            def prepare(setup=setup, case=case, folder=folder):
                setup()
                adopt_fixture(case, mode, folder)
                # Some original incident cases explicitly approve a separate
                # preview/package fixture controller. Keep the reviewed profile
                # in those subsequent fixture policies as well; this changes
                # no live approval and does not migrate away the original state.
                case.policy['project']['audit'] = dict(DEFAULT)

                def retain():
                    audit = case.store.audit_export('python-demo')
                    save(folder / 'final-audit.json', audit)
                    case.assertEqual(audit['profile'], DEFAULT)
                case.addCleanup(retain)
            case.setUp = prepare
        suite.addTest(case)

    rows = []

    class Result(unittest.TextTestResult):
        def startTest(self, test):
            super().startTest(test)
            rows.append({'id': test.id(), 'started_monotonic': time.monotonic(), 'passed': False})

        def addSuccess(self, test):
            super().addSuccess(test)
            rows[-1]['passed'] = True

        def stopTest(self, test):
            rows[-1]['ended_monotonic'] = time.monotonic()
            # Cleanup has finished, including the fixtures' original event and
            # physical-effect exports. Retain references, not a copied verdict.
            evidence = getattr(test, 'evidence', None)
            rows[-1]['originals'] = [reference(out, p) for p in sorted(evidence.rglob('*'))
                if p.is_file() and not p.is_symlink()] if evidence else []
            save(out / 'tests.json', rows)
            super().stopTest(test)

    started = time.time()
    with (out / 'unittest.log').open('w') as stream:
        result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
    # Check every loaded ptw module, including lazy imports made by the cases.
    runtime_root = Path(identity()['path'])
    imported = {name: str(Path(module.__file__).resolve()) for name, module in sys.modules.items()
                if (name == 'ptw' or name.startswith('ptw.')) and getattr(module, '__file__', None)}
    contamination = any(not Path(path).is_relative_to(runtime_root) for path in imported.values())
    report = {'schema': 1, 'mode': mode, 'label': 'deterministic installed fixtures; no live model review',
              'started_epoch': started, 'ended_epoch': time.time(), 'tests': rows,
              'tests_run': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
              'skipped': len(result.skipped), 'passed': result.wasSuccessful() and not result.skipped and not contamination
                  and all(row['originals'] for row in rows),
              'imports': imported, 'checkout_imported': contamination,
              'output': reference(out, out / 'unittest.log')}
    save(out / 'result.json', report)
    if not report['passed'] or result.testsRun != len(names):
        raise AssertionError('Installed extension cases failed; inspect ' + str(out / 'unittest.log'))


def installed_case(out, mode, wheel, hashes):
    from product_ecosystems_acceptance import wheel_step
    from product_install import clean_env
    if mode not in ('new', 'existing', 'upgrade'):
        raise ValueError('Unknown installed extension journey')
    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).resolve().parents[1]
    import native_receipt
    source_hashes = native_receipt.sources(source.parent)
    runtime = tree(source)
    with zipfile.ZipFile(wheel) as archive:
        actual = {name: hashlib.sha256(archive.read(name)).hexdigest()
                  for name in archive.namelist() if name.startswith('ptw/') and not name.endswith('/')}
    if actual != runtime:
        raise AssertionError('Candidate wheel runtime/package data do not match source')
    save(out / 'source.json', {'runtime_sha256': runtime,
         'distribution_inputs_sha256': inputs(source.parent),
         'wheel_sha256': hashlib.sha256(Path(wheel).read_bytes()).hexdigest(),
         'support_sha256': {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
             for directory in ('tests', 'scripts') for p in sorted((source / directory).glob('*.py'))},
         'contracts': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                       for p in source.glob('*ACCEPTANCE.json')}})
    env = clean_env(out)
    installation = out / 'installation'
    python = installation / 'bin/python'
    uv = shutil.which('uv')
    if not uv:
        raise AssertionError('Provision uv before installed extension acceptance')
    wheel_step([uv, '--no-config', 'venv', '--no-python-downloads', '--python', sys.executable, installation],
               out / 'venv.json', env)
    wheel_step([uv, '--no-config', 'pip', 'sync', '--python', python, '--require-hashes',
                '--only-binary', ':all:', '--index-url', 'https://pypi.org/simple', source / 'requirements.lock'],
               out / 'dependencies.json', env)
    wheel_step([uv, '--no-config', 'pip', 'install', '--python', python, '--no-deps', wheel],
               out / 'install.json', env)
    env['PATH'] = str(installation / 'bin') + os.pathsep + env.get('PATH', '')
    env['PTW_LINUX_TESTS'] = '1'
    bootstrap = 'import sys; sys.path.insert(0,sys.argv[1]); '
    probe = bootstrap + 'import json; from product_safety_acceptance import identity; print(json.dumps(identity()))'
    for label in ('foreground', 'detached'):
        argv = [python, '-I', '-B', '-c', probe, source / 'scripts']
        if label == 'detached':
            unit = 'ptw-safety-' + hashlib.sha256(str(out).encode()).hexdigest()[:24]
            argv = ['systemd-run', '--user', '--wait', '--pipe', '--collect', '--quiet', '--unit=' + unit,
                    python, '-B', '-c', probe, source / 'scripts']
        value = json.loads(wheel_step(argv, out / (label + '-step.json'), env, cwd=out))
        save(out / (label + '-identity.json'), value)
        verify_identity(value, installation, hashes, runtime)
    script = bootstrap + 'from product_safety_acceptance import run_installed; run_installed(*sys.argv[2:])'
    wheel_step([python, '-I', '-B', '-c', script, source / 'scripts', out / 'journey', source, mode],
               out / 'journey-step.json', env, cwd=out, timeout=600)
    value = json.loads(wheel_step([python, '-I', '-B', '-c', probe, source / 'scripts'],
                                 out / 'after-step.json', env, cwd=out))
    verify_identity(value, installation, hashes, runtime)
    save(out / 'after-identity.json', value)
    if native_receipt.sources(source.parent) != source_hashes:
        raise AssertionError('Maintained source changed during installed safety journey')
    save(out / 'evidence.json', {'schema': 1, 'mode': mode, 'source_sha256': source_hashes,
        'ended_epoch': time.time(), 'wheel_sha256': hashlib.sha256(Path(wheel).read_bytes()).hexdigest(),
        'result': reference(out, out / 'journey/result.json'), 'source': reference(out, out / 'source.json'),
        'identities': {label: reference(out, out / (label + '-identity.json'))
                       for label in ('foreground', 'detached', 'after')},
        'profiles': {str(i): {**{label: reference(out, out / 'journey' / ('profile-' + str(i)) / (label + '.json'))
                             for label in ('before', 'after')},
                             'terminals': {label: {name: reference(out, out / 'journey' / ('profile-' + str(i)) / label / name)
                                 for name in ('terminal.txt', 'inputs.json', 'exit.json')}
                                 for label in ('review', 'reject-forged', 'adopt')}}
                     for i in range(len(NATIVE))} if mode != 'upgrade' else {}})
    return json.loads((out / 'journey/result.json').read_text())
