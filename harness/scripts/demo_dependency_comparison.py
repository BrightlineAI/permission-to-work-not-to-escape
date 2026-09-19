"""Fixed invoice comparison using the installed builders, collector and export.

The idle store is only reviewed setup configuration. Static payload execution
does not use dispatch, project workload admission or controller counters.
Broad execution is admitted only inside a separate outer network namespace.
"""
import json
import os
from pathlib import Path
import shutil
import sys
import time

import demo_dependency as dependency
from evidence_io import capture, digest, load, require, save


def broad_command(command, secret):
    """Broaden only the two synthetic effects inside the disposable outer net."""
    require(os.environ.get('PTW_DEMO_OUTER_NET') == os.readlink('/proc/self/ns/net'),
            'Broad comparison requires its outer network namespace')
    split = command.index('--')
    prefix, payload = command[:split], command[split + 1:]
    if payload[0] == '/nono':
        payload = payload[payload.index('--') + 1:]
    secret = Path(secret)
    require(secret.is_absolute() and secret.name == 'token.txt' and
            secret.parent.name == 'host-credentials' and secret.parent.parent != Path('/'),
            'Broad comparison requires the synthetic credential fixture')
    # A lone file bind creates writable ancestors in bubblewrap's root tmpfs.
    # Do not let the probe create a lookalike approved.json beside that mount.
    # This empty mount exposes only the synthetic secret, never the host policy.
    parent = str(secret.parent.parent)
    return [*prefix, '--share-net', '--tmpfs', parent,
            '--ro-bind', str(secret), str(secret), '--remount-ro', parent, '--', *payload]


def execute_static(store, command, seed, folder, secret, marker, expected, arm, *, definition=None):
    from demo_namespace import observe, verify
    from ptw.package_build import bounded_command, extract_result
    require(arm in ('broad', 'sandbox'), 'Unknown dependency comparator')
    folder.mkdir()
    if arm == 'broad':
        command = broad_command(command, secret)
    boundary = bounded_command(command, seed, definition)
    save(folder / 'boundary.json', {'argv': boundary})
    launcher = {}
    with observe(store, dependency.PROJECT, secret, marker, expected, folder / 'observer',
                 launcher=launcher, isolated=arm != 'broad'):
        result = capture(boundary, folder / 'process', timeout=45,
                         on_spawn=lambda pid: launcher.update(pid=pid))
    require(result.returncode == 0, 'Static launcher/build failed; retain stderr')
    exported = folder / 'export'
    exported.mkdir()
    with (folder / 'process/stdout').open('rb') as archive:
        extract_result(archive, exported)
    observations = verify(folder / 'observer', secret=secret, marker=marker, expected=expected,
                          sessions=set(), registered=False, isolated=arm != 'broad')
    save(folder / 'launcher.json', launcher)
    return exported, observations


def static_wheel(store, actor, bundle, folder, secret, arm):
    """Fixed empty-graph fixture; retain normal assessment and wheel validation."""
    from ptw.package_install import file_manifest, install_wheels, target_environment, validate_wheels
    from ptw.python_local import (assessed_artifacts, authorized_snapshot, validate_output_metadata,
                                  wheel_command)
    from ptw.workspace import materialize
    from email.parser import BytesParser
    import zipfile
    source, entries, python, approval = authorized_snapshot(store, actor['token'], 'invoice')
    require(source['mode'] == 'wheel' and source['name'] == 'invoice-dep' and source['version'] == '1.0',
            'Comparator supports only the reviewed invoice wheel')
    stage = folder / 'wheel'
    stage.mkdir()
    seed, artifacts = stage / 'seed', stage / 'artifacts'
    (seed / 'source').mkdir(parents=True)
    artifacts.mkdir()
    materialize(entries, seed / 'source')
    selected, records = assessed_artifacts(store, actor['token'], artifacts, python, identity='invoice')
    require(not selected and not records, 'Comparator requires the reviewed empty build graph')
    uv = Path(os.environ.get('PTW_UV') or shutil.which('uv')).resolve()
    command = wheel_command(uv, artifacts, seed, python, source['path'])
    exported, _ = execute_static(store, command, seed, stage / 'build', secret,
        '/target/source/src/invoice_dep/__init__.py', digest(folder / 'repo/src/invoice_dep/__init__.py'), arm)
    wheels = list((exported / 'out').glob('*.whl'))
    require(len(wheels) == 1 and wheels[0].name == 'invoice_dep-1.0-py3-none-any.whl',
            'Build did not produce the expected functional wheel')
    wheel = wheels[0]
    validate_wheels({'invoice-dep': wheel}, {'invoice-dep': '1.0'},
                    environment=target_environment(python), extended=True)
    with zipfile.ZipFile(wheel) as archive:
        meta = BytesParser().parsebytes(archive.read('invoice_dep-1.0.dist-info/METADATA'))
    validate_output_metadata(meta, entries, source)
    require(authorized_snapshot(store, actor['token'], 'invoice') == (source, entries, python, approval),
            'Source review changed during static build')
    site = stage / 'site'
    wheel_record = {'name': 'invoice-dep', 'filename': wheel.name, 'sha256': digest(wheel)}
    install_wheels(wheel.parent, site, [wheel_record], python=python)
    require((site / 'invoice_dep/__init__.py').read_bytes() ==
            (folder / 'repo/src/invoice_dep/__init__.py').read_bytes(), 'Installed fixture bytes differ')
    save(stage / 'installation.json', {'wheel': wheel_record, 'manifest': file_manifest(site),
        'source_sha256': source['snapshot_sha256'], 'policy_sha256': approval,
        'runtime_sha256': digest(python), 'uv_sha256': digest(uv), 'assessment_records': records})
    return site


def run_static(folder, port, arm='sandbox'):
    from ptw.execution import command_output, prepare_command
    from ptw.workspace import scan
    from demo_task_scope import publish_comparison
    require(arm in ('broad', 'sandbox'), 'Unknown dependency comparator')
    folder.mkdir()
    started = time.monotonic()
    save(folder / 'attempt.json', {'arm': arm, 'complete': False, 'started_epoch': time.time()})
    try:
        store, actor, bundle, secret = dependency.fixture(folder, port, 'tolerant')
        sibling = digest(folder / 'sibling.txt')
        site = static_wheel(store, actor, bundle, folder, secret, arm)
        definition = bundle['policy']['project']['commands'][0]
        before = scan(bundle['inventory'], definition['resources'])
        stage = folder / 'import'
        stage.mkdir()
        seed, command, extra = prepare_command(store, actor['token'], definition, before, '', stage)
        require(not extra, 'Unexpected editable artifacts')
        # Same immutable package mount and environment as prepare_command's pypi
        # branch. No package-set/controller lookup occurs during static execution.
        split = command.index('--')
        command[split:split] = ['--ro-bind', str(site), '/python-packages']
        split = command.index('--')
        payload_split = command.index('--', split + 1)
        command[payload_split:payload_split] = ['--read', '/python-packages']
        command.insert(command.index('PYTHONNOUSERSITE=1') + 1, 'PYTHONPATH=/python-packages:/target')
        exported, observations = execute_static(store, command, seed, stage / 'execution', secret,
            '/target/src/invoice_dep/__init__.py', digest(folder / 'repo/src/invoice_dep/__init__.py'), arm,
            definition=definition)
        after, result = command_output(exported, before)
        save(stage / 'action.json', result)
        require(result['exit_code'] == 0, 'Static installed application failed')
        publish_comparison(bundle, actor, before, after)
        attempts = verify_import_attempts(result, observations, broad=arm == 'broad')
        actual = load(folder / 'repo/out/invoices.json')
        require(actual == dependency.expected_invoice(), 'Independent static invoice oracle failed')
        require(digest(folder / 'sibling.txt') == sibling and secret.read_text() == dependency.SECRET,
                'Unrelated static fixture changed')
        audit = store.audit_export(dependency.PROJECT)
        require(not any(e['request'].get('action') == 'workload_launch' for e in audit['events']),
                'Comparator used project workload supervision')
        save(folder / 'audit.json', audit)
        outcome = {'arm': arm, 'case': 'tolerant', 'application': actual, 'result': 'completed',
            'attempts': len(attempts), 'configuration_only_store': True, 'model_calls': 0,
            'manual_interventions': 0, 'scripted_operator_approvals': 1,
            'seconds': time.monotonic() - started, 'ended_epoch': time.time(), 'complete': True}
        save(folder / 'outcome.json', outcome)
        return outcome
    except BaseException as exc:
        save(folder / 'failed.json', {'type': type(exc).__name__, 'complete': False, 'ended_epoch': time.time()})
        raise


def verify_import_attempts(result, observations, *, broad):
    attempts = [json.loads(line[len('DEPENDENCY_ATTEMPT '):]) for line in result['output'].splitlines()
                if line.startswith('DEPENDENCY_ATTEMPT ')]
    require(len(attempts) == 2 and {a['route'] for a in attempts} == {'invoice_dep', '__probe_child__'},
            'Missing direct or child import attempt')
    require(all(p.get('operator_policy') == {'read': False, 'errno': 2}
                for p in observations['observations']), 'Operator authority was visible to dependency')
    parent = next(a for a in attempts if a['route'] == 'invoice_dep')
    child = next(a for a in attempts if a['route'] == '__probe_child__')
    require(child['ppid'] == parent['pid'] and child['pid'] != parent['pid'], 'Child lineage differs')
    import errno
    for row in attempts:
        require(row.get('policy_edit') == (errno.EROFS if broad else errno.ENOENT),
                'Dependency could create or edit apparent operator approval')
        require(any(p['namespace_pid'] == row['pid'] for p in observations['observations']),
                'Attempt lacks an independently observed process')
        require(row['read'] == ('obtained' if broad else 'FileNotFoundError'), 'Unexpected credential read')
        if broad:
            require(row.get('secret_send') == row['canary_send'] == 200, 'Broad delivery did not succeed')
        else:
            require('secret_send' not in row and isinstance(row.get('canary_send'), str),
                    'Protected attempt did not test available-canary denial')
    return attempts


def broad_worker(folder):
    """Called only by run_broad's fresh outer sandbox; no ambient network."""
    from product_demo import collector, probe
    outer_net = os.readlink('/proc/self/ns/net')
    require(outer_net != os.environ['PTW_DEMO_HOST_NET'], 'Broad outer network was not isolated')
    os.environ['PTW_DEMO_OUTER_NET'] = outer_net
    save(folder / 'outer.json', {'network': outer_net, 'host_network': os.environ['PTW_DEMO_HOST_NET'],
        'mountinfo': Path('/proc/self/mountinfo').read_text(), 'pid': os.getpid()})
    with collector(folder) as (port, rows):
        save(folder / 'collector-port.json', {'port': port})
        probe(port, 'broad-before')
        outcome = run_static(folder / 'arm', port, 'broad')
        probe(port, 'broad-after')
        verify_collector(rows, broad=True)
    save(folder / 'outcome.json', outcome)
    print(json.dumps(outcome, sort_keys=True))


def verify_collector(rows, *, broad):
    controls = [r for r in rows if r['path'] == '/control']
    label = 'broad' if broad else 'sandbox'
    require([r['body'] for r in controls] == [label + '-before', label + '-after'] and
            rows[0] == controls[0] and rows[-1] == controls[-1], 'Collector window/control missing')
    deliveries = [r for r in rows if r['path'] != '/control']
    expected = [('/secret', dependency.SECRET), ('/canary', dependency.CANARY)] * 4 if broad else []
    require([(r['path'], r['body']) for r in deliveries] == expected,
            'Missing broad build/import/child delivery or unexpected protected delivery')


def normalized_boundary(command):
    """Normalize only host-side data mounts, never payload permissions or argv."""
    command = list(command)
    split = command.index('--')
    for index in range(split):
        if command[index] in ('--ro-bind', '--bind'):
            destination = command[index + 2]
            if destination in ('/seed', '/artifacts', '/python-packages'):
                command[index + 1] = '<' + destination.lstrip('/') + '>'
    return command


def verify_comparison(out, protected):
    from demo_namespace import verify
    from ptw.policy import check_approval
    out, protected = Path(out), Path(protected)
    broad = out / 'broad'
    require(load(broad / 'outer.json')['network'] != load(broad / 'outer.json')['host_network'],
            'Broad comparison escaped outer network isolation')
    verify_collector(load(broad / 'collector.json')['requests'], broad=True)
    verify_collector(load(out / 'collector.json')['requests'], broad=False)
    bundles = []
    for folder, arm in ((broad / 'arm', 'broad'), (out / 'sandbox', 'sandbox')):
        bundle = load(folder / 'approved.json')
        check_approval(bundle)
        bundles.append(bundle)
        secret = folder / 'host-credentials/token.txt'
        module = folder / 'repo/src/invoice_dep/__init__.py'
        port = load(broad / 'collector-port.json')['port'] if arm == 'broad' else load(out / 'collector-port.json')['port']
        require(module.read_text() == dependency.module_source(secret, port, 'tolerant') and
                (folder / 'repo/backend/backend.py').read_text() == dependency.BACKEND and
                (folder / 'repo/app/main.py').read_text() == dependency.APP and
                load(folder / 'repo/app/invoices.json') == dependency.INVOICES,
                'Comparator fixture changed')
        for phase, marker in [('wheel/build', '/target/source/src/invoice_dep/__init__.py'),
                              ('import/execution', '/target/src/invoice_dep/__init__.py')]:
            location = folder / phase
            observed = verify(location / 'observer', secret=secret, marker=marker, expected=digest(module),
                              sessions=set(), registered=False, isolated=arm != 'broad')
            require(all(p.get('operator_policy') == {'read': False, 'errno': 2}
                        for p in observed['observations']), 'Comparator could access apparent operator policy')
            process = load(location / 'process/process.json')
            require(process['complete'] and process['exit_code'] == 0 and
                    process['argv'] == load(location / 'boundary.json')['argv'], 'Static launcher receipt differs')
            if phase == 'import/execution':
                result = load(folder / 'import/action.json')
                require(result['exit_code'] == 0, 'Application failed')
                verify_import_attempts(result, observed, broad=arm == 'broad')
        outcome = load(folder / 'outcome.json')
        require(outcome['arm'] == arm and outcome['complete'] and outcome['attempts'] == 2 and
                load(folder / 'repo/out/invoices.json') == outcome['application'] == dependency.expected_invoice(),
                'Static functional oracle differs')
        require(secret.read_text() == dependency.SECRET and
                (folder / 'sibling.txt').read_text() == 'UNRELATED_PROJECT_UNCHANGED\n', 'Unrelated fixture changed')
    bundles.append(load(protected / 'approved.json'))
    # Only fixture content identity changes across absolute-path/port variants.
    policies = []
    import copy
    for bundle in bundles:
        policy = copy.deepcopy(bundle['policy'])
        policy['project']['python_dependencies']['sources'][0]['snapshot_sha256'] = '<fixture-source>'
        policies.append(policy)
    require(policies[0] == policies[1] == policies[2] and
            all(b['inventory']['resources'] == bundles[0]['inventory']['resources'] for b in bundles),
            'Comparison legitimate authority differs')
    require(normalized_boundary(load(out / 'sandbox/import/execution/boundary.json')['argv']) ==
            normalized_boundary(load(protected / 'import-boundary.json')['argv']), 'Sandbox/Vega command scope differs')
    return {'broad_delivery': 'build/import and children', 'protected_delivery': 'none',
            'completion': 'all three arms', 'prevention': 'tie; underlying confinement'}


def run_comparison(out, protected):
    from product_demo import collector, probe
    out.mkdir()
    run_broad(out / 'broad')
    with collector(out) as (port, rows):
        save(out / 'collector-port.json', {'port': port})
        probe(port, 'sandbox-before')
        run_static(out / 'sandbox', port)
        probe(port, 'sandbox-after')
        verify_collector(rows, broad=False)
    result = verify_comparison(out, protected)
    save(out / 'comparison.json', result)
    return result


def python_runtime_mounts():
    """Expose this installation and its interpreter, including uv's runtime alias.

    The venv executable can name a version-family symlink outside base_prefix.
    Mount only that same runtime at the alias, never its containing home/cache.
    """
    installation = Path(sys.prefix).absolute()
    runtime = Path(sys.base_prefix).resolve(strict=True)
    executable = Path(sys.executable).absolute()
    require(executable.is_relative_to(installation) and executable.is_file(),
            'Comparison interpreter must belong to its installation')
    roots = [installation, runtime]
    if executable.is_symlink():
        target = executable.parent / executable.readlink()
        alias = target.parent.parent
        require(target.parent.name == 'bin' and alias.resolve(strict=True) == runtime and
                target.resolve(strict=True).is_relative_to(runtime),
                'Comparison interpreter alias must name the same Python runtime')
        if alias not in roots:
            roots.append(alias)
    return [argument for root in dict.fromkeys(roots)
            for argument in ('--ro-bind', str(root.resolve(strict=True)), str(root))]


def run_broad(folder):
    from ptw.supervisor import runtime_namespace
    folder.mkdir()
    scripts = Path(__file__).resolve().parent
    uv = Path(os.environ.get('PTW_UV') or shutil.which('uv')).resolve()
    nono = Path(os.environ.get('PTW_NONO') or shutil.which('nono')).resolve()
    # The only writable host mount is this new evidence directory. Payloads get
    # their own tmpfs/export boundary and never see this driver's receipt channel.
    command = runtime_namespace() + [
        '--bind', str(folder), str(folder), '--ro-bind', str(scripts), '/demo-driver/scripts',
        *python_runtime_mounts(),
        '--ro-bind', str(uv), str(uv),
        '--ro-bind', str(nono), str(nono), '--setenv', 'PTW_UV', str(uv),
        '--setenv', 'PTW_NONO', str(nono), '--setenv', 'PYTHONDONTWRITEBYTECODE', '1',
        '--setenv', 'PTW_DEMO_HOST_NET', os.readlink('/proc/self/ns/net'),
        '--', sys.executable, '-B', '/demo-driver/scripts/demo_dependency_comparison.py', str(folder)]
    result = capture(command, folder / 'outer-process', timeout=90)
    require(result.returncode == 0, 'Broad outer comparison failed; inspect retained stderr')
    return load(folder / 'outcome.json')


if __name__ == '__main__':
    require(len(sys.argv) == 2, 'Internal outer worker requires one evidence directory')
    broad_worker(Path(sys.argv[1]))
