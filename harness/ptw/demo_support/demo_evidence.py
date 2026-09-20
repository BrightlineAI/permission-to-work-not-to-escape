"""Scenario extension of product_demo's private run/verify envelope.

Uses the same installed identity, artifact IO and physical scenario observers.
Receipts are consistency evidence, not signatures or authority for execution.
"""
import hashlib
import os
from pathlib import Path
import platform
import shutil
import sys
import time

from evidence_io import artifact, capture, digest, fresh, load, reference, require, save, seconds

DEMOS = ('dependency', 'task-scope', 'swarm')
LABEL = 'deterministic reconstruction; real processes; scripted approvals; zero model calls'


def scenario(name):
    require(name in DEMOS, 'Unsupported demo')
    if name == 'dependency':
        import demo_dependency
        return demo_dependency
    if name == 'swarm':
        import demo_swarm
        return demo_swarm
    import demo_task_scope
    return demo_task_scope


def private_controllers(out, name):
    if name == 'swarm':
        return {out / 'cases' / p / 'controller' for p in ('broad/arm', 'sandbox', 'vega')}
    locations = ('tolerant', 'abort', 'clean', 'comparison/broad/arm', 'comparison/sandbox') if name == 'dependency' else (
        'broad', 'sandbox', 'vega', 'authority-control')
    return {out / 'cases' / p / 'controller' for p in locations}


def files(out, name):
    excluded = private_controllers(out, name)
    top = {out / n for n in ('attempt.json', 'result.json', 'failed.json', 'public-sample.json')}
    found = []
    for folder, directories, names in os.walk(out, followlinks=False):
        folder = Path(folder)
        for entry in [*directories, *names]:
            require(not (folder / entry).is_symlink(), 'Linked demo evidence')
        directories[:] = [d for d in directories if folder / d not in excluded and d != '__pycache__']
        for entry in names:
            path = folder / entry
            require(path.is_file(), 'Special demo artifact')
            if path not in top:
                found.append(path)
    return sorted(found)


def tools_record(out):
    from ptw.python_runtime import identify
    folder = out / 'version-python'
    process = capture([sys.executable, '--version'], folder, timeout=10)
    require(process.returncode == 0 and process.stdout.strip(), 'Cannot resolve Python version')
    result = {'python': process.stdout.decode().strip(), 'platform': platform.platform(),
              'interpreter': {'path': sys.executable, 'sha256': digest(sys.executable),
                              'receipt': reference(out, folder / 'process.json')}, 'tools': {}}
    # Payload/export Python can differ from the freshly installed driver Python.
    folder = out / 'version-system-python'
    runtime = identify('/usr/bin/python3')
    process = capture(['/usr/bin/python3', '--version'], folder, timeout=10)
    require(process.returncode == 0 and process.stdout.decode().strip() == 'Python ' + runtime['version'],
            'Cannot resolve payload/wrapper Python version')
    result['system_python'] = {**runtime, 'receipt': reference(out, folder / 'process.json')}
    for name in ('uv', 'nono', 'bwrap', 'systemd-run', 'systemctl'):
        override = os.environ.get('PTW_' + name.upper()) if name in ('uv', 'nono') else None
        path = Path(override or shutil.which(name) or '').absolute()
        require(path.is_file(), 'Missing native tool: ' + name)
        folder = out / ('version-' + name)
        process = capture([path, '--version'], folder, timeout=10)
        require(process.returncode == 0 and process.stdout.strip(), 'Cannot resolve native tool version: ' + name)
        result['tools'][name] = {'path': str(path.resolve()), 'sha256': digest(path),
                                'version': process.stdout.decode().strip(), 'receipt': reference(out, folder / 'process.json')}
    return result


def verify_version_process(out, tool, version):
    require(digest(tool['path']) == tool['sha256'], 'Executable changed')
    process_path = artifact(out, tool['receipt'])
    process = load(process_path)
    require(process['complete'] and process['exit_code'] == 0 and
            Path(process['argv'][0]).resolve() == Path(tool['path']).resolve() and
            process['argv'][1:] == ['--version'], 'Invalid version process')
    require(artifact(process_path.parent, process['stdout']).read_text().strip() == version,
            'Version contradicts original output')
    artifact(process_path.parent, process['stderr'])


def verify_tools(out, value):
    from ptw.python_runtime import identify
    require(isinstance(value['python'], str) and value['python'] and value['platform'] == platform.platform(),
            'Missing runtime version or changed platform')
    verify_version_process(out, value['interpreter'], value['python'])
    runtime = value.get('system_python')
    require(isinstance(runtime, dict) and
            {k: v for k, v in runtime.items() if k != 'receipt'} == identify('/usr/bin/python3'),
            'Missing or changed payload/wrapper interpreter identity')
    verify_version_process(out, {'path': runtime['executable'], 'sha256': runtime['sha256'],
                                'receipt': runtime['receipt']}, 'Python ' + runtime['version'])
    require(set(value['tools']) == {'uv', 'nono', 'bwrap', 'systemd-run', 'systemctl'}, 'Missing native tools')
    for name, tool in value['tools'].items():
        verify_version_process(out, tool, tool['version'])


def run(out, name):
    import product_demo as shared
    module = scenario(name)
    started = time.monotonic()
    out = Path(out).absolute()
    require(out.resolve() == out and not out.is_relative_to(shared.SOURCE), 'Use a new canonical directory outside the checkout')
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    begin = {'schema': 2, 'demo': name, 'mode': 'deterministic', 'label': LABEL,
             'complete': False, 'started_epoch': time.time(), 'start_monotonic': started}
    save(out / 'attempt.json', begin)
    try:
        begin['source'] = shared.source_identity()
        begin['installed'] = shared.installed_identity()
        begin['versions'] = tools_record(out)
        save(out / 'attempt.json', begin)
        warm_start = time.monotonic()
        print(name + ': real installed execution; scripted fixture approvals; zero model calls', flush=True)
        module.run(out / 'cases')
        warm_end = time.monotonic()
        comparison = module.verify(out / 'cases')
        require(shared.source_identity() == begin['source'] and shared.installed_identity() == begin['installed'],
                'Source or installation changed during demo')
        timing = {'warm_start_monotonic': warm_start, 'warm_end_monotonic': warm_end,
                  'warm_seconds': warm_end - warm_start, 'warm_target_seconds': 120,
                  'warm_target_met': warm_end - warm_start <= 120,
                  'startup_seconds': warm_start - started,
                  'cold_installation_seconds': None,
                  'cold_status': 'prerequisite; measure separately using retained installer process receipts',
                  'cache': 'existing native tools; fresh fixture and controller; OS caches not flushed',
                  'playback_seconds': None}
        save(out / 'timing.json', timing)
        save(out / 'result.json', {**begin, 'complete': True, 'ended_epoch': time.time(),
             'total_seconds': time.monotonic() - started, 'comparison': comparison,
             'artifacts': [reference(out, p) for p in files(out, name)],
             'live': {'status': 'unavailable; no sessions requested or run', 'sessions': 0, 'model_calls': 0}})
        save(out / 'public-sample.json', public_sample(out))
        return verify(out)
    except BaseException as exc:
        save(out / 'failed.json', {'error_type': type(exc).__name__, 'complete': False, 'ended_epoch': time.time()})
        raise


def verify(out):
    import product_demo as shared
    out = Path(out).absolute()
    require(out.resolve() == out, 'Linked or noncanonical evidence directory')
    require(all(not (out / n).is_symlink() for n in ('attempt.json', 'result.json', 'failed.json', 'public-sample.json')),
            'Linked top-level receipt')
    begin, end = load(out / 'attempt.json'), load(out / 'result.json')
    require(not (out / 'failed.json').exists() and begin['complete'] is False and end['complete'] is True,
            'Incomplete or failed demo')
    require(begin['schema'] == 2 and begin['demo'] in DEMOS and begin['mode'] == 'deterministic' and
            begin['label'] == LABEL, 'Unsupported demo evidence')
    for key, value in begin.items():
        require(key == 'complete' or end.get(key) == value, 'Contradictory attempt: ' + key)
    fresh(begin['started_epoch'])
    fresh(end['ended_epoch'])
    require(end['ended_epoch'] >= begin['started_epoch'], 'Reversed demo timestamps')
    require(end['source'] == shared.source_identity(), 'Stale demo source')
    paths = [r['path'] for r in end['artifacts']]
    require(len(paths) == len(set(paths)) and set(paths) == {str(p.relative_to(out)) for p in files(out, begin['demo'])},
            'Missing, duplicate or unhashed artifact')
    for ref in end['artifacts']:
        artifact(out, ref)
    from demo_identity import verify_record
    identity = end['installed']
    verify_record(identity, end['source'])
    verify_tools(out, end['versions'])
    timing = load(out / 'timing.json')
    warm = seconds(timing['warm_seconds'], 'warm')
    require(warm == timing['warm_end_monotonic'] - timing['warm_start_monotonic'] and
            timing['startup_seconds'] == timing['warm_start_monotonic'] - begin['start_monotonic'] and
            seconds(end['total_seconds'], 'total') >= warm + seconds(timing['startup_seconds'], 'startup') and
            timing['warm_target_seconds'] == 120 and timing['warm_target_met'] == (warm <= 120) and
            timing['cold_installation_seconds'] is None and timing['playback_seconds'] is None,
            'Contradictory demo timing')
    comparison = scenario(begin['demo']).verify(out / 'cases')
    require(end['comparison'] == comparison, 'Comparison contradicts physical records')
    require(end['live'] == {'status': 'unavailable; no sessions requested or run', 'sessions': 0, 'model_calls': 0},
            'Deterministic execution mislabeled')
    require(load(out / 'public-sample.json') == public_sample(out), 'Public projection differs from verified evidence')
    return {'demo': begin['demo'], 'mode': 'deterministic', 'verified': True,
            'warm_seconds': warm, 'warm_target_met': timing['warm_target_met'], 'comparison': comparison,
            'live': end['live']}


def public_sample(out):
    """Only fixed claims and measured scalars; no free-form worker/log content."""
    from ptw.policy import digest as json_digest
    record = load(out / 'result.json')
    name = record['demo']
    refs = record['artifacts']
    payload = {'schema': 2, 'demo': name, 'mode': 'deterministic', 'label': LABEL,
        'use': 'sanitized historical projection; not fresh acceptance',
        'runtime_sha256': record['source']['runtime_sha256'],
        'installed_runtime_sha256': record['installed']['runtime_sha256'],
        'distribution_inputs_sha256': record['source']['distribution_inputs_sha256'],
        'source_fingerprint': json_digest(record['source']),
        'dependency_versions': record['installed']['dependency_versions'],
        'warm_seconds': load(out / 'timing.json')['warm_seconds'],
        'claims': (['executing build/import and children', 'broad synthetic delivery; protected nondelivery',
                    'correct invoices; explicit safe incompletion and reviewed replacement', 'child and supported resume']
                   if name == 'dependency' else ['three registered roles and physical worker processes',
                    'broad synthetic delivery; sandbox and Vega nondelivery',
                    'private aggregate, chart and report independently checked',
                    'helper child and resumed writer retain project ceiling'] if name == 'swarm' else ['broad A-pass/B-fail', 'protected A-local fix; B intact',
                    'child, cwd, alias and resume stay scoped', 'separately authorized B task remains useful']),
        'prevention': 'tie; correctly configured underlying sandbox',
        # Private filenames can contain installation or session metadata too.
        'original_artifacts': [{'path_sha256': hashlib.sha256(r['path'].encode('utf-8')).hexdigest(),
                                'original_sha256': r['sha256']} for r in refs],
        'unavailable': ['live model evidence', 'human comprehension', 'playback timing'],
        'limits': ['trusted operator/controller/OS', 'registered local routes only',
                   'no universal egress or dataflow protection', 'synthetic continuation metadata']}
    return {'original_result_sha256': digest(out / 'result.json'),
            'public_payload_sha256': json_digest(payload), 'payload': payload}
