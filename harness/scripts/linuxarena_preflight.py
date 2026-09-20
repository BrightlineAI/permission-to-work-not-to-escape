"""Bounded native prerequisites for the file_indexing bridge; no model calls.

This is a compatibility probe, NOT a complete adapter or benchmark episode.
It creates/removes two sequential owned fixtures in the retained daemon.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time
from urllib.parse import urlparse

from evidence_io import capture, digest, load, reference, require, save
from ptw.linuxarena_cgroup import ExecutionSubtree, container_group, process_identity
from ptw import linuxarena_lifecycle
from ptw.policy import Invalid, approve, compile_policy, digest as policy_digest
from ptw.sample import create as create_sample
from ptw.store import Store
from ptw.supervisor import Supervisor
from ptw.workflow import end_session

CT_PIN = '3d86b8db50c1d5ee8586a13976642fcbe4a34ca3'
ENV_PIN = '44e200685340997560e15997fd8c7973b6675a48'
MAIN_IMAGE = 'linuxarena/env-file_indexing@sha256:f7edcb45b452e77b5b2c74526ca1ac10cd5d40c9695375b31225f8b06302cdbb'
SCRIPTS = Path(__file__).resolve().parent


def private_output(path):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path and '..' not in path.parts,
            'Output must be a new canonical absolute directory')
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Linked output directory')
    # Empty .git directories can be sandbox sentinels, not repositories. Reject
    # all other markers conservatively, including malformed/dangling gitfiles;
    # never follow a marker or read its configuration. Inspection errors fail
    # closed. Also reject this checkout even when its metadata is masked.
    require(not path.is_relative_to(SCRIPTS.parents[1]), 'Raw receipts must be outside checkouts')
    for parent in (path, *path.parents):
        marker = parent / '.git'
        require(not marker.is_symlink(), 'Raw receipts must be outside checkouts')
        if marker.exists():
            require(marker.is_dir() and next(marker.iterdir(), None) is None,
                    'Raw receipts must be outside checkouts')
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    return path


def child_environment(runtime, out):
    # Do not read or propagate credentials, proxy clients or the budget ledger.
    env = {k: os.environ[k] for k in ('PATH', 'LANG', 'TZ', 'XDG_RUNTIME_DIR') if k in os.environ}
    env.update(HOME=str(out / 'home'), XDG_CACHE_HOME=str(out / 'cache'),
               CONTROL_TOWER_SETTINGS_DIR=str(runtime / 'settings'),
               CONTROL_TOWER_MODEL_RATES=str(runtime / 'model_rates.json'),
               INSPECT_EVAL_MODEL_COST_CONFIG=str(runtime / 'inspect_model_costs.json'),
               OPENROUTER_BASE_URL='http://127.0.0.1:1/api/v1',
               OPENROUTER_API_KEY='closed-endpoint-no-model-calls',
               CONTROL_TOWER_MAX_RETRIES='0', DISABLE_TUI='1', INSPECT_DISPLAY='plain',
               PYTHONDONTWRITEBYTECODE='1', PYTHONUNBUFFERED='1')
    return env


class Commands:
    def __init__(self, out, env):
        self.out, self.env, self.sequence = out, env, 0

    def __call__(self, argv, timeout=30):
        self.sequence += 1
        result = capture(argv, self.out / 'processes' / f'{self.sequence:04d}',
                         env=self.env, cwd=self.out, timeout=timeout)
        require(result.returncode == 0,
                f'Native prerequisite command {self.sequence} failed; retain original receipt')
        return result.stdout


def source_tree(root, pin, command):
    """Verify actual bytes against the pinned Git tree, not just clean status.

    Tracked documentation symlinks are hashed as links, never dereferenced.
    No whole repository is copied or put in a public evidence blob.
    """
    require(root.is_dir() and root.resolve() == root, 'Missing or linked retained source')
    actual = command(['git', '-C', str(root), 'rev-parse', 'HEAD']).decode().strip()
    require(actual == pin, 'Retained source revision differs from the approved pin')
    rows = command(['git', '-C', str(root), 'ls-tree', '-rz', pin]).split(b'\0')
    hashes = {}
    for row in filter(None, rows):
        meta, raw_name = row.split(b'\t', 1)
        mode, kind, oid = meta.decode().split()
        name = raw_name.decode()
        relative = PurePosixPath(name)
        require(not relative.is_absolute() and '..' not in relative.parts and kind == 'blob',
                'Unsupported retained source entry')
        path = root / name
        require(all(not p.is_symlink() for p in path.parents if p.is_relative_to(root)),
                'Linked source ancestor')
        info = path.lstat()
        if mode == '120000':
            require(stat.S_ISLNK(info.st_mode), 'Tracked link changed type')
            data = os.fsencode(os.readlink(path))
        else:
            require(mode in ('100644', '100755') and stat.S_ISREG(info.st_mode),
                    'Tracked source changed type')
            require(bool(info.st_mode & 0o111) == (mode == '100755'), 'Tracked source mode changed')
            data = path.read_bytes()
        require(hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == oid,
                'Retained source content differs from pin: ' + name)
        hashes[name] = hashlib.sha256(data).hexdigest()
    require(bool(hashes), 'Empty retained source tree')
    return {'commit': pin, 'files_sha256': hashes}


def daemon_environment(runtime, env):
    receipt_path = runtime.parent / 'docker/runtime.json'
    require(receipt_path.is_file() and not receipt_path.is_symlink(), 'Missing private daemon receipt')
    receipt = load(receipt_path)
    host = receipt.get('docker_host', '')
    parsed = urlparse(host)
    require(parsed.scheme == 'unix' and not parsed.netloc and not parsed.query and
            not parsed.fragment and parsed.path.startswith('/') and
            Path(parsed.path).resolve() not in (Path('/run/docker.sock'), Path('/var/run/docker.sock')),
            'Only the recorded private Unix Docker socket is allowed')
    require(receipt.get('rootless') is True and
            re.fullmatch(r'[a-zA-Z0-9_-]+\.slice', receipt.get('slice', '')),
            'Missing rootless project allocation')
    return {**env, 'DOCKER_HOST': host}, receipt


def verify_daemon(command, receipt):
    info = json.loads(command(['docker', 'info', '--format', '{{json .}}']))
    require(info.get('ID') == receipt.get('daemon_id') and
            any('rootless' in x for x in info.get('SecurityOptions', [])) and
            info.get('CgroupVersion') == '2' and info.get('CgroupDriver') == 'systemd',
            'Native daemon identity/rootless/cgroup compatibility failed')
    # Inspect only; do not create or alter a shared slice.
    raw = command(['systemctl', '--user', 'show', receipt['slice'],
                   '-p', 'ControlGroup', '-p', 'CPUQuotaPerSecUSec', '-p', 'MemoryMax'])
    values = dict(line.split('=', 1) for line in raw.decode().splitlines() if '=' in line)
    group = values.get('ControlGroup', '')
    require(group.startswith('/') and PurePosixPath(group).name == receipt['slice'] and
            '..' not in PurePosixPath(group).parts, 'Missing existing experiment allocation')
    cgroup = Path('/sys/fs/cgroup') / group[1:]
    quota, period = (cgroup / 'cpu.max').read_text().split()
    memory = (cgroup / 'memory.max').read_text().strip()
    require(quota != 'max' and 0 < int(quota) <= int(period) and memory != 'max' and
            0 < int(memory) <= 5 * 1024 ** 3, 'Existing aggregate limit exceeds one CPU / 5 GiB')
    images = json.loads(command(['docker', 'image', 'inspect', '--format',
                                 '{{json .Id}}', MAIN_IMAGE]))
    require(re.fullmatch('sha256:[0-9a-f]{64}', images), 'Missing installed image identity')
    return {'daemon_id': info['ID'], 'cgroup': group, 'cpu_max': [quota, period],
            'memory_max': memory, 'image_id': images}


def wait_for(predicate, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(.05)
    raise TimeoutError('Native prerequisite observation timed out')


# Trusted deterministic compatibility payload. SIGSTOP is before fork/effects.
# It is NOT a LinuxArena agent, scorer or confinement demonstration.
HEARTBEAT = '''import os, signal, sys, time
os.kill(os.getpid(), signal.SIGSTOP)
child = os.fork()
path = '/probe/' + sys.argv[2] + ('child' if child == 0 else 'parent')
while True:
    with open(path, 'ab', buffering=0) as stream:
        stream.write(b'x')
    time.sleep(.02)
'''


def subtree_probe(command, out, daemon):
    """No network, pulls, native entrypoint, task code, services or model."""
    nonce = secrets.token_hex(12)
    name = 'ptw-linuxarena-prerequisite-' + nonce
    effects = out / 'effects'
    effects.mkdir(mode=0o700)
    cid = None
    subtree = None
    unrelated = None
    result = {}
    try:
        # `create` retains an immutable identity before starting any process.
        cid = command(['docker', 'create', '--pull=never', '--name', name,
                       '--label', 'ptw.prerequisite=' + nonce, '--network=none',
                       '--read-only', '--cpus=0.25', '--memory=256m', '--pids-limit=32',
                       '--cgroup-parent=' + PurePosixPath(daemon['cgroup']).name,
                       '--mount', 'type=bind,src=' + str(effects) + ',dst=/probe',
                       '--entrypoint', '/bin/sleep', daemon['image_id'], '120']).decode().strip()
        require(re.fullmatch('[0-9a-f]{64}', cid), 'Docker did not return an immutable container ID')
        save(out / 'owned-container.json', {'id': cid, 'nonce': nonce, 'daemon_id': daemon['daemon_id']})
        command(['docker', 'start', cid])
        initial = json.loads(command(['docker', 'inspect', '--format', '{{json .State}}', cid]))
        identity = process_identity(initial['Pid'])
        group = container_group(identity['cgroup'], cid)
        require(group.is_relative_to(Path('/sys/fs/cgroup') / daemon['cgroup'][1:]),
                'Container is outside the existing aggregate allocation')
        subtree = ExecutionSubtree(identity['cgroup'], cid, nonce)
        unrelated = ExecutionSubtree(identity['cgroup'], cid, secrets.token_hex(12))
        store = Store(out / 'controller')

        def project(name):
            folder = out / name
            create_sample(folder)
            policy, inventory = load(folder / 'policy.json'), load(folder / 'inventory.json')
            policy['project']['id'] = name
            store.activate(approve(policy, inventory, policy_digest(compile_policy(policy, inventory)),
                                   'deterministic lifecycle fixture operator'))
            return store.register(name, 'frontend')

        actor, other_actor = project('website'), project('unrelated')
        unit = linuxarena_lifecycle.register(store, actor['token'], subtree,
                                            daemon_id=daemon['daemon_id'], control=identity)
        other_unit = linuxarena_lifecycle.register(store, other_actor['token'], unrelated,
                                                  daemon_id=daemon['daemon_id'], control=identity)

        def launcher(label):
            launch_nonce = secrets.token_hex(12)
            command(['docker', 'exec', '--detach', cid, '/usr/bin/python3', '-I', '-S', '-c',
                     HEARTBEAT, launch_nonce, label])

            def stopped_process():
                listing = command(['docker', 'top', cid, '-eo', 'pid,args']).decode()
                candidates = []
                for line in listing.splitlines()[1:]:
                    pid = int(line.split(None, 1)[0])
                    try:
                        args = (Path('/proc') / str(pid) / 'cmdline').read_bytes().split(b'\0')
                        if launch_nonce.encode() in args:
                            observed = process_identity(pid)
                            if observed['state'] == 'T':
                                candidates.append(observed)
                    except FileNotFoundError:
                        continue
                require(len(candidates) <= 1, 'Ambiguous stopped launcher identity')
                return candidates[0] if candidates else None
            return wait_for(stopped_process)

        stopped = launcher('')
        require(not list(effects.iterdir()), 'Payload acted before admission')
        for token in ('forged-' * 8, other_actor['token']):
            try:
                linuxarena_lifecycle.admit(store, token, unit, stopped)
            except Invalid:
                pass
            else:
                raise ValueError('Forged or unrelated session admitted')
        require(not list(effects.iterdir()), 'Rejected actor produced effects')
        # New controller object reopens only the stored cgroup inode/boot identity.
        store = Store(out / 'controller')
        admitted = linuxarena_lifecycle.admit(store, actor['token'], unit, stopped)
        linuxarena_lifecycle.admit(store, other_actor['token'], other_unit, launcher('unrelated-'))
        resumed = linuxarena_lifecycle.admit(Store(out / 'controller'), actor['token'], unit,
                                            launcher('reopened-'))
        wait_for(lambda: all((effects / part).exists() and (effects / part).stat().st_size >= 3
                             for part in ('parent', 'child', 'reopened-parent', 'reopened-child',
                                          'unrelated-parent', 'unrelated-child')))
        store.stop('website', 'deterministic lifecycle prerequisite')
        outcomes = Supervisor(Store(out / 'controller')).reconcile()
        termination = next(item for item in outcomes if item['unit'] == unit)
        require(termination['confirmed_stopped'], 'Container descendant termination unconfirmed')
        lengths = {p.name: p.stat().st_size for p in effects.iterdir() if not p.name.startswith('unrelated-')}
        other_before = (effects / 'unrelated-child').stat().st_size
        time.sleep(.15)
        require(lengths == {p.name: p.stat().st_size for p in effects.iterdir() if not p.name.startswith('unrelated-')},
                'Physical effects continued after confirmed stop')
        require((effects / 'unrelated-child').stat().st_size > other_before,
                'Project stop interrupted unrelated execution domain')
        closure = end_session(Store(out / 'controller'), other_actor['token'], 'finish')
        require(closure['confirmed_stopped'], 'Native session closure could not confirm physical stop')
        late = launcher('late-')
        try:
            linuxarena_lifecycle.admit(Store(out / 'controller'), actor['token'], unit, late)
        except Invalid:
            pass
        else:
            raise ValueError('Stopped project admitted a later launcher')
        require(not (effects / 'late-parent').exists(), 'Late admission acted after stop')
        # Same container/root filesystem remains available for trusted inspection.
        command(['docker', 'exec', cid, '/bin/sh', '-c', 'test -s /probe/parent && test -s /probe/child'])
        after = process_identity(initial['Pid'])
        require(after['starttime'] == identity['starttime'] and after['cgroup'] == identity['cgroup'],
                'Stopping the execution domain killed or replaced the control process')
        result = {'scope': 'cgroup prerequisite only; no confinement/scorer claim',
                  'container': cid, 'initial': identity, 'launcher': admitted,
                  'termination': termination, 'effects_bytes': lengths,
                  'controller_reopened_launcher': resumed, 'unrelated_continued': True,
                  'unrelated_explicit_closure': closure,
                  'late_admission_denied': True, 'control_process_preserved': True, 'paid_calls': 0}
        save(out / 'lifecycle.json', store.audit_export('website'))
        save(out / 'subtree.json', result)
        return result
    finally:
        # Only the immutable ID created by this invocation may be cleaned up.
        try:
            for owned in (subtree, unrelated):
                if owned is not None:
                    try:
                        owned.terminate()
                    finally:
                        owned.close()
        finally:
            if cid and re.fullmatch('[0-9a-f]{64}', cid):
                command(['docker', 'rm', '--force', cid])


def run(runtime, output):
    runtime = Path(runtime)
    require(runtime.is_absolute() and runtime.resolve() == runtime and runtime.is_dir(),
            'Retained runtime must be an existing canonical absolute directory')
    out = private_output(output)
    attempt = {'schema': 1, 'scope': 'native bridge prerequisites', 'started_epoch': time.time(),
               'status': 'incomplete', 'paid_calls': 0,
               'driver_sha256': digest(__file__), 'taskspace_driver_sha256': digest(SCRIPTS / 'linuxarena_taskspace.py'),
               'confinement_driver_sha256': digest(SCRIPTS / 'linuxarena_confinement.py'),
               'loader_diagnostics_sha256': digest(SCRIPTS / 'linuxarena_loader_diagnostics.py'),
               'subtree_sha256': digest(sys.modules[ExecutionSubtree.__module__].__file__),
               'runtime_sha256': linuxarena_lifecycle.runtime_identity()}
    save(out / 'attempt.json', attempt)
    try:
        env = child_environment(runtime, out)
        (out / 'home').mkdir(mode=0o700)
        command = Commands(out, env)
        sources = {name: source_tree(runtime / relative, pin, command) for name, relative, pin in
                   (('control_tower', 'control-tower', CT_PIN),
                    ('file_indexing', 'settings/pilot/file_indexing', ENV_PIN))}
        save(out / 'sources.json', sources)
        native = json.loads(command([str(runtime / 'control-tower/.venv/bin/python'), '-I', '-B',
                                    '-X', 'pycache_prefix=' + str(out / 'empty-pycache'),
                                    str(SCRIPTS / 'linuxarena_taskspace.py')], timeout=120).decode().splitlines()[-1])
        require(native['sandbox_module'] == str(runtime / 'control-tower/src/control_tower/sandbox/docker.py'),
                'Native sandbox imported a different source')
        save(out / 'taskspace.json', native)
        command.env, receipt = daemon_environment(runtime, env)
        daemon = verify_daemon(command, receipt)
        save(out / 'daemon.json', daemon)
        # A conservative no-download gate; this fixture uses only 256 MiB.
        memory = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
        require(int(memory['MemAvailable'].split()[0]) >= 512 * 1024 and
                shutil.disk_usage(out).free >= 1024 ** 3, 'Insufficient free resources for prerequisite fixture')
        subtree_probe(command, out, daemon)
        from linuxarena_confinement import probe as namespace_probe
        namespace_probe(command, out, daemon)
        require(linuxarena_lifecycle.runtime_identity() == attempt['runtime_sha256'],
                'Controller runtime changed during native prerequisite')
        attempt.update(status='complete', records={name: reference(out, out / name) for name in
                       ('sources.json', 'taskspace.json', 'daemon.json', 'subtree.json', 'lifecycle.json',
                        'namespace.json', 'namespace-spec.json', 'namespace-lifecycle.json', 'tools.json',
                        'namespace-diagnostics.json')})
        return attempt
    except BaseException as exc:
        attempt.update(status='failed', error_type=type(exc).__name__)
        raise
    finally:
        attempt['ended_epoch'] = time.time()
        save(out / 'attempt.json', attempt)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, required=True, help='Read-only retained native runtime')
    parser.add_argument('--out', type=Path, required=True, help='New private receipt directory outside Git')
    args = parser.parse_args(argv)
    try:
        result = run(args.runtime, args.out)
        print(json.dumps({'status': result['status'], 'scope': result['scope'], 'paid_calls': 0}))
        return 0
    except KeyboardInterrupt:
        print('Prerequisite interrupted; retain its attempt and process receipts.', file=sys.stderr)
        return 130
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print('Prerequisite failed: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
