"""Original lifecycle observations. Synthetic faults, real installed commands.

No model calls or authentication copies. The resumed native boundary probe uses
the actual launch's configuration and Codex's documented sandbox test command.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import time

from evidence_io import capture, digest, load, reference, require, save
from product_security import Probe
from sandbox_diagnostics import BoundaryTrace, executable_identity
from terminal_driver import Terminal

LIFECYCLE_IDS = ('cancel-preserves-repo', 'installation-retry-preserves-data',
                 'upgrade-rollback-uninstall')


def snapshot(repo):
    return {str(p.relative_to(repo)): digest(p) if p.is_file() else 'directory'
            for p in sorted(repo.rglob('*'))}


def cancellation(probe, ptw, env):
    repo = probe.folder / 'repo'
    (repo / 'src').mkdir(parents=True)
    (repo / 'private').mkdir()
    (repo / 'src/app.py').write_text('print("existing useful project")\n')
    (repo / 'requirements.txt').write_text('')
    (repo / 'private/customer.txt').write_text('SYNTHETIC_PRIVATE\n')
    before = snapshot(repo)
    probe.response('initial repository hashes', before)
    state = probe.folder / 'operator-state'
    env = {**env, 'PTW_USER_STATE': str(state)}
    directory = state / hashlib.sha256(str(repo).encode()).hexdigest()[:24]
    argv = [ptw, 'codex', '--repo', str(repo), '--goal', 'Maintain this Python application',
            '--editable', 'src', '--files', '-', '--setup-only']
    for label, answer in (('reject', 'reject'), ('cancel', 'cancel'), ('eof', '\x04'),
                          ('interrupt', '\x03'), ('blank', '')):
        terminal = Terminal(argv, probe.folder / label, env=env, replace_env=True, cwd=probe.folder)
        try:
            terminal.expect('Approve exactly this policy?', 60)
            if label in ('eof', 'interrupt'):
                terminal.inputs.append({'seconds': time.monotonic() - terminal.started,
                                        'control': label})
                terminal._save_inputs()
                os.write(terminal.fd, answer.encode())
            else:
                terminal.send(answer)
            terminal.wait(lambda: terminal.exited, 30, label + ' exit')
        finally:
            code = terminal.close(graceful=False)
            probe.response(label + ' original PTY', reference(probe.evidence, terminal.folder / 'terminal.txt'))
            probe.response(label + ' original inputs', reference(probe.evidence, terminal.folder / 'inputs.json'))
            probe.response(label + ' process exit', {'exit_code': code})
        probe.check(label + ' cancellation exit', 130 if label in ('eof', 'interrupt') else 2, code)
        probe.check(label + ' no traceback', False, 'Traceback' in terminal.text)
        probe.check(label + ' preserves repository', before, snapshot(repo))
        probe.check(label + ' no active project', False, (directory / 'project.json').exists())
    # Rejection is recoverable through the same advertised command and review.
    terminal = Terminal(argv, probe.folder / 'retry', env=env, replace_env=True, cwd=probe.folder)
    try:
        terminal.expect('Approve exactly this policy?', 60)
        terminal.send('yes')
        terminal.wait(lambda: terminal.exited, 60, 'approved setup retry')
    finally:
        code = terminal.close(graceful=False)
        probe.response('retry original PTY', reference(probe.evidence, terminal.folder / 'terminal.txt'))
    try:
        probe.check('retry succeeds after explicit approval', 0, code)
        after = snapshot(repo)
        probe.check('retry preserves existing files/directories', before, {p: after.get(p) for p in before})
        probe.check('retry published project', True, (directory / 'project.json').is_file())
    finally:
        if (directory / 'project.json').is_file():
            from ptw.monitor import remove
            from ptw.store import Store
            from ptw.supervisor import Supervisor
            record = load(directory / 'project.json')
            store = Store(record['state'])
            store.stop(record['project'], 'cancellation probe cleanup')
            probe.response('cleanup', Supervisor(store).reconcile())
            remove(store)


def lifecycle_security(evidence, source, candidate, ptw, env):
    from product_install_acceptance import acceptance
    evidence = Path(evidence)
    probes = {name: Probe(evidence, evidence / 'security' / name, name, source,
        kind='native-lifecycle', fixture='synthetic download faults/version; actual installer and PTYs')
        for name in LIFECYCLE_IDS}
    rows = []
    try:
        cancellation(probes[LIFECYCLE_IDS[0]], ptw, env)
        rows.append(probes[LIFECYCLE_IDS[0]].finish())
        root = evidence / 'installer-lifecycle'
        result = acceptance(root, candidate=candidate)
        for name, labels in (
                ('installation-retry-preserves-data', ('http-error', 'interrupted-download', 'incorrect-hash',
                    'cold-install-http-and-automatic-doctor', 'same-version-retry', 'missing-login')),
                ('upgrade-rollback-uninstall', ('fixture-upgrade', 'rollback-with-real-doctor',
                    'uninstall', 'repeated-uninstall'))):
            probe = probes[name]
            probe.response('original lifecycle result', reference(evidence, root / 'result.json'))
            phases = {p['phase']: p for p in result['phases']}
            for label in labels:
                phase = phases[label]
                probe.response(label + ' original process', reference(evidence, root / phase['probe']['path']))
                probe.response(label + ' measurements', phase)
                probe.check(label + ' expected exit', phase['expected_exit'], phase['exit_code'])
                probe.check(label + ' preserved project', result['project_hashes_preserved'],
                            phase['preservation']['project'])
                probe.check(label + ' unrelated process alive', True, phase['preservation']['unrelated_job_alive'])
            if name == 'upgrade-rollback-uninstall':
                first = phases['same-version-retry']['installation_state']['active']
                upgraded = phases['fixture-upgrade']['installation_state']
                probe.check('upgrade changed active release', True, upgraded['active'] != first)
                probe.check('upgrade retains rollback', first, upgraded['previous'])
                probe.check('rollback restores first release', first,
                            phases['rollback-with-real-doctor']['installation_state']['active'])
                probe.check('unowned installation file retained', True, result['unowned_installation_file_retained'])
                effects = result['uninstall_effects']
                probe.check('retained original unowned note digest', effects['unowned_note_sha256'],
                            digest(effects['unowned_note']))
                probe.check('owned launchers removed', {'ptw': False, 'ptw-codex': False, 'ptw-install': False},
                            effects['owned_launchers'])
            rows.append(probe.finish())
        return rows
    except BaseException as exc:
        for probe in probes.values():
            if not probe.complete:
                probe.persist(exc)
        raise
    finally:
        save(evidence / 'lifecycle-security.json', {'security_checks': rows, 'source_sha256': source,
            'ended_epoch': time.time(), 'complete': len(rows) == len(LIFECYCLE_IDS)})


def resumed_sandbox_command(launch, payload):
    """Preserve the actual configuration-isolation wrapper and CLI overrides."""
    argv = launch['argv']
    split = argv.index('--')
    base = argv[split + 1:]
    require(len(base) > 3 and base[1] == 'resume', 'Expected actual resumed Codex launch')
    overrides = [base[i + 1] for i, arg in enumerate(base[:-1]) if arg == '-c']
    keys = [v.split('=', 1)[0] for v in overrides]
    require(len(keys) == len(set(keys)), 'Duplicate resumed configuration override')
    required = {'default_permissions="ptw-interactive"',
        'permissions.ptw-interactive.filesystem={"/"="deny"}',
        'permissions.ptw-interactive.network.enabled=false'}
    require(required <= set(overrides), 'Resumed launch lacks native denial profile')
    require(not any(v.startswith(('sandbox_mode=', 'sandbox_workspace_write=')) for v in overrides),
            'Legacy sandbox override would replace permission profile')
    # CLI 0.154.0 selects the host platform itself. A positional "linux"
    # becomes the executable, not a subcommand (see `codex help sandbox`).
    # Select the same named profile explicitly; the diagnostic helper must not
    # fall back to its own default sandbox policy.
    cwd = base[base.index('-C') + 1]
    command = argv[:split + 1] + [base[0], 'sandbox', '-P', 'ptw-interactive', '-C', cwd]
    for value in overrides:
        command += ['-c', value]
    return command + ['--', '/usr/bin/python3', '-I', '-B', '-c', payload]


def retain_boundary(probe, folder):
    """Retain all available originals, without following links or hiding gaps."""
    errors = []

    def visit(path):
        try:
            relative = path.relative_to(probe.evidence)
            require('..' not in relative.parts and
                    not any(p.is_symlink() for p in (path, *path.parents)) and
                    path.resolve().is_relative_to(probe.evidence.resolve()),
                    'Linked or escaping boundary artifact')
            mode = path.lstat().st_mode
            if stat.S_ISDIR(mode):
                for child in sorted(path.iterdir()):
                    visit(child)
            else:
                require(stat.S_ISREG(mode), 'Nonregular boundary artifact')
                probe.response('original boundary ' + str(path.relative_to(folder)),
                               reference(probe.evidence, path))
        except (OSError, ValueError) as exc:
            errors.append({'path': str(path), 'error_type': type(exc).__name__})

    visit(folder)
    return errors


def resume_security(evidence, source, session_root, private, outside, env):
    probe = Probe(evidence, Path(evidence) / 'security/resume-native-tools-denied',
                  'resume-native-tools-denied', source,
                  fixture='injected hostile command under actual resumed native permission configuration')
    try:
        launch_path = session_root / 'launch.json'
        launch = load(launch_path)
        probe.response('actual resumed launch', reference(evidence, launch_path))
        targets = [str(private), str(outside)]
        before = {p: digest(p) for p in targets}
        probe.response('sensitive fixtures before native launch', before)
        payload = '''import json, pathlib
result = {}
for name in TARGETS:
    p = pathlib.Path(name)
    row = {}
    for op in ('read', 'write'):
        try:
            if op == 'read': p.read_bytes()
            else: p.write_text('INDEPENDENT_NATIVE_ESCAPE')
            row[op] = True
        except OSError: row[op] = False
    result[name] = row
print(json.dumps(result, sort_keys=True))
'''.replace('TARGETS', repr(targets))
        command = resumed_sandbox_command(launch, payload)
        base = launch['argv'][launch['argv'].index('--') + 1:]
        cwd = base[base.index('-C') + 1]
        probe.response('host executable identities before native launch',
                       [executable_identity(p) for p in (launch['argv'][0], base[0], '/usr/bin/python3')])
        trace = BoundaryTrace(probe.folder / 'boundary')
        try:
            result = capture(command, probe.folder / 'native-command', env=env, cwd=cwd,
                             timeout=30, on_spawn=trace.start)
        finally:
            # Collection failures are secondary. Preserve the launch exception,
            # process receipt and each fixture measurement independently.
            collection_errors = []
            try:
                trace.close()
            except (OSError, ValueError) as exc:
                collection_errors.append({'path': str(trace.folder), 'error_type': type(exc).__name__})
            process = probe.folder / 'native-command/process.json'
            try:
                if process.is_file():
                    probe.response('original sandbox process', reference(evidence, process))
            except (OSError, ValueError) as exc:
                collection_errors.append({'path': str(process), 'error_type': type(exc).__name__})
            # Record effects before any exit/output assertion, including timeout
            # and deletion. A missing fixture must not suppress the other hash.
            after = {}
            for p in targets:
                try:
                    after[p] = digest(p) if Path(p).is_file() else None
                except OSError as exc:
                    after[p] = None
                    collection_errors.append({'path': p, 'error_type': type(exc).__name__})
            probe.response('sensitive fixtures after native launch', after)
            collection_errors.extend(retain_boundary(probe, trace.folder))
            if collection_errors:
                probe.response('native diagnostic collection errors', collection_errors)
        if result.returncode:
            from native_boundary import compiled_command, namespace_probe
            try:
                compiled, shell = compiled_command(trace.folder, command[command.index('--',
                    command.index('--') + 1) + 1:])
            except ValueError:
                # A generic startup failure remains a failure, never proof.
                probe.check('hostile command actually executed', 0, result.returncode)
                raise
            executable = compiled[compiled.index('--') + 1]
            probe.response('captured native compilation', compiled)
            probe.response('native denial classification', {
                'native_payload_executed': False,
                'method': 'independent syscalls through paused compiled namespace root',
                'limitation': 'filesystem visibility and exec denial only; no seccomp or in-sandbox payload claim'})
            probe.check('native bootstrap exists on host', True, Path(executable).is_file())
            probe.check('native bootstrap is executable on host', True, os.access(executable, os.X_OK))
            probe.check('original native exec denied', 1, result.returncode)
            probe.check('original native exec produced no payload output', '', result.stdout.decode())
            probe.check('original native exec reached denied executable',
                'bwrap: execvp ' + executable + ': No such file or directory', result.stderr.decode().strip())
            try:
                namespace_probe(probe, compiled, shell, targets, env, cwd)
            finally:
                after = {p: digest(p) if Path(p).is_file() else None for p in targets}
                probe.response('sensitive fixtures after namespace observation', after)
        else:
            probe.check('hostile command actually executed', 0, result.returncode)
            observed = json.loads(result.stdout)
            probe.response('actual hostile command result', observed)
            probe.check('private and outside reads/writes denied',
                        {p: {'read': False, 'write': False} for p in targets}, observed)
        probe.check('sensitive fixtures unchanged', before, after)
        probe.check('native diagnostic collection succeeded', [], collection_errors)
        row = probe.finish()
        save(Path(evidence) / 'resume-security.json', {'security_checks': [row], 'source_sha256': source,
            'ended_epoch': time.time(), 'complete': True})
        return row
    except BaseException as exc:
        probe.persist(exc)
        raise
