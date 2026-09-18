"""Reviewed snapshot previews; no arbitrary argv, URL or host-network workload."""
import fcntl
import json
import os
from pathlib import Path
import secrets
import sys
import time

from .execution import WRAPPER, prepare_command
from .monitor import health
from .policy import Invalid, OutsideScope, save, validate
from .supervisor import RUNTIME_HOST_PATHS, Supervisor
from .workspace import REQUEST_SCHEMA, scan, stamp


def candidates(scope, metadata, python, args):
    """Only explicit operator flags add network authority at policy review."""
    from .workspace_policy import relative
    result = []
    for language, executable in (('python', python), ('node', '/usr/bin/node')):
        value = getattr(args, 'preview_' + language, None)
        if value is None:
            continue
        path, separator, raw_port = value.rpartition(':')
        relative(path)
        if (not separator or not raw_port.isascii() or not raw_port.isdecimal() or
                not 1024 <= int(raw_port) <= 65535 or not any(
                    path == root or kind == 'tree' and path.startswith(root + '/') for root, kind in scope.items())):
            raise Invalid('Preview requires a selected source entry script and port 1024 to 65535')
        lifetime = getattr(args, 'preview_seconds', None)
        lifetime = 900 if lifetime is None else lifetime
        if type(lifetime) is not int or not 1 <= lifetime <= 3600:
            raise Invalid('Preview lifetime must be 1 to 3600 seconds')
        result.append({'id': language + '-preview', 'argv': [executable, *(['-B'] if language == 'python' else []), path],
                       'resources': sorted(set(scope) | set(metadata)), 'timeout_seconds': 10,
                       'preview': {'port': int(raw_port), 'lifetime_seconds': lifetime}})
    if len({c['preview']['port'] for c in result}) != len(result):
        raise Invalid('Choose distinct preview ports')
    if not result and getattr(args, 'preview_seconds', None) is not None:
        raise Invalid('Preview lifetime requires an explicit preview script')
    return result


def preview_command(store, token, definition, before, settings, directory):
    target, command, _ = prepare_command(store, token, definition, before, settings, directory)
    boundary = command.index('--')
    namespace, payload = command[:boundary], command[boundary + 1:]
    mount = namespace.index('--bind')
    if namespace[mount:mount + 3] != ['--bind', str(target), '/target']:
        raise Invalid('Unexpected preview mount layout')
    namespace[mount:mount + 3] = ['--ro-bind', str(target), '/seed',
                                 '--size', str(512 * 1024 * 1024), '--tmpfs', '/target']
    worker = Path(__file__).with_name('preview_transport.py')
    namespace += ['--ro-bind', str(worker), '/preview-transport.py']
    wrapper = payload.index(WRAPPER)
    if payload[wrapper - 4:wrapper] != ['/usr/bin/python3', '-I', '-S', '-c']:
        raise Invalid('Unexpected preview command wrapper')
    # Preserve package mounts, environment and the fixed reviewed argv.
    app = payload[:wrapper - 4] + payload[wrapper + 3:]
    env = app.index('/usr/bin/env')
    app[env + 1:env + 1] = ['HOST=127.0.0.1', 'PORT=' + str(definition['preview']['port'])]
    # nono 0.77.0's --block-net wins over --listen-port. Its manifest
    # conversion independently adds bind exceptions to blocked networking.
    # The manifest path does not inherit CLI filesystem defaults or the
    # --sandbox-policy override: it uses auto (Landlock + static seccomp).
    # Grant only the already mounted runtimes, devices and prepared inputs.
    grants = [{'path': p, 'access': 'read', 'type': 'directory'}
              for p in RUNTIME_HOST_PATHS if Path(p).exists()]
    grants.append({'path': '/proc', 'access': 'read', 'type': 'directory'})
    grants += [{'path': '/dev/' + p, 'access': 'readwrite', 'type': 'file'}
               for p in ('null', 'zero', 'random', 'urandom')]
    permissions = app[:app.index('--')]
    grants += [{'path': permissions[i + 1], 'access': 'readwrite' if arg == '--allow' else 'read',
                'type': 'directory'} for i, arg in enumerate(permissions) if arg in ('--allow', '--read')]
    manifest = {'version': '0.1.0', 'filesystem': {'grants': grants},
                'network': {'mode': 'blocked', 'ports': {
                    'bind': [definition['preview']['port']], 'connect': [], 'localhost': [], 'localhost_range': []}}}
    manifest_path = Path(directory) / 'capabilities.json'
    save(manifest_path, manifest)
    namespace += ['--ro-bind', str(manifest_path), '/preview-capabilities.json']
    # The manifest is outside /target and has no application read/write grant.
    # Keep verbose backend/capability diagnostics in the bounded startup tail.
    app = ['/nono', 'run', '--config', '/preview-capabilities.json', '--verbose',
           '--no-rollback', '--no-audit', '--no-diagnostics', *app[app.index('--'):]]
    return namespace + ['--', '/usr/bin/python3', '-I', '-S', '/preview-transport.py',
                        'inner', str(definition['preview']['port']), definition.get('cwd', ''), *app]


def service_request(broker, token, event, req):
    store, supervisor = broker.store, Supervisor(broker.store)
    # A per-controller launch mutex prevents duplicate starts and replays, but
    # never blocks monitor/stop admission. No model input becomes a lock path.
    lock = os.open(store.directory / 'preview.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _service_request(broker, supervisor, token, event, req)
    finally:
        os.close(lock)


def _service_request(broker, supervisor, token, event, req):
    store = broker.store
    with store.locked() as db:
        actor, project, bundle, prior = broker.inspect(db, token, event, req)
        if prior is not None:
            return prior
        try:
            validate(REQUEST_SCHEMA, req)
            if (req['path'] or req['destination'] or req['expected'] or len(req['content']) > 8192 or
                    (req['action'] != 'service_start' and req['content'])):
                raise Invalid('Unsupported preview request fields')
        except Invalid:
            return broker.deny(db, actor, project, bundle, event, req, 'Malformed preview request')
        definition = next((c for c in bundle['policy']['project']['commands'] if c['id'] == req['resource']), None)
        if (req['resource'] not in json.loads(actor['commands']) or not definition or 'preview' not in definition):
            return broker.deny(db, actor, project, bundle, event, req, 'Preview outside reviewed task/session commands')
        row = db.execute('SELECT * FROM previews WHERE session=? AND command=?',
                         (actor['id'], req['resource'])).fetchone()
        state = supervisor.state(row['unit']) if row else {'confirmed_stopped': True}
        if req['action'] == 'service_stop':
            if row:
                state = supervisor.terminate(row['unit'])
            return broker.record(db, actor, event, req, 'allow' if state['confirmed_stopped'] else 'blocked',
                                 'Preview termination checked', effect='service_stop', **state)
        if req['action'] == 'service_status' or (row and not state['confirmed_stopped']):
            ready = bool(row and (Path(row['directory']) / 'ready.json').is_file() and
                         state.get('ActiveState') == 'active')
            return broker.record(db, actor, event, req, 'allow', 'Preview state', effect='service_status',
                                 ready=ready, url='http://127.0.0.1:' + str(definition['preview']['port']) + '/' if ready else None,
                                 **state)
        try:
            broker.integrity(db, actor['project'], bundle)
            before = scan(bundle['inventory'], definition['resources'])
        except (Invalid, OSError) as exc:
            return broker.record(db, actor, event, req, 'blocked', 'Cannot snapshot preview inputs: ' + str(exc))
        approval = bundle['approval']['sha256']
    directory = store.directory / 'previews' / secrets.token_hex(16)
    directory.mkdir(mode=0o700, parents=True)
    unit = None
    try:
        if not health(store)['healthy']:
            raise Invalid('Controller monitoring is unavailable')
        command = preview_command(store, token, definition, before, req['content'], directory)
        config = {'argv': command, 'port': definition['preview']['port'], 'directory': str(directory),
                  'lifetime_seconds': definition['preview']['lifetime_seconds']}
        save(directory / 'config.json', config)
        save(directory / 'inputs.json', {p: stamp(v) for p, v in before.items()})
        worker = Path(__file__).with_name('preview_transport.py')
        unit = supervisor.background(token, [sys.executable, '-I', '-B', str(worker), 'outer', str(directory / 'config.json')],
                                     service_seconds=definition['preview']['lifetime_seconds'] + 15)
        save(directory / 'unit.json', {'unit': unit})
        deadline = time.monotonic() + 15
        while not (directory / 'ready.json').is_file():
            if ((directory / 'error.json').exists() or time.monotonic() >= deadline or
                    supervisor.state(unit)['confirmed_stopped']):
                raise Invalid('Preview startup failed or timed out; no fallback')
            time.sleep(.05)
        monitored = health(store)['healthy']
        with store.locked() as db:
            actor, project, bundle, prior = broker.inspect(db, token, event, req)
            if prior is not None or bundle['approval']['sha256'] != approval:
                raise Invalid('Preview session or approval changed during launch')
            state = supervisor.state(unit)
            if state.get('ActiveState') != 'active' or not monitored:
                raise Invalid('Preview or controller exited during startup')
            db.execute('INSERT OR REPLACE INTO previews VALUES(?,?,?,?)',
                       (actor['id'], definition['id'], unit, str(directory)))
            result = broker.record(db, actor, event, req, 'allow', 'Snapshot preview ready',
                effect='service_start', ready=True, unit=unit,
                url='http://127.0.0.1:' + str(definition['preview']['port']) + '/',
                lifetime_seconds=definition['preview']['lifetime_seconds'])
        save(directory / 'result.json', result)
        return result
    except (Invalid, OSError) as exc:
        state = supervisor.terminate(unit) if unit else {'confirmed_stopped': True}
        save(directory / 'failure.json', {'error': str(exc), 'termination': state})
        with store.locked() as db:
            actor, project, bundle, prior = broker.inspect(db, token, event, req)
            if not state['confirmed_stopped']:
                store.stop_from_db(db, actor['project'], 'Preview termination uncertain')
            if isinstance(exc, OutsideScope):
                return prior or broker.deny(db, actor, project, bundle, event, req, str(exc))
            return prior or broker.record(db, actor, event, req, 'blocked', str(exc),
                                          violation_counted=False, termination=state)
