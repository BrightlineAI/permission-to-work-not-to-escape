"""Operator-only dependency edits with same-project, recoverable publication."""
import copy
import fcntl
import getpass
import hashlib
import json
import os
from pathlib import Path
import secrets

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from .dependency_binding import verify_inputs
from .policy import Invalid, approve, canonical, check_approval, compile_policy, digest, load, save
from .setup_transaction import atomic, fingerprint, move, sync
from .store import Store
from .workspace_policy import relative, resource_info


def recover(directory):
    """Called under onboarding.lock, before admitting any new operator session."""
    journal_path = directory / 'dependency-journal.json'
    if not journal_path.exists():
        return
    journal = load(journal_path)
    if journal['phase'] in ('committed', 'rolled-back'):
        return
    store = Store(directory / 'controller')
    with store.locked() as db:
        row, bundle = store.project(db, journal['project'])
        committed = bundle['approval']['sha256'] == journal['new_sha256']
    if committed:
        try:
            for operation in journal['operations']:
                if fingerprint(Path(operation['destination'])) != operation['new']:
                    raise Invalid('Committed dependency revision needs operator recovery')
            verify_inputs(bundle)
        except BaseException:
            store.stop(journal['project'], 'Committed dependency revision changed during recovery')
            raise
        journal['phase'] = 'committed'
        atomic(journal_path, journal)
        return
    try:
        for operation in reversed(journal['operations']):
            destination, source, backup = (Path(operation[k]) for k in ('destination', 'source', 'backup'))
            current = fingerprint(destination)
            if current == operation['new']:
                move(destination, source)
                current = None
            if current is not None and current != operation['old']:
                raise Invalid('Dependency recovery preserves a concurrent edit; inspect the journal')
            if backup.exists():
                if fingerprint(backup) != operation['old'] or current is not None:
                    raise Invalid('Dependency recovery backup conflict')
                move(backup, destination)
        with store.locked() as db:
            row, bundle = store.project(db, journal['project'])
            if bundle['approval']['sha256'] != journal['old_sha256']:
                raise Invalid('Concurrent policy revision cannot be overwritten')
            # A real stop and all counters survive rollback. Revoked sessions
            # remain revoked; recovery never restarts prior processes.
            if row['dependency_revision'] == journal['new_sha256']:
                db.execute('UPDATE projects SET setup_pending=0,dependency_revision=NULL WHERE id=?', (journal['project'],))
        journal['phase'] = 'rolled-back'
        atomic(journal_path, journal)
    except BaseException:
        store.stop(journal['project'], 'Dependency recovery conflict; operator inspection required')
        raise


def publish(directory, stage, old, new, changes, expected, record):
    """Only called after exact review approval. No task/project rows are recreated."""
    from .supervisor import Supervisor
    from .workspace import Workspace
    check_approval(new)
    project = old['policy']['project']['id']
    if new['policy']['project']['id'] != project or old['inventory']['root'] != new['inventory']['root']:
        raise Invalid('Dependency revision cannot replace project identity or source root')
    if [t['id'] for t in old['policy']['tasks']] != [t['id'] for t in new['policy']['tasks']]:
        raise Invalid('Dependency revision must preserve task identities')
    store = Store(directory / 'controller')
    repo = Path(old['inventory']['root'])
    if stage.stat().st_dev != repo.stat().st_dev:
        raise Invalid('Dependency staging must be on the project filesystem for atomic publication')
    journal = {'phase': 'approved', 'project': project, 'old_sha256': old['approval']['sha256'],
        'new_sha256': new['approval']['sha256'], 'operations': []}
    # Staged replacements are durable before suspending work or touching files.
    replacements = [(repo / name, content) for name, content in sorted(changes.items())]
    replacements += [(repo / '.ptw/policy.json', json.dumps(new['policy'], indent=2) + '\n'),
                     (directory / 'project.json', json.dumps(record, indent=2) + '\n')]
    for index, (destination, content) in enumerate(replacements):
        source, backup = stage / ('publish-' + str(index)), stage / ('backup-' + str(index))
        with source.open('x') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        journal['operations'].append({'destination': str(destination), 'source': str(source), 'backup': str(backup),
            'old': fingerprint(destination), 'new': fingerprint(source)})
    sync(stage)
    for name, identity in expected.items():
        if fingerprint(repo / name) != identity:
            raise Invalid('Dependency input changed after review: ' + name)
    path = directory / 'dependency-journal.json'
    if path.exists():
        save(stage / 'previous-journal.json', load(path))
    atomic(path, journal)
    try:
        with store.locked() as db:
            row, current = store.project(db, project)
            if row['stopped'] or row['setup_pending'] or current['approval']['sha256'] != old['approval']['sha256']:
                raise Invalid('Stopped, pending or changed project cannot begin dependency revision')
            Workspace(store).integrity(db, project, current)
            db.execute('BEGIN IMMEDIATE')
            db.execute('UPDATE projects SET setup_pending=1,dependency_revision=? WHERE id=?',
                (journal['new_sha256'], project))
            db.execute('UPDATE sessions SET closed=1 WHERE project=?', (project,))
            db.commit()
        journal['phase'] = 'suspended'
        atomic(path, journal)
        Supervisor(store).reconcile()
        if any(not w['stopped'] for w in store.status(project)['workloads']):
            raise Invalid('Project work has not stopped; dependency revision cannot publish')
        for name, identity in expected.items():
            if fingerprint(repo / name) != identity:
                raise Invalid('Dependency input changed during suspension: ' + name)
        journal['phase'] = 'publishing'
        atomic(path, journal)
        for operation in journal['operations']:
            destination = Path(operation['destination'])
            if fingerprint(destination) != operation['old']:
                raise Invalid('Dependency publication conflicts with a concurrent edit')
            if operation['old'] is not None:
                move(destination, Path(operation['backup']))
            move(Path(operation['source']), destination)
        with store.locked() as db:
            row, current = store.project(db, project)
            if row['stopped'] or current['approval']['sha256'] != old['approval']['sha256']:
                raise Invalid('Stop or concurrent policy revision prevents activation')
            verify_inputs(new)
            check_approval(new)
            db.execute('BEGIN IMMEDIATE')
            for name in new['inventory']['resources']:
                info = resource_info(new['inventory'], name)
                if name in old['inventory']['resources'] and new['inventory']['resources'][name]['path'] not in changes:
                    binding = db.execute('SELECT device,inode FROM bindings WHERE project=? AND resource=?',
                        (project, name)).fetchone()
                    if binding is None or tuple(binding) != (info.st_dev if info else 0, info.st_ino if info else 0):
                        raise Invalid('Unrelated resource identity changed during dependency revision')
                db.execute('INSERT OR REPLACE INTO bindings VALUES(?,?,?,?)',
                    (project, name, info.st_dev if info else 0, info.st_ino if info else 0))
            db.execute('UPDATE projects SET bundle=?,setup_pending=0,dependency_revision=NULL WHERE id=?', (canonical(new), project))
            db.commit()
        journal['phase'] = 'committed'
        atomic(path, journal)
    except BaseException:
        recover(directory)
        raise


def edit_requirements(text, operation, specs):
    from .dependency_resolution import checked_requirement, requirement_lines
    wanted = {}
    for spec in specs:
        value = checked_requirement(spec)
        name = canonicalize_name(value.name)
        if name in wanted or value.marker or value.extras:
            raise Invalid('Dependency edit needs distinct plain package declarations')
        wanted[name] = spec
    lines = text.splitlines(keepends=True)
    found = set()
    result = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            result.append(line)
            continue
        if stripped.startswith('-') or stripped.endswith('\\'):
            raise Invalid('Edit included/continued requirements at their explicit authoritative file')
        declaration = checked_requirement(next(requirement_lines(line)))
        name = canonicalize_name(declaration.name)
        if name not in wanted:
            result.append(line)
            continue
        if name in found:
            raise Invalid('Ambiguous duplicate direct dependency')
        found.add(name)
        if operation == 'add':
            raise Invalid('Dependency already exists; use update')
        if operation == 'update':
            if not Requirement(wanted[name]).specifier:
                raise Invalid('Updating an exact declaration requires an explicit compatible range or pin')
            result.append(wanted[name] + '\n')
    if operation in ('remove', 'update') and found != set(wanted):
        raise Invalid('Dependency is absent from the selected declaration file')
    if operation == 'add':
        if result and not result[-1].endswith('\n'):
            result[-1] += '\n'
        result.extend(spec + '\n' for spec in wanted.values())
    return ''.join(result)


def start(args):
    from .onboarding import ask, data, private_directory, safe_text
    from .setup_transaction import recover as recover_setup
    repo = Path(args.repo).absolute()
    directory = private_directory(repo)
    fd = os.open(directory / 'onboarding.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        recover_setup(directory)
        recover(directory)
        record = load(directory / 'project.json')
        store = Store(record['state'])
        with store.locked() as db:
            row, old = store.project(db, record['project'])
            if row['stopped'] or row['setup_pending']:
                raise Invalid('Stopped or pending project cannot revise dependencies')
        verify_inputs(old)
        root = relative(args.root, empty=True)
        kind = 'python_dependencies' if args.ecosystem == 'pypi' else 'npm_dependencies'
        descriptor = old['policy']['project'].get(kind)
        if not descriptor:
            raise Invalid('Set up the selected ecosystem before editing dependencies')
        task = next((t for t in old['policy']['tasks'] if t['id'] == args.task), None)
        if task is None:
            raise Invalid('Unknown dependency task')
        stage = directory / ('dependencies-' + secrets.token_hex(8))
        stage.mkdir(mode=0o700)
        save(stage / 'previous-bundle.json', old)
        shadow = stage / 'metadata'
        shadow.mkdir()
        expected = {name: fingerprint(repo / name) for name in descriptor['inputs']}
        expected[''] = fingerprint(repo)
        expected['.ptw/policy.json'] = fingerprint(repo / '.ptw/policy.json')
        for name in descriptor['inputs']:
            path = shadow / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(data(repo / name, 8 * 1024 * 1024))
        rules = old['policy']['project']['packages']
        if args.ecosystem == 'pypi':
            from .dependency_resolution import resolve_python
            source = args.source or ('requirements.in' if (shadow / root / 'requirements.in').exists() else 'requirements.txt')
            relative(source)
            declaration = shadow / root / source
            if not declaration.is_file() or declaration.suffix not in ('.in', '.txt'):
                raise Invalid('This edit path needs a requirements.in/txt declaration; native project edits remain separate')
            declaration.write_text(edit_requirements(data(declaration), args.operation, args.specs))
            result = resolve_python(shadow / root, stage / 'resolution', rules, source=source,
                executable=old['policy']['project']['python_runtime']['executable'])
            lock = shadow / root / 'ptw-requirements.txt'
            lock.write_text('\n'.join(result['pins']) + ('\n' if result['pins'] else ''))
            selected = {'pypi:' + canonicalize_name(Requirement(p).name) for p in result['pins']}
            updated = {k: result[k] for k in ('inputs', 'pins', 'artifacts')}
            updated['inputs'] = {str(Path(root) / n): h for n, h in result['inputs'].items()}
            updated['inputs'][str(lock.relative_to(shadow))] = hashlib.sha256(lock.read_bytes()).hexdigest()
        else:
            from .npm_resolution import declarations, resolve_npm
            from .registry import provider_for
            source = str(Path(root) / 'package.json')
            declaration = shadow / source
            manifest = load(declaration)
            field = args.group or 'dependencies'
            if field not in ('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'):
                raise Invalid('Select a standard npm dependency group')
            entries = manifest.setdefault(field, {})
            for spec in args.specs:
                if args.operation == 'remove':
                    name = spec
                    if name not in entries:
                        raise Invalid('Dependency is absent from the selected group')
                    del entries[name]
                else:
                    name, sep, value = spec.rpartition('@')
                    if not sep or not name or not value:
                        raise Invalid('Use an explicit name@range or @scope/name@range')
                    declarations({field: {name: value}})
                    if (args.operation == 'add') == (name in entries):
                        raise Invalid('Use add for new dependencies and update for existing dependencies')
                    entries[name] = value
            declaration.write_text(json.dumps(manifest, indent=2) + '\n')
            result = resolve_npm(shadow / root, stage / 'resolution', rules, update=True,
                provider=provider_for(store, old))
            lock = shadow / root / 'package-lock.json'
            if result['lock'] is None:
                result['lock'] = {'lockfileVersion': 3, 'packages': {'': manifest}}
            lock.write_text(json.dumps(result['lock'], indent=2) + '\n')
            selected = {'npm:' + e['name'] for e in result['artifacts']}
            updated = {**descriptor, 'inputs': {str(Path(root) / n): h for n, h in result['inputs'].items()},
                'artifacts': result['artifacts'], 'lock_sha256': digest(result['lock'])}
            updated['inputs'][str(lock.relative_to(shadow))] = hashlib.sha256(lock.read_bytes()).hexdigest()
        # Resolver inputs were captured after the staged edit. They are the new
        # approval, while expected retains the original publication identities.
        updated['inputs'][str(declaration.relative_to(shadow))] = hashlib.sha256(declaration.read_bytes()).hexdigest()
        policy, inv = copy.deepcopy(old['policy']), copy.deepcopy(old['inventory'])
        policy['project'][kind] = updated
        prior_names = {n for n in rules['allowed_names'] if n.startswith(args.ecosystem + ':')}
        policy['project']['packages']['allowed_names'] = sorted((set(rules['allowed_names']) - prior_names) | selected)
        policy['project']['packages']['build_packages'] = [n for n in rules['build_packages'] if n not in prior_names - selected]
        for item in policy['tasks']:
            item['packages'] = sorted((set(item['packages']) - (prior_names - selected)) |
                (selected - prior_names if item['id'] == args.task else set()))
        changes = {name: data(shadow / name, 8 * 1024 * 1024) for name in updated['inputs']
                   if not (repo / name).exists() or data(repo / name, 8 * 1024 * 1024) != data(shadow / name, 8 * 1024 * 1024)}
        for name in changes:
            expected.setdefault(name, fingerprint(repo / name))
            if name not in {v['path'] for v in inv['resources'].values()}:
                key = 'dependency-' + hashlib.sha256(name.encode()).hexdigest()[:12]
                inv['resources'][key] = {'path': name, 'kind': 'file', 'description': 'Reviewed dependency metadata'}
                policy['project']['grants'].append({'resource': key, 'actions': ['read']})
                next(t for t in policy['tasks'] if t['id'] == args.task)['grants'].append({'resource': key, 'actions': ['read']})
        compiled = compile_policy(policy, inv)
        save(stage / 'proposal.json', {'policy': policy, 'inventory': inv, 'changes': changes})
        versions = updated.get('pins', [e['name'] + '@' + e['version'] for e in updated.get('artifacts', [])])
        print(safe_text('DEPENDENCY REVIEW\nAdd: ' + ', '.join(sorted(selected - prior_names)) +
            '\nRemove: ' + ', '.join(sorted(prior_names - selected)) + '\nFiles: ' + ', '.join(changes) +
            '\nResolved: ' + ', '.join(versions[:20]) + ('; use details for all versions' if len(versions) > 20 else '') +
            '\nPolicy hash: ' + digest(compiled) + '\nScope, thresholds, project/task identities and violation history are preserved.'), flush=True)
        answer = ask('Approve dependency revision? Type yes, details, reject or cancel', 'no').lower()
        if answer == 'details':
            print(safe_text(json.dumps({'changes': changes, 'dependencies': updated}, indent=2)), flush=True)
            answer = ask('Approve exactly this dependency revision?', 'no').lower()
        if answer != 'yes':
            raise Invalid('Dependency revision not approved; project unchanged')
        new = approve(policy, inv, digest(compiled), getpass.getuser())
        save(stage / 'approved.json', new)
        new_record = {**record, 'bundle': str(stage / 'approved.json'), 'policy_sha256': new['approval']['sha256']}
        publish(directory, stage, old, new, changes, expected, new_record)
        return {'project': record['project'], 'policy_sha256': new['approval']['sha256'],
                'changed': sorted(changes), 'history_preserved': True, 'sessions_revoked': True}
    finally:
        os.close(fd)
