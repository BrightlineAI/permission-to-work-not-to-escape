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
        committed = bundle['approval']['sha256'] == journal['new_sha256'] and not row['setup_pending']
    if committed:
        try:
            for operation in journal['operations']:
                if fingerprint(Path(operation['destination'])) != operation['new']:
                    raise Invalid('Committed dependency revision needs operator recovery')
            verify_inputs(bundle)
        except BaseException:
            store.stop(journal['project'], 'Committed dependency revision changed during recovery')
            raise
        with store.locked() as db:
            db.execute('UPDATE projects SET dependency_revision=NULL WHERE id=? AND dependency_revision=?',
                       (journal['project'], journal['new_sha256']))
        journal['phase'] = 'committed'
        atomic(journal_path, journal)
        return
    try:
        # A revised bundle may be active only for preparation. Revoke and stop
        # those workers before restoring its metadata or authority after a crash.
        with store.locked() as db:
            row, bundle = store.project(db, journal['project'])
            if row['dependency_revision'] == journal['new_sha256']:
                db.execute('UPDATE sessions SET closed=1 WHERE project=?', (journal['project'],))
        from .supervisor import Supervisor
        Supervisor(store).reconcile()
        if any(not w['stopped'] for w in store.status(journal['project'])['workloads']):
            raise Invalid('Dependency recovery awaits confirmed workload termination')
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
            db.execute('BEGIN IMMEDIATE')
            if (bundle['approval']['sha256'] == journal['new_sha256'] and row['setup_pending']
                    and row['dependency_revision'] == journal['new_sha256']):
                previous = load(directory / journal['previous_bundle'])
                check_approval(previous)
                if previous['approval']['sha256'] != journal['old_sha256']:
                    raise Invalid('Dependency recovery prior approval mismatch')
                replaced = {op['destination'] for op in journal['operations']}
                for name in previous['inventory']['resources']:
                    info = resource_info(previous['inventory'], name)
                    path = Path(previous['inventory']['root']) / previous['inventory']['resources'][name]['path']
                    if str(path) not in replaced:
                        binding = db.execute('SELECT device,inode FROM bindings WHERE project=? AND resource=?',
                            (journal['project'], name)).fetchone()
                        if binding is None or tuple(binding) != (info.st_dev if info else 0, info.st_ino if info else 0):
                            raise Invalid('Dependency recovery preserves a replaced unrelated resource')
                    db.execute('INSERT OR REPLACE INTO bindings VALUES(?,?,?,?)',
                        (journal['project'], name, info.st_dev if info else 0, info.st_ino if info else 0))
                db.execute("DELETE FROM bindings WHERE project=? AND resource<>'' AND resource NOT IN (" +
                    ','.join('?' for _ in previous['inventory']['resources']) + ')',
                    (journal['project'], *previous['inventory']['resources']))
                db.execute('UPDATE projects SET bundle=? WHERE id=?', (canonical(previous), journal['project']))
            elif bundle['approval']['sha256'] != journal['old_sha256']:
                raise Invalid('Concurrent policy revision cannot be overwritten')
            # A real stop and all counters survive rollback. Revoked sessions
            # remain revoked; recovery never restarts prior processes.
            if row['dependency_revision'] == journal['new_sha256']:
                db.execute('UPDATE projects SET setup_pending=0,dependency_revision=NULL WHERE id=?', (journal['project'],))
            db.commit()
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
        'new_sha256': new['approval']['sha256'], 'operations': [],
        'previous_bundle': str((stage / 'previous-bundle.json').relative_to(directory))}
    previous_path = stage / 'previous-bundle.json'
    if previous_path.exists():
        if load(previous_path) != old:
            raise Invalid('Dependency prior bundle changed before publication')
    else:
        save(previous_path, old)
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
            # Keep ordinary sessions closed until every reviewed local build
            # and its final source/artifact validation has succeeded.
            db.execute('UPDATE projects SET bundle=? WHERE id=?', (canonical(new), project))
            db.commit()
        from .python_local import prepare_setup, validate_prepared_setup
        receipts = prepare_setup(store, new, record['task'], stage)
        def validate_commit():
            verify_inputs(new)
            validate_prepared_setup(store, new, receipts)
        store.commit_setup(project, new['approval']['sha256'], validate_commit)
        with store.locked() as db:
            db.execute('UPDATE projects SET dependency_revision=NULL WHERE id=?', (project,))
        journal['phase'] = 'committed'
        atomic(path, journal)
    except BaseException:
        recover(directory)
        raise


def edit_requirements(text, operation, specs):
    from .dependency_resolution import checked_requirement, requirement_lines
    from .python_projects import local_requirement
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
        if local_requirement(stripped) is not None:
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
        local_sources = old['policy']['project'].get('python_dependencies', {}).get('sources', [])
        if local_sources:
            from .workspace import materialize, scan
            # Copy only the already approved source closure, never the repo.
            resources = sorted({r for s in local_sources for r in s['resources']})
            materialize(scan(old['inventory'], resources), shadow)
        rules = old['policy']['project']['packages']
        if args.ecosystem == 'pypi':
            from .dependency_resolution import resolve_python
            from .python_revision import edit_project, update_uv_lock
            from .registry import provider_for
            provider = provider_for(store, old, 'pypi')
            source = args.source or ('pyproject.toml' if descriptor.get('authority') in
                ('pyproject.toml', 'uv.lock', 'poetry.lock') else
                'requirements.in' if (shadow / root / 'requirements.in').exists() else
                'requirements.txt' if (shadow / root / 'requirements.txt').exists() else 'pyproject.toml')
            relative(source)
            declaration = shadow / root / source
            if str(declaration.relative_to(shadow)) not in descriptor['inputs']:
                raise Invalid('Select a previously reviewed Python declaration')
            python = old['policy']['project']['python_runtime']['executable']
            from .python_runtime import verify
            verify(old['policy']['project']['python_runtime'])
            groups = tuple(descriptor.get('groups', ('dev', 'test')))
            extras = tuple(descriptor.get('extras', ()))
            poetry = descriptor.get('authority') == 'poetry.lock' or (shadow / root / 'poetry.lock').exists()
            if poetry:
                from .poetry_revision import edit_project as edit_poetry
                from .poetry_resolution import update_poetry_lock
                if (source != 'pyproject.toml' or any(str(Path(root) / name) not in descriptor['inputs']
                        for name in ('pyproject.toml', 'poetry.lock'))):
                    raise Invalid('Poetry revisions must edit the reviewed authoritative manifest and lock')
                edit_poetry(shadow / root, args.operation, args.specs, group=args.group, python=python)
            elif source == 'pyproject.toml':
                edit_project(shadow / root, args.operation, args.specs, group=args.group, python=python)
            elif declaration.is_file() and declaration.suffix in ('.in', '.txt'):
                if args.group:
                    raise Invalid('Requirements edits select a file, not a dependency group')
                declaration.write_text(edit_requirements(data(declaration), args.operation, args.specs))
            else:
                raise Invalid('Select a requirements file or pyproject.toml declaration')
            if local_sources:
                from .python_projects import discover_projects, resolve_projects
                if any(s.get('dynamic_metadata') for s in local_sources):
                    raise Invalid('Dynamic source revisions require explicit setup discovery with --revise')
                projects = discover_projects(shadow / root, source=source, groups=groups)
                if projects is not None:
                    result = resolve_projects(shadow / root, stage / 'resolution', rules, source=source,
                        executable=python, groups=groups, provider=provider)
                    plans = {str(Path(root) / p['path']).removeprefix('./'): p for p in result['local_projects']}
                    plans = {('' if k == '.' else k): v for k, v in plans.items()}
                    if set(plans) != {s['path'] for s in local_sources}:
                        raise Invalid('Dependency edit changes local source scope; review setup explicitly')
                    local_sources = copy.deepcopy(local_sources)
                    for s in local_sources:
                        plan = plans[s['path']]
                        if any(s[k] != plan[k] for k in ('name', 'version', 'mode')):
                            raise Invalid('Dependency edit changes local source identity')
                        s['build_dependencies'] = plan['build_dependencies']
                else:
                    if len(local_sources) != 1 or local_sources[0]['path'] != root:
                        raise Invalid('Dependency edit must retain its reviewed local project')
                    result = resolve_python(shadow / root, stage / 'resolution', rules, source=source,
                        executable=python, groups=groups, extras=extras, provider=provider,
                        local_build=True, local_mode=local_sources[0]['mode'])
            elif poetry or (shadow / root / 'uv.lock').exists():
                resolver = update_poetry_lock if poetry else update_uv_lock
                result = resolver(shadow / root, stage / 'resolution', rules, executable=python,
                    groups=groups, extras=extras, provider=provider, upgrade=[canonicalize_name(Requirement(p).name) for p in args.specs]
                    if args.operation == 'update' else [])
                if poetry and (result['authority'] != 'poetry.lock' or
                        result['runtime'] != old['policy']['project']['python_runtime']):
                    raise Invalid('Poetry revision changed lock authority or reviewed Python runtime')
                for name, text in result['files'].items():
                    (shadow / root / name).write_text(text)
            else:
                result = resolve_python(shadow / root, stage / 'resolution', rules, source=source,
                    executable=python, groups=groups, extras=extras, provider=provider)
            lock = shadow / root / 'ptw-requirements.txt'
            lock.write_text('\n'.join(result['pins']) + ('\n' if result['pins'] else ''))
            selected = {'pypi:' + canonicalize_name(Requirement(p).name) for p in result['pins']}
            updated = {**descriptor, **{k: result[k] for k in ('inputs', 'pins', 'artifacts')}}
            updated['inputs'] = {str(Path(root) / n): h for n, h in result['inputs'].items()}
            updated['inputs'][str(lock.relative_to(shadow))] = hashlib.sha256(lock.read_bytes()).hexdigest()
            if result['runtime'] != old['policy']['project']['python_runtime']:
                raise Invalid('Dependency revision changed the reviewed Python runtime')
        else:
            from .npm_resolution import declarations, resolve_npm
            from .registry import provider_for
            source = str(Path(root) / relative(args.source or 'package.json'))
            if source not in descriptor['inputs'] or Path(source).name != 'package.json':
                raise Invalid('Select a previously reviewed root or workspace package.json')
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
            pnpm = str(Path(root) / 'pnpm-lock.yaml') in descriptor['inputs']
            yarn = str(Path(root) / 'yarn.lock') in descriptor['inputs']
            if pnpm:
                from .pnpm_resolution import resolve_pnpm as resolve_npm
            elif yarn:
                from .yarn_resolution import resolve_yarn as resolve_npm
            result = resolve_npm(shadow / root, stage / 'resolution', rules, update=True,
                provider=provider_for(store, old))
            if set(result.get('sources', [])) != {s['path'] for s in descriptor.get('sources', [])}:
                raise Invalid('Dependency edit changes local source scope; review that source scope explicitly')
            lock = shadow / root / ('pnpm-lock.yaml' if pnpm else 'yarn.lock' if yarn else 'package-lock.json')
            if pnpm or yarn:
                lock.write_text(result['files'][lock.name])
            else:
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
        if local_sources:
            from .python_local import describe_source
            source_inv = {**inv, 'root': str(shadow)}
            refreshed = []
            for s in local_sources:
                current = describe_source(source_inv, s['resources'], identity=s['id'], path=s['path'],
                    allow_build=s['allow_build'], editable_resources=s.get('editable_resources', ()),
                    dynamic_metadata=s.get('dynamic_metadata'), extras=s.get('extras', ()),
                    full_build=s.get('native_build_view') == 'full')
                if any(current[k] != s[k] for k in ('name', 'version', 'mode')):
                    raise Invalid('Dependency revision changed local source identity')
                refreshed.append({**s, **current})
            policy['project']['python_dependencies']['sources'] = refreshed
        prior_names = {args.ecosystem + ':' + e['name'] for e in descriptor['artifacts']}
        if args.ecosystem == 'pypi':
            prior_names |= {'pypi:' + e['name'] for s in descriptor.get('sources', [])
                            for e in s.get('build_dependencies', {}).get('artifacts', [])}
            selected |= {'pypi:' + e['name'] for s in local_sources
                         for e in s.get('build_dependencies', {}).get('artifacts', [])}
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
            '\nLocal preparation on approval: ' + (', '.join(s['id'] + ' (' + s['mode'] +
                ', offline backend execution, snapshot ' + s['snapshot_sha256'] + ')'
                for s in policy['project'].get('python_dependencies', {}).get('sources', [])) or 'none') +
            '\nPolicy hash: ' + digest(compiled) + '\nScope, thresholds, project/task identities and violation history are preserved.'), flush=True)
        answer = ask('Approve dependency revision? Type yes, details, reject or cancel', 'no').lower()
        if answer == 'details':
            print(safe_text(json.dumps({'changes': changes, 'dependencies': updated}, indent=2)), flush=True)
            answer = ask('Approve exactly this dependency revision?', 'no').lower()
        if answer != 'yes':
            raise Invalid('Dependency revision not approved; project unchanged')
        new = approve(policy, inv, digest(compiled), getpass.getuser())
        save(stage / 'approved.json', new)
        new_record = {**record, 'bundle': str(stage / 'approved.json'), 'policy_sha256': new['approval']['sha256'],
                      'resume_policy': record.get('resume_policy', record['policy_sha256'])}
        publish(directory, stage, old, new, changes, expected, new_record)
        return {'project': record['project'], 'policy_sha256': new['approval']['sha256'],
                'changed': sorted(changes), 'history_preserved': True, 'sessions_revoked': True}
    finally:
        os.close(fd)
