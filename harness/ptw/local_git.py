"""Scoped local Git inspection and exact operator-approved checkpoint refs.

The model can prepare a checkpoint but cannot approve or publish one. Only the
operator terminal calls publish_checkpoint. The real branch and index stay intact.
"""
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat

from .monitor import health
from .policy import Invalid, digest, load, save, scope, validate
from .setup_transaction import atomic
from .workspace import REQUEST_SCHEMA, MAX_FILE, MAX_TREE, MAX_ENTRIES, materialize, owner, scan, stamp
from .workspace_policy import directory_fd, relative

OID = re.compile(r'[0-9a-f]{40}')
IDENTITY = re.compile(r'[0-9a-f]{32}')
OBJECT_LIMIT = 256 * 1024 * 1024


@contextmanager
def child_dir(fd, path, *, create=False):
    current = os.dup(fd)
    try:
        for part in relative(path).split('/'):
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=current)
                except FileExistsError:
                    pass
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = nxt
        yield current
    finally:
        os.close(current)


def read_at(fd, path, limit=MAX_FILE, *, missing=False):
    parent, _, name = relative(path).rpartition('/')
    with child_dir(fd, parent) if parent else borrowed(fd) as location:
        try:
            opened = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=location)
        except FileNotFoundError:
            if missing:
                return None
            raise
        with os.fdopen(opened, 'rb') as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
                raise Invalid('Git metadata must be bounded regular files without links')
            data = handle.read(limit + 1)
            if len(data) > limit:
                raise Invalid('Git metadata exceeds limit')
            return data


@contextmanager
def borrowed(fd):
    yield fd


def exists_at(fd, path):
    try:
        os.stat(path, dir_fd=fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def binding(repo):
    fd = directory_fd(Path(repo) / '.git')
    try:
        info = os.fstat(fd)
        return {'device': info.st_dev, 'inode': info.st_ino}
    finally:
        os.close(fd)


def candidates(repo, resources, *, tests=()):
    try:
        identity = binding(repo)
    except OSError as exc:
        raise Invalid('--git requires an ordinary .git directory at the approved repository root') from exc
    return [{'id': 'git-' + action, 'argv': ['/usr/bin/git', action], 'resources': resources,
             'timeout_seconds': 120, 'git': {'operation': action, **identity,
                 **({'review': {'version': 1, 'assumptions':
                     'Review all scoped candidate text and declared tests; external behavior is not certified.',
                     'required_paths': [], 'tests': list(tests)}} if action == 'checkpoint' else {})}}
            for action in ('status', 'diff', 'checkpoint')]


@contextmanager
def repository(inv, definition):
    fd = directory_fd(Path(inv['root']) / '.git')
    try:
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) != (definition['git']['device'], definition['git']['inode']):
            raise Invalid('Approved Git directory identity changed')
        for name in ('commondir', 'gitdir', 'shallow', 'reftable'):
            if exists_at(fd, name):
                raise Invalid('Linked, shallow and reftable repositories require a different reviewed adapter')
        yield fd
    finally:
        os.close(fd)


def metadata(fd):
    raw = read_at(fd, 'HEAD', 1024)
    head = raw.decode('ascii').strip()
    ref = None
    packed = read_at(fd, 'packed-refs', missing=True)
    refs = {}
    if packed:
        for line in packed.decode('ascii').splitlines():
            if line.startswith(('#', '^')):
                continue
            identity, sep, name = line.partition(' ')
            if not sep or not OID.fullmatch(identity) or name in refs:
                raise Invalid('Unsupported packed refs')
            refs[name] = identity
    if head.startswith('ref: '):
        ref = head[5:]
        if (not re.fullmatch(r'refs/heads/[A-Za-z0-9_/-]+(?:\.[A-Za-z0-9_-]+)*', ref) or
                '..' in ref or ref.endswith(('.lock', '/'))):
            raise Invalid('Unsupported HEAD reference')
        relative(ref)
        try:
            loose = read_at(fd, ref, 1024, missing=True)
        except FileNotFoundError:
            loose = None
        base = loose.decode('ascii').strip() if loose is not None else refs.get(ref)
    else:
        base = head
    if base is not None and not OID.fullmatch(base):
        raise Invalid('Only ordinary SHA-1 Git repositories are supported')
    index = read_at(fd, 'index', missing=True)
    return {'base': base, 'head': head, 'ref': ref,
            'index_sha256': hashlib.sha256(index).hexdigest() if index is not None else None,
            'packed_sha256': hashlib.sha256(packed).hexdigest() if packed is not None else None}, index


def copy_objects(fd, target):
    size, count = 0, 0
    with child_dir(fd, 'objects') as objects:
        # Alternates would redirect Git outside the selected metadata view.
        if exists_at(objects, 'info'):
            with child_dir(objects, 'info') as info:
                if any(exists_at(info, n) for n in ('alternates', 'http-alternates')):
                    raise Invalid('Git object alternates are not supported')
        for name in sorted(os.listdir(objects)):
            if name == 'info':
                continue
            if name != 'pack' and not re.fullmatch(r'[0-9a-f]{2}', name):
                raise Invalid('Unsupported object store entry')
            with child_dir(objects, name) as sub:
                for leaf in sorted(os.listdir(sub)):
                    if not (re.fullmatch(r'pack-[0-9a-f]{40}\.(pack|idx|rev)', leaf) if name == 'pack'
                            else re.fullmatch(r'[0-9a-f]{38}', leaf)):
                        raise Invalid('Unsupported object pack, partial clone or object entry')
                    data = read_at(sub, leaf, OBJECT_LIMIT)
                    count += 1
                    size += len(data)
                    if count > 16384 or size > OBJECT_LIMIT:
                        raise Invalid('Git object snapshot exceeds 256 MiB or 16384 files')
                    path = target / name / leaf
                    path.parent.mkdir(exist_ok=True)
                    path.write_bytes(data)


def snapshot_hash(before):
    return digest({p: [stamp(e), e.get('mode')] for p, e in before.items()})


def prepare(inv, definition, before, options, folder):
    target = folder / 'target'
    target.mkdir()
    gitdir = target / 'repository'
    (gitdir / 'objects').mkdir(parents=True)
    (gitdir / 'refs/heads').mkdir(parents=True)
    (target / 'tree').mkdir()
    materialize(before, target / 'tree')
    with repository(inv, definition) as fd:
        meta, index = metadata(fd)
        copy_objects(fd, gitdir / 'objects')
        if metadata(fd)[0] != meta:
            raise Invalid('Git metadata changed while preparing its view')
    (gitdir / 'HEAD').write_text((meta['base'] or 'ref: refs/heads/unborn') + '\n')
    if index is not None:
        (gitdir / 'index').write_bytes(index)
    info = {'operation': definition['git']['operation'], 'base': meta['base'],
            'resources': [inv['resources'][r] for r in definition['resources']],
            'files': {p: '100755' if e['mode'] & 0o111 else '100644'
                      for p, e in before.items() if e['kind'] == 'file'}, **options}
    save(target / 'request.json', info)
    return target, meta


def execute(store, token, target):
    from .package_build import run_build
    from .supervisor import runtime_namespace
    nono = os.environ.get('PTW_NONO') or shutil.which('nono')
    if not nono:
        raise Invalid('nono is required; no unconfined Git fallback')
    command = runtime_namespace() + ['--bind', str(target), '/target',
        '--ro-bind', str(Path(nono).resolve()), '/nono',
        '--ro-bind', str(Path(__file__).with_name('git_worker.py')), '/git-worker.py', '--',
        '/nono', 'run', '--sandbox-policy', 'landlock', '--block-net', '--allow', '/target',
        '--allow', '/tmp', '--read-file', '/git-worker.py', '--no-rollback', '--no-audit', '--no-diagnostics',
        '--', '/usr/bin/python3', '-I', '-S', '/git-worker.py']
    run_build(store, token, command, target,
              storage_limit=load(target.parent / 'request.json')['export_storage_limit'])
    result = load(target / 'result.json')
    if not result.get('ok'):
        raise Invalid(result.get('reason', 'Confined Git failed'))
    return result


def options_for(req, inv, actor, definition):
    if any(req[k] for k in ('path', 'destination', 'expected')):
        raise Invalid('Git actions accept no path, destination or expected fields')
    if definition['git']['operation'] != 'checkpoint':
        if req['content']:
            raise Invalid('Git inspection accepts no content')
        return {}
    from .policy import parse_json
    try:
        options = parse_json(req['content'])
    except ValueError as exc:
        raise Invalid('Checkpoint content must contain paths and message') from exc
    if (not isinstance(options, dict) or set(options) != {'paths', 'message'} or
            not isinstance(options['paths'], list) or not 1 <= len(options['paths']) <= 128 or
            not isinstance(options['message'], str) or not 1 <= len(options['message']) <= 1000 or
            any(ord(c) < 32 for c in options['message'])):
        raise Invalid('Checkpoint requires 1 to 128 exact file paths and a single-line message')
    allowed = scope(json.loads(actor['grants']))
    for path in options['paths']:
        relative(path)
        resource = owner(inv, path)
        if (resource not in definition['resources'] or '.git' in path.split('/') or
                not {'read', 'write'} <= allowed.get(resource, set())):
            raise Invalid('Checkpoint path requires command scope and task read/write authority')
    if len(set(options['paths'])) != len(options['paths']):
        raise Invalid('Checkpoint paths must be unique')
    return options


def git_request(broker, token, event, req):
    store = broker.store
    with store.locked() as db:
        actor, project, bundle, prior = broker.inspect(db, token, event, req)
        if prior is not None:
            return prior
        try:
            validate(REQUEST_SCHEMA, req)
            definition = next((c for c in bundle['policy']['project']['commands']
                               if c['id'] == req['resource']), None)
            if (definition is None or 'git' not in definition or req['resource'] not in json.loads(actor['commands'])
                    or req['action'] != 'git_' + definition['git']['operation']):
                raise Invalid('Git command outside reviewed task/delegated scope')
            options = options_for(req, bundle['inventory'], actor, definition)
        except Invalid as exc:
            return broker.deny(db, actor, project, bundle, event, req, str(exc))
        if not health(store, db=db)['healthy']:
            return broker.record(db, actor, event, req, 'blocked', 'Controller monitoring unavailable')
        store.begin(db, actor['id'], event, digest(req), req)
        from .evidence_storage import admit, file_usage
        try:
            # Seed creation holds the controller lock. Include file overhead,
            # index/request metadata and the bounded working tree before copying.
            admit(db, actor['project'], OBJECT_LIMIT + MAX_TREE +
                  (16384 + MAX_ENTRIES) * 4096 + 16 * 1024 * 1024)
        except OSError:
            store.capture_fault(db, actor['project'])
            raise
        folder = store.directory / 'git-requests' / secrets.token_hex(16)
        folder.mkdir(parents=True, mode=0o700)
        save(folder / 'request.json', {'session': actor['id'], 'request': req})
        try:
            broker.integrity(db, actor['project'], bundle)
            before = scan(bundle['inventory'], definition['resources'])
            target, meta = prepare(bundle['inventory'], definition, before, options, folder)
            policy_hash = bundle['approval']['sha256']
            # Both the original seed and export survive; the archive also
            # occupies disk during extraction. Reserve all three before unlock.
            # The exporter enforces its byte/file-overhead bound before writing.
            used = file_usage(folder)
            export_limit = file_usage(target) + MAX_TREE + 16 * 1024 * 1024
            extra = 2 * export_limit + 16 * 1024 * 1024
            admit(db, actor['project'], extra)
            atomic(folder / 'request.json', {'session': actor['id'], 'request': req,
                'export_storage_limit': export_limit, 'reserved_bytes': used + extra})
        except (Invalid, OSError, ValueError) as exc:
            from .evidence_storage import QuotaError
            if isinstance(exc, QuotaError):
                store.capture_fault(db, actor['project'])
            save(folder / 'failure.json', {'error': str(exc)})
            return broker.record(db, actor, event, req, 'blocked', str(exc))
    try:
        result = execute(store, token, target)
    except Exception as exc:
        from .package_evidence import EvidenceError
        if not isinstance(exc, (Invalid, OSError, ValueError, EvidenceError)):
            raise
        save(folder / 'failure.json', {'error': str(exc)})
        with store.locked() as db:
            actor, project, bundle, prior = broker.inspect(db, token, event, req)
            return prior or broker.record(db, actor, event, req, 'blocked', str(exc))
    with store.locked() as db:
        actor, project, bundle, prior = broker.inspect(db, token, event, req)
        if prior is not None:
            return prior
        if bundle['approval']['sha256'] != policy_hash:
            return broker.record(db, actor, event, req, 'conflict', 'Policy changed during Git operation')
        if definition['git']['operation'] == 'checkpoint':
            from .artifact_review import packet, initial_result
            allowed = scope(json.loads(actor['grants']))
            for change in result['changes']:
                needed = {'A': 'create', 'D': 'delete', 'M': 'write'}[change['change']]
                if needed not in allowed.get(owner(bundle['inventory'], change['path']), set()):
                    return broker.deny(db, actor, project, bundle, event, req, 'Checkpoint change exceeds file action scope')
            inputs = packet(store, db, actor, bundle, definition, result, event)
            review = {'id': folder.name, 'project': actor['project'], 'session': actor['id'],
                      'policy_sha256': policy_hash, 'command': definition['id'], 'metadata': meta,
                      'snapshot_sha256': snapshot_hash(before), 'message': options['message'],
                      'changes': result['changes'], 'commit': result['commit'], 'objects': result['objects'],
                      'ref': 'refs/ptw/checkpoints/' + folder.name,
                      'finding_records': [],
                      'review_input': inputs, 'review_result': initial_result(inputs),
                      'object_sha256': {name: hashlib.sha256((target / 'repository/objects' / name).read_bytes()).hexdigest()
                                        for name in result['objects']}}
            # Account the actual packet too; unusually large history cannot
            # outrun the provisional allowance or silently evict old evidence.
            from .evidence_storage import charge
            try:
                admit(db, actor['project'], charge(review))
            except OSError:
                store.capture_fault(db, actor['project'])
                raise
            save(folder / 'review.json', review)
            save(folder / 'state.json', {'phase': 'review', 'sha256': digest(review)})
            db.execute('INSERT OR IGNORE INTO evidence_pins VALUES(?,?)',
                       (actor['project'], 'checkpoint:' + folder.name))
            release_storage(folder)
            return broker.record(db, actor, event, req, 'allow', 'Checkpoint prepared; no repository write',
                effect='git_review', review_sha256=digest(review), checkpoint=folder.name,
                next='Operator: run ptw checkpoint ' + folder.name + ' in a separate terminal in this repository')
        release_storage(folder)
        return broker.record(db, actor, event, req, 'allow', 'Scoped Git snapshot', effect=req['action'], **result)


def release_storage(folder):
    # Caller holds the controller lock after the exporter has finished. Failed
    # or interrupted exports retain their reservation for operator recovery.
    record = load(folder / 'request.json')
    record['reserved_bytes'] = 0
    atomic(folder / 'request.json', record)


@contextmanager
def git_locks(fd, meta, ref):
    with ExitStack() as stack:
        for path in ['HEAD', 'index', 'packed-refs', *([meta['ref']] if meta['ref'] else []), ref]:
            parent, _, name = path.rpartition('/')
            location = stack.enter_context(child_dir(fd, parent, create=True)) if parent else fd
            lock = name + '.lock'
            opened = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=location)
            os.close(opened)
            stack.callback(os.unlink, lock, dir_fd=location)
        yield


def write_new(fd, path, data):
    parent, _, name = relative(path).rpartition('/')
    with child_dir(fd, parent, create=True) as location:
        opened = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=location)
        with os.fdopen(opened, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.fsync(location)


def publish_checkpoint(store, identity, expected, *, disposition=None):
    """Trusted operator API. Not reachable through dispatch or MCP."""
    from .workspace import Workspace
    if not isinstance(identity, str) or not IDENTITY.fullmatch(identity):
        raise Invalid('Malformed checkpoint ID')
    folder = store.directory / 'git-requests' / identity
    with store.locked() as db:
        review, state = load(folder / 'review.json'), load(folder / 'state.json')
        if state['phase'] != 'review' or expected != digest(review) or state['sha256'] != expected:
            raise Invalid('Checkpoint approval is stale, consumed or mismatched')
        actor = db.execute('SELECT * FROM sessions WHERE id=?', (review['session'],)).fetchone()
        project, bundle = store.project(db, review['project'])
        if (actor is None or actor['closed'] or project['stopped'] or project['setup_pending'] or
                project['dependency_revision'] or bundle['approval']['sha256'] != review['policy_sha256'] or
                not health(store, db=db)['healthy']):
            raise Invalid('Checkpoint requires its active session, original approval and healthy unstopped project')
        definition = next(c for c in bundle['policy']['project']['commands'] if c['id'] == review['command'])
        broker = Workspace(store)
        broker.integrity(db, review['project'], bundle)
        if snapshot_hash(scan(bundle['inventory'], definition['resources'])) != review['snapshot_sha256']:
            raise Invalid('Working files changed since checkpoint review; request a fresh checkpoint')
        from .evidence_storage import admit, COMPLETION_BYTES
        try:
            admit(db, review['project'], COMPLETION_BYTES)
        except OSError:
            store.capture_fault(db, review['project'])
            raise
        from .artifact_review import eligible
        eligible(store, db, actor, bundle, definition, review, disposition)
        with repository(bundle['inventory'], definition) as fd:
            with git_locks(fd, review['metadata'], review['ref']):
                if metadata(fd)[0] != review['metadata']:
                    raise Invalid('Git HEAD or index changed since checkpoint review')
                if exists_at(fd, review['ref']):
                    raise Invalid('Checkpoint ref already exists')
                audit_event = 'checkpoint-publish-' + identity
                audit_request = {'action': 'checkpoint_publish', 'resource': definition['id'],
                                 'path': review['ref'], 'expected': expected, 'content': ''}
                store.begin(db, actor['id'], audit_event, digest(audit_request), audit_request,
                            authorization={'method': 'exact_operator_approval', 'receipt_sha256': expected})
                # Durable fail-closed intent. A killed operator cannot leave a
                # partly published checkpoint while existing agents keep working.
                held = store.stop_from_db(db, review['project'], 'Git checkpoint publication in progress; interrupted work requires review')
                if held['evidence'] != 'recorded':
                    raise Invalid('Required checkpoint hold evidence unavailable')
                atomic(folder / 'state.json', {'phase': 'publishing', 'sha256': expected})
                try:
                    for name in review['objects']:
                        if not re.fullmatch(r'[0-9a-f]{2}/[0-9a-f]{38}', name):
                            raise Invalid('Unexpected checkpoint object')
                        data = (folder / 'target/repository/objects' / name).read_bytes()
                        try:
                            write_new(fd, 'objects/' + name, data)
                        except FileExistsError:
                            if read_at(fd, 'objects/' + name, OBJECT_LIMIT) != data:
                                raise Invalid('Checkpoint object collision')
                    # Publish the sole ref atomically only after every object is durable.
                    parent, _, name = review['ref'].rpartition('/')
                    with child_dir(fd, parent) as refs:
                        lock = os.open(name + '.lock', os.O_WRONLY | os.O_NOFOLLOW, dir_fd=refs)
                        with os.fdopen(lock, 'wb') as handle:
                            handle.write((review['commit'] + '\n').encode())
                            handle.flush()
                            os.fsync(handle.fileno())
                        # Link the complete lock bytes without overwriting any concurrent ref.
                        os.link(name + '.lock', name, src_dir_fd=refs, dst_dir_fd=refs, follow_symlinks=False)
                        os.fsync(refs)
                    atomic(folder / 'state.json', {'phase': 'published', 'sha256': expected})
                    store.complete(db, actor['id'], audit_event, {
                        'allowed': True, 'level': 'allow', 'effect': 'checkpoint_publish',
                        'checkpoint': identity, 'commit': review['commit'], 'ref': review['ref'],
                        'review_sha256': expected, 'published': True,
                        'review_result_sha256': digest(review['review_result']),
                        'operator_disposition': disposition})
                    db.execute('BEGIN IMMEDIATE')
                    store.lifecycle(db, review['project'], 'checkpoint_hold_released',
                                    facts={'publication': digest([actor['id'], audit_event])})
                    db.execute('DELETE FROM evidence_pins WHERE project=? AND reference=?',
                               (review['project'], 'checkpoint:' + identity))
                    db.execute('UPDATE projects SET stopped=0,reason=NULL WHERE id=?', (review['project'],))
                    db.commit()
                except BaseException:
                    store.stop_from_db(db, review['project'], 'Uncertain Git checkpoint publication; inspect private receipt')
                    raise
        return {'checkpoint': identity, 'commit': review['commit'], 'ref': review['ref'], 'published': True}


def review_checkpoint(args):
    from .onboarding import ask, private_directory, safe_text
    from .store import Store
    import sys
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise Invalid('Checkpoint approval requires a real operator terminal')
    if not IDENTITY.fullmatch(args.identity):
        raise Invalid('Malformed checkpoint ID')
    repo = Path(args.repo).resolve(strict=True)
    record = load(private_directory(repo) / 'project.json')
    if record['repo'] != str(repo):
        raise Invalid('Project identity mismatch')
    store = Store(record['state'])
    folder = store.directory / 'git-requests' / args.identity
    review = load(folder / 'review.json')
    if review['project'] != record['project']:
        raise Invalid('Foreign checkpoint review')
    from .artifact_review import record_findings, validate_result
    if getattr(args, 'finding', None):
        record_findings(store, args.identity, digest(review),
                        [{'id': 'operator-' + digest([digest(review), i, text])[:40], 'text': text}
                         for i, text in enumerate(args.finding)])
        review = load(folder / 'review.json')
    inputs, result = validate_result(review)
    shown = {k: review[k] for k in ('ref', 'commit', 'changes', 'review_input', 'review_result')}
    shown['untrusted_rationale'] = {'source': 'worker checkpoint message', 'text': review['message']}
    shown['parent'] = review['metadata']['base']
    print(safe_text('LOCAL CHECKPOINT REVIEW\nController authority and observed evidence are separate from untrusted source text and rationale.\n' + json.dumps(shown, indent=2) +
        '\nCreates the displayed ref in this repository. Branch, staging and working files stay unchanged.'), flush=True)
    expected = digest(review)
    if inputs['coverage']['state'] != 'complete' or result['state'] == 'incomplete':
        raise Invalid('Checkpoint review incomplete; mandatory evidence cannot be waived')
    disposition = None
    if result['findings']:
        answer = ask('Unresolved suspicion. Type resolve ' + expected + ': REASON, or reject', 'reject')
        prefix = 'resolve ' + expected + ': '
        if answer.startswith(prefix) and answer[len(prefix):].strip():
            disposition = answer[len(prefix):]
        else:
            # Reuse the ordinary rejection path below, without offering approval.
            disposition = False
    if disposition is False or ask('Type approve ' + expected + ' to create this exact checkpoint', 'reject') != 'approve ' + expected:
        with store.locked() as db:
            state = load(folder / 'state.json')
            if state['phase'] == 'review':
                atomic(folder / 'state.json', {**state, 'phase': 'rejected'})
                captured = store.lifecycle(db, record['project'], 'checkpoint_rejected',
                                session=review['session'], facts={'checkpoint': args.identity,
                                'review_sha256': expected}, reduction=True,
                                response={'allowed': False, 'level': 'blocked', 'effect': 'checkpoint_rejected'})
                if captured:
                    db.execute('DELETE FROM evidence_pins WHERE project=? AND reference=?',
                               (record['project'], 'checkpoint:' + args.identity))
            else:
                captured = False  # No new review decision or durable capture is claimed.
        return {'published': False, 'rejected': True, 'evidence': 'recorded' if captured else 'unavailable'}
    try:
        return publish_checkpoint(store, args.identity, expected, disposition=disposition)
    finally:
        from .supervisor import Supervisor
        Supervisor(store).reconcile()
