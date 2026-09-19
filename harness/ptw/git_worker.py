"""Trusted Git plumbing worker, executed only inside the supervised namespace.

No repository scripts, configuration, hooks, filters, external diff or network.
Input paths are literal, output contains only the explicitly selected resources.
"""
import difflib
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

LIMIT = 8 * 1024 * 1024
OUTPUT_LIMIT = 2 * 1024 * 1024
CONTEXT_LIMIT = 256 * 1024


def git(root, *args, data=None):
    env = {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'LC_ALL': 'C',
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
           'GIT_CONFIG_SYSTEM': '/dev/null', 'GIT_ATTR_NOSYSTEM': '1',
           'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_OPTIONAL_LOCKS': '0',
           'GIT_TERMINAL_PROMPT': '0', 'GIT_ALLOW_PROTOCOL': '',
           'GIT_AUTHOR_NAME': 'Protected checkpoint', 'GIT_AUTHOR_EMAIL': 'checkpoint@localhost',
           'GIT_COMMITTER_NAME': 'Protected checkpoint', 'GIT_COMMITTER_EMAIL': 'checkpoint@localhost'}
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        result = subprocess.run(['/usr/bin/git', '--no-pager', '--literal-pathspecs',
            '--git-dir=' + str(root / 'repository'), '--work-tree=' + str(root / 'tree'),
            '-c', 'core.hooksPath=/nonexistent', '-c', 'core.attributesFile=/dev/null',
            '-c', 'core.fsmonitor=false', '-c', 'gc.auto=0', '-c', 'maintenance.auto=false',
            '-c', 'commit.gpgSign=false', *args], input=data, stdout=out, stderr=err,
            env=env, cwd=root, timeout=20)
        if result.returncode:
            # Git diagnostics can name unrelated index/object paths. Never relay them.
            raise ValueError('Git rejected missing, corrupt or unsupported metadata')
        out.seek(0)
        value = out.read(LIMIT + 1)
        if len(value) > LIMIT:
            raise ValueError('Git result exceeds 8 MiB')
        return value


def oid(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def selected(path, resources):
    return any(path == r['path'] or (r.get('kind') == 'tree' and path.startswith(r['path'] + '/'))
               for r in resources)


def entries(root, args, resources, *, index=False):
    result = {}
    for row in git(root, *args).split(b'\0'):
        if not row:
            continue
        meta, path = row.split(b'\t', 1)
        path = path.decode('utf-8')
        if not selected(path, resources):
            continue
        if (len(path) > 1024 or '\\' in path or any(ord(c) < 32 for c in path) or
                any(p in ('', '.', '..', '.git') for p in path.split('/'))):
            raise ValueError('Unsafe historical Git path')
        fields = meta.decode('ascii').split()
        mode, identity, stage = (fields if index else (fields[0], fields[2], '0'))
        if mode not in ('100644', '100755') or stage != '0':
            raise ValueError('Selected Git entries must be regular files without merge conflicts')
        result[path] = (mode, identity)
    return result


def change(before, after):
    return ' ' if before == after else 'A' if before is None else 'D' if after is None else 'M'


def delta(root, path, before, after, current=None):
    def read(entry, working=False):
        if entry is None:
            return b''
        return current[path] if working else git(root, 'cat-file', 'blob', entry[1])
    old, new = read(before), read(after, current is not None)
    result = {'path': path, 'change': change(before, after),
              'old_mode': before[0] if before else None, 'new_mode': after[0] if after else None}
    try:
        if b'\0' in old or b'\0' in new:
            raise UnicodeError()
        result['patch'] = ''.join(difflib.unified_diff(old.decode().splitlines(True), new.decode().splitlines(True),
                                                    fromfile='a/' + path, tofile='b/' + path))
    except UnicodeError:
        result['binary'] = True
        result['old_sha256'] = hashlib.sha256(old).hexdigest()
        result['new_sha256'] = hashlib.sha256(new).hexdigest()
    return result


def context(root, tree, resources):
    """Only scoped blobs are opened. Opaque entries remain bound by tree ID."""
    files, gaps, used = {}, [], 0
    for path, (mode, identity) in entries(root,
            ['ls-tree', '-r', '-z', tree, '--', *[r['path'] for r in resources]], resources).items():
        value = git(root, 'cat-file', 'blob', identity)
        item = {'mode': mode, 'sha256': hashlib.sha256(value).hexdigest()}
        try:
            if b'\0' in value:
                raise UnicodeError()
            text = value.decode('utf-8')
            if used + len(value) > CONTEXT_LIMIT:
                gaps.append({'path': path, 'reason': 'oversized'})
            else:
                item['text'] = text
                used += len(value)
        except UnicodeError:
            gaps.append({'path': path, 'reason': 'binary'})
        files[path] = item
    return {'tree': tree, 'files': files, 'gaps': gaps}


def work(root):
    info = json.loads((root / 'request.json').read_text())
    resources, base = info['resources'], info['base']
    head = entries(root, ['ls-tree', '-r', '-z', base, '--', *[r['path'] for r in resources]], resources) if base else {}
    index = entries(root, ['ls-files', '--stage', '-z'], resources, index=True)
    current, files = {}, {}
    for path, mode in info['files'].items():
        value = (root / 'tree' / path).read_bytes()
        if len(value) > LIMIT:
            raise ValueError('Worktree file exceeds limit')
        current[path] = value
        files[path] = (mode, oid(value))
    paths = sorted(head.keys() | index.keys() | files.keys())
    result = {'base': base, 'status': [{'path': p, 'staged': change(head.get(p), index.get(p)),
        'working': change(index.get(p), files.get(p))} for p in paths
        if head.get(p) != index.get(p) or index.get(p) != files.get(p)]}
    if info['operation'] == 'diff':
        result['staged'] = [delta(root, p, head.get(p), index.get(p)) for p in paths if head.get(p) != index.get(p)]
        result['working'] = [delta(root, p, index.get(p), files.get(p), current) for p in paths if index.get(p) != files.get(p)]
    if info['operation'] == 'checkpoint':
        chosen = info['paths']
        if any(head.get(p) == files.get(p) for p in chosen):
            raise ValueError('Select changed file paths relative to HEAD; directories and unchanged files are not checkpoints')
        result['changes'] = [delta(root, p, head.get(p), files.get(p), current) for p in chosen]
        objects = root / 'repository/objects'
        before = {str(p.relative_to(objects)) for p in objects.glob('*/*') if p.is_file()}
        # Start from HEAD, never the real index. Preserve all unrelated tree entries.
        (root / 'repository/index').unlink(missing_ok=True)
        git(root, 'read-tree', *([base] if base else ['--empty']))
        rows = []
        for path in chosen:
            mode, identity = files.get(path, ('0', '0' * 40))
            if path in files:
                actual = git(root, 'hash-object', '-w', '--stdin', data=current[path]).decode().strip()
                if actual != identity:
                    raise ValueError('Blob identity mismatch')
            rows.append((mode + ' ' + identity + '\t' + path).encode() + b'\0')
        git(root, 'update-index', '-z', '--index-info', data=b''.join(rows))
        tree = git(root, 'write-tree').decode().strip()
        result['candidate'] = context(root, tree, resources)
        result['commit'] = git(root, 'commit-tree', tree, *(['-p', base] if base else []),
                               data=(info['message'] + '\n').encode()).decode().strip()
        result['objects'] = sorted(str(p.relative_to(objects)) for p in objects.glob('*/*')
                                   if p.is_file() and str(p.relative_to(objects)) not in before)
    if len(json.dumps(result).encode()) > OUTPUT_LIMIT:
        raise ValueError('Scoped Git output exceeds 2 MiB; use a narrower reviewed command')
    return result


def main(root):
    try:
        result = {'ok': True, **work(root)}
    except (ValueError, OSError, UnicodeError, subprocess.SubprocessError) as exc:
        result = {'ok': False, 'reason': str(exc) if isinstance(exc, ValueError) else type(exc).__name__}
    (root / 'result.json').write_text(json.dumps(result))


if __name__ == '__main__':
    main(Path('/target'))
