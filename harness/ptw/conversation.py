"""Operator-owned conversation bindings; rollout contents confer no authority."""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import uuid

from .policy import Invalid, load
from .setup_transaction import atomic


def native_id(value):
    if not isinstance(value, str) or not re.fullmatch(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', value):
        raise Invalid('Resume requires a recorded protected conversation UUID')
    return str(uuid.UUID(value))


def binding(record, task):
    repo = Path(record['repo'])
    info = repo.stat()
    return {'repo': str(repo), 'device': info.st_dev, 'inode': info.st_ino,
            'project': record['project'], 'task': task,
            'approval': record.get('resume_policy', record['policy_sha256'])}


def discover(folder):
    """Read only the bounded metadata header of this launch's private rollouts."""
    found = []
    root = folder / 'native-sessions'
    for path in root.glob('*/*/*/*.jsonl'):
        if path.is_symlink() or path.resolve().parent != path.parent or not path.is_file():
            raise Invalid('Invalid protected rollout path')
        with path.open('rb') as stream:
            header = stream.readline(65537)
        if len(header) > 65536:
            raise Invalid('Oversized protected rollout header')
        try:
            row = json.loads(header)
            payload = row['payload']
            if row['type'] != 'session_meta' or payload['cwd'] != str(folder / 'work'):
                raise Invalid('Protected rollout workspace changed')
            found.append(native_id(payload['id']))
        except (ValueError, KeyError, TypeError) as exc:
            raise Invalid('Invalid protected rollout metadata') from exc
    if len(found) != 1:
        raise Invalid('Expected exactly one protected conversation; start a new protected session')
    return found[0]


@contextmanager
def attach(directory, record, task, resume=None):
    """Hold a lease through credential revocation, including failed launches."""
    root = directory / 'conversations'
    root.mkdir(mode=0o700, exist_ok=True)
    expected = binding(record, task)
    if resume is None:
        folder = root / str(uuid.uuid4())
        folder.mkdir(mode=0o700)
        atomic(folder / 'binding.json', expected)
    else:
        if resume:
            native_id(resume)
        matches = []
        for candidate in root.iterdir():
            if candidate.is_symlink() or not candidate.is_dir():
                raise Invalid('Invalid protected conversation directory')
            metadata = load(candidate / 'binding.json')
            if (metadata == expected and (candidate / 'conversation.json').is_file()
                    and (not resume or load(candidate / 'conversation.json').get('id') == resume)):
                matches.append(candidate)
        if len(matches) != 1:
            raise Invalid('No unique protected conversation for this project, task and approval; supply its ID')
        folder = matches[0]
    fd = os.open(folder / 'attach.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Invalid('This protected conversation is already attached') from exc
        identity = None
        if resume is not None:
            identity = native_id(load(folder / 'conversation.json')['id'])
            if discover(folder) != identity:
                raise Invalid('Protected conversation metadata mismatch')
        yield folder, identity
    finally:
        os.close(fd)


def remember(folder, previous=None):
    identity = discover(folder)
    if previous is not None and identity != previous:
        raise Invalid('Native resume unexpectedly changed conversation')
    atomic(folder / 'conversation.json', {'id': identity})
    return identity
