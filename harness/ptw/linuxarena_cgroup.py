"""File-indexing execution subtree primitive, not a complete execution adapter.

Only a trusted, stopped launcher in a newly owned container may be admitted.
The caller must serialize admission with revocation in the controller. This
module deliberately cannot discover/adopt workloads by name or launch commands.
"""
import os
from pathlib import Path, PurePosixPath
import re
import signal
import time

from .policy import Invalid

CGROUP_ROOT = Path('/sys/fs/cgroup')


def boot_identity():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def container_group(value, container_id):
    """Accept only an exact Docker systemd scope, never an ancestor slice."""
    if not isinstance(container_id, str) or not re.fullmatch('[0-9a-f]{64}', container_id):
        raise Invalid('Expected immutable container ID')
    if (not isinstance(value, str) or not value.startswith('/') or value.startswith('//') or
            str(PurePosixPath(value)) != value or '..' in PurePosixPath(value).parts or
            PurePosixPath(value).name != 'docker-' + container_id + '.scope'):
        raise Invalid('Expected exact container cgroup, not an ancestor or alias')
    return CGROUP_ROOT / value[1:]


def process_identity(pid):
    if type(pid) is not int or pid <= 1:
        raise Invalid('Expected a live container process')
    proc = Path('/proc') / str(pid)
    # comm may contain spaces and closing parentheses; fields after its LAST
    # parenthesis begin at state (field 3), starttime is field 22.
    fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
    groups = (proc / 'cgroup').read_text().splitlines()
    if len(groups) != 1 or not groups[0].startswith('0::/'):
        raise Invalid('Unified cgroup v2 is required')
    return {'pid': pid, 'starttime': int(fields[19]), 'state': fields[0],
            'cgroup': groups[0][3:],
            'pid_namespace': os.readlink(proc / 'ns/pid'),
            'user_namespace': os.readlink(proc / 'ns/user')}


class ExecutionSubtree:
    """Pinned descriptors prevent a replaced path becoming a new stop target.

    No permission changes, controller enabling, parent moves, or PID-name kills.
    Leaving a failed subtree behind is preferable to touching an unknown target.
    The native prerequisite must prove delegation before using this primitive.
    """
    def __init__(self, group, container_id, nonce):
        if not isinstance(nonce, str) or not re.fullmatch('[0-9a-f]{24}', nonce):
            raise Invalid('Invalid execution subtree identity')
        self.parent = container_group(group, container_id)
        self.name = 'ptw-' + nonce
        self.path = self.parent / self.name
        self.group = group + '/' + self.name
        self.closed = False
        self.revoked = False
        self.fd = None
        self.parent_fd = None
        if self.parent.resolve(strict=True) != self.parent:
            raise Invalid('Linked container cgroup')
        try:
            self.parent_fd = os.open(self.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            os.mkdir(self.name, dir_fd=self.parent_fd)
            self.fd = os.open(self.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=self.parent_fd)
            info = os.fstat(self.fd)
            self.identity = {'container_id': container_id, 'cgroup': self.group,
                             'device': info.st_dev, 'inode': info.st_ino,
                             'boot_id': boot_identity()}
            if self._read('cgroup.type').strip() != 'domain':
                raise Invalid('Execution subtree is not a domain cgroup')
            if self.populated():
                raise Invalid('New execution subtree is populated')
            # Opening proves access, without issuing a kill or changing limits.
            fd = os.open('cgroup.kill', os.O_WRONLY | os.O_NOFOLLOW, dir_fd=self.fd)
            os.close(fd)
        except BaseException:
            self.close()
            raise

    @classmethod
    def reopen(cls, identity):
        """Reopen only a recorded kernel object, never create/adopt a replacement.

        The controller owns this record. A missing group remains uncertain; an
        absent path alone is not evidence that every process stopped.
        """
        if (not isinstance(identity, dict) or set(identity) !=
                {'container_id', 'cgroup', 'device', 'inode', 'boot_id'} or
                identity['boot_id'] != boot_identity() or
                any(type(identity[k]) is not int or identity[k] < 0 for k in ('device', 'inode'))):
            raise Invalid('Invalid or stale execution subtree identity')
        value = identity['cgroup']
        if not isinstance(value, str) or not re.fullmatch(r'.*/ptw-[0-9a-f]{24}', value):
            raise Invalid('Invalid execution subtree path')
        group, name = value.rsplit('/', 1)
        obj = cls.__new__(cls)
        obj.parent = container_group(group, identity['container_id'])
        obj.name, obj.path, obj.group = name, obj.parent / name, value
        obj.closed, obj.revoked = False, False
        obj.fd = obj.parent_fd = None
        obj.identity = dict(identity)
        if obj.path.resolve(strict=True) != obj.path:
            raise Invalid('Linked execution subtree')
        try:
            obj.parent_fd = os.open(obj.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            obj.fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=obj.parent_fd)
            info = os.fstat(obj.fd)
            if (info.st_dev, info.st_ino) != (identity['device'], identity['inode']):
                raise Invalid('Execution subtree was replaced')
            if obj._read('cgroup.type').strip() != 'domain':
                raise Invalid('Execution subtree is not a domain cgroup')
            return obj
        except BaseException:
            obj.close(remove=False)
            raise

    def _read(self, name):
        if self.closed:
            raise Invalid('Closed execution subtree')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.fd)
        with os.fdopen(fd) as stream:
            return stream.read(4096)

    def _write(self, name, value):
        if self.closed:
            raise Invalid('Closed execution subtree')
        fd = os.open(name, os.O_WRONLY | os.O_NOFOLLOW, dir_fd=self.fd)
        try:
            data = value.encode('ascii')
            if os.write(fd, data) != len(data):
                raise OSError('Short cgroup write')
        finally:
            os.close(fd)

    def populated(self):
        fields = dict(line.split() for line in self._read('cgroup.events').splitlines())
        if fields.get('populated') not in ('0', '1'):
            raise Invalid('Missing cgroup population evidence')
        return fields['populated'] == '1'

    def admit_stopped(self, expected):
        """Move a pinned stopped trusted launcher; never migrate running code."""
        if self.revoked or self.closed:
            raise Invalid('Execution subtree revoked or closed')
        pid = expected['pid']
        fd = os.pidfd_open(pid)
        try:
            actual = process_identity(pid)
            if actual != expected or actual['state'] != 'T':
                raise Invalid('Launcher changed or was not stopped before admission')
            if container_group(actual['cgroup'], self.identity['container_id']) != self.parent:
                raise Invalid('Launcher is outside the owned container')
            self._write('cgroup.procs', str(pid))
            moved = process_identity(pid)
            if moved != dict(actual, cgroup=self.group):
                raise Invalid('Launcher membership changed during admission')
            # pidfd addresses the original process even if the PID gets reused.
            signal.pidfd_send_signal(fd, signal.SIGCONT)
            return moved
        finally:
            os.close(fd)

    def terminate(self, timeout=3):
        if type(timeout) not in (int, float) or not 0 < timeout <= 10:
            raise Invalid('Invalid termination observation deadline')
        self.revoked = True
        self._write('cgroup.kill', '1')
        deadline = time.monotonic() + timeout
        while self.populated():
            if time.monotonic() >= deadline:
                return {**self.identity, 'confirmed_stopped': False}
            time.sleep(.02)
        return {**self.identity, 'confirmed_stopped': True}

    def close(self, *, remove=True):
        """Release descriptors; removal is allowed only for our empty leaf."""
        if self.closed:
            return
        try:
            if remove and self.fd is not None and not self.populated():
                info = os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False)
                pinned = os.fstat(self.fd)
                if (info.st_dev, info.st_ino) == (pinned.st_dev, pinned.st_ino):
                    os.rmdir(self.name, dir_fd=self.parent_fd)
        finally:
            for fd in (self.fd, self.parent_fd):
                if fd is not None:
                    os.close(fd)
            self.closed = True
