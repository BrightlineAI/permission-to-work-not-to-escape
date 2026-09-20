"""Acquire the exact image sudo sources before implementing a native plugin.

This is source provenance, not authentication or confinement evidence. Downloads
are fixed, bounded, hash checked and never executed. Raw archives and selected
source files stay in a fresh private receipt directory, outside the checkout.
"""
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import tarfile
import time
import urllib.error
import urllib.request

from evidence_io import digest, reference, require, save
from linuxarena_preflight import (Commands, child_environment, daemon_environment,
                                 private_output, verify_daemon)

VERSION = '1.9.9-1ubuntu2.5'
# The rolling archive removed this superseded Ubuntu patch archive (HTTP 404).
# Use the fixed snapshot immediately after its 2025-06-30 publication:
# https://lists.ubuntu.com/archives/jammy-changes/2025-June/039524.html
# https://snapshot.ubuntu.com/ documents the timestamped archive interface.
SOURCE_URL = 'https://snapshot.ubuntu.com/ubuntu/20250701T000000Z/pool/main/s/sudo/'
# Canonical's source publication, not hashes computed from an unverified download:
# https://launchpad.net/ubuntu/+source/sudo/1.9.9-1ubuntu2.5
ARCHIVES = {
    'sudo_1.9.9.orig.tar.gz': '6d6ee863a3bc26c87661093a74ec63e10fd031ceba714642d21636dfe25e3e00',
    'sudo_1.9.9-1ubuntu2.5.debian.tar.xz': '5b865102a569d6bd6bb75c38a00298e5ad8897ced9ec11f71c1715b19790149d',
}
EXECUTION_FILES = (
    'include/sudo_plugin.h', 'include/sudo_fatal.h', 'lib/util/fatal.c',
    'src/exec.c', 'src/exec_nopty.c', 'src/exec_pty.c',
    'src/exec_monitor.c', 'src/sudo.c', 'src/preserve_fds.c',
    'plugins/sudoers/policy.c', 'plugins/sudoers/sudoers.c', 'plugins/sudoers/auth/pam.c',
)
MAX_ARCHIVE = 8 * 1024 * 1024
MAX_MEMBER = 2 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Source archive redirect refused')


def download(name, destination):
    """One attempt, no ambient proxy/auth configuration and no retry."""
    require(name in ARCHIVES, 'Unapproved sudo source archive')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(SOURCE_URL + name, headers={'Accept-Encoding': 'identity'})
    deadline = time.monotonic() + 60
    with destination.open('xb') as output:
        with opener.open(request, timeout=20) as response:
            require(response.status == 200 and response.geturl() == SOURCE_URL + name,
                    'Unexpected sudo source response')
            size = 0
            while True:
                require(time.monotonic() < deadline, 'Sudo source download deadline exceeded')
                chunk = response.read(65536)
                if not chunk:
                    break
                size += len(chunk)
                require(size <= MAX_ARCHIVE, 'Sudo source archive exceeds bound')
                output.write(chunk)
    require(digest(destination) == ARCHIVES[name], 'Sudo source archive hash mismatch')


def source_members(data, expected_sha256, *, debian):
    """Inspect verified archives without tar extraction, links or package hooks."""
    require(len(data) <= MAX_ARCHIVE and hashlib.sha256(data).hexdigest() == expected_sha256,
            'Sudo source archive hash mismatch or size exceeded')
    selected, names, expanded = {}, set(), 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as archive:
        for member in archive:
            name = member.name.rstrip('/')
            path = PurePosixPath(name)
            require(name and not path.is_absolute() and '..' not in path.parts and
                    str(path) == name and name not in names, 'Unsafe or duplicate source member')
            names.add(name)
            expanded += max(0, member.size)
            require(len(names) <= 10000 and expanded <= 64 * 1024 * 1024,
                    'Sudo source expansion exceeds bound')
            wanted = (name in ('debian/patches/series', 'debian/rules', 'debian/changelog') or
                      name.startswith('debian/patches/')) if debian else (
                          name in {'sudo-1.9.9/' + p for p in EXECUTION_FILES})
            if not wanted or member.isdir():
                continue
            require(member.isfile() and 0 <= member.size <= MAX_MEMBER,
                    'Selected sudo source must be a bounded regular file')
            stream = archive.extractfile(member)
            require(stream is not None, 'Missing sudo source member')
            with stream:
                content = stream.read(MAX_MEMBER + 1)
            require(len(content) == member.size, 'Incomplete sudo source member')
            selected[name] = content
    required = ({'debian/patches/series', 'debian/rules', 'debian/changelog'} if debian else
                {'sudo-1.9.9/' + p for p in EXECUTION_FILES})
    require(required <= selected.keys(), 'Missing required sudo execution source')
    if debian:
        require(selected['debian/changelog'].startswith(('sudo (' + VERSION + ')').encode()),
                'Distribution source version mismatch')
        for line in selected['debian/patches/series'].decode('utf-8').splitlines():
            entry = line.split('#', 1)[0].strip()
            if not entry:
                continue
            # The pinned series must name plain patches, not executable options.
            require(len(entry.split()) == 1 and 'debian/patches/' + entry in selected,
                    'Missing or unsupported distribution patch')
    return selected


IMAGE_IDENTITY = '''import hashlib, json, subprocess
version = subprocess.check_output(['/usr/bin/dpkg-query', '-W', '-f=${Version}', 'sudo'], text=True)
paths = ('/usr/bin/sudo', '/usr/libexec/sudo/sudoers.so')
print(json.dumps({'version': version, 'files_sha256': {
    p: hashlib.sha256(open(p, 'rb').read()).hexdigest() for p in paths}}))
'''


def run(runtime, output):
    """Fresh immutable-image metadata fixture; no sudo, task or grader executes."""
    runtime = Path(runtime)
    require(runtime.is_absolute() and runtime.resolve() == runtime and runtime.is_dir(),
            'Expected existing canonical retained runtime')
    out = private_output(output)
    attempt = {'schema': 1, 'status': 'incomplete', 'paid_calls': 0,
               'scope': 'sudo package/source provenance only; no launch-boundary proof',
               'driver_sha256': digest(__file__), 'started_epoch': time.time(),
               'downloads': {}}
    save(out / 'attempt.json', attempt)
    cid, command = None, None
    try:
        env, receipt = daemon_environment(runtime, child_environment(runtime, out))
        command = Commands(out, env)
        daemon = verify_daemon(command, receipt)
        save(out / 'daemon.json', daemon)
        memory = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
        require(int(memory['MemAvailable'].split()[0]) >= 256 * 1024 and
                shutil.disk_usage(out).free >= 128 * 1024 ** 2,
                'Insufficient free resources for sudo source prerequisite')
        cid = command(['docker', 'create', '--pull=never', '--network=none', '--read-only',
                       '--cpus=0.25', '--memory=64m', '--pids-limit=16', '--cap-drop=ALL',
                       '--security-opt=no-new-privileges',
                       '--cgroup-parent=' + PurePosixPath(daemon['cgroup']).name,
                       '--label', 'ptw.sudo-source=' + secrets.token_hex(12),
                       '--entrypoint', '/usr/bin/python3', daemon['image_id'],
                       '-I', '-S', '-c', IMAGE_IDENTITY]).decode().strip()
        require(re.fullmatch('[0-9a-f]{64}', cid), 'Missing immutable source fixture ID')
        save(out / 'container.json', {'id': cid, 'image_id': daemon['image_id']})
        identity = json.loads(command(['docker', 'start', '--attach', cid]))
        save(out / 'installed.json', identity)
        require(identity.get('version') == VERSION, 'Unsupported installed sudo version')
        require(set(identity.get('files_sha256', {})) ==
                {'/usr/bin/sudo', '/usr/libexec/sudo/sudoers.so'} and
                all(re.fullmatch('[0-9a-f]{64}', h) for h in identity['files_sha256'].values()),
                'Missing installed sudo binary identity')
        sources = {}
        for name, expected in ARCHIVES.items():
            path = out / name
            record = {'url': SOURCE_URL + name, 'expected_sha256': expected,
                      'status': 'incomplete'}
            attempt['downloads'][name] = record
            save(out / 'attempt.json', attempt)
            try:
                download(name, path)
            except BaseException as exc:
                record.update(status='failed', error_type=type(exc).__name__)
                if isinstance(exc, urllib.error.HTTPError):
                    record['http_status'] = exc.code
                raise
            record['status'] = 'verified'
            members = source_members(path.read_bytes(), expected, debian='.debian.' in name)
            for relative, content in members.items():
                target = out / 'source' / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open('xb') as stream:
                    stream.write(content)
                sources[relative] = reference(out, target)
        save(out / 'source.json', {'package': VERSION, 'publication':
             'https://launchpad.net/ubuntu/+source/sudo/' + VERSION,
             'archive_urls': {name: SOURCE_URL + name for name in ARCHIVES},
             'archives': {name: reference(out, out / name) for name in ARCHIVES},
             'members': sources, 'patches_applied': False,
             'limitation': 'Exact sources retained for review; callback compatibility not yet proved'})
        attempt['status'] = 'complete'
        return attempt
    except BaseException as exc:
        attempt.update(status='failed', error_type=type(exc).__name__)
        raise
    finally:
        try:
            if command and cid and re.fullmatch('[0-9a-f]{64}', cid):
                command(['docker', 'rm', '--force', cid])
        except BaseException as exc:
            attempt.update(status='failed', cleanup_error_type=type(exc).__name__)
            raise
        finally:
            attempt['ended_epoch'] = time.time()
            attempt['records'] = {p.name: reference(out, p) for p in out.iterdir()
                                  if p.is_file() and p.name != 'attempt.json'}
            save(out / 'attempt.json', attempt)
