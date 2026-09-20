"""Four exact Ubuntu development inputs, acquired only for the closed fixture.

Verify archive signatures before package hashes; never install packages or run
maintainer scripts. Only regular headers and reviewed runtime linker references
reach the build. All acquisition evidence stays in the fresh private run.
"""
import gzip
import hashlib
import io
from pathlib import Path, PurePosixPath
import posixpath
import re
import subprocess
import sys
import tarfile
import time
import urllib.request

from evidence_io import digest, reference, require, save
from linuxarena_sudo_source import NoRedirect
from linuxarena_sudo_inputs import REQUIRED

BASE = 'https://snapshot.ubuntu.com/ubuntu/20250701T000000Z/'
SIGNER = 'F6ECB3762474EDA9D21B7022871920D1991BC93C'
SUITES = ('jammy', 'jammy-updates')
INDEX = 'main/binary-amd64/Packages.gz'
MAX_DOWNLOAD = 8 * 1024 ** 2
MAX_EXPANDED = 64 * 1024 ** 2


class ArchiveMemberError(ValueError):
    """Bounded rejection metadata; never retain member contents in diagnostics."""
    def __init__(self, item, reason):
        super().__init__(reason)
        self.member = {'name': item.name[:512],
                       'name_sha256': hashlib.sha256(item.name.encode(
                           'utf-8', errors='surrogatepass')).hexdigest(),
                       'type': item.type.hex()[:16], 'mode': oct(item.mode)[:32],
                       'reason': reason}


def require_member(condition, item, reason):
    if not condition:
        raise ArchiveMemberError(item, reason)


def fetch(relative, destination, *, size=None, sha256=None):
    require(re.fullmatch(r'[A-Za-z0-9_./+%-]+', relative) and
            '..' not in PurePosixPath(relative).parts and not relative.startswith('/'),
            'Unsafe archive URL')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    limit = MAX_DOWNLOAD if size is None else size
    require(type(limit) is int and 0 < limit <= MAX_DOWNLOAD, 'Invalid download size')
    deadline = time.monotonic() + 60
    with destination.open('xb') as output:
        with opener.open(urllib.request.Request(BASE + relative,
                headers={'Accept-Encoding': 'identity'}), timeout=20) as response:
            require(response.status == 200 and response.geturl() == BASE + relative,
                    'Unexpected archive response')
            total = 0
            while True:
                require(time.monotonic() < deadline, 'Archive download deadline exceeded')
                chunk = response.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                require(total <= limit, 'Archive download exceeds bound')
                output.write(chunk)
    require(size is None or total == size, 'Truncated archive download')
    require(sha256 is None or digest(destination) == sha256, 'Archive download hash mismatch')


def paragraphs(text):
    """Strict Debian control fields, including folded descriptions/checksums."""
    result, row, key = [], {}, None
    for line in text.splitlines() + ['']:
        if not line:
            if row:
                result.append(row)
            row, key = {}, None
        elif line.startswith((' ', '\t')):
            require(key is not None, 'Orphan metadata continuation')
            row[key] += '\n' + line[1:]
        else:
            key, sep, value = line.partition(':')
            require(sep and re.fullmatch('[A-Za-z0-9-]+', key) and key not in row,
                    'Malformed or duplicate metadata field')
            row[key] = value.strip()
    return result


def index_identity(release, suite):
    rows = paragraphs(release)
    require(len(rows) == 1 and rows[0].get('Origin') == 'Ubuntu' and
            rows[0].get('Suite') == suite and rows[0].get('Codename') == 'jammy',
            'Wrong distribution release')
    matches = [line.split() for line in rows[0].get('SHA256', '').splitlines()
               if line.split() and line.split()[-1] == INDEX]
    require(len(matches) == 1 and len(matches[0]) == 3, 'Missing or duplicate index checksum')
    sha, size, _ = matches[0]
    require(re.fullmatch('[0-9a-f]{64}', sha) and size.isdecimal() and
            0 < int(size) <= MAX_DOWNLOAD, 'Invalid index identity')
    return int(size), sha


def select_packages(text, found):
    versions = {dev: version for dev, _, version, *_ in REQUIRED}
    for row in paragraphs(text):
        name = row.get('Package')
        if name not in versions or row.get('Version') != versions[name]:
            continue
        require(row.get('Architecture') == 'amd64', 'Wrong development architecture')
        filename, sha, size = (row.get(k, '') for k in ('Filename', 'SHA256', 'Size'))
        require(re.fullmatch(r'pool/main/[a-z0-9/+_.-]+_amd64\.deb', filename) and
                '..' not in PurePosixPath(filename).parts and
                re.fullmatch('[0-9a-f]{64}', sha) and size.isdecimal() and
                0 < int(size) <= MAX_DOWNLOAD, 'Invalid development package identity')
        entry = {k: row[k] for k in ('Package', 'Version', 'Architecture', 'Filename', 'SHA256', 'Size')}
        require(name not in found or found[name] == entry, 'Conflicting package metadata')
        found[name] = entry


def verify_release(folder, keyring):
    home = folder / 'gpg-home'
    home.mkdir()
    argv = ['/usr/bin/gpgv', '--homedir', str(home), '--keyring', str(keyring),
            '--status-fd', '1', '--output', str(folder / 'Release'), str(folder / 'InRelease')]
    with (folder / 'signature.log').open('xb') as log:
        proc = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT,
                              env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, cwd=folder, timeout=30)
    status = (folder / 'signature.log').read_text()
    signatures = [line.split()[2] for line in status.splitlines()
                  if line.startswith('[GNUPG:] VALIDSIG ')]
    require(proc.returncode == 0 and signatures == [SIGNER], 'Ubuntu archive signature rejected')


def deb_tar(archive, kind, folder):
    # dpkg-deb handles the distribution's compression without installing it.
    # A separate child sets the output bound; no preexec_fn in a threaded host.
    target = folder / (kind + '.tar')
    program = ('import os, resource, sys; '
               'resource.setrlimit(resource.RLIMIT_CORE, (0, 0)); '
               'resource.setrlimit(resource.RLIMIT_FSIZE, (67108864, 67108864)); '
               'os.execv("/usr/bin/dpkg-deb", ["dpkg-deb", sys.argv[1], sys.argv[2]])')
    with target.open('xb') as stream, (folder / (kind + '.log')).open('xb') as log:
        result = subprocess.run([sys.executable, '-I', '-S', '-c', program,
            '--ctrl-tarfile' if kind == 'control' else '--fsys-tarfile', str(archive)],
            stdout=stream, stderr=log, cwd=folder, timeout=30,
            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    require(result.returncode == 0 and target.stat().st_size <= MAX_EXPANDED,
            'Development package decompression failed')
    return target.read_bytes()


def members(data):
    require(len(data) <= MAX_EXPANDED, 'Development archive expansion exceeded')
    rows, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
        for item in archive:
            name = item.name.removeprefix('./').rstrip('/')
            if name in ('', '.') and item.isdir():
                continue
            path = PurePosixPath(name)
            require_member(name and str(path) == name and not path.is_absolute() and
                    '..' not in path.parts and name not in rows and
                    not item.mode & 0o7000 and (item.isdir() or item.isfile() or item.issym()),
                    item, 'Unsafe development archive member')
            total += item.size
            require_member(len(rows) < 10000 and 0 <= item.size <= 4 * 1024 ** 2 and
                    total <= MAX_EXPANDED, item, 'Development archive member exceeds bound')
            content = archive.extractfile(item).read() if item.isfile() else None
            if item.issym():
                # Links are inspected, never followed or extracted. Distribution
                # documentation aliases may name another package's documentation;
                # they are discarded along with the rest of usr/share.
                target = posixpath.normpath(posixpath.join('/' + str(path.parent), item.linkname))
                documentation = bool(item.linkname) and any(name.startswith(tree) and
                    not item.linkname.startswith('/') and target.startswith('/' + tree)
                    for tree in ('usr/share/doc/', 'usr/share/man/'))
                require_member(documentation or
                        re.fullmatch(r'/(usr/)?lib/x86_64-linux-gnu/lib[a-z0-9_.+-]+', target),
                        item, 'Escaping development link')
            rows[name] = (item, content)
    for name, (item, _) in rows.items():
        require_member(not any(str(parent) in rows and not rows[str(parent)][0].isdir()
                       for parent in PurePosixPath(name).parents),
                       item, 'Conflicting development archive paths')
    return rows


def extract_headers(control, data, entry, library):
    controls = members(control)
    require('control' in controls and controls['control'][1] is not None,
            'Missing development control')
    metadata = paragraphs(controls['control'][1].decode())
    require(len(metadata) == 1 and all(metadata[0].get(k) == entry[k]
            for k in ('Package', 'Version', 'Architecture')), 'Development control mismatch')
    files = members(data)
    headers = {}
    for name, (item, content) in files.items():
        # Signed development packages contain executable documentation examples.
        # All member/path/link checks above still apply; these files never reach
        # the build stage and are never executed, extracted or followed.
        if name.startswith('usr/share/doc/' + entry['Package'] + '/'):
            continue
        if name.startswith('usr/include/') and not item.isdir():
            require_member(item.isfile() and not item.mode & 0o111 and name.endswith('.h'),
                    item, 'Unexpected executable or linked build header')
            headers[name.removeprefix('usr/include/')] = content
        # Static libraries/pkg-config/manpages are deliberately not installed.
        require_member(not (item.isfile() and item.mode & 0o111),
                       item, 'Unexpected executable package payload')
    link = 'usr/lib/x86_64-linux-gnu/lib' + library + '.so'
    require(headers and link in files and files[link][0].issym(), 'Missing development header/linker input')
    target = posixpath.normpath(posixpath.join('/usr/lib/x86_64-linux-gnu', files[link][0].linkname))
    require_member(re.fullmatch(r'/(usr/)?lib/x86_64-linux-gnu/lib' + library + r'\.so\.[0-9.]+', target),
            files[link][0], 'Unexpected native runtime link target')
    return headers, target


def acquire(out, keyring):
    folder = out / 'development-inputs'
    folder.mkdir()
    record = {'schema': 1, 'status': 'incomplete', 'snapshot': BASE,
              'signer': SIGNER, 'keyring': reference(out, keyring),
              'driver_sha256': digest(__file__), 'downloads': []}
    def download(relative, destination, **expected):
        row = {'url': BASE + relative, 'status': 'incomplete', **expected}
        record['downloads'].append(row)
        save(folder / 'attempt.json', record)
        try:
            fetch(relative, destination, **expected)
            row['status'] = 'verified'
        except BaseException as exc:
            row.update(status='failed', error_type=type(exc).__name__)
            raise
        finally:
            if destination.is_file():
                row['artifact'] = reference(out, destination)
            save(folder / 'attempt.json', record)
    package, archive = None, None
    try:
        found = {}
        for suite in SUITES:
            part = folder / suite
            part.mkdir()
            download('dists/' + suite + '/InRelease', part / 'InRelease')
            verify_release(part, keyring)
            size, sha = index_identity((part / 'Release').read_text(), suite)
            download('dists/' + suite + '/' + INDEX, part / 'Packages.gz', size=size, sha256=sha)
            with gzip.open(part / 'Packages.gz', 'rb') as stream:
                text = stream.read(MAX_EXPANDED + 1)
            require(len(text) <= MAX_EXPANDED, 'Package index expansion exceeded')
            select_packages(text.decode(), found)
        require(set(found) == {r[0] for r in REQUIRED}, 'Exact development packages unavailable')
        save(folder / 'freeze.json', found)  # finite artifact set before extraction/build
        headers, packages = {}, {}
        for dev, _, _, _, library, _ in REQUIRED:
            entry = found[dev]
            package = {k: entry[k] for k in ('Package', 'Version', 'Architecture', 'SHA256')}
            part = folder / dev
            archive = part / 'package.deb'
            part.mkdir()
            download(entry['Filename'], archive, size=int(entry['Size']), sha256=entry['SHA256'])
            selected, target = extract_headers(deb_tar(archive, 'control', part),
                deb_tar(archive, 'data', part), entry, library)
            require(not headers.keys() & selected.keys(), 'Conflicting staged headers')
            headers.update(selected)
            packages[dev] = {'metadata': entry, 'runtime_library': target}
        package, archive = None, None
        dest = out / 'development-stage'
        require(dest.is_dir() and not any(dest.iterdir()), 'Build input staging is not fresh')
        for name, content in headers.items():
            target = dest / 'include' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as stream:
                stream.write(content)
        manifest = {'schema': 1, 'packages': packages,
                    'headers': {name: hashlib.sha256(data).hexdigest() for name, data in headers.items()}}
        save(dest / 'verified.json', manifest)
        save(folder / 'staged.json', manifest)
        record['status'] = 'complete'
    except BaseException as exc:
        record.update(status='failed', error_type=type(exc).__name__)
        if package is not None:
            record['rejected_package'] = package
            if archive is not None and archive.is_file():
                record['rejected_archive'] = reference(out, archive)
        if isinstance(exc, ArchiveMemberError):
            record['rejected_member'] = exc.member
        raise
    finally:
        record['artifacts'] = {str(p.relative_to(folder)): reference(out, p)
            for p in folder.rglob('*') if p.is_file() and p.name != 'attempt.json'}
        save(folder / 'attempt.json', record)
