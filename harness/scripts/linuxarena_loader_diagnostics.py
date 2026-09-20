"""Private, bounded sudo loader observations for the native compatibility fixture.

Reads selected runtime/configuration metadata only; never emits file contents.
No policy changes or application execution.
ELF decoding is limited to the pinned x86_64 little-endian runtime, not a general
binary inspection API. The trusted image scan runs before payload admission.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys

MAX_FILE = 32 * 1024 * 1024
MAX_OUTPUT = 32768
PAM_ROOT = '/etc/pam.d'
MAX_PAM_FILES = 32
MAX_PAM_FILE = 65536
HOST_FILES = ('/etc/hostname', '/etc/hosts', '/etc/nsswitch.conf', '/etc/resolv.conf')
PACKAGES = ('sudo', 'libpam0g', 'libpam-modules', 'libpam-modules-bin', 'libpam-runtime')


def elf_metadata(data):
    def region(offset, size):
        if offset < 0 or size < 0 or offset + size > len(data):
            raise ValueError('Truncated ELF region')
        return data[offset:offset + size]

    def string(data, offset=0):
        if not 0 <= offset < len(data):
            raise ValueError('Invalid ELF string offset')
        end = data.find(b'\0', offset)
        if end < 0:
            raise ValueError('Unterminated ELF string')
        return data[offset:end].decode('utf-8', errors='replace')

    header = struct.unpack('<16sHHIQQQIHHHHHH', region(0, 64))
    if header[0][:7] != b'\x7fELF\x02\x01\x01' or header[2] != 62:
        raise ValueError('Expected x86_64 little-endian ELF')
    offset, size, count = header[5], header[9], header[10]
    if size != 56 or not 0 < count <= 128:
        raise ValueError('Invalid ELF program header table')
    segments = [struct.unpack('<IIQQQQQQ', region(offset + i * size, size))
                for i in range(count)]
    result = {'interpreter': None, 'needed': [], 'rpath': [], 'runpath': []}
    dynamic = []
    for kind, flags, off, va, pa, filesz, memsz, align in segments:
        if kind == 3:
            result['interpreter'] = string(region(off, filesz))
        if kind == 2:
            if filesz % 16 or filesz > 65536:
                raise ValueError('Invalid ELF dynamic table')
            for pos in range(off, off + filesz, 16):
                tag, value = struct.unpack('<qQ', region(pos, 16))
                if tag == 0:
                    break
                dynamic.append((tag, value))
    tags = dict(dynamic)
    if dynamic:
        address, length = tags[5], tags[10]
        tables = [region(off + address - va, length)
                  for kind, flags, off, va, pa, filesz, memsz, align in segments
                  if kind == 1 and va <= address and address + length <= va + filesz]
        if len(tables) != 1:
            raise ValueError('Invalid ELF string table mapping')
        for tag, value in dynamic:
            if tag in (1, 15, 29):
                result[{1: 'needed', 15: 'rpath', 29: 'runpath'}[tag]].append(string(tables[0], value))
    return result


def file_metadata(name, *, parser=None, limit=MAX_FILE, beneath=None):
    path = Path(name)
    result = {'path': name, 'components': []}
    for component in reversed((path, *path.parents)):
        row = {'path': str(component)}
        try:
            info = component.lstat()
            row.update(mode=oct(info.st_mode), uid=info.st_uid, gid=info.st_gid)
            if stat.S_ISLNK(info.st_mode):
                row['target'] = os.readlink(component)
        except OSError as exc:
            row['errno'] = exc.errno
        result['components'].append(row)
    try:
        # Includes are inspected only in the trusted immutable image, before
        # admission. Never follow an unexpected config link into a secret store.
        if beneath is not None:
            resolved = path.resolve(strict=True)
            result['resolved'] = str(resolved)
            if not resolved.is_relative_to(beneath):
                raise ValueError('Diagnostic resolved path outside configuration root')
        # O_NONBLOCK prevents a malformed image path naming a FIFO from hanging.
        fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                raise ValueError('Diagnostic file type/size limit')
            data = stream.read(limit + 1)
            if len(data) > limit:
                raise ValueError('Diagnostic file grew past limit')
        result.update(resolved=str(path.resolve(strict=True)), size=len(data),
                      opened_mode=oct(info.st_mode), opened_uid=info.st_uid, opened_gid=info.st_gid,
                      sha256=hashlib.sha256(data).hexdigest(), open_errno=None)
        if parser is not None:
            try:
                result['parsed'] = parser(data)
            except (ValueError, UnicodeError):
                result['parse_error'] = 'Malformed diagnostic configuration'
        else:
            try:
                result['elf'] = elf_metadata(data)
            except (ValueError, KeyError, struct.error) as exc:
                result['elf_error'] = str(exc)
    except OSError as exc:
        result['open_errno'] = exc.errno
    except ValueError as exc:
        result['error'] = str(exc)
    except RuntimeError:
        result['error'] = 'Diagnostic path resolution failed'
    return result


def pam_includes(data):
    """Bounded include discovery, not a PAM policy interpreter or validator.

    Keep only canonical pam.d include names and line/error codes, never module
    arguments or configuration contents. Other native syntax remains unexecuted.
    """
    text = data.decode('utf-8')
    if '\0' in text:
        raise ValueError('Invalid configuration')
    includes, errors = [], []
    # PAM assembles continued lines before parsing. Comment text is not data.
    lines = '\n'.join(line.split('#', 1)[0] for line in text.splitlines()).replace('\\\n', '').split('\n')
    for number, line in enumerate(lines, 1):
        if len(errors) == 32:
            errors.append({'line': number, 'error': 'error limit'})
            break
        if number > 1024:
            errors.append({'line': number, 'error': 'line limit'})
            break
        fields = line.split()
        if not fields:
            continue
        if fields[0] == '@include':
            target = fields[1] if len(fields) == 2 else None
        elif fields[0].lstrip('-') in ('auth', 'account', 'password', 'session'):
            if len(fields) < 3:
                errors.append({'line': number, 'error': 'malformed entry'})
                continue
            if fields[1] not in ('include', 'substack'):
                continue
            target = fields[2] if len(fields) == 3 else None
        else:
            errors.append({'line': number, 'error': 'unsupported entry'})
            continue
        if target and target.startswith(PAM_ROOT + '/'):
            target = target[len(PAM_ROOT) + 1:]
        if not target or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', target):
            errors.append({'line': number, 'error': 'malformed or out-of-scope include'})
            continue
        name = PAM_ROOT + '/' + target
        if name not in includes:
            if len(includes) == MAX_PAM_FILES:
                errors.append({'line': number, 'error': 'include limit'})
                break
            includes.append(name)
    return {'includes': includes, 'errors': errors}


def pam_inventory():
    pending = [PAM_ROOT + '/sudo', PAM_ROOT + '/other']
    files, seen = [], set(pending)
    limited = False
    while pending:
        row = file_metadata(pending.pop(0), parser=pam_includes,
                            limit=MAX_PAM_FILE, beneath=PAM_ROOT)
        files.append(row)
        for name in row.get('parsed', {}).get('includes', []):
            if name not in seen:
                if len(seen) == MAX_PAM_FILES:
                    limited = True
                else:
                    seen.add(name)
                    pending.append(name)
    return {'files': files, 'file_limit_exceeded': limited,
            'scope': 'trusted image include discovery only, not PAM validation'}


def package_fields(data):
    """Read only fixed package identity fields from Debian's local database."""
    found = {}
    for stanza in data.decode('utf-8').split('\n\n'):
        fields = {}
        for line in stanza.splitlines():
            key, separator, value = line.partition(': ')
            if separator and key in ('Package', 'Version', 'Architecture', 'Status'):
                if key in fields:
                    raise ValueError('Duplicate package field')
                fields[key] = value
        name = fields.get('Package')
        if name in PACKAGES:
            if (name in found or set(fields) != {'Package', 'Version', 'Architecture', 'Status'} or
                    any(not re.fullmatch(r'[A-Za-z0-9.+:~ -]{1,128}', v) for v in fields.values())):
                raise ValueError('Malformed package identity')
            found[name] = fields
    return {'packages': found, 'missing': sorted(set(PACKAGES) - set(found))}


def sudoers_directory_metadata():
    """Observe the fixed include directory without reading configuration bytes."""
    name = '/etc/sudoers.d'
    result = {'path': name}
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            result.update(opened_mode=oct(info.st_mode), opened_uid=info.st_uid,
                          opened_gid=info.st_gid, open_errno=None)
            entries = []
            with os.scandir(fd) as iterator:
                for entry in iterator:
                    if len(entries) == 64:
                        result['truncated'] = True
                        break
                    entries.append(entry.name)
            result['entries'] = sorted(entries)
        finally:
            os.close(fd)
    except OSError as exc:
        result['open_errno'] = exc.errno
    return result


def image_inventory():
    names = {'/usr/bin/sudo', '/bin/sudo', '/lib64/ld-linux-x86-64.so.2',
             '/usr/libexec/sudo/sudoers.so', '/etc/sudoers',
             '/usr/lib/sudo/libsudo_util.so.0', '/usr/libexec/sudo/libsudo_util.so.0',
             '/usr/lib/x86_64-linux-gnu/sudo/libsudo_util.so.0'}
    errors, visited = [], 0
    for base in ('/usr/lib', '/usr/libexec'):
        for root, dirs, files in os.walk(base, followlinks=False,
                                         onerror=lambda e: errors.append({'path': e.filename, 'errno': e.errno})):
            dirs.sort()
            visited += len(dirs) + len(files)
            if visited > 50000:
                raise ValueError('Runtime library scan limit exceeded')
            for name in files:
                if name.startswith('libsudo_util.so'):
                    names.add(str(Path(root) / name))
    sudo = file_metadata('/usr/bin/sudo')
    interpreter = sudo.get('elf', {}).get('interpreter')
    if interpreter:
        names.add(interpreter)
    if len(names) > 64:
        raise ValueError('Runtime library path limit exceeded')
    return {'files': [file_metadata(name) for name in sorted(names)], 'scan_errors': errors,
            'pam': pam_inventory(),
            'packages': file_metadata('/var/lib/dpkg/status', parser=package_fields),
            'hostname_configuration': [file_metadata(name) for name in HOST_FILES],
            'sudoers_include_directory': sudoers_directory_metadata()}


def process_record(argv):
    # Only the selected image loader is invoked, with --list (no application
    # entry point). Explicit invocation is diagnostic, not a sudo equivalence
    # claim: setuid/AT_SECURE behavior may differ from ordinary exec.
    try:
        result = subprocess.run(argv, capture_output=True, timeout=5,
                                env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'LD_DEBUG': 'libs'})
        return {'argv': argv, 'returncode': result.returncode,
                'stdout': result.stdout[:MAX_OUTPUT].decode(errors='replace'),
                'stderr': result.stderr[:MAX_OUTPUT].decode(errors='replace'),
                'truncated': len(result.stdout) > MAX_OUTPUT or len(result.stderr) > MAX_OUTPUT}
    except subprocess.TimeoutExpired as exc:
        return {'argv': argv, 'timeout': True,
                'stdout': (exc.stdout or b'')[:MAX_OUTPUT].decode(errors='replace'),
                'stderr': (exc.stderr or b'')[:MAX_OUTPUT].decode(errors='replace')}
    except OSError as exc:
        return {'argv': argv, 'errno': exc.errno}


def confined_record(inventory):
    files = [file_metadata(row['path']) for row in inventory['files']]
    sudo = next(row for row in inventory['files'] if row['path'] == '/usr/bin/sudo')
    interpreter = sudo.get('elf', {}).get('interpreter')
    loader = (process_record([interpreter, '--list', '/usr/bin/sudo']) if interpreter else
              {'unavailable': 'Trusted image sudo has no decoded interpreter'})
    return {'files': files, 'loader_list': loader,
            # The trusted image determines the complete bounded path list;
            # confinement denial must not silently prune includes from it.
            'pam': {'files': [file_metadata(row['path'], limit=MAX_PAM_FILE, beneath=PAM_ROOT)
                              for row in inventory.get('pam', {}).get('files', [])]},
            'hostname_configuration': [file_metadata(name) for name in HOST_FILES],
            'sudoers_include_directory': sudoers_directory_metadata(),
            'scope': 'confined diagnostic only; actual sudo exec asserted separately'}


if __name__ == '__main__':
    if len(sys.argv) != 1:
        raise ValueError('Trusted image diagnostic takes no arguments')
    print(json.dumps(image_inventory(), sort_keys=True))
