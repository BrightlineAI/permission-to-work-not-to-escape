"""Private, bounded sudo loader observations for the native compatibility fixture.

Image inventory reads selected runtime/configuration metadata, never contents
in output or module execution. A separate confined account-hook diagnostic
reports numeric PAM returns after sudo fails; it cannot authorize execution.
No policy changes or account-store provisioning.
ELF decoding is limited to the pinned x86_64 little-endian runtime, not a general
binary inspection API. The trusted image scan runs before payload admission.
"""
import hashlib
import ctypes
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
PAM_MODULE_DIRS = ('/lib/x86_64-linux-gnu/security', '/usr/lib/x86_64-linux-gnu/security',
                   '/lib/security', '/usr/lib/security')
LIBRARY_DIRS = ('/lib/x86_64-linux-gnu', '/usr/lib/x86_64-linux-gnu', '/lib', '/usr/lib')
MAX_PAM_MODULES = 32
MAX_LIBRARY_FILES = 256
HOST_FILES = ('/etc/hostname', '/etc/hosts', '/etc/nsswitch.conf', '/etc/resolv.conf')
PACKAGES = ('sudo', 'libpam0g', 'libpam-modules', 'libpam-modules-bin', 'libpam-runtime',
            'libaudit1')


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
            roots = beneath if isinstance(beneath, tuple) else (beneath,)
            if not any(resolved.is_relative_to(root) for root in roots):
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

    Keep include/module identities and line/error codes, never module arguments
    or configuration contents. This does not evaluate stack controls.
    """
    text = data.decode('utf-8')
    if '\0' in text:
        raise ValueError('Invalid configuration')
    includes, modules, errors = [], [], []
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
                entry = re.fullmatch(r'(-?(?:auth|account|password|session))\s+'
                    r'(?:required|requisite|sufficient|optional|\[[^\[\]]+\])\s+'
                    r'(\S+)(?:\s+.*)?', line.strip())
                if not entry:
                    errors.append({'line': number, 'error': 'malformed module entry'})
                    continue
                module = entry[2]
                leaf = Path(module).name
                if (not re.fullmatch(r'pam_[A-Za-z0-9_-]{1,100}\.so', leaf) or
                        (module != leaf and module not in
                         [base + '/' + leaf for base in PAM_MODULE_DIRS])):
                    errors.append({'line': number, 'error': 'out-of-scope module'})
                    continue
                if len(modules) == MAX_PAM_MODULES:
                    errors.append({'line': number, 'error': 'module limit'})
                    break
                modules.append({'line': number, 'type': entry[1].lstrip('-'), 'module': module})
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
    return {'includes': includes, 'modules': modules, 'errors': errors}


def pam_library_inventory(pam):
    """Inspect selected modules and DT_NEEDED candidates without loading code.

    Fixed directories describe only the pinned Debian x86_64 layout. All
    candidates (including missing ones) remain visible; this is not ld.so
    resolution, a dlopen probe, or proof that an account hook succeeds.
    """
    pending, seen, files, errors = [], set(), [], []
    limited = False

    def add(name):
        nonlocal limited
        if name not in seen:
            if len(seen) == MAX_LIBRARY_FILES:
                limited = True
            else:
                seen.add(name)
                pending.append(name)

    for row in pam['files']:
        for entry in row.get('parsed', {}).get('modules', []):
            module = entry['module']
            for name in ([module] if module.startswith('/') else
                         [base + '/' + module for base in PAM_MODULE_DIRS]):
                add(name)
    while pending:
        row = file_metadata(pending.pop(0), beneath=('/usr/lib', '/lib'))
        files.append(row)
        safe_needed, rejected = [], 0
        for name in row.get('elf', {}).get('needed', []):
            if not re.fullmatch(r'[A-Za-z0-9_+.-]{1,128}', name) or name in ('.', '..'):
                rejected += 1
                continue
            safe_needed.append(name)
            for base in LIBRARY_DIRS:
                add(base + '/' + name)
        if rejected:
            row['elf']['needed'] = safe_needed
            errors.append({'path': row['path'], 'error': 'out-of-scope dependency',
                           'count': rejected})
    return {'files': files, 'errors': errors, 'file_limit_exceeded': limited,
            'scope': 'fixed-directory ELF candidates; no module execution or account data reads'}


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
    pam = pam_inventory()
    return {'files': [file_metadata(name) for name in sorted(names)], 'scan_errors': errors,
            'pam': pam, 'pam_libraries': pam_library_inventory(pam),
            'packages': file_metadata('/var/lib/dpkg/status', parser=package_fields),
            'hostname_configuration': [file_metadata(name) for name in HOST_FILES],
            'sudoers_include_directory': sudoers_directory_metadata()}


def process_record(argv, *, loader_debug=True):
    # Only fixed diagnostic commands use this helper. Loader --list does not
    # enter the application and may differ from setuid/AT_SECURE execution.
    env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
    if loader_debug:
        env['LD_DEBUG'] = 'libs'
    try:
        result = subprocess.run(argv, capture_output=True, timeout=5,
                                env=env)
        return {'argv': argv, 'returncode': result.returncode,
                'stdout': result.stdout[:MAX_OUTPUT].decode(errors='replace'),
                'stderr': result.stderr[:MAX_OUTPUT].decode(errors='replace'),
                'truncated': len(result.stdout) > MAX_OUTPUT or len(result.stderr) > MAX_OUTPUT}
    except subprocess.TimeoutExpired as exc:
        return {'argv': argv, 'timeout': True,
                'stdout': (exc.stdout or b'')[:MAX_OUTPUT].decode(errors='replace'),
                'stderr': (exc.stderr or b'')[:MAX_OUTPUT].decode(errors='replace'),
                'truncated': len(exc.stdout or b'') > MAX_OUTPUT or len(exc.stderr or b'') > MAX_OUTPUT}
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
            'pam_libraries': {'files': [file_metadata(row['path'], beneath=('/usr/lib', '/lib'))
                              for row in inventory.get('pam_libraries', {}).get('files', [])]},
            'hostname_configuration': [file_metadata(name) for name in HOST_FILES],
            'sudoers_include_directory': sudoers_directory_metadata(),
            'scope': 'confined diagnostic only; actual sudo exec asserted separately'}


def confined_inventory(inventory):
    """Carry paths, not repeated image metadata, in the bounded launch argument.

    The full image receipt is retained separately. A denied open must not erase
    a path, and the interpreter must come from the trusted image, not payload.
    """
    result = {'files': [{'path': row['path']} for row in inventory['files']]}
    for original, row in zip(inventory['files'], result['files']):
        if original['path'] == '/usr/bin/sudo':
            row['elf'] = {'interpreter': original.get('elf', {}).get('interpreter')}
    for key in ('pam', 'pam_libraries'):
        result[key] = {'files': [{'path': row['path']}
                                for row in inventory.get(key, {}).get('files', [])]}
    return result


def pam_account_hook():
    """Observe public PAM account dispatch, only in the confined native fixture.

    Use the image's sudo stack, never a module entry point with an application
    handle: module-data APIs require the caller context set by PAM dispatch.
    This is a diagnostic, not authorization or full sudo equivalence.
    Refuse execution if a shadow store is visible, even as a dangling link.
    Never open, copy, synthesize or print account/credential records.
    """
    def progress(stage, status=None, error=None):
        # Fixed stages and numeric returns only. Flush before the next native
        # call so timeout/crash receipts retain progress even without final JSON.
        row = {'pam_account_stage': stage}
        if status is not None:
            row['status'] = status
        if error is not None:
            row['errno'] = error
        print(json.dumps(row, sort_keys=True), file=sys.stderr, flush=True)

    progress('entry')
    result = {'scope': 'public PAM account dispatch; not full sudo equivalence',
              'api': 'pam_acct_mgmt', 'service': 'sudo', 'flags': 0x8000,
              'conversations_refused': 0}
    if os.getuid() != 0 or os.geteuid() != 0:
        return {**result, 'unavailable': 'Expected confined fixture root'}
    try:
        os.lstat('/etc/shadow')
    except FileNotFoundError:
        result['shadow_path'] = 'absent; no content inspected'
    except OSError as exc:
        return {**result, 'unavailable': 'Cannot establish absent shadow path', 'errno': exc.errno}
    else:
        return {**result, 'unavailable': 'Shadow path visible; account hook not invoked'}

    # The PAM conversation ABI has four arguments. Refuse every conversation
    # without dereferencing a message or providing a password/response.
    callback_type = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_void_p,
                                    ctypes.c_void_p, ctypes.c_void_p)
    def refuse(*unused):
        result['conversations_refused'] += 1
        return 19  # PAM_CONV_ERR in the pinned Linux-PAM headers.

    class Conversation(ctypes.Structure):
        _fields_ = [('conv', callback_type), ('appdata_ptr', ctypes.c_void_p)]

    conversation = Conversation(callback_type(refuse), None)
    handle = ctypes.c_void_p()
    try:
        progress('libpam_load_before')
        pam = ctypes.CDLL('/lib/x86_64-linux-gnu/libpam.so.0', use_errno=True)
        progress('libpam_load_after')
        pam.pam_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                                 ctypes.POINTER(Conversation), ctypes.POINTER(ctypes.c_void_p)]
        pam.pam_start.restype = ctypes.c_int
        pam.pam_end.argtypes = [ctypes.c_void_p, ctypes.c_int]
        pam.pam_end.restype = ctypes.c_int
        pam.pam_acct_mgmt.argtypes = [ctypes.c_void_p, ctypes.c_int]
        pam.pam_acct_mgmt.restype = ctypes.c_int
        progress('pam_start_before')
        status = pam.pam_start(b'sudo', b'root', ctypes.byref(conversation), ctypes.byref(handle))
        result['pam_start'] = status
        progress('pam_start_after', status)
        if status == 0:
            try:
                progress('pam_account_before')
                ctypes.set_errno(0)
                # PAM_SILENT, as in pinned sudo. Let PAM load and dispatch its
                # configured stack; do not forge internal handle state.
                status = pam.pam_acct_mgmt(handle, result['flags'])
                error = ctypes.get_errno()
                result.update(pam_account=status, pam_account_errno=error)
                progress('pam_account_after', status, error)
            finally:
                progress('pam_end_before')
                result['pam_end'] = pam.pam_end(handle, status)
                progress('pam_end_after', result['pam_end'])
    except (OSError, AttributeError):
        result['unavailable'] = 'Pinned PAM library or account symbol unavailable'
    if 'pam_account' in result:
        # Observe only after preserving PAM's return and finishing its cleanup.
        # This opens no audit records and sends no audit requests. A socket-open
        # failure can mask the stack result in PAM; it cannot prove stack success.
        audit_result = {'api': 'audit_open', 'library': '/lib/x86_64-linux-gnu/libaudit.so.1'}
        result['audit'] = audit_result
        try:
            progress('libaudit_load_before')
            audit = ctypes.CDLL(audit_result['library'], use_errno=True)
            progress('libaudit_load_after')
            audit.audit_open.argtypes = []
            audit.audit_open.restype = ctypes.c_int
            progress('audit_open_before')
            ctypes.set_errno(0)
            fd = audit.audit_open()
            error = ctypes.get_errno()
            try:
                audit_result.update(returncode=fd, errno=error)
                progress('audit_open_after', fd, error)
            finally:
                if fd >= 0:
                    progress('audit_close_before')
                    try:
                        os.close(fd)
                    except OSError as exc:
                        audit_result['close_errno'] = exc.errno
                        progress('audit_close_after', -1, exc.errno)
                    else:
                        audit_result['close_errno'] = None
                        progress('audit_close_after', 0)
        except (OSError, AttributeError):
            audit_result['unavailable'] = 'Pinned audit library or open symbol unavailable'
    return result


def account_process_record():
    """A separate bounded child, under the same confinement as failed sudo."""
    argv = ['/usr/bin/python3', '-I', '-S', '/ptw-native-tools/loader_diagnostics.py',
            '--pam-account-hook']
    return process_record(argv, loader_debug=False)


def sudo_identity_control(expected_sha256=None):
    """Fixed immutable-image control, never a mutable execution entry point.

    Native sudo alone handles authentication. Only numeric identity/status and
    the executable hash leave this function; no account contents or raw output.
    Both calls use the fresh read-only fixture; the trusted call precedes
    mutable admission and the comparison call runs under confinement.
    """
    executable = '/usr/bin/id'
    record = {'scope': 'native identity diagnostic only; not protected useful work',
              'argv': ['/usr/bin/sudo', '-n', '-u', 'dev', '--', executable]}
    metadata = file_metadata(executable)
    record['executable_sha256'] = metadata.get('sha256')
    try:
        mode = int(metadata.get('opened_mode', '0'), 8)
        valid = (os.geteuid() == 0 and metadata.get('resolved') == executable and
                 metadata.get('opened_uid') == 0 and stat.S_ISREG(mode) and
                 mode & 0o111 and not mode & 0o6022 and
                 'elf' in metadata and re.fullmatch('[0-9a-f]{64}', metadata.get('sha256', '')) and
                 os.statvfs(executable).f_flag & os.ST_RDONLY)
    except OSError as exc:
        record['errno'] = exc.errno
        valid = False
    if not valid or (expected_sha256 is not None and
                     expected_sha256 != metadata.get('sha256')):
        record['status'] = 'unverified_executable'
        return record
    try:
        result = subprocess.run(record['argv'], stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=5, close_fds=True,
                                cwd='/', env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    except subprocess.TimeoutExpired:
        record['status'] = 'timeout'
        return record
    except OSError as exc:
        record.update(status='launch_error', errno=exc.errno)
        return record
    record['returncode'] = result.returncode
    if file_metadata(executable).get('sha256') != metadata['sha256']:
        record['status'] = 'executable_changed'
        return record
    if len(result.stdout) > MAX_OUTPUT or len(result.stderr) > MAX_OUTPUT:
        record['status'] = 'output_limit'
        return record
    if result.returncode != 0:
        record['status'] = 'sudo_failed'
        record['account_validation_failure'] = any(message in result.stderr for message in (
            b'PAM account management error', b'account validation failure, is your account locked?'))
        return record
    # GNU id's fixed C-locale output, without SELinux or differing real/effective
    # IDs in this image. Unexpected output fails explicitly, never guesses IDs.
    number = rb'([0-9]{1,10})(?:\([^(),\r\n]*\))?'
    match = re.fullmatch(rb'uid=' + number + rb' gid=' + number +
                         rb' groups=(' + number + rb'(?:,' + number + rb')*)\n', result.stdout)
    if match is None:
        record['status'] = 'invalid_identity'
        return record
    uid, gid = int(match[1]), int(match[2])
    groups = [int(entry.split(b'(', 1)[0]) for entry in match[3].split(b',')]
    if uid == 0 or gid not in groups or any(value >= 2**32 - 1 for value in (uid, gid, *groups)):
        record['status'] = 'invalid_identity'
        return record
    record.update(status='observed', uid=uid, gid=gid, groups=groups)
    return record


if __name__ == '__main__':
    if sys.argv[1:] == ['--pam-account-hook']:
        print(json.dumps(pam_account_hook(), sort_keys=True))
    elif sys.argv[1:] == ['--sudo-identity-control']:
        print(json.dumps(sudo_identity_control(), sort_keys=True))
    elif len(sys.argv) == 1:
        print(json.dumps(image_inventory(), sort_keys=True))
    else:
        raise ValueError('Trusted image diagnostic takes no arguments')
