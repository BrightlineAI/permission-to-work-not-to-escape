"""Source-bound sudo frontend checkpoint build, still closed to mutable work.

All distribution patches precede the small execution patch. Retained archives
are read only; derived sources/builds belong only to a fresh private fixture.
This does not install sudo or rebuild/replace its native policy/PAM plugin.
"""
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import re
import struct
import subprocess
import tarfile

from evidence_io import digest, reference, require, save
from ptw import linuxarena_namespace as namespace
import linuxarena_sudo_source as source
import linuxarena_sudo_inputs as inputs

HERE = Path(__file__).resolve().parent


def unpack(data, expected, destination, *, prefix):
    """Create regular files only, after validating the complete pinned archive."""
    require(len(data) <= source.MAX_ARCHIVE and hashlib.sha256(data).hexdigest() == expected,
            'Sudo build archive hash or size mismatch')
    rows, names, total = [], set(), 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as archive:
        for member in archive:
            name = member.name.rstrip('/')
            path = PurePosixPath(name)
            require(name and str(path) == name and not path.is_absolute() and
                    '..' not in path.parts and path.parts[0] == prefix and name not in names,
                    'Unsafe or duplicate sudo build path')
            names.add(name)
            total += max(0, member.size)
            require(len(names) <= 10000 and total <= 64 * 1024 ** 2 and
                    0 <= member.size <= source.MAX_MEMBER and
                    (member.isdir() or member.isfile()) and not member.mode & 0o7000,
                    'Unsupported sudo build member')
            content = None
            if member.isfile():
                with archive.extractfile(member) as stream:
                    content = stream.read(source.MAX_MEMBER + 1)
                require(len(content) == member.size, 'Incomplete sudo build member')
            rows.append((path, member.mode, content))
    require(rows, 'Empty sudo build archive')
    # Reject file/child conflicts before creating anything.
    files = {p for p, _, content in rows if content is not None}
    require(not any(parent in files for p, _, _ in rows for parent in p.parents),
            'Conflicting sudo build member paths')
    destination.mkdir()  # must be fresh, never extract into retained source
    for path, mode, content in rows:
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        if content is None:
            target.mkdir(exist_ok=True)
        else:
            # Preserve executable source scripts at creation; no chmod/chown,
            # tar extraction hooks, links, set-ID bits or package installation.
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode & 0o755)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(content)


def patch_targets(data):
    old, new = [], []
    for line in data.decode('utf-8').splitlines():
        if line.startswith(('--- ', '+++ ')):
            name = line[4:].split()[0]
            if name == '/dev/null' and line.startswith('--- '):
                old.append(None)  # pinned distribution regressions add files
                continue
            path = PurePosixPath(name)
            require(not path.is_absolute() and '..' not in path.parts and
                    len(path.parts) > 1 and str(path) == name,
                    'Unexpected distribution patch target')
            (old if line.startswith('--- ') else new).append('/'.join(path.parts[1:]))
    require(old and len(old) == len(new) and len(new) == len(set(new)) and
            all(a is None or a == b for a, b in zip(old, new)),
            'Distribution patch must modify or add regular targets')
    return [{'path': b, 'create': a is None} for a, b in zip(old, new)]


def replace_once(text, before, after):
    require(text.count(before) == 1, 'Sudo execution patch context changed')
    return text.replace(before, after, 1)


def execution_patch(root):
    """Only the common command-child setup seam, no parent/monitor mutation yet."""
    path = root / 'src/exec.c'
    text = path.read_text()
    text = replace_once(text, '#include "sudo.h"',
                        '#include "sudo.h"\n#include "linuxarena_sudo_child.h"')
    text = replace_once(text, '    unlimit_nproc();\n\n#if defined(HAVE_SETRESUID)',
                        '    unlimit_nproc();\n\n'
                        '    if (ptw_child_before_uid(details->cred.uid, details->cred.euid))\n'
                        '\tgoto done;\n\n#if defined(HAVE_SETRESUID)')
    # Restore/cwd remain native; the post-check executes after both, just before
    # exec_setup returns success. Failure goes through sudo's existing errfd.
    text = replace_once(text, '    ret = true;\n\ndone:\n',
                        '    if (ptw_child_after_uid(details->cred.uid, details->cred.euid))\n'
                        '\tgoto done;\n\n    ret = true;\n\ndone:\n')
    path.write_text(text)
    make = root / 'src/Makefile.in'
    make.write_text(replace_once(make.read_text(), 'OBJS = conversation.o',
                                 'OBJS = linuxarena_sudo_child.o conversation.o'))


def filter_header():
    data = namespace.socket_filter()
    rows = '\n'.join('    {0x%x, %d, %d, 0x%x},' % row
                     for row in struct.iter_unpack('<HBBI', data))
    return ('/* Generated from linuxarena_namespace.socket_filter(). */\n'
            '#define PTW_PAYLOAD_MASK UINT64_C(0x%x)\n' % namespace.CAPABILITY_MASK +
            '#define PTW_FILTER_SHA256 "%s"\n' % hashlib.sha256(data).hexdigest() +
            'static struct sock_filter ptw_socket_filter[] = {\n' + rows + '\n};\n')


def stage(source_receipt, out, bundle):
    original, debian = list(source.ARCHIVES)
    unpack((source_receipt / original).read_bytes(), source.ARCHIVES[original],
           bundle / 'upstream', prefix='sudo-1.9.9')
    unpack((source_receipt / debian).read_bytes(), source.ARCHIVES[debian],
           bundle / 'distribution', prefix='debian')
    root = bundle / 'upstream/sudo-1.9.9'
    patchdir = bundle / 'distribution/debian/patches'
    records = []
    for entry in (patchdir / 'series').read_text().splitlines():
        entry = entry.split('#', 1)[0].strip()
        if not entry:
            continue
        require(re.fullmatch(r'[A-Za-z0-9_.+-]+', entry) and
                entry not in {r['name'] for r in records}, 'Invalid distribution patch series')
        data = (patchdir / entry).read_bytes()
        targets = patch_targets(data)
        require(all(not (root / p['path']).is_symlink() and
                    ((not (root / p['path']).exists()) if p['create'] else
                     (root / p['path']).is_file()) for p in targets),
                'Distribution patch target missing')
        # Archive hashes fix the instructions. No shell or distro packaging hooks.
        command = ['patch', '--batch', '--forward', '--fuzz=0', '--no-backup-if-mismatch', '-p1']
        proc = subprocess.run(command, input=data, cwd=root, capture_output=True, timeout=30,
                              env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        log = out / ('distribution-patch-%02d.log' % len(records))
        log.write_bytes(proc.stdout + proc.stderr)
        records.append({'name': entry, 'sha256': hashlib.sha256(data).hexdigest(),
                        'targets': targets, 'argv': command, 'returncode': proc.returncode,
                        'log': reference(out, log)})
        save(out / 'distribution-patches.json', records)
        require(proc.returncode == 0 and not re.search(rb'with fuzz \d', proc.stdout + proc.stderr),
                'Distribution source patch failed')
    before = {p: digest(root / p) for p in ('src/exec.c', 'src/Makefile.in')}
    execution_patch(root)
    for name in ('linuxarena_sudo_child.c', 'linuxarena_sudo_child.h'):
        (root / 'src' / name).write_bytes((HERE / name).read_bytes())
    (root / 'src/linuxarena_sudo_filter.h').write_text(filter_header())
    checker = bundle / 'linuxarena_sudo_inputs.py'
    checker.write_bytes(Path(inputs.__file__).read_bytes())
    save(out / 'checkpoint-source.json', {
        'schema': 1, 'scope': 'closed command-child capability/filter checkpoint only',
        'archives': source.ARCHIVES, 'before_adapter_sha256': before,
        'driver_sha256': digest(__file__), 'namespace_sha256': digest(namespace.__file__),
        'build_input_checker': reference(out, checker),
        'filter_sha256': hashlib.sha256(namespace.socket_filter()).hexdigest(),
        'sources': {str(p.relative_to(root)): reference(out, p)
                    for p in sorted(root.rglob('*')) if p.is_file()},
        'distribution': {str(p.relative_to(bundle / 'distribution')): reference(out, p)
                         for p in sorted((bundle / 'distribution').rglob('*')) if p.is_file()}})


# Runs only in a fresh, offline private-daemon container. The native plugin,
# PAM stack and account/session handling stay installed and unmodified. Reuse
# the pinned distribution's configure arguments, and refuse absent build
# dependencies instead of disabling a configured security feature.
PREFLIGHT = r'''import hashlib, json, os, pathlib, runpy, subprocess
root = pathlib.Path('/ptw-sudo-gate/upstream/sudo-1.9.9')
out = pathlib.Path('/ptw-sudo-gate')
inputs = runpy.run_path(str(out / 'linuxarena_sudo_inputs.py'))
env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'LANG': 'C', 'HOME': '/tmp'}
version = subprocess.check_output(['/usr/bin/sudo', '-V'], env=env, text=True)
(out / 'native-version.txt').write_text(version)
args = inputs['configure_arguments']((out / 'distribution/debian/rules').read_bytes(), version)
binding = {'configure_argv': ['/bin/sh', str(root / 'configure'), *args],
    'rules_sha256': inputs['RULES_SHA256']}
(out / 'checkpoint-build-inputs.json').write_text(json.dumps(binding, indent=2))
inputs['prerequisites'](out)
'''

BUILD = r'''
def run(argv, cwd, name):
    with (out / (name + '.log')).open('xb') as log:
        subprocess.run(argv, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
build = out / 'frontend-build'
build.mkdir()
run(binding['configure_argv'], build, 'configure')
for name in ('lib/util', 'lib/protobuf-c', 'src'):
    run(['/usr/bin/make', '-j1', '-C', name, 'sudo' if name == 'src' else 'all'],
        build, 'make-' + name.replace('/', '-'))
binary = build / 'src/.libs/sudo'
assert binary.is_file() and binary.read_bytes().startswith(b'\x7fELF')
with os.fdopen(os.open(out / 'checkpoint-sudo', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o755), 'wb') as f:
    f.write(binary.read_bytes())
# No chmod, set-ID bits or install into an image/host runtime path.
base = ['/usr/bin/cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-static',
        '-I' + str(root / 'src'), '-I/ptw-sudo-gate']
run(base + ['-DPTW_CLOSED_HELPER', '-DPTW_CHECKPOINT_HELPER',
    '/ptw-sudo-gate/linuxarena_sudo_gate.c', str(root / 'src/linuxarena_sudo_child.c'),
    '-o', '/ptw-sudo-gate/closed'], build, 'make-checkpoint-helper')
headers = subprocess.check_output(['/usr/bin/readelf', '-l', '/ptw-sudo-gate/closed'],
    env=env, text=True)
assert 'INTERP' not in headers
print(json.dumps({'helper_static': True, 'frontend_sha256':
    hashlib.sha256(binary.read_bytes()).hexdigest(), 'native_configure_preserved': True}))
'''
