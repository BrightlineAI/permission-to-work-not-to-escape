"""Pinned Ubuntu frontend build inputs; no downloads or package installation.

This stdlib-only file is copied into the fresh offline checkpoint fixture. The
native display is compared with source-derived argv, never parsed as shell input.
"""
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess

RULES_SHA256 = 'b1e04236014887eece5ccc8e96990aa18473062b105f6ace5d48442c85ec7d6b'
PREFIX = (
    '--build=x86_64-linux-gnu', '--prefix=/usr', '--includedir=${prefix}/include',
    '--mandir=${prefix}/share/man', '--infodir=${prefix}/share/info', '--sysconfdir=/etc',
    '--localstatedir=/var', '--disable-option-checking', '--disable-silent-rules',
    '--libdir=${prefix}/lib/x86_64-linux-gnu', '--runstatedir=/run',
    '--disable-maintainer-mode', '--disable-dependency-tracking',
)
ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'LANG': 'C', 'HOME': '/tmp'}
# Versions observed in the hash-bound image, not versions from the worker host.
# Each development package must match its installed runtime library exactly.
REQUIRED = (
    ('libaudit-dev', 'libaudit1', '1:3.0.7-1build1', 'libaudit.h', 'audit',
     'int main(void) { return audit_open(); }'),
    ('libpam0g-dev', 'libpam0g', '1.4.0-11ubuntu2.6', 'security/pam_appl.h', 'pam',
     'int main(void) { pam_handle_t *p = 0; return pam_start("sudo", 0, 0, &p); }'),
    ('libselinux1-dev', 'libselinux1', '3.3-1build2', 'selinux/selinux.h', 'selinux',
     'int main(void) { return is_selinux_enabled(); }'),
    ('zlib1g-dev', 'zlib1g', '1:1.2.11.dfsg-2ubuntu9.2', 'zlib.h', 'z',
     'int main(void) { return zlibVersion() == 0; }'),
)


def configure_arguments(rules, version):
    if not isinstance(rules, bytes) or hashlib.sha256(rules).hexdigest() != RULES_SHA256:
        raise ValueError('Distribution configure rules changed')
    if not isinstance(version, str) or len(version) > 65536 or '\x00' in version:
        raise ValueError('Invalid native configure metadata')
    text = rules.decode('utf-8')
    body = text.split('define CONFIGURE_ARGS\n', 1)[1].split('\nendef', 1)[0]
    additions = re.findall(r'^CONFIGURE_ARGS \+= (.+)$', text, re.MULTILINE)
    # The verified rules select these two branches for the pinned Ubuntu/Linux
    # image. Do not execute make or packaging hooks to evaluate the file.
    args = list(PREFIX) + shlex.split((' '.join([body, *additions])).replace(
        '$(DEB_HOST_MULTIARCH)', 'x86_64-linux-gnu'))
    lines = version.splitlines()
    displayed = [line for line in lines if line.startswith('Configure options:')]
    if (not lines or lines[0] != 'Sudo version 1.9.9' or
            displayed != ['Configure options: ' + ' '.join(args)]):
        raise ValueError('Native configure metadata differs from pinned distribution argv')
    return args


def file_identity(path):
    path = Path(path)
    try:
        return {'path': str(path), 'resolved': str(path.resolve(strict=True)),
                'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    except OSError as exc:
        return {'path': str(path), 'error': type(exc).__name__}


def prerequisites(out):
    """Retain all four header/link probes before rejecting missing inputs.

    Compile/link only: the resulting programs (including PAM/audit calls) are
    never executed. Missing inputs cannot be replaced by successful cache values.
    """
    out = Path(out)
    report = {'schema': 1, 'status': 'incomplete', 'requirements': [], 'tools': {}}
    def command(argv, name, *, source=None):
        record = {'argv': argv}
        log = out / (name + '.log')
        try:
            with log.open('xb') as stream:
                result = subprocess.run(argv, input=source, stdout=stream,
                    stderr=subprocess.STDOUT, env=ENV, cwd=out, timeout=30)
            record['returncode'] = result.returncode
        except (OSError, subprocess.TimeoutExpired) as exc:
            record['error'] = type(exc).__name__
        record['log'] = file_identity(log)
        return record
    try:
        query = command(['/usr/bin/dpkg-query', '-W',
            '-f=${binary:Package}\t${Version}\t${Status}\n'], 'prerequisite-packages')
        report['package_query'] = query
        packages = {}
        if query.get('returncode') == 0:
            for line in (out / 'prerequisite-packages.log').read_text().splitlines():
                name, version, status = line.split('\t')
                name = name.removesuffix(':amd64')
                if name in packages:
                    raise ValueError('Duplicate build package metadata')
                packages[name] = {'version': version, 'status': status}
        for tool in ('cc', 'make', 'ld', 'as'):
            report['tools'][tool] = {'file': file_identity('/usr/bin/' + tool),
                'version': command(['/usr/bin/' + tool, '--version'], 'prerequisite-' + tool)}
        for dev, runtime, version, header, library, program in REQUIRED:
            row = {'development_package': dev, 'runtime_package': runtime,
                   'expected_version': version,
                   'packages': {name: packages.get(name) for name in (dev, runtime)},
                   'header': file_identity('/usr/include/' + header),
                   'library': file_identity('/usr/lib/x86_64-linux-gnu/lib' + library + '.so')}
            report['requirements'].append(row)
            expected = {'version': version, 'status': 'install ok installed'}
            row['inputs_present'] = (all(value == expected for value in row['packages'].values())
                and all('sha256' in row[key] for key in ('header', 'library')))
            if row['inputs_present']:
                row['link_probe'] = command(['/usr/bin/cc', '-x', 'c', '-', '-o',
                    str(out / ('prerequisite-' + library)), '-l' + library],
                    'prerequisite-' + library,
                    source=('#include <' + header + '>\n' + program + '\n').encode())
            row['ready'] = row['inputs_present'] and row['link_probe'].get('returncode') == 0
        report['status'] = ('ready' if query.get('returncode') == 0 and
            all('sha256' in t['file'] and t['version'].get('returncode') == 0
                for t in report['tools'].values()) and
            all(row['ready'] for row in report['requirements']) else 'unavailable')
    except BaseException as exc:
        report['error_type'] = type(exc).__name__
        raise
    finally:
        with (out / 'checkpoint-prerequisites.json').open('x') as stream:
            json.dump(report, stream, indent=2)
    if report['status'] != 'ready':
        raise ValueError('Checkpoint build inputs unavailable; see checkpoint-prerequisites.json')
    return report
