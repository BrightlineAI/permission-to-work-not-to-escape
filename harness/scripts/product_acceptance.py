#!/usr/bin/env python3
"""Private installed-user evidence runner. Run only on the isolated Linux VPS.

Every installed language path uses the same live driver. Missing or failed
evidence remains an explicit failure, never a simulated pass.
"""
import argparse
from contextlib import contextmanager
import http.server
import json
import os
from pathlib import Path
import platform
import re
import sys
import threading
import time
import tomllib
import urllib.request

from evidence_io import artifact, capture, digest, load, reference, require, save
import native_receipt
from product_gate import REPO, IDS, SECURITY, RELEASES, inputs, tree, requirement_evidence, verify
from product_journey import child_environment
from product_projects import CASES, fixture

def fetch(url, path):
    """Retain original bytes, including partial failure, outside the checkout."""
    value = {'url': url, 'complete': False, 'started_epoch': time.time()}
    try:
        with urllib.request.urlopen(url, timeout=30) as response, path.open('xb') as output:
            value['resolved_url'] = response.url
            size = 0
            while chunk := response.read(65536):
                size += len(chunk)
                require(size <= 64 * 1024 * 1024, 'Release download too large')
                output.write(chunk)
                output.flush()
        value['complete'] = True
    except BaseException as exc:
        value['error_type'] = type(exc).__name__
        raise
    finally:
        value['ended_epoch'] = time.time()
        if path.exists():
            value['artifact'] = reference(path.parent, path)
        save(path.with_name(path.name + '.download.json'), value)


def candidate(out, release_tag=None):
    release = out / 'release'
    if release_tag is None:
        result = capture([sys.executable, '-B', REPO / 'harness/scripts/build_product_release.py',
                          '--out', release], out / 'build-process', cwd=out, timeout=300)
        require(result.returncode == 0, 'Candidate build failed; inspect retained build-process')
        build = load(release / 'build.json')
        return {'bootstrap': str(release / 'install.sh'), 'artifact': str(release / build['archive']),
                'sha256': build['archive_sha256'], 'origin': 'local-candidate',
                'provenance': reference(out, release / 'build.json')}
    require(re.fullmatch(r'(harness|ptw)-v[0-9]+\.[0-9]+\.[0-9]+', release_tag), 'Invalid public release tag')
    release.mkdir()
    base = RELEASES + release_tag + '/'
    fetch(base + 'SHA256SUMS', release / 'SHA256SUMS')
    checksums = {}
    for line in (release / 'SHA256SUMS').read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_.-]+)', line)
        require(match is not None and match[2] not in checksums, 'Malformed or duplicate release checksum')
        checksums[match[2]] = match[1]
    version = release_tag.split('-v', 1)[1]
    archive = 'ptw-' + version + '-linux-x86_64.tar.gz'
    require(archive in checksums and 'install.sh' in checksums, 'Exact public candidate assets missing')
    for name in ('install.sh', archive):
        fetch(base + name, release / name)
        require(digest(release / name) == checksums[name], 'Public candidate checksum mismatch')
    return {'bootstrap': str(release / 'install.sh'), 'artifact': str(release / archive),
            'sha256': checksums[archive], 'origin': 'public-release', 'release_tag': release_tag,
            'download_url': base + archive,
            'provenance': reference(out, release / 'SHA256SUMS')}


def record_candidate(out, release, source):
    archive, bootstrap = Path(release['artifact']), Path(release['bootstrap'])
    actual = digest(archive)
    require(actual == release['sha256'], 'Candidate archive changed')
    value = {'source_sha256': source, 'ended_epoch': time.time(),
        'version': tomllib.loads((REPO / 'harness/pyproject.toml').read_text())['project']['version'],
        'origin': release['origin'], 'publication': 'still-required',
        'archive': reference(out, archive), 'bootstrap': reference(out, bootstrap),
        'provenance': release['provenance'],
        'assertions': [{'name': 'candidate archive checksum', 'expected': release['sha256'], 'observed': actual}]}
    if release['origin'] == 'public-release':
        value.update(release_tag=release['release_tag'], downloads=[reference(out, path.with_name(path.name + '.download.json'))
            for path in (out / release['provenance']['path'], bootstrap, archive)])
    save(out / 'candidate-evidence.json', value)
    return reference(out, out / 'candidate-evidence.json')


def map_requirements(out, report):
    """Bind every contract to original records; the gate validates their contents."""
    coverage = {}
    folder = out / 'requirements'
    folder.mkdir()
    for name, refs in requirement_evidence(report).items():
        observed = sum(artifact(out, ref).is_file() for ref in refs)
        save(folder / (name + '.json'), {'contract_ids': [name], 'evidence': refs,
            'source_sha256': report['source_sha256'], 'ended_epoch': time.time(),
            'assertions': [{'name': 'required supporting records retained', 'expected': len(refs), 'observed': observed}]})
        coverage[name] = {'status': 'ready-for-publication' if name == 'release' else 'passed',
                         'records': [reference(out, folder / (name + '.json'))]}
    return coverage


@contextmanager
def installer_artifact(folder, release, profile):
    """Cold fetch versus a verified warm release archive, never a reused app.

    Local candidates use an explicitly labeled loopback transport fixture. Public
    candidates use the exact public URL. Tool and package caches stay cold in both
    profiles because the production installer intentionally isolates them.
    """
    require(profile in ('cold', 'warm'), 'Invalid cache profile')
    artifact = Path(release['artifact'])
    require(digest(artifact) == release['sha256'], 'Candidate changed before installation')
    if profile == 'warm':
        yield [str(artifact)], {'release_archive': reference(folder.parent, artifact),
            'tool_cache': 'empty private cache', 'uv_cache': 'empty private cache', 'npm_cache': 'empty private cache'}
        return
    if release['origin'] == 'public-release':
        require(release.get('download_url', '').startswith(RELEASES + release['release_tag'] + '/'),
                'Cold public installation requires exact candidate URL')
        yield [release['download_url']], {}
        return
    records = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            receipt = {'path': self.path, 'started_epoch': time.time(), 'complete': False}
            try:
                if self.path != '/candidate.tar.gz':
                    self.send_error(404)
                    return
                body = artifact.read_bytes()
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                self.wfile.flush()
                receipt.update(complete=True, bytes=len(body), sha256=digest(artifact))
            finally:
                receipt['ended_epoch'] = time.time()
                records.append(receipt)

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield ['http://127.0.0.1:' + str(server.server_port) + '/candidate.tar.gz', '--test-loopback-http'], {}
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
        save(folder / 'artifact-transport.json', {'kind': 'local-candidate-loopback-fixture', 'requests': records})


def installed_journey(out, release, case):
    """Fresh app, two bounded live rounds, and the full installer-to-ready clock."""
    require(case in CASES, 'Unknown mandatory journey')
    folder = out / case
    folder.mkdir()
    repo = folder / 'repo'
    initial = fixture(repo, case)
    (folder / 'outside.txt').write_text('SYNTHETIC OUTSIDE FIXTURE\n')
    env = child_environment(os.environ)
    root, commands = folder / 'installation', folder / 'commands'
    source = native_receipt.sources(REPO)
    profile = 'cold' if case.startswith('new-') else 'warm'
    config = {'id': case, 'fixture': initial, 'out': str(folder), 'evidence': str(out), 'source_repo': str(REPO),
        'source_sha256': source, 'runtime_sha256': tree(REPO / 'harness'),
        'distribution_inputs_sha256': inputs(REPO), 'cache_profile': profile,
        'preconditions': ['Linux x86_64 developer VPS, active systemd user manager',
            'Python 3.11-3.13, Node22/npm, bubblewrap, curl and Git on PATH',
            'existing operator Codex login and model catalog; browser/MFA external',
            'fresh application root; installer creates empty private uv/npm caches',
            'bootstrap acquisition/build before installer invocation; cold archive transfer inside clock',
            'cache profile concerns release archive only; private uv/npm/tool caches always cold',
            'local candidate archive uses loopback transport fixture; public candidate uses exact release URL',
            'synthetic project and private/outside controls; existing cases include protected legacy functions']}
    with installer_artifact(folder, release, profile) as (arguments, cache):
        started_epoch, started = time.time(), time.monotonic()
        config.update(start_monotonic=started, cache_before=cache)
        save(folder / 'start.json', dict(config, started_epoch=started_epoch, candidate=release))
        result = capture(['bash', release['bootstrap'], '--artifact', *arguments, '--sha256', release['sha256'],
                          '--root', root, '--bin-dir', commands], folder / 'installer', env=env, cwd=folder, timeout=600)
    require(result.returncode == 0, 'Fresh installer failed; retained installer receipt')
    state = load(root / 'state.json')
    install_root = root / 'releases' / state['active']
    config.update(installed_root=str(install_root), ptw=str(commands / 'ptw'))
    save(folder / 'driver.json', config)
    scripts = REPO / 'harness/scripts'
    driver = ('import sys; sys.path.insert(0,sys.argv[1]); '
              'from evidence_io import load; from product_journey import run_journey; '
              'run_journey(load(sys.argv[2]))')
    result = capture([install_root / 'venv/bin/python', '-I', '-B', '-c', driver, scripts, folder / 'driver.json'],
                     folder / 'driver-process', env=child_environment(env, install_root), cwd=folder, timeout=800)
    require(result.returncode == 0, 'Installed live journey failed; inspect original driver/PTY records')
    require(native_receipt.sources(REPO) == source, 'Source changed during journey')
    return load(folder / 'journey.json')


def first_journey(out, release):
    return installed_journey(out, release, 'new-python')


def installed_security(out):
    """Use a retained fresh installation, never the editable source interpreter."""
    config = load(out / 'new-python/driver.json')
    installed_root = Path(config['installed_root'])
    driver = ('import sys; sys.path.insert(0,sys.argv[1]); '
              'from evidence_io import load; from product_security import package_security; '
              'from product_scope import scope_security; '
              'from product_lifecycle import lifecycle_security; '
              'from product_daily_acceptance import git_evidence; '
              'from product_journey import child_environment; import os; '
              'c=load(sys.argv[2]); package_security(c["evidence"],c["source_sha256"]); '
              'scope_security(c["evidence"],c["source_sha256"]); '
              'lifecycle_security(c["evidence"],c["source_sha256"],load(sys.argv[3]),c["ptw"],'
              'child_environment(os.environ,c["installed_root"])); '
              'git_evidence(c["evidence"],c["source_sha256"])')
    result = capture([installed_root / 'venv/bin/python', '-I', '-B', '-c', driver,
                      REPO / 'harness/scripts', out / 'new-python/driver.json', out / 'candidate.json'],
                     out / 'independent-security-process', env=child_environment(os.environ, installed_root),
                     cwd=out, timeout=600)
    require(result.returncode == 0, 'Native independent security failed; inspect retained originals')
    rows = []
    for name in ('package', 'scope', 'lifecycle', 'resume'):
        receipt = load(out / (name + '-security.json'))
        require(receipt['complete'] is True and receipt['source_sha256'] == native_receipt.sources(REPO),
                'Incomplete or changed ' + name + ' security evidence')
        rows.extend(receipt['security_checks'])
    return rows


def acceptance(out, release_tag=None):
    out = Path(out).absolute()
    require(not out.exists() and not out.resolve().is_relative_to(REPO), 'Use a new evidence directory outside checkout')
    out.mkdir(mode=0o700, parents=True)
    report = {'schema': 1, 'started_epoch': time.time(), 'contract_sha256': digest(REPO / 'harness/PRODUCT_ACCEPTANCE.json'),
        'source_sha256': native_receipt.sources(REPO), 'runtime_sha256': tree(REPO / 'harness'),
        'distribution_inputs_sha256': inputs(REPO), 'execution_host': platform.node(), 'simulation': False,
        'real_model': 'gpt-5.6-sol', 'reasoning_effort': 'low', 'journeys': [], 'security_checks': [],
        'requirements': {}, 'unmet_requirements': ['evidence-incomplete'],
        'auth_files_copied': False, 'unknown_vulnerability_guarantee': False}
    save(out / 'attempt.json', report)
    try:
        require(platform.node() == 'algol-box-2' and platform.system() == 'Linux', 'Use the authorized isolated Algol VPS')
        # Fail promptly before paid runs if the existing regression handoff is missing.
        report['native_suite'] = native_receipt.retain(out)
        release = candidate(out, release_tag)
        save(out / 'candidate.json', release)
        report['candidate_record'] = record_candidate(out, release, report['source_sha256'])
        for case in CASES:
            row = installed_journey(out, release, case)
            report['journeys'].append(row)
            report['unmet_requirements'] = sorted(IDS - {r['id'] for r in report['journeys']}) + sorted(SECURITY)
            if any(not r['passed'] for r in report['journeys']):
                report['unmet_requirements'].append('first-setup')
            save(out / 'attempt.json', report)
        try:
            report['security_checks'] = installed_security(out)
        finally:
            report['security_checks'] = [row for name in ('package', 'scope', 'lifecycle', 'resume')
                if (out / (name + '-security.json')).exists()
                for row in load(out / (name + '-security.json'))['security_checks']]
            report['unmet_requirements'] = sorted(SECURITY - {r['id'] for r in report['security_checks']})
            report['unmet_requirements'].append('contract-mappings')
            if any(not r['passed'] for r in report['journeys']):
                report['unmet_requirements'].append('first-setup')
            save(out / 'attempt.json', report)
        report['local_git'] = load(out / 'local-git.json')
        report['requirements'] = map_requirements(out, report)
        report['unmet_requirements'] = [] if all(r['passed'] for r in report['journeys']) else ['first-setup']
        report['ended_epoch'] = time.time()
        save(out / 'completion-evidence.json', report)
        # This also rechecks the native handoff and every retained installation.
        # Exit zero means candidate readiness, never publication or final completion.
        result = verify(out)
        save(out / 'gate.json', result)
        return result
    except BaseException as exc:
        report['error'] = type(exc).__name__ + ': ' + str(exc)
        if not report['unmet_requirements']:
            report['unmet_requirements'] = ['evidence-validation']
        raise
    finally:
        if 'ended_epoch' not in report or 'error' in report:
            report['ended_epoch'] = time.time()
        save(out / 'completion-evidence.json', report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--release-tag')
    args = parser.parse_args()
    try:
        acceptance(args.out, args.release_tag)
    except (ValueError, OSError) as exc:
        print(json.dumps({'passed': False, 'error': str(exc)}), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
