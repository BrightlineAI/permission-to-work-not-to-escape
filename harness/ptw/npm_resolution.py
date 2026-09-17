"""Native npm compatibility resolution over a bounded, filtered metadata view."""
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import threading
import time
from urllib.parse import unquote

from .dependency_resolution import ResolutionError, resolver_environment, run_metadata
from .npm import DEPENDENCIES, NAME, NpmEvidence, NpmPlan
from .package_evidence import EvidenceError, evaluate
from .policy import Invalid, load, parse_json, save


def local_path(parent, value):
    """Normalize sibling references without ever leaving the project root."""
    from .workspace_policy import relative
    if not isinstance(value, str) or not value or value.startswith('/') or '\\' in value:
        raise Invalid('Local dependency must be an in-project relative path')
    parts = list(Path(parent).parts) if parent else []
    for part in value.split('/'):
        if part == '..':
            if not parts:
                raise Invalid('Local dependency escapes project root')
            parts.pop()
        elif part not in ('', '.'):
            parts.append(part)
    return relative('/'.join(parts))


def declarations(manifest, *, local_paths=(), parent=''):
    if not isinstance(manifest, dict):
        raise Invalid('Expected package.json object')
    clean = {k: manifest[k] for k in ('name', 'version', 'private') if k in manifest}
    for field in DEPENDENCIES:
        value = manifest.get(field, {})
        if not isinstance(value, dict):
            raise Invalid('Expected npm dependency maps')
        for name, spec in value.items():
            local = isinstance(spec, str) and spec.startswith('file:') and local_path(parent, spec[5:]) in local_paths
            if (not isinstance(name, str) or not re.fullmatch(NAME, name) or
                    not isinstance(spec, str) or len(spec) > 1000 or
                    not (local or re.fullmatch(r'[A-Za-z0-9.*<>=~^|+ -]+', spec))):
                raise Invalid('npm resolution requires registry version ranges; source dependencies need source approval')
        if field in manifest:
            clean[field] = value
    if 'peerDependenciesMeta' in manifest:
        value = manifest['peerDependenciesMeta']
        if not isinstance(value, dict) or any(not isinstance(v, dict) or set(v) - {'optional'} or
                ('optional' in v and type(v['optional']) is not bool) for v in value.values()):
            raise Invalid('Malformed npm peer metadata')
        clean['peerDependenciesMeta'] = value
    return clean


def node_inputs(root):
    """Bounded workspace globs and in-tree file dependencies, metadata only."""
    from .onboarding import data
    from .workspace_policy import directory_fd, relative
    import os
    root = Path(root)
    manifests, inputs, pending = {}, {}, ['']
    while pending:
        folder = pending.pop(0)
        if folder in manifests:
            continue
        if len(manifests) >= 64:
            raise Invalid('Too many npm source manifests')
        # data() protects the basename. Validate every parent before opening it;
        # a lexical in-tree path must not read metadata through a symlink.
        fd = directory_fd(root / folder)
        os.close(fd)
        name = str(Path(folder) / 'package.json')
        raw = data(root / name)
        manifest = parse_json(raw)
        if not isinstance(manifest, dict):
            raise Invalid('Expected npm source manifest object')
        manifests[folder] = manifest
        inputs[name] = hashlib.sha256(raw.encode()).hexdigest()
        if not folder:
            workspaces = manifest.get('workspaces', [])
            if not isinstance(workspaces, list) or len(workspaces) > 64:
                raise Invalid('npm workspaces must be a bounded path list')
            for pattern in workspaces:
                relative(pattern)
                if '**' in pattern or any(c in pattern for c in ('?', '[', ']', '!', '{', '}')):
                    raise Invalid('Supported workspace globs use only single directory wildcards')
                for count, path in enumerate(root.glob(pattern)):
                    if count >= 64:
                        raise Invalid('Too many workspace matches')
                    if not path.is_dir() or path.is_symlink():
                        raise Invalid('Workspace must be a confined ordinary directory')
                    pending.append(str(path.relative_to(root)))
        for field in DEPENDENCIES:
            dependencies = manifest.get(field, {})
            if not isinstance(dependencies, dict):
                raise Invalid('Malformed npm source dependency map')
            for spec in dependencies.values():
                if isinstance(spec, str) and spec.startswith('file:'):
                    pending.append(local_path(folder, spec[5:]))
    local_paths = set(manifests) - {''}
    for path, manifest in manifests.items():
        declarations(manifest, local_paths=local_paths, parent=path)
    return manifests, inputs


class MetadataView:
    """Only sanitized package documents. Never forwards headers, URLs or credentials.

    Native npm remains the solver. An exclusion removes one confirmed forbidden
    version; it never rewrites a dependency range or supplies an override.
    """
    def __init__(self, provider, excluded, deadline):
        self.provider, self.excluded, self.deadline = provider, excluded, deadline
        self.error, self.requests = None, 0
        self.cache = {}

    def document(self, name):
        if not re.fullmatch(NAME, name):
            raise EvidenceError('Metadata route is not a package identity')
        if time.monotonic() >= self.deadline:
            raise EvidenceError('Metadata deadline reached')
        self.requests += 1
        if self.requests > 256:
            raise EvidenceError('Metadata request budget exhausted')
        if name not in self.cache:
            document = self.provider.packument(name)
            if (not isinstance(document, dict) or not isinstance(document.get('versions'), dict) or
                    len(document['versions']) > 10000 or not isinstance(document.get('time'), dict)):
                raise EvidenceError('Malformed npm registry document')
            self.cache[name] = document
        original = self.cache[name]
        versions, times = {}, {}
        for version, record in original['versions'].items():
            if (name, version) in self.excluded:
                continue
            if (not isinstance(record, dict) or record.get('name') != name or record.get('version') != version):
                raise EvidenceError('Registry metadata identity mismatch')
            fields = declarations(record)
            dist = record.get('dist', {})
            if not isinstance(dist, dict) or not isinstance(dist.get('integrity'), str):
                raise EvidenceError('Missing npm artifact integrity')
            if not self.provider.artifact_allowed(dist.get('tarball', ''), name):
                raise EvidenceError('Unapproved npm artifact origin')
            fields['dist'] = {'tarball': dist['tarball'], 'integrity': dist['integrity']}
            for key in ('engines', 'os', 'cpu', 'libc', 'bin'):
                if key in record:
                    fields[key] = record[key]
            fields['hasInstallScript'] = bool(record.get('hasInstallScript') or any(
                k in record.get('scripts', {}) for k in ('preinstall', 'install', 'postinstall')))
            versions[version] = fields
            if version in original['time']:
                times[version] = original['time'][version]
        tags = original.get('dist-tags', {})
        if not isinstance(tags, dict):
            raise EvidenceError('Malformed npm dist-tags')
        # npm chooses a compatible version if latest has been excluded; other
        # explicitly requested tags cannot silently become a different tag.
        tags = {k: v for k, v in tags.items() if isinstance(k, str) and v in versions}
        return {'name': name, 'versions': versions, 'time': times, 'dist-tags': tags}

    def __enter__(self):
        view, prefix = self, '/' + secrets.token_hex(24) + '/'

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                try:
                    if not self.path.startswith(prefix) or '?' in self.path or len(self.path) > 4096:
                        self.send_error(404)
                        return
                    body = json.dumps(view.document(unquote(self.path[len(prefix):]))).encode()
                    if len(body) > 16 * 1024 * 1024:
                        raise EvidenceError('Metadata response exceeds limit')
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except (ValueError, TypeError, KeyError, Invalid) as exc:
                    view.error = 'Metadata unavailable: ' + type(exc).__name__
                    self.send_error(502, 'Metadata unavailable')

        self.server = HTTPServer(('127.0.0.1', 0), Handler)
        self.server.timeout = 1
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return 'http://127.0.0.1:' + str(self.server.server_port) + prefix

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=16)


def resolve_npm(root, stage, rules, *, provider=None, runner=None, view_factory=MetadataView,
                update=False, max_rounds=8, max_assessments=256, seconds=180):
    """Import an exact lock or resolve ranges without weakening their meaning."""
    from .onboarding import data
    root, stage = Path(root), Path(stage)
    stage.mkdir(parents=True, exist_ok=True)
    started, attempts, outcome = time.monotonic(), [], 'invalid'
    inputs, records, cache, excluded = {}, [], {}, set()
    try:
        if (type(max_rounds) is not int or not 1 <= max_rounds <= 8 or
                type(max_assessments) is not int or not 1 <= max_assessments <= 256 or
                not isinstance(seconds, (int, float)) or not 0 < seconds <= 180):
            raise Invalid('Resolution budgets may only narrow the fixed limits')

        def read(name):
            content = data(root / name, 8 * 1024 * 1024)
            inputs[name] = hashlib.sha256(content.encode()).hexdigest()
            return content

        manifests, inputs = node_inputs(root)
        original = manifests['']
        local_paths = set(manifests) - {''}
        manifest = declarations(original, local_paths=local_paths)
        if original.get('workspaces'):
            manifest['workspaces'] = original['workspaces']
        if (root / 'pnpm-lock.yaml').exists():
            raise Invalid('pnpm authoritative lock requires the native pnpm adapter')
        yarn = None
        if (root / 'yarn.lock').exists() and not (root / 'package-lock.json').exists():
            yarn = read('yarn.lock')
            if '# yarn lockfile v1' not in yarn[:200] or '__metadata:' in yarn:
                raise Invalid('Only Yarn Classic v1 can be imported by npm; Berry/PnP needs its own adapter')
        resolved = parse_json(read('package-lock.json')) if (root / 'package-lock.json').exists() else None
        if resolved is not None:
            if (not isinstance(resolved, dict) or resolved.get('lockfileVersion') not in (2, 3) or
                    not isinstance(resolved.get('packages'), dict) or not isinstance(resolved['packages'].get(''), dict)):
                raise Invalid('Malformed npm lock')
            if manifest.get('workspaces', []) != resolved['packages'][''].get('workspaces', []):
                raise Invalid('package.json and package-lock.json workspaces disagree')
            for field in (*DEPENDENCIES, 'peerDependenciesMeta'):
                if manifest.get(field, {}) != resolved['packages'].get('', {}).get(field, {}):
                    if not update:
                        raise Invalid('package.json and package-lock.json disagree; review a native lock update')
            if resolved['packages'].keys() == {''} and not local_paths and not any(manifest.get(k) for k in DEPENDENCIES):
                resolved = None
        if resolved is None and not local_paths and not any(manifest.get(k) for k in DEPENDENCIES):
            outcome = 'resolved'
            return {'lock': None, 'inputs': inputs, 'artifacts': [], 'attempts': attempts}
        if resolved is not None:
            NpmPlan(resolved)
        provider = provider or NpmEvidence()
        if isinstance(provider, NpmEvidence):
            provider.deadline = started + seconds
        cutoff = datetime.fromtimestamp(time.time() - rules['min_release_age_days'] * 86400, timezone.utc).isoformat()
        npm = shutil.which('npm')
        if not npm:
            raise ResolutionError('unavailable', 'Node/npm are missing')
        save(stage / 'resolver-tool.json', {'path': str(Path(npm).resolve()),
            'sha256': hashlib.sha256(Path(npm).resolve().read_bytes()).hexdigest(), 'inputs': inputs,
            'cutoff': cutoff})
        frozen = resolved is not None and not update
        for index in range(max_rounds):
            if time.monotonic() >= started + seconds:
                raise ResolutionError('budget_exhausted', 'npm resolution deadline reached')
            attempt = {'round': index + 1, 'excluded': sorted([list(x) for x in excluded]), 'outcome': 'running'}
            attempts.append(attempt)
            if resolved is None or update or index:
                folder = stage / ('round-' + str(index + 1))
                folder.mkdir()
                save(folder / 'package.json', manifest)
                for path in sorted(local_paths):
                    save(folder / path / 'package.json', declarations(manifests[path], local_paths=local_paths, parent=path))
                if resolved is not None and not excluded:
                    save(folder / 'package-lock.json', resolved)
                if yarn is not None and not excluded:
                    (folder / 'yarn.lock').write_text(yarn)
                view = view_factory(provider, excluded, started + seconds)
                with view as endpoint:
                    argv = [npm, 'install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund',
                        '--before=' + cutoff, '--registry=' + endpoint, '--userconfig=/dev/null',
                        '--globalconfig=' + str(folder / 'empty-global'), '--cache=' + str(folder / 'cache'),
                        '--fetch-retries=0', '--fetch-timeout=' + str(max(1, int((started + seconds - time.monotonic()) * 1000)))]
                    try:
                        proc = (runner or run_metadata)(argv, cwd=folder, env=resolver_environment(folder),
                            capture_output=True, text=True, timeout=max(.001, started + seconds - time.monotonic()))
                    except subprocess.TimeoutExpired as exc:
                        raise ResolutionError('budget_exhausted', 'native npm timed out') from exc
                attempt['returncode'] = proc.returncode
                if view.error:
                    raise EvidenceError(view.error)
                if proc.returncode:
                    attempt['stderr_sha256'] = hashlib.sha256(proc.stderr.encode()).hexdigest()
                    conflict = any('code ' + code in proc.stderr for code in ('ETARGET', 'ERESOLVE'))
                    raise ResolutionError('unsatisfiable' if conflict else 'unavailable',
                        'Native npm could not resolve the original declarations under policy')
                resolved = parse_json(data(folder / 'package-lock.json', 8 * 1024 * 1024))
            plan = NpmPlan(resolved)
            if set(plan.locals) != local_paths:
                raise Invalid('npm lock local sources differ from reviewed source manifests')
            for path in local_paths:
                source = manifests[path]
                entry = plan.locals[path]
                for field in ('name', 'version', *DEPENDENCIES, 'peerDependenciesMeta'):
                    if source.get(field, {} if field in (*DEPENDENCIES, 'peerDependenciesMeta') else None) != entry.get(
                            field, {} if field in (*DEPENDENCIES, 'peerDependenciesMeta') else None):
                        raise Invalid('npm source manifest and lock disagree: ' + path)
            for field in (*DEPENDENCIES, 'peerDependenciesMeta'):
                if manifest.get(field, {}) != resolved['packages'][''].get(field, {}):
                    raise Invalid('Native npm output changed original dependency declarations')
            rejected, records = set(), []
            for identity, version in plan.selected.items():
                name = identity.rsplit('@', 1)[0]
                key = name, version
                if key not in cache:
                    if len(cache) >= max_assessments or time.monotonic() >= started + seconds:
                        raise ResolutionError('budget_exhausted', 'npm candidate budget exhausted')
                    cache[key] = provider.assess(name, version)
                if time.monotonic() >= started + seconds:
                    raise ResolutionError('budget_exhausted', 'npm evidence deadline reached')
                record = cache[key]
                if record.get('name') != name or record.get('version') != version:
                    raise EvidenceError('Candidate evidence identity mismatch')
                if evaluate(record, rules):
                    rejected.add(key)
                records.append(record)
            plan.bind_evidence(records)
            attempt['selected'] = plan.selected
            attempt['rejected'] = sorted([list(x) for x in rejected])
            if not rejected:
                outcome = attempt['outcome'] = 'resolved'
                return {'lock': resolved, 'inputs': inputs, 'artifacts': [
                    {k: e[k] for k in ('name', 'version', 'url', 'integrity')} for e in records],
                    'attempts': attempts, 'authority': 'npm', 'sources': sorted(local_paths),
                    'migration': 'yarn-v1' if yarn else None}
            attempt['outcome'] = 'policy_exclusion'
            if frozen:
                raise ResolutionError('unsatisfiable', 'Frozen npm lock violates policy; explicitly review a native lock update')
            if rejected <= excluded:
                raise ResolutionError('unsatisfiable', 'Native npm retained an excluded version')
            excluded |= rejected
        raise ResolutionError('budget_exhausted', 'npm candidate retry limit reached')
    except ResolutionError as exc:
        outcome = exc.outcome
        raise
    except EvidenceError:
        outcome = 'unavailable_evidence'
        raise
    finally:
        if attempts and attempts[-1]['outcome'] == 'running':
            attempts[-1]['outcome'] = outcome
        save(stage / 'resolution.json', {'outcome': outcome, 'inputs': inputs, 'attempts': attempts,
            'elapsed_seconds': time.monotonic() - started})
