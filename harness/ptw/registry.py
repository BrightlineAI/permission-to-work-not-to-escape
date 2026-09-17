"""Operator-configured npm origins. Upstream credentials exist only in this broker."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from urllib.parse import quote, urlsplit
from urllib.request import Request

from .npm import NAME, NpmEvidence
from .package_evidence import EvidenceError, PyPIEvidence, index_urls
from .policy import Invalid, data_directory, parse_json


def provider_for(store, bundle, ecosystem='npm'):
    from .policy import digest
    if ecosystem not in ('npm', 'pypi'):
        raise Invalid('Unknown registry ecosystem')
    project = bundle['policy']['project']
    options = {} if ecosystem == 'npm' else {
        'native': project['packages'].get('allow_native_wheels', False),
        'sources': [x[5:] for x in project['packages'].get('build_packages', []) if x.startswith('pypi:')],
        'python': project.get('python_runtime', {}).get('executable', '/usr/bin/python3')}
    identity = project.get('npm_dependencies' if ecosystem == 'npm' else 'python_dependencies', {}).get('registry_config_sha256')
    if not identity:
        return NpmEvidence() if ecosystem == 'npm' else PyPIEvidence(**options)
    config = private_json(store.directory / (ecosystem + '-registry-' + identity + '.json'))
    if digest(config) != identity:
        raise EvidenceError('Private registry configuration differs from its approval')
    outside_repository(config, bundle['inventory']['root'])
    return RoutedNpmEvidence(config) if ecosystem == 'npm' else RoutedPyPIEvidence(config, **options)


def credential_path(value):
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise Invalid('Credential references must be absolute paths')
    path = Path(value)
    # Same-user workers can read even owner-only files in runtime mounts.
    data_directory(path)
    from .dependency_resolution import METADATA_HOST_PATHS
    from .supervisor import RUNTIME_HOST_PATHS
    # Metadata tools add network configuration to the shared build/runtime
    # namespace. Check both spellings and resolved sources, including mounts
    # redirected to an otherwise valid data directory by host symlinks.
    resolved = path.resolve()
    for source in (*RUNTIME_HOST_PATHS, *METADATA_HOST_PATHS):
        for exposed in (Path(source), Path(source).resolve()):
            if path.is_relative_to(exposed) or resolved.is_relative_to(exposed):
                raise Invalid('Credential references must be outside resolver and build host mounts')
    return path


def outside_repository(config, root):
    root = Path(root).resolve()
    if not isinstance(config, dict) or not isinstance(config.get('packages'), dict):
        raise Invalid('Malformed private registry configuration')
    for route in config['packages'].values():
        if not isinstance(route, dict) or not isinstance(route.get('credential_ref'), str):
            raise Invalid('Expected an external credential reference')
        path = credential_path(route['credential_ref'])
        if path.resolve().is_relative_to(root):
            raise Invalid('Credential references must be absolute and outside project source')


def origin(value, *, fixture=False):
    try:
        endpoint = urlsplit(value)
        if (not endpoint.hostname or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment or
                endpoint.path not in ('', '/') or
                not (endpoint.scheme == 'https' or (fixture and endpoint.scheme == 'http' and endpoint.hostname == '127.0.0.1'))):
            raise ValueError()
        endpoint.port  # Reject malformed ports.
    except (TypeError, ValueError) as exc:
        raise Invalid('Registry and advisory origins must be credential-free HTTPS origins') from exc
    return value.rstrip('/')


def private_json(path):
    """A trusted operator file, never an agent-supplied filename or repository input."""
    from .workspace_policy import directory_fd
    path = Path(path).absolute()
    parent = directory_fd(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
    finally:
        os.close(parent)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or
                info.st_mode & 0o077 or info.st_size > 65536):
            raise Invalid('Registry configuration and credential references must be private owned regular files')
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise Invalid('Registry configuration exceeds limit')
    try:
        return parse_json(raw)
    except (ValueError, TypeError):
        raise Invalid('Malformed private configuration JSON') from None


class RoutedNpmEvidence(NpmEvidence):
    """Exact private-name routing; public OSV is never evidence for a private name.

    Private advisory service contract: an exact origin/name/version envelope
    with explicit complete coverage and standard OSV vulnerability records.
    Redirects and ambient proxies remain disabled by the base transport.
    """
    def __init__(self, config, *, fixture=False):
        super().__init__()
        if not isinstance(config, dict) or set(config) != {'version', 'packages'} or config['version'] != 1:
            raise Invalid('Expected version 1 private registry configuration')
        packages = config['packages']
        if not isinstance(packages, dict) or not 1 <= len(packages) <= 256:
            raise Invalid('Configure 1 to 256 exact private package names')
        self.routes = {}
        for name, route in packages.items():
            if not re.fullmatch(NAME, name) or not isinstance(route, dict) or set(route) != {
                    'registry', 'advisories', 'credential_ref'}:
                raise Invalid('Private routes require exact name, registry, advisories and credential_ref')
            registry, advisories = (origin(route[k], fixture=fixture) for k in ('registry', 'advisories'))
            credentials = private_json(credential_path(route['credential_ref']))
            if (not isinstance(credentials, dict) or set(credentials) != {'authorization'} or
                    not isinstance(credentials['authorization'], str) or
                    not 1 <= len(credentials['authorization']) <= 8192 or
                    any(ord(c) < 32 or ord(c) > 126 for c in credentials['authorization'])):
                raise Invalid('Credential reference must contain a bounded authorization header')
            self.routes[name] = {'registry': registry, 'advisories': advisories,
                                 'authorization': credentials['authorization']}

    def _request(self, route, endpoint, *, data=None, limit=16 * 1024 * 1024, accept=None):
        parsed = urlsplit(endpoint)
        base = parsed.scheme + '://' + parsed.netloc
        if (base not in (route['registry'], route['advisories']) or parsed.username or parsed.password or parsed.fragment):
            raise EvidenceError('Private request escaped its configured origin')
        remaining = self.deadline - time.monotonic() if self.deadline is not None else 15
        if remaining <= 0:
            raise EvidenceError('Private evidence deadline reached')
        headers = {'Content-Type': 'application/json', 'User-Agent': 'permission-to-work'}
        if accept:
            headers['Accept'] = accept
        if base == route['registry']:
            headers['Authorization'] = route['authorization']
        request = Request(endpoint, data=json.dumps(data).encode() if data is not None else None, headers=headers)
        try:
            with self.http.open(request, timeout=min(15, remaining)) as response:
                raw = response.read(limit + 1)
            if len(raw) > limit or (self.deadline is not None and time.monotonic() >= self.deadline):
                raise EvidenceError('Private response exceeded its budget')
            # Even an upstream error/echo must not put the credential into an
            # export, evidence receipt, native resolver or model-facing output.
            if any(value.encode() in raw for value in (route['authorization'], route['authorization'].split()[-1])):
                raise EvidenceError('Private response contains credential material')
            return raw
        except Exception:
            # Do not include HTTP bodies, exception strings, response headers or
            # chained exceptions that could echo the authorization header.
            raise EvidenceError('Private evidence or artifact unavailable') from None

    def packument(self, name):
        route = self.routes.get(name)
        if route is None:
            return super().packument(name)
        return self._json(route, self._request(route, route['registry'] + '/' + quote(name, safe='')))

    @staticmethod
    def _json(route, raw):
        try:
            value = parse_json(raw)
            normalized = json.dumps(value, ensure_ascii=False)
            if any(v in normalized for v in (route['authorization'], route['authorization'].split()[-1])):
                raise ValueError()
            return value
        except (ValueError, TypeError):
            raise EvidenceError('Invalid private evidence JSON') from None

    def artifact_allowed(self, url, name):
        route = self.routes.get(name)
        if route is None:
            return super().artifact_allowed(url, name)
        parsed = urlsplit(url)
        return (parsed.scheme + '://' + parsed.netloc == route['registry'] and
                not parsed.username and not parsed.password and not parsed.fragment and not parsed.query)

    def advisories(self, ecosystem, name, version):
        route = self.routes.get(name)
        if route is None:
            return super().advisories(ecosystem, name, version)
        query = {'origin': route['registry'], 'package': {'ecosystem': ecosystem, 'name': name}, 'version': version}
        record = self._json(route, self._request(route, route['advisories'] + '/v1/query', data=query))
        if (not isinstance(record, dict) or record.get('origin') != route['registry'] or
                record.get('name') != name or record.get('version') != version or
                record.get('coverage') != 'complete' or not isinstance(record.get('vulns'), list)):
            raise EvidenceError('Private advisory origin, identity or complete coverage is missing')
        return record['vulns']

    def download(self, evidence, destination):
        route = self.routes.get(evidence['name'])
        if route is None:
            return super().download(evidence, destination)
        if not self.artifact_allowed(evidence['url'], evidence['name']):
            raise EvidenceError('Private artifact origin mismatch')
        raw = self._request(route, evidence['url'], limit=128 * 1024 * 1024)
        if 'sha512-' + base64.b64encode(hashlib.sha512(raw).digest()).decode() != evidence['integrity']:
            raise EvidenceError('Private artifact integrity mismatch')
        evidence['sha256'] = hashlib.sha256(raw).hexdigest()
        with destination.open('xb') as stream:
            stream.write(raw)


class RoutedPyPIEvidence(PyPIEvidence):
    """PyPI JSON compatible private origins, with exact names and no public fallback."""
    _request = RoutedNpmEvidence._request
    _json = staticmethod(RoutedNpmEvidence._json)

    def __init__(self, config, *, fixture=False, **options):
        from packaging.utils import canonicalize_name
        if not isinstance(config, dict) or not isinstance(config.get('packages'), dict):
            raise Invalid('Malformed Python registry routes')
        for name in config['packages']:
            try:
                if canonicalize_name(name, validate=True) != name:
                    raise ValueError()
            except (TypeError, ValueError):
                raise Invalid('Python registry routes require canonical package names') from None
        # Reuse the same private-file, origin, header and echo validation.
        routed = RoutedNpmEvidence(config, fixture=fixture)
        super().__init__(**options)
        self.routes = routed.routes

    def release(self, name, version=None):
        route = self.routes.get(name)
        if route is None:
            return super().release(name, version)
        return self._json(route, self._request(route, route['registry'] + '/pypi/' +
            quote(name, safe='') + ('/' + quote(version, safe='') if version else '') + '/json'))

    def index(self, name):
        route = self.routes.get(name)
        if route is None:
            return super().index(name)
        endpoint = route['registry'] + '/simple/' + quote(name, safe='') + '/'
        return index_urls(self._json(route, self._request(route, endpoint,
            accept='application/vnd.pypi.simple.v1+json')), endpoint)

    def artifact_allowed(self, url, name):
        if name not in self.routes:
            return super().artifact_allowed(url, name)
        return RoutedNpmEvidence.artifact_allowed(self, url, name)

    def advisories(self, ecosystem, name, version):
        if name not in self.routes:
            return super().advisories(ecosystem, name, version)
        return RoutedNpmEvidence.advisories(self, 'PyPI', name, version)

    def assess(self, name, version):
        record = super().assess(name, version)
        if name in self.routes:
            record['source'] = 'Private PyPI-compatible release JSON and origin-bound advisory coverage'
            record['origin'] = self.routes[name]['registry']
        return record

    def download(self, evidence, destination):
        if evidence['name'] not in self.routes:
            return super().download(evidence, destination)
        if not self.artifact_allowed(evidence['url'], evidence['name']):
            raise EvidenceError('Private Python artifact origin mismatch')
        raw = self._request(self.routes[evidence['name']], evidence['url'], limit=128 * 1024 * 1024)
        if hashlib.sha256(raw).hexdigest() != evidence['sha256']:
            raise EvidenceError('Private Python artifact digest mismatch')
        with destination.open('xb') as stream:
            stream.write(raw)
