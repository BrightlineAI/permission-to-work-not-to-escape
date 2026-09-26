"""Credential-free wheel metadata view for native uv, not a version solver."""
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import secrets
import threading
import time
from urllib.parse import quote, unquote

from packaging.utils import canonicalize_name, parse_wheel_filename

from .package_evidence import EvidenceError, timestamp


class WheelIndex:
    """Only broker-fetched wheels, bounded requests and no upstream credentials.

    Native tools can inspect wheel metadata but cannot request a source archive
    or choose a destination URL. Final candidate assessment remains separate.
    """
    def __init__(self, provider, stage, deadline):
        self.provider, self.stage, self.deadline = provider, Path(stage), deadline
        self.error, self.requests, self.downloaded = None, 0, 0
        self.documents, self.artifacts = {}, {}

    def budget(self):
        self.requests += 1
        if self.requests > 512 or time.monotonic() >= self.deadline:
            raise EvidenceError('Python metadata view budget exhausted')

    def document(self, name):
        self.budget()
        if canonicalize_name(name, validate=True) != name:
            raise EvidenceError('Python index requires a canonical package name')
        if name in self.documents:
            return self.documents[name]
        if len(self.documents) >= 256:
            raise EvidenceError('Python index package budget exhausted')
        source = self.provider.index(name)
        if (not isinstance(source, dict) or not isinstance(source.get('meta'), dict) or
                not str(source['meta'].get('api-version', '')).startswith('1.') or
                canonicalize_name(source.get('name', ''), validate=True) != name or
                not isinstance(source.get('files'), list) or len(source['files']) > 20000):
            raise EvidenceError('Malformed Python index listing')
        files, versions, seen = [], set(), set()
        for item in source['files']:
            if not isinstance(item, dict) or not isinstance(item.get('filename'), str):
                raise EvidenceError('Malformed Python artifact')
            filename = item['filename']
            if not filename.endswith('.whl') or item.get('yanked', False) is not False:
                continue
            if Path(filename).name != filename or '\\' in filename:
                raise EvidenceError('Unsafe Python wheel filename')
            wheel_name, wheel_version, _, _ = parse_wheel_filename(filename)
            if not isinstance(item.get('hashes'), dict):
                raise EvidenceError('Missing Python artifact digest')
            sha = item['hashes'].get('sha256')
            if (wheel_name != name or filename in seen or
                    not isinstance(sha, str) or len(sha) != 64 or any(c not in '0123456789abcdef' for c in sha) or
                    not self.provider.artifact_allowed(item.get('url', ''), name)):
                raise EvidenceError('Python index artifact identity mismatch')
            timestamp(item.get('upload-time'))
            size = item.get('size')
            requires = item.get('requires-python')
            if type(size) is not int or not 0 <= size <= 128 * 1024 * 1024 or (requires is not None and not isinstance(requires, str)):
                raise EvidenceError('Malformed Python wheel size or runtime constraint')
            seen.add(filename)
            version = str(wheel_version)
            versions.add(version)
            key = hashlib.sha256((name + ':' + filename + ':' + sha).encode()).hexdigest()
            self.artifacts[key] = {'name': name, 'version': version, 'filename': filename,
                'url': item['url'], 'sha256': sha, 'size': size}
            files.append({'filename': filename, 'url': '../../files/' + key + '/' + quote(filename),
                'hashes': {'sha256': sha}, 'size': size, 'upload-time': item['upload-time'],
                'requires-python': requires, 'yanked': False})
            if len(self.artifacts) > 20000:
                raise EvidenceError('Python index artifact budget exhausted')
        document = {'meta': {'api-version': '1.1'}, 'name': name, 'versions': sorted(versions), 'files': files}
        if len(json.dumps(document).encode()) > 16 * 1024 * 1024:
            raise EvidenceError('Python index document exceeds limit')
        self.documents[name] = document
        return document

    def artifact(self, key, filename):
        self.budget()
        record = self.artifacts.get(key)
        if record is None or record['filename'] != filename:
            raise EvidenceError('Unknown Python artifact route')
        destination = self.stage / key
        if not destination.exists():
            if self.downloaded + record['size'] > 512 * 1024 * 1024:
                raise EvidenceError('Python index download budget exhausted')
            self.provider.download(record, destination)
            self.downloaded += destination.stat().st_size
        raw = destination.read_bytes()
        if (len(raw) != record['size'] or hashlib.sha256(raw).hexdigest() != record['sha256'] or
                self.downloaded > 512 * 1024 * 1024):
            raise EvidenceError('Python index artifact changed or exceeded size')
        return raw

    def __enter__(self):
        self.stage.mkdir(parents=True, exist_ok=False)
        view, prefix = self, '/' + secrets.token_hex(24) + '/'

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.respond(head=False)

            def do_HEAD(self):
                # uv probes wheel headers before requesting metadata. Use the
                # same checked bytes and routes as GET, with no response body.
                self.respond(head=True)

            def respond(self, *, head):
                try:
                    if not self.path.startswith(prefix) or '?' in self.path or len(self.path) > 4096:
                        self.send_error(404)
                        return
                    parts = self.path[len(prefix):].split('/')
                    if len(parts) == 3 and parts[0] == 'simple' and parts[2] == '':
                        raw = json.dumps(view.document(unquote(parts[1]))).encode()
                        content_type = 'application/vnd.pypi.simple.v1+json'
                    elif len(parts) == 3 and parts[0] == 'files':
                        raw = view.artifact(parts[1], unquote(parts[2]))
                        content_type = 'application/octet-stream'
                    else:
                        self.send_error(404)
                        return
                    self.send_response(200)
                    self.send_header('Content-Type', content_type)
                    self.send_header('Content-Length', str(len(raw)))
                    self.send_header('Accept-Ranges', 'none')
                    self.end_headers()
                    if not head:
                        self.wfile.write(raw)
                except (ValueError, TypeError, KeyError, AttributeError, OSError, EvidenceError):
                    view.error = 'Python metadata or artifact unavailable'
                    self.send_error(502, view.error)

        self.server = HTTPServer(('127.0.0.1', 0), Handler)
        self.server.timeout = 1
        # These views are short-lived. serve_forever ignores server.timeout;
        # its default poll would delay every idle shutdown by up to 0.5s.
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={'poll_interval': .05}, daemon=True)
        self.thread.start()
        return 'http://127.0.0.1:' + str(self.server.server_port) + prefix + 'simple/'

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=16)
