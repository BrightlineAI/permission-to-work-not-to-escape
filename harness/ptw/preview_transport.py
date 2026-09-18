"""Fixed-target HTTP preview over pipes. Standard library only, also run in bwrap.

The outer process owns one loopback listener and never connects to a network
destination. The inner process can reach only its isolated network namespace.
Application stdout/stderr cannot become the framing protocol or fill host logs.
"""
import base64
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import threading
import time
from urllib.parse import unquote, urlsplit

BODY_LIMIT = 2 * 1024 * 1024
FRAME_LIMIT = 3 * 1024 * 1024
REQUEST_SECONDS = 5
START_SECONDS = 10


def origin_path(value):
    if not isinstance(value, str) or not value.startswith('/') or len(value) > 4096:
        raise ValueError('Expected a bounded origin-relative HTTP path')
    for candidate in (value, unquote(value)):
        if (candidate.startswith('//') or '\\' in candidate or
                any(ord(c) < 32 or ord(c) > 126 for c in candidate) or
                urlsplit(candidate).netloc or urlsplit(candidate).fragment):
            raise ValueError('External, malformed or encoded control destination')
    return value


def response(value):
    if (not isinstance(value, dict) or set(value) != {'status', 'type', 'body'} or
            type(value['status']) is not int or not 200 <= value['status'] <= 599 or
            not isinstance(value['type'], str) or len(value['type']) > 256 or
            any(ord(c) < 32 or ord(c) > 126 for c in value['type']) or
            not isinstance(value['body'], str)):
        raise ValueError('Invalid preview response')
    body = base64.b64decode(value['body'], validate=True)
    if len(body) > BODY_LIMIT:
        raise ValueError('Preview response exceeds 2 MiB')
    return value['status'], value['type'], body


def fetch(port, path):
    # HTTPConnection does not follow redirects, consult proxies, or accept a
    # model-selected hostname. Request headers never carry browser credentials.
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=REQUEST_SECONDS)
    try:
        conn.request('GET', origin_path(path), headers={'Connection': 'close'})
        reply = conn.getresponse()
        body = reply.read(BODY_LIMIT + 1)
        if len(body) > BODY_LIMIT or 300 <= reply.status < 400:
            raise ValueError('Oversized response or redirect is unsupported')
        result = {'status': reply.status, 'type': reply.getheader('Content-Type', 'application/octet-stream'),
                  'body': base64.b64encode(body).decode('ascii')}
        response(result)
        return result
    finally:
        conn.close()


def timed_out(signum, frame):
    raise TimeoutError('Preview request deadline')


def inner(port, cwd, argv):
    shutil.copytree('/seed', '/target', dirs_exist_ok=True)
    os.chdir('/target' + ('/' + cwd if cwd else ''))
    # Native launchers may report startup errors on either output stream.
    # Keep both separate from the relay protocol and retain only a bounded tail.
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, bufsize=0, close_fds=True)
    errors = bytearray()

    def drain():
        while chunk := child.stdout.read(8192):
            errors.extend(chunk)
            del errors[:-8192]

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    signal.signal(signal.SIGALRM, timed_out)
    try:
        deadline = time.monotonic() + START_SECONDS
        while True:
            code = child.poll()
            if code is not None or time.monotonic() >= deadline:
                # waitpid can win the race with the drain thread at exit. A
                # descendant retaining the pipe must not make this wait unbounded.
                if code is not None:
                    reader.join(timeout=.5)
                raise RuntimeError('Application exited (code ' + str(code) +
                                   ') or startup timed out: ' + errors.decode('utf-8', 'replace'))
            try:
                signal.alarm(1)
                fetch(port, '/')
                break
            except (OSError, ValueError, http.client.HTTPException):
                time.sleep(.05)
            finally:
                signal.alarm(0)
        print('{"ready":true}', flush=True)
        while child.poll() is None:
            if not select.select([sys.stdin], [], [], .2)[0]:
                continue
            line = sys.stdin.buffer.readline(8193)
            if not line:
                return
            if len(line) > 8192 or not line.endswith(b'\n'):
                raise ValueError('Invalid preview request frame')
            try:
                signal.alarm(REQUEST_SECONDS)
                value = fetch(port, json.loads(line)['path'])
            except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
                value = {'status': 502, 'type': 'text/plain',
                         'body': base64.b64encode(b'Preview request failed or unsupported').decode()}
            finally:
                signal.alarm(0)
            print(json.dumps(value), flush=True)
    finally:
        child.terminate()
        try:
            child.wait(timeout=1)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
        reader.join(timeout=.5)
        if not reader.is_alive():
            child.stdout.close()


def read_frame(pipe, seconds):
    result = bytearray()
    deadline = time.monotonic() + seconds
    while len(result) <= FRAME_LIMIT:
        left = deadline - time.monotonic()
        if left <= 0 or not select.select([pipe], [], [], left)[0]:
            raise TimeoutError('Preview frame deadline')
        chunk = os.read(pipe.fileno(), min(65536, FRAME_LIMIT + 1 - len(result)))
        if not chunk:
            raise ValueError('Preview exited before reply')
        result.extend(chunk)
        if b'\n' in chunk:
            if not result.endswith(b'\n') or result.count(b'\n') != 1:
                raise ValueError('Invalid preview framing')
            return json.loads(result)
    raise ValueError('Preview frame exceeds limit')


def exchange(child, path):
    data = json.dumps({'path': origin_path(path)}).encode() + b'\n'
    # Only one bounded request is outstanding. A broken inner relay terminates
    # the service rather than allowing later frames to be misassociated.
    os.set_blocking(child.stdin.fileno(), False)
    if not select.select([], [child.stdin], [], REQUEST_SECONDS)[1]:
        raise TimeoutError('Preview write deadline')
    if os.write(child.stdin.fileno(), data) != len(data):
        raise ValueError('Short preview request write')
    return response(read_frame(child.stdout, REQUEST_SECONDS + 1))


def outer(config):
    port, directory = config['port'], Path(config['directory'])
    child = None
    server = None
    fatal = False
    logs = None

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def setup(self):
            super().setup()
            self.connection.settimeout(2)

        def do_GET(self):
            nonlocal fatal
            try:
                # BaseHTTPRequestHandler normalizes leading // in self.path.
                # Validate the original target before that normalization or
                # Host rejection can hide a malformed forwarding request.
                words = self.requestline.split(' ')
                if len(words) != 3 or origin_path(words[1]) != self.path:
                    raise ValueError('Invalid HTTP request target')
            except ValueError:
                self.send_error(400, 'Only origin-relative preview paths are supported')
                return
            origin = 'http://127.0.0.1:' + str(port)
            if (self.headers.get_all('Host') != ['127.0.0.1:' + str(port)] or
                    self.headers.get('Origin', origin) != origin or
                    self.headers.get('Sec-Fetch-Site', 'none') not in ('none', 'same-origin') or
                    self.headers.get('Content-Length', '0') != '0' or self.headers.get('Transfer-Encoding')):
                self.send_error(403, 'Preview requires same-origin localhost requests')
                return
            try:
                status, content_type, body = exchange(child, self.path)
            except (OSError, ValueError):
                fatal = True
                self.send_error(502, 'Preview transport failed')
                return
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            # Scripts may run for local UI preview; no remote subresources,
            # forms, frames, workers, websockets or privileged browser access.
            self.send_header('Content-Security-Policy', "default-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src 'self'; form-action 'none'; frame-src 'none'; worker-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; sandbox allow-scripts allow-same-origin")
            self.end_headers()
            self.wfile.write(body)

    try:
        # Bind before starting the app. An occupied port is never stolen and
        # there is no external-address or automatic-port fallback.
        server = HTTPServer(('127.0.0.1', port), Handler)
        server.timeout = .2
        logs = (directory / 'transport.log').open('xb')
        child = subprocess.Popen(config['argv'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=logs, bufsize=0, close_fds=True)
        if read_frame(child.stdout, START_SECONDS + 2) != {'ready': True}:
            raise ValueError('Application did not establish readiness')
        (directory / 'ready.json').write_text('{"ready":true}')
        deadline = time.monotonic() + config['lifetime_seconds']
        signal.signal(signal.SIGALRM, timed_out)
        while not fatal and time.monotonic() < deadline and child.poll() is None:
            # Includes slow request headers/body and socket response writes.
            signal.alarm(REQUEST_SECONDS + 2)
            try:
                server.handle_request()
            except OSError:
                pass
            finally:
                signal.alarm(0)
    except (OSError, ValueError) as exc:
        (directory / 'error.json').write_text(json.dumps({'error': type(exc).__name__,
            'reason': 'Preview bind, startup or transport failed; no fallback'}))
        raise
    finally:
        if server:
            server.server_close()
        if child:
            child.terminate()
            try:
                child.wait(timeout=1)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        if logs:
            logs.close()


if __name__ == '__main__':
    if sys.argv[1] == 'inner':
        inner(int(sys.argv[2]), sys.argv[3], sys.argv[4:])
    elif sys.argv[1] == 'outer':
        outer(json.loads(Path(sys.argv[2]).read_text()))
    else:
        raise SystemExit('Invalid trusted preview mode')
