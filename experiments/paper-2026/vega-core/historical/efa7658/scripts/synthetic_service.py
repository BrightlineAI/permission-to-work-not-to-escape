#!/usr/bin/env python3
"""Loopback-only synthetic effect service; state is outside the agent boundary."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class Handler(BaseHTTPRequestHandler):
    state_root: Path

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length))
            if set(body) != {"action_hash", "request"}:
                raise ValueError("invalid body")
            name = self.path.strip("/").replace("/", "-")
            if not name or ".." in name:
                raise ValueError("invalid path")
            target = self.state_root / f"{name}.json"
            events = json.loads(target.read_text()) if target.exists() else []
            events.append(body)
            fd, temporary = tempfile.mkstemp(dir=self.state_root, prefix=".event-")
            with os.fdopen(fd, "w") as stream:
                json.dump(events, stream, sort_keys=True, indent=2)
                stream.write("\n")
            os.replace(temporary, target)
            payload = b'{"accepted":true}\n'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except Exception as exc:
            payload = json.dumps({"accepted": False, "error": str(exc)}).encode()
            self.send_response(400)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    def log_message(self, format, *args):
        return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-root", required=True)
    parser.add_argument("--port", type=int, default=39080)
    args = parser.parse_args()
    Handler.state_root = Path(args.state_root).resolve()
    Handler.state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
