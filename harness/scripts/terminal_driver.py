"""Small Linux PTY driver for genuine terminal acceptance, not a replacement UI."""
import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import struct
import termios
import time


ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b.")


class Terminal:
    def __init__(self, argv, folder, *, env=None, cwd=None):
        self.folder = Path(folder)
        self.folder.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.raw = (self.folder / "terminal.txt").open("wb")
        os.chmod(self.folder / "terminal.txt", 0o600)
        self.started = time.monotonic()
        self.last_output = self.started
        self.text = ""
        self.exited = False
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            if cwd:
                os.chdir(cwd)
            os.environ.update(env or {}, TERM="xterm-256color")
            os.execvpe(argv[0], argv, os.environ)
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 140, 0, 0))
        self.inputs = []

    def read(self, timeout=.2):
        if self.exited:
            return ""
        if select.select([self.fd], [], [], timeout)[0]:
            try:
                chunk = os.read(self.fd, 65536)
            except OSError as exc:
                if exc.errno != errno.EIO:
                    raise
                chunk = b""
            if not chunk:
                self.exited = True
                return ""
            self.last_output = time.monotonic()
            self.raw.write(chunk)
            self.raw.flush()
            text = ANSI.sub("", chunk.decode("utf-8", errors="replace"))
            self.text += text
            return text
        return ""

    def wait(self, condition, timeout=180, label="terminal condition"):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            self.read()
            if condition():
                return time.monotonic() - self.started
            if self.exited:
                break
        raise AssertionError(label + " failed; inspect " + str(self.folder))

    def expect(self, text, timeout=180):
        return self.wait(lambda: text in self.text, timeout, repr(text))

    def send(self, text):
        self.inputs.append({"seconds": round(time.monotonic() - self.started, 3), "text": text})
        os.write(self.fd, text.encode())
        # Codex distinguishes pasted input from the later Enter key.
        self.read(.3)
        time.sleep(.15)
        os.write(self.fd, b"\r")

    def quiet(self, timeout=300, seconds=3):
        return self.wait(lambda: time.monotonic() - self.last_output >= seconds, timeout, "idle terminal")

    def close(self):
        if not self.exited:
            self.send("/quit")
            try:
                self.wait(lambda: self.exited, 15, "clean Codex exit")
            except AssertionError:
                os.kill(self.pid, signal.SIGTERM)
        try:
            _, status = os.waitpid(self.pid, 0)
            code = os.waitstatus_to_exitcode(status)
        except ChildProcessError:
            code = None
        self.raw.close()
        os.close(self.fd)
        (self.folder / "inputs.json").write_text(json.dumps(self.inputs, indent=2))
        (self.folder / "exit.json").write_text(json.dumps({"exit_code": code,
                  "seconds": round(time.monotonic() - self.started, 3)}))
        return code
