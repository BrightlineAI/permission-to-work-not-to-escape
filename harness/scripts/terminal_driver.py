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
    def __init__(self, argv, folder, *, env=None, cwd=None, replace_env=False):
        if replace_env and env is None:
            raise ValueError('Replacement terminal environment must be explicit')
        child_env = {} if replace_env else dict(os.environ)
        child_env.update(env or {}, TERM="xterm-256color")
        self.folder = Path(folder)
        self.folder.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.raw = (self.folder / "terminal.txt").open("wb")
        os.chmod(self.folder / "terminal.txt", 0o600)
        self.started = time.monotonic()
        self.last_output = self.started
        self.text = ""
        self.exited = False
        self.inputs = []
        self.closed = False
        self.bracketed_paste = False
        self.control_tail = b""
        self.argv = [str(arg) for arg in argv]
        self._save_inputs()
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            if cwd:
                os.chdir(cwd)
            os.execvpe(self.argv[0], self.argv, child_env)
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 140, 0, 0))

    def _save_inputs(self):
        from evidence_io import save
        save(self.folder / "inputs.json", self.inputs)

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
            controls = self.control_tail + chunk
            modes = re.findall(rb"\x1b\[\?2004([hl])", controls)
            if modes:
                self.bracketed_paste = modes[-1] == b"h"
            self.control_tail = controls[-7:]
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
        self._save_inputs()
        os.write(self.fd, text.encode())
        # Codex distinguishes pasted input from the later Enter key.
        self.read(.3)
        time.sleep(.15)
        os.write(self.fd, b"\r")

    def paste(self, text):
        """Submit one prompt to a ready bracketed-paste composer, never a review.

        Raw bursts can absorb Enter as part of the paste. Explicit boundaries
        preserve multiline/long prompts without guessing whether to press again.
        """
        if self.closed or self.exited or not self.bracketed_paste:
            raise ValueError('Terminal has not enabled bracketed paste')
        if not text or any(ord(c) < 32 and c not in '\n\t' or ord(c) == 127 for c in text):
            raise ValueError('Prompt contains terminal controls or is empty')
        entry = {"seconds": round(time.monotonic() - self.started, 3),
                 "text": text, "mode": "bracketed-paste"}
        self.inputs.append(entry)
        self._save_inputs()
        pending = b"\x1b[200~" + text.encode() + b"\x1b[201~"
        while pending:
            count = os.write(self.fd, pending)
            if count <= 0:
                raise OSError('Terminal accepted no prompt bytes')
            pending = pending[count:]
        # Drain output for the whole interval. A single read can return at once.
        until = time.monotonic() + .3
        while time.monotonic() < until:
            self.read(min(.05, max(0., until - time.monotonic())))
            if self.exited:
                raise OSError('Terminal exited before prompt submission')
        os.write(self.fd, b"\r")
        entry['submitted_seconds'] = round(time.monotonic() - self.started, 3)
        self._save_inputs()

    def quiet(self, timeout=300, seconds=3):
        return self.wait(lambda: time.monotonic() - self.last_output >= seconds, timeout, "idle terminal")

    def close(self, *, graceful=True):
        """Quit a known ready Codex, or terminate without typing into unknown UI.

        Failure cleanup must use graceful=False: Enter at an onboarding/update
        prompt can approve an operation instead of quitting a conversation.
        """
        if self.closed:
            return self.exit_code
        if not self.exited and graceful:
            self.send("/quit")
            try:
                self.wait(lambda: self.exited, 15, "clean Codex exit")
            except AssertionError:
                pass
        if not self.exited:
            try:
                os.kill(self.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.wait(lambda: self.exited, 5, "terminal termination")
            except AssertionError:
                try:
                    os.kill(self.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        try:
            _, status = os.waitpid(self.pid, 0)
            code = os.waitstatus_to_exitcode(status)
        except ChildProcessError:
            code = None
        self.raw.close()
        os.close(self.fd)
        self._save_inputs()
        (self.folder / "exit.json").write_text(json.dumps({"argv": self.argv, "exit_code": code,
                  "graceful_requested": graceful,
                  "seconds": round(time.monotonic() - self.started, 3)}))
        self.closed, self.exit_code = True, code
        return code
