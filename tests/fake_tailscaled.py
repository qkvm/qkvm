"""A stand-in for Tailscale's local API (tailscaled), on a Unix socket in a folder of the test's own.

It answers each path it is told an answer for (`answers`: path without its query -> (status, body)), 404 to anything
else, and keeps what it was asked (`asked`: method, target and headers of each request) so that a test can see that
nothing else was. `hold` keeps it from answering for that long; `trickle` has it send a byte at a time for ever after
its headers; `raw` is sent as the whole answer instead, status line and all. Linux and macOS only: Windows keeps
Tailscale's local API behind a named pipe, which qKVM does not ask.
"""

from __future__ import annotations

import os
import shutil
import socket
import socketserver
import tempfile
import threading
from pathlib import Path
from typing import BinaryIO


class FakeTailscaled:
    def __init__(self) -> None:
        # (A short path of its own: a Unix socket's path may be some hundred characters long at the most, and pytest's
        # folders for a test are named after the test.)
        self.folder = Path(tempfile.mkdtemp(prefix="ts", dir="/tmp"))
        self.path = self.folder / "tailscaled.sock"
        self.answers: dict[str, tuple[int, bytes]] = {}
        self.asked: list[tuple[str, str, dict[str, str]]] = []
        self.hold = 0.0
        self.trickle = False
        self.raw: bytes | None = None
        self._stopping = threading.Event()
        self._server: socketserver.UnixStreamServer | None = None

    def start(self) -> FakeTailscaled:
        fake = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                try:
                    fake._answer(self.rfile, self.connection)
                except OSError:
                    pass  # (the asker hung up: what it was sent is what it read)

        class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True

        self._server = Server(str(self.path), Handler)
        os.chmod(self.path, 0o666)  # as tailscaled leaves its socket: who may do what is its to judge, by who connects
        threading.Thread(target=self._server.serve_forever, name="fake tailscaled", daemon=True).start()
        return self

    def _answer(self, reader: BinaryIO, line: socket.socket) -> None:
        request = reader.readline(8192).decode("latin-1").rstrip("\r\n")
        headers: dict[str, str] = {}
        while header := reader.readline(8192).decode("latin-1").rstrip("\r\n"):
            name, _, value = header.partition(":")
            headers[name.strip().lower()] = value.strip()
        method, _, rest = request.partition(" ")
        target = rest.rsplit(" ", 1)[0]
        self.asked.append((method, target, headers))
        if self.hold and self._stopping.wait(self.hold):
            return
        if self.raw is not None:
            line.sendall(self.raw)
            return
        status, body = self.answers.get(target.split("?", 1)[0], (404, b"not found\n"))
        line.sendall(f"HTTP/1.0 {status} X\r\nContent-Type: application/json\r\n\r\n".encode("ascii"))
        if self.trickle:
            while not self._stopping.wait(0.05):
                line.sendall(b" ")
            return
        line.sendall(body)

    def stop(self) -> None:
        self._stopping.set()
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        shutil.rmtree(self.folder, ignore_errors=True)
