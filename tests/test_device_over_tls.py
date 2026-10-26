"""The same hostile ends of a device's WebSocket as test_what_a_library_says.py, over TLS.

A kvmd device is talked to over HTTPS as a rule, and there the connection is another transport of the
event loop's (`_SSLProtocolTransport`), with its own `abort`, `is_closing` and order of events.
"""

from __future__ import annotations

import asyncio
import base64
import functools
import hashlib
import socket
import ssl
import struct
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from qkvm import cli, kvm
from qkvm.kvm import DeviceSpec, KvmDevice
from qkvm.tlscert import ensure_certificate
from tests.test_device_limits import GUID, frame
from tests.test_what_a_library_says import Terminal, as_the_program_logs, nothing_else_listening  # noqa: F401 (a fixture)


class OverTls:
    """A device's WebSocket end over TLS that sends something of its own in one TLS record with its answer to the handshake."""

    def __init__(self, folder: Path, with_it: bytes, then: Callable[[ssl.SSLSocket], None]) -> None:
        cert, key, _ = ensure_certificate(folder, ["127.0.0.1"])
        self._tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._tls.load_cert_chain(cert, key)
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        self._with_it, self._then = with_it, then
        self.opened = 0
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, plain: socket.socket) -> None:
        try:
            conn = self._tls.wrap_socket(plain, server_side=True)
        except OSError:
            plain.close()
            return
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                more = conn.recv(4096)
                if not more:
                    return
                data += more
            head = data.split(b"\r\n\r\n")[0].decode("latin1")
            key = next(line.split(":", 1)[1].strip() for line in head.split("\r\n") if line.lower().startswith("sec-websocket-key"))
            accept = base64.b64encode(hashlib.sha1(key.encode() + GUID).digest()).decode()
            answer = f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            self.opened += 1
            conn.sendall(answer.encode() + self._with_it)
            self._then(conn)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self) -> None:
        self._sock.close()


def reset(conn: ssl.SSLSocket) -> None:
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("hh" if sys.platform == "win32" else "ii", 1, 0))
    conn.close()


ENDS: dict[str, tuple[bytes, Callable[[ssl.SSLSocket], None]]] = {
    "a flood in one breath with the answer": (frame(0x9) * 60, lambda conn: time.sleep(5)),
    "a flood, then a reset": (frame(0x9) * 2000, reset),
    "the answer, then a reset": (b"", reset),
    "the answer and a close frame, and then nothing": (frame(0x8, struct.pack(">H", 1000) + b"bye"), lambda conn: time.sleep(5)),
    "the answer, and the line is closed": (b"", lambda conn: None),
    "the answer, a ping, and the line is closed": (frame(0x9, b"x"), lambda conn: None),
}


@pytest.mark.parametrize("end", list(ENDS))
def test_over_tls_no_task_of_the_library_is_left_and_nothing_is_on_the_terminal(end: str, tmp_path: Path, as_the_program_logs: tuple[Terminal, Path], monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    monkeypatch.setattr(kvm, "ws_connect", functools.partial(kvm.ws_connect, ping_interval=1))  # the library's first ping after one second, not twenty
    terminal, folder = as_the_program_logs
    with_it, then = ENDS[end]
    device = OverTls(tmp_path / "device", with_it, then)
    connections = 8

    async def run() -> int:
        kvmd = KvmDevice(DeviceSpec("d", "Hostile", f"https://127.0.0.1:{device.port}", "admin", "secret", tls="insecure"))
        kvmd._token = "t"
        kvmd._glinet = True  # (known for a GLKVM, as a look finds one: the family is not asked of a device that only speaks this line)
        await kvmd._http()  # as every request to the device does first: how its certificate is checked is known from here on
        for _ in range(connections):
            kvmd._wanted_at = time.monotonic()
            await asyncio.wait_for(kvmd._hold_stream_open(), 20)
        await asyncio.sleep(0.2)  # a task that was cancelled in the moment its connection was lost has ended by now; one that was left is asleep for a second
        left = sum(1 for task in asyncio.all_tasks() if "keepalive" in repr(task.get_coro()))
        await asyncio.sleep(3.0)
        await kvmd.close()
        return left

    try:
        with nothing_else_listening():
            left = asyncio.run(run())
    finally:
        device.stop()
    cli.stop_logging()
    written = terminal.getvalue()
    log = (folder / "qkvm.log").read_text(encoding="utf-8")
    print(f">>> {end}: {device.opened} handshakes; {left} library tasks left; terminal {len(written)} characters, {terminal.from_the_loop} writes from the loop; qkvm.log {len(log.splitlines())} lines: " + " /// ".join(line[:140] for line in log.splitlines()[:6]))
    assert device.opened == connections
    assert left == 0
    assert written == "" and terminal.from_the_loop == 0
    assert "Traceback" not in log, log[:2000]
