"""A stand-in device that answers what a test tells it to, and keeps every request as it arrived.

Written by a reviewer, for the answers that the other stand-ins cannot give: one that comes late, a
connection hung up on in the middle of a sign-in, an answer of a byte every so often.

    Scripted(answer).start()    answer(method, path, head, body) says what goes back:
        (status, {header: value}, body)      that answer
        "drop"                               nothing: the connection is cut
        ("after", seconds, (status, ...))    that answer, later
        ("drip", seconds)                    the head of an answer, and then a byte of it every so often
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from collections.abc import Callable
from typing import Any

from tests import ServerThread, local_socket

Answer = Any


def as_json(status: int, said: Any, **headers: Any) -> tuple[int, dict[str, Any], bytes]:
    return status, {"Content-Type": "application/json", **headers}, json.dumps(said).encode()


class Scripted:
    def __init__(self, answer: Callable[[str, str, str, bytes], Answer]) -> None:
        self.answer = answer
        self.seen: list[tuple[float, str, str, str, bytes]] = []  # when, method, path, the head as sent, the body
        self._sock = local_socket()
        self.port: int = self._sock.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop: asyncio.Event | None = None
        self._ready = threading.Event()
        self._serving = ServerThread("scripted device", lambda: asyncio.run(self._serve()), self._ready.is_set)
        self._thread = self._serving.thread

    def start(self) -> Scripted:
        self._serving.start()
        return self

    def stop(self) -> None:
        if self._loop is not None and self._stop is not None:
            self._loop.call_soon_threadsafe(self._stop.set)
        self._thread.join(timeout=10)

    def asked(self, method: str, path: str) -> list[tuple[float, str, str, str, bytes]]:
        return [one for one in self.seen if one[1] == method and one[2].split("?")[0] == path]

    async def _serve(self) -> None:
        self._loop, self._stop = asyncio.get_running_loop(), asyncio.Event()
        server = await asyncio.start_server(self._client, sock=self._sock)
        self._ready.set()
        await self._stop.wait()
        server.close()

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                head = (await reader.readuntil(b"\r\n\r\n")).decode("latin-1")
                lines = head.split("\r\n")
                method, path = lines[0].split(" ")[0], lines[0].split(" ")[1]
                length = 0
                for line in lines[1:]:
                    name, _, value = line.partition(":")
                    if name.strip().lower() == "content-length":
                        length = int(value.strip())
                body = await reader.readexactly(length) if length else b""
                self.seen.append((time.monotonic(), method, path, head, body))
                answer = self.answer(method, path, head, body)
                if answer == "drop":
                    writer.transport.abort()
                    return
                if answer[0] == "drip":
                    writer.write(b"HTTP/1.1 200 X\r\nContent-Type: text/plain\r\nContent-Length: 1000000\r\n\r\n")
                    while True:
                        writer.write(b"x")
                        await writer.drain()
                        await asyncio.sleep(answer[1])
                if answer[0] == "after":
                    await asyncio.sleep(answer[1])
                    answer = answer[2]
                status, headers, content = answer
                out = [f"HTTP/1.1 {status} X", f"Content-Length: {len(content)}"]
                for name, value in headers.items():
                    out += [f"{name}: {one}" for one in (value if isinstance(value, list) else [value])]
                writer.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1") + content)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            try:
                writer.close()
            except Exception:  # (whatever closing a connection that is gone throws: the test is over for it)
                pass
