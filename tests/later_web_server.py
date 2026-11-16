"""A web server of qKVM's options (cli.SERVER_OPTIONS) whose own HTTP is first made into what a later version of it might be,
in a process of its own, for tests/test_hardening.py: `python -m tests.later_web_server <what>`.

<what>: one of the things the number of connections kept between requests (cli.Http) uses of the web server, renamed in its
source everywhere it stands (RENAMED: its own uses with it, as a version that renamed it would have them); "unhashable", its
ServerState made what a dataclass is, unhashable; "moved", its ServerState not in uvicorn.server when qKVM is imported (put
back after, for the web server's own use); "as_it_is". Four connections are answered with the number made 2, each looked at
for half a second for whether it was let go, and asked again where it was not. Then, with HEADERS_WITHIN and KEPT_SHORT made
1 s, one that sent a request with the beginning of the next (`ahead`) and one kept between requests (`idle`): how long after
its answer each was let go (None: not within 3 s). What came of it is printed: one line of JSON, with what was logged at a
warning or above.
"""

from __future__ import annotations

import json
import logging
import socket
import sys
import threading
import time
import types
from typing import Any

import uvicorn
import uvicorn.protocols.http
import uvicorn.protocols.websockets.websockets_sansio_impl  # (the web server's own, which a version that moved ServerState imports from where it is)
import uvicorn.server
from uvicorn.protocols.http import h11_impl

RENAMED = {
    "_unset_keepalive_if_required": ("_unset_keepalive_if_required", "_cancel_keep_alive"),
    "timeout_keep_alive_handler": ("timeout_keep_alive_handler", "keep_alive_ended"),
    "timeout_keep_alive_task": ("timeout_keep_alive_task", "keep_alive_task"),
    "server_state": ("self.server_state", "self.shared_state"),
    "conn": ("self.conn", "self.h11"),
}
CRLF = chr(13) + chr(10)


def renamed(old: str, new: str) -> types.ModuleType:
    """The web server's HTTP with `old` renamed `new` in its source, made as a module of the same name."""
    with open(h11_impl.__file__, encoding="utf-8") as file:
        source = file.read()
    assert old in source, f"{old} is not in the web server's source any more"
    module = types.ModuleType(h11_impl.__name__)
    module.__file__ = h11_impl.__file__
    exec(compile(source.replace(old, new), h11_impl.__file__, "exec"), module.__dict__)
    return module


async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
    if scope["type"] != "http":
        return
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-length", b"2")]})
    await send({"type": "http.response.body", "body": b"ok"})


def asked(connection: socket.socket) -> int:
    """GET / on a connection kept between requests: the answer's status, its body read. 0: closed."""
    answer = b""
    try:
        connection.sendall(f"GET / HTTP/1.1{CRLF}Host: 127.0.0.1{CRLF}{CRLF}".encode())
        while not answer.endswith(b"ok"):
            more = connection.recv(4096)
            if not more:
                return 0
            answer += more
    except ConnectionError:
        return 0
    return int(answer.split(b" ", 2)[1])


def let_go(connection: socket.socket) -> bool:
    """Whether the web server closes this connection (nothing sent on it since its last answer) within half a second."""
    connection.settimeout(0.5)
    try:
        return connection.recv(100) == b""
    except TimeoutError:
        return False
    except ConnectionError:
        return True
    finally:
        connection.settimeout(10)


def main(what: str) -> None:
    moved = None
    if what == "unhashable":
        uvicorn.server.ServerState.__hash__ = None  # type: ignore[assignment]
    elif what == "moved":
        moved = uvicorn.server.ServerState
        del uvicorn.server.ServerState
    elif what in RENAMED:
        sys.modules[h11_impl.__name__] = uvicorn.protocols.http.h11_impl = renamed(*RENAMED[what])
    else:
        assert what == "as_it_is", what
    logged: list[tuple[str, int, str]] = []

    class Kept(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            logged.append((record.name, record.levelno, record.getMessage()))

    logging.getLogger().addHandler(Kept())
    from qkvm import cli  # (as qKVM is started: the web server is what it is by then)

    if moved is not None:
        uvicorn.server.ServerState = moved
    assert cli.Http.__mro__[1] is sys.modules[h11_impl.__name__].H11Protocol
    cli.IDLE_KEPT_MOST = 2
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, **cli.SERVER_OPTIONS))
    serving = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    serving.start()
    began = time.monotonic()
    while not server.started:
        assert serving.is_alive() and time.monotonic() - began < 30, "the web server did not start"
        time.sleep(0.02)
    connections = [socket.create_connection(("127.0.0.1", port), timeout=10) for _ in range(4)]
    try:
        first = [asked(connection) for connection in connections]
        gone = [let_go(connection) for connection in connections]
        again = [None if was_let_go else asked(connection) for connection, was_let_go in zip(connections, gone, strict=True)]
        for connection in connections:
            connection.close()
        # Two more, with the time for a request's head and the short keep-alive made 1 s: one that sent a request with the
        # beginning of the next (`ahead`), and one kept between requests (`idle`). How long after its answer each was let go.
        cli.HEADERS_WITHIN = cli.KEPT_SHORT = 1.0
        ahead, idle = (socket.create_connection(("127.0.0.1", port), timeout=10) for _ in range(2))
        connections += [ahead, idle]
        ahead.sendall(f"GET / HTTP/1.1{CRLF}Host: 127.0.0.1{CRLF}{CRLF}GET / HTTP/1.1{CRLF}Host: 127".encode())
        answered(ahead)
        assert asked(idle) == 200
        began = time.monotonic()
        let_go_after = [gone_within(connection, began, 3.0) for connection in (ahead, idle)]
    finally:
        for connection in connections:
            connection.close()
        server.should_exit = True
        serving.join(15)
    print(json.dumps({"first": first, "let_go": gone, "again": again, "ahead": let_go_after[0], "idle": let_go_after[1], "logged": logged}))


def answered(connection: socket.socket) -> None:
    """The answer to a GET / sent on `connection`, read to its end."""
    answer = b""
    while not answer.endswith(b"ok"):
        more = connection.recv(4096)
        assert more, "closed before its answer"
        answer += more


def gone_within(connection: socket.socket, began: float, seconds: float) -> float | None:
    """How long after `began` the web server closed this connection, where it did within `seconds` of it; else None."""
    connection.settimeout(max(0.01, began + seconds - time.monotonic()))
    try:
        closed = connection.recv(100) == b""
    except TimeoutError:
        return None
    except ConnectionError:
        closed = True
    return time.monotonic() - began if closed else None


if __name__ == "__main__":
    main(sys.argv[1])
