"""The program proper: options, logging, and the loop that keeps the web server up."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import logging.handlers
import os
import queue
import re
import secrets
import ssl
import stat
import sys
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import uvicorn
from uvicorn.protocols.http.h11_impl import H11Protocol
from uvicorn.protocols.websockets.websockets_sansio_impl import WebSocketsSansIOProtocol
from websockets.exceptions import InvalidState
from websockets.frames import Frame

from . import activity, history, live, unlock
from ._version import __version__
from ._where import default_data_dir
from .core import Core
from .kvm import WarningsOnly
from .netbind import BindError, normalize, open_sockets, resolve
from .server import create_app
from .store import InstanceLock, ServerSettings, StoreError
from .update import UpdateError, check_startup_requirements

log = logging.getLogger("qkvm")
MAX_CRASHES = 5  # restarts allowed within CRASH_WINDOW before giving up
CRASH_WINDOW = 60.0


# Minimum library versions for the reviewed security/runtime baseline. These floors do not
# certify that every bundled component is vulnerability-free. The same floors are in
# pyproject.toml; this warns about environments maintained outside the normal installer.
SAFE_FROM = {"starlette": (1, 3, 1), "cryptography": (50, 0, 0), "anyio": (4, 14, 2), "idna": (3, 15, 0), "certifi": (2026, 10, 19), "h11": (0, 16, 0), "aiortc": (1, 15, 0), "av": (17, 1, 0)}


def outdated_libraries() -> dict[str, str]:
    """Installed libraries that are older than SAFE_FROM: the name of each, and a line about it fit for showing."""
    from importlib.metadata import PackageNotFoundError, version

    found = {}
    for name, minimum in SAFE_FROM.items():
        try:
            installed = version(name)
        except PackageNotFoundError:
            continue
        numbers = tuple(int(part) for part in re.findall(r"[0-9]+", installed)[:3])
        if numbers < minimum:
            found[name] = f"{name} {installed} (required minimum {'.'.join(str(part) for part in minimum)})"
    return found


def raise_file_limit() -> None:
    """Allow as many open connections as the system will give.

    Every KVM on the wall takes several, and so does every browser looking at it. The usual
    starting allowance on Linux and macOS (1024, 256) is used up by a wall of a hundred KVMs.
    """
    if sys.platform == "win32":  # Windows has no such allowance
        return
    import resource

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    for wanted in (65536, 10240, 4096):  # macOS refuses more than 10240, whatever it claims to allow
        if hard != resource.RLIM_INFINITY:
            wanted = min(wanted, hard)
        if soft == resource.RLIM_INFINITY or soft >= wanted:
            return  # enough as it is
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))
        except (ValueError, OSError):
            continue
        log.info("open files allowed: %d (was %d)", wanted, soft)
        return


HEADERS_WITHIN = 20.0  # seconds a connection has to say what it wants: a request's first line and its headers
STALLED_AFTER = 20.0  # seconds an answer may wait for its caller to take some more of it
TAKEN_AT_LEAST = 4096  # bytes of a waiting answer that have to be taken in that time for the wait to go on


class Http(H11Protocol):
    """The web server's HTTP, with two clocks added: for a connection that does not ask, and for one that does not listen.

    As it comes, a connection may stay open for ever without sending a request, or after sending half of
    one (the web server keeps time only between two requests). And one that asks for something large and
    then takes nothing of the answer is kept for as long as it likes: an answer is not given up on, and a
    connection is not closed, while there is something left to send. Anybody who can reach the port could
    hold as many as the system gives out, and leave none for a browser, or for qKVM to reach a device with.
    """

    _asking: asyncio.TimerHandle | None = None  # runs while a request is awaited or arriving
    _handing_over: asyncio.TimerHandle | None = None  # runs while an answer waits to be taken
    _still_to_take = 0  # how much of it was waiting when that clock was started

    def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
        super().connection_made(transport)
        self._expect_a_request()

    def data_received(self, data: bytes) -> None:
        super().data_received(data)
        if self.transport.get_protocol() is not self:
            # The request was for the live line, and the connection is the WebSocket's now (`Line`, which keeps time of
            # its own). Left running, these clocks closed every line twenty seconds after it opened.
            self._stop_the_clock()
            self._taken()
            return
        if self.cycle is not None and not self.cycle.response_complete:
            self._stop_the_clock()  # a whole request is here and being answered (its body has a clock of its own)
        else:
            # The beginning of a request. The time for the rest of it runs from its first byte, and is not
            # started afresh by every further one: a byte every few seconds would keep it open for ever.
            self._expect_a_request()

    def connection_lost(self, exc: Exception | None) -> None:
        self._stop_the_clock()
        self._taken()
        super().connection_lost(exc)

    def pause_writing(self) -> None:
        super().pause_writing()  # more is waiting than is kept ready: the answer stops until some of it is taken
        self._wait_for_the_taker()

    def resume_writing(self) -> None:
        self._taken()
        super().resume_writing()

    def on_response_complete(self) -> None:
        super().on_response_complete()
        # An answer may be finished and its end still here, with a caller that takes nothing. A connection
        # is closed only once everything was sent, so this one would not be: not after the pause the web
        # server allows between two requests, and not when the answer said it was the last.
        if self.transport.get_write_buffer_size():
            self._wait_for_the_taker()

    def _wait_for_the_taker(self) -> None:
        if self._handing_over is None:
            self._still_to_take = self.transport.get_write_buffer_size()
            self._handing_over = self.loop.call_later(STALLED_AFTER, self._taken_anything)

    def _taken(self) -> None:
        if self._handing_over is not None:
            self._handing_over.cancel()
            self._handing_over = None

    def _taken_anything(self) -> None:
        self._handing_over = None
        left = self.transport.get_write_buffer_size()
        if not left:
            return
        if 0 <= self._still_to_take - left < TAKEN_AT_LEAST:
            # Dropped, not closed: closing waits for what is left to be taken, which is what does not happen.
            self.transport.abort()
            return
        self._wait_for_the_taker()  # slow, and getting somewhere (or there is more to take than before: it asked again)

    def _expect_a_request(self) -> None:
        if self._asking is None:
            self._asking = self.loop.call_later(HEADERS_WITHIN, self._waited_long_enough)

    def _stop_the_clock(self) -> None:
        if self._asking is not None:
            self._asking.cancel()
            self._asking = None

    def _waited_long_enough(self) -> None:
        self._asking = None
        answering = self.cycle is not None and not self.cycle.response_complete
        if not answering and not self.transport.is_closing():
            self.transport.close()


# What the WebSocket library logs of a connection at its finer levels is every frame: the pass in a live line's first
# message, and every key after it. A live line's connection logs through a logger that says nothing finer than a warning,
# whatever any level says (`--log-level debug` included: kvm.WarningsOnly); to the web server's logger, so that what it
# does say goes where its other lines go.
_LINE_FRAMES = WarningsOnly(logging.getLogger("uvicorn.error"), {})


# How the web server is run, whatever it listens on.
class Line(WebSocketsSansIOProtocol):
    """The web server's WebSocket, for the live line (live.py), with what it does not do by itself: hang up on a viewer that stops taking what is sent.

    As it comes, it answers every ping straight into what waits to be sent, without a bound, and it keeps a
    connection whose viewer takes nothing off it for as long as the viewer keeps it: a viewer that sent pings by
    the million and read nothing had the answers held for it without end, and one that read nothing at all kept
    a machine's keyboard and mouse, the keys it had down with them, for as long as its connection lived. So the
    pings are counted, what waits to be sent is looked at, and a connection that has not drained for a while is
    dropped: the program is told that the line is gone, as it is, and lets go of what it held.

    And it reads, before any pass was shown, every frame anybody who reaches the port sends: a pong nobody asked for,
    a piece of a message that never ends (kept, every one, for the message: two million pieces of no bytes in four
    seconds, eighty megabytes in twenty, the program's loop at a sixth of its pace meanwhile). The program counts the
    messages it is handed (live.MOST_A_SECOND); every other frame is counted here, and so are the pieces of a message.
    """

    _second = 0.0  # the second being counted in, and the pings and other frames that came in it
    _pings = 0
    _frames = 0
    _pieces = 0  # of the message that is coming
    _paused_since: float | None = None  # since when more waits to be sent than is kept ready, and the viewer has taken none of it
    _hung_up = False

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # The connection the web server made, logging through the logger above: whatever it asks to say finer than a warning
        # is dropped there, unformatted, whether or not it found out at its making that the web server's logger is finer.
        self.conn.logger = _LINE_FRAMES
        self.conn.debug = False

    def data_received(self, data: bytes) -> None:
        if self._hung_up:
            return
        super().data_received(data)
        if not self._hung_up and self.transport.get_write_buffer_size() > live.MOST_UNSENT_TO_VIEWER:
            self._hang_up()

    def _counted(self) -> bool:
        """One more frame of those the program does not count itself: False, and hung up on, where that is more in a second than a viewer has reason to send."""
        if self._hung_up:
            return False
        now = time.monotonic()
        if now - self._second >= 1.0:
            self._second, self._pings, self._frames = now, 0, 0
        self._frames += 1
        if self._frames > live.MOST_FRAMES_A_SECOND:
            self._hang_up()
            return False
        return True

    def handle_ping(self) -> None:
        if not self._counted():
            return
        self._pings += 1
        if self._pings > live.MOST_PINGS_A_SECOND or self.transport.get_write_buffer_size() > live.MOST_UNSENT_TO_VIEWER:
            self._hang_up()
            return
        super().handle_ping()

    def handle_pong(self, event: Frame) -> None:
        if self._counted():
            super().handle_pong(event)

    def handle_text(self, event: Frame) -> None:
        # A whole message the program is handed, it counts; the first piece of one in pieces, or one that comes after the
        # line was closed (thrown away unread, and read on all the same), is counted here.
        if self._hung_up:
            return  # (the rest of what came in one read, after the hang-up: nobody's)
        if (event.fin and not self.close_sent) or self._counted():
            self._pieces = 1
            super().handle_text(event)

    def handle_bytes(self, event: Frame) -> None:
        if self._hung_up:
            return
        if (event.fin and not self.close_sent) or self._counted():
            self._pieces = 1
            super().handle_bytes(event)

    def handle_cont(self, event: Frame) -> None:
        if not self._counted():
            return
        self._pieces += 1
        if self._pieces > live.MOST_PIECES:
            self._hang_up()  # (a message in more pieces than any client sends one: the web server keeps what came, piece by piece)
            return
        super().handle_cont(event)

    def shutdown(self) -> None:
        # The web server is stopping, and says goodbye on every connection. On one that is closing already (its viewer said
        # goodbye, or the line did, and the answer still waits to be taken) the library refuses to say it twice, and the
        # web server's stop went no further: not to the connections after this one, and not to the program's own stop
        # (every line letting go of what it held, every device's connection closed). Dropped as it stands instead; and so is
        # one where anything else goes wrong in that goodbye, for the same reason.
        try:
            super().shutdown()
        except InvalidState:
            self.transport.abort()
        except Exception:
            log.debug("saying goodbye on a live line as the web server stopped failed", exc_info=True)
            self.transport.abort()

    def keepalive_timeout(self) -> None:
        # The viewer answered none of the pings: it is gone. Dropped as the connection stands, and not closed: closing waits
        # for what is still to be sent to be taken, which is what a viewer that is gone never does, and the program would
        # hear of the end only then (minutes on, for a computer that vanished with something unsent), keeping the
        # machine's keyboard and mouse for it meanwhile, and the keys it had down.
        self.pong_timer = None
        self.pending_ping_payload = None
        if not self._hung_up:
            self._hang_up()

    # What is sent waits while more waits to be sent than is kept ready (`writable`), so that a viewer that falls behind is
    # brought forward to the next key frame, and one that is not read at all ends (`slow`), instead of everything sent to it
    # piling up in this program's memory. The web server does this itself from some version after 0.46, which this
    # program still runs on (pyproject.toml), and which does not: so it is done here as well, in the same three places.
    def pause_writing(self) -> None:
        super().pause_writing()
        self.writable.clear()
        since = self._paused_since = time.monotonic()
        self.loop.call_later(live.STUCK_AFTER, self._still_stuck, since)

    def resume_writing(self) -> None:
        self._paused_since = None
        super().resume_writing()
        self.writable.set()

    def connection_lost(self, exc: Exception | None) -> None:
        super().connection_lost(exc)
        self.writable.set()  # (a send that waits is let go, and finds the line gone: a lost connection is never resumed)

    def _still_stuck(self, since: float) -> None:
        if self._paused_since == since and not self._hung_up:
            self._hang_up()

    def _hang_up(self) -> None:
        self._hung_up = True
        self.transport.abort()  # the connection is lost, and the program is told so (a disconnect), as for a viewer that went away


SERVER_OPTIONS: dict[str, Any] = {
    "http": Http,
    # The live line (live.py) is the one thing in qKVM that is talked to over a WebSocket: let in by a pass of its own,
    # every message from it bounded, asked by the web server every few seconds whether it is there (a line that has
    # answered none of three such askings is gone, and what it held down on a machine is let go of), and hung up on
    # when it stops taking what is sent (`Line` above).
    "ws": Line,
    "ws_max_size": live.MOST_WORD,
    "ws_ping_interval": live.ASK_EVERY,
    "ws_ping_timeout": live.ASK_EVERY * 3,
    "ws_per_message_deflate": False,  # pictures do not pack; and what a client sent packed would be unpacked before it is counted
    "log_config": None,  # keep the handlers set up in setup_logging
    "log_level": "warning",
    "access_log": False,  # tiles poll for a frame every second; an access log would be nothing but noise
    "server_header": False,
    "timeout_graceful_shutdown": 3,
    # Who is calling, and whether over HTTPS, is worked out in one place (security.client_ip, is_secure)
    # from the proxies named with --trusted-proxy. Left on, the web server would rewrite both by itself,
    # for whatever an environment variable of its own (FORWARDED_ALLOW_IPS) happens to say.
    "proxy_headers": False,
}


def tls_pair(cert: str | None, key: str | None) -> tuple[Path, Path] | None:
    """The certificate and key given at start, as files that belong together. None: none were given.

    ValueError says, for whoever started it, what is wrong with them: found out here, and not by the
    web server failing to start, or by the first browser.
    """
    if not cert and not key:
        return None
    if not cert or not key:
        raise ValueError("--tls-cert and --tls-key go together: a certificate is of no use without its key, nor a key without its certificate")
    for name in (cert, key):
        if not Path(name).is_file():
            raise ValueError(f"{name}: there is no such file")
    try:
        if "ENCRYPTED" in Path(key).read_text(encoding="ascii", errors="replace"):
            # The library would stop and ask for it on the terminal, at every start, where a service has nobody.
            raise ValueError(f"{key} is protected by a passphrase, and there is nobody to type it when qKVM starts: use a key without one")
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(cert, key, password=lambda: "")
    except ssl.SSLError as ex:
        raise ValueError(f"{cert} and {key} do not belong together, or are not a certificate and its key ({ex.reason or ex})") from None
    except OSError as ex:  # the key is another user's, more often than not
        raise ValueError(f"{ex.filename or key} cannot be read by the user qKVM runs as ({ex.strerror or ex})") from None
    return Path(cert), Path(key)


def networks_said(option: str, value: str | None) -> list[str]:
    """The addresses given with --allow-from or --trusted-proxy. ValueError when the option is there and they are not.

    `--allow-from "$OFFICE"` with nothing in OFFICE would otherwise start a qKVM that answers everybody,
    by the very option that was to prevent it.
    """
    if value is None:
        return []
    names = [name.strip() for name in value.split(",") if name.strip()]
    if not names:
        raise ValueError(f"{option} was given without an address. Leave the option out if it is not wanted.")
    return names


def listening_as(settings: ServerSettings) -> tuple[list[str], int, bool]:
    """Where and how qKVM listens, of everything that is set: what has to be taken back if the next try fails."""
    return list(settings.bind), settings.port, settings.https


def listen_again_as(settings: ServerSettings, before: tuple[list[str], int, bool]) -> None:
    """Take back where it listens, and nothing else that was changed meanwhile."""
    settings.bind, settings.port, settings.https = list(before[0]), before[1], before[2]


def _in_full(folder: Path) -> Path:
    """The folder with everything that leads to it, where that can be said: not from a current folder that is gone."""
    try:
        return folder.resolve()
    except (OSError, RuntimeError):  # (RuntimeError: a link that leads to itself, as Python before 3.13 says it)
        return folder


def say(text: str = "", error: bool = False) -> None:
    """A line for whoever started qKVM, if there is anybody to read it."""
    try:
        # flush: when output goes to a log file, the addresses should show up right away
        print(text, file=sys.stderr if error else sys.stdout, flush=True)
    except (OSError, ValueError):
        # Started without a window, or from a terminal that is gone since: there is nowhere to print to.
        # Everything that matters is in qkvm.log as well, and a wall does not stop for want of a reader.
        pass


_listener: logging.handlers.QueueListener | None = None  # the thread that writes what is logged
_others: logging.Handler | None = None  # what takes the lines that are not this program's own (see setup_logging)
OURS = ("qkvm", "uvicorn")  # whose lines are this program's own to say

# For a line in the log that whoever started qKVM is told in words of their own (see `say`): it is kept
# out of the terminal, where the same thing twice, the second time in the middle of the first, helps nobody.
SAID = {"said": True}


class _Unsaid(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        # (Nor what a library or the event loop has to say, which a device can make them say as often as it
        # likes: that is for the log, which is kept to a size.)
        return not getattr(record, "said", False) and record.name.split(".", 1)[0] in OURS


class _OnceAMinute(logging.Filter):
    """Lets each kind of line through once a minute, and no more than `MOST` kinds in one.

    What a library, the event loop or the web server says, it says for every connection it happens on: a
    line (with a traceback, some of them) for each connection that a device broke in a way the library had
    not thought of, and for each request that is none, which anybody who reaches the port can send by the
    thousand. The log is kept to a size, so that is its history gone in minutes; the terminal is not.
    """

    MOST = 200
    _NUMBERS = re.compile(r"0x[0-9a-fA-F]+|[0-9]+")  # which task, which object, at what address: not what makes a kind

    def __init__(self) -> None:
        super().__init__()
        self._last: dict[str, float] = {}

    def filter(self, record: logging.LogRecord) -> bool:
        # A kind is who says it, the first line of what is said before anything is filled in, and for an
        # error the kind of error and where it was raised. (Of what the event loop says about a task that
        # failed, the lines after the first name the task: by those, every one was a kind of its own.)
        kind, now = f"{record.name}: {self._NUMBERS.sub('#', (str(record.msg).splitlines() or [''])[0][:120])}", time.monotonic()
        error = record.exc_info[1] if record.exc_info else None
        if error is not None:
            at = error.__traceback__
            while at is not None and at.tb_next is not None:
                at = at.tb_next
            kind += f" {type(error).__name__}" + (f" {at.tb_frame.f_code.co_filename}:{at.tb_lineno}" if at is not None else "")
        if now - self._last.get(kind, float("-inf")) < 60:
            return False
        if len(self._last) >= self.MOST:
            self._last = {said: when for said, when in self._last.items() if now - when < 60}
            if len(self._last) >= self.MOST:
                return False  # so many kinds within the minute are no kinds any more: nothing further until one is a minute old
        self._last[kind] = now
        return True


def setup_logging(data_dir: Path, level: str) -> None:
    """Everything goes to qkvm.log in the data folder (rotated); warnings and worse also reach the terminal.

    Both are written by a thread of their own. A line is logged from wherever something happens, which is
    the thread that serves every browser and looks at every device, and that one must not wait: not for a
    disk that stalls, and not for a terminal that holds its output back (a click into a Windows console
    window does, until a key is pressed).
    """
    global _listener, _others
    stop_logging()
    formatter = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    to_file = logging.handlers.RotatingFileHandler(
        data_dir / "qkvm.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8"
    )
    to_file.setFormatter(formatter)
    handlers: list[logging.Handler] = [to_file]
    if sys.stderr is not None:  # there is no terminal when started with pythonw or as a scheduled task
        to_terminal = logging.StreamHandler()
        to_terminal.setLevel(logging.WARNING)
        to_terminal.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        to_terminal.addFilter(_Unsaid())
        handlers.append(to_terminal)
    waiting: queue.SimpleQueue[logging.LogRecord] = queue.SimpleQueue()
    _listener = logging.handlers.QueueListener(waiting, *handlers, respect_handler_level=True)
    _listener.start()
    for name in ("qkvm", "uvicorn.error"):
        logger = logging.getLogger(name)
        logger.setLevel(level.upper())
        ours = logging.handlers.QueueHandler(waiting)
        if name != "qkvm":
            # The web server writes a line for every request that is none, and for every one that asks for
            # something it does not do: requests anybody can send who reaches the port, signed in or not.
            ours.addFilter(_OnceAMinute())
        logger.handlers[:] = [ours]
        logger.propagate = False
    # What anybody else has to say (the event loop, the libraries that talk to devices, whatever is
    # installed beside them) goes the same way: to the thread that writes, into the log, which is kept to a
    # size, each kind of line once a minute; and not to the terminal (see _Unsaid). Given no place at all,
    # such a line is written to the terminal by Python itself, there and then, by the thread that logged
    # it: a traceback for every connection a device broke in the right way, and the wall standing still
    # where the terminal held its output back.
    _others = logging.handlers.QueueHandler(waiting)
    _others.setLevel(logging.WARNING)  # whatever level one of them sets for itself: at their finer levels they name what they ask (see below)
    _others.addFilter(_OnceAMinute())
    logging.getLogger().addHandler(_others)
    # Of the event loop, errors only. What it warns of is an answer sent into a connection that is gone,
    # two thousand times for a device that had that many pings answered before it hung up: at this level
    # the loop does not so much as put the line together.
    loop_says = logging.getLogger("asyncio")
    loop_says.setLevel(logging.ERROR)
    loop_says.handlers[:], loop_says.filters[:], loop_says.propagate = [], [], True
    # The libraries that talk to devices and to the alert address log, at their finer levels, the addresses
    # they ask, and those carry a device's session and the token in an alert address: warnings and worse only.
    for name in ("httpx", "httpcore", "websockets", "aiortc", "aioice"):
        logging.getLogger(name).setLevel(logging.WARNING)


def stop_logging() -> None:
    """Write what is still waiting to be logged, and close the log file."""
    global _listener, _others
    if _others is not None:
        logging.getLogger().removeHandler(_others)
        _others = None
    if _listener is not None:
        _listener.stop()
        for handler in _listener.handlers:
            handler.close()
        _listener = None


def stop_with_starter(core: Core) -> None:
    """Stop when the process that started us disappears (it holds the other end of our stdin)."""

    def watch() -> None:
        try:
            # os.read on the bare descriptor, not sys.stdin: a thread parked inside Python's
            # buffered reader makes the interpreter abort when the program exits normally.
            descriptor = sys.stdin.fileno()
            while os.read(descriptor, 1024):
                pass  # nothing is ever sent; an empty read means the other end is closed
        except (OSError, ValueError, AttributeError):
            return  # no usable stdin: nothing to watch
        log.warning("the process that started the wall is gone; stopping")
        core.exit_status = 0
        if core.stop:
            core.stop()
        time.sleep(10)
        os._exit(0)  # the web server did not wind down in time

    threading.Thread(target=watch, name="starter-watch", daemon=True).start()


def _others_read(path: Path) -> bool:
    """Whether the file there can be read by other users of this computer than its owner (False where there is none)."""
    try:
        return bool(stat.S_IMODE(path.stat().st_mode) & 0o044)
    except OSError:
        return False


def serve(core: Core, running: InstanceLock | None = None) -> int:
    """Run the wall, re-opening the listeners whenever the network settings change."""
    working = None  # where it last listened, and could
    restarted = False
    crashes: list[float] = []
    while True:
        try:
            addresses, core.missing = resolve(core.bind)
            # After a restart the previous sockets may take a moment to let go of the port.
            # (Started again by the starter, after an update: the copy that was running until a moment ago may
            # be a moment more in letting go of it as well.)
            sockets = open_sockets(addresses, core.port, wait=5.0 if restarted else 2.0 if core.supervised else 0.0)
        except BindError as ex:
            say(f"qkvm: {ex}", error=True)
            log.error("cannot listen: %s", ex)
            if working is None:
                return 2
            # New settings from the app don't work: say so there, and go back to the old ones. To where it
            # listened, that is, and to nothing else that was set then: a token that has been withdrawn
            # since stays withdrawn.
            core.bind_error = str(ex)
            listen_again_as(core.store.server, working)
            try:
                core.store.save()
            except OSError as failed:  # it listens where it did; that this is not written down is said, and nothing more
                log.error("going back to where qKVM listened before could not be saved: %s", failed)
            working = None
            continue
        working = listening_as(core.store.server)
        first, restarted = not restarted, True
        core.addresses = addresses

        certfile = keyfile = None
        if core.https:
            try:
                cert, key = core.prepare_tls(addresses)
            except (OSError, ValueError) as ex:
                log.error("the certificate for HTTPS could not be made or read: %s", ex)
                had = (core.data_dir / "tls" / "cert.pem", core.data_dir / "tls" / "key.pem")
                if first or core.tls_files is not None or not all(file.is_file() for file in had):
                    # "Could not start", like a data folder that takes no writes: not a version that does not
                    # work, for which the starter would take an installed update back.
                    where = f": {ex.filename}" if isinstance(ex, OSError) and ex.filename else ""
                    why = ex.strerror if isinstance(ex, OSError) and ex.strerror else ex
                    say(f"qkvm: the certificate for HTTPS could not be made or read ({why}{where}); qKVM was not started", error=True)
                    return 2
                # The listeners are being opened again while it runs (an address of the computer changed):
                # with the certificate it had, which may not name the new address, rather than not at all.
                cert, key = had
            certfile, keyfile = str(cert), str(key)
        core.listening = core.urls(addresses, core.port, core.https)
        log.info("listening on %s", ", ".join(core.listening))
        if running is not None:
            running.say(listening=core.listening)  # for `qkvm status`

        count = len(core.store.devices)
        say(f"qKVM {__version__} - {count} device{'' if count == 1 else 's'}")
        for url in core.listening:
            say(f"  {url}")
        say(f"  settings in {_in_full(core.data_dir)}")  # the first thing asked when something is not where it was expected
        for name in core.missing:
            say(f"  ({name}: no address yet, will start listening when it appears)")
        if core.https:
            say(f"  certificate SHA-256: {core.cert_fingerprint}")
        if core.updater.allow_unsigned and core.updater.keys:
            # Asked for, and without effect here: said, so that nobody takes an unsigned release to be let in.
            say("  --allow-unsigned-updates changes nothing: this copy has a release key built in, and installs only what that key signed.")
        if core.initialized and not core.vault.unlocked:
            # The first thing to know after a power cut: it is up, and it is watching nothing yet.
            say("  Locked: no device is looked at, and no alert sent, until somebody signs in.")
        if not core.initialized:
            say("  First run: open the address above to choose a password.")
            if core.setup_code is not None:
                say(f"  Setup code (asked for when setting up from another machine): {core.setup_code}")
                # Also in the log, for a wall started without a terminal. It stops working once setup is done.
                log.info("first run - setup code for setting up from another machine: %s", core.setup_code)
            elif any(urlsplit(url).hostname not in ("127.0.0.1", "localhost", "::1") for url in core.listening):
                # Easy by default, and said as it is: until then the wall is whoever's comes first.
                say("  Whoever opens it first chooses that password, so do it now. (Started with --setup-code, qKVM asks for a code printed here first.)")

        config = uvicorn.Config(create_app(core), ssl_certfile=certfile, ssl_keyfile=keyfile, **SERVER_OPTIONS)
        server = uvicorn.Server(config)
        core.stop = lambda server=server: setattr(server, "should_exit", True)
        core.restart_requested = False
        try:
            server.run(sockets=sockets)
        except KeyboardInterrupt:
            # Ctrl+C. The web server has closed what was open and then handed the signal on, as it does. A
            # person asked for this: it ends as any other stop does, and not in a page of traceback.
            core.restart_requested = False
        except Exception:
            # Not expected to happen. Come back up rather than leave the wall dark, unless it keeps happening.
            log.exception("the web server stopped unexpectedly")
            now = time.monotonic()
            crashes = [t for t in crashes if now - t < CRASH_WINDOW] + [now]
            if len(crashes) > MAX_CRASHES:
                say("qkvm: the web server keeps failing, giving up (see qkvm.log)", error=True)
                return 1
            core.restart_requested = True
            time.sleep(1)
        finally:
            core.stop = None
            for sock in sockets:
                sock.close()
        if core.exit_status is not None:
            # Asked to leave with a particular status: after an update, that tells the starter to run us again.
            log.info("stopping with status %s", core.exit_status)
            return core.exit_status
        if not core.restart_requested:
            log.info("stopped")
            return 0
        say("qKVM - restarting listeners")


# `start` is what it does without a word: run here, in this window, until it is stopped. The others are
# about the copy that runs already with the same data folder, from whatever window that was started in.
COMMANDS = ("start", "stop", "restart", "status")
ASK_FILE = "qkvm.ask"
ASK_PATIENCE = 25.0  # how long `qkvm stop` and `qkvm restart` wait for the running copy to do as it was asked
# A wall counts as stopped once nothing has held its lock for this long. For a moment nothing holds it either
# while a wall is being started again, and the copy that comes up does not know what was asked of the one before.
GONE_FOR = 1.5


class Asks:
    """What another `qkvm` on this computer asks of this one: to stop, or to be started again.

    It is a file in the data folder, looked for once a second by a thread of its own. No port is opened
    for it and no signal is needed, so it works the same on every system, also for a wall that was started
    without a window. Whoever may write to the data folder can do worse to the wall than stop it.
    """

    def __init__(self, data_dir: Path, core: Core) -> None:
        self.path, self.core = data_dir / ASK_FILE, core

    def look(self) -> None:
        stop = self.core.stop
        if stop is None:
            return  # between two sets of listeners: it is answered when there is something to stop
        try:
            with self.path.open("rb") as file:
                asked = file.read(16).decode("ascii", "replace").strip()  # one word; whatever else is there is not read
            self.path.unlink()
        except OSError:
            return  # nothing asked
        # Said in the window it runs in as well: whoever sits at that one did not ask for this. Done first and
        # said after: a window that is not taking what is printed to it would hold the saying, and the doing with it.
        if asked == "stop":
            self.core.exit_status = 0
            stop()
            log.info("asked to stop, by `qkvm stop`")
            say("qkvm: stopping, as asked by `qkvm stop`")
        elif asked == "restart" and self.core.supervised:  # (run without its starter, nothing would start it again)
            self.core.restart_program()
            log.info("asked to start again, by `qkvm restart`")
            say("qkvm: starting again, as asked by `qkvm restart`")

    def listen(self) -> None:
        def watch() -> None:
            while True:
                time.sleep(1.0)
                self.look()

        threading.Thread(target=watch, name="asks", daemon=True).start()


KNOWN = "elsewhere.json"  # in the folder qKVM keeps at home: the other folders walls were started with


def home_folder() -> Path | None:
    """The folder qKVM keeps at home, without a word where there is no home (a service, a container)."""
    try:
        Path.home()
    except RuntimeError:
        return None
    return default_data_dir()


def known_folders() -> list[Path]:
    """The data folders walls were started with, other than the one at home (see `remember`)."""
    home = home_folder()
    try:
        listed = json.loads((home / KNOWN).read_text(encoding="utf-8")) if home else []
    except (OSError, ValueError, RecursionError):
        return []
    return [Path(entry) for entry in listed if isinstance(entry, str)][:50] if isinstance(listed, list) else []


def remember(data_dir: Path) -> None:
    """Note, at home, that a wall was started with a folder that is somewhere else.

    `qkvm stop` typed without saying where then finds it: whoever types that means the wall they run, and
    not a folder. The note is a list of places to look, no more: whether a wall runs there is asked of the
    lock in each. A courtesy, too: where there is no home, or none to write to, it is left.
    """
    home = home_folder()
    try:
        folder = _in_full(data_dir)
        if home is None or folder == _in_full(home):
            return
        others = [known for known in known_folders() if known != folder and known.is_dir()]  # one that is gone is forgotten
        home.mkdir(mode=0o700, exist_ok=True)
        being_written = home / (KNOWN + ".new")
        being_written.write_text(json.dumps([str(folder), *(str(other) for other in others)][:50]), encoding="utf-8")
        os.replace(being_written, home / KNOWN)
    except OSError:
        pass


def running_with(folder: Path) -> InstanceLock | None:
    """The lock of the copy that runs with `folder`, if one does. OSError: the folder cannot be looked into.

    Only looked at: nothing is made or changed in a folder for having been asked about.
    """
    lock = InstanceLock(folder)
    # (Asked for a moment longer than once: another `qkvm status` may be having the same look just now.)
    return lock if folder.is_dir() and lock.held_elsewhere(patience=0.2) else None


def leave_request(folder: Path, command: str) -> None:
    """Put what is asked where the running copy looks for it: there in one piece, or not at all.

    Written under a name nobody could have put a link at beforehand, and never through one: the folder may
    be somebody else's, and whoever asks may be allowed more than they are. OSError: it could not be written.
    """
    being_written = folder / f"{ASK_FILE}.{secrets.token_hex(8)}"
    fd = os.open(being_written, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as file:
            file.write(command)
        os.replace(being_written, folder / ASK_FILE)  # a link by that name is replaced, not followed
    except OSError:
        try:
            being_written.unlink()
        except OSError:
            pass
        raise


def running_elsewhere() -> list[tuple[Path, InstanceLock]]:
    """The walls that run with a folder other than the one at home, as far as the note at home leads to them."""
    found = []
    for folder in known_folders():
        try:
            # The note outlives the folders in it. One that is somebody else's by now (made again under /tmp,
            # say) is not looked into for not having been named: to ask about it, it is named with --data-dir.
            if sys.platform != "win32" and folder.stat().st_uid != os.geteuid():
                continue
            held = running_with(folder)
        except (OSError, ValueError):  # (the second: a name no folder can have, with a zero byte in it)
            continue
        if held is not None:
            found.append((folder, held))
    return found


def who(holder: dict[str, Any] | None) -> str:
    """' (process 4321, since 21:51)', as far as the running copy said."""
    if not holder or not isinstance(holder.get("pid"), int):
        return ""
    started, when = holder.get("since"), ""
    if isinstance(started, (int, float)):
        try:
            then = time.localtime(started)
            when = time.strftime(", since %H:%M" if then[:3] == time.localtime()[:3] else ", since %Y-%m-%d %H:%M", then)
        except (OverflowError, OSError, ValueError):
            when = ""  # not a date this system has
    return f" (process {holder['pid']}{when})"


def by_hand(holder: dict[str, Any] | None) -> str:
    """How to end a running copy that does not do as it is asked."""
    pid = holder.get("pid") if holder else None
    if not isinstance(pid, int):
        return "Ctrl+C in the window it runs in"
    return f"Ctrl+C in the window it runs in, or: {'taskkill /F /T /PID' if sys.platform == 'win32' else 'kill'} {pid}"


def history_said(folder: Path) -> None:
    """What `qkvm status` says of the history kept in `folder` (what the wall saw of its machines): how large it is. Only looks."""
    size = history.size_of(folder)
    if size:
        say(f"  the history takes {history.said_size(size)} ({history.FILE})")
    count, aside = history.aside_in(folder)
    if count:
        # Left for somebody to look at, and gone by themselves once older than the history is kept.
        say(f"  and {count} {'copy' if count == 1 else 'copies'} of it that could not be read {'takes' if count == 1 else 'take'} {history.said_size(aside)} (history.damaged-*.sqlite)")
    # ...and so does the activity log: its files (the record), and its index beside them.
    text, files, index = activity.size_of(folder)
    if files:
        made = f", and its index {history.said_size(index)} ({activity.FILE})" if index else ""
        say(f"  the activity log takes {history.said_size(text)} in {files} {'file' if files == 1 else 'files'} (audit.log){made}")


def describe(where: Path, holder: dict[str, Any] | None) -> None:
    """What `qkvm status` says of one running copy."""
    version = holder.get("version") if holder else None
    say(f"qKVM{f' {version}' if isinstance(version, str) else ''} is running with {where}{who(holder)}")
    for url in (holder.get("listening") if holder else None) or []:
        say(f"  {url}")
    history_said(where)


def ask(command: str, data_dir: Path, folder_said: bool) -> int:
    """`qkvm status`, `stop` and `restart`: about, and to, the copy that runs with this data folder."""
    where = _in_full(data_dir)
    try:
        lock = running_with(data_dir)
    except OSError as ex:
        say(f"qkvm: cannot look into {where}: {ex.strerror or ex}", error=True)
        return 1
    found: Path | None = None  # the folder, where it was not named and had to be looked for
    if lock is None and not folder_said:
        # No folder was named, and nothing runs with the one at home: the walls that were started with
        # another are looked for. One of them is the one meant; of two, nobody can tell which.
        elsewhere = running_elsewhere()
        if command == "status" and elsewhere:
            for folder, held in elsewhere:
                describe(folder, held.holder())
            return 0
        if len(elsewhere) > 1:
            say(f"qkvm: more than one qKVM is running. Say which one to {command} with --data-dir:", error=True)
            for folder, held in elsewhere:
                say(f"      {folder}{who(held.holder())}", error=True)
            return 2
        if elsewhere:
            (where, lock), = elsewhere
            data_dir = found = where
    if lock is None:
        hint = ""
        if not folder_said:
            others = [str(folder) for folder in known_folders()]
            hint = f", nor with {', '.join(others)}" if others else " (settings kept elsewhere? Say where: --data-dir FOLDER)"
        if command == "restart":
            say(f"qkvm: qKVM is not running with {where}{hint}: there is nothing to restart", error=True)
            return 1
        say(f"qKVM is not running with {where}{hint}")
        if command == "status":
            history_said(data_dir)
        return 3 if command == "status" else 0  # 3: what a service manager expects of "not running"
    holder = lock.holder()
    if command == "status":
        describe(where, holder)
        return 0
    request = data_dir / ASK_FILE
    try:
        leave_request(data_dir, command)
    except OSError as ex:
        say(f"qkvm: cannot write to {where}: {ex.strerror or ex}", error=True)
        return 1
    before = holder.get("since") if holder else None
    asked = time.monotonic()
    waiting_said = False
    free_since: float | None = None
    while time.monotonic() - asked < ASK_PATIENCE:
        time.sleep(0.1)
        if command == "stop":
            try:
                taken = lock.held_elsewhere()
            except OSError:
                taken = True  # what cannot be looked at just now is not taken for gone
            if not taken:
                free_since = time.monotonic() if free_since is None else free_since
                if time.monotonic() - free_since >= GONE_FOR:
                    say(f"qKVM stopped{who(holder)}{f', which ran with {found}' if found else ''}")
                    return 0
            elif free_since is not None:
                # It let go and holds the lock again: it was being started again when it was asked, and the
                # copy that came up has thrown away what was asked of the one before. It is asked anew.
                free_since = None
                try:
                    leave_request(data_dir, command)
                except OSError:
                    pass
        else:
            # The lock is not tried for here: in the moment between the old one and the new, it would be had.
            now = lock.holder()
            if now and now.get("since") != before and now.get("listening"):
                say(f"qKVM restarted{who(now)}{f', which runs with {found}' if found else ''}")
                return 0
        if not waiting_said and time.monotonic() - asked > 4:
            # It answers within a second or two. Past that, whoever typed this is told that it is waited for.
            say(f"qkvm: waiting for the running copy{who(holder)} to {command} ...")
            waiting_said = True
    try:
        request.unlink(missing_ok=True)  # what was asked is not left lying, to be done whenever
    except OSError:
        pass
    say(f"qkvm: the running copy{who(holder)} did not {command} within {ASK_PATIENCE:.0f} seconds.", error=True)
    say(f"      It may be an older version, which does not listen for this. To end it: {by_hand(holder)}", error=True)
    return 1


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    command = argv.pop(0) if argv and argv[0] in COMMANDS else "start"
    parser = argparse.ArgumentParser(
        prog="qkvm",
        allow_abbrev=False,  # an option is its whole name: the starter reads --data-dir before this does, and has to read the same
        usage="qkvm [start|stop|restart|status] [options]",
        description="qKVM: a self-hosted screen wall and command center for IP KVMs and servers. "
        "Without a command, or with `start`, it runs here until it is stopped (Ctrl+C). The other commands are "
        "about the copy that runs already with the same data folder, whatever window it was started in: "
        "`status` says whether there is one and where it listens, `stop` ends it, `restart` has it started again.",
        epilog="Documentation: https://docs.qkvm.com",
    )
    parser.add_argument("-d", "--data-dir", help="where settings are kept (default: the folder .qkvm in your home folder)")
    parser.add_argument(
        "-b",
        "--bind",
        help="where to listen, comma separated: local, lan, tailscale, all or an IP address "
        "(overrides what is set in the app)",
    )
    parser.add_argument("-p", "--port", type=int, help="port to listen on (overrides what is set in the app)")
    parser.add_argument(
        "--log-level",
        default="info",
        choices=["debug", "info", "warning", "error"],
        help="how much is written to qkvm.log in the data folder (default: info)",
    )
    parser.add_argument(
        "--trusted-proxy",
        metavar="ADDRESS",
        help="a reverse proxy in front of qKVM, as an address or a network (10.0.0.5, 172.18.0.0/16), comma separated: "
        "it is believed about who is calling (X-Forwarded-For) and whether over HTTPS (X-Forwarded-Proto). "
        "Where none is named, a proxy on this computer is believed; once one is named, only what was named",
    )
    parser.add_argument(
        "--allow-from",
        metavar="NETWORK",
        help="answer only these addresses or networks (192.168.1.0/24, 100.64.0.0/10), comma separated, and this computer itself; "
        "anybody else is turned away before the sign-in page",
    )
    parser.add_argument(
        "--audit-syslog",
        metavar="COLLECTOR",
        help="send every entry of the activity log on to a syslog collector as it is written: host, host:port (UDP), or tcp://host:port",
    )
    parser.add_argument(
        "--sso-header",
        metavar="HEADER",
        help="sign in whoever the reverse proxy named with --trusted-proxy says it has signed in, in this header "
        "(Remote-User, X-Forwarded-User, X-authentik-username ...), as the qKVM account of that name. Not together with --locked-start",
    )
    parser.add_argument("--https", action="store_true", help="serve HTTPS from the first request, whatever the settings say (with a certificate made here)")
    parser.add_argument("--tls-cert", metavar="FILE", help="serve HTTPS with this certificate (PEM, with the chain that leads to it) instead of one made here")
    parser.add_argument("--tls-key", metavar="FILE", help="the private key of --tls-cert (PEM, without a passphrase)")
    parser.add_argument(
        "--unlock-file",
        metavar="FILE",
        help="open the saved device passwords at start with the key in this file, so that qKVM watches, alerts and answers "
        "a collector after a restart without anybody signing in. The file is kept outside the data folder (it is made if it "
        "is not there): whoever has both has the passwords. Also read from the environment variable QKVM_UNLOCK_FILE",
    )
    parser.add_argument(
        "--update-repo",
        metavar="OWNER/NAME",
        help="GitHub repository to get updates from (overrides the one built in)",
    )
    parser.add_argument(
        "--allow-unsigned-updates",
        action="store_true",
        help="for a copy built without a release key: let the app install an update checked by its checksum only (a copy with a key built in, as published ones are, installs signed releases only, with this or without)",
    )
    parser.add_argument(
        "--reset-password",
        action="store_true",
        help="forget every account and its password; the saved KVM passwords are encrypted for them and are erased too",
    )
    parser.add_argument(
        "--disable-2fa", metavar="NAME", help="switch two-factor sign-in off for this account (a lost phone)"
    )
    parser.add_argument(
        "--roll-back", action="store_true", help="go back to the version that ran before the last in-app update"
    )
    parser.add_argument(
        "--locked-start",
        action="store_true",
        help="keep no key that opens the saved device passwords: after every restart nothing is watched until somebody signs in, "
        "and a copy of the data folder is worth nothing without an account's password",
    )
    parser.add_argument(
        "--setup-code",
        action="store_true",
        help="ask whoever sets qKVM up from another computer for a code that is printed here at start (where others could reach a new wall before you do)",
    )
    parser.add_argument("--version", action="version", version=f"qkvm {__version__}")
    args = parser.parse_args(argv)

    if os.name == "posix":
        # What qKVM writes is its owner's alone, also where the folder it writes to was made by somebody
        # else and is open to more: the settings with the accounts in them, the logs, the activity log.
        os.umask(0o077)
    data_dir = Path(args.data_dir) if args.data_dir else default_data_dir()
    if command != "start":
        return ask(command, data_dir, bool(args.data_dir))
    try:
        check_startup_requirements(Path(__file__).resolve().parent, __version__)
    except UpdateError as ex:
        say(f"qkvm: {ex}", error=True)
        # A trial update installed by an older updater must fail before any settings migration. Status 1
        # lets even the original supervisor roll it back; status 2 is reserved for configuration errors.
        return 1
    lock = InstanceLock(data_dir)
    try:
        # A folder made here is its owner's alone: what is in it is not for the others who use this computer.
        data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        free = lock.acquire(patience=0.5)
    except OSError as ex:
        # Usually a folder mounted into a container that belongs to another user than the one qKVM runs as.
        say(f"qkvm: cannot keep settings in {_in_full(data_dir)}: {ex.strerror or ex}", error=True)
        say("      The folder has to be writable by the user qKVM runs as (in the container: uid 10001).", error=True)
        return 2
    if not free:
        say(f"qkvm: another copy is already running with {_in_full(data_dir)}{who(lock.holder())}", error=True)
        say(f"      Stop it with: qkvm stop{f' --data-dir {args.data_dir}' if args.data_dir else ''}   (or Ctrl+C in the window it runs in)", error=True)
        return 2
    try:
        # The process to stop is the one that started this one, where there is one: it would only start it again.
        lock.say(pid=os.getppid() if os.environ.get("QKVM_CHILD") == "1" else os.getpid(), since=time.time(), version=__version__)
        remember(data_dir)
        try:
            if os.name == "posix" and stat.S_IMODE(data_dir.stat().st_mode) & 0o022:
                # Not refused: it may be meant (a folder shared with a group that looks after the wall). But said.
                say(f"qkvm: {_in_full(data_dir)} can be written to by other users of this computer.", error=True)
                say("      Whoever can write there can stop qKVM, and can put there what it runs after an update (chmod go-w makes it yours alone).", error=True)
            if os.name == "posix" and not os.environ.get("QKVM_CONTAINER"):
                # What qKVM writes there is its owner's alone from the first byte. A folder that came back from
                # a copy (through a share, out of an archive that kept no modes) is used as it is found.
                readable = [name for name in (unlock.OWN, "qkvm.json", "qkvm.bak") if _others_read(data_dir / name)]
                if readable and stat.S_IMODE(data_dir.stat().st_mode) & 0o055:
                    say(f"qkvm: in {_in_full(data_dir)}, {', '.join(readable)} can be read by other users of this computer.", error=True)
                    say("      Together they open every saved device password (chmod -R go-rwx on the folder makes it yours alone).", error=True)
        except OSError:
            pass
        try:
            (data_dir / ASK_FILE).unlink(missing_ok=True)  # what was asked of a copy that ran before is not for this one
        except OSError:
            pass
        setup_logging(data_dir, args.log_level)
        try:
            bind = normalize(args.bind.split(",")) if args.bind else None
            unlock_file = args.unlock_file or os.environ.get("QKVM_UNLOCK_FILE") or None
            if args.sso_header is not None:
                # What it takes is said here, and not found out by the first person who is not let in.
                if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,63}", args.sso_header):
                    raise ValueError("--sso-header: that is not the name of a header (letters, digits and dashes, as in Remote-User)")
                if not networks_said("--trusted-proxy", args.trusted_proxy):
                    raise ValueError("--sso-header needs --trusted-proxy: who somebody is, is believed of a proxy that was named, and of nobody else")
                if args.locked_start:
                    raise ValueError(
                        "--sso-header cannot be had with --locked-start: whoever signs in elsewhere brings no password here, "
                        "and without a key of its own qKVM cannot open the saved device passwords"
                    )
            if args.locked_start and unlock_file:
                raise ValueError("--locked-start and --unlock-file say opposite things: one keeps no key that opens the saved passwords, the other says where it is")
            secret, key_made = unlock.secret_in(Path(unlock_file), data_dir) if unlock_file else (None, False)
            core = Core(
                data_dir,
                bind_override=bind,
                port_override=args.port,
                update_repo=args.update_repo,
                allow_unsigned_updates=args.allow_unsigned_updates,
                trusted_proxies=networks_said("--trusted-proxy", args.trusted_proxy),
                allow_from=networks_said("--allow-from", args.allow_from),
                https=args.https,
                tls_files=tls_pair(args.tls_cert, args.tls_key),
                unlock_secret=secret,
                sso_header=args.sso_header,
                audit_syslog=args.audit_syslog,
                setup_code=args.setup_code,
                locked_start=args.locked_start,
            )
        except (BindError, StoreError, ValueError) as ex:
            say(f"qkvm: {'--audit-syslog: ' if args.audit_syslog is not None and 'collector' in str(ex) else ''}{ex}", error=True)
            return 2
        except OSError as ex:
            # A disk that is full, a file something else holds: said as what it is, and as "could not start".
            # Left to end in a traceback, it would be taken for a version that does not work, and a version
            # that had just been installed would be taken back for it.
            say(f"qkvm: the data folder {data_dir} could not be read or written ({ex.strerror or ex}{f': {ex.filename}' if ex.filename else ''}); qKVM was not started", error=True)
            return 2
        # Started by `python -m qkvm`, which can start us again; a bare `python -m qkvm.cli` cannot.
        core.supervised = os.environ.get("QKVM_CHILD") == "1"
        if core.supervised and not (args.reset_password or args.disable_2fa):
            stop_with_starter(core)
        if core.store.restored:
            aside = core.store.recovered_from
            message = "the settings file could not be used; the settings were taken from its second copy, which holds what was saved last " + (
                f"(the file is kept as {aside.name}; what was wrong with it: {core.store.damage[:200] or 'not said'})" if aside else "(there was no settings file, only the copy)"
            )
            say(f"qkvm: {message}", error=True)
            log.warning(message, extra=SAID)

        if args.disable_2fa:
            account = core.store.user_named(args.disable_2fa)
            if account is None:
                say(f"qkvm: there is no account called {args.disable_2fa}", error=True)
                return 2
            account.totp, account.totp_codes, account.totp_step, account.totp_changes = None, [], 0, account.totp_changes + 1
            try:
                core.store.save()
            except OSError as ex:
                say(f"qkvm: the data folder {data_dir} could not be written ({ex.strerror or ex}); nothing was changed", error=True)
                return 2
            log.warning("two-factor sign-in switched off for %s from the command line", account.name)
            # ...and in the activity log, where whoever looks into what happened looks: an account's second step taken away is
            # one of the first things asked after an incident. (Written before the program ends: the log's writer is a thread.)
            core.audit.write("totp_disabled", "", account=account.name, note="from the command line where qKVM runs")
            core.audit.flush()
            say(f"Two-factor sign-in is off for {account.name}. Their password is unchanged.")
            return 0
        if args.reset_password:
            try:
                left = core.reset_password()
            except OSError as ex:
                say(f"qkvm: the data folder {data_dir} could not be written ({ex.strerror or ex}); nothing was changed", error=True)
                return 2
            log.warning("accounts reset from the command line")
            core.audit.write("accounts_reset", "", note="from the command line where qKVM runs: every account and every saved password erased")
            core.audit.flush()
            say("Accounts cleared. Start qKVM and open it to create the first one again, then re-enter the KVM passwords.")
            if left:
                names = ", ".join(left)
                say(f"qkvm: in {data_dir}, {names} could not be removed, and still holds the accounts and the saved passwords: remove it by hand", error=True)
                return 1
            return 0
        log.info("qkvm %s starting, data in %s", __version__, _in_full(data_dir))
        outdated = outdated_libraries()
        if outdated:
            log.warning("libraries with known vulnerabilities: %s", "; ".join(outdated.values()), extra=SAID)
            # By name: upgrading qKVM itself leaves a library alone that still meets what an older qKVM asked for.
            say(f"qkvm: these libraries have known vulnerabilities - update them with: pip install --upgrade {' '.join(outdated)}", error=True)
            for line in outdated.values():
                say(f"  {line}", error=True)
        raise_file_limit()
        if unlock_file:
            if key_made:
                log.info("made a new unlock key in %s", _in_full(Path(unlock_file)))
                say(f"qkvm: made a new unlock key in {_in_full(Path(unlock_file))}")
            if not core.container and unlock.open_to_others(Path(unlock_file)):
                log.warning("%s can be read by other users of this computer", unlock_file, extra=SAID)
                say(f"qkvm: {unlock_file} can be read by other users of this computer (chmod 600 makes it yours alone)", error=True)
        try:
            told = core.unlock_at_start()
        except OSError as ex:
            # (As above: a disk that takes no writes is "could not start", not a version that does not work.)
            say(f"qkvm: the data folder {data_dir} could not be written ({ex.strerror or ex}{f': {ex.filename}' if ex.filename else ''}); qKVM was not started", error=True)
            return 2
        if told:
            say(f"qkvm: {told}", error=True)
        Asks(data_dir, core).listen()
        return serve(core, lock)
    except KeyboardInterrupt:
        log.info("stopped")  # Ctrl+C before it was serving, or after it had stopped
        return 0
    finally:
        lock.release()
        stop_logging()


if __name__ == "__main__":
    sys.exit(main())
