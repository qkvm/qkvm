"""The activity log, sent on as it is written: to a syslog collector (RFC 5424), over UDP or TCP.

The file in the data folder stays the record. This is a copy for somebody else's collector, made as each
entry is written, so that what was done is also known somewhere that whoever did it cannot reach. It is
sent by a thread of its own and never waited for: a collector that is away loses entries (said in
qkvm.log, once a minute at most), and the file has them all.
"""

from __future__ import annotations

import json
import logging
import queue
import re
import socket
import threading
import time
from typing import Any
from urllib.parse import urlsplit

log = logging.getLogger("qkvm")

WAITING = 1000  # entries kept for a collector that is slow or away; beyond that the oldest are let go
CONNECT_WITHIN = 5.0  # seconds a TCP connection to the collector may take to come about, or to take an entry
FACILITY = 13  # "log audit", in syslog's numbering


def where(target: str) -> tuple[str, str, int]:
    """(how, host, port) for `collector`, `collector:5514`, `udp://...` or `tcp://...`. ValueError: it is none of these."""
    target = target.strip()
    try:
        parts = urlsplit(target if "://" in target else f"udp://{target}")
        host, port = parts.hostname or "", parts.port or 514
    except ValueError:
        host = ""
    usable = bool(host) and parts.scheme in ("udp", "tcp") and not (parts.path or parts.query or parts.fragment or parts.username)
    try:
        host.encode("idna")  # (a name that cannot be looked up at all, "a..example": said now, not found out at the first entry)
    except UnicodeError:
        usable = False
    if not usable or any(ch.isspace() for ch in target):
        raise ValueError(f"{target!r} is not a collector's address: write host, host:port, or tcp://host:port")
    return parts.scheme, host, port


class Syslog:
    """Sends activity-log entries to a syslog collector."""

    def __init__(self, target: str) -> None:
        self.how, self.host, self.port = where(target)
        self._waiting: queue.Queue[str] = queue.Queue(maxsize=WAITING)
        self._sender: threading.Thread | None = None
        self._starting = threading.Lock()
        self._told = 0.0  # when a failure was last written to the program's own log
        self._name = re.sub(r"[^!-~]", "-", socket.gethostname())[:255] or "-"

    def send(self, line: str) -> None:
        """Hand over one entry (a line of JSON). Returns at once, whatever the collector is doing."""
        try:
            self._waiting.put_nowait(line)
        except queue.Full:
            try:
                self._waiting.get_nowait()  # the oldest gives way to the newest
                self._waiting.put_nowait(line)
            except (queue.Empty, queue.Full):
                pass
        if self._sender is None:
            with self._starting:
                if self._sender is None:
                    self._sender = threading.Thread(target=self._send_on, name="activity-forward", daemon=True)
                    self._sender.start()

    def message(self, line: str) -> bytes:
        """One entry as a syslog message."""
        try:
            said = json.loads(line)
        except (ValueError, RecursionError):
            said = None
        entry: dict[str, Any] = said if isinstance(said, dict) else {}
        noted = entry.get("time")
        at: float = noted if isinstance(noted, (int, float)) and 0 <= noted < 1e11 else time.time()
        event = re.sub(r"[^!-~]", "_", str(entry.get("event") or "-"))[:32]
        # What went wrong is a warning to the collector; everything else is "notice".
        severity = 4 if event.endswith("_failed") else 5
        when = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(at)) + f".{int(at % 1 * 1000):03d}Z"
        return f"<{FACILITY * 8 + severity}>1 {when} {self._name} qkvm - {event} - {line.strip()}".encode()

    def _send_on(self) -> None:
        link: socket.socket | None = None
        while True:
            message = self.message(self._waiting.get())
            try:
                if self.how == "udp":
                    family = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_DGRAM)[0]
                    if link is None:
                        link = socket.socket(family[0], socket.SOCK_DGRAM)
                    link.sendto(message, family[4])
                else:
                    if link is None:
                        link = socket.create_connection((self.host, self.port), timeout=CONNECT_WITHIN)
                    link.sendall(message + b"\n")  # one message a line, as collectors take it over TCP
            except (OSError, ValueError) as ex:  # (the second: a name no lookup takes. It ended this thread, and the sending with it.)
                if link is not None:
                    link.close()
                    link = None
                if time.monotonic() - self._told > 60:
                    self._told = time.monotonic()
                    log.warning("the activity log could not be sent on to %s:%s (%s); the file has every entry", self.host, self.port, ex)
