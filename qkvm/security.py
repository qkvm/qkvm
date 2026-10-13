"""Sessions, login throttling and the request checks every route sits behind."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import queue
import re
import secrets
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from starlette.requests import Request

log = logging.getLogger("qkvm")

COOKIE = "qkvm_session"
IDLE_TTL = 12 * 3600  # a normal login ends after this long without activity
REMEMBER_TTL = 30 * 86400  # "keep this browser signed in", for wall displays

# Names that cannot be pointed at this server by someone else's public DNS.
PRIVATE_SUFFIXES = (".ts.net", ".local", ".lan", ".internal", ".home.arpa")

SECURITY_HEADERS = {
    # Everything the page needs comes from this server; nothing inline, nothing framed.
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob:; "
        "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), usb=()",
}


_HOST_HEADER = re.compile(r"(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._-]+)(:[0-9]{1,5})?")


def host_allowed(host_header: str, extra: tuple[str, ...] | list[str] = ()) -> bool:
    """DNS-rebinding guard: a web page on the internet must not be able to reach the wall.

    IP literals and private names are fine; any other DNS name has to be listed
    in the allowed_hosts setting.
    """
    # Nothing but a host name or address and an optional port. A "/" or "?" in here would let the
    # sender shift what the rest of the server takes to be the path of the request.
    if not _HOST_HEADER.fullmatch(host_header):
        return False
    try:
        host = (urlsplit(f"//{host_header}").hostname or "").rstrip(".")
    except ValueError:
        return False
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return "." not in host or host.endswith(PRIVATE_SUFFIXES) or host in extra


def same_origin(request: Request) -> bool:
    """CSRF guard for requests that change something.

    Our own page always sends the X-QKVM header, which a cross-site form
    cannot add and a cross-site script cannot add without a CORS preflight that
    this server never approves. Origin and Sec-Fetch-Site are checked as well.
    """
    if request.headers.get("x-qkvm") != "1":
        return False
    if request.headers.get("sec-fetch-site", "same-origin") not in ("same-origin", "none"):
        return False
    origin = request.headers.get("origin")
    if origin is None:
        return True
    try:
        return urlsplit(origin).netloc == request.headers.get("host", "")
    except ValueError:  # not an address at all
        return False


def same_text(a: str, b: str) -> bool:
    """Whether two strings are equal, without the time it takes giving away where they differ.

    Compared as bytes: the standard comparison refuses text with characters outside ASCII,
    and what is compared here was typed by whoever is asking.
    """
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _proxied(request: Request) -> bool:
    return any(h in request.headers for h in ("x-forwarded-for", "forwarded", "x-real-ip"))


def proxy_networks(names: Iterable[str]) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """The addresses and networks given with --trusted-proxy, as networks. ValueError for one that is neither."""
    return tuple(ipaddress.ip_network(name.strip(), strict=False) for name in names if name.strip())


def _address(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The address in one entry of X-Forwarded-For, which may carry a port or brackets. None: it is not one."""
    text = text.strip()
    if text.startswith("["):
        text = text[1:].split("]", 1)[0]
    elif text.count(":") == 1:
        text = text.split(":", 1)[0]
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    # An IPv4 caller seen through a socket that listens for both kinds arrives written the IPv6 way
    # (::ffff:192.0.2.7). It is the IPv4 address it is, for every list it is looked up in.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _believed(request: Request, address: ipaddress.IPv4Address | ipaddress.IPv6Address | None) -> bool:
    """Whether what this address says about who is calling is believed: a proxy that QKVM was told
    about when it was started; or, where it was told of none, one on this machine (`tailscale serve`).

    Any program on this machine can connect from there and say it passes on whichever address it likes:
    it then has a lock-out of its own for every guess, and the activity log names an address of its
    choosing. That is how it comes, so that a proxy on the same machine works without an option. Whoever
    names their proxies has said who is believed, and nobody else is.
    """
    if address is None:
        return False
    named = getattr(request.app.state, "trusted_proxies", ())
    if not named:
        return address.is_loopback
    return any(address in network for network in named)


def sso_name(request: Request, header: str) -> str | None:
    """Who the identity proxy in front of QKVM says has signed in there. None: nobody that QKVM would believe it of.

    Believed of a proxy that was named at start (--trusted-proxy) and of nobody else: not of this
    computer itself, where any program can connect and say what it likes. And only where the header comes
    once. A proxy that adds its line to one the visitor sent, instead of replacing it, would be passing on
    the visitor's own word about who they are.
    """
    address = _address(request.client.host) if request.client else None
    named = address is not None and any(address in network for network in getattr(request.app.state, "trusted_proxies", ()))
    said = request.headers.getlist(header) if named else []
    return said[0].strip() or None if len(said) == 1 else None


def is_local(request: Request) -> bool:
    """True for a browser on this machine talking to the wall directly (not through a proxy)."""
    address = _address(request.client.host) if request.client else None
    return address is not None and address.is_loopback and not _proxied(request)


def client_allowed(request: Request) -> bool:
    """Whether the caller is one of those QKVM was told to answer (--allow-from). Without that option: anybody.

    This computer itself is always answered, as long as nobody is being passed on through it: the
    container's own health check asks from there, and so does whoever has to put a wrong list right.
    """
    networks = getattr(request.app.state, "allowed_clients", ())
    if not networks or is_local(request):
        return True
    address = _address(client_ip(request))
    return address is not None and any(address in network for network in networks)


def client_ip(request: Request) -> str:
    """Who is calling: the address the connection comes from, or, where that is a proxy that is believed,
    the address the proxy says it is passing on."""
    host = request.client.host if request.client else "unknown"
    # Every line of that name, in the order they came. A proxy that adds a line of its own to the one a
    # visitor sent along (HAProxy does) has its word last; reading only the first line would be reading
    # the visitor's.
    forwarded = ",".join(request.headers.getlist("x-forwarded-for"))
    if not forwarded or not _believed(request, _address(host)):
        return host
    # Read from the right. Each proxy adds the address it heard from at the end, so the last one that is not
    # itself a believed proxy is the caller; anything to the left of it the caller may have written.
    for entry in reversed(forwarded.split(",")):
        address = _address(entry)
        if address is None:
            return host  # not an address: nothing in this header is to be relied on
        if not _believed(request, address):
            return str(address)
    return host


def is_secure(request: Request) -> bool:
    """Whether the browser reached QKVM over HTTPS: directly, or as far as a believed proxy that says so."""
    if request.scope.get("scheme") == "https":
        return True
    host = request.client.host if request.client else ""
    said = ",".join(request.headers.getlist("x-forwarded-proto")).rsplit(",", 1)[-1].strip().lower()  # the proxy's word is the last
    return _believed(request, _address(host)) and said == "https"


@dataclass
class Session:
    created: float  # a date: it is written down for a browser that asked to be kept, and counted over restarts
    seen: float  # when it was last used, on the clock that only goes forward: a clock put right must not keep it alive, or end it
    ttl: float
    ip: str
    user: str = ""  # id of the account that signed in
    sso: bool = False  # signed in by the identity proxy in front of QKVM, not by a password given here
    mark: str = ""  # of the account's password as it was when they signed in (see Sessions.load)
    # How old it was when this program took it up (0 for one made here), and when that was on the clock that
    # only goes forward: its age is counted from there, and a clock that is put right neither ends it nor keeps it.
    aged: float = 0.0
    since: float = 0.0
    taken_up: bool = False  # it was made by an earlier run of this program, and read back from what that one wrote down

    def age(self) -> float:
        return self.aged + time.monotonic() - self.since


MOST_KEPT = 500  # browsers that are written down to outlast a restart; a wall has a handful
MOST_OF_ONE = 100  # sign-ins of one account at a time: the oldest goes when one more comes
MOST_KEPT_OF_ONE = 20  # of which this many are written down to outlast a restart (the newest); a person has a handful of browsers
TRY_AGAIN = 60.0  # seconds before writing them down is tried again after it failed, where nothing else has changed


class Sessions:
    """Logged-in browsers.

    In memory, and a restart signs everyone out, except those that asked to be kept ("keep this browser
    signed in for 30 days"): where a file is named to keep them in, they are written down and outlast a
    restart. What is written is what is held here: a hash of each cookie, never the cookie, so the file
    cannot be replayed as sign-ins. Written by a thread of its own; nobody who signs in waits for a disk.

    A sign-out is another matter: it is not done until what is on disk no longer names that browser,
    or whoever kept a copy of its cookie would be let in with it after a restart. Whoever ends a
    sign-in waits for that (`settled`), and where the file can be neither written anew nor taken
    away, is told so.
    """

    def __init__(self, kept_in: Path | None = None) -> None:
        self._sessions: dict[str, Session] = {}
        self._file = kept_in
        self._asked: dict[str, list[Any]] = {}  # what the writer was last handed
        self._behind = False  # the last write failed: what is held here is handed over again at the next occasion
        self._tried = 0.0  # ...and this is when that was
        self._stale: str | None = None  # why what is on disk may still name a browser that has signed out; None: it does not
        self._waiting: queue.Queue[str] = queue.Queue()
        self._writer: threading.Thread | None = None
        self._starting = threading.Lock()

    def load(self, still_good: Callable[[str, str], bool]) -> None:
        """Take up again the browsers that were written down, as far as each is still to be let in.

        `still_good(account id, mark)`: whether that account is there, may sign in, and has the password
        it had then. Asked of what is saved now, and not of this file: that an account's password was
        changed, or the account suspended or removed, holds whether or not the file was written since.
        """
        if self._file is None:
            return
        # What the file names, as far as that can be told. Whatever of it is not taken up here is taken out of
        # it now: left in, a later start could take it up after all (the clock was behind at this one, say),
        # whoever signed out in between and was told that it was done.
        unreadable: dict[str, list[Any]] = {"": []}  # equal to nothing that is ever written
        try:
            with self._file.open("rb") as fh:
                kept = json.loads(fh.read(1_000_000))
        except FileNotFoundError:
            return
        except (OSError, ValueError, RecursionError):
            kept = None
        now = time.time()
        for key, said in list(kept.items())[:MOST_KEPT] if isinstance(kept, dict) else []:
            if not (isinstance(key, str) and re.fullmatch(r"[0-9a-f]{64}", key) and isinstance(said, list) and len(said) == 3):
                continue
            created, user, mark = said
            if not (isinstance(created, (int, float)) and not isinstance(created, bool) and isinstance(user, str) and isinstance(mark, str)):
                continue
            if not 0 <= created < 1e11:  # (not a date: a number of hundreds of digits is no float at all)
                continue
            if 0 <= now - created <= REMEMBER_TTL and mark and still_good(user, mark):
                self._sessions[key] = Session(float(created), time.monotonic(), REMEMBER_TTL, "", user, False, mark, now - created, time.monotonic(), True)
        self._asked = kept if isinstance(kept, dict) else unreadable
        self._keep()

    def _to_keep(self) -> dict[str, list[Any]]:
        """What of this outlasts a restart: people who asked for it. Not a wall screen (its link signs it in again), nor who a proxy vouched for."""
        # (Each with its place in the order they were made in: where the clock ticks coarsely, several are made at
        # "the same time", and which of those is the newer is then said by that, not by chance.)
        kept = [(s.created, place, key, s) for place, (key, s) in enumerate(self._sessions.items()) if s.ttl == REMEMBER_TTL and s.mark and not s.sso and not s.user.startswith("token:")]
        # No more than are read back (the newest, where there are more): a file too long to be read is nobody's
        # sign-in. And of one account only so many, so that a few accounts cannot fill it between them and
        # leave everybody else to sign in again after a restart.
        kept.sort(key=lambda entry: entry[:2], reverse=True)
        of_one: dict[str, int] = {}
        chosen = []
        for entry in kept:
            of_one[entry[3].user] = of_one.get(entry[3].user, 0) + 1
            if of_one[entry[3].user] <= MOST_KEPT_OF_ONE:
                chosen.append(entry)
        return {key: [s.created, s.user, s.mark] for _, _, key, s in chosen[:MOST_KEPT]}

    def _keep(self) -> None:
        """Have what outlasts a restart written down, if it is not what was written last."""
        if self._file is None:
            return
        kept = self._to_keep()
        # (What failed is tried again, at a change or else once in a while: not at every occasion there is.)
        if kept == self._asked and not (self._behind and time.monotonic() - self._tried > TRY_AGAIN):
            return
        self._asked = kept
        self._waiting.put(json.dumps(kept))
        if self._writer is None:
            with self._starting:
                if self._writer is None:
                    self._writer = threading.Thread(target=self._write_on, name="kept-sign-ins", daemon=True)
                    self._writer.start()

    def _write_on(self) -> None:
        while True:
            text = self._waiting.get()
            try:
                self._write(text)
            finally:
                self._waiting.task_done()

    def _write(self, text: str) -> None:
        kept_in = self._file
        if kept_in is None:
            return
        try:
            # In one piece or not at all, and its owner's alone from the first byte.
            being_written = kept_in.with_name(kept_in.name + ".new")
            descriptor = os.open(being_written, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(descriptor, "w", encoding="ascii") as fh:
                fh.write(text)
                fh.flush()
                os.fsync(fh.fileno())  # on the disk, not on its way there: a sign-out answered as done is done
            os.replace(being_written, kept_in)
        except OSError as ex:
            why = ex.strerror or type(ex).__name__
            try:
                os.unlink(being_written)  # nothing half-written is left lying
            except OSError:
                pass
        else:
            if self._behind:
                log.info("who is kept signed in over a restart is written down again")
            self._behind, self._stale = False, None
            return
        # What is on disk is what was written before, and may name a browser that has signed out since: a
        # restart would let it in again. It cannot be replaced (a full disk, most likely), so it is taken
        # away, which needs no room. Whoever asked to be kept signs in once more after a restart: nothing worse.
        first, self._behind, self._tried = not self._behind, True, time.monotonic()
        try:
            os.unlink(kept_in)
        except FileNotFoundError:
            self._stale = None
        except OSError:
            self._stale = why
        else:
            self._stale = None
        if first:  # said once, not at every attempt while the disk stays as it is
            log.warning(
                "Who is kept signed in over a restart could not be written down (%s); what was written before %s",
                why, "could not be taken away either" if self._stale else "was taken away, so nobody is, until it can be",
            )  # fmt: skip

    def settled(self, within: float = 10.0) -> str | None:
        """Wait until what was to be written down has been dealt with; for whoever ends a sign-in. Not for the event loop.

        None: nothing on disk names a browser that has signed out since. Otherwise, why that could not be
        seen to: a restart would then let such a browser in again, and whoever signed out is to be told.
        Waits `within` seconds at the most: a disk that does not answer must not hold a thread for good,
        one for every sign-out, until there is none left for anything else.
        """
        if self._writer is not None:
            give_up = time.monotonic() + within
            with self._waiting.all_tasks_done:
                while self._waiting.unfinished_tasks:
                    left = give_up - time.monotonic()
                    if left <= 0:
                        return "the disk does not answer"
                    self._waiting.all_tasks_done.wait(left)
        return self._stale

    @property
    def stale(self) -> bool:
        """Whether what is on disk is known to name a browser that should not be let in again, and could not be put right."""
        return self._stale is not None

    def flush(self, within: float = 10.0) -> str | None:
        """Wait until what was to be written down is (before the program ends: a sign-out is not to come back).

        For `within` seconds and no longer, like `settled`, whose answer this hands on: None once it is on
        disk, and otherwise why it is not. Coming back is not a promise that it is written: a disk slow
        enough was still being written to, and what read the file next read what was there before.
        """
        if self._behind:
            self._tried = 0.0
            self._keep()  # one more try at what failed
        return self.settled(within)

    def kept(self, token: str | None) -> bool:
        """Whether the browser holding `token` is one that is written down to outlast a restart."""
        return bool(token) and self._key(str(token)) in self._to_keep()

    def of_the_kept_kind(self, token: str | None) -> bool:
        """Whether the browser holding `token` is one that asked to be kept signed in, written down at this moment or not."""
        session = self._sessions.get(self._key(str(token))) if token else None
        return session is not None and session.ttl == REMEMBER_TTL and bool(session.mark) and not session.sso and not session.user.startswith("token:")

    def any_kept(self, user: str, keep: str | None = None) -> bool:
        """Whether any browser of this account is, the one holding `keep` aside."""
        aside = self._key(keep) if keep else None
        written = self._to_keep()
        return any(session.user == user and key != aside and key in written for key, session in self._sessions.items())

    def carry_over(self, token: str | None, mark: str) -> None:
        """The browser holding `token` stays signed in although what its account signs in with was changed (it was changed there).

        After a restart a browser is let in again by the mark of what it signed in with: so it is given the new one.
        """
        session = self._sessions.get(self._key(token)) if token else None
        if session is not None:
            session.mark = mark
            self._keep()

    def carry_all(self, user: str, mark: str) -> None:
        """Every browser of this account stays signed in: what was changed asks less of them than they gave (the second step was switched off)."""
        for session in self._sessions.values():
            if session.user == user and session.mark:
                session.mark = mark
        self._keep()

    def forget_kept(self, for_good: bool = True) -> None:
        """What was written down to outlast a restart is taken away. `for_good`: and nothing is written down from here on.

        Where the file can be neither removed nor emptied, it still names browsers that a later start would
        let in again, whoever signs out meanwhile: said in the log, and to whoever signs out (see `settled`).
        """
        kept_in = self._file
        if kept_in is not None:
            try:
                os.unlink(kept_in)
            except FileNotFoundError:
                pass
            except OSError as ex:
                why = ex.strerror or type(ex).__name__
                try:
                    with open(kept_in, "w", encoding="ascii") as fh:  # what cannot be removed can often still be emptied
                        fh.write("{}")
                except OSError:
                    self._stale = why
                    log.error("who was kept signed in over a restart is written in %s, which could be neither removed nor emptied (%s)", kept_in, why)
        if for_good:
            self._file = None
        self._asked = {}

    @staticmethod
    def _key(token: str) -> str:
        # Only a hash is kept, so a memory dump of this table cannot be replayed as cookies.
        return hashlib.sha256(token.encode()).hexdigest()

    def __len__(self) -> int:
        self.prune()
        return len(self._sessions)

    def create(self, ip: str, remember: bool, user: str = "", sso: bool = False, mark: str = "") -> str:
        token = secrets.token_urlsafe(32)
        now = time.monotonic()
        if user and sum(1 for session in self._sessions.values() if session.user == user) >= MOST_OF_ONE:
            # Somebody signing in over and over, each time kept: without an end to it, the file of them grew
            # past what is read back, and then nobody's browser was taken up after a restart.
            own = sorted((s.created, place, k) for place, (k, s) in enumerate(self._sessions.items()) if s.user == user)
            for _, _, key in own[: len(own) - MOST_OF_ONE + 1]:
                del self._sessions[key]
        self._sessions[self._key(token)] = Session(time.time(), now, REMEMBER_TTL if remember else IDLE_TTL, ip, user, sso, mark, 0.0, now)
        self._keep()
        return token

    def get(self, token: str | None) -> Session | None:
        if not token:
            return None
        key = self._key(token)
        session = self._sessions.get(key)
        if session is None:
            return None
        now = time.monotonic()
        if now - session.seen > session.ttl or self._too_old(session):
            del self._sessions[key]
            self._keep()
            return None
        session.seen = now
        return session

    @staticmethod
    def _too_old(session: Session) -> bool:
        """Past the longest a sign-in lasts.

        By the clock that only goes forward, counted from when it was made or taken up: a clock that is put
        right neither ends it nor keeps it alive. One that was taken up from an earlier run is held to its
        date as well: a computer that started with its clock behind, and had it put right a moment later,
        took up as new what was a month old. (So a clock that jumps a month ahead ends those, and they sign
        in again; a sign-in made in this run is not touched by it.)
        """
        return session.age() > REMEMBER_TTL or (session.taken_up and time.time() - session.created > REMEMBER_TTL)

    def drop(self, token: str | None) -> None:
        if token:
            self._sessions.pop(self._key(token), None)
            self._keep()

    def keep_newest(self, user: str, most: int) -> None:
        """Leave an account (or a display link) at most `most` of its sessions: the ones made last."""
        own = sorted((s.created, k) for k, s in self._sessions.items() if s.user == user)
        for _, key in own[: max(0, len(own) - most)]:
            del self._sessions[key]
        self._keep()

    def drop_user(self, user: str, keep: str | None = None) -> int:
        """Sign an account out everywhere, except in the browser holding the token `keep`. Returns how many were signed out."""
        kept = self._key(keep) if keep else None
        before = len(self._sessions)
        self._sessions = {k: s for k, s in self._sessions.items() if s.user != user or k == kept}
        self._keep()
        return before - len(self._sessions)

    def counts(self) -> dict[str, int]:
        """How many browsers each account is signed in from."""
        self.prune()
        totals: dict[str, int] = {}
        for session in self._sessions.values():
            totals[session.user] = totals.get(session.user, 0) + 1
        return totals

    def prune(self) -> None:
        now = time.monotonic()
        self._sessions = {k: s for k, s in self._sessions.items() if now - s.seen <= s.ttl and not self._too_old(s)}
        self._keep()


@dataclass
class _Guesses:
    by_account: dict[str, int]  # wrong guesses, by the account they were made at ("": at nobody's in particular)
    locked_until: float = 0.0
    last: float = 0.0


class Limiter:
    """Locks an address out for longer and longer after repeated wrong passwords."""

    FREE = 5  # failures before the first lockout
    BASE = 30.0  # first lockout, doubling each further failure
    LONGEST = 900.0
    FORGET = 3600.0

    def __init__(self) -> None:
        self._failures: dict[str, _Guesses] = {}

    @staticmethod
    def counted_as(ip: str) -> str:
        """What the guesses from `ip` are counted under, for whoever has to treat as one what this does."""
        return Limiter._key(ip)

    @staticmethod
    def _key(ip: str) -> str:
        """What is counted together: one IPv4 address, or the whole /64 an IPv6 address is in. Whoever has
        one IPv6 address has every other one of its network to make the next guess from."""
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return ip
        if isinstance(address, ipaddress.IPv6Address):
            if address.ipv4_mapped is not None:
                return str(address.ipv4_mapped)
            return str(ipaddress.ip_network((address, 64), strict=False))
        return str(address)

    def retry_after(self, ip: str) -> float:
        key = self._key(ip)
        entry = self._failures.get(key)
        if entry is None:
            return 0.0
        if time.monotonic() - entry.last > self.FORGET:
            del self._failures[key]
            return 0.0
        return max(0.0, entry.locked_until - time.monotonic())

    def fail(self, ip: str, account: str = "") -> None:
        """One more wrong guess from this address, at this account's password or code."""
        now = time.monotonic()
        if len(self._failures) > 10_000:
            self._failures = {k: v for k, v in self._failures.items() if now - v.last <= self.FORGET}
        entry = self._failures.setdefault(self._key(ip), _Guesses({}))
        account = account.lower()[:64]
        if account not in entry.by_account and len(entry.by_account) >= 50:
            account = ""  # names made up by the dozen are counted without being kept
        entry.by_account[account] = entry.by_account.get(account, 0) + 1
        count = sum(entry.by_account.values())
        # (The doubling is stopped where it no longer matters: left to run, it outgrows what a number can hold.)
        lock = min(self.LONGEST, self.BASE * 2 ** min(count - self.FREE, 32)) if count >= self.FREE else 0.0
        entry.locked_until, entry.last = now + lock, now

    def reset(self, ip: str, account: str) -> None:
        """This account signed in from this address: its own slips are forgotten.

        Only its own. Guesses made from the same address at another account stay counted, or anybody
        with an account could guess at the admin's for ever by signing in as themselves in between.
        """
        key = self._key(ip)
        entry = self._failures.get(key)
        if entry is None:
            return
        entry.by_account.pop(account.lower()[:64], None)
        if not entry.by_account:
            del self._failures[key]
