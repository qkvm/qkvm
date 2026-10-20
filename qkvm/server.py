"""FastAPI app: setup and login, the wall page, device management and the proxy to the KVMs."""

from __future__ import annotations

import asyncio
import contextvars
import csv
import dataclasses
import hashlib
import io
import json
import logging
import math
import os
import re
import secrets
import shutil
import tempfile
import threading
import time
import unicodedata
import weakref
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, Literal, TypeVar
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, Query, Request, WebSocket
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse
from pydantic import BaseModel, Field, field_validator
from starlette.requests import ClientDisconnect

from . import about, activity, alerts, amt, discover, exchange, history, live, metrics, proxmox, qr, totp, vncdevice
from ._version import __version__
from .core import Core, DeviceManager, auth_mark, driver_for, identity
from .kvm import FINGERBOT_PRESSES, KEYS, MAX_PROBE, MAX_TEXT, PRESS_ANSWERED, PRESS_SENT, REJECTED, RETIRED, AlreadySo, Device, KvmError, bounded, can_do, fetch_certificate, fingerprint, listens, other_way, plain, publicly_trusted, read_json, saved_fingerprint
from .netbind import BindError, lan_ip, normalize, resolve, tailscale_ip
from .security import (
    COOKIE,
    REMEMBER_TTL,
    SECURITY_HEADERS,
    client_allowed,
    client_ip,
    host_allowed,
    is_local,
    is_secure,
    same_origin,
    same_text,
    sso_name,
)
from .store import FINGERBOT_STRENGTHS, ROLES, ActionRecord, AuditLog, DeviceRecord, TokenRecord, UserRecord, as_a_line, device_url
from .update import UpdateError
from .vault import NoMemory, Vault, VaultLocked, new_recovery_key, tidy_recovery_key

log = logging.getLogger("qkvm")
STATIC = Path(__file__).parent / "static"
ASSET_TYPES = {
    "index.html": "text/html; charset=utf-8",
    "app.js": "text/javascript",
    "app.css": "text/css",
    "theme.js": "text/javascript",
    "favicon.svg": "image/svg+xml",
    # The words the page shows for a state, a device's trouble and a kind of device, and every code the wall
    # answers with: one file, read by the page, and by the other programs that talk to a wall when they are built.
    "words.json": "application/json",
}
# Answered without a session. (/metrics asks for a token of its own instead: see there.)
# The API has a version in its path, /api/v1/..., since before the first release: what a script or another
# program was written against goes on working when the API changes, because a change that would break it
# gets a path of its own (/api/v2/...) beside this one. Within a version, things are added and none is
# taken away or given another meaning. The page asks the same routes; it comes with the program and is
# never older or newer than it.
API_VERSIONS = ("v1",)

PUBLIC = {"/", "/healthz", "/metrics", "/api/v1/session", "/api/v1/setup", "/api/v1/login", "/api/v1/recover", "/api/v1/display"}
MAX_BODY = 64 * 1024  # nothing the page sends is larger; anything bigger is refused unread
# ...but for a file that is handed in to be read: as large as such a file may be, written as a string inside a request.
MAX_FILE_BODY = 2 * exchange.MAX_FILE + MAX_BODY
_FILES = ("/api/v1/import", "/api/v1/import/read")  # the requests that carry one (admins only, like all that is not listed otherwise)
MOST_TWINS = 12  # other tiles that a tile is told are the same device
MOST_NAMED = 200  # devices a file brought that are each written into the activity log; beyond that, their number
BODY_TIMEOUT = 20.0  # seconds a request may take to arrive in full
SAVE_WITHIN = 10.0  # seconds a sign-out waits to be written down, before it says that it was not
MIN_PASSWORD = 10
DISPLAY_SESSIONS = 10  # browsers one display link keeps signed in at a time; one more, and the oldest gives way
MAX_PASSWORD_CHECKS = 6  # scrypt runs queued at once; each one holds ~130 MB
UPDATE_CHECK_EVERY = 24 * 3600.0
BACKGROUND_OWED = 5.0  # seconds a stopping wall gives what a request set going to finish (see lifespan)
HOUSEKEEPING_EVERY = 30.0  # seconds between the rounds that tidy up, lock up, and look whether the addresses are still the same
HISTORY_LOOK_EVERY = 60.0  # seconds between the looks the history takes at every machine by itself (see history.py)
HISTORY_READS_AT_ONCE = 3  # reads of the history under way at once, from everybody together; beyond that: come back in a moment
# Of one account or token, one read of the history at a time: the next waits its turn for so many seconds at the most
# (with one waiting already, or longer than that: come back in a moment). And after a read the same one waits as long
# as that read took before its next begins. A viewer whose script asked again and again had the three reads to itself,
# and everybody else was told to come back.
HISTORY_TURN_WAIT = history.READ_WAIT + history.READ_PATIENCE
HISTORY_TURNS_KEPT = 256  # accounts and tokens whose last turn is remembered, before those that are done with it are let go of
# The activity log is read by the same rule (W4b's): so many reads at once from everybody together, one at a time of each
# account, and after a read the same one waits as long as it took. A read waits for the index for CATCH_UP at the most,
# and then reads the text files where the index is behind.
ACTIVITY_READS_AT_ONCE = 3
ACTIVITY_TURN_WAIT = activity.CATCH_UP + activity.READ_PATIENCE
SPOOL_IN_MEMORY = 8_000_000  # bytes of a download of the activity log made in memory; beyond that in a temporary file in the data folder
DOWNLOADS_AT_ONCE = 3  # downloads of the activity log made or being sent at once, from everybody together (one of each account)
# The actions the history keeps as power events, pressed from the wall. The rest (keys, text) is the activity log's.
POWER_ACTIONS = frozenset({"atx_power", "atx_power_long", "atx_reset", "fingerbot_power", "fingerbot_power_long", "power_on", "power_off", "bios_setup", "wol", "reboot"})
# Hostnames every device has out of the box; useless as a tile name.
GENERIC_NAMES = {"", "glkvm", "pikvm", "localhost", "localhost.localdomain"}


USER_NAME = r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,63}$"  # also what an identity provider calls somebody: olga@example.org
IDENT = re.compile(r"[a-z]{2,12}:[0-9a-f]{16,64}")  # what a driver may say a device is: a kind of mark, and a digest
RANK = {role: rank for rank, role in enumerate(reversed(ROLES))}  # viewer 0, operator 1, admin 2
_DEVICE = r"/api/v1/devices/[^/]+"
_VIEWER = re.compile(
    rf"GET (/api/v1/wall|/api/v1/status|/api/v1/about|{_DEVICE}/snapshot|{_DEVICE}/history)|POST (/api/v1/logout|/api/v1/password|/api/v1/totp/(begin|enable|disable|codes)|{_DEVICE}/live)"
)
# What an account does for itself. A token is nobody's account: it has no password to change or to be asked for.
_OWN_ACCOUNT = re.compile(r"POST /api/v1/(password|totp/(begin|enable|disable|codes))")
# All that an account can do while it has to set up two-factor sign-in and has not: set it up, or leave.
_ENROLLING = re.compile(r"POST /api/v1/(logout|totp/(begin|enable))")
_OPERATOR = re.compile(rf"GET (/api/v1/actions|{_DEVICE}/wol)|POST {_DEVICE}/(actions|console)")

# Requests that change what is saved: accounts, KVMs, saved actions, settings. They are handled one at
# a time, so that no two can interleave a check ("is that name free?") with each other's write.
# Running an action on a KVM, signing in and looking for updates are not among them: those can take long.
# Nor are adding a KVM, changing one and trusting its certificate, which talk to the KVM first (that can
# take seconds, and must not make every other change wait). Those take the same turn themselves, for
# the part that changes what is saved: see `one_change` in their handlers.
_CHANGES = re.compile(
    r"(POST|PUT|DELETE) /api/v1/(setup|recover|recovery|password|totp/(enable|disable|codes)|users(/[^/]+)?"
    r"|actions(/[^/]+)?|settings|alerts(/pause)?|update|metrics/token|security|tokens(/[^/]+)?|wall/order)|DELETE /api/v1/devices/[^/]+"
    r"|POST /api/v1/devices/remove"
)

# What no path of this program has in it: a character that is none (a line feed, a tab, a zero).
_NO_PATH = re.compile("[\x00-\x1f\x7f]")

# The name of whoever is making the request being handled, for the activity log.
acting: contextvars.ContextVar[str] = contextvars.ContextVar("acting", default="")


def required_role(method: str, path: str) -> str:
    """The least role that may make this request. Whatever is not listed here takes an admin."""
    call = f"{method} {path}"
    if _VIEWER.fullmatch(call):
        return "viewer"
    if _OPERATOR.fullmatch(call):
        return "operator"
    return "admin"


# (What the activity log's entries are about, for whoever wants to see one kind of them, is activity.KINDS.)
AUDIT_COLUMNS = ("time", "event", "user", "ip", "device", "action")  # a column each in the table; the rest of an entry goes into one


def audit_table(entries: list[dict[str, Any]], heading: bool = True) -> str:
    """The entries as a table for a spreadsheet (CSV): with its heading, or (a later page of one) without."""

    def cell(value: Any) -> str:
        text = "" if value is None else str(value)
        # A spreadsheet runs what begins like a formula, and device names are not ours to choose: such a cell is made text.
        return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text

    out = io.StringIO()
    table = csv.writer(out, lineterminator="\n")
    if heading:
        table.writerow([*AUDIT_COLUMNS, "more"])
    for entry in entries:
        at = entry.get("time")
        when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(at)) if isinstance(at, (int, float)) and 0 <= at < 1e11 else ""
        rest = {key: value for key, value in entry.items() if key not in AUDIT_COLUMNS}
        table.writerow([when, *(cell(entry.get(name)) for name in AUDIT_COLUMNS[1:]), cell(json.dumps(rest, ensure_ascii=False, sort_keys=True)) if rest else ""])
    return out.getvalue()


class Attributed:
    """The activity log, with the name of whoever is signed in added to each entry."""

    def __init__(self, log: AuditLog) -> None:
        self._log = log

    def write(self, event: str, ip: str, **detail: Any) -> None:
        if "user" not in detail and acting.get():
            detail = {"user": acting.get(), **detail}
        self._log.write(event, ip, **detail)

    def tail(self, limit: int, wanted: Callable[[dict[str, Any]], bool] | None = None) -> list[dict[str, Any]]:
        return self._log.tail(limit, wanted)

    def flush(self, within: float = 5.0) -> None:
        self._log.flush(within)

    @property
    def missing(self) -> dict[str, Any] | None:
        """What is known of entries that could not be written (see store.AuditLog). None: all were."""
        return self._log.missing


class SetupIn(BaseModel):
    name: str = Field("admin", pattern=USER_NAME)
    password: str = Field(min_length=MIN_PASSWORD, max_length=256)
    setup_code: str = Field("", max_length=32)


class LoginIn(BaseModel):
    name: str = Field("", max_length=64)  # may be left out while there is only one account
    password: str = Field(max_length=256)
    code: str = Field("", max_length=24)  # from the authenticator app, or a one-time code, for accounts with two-factor sign-in
    remember: bool = False


def _group_names(names: list[str]) -> list[str]:
    """The groups an account or a token is limited to, each a line as a group's name is one (a device's
    is: DeviceIn). Unasked, half a character in one was saved, and the list of accounts was an error from
    then on. (How long one is, and that each is there once, is seen to where they are kept: tidy_groups.)"""
    kept = []
    for name in names:
        line = as_a_line(name.strip())  # (what is around it is no part of it: as for a device's group, and every other name)
        if line is None:
            raise ValueError("a group's name has to be one line: no line breaks or control characters, and nothing that turns the direction of the writing round")
        kept.append(line)
    return kept


class UserIn(BaseModel):
    _groups = field_validator("groups")(_group_names)
    name: str = Field(pattern=USER_NAME)
    role: Literal["admin", "operator", "viewer"]
    password: str = Field("", max_length=256)  # empty on an edit means "keep the current one"
    devices: list[str] | None = Field(None, max_length=500)  # the KVMs they may see; None: all
    groups: list[str] = Field(default_factory=list, max_length=100)  # and every KVM of these groups, now and later
    suspended: bool | None = None  # cannot sign in until this is lifted; None: as it was
    totp_off: bool = False  # on an edit: switch their two-factor sign-in off (a lost phone)


class AlertsIn(BaseModel):
    enabled: bool
    webhook: str = Field("", max_length=500)  # empty means "keep the saved one"
    forget_webhook: bool = False
    format: Literal["auto", "json", "ntfy", "slack", "discord"] = "auto"
    offline: bool = True
    no_signal: bool = True
    problem: bool = True
    recovered: bool = True
    link: str | None = Field(None, max_length=300)  # the wall's own address, for alerts to point at; None: as it was


class OrderIn(BaseModel):
    ids: list[str] = Field(max_length=5000)  # device ids, first to last


class RemoveIn(BaseModel):
    # The machines to take off the wall, all of them or none. Each an id as this program gives them and its settings
    # file takes them (store._ID): what is no id at all is refused here, and never written back into an answer.
    ids: list[Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")]] = Field(min_length=1, max_length=5000)


class TokenIn(BaseModel):
    _groups = field_validator("groups")(_group_names)
    name: str = Field(min_length=1, max_length=60)
    kind: Literal["api", "display"] = "api"
    role: Literal["viewer", "operator"] = "viewer"  # never an admin: what manages qKVM itself takes a person
    devices: list[str] | None = Field(None, max_length=1000)  # the KVMs it is for; None: all of them
    groups: list[str] = Field(default_factory=list, max_length=100)  # and every KVM of these groups, now and later
    days: int | None = Field(None, ge=1, le=3650)  # how long it works; None: until it is taken back


class DisplayIn(BaseModel):
    key: str = Field(max_length=100)


class SecurityIn(BaseModel):
    require_totp: Literal["", "admin", "operator", "viewer"]  # who has to have two-factor sign-in: that role and above


LONGEST_PAUSE = 7 * 24 * 60  # minutes alerts can be paused for


class PauseIn(BaseModel):
    minutes: int = Field(ge=0, le=LONGEST_PAUSE)  # 0: send again from now


class RecoverIn(BaseModel):
    name: str = Field("", max_length=64)  # may be left out while there is only one account
    recovery_key: str = Field(max_length=80)
    new_password: str = Field(min_length=MIN_PASSWORD, max_length=256)


class TotpBeginIn(BaseModel):
    password: str = Field(max_length=256)  # turning it on or off asks for the password again


class TotpEnableIn(BaseModel):
    code: str = Field(max_length=12)


class LogoutIn(BaseModel):
    scope: Literal["this", "others", "all"] = "this"


class PasswordIn(BaseModel):
    current: str = Field(max_length=256)
    new: str = Field(min_length=MIN_PASSWORD, max_length=256)


def _a_line(most: int, needed: bool = False, otherwise: str = "", one_blank: bool = False) -> Callable[[str], str]:
    """The check of what is kept as a name, by the rule a file is read by (store.as_a_line; exchange._short):
    what a wall takes it also takes back.

    As a file's: without the blanks around it and without what is not seen, and only then counted (counted
    as it was typed, eighty letters with a blank of no width among them were too long for the form and not
    for a file). `needed`: a blank is no name. `otherwise`: what a blank stands for. `one_blank`: a run of
    blanks is one blank, as a group's name is kept (a name keeps the blanks it was typed with, a no-break
    one or a wide one among them).
    """

    def kept(value: str) -> str:
        line = as_a_line(value.strip())
        if line is None:
            raise ValueError("this has to be one line: no line breaks or control characters, and nothing that turns the direction of the writing round")
        line = " ".join(line.split()) if one_blank else line.strip()
        if len(line) > most:
            raise ValueError(f"this may have {most} characters at the most")
        if needed and not line:
            raise ValueError("a name is needed")
        return line or otherwise

    return kept


class DeviceIn(BaseModel):
    _name = field_validator("name")(_a_line(80))
    _group = field_validator("group")(_a_line(40, one_blank=True))
    _user = field_validator("username")(_a_line(64, otherwise="admin"))  # (a blank: the one every device comes with, as a file has it)
    name: str = Field("", max_length=4 * 80)  # (how long it may be is asked above, of the name as it is kept)
    url: str = Field(min_length=1, max_length=255)
    username: str = Field("admin", min_length=1, max_length=4 * 64)
    password: str = Field("", max_length=256)  # empty on an edit means "keep the saved one"
    open_url: str = Field("", max_length=255)
    # How the device's certificate is checked. None: as it was (an edit), or as suits the device (a new one).
    tls: Literal["pinned", "system", "insecure"] | None = None
    # "auto": ask the device what it is; "vnc": a VNC server, which is not asked; "proxmox": a guest of Proxmox VE, named by its address
    kind: Literal["auto", "kvmd", "jetkvm", "redfish", "amt", "vnc", "proxmox"] = "auto"
    group: str = Field("", max_length=4 * 40)
    alerts: bool | None = None  # whether anybody is told when it changes; None: as it was (told, for a new one)
    # How hard a Fingerbot paired with the KVM presses its power button; None: as it was ("firm", for a new one).
    fingerbot_strength: Literal["firm", "light"] | None = None
    force: bool = False  # save even though the device could not be checked
    keep_both: bool = False  # it is the same device as one already on the wall, and is to have a tile of its own all the same


class ProxmoxIn(BaseModel):
    """A Proxmox, and the API token to list its guests with (see POST /api/v1/proxmox/guests)."""

    _user = field_validator("username")(_a_line(64, otherwise="admin"))
    url: str = Field(min_length=1, max_length=255)
    username: str = Field(min_length=1, max_length=4 * 64)  # the token's ID
    password: str = Field(min_length=1, max_length=256)  # its secret


class TrustIn(BaseModel):
    fingerprint: str = Field(max_length=120)


class ActionIn(BaseModel):
    action: Literal[
        "reboot", "ctrl_alt_del", "atx_power", "atx_power_long", "atx_reset", "fingerbot_power", "fingerbot_power_long", "power_on", "power_off", "bios_setup",
        "jiggler_on", "jiggler_off", "wol", "keys", "text", "custom", "port", "resume", "locate_on", "locate_off",
    ]  # fmt: skip
    mac: str = Field("", max_length=17)  # for "wol"
    port: int = Field(0, ge=0, le=63)  # for "port": the input to show, counted from 0
    keys: str = Field("", max_length=160)  # for "keys"
    text: str = Field("", max_length=MAX_TEXT)  # for "text"
    enter: bool = False  # for "text": press Enter afterwards
    custom_id: str = Field("", max_length=32)  # for "custom": a saved action
    custom_changed: int | None = None  # ...as it was when the sender looked at it (see ActionRecord.changed)
    batch: str = Field("", max_length=40, pattern=r"^[A-Za-z0-9-]*$")  # ties the entries of one bulk run together
    # The sender has this machine's large view or live view open: a PC with Intel AMT then opens a session before switching
    # on (or starting into its BIOS setup), so the start shows from the first moment.
    watching: bool = False


class KvmSwitchIn(BaseModel):
    on: bool  # a PC's Intel AMT KVM on (true) or off, on its management engine


class CustomActionIn(BaseModel):
    _name = field_validator("name")(_a_line(60, needed=True))
    name: str = Field(min_length=1, max_length=4 * 60)
    kind: Literal["keys", "text"]
    keys: str = Field("", max_length=160)
    text: str = Field("", max_length=MAX_TEXT)  # empty on an edit means "keep the saved text"
    enter: bool = False
    danger: bool = False


Part = Literal["devices", "actions", "alerts", "wall"]


class ExportIn(BaseModel):
    password: str = Field(max_length=256)  # handing the wall's secrets out asks for the password again
    # What the file is encrypted with. Empty: a plain file, with every secret left out.
    passphrase: str = Field("", max_length=256)
    parts: list[Part] = Field(min_length=1, max_length=4)


class ImportIn(BaseModel):
    file: str = Field(max_length=exchange.MAX_SEALED)  # the file's text (a plain one is held to less where it is read)
    passphrase: str = Field("", max_length=256)
    take: list[Part] = Field(default_factory=list, max_length=4)  # for /api/v1/import: which of its parts to take


class UpdateSettingsIn(BaseModel):
    auto_check: bool


class UpdateInstallIn(BaseModel):
    password: str = Field(max_length=256)  # installing new code asks for the password again


class SettingsIn(BaseModel):
    bind: list[str] = Field(max_length=8)
    port: int = Field(ge=1, le=65535)
    https: bool
    interval: float = Field(ge=0.2, le=60)


def tidy_groups(names: list[str]) -> list[str]:
    """Group names as they are kept: each once, however it was typed."""
    kept: dict[str, str] = {}
    for name in names:
        name = " ".join(name.split())[:40]
        if name:
            kept.setdefault(name.casefold(), name)
    return list(kept.values())


def fail(status: int, code: str, message: str, **headers: str) -> JSONResponse:
    return JSONResponse({"code": code, "message": message}, status_code=status, headers=headers or None)


@dataclasses.dataclass
class HistoryTurn:
    """One account's or token's turn at reading the history (see device_history and HISTORY_TURN_WAIT), or the activity log."""

    lock: asyncio.Lock = dataclasses.field(default_factory=asyncio.Lock)  # held from its turn until its read's thread is done
    waiting: int = 0  # requests waiting for the lock: one at the most
    free_at: float = 0.0  # time.monotonic() at which its next read may begin

    def idle(self, now: float) -> bool:
        return not self.lock.locked() and not self.waiting and self.free_at <= now


class Downloads:
    """Downloads of the activity log made or being sent at once (each holds a file as large as what it holds): so many from
    everybody together, and one of each account."""

    def __init__(self, at_once: int) -> None:
        self._lock = threading.Lock()  # (given back from the loop, and from whatever thread lets go of an answer never sent)
        self._at_once = at_once
        self._of: set[str] = set()

    def take(self, asker: str) -> Callable[[], None] | None:
        """A place for one, and what gives it back (once, however often it is called); None where there is none."""
        with self._lock:
            if len(self._of) >= self._at_once or asker in self._of:
                return None
            self._of.add(asker)
        given: list[bool] = []

        def give_back() -> None:
            with self._lock:
                if not given:
                    given.append(True)
                    self._of.discard(asker)

        return give_back


class Handed(StreamingResponse):
    """An answer that lets go of what it was made from once it is sent, or could not be, or is never sent at all."""

    def __init__(self, content: AsyncIterator[bytes], done: Callable[[], None], **how: Any) -> None:
        super().__init__(content, **how)
        self._done = done
        weakref.finalize(self, done)  # (an answer never sent: let go of when it is)

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            self._done()


class TurnRefused(Exception):
    """A read that is not let in now (Reads.run): the answer to give."""

    def __init__(self, reply: JSONResponse) -> None:
        super().__init__(reply.status_code)
        self.reply = reply


T = TypeVar("T")


class Reads:
    """Reads of a store that take a worker thread for seconds (the history, the activity log), as W4b set them: so many at
    once from everybody together, and of each account or token one at a time, the next waiting its turn for `wait` seconds
    at the most (with one waiting already, or longer than that: come back in a moment); and after a read the same one waits
    as long as that read took before its next begins. A viewer whose script asked again and again had the reads to itself,
    and everybody else was told to come back."""

    def __init__(self, at_once: int, wait: float, what: str) -> None:
        self.places = asyncio.Semaphore(at_once)
        self.turns: dict[str, HistoryTurn] = {}
        self.wait = wait
        self.what = what  # "the history": as it is said to whoever is told to come back

    def turn(self, asker: str) -> HistoryTurn:
        turn = self.turns.get(asker)
        if turn is None:
            if len(self.turns) >= HISTORY_TURNS_KEPT:
                now = time.monotonic()
                for done in [key for key, each in self.turns.items() if each.idle(now)]:
                    del self.turns[done]
            turn = self.turns[asker] = HistoryTurn()
        return turn

    async def run(self, asker: str, work: Callable[[], T], patient: bool = False) -> T:
        """`work` in a worker thread, in its turn. TurnRefused where it is not let in now. `patient`: the next page of a
        download that is under way, which waits for its turn and a place however long (a download cut off ends the wait)."""
        turn = self.turn(asker)
        yours = f"This account or token is reading {self.what} already. Try again in a moment."
        if turn.waiting and not patient:
            raise TurnRefused(fail(503, "busy", yours, **{"Retry-After": "2"}))
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.wait
        turn.waiting += 1
        try:
            if patient:
                await turn.lock.acquire()
            else:
                async with asyncio.timeout_at(deadline):
                    await turn.lock.acquire()
        except TimeoutError:
            raise TurnRefused(fail(503, "busy", yours, **{"Retry-After": "2"})) from None
        finally:
            turn.waiting -= 1
        reading: asyncio.Task[T] | None = None
        try:
            pause = turn.free_at - time.monotonic()
            if pause > deadline - loop.time() and not patient:
                raise TurnRefused(fail(503, "busy", yours, **{"Retry-After": str(math.ceil(pause))}))
            if pause > 0:
                await asyncio.sleep(pause)
            if patient:
                await self.places.acquire()
            elif self.places.locked():
                raise TurnRefused(fail(503, "busy", f"{self.what[0].upper()}{self.what[1:]} is being read by others just now. Try again in a moment.", **{"Retry-After": "2"}))
            else:
                await self.places.acquire()  # (free: taken at once)
            began = time.monotonic()

            def read_done(_: object) -> None:
                # The turn and the place are given back when the thread is done, and not before: a request that is cut off
                # leaves its thread reading for up to the time a read may take, which counts as a read under way all that time.
                turn.free_at = time.monotonic() + (time.monotonic() - began)
                self.places.release()
                turn.lock.release()

            reading = asyncio.create_task(asyncio.to_thread(work))
            reading.add_done_callback(read_done)
            return await asyncio.shield(reading)
        finally:
            if reading is None:
                turn.lock.release()


_open_url = exchange.console_link


def page_mark() -> str:
    """A mark that is another one whenever any of the page's files is: what a page left open compares itself by.

    The version alone does not tell: the same version is run from the source while it is worked on, and a
    page that stayed open across a restart went on running the script from before it, for as long as nobody
    thought to fetch the page again.
    """
    seen = hashlib.sha256()
    for name in ASSET_TYPES:
        seen.update((STATIC / name).read_bytes())
    return seen.hexdigest()[:12]


def load_assets() -> dict[str, tuple[bytes, str, str]]:
    """The page's files, read once: name -> (content, media type, ETag).

    Held in memory so that the page a browser gets always matches the server that is
    answering it. Read from disk per request, a newer page could end up talking to an
    older server process that is still running.
    """
    assets = {}
    mark = page_mark().encode()
    for name, media_type in ASSET_TYPES.items():
        data = (STATIC / name).read_bytes()
        if name == "index.html":
            # The page carries the version of the server that sent it, and the mark of its own files. A page
            # still showing the placeholder is talking to a server from before this existed, and says so.
            data = data.replace(b"{{version}}", __version__.encode()).replace(b"{{page}}", mark)
        assets[name] = (data, media_type, '"' + hashlib.sha256(data).hexdigest()[:20] + '"')
    return assets


def action_view(record: ActionRecord) -> dict[str, Any]:
    """A saved action as the browser may see it. Never the text it types."""
    return {
        "id": record.id,
        "name": record.name,
        "kind": record.kind,
        "keys": record.keys,
        "enter": record.enter,
        "danger": record.danger,
        "changed": record.changed,
    }


# How long what is being added has to say what it is: a device's own patience to begin an answer (kvm.WAITS),
# not less. An older server's controller took 3.2 s to show the root of its Redfish service; asked with three,
# it was taken for a KVM, and the one adding it was told "did not respond in time" though the login was right.
# The questions are asked together, so an address where nothing answers costs one wait, not one per make.
RECOGNISE = httpx.Timeout(8.0, connect=1.5)
RECOGNISE_WITHIN = 10.0


async def detect_kind(url: str, scheme_given: bool, port: int | None = None) -> tuple[str, str]:
    """What answers at `url`: (driver kind, the address to use for it). `port`: the port that was typed, where one was.

    A JetKVM says so without a login, at /device/status. It serves plain HTTP, and HTTPS beside
    it once its owner turns that on, so it is asked both ways whatever was typed in front of its
    address, and HTTPS is what is used where it answers.
    A server's management controller shows the root of its Redfish service to anyone.
    Anything else is taken to speak kvmd (GLKVM, PiKVM).
    """
    # Typed without http or https in front: the same host and port, the plain way. Otherwise where a JetKVM's other way is.
    if not scheme_given and url.startswith("https://"):
        rest = url[len("https://"):]
        if port is not None and urlsplit(url).port is None:
            # (The port every HTTPS address has anyway is not written into one. It was typed all the same:
            # the plain way is that port, and not the one plain addresses have.)
            rest += f":{port}"
        twin: str | None = device_url("http://" + rest)
    else:
        twin = other_way(url)
    candidates = sorted({url, twin or url}, key=lambda address: not address.startswith("https://"))
    # No credentials are sent and the answer only picks a driver, so the certificate is not checked here.
    async with httpx.AsyncClient(verify=False, timeout=RECOGNISE, trust_env=False) as client:

        async def said(address: str) -> tuple[bool, Any]:
            """(whether anything answered there at all, what it said where that was a plain yes in JSON)"""
            try:
                reply = await bounded(client, client.build_request("GET", address), MAX_PROBE, RECOGNISE_WITHIN)
            except KvmError as ex:
                return ex.code != "timeout", None  # too much, or packed oddly: somebody is there all the same
            except httpx.HTTPError:
                return False, None
            try:
                return True, read_json(reply) if reply.status_code == 200 else None
            except ValueError:
                return True, None

        # Asked together: an address where nothing answers costs one wait, not one for each make.
        *jets, (root_answers, root) = await asyncio.gather(*(said(f"{c}/device/status") for c in candidates), said(f"{url}/redfish/v1/"))
    wanted_tls = url.startswith("https://")  # https:// was typed, or nothing was
    over_tls = wanted_tls and (root_answers or any(answers for c, (answers, _) in zip(candidates, jets, strict=True) if c.startswith("https://")))
    for candidate, (_, status) in zip(candidates, jets, strict=True):
        if isinstance(status, dict) and "isSetup" in status:
            if wanted_tls and not candidate.startswith("https://"):
                if over_tls:
                    # Something answers over HTTPS at this address, and it is no JetKVM: that is the device
                    # that was meant. What says "JetKVM" beside it, the plain way, may be somebody else (the
                    # other port of a forwarding gateway, anybody on the way), and is not sent a password.
                    continue
                if scheme_given:
                    # Whoever types https:// has said how it is to be talked to. That nothing answers there is said,
                    # and not made up for by sending what they typed beside it, password and all, the plain way.
                    raise KvmError("plain_only", f"Nothing answers over HTTPS at this address, but a JetKVM answers over plain HTTP. To add it that way, type {candidate}")
                if port is None and await listens(url):
                    # Nothing answered over HTTPS in the time given, and yet something is there (or may be: it
                    # did not say no). A device that is only slow is not "no device": the password typed for
                    # it does not go to what answers the plain way beside it unless somebody says so.
                    # (Where a port was typed, the two ways are one port, and what answers the plain way
                    # there is all that listens on it.)
                    raise KvmError(
                        "plain_only",
                        f"A JetKVM answers over plain HTTP at this address, and something on its HTTPS port did not answer in time. To add the JetKVM, type {candidate}. For the device on HTTPS, type {url} and try again.",
                    )
            return "jetkvm", candidate
    if isinstance(root, dict) and "RedfishVersion" in root:
        return "redfish", url
    # A PC with Intel AMT answers on ports of its own (16993 with TLS, 16992 plain), and says what it is to anybody.
    found = await amt.detect(url, scheme_given, port)
    if found is not None:
        return found
    return "kvmd", url


# Characters that are not drawn and are not of the kind that says so of itself ("format"): letters that
# are blanks, and the marks that pick one drawing of the letter before them or join it to the next.
NOT_DRAWN = frozenset({0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x2800, 0x3164, 0xFFA0, *range(0x180B, 0x1810), *range(0xFE00, 0xFE10), *range(0xE0100, 0xE01F0)})


async def jetkvm_at(address: str) -> bool:
    """Whether a JetKVM answers at `address`. Asked of anybody, with no credentials, so the certificate is not checked for it."""
    async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(3.0, connect=1.5), trust_env=False) as client:
        try:
            reply = await bounded(client, client.build_request("GET", f"{address}/device/status"), MAX_PROBE, 5.0)
            said = read_json(reply) if reply.status_code == 200 else None
        except (httpx.HTTPError, ValueError, KvmError):
            return False
    return isinstance(said, dict) and "isSetup" in said


def view(record: DeviceRecord, editing: bool = True) -> dict[str, Any]:
    """What a browser may know about a device. Never the password.

    `editing`: for somebody who may change it. Whoever may only look, or act, is told what a tile shows,
    and not how qKVM signs in to the device or how its certificate is checked.
    """
    shown = {
        "id": record.id,
        "name": record.name,
        "host": urlsplit(record.url).netloc,
        # (A guest of Proxmox: its console on Proxmox's own page, where the address the wall keeps is no page.)
        "open_url": record.open_url or (proxmox.console_page(record.url) if record.kind == "proxmox" else f"{record.url}/"),
        "kind": record.kind,
        "picture": driver_for(record.kind).picture,  # False: its tile shows how a server is, not a screen
        "group": record.group,
    }
    if not editing:
        return shown
    return {
        **shown,
        "url": record.url,
        "custom_open_url": record.open_url,
        "username": record.username,
        "tls": record.tls,
        "fingerprint": saved_fingerprint(record.cert_pem),  # (None as well where what is remembered is no certificate)
        "has_password": record.secret is not None,
        "alerts": record.alerts,
        "fingerbot_strength": record.fingerbot_strength if record.fingerbot_strength in FINGERBOT_STRENGTHS else FINGERBOT_STRENGTHS[0],
    }


def create_app(core: Core) -> FastAPI:
    store, audit = core.store, Attributed(core.audit)
    saving = asyncio.Lock()  # settings reach the disk one write at a time, in the order they were made

    async def save(leaving: frozenset[str] = frozenset()) -> None:
        """Write the settings to disk without making every tile wait for the disk. `leaving`: devices written down as
        gone already, which are taken off the wall once that is done (see remove_devices)."""
        async with saving:
            # Taken on the event loop, where nothing can change it halfway, and when its turn has come: taken
            # before the wait, it would still hold a change whose own write failed meanwhile and which was
            # taken back for that, and would then save it after all.
            try:
                data = store.snapshot()
                if leaving:
                    data["devices"] = [device for device in data["devices"] if device["id"] not in leaving]
                await asyncio.to_thread(store.write, data)
            except OSError:
                raise
            except Exception as ex:
                # Not the disk, and nothing that was foreseen. To whoever asked for the change it is the
                # same thing all the same: not saved. Said as that, so that the change is taken back the way
                # it is for a full disk, and not kept in memory until the next restart undoes it.
                log.exception("the settings could not be saved")
                raise OSError(f"{type(ex).__name__} inside qKVM; the details are in its log") from ex

    async def save_in_turn() -> None:
        """Save, for something the program changes by itself: when no change of anybody's is half made."""
        async with one_change:
            await save()

    def not_saved(what: str, ex: OSError) -> JSONResponse:
        log.error("%s could not be saved: %s", what, ex)
        return fail(507, "not_saved", f"{what} could not be saved ({ex.strerror or ex}), so nothing was changed.")

    async def saved(what: str, undo: Callable[[], None]) -> JSONResponse | None:
        """Save a change. Where that fails, take it back; the refusal is then the answer, and None means saved.

        If the disk refuses (it is full, or something holds the file), a change left in memory would hold
        until the next restart and be gone then; or, worse, be made permanent by whatever is saved next,
        long after its maker was told it failed. Every change a request makes is saved through here, or,
        where taking it back has to wait for something (a device's connection), in the same manner by hand.
        """
        try:
            await save()
        except OSError as ex:
            undo()
            return not_saved(what, ex)
        return None

    manager = DeviceManager(core, save_in_turn)

    async def moved(device_id: str, url: str, to: str) -> None:
        """A JetKVM on the wall over plain HTTP offers HTTPS by now, and its tile goes there (its driver asks: see jetkvm.py).

        Done as an edit by a person is: one change at a time, the new client made before anything is touched,
        a new record put in the old one's place (so that an edit under way notices), what is live and what
        is saved changed together. Only ever onto HTTPS at the same host: nothing comes this way that lets
        go of a certificate. The activity log says what the wall did by itself.
        """
        if not to.startswith("https://") or to != other_way(url):
            return
        async with one_change:
            record = store.device(device_id)
            if record is None or record.url != url or record.kind != "jetkvm" or any(d.url == to for d in store.devices):
                return
            changed = dataclasses.replace(record, url=to, cert_pem=None)  # what it shows there is trusted on first contact, as when one is added
            try:
                client = manager.client(changed)
            except Exception:  # the saved passwords were locked away in this very moment: nothing is changed, and it is asked again later
                return
            store.devices[store.devices.index(record)] = changed
            await manager.adopt(client)
            try:
                await save()
            except OSError as ex:
                log.error("%s: its new address could not be saved: %s", changed.name, ex)
        core.audit.write("device_moved", "", device=changed.name, device_id=device_id, url=to, was=url, note="over HTTPS now")
        log.info("%s: offers HTTPS by now, and is talked to at %s", changed.name, to)

    manager.moved = moved

    async def known(device_id: str, url: str, was: str, mark: str) -> None:
        """A driver took a number its machine gives for itself (see DeviceManager._known): kept with the tile as a person's
        change is, one change at a time and with a new record in the old one's place (so that an edit under way notices),
        and only where what is kept is still what the driver had, at the address it was seen at. A save that fails leaves
        it in memory, as for a first certificate, and it is written with the next change that is saved."""
        async with one_change:
            record = store.device(device_id)
            if record is None or record.url != url or record.machine != was:
                return
            changed = dataclasses.replace(record, machine=mark)
            store.devices[store.devices.index(record)] = changed
            try:
                await save()
            except OSError as ex:
                log.error("%s: the number its machine gives for itself could not be saved: %s", changed.name, ex)

    manager.known = known
    assets = load_assets()
    served = page_mark()  # the mark of the page's files as they were read just now
    live_files = os.environ.get("QKVM_DEV") == "1"  # while developing: pick up edits without a restart
    password_checks = asyncio.Semaphore(2)
    waiting = 0
    checking: set[str] = set()  # addresses a password of which is being checked at this moment
    decoy: dict[str, Any] | None = None  # stands in for the record of an account that does not exist
    totp_pending: dict[str, str] = {}  # account id -> key shown to them, until they prove their app has it
    watcher = core.watcher  # kept with the program, not with its listeners: those are reopened now and then, and it must not start from nothing each time
    scanning = asyncio.Lock()  # one search of the network at a time
    acted_on: set[str] = set()  # ids of the devices something is being done to at this moment
    setting_up = asyncio.Lock()  # one first-run setup at a time: two at once would each make a vault key
    one_change = asyncio.Lock()  # see _CHANGES
    alert_log: dict[str, Any] = {"sent": None, "error": None}  # how the last delivery went

    not_opening: list[Any] = [None]  # the saved alert address of which it was last said that it does not open

    def webhook() -> str | None:
        blob = store.alerts.webhook
        if blob is None or not core.vault.unlocked:
            return None
        url = core.vault.read(blob, "alerts:webhook")
        if url is None and not_opening[0] is not blob:
            # An address is saved, and does not open any more: alerts go nowhere. Said, once for that
            # address, in the log and where the page shows how the last alert went; with nothing said,
            # the page showed alerts as set up, and a machine went down unannounced.
            not_opening[0] = blob
            alert_log["error"] = "The saved address does not open any more (the settings file was edited, or is damaged). Enter it again."
            log.error("alerts go nowhere: the saved address does not open any more (the settings file was edited, or is damaged)")
        return url

    def alert_address() -> tuple[str, str] | None:
        """Where alerts go right now and how that service wants to be spoken to; None: nowhere."""
        url = webhook()
        return None if url is None else (url, store.alerts.format)

    def delivered(problem: str | None) -> None:
        if problem is None:
            alert_log["sent"], alert_log["error"] = time.time(), None
        else:
            alert_log["error"] = problem

    outbox = alerts.Outbox(alert_address, delivered)

    held = watcher.held  # device id -> what it was before it changed while alerts were paused

    def pausing() -> bool:
        """Whether alerts are paused at this moment.

        The end of a pause is a date, and is saved. A computer whose clock was far ahead when the pause was
        made, and has been put right since, would otherwise stay silent for as long as its clock was wrong:
        no pause is longer than the longest that can be asked for.
        """
        return 0 < store.alerts.paused_until - time.time() <= LONGEST_PAUSE * 60

    def announce(device_id: str, device: Device, previous: str, state: str, paused: bool) -> None:
        """Tell whoever is to be told that a device went from `previous` to `state`."""
        record = store.device(device_id)
        detail = str(((device._status or {}).get("error") or {}).get("message") or "")
        address = urlsplit(device.spec.base_url).netloc
        atx = (device._status or {}).get("atx")
        off = isinstance(atx, dict) and atx.get("enabled") is True and atx.get("power") is False  # (its power board says so)
        alert = alerts.describe(device.spec.name, address, previous, state, detail, server=not device.picture, off=off)
        if not alerts.wanted(alert, store.alerts) or (record is not None and not record.alerts):
            return
        if paused:
            # Not sent, and not forgotten: when the pause is over, what is not as it was before it is told.
            held.setdefault(device_id, previous)
            core.audit.write("alert", "", device=alert.device, device_id=device_id, state=alert.state, was=alert.previous, held=True)
            return
        alert.link = alerts.link_for(store.alerts.link, device_id)
        core.audit.write("alert", "", device=alert.device, device_id=device_id, state=alert.state, was=alert.previous)
        log.info("alert: %s (%s -> %s)", alert.title, alert.previous, alert.state)
        outbox.put(alert)  # delivered from there: the watching does not wait for somebody else's server

    async def look() -> None:
        """One look at every KVM, for the changes worth telling someone about."""
        watched = list(manager.devices.items())
        # All of them at once: a KVM that is slow to answer must not delay the look at the others.
        states = await asyncio.gather(*(device.probe() for _, device in watched), return_exceptions=True)
        paused = pausing()
        if held and not paused:
            for device_id, before in held.items():
                now, live = watcher.state(device_id), manager.devices.get(device_id)
                if live is not None and now is not None and now != before:
                    announce(device_id, live, before, now, paused=False)
            held.clear()
        for (device_id, device), state in zip(watched, states, strict=True):
            if manager.devices.get(device_id) is not device:
                continue  # edited or removed while it was being looked at: what it said no longer counts
            if isinstance(state, BaseException):  # one KVM's trouble must not stop the others being watched
                log.error("%s: could not be checked: %r", device.spec.name, state)
                continue
            change = watcher.observe(device_id, state)
            if change is not None:
                announce(device_id, device, *change, paused=paused)

    async def watch() -> None:
        """Notice KVMs changing state, also while nobody has the wall open."""
        while True:
            await asyncio.sleep(alerts.CHECK_EVERY)
            if not (store.alerts.enabled and core.vault.unlocked):
                continue
            try:
                await look()
                # What each machine is taken to be is written down when it changes, for the start after this one.
                if (text := watcher.to_write()) is not None:
                    await asyncio.to_thread(watcher.write, text)
            except Exception:  # whatever goes wrong in one look must not end the watching
                log.exception("the KVMs could not be checked for changes")

    def keep_unlocked() -> bool:
        """While alerts are on, or metrics are collected, the KVMs are watched after the last person signs out too.

        And always where qKVM has a key that opens the saved passwords at start (its own, or an unlock
        file's): what opens them is on this computer anyway, and forgetting them here would only mean
        opening them again.
        """
        return store.alerts.enabled or bool(store.server.metrics_token) or core.unlock_secret is not None

    background: set[asyncio.Task[Any]] = set()  # things set going by a request that it does not wait for (or that outlive it, if it is cut off)

    async def fit_unlock_file() -> None:
        """Make the unlock file qKVM was started with fit this data folder, now that a password has opened it."""
        async with one_change:
            if core.unlock_secret is None or store.unlock is not None or not core.vault.unlocked:
                return
            store.unlock = await asyncio.to_thread(core.vault.rewrap, core.unlock_secret)
            try:
                await save()
            except OSError as ex:
                store.unlock = None  # tried again at the next sign-in
                log.error("the unlock file could not be put to use: %s", ex)
                return
        audit.write("unlock_at_start_on", "")
        log.info("%s opens this data folder from the next start on", "the key in the data folder" if core.own_key else "the unlock file")

    moved_to: tuple[list[str], list[str]] | None = None  # where the names led at the last look, if elsewhere than now

    async def keep_house() -> None:
        # (Not while the first account is being made: its key is there before anybody is signed in with it,
        # and taken away in that moment, setup would end signed in to a wall whose saved passwords are shut.)
        if core.vault.unlocked and len(core.sessions) == 0 and not keep_unlocked() and not setting_up.locked():
            # Nobody is signed in any more: forget the key and the KVM sessions.
            core.vault.lock()
            await manager.close()
        manager.tidy()
        updater = core.updater
        stale = updater.checked_at is None or time.time() - updater.checked_at > UPDATE_CHECK_EVERY
        if store.server.update_check and updater.repo and stale and updater.state != "ready":
            try:
                await updater.check()
            except UpdateError:
                updater.checked_at = time.time()  # try again tomorrow, not every half minute
        nonlocal moved_to
        if core.missing or (core.addresses and any(name in ("lan", "tailscale") for name in core.bind)):
            # An address we were asked to serve by name. It may not have been up at start (Tailscale,
            # usually), and it may be another one by now: a new lease from the router, another network.
            # The listeners are reopened where the names lead now. Seen twice running first, so that a
            # network that is gone for a moment does not take the wall's listeners down and up with it.
            now = await asyncio.to_thread(resolve, core.bind)
            if now == (core.addresses, core.missing) or not now[0]:
                moved_to = None  # as it was; or nowhere at all to listen, in which case what is open stays open
            elif now != moved_to and core.addresses:
                moved_to = now
            else:
                moved_to = None
                core.request_restart()

    async def housekeeping() -> None:
        while True:
            await asyncio.sleep(HOUSEKEEPING_EVERY)
            try:
                await keep_house()
            except Exception:  # a failed round must not be the last one: locking up after the last sign-out depends on it
                log.exception("housekeeping failed")

    # --- history (W4): what the wall saw of each machine, kept in history.sqlite (see history.py) -----------------
    # Every look at a device's status reaches the history through the manager (kvm.Device.on_status), whoever
    # asked for it: a browser, the alert round, a collector. And once a minute the history looks by itself, so
    # that a machine is watched while the wall is unlocked, with or without anybody looking, at the least cost
    # (a glance: what the alerts ask, which takes nobody's place at a JetKVM).
    kept = core.history
    manager.observed = kept.observe

    async def history_looks() -> None:
        while True:
            await asyncio.sleep(HISTORY_LOOK_EVERY)
            try:
                watched = list(manager.devices.items())
                glances = await asyncio.gather(*(device.glance() for _, device in watched), return_exceptions=True)
                for (device_id, device), glance in zip(watched, glances, strict=True):
                    if isinstance(glance, dict) and manager.devices.get(device_id) is device:
                        kept.observe(device_id, glance)
                kept.sweep()  # a machine not looked at for a while (the wall locked itself, say) is unwatched from its last look on
            except Exception:  # whatever goes wrong in one round must not end the keeping
                log.exception("the history could not look at the machines")

    def history_pressed(device_id: str, action: str, ok: bool | None, note: str = "", at: float | None = None) -> None:
        """A power action was pressed from the wall: the history keeps that it was, and how the device took it (None: not known).
        `at`: when it was pressed (a press that is waited for until it is seen done is written when that wait ends).

        Not of a machine that is no longer on the wall: its history went with it, and a press that was still being held
        when it was removed (seconds, for a long one) came back as a row of a machine that is gone."""
        if action in POWER_ACTIONS and store.device(device_id) is not None:
            kept.pressed(device_id, action, ok, note, now=at)

    # Reads of the history take a thread each, for up to the few seconds a read may run: so many at once and no
    # more, whoever asks, so that a viewer with a script cannot have the wall's threads to themselves; and of each
    # account or token one at a time, with a pause after it, so that one of them cannot have all of them either.
    history_reads = Reads(HISTORY_READS_AT_ONCE, HISTORY_TURN_WAIT, "the history")

    # (The route that reads the history stands beside the snapshot route below, under the same mark.)

    # --- the activity log's index (activity.py): made from the text files, followed as they are written ----------
    # The text log tells it that there is more as each entry is written (it does not wait for it); reads of the log
    # go to it where it holds what the text files hold, and to the text files where it does not. Read by the same rule
    # as the history: an admin's script cannot have the wall's threads to itself either.
    indexed = core.activity
    activity_reads = Reads(ACTIVITY_READS_AT_ONCE, ACTIVITY_TURN_WAIT, "the activity log")
    downloads = Downloads(DOWNLOADS_AT_ONCE)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        manager.load()
        kept.start()  # (once; the history outlives the listeners, as the rest of core does)
        indexed.start()  # (once, as the history: at the first start after an upgrade it is made from the text files there)
        tasks = [asyncio.create_task(job()) for job in (housekeeping, watch, outbox.run, history_looks)]
        yield
        for task in tasks:
            task.cancel()
        if background:
            # What a request set going is finished, within a time, and not cut off. The note a sign-in makes that
            # opens the saved passwords at the next start: made in memory, on its way to the file. A wall stopped
            # in that moment (the first sign-in, then a restart) had said that it carries on by itself, and
            # came back locked. And the removal of several machines whose request was cut off by the stop.
            await asyncio.wait(list(background), timeout=BACKGROUND_OWED)
        for task in list(background):
            task.cancel()
        await asyncio.gather(*tasks, *background, return_exceptions=True)
        await outbox.close()
        await lines.close()  # (what a live line still has down on a machine is let go of before the machine's connection goes)
        await manager.close()
        await asyncio.to_thread(core.audit.flush)  # what was done last is on disk before the program ends
        # ...and the activity log's index lets go of its file, all of it brought into the file (what it had not taken in yet,
        # the next start takes in: the text files have it). Started again with the listeners, where they are opened anew.
        await asyncio.to_thread(indexed.stop)
        await asyncio.to_thread(core.sessions.flush)  # ...and so is who signed out last
        await asyncio.to_thread(kept.flush)  # ...and what the wall saw last, with when it last looked (history: W4)

    app = FastAPI(title="qKVM", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.trusted_proxies = core.trusted_proxies
    app.state.allowed_clients = core.allowed_clients

    async def screened(request: Request, call_next: Callable[[Request], Awaitable[Response]], path: str) -> Response:
        """Decide whether a request may go ahead, and let it."""
        if not client_allowed(request):
            # Before anything else: to an address that was not named there is no qKVM here to talk to.
            return PlainTextResponse("This address is not allowed to use qKVM.", status_code=403)
        host = request.headers.get("host", "")
        if not host_allowed(host, store.server.allowed_hosts):
            return PlainTextResponse(
                f"Host {host!r} is not allowed. Use the IP address, or add this name to "
                "allowed_hosts in qKVM's settings file (qkvm.json).",
                status_code=400,
            )
        changing = request.method not in ("GET", "HEAD")
        length = request.headers.get("content-length", "")
        public = path in PUBLIC or path.startswith("/static/")
        user, sent = (None, None) if public else asking(request)
        # A cross-site page cannot make a browser send a token: that is no ambient credential like a cookie.
        # So a script is not asked for the headers by which the page's own requests are known.
        if changing and sent is None and not same_origin(request):
            return fail(403, "forbidden", "Cross-site request refused")
        if changing and "transfer-encoding" in request.headers:
            # A body of unknown size could be endless; everything the page sends states its length.
            return fail(411, "length_required", "The request must say how long it is")
        if changing and length and (not length.isdigit() or int(length) > (MAX_FILE_BODY if path in _FILES else MAX_BODY)):
            return fail(413, "too_large", "The request is too large")
        if not public and user is None:
            return fail(401, "unauthorized", "Sign in first")
        if user is not None and RANK[user.role] < RANK[required_role(request.method, path)]:
            return fail(403, "not_allowed", "Your account is not allowed to do that")
        if user is not None and is_token(user) and _OWN_ACCOUNT.fullmatch(f"{request.method} {path}"):
            return fail(403, "not_allowed", "A token has no account of its own to change")
        if sent is not None:
            if path == "/api/v1/logout":
                return fail(403, "not_allowed", "A token has nothing to sign out of")
            if not core.vault.unlocked:
                # Said, and not left to look like "no devices": a script that runs at night meets this after every restart.
                return fail(503, "locked", "qKVM was restarted and nobody has signed in since, so it cannot reach its devices. Started with --unlock-file, it can.")
            sent.used = time.time()
        if user is not None and must_enroll(user, request) and not _ENROLLING.fullmatch(f"{request.method} {path}"):
            # Signed in by password alone where that is not enough: all there is to do is to put that right.
            return fail(403, "totp_required", "Two-factor sign-in is required for your account. Set it up first.")
        if changing:
            # The whole request is in hand before anything is done or held for it. A sender that
            # stops halfway (by accident or to be a nuisance) holds up nobody but itself, and not for long.
            try:
                async with asyncio.timeout(BODY_TIMEOUT):  # (never wait_for, which loses a stop up to Python 3.11: see kvm.Listening.message)
                    await request.body()
            except TimeoutError:
                return fail(408, "timeout", "The request took too long to arrive")
            except ClientDisconnect:
                return fail(400, "disconnected", "The request was not sent in full")
            # The request took its time to arrive, at its sender's pace. The account may have been
            # removed or given a lesser role meanwhile, or signed out everywhere.
            denied = None if user is None else still_allowed(request, user)
            if denied is not None:
                return denied
        request.state.user = user
        who = acting.set(user.name if user else "")
        try:
            if _CHANGES.fullmatch(f"{request.method} {path}"):
                async with one_change:
                    # ...and so it may while the request waited for its turn.
                    denied = None if user is None else still_allowed(request)
                    if denied is not None:
                        return denied
                    return await call_next(request)
            return await call_next(request)
        finally:
            acting.reset(who)

    @app.middleware("http")
    async def guard(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        # The path the request is routed by. Not request.url.path: that one is rebuilt from the Host
        # header, which the sender controls, and so must never decide what counts as public.
        path = request.scope["path"]
        response: Response
        try:
            if _NO_PATH.search(path):
                # The router serves a path with a line feed after it as the path without one (its patterns end
                # in "$", which is content with that), and the rules that go by the path ask for the whole of
                # it: such a change was made out of its turn, two at once. No page and no script sends one.
                response = fail(404, "not_found", "There is nothing at this address")
            else:
                response = await screened(request, call_next, path)
        except Exception:
            # A bug in a check or in a handler: record it, keep serving, and tell the page nothing about
            # the internals. Whatever happened, the answer leaves with the security headers below.
            log.exception("unhandled error in %s %s", request.method, path)
            response = fail(500, "internal", "Something went wrong inside qKVM. The details are in its log.")
        response.headers.update(SECURITY_HEADERS)
        if is_secure(request):
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        if path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Name the field and the rule, never the submitted value (it may be a password).
        first = exc.errors()[0]
        where = ".".join(str(part) for part in first.get("loc", ())[1:])
        said = str(first.get("msg")).removeprefix("Value error, ")  # (the rule in this program's own words, where it has some)
        return fail(422, "invalid", f"{where}: {said}" if where else said)

    # --- pages ----------------------------------------------------------------

    def serve(name: str, request: Request) -> Response:
        if live_files:
            assets.update(load_assets())
        data, media_type, etag = assets[name]
        # no-cache: the browser asks every time, and gets a tiny "unchanged" answer if it has this version.
        headers = {"Cache-Control": "no-cache", "ETag": etag}
        if request.headers.get("if-none-match") == etag:
            return Response(status_code=304, headers=headers)
        return Response(data, media_type=media_type, headers=headers)

    @app.get("/")
    async def index(request: Request) -> Response:
        return serve("index.html", request)

    @app.get("/healthz")
    async def health() -> dict[str, Any]:
        """For monitoring: answers without a login, and says no more than "running", and whether it is watching.

        "locked": it has been restarted and nobody has signed in since, so it cannot reach a single device.
        Nothing is wrong with it, and nothing is being watched: whoever monitors it wants to hear of that.
        """
        # "page": the mark of the page's files as this program serves them (see page_mark).
        # "api": the versions of the API this program speaks, each under /api/<version>/. A program that
        # talks to a wall (a script, an app on a phone) asks here first, before it has anything to sign in with.
        return {
            "status": "ok", "version": __version__, "api": list(API_VERSIONS), "page": page_mark() if live_files else served,
            "locked": core.initialized and not core.vault.unlocked,
        }  # fmt: skip

    running: dict[str, Any] = {}  # what is running, found out once: the libraries do not change under a running program

    @app.get("/api/v1/about")
    async def about_this(request: Request) -> dict[str, Any]:
        """The version and the licence, for anybody signed in; what it runs on, to the version, for admins."""
        if not running:
            running.update(await asyncio.to_thread(about.running))
        if request.state.user.role != "admin":
            return {"version": running["version"], "licence": running["licence"]}
        return running

    # --- numbers for a monitoring system ---------------------------------------------------------

    @app.get("/metrics")
    async def collect(request: Request) -> Response:
        """The state of the wall, in the Prometheus text format, for whoever has the token made for it."""
        expected = store.server.metrics_token
        if not expected:
            return fail(404, "not_found", "Metrics are switched off")
        said = request.headers.get("authorization", "")
        given = said[7:].strip() if said[:7].lower() == "bearer " else ""
        # Nothing is counted against the address for a wrong token: 256 random bits are not guessed, and a
        # collector that was given the wrong one would lock the people at its address out of signing in.
        if not given or not same_text(metrics.kept(given), expected):
            return fail(401, "unauthorized", "This needs the metrics token", **{"WWW-Authenticate": "Bearer"})
        ids = list(manager.devices)
        statuses = dict(zip(ids, await asyncio.gather(*(manager.devices[i].glance() for i in ids)), strict=True))
        text = metrics.render(
            started=core.started,
            unlocked=core.vault.unlocked,
            sessions=len(core.sessions),
            devices=[(record, statuses.get(record.id)) for record in store.devices],
            update_available=core.updater.available,
        )
        return Response(text, media_type=metrics.CONTENT_TYPE, headers={"Cache-Control": "no-store"})

    @app.get("/api/v1/metrics")
    async def metrics_state() -> dict[str, Any]:
        return {"enabled": bool(store.server.metrics_token), "created": store.server.metrics_created if store.server.metrics_token else None}

    @app.post("/api/v1/metrics/token")
    async def metrics_token(request: Request) -> Response:
        """Switch metrics on, or replace the token: the new one is shown this once, and the one before stops working."""
        previous = (store.server.metrics_token, store.server.metrics_created)

        def keep_the_old_token() -> None:
            store.server.metrics_token, store.server.metrics_created = previous

        token, store.server.metrics_token = metrics.new_token()
        store.server.metrics_created = time.time()
        if refused := await saved("The metrics token", keep_the_old_token):
            return refused  # and the new one is shown to nobody: the collector's old one still works
        audit.write("metrics_token_created", client_ip(request))
        return JSONResponse({"token": token, "created": store.server.metrics_created})

    @app.delete("/api/v1/metrics/token")
    async def metrics_off(request: Request) -> Response:
        previous = (store.server.metrics_token, store.server.metrics_created)

        def still_on() -> None:
            store.server.metrics_token, store.server.metrics_created = previous

        store.server.metrics_token, store.server.metrics_created = "", None
        if refused := await saved("Switching metrics off", still_on):
            return refused  # said, so that nobody takes a token for withdrawn that works again after a restart
        audit.write("metrics_switched_off", client_ip(request))
        return JSONResponse({"ok": True})

    @app.get("/static/{name}")
    async def asset(name: str, request: Request) -> Response:
        if name not in assets or name == "index.html":
            return fail(404, "not_found", "No such file")
        return serve(name, request)

    # --- setup, login, sessions -----------------------------------------------

    def is_token(user: UserRecord) -> bool:
        return user.id.startswith("token:")  # an account's id is eight hexadecimal digits

    def token_user(record: TokenRecord) -> UserRecord:
        """A token, as the account it stands for: its role and its machines, and nothing an account has for itself."""
        return UserRecord(id=f"token:{record.id}", name=f"{record.name} (token)", role=record.role, devices=record.devices, groups=record.groups)

    def token_for(key: str, kind: str) -> TokenRecord | None:
        """The token of this kind that `key` is, if it is one, and has not run out."""
        if not key.startswith("qkvm_"):
            return None
        kept, now = metrics.kept(key), time.time()
        valid = (t for t in store.tokens if t.kind == kind and (t.expires is None or t.expires > now))
        return next((t for t in valid if same_text(t.kept, kept)), None)

    def current_user(request: Request) -> UserRecord | None:
        """The account behind this request's session cookie, if it is still a valid one."""
        token = request.cookies.get(COOKIE)
        session = core.sessions.get(token)
        if session is None:
            return None
        if session.sso:
            # Signed in on the identity proxy's word, and for as long as that is its word. Somebody else at the
            # same browser, signed in there by now, is not to work on as the one before, under that one's name
            # in the activity log; and whoever the proxy no longer vouches for is not signed in here either.
            named = sso_name(request, core.sso_header) if core.sso_header else None
            said = store.user_named(named) if named else None
            if said is None or said.id != session.user:
                core.sessions.drop(token)
                return None
        request.state.sso = session.sso
        if session.user.startswith("token:"):  # a screen on the wall, opened with its display link
            now = time.time()
            shown = next((t for t in store.tokens if t.id == session.user[6:] and t.kind == "display"), None)
            if shown is None or (shown.expires is not None and shown.expires <= now):
                core.sessions.drop(token)  # the link was taken back, or has run out
                return None
            return token_user(shown)
        user = store.user(session.user)
        if user is None or user.suspended:  # removed, or put on hold, while this browser was signed in
            core.sessions.drop(token)
            return None
        return user

    def asking(request: Request) -> tuple[UserRecord | None, TokenRecord | None]:
        """Who makes this request: a signed-in browser, or else a script by the token it sends (returned as well)."""
        user = current_user(request)
        if user is not None:
            return user, None
        said = request.headers.get("authorization", "")
        sent = token_for(said[7:].strip(), "api") if said[:7].lower() == "bearer " else None
        return (None, None) if sent is None else (token_user(sent), sent)

    def by_sso(request: Request | None) -> bool:
        """Whether whoever makes this request was signed in by the identity proxy, and not by a password given here."""
        return request is not None and bool(getattr(request.state, "sso", False))

    def must_enroll(user: UserRecord, request: Request | None = None) -> bool:
        """Whether this account has to have two-factor sign-in here, and has not.

        `request`: asked of whoever is making it. Somebody the identity proxy signed in has had their
        second step where they signed in: qKVM's own is for those who sign in with a password here.
        """
        level = store.server.require_totp
        # (The rule is about accounts. A token is made by an admin for one job, and has no phone.)
        return user.totp is None and not is_token(user) and not by_sso(request) and level in RANK and RANK[user.role] >= RANK[level]

    def me(user: UserRecord, request: Request | None = None) -> dict[str, Any]:
        return {
            "id": user.id, "name": user.name, "role": user.role, "totp": user.totp is not None,
            "must_enroll": must_enroll(user, request),  # signed in, and able to do nothing but set the second step up
            "sso": by_sso(request),  # signed in by the identity proxy: there is nothing to sign out of here
            "recovery_codes": len(user.totp_codes),  # one-time codes that are left
            "token": is_token(user),  # not a person: a wall screen opened with a display link
        }  # fmt: skip

    def turned_away(user: UserRecord, checked: dict[str, Any] | None, ip: str) -> JSONResponse | None:
        """Why a sign-in whose password was found right may not go on, as the account stands at this moment. None: it may.

        `checked`: what the password was checked against. Checking takes a while, on purpose, and is done
        beside everything else; so is saving that a code was used. An admin who meanwhile replaced the
        password, or removed or suspended the account, has signed it out everywhere: a sign-in that was still
        being checked against the account as it had been must not come out of that signed in. So this is
        asked again after everything that was waited for, the last time with nothing left to wait for.
        """
        if store.user(user.id) is not user or user.auth is not checked:
            core.limiter.fail(ip, user.name)
            audit.write("login_failed", ip, user=user.name)
            return fail(401, "bad_password", "Wrong user name or password" if len(store.users) > 1 else "Wrong password")
        if user.suspended:
            # Said to whoever knows the password, and to nobody else: a wrong guess is answered as for any account.
            audit.write("login_failed", ip, user=user.name, suspended=True)
            return fail(403, "suspended", "This account is suspended. An admin can lift that.")
        return None

    no_step_said: dict[str, float] = {}  # account id -> when it was last written that its second step's key does not open
    code_asked_said: dict[str, float] = {}  # account id -> when it was last written that its password was right and a code was asked for

    def held_for_codes(user: UserRecord) -> JSONResponse | None:
        """The answer for an account that has had too many wrong codes just now. None: it is not held."""
        wait = core.limiter.retry_after(f"account:{user.id}")
        if wait <= 0:
            return None
        seconds = math.ceil(wait)
        return fail(429, "rate_limited", f"Too many wrong codes for this account. Try again in {seconds} s.", **{"Retry-After": str(seconds)})

    async def written_down() -> JSONResponse | None:
        """Wait until a sign-out is on disk as well. Where it could not be put there: the answer that says so.

        Ended here, a sign-in is ended for as long as qKVM runs. A browser that asked to be kept signed in
        is also written down, to outlast a restart; if that could neither be written anew nor taken away,
        a restart would let whoever holds a copy of its cookie in again, and "signed out" would not be true.
        """
        why = await asyncio.to_thread(core.sessions.settled, SAVE_WITHIN)
        if why is None:
            return None
        log.error("A sign-out could not be written down: %s", why)
        return fail(
            507, "not_saved",
            f"Signed out, but that could not be written down ({why}). If qKVM is restarted before it can be, the sign-in "
            "that was ended works again for whoever kept a copy of it. Make room where qKVM keeps its settings; the next sign-in or sign-out then puts it right.",
        )  # fmt: skip

    def still_allowed(request: Request, was: UserRecord | None = None) -> JSONResponse | None:
        """May whoever sent this request still make it? Asked again whenever time has passed since the last answer.

        The guard checks when a request comes in, again once it has arrived in full, and again when
        its turn to change something has come. A handler that talks to a KVM for seconds before it
        takes that turn itself asks once more at that point. In between, the account may have been
        removed or given a lesser role, or everybody may have signed out.

        `was`: who the request was let in as, where the guard asks before it has noted that with the request.
        It has to be the same one still, not merely somebody: a request that carries a cookie and a token was
        let in as the account, and must not go on as that account, on the strength of the token, once the
        account is gone.
        """
        user, _ = asking(request)
        was = was if was is not None else getattr(request.state, "user", None)
        if user is None or (was is not None and user.id != was.id):
            return fail(401, "unauthorized", "Sign in first")
        if RANK[user.role] < RANK[required_role(request.method, request.scope["path"])]:
            return fail(403, "not_allowed", "Your account is not allowed to do that")
        if must_enroll(user, request) and not _ENROLLING.fullmatch(f"{request.method} {request.scope['path']}"):
            return fail(403, "totp_required", "Two-factor sign-in is required for your account. Set it up first.")
        return None

    def allowed(request: Request, device_id: str) -> bool:
        """May the signed-in account see this KVM? It may if it is one of its KVMs, or in one of its groups."""
        user: UserRecord = request.state.user
        if user.devices is None or device_id in user.devices:
            return True
        record = store.device(device_id) if user.groups else None
        return record is not None and record.group.casefold() in {group.casefold() for group in user.groups}

    def still_shown(request: Request, device_id: str) -> JSONResponse | None:
        """After a wait for a device: may whoever asked still be handed what it answered? None: yes.

        A device takes its time, seconds of it where it is slow or far away. Meanwhile the account may have
        been signed out everywhere, suspended, or limited to other machines, or the tile taken off the wall.
        What was asked for while that was still allowed is not handed over once it is not: a picture of the
        screen least of all. (Asked before the wait as well, by each handler: this is the second time. Where
        the device answered nothing, there is nothing to hand over, and its "ask again" goes out as it is.)
        """
        if refused := still_allowed(request):
            return refused
        if device_id not in manager.devices or not allowed(request, device_id):
            return fail(404, "not_found", "Unknown device")
        return None

    async def check_password(password: str, record: dict[str, Any] | None, ip: str) -> bytes | None:
        """The vault key if `password` is right for `record`. Raises KvmError when too many checks are queued.

        Without a record (no such account) the same work is done against a made-up one,
        so the answer takes as long and does not give away which names exist.

        One at a time from an address (`ip`). A wrong password is counted when its check is done; several
        sent together would all be checked before any of them was counted, and the address would get as many
        guesses as fit through at once where five are meant to lock it out.
        """
        nonlocal waiting, decoy
        if waiting >= MAX_PASSWORD_CHECKS:
            raise KvmError("busy", "Too many sign-in attempts at once, try again shortly", 429)
        # (By what the lock-out counts as one: an address, or the whole network an IPv6 address is in. Whoever
        # has one such address has all the others of its network to send the next guess from.)
        ip = core.limiter.counted_as(ip)
        if ip in checking:
            raise KvmError("busy", "A password from this address is being checked just now. Try again in a moment.", 429)
        waiting += 1
        checking.add(ip)
        try:
            async with password_checks:
                if record is None:
                    if decoy is None:
                        # Making it is the same work as a check, once: the first question about a name that
                        # is nobody's is answered after that, and not after that and a check on top, which
                        # told whoever asked first, by the clock, that there is no such account.
                        decoy = await asyncio.to_thread(Vault().create, secrets.token_urlsafe(24))
                        return None
                    await asyncio.to_thread(Vault.open, decoy, password)
                    return None
                return await asyncio.to_thread(Vault.open, record, password)
        except (MemoryError, NoMemory) as ex:
            raise no_memory(ex) from None
        finally:
            waiting -= 1
            checking.discard(ip)

    said_no_memory = 0.0

    def no_memory(ex: BaseException) -> KvmError:
        """What a password check, or the sealing of a file, is answered with where the work could not be done.

        The 130 MB it takes were not to be had. That is nobody's wrong password, and not an error inside the
        program either, with a page of traceback for every attempt by anybody: said once a minute, in a line.
        """
        nonlocal said_no_memory
        if time.monotonic() - said_no_memory > 60:
            said_no_memory = time.monotonic()
            log.error("a password could not be checked: the memory that takes was not to be had (%s)", str(ex) or type(ex).__name__)
        return KvmError("busy", "A password cannot be checked just now: this computer has no memory to spare for it. Try again in a moment.", 503)

    def throttled(ip: str) -> JSONResponse | None:
        wait = core.limiter.retry_after(ip)
        if wait <= 0:
            return None
        seconds = math.ceil(wait)
        return fail(429, "rate_limited", f"Too many attempts. Try again in {seconds} s.", **{"Retry-After": str(seconds)})

    def signed_in(request: Request, remember: bool, user: UserRecord, **extra: Any) -> JSONResponse:
        token = core.sessions.create(client_ip(request), remember, user.id, mark=auth_mark(user))
        manager.load()
        if core.unlock_secret is not None and store.unlock is None:
            # Not waited for by whoever is signing in: it takes as long as checking a password does.
            task = asyncio.create_task(fit_unlock_file())
            background.add(task)
            task.add_done_callback(background.discard)
        return with_cookie(JSONResponse({"ok": True, "user": me(user, request), **extra}), request, token, remember)

    def with_cookie(response: JSONResponse, request: Request, token: str, remember: bool) -> JSONResponse:
        response.set_cookie(
            COOKIE,
            token,
            max_age=REMEMBER_TTL if remember else None,
            httponly=True,
            samesite="strict",
            secure=is_secure(request),
            path="/",
        )
        return response

    @app.get("/api/v1/session")
    async def session(request: Request) -> Response:
        user = current_user(request)
        token: str | None = None
        sso: dict[str, Any] = {}
        if core.sso_header:
            # Somebody the proxy in front of qKVM has signed in is signed in here, as the account of that
            # name, if there is one that may. The page asks this first thing, and again when its session is gone.
            name = None if user is not None else sso_name(request, core.sso_header)
            known = store.user_named(name) if name else None
            if known is not None and known.suspended:
                known = None
            sso = {"sso": {"on": True, "name": name, "known": known is not None}}
            if known is not None:
                core.sessions.keep_newest(known.id, 19)  # a browser that keeps no cookie gets a session per look: not without end
                token = core.sessions.create(client_ip(request), False, known.id, sso=True)
                request.state.sso = True
                manager.load()
                audit.write("login", client_ip(request), user=known.name, sso=True)
                user = known
        said = {
            **sso,
            "initialized": core.initialized,
            "authenticated": user is not None,
            "user": me(user, request) if user else None,
            "ask_name": len(store.users) > 1,  # with one account, its password alone is enough
            "recovery": store.recovery is not None,  # a forgotten password can be replaced with the recovery key
            "recovery_created": store.recovery_created if user is not None and user.role == "admin" else None,
            "setup_code_required": core.setup_code is not None and not core.initialized and not is_local(request),
            "min_password": MIN_PASSWORD,
            # Whether qKVM carries on by itself after a restart (it was started with an unlock file that fits).
            "unlocks_at_start": user is not None and core.unlock_secret is not None and store.unlock is not None,
        }
        response = JSONResponse(said)
        return response if token is None else with_cookie(response, request, token, False)

    @app.post("/api/v1/setup")
    async def setup(body: SetupIn, request: Request) -> Response:
        ip = client_ip(request)
        if core.initialized:
            return fail(409, "initialized", "qKVM is already set up")
        if blocked := throttled(ip):
            return blocked
        # Where it was started with --setup-code: from another machine, the code printed where qKVM runs proves you own it.
        if core.setup_code is not None and not is_local(request) and not same_text(body.setup_code.strip(), core.setup_code):
            core.limiter.fail(ip)
            return fail(403, "bad_setup_code", "That is not the setup code shown in qKVM's terminal")
        async with setting_up:
            if core.initialized:  # someone else finished setting up while this request waited
                return fail(409, "initialized", "qKVM is already set up")
            auth = await asyncio.to_thread(core.vault.create, body.password)
            user = UserRecord(id=secrets.token_hex(4), name=body.name, role="admin", auth=auth, created=time.time())
            before = (store.users, store.unlock, store.recovery, store.recovery_created)
            store.users, store.unlock = [user], None  # a new key for everything: nothing made before it opens it
            recovery_key = await new_recovery()

            def not_set_up() -> None:
                # Set up in memory only, the wall would take this password until the next restart and none after
                # it, with a recovery key that was shown to nobody.
                store.users, store.unlock, store.recovery, store.recovery_created = before
                core.vault.lock()

            if refused := await saved("The first account", not_set_up):
                return refused
        audit.write("setup", ip, user=user.name)
        # Shown once, now: it is the way back in if this password is ever forgotten.
        return signed_in(request, remember=False, user=user, recovery_key=recovery_key)

    @app.post("/api/v1/login")
    async def login(body: LoginIn, request: Request) -> Response:
        ip = client_ip(request)
        if not core.initialized:
            return fail(409, "not_initialized", "qKVM has not been set up yet")
        if blocked := throttled(ip):
            return blocked
        name = body.name.strip()
        if name:
            user = store.user_named(name)
        elif len(store.users) == 1:
            user = store.users[0]
        else:
            return fail(422, "name_required", "Enter your user name")
        # (An account that only the identity proxy signs in has no password: none that is typed is right for it.)
        checked = user.auth if user is not None and user.auth else None
        try:
            key = await check_password(body.password, checked, ip)
        except KvmError as ex:
            return fail(ex.status, ex.code, ex.message)
        if user is None or key is None:
            core.limiter.fail(ip, user.name if user else name)
            # An account's name where it was one. What was typed and is nobody's name is not kept: often
            # enough it is a password, typed a field too early.
            audit.write("login_failed", ip, user=user.name if user else "", **({} if user else {"no_such_account": True}))
            return fail(401, "bad_password", "Wrong user name or password" if len(store.users) > 1 else "Wrong password")
        if refused := turned_away(user, checked, ip):
            return refused
        one_time = False  # whether the second step was one of the codes that work once
        if user.totp is not None:
            # The password was right; the second step is the code. Nothing is unlocked until both are.
            if not body.code.strip():
                # Every sign-in with a second step begins like this, and so does one by somebody who has
                # the password and nothing else: written down as what it is, so that it can be seen. Once
                # a minute for an account: whoever has the password could otherwise write a line with every
                # try, and the activity log keeps only so much.
                if time.monotonic() - code_asked_said.get(user.id, float("-inf")) >= 60:
                    if len(code_asked_said) > 500:
                        code_asked_said.clear()
                    code_asked_said[user.id] = time.monotonic()
                    audit.write("login_code_asked", ip, user=user.name)
                return fail(401, "code_required", "Enter the code from your authenticator app")
            # Wrong passwords are counted against the address they come from. That is not enough here:
            # whoever has the password and many addresses would have five guesses at the code from each.
            # From here on it is the account that is held, and only somebody with its password finds that out.
            # Asked here, and again when this sign-in's turn has come: guesses that wait their turn together
            # (and anybody can make them wait) would otherwise all be judged, however many there are.
            if refused := held_for_codes(user):
                return refused
            opened = Vault()
            opened.adopt(key)
            typed = opened.mark(f"{user.id}:{totp.as_issued(body.code)}", "one-time code")
            if typed in user.totp_codes:
                # One of the codes for when the phone is not at hand. It is used up, and that is saved, before
                # anybody is let in on the strength of it: it must not work a second time after a restart.
                async with one_change:
                    if refused := turned_away(user, checked, ip) or held_for_codes(user):
                        return refused
                    at = user.totp_codes.index(typed) if typed in user.totp_codes else -1
                    if at < 0:  # used by another sign-in while this one waited its turn
                        return fail(401, "bad_code", "That code is not right. Codes change every 30 seconds and work once.")
                    del user.totp_codes[at]
                    if refused := await saved("This sign-in", lambda: user.totp_codes.insert(at, typed)):
                        return refused
                one_time = True
            else:
                second = user.totp
                secret = opened.read(second, f"totp:{user.id}")
                if secret is None:
                    # Not a wrong code: nothing a code could be checked against. Said as what it is, to
                    # whoever had the password right, and with the way out; it was an error inside the
                    # program, at every try. Counted and written down as a wrong code is, all the same: what
                    # was typed may have been a guess at one of the codes that work once, and those are
                    # still checked. And in the log once a minute for an account, not at every try.
                    core.limiter.fail(ip, user.name)
                    core.limiter.fail(f"account:{user.id}")
                    audit.write("login_failed", ip, user=user.name, step="code", no_second_step=True)
                    if time.monotonic() - no_step_said.get(user.id, float("-inf")) >= 60:
                        if len(no_step_said) > 500:
                            no_step_said.clear()
                        no_step_said[user.id] = time.monotonic()
                        log.error("%s: the key of this account's second step does not open (the settings file was edited, or is damaged)", plain(user.name) or user.id)
                    return fail(409, "no_second_step", "The second step of this account cannot be checked: its saved key does not open any more. On the computer qKVM runs on, `qkvm --disable-2fa NAME` switches it off.")
                # A code of the app works once as well, a restart later too. Which one was accepted last is
                # kept with the account, and that is saved before anybody is let in on the code: what was only
                # remembered while qKVM ran could be typed again after a restart, while its half minute lasted.
                # One sign-in at a time, so that the same code sent twice at once is taken once.
                async with one_change:
                    if refused := turned_away(user, checked, ip) or held_for_codes(user):
                        return refused
                    step = totp.matching_step(secret, body.code) if user.totp is second else None
                    if step is None or step <= user.totp_step:
                        core.limiter.fail(ip, user.name)
                        core.limiter.fail(f"account:{user.id}")
                        audit.write("login_failed", ip, user=user.name, step="code")
                        return fail(401, "bad_code", "That code is not right. Codes change every 30 seconds and work once.")
                    previous, user.totp_step = user.totp_step, step
                    if refused := await saved("This sign-in", lambda: setattr(user, "totp_step", previous)):
                        return refused
        # Asked a last time, with nothing left to wait for between here and being signed in.
        if refused := turned_away(user, checked, ip):
            return refused
        core.limiter.reset(ip, user.name)
        core.limiter.reset(f"account:{user.id}", "")
        core.vault.adopt(key)
        if one_time:
            audit.write("login", ip, user=user.name, recovery_code=True, codes_left=len(user.totp_codes))
        else:
            audit.write("login", ip, user=user.name)
        return signed_in(request, body.remember, user)

    @app.post("/api/v1/logout")
    async def logout(body: LogoutIn, request: Request) -> Response:
        token = request.cookies.get(COOKIE)
        ended = int(core.sessions.get(token) is not None)
        # Whether any of what is ended was written down to outlast a restart: only then is there a disk to wait for.
        if body.scope == "this":
            # (Or was, and is not any more because the account has newer ones, while the file is known to
            # name what it should not: it may name this one still.)
            written = core.sessions.kept(token) or (core.sessions.stale and core.sessions.of_the_kept_kind(token))
            core.sessions.drop(token)
        else:  # this account's other browsers, or all of them
            staying = token if body.scope == "others" else None
            written = core.sessions.any_kept(request.state.user.id, keep=staying) or core.sessions.stale
            ended = core.sessions.drop_user(request.state.user.id, keep=staying)
        if ended:  # asked again and again with nobody left to sign out, it is not written down again and again
            audit.write("logout", client_ip(request), scope=body.scope)
        # Signed out here whatever comes of this; the answer says whether a restart would undo it.
        response = (await written_down() if written else None) or JSONResponse({"ok": True})
        if body.scope != "others":
            response.delete_cookie(COOKIE, path="/")
        if len(core.sessions) == 0 and not keep_unlocked():
            core.vault.lock()
            await manager.close()
        return response

    @app.post("/api/v1/password")
    async def change_password(body: PasswordIn, request: Request) -> Response:
        ip = client_ip(request)
        if blocked := throttled(ip):
            return blocked
        user: UserRecord = request.state.user
        if not user.auth:
            return fail(409, "no_password", "This account has no password here: it is signed in by your identity provider")
        try:
            key = await check_password(body.current, user.auth, ip)
        except KvmError as ex:
            return fail(ex.status, ex.code, ex.message)
        if key is None:
            core.limiter.fail(ip)
            return fail(401, "bad_password", "The current password is wrong")
        # The check took a moment. Signed out meanwhile (in another tab, or by an admin), this request has no
        # business left, least of all handing the key back to a wall that the last sign-out has just locked.
        if refused := still_allowed(request):
            return refused
        core.vault.adopt(key)
        previous = user.auth
        user.auth = await asyncio.to_thread(core.vault.rewrap, body.new)
        if refused := await saved("The new password", lambda: setattr(user, "auth", previous)):
            return refused
        here = request.cookies.get(COOKIE)
        core.sessions.drop_user(user.id, keep=here)
        core.sessions.carry_over(here, auth_mark(user))  # kept signed in here, and so it stays, a restart later too
        audit.write("password_changed", ip)
        return JSONResponse({"ok": True})

    # --- a way back in after a forgotten password ---------------------------------

    async def new_recovery() -> str:
        """Make a recovery key, replacing any earlier one. The vault must be unlocked. Caller saves."""
        key = new_recovery_key()
        store.recovery = await asyncio.to_thread(core.vault.rewrap, tidy_recovery_key(key))
        store.recovery_created = time.time()
        return key

    @app.post("/api/v1/recover")
    async def recover(body: RecoverIn, request: Request) -> Response:
        """Set a new password for an account, proving the right to with the recovery key instead of the old one."""
        ip = client_ip(request)
        if not core.initialized:
            return fail(409, "not_initialized", "qKVM has not been set up yet")
        if blocked := throttled(ip):
            return blocked
        name = body.name.strip()
        if name:
            user = store.user_named(name)
        elif len(store.users) == 1:
            user = store.users[0]
        else:
            return fail(422, "name_required", "Enter your user name")
        try:
            # Without such an account, or without a recovery key, the same work is done against a made-up record.
            key = await check_password(tidy_recovery_key(body.recovery_key), store.recovery if user else None, ip)
        except KvmError as ex:
            return fail(ex.status, ex.code, ex.message)
        if user is None or key is None:
            core.limiter.fail(ip, user.name if user else name)
            audit.write("recovery_failed", ip, user=user.name if user else "", **({} if user else {"no_such_account": True}))
            return fail(401, "bad_recovery", "The recovery key is not right" + (" for that user name" if len(store.users) > 1 else ""))
        opened = Vault()
        opened.adopt(key)
        previous = user.auth
        user.auth = await asyncio.to_thread(opened.rewrap, body.new_password)
        if refused := await saved("The new password", lambda: setattr(user, "auth", previous)):
            return refused
        core.sessions.drop_user(user.id)
        core.limiter.reset(ip, user.name)
        audit.write("password_recovered", ip, user=user.name)
        return JSONResponse({"ok": True})

    @app.post("/api/v1/recovery")
    async def renew_recovery(body: TotpBeginIn, request: Request) -> Response:
        """A new recovery key (admins only). The previous one stops working."""
        if refused := await own_password(request, body.password):
            return refused
        previous = (store.recovery, store.recovery_created)

        def keep_the_old_key() -> None:
            store.recovery, store.recovery_created = previous

        key = await new_recovery()
        if refused := await saved("The new recovery key", keep_the_old_key):
            return refused  # and the new key is shown to nobody: the one before it is still the key
        audit.write("recovery_key_created", client_ip(request))
        return JSONResponse({"recovery_key": key, "created": store.recovery_created})

    # --- two-factor sign-in, for one's own account --------------------------------

    async def own_password(request: Request, password: str) -> JSONResponse | None:
        """Refuse unless `password` is the signed-in account's own."""
        ip = client_ip(request)
        if blocked := throttled(ip):
            return blocked
        if not request.state.user.auth:
            return fail(409, "no_password", "This account has no password here: it is signed in by your identity provider")
        try:
            key = await check_password(password, request.state.user.auth, ip)
        except KvmError as ex:
            return fail(ex.status, ex.code, ex.message)
        if key is None:
            core.limiter.fail(ip)
            return fail(401, "bad_password", "Wrong password")
        # The check took half a second, and longer with others waiting: the account may have been signed out,
        # removed or given a lesser role meanwhile. What the password was asked for is not done for it then.
        return still_allowed(request)

    @app.post("/api/v1/totp/begin")
    async def totp_begin(body: TotpBeginIn, request: Request) -> Response:
        user: UserRecord = request.state.user
        if user.totp is not None:
            return fail(409, "enabled", "Two-factor sign-in is already on for this account")
        if refused := await own_password(request, body.password):
            return refused
        secret = totp.new_secret()
        totp_pending[user.id] = secret
        uri = totp.setup_uri(secret, user.name)
        return JSONResponse({"secret": totp.spaced(secret), "uri": uri, "qr": qr.matrix(uri)})

    @app.post("/api/v1/totp/enable")
    async def totp_enable(body: TotpEnableIn, request: Request) -> Response:
        user: UserRecord = request.state.user
        secret = totp_pending.get(user.id)
        if secret is None or user.totp is not None:
            return fail(409, "not_started", "Start again: the setup key is no longer valid")
        if blocked := throttled(client_ip(request)):
            return blocked
        # "A code works once" is about one key. This is a new one: its first code is not refused for having
        # the time of the last one of the key before it (switched off and on again within a minute).
        step = totp.matching_step(secret, body.code)
        if step is None:
            core.limiter.fail(client_ip(request))
            return fail(401, "bad_code", "That code is not right. Check the key in your app and the clock of your phone.")

        switched = user.totp_changes

        def not_on() -> None:
            user.totp, user.totp_codes, user.totp_step, user.totp_changes = None, [], 0, switched

        codes = totp.new_one_time_codes()
        user.totp = core.vault.encrypt(secret, f"totp:{user.id}")
        user.totp_changes += 1
        user.totp_codes = [core.vault.mark(f"{user.id}:{totp.as_issued(code)}", "one-time code") for code in codes]
        user.totp_step = step  # the code that switched it on is used up by that
        if refused := await saved("Two-factor sign-in", not_on):
            return refused
        del totp_pending[user.id]
        # Whoever was signed in to this account with its password alone is not any more, except here: the
        # second step is switched on against somebody who has the password.
        core.sessions.drop_user(user.id, keep=request.cookies.get(COOKIE))
        # After a restart a kept browser is let in by the mark of what it signed in with, the second step's
        # key included: this one has just given a code, and is given the new mark. No other has it, whether
        # or not their signing out got written down.
        core.sessions.carry_over(request.cookies.get(COOKIE), auth_mark(user))
        audit.write("totp_enabled", client_ip(request))
        # Shown this once: each stands in for the phone one time, and only what recognises them is kept.
        return JSONResponse({"ok": True, "user": me(user, request), "recovery_codes": codes})

    @app.post("/api/v1/totp/codes")
    async def totp_codes(body: TotpBeginIn, request: Request) -> Response:
        """Ten new one-time codes for one's own account. The ones that were left stop working."""
        user: UserRecord = request.state.user
        if user.totp is None:
            return fail(409, "not_enabled", "Two-factor sign-in is not on for this account")
        if refused := await own_password(request, body.password):
            return refused
        previous = user.totp_codes
        codes = totp.new_one_time_codes()
        user.totp_codes = [core.vault.mark(f"{user.id}:{totp.as_issued(code)}", "one-time code") for code in codes]
        if refused := await saved("The new codes", lambda: setattr(user, "totp_codes", previous)):
            return refused
        audit.write("totp_codes_created", client_ip(request))
        return JSONResponse({"ok": True, "user": me(user, request), "recovery_codes": codes})

    @app.post("/api/v1/totp/disable")
    async def totp_disable(body: TotpBeginIn, request: Request) -> Response:
        user: UserRecord = request.state.user
        if refused := await own_password(request, body.password):
            return refused
        previous = (user.totp, user.totp_codes, user.totp_step, user.totp_changes)

        def still_on() -> None:
            user.totp, user.totp_codes, user.totp_step, user.totp_changes = previous

        user.totp, user.totp_codes, user.totp_step, user.totp_changes = None, [], 0, user.totp_changes + 1
        totp_pending.pop(user.id, None)
        if refused := await saved("Switching two-factor sign-in off", still_on):
            return refused
        core.sessions.carry_all(user.id, auth_mark(user))  # less is asked of its browsers now than they gave: they stay, a restart later too
        audit.write("totp_disabled", client_ip(request))
        return JSONResponse({"ok": True, "user": me(user, request)})

    # --- tokens: for a script, or for a screen on the wall -------------------------------------

    displays_logged: dict[str, float] = {}  # display link id -> when its being opened was last written down

    def token_view(record: TokenRecord) -> dict[str, Any]:
        """What an admin may know of a token. Never the token."""
        return {
            "id": record.id, "name": record.name, "kind": record.kind, "role": record.role, "devices": record.devices, "groups": record.groups,
            "created": record.created, "expires": record.expires, "used": record.used,
        }  # fmt: skip

    @app.get("/api/v1/tokens")
    async def list_tokens() -> dict[str, Any]:
        return {"tokens": [token_view(t) for t in store.tokens]}

    @app.post("/api/v1/tokens")
    async def create_token(body: TokenIn, request: Request) -> Response:
        """Make a token for a script, or a link for a wall screen. It is shown this once; qKVM keeps what recognises it."""
        key, kept = metrics.new_token()
        known, now = {d.id for d in store.devices}, time.time()
        record = TokenRecord(
            id=secrets.token_hex(4),
            name=" ".join(body.name.split()),
            kind=body.kind,
            role="viewer" if body.kind == "display" else body.role,  # a screen looks
            devices=None if body.devices is None else [i for i in body.devices if i in known],
            groups=[] if body.devices is None else tidy_groups(body.groups),
            kept=kept,
            created=now,
            expires=now + body.days * 86400 if body.days else None,
        )
        store.tokens.append(record)
        if refused := await saved("The token", lambda: store.tokens.remove(record)):
            return refused
        audit.write("token_created", client_ip(request), name=record.name, kind=record.kind, role=record.role)
        return JSONResponse({"token": key, "record": token_view(record)}, status_code=201)

    @app.delete("/api/v1/tokens/{token_id}")
    async def remove_token(token_id: str, request: Request) -> Response:
        record = next((t for t in store.tokens if t.id == token_id), None)
        if record is None:
            return fail(404, "not_found", "Unknown token")
        place = store.tokens.index(record)
        store.tokens.remove(record)
        if refused := await saved("Taking the token back", lambda: store.tokens.insert(place, record)):
            return refused  # said: a token taken for withdrawn would work again after a restart
        core.sessions.drop_user(f"token:{record.id}")  # a screen that is showing with it goes dark now
        audit.write("token_removed", client_ip(request), name=record.name, kind=record.kind)
        return JSONResponse({"ok": True})

    @app.post("/api/v1/display")
    async def open_display(body: DisplayIn, request: Request) -> Response:
        """A browser on a wall screen hands in its display link, and is signed in as the screen it is for.

        Sessions do not outlast a restart; the link does. The page keeps it and asks again when its
        session is gone, so the screen comes back by itself after a power cut.
        """
        shown = token_for(body.key.strip(), "display")
        if shown is None:
            return fail(401, "bad_key", "This display link is not valid any more. Ask an admin for a new one.")
        now = shown.used = time.time()
        user = token_user(shown)
        showing = current_user(request)
        if showing is not None and showing.id == user.id:
            return JSONResponse({"ok": True, "user": me(user)})  # the screen that is on already, asking again
        # Whoever has the link can ask without end. What they get for it is bounded: so many screens at a
        # time, the oldest giving way, and a line in the activity log now and then, not one for each.
        core.sessions.keep_newest(user.id, DISPLAY_SESSIONS - 1)
        if now - displays_logged.get(shown.id, 0.0) > 60:
            displays_logged[shown.id] = now
            audit.write("display_opened", client_ip(request), user=user.name)
        return signed_in(request, remember=True, user=user)

    def security_view() -> dict[str, Any]:
        # Who is under the rule and has not set it up yet: they can sign in, and do nothing else until they have.
        return {"require_totp": store.server.require_totp, "without": [u.name for u in store.users if must_enroll(u)]}

    @app.get("/api/v1/security")
    async def security() -> dict[str, Any]:
        return security_view()

    @app.put("/api/v1/security")
    async def set_security(body: SecurityIn, request: Request) -> Response:
        """Say who has to have two-factor sign-in: nobody, admins, admins and operators, or everybody."""
        user: UserRecord = request.state.user
        if body.require_totp and user.totp is None:
            # Whoever makes the rule has done it themselves: nobody is locked into setting it up by somebody who has not.
            return fail(409, "own_first", "Switch two-factor sign-in on for your own account first (Settings > Security), then require it of others")
        previous = store.server.require_totp
        store.server.require_totp = body.require_totp
        if refused := await saved("This rule", lambda: setattr(store.server, "require_totp", previous)):
            return refused
        audit.write("security_changed", client_ip(request), require_totp=body.require_totp or "nobody")
        return JSONResponse(security_view())

    # --- accounts ---------------------------------------------------------------

    def user_view(user: UserRecord, request: Request, signed_in_from: dict[str, int] | None = None) -> dict[str, Any]:
        """What an admin may know about an account. Never anything of the password."""
        if signed_in_from is None:
            signed_in_from = core.sessions.counts()
        return {
            **me(user),
            "devices": user.devices,
            "groups": user.groups,
            "suspended": user.suspended,
            "created": user.created,
            "you": user.id == request.state.user.id,
            "sessions": signed_in_from.get(user.id, 0),
        }

    def check_user(body: UserIn, own: UserRecord | None) -> JSONResponse | None:
        if body.password and len(body.password) < MIN_PASSWORD:
            return fail(422, "invalid", f"The password must be at least {MIN_PASSWORD} characters")
        if own is None and not body.password and not core.sso_header:
            return fail(422, "invalid", "Choose a password for the new account")
        clash = store.user_named(body.name)
        if clash is not None and clash is not own:
            return fail(409, "duplicate", "There is already an account with that name")
        if not core.vault.unlocked:
            return fail(409, "locked", "Sign in again first")
        return None

    def fill_user(user: UserRecord, body: UserIn) -> None:
        user.name, user.role = body.name, body.role
        # An admin manages every KVM; a list would only hide some from the person who can lift it anyway.
        known = {d.id for d in store.devices}
        user.devices = None if body.devices is None or body.role == "admin" else [i for i in body.devices if i in known]
        user.groups = [] if user.devices is None else tidy_groups(body.groups)

    def admins() -> int:
        """Admins who can sign in. One that is suspended is not one to fall back on."""
        return sum(1 for u in store.users if u.role == "admin" and not u.suspended)

    @app.get("/api/v1/users")
    async def list_users(request: Request) -> dict[str, Any]:
        signed_in_from = core.sessions.counts()  # counted once, not once per account
        return {"users": [user_view(u, request, signed_in_from) for u in store.users]}

    @app.post("/api/v1/users")
    async def create_user(body: UserIn, request: Request) -> Response:
        if problem := check_user(body, None):
            return problem
        user = UserRecord(id=secrets.token_hex(4), name=body.name, created=time.time())
        fill_user(user, body)
        # Without a password (where an identity proxy signs people in) there is nothing for one to unlock: no
        # copy of the data key is kept for this account, and nobody signs in as it by typing anything.
        user.auth = await asyncio.to_thread(core.vault.rewrap, body.password) if body.password else {}
        store.users.append(user)
        if refused := await saved("The new account", lambda: store.users.remove(user)):
            return refused
        audit.write("user_added", client_ip(request), account=user.name, role=user.role)
        return JSONResponse({"user": user_view(user, request)}, status_code=201)

    @app.put("/api/v1/users/{user_id}")
    async def update_user(user_id: str, body: UserIn, request: Request) -> Response:
        user = store.user(user_id)
        if user is None:
            return fail(404, "not_found", "Unknown account")
        if problem := check_user(body, user):
            return problem
        yourself = user.id == request.state.user.id
        if body.role != user.role:
            if yourself:
                return fail(409, "own_role", "You cannot change your own role; ask another admin")
            if user.role == "admin" and not user.suspended and admins() == 1:
                return fail(409, "last_admin", "This is the only admin; make someone else an admin first")
        if body.suspended and yourself:
            return fail(409, "yourself", "You cannot suspend the account you are signed in with")
        if yourself and (body.password or body.totp_off):
            # Here nothing is asked for. A browser left open for a minute would be an account taken over for good.
            return fail(409, "own_account", "Change your own password and second step under Settings > Security, where your current password is asked for")
        before = (user.name, user.role, user.devices, user.groups, user.suspended, user.auth, user.totp, user.totp_codes, user.totp_step, user.totp_changes)

        def as_it_was() -> None:
            user.name, user.role, user.devices, user.groups, user.suspended, user.auth, user.totp, user.totp_codes, user.totp_step, user.totp_changes = before

        fill_user(user, body)
        was_suspended = user.suspended
        if body.suspended is not None:
            user.suspended = body.suspended
        if body.password:
            user.auth = await asyncio.to_thread(core.vault.rewrap, body.password)
        second_step_off = body.totp_off and user.totp is not None
        if second_step_off:
            user.totp, user.totp_codes, user.totp_step, user.totp_changes = None, [], 0, user.totp_changes + 1
        # Nobody is signed out, and nothing is written down as done, before it is: a password that could
        # not be saved is not that account's password, now or after the next thing that is saved.
        if refused := await saved("The change to this account", as_it_was):
            return refused
        if body.password:
            # A changed password signs the account out everywhere, except in the browser doing the change.
            core.sessions.drop_user(user.id, keep=request.cookies.get(COOKIE) if yourself else None)
            if yourself:
                core.sessions.carry_over(request.cookies.get(COOKIE), auth_mark(user))  # kept signed in here, a restart later too
        if second_step_off:
            core.sessions.carry_all(user.id, auth_mark(user))  # less is asked of its browsers now than they gave
            audit.write("totp_disabled", client_ip(request), account=user.name)
        if user.suspended != was_suspended:
            if user.suspended:
                core.sessions.drop_user(user.id)  # out at once, wherever they are signed in
            audit.write("user_suspended" if user.suspended else "user_resumed", client_ip(request), account=user.name)
        audit.write("user_changed", client_ip(request), account=user.name, role=user.role, password=bool(body.password))
        return JSONResponse({"user": user_view(user, request)})

    @app.post("/api/v1/users/{user_id}/logout")
    async def sign_out_everywhere(user_id: str, request: Request) -> Response:
        """End every session of an account, now. Its password and everything else stay as they are."""
        user = store.user(user_id)
        if user is None:
            return fail(404, "not_found", "Unknown account")
        staying = request.cookies.get(COOKIE) if user.id == request.state.user.id else None
        written = core.sessions.any_kept(user.id, keep=staying) or core.sessions.stale
        ended = core.sessions.drop_user(user.id, keep=staying)
        audit.write("user_signed_out", client_ip(request), account=user.name, sessions=ended)
        if written and (refused := await written_down()):
            return refused
        return JSONResponse({"ok": True, "ended": ended})

    @app.delete("/api/v1/users/{user_id}")
    async def delete_user(user_id: str, request: Request) -> Response:
        user = store.user(user_id)
        if user is None:
            return fail(404, "not_found", "Unknown account")
        if user.id == request.state.user.id:
            return fail(409, "yourself", "You cannot remove the account you are signed in with")
        if user.role == "admin" and not user.suspended and admins() == 1:
            return fail(409, "last_admin", "This is the only admin")
        place = store.users.index(user)
        store.users.remove(user)
        if refused := await saved("Removing this account", lambda: store.users.insert(place, user)):
            return refused  # said: an account taken for removed would be back, password and all, after a restart
        core.sessions.drop_user(user.id)
        audit.write("user_removed", client_ip(request), account=user.name)
        return JSONResponse({"ok": True})

    # --- the wall ---------------------------------------------------------------

    def abilities_of(record: DeviceRecord) -> list[str]:
        """What this tile can do (kvm.ABILITIES): as its driver last found it, or the driver's own list while nothing
        is known of the device (the saved passwords locked, say). A client goes by this, never by the kind."""
        device = manager.devices.get(record.id)
        return device.abilities() if device is not None else can_do(*driver_for(record.kind).can)

    @app.get("/api/v1/wall")
    async def wall(request: Request) -> dict[str, Any]:
        shown = [d for d in store.devices if allowed(request, d.id)]
        # Tiles that are one and the same device, reached by two addresses: each is told of the others,
        # so that whoever looks after the wall can decide which to keep. (Of those this account may see.)
        marks = {d.id: identity(d) for d in shown}
        alike: dict[str, list[DeviceRecord]] = {}
        for record in shown:
            mark = marks[record.id]
            if mark is not None:
                alike.setdefault(mark, []).append(record)
        devices = []
        for record in shown:
            # (A handful at most, as far as a person can make them. No more than that is listed of however
            # many there are: the list of all pairs of a thousand tiles was a quarter of a gigabyte.)
            twins = [d for d in alike.get(marks[record.id] or "", []) if d is not record][:MOST_TWINS]
            same_as = [{"id": d.id, "name": d.name, "host": urlsplit(d.url).netloc} for d in twins]
            devices.append({**view(record, editing=request.state.user.role == "admin"), "same_as": same_as, "can": abilities_of(record)})
        # "live": the form of the live connection this server speaks (live.py); a client that speaks another asks for none.
        return {"interval": store.server.interval, "live": live.FORM, "devices": devices}

    @app.put("/api/v1/wall/order")
    async def arrange(body: OrderIn, request: Request) -> Response:
        """Put the tiles in an order: the devices named first, in that order, and the rest after them as they stood.

        It is the wall's own order, the same for every browser and every screen that shows it. A
        browser may still sort for itself (by name, by what needs attention): that is its own affair.
        """
        place = {device_id: at for at, device_id in reversed(list(enumerate(body.ids)))}  # named twice: where it was named first
        before = list(store.devices)
        store.devices.sort(key=lambda d: (0, place[d.id]) if d.id in place else (1, 0))  # (a stable sort: the rest keep their order)
        if refused := await saved("The order", lambda: store.devices.__setitem__(slice(None), before)):
            return refused
        audit.write("wall_arranged", client_ip(request), devices=len(store.devices))
        return JSONResponse({"ok": True, "ids": [d.id for d in store.devices]})

    @app.get("/api/v1/status")
    async def status(request: Request) -> Response:
        ids = [device_id for device_id in manager.devices if allowed(request, device_id)]
        results = await asyncio.gather(*(manager.devices[i].status() for i in ids))
        # (How each of them is, as it was found while waiting: of those that whoever asked may still see.)
        if refused := still_allowed(request):
            return refused
        return JSONResponse({device_id: result for device_id, result in zip(ids, results, strict=True) if still_shown(request, device_id) is None})

    @app.get("/api/v1/devices/{device_id}/snapshot")
    async def snapshot(
        device_id: str,
        request: Request,
        w: int = Query(640, ge=1, le=16384),
        age: float | None = Query(None, ge=0, le=3600),
        big: bool = Query(False),
    ) -> Response:
        """One frame, at least `w` pixels wide when the source has that many.

        `age`: how old, in seconds, the frame may be. A tile that refreshes once a second does not
        need one taken for it alone when another browser got one a moment ago. `big`: this is the
        enlarged (large) view of the machine, so a PC with Intel AMT holds a session open for it (and
        opens one before a power-on), where a tile that is only shown gets a still now and then.
        """
        device = manager.devices.get(device_id)
        if device is None or not allowed(request, device_id):
            return fail(404, "not_found", "Unknown device")
        try:
            frame = await device.snapshot(w, age, big=big)
        except KvmError as ex:
            return fail(ex.status, ex.code, ex.message)
        if refused := still_shown(request, device_id):
            return refused
        headers = {"Cache-Control": "no-store", "X-KVM-Signal": "1" if frame.signal else "0"}
        if frame.still:
            # A still kept between sessions (a PC with Intel AMT whose tile is only shown): the page says its age.
            headers["X-KVM-Still"] = "1"
            headers["X-KVM-Age"] = str(max(0, round(time.monotonic() - frame.taken_at)))
        return Response(frame.data, media_type=frame.content_type, headers=headers)

    # --- history (W4): the one route that reads it; what feeds it stands above the lifespan ----------------------

    @app.get("/api/v1/devices/{device_id}/history")
    async def device_history(
        device_id: str,
        request: Request,
        what: Literal["summary", "states", "samples", "events"] = "summary",
        since: float | None = Query(None, ge=0, le=1e11),  # seconds since 1970; left out: a week back (samples: a day)
        until: float | None = Query(None, ge=0, le=1e11),  # left out: now
        limit: int = Query(1000, ge=1, le=history.MOST_ROWS),
        every: int = Query(0, ge=0, le=86400),  # samples: averaged over spans of that many seconds; 0: as they were taken
    ) -> Response:
        """What the history says of one machine, for the roles that may see it (see history.py and the README).

        `summary`: when it was first and last heard from, and how much of the window it was watched and online.
        `states`, `samples`, `events`: the rows in the window, oldest first, a bounded page (`more` says if it was cut).
        """
        if store.device(device_id) is None or not allowed(request, device_id):
            return fail(404, "not_found", "Unknown device")
        now = time.time()
        until_at = now if until is None else until
        since_at = until_at - (history.DAY if what == "samples" else history.WEEK) if since is None else since
        if since_at > until_at:
            return fail(422, "invalid", "since: has to be before until")
        # Its turn: after the read of the same account or token that is under way, and the pause after that one.
        try:
            found = await history_reads.run(request.state.user.id, lambda: kept.read(device_id, what, since_at, until_at, limit, every, now))
        except TurnRefused as turned:
            return turned.reply
        except history.NotReadable as ex:
            return fail(503, "history_unavailable", str(ex))
        # The read took its time. Whoever asked may have lost the right to the machine meanwhile.
        if refused := still_allowed(request):
            return refused
        if store.device(device_id) is None or not allowed(request, device_id):
            return fail(404, "not_found", "Unknown device")
        return JSONResponse(found)

    # --- devices ----------------------------------------------------------------

    async def connect(record: DeviceRecord, password: str | None, force: bool, take: bool = False) -> tuple[Device, dict[str, Any]]:
        """Contact a device with these settings: (its client, what it says about itself).

        Raises KvmError when the device can't be reached or logged in to, unless `force`. `take`: whoever typed the password
        says "this is it", and the machine that answers now is the one the tile is for (see DeviceSpec.machine); where nothing
        answered (saved without being checked), the machine it was for stands, and nothing is taken at a later look.
        """
        if password:
            vncdevice.forget_pace(record.url)  # (a console behind a door is asked for at once as well: before its client is made, which reads it)
        client = manager.client(record, password)
        kept = record.machine
        if take:
            client.spec.machine = ""
        if password:
            # Typed by a person just now, for this device: tried at once, whatever was rejected there before
            # and however long that was to wait. (A save without one finds the wait standing, and offers nothing.)
            REJECTED.forget(client.spec)
        about: dict[str, Any] = {}
        identified = False
        try:
            about = await client.identify()
            identified = True
        except KvmError:
            if not force:
                await client.close()
                raise
        except Exception:
            log.exception("%s: the device answered in a way that was not expected", record.url)
            await client.close()
            raise KvmError("bad_response", "The device answered in a way qKVM does not understand") from None
        if take and not identified:
            client.spec.machine = kept  # (nothing was found to take: the next machine to answer there is not taken for it)
        record.cert_pem = client.spec.cert_pem  # keep what was trusted on first contact
        record.machine = client.spec.machine  # ...and the machine it was found to be, where its driver can tell (see DeviceSpec.machine)
        said = about.pop("ident", None)  # what it says it is: for telling it from the others, not for the page
        if not record.ident.startswith("own:"):
            if isinstance(said, str) and IDENT.fullmatch(said):
                record.ident = said
            elif identified and said == "":
                # (Its driver read it, and it says none: a number it gave before is not kept. None is "not read just now",
                # which leaves what is kept as it is.)
                record.ident = ""
        return client, about

    def twin_of(record: DeviceRecord) -> DeviceRecord | None:
        """The device already on the wall that `record` is another address of, if there is one."""
        mark = identity(record)
        return next((d for d in store.devices if d.id != record.id and mark is not None and identity(d) == mark), None)

    def same_device(twin: DeviceRecord, said_so: bool = False) -> JSONResponse:
        """`said_so`: it is known again by what it says of itself (a number), not by a certificate it has the key to."""
        host = urlsplit(twin.url).netloc
        said = f"This {'says it is' if said_so else 'is'} the same device as {twin.name}, which is on the wall already" + ("" if twin.name == host else f" ({host})")
        return JSONResponse({"code": "same_device", "message": said, "same_as": {"id": twin.id, "name": twin.name, "host": host}}, status_code=409)

    def parse_vnc(body: DeviceIn, own: DeviceRecord | None) -> tuple[str, str, str] | JSONResponse:
        """A VNC server, said so by the kind chosen or by its address (vnc://, vncs://): it speaks no HTTP, and is not asked what it is."""
        try:
            url, open_url = vncdevice.vnc_url(body.url), _open_url(body.open_url)
        except ValueError as ex:
            return fail(422, "invalid", str(ex).capitalize())
        if any(d.url == url and d is not own for d in store.devices):
            return fail(409, "duplicate", "This device is already on the wall")
        return url, open_url, "vnc"

    async def parse_proxmox(body: DeviceIn, own: DeviceRecord | None) -> tuple[str, str, str] | JSONResponse:
        """A guest of Proxmox, said so by the kind chosen: the address names the guest, by its number and its node.
        Where only its number is given, its node is asked of Proxmox with the token typed (or, at the address it was
        saved for, the saved one: never sent anywhere else on the strength of an address typed in an edit)."""
        try:
            found, open_url = proxmox.address_of(body.url), _open_url(body.open_url)
        except ValueError as ex:
            return fail(422, "invalid", str(ex).capitalize())
        if found.vmid is None:
            return fail(422, "invalid", "Name the guest: the Proxmox's address with the guest's ID after it (pve.lan/100), or pick guests from its list")
        node = found.node
        if node is None:
            saved_for = None  # the tile being edited, where its token was saved for this very Proxmox
            if own is not None and own.kind == "proxmox" and own.username == body.username.strip():
                try:
                    saved_for = own if proxmox.address_of(own.url).origin == found.origin else None
                except ValueError:
                    saved_for = None
            token = body.password or (manager.spec(saved_for).password if saved_for is not None else "")
            if not token:
                return fail(422, "invalid", "Name the guest's node as well (pve.lan/pve1/100), or type the token's secret, with which its node is looked up")
            try:
                listed, _, _ = await proxmox.guests(
                    found.origin, body.username.strip(), token, typed=bool(body.password),
                    tls=saved_for.tls if saved_for is not None else "pinned", cert_pem=saved_for.cert_pem if saved_for is not None else None,
                )  # fmt: skip
            except KvmError as ex:
                return fail(422, ex.code, ex.message)
            node = next((guest["node"] for guest in listed if guest["vmid"] == found.vmid), None)
            if node is None:
                return fail(422, "invalid", f"The token sees no virtual machine {found.vmid} on this Proxmox")
        url = proxmox.guest_url(found.origin, node, found.vmid)
        if any(d.url == url and d is not own for d in store.devices):
            return fail(409, "duplicate", "This device is already on the wall")
        return url, open_url, "proxmox"

    async def parse(body: DeviceIn, own: DeviceRecord | None) -> tuple[str, str, str] | JSONResponse:
        """Check what was typed: (address, console address, driver kind), or what is wrong with it."""
        if body.kind == "vnc" or vncdevice.is_vnc(body.url) or (body.kind == "auto" and own is not None and own.kind == "vnc"):
            return parse_vnc(body, own)
        if body.kind == "proxmox" or (body.kind == "auto" and own is not None and own.kind == "proxmox"):
            return await parse_proxmox(body, own)
        try:
            url, open_url = device_url(body.url), _open_url(body.open_url)
        except ValueError as ex:
            return fail(422, "invalid", str(ex).capitalize())
        kind: str = body.kind
        try:
            typed = urlsplit(body.url.strip() if "://" in body.url else f"https://{body.url.strip()}").port
        except ValueError:
            typed = None
        if kind == "amt" and typed is None:
            # Intel AMT answers on ports of its own: an engine's address typed without one is at its port (16993 with TLS,
            # 16992 plain), not at 443 or 80, where its redirection port would not be known (amt.REDIRECTION_BESIDE).
            url = device_url(amt.at_its_port(url))
        if kind == "auto" and own is not None and url == own.url:
            kind = own.kind  # same device as before: no need to ask it again
            # Every edit signs in to the device again, with the password typed or the one saved. For a JetKVM at
            # a plain address that is about to go out in the clear: whether it offers HTTPS by now (its owner
            # may have switched that on since) is asked first, and that is then its address. What it is, is
            # not asked again: one that does not answer just now is still a JetKVM.
            twin = other_way(url) if kind == "jetkvm" and url.startswith("http://") and (body.password or own.secret is not None) else None
            if twin is not None and twin.startswith("https://") and await jetkvm_at(twin):
                url = twin
        if kind == "auto":
            try:
                kind, url = await detect_kind(url, "://" in body.url, typed)
            except KvmError as ex:
                return fail(422, ex.code, ex.message)
        if any(d.url == url and d is not own for d in store.devices):
            return fail(409, "duplicate", "This device is already on the wall")
        return url, open_url, kind

    @app.post("/api/v1/devices")
    async def create_device(body: DeviceIn, request: Request) -> Response:
        parsed = await parse(body, None)
        if isinstance(parsed, JSONResponse):
            return parsed
        url, open_url, kind = parsed
        record = DeviceRecord(
            id=secrets.token_hex(4),
            name=body.name.strip(),
            url=url,
            username=body.username.strip(),
            open_url=open_url,
            tls=body.tls or "pinned",
            kind=kind,
            group=" ".join(body.group.split()),
            alerts=body.alerts is not False,
            fingerbot_strength=body.fingerbot_strength or FINGERBOT_STRENGTHS[0],
        )
        if body.tls is None and url.startswith("https") and await publicly_trusted(url):
            # Reached through somebody's front door, whose certificate changes every few weeks: not one to remember.
            record.tls = "system"
        try:
            client, about = await connect(record, body.password, body.force)
        except KvmError as ex:
            return fail(422, ex.code, ex.message)
        if not record.name:
            hostname = str(about.get("hostname") or "")
            # (No longer than a name may be: a device named by an address of ninety characters could not be
            # edited any more, nor read back from the file it was exported to.)
            record.name = (hostname if hostname.lower() not in GENERIC_NAMES else urlsplit(url).netloc)[:80]
            client.spec.name = record.name
        async with one_change:
            # The KVM was talked to without holding up other changes. What was checked before that is checked again.
            refusal = still_allowed(request)
            if refusal is None and any(d.url == url for d in store.devices):
                refusal = fail(409, "duplicate", "This device is already on the wall")
            twin = twin_of(record)
            if refusal is None and twin is not None and not body.keep_both:
                # Reached by another address, it is still the one device. Whether it is to be on the wall
                # twice is for the person adding it to say, and they are asked.
                refusal = same_device(twin, said_so=bool(record.ident))
            if refusal is not None:
                await client.close()
                return refusal
            if twin is not None:
                record.ident = f"own:{record.id}"  # told to keep both: from here on it is a device of its own
            if body.password:
                record.secret = core.vault.encrypt(body.password, record.id)
            # What is on the wall and what is saved change together, before the disk is waited for, and go
            # back together should the write fail: the two always agree, and no connection is left without an owner.
            store.devices.append(record)
            await manager.adopt(client)
            try:
                await save()
            except OSError as ex:
                store.devices.remove(record)
                await manager.remove(record.id)
                kept.forget(record.id)  # (looked at while the settings were being written: what the history noted of it goes too)
                return not_saved("The new device", ex)
        audit.write("device_added", client_ip(request), device=record.name, device_id=record.id, url=url)
        return JSONResponse({"device": view(record), "about": about}, status_code=201)

    @app.put("/api/v1/devices/{device_id}")
    async def update_device(device_id: str, body: DeviceIn, request: Request) -> Response:
        record = store.device(device_id)
        if record is None:
            return fail(404, "not_found", "Unknown device")
        parsed = await parse(body, record)
        if isinstance(parsed, JSONResponse):
            return parsed
        url, open_url, kind = parsed
        changed = dataclasses.replace(
            record,
            name=body.name.strip() or record.name,
            url=url,
            username=body.username.strip(),
            open_url=open_url,
            tls=body.tls or record.tls,
            kind=kind,
            group=" ".join(body.group.split()),
            alerts=record.alerts if body.alerts is None else body.alerts,
            fingerbot_strength=body.fingerbot_strength or record.fingerbot_strength,
        )
        moved, typed = url != record.url, bool(body.password)
        # A new address, and no password typed: the saved one is about to be used somewhere it was not saved
        # for. That is safe where what answers there can be known for the same device, by the certificate
        # remembered for it, which is then kept and has to be shown again. Anywhere else (a device that shows
        # no certificate, a mode that remembers none) the password is typed, by whoever says "this is it".
        # (Not a server's controller: its maker may have put one certificate, and one key, on every board. Two
        # of them are not told apart by it, and the password of one is not for the other. Nor a guest of Proxmox:
        # the certificate is its Proxmox's, or a proxy's in front of it, or a wildcard shared with other hosts, and
        # its saved API token is not for whatever else shows that one. As core.identity, which knows neither by it.)
        known_again = (
            moved
            and not typed
            and record.tls == changed.tls == "pinned"
            and bool(record.cert_pem)
            and url.startswith("https")
            and not {"redfish", "proxmox"} & {record.kind, kind}
        )
        # A JetKVM that was on plain HTTP and offers HTTPS now, at the same host: its saved password goes with
        # it without being typed, as it does when the tile follows by itself. It only gains by the move.
        to_https = moved and record.kind == kind == "jetkvm" and record.url.startswith("http://") and url == other_way(record.url)
        if moved and not typed and not known_again and not to_https and record.secret is not None:
            return fail(422, "password_needed", "There is nothing to know this device by at another address. Type its password to use it there.")
        if changed.tls != record.tls or (moved and not known_again):
            changed.cert_pem = None  # another mode, or another place that somebody vouched for: trust is established afresh
        # Whoever types the password says "this is it": the machine that answers now is the one the tile is for (a PC whose
        # board was changed, or the one the tile said answers there instead), where one answers (`connect`'s `take`); saved
        # without being checked, the one remembered stands. Not typed, it has to be the one remembered.
        # "Save anyway" is for a device that is down, at the address it was vouched for. Not for a new address
        # the saved password goes along to: saved there unchecked, the tile says "another certificate", and
        # whoever then presses "Trust" (or sets it to "don't check") has sent the password to whatever is there.
        carried = moved and not typed and record.secret is not None
        # Saved again by a person (another address, another certificate check, the password, or nothing changed but the
        # saving): a console behind a door is asked for afresh, whatever pause it was in. Before the client is made, which
        # reads it; and again once the client before it is gone, which may have written meanwhile.
        for url_ in (record.url, changed.url):
            vncdevice.forget_pace(url_)
        try:
            client, _ = await connect(changed, body.password or None, body.force and not carried, take=typed)
        except KvmError as ex:
            if body.force and carried:
                return fail(422, "password_needed", f"This device could not be checked at its new address ({ex.message}). Type its password to save it there all the same.")
            return fail(422, ex.code, ex.message)
        async with one_change:
            # The KVM was talked to without holding up other changes. What was checked before that is checked again.
            refusal = still_allowed(request)
            if refusal is None and store.device(device_id) is not record:
                refusal = fail(409, "conflict", "This KVM was changed or removed by someone else just now. Look at it again.")
            if refusal is None and body.keep_both and twin_of(changed) is not None:
                changed.ident = f"own:{record.id}"  # the two are to stay, and nobody is to be asked about them again
            if refusal is None and any(d.url == url and d is not record for d in store.devices):
                refusal = fail(409, "duplicate", "This device is already on the wall")
            if refusal is not None:
                await client.close()
                return refusal
            if body.password:
                changed.secret = core.vault.encrypt(body.password, changed.id)
            at = store.devices.index(record)
            store.devices[at] = changed
            await manager.adopt(client)
            for url_ in (record.url, changed.url):
                vncdevice.forget_pace(url_)
            try:
                await save()
            except OSError as ex:
                store.devices[at] = record
                await manager.replace(record)
                return not_saved("The change to this device", ex)
        audit.write("device_changed", client_ip(request), device=changed.name, device_id=changed.id, url=url)
        return JSONResponse({"device": view(changed)})

    @app.delete("/api/v1/devices/{device_id}")
    async def delete_device(device_id: str, request: Request) -> Response:
        """Take one machine off the wall, the way several are taken off (take_off): the settings written without it first,
        and only then the machine taken off the wall and its connection closed. A write that fails changes nothing, so
        nothing is put back. (It was taken off first: a write that failed had told its live lines that it was gone, let
        go of their keys, cut off what was being done to it and signed in to it anew, and then said that nothing was
        changed.) Its answers are as they were: `ok`; 404 `not_found`; 507 `not_saved`."""
        record = store.device(device_id)
        if record is None:
            return fail(404, "not_found", "Unknown device")
        answer = await removing(frozenset({device_id}), f"Removing {record.name}", client_ip(request))
        return JSONResponse({"ok": True}) if answer.status_code == 200 else answer

    @app.post("/api/v1/devices/remove")
    async def remove_devices(body: RemoveIn, request: Request) -> Response:
        """Take several machines off the wall in one go: every one of them, or none.

        With the settings written once for all of them, and for each what goes with one that the route above removes:
        its saved password, its history, what alerts knew of it, its line in the activity log. An id that is not on the
        wall (removed by somebody else a moment ago, or never there) removes nothing, and the answer names it: what was
        asked for is not what would be done. Nor is a write that fails.

        Nothing on the wall changes until the file says that they are gone: the settings are written as they will be,
        and only then are the machines taken off and their connections closed. (Taken off first, a write that failed had
        them to put back, and meanwhile their live lines had been told that they were gone.) The work is a task of its
        own, which the answer waits for: should the request be cut off (qKVM stopping, its listeners opened anew), the
        task goes on to the end the file has (within the time a stopping wall gives it: see take_off), and in a request
        that is being stopped nothing is awaited.

        What is being done to one of them at this moment does not keep it, as it does not keep a single one: the
        admin's word is the last. An action on its way is answered as one cut off by an edit, "it may have been done"
        (its connection is taken away under it, kvm.RETIRED), and a live line is told, and lets go of the keys it
        holds down on the machine before the connection goes (live.Lines.retiring). Refused instead, a machine that
        somebody held over a live line, or typed to again and again, could be kept on the wall for as long as they liked.
        """
        wanted = list(dict.fromkeys(body.ids))  # (an id given twice is one machine)
        on_wall = {record.id: record for record in store.devices}
        unknown = [device_id for device_id in wanted if device_id not in on_wall]
        if unknown:
            named = ", ".join(unknown[:5]) + (f" and {len(unknown) - 5} more" if len(unknown) > 5 else "")
            said = f"{'This is' if len(unknown) == 1 else 'These are'} not on the wall: {named}. Nothing was removed."
            return JSONResponse({"code": "not_found", "message": said, "unknown": unknown}, status_code=404)
        what = f"Removing {on_wall[wanted[0]].name}" if len(wanted) == 1 else f"Removing {len(wanted)} KVMs"
        return await removing(frozenset(wanted), what, client_ip(request))

    async def removing(going: frozenset[str], what: str, ip: str) -> Response:
        """take_off, as a task of its own that the request waits for: cut off, the request lets go of it and it ends as its
        write does (see remove_devices). For one machine (delete_device) as for several."""
        work = asyncio.ensure_future(take_off(going, what, ip))
        background.add(work)  # (one that a stopping wall gives time to finish: see lifespan)
        work.add_done_callback(background.discard)
        try:
            return await asyncio.shield(work)
        except asyncio.CancelledError:
            work.add_done_callback(unheard)  # (cut off: should it fail now, nobody else would hear of it)
            raise

    def unheard(work: asyncio.Task[Response]) -> None:
        if not work.cancelled() and (ex := work.exception()) is not None:
            log.error("removing machines failed after its request was cut off", exc_info=ex)

    async def take_off(going: frozenset[str], what: str, ip: str) -> Response:
        """The part of removing one machine or several that waits: the file, then the wall, then the connections.

        Cut off with its request, it goes on without the turn for changes, within the time a stopping wall gives it
        (BACKGROUND_OWED; a write that takes longer still ends in its thread, and the wall is left as it was in memory).
        A stop cuts off every request at once, so what can come between is only what the program changes by itself (a
        JetKVM followed to HTTPS, a certificate remembered, the unlock note), none of which keeps a place in the list of
        devices across a wait.
        """
        try:
            await save(leaving=going)
        except OSError as ex:
            return not_saved(what, ex)
        # Written down. From here to the end of what goes with them nothing is waited for: no other change sees half of it.
        places = [record for record in store.devices if record.id in going]
        store.devices[:] = [record for record in store.devices if record.id not in going]
        taken = manager.take(going)
        try:
            together = {"note": f"one of {len(places)} removed together"} if len(places) > 1 else {}
            for record in places:
                watcher.forget(record.id)
            kept.forget(*(record.id for record in places))  # their history goes with them (never dropped, however full the history's queue)
            for record in places:
                audit.write("device_removed", ip, device=record.name, device_id=record.id, url=record.url, **together)
        finally:
            # Closed side by side, whatever the above came to; every live line told first, and what it held down let go
            # of through the machine's own connection.
            await manager.retire_all(taken)
        return JSONResponse({"ok": True, "removed": [record.id for record in places]})

    def certificate_at(record: DeviceRecord) -> str | None:
        """Where the certificate a tile checks is asked for: its https address, or a `vncs://` server's host and port (asked
        at its address as an https one, it was asked at port 443, somebody else's); None for a device reached without TLS."""
        if record.url.startswith("https"):
            return record.url
        if record.url.startswith("vncs://"):
            return vncdevice.certificate_address(record.url)
        return None

    @app.get("/api/v1/devices/{device_id}/certificate")
    async def certificate(device_id: str) -> Response:
        record = store.device(device_id)
        if record is None:
            return fail(404, "not_found", "Unknown device")
        where = certificate_at(record)
        if where is None:
            return JSONResponse({"saved": None, "presented": None})
        try:
            presented = fingerprint(await fetch_certificate(where))
        except KvmError as ex:
            return fail(ex.status, ex.code, ex.message)
        saved = saved_fingerprint(record.cert_pem)
        return JSONResponse({"saved": saved, "presented": presented})

    @app.post("/api/v1/devices/{device_id}/trust")
    async def trust(device_id: str, body: TrustIn, request: Request) -> Response:
        record = store.device(device_id)
        if record is None:
            return fail(404, "not_found", "Unknown device")
        try:
            pem = await fetch_certificate(certificate_at(record) or record.url)
        except KvmError as ex:
            return fail(ex.status, ex.code, ex.message)
        # Pin only the certificate the user was shown, not whatever is there a moment later.
        if not same_text(fingerprint(pem), body.fingerprint.strip().upper()):
            return fail(409, "cert_mismatch", "The device now presents a different certificate than the one shown")
        async with one_change:
            refusal = still_allowed(request)
            if refusal is None and store.device(device_id) is not record:  # while the certificate was being fetched
                refusal = fail(409, "conflict", "This KVM was changed or removed by someone else just now. Look at it again.")
            if refusal is not None:
                return refusal
            # A new record rather than a changed one: an edit that is being checked right now sees that it was overtaken.
            trusted = dataclasses.replace(record, cert_pem=pem, tls="pinned")
            at = store.devices.index(record)
            store.devices[at] = trusted
            vncdevice.forget_pace(trusted.url)  # (a console behind a door that met the other certificate is asked for again at once)
            await manager.replace(trusted)
            vncdevice.forget_pace(trusted.url)  # (and what the client before it wrote while it was retired)
            try:
                await save()
            except OSError as ex:
                store.devices[at] = record
                await manager.replace(record)
                return not_saved("Trusting this certificate", ex)
        audit.write("certificate_trusted", client_ip(request), device=trusted.name, device_id=trusted.id, fingerprint=fingerprint(pem))
        return JSONResponse({"device": view(trusted)})

    # --- device actions ---------------------------------------------------------

    @app.get("/api/v1/devices/{device_id}/wol")
    async def wol_targets(device_id: str, request: Request) -> Response:
        device = manager.devices.get(device_id)
        if device is None or not allowed(request, device_id):
            return fail(404, "not_found", "Unknown device")
        try:
            targets = await device.wol_targets()
        except KvmError as ex:
            return fail(ex.status, ex.code, ex.message)
        return still_shown(request, device_id) or JSONResponse({"targets": targets})

    def waited_for(request: Request, device_id: str, device: Device, custom: tuple[ActionRecord, int, str] | None = None) -> JSONResponse | None:
        """Asked again of an action that waited (seconds, for a last holder's letting go: Lines.handed_over) before it goes:
        whoever asked may no longer, and the tile may have been changed or taken off meanwhile. Nothing was sent, and the
        refusal says so; sent on, it went to a connection taken away and was answered "it may have been done". `custom`:
        the saved action it runs, its `changed` and its name as they were when it was looked up, before the wait."""
        if (refusal := still_allowed(request)) is not None:
            return refusal
        if not allowed(request, device_id):
            return fail(404, "not_found", "Unknown device")
        if manager.devices.get(device_id) is not device:
            return fail(409, "conflict", f"{device.spec.name} was changed or taken off the wall while this waited. Nothing was sent: look at it again.")
        if custom is not None and (not any(action is custom[0] for action in store.actions) or custom[0].changed != custom[1]):
            # (Edited meanwhile, it may type where it pressed a key, and want a question it did not want; removed, it is no
            # action of anybody's. Run as it was clicked, it was neither.)
            return fail(409, "changed", f"\"{custom[2]}\" was changed or removed while this waited. Nothing was sent: look at it again.")
        return None

    def keyboard_held(name: str, by: str, request: Request) -> JSONResponse:
        """What is said while somebody has a machine's keyboard and mouse over a live line: who, as the live line's own
        refusal says it (`by`), to whoever may act on the machine, an operator as an admin. In the sentence, for the page;
        and to an admin in person, where they can take them over (an action does not take over by itself: live_may_take)."""
        message = f"{by} has {name}'s keyboard and mouse over a live line at this moment. Wait until they are given back."
        user: UserRecord = request.state.user
        if user.role == "admin" and not is_token(user):
            message += " As an admin you can take them over in its live view."
        return JSONResponse({"code": "busy", "message": message, "by": by}, status_code=409)

    @app.post("/api/v1/devices/{device_id}/actions")
    async def act(device_id: str, body: ActionIn, request: Request) -> Response:
        device = manager.devices.get(device_id)
        if device is None or not allowed(request, device_id):
            return fail(404, "not_found", "Unknown device")
        # What goes into the activity log: which action, never the text that was typed.
        detail: dict[str, Any] = {"device": device.spec.name, "device_id": device_id, "action": body.action}
        if body.batch:
            detail["batch"] = body.batch
        action: str = body.action
        keys, text, enter = body.keys, body.text, body.enter
        custom: tuple[ActionRecord, int, str] | None = None  # the saved action, as it was looked up (see waited_for)
        if action == "bios_setup" and body.batch:
            # One machine at a time: it opens the machine's large view to show the setup screen, and leaving several
            # halted in their firmware setup at once is rarely meant. Not offered in a bulk run (the page does not either).
            return fail(422, "invalid", "Start into BIOS setup is for one machine at a time: it opens its large view to show the setup screen.")
        if action == "custom":
            saved = next((a for a in store.actions if a.id == body.custom_id), None)
            if saved is None:
                return fail(404, "not_found", "That saved action no longer exists")
            if saved.kind == "text" and is_token(request.state.user):
                # Typed on a machine it can take pictures of, a saved passphrase is the token's to read.
                return fail(403, "not_allowed", "Saved text is for people to type. A token sends its own text.")
            if body.custom_changed is not None and body.custom_changed != saved.changed:
                # The button that was clicked showed what this action used to be. What it is now may type
                # where it used to press a key, and want a confirmation it did not want before.
                return fail(409, "changed", f"\"{saved.name}\" was changed since you opened this list. Look at it again before running it.")
            detail["name"] = saved.name
            custom = (saved, saved.changed, saved.name)
            action, keys, enter = saved.kind, saved.keys, saved.enter
            if saved.kind == "text":
                # Its text is opened whatever is saved for it, nothing included: an action that types has a
                # text, and one whose text is not there (never brought along by a file, or false, 0, an empty
                # list after a slip in the settings file) typed nothing and pressed Enter. Whatever stood at
                # that machine's prompt was sent off.
                opened_text = core.vault.read(saved.secret, f"action:{saved.id}")
                if not opened_text:  # (does not open; or opens to no text at all, which no form saves)
                    return fail(409, "no_text", f"The text saved for \"{saved.name}\" does not open any more. Edit the action and type it again.")
                text = opened_text
        if action == "text":
            if body.action != "custom":  # (how long a saved passphrase is, is nobody's to read in the log)
                detail["chars"] = len(text)
            text += "\n" if enter else ""
        elif action == "keys":
            detail["keys"] = keys
        elif action == "wol":
            detail["mac"] = body.mac
        elif action == "port":
            detail["port"] = body.port + 1  # as people count them
        elif action in FINGERBOT_PRESSES:
            detail["strength"] = device.spec.fingerbot_strength  # (how hard it was told to press: the machine's own setting)
        if device_id in acted_on:
            # The page holds a second action back while the first is out, but only the page it was sent from.
            # Another tab, somebody else, a run over many machines know nothing of it; and a power button
            # pressed twice is not pressed harder: the second press undoes the first.
            return fail(409, "busy", f"Something else is being done to {device.spec.name} at this moment. Wait for it to finish.")
        if (by := lines.held_by(device_id)) is not None:
            # One thing at a time per machine: somebody has its keyboard and mouse over a live line (live.py). Also for
            # whoever holds them: a text typed by this road beside keys sent by that one would be two hands on one keyboard.
            return keyboard_held(device.spec.name, by, request)
        acted_on.add(device_id)
        try:
            # Keyboard and mouse given back, or taken away, a moment ago: what the holder still had on its way, and the
            # letting go of what they had down, goes first. (Nobody takes them meanwhile: the machine is being acted on.)
            refusal = waited_for(request, device_id, device, custom) if await lines.handed_over(device_id) else None
        except BaseException:
            acted_on.discard(device_id)  # (cut off before anything was sent)
            raise
        if refusal is not None:
            acted_on.discard(device_id)
            return refusal
        note: str | None = None  # where what happened is not simply "done": "already on"
        def still_theirs() -> bool:
            """Whether whoever asked for this may still have it done (asked by what takes long: typing key by key)."""
            return still_allowed(request) is None and allowed(request, device_id)

        pressed_at = time.time()  # (what the history keeps of a power button: when it was pressed)
        answered, sent = PRESS_ANSWERED.set(False), PRESS_SENT.set(None)
        if body.watching and not body.batch:
            # The sender has its large or live view open (see Device.watched). Never an entry of a bulk run: that comes from
            # the selection, and forty PCs switched on together are not forty sessions opened first.
            device.watched()
        try:
            await device.act(action, mac=body.mac, keys=keys, text=text, port=body.port, still=still_theirs)
        except AlreadySo as so:
            note = detail["note"] = str(so)
            history_pressed(device_id, action, True, note, pressed_at)
        except KvmError as ex:
            if ex is RETIRED:
                # The connection it went out on was taken away meanwhile: the device was edited, or the last
                # person signed out. It may have arrived all the same. That is no refusal, and is not answered
                # as one: "Retry failed" would press a power button a second time.
                unknown = f"{device.spec.name} was being changed while this was under way. It may have been done all the same: look at the machine before trying again."
                audit.write("action_failed", client_ip(request), error=unknown, **detail)
                history_pressed(device_id, action, None, "retired", pressed_at)  # (it may have been done: nobody knows)
                return fail(504, "timeout", unknown)
            audit.write("action_failed", client_ip(request), error=ex.message, **detail)
            # (No answer in time, or one that broke off on its way: it may have been done, as the page says, and the history
            # keeps that nobody knows.)
            history_pressed(device_id, action, None if ex.code in ("timeout", "dropped") else False, ex.code, pressed_at)
            return fail(ex.status, ex.code, ex.message)
        except asyncio.CancelledError:
            # qKVM is being stopped, or its listeners reopened, and this request is cut off. What was sent may
            # have been carried out: whoever reads the log is to find that it was sent.
            if PRESS_ANSWERED.get():
                # (The KVM had answered the click, and the button was being held, or its change waited for: it was pressed.)
                audit.write("action", client_ip(request), note="qKVM was stopped after the KVM had taken the press: it was pressed", **detail)
                history_pressed(device_id, action, True, "stopped", pressed_at)
            elif PRESS_SENT.get() is False:
                # (The driver says the press had not gone out: the KVM was only being asked, whether a Fingerbot is paired, say.)
                audit.write("action_failed", client_ip(request), error="qKVM was stopped before the press went out: nothing was pressed", **detail)
                history_pressed(device_id, action, False, "stopped", pressed_at)
            else:
                audit.write("action_failed", client_ip(request), error="qKVM was stopped or restarted before the machine answered: it may have been done", **detail)
                history_pressed(device_id, action, None, "stopped", pressed_at)
            raise
        else:
            history_pressed(device_id, action, True, at=pressed_at)
        finally:
            PRESS_ANSWERED.reset(answered)
            PRESS_SENT.reset(sent)
            acted_on.discard(device_id)
        audit.write("action", client_ip(request), **detail)
        return JSONResponse({"ok": True, "note": note})

    # (Each its own: consoles not had, asked for in a loop, leave the openings' allowance as it was.)
    console_said = {event: activity.Allowance(lambda: activity.CONSOLE_SAID_AN_HOUR) for event in ("console_opened", "console_failed")}

    def console_written(event: str, request: Request, device: str, device_id: str, **detail: Any) -> None:
        """A server's console opened or not had, into the activity log: within the account's allowance (activity.Allowance)."""
        # (Each server opened is named once an hour whatever is left; a console not had gives nobody a way in, and is not.)
        unsaid = console_said[event].take(request.state.user.id, device_id if event == "console_opened" else None)
        if unsaid is not None:
            audit.write(event, client_ip(request), device=device, device_id=device_id, **detail, **({"unsaid": unsaid} if unsaid else {}))

    @app.post("/api/v1/devices/{device_id}/console")
    async def open_console(device_id: str, request: Request) -> Response:
        """Where to send a browser so that it lands in a server's own console, signed in.

        Only for a device whose controller hands out a pass for that, good for one use. Whoever gets
        it uses the console as the account the wall signs in with, so it is for those who may act on
        the machine, it is written down that they asked, and the pass itself is written down nowhere.
        """
        device, record = manager.devices.get(device_id), store.device(device_id)
        if device is None or record is None or not allowed(request, device_id):
            return fail(404, "not_found", "Unknown device")
        if is_token(request.state.user):
            return fail(403, "not_allowed", "A way into a console is for a person's browser, not for a token")
        try:
            way_in = await device.console()
        except KvmError as ex:
            # Asked of a server that has a console, and not had: in the log as well (somebody at a server's console, trying
            # again and again, is worth knowing of). Not of a machine that has none to give (`no_console`): nothing was tried.
            if ex.code != "no_console":
                console_written("console_failed", request, device=record.name, device_id=device_id, error=ex.message)
            return fail(ex.status, ex.code, ex.message)
        # The controller took its time making the pass out. Whoever asked may have lost the right to it meanwhile.
        if refused := still_allowed(request):
            return refused
        now = store.device(device_id)
        # (Changed meanwhile where it matters here: its address, or the one a browser reaches it by. Not where the record was
        # replaced for a number its machine gave, which the asking itself may have taken: see DeviceManager._known.)
        if not allowed(request, device_id) or now is None or (now.url, now.open_url) != (record.url, record.open_url):
            return fail(404, "not_found", "Unknown device")
        # At the address a browser reaches the device by, which is not always the one this program uses.
        where = urlsplit(record.open_url or record.url)
        console_written("console_opened", request, device=record.name, device_id=device_id)
        return JSONResponse({"url": f"{where.scheme}://{where.netloc}{way_in}"})

    @app.post("/api/v1/devices/{device_id}/kvm")
    async def switch_kvm(device_id: str, body: KvmSwitchIn, request: Request) -> Response:
        """Switch a PC's Intel AMT KVM on, or off, on its management engine: a setting of the PC, which only an admin
        changes, only by asking for it here (a look never does), and which is written down."""
        device, record = manager.devices.get(device_id), store.device(device_id)
        if device is None or record is None or not allowed(request, device_id):
            return fail(404, "not_found", "Unknown device")
        if not isinstance(device, amt.AmtDevice):
            return fail(422, "invalid", "Only a PC with Intel AMT has a KVM to switch on from here")
        if device_id in acted_on:
            return fail(409, "busy", f"Something else is being done to {record.name} at this moment. Wait for it to finish.")
        if (by := lines.held_by(device_id)) is not None:
            return keyboard_held(record.name, by, request)
        acted_on.add(device_id)
        try:
            # (As for an action: the last holder's letting go goes first.)
            refusal = waited_for(request, device_id, device) if await lines.handed_over(device_id) else None
        except BaseException:
            acted_on.discard(device_id)
            raise
        if refusal is not None:
            acted_on.discard(device_id)
            return refusal
        try:
            await device.switch_kvm(body.on)
        except KvmError as ex:
            if ex is RETIRED:
                # (As for an action: the connection it went out on was taken away meanwhile, and it may have been done.)
                unknown = f"{record.name} was being changed while this was under way. It may have been done all the same: look at the machine before trying again."
                audit.write("kvm_switch_failed", client_ip(request), device=record.name, device_id=device_id, on=body.on, error=unknown)
                return fail(504, "timeout", unknown)
            audit.write("kvm_switch_failed", client_ip(request), device=record.name, device_id=device_id, on=body.on, error=ex.message)
            return fail(ex.status, ex.code, ex.message)
        except asyncio.CancelledError:
            audit.write("kvm_switch_failed", client_ip(request), device=record.name, device_id=device_id, on=body.on, error="qKVM was stopped or restarted before the machine answered: it may have been done")
            raise
        finally:
            acted_on.discard(device_id)
        audit.write("kvm_switched", client_ip(request), device=record.name, device_id=device_id, on=body.on)
        return JSONResponse({"ok": True})

    # --- the live line: one WebSocket per viewer, the picture down, keys and the mouse up (live.py) ---------------
    # The two calls of desktop/SPEC.md section 6.2: a pass, then the line that shows it. Everything behind them is in
    # live.py; what is here is who may ask, and what the guard above does for a request over HTTP and not for a WebSocket.

    def may_see(user: UserRecord, device_id: str) -> bool:
        """May this account see this KVM? (`allowed`, for an account that is not the one making the request in hand.)"""
        if user.devices is None or device_id in user.devices:
            return True
        record = store.device(device_id) if user.groups else None
        return record is not None and record.group.casefold() in {group.casefold() for group in user.groups}

    def live_standing(holder: live.Holder, device_id: str) -> tuple[str | None, bool]:
        """Whether whoever was given this pass may still be on a line to this machine, and whether they may act: (why not, may act).

        Asked when the line is let in and every few seconds after it. The line carries no cookie, so the account the
        pass was given to is looked at anew here: a browser's sign-in that ended (signed out, or signed out everywhere
        by an admin) ends the line; so does an account removed, suspended or limited to other machines, a token taken
        back or run out, and a wall that locked itself. An account given a lesser role keeps looking and loses the keys.
        """
        user: UserRecord | None
        if holder.token is not None:
            sent = next((t for t in store.tokens if t.id == holder.token and t.kind == "api"), None)
            if sent is None or (sent.expires is not None and sent.expires <= time.time()):
                return "signed_out", False
            user = token_user(sent)
        else:
            session = core.sessions.get(holder.session)
            if session is None:
                return "signed_out", False
            if holder.user_id.startswith("token:"):  # a screen on the wall, opened with its display link
                shown = next((t for t in store.tokens if t.id == holder.user_id[6:] and t.kind == "display"), None)
                if shown is None or (shown.expires is not None and shown.expires <= time.time()):
                    return "signed_out", False
                user = token_user(shown)
            else:
                user = store.user(holder.user_id)
                if user is None or user.suspended:
                    return "signed_out", False
                if must_enroll(user) and not session.sso:
                    return "not_allowed", False
        if not core.vault.unlocked or device_id not in manager.devices or not may_see(user, device_id):
            return "not_found", False
        return None, RANK[user.role] >= RANK["operator"]

    def live_may_take(holder: live.Holder, device_id: str) -> bool:
        """Whether whoever was given this pass may take this machine's keyboard and mouse from whoever holds them over a live
        line: an admin, in person, as the account is at this moment (asked when they ask, not when the pass was given).

        Never a token, of any role (a token is never an admin, and one written as one in the settings file is not taken for
        one here), and never a wall screen, which only looks. An admin's action without the live view does not take over
        (it is refused 409 with the holder's name, `keyboard_held`): taking a person's keyboard away is done where it can be
        seen, after a question that names them."""
        if holder.token is not None or holder.user_id.startswith("token:"):
            return False
        why, may_act = live_standing(holder, device_id)
        user = store.user(holder.user_id)
        return why is None and may_act and user is not None and user.role == "admin"

    lines = live.Lines(manager, standing=live_standing, busy=lambda device_id: device_id in acted_on, audit=audit.write, may_take=live_may_take)
    manager.retiring = lines.retiring  # (keys a line has down on a device are let go of before its connection is closed)

    @app.post("/api/v1/devices/{device_id}/live")
    async def live_pass(device_id: str, request: Request) -> Response:
        """A pass for one live line to this machine: good for half a minute, and for one use (live.py)."""
        if not core.vault.unlocked:
            return fail(503, "locked", "qKVM was restarted and nobody has signed in since, so it cannot reach its devices.")
        device = manager.devices.get(device_id)
        if device is None or not allowed(request, device_id):
            return fail(404, "not_found", "Unknown device")
        if not lines.offers(device):
            return fail(404, "no_live", "This machine has no live picture")
        user: UserRecord = request.state.user
        _, sent = asking(request)
        holder = live.Holder(
            user_id=user.id,
            name=user.name,
            may_control=RANK[user.role] >= RANK["operator"],
            ip=client_ip(request),
            session=None if sent is not None else request.cookies.get(COOKIE),
            token=None if sent is None else sent.id,
        )
        try:
            ticket = lines.issue(device_id, holder)
        except KvmError as ex:  # (as many live pictures as one account may have: busy, and a pass runs out within half a minute)
            return fail(ex.status, ex.code, ex.message, **{"Retry-After": str(round(live.PASS_LASTS))})
        return JSONResponse({"v": live.FORM, "ticket": ticket})

    def same_host(origin: str, host: str) -> bool:
        """Whether a page at `origin` is this wall's own page: a WebSocket cannot carry the header the guard asks for, and a browser sends where a page is from."""
        try:
            return urlsplit(origin).netloc == host
        except ValueError:
            return False

    @app.websocket("/api/v1/devices/{device_id}/live")
    async def live_line(ws: WebSocket, device_id: str) -> None:
        """The line itself. It carries no cookie: the pass in its first message says whom it is for (live.py).

        The guard above runs for a request over HTTP and not for this. What it asks of everybody before anything
        else, whether the address and the host are ones this wall answers at all, is asked here. A page of another
        site cannot open a line that is let in: a pass is had only through the guarded call above.
        """
        host, origin = ws.headers.get("host", ""), ws.headers.get("origin")
        if not client_allowed(ws) or not host_allowed(host, store.server.allowed_hosts) or (origin is not None and not same_host(origin, host)):
            # Closed before it is let in, which the web server answers with a bare 403. (Refused with an answer of
            # our own, it wrote an error into the log for every one: anybody who can reach the port could fill it.)
            await ws.close(code=1008)
            return
        await lines.serve(ws, device_id, client_ip(ws))

    # --- saved actions ----------------------------------------------------------

    def check_action(body: CustomActionIn, existing: ActionRecord | None) -> JSONResponse | None:
        if body.kind == "keys" and not KEYS.fullmatch(body.keys):
            return fail(422, "invalid", "Choose at least one key")
        keeps_text = existing is not None and existing.kind == "text" and existing.secret is not None
        if body.kind == "text" and not body.text and not keeps_text:
            return fail(422, "invalid", "Enter the text to type")
        return None

    def fill_action(record: ActionRecord, body: CustomActionIn) -> None:
        was_text = record.kind == "text"
        record.name, record.kind, record.danger = body.name.strip(), body.kind, body.danger
        record.keys = body.keys if body.kind == "keys" else ""
        record.enter = body.enter and body.kind == "text"
        if body.kind != "text":
            record.secret = None
        elif body.text or not was_text:
            record.secret = core.vault.encrypt(body.text, f"action:{record.id}")

    def saved_action(action_id: str) -> ActionRecord | None:
        return next((a for a in store.actions if a.id == action_id), None)

    @app.get("/api/v1/actions")
    async def list_actions() -> dict[str, Any]:
        return {"actions": [action_view(a) for a in store.actions]}

    @app.post("/api/v1/actions")
    async def create_action(body: CustomActionIn, request: Request) -> Response:
        if problem := check_action(body, None):
            return problem
        record = ActionRecord(id=secrets.token_hex(4), name="", kind=body.kind)
        fill_action(record, body)
        store.actions.append(record)
        if refused := await saved("The new action", lambda: store.actions.remove(record)):
            return refused
        audit.write("saved_action_added", client_ip(request), name=record.name)
        return JSONResponse({"action": action_view(record)}, status_code=201)

    @app.put("/api/v1/actions/{action_id}")
    async def update_action(action_id: str, body: CustomActionIn, request: Request) -> Response:
        record = saved_action(action_id)
        if record is None:
            return fail(404, "not_found", "Unknown action")
        if problem := check_action(body, record):
            return problem
        before = dataclasses.asdict(record)

        def as_it_was() -> None:
            # Somebody may have been shown the edit that is now taken back, under its number. Their button
            # must run neither what the action is again (they saw something else), nor what it becomes at
            # the next edit.
            for name, value in before.items():
                setattr(record, name, value)
            # ...and what it is again stands under a number nobody was shown: not the one it had (the edit
            # that is taken back was shown under the next), and not that next one either.
            record.changed = before["changed"] + 2

        fill_action(record, body)
        record.changed += 1
        if refused := await saved("The change to this action", as_it_was):
            return refused
        audit.write("saved_action_changed", client_ip(request), name=record.name)
        return JSONResponse({"action": action_view(record)})

    @app.delete("/api/v1/actions/{action_id}")
    async def delete_action(action_id: str, request: Request) -> Response:
        record = saved_action(action_id)
        if record is None:
            return fail(404, "not_found", "Unknown action")
        at = store.actions.index(record)
        store.actions.remove(record)
        if refused := await saved("Removing this action", lambda: store.actions.insert(at, record)):
            return refused
        audit.write("saved_action_removed", client_ip(request), name=record.name)
        return JSONResponse({"ok": True})

    # --- settings ---------------------------------------------------------------

    @app.get("/api/v1/settings")
    async def get_settings() -> dict[str, Any]:
        tailscale, lan = await asyncio.gather(asyncio.to_thread(tailscale_ip), asyncio.to_thread(lan_ip))
        server = store.server
        return {
            "bind": server.bind,
            "port": server.port,
            "https": core.https,
            "https_forced": core.https_forced,  # said at start: the box in the settings cannot switch it off
            "interval": server.interval,
            "addresses": {"tailscale": tailscale, "lan": lan},
            "listening": core.listening,
            "missing": core.missing,
            "bind_error": core.bind_error,
            "cert_fingerprint": core.cert_fingerprint if core.https else None,
            "overridden": core.bind_override is not None or core.port_override is not None,
            "version": __version__,
            "uptime": round(time.time() - core.started),
        }

    @app.put("/api/v1/settings")
    async def put_settings(body: SettingsIn, request: Request) -> Response:
        try:
            bind = normalize(body.bind)
        except BindError as ex:
            return fail(422, "invalid", str(ex))
        server = store.server
        was = core.https
        before = (server.bind, server.port, server.https, server.interval)
        restart = (bind, body.port) != (server.bind, server.port)
        server.bind, server.port, server.https, server.interval = bind, body.port, body.https, body.interval
        restart = restart or core.https != was  # (said at start, HTTPS stays on whatever the box says)

        shown = core.cert_fingerprint

        def as_it_was() -> None:
            server.bind, server.port, server.https, server.interval = before
            core.cert_fingerprint = shown  # (what is served is the certificate of before: that is the one to show)

        addresses, _ = await asyncio.to_thread(resolve, core.bind)
        if core.https:
            # Made before anything is saved: HTTPS that is switched on and has no certificate is a qKVM that
            # does not start again. And made now so the page can show the fingerprint before the browser's
            # warning appears.
            try:
                await asyncio.to_thread(core.prepare_tls, addresses)
            except Exception as ex:  # the disk takes none; what it would have to name cannot be named; or whatever else
                as_it_was()
                log.error("the certificate for HTTPS could not be made or read: %s", ex)
                why = ex.strerror if isinstance(ex, OSError) and ex.strerror else ex
                return fail(507, "no_certificate", f"The certificate for HTTPS could not be made ({why}), so nothing was changed.")
            # It was made anew (another address to be good for, or its time nearly up): served from now on,
            # and not only shown. Shown and not served, whoever compares the two sees an attack that is none.
            restart = restart or (was and core.cert_fingerprint != shown)
        # (Where qKVM listens, of all things, must not be changed by whatever is saved next, after this was refused.)
        if refused := await saved("These settings", as_it_was):
            return refused
        core.bind_error = None
        audit.write("settings_changed", client_ip(request), bind=bind, port=body.port, https=core.https)
        if restart:
            # Let this response reach the browser before the listeners are replaced.
            asyncio.get_running_loop().call_later(0.5, core.request_restart)
        # Worked out in a worker thread: finding the Tailscale address means running a program.
        urls = await asyncio.to_thread(core.urls, addresses, core.port, core.https)
        return JSONResponse(
            {"restart": restart, "urls": urls, "cert_fingerprint": core.cert_fingerprint if core.https else None}
        )

    # --- the wall as a file: to keep, or to take to another wall ------------------

    files_in_hand = 0
    one_file = asyncio.Lock()

    async def slowly(work: Callable[..., Any], *given: Any) -> Any:
        """Run what puts a passphrase through its paces: off the event loop, one at a time, and in nobody's way who signs in.

        (In a queue of its own: counted with the password checks, a few files being read at once had
        whoever tried to sign in meanwhile told that too much was going on.)
        """
        nonlocal files_in_hand
        if files_in_hand >= 3:
            raise KvmError("busy", "Another file is being worked on just now. Try again in a moment.", 429)
        files_in_hand += 1
        try:
            async with one_file:
                return await asyncio.to_thread(work, *given)
        finally:
            files_in_hand -= 1

    def not_for_a_token(request: Request) -> JSONResponse | None:
        if is_token(request.state.user):
            return fail(403, "not_allowed", "A file of the wall is for a person to ask for, not for a token")
        return None

    @app.post("/api/v1/export")
    async def export_wall(body: ExportIn, request: Request) -> Response:
        """The wall's devices and settings as a file (see exchange.py for what is in one, and what never is).

        With a passphrase the file holds every device's password, and is encrypted with it. That is all of
        the wall's secrets leaving it in one answer: an admin's own to ask for, with the password typed
        again, and written down as done.
        """
        if refused := not_for_a_token(request):
            return refused
        if body.passphrase and len(body.passphrase) < exchange.MIN_PASSPHRASE:
            return fail(422, "invalid", f"The passphrase needs {exchange.MIN_PASSPHRASE} characters or more. Leave it empty for a file without passwords.")
        if refused := await own_password(request, body.password):
            if refused.status_code == 401 and b'"bad_password"' in bytes(refused.body):  # (somebody at an admin's open browser, trying passwords for the wall's secrets)
                audit.write("export_refused", client_ip(request))
            return refused
        sealed = bool(body.passphrase)
        not_opened: list[str] = []
        try:
            parts = exchange.gather(store, core.vault, set(body.parts), secrets=sealed, not_opened=not_opened)
            text = await slowly(exchange.pack, parts, body.passphrase, __version__) if sealed else exchange.pack(parts, "", __version__)
        except VaultLocked:
            return fail(503, "locked", "The saved passwords are locked just now. Sign in again and try once more.")
        except exchange.ExchangeError as ex:  # (more in the wall than a file holds)
            return fail(422, ex.code, ex.message)
        except KvmError as ex:
            return fail(ex.status, ex.code, ex.message)
        except (MemoryError, NoMemory) as ex:
            refused_now = no_memory(ex)
            return fail(refused_now.status, refused_now.code, refused_now.message)
        # (The check and the sealing took their time: asked once more whether whoever wanted it may still have it.)
        if refused := still_allowed(request):
            return refused
        if not_opened:
            # A file kept for the passwords in it, and without some of them: said to whoever made it (the
            # page reads the number), in the activity log, and by name in the log.
            log.warning("an export left out what is saved for these and does not open any more (%d): %s", len(not_opened), "; ".join(plain(whose, 60) or "?" for whose in not_opened[:20]))
        audit.write(
            "export_made", client_ip(request), parts=sorted(set(body.parts)), encrypted=sealed, devices=len(parts.get("devices", [])),
            **({"not_opened": len(not_opened)} if not_opened else {}),
        )  # fmt: skip
        name = f"qkvm-{time.strftime('%Y-%m-%d')}.{'qkvm' if sealed else 'json'}"
        said = {"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store", "X-QKVM-Not-Opened": str(len(not_opened))}
        return Response(text, media_type="application/json", headers=said)

    async def opened_file(body: ImportIn) -> exchange.Content | JSONResponse:
        try:
            if exchange.is_sealed(body.file):
                return await slowly(exchange.unpack, body.file, body.passphrase)  # type: ignore[no-any-return]
            return exchange.unpack(body.file, "")
        except exchange.ExchangeError as ex:
            return fail(422, ex.code, ex.message)
        except KvmError as ex:
            return fail(ex.status, ex.code, ex.message)
        except (MemoryError, NoMemory) as ex:
            refused_now = no_memory(ex)
            return fail(refused_now.status, refused_now.code, refused_now.message)

    def called(name: str) -> str:
        """A name as it is compared: without what is not drawn.

        Capitals, blanks, the wide and narrow forms of a letter, and what cannot be seen at all (a mark that
        only says which drawing of the letter before it is meant, a letter that is a blank, a sign that
        only steers how text is set) make no other name of it. Everything that is drawn does: the marks
        that are the vowels of Thai, Hindi, Arabic or Hebrew are letters to whoever reads them, and with
        all marks thrown out two words were one name, and the second of them was "on the wall already".
        (A letter of another alphabet that looks like this one is another name, too. That cannot be told here.)
        """
        seen = unicodedata.normalize("NFKC", name)
        seen = "".join(ch for ch in seen if unicodedata.category(ch) != "Cf" and ord(ch) not in NOT_DRAWN)
        return " ".join(seen.split()).casefold()

    def new_to_this_wall(content: exchange.Content) -> tuple[list[exchange.Device], list[exchange.Action], dict[str, str]]:
        """What of the file's devices and saved actions this wall does not have, and (address -> name) of
        which tile each device that is left out for being here under another address is the same as.

        A device is here that is at that address, or that is the same device at another one (by what it
        says it is, or by its certificate: what the form asks "keep both?" about). The form asks; a file
        cannot answer, except where the wall it comes from was told "keep both" for that very device. A
        saved action is here by its name, whatever it does: one that types something under the name of
        one that presses keys is not "another action" to whoever sees the name on a button.
        """

        def marks(record: DeviceRecord) -> set[str]:
            """Every mark a device is known by: what it says it is, and its certificate's. (`identity` gives the first there is.)"""
            return {mark for mark in (identity(record), identity(dataclasses.replace(record, ident=""))) if mark is not None}

        here = {device.url: device.name for device in store.devices}
        jetkvms = {device.url for device in store.devices if device.kind == "jetkvm"}
        known = {mark: device.name for device in store.devices if not device.ident.startswith("own:") for mark in marks(device)}
        devices, twins = [], {}
        for device in content.devices or []:
            if device.url in here:
                continue
            # A JetKVM that was on plain HTTP and is talked to over HTTPS by now (the wall follows it there by
            # itself) is here, under its other address: taken in again the plain way, it was a second tile
            # that signed in in the clear. Where what is at the other address is a JetKVM, that is: another
            # kind of device there is another device (a gateway whose two ports lead to two machines).
            other = other_way(device.url) if device.kind == "jetkvm" else None
            if other is not None and other in jetkvms:
                twins[device.url] = here[other]
                continue
            as_saved = DeviceRecord(id="", name=device.name, url=device.url, tls=device.tls, cert_pem=device.cert_pem, kind=device.kind, ident=device.ident)
            mine = set() if device.keep_both else marks(as_saved)
            same = next((known[mark] for mark in mine if mark in known), None)
            if same is not None:
                twins[device.url] = same
                continue
            known.update(dict.fromkeys(mine, device.name))
            here[device.url] = device.name
            if device.kind == "jetkvm":
                jetkvms.add(device.url)
            devices.append(device)
        have = {called(action.name) for action in store.actions}
        actions = []
        for action in content.actions or []:
            if called(action.name) not in have:
                have.add(called(action.name))
                actions.append(action)
        return devices, actions, twins

    @app.post("/api/v1/import/read")
    async def read_file(body: ImportIn, request: Request) -> Response:
        """What a file holds, and what of it would be new here. Changes nothing."""
        if refused := not_for_a_token(request):
            return refused
        content = await opened_file(body)
        if isinstance(content, JSONResponse):
            return content
        # (Opening it took its time. What it says of this wall, which of its addresses are here, is for whoever may still ask.)
        if refused := still_allowed(request):
            return refused
        devices, actions, twins = new_to_this_wall(content)
        new = {device.url for device in devices}
        told = content.alerts
        return JSONResponse(
            {
                "encrypted": content.sealed,
                "secrets": content.secrets,  # (a plain file with passwords in it was written by hand: said, so that it is known)
                "made": content.made,
                "program": content.program,
                # Everything that decides what a tile will do is said before it is taken: where it is, how its
                # certificate is checked, and where "Open console" would send a browser.
                "devices": None
                if content.devices is None
                else [
                    {
                        "name": device.name, "host": urlsplit(device.url).netloc, "kind": device.kind, "group": device.group, "password": bool(device.password),
                        # (A console over vncs:// has its certificate checked as one over https:// does, and is said so.)
                        "tls": device.tls if device.url.startswith(("https://", "vncs://")) else "", "open_url": device.open_url, "new": device.url in new, "same_as": twins.get(device.url, ""),
                    }
                    for device in content.devices
                ],
                # A saved text is shown to nobody once it is on the wall. Whoever holds the file and its
                # passphrase has it already, and is shown it here: what a button will type is not taken unread.
                "actions": None
                if content.actions is None
                else [
                    {"name": action.name, "kind": action.kind, "keys": action.keys, "text": action.text if action in actions else "", "enter": action.enter, "danger": action.danger, "new": action in actions}
                    for action in content.actions
                ],
                "alerts": None
                if told is None
                else {
                    "enabled": told["enabled"], "address": bool(told["webhook"]), "host": urlsplit(told["webhook"]).hostname or "", "format": told["format"],
                    "kinds": [kind for kind in ("offline", "no_signal", "problem", "recovered") if told[kind]],
                },
                "wall": content.wall,
                "left_out": content.left_out[:200],
            }
        )

    @app.post("/api/v1/import")
    async def import_file(body: ImportIn, request: Request) -> Response:
        """Take in what a file holds, as far as `take` names it.

        Devices and saved actions are added where this wall has none at that address, or of that name:
        nothing that is here is changed or removed by a file. The alert settings and the wall's settings,
        of which there is one set, are replaced where they are taken. No device is talked to for this: a
        tile that was taken in says for itself, on the wall, whether its device answers.
        """
        if refused := not_for_a_token(request):
            return refused
        content = await opened_file(body)
        if isinstance(content, JSONResponse):
            return content
        take = set(body.take)
        async with one_change:
            # Reading the file took its time. What was checked when the request came in is checked again.
            if refused := still_allowed(request):
                return refused
            devices, actions, _ = new_to_this_wall(content)
            devices = devices if "devices" in take else []
            actions = actions if "actions" in take else []
            told = content.alerts if "alerts" in take else None
            wall = content.wall if "wall" in take else None
            used = {device.id for device in store.devices} | {action.id for action in store.actions}

            def new_id() -> str:
                while (made := secrets.token_hex(4)) in used:
                    pass
                used.add(made)
                return made

            try:
                added: list[DeviceRecord] = []
                for device in devices:
                    record = DeviceRecord(
                        id=new_id(), name=device.name, url=device.url, username=device.username, open_url=device.open_url, tls=device.tls,
                        cert_pem=device.cert_pem, kind=device.kind, group=device.group, ident=device.ident, alerts=device.alerts,
                        fingerbot_strength=device.fingerbot_strength,
                    )  # fmt: skip
                    # The machine it was added for, which its driver checks before anything is sent to it (DeviceSpec.machine). Where
                    # the file has none, the first look takes it.
                    record.machine = device.machine
                    if device.keep_both:
                        record.ident = f"own:{record.id}"  # as the form marks a tile that is to stay beside its twin
                    record.secret = core.vault.encrypt(device.password, record.id) if device.password else None
                    added.append(record)
                saved_actions: list[ActionRecord] = []
                for action in actions:
                    made = ActionRecord(id=new_id(), name=action.name, kind=action.kind, keys=action.keys, enter=action.enter, danger=action.danger)
                    made.secret = core.vault.encrypt(action.text, f"action:{made.id}") if action.kind == "text" else None
                    saved_actions.append(made)
                address = core.vault.encrypt(told["webhook"], "alerts:webhook") if told is not None and told["webhook"] else None
                # Made before anything is touched: whatever goes wrong in the making leaves the wall as it was.
                clients = [manager.client(record) for record in added]
            except VaultLocked:
                return fail(503, "locked", "The saved passwords are locked just now. Sign in again and try once more.")
            before = (dataclasses.asdict(store.alerts), store.server.interval, store.server.update_check)

            async def as_it_was() -> None:
                for record in added:
                    if record in store.devices:
                        store.devices.remove(record)
                    await manager.remove(record.id)
                kept.forget(*(record.id for record in added))  # (looked at while the settings were being written: what the history noted goes too)
                for made in saved_actions:
                    if made in store.actions:
                        store.actions.remove(made)
                for name, value in before[0].items():
                    setattr(store.alerts, name, value)
                store.server.interval, store.server.update_check = before[1], before[2]

            try:
                store.devices.extend(added)
                store.actions.extend(saved_actions)
                if told is not None:
                    # What is set about alerts, and where they go. Not the link they carry, which is this
                    # wall's own address, nor a pause, which is a thing of the moment here.
                    settings = store.alerts
                    settings.enabled, settings.format = told["enabled"], told["format"]
                    settings.offline, settings.no_signal, settings.problem, settings.recovered = told["offline"], told["no_signal"], told["problem"], told["recovered"]
                    if address is not None:  # a file without one (a plain file) leaves the address this wall has
                        settings.webhook = address
                if wall is not None:
                    store.server.interval = wall.get("interval", store.server.interval)
                    store.server.update_check = wall.get("update_check", store.server.update_check)
                for client in clients:
                    await manager.adopt(client)
                await save()
            except OSError as ex:
                await as_it_was()
                return not_saved("What the file holds", ex)
            except BaseException:
                await as_it_was()  # not half of a file: whatever it was that went wrong
                raise
            if told is not None:
                alert_log["error"], not_opening[0] = None, None  # (one that still does not open is said again, at the next look)
        # Each device by name and address, as one that was typed in is written down; a file of hundreds, by their number.
        for record in added[:MOST_NAMED]:
            audit.write("device_added", client_ip(request), device=record.name, device_id=record.id, url=record.url, note="from a file")
        audit.write(
            "import_done", client_ip(request), devices=len(added), actions=len(saved_actions), encrypted=content.sealed,
            parts=sorted(part for part, there in (("devices", added), ("actions", saved_actions), ("alerts", told is not None), ("wall", wall is not None)) if there),
        )  # fmt: skip
        return JSONResponse({"devices": len(added), "actions": len(saved_actions), "alerts": told is not None, "wall": wall is not None, "left_out": content.left_out[:200]})

    # --- updates ----------------------------------------------------------------

    def update_view() -> dict[str, Any]:
        return {
            **core.updater.view(),
            "auto_check": store.server.update_check,
            "supervised": core.supervised,
            "container": core.container,
        }

    @app.get("/api/v1/update")
    async def update_status() -> dict[str, Any]:
        return update_view()

    @app.put("/api/v1/update")
    async def update_settings(body: UpdateSettingsIn, request: Request) -> Response:
        before, store.server.update_check = store.server.update_check, body.auto_check
        if refused := await saved("This setting", lambda: setattr(store.server, "update_check", before)):
            return refused
        audit.write("settings_changed", client_ip(request), update_check=body.auto_check)
        return JSONResponse(update_view())

    @app.post("/api/v1/update/check")
    async def update_check() -> Response:
        try:
            await core.updater.check()
        except UpdateError as ex:
            return fail(502, "update_failed", str(ex))
        return JSONResponse(update_view())

    @app.post("/api/v1/update/install")
    async def update_install(body: UpdateInstallIn, request: Request) -> Response:
        ip = client_ip(request)
        if core.container:
            # An image is replaced as a whole; unpacking program files inside one would be undone by the next start.
            return fail(409, "container", "This copy runs from a container image: update by pulling the new image")
        if refused := await own_password(request, body.password):
            return refused
        try:
            version = await core.updater.install()
        except UpdateError as ex:
            audit.write("update_failed", ip, error=str(ex))
            return fail(502, "update_failed", str(ex))
        audit.write("update_installed", ip, version=version)
        if core.supervised:
            # Let this answer reach the browser, then leave; the starter runs the new version.
            asyncio.get_running_loop().call_later(1.0, core.restart_program)
        return JSONResponse({**update_view(), "restarting": core.supervised})

    # --- finding KVMs ---------------------------------------------------------------

    @app.post("/api/v1/discover")
    async def find_kvms() -> Response:
        """Look on this computer's own networks for KVMs that could be added."""
        if scanning.locked():
            return fail(409, "busy", "A search is already running")
        async with scanning:
            result = await discover.scan()
        on_wall = {urlsplit(d.url).hostname: d for d in store.devices}
        by_mark = {mark: d for d in store.devices if (mark := identity(d)) is not None}
        for entry in result["found"]:
            # On the wall already, under this address, under another of its addresses, or under one that
            # was not even found this time: it is the device that counts.
            addresses = [entry["address"], *(other["address"] for other in entry["also"])]
            urls = {entry["url"], *(other["url"] for other in entry["also"])}
            here = next((on_wall[address] for address in addresses if address in on_wall), None)
            same = by_mark.get(entry.pop("mark", None))
            # What it is counts for more than where it was found: an address may have gone to another device since.
            device = same or here
            entry["known"], entry["known_as"] = device is not None, device.name if device else None
            entry["known_id"] = device.id if device else None
            # On the wall under an address it was not found at, and not answering there: it has moved (a new
            # lease from the router, after a power cut most often), and its tile can be told where to.
            live = manager.devices.get(same.id) if same is not None and same.url not in urls else None
            gone = live is not None and (live._status or {}).get("state") == "offline"
            entry["moved_from"] = urlsplit(same.url).netloc if gone and same is not None else None
        # From inside a container the network that can be looked through is the container's: said, not left to be wondered at.
        return JSONResponse({**result, "container": core.container})

    @app.post("/api/v1/proxmox/guests")
    async def proxmox_guests(body: ProxmoxIn) -> Response:
        """The virtual machines an API token may see on a Proxmox, to pick from for adding; and, where the address
        named one by its number, that one's address as the wall keeps it (`named`, its node looked up)."""
        try:
            found = proxmox.address_of(body.url)
        except ValueError as ex:
            return fail(422, "invalid", str(ex).capitalize())
        try:
            listed, containers, _ = await proxmox.guests(found.origin, body.username.strip(), body.password, typed=True)
        except KvmError as ex:
            return fail(422, ex.code, ex.message)
        on_wall = {d.url: d for d in store.devices}
        for guest in listed:
            there = on_wall.get(guest["url"])
            guest["known_as"] = there.name if there is not None else None
        named = None
        if found.vmid is not None:
            named = next((guest["url"] for guest in listed if guest["vmid"] == found.vmid and found.node in (None, guest["node"])), None)
            if named is None:
                return fail(422, "invalid", f"The token sees no virtual machine {found.vmid} on this Proxmox")
        return JSONResponse({"guests": listed, "containers": containers, "named": named})

    # --- alerts -------------------------------------------------------------------

    def alerts_view() -> dict[str, Any]:
        settings = store.alerts
        return {
            "enabled": settings.enabled,
            # (One that is saved and does not open is none to send to. Whether it opens can only be said while
            # the saved passwords are open; until then it is shown as it is saved.)
            "has_webhook": settings.webhook is not None and (not core.vault.unlocked or webhook() is not None),
            "format": settings.format,
            "offline": settings.offline,
            "no_signal": settings.no_signal,
            "problem": settings.problem,
            "recovered": settings.recovered,
            "link": settings.link,
            "paused_until": settings.paused_until if pausing() else None,
            "last_sent": alert_log["sent"],
            "last_error": alert_log["error"],
        }

    @app.get("/api/v1/alerts")
    async def get_alerts() -> dict[str, Any]:
        return alerts_view()

    @app.put("/api/v1/alerts")
    async def put_alerts(body: AlertsIn, request: Request) -> Response:
        settings = store.alerts
        # Everything is looked at before anything is changed: a form that is refused for one of its fields
        # has changed none of them (an address in a refused form was put to use all the same).
        webhook, link = settings.webhook, settings.link
        if body.webhook.strip():
            try:
                webhook = core.vault.encrypt(alerts.check_url(body.webhook), "alerts:webhook")
            except ValueError as ex:
                return fail(422, "invalid", str(ex))
        elif body.forget_webhook:
            webhook = None
        if body.link is not None:
            try:
                link = alerts.wall_link(body.link) if body.link.strip() else ""
            except ValueError:
                return fail(422, "invalid", "The link in alerts has to be the address of this wall, starting with http:// or https://")
        before = dataclasses.asdict(settings)

        def as_it_was() -> None:
            for name, value in before.items():
                setattr(settings, name, value)

        settings.webhook, settings.link = webhook, link
        settings.enabled, settings.format = body.enabled, body.format
        settings.offline, settings.no_signal = body.offline, body.no_signal
        settings.problem, settings.recovered = body.problem, body.recovered
        # (An address that was to be forgotten and was not, for one: it would go on being sent to after a restart.)
        if refused := await saved("The alert settings", as_it_was):
            return refused
        alert_log["error"], not_opening[0] = None, None  # (one that still does not open is said again, at the next look)
        audit.write("settings_changed", client_ip(request), alerts=body.enabled)
        return JSONResponse(alerts_view())

    @app.post("/api/v1/alerts/pause")
    async def pause_alerts(body: PauseIn, request: Request) -> Response:
        """Send nothing for a while (maintenance); or, with no minutes, send again from now."""
        before = store.alerts.paused_until
        store.alerts.paused_until = time.time() + body.minutes * 60 if body.minutes else 0.0
        if refused := await saved("Pausing the alerts" if body.minutes else "Sending alerts again", lambda: setattr(store.alerts, "paused_until", before)):
            return refused
        if body.minutes:
            audit.write("alerts_paused", client_ip(request), minutes=body.minutes)
        else:
            audit.write("alerts_resumed", client_ip(request))
        return JSONResponse(alerts_view())

    @app.post("/api/v1/alerts/test")
    async def test_alert() -> Response:
        target = alert_address()
        if target is None:
            return fail(409, "no_webhook", "Save an address to send alerts to first")
        sample = alerts.Alert("test", "qKVM", "", "online", "online", "Test alert from qKVM", "If you can read this, alerts will reach you.")
        sample.link = store.alerts.link
        try:
            await outbox.send(*target, sample)  # at once and one attempt: whoever pressed the button is waiting
        except alerts.NotDelivered as ex:
            delivered(str(ex))
            return fail(502, "not_delivered", str(ex))
        delivered(None)
        return JSONResponse(alerts_view())

    def asked_of(
        q: list[str] | None, kind: str, before: float | None, since: float | None, until: float | None, user: str | None, device: str | None
    ) -> activity.Asked:
        """What a request asks of the activity log. A machine by its id; and where it is on the wall, by the name it has now as
        well, for what was written before entries gave the id (0.1.x), which named it only."""
        record = store.device(device) if device is not None else None
        return activity.Asked.of(q, kind, before, since, until, user, device, record.name if record is not None else None)

    @app.get("/api/v1/audit")
    async def audit_log(
        request: Request,
        limit: int = 100,
        q: Annotated[list[str] | None, Query()] = None,  # words to look for, in whatever case; several: any of them
        kind: Literal["", "signin", "action", "change", "alert"] = "",
        before: float | None = None,  # only what is older than this moment: the next page of a long log
        since: float | None = Query(None, ge=0, le=1e11),  # seconds since 1970: what was done from then on
        until: float | None = Query(None, ge=0, le=1e11),  # ...up to then
        user: str | None = Query(None, min_length=1, max_length=100),  # what one account (or token) did, by its name
        device: str | None = Query(None, min_length=1, max_length=64),  # what was done to one machine, by its id
    ) -> Response:
        limit = max(1, min(limit, 500))
        if since is not None and until is not None and since > until:
            return fail(422, "invalid", "since: has to be before until")
        asked = asked_of(q, kind, before, since, until, user, device)
        # Read in a worker thread, in its turn: the index where it holds what the text files hold, else the files.
        try:
            found = await activity_reads.run(request.state.user.id, lambda: indexed.read(asked, limit))
        except TurnRefused as turned:
            return turned.reply
        except activity.NotReadable as ex:
            return fail(503, "activity_unavailable", str(ex))
        # The read waited its turn, and for the index or the files: whoever asked may have lost the right to it meanwhile.
        if refused := still_allowed(request):
            return refused
        # (And whether this is all of it: entries that could not be written are counted, and that is said.)
        return JSONResponse({"entries": found.entries, "more": found.more, "missing": audit.missing})

    @app.get("/api/v1/audit/export")
    async def audit_export(
        request: Request,
        format: Literal["csv", "jsonl"] = "csv",
        q: Annotated[list[str] | None, Query()] = None,
        kind: Literal["", "signin", "action", "change", "alert"] = "",
        since: float | None = Query(None, ge=0, le=1e11),
        until: float | None = Query(None, ge=0, le=1e11),
        user: str | None = Query(None, min_length=1, max_length=100),
        device: str | None = Query(None, min_length=1, max_length=64),
    ) -> Response:
        """The activity log as a file: all of it, or what a search finds. A table (CSV), or the entries as they are (JSON lines).

        Made a page at a time, each page a read in its turn, into a file of its own (in memory up to SPOOL_IN_MEMORY, on the
        disk beyond that): a long log is never held in memory whole (it was, a list of every entry, and of the table made of
        it), nor the index by one download for longer than a page. Sent once it is whole, with its length: one that cannot be
        made whole is refused before anything is sent, and one cut off on its way falls short of its length, which whatever
        fetched it sees. (Sent as it was read, a download cut short ended as a whole one does, a file that looked complete with
        part of the log missing: the second reviewer of W4c. The web server's middleware ends a streamed answer whose source
        failed as if it were done.)
        """
        if since is not None and until is not None and since > until:
            return fail(422, "invalid", "since: has to be before until")
        asked = asked_of(q, kind, None, since, until, user, device)
        asker = request.state.user.id
        # Made or being sent at once: DOWNLOADS_AT_ONCE from everybody together, one of each account. Each holds a file as large
        # as what it holds until it is sent: stacked by one admin, they filled the disk (the third reviewer of W4c).
        give_back = downloads.take(asker)
        if give_back is None:
            return fail(503, "busy", "Downloads of the activity log are being made or sent just now (one of each account at a time). Try again in a moment.", **{"Retry-After": "2"})
        pager = indexed.pager(asked)
        # (Beyond what is held in memory, in the data folder, where the record is: the room kept for the record is asked of the
        # disk it is made on, and what the log holds is not left in the system's temporary folder, nor in memory where that is
        # a tmpfs, nor in a container's own layer where the data folder is a volume.)
        prefix, suffix = activity.DOWNLOAD_NAMED  # (by which a start finds one a power cut left: activity.leftover_downloads)
        spool = tempfile.SpooledTemporaryFile(max_size=SPOOL_IN_MEMORY, dir=str(core.data_dir), prefix=prefix, suffix=suffix)
        closing = threading.Lock()  # (taken by the first to let go of it: it is closed once)

        def done() -> None:
            give_back()
            if not closing.acquire(blocking=False):
                return
            # Closed, and so gone from the disk, in a thread and not waited for: a large file takes its time to go, and nothing
            # waits for the disk on the event loop. (Where no thread can be had any more, the program ending: here.)
            try:
                asyncio.get_running_loop().run_in_executor(None, spool.close)
            except RuntimeError:
                spool.close()

        def said(page: list[dict[str, Any]], heading: bool) -> bytes:
            if format == "csv":
                return audit_table(page, heading).encode()
            return "".join(json.dumps(entry, ensure_ascii=False) + "\n" for entry in page).encode()

        def room_for(more: int) -> bool:
            """Whether the disk the file is made on keeps the record's room (activity.Index._room) with `more` bytes in it. (Asks
            the disk: in a thread.)"""
            try:
                free = shutil.disk_usage(core.data_dir).free
            except OSError:
                return True
            return free - more >= 2 * core.audit.max_bytes + 2 * activity.WAL_MOST

        handed = False  # (from there on, the file and the place go with the answer: see Handed)
        try:
            page, heading = await activity_reads.run(asker, pager.next), True
            if page is None and format == "csv":
                spool.write(said([], True))
            while page is not None:
                if await request.is_disconnected():
                    # Asked for and not waited for: nothing more is made, and nothing was taken away (no entry).
                    return fail(400, "disconnected", "The download was not waited for")
                chunk = await asyncio.to_thread(said, page, heading)
                if spool.tell() + len(chunk) > SPOOL_IN_MEMORY and not await asyncio.to_thread(room_for, len(chunk)):  # (in memory it takes none of the disk)
                    return fail(507, "not_saved", "There is not room enough on the disk to make this download beside what the activity log is to keep: narrow it down, or make room")
                await asyncio.to_thread(spool.write, chunk)
                heading = False
                if refused := still_allowed(request):  # (as after any read that waited: before each page, and at the end)
                    return refused
                page = await activity_reads.run(asker, pager.next, patient=True)
            if refused := still_allowed(request):
                return refused
            # Written down before it is sent: who took the log away, and which part of it. (What it holds was read before. The
            # words as they are looked for: twenty of a hundred characters at the most. As they came, an address long enough
            # made an entry longer than any the log is read for.)
            words = [text[: activity.LONGEST_WORD] for text in (q or [])[: activity.MOST_WORDS]]
            narrowed = {key: value for key, value in (("q", words), ("kind", kind), ("since", since), ("until", until), ("user", user), ("device", device)) if value}
            audit.write("activity_exported", client_ip(request), format=format, **({"asked": narrowed} if narrowed else {}))
            size = spool.tell()

            async def body() -> AsyncIterator[bytes]:
                await asyncio.to_thread(spool.seek, 0)
                # (64 kB at a time: on Windows a megabyte handed to the connection counts as one write until all of it is
                # taken, and a client that took less than 50 kB a second was taken for one that takes nothing, and dropped.)
                while chunk := await asyncio.to_thread(spool.read, 1 << 16):
                    yield chunk

            name = f"qkvm-activity-{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}.{format}"
            media = "text/csv; charset=utf-8" if format == "csv" else "application/x-ndjson"
            said_how = {"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store", "Content-Length": str(size)}
            reply = Handed(body(), done, media_type=media, headers=said_how)
            handed = True
            return reply
        except TurnRefused as turned:
            return turned.reply
        except activity.NotReadable as ex:
            return fail(503, "activity_unavailable", str(ex))
        finally:
            if not handed:
                done()  # (refused, or cut off: what was made of it goes, and so does its place)
            # Let go of in a thread of its own and not waited for: a download cut off is a task being stopped, and the page
            # it was reading is done first (Pager.close waits for it). (Where no thread can be had any more, the program
            # ending, here: it waits a page at the most.)
            try:
                asyncio.get_running_loop().run_in_executor(None, pager.close)
            except RuntimeError:
                pager.close()

    return app
