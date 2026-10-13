"""The wall's saved state: one JSON file, replaced atomically on every change."""

from __future__ import annotations

import copy
import errno
import ipaddress
import json
import logging
import os
import queue
import re
import shutil
import stat
import sys
import unicodedata
import threading
import time
from collections.abc import Callable
from dataclasses import MISSING, asdict, dataclass, field, fields
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

log = logging.getLogger("qkvm")

DEFAULT_PORT = 8787


# The id of an account, a device, a saved action or a token: this program gives eight hex digits, and takes
# what else has no colon in it (see Store._read for why the colon matters).
_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")


def _shallow(value: Any, most: int = 24) -> bool:
    """Whether `value` (lists and dicts of plain things) is nested no deeper than `most`. Counted without going as deep itself."""
    level: list[Any] = [value]
    for _ in range(most):
        level = [inner for outer in level if isinstance(outer, (dict, list)) for inner in (outer.values() if isinstance(outer, dict) else outer)]
        if not any(isinstance(inner, (dict, list)) for inner in level):
            return True
    return False


class StoreError(Exception):
    """The state file exists but cannot be used."""


@dataclass
class ServerSettings:
    bind: list[str] = field(default_factory=lambda: ["local"])
    port: int = DEFAULT_PORT
    https: bool = False
    interval: float = 1.0
    allowed_hosts: list[str] = field(default_factory=list)
    update_check: bool = True  # ask GitHub once a day whether a newer release exists
    metrics_token: str = ""  # what is kept of the token a monitoring system collects /metrics with (its hash); "": off
    metrics_created: float | None = None  # when that token was made
    # Who has to have two-factor sign-in: "" nobody, or a role, meaning accounts of that role and above
    # ("operator": operators and admins). One of them without it can sign in to set it up, and to nothing else.
    require_totp: str = ""


@dataclass
class AlertSettings:
    """When to tell someone that a KVM changed state, and where."""

    enabled: bool = False
    webhook: dict[str, str] | None = None  # the address to post to, encrypted by the vault (it often holds a token)
    format: str = "auto"  # how the service behind it wants to be spoken to: see alerts.FORMATS
    offline: bool = True  # a KVM stopped answering
    no_signal: bool = True  # the computer behind it went dark
    problem: bool = True  # login rejected, certificate changed
    recovered: bool = True  # any of those is over
    link: str = ""  # the wall's address as people reach it: an alert points there, at the tile it is about
    paused_until: float = 0.0  # nothing is sent before this time (maintenance); what is still wrong then is told then


@dataclass
class DeviceRecord:
    id: str
    name: str
    url: str  # scheme://host[:port], what the wall server talks to
    username: str = "admin"
    open_url: str = ""  # where the browser's "Open console" goes, if not url
    tls: str = "pinned"  # "pinned" | "system" | "insecure"
    cert_pem: str | None = None  # the certificate trusted in "pinned" mode
    secret: dict[str, str] | None = None  # the device password, encrypted by the vault
    kind: str = "kvmd"  # which driver talks to it: "kvmd" (GLKVM, PiKVM) | "jetkvm" | "redfish" (a server's BMC)
    group: str = ""  # a label to show KVMs together by: a rack, a room, a customer
    # What the device says it is, where it has a say (a server's own number), or "own:..." once somebody
    # decided that it is to have a tile of its own whatever it looks like. See core.identity.
    ident: str = ""
    alerts: bool = True  # False: nobody is told when this one changes (a test bench, a machine that sleeps)


ROLES = ("admin", "operator", "viewer")  # most to least: everything / watch and act / watch only


@dataclass
class UserRecord:
    """Someone who may sign in."""

    id: str
    name: str  # what they type to sign in; upper and lower case are the same
    role: str = "admin"  # one of ROLES
    auth: dict[str, Any] = field(default_factory=dict)  # lets their password unlock the vault (vault.Vault.rewrap)
    devices: list[str] | None = None  # ids of the KVMs they may see and use; None: all of them
    # Groups whose KVMs they may see and use as well, whichever are in them on the day (not looked at while `devices` is None).
    groups: list[str] = field(default_factory=list)
    suspended: bool = False  # cannot sign in until an admin lifts it; everything else about the account is kept
    created: float = 0.0
    totp: dict[str, str] | None = None  # the key of their authenticator app, encrypted by the vault; None: not in use
    totp_codes: list[str] = field(default_factory=list)  # what is kept of their unused one-time codes (totp.kept)
    totp_step: int = 0  # the time step of the last code of their app that was accepted: a code works once, a restart later too
    totp_changes: int = 0  # how often the second step was switched on or off: part of what a kept sign-in is good by (core.auth_mark)


@dataclass
class TokenRecord:
    """Something that may use QKVM without a person signing in: a script, or a screen on the wall."""

    id: str
    name: str  # what it is for, in its maker's words
    kind: str = "api"  # "api": a script sends it with every request | "display": a browser on a wall screen opens it once
    role: str = "viewer"  # "viewer" or "operator"; there is no token that can do what an admin can
    devices: list[str] | None = None  # ids of the KVMs it is for; None: all of them
    groups: list[str] = field(default_factory=list)  # and the KVMs of these groups, as for an account
    kept: str = ""  # what is kept of the token itself: enough to know it again, not to use it
    created: float = 0.0
    expires: float | None = None  # after this it is nobody; None: until it is taken back
    used: float | None = None  # when it was last used, as far as was saved since


@dataclass
class ActionRecord:
    """A custom action: a key combination or some text to type, runnable on any KVM."""

    id: str
    name: str
    kind: str  # "keys" | "text"
    keys: str = ""  # for "keys": names such as "MetaLeft,KeyL"
    secret: dict[str, str] | None = None  # for "text": what to type, encrypted by the vault
    enter: bool = False  # for "text": press Enter afterwards
    danger: bool = False  # ask for extra confirmation before running it
    changed: int = 0  # how often it was edited: whoever runs it says which of its states they saw


# What ends a line, and what turns round the direction of the text after it (a name could be made to read
# as another one with those): not in a name.
_NOT_IN_A_LINE = frozenset({0x2028, 0x2029, *range(0x202A, 0x202F), *range(0x2066, 0x206A)})
# Blanks of no width. Typed without knowing (a Khmer keyboard's space bar gives one between words) and
# pasted without seeing: gone without a word, as the blanks around a name are.
_NOT_KEPT = frozenset({0x200B, 0x2060, 0xFEFF})


def as_a_line(text: str) -> str | None:
    """`text` as one line that reads as it is written, or None where it cannot be made one.

    The rule for a name, for the form and for a file alike: what the wall takes from the one it writes
    into the other, and has to take back. (A file was held to "printable", which to Python leaves out
    every blank but the plain one, and the joiner inside many an emoji: a device with such a name was
    exported, and left out when the file was read.) A tab is a blank; a blank of no width is nothing;
    what ends a line, what moves the cursor and what turns the writing round make it no line.
    """
    kept = []
    for ch in text:
        if ch == chr(9):
            kept.append(" ")
        elif ord(ch) in _NOT_KEPT:
            continue
        elif unicodedata.category(ch) in ("Cc", "Cs") or ord(ch) in _NOT_IN_A_LINE:
            return None
        else:
            kept.append(ch)
    return "".join(kept)


def device_url(text: str) -> str:
    """Accept '192.168.1.20', 'kvm.lan:8443' or a pasted 'https://192.168.1.20/#/'."""
    text = text.strip()
    parts = urlsplit(text if "://" in text else f"https://{text}")
    try:
        port = parts.port
        usable = parts.scheme in ("http", "https") and port != 0
        # (Letters, digits, dots and hyphens, as a host name is made; and the underscore, which no host name
        # has by the book and many a name on a home network has all the same.)
        usable = usable and re.fullmatch(r"[A-Za-z0-9._:-]+", parts.hostname or "") is not None
    except ValueError:  # port is not a number
        usable = False
    if not usable or "@" in parts.netloc:
        raise ValueError(f"not a usable device address: {text!r}")
    # One device, one way to write where it is: whether it is "on the wall already" is asked by this text.
    # Written with capitals, with the port every such address has anyway, or with a dot after its name, it
    # was another address each time, and a tile each.
    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise ValueError(f"not a usable device address: {text!r}")
    numbers = ":" in host or host.rsplit(".", 1)[-1].isdigit() or host.rsplit(".", 1)[-1].startswith("0x")
    if numbers:
        # Numbers are written the one way too: "::1" and "0:0:0:0:0:0:0:1" are one address, and "127.1" or
        # "010.1.1.1" are numbers that this takes for another host than the system does, or for none.
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            raise ValueError(f"not a usable device address: {text!r}") from None
        host = f"[{address}]" if address.version == 6 else str(address)
    usual = 443 if parts.scheme == "https" else 80
    written = f"{parts.scheme}://{host}" + ("" if port is None or port == usual else f":{port}")
    import httpx  # (here, and not at the top: this file is read by commands that connect to nothing)

    try:
        # What will have to connect to it has the last word on whether it is an address (and says it of a
        # name only when it is asked for the name).
        named = bool(httpx.URL(written).host)
    except (httpx.InvalidURL, ValueError):
        named = False
    if not named:
        raise ValueError(f"not a usable device address: {text!r}")
    return written


def _settle(folder: Path) -> None:
    """Have the folder itself written out, so that a file just put in place is still there after a power cut.

    Where the system offers that: Windows does not, and writes the folder with the file.
    """
    if sys.platform == "win32":
        return
    try:
        descriptor = os.open(folder, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


# What a field of a record may hold, by what it is declared as. (A number that is too large to be worked
# with is none: one of four hundred digits was read, and was an error wherever it was first compared.)
def _a_text(value: Any) -> bool:
    """A text that can be written down again. Half a character (which a file can spell out) is read, and
    can then be sent to no browser and saved to no file: the page that showed it was an error from then on."""
    if not isinstance(value, str):
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


_HOLDS: dict[str, Callable[[Any], bool]] = {
    "str": _a_text,
    "bool": lambda value: isinstance(value, bool),
    "int": lambda value: isinstance(value, int) and not isinstance(value, bool) and abs(value) < 2**63,
    "float": lambda value: isinstance(value, (int, float)) and not isinstance(value, bool) and abs(value) < 1e300,
    "list[str]": lambda value: isinstance(value, list) and all(_a_text(each) for each in value),
    "dict[str, str]": lambda value: isinstance(value, dict),
    "dict[str, Any]": lambda value: isinstance(value, dict),
}
# What a field is with nothing in it (null): the empty one of its kind. It is what the program took nothing
# for while it did not ask (off, no text, none), and it is NOT what the field is when it is not written at
# all: that, for an account's role, is "admin".
_EMPTY: dict[str, Callable[[], Any]] = {"str": str, "bool": bool, "int": int, "float": float, "list[str]": list, "dict[str, str]": dict, "dict[str, Any]": dict}
# ...but for these, where empty is of no use and what is declared gives nothing away: how a device is
# signed in to and talked to, how alerts are written, where the wall listens and how often it looks.
_NEVER_EMPTY = frozenset({("DeviceRecord", "username"), ("DeviceRecord", "tls"), ("DeviceRecord", "kind"), ("AlertSettings", "format"), ("ServerSettings", "bind"), ("ServerSettings", "port"), ("ServerSettings", "interval")})  # fmt: skip
# ...and for what somebody may do, where nothing is the least there is.
_LEAST = {("UserRecord", "role"): "viewer", ("TokenRecord", "role"): "viewer"}
# ...and what each is called, for whoever edited the file and is told what was wrong with it.
_CALLED = {"str": "a text", "bool": "true or false", "int": "a whole number", "float": "a number", "list[str]": "a list of texts", "dict[str, str]": "a record", "dict[str, Any]": "a record"}
# What is saved encrypted is asked whether it opens where it is used, and is "nothing saved" where it does
# not, whatever it is made of (Vault.read); and a remembered certificate is asked whether it is one
# (kvm.saved_fingerprint, Device._tls_context). A damaged one of either is no reason not to start: the
# device it belongs to says what is wrong with it, and the rest of the wall is there.
#
# One thing is seen to here all the same: that what is remembered as a certificate is a text, or nothing.
# Nothing is what a device has that was never reached, and it is what lets the first certificate it shows
# be trusted. `false`, 0 or an empty list where a certificate was (a slip of a hand, or of a script) read
# as nothing too: whatever answered at that address next was trusted, and sent the saved password. What
# is there and is no text is kept as a text, which is no certificate either: the tile says that its
# certificate cannot be read, the device is not talked to, and a person says what is trusted in its place.
_OPENED_LATER = frozenset({"secret", "webhook", "totp", "cert_pem"})


def _as_declared(record: Any, what: str) -> None:
    """Have every field of `record` hold what it is declared to hold. ValueError (naming it) where one cannot be made to.

    Every look at the wall takes these fields for what they are. With something else in one of them (a
    hand edit, a slip of a script) the file was read, the program started, and then the list of tiles, or
    every sign-in, was an error for everybody. Such a file cannot be used: the second copy is.

    Nothing at all in a field (null) is no such thing. Earlier versions ran with it, taking it for off, or
    for no text; a file that one of them ran with is not refused, and means what it meant (see _EMPTY).
    And 0 and 1 where yes or no belongs are no and yes, as whoever writes a file by hand writes them.
    """
    for each in fields(record):
        value = getattr(record, each.name)
        if each.name in _OPENED_LATER:
            if each.name == "cert_pem" and value is not None and not isinstance(value, str):
                setattr(record, each.name, str(value)[:80] or "?")
            elif each.name != "cert_pem" and value is not None and not (isinstance(value, dict) and value):
                # The same for what is saved sealed (a password, a text to type, the address alerts go to, the
                # key of a second step): nothing saved is null, and anything else is something. `false`, 0,
                # an empty list or record read as nothing wherever the question was "is there one?", and
                # nothing is not what a damaged one is. It is kept as a record that opens with no key.
                setattr(record, each.name, {"damaged": str(value)[:80]})
            continue
        kinds = [kind.strip() for kind in str(each.type).split("|")]
        whose = (type(record).__name__, each.name)
        if value is None:
            if "None" in kinds:
                continue
            if whose in _LEAST:
                setattr(record, each.name, _LEAST[whose])
            elif whose in _NEVER_EMPTY:
                made = each.default_factory
                setattr(record, each.name, each.default if made is MISSING else made())
            else:
                setattr(record, each.name, _EMPTY[kinds[0]]())
        elif "bool" in kinds and type(value) is int and value in (0, 1):
            setattr(record, each.name, bool(value))
        elif not any(_HOLDS[kind](value) for kind in kinds if kind != "None"):  # (every kind a record is declared with is in _HOLDS: a test sees to that)
            raise ValueError(f"{what}: \"{each.name}\" has to be {' or '.join(_CALLED[kind] for kind in kinds if kind != 'None')}{', or null' if 'None' in kinds else ''}")


def _only_known(cls: type, data: dict[str, Any]) -> dict[str, Any]:
    known = {f.name for f in fields(cls)}
    return {key: value for key, value in data.items() if key in known}


VERSION = 1  # of the settings file as this program writes it
# The parts of the settings file this program knows of.
_PARTS = ("version", "recovery", "recovery_created", "unlock", "server", "alerts", "users", "devices", "actions", "tokens")


def _not_known(cls: type, data: Any) -> dict[str, Any]:
    known = {f.name for f in fields(cls)}
    return {key: value for key, value in data.items() if key not in known} if isinstance(data, dict) else {}


def _beyond(data: dict[str, Any]) -> dict[str, Any]:
    """What a settings file holds that this program has not heard of: written by a later version of it.

    Kept as it is and written back with every save (see Store.snapshot). This version is the one every
    later one goes back to when an update does not start. Started on a file the later one wrote, it would
    otherwise drop, at its first save, every setting it does not know (a rule about signing in could be
    one), and say nothing; updated again, the later version would find its settings gone.
    """
    by_id: dict[str, dict[str, dict[str, Any]]] = {}
    for part, cls in (("users", UserRecord), ("devices", DeviceRecord), ("actions", ActionRecord), ("tokens", TokenRecord)):
        found = data.get(part)
        things: list[Any] = found if isinstance(found, list) else []
        by_id[part] = {str(thing["id"]): more for thing in things if isinstance(thing, dict) and "id" in thing and (more := _not_known(cls, thing))}
    return {
        "top": {key: value for key, value in data.items() if key not in _PARTS},
        "server": _not_known(ServerSettings, data.get("server")),
        "alerts": _not_known(AlertSettings, data.get("alerts")),
        "by_id": by_id,
    }


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.backup = path.with_suffix(".bak")  # a second copy of what was saved last (see write)
        self.backup_is_old = False  # the second copy could be neither renewed nor taken away: it is from before the last change
        self.server = ServerSettings()
        self.users: list[UserRecord] = []
        # Lets the recovery key unlock the vault, as a password would (vault.Vault.rewrap); None: no key was made.
        self.recovery: dict[str, Any] | None = None
        self.recovery_created = 0.0
        # Lets the secret in the unlock file open the vault at start, in the same way (see unlock.py); None: not in use.
        self.unlock: dict[str, Any] | None = None
        self.devices: list[DeviceRecord] = []
        self.actions: list[ActionRecord] = []
        self.tokens: list[TokenRecord] = []
        self.alerts = AlertSettings()
        self.recovered_from: Path | None = None  # set when the settings were read from the second copy: the damaged file, or None for one that was not there
        self.restored = False  # ...and this says that they were
        self.damage = ""  # ...and what was wrong with the file that was not used
        self._version = VERSION
        self._beyond = _beyond({})
        self._writing = threading.Lock()  # one write at a time: they all go through the same temporary file
        # With either of the two there, this is not a new wall. A start that was cut off between setting a damaged
        # file aside and writing the settings anew leaves only the second copy: taken for a first run, the wall
        # would be anybody's to set up, and the owner's settings would be written over at the second change.
        if path.exists() or self.backup.exists():
            self._load()

    def _read(self, path: Path) -> None:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("not a settings file")
        version = data.get("version")
        self._version = max(VERSION, version) if isinstance(version, int) and not isinstance(version, bool) else VERSION
        self._beyond = _beyond(data)
        # What is read here is copied and written out again at every save, from deeper inside the program
        # than this is read at. Nested deeper than that can be done (some hundreds of lists, one in
        # another), it was read without complaint, and then no change could be saved for as long as the
        # program ran. Nothing any version writes is nested like that: counted, and refused. (Asked of the
        # whole file: asked only of what is carried along for a later version, a saved password that was
        # such a thing was kept, and every save after that was answered "not saved".)
        if not _shallow(data):
            raise ValueError("nested deeper than a settings file is")
        self.server = ServerSettings(**_only_known(ServerSettings, data.get("server", {})))
        if isinstance(self.server.allowed_hosts, str):
            # One name, written without the brackets a list has: what was meant is plain, and taken as
            # a text it was looked for inside ("e.org" is in "wall.example.org").
            self.server.allowed_hosts = [self.server.allowed_hosts]
        self.users = [UserRecord(**_only_known(UserRecord, u)) for u in data.get("users", [])]
        self.recovery = data.get("recovery") or None
        made = data.get("recovery_created") or 0.0
        if not _HOLDS["float"](made):
            raise ValueError("when the recovery key was made is not a time")
        self.recovery_created = float(made)
        self.unlock = data.get("unlock") or None
        self.devices = [DeviceRecord(**_only_known(DeviceRecord, d)) for d in data.get("devices", [])]
        self.actions = [ActionRecord(**_only_known(ActionRecord, a)) for a in data.get("actions", [])]
        self.tokens = [TokenRecord(**_only_known(TokenRecord, t)) for t in data.get("tokens", [])]
        self.alerts = AlertSettings(**_only_known(AlertSettings, data.get("alerts", {})))
        _as_declared(self.server, "the settings under \"server\"")
        _as_declared(self.alerts, "the settings under \"alerts\"")
        if not 1 <= self.server.port <= 65535:
            raise ValueError("the settings under \"server\": \"port\" has to be a number from 1 to 65535")
        # How often the wall looks is a number of seconds the form takes: from a fifth of one to a minute.
        # Written by hand as 0, every browser opened on "Paused"; as less than nothing, every browser asked
        # for pictures without a pause. Neither is a reason not to start: it is the nearest that makes sense.
        self.server.interval = min(60.0, max(0.2, float(self.server.interval)))
        records: list[Any] = [*self.users, *self.devices, *self.actions, *self.tokens]
        for number, record in enumerate(records):
            kind = {UserRecord: "account", DeviceRecord: "device", ActionRecord: "saved action", TokenRecord: "token"}[type(record)]
            what = f"the {kind} {record.id!r}" if isinstance(record.id, str) and _ID.fullmatch(record.id) else f"record {number + 1} (a {kind})"
            _as_declared(record, what)
            # And a few that are of the right kind and still no good: every look at the wall asks an
            # account what it may do, and a device where it is.
            if isinstance(record, (UserRecord, TokenRecord)) and record.role not in ROLES:
                raise ValueError(f"{what}: \"role\" has to be one of {', '.join(ROLES)}")
            if isinstance(record, TokenRecord) and record.role == "admin":
                # What manages QKVM itself takes a person: no form makes such a token, and one written into
                # the file by hand administered (accounts, devices, other tokens) on the strength of a key.
                raise ValueError(f"{what}: \"role\" has to be viewer or operator (no token does what an admin does)")
            if isinstance(record, DeviceRecord):
                try:
                    where = urlsplit(record.url)
                    usable = bool(where.hostname) and where.scheme in ("http", "https") and where.port != 0
                except ValueError:
                    usable = False
                if not usable:
                    raise ValueError(f"{what}: \"url\" is not an address")
            # What is saved encrypted is sealed for the id of its record: a device's password for the device,
            # a saved text for "action:" and its id, an authenticator's key for "totp:" and the account's.
            # An id with no colon in it is never one of those other names: no edit of the file makes a saved
            # text, or an authenticator's key, a device's "password", to be sent to an address of the
            # editor's choosing.
            if not (isinstance(record.id, str) and _ID.fullmatch(record.id)):
                raise ValueError("a record's id is not one this program gives")

    def _load(self) -> None:
        failures = (OSError, ValueError, TypeError, AttributeError, RecursionError, OverflowError)
        try:
            self._read(self.path)
            return
        except failures as ex:
            damage = ex
        # The file is unreadable (a bad hand edit, a fault of the disk) or not there. Fall back to the second
        # copy, which is of what was saved last, and keep a damaged file next to it for inspection.
        try:
            self._read(self.backup)
        except failures:
            # Never start from scratch over a file that might still be recoverable.
            raise StoreError(
                f"{self.path} cannot be read ({damage}), and neither can its second copy, {self.backup.name}; "
                "fix one of them, or move both aside to start over"
            ) from damage
        self.restored = True
        # (What was wrong with it, for whoever edited it and finds their edit set aside. In words of this
        # program's own, or the kind of error: never a piece of the file, which may be a secret.)
        self.damage = str(damage) if isinstance(damage, (ValueError, OSError)) and not isinstance(damage, (json.JSONDecodeError, UnicodeError)) else type(damage).__name__
        if isinstance(damage, json.JSONDecodeError):
            self.damage = f"it is not JSON any more, at line {damage.lineno}"
        if self.path.exists():
            aside = self.path.with_name(f"{self.path.stem}.damaged-{int(time.time())}{self.path.suffix}")
            os.replace(self.path, aside)
            self.recovered_from = aside
        self.save()

    def snapshot(self) -> dict[str, Any]:
        """Everything that gets saved, copied into plain data. Quick, and safe to hand to another thread."""
        beyond = copy.deepcopy(self._beyond)  # what a later version wrote and this one does not know: carried along (see _beyond)

        def things(part: str, records: list[Any]) -> list[dict[str, Any]]:
            return [{**beyond["by_id"][part].get(record.id, {}), **asdict(record)} for record in records]

        return {
            **beyond["top"],
            "version": self._version,
            "server": {**beyond["server"], **asdict(self.server)},
            "users": things("users", self.users),
            "recovery": copy.deepcopy(self.recovery),
            "recovery_created": self.recovery_created,
            "unlock": copy.deepcopy(self.unlock),
            "devices": things("devices", self.devices),
            "actions": things("actions", self.actions),
            "tokens": things("tokens", self.tokens),
            "alerts": {**beyond["alerts"], **asdict(self.alerts)},
        }

    def save(self) -> None:
        self.write(self.snapshot())

    def write(self, data: dict[str, Any]) -> None:
        """Put a snapshot on disk: all of it or none of it, and then a second copy of it beside it.

        Waits for the disk, so the server calls this from a worker thread, one write at a time.

        The second copy (qkvm.bak) is what a start falls back to when the file itself cannot be read. It is
        of what was just written, not of what was there before: a copy from before the last change would, at
        such a start, bring back whatever that change took away (an account that was removed, a token taken
        back, a password that was replaced, the key an unlock file fitted). Where it cannot be renewed it is
        taken away, for the same reason: no second copy rather than an old one.
        """
        tmp = self.path.with_suffix(".tmp")
        with self._writing:
            with tmp.open("w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
            _settle(self.path.parent)
            again = self.backup.with_name(self.backup.name + ".new")
            try:
                shutil.copy2(self.path, again)
                os.replace(again, self.backup)
                self.backup_is_old = False
            except OSError as ex:
                try:
                    os.unlink(again)  # the copy in the making holds what the settings held: not left lying half made
                except OSError:
                    pass
                try:
                    os.unlink(self.backup)
                    self.backup_is_old = False
                except FileNotFoundError:
                    self.backup_is_old = False
                except OSError:
                    self.backup_is_old = True
                # (Not a reason to call the change unsaved: it is saved. But somebody has to hear of it.)
                log.error(
                    "the second copy of the settings (%s) could not be renewed (%s); %s",
                    self.backup.name, ex.strerror or ex,
                    "it could not be taken away either, and is from before the last change" if self.backup_is_old else "it was taken away, and is made again at the next change",
                )  # fmt: skip

    def clear_out(self) -> list[str]:
        """Remove what else in the folder holds settings as they once were. Returns the names of what could not be removed.

        A damaged settings file that was set aside for somebody to look at, a second copy that was left in
        the making, a write that was cut off: each holds the accounts and the saved passwords of its day.
        Whoever erases those, or takes away what a key opened them with, means every copy in the folder.
        """
        stem, suffix = self.path.stem, self.path.suffix
        old = [*self.path.parent.glob(f"{stem}.damaged-*{suffix}"), self.backup.with_name(self.backup.name + ".new"), self.path.with_suffix(".tmp")]
        left = []
        for path in old:
            try:
                os.unlink(path)
            except FileNotFoundError:
                continue
            except OSError:
                left.append(path.name)
            else:
                log.warning("removed %s from the data folder: it held the settings as they were before", path.name)
        if self.backup_is_old:
            left.append(self.backup.name)
        return left

    def device(self, device_id: str) -> DeviceRecord | None:
        return next((d for d in self.devices if d.id == device_id), None)

    def user(self, user_id: str) -> UserRecord | None:
        return next((u for u in self.users if u.id == user_id), None)

    def user_named(self, name: str) -> UserRecord | None:
        wanted = name.strip().casefold()
        return next((u for u in self.users if u.name.casefold() == wanted), None)


def _to_read(path: Path) -> int:
    """Open what is at `path` for reading and nothing else, as whoever only asks about a folder opens what is in it.

    Never through a link, never waiting (for a pipe put there to be written to), and only a file: whoever
    asks may be more than whoever owns the folder. OSError for anything else, and for nothing there.
    """
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise OSError(errno.EINVAL, "not a file", str(path))
    return fd


def _held(path: Path) -> bool:
    """Whether another process holds the lock at `path`, found out without writing anything.

    Nothing is made where there is no file (then nobody holds it), and nothing in the file is changed.
    OSError: what is there cannot be looked at (a link, something that is not a file, somebody else's).
    """
    try:
        fd = _to_read(path)
    except FileNotFoundError:
        return False
    try:
        if sys.platform == "win32":
            import msvcrt

            os.lseek(fd, 0, os.SEEK_SET)
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            except OSError:
                return True
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                return True
            fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


_VERSION = re.compile(r"[0-9A-Za-z.+-]{1,32}")
_LISTENS = re.compile(r"https?://[0-9A-Za-z.:\[\]-]{1,120}/?")


def _locked(path: Path) -> Any | None:
    """Open `path` and take an exclusive lock on it. None if another process holds it."""
    handle = path.open("ab+")
    try:
        if sys.platform == "win32":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return None
    return handle


class InstanceLock:
    """Held by the running program so that a second copy can't write to the same data folder.

    The file also says who holds it: the process to stop, since when, which version, where it listens. That
    is for the second copy that is turned away, and for `qkvm status`. On Windows the locked byte (the first)
    can be read by nobody else, so what is said stands after it.
    """

    def __init__(self, directory: Path) -> None:
        self.path = directory / "qkvm.lock"
        self._file: Any | None = None
        self._said: dict[str, Any] = {}

    def acquire(self, patience: float = 0.0) -> bool:
        """Take the lock. False when another process already holds it.

        `patience`: for that many seconds it is tried again. `qkvm status` holds the lock for the moment it
        takes to find out that nobody else does, and a wall that starts in that moment is not to be told
        that a copy of it runs already.
        """
        until = time.monotonic() + patience
        while True:
            self._file = _locked(self.path)  # held for as long as it stays open; the OS drops it if we crash
            if self._file is not None or time.monotonic() >= until:
                return self._file is not None
            time.sleep(0.05)

    def say(self, **about: Any) -> None:
        """Write down who holds the lock, adding to what was said before."""
        if self._file is None:
            return
        self._said.update(about)
        try:
            self._write(json.dumps(self._said).encode())
        except OSError:
            pass  # a courtesy to whoever asks; the lock itself is what counts

    def _write(self, said: bytes) -> None:
        file = self._file
        assert file is not None
        file.seek(0, os.SEEK_END)
        if file.tell() == 0:
            file.write(b"\n")  # the byte that is locked
            file.flush()
        file.truncate(1)
        file.write(said)  # opened for appending: it lands after that byte
        file.flush()

    def held_elsewhere(self, patience: float = 0.0) -> bool:
        """Whether another process holds the lock: asked without taking it for keeps, and without writing a byte.

        For `qkvm status` and its like, which look into folders that may be somebody else's. `patience`: for
        that many seconds it is asked again, since another one asking holds it for the moment that takes.
        """
        until = time.monotonic() + patience
        while _held(self.path):
            if time.monotonic() >= until:
                return True
            time.sleep(0.05)
        return False

    def holder(self) -> dict[str, Any] | None:
        """What the copy that holds the lock said of itself. None if it said nothing (an older version does not).

        Read by whoever asks, and written by whoever could: nothing of it is taken at its word. A process
        number is a number, a date is one that a calendar has, and text is of the few characters a version
        and an address are made of. Whatever else stands there is left out.
        """
        try:
            fd = _to_read(self.path)
            with os.fdopen(fd, "rb") as file:
                file.seek(1)
                said = json.loads(file.read(8192))
        except (OSError, ValueError, RecursionError):
            return None
        if not isinstance(said, dict):
            return None
        known: dict[str, Any] = {}
        pid, since, version, listening = said.get("pid"), said.get("since"), said.get("version"), said.get("listening")
        if isinstance(pid, int) and not isinstance(pid, bool) and 0 < pid < 2**31:
            known["pid"] = pid
        # (A date before the year 2100. What is not a number is none, and neither is "not a number".)
        if isinstance(since, (int, float)) and not isinstance(since, bool) and 0 < since < 4_102_444_800:
            known["since"] = float(since)
        if isinstance(version, str) and _VERSION.fullmatch(version):
            known["version"] = version
        if isinstance(listening, list):
            known["listening"] = [url for url in listening[:16] if isinstance(url, str) and _LISTENS.fullmatch(url)]
        return known or None

    def release(self) -> None:
        if self._file is not None:
            try:
                self._write(b"")  # nobody holds it now, and the file does not say otherwise
            except OSError:
                pass
            self._file.close()
            self._file = None
            self._said = {}


class AuditLog:
    """Append-only record of logins, changes and device actions (JSON lines).

    Entries are written by a thread of its own, in the order they were made: whoever makes one is in the
    middle of answering a request, on the one thread that serves everybody, and does not wait for a disk.

    Kept: the file being written, and OLD_FILES before it, of max_bytes each. That is years of an
    ordinary wall, and enough that what somebody did cannot be pushed out of the log by doing something
    harmless a few thousand times afterwards.
    """

    OLD_FILES = 9

    def __init__(self, path: Path, max_bytes: int = 2_000_000, forward: Callable[[str], None] | None = None) -> None:
        self.path = path
        self.max_bytes = max_bytes
        self.forward = forward  # given each entry once it is written, for sending on (it must not wait for anything)
        # Entries that could not be written since the program started: how many, since when, and why the last time.
        self.missing: dict[str, Any] | None = None
        self._unsaid = 0  # ...and how many of them the log itself does not yet say are missing
        self._unsaid_since: float | None = None  # ...since when (of this hole: there may have been one before)
        self._told = 0.0  # when the program's own log last said so
        self._waiting: queue.Queue[str] = queue.Queue()
        self._writer: threading.Thread | None = None
        self._starting = threading.Lock()

    def write(self, event: str, ip: str, **detail: Any) -> None:
        self._waiting.put(json.dumps({"time": time.time(), "event": event, "ip": ip, **detail}) + "\n")
        if self._writer is None:
            with self._starting:
                if self._writer is None:
                    self._writer = threading.Thread(target=self._write_on, name="activity-log", daemon=True)
                    self._writer.start()

    def _write_on(self) -> None:
        while True:
            line = self._waiting.get()
            try:
                self._append(line)
                if self.forward is not None:
                    self.forward(line)
            except Exception:  # whatever goes wrong with one entry, the ones after it are written
                pass
            finally:
                self._waiting.task_done()

    def _old(self, number: int) -> Path:
        return self.path.with_name(f"{self.path.name}.{number}")

    def _append(self, line: str) -> None:
        try:
            if self.path.stat().st_size > self.max_bytes:
                # The oldest goes, each of the others becomes one older, and the full one the newest of them.
                for number in range(self.OLD_FILES, 0, -1):
                    newer = self.path if number == 1 else self._old(number - 1)
                    if newer.exists():
                        os.replace(newer, self._old(number))
        except OSError:
            pass  # not there yet, or held open by something else just now: written on, and moved aside another time
        told = bool(self._unsaid and self.missing is not None)
        try:
            with self.path.open("a", encoding="utf-8") as fh:
                if told and self.missing is not None:
                    # It can be written again. The hole is written into it first: what is known of it here
                    # is gone with the next restart, and the log would then read as if nothing were missing.
                    gap = {"time": time.time(), "event": "log_gap", "ip": "", "count": self._unsaid, "since": self._unsaid_since or self.missing["since"], "why": self.missing["why"]}
                    fh.write(json.dumps(gap) + "\n")
                fh.write(line)
            # (Only now is it on its way to the disk: a full one refuses at the end, when the file is closed.)
            if told:
                self._unsaid, self._unsaid_since = 0, None
        except OSError as ex:
            # A full disk must not take the wall down, nor keep anybody from pressing what has to be pressed.
            # But then things are done of which no record is kept, and that at least is said: in the program's
            # own log, and to whoever opens the activity log (see `missing`).
            now = time.time()
            why = ex.strerror or type(ex).__name__
            self.missing = {"count": (self.missing or {}).get("count", 0) + 1, "since": (self.missing or {}).get("since", now), "why": why}
            self._unsaid += 1
            self._unsaid_since = self._unsaid_since or now
            if now - self._told > 60:
                self._told = now
                log.error("the activity log could not be written (%s): %d of its entries are missing since this started", why, self.missing["count"])

    def flush(self, within: float = 5.0) -> None:
        """Wait until what has been given so far is written, though not for ever."""
        deadline = time.monotonic() + within
        while self._waiting.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.005)

    def tail(self, limit: int, wanted: Callable[[dict[str, Any]], bool] | None = None) -> list[dict[str, Any]]:
        """The newest `limit` entries, newest first. `wanted`: only those it says yes to."""
        self.flush()  # what was done a moment ago is in what is read
        entries: list[dict[str, Any]] = []
        for path in (self.path, *(self._old(number) for number in range(1, self.OLD_FILES + 1))):
            if len(entries) >= limit:
                break
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for line in reversed(lines):
                if len(entries) >= limit:
                    break
                try:
                    entry = json.loads(line)
                except (ValueError, RecursionError):
                    continue
                # An entry is what this program writes: a record of plain things, whose event is a text and
                # whose time is a moment. A line that is something else (damaged, or written by hand) is no
                # entry. Handed on, a list where the event belongs or a value nested a few hundred deep
                # made the whole log an error for whoever opened it.
                if not (isinstance(entry, dict) and isinstance(entry.get("event"), str) and _shallow(entry, 3)):
                    continue
                at = entry.get("time")
                if not (isinstance(at, (int, float)) and not isinstance(at, bool) and 0 <= at < 1e11):
                    continue
                if wanted is None or wanted(entry):
                    entries.append(entry)
        return entries
