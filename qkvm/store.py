"""The wall's saved state: an authenticated encrypted document, replaced atomically."""

from __future__ import annotations

import copy
import errno
import ipaddress
import json
import logging
import math
import os
import queue
import re
import shutil
import stat
import sys
import unicodedata
import threading
import time
from collections.abc import Callable, Generator, Iterator
from dataclasses import MISSING, asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import urlsplit

from .vault_storage import MAGIC, MigrationRequired, StorageCipher, UnsupportedFormat, create_key, key_path, read_key

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
    # How long what the wall saw of the machines is kept (history.sqlite; see history.py), and how large that
    # file may grow, in millions of bytes. Outside what makes sense, the nearest that does is taken.
    history_days: int = 90
    history_mb: int = 200
    # How large the activity log may grow, in millions of bytes: its text files together (ten of them, each a tenth of
    # this), which are the record; its index (audit.sqlite) holds what they hold, and takes about two and a half times
    # that. Read at the start. Outside what makes sense, the nearest that does is taken (activity_file_bytes).
    activity_mb: int = 50


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
    kind: str = "kvmd"  # which driver talks to it: "kvmd" (GLKVM, PiKVM) | "jetkvm" | "redfish" (a server's BMC) | "amt" (a PC with Intel AMT) | "vnc" (a VNC server) | "proxmox" (a virtual machine on Proxmox VE)
    group: str = ""  # a label to show KVMs together by: a rack, a room, a customer
    # What the device says it is, where it has a say (a server's own number), or "own:..." once somebody
    # decided that it is to have a tile of its own whatever it looks like. See core.identity.
    ident: str = ""
    alerts: bool = True  # False: nobody is told when this one changes (a test bench, a machine that sleeps)
    # The machine behind the address, by the number it gave for itself when it was added ("amt:..." for a PC with Intel
    # AMT, from its PlatformGUID): its driver checks it before anything is sent to the machine, and the tile says so where
    # another one answers there. Apart from `ident`, which a tile kept beside its twin gives up ("own:..."). "": none yet;
    # the first one seen is taken (DeviceManager._known). A person who types the password in an edit takes what answers.
    machine: str = ""
    fingerbot_strength: str = "firm"  # how hard a Fingerbot paired with the KVM presses its power button: "firm" | "light"


FINGERBOT_STRENGTHS = ("firm", "light")  # (what fingerbot_strength may be; anything else in a file is taken as the first)

# What a server's tile of 0.1.x kept as what the server is: the number its computer gives for itself (redfish.own_number).
_SERVER_BEFORE = re.compile(r"server:[0-9a-f]{32}")


def machine_from_before(kind: Any, ident: Any, machine: Any) -> Any:
    """The machine a tile was added for, where it was written by a version that had no `machine` (asked only where the
    field is not there at all: a file of 0.1.x): a server's tile of 0.1.x kept the number its computer gives for itself as
    what the server is (`ident`), unless it was kept beside its twin ("own:..."). That number is the server's from then on,
    so that an upgrade never trusts whatever answers first at its address (see redfish.RedfishDevice._judge). Anything else
    is handed back as it was."""
    if machine == "" and kind == "redfish" and isinstance(ident, str) and _SERVER_BEFORE.fullmatch(ident):
        return ident
    return machine


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
    """Something that may use qKVM without a person signing in: a script, or a screen on the wall."""

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


def holds_nothing(raw: bytes) -> bool:
    """Whether a settings file's bytes are what a power cut leaves of a write: nothing, or zeros only.

    (NTFS and XFS keep the length of a file whose data never reached the disk, and give zeros for it.) Such a file is
    no copy of any settings, of the old format or the new, and is passed over where it would be a remnant.
    """
    return not raw.strip(b"\0")


def sealed_beside(folder: Path) -> bool:
    """Whether the data folder holds something sealed with a storage key beside the settings themselves.

    The migration's recovery archive, a damaged copy set aside, what a write left: where one of those is, a key that is
    not found is a key not mounted or not restored yet, and a new one is never made where the real one is to go.
    """
    for found in (folder / "vault-migration.recovery", *folder.glob("qkvm.damaged-*.json"), folder / "qkvm.tmp", folder / "qkvm.bak.new"):
        if found.is_file() and not found.is_symlink():
            try:
                with found.open("rb") as stream:
                    if stream.read(len(b"QKVM-VAULT-")) == b"QKVM-VAULT-":
                        return True
            except OSError:
                return True  # (what cannot be read may be sealed: no key is made beside it, and reading it says why)
    return False


def _replace_settings(source: Path, destination: Path) -> None:
    """Replace atomically, allowing a brief Windows reader to finish first.

    Windows readers and scanners can deny replacement while a file is open. Retry only those errors,
    with at most 0.4 seconds of waiting per copy; persistent failures still reach the caller. Never
    remove the destination first: the previous complete settings must survive a failed replacement.
    """
    deadline = time.monotonic() + 0.4
    for delay in (0.01, 0.02, 0.04, 0.08, 0.10, 0.15, 0.0):
        try:
            os.replace(source, destination)
            return
        except OSError as ex:
            if sys.platform != "win32" or getattr(ex, "winerror", None) not in (5, 32, 33) or not delay:
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise
            time.sleep(min(delay, remaining))


def _settle(folder: Path) -> None:
    """Have the folder itself written out, so that a file just put in place is still there after a power cut.

    Where the system offers that. Windows does not: there the rename is kept whole by the file system's journal and
    written out a moment later, so a power cut right after it can leave the earlier complete copy in place.
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
    def __init__(self, path: Path, *, vault_key_file: Path | None = None, protected: bool = False, read_only: bool = False) -> None:
        self.path = path
        self.backup = path.with_suffix(".bak")  # a second copy of what was saved last (see write)
        self.backup_is_old = False  # the second copy could be neither renewed nor taken away: it is from before the last change
        self.read_only = read_only
        self.protected = protected
        self.cipher: StorageCipher | None = None
        self.key_file: Path | None = None
        existing = [file for file in (self.path, self.backup) if file.exists()]
        encrypted = False
        for file in existing:
            if file.is_file():
                with file.open("rb") as stream:
                    encrypted = encrypted or stream.read(len(MAGIC)).startswith(b"QKVM-VAULT-")
        empty_left: list[Path] = []  # what a power cut left of a write, holding nothing (see holds_nothing)
        if protected:
            # A stale legacy backup/remnant still contains password-openable records. Do not
            # report this profile as migrated while such a copy remains beside the envelope.
            remnants = [self.backup, *path.parent.glob("qkvm.damaged-*.json"), path.with_suffix(".tmp"), self.backup.with_name(self.backup.name + ".new")]
            for remnant in remnants:
                if not remnant.is_file() or remnant.is_symlink():
                    continue
                raw = remnant.read_bytes()
                if raw.startswith(b"QKVM-VAULT-"):
                    continue
                if holds_nothing(raw):
                    # No remnant of the old format: an empty or zero-filled file is what a power cut leaves of a
                    # write whose data never reached the disk. It locked a protected wall out of every start,
                    # verification and migration, with advice that did not help. Taken away below (the second
                    # copy is written anew); a remnant that holds anything at all still blocks, as before.
                    empty_left.append(remnant)
                    continue
                raise MigrationRequired("a legacy settings remnant remains; finish --migrate-vault with the original storage key before starting")
        if protected or encrypted:
            selected = key_path(path.parent, vault_key_file)
            self.key_file = selected
            if existing and not any(file.is_file() for file in existing):
                raise StoreError("the settings paths exist but are not readable settings files; refusing a new setup")
            if existing and not encrypted and protected:
                raise MigrationRequired("legacy vault: stop qKVM and run --migrate-vault with a separate --vault-key-file before starting this version")
            # (Beside files sealed with a key, a key not found is asked for and never made anew: see sealed_beside.)
            self.cipher = StorageCipher(read_key(selected) if existing or read_only or sealed_beside(path.parent) else create_key(selected))
            if encrypted and not read_only:
                self.protected = True
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
        if empty_left and not self.read_only:
            self._clear_empty(empty_left)

    def _clear_empty(self, empty_left: list[Path]) -> None:
        """Take away what a power cut left of a write and holds nothing; write the second copy anew where that was it."""
        for left in empty_left:
            if left == self.backup:
                continue  # (replaced, not removed: see below)
            try:
                os.unlink(left)
            except FileNotFoundError:
                continue
            except OSError as ex:
                log.warning("%s holds nothing (an interrupted write) and could not be taken away: %s", left.name, ex.strerror or ex)
            else:
                log.warning("took away %s: it held nothing, as an interrupted write leaves a file", left.name)
        if self.backup in empty_left and not self.restored:  # (a restore has just written both anew)
            log.warning("the second copy of the settings (%s) held nothing, as an interrupted write leaves it: written anew", self.backup.name)
            self.save()

    def _read(self, path: Path) -> None:
        raw = path.read_bytes()
        if raw.startswith(b"QKVM-VAULT-") and not raw.startswith(MAGIC):
            raise UnsupportedFormat("unsupported protected vault version; use the matching qKVM version, not an older backup")
        if raw.startswith(MAGIC):
            if self.cipher is None:
                raise StoreError("the server storage key is required to read this vault")
            data = self.cipher.decode(raw)
        elif self.protected:
            try:
                legacy = json.loads(raw)
            except (ValueError, UnicodeError):
                raise ValueError("damaged protected vault header") from None
            if isinstance(legacy, dict):
                raise MigrationRequired("unprotected or interrupted vault migration: run --migrate-vault with the original storage key; plaintext fallback is refused")
            raise ValueError("damaged protected vault header")
        else:
            data = json.loads(raw)
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
                # What manages qKVM itself takes a person: no form makes such a token, and one written into
                # the file by hand administered (accounts, devices, other tokens) on the strength of a key.
                raise ValueError(f"{what}: \"role\" has to be viewer or operator (no token does what an admin does)")
            if isinstance(record, DeviceRecord):
                # A VNC server is where vncdevice.vnc_url wrote it, vnc:// or vncs:// (as the Add box, the network
                # search and an import keep it), and only a VNC server is: every other kind talks HTTP.
                schemes = ("http", "https", "vnc", "vncs") if record.kind == "vnc" else ("http", "https")
                try:
                    where = urlsplit(record.url)
                    usable = bool(where.hostname) and where.scheme in schemes and where.port != 0
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
        # A server's tile written by 0.1.x, which had no `machine` (every later write has the field): known by the number it
        # kept as what the server is. Only there: a tile whose machine was found to be none since keeps that.
        for record, written in zip(self.devices, data.get("devices", []), strict=True):
            if "machine" not in written:
                record.machine = machine_from_before(record.kind, record.ident, record.machine)

    def _load(self) -> None:
        failures = (OSError, ValueError, TypeError, AttributeError, RecursionError, OverflowError)
        try:
            self._read(self.path)
            return
        except (MigrationRequired, UnsupportedFormat):
            raise
        except failures as ex:
            damage = ex
        # The file is unreadable (a bad hand edit, a fault of the disk) or not there. Fall back to the second
        # copy, which is of what was saved last, and keep a damaged file next to it for inspection.
        try:
            self._read(self.backup)
        except (MigrationRequired, UnsupportedFormat):
            raise
        except failures as second:
            # Never start from scratch over a file that might still be recoverable. (What was wrong with each: with the first
            # only, a second copy refused for another reason said that the first was missing.)
            raise StoreError(
                f"{self.path} cannot be read ({damage}), and neither can its second copy, {self.backup.name} ({second}); "
                "fix one of them, or move both aside to start over"
            ) from damage
        self.restored = True
        # (What was wrong with it, for whoever edited it and finds their edit set aside. In words of this
        # program's own, or the kind of error: never a piece of the file, which may be a secret.)
        self.damage = str(damage) if isinstance(damage, (ValueError, OSError)) and not isinstance(damage, (json.JSONDecodeError, UnicodeError)) else type(damage).__name__
        if isinstance(damage, json.JSONDecodeError):
            self.damage = f"it is not JSON any more, at line {damage.lineno}"
        if self.read_only:
            return
        if self.path.exists():
            aside = self.path.with_name(f"{self.path.stem}.damaged-{int(time.time())}{self.path.suffix}")
            if self.cipher is not None and not self.path.read_bytes().startswith(MAGIC):
                # Even a malformed legacy fragment can contain passwords. Keep its exact
                # bytes for diagnosis inside the envelope, never as a readable side copy.
                with aside.open("xb") as saved:
                    saved.write(self.cipher.seal(self.path.read_bytes()))
                    saved.flush()
                    os.fsync(saved.fileno())
            else:
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
            if self.read_only:
                raise OSError("a read-only settings snapshot cannot be written")
            if self.cipher is None:
                with tmp.open("w", encoding="utf-8") as fh:
                    json.dump(data, fh, indent=2)
                    fh.flush()
                    os.fsync(fh.fileno())
            else:
                encoded = self.cipher.encode(data)
                with tmp.open("wb") as fh:
                    fh.write(encoded)
                    fh.flush()
                    os.fsync(fh.fileno())
            _replace_settings(tmp, self.path)
            _settle(self.path.parent)
            again = self.backup.with_name(self.backup.name + ".new")
            try:
                shutil.copy2(self.path, again)
                # On the disk before it takes the place of the last copy: renamed first, a power cut could leave the
                # name with its data never written (an empty or zero-filled qkvm.bak).
                with again.open("rb+") as copied:
                    os.fsync(copied.fileno())
                _replace_settings(again, self.backup)
                _settle(self.backup.parent)  # (and that rename on the disk too, as the one of the settings above)
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
        old = [*self.path.parent.glob(f"{stem}.damaged-*{suffix}"), self.backup.with_name(self.backup.name + ".new"), self.path.with_suffix(".tmp"), self.path.parent / "vault-migration.recovery"]
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


LONGEST_LINE = 65_536  # bytes of a line of the activity log that is read as an entry, at the most: qKVM writes a few hundred


def _no_number(name: str) -> Any:
    raise ValueError(f"{name} is no number")


def _finite(text: str) -> float:
    number = float(text)
    if not math.isfinite(number):  # (1e400: written as a number, read as none)
        raise ValueError(f"{text[:20]} is no number")
    return number


_DECODERS = threading.local()  # one reader of entries a thread, made once: json.loads with these hooks made one a line


def _decoder() -> json.JSONDecoder:
    decoder: json.JSONDecoder | None = getattr(_DECODERS, "decoder", None)
    if decoder is None:
        decoder = _DECODERS.decoder = json.JSONDecoder(parse_constant=_no_number, parse_float=_finite)
    return decoder


def entry_of(line: bytes) -> dict[str, Any] | None:
    """The entry one line of the activity log holds, or None where it holds none.

    An entry is what this program writes: a record of plain things, whose event is a text and whose time is a
    moment. A line that is something else (damaged, cut off, written by hand, longer than any entry) is no entry.
    Handed on, a list where the event belongs or a value nested a few hundred deep made the whole log an error for
    whoever opened it. Read here and nowhere else, by the index (activity.py) as by `tail`, so that the two agree.
    """
    if len(line) > LONGEST_LINE:
        return None
    try:
        # (NaN and Infinity are no numbers a reader of JSON takes, nor any qKVM writes: a line with one in it handed on
        # made the answer that held it fail.)
        entry = _decoder().decode(line.decode("utf-8", errors="replace"))
    except (ValueError, RecursionError):
        return None
    if not (isinstance(entry, dict) and isinstance(entry.get("event"), str) and _shallow(entry, 3)):
        return None
    at = entry.get("time")
    if not (isinstance(at, (int, float)) and not isinstance(at, bool) and 0 <= at < 1e11):
        return None
    if b"\\ud" in line.lower():
        # Half of a character named in an escape (a lone surrogate), which no text in UTF-8 can carry: handed on, the answer
        # that held it failed, and a download stopped there. (A pair of halves is one character, and is read as such.)
        try:
            json.dumps(entry, ensure_ascii=False).encode("utf-8")
        except UnicodeEncodeError:
            return None
    return entry


def read_only_uri(path: Path) -> str:
    """The URI that opens an existing SQLite file to be read (`mode=rw`: never made where there is none), for any path.

    A path on a share (\\\\server\\share\\...) is `file://server/share/...` to Python, and SQLite refuses a URI that names a
    host ("invalid uri authority"): every read of the history and of the activity log's index was refused there, and the
    activity log was read from its files for as long as qKVM ran. SQLite takes the share as a path with an empty host.
    """
    uri = path.resolve().as_uri()
    if uri.startswith("file://") and not uri.startswith("file:///"):
        uri = "file:////" + uri[len("file://") :]
    return f"{uri}?mode=rw"


def open_shared(path: Path) -> BinaryIO:
    """Open a file of the activity log to be read, without standing in the way of its writer.

    The writer moves its files on (the full one becomes the newest of the old ones) while they are read: by the index,
    by a read of the page, by a download. On Windows a file that is open cannot be moved or removed, unless whoever
    opened it said that it may be (FILE_SHARE_DELETE), which Python's own open does not say: a read in that moment
    made the writer write on into the full file, to move it another time. Elsewhere it never could stand in the way.
    """
    if sys.platform != "win32":
        return path.open("rb")
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    where = os.path.abspath(path)
    if len(where) >= 250 and not where.startswith("\\\\"):
        where = "\\\\?\\" + where  # (a long path, as Windows takes one)
    # GENERIC_READ; FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE; OPEN_EXISTING; FILE_ATTRIBUTE_NORMAL
    handle = kernel32.CreateFileW(where, 0x80000000, 0x7, None, 3, 0x80, None)
    if handle is None or handle == wintypes.HANDLE(-1).value:
        code = ctypes.get_last_error()
        raise OSError(None, ctypes.FormatError(code).strip(), str(path), code)  # (2 and 3 come out as FileNotFoundError)
    try:
        number = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except OSError:
        kernel32.CloseHandle(handle)
        raise
    return os.fdopen(number, "rb")


def lines_backwards(file: Any, end: int, block: int = 1 << 16) -> Iterator[bytes]:
    """The lines of an open file of the activity log up to byte `end`, the last first: what lies between two line
    feeds (b"\\n"), and before the first and after the last. Read from the end a block at a time, so that a long log
    is read only as far as it is wanted. A line whose beginning lies further back than LONGEST_LINE from where a block
    cuts it is handed on as b"", its bytes not kept while its beginning is looked for; one shorter than that and yet
    longer than LONGEST_LINE whole (entry_of takes neither for an entry). Memory: a block and LONGEST_LINE at the most."""
    at, pending, too_long = end, b"", False
    while at > 0:
        start = max(0, at - block)
        file.seek(start)
        data = file.read(at - start) + pending
        at = start
        if at > 0:
            first = data.find(b"\n")
            if first < 0:  # (all of it is the end of one line that began further back)
                too_long = too_long or len(data) > LONGEST_LINE
                pending = b"" if too_long else data
                continue
            pending, data = data[:first], data[first + 1 :]
        else:
            pending = b""
        lines = data.split(b"\n")
        if too_long:
            lines[-1], too_long = b"", False
        if at > 0:
            too_long = len(pending) > LONGEST_LINE
            if too_long:
                pending = b""
        yield from reversed(lines)


DEFAULT_ACTIVITY_MB, LEAST_ACTIVITY_MB, MOST_ACTIVITY_MB = 50, 10, 100_000


def activity_file_bytes(megabytes: Any) -> int:
    """Bytes each file of the activity log may grow to, for `activity_mb` as the settings file says it: held to what makes
    sense (nothing, 0, or less than that is the default; a text, a list or a fraction where a number belongs, too)."""
    wanted = megabytes if isinstance(megabytes, int) and not isinstance(megabytes, bool) else 0
    wanted = DEFAULT_ACTIVITY_MB if wanted <= 0 else min(MOST_ACTIVITY_MB, max(LEAST_ACTIVITY_MB, wanted))
    return wanted * 1_000_000 // (AuditLog.OLD_FILES + 1)


class AuditLog:
    """Append-only record of logins, changes and device actions (JSON lines).

    Entries are written by a thread of its own, in the order they were made: whoever makes one is in the
    middle of answering a request, on the one thread that serves everybody, and does not wait for a disk.
    These files are the record. What is sent on to a collector is a copy of each line as it is written, and the
    index the page searches (activity.py) is made from these files and from nothing else; neither is waited for.

    Kept: the file being written, and OLD_FILES before it, of max_bytes each (a tenth of `activity_mb`: 5 MB as it
    comes, which is some nine months of a busy wall; the README has the numbers). Enough that what somebody did cannot
    be pushed out of the log by doing something harmless a few thousand times afterwards.
    """

    OLD_FILES = 9

    def __init__(self, path: Path, max_bytes: int | None = None, forward: Callable[[str], None] | None = None) -> None:
        self.path = path
        self.max_bytes = activity_file_bytes(DEFAULT_ACTIVITY_MB) if max_bytes is None else max_bytes
        self.forward = forward  # given each entry once it is written, for sending on (it must not wait for anything)
        self.on_written: Callable[[], None] | None = None  # told that the file has more in it (it must not wait for anything)
        # How often the files were moved on, twice a time: one more as it begins and one more as it ends, odd in between. Whoever
        # looks at several of the files one after the other (the index's round, a reading of them) can tell by it that they were
        # moved on meanwhile, and that what it found at one name may be at the next by now.
        self.rotations = 0
        self._ends = False  # the writer's: the file being written was seen to end where a line ends (see _append)
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
                if self.on_written is not None:
                    self.on_written()
                if self.forward is not None:
                    self.forward(line)
            except Exception:  # whatever goes wrong with one entry, the ones after it are written
                pass
            finally:
                self._waiting.task_done()

    def _old(self, number: int) -> Path:
        return self.path.with_name(f"{self.path.name}.{number}")

    def files(self) -> list[Path]:
        """Where the log is, the newest first: the file being written, then the old ones, whether they are there or not."""
        return [self.path, *(self._old(number) for number in range(1, self.OLD_FILES + 1))]

    def _rotate(self) -> None:
        """The full file becomes the newest of the old ones, each of the others one older, and the oldest goes.

        From the first old one that is not there, if one is not: a step that failed (a file held open by something else
        just now, on Windows) left one out, and the next try moved the ones above it on all the same, so that a file
        went for every step that had failed. Now the files above a gap stay as they are, and nothing goes but the oldest.
        That one is removed first, and not replaced by the next: a file being read (opened to be shared, open_shared)
        can be removed and renamed on Windows, and not replaced.
        """
        self.rotations += 1  # (odd while the files are being moved on: see `rotations`)
        try:
            free = next((number for number in range(1, self.OLD_FILES + 1) if not self._old(number).exists()), None)
            if free is None:
                self._old(self.OLD_FILES).unlink()
                free = self.OLD_FILES
            for number in range(free, 0, -1):
                newer = self.path if number == 1 else self._old(number - 1)
                if newer.exists():
                    os.replace(newer, self._old(number))
        finally:
            self.rotations += 1
        self._ends = True  # (the next line begins a file of its own)

    def _ended(self) -> bool:
        """Whether the file being written ends where a line ends: it is empty, not there, or its last byte is a line feed."""
        try:
            with self.path.open("rb") as file:
                if file.seek(0, os.SEEK_END) == 0:
                    return True
                file.seek(-1, os.SEEK_END)
                return file.read(1) == b"\n"
        except OSError:
            return True  # (not there; or not to be read just now, and then whatever is written is written as it was)

    def _append(self, line: str) -> None:
        try:
            if self.path.stat().st_size > self.max_bytes:
                self._rotate()
        except OSError:
            pass  # not there yet, or held open by something else just now: written on, and moved aside another time
        told = bool(self._unsaid and self.missing is not None)
        # A line the last run did not end (it was cut off in the middle of a write) is ended first. Written on, the next entry
        # was part of that line, and read as one with it it was no entry: the first thing done after a restart was missing
        # from the log as it is read. Looked at once, at the first entry, and again after a write the disk refused (not at
        # every entry: a second opening of the file for each slowed the writer, and under load what was asked to be read a
        # moment later was not written yet). A line feed is added; nothing that is there is changed.
        mended = "" if self._ends or self._ended() else "\n"
        try:
            with self.path.open("a", encoding="utf-8") as fh:
                if mended:
                    fh.write(mended)
                if told and self.missing is not None:
                    # It can be written again. The hole is written into it first: what is known of it here
                    # is gone with the next restart, and the log would then read as if nothing were missing.
                    gap = {"time": time.time(), "event": "log_gap", "ip": "", "count": self._unsaid, "since": self._unsaid_since or self.missing["since"], "why": self.missing["why"]}
                    fh.write(json.dumps(gap) + "\n")
                fh.write(line)
            # (Only now is it on its way to the disk: a full one refuses at the end, when the file is closed.)
            self._ends = True
            if told:
                self._unsaid, self._unsaid_since = 0, None
        except OSError as ex:
            # A full disk must not take the wall down, nor keep anybody from pressing what has to be pressed.
            # But then things are done of which no record is kept, and that at least is said: in the program's
            # own log, and to whoever opens the activity log (see `missing`).
            now = time.time()
            why = ex.strerror or type(ex).__name__
            self._ends = False  # (a write the disk refused may have left part of a line: looked at before the next)
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
        found: list[dict[str, Any]] = []
        for entry in self.entries():
            if len(found) >= limit:
                break
            if wanted is None or wanted(entry):
                found.append(entry)
        return found

    def entries(self) -> Generator[dict[str, Any], None, None]:
        """Every entry of the files, the newest first, read from their ends as far as they are wanted (entry_of).

        The files as they are when this begins: all of them are opened at once (to be shared, open_shared), so that the
        writer moving them on meanwhile neither reads one of them twice nor leaves the oldest out. Of the file being written,
        only lines that have ended: its last one without its line feed is still being written (or was written so by hand, and
        the writer's next entry then runs into it), as the index takes it (activity.py).
        """
        opened: list[tuple[Path, BinaryIO]] = []
        try:
            # Where the files were moved on while they were being opened, one of them was opened under two names (the second
            # reviewer of W4c): opened again, a few times at the most. (A writer that moves them on at every look leaves it as
            # it is: what is read is then the files as they were opened, one of them perhaps twice, as before W4c.)
            for attempt in range(5):
                began = self.rotations
                for path in self.files():
                    try:
                        opened.append((path, open_shared(path)))
                    except OSError:
                        continue
                if (began % 2 == 0 and self.rotations == began) or attempt == 4:
                    break
                for _, file in opened:
                    file.close()
                opened = []
                time.sleep(0.01)
            for path, file in opened:
                try:
                    end = file.seek(0, os.SEEK_END)
                    lines = lines_backwards(file, end)
                    if path == self.path:
                        next(lines, None)  # (what follows its last line feed: nothing, or a line not yet ended)
                    for line in lines:
                        entry = entry_of(line)
                        if entry is not None:
                            yield entry
                except OSError:
                    continue  # (gone bad while it was read: what is after it is read all the same)
        finally:
            for _, file in opened:
                file.close()
