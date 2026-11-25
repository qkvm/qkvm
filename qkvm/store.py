"""The wall's saved state: an authenticated encrypted document, replaced atomically."""

from __future__ import annotations

import contextlib
import copy
import errno
import hashlib
import hmac
import ipaddress
import json
import logging
import math
import os
import queue
import re
import sqlite3
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

from . import chain
from ._folders import open_private, private
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
    # Virtual media of servers (0.3.0, A4): the folder on this computer whose ISO images can be mounted on a server, and the
    # wall's address as the servers' controllers reach it, to read them from ("": where it listens on the network).
    media_folder: str = ""
    media_address: str = ""


@dataclass
class AlertSettings:
    """When to tell someone that a KVM changed state. Where to: the destinations (DestinationRecord), and the browsers."""

    enabled: bool = False
    # The kinds of change told at all, to every destination and every browser (as in 0.3.2); a destination narrows them.
    offline: bool = True  # a KVM stopped answering
    no_signal: bool = True  # the computer behind it went dark
    problem: bool = True  # login rejected, certificate changed
    recovered: bool = True  # any of those is over
    link: str = ""  # the wall's address as people reach it: an alert points there, at the tile it is about
    paused_until: float = 0.0  # nothing is sent before this time (maintenance); what is still wrong then is told then
    # The wall's own key for Web Push (webpush.py: VAPID, RFC 8292), sealed by the vault for "alerts:push-key"; made the
    # first time an account opens its browser's alerts, and never handed out but for its public half. None: not made yet.
    push_key: dict[str, str] | None = None


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
    # Its screen watched (screens.py): an alert after so many minutes with no video signal, or with a screen that looks the
    # same; 0: not watched for that. (Read through screens.minutes: what is no whole number above 0 is off, a day the most.)
    no_signal_minutes: int = 0
    unchanged_minutes: int = 0
    # Which of its three views a PC with Intel AMT is in (AMT_VIEWS): "health" (no KVM session is ever opened), "stills" (a
    # still now and then for its tile, a session while its enlarged or live view is open), "live" (a session held while its
    # tile is shown as well). An admin's or an operator's to change, by its own route. Kept, unused, for every other kind.
    amt_view: str = "stills"
    # Where else the machine can be opened, by kind (open_in.KINDS: MeshCentral, RustDesk, Remote Desktop): plain links an
    # admin gives it, by its own route, shown to its operators. Read through open_in.kept, which leaves out what is not one.
    # (A record of 0.3.2 or before has none.)
    open_in: dict[str, str] = field(default_factory=dict)
    # Where it has shown several inputs (a KVM with a switch), the mark of the machine it showed them at (kvm.several_mark of its
    # address, kind, check, certificate, machine and identity: what its `target` is made of); "" none. Holds only while the tile is
    # at that machine, across restarts and locks: keys sent as for a KVM of one input are refused, and its input is asked, also
    # while its switch is not up (a wall started again took it for one of a single input: the review of HB, M1). Written when it
    # is first seen (DeviceManager._several), emptied by the change that points the tile at another machine
    # (DeviceManager._install). (A record of 0.3.2 has none.)
    several_inputs_at: str = ""


FINGERBOT_STRENGTHS = ("firm", "light")  # (what fingerbot_strength may be; anything else in a file is taken as the first)
AMT_VIEWS = ("stills", "health", "live")  # (what amt_view may be; a record without it, or with another word, is the first)
# The kinds of machine this version has a driver for (DeviceRecord.kind). A device of another kind, as a later version
# that adds one writes it, read after going back to this version, is kept as it is and left alone (core.UnknownKind).
KINDS = ("kvmd", "jetkvm", "redfish", "amt", "vnc", "proxmox")

# What a server's tile of 0.1.x kept as what the server is: the number its computer gives for itself (redfish.own_number).
_SERVER_BEFORE = re.compile(r"server:[0-9a-f]{32}")


# What a JetKVM's tile of 0.2.0 and before kept as what the JetKVM is: the number it gives for itself (jetkvm.own_number).
_JETKVM_BEFORE = re.compile(r"jetkvm:[0-9a-f]{32}")


def jetkvm_machine_from_before(kind: Any, ident: Any, machine: Any) -> Any:
    """The JetKVM a tile was added for, where it was written by a version whose JetKVM driver checked none (0.2.0 and before
    kept no machine for a JetKVM): the number it kept as what the JetKVM is (`ident`), unless it was kept beside its twin
    ("own:..."). That number is the JetKVM's from then on, so that an upgrade never trusts whatever answers first at its
    address (see jetkvm.JetKvmDevice._judge). Asked of every JetKVM's tile with none: since 0.2.1 the number is kept wherever
    it is read, and `ident` is emptied where it is read and is none, so a tile with none and a number in `ident` is from
    before. Anything else is handed back as it was."""
    if machine == "" and kind == "jetkvm" and isinstance(ident, str) and _JETKVM_BEFORE.fullmatch(ident):
        return ident
    return machine


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
class OidcSettings:
    """Signing in through an identity provider by OpenID Connect (oidc.py, 0.4.0). Off until an admin sets it up."""

    enabled: bool = False
    name: str = ""  # what the button on the sign-in page says after "Sign in with" ("": the provider's host)
    issuer: str = ""  # https://..., exactly as the provider says it of itself
    client_id: str = ""
    secret: dict[str, str] | None = None  # the client secret, sealed by the vault for "oidc:client"; never handed back
    scopes: str = "openid profile email"
    groups_claim: str = "groups"  # the claim of the ID token (or of userinfo) that carries a person's groups; "": none is read
    roles: dict[str, str] = field(default_factory=dict)  # a group's name, as the provider writes it -> the role it gives (ROLES)
    anyone: str = ""  # "": only somebody in a group of `roles` signs in; a role: anybody else the provider signs in, as that
    domain: str = ""  # "": any; an email domain everybody has to have, verified by the provider (Google, which sends no groups)
    private: bool = False  # the provider may be at a private address (egress.PRIVATE): an admin's switch, off by default
    # Where the provider sends a browser back to: this wall's own address as the admin saw it on the page, as they entered it
    # at the provider. A sign-in is begun only from that address (the browser's cookie of it is there).
    redirect_uri: str = ""


@dataclass
class BackupSettings:
    """Backups of the whole wall to a folder (backup.py, 0.4.0): off until an admin switches them on, which takes a key."""

    enabled: bool = False
    folder: str = ""  # where they are written: a whole path on the computer qKVM runs on (a mounted share, a synced folder)
    hour: int = 3  # the hour of the day they are made at, the wall's local time (0 to 23)
    keep: int = 7  # how many are kept: the oldest beyond that go, once a new one is written and read back whole
    history: bool = False  # the history (history.sqlite) as well: large, and not needed to bring the wall back
    # The backup key (32 random bytes, in hex), sealed by the vault for backup.SEALED_FOR: kept here so that a run made by the
    # clock seals a backup without anybody. Handed out once, as its recovery kit, when it is made; never again. None: none yet.
    secret: dict[str, str] | None = None
    key_id: str = ""  # what that key is known by (backup.key_id): in each backup's head and on its kit; no secret
    key_made: float = 0.0
    since: float = 0.0  # when they were switched on: the first run made by the clock is the first hour after that
    last_at: float = 0.0  # the last run, made by the clock or by somebody: when it ended
    last_ok: bool = True  # ...whether it made a backup (True where none ran yet: nothing has failed)
    last_name: str = ""  # ...the file it made
    last_size: int = 0
    last_error: str = ""  # ...or why it made none, in a sentence
    last_good: float = 0.0  # when the last backup that was made was made
    last_folder: str = ""  # ...and the folder it is in: the latest only of that folder (another, saved since, has none yet)
    # Backups of another key in the folder, as the last run found them (another wall's, or this wall's before its key was
    # made new): never touched by this wall, and said in Settings (of the folder the last backup is in).
    others: int = 0
    # The alert destinations told that a backup failed, and not yet that one was made again: told so once one is, a restart
    # between (an incident PagerDuty opened for the failure is closed by it).
    told: list[str] = field(default_factory=list)


@dataclass
class NetbirdSettings:
    """NetBird's management API, asked for the machines of a NetBird network where its client is not on this computer (qKVM
    in a container beside NetBird's own; tailnet.py, 0.4.0). Off until an admin sets it up."""

    url: str = ""  # https://api.netbird.io, or a self-hosted management's address (tailnet.management_url)
    secret: dict[str, str] | None = None  # the token, sealed by the vault for "netbird:token"; never handed back, never exported
    private: bool = False  # the management API may be at a private address (egress.PRIVATE): an admin's switch, off by default


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
    # An account of an identity provider's (oidc.py): the provider (its issuer) and its own word for the person (`sub`),
    # which together are who it is, whatever its name here. "" and "": an account of this wall's own. Such an account has
    # no password here and never gets one; the provider signs it in, and its role is read from its groups at each sign-in.
    issuer: str = ""
    subject: str = ""


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
class PushRecord:
    """A browser the alerts are told to by Web Push (webpush.py): a phone's, most of the time."""

    id: str
    user: str  # the account it is for: it is told what that account may see, and it goes when the account goes
    # Where its push service takes messages for it and its two keys (JSON: endpoint, p256dh, auth), sealed by the vault for
    # "push:" and its id: whoever has its address can send it nothing without the wall's key, and read nothing without its keys.
    secret: dict[str, str] | None = None
    name: str = ""  # what browser it is, as the page said when it subscribed: "Chrome on Android"
    service: str = ""  # its push service's name (fcm.googleapis.com, web.push.apple.com), in clear for the list
    created: float = 0.0


# What a destination may be told of (destinations.EVENTS, said in the guide), and how serious, from the least.
# "backup": a backup of the wall that was not made (backup.py), and no machine's: told where it is asked for, as the others.
ALERT_EVENTS = ("offline", "no_signal", "unchanged", "auth", "certificate", "fault", "problem", "backup", "recovered")
ALERT_LEVELS = ("info", "warning", "error", "critical")
# The id a 0.3.2 wall's one alert address is kept under as its first destination: its sealed address is opened for
# "alerts:webhook", as 0.3.2 sealed it (`sealed_for`). No id this program gives has letters past f.
FROM_0_3_2 = "webhook"


def sealed_for(destination_id: str) -> str:
    """What a destination's secrets are sealed for: its id, which no other record's sealed text is for."""
    return "alerts:webhook" if destination_id == FROM_0_3_2 else f"destination:{destination_id}"


@dataclass
class DestinationRecord:
    """A place the alerts go (destinations.py): a mail server, a chat, PagerDuty, a webhook."""

    id: str
    kind: str  # destinations.KINDS; one this version does not know (a later one's) is kept and sent nothing
    name: str = ""  # what the admin calls it
    enabled: bool = True
    # Its secrets (an address with a token in it, a key, a password), as JSON sealed by the vault for `sealed_for(id)`. The
    # one carried over from 0.3.2 holds its address as it was sealed then: the address alone, not in JSON.
    secret: dict[str, str] | None = None
    host: str = ""  # where it goes, in clear, for the list: the host only ("" for the one from 0.3.2 until it is saved again)
    config: dict[str, Any] = field(default_factory=dict)  # what is not secret: a mail's sender and recipients, a chat's id
    private: bool = False  # may be a private address (RFC 1918, fc00::/7, 100.64.0.0/10): an admin's switch, off by default
    minimal: bool = False  # told the machine's name, what happened and the link, and nothing else
    events: list[str] = field(default_factory=lambda: list(ALERT_EVENTS))  # what it is told of
    least: str = "info"  # ...from this severity on (ALERT_LEVELS)
    devices: list[str] | None = None  # ids of the machines it is told about; None: all of them, new ones too
    groups: list[str] = field(default_factory=list)  # and the machines of these groups, whichever are in them on the day
    quiet_from: int = -1  # its quiet hours, minutes of the day (the wall's local time); -1: none
    quiet_to: int = -1
    quiet_days: list[str] = field(default_factory=list)  # "mon".."sun"; none: every day
    remind: int = 0  # minutes after which what is still wrong is told again; 0: never
    created: float = 0.0
    # Told the activity log's head once a day (0.4.0, chain.py: kept there, it shows a later rewrite of the log), quietly; never
    # where it is PagerDuty, whose every event opens an incident.
    log_seal: bool = False


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
_NEVER_EMPTY = frozenset({("DeviceRecord", "username"), ("DeviceRecord", "tls"), ("DeviceRecord", "kind"), ("DestinationRecord", "events"), ("DestinationRecord", "least"), ("ServerSettings", "bind"), ("ServerSettings", "port"), ("ServerSettings", "interval")})  # fmt: skip
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
_OPENED_LATER = frozenset({"secret", "webhook", "totp", "cert_pem", "push_key"})


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


def position_of(said: Any) -> tuple[int, bytes] | None:
    """Where the activity log's chain had come to, as the settings keep it ({"n": ..., "head": 64 hex digits}): (number, head),
    or None where it is not that."""
    if not isinstance(said, dict) or set(said) != {"n", "head"}:
        return None
    number, head = said.get("n"), chain.hex_head(said.get("head"))
    if not isinstance(number, int) or isinstance(number, bool) or not 0 < number < 2**63 or head is None:
        return None
    return number, head


def _from_0_3_2(said: Any) -> list[DestinationRecord]:
    """The destination a 0.3.2 wall's alert address is from now on: its first, sent to as before. That wall kept one
    address (sealed, for "alerts:webhook") and how its service wanted to be spoken to; it is kept as it was sealed, so
    nothing needs the saved passwords open to carry it over, and it may be a private address, as every address could
    be then (a self-hosted ntfy on the network). This computer and link-local are refused all the same, as for any.
    None where there was no address."""
    if not isinstance(said, dict):
        return []
    blob = said.get("webhook")
    if blob is None:
        return []
    if not (isinstance(blob, dict) and blob):
        blob = {"damaged": str(blob)[:80]}  # (as _as_declared keeps what is no sealed text: it opens with no key)
    form = said.get("format") if said.get("format") in _FORMATS_OF_0_3_2 else "auto"
    kind = _FORMATS_OF_0_3_2[str(form)]
    return [DestinationRecord(FROM_0_3_2, kind, secret=blob, config={"format": form} if kind == "webhook" else {}, private=True)]


def _only_known(cls: type, data: dict[str, Any]) -> dict[str, Any]:
    known = {f.name for f in fields(cls)}
    return {key: value for key, value in data.items() if key in known}


VERSION = 1  # of the settings file as this program writes it
# The parts of the settings file this program knows of.
_PARTS = (
    "version", "recovery", "recovery_created", "unlock", "server", "alerts", "users", "devices", "actions", "tokens", "pushes", "destinations", "oidc",
    "activity_key", "activity_position", "backups", "netbird",
)  # fmt: skip
_ACTIVITY_KEY = re.compile(r"[0-9a-f]{64}")
# What 0.3.2 kept under "alerts" and 0.4.0 keeps as the first destination: carried over (Store._read), never carried along.
_ALERTS_OF_0_3_2 = ("webhook", "format")
_FORMATS_OF_0_3_2 = {"auto": "webhook", "json": "webhook", "ntfy": "ntfy", "slack": "slack", "discord": "discord"}


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
    for part, cls in (("users", UserRecord), ("devices", DeviceRecord), ("actions", ActionRecord), ("tokens", TokenRecord), ("pushes", PushRecord), ("destinations", DestinationRecord)):
        found = data.get(part)
        things: list[Any] = found if isinstance(found, list) else []
        by_id[part] = {str(thing["id"]): more for thing in things if isinstance(thing, dict) and "id" in thing and (more := _not_known(cls, thing))}
    return {
        "top": {key: value for key, value in data.items() if key not in _PARTS},
        "server": _not_known(ServerSettings, data.get("server")),
        "alerts": {key: value for key, value in _not_known(AlertSettings, data.get("alerts")).items() if key not in _ALERTS_OF_0_3_2},
        "oidc": _not_known(OidcSettings, data.get("oidc")),
        "backups": _not_known(BackupSettings, data.get("backups")),
        "netbird": _not_known(NetbirdSettings, data.get("netbird")),
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
        self._defaults()
        # With either of the two there, this is not a new wall. A start that was cut off between setting a damaged
        # file aside and writing the settings anew leaves only the second copy: taken for a first run, the wall
        # would be anybody's to set up, and the owner's settings would be written over at the second change.
        if path.exists() or self.backup.exists():
            self._load()
        if empty_left and not self.read_only:
            self._clear_empty(empty_left)
        elif self.carried_over and not self.read_only and not self.restored:
            self.save()  # (in the shape of this version from now on: a 0.3.2 wall's alert address as its first destination)

    @classmethod
    def of_document(cls, data: Any, path: Path) -> Store:
        """Settings as a wall reads them from its file (`_take`), from a document held in memory: nothing is read or written,
        and nothing can be. For a backup's settings (backup.py), checked whole before anything of them is restored, and read
        for what they hold. ValueError (or another error of reading, as `_load` counts them) where a wall would not load them."""
        store = cls.__new__(cls)
        store.path, store.backup, store.backup_is_old = path, path.with_suffix(".bak"), False
        store.read_only, store.protected, store.cipher, store.key_file = True, False, None, None
        store._defaults()
        if not isinstance(data, dict):
            raise ValueError("not a settings file")
        store._take(data)
        return store

    def _defaults(self) -> None:
        """What a wall holds before anything is read: nothing (see `_take` for what a file gives)."""
        self.server = ServerSettings()
        self.users: list[UserRecord] = []
        # Lets the recovery key unlock the vault, as a password would (vault.Vault.rewrap); None: no key was made.
        self.recovery: dict[str, Any] | None = None
        self.recovery_created = 0.0
        # Lets the secret in the unlock file open the vault at start, in the same way (see unlock.py); None: not in use.
        self.unlock: dict[str, Any] | None = None
        # The activity log's key (0.4.0, chain.py): what signs each line of it, in hex; "" where none is made yet (a wall of
        # 0.3.2: made at its first start of 0.4.0). Kept here, in the settings sealed with the vault key outside the data
        # folder, and never in the activity log: rewriting the log so that it checks takes the vault as well.
        self.activity_key = ""
        # ...and where its chain had come to, the line and head of its last seal ({"n": ..., "head": hex}), kept here at each of
        # them: the writer holds the files to it before its first line, so that a log edited while it was out of the wall's
        # hands (its chain taken away, its end cut off) is not taken in as it is found. None: nothing kept yet.
        self.activity_position: dict[str, Any] | None = None
        self.devices: list[DeviceRecord] = []
        self.actions: list[ActionRecord] = []
        self.tokens: list[TokenRecord] = []
        self.pushes: list[PushRecord] = []  # the browsers told the alerts by Web Push
        self.destinations: list[DestinationRecord] = []  # where the alerts go; the first is the one GET/PUT /api/v1/alerts speak of
        self.alerts = AlertSettings()
        self.oidc = OidcSettings()  # signing in through an identity provider (oidc.py): off until an admin sets it up
        self.backups = BackupSettings()  # backups of the whole wall to a folder (backup.py): off until an admin switches them on
        self.netbird = NetbirdSettings()  # NetBird's management API, for "Find KVMs" (tailnet.py): off until an admin sets it up
        self.recovered_from: Path | None = None  # set when the settings were read from the second copy: the damaged file, or None for one that was not there
        self.restored = False  # ...and this says that they were
        self.damage = ""  # ...and what was wrong with the file that was not used
        self._version = VERSION
        self._beyond = _beyond({})
        self._writing = threading.Lock()  # one write at a time: they all go through the same temporary file
        self.carried_over = False  # what an earlier version wrote was read in this version's shape: written so at the start
        # The alert address of 0.3.2 as it was sealed then, written in 0.3.2's place as well for as long as the first destination
        # is that address unchanged: a wall that goes back to 0.3.2 (an update that failed its trial, `qkvm --roll-back`)
        # still finds it there, and does not go on with alerts on and nowhere to send them. None: there is none to keep.
        self._for_0_3_2: dict[str, str] | None = None

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
        self._take(data)

    def _take(self, data: dict[str, Any]) -> None:
        """Settings, from what a settings file holds (`_read`), as this version keeps them; ValueError (and the like: see
        `_load`) where they cannot be used."""
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
        activity_key = data.get("activity_key", "")
        if activity_key != "" and not (isinstance(activity_key, str) and _ACTIVITY_KEY.fullmatch(activity_key)):
            # (Made anew instead, every line before it would read as written by somebody else: the settings are damaged.)
            raise ValueError("the activity log's key is not one this program makes")
        self.activity_key = activity_key
        position = data.get("activity_position")
        if position is not None and position_of(position) is None:
            raise ValueError("where the activity log's chain had come to is not said as this program says it")
        self.activity_position = position
        self.devices = [DeviceRecord(**_only_known(DeviceRecord, d)) for d in data.get("devices", [])]
        self.actions = [ActionRecord(**_only_known(ActionRecord, a)) for a in data.get("actions", [])]
        self.tokens = [TokenRecord(**_only_known(TokenRecord, t)) for t in data.get("tokens", [])]
        self.pushes = [PushRecord(**_only_known(PushRecord, p)) for p in data.get("pushes", [])]
        self.destinations = [DestinationRecord(**_only_known(DestinationRecord, d)) for d in data.get("destinations", [])]
        self.alerts = AlertSettings(**_only_known(AlertSettings, data.get("alerts", {})))
        self.oidc = OidcSettings(**_only_known(OidcSettings, data.get("oidc", {})))  # (a file of 0.3.2 has none: off)
        self.backups = BackupSettings(**_only_known(BackupSettings, data.get("backups", {})))  # (none before 0.4.0: off)
        _as_declared(self.server, "the settings under \"server\"")
        _as_declared(self.alerts, "the settings under \"alerts\"")
        _as_declared(self.oidc, "the settings under \"oidc\"")
        _as_declared(self.backups, "the settings under \"backups\"")
        self.netbird = NetbirdSettings(**_only_known(NetbirdSettings, data.get("netbird", {})))  # (a file of 0.3.2 has none: off)
        _as_declared(self.netbird, "the settings under \"netbird\"")
        # What a group gives is a role, and somebody let in by the provider who is in no such group is given one or none:
        # anything else written there by hand would be read at a sign-in as a role that is none.
        if not all(isinstance(group, str) and role in ROLES for group, role in self.oidc.roles.items()):
            raise ValueError(f"the settings under \"oidc\": every role in \"roles\" has to be one of {', '.join(ROLES)}")
        if self.oidc.anyone not in ("", *ROLES):
            raise ValueError(f"the settings under \"oidc\": \"anyone\" has to be empty or one of {', '.join(ROLES)}")
        said_alerts: dict[str, Any] = data["alerts"] if isinstance(data.get("alerts"), dict) else {}
        if "destinations" not in data:
            self.destinations = _from_0_3_2(said_alerts)
            self.carried_over = bool(self.destinations)
        old_place = said_alerts.get("webhook")
        first = self.destinations[0] if self.destinations else None
        if isinstance(old_place, dict) and old_place and first is not None and first.id == FROM_0_3_2 and first.secret == old_place:
            self._for_0_3_2 = copy.deepcopy(old_place)
        if not 1 <= self.server.port <= 65535:
            raise ValueError("the settings under \"server\": \"port\" has to be a number from 1 to 65535")
        # How often the wall looks is a number of seconds the form takes: from a fifth of one to a minute.
        # Written by hand as 0, every browser opened on "Paused"; as less than nothing, every browser asked
        # for pictures without a pause. Neither is a reason not to start: it is the nearest that makes sense.
        self.server.interval = min(60.0, max(0.2, float(self.server.interval)))
        records: list[Any] = [*self.users, *self.devices, *self.actions, *self.tokens, *self.pushes, *self.destinations]
        for number, record in enumerate(records):
            kind = {
                UserRecord: "account", DeviceRecord: "device", ActionRecord: "saved action", TokenRecord: "token", PushRecord: "browser told the alerts",
                DestinationRecord: "alert destination",
            }[type(record)]  # fmt: skip
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
                # search and an import keep it), and only a VNC server is: every other kind talks HTTP. A kind this
                # version does not know is at whatever address the version that added it keeps it (an address of its
                # own, spice:// say): read as no address, the wall did not start after going back to this version.
                schemes = ("http", "https", "vnc", "vncs") if record.kind == "vnc" else ("http", "https") if record.kind in KINDS else None
                try:
                    where = urlsplit(record.url)
                    usable = bool(where.hostname) and (schemes is None or where.scheme in schemes) and where.port != 0
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
            # (And a JetKVM's tile of 0.2.0 and before, which kept its JetKVM's number as what it is and checked none.)
            record.machine = jetkvm_machine_from_before(record.kind, record.ident, record.machine)

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
                with private(aside, "xb") as saved:
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
            "activity_key": self.activity_key,
            "activity_position": copy.deepcopy(self.activity_position),
            "devices": things("devices", self.devices),
            "actions": things("actions", self.actions),
            "tokens": things("tokens", self.tokens),
            "pushes": things("pushes", self.pushes),
            "destinations": things("destinations", self.destinations),
            "alerts": {**beyond["alerts"], **asdict(self.alerts), **self._place_of_0_3_2()},
            "oidc": {**beyond["oidc"], **asdict(self.oidc)},
            "backups": {**beyond["backups"], **asdict(self.backups)},
            "netbird": {**beyond["netbird"], **asdict(self.netbird)},
        }

    def _place_of_0_3_2(self) -> dict[str, Any]:
        """The alert address in the place 0.3.2 reads it from, with how its service is spoken to: while the first destination
        is the address carried over from 0.3.2, unchanged (see _for_0_3_2). Nothing once it was changed or removed."""
        first = self.destinations[0] if self.destinations else None
        if self._for_0_3_2 is None or first is None or first.id != FROM_0_3_2 or first.secret != self._for_0_3_2:
            return {}
        form = (first.config.get("format") if first.config.get("format") in ("auto", "json") else "json") if first.kind == "webhook" else first.kind
        return {"webhook": copy.deepcopy(self._for_0_3_2), "format": form if form in _FORMATS_OF_0_3_2 else "auto"}

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
            # Made anew, its owner's alone from its first moment (one left by a write that was cut off is not written into:
            # it may have been made before, as the folder gave it).
            tmp.unlink(missing_ok=True)
            if self.cipher is None:
                with private(tmp, "x", encoding="utf-8") as fh:
                    json.dump(data, fh, indent=2)
                    fh.flush()
                    os.fsync(fh.fileno())
            else:
                encoded = self.cipher.encode(data)
                with private(tmp, "xb") as fh:
                    fh.write(encoded)
                    fh.flush()
                    os.fsync(fh.fileno())
            _replace_settings(tmp, self.path)
            _settle(self.path.parent)
            again = self.backup.with_name(self.backup.name + ".new")
            try:
                # (Copied by this program and not by the system's copy, which gives a new file the folder's entries.)
                again.unlink(missing_ok=True)
                with private(again, "xb") as copied:
                    copied.write(self.path.read_bytes())
                    copied.flush()
                    # On the disk before it takes the place of the last copy: renamed first, a power cut could leave the
                    # name with its data never written (an empty or zero-filled qkvm.bak).
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
        old = [*self.kept_to_recover_from(), self.backup.with_name(self.backup.name + ".new"), self.path.with_suffix(".tmp")]
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

    def kept_to_recover_from(self) -> list[Path]:
        """What the folder keeps to recover the settings from: the damaged copies set aside, and the migration's archive.

        Removed by clear_out, where everything of the settings as they once were is meant to go (the accounts reset, the
        key switched off on purpose); never because a key did not fit (core.Core.unlock_at_start).
        """
        stem, suffix = self.path.stem, self.path.suffix
        return [*sorted(self.path.parent.glob(f"{stem}.damaged-*{suffix}")), self.path.parent / "vault-migration.recovery"]

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
    handle = private(path, "ab+")
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


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """An object of an entry, where a name comes once. Twice, a reader of JSON keeps the last, and whoever reads the line as
    text (grep, a collector) may read the first: such a line is no entry (the review of wave 2, L4; as oidc._unique)."""
    made = dict(pairs)
    if len(made) != len(pairs):
        raise ValueError("a name twice in one object")
    return made


def _decoder() -> json.JSONDecoder:
    decoder: json.JSONDecoder | None = getattr(_DECODERS, "decoder", None)
    if decoder is None:
        decoder = _DECODERS.decoder = json.JSONDecoder(parse_constant=_no_number, parse_float=_finite, object_pairs_hook=_unique)
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


class Gate:
    """What a store's own reads pass before they take hold of its database: shut while its writer brings the -wal file into
    the file (a checkpoint, TRUNCATE), for the history (history.py) and the activity log's index (activity.py) alike.

    SQLite's checkpoint waits for the place in the file's index that a read under way holds; a read that begins as that one
    ends can take the same place, and the next ones share it, so that reads that keep coming, one beginning before the other
    ends, keep it from getting through however short each is (the history's -wal file at four times its share on GitHub's
    runners, 0.3.1). With no read of the store's own beginning meanwhile, those under way end within their patience, and
    it gets through. A read waits at the gate only so long, and is then told to come back (the store says how); the gate
    is opened again whatever happens in the checkpoint.

    The reads let in are counted until they have let go of the file (`left`), and the writer waits for those (`emptied`)
    rather than SQLite: what SQLite then still waits for is held outside qKVM (a database browser, a monitoring script,
    Litestream, which keeps a read open by design), waits at no such gate, and cannot be waited out. The checkpoint is
    given a moment for it, and the gate opened again: shut for the whole of SQLite's wait, the wall's own reads were told to
    come back for most of every minute where such a read stayed open, and the file was held all the same (the
    independent review of 0.3.2, M1).
    """

    def __init__(self) -> None:
        self._turn = threading.Condition()
        self._shut = False
        self._in = 0  # reads let in that have not let go of the file yet

    @contextlib.contextmanager
    def shut(self) -> Iterator[None]:
        """Shut while what is in it runs (the writer's checkpoint), and opened again however that ends."""
        with self._turn:
            self._shut = True
        try:
            yield
        finally:
            with self._turn:
                self._shut = False
                self._turn.notify_all()

    def passed(self, until: float) -> bool:
        """Wait (a worker thread) until the gate is open, to the monotonic time `until` at the most. False where it is shut then.
        True: the read is let in, and counted as under way until it says `left`, once it has let go of the file (whatever
        came of it: a read that never says so is waited for by every checkpoint, to its patience)."""
        with self._turn:
            if not self._turn.wait_for(lambda: not self._shut, max(0.0, until - time.monotonic())):
                return False
            self._in += 1
            return True

    def left(self) -> None:
        """A read let in (`passed`) has let go of the file."""
        with self._turn:
            self._in -= 1
            if self._in <= 0:
                self._turn.notify_all()

    def emptied(self, within: float) -> bool:
        """Wait (the writer, with the gate shut) until the reads let in have all left, `within` seconds at the most. False
        where some are still under way then."""
        with self._turn:
            return self._turn.wait_for(lambda: self._in <= 0, within)


# Taken around every opening and closing of a database (sqlite_open, _Private.close): a database's -wal and -shm, which SQLite
# removes where the last connection to it closes, are made private again before the next opening, and never by SQLite.
_SQLITE_OPENING = threading.Lock()


class _Private(sqlite3.Connection):
    """A connection that is closed with _SQLITE_OPENING held (see there)."""

    def close(self) -> None:
        with _SQLITE_OPENING:
            super().close()


def _beside(path: Path) -> None:
    """On Windows, the -wal and -shm of a database that holds pages, made private where they are not there (SQLite takes
    them as it finds them: an empty -wal is a WAL with nothing in it, an empty -shm is made anew by the first connection).
    Not beside an empty database: SQLite removes a -wal it finds there, and makes its own (into_wal makes them after that).
    On POSIX SQLite makes them with its database's mode, which umask 077 makes 0600."""
    if sys.platform != "win32":
        return
    try:
        if path.stat().st_size == 0:
            return
    except OSError:
        return
    for tail in ("-wal", "-shm"):
        try:
            os.close(open_private(path.with_name(path.name + tail), os.O_RDWR | os.O_CREAT | os.O_EXCL))
        except FileExistsError:
            pass


def sqlite_open(path: Path, *, read: bool = False, **how: Any) -> sqlite3.Connection:
    """sqlite3.connect for a database in the data folder, where no file is made by SQLite itself (the round 4 review, M1:
    in a found open folder SQLite's files took the folder's entries, and what the wall saw of each machine was everybody's
    to read). The database is made private where there is none (open_private), its -wal and -shm beside it (_beside), and
    into_wal takes a new one to WAL without a rollback journal. `read`: opened to be read (read_only_uri: never made).
    """
    with _SQLITE_OPENING:
        if not read:
            try:
                os.close(open_private(path, os.O_RDWR | os.O_CREAT | os.O_EXCL))
            except FileExistsError:
                pass
        _beside(path)
        if read:
            return sqlite3.connect(read_only_uri(path), uri=True, factory=_Private, **how)
        conn = sqlite3.connect(path, factory=_Private, **how)
    try:
        if path.stat().st_size == 0:
            # A database just made: whatever is written first (auto_vacuum's page, the header into_wal writes) without a rollback
            # journal file (into_wal says why).
            conn.execute("PRAGMA journal_mode = MEMORY").fetchall()
    except BaseException:
        conn.close()
        raise
    return conn


def into_wal(conn: sqlite3.Connection, path: Path) -> None:
    """PRAGMA journal_mode = WAL, with no file made beside the database but its own -wal and -shm, private (sqlite_open).

    A database not in WAL yet (one just made) is taken there through MEMORY, which SQLite takes through OFF to WAL: the one
    write that says WAL in its header is made without a rollback journal, which SQLite would have made with the folder's
    entries. (Only that first write goes without one: a power cut in it leaves a database just made, which a start that
    finds it damaged makes anew.) Its -wal and -shm are made private after that write, before SQLite opens them at the next
    read: made before it, beside a database without a page, SQLite removes them and makes its own.
    """
    if str(conn.execute("PRAGMA journal_mode").fetchone()[0]).lower() != "wal":
        conn.execute("PRAGMA journal_mode = MEMORY").fetchall()
        conn.execute("PRAGMA journal_mode = WAL").fetchall()
    with _SQLITE_OPENING:
        _beside(path)


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


_BLOCK = 1 << 16  # bytes read at a time by the readers of the chain below


def _back_with_places(file: Any, end: int) -> Iterator[tuple[int, bytes]]:
    """The lines of an open file of the activity log up to byte `end`, the last first, each with where it begins: (place,
    line). As lines_backwards, a line longer than LONGEST_LINE is handed on as (-1, b"") and its bytes are not kept."""
    at, tail, long = end, b"", False  # (tail: the end of a line whose beginning lies further back, as far as it was read)
    while at > 0:
        start = max(0, at - _BLOCK)
        file.seek(start)
        data = file.read(at - start)
        at = start
        cut = data.rfind(b"\n")
        if cut < 0:
            if not long:
                tail = data + tail
                long = len(tail) > LONGEST_LINE
                tail = b"" if long else tail
            continue
        first = data[cut + 1 :]
        yield (-1, b"") if long or len(first) + len(tail) > LONGEST_LINE else (start + cut + 1, first + tail)
        end_of = cut
        while (cut := data.rfind(b"\n", 0, end_of)) >= 0:
            line = data[cut + 1 : end_of]
            yield (start + cut + 1, line) if len(line) <= LONGEST_LINE else (-1, b"")
            end_of = cut
        tail = data[:end_of]
        long = len(tail) > LONGEST_LINE
        tail = b"" if long else tail
    yield (-1, b"") if long else (0, tail)


def _forward(file: Any, start: int, end: int, newest: bool) -> Iterator[bytes]:
    """The lines of an open file of the activity log from byte `start` to `end`, the first first, as AuditLog.entries reads
    them: of the file being written (`newest`), not what follows its last line feed (a line still on its way); of an old one,
    that too (it will never end). A line longer than LONGEST_LINE is handed on as b"", its bytes not kept."""
    at, carry, long = start, b"", False
    while at < end:
        file.seek(at)
        data = file.read(min(_BLOCK, end - at))
        if not data:
            break
        at += len(data)
        parts = data.split(b"\n")
        for part in parts[:-1]:
            yield b"" if long or len(carry) + len(part) > LONGEST_LINE else carry + part
            carry, long = b"", False
        if not long:
            carry += parts[-1]
            long = len(carry) > LONGEST_LINE
            carry = b"" if long else carry
    if not newest and (carry or long):
        yield b"" if long else carry


def _signed(entry: dict[str, Any], found: chain.Link, key: bytes | None) -> bool:
    """Whether a chained line's signature checks with `key` (every line does where there is none to check it with)."""
    return key is None or hmac.compare_digest(chain.signature(key, chain.link(found.prev, found.number, chain.digest(entry))), found.mac)


def _last_chained(file: Any, end: int, key: bytes | None = None) -> tuple[int, dict[str, Any], chain.Link] | None:
    """The last line of an open file of the activity log that has its place in the chain, its signature checking with `key`:
    (where the line after it begins, its entry, its place). None where none has. (Read from the end: in a large file only as
    far as it is wanted.) A line with a chain whose signature does not check is passed over: it is no place of the wall's
    chain (made up, or changed: its number may be any, 2**63 - 1 say, and was taken for where the chain stands; the
    re-review of wave 2, N1)."""
    for place, line in _back_with_places(file, end):
        if place >= 0 and b'"chain"' in line:
            entry = entry_of(line)
            found = chain.Link.of(entry) if entry is not None else None
            if entry is not None and found is not None and found.number and _signed(entry, found, key):
                return min(place + len(line) + 1, end), entry, found
    return None


def _time_of(line: str) -> float | None:
    """The time a line given to the writer says, for a seal the writer writes before it (the genesis, a seal of lines without
    the chain, a seal of pruning): such a seal says the moment of the line it comes with, not of when the writer got to it (a
    look at a long log takes seconds, and the lines given meanwhile were then older than the seal written before them)."""
    entry = entry_of(line.encode("utf-8"))
    return float(entry["time"]) if entry is not None else None


def _head_of(entry: dict[str, Any], found: chain.Link) -> tuple[int, bytes]:
    """(number, head) after a chained line, as it stands."""
    return found.number, chain.link(found.prev, found.number, chain.digest(entry))


@dataclass
class Sealing:
    """A seal asked of the activity log's writer (AuditLog.seal): written in its turn, and then `done`, with `head` the place
    of the seal in the chain, (number, head), where it was written."""

    why: str
    detail: dict[str, Any]
    done: threading.Event = field(default_factory=threading.Event)
    head: tuple[int, bytes] | None = None
    at: float = field(default_factory=time.time)  # when it was asked for: its time, as an entry's is when it is given


SEAL_EVERY = 3600.0  # seconds after a seal after which one is written again, where anything was written since


class CheckHalted(Exception):
    """A check of the activity log was stopped before its end (the wall stopping)."""


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
    comes, which is some nine months of a busy wall; the guide has the numbers). Enough that what somebody did cannot
    be pushed out of the log by doing something harmless a few thousand times afterwards.

    Given a `key` (the wall's, kept in its sealed settings), each line is chained and signed as it is written (chain.py),
    by the writer alone and in its order: its number, the head before it and its signature are added at its end. Before
    its first line the writer reads where the chain stands in the files (`_begin`), and seals what it finds without the
    chain there; before the oldest file goes, it writes what goes and the head the rest goes on from; and it writes a seal
    of its own every SEAL_EVERY where anything was written since, and where it is asked (`seal`: at the wall's start and
    end, and for the daily seal of the alerts). Without a key, lines are written as before 0.4.0.
    """

    OLD_FILES = 9

    def __init__(
        self,
        path: Path,
        max_bytes: int | None = None,
        forward: Callable[[str], None] | None = None,
        key: bytes | None = None,
        held: Callable[[], tuple[int, bytes] | None] | None = None,
    ) -> None:
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
        self._waiting: queue.Queue[str | Sealing | None] = queue.Queue()  # (None: the writer ends there, see close)
        self._writer: threading.Thread | None = None
        self._starting = threading.Lock()
        self.key = key
        # The writer's: where the chain stands, (number, head) of the last line of it in the file; None until it has looked
        # (`_begin`), and again where a write may have been cut short (it looks again before the next).
        self._chain: tuple[int, bytes] | None = None
        self.head: tuple[int, bytes] | None = None  # the same, as last written, for whoever checks the log while it runs
        self._chain_off = False  # the writer's: the chain failed for a slip of this program's own; this run writes without it
        self._sealed_at = time.monotonic()  # the writer's: when it last wrote a seal of its own (SEAL_EVERY)
        self._since_seal = False  # ...and whether anything was written since
        self._let_go: str | None = None  # the writer's: the oldest file (its mark) a seal of pruning was written for
        # Where the chain had come to as the wall keeps it outside the data folder (the line and head of its last seal, in the
        # sealed settings): the files are held to it before the writer's first line (`_begin`). None: nothing is kept.
        self.held = held
        # Told the place of each seal once it is written (why, number, head), to keep it where `held` reads it. Called in the
        # writer's thread: it must not wait for anything.
        self.on_sealed: Callable[[str, int, bytes], None] | None = None

    def write(self, event: str, ip: str, **detail: Any) -> None:
        if chain.FIELD in detail:
            detail["chain_"] = detail.pop(chain.FIELD)  # (the chain's own field is the writer's alone)
        line = json.dumps({"time": time.time(), "event": event, "ip": ip, **detail}) + "\n"
        self._give(line)

    def _give(self, item: str | Sealing) -> None:
        with self._starting:  # (with the writer's end, see close: an entry is never left behind a writer that has ended)
            self._waiting.put(item)
            if self._writer is None:
                self._writer = threading.Thread(target=self._write_on, name="activity-log", daemon=True)
                self._writer.start()

    def seal(self, why: str, **detail: Any) -> Sealing | None:
        """A seal written in its turn, after what was given before it (None where the log has no key: no chain). Never waits."""
        if self.key is None:
            return None
        sealing = Sealing(why, detail)
        self._give(sealing)
        return sealing

    def sealed(self, why: str, within: float = 10.0, **detail: Any) -> tuple[int, bytes] | None:
        """A seal, waited for (in a worker thread): its place in the chain, (number, head), or None where none was written."""
        sealing = self.seal(why, **detail)
        if sealing is None or not sealing.done.wait(within):
            return None
        return sealing.head

    def close(self, within: float = 5.0) -> None:
        """What was given is written, and the writer's thread ends: waited for `within` seconds at the most (a disk that
        does not answer does not hold whoever closes it). An entry given after this starts one again, as the first did.

        For a wall that ends (its listeners closed, and opened anew where the network settings changed): one ended in a
        test went on waiting for an entry that never came, a thread for every wall, some 1,400 in one run of the tests."""
        with self._starting:
            writer = self._writer
            if writer is None:
                return
            self._waiting.put(None)  # (after what was given before it)
        writer.join(within)

    def _write_on(self) -> None:
        self._chain = None  # (a writer of its own reads where the chain stands before its first line: see _begin)
        while True:
            try:
                item = self._waiting.get(timeout=self._seal_due())
            except queue.Empty:
                self._seal_every()
                continue
            if item is None:
                with self._starting:
                    self._waiting.task_done()
                    if self._waiting.empty():
                        self._writer = None
                        return
                continue  # (given after the close and before its end was come to: written by this one, in its turn)
            try:
                self._put(item)
            except Exception:  # whatever goes wrong with one entry, the ones after it are written
                pass
            finally:
                if isinstance(item, Sealing):
                    item.done.set()
                self._waiting.task_done()
            due = self._seal_due()
            if due is not None and time.monotonic() - self._sealed_at >= SEAL_EVERY:
                self._seal_every()  # (a wall that writes all the time is sealed as often: it never waits that long)

    def _put(self, item: str | Sealing) -> None:
        """One entry given, or a seal asked for: written, told, sent on."""
        if isinstance(item, Sealing):
            sealing: Sealing | None = item
            detail = dict(item.detail)
            if item.why == "start" and self.key is not None:
                detail.setdefault("key", chain.key_id(self.key))  # (which key the run signs with: a check given another says so)
            line = self._seal_line(item.why, at=item.at, **detail)
        else:
            sealing, line = None, item
        written = self._append(line, sealing)
        if self.on_written is not None:
            self.on_written()
        if self.forward is not None:
            for each in written:
                self.forward(each)

    def _seal_due(self) -> float | None:
        """Seconds the writer waits for an entry before it writes a seal of its own (None: for ever, without the chain)."""
        if self.key is None or self._chain_off:
            return None
        return max(0.05, SEAL_EVERY - (time.monotonic() - self._sealed_at))

    def _seal_every(self) -> None:
        """A seal of the writer's own, every SEAL_EVERY where anything was written since the last. (Its time is counted from
        the try: one the disk refuses is tried again in SEAL_EVERY, not at once and again.)"""
        self._sealed_at = time.monotonic()
        if not self._since_seal:
            return
        try:
            self._put(Sealing("hourly", {}))
        except Exception:
            pass

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

    def _append(self, line: str, sealing: Sealing | None = None) -> list[str]:
        """Write one line, and what has to come before it. Returns what was written, to be sent on (the line as it was given,
        where it could not be written).

        Where the chain fails for a slip of this program's own, the line is written all the same, without it, and so is
        every line after it until qKVM starts again: the record comes first. (The next start seals what it finds without
        the chain, and the check says so.)"""
        chained = self.key is not None and not self._chain_off
        try:
            return self._write_line(line, sealing, chained)
        except OSError as ex:
            self._refused(ex)
            return [line]
        except Exception:
            if not chained:
                raise
            log.exception("the activity log's chain failed: its lines are written without it until qKVM starts again")
            self._chain_off, self._chain = True, None
        try:
            return self._write_line(line, sealing, chained=False)
        except OSError as ex:
            self._refused(ex)
            return [line]

    def _write_line(self, line: str, sealing: Sealing | None, chained: bool) -> list[str]:
        written: list[str] = []
        if chained and self._chain is None:
            begun = self._begin(_time_of(line))
            if begun:
                written += self._written(begun, chained=True, sync=True)
        try:
            full = self.path.stat().st_size > self.max_bytes
        except OSError:
            full = False  # not there yet, or held open by something else just now: written on, and moved aside another time
        if full:
            # The seal of what goes is written before anything goes. Where the disk refuses it, the line is refused with it, as any
            # write: counted, said before the next line, and that one begins where a line ends. (Written on regardless, the line
            # went in without the chain, the writer's place being unknown then, and onto what the refused seal left of a line:
            # the review of wave 2, L3.) Where the oldest file cannot be read just now, nothing goes this time (None).
            sealed = self._seal_pruning(_time_of(line)) if chained else []
            if sealed is not None:
                written += sealed
                try:
                    self._rotate()
                except OSError:
                    pass  # (held open by something else just now: moved aside another time)
        told = bool(self._unsaid and self.missing is not None)
        # A line the last run did not end (it was cut off in the middle of a write) is ended first. Written on, the next entry
        # was part of that line, and read as one with it it was no entry: the first thing done after a restart was missing
        # from the log as it is read. Looked at once, at the first entry, and again after a write the disk refused (not at
        # every entry: a second opening of the file for each slowed the writer, and under load what was asked to be read a
        # moment later was not written yet). A line feed is added; nothing that is there is changed.
        mended = "" if self._ends or self._ended() else "\n"
        lines = []
        if told and self.missing is not None:
            # It can be written again. The hole is written into it first: what is known of it here
            # is gone with the next restart, and the log would then read as if nothing were missing.
            gap = {"time": time.time(), "event": "log_gap", "ip": "", "count": self._unsaid, "since": self._unsaid_since or self.missing["since"], "why": self.missing["why"]}
            lines.append(json.dumps(gap) + "\n")
        lines.append(line)
        written += self._written(lines, chained=chained, mended=mended, sync=sealing is not None)
        if told:
            self._unsaid, self._unsaid_since = 0, None
        if sealing is not None and chained:
            sealing.head = self._chain
        return written

    def _written(self, lines: list[str], *, chained: bool, mended: str = "", sync: bool = False) -> list[str]:
        """Lines written, in one go, each stamped with its place in the chain where `chained` (a line that is no entry, as
        entry_of reads it, is written as it is: nothing reads it as one). `sync`: on the disk before this returns (a seal,
        whose head goes outward). The writer's place in the chain moves on only once they are on their way: where the disk
        refuses, it is read again from the files before the next line (`_append`)."""
        out: list[str] = []
        place = self._chain if chained else None
        sealed_last: bool | None = None
        seals: list[tuple[str, int, bytes]] = []
        for line in lines:
            entry = entry_of(line.encode("utf-8")) if place is not None else None
            if place is None or entry is None or self.key is None:
                out.append(line)
                continue
            stamped, head = chain.stamp(line, entry, place[0] + 1, place[1], self.key)
            place = (place[0] + 1, head)
            out.append(stamped)
            sealed_last = entry.get("event") == chain.SEALED
            if sealed_last:
                seals.append((str(entry.get("why")), *place))
        try:
            with private(self.path, "a", encoding="utf-8") as fh:
                if mended:
                    fh.write(mended)
                fh.write("".join(out))
                if sync:
                    fh.flush()
                    os.fsync(fh.fileno())
            # (Only now is it on its way to the disk: a full one refuses at the end, when the file is closed.)
        except OSError:
            self._chain = None  # (part of it may be there: where the chain stands is read again before the next line)
            raise
        self._ends = True
        if place is not None:
            self._chain = self.head = place
        if sealed_last is not None:
            self._since_seal = not sealed_last
            if sealed_last:
                self._sealed_at = time.monotonic()
        told = self.on_sealed
        for why, number, head in seals:
            try:
                if told is not None:
                    told(why, number, head)
            except Exception:  # (keeping it is somebody else's; the log goes on)
                log.exception("where the activity log's chain had come to could not be handed on to be kept")
        return out

    def _refused(self, ex: OSError) -> None:
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

    def _opened(self) -> list[tuple[Path, BinaryIO]]:
        """The files there are, the newest first, opened at once to be read (open_shared). One that cannot be opened is passed
        over, as a reading of the log passes it over (entries)."""
        opened: list[tuple[Path, BinaryIO]] = []
        for path in self.files():
            try:
                opened.append((path, open_shared(path)))
            except OSError:
                continue
        return opened

    def _seal_line(self, why: str, at: float | None = None, **detail: Any) -> str:
        """A seal as a line: its time `at` (when it was asked for, or that of the line it is written before), else now."""
        return json.dumps({"time": time.time() if at is None else at, "event": chain.SEALED, "ip": "", "why": why, **detail}) + "\n"

    def _begin(self, at: float | None = None) -> list[str]:
        """(The writer's, before its first line.) Where the chain stands in the files: its last line, read from the end. Lines
        without the chain after it (an earlier version ran in between, or somebody put them in) are taken in as they are and
        sealed ("unchained": how many; their head is in the seal's link). Where no line has the chain (the first start of
        0.4.0, or a new log), every line there is is taken in, from the oldest file's first, and sealed ("genesis": how many,
        and the head after each file, so that the oldest can go as the log lets it go). Returns that seal, to be written
        first; nothing where the chain goes on from its last line.

        The file being written is ended first where it does not end with a line feed (as `_append` ends it): a line a power
        cut left without its end is read as what it will be once it is ended, and its number is never given twice."""
        if not self._ends and not self._ended():
            with private(self.path, "a", encoding="utf-8") as fh:
                fh.write("\n")
        self._ends = True
        assert self.key is not None
        # Where the chain had come to: as this writer last wrote it, else as the wall keeps it in its sealed settings.
        held = self.head if self.head is not None else (self.held() if self.held is not None else None)
        opened = self._opened()
        try:
            for index, (path, file) in enumerate(opened):
                end = file.seek(0, os.SEEK_END)
                found = _last_chained(file, end, self.key)
                if found is None:
                    continue
                after, entry, place = found
                number, head = _head_of(entry, place)
                rest = [(file, after, path == self.path)] + [(newer, 0, name == self.path) for name, newer in reversed(opened[:index])]
                lines = list(self._entries_of(rest))
                wrong = [] if held is None else self._held_to(opened[index:], number, head, held, self.key)
                made_up = sum(chain.FIELD in one for one in lines)
                if made_up:
                    wrong.append(f"{made_up} {'line' if made_up == 1 else 'lines'} after line {number} carry a chain the wall did not sign (made up, or changed)")
                stopped = entry.get("event") == chain.SEALED and entry.get("why") == "stop"
                seals = sum(one.get("event") == chain.SEALED for one in lines)
                if lines and not stopped:
                    wrong.append(f"{len(lines)} lines without the chain after line {number}, where the wall did not stop")
                elif seals:
                    wrong.append(f"{seals} of the {len(lines)} lines without the chain after line {number} are seals of the chain with their chain taken away")
                if not lines and not wrong:
                    self._chain = self.head = (number, head)
                    return []
                after_them, head = chain.virtual(head, number + 1, (chain.digest(one) for one in lines))
                self._chain = (after_them - 1, head)
                if wrong:
                    return [self._broken(at, len(lines), wrong, held)]
                return [self._seal_line("unchained", at=at, count=len(lines), key=chain.key_id(self.key))]
            number, head, cuts, seals, made_up = 1, chain.ZERO, [], 0, 0
            for path, file in reversed(opened):
                before = number
                for entry in self._entries_of([(file, 0, path == self.path)]):
                    head = chain.link(head, number, chain.digest(entry))
                    number += 1
                    seals += entry.get("event") == chain.SEALED
                    made_up += chain.FIELD in entry
                if number > before:
                    cuts.append([number - 1, head.hex()])
            self._chain = (number - 1, head)
            wrong = []
            if made_up:
                wrong.append(f"{made_up} of the lines found carry a chain the wall did not sign (made up, or changed)")
            if held is not None:
                wrong.append(f"no line of the log has the chain, and the wall had written it up to line {held[0]}: its chain was taken away, or the log replaced")
            if seals:
                wrong.append(f"{seals} of the lines found are seals of the chain with their chain taken away")
            if wrong:
                return [self._broken(at, number - 1, wrong, held)]
            return [self._seal_line("genesis", at=at, before=number - 1, files=cuts, key=chain.key_id(self.key))]
        finally:
            for _, file in opened:
                file.close()

    def _broken(self, at: float | None, count: int, wrong: list[str], held: tuple[int, bytes] | None) -> str:
        """The seal of what the writer found wrong before its first line (a problem in every check), with the lines without the
        chain it takes in so that what comes after it is checked as before."""
        assert self.key is not None
        log.error("the activity log is not as the wall left it: %s", "; ".join(wrong))
        kept = {"held": [held[0], held[1].hex()]} if held is not None else {}
        return self._seal_line("broken", at=at, count=count, said="; ".join(wrong)[:1000], key=chain.key_id(self.key), **kept)

    @staticmethod
    def _held_to(opened: list[tuple[Path, BinaryIO]], number: int, head: bytes, held: tuple[int, bytes], key: bytes | None = None) -> list[str]:
        """What is wrong with the files where the chain had come to `held` (number, head), their last chained line being
        `number` with `head`: nothing, where that line is there as it was written. `opened`: the file of that last line, and the
        older ones, the newest first."""
        wanted, kept = held
        if number < wanted:
            return [f"the chain ends at line {number}, and the wall had written it up to line {wanted}: lines were cut off its end, or their chain taken away"]
        if number == wanted:
            return [] if head == kept else [f"line {wanted} is not the line the wall wrote there: it was changed, or the log written anew from there on"]
        for _, file in opened:
            for place, line in _back_with_places(file, file.seek(0, os.SEEK_END)):
                if place < 0 or b'"chain"' not in line or (entry := entry_of(line)) is None or (found := chain.Link.of(entry)) is None or not found.number:
                    continue
                if not _signed(entry, found, key):  # (a line the wall did not sign is not its line, whatever its number)
                    continue
                if found.number == wanted:
                    if _head_of(entry, found)[1] == kept:
                        return []
                    return [f"line {wanted} is not the line the wall wrote there: it was changed, or the log written anew from there on"]
                if found.number < wanted:
                    return [f"line {wanted}, which the wall wrote, is not in the log"]
        return [f"line {wanted}, which the wall wrote, is not in the log"]

    @staticmethod
    def _entries_of(parts: list[tuple[BinaryIO, int, bool]]) -> Iterator[dict[str, Any]]:
        """The entries of open files from a place in each, the first first: (file, from, whether it is the file being written)."""
        for file, start, newest in parts:
            end = file.seek(0, os.SEEK_END)
            for line in _forward(file, start, end, newest):
                entry = entry_of(line) if line else None
                if entry is not None:
                    yield entry

    def _seal_pruning(self, at: float | None = None) -> list[str] | None:
        """(The writer's, before the files move on.) Where the oldest file is about to go (every old one is there: see
        _rotate), a seal of what goes, written into the full file before it: the last line it holds and the head after it
        ("to", "head"), or, of a file from before the chain, how many lines it holds ("let_go"), which the genesis seal says
        the head after. Written once a file (a rotation whose last step failed is tried again at the next line). None where
        the oldest file cannot be read just now: nothing is to go this time. OSError where the disk refuses the seal."""
        if any(not self._old(number).exists() for number in range(1, self.OLD_FILES + 1)):
            return []
        oldest = self._old(self.OLD_FILES)
        try:
            found = self._what_goes(oldest)
        except OSError:
            return None
        if found is None:
            return []
        mark, detail = found
        written = self._written([self._seal_line("pruned", at=at, **detail)], chained=True, sync=True)
        self._let_go = mark
        return written

    def _what_goes(self, oldest: Path) -> tuple[str, dict[str, Any]] | None:
        """What the seal of the oldest file says, with the file's mark; None where one was written for it already."""
        with open_shared(oldest) as file:
            end = file.seek(0, os.SEEK_END)
            file.seek(0)
            mark = f"{end}:{hashlib.sha256(file.read(4096)).hexdigest()}"
            if mark == self._let_go:
                return None
            found = _last_chained(file, end, self.key)
            if found is not None:
                after, entry, place = found
                number, head = _head_of(entry, place)
                digests = [chain.digest(one) for one in self._entries_of([(file, after, False)])]
                if digests:
                    after_them, head = chain.virtual(head, number + 1, digests)
                    number = after_them - 1
                detail: dict[str, Any] = {"file": oldest.name, "to": number, "head": head.hex()}
            else:
                detail = {"file": oldest.name, "let_go": sum(1 for _ in self._entries_of([(file, 0, False)])), "to": None, "head": None}
        return mark, detail

    def oldest_first(self) -> Generator[dict[str, Any], None, None]:
        """Every entry of the files, the oldest first, as `entries` reads them (the files as they are when this begins, all
        opened at once, again where the writer moved them on meanwhile; of the file being written only lines that have
        ended): what a check of the chain reads."""
        opened: list[tuple[Path, BinaryIO]] = []
        for attempt in range(5):
            began = self.rotations
            opened = self._opened()
            if (began % 2 == 0 and self.rotations == began) or attempt == 4:
                break
            for _, file in opened:
                file.close()
            time.sleep(0.01)
        try:
            for path, file in reversed(opened):
                try:
                    yield from self._entries_of([(file, 0, path == self.path)])
                except OSError:
                    continue  # (gone bad while it was read: what is after it is read all the same)
        finally:
            for _, file in opened:
                file.close()

    def check(self, walk: chain.Walk, halt: threading.Event | None = None) -> chain.Verdict:
        """Check the chain of the files as they are (in a worker thread: it reads them all), as the whole log: against the
        wall's own head as well, as its writer last wrote it, and the place its sealed settings keep (`held`), whatever order
        the lines are in (the outside review of 0.4.0, M3: after a start over a log cut back and turned round, the check said
        lines out of their order and nothing of where the wall had come to). `walk` is made by whoever asks (its key, the heads
        kept outside), and may be looked at while this runs (how far it is: walk.verdict.entries). CheckHalted where `halt`
        is set meanwhile."""
        self.flush()
        if walk.own is None and self.head is not None:
            walk.own = self.head
        if walk.kept is None and self.held is not None:
            walk.kept = self.held()
        reading = self.oldest_first()
        try:
            for count, entry in enumerate(reading):
                if halt is not None and count % 1000 == 0 and halt.is_set():
                    raise CheckHalted("the check of the activity log was stopped: qKVM is stopping")
                walk.take(entry)
        finally:
            reading.close()
        return walk.end()

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
