"""A wall's devices and settings as a file: to keep, or to take to another wall. And reading one back.

One format, written two ways:

* With a passphrase, as a `.qkvm` file: everything that was asked for, the devices' passwords, the texts
  of saved actions and the address alerts go to included, encrypted. The passphrase locks a key that is
  made for this one file, the way an account's password locks the wall's own key (see vault.py), and
  that key seals the content. Nothing new is invented for it.
* Without one, as a `.json` file: the same with every secret left out, in plain text that can be read,
  compared and kept anywhere.

Accounts, tokens, two-factor keys and the recovery key are in neither. Each of them is locked to the key
of the wall it was made on, and could be carried to another only by carrying that key, which is every
secret of the first wall. A whole wall, accounts and all, is a copy of its data folder (see the guide, GUIDE.md).

What is read back is somebody's file and not this program's own. Every entry is checked as if it had
been typed into the page; what does not pass is left out, and said. Nothing in a file can make a wall do
more than add devices and saved actions, and set what an admin could have set in the page. What a tile
is known by is not taken at a file's word either: a mark this program makes itself (a certificate's, or
that of "keep both") is worked out anew on the wall that takes the file in (see server.new_to_this_wall).
"""

from __future__ import annotations

import json
import ssl
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization

from . import alerts, destinations, egress, oidc, open_in, screens
from .amt import at_its_port
from .kvm import KEYS, MAX_TEXT, POWER_KEY_REFUSED, names_the_power_key
from .store import AMT_VIEWS, FINGERBOT_STRENGTHS, ROLES, DestinationRecord, Store, as_a_line, device_url, jetkvm_machine_from_before, machine_from_before, sealed_for
from .store import KINDS as STORE_KINDS
from .vault import Vault, VaultLocked
from .proxmox import address_of as proxmox_address
from .proxmox import guest_url
from .vncdevice import is_vnc, vnc_url

FORMAT = "qkvm-export"
VERSION = 1  # of the file: a later version of this program reads every earlier one
MAX_FILE = 4_000_000  # characters of what a file holds, written out plain: the most that is read, and so the most that is written
# A sealed file is that (written without its blanks), encrypted, and the result written as text, which
# is a third more; and its lock. One number for both let a wall write a sealed file that it would not read.
MAX_SEALED = MAX_FILE * 4 // 3 + 4096
TOO_MUCH = "This wall holds more than a file of qKVM's can. Nothing was written."
MOST_DEVICES = 2000
MOST_ACTIONS = 500
MIN_PASSPHRASE = 10  # as for an account's password
SEALED_FOR = f"export {VERSION}"  # what the content is sealed for: it is not a device's password, and opens as nothing else
KINDS = STORE_KINDS  # (an entry of another kind is refused: a later version's file is not for this one)
TLS = ("pinned", "system", "insecure")
PARTS = ("devices", "actions", "alerts", "wall", "signin")
# What a device says it is (server.IDENT), as a driver gives it. Not the marks this program makes itself:
# "own:..." is somebody's decision on the wall it was made on (carried as `keep_both`), "cert:..." is worked
# out of the certificate.
_IDENT = re.compile(r"(?!own:|cert:)[a-z]{2,12}:[0-9a-f]{16,64}")
_MOST_CERTIFICATE = 20_000  # characters of one remembered certificate


class ExchangeError(Exception):
    """The file cannot be read, or not with what was given. `code` is for the page, `message` for a person."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code, self.message = code, message


@dataclass(frozen=True)
class Device:
    name: str
    url: str
    username: str
    password: str = field(repr=False)
    kind: str
    group: str
    tls: str
    cert_pem: str | None
    open_url: str
    alerts: bool
    ident: str
    keep_both: bool = False  # on the wall it comes from, somebody said it is to have a tile of its own though another tile is the same device
    machine: str = ""  # the machine its tile was added for, by the number it gives for itself (store.DeviceRecord.machine)
    fingerbot_strength: str = "firm"  # how hard a Fingerbot paired with it presses: "firm" | "light"
    no_signal_minutes: int = 0  # its screen watched (screens.py): minutes with no signal before an alert; 0: not watched
    unchanged_minutes: int = 0  # ...and minutes with a screen that looks the same
    amt_view: str = "stills"  # a PC with Intel AMT: which of its three views its tile is in (store.AMT_VIEWS)
    open_in: dict[str, str] = field(default_factory=dict)  # where else it is opened (open_in.py), each checked; 0.4.0


@dataclass(frozen=True)
class Action:
    name: str
    kind: str  # "keys" | "text"
    keys: str
    text: str = field(repr=False)
    enter: bool
    danger: bool


@dataclass
class Content:
    """What a file holds, as far as it passed. Each part is None where the file has no such part."""

    devices: list[Device] | None = None
    actions: list[Action] | None = None
    # As store.AlertSettings without what is a wall's own (its link, a pause), and "destinations": each as checked
    # (destinations.check and settle), its secrets in clear; None where the file has none (a plain file).
    alerts: dict[str, Any] | None = None
    wall: dict[str, Any] | None = None  # "interval", "update_check"
    # Signing in through an identity provider (0.4.0), as store.OidcSettings without what is a wall's own (the address the
    # provider sends a browser back to), each field as checked (`_signin`); its client secret in clear where the file has
    # one (an encrypted file).
    signin: dict[str, Any] | None = None
    left_out: list[str] = field(default_factory=list)  # entries that did not pass, each in a sentence
    sealed: bool = False  # it was encrypted
    made: float = 0.0
    program: str = ""  # the version that wrote it

    @property
    def secrets(self) -> bool:
        """Whether it holds anything that is kept encrypted on a wall."""
        return (
            any(device.password for device in self.devices or [])
            or any(action.text for action in self.actions or [])
            or bool((self.alerts or {}).get("destinations"))
            or bool((self.signin or {}).get("client_secret"))
        )


def console_link(text: str) -> str:
    """Where "Open console" goes, as it may be saved; "" for none. ValueError for what is no such address."""
    text = text.strip()
    if not text:
        return ""
    parts = urlsplit(text)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError("the console link must start with http:// or https://")
    if parts.username is not None or parts.password is not None:
        # The link is handed to every account that may look at the tile.
        raise ValueError("the console link must not have a user name or password in it")
    # Its host as a device's address is written (device_url): small letters, no dot at the end, numbers one way, and none
    # that the system reads as another host than it looks like. The page and the server each say whether the link is on a
    # name this wall is looked at under (a browser would hand that page the sign-in to the wall), and read 2130706433, 127.1
    # or a dot at the end otherwise; from one written so, both read the same host (I2 of 0.2.1). What follows is as typed.
    netloc = parts.netloc
    if not netloc.isascii():
        try:
            host = (parts.hostname or "").encode("idna").decode("ascii")
        except UnicodeError:
            raise ValueError("the console link's host is not a host name") from None
        netloc = host if parts.port is None else f"{host}:{parts.port}"
    try:
        where = urlsplit(device_url(f"{parts.scheme}://{netloc}"))
    except ValueError:
        raise ValueError("the console link's host is not one a browser and qKVM would read alike") from None
    return urlunsplit((parts.scheme, where.netloc, parts.path, parts.query, parts.fragment))


# --- writing ----------------------------------------------------------------------------------------------------


def gather(store: Store, vault: Vault, what: set[str], secrets: bool, not_opened: list[str] | None = None) -> dict[str, Any]:
    """The parts of a wall named in `what`, as plain data. `secrets`: with what is kept encrypted, in clear.

    Raises VaultLocked where secrets are asked for and cannot be opened just now. `not_opened` is given
    the name of everything whose saved secret does not open and is therefore not in what comes back: a
    file that is kept for the passwords in it has to say which of them it is without.
    """

    def opened(blob: dict[str, str] | None, context: str, whose: str, known: bool = True) -> str:
        if not secrets or not blob:
            return ""
        if not known:
            # A tile of a kind this version does not know (a later version's settings, a file written by hand): no device it
            # talks to, and refused on the way in (KINDS). Its password is not opened for a file, and is said to be left out.
            if not_opened is not None:
                not_opened.append(whose)
            return ""
        # (None: sealed under a key from before a reset, or not what this program writes. As good as not
        # saved, here as for the wall itself: see Vault.read.)
        text = vault.read(blob, context)
        if text is None and not_opened is not None:
            not_opened.append(whose)
        return text or ""

    if secrets and not vault.unlocked:
        raise VaultLocked("the vault is locked")
    parts: dict[str, Any] = {}
    if "devices" in what:
        parts["devices"] = [
            {
                "name": device.name,
                "url": device.url,
                "username": device.username,
                **({"password": opened(device.secret, device.id, device.name or device.url, device.kind in KINDS)} if secrets else {}),
                "kind": device.kind,
                "group": device.group,
                "tls": device.tls,
                "cert_pem": device.cert_pem,
                "open_url": device.open_url,
                "alerts": device.alerts,
                "fingerbot_strength": device.fingerbot_strength if device.fingerbot_strength in FINGERBOT_STRENGTHS else FINGERBOT_STRENGTHS[0],
                "no_signal_minutes": screens.minutes(device.no_signal_minutes),
                "unchanged_minutes": screens.minutes(device.unchanged_minutes),
                # (A PC with Intel AMT's alone: a file without it is of 0.2.x or before, whose PCs are taken in as stills.)
                **({"amt_view": device.amt_view if device.amt_view in AMT_VIEWS else AMT_VIEWS[0]} if device.kind == "amt" else {}),
                "ident": device.ident if _IDENT.fullmatch(device.ident) else "",
                **({"keep_both": True} if device.ident.startswith("own:") else {}),
                # (Apart from `ident`, which a tile kept beside its twin does not carry: it is checked before anything is sent.)
                # (Written also where none is known, "": a file without the field is one of 0.1.x, whose server's number is
                # taken from what it kept as the server's, see store.machine_from_before.)
                "machine": device.machine if _IDENT.fullmatch(device.machine) else "",
                # (0.4.0. Only where it has any: a file of a wall without them is as before. Each as it is shown, checked again.)
                **({"open_in": links} if (links := open_in.kept(device.open_in)) else {}),
            }
            for device in store.devices
        ]
    if "actions" in what:
        # A saved text without its text is nothing to keep: in a plain file those are not there at all.
        parts["actions"] = [
            {
                "name": action.name,
                "kind": action.kind,
                "keys": action.keys,
                **({"text": opened(action.secret, f"action:{action.id}", action.name)} if action.kind == "text" else {}),
                "enter": action.enter,
                "danger": action.danger,
            }
            for action in store.actions
            if action.kind == "keys" or secrets
        ]
    if "alerts" in what:
        told = store.alerts
        parts["alerts"] = {
            "enabled": told.enabled,
            "offline": told.offline,
            "no_signal": told.no_signal,
            "problem": told.problem,
            "recovered": told.recovered,
            # (Not the link an alert carries: that is the address of the wall it comes from, and no setting to take along.)
        }
        if secrets:
            # Where the alerts go: only in an encrypted file. Each with its secrets in clear (an address with a token in it, a
            # key, a password); the machines it is told about by their addresses, which the wall that takes it knows them by.
            urls = {device.id: device.url for device in store.devices}
            listed = []
            for one in store.destinations:
                called = f"the alert destination {one.name or destinations.KIND_NAMES.get(one.kind, one.kind)}"
                text = opened(one.secret, sealed_for(one.id), called, one.kind in destinations.KINDS)
                if not text:
                    continue
                kept = opened_secrets(text)
                if kept is None:
                    if not_opened is not None:
                        not_opened.append(called)
                    continue
                listed.append({
                    "kind": one.kind, "name": one.name, "enabled": one.enabled, "private": one.private, "minimal": one.minimal,
                    "events": list(one.events), "least": one.least,
                    "devices": None if one.devices is None else [urls[device] for device in one.devices if device in urls],
                    "groups": list(one.groups), "quiet_from": one.quiet_from, "quiet_to": one.quiet_to, "quiet_days": list(one.quiet_days),
                    "remind": one.remind, "config": dict(one.config), "secrets": kept,
                })  # fmt: skip
            parts["alerts"]["destinations"] = listed
    if "wall" in what:
        parts["wall"] = {"interval": store.server.interval, "update_check": store.server.update_check}
    if "signin" in what and store.oidc.issuer:  # (a wall that never set one up has nothing to say: taken in, it would say "none")
        signin = store.oidc
        parts["signin"] = {
            "enabled": signin.enabled, "name": signin.name, "issuer": signin.issuer, "client_id": signin.client_id, "scopes": signin.scopes,
            "groups_claim": signin.groups_claim, "roles": [{"group": group, "role": role} for group, role in signin.roles.items()],
            "anyone": signin.anyone, "domain": signin.domain, "private": signin.private,
            # (Not the redirect address: it is the address of the wall the file comes from. And the client secret only in an
            # encrypted file, as every secret.)
            **({"client_secret": opened(signin.secret, oidc.SEALED_FOR, "the identity provider's client secret")} if secrets and signin.secret else {}),
        }  # fmt: skip
    return parts


def pack(parts: dict[str, Any], passphrase: str, program: str) -> str:
    """The text of a file that holds `parts`: sealed with `passphrase`, or plain where that is empty.

    Slow where it seals (the passphrase is put through the same work as a password): not for the event loop.
    """
    whole = {"format": FORMAT, "version": VERSION, "made": round(time.time()), "program": program, **parts}
    # Nothing is written that would not be read back: a file that turns out to be too large on the day it
    # is needed, or to have lost its last devices, is worse than none. ExchangeError "too_large".
    for part, most, what in (("devices", MOST_DEVICES, "devices"), ("actions", MOST_ACTIONS, "saved actions")):
        if len(parts.get(part) or ()) > most:
            raise ExchangeError("too_large", f"This wall has {len(parts[part])} {what}, and a file of qKVM's holds {most}. Nothing was written: leave that part out, or have fewer.")
    inside = json.dumps(whole, indent=2) + "\n" if not passphrase else json.dumps(whole, separators=(",", ":"))
    if len(inside) > MAX_FILE:
        raise ExchangeError("too_large", TOO_MUCH)
    if not passphrase:
        return inside
    file_key = Vault()
    lock = file_key.create(passphrase)  # a key of this file's own, and what lets the passphrase open it
    sealed = file_key.encrypt(inside, SEALED_FOR)
    return json.dumps({"format": FORMAT, "version": VERSION, "lock": lock, "sealed": sealed}, indent=2) + "\n"


# --- reading ----------------------------------------------------------------------------------------------------


def _parsed(text: str) -> dict[str, Any]:
    if len(text) > MAX_SEALED:
        raise ExchangeError("too_large", "The file is larger than anything qKVM writes")
    try:
        said = _whole(json.loads(text))
    except (ValueError, RecursionError):
        raise ExchangeError("not_a_file", "This is not a file that qKVM made") from None
    if not isinstance(said, dict) or said.get("format") != FORMAT:
        raise ExchangeError("not_a_file", "This is not a file that qKVM made")
    if "sealed" not in said and len(text) > MAX_FILE:
        raise ExchangeError("too_large", "The file is larger than anything qKVM writes")
    version = said.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise ExchangeError("not_a_file", "This is not a file that qKVM made")
    if version > VERSION:
        raise ExchangeError("newer", "This file was made by a later version of qKVM than this one. Update this one first.")
    return said


def _whole(said: Any) -> Any:
    """`said` as it is; ValueError where it holds half a character.

    A file can spell one out (a "\\ud800" by itself), and reading it gives text that cannot be written
    anywhere again: saved, it was a wall whose list of devices no browser could be sent any more.
    """
    json.dumps(said, ensure_ascii=False).encode("utf-8")
    return said


def is_sealed(text: str) -> bool:
    """Whether the file needs a passphrase to be read. ExchangeError where it is no file of this kind at all."""
    return "sealed" in _parsed(text)


def unpack(text: str, passphrase: str) -> Content:
    """What the file holds. Slow for a sealed one (see `pack`): not for the event loop.

    ExchangeError with the code "passphrase_needed", "wrong_passphrase", "damaged", "newer", "too_large" or "not_a_file".
    """
    said = _parsed(text)
    sealed = "sealed" in said
    if sealed:
        if not passphrase:
            raise ExchangeError("passphrase_needed", "This file is encrypted. Enter the passphrase it was made with.")
        lock = said.get("lock")
        key = Vault.open(lock, passphrase) if isinstance(lock, dict) else None  # (bounded in its cost, whatever the file says: vault._derive)
        if key is None:
            raise ExchangeError("wrong_passphrase", "That is not the passphrase this file was made with")
        file_key = Vault()
        file_key.adopt(key)
        try:
            inside = file_key.decrypt(said["sealed"], SEALED_FOR)
            if len(inside) > MAX_FILE:
                raise ExchangeError("too_large", "The file is larger than anything qKVM writes")
            said = _whole(json.loads(inside))
        except (InvalidTag, KeyError, TypeError, ValueError, RecursionError):
            raise ExchangeError("damaged", "The file is damaged: what is in it does not open with its own key") from None
        if not isinstance(said, dict):
            raise ExchangeError("damaged", "The file is damaged: what is in it is not what qKVM writes")
    made = said.get("made")
    content = Content(
        sealed=sealed,
        made=float(made) if isinstance(made, (int, float)) and not isinstance(made, bool) and 0 <= made < 1e11 else 0.0,
        program=_short(said.get("program"), 20) or "",
    )
    if "devices" in said:
        content.devices = _devices(said["devices"], content.left_out)
    if "actions" in said:
        content.actions = _actions(said["actions"], content.left_out)
    if "alerts" in said:
        content.alerts = _alerts(said["alerts"], content.left_out)
    if "wall" in said:
        content.wall = _wall(said["wall"], content.left_out)
    if "signin" in said:
        content.signin = _signin(said["signin"], content.left_out)
    return content


def _short(value: Any, most: int) -> str | None:
    """`value` as a line of text of at most `most` characters, with the blanks around it gone. None: it is not one."""
    if not isinstance(value, str):
        return None
    # (The rule the form has for a name: what a wall holds, it reads back. The blanks around it go first, a
    # line break at its end among them, which a list of names written by a script has after every one.)
    line = as_a_line(value.strip())
    if line is None or len(line.strip()) > most:
        return None
    return line.strip()


def _flag(value: Any, default: bool) -> bool:
    return value if isinstance(value, bool) else default


def _watch_minutes(value: Any) -> int:
    """The minutes of one of its screen watches (screens.py), as the form takes them: a whole number from 0 (not watched) to
    a day; left out or null: not watched. ValueError for anything else, as the form refuses it."""
    if value is None:
        return 0
    if type(value) is not int or not 0 <= value <= screens.MOST_MINUTES:
        raise ValueError("how long its screen is watched for is not said in a way this version knows")
    return value


MOST_ODD = 256  # different certificates of one file that are tried the slow way (see _Odd)


class _Odd:
    """Where a certificate is tried that the quick reader refuses, and how many of one file still may be.

    A device's own certificate is whatever its maker's software wrote. The wall remembers one without
    reading it, and uses it with OpenSSL (kvm.pinned_context), which takes some that the quick reader,
    going by the book, does not: a device the wall had talked to for months was "not a certificate" to its
    own export. So what the quick reader refuses is asked of OpenSSL. That costs half a millisecond each
    on the thread there is one of, and a file may hold two thousand: so many different ones of a file are
    asked, and the rest are none. (One that many devices share, as a maker's on every board of a rack is,
    is asked once.)
    """

    def __init__(self) -> None:
        self._asked: dict[str, bool] = {}
        self._context: ssl.SSLContext | None = None

    def takes(self, written: str) -> bool:
        known = self._asked.get(written)
        if known is not None:
            return known
        if len(self._asked) >= MOST_ODD:
            return False
        if self._context is None:
            self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # (nothing is ever connected to with it)
        try:
            self._context.load_verify_locations(cadata=written)
            taken = True
        except (ssl.SSLError, ValueError):
            taken = False
        self._asked[written] = taken
        return taken


def _one_piece(der: bytes) -> bool:
    """Whether `der` is one sequence, as a certificate is, that says of itself that it is as long as it is,
    with every length in it written the one way a length is written."""
    return len(der) >= 4 and der[0] == 0x30 and _parts(der, 0) == 1


def _parts(der: bytes, depth: int) -> int | None:
    """How many values lie in `der`, one after the other and nothing left over; None where that is not so, or
    where a length, of one of them or of anything inside one, is written in more bytes than it takes.

    A length has one spelling (in as few bytes as it takes). Written in more, the quick reader refuses the
    certificate, OpenSSL reads it, and what would be kept is not what the device presents: a fingerprint
    nobody shows, and no twin of the tile that has the same device under another address. Asked of the
    outermost length alone, the length of the signature written the long way went through.
    """
    if depth > 24:
        return None
    at, parts = 0, 0
    while at < len(der):
        if at + 2 > len(der) or der[at] & 0x1F == 0x1F:  # (a tag of more than one byte: nothing in a certificate has one)
            return None
        constructed, first = bool(der[at] & 0x20), der[at + 1]
        at += 2
        if first < 0x80:
            length = first
        else:
            count = first & 0x7F
            if not 1 <= count <= 4 or at + count > len(der):
                return None
            length = int.from_bytes(der[at : at + count], "big")
            if der[at] == 0 or length < 0x80:
                return None
            at += count
        if at + length > len(der):
            return None
        if constructed and _parts(der[at : at + length], depth + 1) is None:
            return None
        at += length
        parts += 1
    return parts


def _certificate(value: Any, odd: _Odd) -> str | None:
    """The certificate as this program keeps one. ValueError for what is none."""
    if value is None or value == "":
        return None
    if not isinstance(value, str) or len(value) > _MOST_CERTIFICATE:
        raise ValueError("its certificate is not one")
    try:
        return x509.load_pem_x509_certificate(value.encode("ascii")).public_bytes(serialization.Encoding.PEM).decode("ascii")
    except (ValueError, TypeError):  # (UnicodeEncodeError is a ValueError)
        pass
    try:
        der = ssl.PEM_cert_to_DER_cert(value.strip())
        written = ssl.DER_cert_to_PEM_cert(der)
    except (ValueError, TypeError) as ex:  # (what is no base64 is a ValueError)
        raise ValueError("its certificate is not one") from ex
    # One certificate and nothing after it. OpenSSL reads the one at the front and passes over the rest;
    # kept with the rest, what the wall showed as its fingerprint was that of something no device presents.
    if not _one_piece(der) or not odd.takes(written):
        raise ValueError("its certificate is not one")
    return written


def _devices(said: Any, left_out: list[str]) -> list[Device]:
    odd = _Odd()
    if not isinstance(said, list):
        left_out.append("The list of devices is not a list")
        return []
    if len(said) > MOST_DEVICES:
        left_out.append(f"More than {MOST_DEVICES} devices: the ones after that")
        said = said[:MOST_DEVICES]
    found: dict[str, Device] = {}
    for number, entry in enumerate(said, 1):
        try:
            if not isinstance(entry, dict):
                raise ValueError("not an entry")
            address = entry.get("url")
            if not isinstance(address, str) or len(address) > 255 or "://" not in address:
                raise ValueError("it has no address")
            if entry.get("kind") == "proxmox":
                # (A guest's address goes on past the host: the guest, by its node and number, which it must name.)
                where = proxmox_address(address)
                if where.node is None or where.vmid is None:
                    raise ValueError("it does not name a guest of Proxmox")
                url = guest_url(where.origin, where.node, where.vmid)
            else:
                url = vnc_url(address) if is_vnc(address) else device_url(address)  # (a VNC server's address says so by itself)
                if entry.get("kind") == "amt" and urlsplit(address.strip()).port is None:
                    # Written without a port, an engine is at its own (16993 with TLS, 16992 plain), as an add or an edit
                    # takes it: at 443 or 80 no engine answers, and its redirection port would not be known.
                    url = device_url(at_its_port(url))
            name = _short(entry.get("name", ""), 80)
            username = _short(entry.get("username", "admin"), 64)
            group = _short(entry.get("group", ""), 200)
            password = entry.get("password", "")
            kind, tls = entry.get("kind"), entry.get("tls", "pinned")
            if name is None or username is None or group is None:
                raise ValueError("its name, user name or group is not a short line of text")
            if not isinstance(password, str) or len(password) > 256:
                raise ValueError("its password is not one")
            if kind not in KINDS or (kind == "vnc") != is_vnc(address):
                raise ValueError("it is not a kind of device this version knows")
            if tls not in TLS:
                raise ValueError("how its certificate is checked is not said in a way this version knows")
            group = " ".join(group.split())
            if len(group) > 40:
                raise ValueError("its group's name is too long")
            link = entry.get("open_url", "")
            if not isinstance(link, str) or len(link) > 255:
                raise ValueError("its console link is not one")
            strength = entry.get("fingerbot_strength")
            strength = FINGERBOT_STRENGTHS[0] if strength is None else strength  # (null: not said, as the form has it)
            if strength not in FINGERBOT_STRENGTHS:
                raise ValueError("how hard its Fingerbot presses is not said in a way this version knows")
            watches = {name: _watch_minutes(entry.get(name)) for name in ("no_signal_minutes", "unchanged_minutes")}
            view = entry.get("amt_view")
            view = AMT_VIEWS[0] if view is None else view  # (not said: a file of 0.2.x or before, as a record without it)
            if view not in AMT_VIEWS:
                raise ValueError("the view of its tile is not said in a way this version knows")
            ident, machine = entry.get("ident", ""), entry.get("machine", "")
            if not (isinstance(machine, str) and (machine == "" or _IDENT.fullmatch(machine))):
                # (What its tile checks before anything is sent to the machine: one that is no such number is not "none",
                # which would have the tile take whatever answers first.)
                raise ValueError("the number its machine gave for itself is not one")
            if "machine" not in entry:
                # (A server's, from a file of 0.1.x, which kept it as what the server is: taken as its machine, as at an upgrade.)
                machine = machine_from_before(kind, ident, machine)
            # (And a JetKVM's, from a file of 0.2.0 or before, which kept none for a JetKVM: its number, as at an upgrade.)
            machine = jetkvm_machine_from_before(kind, ident, machine)
            links = _links(entry.get("open_in"))
            device = Device(
                name=name or urlsplit(url).netloc[:80],  # (no longer than a name may be, as the form names one that is added without a name)
                url=url,
                username=username or "admin",
                password=password,
                kind=kind,
                group=group,
                tls=tls if url.startswith(("https://", "vncs://")) else "pinned",
                cert_pem=_certificate(entry.get("cert_pem"), odd) if url.startswith(("https://", "vncs://")) and tls == "pinned" else None,
                open_url=console_link(link),
                alerts=_flag(entry.get("alerts"), True),
                ident=ident if isinstance(ident, str) and _IDENT.fullmatch(ident) else "",
                keep_both=entry.get("keep_both") is True,
                machine=machine,
                fingerbot_strength=strength,
                **watches,
                amt_view=view if kind == "amt" else AMT_VIEWS[0],
                open_in=links,
            )
        except ValueError as ex:
            left_out.append(f"Device {number}: {ex}")
            continue
        if device.url in found:
            left_out.append(f"Device {number} ({device.name}): the file has that address twice")
            continue
        found[device.url] = device
    return list(found.values())


def _links(said: Any) -> dict[str, str]:
    """A machine's "Open in" links as a file holds them (0.4.0; none in a file of a version before): each checked as the
    page's form checks it (open_in.checked). ValueError, in words, where one is not a link, or not of a kind this version
    knows: the machine is left out, as for anything else of it that is not what it says."""
    if said is None:
        return {}
    if not isinstance(said, dict) or not set(said) <= set(open_in.KINDS):
        raise ValueError("its Open in links are not said in a way this version knows")
    links = {}
    for kind in open_in.KINDS:
        try:
            link = open_in.checked(kind, said.get(kind, ""))
        except ValueError as ex:
            raise ValueError(f"its Open in links: {ex}") from None
        if link:
            links[kind] = link
    return links


def _actions(said: Any, left_out: list[str]) -> list[Action]:
    if not isinstance(said, list):
        left_out.append("The list of saved actions is not a list")
        return []
    if len(said) > MOST_ACTIONS:
        left_out.append(f"More than {MOST_ACTIONS} saved actions: the ones after that")
        said = said[:MOST_ACTIONS]
    found = []
    for number, entry in enumerate(said, 1):
        try:
            if not isinstance(entry, dict):
                raise ValueError("not an entry")
            name, kind = _short(entry.get("name"), 60), entry.get("kind")
            keys, text = entry.get("keys", ""), entry.get("text", "")
            if not name:
                raise ValueError("it has no name")
            if kind == "keys":
                if not isinstance(keys, str) or not KEYS.fullmatch(keys):
                    raise ValueError("its keys are not keys this version knows")
                if names_the_power_key(keys):
                    raise ValueError(POWER_KEY_REFUSED[0].lower() + POWER_KEY_REFUSED[1:])
                text = ""
            elif kind == "text":
                if not isinstance(text, str) or not text or len(text) > MAX_TEXT:
                    raise ValueError("it has no text to type, or more than can be typed at once")
                keys = ""
            else:
                raise ValueError("it is not a kind of action this version knows")
            found.append(Action(name, kind, keys, text, _flag(entry.get("enter"), False) and kind == "text", _flag(entry.get("danger"), False)))
        except ValueError as ex:
            left_out.append(f"Saved action {number}: {ex}")
    return found


URL_KINDS = ("webhook", "ntfy", "slack", "discord")  # the kinds 0.3.2's one address could be: what its "format" speaks of


def format_of(one: dict[str, Any]) -> str:
    """The "format" of 0.3.2 a destination (its "kind" and "config") is: how its service is spoken to. A kind 0.3.2 did not
    have is said by its own name."""
    if one.get("kind") == "webhook":
        return "auto" if (one.get("config") or {}).get("format") == "auto" else "json"
    return str(one.get("kind"))


def opened_secrets(text: str) -> dict[str, str] | None:
    """A destination's secrets as they open from the vault: JSON, or the bare address of the one carried over from 0.3.2."""
    if not text.startswith("{"):
        return {"url": text}
    try:
        said = json.loads(text)
    except (ValueError, RecursionError):
        return None
    if not isinstance(said, dict) or not all(isinstance(value, str) for value in said.values()):
        return None
    return said


def destination_record(one: dict[str, Any], made_id: str, where: dict[str, str], vault: Vault) -> DestinationRecord:
    """A destination of a file, as this wall keeps it: its secrets sealed, its machines by this wall's ids (by their
    addresses: one this wall does not have is left out)."""
    record = DestinationRecord(
        made_id, one["kind"], name=one["name"], enabled=one["enabled"], host=one["host"], config=dict(one["config"]), private=one["private"],
        minimal=one["minimal"], events=list(one["events"]), least=one["least"], groups=list(one["groups"]), quiet_from=one["quiet_from"],
        quiet_to=one["quiet_to"], quiet_days=list(one["quiet_days"]), remind=one["remind"], created=time.time(),
    )  # fmt: skip
    record.devices = None if one["devices"] is None else [where[url] for url in one["devices"] if url in where]
    record.secret = vault.encrypt(json.dumps(one["secrets"]), sealed_for(made_id))
    return record


MOST_DESTINATIONS = 50  # destinations taken from one file


def _destination(entry: Any) -> dict[str, Any]:
    """A destination as a file of 0.4.0 or later writes it, checked as a form's is. ValueError with what is wrong."""
    if not isinstance(entry, dict):
        raise ValueError("it is not a destination")
    config: dict[str, Any] = entry["config"] if isinstance(entry.get("config"), dict) else {}
    secrets: dict[str, Any] = entry["secrets"] if isinstance(entry.get("secrets"), dict) else {}
    kind = entry.get("kind")
    said = {**config, **{name: value for name, value in secrets.items() if name != "signing"}}
    checked, kept, host = destinations.check(str(kind), said, {})
    signing = secrets.get("signing")
    if kind == "webhook" and isinstance(signing, str) and destinations.SIGNING.fullmatch(signing):
        kept["signing"] = signing
    devices = entry.get("devices")
    if devices is not None:
        if not isinstance(devices, list):
            raise ValueError("its machines are not a list")
        devices = [device_url(url) for url in devices[:10_000] if isinstance(url, str)]
    return {"kind": kind, "config": checked, "secrets": kept, "host": host, **destinations.settle({**entry, "devices": devices})}


def _alerts(said: Any, left_out: list[str]) -> dict[str, Any] | None:
    if not isinstance(said, dict):
        left_out.append("The alert settings are not settings")
        return None
    told: dict[str, Any] = {
        "enabled": _flag(said.get("enabled"), False),
        "offline": _flag(said.get("offline"), True),
        "no_signal": _flag(said.get("no_signal"), True),
        "problem": _flag(said.get("problem"), True),
        "recovered": _flag(said.get("recovered"), True),
        "destinations": None,
    }
    listed = said.get("destinations")
    if isinstance(listed, list):
        found = []
        for number, entry in enumerate(listed[:MOST_DESTINATIONS], 1):
            try:
                found.append(_destination(entry))
            except (ValueError, TypeError) as ex:
                left_out.append(f"Alert destination {number}: {ex}")
        told["destinations"] = found or None
    elif said.get("webhook"):
        # A file of 0.3.2: its one address, and how its service was spoken to. Taken as a 0.3.2 wall's own is carried
        # over (store._from_0_3_2): its first destination, which may be a private address as every address could be then.
        value = said["webhook"]
        form = said.get("format") if said.get("format") in alerts.FORMATS else "auto"
        kind = "webhook" if form in ("auto", "json") else str(form)
        try:
            if not isinstance(value, str):
                raise ValueError
            config, kept, host = destinations.check(kind, {"url": egress.check_url(value), "format": form}, {})
            told["destinations"] = [{"kind": kind, "config": config, "secrets": kept, "host": host, **destinations.settle({"private": True})}]
        except ValueError:
            left_out.append("Alert settings: the address alerts go to is not a web address")
    return told


def _wall(said: Any, left_out: list[str]) -> dict[str, Any] | None:
    if not isinstance(said, dict):
        left_out.append("The wall's settings are not settings")
        return None
    told: dict[str, Any] = {}
    interval = said.get("interval")
    if isinstance(interval, (int, float)) and not isinstance(interval, bool) and 0.2 <= interval <= 60:
        told["interval"] = float(interval)
    elif "interval" in said:
        left_out.append("Wall settings: how often pictures are fetched is not a time this version allows")
    if isinstance(said.get("update_check"), bool):
        told["update_check"] = said["update_check"]
    return told


def _signin(said: Any, left_out: list[str]) -> dict[str, Any] | None:
    """Signing in through an identity provider, as a file holds it: every field as the page's form would have it checked
    (oidc.py), or the part left out, and said, as a whole (half of a provider's settings is none)."""
    if not isinstance(said, dict):
        left_out.append("The sign-in settings are not settings")
        return None
    try:
        roles = said.get("roles", [])
        if not isinstance(roles, list) or not all(isinstance(each, dict) and isinstance(each.get("group"), str) and isinstance(each.get("role"), str) for each in roles):
            raise ValueError("the groups and their roles are not a list of them")
        anyone = said.get("anyone", "")
        if anyone not in ("", *ROLES):
            raise ValueError("who else may sign in is no role")
        texts = {name: said.get(name, "") for name in ("name", "issuer", "client_id", "client_secret", "domain")}
        if not all(isinstance(value, str) for value in texts.values()) or not isinstance(said.get("scopes", ""), str) or not isinstance(said.get("groups_claim", ""), str):
            raise ValueError("a field that is a text is not one")
        return {
            "enabled": _flag(said.get("enabled"), False),
            "name": oidc.button_name(texts["name"]),
            "issuer": oidc.issuer_url(texts["issuer"]) if texts["issuer"].strip() else "",
            "client_id": oidc.client_id(texts["client_id"]) if texts["client_id"].strip() else "",
            "client_secret": oidc.client_secret(texts["client_secret"]) if texts["client_secret"] else "",
            "scopes": oidc.scopes_of(said.get("scopes") or "openid profile email"),
            "groups_claim": oidc.groups_claim(said.get("groups_claim", "groups")),
            "roles": oidc.roles_of([(each["group"], each["role"]) for each in roles[:100]]),
            "anyone": anyone,
            "domain": oidc.email_domain(texts["domain"]),
            "private": _flag(said.get("private"), False),
        }
    except ValueError as ex:
        left_out.append(f"Sign-in settings: {str(ex)[:1].lower()}{str(ex)[1:200]}")
        return None
