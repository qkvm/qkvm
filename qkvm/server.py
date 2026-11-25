"""FastAPI app: setup and login, the wall page, device management and the proxy to the KVMs."""

from __future__ import annotations

import asyncio
import contextvars
import csv
import dataclasses
import functools
import hashlib
import inspect
import io
import json
import logging
import math
import os
import queue
import re
import secrets
import shutil
import threading
import time
import unicodedata
import weakref
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Annotated, Any, Literal, TypeVar
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, Query, Request, WebSocket
from fastapi.exception_handlers import http_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import ClientDisconnect

from . import about, activity, alerts, amt, backup, chain, destinations, discover, egress, exchange, history, live, metrics, oidc, open_in, proxmox, qr, screens, tailcert, tailnet, totp, unlock, video, vncdevice, webpush
from ._version import __version__
from .core import RUN_STILL_WAITING, Core, DeviceManager, auth_mark, driver_for, identity, unknown_kind
from .kvm import FINGERBOT_PRESSES, INPUT_ASKED, KEYBOARD_ACTIONS, KEYS, MAX_PROBE, MAX_TEXT, MOST_UPLOAD, ONE_INPUT, POWER_KEY_REFUSED, PRESS_ANSWERED, PRESS_SENT, REJECTED, RETIRED, AlreadySo, Carried, Device, DeviceSpec, KvmError, MediaOffer, UploadCut, bounded, can_do, fetch_certificate, fingerprint, https_instead, input_refused, listens, names_the_power_key, on_https, one_input_refused, other_way, plain, publicly_trusted, read_json, saved_fingerprint, saved_mark
from .netbind import BindError, lan_ip, normalize, resolve, tailscale_ip
from .served import SERVED_PATH, MOST_AT_ONCE, Binding, identity_follows, MOST_REFUSED_SAID, Lending, Opening, Slot, address_of, basic_matches, byte_range, hand_to_readers, let_go_and_give_back, read_at, same_address, scrubbed
from .served import READERS as SERVED_READERS
from .served import PIECE as SERVED_PIECE
from .security import (
    COOKIE,
    REMEMBER_TTL,
    SSO_LIVE_UNCONFIRMED,
    SECURITY_HEADERS,
    Session,
    client_allowed,
    client_ip,
    host_allowed,
    is_local,
    is_secure,
    same_origin,
    same_text,
    shares_our_name,
    sso_name,
)
from .store import AMT_VIEWS, FINGERBOT_STRENGTHS, KINDS, ROLES, ActionRecord, AuditLog, CheckHalted, DestinationRecord, DeviceRecord, NetbirdSettings, OidcSettings, PushRecord, TokenRecord, UserRecord, as_a_line, device_url, position_of, sealed_for
from .update import NoLongerAllowed, Unfit, UpdateError
from .vault import NoMemory, Vault, VaultLocked, new_recovery_key, tidy_recovery_key

log = logging.getLogger("qkvm")
STATIC = Path(__file__).parent / "static"
ASSET_TYPES = {
    "index.html": "text/html; charset=utf-8",
    "app.js": "text/javascript",
    "app.css": "text/css",
    "theme.js": "text/javascript",
    "favicon.svg": "image/svg+xml",
    # The service worker that shows the alerts a browser is told by Web Push (webpush.py), and nothing else; and what a
    # phone needs to add the wall to its Home Screen as an app of its own, which an iPhone asks before it takes them.
    "push.js": "text/javascript",
    "manifest.webmanifest": "application/manifest+json",
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
# ...and signing in through an identity provider (oidc.py): whether the sign-in page offers it, the press of its button (a
# POST, so the page's own header is asked of it like every change), and the way back from the provider (a GET the provider's
# redirect makes, which carries the browser's cookie of the sign-in and nothing the wall trusts by itself).
PUBLIC |= {"/api/v1/oidc/offer", "/api/v1/oidc/begin", oidc.CALLBACK}
OIDC_REFUSALS_SAID = 60.0  # seconds between lines in the activity log of ways back from a provider that no sign-in on this wall began
# ...and what is below these: the page's files, and an image mounted on a server, which its controller reads by an address
# made for that mount alone, from its own address alone (served.py; "/media/{token}/{name}").
PUBLIC_UNDER = ("/static/", "/media/")
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
BACKUP_LOOK = 30.0  # seconds between two looks of the clock at whether a backup is due (backup.py)
RUN_WAIT = 60.0  # seconds "Back up now" waits for its run before it answers that it is still running
HISTORY_AGAIN = 5.0  # seconds a run waits before it asks a history that was busy again (three times in all)
BACKUP_STUCK = 3600.0  # seconds after which a run its folder holds is said to have failed, and alerted, its thread still held
SCHEDULE_AHEAD = 25 * 3600.0  # the next backup by the clock is never further away than this (a day, and an hour the clock may skip)
VERIFY_WITHIN = 600.0  # seconds Verify waits for the folder (reading a backup whole) before it says the folder does not answer
FOLDER_WITHIN = 30.0  # seconds a look at where a folder lies waits for it (a setting saved)
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
CHECK_WAIT = 20.0  # seconds a request to check the activity log waits for the check before it is answered with how far it got
# The activity log's daily seal to the alert destinations that asked for it (chain.py): the first after a start, then each
# destination again so long after the last it was sent, looked for so often (one in its quiet hours waits for their end).
LOG_SEAL_FIRST, LOG_SEAL_EVERY, LOG_SEAL_LOOK = 600.0, 86400.0, 900.0
MOST_PROBLEMS_SHOWN = 50  # problems of a check of the activity log the page is given; the rest are counted
# The actions the history keeps as power events, pressed from the wall. The rest (keys, text) is the activity log's.
POWER_ACTIONS = frozenset({"atx_power", "atx_power_long", "atx_reset", "fingerbot_power", "fingerbot_power_long", "power_on", "power_off", "bios_setup", "wol", "reboot"})
# Hostnames every device has out of the box; useless as a tile name.
GENERIC_NAMES = {"", "glkvm", "pikvm", "localhost", "localhost.localdomain"}


USER_NAME = r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,63}$"  # also what an identity provider calls somebody: olga@example.org
IDENT = re.compile(r"[a-z]{2,12}:[0-9a-f]{16,64}")  # what a driver may say a device is: a kind of mark, and a digest
RANK = {role: rank for rank, role in enumerate(reversed(ROLES))}  # viewer 0, operator 1, admin 2
_DEVICE = r"/api/v1/devices/[^/]+"
_VIEWER = re.compile(
    rf"GET (/api/v1/wall|/api/v1/status|/api/v1/about|{_DEVICE}/snapshot|{_DEVICE}/history|/api/v1/push)"
    rf"|POST (/api/v1/logout|/api/v1/password|/api/v1/totp/(begin|enable|disable|codes)|{_DEVICE}/live|/api/v1/push(/key|/[^/]+/test)?)"
    r"|DELETE /api/v1/push/[^/]+"
)
# What an account does for itself. A token is nobody's account: it has no password to change or to be asked for, and no
# browser of its own to be told the alerts in (Web Push: a phone is a person's).
_OWN_ACCOUNT = re.compile(r"POST /api/v1/(password|totp/(begin|enable|disable|codes))|(GET|POST|DELETE) /api/v1/push(/[^/]+(/test)?)?")
# All that an account can do while it has to set up two-factor sign-in and has not: set it up, or leave.
_ENROLLING = re.compile(r"POST /api/v1/(logout|totp/(begin|enable))")
_OPERATOR = re.compile(rf"GET (/api/v1/actions|{_DEVICE}/wol)|POST {_DEVICE}/(actions|console)|PUT {_DEVICE}/view")
# Virtual media: an image mounted on a machine, and the machine started from it, is root on that machine (an installer, a
# rescue system). A right of its own, for this role and above: an admin's (the owner's decision for 0.3.0). A token is never
# an admin, and the routes refuse one besides.
_MEDIA = re.compile(rf"(GET|POST) {_DEVICE}/media(/upload)?|POST {_DEVICE}/media/(unmount|delete)")
MEDIA_ROLE = "admin"
# The one request whose body is an image, carried through to the device a piece at a time as it comes (never read in
# full, never kept): its own rule for its length (MOST_UPLOAD, said in advance), and no time for the whole of it, only for
# each piece (UPLOAD_QUIET).
_UPLOAD = re.compile(rf"POST {_DEVICE}/media/upload")
UPLOAD_QUIET = 60.0  # seconds an upload may send nothing before it is cut off
UPLOAD_ASK_EVERY = 5.0  # ...and how often, while it comes, it is asked whether whoever sends it may still
MEDIA_DRIVE_SAID = {"cd": "a CD-ROM drive", "flash": "a USB flash drive", "disk": "a disk"}

# Requests that change what is saved: accounts, KVMs, saved actions, settings. They are handled one at
# a time, so that no two can interleave a check ("is that name free?") with each other's write.
# Running an action on a KVM, signing in and looking for updates are not among them: those can take long.
# Nor are adding a KVM, changing one and trusting its certificate, which talk to the KVM first (that can
# take seconds, and must not make every other change wait). Nor what checks a password or the recovery key
# first (a deliberate half second each, and anybody may send /recover: strangers' guesses held every change
# of the wall). Those take the same turn themselves, for the part that changes what is saved, and ask there
# again whether what they checked still holds: see `one_change` in their handlers.
_CHANGES = re.compile(
    r"(POST|PUT|DELETE) /api/v1/(setup|totp/enable|users(/[^/]+)?"
    r"|actions(/[^/]+)?|settings(/media)?|backups|alerts(/pause|/destinations(/[^/]+(/secret)?)?)?|update|metrics/token|security|tokens(/[^/]+)?|wall/order)"
    r"|DELETE /api/v1/devices/[^/]+"
    r"|POST /api/v1/devices/remove|POST /api/v1/push(/key)?|DELETE /api/v1/push/[^/]+"
    r"|PUT /api/v1/devices/[^/]+/(view|open-in)"
)

# What no path of this program has in it: a character that is none (a line feed, a tab, a zero).
_NO_PATH = re.compile("[\x00-\x1f\x7f]")

# The name of whoever is making the request being handled, for the activity log.
acting: contextvars.ContextVar[str] = contextvars.ContextVar("acting", default="")


def required_role(method: str, path: str) -> str:
    """The least role that may make this request. Whatever is not listed here takes an admin."""
    call = f"{method} {path}"
    if _MEDIA.fullmatch(call):
        return MEDIA_ROLE
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
    # (0.4.0) The first destination may be a private address (destinations.py); None: as it was, and off for a new one.
    private: bool | None = None


class DestinationIn(BaseModel):
    """A place the alerts go (destinations.py), as the page's box for its kind sends it. A secret left empty keeps the one
    saved (an address with a token in it, a key, a token, a password)."""

    kind: str = Field(max_length=20)
    name: str = Field("", max_length=80)
    enabled: bool = True
    private: bool = False  # may be a private address (RFC 1918, fc00::/7, 100.64.0.0/10)
    minimal: bool = False  # the machine's name, what happened and the link, and nothing else
    events: list[str] | None = Field(None, max_length=20)  # None: all of them
    least: str = Field("info", max_length=10)
    devices: list[str] | None = Field(None, max_length=10_000)  # ids of the machines it is told about; None: all, new ones too
    groups: list[str] = Field(default_factory=list, max_length=100)
    quiet_from: int = -1  # minutes of the day; -1: no quiet hours
    quiet_to: int = -1
    quiet_days: list[str] = Field(default_factory=list, max_length=7)
    remind: int = 0
    log_seal: bool = False  # told the activity log's head once a day (chain.py; never to PagerDuty)
    # Its kind's own.
    url: str = Field("", max_length=2048)  # Slack, Teams, Discord, ntfy, a webhook
    token: str = Field("", max_length=500)  # a Telegram bot's, an ntfy access token
    forget_token: bool = False
    forget_signing: bool = False  # a webhook sent without a signature
    key: str = Field("", max_length=200)  # PagerDuty's routing key, Resend's API key
    password: str = Field("", max_length=500)  # the mail server's
    host: str = Field("", max_length=253)  # the mail server
    port: int | None = None
    user: str = Field("", max_length=200)
    sender: str = Field("", max_length=320)
    to: list[str] | str = Field(default_factory=list, max_length=50)
    chat: str = Field("", max_length=40)  # a Telegram chat
    region: str = Field("", max_length=4)  # PagerDuty's service region
    format: str = Field("", max_length=10)  # a webhook carried over from 0.3.2: "auto" works its service out from its address


class PushKeysIn(BaseModel):
    p256dh: str = Field(max_length=200)
    auth: str = Field(max_length=100)


class PushIn(BaseModel):
    """A browser's subscription to the alerts by Web Push, as its PushSubscription.toJSON() gives it (webpush.py)."""

    endpoint: str = Field(max_length=webpush.LONGEST_ENDPOINT)
    keys: PushKeysIn
    name: str = Field("", max_length=100)  # what browser it is, for the list: "Chrome on Android"
    key: str = Field("", max_length=200)  # the wall's key the browser subscribed with (GET /api/v1/push), where the page says it


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


class GroupRoleIn(BaseModel):
    group: str = Field(max_length=oidc.MOST_GROUP)  # a group's name, as the identity provider writes it
    role: Literal["admin", "operator", "viewer"]


class NetbirdIn(BaseModel):
    """NetBird's management API, as Settings > Network sends it (tailnet.py): an address ("" switches it off), the token ("":
    keep the one saved, for the same address only), and whether the address may be a private one."""

    url: str = Field("", max_length=600)
    token: str = Field("", max_length=600)
    private: bool = False


class OidcIn(BaseModel):
    """Signing in through an identity provider (oidc.py), as Settings > Accounts sends it. Each field is checked by
    oidc's own rules; with `enabled`, every one the sign-in needs has to be there."""

    enabled: bool
    name: str = Field("", max_length=80)
    issuer: str = Field("", max_length=600)
    client_id: str = Field("", max_length=300)
    client_secret: str = Field("", max_length=600)  # empty: keep the one saved (for the same issuer and client id only)
    scopes: str = Field("openid profile email", max_length=600)
    groups_claim: str = Field("groups", max_length=120)
    roles: list[GroupRoleIn] = Field(default_factory=list, max_length=100)
    anyone: Literal["", "admin", "operator", "viewer"] = ""
    domain: str = Field("", max_length=260)
    private: bool = False
    redirect_uri: str = Field("", max_length=600)


LONGEST_PAUSE = 7 * 24 * 60  # minutes alerts can be paused for
PUSH_KEY_FOR = "alerts:push-key"  # what the wall's key for Web Push is sealed for (store.AlertSettings.push_key)
DOES_NOT_OPEN = "The saved address does not open any more (the settings file was edited, or is damaged). Enter it again."
MOST_DESTINATIONS = 50  # places alerts go, on one wall
REMINDER_MINUTE = 60.0  # seconds of a minute of a destination's reminders (a test makes it shorter)
TROUBLE = ("offline", "no_signal", "auth", "error")  # the states a reminder is of
TEST_EVERY = 3.0  # seconds between two tests of one destination
MOST_BROWSERS_EACH = 10  # browsers one account may have told the alerts by Web Push
MOST_BROWSERS = 200  # ...and all accounts together
PUSH_TEST_EVERY = 5.0  # seconds between two test alerts of one account to its browsers


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
    # Its screen watched (screens.py): an alert after so many minutes with no video signal, or with a screen that looks the
    # same; 0: not watched for that; None: as it was (not watched, for a new one).
    no_signal_minutes: int | None = Field(None, ge=0, le=screens.MOST_MINUTES)
    unchanged_minutes: int | None = Field(None, ge=0, le=screens.MOST_MINUTES)
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
    # The tile's `target` as the box that showed the certificate had it (target_of): refused, nothing pinned (409
    # `machine_changed`), where the tile is at another machine by then (the second fresh review of the HA round, L2). None: not asked.
    target: str | None = Field(None, min_length=1, max_length=64)


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
    # The tile's `target` as the sender saw it, when its confirmation was shown (target_of): refused, nothing sent (409
    # `machine_changed`), where the tile is at another machine by then. None (a script, a client before 0.4.0): not asked, as before.
    target: str | None = Field(None, min_length=1, max_length=64)
    # On a KVM with several inputs, the one the sender saw on screen (the status's `ports.active`), for keys and typed text (a
    # saved action's and the dedicated Ctrl+Alt+Del too), which go to that one's computer: refused, nothing sent (409
    # `input_changed`), where the KVM itself, asked right before they go, shows another or does not say which (kvm.INPUT_ASKED).
    # None: not asked, as before. Power and the rest are the KVM's own, whichever is on screen.
    input: int | None = Field(None, ge=0, le=63)
    # Instead of `input`: the sender took the KVM for one of a single input (its status said no `several_inputs` and no `ports`).
    # Refused the same way, nothing sent, where the wall knows it has several, or its switch, asked right before they go, lists
    # several; a machine with no inputs to choose from takes it as so (kvm.ONE_INPUT). False: not asked, as before.
    one_input: bool = False


class KvmSwitchIn(BaseModel):
    on: bool  # a PC's Intel AMT KVM on (true) or off, on its management engine
    # The tile's `target` as the sender saw it (target_of), as an action's: refused, nothing changed on either engine (409
    # `machine_changed`), where the tile is at another PC by then (the fresh review of the HA round, H1). None: not asked, as before.
    target: str | None = Field(None, min_length=1, max_length=64)


def media_listed(device_id: str, spec: DeviceSpec) -> str:
    """The machine a list of its images was made of, as a mark: its tile, the address and the kind it is spoken to as, how its
    certificate is checked, and what it is known by there (its pinned certificate, the number its machine gives for itself,
    its identity). GET .../media answers it as `listed`, and a change that sends it back is refused where the tile's machine
    is no longer so (409 `moved`): a Media box opened for one machine, its tile then edited to another address, sent its
    mount or its deletion there, wherever an image of that name was (the desktop app's finding 21). Made anew of what is so
    each time, it cannot stand for another machine after a restart or an edit taken back; nothing in it is secret, and none
    of it can be read out of it. (Where the machine's number is first learned between a list and its change, that change is
    refused once, and the box lists again.)"""
    said = "\0".join((device_id, spec.base_url, spec.kind, spec.tls, spec.cert_pem or "", spec.machine, spec.ident))
    return hashlib.sha256(said.encode("utf-8", "surrogatepass")).hexdigest()[:32]


def target_of(record: DeviceRecord) -> str:
    """The machine a tile is at, as a mark: `target` in the wall's view of the tile. Made as media_listed is, of the tile, the
    address and the kind it is spoken to as, how its certificate is checked, and what it is known by there (its pinned
    certificate, the number its machine gives for itself, its identity). An action (power, keys, typed text, a saved action,
    one tile's or a bulk run's) and a live line's pass that send it back are refused, nothing sent, where the tile is at
    another machine by then (409 `machine_changed`): a confirmation seen for one machine went to the one an admin's edit put
    in its place meanwhile, by the same tile id (the outside review of 0.4.0, H3). Made anew of what is so each time, it cannot
    stand for another machine after a restart or an edit taken back; nothing in it is secret, and none of it can be read out
    of it. Where what qKVM knows of the machine grows meanwhile (its certificate or its number first remembered, the JetKVM
    followed onto HTTPS), it changes too, and the action sent with the mark before is refused once."""
    said = "\0".join(("target", record.id, record.url, record.kind, record.tls, record.cert_pem or "", record.machine, record.ident))
    return hashlib.sha256(said.encode("utf-8", "surrogatepass")).hexdigest()[:32]


class MediaIn(BaseModel):
    image: str = Field(min_length=1, max_length=300)  # an image's `id`, as GET .../media listed it
    machine: str = Field(min_length=1, max_length=4 * 60)  # the machine's name, as the confirmation named it
    # GET .../media's `listed`, as the box that sends this was shown it: refused (409 `moved`) where the tile's machine is no
    # longer that one. None (a client before 0.3.2, as the Desktop App 0.1.x): not asked, as before. (Also below.)
    listed: str | None = Field(None, min_length=1, max_length=64)
    drive: Literal["cd", "flash", "disk"] = "cd"  # what it goes in as, of the offer's `drives`
    writable: bool = False  # the machine may change what is on it: only for a drive of the offer's `writable`, and chosen
    boot: Literal["none", "once", "until_unmounted"] = "none"  # start it from the image: not, once (restarted now), until unmounted
    # Restart it now: to start from the image (with "until_unmounted"; "once" always restarts), or, where it cannot be told to
    # start from it (a KVM: no `boot` in its offer), for its firmware to find it (its boot menu).
    restart: bool = False


class UnmountIn(BaseModel):
    image: str = Field(min_length=1, max_length=300)  # what is mounted (`image` of `mounted`), as the confirmation named it
    machine: str = Field(min_length=1, max_length=4 * 60)
    listed: str | None = Field(None, min_length=1, max_length=64)


class DeleteIn(BaseModel):
    image: str = Field(min_length=1, max_length=300)  # an image's `id`, as GET .../media listed it, as the confirmation named it
    machine: str = Field(min_length=1, max_length=4 * 60)
    listed: str | None = Field(None, min_length=1, max_length=64)


class AmtViewIn(BaseModel):
    view: Literal["health", "stills", "live"]  # which of its three views a PC with Intel AMT is in (store.AMT_VIEWS)
    # The tile's `target` as the sender saw it (target_of), as an action's: refused, nothing changed (409 `machine_changed`),
    # where the tile is at another PC by then (the outside review 6.2 second re-check, M1). None: not asked, as before.
    target: str | None = Field(None, min_length=1, max_length=64)


class OpenInIn(BaseModel):
    """A machine's "Open in" links (open_in.py), all of them: one left out or empty is none of that kind. Each is checked by
    open_in.checked in the route, which says in words what is wrong with one; here, only that each is a text of a length."""

    model_config = ConfigDict(extra="forbid")  # (a kind this version does not know is refused, not dropped without a word)
    meshcentral: str = Field("", max_length=2 * open_in.MOST[open_in.MESHCENTRAL])
    rustdesk: str = Field("", max_length=2 * open_in.MOST[open_in.RUSTDESK])
    rdp: str = Field("", max_length=2 * open_in.MOST[open_in.RDP])
    # The tile's `target` as the sender saw it (target_of), as an action's: refused, nothing saved (409 `machine_changed`), where
    # the tile is at another machine by then (the fresh review of the HA round, L1). None: not asked, as before.
    target: str | None = Field(None, min_length=1, max_length=64)


class CustomActionIn(BaseModel):
    _name = field_validator("name")(_a_line(60, needed=True))
    name: str = Field(min_length=1, max_length=4 * 60)
    kind: Literal["keys", "text"]
    keys: str = Field("", max_length=160)
    text: str = Field("", max_length=MAX_TEXT)  # empty on an edit means "keep the saved text"
    enter: bool = False
    danger: bool = False


Part = Literal["devices", "actions", "alerts", "wall", "signin"]


class ExportIn(BaseModel):
    password: str = Field(max_length=256)  # handing the wall's secrets out asks for the password again
    # What the file is encrypted with. Empty: a plain file, with every secret left out.
    passphrase: str = Field("", max_length=256)
    parts: list[Part] = Field(min_length=1, max_length=5)


class ImportIn(BaseModel):
    file: str = Field(max_length=exchange.MAX_SEALED)  # the file's text (a plain one is held to less where it is read)
    passphrase: str = Field("", max_length=256)
    take: list[Part] = Field(default_factory=list, max_length=5)  # for /api/v1/import: which of its parts to take


class UpdateSettingsIn(BaseModel):
    auto_check: bool


class UpdateInstallIn(BaseModel):
    password: str = Field(max_length=256)  # installing new code asks for the password again


class SettingsIn(BaseModel):
    bind: list[str] = Field(max_length=8)
    port: int = Field(ge=1, le=65535)
    https: bool
    interval: float = Field(ge=0.2, le=60)


class BackupsIn(BaseModel):
    enabled: bool
    folder: str = Field("", max_length=1000)  # where they go, on the computer qKVM runs on: a whole path ("": none yet)
    hour: int  # the hour of the day they are made at, the wall's local time (0 to 23)
    keep: int  # how many are kept (1 to 365)
    history: bool = False  # the history as well


class MediaSettingsIn(BaseModel):
    folder: str = Field("", max_length=1000)  # where the images for servers are, on the computer qKVM runs on ("": none)
    address: str = Field("", max_length=300)  # the wall's address as servers' controllers reach it ("": where it listens)


def tidy_groups(names: list[str]) -> list[str]:
    """Group names as they are kept: each once, however it was typed."""
    kept: dict[str, str] = {}
    for name in names:
        name = " ".join(name.split())[:40]
        if name:
            kept.setdefault(name.casefold(), name)
    return list(kept.values())


# FastAPI (0.148 at the latest) traces, measures and logs every request through OpenTelemetry wherever something in the
# process has set a provider up, and sets exporters up itself where FASTAPI_OTEL_AUTO_CONFIGURE=true and an endpoint are in
# the environment: a request's path, query and address, and to whatever processes the spans what it carried, would go where
# an environment variable or another library says. qKVM writes down what it does in its own activity log. All of it off,
# for good, where this FastAPI has it at all (an older one has no such argument, and nothing to switch off).
TELEMETRY_OFF: dict[str, Any] = (
    {"telemetry": {"tracing": False, "metrics": False, "logs": False, "operation_spans": False, "auto_configure": False}}
    if "telemetry" in inspect.signature(FastAPI.__init__).parameters
    else {}
)


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
        self._lock = threading.Lock()  # (given back on the loop, and by the thread that lets go of answers never sent: _LEFT)
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


# What an answer that was never sent was made from (Handed), put here by its finalizer and let go of by a thread of its own.
# The collector runs a finalizer in whichever thread it runs, between any two steps of that thread's code, with whatever
# lock that code holds; and every `done` takes a lock: the download places' (Downloads), a thread pool's and the one all
# pools share (a download's file is closed in a pool, a served image's is handed to the readers), a served image's places.
# Run there, a download's gave its place back between two steps of Downloads.take, and waited for the lock its own thread
# held, the event loop and every request of the wall with it (the runner, 2026-11-17). A SimpleQueue's put takes no lock and
# may run within another call of its own: made for this. (Not the event loop's call_soon_threadsafe: what a loop that ends
# was handed is dropped, qKVM stopping or its listeners started again, and a served image's places outlive the loop.)
_LEFT: queue.SimpleQueue[Callable[[], None]] = queue.SimpleQueue()
_LETTING_GO = threading.Lock()  # taken for good by the first answer made, which starts the thread that lets go


def _let_go_of_what_is_left() -> None:
    while True:
        done = _LEFT.get()
        try:
            done()
        except Exception:
            log.exception("what an answer that was never sent was made from could not be let go of")


class Handed(StreamingResponse):
    """An answer that lets go of what it was made from once it is sent, or could not be, or is never sent at all.

    `sent_while`: what is asked before each piece of it goes to the connection (SentOnlyWhile), where it is asked
    before each piece is made too. Such an answer says its length: cut off, it is then shorter than it says, where
    one without a length would end as a whole one does, and its reader would take the part for the whole.
    """

    def __init__(self, content: AsyncIterator[bytes], done: Callable[[], None], *, sent_while: Callable[[], bool] | None = None, **how: Any) -> None:
        if sent_while is not None and not any(name.lower() == "content-length" for name in (how.get("headers") or {})):
            done()  # (refused, it lets go of what it was made from, as an answer never sent does)
            raise ValueError("an answer that may be cut off says its length")
        super().__init__(content, **how)
        self._done = done
        self._sent_while = sent_while
        if _LETTING_GO.acquire(blocking=False):  # (here, never by a finalizer: a thread is started under threading's locks)
            try:
                threading.Thread(target=_let_go_of_what_is_left, name="qkvm-let-go", daemon=True).start()
            except BaseException:
                _LETTING_GO.release()  # (the next answer tries again)
                done()
                raise
        self._left = weakref.finalize(self, _LEFT.put, done)  # (an answer never sent: let go of when it is collected, see _LEFT)

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        try:
            if self._sent_while is not None:
                scope[SentOnlyWhile.KEY] = self._sent_while
            await super().__call__(scope, receive, send)
        finally:
            self._done()
            self._left.detach()  # (let go of: not again when it is collected)


class CarriedThrough:
    """Outside the guard: the one way an upload's route reads its body (an image, up to MOST_UPLOAD), from the web server
    itself, a piece at a time, and nothing else does.

    The guard is a middleware of Starlette's, which hands each piece of a body on to the app inside it through a task of its
    own, and keeps something of each until the request ends: measured, some 45 KB for every megabyte that came, which for
    a 16 GB image is the better part of a gigabyte. Everything else the page sends is 64 KiB at the most, and read whole by
    the guard. The guard still decides whether the upload may come in at all (it does not read its body: see `screened`).
    """

    KEY = "qkvm.carried_through"

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        # (By the path the request is routed by, as the guard has it; set for that route alone.)
        if scope["type"] == "http" and _UPLOAD.fullmatch(f"{scope.get('method')} {scope.get('path')}"):
            scope[CarriedThrough.KEY] = receive
        await self.app(scope, receive, send)


class SentOnlyWhile:
    """Outside every other part of the app: a piece of an answer that says what it may be sent while (Handed's
    `sent_while`) goes to the connection only while that is so, asked as it goes.

    (Asked where the answer is made, it is asked too early: the guard's middleware takes the next piece of an answer
    while the one before is still going out, so one piece, made and asked for before the right to it was lost, went
    out after it. L-W1 of the review of 850745e.) Asked once the connection takes more: the web server waits for a
    slow receiver before it writes, so an empty piece goes first, which is that wait and writes nothing, and the
    piece is asked for and handed on with no wait in between. (Asked before that wait, a piece was written after a
    right lost during it: the delta review of cccf01a.) From the first piece refused on, none goes; the answer ends
    as the one who made it ends it, shorter than its length says. What the connection holds already still arrives.
    The web server then refuses that end, and its error carries CUT_OFF: said in a line of the log (cli._CutShort),
    where an answer that ends short by a fault is written with its traceback.
    """

    KEY = "qkvm.sent_while"
    CUT_OFF = "qkvm: cut off on purpose, its reader having lost the right to the rest"

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        refused = False

        async def asked(message: Any) -> None:
            nonlocal refused
            may = scope.get(SentOnlyWhile.KEY) if message["type"] == "http.response.body" else None
            if may is not None and not refused:
                if message.get("body"):
                    await send({"type": "http.response.body", "body": b"", "more_body": True})  # (the wait)
                refused = not may()  # (asked of the end too: the answer may have been ended short where it was made)
            if refused and message.get("body"):
                message = {**message, "body": b""}
            try:
                await send(message)
            except Exception as ended:
                if refused:
                    ended.add_note(SentOnlyWhile.CUT_OFF)
                raise

        await self.app(scope, receive, asked)


class SpelledOut:
    """Outside every other part of the app: the answer to a server's controller reading a served image names its headers as
    they are usually spelled ("Content-Length", "Accept-Ranges"), where the web framework writes them in lowercase. Names
    are not case-sensitive, but a controller's own reader may look for them as spelled (a real AMI board reads with
    httpfs2 0.1.5a, which looks for "Accept-Ranges: bytes" and "Content-Length: "). That board's mount still failed with
    them spelled out ("Error code: 416", after one HEAD): this is not what it wanted, and is kept as the usual spelling.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http" or not SERVED_PATH.fullmatch(scope.get("path") or ""):
            await self.app(scope, receive, send)
            return

        async def spelled(message: Any) -> None:
            if message["type"] == "http.response.start":
                message = {**message, "headers": [(spelled_out(name), value) for name, value in message.get("headers") or []]}
            await send(message)

        await self.app(scope, receive, spelled)


def spelled_out(name: bytes) -> bytes:
    """A header's name as it is usually spelled: each of its parts capitalized (content-range: Content-Range)."""
    return b"-".join(part[:1].upper() + part[1:].lower() for part in name.split(b"-"))


class TurnRefused(Exception):
    """A read that is not let in now (Reads.run): the answer to give."""

    def __init__(self, reply: JSONResponse) -> None:
        super().__init__(reply.status_code)
        self.reply = reply


T = TypeVar("T")
R = TypeVar("R", bound=Response)


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

        async def said(address: str) -> tuple[bool, Any, str | None]:
            """(whether anything answered there at all, what it said where that was a plain yes in JSON, the HTTPS address at the
            same host that a plain one sends everybody on to: kvm.https_instead)"""
            try:
                reply = await bounded(client, client.build_request("GET", address), MAX_PROBE, RECOGNISE_WITHIN)
            except KvmError as ex:
                return ex.code != "timeout", None, None  # too much, or packed oddly: somebody is there all the same
            except httpx.HTTPError:
                return False, None, None
            sent_on = https_instead(address, reply)
            try:
                return True, read_json(reply) if reply.status_code == 200 else None, sent_on
            except ValueError:
                return True, None, sent_on

        # Asked together: an address where nothing answers costs one wait, not one for each make.
        *jets, (root_answers, root, _) = await asyncio.gather(*(said(f"{c}/device/status") for c in candidates), said(f"{url}/redfish/v1/"))
    wanted_tls = url.startswith("https://")  # https:// was typed, or nothing was
    over_tls = wanted_tls and (root_answers or any(answers for c, (answers, _, _) in zip(candidates, jets, strict=True) if c.startswith("https://")))
    for candidate, (_, status, _) in zip(candidates, jets, strict=True):
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
    # Its plain address sends everybody on to HTTPS at the same host (nginx in front of kvmd, once that is its only way in): said,
    # with that address, before the password typed goes out the plain way to be sent on. Never followed by itself.
    sent_on = next((to for candidate, (_, _, to) in zip(candidates, jets, strict=True) if candidate == url and to), None)
    if sent_on is not None:
        raise on_https(sent_on)
    return "kvmd", url


SENT_ON_WITHIN = 3.0  # seconds a KVM at a plain address has to say that it sends everybody on: a web server that does answers at once


async def sent_on_to_https(url: str) -> str | None:
    """Where a KVM's plain address sends everybody on to HTTPS at the same host (kvm.https_instead), asked of its API with no
    credentials before a kvmd is signed in to, its kind chosen or found by asking (detect_kind sees only its own paths sent
    on, and a web server may send the API alone): so that a KVM that wants HTTPS is not sent the password the plain way to
    say so. None for an address that is not plain, and for whatever else answers or nothing: the sign-in after it says that,
    as before."""
    if not url.startswith("http://"):
        return None
    async with httpx.AsyncClient(timeout=RECOGNISE, trust_env=False) as client:
        try:
            reply = await bounded(client, client.build_request("GET", f"{url}/api/auth/check"), MAX_PROBE, SENT_ON_WITHIN)
        except (httpx.HTTPError, KvmError):
            return None
    return https_instead(url, reply)


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


class NotFollowed(Exception):
    """What answers at a plain JetKVM's HTTPS address is not that JetKVM (see the server's `onto_https`); its words say why."""


def view(record: DeviceRecord, editing: bool = True, links: bool = True) -> dict[str, Any]:
    """What a browser may know about a device. Never the password.

    `editing`: for somebody who may change it. Whoever may only look, or act, is told what a tile shows,
    and not how qKVM signs in to the device or how its certificate is checked. `links`: for somebody who may act on it (an
    operator, an admin), its "Open in" links (open_in.py), where it has any: a viewer is not told where else it is opened.
    """
    found = open_in.kept(record.open_in) if links else {}
    shown = {
        "id": record.id,
        "name": record.name,
        "host": urlsplit(record.url).netloc,
        # (A guest of Proxmox: its console on Proxmox's own page, where the address the wall keeps is no page.)
        "open_url": record.open_url or (proxmox.console_page(record.url) if record.kind == "proxmox" else f"{record.url}/"),
        "kind": record.kind,
        "picture": driver_for(record.kind).picture,  # False: its tile shows how a server is, not a screen
        "group": record.group,
        # A PC with Intel AMT: which of its three views its tile is in (said to everybody: the tile says it).
        **({"amt_view": record.amt_view if record.amt_view in AMT_VIEWS else AMT_VIEWS[0]} if record.kind == "amt" else {}),
        **({"open_in": found} if found else {}),  # (0.4.0; none set: not there, as before)
        "target": target_of(record),  # (0.4.0) the machine it is at, for an action or a live line to name (target_of)
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
        "no_signal_minutes": screens.minutes(record.no_signal_minutes),
        "unchanged_minutes": screens.minutes(record.unchanged_minutes),
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

    def certificate_of_another(device_id: str, cert_pem: str) -> DeviceRecord | None:
        """Another tile of the wall that remembers this certificate (as its own, pinned), if there is one."""
        mark = saved_mark(cert_pem)
        return next((d for d in store.devices if d.id != device_id and mark is not None and saved_mark(d.cert_pem) == mark), None)

    async def https_certificate(device_id: str, to: str) -> str:
        """The certificate a plain JetKVM's HTTPS address `to` shows, looked at before anything is sent there (see
        `onto_https`). NotFollowed where another tile of the wall remembers it; KvmError where nothing answers there."""
        shown = await fetch_certificate(to)
        if (twin := certificate_of_another(device_id, shown)) is not None:
            raise NotFollowed(f"it shows the certificate of {twin.name}, which is on the wall already")
        return shown

    async def onto_https(changed: DeviceRecord, to: str, shown: str, password: str | None) -> Device:
        """A client for a plain JetKVM's tile (as `changed` has it, with the password typed or saved) at its HTTPS address `to`,
        where what answers there is that JetKVM: the certificate it showed (`shown`, see `https_certificate`) pinned, signed in
        to and asked which it is as an edit asks (`connect`, JetKvmDevice._same_jetkvm: the JetKVM the tile was added for,
        and no other), and none another tile is (`twin_of`). `changed` then takes the address, the certificate and what it
        says it is. NotFollowed where it is not that JetKVM; KvmError where that could not be told (`changed` untouched).
        For the tile's own move (`moved`) and an edit's (update_device) alike."""
        trial = dataclasses.replace(changed, url=to, tls="pinned", cert_pem=shown)  # (that very certificate, and no other)
        try:
            client, _ = await connect(trial, password, force=False)
        except KvmError as ex:
            if ex.code == "another_machine":
                raise NotFollowed("it is another JetKVM than this tile's: it gives another number for itself") from None
            raise
        if (twin := twin_of(trial)) is not None:
            await client.close()
            raise NotFollowed(f"it says it is {twin.name}, which is on the wall already")
        changed.url, changed.tls, changed.cert_pem, changed.machine, changed.ident = trial.url, trial.tls, trial.cert_pem, trial.machine, trial.ident
        return client

    # A move refused once signed in (another JetKVM at a tile's HTTPS address, or another tile's), by the tile, with the
    # certificate shown there then and the number the tile knew its JetKVM by: while that address shows it, to a tile that knows
    # the same JetKVM, it is not signed in to again (see `moved`). Kept here, with the wall, and not with a tile's client, which
    # is made anew at every edit.
    refused_after_sign_in: dict[str, tuple[str, str]] = {}

    async def moved(device_id: str, url: str, to: str) -> None:
        """A JetKVM on the wall over plain HTTP offers HTTPS by now, and its tile goes there (its driver asks: see jetkvm.py).

        Only where what answers there is that JetKVM. Before anything is sent to it: the certificate it shows is no other
        tile's (another KVM of the wall, reached through a gateway's port, say). Then, signed in to with that certificate
        pinned, it is asked which it is as an edit by a person asks (`connect`, and JetKvmDevice._same_jetkvm): the JetKVM the
        tile was added for and no other, and none that another tile is (the twin check, `twin_of`). Where it asks for a
        password and none is saved, nothing could be sent that it may not have: the tile goes there, and asks for it (where it
        is typed, it takes what answers, as in any edit). Anything else at the HTTPS address is not followed, said in the log,
        and asked about again at the next round (WAY_EVERY).

        Then done as an edit by a person is: one change at a time, the record unchanged since it was looked at, a new record
        put in the old one's place (so that an edit under way notices), what is live and what is saved changed together.
        Only ever onto HTTPS at the same host: nothing comes this way that lets go of a certificate. The activity log says
        what the wall did by itself.
        """
        if not to.startswith("https://") or to != other_way(url):
            return
        record = store.device(device_id)
        if record is None or record.url != url or record.kind != "jetkvm" or any(d.url == to for d in store.devices):
            return

        def not_followed(why: object) -> None:
            log.warning("%s: offers HTTPS at %s, and what answers there is not followed: %s", record.name, to, why)

        try:
            shown = await https_certificate(device_id, to)
        except NotFollowed as ex:
            not_followed(ex)
            return
        except KvmError:
            return  # (nothing answers there just now: asked again at the next round)
        mark = saved_mark(shown)
        if mark is not None and refused_after_sign_in.get(device_id) == (mark, record.machine):
            # Refused once signed in, and it shows the same certificate: not signed in to again (a JetKVM has one session, and
            # each sign-in signs out every browser on its own page, or another tile's). Said once, when it was refused.
            return
        changed = dataclasses.replace(record)
        try:
            client = await onto_https(changed, to, shown, None)
        except NotFollowed as ex:
            not_followed(ex)
            if mark is not None:
                refused_after_sign_in[device_id] = (mark, record.machine)
                for gone in [kept for kept in refused_after_sign_in if store.device(kept) is None]:
                    del refused_after_sign_in[gone]
            return
        except KvmError as ex:
            if ex.code != "no_password" or record.secret is not None:
                not_followed(ex.message)
                return
            # It asks for a password now, and none is saved: nothing was sent that it may not have. It goes there, and asks:
            # where its owner switched a password on, which covers both its ports, its plain address asks for one as well. Not
            # where that still lets anybody in (it says its number to anybody there): the tile's JetKVM is well where it is,
            # and what asks for a password at its HTTPS address is something else (another device behind a gateway's port).
            from .jetkvm import number_to_anybody  # (loaded where a JetKVM is: most walls have none)

            status, _ = await number_to_anybody(url)
            if status != 401:
                not_followed("its JetKVM lets anybody in at its plain address still, and what answers at its HTTPS address asks for a password")
                return
            changed.url, changed.tls, changed.cert_pem = to, "pinned", shown
            try:
                client = manager.client(changed)
            except Exception:  # the saved passwords were locked away in this very moment: asked again later
                return
        except Exception:  # the saved passwords were locked away in this very moment: nothing is changed, and it is asked again later
            return
        async with one_change:
            # Asking took its time: the tile may have been changed or removed meanwhile, or another put at that address.
            if store.device(device_id) is not record or any(d.url == to for d in store.devices) or certificate_of_another(device_id, shown) or twin_of(changed):
                await client.close()
                return
            store.devices[store.devices.index(record)] = changed
            core.served.changed(device_id)  # (another address)
            refused_after_sign_in.pop(device_id, None)
            await manager.adopt(client)
            try:
                await save()
            except OSError as ex:
                log.error("%s: its new address could not be saved: %s", changed.name, ex)
        core.audit.write("device_moved", "", device=changed.name, device_id=device_id, url=to, was=url, note="over HTTPS now")
        log.info("%s: offers HTTPS by now, and is talked to at %s", changed.name, to)

    manager.moved = moved

    async def known(device_id: str, url: str, was: str, mark: str, current: Callable[[], bool] | None = None) -> None:
        """A driver took a number its machine gives for itself (see DeviceManager._known): kept with the tile as a person's
        change is, one change at a time and with a new record in the old one's place (so that an edit under way notices),
        and only where what is kept is still what the driver had, at the address it was seen at. A save that fails leaves
        it in memory, as for a first certificate, and it is written with the next change that is saved."""
        async with one_change:
            record = store.device(device_id)
            # (`current`: the driver that saw it still speaks for the tile, now that its turn has come; one replaced meanwhile
            # has nothing to say of the record that took its place. The outside review's fourth round.)
            if record is None or record.url != url or record.machine != was or (current is not None and not current()):
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
    # --- where the alerts go: the destinations (destinations.py), each delivered to by itself (alerts.Courier) ----------
    last_told: dict[str, tuple[float | None, str | None]] = {}  # destination id -> (when an alert last arrived, what went wrong last)
    not_opening: dict[str, Any] = {}  # destination id -> its sealed settings, of which it was said that they do not open
    failing: set[str] = set()  # destinations whose last delivery failed: the activity log says when that begins and ends

    def destination(destination_id: str) -> DestinationRecord | None:
        return next((one for one in store.destinations if one.id == destination_id), None)

    def destination_secrets(record: DestinationRecord) -> dict[str, str] | None:
        """A destination's secrets, opened. None where they do not open, or the saved passwords are locked."""
        if record.secret is None or not core.vault.unlocked:
            return None
        text = core.vault.read(record.secret, sealed_for(record.id))
        opened: dict[str, str] | None = None
        if text is not None and text.startswith("{"):
            try:
                said = json.loads(text)
            except (ValueError, RecursionError):
                said = None
            if isinstance(said, dict) and all(isinstance(value, str) for value in said.values()):
                opened = said
        elif text is not None:
            opened = {"url": text}  # (the one carried over from 0.3.2: its address, as 0.3.2 sealed it)
        if opened is None and not_opening.get(record.id) is not record.secret:
            # Saved, and does not open any more: alerts go nowhere there. Said, once for what is saved, in the log and where
            # the page shows how the last alert went; with nothing said, the page showed alerts as set up, and a machine
            # went down unannounced.
            not_opening[record.id] = record.secret
            last_told[record.id] = (last_told.get(record.id, (None, None))[0], DOES_NOT_OPEN)
            log.error("alerts go nowhere at a destination: what is saved of it does not open any more (the settings file was edited, or is damaged)")
        return opened

    def destination_target(destination_id: str) -> alerts.Target | str | None:
        """What a destination is to be sent to as, at this moment: a sentence where it cannot be; None where it is gone."""
        record = destination(destination_id)
        if record is None:
            return None
        if record.kind not in destinations.KINDS:
            return "It is of a kind this version of qKVM does not know"
        if not core.vault.unlocked:
            return "The saved passwords are locked: nothing is sent until somebody signs in"
        opened = destination_secrets(record)
        if opened is None:
            return DOES_NOT_OPEN
        try:
            # (What is kept is checked again as it is used: a hand's edit of the settings file is said, not sent.)
            config, opened, _ = destinations.check(record.kind, record.config, opened)
        except ValueError as ex:
            return f"Its settings are not usable: {ex}"
        return alerts.Target(record.id, record.kind, config, opened, record.private, record.minimal, store.alerts.link)

    own_known: list[Any] = [None, frozenset()]  # when the wall's own addresses were last looked up, and what they were

    async def own_addresses() -> egress.Own:
        """The wall itself, which no alert is sent to (egress.judge): the addresses it listens on (for a wall that listens on
        every address, this computer's), and its port there and on loopback. Looked up once a minute at the most."""
        if own_known[0] is None or time.monotonic() - own_known[0] > 60:

            def look() -> frozenset[str]:
                # Where it listens, and every address of this computer's whatever it listens on (egress.this_computer),
                # Tailscale's besides: this computer is reached only with a destination's switch (the second review, L5).
                found = {address for address in core.addresses if address not in ("0.0.0.0", "::")}
                found.update(address for address in (lan_ip(), tailscale_ip()) if address)
                found |= egress.this_computer()
                return frozenset(found)

            own_known[:] = [time.monotonic(), await asyncio.to_thread(look)]
        known: frozenset[str] = own_known[1]
        # The ports the listeners were opened on, and the one it is to listen on (started with --port; or one changed in
        # its settings, saved at once and listened on after a restart): never the saved one alone (the second review, M1).
        return egress.Own(known, frozenset({*core.ports, core.port}))

    def delivered(destination_id: str, delivery: alerts.Delivery) -> None:
        """How a delivery went: shown with the destination; and in the activity log where a destination begins to fail,
        and where it is delivered to again (once each: not a line for every alert that does not arrive). One withheld by
        the wall's own rules (held_back) is in the delivery log alone: it is no failure of the destination's."""
        if delivery.withheld:
            return
        sent = last_told.get(destination_id, (None, None))[0]
        last_told[destination_id] = (delivery.at, None) if delivery.ok else (sent, delivery.said)
        record = destination(destination_id)
        if record is None or delivery.test:
            return
        called = record.name or destinations.KIND_NAMES.get(record.kind, record.kind)
        if not delivery.ok and destination_id not in failing:
            failing.add(destination_id)
            core.audit.write("alert_not_delivered", "", destination=called, kind=record.kind, said=delivery.said, attempts=delivery.attempts)
        elif delivery.ok and destination_id in failing:
            failing.discard(destination_id)
            core.audit.write("alert_delivered_again", "", destination=called, kind=record.kind)

    # Destination id ("" for alerts as a whole) -> the courier's count of alerts handed over when it was last switched off:
    # what was handed over before that goes no more, even where it is switched on again before its next try (the outside
    # review of 0.4.0, bugs round 2, M3). In memory: what waits does not outlive a restart either.
    switched_off: dict[str, int] = {}

    def switched_since(destination_id: str, alert: alerts.Alert, which: str) -> bool:
        """Whether `which` (a destination's id, or "" for alerts as a whole) was switched off after `alert` was handed to this
        destination."""
        handed = alert.handed.get(destination_id)
        return handed is not None and handed <= switched_off.get(which, 0)

    def alerts_switched_off() -> None:
        """Alerts as a whole switched off, and saved so: what waits for a destination or a browser goes no more."""
        switched_off[""] = courier.handed
        pusher.cut()

    # Destination id -> the courier's count when it was edited to send elsewhere (destinations.receiver): what was handed
    # over before goes no more, to the new receiver or the old (the outside review of 0.4.0, bugs round 2, M6).
    sent_elsewhere: dict[str, int] = {}

    def started_anew(destination_id: str) -> None:
        """A destination edited to send elsewhere (another address, chat, routing key or recipients), saved so: its new receiver
        knows nothing of what the one before was told. What it knew of the machines, where a screen watch's start went, its
        reminders, what quiet hours held for it, a backup's failure it was told and what is on its way are forgotten there;
        what waited for it was dropped (sent_elsewhere). Saved where who is owed a backup's end changed."""
        for kept in (on_way, reminded, quiet_held, quiet_ends, backup_owed, backup_going):
            kept.pop(destination_id, None)
        # Each machine's trouble as not told there (""): nothing known is no book at all, which tells every end, as 0.3.2 did.
        told_there[destination_id] = dict.fromkeys((record.id for record in store.devices), "")
        for watches in watch_told.values():
            for watch in watches.values():
                watch[1].discard(destination_id)
        backup_sending.discard(destination_id)
        if destination_id in store.backups.told:
            told_so(destination_id, False)
            told_changed()

    def held_back(destination_id: str, alert: alerts.Alert) -> str | None:
        """(alerts.Courier, before each attempt and right before it goes, from the event loop or a mail send's thread.) Why an
        alert waiting for a destination may not go now: the destination switched off, or, but for the daily seal of the
        activity log (which goes whatever the alerts' switch says), alerts switched off, now or since it was handed over
        (switched_off); and a machine's end of a trouble that a switch dropped there (untold), or of a screen watch whose
        start it dropped there (unwatched), or a backup's end where no failure is told there (failure_off_way); and a reminder
        of a trouble the destination is not said to know any more (knows). What is held back is dropped: not sent, then or later
        (the second outside review of 0.4.0, M4). A pause and quiet hours stop new alerts only, judged where an alert is
        routed (tell, tell_backup, seal_to_destinations): what was handed to a destination before they began goes as it would
        have, its retries bounded (alerts.RETRY_AFTER). (They held it once, and told it when they ended: three review rounds
        found ways that lost or falsely told it, the fresh review of the fixes, N2, and the last look, M1 to M5.)"""
        record = destination(destination_id)
        if record is None:
            return None  # (gone: said by destination_target)
        if not record.enabled or switched_since(destination_id, alert, destination_id):
            return "Not sent: the destination was switched off while it waited"
        if (handed := alert.handed.get(destination_id)) is not None and handed <= sent_elsewhere.get(destination_id, 0):
            return "Not sent: the destination was changed to send elsewhere while it waited"
        if alert.event != "log_seal" and (not store.alerts.enabled or switched_since(destination_id, alert, "")):
            return "Not sent: alerts were switched off while it waited"
        if not alert.device_id and alert.event == "recovered" and destination_id not in store.backups.told:
            return "Not sent: the failure it ends was not sent there, a switch dropped it"  # (a backup's end: failure_off_way)
        if alert.device_id and any(each[0] is alert and each[2] for each in list(on_way.get(destination_id, {}).get(alert.device_id, ()))):
            return "Not sent: the trouble it ends was not sent there, a switch dropped it"
        if alert.device_id and not watch_ended_there(destination_id, alert):
            return "Not sent: the trouble it ends was not sent there, a switch dropped it"  # (a screen watch's: M2)
        if alert.device_id and alert.previous == alert.state and not knows(destination_id, alert.device_id):
            # (A reminder: it says the machine is as it was. Put behind a trouble that a switch dropped since, or that is over.)
            return "Not sent: a reminder of a trouble not known there, a switch dropped it or it is over"
        return None

    def done(destination_id: str, sent: list[alerts.Alert], ok: bool) -> None:
        """(alerts.Courier.) What was delivered to a destination, or given up on."""
        for alert in sent:
            if not alert.device_id and alert.event == "recovered":
                backup_end_settled(destination_id)
            elif not alert.device_id and alert.event == "backup":
                failure_off_way(destination_id, alert, told=True)
            elif alert.device_id:
                off_way(destination_id, alert)

    def dropped(destination_id: str, stopped: list[alerts.Alert]) -> None:
        """(alerts.Courier.) What a switch dropped of what waited for a destination: a backup's alert, by who is owed what; a
        machine's change, out of what the destination knows of the machine (untold); a screen watch's start, out of where it
        went (unwatched)."""
        for alert in stopped:
            if not alert.device_id and alert.event in ("backup", "recovered"):
                backup_dropped(destination_id, alert)
            elif alert.device_id:
                untold(destination_id, alert)
                unwatched(destination_id, alert)

    courier = alerts.Courier(destination_target, own_addresses, delivered, held_back, done, dropped)
    # A machine's changes on their way to a destination (destination id -> device id -> [[the alert as handed over, what the
    # destination knew of the machine before it (told_there), whether it is to go no more], ...], in the order they were
    # handed over): what a switch drops of them is taken back out of what the destination knows (untold), and forgotten
    # once delivered or given up on (done).
    on_way: dict[str, dict[str, list[list[Any]]]] = {}

    def off_way(destination_id: str, alert: alerts.Alert) -> tuple[list[Any], list[Any] | None] | None:
        """A machine's change no longer on its way to a destination, taken out of on_way: its place there, and that of the
        change of the machine handed over next, if any. None where it had none (a screen watch's, a reminder)."""
        ways = on_way.get(destination_id, {})
        chain = ways.get(alert.device_id, [])
        place = next((at for at, each in enumerate(chain) if each[0] is alert), None)
        if place is None:
            return None
        way = chain.pop(place)
        after = chain[place] if place < len(chain) else None
        if not chain:
            ways.pop(alert.device_id, None)
            if not ways:
                on_way.pop(destination_id, None)
        return way, after

    def untold(destination_id: str, alert: alerts.Alert) -> None:
        """(dropped.) A machine's change a switch dropped on its way to a destination: what the destination knows of the
        machine is what it knew before it, as where it was never handed over (destinations.noted, not told). Where that is no
        trouble told there, nothing reminds it of this one, and an end of it that waits behind it goes no more (held_back).
        (What it knows was written down as the change was handed over: a trouble dropped left it saying the trouble was told
        there, and once switched on again it was reminded of it, and told the machine was back to normal, of a trouble it never
        heard of. The final look at 0.4.0, M1.)"""
        taken = off_way(destination_id, alert)
        if taken is None or alert.event == "recovered" or alert.state not in TROUBLE:
            return  # (an end dropped: it knows nothing of the machine from then on, as when the end was handed over)
        (_, known, _), after = taken
        before = destinations.noted(known, alert, told=False) or ""  # (of a trouble: the trouble told there before, or "")
        if after is not None:
            # Handed over after it, as though it had been told: what that one knew before is this. An end of it goes no more
            # where nothing of the trouble was told there.
            if after[1] == alert.state:
                after[1] = before
                after[2] = after[2] or (after[0].event == "recovered" and not before)
            return
        book = told_there.get(destination_id)
        if book is not None and book.get(alert.device_id) == alert.state:
            book[alert.device_id] = before
            if not before:
                reminded.get(destination_id, {}).pop(alert.device_id, None)

    # Where a screen watch's start was handed over (device id -> watch -> [its start, the destinations it was handed to and
    # not dropped at, its end once that came]): its end goes there alone, and a start a switch dropped takes with it there its
    # end and its reminders. A start within a destination's quiet hours is not handed over there, and its end after them was
    # told there all the same, as one dropped by a switch was (the narrow look at 0.4.0, M2). In memory: after a restart, the
    # end of a watch that went off before it is told wherever it is heard, as before 0.4.0.
    watch_told: dict[str, dict[str, list[Any]]] = {}
    # A screen watch's end within the quiet hours of a destination its start went to (destination id -> the records of
    # watch_told whose end it is owed): told when they, and a pause, are over, where that watch is still over then; a watch
    # that goes off again before carries the destination over to its new record, which still knows the screen dark. (Lost
    # there, the start stayed the last word of the trouble: the outside review of 0.4.0, bugs round 2, M5.) In memory.
    quiet_ends: dict[str, list[list[Any]]] = {}

    def unwatched(destination_id: str, alert: alerts.Alert) -> None:
        """(dropped.) A screen watch's start a switch dropped on its way to a destination: its end goes no more there (held_back
        drops one that waits behind it), nor its reminders, where the destination knows no other trouble of the machine."""
        start = watch_told.get(alert.device_id, {}).get(alert.state)
        if start is None or start[0] is not alert:
            return
        start[1].discard(destination_id)
        if not knows(destination_id, alert.device_id):
            reminded.get(destination_id, {}).pop(alert.device_id, None)

    def watch_ended_there(destination_id: str, alert: alerts.Alert) -> bool:
        """Of a screen watch's end on its way to a destination (an alert of no other kind is no such end: True): whether its
        start went there, and was not dropped since."""
        start = watch_told.get(alert.device_id, {}).get(alert.previous)
        return start is None or start[2] is not alert or destination_id in start[1]

    def knows(destination_id: str, device_id: str) -> bool:
        """Whether a destination is said to know a trouble of a machine, which a reminder reminds it of: one told there
        (told_there), or a screen watch's "no signal" that went there and is not over (watch_told). (The narrow look at
        0.4.0, L4: untold() stopped the reminders still to come of a trouble a switch dropped, and not those already put
        behind it; switched on again before their turn, they went.)"""
        if told_there.get(destination_id, {}).get(device_id):
            return True
        start = watch_told.get(device_id, {}).get(screens.NO_SIGNAL)
        return start is not None and start[2] is None and destination_id in start[1]

    # A destination's quiet hours hold back what happens (destination id -> device id -> what it was when the first change
    # was held), and what is not so any more when they end is told then, as after a pause. In memory: a restart within them
    # forgets what was held. A screen watch that goes off within them is not told there.
    quiet_held: dict[str, dict[str, str]] = {}
    # What a destination with reminders was told is wrong (destination id -> device id -> (when first told, when last)).
    reminded: dict[str, dict[str, tuple[float, float]]] = {}

    def heard(one: DestinationRecord, alert: alerts.Alert, at: float | None = None) -> None:
        """A destination was sent this alert: what to remind it of from now on, or no more."""
        if not one.remind or not alert.device_id:
            return
        now = time.monotonic() if at is None else at
        mine = reminded.setdefault(one.id, {})
        if alert.state in TROUBLE and alert.event != "test":
            first = mine.get(alert.device_id, (now, now))[0]
            mine[alert.device_id] = (first, now)
        else:
            mine.pop(alert.device_id, None)

    told_there = watcher.heard  # destination id -> device id -> the trouble last told there (alerts.Watcher.heard)

    def deliver(one: DestinationRecord, alert: alerts.Alert, again: Callable[[str], alerts.Alert] | None, at: float | None = None) -> None:
        """A machine's change, to one destination as fitted for it (destinations.fitted: by what it was told before), and
        what it knows of the machine from now on."""
        book = told_there.setdefault(one.id, {})
        known = book.get(alert.device_id)
        made = destinations.fitted(one, alert, known, again)
        if made is not None:
            on_way.setdefault(one.id, {}).setdefault(alert.device_id, []).append([made, known, False])
            courier.put(one.id, made)
            heard(one, made, at)
        after = destinations.noted(known, alert, told=made is not None)
        if after is None:
            book.pop(alert.device_id, None)
        else:
            book[alert.device_id] = after

    def tell(alert: alerts.Alert, record: DeviceRecord | None, change: bool = True, again: Callable[[str], alerts.Alert] | None = None) -> None:
        """An alert, to each destination that asked to hear it about this machine. Never waits (alerts.Courier).
        `change`: it is a machine's change of state (not a screen watch's), which quiet hours hold back and tell afterwards;
        `again(previous)` describes it anew from another state, for a destination that was told another one last. A screen
        watch's end goes where its start went (watch_told)."""
        now = time.localtime()
        watch: list[Any] | None = None  # (a screen watch's start or end: its record in watch_told; None for an end not known)
        if not change and alert.event != "recovered":
            watch = [alert, set(), None]
            before = watch_told.setdefault(alert.device_id, {}).get(alert.state)
            watch_told[alert.device_id][alert.state] = watch
            for destination_id, owed in quiet_ends.items():
                if any(each is before for each in owed):  # (told of the dark screen before, and not that it was over: it still knows it)
                    owed[:] = [each for each in owed if each is not before]
                    watch[1].add(destination_id)
        elif not change and (watch := watch_told.get(alert.device_id, {}).get(alert.previous)) is not None:
            watch[2] = alert  # (an end comes once: the next start makes a new record)
        for one in store.destinations:
            if not one.enabled or one.kind not in destinations.KINDS:
                continue
            if record is not None and not destinations.covers(one, record.id, record.group):
                continue
            if destinations.quiet(one, now):
                if change and record is not None:
                    quiet_held.setdefault(one.id, {}).setdefault(record.id, alert.previous)
                elif watch is not None and watch[2] is alert and one.id in watch[1] and destinations.passes(one, alert):
                    quiet_ends.setdefault(one.id, []).append(watch)  # (its start went there: its end is told when they end)
                continue
            if change and alert.device_id:
                deliver(one, alert, again)
            elif destinations.passes(one, alert) and (watch is None or watch[0] is alert or one.id in watch[1]):
                courier.put(one.id, alert)
                heard(one, alert)
                if watch is not None and watch[0] is alert:
                    watch[1].add(one.id)

    def told_later(paused: bool) -> None:
        """At each look: what quiet hours that ended held back, where it is not as it was; and the reminders that are due."""
        if paused:
            return
        local, now = time.localtime(), time.monotonic()
        for one in list(store.destinations):
            if destinations.quiet(one, local) or not one.enabled or one.kind not in destinations.KINDS:
                continue
            for device_id, before in quiet_held.pop(one.id, {}).items():
                live, record, state = manager.devices.get(device_id), store.device(device_id), watcher.state(device_id)
                if live is None or record is None or not record.alerts or state is None or state == before:
                    continue  # (what went wrong and was put right within them is nobody's news there)
                alert = alert_for(device_id, live, before, state)
                if alerts.wanted(alert, store.alerts) and destinations.covers(one, device_id, record.group):

                    def anew(previous: str, live: Device = live, state: str = state, device_id: str = device_id) -> alerts.Alert:
                        return alert_for(device_id, live, previous, state)

                    deliver(one, alert, anew, now)
            for watch in quiet_ends.pop(one.id, []):
                end = watch[2]
                live, record = manager.devices.get(end.device_id), store.device(end.device_id)
                if live is None or record is None or not record.alerts or watch_told.get(end.device_id, {}).get(end.previous) is not watch:
                    continue  # (off the wall, its alerts off, or a watch begun anew since: that one is told as it comes)
                if one.id in watch[1] and store.alerts.recovered and destinations.passes(one, end) and destinations.covers(one, end.device_id, record.group):
                    courier.put(one.id, end)  # (over still: the screen is back)
                    heard(one, end, now)
            for device_id, (first, last) in list(reminded.get(one.id, {}).items()):
                if now - last < max(one.remind, 1) * REMINDER_MINUTE:
                    continue
                live, record, state = manager.devices.get(device_id), store.device(device_id), watcher.state(device_id)
                if live is None or record is None or not record.alerts or state not in TROUBLE or not one.remind:
                    reminded[one.id].pop(device_id, None)
                    continue
                alert = alert_for(device_id, live, state, state)
                alert.title = f"Still: {alert.title}"
                alert.text = f"{alert.text} For {alerts.lasted(now - first)} now.".strip()
                if destinations.passes(one, alert) and destinations.covers(one, device_id, record.group):
                    courier.put(one.id, alert)
                reminded[one.id][device_id] = (first, now)

    # The activity log's daily seal (chain.py): its head, to the destinations whose "Daily seal of the activity log" is ticked,
    # through the alerts' own way out (the courier: its outbound rules, its retries, its delivery log), as a message that is no
    # trouble. A seal is written for it (why "daily"), and what is sent is its number and head: no secret, nothing of what the
    # log says. Kept there, a head shows a later rewrite of the log up to it, even by someone who holds the wall's key.
    sealed_to: dict[str, float] = {}  # destination id -> monotonic time it was last sent a seal

    async def log_seals() -> None:
        await asyncio.sleep(LOG_SEAL_FIRST)
        while True:
            try:
                await seal_to_destinations()
            except Exception:  # a failed round must not be the last one
                log.exception("the activity log's seal could not be sent to the alert destinations")
            await asyncio.sleep(LOG_SEAL_LOOK)

    async def seal_to_destinations() -> None:
        now, local = time.monotonic(), time.localtime()
        due = [
            one for one in store.destinations
            if one.log_seal and one.enabled and one.kind in destinations.KINDS and one.kind != "pagerduty"
            and now - sealed_to.get(one.id, -LOG_SEAL_EVERY) >= LOG_SEAL_EVERY and not destinations.quiet(one, local)
        ]  # fmt: skip
        if not due or core.audit.key is None:
            return
        place = await asyncio.to_thread(core.audit.sealed, "daily")
        if place is None:
            return  # (not written: the disk refused it, and the log says so; tried again at the next look)
        number, head = place
        said = f"qKVM activity log seal: line {number} head {head.hex()}"
        text = "Keep this message. With it, python -m qkvm.checklog --heads shows any later rewrite of the activity log up to this line."
        for one in due:
            courier.put(one.id, alerts.Alert("log_seal", "qKVM", "", "", "", said, text, event="log_seal"))
            sealed_to[one.id] = now

    # --- alerts by Web Push (webpush.py): the wall's key, and the browsers each account has them told to ---------------
    push_opened: list[Any] = [None, None]  # the sealed key last opened, and what it opened as

    def push_key() -> webpush.WallKey | None:
        """The wall's key for Web Push. None where it is not made yet, the saved passwords are locked, or it does not open."""
        blob = store.alerts.push_key
        if blob is None or not core.vault.unlocked:
            return None
        if push_opened[0] is not blob:
            text = core.vault.read(blob, PUSH_KEY_FOR)
            try:
                opened = webpush.WallKey(text) if text is not None else None
            except ValueError:
                opened = None
            if opened is None:
                log.error("the wall's key for push does not open (the settings file was edited, or is damaged): no browser is told the alerts")
            push_opened[:] = [blob, opened]
        key: webpush.WallKey | None = push_opened[1]
        return key

    def push_target(record: PushRecord) -> webpush.Target | None:
        """A browser's subscription, opened from the vault. None where it does not open, or the saved passwords are locked."""
        if record.secret is None or not core.vault.unlocked:
            return None
        text = core.vault.read(record.secret, f"push:{record.id}")
        try:
            said = json.loads(text) if text is not None else None
            subscription = webpush.check(said["endpoint"], said["p256dh"], said["auth"])  # type: ignore[index]
        except (ValueError, TypeError, KeyError, RecursionError):
            return None
        return webpush.Target(record.id, subscription)

    async def push_gone(push_id: str) -> None:
        """A browser its push service says is no longer subscribed (it was unsubscribed there, or its site data cleared):
        taken off the list, in the turn of changes."""
        async with one_change:
            record = next((p for p in store.pushes if p.id == push_id), None)
            if record is None:
                return
            place = store.pushes.index(record)
            store.pushes.remove(record)
            try:
                await save()
            except OSError as ex:
                store.pushes.insert(place, record)  # (asked again at its next alert, which is told the same)
                log.error("a browser that is no longer subscribed could not be taken off the list: %s", ex)
                return
        pusher.told.pop(push_id, None)
        core.audit.write("push_removed", "", account=account_named(record.user), browser=record.name, why="gone")

    def push_allowed(push_id: str, device_id: str | None) -> bool:
        """Whether a browser may be told an alert about this machine now: alerts switched on, its record there, its account
        there, not suspended, and the machine one it may see (asked before each attempt and right before it goes:
        webpush.Pusher; what it says no to is dropped). A pause is not asked: it stops new alerts only (announce), and one
        already on its way to a browser goes, as one on its way to a destination does (held_back)."""
        if not store.alerts.enabled:
            return False  # (the fresh review of the fixes, N3: one waiting to be tried again went out after they were switched off)
        record = next((one for one in store.pushes if one.id == push_id), None)
        user = store.user(record.user) if record is not None else None
        return user is not None and not user.suspended and (device_id is None or may_see(user, device_id))

    pusher = webpush.Pusher(push_key, push_gone, push_allowed)

    def push_out(alert: alerts.Alert, device_id: str) -> None:
        """An alert about this machine, to every browser subscribed for an account that may see it: put in for each, never
        waited for (the browsers' own tasks send it, webpush.Pusher)."""
        if not store.pushes or push_key() is None:
            return
        said = webpush.payload(alert, device_id)
        for record in store.pushes:
            user = store.user(record.user)
            if user is None or user.suspended or not may_see(user, device_id):
                continue
            if (target := push_target(record)) is not None:
                pusher.put(target, said, webpush.urgency(alert.kind), device_id)

    held = watcher.held  # device id -> what it was before it changed while alerts were paused

    def pausing() -> bool:
        """Whether alerts are paused at this moment.

        The end of a pause is a date, and is saved. A computer whose clock was far ahead when the pause was
        made, and has been put right since, would otherwise stay silent for as long as its clock was wrong:
        no pause is longer than the longest that can be asked for.
        """
        return 0 < store.alerts.paused_until - time.time() <= LONGEST_PAUSE * 60

    def alert_for(device_id: str, device: Device, previous: str, state: str) -> alerts.Alert:
        """What is said of a device that went from `previous` to `state`, by what it shows now; with its link."""
        detail = str(((device._status or {}).get("error") or {}).get("message") or "")
        address = urlsplit(device.spec.base_url).netloc
        atx = (device._status or {}).get("atx")
        off = isinstance(atx, dict) and atx.get("enabled") is True and atx.get("power") is False  # (its power board says so)
        code = str(((device._status or {}).get("error") or {}).get("code") or "")
        alert = alerts.describe(device.spec.name, address, previous, state, detail, server=not device.picture, off=off, device_id=device_id, code=code)
        alert.link = alerts.link_for(store.alerts.link, device_id)
        return alert

    def announce(device_id: str, device: Device, previous: str, state: str, paused: bool) -> None:
        """Tell whoever is to be told that a device went from `previous` to `state`."""
        record = store.device(device_id)
        alert = alert_for(device_id, device, previous, state)
        if not alerts.wanted(alert, store.alerts) or (record is not None and not record.alerts):
            return
        if record is not None and device.picture and screens.minutes(record.no_signal_minutes) and (state == "no_signal" or (previous, state) == ("no_signal", "online")):
            return  # its screen is watched for no signal: that is told by the watch, after its minutes (see `watch_screens`)
        if paused:
            # Not sent, and not forgotten: when the pause is over, what is not as it was before it is told.
            held.setdefault(device_id, previous)
            core.audit.write("alert", "", device=alert.device, device_id=device_id, state=alert.state, was=alert.previous, held=True)
            return
        core.audit.write("alert", "", device=alert.device, device_id=device_id, state=alert.state, was=alert.previous)
        log.info("alert: %s (%s -> %s)", alert.title, alert.previous, alert.state)
        # Delivered from there: the watching does not wait for somebody else's server. Each destination is told as fitted for
        # it (a machine told there as offline that answers again without a picture is no news there: destinations.fitted).
        tell(alert, record, again=lambda before: alert_for(device_id, device, before, state))
        if (previous, state) != ("offline", "no_signal"):
            push_out(alert, device_id)  # ...nor for a push service (a browser was told it was offline: no picture lost)

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
        told_later(paused)
        for (device_id, device), state in zip(watched, states, strict=True):
            if manager.devices.get(device_id) is not device:
                continue  # edited or removed while it was being looked at: what it said no longer counts
            if isinstance(state, BaseException):  # one KVM's trouble must not stop the others being watched
                log.error("%s: could not be checked: %r", device.spec.name, state)
                continue
            change = watcher.observe(device_id, state)
            if change is not None:
                announce(device_id, device, *change, paused=paused)

    screen_watch = core.screens  # kept with the program, as the watcher is

    async def watch_screens() -> None:
        """After a look: the screens of the machines that have a watch on them (screens.py), told through the alerts."""
        paused = pausing()
        watched = []
        for device_id, device in manager.devices.items():
            record = store.device(device_id)
            if record is None or not record.alerts or not device.picture:
                continue
            dark, same = screens.minutes(record.no_signal_minutes), screens.minutes(record.unchanged_minutes)
            if dark or same:
                watched.append(screens.Watched(device_id, watcher.state(device_id), dark, same))
        for event in await screen_watch.round(watched, set(manager.devices), paused):
            live, record = manager.devices.get(event.device_id), store.device(event.device_id)
            if live is None or record is None:
                continue  # removed meanwhile
            address = urlsplit(live.spec.base_url).netloc
            alert = alerts.describe_watch(live.spec.name, address, event.watch, event.minutes, event.back, event.lasted, kept=bool(event.stamp), device_id=event.device_id)
            if event.back and not store.alerts.recovered:
                continue  # (what is over is told where the admin asked to hear what is back to normal)
            picture = {"picture": event.stamp, "picture_at": round(event.picture.at, 3)} if event.stamp and event.picture is not None else {}
            core.audit.write(
                "alert", "", device=alert.device, device_id=event.device_id, state=alert.state, was=alert.previous, watch=event.watch,
                minutes=event.minutes, **({"back": True} if event.back else {}), **picture,
            )  # fmt: skip
            alert.link = alerts.link_for(store.alerts.link, event.device_id)
            log.info("alert: %s", alert.title)
            tell(alert, record, change=False)
            push_out(alert, event.device_id)

    async def book_written() -> None:
        """What each machine is taken to be, and what each destination knows of it, written down where it changed, for the
        start after this one: after each look, and whatever the switches say, as a switch that drops a trouble on its way
        changes what its destination knows (untold). Written after a look alone, that was lost by a restart made while
        alerts were switched off, and the trouble dropped came back as told there (the narrow look at 0.4.0, M1)."""
        try:
            if (text := watcher.to_write()) is not None:
                await asyncio.to_thread(watcher.write, text)
        except Exception:
            log.exception("what the machines were last seen as could not be written down")

    async def watch() -> None:
        """Notice KVMs changing state, also while nobody has the wall open."""
        while True:
            await asyncio.sleep(alerts.CHECK_EVERY)
            if not (store.alerts.enabled and core.vault.unlocked):
                try:
                    # (The pictures kept for screen alerts go with time and with their machine all the same: by the
                    # settings' machines, which are there while the saved passwords are locked.)
                    await screen_watch.sweep({record.id for record in store.devices})
                except Exception:
                    log.exception("the pictures kept for screen alerts could not be looked through")
            else:
                try:
                    await look()
                    await watch_screens()
                except Exception:  # whatever goes wrong in one look must not end the watching
                    log.exception("the KVMs could not be checked for changes")
            await book_written()

    def keep_unlocked() -> bool:
        """While alerts are on, or metrics are collected, the KVMs are watched after the last person signs out too.

        And always where qKVM has a key that opens the saved passwords at start (its own, or an unlock
        file's): what opens them is on this computer anyway, and forgetting them here would only mean
        opening them again. And while backups are on: a run by the clock seals with the backup key, which
        the vault keeps (backup.py), at an hour nobody is signed in.
        """
        return store.alerts.enabled or bool(store.server.metrics_token) or core.unlock_secret is not None or store.backups.enabled

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
    release_check: asyncio.Task[None] | None = None  # the release check a round set going (see check_for_updates)

    async def check_for_updates() -> None:
        """The daily release check: set going by a round, never waited for by one. It downloads the release's package to
        judge it (update.Updater._judge), on a line that may be slow, and the round is what locks the saved passwords."""
        try:
            await core.updater.check()
        except UpdateError:
            core.updater.checked_at = time.time()  # try again tomorrow, not every half minute
        except Exception:  # (said, as when it was a part of the round)
            log.exception("the release check failed")

    async def keep_house() -> None:
        nonlocal moved_to, release_check
        # (Not while the first account is being made: its key is there before anybody is signed in with it,
        # and taken away in that moment, setup would end signed in to a wall whose saved passwords are shut.)
        if core.vault.unlocked and len(core.sessions) == 0 and not keep_unlocked() and not setting_up.locked():
            # Nobody is signed in any more: forget the key and the KVM sessions.
            core.vault.lock()
            await manager.close()
        manager.tidy()
        updater = core.updater
        stale = updater.checked_at is None or time.time() - updater.checked_at > UPDATE_CHECK_EVERY
        if store.server.update_check and updater.repo and stale and updater.state != "ready" and (release_check is None or release_check.done()):
            release_check = asyncio.create_task(check_for_updates())
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

    async def tailscale_certificate() -> None:
        """Tailscale's certificate for this computer's name (--tls-tailscale, tailcert.py): asked for again when it is due, and
        served from the next connection on where it is another. Nothing where it was not asked for."""
        held = core.tailscale_cert
        if held is None:
            return
        while True:
            try:
                wait = held.due()
            except Exception:  # (when it is due is guarded as the ask is: an error there ended the asking for good before)
                log.exception("when to ask for Tailscale's certificate again could not be worked out")
                wait = tailcert.RETRY_MOST
            await asyncio.sleep(wait)
            try:
                await held.renew()
            except Exception:  # a failed ask must not be the last one
                log.exception("Tailscale's certificate could not be asked for")

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
    # A check of its chain (chain.py: the routes beside its download): the one under way and its walk, and the last one's result.
    log_check: dict[str, Any] = {"task": None, "walk": None, "began": None, "by": "", "kept": None}
    # Where its chain had come to, kept in the sealed settings at each seal (chain.py; H1 of the review of wave 2): told by the
    # writer's thread, kept on the event loop, saved in turn. Never moved back: a seal told late changes nothing.
    loop_of: list[asyncio.AbstractEventLoop] = []  # (the wall's event loop, from its start)

    def keep_position(number: int, head: bytes) -> bool:
        """(On the event loop.) Where the chain had come to, into the settings, where it is further on than they say; True if so."""
        kept = position_of(store.activity_position)
        if kept is not None and kept[0] >= number:
            return False
        said = {"n": number, "head": head.hex()}
        if position_of(said) is None:
            # Never one the settings would not read back (a number past 2**63): kept, the next start found them damaged, both
            # copies, and the wall did not start (the re-review of wave 2, N1). The writer gives no such number now; this holds
            # whatever comes.
            log.error("the activity log's chain is at a line no settings keep (%d): its place is not kept", number)
            return False
        store.activity_position = said
        return True

    async def save_position() -> None:
        try:
            await save_in_turn()
        except OSError as ex:
            log.error("where the activity log's chain had come to could not be saved with the settings: %s", ex.strerror or ex)

    def sealed_now(number: int, head: bytes) -> None:
        if keep_position(number, head):
            task = asyncio.create_task(save_position())
            background.add(task)
            task.add_done_callback(background.discard)

    def sealed(why: str, number: int, head: bytes) -> None:
        """(In the writer's thread.) A seal was written: its place kept, on the event loop."""
        if not loop_of:
            return
        try:
            loop_of[0].call_soon_threadsafe(sealed_now, number, head)
        except RuntimeError:
            pass  # (the loop has ended: the stop seal's place was kept by the lifespan itself)

    core.audit.on_sealed = sealed
    check_halt = threading.Event()  # (set as the wall stops: a check under way ends there)

    def account_named(user_id: str) -> str:
        """An account's name as its entries carry it, by its id (a token's with " (token)"); the id where it is gone."""
        if user_id.startswith("token:"):
            token = next((t for t in store.tokens if f"token:{t.id}" == user_id), None)
            return f"{token.name} (token)" if token is not None else user_id
        user = store.user(user_id)
        return user.name if user is not None else user_id

    def said_left_out() -> None:
        """What the activity log's allowances left out and no later entry of the account said yet, said as the listeners end
        (the network settings changed, or qKVM stopping), in an entry of its own each (`of`: "live" for live views, or the
        event of a server's console; `unsaid`: how many): it waited in memory for the account's next entry, and was lost at a
        restart (register row 22 of 0.2.1). After a power cut it is lost all the same."""
        counts = [("live", lines.left_out()), *((event, allowance.left_out()) for event, allowance in console_said.items())]
        for of, left_out in counts:
            for who, unsaid in left_out.items():
                audit.write("activity_left_out", "", user=account_named(who), of=of, unsaid=unsaid)

    # --- backups of the whole wall to a folder (backup.py) -----------------------------------------------------------
    # Made by the clock at the hour set, or by "Back up now"; one at a time. The backup key is opened from the vault for the
    # run and handed to the worker thread alone; it is never written, logged or answered. A run that fails is said in the
    # activity log, in Settings and to the destinations that ask for "backup"; the first run that succeeds after one that
    # failed, to those that were told, as over.
    backup_turn = asyncio.Lock()
    backup_task: list[asyncio.Task[dict[str, Any]] | None] = [None]
    clock_said: list[float] = [0.0]  # the moment due by the clock that was said not to have been started (one run was going)
    stuck_said = [False]  # said that the clock begins none while a run cut off by its bound goes on (once, until it ends)
    waiting_told = [0.0]  # the hour at which it was last told what runs cut off still wait for (once a day, at the hour)
    # Destination id -> a backup's failure a pause or its quiet hours held back: told when they end where backups still fail,
    # and not at all once they are made again. In memory: a restart within them forgets it (the next run that fails is told).
    backup_owed: dict[str, alerts.Alert] = {}
    backup_sending: set[str] = set()  # destinations a backup's end is on its way to: owed it (told) until it is delivered
    # Destination id -> [the failures on their way there (as handed over), whether it was told of one before them and not
    # since that backups are made again]: a failure a switch drops takes back what it put on the told list and no more (the
    # outside review of 0.4.0, bugs round 2, M2: only the last hand-over was remembered, and two dropped left it owed an end).
    backup_going: dict[str, list[Any]] = {}
    # (Who was told that a backup failed, and not yet that one was made again, is kept with the backups' settings: told
    # = store.backups.told, saved, so that it is told after a restart too: the outside review of 0.4.0, bugs round, M3.)

    def told_so(destination_id: str, failed: bool) -> None:
        told = store.backups.told
        if failed and destination_id not in told:
            told.append(destination_id)
        elif not failed and destination_id in told:
            told.remove(destination_id)

    def backup_key() -> bytes:
        """The backup key, opened from the vault for a run. BackupError where there is none, or it cannot be opened now."""
        sealed = store.backups.secret
        if sealed is None:
            raise backup.BackupError("no_key", "No backup key has been made yet: make one in Settings > Backups (its recovery kit is shown once)")
        if not core.vault.unlocked:
            raise backup.BackupError("locked", "The saved passwords are locked, and the backup key with them: qKVM was started with --locked-start and nobody has signed in since")
        text = core.vault.read(sealed, backup.SEALED_FOR)
        try:
            key = bytes.fromhex(text or "")
        except ValueError:
            key = b""
        if len(key) != backup.KEY_BYTES:
            raise backup.BackupError("no_key", "The saved backup key does not open (the settings file was edited, or is damaged): make a new key")
        return key

    def backup_failure(ex: BaseException) -> str:
        """Why a run made no backup, in a sentence: never more of a file or a key than its name."""
        if isinstance(ex, backup.BackupError):
            return ex.message
        if isinstance(ex, OSError):
            where = f": {ex.filename}" if getattr(ex, "filename", None) else ""
            return f"{ex.strerror or type(ex).__name__}{where}"
        if isinstance(ex, MemoryError):
            return "there was not enough memory for it"
        if isinstance(ex, VaultLocked):
            return "the saved passwords are locked just now"
        return str(ex) or type(ex).__name__

    def backup_alert(failed: bool, said: str) -> alerts.Alert:
        if failed:
            last = store.backups.last_good
            before = f" The last backup made is from {time.strftime('%Y-%m-%d %H:%M', time.localtime(last))}." if last else " No backup has been made yet."
            alert = alerts.Alert("backup", "qKVM", "", "backup_failed", "backup_ok", "Backup failed", f"No backup was made: {said}{before}", event="backup")
        else:
            alert = alerts.Alert("recovered", "qKVM", "", "backup_ok", "backup_failed", "Backups are made again", f"A backup was made: {said}.", event="recovered")
        alert.link = store.alerts.link
        return alert

    def tell_backup(alert: alerts.Alert, only: set[str] | None = None) -> bool:
        """A backup's alert, to each destination that asks for it (the one that it is over, to those told that it failed).
        Nothing while alerts are off. A pause, or a destination's quiet hours, hold it as they hold a machine's change: a
        failure is owed there (backup_owed) and told when they end where backups still fail (tell_owed); that it is over goes,
        when they end, to whoever was told that it failed (the told list). True where it was handed to a destination at once.
        `only`: to these destinations alone. (In the turn of changes, before the save that keeps who was told.)"""
        if not store.alerts.enabled:
            return False
        failed, now, told, paused = alert.event == "backup", time.localtime(), False, pausing()
        for one in store.destinations:
            if only is not None and one.id not in only:
                continue
            if not failed and one.id not in store.backups.told:
                backup_owed.pop(one.id, None)  # (what was held back and never told is over: nothing to tell there)
                continue
            if not failed and one.id in backup_sending:
                continue  # (its end is on its way there already)
            if not one.enabled or one.kind not in destinations.KINDS or not destinations.passes(one, alert):
                if not failed:
                    told_so(one.id, False)  # (nothing to close where it is not told: not owed for ever)
                backup_owed.pop(one.id, None)
                continue
            if paused or destinations.quiet(one, now):
                if failed:
                    backup_owed[one.id] = alert
                else:
                    backup_owed.pop(one.id, None)  # (owed its end, on the told list: told when they end, tell_owed)
                continue
            backup_owed.pop(one.id, None)
            backup_handed(one.id, alert)
            told = True
        if not failed:  # (and none owed to a destination that is no more)
            there = {one.id for one in store.destinations}
            store.backups.told[:] = [each for each in store.backups.told if each in there]
        return told

    def tell_owed() -> None:
        """What a pause or quiet hours held back of the backups, told where they are over: a failure where backups still fail
        (once they are made again, nothing: the last look, M2), and that backups are made again to whoever was told that they
        failed (after a restart too: the told list is saved). (In the turn of changes, before the save that keeps who was
        told.)"""
        kept = store.backups
        if kept.last_ok:
            backup_owed.clear()  # (a failure held back is over: nobody's news)
            if kept.told and (owed := set(kept.told) - backup_sending):
                tell_backup(backup_alert(False, kept.last_name or "the last one"), only=owed)
            return
        # (Backups fail again: what is owed is a failure. Who was told of one before, and not yet that it was over, is owed
        # its end still, of this one.)
        now = time.localtime()
        for destination_id, alert in list(backup_owed.items()):
            one = destination(destination_id)
            if one is None or not one.enabled or not store.alerts.enabled:
                backup_owed.pop(destination_id, None)
            elif not destinations.quiet(one, now) and not pausing():
                backup_owed.pop(destination_id, None)
                backup_handed(one.id, alert)

    def backup_handed(destination_id: str, alert: alerts.Alert) -> None:
        """A backup's alert handed to a destination: one that it failed, and it is owed the end from now on; one that it is
        over, and it is owed it still until it is delivered (backup_end_settled): lost with a restart while it waited to be
        tried again, the incident a failure opened stayed open (the fresh review of the fixes, N2)."""
        courier.put(destination_id, alert)
        if alert.event == "backup":
            going = backup_going.setdefault(destination_id, [[], destination_id in store.backups.told])
            going[0].append(alert)
            told_so(destination_id, True)
        else:
            backup_sending.add(destination_id)

    def backup_end_settled(destination_id: str) -> None:
        """(done.) A backup's end delivered to a destination, or given up on: owed no more there, unless a failure was handed
        to it since (that one is owed its end, once it is told there). Saved."""
        backup_sending.discard(destination_id)
        if (going := backup_going.get(destination_id)) is not None:
            going[1] = False
        elif destination_id in store.backups.told:
            told_so(destination_id, False)
            told_changed()

    def failure_off_way(destination_id: str, alert: alerts.Alert, told: bool) -> None:
        """(done, dropped.) A backup's failure no longer on its way to a destination: `told` there (delivered, or given up on),
        or not (a switch dropped it). Once none is on its way, the destination is owed the end where one was told there,
        before them or of them, and not since that backups are made again; else it is owed nothing. Saved."""
        going = backup_going.get(destination_id)
        if going is None or not any(each is alert for each in going[0]):
            return
        going[0] = [each for each in going[0] if each is not alert]
        going[1] = going[1] or told
        if going[0]:
            return
        del backup_going[destination_id]
        if not going[1] and destination_id in store.backups.told:
            told_so(destination_id, False)
            told_changed()

    def backup_dropped(destination_id: str, alert: alerts.Alert) -> None:
        """(dropped.) A backup's alert dropped on its way to a destination, by a switch. Its end: still owed there where alerts
        were switched off (told by the clock once they are on again), and owed nothing where the destination itself was. A
        failure: not told, so it takes back what it put on the told list (failure_off_way)."""
        one = destination(destination_id)
        if alert.event == "recovered":
            backup_sending.discard(destination_id)
            if (one is None or not one.enabled or switched_since(destination_id, alert, destination_id)) and destination_id in store.backups.told:
                told_so(destination_id, False)
                told_changed()
            return
        failure_off_way(destination_id, alert, told=False)

    def told_changed() -> None:
        """Who is owed a backup's end changed outside the turn of changes: saved in its turn."""

        async def save_told() -> None:
            try:
                await save_in_turn()
            except OSError as ex:
                log.error("who was told of the backups could not be saved with the settings: %s", ex.strerror or ex)

        task = asyncio.create_task(save_told())
        background.add(task)
        task.add_done_callback(background.discard)

    def backup_work(key: bytes, settings: dict[str, Any], data_key: bytes, folder: Path, keep: int, with_history: bool) -> tuple[backup.Made, int]:
        """(A worker thread.) The history copied where asked for, the activity log's files opened, the backup made."""
        # This run's copy of the history has a name of its own, held before the copy is made; what runs before left of theirs
        # (stopped with the wall) is taken away, but never a copy a run still holds (one its hour cut off, waiting for its
        # folder, or one begun after this one: core.backup_copies), judged as each is taken away, under the lock its name is
        # held under. (The names held as it began were judged by: cut off between the two, a run went on to take away the copy
        # of one begun after it, which failed. The outside review of 0.4.0, bugs round 2, M1.)
        with core.backup_copies_lock:
            number = time.time_ns()
            while (copy := core.data_dir / backup.HISTORY_COPY.format(number)).name in core.backup_copies:
                number += 1
            core.backup_copies.add(copy.name)
        try:
            for entry in os.scandir(core.data_dir):  # (no lock held while the folder is looked through)
                if backup.HISTORY_COPIES.fullmatch(entry.name) and entry.is_file(follow_symlinks=False):
                    with core.backup_copies_lock, suppress(OSError):
                        if entry.name not in core.backup_copies:
                            Path(entry.path).unlink()
            has_history = False
            for attempt in range(3 if with_history else 0):
                try:
                    has_history = core.history.copy_to(copy)
                    break
                except history.NotReadable:
                    if attempt == 2:
                        raise
                    copy.unlink(missing_ok=True)
                    time.sleep(HISTORY_AGAIN)  # (a checkpoint of its own holds it for a moment: asked again, as a read of the page is)
            with backup.log_files(core.audit) as logs:
                made = backup.make(folder, key, settings=settings, data_key=data_key, logs=logs, history=copy if has_history else None, program=__version__, keep=keep)
            return made, backup.others(folder, backup.key_id(key))
        finally:
            copy.unlink(missing_ok=True)
            with core.backup_copies_lock:
                core.backup_copies.discard(copy.name)

    def folder_fit(folder: str) -> None:
        """BackupError where backups cannot go to this folder, by how it is written (the disk is asked nothing)."""
        if not folder or not Path(folder).is_absolute():
            raise backup.BackupError("no_folder", "No folder is set for the backups")
        if backup.spelled_inside(folder, core.data_dir):  # (as a save refuses it: backups there would go with it)
            raise backup.BackupError("no_folder", "The backups' folder is in the data folder, and backups there would go with it: choose a folder elsewhere")

    def of_now(run: backup.Run) -> bool:
        """Whether a run was made for the backups as they are set up now (the folder they go to, the key they are sealed with):
        only then is its end their last run, their latest backup and what the clock's next is counted from."""
        kept = store.backups
        return backup.place_of(run.folder) == backup.place_of(kept.folder) and run.key == kept.key_id

    def not_finished(within: float) -> str:
        return f"The backup did not finish within {alerts.lasted(within)}: its folder does not answer (a share whose server is gone?)"

    async def back_up(by_the_clock: bool) -> dict[str, Any]:
        """One run, start to end: what it made, or why it made none, kept in the settings and said."""
        async with backup_turn:
            how = "by the clock" if by_the_clock else "by hand"
            began = time.time()
            kept = store.backups
            run = backup.Run(kept.folder, kept.key_id, how=how, began=began)  # (what it is for until it is taken with its settings, below)
            made: tuple[backup.Made, int] | None = None
            outcome: dict[str, Any]
            try:
                folder_fit(kept.folder)
                backup_key()  # (none, or none that opens: said before a seal is written for nothing)
                # A seal of the activity log first, waited for: the files taken after it hold it, and the settings taken after it
                # hold every change it follows (their place of the chain), so that the restored log checks as it did, up to that
                # line and past it.
                place = await asyncio.to_thread(core.audit.sealed, "backup")
                # Then, at one moment in the turn of changes (never one half made, which its save may yet take back): what the run
                # is for, its key, and the settings it holds with the data key that opens them. A key made new while the seal was
                # waited for is this run's key: nothing taken after a new kit was shown goes into a backup the kit before opens
                # (the outside review of 0.4.0, H1). A change refused meanwhile is none of the run's. Work on the folder, which
                # may never end, is outside the turn.
                async with one_change:
                    kept = store.backups
                    run = backup.Run(kept.folder, kept.key_id, min(365, max(1, kept.keep)), kept.history, how, began)
                    folder_fit(run.folder)
                    key = backup_key()
                    snapshot = store.snapshot()
                    data_key = core.vault.held_key()
                if place is not None:
                    snapshot["activity_position"] = {"n": place[0], "head": place[1].hex()}
                # On the folder's own threads, bounded: a folder that never answers holds a thread of those, and the run is said
                # to have failed after BACKUP_STUCK all the same, alerted, and the next can begin. The bound is the run's own,
                # kept with it by the program: listeners opened anew meanwhile say it once it has come (overdue_runs).
                ended = await core.backup_runs.run(
                    BACKUP_STUCK, backup_work, key, snapshot, data_key, Path(run.folder), run.keep, run.history,
                    late=functools.partial(ended_late, run), folder=run.folder, for_run=run,
                )
            except backup.FolderTimeout:  # (the run's bound; a folder's own ETIMEDOUT is an OSError, said as the folder's below)
                outcome = {"ok": False, "error": not_finished(BACKUP_STUCK)}
            except backup.FolderHeld as ex:
                # Its folder held by a run before, by this name or another for the same folder (found out on its thread): not
                # begun, which is no failed run, and said so (Back up now answers it as busy; the clock says it once).
                why = RUN_STILL_WAITING if ex.holder.cut_off else "A backup is being made into this folder just now"
                audit.write("backup_not_started", "", why=why, how=how, folder=run.folder)
                log.warning("a backup was not begun: %s", why)
                return {"ok": False, "error": why, "held": True}
            except (backup.BackupError, OSError, VaultLocked, history.NotReadable, MemoryError, ValueError) as ex:
                outcome = {"ok": False, "error": backup_failure(ex)[:500]}
            except Exception as ex:
                # Of no kind foreseen: a failed run all the same, kept and said as every other (left to escape, it was kept
                # nowhere, and the clock began another at every look). Said by its kind; its words, which may hold anything, go
                # to the program's log alone.
                log.exception("a backup could not be made")
                outcome = {"ok": False, "error": f"an error inside qKVM ({type(ex).__name__}); the details are in its log"}
            else:
                made = ended
                outcome = {"ok": True, "name": ended[0].name, "size": ended[0].size}
            await run_ended(run, outcome, began, made)
            return outcome

    async def run_ended(run: backup.Run, outcome: dict[str, Any], began: float, made: tuple[backup.Made, int] | None) -> None:
        """How a run ended, kept and said: in the activity log, with the folder it was made for, always; as Settings' last run,
        their latest backup and what the clock's next run is counted from, and to the alert destinations, only where it was
        made for the backups as they are set up now (the outside review of 0.4.0, M1: a run still writing into the folder
        before was the new folder's latest, which Verify looked for there and did not find, and it moved the next run on)."""
        told = False
        async with one_change:
            kept = store.backups
            current = of_now(run)
            was_ok = kept.last_ok
            if current:
                kept.last_at, kept.last_ok, kept.last_error = time.time(), outcome["ok"], outcome.get("error", "")
                if made is not None:  # (the backup last made, its size and its folder: kept through runs that make none)
                    kept.last_good, kept.others, kept.last_name, kept.last_size, kept.last_folder = began, made[1], made[0].name, made[0].size, run.folder
                    if not was_ok:
                        tell_backup(backup_alert(False, made[0].name))
                else:
                    told = tell_backup(backup_alert(True, outcome["error"]))
                try:
                    await save()  # (and who was told: store.backups.told)
                except OSError as ex:
                    log.error("how the last backup went could not be saved with the settings: %s", ex.strerror or ex)
        other = {} if current else {"current": False}
        if made is not None:
            done = made[0]
            audit.write(
                "backup_made", "", file=done.name, size=done.size, devices=done.held.devices, history=done.held.history is not None, pruned=len(done.pruned),
                how=run.how, folder=run.folder, **other,
            )  # fmt: skip
            if not current:
                log.info("a backup was made in %s, which backups do not go to now (or with the key before): %s", run.folder, done.name)
                return
            log.info("a backup was made: %s (%d bytes)", done.name, done.size)
        else:
            audit.write("backup_failed", "", why=outcome["error"], told=told, how=run.how, folder=run.folder, **other)
            if current:
                log.error("no backup was made: %s", outcome["error"])
            else:
                log.warning("no backup was made in %s, which backups do not go to now (or with the key before): %s", run.folder, outcome["error"])

    async def overdue_runs() -> None:
        """Runs begun before the listeners were opened anew, whose bound has come meanwhile with their folders not answering
        still: each said to have failed, once, and alerted, as its waiter would have (the outside review of 0.4.0, M2: the
        bound went with the waiter, and a run on a share that never answered was never said failed). Each holds its folder
        until its thread ends, and that end is kept then (ended_late)."""
        for each in core.backup_runs.overdue():
            await run_ended(each.for_run or backup.Run(each.folder), {"ok": False, "error": not_finished(each.within)}, each.since, None)

    def ended_late(run: backup.Run, made: tuple[backup.Made, int] | None, failure: BaseException | None) -> None:
        """(The run's thread, or the loop where its waiter was stopped.) A run nobody waited for any more (cut off by its hour, or
        begun before the listeners were opened anew) has ended: handed to the program (core.backup_ended), and kept and said
        by whichever listeners there are now, at once where they are open (core.backup_poke), or at the clock's next look. Never
        to the event loop the run was begun on, which may have ended with its listeners."""
        # Whether its hour had cut it off (its failure said then), or its waiter had only stopped (the listeners opened anew):
        # asked while its place is still held (FolderThreads tells before it gives the place back, and none is cut off after).
        cut = any(each.cut_off for each in core.backup_runs.working() if each.for_run is run)
        core.backup_ended.append((run, made, failure, cut))
        poke = core.backup_poke
        if poke is not None:
            try:
                poke()
            except RuntimeError:  # (that loop has ended this moment: the next listeners' clock takes it)
                pass

    ending = asyncio.Lock()  # (one keeps what runs ended with at a time: the clock looks at when the next is due only after)

    async def ended_runs() -> None:
        """What runs nobody waited for any more ended with, kept and said, in the order they ended (one at a time)."""
        async with ending:
            while core.backup_ended:
                run, made, failure, cut = core.backup_ended.popleft()
                try:
                    await record_late(run, made, failure, cut)
                except Exception:
                    log.exception("how a backup ended could not be kept")

    def background_task(work: Awaitable[None]) -> None:
        task = asyncio.ensure_future(work)
        background.add(task)
        task.add_done_callback(background.discard)

    async def record_late(run: backup.Run, made: tuple[backup.Made, int] | None, failure: BaseException | None, cut: bool) -> None:
        if not cut:
            # Never cut off (its waiter stopped as the listeners were opened anew, and it ended before its hour): its end is
            # an end as every run's, kept and said by run_ended: Settings' last run and what the clock counts from, the
            # alerts, "made" or "failed" (the fresh review of the fixes, N4: a failure was a line alone, Settings still saying
            # the run before made a backup and nobody alerted; a backup made was not counted by the clock, which began another).
            if made is not None:
                outcome: dict[str, Any] = {"ok": True, "name": made[0].name, "size": made[0].size}
            else:
                known = (backup.BackupError, OSError, ValueError, MemoryError, VaultLocked, history.NotReadable)
                outcome = {"ok": False, "error": (backup_failure(failure) if isinstance(failure, known) else f"an error inside qKVM ({type(failure).__name__}); the details are in its log")[:500]}
            await run_ended(run, outcome, run.began or time.time(), made)
            return
        if made is None:
            known = (backup.BackupError, OSError, ValueError, MemoryError, VaultLocked, history.NotReadable)
            why = backup_failure(failure) if isinstance(failure, known) else f"an error inside qKVM ({type(failure).__name__}); the details are in its log"
            audit.write("backup_ended_late", "", ok=False, why=why[:500], folder=run.folder)
            log.warning("a backup cut off by its bound ended after all, without a backup: %s", why)
            return
        done, others = made
        async with one_change:
            kept = store.backups
            was_ok = kept.last_ok
            # The latest only of the backups as they are set up now (the folder they go to, and their key), and only where
            # nothing made since is newer: a run cut off on a share that answers after the backups were moved made its backup
            # there, not here (Verify would look for it here).
            current = of_now(run)
            here = current and done.made > kept.last_good
            if here:
                kept.last_ok, kept.last_error, kept.others = True, "", others
                kept.last_name, kept.last_size, kept.last_good, kept.last_folder = done.name, done.size, done.made, run.folder
                if not was_ok:
                    tell_backup(backup_alert(False, done.name))
                try:
                    await save()  # (and who was told: store.backups.told)
                except OSError as ex:
                    log.error("how the last backup went could not be saved with the settings: %s", ex.strerror or ex)
        audit.write(
            "backup_ended_late", "", ok=True, file=done.name, size=done.size, devices=done.held.devices, pruned=len(done.pruned), folder=done.folder,
            **({} if here else {"current": False} if not current else {"latest": False}),
        )  # fmt: skip
        if not here:
            log.info("a backup cut off by its bound ended after all, in %s, and is not the latest of the backups as they are now: %s", done.folder, done.name)
            return
        log.info("a backup cut off by its bound ended after all: %s (%d bytes)", done.name, done.size)

    def runs_waiting() -> list[backup.Working]:
        """The runs their hour cut off that still wait for their folders (their threads go on until the folder answers): those
        their waiter said so of, and those whose hour came after the listeners were opened anew (overdue_runs)."""
        return [each for each in core.backup_runs.working() if each.cut_off]

    def held_here() -> backup.Working | None:
        """A run that holds the folder backups go to now (none more is begun into it meanwhile): one its hour cut off, still
        waiting for it; or one under way that was begun before the listeners were opened anew, and is waited for by nobody. By
        the folder's name, or by what it is on the disk where its threads have found that out (FolderThreads.holding: another
        name for the same folder, a junction or a link, is that folder: the outside review of 0.4.0, bugs round, M6)."""
        return core.backup_runs.holding(store.backups.folder) if store.backups.folder else None

    def latest_here() -> bool:
        """Whether the backup last made is in the folder backups go to now (one saved since has none yet: the outside review of
        0.4.0, bugs round, M2), made with their key."""
        kept = store.backups
        return bool(kept.last_name) and backup.place_of(kept.last_folder) == backup.place_of(kept.folder) and backup.made_with(kept.last_name, kept.key_id)

    def cut_off_run() -> bool:
        """Whether a run its hour cut off still waits for the folder backups go to now."""
        held = held_here()
        return held is not None and held.cut_off

    def tell_what_waits() -> None:
        """Once a day, at the hour, while runs cut off still wait: an alert (and a line) of what waits, and that a restart
        frees it. (The run's failure was told when it was cut off; this says that it still holds its thread.)"""
        held = runs_waiting()
        kept = store.backups
        if not held or not kept.enabled:
            return
        now = time.time()
        came = backup.next_run(kept.hour, now - 86400)  # (the last time the hour came)
        if came > now or came == waiting_told[0] or not any(each.since < came for each in held):
            return
        waiting_told[0] = came
        folders = [each.folder for each in held]
        since = time.strftime("%Y-%m-%d %H:%M", time.localtime(min(each.since for each in held)))
        said = (
            f"A backup cut off after its hour is still waiting for {', '.join(folders)}, since {since}: it holds a thread of qKVM's "
            "until that folder answers, and none is begun into it meanwhile. A restart of qKVM frees it."
        )
        alert = alerts.Alert("backup", "qKVM", "", "backup_failed", "backup_failed", "A backup is still waiting for its folder", said, event="backup")
        alert.link = store.alerts.link
        told = tell_backup(alert)
        audit.write("backup_still_waiting", "", folders=folders, told=told)
        log.warning("%s", said)

    def backup_poker(loop: asyncio.AbstractEventLoop) -> Callable[[], None]:
        """What hands a run's end to these listeners' loop, from any thread."""
        def poke() -> None:
            loop.call_soon_threadsafe(lambda: background_task(ended_runs()))

        return poke

    def start_backup(by_the_clock: bool) -> asyncio.Task[dict[str, Any]] | None:
        """A run set going, never waited for by whoever set it going (it outlives a request that is cut off). None where one is
        under way already."""
        running = backup_task[0]
        if running is not None and not running.done():
            return None
        task = asyncio.create_task(back_up(by_the_clock))
        backup_task[0] = task
        background.add(task)
        task.add_done_callback(background.discard)
        return task

    def days_ahead(kept: Any, now: float) -> bool:
        """Whether the times the clock's next run counts from were saved while the computer's clock was a day or more ahead:
        the next run would be a day or more away, and every day until that time came round would have no backup."""
        return backup.next_run(kept.hour, max(kept.last_at, kept.since)) > now + SCHEDULE_AHEAD

    def next_backup() -> float | None:
        kept = store.backups
        if not kept.enabled:
            return None
        now = time.time()
        if days_ahead(kept, now):  # (until the clock's next look sets them right: mend_times)
            return backup.next_run(kept.hour, now)
        return backup.next_run(kept.hour, max(kept.last_at, kept.since))

    async def mend_times() -> None:
        """Times of the backups saved while the computer's clock was a day or more ahead, and that clock set right since: set to
        now, and said, so that the next run is the next time the hour comes, and not the day those times come round (the
        outside review of 0.4.0, bugs round, M5: months without a backup by the clock, and nothing said)."""
        kept, now = store.backups, time.time()
        if not kept.enabled or not days_ahead(kept, now):
            return
        async with one_change:
            kept, now = store.backups, time.time()
            if not kept.enabled or not days_ahead(kept, now):
                return
            ahead = {name: getattr(kept, name) for name in ("last_at", "since", "last_good") if getattr(kept, name) > now}
            for name in ahead:
                setattr(kept, name, now)
            try:
                await save()
            except OSError as ex:
                log.error("the backups' times set right could not be saved with the settings: %s", ex.strerror or ex)
        audit.write("backup_times_mended", "", now=now, **ahead)
        log.warning("times of the backups were ahead of this computer's clock (%s), and are set to now: was its clock ahead, and set right since?", ", ".join(sorted(ahead)))

    async def told_in_turn() -> None:
        """What the clock tells of the backups (held back by quiet hours, owed after a restart, what still waits), in the turn of
        changes, and who was told kept with the settings, saved."""
        async with one_change:
            before = list(store.backups.told)
            tell_owed()
            tell_what_waits()
            if store.backups.told != before:
                try:
                    await save()
                except OSError as ex:
                    log.error("who was told of the backups could not be saved with the settings: %s", ex.strerror or ex)

    async def backups_due() -> None:
        """The clock: a run at the hour set, the first the next time it comes after they were switched on; one missed while the
        wall was not running, at its next look. And what quiet hours held back of their alerts, when they are over."""
        while True:
            await asyncio.sleep(BACKUP_LOOK)
            try:
                await ended_runs()  # (and what the listeners before could not keep: they were closed meanwhile)
                await overdue_runs()  # (and runs begun before them whose hour has come since)
                await told_in_turn()
                await mend_times()
                due = next_backup()
                if not cut_off_run():
                    stuck_said[0] = False
                # (Not while what a run ended with waits to be kept: its time is what the clock counts from. A run hands its end
                # over before it lets go of its folder, so that none is begun beside it unkept: the fresh review of the fixes, N4.)
                settling = bool(core.backup_ended) or ending.locked()
                if due is not None and due <= time.time() and store.backups.secret is not None and not settling:
                    if cut_off_run():
                        # A run cut off by its bound goes on in its thread: none is begun beside it (they would share their
                        # files). Said once; the clock's run follows once that one ends.
                        if not stuck_said[0]:
                            stuck_said[0] = True
                            audit.write("backup_not_started", "", why=RUN_STILL_WAITING)
                            log.warning("the backup due by the clock was not begun: %s", RUN_STILL_WAITING)
                    elif (held_here() is not None or start_backup(by_the_clock=True) is None) and clock_said[0] != due:
                        # A run is going (by hand, a moment before the hour): it counts as the clock's, which is said once.
                        clock_said[0] = due
                        audit.write("backup_not_started", "", why="a backup was being made already when the clock's was due: the one under way counts as this one")
                        log.warning("the backup due by the clock was not started: one was being made already")
            except Exception:  # a failed look must not be the last one
                log.exception("whether a backup is due could not be looked at")

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        manager.load()
        # The activity log's seal of a start (chain.py): the head of its chain as the wall begins to serve, written and sent on
        # (syslog) in its turn; a run whose stop seal is missing shows in a check (a crash, a power cut, or its end cut off).
        loop_of[:] = [asyncio.get_running_loop()]  # (the seals' places are kept on it: see keep_position)
        # How runs nobody waited for any more ended reaches these listeners from now on (ended_late), and what came while there
        # were none is kept now.
        poke = backup_poker(loop_of[0])
        core.backup_poke = poke
        background_task(ended_runs())
        core.audit.seal("start", version=__version__)
        kept.start()  # (once; the history outlives the listeners, as the rest of core does)
        indexed.start()  # (once, as the history: at the first start after an upgrade it is made from the text files there)
        tasks = [asyncio.create_task(job()) for job in (housekeeping, watch, history_looks, log_seals, backups_due, tailscale_certificate)]
        yield
        if core.backup_poke is poke:
            core.backup_poke = None  # (from here on a run's end waits for the next listeners: their clock keeps it)
        if release_check is not None:
            tasks.append(release_check)  # (a release check: nothing of it is owed)
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
        await courier.close()  # (what still waits for a destination is not sent: as at a restart of 0.3.2)
        await book_written()  # (...and what a switch dropped of it since the last look is written down: untold, M1)
        await pusher.close()  # (what still waits for a browser is not sent: the push service keeps nothing of it either)
        await lines.close()  # (what a live line still has down on a machine is let go of before the machine's connection goes)
        await manager.close()
        said_left_out()
        # ...and its seal of the end, the last line of this run: the head the next start goes on from, on the disk and sent on.
        check_halt.set()  # (a check of the log under way ends: it writes nothing)
        stopped = await asyncio.to_thread(core.audit.sealed, "stop")
        if stopped is not None:
            # Kept before the program ends: the next start holds the files to it. Saved here, whichever code kept it in memory
            # first: the writer's callback mostly does, and sets a save going that the end of the program does not wait for (one
            # still waiting for its turn was let go of, and the place of the hour before stayed: the re-review of wave 2, N4).
            keep_position(*stopped)
            if position_of(store.activity_position) == stopped:
                await save_position()
        # What was done last is on disk before the program ends, and the activity log's writer ends (an entry after this, of
        # the listeners opened anew, starts one again: see AuditLog.close).
        await asyncio.to_thread(core.audit.close)
        # ...and the activity log's index lets go of its file, all of it brought into the file (what it had not taken in yet,
        # the next start takes in: the text files have it). Started again with the listeners, where they are opened anew.
        await asyncio.to_thread(indexed.stop)
        await asyncio.to_thread(core.sessions.close)  # ...and so is who signed out last, and its writer ends as well
        await asyncio.to_thread(kept.flush)  # ...and what the wall saw last, with when it last looked (history: W4)
        await asyncio.to_thread(screen_watch.close)  # ...and the video worker the screens were compared in goes

    app = FastAPI(title="qKVM", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None, **TELEMETRY_OFF)
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
                "allowed_hosts using the stopped-server --configure-server command (see the qKVM guide, GUIDE.md).",
                status_code=400,
            )
        changing = request.method not in ("GET", "HEAD")
        length = request.headers.get("content-length", "")
        public = path in PUBLIC or path.startswith(PUBLIC_UNDER)
        user, sent = (None, None) if public else asking(request)
        # A cross-site page cannot make a browser send a token: that is no ambient credential like a cookie.
        # So a script is not asked for the headers by which the page's own requests are known.
        if changing and sent is None and not same_origin(request):
            return fail(403, "forbidden", "Cross-site request refused")
        if changing and "transfer-encoding" in request.headers:
            # A body of unknown size could be endless; everything the page sends states its length.
            return fail(411, "length_required", "The request must say how long it is")
        # An image carried through to a device's own storage (an admin's: the media right) says its length, and is read as it
        # comes, by its route, never in full here: the one request of its kind.
        upload = changing and _UPLOAD.fullmatch(f"{request.method} {path}") is not None
        if upload and not length.isdigit():
            return fail(411, "length_required", "An upload must say how long it is")
        if upload and int(length) > MOST_UPLOAD:
            return fail(413, "too_large", f"An image carried through qKVM may be {MOST_UPLOAD // 10**9} GB at the most")
        if changing and not upload and length and (not length.isdigit() or int(length) > (MAX_FILE_BODY if path in _FILES else MAX_BODY)):
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
        if changing and not upload:
            # The whole request is in hand before anything is done or held for it. A sender that
            # stops halfway (by accident or to be a nuisance) holds up nobody but itself, and not for long.
            # (An upload is read by its route a piece at a time, each within UPLOAD_QUIET, and holds up nobody else either.)
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
            # (Not the address of an image mounted on a server, which is that controller's alone: see served.py.)
            log.exception("unhandled error in %s %s", request.method, "/media/..." if path.startswith("/media/") else path)
            response = fail(500, "internal", "Something went wrong inside qKVM. The details are in its log.")
        response.headers.update(SECURITY_HEADERS)
        if is_secure(request):
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        if path.startswith(("/api/", "/media/")):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    app.add_middleware(SentOnlyWhile)  # (added last: outside the guard, where a piece of an answer goes out)
    app.add_middleware(SpelledOut)  # (outside that: what a served image's answer is headed with, spelled out)
    app.add_middleware(CarriedThrough)  # (outside the guard too: an upload's own way to its body)

    @app.exception_handler(RequestValidationError)
    async def invalid(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Name the field and the rule, never the submitted value (it may be a password).
        first = exc.errors()[0]
        where = ".".join(str(part) for part in first.get("loc", ())[1:])
        said = str(first.get("msg")).removeprefix("Value error, ")  # (the rule in this program's own words, where it has some)
        return fail(422, "invalid", f"{where}: {said}" if where else said)

    @app.exception_handler(StarletteHTTPException)
    async def not_served(request: Request, exc: StarletteHTTPException) -> Response:
        # The router's own refusals, refused as every other is ({code, message}, as GUIDE.md's The API promises): an address
        # nothing is served at, and one served by another method (with Allow, which says by which). They were the framework's
        # {"detail": ...}, which a client that reads `code` (a newer one, asking an older wall for what it has not got) read
        # nothing in. (Only an admin meets them: to anybody else what no rule lists is 403 not_allowed.)
        if exc.status_code == 404:
            return fail(404, "not_found", "There is nothing at this address")
        if exc.status_code == 405:
            return fail(405, "method_not_allowed", "This address is not asked for that way", **dict(exc.headers or {}))
        return await http_exception_handler(request, exc)

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
        """For monitoring: answers without a login, and says no more than "running", whether it is watching, and whether
        pictures can be made on this computer at all ("video").

        "locked": it has been restarted and nobody has signed in since, so it cannot reach a single device.
        Nothing is wrong with it, and nothing is being watched: whoever monitors it wants to hear of that.
        """
        # "page": the mark of the page's files as this program serves them (see page_mark).
        # "api": the versions of the API this program speaks, each under /api/<version>/. A program that
        # talks to a wall (a script, an app on a phone) asks here first, before it has anything to sign in with.
        said: dict[str, Any] = {
            "status": "ok", "version": __version__, "api": list(API_VERSIONS), "page": page_mark() if live_files else served,
            "locked": core.initialized and not core.vault.unlocked,
        }  # fmt: skip
        if video.unavailable() is not None:
            # "video": no video worker can start on this computer (the last that was to could not, and none has since), so
            # tiles that need one show no picture. Said as that alone: why, the tiles say to those signed in, and the log.
            said["video"] = "unavailable"
        return said

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
            if said is None or said.id != session.user or said.subject:
                core.sessions.drop(token)
                return None
            session.vouched = time.monotonic()  # (what a live line of this sign-in goes by: see live_standing)
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
        if user.subject and not provider_holds(session, user):
            core.sessions.drop(token)
            return None
        return user

    def provider_holds(session: Session, user: UserRecord) -> bool:
        """Whether a sign-in of an identity provider's account still holds by the provider's settings: they are the wall's
        provider's still (not switched off, not another one), and still what decided its role when it signed in (groups and
        roles, who else, the domain, the groups claim, the scopes, the client). Its word is all such an account has.

        (How long it lasts is the session's own: oidc.SIGNED_IN_FOR, whatever its use.)"""
        settings = store.oidc
        return settings.enabled and user.issuer == settings.issuer and session.granted == oidc.granted_by(settings)

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
        second step where they signed in: qKVM's own is for those who sign in with a password here. So has an account of an
        identity provider's (oidc.py), which nothing but its provider signs in.
        """
        level = store.server.require_totp
        # (The rule is about accounts. A token is made by an admin for one job, and has no phone.)
        return user.totp is None and not is_token(user) and not user.subject and not by_sso(request) and level in RANK and RANK[user.role] >= RANK[level]

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

    async def wrapped(opened: Vault, password: str) -> dict[str, Any]:
        """`password` made into a record that opens the key `opened` holds: the same work as a check, and as many at a time.

        Done beside everything else, before a change takes its turn (`one_change`): the turn is for the change alone.
        Raises KvmError where the memory it takes is not to be had.
        """
        try:
            async with password_checks:
                return await asyncio.to_thread(opened.rewrap, password)
        except (MemoryError, NoMemory) as ex:
            raise no_memory(ex) from None

    def changed_meanwhile(user: UserRecord, checked: dict[str, Any] | None) -> JSONResponse | None:
        """Why a change an account's own password was checked for may not be made, as the account stands now. None: it may.

        The check is made beside everything else, and the change in its turn after it (`one_change`). Meanwhile the
        account may have been removed or replaced, or its password changed in another tab or by an admin: what was
        checked is then not the account's password any more, and nothing is done on the strength of it.
        """
        if store.user(user.id) is not user or user.auth is not checked:
            return fail(409, "changed", "Your account was changed while your password was being checked (in another tab, or by an admin). Nothing was done: try again.")
        return None

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
        token = new_session(request, remember, user)
        return with_cookie(JSONResponse({"ok": True, "user": me(user, request), **extra}), request, token, remember)

    def new_session(request: Request, remember: bool, user: UserRecord, lasts: float = 0.0, granted: str = "") -> str:
        """A sign-in of this account, in the browser making this request: its token, for the cookie. `lasts`, `granted`: see
        security.Session (a sign-in by an identity provider)."""
        token = core.sessions.create(client_ip(request), remember, user.id, mark=auth_mark(user), lasts=lasts, granted=granted)
        manager.load()
        if core.unlock_secret is not None and store.unlock is None:
            # Not waited for by whoever is signing in: it takes as long as checking a password does.
            task = asyncio.create_task(fit_unlock_file())
            background.add(task)
            task.add_done_callback(background.discard)
        return token

    def with_cookie(response: R, request: Request, token: str, remember: bool) -> R:
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
            if known is not None and (known.suspended or known.subject):  # (an identity provider's account is its provider's alone)
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
        checked = user.auth
        try:
            # (Beside every change of the wall, as a sign-in's check is: the turn below is taken for the change alone.)
            key = await check_password(body.current, checked, ip)
        except KvmError as ex:
            return fail(ex.status, ex.code, ex.message)
        if key is None:
            core.limiter.fail(ip)
            return fail(401, "bad_password", "The current password is wrong")
        # The check took a moment. Signed out meanwhile (in another tab, or by an admin), this request has no
        # business left, least of all handing the key back to a wall that the last sign-out has just locked.
        if refused := still_allowed(request):
            return refused
        opened = Vault()
        opened.adopt(key)
        try:
            auth = await wrapped(opened, body.new)
        except KvmError as ex:
            return fail(ex.status, ex.code, ex.message)
        async with one_change:
            # ...and asked again in the turn, with what was checked: the account as it was, its password unchanged.
            if refused := still_allowed(request) or changed_meanwhile(user, checked):
                return refused
            core.vault.adopt(key)
            user.auth = auth
            if refused := await saved("The new password", lambda: setattr(user, "auth", checked)):
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
        recovery = store.recovery if user else None
        try:
            # Without such an account, or without a recovery key, the same work is done against a made-up record. Beside
            # every change of the wall, as a sign-in's check is: anybody may send this, and the turn is for the change alone.
            key = await check_password(tidy_recovery_key(body.recovery_key), recovery, ip)
        except KvmError as ex:
            return fail(ex.status, ex.code, ex.message)
        if user is None or key is None:
            core.limiter.fail(ip, user.name if user else name)
            audit.write("recovery_failed", ip, user=user.name if user else "", **({} if user else {"no_such_account": True}))
            return fail(401, "bad_recovery", "The recovery key is not right" + (" for that user name" if len(store.users) > 1 else ""))
        if user.subject:
            # Never a password of the wall's own for an account of the identity provider's: its provider alone signs it in.
            # (Said to whoever has the recovery key, and to nobody else: a wrong key is answered as for any account.)
            return fail(409, "provider_account", "This account is signed in by your identity provider, and has no password here to set")
        opened = Vault()
        opened.adopt(key)
        try:
            auth = await wrapped(opened, body.new_password)
        except KvmError as ex:
            return fail(ex.status, ex.code, ex.message)
        async with one_change:
            # The key was checked as it was then. Replaced meanwhile by a new one, it is not the key any more; and the account
            # removed or replaced meanwhile is not the one it was checked for.
            if store.user(user.id) is not user or store.recovery is not recovery:
                core.limiter.fail(ip, user.name)
                audit.write("recovery_failed", ip, user=user.name)
                return fail(401, "bad_recovery", "The recovery key is not right" + (" for that user name" if len(store.users) > 1 else ""))
            previous, user.auth = user.auth, auth
            if refused := await saved("The new password", lambda: setattr(user, "auth", previous)):
                return refused
            core.sessions.drop_user(user.id)
        core.limiter.reset(ip, user.name)
        audit.write("password_recovered", ip, user=user.name)
        return JSONResponse({"ok": True})

    @app.post("/api/v1/recovery")
    async def renew_recovery(body: TotpBeginIn, request: Request) -> Response:
        """A new recovery key (admins only). The previous one stops working."""
        user: UserRecord = request.state.user
        checked = user.auth
        if refused := await own_password(request, body.password):
            return refused
        async with one_change:  # (the password checked beside every change; the turn for the change, asked again in it)
            if refused := still_allowed(request) or changed_meanwhile(user, checked):
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
        checked = user.auth
        if refused := await own_password(request, body.password):
            return refused
        async with one_change:  # (the password checked beside every change; the turn for the change, asked again in it)
            if refused := still_allowed(request) or changed_meanwhile(user, checked):
                return refused
            if user.totp is None:  # switched off meanwhile (by an admin, for a lost phone)
                return fail(409, "not_enabled", "Two-factor sign-in is not on for this account")
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
        checked = user.auth
        if refused := await own_password(request, body.password):
            return refused
        async with one_change:  # (the password checked beside every change; the turn for the change, asked again in it)
            if refused := still_allowed(request) or changed_meanwhile(user, checked):
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
        # `expires`: when the link runs out (null: when it is taken back); `expires_in`: how many seconds that is from now, by
        # this wall's clock. The page counts those on its own steady clock: a screen's time of day may be far off.
        ends = {"expires": shown.expires, "expires_in": None if shown.expires is None else max(0.0, shown.expires - now)}
        if showing is not None and showing.id == user.id:
            return JSONResponse({"ok": True, "user": me(user), **ends})  # the screen that is on already, asking again
        # Whoever has the link can ask without end. What they get for it is bounded: so many screens at a
        # time, the oldest giving way, and a line in the activity log now and then, not one for each.
        core.sessions.keep_newest(user.id, DISPLAY_SESSIONS - 1)
        if now - displays_logged.get(shown.id, 0.0) > 60:
            displays_logged[shown.id] = now
            audit.write("display_opened", client_ip(request), user=user.name)
        return signed_in(request, remember=True, user=user, **ends)

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
            "provider": bool(user.subject),  # signed in by the identity provider (oidc.py): its role is its groups'
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
        """Admins who can sign in here. One that is suspended is not one to fall back on; nor is one only an identity
        provider signs in (oidc.py), which is no way back in on the day the provider is down, or switched off."""
        return sum(1 for u in store.users if u.role == "admin" and not u.suspended and not u.subject)

    def the_last_admin(user: UserRecord) -> bool:
        """Whether this account is the last admin who signs in here (`admins`): it is not removed, demoted or suspended."""
        return user.role == "admin" and not user.suspended and not user.subject and admins() == 1

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
        if user.subject and (body.password or body.role != user.role):
            # An account of the identity provider's has no password here, ever; and its role is read from its groups at
            # each sign-in, where one set here would be undone. (Its machines are the wall's to limit, and stay limited.)
            return fail(409, "provider_account", "This account is signed in by your identity provider: it has no password here, and its role comes from its groups there. Suspend it to keep it out.")
        if body.role != user.role:
            if yourself:
                return fail(409, "own_role", "You cannot change your own role; ask another admin")
            if the_last_admin(user):
                return fail(409, "last_admin", "This is the only admin who signs in here; make someone else an admin first")
        if body.suspended and yourself:
            return fail(409, "yourself", "You cannot suspend the account you are signed in with")
        if body.suspended and not user.suspended and the_last_admin(user):
            # (Suspended by an admin of the identity provider's, the wall would have no admin left to sign in with the day the
            # provider is down.)
            return fail(409, "last_admin", "This is the only admin who signs in here; make someone else an admin first")
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
        if the_last_admin(user):
            return fail(409, "last_admin", "This is the only admin who signs in here")
        place, pushes = store.users.index(user), store.pushes
        store.users.remove(user)
        store.pushes = [push for push in pushes if push.user != user.id]  # its browsers are told nothing more (Web Push)

        def undo() -> None:
            store.users.insert(place, user)
            store.pushes = pushes

        if refused := await saved("Removing this account", undo):
            return refused  # said: an account taken for removed would be back, password and all, after a restart
        for push in pushes:
            if push.user == user.id:
                pusher.forget(push.id)
        core.sessions.drop_user(user.id)
        audit.write("user_removed", client_ip(request), account=user.name)
        return JSONResponse({"ok": True})

    # --- signing in through an identity provider (oidc.py, 0.4.0) ---------------------------------------------------------
    # The settings are an admin's (the client secret sealed by the vault, never handed back); the button, its press and the
    # way back from the provider are anybody's. Nothing a provider or a browser sends signs anybody in until oidc.py has held
    # it to every rule; an account the provider signs in is its provider's alone (no password here, its role its groups').

    provider = oidc.Client(own_addresses)
    signing_in = oidc.Starts()
    tokens_checked = oidc.Verifier(provider)
    oidc_said: dict[str, float] = {}  # when a way back that no sign-in here began was last written into the activity log

    def oidc_view() -> dict[str, Any]:
        settings = store.oidc
        accounts = [user.id for user in store.users if user.subject]
        counts = core.sessions.counts()
        return {
            "enabled": settings.enabled, "name": settings.name, "issuer": settings.issuer, "client_id": settings.client_id,
            "has_secret": bool(settings.secret),  # (never the secret)
            "scopes": settings.scopes, "groups_claim": settings.groups_claim,
            "roles": [{"group": group, "role": role} for group, role in settings.roles.items()], "anyone": settings.anyone,
            "domain": settings.domain, "private": settings.private, "redirect_uri": settings.redirect_uri, "callback": oidc.CALLBACK,
            "offered": oidc.offered(settings), "accounts": len(accounts), "signed_in": sum(counts.get(each, 0) for each in accounts),
            # Started with --locked-start: after a restart the button works only once somebody has signed in with a password.
            "locked_start": core.unlock_secret is None,
        }  # fmt: skip

    def provider_sessions(keep: str | None = None) -> int:
        """End every sign-in of every account of an identity provider's, but the browser holding `keep`. How many ended."""
        return sum(core.sessions.drop_user(user.id, keep=keep) for user in store.users if user.subject)

    @app.get("/api/v1/oidc")
    async def get_oidc() -> dict[str, Any]:
        return oidc_view()

    @app.put("/api/v1/oidc")
    async def set_oidc(body: OidcIn, request: Request) -> Response:
        """Set up signing in through an identity provider. Switched on, the provider is asked what it is (and for its keys)
        before anything is saved: a provider that cannot be asked, or calls itself otherwise, is said now, not at the first
        person's sign-in."""
        before = store.oidc
        on = body.enabled
        try:
            issuer = oidc.issuer_url(body.issuer) if body.issuer.strip() else ""
            client = oidc.client_id(body.client_id) if body.client_id.strip() else ""
            given = oidc.client_secret(body.client_secret) if body.client_secret else ""
            made = OidcSettings(
                enabled=on, name=oidc.button_name(body.name), issuer=issuer, client_id=client, scopes=oidc.scopes_of(body.scopes),
                groups_claim=oidc.groups_claim(body.groups_claim), roles=oidc.roles_of([(each.group, each.role) for each in body.roles]),
                anyone=body.anyone, domain=oidc.email_domain(body.domain), private=body.private,
                redirect_uri=oidc.redirect_uri(body.redirect_uri, request.headers.get("host", "")) if body.redirect_uri.strip() else "",
            )  # fmt: skip
        except ValueError as ex:
            return fail(422, "invalid", str(ex))
        if (wide := oidc.open_to_the_world(made)) is not None:  # (saved switched off or on: switched on later, it would be)
            return fail(422, "invalid", wide)
        # A secret left empty keeps the one saved, for the provider and the client it was entered for and no other: kept
        # across a change of either, it would be handed to a provider it was never meant for at the next sign-in.
        if given:
            if not core.vault.unlocked:
                return fail(409, "locked", "Sign in again first")
            made.secret = core.vault.encrypt(given, oidc.SEALED_FOR)
        elif before.secret and (issuer, client) == (before.issuer, before.client_id):
            made.secret = before.secret
        if on:
            missing = [what for what, there in (("the issuer", issuer), ("the client ID", client), ("the client secret", made.secret), ("the redirect address", made.redirect_uri)) if not there]
            if missing:
                return fail(422, "invalid", f"To switch it on, enter {' and '.join(missing)}" + (" (again: it is sent only to the provider and client it was entered for)" if "the client secret" in missing and before.secret else ""))
            if not made.roles and not made.anyone:
                return fail(422, "invalid", "Nobody could sign in: give a group a role, or let anybody the provider signs in in, as a viewer at least")
            # Asked of a client of its own: what a check of new settings finds is not what the wall's sign-ins go by.
            checking = oidc.Client(own_addresses)
            try:
                found = await checking.provider(made)
                await checking.keys(found, made)
            except oidc.Refusal as ex:
                return fail(502, "provider_refused", f"{ex.said}. Nothing was saved.")
        async with one_change:
            if refused := still_allowed(request):
                return refused
            if store.oidc is not before:
                return fail(409, "changed", "These settings were changed meanwhile (in another tab, or by another admin). Nothing was saved: look again.")
            store.oidc = made

            def as_it_was() -> None:
                store.oidc = before

            if refused := await saved("Signing in through an identity provider", as_it_was):
                return refused
            provider.forget()
            # Switched off, set to another provider, or anything changed that decides who gets what (groups and roles, who else,
            # the domain, the groups claim, the scopes, the client): whoever the provider signed in is signed out now, the
            # admin who saves it included where they are one, live views and all (provider_holds holds every request and every
            # line to that as well). The button signs them in again, with the role the settings give them now.
            if oidc.granted_by(made) != oidc.granted_by(before):
                provider_sessions()
        audit.write(
            "oidc_changed", client_ip(request), enabled=on, issuer=issuer, client_id=client, roles=len(made.roles), anyone=made.anyone or None,
            domain=made.domain or None, private=made.private, **({"secret": "replaced"} if given else {}),
        )  # fmt: skip
        return JSONResponse(oidc_view())

    @app.post("/api/v1/oidc/logout")
    async def oidc_everyone_out(request: Request) -> Response:
        """Sign out every browser that the identity provider signed in, at once (somebody left a group: their sign-in that is
        open keeps the role it had until it ends, and this ends it). The admin's own, where it is one, stays."""
        # (Nothing to wait for on the disk: a sign-in by the provider is never written down to outlast a restart.)
        ended = provider_sessions(keep=request.cookies.get(COOKIE))
        audit.write("provider_signed_out", client_ip(request), sessions=ended)
        return JSONResponse({"ok": True, "ended": ended})

    @app.get("/api/v1/oidc/offer")
    async def oidc_offer() -> dict[str, Any]:
        """For the sign-in page: whether it offers a button for the identity provider, and what the button calls it."""
        on = oidc.offered(store.oidc)
        return {"on": on, "name": oidc.called(store.oidc) if on else ""}

    @app.post("/api/v1/oidc/begin")
    async def oidc_begin(request: Request) -> Response:
        """The button: a sign-in under way, bound to this browser by a cookie, and where to send the browser to sign in."""
        settings = store.oidc
        if not oidc.offered(settings):
            return fail(409, "not_offered", "Signing in through an identity provider is not set up on this wall")
        back = urlsplit(settings.redirect_uri)
        if not oidc.same_host(back.netloc, request.headers.get("host", "")):
            # Its cookie would be set for this address, and the provider sends the browser back to that one, which has none.
            at = f"{back.scheme}://{back.netloc}"
            return JSONResponse({"code": "elsewhere", "message": f"Signing in with {oidc.called(settings)} works at {at}, the address it sends you back to. Open qKVM there.", "at": at}, status_code=409)
        if not core.vault.unlocked:
            return fail(503, "locked", "qKVM was restarted and nobody has signed in with a password since, so it cannot sign anybody in through the provider yet")
        try:
            found = await provider.provider(settings)
        except oidc.Refusal as ex:
            return fail(502, "provider_refused", ex.said)
        made = signing_in.begin(settings, core.limiter.counted_as(client_ip(request)))
        if made is None:
            return fail(429, "busy", "Too many sign-ins are under way just now. Try again in a few minutes.", **{"Retry-After": "60"})
        state, start, cookie = made
        response = JSONResponse({"url": oidc.authorization_url(found, settings, state, start)})
        # SameSite=Lax, and not Strict as the wall's own: the browser comes back by the provider's redirect, a navigation from
        # another site, and a Strict cookie is not sent with that. HttpOnly, for its ten minutes; over HTTPS a __Host- cookie,
        # which no page on a name beside the wall's can set (oidc.cookie_for), and otherwise one of the way back alone.
        secure = is_secure(request)
        name, path = oidc.cookie_for(secure)
        response.set_cookie(name, cookie, max_age=int(oidc.STARTED_WITHIN), httponly=True, samesite="lax", secure=secure, path=path)
        return response

    def without_the_sign_ins_cookie(response: Response, request: Request) -> Response:
        """`response`, taking the cookie of the sign-in that was under way out of the browser (it is used once)."""
        secure = is_secure(request)
        name, path = oidc.cookie_for(secure)
        response.delete_cookie(name, path=path, secure=secure, httponly=True, samesite="lax")  # (a __Host- one goes only so)
        return response

    def oidc_refused(request: Request, refusal: oidc.Refusal, who: UserRecord | None = None, began: bool = True) -> Response:
        """The way back to the sign-in page, with the word for why (in its address's fragment: never sent to any server);
        and a line in the activity log (`began`: for a sign-in this wall began; for a way back that none here began, once a
        minute at the most: anybody can send one)."""
        now = time.monotonic()
        if began or now - oidc_said.get("", float("-inf")) >= OIDC_REFUSALS_SAID:
            if not began:
                oidc_said[""] = now
            audit.write("login_failed", client_ip(request), user=who.name if who is not None else "", provider=True, why=refusal.code, said=refusal.said[:300])
        return without_the_sign_ins_cookie(RedirectResponse(f"/#signin={refusal.code}", status_code=303), request)

    @app.get(oidc.CALLBACK)
    async def oidc_back(request: Request) -> Response:
        """The way back from the provider: the sign-in this browser began, finished, or refused with the reason."""
        query = request.query_params
        try:
            # (By the one name it is set under for this wall's way of being served: over HTTPS a cookie of the plain name, which
            # a page beside the wall's could have set, is not the browser's word.)
            start = signing_in.take(query.get("state", ""), request.cookies.get(oidc.cookie_for(is_secure(request))[0]))
        except oidc.Refusal as ex:
            return oidc_refused(request, ex, began=False)
        settings = store.oidc
        who: UserRecord | None = None
        try:
            if not oidc.offered(settings) or start.mark != oidc.mark_of(settings):
                raise oidc.Refusal("changed", "Signing in through the provider was changed while this sign-in was under way")
            if "error" in query:
                error = oidc.error_word(query.get("error", ""))
                raise oidc.Refusal("provider_error", "The provider did not sign this person in" + (f" ({error})" if error else ""))
            found = await provider.provider(settings)
            said_issuer = query.get("iss")
            if (said_issuer is not None and said_issuer != found.issuer) or (said_issuer is None and found.says_issuer):
                # (RFC 9207: the browser comes back from another provider than this sign-in went to. A mix-up.)
                raise oidc.Refusal("issuer", "The way back names another provider than the one this sign-in went to (iss)")
            code = query.get("code", "")
            if not oidc.a_code(code):
                raise oidc.Refusal("provider_error", "The provider sent no code back")
            if not core.vault.unlocked:
                raise oidc.Refusal("locked", "The saved passwords are locked: the client secret cannot be opened")
            secret = core.vault.read(settings.secret, oidc.SEALED_FOR) if settings.secret else None
            if secret is None:
                raise oidc.Refusal("secret", "The client secret does not open any more (the settings file was edited, or is damaged): enter it again")
            answer = await provider.exchange(found, settings, secret, code, start.verifier)
            claims = await tokens_checked.checked(answer.get("id_token"), found, settings, start.nonce)
            subject = str(claims["sub"])
            who = next((user for user in store.users if user.subject == subject and user.issuer == settings.issuer), None)
            if refusal := oidc.domain_refusal(claims, settings):
                raise refusal
            groups = oidc.groups_in(claims, settings.groups_claim)
            if groups is None and oidc.overage(claims, settings.groups_claim):
                raise oidc.Refusal("group_overage", "The provider has too many groups of this person to put in the token, and says where to fetch them, which this program does not: have it send only the groups given to this application")
            if groups is None:
                info = await provider.userinfo(found, settings, answer.get("access_token"), subject)
                groups = oidc.groups_in(info, settings.groups_claim)
                if groups is None and oidc.overage(info, settings.groups_claim):
                    raise oidc.Refusal("group_overage", "The provider has too many groups of this person to say, and says where to fetch them, which this program does not: have it send only the groups given to this application")
            role = oidc.role_for(groups or [], settings)
            if role is None:
                raise oidc.Refusal("no_group", "This person is in no group that gives a role on this wall")
            if who is not None and who.suspended:
                raise oidc.Refusal("suspended", "This account is suspended on this wall")
        except oidc.Refusal as ex:
            return oidc_refused(request, ex, who)
        ip = client_ip(request)
        async with one_change:
            # The provider was asked meanwhile, for seconds perhaps: asked again with nothing left to wait for.
            # (And what decided the role is still what the role was worked out by: no account is written by a mapping gone.)
            if not oidc.offered(store.oidc) or start.mark != oidc.mark_of(store.oidc) or oidc.granted_by(store.oidc) != oidc.granted_by(settings):
                return oidc_refused(request, oidc.Refusal("changed", "Signing in through the provider was changed while this sign-in was under way"), who)
            user = next((each for each in store.users if each.subject == subject and each.issuer == settings.issuer), None)
            if user is not None and user.suspended:
                return oidc_refused(request, oidc.Refusal("suspended", "This account is suspended on this wall"), user)
            was = user.role if user is not None else None
            if user is None:
                user = UserRecord(id=new_user_id(), name=provider_account_name(claims, settings.issuer), role=role, created=time.time(), issuer=settings.issuer, subject=subject)
                store.users.append(user)
                made = user

                def undo() -> None:
                    store.users.remove(made)

            else:
                kept = user
                user.role = role

                def undo() -> None:
                    kept.role = str(was)

            if was != role and await saved("This sign-in", undo):
                return oidc_refused(request, oidc.Refusal("not_saved", "The account could not be saved, so nobody was signed in"), user)
        if was is None:
            audit.write("user_added", ip, user=user.name, account=user.name, role=role, provider=True)
        elif was != role:
            audit.write("user_changed", ip, user=user.name, account=user.name, role=role, was=was, by="provider")
        # Never kept over a restart, and a working day at the most however much it is used (oidc.SIGNED_IN_FOR): the role was
        # read from the groups now. And over once the settings that decided it are not those any more (provider_holds).
        token = new_session(request, False, user, lasts=oidc.SIGNED_IN_FOR, granted=oidc.granted_by(settings))
        audit.write("login", ip, user=user.name, provider=True)
        return without_the_sign_ins_cookie(with_cookie(RedirectResponse("/", status_code=303), request, token, False), request)

    def new_user_id() -> str:
        while (made := secrets.token_hex(4)) in {user.id for user in store.users}:
            pass
        return made

    def provider_account_name(claims: dict[str, Any], issuer: str) -> str:
        """What an account the provider signs in for the first time is called here: a name it would be called by (its
        verified email, its user name at the provider, its name), as a name here is written, and one nobody has. Only a
        label: the account is the provider's `sub` with its issuer, and a name taken already is never taken over."""
        email = claims.get("email") if claims.get("email_verified") is True else None
        base = ""
        for said in (email, claims.get("preferred_username"), claims.get("name")):
            if isinstance(said, str):
                base = re.sub(r"[^A-Za-z0-9._@+-]", "", said.strip().replace(" ", ".")).lstrip("._@+-")[:64]
                if base:
                    break
        base = base or "user"
        mark = hashlib.sha256(f"{issuer} {claims['sub']}".encode()).hexdigest()
        for name in (base, *(f"{base[: 63 - length]}-{mark[:length]}" for length in (6, 12, 24))):
            if store.user_named(name) is None:
                return name
        return f"user-{mark[:32]}"

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
            role = request.state.user.role
            devices.append({**view(record, editing=role == "admin", links=RANK[role] >= RANK["operator"]), "same_as": same_as, "can": abilities_of(record)})
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
        # Each row with the machine it is of (`target`, as the wall's view of the tile says it), taken with the connection that
        # is asked, before anything is waited for: a tile's record and its connection change together (an edit, one taken back),
        # so a row answered after an edit put another machine under the tile says the one it was found at. Keyed by the tile's
        # id alone, a page with the wall as it was took the other machine's ports under the old one's name (the outside review 6.2's narrow
        # look, HIGH 6). (A connection whose record is gone already is of no tile: left out, as it will be at the next look.)
        # (The records by id once: looked up by store.device(), which walks the list, once per tile, a status of 10,000 tiles took
        # 1.6 s on the event loop, every 4 s for every page open: the last look at the hold round, M1.)
        records = {record.id: record for record in store.devices}
        asked = [(device_id, device, target_of(record)) for device_id, device in manager.devices.items()
                 if allowed(request, device_id) and (record := records.get(device_id)) is not None]  # fmt: skip
        results = await asyncio.gather(*(device.status() for _, device, _ in asked))
        # (How each of them is, as it was found while waiting: of those that whoever asked may still see.)
        if refused := still_allowed(request):
            return refused
        return JSONResponse({
            device_id: {**result, "target": target} for (device_id, _, target), result in zip(asked, results, strict=True)
            if still_shown(request, device_id) is None
        })  # fmt: skip

    @app.get("/api/v1/devices/{device_id}/snapshot")
    async def snapshot(
        device_id: str,
        request: Request,
        w: int = Query(640, ge=1, le=16384),
        age: float | None = Query(None, ge=0, le=3600),
        big: bool = Query(False),
        target: str | None = Query(None, max_length=64),  # (empty: none, as a read older than 0.4.0 took it)
    ) -> Response:
        """One frame, at least `w` pixels wide when the source has that many.

        `age`: how old, in seconds, the frame may be. A tile that refreshes once a second does not
        need one taken for it alone when another browser got one a moment ago. `big`: this is the
        enlarged (large) view of the machine, so a PC with Intel AMT holds a session open for it (and
        opens one before a power-on), where a tile that is only shown gets a still now and then.
        `target`: the machine the picture is for (target_of), as the page has the tile: refused, nothing asked of either
        machine (409 `machine_changed`), where an edit has put another under the tile since, whose screen a page with the
        wall as it was showed under the old one's name (the fresh review of the HA round, L2). Left out: not asked.
        """
        device = manager.devices.get(device_id)
        if device is None or not allowed(request, device_id):
            return fail(404, "not_found", "Unknown device")
        if refused := not_as_seen(target or None, device_id):
            return refused
        try:
            frame = await device.snapshot(w, age, big=big)
        except KvmError as ex:
            return fail(ex.status, ex.code, ex.message)
        if refused := still_shown(request, device_id):
            return refused
        if manager.devices.get(device_id) is device:
            screen_watch.saw(device_id, frame)  # (a reference, where its screen is watched: screens.py)
        headers = {"Cache-Control": "no-store", "X-KVM-Signal": "1" if frame.signal else "0"}
        if frame.still:
            # A still kept between sessions (a PC with Intel AMT whose tile is only shown): the page says its age.
            headers["X-KVM-Still"] = "1"
            headers["X-KVM-Age"] = str(max(0, round(time.monotonic() - frame.taken_at)))
        return Response(frame.data, media_type=frame.content_type, headers=headers)

    @app.get("/api/v1/devices/{device_id}/alert-picture/{stamp}")
    async def alert_picture(device_id: str, stamp: str, request: Request) -> Response:
        """The picture that set off an alert of a machine's screen watch (screens.py), by the stamp its entry in the activity
        log names: for an admin, as that log is. Only the last one of each machine is kept, for some days."""
        if store.device(device_id) is None or not allowed(request, device_id):
            return fail(404, "not_found", "Unknown device")
        found = await asyncio.to_thread(screen_watch.picture, device_id, stamp)
        if refused := still_shown(request, device_id):
            return refused
        if found is None:
            return fail(404, "no_picture", "That picture is no longer kept: only the last alert's is, and for some days")
        data, kind = found
        return Response(data, media_type=kind, headers={"Cache-Control": "no-store"})

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
        """What the history says of one machine, for the roles that may see it (see history.py and the guide).

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

    def not_taken_there(ex: KvmError) -> JSONResponse:
        """A device that could not be added, or saved as edited, at the address typed: as its driver said, and with the address
        the device itself says to use instead where it says one (`use`: a KVM whose plain address sends everybody on to HTTPS
        at the same host), for whoever typed it to take. Never taken by itself."""
        return JSONResponse({"code": ex.code, "message": ex.message, **({"use": ex.use} if ex.use else {})}, status_code=422)

    def not_taken(ex: ValueError) -> JSONResponse:
        """What was typed, refused: said as the check says it (capitalize() wrote the rest small, qKVM as qkvm)."""
        said = str(ex)
        return fail(422, "invalid", said[:1].upper() + said[1:])

    def console_link_of(body: DeviceIn, own: DeviceRecord | None) -> str:
        """The console link to save (`_open_url`). One 0.2.0 saved as typed, in a form not taken since 0.2.1 (a host written as
        numbers another way, 127.1), that an edit sends back unchanged is kept as it was saved: the edit of the rest was
        refused for it until the link was written again. (No way into a console is made out to such a host: shares_our_name
        takes one that looks like numbers and cannot be read so for the wall's own; and the page reads it as a browser does.)"""
        if own is not None and own.open_url and body.open_url.strip() == own.open_url:
            try:
                return _open_url(body.open_url)
            except ValueError:
                return own.open_url
        return _open_url(body.open_url)

    def parse_vnc(body: DeviceIn, own: DeviceRecord | None) -> tuple[str, str, str] | JSONResponse:
        """A VNC server, said so by the kind chosen or by its address (vnc://, vncs://): it speaks no HTTP, and is not asked what it is."""
        try:
            url, open_url = vncdevice.vnc_url(body.url), console_link_of(body, own)
        except ValueError as ex:
            return not_taken(ex)
        if any(d.url == url and d is not own for d in store.devices):
            return fail(409, "duplicate", "This device is already on the wall")
        return url, open_url, "vnc"

    async def parse_proxmox(body: DeviceIn, own: DeviceRecord | None) -> tuple[str, str, str] | JSONResponse:
        """A guest of Proxmox, said so by the kind chosen: the address names the guest, by its number and its node.
        Where only its number is given, its node is asked of Proxmox with the token typed (or, at the address it was
        saved for, the saved one: never sent anywhere else on the strength of an address typed in an edit)."""
        try:
            found, open_url = proxmox.address_of(body.url), console_link_of(body, own)
        except ValueError as ex:
            return not_taken(ex)
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
            url, open_url = device_url(body.url), console_link_of(body, own)
        except ValueError as ex:
            return not_taken(ex)
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
        # Saved without checking, nothing about how it is signed in to changed (its name, its group, its alerts): as any edit so
        # saved, not asked what its plain address says now. Refused for that in full, a tile whose KVM sends that address on to
        # HTTPS since could not be renamed while it keeps it (the independent review of 0.3.2, L1). Its own connection goes on
        # holding its sign-in back there; anything else is asked, saved without checking or not: a password typed, another
        # user name, address, kind or certificate check is not sent the plain way to a KVM that says it answers on HTTPS.
        unchecked_as_it_was = (
            own is not None
            and body.force
            and not body.password
            and (url, kind, body.tls or own.tls, body.username.strip()) == (own.url, own.kind, own.tls, own.username)
        )
        if kind == "auto":
            try:
                kind, url = await detect_kind(url, "://" in body.url, typed)
            except KvmError as ex:
                return not_taken_there(ex)
        if kind == "kvmd" and not unchecked_as_it_was and (to := await sent_on_to_https(url)) is not None:
            # Asked before the password typed or saved goes to its plain address: of a kvmd chosen, or kept in an edit of the same
            # address, which is not asked what it is; and of one found by asking, where nothing else answered. Asking what it is
            # sees a plain address that sends its own paths on to HTTPS, and not one that sends its API alone (nginx with only
            # /api/ on HTTPS), which was sent the password typed the plain way before (the outside review of 0.3.2, its L4).
            return not_taken_there(on_https(to))
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
            no_signal_minutes=body.no_signal_minutes or 0,
            unchanged_minutes=body.unchanged_minutes or 0,
        )
        if body.tls is None and url.startswith("https") and await publicly_trusted(url):
            # Reached through somebody's front door, whose certificate changes every few weeks: not one to remember.
            record.tls = "system"
        try:
            client, about = await connect(record, body.password, body.force)
        except KvmError as ex:
            return not_taken_there(ex)
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
                record.ident = client.spec.ident = f"own:{record.id}"  # told to keep both: from here on it is a device of its own
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

    def left_alone(record: DeviceRecord) -> JSONResponse | None:
        """The answer for a tile of a kind this version does not know (core.UnknownKind), which nothing here contacts."""
        if record.kind in KINDS:
            return None
        said = unknown_kind(record.kind)
        return fail(said.status, said.code, f"{said.message}. It can be removed, not edited, here.")

    @app.put("/api/v1/devices/{device_id}")
    async def update_device(device_id: str, body: DeviceIn, request: Request) -> Response:
        record = store.device(device_id)
        if record is None:
            return fail(404, "not_found", "Unknown device")
        if refusal := left_alone(record):
            return refusal
        parsed = await parse(body, record)
        if isinstance(parsed, JSONResponse):
            return parsed
        url, open_url, kind = parsed
        # (Where parse took a plain JetKVM to its HTTPS address by itself: it offers it by now, and the plain one was typed.)
        try:
            typed_url = device_url(body.url)
        except ValueError:
            typed_url = url
        by_itself = kind == record.kind == "jetkvm" and record.url.startswith("http://") and url == other_way(record.url) and typed_url == record.url
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
            no_signal_minutes=record.no_signal_minutes if body.no_signal_minutes is None else body.no_signal_minutes,
            unchanged_minutes=record.unchanged_minutes if body.unchanged_minutes is None else body.unchanged_minutes,
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
        # Onto its HTTPS address with its password, typed or saved: only where what answers there is this JetKVM, as when the
        # tile follows by itself (`onto_https`, and `moved`). Without that check the saved password went to whatever showed
        # another tile's certificate there, and with the password typed the tile became that other tile's JetKVM. Where parse
        # took it there by itself and it is not that JetKVM, the edit is made at the plain address typed, as it stands, and
        # says so; where the HTTPS address was typed, it is refused, in words of that address.
        client: Device | None = None
        not_followed = ""
        if to_https:
            try:
                client = await onto_https(changed, url, await https_certificate(record.id, url), body.password or None)
            except NotFollowed as ex:
                if not by_itself:
                    return fail(422, "another_machine", f"What answers at {url} is not this JetKVM ({ex}): nothing was changed")
                log.warning("%s: offers HTTPS at %s, and what answers there is not followed: %s", record.name, url, ex)
                not_followed = f"Not followed onto HTTPS at {url}: {ex}"
                url = changed.url = record.url
                moved = to_https = False
            except KvmError as ex:
                # Not checked: never onto HTTPS unchecked, saved without checking or not ("Keep both" sends that too). There
                # it fell through to a connect that trusted what answered first, took its number, and refused no twin (the
                # JetKVM/Proxmox review, F1). Saved without checking where parse took it there by itself: at the plain address
                # typed, as where what answers is not followed; with the HTTPS address typed, refused.
                if not body.force:
                    return fail(422, ex.code, ex.message)
                if not by_itself:
                    return fail(422, ex.code, f"{ex.message}. What answers at {url} could not be checked, and a JetKVM is not taken onto HTTPS unchecked: nothing was changed")
                log.warning("%s: offers HTTPS at %s, which could not be checked: %s", record.name, url, ex.message)
                not_followed = f"Not followed onto HTTPS at {url}: {ex.message}"
                url = changed.url = record.url
                moved = to_https = False
        if client is None and (changed.tls != record.tls or (moved and not known_again)):
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
        if client is None:
            try:
                client, _ = await connect(changed, body.password or None, body.force and not carried, take=typed)
            except KvmError as ex:
                if body.force and carried:
                    return fail(422, "password_needed", f"This device could not be checked at its new address ({ex.message}). Type its password to save it there all the same.")
                return not_taken_there(ex)
        async with one_change:
            # The KVM was talked to without holding up other changes. What was checked before that is checked again.
            refusal = still_allowed(request)
            if refusal is None and store.device(device_id) is not record:
                refusal = fail(409, "conflict", "This KVM was changed or removed by someone else just now. Look at it again.")
            if refusal is None and body.keep_both and twin_of(changed) is not None:
                changed.ident = client.spec.ident = f"own:{record.id}"  # the two are to stay, and nobody is to be asked about them again
            if refusal is None and any(d.url == url and d is not record for d in store.devices):
                refusal = fail(409, "duplicate", "This device is already on the wall")
            if refusal is not None:
                await client.close()
                return refusal
            if body.password:
                changed.secret = core.vault.encrypt(body.password, changed.id)
            at = store.devices.index(record)
            store.devices[at] = changed
            # Another address, kind or check, or another controller (not the same one known better: identity_follows): what
            # was lent to the one before ends, and a mount of it under way hands out nothing (the outside review's fourth round)
            before = (record.cert_pem, record.machine, record.ident)
            ended = None
            if (record.url, record.kind, record.tls) != (changed.url, changed.kind, changed.tls) or identity_follows(before, (changed.cert_pem, changed.machine, changed.ident)) is None:
                ended = core.served.of(device_id)
                core.served.changed(device_id)
            await manager.adopt(client)
            for url_ in (record.url, changed.url):
                vncdevice.forget_pace(url_)
            try:
                await save()
            except OSError as ex:
                store.devices[at] = record
                await manager.replace(record)
                refused = not_saved("The change to this device", ex)
                if ended is None:
                    return refused
                # (Ended before the save, for whichever controller it was to be: not given back with the record. The outside
                # review's fifth round found "nothing was changed" said of it.)
                return fail(507, "not_saved", f"The change to this device could not be saved ({ex.strerror or ex}), so nothing was changed, "
                            f"but for {ended.name}, mounted on it from qKVM, which is served no more: mount it again.")
        # (Where the password typed took a machine that gives another number than the one the tile knew, that is said: a person
        # who typed it for a tile that said "it may be another one" is to find what became of it.)
        notes = [not_followed] if not_followed else []
        kept = ""  # (a console link 0.2.0 saved in a form not taken since, kept as it was: see console_link_of)
        if open_url and open_url == record.open_url:
            try:
                _open_url(open_url)
            except ValueError as ex:
                kept = f"The console link is kept as it was saved, in a form qKVM no longer takes ({ex}): write it again to change it"
                notes.append(kept)
        if typed and record.machine and changed.machine and changed.machine != record.machine:
            notes.append("It takes the machine that answers now, which gives another number for itself than the one this tile was known by")
        note = ". ".join(notes)
        audit.write("device_changed", client_ip(request), device=changed.name, device_id=changed.id, url=url, **({"note": note} if note else {}))
        said = ". ".join(word for word in (not_followed, kept) if word)
        return JSONResponse({"device": view(changed), **({"note": said} if said else {})})

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
            work.add_done_callback(unheard("removing machines"))  # (cut off: should it fail now, nobody else would hear of it)
            raise

    def unheard(what: str) -> Callable[[asyncio.Task[Response]], None]:
        def heard(work: asyncio.Task[Response]) -> None:
            if not work.cancelled() and (ex := work.exception()) is not None:
                log.error("%s failed after its request was cut off", what, exc_info=ex)

        return heard

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
        for gone in going:
            core.served.changed(gone)  # (what was lent to them ends, and a mount of them under way hands out nothing)
        taken = manager.take(going)
        try:
            together = {"note": f"one of {len(places)} removed together"} if len(places) > 1 else {}
            for record in places:
                watcher.forget(record.id)
                screen_watch.forget(record.id)  # (and the picture kept for an alert of its screen, at the next round)
                watch_told.pop(record.id, None)
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
    async def certificate(device_id: str, target: str | None = Query(None, max_length=64)) -> Response:
        record = store.device(device_id)
        if record is None:
            return fail(404, "not_found", "Unknown device")
        if refused := not_as_seen(target or None, device_id):  # (no certificate of the machine an edit put under the tile, under the old name)
            return refused
        if refusal := left_alone(record):
            return refusal
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
        if refused := not_as_seen(body.target, device_id):
            return refused
        if refusal := left_alone(record):
            return refusal
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
            if trusted.cert_pem != record.cert_pem:
                core.served.changed(device_id)  # (a certificate trusted anew: what was lent before ends; mount again)
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
    async def wol_targets(device_id: str, request: Request, target: str | None = Query(None, max_length=64)) -> Response:
        device = manager.devices.get(device_id)
        if device is None or not allowed(request, device_id):
            return fail(404, "not_found", "Unknown device")
        # (The computers the machine the menu was opened for wakes, not those of the one an edit put under the tile since. An
        # empty `target` is none, as these reads older than 0.4.0 took whatever came along; what acts refuses an empty one.)
        if refused := not_as_seen(target or None, device_id):
            return refused
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

    def inputs_listed(device: Device) -> bool:
        """Whether the device's last look listed its inputs, two or more (its status's `ports`). Where it says `several_inputs`
        without them (its switch did not answer that look, or had not said yet), how many it has is not known at the moment."""
        ports = (device._status or {}).get("ports")
        return isinstance(ports, dict) and isinstance(ports.get("list"), list) and len(ports["list"]) > 1

    def inputs_unknown(name: str) -> KvmError:
        """Keys or text sent as for a KVM of one input where the wall does not know at the moment how many inputs it has (the
        review of Builder HB's round, L3: they were said to go to a KVM that "has several inputs" also then)."""
        said = f"{name} has several inputs, or may have (qKVM does not know at the moment how many), and keys and text go to the computer on screen: this was sent as for a KVM of one input."
        return KvmError("input_changed", f"{said} Nothing was sent: look at it again.", 409)

    def not_as_seen(target: str | None, device_id: str) -> JSONResponse | None:
        """Asked of an action and of a live line's pass before anything is sent: the request was made for the machine this
        tile is at now (`target`, as its view gave it: target_of). Otherwise nothing is sent, and it is said why, in words that
        send whoever asked to look again (the page does not send it again by itself). Left out, as by a script or a client
        before 0.4.0: not asked, as before. (Asked once, at the start: a later edit of the tile puts another connection in the
        device's place, which `waited_for` and the driver's own retirement find, RETIRED, as before.)"""
        record = store.device(device_id)
        if target is None or (record is not None and target == target_of(record)):
            return None
        name = record.name if record is not None else "This machine"
        return fail(
            409, "machine_changed",
            f"{name} is not the machine you saw any more: its tile was pointed at another machine, or qKVM knows more of the machine "
            "since. Nothing was sent: look at it again.",
        )  # fmt: skip

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
        if refused := not_as_seen(body.target, device_id):  # (confirmed for the machine before an edit put another in its place)
            return refused
        if body.one_input and body.input is not None:
            return fail(422, "invalid", "Name the input on screen (input), or say the KVM has one (one_input): not both.")
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
        # Keys and text for the computer on one input of a KVM with several: the driver asks the KVM which is on screen right
        # before they go (INPUT_ASKED). A machine whose driver cannot has no input to name: refused unsent. (Power and the rest
        # are the KVM's own, whichever is on screen. The outside review 6.2 re-checks, R2, H4 and H5.)
        asked = body.input if action in KEYBOARD_ACTIONS else None
        # (In the activity log, keys and text say the input they were for, as people count them, or that they were sent as for a
        # KVM of one input: the supervised key test of 2026-11-23 found neither there.)
        if asked is not None:
            detail["input"] = asked + 1
        elif body.one_input and action in KEYBOARD_ACTIONS:
            detail["one_input"] = True
        said: KvmError | None = None  # refused on what the wall knows of the machine's inputs, before anything went
        if refusal is None and asked is not None and not device.reads_input:
            said = input_refused(device.spec.name, asked, None, "it has no inputs to choose from")
        # Sent as for a KVM of one input (`one_input`): refused where it has shown several; its switch is asked right before they
        # go (INPUT_ASKED). A machine with no inputs to choose from is one of a single input. (The narrow look, HIGH 5.)
        if body.one_input and action in KEYBOARD_ACTIONS and device.reads_input:
            asked = ONE_INPUT
            if refusal is None and said is None and device.several_inputs():
                said = one_input_refused(device.spec.name) if inputs_listed(device) else inputs_unknown(device.spec.name)
        if said is not None:
            # (In the activity log as the KVM's own refusal of them is, in its words: it was tried, and nothing went.)
            audit.write("action_failed", client_ip(request), error=said.message, **detail)
            refusal = fail(said.status, said.code, said.message)
        if refusal is not None:
            acted_on.discard(device_id)
            return refusal
        note: str | None = None  # where what happened is not simply "done": "already on"
        def still_theirs() -> bool:
            """Whether whoever asked for this may still have it done (asked by what takes long: typing key by key)."""
            return still_allowed(request) is None and allowed(request, device_id)

        pressed_at = time.time()  # (what the history keeps of a power button: when it was pressed)
        answered, sent, named = PRESS_ANSWERED.set(False), PRESS_SENT.set(None), INPUT_ASKED.set(asked)
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
            INPUT_ASKED.reset(named)
            acted_on.discard(device_id)
        audit.write("action", client_ip(request), **detail)
        return JSONResponse({"ok": True, "note": note})

    # (Each its own: consoles not had, asked for in a loop, leave the openings' allowance as it was. The program's: Core.)
    console_said = core.console_said

    def console_written(event: str, request: Request, device: str, device_id: str, **detail: Any) -> None:
        """A server's console opened or not had, into the activity log: within the account's allowance (activity.Allowance)."""
        # (Each server opened is named once an hour whatever is left; a console not had gives nobody a way in, and is not.)
        unsaid = console_said[event].take(request.state.user.id, device_id if event == "console_opened" else None)
        if unsaid is not None:
            audit.write(event, client_ip(request), device=device, device_id=device_id, **detail, **({"unsaid": unsaid} if unsaid else {}))

    @app.post("/api/v1/devices/{device_id}/console")
    async def open_console(device_id: str, request: Request, target: str | None = Query(None, min_length=1, max_length=64)) -> Response:
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
        # `target`: the server the page showed (target_of), as for an action: no way into the console of the one an edit put
        # under the tile meanwhile (409 `machine_changed`, nothing asked of it; the fresh review of the HA round, L1).
        if refused := not_as_seen(target, device_id):
            return refused
        # Not to a page on a name this wall is looked at under (another port of it): the browser would hand that page the
        # sign-in to this wall along with the pass. The page offers no link there and says why; nothing is asked of the device.
        # (A kind of device that hands out no way in at all says so below, as it did: `no_console`, and nothing is asked.)
        offers = type(device).console is not Device.console
        if offers and shares_our_name(record.open_url or record.url, request.headers.get("host", ""), store.server.allowed_hosts):
            return fail(
                409, "same_host",
                "Its console is on a host name qKVM is looked at under, at another port, and a browser would hand it your sign-in to "
                "qKVM. Look at one of the two under another name or address.",
            )  # fmt: skip
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
        if refused := not_as_seen(body.target, device_id):  # (asked for the PC before an edit put another under the tile)
            return refused
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

        def still_theirs() -> bool:
            """Whether whoever asked may still have it done: asked before each write to the engine, which may come seconds
            after this (a look the switch waits for, the question which PC answers). As for an action (`act`)."""
            return still_allowed(request) is None and allowed(request, device_id)

        try:
            await device.switch_kvm(body.on, still=still_theirs)
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

    # --- virtual media: an image mounted on a machine, and the machine started from it (0.3.0) -------------------------
    # Root on that machine: the media right's (MEDIA_ROLE, in required_role, asked again by still_allowed whenever time has
    # passed), a person's and never a token's, named in a confirmation (the machine, by the name the person was shown, and
    # the image), one thing at a time per machine, every mount, unmount, start, upload and deletion in the activity log.
    # What is mounted is only ever what the driver itself listed, by its id: never an address. An image carried to a
    # device's own storage goes through a piece at a time as it comes (never read in full, never written anywhere here),
    # counted and hashed on its way (kvm.Carried).

    uploads: dict[str, dict[str, Any]] = {}  # device id -> the upload under way to it: its name, who, since when, what carries it

    def media_target(request: Request, device_id: str, target: str | None = None) -> tuple[Device, DeviceRecord, MediaOffer] | JSONResponse:
        device, record = manager.devices.get(device_id), store.device(device_id)
        if device is None or record is None or not allowed(request, device_id):
            return fail(404, "not_found", "Unknown device")
        if is_token(request.state.user):
            return fail(403, "not_allowed", "Virtual media is for a person, not for a token")
        # `target`: the machine the Media box was opened for (target_of): no list of the one an edit put under the tile since,
        # whose `listed` the box's next change would carry there (409 `machine_changed`; the second fresh review of the HA round).
        if refused := not_as_seen(target, device_id):
            return refused
        offer = device.media_offer()  # (this machine's, as the last look at it found it)
        if offer is None:
            return fail(404, "no_virtual_media", f"{record.name} has no virtual media")
        return device, record, offer

    def media_named(machine: str, record: DeviceRecord, what: str) -> JSONResponse | None:
        """The confirmation named this machine as it is called now: otherwise nothing is done, and it is said why."""
        if machine != record.name:
            return fail(409, "changed", f"The confirmation named {machine}, and this machine is called {record.name} now. Nothing was {what}: look at it again.")
        return None

    def media_moved(listed: str | None, device_id: str, device: Device, record: DeviceRecord, what: str) -> JSONResponse | None:
        """The change was chosen from a list of this tile's machine as it is now (`listed`, media_listed of the driver that will
        do it): otherwise nothing is done, and it is said why (the desktop app's finding 21). A change that names no list (a
        client before 0.3.2) is not asked this, as before."""
        if listed is None or listed == media_listed(device_id, device.spec):
            return None
        return fail(
            409, "moved",
            f"{record.name} is not the machine its images were listed for any more: its address, or what qKVM knows of the machine "
            f"there, was changed since. Nothing was {what}: list its images again.",
        )  # fmt: skip

    def media_failed(event: str, ex: KvmError, detail: dict[str, Any], request: Request, record: DeviceRecord, mounted: str = "") -> JSONResponse:
        """A refusal of the device's, written down and said; `mounted`: the image is mounted, and what failed came after it
        (what was not done, for the sentence: "started from it", "restarted")."""
        if ex is RETIRED:
            # (As for an action: the connection it went out on was taken away meanwhile, and it may have been done.)
            ex = KvmError("timeout", f"{record.name} was being changed while this was under way. It may have been done all the same: look at the machine before trying again.", 504)
        said = scrubbed(ex.message)  # (nothing of a mount's that the controller said back, whatever passed it on)
        audit.write(event, client_ip(request), error=said, **detail)
        message = f"The image is mounted, and {record.name} was not {mounted}: {said}" if mounted else said
        return JSONResponse({"code": ex.code, "message": message, "mounted": bool(mounted)}, status_code=ex.status)

    def media_held(request: Request, device_id: str, record: DeviceRecord, image: str, restart: bool, drops: bool = False) -> JSONResponse | None:
        """One thing at a time per machine, as for an action: and a restart, as a power button, not while somebody has its
        keyboard and mouse over a live line; nor, where a mount or an unmount drops them for a moment (`drops`: the offer
        says so), while somebody else has them (whoever asks has been told, in the box). Nor anything of the image that is
        being uploaded to it (by its name, or as a JetKVM lists it meanwhile: `<name>.incomplete`). None: it is the caller's
        now (acted_on), and is let go of by it."""
        if device_id in acted_on:
            return fail(409, "busy", f"Something else is being done to {record.name} at this moment. Wait for it to finish.")
        if (up := uploads.get(device_id)) is not None and image in (up["name"], up["name"] + ".incomplete"):
            return fail(409, "busy", f"{image} is being uploaded to {record.name} at this moment. Wait for it to finish.")
        by = lines.held_by(device_id)
        if by is not None and (restart or (drops and by != request.state.user.name)):
            return keyboard_held(record.name, by, request)
        return None

    def still_theirs_of(request: Request, device_id: str) -> Callable[[], bool]:
        def still_theirs() -> bool:
            """Whether whoever asked may still have it done: asked before every change the driver makes (as for an action)."""
            return still_allowed(request) is None and allowed(request, device_id)

        return still_theirs

    def uploading(device_id: str) -> dict[str, Any] | None:
        """The upload under way to this machine, as far as it has come: None where there is none."""
        up = uploads.get(device_id)
        if up is None:
            return None
        carried: Carried = up["carried"]
        return {"name": up["name"], "size": carried.size, "sent": carried.sent, "by": up["by"], "at": up["at"]}

    @app.get("/api/v1/devices/{device_id}/media")
    async def media_list(device_id: str, request: Request, target: str | None = Query(None, max_length=64)) -> Response:
        """The images that can be mounted on this machine, what is mounted, and what its virtual media can do."""
        found = media_target(request, device_id, target or None)  # (empty: none, as for the other reads older than 0.4.0)
        if isinstance(found, JSONResponse):
            return found
        device, _, offer = found
        try:
            listed = await device.media_images()
        except KvmError as ex:
            return fail(ex.status, ex.code, ex.message)
        # (The machine as this list was made of it, once it has answered: what it was known by as it did.)
        said = {
            **listed, "mounted": device.media_now(), "offers": (device.media_offer() or offer).as_dict(), "uploading": uploading(device_id),
            "listed": media_listed(device_id, device.spec),
        }  # fmt: skip
        return still_shown(request, device_id) or JSONResponse(said)

    @app.get("/api/v1/devices/{device_id}/media/upload")
    async def media_upload_now(device_id: str, request: Request) -> Response:
        """How far the upload under way to this machine has come (asked by the page while its own is out): nothing is asked of
        the machine for it."""
        found = media_target(request, device_id)
        if isinstance(found, JSONResponse):
            return found
        return JSONResponse({"uploading": uploading(device_id)})

    @app.post("/api/v1/devices/{device_id}/media")
    async def media_mount(device_id: str, body: MediaIn, request: Request) -> Response:
        found = media_target(request, device_id)
        if isinstance(found, JSONResponse):
            return found
        device, record, offer = found
        if refused := media_moved(body.listed, device_id, device, record, "mounted") or media_named(body.machine, record, "mounted"):
            return refused
        restart = body.restart or body.boot == "once"
        if body.drive not in offer.drives:
            return fail(422, "invalid", f"{record.name} takes no image as {MEDIA_DRIVE_SAID[body.drive]}")
        if body.writable and body.drive not in offer.writable:
            return fail(422, "invalid", f"{record.name} takes an image as {MEDIA_DRIVE_SAID[body.drive]} read-only, and only so")
        if body.boot != "none" and body.boot not in offer.boot:
            return fail(422, "invalid", f"{record.name} cannot be told to start from an image that way")
        if body.restart and body.boot == "none" and offer.boot:
            return fail(422, "invalid", "A restart that does not start from the image is a power button's: use the power buttons")
        if restart and not offer.restart:
            return fail(422, "invalid", f"{record.name} cannot be restarted from here")
        if refused := media_held(request, device_id, record, body.image, restart, offer.drops_input):
            return refused
        acted_on.add(device_id)
        try:
            # (A restart is a power button's: the last holder's keys are let go of first, as for an action.)
            refusal = waited_for(request, device_id, device) if restart and await lines.handed_over(device_id) else None
        except BaseException:
            acted_on.discard(device_id)
            raise
        if refusal is not None:
            acted_on.discard(device_id)
            return refusal
        still_theirs = still_theirs_of(request, device_id)
        detail: dict[str, Any] = {
            "device": record.name, "device_id": device_id, "image": body.image, "drive": body.drive, "writable": body.writable,
            "boot": body.boot, "restart": restart,
        }  # fmt: skip
        notes: list[str] = []
        # Bound to the controller as it is known now, before anything is asked of it: an edit that slips in meanwhile (to
        # another controller at the same address) changes the record, not this (the outside review's third round).
        core.served.binding[device_id] = Binding((record.cert_pem, record.machine, record.ident), record.kind, core.served.epoch(device_id))
        try:
            try:
                note = await device.media_mount(body.image, drive=body.drive, writable=body.writable, by=request.state.user.name, still=still_theirs)
            except KvmError as ex:
                return media_failed("media_mount_failed", ex, detail, request, record)
            except asyncio.CancelledError:
                audit.write("media_mount_failed", client_ip(request), error="qKVM was stopped or restarted before the machine answered: it may have been mounted", **detail)
                raise
            mounted = device.media_now()
            if mounted is not None and mounted.get("image") == body.image and mounted.get("sha256"):
                detail["sha256"] = mounted["sha256"]  # (an image qKVM carried there, and still that one)
            audit.write("media_mounted", client_ip(request), **detail, **({"note": note} if note else {}))
            notes += [note] if note else []
            if body.boot != "none":
                try:
                    note = await device.media_boot(body.boot, restart=restart, still=still_theirs)
                except KvmError as ex:
                    return media_failed("media_boot_failed", ex, detail, request, record, mounted="started from it")
                except asyncio.CancelledError:
                    audit.write("media_boot_failed", client_ip(request), error="qKVM was stopped or restarted while the machine was being started from the image: look at it", **detail)
                    raise
                audit.write("media_booted", client_ip(request), **detail, **({"note": note} if note else {}))
                notes += [note] if note else []
            elif restart:
                # (A machine that cannot be told to start from it, restarted for its firmware to find it: a power button's press.)
                try:
                    note = await device.media_restart(still=still_theirs)
                except KvmError as ex:
                    return media_failed("media_restart_failed", ex, detail, request, record, mounted="restarted")
                except asyncio.CancelledError:
                    audit.write("media_restart_failed", client_ip(request), error="qKVM was stopped or restarted while the machine was being restarted: look at it", **detail)
                    raise
                audit.write("media_restarted", client_ip(request), **detail, **({"note": note} if note else {}))
                notes += [note] if note else []
        finally:
            core.served.binding.pop(device_id, None)
            acted_on.discard(device_id)
        return JSONResponse({"ok": True, "note": " ".join(notes) or None, "mounted": device.media_now()})

    @app.post("/api/v1/devices/{device_id}/media/unmount")
    async def media_unmount(device_id: str, body: UnmountIn, request: Request) -> Response:
        found = media_target(request, device_id)
        if isinstance(found, JSONResponse):
            return found
        device, record, offer = found
        if refused := media_moved(body.listed, device_id, device, record, "taken out") or media_named(body.machine, record, "taken out"):
            return refused
        if refused := media_held(request, device_id, record, "", restart=False, drops=offer.drops_input):
            return refused
        acted_on.add(device_id)
        detail: dict[str, Any] = {"device": record.name, "device_id": device_id, "image": body.image}
        if (was := device.media_now()) is not None and was.get("image") == body.image and was.get("sha256"):
            detail["sha256"] = was["sha256"]
        try:
            note = await device.media_unmount(body.image, still=still_theirs_of(request, device_id))
        except AlreadySo as so:
            note = str(so)
        except KvmError as ex:
            return media_failed("media_unmount_failed", ex, detail, request, record)
        except asyncio.CancelledError:
            audit.write("media_unmount_failed", client_ip(request), error="qKVM was stopped or restarted before the machine answered: it may have been taken out", **detail)
            raise
        finally:
            acted_on.discard(device_id)
        audit.write("media_unmounted", client_ip(request), **detail, **({"note": note} if note else {}))
        return JSONResponse({"ok": True, "note": note, "mounted": device.media_now()})

    @app.post("/api/v1/devices/{device_id}/media/delete")
    async def media_delete(device_id: str, body: DeleteIn, request: Request) -> Response:
        """Delete an image from the device's own storage: what qKVM carried there, or anything else it lists."""
        found = media_target(request, device_id)
        if isinstance(found, JSONResponse):
            return found
        device, record, offer = found
        if refused := media_moved(body.listed, device_id, device, record, "deleted"):
            return refused
        if not offer.delete:
            return fail(422, "invalid", f"{record.name} has no images of its own that qKVM deletes")
        if refused := media_named(body.machine, record, "deleted"):
            return refused
        if refused := media_held(request, device_id, record, body.image, restart=False):
            return refused
        acted_on.add(device_id)
        detail: dict[str, Any] = {"device": record.name, "device_id": device_id, "image": body.image}
        try:
            note = await device.media_delete(body.image, still=still_theirs_of(request, device_id))
        except AlreadySo as so:
            note = str(so)
        except KvmError as ex:
            return media_failed("media_delete_failed", ex, detail, request, record)
        except asyncio.CancelledError:
            audit.write("media_delete_failed", client_ip(request), error="qKVM was stopped or restarted before the device answered: it may have been deleted", **detail)
            raise
        finally:
            acted_on.discard(device_id)
        audit.write("media_deleted", client_ip(request), **detail, **({"note": note} if note else {}))
        return JSONResponse({"ok": True, "note": note})

    async def upload_pieces(request: Request, still: Callable[[], bool]) -> AsyncIterator[bytes]:
        """The image as the browser sends it, a piece at a time as it arrives (bounded: the web server reads no further ahead
        than a piece or two). Cut off where nothing comes for UPLOAD_QUIET seconds, where the sender stops, and where whoever
        sends it may no longer (asked every UPLOAD_ASK_EVERY seconds): kvm.UploadCut, raised inside the driver's carrying."""
        receive = request.scope.get(CarriedThrough.KEY)  # (the web server's own: see CarriedThrough)
        if receive is None:
            raise UploadCut("The upload did not come the way an upload comes")
        asked_at = time.monotonic()
        more = True
        while more:
            try:
                async with asyncio.timeout(UPLOAD_QUIET):  # (never wait_for: see kvm.Listening.message)
                    message = await receive()
            except TimeoutError:
                raise UploadCut(f"Nothing of the image came for {round(UPLOAD_QUIET)} seconds, and its upload was stopped") from None
            if message.get("type") != "http.request":
                raise UploadCut("The upload was stopped before the image came in full")
            piece, more = message.get("body", b""), bool(message.get("more_body", False))
            if time.monotonic() - asked_at >= UPLOAD_ASK_EVERY:
                asked_at = time.monotonic()
                if not still():
                    raise UploadCut("Whoever uploads it may no longer do that, and its upload was stopped")
            if piece:
                yield piece

    @app.post("/api/v1/devices/{device_id}/media/upload")
    async def media_upload(
        device_id: str, request: Request,
        name: Annotated[str, Query(min_length=1, max_length=300)], machine: Annotated[str, Query(min_length=1, max_length=4 * 60)],
        listed: Annotated[str | None, Query(min_length=1, max_length=64)] = None,  # (as MediaIn's)
    ) -> Response:  # fmt: skip
        """Carry the image in the body into the device's own storage, as `name`: streamed through as it comes, kept nowhere."""
        found = media_target(request, device_id)
        if isinstance(found, JSONResponse):
            return found
        device, record, offer = found
        if refused := media_moved(listed, device_id, device, record, "uploaded"):
            return refused
        if not offer.upload:
            return fail(422, "invalid", f"Images are not carried through qKVM to {record.name}")
        if refused := media_named(machine, record, "uploaded"):
            return refused
        size = int(request.headers["content-length"])  # (said, a number, and no more than MOST_UPLOAD: the guard saw to it)
        if size <= 0:
            return fail(422, "invalid", "An empty file is no image")
        if (up := uploads.get(device_id)) is not None:
            return fail(409, "busy", f"{up['name']} is being uploaded to {record.name} at this moment, by {up['by']}. Wait for it to finish.")
        user: UserRecord = request.state.user
        still_theirs = still_theirs_of(request, device_id)
        carried = Carried(upload_pieces(request, still_theirs), size)
        uploads[device_id] = {"name": name, "by": user.name, "at": time.time(), "carried": carried}
        detail: dict[str, Any] = {"device": record.name, "device_id": device_id, "image": name, "size": size}
        try:
            try:
                put_there = await device.media_upload(name, carried, by=user.name, still=still_theirs)
            except KvmError as ex:
                message = ex.message
                if ex is RETIRED and (other := manager.devices.get(device_id)) is not None and other is not device:
                    # (The tile was edited meanwhile. What the cut-off upload left is taken off by the client that took its place
                    # only where that client is for the same device: its address, its kind, its pinned certificate and its
                    # identity marks unchanged. Moved to another device, nothing is touched there: a partial image of the
                    # same name on it is none of this upload's (the outside review of 0.3.0, M3).)
                    same = [(spec.base_url, spec.kind, spec.cert_pem, spec.machine, spec.ident) for spec in (device.spec, other.spec)]
                    if same[0] == same[1]:
                        try:
                            left = await other.media_discard(name)
                        except KvmError as again:
                            left = f"What it left on the device could not be taken off: {again.message}"
                        left = left or "Nothing of it is left on the device."
                    else:
                        left = f"What came of it may be on the device it was going to, at {device.spec.base_url}: look there."
                    message = f"{record.name} was changed while its image was on its way, and the upload was stopped. {left}"
                    ex = KvmError("timeout", message, 504)
                audit.write("media_upload_failed", client_ip(request), error=message, sent=carried.sent, **detail)
                return JSONResponse({"code": ex.code, "message": message, "sent": carried.sent}, status_code=ex.status)
            except asyncio.CancelledError:
                audit.write("media_upload_failed", client_ip(request), error="qKVM was stopped or restarted while the image was on its way: what came of it is on the device as the device left it", sent=carried.sent, **detail)
                raise
        finally:
            uploads.pop(device_id, None)
        audit.write("media_uploaded", client_ip(request), sha256=carried.sha256, **detail)
        return JSONResponse({"ok": True, "image": put_there, "sha256": carried.sha256})

    # --- an image mounted on a server, as its controller reads it (served.py, 0.3.0 A4) ------------------------------
    # Public: the controller has no session here. By the address made for that one mount, to the controller's own address
    # alone (where the connection comes from, or a believed proxy says it does), with the user and the password made for that
    # mount where there are some; to anything else there is nothing at this address, the same answer whatever was wrong.
    # Only while it is mounted, on the tile it was mounted for at the address it had then; only the file that was mounted,
    # unchanged; a range of it as asked (a controller reads it a piece at a time), GET and HEAD alone. Cut off where its
    # mount ends meanwhile. Nothing is written in the activity log for a read (a controller reads an image in thousands).
    # The file is opened, read and let go of in threads of its own (served.READERS), never on the loop: on a share that
    # stalls, a close waits for the read under way, and a read's place among MOST_AT_ONCE is given back once its thread
    # has let go of the file.

    def nothing_here() -> Response:
        return PlainTextResponse("There is nothing at this address.", status_code=404)

    def still_lent(lending: Lending) -> bool:
        """Whether what a mount lends is served still: not ended, and its tile on the wall at the address it had. A tile
        removed or moved to another address ends it there and then, a reading under way included (the outside review of
        0.3.0, M2: a reading went on to its end after its tile was removed; only a new one found it gone)."""
        if lending.ended:
            return False
        record = store.device(lending.device_id)
        if record is None or record.url != lending.tile_url or (lending.kind and record.kind != lending.kind) or not same_controller(lending, record):
            # (Removed, moved, or another controller accepted at the same address since: its certificate trusted, its
            # numbers taken. The outside review's second round, R2-M2.)
            core.served.end(lending.device_id, lending)
            return False
        return True

    def same_controller(lending: Lending, record: DeviceRecord) -> bool:
        """Whether the tile's controller is still the one a mount was bound to (served.identity_follows), and the binding
        takes what was learned of it (the outside review's third round: a look that learned the numbers ended a good mount;
        its fourth: a mount known by nothing learned another controller's)."""
        follows = identity_follows(lending.identity, (record.cert_pem, record.machine, record.ident))
        if follows is None:
            return False
        lending.identity = follows
        return True

    @app.api_route("/media/{token}/{name}", methods=["GET", "HEAD"])
    async def served_image(token: str, name: str, request: Request) -> Response:
        lending = core.served.find(token)
        if lending is None or name != lending.url_name or not still_lent(lending):
            return nothing_here()
        record = store.device(lending.device_id)
        assert record is not None  # (still_lent)
        asker = same_address(client_ip(request)) or "?"
        if asker not in lending.addresses:
            if asker not in lending.refused and len(lending.refused) < MOST_REFUSED_SAID:
                lending.refused.add(asker)
                log.warning("%s: its mounted image was asked for from %s, which is not its controller's address, and nothing was answered", record.name, asker)
            return nothing_here()
        # (As the controller says it, with nothing of the mount's in it, then cut short: the second round, R2-L2.)
        asked = plain(scrubbed(request.headers.get("range") or "", lending), 60) or ""
        if "asked" not in lending.refused:
            # Its first ask, once a mount: whether a controller that took a mount ever came for the image is said (a real
            # AMI board took one over plain HTTP and showed nothing: a read is said only once it went out whole).
            lending.refused.add("asked")
            log.info("%s: its controller asks for %s (%s%s)", record.name, lending.name, request.method, f", {asked}" if asked else "")
        if lending.credentials is not None and not basic_matches(request.headers.get("authorization", ""), lending.credentials):
            if "credentials" not in lending.refused:
                lending.refused.add("credentials")
                how = "with another user or password" if request.headers.get("authorization") else "without a user and a password (a client may send them once asked)"
                log.info("%s: its controller asked for %s %s, and was refused: it is read with those it was mounted with", record.name, lending.name, how)
            return PlainTextResponse("This image is read with the user and the password it was mounted with.", status_code=401, headers={"WWW-Authenticate": 'Basic realm="qKVM"'})
        wanted = byte_range(request.headers.get("range"), lending.image.size)
        if wanted is None:
            if "range" not in lending.refused:
                lending.refused.add("range")
                log.info("%s: its controller asked for %s with a range that could not be read as asked (%s), and was refused", record.name, lending.name, asked or "none")
            return Response(status_code=416, headers={"Content-Range": f"bytes */{lending.image.size}", "Accept-Ranges": "bytes"})
        # Its place among MOST_AT_ONCE is taken here, before the first wait, by a HEAD as well: reads that come together are
        # counted together (its M1: it was taken after the file was open, and never by a HEAD: 32 at once were all
        # taken). It is given back once, on every road, by the reader thread that lets go of the file: never by this
        # loop, which a restart of the listeners ends first (the second round, R2-M1).
        if not lending.take(MOST_AT_ONCE):
            return PlainTextResponse("Too many reads of this image at once.", status_code=503, headers={"Retry-After": "1"})
        slot = Slot(lending)
        loop = asyncio.get_running_loop()

        def readers() -> Any:
            return SERVED_READERS  # (as it is now: a test puts its own in place)

        opening = Opening(lending, slot, readers)
        try:
            opening.pending = SERVED_READERS.submit(opening.run)
        except RuntimeError:  # (the readers have stopped: qKVM stops)
            slot.give_back()
            return PlainTextResponse("qKVM is stopping.", status_code=503)
        try:
            handle = await asyncio.wrap_future(opening.pending)
        except asyncio.CancelledError:
            opening.abandon()  # (cut off while the file was being opened: the thread that opens it lets go of it)
            raise
        except OSError as ex:
            slot.give_back()
            if "changed" not in lending.refused:
                lending.refused.add("changed")
                log.warning("%s: its mounted image %s was changed, moved or removed in the folder, and is served no more: %s", record.name, lending.name, ex)
            return PlainTextResponse("The image was changed or removed since it was mounted.", status_code=410)
        except Exception:
            slot.give_back()  # (an opening that raised what is no OSError kept its read's place: the outside review's fourth round)
            raise
        first, last, part = wanted
        headers = {"Accept-Ranges": "bytes", "Content-Length": str(last - first + 1)}
        if part:
            headers["Content-Range"] = f"bytes {first}-{last}/{lending.image.size}"
        assert handle is not None  # (None only for a read that was cut off: it has not come back here)
        if request.method == "HEAD":
            hand_to_readers(readers, let_go_and_give_back, handle, slot)
            return Response(status_code=206 if part else 200, headers=headers, media_type="application/octet-stream")
        if lending.served == 0 and first == 0:
            log.info("%s: its controller reads %s from qKVM", record.name, lending.name)
        let_go: list[bool] = []

        def done() -> None:
            if let_go:
                return
            let_go.append(True)
            hand_to_readers(readers, let_go_and_give_back, handle, slot)

        async def pieces() -> AsyncIterator[bytes]:
            at, left = first, last - first + 1
            while left > 0 and still_lent(lending):
                try:
                    piece = await loop.run_in_executor(SERVED_READERS, read_at, handle, at, min(SERVED_PIECE, left))
                except (OSError, ValueError):  # (the disk would not, or the file was closed under it as the answer was cut off)
                    return
                if not piece:
                    return  # (shorter than it was: the answer ends short of its length)
                at, left = at + len(piece), left - len(piece)
                lending.served += len(piece)
                yield piece

        return Handed(pieces(), done, sent_while=lambda: still_lent(lending), status_code=206 if part else 200, headers=headers, media_type="application/octet-stream")

    @app.put("/api/v1/devices/{device_id}/view")
    async def set_amt_view(device_id: str, body: AmtViewIn, request: Request) -> Response:
        """Which of its three views a PC with Intel AMT is in: health only (no KVM session at all), stills (a still now and
        then for its tile; a session while its enlarged or live view is open), live KVM (a session held while its tile is
        shown as well). A setting of the tile and of nothing else, so an operator may change it as an admin may (an operator
        edits no tile otherwise); kept with the tile, in effect at once, and written down. One change at a time (_CHANGES)."""
        record = store.device(device_id)
        if record is None or not allowed(request, device_id):
            return fail(404, "not_found", "Unknown device")
        if is_token(request.state.user):
            # (A token changes no setting of a tile, this one included: it looks and acts, as SECURITY.md says.)
            return fail(403, "not_allowed", "A token does not change how a tile is set. Change its view on the wall's page.")
        # The machine it was chosen for first: a tile pointed from the PC at a KVM meanwhile is another machine (409
        # `machine_changed`, which sends the page to fetch the wall again), not a KVM without views (the outside review 5, Low 1).
        if refused := not_as_seen(body.target, device_id):  # (asked in the turn of changes: an edit of the tile waits for it, or it for the edit)
            return refused
        if record.kind != "amt":
            return fail(422, "invalid", "Only a PC with Intel AMT has these views")
        was = record.amt_view if record.amt_view in AMT_VIEWS else AMT_VIEWS[0]
        if body.view == was:
            return JSONResponse({"ok": True, "amt_view": was})  # (nothing changes, and nothing is written down)
        changed = dataclasses.replace(record, amt_view=body.view)
        at = store.devices.index(record)
        store.devices[at] = changed  # (a new record in the old one's place: an edit under way notices)
        device = manager.devices.get(device_id)
        if isinstance(device, amt.AmtDevice):  # (none while the saved passwords are locked: the one made later reads the record)
            device.set_view(body.view)

        def undo() -> None:
            if store.devices[at] is changed:
                store.devices[at] = record
            if isinstance(device, amt.AmtDevice) and manager.devices.get(device_id) is device:
                device.set_view(was)

        if refused := await saved("The view of this PC", undo):
            return refused
        audit.write("amt_view_changed", client_ip(request), device=record.name, device_id=device_id, view=body.view, was=was)
        return JSONResponse({"ok": True, "amt_view": body.view})

    @app.put("/api/v1/devices/{device_id}/open-in")
    async def set_open_in(device_id: str, body: OpenInIn, request: Request) -> Response:
        """Where else a machine can be opened, from its tile's menu: its page on MeshCentral, its RustDesk ID, its Remote
        Desktop host (open_in.py). An admin's (an admin may give a machine anything a tile is set with); all three at once,
        one left out or empty is none of that kind. Plain links, kept with the tile and written down: nothing is fetched from
        them, and no secret is taken for them. One change at a time (_CHANGES)."""
        record = store.device(device_id)
        if record is None or not allowed(request, device_id):
            return fail(404, "not_found", "Unknown device")
        if refused := not_as_seen(body.target, device_id):  # (links typed for the machine shown, not the one put in its place)
            return refused
        links: dict[str, str] = {}
        for kind in open_in.KINDS:
            try:
                link = open_in.checked(kind, getattr(body, kind))
            except ValueError as ex:
                return fail(422, "invalid", f"{str(ex)[:1].upper()}{str(ex)[1:]}.")
            if link:
                links[kind] = link
        was = open_in.kept(record.open_in)
        if links == was:
            return JSONResponse({"ok": True, "open_in": links})  # (nothing changes, and nothing is written down)
        changed = dataclasses.replace(record, open_in=links)
        at = store.devices.index(record)
        store.devices[at] = changed  # (a new record in the old one's place: an edit under way notices)

        def undo() -> None:
            if store.devices[at] is changed:
                store.devices[at] = record

        if refused := await saved("Its Open in links", undo):
            return refused
        audit.write("open_in_changed", client_ip(request), device=record.name, device_id=device_id, open_in=links, **({"was": was} if was else {}))
        return JSONResponse({"ok": True, "open_in": links})

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

        Asked at admission, before input and frame delivery, and periodically for idle lines. The account the
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
            # (Asked without using the sign-in: only the person's own requests keep it from ending. And one by the identity
            # proxy holds only while the proxy's word comes with the requests, which a line does not make.)
            session = core.sessions.get(holder.session, use=False)
            if session is None:
                return "signed_out", False
            if session.sso and time.monotonic() - session.vouched > SSO_LIVE_UNCONFIRMED:
                return "unconfirmed", False
            if holder.user_id.startswith("token:"):  # a screen on the wall, opened with its display link
                shown = next((t for t in store.tokens if t.id == holder.user_id[6:] and t.kind == "display"), None)
                if shown is None or (shown.expires is not None and shown.expires <= time.time()):
                    return "signed_out", False
                user = token_user(shown)
            else:
                user = store.user(holder.user_id)
                if user is None or user.suspended:
                    return "signed_out", False
                if user.subject and not provider_holds(session, user):  # (and its keyboard and mouse are let go of with it)
                    core.sessions.drop(holder.session)
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

    lines = live.Lines(manager, standing=live_standing, busy=lambda device_id: device_id in acted_on, audit=audit.write, may_take=live_may_take, said=core.live_said, control_said=core.control_said)
    manager.retiring = lines.retiring  # (keys a line has down on a device are let go of before its connection is closed)

    @app.post("/api/v1/devices/{device_id}/live")
    async def live_pass(
        device_id: str, request: Request,
        target: Annotated[str | None, Query(min_length=1, max_length=64)] = None,  # (as ActionIn's: the view that asks, since 0.4.0)
    ) -> Response:
        """A pass for one live line to this machine: good for half a minute, and for one use (live.py); for the connection to
        it there is now, and no other (live.Pass.device): an edit of the tile before the line is opened ends the line there."""
        if not core.vault.unlocked:
            return fail(503, "locked", "qKVM was restarted and nobody has signed in since, so it cannot reach its devices.")
        device = manager.devices.get(device_id)
        if device is None or not allowed(request, device_id):
            return fail(404, "not_found", "Unknown device")
        if refused := not_as_seen(target, device_id):
            return refused
        if not lines.offers(device):
            return fail(404, "no_live", lines.why_no_live(device))
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
            ticket = lines.issue(device_id, holder, device)
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
        if body.kind == "keys" and names_the_power_key(body.keys):
            return fail(422, "invalid", POWER_KEY_REFUSED)  # (which every run would answer, on every machine)
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
            # Tailscale's certificate for this computer's name (--tls-tailscale): which, until when, or why none. None: not asked for.
            "tailscale_certificate": core.tailscale_cert.view() if core.tailscale_cert is not None and core.https else None,
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

    # Virtual media of servers (0.3.0, A4): the folder whose ISO images can be mounted on a server, and the wall's address as
    # the servers' controllers reach it to read them (served.py).

    @app.get("/api/v1/settings/media")
    async def get_media_settings() -> dict[str, Any]:
        return {"folder": store.server.media_folder, "address": store.server.media_address, "serving_at": core.served.base(), "https": core.https}

    @app.put("/api/v1/settings/media")
    async def put_media_settings(body: MediaSettingsIn, request: Request) -> Response:
        folder, address = body.folder.strip(), body.address.strip()
        if folder and not (os.path.isabs(folder) and await asyncio.to_thread(os.path.isdir, folder)):
            return fail(422, "invalid", f"{folder} is no folder on the computer qKVM runs on: name the whole path of a folder that is there.")
        if address:
            said = address_of(address)
            if said is None:
                return fail(422, "invalid", "The address is http:// or https://, a host and a port, and nothing after them, as https://192.168.1.10:8787")
            if not host_allowed(urlsplit(said).netloc, store.server.allowed_hosts):
                # (A controller asks for the image by this name: refused as any request by a name qKVM is not told it has.)
                return fail(422, "invalid", f"qKVM answers no request made to {urlsplit(said).hostname}: add that name to allowed_hosts first (see the qKVM guide, GUIDE.md), or name the address by its number.")
            address = said
        server = store.server
        before = (server.media_folder, server.media_address)
        server.media_folder, server.media_address = folder, address

        def as_it_was() -> None:
            server.media_folder, server.media_address = before

        if refused := await saved("These settings", as_it_was):
            return refused
        audit.write("media_settings_changed", client_ip(request), folder=folder, address=address)
        return JSONResponse({"ok": True, "serving_at": core.served.base()})

    # --- backups of the whole wall to a folder (backup.py): an admin's, as every setting is ---------------------------
    # The key is made with the admin's password typed again (it opens every secret of the wall), shown once as its recovery
    # kit, and never again: no answer holds it after that one, nor does any log, export or page.

    @app.get("/api/v1/backups")
    async def get_backups() -> dict[str, Any]:
        """What is saved of the backups and how the last run went: never a look at the folder, which may not answer (a share
        whose server is gone) and would hold whoever opens Settings."""
        kept = store.backups
        running = backup_task[0]
        here = latest_here()
        return {
            "enabled": kept.enabled, "folder": kept.folder, "hour": kept.hour, "keep": kept.keep, "history": kept.history,
            "key": {"id": kept.key_id, "made": kept.key_made} if kept.secret is not None else None,
            "last": {
                "at": kept.last_at, "ok": kept.last_ok, "name": kept.last_name, "size": kept.last_size, "error": kept.last_error, "good": kept.last_good,
                "folder": kept.last_folder,  # (where the backup last made is: another folder than backups go to now, where saved since)
            } if kept.last_at else None,
            "next": next_backup(), "running": running is not None and not running.done(),
            # (This key's, in this folder: after a new key, the last one made opens with the kit before, and after a new folder
            # it is in the one before; none is made here yet.)
            "latest": {"name": kept.last_name, "size": kept.last_size} if here else None,
            "others": kept.others if backup.place_of(kept.last_folder) == backup.place_of(kept.folder) else 0,
            # Runs their hour cut off that still wait for their folders, each holding a thread until it answers (a restart frees
            # them): where and since when.
            "waiting": [{"folder": each.folder, "since": each.since} for each in runs_waiting()],
            # How long the wall gives Back up now before it answers that the run goes on, and Verify before it says the folder
            # does not answer, in seconds: the page waits for each longer than that (the outside review of 0.4.0, bugs round, M7).
            "waits": {"run": RUN_WAIT, "verify": VERIFY_WITHIN},
        }  # fmt: skip

    @app.put("/api/v1/backups")
    async def put_backups(body: BackupsIn, request: Request) -> Response:
        folder = body.folder.strip()
        if folder and not Path(folder).is_absolute():
            return fail(422, "invalid", "The folder is a whole path on the computer qKVM runs on, as /srv/qkvm-backups or D:\\qkvm-backups")
        if folder:
            # The data folder is refused by the folder's spelling at every save, which asks the disk nothing: the folder saved as
            # well (a restored wall keeps the one its backups went to on the old computer, which may be where its data folder is
            # now: the last look of wave 3). Then by where it lies (links, other names of one folder), on the look's own threads,
            # bounded; not for the folder saved before, which may be on a share whose server is gone (no save, backups switched
            # off among them, could be made until a restart: the re-review of wave 3, N2).
            inside = backup.spelled_inside(folder, core.data_dir)
            if not inside and folder != store.backups.folder:
                try:
                    inside = await core.backup_looks.run(FOLDER_WITHIN, unlock.lies_in, Path(folder) / "x", core.data_dir)
                except backup.BackupError as ex:
                    return fail(409, "busy", ex.message)  # (busy as busy: not the typed folder's doing)
                except backup.FolderTimeout:
                    return fail(504, "timeout", f"{folder} did not answer (a share whose server is gone?): nothing was saved")
                except (OSError, RuntimeError) as ex:  # (RuntimeError: a link that leads to itself, as Python before 3.13 says it)
                    # What cannot be looked at is not taken for somewhere else than the data folder: refused, and said.
                    said = ex.strerror if isinstance(ex, OSError) and ex.strerror else type(ex).__name__
                    return fail(422, "invalid", f"Where {folder} lies could not be looked at ({said}): nothing was saved")
            if inside:
                return fail(422, "invalid", "Backups in the data folder would go with it: choose a folder elsewhere (another disk, a share)")
        if not 0 <= body.hour <= 23:
            return fail(422, "invalid", "The hour is from 0 to 23")
        if not 1 <= body.keep <= 365:
            return fail(422, "invalid", "Keep from 1 to 365 backups")
        if body.enabled and not folder:
            return fail(422, "invalid", "Name the folder the backups go to")
        if body.enabled and store.backups.secret is None:
            return fail(409, "no_key", "Make the backup key first: its recovery kit is shown once, to print or to save")
        kept = store.backups
        before = dataclasses.replace(kept)
        kept.enabled, kept.folder, kept.hour, kept.keep, kept.history = body.enabled, folder, body.hour, body.keep, body.history
        if body.enabled and not before.enabled:
            kept.since = time.time()  # (the first run by the clock is the next time the hour comes)

        def as_it_was() -> None:
            store.backups = before

        if refused := await saved("The backup settings", as_it_was):
            return refused
        audit.write("backup_settings_changed", client_ip(request), enabled=body.enabled, folder=folder, hour=body.hour, keep=body.keep, history=body.history)
        return JSONResponse({"ok": True, "next": next_backup()})

    @app.post("/api/v1/backups/key")
    async def make_backup_key(body: TotpBeginIn, request: Request) -> Response:
        """A new backup key, its recovery kit in the answer: this once. Backups made before it open with the kit before."""
        if refused := not_for_a_token(request):
            return refused
        user: UserRecord = request.state.user
        checked = user.auth
        if refused := await own_password(request, body.password):
            return refused
        key, made = backup.new_key(), time.time()
        async with one_change:  # (the password checked beside every change; the turn for the change, asked again in it)
            if refused := still_allowed(request) or changed_meanwhile(user, checked):
                return refused
            if not core.vault.unlocked:
                return fail(503, "locked", "The saved passwords are locked just now. Sign in again and try once more.")
            before = dataclasses.replace(store.backups)
            kept = store.backups
            kept.secret, kept.key_id, kept.key_made = core.vault.encrypt(key.hex(), backup.SEALED_FOR), backup.key_id(key), made

            def keep_the_old_key() -> None:
                store.backups = before

            if refused := await saved("The new backup key", keep_the_old_key):
                return refused  # (and its kit is shown to nobody: the key before it is still the key)
        audit.write("backup_key_made", client_ip(request), key=backup.key_id(key), replaced=before.key_id or None)
        said = {"kit": backup.kit(key, made), "key": backup.written(key), "id": backup.key_id(key), "made": made}
        return JSONResponse(said, headers={"Cache-Control": "no-store"})

    @app.post("/api/v1/backups/run")
    async def run_backup(request: Request) -> Response:
        """Back up now: a run as the clock's, waited for a while (RUN_WAIT) and then said to be still running. The run saves
        how it went in the turn of changes itself, and goes on if this request is cut off."""
        if not store.backups.folder:
            return fail(409, "no_folder", "Name the folder the backups go to, and save, first")
        if store.backups.secret is None:
            return fail(409, "no_key", "Make the backup key first: its recovery kit is shown once, to print or to save")
        if (held := held_here()) is not None:
            # (A run holds this folder: one cut off, waiting for it; or one under way, begun before the listeners were opened anew.)
            return fail(409, "busy", RUN_STILL_WAITING if held.cut_off else "A backup is being made just now")
        task = start_backup(by_the_clock=False)
        if task is None:
            return fail(409, "busy", "A backup is being made just now")
        done, _ = await asyncio.wait({task}, timeout=RUN_WAIT)
        if not done:
            return JSONResponse({"running": True})
        if (said := task.result()).get("held"):  # (its folder held by a run before, by another name for it: not begun)
            return fail(409, "busy", said["error"])
        return JSONResponse(said)

    @app.post("/api/v1/backups/verify")
    async def verify_backup(request: Request) -> Response:
        """Verify the latest: the newest backup in the folder read whole with the key, nothing restored; what it holds."""
        kept = store.backups
        if backup_turn.locked():
            return fail(409, "busy", "A backup is being made just now")
        try:
            key = backup_key()
        except backup.BackupError as ex:
            return fail(503 if ex.code == "locked" else 409, ex.code, ex.message)
        # The last backup this wall made, by the name it saved: not a look through the folder (another key's, a name later than
        # now), and read on the folder's own threads, bounded.
        if not kept.last_name or not kept.folder or not Path(kept.folder).is_absolute():
            return fail(404, "no_backup", "There is no backup in the folder yet")
        if not backup.made_with(kept.last_name, kept.key_id):
            # (The last one made was made with the key before, which this key does not open: none of this key's yet.)
            return fail(404, "no_backup", "No backup has been made with this key yet: the last one was made with the key before, and opens with its kit")
        if not latest_here():
            # (The last one made is in the folder backups went to before this one was saved: none is made here yet.)
            return fail(404, "no_backup", f"No backup has been made in this folder yet: the last one made is in {kept.last_folder or 'another folder'}")
        newest = Path(kept.folder) / kept.last_name
        try:
            held = await core.backup_reads.run(VERIFY_WITHIN, backup.verify, newest, key)
        except backup.FolderTimeout:
            return fail(504, "timeout", f"{newest.name}: the folder did not answer within {alerts.lasted(VERIFY_WITHIN)} (a share whose server is gone?)")
        except FileNotFoundError:
            return fail(404, "no_backup", f"{newest.name}, the last backup made, is no longer in the folder")
        except backup.BackupError as ex:
            if ex.code == "busy":
                return fail(409, "busy", ex.message)
            audit.write("backup_verified", client_ip(request), file=newest.name, ok=False, said=ex.message[:300])
            return fail(422, ex.code, f"{newest.name}: {ex.message}")
        except OSError as ex:
            return fail(409, "unreadable", f"{newest.name} could not be read: {ex.strerror or ex}")
        audit.write("backup_verified", client_ip(request), file=newest.name, ok=True, devices=held.devices, accounts=held.accounts)
        return JSONResponse({"name": newest.name, **held.said()})

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
                    # (Of the first destination in the file, as 0.3.2 said of its one address; and then each of them.)
                    "enabled": told["enabled"], "address": bool(told["destinations"]), "host": (told["destinations"] or [{}])[0].get("host", ""),
                    "format": exchange.format_of((told["destinations"] or [{"kind": "webhook", "config": {"format": "auto"}}])[0]),
                    "kinds": [kind for kind in ("offline", "no_signal", "problem", "recovered") if told[kind]],
                    "destinations": [
                        {"kind": one["kind"], "name": one["name"], "host": one["host"], "private": one["private"]} for one in told["destinations"] or []
                    ],
                },
                "wall": content.wall,
                # (0.4.0, where the file has it: signing in through an identity provider, its secret by whether it is there.)
                **({} if content.signin is None else {"signin": {
                    "enabled": content.signin["enabled"], "name": content.signin["name"], "issuer": content.signin["issuer"],
                    "client_id": content.signin["client_id"], "password": bool(content.signin["client_secret"]),  # (the client secret's, by whether it is there)
                    "roles": [{"group": group, "role": role} for group, role in content.signin["roles"].items()],
                    "anyone": content.signin["anyone"], "domain": content.signin["domain"], "private": content.signin["private"],
                }}),
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
            signin = content.signin if "signin" in take else None
            used = {device.id for device in store.devices} | {action.id for action in store.actions} | {one.id for one in store.destinations}

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
                        fingerbot_strength=device.fingerbot_strength, no_signal_minutes=device.no_signal_minutes,
                        unchanged_minutes=device.unchanged_minutes, amt_view=device.amt_view, open_in=dict(device.open_in),
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
                # The file's destinations take the place of this wall's; a file without any leaves this wall's as they are.
                where = {device.url: device.id for device in [*store.devices, *added]}
                places = [exchange.destination_record(one, new_id(), where, core.vault) for one in told["destinations"] or []] if told is not None else []
                oidc_made = oidc_from_file(signin) if signin is not None else None
                # Made before anything is touched: whatever goes wrong in the making leaves the wall as it was.
                clients = [manager.client(record) for record in added]
            except VaultLocked:
                return fail(503, "locked", "The saved passwords are locked just now. Sign in again and try once more.")
            before = (dataclasses.asdict(store.alerts), store.server.interval, store.server.update_check)
            places_before = list(store.destinations)
            oidc_before = store.oidc

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
                store.destinations = places_before
                store.server.interval, store.server.update_check = before[1], before[2]
                store.oidc = oidc_before

            try:
                store.devices.extend(added)
                store.actions.extend(saved_actions)
                if told is not None:
                    # What is set about alerts, and where they go. Not the link they carry, which is this
                    # wall's own address, nor a pause, which is a thing of the moment here.
                    settings = store.alerts
                    settings.enabled = told["enabled"]
                    settings.offline, settings.no_signal, settings.problem, settings.recovered = told["offline"], told["no_signal"], told["problem"], told["recovered"]
                    if places:  # a file without any (a plain file) leaves the destinations this wall has
                        store.destinations = places
                if wall is not None:
                    store.server.interval = wall.get("interval", store.server.interval)
                    store.server.update_check = wall.get("update_check", store.server.update_check)
                if oidc_made is not None:
                    store.oidc = oidc_made
                for client in clients:
                    await manager.adopt(client)
                await save()
            except OSError as ex:
                await as_it_was()
                return not_saved("What the file holds", ex)
            except BaseException:
                await as_it_was()  # not half of a file: whatever it was that went wrong
                raise
            if before[0]["enabled"] and not store.alerts.enabled:
                alerts_switched_off()
            if places:
                for gone in places_before:
                    courier.forget(gone.id)
                    on_way.pop(gone.id, None)
                    last_told.pop(gone.id, None)
                    not_opening.pop(gone.id, None)
                    failing.discard(gone.id)
            if oidc_made is not None:
                provider.forget()
                provider_sessions()  # (taken in switched off: whoever the provider signed in here before is signed out)
        # Each device by name and address, as one that was typed in is written down; a file of hundreds, by their number.
        for record in added[:MOST_NAMED]:
            audit.write("device_added", client_ip(request), device=record.name, device_id=record.id, url=record.url, note="from a file")
        taken_in = (("devices", added), ("actions", saved_actions), ("alerts", told is not None), ("wall", wall is not None), ("signin", oidc_made is not None))
        audit.write(
            "import_done", client_ip(request), devices=len(added), actions=len(saved_actions), encrypted=content.sealed,
            parts=sorted(part for part, there in taken_in if there),
        )  # fmt: skip
        if oidc_made is not None:
            audit.write("oidc_changed", client_ip(request), enabled=False, issuer=oidc_made.issuer, client_id=oidc_made.client_id, note="from a file", **({"secret": "replaced"} if signin and signin["client_secret"] else {}))
        said = {"devices": len(added), "actions": len(saved_actions), "alerts": told is not None, "wall": wall is not None, **({"signin": True} if oidc_made is not None else {})}
        left_out = content.left_out[:200]
        if signin is not None and signin["enabled"]:
            left_out = [*left_out, "Sign-in settings: taken in switched off. Look at them under Settings > Accounts > Identity provider, at the address your team opens qKVM at, and switch them on there: the provider is asked then whether it is what they say."]
        return JSONResponse({**said, "left_out": left_out})

    def oidc_from_file(signin: dict[str, Any]) -> OidcSettings:
        """Signing in through an identity provider as a file holds it (exchange._signin), as it is taken in on this wall:
        switched off (a file never switches on a way into the wall: an admin does, in the page, where the provider is asked
        what it is first), with this wall's own redirect address, and the client secret of the file, or else the one saved
        here for that very provider and client and for no other. VaultLocked where a secret is to be sealed and cannot be."""
        here = store.oidc
        made = OidcSettings(
            enabled=False, name=signin["name"], issuer=signin["issuer"], client_id=signin["client_id"], scopes=signin["scopes"],
            groups_claim=signin["groups_claim"], roles=dict(signin["roles"]), anyone=signin["anyone"], domain=signin["domain"],
            private=signin["private"], redirect_uri=here.redirect_uri,
        )  # fmt: skip
        if signin["client_secret"]:
            made.secret = core.vault.encrypt(signin["client_secret"], oidc.SEALED_FOR)
        elif here.secret and (made.issuer, made.client_id) == (here.issuer, here.client_id):
            made.secret = here.secret
        return made

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
    async def update_check(request: Request) -> Response:
        try:
            await core.updater.check()
        except UpdateError as ex:
            # (Asked again, as after any wait: what GitHub said, or why it could not be asked, is for whoever may still
            # ask. Left open by W4's agent.)
            return still_allowed(request) or fail(502, "update_failed", str(ex))
        return still_allowed(request) or JSONResponse(update_view())

    @app.post("/api/v1/update/install")
    async def update_install(body: UpdateInstallIn, request: Request) -> Response:
        if core.container:
            # An image is replaced as a whole; unpacking program files inside one would be undone by the next start.
            return fail(409, "container", "This copy runs from a container image: update by pulling the new image")
        if refused := await own_password(request, body.password):
            return refused
        # As a task of its own that the request waits for, as removing machines is: cut off (a stop, the listeners opened
        # again), the request lets go of it, and it runs on for the time a stopping wall gives such a task (lifespan), its
        # activity entry written whichever way it ends; and no other install begins while it runs.
        work = asyncio.ensure_future(installing(request))
        background.add(work)
        work.add_done_callback(background.discard)
        try:
            return await asyncio.shield(work)
        except asyncio.CancelledError:
            work.add_done_callback(unheard("installing an update"))
            raise

    async def installing(request: Request) -> Response:
        """The installation of an update, and its activity entry (update_install)."""
        ip = client_ip(request)

        def still_theirs() -> bool:
            """Whether whoever asked may still have it installed: asked after the download, before anything is written, again
            once all of it is written and tried, before it is named, and once it is named, before qKVM is restarted into it."""
            return still_allowed(request) is None

        def brought() -> dict[str, list[str]]:
            """What the activity entry names beside the version: the libraries it brought, where it brought any."""
            return {"libraries": core.updater.brought} if core.updater.brought else {}

        try:
            version = await core.updater.install(still=still_theirs)
        except asyncio.CancelledError:
            audit.write("update_failed", ip, error="qKVM was stopped, or its listeners opened again, before it was done")
            raise
        except NoLongerAllowed as ex:
            # (As for an action whose right was lost while it was under way: refused, and written down as not done.)
            audit.write("update_failed", ip, error=str(ex))
            return fail(403, "stopped", str(ex))
        except UpdateError as ex:
            audit.write("update_failed", ip, error=str(ex))
            if not still_theirs():
                # Why it failed is for whoever may still ask (the activity log has it): to one who lost the right while it
                # was under way, it is said as above. (Left open by W4's agent.)
                return fail(403, "stopped", "It was not installed: whoever asked for it may no longer do that")
            # ("unfit": the release needs what this copy has not, and the Updates view says what and how to install it instead.)
            return fail(502, "unfit" if isinstance(ex, Unfit) else "update_failed", str(ex))
        if not still_theirs():
            # Lost the right while the package was being written (asked just before; a thread is not stopped half way): it is
            # installed, and takes effect at the next start. qKVM is not restarted for whoever may no longer ask for that, and
            # they are handed nothing of the update's state. (The Updates view says to other admins that it is installed and is
            # used from the next start, which `qkvm restart` on its computer makes now.)
            if core.supervised:
                note = "not restarted: whoever asked for it may no longer do that"
                said = f"It was installed, and takes effect the next time qKVM starts. qKVM was {note}"
            else:
                note = "whoever asked for it lost the right while it was being installed"
                said = "It was installed, and takes effect the next time qKVM starts. Whoever asked for it may not see more of it now"
            audit.write("update_installed", ip, version=version, note=note, **brought())
            return fail(403, "stopped", said)
        audit.write("update_installed", ip, version=version, **brought())
        if core.supervised:
            # Let this answer reach the browser, then leave; the starter runs the new version.
            asyncio.get_running_loop().call_later(1.0, core.restart_program)
        return JSONResponse({**update_view(), "restarting": core.supervised})

    # --- finding KVMs ---------------------------------------------------------------

    async def netbird_api() -> tuple[tailnet.NetbirdApi | None, str | None]:
        """NetBird's management API with its token opened, for a search, where an admin set it up; or why it is not asked."""
        settings = store.netbird
        if not settings.url or not settings.secret:
            return None, None
        if not core.vault.unlocked:
            return None, "NetBird's management API was not asked: the saved passwords are locked, and its token with them"
        token = core.vault.read(settings.secret, tailnet.SEALED_FOR)
        if token is None:
            return None, "NetBird's management API was not asked: its saved token does not open any more (the settings file was edited, or is damaged). Enter it again under Settings > Network"
        own = await own_addresses()
        return tailnet.NetbirdApi(settings.url, token, settings.private, own.addresses, own.ports), None

    @app.post("/api/v1/discover")
    async def find_kvms() -> Response:
        """Look on this computer's own networks for KVMs that could be added."""
        if scanning.locked():
            return fail(409, "busy", "A search is already running")
        async with scanning:
            netbird, unasked = await netbird_api()
            result = await discover.scan(netbird)
            if unasked is not None and await asyncio.to_thread(tailnet.netbird_command) is None:
                result["notes"].append(unasked)
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

    # --- NetBird's management API (tailnet.py, 0.4.0) --------------------------------------------------------------------
    # Asked for the machines of a NetBird network where NetBird's client is not on this computer (qKVM in a container beside
    # NetBird's own). An admin's: the token sealed by the vault, never handed back, sent to the address it was entered for and
    # to no other; settings that do not work are not saved.

    async def netbird_view() -> dict[str, Any]:
        settings = store.netbird
        return {
            "url": settings.url, "has_token": bool(settings.secret), "private": settings.private,  # (never the token)
            # NetBird's client is on this computer: it is asked, and these settings are not needed.
            "client": await asyncio.to_thread(tailnet.netbird_command) is not None,
        }  # fmt: skip

    @app.get("/api/v1/netbird")
    async def get_netbird() -> dict[str, Any]:
        return await netbird_view()

    @app.put("/api/v1/netbird")
    async def set_netbird(body: NetbirdIn, request: Request) -> Response:
        before = store.netbird
        try:
            url = tailnet.management_url(body.url) if body.url.strip() else ""
            given = tailnet.management_token(body.token) if body.token.strip() else ""
        except ValueError as ex:
            return fail(422, "invalid", str(ex))
        made = NetbirdSettings(url=url, private=body.private)
        found = 0
        if url:
            # A token left empty is the one saved, for the address it was entered for and no other: kept across a change of
            # address, it would be handed to a server it was never meant for at the next search.
            if not given and not (before.secret and url == before.url):
                again = " again: it is sent only to the address it was entered for" if before.secret else ""
                return fail(422, "invalid", f"Enter the token{again}")
            if not core.vault.unlocked:
                return fail(409, "locked", "Sign in again first")
            token = given or core.vault.read(before.secret, tailnet.SEALED_FOR)
            if token is None:
                return fail(422, "invalid", "The saved token does not open any more (the settings file was edited, or is damaged): enter it again")
            own = await own_addresses()
            try:
                found = len(await tailnet.netbird_by_api(tailnet.NetbirdApi(url, token, body.private, own.addresses, own.ports)))
            except tailnet.Unasked as ex:
                return fail(502, "provider_refused", f"{ex}. Nothing was saved.")
            made.secret = core.vault.encrypt(given, tailnet.SEALED_FOR) if given else before.secret
        async with one_change:
            if refused := still_allowed(request):
                return refused
            if store.netbird is not before:
                return fail(409, "changed", "These settings were changed meanwhile (in another tab, or by another admin). Nothing was saved: look again.")
            store.netbird = made

            def as_it_was() -> None:
                store.netbird = before

            if refused := await saved("NetBird's management API", as_it_was):
                return refused
        token_was = {"token": "replaced"} if given else {"token": "removed"} if before.secret and not made.secret else {}
        audit.write("netbird_changed", client_ip(request), url=url or None, private=made.private, **token_was)
        return JSONResponse({**await netbird_view(), "peers": found})

    @app.post("/api/v1/proxmox/guests")
    async def proxmox_guests(body: ProxmoxIn) -> Response:
        """The virtual machines an API token may see on a Proxmox, to pick from for adding; and, where the address
        named one by its number, that one's address as the wall keeps it (`named`, its node looked up)."""
        try:
            found = proxmox.address_of(body.url)
        except ValueError as ex:
            return not_taken(ex)
        def number_on_its_proxmox(url: str) -> tuple[str, int] | None:
            try:
                where = proxmox.address_of(url)
            except ValueError:
                return None
            return (where.origin, where.vmid) if where.vmid is not None else None

        # On the wall by its number on this Proxmox, not by its address: a tile follows its guest to another node of the
        # cluster with its address left as it was added, and a cluster numbers its guests once (register row 13 of 0.2.1).
        on_wall = {number: d for d in store.devices if d.kind == "proxmox" and (number := number_on_its_proxmox(d.url)) is not None}
        # ...and by the number its guest gave for itself (its SMBIOS UUID), where the tile keeps one: a VM made under the
        # number of a guest that was deleted is not that tile's guest, and is said to be a new VM under the tile's number.
        kept = {number: d.machine for (origin, number), d in on_wall.items() if origin == found.origin and d.machine}
        try:
            listed, containers, _ = await proxmox.guests(found.origin, body.username.strip(), body.password, typed=True, numbers_of=kept)
        except KvmError as ex:
            return fail(422, ex.code, ex.message)
        for guest in listed:
            there = on_wall.get((found.origin, guest["vmid"]))
            read, own = "own" in guest, guest.pop("own", None)  # (not read: as before, by its number; read and none: not the tile's)
            if there is not None and read and kept.get(guest["vmid"]) not in (None, own):
                guest["known_as"], guest["new_under"] = None, there.name
            else:
                guest["known_as"] = there.name if there is not None else None
        named = None
        if found.vmid is not None:
            named = next((guest["url"] for guest in listed if guest["vmid"] == found.vmid and found.node in (None, guest["node"])), None)
            if named is None:
                return fail(422, "invalid", f"The token sees no virtual machine {found.vmid} on this Proxmox")
        return JSONResponse({"guests": listed, "containers": containers, "named": named})

    # --- alerts -------------------------------------------------------------------
    # GET/PUT /api/v1/alerts and POST /api/v1/alerts/test keep the fields and the meaning they had in 0.3.2, when a wall had
    # one address: they speak of the first destination. The kinds of change told (offline, no_signal, problem, recovered)
    # are the wall's, as then: to every destination and every browser.

    def first_destination() -> DestinationRecord | None:
        return store.destinations[0] if store.destinations else None

    def new_destination_id() -> str:
        """An id for a new destination: no record of the wall has it."""
        records: list[Any] = [*store.destinations, *store.devices, *store.actions, *store.users, *store.tokens]
        used = {one.id for one in records}
        while (made := secrets.token_hex(4)) in used:
            pass
        return made

    def alerts_view() -> dict[str, Any]:
        settings, first = store.alerts, first_destination()
        sent, problem = last_told.get(first.id, (None, None)) if first is not None else (None, None)
        # (One that is saved and does not open is none to send to. Whether it opens can only be said while the saved
        # passwords are open; until then it is shown as it is saved.)
        opens = first is not None and (not core.vault.unlocked or destination_secrets(first) is not None)
        if first is not None and not opens:
            problem = DOES_NOT_OPEN
        return {
            "enabled": settings.enabled,
            "has_webhook": opens,
            "format": exchange.format_of({"kind": first.kind, "config": first.config}) if first is not None else "auto",
            "offline": settings.offline,
            "no_signal": settings.no_signal,
            "problem": settings.problem,
            "recovered": settings.recovered,
            "link": settings.link,
            "paused_until": settings.paused_until if pausing() else None,
            "last_sent": sent,
            "last_error": problem,
        }

    @app.get("/api/v1/alerts")
    async def get_alerts() -> dict[str, Any]:
        return alerts_view()

    @app.put("/api/v1/alerts")
    async def put_alerts(body: AlertsIn, request: Request) -> Response:
        settings, first = store.alerts, first_destination()
        given = body.model_fields_set
        # Everything is looked at before anything is changed: a form that is refused for one of its fields has changed
        # none of them (an address in a refused form was put to use all the same).
        link, made, elsewhere = settings.link, None, False
        speaks = first is not None and first.kind in exchange.URL_KINDS  # (an address of the first destination: what 0.3.2 had)
        form = body.format if "format" in given or not speaks or first is None else exchange.format_of({"kind": first.kind, "config": first.config})
        typed = body.webhook.strip()
        if typed or (speaks and first is not None and "format" in given and form != exchange.format_of({"kind": first.kind, "config": first.config})):
            kept = (destination_secrets(first) or {}) if speaks and first is not None else {}
            kind = "webhook" if form in ("auto", "json") else form
            if not typed and not kept:
                return fail(422, "invalid", DOES_NOT_OPEN)
            try:
                # (A token saved for the first destination goes only where it was saved for: typed again for another host.)
                where = destinations.reached(first.kind, first.config, kept) if kept and first is not None else None
                config, sealed, host = destinations.check(kind, {"url": egress.check_url(typed) if typed else "", "format": form}, kept, where)
            except ValueError as ex:
                return fail(422, "invalid", str(ex))
            made = dataclasses.replace(first) if speaks and first is not None else DestinationRecord(new_destination_id(), kind, created=time.time())
            # (The first destination typed to another receiver: it starts with nothing known, as an edit of it does.)
            elsewhere = speaks and first is not None and (not kept or destinations.receiver(first.kind, first.config, kept) != destinations.receiver(kind, config, sealed))
            made.kind, made.config, made.host = kind, config, host
            made.secret = core.vault.encrypt(json.dumps(sealed), sealed_for(made.id))
        if body.private is not None and first is not None and made is None and not body.forget_webhook:
            made = dataclasses.replace(first)
        if made is not None and body.private is not None:
            made.private = body.private
        if body.link is not None:
            try:
                link = alerts.wall_link(body.link) if body.link.strip() else ""
            except ValueError:
                return fail(422, "invalid", "The link in alerts has to be the address of this wall, starting with http:// or https://")
        before, places = dataclasses.asdict(settings), list(store.destinations)
        marked = dict(sent_elsewhere)
        if elsewhere and made is not None:
            sent_elsewhere[made.id] = courier.handed

        def as_it_was() -> None:
            for name, value in before.items():
                setattr(settings, name, value)
            store.destinations = places
            sent_elsewhere.clear()
            sent_elsewhere.update(marked)

        gone: DestinationRecord | None = None
        if made is not None and first is not None and made.id == first.id:
            store.destinations = [made, *places[1:]]
        elif made is not None:
            store.destinations = [made, *places]
        elif body.forget_webhook and first is not None:
            gone, store.destinations = first, places[1:]
        settings.link = link
        settings.enabled = body.enabled
        settings.offline, settings.no_signal = body.offline, body.no_signal
        settings.problem, settings.recovered = body.problem, body.recovered
        # (An address that was to be forgotten and was not, for one: it would go on being sent to after a restart.)
        if refused := await saved("The alert settings", as_it_was):
            return refused
        if elsewhere and made is not None:
            started_anew(made.id)
        if before["enabled"] and not settings.enabled:
            alerts_switched_off()
        for changed in (gone, made):
            if changed is not None:
                last_told.pop(changed.id, None)  # (one that still does not open is said again, at the next look)
                not_opening.pop(changed.id, None)
                failing.discard(changed.id)
        if gone is not None:
            courier.forget(gone.id)
            on_way.pop(gone.id, None)
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

    def test_alert() -> alerts.Alert:
        return alerts.Alert("test", "qKVM", "", "online", "online", "Test alert from qKVM", "If you can read this, alerts will reach you.", event="test")

    @app.post("/api/v1/alerts/test")
    async def test_first_destination() -> Response:
        first = first_destination()
        if first is None or destination_secrets(first) is None:
            return fail(409, "no_webhook", "Save an address to send alerts to first")
        done = await courier.test(first.id, test_alert())  # at once and one attempt: whoever pressed the button is waiting
        if not done.ok:
            return fail(502, "not_delivered", done.said)
        return JSONResponse(alerts_view())

    # --- the destinations, each by itself (0.4.0) -------------------------------------------------------------------
    # Every address, key, token and password stays in the vault: the page is shown the host alone, and what a destination
    # has saved by whether it has it. A webhook's signing secret is shown once, when it is made.

    def destination_view(record: DestinationRecord) -> dict[str, Any]:
        sent, problem = last_told.get(record.id, (None, None))
        opened = destination_secrets(record) if core.vault.unlocked else None
        if core.vault.unlocked and opened is None:
            problem = DOES_NOT_OPEN
        host = record.host or (urlsplit(opened.get("url", "")).hostname or "" if opened is not None else "")
        return {
            "id": record.id, "kind": record.kind, "known": record.kind in destinations.KINDS, "name": record.name, "enabled": record.enabled,
            "host": host, "config": dict(record.config), "private": record.private, "minimal": record.minimal, "events": list(record.events),
            "least": record.least, "devices": record.devices, "groups": list(record.groups), "quiet_from": record.quiet_from,
            "quiet_to": record.quiet_to, "quiet_days": list(record.quiet_days), "remind": record.remind, "created": record.created,
            "log_seal": record.log_seal,
            # What it has saved, by whether it has it: never what it is.
            "has_token": bool(opened and opened.get("token")), "signed": bool(opened and opened.get("signing")),
            "last_sent": sent, "last_error": problem, "failing": record.id in failing, "waiting": courier.waiting(record.id),
        }  # fmt: skip

    def destinations_view() -> dict[str, Any]:
        return {
            "destinations": [destination_view(record) for record in store.destinations],
            "kinds": destinations.KIND_NAMES, "events": destinations.EVENT_NAMES, "levels": list(destinations.LEVELS),
            "severity": destinations.SEVERITY, "remind": list(destinations.REMIND), "most": MOST_DESTINATIONS,
        }  # fmt: skip

    def destination_settings(body: DestinationIn, kept: dict[str, str], record: DestinationRecord | None = None) -> tuple[dict[str, Any], dict[str, str], str, dict[str, Any]]:
        """What a form says a destination is: (what is kept in clear, its secrets, its host, the rest). ValueError. A secret
        left empty is the one `record` has saved, where it is still reached where that was saved for (destinations.check)."""
        said = body.model_dump()
        where = destinations.reached(record.kind, record.config, kept) if record is not None and kept else None
        config, sealed, host = destinations.check(body.kind, said, kept, where)
        if body.kind == "webhook" and body.forget_signing:
            sealed.pop("signing", None)
        rest = destinations.settle(said)
        if rest["devices"] is not None:
            rest["devices"] = [device for device in rest["devices"] if store.device(device) is not None]  # (one gone meanwhile: left out)
        return config, sealed, host, rest

    @app.get("/api/v1/alerts/destinations")
    async def list_destinations() -> dict[str, Any]:
        return destinations_view()

    @app.post("/api/v1/alerts/destinations")
    async def add_destination(body: DestinationIn, request: Request) -> Response:
        if len(store.destinations) >= MOST_DESTINATIONS:
            return fail(409, "conflict", f"A wall has {MOST_DESTINATIONS} destinations at the most. Remove one first.")
        try:
            config, sealed, host, rest = destination_settings(body, {})
        except ValueError as ex:
            return fail(422, "invalid", str(ex))
        signing = destinations.new_signing_secret() if body.kind == "webhook" and config.get("format") == "json" and not body.forget_signing else None
        if signing is not None:
            sealed["signing"] = signing
        record = DestinationRecord(new_destination_id(), body.kind, host=host, config=config, created=time.time(), **rest)
        record.secret = core.vault.encrypt(json.dumps(sealed), sealed_for(record.id))
        store.destinations.append(record)
        if refused := await saved("The destination", lambda: store.destinations.remove(record)):
            return refused
        called = record.name or destinations.KIND_NAMES[record.kind]
        audit.write("destination_added", client_ip(request), destination=called, kind=record.kind, host=host)
        # The webhook's signing secret, this once: whoever receives the alerts checks them with it.
        return JSONResponse({"destination": destination_view(record), **({"signing_secret": signing} if signing else {})}, status_code=201)

    @app.put("/api/v1/alerts/destinations/{destination_id}")
    async def change_destination(destination_id: str, body: DestinationIn, request: Request) -> Response:
        record = destination(destination_id)
        if record is None:
            return fail(404, "not_found", "No such destination")
        if body.kind != record.kind:
            return fail(422, "invalid", "A destination keeps its kind. Add one of the other kind, and remove this one.")
        kept = destination_secrets(record)
        try:
            config, sealed, host, rest = destination_settings(body, kept or {}, record)
        except ValueError as ex:
            return fail(422, "invalid", str(ex))
        changed = dataclasses.replace(record, host=host, config=config, **rest)
        changed.secret = core.vault.encrypt(json.dumps(sealed), sealed_for(record.id))
        place = store.destinations.index(record)
        store.destinations[place] = changed
        # Another receiver (destinations.receiver): what waits for it goes to neither, from the moment it is changed.
        elsewhere = kept is None or destinations.receiver(record.kind, record.config, kept) != destinations.receiver(changed.kind, config, sealed)
        marked = dict(sent_elsewhere)
        if elsewhere:
            sent_elsewhere[record.id] = courier.handed

        def as_it_was() -> None:
            if changed in store.destinations:
                store.destinations[store.destinations.index(changed)] = record
            sent_elsewhere.clear()
            sent_elsewhere.update(marked)

        if refused := await saved("The destination", as_it_was):
            return refused
        if elsewhere:
            started_anew(record.id)
        if record.enabled and not changed.enabled:
            switched_off[record.id] = courier.handed  # (what waits for it goes no more, even switched on before its next try)
        last_told.pop(record.id, None)  # (one that does not open is said again: it was entered again, or it was not)
        not_opening.pop(record.id, None)
        audit.write("destination_changed", client_ip(request), destination=changed.name or destinations.KIND_NAMES[changed.kind], kind=changed.kind, host=host)
        return JSONResponse({"destination": destination_view(changed)})

    @app.delete("/api/v1/alerts/destinations/{destination_id}")
    async def remove_destination(destination_id: str, request: Request) -> Response:
        record = destination(destination_id)
        if record is None:
            return fail(404, "not_found", "No such destination")
        place = store.destinations.index(record)
        store.destinations.remove(record)
        if refused := await saved("Removing the destination", lambda: store.destinations.insert(place, record)):
            return refused
        courier.forget(record.id)  # (what waited for it goes with it)
        for kept in (last_told, not_opening, tested_at, quiet_held, quiet_ends, reminded, told_there, sealed_to, backup_going, on_way):
            kept.pop(record.id, None)
        failing.discard(record.id)
        backup_sending.discard(record.id)
        audit.write("destination_removed", client_ip(request), destination=record.name or destinations.KIND_NAMES.get(record.kind, record.kind), kind=record.kind)
        return JSONResponse(destinations_view())

    tested_at: dict[str, float] = {}  # destination id -> when it was last sent a test

    @app.post("/api/v1/alerts/destinations/{destination_id}/test")
    async def test_destination(destination_id: str) -> Response:
        """A test alert to one destination, at once and one attempt: whoever pressed the button is waiting. What its service
        answered is said, with every secret taken out."""
        record = destination(destination_id)
        if record is None:
            return fail(404, "not_found", "No such destination")
        wait = TEST_EVERY - (time.monotonic() - tested_at.get(record.id, -TEST_EVERY))
        if wait > 0:
            return fail(429, "rate_limited", f"A test was sent a moment ago. Try again in {math.ceil(wait)} s.", **{"Retry-After": str(math.ceil(wait))})
        tested_at[record.id] = time.monotonic()
        done = await courier.test(record.id, test_alert())
        if not done.ok:
            return fail(502, "not_delivered", done.said)
        return JSONResponse({"said": done.said, "destination": destination_view(record)})

    @app.get("/api/v1/alerts/destinations/{destination_id}/log")
    async def destination_log(destination_id: str) -> Response:
        """How each delivery to a destination went, the latest first (kept in memory since the start: MOST_LOGGED)."""
        if destination(destination_id) is None:
            return fail(404, "not_found", "No such destination")
        return JSONResponse({"deliveries": [dataclasses.asdict(each) for each in courier.log.get(destination_id, ())]})

    @app.post("/api/v1/alerts/destinations/{destination_id}/secret")
    async def new_signing_secret(destination_id: str, request: Request) -> Response:
        """A new signing secret for a webhook (the old one stops working), shown this once."""
        record = destination(destination_id)
        if record is None:
            return fail(404, "not_found", "No such destination")
        if record.kind != "webhook":
            return fail(422, "invalid", "Only a webhook is signed")
        opened = destination_secrets(record)
        if opened is None:
            return fail(409, "conflict", DOES_NOT_OPEN)
        signing = destinations.new_signing_secret()
        changed = dataclasses.replace(record, config={**record.config, "format": "json"})
        changed.secret = core.vault.encrypt(json.dumps({**opened, "signing": signing}), sealed_for(record.id))
        store.destinations[store.destinations.index(record)] = changed

        def as_it_was() -> None:
            if changed in store.destinations:
                store.destinations[store.destinations.index(changed)] = record

        if refused := await saved("The new signing secret", as_it_was):
            return refused
        audit.write("destination_changed", client_ip(request), destination=changed.name or destinations.KIND_NAMES["webhook"], kind="webhook", what="signing secret")
        return JSONResponse({"signing_secret": signing, "destination": destination_view(changed)})

    # --- alerts by Web Push: the browsers of each account (webpush.py) --------------------------------------------------
    # Any account may have the alerts told to its own browsers, of the machines it may see; an admin sees and may remove
    # everybody's. A token has no browser of its own (_OWN_ACCOUNT).

    def push_view(record: PushRecord, user: UserRecord) -> dict[str, Any]:
        sent, problem = pusher.told.get(record.id, (None, None))
        if push_target(record) is None:
            problem = "Its subscription does not open any more (the settings file was edited, or is damaged): remove it, and turn alerts on again in that browser."
        return {
            "id": record.id, "name": record.name, "service": record.service, "created": record.created,
            "account": account_named(record.user), "mine": record.user == user.id, "last_sent": sent, "last_error": problem,
        }  # fmt: skip

    def own_push(push_id: str, user: UserRecord, admins_too: bool) -> PushRecord | None:
        return next((p for p in store.pushes if p.id == push_id and (p.user == user.id or (admins_too and user.role == "admin"))), None)

    @app.get("/api/v1/push")
    async def push_state(request: Request) -> dict[str, Any]:
        """The wall's key a browser subscribes with (null until one is made), whether the wall sends alerts at all, and the
        browsers told them: the account's own, and for an admin everybody's."""
        user: UserRecord = request.state.user
        key = push_key()
        shown = [p for p in store.pushes if p.user == user.id or user.role == "admin"]
        return {"key": key.public_text if key is not None else None, "alerts": store.alerts.enabled, "browsers": [push_view(p, user) for p in shown]}

    @app.post("/api/v1/push/key")
    async def push_key_made(request: Request) -> Response:
        """Make the wall's key for Web Push where it has none (the first browser to be told the alerts asks); its public half."""
        if (key := push_key()) is not None:
            return JSONResponse({"key": key.public_text})
        if not core.vault.unlocked:
            return fail(503, "locked", "The saved passwords are locked just now. Sign in again and try once more.")
        before, pushes = store.alerts.push_key, store.pushes
        store.alerts.push_key = core.vault.encrypt(webpush.new_key(), PUSH_KEY_FOR)
        if before is not None:
            # Made anew over one that does not open: a browser that subscribed to that one hears nothing from this one.
            store.pushes = []

        def undo() -> None:
            store.alerts.push_key, store.pushes = before, pushes

        if refused := await saved("The wall's key for push", undo):
            return refused
        for record in pushes if before is not None else []:
            pusher.forget(record.id)
        audit.write("push_key_made", client_ip(request), **({"replaced": True} if before is not None else {}))
        made = push_key()
        return JSONResponse({"key": made.public_text if made is not None else None})

    @app.post("/api/v1/push")
    async def push_subscribe(body: PushIn, request: Request) -> Response:
        """This browser, told the alerts from now on: its subscription, as its push service gave it to it."""
        user: UserRecord = request.state.user
        key = push_key()
        if key is None:
            return fail(409, "conflict", "The wall has no key for push yet. Open Settings > Alerts again, and turn alerts on there.")
        if body.key and body.key != key.public_text:
            return fail(409, "changed", "The wall's key for push is another one by now. Turn alerts on again in this browser.")
        try:
            subscription = webpush.check(body.endpoint, body.keys.p256dh, body.keys.auth)
        except ValueError as ex:
            return fail(422, "invalid", str(ex))
        name = " ".join((as_a_line(body.name) or "").split())[:60] or "A browser"
        # The same browser again (turned on once more, or by another account signed in there now): the one record, for whoever
        # turned it on last, where that is its own account or an admin (whoever has a browser's address would otherwise have it
        # told their alerts). Known by its address, which is its own: opened from the vault to be compared.
        same = next((p for p in store.pushes if (t := push_target(p)) is not None and t.subscription.endpoint == subscription.endpoint), None)
        if same is not None and same.user != user.id and user.role != "admin":
            return fail(409, "conflict", "This browser is told another account's alerts. That account or an admin removes it first (Settings > Alerts).")
        if sum(p.user == user.id and p is not same for p in store.pushes) >= MOST_BROWSERS_EACH:
            return fail(409, "conflict", f"An account has {MOST_BROWSERS_EACH} browsers told the alerts at the most. Remove one first.")
        if same is None and len(store.pushes) >= MOST_BROWSERS:
            return fail(409, "conflict", f"The wall tells {MOST_BROWSERS} browsers the alerts at the most. An admin removes some first.")
        sealed = json.dumps({"endpoint": subscription.endpoint, "p256dh": webpush.b64(subscription.p256dh), "auth": webpush.b64(subscription.auth)})
        if same is not None:
            record, before = same, dataclasses.replace(same)
            record.user, record.name, record.service = user.id, name, subscription.host
            record.secret = core.vault.encrypt(sealed, f"push:{record.id}")

            def undo() -> None:
                for each in dataclasses.fields(before):
                    setattr(record, each.name, getattr(before, each.name))

        else:
            taken = {p.id for p in store.pushes}
            while (made := secrets.token_hex(4)) in taken:
                pass
            record = PushRecord(id=made, user=user.id, name=name, service=subscription.host, created=time.time())
            record.secret = core.vault.encrypt(sealed, f"push:{record.id}")
            store.pushes.append(record)

            def undo() -> None:
                store.pushes.remove(record)

        if refused := await saved("This browser's alerts", undo):
            return refused
        pusher.told.pop(record.id, None)
        audit.write("push_subscribed", client_ip(request), browser=record.name, service=record.service)
        return JSONResponse(push_view(record, user), status_code=201)

    @app.delete("/api/v1/push/{push_id}")
    async def push_remove(push_id: str, request: Request) -> Response:
        """A browser told the alerts no more: the account's own, or for an admin anybody's."""
        user: UserRecord = request.state.user
        record = own_push(push_id, user, admins_too=True)
        if record is None:
            return fail(404, "not_found", "No such browser is told the alerts")
        place = store.pushes.index(record)
        store.pushes.remove(record)
        if refused := await saved("Taking this browser off", lambda: store.pushes.insert(place, record)):
            return refused
        pusher.forget(record.id)
        audit.write("push_removed", client_ip(request), account=account_named(record.user), browser=record.name, why="removed")
        return JSONResponse({"ok": True})

    @app.post("/api/v1/push/{push_id}/test")
    async def push_test(push_id: str, request: Request) -> Response:
        """A test alert to one of the account's own browsers: at once and one attempt, for whoever pressed the button is waiting."""
        user: UserRecord = request.state.user
        record = own_push(push_id, user, admins_too=False)
        if record is None:
            return fail(404, "not_found", "No such browser of yours is told the alerts")
        target = push_target(record)
        if target is None:
            return fail(502, "not_delivered", "This browser's subscription does not open any more. Turn alerts on again in it.")
        # A request to the address the browser gave, which an account may choose: one every few seconds of each account.
        tested, now = core.push_tested, time.monotonic()
        if (wait := PUSH_TEST_EVERY - (now - tested.get(user.id, -PUSH_TEST_EVERY))) > 0:
            return fail(429, "rate_limited", f"A test was sent a moment ago. Try again in {math.ceil(wait)} s.", **{"Retry-After": str(math.ceil(wait))})
        if len(tested) >= 1000:
            tested.clear()  # (as many accounts as there may be: forgetting them all lets each one test once more)
        tested[user.id] = now
        sample = alerts.Alert("test", "qKVM", "", "online", "online", "Test alert from qKVM", "If you can read this, alerts will reach this browser.")
        try:
            await pusher.send(target, webpush.payload(sample), webpush.urgency(sample.kind))
        except webpush.NotDelivered as ex:
            pusher.told[record.id] = (pusher.told.get(record.id, (None, None))[0], str(ex))
            if not ex.gone:
                return fail(502, "not_delivered", str(ex))
            await push_gone(record.id)  # (taken off in the turn of changes, one_change, as one that is gone at an alert)
            return fail(502, "not_delivered", f"{ex}. It was taken off the list: turn alerts on again in this browser.")
        pusher.told[record.id] = (time.time(), None)
        return JSONResponse(push_view(record, user))

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
        # (Named activity.DOWNLOAD_NAMED, by which a start finds one a power cut left: activity.leftover_downloads. Its owner's
        # alone from its first moment, on Windows too: activity.Spool.)
        spool = activity.Spool(SPOOL_IN_MEMORY, core.data_dir)
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
                    # A slow receiver can outlive its session or admin role. Keep the original
                    # Content-Length so a stopped download is recognized as incomplete.
                    if still_allowed(request) is not None:
                        return
                    yield chunk

            name = f"qkvm-activity-{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}.{format}"
            media = "text/csv; charset=utf-8" if format == "csv" else "application/x-ndjson"
            said_how = {"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store", "Content-Length": str(size)}
            reply = Handed(body(), done, sent_while=lambda: still_allowed(request) is None, media_type=media, headers=said_how)
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

    # --- a check of the activity log's chain (chain.py), on the page ---------------------------------------------------
    # It reads the whole record, the text files, in a worker thread (some seconds for 50 MB): one at a time for the whole
    # wall, whoever asks; asked again while one runs, it is that one that is waited for, and how far it got is said. What it
    # found is written into the log itself (log_checked: who checked, and what the head was), and kept for the page until
    # the next. Stopped where the wall stops (check_halt): a long log does not hold the program's end.
    def check_state() -> dict[str, Any]:
        task, walk = log_check["task"], log_check["walk"]
        if task is not None and not task.done():
            return {"running": True, "began": log_check["began"], "by": log_check["by"], "entries": walk.verdict.entries if walk is not None else 0, "result": None}
        kept = log_check["kept"]
        return {"running": False, **(kept if kept is not None else {"result": None})}

    def check_done(ip: str, by: str) -> Callable[[asyncio.Future[chain.Verdict]], None]:
        def done(task: asyncio.Future[chain.Verdict]) -> None:
            if task.cancelled() or isinstance(task.exception(), CheckHalted):
                return
            failed = task.exception()
            if failed is not None:
                log.error("the activity log could not be checked", exc_info=failed)
                log_check["kept"] = {"at": time.time(), "by": by, "said": f"The activity log could not be checked: {type(failed).__name__} (the log of qKVM says more)", "result": None}
                return
            verdict = task.result()
            log_check["kept"] = {"at": time.time(), "by": by, "said": verdict.summary(), "result": verdict.as_dict(MOST_PROBLEMS_SHOWN)}
            first = verdict.problems[0] if verdict.problems else None
            found = {"broken_at": first.line, "what": first.what} if first is not None and first.line is not None else {}
            # (Lines taken in without proof are said with it: such a log is intact only where it is chained.)
            unproved = {"unproved": verdict.unchained} if verdict.unchained else {}
            audit.write(
                chain.CHECKED, ip, intact=verdict.intact, lines=verdict.entries, problems=len(verdict.problems) + verdict.more, last=verdict.last,
                head=verdict.head, **unproved, **found,
            )  # fmt: skip

        return done

    @app.post("/api/v1/audit/check")
    async def audit_check(request: Request) -> Response:
        """Check the activity log's chain (an admin's): the answer once it is done, or after CHECK_WAIT, 202 with how far it got
        (asked for again with GET until it is done)."""
        if core.audit.key is None:
            return fail(409, "no_chain", "This wall writes its activity log without the chain: its key could not be saved at the start (the log of qKVM says why). Start it again once that is put right.")
        task = log_check["task"]
        if task is None or task.done():
            walk = chain.Walk(core.audit.key)
            task = asyncio.ensure_future(asyncio.to_thread(core.audit.check, walk, check_halt))
            log_check.update(task=task, walk=walk, began=time.time(), by=request.state.user.name)
            task.add_done_callback(check_done(client_ip(request), request.state.user.name))
        try:
            async with asyncio.timeout(CHECK_WAIT):  # (never wait_for: see kvm.Listening.message)
                await asyncio.shield(task)  # (the check itself goes on where this wait ends: asked for again with GET)
        except TimeoutError:
            return JSONResponse(check_state(), status_code=202)
        except Exception:
            pass  # (said in what is kept: check_done)
        if refused := still_allowed(request):
            return refused
        return JSONResponse(check_state())

    @app.get("/api/v1/audit/check")
    async def audit_checked(request: Request) -> Response:
        """The check under way (how far it got), or the last one's result (null where none was made since the wall started)."""
        return JSONResponse(check_state())

    return app
