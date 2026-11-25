"""The places an alert can go (0.4.0): what each kind takes when it is set up, what it is sent, and how its answer reads.

Kinds: mail by SMTP, Resend (mail by an HTTPS API), Slack, Microsoft Teams (a Workflows webhook, sent an Adaptive
Card), Telegram (a bot), Discord, PagerDuty (Events API v2), ntfy, and a JSON webhook signed by the Standard Webhooks
scheme. The JSON webhook keeps the fields 0.3.2 sent, which other tools read; one of 0.3.2 whose service was worked out
from its address ("auto") still is.

What a destination is told is fixed words with fixed places for a machine's name, what happened and the link: no
template engine, nothing an admin or a device can make run. Never a password, a token, a picture or the wall's own
address beyond the link the admin gave. With "minimal content" on, only the machine's name, what happened and the link.
What a service answers is shown in its own words (its status, Slack's error string, Telegram's description), on one
line, with every secret of the destination taken out (`scrub`).

Every send goes by the wall's outbound rules (egress.py): the address judged, and connected to as judged.
"""

from __future__ import annotations

import base64
import dataclasses
import email.utils
import hashlib
import hmac
import ipaddress
import json
import os
import re
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any
from urllib.parse import SplitResult, parse_qsl, unquote, urlsplit

from . import egress
from .store import ALERT_EVENTS, ALERT_LEVELS

KINDS = ("email", "resend", "slack", "teams", "telegram", "discord", "pagerduty", "ntfy", "webhook")
KIND_NAMES = {
    "email": "Email (SMTP)", "resend": "Email (Resend)", "slack": "Slack", "teams": "Microsoft Teams", "telegram": "Telegram",
    "discord": "Discord", "pagerduty": "PagerDuty", "ntfy": "ntfy", "webhook": "Webhook (JSON)",
}  # fmt: skip
# Kinds a person reads: many changes at once are one message to them. A program reading the JSON webhook, and
# PagerDuty's incidents (one per machine), are told each change by itself.
SUMMARIZED = frozenset(KINDS) - {"webhook", "pagerduty"}
# Seconds between two messages to one destination at the least: within Slack's one a second, Telegram's 20 a minute to
# a group, Discord's 30 a minute to a webhook. (Many changes in that time are one message: see SUMMARIZED.)
SPACING = {"slack": 1.0, "telegram": 3.0, "discord": 2.0, "teams": 1.0, "email": 1.0, "resend": 1.0, "ntfy": 1.0, "webhook": 0.0, "pagerduty": 0.0}

EVENTS = ALERT_EVENTS  # offline, no_signal, unchanged, auth, certificate, fault, problem, backup, recovered
EVENT_NAMES = {
    "offline": "Offline", "no_signal": "Picture lost", "unchanged": "Screen unchanged", "auth": "Login rejected",
    "certificate": "Certificate changed", "fault": "Server critical fault", "problem": "Other problem", "backup": "Backup failed",
    "recovered": "Back to normal",
}  # fmt: skip
LEVELS = ALERT_LEVELS  # info, warning, error, critical
REMIND = (0, 30, 60, 120, 240, 480, 1440)  # minutes after which what is still wrong is told again (0: never)
MOST_GROUPS = 100
# How serious each event is (said in the guide). "Back to normal" is heard by a destination that heard what it ends.
SEVERITY = {
    "offline": "critical", "fault": "critical", "certificate": "error", "auth": "error", "problem": "error", "backup": "error",
    "no_signal": "warning", "unchanged": "warning", "recovered": "info",
}  # fmt: skip
# What a state a machine was in is, as trouble: its family (one PagerDuty incident each per machine) and how serious.
# (And the wall's own trouble that is no machine's: a backup that was not made, "backup_failed", until one is made, "backup_ok".)
FAMILY = {"offline": "down", "no_signal": "down", "auth": "login", "error": "problem", "unchanged": "screen", "backup_failed": "backup"}
_STATE_LEVEL = {"offline": "critical", "no_signal": "warning", "auth": "error", "error": "error", "unchanged": "warning", "backup_failed": "error"}
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")

MOST_TO = 10  # addresses one mail goes to
MOST_SAID = 300  # characters of a service's answer that are shown
MOST_LISTED = 30  # changes listed in one message; the rest are counted
LONGEST_WAIT = 600.0  # seconds of a service's own Retry-After that are waited for at the most
HIDDEN = egress.HIDDEN

TELEGRAM = "api.telegram.org"
RESEND = "api.resend.com"
PAGERDUTY = {"us": "events.pagerduty.com", "eu": "events.eu.pagerduty.com"}
# Microsoft retired the Office 365 connectors of Teams; their addresses take nothing any more.
_RETIRED_TEAMS = re.compile(r"(^|\.)(outlook\.office\.com|outlook\.office365\.com|webhook\.office\.com)\.?$")
_TELEGRAM_TOKEN = re.compile(r"[0-9]{1,20}:[A-Za-z0-9_-]{1,100}")
_TELEGRAM_CHAT = re.compile(r"-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{3,31}")
_ROUTING_KEY = re.compile(r"[A-Za-z0-9_+-]{20,64}")
_RESEND_KEY = re.compile(r"re_[A-Za-z0-9_]{8,100}")
_NTFY_TOKEN = re.compile(r"[A-Za-z0-9_.-]{1,200}")
SIGNING = re.compile(r"whsec_[A-Za-z0-9+/]{32,172}={0,2}")  # a Standard Webhooks secret: whsec_ and base64 of 24 to 128 bytes
_ADDRESS = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)+")
_HOST = re.compile(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*\.?")


@dataclass
class Post:
    """An alert as an HTTP POST: where, what, and the headers of the service's own."""

    url: str
    body: bytes
    headers: dict[str, str]


@dataclass
class Mail:
    """An alert as a mail: the server, its login, the message, and the envelope's sender and recipients."""

    host: str
    port: int
    login: tuple[str, str] | None
    message: EmailMessage
    sender: str
    to: list[str]


@dataclass
class Outcome:
    """How a send went: arrived, worth another try (after `wait` seconds where the service said), and its words."""

    ok: bool
    again: bool
    said: str
    wait: float = 0.0
    withheld: bool = False  # not sent: what it was for was stopped while it waited (alerts.Courier's held_back)


def _field(destination: Any, name: str) -> Any:
    return destination[name] if isinstance(destination, Mapping) else getattr(destination, name)


# --- what each kind takes --------------------------------------------------------------------------------------------


def _typed(said: Mapping[str, Any], name: str, most: int = 500) -> str:
    """What was typed as `name`, every sign of it ("" for nothing): one line of text, without a control character."""
    value = said.get(name, "")
    if value is None:
        return ""
    if not isinstance(value, str) or len(value) > most or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError(f"\"{name}\" is not a line of text")
    return value


def _text(said: Mapping[str, Any], name: str, most: int = 500) -> str:
    return _typed(said, name, most).strip()


def _secret(said: Mapping[str, Any], kept: Mapping[str, str], name: str, what: str, most: int = 500) -> str:
    """A secret as typed, or the one kept where nothing was typed. ValueError where there is neither."""
    value = _text(said, name, most) or kept.get(name, "")
    if not value:
        raise ValueError(f"Enter {what}")
    return value


LEAST_PASSWORD = egress.LEAST_WHOLE  # characters of a mail password at the least, the blanks at its ends not counted


def _password(said: Mapping[str, Any], kept: Mapping[str, str]) -> str:
    """A mail login's password as it was typed, sign for sign, or the one kept where nothing was typed; ValueError where
    there is neither, and for one of fewer than LEAST_PASSWORD characters but the blanks at its ends.

    The blanks at its ends are the password's own: taken off as a host's name has them taken off, the server was sent
    another password, and refused every alert (the outside review of 0.4.0, round 6.2, M8). What a mail server
    says is shown (Send test, the delivery log, the activity log) with the password taken out (scrub), which takes out one
    of LEAST_WHOLE characters at the least: a shorter one came back whole, and could not be told apart from the server's
    own words ("250 2.0.0 OK" of "OK"), nor be taken out of them without saying which of them it is (H2). So it is
    refused, typed or saved: a saved one as it is used (server.destination_target checks what is saved so), and nothing
    goes out with it."""
    value = _typed(said, "password") or kept.get("password", "")
    if not value:
        raise ValueError("Enter the password (for Gmail: an app password)")
    if len(value.strip()) < LEAST_PASSWORD:
        raise ValueError(
            f"A mail password has {LEAST_PASSWORD} characters at the least, the blanks at its ends not counted: what the mail "
            "server says back is shown with the password taken out, and one that short could not be told apart from its words"
        )
    return value


def _mail_address(value: Any, what: str) -> str:
    """An address mail can go to or come from: "name@example.com", or "Name <name@example.com>" for a sender."""
    if not isinstance(value, str) or not value.strip() or len(value) > 320 or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError(f"{what} is not a mail address")
    name, address = email.utils.parseaddr(value.strip())
    if not _ADDRESS.fullmatch(address) or any(ch in name for ch in '<>"'):
        raise ValueError(f"{what} is not a mail address")
    return value.strip()


def _recipients(said: Mapping[str, Any]) -> list[str]:
    to = said.get("to")
    if isinstance(to, str):
        to = [part for part in re.split(r"[,;\s]+", to) if part]
    if not isinstance(to, list) or not to:
        raise ValueError("Enter the address or addresses the alerts go to")
    if len(to) > MOST_TO:
        raise ValueError(f"A mail goes to {MOST_TO} addresses at the most")
    found = [_mail_address(one, "An address to send to") for one in to]
    if any(email.utils.parseaddr(one)[0] for one in found):
        raise ValueError("Write the addresses to send to as name@example.com, each by itself")
    return list(dict.fromkeys(found))


def _url_host(url: str) -> str:
    return urlsplit(url).hostname or ""


# The secrets of a destination that are somebody's credential, and what each is called: they go only where they were saved
# for. (A webhook's signing secret is the wall's own, and the address of a chat's webhook is itself what is typed.)
CREDENTIALS = {"password": "password", "token": "token", "key": "key"}


def reached(kind: str, config: Mapping[str, Any], secrets: Mapping[str, str]) -> str:
    """Where a destination is reached, as far as a credential is concerned: the scheme, host and port of its address, its
    mail server and port, PagerDuty's region. A path or a recipient is not part of it."""
    if kind == "email":
        return f"smtp://{str(config.get('host', '')).lower()}:{config.get('port')}"
    if kind == "pagerduty":
        return PAGERDUTY.get(str(config.get("region", "us")), "")
    if kind in ("telegram", "resend"):
        return kind
    try:
        parts = urlsplit(secrets.get("url", ""))
        return f"{parts.scheme}://{(parts.hostname or '').lower()}:{parts.port or (443 if parts.scheme == 'https' else 80)}"
    except ValueError:
        return ""


def _mailbox(address: str) -> str:
    local, at, domain = address.rpartition("@")
    return f"{local}{at}{domain.lower()}" if at else address


def receiver(kind: str, config: Mapping[str, Any], secrets: Mapping[str, str]) -> str:
    """Who a destination's alerts reach, as a mark (a digest: never a secret itself): where it is reached (`reached`) and,
    wider, the whole address of a chat's or a webhook's, Telegram's chat, PagerDuty's routing key, the recipients of a mail.
    A destination edited to another receiver knows nothing of what the one before was told (server.change_destination);
    its name, the events it is told and the machines it hears of, its login, token or signing secret are none of it."""
    if kind in ("email", "resend"):
        # (The domain in small letters, and the part before the @ as it is: that is the mailbox's own, as its mail server reads
        # it, and another case of it may be another mailbox. The outside review 6.2 re-check, R8.)
        whom: Any = sorted(_mailbox(str(each)) for each in config.get("to") or [])
    elif kind == "telegram":
        whom = config.get("chat", "")
    elif kind == "pagerduty":
        whom = secrets.get("key", "")
    else:
        whom = secrets.get("url", "")
    return hashlib.sha256(json.dumps([kind, reached(kind, config, secrets), whom]).encode()).hexdigest()


def check(kind: str, said: Mapping[str, Any], kept: Mapping[str, str], before: str | None = None) -> tuple[dict[str, Any], dict[str, str], str]:
    """What a destination of this kind is, from what a form or a file says: (what is kept in clear, its secrets, the host
    the page shows). A secret left empty is the one `kept`, saved for where `before` says (reached): only where the
    destination is still reached there. A password, token or key goes only where it was saved for, as a device's password
    does; elsewhere it is typed again. ValueError with a sentence fit for showing otherwise."""
    config, secrets, host = _check(kind, said, kept)
    if before is not None and reached(kind, config, secrets) != before:
        for name, called in CREDENTIALS.items():
            typed = _typed(said, name, 500) if name in PASSWORDS else _text(said, name, 500)  # (as _check reads it: M8)
            if secrets.get(name) and not typed and secrets[name] == kept.get(name):
                again = f"type its {called} again, or forget it" if kind == "ntfy" else f"type its {called} again"
                raise ValueError(f"It is reached elsewhere now: {again}. A saved {called} goes only where it was saved for")
    return config, secrets, host


def _check(kind: str, said: Mapping[str, Any], kept: Mapping[str, str]) -> tuple[dict[str, Any], dict[str, str], str]:
    if kind in ("slack", "discord", "ntfy", "webhook", "teams"):
        typed = _text(said, "url", egress.MOST_URL)
        url = egress.check_url(typed, https_only=kind == "teams") if typed else kept.get("url", "")
        if not url:
            raise ValueError("Enter the address the service gave you")
        host = _url_host(url)
        if kind == "teams" and _RETIRED_TEAMS.search(host):
            raise ValueError(
                "That is an address of an Office 365 connector, which Microsoft retired: it takes nothing any more. In Teams, "
                "make a Workflows webhook (Workflows, \"Post to a channel when a webhook request is received\") and paste its address"
            )
        secrets = {"url": url}
        config: dict[str, Any] = {}
        if kind == "ntfy":
            token = _text(said, "token", 200) or ("" if said.get("forget_token") else kept.get("token", ""))
            if token and not _NTFY_TOKEN.fullmatch(token):
                raise ValueError("An ntfy access token is letters and digits (tk_...)")
            if token:
                secrets["token"] = token
        if kind == "webhook":
            form = said.get("format") or "json"
            if form not in ("json", "auto"):
                raise ValueError("A webhook is sent JSON")
            config["format"] = form
            if kept.get("signing"):
                secrets["signing"] = kept["signing"]
        return config, secrets, host
    if kind == "telegram":
        token = _secret(said, kept, "token", "the bot's token (from BotFather)", 200)
        chat = _text(said, "chat", 40)
        if not _TELEGRAM_TOKEN.fullmatch(token):
            raise ValueError("A bot's token is its number, a colon and letters: 123456789:AA...")
        if not _TELEGRAM_CHAT.fullmatch(chat):
            raise ValueError("A chat is its number (-100... for a group or a channel) or a channel's @name")
        return {"chat": chat}, {"token": token}, TELEGRAM
    if kind == "pagerduty":
        key = _secret(said, kept, "key", "the integration's routing key", 100)
        region = said.get("region") or "us"
        if not _ROUTING_KEY.fullmatch(key):
            raise ValueError("A routing key (Events API v2) is the 32 letters and digits PagerDuty shows for the integration")
        if region not in PAGERDUTY:
            raise ValueError("PagerDuty's service region is us or eu")
        return {"region": region}, {"key": key}, PAGERDUTY[region]
    if kind == "resend":
        key = _secret(said, kept, "key", "the API key (re_...)", 200)
        if not _RESEND_KEY.fullmatch(key):
            raise ValueError("A Resend API key starts with re_")
        return {"sender": _mail_address(said.get("sender"), "The sender"), "to": _recipients(said)}, {"key": key}, RESEND
    if kind == "email":
        host = _text(said, "host", 253).lower()
        if egress.zoned(host):
            raise ValueError(egress.ZONE_TYPED)  # (the second outside review of 0.4.0, M1)
        try:
            ipaddress.ip_address(host)
            literal = True
        except ValueError:
            literal = False
        host = egress.plain_host(host)  # (ValueError with its own sentence: the review of 0.4.0's first wave, L3)
        if not (literal or _HOST.fullmatch(host)):
            raise ValueError("Enter the mail server's name, as smtp.example.com")
        port = said.get("port")
        if port not in egress.MAIL_PORTS or isinstance(port, bool):
            raise ValueError("A mail server is reached on port 587 (STARTTLS) or 465 (TLS)")
        user = _text(said, "user", 200)
        secrets = {"password": _password(said, kept)} if user else {}
        config = {"host": host, "port": port, "user": user, "sender": _mail_address(said.get("sender"), "The sender"), "to": _recipients(said)}
        return config, secrets, host
    raise ValueError("That is no kind of destination this version knows")


def _flag(said: Mapping[str, Any], name: str, default: bool) -> bool:
    value = said.get(name)
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ValueError(f"\"{name}\" is true or false")
    return value


def _minute(said: Mapping[str, Any], name: str) -> int:
    value = said.get(name)
    if value is None:
        return -1
    if isinstance(value, bool) or not isinstance(value, int) or not -1 <= value <= 24 * 60:
        raise ValueError("Quiet hours are minutes of the day, from 0 to 1440")
    return value


def settle(said: Mapping[str, Any]) -> dict[str, Any]:
    """The rest of a destination as a form or a file gives it, made what is kept: its name; whether it is on, may be a
    private address, is told the least; which events from which severity; which machines; its quiet hours; reminders.
    An event a later version knows and this one does not is left out. ValueError with a sentence fit for showing."""
    events = said.get("events")
    if events is None:
        events = list(EVENTS)
    if not isinstance(events, list) or not all(isinstance(each, str) for each in events):
        raise ValueError("The events are a list of their names")
    least = said.get("least") or "info"
    if least not in LEVELS:
        raise ValueError("The least severity is info, warning, error or critical")
    devices = said.get("devices")
    if devices is not None and (not isinstance(devices, list) or len(devices) > 10_000 or not all(isinstance(each, str) and 0 < len(each) <= 300 for each in devices)):
        raise ValueError("The machines are a list of them")
    groups = said.get("groups") or []
    if not isinstance(groups, list) or len(groups) > MOST_GROUPS or not all(isinstance(each, str) and len(each) <= 80 and each.isprintable() for each in groups):
        raise ValueError("The groups are a list of their names")
    start, end = _minute(said, "quiet_from"), _minute(said, "quiet_to")
    if (start < 0) != (end < 0) or (start >= 0 and (start == end or start >= 24 * 60)):
        raise ValueError("Quiet hours need a start and an end, and are not the same minute")
    days = said.get("quiet_days") or []
    if not isinstance(days, list) or not all(day in DAYS for day in days):
        raise ValueError("Quiet days are mon, tue, wed, thu, fri, sat, sun")
    remind = said.get("remind") or 0
    if remind not in REMIND or isinstance(remind, bool):
        raise ValueError(f"A reminder comes after {', '.join(str(each) for each in REMIND[1:])} minutes, or never (0)")
    return {
        "name": _text(said, "name", 80),
        "enabled": _flag(said, "enabled", True),
        "private": _flag(said, "private", False),
        "minimal": _flag(said, "minimal", False),
        "events": [event for event in EVENTS if event in events],
        "least": least,
        "devices": None if devices is None else list(dict.fromkeys(devices)),
        "groups": list(dict.fromkeys(group.strip() for group in groups if group.strip())),
        "quiet_from": start,
        "quiet_to": end,
        "quiet_days": [day for day in DAYS if day in days],
        "remind": remind,
        "log_seal": _flag(said, "log_seal", False),
    }


def new_signing_secret() -> str:
    """A webhook's signing secret, as Standard Webhooks writes one: whsec_ and 32 random bytes in base64."""
    return "whsec_" + base64.b64encode(os.urandom(32)).decode("ascii")


def sign(secret: str, message_id: str, timestamp: int, body: bytes) -> str:
    """The webhook-signature header of Standard Webhooks: v1, and HMAC-SHA256 over "id.timestamp.body" with the secret."""
    key = base64.b64decode(secret.removeprefix("whsec_"))
    mac = hmac.new(key, f"{message_id}.{timestamp}.".encode() + body, hashlib.sha256).digest()
    return "v1," + base64.b64encode(mac).decode("ascii")


# --- routing ---------------------------------------------------------------------------------------------------------


def _rank(level: str) -> int:
    return LEVELS.index(level) if level in LEVELS else 0


def passes(destination: Any, alert: Any) -> bool:
    """Whether a destination asked to hear this: its event, from the severity it asked for. "Back to normal" is heard where
    the trouble it ends would be: an incident a destination was told of is closed there."""
    if alert.event == "test":
        return True
    events, least = _field(destination, "events"), _rank(_field(destination, "least"))
    if alert.event not in events:
        return False
    if alert.event == "recovered":
        return _rank(_STATE_LEVEL.get(alert.previous, "info")) >= least
    return _rank(SEVERITY.get(alert.event, "info")) >= least


TROUBLE = ("offline", "no_signal", "auth", "error")  # the states of a machine that are trouble


def fitted(destination: Any, alert: Any, known: str | None, again: Callable[[str], Any] | None = None) -> Any:
    """The alert as this destination is to be told it, or None where it is not, by what it was told of the machine before.
    `known`: the trouble last told there ("" where the machine's trouble was not told there; None where nothing is known,
    as before 0.4.0 knew it). `again(previous)`: the change described anew from another state than the last.

    "Back to normal" goes exactly where the trouble was told (judged by the last state alone, a power cut's "offline, no
    picture, back" ended as a warning, and an incident opened for "offline" stayed open), as the end of what was told there.
    A machine told as offline that answers again without a picture is no news there (it had none to lose); where it was
    not told as offline, its picture lost is. (The review of 0.4.0's first wave, M1.)"""
    if alert.event == "test":
        return alert
    if alert.event == "recovered":
        if known is None:
            return alert if passes(destination, alert) else None
        if not known or "recovered" not in _field(destination, "events"):
            return None
        return _told_from(alert, known, again)
    if known and known == alert.state:
        return None  # (what it was told is so again)
    if (alert.previous, alert.state) == ("offline", "no_signal") and known == "offline":
        return None
    if not passes(destination, alert):
        return None
    if known == "" and alert.previous in TROUBLE:
        # Nothing of this machine's trouble was told there: what it is told is the trouble from a machine that was fine
        # (PagerDuty took "offline, then no picture" for the same trouble, and opened nothing: the second review, L6).
        return _told_from(alert, "online", again)
    return _told_from(alert, known, again) if known else alert


def _told_from(alert: Any, previous: str, again: Callable[[str], Any] | None) -> Any:
    if previous == alert.previous:
        return alert
    if again is not None:
        return again(previous)
    return dataclasses.replace(alert, previous=previous)


def noted(known: str | None, alert: Any, told: bool) -> str | None:
    """What a destination knows of a machine after this change: the trouble told there, "" where its trouble was not told
    there, None where it has nothing to know (its trouble is over)."""
    if alert.event == "recovered":
        return None
    if alert.state in TROUBLE:
        return alert.state if told else (known or "")
    return known


def covers(destination: Any, device_id: str, group: str) -> bool:
    """Whether a destination is told about this machine: all of them, or those chosen, and those of the groups chosen
    whichever are in them on the day (as an account is limited to some)."""
    devices = _field(destination, "devices")
    if devices is None or device_id in devices:
        return True
    groups = {each.casefold() for each in _field(destination, "groups")}
    return bool(group) and group.casefold() in groups


def quiet(destination: Any, now: time.struct_time) -> bool:
    """Whether a destination's quiet hours are on at this moment (the wall's local time). From and to are minutes of the
    day; a window past midnight belongs to the day it starts on. No days chosen: every day."""
    start, end = _field(destination, "quiet_from"), _field(destination, "quiet_to")
    if not (isinstance(start, int) and isinstance(end, int)) or start < 0 or end < 0 or start == end:
        return False
    days = {DAYS.index(day) for day in _field(destination, "quiet_days") if day in DAYS} or set(range(7))
    minute, today = now.tm_hour * 60 + now.tm_min, now.tm_wday
    if start < end:
        return start <= minute < end and today in days
    return (minute >= start and today in days) or (minute < end and (today - 1) % 7 in days)


# --- what each kind is sent ------------------------------------------------------------------------------------------


def _words(alert: Any, minimal: bool) -> tuple[str, str]:
    """An alert's title and text, as told: the text left out where only the least is to be told."""
    return alert.title, "" if minimal else alert.text


def _link(alert: Any, link: str) -> str:
    return str(alert.link or link)


def _inert(text: str) -> str:
    """Words a device or a name brought, where Markdown is read: no link of somebody else's can be made of them."""
    return text.replace("](", "] (")


def _slack(text: str) -> str:
    """Text as Slack reads it: <, > and & would make a mention (<!channel>) or a link of it."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _summary(alerts: list[Any], minimal: bool) -> tuple[str, str]:
    lines = [f"- {alert.title}" for alert in alerts[:MOST_LISTED]]
    if len(alerts) > MOST_LISTED:
        lines.append(f"and {len(alerts) - MOST_LISTED} more")
    return f"{len(alerts)} changes on the wall", "\n".join(lines)


def _json(said: Any) -> bytes:
    return json.dumps(said, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _post(url: str, said: Any, **headers: str) -> Post:
    return Post(url, _json(said), {"Content-Type": "application/json", **headers})


def guess(url: str) -> str:
    """The service a 0.3.2 address was worked out to be ("auto"): Discord's, Slack's, an ntfy's, or JSON for anything else."""
    host = _url_host(url).lower()
    if host.endswith(("discord.com", "discordapp.com")):
        return "discord"
    if host == "hooks.slack.com":
        return "slack"
    if "ntfy" in host:
        return "ntfy"
    return "webhook"


def _worst(alerts: list[Any]) -> str:
    return max((SEVERITY.get(alert.event, "info") for alert in alerts), key=_rank, default="info")


def _one_message(kind: str, config: Mapping[str, Any], secrets: Mapping[str, str], title: str, text: str, link: str, problem: bool, level: str) -> Post | Mail:
    """One message to a destination a person reads."""
    url = secrets.get("url", "")
    where = f"\n{link}" if link else ""
    said = f"{text}{where}".strip("\n")
    if kind == "slack":
        return _post(url, {"text": f"*{_slack(title)}*\n{_slack(text)}{where}".replace("\n\n", "\n").rstrip("\n")})
    if kind == "discord":
        content = f"**{_inert(title)}**\n{_inert(text)}{where}".replace("\n\n", "\n")[:2000]
        return _post(url, {"content": content, "allowed_mentions": {"parse": []}})
    if kind == "telegram":
        body = f"{title}\n{said}" if said else title
        sent = {"chat_id": config.get("chat", ""), "text": body[:4096], "link_preview_options": {"is_disabled": True}}
        return _post(f"https://{TELEGRAM}/bot{secrets.get('token', '')}/sendMessage", sent)
    if kind == "teams":
        color = "Good" if not problem else "Attention" if _rank(level) >= _rank("error") else "Warning"
        card: dict[str, Any] = {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
            "body": [{"type": "TextBlock", "text": _inert(title), "weight": "Bolder", "size": "Medium", "wrap": True, "color": color}],
        }  # fmt: skip
        if text:
            card["body"].append({"type": "TextBlock", "text": _inert(text), "wrap": True})
        if link:
            card["actions"] = [{"type": "Action.OpenUrl", "title": "Open the wall", "url": link}]
        return _post(url, {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]})
    if kind == "ntfy":
        # Header values travel as Latin-1; a name outside it is sent without its special characters.
        headers = {"Title": title.encode("ascii", "ignore").decode(), "Tags": "warning" if problem else "white_check_mark", "Priority": "high" if problem else "default"}
        if link and link.isascii():
            headers["Click"] = link  # a tap on the notification opens the wall at that tile
        if secrets.get("token"):
            headers["Authorization"] = f"Bearer {secrets['token']}"
        return Post(url, (text or title).encode("utf-8"), headers)
    if kind == "resend":
        sent = {"from": config.get("sender", ""), "to": list(config.get("to", [])), "subject": title[:200], "text": said or title}
        return _post(f"https://{RESEND}/emails", sent, Authorization=f"Bearer {secrets.get('key', '')}")
    if kind == "email":
        sender = str(config.get("sender", ""))
        message = EmailMessage()
        # (Headers by the email package's own rules: a line break in a name is refused there, and cannot add a header.)
        message["Subject"] = " ".join(title.split())[:200]
        message["From"] = sender
        message["To"] = ", ".join(config.get("to", []))
        message["Date"] = email.utils.formatdate(localtime=False)
        domain = email.utils.parseaddr(sender)[1].rpartition("@")[2] or "qkvm.invalid"
        message["Message-ID"] = email.utils.make_msgid("qkvm", domain=domain)  # (not this computer's name, which make_msgid would take)
        message["Auto-Submitted"] = "auto-generated"  # (RFC 3834: no out-of-office answers to it)
        message.set_content(said or title)
        user = str(config.get("user", ""))
        login = (user, secrets.get("password", "")) if user else None
        return Mail(str(config.get("host", "")), int(config.get("port", 587)), login, message, email.utils.parseaddr(sender)[1], list(config.get("to", [])))
    raise ValueError(f"no message of kind {kind}")


def _webhook(alert: Any, secrets: Mapping[str, str], link: str, minimal: bool) -> Post:
    """One alert to the JSON webhook: the fields of 0.3.2, an id, its severity, and the Standard Webhooks signature where
    there is a secret to sign with."""
    title, text = _words(alert, minimal)
    message_id = "msg_" + base64.b32encode(os.urandom(15)).decode("ascii").lower()
    said = {
        "app": "QKVM",
        "event": alert.kind,
        "device": alert.device,
        "address": "" if minimal else alert.address,
        "state": alert.state,
        "previous": alert.previous,
        "title": title,
        "message": text,
        "link": link or None,
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "id": message_id,
        "what": alert.event,
        "severity": SEVERITY.get(alert.event, "info"),
    }
    post = _post(secrets.get("url", ""), said)
    if secrets.get("signing"):
        stamp = int(time.time())
        post.headers.update({"webhook-id": message_id, "webhook-timestamp": str(stamp), "webhook-signature": sign(secrets["signing"], message_id, stamp, post.body)})
    return post


def _incident(alert: Any, family: str) -> str:
    """The key of a PagerDuty incident: one per machine and kind of trouble; the wall's own (a backup not made) by its kind alone."""
    return f"qkvm/{alert.device_id}/{family}" if alert.device_id else f"qkvm/{family}"


def _pagerduty(alert: Any, config: Mapping[str, Any], secrets: Mapping[str, str], link: str, minimal: bool) -> list[Post]:
    """PagerDuty's events for one change: the incident of the trouble that is over resolved, the one of the trouble that
    begins opened. One incident per machine and kind of trouble (FAMILY), by a key that stays the same."""
    url = f"https://{PAGERDUTY.get(str(config.get('region', 'us')), PAGERDUTY['us'])}/v2/enqueue"
    key = secrets.get("key", "")
    before, now = FAMILY.get(alert.previous), FAMILY.get(alert.state)
    sent: list[Post] = []
    if alert.event == "test":
        title, text = _words(alert, minimal)
        payload = {"summary": title[:1024], "source": "qKVM", "severity": "info", "custom_details": {"text": text}}
        return [_post(url, {"routing_key": key, "event_action": "trigger", "dedup_key": "qkvm/test", "payload": payload})]
    if before is not None and before != now:
        sent.append(_post(url, {"routing_key": key, "event_action": "resolve", "dedup_key": _incident(alert, before)}))
    # (Within one kind of trouble: a machine that answers again without a picture is no news; one that stops answering
    # altogether is the same incident, said again as the worse it is.)
    if now is not None and (now != before or alert.state == "offline"):
        title, text = _words(alert, minimal)
        details = {"text": text, "state": alert.state, "previous": alert.previous}
        if not minimal:
            details["address"] = alert.address
        payload = {
            "summary": title[:1024], "source": alert.device[:255] or "qKVM", "severity": SEVERITY.get(alert.event, "warning"),
            "component": alert.device[:255], "group": "qKVM", "class": alert.event, "custom_details": details,
        }  # fmt: skip
        event: dict[str, Any] = {"routing_key": key, "event_action": "trigger", "dedup_key": _incident(alert, now), "payload": payload, "client": "qKVM"}
        if link:
            event["links"] = [{"href": link, "text": "Open the wall"}]
            event["client_url"] = link
        sent.append(_post(url, event))
    return sent


# What is told as no trouble (ntfy's default priority, Teams' "Good"): a machine back, a test, the activity log's daily seal.
NO_PROBLEM = ("recovered", "test", "log_seal")


def outgoing(kind: str, config: Mapping[str, Any], secrets: Mapping[str, str], alerts: list[Any], *, link: str, minimal: bool) -> list[Post | Mail]:
    """What goes to a destination for these alerts: for a kind a person reads, one message (a summary where there are
    several); for the JSON webhook and PagerDuty, each by itself. `link`: the wall's address (an alert's own link, to its
    tile, where it has one)."""
    if kind == "webhook" and config.get("format") == "auto":
        kind = guess(secrets.get("url", ""))
        if kind == "webhook":
            return [_webhook(alert, {"url": secrets.get("url", "")}, _link(alert, link), minimal) for alert in alerts]
    if kind == "webhook":
        return [_webhook(alert, secrets, _link(alert, link), minimal) for alert in alerts]
    if kind == "pagerduty":
        return [post for alert in alerts for post in _pagerduty(alert, config, secrets, _link(alert, link), minimal)]
    if not alerts:
        return []
    if len(alerts) == 1:
        title, text = _words(alerts[0], minimal)
        problem = alerts[0].kind not in NO_PROBLEM
        return [_one_message(kind, config, secrets, title, text, _link(alerts[0], link), problem, SEVERITY.get(alerts[0].event, "info"))]
    title, text = _summary(alerts, minimal)
    problem = any(alert.kind not in NO_PROBLEM for alert in alerts)
    return [_one_message(kind, config, secrets, title, text, link, problem, _worst(alerts))]


# --- how an answer reads ---------------------------------------------------------------------------------------------


PASSWORDS = frozenset({"password"})  # the secrets of a destination that are a person's password (a mail login's)
_WORD = re.compile(r"[a-z]+")  # what of an address is a word of its own: small letters alone between its slashes


def _between_slashes(parts: SplitResult) -> set[str]:
    """What stands between an address's slashes: each part of its path, and of each value of its query, as it is written and
    unquoted."""
    values = [parts.path, unquote(parts.path), *(value for _, value in parse_qsl(parts.query))]
    return {piece for value in values for piece in value.split("/") if piece}


def _pieces(secrets: Mapping[str, str]) -> list[str]:
    """Everything of a destination's secrets that could show up in what a service says: each whole, and of an address,
    its path, query, login and each longer part of them, and the Basic header a login in it is sent as. A person's
    password (a mail login's), as typed and without the blanks at its ends, as egress.Password, which egress.hidden takes
    out whole only; and so a word of an address's
    own (egress.Word: what stands between its slashes in small letters alone, "services", "manual"), which a service's
    own words may hold. Anything else is a machine's, whatever its letters: an ntfy topic or a webhook's id with a dash in
    it, a key of small letters, glued to a letter or cut, showed while every secret of small letters alone was taken for a
    word (the narrow look at 0.4.0, L7); and a password in an address too: a key carried that way (Basic sign-in to an
    API) said back cut came back in part while it was taken for a person's (the final look at 0.4.0, L5)."""
    found: set[str] = set()
    persons: set[str] = set()
    words: set[str] = set()
    shown: set[str] = set()  # the host of an address, which the page shows anyway: what a service says of it stays readable
    for name, value in secrets.items():
        if not value:
            continue
        if name in PASSWORDS:
            persons.update(piece for piece in (value, value.strip()) if piece)  # (said back without the blanks at its ends: M8)
            continue
        found.add(value)
        if "://" in value:
            try:
                parts = urlsplit(value)
            except ValueError:
                continue
            shown.add(parts.hostname or "")
            words.update(piece for piece in _between_slashes(parts) if _WORD.fullmatch(piece))
            found.update(piece for piece in {parts.password or "", unquote(parts.password or "")} if piece)
            found.update(piece for piece in (parts.path, parts.query, parts.username or "") if len(piece) >= 4)
            found.update(piece for piece in parts.path.split("/") if len(piece) >= 6)
            found.update(piece for _, piece in parse_qsl(parts.query) if len(piece) >= 6)
            if (login := egress.basic(value)) is not None:
                found.update((login, login.removeprefix("Basic ")))
        found.update(unquote(piece) for piece in list(found))
        found.update(piece for piece in re.split(r"[:/]", value) if len(piece) >= 8)
    machines = [egress.Word(piece) if piece in words else piece for piece in found if piece not in persons]
    every = [egress.Password(piece) for piece in persons] + machines
    return sorted((piece for piece in every if len(piece) >= 4 and piece.lower() not in shown), key=len, reverse=True)


def _parts(secrets: Mapping[str, str]) -> list[str]:
    """What of a destination's secrets is taken out wherever a part of it stands (egress.hidden): each secret that is no
    address and no person's password, all of it; of an address, its name to sign in with, its password and the Basic
    header that is sent of its login, all of them, what stands between its slashes but its words (small letters alone),
    all of it, and of its path and its query each run of egress.PART characters that has a digit or a capital letter in
    it, as a token's have. ("services", "webhooks" or "manual" in an address go only where they stand whole, by _pieces
    and egress.hidden: a word of a service's own that holds the same letters, or two words that do between them, stays
    readable: "manually", "webhook settings"; the final look at 0.4.0, L3. An ntfy topic or a webhook's id of small
    letters with a dash in it goes in part, as a token does: the narrow look at 0.4.0, L7.) A person's password, a mail
    login's, is never among them: it goes whole only, so that a service's own words stay (the last look at the fixes of
    0.4.0, L1)."""
    found: list[str] = []
    for name, value in secrets.items():
        if not value or name in PASSWORDS:
            continue
        if "://" not in value:
            found.append(value)
            continue
        try:
            parts = urlsplit(value)
        except ValueError:
            continue
        login = egress.basic(value)
        found += [piece for piece in {parts.username or "", unquote(parts.username or "")} if piece]
        found += [piece for piece in {parts.password or "", unquote(parts.password or "")} if piece]  # (a machine's: L5)
        found += [login.removeprefix("Basic ")] if login else []
        found += [piece for piece in _between_slashes(parts) if not _WORD.fullmatch(piece)]  # (L7)
        for piece in {parts.path, parts.query, unquote(parts.path), unquote(parts.query)}:
            runs = (piece[at : at + egress.PART] for at in range(len(piece) - egress.PART + 1))
            found += [run for run in runs if any(ch.isdigit() or ch.isupper() for ch in run)]
    return found


MOST_SCRUBBED = 1_000_000  # characters of what a service said that are looked through (an answer is read 8 KiB at the most)


def scrub(text: str, secrets: Mapping[str, str]) -> str:
    """`text` with every secret of a destination taken out, whole or in part, as one printable line of MOST_SAID
    characters at the most. The secrets go first, out of the text as it came: cut first, a token across the cut showed its
    start, and with the blanks closed up first a password with two of them was not found (the review of 0.4.0's first
    wave, L4). A part of a machine's secret goes as well, wherever it stands (egress.hidden): a service that repeats only the
    start of a token, or a bound that cuts it, showed that start (the outside review of 0.4.0, L1); a person's password (a
    mail login's) goes whole only, in any spelling, where it stands whole, so that the service's own words stay (the last
    look at its fixes, L1; the final look, L4). A host is shown as it is, the page shows it anyway: a receiver that carries
    its token in its host name shows it there."""
    pieces, parts = _pieces(secrets), _parts(secrets)
    text = egress.hidden(text[:MOST_SCRUBBED], pieces, ())  # (whole, in all of it; parts in what can be shown, below)
    text = egress.hidden(text[: MOST_SAID * 8], pieces, parts)
    line = " ".join("".join(ch if ch.isprintable() else " " for ch in text).split())
    return egress.hidden(line, pieces, parts)[:MOST_SAID]  # (and once more, where closing up the blanks made one of them whole)


def _wait(reply: egress.Reply, said: Any) -> float:
    """How long the service asked to be left alone: Retry-After (seconds, or a date), or what its JSON says (Discord's
    retry_after, Telegram's parameters.retry_after); LONGEST_WAIT at the most."""
    given = reply.headers.get("retry-after", "").strip()
    seconds = 0.0
    try:
        seconds = float(given) if given else 0.0
    except ValueError:
        try:
            seconds = email.utils.parsedate_to_datetime(given).timestamp() - time.time()
        except (TypeError, ValueError, IndexError, OverflowError):
            seconds = 0.0
    if not seconds and isinstance(said, dict):
        inner = said.get("parameters")
        for value in (said.get("retry_after"), inner.get("retry_after") if isinstance(inner, dict) else None):
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                seconds = float(value)
                break
    return max(0.0, min(seconds, LONGEST_WAIT)) if seconds == seconds else 0.0


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        yield from (each for each in value[:5] if isinstance(each, str))


def _reason(said: Any, raw: bytes) -> str:
    """A service's own words for how it went: the field its JSON keeps them in, or the text it sent."""
    if isinstance(said, dict):
        words = [
            text for name in ("description", "message", "error", "error_description")
            for text in _strings(said.get(name) if not isinstance(said.get(name), dict) else said[name].get("message"))
        ]  # fmt: skip
        extra = list(_strings(said.get("errors")))
        if words or extra:
            return (words[0] if words else "") + (f" ({'; '.join(extra)})" if extra and words else "; ".join(extra) if extra else "")
    return raw.decode("utf-8", "replace")


def outcome(kind: str, reply: egress.Reply, secrets: Mapping[str, str]) -> Outcome:
    """How a service's answer reads: arrived, worth another try (429, 5xx, 408; never another 4xx), and in its words."""
    try:
        said = json.loads(reply.body) if reply.body[:1] in (b"{", b"[") else None
    except (ValueError, RecursionError):
        said = None
    words = scrub(_reason(said, reply.body), secrets)
    status = reply.status
    head = scrub(f"HTTP {status}" + (f" {reply.reason}" if reply.reason and not words else ""), secrets)
    if 200 <= status < 300:
        return Outcome(True, False, head)
    if 300 <= status < 400:
        return Outcome(False, False, f"HTTP {status}: the service answered with a redirect, which is not followed")
    again = status in (408, 429) or status >= 500
    return Outcome(False, again, scrub(f"{head}: {words}" if words else head, secrets), _wait(reply, said) if again else 0.0)
