"""Tell someone when a KVM stops answering, loses its picture, has a problem, or comes back."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from .kvm import public_context

log = logging.getLogger("qkvm")

CHECK_EVERY = 15.0  # seconds between looks at each KVM
SETTLE = 2  # looks in a row that must agree before a change counts; rides out a single hiccup
STARTING = 120.0  # seconds after a start in which a machine is not yet believed to differ from what it was before the restart
MOST_WATCHED = 10_000  # machines whose last state is taken up from what was written down
STATES = ("online", "no_signal", "offline", "auth", "error")  # the ones worth telling apart; others are in-between
FORMATS = ("auto", "json", "ntfy", "slack", "discord")
RETRY_AFTER = (5.0, 30.0, 120.0)  # seconds to wait before a delivery that failed is tried again, and again
MAX_WAITING = 100  # alerts kept for delivery; when the service is away for long, the oldest give way
SEND_TIMEOUT = 15.0  # seconds one attempt at delivering may take, start to finish


@dataclass
class Alert:
    kind: str  # "offline" | "no_signal" | "problem" | "recovered" | "test"
    device: str
    address: str
    state: str
    previous: str
    title: str
    text: str
    link: str = ""  # where to look: the wall, opened at this device's tile


TRY_AGAIN = 60.0  # seconds before what could not be written down is tried again, where nothing has changed since


class Watcher:
    """Turns a stream of states per KVM into the changes worth an alert.

    What each was last known to be is written down (`kept_in`), and taken up again at the next start.
    Without that, the first look after a start is the first thing known, and "is not a change": a power
    cut after which qKVM comes back and a machine does not is then never told, which is the one thing an
    alert is most wanted for. For the first while after a start (STARTING) nothing that differs from what
    was written down is believed yet: a network that comes up after qKVM would make everything look gone.
    """

    def __init__(self, kept_in: Path | None = None) -> None:
        self._stable: dict[str, str] = {}
        self._pending: dict[str, tuple[str, int]] = {}
        # Device id -> what it was before it changed while alerts were paused: told when the pause is over.
        self.held: dict[str, str] = {}
        self._file = kept_in
        self._written = ""
        self._refused: str = ""
        self._failed_at: float | None = None  # when what `_refused` holds could not be written down (None: nothing is owed)
        self._from_before: set[str] = set()  # devices whose state is what was written down, and not yet seen again
        self._started = time.monotonic()
        if kept_in is not None:
            self._load(kept_in)

    def _load(self, kept_in: Path) -> None:
        try:
            with kept_in.open("rb") as fh:
                said = json.loads(fh.read(1_000_000))
        except (OSError, ValueError, RecursionError):
            return
        if not isinstance(said, dict):
            return

        def states(of: Any) -> dict[str, str]:
            pairs = list(of.items())[:MOST_WATCHED] if isinstance(of, dict) else []
            return {key: value for key, value in pairs if isinstance(key, str) and len(key) <= 64 and value in STATES}

        self._stable, self.held = states(said.get("stable")), states(said.get("held"))
        self._from_before = set(self._stable)
        self._written = self._text()

    def _text(self) -> str:
        return json.dumps({"stable": self._stable, "held": self.held}, sort_keys=True)

    def to_write(self) -> str | None:
        """What is to be written down, if it is not what was written last (taken on the event loop; see `write`)."""
        text = self._text()
        if self._file is None or text == self._written:
            return None
        if self._failed_at is not None and text == self._refused and time.monotonic() - self._failed_at < TRY_AGAIN:
            return None  # the same as could not be written a moment ago: not again every quarter of a minute
        self._refused = text
        return text

    def write(self, text: str) -> None:
        """Write down what `to_write` gave. Waits for the disk: for a worker thread."""
        if self._file is None:
            return
        try:
            being_written = self._file.with_name(self._file.name + ".new")
            with being_written.open("w", encoding="ascii") as fh:
                fh.write(text)
                fh.flush()
                os.fsync(fh.fileno())  # on the disk: after a power cut, what came back before it is not told as news
            os.replace(being_written, self._file)
            self._written, self._failed_at = text, None
        except OSError as ex:
            # Tried again at the next change, or after a while. Until then a restart knows the states of before this one.
            if self._failed_at is None:
                log.warning("what the machines were last seen as could not be written down: %s", ex.strerror or ex)
            self._failed_at = time.monotonic()

    def forget(self, device_id: str) -> None:
        self._stable.pop(device_id, None)
        self._pending.pop(device_id, None)
        self.held.pop(device_id, None)
        self._from_before.discard(device_id)

    def state(self, device_id: str) -> str | None:
        """What the KVM is taken to be at the moment; None before enough was seen of it."""
        return self._stable.get(device_id)

    def observe(self, device_id: str, state: str) -> tuple[str, str] | None:
        """Note what a KVM looks like now. Returns (previous, new) once a change has settled."""
        if state not in STATES:
            return None  # connecting, in use elsewhere: says nothing either way
        stable = self._stable.get(device_id)
        if state == stable:
            self._pending.pop(device_id, None)
            self._from_before.discard(device_id)
            return None
        if device_id in self._from_before and time.monotonic() - self._started < STARTING:
            return None  # just started: what differs from before the restart may be this computer still finding its network
        seen, count = self._pending.get(device_id, (state, 0))
        count = count + 1 if seen == state else 1
        if count < SETTLE:
            self._pending[device_id] = (state, count)
            return None
        self._from_before.discard(device_id)
        self._pending.pop(device_id, None)
        self._stable[device_id] = state
        if stable is None:
            return None  # the first thing known about it is not a change
        return stable, state


def describe(name: str, address: str, previous: str, state: str, detail: str = "", server: bool = False) -> Alert:
    """What to say about a KVM going from `previous` to `state`.

    `server`: it is a server seen through its management controller, where "no signal" means switched off.
    """
    box = "Its management controller" if server else "The KVM"
    if state == "offline":
        return Alert("offline", name, address, state, previous, f"{name} is offline", f"{box} stopped answering.")
    if state == "no_signal":
        if server:
            return Alert("no_signal", name, address, state, previous, f"{name} is powered off", "The server was switched off or shut down.")
        text = "The computer is off, asleep or no longer plugged into the KVM."
        return Alert("no_signal", name, address, state, previous, f"{name} has no video signal", text)
    if state == "auth":
        return Alert("problem", name, address, state, previous, f"{name}: login rejected", f"{box} rejects the saved login.")
    if state == "error":
        return Alert("problem", name, address, state, previous, f"{name} has a problem", detail or "See the wall for details.")
    if previous == "no_signal":
        if server:
            return Alert("recovered", name, address, state, previous, f"{name} is powered on", "The server is running again.")
        return Alert("recovered", name, address, state, previous, f"{name} has a picture again", "The video signal is back.")
    return Alert("recovered", name, address, state, previous, f"{name} is back", f"{box} answers again.")


def wanted(alert: Alert, settings: Any) -> bool:
    """Did the admin ask to hear about this kind of change?"""
    return bool(getattr(settings, alert.kind, True))


def wall_link(url: str) -> str:
    """The address of the wall as people reach it, for alerts to point at. ValueError if it is not a web address."""
    url = check_url(url).split("#", 1)[0]
    if not url.isascii():
        # It travels in a header to some services, which carries nothing else; and then no alert arrives at all.
        raise ValueError("Write the address with plain characters only (a name with others in it: in its xn-- form)")
    return url


def link_for(wall: str, device_id: str) -> str:
    """Where an alert about this device points: the wall, opened at its tile. "" where the wall's address is not known."""
    return f"{wall}#tile={device_id}" if wall else ""


def check_url(url: str) -> str:
    """A usable webhook address, or ValueError."""
    url = url.strip()
    try:
        parts = urlsplit(url)
        usable = parts.scheme in ("http", "https") and bool(parts.hostname) and len(url) <= 500
        usable = usable and httpx.URL(url).host != ""  # what the sender itself would refuse later
    except (ValueError, httpx.InvalidURL):
        usable = False
    if not usable or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in url):
        raise ValueError("Enter a web address starting with http:// or https://")
    return url


def _format_for(url: str, chosen: str) -> str:
    if chosen != "auto":
        return chosen
    host = (urlsplit(url).hostname or "").lower()
    if host.endswith(("discord.com", "discordapp.com")):
        return "discord"
    if host == "hooks.slack.com":
        return "slack"
    if "ntfy" in host:
        return "ntfy"
    return "json"


def request_for(url: str, chosen: str, alert: Alert) -> dict[str, Any]:
    """The HTTP request that delivers `alert` to the service behind `url`."""
    kind = _format_for(url, chosen)
    where = f"\n{alert.link}" if alert.link else ""
    if kind == "discord":
        return {"json": {"content": f"**{alert.title}**\n{alert.text}{where}"}}
    if kind == "slack":
        return {"json": {"text": f"*{alert.title}*\n{alert.text}{where}"}}
    if kind == "ntfy":
        tag = {"recovered": "white_check_mark", "test": "bell"}.get(alert.kind, "warning")
        priority = "default" if alert.kind in ("recovered", "test") else "high"
        # Header values travel as latin-1; a name outside it is sent without its special characters.
        title = alert.title.encode("ascii", "ignore").decode()
        headers = {"Title": title, "Tags": tag, "Priority": priority}
        if alert.link and alert.link.isascii():
            headers["Click"] = alert.link  # a tap on the notification opens the wall at that tile
        return {"content": alert.text.encode("utf-8"), "headers": headers}
    return {
        "json": {
            "app": "QKVM",
            "event": alert.kind,
            "device": alert.device,
            "address": alert.address,
            "state": alert.state,
            "previous": alert.previous,
            "title": alert.title,
            "message": alert.text,
            "link": alert.link or None,
            "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
    }


class NotDelivered(ValueError):
    """An alert did not arrive. The message is a sentence fit for showing."""

    def __init__(self, message: str, again: bool) -> None:
        super().__init__(message)
        self.again = again  # worth another try: the service was away or busy, as opposed to unwilling


class Outbox:
    """Delivers alerts to the address the admin gave: in the background, in order, and again
    after a while when the service behind the address is away for a moment.

    Watching the KVMs must not wait for somebody else's server, so the watcher only puts alerts in.
    """

    def __init__(self, address: Callable[[], tuple[str, str] | None], report: Callable[[str | None], None]) -> None:
        self._address = address  # where to post right now and in which format; None: nowhere
        self._report = report  # told how each attempt went: None, or what went wrong
        self._waiting: asyncio.Queue[Alert] = asyncio.Queue(MAX_WAITING)
        self._client: httpx.AsyncClient | None = None

    def put(self, alert: Alert) -> None:
        if self._waiting.full():
            dropped = self._waiting.get_nowait()
            log.warning("alert dropped, too many are waiting to be delivered: %s", dropped.title)
        self._waiting.put_nowait(alert)

    async def run(self) -> None:
        """Deliver what is put in, for as long as the program runs."""
        while True:
            alert = await self._waiting.get()
            try:
                await self._deliver(alert)
            except Exception:  # whatever goes wrong with one alert must not be the end of all the others
                log.exception("alert could not be sent: %s", alert.title)

    async def _deliver(self, alert: Alert) -> None:
        for pause in (*RETRY_AFTER, None):
            target = self._address()
            if target is None:
                return  # the address was taken away while this one waited
            try:
                await self.send(*target, alert)
            except NotDelivered as ex:
                self._report(str(ex))
                if pause is None or not ex.again:
                    log.warning("alert not delivered: %s (%s)", alert.title, ex)
                    return
                log.info("alert not delivered yet, trying again in %d s: %s (%s)", pause, alert.title, ex)
                await asyncio.sleep(pause)
            else:
                self._report(None)
                return

    async def send(self, url: str, chosen: str, alert: Alert) -> None:
        """One attempt at delivering one alert. Raises NotDelivered when it does not arrive."""
        try:
            tls = await public_context()
            if self._client is None:
                self._client = httpx.AsyncClient(verify=tls, timeout=httpx.Timeout(8.0, connect=4.0), follow_redirects=False)
            client = self._client
            async with asyncio.timeout(SEND_TIMEOUT):
                reply = await client.send(client.build_request("POST", url, **request_for(url, chosen, alert)), stream=True)
                # Only the status matters. Whatever else the service sends is not read, however much it is.
                await reply.aclose()
        except (httpx.HTTPError, httpx.InvalidURL, TimeoutError) as ex:
            raise NotDelivered(f"The alert address could not be reached ({type(ex).__name__})", again=True) from ex
        status = reply.status_code
        if status >= 300:
            again = status in (408, 425, 429) or status >= 500
            raise NotDelivered(f"The alert address answered with an error (HTTP {status})", again)

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
