"""Tell someone when a KVM stops answering, loses its picture, has a problem, or comes back."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from . import destinations, egress
from ._folders import private

log = logging.getLogger("qkvm")

CHECK_EVERY = 15.0  # seconds between looks at each KVM
SETTLE = 2  # looks in a row that must agree before a change counts; rides out a single hiccup
STARTING = 120.0  # seconds after a start in which a machine is not yet believed to differ from what it was before the restart
MOST_WATCHED = 10_000  # machines whose last state is taken up from what was written down
MOST_DESTINATIONS = 50  # destinations whose knowledge of the machines is taken up from what was written down
MOST_ID = 64  # characters of a machine's or a destination's id taken up from it
STATES = ("online", "no_signal", "offline", "auth", "error")  # the ones worth telling apart; others are in-between
# Bytes of what was written down that are read back, and so the most that is written: the longest the limits above make, as
# Watcher._text writes it (an entry is an id of MOST_ID and the longest state with the signs between: `"...": "no_signal", `),
# for the states, what was held, and each destination's book: some 42 MB. (A megabyte was read once, whatever was written:
# a wall of 1100 machines and fifty destinations started with nothing known. The outside review of 0.4.0, bugs round 2, M7.)
MOST_BOOK = (2 + MOST_DESTINATIONS) * MOST_WATCHED * (MOST_ID + 17) + MOST_DESTINATIONS * (MOST_ID + 8) + 64
# How the service behind an address wanted to be spoken to in 0.3.2 ("format" of GET/PUT /api/v1/alerts, which speak of
# the first destination): "auto" worked it out from the address; "json" is the JSON webhook.
FORMATS = ("auto", "json", "ntfy", "slack", "discord")
RETRY_AFTER = (5.0, 30.0, 120.0)  # seconds to wait before a delivery that failed is tried again, and again
MAX_WAITING = 100  # alerts waiting for one destination; when its service is away for long, the oldest give way
MOST_LOGGED = 50  # lines of each destination's delivery log (kept in memory: the activity log keeps what failed)


@dataclass
class Alert:
    kind: str  # "offline" | "no_signal" | "problem" | "recovered" | "unchanged" (a screen that looked the same: screens.py) | "test"
    device: str
    address: str
    state: str
    previous: str
    title: str
    text: str
    link: str = ""  # where to look: the wall, opened at this device's tile
    device_id: str = ""  # the tile it is about ("" for a test)
    # What happened, as a destination asks to hear it (destinations.EVENTS): finer than `kind`, which the JSON webhook
    # of 0.3.2 sends as its "event" and other tools read.
    event: str = ""
    # Destination id -> the courier's count when it was handed over there (Courier.put): what was handed over before a
    # switch was turned off is dropped at its next try, even where the switch is on again by then (server.held_back).
    handed: dict[str, int] = field(default_factory=dict, init=False, repr=False, compare=False)


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
        # Destination id -> device id -> the trouble last told there ("" where it was not told there): its "back to normal"
        # goes exactly where the trouble went (destinations.fitted), after a restart too.
        self.heard: dict[str, dict[str, str]] = {}
        self._file = kept_in
        self._writing = threading.Lock()
        self._written = self._text()  # (nothing known yet is nothing to write down, whatever the switches say: server)
        self._refused: str = ""
        self._failed_at: float | None = None  # when what `_refused` holds could not be written down (None: nothing is owed)
        self._from_before: set[str] = set()  # devices whose state is what was written down, and not yet seen again
        self._started = time.monotonic()
        if kept_in is not None:
            self._load(kept_in)

    def _load(self, kept_in: Path) -> None:
        # (One that cannot be read is said, and nothing of it is taken up: what is known from now on is written over it.)
        try:
            with kept_in.open("rb") as fh:
                text = fh.read(MOST_BOOK + 1)
        except FileNotFoundError:
            return  # (nothing written down yet)
        except OSError as ex:
            log.warning("what the machines were last seen as could not be read back: %s", ex.strerror or ex)
            return
        if len(text) > MOST_BOOK:
            log.warning("what the machines were last seen as is larger than qKVM reads back (%d bytes at the most): nothing of it is taken up", MOST_BOOK)
            return
        try:
            said = json.loads(text)
        except (ValueError, RecursionError):
            said = None
        if not isinstance(said, dict):
            log.warning("what the machines were last seen as could not be read back (it is damaged): nothing of it is taken up")
            return

        def states(of: Any) -> dict[str, str]:
            pairs = list(of.items())[:MOST_WATCHED] if isinstance(of, dict) else []
            return {key: value for key, value in pairs if isinstance(key, str) and len(key) <= MOST_ID and value in STATES}

        self._stable, self.held = states(said.get("stable")), states(said.get("held"))
        heard = said.get("heard")
        for destination, book in list(heard.items())[:MOST_DESTINATIONS] if isinstance(heard, dict) else []:
            if isinstance(destination, str) and len(destination) <= MOST_ID and isinstance(book, dict):
                pairs = list(book.items())[:MOST_WATCHED]
                self.heard[destination] = {key: value for key, value in pairs if isinstance(key, str) and len(key) <= MOST_ID and (value in STATES or value == "")}
        self._from_before = set(self._stable)
        self._written = self._text()

    def _text(self) -> str:
        return json.dumps({"stable": self._stable, "held": self.held, "heard": {key: book for key, book in self.heard.items() if book}}, sort_keys=True)

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
        """Write down what `to_write` gave. Waits for the disk: for a worker thread, one at a time (a look's write that the
        stop cut off goes on in its thread while the stop writes down what was dropped since: server.book_written)."""
        if self._file is None:
            return
        with self._writing:
            self._write(text)

    def _write(self, text: str) -> None:
        assert self._file is not None
        if len(text) > MOST_BOOK:
            # Never written over the one before, which still reads: one too large would be read back as nothing known. Said
            # once, and tried again after a while or at the next change, as a disk that refuses it is.
            if self._failed_at is None:
                log.warning("what the machines were last seen as is larger than qKVM reads back (%d bytes, %d at the most): the last one written down stays", len(text), MOST_BOOK)
            self._failed_at = time.monotonic()
            return
        try:
            being_written = self._file.with_name(self._file.name + ".new")
            being_written.unlink(missing_ok=True)  # (made anew, its owner's alone: _folders.private)
            with private(being_written, "x", encoding="ascii") as fh:
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
        for book in self.heard.values():
            book.pop(device_id, None)

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


def event_of(state: str, previous: str, code: str = "") -> str:
    """What happened, as a destination asks to hear it: from the state a machine is in now and the code of its error."""
    if state == "online":
        return "recovered"
    if code in ("cert_mismatch", "cert_invalid"):
        return "certificate"  # (a KVM whose certificate changed is offline to the wall; a server's controller, a problem)
    if state == "error":
        return "fault" if code == "health" else "problem"
    return {"offline": "offline", "no_signal": "no_signal", "auth": "auth", "unchanged": "unchanged"}.get(state, "problem")


def describe(
    name: str, address: str, previous: str, state: str, detail: str = "", server: bool = False, off: bool = False, device_id: str = "", code: str = ""
) -> Alert:
    """What to say about a KVM going from `previous` to `state`.

    `server`: it is a server seen through its management controller, where "no signal" means switched off.
    `off`: the KVM's power board says the computer behind it is off: its light is out, which it is too where a computer
    asleep puts it out (without a board, a KVM cannot tell either from a computer that is unplugged).
    `code`: the code of the error it shows, which tells a changed certificate and a server's critical fault apart.
    """
    alert = _describe(name, address, previous, state, detail, server, off)
    alert.device_id, alert.event = device_id, event_of(state, previous, code)
    return alert


def _describe(name: str, address: str, previous: str, state: str, detail: str, server: bool, off: bool) -> Alert:
    box = "Its management controller" if server else "The KVM"
    if state == "offline":
        return Alert("offline", name, address, state, previous, f"{name} is offline", f"{box} stopped answering.")
    if state == "no_signal":
        if server:
            return Alert("no_signal", name, address, state, previous, f"{name} is powered off", "The server was switched off or shut down.")
        if off:
            return Alert("no_signal", name, address, state, previous, f"{name} is off or asleep", "The KVM's power board shows the computer's power light out.")
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


def lasted(seconds: float) -> str:
    """How long something lasted, in words: "45 min", "2 h 10 min", "3 d 4 h"."""
    whole = max(1, round(seconds / 60))
    if whole < 60:
        return f"{whole} min"
    if whole < 24 * 60:
        hours, left = divmod(whole, 60)
        return f"{hours} h {left} min" if left else f"{hours} h"
    days, left = divmod(whole // 60, 24)
    return f"{days} d {left} h" if left else f"{days} d"


def describe_watch(
    name: str, address: str, watch: str, minutes: int, back: bool, seconds: float = 0.0, kept: bool = False, device_id: str = ""
) -> Alert:
    """What to say of a machine's screen watch (screens.py): `watch` "no_signal" or "unchanged" went off after `minutes`, or
    is over (`back`) after `seconds` of being so. `kept`: the picture that set it off is kept on the wall."""
    alert = _describe_watch(name, address, watch, minutes, back, seconds, kept)
    alert.device_id, alert.event = device_id, "recovered" if back else watch
    return alert


def _describe_watch(name: str, address: str, watch: str, minutes: int, back: bool, seconds: float, kept: bool) -> Alert:
    if watch == "no_signal":
        if back:
            text = f"The video signal is back, after {lasted(seconds)} without." if seconds else "The video signal is back."
            return Alert("recovered", name, address, "online", "no_signal", f"{name} has a picture again", text)
        text = f"No video signal for {minutes} min: the computer is off, asleep or no longer plugged into the KVM."
        text += " Its last picture is kept on the wall." if kept else ""
        return Alert("no_signal", name, address, "no_signal", "online", f"{name} has had no video signal for {minutes} min", text)
    if back:
        text = f"Its screen changed after looking the same for {lasted(seconds)}." if seconds else "Its screen changed again."
        return Alert("recovered", name, address, "online", "unchanged", f"{name}: the screen changes again", text)
    text = f"Its screen has looked the same for {minutes} min. That is not always a hang: a screen nobody uses looks the same too."
    text += " Its picture is kept on the wall." if kept else ""
    return Alert("unchanged", name, address, "unchanged", "online", f"{name}: screen unchanged for {minutes} min", text)


def wanted(alert: Alert, settings: Any) -> bool:
    """Did the admin ask to hear about this kind of change?"""
    return bool(getattr(settings, alert.kind, True))


def wall_link(url: str) -> str:
    """The address of the wall as people reach it, for alerts to point at. ValueError if it is not a web address."""
    url = _web_address(url).split("#", 1)[0]
    if not url.isascii():
        # It travels in a header to some services, which carries nothing else; and then no alert arrives at all.
        raise ValueError("Write the address with plain characters only (a name with others in it: in its xn-- form)")
    return url


def link_for(wall: str, device_id: str) -> str:
    """Where an alert about this device points: the wall, opened at its tile. "" where the wall's address is not known."""
    return f"{wall}#tile={device_id}" if wall else ""


def _web_address(url: str) -> str:
    """A web address as the wall's own may be written, or ValueError."""
    url = url.strip()
    try:
        parts = urlsplit(url)
        usable = parts.scheme in ("http", "https") and bool(parts.hostname) and len(url) <= 500
        usable = usable and httpx.URL(url).host != ""
    except (ValueError, httpx.InvalidURL):
        usable = False
    if not usable or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in url):
        raise ValueError("Enter a web address starting with http:// or https://")
    return url


# --- delivery: to each destination, by itself ----------------------------------------------------------------------


@dataclass
class Target:
    """A destination as it is sent to at this moment: its kind, what it is set to, and its secrets, opened."""

    id: str
    kind: str
    config: dict[str, Any]
    secrets: dict[str, str]
    private: bool  # may be a private address
    minimal: bool
    link: str  # the wall's address, for an alert to point at


@dataclass
class Delivery:
    """A line of a destination's delivery log: when, what (an alert's title, or how many in one message), how it went
    (the status, or the service's own words with every secret taken out), and after how many attempts."""

    at: float
    what: str
    events: list[str]
    ok: bool
    said: str
    attempts: int
    test: bool = False
    withheld: bool = False  # not sent, by the wall's own rules when it was to go (a switch): no failure of the destination's


class Courier:
    """Delivers the alerts to each destination: in the background, in order, one task per destination while it has
    something to send, so that a service that is slow or away holds up only its own destination, never the watching nor
    another destination.

    For a kind a person reads (destinations.SUMMARIZED), what waits when its turn comes goes as one message: a switch
    that dies takes thirty machines with it in the same look, and is one message, not thirty. The first of a run waits one
    look for the rest (some are seen a look later than the others), and after a message of several the destination is
    left alone for one look more, which gathers what is late of the same event; and between two
    messages to one destination there is at least the time its service asks for (destinations.SPACING). Each send is
    tried again after RETRY_AFTER where the service was away or busy (its own Retry-After where it gave one), and never
    where it said no. `target` says what a destination is at each attempt (a sentence where it cannot be sent to, None
    where it is gone); `report` is told how each delivery went. `held_back` says, of an alert waiting for a destination,
    why it may not go now (a sentence; None where it may): the destination or alerts switched off, now or at any moment
    since it was handed over (Alert.handed: switched on again before its next try, what waited went; the outside review of
    0.4.0, bugs round 2, M3). Asked before each attempt
    and once more right before it goes, after the waits for a turn and for the name (egress's `still`), what it holds back
    is dropped: not sent, then or later, its delivery logged as withheld, and handed to `dropped`; once a message of it
    arrived, the rest of it goes unasked (PagerDuty's two events of one change: the narrow look at 0.4.0, L3). (Only
    `target` was asked once, and what waited went all the same: the second outside review of 0.4.0, M4.) A pause and quiet
    hours are not asked here: they stop new alerts only, where an alert is routed, and what was handed to a destination
    before they began goes as it would have (three review rounds found ways to lose or falsely tell what they held of it:
    the fresh review of the fixes, N2; the last look, M1 to M5). `done` is told what was delivered, or given up on, once it
    is (who is owed a backup's end keeps it until then). A test (`test`) is not held back.
    """

    def __init__(
        self,
        target: Callable[[str], Target | str | None],
        own: Callable[[], Awaitable[egress.Own]],
        report: Callable[[str, Delivery], None],
        held_back: Callable[[str, Alert], str | None] | None = None,
        done: Callable[[str, list[Alert], bool], None] | None = None,
        dropped: Callable[[str, list[Alert]], None] | None = None,
    ) -> None:
        self._target = target
        self._own = own
        self._report = report
        self._held_back = held_back
        self._done = done
        self._dropped = dropped
        self._waiting: dict[str, deque[Alert]] = {}
        self._workers: dict[str, asyncio.Task[None]] = {}
        self._dropping: set[str] = set()
        self.log: dict[str, deque[Delivery]] = {}
        self.handed = 0  # alerts handed over so far, to any destination: what a switch turned off marks (Alert.handed)

    def put(self, destination_id: str, alert: Alert) -> None:
        """Have `alert` delivered to this destination, after what waits for it already. Never waits itself."""
        self.handed += 1
        alert.handed[destination_id] = self.handed
        waiting = self._waiting.setdefault(destination_id, deque())
        if len(waiting) >= MAX_WAITING:
            dropped = waiting.popleft()
            if destination_id not in self._dropping:  # (said once for a run of them: a line for each would be a flood)
                self._dropping.add(destination_id)
                log.warning("alerts gave way, too many were waiting for a destination that is away (the first: %s)", dropped.title)
            if self._done is not None:
                self._done(destination_id, [dropped], False)  # (given up on, as one never delivered is)
        waiting.append(alert)
        if destination_id not in self._workers:
            self._workers[destination_id] = asyncio.create_task(self._work(destination_id))

    def waiting(self, destination_id: str) -> int:
        return len(self._waiting.get(destination_id, ()))

    def forget(self, destination_id: str) -> None:
        """A destination that is gone: what waits for it goes, its log too, and what is under way for it is let go of."""
        self._waiting.pop(destination_id, None)
        self.log.pop(destination_id, None)
        self._dropping.discard(destination_id)
        task = self._workers.pop(destination_id, None)
        if task is not None and task is not asyncio.current_task():
            task.cancel()

    def _logged(self, destination_id: str, delivery: Delivery) -> None:
        self.log.setdefault(destination_id, deque(maxlen=MOST_LOGGED)).appendleft(delivery)
        self._report(destination_id, delivery)

    async def _work(self, destination_id: str) -> None:
        waiting = self._waiting[destination_id]
        gathered = False
        try:
            while waiting:
                target = self._target(destination_id)
                kind = target.kind if isinstance(target, Target) else ""
                if kind in destinations.SUMMARIZED and not gathered:
                    # What else changes in this look and the next is gathered first: a probe under way as a switch dies sees
                    # some machines go a look later than the others, and they are the same event.
                    gathered = True
                    await asyncio.sleep(CHECK_EVERY + 1.0)
                    continue
                if kind in destinations.SUMMARIZED:
                    batch = list(waiting)
                    waiting.clear()
                else:
                    batch = [waiting.popleft()]
                try:
                    await self._deliver(destination_id, batch)
                except Exception as ex:  # whatever goes wrong with one delivery must not be the end of this destination's others
                    log.exception("alerts could not be sent to a destination")
                    what = batch[0].title if len(batch) == 1 else f"{len(batch)} changes in one message"
                    said = f"Not sent: an error of qKVM's own ({type(ex).__name__}), in its log"
                    self._logged(destination_id, Delivery(time.time(), what, list(dict.fromkeys(alert.event for alert in batch)), False, said, 0))
                await asyncio.sleep(CHECK_EVERY + 1.0 if len(batch) > 1 else destinations.SPACING.get(kind, 1.0))
        finally:
            if self._waiting.get(destination_id) is waiting:
                del self._waiting[destination_id]
            if self._workers.get(destination_id) is asyncio.current_task():
                del self._workers[destination_id]
            self._dropping.discard(destination_id)

    async def attempt(
        self, target: Target, batch: list[Alert], still: Callable[[], str | None] | None = None, went: list[int] | None = None
    ) -> destinations.Outcome:
        """One attempt at delivering `batch` to a destination: each of its messages, until one does not arrive. `still`: why
        it may not go after all (None where it may), asked right before each message goes; withheld where it says so.
        `went`: how many of its messages arrived, counted on (PagerDuty's first of a change's two): those are not sent again
        (a retry began at the first, and the resolve that went was sent twice: the outside review of 0.4.0, bugs round 2)."""
        try:
            return await self._attempt(target, batch, still, went)
        except Exception as ex:
            # An error of qKVM's own: said where a delivery is said (its log, its last error, the activity log), not only in
            # the program's log, and not tried again (the review of 0.4.0's first wave, L2).
            log.exception("alerts could not be sent to a destination (%s)", destinations.KIND_NAMES.get(target.kind, target.kind))
            return destinations.Outcome(False, False, f"Not sent: an error of qKVM's own ({type(ex).__name__}), in its log")

    async def _attempt(
        self, target: Target, batch: list[Alert], still: Callable[[], str | None] | None = None, went: list[int] | None = None
    ) -> destinations.Outcome:
        own = await self._own()
        said = destinations.Outcome(True, False, "Nothing to send")
        why: list[str] = []  # (what `still` said, where it said no)

        def going() -> bool:
            if still is None:
                return True
            if (stopped := still()) is not None:
                why.append(stopped)
                return False
            return True

        messages = destinations.outgoing(target.kind, target.config, target.secrets, batch, link=target.link, minimal=target.minimal)
        for message in messages[went[0] if went is not None else 0 :]:
            try:
                if isinstance(message, destinations.Mail):
                    answer = await egress.send_mail(
                        message.host, message.port, message.login, message.message, message.sender, message.to, private_ok=target.private,
                        own=own.addresses, own_ports=own.ports, still=going,
                    )
                    said = destinations.Outcome(True, False, destinations.scrub(answer, target.secrets))
                else:
                    reply = await egress.post(
                        message.url, message.body, message.headers, private_ok=target.private, own=own.addresses, own_ports=own.ports, still=going
                    )
                    said = destinations.outcome(target.kind, reply, target.secrets)
            except egress.Withheld as ex:
                said = destinations.Outcome(False, False, why[-1] if why else str(ex), withheld=True)
            except egress.MailRefused as ex:
                said = destinations.Outcome(False, ex.again, destinations.scrub(str(ex), target.secrets))
            except (egress.Refused, egress.NotReached) as ex:
                said = destinations.Outcome(False, ex.again, destinations.scrub(str(ex), target.secrets))
            if not said.ok:
                return said
            if went is not None:
                went[0] += 1
        return said

    def _stopped(self, destination_id: str, batch: list[Alert]) -> str | None:
        """Why any of `batch` may not go now (held_back), or None where all of it may."""
        if self._held_back is None:
            return None
        for alert in batch:
            if (why := self._held_back(destination_id, alert)) is not None:
                return why
        return None

    def _drop(self, destination_id: str, batch: list[Alert], attempts: int) -> list[Alert]:
        """What of `batch` may go now; what may not (held_back) is dropped: logged as withheld, by why, and told `dropped`."""
        if self._held_back is None:
            return batch
        going: list[Alert] = []
        stopped: dict[str, list[Alert]] = {}
        for alert in batch:
            why = self._held_back(destination_id, alert)
            if why is None:
                going.append(alert)
            else:
                stopped.setdefault(why, []).append(alert)
        for why, those in stopped.items():
            what = those[0].title if len(those) == 1 else f"{len(those)} changes in one message"
            log.info("an alert waiting for a destination was not sent: %s", why)
            events = list(dict.fromkeys(alert.event for alert in those))
            self._logged(destination_id, Delivery(time.time(), what, events, False, why, attempts, withheld=True))
            if self._dropped is not None:
                try:
                    self._dropped(destination_id, those)
                except Exception:  # (what keeps count of it is the wall's own: its trouble must not end this destination's work)
                    log.exception("what became of an alert that was not sent could not be told")
        return going

    async def _deliver(self, destination_id: str, batch: list[Alert]) -> None:
        attempts, ok = 0, False
        tries = iter((*RETRY_AFTER, None))
        pause = next(tries)
        # Whether a message of it arrived: then the rest of it goes, whatever the switches say since. (PagerDuty is sent a
        # change between two kinds of trouble as two events: asked before each, a switch flipped while the first was on the
        # line held the second back, and the change was taken back as untold though its resolve went; no incident was open
        # then where the machine went back to that trouble. The narrow look at 0.4.0, L3.) Counted: a retry sends what is left.
        went = [0]
        # Who its first message went to (destinations.receiver): what is left of a change, which goes whatever the switches
        # say since, goes there or nowhere. A routing key edited while PagerDuty's trigger waited for its retry had it go to the
        # new key, which never heard of the trouble, and none to the one that took the resolve (the re-check of the outside
        # review's fixes, N1). Before a message went, an edit drops it anyway (held_back).
        first_receiver: str | None = None
        try:
            while batch:
                # Asked again before each attempt: a destination removed or changed meanwhile is sent nothing of what waited
                # for it as it was; and what waits goes only while it is not switched off (held_back), asked once more right
                # before it goes (the second outside review of 0.4.0, M4). What may not go is dropped (_drop).
                target = self._target(destination_id)
                if target is None:
                    return
                batch = batch if went[0] else self._drop(destination_id, batch, attempts)
                if not batch:
                    return
                what = batch[0].title if len(batch) == 1 else f"{len(batch)} changes in one message"
                events = list(dict.fromkeys(alert.event for alert in batch))
                if isinstance(target, str):
                    self._logged(destination_id, Delivery(time.time(), what, events, False, target, attempts))
                    return
                reached = destinations.receiver(target.kind, target.config, target.secrets)
                if first_receiver is None:
                    first_receiver = reached
                elif went[0] and reached != first_receiver:
                    said_why = "Not sent: the destination was changed to send elsewhere while it waited"
                    log.info("what was left of an alert was not sent: %s", said_why)
                    self._logged(destination_id, Delivery(time.time(), what, events, False, said_why, attempts, withheld=True))
                    return

                def still(batch: list[Alert] = batch) -> str | None:
                    return None if went[0] else self._stopped(destination_id, batch)

                attempts += 1
                said = await self.attempt(target, batch, still, went)
                if said.withheld:
                    attempts -= 1  # (nothing went: what may not go is sorted from what may at the top, at once)
                    continue
                if said.ok or pause is None or not said.again:
                    if not said.ok:
                        log.warning("an alert was not delivered to a destination (%s): %s", destinations.KIND_NAMES.get(target.kind, target.kind), said.said)
                    self._logged(destination_id, Delivery(time.time(), what, events, said.ok, said.said, attempts))
                    ok = said.ok
                    return
                log.info("an alert was not delivered yet, tried again in %d s: %s", max(pause, said.wait), said.said)
                await asyncio.sleep(max(pause, said.wait))
                pause = next(tries)
        except asyncio.CancelledError:
            batch = []  # (stopped with the program, or its destination gone: nothing became of it, and nothing is said of it)
            raise
        finally:
            if batch and self._done is not None:
                try:
                    self._done(destination_id, batch, ok)
                except Exception:
                    log.exception("what became of an alert could not be told")

    async def test(self, destination_id: str, alert: Alert) -> Delivery:
        """One attempt at a test alert, at once: whoever pressed the button is waiting. Its outcome is in the log too."""
        target = self._target(destination_id)
        if not isinstance(target, Target):
            delivery = Delivery(time.time(), alert.title, ["test"], False, target or "There is no such destination", 0, test=True)
        else:
            said = await self.attempt(target, [alert])
            delivery = Delivery(time.time(), alert.title, ["test"], said.ok, said.said, 1, test=True)
        self._logged(destination_id, delivery)
        return delivery

    async def close(self) -> None:
        for task in self._workers.values():
            task.cancel()
        await asyncio.gather(*self._workers.values(), return_exceptions=True)
        self._workers.clear()
        self._waiting.clear()
