"""What a live line still had on its way to a machine when it lost keyboard and mouse (qkvm/live.py: `Hid.end`, `Machine._let_go`).

A word to a machine may take its time: a PC with Intel AMT whose session the engine ended (it does, every few minutes)
has a key wait up to ten seconds for the next session. The line may lose keyboard and mouse meanwhile: its account
lowered to a viewer, signed out, the tile edited, the wall stopping. Everything it had down is let go of then, which
on a PC between two sessions goes nowhere; and the key that was waiting lands after that, in a session where nothing
would ever let it go. Ctrl held down on a machine that runs production work is the worst this program can leave.

Each test here plays one row of that: a made-up way to the machine whose words wait for as long as the test says, a
machine with two lines, and at the end a look at what the machine was told, in order, replayed into what it holds down
now: nothing, in every row. And the other half of it: a word that fails after its line lost keyboard and mouse takes
nothing away from whoever holds them now.

Beside it, the other ways a line ends without its socket closing, each of which must give up what it held at once: a
line that is not read, one told goodbye while the machine is first looked at, one stopped then, and the look every few
seconds that ends a signed-out line, which one failure must not stop for good. And what the wall waits for before a
device's connection is closed under a letting go.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import pytest
from starlette.websockets import WebSocketState

from qkvm import amt, live
from qkvm.amt import AmtDevice
from qkvm.kvm import DeviceSpec, KvmError
from tests.fake_amt import FakeAmt


class Way(live.Hid):
    """A made-up way to a machine (as RFB is: the pointer carries the buttons that are held). A word of a kind named in
    `waits` waits until the test lets it through (`through`), and then lands, or fails."""

    def __init__(self, name: str, said: list[tuple[Any, ...]]) -> None:
        super().__init__()
        self.name, self.said = name, said
        self.waits: dict[str, asyncio.Future[str]] = {}
        self.waiting: dict[str, asyncio.Event] = {}
        self.closed = False
        self.releases = 0
        self.slow_up = 0.0  # seconds a key let go of takes to be taken (a device slow to take what is sent)
        self.slow_button_up = 0.0  # ...and a button let go of
        self.opening: asyncio.Future[None] | None = None  # where set, making the way in waits for it
        self.opening_started = asyncio.Event()
        self.closing: asyncio.Future[None] | None = None  # where set, closing it waits for it

    def hold(self, kind: str) -> None:
        """The next word of this kind ("key", "place", "button") waits for `through`."""
        self.waits[kind] = asyncio.get_running_loop().create_future()
        self.waiting[kind] = asyncio.Event()

    async def wait_until_waiting(self, kind: str) -> None:
        await asyncio.wait_for(self.waiting[kind].wait(), timeout=5)

    def through(self, kind: str, how: str = "lands") -> None:
        self.waits.pop(kind).set_result(how)

    async def _wait(self, kind: str) -> None:
        gate = self.waits.get(kind)
        if gate is not None:
            self.said.append((self.name, "waiting", kind))
            self.waiting[kind].set()
            if await gate == "fails":
                raise KvmError("dropped", "the way to the machine ended")

    async def _say_key(self, usage: int, down: bool) -> None:
        if down:
            await self._wait("key")
        else:
            await asyncio.sleep(self.slow_up)
        self.said.append((self.name, "key", usage, down))

    async def _say_place(self, x: int, y: int) -> None:
        held = sorted(self.buttons_down)  # (what the pointer carries, as RFB's does: taken as it is sent)
        await self._wait("place")
        self.said.append((self.name, "pointer", x, y, held))

    async def _say_move(self, dx: int, dy: int) -> None:
        self.said.append((self.name, "pointer", dx, dy, sorted(self.buttons_down)))

    async def _say_button(self, button: int, down: bool) -> None:
        if down:
            await self._wait("button")
        elif self.slow_button_up:
            await asyncio.sleep(self.slow_button_up)
        self.said.append((self.name, "button", button, down))

    async def _say_wheel(self, dx: int, dy: int) -> None:
        self.said.append((self.name, "wheel", dx, dy))

    async def open(self) -> None:
        self.opening_started.set()
        if self.opening is not None:
            await self.opening

    async def close(self) -> None:
        if self.closing is not None:
            await self.closing
        self.closed = True
        self.said.append((self.name, "closed"))

    async def release_all(self) -> None:
        self.releases += 1
        await super().release_all()


def held_down(said: list[tuple[Any, ...]]) -> tuple[set[int], set[int]]:
    """What the machine holds down after what it was told, in order: (keys, buttons). The pointer says every button anew."""
    keys: set[int] = set()
    buttons: set[int] = set()
    for word in said:
        if word[1] == "key":
            (keys.add if word[3] else keys.discard)(word[2])
        elif word[1] == "button":
            (buttons.add if word[3] else buttons.discard)(word[2])
        elif word[1] == "pointer":
            buttons = set(word[4])
    return keys, buttons


class Owed:
    """The wall's side of a machine, as far as a machine asks it: what is owed, the log, one thing at a time."""

    def __init__(self) -> None:
        self.machines: dict[str, live.Machine] = {}
        self.manager = SimpleNamespace(devices={})
        self.audited: list[dict[str, Any]] = []
        self.tasks: set[asyncio.Task[None]] = set()
        self.admins: set[str] = set()  # the accounts that may take keyboard and mouse over (as the server says of an admin in person)
        self.handing: dict[str, list[live.Hid]] = {}  # (as Lines.handing: what the holders before still let go of)

    def busy(self, device_id: str) -> bool:
        return False

    def standing(self, holder: live.Holder, device_id: str) -> tuple[str | None, bool]:
        return None, True

    def may_take(self, holder: live.Holder, device_id: str) -> bool:
        return holder.user_id in self.admins

    def audit(self, event: str, ip: str, **detail: Any) -> None:
        self.audited.append(detail)

    def owed(self, task: asyncio.Task[None], device_id: str | None = None) -> None:
        self.tasks.add(task)

    async def settled(self) -> None:
        while pending := {task for task in self.tasks if not task.done()}:
            await asyncio.wait(pending, timeout=5)


class Scene:
    """One machine, two lines to it (A and B, both of operators), and the ways to the machine handed out in that order."""

    def __init__(self) -> None:
        self.said: list[tuple[Any, ...]] = []
        self.lines = Owed()
        device = SimpleNamespace(kind="kvmd", spec=SimpleNamespace(name="PC", id="d1"), label="PC")
        self.machine = live.Machine(self.lines, "d1", device)  # type: ignore[arg-type]
        self.a, self.b = self.line("A"), self.line("B")
        self.ways = [Way("way A", self.said), Way("way B", self.said)]
        handed = iter(self.ways)

        def way() -> live.Hid:
            made = next(handed)
            made.owe = self.lines.tasks.add  # (as the program's machine does: what is owed later is waited for by the wall)
            return made

        self.machine._hid = way  # type: ignore[method-assign]

    def line(self, name: str) -> live.Line:
        made = live.Line(SimpleNamespace(), live.Holder(name, name, True, "127.0.0.1", "s-" + name), self.machine, frozenset({"jpeg"}), 640, 30.0)  # type: ignore[arg-type]
        self.machine.viewers.add(made)
        return made

    async def take(self, line: live.Line) -> None:
        assert await self.machine.control(line, True) == {"t": "control", "on": True}

    def lose(self, line: live.Line) -> None:
        """From elsewhere: the look every few seconds found the account lowered to a viewer."""
        self.machine._let_go(line, "not_allowed", "Your account may no longer act on this machine")

    async def settled(self) -> None:
        await asyncio.sleep(0.05)
        await self.lines.settled()


def played(scene: Any) -> Any:
    def run() -> None:
        asyncio.run(asyncio.wait_for(scene(), timeout=30))

    return run


@pytest.fixture
def pointer_clock(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    # Freeze only live.py's clock, not asyncio's: selecting the paced path must not depend on two calls
    # landing within ten real milliseconds. The delayed task and timeout guards still use real time.
    clock = SimpleNamespace(now=0.0)
    monkeypatch.setattr(live, "time", SimpleNamespace(monotonic=lambda: clock.now, monotonic_ns=time.monotonic_ns))
    return clock


@pytest.mark.parametrize("checked_while_opening", [False, True])
def test_a_role_lowered_while_the_way_in_opens_never_gets_keyboard_or_mouse(checked_while_opening: bool) -> None:
    async def scene() -> None:
        s = Scene()
        may_control = True
        s.lines.standing = lambda holder, device_id: (None, may_control)  # type: ignore[method-assign]
        way = s.ways[0]
        way.opening = asyncio.get_running_loop().create_future()
        asking = asyncio.create_task(s.machine.control(s.a, True))
        await way.opening_started.wait()
        may_control = False
        if checked_while_opening:
            s.machine._stands(s.a)
            assert not s.a.may_control
        way.opening.set_result(None)
        reply = await asking
        for _ in range(3):
            s.machine._stands(s.a)
        await s.machine.input(s.a, {"t": "k", "u": 0x04, "d": True})
        await s.machine.input(s.a, {"t": "mb", "b": 1, "d": True})
        await s.settled()
        assert reply["on"] is False and reply["code"] == "not_allowed", reply
        assert s.machine.holder is None and s.machine.hid is None and not s.a.control
        assert not s.a.may_control and s.a.leaving is None  # (viewing is still allowed)
        assert way.closed and way.ended
        assert way.releases == 0  # (it held nothing: releasing could disturb another holder's shared device connection)
        assert s.said == [("way A", "closed")], s.said
        assert s.lines.audited == [], "a refused grant must never be recorded as control acquired"

    played(scene)()


def test_a_holder_without_permission_loses_control_even_if_the_cached_flag_is_already_false() -> None:
    async def scene() -> None:
        s = Scene()
        await s.take(s.a)
        await s.machine.input(s.a, {"t": "k", "u": 0xE0, "d": True})
        s.a.may_control = False
        s.lines.standing = lambda holder, device_id: (None, False)  # type: ignore[method-assign]
        for _ in range(3):
            s.machine._stands(s.a)
        await s.machine.input(s.a, {"t": "k", "u": 0x04, "d": True})
        await s.settled()
        assert s.machine.holder is None and s.machine.hid is None and not s.a.control
        assert s.ways[0].closed and s.ways[0].ended
        assert ("way A", "key", 0x04, True) not in s.said
        assert held_down(s.said) == (set(), set()), s.said
        assert [entry["on"] for entry in s.lines.audited] == [True, False]
        assert s.lines.audited[-1]["why"] == "not_allowed"

    played(scene)()


@pytest.mark.parametrize("standing_failure", ["signed_out", "internal"])
def test_a_way_in_is_closed_if_access_ends_or_cannot_be_checked_while_it_opens(standing_failure: str) -> None:
    async def scene() -> None:
        s = Scene()
        errors: list[str] = []
        s.machine.device._unexpected = lambda what, error: errors.append(what)  # type: ignore[attr-defined]
        way = s.ways[0]
        way.opening = asyncio.get_running_loop().create_future()
        asking = asyncio.create_task(s.machine.control(s.a, True))
        await way.opening_started.wait()

        def standing(holder: live.Holder, device_id: str) -> tuple[str | None, bool]:
            if standing_failure == "internal":
                raise RuntimeError("the account could not be checked")
            return "signed_out", False

        s.lines.standing = standing  # type: ignore[method-assign]
        way.opening.set_result(None)
        reply = await asking
        await s.machine.input(s.a, {"t": "k", "u": 0x04, "d": True})
        await s.settled()
        assert reply["on"] is False, reply
        assert s.a.leaving == standing_failure
        assert s.machine.holder is None and s.machine.hid is None and not s.a.control
        assert way.closed and way.ended
        assert way.releases == 0
        assert s.said == [("way A", "closed")], s.said
        assert s.lines.audited == []
        assert bool(errors) is (standing_failure == "internal")

    played(scene)()


def test_a_key_that_lands_after_its_line_lost_the_keyboard_is_let_go_of_again() -> None:
    async def scene() -> None:
        s = Scene()
        await s.take(s.a)
        way_a = s.ways[0]
        way_a.hold("key")
        typing = asyncio.create_task(s.machine.input(s.a, {"t": "k", "u": 0xE0, "d": True}))  # Ctrl, and the PC is between two sessions
        await asyncio.sleep(0.01)
        s.lose(s.a)  # everything A had down is let go of: Ctrl goes up into no session, and A's way is closed
        await asyncio.sleep(0.01)
        await s.take(s.b)
        way_a.through("key")  # the next session opens, and Ctrl lands in it
        await typing
        await s.settled()
        landed = s.said.index(("way A", "key", 0xE0, True))
        assert ("way A", "key", 0xE0, False) in s.said[landed:], f"Ctrl stayed down on the machine: {s.said}"
        assert held_down(s.said) == (set(), set()), s.said
        assert s.machine.holder is s.b and s.b.control  # (B's, and nothing of this touched B)

    played(scene)()


def test_a_key_that_fails_after_its_line_lost_the_keyboard_takes_nothing_from_whoever_holds_it_now() -> None:
    async def scene() -> None:
        s = Scene()
        await s.take(s.a)
        way_a, way_b = s.ways
        way_a.hold("key")
        typing = asyncio.create_task(s.machine.input(s.a, {"t": "k", "u": 0x04, "d": True}))
        await asyncio.sleep(0.01)
        s.lose(s.a)
        await asyncio.sleep(0.01)
        await s.take(s.b)
        heard_before = len(s.lines.audited)
        way_a.through("key", "fails")  # A's key fails, after B took the keyboard
        await typing
        await s.settled()
        assert s.machine.holder is s.b and s.machine.hid is way_b and s.b.control, "B's keyboard and mouse were taken by A's failure"
        assert not way_b.closed and not way_b.ended
        assert list(s.b.words) == [], "B was told something about A's key"
        assert s.lines.audited[heard_before:] == [], f"the activity log says more after B took them: {s.lines.audited[heard_before:]}"
        # B goes on typing, and it arrives.
        await s.machine.input(s.b, {"t": "k", "u": 0x05, "d": True})
        assert s.said[-1] == ("way B", "key", 0x05, True)

    played(scene)()


def test_a_key_behind_a_place_that_was_on_its_way_is_not_sent_after_the_end(pointer_clock: SimpleNamespace) -> None:
    async def scene() -> None:
        s = Scene()
        await s.take(s.a)
        way_a = s.ways[0]
        await s.machine.input(s.a, {"t": "m", "x": 10, "y": 10})  # (the pointer is put; the next place within ten milliseconds waits its turn)
        await s.machine.input(s.a, {"t": "m", "x": 20, "y": 20})
        way_a.hold("place")
        typing = asyncio.create_task(s.machine.input(s.a, {"t": "k", "u": 0xE2, "d": True}))  # Alt, behind the place that waits
        await way_a.wait_until_waiting("place")
        s.lose(s.a)
        await asyncio.sleep(0.01)
        way_a.through("place")
        await typing
        await s.settled()
        assert ("way A", "key", 0xE2, True) not in s.said, f"a key went to the machine after its line lost the keyboard: {s.said}"
        assert held_down(s.said) == (set(), set()), s.said

    played(scene)()


def test_a_place_that_carried_a_held_button_and_landed_after_the_end_lets_the_button_go_again() -> None:
    async def scene() -> None:
        s = Scene()
        await s.take(s.a)
        way_a = s.ways[0]
        await s.machine.input(s.a, {"t": "mb", "b": 1, "d": True})  # a drag: the left button is down
        await asyncio.sleep(live.POINTER_EVERY * 2)
        way_a.hold("place")
        dragging = asyncio.create_task(s.machine.input(s.a, {"t": "m", "x": 300, "y": 300}))  # carries the left button, as RFB's pointer does
        await asyncio.sleep(0.01)
        s.lose(s.a)  # the button goes up into no session
        await asyncio.sleep(0.01)
        way_a.through("place")  # and the pointer with the button lands in the next
        await dragging
        await s.settled()
        assert held_down(s.said) == (set(), set()), f"the left button stayed down on the machine: {s.said}"

    played(scene)()


def test_a_button_pressed_on_its_way_at_the_end_is_let_go_of_again_and_nothing_more_goes() -> None:
    async def scene() -> None:
        s = Scene()
        await s.take(s.a)
        way_a = s.ways[0]
        way_a.hold("button")
        clicking = asyncio.create_task(s.machine.input(s.a, {"t": "mb", "b": 2, "d": True}))
        await asyncio.sleep(0.01)
        s.lose(s.a)
        await asyncio.sleep(0.01)
        way_a.through("button")
        await clicking
        await s.settled()
        assert held_down(s.said) == (set(), set()), f"the right button stayed down on the machine: {s.said}"
        # Whatever still reaches the way it had finds it ended: nothing more goes to the machine.
        before = len(s.said)
        await way_a.key(0x04, True)
        await way_a.place(1, 1)
        await way_a.move(5, 5)
        await way_a.wheel(0, 1)
        await way_a.button(1, True)
        await s.settled()
        assert s.said[before:] == [], f"sent after the end: {s.said[before:]}"

    played(scene)()


def test_a_place_the_pacing_sent_with_a_drags_button_lands_after_the_button_was_let_go_of_and_lets_it_go_again(pointer_clock: SimpleNamespace) -> None:
    # A drag on a PC whose engine just ended its session: the last place of the drag is sent by the pointer's pacing, in a
    # task of its own, with the button in it (RFB says the buttons with every pointer event), and waits for the next
    # session. Meanwhile the person lets go of the button: that goes to the session that is open, none, and the place
    # lands afterwards and presses the button again. Nothing in the program knew it was down.
    async def scene() -> None:
        s = Scene()
        await s.take(s.a)
        way_a = s.ways[0]
        await s.machine.input(s.a, {"t": "mb", "b": 1, "d": True})
        await s.machine.input(s.a, {"t": "m", "x": 10, "y": 10})  # (sent at once)
        way_a.hold("place")
        await s.machine.input(s.a, {"t": "m", "x": 20, "y": 20})  # (within ten milliseconds: sent by the pacing, a moment later)
        await way_a.wait_until_waiting("place")
        assert way_a._placing is not None and not way_a._placing.done(), "the pacing did not send the place"
        await s.machine.input(s.a, {"t": "mb", "b": 1, "d": False})  # let go of, while the place waits
        way_a.through("place")
        await s.settled()
        assert held_down(s.said) == (set(), set()), f"the left button stayed down on the machine: {s.said}"
        assert s.machine.holder is s.a and s.a.control  # (nothing was ended: the line goes on)

    played(scene)()


def test_a_way_in_made_for_a_line_that_is_stopped_meanwhile_is_closed_all_the_same() -> None:
    # Control asked, and the line's task stopped (the web server stopping) while the way in is made, or while one that was
    # made for nothing is closed again: closed in the line's task, the closing was cut off, and the way left open.
    async def scene() -> None:
        s = Scene()
        way_a, way_b = s.ways
        way_a.opening = asyncio.get_running_loop().create_future()
        asking = asyncio.create_task(s.machine.control(s.a, True))
        await asyncio.sleep(0.01)
        asking.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await asking
        await s.settled()
        assert way_a.closed, "a way in made for a line that was stopped was left open"

        way_b.opening = asyncio.get_running_loop().create_future()
        way_b.closing = asyncio.get_running_loop().create_future()
        asking = asyncio.create_task(s.machine.control(s.b, True))
        await asyncio.sleep(0.01)
        s.machine.holder = s.a  # (somebody else took them while the way in was made: it is closed again)
        s.machine.control_reference = "another-control-lease"
        way_b.opening.set_result(None)
        await asyncio.sleep(0.01)
        asking.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await asking
        way_b.closing.set_result(None)
        await s.settled()
        assert way_b.closed, "a way in closed in the task of a line that was stopped was left open"

    played(scene)()


@pytest.mark.parametrize("paced", [True, False], ids=["paced", "immediate"])
def test_a_late_letting_go_of_two_buttons_leaves_one_pressed_again_meanwhile_down(pointer_clock: SimpleNamespace, paced: bool) -> None:
    # A late letting go owes two buttons; while the first goes (a device slow to take it), the holder presses the second
    # again. It was asked once, at the start, whether each was held again: the second went up on the machine, and the
    # program went on believing it down.
    async def scene() -> None:
        s = Scene()
        await s.take(s.a)
        way_a = s.ways[0]
        await s.machine.input(s.a, {"t": "mb", "b": 1, "d": True})
        await s.machine.input(s.a, {"t": "mb", "b": 3, "d": True})
        await s.machine.input(s.a, {"t": "m", "x": 10, "y": 10})
        way_a.hold("place")
        if not paced:
            pointer_clock.now += live.POINTER_EVERY * 2
        placing = asyncio.create_task(s.machine.input(s.a, {"t": "m", "x": 20, "y": 20}))
        await way_a.wait_until_waiting("place")
        assert (way_a._placing is not None) is paced
        await s.machine.input(s.a, {"t": "mb", "b": 1, "d": False})
        await s.machine.input(s.a, {"t": "mb", "b": 3, "d": False})
        first_up_started, first_up_allowed = asyncio.Event(), asyncio.Event()
        say_button = way_a._say_button

        async def hold_first_up(button: int, down: bool) -> None:
            if button == 1 and not down:
                first_up_started.set()
                await first_up_allowed.wait()
            await say_button(button, down)

        way_a._say_button = hold_first_up  # type: ignore[method-assign]
        way_a.through("place")  # lands with both: both are owed a letting go again
        await asyncio.wait_for(first_up_started.wait(), timeout=5)
        await s.machine.input(s.a, {"t": "mb", "b": 3, "d": True})  # the middle button pressed again
        first_up_allowed.set()
        await placing
        await s.settled()
        assert held_down(s.said)[1] == way_a.buttons_down == {3}, f"the machine and the program disagree about the middle button: {s.said}"

    played(scene)()


class Pc:
    """A PC with Intel AMT as RfbHid sees it: a session the test ends and opens again (`session`). A key or a pointer event
    waits for a session, as the real one's do; a letting go goes to the session that is open, or nowhere."""

    kind, label = "amt", "PC"

    def __init__(self) -> None:
        self.spec = SimpleNamespace(name="PC", id="d1")
        self.session = asyncio.Event()
        self.session.set()
        self.waiting_for_session = asyncio.Event()
        self.pointers: list[tuple[int, int, int, bool]] = []  # x, y, buttons, a letting go

    async def input_ready(self) -> None:
        if not self.session.is_set():
            self.waiting_for_session.set()
        await self.session.wait()

    def screen_size(self) -> tuple[int, int] | None:
        return (321, 201) if self.session.is_set() else None

    async def pointer(self, x: int, y: int, buttons: int = 0, letting_go: bool = False, still: Any = None) -> None:
        if not letting_go:
            await self.session.wait()
            if still is not None and not still():
                return  # (as the PC does: see AmtDevice.pointer)
        elif not self.session.is_set():
            return  # (nowhere)
        self.pointers.append((x, y, buttons, letting_go))

    async def press(self, usage: int, down: bool, still: Any = None) -> None:
        if down:
            await self.session.wait()
            if still is not None and not still():
                return


def a_pc_held() -> tuple[Pc, live.Machine, live.Line, Owed]:
    pc, lines = Pc(), Owed()
    machine = live.Machine(lines, "d1", pc)  # type: ignore[arg-type]
    line = live.Line(SimpleNamespace(), live.Holder("olga", "olga", True, "127.0.0.1", "s"), machine, frozenset({"jpeg"}), 640, 30.0)  # type: ignore[arg-type]
    machine.viewers.add(line)
    return pc, machine, line, lines


def test_a_click_after_a_place_that_waited_for_the_next_session_lands_at_that_place(pointer_clock: SimpleNamespace) -> None:
    # The last place before a click waits for the next session (the pacing sent it in the gap); the click comes meanwhile,
    # and waits too. Worked out as it was asked for, the click went to where the pointer had been before the gap, or a
    # press there and a drag to the place.
    async def scene() -> None:
        pc, machine, line, lines = a_pc_held()
        assert (await machine.control(line, True))["on"] is True
        await machine.input(line, {"t": "m", "x": 8192, "y": 8192})  # (80, 50)
        pc.session.clear()  # the engine ends its session
        await machine.input(line, {"t": "m", "x": 24576, "y": 24576})  # (240, 150), within the controlled pacing interval
        await asyncio.wait_for(pc.waiting_for_session.wait(), timeout=5)
        clicking = asyncio.create_task(machine.input(line, {"t": "mb", "b": 1, "d": True}))
        await asyncio.sleep(0.05)
        pc.session.set()  # the next session
        await clicking
        await machine.input(line, {"t": "mb", "b": 1, "d": False})
        await asyncio.sleep(0.05)
        await lines.settled()
        assert pc.pointers[0] == (80, 50, 0, False)
        assert all((x, y) == (240, 150) for x, y, _, _ in pc.pointers[1:]), f"the click did not land at the place: {pc.pointers}"
        assert [buttons for _, _, buttons, _ in pc.pointers[1:]][-1] == 0 and 1 in [buttons for _, _, buttons, _ in pc.pointers[1:]]

    played(scene)()


def test_a_place_waiting_for_the_next_session_goes_nowhere_once_the_line_lost_the_keyboard() -> None:
    # It waited for the screen's size; meanwhile the line lost keyboard and mouse. It went out all the same when the next
    # session opened: on RFB the buttons are the session's, and whoever holds them by then had theirs let go of, and their
    # pointer moved.
    async def scene() -> None:
        pc, machine, line, lines = a_pc_held()
        assert (await machine.control(line, True))["on"] is True
        pc.session.clear()
        placing = asyncio.create_task(machine.input(line, {"t": "m", "x": 16384, "y": 16384}))
        await asyncio.sleep(0.05)
        machine._let_go(line, "not_allowed", "Your account may no longer act on this machine")
        await asyncio.sleep(0.05)
        pc.session.set()
        await placing
        await lines.settled()
        assert [event for event in pc.pointers if not event[3]] == [], f"a pointer event went out after the end: {pc.pointers}"

    played(scene)()


class Jet:
    """A JetKVM as JetHid sees it: its one queue of reports, and its connection, made for the first that asks slowly."""

    kind, label = "jetkvm", "Jet"

    def __init__(self) -> None:
        self.spec = SimpleNamespace(name="Jet", id="d1")
        self.reports: list[tuple[str, dict[str, Any]]] = []
        self.first_waits: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self.asked = 0

    async def input_ready(self) -> object:
        self.asked += 1
        if self.asked == 1:
            await self.first_waits
        return "the connection"

    def say(self, method: str, params: dict[str, Any], fold: bool = False, on: object = None, holder_may: Any = None, letting_go: bool = False) -> None:
        self.reports.append((method, dict(params)))

    async def all_said(self) -> None:
        pass


def test_a_way_in_to_a_jetkvm_made_for_nothing_is_closed_without_letting_go_of_the_holders_keys() -> None:
    # Two lines ask for a JetKVM's keyboard as its connection is being made; the second gets it and holds Ctrl, the first
    # is refused once its way in is made. Closing that way in let go of everything on the JetKVM: its letting go is the whole
    # state of the keyboard, on the connection the holder uses. Ctrl went up under the holder's hands.
    async def scene() -> None:
        jet, lines = Jet(), Owed()
        machine = live.Machine(lines, "d1", jet)  # type: ignore[arg-type]
        first, second = (live.Line(SimpleNamespace(), live.Holder(name, name, True, "127.0.0.1", "s"), machine, frozenset({"jpeg"}), 640, 30.0) for name in ("a", "b"))  # type: ignore[arg-type]
        machine.viewers |= {first, second}
        asking = asyncio.create_task(machine.control(first, True))
        await asyncio.sleep(0.01)
        assert (await machine.control(second, True))["on"] is True
        await machine.input(second, {"t": "k", "u": 0xE0, "d": True})
        jet.first_waits.set_result(None)
        assert (await asking)["code"] == "taken"
        await asyncio.sleep(0.05)
        await lines.settled()
        assert jet.reports == [("keyboardReport", {"modifier": 1, "keys": []})], f"the JetKVM was told: {jet.reports}"

    played(scene)()


# --- a line that ends in other ways ------------------------------------------------------------------------------


def test_a_line_that_is_not_read_ends_and_gives_up_the_keyboard_and_what_it_had_down() -> None:
    # A viewer that reads nothing has what it is told pile up. Past MOST_WORDS it is told goodbye ("slow"); it kept the
    # machine's keyboard and mouse, and Shift down, until its socket was found closed, and its key ups were not heard.
    async def scene() -> None:
        s = Scene()
        await s.take(s.a)
        await s.machine.input(s.a, {"t": "k", "u": 0xE1, "d": True})  # Shift
        source = live.Source(s.machine)
        for line in (s.a, s.b):
            source.viewers.add(line)
            line.source = source
        for _ in range(live.MOST_WORDS):
            s.a.say({"t": "state", "state": "online"})  # (nobody takes them off the line)
        source.announce()  # every viewer is told what follows: one word too many for A
        assert s.a.leaving == "slow" and json.loads(s.a.words[-1])["t"] == "bye"
        assert s.machine.holder is None and not s.a.control, "a line that is not read kept the keyboard and mouse"
        assert source.viewers == {s.b} and s.a.source is None
        assert json.loads(s.b.words[-1])["t"] == "video"  # (the other line was told, and goes on)
        await s.settled()
        assert held_down(s.said) == (set(), set()), f"Shift stayed down: {s.said}"
        await s.take(s.b)  # and somebody else may take them

    played(scene)()


class Screen:
    """A server's screen as far as a line asks it: how it is, when the test says; its picture never comes."""

    def __init__(self) -> None:
        self.kind = "redfish"
        self.spec = SimpleNamespace(name="Server", id="d1")
        self.label = "Server"
        self.console_readable = True
        self.looked = asyncio.get_running_loop().create_future()
        self.said: list[str] = []

    async def status(self) -> dict[str, Any]:
        await self.looked
        return {"state": "online"}

    async def live_screen(self) -> Any:
        await asyncio.Event().wait()

    def _unexpected(self, what: str, error: BaseException) -> None:
        self.said.append(f"{what}: {error}")


def lines_to(device: Any, standing: Any = None) -> live.Lines:
    return live.Lines(SimpleNamespace(devices={"d1": device}), standing=standing or (lambda holder, device_id: (None, True)), busy=lambda device_id: False, audit=lambda *given, **more: None)  # type: ignore[arg-type]


def test_a_line_told_goodbye_while_the_machine_is_first_looked_at_joins_nothing() -> None:
    async def scene() -> None:
        device = Screen()
        lines = lines_to(device)
        machine = lines.machines["d1"] = live.Machine(lines, "d1", device)  # type: ignore[arg-type]
        line = live.Line(SimpleNamespace(), live.Holder("u", "u", True, "127.0.0.1", "s"), machine, frozenset({"jpeg"}), 640, 5.0)  # type: ignore[arg-type]
        joining = asyncio.create_task(machine.join(line))
        await asyncio.sleep(0.01)
        line.end("gone", "This machine was changed or taken off the wall. Open it again.")  # (the tile edited meanwhile)
        device.looked.set_result(None)
        await joining
        assert line.source is None and all(not source.viewers for source in machine.sources.values()), "a line told goodbye was made a viewer of the picture"
        assert machine.watching is None

    played(scene)()


class Socket:
    """A web server's WebSocket as a line sees it: the first message is the hello, and nothing comes after it."""

    def __init__(self, hello: dict[str, Any]) -> None:
        self.came = [{"type": "websocket.receive", "text": json.dumps(hello)}]
        self.sent: list[str] = []
        self.client_state = WebSocketState.CONNECTED

    async def accept(self) -> None:
        pass

    async def receive(self) -> dict[str, Any]:
        if self.came:
            return self.came.pop(0)
        await asyncio.Event().wait()
        raise AssertionError

    async def send_text(self, text: str) -> None:
        self.sent.append(text)

    async def send_bytes(self, data: bytes) -> None:
        pass

    async def close(self, code: int = 1000) -> None:
        self.client_state = WebSocketState.DISCONNECTED


def test_a_line_stopped_while_the_machine_is_first_looked_at_leaves_the_machine() -> None:
    async def scene() -> None:
        device = Screen()
        lines = lines_to(device)
        ticket = lines.issue("d1", live.Holder("u", "u", True, "127.0.0.1", "s"))
        socket = Socket({"t": "hello", "v": live.FORM, "ticket": ticket, "video": ["jpeg"]})
        serving = asyncio.create_task(lines.serve(socket, "d1", "127.0.0.1"))  # type: ignore[arg-type]
        await asyncio.sleep(0.05)  # (the machine is being looked at for the first time)
        assert "d1" in lines.machines
        serving.cancel()  # the web server is stopping
        with contextlib.suppress(asyncio.CancelledError):
            await serving
        assert "d1" not in lines.machines, "the machine kept a line that was gone, and with it whatever it held"

    played(scene)()


def test_a_line_whose_standing_cannot_be_found_out_ends_and_the_others_are_still_looked_at(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(live, "STATE_EVERY", 0.02)
    monkeypatch.setattr(live, "STANDING_EVERY", 0.02)

    async def scene() -> None:
        signed_out: set[str] = set()

        def standing(holder: live.Holder, device_id: str) -> tuple[str | None, bool]:
            if holder.name == "broken":
                raise RuntimeError("a bug in the accounts")
            return ("signed_out", False) if holder.name in signed_out else (None, True)

        device = Screen()
        device.looked.set_result(None)
        lines = lines_to(device, standing)
        machine = lines.machines["d1"] = live.Machine(lines, "d1", device)  # type: ignore[arg-type]
        broken, olga = (live.Line(SimpleNamespace(), live.Holder(name, name, True, "127.0.0.1", "s"), machine, frozenset({"jpeg"}), 640, 5.0) for name in ("broken", "olga"))  # type: ignore[arg-type]
        await machine.join(broken)
        await machine.join(olga)
        await asyncio.sleep(0.2)  # (the look has asked of both lines, a few times)
        signed_out.add("olga")  # she is signed out: her line ends, whatever the look found of the other line before
        deadline = time.monotonic() + 2
        while olga.leaving is None:
            assert time.monotonic() < deadline, "after one look that failed, nobody was looked at again: a line signed out stays"
            await asyncio.sleep(0.02)
        assert olga.leaving == "signed_out"
        assert broken.leaving == "internal", "a line whose right to be there could not be found out was kept"
        assert device.said, "nothing was said of the bug"

    played(scene)()


# --- keyboard and mouse handed over: taken over by an admin, given back after no input, given back and taken again ------
# The rows of a hand-over: whatever the line before had down is let go of before the next holder's first word reaches the
# machine, and nothing of the line before lands after that, not even a word that was still on its way.


def told(line: live.Line) -> list[dict[str, Any]]:
    """What a line was told, in order."""
    return [json.loads(word) for word in line.words]


def test_a_key_held_by_the_holder_before_is_let_go_of_before_the_next_holders_first_key() -> None:
    # A gives keyboard and mouse back with Ctrl down, on a machine slow to take the letting go; B takes them at once and
    # types c. Sent as it came, B's c reached the machine before A's Ctrl went up: Ctrl+C on whatever was in front.
    async def scene() -> None:
        s = Scene()
        await s.take(s.a)
        way_a = s.ways[0]
        await s.machine.input(s.a, {"t": "k", "u": 0xE0, "d": True})
        way_a.slow_up = 0.3
        assert await s.machine.control(s.a, False) == {"t": "control", "on": False}
        await s.take(s.b)
        await s.machine.input(s.b, {"t": "k", "u": 0x06, "d": True})
        await s.machine.input(s.b, {"t": "k", "u": 0x06, "d": False})
        await s.settled()
        up, c = s.said.index(("way A", "key", 0xE0, False)), s.said.index(("way B", "key", 0x06, True))
        assert up < c, f"B's key reached the machine while A's Ctrl was still down: {s.said}"
        assert held_down(s.said) == (set(), set()), s.said

    played(scene)()


def test_an_admin_takes_over_the_holder_is_told_who_and_what_they_had_down_is_let_go_of_first() -> None:
    async def scene() -> None:
        s = Scene()
        s.lines.admins.add("B")
        await s.take(s.a)
        way_a, way_b = s.ways
        await s.machine.input(s.a, {"t": "k", "u": 0xE0, "d": True})  # A holds Ctrl down
        await s.machine.input(s.a, {"t": "mb", "b": 1, "d": True})  # and the left button
        way_a.slow_up = way_a.slow_button_up = 0.2  # (a machine slow to take the letting go)
        assert await s.machine.control(s.b, True) == live.refused("taken", "Somebody else has this machine's keyboard and mouse", by="A", reference=s.machine.control_reference)
        assert await s.machine.control(s.b, True, take=True, taking_from="A") == {"t": "control", "on": True}
        assert s.machine.holder is s.b and s.machine.hid is way_b and not s.a.control and s.b.control
        assert told(s.a)[-1] == {"t": "control", "on": False, "code": "taken", "message": "B took over this machine's keyboard and mouse", "by": "B", "from": s.machine.control_reference}
        await s.machine.input(s.b, {"t": "k", "u": 0x06, "d": True})  # B's first key, at once
        await s.machine.input(s.a, {"t": "k", "u": 0x04, "d": True})  # A's, after: from a line that holds nothing, nothing
        await s.machine.input(s.a, {"t": "up"})
        await s.machine.input(s.b, {"t": "k", "u": 0x06, "d": False})
        await s.settled()
        first_of_b = s.said.index(("way B", "key", 0x06, True))
        assert [word for word in s.said[first_of_b:] if word[0] == "way A"] == [], f"something of A's reached the machine after B's first key: {s.said}"
        assert ("way A", "key", 0xE0, False) in s.said[:first_of_b] and ("way A", "button", 1, False) in s.said[:first_of_b], s.said
        assert ("way A", "key", 0x04, True) not in s.said
        assert held_down(s.said) == (set(), set()), s.said
        assert way_a.closed, s.said
        assert not way_b.closed, s.said
        assert s.lines.audited[-2:] == [
            {"user": "A", "device": "PC", "device_id": "d1", "on": False, "why": "taken", "by": "B"},
            {"user": "B", "device": "PC", "device_id": "d1", "on": True, "from": "A"},
        ], s.lines.audited

    played(scene)()


def test_a_key_of_the_holders_still_on_its_way_at_a_take_over_lands_and_is_let_go_of_before_the_admins_first_word() -> None:
    # A PC between two AMT sessions: A's Shift waits for the next session when an admin takes over. The admin's first key
    # waits until A's Shift has landed and been let go of again; sent at once, it landed first, and was typed with Shift.
    async def scene() -> None:
        s = Scene()
        s.lines.admins.add("B")
        await s.take(s.a)
        way_a = s.ways[0]
        way_a.hold("key")
        typing = asyncio.create_task(s.machine.input(s.a, {"t": "k", "u": 0xE1, "d": True}))
        await asyncio.sleep(0.01)
        assert (await s.machine.control(s.b, True))["code"] == "taken"  # observe the holder before confirmation
        assert await s.machine.control(s.b, True, take=True, taking_from="A") == {"t": "control", "on": True}
        admins = asyncio.create_task(s.machine.input(s.b, {"t": "k", "u": 0x04, "d": True}))
        await asyncio.sleep(0.1)
        assert ("way B", "key", 0x04, True) not in s.said, f"the admin's key went while A's Shift was still on its way: {s.said}"
        way_a.through("key")  # A's Shift lands
        await typing
        await admins
        await s.machine.input(s.b, {"t": "k", "u": 0x04, "d": False})
        await s.settled()
        landed = s.said.index(("way A", "key", 0xE1, True))
        assert ("way A", "key", 0xE1, False) in s.said[landed:], f"A's Shift stayed down: {s.said}"
        up = s.said.index(("way A", "key", 0xE1, False), landed)
        assert up < s.said.index(("way B", "key", 0x04, True)), s.said
        assert held_down(s.said) == (set(), set()), s.said

    played(scene)()


def test_only_an_admin_takes_over_and_only_from_whom_they_were_asked_about() -> None:
    async def scene() -> None:
        s = Scene()
        await s.take(s.a)
        await s.machine.input(s.a, {"t": "k", "u": 0xE0, "d": True})
        # An operator (B, no admin) asks to take over: refused, and told who holds them.
        no = await s.machine.control(s.b, True, take=True)
        assert no["on"] is False and no["code"] == "taken" and no["by"] == "A" and "only an admin" in no["message"], no
        s.lines.admins.add("B")
        # The admin was asked about Z, who no longer holds them; "" is nobody; and a take-over that says from nobody (no
        # `from`, or one of another kind than a text: Lines._listen) takes nothing.
        for named in ("Z", "", None):
            no = await s.machine.control(s.b, True, take=True, taking_from=named)
            assert no["on"] is False and no["code"] == "taken" and no["by"] == "A", no
        assert "says whom" in no["message"], no
        # Asking without "take" is asking, as ever.
        assert (await s.machine.control(s.b, True))["code"] == "taken"
        assert s.machine.holder is s.a and s.a.control and told(s.a) == [], "the holder lost or was told something by a take-over that was refused"
        assert len(s.lines.audited) == 1
        # A line that may only look takes nothing over, admin or not.
        c = s.line("C")
        c.may_control = False
        s.lines.admins.add("C")
        assert (await s.machine.control(c, True, take=True))["code"] == "not_allowed"
        assert s.machine.holder is s.a
        # A take-over where nobody holds them is an asking: given, from nobody.
        assert await s.machine.control(s.a, False) == {"t": "control", "on": False}
        assert await s.machine.control(s.b, True, take=True, taking_from="A") == {"t": "control", "on": True}
        assert s.lines.audited[-1] == {"user": "B", "device": "PC", "device_id": "d1", "on": True}

    played(scene)()


def test_a_take_over_answered_after_the_way_in_was_made_asks_again_who_holds_them() -> None:
    # Making the admin's way in takes its time; meanwhile A gives them back and C takes them. The admin was asked about A.
    async def scene() -> None:
        s = Scene()
        s.lines.admins.add("B")
        way_a, way_b, way_c = Way("way A", s.said), Way("way B", s.said), Way("way C", s.said)
        handed = iter([way_a, way_b, way_c])  # (in the order they are asked for: A's, B's, C's)

        def way() -> live.Hid:
            made = next(handed)
            made.owe = s.lines.tasks.add
            return made

        s.machine._hid = way  # type: ignore[method-assign]
        await s.take(s.a)
        c = s.line("C")
        way_b.opening = asyncio.get_running_loop().create_future()
        assert (await s.machine.control(s.b, True))["code"] == "taken"  # observe the holder before confirmation
        asking = asyncio.create_task(s.machine.control(s.b, True, take=True, taking_from="A"))
        await asyncio.sleep(0.01)
        assert await s.machine.control(s.a, False) == {"t": "control", "on": False}
        assert await s.machine.control(c, True) == {"t": "control", "on": True}
        way_b.opening.set_result(None)
        answer = await asking
        assert answer["on"] is False and answer["code"] == "taken" and answer["by"] == "C", answer
        assert s.machine.holder is c and s.machine.hid is way_c and told(c) == []
        await s.settled()
        assert way_b.closed and not way_c.closed

    played(scene)()


def test_keyboard_and_mouse_are_given_back_after_the_time_without_input_and_what_was_held_is_let_go_of(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(live, "IDLE_GIVE_BACK", 0.3)

    async def scene() -> None:
        s = Scene()
        await s.take(s.a)
        for _ in range(4):  # input keeps them: a move of the pointer now and then
            await asyncio.sleep(0.15)
            await s.machine.input(s.a, {"t": "mr", "dx": 1, "dy": 0})
            s.machine._idle()
            assert s.machine.holder is s.a, "given back while the holder was moving the pointer"
        # Letting go of everything is no input: the last input was the key.
        await s.machine.input(s.a, {"t": "k", "u": 0xE1, "d": True})
        await asyncio.sleep(0.2)
        await s.machine.input(s.a, {"t": "up"})
        await asyncio.sleep(0.15)
        s.machine._idle()
        assert s.machine.holder is None and not s.a.control, "an `up` kept keyboard and mouse held"
        assert told(s.a)[-1] == {"t": "control", "on": False, "code": "idle", "message": "Given back after 1 second without input"}
        # Taken again, the clock begins anew; and a key held when they are given back is let go of.
        await s.take(s.a)
        s.machine._idle()
        assert s.machine.holder is s.a
        await s.machine.input(s.a, {"t": "k", "u": 0xE0, "d": True})  # Ctrl, and the holder walks away
        await asyncio.sleep(0.35)
        s.machine._idle()
        assert s.machine.holder is None and not s.a.control
        assert s.a in s.machine.viewers and s.a.leaving is None, "the line was ended: it is to go on showing the machine"
        await s.settled()
        assert ("way B", "key", 0xE0, False) in s.said and held_down(s.said) == (set(), set()), f"a key stayed down after the give-back: {s.said}"
        assert [(entry["on"], entry.get("why")) for entry in s.lines.audited] == [(True, None), (False, "idle"), (True, None), (False, "idle")]
        assert all("minutes" in entry for entry in s.lines.audited if entry.get("why") == "idle")

    played(scene)()


def test_a_check_of_the_account_that_fails_during_a_take_over_ends_the_line_and_closes_its_way_in() -> None:
    # Asked before the way in is made, and again after: where the second asking raises (a bug in the accounts), the way in
    # made for it was left open (a kvmd KVM's line for events), and the line ended with no goodbye.
    async def scene() -> None:
        s = Scene()
        await s.take(s.a)
        way_b = s.ways[1]
        asked: list[int] = []

        def may_take(holder: live.Holder, device_id: str) -> bool:
            asked.append(1)
            if len(asked) > 1:
                raise RuntimeError("a bug in the accounts")
            return True

        s.lines.may_take = may_take  # type: ignore[method-assign]
        s.machine.device._unexpected = lambda what, error: None  # type: ignore[attr-defined]
        assert (await s.machine.control(s.b, True))["code"] == "taken"  # observe the holder before confirmation
        answer = await s.machine.control(s.b, True, take=True, taking_from="A")
        assert answer["on"] is False and answer["code"] == "taken", answer
        assert s.b.leaving == "internal", "a line whose right to take over could not be found out went on"
        assert s.machine.holder is s.a and s.a.control and told(s.a) == []
        await s.settled()
        assert way_b.closed, "the way in made for the take-over was left open"

    played(scene)()


def test_a_wait_for_the_holder_before_that_runs_out_gives_up_on_that_one_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    # B's first word waits for A's Ctrl, still on its way, and gives up after HAND_OVER_WITHIN. Meanwhile C took over from B,
    # whose letting go is not through yet: C's first word waits for that, though B's own wait ran out.
    monkeypatch.setattr(live, "HAND_OVER_WITHIN", 0.3)

    async def scene() -> None:
        s = Scene()
        s.lines.admins.update({"B", "C"})
        way_a, way_b, way_c = Way("way A", s.said), Way("way B", s.said), Way("way C", s.said)
        handed = iter([way_a, way_b, way_c])

        def way() -> live.Hid:
            made = next(handed)
            made.owe = s.lines.tasks.add
            return made

        s.machine._hid = way  # type: ignore[method-assign]
        c = s.line("C")
        await s.take(s.a)
        way_a.hold("key")
        typing = asyncio.create_task(s.machine.input(s.a, {"t": "k", "u": 0xE0, "d": True}))
        await asyncio.sleep(0.01)
        assert (await s.machine.control(s.b, True))["code"] == "taken"  # observe the holder before confirmation
        assert await s.machine.control(s.b, True, take=True, taking_from="A") == {"t": "control", "on": True}
        waiting = asyncio.create_task(s.machine.input(s.b, {"t": "k", "u": 0x04, "d": True}))
        await asyncio.sleep(0.1)
        way_b.closing = asyncio.get_running_loop().create_future()  # (B's way in is slow to close)
        assert (await s.machine.control(c, True))["code"] == "taken"
        assert await s.machine.control(c, True, take=True, taking_from="B") == {"t": "control", "on": True}
        await waiting  # B's wait ran out, and B holds nothing by now: nothing of B's goes
        assert ("way B", "key", 0x04, True) not in s.said
        await asyncio.sleep(0.1)
        cs = asyncio.create_task(s.machine.input(c, {"t": "k", "u": 0x05, "d": True}))
        await asyncio.sleep(0.1)
        assert ("way C", "key", 0x05, True) not in s.said, f"C's first word did not wait for B's letting go: {s.said}"
        way_b.closing.set_result(None)
        await cs
        assert s.said.index(("way B", "closed")) < s.said.index(("way C", "key", 0x05, True)), s.said
        way_a.through("key")
        await typing
        await s.machine.input(c, {"t": "k", "u": 0x05, "d": False})
        await s.settled()
        assert held_down(s.said) == (set(), set()), s.said

    played(scene)()


def test_the_wall_waits_for_the_last_holders_letting_go_before_an_action_and_cancels_none_of_it() -> None:
    # An action from the page right after keyboard and mouse were given back: it waits as the next holder would.
    async def scene() -> None:
        s = Scene()
        await s.take(s.a)
        way_a = s.ways[0]
        await s.machine.input(s.a, {"t": "k", "u": 0xE0, "d": True})
        way_a.slow_up = 0.3
        assert await s.machine.control(s.a, False) == {"t": "control", "on": False}
        lines = live.Lines(SimpleNamespace(devices={}), standing=lambda holder, device_id: (None, True), busy=lambda device_id: False, audit=lambda *given, **more: None)  # type: ignore[arg-type]
        lines.handing = s.lines.handing  # (the wall's: kept beside its machines)
        assert await lines.handed_over("d1") is True
        assert ("way A", "key", 0xE0, False) in s.said, f"the action went before the letting go: {s.said}"
        assert "d1" not in lines.handing and await lines.handed_over("d1") is False  # (through: nothing is kept, and nothing waited for)
        # Stopped while it waits, it cancels nothing of the letting go.
        await s.take(s.b)
        way_b = s.ways[1]
        await s.machine.input(s.b, {"t": "k", "u": 0xE1, "d": True})
        way_b.slow_up = 0.3
        assert await s.machine.control(s.b, False) == {"t": "control", "on": False}
        waiting = asyncio.create_task(lines.handed_over("d1"))
        await asyncio.sleep(0.05)
        waiting.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await waiting
        await s.settled()
        assert ("way B", "key", 0xE1, False) in s.said and way_b.closed, s.said
        assert await lines.handed_over("unknown") is False  # (a machine with no line: nothing to wait for)

    played(scene)()


# --- what the wall waits for before a device's connection is closed ---------------------------------------------------


def a_wall_of_two() -> tuple[live.Lines, dict[str, Any]]:
    """The program's own Lines, with two machines on it, each with a line that holds its keyboard and mouse through a made-up way."""
    said: list[tuple[Any, ...]] = []
    devices = {name: SimpleNamespace(kind="kvmd", spec=SimpleNamespace(name=name, id=name), label=name) for name in ("x", "y")}
    lines = live.Lines(SimpleNamespace(devices=dict(devices)), standing=lambda holder, device_id: (None, True), busy=lambda device_id: False, audit=lambda *given, **more: None)  # type: ignore[arg-type]
    held: dict[str, Any] = {"said": said}
    for name, device in devices.items():
        machine = lines.machines[name] = live.Machine(lines, name, device)  # type: ignore[arg-type]
        way = Way(f"way {name}", said)
        machine._hid = lambda way=way: way  # type: ignore[method-assign]
        line = live.Line(SimpleNamespace(), live.Holder(name, name, True, "127.0.0.1", "s"), machine, frozenset({"jpeg"}), 640, 30.0)  # type: ignore[arg-type]
        machine.viewers.add(line)
        held[name] = (machine, line, way)
    return lines, held


def test_a_tile_edited_waits_for_its_own_machine_and_for_no_other() -> None:
    async def scene() -> None:
        lines, held = a_wall_of_two()
        for name in ("x", "y"):
            machine, line, _ = held[name]
            await machine.control(line, True)
            await machine.input(line, {"t": "k", "u": 0x04, "d": True})
        held["x"][2].slow_up = 3.0  # machine x takes three seconds to take its key let go of
        held["x"][0]._let_go(held["x"][1], None, None)
        await asyncio.sleep(0.05)
        began = time.monotonic()
        await lines.retiring(held["y"][0].device)  # machine y is edited: its own letting go is waited for, and only that
        assert time.monotonic() - began < 1.0, f"the edit of one tile waited {time.monotonic() - began:.1f} s for another machine's keys"
        assert ("way y", "key", 0x04, False) in held["said"]
        await lines.close()

    played(scene)()


def test_what_the_last_holders_left_to_be_let_go_of_is_forgotten_with_a_tile_taken_off_and_kept_for_one_edited() -> None:
    async def scene() -> None:
        lines, held = a_wall_of_two()
        typing = []
        for name in ("x", "y"):
            machine, line, way = held[name]
            await machine.control(line, True)
            way.hold("key")
            typing.append(asyncio.create_task(machine.input(line, {"t": "k", "u": 0x04, "d": True})))  # (a key still on its way)
            await asyncio.sleep(0.01)
            machine._let_go(line, None, None)
            await asyncio.sleep(0.01)
        assert set(lines.handing) == {"x", "y"}
        del lines.manager.devices["x"]  # x taken off the wall; y edited: a new connection under the same id
        await lines.retiring(held["x"][0].device)
        await lines.retiring(held["y"][0].device)
        assert "x" not in lines.handing, "what a tile taken off the wall left behind is kept for ever"
        assert [way.name for way in lines.handing["y"]] == ["way y"]
        for name in ("x", "y"):
            held[name][2].through("key", "fails")
        await asyncio.gather(*typing)

    played(scene)()


def test_a_client_whose_retirement_is_cut_off_while_its_lines_are_let_go_of_is_closed_all_the_same(tmp_path: Any) -> None:
    # The wall locking itself as the program stops, or a request cut off: the retirement waited for a letting go (seconds,
    # on a slow device) and was cancelled there, and the client was never closed: its session on the device kept. Closed
    # by what is left of the retirement, it is closed once, and after the letting go: Ctrl is not left down.
    from qkvm.core import Core, DeviceManager

    async def scene() -> None:
        core = Core(tmp_path / "data")

        async def save() -> None:
            pass

        manager = DeviceManager(core, save)
        lines = live.Lines(manager, standing=lambda holder, device_id: (None, True), busy=lambda device_id: False, audit=lambda *given, **more: None)
        manager.retiring = lines.retiring
        said: list[tuple[Any, ...]] = []

        class Client:
            kind = "kvmd"
            spec = SimpleNamespace(id="ab12", name="KVM")
            label = "KVM"

            async def close(self) -> None:
                said.append(("client", "closed"))

        client = Client()
        manager.devices["ab12"] = client  # type: ignore[assignment]
        machine = lines.machines["ab12"] = live.Machine(lines, "ab12", client)  # type: ignore[arg-type]
        way = Way("way", said)
        way.owe = machine._owe
        machine._hid = lambda: way  # type: ignore[method-assign]
        line = live.Line(SimpleNamespace(), live.Holder("olga", "olga", True, "127.0.0.1", "s"), machine, frozenset({"jpeg"}), 640, 30.0)  # type: ignore[arg-type]
        machine.viewers.add(line)
        assert await machine.control(line, True) == {"t": "control", "on": True}
        await machine.input(line, {"t": "k", "u": 0xE0, "d": True})
        way.slow_up = 0.6  # (a device slow to take the letting go)
        removing = asyncio.create_task(manager.remove("ab12"))
        await asyncio.sleep(0.2)
        removing.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await removing
        await manager.close()  # (as the program's end does: waits for what is left of a retirement)
        assert said.count(("client", "closed")) == 1, f"a client whose retirement was cut off was not closed, or closed twice: {said}"
        let_go = said.index(("way", "key", 0xE0, False)) if ("way", "key", 0xE0, False) in said else len(said)
        assert let_go < said.index(("client", "closed")), f"the client was closed before Ctrl was let go of: {said}"
        assert "ab12" not in lines.handing

    played(scene)()


def test_a_tile_edited_waits_for_a_letting_go_for_as_long_as_one_is_given() -> None:
    # A letting go is given LET_GO_WITHIN (four seconds) by the device; the edit closed the device's connection after three,
    # under a key up that was still on its way.
    async def scene() -> None:
        lines, held = a_wall_of_two()
        machine, line, way = held["y"]
        await machine.control(line, True)
        await machine.input(line, {"t": "k", "u": 0xE0, "d": True})
        way.slow_up = live.SAY_WITHIN * 2 - 0.5
        await lines.retiring(machine.device)
        assert ("way y", "key", 0xE0, False) in held["said"], "the device was closed with Ctrl's letting go still on its way"

    played(scene)()


# --- the same on a PC with Intel AMT, through its own engine (the stand-in's) ------------------------------------------


@pytest.fixture
def pc() -> Iterator[FakeAmt]:
    machine = FakeAmt().start()
    yield machine
    machine.stop()


def test_a_pcs_key_that_waited_for_the_next_session_is_not_sent_once_the_line_lost_the_keyboard(pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    # The engine ends its session at its own time; Ctrl waits for the next one, which takes its time to open; the line loses
    # keyboard and mouse meanwhile, and everything it had down is let go of into no session. (It was decided here that
    # Ctrl then lands, and is let go of after it. The review of 850745e, L-W2: a key that waited goes into the machine
    # of somebody who may no longer act on it. It is asked again once the session is there, and goes nowhere.)
    pc.state.session_timeout, pc.state.session_lasts = 1, 1.5
    monkeypatch.setattr(amt, "TIMEOUT_SLACK", 59.0)
    screen = pc.state.screen

    async def run() -> None:
        device = AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=pc.url, username="admin", password="secret", kind="amt"))
        lines = Owed()
        machine = live.Machine(lines, "ab12", device)  # type: ignore[arg-type]
        line = live.Line(SimpleNamespace(), live.Holder("olga", "olga", True, "127.0.0.1", "s-olga"), machine, frozenset({"jpeg"}), 640, 30.0)  # type: ignore[arg-type]
        machine.viewers.add(line)
        try:
            await device.status()
            assert await machine.control(line, True) == {"t": "control", "on": True}
            await machine.input(line, {"t": "k", "u": 0x04, "d": True})
            await machine.input(line, {"t": "k", "u": 0x04, "d": False})
            deadline = time.monotonic() + 5
            while device._screen._connected_or_none() is not None:
                assert time.monotonic() < deadline, "the session never ended at its time"
                await asyncio.sleep(0.02)
            pc.state.challenge_takes = 1.5  # (the next session is slow to open)
            pressing = asyncio.create_task(machine.input(line, {"t": "k", "u": 0xE0, "d": True}))  # ControlLeft
            await asyncio.sleep(0.5)
            assert not pressing.done(), "Ctrl did not wait for the next session"
            machine._let_go(line, "not_allowed", "Your account may no longer act on this machine")  # (as the look every few seconds does)
            await asyncio.sleep(0.1)
            await pressing  # the next session opened, and Ctrl was not sent into it
            await lines.settled()
            await asyncio.sleep(0.5)  # (time for anything late to arrive)
        finally:
            await device.close()

    asyncio.run(run())
    assert (0x61, True) in screen.keys, f"the key before the wait never arrived: {screen.keys}"
    assert (0xFFE3, True) not in screen.keys, f"Ctrl went to the PC after the line lost the keyboard: {screen.keys}"
