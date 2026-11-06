"""A JetKVM spoken to over its binary hidrpc channel, as its own page speaks it (track W14d).

What the JetKVM does there (its source at release 0.5.9, and the real one on 2026-10-18): it answers a handshake; it
does the keyboard's messages in order, and the mouse's in order, each kind in a task of its own; a key pressed by a
keypress message it lets go of 100 ms later unless kept alive every 50 ms, a modifier never; it says every change of
the keyboard back; nothing else is answered. At a hand-over and as the viewer's connection closes it lets go of the
keyboard, never of a mouse button (the real one kept the left button down across both). The stand-in does the same.

The table of situations, with its timing, is in the hand-back (roadmap/handbacks/w14d-jetkvm-hidrpc.md):

| Row | Situation | What qKVM does | Test |
|---|---|---|---|
| A1 | the JetKVM answers the handshake | keys and the mouse on hidrpc; the wheel on JSON-RPC | a1 |
| A2 | no answer (an older firmware) | JSON-RPC for the connection, once it has asked long enough | a2 |
| A3 | another version | JSON-RPC | a3 |
| A4 | an answer after the wall's two seconds (a busy wall, a JetKVM still setting the channel up) | JSON-RPC until it comes; asked again once a second for ten; hidrpc from the first moment nothing of ours is down or on its way | a4 |
| A5 | that answer while a key is held, or an action types, over JSON-RPC | JSON-RPC until the key is let go of, the action done | a5 |
| A6 | the wall asking again as the JetKVM's own page takes the viewer | no handshake after the wall heard of it | a6 |
| A7 | an action that waits for its turn to type as the road changes | it types over the road it finds once its turn came | a7 |
| A8 | a report over JSON-RPC whose answer comes after its wait (a letting go) | JSON-RPC until the answer comes | a8 |
| A9 | a letting go sent without waiting for its answer (a button at a hand-over or an end; a key) | JSON-RPC until the answer comes | a9 |
| B1 | a key held over the live line | a keypress message, kept alive every 30 ms (its page: 50); let go of by one message | b1 |
| C1 | the line loses control with keys and a button down | the keyboard and the buttons let go of at once, the keep-alive stops | c1 |
| D1 | the wall ends the connection itself (the tile closed, made anew) with something down | let go of first, both roads | d1 |
| D2 | the wall vanishes | the JetKVM lets go of a key that is no modifier within 0.1 s (not of a modifier, not of a button) | d2 |
| D3 | the JetKVM ends the connection with a button down | the next connection begins with "nothing down", both roads | d3 |
| D4 | the hidrpc channel closes | the connection is ended and made anew | d4 |
| D5 | the wall ended a connection with a key that may be down (not answered) | the next begins with "nothing down", both roads | d5 |
| E1 | a hand-over with a key held | one keyboard letting go, no keep-alive after | e1 |
| E2 | a hand-over with a press on its way (done after it) | the letting go is done after the press | e2 |
| E3 | a hand-over with a mouse button held | one letting go of the buttons, both roads | e3 |
| E4 | a hand-over with nothing down | nothing | e4 |
| E5 | a hand-over while an action types | 409, or done, or 504 "may have been done"; only the letting go after it | e5 |
| F1 | an action types | a whole report a key, each once the JetKVM said it has the one before | f1 |
| F2 | a typed key the JetKVM never says it has | 504, let go of in turn, the connection made anew | f2 |
| G | the wall stops while a line holds a key and a button | let go of | g |
| H | nobody watches | let go of first; the connection is given back after 300 s | unwatched |
| (review) | a drag begun on one mouse and ended on the other; a connection ending while what is owed is said; a handshake after a hand-over; a keyboard said over JSON-RPC; a layout or road not found out | | r1 to r5 |
| (review 2) | a connection ending while an action types; a hand-over while the layout is asked; the hidrpc channel closing with a button down; the keys said in another order; the road never chosen; a layout never chosen | | r6 to r11 |
| (review 3) | an action's key down as its connection is marked to end; a live line's key then; the hidrpc channel shut under a modifier; a press or a release that could not go; a letting go after the end has looked | | r12 to r16 |
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import struct
import time
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from qkvm import jetkvm, kvm, live, update, vault
from tests.fake_jetkvm import FakeJetKvm, JetState, no_long_handshake
from tests.test_live import Wall
from tests.test_wall import wait_until

PRESS_A = {"modifier": 0, "keys": [0x04]}
SHIFT = {"modifier": 0x02, "keys": []}
NOTHING = {"modifier": 0, "keys": []}
# (A line is held by a `Viewer` for as long as a test wants it, not in a `with`: as in test_live.py.)
pytestmark = pytest.mark.filterwarnings(r"ignore:connect\(\) must be used as a context manager:DeprecationWarning")


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")
    monkeypatch.setattr(live, "STANDING_EVERY", 0.2)
    # (Where the stand-in plays an older JetKVM, without hidrpc, the wall gives up asking sooner: in the tests that run on
    # both roads and say so; a2 sets it itself. Where it speaks hidrpc, as in most of these, the wall's own two seconds.)
    callspec = getattr(request.node, "callspec", None)
    no_long_handshake(monkeypatch, callspec.params.get("hidrpc", True) if callspec is not None else True)


def the_wall(jet: FakeJetKvm) -> jetkvm.JetKvmDevice:
    return jetkvm.JetKvmDevice(kvm.DeviceSpec("w", "the wall", jet.url, "", "secret", kind="jetkvm"))


async def settled(happened: Callable[[], bool], within: float = 3.0) -> None:
    """Wait until something has happened at the stand-in; and then a moment more, for anything that would follow it."""
    give_up = time.monotonic() + within
    while not happened() and time.monotonic() < give_up:
        await asyncio.sleep(0.02)
    await asyncio.sleep(0.4)


def nothing_down(jet: FakeJetKvm) -> bool:
    return jet.state.down == [] and jet.state.modifier == 0 and jet.state.buttons == 0


def run(jet: FakeJetKvm, test: Callable[[jetkvm.JetKvmDevice], Any]) -> None:
    async def inside() -> None:
        wall = the_wall(jet)
        try:
            await test(wall)
        finally:
            await wall.close()

    try:
        asyncio.run(inside())
    finally:
        jet.stop()


def place(x: int, y: int, buttons: int) -> bytes:
    return b"\x03" + struct.pack(">iiB", x, y, buttons)


def keys_after_hand_over(jet: FakeJetKvm) -> list[bytes]:
    """What the stand-in had done on hidrpc after the hand-over, the handshakes and keep-alives left out: one sent before
    the wall heard of the hand-over may arrive after it (none is sent after: r3), and neither presses anything."""
    return [message for message in jet.state.hid_after_hand_over if message[:1] not in (b"\x01", b"\x09")]


def said(jet: FakeJetKvm, since: int = 0) -> list[bytes]:
    """What the stand-in received on hidrpc from `since` on, the handshakes and keep-alives left out."""
    return [message for message in jet.state.hid_sent[since:] if message[:1] not in (b"\x01", b"\x09")]


ROADS = pytest.mark.parametrize("hidrpc", [True, False], ids=["hidrpc", "json-rpc"])
DEAF = 1e9  # (a stand-in that hears no handshake until a test sets its `hid_deaf_for` to nothing)


# --- A: which way keys go ---------------------------------------------------------------------------------------------


def test_a1_keys_and_the_mouse_go_over_hidrpc_where_the_jetkvm_answers_its_handshake() -> None:
    jet = FakeJetKvm(JetState(width=640, height=360)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session)
        # (Where a busy computer heard the answer after the wall's two seconds, the road is taken late: a4.)
        await settled(lambda: held.road == "hidrpc", within=15)
        assert held.road == "hidrpc"
        wall.say("keyboardReport", dict(PRESS_A), on=held)
        wall.say("keyboardReport", dict(NOTHING), on=held)
        wall.say("absMouseReport", {"x": 100, "y": 200, "buttons": 1}, on=held)
        wall.say("absMouseReport", {"x": 100, "y": 200, "buttons": 0}, on=held)
        wall.say("relMouseReport", {"dx": -3, "dy": 5, "buttons": 0}, on=held)
        wall.say("wheelReport", {"wheelY": 1, "wheelX": 0}, on=held)
        await settled(lambda: ("wheel", 0, 1) in jet.state.mouse)
        await wall.act("text", text="B")
        assert jet.state.hid_sent[0] == b"\x01\x01"  # (the handshake first)
        assert said(jet) == [
            b"\x05\x04\x01", b"\x02\x00",  # a key pressed by a keypress message; nothing down: a whole report
            place(100, 200, 1), place(100, 200, 0), b"\x06\xfd\x05\x00",
            b"\x02\x02\x05", b"\x02\x00",  # typed: a whole report a key (Shift and B), then nothing down
        ], said(jet)  # fmt: skip
        assert ("wheel", 0, 1) in jet.state.mouse  # (over JSON-RPC: it has no wheel on hidrpc)
        assert jet.state.reports == [(0, [0x04]), (0, []), (0x02, [0x05]), (0, [])]
        assert nothing_down(jet)

    run(jet, test)


def test_a2_a_jetkvm_without_hidrpc_gets_its_keys_over_json_rpc_once_the_wall_has_asked_long_enough(monkeypatch: pytest.MonkeyPatch) -> None:
    no_long_handshake(monkeypatch, False)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        await wall._connected(urgent=True)
        began = time.monotonic()
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session) and held.road == "rpc"
        assert time.monotonic() - began >= 0.3, "keys went before it was known which way"
        wall.say("keyboardReport", dict(PRESS_A), on=held)
        wall.say("keyboardReport", dict(NOTHING), on=held)
        await wall.act("text", text="b")
        assert jet.state.reports == [(0, [0x04]), (0, []), (0, [0x05]), (0, [])]
        assert jet.state.hid_sent == [] and jet.state.handshakes == 0  # (it did not listen there)

    run(jet, test)


def test_a3_a_jetkvm_that_answers_another_version_gets_its_keys_over_json_rpc() -> None:
    jet = FakeJetKvm(JetState(hid_version=2, width=640, height=360)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session) and held.road == "rpc"
        await wall.act("text", text="b")
        assert jet.state.reports == [(0, [0x05]), (0, [])]
        assert jet.state.handshakes >= 1 and said(jet) == []

    run(jet, test)


def test_a4_a_jetkvm_that_answers_the_handshake_late_gets_its_keys_over_hidrpc_from_then_on(caplog: pytest.LogCaptureFixture) -> None:
    # (A JetKVM with hidrpc kept JSON-RPC for the whole connection where its answer came after the wall's two seconds, and
    # the log said it did not speak hidrpc. A busy computer took up to 1.4 s to answer a stand-in.)
    caplog.set_level(logging.INFO, logger="qkvm")
    jet = FakeJetKvm(JetState(width=640, height=360, hid_deaf_for=DEAF)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session) and held.road == "rpc"
        jet.state.hid_deaf_for = 0.0  # (it hears the next question)
        wall.say("keyboardReport", dict(PRESS_A), on=held)
        wall.say("keyboardReport", dict(NOTHING), on=held)
        await settled(lambda: len(jet.state.reports) >= 2)
        assert said(jet) == [] and jet.state.handshakes_unheard >= 1  # (over JSON-RPC: no answer had come)
        give_up = time.monotonic() + 15
        while held.road != "hidrpc" and time.monotonic() < give_up:
            await asyncio.sleep(0.05)
        assert held.road == "hidrpc" and jet.state.handshakes >= 1, (held.road, jet.state.handshakes, jet.state.handshakes_unheard)
        wall.say("keyboardReport", dict(PRESS_A), on=held)
        wall.say("keyboardReport", dict(NOTHING), on=held)
        await settled(lambda: len(jet.state.reports) >= 4)
        assert said(jet) == [b"\x05\x04\x01", b"\x02\x00"], said(jet)
        assert jet.state.reports == [(0, [0x04]), (0, []), (0, [0x04]), (0, [])] and nothing_down(jet)
        words = [record.getMessage() for record in caplog.records]
        assert not any("does not speak hidrpc" in word for word in words), words
        assert any("did not answer" in word and "hidrpc" in word for word in words) and any("answered" in word and "late" in word for word in words), words

    run(jet, test)


@pytest.mark.parametrize("what", ["a key held", "a button held", "an action typing"])
def test_a5_the_road_changes_only_once_nothing_of_ours_is_down_or_on_its_way(what: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # (A key pressed over JSON-RPC and let go of over hidrpc could be done in the other order, the two in tasks of their own
    # on the JetKVM; and a modifier held across the change would be kept for good.)
    monkeypatch.setattr(jetkvm, "KEY_PAUSE", 0.4)
    jet = FakeJetKvm(JetState(width=640, height=360, hid_deaf_for=DEAF)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session) and held.road == "rpc"
        typing = None
        if what == "a key held":
            wall.say("keyboardReport", {"modifier": 0x01, "keys": []}, on=held)  # (Ctrl)
        elif what == "a button held":
            wall.say("absMouseReport", {"x": 100, "y": 200, "buttons": 1}, on=held)
        else:
            typing = asyncio.ensure_future(wall.act("text", text="abcdefghijklm"))  # (some ten seconds)
            while not wall._typing.locked():
                await asyncio.sleep(0.01)
        jet.state.hid_deaf_for = 0.0  # (it hears the next question, with that under way)
        give_up = time.monotonic() + 15
        while jet.state.handshakes == 0 and time.monotonic() < give_up:
            await asyncio.sleep(0.05)
        assert jet.state.handshakes >= 1, "the wall did not ask again"
        await asyncio.sleep(1.0)
        assert held.road == "rpc", f"the road changed with {what}"
        if what == "a key held":
            wall.say("keyboardReport", dict(NOTHING), on=held)
        elif what == "a button held":
            wall.say("absMouseReport", {"x": 100, "y": 200, "buttons": 0}, on=held)
        elif typing is not None:
            await typing
            # (The whole text over JSON-RPC. The road itself may have changed by the time this looks, the action's end and
            # the next look of the wall's in one turn of a busy loop.)
            assert said(jet) == [], said(jet)
        give_up = time.monotonic() + 10
        while held.road != "hidrpc" and time.monotonic() < give_up:
            await asyncio.sleep(0.05)
        assert held.road == "hidrpc"
        assert said(jet) == [] and nothing_down(jet), (said(jet), jet.state.down, jet.state.modifier, jet.state.buttons)

    run(jet, test)


def test_a6_no_handshake_goes_after_a_hand_over_while_the_wall_asks_again(monkeypatch: pytest.MonkeyPatch) -> None:
    # (The first reviewer's x1: the JetKVM never hears the handshake, the wall asks again, and its own page takes the
    # viewer: nothing goes once the wall has heard of that. Asked ten times a second here, not once: once a second, a
    # question sent after the hand-over mostly fell after the wall had stepped aside, and nothing showed it.)
    monkeypatch.setattr(jetkvm, "HID_ASK_AGAIN_EVERY", 0.1)
    monkeypatch.setattr(jetkvm, "HID_ASKS_AGAIN", 1000)
    jet = FakeJetKvm(JetState(width=640, height=360, hid_deaf_for=DEAF, hand_over_close=3.5)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session) and held.road == "rpc"
        after: list[bytes] = []  # what the wall sent on hidrpc once it knew of the hand-over
        send = held.hid.send

        def sending(data: bytes) -> None:
            if held.taken:
                after.append(data)
            send(data)

        held.hid.send = sending
        before = jet.state.handshakes_unheard
        await settled(lambda: jet.state.handshakes_unheard > before, within=10)
        assert jet.state.handshakes_unheard > before, "the wall did not ask again"
        jet.hand_over()
        await settled(lambda: held.taken and held.done.is_set(), within=10)  # (heard of, and the wall stepped aside)
        assert after == [], after
        assert held.road == "rpc"

    run(jet, test)


def test_a7_an_action_that_waits_for_its_turn_types_over_the_road_it_finds_then(monkeypatch: pytest.MonkeyPatch) -> None:
    # (The first reviewer's x4: the first action types over JSON-RPC while the late answer comes, the second waits for its
    # turn. Between the first letting go of its turn and the second taking it nobody types, and the road may change: the
    # second reads it once its turn has come, and types over the road it finds.)
    monkeypatch.setattr(jetkvm, "KEY_PAUSE", 0.4)
    jet = FakeJetKvm(JetState(width=640, height=360, hid_deaf_for=DEAF)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session) and held.road == "rpc"
        monkeypatch.setattr(jetkvm, "HID_SHAKE_EVERY", 0)  # (`_late_road` looks at every turn of the loop)
        first = asyncio.ensure_future(wall.act("text", text="abcdefgh"))
        while not wall._typing.locked():
            await asyncio.sleep(0.01)
        jet.state.hid_deaf_for = 0.0
        second = asyncio.ensure_future(wall.act("text", text="xyz"))
        await asyncio.gather(first, second)
        await settled(lambda: held.road == "hidrpc")
        assert held.road == "hidrpc", held.road
        # x, y and z (0x1B, 0x1C, 0x1D) over hidrpc as whole reports, each let go of; a to h over JSON-RPC.
        assert said(jet) == [bytes([2, 0, 0x1B]), bytes([2, 0]), bytes([2, 0, 0x1C]), bytes([2, 0]), bytes([2, 0, 0x1D]), bytes([2, 0])], said(jet)
        assert [codes for _, codes in jet.state.typed] == [[0x04 + i] for i in range(8)] + [[0x1B], [0x1C], [0x1D]] and nothing_down(jet)

    run(jet, test)


def test_a8_a_report_whose_answer_comes_after_its_wait_keeps_the_road(monkeypatch: pytest.MonkeyPatch) -> None:
    # (The first reviewer's finding: an action's letting go over JSON-RPC whose wait ran out was tracked nowhere, the road
    # changed, a key pressed over hidrpc next could be done before it, and that late letting go let go of it.)
    monkeypatch.setattr(jetkvm, "HOLD", 0.05)
    held_back: list[tuple[Any, Any]] = []
    holding = [True]
    real_heard = jetkvm.JetKvmDevice._on_message

    def heard(self: Any, session: Any, message: Any) -> None:
        # (The answer to a keyboard report that lets go of everything is held back until the test gives it.)
        if holding[0] and isinstance(message, str) and '"result"' in message:
            number = json.loads(message).get("id")
            if number in lettings_go:
                held_back.append((session, message))
                return
        real_heard(self, session, message)

    lettings_go: set[int] = set()
    real_call = jetkvm.JetKvmDevice._call

    async def call(self: Any, session: Any, method: str, params: Any = None, within: Any = None) -> Any:
        if method == "keyboardReport" and params == NOTHING:
            lettings_go.add(session.next_id + 1)
            within = 0.3  # (its answer is held back: its wait runs out; the press before it is waited for as the wall waits)
        return await real_call(self, session, method, params, within)

    monkeypatch.setattr(jetkvm.JetKvmDevice, "_on_message", heard)
    monkeypatch.setattr(jetkvm.JetKvmDevice, "_call", call)
    jet = FakeJetKvm(JetState(width=640, height=360, hid_deaf_for=DEAF)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session) and held.road == "rpc"
        with pytest.raises(kvm.KvmError) as said_no:
            await wall.act("keys", keys="ControlLeft,KeyC")
        assert said_no.value.code == "timeout", said_no.value.message  # (its letting go not answered in time)
        await settled(lambda: bool(held_back) and nothing_down(jet), within=30)  # (the answer came, and is held back)
        assert held_back and held.live and nothing_down(jet)  # (the connection kept: the JetKVM did let go)
        jet.state.hid_deaf_for = 0.0
        await settled(lambda: jet.state.handshakes >= 1, within=30)
        assert jet.state.handshakes >= 1, "the wall did not ask again"
        await asyncio.sleep(1.0)
        assert held.road == "rpc", "the road changed with a letting go on its way"
        holding[0] = False
        for session, message in held_back:
            real_heard(wall, session, message)
        await settled(lambda: held.road == "hidrpc")
        assert held.road == "hidrpc"

    run(jet, test)


@pytest.mark.parametrize("how", ["a button, by _send_let_go", "a key, by _let_go"])
def test_a9_a_letting_go_not_waited_for_keeps_the_road_until_it_is_answered(monkeypatch: pytest.MonkeyPatch, how: str) -> None:
    # (The second reviewer's S5: the lettings go that `_let_go_of` and `_let_go` send without waiting were counted in
    # `unanswered` by no test.)
    numbers: set[int] = set()
    held_back: list[tuple[Any, Any]] = []
    holding = [True]
    real_heard = jetkvm.JetKvmDevice._on_message

    def heard(self: Any, session: Any, message: Any) -> None:
        if holding[0] and isinstance(message, str) and '"result"' in message and json.loads(message).get("id") in numbers:
            held_back.append((session, message))
            return
        real_heard(self, session, message)

    monkeypatch.setattr(jetkvm.JetKvmDevice, "_on_message", heard)
    jet = FakeJetKvm(JetState(width=640, height=360, hid_deaf_for=DEAF)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session) and held.road == "rpc"
        if how.startswith("a button"):
            wall.say("absMouseReport", {"x": 100, "y": 200, "buttons": 1}, on=held)
            await settled(lambda: jet.state.buttons == 1 and not held.unanswered, within=30)
            assert jet.state.buttons == 1 and not held.unanswered, "the button did not go down"
            numbers.add(held.next_id + 1)
            wall._send_let_go(held)
        else:
            wall.say("keyboardReport", dict(PRESS_A), on=held)
            await settled(lambda: jet.state.down == [0x04] and not held.unanswered, within=30)
            assert jet.state.down == [0x04] and not held.unanswered, "the key did not go down"
            numbers.add(held.next_id + 1)
            wall._let_go(held)
        await settled(lambda: bool(held_back), within=30)  # (the letting go's answer came, and is held back)
        assert held_back, "the letting go was not answered"
        jet.state.hid_deaf_for = 0.0
        await settled(lambda: jet.state.handshakes >= 1, within=30)
        assert jet.state.handshakes >= 1, "the wall did not ask again"
        await asyncio.sleep(1.0)
        assert held.road == "rpc", "the road changed with a letting go on its way"
        holding[0] = False
        for session, message in held_back:
            real_heard(wall, session, message)
        await settled(lambda: held.road == "hidrpc")
        assert held.road == "hidrpc" and nothing_down(jet)

    run(jet, test)


# --- B and C: the live line -------------------------------------------------------------------------------------------


def test_b1_a_key_held_over_the_live_line_is_kept_alive_and_let_go_of_by_one_message() -> None:
    jet = FakeJetKvm(JetState(width=640, height=360)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        wall.say("keyboardReport", dict(PRESS_A), on=held)
        await asyncio.sleep(1.0)
        assert jet.state.down == [0x04], f"the JetKVM let go of a key the line holds: {jet.state.auto_released}"
        assert jet.state.auto_released == [] and jet.state.keep_alives >= 10 and jet.state.keep_alives_refused == 0, (jet.state.keep_alives, jet.state.keep_alives_refused)
        wall.say("keyboardReport", dict(NOTHING), on=held)
        await settled(lambda: jet.state.down == [])
        kept = jet.state.keep_alives
        await asyncio.sleep(0.3)
        assert jet.state.keep_alives == kept, "keep-alives went on with nothing held"
        assert said(jet) == [b"\x05\x04\x01", b"\x02\x00"] and nothing_down(jet)

    run(jet, test)


def test_c1_a_line_that_loses_control_lets_go_of_its_keys_and_buttons_over_hidrpc(tmp_path: Path) -> None:
    jet = FakeJetKvm(JetState(width=640, height=360)).start()
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, jet.url)
            line = wall.line(admin, device, max_fps=5)
            assert line.picture(timeout=20).kind == 2
            line.say(t="control", on=True)
            assert line.word("control")["on"] is True
            line.say(t="k", u=0xE1, d=True)  # Shift
            line.say(t="k", u=0x04, d=True)
            line.say(t="m", x=1000, y=2000)
            line.say(t="mb", b=1, d=True)
            wait_until(lambda: jet.state.buttons == 1 and jet.state.down == [0x04] and jet.state.modifier == 0x02, f"not down: {jet.state.down} {jet.state.buttons}")
            time.sleep(0.5)
            assert jet.state.auto_released == []
            line.say(t="control", on=False)
            assert line.word("control") == {"t": "control", "on": False}
            wait_until(lambda: nothing_down(jet), f"down after the line gave the keyboard back: {jet.state.down} {jet.state.modifier} {jet.state.buttons}")
            kept = jet.state.keep_alives
            time.sleep(0.3)
            assert jet.state.keep_alives == kept, "keep-alives went on"
            assert jet.state.auto_released == []  # (let go of by the line, not by the JetKVM's own clock)
            line.close()
    finally:
        jet.stop()


# --- D: the connection ending -----------------------------------------------------------------------------------------


@ROADS
@pytest.mark.parametrize("how", ["the tile closed", "made anew"])
def test_d1_a_connection_the_wall_ends_lets_go_first_of_what_it_has_down(hidrpc: bool, how: str) -> None:
    # (A JetKVM lets go of the keyboard as a connection ends, and keeps a mouse button down: the real one did, on
    # 2026-10-18. On the program as it was, the button stayed down for whoever came next.)
    jet = FakeJetKvm(JetState(hidrpc=hidrpc, width=640, height=360)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session)
        wall.say("keyboardReport", {"modifier": 0x02, "keys": [0x04]}, on=held)
        wall.say("absMouseReport", {"x": 300, "y": 400, "buttons": 1}, on=held)
        await settled(lambda: jet.state.buttons == 1 and jet.state.down == [0x04])
        if how == "the tile closed":
            await wall.close()
        else:
            wall._make_anew(held, "a test made it anew")
            await settled(lambda: held.done.is_set())
        await settled(lambda: nothing_down(jet))
        assert nothing_down(jet), f"down after the wall ended the connection: {jet.state.down} {jet.state.modifier} {jet.state.buttons}"
        assert jet.state.mouse[-1] == ("abs", 300, 400, 0), jet.state.mouse  # (where it was pressed)

    run(jet, test)


@ROADS
def test_d1_a_connection_the_wall_makes_anew_lets_go_at_once_and_ends_at_once(hidrpc: bool) -> None:
    # (Register row 16, W14d's open point.) An end the wall decides (keys it was late with: the connection made anew) took effect
    # only at the next look of the connection's loop, up to a second later: a modifier or a button the live line held stayed
    # down on the computer until then. The letting go goes as the end is decided, and the connection ends at once.
    jet = FakeJetKvm(JetState(hidrpc=hidrpc, width=640, height=360)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session)
        wall.say("keyboardReport", {"modifier": 0x02, "keys": []}, on=held)
        wall.say("absMouseReport", {"x": 300, "y": 400, "buttons": 1}, on=held)
        await settled(lambda: jet.state.buttons == 1 and jet.state.modifier == 0x02)
        await asyncio.sleep(0.2)  # (into the loop's second-long wait)
        began = time.monotonic()
        wall._make_anew(held, "a test made it anew")
        # Let go of as the end is decided: what the wall says it has down is nothing, before anything else runs.
        assert held.abs_sent is not None and held.abs_sent[2] == 0, held.abs_sent
        if hidrpc:
            assert held.kb_sent == jetkvm.NOTHING_DOWN, held.kb_sent  # (over JSON-RPC the JetKVM lets go of the keyboard as it ends)
        while not held.done.is_set() and time.monotonic() - began < 5:
            await asyncio.sleep(0.01)
        ended = time.monotonic() - began
        # (Ended once the letting go has left, LET_GO_WAIT at the most, not at the loop's next look a second later.)
        assert held.done.is_set() and ended < jetkvm.LET_GO_WAIT + 0.4, ended
        await settled(lambda: nothing_down(jet))
        assert nothing_down(jet), f"down: {jet.state.down} {jet.state.modifier} {jet.state.buttons}"

    run(jet, test)


def test_d2_when_the_wall_vanishes_the_jetkvm_lets_go_of_a_held_key_within_a_tenth_of_a_second() -> None:
    # The wall's keep-alives stop as if it were killed, the connection staying open (a JetKVM notices a connection gone
    # only some seconds later). A key that is no modifier: let go of by the JetKVM ~0.1 s after the last keep-alive; a
    # modifier and a mouse button: not (they wait for the connection's end, and for the next viewer).
    jet = FakeJetKvm(JetState(width=640, height=360)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session)
        wall.say("keyboardReport", {"modifier": 0x02, "keys": [0x04]}, on=held)
        await asyncio.sleep(0.5)
        assert jet.state.down == [0x04]
        held.held.clear()  # (the wall is gone: nothing more of it goes, no keep-alive)
        if held.keeping is not None:
            held.keeping.cancel()
        gone = time.monotonic()
        while jet.state.down and time.monotonic() - gone < 2:
            await asyncio.sleep(0.01)
        took = time.monotonic() - gone
        assert jet.state.down == [] and jet.state.auto_released == [0x04], jet.state.down
        assert took < 0.4, f"let go of {took:.3f} s after the last keep-alive"
        assert jet.state.modifier == 0x02  # (a modifier it never lets go of that way)

    run(jet, test)


@ROADS
def test_d3_after_the_jetkvm_ended_a_connection_with_a_button_down_the_next_begins_with_nothing_down(hidrpc: bool) -> None:
    jet = FakeJetKvm(JetState(hidrpc=hidrpc, width=640, height=360)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session)
        wall.say("absMouseReport", {"x": 300, "y": 400, "buttons": 1}, on=held)
        await settled(lambda: jet.state.buttons == 1)
        jet.drop()  # (the JetKVM ends the connection: it lets go of the keyboard, not of the button)
        await settled(lambda: held.done.is_set(), within=10)
        assert held.done.is_set() and jet.state.buttons == 1
        sent, mouse = len(jet.state.hid_sent), len(jet.state.mouse)
        again = await wall.input_ready()  # (a new connection)
        assert again is not held
        await settled(lambda: jet.state.buttons == 0)
        assert jet.state.buttons == 0, "the button stayed down"
        assert jet.state.mouse[mouse:] == [("rel", 0, 0, 0), ("abs", 300, 400, 0)], jet.state.mouse[mouse:]
        if hidrpc:
            assert said(jet, sent) == [b"\x02\x00", b"\x06\x00\x00\x00", place(300, 400, 0)], said(jet, sent)

    run(jet, test)


def test_d4_the_hidrpc_channel_closing_ends_the_connection_and_a_new_one_is_made() -> None:
    jet = FakeJetKvm(JetState(width=640, height=360)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session) and held.road == "hidrpc"
        sessions = jet.state.sessions
        jet.close_hid()
        await settled(lambda: held.done.is_set(), within=5)
        assert held.done.is_set(), "the connection went on with the channel keys go over closed"
        with pytest.raises(kvm.KvmError):
            wall.say("keyboardReport", dict(PRESS_A), on=held)
        again = await wall.input_ready()
        assert isinstance(again, jetkvm._Session) and again.road == "hidrpc" and jet.state.sessions == sessions + 1

    run(jet, test)


@ROADS
def test_d5_after_a_connection_ended_with_a_key_that_may_be_down_the_next_begins_with_nothing_down(monkeypatch: pytest.MonkeyPatch, hidrpc: bool) -> None:
    # The JetKVM does a key and never says so (an answer lost, a word lost): the wall lets go of it and ends the
    # connection. Whether the JetKVM then let go of it, nobody knows (a press done after the connection closed is not):
    # the next connection says "nothing down" before anything else.
    # (Two seconds for an answer that never comes, not half a second: that wait is every question's, and a busy computer
    # answered the keyboard layout later than half a second, and nothing was typed.)
    monkeypatch.setattr(jetkvm, "RPC_TIMEOUT", 2.0)
    jet = FakeJetKvm(JetState(hidrpc=hidrpc, width=640, height=360, take_over_at=None if hidrpc else ("silent_only", 1, 0))).start()
    if hidrpc:
        real = jetkvm.JetKvmDevice._on_hid

        def heard(self: Any, session: Any, message: Any) -> None:
            if isinstance(message, bytes) and message[:1] == b"\x33" and 0x04 in message[2:]:
                return  # (the word that it has the press never comes)
            real(self, session, message)

        monkeypatch.setattr(jetkvm.JetKvmDevice, "_on_hid", heard)

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        with pytest.raises(kvm.KvmError) as refused:
            await wall.act("text", text="ab")
        assert refused.value.code == "timeout", refused.value.message
        first = wall._session
        assert first is not None
        await settled(lambda: first.done.is_set())  # (ended by the wall; its letting go, sent as no word came, done)
        reports, mouse, sent = len(jet.state.reports), len(jet.state.mouse), len(jet.state.hid_sent)
        await wall.act("text", text="c")  # (over a new connection)
        assert jet.state.reports[reports:] == [(0, []), (0, [0x06]), (0, [])], jet.state.reports[reports:]  # nothing down, first
        assert jet.state.mouse[mouse:] == [("rel", 0, 0, 0)], jet.state.mouse[mouse:]  # (and the mouse: its place is not known)
        if hidrpc:
            assert said(jet, sent)[:2] == [b"\x02\x00", b"\x06\x00\x00\x00"], said(jet, sent)

    run(jet, test)


# --- E: the JetKVM's own page takes the viewer ------------------------------------------------------------------------


def test_e1_a_key_held_at_the_hand_over_is_let_go_of_once_and_nothing_else_goes() -> None:
    jet = FakeJetKvm(JetState(width=640, height=360, hand_over_close=1.0)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session)
        after: list[bytes] = []  # what the wall sent once it knew of the hand-over
        send = held.hid.send

        def sending(data: bytes) -> None:
            if held.taken:
                after.append(data)
            send(data)

        held.hid.send = sending
        wall.say("keyboardReport", dict(PRESS_A), on=held)
        await settled(lambda: jet.state.down == [0x04])  # (held at the hand-over: a busy computer had not delivered it 0.3 s later)
        await asyncio.sleep(0.3)  # (kept alive meanwhile)
        jet.hand_over()
        await settled(lambda: held.taken)
        await asyncio.sleep(0.6)  # (the JetKVM closes the connection a second after the hand-over)
        assert after == [b"\x02\x00"], after  # the letting go, and no keep-alive after it
        # (A keep-alive already on its way may arrive after the hand-over, and be done after the letting go: it is of
        # another of the JetKVM's queues. It keeps nothing alive there: the hand-over stopped every key's clock.)
        assert keys_after_hand_over(jet) == [b"\x02\x00"], jet.state.hid_after_hand_over
        assert nothing_down(jet) and jet.state.auto_released == []

    run(jet, test)


def test_e2_a_press_on_its_way_at_the_hand_over_is_let_go_of_after_it() -> None:
    # Shift (a modifier: the JetKVM never lets go of it by itself) is on its way as the page takes the viewer; the
    # JetKVM does it 50 ms later, after the hand-over: down for whoever has the viewer, but for the letting go behind it.
    jet = FakeJetKvm(JetState(width=640, height=360, together=0.05, hand_over_close=1.0, take_over_at=("before", 1, 0))).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        wall.say("keyboardReport", dict(SHIFT), on=held)
        await settled(lambda: len(keys_after_hand_over(jet)) >= 2)
        assert keys_after_hand_over(jet) == [b"\x05\xe1\x01", b"\x02\x00"], jet.state.hid_after_hand_over
        assert nothing_down(jet), f"down for whoever took the viewer: {jet.state.modifier}"

    run(jet, test)


@ROADS
def test_e3_a_mouse_button_held_at_the_hand_over_is_let_go_of(hidrpc: bool) -> None:
    # (The real JetKVM kept the left button down across a hand-over to its own page: the program as it was sent nothing,
    # and the button stayed down for whoever had taken the viewer.)
    jet = FakeJetKvm(JetState(hidrpc=hidrpc, width=640, height=360, hand_over_close=1.0)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session)
        wall.say("absMouseReport", {"x": 10, "y": 20, "buttons": 1}, on=held)
        await settled(lambda: jet.state.buttons == 1)
        jet.hand_over()
        await settled(lambda: held.taken and jet.state.buttons == 0)
        assert jet.state.done_after_hand_over == [("absMouseReport", {"x": 10, "y": 20, "buttons": 0})], jet.state.done_after_hand_over
        assert nothing_down(jet), f"a button down for whoever took the viewer: {jet.state.buttons}"

    run(jet, test)


@ROADS
def test_e3_a_mouse_button_held_is_let_go_of_where_the_connection_closed_before_the_hand_over_was_heard(monkeypatch: pytest.MonkeyPatch, hidrpc: bool) -> None:
    # (The 0.2.0 requalification: under load the end of the video stream, which the JetKVM sends as it closes the connection
    # a second after a hand-over, was taken in before the word of the hand-over, and said "Secure video processing stopped".)
    # Here the word of the hand-over is held back until the channel it comes over has closed: the order a busy wall can meet.
    # Nothing can go over a connection that is closed, and the JetKVM keeps a mouse button down across both: the hand-over is
    # still heard as one (the wall steps aside), the stream's end is not said to be the decoder's, and what was held is owed
    # to the wall's next connection, which "Show here" makes and which lets go before anything else.
    jet = FakeJetKvm(JetState(hidrpc=hidrpc, width=640, height=360, hand_over_close=0.3)).start()
    held_back: list[tuple[Any, str]] = []
    real_on_message, real_no_more = jetkvm.JetKvmDevice._on_message, jetkvm.JetKvmDevice._no_more_asking

    def on_message(self: Any, session: Any, message: Any) -> None:
        if isinstance(message, str) and "otherSessionConnected" in message and session.rpc.readyState == "open":
            held_back.append((session, message))
            return
        real_on_message(self, session, message)

    def no_more_asking(self: Any, session: Any) -> None:
        for waited, message in held_back:  # (heard only now that the channel it came over has closed)
            real_on_message(self, waited, message)
        held_back.clear()
        real_no_more(self, session)

    monkeypatch.setattr(jetkvm.JetKvmDevice, "_on_message", on_message)
    monkeypatch.setattr(jetkvm.JetKvmDevice, "_no_more_asking", no_more_asking)

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session)
        wall.say("absMouseReport", {"x": 10, "y": 20, "buttons": 1}, on=held)
        await settled(lambda: jet.state.buttons == 1)
        jet.hand_over()
        await settled(lambda: held.done.is_set(), within=10)
        assert held.done.is_set() and held.taken and wall._displaced, (held.done.is_set(), held.taken)
        said = " ".join(str(error) for error in (held.error, held.lost) if error is not None)
        assert "Secure video processing" not in said, said
        # (Nothing could go over the connection, closed by now: the button is down for whoever took the viewer, until...)
        # "Show here": the wall's next connection lets go of what the last one could not, before anything else.
        await wall.act("resume")
        await settled(lambda: jet.state.buttons == 0)
        assert nothing_down(jet), f"a button down: {jet.state.buttons}"

    run(jet, test)


@pytest.mark.parametrize("why", ["ended", "too_large", "failed"])
def test_e3_the_end_of_a_video_stream_is_told_from_a_decoder_that_stopped(why: str) -> None:
    from aiortc.mediastreams import MediaStreamError

    from qkvm import video

    async def check() -> jetkvm._Session:
        device = jetkvm.JetKvmDevice(kvm.DeviceSpec("j", "jet", "http://127.0.0.1:18901", "", "", kind="jetkvm"))
        session = jetkvm._Session()
        session.ready.set()
        session.decoding = video.BoundedDecoderQueue()
        session.decoding.ended = why  # (as the queue notes it: the receiver ended the stream, a unit too large came, or decoding failed)

        class Track:
            async def recv(self) -> object:
                raise MediaStreamError

        await device._watch(session, Track())
        return session

    session = asyncio.run(check())
    if why == "ended":
        # The JetKVM ended its stream, or the connection ended: the connection is not ended for the decoder's sake; the
        # hand-over, the channel's close or the connection's end says what it is, and a JetKVM that only ended its video
        # is taken for one that stopped sending it HAND_OVER_GRACE later (see _hold).
        assert session.lost is None and not session.done.is_set() and session.video_ended_at is not None
    else:
        assert session.lost is not None and session.lost.code == "no_stream" and session.done.is_set()
        assert ("too large" in session.lost.message) == (why == "too_large"), session.lost.message
        assert "fell behind" not in session.lost.message, session.lost.message  # (falling behind ends nothing: see below)


H264 = SimpleNamespace(mimeType="video/h264")
# Units of H.264 as the WebRTC library puts them together (Annex B): a picture that needs those before it (a slice of type
# 1, with an access unit delimiter before it or not), and key frames (parameter sets and an IDR slice; with three-byte start
# codes and an SEI before them; an IDR slice alone).
P_FRAME = b"\x00\x00\x00\x01\x41\x9a\x02"
P_FRAME_AFTER_AUD = b"\x00\x00\x00\x01\x09\xf0\x00\x00\x00\x01\x41\x9a"
KEY_FRAME = b"\x00\x00\x00\x01\x67\x42\xc0\x1f\x00\x00\x00\x01\x68\xce\x3c\x80\x00\x00\x00\x01\x65\x88\x84"
KEY_FRAME_SHORT_CODES = b"\x00\x00\x01\x09\xf0\x00\x00\x01\x06\x05\x00\x00\x01\x67\x42\x00\x00\x01\x65\x88"
IDR_ALONE = b"\x00\x00\x00\x01\x65\x88\x84"


def unit(data: bytes) -> tuple[Any, Any]:
    return (H264, SimpleNamespace(data=data))


def test_e3_the_decoders_queue_says_why_decoding_stopped() -> None:
    from qkvm import video

    ended = video.BoundedDecoderQueue()
    ended.put(unit(KEY_FRAME))
    ended.put(None)  # (what the receiver puts as it stops: the sender ended the stream, or the connection ended)
    too_large = video.BoundedDecoderQueue()
    too_large.put(unit(bytes(video.MAX_COMPRESSED + 1)))
    assert (ended.ended, too_large.ended) == ("ended", "too_large")
    assert ended.stopped and too_large.stopped


def test_e3_a_decoder_behind_lets_go_of_what_waits_up_to_the_next_key_frame_and_asks_for_one(monkeypatch: pytest.MonkeyPatch) -> None:
    # (Pulled back from 0.3.0.) Four units waiting to be decoded (a busy computer) ended decoding, and with it the connection:
    # the keys, the buttons held and the JetKVM's one viewer, made anew. What waits is let go of instead, and what comes
    # after it, up to the next key frame (each picture between needs the ones before it), and the JetKVM is asked for one
    # (at most once a second, while none has come); decoding goes on from it.
    from qkvm import video

    asked: list[int] = []
    behind = video.BoundedDecoderQueue(ask_key_frame=lambda: asked.append(behind.qsize()))
    for data in (KEY_FRAME, P_FRAME, P_FRAME, P_FRAME):
        behind.put(unit(data))
    assert behind.qsize() == 4 and behind.let_go == 0 and asked == []
    for data in (P_FRAME, P_FRAME_AFTER_AUD, P_FRAME, P_FRAME):  # (the decoder still behind)
        behind.put(unit(data))
    assert not behind.stopped and behind.ended is None, (behind.stopped, behind.ended)
    assert behind.qsize() == 0 and behind.let_go == 8 and asked == [0], (behind.qsize(), behind.let_go, asked)
    behind.put(unit(KEY_FRAME_SHORT_CODES))
    behind.put(unit(P_FRAME))
    assert behind.qsize() == 2 and behind.let_go == 8 and asked == [0]
    assert [task[1].data for task in list(behind.queue)] == [KEY_FRAME_SHORT_CODES, P_FRAME]
    # Behind again, and no key frame for a while: asked again once a second (here, at every unit), and an IDR slice alone
    # (no parameter sets before it) is one too.
    monkeypatch.setattr(video, "KEY_FRAME_ASK_EVERY", 0.0)
    for data in (P_FRAME, P_FRAME, P_FRAME, P_FRAME):
        behind.put(unit(data))
    assert behind.qsize() == 0 and len(asked) == 3, (behind.qsize(), asked)
    behind.put(unit(IDR_ALONE))
    assert behind.qsize() == 1 and not behind.stopped


def test_e3_a_decoder_that_falls_behind_keeps_the_connection_and_a_button_held_and_its_picture_goes_on(monkeypatch: pytest.MonkeyPatch) -> None:
    # The same with the stand-in's video, decoded by the wall's own decoder, made slow on purpose for three seconds (as a
    # busy computer makes it): the connection stays, and with it the button held and the JetKVM's one viewer (the 0.2.0
    # requalification saw e3 fail under load for this: the connection made anew under the hand-over); the JetKVM is asked
    # for a key frame (the stand-in, as aiortc does, sends one when asked; by itself, one in twenty-five seconds), and the
    # picture goes on.
    from aiortc import rtcrtpsender

    from qkvm import video

    asked: list[float] = []
    real_keyframe = rtcrtpsender.RTCRtpSender._send_keyframe

    def send_keyframe(self: Any) -> None:
        asked.append(time.monotonic())
        real_keyframe(self)

    monkeypatch.setattr(rtcrtpsender.RTCRtpSender, "_send_keyframe", send_keyframe)
    slow_until = [0.0]
    real_decode = video.H264Decoder.decode

    def decode(self: Any, encoded: Any) -> Any:
        if time.monotonic() < slow_until[0]:
            time.sleep(0.3)  # (ten frames a second come; three of them while one is decoded)
        return real_decode(self, encoded)

    monkeypatch.setattr(video.H264Decoder, "decode", decode)
    jet = FakeJetKvm(JetState(width=640, height=360)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session)
        until = time.monotonic() + 20
        while held.frame is None:
            assert time.monotonic() < until and not held.done.is_set(), "no first picture"
            await asyncio.sleep(0.05)
        wall.say("absMouseReport", {"x": 10, "y": 20, "buttons": 1}, on=held)
        await settled(lambda: jet.state.buttons == 1)
        asked.clear()
        slow_until[0] = time.monotonic() + 3.0
        await asyncio.sleep(3.0)
        assert not held.done.is_set() and held.lost is None, held.lost
        assert getattr(held.decoding, "let_go", 0) > 0, "decoding never fell behind: the decoder was not made slow enough"
        then = time.monotonic()
        while held.frame_at <= then:
            assert time.monotonic() < then + 8 and not held.done.is_set(), (held.lost, held.decoding.ended)
            await asyncio.sleep(0.05)
        assert wall._session is held and not held.done.is_set() and held.lost is None, held.lost
        assert len(jet.state.video_offers) == 1, f"offers: {len(jet.state.video_offers)}"
        assert asked, "no key frame was asked for"
        assert jet.state.buttons == 1, f"the button held was let go of: {jet.state.buttons}"
        wall.say("absMouseReport", {"x": 10, "y": 20, "buttons": 0}, on=held)
        await settled(lambda: jet.state.buttons == 0)
        assert nothing_down(jet)

    run(jet, test)


@ROADS
def test_e4_nothing_goes_after_a_hand_over_with_nothing_down(hidrpc: bool) -> None:
    jet = FakeJetKvm(JetState(hidrpc=hidrpc, width=640, height=360, hand_over_close=1.0)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session)
        wall.say("keyboardReport", dict(PRESS_A), on=held)
        wall.say("keyboardReport", dict(NOTHING), on=held)
        wall.say("absMouseReport", {"x": 10, "y": 20, "buttons": 1}, on=held)
        wall.say("absMouseReport", {"x": 10, "y": 20, "buttons": 0}, on=held)
        await settled(lambda: len(jet.state.mouse) >= 2)
        jet.hand_over()
        await settled(lambda: held.taken)
        await asyncio.sleep(0.6)
        assert jet.state.hid_after_hand_over == [] and jet.state.done_after_hand_over == [] and jet.state.asked_after_hand_over == []

    run(jet, test)


@pytest.mark.parametrize("when", ["in the pause after a key", "after the last key", "a press on its way", "the last press on its way"])
def test_e5_a_hand_over_while_an_action_types_over_hidrpc(monkeypatch: pytest.MonkeyPatch, when: str) -> None:
    # (The pause after a typed key: the hand-over comes 30 ms into it, and the wall hears of it within it. In 0.15 s a busy
    # computer had not, and that is another case: see test_a_jetkvm_handed_over_with_a_key_on_its_way.py, test 5.)
    monkeypatch.setattr(jetkvm, "KEY_PAUSE", 1.5)
    if when in ("in the pause after a key", "after the last key"):
        state = JetState(width=640, height=360, take_over_at=("after", 1, 0.03), hand_over_close=1.0)
    else:
        state = JetState(width=640, height=360, together=0.05, take_over_at=("before", 1, 0), hand_over_close=1.0)
    jet = FakeJetKvm(state).start()
    text = "a" if when in ("after the last key", "the last press on its way") else "ab"

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        if when == "after the last key":
            await wall.act("text", text=text)  # done: its last key was pressed before the hand-over
        else:
            with pytest.raises(kvm.KvmError) as said:
                await wall.act("text", text=text)
            if when == "in the pause after a key":
                assert said.value.code == "in_use" and "after 1 of 2 keys" in said.value.message, said.value.message
            elif when == "a press on its way":
                assert said.value.code == "in_use" and "at key 1 of 2, which may have been pressed" in said.value.message, said.value.message
            else:
                assert said.value.code == "timeout" and "may have been done" in said.value.message and said.value.status == 504, said.value.message
        # (Until what is to come after the hand-over has come: the hand-over itself leaves nothing down.)
        expected = [b"\x02\x00"] if when in ("in the pause after a key", "after the last key") else [b"\x02\x00\x04", b"\x02\x00"]
        await settled(lambda: jet.state.hand_overs == 1 and len(keys_after_hand_over(jet)) >= len(expected) and nothing_down(jet))
        assert keys_after_hand_over(jet) == expected, jet.state.hid_after_hand_over  # (the letting go only; or the press, done after, and the letting go)
        assert nothing_down(jet), f"down for whoever took the viewer: {jet.state.down}"

    run(jet, test)


# --- F: an action that types ------------------------------------------------------------------------------------------


def test_f1_typing_over_hidrpc_is_a_whole_report_a_key_each_once_the_jetkvm_said_it_has_the_one_before(monkeypatch: pytest.MonkeyPatch) -> None:
    jet = FakeJetKvm(JetState(width=640, height=360, together=0.05)).start()  # (it does each 50 ms late)
    events: list[str] = []  # "press" as a typed key's press goes, "said" as the JetKVM says it has one, in that order
    real = jetkvm.JetKvmDevice._on_hid

    def heard(self: Any, session: Any, message: Any) -> None:
        if isinstance(message, bytes) and message[:1] == b"\x33" and any(message[2:]):
            events.append("said")
        real(self, session, message)

    monkeypatch.setattr(jetkvm.JetKvmDevice, "_on_hid", heard)

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session)
        send = held.hid.send

        def sending(data: bytes) -> None:
            if data[:1] == b"\x02" and len(data) > 2:
                events.append("press")
            send(data)

        held.hid.send = sending
        await wall.act("text", text="Hi!")
        assert said(jet) == [b"\x02\x02\x0b", b"\x02\x00", b"\x02\x00\x0c", b"\x02\x00", b"\x02\x02\x1e", b"\x02\x00"], said(jet)
        assert jet.state.reports == [(0x02, [0x0B]), (0, []), (0, [0x0C]), (0, []), (0x02, [0x1E]), (0, [])]
        # Each press went once the JetKVM had said it had the one before (one key on its way at the most).
        assert events == ["press", "said"] * 3, events
        assert nothing_down(jet)

    run(jet, test)


def test_f2_a_typed_key_the_jetkvm_never_says_it_has_is_let_go_of_and_the_connection_ended(monkeypatch: pytest.MonkeyPatch) -> None:
    # (Two seconds for the word that never comes, not half a second: the same wait is the first two keys', and a busy
    # computer's word for the second came later than half a second.)
    monkeypatch.setattr(jetkvm, "RPC_TIMEOUT", 2.0)
    real = jetkvm.JetKvmDevice._on_hid

    def heard(self: Any, session: Any, message: Any) -> None:
        if isinstance(message, bytes) and message[:1] == b"\x33" and 0x06 in message[2:]:
            return  # (the third key: the word that it has it never comes)
        real(self, session, message)

    monkeypatch.setattr(jetkvm.JetKvmDevice, "_on_hid", heard)
    jet = FakeJetKvm(JetState(width=640, height=360)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        await wall.input_ready()
        sessions = jet.state.sessions
        with pytest.raises(kvm.KvmError) as refused:
            await wall.act("text", text="abcd")
        assert (refused.value.code, refused.value.status) == ("timeout", 504), refused.value.message
        await settled(lambda: len(jet.state.typed) >= 3 and nothing_down(jet))
        assert [codes for _, codes in jet.state.typed] == [[0x04], [0x05], [0x06]], jet.state.typed  # (nothing after it)
        assert nothing_down(jet)
        await wall.act("text", text="x")  # (over a new connection)
        assert jet.state.sessions == sessions + 1 and jet.state.reports[-2:] == [(0, [0x1B]), (0, [])]

    run(jet, test)


# --- G: the wall stopping, and nobody watching -------------------------------------------------------------------------


def test_g_the_wall_stopping_lets_go_of_what_a_line_had_down_over_hidrpc(tmp_path: Path) -> None:
    jet = FakeJetKvm(JetState(width=640, height=360)).start()
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, jet.url)
            line = wall.line(admin, device, max_fps=5)
            assert line.picture(timeout=20).kind == 2
            line.say(t="control", on=True)
            assert line.word("control")["on"] is True
            line.say(t="k", u=0xE0, d=True)  # Ctrl
            line.say(t="k", u=0x04, d=True)
            line.say(t="m", x=1000, y=2000)
            line.say(t="mb", b=1, d=True)
            wait_until(lambda: jet.state.buttons == 1 and jet.state.down == [0x04], f"not down: {jet.state.down} {jet.state.buttons}")
        wait_until(lambda: nothing_down(jet), f"down after the wall stopped: {jet.state.down} {jet.state.modifier} {jet.state.buttons}")
    finally:
        jet.stop()


def test_a_jetkvm_nobody_watches_is_given_back_after_five_minutes(monkeypatch: pytest.MonkeyPatch) -> None:
    # The owner's standard for such holds is 300 s (a JetKVM nobody watched for a minute sends its first picture some five
    # seconds after it is connected to). Here the same hold, shortened: the connection is kept while it lasts.
    assert jetkvm.UNWATCHED == 300.0
    monkeypatch.setattr(jetkvm, "UNWATCHED", 1.5)
    jet = FakeJetKvm(JetState(width=640, height=360)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        session = await wall.input_ready()
        wall.say("absMouseReport", {"x": 10, "y": 20, "buttons": 1}, on=session)  # (a button left down, then nobody)
        await asyncio.sleep(0.8)
        assert isinstance(session, jetkvm._Session) and session.live, "given back before the time"
        await settled(lambda: session.done.is_set(), within=5)
        assert session.done.is_set() and jet.state.sessions == 1
        assert jet.state.buttons == 0 and jet.state.mouse[-1] == ("abs", 10, 20, 0), jet.state.mouse  # (let go of first)

    run(jet, test)


# --- The first review's findings ----------------------------------------------------------------------------------------


@ROADS
@pytest.mark.parametrize("ends", ["a place lets go", "the hand-over"])
def test_r1_a_drag_begun_on_one_of_the_two_mice_is_let_go_of_on_both(hidrpc: bool, ends: str) -> None:
    # The JetKVM's absolute and relative mice are two devices to the computer, each with buttons of its own. A drag begun
    # by steps (the pointer locked) and ended by a place (the lock let go of) left the relative mouse's button down.
    jet = FakeJetKvm(JetState(hidrpc=hidrpc, width=640, height=360, hand_over_close=1.0)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        wall.say("relMouseReport", {"dx": 3, "dy": 3, "buttons": 1}, on=held)
        wall.say("absMouseReport", {"x": 100, "y": 200, "buttons": 1}, on=held)
        if ends == "a place lets go":
            wall.say("absMouseReport", {"x": 100, "y": 200, "buttons": 0}, on=held)
        else:
            await settled(lambda: len(jet.state.mouse) >= 2)
            jet.hand_over()
        await settled(lambda: ("rel", 0, 0, 0) in jet.state.mouse and ("abs", 100, 200, 0) in jet.state.mouse)
        assert jet.state.buttons == 0, f"down: {jet.state.mouse}"
        assert ("rel", 0, 0, 0) in jet.state.mouse and ("abs", 100, 200, 0) in jet.state.mouse, jet.state.mouse

    run(jet, test)


def test_r2_what_is_owed_stays_owed_where_the_connection_ends_while_it_is_said(monkeypatch: pytest.MonkeyPatch) -> None:
    # (The "nothing down" owed was taken off the list before it went: the tile closed while it was being said over
    # JSON-RPC, it was never said, and the next connection did not say it either.)
    no_long_handshake(monkeypatch, False)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        wall.say("absMouseReport", {"x": 10, "y": 20, "buttons": 1}, on=held)
        await settled(lambda: jet.state.buttons == 1)
        jet.drop()
        await settled(lambda: isinstance(held, jetkvm._Session) and held.done.is_set(), within=10)
        assert wall._leftover.down
        jet.state.together = 2.0  # (keyboard and mouse reports answered two seconds late: the next connection says it slowly)
        asking = asyncio.ensure_future(wall.input_ready())
        await asyncio.sleep(1.5)
        await wall.close()  # (the tile edited or removed while it is said)
        with contextlib.suppress(kvm.KvmError, asyncio.CancelledError):
            await asking
        assert wall._leftover.down, "what was owed was forgotten"

    run(jet, test)


def test_r3_no_handshake_goes_after_a_hand_over(monkeypatch: pytest.MonkeyPatch) -> None:
    # A JetKVM that answers another version is asked again every quarter of a second, for two seconds: not after its own
    # page has taken the viewer. (One may be on its way as the JetKVM hands over, before the wall hears of it: none after.)
    monkeypatch.setattr(jetkvm, "HID_SHAKE_WITHIN", 2.0)
    jet = FakeJetKvm(JetState(hid_version=2, width=640, height=360, hand_over_close=1.5)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        session = await wall._connected(urgent=True)
        jet.hand_over()
        await settled(lambda: session.taken)
        await asyncio.sleep(0.05)  # (what was on its way as the wall heard of it has landed)
        on_its_way = list(jet.state.hid_after_hand_over)
        assert len(on_its_way) <= 1, on_its_way
        await asyncio.sleep(1.0)
        assert jet.state.hid_after_hand_over == on_its_way, jet.state.hid_after_hand_over

    run(jet, test)


def test_r4_a_jetkvm_that_says_its_keyboard_over_json_rpc_gets_its_text_typed_over_hidrpc_all_the_same() -> None:
    jet = FakeJetKvm(JetState(keys_said_on_rpc=True, width=640, height=360)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session) and held.road == "hidrpc"
        await wall.act("text", text="ok")
        assert jet.state.reports == [(0, [0x12]), (0, []), (0, [0x0E]), (0, [])], jet.state.reports

    run(jet, test)


@pytest.mark.parametrize("ends", ["the tile closed", "made anew", "the JetKVM dropped it"])
def test_r6_nothing_typed_goes_after_the_connection_ended_and_the_action_says_so_at_once(monkeypatch: pytest.MonkeyPatch, ends: str) -> None:
    # (The connection's end lets go of what is down, and then closes it; its channel reads "open" until it is closed,
    # and a key typed meanwhile went after the letting go: down for nobody to let go of, and the action waited eight
    # seconds for a word that never came. A close that takes a moment, as when the decoder is stopped, is made here.)
    from aiortc import RTCPeerConnection

    real_close = RTCPeerConnection.close

    async def slow_close(self: Any) -> None:
        await asyncio.sleep(0.05)
        await real_close(self)

    monkeypatch.setattr(RTCPeerConnection, "close", slow_close)
    late: list[bytes] = []
    after_close: list[bytes] = []  # (keys typed once the wall had begun to close: its letting go went then)
    real_send = jetkvm.JetKvmDevice._hid_send

    def send(self: Any, session: Any, data: bytes) -> None:
        real_send(self, session, data)
        if data[:1] == b"\x02" and any(data[2:]):
            if session.done.is_set():
                late.append(data)
            if self._closed:
                after_close.append(data)

    monkeypatch.setattr(jetkvm.JetKvmDevice, "_hid_send", send)
    jet = FakeJetKvm(JetState(width=640, height=360)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session) and held.road == "hidrpc"
        typing = asyncio.ensure_future(wall.act("text", text="abcdefghij" * 40))
        await settled(lambda: len(jet.state.typed) >= 10)
        began = time.monotonic()
        if ends == "the tile closed":
            await wall.close()
        elif ends == "made anew":
            wall._make_anew(held, "a test")
        else:
            jet.drop()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(asyncio.shield(typing), 5)
        assert late == [], f"typed after the connection's end: {late}"
        assert after_close == [], f"typed after the wall began to close the connection: {after_close}"
        assert time.monotonic() - began < 2, "the action waited for a word about a key sent after the end"
        with pytest.raises(kvm.KvmError) as stopped:
            await typing
        assert stopped.value.code in ("action_failed", "timeout"), stopped.value.as_dict()
        await settled(lambda: held.done.is_set())
        assert jet.state.down == [] and jet.state.modifier == 0

    run(jet, test)


def test_r7_a_hand_over_while_the_layout_is_asked_says_in_use_and_nothing_was_done(monkeypatch: pytest.MonkeyPatch) -> None:
    # (It said "Nothing was typed: ... it may have been done", 502, where the JetKVM's own page had taken the viewer.)
    jet = FakeJetKvm(JetState(width=640, height=360, hand_over_close=1.0)).start()
    real = jetkvm.JetKvmDevice._call

    async def call(self: Any, session: Any, method: str, params: Any = None, within: Any = None) -> Any:
        if method == "getKeyboardLayout":
            jet.hand_over()
            give_up = time.monotonic() + 3
            while not session.taken and time.monotonic() < give_up:
                await asyncio.sleep(0.02)
            raise self._cut_off(session)  # (as the question's end says it when the page takes the viewer meanwhile)
        return await real(self, session, method, params, within)

    monkeypatch.setattr(jetkvm.JetKvmDevice, "_call", call)

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        with pytest.raises(kvm.KvmError) as refused:
            await wall.act("text", text="ok")
        assert refused.value.code == "in_use" and refused.value.status == 409, refused.value.as_dict()
        assert refused.value.message.startswith("It was not done"), refused.value.message
        assert jet.state.typed == []

    run(jet, test)


def test_r8_where_only_the_hidrpc_channel_closes_a_button_held_is_let_go_of_over_the_other() -> None:
    # (Where hidrpc closed and rpc had not, nothing let go of the button as the connection ended: a JetKVM keeps it.)
    jet = FakeJetKvm(JetState(width=640, height=360)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session) and held.road == "hidrpc"
        wall.say("absMouseReport", {"x": 10, "y": 20, "buttons": 1}, on=held)
        await settled(lambda: jet.state.buttons == 1)
        jet.close_hid()
        await settled(lambda: held.done.is_set(), within=5)
        assert held.done.is_set()
        assert jet.state.buttons == 0 and jet.state.mouse[-1] == ("abs", 10, 20, 0), jet.state.mouse

    run(jet, test)


def test_r9_the_jetkvm_saying_the_keys_down_in_another_order_is_heard_all_the_same(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jetkvm, "RPC_TIMEOUT", 1.0)
    jet = FakeJetKvm(JetState(keys_said_backwards=True, width=640, height=360)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        await wall.input_ready()  # (connected first: only the keys are timed)
        began = time.monotonic()
        await wall.act("keys", keys="KeyA,KeyB")
        assert time.monotonic() - began < 0.9, "the word that it had the keys was not heard"
        assert jet.state.reports == [(0, [0x04, 0x05]), (0, [])], jet.state.reports

    run(jet, test)


def test_r10_whoever_waits_for_the_road_hears_of_the_connection_ending_before_it_was_chosen(monkeypatch: pytest.MonkeyPatch) -> None:
    # (The choice stopped before it began never said keys were ready: the wait went on for twenty seconds.)
    async def never(self: Any, session: Any) -> None:
        await asyncio.Event().wait()

    monkeypatch.setattr(jetkvm.JetKvmDevice, "_choose_road", never)
    jet = FakeJetKvm(JetState(width=640, height=360)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        session = await wall._connected(urgent=True)
        waiting = asyncio.ensure_future(wall.input_ready())
        await asyncio.sleep(0.2)
        jet.drop()
        with pytest.raises(kvm.KvmError):
            await asyncio.wait_for(waiting, 3)
        assert session.done.is_set()

    run(jet, test)


def test_r11_a_layout_never_chosen_is_us_english_as_the_jetkvms_own_page_takes_it() -> None:
    jet = FakeJetKvm(JetState(layout="", width=640, height=360)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        await wall.act("text", text="zy")
        assert jet.state.typed == [(0, [0x1D]), (0, [0x1C])], jet.state.typed

    run(jet, test)


def slow_letting_go_at_the_end(monkeypatch: pytest.MonkeyPatch) -> None:
    """The connection's own letting go, as the wall ends it, a second late: as when it looks just after the end began
    (it looks once a second)."""
    real = jetkvm.JetKvmDevice._let_go_before_closing

    async def slow(self: Any, session: Any, wait: bool) -> None:
        await asyncio.sleep(1.0)
        await real(self, session, wait)

    monkeypatch.setattr(jetkvm.JetKvmDevice, "_let_go_before_closing", slow)


async def down_for(jet: FakeJetKvm, within: float = 2.0) -> float:
    """How long until nothing is down at the stand-in (`within` where it stays down)."""
    began = time.monotonic()
    while (jet.state.down or jet.state.modifier) and time.monotonic() - began < within:
        await asyncio.sleep(0.005)
    return time.monotonic() - began


def test_r12_an_actions_key_down_as_its_connection_is_marked_to_end_is_let_go_of_by_the_action(monkeypatch: pytest.MonkeyPatch) -> None:
    # (The action stopped without letting go of the key the JetKVM had: down until the connection was looked at, up to a
    # second later, long enough for the computer to repeat it. A typed key is a whole report: the JetKVM never lets go
    # of it by itself.)
    slow_letting_go_at_the_end(monkeypatch)
    jet = FakeJetKvm(JetState(width=640, height=360)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session) and held.road == "hidrpc"
        typing = asyncio.ensure_future(wall.act("text", text="abcdefghij" * 20))
        give_up = time.monotonic() + 5
        seen: list[int] = []
        while not seen and time.monotonic() < give_up:
            seen = list(jet.state.down)
            await asyncio.sleep(0.001)
        assert seen, "no key was typed"
        wall._make_anew(held, "a test")
        with pytest.raises(kvm.KvmError) as stopped:
            await asyncio.wait_for(typing, 3)
        assert stopped.value.code == "action_failed" and "Typing was stopped after" in stopped.value.message, stopped.value.as_dict()
        took = await down_for(jet)
        assert took < 0.3, f"a typed key was down {took:.2f} s after the action stopped: {jet.state.down}"

    run(jet, test)


def test_r13_a_live_lines_key_is_not_kept_alive_once_its_connection_is_marked_to_end(monkeypatch: pytest.MonkeyPatch) -> None:
    # (The keep-alive went on until the connection was looked at, the line's letting go being refused meanwhile: the key
    # held up to a second. Stopped, the JetKVM lets go of it itself within a tenth of a second. Since the letting go goes as
    # the end is decided (register row 16), it is let go of by that, sooner still: the keep-alive stops all the same.)
    slow_letting_go_at_the_end(monkeypatch)
    jet = FakeJetKvm(JetState(width=640, height=360)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session) and held.road == "hidrpc"
        wall.say("keyboardReport", dict(PRESS_A), on=held)
        await asyncio.sleep(0.15)  # (longer than the JetKVM keeps a key nothing keeps alive)
        assert jet.state.down == [0x04], "the key was not held"
        kept_alive = jet.state.keep_alives
        wall._make_anew(held, "a test")
        took = await down_for(jet)
        assert took < 0.3, f"the key was kept down {took:.2f} s after the connection was marked to end"
        await asyncio.sleep(0.2)
        assert jet.state.keep_alives <= kept_alive + 1, "kept alive after the connection was marked to end"  # (one on its way)

    run(jet, test)


def test_r14_where_only_the_hidrpc_channel_shuts_a_modifier_held_is_let_go_of_over_the_other() -> None:
    # (Only the buttons went over the other channel: a modifier, which the JetKVM never lets go of by itself, stayed down
    # until the connection ended.)
    jet = FakeJetKvm(JetState(width=640, height=360)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session) and held.road == "hidrpc"
        sessions = jet.state.sessions
        wall.say("keyboardReport", dict(SHIFT), on=held)
        await settled(lambda: jet.state.modifier == 0x02)
        jet.close_hid()
        await settled(lambda: held.done.is_set(), within=5)
        assert held.done.is_set() and jet.state.sessions == sessions
        assert jet.state.reports[-1] == (0, []), f"not let go of before the end: {jet.state.reports}"

    run(jet, test)


@pytest.mark.parametrize("refused", ["press", "release", "release, the channel shut", "press, the channel shut"])
def test_r15_a_typed_key_that_could_not_go_or_could_not_be_let_go_of_stops_the_text_with_the_count(monkeypatch: pytest.MonkeyPatch, refused: str) -> None:
    # (The channel shutting as a key went: "dropped", which the page shows as "may have been done", of a key that never
    # went; and, where it was the letting go that could not go, the key the JetKVM had was left down. Where it shut
    # before a press, the letting go of the key before it may not have been taken: the last variant has it so.)
    counted = {"press": 0, "release": 0}
    real_send = jetkvm.JetKvmDevice._hid_send

    def send(self: Any, session: Any, data: bytes) -> None:
        if data[:1] == b"\x02":
            kind = "press" if any(data[2:]) else "release"
            counted[kind] += 1
            if refused == "press, the channel shut" and kind == "release" and counted[kind] == 2:
                return  # (handed to the channel and never taken by the JetKVM: the key stays down there)
            if refused.startswith(kind) and counted[kind] == 3:
                if refused.endswith("shut"):
                    session.hid.close()  # (the channel shutting as this was to go: a letting go goes over the other)
                raise kvm.KvmError("dropped", "The JetKVM closed the channel keys go over")
        real_send(self, session, data)

    monkeypatch.setattr(jetkvm.JetKvmDevice, "_hid_send", send)
    jet = FakeJetKvm(JetState(width=640, height=360)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session)
        with pytest.raises(kvm.KvmError) as stopped:
            await wall.act("text", text="abcdef")
        # (Let go of by the action as it stopped, not later by the connection's end: nothing has run in between.)
        assert held.kb_sent == jetkvm.NOTHING_DOWN, held.kb_sent
        typed = 2 if refused.startswith("press") else 3
        assert stopped.value.code == "action_failed", stopped.value.as_dict()
        assert stopped.value.message.startswith(f"Typing was stopped after {typed} of 6 keys"), stopped.value.message
        assert [keys for _, keys in jet.state.typed] == [[0x04], [0x05], [0x06]][:typed], jet.state.typed
        await settled(lambda: nothing_down(jet))
        assert nothing_down(jet), f"down: {jet.state.down}"
        if refused.endswith("shut"):  # (by a letting go of the wall's, not the JetKVM's own at the end)
            assert jet.state.reports[-1] == (0, []), f"not let go of over the other channel: {jet.state.reports}"

    run(jet, test)


def test_r16_a_letting_go_asked_for_after_the_end_has_looked_is_owed_to_the_next_connection() -> None:
    jet = FakeJetKvm(JetState(width=640, height=360)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session)
        jet.drop()
        await settled(lambda: held.done.is_set(), within=5)
        assert held.done.is_set()
        wall._leftover.down = False
        held.rel_buttons = 1  # (a button the wall said down, let go of only now)
        wall._send_let_go(held)
        assert wall._leftover.down, "nothing owed: the next connection would not say nothing is down"

    run(jet, test)


@pytest.mark.parametrize("what", ["the layout", "the road"])
def test_r5_a_text_whose_layout_or_road_could_not_be_found_out_was_not_typed_and_says_so(monkeypatch: pytest.MonkeyPatch, what: str) -> None:
    # (It said "may have been done", 504, which the history keeps as unknown, of a text nothing of which was typed.)
    jet = FakeJetKvm(JetState(width=640, height=360)).start()
    if what == "the layout":
        real = jetkvm.JetKvmDevice._call

        async def call(self: Any, session: Any, method: str, params: Any = None, within: Any = None) -> Any:
            if method == "getKeyboardLayout":
                raise kvm.KvmError("timeout", "The JetKVM did not answer in time", 504)
            return await real(self, session, method, params, within)

        monkeypatch.setattr(jetkvm.JetKvmDevice, "_call", call)
    else:

        async def never(self: Any, session: Any) -> None:
            raise kvm.KvmError("timeout", "The JetKVM is taking too long to connect", 504)

        monkeypatch.setattr(jetkvm.JetKvmDevice, "_keys_ready", never)

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        with pytest.raises(kvm.KvmError) as refused:
            await wall.act("text", text="ok")
        assert refused.value.code == "action_failed" and refused.value.message.startswith("Nothing was typed"), refused.value.message
        assert jet.state.reports == []

    run(jet, test)


def test_reconnect_waits_for_an_ended_sessions_decoder_cleanup(monkeypatch: pytest.MonkeyPatch) -> None:
    async def exercise() -> None:
        device = jetkvm.JetKvmDevice(kvm.DeviceSpec("w", "test wall", "http://127.0.0.1:18901", "", "", kind="jetkvm"))
        previous = jetkvm._Session()
        previous.done.set()
        previous.lost = kvm.KvmError("no_stream", "Secure video processing stopped", 503)
        cleanup = asyncio.Event()
        ending = asyncio.create_task(cleanup.wait())
        device._session, device._task = previous, ending

        async def next_session(session: jetkvm._Session) -> None:
            session.ready.set()
            await session.done.wait()

        monkeypatch.setattr(device, "_run", next_session)
        connecting = asyncio.create_task(device._connected(urgent=True))
        try:
            done, _ = await asyncio.wait({connecting}, timeout=0.05)
            assert not done, "reconnection returned the ended session before decoder cleanup finished"
            cleanup.set()
            current = await asyncio.wait_for(connecting, 2)
            assert current is not previous and current.live
        finally:
            cleanup.set()
            connecting.cancel()
            if device._task is not None:
                device._task.cancel()
            await asyncio.gather(connecting, ending, *([device._task] if device._task is not None else []), return_exceptions=True)
            await device.close()

    asyncio.run(exercise())


@pytest.mark.parametrize("end", ["made anew", "the outbox overflowing", "the tile closed"])
def test_r16_over_json_rpc_the_letting_go_on_an_end_the_wall_decides_waits_for_the_press_in_flight(end: str) -> None:
    # The JetKVM/Proxmox review (R16, review-jet2\probes\probe_r16_let_go_overtakes_a_press_in_flight.py): over JSON-RPC a
    # JetKVM does every call in a task of its own, and two that arrive together are done in either order (the stand-in's
    # `together`: the opposite one). The letting go sent at once as the wall decided an end overtook a press still in its
    # hands, and the button, which a JetKVM never lets go of by itself, stayed down. The press's answer is waited for first
    # (HAND_OVER_GRACE at the most), as at a hand-over (`_let_go_at_hand_over`).
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, together=0.4)).start()
    down: list[int] = []

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session) and held.road == "rpc", held.road
        await asyncio.sleep(0.3)
        wall.say("absMouseReport", {"x": 300, "y": 400, "buttons": 1}, on=held)
        await asyncio.sleep(0.05)  # (the press is out, in the JetKVM's hands: answered 0.4 s after it came)
        assert held.mouse_calls == 1, held.mouse_calls
        if end == "made anew":
            wall._make_anew(held, "made anew by the test")
        elif end == "the tile closed":
            await wall.close()
        else:
            with pytest.raises(kvm.KvmError):
                for n in range(jetkvm.MOST_WAITING + 1):
                    wall.say("absMouseReport", {"x": 301 + n, "y": 400, "buttons": n % 2}, on=held)
        await settled(lambda: held.done.is_set(), within=5)
        await asyncio.sleep(1.0)  # (whatever was handed over is done by now)
        down.append(jet.state.buttons)

    run(jet, test)
    assert down == [0], "a mouse button left down at the JetKVM"

def test_p1_a_jetkvm_deaf_to_key_frame_requests_is_not_said_to_have_stopped_sending_video_nor_counted_as_down(monkeypatch: pytest.MonkeyPatch) -> None:
    # The JetKVM/Proxmox review (P1, a LOW; review-jet2\probes\probe_p1_jetkvm_that_never_answers_a_key_frame_request.py):
    # decoding fell behind, what came was let go of up to a key frame and one was asked for, and the JetKVM never answered
    # the request (a firmware that reads it and throws it away; the stand-in sends one by itself in twenty-five seconds).
    # The connection ended "The JetKVM stopped sending video", counted as the JetKVM being down. Its video came all along:
    # the connection is made anew (a new one begins with a key frame), which is not counted.
    from aiortc import rtcrtpsender
    from aiortc.codecs import h264

    from qkvm import video

    monkeypatch.setattr(rtcrtpsender.RTCRtpSender, "_send_keyframe", lambda self: None)
    # (Held at one rate: aiortc's encoder also starts afresh, with a key frame, where the bitrate estimate moves.)
    monkeypatch.setattr(h264.H264Encoder, "target_bitrate", property(lambda self: h264.DEFAULT_BITRATE, lambda self, value: None))
    slow_until = [0.0]
    real_decode = video.H264Decoder.decode

    def decode(self: Any, encoded: Any) -> Any:
        if time.monotonic() < slow_until[0]:
            time.sleep(0.3)
        return real_decode(self, encoded)

    monkeypatch.setattr(video.H264Decoder, "decode", decode)
    jet = FakeJetKvm(JetState(width=640, height=360)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session)
        until = time.monotonic() + 20
        while held.frame is None:
            assert time.monotonic() < until and not held.done.is_set(), "no first picture"
            await asyncio.sleep(0.05)
        failures = wall._failures
        slow_until[0] = time.monotonic() + 3.0
        await settled(lambda: held.done.is_set(), within=15)
        assert held.done.is_set() and getattr(held.decoding, "let_go", 0) > 0, "decoding never fell behind"
        said = " ".join(str(error) for error in (held.error, held.lost) if error is not None)
        assert "stopped sending video" not in said and wall._failures == failures, (said, wall._failures - failures)

    run(jet, test)


def test_a_jetkvm_deaf_to_key_frame_requests_is_made_anew_less_and_less_often(monkeypatch: pytest.MonkeyPatch) -> None:
    # (0.3.0, section 5.) On a computer too slow for its video, decoding fell behind again on every new connection, and the
    # JetKVM deaf to the requests was made anew every FRAME_STALE for as long as it was watched: its keys let go of, a
    # connection opened, every five seconds. Each time in a row it waits twice as long before.
    from aiortc import rtcrtpsender
    from aiortc.codecs import h264

    from qkvm import video

    monkeypatch.setattr(rtcrtpsender.RTCRtpSender, "_send_keyframe", lambda self: None)
    monkeypatch.setattr(h264.H264Encoder, "target_bitrate", property(lambda self: h264.DEFAULT_BITRATE, lambda self, value: None))
    monkeypatch.setattr(jetkvm, "FRAME_STALE", 0.5)
    slow = [False]
    real_decode = video.H264Decoder.decode

    def decode(self: Any, encoded: Any) -> Any:
        if slow[0]:
            time.sleep(0.3)
        return real_decode(self, encoded)

    monkeypatch.setattr(video.H264Decoder, "decode", decode)
    stalls: list[float] = []  # how long each connection had no picture before it was made anew for that
    real_anew = jetkvm.JetKvmDevice._make_anew

    def anew(self: jetkvm.JetKvmDevice, session: Any, why: str) -> None:
        if "key frame" in why and session.anew is None:
            stalls.append(time.monotonic() - session.frame_at)
        real_anew(self, session, why)

    monkeypatch.setattr(jetkvm.JetKvmDevice, "_make_anew", anew)
    jet = FakeJetKvm(JetState(width=640, height=360)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session)
        until = time.monotonic() + 20
        while held.frame is None:
            assert time.monotonic() < until and not held.done.is_set(), "no first picture"
            await asyncio.sleep(0.05)
        slow[0] = True
        until = time.monotonic() + 40
        while len(stalls) < 3:
            assert time.monotonic() < until, stalls
            with contextlib.suppress(kvm.KvmError):
                await wall.input_ready()  # (watched: connected again after each)
            await asyncio.sleep(0.1)

    run(jet, test)
    assert stalls[1] >= 1.0 and stalls[2] >= 2.0, stalls  # (half a second, one, two: each twice the one before)

@pytest.mark.parametrize("end", ["an oversized message", "the decoder failed"])
def test_r16_on_the_other_ends_the_wall_decides_what_is_down_is_let_go_of_at_once(end: str) -> None:
    # The JetKVM/Proxmox review (R16, a LOW; review-jet2\probes\probe_r16_other_ends_the_wall_decides.py): `_make_anew` wakes
    # the connection's loop, and the letting go is at once. The other ends the wall decides (a message larger than any a
    # JetKVM sends, a decoder that failed, the status's "stopped answering") woke nothing: a modifier and a button stayed down
    # until the loop looked, up to a second later. They wake it.
    from aiortc.mediastreams import MediaStreamError

    jet = FakeJetKvm(JetState(width=640, height=360)).start()
    took: list[float] = []

    class Ended:
        async def recv(self) -> object:
            raise MediaStreamError

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        for _ in range(3):
            assert isinstance(held, jetkvm._Session)
            wall.say("keyboardReport", {"modifier": 0x02, "keys": []}, on=held)
            wall.say("absMouseReport", {"x": 300, "y": 400, "buttons": 1}, on=held)
            await settled(lambda: jet.state.buttons == 1 and jet.state.modifier == 0x02, within=1.0)
            await asyncio.sleep(0.1)  # (into the loop's second-long wait)
            began = time.monotonic()
            if end == "an oversized message":
                wall._on_message(held, "x" * (jetkvm.MOST_RPC_MESSAGE + 1))
            else:
                held.decoding.ended = "failed"  # (as the queue notes a decoder that failed, and its track then ends)
                await wall._watch(held, Ended())
            while (jet.state.buttons or jet.state.modifier) and time.monotonic() - began < 3:
                await asyncio.sleep(0.005)
            took.append(round(time.monotonic() - began, 3))
            await asyncio.sleep(0.3)
            held = await wall.input_ready()

    run(jet, test)
    assert max(took) < 0.3, took
