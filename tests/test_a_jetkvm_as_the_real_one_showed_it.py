"""A JetKVM as a real one showed it (track W14), against the stand-in that now answers the same way.

A real JetKVM does every call on the channel it is asked over in a task of its own, so two calls that arrive
together are done in either order. Keys and the mouse sent over the live line without waiting for the answer
to the one before came out of order on the real one: the alphabet typed as "abdcegfhjikmlnpoqsrtvuwyxz", a key
let go of before it was pressed (so held, and repeated by the computer), a right button left down until the line
gave the keyboard back. The stand-in does calls that arrive together in the opposite order.

These are about JSON-RPC, which a JetKVM without the hidrpc channel (an older firmware) is still spoken to over; the
three that hold for both roads run on both. hidrpc itself: `test_a_jetkvm_over_hidrpc.py`.
"""

from __future__ import annotations

import asyncio
import gc
import json
import logging
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

import pytest

from qkvm import jetkvm, kvm, live, update, vault
from tests.fake_jetkvm import FakeJetKvm, JetState, no_long_handshake, presses_wait
from tests.test_live import Viewer, Wall
from tests.test_wall import wait_until

ALPHABET = [0x04 + i for i in range(26)]
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
    # (Most of these are about JSON-RPC, the road an older JetKVM takes: its stand-in leaves the hidrpc channel
    # unanswered, and keys go over JSON-RPC once the wall has given up asking, not waited for two seconds each time.
    # Those that run on both roads say which: on hidrpc the wall waits for the handshake as long as it does.)
    callspec = getattr(request.node, "callspec", None)
    no_long_handshake(monkeypatch, callspec.params.get("hidrpc", False) if callspec is not None else False)


@pytest.mark.parametrize("hidrpc", [True, False], ids=["hidrpc", "json-rpc"])
def test_keys_and_buttons_sent_fast_over_the_live_line_arrive_in_order_and_none_stays_down(tmp_path: Path, hidrpc: bool) -> None:
    jet = FakeJetKvm(JetState(hidrpc=hidrpc, width=640, height=360)).start()
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, jet.url)
            line = wall.line(admin, device, max_fps=5)
            assert line.picture(timeout=20).kind == 2
            line.say(t="control", on=True)
            assert line.word("control")["on"] is True
            for usage in ALPHABET:  # as fast as a line takes them: each pressed and let go of
                line.say(t="k", u=usage, d=True)
                line.say(t="k", u=usage, d=False)
            line.say(t="m", x=100, y=200)
            for button in (1, 2, 3):
                line.say(t="mb", b=button, d=True)
                line.say(t="mb", b=button, d=False)
            # (Over JSON-RPC one report a round trip: a busy computer took up to two seconds for one, and these are 59. The
            # line is read meanwhile, as a browser reads it: left unread for a minute, the pictures it is sent filled what
            # the client holds, and its own pings went unanswered.)
            line.until(lambda: len(jet.state.reports) >= 52 and len(jet.state.mouse) >= 7, f"the JetKVM got {jet.state.reports} {jet.state.mouse}", timeout=180)
            time.sleep(0.3)  # (whatever was still on its way)
            assert [codes[0] for _, codes in jet.state.typed] == ALPHABET, jet.state.typed
            assert jet.state.reports == [report for usage in ALPHABET for report in ((0, [usage]), (0, []))]
            assert jet.state.down == []
            assert [buttons for *_, buttons in jet.state.mouse] == [0, 1, 0, 2, 0, 4, 0], jet.state.mouse
            line.say(t="control", on=False)
            assert line.word("control") == {"t": "control", "on": False}
            line.close()
    finally:
        jet.stop()


def test_the_pointer_follows_where_it_is_put_now_and_not_every_place_it_was_on_the_way(tmp_path: Path) -> None:
    # A JetKVM that answers slower than the pointer is moved: what waits to go to it is where the pointer is now.
    # (Every place sent on regardless, the last of them came long after the hand had stopped, and in no order.)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, together=0.05)).start()
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, jet.url)
            line = wall.line(admin, device, max_fps=5)
            assert line.picture(timeout=20).kind == 2
            line.say(t="control", on=True)
            assert line.word("control")["on"] is True
            for step in range(1, 61):
                line.say(t="m", x=step * 100, y=step * 50)
                time.sleep(0.01)
            stopped = time.monotonic()
            wait_until(lambda: jet.state.mouse[-1:] == [("abs", 6000, 3000, 0)], f"the pointer did not end where it was put: {jet.state.mouse[-5:]}", timeout=60)
            # Soon after the hand stopped, in the JetKVM's own time: a few of its answers (each place goes once the one
            # before was answered), where every place sent on regardless came dozens later. (In seconds, a busy computer
            # took two for one answer.)
            took = sorted(later - sooner for sooner, later in zip(jet.state.mouse_at, jet.state.mouse_at[1:], strict=False))
            answer = took[len(took) // 2] if took else 0.05
            assert jet.state.mouse_at[-1] - stopped < 6 * answer + 0.5, f"the pointer came to where it was put {jet.state.mouse_at[-1] - stopped:.2f} s after the hand had stopped, where an answer takes {answer:.2f} s"
            places = [(x, y) for _, x, y, _ in jet.state.mouse]
            assert len(places) < 40, f"{len(places)} places were sent for 60 moves to a JetKVM that answers every 50 ms"
            assert places == sorted(places), f"the pointer went back to where it had been: {places}"
            line.close()
    finally:
        jet.stop()


def test_a_jetkvm_that_stops_answering_keys_has_the_keyboard_taken_from_the_line(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jetkvm, "TAKE_WITHIN", 1.0, raising=False)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360)).start()
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, jet.url)
            line = wall.line(admin, device, max_fps=5)
            assert line.picture(timeout=20).kind == 2
            line.say(t="control", on=True)
            assert line.word("control")["on"] is True
            line.say(t="k", u=0x04, d=True)
            line.say(t="k", u=0x04, d=False)
            wait_until(lambda: len(jet.state.reports) >= 2, "the first key did not arrive")
            jet.state.frozen = True  # it takes what it is sent and answers nothing, does nothing
            began = time.monotonic()
            line.say(t="k", u=0x05, d=True)
            time.sleep(2.5)  # (under the five seconds after which a JetKVM that sends no picture is taken to be gone)
            line.say(t="k", u=0x05, d=False)  # the next word finds it not taking them
            taken = line.word("control", timeout=10)
            assert taken["on"] is False and taken["code"] == "dropped", taken
            assert "stopped answering keys" in taken["message"], taken
            assert time.monotonic() - began < 8
            line.close()
    finally:
        jet.state.frozen = False
        jet.stop()


@pytest.mark.parametrize("hidrpc", [True, False], ids=["hidrpc", "json-rpc"])
def test_the_line_that_holds_the_keyboard_is_told_at_once_when_the_jetkvms_own_page_takes_it(tmp_path: Path, hidrpc: bool) -> None:
    # On a real one: the line kept "control on" after the JetKVM's own page had taken its one viewer, and the holder
    # heard only at the next key, that "the JetKVM closed the connection". The key it held was let go of by the device.
    jet = FakeJetKvm(JetState(hidrpc=hidrpc, width=640, height=360)).start()
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, jet.url)
            line = wall.line(admin, device, max_fps=5)
            assert line.picture(timeout=20).kind == 2
            line.say(t="control", on=True)
            assert line.word("control")["on"] is True
            line.say(t="k", u=0x04, d=True)
            wait_until(lambda: jet.state.down == [0x04], "the key did not go down")

            async def open_its_own_page() -> None:
                other = jetkvm.JetKvmDevice(kvm.DeviceSpec("x", "its own page", jet.url, "", "secret", kind="jetkvm"))
                await other._connected()
                await asyncio.sleep(1.0)
                await other.close()

            asyncio.run(open_its_own_page())
            taken = line.word("control", timeout=10)  # nothing was sent meanwhile: told all the same
            assert taken["on"] is False and taken["code"] == "in_use", taken
            assert "own" in taken["message"], taken
            # (Let go of by the device at the hand-over; or over hidrpc, where a busy wall's keep-alive came more than a
            # tenth of a second late, by the device before it, as the README says: never down for whoever took it.)
            assert jet.state.down == [] and (jet.state.let_go_at_end == 1 or (hidrpc and jet.state.auto_released == [0x04])), (jet.state.let_go_at_end, jet.state.auto_released)
            line.close()
    finally:
        jet.stop()


def held(wall: Wall, jet: FakeJetKvm) -> Viewer:
    """A live line to the stand-in that holds its keyboard and mouse."""
    admin = wall.browser()
    device = wall.add(admin, jet.url)
    line = wall.line(admin, device, max_fps=5)
    assert line.picture(timeout=20).kind == 2
    line.say(t="control", on=True)
    assert line.word("control")["on"] is True
    return line


def test_a_press_and_a_release_of_a_button_stay_where_they_were_made_however_slowly_the_jetkvm_answers(tmp_path: Path) -> None:
    # (Found by the review: a place that came after a press was folded into the press, which then landed there. A drag
    # began where the hand had already gone; a click let go of far from where it was pressed, which is a drag too.)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, together=0.05)).start()  # it answers each 50 ms later
    try:
        with Wall(tmp_path) as wall:
            line = held(wall, jet)
            line.say(t="m", x=1000, y=1000)
            line.say(t="mb", b=1, d=True)
            time.sleep(0.02)
            line.say(t="m", x=5000, y=5000)  # dragged on, while the press waits to go
            time.sleep(0.02)
            line.say(t="mb", b=1, d=False)
            line.say(t="m", x=6000, y=6000)
            line.say(t="mb", b=2, d=True)
            line.say(t="mb", b=2, d=False)
            time.sleep(0.02)
            line.say(t="m", x=9000, y=9000)  # and away, while the click's release waits to go
            wait_until(lambda: jet.state.mouse[-1:] == [("abs", 9000, 9000, 0)], f"the pointer did not end where it was put: {jet.state.mouse}", timeout=10)
            pressed = [report for report in jet.state.mouse if report[3]]
            assert pressed[0] == ("abs", 1000, 1000, 1), f"the drag did not begin where the button went down: {jet.state.mouse}"
            assert ("abs", 5000, 5000, 0) in jet.state.mouse, f"the drag did not end where the button was let go: {jet.state.mouse}"
            assert pressed[-1] == ("abs", 6000, 6000, 2) and ("abs", 6000, 6000, 0) in jet.state.mouse, f"the click did not stay a click: {jet.state.mouse}"
            line.close()
    finally:
        jet.stop()


def test_moves_and_turns_of_the_wheel_add_up_while_they_wait_and_the_line_keeps_the_mouse(tmp_path: Path) -> None:
    # (Found by the review: relative moves at the page's pace to a JetKVM that answers every 50 ms piled up until the
    # line lost keyboard and mouse.)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, together=0.05)).start()
    try:
        with Wall(tmp_path) as wall:
            line = held(wall, jet)
            began, sent = time.monotonic(), 0
            while time.monotonic() - began < 3.0:  # a move and a turn every 10 ms, as the page sends them at the most
                line.say(t="mr", dx=3, dy=1)
                line.say(t="mw", dx=0, dy=1)
                sent += 1
                time.sleep(0.01)
            with pytest.raises(TimeoutError):
                line.word("control", timeout=1.0)  # nothing taken away

            def moved() -> list[tuple[int, int]]:
                return [(report[1], report[2]) for report in jet.state.mouse if report[0] == "rel"]

            def turned() -> int:
                return sum(report[2] for report in jet.state.mouse if report[0] == "wheel")

            wait_until(lambda: sum(dx for dx, _ in moved()) == 3 * sent and turned() == sent, f"the moves and turns did not add up to what was sent: {sent}, {jet.state.mouse[-4:]}", timeout=10)
            assert sum(dy for _, dy in moved()) == sent
            assert len(moved()) < sent / 2, f"{len(moved())} moves were sent for {sent} to a JetKVM that answers every 50 ms"
            assert all(abs(dx) <= 127 and abs(dy) <= 127 for dx, dy in moved())
            line.close()
    finally:
        jet.stop()


def test_an_answer_that_comes_too_late_ends_the_connection_and_leaves_no_key_down(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (Found by the review: a key whose press was answered late was done late, its release was dropped, and the wall
    # told nobody: the key stayed down, and the computer repeated it. A JetKVM lets go of every key when a connection
    # ends: a real one did at once.)
    monkeypatch.setattr(jetkvm, "TAKE_WITHIN", 1.0, raising=False)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360)).start()
    try:
        with Wall(tmp_path) as wall:
            line = held(wall, jet)
            line.say(t="k", u=0x04, d=True)
            line.say(t="k", u=0x04, d=False)
            wait_until(lambda: len(jet.state.reports) >= 2, "the first key did not arrive")
            sessions = jet.state.sessions
            jet.state.together = 1.5  # an answer that comes late (a packet lost and sent again, twice): the call is done late
            line.say(t="k", u=0x05, d=True)
            line.say(t="k", u=0x05, d=False)
            wait_until(lambda: 0x05 in [codes[0] for _, codes in jet.state.typed], "the late press was never done", timeout=10)
            jet.state.together = 0.005
            wait_until(lambda: jet.state.down == [], f"a key stays down on the machine: {jet.state.down}", timeout=10)
            line.say(t="k", u=0x06, d=True)  # the holder is told at the next word
            taken = line.word("control", timeout=10)
            assert taken["on"] is False and taken["code"] == "dropped", taken
            # Asked again (once the old connection is closed), keyboard and mouse are had over a new one, and the next
            # key goes through.
            for _ in range(20):
                line.say(t="control", on=True)
                if line.word("control", timeout=20)["on"] is True:
                    break
                time.sleep(0.5)
            else:
                raise AssertionError("keyboard and mouse were not had again")
            line.say(t="k", u=0x07, d=True)
            line.say(t="k", u=0x07, d=False)
            wait_until(lambda: jet.state.reports[-2:] == [(0, [0x07]), (0, [])], f"the next key did not go through: {jet.state.reports[-4:]}", timeout=10)
            assert jet.state.sessions > sessions and jet.state.down == []
            line.close()
    finally:
        jet.stop()


def test_keys_from_the_live_view_still_on_their_way_hold_back_an_action_that_types(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (Found by the review: after a wait the action typed regardless, in among the keys of the live view still on
    # their way: they would land in its text, a password perhaps.)
    # (Two seconds for an answer to a report, which the stand-in gives 0.3 s late: with one second, a busy computer's answer
    # came later once, the connection was made anew, and the action went through: the third reviewer's note.)
    monkeypatch.setattr(jetkvm, "TAKE_WITHIN", 2.0, raising=False)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, together=0.3)).start()  # every report answered 0.3 s late
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, jet.url)
            line = wall.line(admin, device, max_fps=5)
            assert line.picture(timeout=20).kind == 2
            line.say(t="control", on=True)
            assert line.word("control")["on"] is True
            for usage in ALPHABET[:10]:
                line.say(t="k", u=usage, d=True)
                line.say(t="k", u=usage, d=False)
            line.say(t="control", on=False)
            assert line.word("control") == {"t": "control", "on": False}
            refused = admin.post(f"/api/v1/devices/{device}/actions", json={"action": "text", "text": "secret"})
            assert (refused.status_code, refused.json()["code"]) == (409, "busy"), refused.text
            assert "live view" in refused.json()["message"]
            wait_until(lambda: len(jet.state.reports) >= 20, "the line's keys did not all arrive", timeout=20)  # (and its letting go, the same as the last)
            assert [codes[0] for _, codes in jet.state.typed] == ALPHABET[:10]
            jet.state.together = 0.005
            assert admin.post(f"/api/v1/devices/{device}/actions", json={"action": "text", "text": "ok"}).status_code == 200
            assert [codes[0] for _, codes in jet.state.typed][10:] == [0x12, 0x0E]  # o k
            line.close()
    finally:
        jet.stop()


@pytest.mark.parametrize("hidrpc", [True, False], ids=["hidrpc", "json-rpc"])
def test_nothing_goes_to_a_jetkvm_whose_own_page_has_taken_its_viewer(hidrpc: bool) -> None:
    # (Found by the review: in the moment before the wall notices, keys still went over the connection that had been
    # taken over, to the keyboard of whoever is at the JetKVM's own page.)
    jet = FakeJetKvm(JetState(hidrpc=hidrpc, width=640, height=360)).start()

    async def run() -> None:
        wall_side = jetkvm.JetKvmDevice(kvm.DeviceSpec("w", "the wall", jet.url, "", "secret", kind="jetkvm"))
        own_page = jetkvm.JetKvmDevice(kvm.DeviceSpec("p", "its own page", jet.url, "", "secret", kind="jetkvm"))
        try:
            session = await wall_side._connected(urgent=True)
            opening = asyncio.ensure_future(own_page._connected())
            for _ in range(2000):  # (the JetKVM says so, and drops the wall's connection a moment later)
                if session.taken:
                    break
                await asyncio.sleep(0.005)
            assert session.taken
            reports = len(jet.state.reports)
            with pytest.raises(kvm.KvmError) as refused:
                wall_side.say("keyboardReport", {"modifier": 0, "keys": [0x04]})
            assert refused.value.code in ("in_use", "dropped")  # (the second once the wall has stepped aside)
            await opening
            await asyncio.sleep(0.5)
            assert len(jet.state.reports) == reports, jet.state.reports
        finally:
            await wall_side.close()
            await own_page.close()

    try:
        asyncio.run(run())
    finally:
        jet.stop()


def the_wall_side(device: str) -> jetkvm.JetKvmDevice:
    """The wall's own object for a JetKVM on it (to look at what waits to go to it)."""
    # (By its type, not isinstance: among the objects are weak proxies to objects that are gone, which isinstance asks.)
    return next(o for o in gc.get_objects() if type(o) is jetkvm.JetKvmDevice and o.spec.id == device and not o._closed and o._session is not None)


def test_what_is_folded_and_what_is_not() -> None:
    fold, same = jetkvm._fold_into, jetkvm._same_as_last
    waiting: deque[tuple[str, dict[str, Any], bool]]
    # A report of the buttons alone (no place, no move) is never folded into: the move would happen before the press.
    waiting = deque([("relMouseReport", {"dx": 5, "dy": 0, "buttons": 0}, True), ("relMouseReport", {"dx": 0, "dy": 0, "buttons": 1}, False)])
    assert not fold(waiting, "relMouseReport", {"dx": 3, "dy": 0, "buttons": 1})
    # Nor across a key.
    waiting = deque([("relMouseReport", {"dx": 5, "dy": 0, "buttons": 0}, True), ("keyboardReport", {"modifier": 0, "keys": [4]}, False)])
    assert not fold(waiting, "relMouseReport", {"dx": 1, "dy": 0, "buttons": 0})
    # Moves add up as far as a signed byte carries them, and no further; turns of the wheel the same.
    waiting = deque([("relMouseReport", {"dx": 120, "dy": -120, "buttons": 0}, True)])
    assert fold(waiting, "relMouseReport", {"dx": 7, "dy": -7, "buttons": 0}) and waiting[0][1] == {"dx": 127, "dy": -127, "buttons": 0}
    assert not fold(waiting, "relMouseReport", {"dx": 1, "dy": 0, "buttons": 0})
    waiting = deque([("wheelReport", {"wheelY": -120, "wheelX": 0}, True)])
    assert not fold(waiting, "wheelReport", {"wheelY": -8, "wheelX": 0})
    # A move across a turn of the wheel, and a turn across moves: folded. A place and a move across each other: not.
    waiting = deque([("relMouseReport", {"dx": 5, "dy": 0, "buttons": 0}, True), ("wheelReport", {"wheelY": 1, "wheelX": 0}, True)])
    assert fold(waiting, "relMouseReport", {"dx": 3, "dy": 0, "buttons": 0}) and waiting[0][1]["dx"] == 8
    waiting = deque([("relMouseReport", {"dx": 5, "dy": 0, "buttons": 0}, True), ("absMouseReport", {"x": 1, "y": 1, "buttons": 0}, True)])
    assert not fold(waiting, "relMouseReport", {"dx": 1, "dy": 0, "buttons": 0})
    # A whole state said again, as the last of its kind that waits says it, adds nothing; a move or a turn always does.
    waiting = deque([("keyboardReport", {"modifier": 0, "keys": []}, False), ("absMouseReport", {"x": 1, "y": 1, "buttons": 0}, False)])
    assert same(waiting, "keyboardReport", {"modifier": 0, "keys": []}) and same(waiting, "absMouseReport", {"x": 1, "y": 1, "buttons": 0})
    assert not same(waiting, "keyboardReport", {"modifier": 0, "keys": [4]}) and not same(waiting, "absMouseReport", {"x": 1, "y": 2, "buttons": 0})
    waiting = deque([("relMouseReport", {"dx": 0, "dy": 0, "buttons": 0}, False), ("wheelReport", {"wheelY": 1, "wheelX": 0}, True)])
    assert same(waiting, "relMouseReport", {"dx": 0, "dy": 0, "buttons": 0})
    assert not same(waiting, "wheelReport", {"wheelY": 1, "wheelX": 0})
    assert not same(deque([("relMouseReport", {"dx": 2, "dy": 0, "buttons": 0}, True)]), "relMouseReport", {"dx": 2, "dy": 0, "buttons": 0})


def test_letting_go_again_and_again_does_not_pile_up(tmp_path: Path) -> None:
    # (Found by the second review: every "let go of everything" from the holder went past the bound of what may wait.
    # Thousands of them a second to a JetKVM that answers every 50 ms: nine thousand waiting, and growing.)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, together=0.05)).start()
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, jet.url)
            line = wall.line(admin, device, max_fps=5)
            assert line.picture(timeout=20).kind == 2
            line.say(t="control", on=True)
            assert line.word("control")["on"] is True
            line.say(t="m", x=100, y=100)
            for _ in range(2):
                for _ in range(1500):
                    line.say(t="up")
                time.sleep(1.05)
            session = the_wall_side(device)._session
            assert session is not None
            assert len(session.outbox) <= 4, f"{len(session.outbox)} reports wait to go"
            with pytest.raises(TimeoutError):
                line.word("control", timeout=0.5)  # (and the line keeps keyboard and mouse)
            line.close()
    finally:
        jet.stop()


def test_a_line_far_behind_has_its_connection_made_anew_and_nothing_stays_down(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jetkvm, "MOST_WAITING", 8, raising=False)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, together=0.05)).start()
    try:
        with Wall(tmp_path) as wall:
            line = held(wall, jet)
            sessions = jet.state.sessions
            line.say(t="k", u=0x2C, d=True)  # the space bar, held
            # (Down on the stand-in before the flood: a busy computer took the flood in before it sent the space bar, and
            # the space bar went with what was lost when the connection was made anew, so nothing was down at its end.)
            wait_until(lambda: jet.state.down == [0x2C], "the space bar did not go down", timeout=30)
            for usage in ALPHABET:
                line.say(t="k", u=usage, d=True)
                line.say(t="k", u=usage, d=False)
            taken = line.word("control", timeout=10)
            assert taken["on"] is False and taken["code"] == "dropped" and "not keeping up" in taken["message"], taken
            wait_until(lambda: jet.state.let_go_at_end >= 1 and jet.state.down == [], f"the connection was not ended, or a key stayed down: {jet.state.down}", timeout=10)
            assert len(jet.state.typed) < len(ALPHABET), "what waited was sent all the same"
            line.say(t="control", on=True)  # had again, over a new connection
            for _ in range(20):
                if line.word("control", timeout=20)["on"] is True:
                    break
                time.sleep(0.5)
                line.say(t="control", on=True)
            assert jet.state.sessions > sessions
            line.close()
    finally:
        jet.stop()


def test_an_action_whose_key_press_is_answered_late_lets_go_by_ending_the_connection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (Found by the second review: the release went out at once, while the press could still be done after it; the
    # stand-in did them in the opposite order, and the key stayed down on the same connection.)
    waits = presses_wait(monkeypatch, 0.5)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360)).start()
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, jet.url)
            assert admin.post(f"/api/v1/devices/{device}/actions", json={"action": "text", "text": "x"}).status_code == 200
            sessions = jet.state.sessions
            before = len(jet.state.reports)
            jet.state.together = 1.0  # the press is done a second after it came
            reply = admin.post(f"/api/v1/devices/{device}/actions", json={"action": "text", "text": "a"})
            assert reply.status_code == 504, reply.text
            wait_until(lambda: 0x04 in [codes[0] for _, codes in jet.state.typed], "the late press was never done", timeout=10)
            jet.state.together = 0.005
            # A letting go was sent as no answer came (W14b), and as that could be done before the late press (here it
            # was: both in the stand-in's hands at once), the connection was ended, which let go of the key; or, where
            # the late answer came while the connection was still open (a busy computer was slow to end it), a letting
            # go went in turn after it.
            wait_until(lambda: jet.state.down == [], f"the key stays down: {jet.state.down}", timeout=10)
            assert set(map(str, jet.state.reports[before:])) == {"(0, [4])", "(0, [])"}, jet.state.reports  # (the press, its letting go)
            waits["seconds"] = None  # (the next action as the wall waits: a busy computer answered it later than half a second)
            assert admin.post(f"/api/v1/devices/{device}/actions", json={"action": "text", "text": "x"}).status_code == 200
            assert jet.state.sessions > sessions and jet.state.down == []
    finally:
        jet.stop()


def test_nothing_waiting_and_no_typed_key_goes_after_the_jetkvms_own_page_took_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (Found by the second review: reports that waited, and the rest of a text being typed, went on for up to a second
    # after the JetKVM had said that somebody else has it: to the keyboard of whoever is at its own page.)
    after: list[Any] = []
    real = jetkvm.JetKvmDevice._call

    async def call(self: Any, session: Any, method: str, params: Any = None, within: Any = None) -> Any:
        if method == "keyboardReport" and session.taken:
            after.append(params)
        return await real(self, session, method, params, within)

    monkeypatch.setattr(jetkvm.JetKvmDevice, "_call", call)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, together=0.05)).start()

    async def queued_then_taken() -> None:
        wall_side = jetkvm.JetKvmDevice(kvm.DeviceSpec("w", "the wall", jet.url, "", "secret", kind="jetkvm"))
        own_page = jetkvm.JetKvmDevice(kvm.DeviceSpec("p", "its own page", jet.url, "", "secret", kind="jetkvm"))
        try:
            session = await wall_side.input_ready()
            for usage in ALPHABET:  # faster than it takes them
                wall_side.say("keyboardReport", {"modifier": 0, "keys": [usage]}, on=session)
                wall_side.say("keyboardReport", {"modifier": 0, "keys": []}, on=session)
            await asyncio.sleep(0.2)
            await own_page._connected()
            await asyncio.sleep(1.5)
            # (Looked at while the page has the viewer: when it goes, the JetKVM lets go of everything anyway.)
            assert jet.state.down == [] and jet.state.modifier == 0, f"down for whoever took the viewer: {jet.state.down}"
        finally:
            await wall_side.close()
            await own_page.close()

    async def its_own_page() -> None:
        own_page = jetkvm.JetKvmDevice(kvm.DeviceSpec("p", "its own page", jet.url, "", "secret", kind="jetkvm"))
        try:
            await own_page._connected()
            await asyncio.sleep(1.5)
            assert jet.state.down == [] and jet.state.modifier == 0, f"down for whoever took the viewer: {jet.state.down}"
        finally:
            await own_page.close()

    try:
        asyncio.run(queued_then_taken())
        assert after == [], f"{len(after)} reports went after the JetKVM's own page took it"
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, jet.url)
            answers: list[Any] = []
            text = "abcdefghijklmnopqrstuvwxyz" * 2
            typing = threading.Thread(target=lambda: answers.append(admin.post(f"/api/v1/devices/{device}/actions", json={"action": "text", "text": text})))
            before = len(jet.state.typed)
            typing.start()
            wait_until(lambda: len(jet.state.typed) >= before + 3, "the typing did not begin", timeout=20)
            asyncio.run(its_own_page())
            typing.join(30)
            reply = answers[0]
            assert (reply.status_code, reply.json()["code"]) in ((409, "in_use"), (502, "dropped")), reply.text
            assert after == [], f"{len(after)} typed reports went after the JetKVM's own page took it"
    finally:
        jet.stop()


def test_a_takeover_in_the_pause_between_a_typed_key_and_its_release_sends_no_release(monkeypatch: pytest.MonkeyPatch) -> None:
    # (Linux with Python 3.13, four suites at once: the JetKVM's own page took the viewer in the pause after a typed key
    # was pressed, and its release still went, to the keyboard of whoever was at that page. A JetKVM lets go of every key
    # of a viewer it hands over, so nothing is to be sent after that. Here the takeover comes in exactly that pause.)
    after: list[Any] = []
    real = jetkvm.JetKvmDevice._call

    async def call(self: Any, session: Any, method: str, params: Any = None, within: Any = None) -> Any:
        if method == "keyboardReport" and session.taken:
            after.append(params)
        answer = await real(self, session, method, params, within)
        if method == "keyboardReport" and params.get("keys"):
            session.taken = True  # (its own page takes the viewer in the moment after the press was answered)
        return answer

    monkeypatch.setattr(jetkvm.JetKvmDevice, "_call", call)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360)).start()

    async def typing() -> None:
        device = jetkvm.JetKvmDevice(kvm.DeviceSpec("w", "the wall", jet.url, "", "secret", kind="jetkvm"))
        try:
            with pytest.raises(kvm.KvmError) as said:
                await device.act("text", text="ab")
            assert said.value.code == "in_use" and "after 1 of 2 keys" in said.value.message, said.value.message
        finally:
            await device.close()

    try:
        asyncio.run(typing())
        assert after == [], f"{len(after)} reports went after the JetKVM's own page took it"
    finally:
        jet.stop()


def test_letting_go_of_the_keys_sends_nothing_once_the_jetkvms_own_page_has_the_viewer(monkeypatch: pytest.MonkeyPatch) -> None:
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360)).start()
    sent: list[str] = []

    async def run() -> None:
        device = jetkvm.JetKvmDevice(kvm.DeviceSpec("w", "the wall", jet.url, "", "secret", kind="jetkvm"))
        try:
            session = await device._connected()
            monkeypatch.setattr(session.rpc, "send", sent.append)
            session.taken = True
            device._let_go(session)
            assert sent == [], "a letting go went to whoever took the JetKVM's viewer"
            session.taken = False
            device._let_go(session)
            assert len(sent) == 1 and '"keys": []' in sent[0]  # (and while the viewer is the wall's, it is said)
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        jet.stop()


@pytest.mark.parametrize(("who", "cuts"), [("the tile", 1), ("the tile", 2), ("the alerts' look", 1)])
def test_a_status_read_under_way_as_the_wall_makes_the_connection_anew_is_not_the_jetkvm_going_offline(monkeypatch: pytest.MonkeyPatch, who: str, cuts: int) -> None:
    # (Found under load, W1b: the test below saw the tile say "offline" once. A status read under way when the wall made the
    # connection anew had its question cut off by the wall's own doing, and took that for the JetKVM no longer answering. On
    # an idle computer the question is answered within milliseconds, and the window was seldom met; here it is held open.)
    # The tile's look asks again over the new connection, once (`cuts` 2: cut off again, what was known stands, and no third
    # connection is made); the alerts' look makes no connection for it (it would take the JetKVM's one viewer: the second
    # reviewer's finding), and what was known stands.
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360)).start()
    held: set[tuple[int, int]] = set()  # (the connection, the number of the call on it)
    holding = [0]  # getVideoState questions still to leave unanswered
    real_call, real_heard = jetkvm.JetKvmDevice._call, jetkvm.JetKvmDevice._on_message
    asked = asyncio.Event()

    async def call(self: Any, session: Any, method: str, params: Any = None, within: Any = None) -> Any:
        if method == "getVideoState" and holding[0] > 0:
            holding[0] -= 1
            held.add((id(session), session.next_id + 1))  # (not answered: the connection is made anew under it)
            asked.set()
        return await real_call(self, session, method, params, within)

    def heard(self: Any, session: Any, message: Any) -> None:
        try:
            said = json.loads(message) if isinstance(message, str) else None
        except ValueError:
            said = None
        if isinstance(said, dict) and (id(session), said.get("id")) in held:
            return
        real_heard(self, session, message)

    monkeypatch.setattr(jetkvm.JetKvmDevice, "_call", call)
    monkeypatch.setattr(jetkvm.JetKvmDevice, "_on_message", heard)

    async def main() -> None:
        wall = jetkvm.JetKvmDevice(kvm.DeviceSpec("w", "the wall", jet.url, "", "secret", kind="jetkvm"))
        try:
            await wall._connected(urgent=True)
            wall._status_at = 0.0
            await wall._refresh_status()
            assert wall._status is not None and wall._status["state"] == "online", wall._status
            holding[0] = cuts
            reading = asyncio.ensure_future(wall.probe() if who == "the alerts' look" else wall._refresh_status())
            for _ in range(cuts):
                await asyncio.wait_for(asked.wait(), 30)
                asked.clear()
                assert wall._session is not None
                wall._make_anew(wall._session, "a key it was sent was not answered in time")
            said = await asyncio.wait_for(reading, 60)
            assert wall._status is not None and wall._status["state"] == "online", wall._status
            if who == "the alerts' look":
                assert said == "online" and jet.state.sessions == 1, (said, jet.state.sessions)
            else:
                assert jet.state.sessions == 2, jet.state.sessions
        finally:
            await wall.close()

    try:
        asyncio.run(main())
    finally:
        jet.stop()


@pytest.mark.parametrize("who", ["the alerts' look", "the tile"])
def test_a_jetkvm_that_stops_answering_over_a_live_connection_is_said_offline(monkeypatch: pytest.MonkeyPatch, who: str) -> None:
    # (The third reviewer's E9: where every unanswered question were taken for the wall's own making anew, a JetKVM that
    # lost its power over a live connection was said online, by the tile and by the alerts' look.)
    monkeypatch.setattr(jetkvm, "RPC_TIMEOUT", 1.0)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360)).start()
    said: list[Any] = []

    async def main() -> None:
        wall = jetkvm.JetKvmDevice(kvm.DeviceSpec("w", "the wall", jet.url, "", "secret", kind="jetkvm"))
        try:
            await wall._connected(urgent=True)
            await wall._refresh_status()
            assert (wall._status or {}).get("state") == "online", wall._status
            jet.state.frozen = True  # (no answers, no pictures: it lost power, say)
            if who == "the alerts' look":
                said.append(await asyncio.wait_for(wall.probe(), 60))
            else:
                await asyncio.wait_for(wall._refresh_status(), 60)
                said.append((wall._status or {}).get("state"))
        finally:
            jet.state.frozen = False  # (a frozen stand-in does not stop: its pictures wait for ever)
            await wall.close()

    try:
        asyncio.run(main())
    finally:
        jet.stop()
    assert said == ["offline"], said


def slow_to_end(monkeypatch: pytest.MonkeyPatch) -> None:
    """The wall's end of a connection made anew takes a second: the time in which something can happen meanwhile."""
    real = jetkvm.JetKvmDevice._let_go_before_closing

    async def slow(self: Any, session: Any, wait: bool) -> None:
        await asyncio.sleep(1.0)
        await real(self, session, wait)

    monkeypatch.setattr(jetkvm.JetKvmDevice, "_let_go_before_closing", slow)


@pytest.mark.parametrize("meanwhile", ["its own page took the viewer", "the tile was removed"])
def test_nothing_is_connected_where_the_viewer_was_taken_or_the_tile_removed_while_the_old_connection_ended(monkeypatch: pytest.MonkeyPatch, meanwhile: str) -> None:
    # (The third reviewer's E4a and E4c: a connection asked for while the one made anew was ending was made all the same:
    # it took the viewer back from a person at the JetKVM's own page, or was started on a client being retired.)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360)).start()
    other = json.dumps({"jsonrpc": "2.0", "method": "otherSessionConnected", "params": None})
    out: dict[str, Any] = {}

    async def main() -> None:
        wall = jetkvm.JetKvmDevice(kvm.DeviceSpec("w", "the wall", jet.url, "", "secret", kind="jetkvm"))
        try:
            first = await wall._connected(urgent=True)
            slow_to_end(monkeypatch)
            task = wall._task
            wall._make_anew(first, "a key it was sent was not answered in time")
            waiting = asyncio.ensure_future(wall._connected())
            await asyncio.sleep(0.3)
            assert not waiting.done()
            closing = None
            if meanwhile == "its own page took the viewer":
                wall._on_message(first, other)  # (the JetKVM says so over the connection that is ending)
            else:
                closing = asyncio.ensure_future(wall.close())
            with pytest.raises(kvm.KvmError) as raised:
                await asyncio.wait_for(waiting, 40)
            out["raised"] = raised.value
            if closing is not None:
                await closing
            out["started"] = wall._task is not task
            await asyncio.sleep(0.5)
            out["sessions"] = jet.state.sessions
        finally:
            await wall.close()

    try:
        asyncio.run(main())
    finally:
        jet.stop()
    if meanwhile == "its own page took the viewer":
        assert out["raised"].code == "in_use" and out["sessions"] == 1, out
    else:
        assert out["raised"] is kvm.RETIRED and not out["started"] and out["sessions"] == 1, out


def test_a_status_read_whose_power_question_alone_was_cut_off_asks_again(monkeypatch: pytest.MonkeyPatch) -> None:
    # (The third reviewer's E10: where only the video question was looked at, a power extension's question cut off by the
    # wall's own making anew took the power buttons off the tile for a look.)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, extension="atx-power")).start()
    held: set[tuple[int, int]] = set()
    holding = [0]
    real_call, real_heard = jetkvm.JetKvmDevice._call, jetkvm.JetKvmDevice._on_message

    async def call(self: Any, session: Any, method: str, params: Any = None, within: Any = None) -> Any:
        if method == "getActiveExtension" and holding[0] > 0:
            holding[0] -= 1
            held.add((id(session), session.next_id + 1))
        return await real_call(self, session, method, params, within)

    def heard(self: Any, session: Any, message: Any) -> None:
        said = json.loads(message) if isinstance(message, str) else None
        if isinstance(said, dict) and (id(session), said.get("id")) in held:
            return
        real_heard(self, session, message)

    monkeypatch.setattr(jetkvm.JetKvmDevice, "_call", call)
    monkeypatch.setattr(jetkvm.JetKvmDevice, "_on_message", heard)

    async def main() -> None:
        wall = jetkvm.JetKvmDevice(kvm.DeviceSpec("w", "the wall", jet.url, "", "secret", kind="jetkvm"))
        try:
            await wall._connected(urgent=True)
            await wall._refresh_status()
            assert "power" in (wall._status or {}).get("can", []), wall._status
            holding[0] = 1
            reading = asyncio.ensure_future(wall._refresh_status())
            while holding[0] > 0:
                await asyncio.sleep(0.01)
            await asyncio.sleep(0.3)  # (the other three answered meanwhile)
            assert wall._session is not None
            wall._make_anew(wall._session, "a key it was sent was not answered in time")
            await asyncio.wait_for(reading, 60)
            status = wall._status or {}
            assert status.get("state") == "online" and (status.get("atx") or {}).get("enabled") is True and "power" in status.get("can", []), status
            assert jet.state.sessions == 2
        finally:
            await wall.close()

    try:
        asyncio.run(main())
    finally:
        jet.stop()


def test_a_connection_made_anew_by_the_wall_is_not_the_jetkvm_going_offline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    # (Found by the second review: the tile, the line and the log said the JetKVM was offline for a moment, of a
    # JetKVM that is there: it was the wall that ended the connection.)
    monkeypatch.setattr(jetkvm, "TAKE_WITHIN", 1.0, raising=False)
    caplog.set_level(logging.INFO, logger="qkvm")
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360)).start()
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, jet.url)
            line = wall.line(admin, device, max_fps=5)
            assert line.picture(timeout=20).kind == 2
            line.say(t="control", on=True)
            assert line.word("control")["on"] is True
            sessions = jet.state.sessions
            jet.state.together = 1.5
            line.say(t="k", u=0x05, d=True)
            line.say(t="k", u=0x05, d=False)
            states = []
            began = time.monotonic()
            while time.monotonic() - began < 6:
                states.append(admin.get("/api/v1/status").json()[device]["state"])
                if time.monotonic() - began > 2:
                    jet.state.together = 0.005
                time.sleep(0.05)
            assert jet.state.sessions > sessions, "the connection was not made anew"
            assert set(states) == {"online"}, states
            said = []
            while True:
                try:
                    said.append(line.word("state", timeout=0.3))
                except TimeoutError:
                    break
            assert all(word["state"] == "online" for word in said), said
            assert not [record.getMessage() for record in caplog.records if record.levelno >= logging.WARNING]
            assert "made anew" in caplog.text
            line.close()
    finally:
        jet.stop()


def test_fake_handover_keeps_pending_connection_cleanup_alive() -> None:
    """A delayed close must remain owned even while its only wait is internal."""
    import gc
    from tests.fake_jetkvm import make_fake_jetkvm

    async def main() -> None:
        loop = asyncio.get_running_loop()
        errors = []
        previous = loop.get_exception_handler()
        loop.set_exception_handler(lambda loop, context: errors.append(context))
        started, finished = asyncio.Event(), asyncio.Event()

        class Peer:
            async def close(self) -> None:
                started.set()
                try:
                    await loop.create_future()
                finally:
                    finished.set()

        app = make_fake_jetkvm(JetState(hand_over_close=0))
        app.state.current.update(pc=Peer(), rpc=None, hid=None)
        before = asyncio.all_tasks()
        try:
            app.state.hand_over()
            await asyncio.wait_for(started.wait(), 1)
            gc.collect()
            await asyncio.sleep(0)
            assert not errors, [item.get("message") for item in errors]
            assert not finished.is_set(), "pending close was garbage collected"
        finally:
            pending = asyncio.all_tasks() - before
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            loop.set_exception_handler(previous)

    asyncio.run(main())
