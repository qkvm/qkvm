"""A JetKVM whose own page takes its one viewer while a key or a mouse button of ours is on its way (track W14b).

The JetKVM lets go of everything as it hands its viewer over, and does what the previous viewer still sends until it
closes that connection, letting go of none of that then: it is no longer that viewer's. Its channel keeps the order of
what it says, so the answer to a press it did after the hand-over comes after its "otherSessionConnected". The rule:
after a hand-over nothing more of ours goes to it, but a letting go of what may have been pressed after the hand-over.

| The press (keys or mouse buttons) | Done | What qKVM sends after the hand-over | Test |
|---|---|---|---|
| answered before "otherSessionConnected" | before the hand-over: let go of by the JetKVM | nothing (an action stops with 409 `in_use`, or ends as done where it was its last key) | 1, 5, 8 |
| answered after it | after the hand-over: down for whoever has the viewer | one letting go, at once, not waited for | 2, 6, 7 |
| never answered (no answer in time) | unknown | one letting go, while the connection is open; then the connection is ended (where nobody took over, that end lets go too: test 4 pins the letting go before it) | 3, 4 |
| still in the JetKVM's hands when the wall steps aside | done after the hand-over | its answer is waited for (HAND_OVER_GRACE), then one letting go, in turn | 10, 13 (the tile closed meanwhile) |
| its own wait ran out, and it is answered after all | done, maybe after the letting go sent then | one more letting go, in turn, as the answer comes; after a hand-over the wall waits for that answer too (HAND_OVER_GRACE) | 14, 17, 18 |
| never answered, and the wall's wait is over first | unknown | one letting go, from the end of the connection, while it is open | 16 |
| a power press asked about while the hand-over came | (not pressed) | nothing | 9; the question cut off, or unanswered: 20 |
| anything but a letting go (a question, the status, a key) | | nothing: refused; the status says busy | 11, 12, 19, 21 |
| cut off by the connection's end, however it ended: a hand-over, the tile edited or removed, the wall making it anew or giving it up | maybe | answered "may have been done" (a power press: "unknown" in the history), not "dropped" | 15, 22, 24 |
| its own wait running out in the same turn of the loop as the wall looks at the hand-over | done, maybe after the letting go sent then | the wait for answers still waits for its answer, and lets go of it in turn | 23 |
| (the wait itself) | | it ends as soon as nothing more is owed, or the channel closes; a stop of the wall while it waits still closes the connection | 26, 27 |

The stand-in hands its viewer over at the moment a test chooses (`JetState.take_over_at`). Every test looks at what is
down on it at the end. All of them on JSON-RPC, the road an older JetKVM takes (it has no hidrpc channel): the same on
hidrpc is in `test_a_jetkvm_over_hidrpc.py`.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
from collections.abc import Callable
from typing import Any

import pytest

from qkvm import jetkvm, kvm
from tests.fake_jetkvm import FakeJetKvm, JetState, presses_wait

PRESS_A = {"modifier": 0, "keys": [0x04]}
NOTHING = {"modifier": 0, "keys": []}


@pytest.fixture(autouse=True)
def no_long_handshake(monkeypatch: pytest.MonkeyPatch) -> None:
    # (The stand-in here leaves the hidrpc channel unanswered, as an older JetKVM: keys go over JSON-RPC once the wall
    # has given up asking, which is not waited for the whole two seconds in every test.)
    monkeypatch.setattr(jetkvm, "HID_SHAKE_WITHIN", 0.3)


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
            await wall._connected(urgent=True)
            await test(wall)
        finally:
            await wall.close()

    try:
        asyncio.run(inside())
    finally:
        jet.stop()


# --- an action that types or presses keys --------------------------------------------------------------------------


def test_1_a_key_pressed_before_the_hand_over_is_not_let_go_of_after_it(monkeypatch: pytest.MonkeyPatch) -> None:
    # The hand-over comes in the pause between a key's press (answered) and its release: the JetKVM let go of it then.
    # (A pause long enough for the wall to hear of the hand-over within it, as in test 5: in a tenth of a second a busy
    # computer had not, the release went as it must where nothing is known yet, and that is another case.)
    monkeypatch.setattr(jetkvm, "KEY_PAUSE", 1.5)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, take_over_at=("after", 1, 0.03))).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        with pytest.raises(kvm.KvmError) as said:
            await wall.act("text", text="ab")
        assert said.value.code == "in_use" and "after 1 of 2 keys" in said.value.message, said.value.message
        await settled(lambda: jet.state.hand_overs == 1)
        assert jet.state.reports == [(0, [0x04])], f"something of ours went after the hand-over: {jet.state.reports}"
        assert jet.state.done_after_hand_over == []
        assert nothing_down(jet)

    run(jet, test)


def test_2_a_key_the_jetkvm_pressed_after_the_hand_over_is_let_go_of_at_once() -> None:
    # The hand-over comes while the press is in the JetKVM's hands: it does the press after it, and answers after
    # saying "otherSessionConnected". (On the program as it was, the key stayed down for whoever had taken the viewer.)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, together=0.05, take_over_at=("before", 1, 0))).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        with pytest.raises(kvm.KvmError) as said:
            await wall.act("text", text="ab")
        assert said.value.code == "in_use" and "after 1 of 2 keys" in said.value.message, said.value.message
        # (Waited for until the press was done after the hand-over and its letting go came: the hand-over itself left
        # nothing down, which a wait for "nothing down" took for the end.)
        await settled(lambda: len(jet.state.done_after_hand_over) >= 2)
        assert jet.state.done_after_hand_over == [("keyboardReport", PRESS_A), ("keyboardReport", NOTHING)]
        assert nothing_down(jet), f"down for whoever took the viewer: {jet.state.down}"

    run(jet, test)


def test_3_a_key_never_answered_while_the_hand_over_came_is_let_go_of_before_the_connection_ends(monkeypatch: pytest.MonkeyPatch) -> None:
    presses_wait(monkeypatch, 0.5)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, hand_over_close=3.0, take_over_at=("silent", 1, 0))).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        with pytest.raises(kvm.KvmError) as said:
            await wall.act("text", text="ab")
        # (The call's own time ran out: the wall waited for it before it stepped aside, rather than cutting it off.)
        assert (said.value.code, said.value.message) == ("timeout", "The JetKVM did not answer in time"), said.value.message
        await settled(lambda: len(jet.state.done_after_hand_over) >= 2)
        assert jet.state.done_after_hand_over == [("keyboardReport", PRESS_A), ("keyboardReport", NOTHING)]
        assert nothing_down(jet), f"down for whoever took the viewer: {jet.state.down}"

    run(jet, test)


def test_4_a_key_never_answered_is_let_go_of_and_the_connection_ended_where_nobody_took_over(monkeypatch: pytest.MonkeyPatch) -> None:
    waits = presses_wait(monkeypatch, 0.5)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, take_over_at=("silent_only", 1, 0))).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        sessions = jet.state.sessions
        with pytest.raises(kvm.KvmError) as said:
            await wall.act("text", text="ab")
        assert said.value.code == "timeout", said.value.message
        await settled(lambda: len(jet.state.reports) >= 2)  # (the press, done late, and its letting go)
        assert jet.state.reports == [(0, [0x04]), (0, [])], jet.state.reports  # (let go of; nothing typed after it)
        assert nothing_down(jet)
        waits["seconds"] = None  # (as the wall waits: a busy computer answered the next press later than half a second)
        await wall.act("text", text="b")  # a new connection, and the next text goes through
        assert jet.state.sessions == sessions + 1 and jet.state.reports[-2:] == [(0, [0x05]), (0, [])]

    run(jet, test)


@pytest.mark.parametrize(("action", "pressed"), [("ctrl_alt_del", (0x05, [0x4C])), ("text", (0, [0x04]))])
def test_5_the_last_key_of_an_action_done_before_the_hand_over_is_an_action_done(monkeypatch: pytest.MonkeyPatch, action: str, pressed: tuple[int, list[int]]) -> None:
    # (On the program as it was: 409, and a run over several KVMs offered "Retry failed", which presses Ctrl+Alt+Del or
    # types a saved text again. Here the keys were pressed, and the JetKVM let go of them as it handed the viewer over.)
    # (The pause after a typed key, and the hold of a combination: the hand-over comes 30 ms into it, and the wall hears
    # of it before the pause is over. A busy computer took more than a tenth of a second to hear of it; then the release
    # went, as it must where nothing is known yet, and this was another case: the last row of the table.)
    monkeypatch.setattr(jetkvm, "KEY_PAUSE", 1.5)
    monkeypatch.setattr(jetkvm, "HOLD", 1.5)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, take_over_at=("after", 1, 0.03))).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        await wall.act(action, text="a")  # done: no error
        await settled(lambda: jet.state.hand_overs == 1)
        assert jet.state.reports == [pressed] and jet.state.done_after_hand_over == []
        assert nothing_down(jet)

    run(jet, test)


# --- the live line ---------------------------------------------------------------------------------------------------


def test_6_a_key_from_the_live_line_the_jetkvm_pressed_after_the_hand_over_is_let_go_of() -> None:
    # (On the program as it was, the release that waited was dropped at the hand-over, and the key stayed down.)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, together=0.05, take_over_at=("before", 1, 0))).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        wall.say("keyboardReport", dict(PRESS_A), on=held)
        wall.say("keyboardReport", dict(NOTHING), on=held)
        await settled(lambda: len(jet.state.done_after_hand_over) >= 2)  # (the hand-over itself left nothing down: see test 2)
        assert jet.state.done_after_hand_over == [("keyboardReport", PRESS_A), ("keyboardReport", NOTHING)]
        assert nothing_down(jet), f"down for whoever took the viewer: {jet.state.down}"
        with pytest.raises(kvm.KvmError):
            wall.say("keyboardReport", dict(PRESS_A), on=held)  # (and nothing more goes)

    run(jet, test)


def test_7_a_mouse_button_the_jetkvm_pressed_after_the_hand_over_is_let_go_of() -> None:
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, together=0.05, take_over_at=("before", 1, 0))).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        wall.say("absMouseReport", {"x": 100, "y": 200, "buttons": 1}, on=held)
        wall.say("absMouseReport", {"x": 100, "y": 200, "buttons": 0}, on=held)
        await settled(lambda: len(jet.state.done_after_hand_over) >= 2)  # (the hand-over itself left nothing down: see test 2)
        assert jet.state.done_after_hand_over == [("absMouseReport", {"x": 100, "y": 200, "buttons": 1}), ("absMouseReport", {"x": 100, "y": 200, "buttons": 0})]
        assert nothing_down(jet), f"a button down for whoever took the viewer: {jet.state.buttons}"

    run(jet, test)


def test_8_a_key_from_the_live_line_pressed_before_the_hand_over_is_not_let_go_of_after_it() -> None:
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, take_over_at=("after", 1, 0.0))).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        wall.say("keyboardReport", dict(PRESS_A), on=held)
        await settled(lambda: jet.state.hand_overs == 1)
        assert jet.state.reports == [(0, [0x04])] and jet.state.done_after_hand_over == []
        assert nothing_down(jet)

    run(jet, test)


# --- the power button ------------------------------------------------------------------------------------------------


def test_9_a_power_press_is_not_made_where_the_hand_over_came_while_the_extension_was_asked_about(monkeypatch: pytest.MonkeyPatch) -> None:
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, extension="atx-power")).start()
    real = jetkvm.JetKvmDevice._call

    async def call(self: Any, session: Any, method: str, params: Any = None, within: Any = None) -> Any:
        answer = await real(self, session, method, params, within)
        if method == "getActiveExtension":
            jet.hand_over()  # its own page takes the viewer as the answer comes
            for _ in range(200):
                if session.taken:
                    break
                await asyncio.sleep(0.01)
        return answer

    monkeypatch.setattr(jetkvm.JetKvmDevice, "_call", call)

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        with pytest.raises(kvm.KvmError) as said:
            await wall.act("atx_power")
        assert said.value.code == "in_use"
        await asyncio.sleep(0.3)
        assert jet.state.actions == [], f"pressed on a machine somebody else has: {jet.state.actions}"

    run(jet, test)


@pytest.mark.parametrize("by", ["typing", "the live line"])
def test_10_a_press_still_in_the_jetkvms_hands_when_the_wall_steps_aside_is_let_go_of_in_turn(by: str) -> None:
    # The JetKVM does the press 1.2 s after it came, and the wall notices the hand-over within a second: it waits for the
    # answer before it closes the connection, and lets go after it. (Let go of as the connection was closed, before the
    # answer, the letting go was done before the press, both in the JetKVM's hands at once, and the key stayed down.)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, together=1.2, hand_over_close=3.0, take_over_at=("before", 1, 0))).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        if by == "typing":
            with pytest.raises(kvm.KvmError) as said:
                await wall.act("text", text="ab")
            assert said.value.code == "in_use", said.value.message
        else:
            held = await wall.input_ready()
            wall.say("keyboardReport", dict(PRESS_A), on=held)
            wall.say("keyboardReport", dict(NOTHING), on=held)
        await settled(lambda: len(jet.state.done_after_hand_over) >= 2, within=5)
        assert jet.state.done_after_hand_over == [("keyboardReport", PRESS_A), ("keyboardReport", NOTHING)]
        assert nothing_down(jet), f"down for whoever took the viewer: {jet.state.down}"

    run(jet, test)


def test_11_show_here_a_moment_after_the_hand_over_makes_a_new_connection() -> None:
    # (Found by the review: "Show here" right after the hand-over took up the connection that had been taken, asked over
    # it, and called the tile online; typing then was refused.)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        sessions = jet.state.sessions
        jet.hand_over()
        for _ in range(200):
            if wall._session is not None and wall._session.taken:
                break
            await asyncio.sleep(0.01)
        await wall.act("resume")
        assert jet.state.sessions == sessions + 1, "the connection that had been taken was used again"
        await wall.act("text", text="b")
        assert jet.state.reports[-2:] == [(0, [0x05]), (0, [])]

    run(jet, test)


def test_12_a_status_read_whose_answers_came_after_the_hand_over_says_busy(monkeypatch: pytest.MonkeyPatch) -> None:
    # (Found by the second review: asked just before the hand-over and answered after it, the status said "online" over
    # the "busy" the hand-over had set, for the tile, the history and the live line.)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360)).start()
    real = jetkvm.JetKvmDevice._call

    async def call(self: Any, session: Any, method: str, params: Any = None, within: Any = None) -> Any:
        if method == "getVideoState":
            jet.hand_over()  # its own page takes the viewer as the status is being asked
        return await real(self, session, method, params, within)

    monkeypatch.setattr(jetkvm.JetKvmDevice, "_call", call)

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        wall._status_at = 0.0
        await wall._refresh_status()
        assert wall._session is not None and wall._session.taken
        assert wall._status is not None and wall._status["state"] == "busy", wall._status

    run(jet, test)


def test_13_a_tile_closed_while_a_press_is_in_the_jetkvms_hands_after_the_hand_over_lets_go_of_it_in_turn() -> None:
    # (Found by the second review: edited, removed or stopped in those seconds, the wall let go of the press as it
    # closed, before the JetKVM had done it, and the key stayed down for whoever took the viewer.)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, together=1.8, hand_over_close=5.0, take_over_at=("before", 1, 0))).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        wall.say("keyboardReport", dict(PRESS_A), on=held)
        await asyncio.sleep(1.0)
        await wall.close()  # (as an edit, a removal or the wall stopping do)
        await settled(lambda: len(jet.state.done_after_hand_over) >= 2, within=4)
        assert jet.state.done_after_hand_over == [("keyboardReport", PRESS_A), ("keyboardReport", NOTHING)]
        assert nothing_down(jet), f"down for whoever took the viewer: {jet.state.down}"

    run(jet, test)


def test_14_a_press_the_wall_gave_up_on_that_is_answered_after_all_is_let_go_of_again_then() -> None:
    # (Found by the second review: the letting go sent as the wait was given up could be done before the press, and an
    # answer that came later was not listened to.)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        session = wall._session
        assert session is not None
        sent: list[str] = []
        real_send = session.rpc.send
        session.rpc.send = lambda text: (sent.append(text), real_send(text))
        session.given_up[999] = ("keyboardReport", dict(PRESS_A))
        wall._on_message(session, '{"jsonrpc": "2.0", "id": 999, "result": null}')
        assert len(sent) == 1 and '"keys": []' in sent[0], sent
        wall._on_message(session, '{"jsonrpc": "2.0", "id": 999, "result": null}')  # (once)
        assert len(sent) == 1

    run(jet, test)


def test_15_what_the_wall_cut_off_after_the_hand_over_may_have_been_done(monkeypatch: pytest.MonkeyPatch) -> None:
    # (Found by the second review: cut off as the wall stepped aside, it was "dropped", which a power press records as not
    # pressed; the JetKVM may still do it. Here the press is done four seconds after it came, past the wall's wait (up to a
    # second to notice the hand-over, and HAND_OVER_GRACE, on however coarse a clock): it is the open case, and the key
    # stays down for whoever took the viewer, as the README's Limits says. Done four seconds after it came, it was
    # answered before the wall gave up where the computer was busy, and the action was done: here the stand-in does it
    # as the wall closes the connection, which is after the wall's whole wait whatever the clock says.)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, together=600.0, hand_over_close=600.0, take_over_at=("before", 1, 0))).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        with pytest.raises(kvm.KvmError) as said:
            await wall.act("text", text="a")
        assert said.value.code == "timeout" and "may have been done" in said.value.message, said.value.message
        assert said.value.status == 504

    run(jet, test)


def answer_to(message: Any) -> Any:
    """The number of the call a message from the stand-in answers (None for anything else)."""
    try:
        said = json.loads(message)
    except (TypeError, ValueError):
        return None
    return said.get("id") if isinstance(said, dict) else None


def test_16_a_press_never_answered_while_the_wall_waits_out_its_grace_is_let_go_of_at_the_connections_end() -> None:
    # The press is done and never answered; its own wait (RPC_TIMEOUT, eight seconds) is longer than the wall's grace
    # after the hand-over, so only the connection's end can let go of it, while the JetKVM still has the connection open.
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, hand_over_close=6.0, take_over_at=("silent", 1, 0))).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        with pytest.raises(kvm.KvmError) as said:
            await wall.act("text", text="ab")
        assert said.value.code == "timeout" and "may have been done" in said.value.message, said.value.message
        await settled(lambda: nothing_down(jet))
        assert jet.state.done_after_hand_over == [("keyboardReport", PRESS_A), ("keyboardReport", NOTHING)]
        assert nothing_down(jet), f"down for whoever took the viewer: {jet.state.down}"

    run(jet, test)


def test_17_a_press_whose_wait_ran_out_and_that_is_answered_after_all_is_let_go_of_in_turn() -> None:
    # Made by `_call` itself (test 14 sets it up by hand): its wait runs out first, the letting go sent then is done before
    # the press (both in the stand-in's hands at once), and the press's answer, after all, brings another, in turn.
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, together=0.8)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        session = wall._session
        assert session is not None
        with pytest.raises(kvm.KvmError) as said:
            await wall._call(session, "keyboardReport", dict(PRESS_A), within=0.3)
        assert said.value.code == "timeout"
        await settled(lambda: len(jet.state.reports) >= 3, within=3)
        assert jet.state.reports == [(0, []), (0, [0x04]), (0, [])], jet.state.reports
        assert nothing_down(jet), f"down: {jet.state.down}"

    run(jet, test)


@pytest.mark.parametrize("by", ["the hand-over noticed", "the tile closed"])
def test_18_after_a_hand_over_the_wall_waits_for_the_answer_to_a_press_whose_own_wait_ran_out(monkeypatch: pytest.MonkeyPatch, by: str) -> None:
    # (Found by the third review: the grace waited only for calls still under way. A live-line press done 1.6 s after it
    # was sent, its own wait over at 1.0 s and the page taking over at 0.5 s: the letting go sent at 1.0 s was done
    # before the press, the wall closed at the next look, the answer at 1.6 s never came, and the key stayed down.)
    monkeypatch.setattr(jetkvm, "TAKE_WITHIN", 1.0)
    monkeypatch.setattr(jetkvm, "HAND_OVER_GRACE", 3.0)  # (noticed 0.3 to 1.3 s in, waited for until 3.3 s at least)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, together=2.0, hand_over_close=6.0)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        wall.say("keyboardReport", dict(PRESS_A), on=held)
        await asyncio.sleep(0.3)
        jet.hand_over()  # (the wall notices it within a second: well before the press's answer, 2 s after it went)
        if by == "the tile closed":
            await asyncio.sleep(0.9)  # (its own wait is over, the press not yet done)
            await wall.close()
        await settled(lambda: len(jet.state.done_after_hand_over) >= 3, within=4)
        assert jet.state.done_after_hand_over[-2:] == [("keyboardReport", PRESS_A), ("keyboardReport", NOTHING)], jet.state.done_after_hand_over
        assert nothing_down(jet), f"down for whoever took the viewer: {jet.state.down}"

    run(jet, test)


def test_19_nothing_but_a_letting_go_goes_after_the_hand_over() -> None:
    # A press the JetKVM does after the hand-over is let go of; a question asked then, a key and a letting go said then,
    # go nowhere. They are asked while the connection is still open: the press is done 1.5 s after it came, and the wall
    # waits for its answer before it closes. (On a mutant whose `_call` no longer refuses when taken, the question went.)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, together=1.5, hand_over_close=4.0, take_over_at=("before", 1, 0))).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session)
        wall.say("keyboardReport", dict(PRESS_A), on=held)
        for _ in range(300):
            if held.taken:
                break
            await asyncio.sleep(0.005)
        assert held.taken and held.live, "the connection is to be open still"
        for method in ("getVideoState", "getWakeOnLanDevices", "keyboardReport"):
            with pytest.raises(kvm.KvmError) as refused:
                await wall._call(held, method, dict(PRESS_A) if method == "keyboardReport" else None)
            assert refused.value.code == "in_use", (method, refused.value.code)
        with pytest.raises(kvm.KvmError):
            wall.say("keyboardReport", dict(NOTHING), on=held)
        await settled(lambda: nothing_down(jet) and len(jet.state.done_after_hand_over) >= 2, within=4)
        assert jet.state.asked_after_hand_over == [], jet.state.asked_after_hand_over
        assert jet.state.done_after_hand_over == [("keyboardReport", PRESS_A), ("keyboardReport", NOTHING)]
        assert nothing_down(jet)

    run(jet, test)


@pytest.mark.parametrize("by", ["the hand-over", "no answer in time"])
def test_20_a_power_action_whose_question_was_cut_off_pressed_nothing_and_says_so(monkeypatch: pytest.MonkeyPatch, by: str) -> None:
    # (Found by the third review: the question whether the power extension is on, cut off as the wall stepped aside, was
    # answered "may have been done", and the history wrote "unknown" of a press never made. Unanswered in time, nobody
    # taking over, it was a 504 "did not answer in time", which says the same.)
    if by == "no answer in time":
        monkeypatch.setattr(jetkvm, "RPC_TIMEOUT", 0.5)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, extension="atx-power")).start()
    held_back: set[int] = set()
    real_call, real_heard = jetkvm.JetKvmDevice._call, jetkvm.JetKvmDevice._on_message

    async def call(self: Any, session: Any, method: str, params: Any = None, within: Any = None) -> Any:
        if method == "getActiveExtension":
            held_back.add(session.next_id + 1)  # (the number this call is about to get)
        return await real_call(self, session, method, params, within)

    def heard(self: Any, session: Any, message: Any) -> None:
        if answer_to(message) in held_back:
            return  # its answer is slow, still on its way when the hand-over comes
        real_heard(self, session, message)

    monkeypatch.setattr(jetkvm.JetKvmDevice, "_call", call)
    monkeypatch.setattr(jetkvm.JetKvmDevice, "_on_message", heard)

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        acting = asyncio.ensure_future(wall.act("atx_power"))
        await asyncio.sleep(0.3)
        if by == "the hand-over":
            jet.hand_over()
        with pytest.raises(kvm.KvmError) as said:
            await acting
        if by == "the hand-over":
            assert said.value.code == "in_use" and said.value.status == 409, (said.value.code, said.value.message)
        else:
            assert said.value.code == "action_failed" and said.value.message.startswith("Nothing was pressed"), said.value.message
        assert jet.state.actions == []

    run(jet, test)


def test_21_a_status_read_with_the_power_extension_on_that_the_hand_over_came_into_says_busy(monkeypatch: pytest.MonkeyPatch) -> None:
    # (The look after the power board's question: the hand-over came while it was asked.)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, extension="atx-power")).start()
    real = jetkvm.JetKvmDevice._call

    async def call(self: Any, session: Any, method: str, params: Any = None, within: Any = None) -> Any:
        answer = await real(self, session, method, params, within)
        if method == "getATXState":
            jet.hand_over()
            for _ in range(200):
                if session.taken:
                    break
                await asyncio.sleep(0.01)
        return answer

    monkeypatch.setattr(jetkvm.JetKvmDevice, "_call", call)

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        wall._status_at = 0.0
        await wall._refresh_status()
        assert wall._session is not None and wall._session.taken
        assert wall._status is not None and wall._status["state"] == "busy", wall._status

    run(jet, test)


@pytest.mark.parametrize("by", ["the tile closed", "the connection made anew"])
def test_22_a_power_press_cut_off_by_the_walls_own_end_of_the_connection_may_have_been_done(monkeypatch: pytest.MonkeyPatch, by: str) -> None:
    # (Found by the third review: edited, removed, the wall locking itself, while the press was in the JetKVM's hands,
    # nobody else there: pressed, and answered "dropped", which the history writes as "not pressed".)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, extension="atx-power")).start()
    held_back: set[int] = set()
    real_call, real_heard = jetkvm.JetKvmDevice._call, jetkvm.JetKvmDevice._on_message

    async def call(self: Any, session: Any, method: str, params: Any = None, within: Any = None) -> Any:
        if method == "setATXPowerAction":
            held_back.add(session.next_id + 1)
        return await real_call(self, session, method, params, within)

    def heard(self: Any, session: Any, message: Any) -> None:
        if answer_to(message) in held_back:
            return  # its answer is slow: still on its way
        real_heard(self, session, message)

    monkeypatch.setattr(jetkvm.JetKvmDevice, "_call", call)
    monkeypatch.setattr(jetkvm.JetKvmDevice, "_on_message", heard)

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        acting = asyncio.ensure_future(wall.act("atx_power"))
        for _ in range(500):
            if jet.state.actions:
                break
            await asyncio.sleep(0.01)
        assert not acting.done() and jet.state.actions == ["atx power-short"]
        if by == "the tile closed":
            await wall.close()  # (an edit of the tile, its removal, the wall locking itself or stopping)
        else:
            assert wall._session is not None
            wall._make_anew(wall._session, "a test made it anew")
        with pytest.raises(kvm.KvmError) as said:
            await acting
        if by == "the tile closed":
            assert said.value is kvm.RETIRED  # (what the server answers "may have been done" of, as for a kvmd KVM)
        else:
            assert said.value.code == "timeout" and "may have been done" in said.value.message, said.value.message

    run(jet, test)


class FakeChannel:
    """In place of the channel a JetKVM is asked over: open, and what is sent over it, kept."""

    readyState = "open"

    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []

    def send(self, text: str) -> None:
        self.sent.append(json.loads(text))


def test_23_a_press_whose_own_wait_ends_as_the_wall_looks_at_the_hand_over_is_still_waited_for() -> None:
    # (Found by the fourth review: where the press's own wait ran out in the same turn of the loop as the wall looked,
    # and the wall's look came first, the press was neither under way any more nor yet among those given up on: the wait
    # for answers returned at once, and its answer was never heard.)

    async def main() -> None:
        loop = asyncio.get_running_loop()
        wall = jetkvm.JetKvmDevice(kvm.DeviceSpec("w", "the wall", "http://127.0.0.1:9", "", "x", kind="jetkvm"))
        session = jetkvm._Session()
        channel = FakeChannel()
        session.rpc = channel
        session.ready.set()
        calling = asyncio.ensure_future(wall._call(session, "keyboardReport", dict(PRESS_A), within=5))
        await asyncio.sleep(0)  # (sent; its answer awaited)
        number = session.next_id
        session.taken = True  # its own page took the viewer meanwhile
        session.pending[number].cancel()  # its own wait ends: the call is over, and has not yet tidied up after itself
        assert number not in session.given_up
        loop.call_later(0.3, wall._on_message, session, json.dumps({"jsonrpc": "2.0", "id": number, "result": None}))
        began = time.monotonic()
        await wall._answers_due(session)  # as the wall's look runs it, before the call's own end
        took = time.monotonic() - began
        with pytest.raises((kvm.KvmError, asyncio.CancelledError)):
            await calling
        assert took >= 0.25, f"the wait for answers returned after {took:.3f} s, before the press's answer"
        assert took < 1.0, f"the wait for answers sat out {took:.3f} s after the press's answer"
        assert session.given_up == {}
        lets_go = [said for said in channel.sent if said["params"] == NOTHING]
        assert len(lets_go) == 2, channel.sent  # (as its wait ended, and in turn after its answer)

    asyncio.run(main())


def test_24_a_power_press_cut_off_as_the_wall_gives_up_a_connection_may_have_been_done(monkeypatch: pytest.MonkeyPatch) -> None:
    # (Found by the fourth review: a status question unanswered, the wall ends the connection as dead, and the power press
    # that went out meanwhile, and was made, was "dropped", which the history writes as "not pressed".)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, extension="atx-power")).start()
    held_back: set[int] = set()
    real_call, real_heard = jetkvm.JetKvmDevice._call, jetkvm.JetKvmDevice._on_message

    async def call(self: Any, session: Any, method: str, params: Any = None, within: Any = None) -> Any:
        if method == "getVideoState":
            # The status question goes out once the press was made, and is never answered: the wall gives the connection up
            # as dead a second later, with the press's answer still to come. (Asked half a second before the press, with a
            # wait of a second for everything, the press went out after that on a busy computer, and nothing was pressed.)
            for _ in range(3000):
                if jet.state.actions:
                    break
                await asyncio.sleep(0.01)
            within = 1.0
        if method in ("getVideoState", "setATXPowerAction"):
            held_back.add(session.next_id + 1)
        if method == "setATXPowerAction":
            within = 10.0  # (its own wait outlasts the connection: only the connection's end ends it)
        return await real_call(self, session, method, params, within)

    def heard(self: Any, session: Any, message: Any) -> None:
        if answer_to(message) in held_back:
            return  # (no answer to these)
        real_heard(self, session, message)

    monkeypatch.setattr(jetkvm.JetKvmDevice, "_call", call)
    monkeypatch.setattr(jetkvm.JetKvmDevice, "_on_message", heard)

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        wall._status_at = 0.0
        looking = asyncio.ensure_future(wall._refresh_status())
        await asyncio.sleep(0.5)
        with pytest.raises(kvm.KvmError) as said:
            await wall.act("atx_power")
        await looking
        assert jet.state.actions == ["atx power-short"]
        assert said.value.code == "timeout" and "may have been done" in said.value.message, (said.value.code, said.value.message)

    run(jet, test)


def test_25_a_status_read_cut_off_by_the_tile_being_closed_is_no_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    # (Found by the fourth review: cut off as the tile was edited or removed, the status read took the old picture's word
    # and said "online", and counted the JetKVM as answering.)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360)).start()
    real_heard = jetkvm.JetKvmDevice._on_message

    def heard(self: Any, session: Any, message: Any) -> None:
        if answer_to(message) is not None:
            return  # (no answer to anything)
        real_heard(self, session, message)

    monkeypatch.setattr(jetkvm.JetKvmDevice, "_on_message", heard)

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        wall._status_at = 0.0
        looking = asyncio.ensure_future(wall._refresh_status())
        await asyncio.sleep(0.3)
        await wall.close()
        await looking
        assert wall._status is not None and wall._status["state"] == "connecting", wall._status  # (no word of the JetKVM)

    run(jet, test)


@pytest.mark.parametrize("by", ["a question's own wait running out", "an answer in the same turn as its own wait ending", "the channel closing"])
def test_26_the_wait_after_a_hand_over_ends_as_soon_as_nothing_more_is_owed(by: str) -> None:
    # (The fourth review's second look: each change that can end the wait wakes it; and an answer that came in the same
    # turn of the loop as its call's own wait ran out is heard, not taken for a press given up on, which nothing would
    # answer again: the wait sat out its whole grace.)

    async def main() -> None:
        loop = asyncio.get_running_loop()
        wall = jetkvm.JetKvmDevice(kvm.DeviceSpec("w", "the wall", "http://127.0.0.1:9", "", "x", kind="jetkvm"))
        session = jetkvm._Session()
        channel = FakeChannel()
        session.rpc = channel
        session.ready.set()
        method, params = ("getVideoState", None) if by != "an answer in the same turn as its own wait ending" else ("keyboardReport", dict(PRESS_A))
        calling = asyncio.ensure_future(wall._call(session, method, params, within=0.3 if by != "the channel closing" else 5))
        await asyncio.sleep(0)  # (sent; its answer awaited)
        number = session.next_id
        session.taken = True  # its own page took the viewer meanwhile
        if by == "an answer in the same turn as its own wait ending":

            def both() -> None:  # (its answer, and its own wait running out, in one turn)
                wall._on_message(session, json.dumps({"jsonrpc": "2.0", "id": number, "result": None}))
                calling.cancel()

            loop.call_later(0.3, both)
        elif by == "the channel closing":

            def closes() -> None:
                channel.readyState = "closed"
                wall._no_more_asking(session)

            loop.call_later(0.3, closes)
        began = time.monotonic()
        await wall._answers_due(session)
        took = time.monotonic() - began
        calling.cancel()  # (whatever is left of it)
        with contextlib.suppress(kvm.KvmError, asyncio.CancelledError):
            await calling
        assert 0.2 <= took < 1.0, f"the wait ended after {took:.3f} s"
        assert session.given_up == {}, session.given_up

    asyncio.run(main())


def test_27_a_stop_while_closing_waits_for_a_press_still_closes_the_connection() -> None:
    # (The second look: stopped in that wait, the rest of closing was skipped, and the connection went on.)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, together=2.0, hand_over_close=5.0, take_over_at=("before", 1, 0))).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        held = await wall.input_ready()
        assert isinstance(held, jetkvm._Session)
        wall.say("keyboardReport", dict(PRESS_A), on=held)
        for _ in range(300):
            if held.taken:
                break
            await asyncio.sleep(0.005)
        closing = asyncio.ensure_future(wall.close())
        await asyncio.sleep(0.2)  # (in its wait for the press's answer)
        closing.cancel()
        with pytest.raises(asyncio.CancelledError):
            await closing
        assert wall._task is not None and wall._task.done(), "the connection went on after a stop while closing"

    run(jet, test)
