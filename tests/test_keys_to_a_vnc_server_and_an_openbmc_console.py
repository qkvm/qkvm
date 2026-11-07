"""A VNC server live (0.3.0): its screen over the live line, on the tile's own connection, and keyboard and mouse as RFB's
key and pointer events; and the same of a server whose controller runs OpenBMC, whose console carries RFB too. Whatever
a line had down is let go of at every end: given back, taken over, closed, dropped, given back for want of input, the
wall stopping.

Against the stand-ins (fake_vnc.py; fake_redfish.py's "openbmc", with fake_vnc behind its /kvm/0), which record every key
and pointer event they are sent. test_live.py has the same of the other families; test_openbmc_console.py the rest of
OpenBMC's console.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from qkvm import kvm, live, redfish, update, vault, vncdevice
from qkvm.kvm import REJECTED
from qkvm.openbmc import OpenBmcScreen
from tests.fake_redfish import BmcState, FakeBmc
from tests.fake_vnc import FakeVnc, VncState
from tests.test_live import Viewer, Wall
from tests.test_openbmc_console import ikvm
from tests.test_wall import wait_until

ENDS = ["given_back", "taken_over", "closed", "dropped", "idle", "wall_stopped"]
CONTROL_L, KEY_C, KEY_A = 0xE0, 0x06, 0x04  # (as the line names them: USB HID usages)
XK_CONTROL_L, XK_C, XK_A = 0xFFE3, 0x63, 0x61  # (as RFB's key events carry them: X11 keysyms)
# (A line is opened and held by a `Viewer` for as long as a test wants it, not in a `with`: as in test_live.py.)
pytestmark = pytest.mark.filterwarnings(r"ignore:connect\(\) must be used as a context manager:DeprecationWarning")


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 20)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")
    monkeypatch.setattr(live, "STANDING_EVERY", 0.2)
    monkeypatch.setattr(redfish, "LOOK_EVERY", 0)
    monkeypatch.setattr(redfish, "FOLLOW_UP", ())
    monkeypatch.setattr(OpenBmcScreen, "LOOK_PACE", 0.05)
    monkeypatch.setattr(OpenBmcScreen, "LIVE_PACE", 0.02)
    REJECTED.clear()
    vncdevice._PACED.clear()


@pytest.fixture
def vnc() -> Iterator[FakeVnc]:
    server = FakeVnc(VncState(width=160, height=100)).start()
    yield server
    server.stop()


def held(line: Viewer, screen: VncState) -> None:
    """Keyboard and mouse taken on `line`, and Ctrl and C held down, and both buttons at a place (a drag)."""
    line.say(t="control", on=True)
    assert line.word("control", timeout=15) == {"t": "control", "on": True}
    line.say(t="k", u=CONTROL_L, d=True)
    line.say(t="k", u=KEY_C, d=True)
    line.say(t="m", x=16384, y=16384)
    line.say(t="mb", b=1, d=True)  # left
    line.say(t="mb", b=2, d=True)  # right
    wait_until(lambda: screen.still_down() == ({XK_CONTROL_L, XK_C}, 1 | 4), f"Ctrl, C and the buttons did not all go down: {screen.keys} {screen.pointers}")


def end_it(wall: Wall, admin: Any, device: str, line: Viewer, end: str) -> Viewer | None:
    """End `line`'s hold of keyboard and mouse in the way `end` names; the admin's line that took them over, for that one."""
    if end == "given_back":
        line.say(t="control", on=False)
        assert line.word("control") == {"t": "control", "on": False}
    elif end == "taken_over":
        mine = wall.line(admin, device)
        mine.say(t="control", on=True)
        refused = mine.word("control")
        assert refused["code"] == "taken" and refused["by"] == "olga", refused
        mine.say(**{"t": "control", "on": True, "take": True, "from": refused["from"]})
        assert mine.word("control", timeout=15) == {"t": "control", "on": True}
        mine.say(t="k", u=KEY_A, d=True)  # the admin's first key, at once: after what olga had down was let go of
        mine.say(t="k", u=KEY_A, d=False)
        assert line.word("control")["code"] == "taken"
        return mine
    elif end == "closed":
        line.close()
    elif end == "dropped":
        line.ws.socket.close()  # the viewer's computer went away: no goodbye
    elif end == "idle":
        assert line.word("control", timeout=10)["code"] == "idle"
    return None


def holder_of(wall: Wall, admin: Any, device: str, end: str) -> Viewer:
    """The line that is to hold keyboard and mouse: an operator's, where an admin is to take them over from it."""
    if end != "taken_over":
        return wall.line(admin, device, max_fps=5)
    assert admin.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": "olga may act here"}).status_code == 201
    return wall.line(wall.browser("olga", "olga may act here"), device, max_fps=5)


def nothing_left_down(screen: VncState, end: str) -> None:
    """Everything the line had down let go of; after a take-over, before the admin's first key."""
    wait_until(lambda: screen.still_down() == (set(), 0), f"something was left down after '{end}': {screen.keys} {screen.pointers}", timeout=15)
    if end == "taken_over":
        wait_until(lambda: (XK_A, False) in screen.keys, f"the admin's key did not arrive: {screen.keys}")
        first_of_his = screen.keys.index((XK_A, True))
        assert {(XK_C, False), (XK_CONTROL_L, False)} <= set(screen.keys[:first_of_his]), screen.keys
        # (Each let go of once, the letter first and the modifier after it: as a person lets go of Ctrl+C.)
        assert screen.keys[:first_of_his].index((XK_C, False)) < screen.keys[:first_of_his].index((XK_CONTROL_L, False)), screen.keys


# --- a VNC server ------------------------------------------------------------------------------------------------------


def test_a_vnc_servers_screen_live_with_its_keys_and_pointer(tmp_path: Path, vnc: FakeVnc) -> None:
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, vnc.url)
        assert {"live", "control", "keys", "text"} <= set(admin.get("/api/v1/status").json()[device]["can"])
        line = wall.line(admin, device, max_fps=5)
        assert line.word("video", timeout=20) == {"t": "video", "codec": "jpeg", "w": 160, "h": 100}
        came = line.picture(timeout=20)
        assert came.kind == 2 and came.key and came.data[:2] == b"\xff\xd8"
        vnc.state.dirty.append((0, 0, 32, 32))  # something changes on its screen: a picture of it comes
        assert line.picture(timeout=10).counter > came.counter
        state = line.word("state", timeout=5)
        assert state["state"] == "online" and state["pointer"] == "both", state  # (to a place, and by steps)
        line.say(t="control", on=True)
        assert line.word("control") == {"t": "control", "on": True}
        line.say(t="k", u=0xE1, d=True)  # ShiftLeft
        line.say(t="k", u=KEY_A, d=True)
        line.say(t="k", u=KEY_A, d=False)
        line.say(t="m", x=32767, y=16384)  # the right edge, half way down
        line.say(t="mb", b=1, d=True)
        line.say(t="mb", b=1, d=False)
        line.say(t="mw", dx=0, dy=1)  # a notch of the wheel: a press and a release of its button
        line.say(t="mr", dx=-9, dy=0)  # and a step to the left
        wait_until(lambda: len(vnc.state.keys) >= 3 and len(vnc.state.pointers) >= 6, f"the server got {vnc.state.keys} {vnc.state.pointers}")
        assert vnc.state.keys == [(0xFFE1, True), (XK_A, True), (XK_A, False)]
        assert vnc.state.pointers == [(159, 49, 0), (159, 49, 1), (159, 49, 0), (159, 49, 8), (159, 49, 0), (150, 49, 0)]
        # The tile's connection is the line's: one, shared with whoever else is at the server.
        assert vnc.state.connections == 1 and vnc.state.shared == [1]
        line.close()  # with Shift still down: let go of at the server
        wait_until(lambda: vnc.state.still_down() == (set(), 0), f"Shift was not let go of: {vnc.state.keys}")
        wait_until(lambda: [entry.get("why") for entry in wall.audit(admin, "live_control")] == [None, "closed"], "the activity log does not say that the keys left with the line")


@pytest.mark.parametrize("end", ENDS)
def test_what_a_line_had_down_on_a_vnc_server_is_let_go_of_at_every_end(tmp_path: Path, vnc: FakeVnc, monkeypatch: pytest.MonkeyPatch, end: str) -> None:
    if end == "idle":
        monkeypatch.setattr(live, "IDLE_GIVE_BACK", 1.5)
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, vnc.url)
        line = holder_of(wall, admin, device, end)
        assert line.picture(timeout=20).kind == 2
        held(line, vnc.state)
        if end != "wall_stopped":
            end_it(wall, admin, device, line, end)
            nothing_left_down(vnc.state, end)
    if end == "wall_stopped":
        nothing_left_down(vnc.state, end)  # (let go of before the wall's connection to the server went)
        line.closed()


def test_a_vnc_server_whose_password_is_rejected_has_no_live_line_and_is_sent_nothing_for_one(tmp_path: Path, vnc: FakeVnc) -> None:
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        made = admin.post("/api/v1/devices", json={"url": vnc.url, "password": "wrong", "force": True})
        assert made.status_code == 201, made.text
        device = made.json()["device"]["id"]
        wait_until(lambda: admin.get("/api/v1/status").json()[device]["state"] == "auth", "the tile never said that the login was rejected")
        tries = vnc.state.password_tries
        refused = admin.post(f"/api/v1/devices/{device}/live")
        assert (refused.status_code, refused.json()["code"]) == (404, "no_live"), refused.text
        time.sleep(1.0)
        assert vnc.state.password_tries == tries  # (the password is not offered again for a line)


def test_a_line_that_asks_for_keyboard_and_mouse_of_a_vnc_server_that_went_away_is_told_why(tmp_path: Path) -> None:
    server = FakeVnc(VncState(width=160, height=100)).start()
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, server.url)
            line = wall.line(admin, device, max_fps=5)
            assert line.picture(timeout=20).kind == 2
            server.stop()  # gone, and nothing answers at its address
            line.say(t="control", on=True)
            answer = line.word("control", timeout=30)
            assert answer["on"] is False and answer["code"] in ("unreachable", "dropped", "timeout", "no_stream"), answer
    finally:
        server.stop()


# --- a server whose controller runs OpenBMC -------------------------------------------------------------------------------


@pytest.mark.parametrize("end", ["given_back", "taken_over", "closed", "dropped"])
def test_what_a_line_had_down_on_an_openbmc_console_is_let_go_of_at_every_end(tmp_path: Path, end: str) -> None:
    bmc = FakeBmc(BmcState(layout="openbmc", kvm_screen=ikvm())).start()
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, bmc.url, kind="redfish")
            wait_until(lambda: admin.get("/api/v1/status").json()[device].get("screen") is True, "the server's screen is not said to be there")
            line = holder_of(wall, admin, device, end)
            assert line.picture(timeout=20).kind == 2
            screen = bmc.state.kvm_screen
            held(line, screen)
            end_it(wall, admin, device, line, end)
            nothing_left_down(screen, end)
            assert bmc.state.logins == 1  # (and none of it signed in again)
    finally:
        bmc.stop()
