"""Keys and the mouse that wait on their way to a machine are not sent once the line has lost them (the review of 850745e,
L-W2; for a PC with Intel AMT see test_live_letting_go and test_live, whose earlier decision this changed).

A live line's word to a machine may wait before it goes: a JetKVM is sent one report at a time, each once the one before
was answered (up to 256 wait); a PC with Intel AMT whose engine ended its session at its own time, and a guest of
Proxmox whose console is being opened again, have a key wait for the next session. The right to send it was asked
before the wait. Signed out, suspended or made a viewer meanwhile (or keyboard and mouse taken over or given back), what
waited went all the same, into a production machine, and was let go of after it landed. Now nothing of the line's goes
once it has lost keyboard and mouse: what waits is dropped, and only the letting go of what it had down goes.
"""
from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace
from pathlib import Path
from typing import Any

import pytest

from qkvm import live
from tests.fake_jetkvm import FakeJetKvm, JetState
from tests.fake_proxmox import FakeProxmox
from tests.test_live import Wall
from tests.test_live_letting_go import Owed
from tests.test_proxmox import a_guest, two_guests
from tests.test_wall import wait_until

ALPHABET = [0x04 + i for i in range(26)]


def test_reports_waiting_for_a_jetkvm_are_dropped_when_the_account_is_signed_out(tmp_path: Path) -> None:
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, together=0.2)).start()  # it answers each 0.2 s later
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, jet.url)
            olga_id = admin.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": "olga may act here"}).json()["user"]["id"]
            olga = wall.browser("olga", "olga may act here")
            line = wall.line(olga, device, max_fps=5)
            assert line.picture(timeout=20).kind == 2
            line.say(t="control", on=True)
            assert line.word("control")["on"] is True
            for usage in ALPHABET:  # (52 reports: some ten seconds of them, at the pace this JetKVM answers)
                line.say(t="k", u=usage, d=True)
                line.say(t="k", u=usage, d=False)
            wait_until(lambda: len(jet.state.typed) >= 2, "nothing was typed", timeout=20)
            assert admin.post(f"/api/v1/users/{olga_id}/logout").status_code == 200
            assert line.word("bye", timeout=10)["code"] == "signed_out"
            typed = len(jet.state.typed)
            time.sleep(3.0)
            # At most the one that was on its way when she was signed out; before, the rest of the alphabet followed.
            assert len(jet.state.typed) <= typed + 1, f"{len(jet.state.typed) - typed} more were typed after the sign-out"
            assert len(jet.state.typed) < len(ALPHABET)
            wait_until(lambda: jet.state.down == [], f"a key stayed down: {jet.state.down}", timeout=10)
    finally:
        jet.stop()


@pytest.fixture
def pve(tmp_path: Path) -> Any:
    fake = FakeProxmox(two_guests(), tls_dir=tmp_path / "pve").start()
    try:
        yield fake
    finally:
        fake.stop()


def test_a_guests_key_waiting_for_its_console_is_not_sent_once_the_line_lost_the_keyboard(pve: FakeProxmox) -> None:
    screen = pve.state.guests[100].screen

    async def run() -> None:
        device = a_guest(pve)
        lines = Owed()
        machine = live.Machine(lines, "ab12", device)  # type: ignore[arg-type]
        line = live.Line(SimpleNamespace(), live.Holder("olga", "olga", True, "127.0.0.1", "s-olga"), machine, frozenset({"jpeg"}), 640, 30.0)  # type: ignore[arg-type]
        machine.viewers.add(line)
        gate = asyncio.Event()
        gate.set()
        ready = device.input_ready

        async def console_being_opened_again() -> None:  # (Proxmox handing out a new console takes its time)
            await gate.wait()
            await ready()

        device.input_ready = console_being_opened_again  # type: ignore[method-assign]
        try:
            await device.status()
            assert await machine.control(line, True) == {"t": "control", "on": True}
            await machine.input(line, {"t": "k", "u": 0x04, "d": True})
            await machine.input(line, {"t": "k", "u": 0x04, "d": False})
            gate.clear()
            pressing = asyncio.create_task(machine.input(line, {"t": "k", "u": 0xE0, "d": True}))  # ControlLeft
            await asyncio.sleep(0.3)
            assert not pressing.done(), "Ctrl did not wait for the console"
            machine._let_go(line, "not_allowed", "Your account may no longer act on this machine")
            gate.set()
            await pressing
            await lines.settled()
            await asyncio.sleep(0.5)
        finally:
            await device.close()

    asyncio.run(run())
    assert (0x61, True) in screen.keys
    assert (0xFFE3, True) not in screen.keys, f"Ctrl went to the guest after the line lost the keyboard: {screen.keys}"


def test_reports_still_waiting_from_a_line_that_closed_are_dropped_when_the_account_is_signed_out(tmp_path: Path) -> None:
    # (The fresh review of 06e82b2, its finding 4: what a line said before it closed, or gave keyboard and mouse back, goes
    # on as it was said; and went on also once the account was signed out a moment later, as a client of its own that
    # closes first, or a closed tab, would have it. Now each report asks, as it goes, whether its holder may still act.)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, together=0.2)).start()  # it answers each 0.2 s later
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, jet.url)
            olga_id = admin.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": "olga may act here"}).json()["user"]["id"]
            olga = wall.browser("olga", "olga may act here")
            line = wall.line(olga, device, max_fps=5)
            assert line.picture(timeout=20).kind == 2
            line.say(t="control", on=True)
            assert line.word("control")["on"] is True
            for usage in ALPHABET:
                line.say(t="k", u=usage, d=True)
                line.say(t="k", u=usage, d=False)
            wait_until(lambda: len(jet.state.typed) >= 2, "nothing was typed", timeout=20)
            line.close()  # (given back: what it said goes on, while she may)
            time.sleep(0.3)
            assert admin.post(f"/api/v1/users/{olga_id}/logout").status_code == 200
            typed = len(jet.state.typed)
            time.sleep(4.0)
            assert len(jet.state.typed) <= typed + 2, f"{len(jet.state.typed) - typed} more were typed after the sign-out"
            wait_until(lambda: jet.state.down == [], f"a key stayed down: {jet.state.down}", timeout=10)
    finally:
        jet.stop()


def test_reports_still_waiting_from_one_holder_are_judged_by_that_holder_and_not_by_the_next(tmp_path: Path) -> None:
    # (The final review of 1e21777, its medium finding: the check was one slot per connection, and the next holder's first
    # report took it over once the wait for the last holder's letting go had given up: what the last holder still had
    # waiting was judged by the next one's right, and went on typing after the last holder was signed out.)
    jet = FakeJetKvm(JetState(hidrpc=False, width=640, height=360, together=0.2)).start()  # it answers each 0.2 s later
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, jet.url)
            ids = {}
            for name in ("olga", "bob"):
                made = admin.post("/api/v1/users", json={"name": name, "role": "operator", "password": f"{name} may act here"})
                ids[name] = made.json()["user"]["id"]
            olga, bob = wall.browser("olga", "olga may act here"), wall.browser("bob", "bob may act here")
            bob_line = wall.line(bob, device, max_fps=5)
            assert bob_line.picture(timeout=20).kind == 2
            line = wall.line(olga, device, max_fps=5)
            assert line.picture(timeout=20).kind == 2
            line.say(t="control", on=True)
            assert line.word("control")["on"] is True
            for usage in ALPHABET:
                line.say(t="k", u=usage, d=True)
                line.say(t="k", u=usage, d=False)
            wait_until(lambda: len(jet.state.typed) >= 2, "nothing was typed", timeout=20)
            started = time.monotonic()
            line.close()  # (given back: what she said goes on while she may)
            time.sleep(0.5)
            bob_line.say(t="control", on=True)
            assert bob_line.word("control")["on"] is True
            time.sleep(max(0.0, 5.0 - (time.monotonic() - started)))  # (past the wait for her letting go)
            bob_line.say(t="m", x=100, y=100)  # (bob's first word)
            time.sleep(0.4)
            assert admin.post(f"/api/v1/users/{ids['olga']}/logout").status_code == 200
            typed = len(jet.state.typed)
            time.sleep(5.0)
            assert len(jet.state.typed) <= typed + 2, f"{len(jet.state.typed) - typed} more of olga's keys were typed after she was signed out"
            wait_until(lambda: jet.state.down == [], f"a key stayed down: {jet.state.down}", timeout=10)
    finally:
        jet.stop()


def test_a_letting_go_never_moves_the_pointer_to_where_a_refused_holder_put_it() -> None:
    # (The delta review of 7371f1a, its finding 2: the letting go is never refused, and it carried the holder's last said
    # place, so a place of theirs that waited and was dropped went to the machine all the same, by the letting go.)
    from qkvm import jetkvm
    from qkvm.kvm import DeviceSpec

    async def run() -> list[tuple[int, int, int]]:
        device = jetkvm.JetKvmDevice(DeviceSpec(id="t", name="t", base_url="https://127.0.0.1:9", username="", password="", kind="jetkvm"))
        session = jetkvm._Session()
        session.ready.set()
        session.road = "rpc"
        device._session = session
        sent: list[tuple[str, dict[str, Any]]] = []

        async def call(said_on: Any, method: str, params: Any = None, within: Any = None) -> None:
            sent.append((method, dict(params or {})))
            device._said(said_on, method, params)
            await asyncio.sleep(0.2)

        device._call = call  # type: ignore[method-assign]
        may = [True]
        hid = live.JetHid(device)
        hid._on = session
        hid.holder_may = lambda: may[0]
        await hid.place(100, 100)
        await asyncio.sleep(0.01)
        await hid.key(0x04, True)
        await hid.key(0x04, False)
        hid._placed_at = -1e9
        await hid.place(31000, 31000)  # (waits behind the keys)
        await asyncio.sleep(0.01)
        may[0] = False  # (signed out: taken away)
        hid.taken_away = True
        hid.end()
        await hid.release_all()
        await asyncio.sleep(2.0)
        return [(p["x"], p["y"], p["buttons"]) for method, p in sent if method == "absMouseReport"]

    places = asyncio.run(run())
    assert all(place[:2] != (31000, 31000) for place in places), places
    assert places[-1][2] == 0  # (and the buttons let go of)


def _jet_on_json_rpc(delay: float = 0.2) -> tuple[Any, Any, list[tuple[str, dict[str, Any]]]]:
    from qkvm import jetkvm
    from qkvm.kvm import DeviceSpec

    device = jetkvm.JetKvmDevice(DeviceSpec(id="t", name="t", base_url="https://127.0.0.1:9", username="", password="", kind="jetkvm"))
    session = jetkvm._Session()
    session.ready.set()
    session.road = "rpc"
    device._session = session
    sent: list[tuple[str, dict[str, Any]]] = []

    async def call(said_on: Any, method: str, params: Any = None, within: Any = None) -> None:
        sent.append((method, dict(params or {})))
        device._said(said_on, method, params)
        await asyncio.sleep(delay)

    device._call = call  # type: ignore[method-assign]
    return device, session, sent


@pytest.mark.parametrize("how", ["signed out", "given back, then signed out"])
def test_a_letting_go_sends_no_place_where_nothing_absolute_went_on_the_connection(how: str) -> None:
    # (The delta review of fe16b1f, its finding 1: where the holder's first place waited behind keys, nothing absolute had
    # gone on the connection, and the letting go went with the place they had said, refused, all the same: by
    # release_all's letting go, or after _refused_holder's.)
    async def run() -> list[tuple[int, int, int]]:
        device, session, sent = _jet_on_json_rpc()
        may = [True]
        hid = live.JetHid(device)
        hid._on = session
        hid.holder_may = lambda: may[0]
        await hid.key(0x04, True)
        await hid.key(0x04, False)
        hid._placed_at = -1e9
        await hid.place(31000, 31000)  # (waits: the first place of this connection)
        await asyncio.sleep(0.01)
        if how == "signed out":
            may[0] = False
            hid.taken_away = True
            hid.end()
            await hid.release_all()
        else:
            hid.end()
            await hid.release_all()
            may[0] = False
        await asyncio.sleep(1.5)
        return [(p["x"], p["y"], p["buttons"]) for method, p in sent if method == "absMouseReport"]

    places = asyncio.run(run())
    assert places == [], places  # (nothing was down on that mouse: there was nothing to let go of)


def test_a_line_said_without_a_check_moves_the_pointer_as_said() -> None:
    # (No check of its holder is not a letting go: taken for one, every place after the first went where the first was.)
    async def run() -> list[tuple[int, int, int]]:
        device, session, sent = _jet_on_json_rpc(0.05)
        hid = live.JetHid(device)
        hid._on = session
        await hid.place(100, 100)
        await asyncio.sleep(0.1)
        hid._placed_at = -1e9
        await hid.place(200, 200)
        await asyncio.sleep(0.3)
        return [(p["x"], p["y"], p["buttons"]) for method, p in sent if method == "absMouseReport"]

    assert asyncio.run(run()) == [(100, 100, 0), (200, 200, 0)]
