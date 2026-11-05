"""The three views of a PC with Intel AMT, a setting of its tile (the owner's decision of 2026-11-03).

Health only: no KVM session is ever opened, so Intel's border never comes up on the PC's own monitor; the tile says how the
PC is, and every way that opens a session today (its stills, a live view, keys, Type text) is refused in words that say how
to change the view. Stills, the default for a new tile and for one saved before the views: a still now and then for a tile
that is only shown, a session while its enlarged or live view is open (as 0.2 had it). Live KVM: a session held while its
tile is shown as well, at the wall's pace.

Counted at the stand-in (tests/fake_amt.py): the sessions each view opens and how long they are held. And who may change the
view (an operator as an admin, by a route of its own; nobody who may only look), that each change is written down, kept over
a restart and an edit of the tile, carried by a file, and that a record from before the views is a still tile.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from qkvm import amt, kvm, update, vault, vncdevice
from qkvm.amt import HEALTH_ONLY, SESSION_CAN, AmtDevice
from qkvm.kvm import REJECTED, DeviceSpec, KvmError
from tests.fake_amt import FakeAmt
from tests.fake_kvm import FakeKvm, FakeState
from tests.settings_file import settings_text, write_settings_text
from tests.test_amt_screen import picture_of, settled_status
from tests.test_live import Wall
from tests.test_live import Viewer as LiveViewer
from tests.test_redfish import status_of
from tests.test_users import account, browser, visitor
from tests.test_wall import PASSWORD, add, snap, wait_until, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(amt, "LOOK_EVERY", 0)
    monkeypatch.setattr(amt, "FOLLOW_UP", ())
    monkeypatch.setattr(amt, "HICCUP", 0)
    monkeypatch.setattr(amt.AmtScreen, "LOOK_PACE", 0.05)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")
    REJECTED.clear()
    vncdevice._STILL_PACED.clear()


@pytest.fixture
def pc() -> Iterator[FakeAmt]:
    machine = FakeAmt().start()
    yield machine
    machine.stop()


def set_to(machine: FakeAmt, view: str) -> AmtDevice:
    return AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=machine.url, username="admin", password="secret", kind="amt", amt_view=view))


async def shown_for(device: AmtDevice, seconds: float, big: bool = False) -> None:
    """The tile asks for its picture as a tile that is shown does (the enlarged view with `big`), for this long."""
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        try:
            await device.snapshot(640, big=big)
        except KvmError:
            pass
        await asyncio.sleep(0.05)


async def closed_within(machine: FakeAmt, seconds: float, why: str) -> None:
    deadline = time.monotonic() + seconds
    while machine.state.redirection_open:
        assert time.monotonic() < deadline, why
        await asyncio.sleep(0.02)


# --- the sessions each view opens ---------------------------------------------------------------------------------


def test_health_only_opens_no_session_for_anything_and_says_so(pc: FakeAmt) -> None:
    async def run() -> None:
        device = set_to(pc, "health")
        try:
            status = await settled_status(device, "online")
            # How the PC is, and no screen: none of what a session brings, and the tile says why, and which view it is in.
            assert status["screen"] is False and set(SESSION_CAN).isdisjoint(status["can"]), status["can"]
            assert status["can"] == ["power", "reset", "power_state", "bios_setup"]
            assert status["server"]["no_screen"] == HEALTH_ONLY and status["server"]["amt"]["view"] == "health"
            assert status["server"]["amt"]["kvm"] == "enabled"  # (its KVM is there: the view, not the PC, keeps it closed)
            assert not device.console_readable and device.no_live_why == HEALTH_ONLY
            # Each way a session is opened today is refused, in words that say how to change it.
            refusals = [device.snapshot(640), device.snapshot(640, big=True), device.live_screen(), device.input_ready(), device.press(0x04, True), device.pointer(10, 10)]
            refusals += [device.act("keys", keys="KeyA"), device.act("text", text="hello"), device.act("ctrl_alt_del")]
            for asked in refusals:
                with pytest.raises(KvmError) as refused:
                    await asked
                assert (refused.value.code, refused.value.status, refused.value.message) == ("no_picture", 404, HEALTH_ONLY)
            # The large view sending an action (`watching`) opens none either, nor a power-on meant to show the start.
            pc.state.power = amt.OFF
            await settled_status(device, "no_signal")
            device.watched()
            await device.act("power_on")
            assert pc.state.actions == [amt.ON]
            # And the screen's own door stays shut, whoever comes to it.
            with pytest.raises(KvmError) as shut:
                await device._screen.ready(1.0)
            assert shut.value.message == HEALTH_ONLY
            await asyncio.sleep(0.3)
            assert (pc.state.redirections, pc.state.kvm_sessions) == (0, 0)
        finally:
            await device.close()

    asyncio.run(run())


def test_stills_take_a_short_session_now_and_then_and_live_kvm_holds_one_while_the_tile_is_shown(pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(amt.AmtScreen, "STILL_EVERY", 3600.0)
    monkeypatch.setattr(amt.AmtScreen, "LET_GO_AFTER", 1.0)
    # (A screen that stands still answers no request for an update: the pacer asks again whether anybody looks at its
    # heartbeat, a minute as shipped, here half a second.)
    monkeypatch.setattr(vncdevice, "HEARTBEAT", 0.5)

    async def run() -> None:
        # Stills (the default): one short session for the still, closed while the tile is still shown.
        device = set_to(pc, "stills")
        try:
            await device.status()
            assert (await picture_of(device)).still is True
            await shown_for(device, 1.0)
            await closed_within(pc, 3, "a still's session was held for a tile that is only shown")
            assert pc.state.kvm_sessions == 1
        finally:
            await device.close()
        await closed_within(pc, 3, "the still's session outlived its tile")
        # Live KVM: the same tile, only shown (no enlarged view), holds one session for as long as it is shown...
        device = set_to(pc, "live")
        try:
            status = await device.status()
            assert status["server"]["amt"]["view"] == "live" and {"screen", "live", "control"} <= set(status["can"])
            assert (await picture_of(device)).still is False  # (a picture of the held session, not a still)
            held = pc.state.kvm_sessions
            await shown_for(device, 2.5)  # (longer than LET_GO_AFTER)
            assert (pc.state.kvm_sessions, pc.state.redirection_open) == (held, 1)
            # ...and lets it go once it is not shown any more (LET_GO_AFTER after the last look).
            await closed_within(pc, 4, "a live KVM tile's session was held after nobody looked")
            assert pc.state.kvm_sessions == held
        finally:
            await device.close()

    asyncio.run(run())


def test_a_change_to_health_only_lets_go_of_a_held_session_at_once(pc: FakeAmt) -> None:
    # (LET_GO_AFTER as shipped, a minute: a session that goes within seconds was let go of by the change, not by the clock.)
    async def run() -> None:
        device = set_to(pc, "live")
        try:
            await device.status()
            await picture_of(device)
            await shown_for(device, 0.5, big=True)  # the enlarged view holds it as well
            assert pc.state.redirection_open == 1
            device.set_view("health")
            await closed_within(pc, 3, "the session was held after the view was changed to health only")
            status = await device.status()  # (said at once, before the next look)
            assert status["screen"] is False and status["server"]["no_screen"] == HEALTH_ONLY and "live" not in status["can"]
            sessions = pc.state.kvm_sessions
            await shown_for(device, 0.5, big=True)  # the enlarged view asking still: refused, and nothing opened
            assert (pc.state.kvm_sessions, pc.state.redirection_open) == (sessions, 0)
            # Back to stills: the tile may be had again, said at once as well, and a still comes.
            device.set_view("stills")
            status = await device.status()
            assert status["screen"] is True and {"screen", "keys", "text", "live", "control"} <= set(status["can"]) and status["server"]["no_screen"] is None
            assert (await picture_of(device)).still is True
        finally:
            await device.close()

    asyncio.run(run())


def test_a_change_from_live_kvm_to_stills_lets_the_shown_tiles_session_go_and_keeps_the_enlarged_views(pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(amt.AmtScreen, "STILL_EVERY", 3600.0)

    async def run() -> None:
        device = set_to(pc, "live")
        try:
            await device.status()
            await picture_of(device)
            await shown_for(device, 0.5)
            held = pc.state.kvm_sessions
            assert pc.state.redirection_open == 1
            # The tile is shown on: the session it held as live KVM goes now (a minute is LET_GO_AFTER), and it shows stills.
            device.set_view("stills")
            shown = asyncio.create_task(shown_for(device, 2.0))
            await closed_within(pc, 3, "the shown tile's session was held after the view was changed to stills")
            await shown
            assert pc.state.kvm_sessions == held and (await device.snapshot(640)).still is True
            # In stills the enlarged view holds a session, as it did before the views (0.2's own: see test_amt_screen.py).
            await shown_for(device, 1.0, big=True)
            assert pc.state.redirection_open == 1
            device.set_view("stills")  # (the same view again: nothing is let go of)
            await shown_for(device, 0.5, big=True)
            assert pc.state.redirection_open == 1
        finally:
            await device.close()

    asyncio.run(run())


# --- the setting: its route, who may, what is written down and kept ----------------------------------------------


def views_of(client: Any, device: str) -> tuple[str, str | None]:
    """The view as the wall lists the tile, and as the status says it."""
    listed = next(d for d in client.get("/api/v1/wall").json()["devices"] if d["id"] == device)
    said = client.get("/api/v1/status").json()[device].get("server", {}).get("amt", {}).get("view")
    return listed["amt_view"], said


def test_an_operator_changes_the_view_by_its_own_route_and_it_is_written_down_and_kept(tmp_path: Path, pc: FakeAmt) -> None:
    kvm_stand_in = FakeKvm(FakeState()).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, pc.url, name="Desk 7")
            other = add(admin, kvm_stand_in.url, name="A KVM")
            status_of(admin, device, screen=True)
            assert views_of(admin, device) == ("stills", "stills")  # a new tile: stills
            assert "amt_view" not in next(d for d in admin.get("/api/v1/wall").json()["devices"] if d["id"] == other)
            account(admin, "olga", "operator")
            account(admin, "victor", "viewer")
            olga, victor = browser(admin, "olga", port=50021), browser(admin, "victor", port=50022)
            route = f"/api/v1/devices/{device}/view"
            # Somebody who may only look may not; an operator may (she edits no tile otherwise); a word that is no view is refused.
            assert victor.put(route, json={"view": "health"}).status_code == 403
            assert olga.put(f"/api/v1/devices/{device}", json={"url": pc.url, "username": "admin"}).status_code == 403
            assert olga.put(route, json={"view": "everything"}).status_code == 422
            assert olga.put(f"/api/v1/devices/{other}/view", json={"view": "health"}).json()["code"] == "invalid"
            assert olga.put("/api/v1/devices/00000000/view", json={"view": "health"}).status_code == 404
            # Nor a token, an operator's included: a token changes no setting of a tile (SECURITY.md).
            made = admin.post("/api/v1/tokens", json={"name": "a script", "role": "operator"})
            assert made.status_code == 201, made.text
            script = visitor(admin, 50023)
            script.headers["Authorization"] = f"Bearer {made.json()['token']}"
            refused = script.put(route, json={"view": "health"})
            assert (refused.status_code, refused.json()["code"]) == (403, "not_allowed"), refused.text
            changed = olga.put(route, json={"view": "health"})
            assert changed.status_code == 200 and changed.json() == {"ok": True, "amt_view": "health"}, changed.text
            assert views_of(victor, device) == ("health", "health")
            refused = victor.get(snap(device))
            assert (refused.status_code, refused.json()["code"], refused.json()["message"]) == (404, "no_picture", HEALTH_ONLY)
            keys = olga.post(f"/api/v1/devices/{device}/actions", json={"action": "text", "text": "hello"})
            assert (keys.status_code, keys.json()["message"]) == (404, HEALTH_ONLY)
            line = victor.post(f"/api/v1/devices/{device}/live", json={})
            assert (line.status_code, line.json()["code"], line.json()["message"]) == (404, "no_live", HEALTH_ONLY)
            assert admin.put(route, json={"view": "live"}).status_code == 200
            assert olga.put(route, json={"view": "live"}).status_code == 200  # (the same again: nothing to write down)
            written = [(e["event"], e.get("user"), e.get("view"), e.get("was")) for e in admin.get("/api/v1/audit").json()["entries"] if e["event"] == "amt_view_changed"]
            assert written[::-1] == [("amt_view_changed", "olga", "health", "stills"), ("amt_view_changed", "admin", "live", "health")]
            # An edit of the tile keeps it.
            assert admin.put(f"/api/v1/devices/{device}", json={"url": pc.url, "username": "admin", "name": "Desk 8"}).status_code == 200
            assert views_of(admin, device)[0] == "live"
        # Kept over a restart; and a record from before the views (the field not there) is a still tile.
        with wall(tmp_path, sign_in=False) as admin:
            assert admin.post("/api/v1/login", json={"name": "admin", "password": PASSWORD}).status_code == 200
            assert views_of(admin, device)[0] == "live"
            status_of(admin, device, state="online")
            wait_until(lambda: views_of(admin, device)[1] == "live", "the status never said the view")
        saved = json.loads(settings_text(tmp_path / "qkvm.json"))
        assert next(d for d in saved["devices"] if d["id"] == device)["amt_view"] == "live"
        for record in saved["devices"]:
            del record["amt_view"]
        write_settings_text(tmp_path / "qkvm.json", json.dumps(saved))
        with wall(tmp_path, sign_in=False) as admin:
            assert admin.post("/api/v1/login", json={"name": "admin", "password": PASSWORD}).status_code == 200
            assert views_of(admin, device)[0] == "stills"
    finally:
        kvm_stand_in.stop()


def test_the_view_goes_along_in_a_file_and_one_from_before_the_views_brings_stills(tmp_path: Path, pc: FakeAmt) -> None:
    with wall(tmp_path / "one") as admin:
        device = add(admin, pc.url, name="Desk 7")
        assert admin.put(f"/api/v1/devices/{device}/view", json={"view": "health"}).status_code == 200
        file = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": "", "parts": ["devices"]}).text
    assert json.loads(file)["devices"][0]["amt_view"] == "health"
    with wall(tmp_path / "two") as other:
        assert other.post("/api/v1/import", json={"file": file, "take": ["devices"]}).json()["devices"] == 1
        assert other.get("/api/v1/wall").json()["devices"][0]["amt_view"] == "health"
        odd = json.loads(file)
        odd["devices"][0]["amt_view"] = "everything"  # what this version does not know: that machine is left out, and why is said
        read = other.post("/api/v1/import/read", json={"file": json.dumps(odd)}).json()
        assert read["devices"] == [] and any("view" in why for why in read["left_out"]), read
    del odd["devices"][0]["amt_view"]  # not said: a file of 0.2.x, whose PCs come as stills
    with wall(tmp_path / "three") as third:
        assert third.post("/api/v1/import", json={"file": json.dumps(odd), "take": ["devices"]}).json()["devices"] == 1
        assert third.get("/api/v1/wall").json()["devices"][0]["amt_view"] == "stills"


def test_a_live_line_open_when_the_view_is_changed_to_health_only_ends_saying_why(tmp_path: Path, pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(amt.AmtScreen, "LIVE_PACE", 0.02)
    with Wall(tmp_path) as live_wall:
        admin = live_wall.browser()
        device = live_wall.add(admin, pc.url)
        wait_until(lambda: admin.get("/api/v1/status").json()[device].get("screen") is True, "the PC's screen is not said to be there", 10)
        line: LiveViewer = live_wall.line(admin, device, max_fps=5)
        line.picture(timeout=20)  # (stills: the live view holds a session, as before the views)
        assert pc.state.redirection_open == 1
        assert admin.put(f"/api/v1/devices/{device}/view", json={"view": "health"}).status_code == 200
        bye = line.word("bye", timeout=10)
        assert (bye["code"], bye["message"]) == ("no_live", HEALTH_ONLY), bye
        line.closed()
        wait_until(lambda: pc.state.redirection_open == 0, "the session outlived the line", 5)
