"""A rejected password, by every road it could still be offered on.

What a reviewer found in the commit that made a rejected password wait longer each time, by counting at
the device how often it was offered:

* The count was kept in the connection to the device, and a connection is made anew when the saved
  passwords were locked and are opened again, when the listeners are reopened, when the tile is saved
  under another name. Each new one began at nothing. Where QKVM is started to lock itself after the last
  sign-out, a viewer signing in and out six times had the password offered six times in a tenth of a second.
* A server's controller with a console of its own is signed in to a second time, at its web page, with the
  same password. That road asked nothing of the wait: every ten minutes for good, the tile saying "online".
* While the wall waited it asked the device nothing at all, so a device that went away in that hour was
  not seen to: the tile went on saying that the login failed, and no alert went out.
* A device that said no and something else by turns was sent the password ten seconds after each
  "something else": seven times in a half hour.
* A JetKVM that took the password and refused the session it gave for it was sent the password every
  three seconds, for as long as its tile was looked at.

Most of these let real time pass, with every wait of the program made a three-hundredth of what it is (a
minute is a fifth of a second), and ask the device the way the wall asks it.
"""

from __future__ import annotations

import asyncio
import dataclasses
import time
import uuid
from itertools import pairwise
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from qkvm import jetkvm, kvm, redfish
from qkvm.kvm import DeviceSpec, KvmError
from qkvm.server import create_app
from tests.fake_jetkvm import FakeJetKvm, JetState
from tests.fake_kvm import FakeKvm
from tests.fake_redfish import BmcState, FakeBmc
from tests.conftest import SCALE, TICK
from tests.test_a_password_a_device_rejects_again_and_again import KINDS
from tests.test_wall import CSRF, PASSWORD, fast, wait_until, wall  # noqa: F401

HALF_HOUR, HOUR = 1800 / SCALE, 3600 / SCALE
VIEWER = "a viewer's password 1"


def a_controller(server: FakeBmc) -> redfish.RedfishDevice:
    return redfish.RedfishDevice(DeviceSpec(id="ab12", name="Server", base_url=server.url, username="admin", password="secret", kind="redfish"))


# --- the count is kept beside the connections, not in one ---------------------------------------------


@pytest.mark.parametrize("kind", list(KINDS))
def test_a_new_connection_to_the_same_device_is_told_what_the_last_one_was(kind: str) -> None:
    stand_in, make = KINDS[kind]
    server = stand_in().start()

    async def run() -> None:
        first, logins, set_password = make(server)
        set_password("changed on the device")
        try:
            with pytest.raises(KvmError):
                await first._login()  # type: ignore[attr-defined]
        finally:
            await first.close()
        assert logins() == 1
        second = make(server)[0]  # the same device and the same login, over a connection made anew
        try:
            for _ in range(3):
                with pytest.raises(KvmError) as again:
                    await second._login()  # type: ignore[attr-defined]
                assert again.value.code == "auth_failed"
            assert logins() == 1, "a new connection offered the rejected password as if for the first time"
            # What is left of the first one's minute: kept beside the connections, and asked there each time.
            assert 50 <= kvm.REJECTED.wait_left(kvm.REJECTED.what("login", second.spec)) <= 60 + TICK
        finally:
            await second.close()
        # Another password for it is another matter: that one was never rejected, and is tried at once.
        other = type(first)(dataclasses.replace(first.spec, password="another one"))  # type: ignore[call-arg]
        try:
            with pytest.raises(KvmError):
                await other._login()  # type: ignore[attr-defined]
            assert logins() == 2
        finally:
            await other.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()


def test_what_is_kept_of_a_rejected_password_is_not_the_password_and_does_not_grow_without_end() -> None:
    spec = DeviceSpec(id="ab12", name="KVM", base_url="https://192.168.1.50", username="admin", password="a password nobody is to find here")
    known = kvm.Rejected()
    assert known.said_no(known.what("login", spec)) == kvm.LOGIN_BACKOFF
    kept = repr(known._known)
    assert "nobody is to find" not in kept and "192.168.1.50" not in kept and "admin" not in kept
    # One mark for each road, each login and each address: none stands for another.
    marks = {
        known.what(road, dataclasses.replace(spec, **change))  # type: ignore[arg-type]
        for road in kvm.ROADS
        for change in ({}, {"password": "another"}, {"username": "root"}, {"base_url": "https://192.168.1.51"}, {"username": "adm", "password": "in"})
    }
    assert len(marks) == 10
    for number in range(known.MOST + 50):  # somebody adding devices with one wrong password after another
        known.said_no(known.what("login", dataclasses.replace(spec, password=f"guess {number}")))
    assert len(known._known) == known.MOST
    # Typed again by a person, it is forgotten on both roads; and a login that is let in is forgotten too.
    again = known.what("web", spec)
    known.said_no(again)
    known.forget(spec)
    assert known.times(again) == 0 and known.wait_left(again) == 0
    known.said_no(again)
    known.accepted(again)
    assert known.times(again) == 0


def a_wall_with_a_rejected_password(admin: TestClient, fake: FakeKvm) -> str:
    fake.state.password = "changed on the device"
    added = admin.post("/api/v1/devices", json={"url": fake.url, "password": "secret", "kind": "kvmd", "name": "KVM", "force": True})
    assert added.status_code == 201, added.text
    assert admin.post("/api/v1/users", json={"name": "vera", "role": "viewer", "password": VIEWER}).status_code == 201
    return str(added.json()["device"]["id"])


def test_started_to_lock_itself_a_viewer_signing_in_and_out_has_nothing_offered(tmp_path: Path) -> None:
    fake = FakeKvm().start()
    try:
        with wall(tmp_path, locked_start=True) as admin:
            device = a_wall_with_a_rejected_password(admin, fake)
            assert admin.post("/api/v1/logout", json={}).status_code == 200  # the last one out: the saved passwords are locked
            assert admin.core.vault.unlocked is False  # type: ignore[attr-defined]
            before = fake.state.logins
            for _ in range(6):  # (the one browser of this test, signed out: the next to sign in at it is the viewer)
                assert admin.post("/api/v1/login", json={"name": "vera", "password": VIEWER}).status_code == 200
                assert admin.get("/api/v1/status").json()[device]["state"] == "auth"
                assert admin.post("/api/v1/logout", json={}).status_code == 200
            assert fake.state.logins == before, "a viewer signing in and out had the rejected password offered again"
    finally:
        fake.stop()


def test_the_listeners_opened_again_do_not_start_the_count_over(tmp_path: Path) -> None:
    # What the program does when an address of the computer changed, or its settings were: the app made once more.
    fake = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            device = a_wall_with_a_rejected_password(admin, fake)
            core = admin.core  # type: ignore[attr-defined]
            assert admin.get("/api/v1/status").json()[device]["state"] == "auth"
            first = fake.state.logins
        for _ in range(3):
            with TestClient(create_app(core), headers=CSRF, client=("127.0.0.1", 50000)) as again:
                assert again.post("/api/v1/login", json={"name": "admin", "password": PASSWORD}).status_code == 200
                assert again.get("/api/v1/status").json()[device]["state"] == "auth"
        assert fake.state.logins == first
    finally:
        fake.stop()


def test_a_save_of_the_tile_offers_nothing_and_a_password_typed_for_it_is_tried_at_once(tmp_path: Path) -> None:
    fake = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            device = a_wall_with_a_rejected_password(admin, fake)
            assert admin.get("/api/v1/status").json()[device]["state"] == "auth"
            before = fake.state.logins
            for number in range(5):  # the tile given another name, five times; no password typed
                reply = admin.put(f"/api/v1/devices/{device}", json={"url": fake.url, "name": f"KVM {number}", "kind": "kvmd"})
                assert (reply.status_code, reply.json()["code"]) == (422, "auth_failed")
            assert fake.state.logins == before, "saving the tile offered the rejected password again"
            # A password typed by a person is that person's doing, and tried at once: a wrong one (once each time),
            wrong = admin.put(f"/api/v1/devices/{device}", json={"url": fake.url, "name": "KVM", "kind": "kvmd", "password": "not it either"})
            assert (wrong.status_code, wrong.json()["code"]) == (422, "auth_failed") and fake.state.logins == before + 1
            # the same one that is saved, typed again (somebody who knows it was set back on the device),
            same = admin.put(f"/api/v1/devices/{device}", json={"url": fake.url, "name": "KVM", "kind": "kvmd", "password": "secret"})
            assert same.status_code == 422 and fake.state.logins == before + 2
            # and the right one, which is what "Update login" is for.
            right = admin.put(f"/api/v1/devices/{device}", json={"url": fake.url, "name": "KVM", "kind": "kvmd", "password": "changed on the device"})
            assert right.status_code == 200 and fake.state.logins == before + 3
            assert admin.get("/api/v1/status").json()[device]["state"] in ("online", "no_signal")
    finally:
        fake.stop()


# --- a device that says no and something else by turns --------------------------------------------------


def test_a_device_that_says_no_and_something_else_by_turns_is_told_no_as_seldom_as_one_that_only_says_no(scaled: None) -> None:
    # What is not a no is never counted as one (a controller that says 503 while it starts has the right
    # password all the while), and is asked again soon. The noes it says in between are as far apart as
    # they would be without: a minute, five, a quarter of an hour, an hour.
    server = FakeKvm().start()
    server.state.password = "changed on the device"
    device = kvm.KvmDevice(DeviceSpec(id="ab12", name="KVM", base_url=server.url, username="admin", password="secret"))
    sent: list[float] = []

    async def run() -> None:
        began = time.monotonic()
        try:
            while time.monotonic() - began < HALF_HOUR:
                await device.status()
                if len(sent) != server.state.logins:
                    sent.append(round((time.monotonic() - began) * SCALE))
                    server.state.login_status = 500 if server.state.login_status == 200 else 200  # the next one fails the other way
                await asyncio.sleep(0.01)
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()
    noes = sent[0::2]  # (the first, the third, ...: the ones in between were answered with an error of its own)
    assert 2 <= len(noes) <= 4 and len(sent) <= 8, f"the password was sent at these seconds of a half hour: {sent}"
    assert all(later - earlier >= least for (earlier, later), least in zip(pairwise(noes), (55, 290, 880), strict=False)), noes


def test_a_device_that_was_never_told_no_and_fails_another_way_keeps_its_ten_seconds(scaled: None) -> None:
    # (Something that is merely broken is asked again as soon as it was before, the first time.)
    server = FakeKvm().start()
    server.state.login_status = 500
    device = kvm.KvmDevice(DeviceSpec(id="ab12", name="KVM", base_url=server.url, username="admin", password="secret"))

    async def run() -> None:
        try:
            with pytest.raises(KvmError) as failed:
                await device._login()
            assert failed.value.code == "no_sign_in" and "500" in failed.value.message  # there, and signs nobody in
            assert device._login_retry_at - time.monotonic() <= kvm.LOGIN_RETRY + TICK
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()


# --- the second road of a server's controller: the sign-in of its own web page ----------------------------


def test_a_controller_with_a_console_is_not_offered_the_rejected_password_by_two_roads(scaled: None) -> None:
    server = FakeBmc(BmcState(own_console=True)).start()
    server.state.password = "changed on the controller"
    device = a_controller(server)

    async def run() -> None:
        began = time.monotonic()
        try:
            while time.monotonic() - began < HALF_HOUR:
                await device.status()  # what a tile asks
                try:
                    await device.snapshot(640)  # what a viewer's script asks, whatever the tile says
                except KvmError:
                    pass
                await asyncio.sleep(0.02)
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()
    assert server.state.web_logins == 0, "its web page was offered a password that its other sign-in had just rejected"
    assert 2 <= server.state.logins <= 4, server.state.logins


def test_a_password_changed_on_the_controller_while_the_wall_is_signed_in_is_not_offered_to_its_web_page_for_good(scaled: None) -> None:
    # The wall holds a session, which goes on working, so the tile says "online" and the page asks for the
    # picture. Somebody changes the password on the controller: the console's own sign-in is told no.
    server = FakeBmc(BmcState(own_console=True)).start()
    device = a_controller(server)
    offered: list[float] = []
    states: set[str] = set()

    async def run() -> None:
        try:
            assert (await device.status())["state"] == "online"
            server.state.password = "changed on the controller"
            server.state.web_sessions.clear()
            began = time.monotonic()
            while time.monotonic() - began < HOUR:
                status = await device.status()
                states.add(status["state"])
                if status.get("screen") is True:  # (the page asks for the picture only while the status says there may be one)
                    try:
                        await device.snapshot(640)
                    except KvmError:
                        pass
                if len(offered) != server.state.web_logins:
                    offered.append(round((time.monotonic() - began) * SCALE))
                await asyncio.sleep(0.02)
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()
    # Ten minutes, ten minutes, a quarter of an hour, then an hour: four in the first hour, where there were seven.
    assert states == {"online"} and server.state.logins == 1
    assert 2 <= len(offered) <= 4, f"the old password went to its web page at these seconds of an hour: {offered}"
    assert all(later - earlier >= 500 for earlier, later in pairwise(offered)), offered


def test_a_viewers_script_asking_for_the_picture_has_nothing_offered_to_the_web_page(tmp_path: Path, scaled: None) -> None:
    server = FakeBmc(BmcState(own_console=True)).start()
    try:
        with wall(tmp_path) as admin:
            # Added away from what is saved for it ("save anyway"): a password that is wrong from the start.
            server.state.password = "changed on the controller"
            added = admin.post("/api/v1/devices", json={"url": server.url, "password": "secret", "kind": "redfish", "name": "Server", "force": True})
            assert added.status_code == 201, added.text
            device = added.json()["device"]["id"]
            token = admin.post("/api/v1/tokens", json={"name": "a script", "role": "viewer"}).json()["token"]
            asks = {"Authorization": f"Bearer {token}"}
            admin.cookies.clear()  # from here on it is the token that asks, and nobody else
            began, states = time.monotonic(), set()
            while time.monotonic() - began < HALF_HOUR:
                assert admin.get(f"/api/v1/devices/{device}/snapshot", headers=asks).status_code != 200
                states.add(admin.get("/api/v1/status", headers=asks).json().get(device, {}).get("state"))
                time.sleep(0.02)
            assert states == {"auth"}
            assert server.state.web_logins == 0, "a viewer's token had the saved password offered to the controller's web sign-in"
            assert server.state.logins <= 4
    finally:
        server.stop()


def test_an_account_the_web_page_refuses_and_the_rest_lets_in_keeps_its_tile(scaled: None) -> None:
    # An account may be let in by the one road and not by the other. What its web page says no to is not
    # held against the sign-in that works: the server stays on the wall, without its screen.
    server = FakeBmc(BmcState(own_console=True)).start()
    device = a_controller(server)

    async def run() -> None:
        try:
            assert (await device.status())["state"] == "online"
            known = kvm.REJECTED
            known.said_no(known.what("web", device.spec))  # (as its web page would have it: no, to this account)
            device._token = None  # and the session has run out meanwhile: it signs in again, and is let in
            before = server.state.logins
            assert (await device._read_status())["state"] == "online"
            assert server.state.logins == before + 1
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()


# --- a device that goes away while the wall waits ---------------------------------------------------------


@pytest.mark.parametrize("kind", list(KINDS))
def test_a_device_that_goes_away_while_its_password_waits_is_seen_to(kind: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "STILL_THERE_EVERY", 0.0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    stand_in, make = KINDS[kind]
    server = stand_in().start()
    stopped = False

    async def run() -> None:
        nonlocal stopped
        device, logins, set_password = make(server)
        set_password("changed on the device")
        try:
            first = await device._read_status()
            assert first["state"] == "auth", first
            offered = logins()
            # Still there, and asked nothing that needs the password: it goes on saying what it said.
            assert (await device._read_status())["state"] == "auth" and logins() == offered
            server.stop()
            stopped = True
            said = await device._read_status()
            assert said["state"] == "offline", f"gone, and its tile says {said}"
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        if not stopped:
            server.stop()


def test_a_device_that_waits_is_asked_whether_it_is_there_twice_a_minute_and_not_at_every_look(monkeypatch: pytest.MonkeyPatch) -> None:
    # It is saying no already. What a tile asks every few seconds is not sent to it on top of that: a
    # machine that goes off is noticed within the half minute that a change has to last anyway.
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    server = FakeKvm().start()
    server.state.password = "changed on the device"
    device = kvm.KvmDevice(DeviceSpec(id="ab12", name="KVM", base_url=server.url, username="admin", password="secret"))
    stopped = False

    async def run() -> None:
        nonlocal stopped
        try:
            assert (await device._read_status())["state"] == "auth"
            server.stop()
            stopped = True
            for _ in range(3):
                assert (await device._read_status())["state"] == "auth"  # it answered a moment ago, and is not asked again yet
            assert device._heard_at is not None
            device._heard_at -= kvm.STILL_THERE_EVERY  # (half a minute later)
            assert (await device._read_status())["state"] == "offline"
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        if not stopped:
            server.stop()


def test_through_the_wall_a_kvm_that_goes_away_while_it_waits_is_said_to_be_offline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "STATUS_TTL", 0.2)
    monkeypatch.setattr(kvm, "STILL_THERE_EVERY", 0.2)
    fake = FakeKvm().start()
    stopped = False
    try:
        with wall(tmp_path) as admin:
            device = a_wall_with_a_rejected_password(admin, fake)
            assert admin.get("/api/v1/status").json()[device]["state"] == "auth"
            fake.stop()
            stopped = True
            wait_until(lambda: admin.get("/api/v1/status").json()[device]["state"] == "offline", "the KVM is gone and its tile still says that the login failed", timeout=20)
    finally:
        if not stopped:
            fake.stop()


# --- a JetKVM that takes the password and refuses the session it gave for it --------------------------------


class Forgetful(JetState):
    """A JetKVM that forgets the session it has just given: the one it handed out is never the one it knows."""

    @property  # type: ignore[override]
    def token(self) -> Any:
        return str(uuid.uuid4())

    @token.setter
    def token(self, value: Any) -> None:
        pass


def test_a_jetkvm_that_refuses_the_session_it_gave_is_not_sent_the_password_at_every_look(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jetkvm, "RETRY_PAUSE", 0.05)  # (three seconds, as it is: looked at for three seconds here, that would be one look)
    server = FakeJetKvm(Forgetful()).start()
    device = jetkvm.JetKvmDevice(DeviceSpec(id="ab12", name="JetKVM", base_url=server.url, username="", password="secret", kind="jetkvm"))

    async def run() -> None:
        began = time.monotonic()
        try:
            while time.monotonic() - began < 3.0:
                with pytest.raises(KvmError) as refused:
                    await device.snapshot(640)
                assert refused.value.code in ("auth_failed", "no_stream"), refused.value.code
                await asyncio.sleep(0.05)
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()
    # Once, and once more for a session that somebody else's sign-in may have replaced; then not for ten seconds.
    assert server.state.logins == 2, f"the password was sent {server.state.logins} times in three seconds"
