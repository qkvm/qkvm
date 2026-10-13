"""Somebody at a device's own console is not pushed out of it, nor asked again, because the tile was edited."""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from qkvm import jetkvm, kvm, redfish, update, vault
from qkvm.kvm import DeviceSpec
from tests.fake_jetkvm import FakeJetKvm
from tests.fake_redfish import BmcState, FakeBmc
from tests.test_jetkvm import picture
from tests.test_redfish import SOMEBODY, a_screen
from tests.test_wall import add, snap, wait_until, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 20)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(redfish, "LOOK_EVERY", 0)
    monkeypatch.setattr(redfish, "FOLLOW_UP", ())
    monkeypatch.setattr(redfish, "HICCUP", 0)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def jet() -> Iterator[FakeJetKvm]:
    server = FakeJetKvm().start()
    yield server
    server.stop()


@pytest.fixture
def with_screen() -> Iterator[FakeBmc]:
    server = FakeBmc(BmcState(own_console=True, screen=a_screen(), piece=50)).start()
    yield server
    server.stop()


def test_an_edit_of_the_tile_does_not_throw_a_person_out_of_a_jetkvms_console(tmp_path: Path, jet: FakeJetKvm) -> None:
    # The same promise, with QKVM running on: an edit of the device (a new name) makes a new client for it.
    leave, seen = threading.Event(), {}

    def at_the_console() -> None:
        async def sit() -> None:
            other = jetkvm.JetKvmDevice(DeviceSpec("x", "console", jet.url, "", "secret", kind="jetkvm"))
            await other._connected()
            seen["there"] = True
            while not leave.is_set():
                await asyncio.sleep(0.1)
            seen["thrown_out"] = other._displaced
            await other.close()

        asyncio.run(sit())

    person = threading.Thread(target=at_the_console, daemon=True)
    try:
        with wall(tmp_path) as client:
            device = add(client, jet.url)
            picture(client, device)
            person.start()
            wait_until(lambda: seen.get("there"), "the person never got in", timeout=20)
            wait_until(lambda: client.get("/api/v1/status").json()[device]["state"] == "busy", "the wall never noticed the other viewer")
            assert (jet.state.sessions, jet.state.logins) == (2, 2)
            renamed = client.put(f"/api/v1/devices/{device}", json={"name": "Lab bench", "url": jet.url, "password": ""})
            assert renamed.status_code == 200, renamed.text
            for _ in range(15):
                client.get("/api/v1/status")
                client.get(snap(device))
                time.sleep(0.2)
            leave.set()
            person.join(10)
            print("\nvideo connections made:", jet.state.sessions, "| sign-ins at the device:", jet.state.logins, "| the person was thrown out:", seen.get("thrown_out"))
            assert jet.state.sessions == 2 and not seen.get("thrown_out"), "renaming the tile threw the person at the console out"
    finally:
        leave.set()


def test_an_edit_of_the_tile_does_not_put_the_question_to_somebody_at_the_console_again(tmp_path: Path, with_screen: FakeBmc) -> None:
    # The same hold, without any restart: an edit of the device (a new name) makes a new client for it.
    bmc = with_screen
    bmc.state.held_by = SOMEBODY
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        wait_until(lambda: client.get(snap(device)).json().get("code") == "console_held", "it was never said that somebody has the console")
        wait_until(lambda: (bmc.state.watching, bmc.state.web_sessions) == (0, {}), "it did not leave")
        assert bmc.state.web_logins == 1
        assert client.put(f"/api/v1/devices/{device}", json={"name": "Rack 4, top", "url": bmc.url, "password": ""}).status_code == 200
        for _ in range(20):
            client.get(snap(device))
            time.sleep(0.1)
        print("\ntimes the console was asked for:", bmc.state.web_logins)
        assert bmc.state.web_logins == 1, "renaming the tile had the person at the console asked again"
