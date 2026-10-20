"""What is done to a machine, by every make of device: not for an account that lost the right meanwhile, not left half done, and asked for again when its tile is saved again."""

from __future__ import annotations

import asyncio
import json
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from qkvm import jetkvm, kvm, redfish, update, vault
from qkvm.jetkvm import JetKvmDevice
from qkvm.redfish import RedfishDevice
from tests.fake_jetkvm import FakeJetKvm, JetState
from tests.fake_redfish import BmcState, FakeBmc
from tests.test_meanwhile import in_background
from tests.test_redfish import a_screen
from tests.test_users import account, browser
from tests.test_wall import add, snap, wait_until, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory) -> None:
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(redfish, "FOLLOW_UP", ())
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.mark.parametrize("how", ["removed", "viewer"])
def test_a_servers_power_is_not_cut_for_an_account_that_lost_the_right_while_the_controller_was_waited_for(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, how: str
) -> None:
    asked, go_on = threading.Event(), threading.Event()
    real = RedfishDevice._offered

    async def slow_to_say_what_it_offers(self: Any, resource: Any, action: str) -> Any:
        # The controller is slow over the last question before the command (which kinds of reset it offers).
        asked.set()
        await asyncio.to_thread(go_on.wait, 20)
        return await real(self, resource, action)

    bmc = FakeBmc().start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, bmc.url)
            who = account(admin, "olga", "operator")
            olga = browser(admin, "olga")
            monkeypatch.setattr(RedfishDevice, "_offered", slow_to_say_what_it_offers)
            pressing, answers = in_background(lambda: olga.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power_long"}))
            assert asked.wait(10)
            assert bmc.state.actions == []  # nothing has been sent yet
            change = {
                "removed": lambda: admin.delete(f"/api/v1/users/{who}"),
                "viewer": lambda: admin.put(f"/api/v1/users/{who}", json={"name": "olga", "role": "viewer"}),
            }[how]()
            assert change.status_code == 200, change.text
            go_on.set()
            pressing.join(40)
            assert bmc.state.actions == [], f"the server's power was cut for an account that was {how} before the wall sent the command"
            assert answers[0].status_code == 403, answers[0].text
    finally:
        go_on.set()
        bmc.stop()


def test_a_jetkvms_power_button_is_not_pressed_for_an_account_removed_while_it_was_waited_for(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    asked, go_on = threading.Event(), threading.Event()
    real = JetKvmDevice._connected

    async def slow_to_connect(self: Any, urgent: bool = False) -> Any:
        session = await real(self, urgent)
        if urgent:  # (the connection an action waits for: a JetKVM takes seconds over it, fifteen at most)
            asked.set()
            await asyncio.to_thread(go_on.wait, 20)
        return session

    jet = FakeJetKvm().start()
    jet.state.extension = "atx-power"
    try:
        with wall(tmp_path) as admin:
            device = add(admin, jet.url)
            who = account(admin, "olga", "operator")
            olga = browser(admin, "olga")
            monkeypatch.setattr(JetKvmDevice, "_connected", slow_to_connect)
            pressing, answers = in_background(lambda: olga.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power_long"}))
            assert asked.wait(30)
            assert jet.state.actions == []
            assert admin.delete(f"/api/v1/users/{who}").status_code == 200
            go_on.set()
            pressing.join(40)
            assert jet.state.actions == [], "the power button was held down for an account that was removed before the wall sent it"
            assert answers[0].status_code in (401, 403), answers[0].text
    finally:
        go_on.set()
        jet.stop()


def test_an_edit_of_the_tile_after_the_cause_was_put_right_has_the_console_asked_for_again(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # What a new connection takes over from the one it replaces is that somebody is at the server's own console,
    # and nothing else: every other reason for there being no picture is one the edit may be the cure of.
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 20)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(redfish, "LOOK_EVERY", 0)
    monkeypatch.setattr(redfish, "HICCUP", 0)
    bmc = FakeBmc(BmcState(own_console=True, screen=a_screen(), piece=50)).start()
    try:
        bmc.state.monitor_goes_dark = True  # a setting of the controller's that the wall rightly keeps away from
        with wall(tmp_path) as client:
            device = add(client, bmc.url)
            wait_until(lambda: client.get(snap(device)).status_code == 404, "it was never said that there is no picture")
            assert client.get("/api/v1/status").json()[device]["server"]["no_screen"]
            asked_before = bmc.state.web_logins
            # The admin reads that on the tile, changes the setting at the controller, and saves the tile again
            # (its password typed once more) for the wall to take note.
            bmc.state.monitor_goes_dark = False
            assert client.put(f"/api/v1/devices/{device}", json={"name": "Rack 4", "url": bmc.url, "username": "admin", "password": "secret"}).status_code == 200
            for _ in range(30):
                client.get(snap(device))
                if bmc.state.web_logins > asked_before:
                    break
                time.sleep(0.2)
            assert bmc.state.web_logins > asked_before, "the new client did not ask for the console: it took over a refusal that no longer holds"
    finally:
        bmc.stop()


def test_no_key_is_left_down_when_typing_ends_in_the_middle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The JetKVM takes the key press, and its answer to that one call does not arrive in time.
    monkeypatch.setattr(jetkvm, "RPC_TIMEOUT", 1.0)
    reports: list[dict[str, Any]] = []  # every keyboard report that went out to the device, in order
    lost: set[int] = set()
    downs = 0
    real_call, real_heard = JetKvmDevice._call, JetKvmDevice._on_message

    async def call(self: Any, session: Any, method: str, params: dict[str, Any] | None = None) -> Any:
        nonlocal downs
        if method == "keyboardReport" and params is not None:
            reports.append(params)
            if params["keys"]:
                downs += 1
                if downs == 10:
                    lost.add(session.next_id + 1)  # the tenth key goes down, and the answer to that never comes
        return await real_call(self, session, method, params)

    def heard(self: Any, session: Any, message: Any) -> None:
        try:
            data = json.loads(message)
        except (TypeError, ValueError):
            data = None
        if isinstance(data, dict) and data.get("id") in lost:
            return
        real_heard(self, session, message)

    monkeypatch.setattr(JetKvmDevice, "_call", call)
    monkeypatch.setattr(JetKvmDevice, "_on_message", heard)
    # (Over JSON-RPC, the road an older JetKVM takes: it leaves hidrpc unanswered. The same over hidrpc is in
    # test_a_jetkvm_over_hidrpc.py.)
    monkeypatch.setattr(jetkvm, "HID_SHAKE_WITHIN", 0.3)
    jet = FakeJetKvm(JetState(hidrpc=False)).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, jet.url)
            reply = admin.post(f"/api/v1/devices/{device}/actions", json={"action": "text", "text": "shutdown -h now\n"})
            assert reply.status_code == 504, reply.text
            assert downs == 10 and reports[-1]["keys"]  # the last that was waited for an answer to: the key going down
            wait_until(lambda: jet.state.down == [], f"the last thing the JetKVM was told is that key {jet.state.down} is down: nothing told it that the key was let go")
    finally:
        jet.stop()
