"""What a server's power press says afterwards: done, not done, or perhaps done, by what was seen.

From the final review of 0.2.0: a server switched on into its BIOS setup on the real AMI board was said to be "still off, not
carried out" (the board answers no read for about a minute after a change of its boot override, and the wait for "On" was
25 seconds); a server switched on by somebody while the override was being set was sent "On", which a running server takes as
nothing to do, and the press said done with the override armed; and a reset answered with an error of the controller's own was
"failed", offered for "Retry failed" and pressed again, where only a 4xx says no.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from qkvm import kvm, redfish, update, vault
from tests.fake_redfish import BmcState, FakeBmc
from tests.test_redfish import status_of
from tests.test_wall import add, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(redfish, "LOOK_EVERY", 0)
    monkeypatch.setattr(redfish, "FOLLOW_UP", ())
    monkeypatch.setattr(redfish, "HICCUP", 0)
    monkeypatch.setattr(redfish, "CONFIRM_EVERY", 0.05)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def pressed(client: object, device: str, action: str) -> tuple[int, str, str]:
    reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": action})  # type: ignore[attr-defined]
    said = reply.json()
    return reply.status_code, str(said.get("code")), str(said.get("message"))


# --- F2: switched on into its setup, through the board's busy minute --------------------------------------------------


def test_an_off_server_started_into_its_setup_is_waited_for_through_the_boards_busy_minute(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The real board's timings, scaled by a twentieth: a look's read 20 s -> 1 s, the change's wait a minute -> 3 s, the wait
    # for "On" 25 s -> 1.25 s, the busy minute after a change of the boot override -> 3 s.
    monkeypatch.setattr(redfish.RedfishDevice, "WAITS", httpx.Timeout(1.0, connect=1.0))
    monkeypatch.setattr(redfish, "BOOT_WAITS", httpx.Timeout(3.0, connect=1.0))
    monkeypatch.setattr(redfish, "CONFIRM_WITHIN", 1.25)
    monkeypatch.setattr(redfish, "CONFIRM_EVERY", 0.1)
    monkeypatch.setattr(redfish, "BOOT_BUSY", 3.0)
    bmc = FakeBmc(BmcState(power="Off", busy_after_boot_change=3.0)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, bmc.url)
            status_of(client, device, state="no_signal")
            assert pressed(client, device, "bios_setup")[0] == 200
            assert bmc.state.actions == ["system On"] and bmc.state.power == "On"
    finally:
        bmc.stop()


def test_a_server_switched_on_that_no_look_came_back_from_may_have_been_done(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Switched on, and then no read of it came back in the whole wait: whether it came on was not seen, which is "perhaps"
    # (504), never "still off, not carried out" (502, kept as failed, and offered again by a bulk run's "Retry failed").
    monkeypatch.setattr(redfish.RedfishDevice, "WAITS", httpx.Timeout(0.5, connect=1.0))
    monkeypatch.setattr(redfish, "CONFIRM_WITHIN", 1.0)
    bmc = FakeBmc(BmcState(power="Off", busy_after_reset=5.0)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, bmc.url)
            status_of(client, device, state="no_signal")
            status, code, message = pressed(client, device, "power_on")
            assert (status, code) == (504, "timeout") and "may have been done" in message, message
            assert bmc.state.actions == ["system On"]
    finally:
        bmc.stop()


def test_a_server_seen_off_all_the_while_was_not_switched_on(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (What stays as it was: reads that came back and showed it off are "not carried out".)
    monkeypatch.setattr(redfish, "CONFIRM_WITHIN", 0.5)
    bmc = FakeBmc(BmcState(power="Off", drops=["On"])).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, bmc.url)
            status_of(client, device, state="no_signal")
            status, code, message = pressed(client, device, "power_on")
            assert (status, code) == (502, "action_failed") and "still off" in message
    finally:
        bmc.stop()


# --- F3: switched on by somebody while the override was being set -------------------------------------------------------


def test_a_server_switched_on_while_the_override_was_set_is_restarted_where_the_change_is_read_back(tmp_path: Path) -> None:
    # Read off, the change taken for later (202), and somebody switches the server on meanwhile: the read that shows the
    # override set shows it on as well, and a restart goes out, not "On" (which a running server takes as nothing to do).
    bmc = FakeBmc(BmcState(power="Off", boot_status=202, power_after_change="On")).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, bmc.url)
            status_of(client, device, state="no_signal")
            assert pressed(client, device, "bios_setup")[0] == 200
            assert bmc.state.actions == ["system ForceRestart"] and bmc.state.boot_override == ("Disabled", "None")
    finally:
        bmc.stop()


def test_a_server_switched_on_while_the_override_was_set_is_restarted_where_the_change_is_answered_204(tmp_path: Path) -> None:
    # (The coordinator, round 3 of 0.2.1; until then a limit in the README.) The same where the change is answered 204, which is
    # taken as made and not read back: the power is read once more before the restart, and the server switched on meanwhile is
    # restarted. (Sent "On", it took that as nothing to do, the button said done, and the override waited for its next boot.)
    bmc = FakeBmc(BmcState(power="Off", power_after_change="On")).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, bmc.url)
            status_of(client, device, state="no_signal")
            assert pressed(client, device, "bios_setup")[0] == 200
            assert bmc.state.actions == ["system ForceRestart"] and bmc.state.boot_override == ("Disabled", "None")
    finally:
        bmc.stop()


def test_a_server_that_begins_to_change_its_state_while_the_override_is_set_is_not_restarted_and_the_override_is_cleared(tmp_path: Path) -> None:
    bmc = FakeBmc(BmcState(power="Off", boot_status=202, power_after_change="PoweringOn")).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, bmc.url)
            status_of(client, device, state="no_signal")
            status, code, message = pressed(client, device, "bios_setup")
            assert (status, code) == (502, "action_failed") and "Nothing was restarted" in message and "cleared again" in message, message
            assert bmc.state.actions == [] and bmc.state.boot_override[0] == "Disabled"
    finally:
        bmc.stop()


def test_the_stand_in_takes_on_for_a_server_that_is_on_as_nothing_to_do(tmp_path: Path) -> None:
    # (As a real controller does: no boot, so a one-time override stays for the next one.)
    bmc = FakeBmc(BmcState(power="On", boot_override=("Once", "BiosSetup"))).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, bmc.url)
            status_of(client, device, state="online")
            reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "power_on"})
            assert reply.status_code == 200 and bmc.state.actions == []  # (already on: nothing sent)
        with httpx.Client(base_url=bmc.url) as direct:
            token = direct.post("/redfish/v1/SessionService/Sessions", json={"UserName": "admin", "Password": "secret"}).headers["x-auth-token"]
            assert direct.post("/redfish/v1/Systems/Self/Actions/ComputerSystem.Reset", json={"ResetType": "On"}, headers={"X-Auth-Token": token}).status_code == 204
        assert bmc.state.boot_override == ("Once", "BiosSetup")
    finally:
        bmc.stop()


# --- F5: only a 4xx is a refusal --------------------------------------------------------------------------------------


@pytest.mark.parametrize("action", ["atx_reset", "atx_power_long", "reboot"])
def test_a_command_answered_with_an_error_of_the_controllers_own_may_have_been_done(tmp_path: Path, action: str) -> None:
    bmc = FakeBmc(BmcState(reset_status=500)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, bmc.url)
            status_of(client, device, state="online")
            if action == "reboot":
                bmc.state.reset_status, bmc.state.manager_reset_status = None, 500
            status, code, message = pressed(client, device, action)
            assert (status, code) == (504, "timeout") and "may" in message, message
    finally:
        bmc.stop()


@pytest.mark.parametrize(
    ("action", "last_read"),
    [("reboot", "/redfish/v1/Managers/Self"), ("atx_reset", "/redfish/v1/Systems/Self/ResetActionInfo"), ("atx_power_long", "/redfish/v1/Systems/Self/ResetActionInfo")],
)
def test_a_press_that_never_went_out_is_said_to_be_not_done(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str, last_read: str) -> None:
    # (The desktop's follow-up 4, 0.2.1.) Between the last read before a command and the command, the controller forgets every
    # session (its web service restarted), and its root is slow after it: the command is answered 401 (not done), and the sign-in
    # that follows does not get as far as the password, its root read before that not answering in time. Nothing was done:
    # that is what is said, never "done" (a controller's restart was), nor "it may have been done" (the reset button was).
    monkeypatch.setattr(redfish.RedfishDevice, "WAITS", httpx.Timeout(0.5, connect=2.0, pool=2.0))  # (the root read waits twice this)
    bmc = FakeBmc().start()
    try:
        with wall(tmp_path) as client:
            device = add(client, bmc.url)
            status_of(client, device, state="online")
            bmc.state.forget_after = (last_read, 3.0)
            status, code, message = pressed(client, device, action)
            assert (status, code) == (502, "action_failed") and message.startswith("It was not done"), (status, code, message)
            assert bmc.state.actions == [] and bmc.state.forget_after is None
            entry = next(e for e in client.get("/api/v1/audit").json()["entries"] if e["event"].startswith("action"))
            assert entry["event"] == "action_failed" and entry["action"] == action
    finally:
        bmc.stop()


def test_a_command_whose_read_before_it_gets_no_answer_is_not_sent_and_says_so(bmc_fast: FakeBmc) -> None:
    # (The same, where the session is gone before the command: the read of the computer it is decided by is answered 401, and
    # the sign-in after it does not get as far as the password.) Nothing went out: "Nothing was sent", not "it may have been".
    async def run() -> kvm.KvmError:
        spec = kvm.DeviceSpec(id="ab12", name="server", base_url=bmc_fast.url, username="admin", password="secret", kind="redfish")
        device = redfish.RedfishDevice(spec)
        try:
            await device.identify()
            bmc_fast.state.tokens.clear()  # (forgotten: the read of what the reset offers is refused, and signed in again)
            bmc_fast.state.root_takes = 3.0
            with pytest.raises(kvm.KvmError) as refused:
                await device.act("atx_reset")
            return refused.value
        finally:
            bmc_fast.state.root_takes = 0.0
            await device.close()

    refused = asyncio.run(run())
    assert refused.code == "action_failed" and refused.message.startswith("Nothing was sent") and redfish.never_sent(refused), refused.message
    assert bmc_fast.state.actions == [] and not any(request.startswith("POST") for request in bmc_fast.state.requests)


@pytest.fixture
def bmc_fast(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeBmc]:
    monkeypatch.setattr(redfish.RedfishDevice, "WAITS", httpx.Timeout(0.5, connect=2.0, pool=2.0))
    server = FakeBmc().start()
    yield server
    server.stop()


def test_a_light_answered_with_an_error_of_the_controllers_own_may_have_been_switched(tmp_path: Path) -> None:
    bmc = FakeBmc(BmcState(light_status=503)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, bmc.url)
            status_of(client, device, state="online")
            assert pressed(client, device, "locate_on")[:2] == (504, "timeout")
    finally:
        bmc.stop()


def test_a_command_the_controller_refuses_is_said_to_be_refused(tmp_path: Path) -> None:
    # (What stays as it was: a 4xx is a no, said in its own words, and nothing was done.)
    bmc = FakeBmc(BmcState(reset_refused=True)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, bmc.url)
            status_of(client, device, state="online")
            status, code, message = pressed(client, device, "atx_reset")
            assert (status, code) == (502, "action_failed") and "not in the list of acceptable values" in message
    finally:
        bmc.stop()
