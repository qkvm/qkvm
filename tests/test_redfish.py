"""Servers on the wall, through their management controller (Redfish)."""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import logging
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from websockets.exceptions import ConnectionClosedOK

from qkvm import alerts, ami, discover, kvm, redfish, update, vault
from qkvm import server as server_module
from qkvm.redfish import link, locator, named
from tests import fake_redfish
from tests.aspeed_frames import Frame
from tests.fake_kvm import FakeKvm
from tests.fake_redfish import BmcState, FakeBmc
from tests.test_users import account, browser
from tests.test_wall import add, snap, wait_until, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(redfish, "LOOK_EVERY", 0)  # every question about a server's status has it read again
    monkeypatch.setattr(redfish, "FOLLOW_UP", ())  # and so nothing needs looking at again of its own accord
    monkeypatch.setattr(redfish, "HICCUP", 0)  # a look that fails says so at once, unless a test is about that
    monkeypatch.setattr(redfish, "CONFIRM_EVERY", 0.05)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def bmc() -> Iterator[FakeBmc]:
    server = FakeBmc().start()
    yield server
    server.stop()


def status_of(client: object, device: str, **wanted: object) -> dict:
    """The device's status once it says what is wanted (the status is read in the background)."""
    found: dict = {}

    def there() -> bool:
        found.clear()
        found.update(client.get("/api/v1/status").json()[device])  # type: ignore[attr-defined]
        return all(found.get(key) == value for key, value in wanted.items())

    wait_until(there, f"the status never said {wanted}")
    return found


def test_a_server_is_recognised_from_its_address_and_shows_how_it_is(tmp_path: Path, bmc: FakeBmc) -> None:
    with wall(tmp_path) as client:
        reply = client.post("/api/v1/devices", json={"url": bmc.url, "username": "admin", "password": "secret"})
        assert reply.status_code == 201, reply.text
        added = reply.json()
        assert added["device"]["kind"] == "redfish"
        assert added["device"]["name"] == "127.0.0.1:" + bmc.url.rsplit(":", 1)[1]  # it has no host name to go by
        assert added["about"] == {"model": "SRV-2200", "version": "1.42.0", "hostname": None}
        status = status_of(client, added["device"]["id"], state="online")
        assert status["picture"] is False and status["kind"] == "redfish"
        assert status["atx"] == {"enabled": True, "power": True, "hdd": None}  # the wall's power buttons apply
        assert status["health"]["temp"] == 61  # the hotter of the two processors
        assert status["about"] == {"model": "SRV-2200", "version": "1.42.0"}
        server = status["server"]
        assert (server["power"], server["health"], server["processors"], server["memory_gib"]) == ("On", "OK", 2, 256)
        assert server["processor"] == "Intel Xeon Silver 4410Y"
        assert server["temperatures"] == [
            {"name": "CPU0_TEMP", "celsius": 61, "ok": True}, {"name": "CPU1_TEMP", "celsius": 55, "ok": True}, {"name": "DIMM_A_TEMP", "celsius": 45, "ok": True},
        ]  # fmt: skip
        assert server["unwell"] == ["CPU1_FAN"]  # what the controller is not happy with, by name
        assert server["fans"] == [  # the one that is not fitted is not listed
            {"name": "CPU0_FAN", "reading": 1650, "unit": "RPM", "ok": True},
            {"name": "CPU1_FAN", "reading": 450, "unit": "RPM", "ok": False},
        ]
        # This controller has no console qKVM reads. That is found out by asking once, without the password,
        # and from then on the tile is told plainly that there is no picture, rather than left to guess.
        assert status["screen"] is True  # (not known yet)
        wait_until(lambda: client.get(snap(added["device"]["id"])).status_code == 404, "it was never said that there is no picture")
        assert client.get(snap(added["device"]["id"])).json()["code"] == "no_picture"
        assert status_of(client, added["device"]["id"], screen=False)["server"]["no_screen"] is None
        assert bmc.state.web_logins == 0


def test_one_sign_in_serves_many_looks_and_is_given_back(tmp_path: Path, bmc: FakeBmc) -> None:
    with wall(tmp_path) as client:
        device = add(client, bmc.url)

        def asked(place: str) -> int:
            return sum(1 for request in bmc.state.requests if request.endswith(place))

        def looked_often() -> bool:
            status_of(client, device, state="online")
            return asked("/Systems/Self") >= 5

        wait_until(looked_often, "the status was not read again")
        assert bmc.state.logins == 1  # the sign-in that checked the password is the one the tile goes on using
        # Where things are, and what rarely changes, is asked once and not with every look. (The controller's own resource
        # twice when the tile is added: once for the service it hosts, which binds its number to the session, see
        # redfish.RedfishDevice._controller_under, and once for what it is.)
        assert (asked("/Systems"), asked("/Chassis/Self"), asked("/Managers/Self")) == (1, 1, 2)
        assert client.delete(f"/api/v1/devices/{device}").status_code == 200
        assert bmc.state.signed_out == 1 and bmc.state.tokens == {}  # no session is left behind on the controller
        # A login that was only tried out, and not kept, is given back as well.
        bmc.state.system_link = "/somewhere/else"
        assert client.post("/api/v1/devices", json={"url": bmc.url, "password": "secret"}).status_code == 422
        assert bmc.state.logins == 2 and bmc.state.tokens == {}


def test_a_controller_that_dawdles_over_the_sign_out_does_not_hold_up_the_removal(tmp_path: Path, bmc: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(redfish, "SIGN_OUT_WITHIN", 1.0)
    bmc.state.dawdles = True  # it answers, a byte at a time, for ten seconds: no single wait for the next piece runs out
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        status_of(client, device, state="online")
        began = time.monotonic()
        assert client.delete(f"/api/v1/devices/{device}").status_code == 200
        assert time.monotonic() - began < 4
        assert bmc.state.signed_out == 1  # it was asked, all the same


def test_a_controller_is_not_asked_more_often_than_a_server_changes(tmp_path: Path, bmc: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(redfish, "LOOK_EVERY", 30)
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        status_of(client, device, state="online")
        before = len(bmc.state.requests)
        for _ in range(8):  # the page asks every few seconds, and so does every other browser that has the wall open
            assert client.get("/api/v1/status").json()[device]["state"] == "online"
        assert len(bmc.state.requests) == before
        # What somebody did to the server shows at the next look, not half a minute later.
        assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power_long"}).status_code == 200
        status_of(client, device, state="no_signal")


def test_a_server_that_is_off_is_there_and_dark(tmp_path: Path, bmc: FakeBmc) -> None:
    bmc.state.power = "Off"
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        status = status_of(client, device, state="no_signal")
        assert status["atx"]["power"] is False and status["video"]["signal"] is False and status["server"]["power"] == "Off"


def test_the_power_buttons_mean_what_they_mean_on_a_server(tmp_path: Path, bmc: FakeBmc) -> None:
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        act = f"/api/v1/devices/{device}/actions"
        assert client.post(act, json={"action": "atx_power"}).status_code == 200  # running: ask it to shut down
        assert bmc.state.actions == ["system GracefulShutdown"]
        status_of(client, device, state="no_signal")
        assert client.post(act, json={"action": "atx_power"}).status_code == 200  # off: switch it on
        assert client.post(act, json={"action": "atx_reset"}).status_code == 200
        assert client.post(act, json={"action": "atx_power_long"}).status_code == 200
        assert client.post(act, json={"action": "reboot"}).status_code == 200  # the controller itself
        assert bmc.state.actions[1:] == ["system On", "system ForceRestart", "system ForceOff", "controller ForceRestart"]
        # What a keyboard-and-screen device does, a controller does not: said before anything is sent.
        for other in ({"action": "ctrl_alt_del"}, {"action": "text", "text": "hello"}, {"action": "wol", "mac": "02:00:5E:00:53:01"}):
            reply = client.post(act, json=other)
            assert (reply.status_code, reply.json()["code"]) == (422, "invalid"), other
        entries = [e for e in client.get("/api/v1/audit").json()["entries"] if e["event"] == "action"]
        assert [e["action"] for e in entries][::-1] == ["atx_power", "atx_power", "atx_reset", "atx_power_long", "reboot"]


def test_start_into_bios_setup_sets_the_boot_override_then_restarts_or_powers_on(tmp_path: Path, bmc: FakeBmc) -> None:
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        act = f"/api/v1/devices/{device}/actions"
        status = status_of(client, device, state="online")
        assert "bios_setup" in status["can"]  # the board allows the BiosSetup boot override
        # On: the boot override is set (once), then the server is restarted.
        assert client.post(act, json={"action": "bios_setup"}).status_code == 200
        assert bmc.state.changes[-1]["Boot"] == {"BootSourceOverrideEnabled": "Once", "BootSourceOverrideTarget": "BiosSetup"}
        assert bmc.state.actions == ["system ForceRestart"]
        # A restart (becoming "On") clears a one-time override, as a real board does.
        assert bmc.state.boot_override == ("Disabled", "None")
        # Off: the boot override is set, then the server is switched on.
        bmc.state.power = "Off"
        status_of(client, device, state="no_signal")
        assert client.post(act, json={"action": "bios_setup"}).status_code == 200
        assert bmc.state.actions == ["system ForceRestart", "system On"]
        entries = [e["action"] for e in client.get("/api/v1/audit").json()["entries"] if e["event"] == "action"]
        assert entries[::-1] == ["bios_setup", "bios_setup"]


def test_a_change_answered_204_is_taken_as_made_and_the_restart_follows_at_once(tmp_path: Path, bmc: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # The real AMI board answered the change of its boot override 204, and then left reads of the computer unanswered for about
    # a minute while it took the restart sent right after. A 204 is the standard's word that the change was made: no read goes
    # between it and the restart (one would have run out, and the button with it).
    monkeypatch.setattr(redfish.RedfishDevice, "WAITS", httpx.Timeout(1.0, connect=1.0))
    bmc.state.busy_after_boot_change = 2.5
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        status_of(client, device, state="online")
        before = len(bmc.state.requests)
        assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "bios_setup"}).status_code == 200
        assert bmc.state.actions == ["system ForceRestart"]
        asked = bmc.state.requests[before:]
        changed = asked.index("PATCH /redfish/v1/Systems/Self")
        restarted = asked.index("POST /redfish/v1/Systems/Self/Actions/ComputerSystem.Reset")
        assert changed < restarted and "GET /redfish/v1/Systems/Self" not in asked[changed:restarted]


def test_a_board_that_does_not_allow_a_bios_setup_boot_is_not_offered_it(tmp_path: Path, bmc: FakeBmc) -> None:
    bmc.state.boot_targets = ["None", "Pxe", "Hdd"]  # no "BiosSetup" among the allowed boot overrides
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        act = f"/api/v1/devices/{device}/actions"
        status = status_of(client, device, state="online")
        assert "bios_setup" not in status["can"]
        reply = client.post(act, json={"action": "bios_setup"})
        assert (reply.status_code, reply.json()["code"]) == (422, "invalid") and "BiosSetup" in reply.json()["message"]
        assert bmc.state.actions == [] and "Boot" not in dict(enumerate(bmc.state.changes)).get(0, {})


def test_a_bios_setup_whose_restart_is_refused_clears_the_override_again(tmp_path: Path, bmc: FakeBmc) -> None:
    # The override is set, then the controller refuses the restart it offered: the override is set back to Disabled, so the
    # server's next boot of any kind (patching at night, a crash) does not stop in its BIOS setup; and the answer says so.
    bmc.state.reset_refused = True
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        status_of(client, device, state="online")
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "bios_setup"})
        assert reply.status_code == 502 and "cleared again" in reply.json()["message"]
        assert bmc.state.boot_override[0] == "Disabled"
        assert [change["Boot"]["BootSourceOverrideEnabled"] for change in bmc.state.changes if "Boot" in change] == ["Once", "Disabled"]


def test_start_into_bios_setup_does_not_replace_another_tools_boot_override(tmp_path: Path, bmc: FakeBmc) -> None:
    bmc.state.boot_override = ("Once", "Pxe")  # (a provisioning tool's network boot, say)
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        status_of(client, device, state="online")
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "bios_setup"})
        assert (reply.status_code, reply.json()["code"]) == (409, "action_failed") and "override" in reply.json()["message"]
        assert bmc.state.boot_override == ("Once", "Pxe") and bmc.state.actions == [] and not any("Boot" in change for change in bmc.state.changes)


def test_start_into_bios_setup_is_for_one_machine_not_a_bulk_run(tmp_path: Path, bmc: FakeBmc) -> None:
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        status_of(client, device, state="online")
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "bios_setup", "batch": "a-run"})
        assert (reply.status_code, reply.json()["code"]) == (422, "invalid") and "one machine at a time" in reply.json()["message"]
        assert bmc.state.actions == []


def boot_changes(bmc: FakeBmc) -> list[str]:
    """BootSourceOverrideEnabled of every change of the boot override the controller took, in order."""
    return [change["Boot"]["BootSourceOverrideEnabled"] for change in bmc.state.changes if "Boot" in change]


def test_a_bios_setup_whose_change_gets_no_answer_restarts_nothing_and_clears_it(tmp_path: Path, bmc: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # The change went out and its answer did not come back (the real board took 20 s over one): the override may be set. No
    # restart goes out, and the override is cleared again where the controller can be reached; where clearing gets no answer
    # either, the answer says that it may be set, never "nothing was done".
    monkeypatch.setattr(redfish.RedfishDevice, "WAITS", httpx.Timeout(1.0, connect=1.0))
    monkeypatch.setattr(redfish, "BOOT_WAITS", httpx.Timeout(1.0, connect=1.0))
    bmc.state.slow_boot_changes, bmc.state.slow_boot_by = 1, 1.6
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        act = f"/api/v1/devices/{device}/actions"
        status_of(client, device, state="online")
        reply = client.post(act, json={"action": "bios_setup"})
        assert (reply.status_code, reply.json()["code"]) == (502, "action_failed") and "cleared again" in reply.json()["message"]
        assert bmc.state.actions == [] and bmc.state.boot_override[0] == "Disabled" and boot_changes(bmc) == ["Once", "Disabled"]
        bmc.state.slow_boot_changes = 2  # (the change, and the clearing after it)
        reply = client.post(act, json={"action": "bios_setup"})
        assert (reply.status_code, reply.json()["code"]) == (504, "timeout") and "may be set" in reply.json()["message"]
        assert bmc.state.actions == []


def test_a_bios_setup_whose_restart_gets_an_error_of_the_controllers_own_leaves_the_override_and_says_so(tmp_path: Path, bmc: FakeBmc) -> None:
    # A 5xx is no refusal for certain: the restart may have been done, and the override may be what the server starts into.
    bmc.state.reset_status = 500
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        status_of(client, device, state="online")
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "bios_setup"})
        assert (reply.status_code, reply.json()["code"]) == (504, "timeout") and "may or may not" in reply.json()["message"]
        assert bmc.state.boot_override == ("Once", "BiosSetup") and boot_changes(bmc) == ["Once"]


def test_another_tools_override_set_meanwhile_is_not_replaced_either(tmp_path: Path, bmc: FakeBmc) -> None:
    # Another tool sets its override between the wall's look and its change: the controller refuses the change (the mark it was
    # decided on is old), the wall reads again, sees the override, and does not replace it with "meant whatever the state".
    bmc.state.override_meanwhile = ("Once", "Pxe")
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        act = f"/api/v1/devices/{device}/actions"
        status_of(client, device, state="online")
        reply = client.post(act, json={"action": "bios_setup"})
        assert (reply.status_code, reply.json()["code"]) == (409, "action_failed") and "override" in reply.json()["message"]
        assert bmc.state.boot_override == ("Once", "Pxe") and bmc.state.actions == [] and boot_changes(bmc) == []
        # A controller that does not take back the marks it hands out: read again, looked at again, and sent with "*".
        bmc.state.boot_override, bmc.state.strict_marks = ("Disabled", "None"), True
        assert client.post(act, json={"action": "bios_setup"}).status_code == 200
        assert boot_changes(bmc) == ["Once"] and bmc.state.actions == ["system ForceRestart"]


def test_a_refused_mark_and_no_second_read_is_nothing_done(bmc: FakeBmc) -> None:
    # The change was refused for its mark (412: nothing set), and the controller then could not be read again: said as
    # nothing done, not as a timeout (which the page reads as "it may have been done").
    bmc.state.strict_marks = True

    async def run() -> None:
        device = redfish.RedfishDevice(kvm.DeviceSpec(id="t4", name="server", base_url=bmc.url, username="admin", password="secret", kind="redfish"))
        try:
            refused_once = False
            reading, requesting = device._read, device._request

            async def noting(method: str, path: str, **kwargs: Any) -> httpx.Response:
                nonlocal refused_once
                reply = await requesting(method, path, **kwargs)
                refused_once = refused_once or (method == "PATCH" and reply.status_code == 412)
                return reply

            async def read_fails_after_it(path: str, urgent: bool = False, vital: bool = True, waits: Any = None) -> tuple[dict[str, Any], str | None]:
                if refused_once and path.endswith("/Systems/Self"):
                    raise kvm.KvmError("timeout", "Device did not respond in time", 504)
                return await reading(path, urgent, vital, waits)

            device._request = noting  # type: ignore[method-assign]
            device._read = read_fails_after_it  # type: ignore[method-assign]
            with pytest.raises(kvm.KvmError) as refused:
                await device.act("bios_setup")
            assert refused.value.code == "action_failed" and refused.value.message.startswith("Nothing was done")
            assert bmc.state.actions == [] and boot_changes(bmc) == []
        finally:
            await device.close()

    asyncio.run(run())


def test_a_bios_setup_the_controller_takes_and_does_not_show_restarts_nothing(tmp_path: Path, bmc: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # "Accepted" (202) and the override does not show: a restart would not land in the setup. Nothing is restarted, and the
    # override is cleared, in case it is made later. One that answers 202 and shows it goes on to the restart.
    monkeypatch.setattr(redfish, "CONFIRM_WITHIN", 0.5)
    bmc.state.boot_status, bmc.state.boot_kept = 202, False
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        act = f"/api/v1/devices/{device}/actions"
        status_of(client, device, state="online")
        reply = client.post(act, json={"action": "bios_setup"})
        # (The seventh review's 1.) It showed off when it was cleared: the clearing went out before a change the controller
        # accepted and may yet make, and cannot undo it. A "maybe", said so.
        said = reply.json()["message"]
        assert (reply.status_code, reply.json()["code"]) == (504, "timeout") and "does not show it set" in said
        assert "should the controller still make the change it accepted" in said
        assert bmc.state.actions == [] and boot_changes(bmc) == ["Once", "Disabled"]
        bmc.state.boot_kept = True
        assert client.post(act, json={"action": "bios_setup"}).status_code == 200
        assert bmc.state.actions == ["system ForceRestart"]


def test_a_boot_override_is_compared_without_regard_to_case(tmp_path: Path, bmc: FakeBmc) -> None:
    bmc.state.boot_override = ("CONTINUOUS", "biossetup")  # an override for every boot, in a controller's own letters: not replaced
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        act = f"/api/v1/devices/{device}/actions"
        status_of(client, device, state="online")
        reply = client.post(act, json={"action": "bios_setup"})
        assert (reply.status_code, reply.json()["code"]) == (409, "action_failed") and boot_changes(bmc) == []
        bmc.state.boot_override = ("once", "biossetup")  # this action's own, from an earlier press, not booted since: set again
        assert client.post(act, json={"action": "bios_setup"}).status_code == 200
        assert boot_changes(bmc) == ["Once"] and bmc.state.actions == ["system ForceRestart"]


def test_a_bios_setup_whose_switching_on_is_not_seen_says_the_override_stays(tmp_path: Path, bmc: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(redfish, "CONFIRM_WITHIN", 0.5)
    bmc.state.power, bmc.state.drops = "Off", ["On"]  # "accepted", and the server stays off
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        status_of(client, device, state="no_signal")
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "bios_setup"})
        assert reply.status_code == 502 and "still off" in reply.json()["message"] and "stays set" in reply.json()["message"]
        assert bmc.state.boot_override == ("Once", "BiosSetup")


def test_a_change_of_the_boot_override_is_waited_for_longer_than_a_look(tmp_path: Path, bmc: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The fourth review's 2.) The real board answered the change after 19.8 s, all but the 20 s a look is given: the change,
    # the restart and the clearing wait BOOT_WAITS (a minute) instead, so a slow answer is no "may be set".
    monkeypatch.setattr(redfish.RedfishDevice, "WAITS", httpx.Timeout(1.0, connect=1.0))
    monkeypatch.setattr(redfish, "BOOT_WAITS", httpx.Timeout(4.0, connect=1.0))
    bmc.state.slow_boot_changes, bmc.state.slow_boot_by = 1, 1.6
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        status_of(client, device, state="online")
        assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "bios_setup"}).status_code == 200
        assert boot_changes(bmc) == ["Once"] and bmc.state.actions == ["system ForceRestart"]


def test_a_power_change_seen_on_the_second_read_is_not_gone_over(tmp_path: Path, bmc: FakeBmc) -> None:
    # (The fourth review's 3.) The server begins to shut down as the change comes: the controller refuses the change for its
    # old mark, the wall reads again, and the power is looked at again too, not only the override: nothing is restarted.
    bmc.state.power_meanwhile = "PoweringOff"
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        status_of(client, device, state="online")
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "bios_setup"})
        assert reply.status_code == 502 and "changing its state" in reply.json()["message"]
        assert bmc.state.actions == [] and boot_changes(bmc) == []


def test_clearing_leaves_another_tools_override_set_meanwhile(tmp_path: Path, bmc: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The fourth review's 4.) Accepted (202), and right after it another tool sets its network boot: the wall's override does
    # not show, nothing is restarted, and the clearing does not wipe the other tool's override.
    monkeypatch.setattr(redfish, "CONFIRM_WITHIN", 0.5)
    bmc.state.boot_status, bmc.state.override_after = 202, ("Once", "Pxe")
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        status_of(client, device, state="online")
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "bios_setup"})
        # (The wall's change, accepted for later, may still come: a "maybe", as the history keeps it.)
        assert reply.status_code == 504 and "another tool's now (Pxe, Once)" in reply.json()["message"]
        assert "may yet be made late" in reply.json()["message"]
        assert bmc.state.boot_override == ("Once", "Pxe") and boot_changes(bmc) == ["Once"] and bmc.state.actions == []


def test_a_clearing_accepted_for_later_is_read_back_until_it_shows(tmp_path: Path, bmc: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The fifth review's M1.) The restart is refused, and the clearing is answered 202 and not made: it is not said to be
    # cleared, but that the override may be set. One answered 202 and made shows Disabled, and is "cleared again".
    monkeypatch.setattr(redfish, "CONFIRM_WITHIN", 0.5)
    bmc.state.reset_refused, bmc.state.clear_status, bmc.state.clear_kept = True, 202, False
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        act = f"/api/v1/devices/{device}/actions"
        status_of(client, device, state="online")
        reply = client.post(act, json={"action": "bios_setup"})
        assert reply.status_code == 504 and "could not be cleared" in reply.json()["message"]  # (a "maybe", in the history too)
        assert bmc.state.boot_override == ("Once", "BiosSetup")
        bmc.state.boot_override, bmc.state.clear_kept = ("Disabled", "None"), True
        reply = client.post(act, json={"action": "bios_setup"})
        assert reply.status_code == 502 and "cleared again" in reply.json()["message"] and bmc.state.boot_override[0] == "Disabled"


def test_a_press_that_comes_late_to_its_restart_goes_no_further_and_its_clearing_is_not_cut(tmp_path: Path, bmc: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The fifth review's M2, and the sixth's M1.) A controller that takes longer than SETUP_WITHIN over the change: no
    # restart goes out that late (whoever pressed may have stopped waiting), and the override is cleared again; the
    # clearing, slow too, is not cut off by that time (cut, it left the override set for the next boot).
    monkeypatch.setattr(redfish, "SETUP_WITHIN", 1.0)
    monkeypatch.setattr(redfish, "BOOT_WAITS", httpx.Timeout(10.0, connect=1.0))
    bmc.state.slow_boot_changes, bmc.state.slow_boot_by = 2, 1.6  # (the change, and the clearing)
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        status_of(client, device, state="online")
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "bios_setup"})
        assert (reply.status_code, reply.json()["code"]) == (502, "action_failed")
        assert "took more than" in reply.json()["message"] and "cleared again" in reply.json()["message"]
        assert bmc.state.actions == [] and boot_changes(bmc) == ["Once", "Disabled"] and bmc.state.boot_override[0] == "Disabled"


def test_no_restart_goes_out_past_the_press_time_also_after_a_new_sign_in(tmp_path: Path, bmc: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The seventh review's 3.) The restart is answered "sign in first" (the controller forgot its sessions) after the press's
    # time ran out: it is not sent again after the new sign-in; nothing is restarted, and the override is cleared.
    monkeypatch.setattr(redfish, "SETUP_WITHIN", 1.0)
    bmc.state.reset_signs_out_once, bmc.state.reset_answer_takes = True, 1.5
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        status_of(client, device, state="online")
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "bios_setup"})
        assert reply.status_code == 502 and "took more than" in reply.json()["message"] and "cleared again" in reply.json()["message"]
        assert bmc.state.actions == [] and bmc.state.boot_override[0] == "Disabled"


def test_an_answer_to_the_change_that_cannot_be_read_is_a_maybe(tmp_path: Path, bmc: FakeBmc) -> None:
    # (The seventh review's 4.) The change was made and answered "moved" to an address that is none: no answer that can be
    # read, so it may be set. Nothing is restarted, and it is cleared again (it was left set, unsaid).
    bmc.state.boot_moved_once = True
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        status_of(client, device, state="online")
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "bios_setup"})
        assert reply.status_code == 502 and "cleared again" in reply.json()["message"]
        assert bmc.state.actions == [] and boot_changes(bmc) == ["Once", "Disabled"] and bmc.state.boot_override[0] == "Disabled"


def test_a_refused_restart_while_the_change_may_yet_come_and_another_override_shows_is_a_maybe(tmp_path: Path, bmc: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The seventh review's 5.) The change accepted for later (202), not readable back in time (the controller busy), another
    # tool's network boot showing when the restart is refused: left as it is, and a "maybe" (504), as every other.
    monkeypatch.setattr(redfish.RedfishDevice, "WAITS", httpx.Timeout(1.0, connect=1.0))
    monkeypatch.setattr(redfish, "BOOT_WAITS", httpx.Timeout(4.0, connect=1.0))
    monkeypatch.setattr(redfish, "CONFIRM_WITHIN", 0.5)
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        status_of(client, device, state="online")
        bmc.state.boot_status, bmc.state.override_after, bmc.state.busy_after_boot_change = 202, ("Once", "Pxe"), 2.0
        bmc.state.reset_refused = True
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "bios_setup"})
        said = reply.json()["message"]
        assert (reply.status_code, reply.json()["code"]) == (504, "timeout")
        assert "another tool's now (Pxe, Once)" in said and "may yet be made late" in said
        assert bmc.state.boot_override == ("Once", "Pxe") and boot_changes(bmc) == ["Once"]


def test_a_change_seen_whole_does_not_make_another_tools_override_the_press_own(tmp_path: Path, bmc: FakeBmc) -> None:
    # (The sixth review's L1.) Disabled with Pxe before (as many controllers keep it after a network boot); the change is
    # answered 204 (made whole), another tool sets Once/Pxe right after, and the restart is refused: that override is not
    # taken for a change of the press's made in part, and is left.
    bmc.state.boot_override, bmc.state.override_after, bmc.state.reset_refused = ("Disabled", "Pxe"), ("Once", "Pxe"), True
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        status_of(client, device, state="online")
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "bios_setup"})
        assert reply.status_code == 502 and "another tool's now (Pxe, Once)" in reply.json()["message"]
        assert bmc.state.boot_override == ("Once", "Pxe") and boot_changes(bmc) == ["Once"]


def test_set_before_the_press_is_said_only_while_it_shows(tmp_path: Path, bmc: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The sixth review's L2.) Once/BiosSetup before the press; the change is accepted for later and not made, and another
    # tool sets Continuous/Pxe: what is said is that override, not "set already before this press".
    monkeypatch.setattr(redfish, "CONFIRM_WITHIN", 0.5)
    bmc.state.boot_override, bmc.state.boot_status, bmc.state.boot_kept = ("Once", "BiosSetup"), 202, False
    bmc.state.override_after = ("Continuous", "Pxe")
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        status_of(client, device, state="online")
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "bios_setup"})
        said = reply.json()["message"]
        assert reply.status_code == 504 and "another tool's now (Pxe, Continuous)" in said and "set already before" not in said
        assert bmc.state.boot_override == ("Continuous", "Pxe") and bmc.state.actions == []


def test_a_setup_boot_set_before_the_press_is_left_as_it_was(tmp_path: Path, bmc: FakeBmc) -> None:
    # (The fifth review's L2.) Set already before the press (an earlier press, not booted since): a press whose restart is
    # refused leaves it as it found it, and says so, not "nothing was done" over a clearing of it.
    bmc.state.boot_override, bmc.state.reset_refused = ("Once", "BiosSetup"), True
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        status_of(client, device, state="online")
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "bios_setup"})
        assert reply.status_code == 502 and "set already before this press" in reply.json()["message"]
        assert bmc.state.boot_override == ("Once", "BiosSetup") and boot_changes(bmc) == ["Once"]


def test_a_change_made_in_part_is_cleared_as_the_press_own(tmp_path: Path, bmc: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The fifth review's L3.) A controller that takes Once and not the target, and answers 200: the override does not show,
    # nothing is restarted, and what it made (Once, with the target there was before) is the press's own: cleared, not taken
    # for another tool's.
    monkeypatch.setattr(redfish, "CONFIRM_WITHIN", 0.5)
    bmc.state.boot_override, bmc.state.boot_status, bmc.state.boot_partial = ("Disabled", "Pxe"), 200, True
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        status_of(client, device, state="online")
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "bios_setup"})
        assert reply.status_code == 502 and "cleared again" in reply.json()["message"]
        assert bmc.state.boot_override == ("Disabled", "Pxe") and bmc.state.actions == []


def test_a_first_look_that_gets_no_answer_is_nothing_done(bmc: FakeBmc) -> None:
    # (The fifth review's L4.) Only a look had gone out: said as nothing done, not as a timeout ("it may have been done").
    async def run() -> None:
        device = redfish.RedfishDevice(kvm.DeviceSpec(id="t5", name="server", base_url=bmc.url, username="admin", password="secret", kind="redfish"))
        try:

            async def no_answer(path: str, urgent: bool = False, vital: bool = True, waits: Any = None) -> tuple[dict[str, Any], str | None]:
                raise kvm.KvmError("timeout", "Device did not respond in time", 504)

            device._read = no_answer  # type: ignore[method-assign]
            with pytest.raises(kvm.KvmError) as refused:
                await device.act("bios_setup")
            assert refused.value.code == "action_failed" and refused.value.message.startswith("Nothing was done")
            assert bmc.state.actions == [] and boot_changes(bmc) == []
        finally:
            await device.close()

    asyncio.run(run())


def test_the_clearing_reads_and_looks_again_on_a_refused_mark(tmp_path: Path, bmc: FakeBmc) -> None:
    # (The fifth review's L5.) A controller that does not take back its marks, and refuses the restart: the clearing is
    # refused for its mark, reads again, and is sent with "*".
    bmc.state.strict_marks, bmc.state.reset_refused = True, True
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        status_of(client, device, state="online")
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "bios_setup"})
        assert reply.status_code == 502 and "cleared again" in reply.json()["message"]
        assert boot_changes(bmc) == ["Once", "Disabled"] and bmc.state.boot_override[0] == "Disabled"


def test_the_restart_and_the_clearing_wait_longer_than_a_look(tmp_path: Path, bmc: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The fifth review's L5.) Not only the change: the restart, and the clearing, wait BOOT_WAITS for their answer too.
    monkeypatch.setattr(redfish.RedfishDevice, "WAITS", httpx.Timeout(1.0, connect=1.0))
    monkeypatch.setattr(redfish, "BOOT_WAITS", httpx.Timeout(4.0, connect=1.0))
    bmc.state.reset_answer_takes = 1.6
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        act = f"/api/v1/devices/{device}/actions"
        status_of(client, device, state="online")
        assert client.post(act, json={"action": "bios_setup"}).status_code == 200
        assert bmc.state.actions == ["system ForceRestart"]
        bmc.state.reset_answer_takes, bmc.state.reset_refused = 0.0, True
        bmc.state.slow_boot_changes, bmc.state.slow_boot_by = 2, 1.6  # (the change, and the clearing after the refusal)
        reply = client.post(act, json={"action": "bios_setup"})
        assert reply.status_code == 502 and "cleared again" in reply.json()["message"]
        assert boot_changes(bmc) == ["Once", "Once", "Disabled"] and bmc.state.boot_override[0] == "Disabled"


def test_a_stop_while_starting_into_setup_is_logged(bmc: FakeBmc) -> None:
    # (The fifth review's L5.) qKVM stopped while the change is under way: nothing is awaited, and the log says what may be left.
    bmc.state.slow_boot_changes, bmc.state.slow_boot_by = 1, 3.0

    async def run() -> None:
        device = redfish.RedfishDevice(kvm.DeviceSpec(id="t6", name="server", base_url=bmc.url, username="admin", password="secret", kind="redfish"))
        try:
            pressing = asyncio.create_task(device.act("bios_setup"))
            deadline = time.monotonic() + 5
            while not any(asked.startswith("PATCH") for asked in bmc.state.requests):
                assert time.monotonic() < deadline
                await asyncio.sleep(0.02)
            pressing.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pressing
        finally:
            await device.close()

    heard: list[str] = []
    listener = logging.Handler(logging.WARNING)
    listener.emit = lambda record: heard.append(record.getMessage())  # type: ignore[method-assign]
    logging.getLogger("qkvm").addHandler(listener)  # (heard on qKVM's own logger, whatever an earlier test set up)
    try:
        asyncio.run(run())
    finally:
        logging.getLogger("qkvm").removeHandler(listener)
    assert any("may be set for the next boot" in line for line in heard), heard


def test_an_answer_no_change_or_command_has_is_a_maybe(tmp_path: Path, bmc: FakeBmc) -> None:
    # (The fourth review's 5.) Only a 4xx is a no for certain. A change answered 201: it may be set, nothing is restarted, and
    # it is cleared (here the clearing is answered 201 as well, so that it may be set is what is said). A restart answered
    # 201: it may have gone through, and the override is left set, and said so.
    bmc.state.boot_status = 201
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        act = f"/api/v1/devices/{device}/actions"
        status_of(client, device, state="online")
        reply = client.post(act, json={"action": "bios_setup"})
        assert (reply.status_code, reply.json()["code"]) == (504, "timeout") and "may be set" in reply.json()["message"]
        assert bmc.state.actions == [] and boot_changes(bmc) == ["Once", "Disabled"]
        bmc.state.boot_status, bmc.state.reset_status = 204, 201
        reply = client.post(act, json={"action": "bios_setup"})
        assert (reply.status_code, reply.json()["code"]) == (504, "timeout") and "may or may not" in reply.json()["message"]
        assert bmc.state.boot_override == ("Once", "BiosSetup")


def test_a_server_between_states_is_not_started_into_its_setup(tmp_path: Path, bmc: FakeBmc) -> None:
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        status_of(client, device, state="online")
        bmc.state.power = "PoweringOn"
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "bios_setup"})
        assert reply.status_code == 502 and "changing its state" in reply.json()["message"]
        assert bmc.state.actions == [] and boot_changes(bmc) == []


def test_a_button_the_controller_does_not_offer_is_not_pressed_some_other_way(tmp_path: Path, bmc: FakeBmc) -> None:
    bmc.state.offered = ["On", "ForceOff", "PowerCycle"]
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        act = f"/api/v1/devices/{device}/actions"
        reply = client.post(act, json={"action": "atx_power"})  # "shut down nicely" is not on offer: pulling the plug is not a substitute
        assert (reply.status_code, reply.json()["code"]) == (502, "action_failed") and "GracefulShutdown" in reply.json()["message"]
        assert client.post(act, json={"action": "atx_reset"}).status_code == 200  # a power cycle does stand in for the reset button
        assert bmc.state.actions == ["system PowerCycle"]


def test_a_wrong_password_is_not_offered_again_and_again(tmp_path: Path, bmc: FakeBmc) -> None:
    with wall(tmp_path) as client:
        refused = client.post("/api/v1/devices", json={"url": bmc.url, "password": "not it"})
        assert (refused.status_code, refused.json()["code"]) == (422, "auth_failed")
        device = add(client, bmc.url)
        bmc.state.password = "changed on the controller"
        bmc.state.tokens.clear()  # the session is gone as well
        status = status_of(client, device, state="auth")
        assert status["error"]["code"] == "auth_failed"
        tries = bmc.state.logins
        for _ in range(5):
            status_of(client, device, state="auth")
        assert bmc.state.logins == tries  # a controller locks the account after a few: it is left alone for a while


def test_switching_on_leaves_alone_what_is_on_and_shutting_down_what_is_off(tmp_path: Path, bmc: FakeBmc) -> None:
    # The power button of a server is one button: pressed on a server that is off it switches it on, pressed
    # on one that runs it asks it to shut down. After a power cut, with forty machines ticked of which some
    # came back by themselves, "press the power button" brings up the ones and takes down the others. Asked
    # for by what is wanted, a server that is there already is left as it is, and says so.
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        act = f"/api/v1/devices/{device}/actions"
        left_alone = client.post(act, json={"action": "power_on"})  # it runs
        assert left_alone.status_code == 200 and left_alone.json()["note"] == "already on"
        assert bmc.state.actions == []
        shut_down = client.post(act, json={"action": "power_off"})
        assert shut_down.status_code == 200 and shut_down.json()["note"] is None
        assert bmc.state.actions == ["system GracefulShutdown"] and bmc.state.power == "Off"
        again = client.post(act, json={"action": "power_off"})
        assert again.status_code == 200 and again.json()["note"] == "already off"
        switched_on = client.post(act, json={"action": "power_on"})
        assert switched_on.status_code == 200 and switched_on.json()["note"] is None
        assert bmc.state.actions == ["system GracefulShutdown", "system On"] and bmc.state.power == "On"
        entries = [e for e in client.get("/api/v1/audit").json()["entries"] if e["event"] == "action"]
        # Written down as what was asked for and what came of it.
        assert [(e["action"], e.get("note")) for e in entries][::-1] == [
            ("power_on", "already on"), ("power_off", None), ("power_off", "already off"), ("power_on", None),
        ]


def test_a_kvm_is_not_asked_whether_it_is_on(tmp_path: Path) -> None:
    # A KVM's power button is a wire to the computer's own button, and whether that computer is on it knows
    # from a light that may not be wired up at all: "switch on" is not something it can promise.
    fake = FakeKvm().start()
    fake.state.atx = True
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            refused = client.post(f"/api/v1/devices/{device}/actions", json={"action": "power_on"})
            assert (refused.status_code, refused.json()["code"]) == (422, "invalid")
            assert fake.state.actions == []
    finally:
        fake.stop()


def test_a_sign_in_turned_away_for_another_reason_is_not_repeated_at_every_look(tmp_path: Path, bmc: FakeBmc) -> None:
    # A controller that has given out every session it has turns the next sign-in away, and the password has
    # nothing to do with it. Every look at the tile ended there, and sent it the password once more.
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        bmc.state.tokens.clear()
        bmc.state.login_status = 503
        status = status_of(client, device, state="error")
        assert status["error"]["code"] == "no_sign_in" and "503" in status["error"]["message"]  # there, and signs nobody in
        tries = bmc.state.logins
        for _ in range(6):
            client.get("/api/v1/status")
            time.sleep(0.1)
        assert bmc.state.logins == tries


def test_a_controller_cannot_send_the_wall_somewhere_else(tmp_path: Path, bmc: FakeBmc) -> None:
    # The session token goes with every request. A controller that names a computer at some other
    # address would be handed it there, were its links followed as given.
    elsewhere = ("https://elsewhere.example/redfish/v1/Systems/1", "//elsewhere.example/x", "/api/v1/session", "/redfish/v1/Systems/1?x=1", 7, None)
    # Nor to some other part of itself, by way of a path that climbs back out.
    climbing = ("/redfish/v1/../../api/v1/session", "/redfish/v1/%2e%2e/%2E%2E/api", "/redfish/v1/./x", "/redfish/v1/a%2f..%2fb", "/redfish/v1/a%5c..", "/redfish/v1/" + "a" * 300)
    for claimed in elsewhere + climbing:
        assert link(claimed) is None, claimed
    for honest in ("/redfish/v1/Systems/Self", "/redfish/v1/Chassis/Self/Thermal", "/redfish/v1/Systems/System.Embedded.1", "/redfish/v1/Systems/a%20b/"):
        assert link(honest) == honest
    bmc.state.system_link = "https://elsewhere.example/redfish/v1/Systems/1"
    with wall(tmp_path) as client:
        reply = client.post("/api/v1/devices", json={"url": bmc.url, "password": "secret"})
        assert (reply.status_code, reply.json()["code"]) == (422, "bad_response")


def test_what_a_controller_says_about_itself_is_not_taken_at_face_value(tmp_path: Path, bmc: FakeBmc) -> None:
    bmc.state.model = "To Be Filled By O.E.M."  # what a board says when nobody filled it in
    bmc.state.manufacturer = "Rack\nMaker <script>" + "x" * 300
    bmc.state.cpu_temperature = "hot"
    bmc.state.firmware = {"not": "a version"}
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        status = status_of(client, device, state="online")
        assert status["about"]["model"].startswith("Rack Maker <script>") and len(status["about"]["model"]) <= 60  # one short line
        assert status["about"]["version"] is None
        assert status["health"]["temp"] == 55 and {"name": "CPU1_TEMP", "celsius": 55, "ok": True} in status["server"]["temperatures"]
    assert named("", "Default string", " n/a ", "SRV-1100") == "SRV-1100"


def test_the_page_is_told_that_a_server_has_no_picture(tmp_path: Path, bmc: FakeBmc) -> None:
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        listed = {entry["id"]: entry for entry in client.get("/api/v1/wall").json()["devices"]}
        assert (listed[device]["kind"], listed[device]["picture"]) == ("redfish", False)


def test_a_board_that_says_too_much_about_its_processor_is_cut_short(tmp_path: Path, bmc: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # The shape of what one real board answered: a name, a run of spaces, and what else it knows about the processor.
    said = "Intel Xeon E-2336 CPU              , 2900 Mhz, 6 Core(s), 12 Logical Processor(s)"
    monkeypatch.setattr(fake_redfish, "PROCESSOR", said)
    bmc.state.model, bmc.state.manufacturer = "", "To Be Filled By O.E.M."
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        status = status_of(client, device, state="online")
        assert status["server"]["processor"] == "Intel Xeon E-2336 CPU"
        assert status["about"]["model"] is None  # nobody filled it in, and nothing is made up in its place


def test_a_critical_fault_is_a_problem_and_a_warning_is_not(tmp_path: Path, bmc: FakeBmc) -> None:
    bmc.state.health = "Warning"  # one slow fan: what a Gigabyte board said of itself while running fine
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        assert status_of(client, device, state="online")["server"]["health"] == "Warning"
        bmc.state.health = bmc.state.temperature_health = "Critical"
        status = status_of(client, device, state="error")
        # It says where to look: the alert that goes out carries this line.
        assert status["error"] == {"code": "health", "message": "The server reports a critical fault (CPU0_TEMP, CPU1_FAN)"}
        assert status["server"]["unwell"] == ["CPU0_TEMP", "CPU1_FAN"] and status["server"]["temperatures"][0]["ok"] is False
        assert status["server"]["power"] == "On" and status["atx"]["power"] is True  # still told how it is, and still switchable
        assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_reset"}).status_code == 200


def test_alerts_call_a_server_what_it_is() -> None:
    off = alerts.describe("db1", "192.168.1.9", "online", "no_signal", server=True)
    assert (off.kind, off.title, off.text) == ("no_signal", "db1 is powered off", "The server was switched off or shut down.")
    assert alerts.describe("db1", "192.168.1.9", "no_signal", "online", server=True).title == "db1 is powered on"
    assert alerts.describe("db1", "192.168.1.9", "online", "offline", server=True).text == "Its management controller stopped answering."
    assert alerts.describe("db1", "192.168.1.9", "online", "no_signal").title == "db1 has no video signal"  # a KVM, as before
    fault = alerts.describe("db1", "192.168.1.9", "online", "error", "The server reports a critical fault", server=True)
    assert (fault.kind, fault.text) == ("problem", "The server reports a critical fault")


def test_servers_are_found_on_the_network(tmp_path: Path, bmc: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    wanted = [discover.Target("127.0.0.1", bmc.url, "http://127.0.0.1:9")]
    monkeypatch.setattr(discover, "targets", lambda: (wanted, ["test network"]))
    with wall(tmp_path) as client:
        found = client.post("/api/v1/discover").json()["found"]
        assert [(entry["kind"], entry["url"], entry["known"]) for entry in found] == [("redfish", bmc.url, False)]
        assert bmc.state.logins == 0  # asked what it is, nothing more
        add(client, bmc.url)
        assert client.post("/api/v1/discover").json()["found"][0]["known"] is True


# --- the way into the controller's own console ---------------------------------------------------


def test_open_console_leads_straight_in_where_the_controller_hands_out_a_pass(tmp_path: Path, bmc: FakeBmc) -> None:
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        assert status_of(client, device, state="online")["console"] is True
        assert bmc.state.passes == []  # knowing that there is a way in does not have a pass made out
        reply = client.post(f"/api/v1/devices/{device}/console")
        assert reply.status_code == 200, reply.text
        assert reply.json() == {"url": f"{bmc.url}/viewer.html?{bmc.state.passes[0]}"}
        assert reply.headers["cache-control"] == "no-store"
        # Where a browser reaches the controller by another address than the wall does, that is where it is sent.
        edit = {"url": bmc.url, "open_url": "https://bmc7.example.net:8443/some/page"}
        assert client.put(f"/api/v1/devices/{device}", json=edit).status_code == 200
        assert client.post(f"/api/v1/devices/{device}/console").json() == {"url": f"https://bmc7.example.net:8443/viewer.html?{bmc.state.passes[1]}"}
        # It is written down who went in. With what is written down nowhere.
        opened = [entry for entry in client.get("/api/v1/audit").json()["entries"] if entry["event"] == "console_opened"]
        assert [(entry["device"], entry["user"]) for entry in opened] == [(opened[0]["device"], "admin")] * 2
        assert len(bmc.state.passes) == 2 and bmc.state.passes[0] != bmc.state.passes[1]
    for file in tmp_path.rglob("*"):
        if file.is_file():
            kept = file.read_bytes()
            assert not any(made.encode() in kept for made in bmc.state.passes), file


def test_the_way_in_is_for_those_who_may_act_on_the_machine(tmp_path: Path, bmc: FakeBmc) -> None:
    other = FakeBmc().start()
    try:
        with wall(tmp_path) as admin:
            device, hidden = add(admin, bmc.url), add(admin, other.url)
            account(admin, "victor", "viewer")
            account(admin, "olga", "operator", devices=[device])
            refused = browser(admin, "victor").post(f"/api/v1/devices/{device}/console")
            assert (refused.status_code, refused.json()["code"]) == (403, "not_allowed")
            olga = browser(admin, "olga", port=50002)
            assert olga.post(f"/api/v1/devices/{device}/console").status_code == 200
            assert olga.post(f"/api/v1/devices/{hidden}/console").status_code == 404  # a server this account was not given
            assert (len(bmc.state.passes), other.state.passes) == (1, [])
            unsigned = admin.post(f"/api/v1/devices/{device}/console", headers={"X-QKVM": ""})  # not from the wall's own page
            assert unsigned.status_code in (400, 403) and len(bmc.state.passes) == 1
    finally:
        other.stop()


@pytest.mark.parametrize(
    "claimed",
    [
        "https://elsewhere.example/viewer.html?abc",  # another machine altogether
        "//elsewhere.example/viewer.html?abc",
        "javascript:alert(1)?abc",
        "/viewer.html",  # no pass: an ordinary link, which the wall has already
        "/../../viewer.html?abc",
        "/a/./viewer.html?abc",
        "/viewer.html?abc def",
        "/viewer.html?<script>",
        "/viewer.html?abc#frag",
        "viewer.html?abc",
        "/viewer.html?" + "a" * 600,
        7,
        None,
    ],
)
def test_a_controller_decides_nothing_about_where_the_browser_is_sent(tmp_path: Path, bmc: FakeBmc, claimed: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    # The fake is told what to answer word for word; `console` is not None, so the manager still points to it.
    monkeypatch.setattr(fake_redfish, "WAY_IN", claimed)
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        reply = client.post(f"/api/v1/devices/{device}/console")
        assert (reply.status_code, reply.json()["code"]) == (502, "bad_response"), reply.text
        assert "url" not in reply.json()


def test_a_console_that_is_a_program_to_download_is_not_offered_as_a_link(tmp_path: Path, bmc: FakeBmc) -> None:
    bmc.state.console_kind = "Java"
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        assert client.post(f"/api/v1/devices/{device}/console").json()["code"] == "bad_response"


def test_where_there_is_no_way_in_the_plain_link_stays(tmp_path: Path, bmc: FakeBmc) -> None:
    bmc.state.console = None  # as on the Gigabyte board
    kvm_box = FakeKvm().start()
    try:
        with wall(tmp_path) as client:
            server, plain_kvm = add(client, bmc.url), add(client, kvm_box.url)
            assert status_of(client, server, state="online")["console"] is False
            for device in (server, plain_kvm):
                reply = client.post(f"/api/v1/devices/{device}/console")
                assert (reply.status_code, reply.json()["code"]) == (404, "no_console")
            assert "console" not in client.get("/api/v1/status").json()[plain_kvm]  # a KVM's page asks for its password itself
            assert not any(entry["event"] == "console_opened" for entry in client.get("/api/v1/audit").json()["entries"])
    finally:
        kvm_box.stop()


# --- the light to find a server by --------------------------------------------------------------


def test_what_the_locator_light_is_and_how_it_is_switched() -> None:
    usual = {"IndicatorLED@Redfish.AllowableValues": ["Lit", "Blinking", "Off"]}  # the two boards this was built from
    # Lit, not blinking: on a real board a light told to blink was out again by itself within twenty seconds.
    assert locator({**usual, "IndicatorLED": "Off"}) == (False, {"IndicatorLED": "Lit"}, {"IndicatorLED": "Off"})
    assert locator({**usual, "IndicatorLED": "Lit"})[0] is True and locator({**usual, "IndicatorLED": "Blinking"})[0] is True
    assert locator({"IndicatorLED": "Off"}) == (False, {"IndicatorLED": "Lit"}, {"IndicatorLED": "Off"})  # it does not say what it takes
    assert locator({"IndicatorLED": "Off", "IndicatorLED@Redfish.AllowableValues": ["Blinking", "Off"]})[1] == {"IndicatorLED": "Blinking"}
    # A light that cannot be switched off: lit is its state of rest, and only blinking calls for attention.
    resting = {"IndicatorLED@Redfish.AllowableValues": ["Lit", "Blinking"]}
    assert locator({**resting, "IndicatorLED": "Lit"}) == (False, {"IndicatorLED": "Blinking"}, {"IndicatorLED": "Lit"})
    assert locator({**resting, "IndicatorLED": "Blinking"})[0] is True
    # One that cannot be told to blink.
    assert locator({"IndicatorLED": "Lit", "IndicatorLED@Redfish.AllowableValues": ["Lit", "Off"]}) == (True, {"IndicatorLED": "Lit"}, {"IndicatorLED": "Off"})
    # The newer, plain way of saying it wins where a controller has both.
    assert locator({**usual, "IndicatorLED": "Lit", "LocationIndicatorActive": False}) == (
        False, {"LocationIndicatorActive": True}, {"LocationIndicatorActive": False},
    )  # fmt: skip
    for none in ({}, {"IndicatorLED": None}, {"IndicatorLED": "Unknown"}, {"IndicatorLED": 1}, {**usual, "IndicatorLED": "Off", "IndicatorLED@Redfish.AllowableValues": ["Off"]}):
        assert locator(none) == (None, None, None), none


def lit(client: Any, device: str, wanted: object) -> None:
    wait_until(lambda: client.get("/api/v1/status").json()[device]["server"]["locator"] is wanted, f"the tile never said the light is {wanted}")


def test_the_locator_light_is_switched_from_the_wall(tmp_path: Path, bmc: FakeBmc) -> None:
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        act = f"/api/v1/devices/{device}/actions"
        lit(client, device, False)
        assert client.post(act, json={"action": "locate_on"}).status_code == 200
        assert bmc.state.led == "Lit"
        lit(client, device, True)
        assert client.post(act, json={"action": "locate_off"}).status_code == 200
        lit(client, device, False)
        assert bmc.state.changes == [{"IndicatorLED": "Lit"}, {"IndicatorLED": "Off"}]
        # Each change showed the controller the state it was decided on, and went through at the first try.
        assert [asked for asked in bmc.state.requests if asked.startswith("PATCH")] == ["PATCH /redfish/v1/Systems/Self"] * 2
        entries = [entry["action"] for entry in client.get("/api/v1/audit").json()["entries"] if entry["event"] == "action"]
        assert entries[::-1] == ["locate_on", "locate_off"]


def test_a_controller_that_will_not_take_back_the_mark_it_gave_is_told_the_change_is_meant(tmp_path: Path, bmc: FakeBmc) -> None:
    bmc.state.strict_marks = True  # what one of the two boards answered: a weak mark, which a strict comparison never accepts
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "locate_on"}).status_code == 200
        assert bmc.state.changes == [{"IndicatorLED": "Lit"}]
        assert len([asked for asked in bmc.state.requests if asked.startswith("PATCH")]) == 2


def test_the_locator_light_stays_on_until_it_is_switched_off(tmp_path: Path, bmc: FakeBmc) -> None:
    bmc.state.blink_lasts = 0.3  # as on the real board: a light told to blink goes out by itself (there, after some fifteen seconds)
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "locate_on"}).status_code == 200
        lit(client, device, True)
        time.sleep(0.8)  # somebody walks to the rack
        assert client.get("/api/v1/status").json()[device]["server"]["locator"] is True
        lit(client, device, True)
        assert bmc.state.led == "Lit"


def test_what_was_done_to_a_server_shows_without_waiting_for_its_next_turn(tmp_path: Path, bmc: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # The real board said "accepted" and showed the change five seconds later, by when the look that follows
    # an action at once had long been taken, and the next regular one was ten seconds away.
    monkeypatch.setattr(redfish, "LOOK_EVERY", 30)
    monkeypatch.setattr(redfish, "FOLLOW_UP", (0.2, 0.6, 1.0, 1.5))
    bmc.state.slow_to_act = 0.5
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        lit(client, device, False)
        began = time.monotonic()
        assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "locate_on"}).status_code == 200
        lit(client, device, True)
        assert time.monotonic() - began < 4
        # Once it has been followed up, the server is back to being looked at when its turn comes.
        asked = len(bmc.state.requests)
        time.sleep(1.8)
        for _ in range(4):
            client.get("/api/v1/status")
        assert len(bmc.state.requests) - asked <= 4  # the last of the looks that follow, at most; none after that


def test_the_newer_kind_of_locator_light_and_none_at_all(tmp_path: Path, bmc: FakeBmc) -> None:
    bmc.state.locating = False
    kvm_box = FakeKvm().start()
    try:
        with wall(tmp_path) as client:
            device, plain_kvm = add(client, bmc.url), add(client, kvm_box.url)
            assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "locate_on"}).status_code == 200
            assert bmc.state.changes == [{"LocationIndicatorActive": True}]
            lit(client, device, True)
            bmc.state.locating, bmc.state.led = None, "Unknown"  # a board without one
            lit(client, device, None)
            reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "locate_on"})
            assert (reply.status_code, reply.json()["code"]) == (502, "action_failed") and len(bmc.state.changes) == 1
            reply = client.post(f"/api/v1/devices/{plain_kvm}/actions", json={"action": "locate_on"})  # a KVM has none either
            assert (reply.status_code, reply.json()["code"]) == (422, "invalid")
    finally:
        kvm_box.stop()


# --- a controller's moments, and commands it takes and does not carry out -------------------------


def test_a_moment_of_the_controller_s_does_not_change_what_the_tile_says(tmp_path: Path, bmc: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # A real controller, with nothing wrong with it or its server, answered errors for twenty-odd seconds
    # at a stretch while the server shut down. On the wall that was "Problem", twice, and nearly an alert.
    monkeypatch.setattr(redfish, "HICCUP", 5.0)
    monkeypatch.setattr(redfish, "RETRY_LOOK", 0.1)
    monkeypatch.setattr(redfish, "LOOK_EVERY", 30)
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        before = status_of(client, device, state="online")
        monkeypatch.setattr(redfish, "LOOK_EVERY", 0.2)
        asked = len(bmc.state.requests)
        bmc.state.unwell_until = time.monotonic() + 1.0
        seen = set()
        while time.monotonic() < bmc.state.unwell_until + 0.6:
            status = client.get("/api/v1/status").json()[device]
            seen.add(status["state"])
            assert status["server"] == before["server"]  # what was known a moment ago, not a blank
            time.sleep(0.05)
        assert seen == {"online"}
        # It was asked again soon after each failed look, and once it answered, things went on as usual.
        wait_until(lambda: len(bmc.state.requests) > asked, "the server was not looked at again after the controller's moment")
        bmc.state.power = "Off"
        status_of(client, device, state="no_signal")


def test_a_controller_that_stays_away_is_said_to_be_away(tmp_path: Path, bmc: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(redfish, "HICCUP", 0.6)
    monkeypatch.setattr(redfish, "RETRY_LOOK", 0.1)
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        status_of(client, device, state="online")
        began = time.monotonic()
        bmc.state.unwell_until = began + 60
        status = status_of(client, device, state="error")
        assert 0.5 < time.monotonic() - began < 4 and "HTTP 503" in status["error"]["message"] and "server" not in status
        bmc.state.unwell_until = 0.0
        status_of(client, device, state="online")


def test_not_being_let_in_is_no_passing_moment(tmp_path: Path, bmc: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(redfish, "HICCUP", 60.0)
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        status_of(client, device, state="online")
        bmc.state.password = "changed on the controller"
        bmc.state.tokens.clear()
        status_of(client, device, state="auth")  # said at once: nobody should wait a minute to learn the password is wrong


def test_a_command_that_was_accepted_and_not_carried_out_is_not_called_done(tmp_path: Path, bmc: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # A real controller took the command to cut the power, answered "accepted", and left the server running.
    monkeypatch.setattr(redfish, "CONFIRM_WITHIN", 0.5)
    bmc.state.drops = ["ForceOff", "On"]
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        act = f"/api/v1/devices/{device}/actions"
        reply = client.post(act, json={"action": "atx_power_long"})
        assert (reply.status_code, reply.json()["code"]) == (502, "action_failed")
        assert reply.json()["message"] == "The controller accepted this, but the server is still on. The command was not carried out."
        assert bmc.state.actions == ["system ForceOff"] and bmc.state.power == "On"  # sent once, and not sent again behind anybody's back
        bmc.state.power = "Off"
        status_of(client, device, state="no_signal")
        reply = client.post(act, json={"action": "atx_power"})
        assert reply.status_code == 502 and "the server is still off" in reply.json()["message"]
        events = [entry["event"] for entry in client.get("/api/v1/audit").json()["entries"] if entry["event"].startswith("action")]
        assert events == ["action_failed", "action_failed"]  # and the activity log does not say it was done either


def test_a_power_command_whose_connection_is_retired_while_it_is_confirmed_is_not_said_to_have_failed(bmc: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # The controller accepts the command, and for some seconds qKVM looks whether the server did change. The tile
    # saved in those seconds (or the last person signing out) takes the connection away: every look after that
    # failed, each was taken for one of the controller's moments, and when the time was up the operator was
    # told "the command was not carried out", of a server that may have been switching on. What is said then is
    # that it was not seen: the server answers that with "it may have been done all the same".
    monkeypatch.setattr(redfish, "CONFIRM_WITHIN", 1.5)
    bmc.state.drops = ["ForceOff"]  # accepted, and the server stays as it is: the looking goes on for its whole time
    device = redfish.RedfishDevice(kvm.DeviceSpec(id="ab12", name="Server", base_url=bmc.url, username="admin", password="secret", kind="redfish"))

    async def run() -> None:
        pressing = asyncio.ensure_future(device.act("atx_power_long"))
        for _ in range(500):
            if bmc.state.actions:
                break
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.2)  # it is being confirmed
        await device.close()
        with pytest.raises(kvm.KvmError) as said:
            await pressing
        assert said.value is kvm.RETIRED, said.value.message

    asyncio.run(run())
    assert bmc.state.actions == ["system ForceOff"]


def test_a_power_command_is_done_when_the_server_is_seen_to_have_changed(tmp_path: Path, bmc: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    bmc.state.power_takes = 0.5  # the real one: nine seconds from "accepted" to on
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        act = f"/api/v1/devices/{device}/actions"
        began = time.monotonic()
        assert client.post(act, json={"action": "atx_power_long"}).status_code == 200
        assert time.monotonic() - began >= 0.5 and bmc.state.power == "Off"
        began = time.monotonic()
        assert client.post(act, json={"action": "atx_power"}).status_code == 200
        assert time.monotonic() - began >= 0.5 and bmc.state.power == "On"
        # What cannot be seen at once is not waited for: a system takes its time to shut down, and a reset shows nothing.
        began = time.monotonic()
        assert client.post(act, json={"action": "atx_power"}).status_code == 200
        assert client.post(act, json={"action": "atx_reset"}).status_code == 200
        assert time.monotonic() - began < 0.5
        assert bmc.state.actions == ["system ForceOff", "system On", "system GracefulShutdown", "system ForceRestart"]


def test_a_server_that_stops_answering_is_offline_and_comes_back(tmp_path: Path) -> None:
    first = FakeBmc().start()
    with wall(tmp_path) as client:
        device = add(client, first.url)
        status_of(client, device, state="online")
        first.stop()
        gone = status_of(client, device, state="offline")
        assert gone["picture"] is False and gone["error"]["code"] in ("unreachable", "dropped")
        first.state.tokens.clear()  # the controller restarted: it knows none of the old sessions
        second = FakeBmc(first.state, port=first.port).start()
        try:
            status_of(client, device, state="online")
            assert first.state.logins == 2  # signed in again by itself, once
        finally:
            second.stop()


def test_a_fault_that_comes_and_goes_is_one_problem_and_not_many(tmp_path: Path, bmc: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # A fan at its limit, on a real board: Critical for fifteen seconds, Warning for five, Critical again, all
    # evening. Every turn was a red tile and "has a problem", then a green one and "is back".
    bmc.state.health = "Critical"
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        status_of(client, device, state="error")

        def now() -> dict:
            return client.get("/api/v1/status").json()[device]

        bmc.state.health = "Warning"
        wait_until(lambda: now()["server"]["health"] == "Warning", "the status never said what the server says of itself now")
        for _ in range(3):
            status = now()
            assert status["state"] == "error"  # still the problem it was a moment ago
            assert status["server"]["health"] == "Warning"  # ...and what it says of itself right now is told as it is
            assert status["error"]["code"] == "health" and "comes and goes" in status["error"]["message"]
        bmc.state.health = "Critical"  # there it is again, and that is said as what it is
        wait_until(lambda: now()["state"] == "error" and "comes and goes" not in now()["error"]["message"], "it never said the fault is there now")
        bmc.state.health = "Warning"
        wait_until(lambda: now()["server"]["health"] == "Warning" and now()["state"] == "error", "it was not held as a problem the second time")
        monkeypatch.setattr(redfish, "FAULT_HOLD", 0)  # ...and once it has stayed away for long enough, it is over
        assert status_of(client, device, state="online")["error"] is None


# --- the server's screen ------------------------------------------------------------------------------------

WHITE, BLACK, RED = 0xEB8080, 0x108080, 0x515AF0  # colours as video has them
# All that is ever said to a console: the greeting, "send the picture", answers to the controller's own questions, and goodbye.
LOOKING = {ami.COMPLETE, ami.PASS, ami.RESUME, ami.FULL_SCREEN, ami.WEB_SESSION, ami.STILL_THERE, ami.BEHIND, ami.STOP}


def a_screen() -> list[Frame]:
    """A screen of 64 by 32: white on the left, black on the right; then one block of it turns red."""
    first = Frame(64, 32)
    for _ in range(4):
        for colour in (WHITE, WHITE, WHITE, WHITE, BLACK, BLACK, BLACK, BLACK):
            first.colours([(0, colour)])
    second = Frame(64, 32)
    second.colours([(2, RED)], None, (6, 2))
    return [first, second]


@pytest.fixture
def with_screen() -> Iterator[FakeBmc]:
    server = FakeBmc(BmcState(own_console=True, screen=a_screen(), piece=50)).start()
    yield server
    server.stop()


def pixel(jpeg: bytes, x: int, y: int) -> tuple[int, ...]:
    import io

    import av

    with av.open(io.BytesIO(jpeg), format="mjpeg") as opened:
        frame = next(opened.decode(video=0)).reformat(format="rgb24")
    plane = frame.planes[0]
    start = y * plane.line_size + 3 * x
    return tuple(bytes(plane)[start : start + 3])


def picture_of(client: object, device: str) -> bytes:
    """The tile's picture, once there is one (the first one asked for opens the console)."""
    found: list[bytes] = []

    def there() -> bool:
        reply = client.get(snap(device))  # type: ignore[attr-defined]
        if reply.status_code == 200:
            found.append(reply.content)
        return bool(found)

    # (As long as the program gives a console to open, and a little: a busy computer took more than five seconds to sign
    # in, open the console and read its first picture, and the program waits CONSOLE_OPENING for the opening alone.)
    wait_until(there, "no picture of the server's screen came", timeout=redfish.CONSOLE_OPENING + 5)
    return found[0]


def test_a_servers_tile_shows_the_servers_screen(tmp_path: Path, with_screen: FakeBmc) -> None:
    # A wall of screens showed a server as a list of temperatures: "there are hundreds of tools that do the
    # same". Its screen is in its controller's own console, and that is where it is taken from.
    bmc = with_screen
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        assert status_of(client, device, state="online")["screen"] is True
        opening = client.get(snap(device))
        assert (opening.status_code, opening.json()["code"]) == (503, "no_stream")  # the tile asks again, as for any picture not there yet
        jpeg = picture_of(client, device)
        wait_until(lambda: pixel(client.get(snap(device)).content, 52, 20)[0] > 150, "the block that turned red never showed")
        jpeg = client.get(snap(device)).content
        assert client.get(snap(device)).headers["content-type"] == "image/jpeg"
        left, right, red = pixel(jpeg, 8, 8), pixel(jpeg, 40, 8), pixel(jpeg, 52, 20)
        assert min(left) > 225 and max(right) < 30 and red[0] > 150 and red[1] < 90 and red[2] < 90
        # The status says how large the screen is, as a KVM's does, and still says how the server is.
        wait_until(lambda: client.get("/api/v1/status").json()[device]["video"]["width"] == 64, "the status never said how large the screen is")
        status = client.get("/api/v1/status").json()[device]
        assert (status["video"]["width"], status["video"]["height"]) == (64, 32) and status["server"]["health"] == "OK"
        # One web session and one console seat, and nothing sent but what looking takes.
        assert (bmc.state.web_logins, len(bmc.state.web_sessions), bmc.state.watching) == (1, 1, 1)
        kinds = {kind for kind, _, _ in bmc.state.heard}
        assert kinds <= LOOKING and ami.PASS in kinds
        assert bmc.state.actions == [] and bmc.state.changes == []
        # Removed from the wall, it says that it is leaving, gives the seat back and signs out of the controller's web page.
        assert client.delete(f"/api/v1/devices/{device}").status_code == 200
        wait_until(lambda: (bmc.state.watching, bmc.state.web_sessions) == (0, {}), "the console was not given back")
        assert bmc.state.heard[-1][0] == ami.STOP and {kind for kind, _, _ in bmc.state.heard} <= LOOKING


def test_a_controller_whose_own_resource_cannot_be_read_still_shows_its_screen_where_its_root_says_it_is_amis(tmp_path: Path) -> None:
    # What the controller is, is read from its own resource; where that read fails, its console is not asked for until it
    # is known (an OpenBMC controller answers AMI's console's door as AMI's does). A root that names AMI as its maker says
    # enough: its screen comes at once, as it did before.
    bmc = FakeBmc(BmcState(own_console=True, screen=a_screen(), piece=50, manager_fails=10**6)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, bmc.url)
            status_of(client, device, state="online")
            assert bmc.state.manager_reads >= 1  # (asked, and refused every time)
            jpeg = picture_of(client, device)
            assert min(pixel(jpeg, 8, 8)) > 225
            assert bmc.state.web_logins == 1
    finally:
        bmc.stop()


def test_the_console_is_given_back_when_nobody_looks(tmp_path: Path, with_screen: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # A controller has two console seats. The wall takes one while somebody looks at it, and not for good.
    monkeypatch.setattr(redfish, "CONSOLE_IDLE", 0.4)
    bmc = with_screen
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        picture_of(client, device)
        assert bmc.state.watching == 1
        wait_until(lambda: (bmc.state.watching, bmc.state.web_sessions) == (0, {}), "the console stayed open with nobody looking")
        # ...and whoever looks again gets it again. (Looked at until it is open: a look in the moment the old one
        # is still being put away is answered with the picture that is kept, and the look after it opens the
        # console. A wall looks every second; this looked once, and on a slow machine once was that moment.)
        wait_until(lambda: (picture_of(client, device), bmc.state.web_logins)[1] >= 2, "the console was not opened again for whoever looked")
        assert bmc.state.web_logins == 2


def test_a_picture_of_a_smaller_size_is_made_for_a_tile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    wide = Frame(1024, 16)
    for _ in range(2 * 128):
        wide.colours([(0, WHITE)])
    bmc = FakeBmc(BmcState(own_console=True, screen=[wide], piece=4000)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, bmc.url)
            picture_of(client, device)
            assert kvm.picture_size(client.get(snap(device) + "?w=400").content) == (480, 8)
            assert kvm.picture_size(client.get(snap(device) + "?w=2000").content) == (1024, 16)
    finally:
        bmc.stop()


def test_a_controller_that_darkens_the_servers_monitor_is_left_alone_and_the_tile_says_why(tmp_path: Path, with_screen: FakeBmc) -> None:
    # Some are set to switch the server's own monitor off while a console is open. Whoever stands at the
    # server would see that: it is not looking any more.
    bmc = with_screen
    bmc.state.monitor_goes_dark = True
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        wait_until(lambda: client.get(snap(device)).status_code == 404, "it was never said that there is no picture")
        assert "monitor" in client.get(snap(device)).json()["message"]
        status = status_of(client, device, screen=False)
        assert "monitor" in status["server"]["no_screen"] and status["state"] == "online"
        assert bmc.state.heard == [] and bmc.state.web_sessions == {}  # the console was never opened, and the web page signed out of
        assert bmc.state.web_logins == 1  # ...and it is not asked again every second


def test_with_every_seat_taken_the_tile_goes_on_saying_how_the_server_is(tmp_path: Path, with_screen: FakeBmc) -> None:
    bmc = with_screen
    bmc.state.seats = 0
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        wait_until(lambda: client.get(snap(device)).json().get("code") == "in_use", "it was never said that the seats are taken")
        status = status_of(client, device, state="online")
        assert status["screen"] is True and status["server"]["no_screen"] is None  # it may be free again in a moment
        assert bmc.state.web_sessions == {}


def test_a_picture_that_cannot_be_read_is_given_up_on(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Another version of the firmware, another chip: what arrives is then not shown as a screen full of noise.
    class Unknown:
        header = dataclasses.replace(Frame(64, 32).header, strength=9)  # a quantization strength there is none of
        data = bytes(range(256)) * 4

    nonsense = FakeBmc(BmcState(own_console=True, screen=[Unknown(), Unknown(), Unknown(), Unknown()], piece=5000)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, nonsense.url)
            wait_until(lambda: client.get(snap(device)).status_code == 404, "it went on trying to read it")
            assert "does not read" in status_of(client, device, screen=False)["server"]["no_screen"]
            wait_until(lambda: nonsense.state.web_sessions == {}, "the web page was not signed out of")
    finally:
        nonsense.stop()


def test_firmware_that_lets_a_console_reconnect_is_greeted_the_way_it_wants(tmp_path: Path, with_screen: FakeBmc) -> None:
    # A real board (a Gigabyte one) said "allowed", was shown the pass, and closed without a word, every thirty
    # seconds, for as long as its tile was looked at. Its firmware wants "connection complete" said first, and
    # says so in the list of what it can do.
    bmc = with_screen
    bmc.state.reconnects = True
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        picture_of(client, device)
        assert bmc.state.heard[0][0] == ami.COMPLETE and bmc.state.web_logins == 1


def test_a_console_that_closes_on_the_greeting_is_greeted_the_other_way_next_time(tmp_path: Path, with_screen: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # ...and where the list does not say, it is found out by trying: once each way, not the same way for ever.
    monkeypatch.setattr(redfish, "CONSOLE_RETRY", (0.2, 0.2, 0.2, 0.2))
    bmc = with_screen
    bmc.state.reconnects, bmc.state.says_what_it_can = True, False
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        picture_of(client, device)
        assert [kind for kind, _, _ in bmc.state.heard if kind in (ami.COMPLETE, ami.PASS)] == [ami.PASS, ami.COMPLETE, ami.PASS]
        assert bmc.state.web_logins == 2


def test_a_console_that_cannot_be_had_is_asked_for_less_and_less_often(tmp_path: Path, with_screen: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # A controller is a small computer. The real one was slow to answer anybody for some seconds after every
    # console that came and went, and one came and went every thirty seconds.
    monkeypatch.setattr(redfish, "CONSOLE_RETRY", (0.2, 30.0))
    bmc = with_screen
    bmc.state.seats = 0
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        wait_until(lambda: (client.get(snap(device)), bmc.state.web_logins)[1] == 2, "it was not tried a second time")
        deadline = time.monotonic() + 1.2
        while time.monotonic() < deadline:
            assert client.get(snap(device)).json()["code"] in ("in_use", "no_stream")  # (the second try is under way, or over)
            time.sleep(0.05)
        assert bmc.state.web_logins == 2  # the third time is half a minute off
        assert client.get(snap(device)).json()["code"] == "in_use"


def test_a_console_that_begins_with_nothing_changed_is_not_shown_as_a_black_screen(tmp_path: Path, with_screen: FakeBmc) -> None:
    # A real board, every time its console was opened again: "the first frame, 16 bytes". That frame says that
    # nothing changed, the whole screen comes when it is asked for, and for the moment between the two the tile
    # of a running server showed a black picture.
    bmc = with_screen
    bmc.state.begins_with_nothing = True
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        first = picture_of(client, device)
        assert min(pixel(first, 8, 8)) > 225 and max(pixel(first, 40, 8)) < 30  # the screen, the first time anything is shown


SOMEBODY = b"admin".ljust(64, b"\0") + b"192.168.1.60".ljust(70, b"\0")  # a person at the controller's own page, as the console names them


@pytest.mark.parametrize("kind", [ami.SHARING, ami.NEXT_HOLDER])
def test_somebody_who_opens_the_servers_own_console_is_let_in_at_once(tmp_path: Path, with_screen: FakeBmc, kind: int) -> None:
    # The controller asks whoever has the console whether a newcomer may have it, and waits half a minute for
    # the answer. The wall has it whenever somebody looks at the wall, and nobody sits at the wall to answer:
    # whoever opened the console of a server to work on it waited that half minute, every time. They are let in
    # at once (the wall only looks, and goes on looking). The same when one who may only look asks for the keys.
    bmc = with_screen
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        picture_of(client, device)
        bmc.state.asks.append((kind, SOMEBODY))
        wait_until(lambda: len(bmc.state.answers) == 2, "whoever asked for the console was left waiting")
        assert [(said, number, who) for said, number, who, _ in bmc.state.answers] == [(ami.SHARING, ami.ASKED, SOMEBODY), (ami.NEXT_HOLDER, ami.ASKED, SOMEBODY)]
        assert max(waited for *_, waited in bmc.state.answers) < 2
        assert client.get(snap(device)).status_code == 200 and bmc.state.watching == 1
        assert {said for said, _, _ in bmc.state.heard} <= LOOKING | {ami.SHARING, ami.NEXT_HOLDER}
        assert bmc.state.actions == [] and bmc.state.changes == []


@pytest.mark.parametrize("shut_out", [False, True])
def test_the_wall_does_not_make_somebody_at_the_console_answer_for_it(tmp_path: Path, with_screen: FakeBmc, monkeypatch: pytest.MonkeyPatch, shut_out: bool) -> None:
    # The other way round: somebody is working in the console, and then the wall is looked at. They would get
    # a question on their screen with half a minute to answer it, and unanswered the console passes to whoever
    # asked: to the wall. It leaves the moment it is told to wait, says so, and looks again later.
    monkeypatch.setattr(redfish, "CONSOLE_HELD", 1.5)
    bmc = with_screen
    bmc.state.held_by, bmc.state.shut_out = SOMEBODY, shut_out
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        wait_until(lambda: client.get(snap(device)).json().get("code") == "console_held", "it was never said that somebody has the console")
        wait_until(lambda: (bmc.state.watching, bmc.state.web_sessions) == (0, {}), "it did not leave")
        said = [kind for kind, _, _ in bmc.state.heard]
        assert said[-1] == ami.STOP and set(said) <= LOOKING and bmc.state.answers == []  # it says that it is leaving, and nothing else
        status = status_of(client, device, screen=False)
        assert "Somebody is using" in status["server"]["no_screen"] and status["state"] == "online" and status["error"] is None
        assert bmc.state.web_logins == 1  # ...and does not come back every few seconds to be told again
        # Later it looks again. They have left, and the screen is back on its tile.
        bmc.state.held_by = b""
        assert status_of(client, device, screen=True)["server"]["no_screen"] is None
        picture_of(client, device)
        assert bmc.state.web_logins == 2


def test_a_console_whose_last_holder_may_come_back_shows_the_screen_all_the_same(tmp_path: Path, with_screen: FakeBmc) -> None:
    # Seen on a real board after a console that had dropped: the next one was told "the one who held it is
    # coming back", and was sent the picture. Nobody is asked anything then, and the wall stays.
    bmc = with_screen
    bmc.state.holder_returning = True
    with wall(tmp_path) as client:
        picture_of(client, add(client, bmc.url))
        assert {kind for kind, _, _ in bmc.state.heard} <= LOOKING and bmc.state.answers == []


def test_what_cannot_be_had_for_now_is_asked_for_again_later(tmp_path: Path, with_screen: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # A controller set to darken the server's monitor was left alone, rightly, and then for ever: the tile stopped
    # asking, so the setting could be changed and the wall never knew until it was started again.
    monkeypatch.setattr(redfish, "CONSOLE_GIVE_UP", 1.5)
    bmc = with_screen
    bmc.state.monitor_goes_dark = True
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        wait_until(lambda: client.get(snap(device)).status_code == 404, "it was never said that there is no picture")
        assert "monitor" in status_of(client, device, screen=False)["server"]["no_screen"]
        bmc.state.monitor_goes_dark = False
        assert status_of(client, device, screen=True)["server"]["no_screen"] is None
        picture_of(client, device)


def test_a_console_session_whose_time_is_up_is_opened_again_at_once(tmp_path: Path, with_screen: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # Read in the log of a wall that was left open overnight on two real servers: each controller ended its
    # console session every half hour (its rule for one in which no key is pressed, and the wall presses none),
    # the wall took that for a failure, waited thirty seconds, and each server's picture was gone for that
    # long, twice an hour, with a warning in the log each time.
    monkeypatch.setattr(redfish, "CONSOLE_SETTLED", 0.3)
    bmc = with_screen
    # Three seconds a session: on a computer that is busy the first frame may take most of one to arrive, and
    # a session must have shown its picture for the 0.3 s above before its end counts as "ran its time".
    bmc.state.session_lasts = 3.0
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        picture_of(client, device)
        seen: set[tuple[int, str]] = set()
        deadline = time.monotonic() + 15  # (half a minute is what it used to take)
        while bmc.state.web_logins < 2 and time.monotonic() < deadline:
            reply = client.get(snap(device))
            seen.add((reply.status_code, "" if reply.status_code == 200 else reply.json()["code"]))
            time.sleep(0.05)
        assert bmc.state.web_logins >= 2  # opened again when its time was up, and not half a minute after that
        assert seen <= {(200, ""), (503, "no_stream")}  # and nothing in between that a tile would show as a fault
        status = status_of(client, device, state="online")
        assert status["screen"] is True and status["server"]["no_screen"] is None


def test_a_console_that_says_its_time_is_up_as_soon_as_it_is_opened_is_not_opened_in_a_circle(tmp_path: Path, with_screen: FakeBmc) -> None:
    # "Again at once" is for a session that has run its time. One that is ended within its first minute is a
    # console that cannot be had, and is asked for less and less often, as any other.
    bmc = with_screen
    bmc.state.session_lasts = 0.4
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        picture_of(client, device)
        deadline = time.monotonic() + 2.5
        while time.monotonic() < deadline:
            client.get(snap(device))
            time.sleep(0.05)
        assert bmc.state.web_logins == 1


# --- what a console may cost (found by two reviews, each shown against the stand-in) --------------------------


class HangsUp:
    """A console connection that is closed from the other end at the moment something is said into it: what
    the controller said last (that the session's time is up) has arrived, and has not been read yet."""

    def __init__(self, real: Any, takes: int) -> None:
        self._real, self._takes, self._last = real, takes, [ami.message(ami.STOP, ami.TIME_UP)]

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    async def send(self, data: Any) -> None:
        self._takes -= 1
        if self._takes < 0:
            raise ConnectionClosedOK(None, None)
        await self._real.send(data)

    async def recv_streaming(self) -> Any:  # (a message is read as the pieces it arrives in)
        if self._takes >= 0:
            async for piece in self._real.recv_streaming():
                yield piece
        elif self._last:
            yield self._last.pop()
        else:
            raise ConnectionClosedOK(None, None)


def test_what_the_controller_said_last_counts_though_it_has_hung_up(tmp_path: Path, with_screen: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # Found by a test that failed one time in ten: the wall says something every second, and when the controller
    # had hung up in that very moment, having just said why, the wall never read why. "Its time was up", which is
    # no fault and is put right at once, became "it closed its console", which is one and is waited out.
    monkeypatch.setattr(redfish, "CONSOLE_SETTLED", 0.3)
    really = redfish.ws_connect

    async def hangs_up(url: str, **options: Any) -> Any:
        return HangsUp(await really(url, **options), takes=8)  # (some seconds in: the picture has long been up)

    bmc = with_screen
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        monkeypatch.setattr(redfish, "ws_connect", hangs_up)
        picture_of(client, device)
        monkeypatch.setattr(redfish, "ws_connect", really)  # the next console is an ordinary one
        deadline = time.monotonic() + 15
        while bmc.state.web_logins < 2 and time.monotonic() < deadline:
            client.get(snap(device))
            time.sleep(0.05)
        assert bmc.state.web_logins >= 2  # opened again at once, as a session whose time is up is


class Deaf:
    """A console connection whose other end stops taking what is sent to it, after the first few things."""

    def __init__(self, real: Any, takes: int) -> None:
        self._real, self._takes = real, takes

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    async def send(self, data: Any) -> None:
        self._takes -= 1
        if self._takes < 0:
            await asyncio.Event().wait()  # for ever: its buffers are full
        await self._real.send(data)


def test_a_controller_that_stops_listening_does_not_keep_the_console_open_for_ever(tmp_path: Path, with_screen: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # Nothing that was said to the console had a time to be said in, and the two checks that end a session
    # (nobody looking, nothing heard) are made between two things said. Stuck in the saying, the wall kept the
    # seat, the web session and the screen in memory until the device was removed.
    monkeypatch.setattr(redfish, "CONSOLE_SAY", 0.3)
    monkeypatch.setattr(redfish, "CONSOLE_IDLE", 0.4)
    really = redfish.ws_connect

    async def deaf(url: str, **options: Any) -> Any:
        return Deaf(await really(url, **options), takes=2)

    monkeypatch.setattr(redfish, "ws_connect", deaf)
    bmc = with_screen
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        client.get(snap(device))
        wait_until(lambda: bmc.state.web_logins == 1, "the console was never asked for")
        wait_until(lambda: (bmc.state.watching, bmc.state.web_sessions) == (0, {}), "the console stayed open, stuck in something it was saying", timeout=8)


class SlowToTakeTheGoodbye:
    """A console connection whose other end takes everything but the goodbye, which it does not take at all."""

    def __init__(self, real: Any) -> None:
        self._real = real

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    async def send(self, data: Any) -> None:
        if data == ami.goodbye():
            await asyncio.Event().wait()  # for ever
        await self._real.send(data)


def test_a_server_taken_off_the_wall_while_its_console_takes_its_time_over_the_goodbye_gives_the_console_back(tmp_path: Path, with_screen: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # Taken off the wall, the console says goodbye, and closes. Whoever retires a device tells its tasks to stop
    # again after half a second: told again while the goodbye was still being said, the console left without
    # closing, the connection stayed open, and the controller kept the seat for as long as it liked.
    really = redfish.ws_connect
    opened: list[Any] = []  # (held here: a connection that nobody holds is closed by the garbage collector, sooner or later)

    async def slow(url: str, **options: Any) -> Any:
        opened.append(await really(url, **options))
        return SlowToTakeTheGoodbye(opened[-1])

    monkeypatch.setattr(redfish, "ws_connect", slow)
    bmc = with_screen
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        picture_of(client, device)
        assert bmc.state.watching == 1
        assert client.delete(f"/api/v1/devices/{device}").status_code == 200
        wait_until(lambda: bmc.state.watching == 0, "the server is off the wall, and its console is still open")


def test_a_picture_that_cannot_be_made_this_moment_is_asked_for_again_and_is_no_error(tmp_path: Path, with_screen: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # A server changes the size of its screen a few times while it starts. A picture being made at that moment
    # failed inside the library that makes it, and the browser was answered with an error 500 and the log with
    # a traceback, each time; a controller that wanted to could have had that all day.
    made: list[bool] = []
    really = redfish.screen_jpeg

    def fails_the_first_time(*given: Any) -> bytes:
        made.append(True)
        if len(made) == 1:
            raise ValueError("got 13824 bytes; need 12288 bytes")
        return really(*given)

    monkeypatch.setattr(redfish, "screen_jpeg", fails_the_first_time)
    with wall(tmp_path) as client:
        device = add(client, with_screen.url)
        assert kvm.picture_size(picture_of(client, device)) == (64, 32)  # asked for again, as a picture that is not there yet is
    assert len(made) >= 2


def test_reading_the_screen_does_not_take_the_threads_that_sign_people_in(tmp_path: Path, with_screen: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # A frame is read in a thread, and it was one of the threads that check passwords and write the settings:
    # a few controllers with much to read, and nobody was signed in until they were through.
    import threading

    from qkvm.aspeed import Screen

    read_in: list[str] = []
    really = Screen.read

    def noted(self: Screen, header: Any, data: bytes) -> int:
        read_in.append(threading.current_thread().name)
        return really(self, header, data)

    monkeypatch.setattr(Screen, "read", noted)
    with wall(tmp_path) as client:
        picture_of(client, add(client, with_screen.url))
    assert read_in and all(name.startswith("screen") for name in read_in)


def test_the_console_is_told_how_much_may_wait_to_be_read(tmp_path: Path, with_screen: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # While a long frame is read nothing is taken from the connection, and what arrives waits in a queue:
    # sixteen things of thirty-two megabytes each, as it stood. Half a gigabyte for one controller.
    asked: dict[str, Any] = {}
    really = redfish.ws_connect

    def looked_at(url: str, **options: Any) -> Any:
        asked.update(options)
        return really(url, **options)

    monkeypatch.setattr(redfish, "ws_connect", looked_at)
    with wall(tmp_path) as client:
        picture_of(client, add(client, with_screen.url))
    assert asked["max_queue"] <= 2 and asked["max_size"] <= 9 * 1024 * 1024


def test_a_controller_that_asks_for_the_console_over_and_over_is_not_answered_for_ever(tmp_path: Path, with_screen: FakeBmc) -> None:
    # Every "may this one have the console?" was answered with two messages, as often as it was asked.
    bmc = with_screen
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        picture_of(client, device)
        bmc.state.asks.extend([(ami.SHARING, SOMEBODY)] * 60)
        wait_until(lambda: not bmc.state.asks, "the stand-in never asked")
        wait_until(lambda: len(bmc.state.answers) >= 2, "nobody was let in at all")
        time.sleep(1.0)
        assert len(bmc.state.answers) <= 2 * redfish.LET_IN_AT_MOST
        assert client.get(snap(device)).status_code == 200  # and the wall goes on showing the screen


def test_a_device_taken_off_the_wall_in_the_moment_it_is_signed_in_to_leaves_no_session_behind(tmp_path: Path, with_screen: FakeBmc) -> None:
    # The controller has made the session by the time it answers. Told to stop while it waited for that answer,
    # the wall never learned what to sign out of, and the session stood until the controller let it run out.
    bmc = with_screen
    bmc.state.sign_in_takes = 1.0
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        client.get(snap(device))
        wait_until(lambda: len(bmc.state.web_sessions) == 1, "it never began to sign in")
        assert client.delete(f"/api/v1/devices/{device}").status_code == 200
        wait_until(lambda: bmc.state.web_sessions == {}, "the session was left on the controller", timeout=8)
        assert bmc.state.heard == []  # and no console was opened for a device that is gone


def test_the_console_is_not_hung_up_on_for_not_answering_a_ping(tmp_path: Path, with_screen: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # The first real screen stayed on its tile for forty seconds. The library that keeps the connection asks
    # "are you there?" in a way of its own every twenty, a real controller does not answer that, and twenty
    # seconds later the library hung up on a console that was sending the screen all the while.
    asked: dict[str, object] = {}
    really = redfish.ws_connect

    def looked_at(url: str, **options: object) -> object:
        asked.update(options)
        return really(url, **options)

    monkeypatch.setattr(redfish, "ws_connect", looked_at)
    with wall(tmp_path) as client:
        picture_of(client, add(client, with_screen.url))
    assert "ping_interval" in asked and asked["ping_interval"] is None


# --- keys, typed text and Ctrl+Alt+Del, over AMI's console (as a KVM takes them) -----------------------------


def test_keys_typed_text_and_ctrl_alt_del_reach_the_servers_console(tmp_path: Path, with_screen: FakeBmc) -> None:
    # A server whose controller is AMI's takes keyboard over the same console the screen comes on. Each report is
    # the whole keyboard; a combination goes down together, a typed character is pressed and released, and nothing
    # is left down. None of it touches Redfish: no power command, no change to the server.
    bmc = with_screen
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        # Keys are offered once the console is known to be AMI's (opened by the tile's first picture), not before.
        picture_of(client, device)
        can = status_of(client, device, state="online")["can"]
        assert "keys" in can and "text" in can and "control" in can
        act = f"/api/v1/devices/{device}/actions"
        assert client.post(act, json={"action": "ctrl_alt_del"}).status_code == 200
        assert client.post(act, json={"action": "keys", "keys": "ControlLeft,KeyC"}).status_code == 200
        assert client.post(act, json={"action": "text", "text": "Hi"}).status_code == 200
        # (The last letting go is read by the stand-in, in a thread of its own, a moment after the answer came.)
        wait_until(lambda: ("key", 0, [0x0C]) in bmc.state.hid and bmc.state.hid[-1] == ("key", 0, []), f"the typed text never arrived: {bmc.state.hid}")
        assert bmc.state.bad_hid == []  # every packet checked out
        assert ("key", 0x05, [0x4C]) in bmc.state.hid  # Ctrl+Alt+Del: left Ctrl and left Alt held, Delete down
        assert ("key", 0x01, [0x06]) in bmc.state.hid  # Ctrl held, C down
        assert ("key", 0x02, [0x0B]) in bmc.state.hid  # Shift held, H down (a capital)
        assert bmc.state.hid[-1] == ("key", 0, [])  # and the keyboard is left with nothing down
        assert bmc.state.actions == [] and bmc.state.changes == []


def test_a_controller_with_no_console_qkvm_reads_cannot_take_keys(tmp_path: Path, bmc: FakeBmc) -> None:
    # The default controller here has no console qKVM reads. Keys are not an action it can do; attempted, it is
    # told so, and once that is known the tile stops offering them.
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "keys", "keys": "KeyA"})
        assert (reply.status_code, reply.json()["code"]) == (422, "invalid")
        assert bmc.state.web_logins == 0  # (no web page was signed in to for a controller that cannot do this)
        assert "keys" not in status_of(client, device, screen=False)["can"]


def test_keys_wait_for_the_console_to_be_this_programs_and_go_nowhere_else(tmp_path: Path, with_screen: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # Found by a review: keys went once the pass was taken, before the controller said "the console is yours". A
    # console whose last holder may come back is shown, and its holder is another session: nothing is typed into it.
    monkeypatch.setattr(redfish, "MASTER_WAIT", 0.5)
    bmc = with_screen
    bmc.state.holder_returning = True
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        picture_of(client, device)
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "keys", "keys": "KeyA"})
        assert (reply.status_code, reply.json()["code"]) == (409, "in_use"), reply.text
        assert bmc.state.hid == [] and ami.HID not in {kind for kind, _, _ in bmc.state.heard}
        # Nor are keys offered meanwhile (found by the second review): a look with that console open leaves them out.
        monkeypatch.setattr(redfish, "LOOK_EVERY", 0.3)
        looked: list[dict[str, Any]] = []

        def a_look_with_the_console_open() -> bool:
            looked[:] = [client.get("/api/v1/status").json()[device]]
            return bool(looked[0]["video"]["width"] == 64)

        wait_until(a_look_with_the_console_open, "no look was had with the console open")
        assert "keys" not in looked[0]["can"]


def test_keys_wait_for_the_keyboard_of_a_first_session_to_be_attached(tmp_path: Path, with_screen: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # Seen on a real board: a letter typed the moment a first console session was the wall's never arrived, the virtual
    # keyboard not being attached to the server yet (its own viewer takes no key for five seconds then). They wait.
    monkeypatch.setattr(redfish, "HID_SETTLE", 1.2, raising=False)
    bmc = with_screen
    bmc.state.first_session, bmc.state.hid_settles = True, 1.0
    with wall(tmp_path) as client:
        device = add(client, bmc.url)
        assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "keys", "keys": "KeyA"}).status_code == 200
        # (Sent by the time the answer comes; read by the stand-in, in a thread of its own, a moment later.)
        wait_until(lambda: len(bmc.state.hid) + bmc.state.hid_lost >= 2, f"the key and its letting go never came: {bmc.state.hid}")
        assert (bmc.state.hid_lost, bmc.state.hid) == (0, [("key", 0, [0x04]), ("key", 0, [])])


def test_a_typing_stopped_with_a_key_down_lets_it_go(with_screen: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # Found by a review: stopped between a key's press and its release (the request cut off as qKVM stops), the key
    # stayed down on the server, and a key held down repeats. It is let go of, in a task of its own.
    monkeypatch.setattr(redfish, "HOLD", 2.0)  # (long enough to be stopped in)
    bmc = with_screen

    async def run() -> None:
        device = redfish.RedfishDevice(kvm.DeviceSpec(id="t1", name="server", base_url=bmc.url, username="admin", password="secret", kind="redfish"))
        try:
            typing = asyncio.ensure_future(device.act("keys", keys="ControlLeft,KeyC"))
            for _ in range(400):
                if ("key", 0x01, [0x06]) in bmc.state.hid:
                    break
                await asyncio.sleep(0.05)
            assert ("key", 0x01, [0x06]) in bmc.state.hid, f"Ctrl+C never went down: {bmc.state.hid}"
            typing.cancel()
            with pytest.raises(asyncio.CancelledError):
                await typing
            for _ in range(100):
                if bmc.state.hid[-1] == ("key", 0, []):
                    break
                await asyncio.sleep(0.05)
            assert bmc.state.hid[-1] == ("key", 0, []), f"Ctrl+C stayed down: {bmc.state.hid}"
        finally:
            await device.close()

    asyncio.run(run())


def test_a_server_taken_off_the_wall_in_the_middle_of_a_typing_has_its_key_let_go_of(with_screen: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # Found by the second review: the device closed while a typing held a key (a tile edited, the last person signed
    # out), the console said goodbye with the key still down. It is let go of before the goodbye.
    monkeypatch.setattr(redfish, "HOLD", 6.0)  # (the typing's own letting go must not come first, on a slow machine either)
    bmc = with_screen

    async def run() -> None:
        device = redfish.RedfishDevice(kvm.DeviceSpec(id="t2", name="server", base_url=bmc.url, username="admin", password="secret", kind="redfish"))
        typing = asyncio.ensure_future(device.act("ctrl_alt_del"))
        for _ in range(400):
            if ("key", 0x05, [0x4C]) in bmc.state.hid:
                break
            await asyncio.sleep(0.05)
        assert ("key", 0x05, [0x4C]) in bmc.state.hid, f"Ctrl+Alt+Del never went down: {bmc.state.hid}"
        await device.close()
        with pytest.raises(kvm.KvmError):
            await typing
        for _ in range(100):  # (the stand-in reads in a thread of its own)
            if bmc.state.heard and bmc.state.heard[-1][0] == ami.STOP:
                break
            await asyncio.sleep(0.05)
        heard = [kind for kind, _, _ in bmc.state.heard]
        assert heard[-1] == ami.STOP and bmc.state.hid[-1] == ("key", 0, []), f"the keys went with the session: {bmc.state.hid}"
        assert max(i for i, kind in enumerate(heard) if kind == ami.HID) < len(heard) - 1

    asyncio.run(run())


class StallingConsole:
    """A console connection with nothing behind it: what is said to it is kept (as messages), what it says is put in by
    the test, and a send can be made to wait once its data is written, as a WebSocket's does while the far end reads nothing."""

    subprotocol = "binary"

    def __init__(self) -> None:
        self.incoming: asyncio.Queue[bytes] = asyncio.Queue()
        self.sent: list[ami.Message] = []
        self.stall: asyncio.Event | None = None  # the next send waits for this, after its data is written
        self.stalled = asyncio.Event()
        self.transport = type("Transport", (), {"abort": lambda self: None})()

    async def recv_streaming(self) -> Any:
        yield await self.incoming.get()

    async def send(self, data: Any) -> None:
        self.sent.extend(ami.Messages().feed(bytes(data)))
        stall, self.stall = self.stall, None
        if stall is not None:
            self.stalled.set()
            await stall.wait()

    async def close(self) -> None:
        pass


def test_a_press_on_its_way_behind_a_letting_go_is_let_go_of_before_the_console_is_given(monkeypatch: pytest.MonkeyPatch) -> None:
    # Found by the fourth review: a letting go that finished late said "nothing is down" of a press that was already on
    # its way behind it (the controller not reading just then), and a person let in at that moment was given the
    # console with the press down. Only the report noted last says what is down.
    conn = StallingConsole()

    async def connect(*args: Any, **kwargs: Any) -> Any:
        return conn

    monkeypatch.setattr(redfish, "ws_connect", connect)

    async def run() -> None:
        device = redfish.RedfishDevice(kvm.DeviceSpec(id="t3", name="server", base_url="http://127.0.0.1:9", username="admin", password="x", kind="redfish"))
        console = device._console = redfish._Console()
        device._console_wanted_at = time.monotonic()
        watching = asyncio.ensure_future(device._watch_console(console, "c=1", "pass", "127.0.0.1", "127.0.0.1", "s"))

        async def looked_at() -> None:
            while True:
                device._console_wanted_at = time.monotonic()
                await asyncio.sleep(0.05)

        looking = asyncio.ensure_future(looked_at())
        try:
            for said in (ami.message(ami.ALLOWED, 2), ami.message(ami.PASS_SEEN, 0, bytes([1, 0])), ami.message(ami.NEXT_HOLDER, ami.BECAME_MASTER)):
                await conn.incoming.put(said)
            for _ in range(200):
                if device._live_send is not None:
                    break
                await asyncio.sleep(0.01)
            era = device._input_era
            await device.send_keyboard(0x01, [], era)  # Ctrl down
            conn.stall = letting_go = asyncio.Event()
            first = asyncio.ensure_future(device.send_keyboard(0, [], era))  # Ctrl let go of, waiting for room
            await conn.stalled.wait()
            conn.stalled.clear()
            second = asyncio.ensure_future(device.send_keyboard(0, [0x04], era))  # 'a' pressed, behind it
            for _ in range(5):
                await asyncio.sleep(0)
            conn.stall = pressing = asyncio.Event()
            letting_go.set()
            await first
            await conn.stalled.wait()  # 'a' is on its way, waiting for room
            await conn.incoming.put(ami.message(ami.SHARING, ami.ASKED, SOMEBODY))  # somebody asks for the console now
            for _ in range(50):
                await asyncio.sleep(0)
            pressing.set()
            await second
            for _ in range(200):
                if any(one.kind == ami.SHARING for one in conn.sent):
                    break
                await asyncio.sleep(0.01)
            given = next(at for at, one in enumerate(conn.sent) if one.kind == ami.SHARING)
            keys = [one.body[33:41] for one in conn.sent[:given] if one.kind == ami.HID]
            assert keys[-1] == bytes(8), f"the console was given with a key down: {[report.hex() for report in keys]}"
        finally:
            looking.cancel()
            watching.cancel()
            with contextlib.suppress(asyncio.CancelledError, kvm.KvmError):
                await watching

    asyncio.run(run())


class LoseKeys:
    """A console connection that is closed for keys and the mouse: what goes up as a HID report finds it closed."""

    def __init__(self, real: Any) -> None:
        self._real = real

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    async def send(self, data: Any) -> None:
        if isinstance(data, bytes) and data[:2] == ami.HID.to_bytes(2, "little"):
            raise ConnectionClosedOK(None, None)
        await self._real.send(data)


def test_a_key_into_a_console_that_has_closed_is_not_said_to_be_sent(tmp_path: Path, with_screen: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # Found by a review: a key sent over a connection that had closed was taken for delivered, its letting go too.
    really = redfish.ws_connect

    async def closed_for_keys(url: str, **options: Any) -> Any:
        return LoseKeys(await really(url, **options))

    monkeypatch.setattr(redfish, "ws_connect", closed_for_keys)
    with wall(tmp_path) as client:
        device = add(client, with_screen.url)
        picture_of(client, device)
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "keys", "keys": "KeyA"})
        assert reply.status_code != 200 and reply.json()["code"] == "dropped", reply.text


def test_an_openbmc_controller_is_not_offered_the_password_for_keys(tmp_path: Path) -> None:
    # Found by a review: asked for keys before its first look, a controller under OpenBMC was taken down AMI's road:
    # its web page was asked for a console pass, and would have been offered the password.
    bmc = FakeBmc(BmcState(layout="openbmc")).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, bmc.url, kind="redfish")
            reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "keys", "keys": "KeyA"})
            assert reply.status_code in (409, 422, 503), reply.text
            assert bmc.state.token_asks == 0 and bmc.state.web_logins == 0
    finally:
        bmc.stop()


def test_a_text_that_cannot_be_typed_is_not_quoted_back(tmp_path: Path, with_screen: FakeBmc) -> None:
    # Found by a review: the character that could not be typed was quoted in the answer, and so in the activity log.
    # The text may be a saved secret: where it went wrong is said, and not what is there.
    with wall(tmp_path) as client:
        device = add(client, with_screen.url)
        odd = chr(0xE9)
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "text", "text": "secret" + odd + "x"})
        assert (reply.status_code, reply.json()["code"]) == (422, "invalid")
        assert "Character 7" in reply.json()["message"] and odd not in reply.json()["message"]
        assert odd not in client.get("/api/v1/audit").text


def test_an_invalid_key_combination_is_refused(tmp_path: Path, with_screen: FakeBmc) -> None:
    with wall(tmp_path) as client:
        device = add(client, with_screen.url)
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "keys", "keys": "NoSuchKey"})
        assert (reply.status_code, reply.json()["code"]) == (422, "invalid")
        assert "JetKVM" not in reply.json()["message"]  # (the key table is shared with a JetKVM; the console is the server's)


def test_a_slow_controller_is_given_longer_to_answer_than_a_kvm(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # An older board (a Gigabyte, AMI's firmware) took nine to twelve seconds to show the root of its Redfish
    # service, and four to seven to show its computer, after a quiet period as at any other time. With the read a
    # KVM is given (eight seconds) those timed out, the tile fell offline and came back by turns, and the one who
    # added it was once told "did not respond in time". A controller is given longer. (The read, not the connect:
    # one that is simply not there is still found at once.) Here the two patiences are shortened to keep the test quick.
    monkeypatch.setattr(kvm, "WAITS", httpx.Timeout(0.4, connect=0.5))  # what a KVM is given
    monkeypatch.setattr(redfish.RedfishDevice, "WAITS", httpx.Timeout(2.0, connect=0.5))  # what a controller is given
    bmc = FakeBmc(BmcState(root_takes=0.9)).start()  # slower than a KVM's read, within a controller's
    try:
        with wall(tmp_path) as client:
            device = add(client, bmc.url)
            assert status_of(client, device, state="online")["server"]["health"] == "OK"
    finally:
        bmc.stop()


def test_a_controller_whose_redfish_root_is_slow_is_still_known_for_one_when_it_is_added() -> None:
    # A real older AMI firmware took 3.2 s to show the root of its Redfish service. Asked with less patience
    # than that, the wall did not know it for a server's controller, took it for a KVM, and said "did not
    # respond in time" to the one adding it, whose login was right.
    server = FakeBmc(BmcState(root_takes=3.5)).start()
    try:
        assert asyncio.run(server_module.detect_kind(server.url, True)) == ("redfish", server.url)
    finally:
        server.stop()
