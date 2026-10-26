"""Business PCs with Intel AMT on the wall, through their management engine: WS-Management for the state and the power
(phase 1), and the redirection port for the screen, keys and the pointer through its KVM (phase 2).

Everything here runs against the stand-in in fake_amt.py, which was built from Intel's class reference and, for the
redirection port, from what a real engine (AMT 16) was seen to send. What was tried on that real machine is in the
README; the tests that need it (test_real_amt.py) skip without it.
"""

from __future__ import annotations

import asyncio
import json
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest

from qkvm import amt, discover, exchange, kvm, update, vault
from qkvm.amt import AmtDevice, Challenge, answer_to, body_of, challenge_from, family_of, fields_of, int_of, own_number
from qkvm.kvm import DeviceSpec, KvmError
from tests.conftest import SCALE, TICK
from tests.fake_amt import GUID, AmtState, FakeAmt
from tests.scripted_device import Scripted
from tests.test_redfish import status_of
from tests.test_wall import PASSWORD, add, closed_port, snap, wait_until, wall
from tests.settings_file import settings_text, write_settings_text

S = 60.0  # for the tests that watch a tile for "minutes": every wait is a sixtieth of what it is


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(amt, "LOOK_EVERY", 0)  # every question about the PC's status has it read again
    monkeypatch.setattr(amt, "FOLLOW_UP", ())
    monkeypatch.setattr(amt, "HICCUP", 0)
    monkeypatch.setattr(amt, "CONFIRM_EVERY", 0.05)
    monkeypatch.setattr(amt.AmtScreen, "LOOK_PACE", 0.05)  # (the screen is asked for what changed twenty times a second)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def pc() -> Iterator[FakeAmt]:
    machine = FakeAmt().start()
    yield machine
    machine.stop()


def a_pc(machine: FakeAmt, password: str = "secret") -> AmtDevice:
    return AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=machine.url, username="admin", password=password, kind="amt"))


def asked(machine: FakeAmt, what: str, of: str) -> int:
    return sum(1 for question, short in machine.state.requests if question == what and short == of)


# --- on the wall ---------------------------------------------------------------------------------------


def test_an_amt_pc_is_recognised_from_its_address_and_shows_how_it_is(tmp_path: Path, pc: FakeAmt) -> None:
    with wall(tmp_path) as client:
        reply = client.post("/api/v1/devices", json={"url": pc.url, "username": "admin", "password": "secret"})
        assert reply.status_code == 201, reply.text
        added = reply.json()
        assert added["device"]["kind"] == "amt" and added["device"]["picture"] is False
        assert added["device"]["name"] == "desk-7"  # what the engine says the PC is called
        assert added["about"] == {"model": "Example Computers Office Desk 7", "version": "12.0.90", "hostname": "desk-7"}
        device = added["device"]["id"]
        status = status_of(client, device, state="online")
        assert status["kind"] == "amt" and status["picture"] is False and status["screen"] is True and status["console"] is False
        assert status["atx"] == {"enabled": True, "power": True, "hdd": None}
        # What a client may ask of it: the power buttons, and through its KVM the screen, keys and text, and the live line.
        assert status["can"] == ["screen", "keys", "text", "power", "reset", "power_state", "live", "control", "bios_setup"]
        assert status["about"] == {"model": "Example Computers Office Desk 7", "version": "12.0.90"}
        server = status["server"]
        assert (server["power"], server["health"], server["processor"], server["processors"], server["memory_gib"]) == ("On", None, "Intel Core i5, 3.4 GHz", 1, 16)
        assert (server["temperatures"], server["fans"], server["unwell"], server["locator"]) == ([], [], [], None)
        assert server["amt"] == {
            "power": 2, "control": "admin", "kvm": "enabled", "consent": False, "make": "Example Computers", "model": "Office Desk 7",
            "serial": "PC0000000001", "bios": "E7ET42W (1.42)", "plain": True, "listener": True, "session_timeout": 0,
        }  # fmt: skip
        assert server["no_screen"] is None  # (nothing stands against its screen)
        # Its screen, through its KVM: the first picture asked for opens a session, and the picture comes.
        wait_until(lambda: client.get(snap(device)).status_code == 200, "no picture of the PC's screen came", 15)
        assert client.get(snap(device)).headers["content-type"] == "image/jpeg" and pc.state.kvm_sessions == 1
        # Known by the number it gives for itself, so that the same PC under another address is one tile.
        twice = client.post("/api/v1/devices", json={"url": pc.url.replace("127.0.0.1", "localhost"), "password": "secret"})
        assert (twice.status_code, twice.json()["code"]) == (409, "same_device")


def test_what_rarely_changes_is_asked_once_and_the_power_at_every_look(tmp_path: Path, pc: FakeAmt) -> None:
    with wall(tmp_path) as client:
        device = add(client, pc.url)

        def looked_often() -> bool:
            status_of(client, device, state="online")
            return asked(pc, "Pull", "CIM_AssociatedPowerManagementService") >= 5

        wait_until(looked_often, "the power was not read again")
        for hardware in ("CIM_Chassis", "CIM_Processor", "CIM_PhysicalMemory", "CIM_BIOSElement", "CIM_SoftwareIdentity", "CIM_ComputerSystemPackage"):
            assert asked(pc, "Enumerate", hardware) == 1, hardware
        for setting in ("IPS_HostBasedSetupService", "CIM_KVMRedirectionSAP", "IPS_KVMRedirectionSettingData", "IPS_OptInService", "AMT_RedirectionService"):
            assert asked(pc, "Get", setting) == 1, setting
        assert asked(pc, "Get", "AMT_GeneralSettings") == 2  # once as the sign-in (the smallest question there is), once for the name
        assert asked(pc, "Enumerate", "CIM_Card") == 0  # the chassis said what the PC is: the board was not asked
        assert pc.state.rejections == 0
        # Nothing is left behind on the engine: Digest has no session to give back.
        assert client.delete(f"/api/v1/devices/{device}").status_code == 200


@pytest.mark.parametrize(
    ("power", "state", "word", "on"),
    [(8, "no_signal", "Off", False), (7, "no_signal", "Hibernating", False), (3, "online", "Sleeping", True), (4, "online", "Sleeping", True), (10, "online", "Resetting", None)],
)
def test_a_pc_that_is_not_running_is_there_and_dark(tmp_path: Path, pc: FakeAmt, power: int, state: str, word: str, on: bool | None) -> None:
    pc.state.power = power
    with wall(tmp_path) as client:
        device = add(client, pc.url)
        status = status_of(client, device, state=state)
        assert status["atx"]["power"] is on and status["video"]["signal"] is on
        assert status["server"]["power"] == word and status["server"]["amt"]["power"] == power


def test_the_power_buttons_mean_what_they_mean_on_an_amt_pc(tmp_path: Path, pc: FakeAmt) -> None:
    with wall(tmp_path) as client:
        device = add(client, pc.url)
        act = f"/api/v1/devices/{device}/actions"
        left_alone = client.post(act, json={"action": "power_on"})  # it runs
        assert left_alone.status_code == 200 and left_alone.json()["note"] == "already on"
        assert pc.state.actions == []
        assert client.post(act, json={"action": "power_off"}).status_code == 200  # the operating system is asked
        assert pc.state.actions == [12] and pc.state.power == 8
        status_of(client, device, state="no_signal")
        again = client.post(act, json={"action": "power_off"})
        assert again.status_code == 200 and again.json()["note"] == "already off"
        assert client.post(act, json={"action": "atx_power"}).status_code == 200  # off: the button switches it on
        assert pc.state.actions == [12, 2] and pc.state.power == 2
        status_of(client, device, state="online")
        assert client.post(act, json={"action": "atx_power"}).status_code == 200  # on: the button asks it to shut down
        assert client.post(act, json={"action": "power_on"}).status_code == 200
        assert client.post(act, json={"action": "atx_power_long"}).status_code == 200  # the plug
        assert client.post(act, json={"action": "power_on"}).status_code == 200
        assert client.post(act, json={"action": "atx_reset"}).status_code == 200
        assert pc.state.actions == [12, 2, 12, 2, 8, 2, 10] and pc.state.power == 2
        # What a KVM with its own board does, an engine does not; nor is the engine itself restarted from here. (Keys and
        # text go through its KVM: see the tests of the screen.)
        for other in ({"action": "wol", "mac": "02:00:5E:00:53:01"}, {"action": "reboot"}, {"action": "locate_on"}, {"action": "jiggler_on"}):
            reply = client.post(act, json=other)
            assert (reply.status_code, reply.json()["code"]) == (422, "invalid"), other
        assert pc.state.actions == [12, 2, 12, 2, 8, 2, 10]
        entries = [e for e in client.get("/api/v1/audit").json()["entries"] if e["event"] == "action"]
        assert [(e["action"], e.get("note")) for e in entries][::-1] == [
            ("power_on", "already on"), ("power_off", None), ("power_off", "already off"), ("atx_power", None), ("atx_power", None),
            ("power_on", None), ("atx_power_long", None), ("power_on", None), ("atx_reset", None),
        ]  # fmt: skip


def test_a_shutdown_the_machine_does_not_offer_is_not_replaced_by_a_power_cut(tmp_path: Path, pc: FakeAmt) -> None:
    pc.state.offered = [2, 5, 8, 10]  # no agent in the operating system to ask: "shut down nicely" is not on offer
    with wall(tmp_path) as client:
        device = add(client, pc.url)
        act = f"/api/v1/devices/{device}/actions"
        refused = client.post(act, json={"action": "power_off"})
        assert (refused.status_code, refused.json()["code"]) == (502, "action_failed") and "shutting down (12)" in refused.json()["message"]
        assert pc.state.actions == [] and pc.state.power == 2
        assert client.post(act, json={"action": "atx_power_long"}).status_code == 200  # the plug is asked for by name
        assert pc.state.actions == [8] and pc.state.power == 8
        # A machine that does not say what it offers is asked for what is wanted.
        pc.state.offered = []
        assert client.post(act, json={"action": "power_on"}).status_code == 200
        assert pc.state.actions == [8, 2]


def test_a_power_command_taken_and_not_carried_out_is_said_so(tmp_path: Path, pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(amt, "CONFIRM_WITHIN", 0.5)
    pc.state.drops = [8]
    with wall(tmp_path) as client:
        device = add(client, pc.url)
        act = f"/api/v1/devices/{device}/actions"
        began = time.monotonic()
        reply = client.post(act, json={"action": "atx_power_long"})
        assert (reply.status_code, reply.json()["code"]) == (502, "action_failed") and "still on" in reply.json()["message"]
        assert 0.4 < time.monotonic() - began < 5
        # One that takes its time is waited for, and said to be done once it is seen.
        pc.state.drops, pc.state.power_takes = [], 0.3
        assert client.post(act, json={"action": "atx_power_long"}).status_code == 200
        assert pc.state.power == 8
        failed = [e for e in client.get("/api/v1/audit").json()["entries"] if e["event"] == "action_failed"]
        assert len(failed) == 1 and failed[0]["action"] == "atx_power_long"


def test_the_machine_refusing_a_power_command_says_why(tmp_path: Path, pc: FakeAmt) -> None:
    with wall(tmp_path) as client:
        device = add(client, pc.url)
        act = f"/api/v1/devices/{device}/actions"
        for returned, said in ((2, "unknown error"), (9, "not a change the PC can make"), (4097, "not a change the PC can make"), (77, "it answered 77")):
            pc.state.returns = returned
            reply = client.post(act, json={"action": "atx_reset"})
            assert (reply.status_code, reply.json()["code"]) == (502, "action_failed") and said in reply.json()["message"], returned
        pc.state.returns = 4096  # "started": a job was made for it, and that is a yes
        assert client.post(act, json={"action": "atx_reset"}).status_code == 200


@pytest.mark.parametrize(
    ("control", "kvm", "consent", "words", "found"),
    [
        (2, "enabled", False, "KVM: enabled, no consent needed, admin control mode", {"control": "admin", "kvm": "enabled", "consent": False}),
        (2, "enabled", True, "KVM: enabled, consent required, admin control mode", {"control": "admin", "kvm": "enabled", "consent": True}),
        (1, "enabled", False, "KVM: enabled, consent required, client control mode", {"control": "client", "kvm": "enabled", "consent": True}),  # mandatory there
        (2, "disabled", False, "KVM: disabled, admin control mode", {"control": "admin", "kvm": "disabled", "consent": False}),
        (2, "mebx", False, "KVM: disabled in the MEBx, admin control mode", {"control": "admin", "kvm": "mebx", "consent": False}),
        (2, "absent", False, "KVM: not on this machine (Essentials), admin control mode", {"control": "admin", "kvm": "absent", "consent": None}),
        (0, "enabled", False, "KVM: enabled, no consent needed, not provisioned", {"control": "none", "kvm": "enabled", "consent": False}),
    ],
)
def test_the_tile_says_whether_the_kvm_could_be_used_and_how_the_pc_was_set_up(tmp_path: Path, pc: FakeAmt, control: int, kvm: str, consent: bool, words: str, found: dict[str, Any]) -> None:
    pc.state.control, pc.state.kvm, pc.state.consent = control, kvm, consent
    with wall(tmp_path) as client:
        device = add(client, pc.url)
        status = status_of(client, device, state="online")
        assert {key: status["server"]["amt"][key] for key in found} == found
        if found["kvm"] == "enabled" and found["consent"] is False:
            assert status["screen"] is True and status["server"]["no_screen"] is None
            return
        assert status["screen"] is False and status["server"]["no_screen"].endswith(f"({words}, over plain HTTP)")
        assert "screen" not in status["can"] and "live" not in status["can"]
        # No session is opened where the screen is not to be had: not even to find out.
        refused = client.get(snap(device))
        assert (refused.status_code, refused.json()["code"]) == (404, "no_picture")
        time.sleep(0.3)
        assert pc.state.redirections == 0


def test_a_pc_whose_chassis_says_nothing_is_named_after_its_board(tmp_path: Path, pc: FakeAmt) -> None:
    pc.state.make, pc.state.model, pc.state.hostname = "To be filled by O.E.M.", "Default string", None
    pc.state.family, pc.state.other_family, pc.state.memory, pc.state.processors = 1, "Example Processor X", [2**30 * 6, 2**30 * 2 + 2**29], 2
    with wall(tmp_path) as client:
        reply = client.post("/api/v1/devices", json={"url": pc.url, "password": "secret"})
        assert reply.status_code == 201, reply.text
        assert reply.json()["about"] == {"model": "Example Boards EB-Q370", "version": "12.0.90", "hostname": None}
        assert reply.json()["device"]["name"] == "127.0.0.1:" + pc.url.rsplit(":", 1)[1]  # it has no name to go by
        status = status_of(client, reply.json()["device"]["id"], state="online")
        assert (status["server"]["processor"], status["server"]["processors"], status["server"]["memory_gib"]) == ("Example Processor X, 3.4 GHz", 2, 8.5)


def test_an_export_takes_an_amt_pc_along_and_an_import_brings_it_back(tmp_path: Path, pc: FakeAmt) -> None:
    with wall(tmp_path / "one") as admin:
        add(admin, pc.url, name="Desk 7")
        file = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": "the passphrase 1", "parts": ["devices"]}).text
    with wall(tmp_path / "two") as admin:
        there = admin.post("/api/v1/import/read", json={"file": file, "passphrase": "the passphrase 1"}).json()
        assert [(d["name"], d["kind"], d["new"]) for d in there["devices"]] == [("Desk 7", "amt", True)]
        assert admin.post("/api/v1/import", json={"file": file, "passphrase": "the passphrase 1", "take": ["devices"]}).json()["devices"] == 1
        device = admin.get("/api/v1/wall").json()["devices"][0]
        assert device["kind"] == "amt"
        status_of(admin, device["id"], state="online")


# --- signing in: Digest, and the pacing every driver keeps ---------------------------------------------


def test_a_wrong_password_is_refused_and_not_offered_again_and_again(tmp_path: Path, pc: FakeAmt) -> None:
    with wall(tmp_path) as client:
        refused = client.post("/api/v1/devices", json={"url": pc.url, "password": "not it"})
        assert (refused.status_code, refused.json()["code"]) == (422, "auth_failed")
        assert pc.state.logins == 1 and pc.state.rejections == 1
        device = add(client, pc.url)
        status_of(client, device, state="online")
        pc.state.password = "changed on the machine"
        status = status_of(client, device, state="auth")
        assert status["error"]["code"] == "auth_failed"
        tries = pc.state.logins
        for _ in range(5):
            status_of(client, device, state="auth")
        assert pc.state.logins == tries  # it is left alone for a while, whatever the tile is asked meanwhile
        # The password typed again is tried at once, and the tile is well again.
        pc.state.password = "secret"
        assert client.put(f"/api/v1/devices/{device}", json={"url": pc.url, "name": "PC", "username": "admin", "password": "secret"}).status_code == 200
        status_of(client, device, state="online")


def test_the_password_is_sent_nowhere_before_the_machine_has_asked_for_a_digest_sign_in(pc: FakeAmt) -> None:
    pc.state.basic_only = True  # it wants a Basic sign-in: the password in the clear, which it does not get

    async def run() -> None:
        device = a_pc(pc)
        try:
            with pytest.raises(KvmError) as refused:
                await device._login()
            assert refused.value.code == "bad_response" and "Digest" in refused.value.message
            assert pc.state.logins == 0  # nothing of the password went out
            status = await device._read_status()
            assert status["state"] == "error" and status["error"]["code"] == "bad_response"
        finally:
            await device.close()

    asyncio.run(run())


def test_a_nonce_that_ran_out_is_answered_again_and_is_no_verdict_on_the_password(pc: FakeAmt) -> None:
    pc.state.stale_once = True

    async def run() -> None:
        device = a_pc(pc)
        try:
            await device._login()
            assert pc.state.stale_sent == 1 and pc.state.rejections == 0 and pc.state.logins == 2
            assert kvm.REJECTED.times(kvm.REJECTED.what("login", device.spec)) == 0
            assert (await device._read_status())["state"] == "online"
            # Later on too: a nonce the engine has forgotten (it restarted) is answered anew, in the middle of a look.
            pc.state.nonces.clear()
            assert (await device._read_status())["state"] == "online"
            assert pc.state.stale_sent >= 2 and pc.state.rejections == 0 and device._login_error is None
            # And an engine that restarted in the middle of a look and says a plain no to the nonce it has
            # forgotten, without the standard's "stale": the look keeps the nonce that no came with and signs
            # in again with it, so that costs nothing either.
            pc.state.forgets_without_saying = True
            pc.state.nonces.clear()
            assert (await device._read_status())["state"] == "online"
            assert pc.state.rejections == 0 and kvm.REJECTED.times(kvm.REJECTED.what("login", device.spec)) == 0
            # Whereas a no to a nonce the engine handed out just now is a no.
            pc.state.password = "changed on the machine"
            assert (await device._read_status())["state"] == "auth"
            assert kvm.REJECTED.times(kvm.REJECTED.what("login", device.spec)) == 1
        finally:
            await device.close()

    asyncio.run(run())


def test_the_password_changed_on_the_machine_is_noticed_in_the_middle_of_a_look_and_then_paced(pc: FakeAmt) -> None:
    async def run() -> None:
        device = a_pc(pc)
        try:
            assert (await device._read_status())["state"] == "online"
            pc.state.password = "changed on the machine"
            said = await device._read_status()
            assert said["state"] == "auth"
            # Once more with the question that was under way, once as a sign-in: a no, and the ladder begins.
            assert pc.state.rejections == 2
            for _ in range(5):
                assert (await device._read_status())["state"] == "auth"
            assert pc.state.rejections == 2
            assert kvm.REJECTED.times(kvm.REJECTED.what("login", device.spec)) == 1
        finally:
            await device.close()

    asyncio.run(run())


def test_a_user_name_that_cannot_stand_in_a_header_is_not_sent(pc: FakeAmt) -> None:
    async def run() -> None:
        device = AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=pc.url, username='ad"min', password="secret", kind="amt"))
        try:
            with pytest.raises(KvmError) as refused:
                await device._login()
            assert refused.value.code == "invalid" and pc.state.logins == 0 and pc.state.unsigned == 0
            status = await device._read_status()  # a problem with the tile, not a machine that went away
            assert status["state"] == "error" and status["error"]["code"] == "invalid"
        finally:
            await device.close()

    asyncio.run(run())


def test_an_engine_having_a_moment_before_the_sign_in_is_asked_again_shortly_and_not_at_every_look(pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "STILL_THERE_EVERY", 0.0)
    pc.state.unsigned_status = 503  # it says neither what it is nor how it is to be signed in to

    async def run() -> None:
        device = a_pc(pc)
        try:
            for _ in range(4):
                status = await device._read_status()
                assert status["state"] == "error" and status["error"]["code"] == "no_sign_in", status
            assert pc.state.unsigned == 1 and pc.state.logins == 0  # asked once, then held back; nothing of the password went out
            assert pc.state.looks >= 1  # and asked whether it is there meanwhile
            # Well again: the wait over, it is asked again and let in.
            pc.state.unsigned_status = None
            device._login_retry_at = 0.0
            for what, (times, unanswered, _) in list(kvm.REJECTED._known.items()):
                kvm.REJECTED._known[what] = (times, unanswered, 0.0)
            assert (await device._read_status())["state"] == "online"
        finally:
            await device.close()

    asyncio.run(run())


def test_an_engine_that_takes_the_sign_in_and_refuses_the_request_after_is_not_sent_the_password_at_every_look(pc: FakeAmt) -> None:
    pc.state.refuses_after_sign_in = True

    async def run() -> None:
        device = a_pc(pc)
        try:
            status = await device._read_status()
            assert status["state"] == "error" and status["error"]["code"] == "no_sign_in", status
            sent = pc.state.logins
            for _ in range(4):
                assert (await device._read_status())["error"]["code"] == "no_sign_in"
            assert pc.state.logins == sent
            assert kvm.REJECTED.times(kvm.REJECTED.what("login", device.spec)) == 0  # it took the password: no verdict on it
            # A connection made anew is told what the last one was, and sends nothing.
            other = a_pc(pc)
            try:
                assert (await other._read_status())["error"]["code"] == "no_sign_in" and pc.state.logins == sent
            finally:
                await other.close()
        finally:
            await device.close()

    asyncio.run(run())


def test_a_look_and_a_power_button_at_the_same_time_do_not_cross_on_the_nonce(pc: FakeAmt) -> None:
    pc.state.strict_nc = True  # an engine that checks the nonce count, as the standard lets it

    async def run() -> None:
        device = a_pc(pc)
        try:
            assert (await device._read_status())["state"] == "online"
            for _ in range(3):
                await asyncio.gather(device._read_status(), device.act("atx_reset"), device._read_status(), device._read_about())
            assert pc.state.replays == 0 and pc.state.rejections == 0 and pc.state.actions == [10, 10, 10]
            assert kvm.REJECTED.times(kvm.REJECTED.what("login", device.spec)) == 0 and device._login_error is None
        finally:
            await device.close()

    asyncio.run(run())


@pytest.fixture
def sixtieth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "LOGIN_BACKOFFS", tuple(wait / S for wait in kvm.LOGIN_BACKOFFS))
    monkeypatch.setattr(kvm, "LOGIN_RETRY", kvm.LOGIN_RETRY / S)
    for name in ("STATUS_TTL", "ERROR_HOLD", "BACKOFF_MAX", "STILL_THERE_EVERY", "TRANSFER_TIME", "STATUS_FIRST_WAIT", "UNANSWERED_MOST"):
        monkeypatch.setattr(kvm, name, getattr(kvm, name) / S)
    monkeypatch.setattr(kvm, "WAITS", httpx.Timeout(8.0 / A, connect=4.0 / A))  # (see A)
    monkeypatch.setattr(amt, "LOOK_EVERY", amt.LOOK_EVERY / S)
    monkeypatch.setattr(amt, "RETRY_LOOK", amt.RETRY_LOOK / S)


# The waits for an answer, and the answers that come late, a twentieth of what they are, not a sixtieth, as in
# test_a_sign_in_that_gets_no_answer.py: the engine's answer "at once" has to come within them, and a sixtieth of the
# eight seconds a look is given (0.13 s) was shorter than a busy computer took for one: the tile said "offline" of an
# engine that answers everything but its sign-in (once, in a whole run beside other tracks).
A = 20.0
CHALLENGE =(401, {"WWW-Authenticate": 'Digest realm="Digest:0123456789ABCDEF", nonce="6c2a6f1b", qop="auth"', "Server": "Intel(R) Active Management Technology 12.0.90"}, b"")
WATCHED = 375 / S
LATE, NEVER = 12 / A, 60 / A  # (later than anything else is waited for, sooner than a sign-in is; and never: see A)
HOW: dict[str, tuple[Any, int]] = {
    # how the engine answers the requests that carry the password (by their number), and how often the password may go out in the time
    "a no every time": (lambda number: CHALLENGE, 3),
    "a no, and from then on it hangs up": (lambda number: CHALLENGE if number == 1 else "drop", 8),
    "a no, and from then on the no comes late": (lambda number: CHALLENGE if number == 1 else ("after", LATE, CHALLENGE), 3),
    "every no comes late": (lambda number: ("after", LATE, CHALLENGE), 3),
    "a no, and from then on nothing in time": (lambda number: CHALLENGE if number == 1 else ("after", NEVER, CHALLENGE), 7),
    "never anything in time": (lambda number: ("after", NEVER, CHALLENGE), 6),
    "a no, and from then on an error of its own": (lambda number: CHALLENGE if number == 1 else (503, {"Content-Type": "text/plain"}, b"busy"), 7),
}


@pytest.mark.parametrize("how", list(HOW))
def test_a_password_is_not_sent_again_and_again_to_an_engine_that_does_not_take_its_sign_in(how: str, sixtieth: None) -> None:
    # The family every driver has (see test_a_sign_in_that_gets_no_answer.py), for one whose sign-in is a Digest:
    # the first request goes without the password and is told the challenge; the ones after carry it.
    answers, most = HOW[how]
    signed = 0

    def answer(method: str, path: str, head: str, body: bytes) -> Any:
        nonlocal signed
        if method == "POST" and path == amt.WSMAN and "authorization: digest" in head.lower():
            signed += 1
            return answers(signed)
        return CHALLENGE  # asked without the password: how it wants to be signed in to, as every engine says

    server = Scripted(answer).start()
    device = AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=server.url, username="admin", password="the-saved-password-1", kind="amt"))
    states: list[str] = []

    async def run() -> None:
        began = time.monotonic()
        try:
            while time.monotonic() - began < WATCHED:
                state = (await device.status())["state"]
                if not states or states[-1] != state:
                    states.append(state)
                await asyncio.sleep(0.02)
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        server.stop()
    sent = [one for one in server.asked("POST", amt.WSMAN) if "authorization: digest" in one[3].lower()]
    assert 2 <= len(sent) <= most, f"{how}: in six minutes the password went out {len(sent)} times; the tile said {states}"
    assert "the-saved-password-1" not in b"".join(one[3].encode() + one[4] for one in sent).decode("latin-1")  # a digest, never the password
    if how != "never anything in time":
        assert "auth" in states, states  # it said no once: that is what its owner is told, whatever came after
    else:
        assert set(states) <= {"connecting", "error"} and "error" in states, states


def test_a_pc_that_goes_off_while_its_password_waits_is_seen_to(pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "STILL_THERE_EVERY", 0.0)
    pc.state.password = "changed on the machine"
    stopped = False

    async def run() -> None:
        nonlocal stopped
        device = a_pc(pc)
        try:
            assert (await device._read_status())["state"] == "auth"
            offered = pc.state.logins
            assert (await device._read_status())["state"] == "auth" and pc.state.logins == offered
            assert pc.state.looks >= 1 and pc.state.unsigned == 1  # asked whether it is there, with nothing that needs the password
            pc.stop()
            stopped = True
            assert (await device._read_status())["state"] == "offline"
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        if not stopped:
            pc.stop()


# --- what a hostile or broken machine at that address can and cannot do --------------------------------


POWER = "CIM_AssociatedPowerManagementService"


@pytest.mark.parametrize(
    ("odd", "to", "code", "state"),
    [
        # Answered to the sign-in (the first request that carries the password): that sign-in came to nothing,
        # and is said as every driver says it (no_sign_in), and the password is not offered again at every look.
        ("json", "*", "no_sign_in", "error"), ("html", "*", "no_sign_in", "error"), ("nonsense", "*", "no_sign_in", "error"),
        ("doctype", "*", "no_sign_in", "error"), ("no_body", "*", "no_sign_in", "error"), ("huge", "*", "no_sign_in", "error"), ("slow", "*", "no_sign_in", "error"),
        # A fault that says "not allowed" is SOAP answered after the sign-in was checked: the password was taken,
        # and the question refused. Any other fault to the sign-in is an answer nothing is made of, like HTML.
        ("fault", "*", "bad_response", "error"), ("fault_other", "*", "no_sign_in", "error"),
        # Answered to a look, once let in: what is no SOAP is an error, never "nothing"; too much, or too slowly, is a
        # connection that is good for nothing, and the machine is asked again later, as one that is down.
        ("json", POWER, "bad_response", "error"), ("html", POWER, "bad_response", "error"), ("nonsense", POWER, "bad_response", "error"),
        ("doctype", POWER, "bad_response", "error"), ("no_body", POWER, "bad_response", "error"), ("fault", POWER, "bad_response", "error"),
        ("fault_other", POWER, "bad_response", "error"), ("huge", POWER, "dropped", "offline"), ("slow", POWER, "timeout", "offline"),
    ],
)  # fmt: skip
def test_an_answer_of_the_wrong_kind_is_an_error_and_never_nothing(tmp_path: Path, pc: FakeAmt, odd: str, to: str, code: str, state: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "TRANSFER_TIME", 0.5)
    monkeypatch.setattr(kvm, "WAITS", httpx.Timeout(1.0, connect=1.0))
    # (A sign-in that came to nothing is held back for ten seconds, as every driver holds one: a fifth of a second here.)
    monkeypatch.setattr(kvm, "LOGIN_RETRY", 0.2)
    pc.state.odd[to] = odd
    with wall(tmp_path) as client:
        refused = client.post("/api/v1/devices", json={"url": pc.url, "password": "secret"})
        assert (refused.status_code, refused.json()["code"]) == (422, code), refused.text
        assert "secret" not in refused.text
        # Added all the same, as a machine that is down may be ("Add anyway"): its tile says what is wrong, and the wall is up.
        device = add(client, pc.url, force=True)
        status = status_of(client, device, state=state)
        assert status["error"]["code"] == code
        assert client.get("/api/v1/wall").status_code == 200
        pc.state.odd.clear()
        status_of(client, device, state="online")


def test_a_detail_answered_wrongly_leaves_the_rest_of_the_tile_standing(tmp_path: Path, pc: FakeAmt) -> None:
    # The power is what the tile stands on. The rest (the hardware, the KVM) is a detail: one answered wrongly is "not said".
    pc.state.odd["CIM_Processor"] = "html"
    pc.state.odd["IPS_OptInService"] = "fault"
    pc.state.odd["CIM_SoftwareIdentity"] = "no_body"
    with wall(tmp_path) as client:
        device = add(client, pc.url)
        status = status_of(client, device, state="online")
        assert status["server"]["processor"] is None and status["server"]["processors"] is None
        assert status["about"]["version"] is None and status["about"]["model"] == "Example Computers Office Desk 7"
        assert status["server"]["amt"]["consent"] is False  # what the KVM settings said; the opt-in service was not heard
        assert status["server"]["memory_gib"] == 16


def test_a_listing_that_never_ends_is_not_followed_for_ever(pc: FakeAmt) -> None:
    pc.state.pages = 3  # a real listing in several pulls is followed to its end
    pc.state.memory = [2**30] * 9

    async def run() -> None:
        device = a_pc(pc)
        try:
            status = await device._read_status()
            assert status["server"]["memory_gib"] == 9 and asked(pc, "Pull", "CIM_PhysicalMemory") == 3
            # ...and one that goes on and on is read as far as the limits allow, and no further.
            pc.state.pages = 1000  # a module a page, and two hundred modules
            pc.state.memory = [2**30] * 200
            device._about = {}
            status = await device._read_status()
            assert status["server"]["memory_gib"] == amt.MOST_PULLS and asked(pc, "Pull", "CIM_PhysicalMemory") == 3 + amt.MOST_PULLS
            # And one that hands out more in a page than is asked for is read up to the limit, and no further.
            pc.state.pages = 1
            device._about = {}
            status = await device._read_status()
            assert status["server"]["memory_gib"] == amt.MAX_ITEMS and asked(pc, "Pull", "CIM_PhysicalMemory") == 4 + amt.MOST_PULLS
        finally:
            await device.close()

    asyncio.run(run())


def test_the_pc_is_looked_at_the_way_the_wall_looks_without_a_password_in_the_log(pc: FakeAmt, caplog: pytest.LogCaptureFixture) -> None:
    async def run() -> None:
        device = a_pc(pc, password="the-password-nobody-is-to-see")
        try:
            with pytest.raises(KvmError) as refused:
                await device._login()
            assert refused.value.code == "auth_failed" and pc.state.rejections == 1
            assert "the-password-nobody-is-to-see" not in caplog.text
            assert "the-password-nobody-is-to-see" not in repr(kvm.REJECTED._known)
        finally:
            await device.close()

    asyncio.run(run())


# --- plain HTTP and TLS ------------------------------------------------------------------------------------


def test_over_tls_the_certificate_is_remembered_and_an_impostor_gets_no_password(tmp_path: Path) -> None:
    state = AmtState()
    original = FakeAmt(state, tls_dir=tmp_path / "cert-a").start()
    try:
        with wall(tmp_path / "data") as client:
            device = add(client, original.url)
            shown = client.get("/api/v1/wall").json()["devices"][0]
            assert shown["tls"] == "pinned" and shown["fingerprint"] and shown["url"].startswith("https://")
            status = status_of(client, device, state="online")
            assert status["server"]["amt"]["plain"] is False and status["server"]["no_screen"] is None
            # The screen comes over TLS on the redirection port, with the certificate remembered on the first (the engine shows the one).
            wait_until(lambda: client.get(snap(device)).status_code == 200, "no picture over TLS", 15)
            assert state.kvm_sessions == 1
            original.stop()
            impostor = FakeAmt(AmtState(), port=original.port, tls_dir=tmp_path / "cert-b").start()
            try:
                status = status_of(client, device, state="error")
                assert status["error"]["code"] == "cert_mismatch"
                assert client.get(snap(device)).status_code != 200
                # The password, or a digest of it, was never offered to it, on either port.
                assert impostor.state.logins == 0 and impostor.state.redirection_logins == 0
            finally:
                impostor.stop()
    finally:
        original.stop()


def test_a_bare_address_is_asked_on_the_ports_an_engine_listens_on(tmp_path: Path, pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    # Typed without a port, as somebody types the address of a PC: the two ports every engine listens on are asked.
    monkeypatch.setattr(amt, "PORTS", (("https", closed_port()), ("http", pc.port)))  # (nothing listens on the TLS one)
    with wall(tmp_path) as client:
        # Typed with https:// in front, what answers only the plain way is said, and not sent the password.
        said = client.post("/api/v1/devices", json={"url": "https://127.0.0.1", "password": "secret"})
        assert (said.status_code, said.json()["code"]) == (422, "plain_only") and pc.url in said.json()["message"]
        assert pc.state.logins == 0
        # Typed bare, it is taken the way it answers, and the tile says that this is the plain way.
        reply = client.post("/api/v1/devices", json={"url": "127.0.0.1", "password": "secret"})
        assert reply.status_code == 201, reply.text
        assert reply.json()["device"]["kind"] == "amt" and reply.json()["device"]["url"] == pc.url
        assert status_of(client, reply.json()["device"]["id"], state="online")["server"]["amt"]["plain"] is True


def test_a_bare_address_whose_tls_port_is_only_slow_is_not_taken_the_plain_way(pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    # Something listens on the TLS port and never answers (a device slow to wake): that is not "nothing there".
    slow = socket.socket()
    slow.bind(("127.0.0.1", 0))
    slow.listen(1)
    try:
        monkeypatch.setattr(amt, "PORTS", (("https", slow.getsockname()[1]), ("http", pc.port)))
        with pytest.raises(KvmError) as said:
            asyncio.run(amt.detect("https://127.0.0.1", False, None, within=0.5))
        assert said.value.code == "plain_only" and pc.url in said.value.message and "did not answer in time" in said.value.message
        # Whereas a TLS port that plainly refuses is nothing there, and the plain way is taken.
        gone = closed_port()
        monkeypatch.setattr(amt, "PORTS", (("https", gone), ("http", pc.port)))
        assert asyncio.run(amt.detect("https://127.0.0.1", False, None, within=0.5)) == ("amt", pc.url)
        # And a port that was typed is asked and nothing else.
        assert asyncio.run(amt.detect(pc.url, True, pc.port, within=0.5)) == ("amt", pc.url)
        assert asyncio.run(amt.detect(f"https://127.0.0.1:{gone}", True, gone, within=0.5)) is None
    finally:
        slow.close()


def test_found_on_the_network(tmp_path: Path, pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    nowhere = "http://127.0.0.1:9"
    monkeypatch.setattr(discover, "targets", lambda: ([discover.Target("127.0.0.1", nowhere, nowhere, "desk")], ["test network"]))
    monkeypatch.setattr(discover, "AMT_PORTS", (("https", closed_port()), ("http", pc.port)))
    with wall(tmp_path) as admin:
        found = admin.post("/api/v1/discover").json()["found"]
        assert [(one["address"], one["kind"], one["url"], one["name"]) for one in found] == [("127.0.0.1", "amt", pc.url, "desk")]
        assert pc.state.logins == 0  # looking is not signing in
        pc.state.without_server_header = True  # an engine that does not say what it is is still known by its realm
        assert admin.post("/api/v1/discover").json()["found"][0]["kind"] == "amt"


@contextmanager
def tls_that_fails() -> Iterator[int]:
    """A port that takes connections, and answers whatever comes with what is no TLS and hangs up: an engine with an old TLS
    stack, or one too busy while its PC starts, as the wall sees it on 16993."""
    listening = socket.socket()
    listening.bind(("127.0.0.1", 0))
    listening.listen(16)
    listening.settimeout(0.1)
    done = threading.Event()

    def serve() -> None:
        while not done.is_set():
            try:
                taken, _ = listening.accept()
            except OSError:
                continue
            with taken:
                taken.settimeout(2.0)
                try:
                    taken.recv(4096)
                    taken.sendall(b"HTTP/1.1 400 Bad Request" + bytes((13, 10, 13, 10)))
                except OSError:
                    pass

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    try:
        yield int(listening.getsockname()[1])
    finally:
        done.set()
        worker.join(timeout=5)
        listening.close()


def test_a_bare_address_whose_tls_port_fails_the_handshake_is_not_taken_the_plain_way(tmp_path: Path, pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    # Something on the TLS port takes the connection and fails the TLS handshake. The HTTP library says that as it says a
    # refusal, and it is none: taken the plain way, the password would go as an MD5 Digest on the wire, and the screen, its
    # keys and the texts typed into it over the plain redirection port. It is said, as for a TLS port that is only slow.
    with tls_that_fails() as port:
        monkeypatch.setattr(amt, "PORTS", (("https", port), ("http", pc.port)))
        with pytest.raises(KvmError) as said:
            asyncio.run(amt.detect("https://127.0.0.1", False, None, within=2.0))
        assert said.value.code == "plain_only" and pc.url in said.value.message and "TLS handshake" in said.value.message
        with wall(tmp_path) as client:
            refused = client.post("/api/v1/devices", json={"url": "127.0.0.1", "password": "secret"})
            assert (refused.status_code, refused.json()["code"]) == (422, "plain_only"), refused.text
    assert pc.state.logins == 0  # nothing of the password went anywhere


def test_an_engine_added_by_its_kind_without_a_port_is_at_its_own_port(tmp_path: Path) -> None:
    # Chosen as a PC with Intel AMT and typed without a port, the engine is at its own port, 16993 (16992 typed with http://),
    # and not at 443 or 80, beside which its redirection port is not known (see the tests of the screen). A port that was
    # typed is taken as typed. (A name that leads nowhere: saved anyway, nothing is asked of any machine.)
    assert amt.at_its_port("https://192.168.1.60") == "https://192.168.1.60:16993" and amt.at_its_port("http://[fd00::5]") == "http://[fd00::5]:16992"
    with wall(tmp_path) as client:
        for typed, kept in (("pc-1.invalid", "https://pc-1.invalid:16993"), ("http://pc-2.invalid", "http://pc-2.invalid:16992"), ("https://pc-3.invalid:443", "https://pc-3.invalid")):
            reply = client.post("/api/v1/devices", json={"url": typed, "kind": "amt", "password": "secret", "force": True})
            assert reply.status_code == 201 and reply.json()["device"]["url"] == kept, (typed, reply.text)


def test_the_reset_button_is_not_sent_to_a_pc_that_is_off(tmp_path: Path, pc: FakeAmt) -> None:
    # As for a guest of Proxmox: what is off is not reset. Where the engine lists nothing it offers, it was sent all the same,
    # and an engine that offered a power cycle there would have switched the PC on for the reset button.
    pc.state.power, pc.state.offered = 8, []
    with wall(tmp_path) as client:
        device = add(client, pc.url)
        status_of(client, device, state="no_signal")
        refused = client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_reset"})
        assert (refused.status_code, refused.json().get("code"), refused.json().get("message")) == (502, "action_failed", "The PC is off: there is nothing to reset")
        assert pc.state.actions == []


# --- which PC answers at the address ---------------------------------------------------------------------------------
# Over plain HTTP (the usual setup of a PC without TLS), or with its certificate not checked, nothing but the number a PC
# gives for itself tells one engine from another. With one MEBx password across a fleet, after a new lease another PC
# answers at a tile's address: a tile that did not ask would switch it off, reset it, and type into it.

OTHER_GUID = "9F8E7D6C5B4A49380716A5B4C3D2E1F0"  # the number another PC gives for itself


def another_pc(**more: Any) -> AmtState:
    return AmtState(**{"guid": OTHER_GUID, "hostname": "desk-8", "serial": "PC0000000002", **more})


def swap_in(machine: FakeAmt, state: AmtState) -> FakeAmt:
    """Another engine at the address `machine` had: it stops, and the other answers at its port from now on (a new lease)."""
    machine.stop()
    return FakeAmt(state, port=machine.port).start()


def test_another_pc_that_took_the_address_is_sent_no_power_command_nor_keys_and_the_tile_says_so(tmp_path: Path) -> None:
    machines = [FakeAmt().start()]
    try:
        with wall(tmp_path) as client:
            device = add(client, machines[0].url)
            assert client.core.store.device(device).machine == own_number(GUID)  # type: ignore[attr-defined]
            status_of(client, device, state="online")
            # In the same realm as this tile's PC, as a fleet set up alike may be: a look sees it when it next reads what the PC is.
            machines.append(swap_in(machines[0], another_pc()))
            other = machines[-1]
            act = f"/api/v1/devices/{device}/actions"
            for action in ("atx_power_long", "atx_reset", "power_off"):
                refused = client.post(act, json={"action": action})
                assert (refused.status_code, refused.json().get("code")) == (502, "another_machine"), (action, refused.text)
            assert other.state.actions == []
            status = status_of(client, device, state="error")
            assert status["error"]["code"] == "another_machine" and "Another PC answers at this address" in status["error"]["message"]
            typed = client.post(act, json={"action": "text", "text": "what is typed into this tile's PC"})
            assert (typed.status_code, typed.json().get("code")) == (502, "another_machine")
            assert client.get(snap(device)).status_code != 200
            switched = client.post(f"/api/v1/devices/{device}/kvm", json={"on": False})
            assert (switched.status_code, switched.json().get("code")) == (502, "another_machine") and other.state.changes == []
            assert (other.state.redirections, other.state.redirection_logins, other.state.kvm_sessions) == (0, 0, 0)
            # This tile's PC answers there again: the tile says how it is, and its buttons are its own again.
            machines.append(swap_in(other, AmtState()))
            status_of(client, device, state="online")
            assert client.post(act, json={"action": "atx_power_long"}).status_code == 200 and machines[-1].state.actions == [8]
    finally:
        machines[-1].stop()


def test_a_session_to_the_screen_is_not_opened_to_another_pc_that_took_the_address(tmp_path: Path) -> None:
    # The first thing asked for after the new lease is the screen, before any look has seen the other PC (one reads what the
    # PC is every ten minutes, and the two answer in one realm): the session asks first, and nothing goes to the redirection
    # port of the other, neither the Digest of the password nor, after it, the keys of the tile.
    machines = [FakeAmt().start()]
    try:
        with wall(tmp_path) as client:
            device = add(client, machines[0].url)
            status_of(client, device, state="online")
            machines.append(swap_in(machines[0], another_pc()))

            def shown() -> str:
                reply = client.get(snap(device))
                return "a picture" if reply.status_code == 200 else str(reply.json().get("code"))

            wait_until(lambda: shown() == "another_machine", "the tile did not say that another PC answers", 15)
            other = machines[-1]
            assert (other.state.redirections, other.state.redirection_logins, other.state.kvm_sessions) == (0, 0, 0)
    finally:
        machines[-1].stop()


@pytest.mark.parametrize("just_started", [False, True])
def test_a_look_that_signs_in_in_another_realm_reads_at_once_which_pc_answers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, just_started: bool) -> None:
    # Each engine has a realm of its own: signed in in another one than before, the look reads at once what the PC is, and
    # the tile says that another PC answers, without anything having been pressed or asked for. Also where the computer
    # qKVM runs on was started less than ABOUT_TTL ago (the clock that never goes back counts from its start, and "read
    # at 0" was "read a moment ago" then): made so here by an ABOUT_TTL longer than that clock has run.
    if just_started:
        monkeypatch.setattr(amt, "ABOUT_TTL", time.monotonic() + 600.0)
    machines = [FakeAmt().start()]
    try:
        with wall(tmp_path) as client:
            device = add(client, machines[0].url)
            status_of(client, device, state="online")
            machines.append(swap_in(machines[0], another_pc(realm="Digest:" + "5B6C7D8E" * 4)))
            status = status_of(client, device, state="error")
            assert status["error"]["code"] == "another_machine" and machines[-1].state.actions == []
    finally:
        machines[-1].stop()


def test_an_engine_that_names_no_pc_where_this_tiles_pc_gave_its_number_is_sent_nothing(tmp_path: Path) -> None:
    machines = [FakeAmt().start()]
    try:
        with wall(tmp_path) as client:
            device = add(client, machines[0].url)
            machines.append(swap_in(machines[0], another_pc(guid=None)))
            refused = client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power_long"})
            assert (refused.status_code, refused.json().get("code")) == (502, "another_machine") and "does not say which PC it is" in refused.json()["message"]
            assert machines[-1].state.actions == []
            # And the tile says so from then on: while one stands, every look asks afresh (a look that read no number in
            # passing would judge nothing, and the tile went on saying "online").
            status = status_of(client, device, state="error")
            assert status["error"]["code"] == "another_machine" and "does not say which PC it is" in status["error"]["message"]
    finally:
        machines[-1].stop()


def test_a_look_in_another_realm_asks_strictly_and_says_so_of_an_engine_that_names_no_pc(tmp_path: Path) -> None:
    # A challenge in another realm: the look asks which PC answers as a button would, and an engine that names no number is
    # said at once (a look that reads none in passing judges nothing, and the tile went on saying "online").
    machines = [FakeAmt().start()]
    try:
        with wall(tmp_path) as client:
            device = add(client, machines[0].url)
            status_of(client, device, state="online")
            machines.append(swap_in(machines[0], another_pc(guid=None, realm="Digest:" + "5B6C7D8E" * 4)))
            status = status_of(client, device, state="error")
            assert status["error"]["code"] == "another_machine" and "does not say which PC it is" in status["error"]["message"]
    finally:
        machines[-1].stop()


def test_an_engine_that_cannot_say_its_number_keeps_its_buttons_and_screen_where_none_is_remembered(tmp_path: Path) -> None:
    # Asked for its number, it answers with a fault of its own: with no number remembered there is nothing to tell it apart
    # from, and it is worked as before the number was asked for at all (the buttons were refused "Nothing was sent").
    pc = FakeAmt(AmtState(odd={"CIM_ComputerSystemPackage": "fault_other"})).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, pc.url)
            assert client.core.store.device(device).machine == ""  # type: ignore[attr-defined]
            status_of(client, device, state="online")
            pressed = client.post(f"/api/v1/devices/{device}/actions", json={"action": "power_off"})
            assert pressed.status_code == 200, pressed.text
            assert pc.state.actions == [12]
            client.post(f"/api/v1/devices/{device}/actions", json={"action": "power_on"})
            wait_until(lambda: client.get(snap(device)).status_code == 200, "its screen did not come", 15)
    finally:
        pc.stop()


LEASED_AFTER_THE_QUESTION = [
    # How the other engine says no to what was signed for the PC that was asked (its nonce), and in which realm.
    ("in another realm, with a plain no", {"realm": "Digest:" + "5B6C7D8E" * 4}),
    ("in one realm, saying that the nonce (one it never handed out) ran out", {}),
    ("in one realm, with a plain no to a nonce it never handed out", {"forgets_without_saying": True}),
]


@pytest.mark.parametrize(("how", "other"), LEASED_AFTER_THE_QUESTION)
def test_a_command_is_not_sent_to_another_pc_that_took_the_address_after_it_was_asked(how: str, other: dict[str, Any]) -> None:
    # The new lease comes between the question which PC answers and the command (a moment, made long here), so that the
    # power read before the command is the first to meet the other engine, and goes on with its nonce: the command is not
    # signed with any but the nonce under which this PC was asked, and is asked again first. (Seen by the third reviewer: with
    # one realm across a fleet, the read took the other engine's nonce without a word, and the command went out with it.)
    pc = FakeAmt().start()
    machines = [pc]

    async def run() -> KvmError:
        device = AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=pc.url, username="admin", password="secret", kind="amt", machine=own_number(GUID)))
        try:
            assert (await device.status())["state"] == "online"
            asked = device._same_machine

            async def then_a_new_lease(urgent: bool, vital: bool = True) -> None:
                await asked(urgent, vital)
                if len(machines) == 1:
                    machines.append(await asyncio.to_thread(swap_in, pc, another_pc(**other)))

            device._same_machine = then_a_new_lease  # type: ignore[method-assign]
            with pytest.raises(KvmError) as refused:
                await device.act("atx_power_long")
            return refused.value
        finally:
            await device.close()

    try:
        refused = asyncio.run(run())
        assert len(machines) == 2 and machines[-1].state.actions == [], how
        assert refused.code == "another_machine", (how, refused.code, refused.message)
    finally:
        machines[-1].stop()


def test_a_power_cut_that_waited_for_the_kvm_session_to_close_asks_again_which_pc_answers() -> None:
    # The engine cuts no power while a KVM session is open: the wall's own is closed, and the offer waited for, seconds in
    # which the address may change hands (here: in that very moment, in one realm). Asked again just before the command.
    pc = FakeAmt().start()
    machines = [pc]

    async def run() -> KvmError:
        device = AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=pc.url, username="admin", password="secret", kind="amt", machine=own_number(GUID)))
        try:
            await device.status()
            deadline = time.monotonic() + 15
            while True:
                device._screen.live_seen()  # (the large view is open: a session is held, as it is for a power cut)
                try:
                    await device.snapshot(4000)
                    break
                except KvmError as ex:
                    if ex.code != "no_stream" or time.monotonic() > deadline:
                        raise
                await asyncio.sleep(0.05)
            device._screen.live_seen()
            assert pc.state.kvm_open == 1  # (a session of the wall's is open: the engine offers no power cut)
            offered = device._offered_after_the_session

            async def a_new_lease_meanwhile(wanted: list[int], within: float) -> int:
                machines.append(await asyncio.to_thread(swap_in, pc, another_pc()))
                return await offered(wanted, within)

            device._offered_after_the_session = a_new_lease_meanwhile  # type: ignore[method-assign]
            with pytest.raises(KvmError) as refused:
                await device.act("atx_power_long")
            return refused.value
        finally:
            await device.close()

    try:
        refused = asyncio.run(run())
        assert refused.code == "another_machine" and len(machines) == 2 and machines[-1].state.actions == []
    finally:
        machines[-1].stop()


@pytest.mark.parametrize(
    ("how", "other"),
    [
        ("in one realm: the command's nonce is one it never handed out, and it says that it ran out", {}),
        ("in another realm, with a plain no", {"realm": "Digest:" + "5B6C7D8E" * 4}),
        ("in another realm, saying that the nonce ran out (it does not compare the realm of an answer)", {"realm": "Digest:" + "5B6C7D8E" * 4, "checks_realm": False}),
    ],
)
def test_a_power_command_answered_with_a_no_is_not_sent_again_before_it_is_asked_which_pc_answers(how: str, other: dict[str, Any]) -> None:
    # The new lease comes after which PC answers was asked and the power read, just before the command: the command is
    # answered with a no, however the other engine words it, and is not sent again (signed anew for whatever answers) before
    # which PC answers is asked again. (Seen by the second reviewer: a no that said "stale" in another realm was answered
    # with the command once more, and the other PC's power was cut.)
    pc = FakeAmt().start()
    machines = [pc]

    async def run() -> KvmError:
        device = AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=pc.url, username="admin", password="secret", kind="amt", machine=own_number(GUID)))
        try:
            assert (await device.status())["state"] == "online"
            read = device._read_power

            async def then_a_new_lease(urgent: bool = False) -> tuple[int, list[int]]:
                found = await read(urgent)
                if urgent and len(machines) == 1:  # (the read before the command, not a look's)
                    machines.append(await asyncio.to_thread(swap_in, pc, another_pc(**other)))
                return found

            device._read_power = then_a_new_lease  # type: ignore[method-assign]
            with pytest.raises(KvmError) as refused:
                await device.act("atx_power_long")
            return refused.value
        finally:
            await device.close()

    try:
        refused = asyncio.run(run())
        assert len(machines) == 2 and machines[-1].state.actions == [], how
        assert refused.code == "another_machine", (how, refused.code, refused.message)
    finally:
        machines[-1].stop()


@pytest.mark.parametrize(("how", "other"), LEASED_AFTER_THE_QUESTION)
def test_the_kvm_of_another_pc_that_took_the_address_meanwhile_is_not_switched(how: str, other: dict[str, Any]) -> None:
    # As for a power command: the KVM's switch writes to the engine, and is signed only with the nonce under which this PC
    # was asked (here the lease comes after that question, and the read of its KVM's settings meets the other engine).
    pc = FakeAmt(AmtState(kvm="disabled", listener=False)).start()
    machines = [pc]

    async def run() -> KvmError:
        device = AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=pc.url, username="admin", password="secret", kind="amt", machine=own_number(GUID)))
        try:
            await device.status()
            asked = device._same_machine

            async def then_a_new_lease(urgent: bool, vital: bool = True) -> None:
                await asked(urgent, vital)
                if len(machines) == 1:
                    machines.append(await asyncio.to_thread(swap_in, pc, another_pc(kvm="disabled", listener=False, **other)))

            device._same_machine = then_a_new_lease  # type: ignore[method-assign]
            with pytest.raises(KvmError) as refused:
                await device.switch_kvm(True)
            return refused.value
        finally:
            await device.close()

    try:
        refused = asyncio.run(run())
        assert len(machines) == 2 and machines[-1].state.changes == [] and refused.code == "another_machine", (how, refused.code, refused.message)
    finally:
        machines[-1].stop()


@pytest.mark.parametrize("its_listener", [False, True])
def test_the_listener_of_another_pc_that_took_the_address_after_the_kvm_was_switched_is_not_switched(its_listener: bool) -> None:
    # The lease comes after the KVM's access point was switched on and before the redirection listener's Put (one realm): the
    # Put is not sent to the other PC, and whoever asked is told what was done and what was not. Also where the other PC's
    # listener is on already: the read that decides whether a Put is needed is this PC's or none (it said "done").
    pc = FakeAmt(AmtState(kvm="disabled", listener=False)).start()
    machines = [pc]

    async def run() -> KvmError:
        device = AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=pc.url, username="admin", password="secret", kind="amt", machine=own_number(GUID)))
        try:
            await device.status()
            got = device._get

            async def a_new_lease_before_the_listener(resource: str, urgent: bool = False, vital: bool = True) -> Any:
                if resource == amt.REDIRECTION and len(machines) == 1:
                    machines.append(await asyncio.to_thread(swap_in, pc, another_pc(kvm="disabled", listener=its_listener)))
                return await got(resource, urgent, vital)

            device._get = a_new_lease_before_the_listener  # type: ignore[method-assign]
            with pytest.raises(KvmError) as refused:
                await device.switch_kvm(True)
            return refused.value
        finally:
            await device.close()

    try:
        refused = asyncio.run(run())
        assert len(machines) == 2 and pc.state.changes == [("CIM_KVMRedirectionSAP", "2")] and machines[-1].state.changes == []
        assert refused.code == "another_machine" and refused.message.startswith("Its KVM was switched on on the engine, and its redirection listener was not: another PC answers at this address"), refused.message
    finally:
        machines[-1].stop()


def test_a_look_that_read_another_pcs_kvm_while_a_button_found_it_says_another_pc() -> None:
    # A look is between reading what the PC is and how its KVM is set up when a button finds that another PC answers: what
    # that look reads next is the other PC's. The look says that another PC answers, and the live line is not offered.
    pc = FakeAmt().start()

    async def run() -> tuple[dict[str, Any], bool, dict[str, Any]]:
        device = AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=pc.url, username="admin", password="secret", kind="amt", machine=own_number(GUID)))
        try:
            assert (await device.status())["state"] == "online"
            kvm_read = device._read_kvm

            async def found_meanwhile(urgent: bool = False) -> dict[str, Any]:
                device._another(amt.ANOTHER_PC)  # (as `_same_machine` does it, from a button pressed at this moment)
                return await kvm_read(urgent)

            device._read_kvm = found_meanwhile  # type: ignore[method-assign]
            device._kvm_at = float("-inf")
            return await device._read_status(), device.console_readable, device._kvm
        finally:
            await device.close()

    try:
        status, readable, kept = asyncio.run(run())
        assert (status["state"], status["error"]["code"], readable) == ("error", "another_machine", False)
        # And what it read meanwhile is not kept: drawn from the other PC's KVM, the tile of the right one, once it answers
        # again, would have taken the other's "no consent" for its own for a minute.
        assert kept == {}
    finally:
        pc.stop()


def routed_to(device: AmtDevice, where: Any) -> None:
    """Every request of `device` goes to the engine `where(request)` names: an address that two engines answer in turn."""
    sent = device._send

    async def routed(client: httpx.AsyncClient, request: httpx.Request, limit: int, within: float | None = None) -> httpx.Response:
        request.url = request.url.copy_with(port=where(request).port)
        return await sent(client, request, limit, within)

    device._send = routed  # type: ignore[method-assign]


def test_a_command_goes_only_under_the_nonce_the_answer_with_the_pcs_number_came_under() -> None:
    # (The fourth reviewer's probe.) The address is answered by two engines in turn (an address that two PCs claim): the
    # question which PC answers reaches this PC's engine, and a request made meanwhile, and the command, the other's. The
    # nonce the check is bound to is the one its answer came under, not the one the other engine handed out meanwhile; so the
    # command is not taken by the other engine, and is not done.
    mine, other = FakeAmt().start(), FakeAmt(another_pc()).start()

    async def run() -> KvmError:
        device = AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=mine.url, username="admin", password="secret", kind="amt", machine=own_number(GUID)))
        try:
            assert (await device.status())["state"] == "online"
            meanwhile: list[asyncio.Task[Any]] = []

            def where(request: httpx.Request) -> FakeAmt:
                if b"CIM_ComputerSystemPackage" in request.content:
                    if b"Enumerate" in request.content and not meanwhile:
                        meanwhile.append(asyncio.ensure_future(device._request(amt.get_of(amt.GENERAL))))  # (waits for its turn)
                    return mine
                return other

            routed_to(device, where)
            await device._same_machine(urgent=True)
            await meanwhile[0]
            with pytest.raises(KvmError) as refused:
                await device._power_command(amt.OFF, None)
            return refused.value
        finally:
            await device.close()

    try:
        refused = asyncio.run(run())
        assert other.state.actions == [] and mine.state.actions == []
        assert refused.code == "action_failed" and refused.message.startswith("It was not done: the engine at this address handed out new nonces"), refused.message
    finally:
        mine.stop()
        other.stop()


def test_a_button_is_not_decided_by_what_another_pc_that_took_the_address_says_of_itself() -> None:
    # This PC is off, and the other that took the address after the question is on: "power on" is not answered "already on"
    # (the other PC's state, read under the other engine's nonce), but that another PC answers.
    pc = FakeAmt(AmtState(power=8)).start()
    machines = [pc]

    async def run() -> KvmError:
        device = AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=pc.url, username="admin", password="secret", kind="amt", machine=own_number(GUID)))
        try:
            await device.status()
            asked = device._same_machine

            async def then_a_new_lease(urgent: bool, vital: bool = True) -> None:
                await asked(urgent, vital)
                if len(machines) == 1:
                    machines.append(await asyncio.to_thread(swap_in, pc, another_pc(power=2)))

            device._same_machine = then_a_new_lease  # type: ignore[method-assign]
            with pytest.raises(KvmError) as refused:
                await device.act("power_on")
            return refused.value
        finally:
            await device.close()

    try:
        refused = asyncio.run(run())
        assert not isinstance(refused, kvm.AlreadySo) and refused.code == "another_machine", (type(refused).__name__, refused.message)
        assert machines[-1].state.actions == []
    finally:
        machines[-1].stop()


def test_power_commands_get_through_beside_busy_looks_where_the_engines_nonces_last_a_few_uses() -> None:
    # (After the fourth reviewer's probe.) An engine whose nonces last three signed requests, and that takes a nonce count only
    # once (a replay otherwise); at every press, looks that read what the PC is too, and the screen's question which PC answers,
    # all at once. Each command, its question which PC answers and its reads go under one nonce, and nothing else spends it in
    # between. (Bound to the nonce with those in between, every command was refused, and the tile's sign-in held back with words
    # that blamed the password; and a command that waited for its turn with an older nonce signed a count already used.)
    pc = FakeAmt(AmtState(nonce_uses=3, strict_nc=True)).start()

    async def run() -> list[Any]:
        device = AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=pc.url, username="admin", password="secret", kind="amt", machine=own_number(GUID)))
        outcomes: list[Any] = []
        try:
            await device.status()
            for _ in range(8):
                device._about_at = float("-inf")  # (what the PC is read again by the looks too: many questions)
                found = await asyncio.gather(
                    device._read_status(), device.act("atx_reset"), device._read_status(), device._before_a_session(), device._read_status(),
                    return_exceptions=True,
                )  # fmt: skip
                outcomes.append(found[1])
                assert all(isinstance(look, dict) and look["state"] == "online" for look in (found[0], found[2], found[4])), found
        finally:
            await device.close()
        return outcomes

    try:
        outcomes = asyncio.run(run())
        assert outcomes == [None] * 8, outcomes
        assert pc.state.actions == [amt.RESET] * 8 and pc.state.replays == 0
    finally:
        pc.stop()


@pytest.mark.parametrize(("where", "said"), [("the Put", "whether its redirection listener was is not known"), ("the read before it", "its redirection listener was not")])
def test_a_listener_switch_whose_answer_did_not_come_back_is_said_as_not_known_only_where_the_put_went_out(where: str, said: str) -> None:
    pc = FakeAmt(AmtState(kvm="disabled", listener=False)).start()

    async def run() -> KvmError:
        device = AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=pc.url, username="admin", password="secret", kind="amt", machine=own_number(GUID)))
        try:
            await device.status()
            sent = device._send

            async def broken(client: httpx.AsyncClient, request: httpx.Request, limit: int, within: float | None = None) -> httpx.Response:
                if where == "the Put" and b"transfer/Put" in request.content:
                    await sent(client, request, limit, within)
                    raise httpx.ReadError("the connection broke after the Put went out")
                if where == "the read before it" and b"transfer/Get" in request.content and b"AMT_RedirectionService" in request.content:
                    raise httpx.ReadTimeout("no answer")
                return await sent(client, request, limit, within)

            device._send = broken  # type: ignore[method-assign]
            with pytest.raises(KvmError) as refused:
                await device.switch_kvm(True)
            return refused.value
        finally:
            await device.close()

    try:
        refused = asyncio.run(run())
        assert refused.message.startswith(f"Its KVM was switched on on the engine, and {said}"), refused.message
        assert pc.state.changes[0] == ("CIM_KVMRedirectionSAP", "2")
    finally:
        pc.stop()


@pytest.mark.parametrize("uses", [3, 4, 6])
@pytest.mark.parametrize("what", ["power", "kvm"])
def test_a_command_gets_through_at_every_phase_of_an_engines_nonce_that_lasts_a_few_uses(what: str, uses: int) -> None:
    # (The fifth reviewer's probe.) An engine whose nonces last a few signed requests: whatever is left of the nonce when the
    # button is pressed (a phase), the command gets through, and is sent once. (A read that a command is decided by, read
    # again after each question which PC answers, met a nonce run out every time at some phases: nonces of four uses, a
    # reset; of three, the KVM's switch, which was then left half done.)
    failed: list[str] = []
    for phase in range(uses):
        pc = FakeAmt(AmtState(nonce_uses=uses, strict_nc=True, kvm="disabled" if what == "kvm" else "enabled", listener=what != "kvm")).start()

        async def run(pc: FakeAmt, phase: int) -> None:
            device = AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=pc.url, username="admin", password="secret", kind="amt", machine=own_number(GUID)))
            try:
                await device.status()
                await asyncio.gather(*[task for task in (device._status_task,) if task is not None])  # (the first look over)
                stale = pc.state.stale_sent
                while pc.state.stale_sent == stale:  # (from a fresh nonce: asked until the engine says that one ran out)
                    await device._request(amt.get_of(amt.GENERAL))
                for _ in range(phase):
                    await device._request(amt.get_of(amt.GENERAL))
                if what == "kvm":
                    await device.switch_kvm(True)
                else:
                    await device.act("atx_reset")
            finally:
                await device.close()

        try:
            asyncio.run(run(pc, phase))
            sent = pc.state.changes if what == "kvm" else pc.state.actions
            wanted = [("CIM_KVMRedirectionSAP", "2"), ("AMT_RedirectionService", "ListenerEnabled=true")] if what == "kvm" else [amt.RESET]
            if sent != wanted or pc.state.replays:
                failed.append(f"phase {phase}: sent {sent}, replays {pc.state.replays}")
        except KvmError as ex:
            failed.append(f"phase {phase}: {ex.code}: {ex.message}")
        finally:
            pc.stop()
    assert failed == [], failed


def test_a_button_waits_for_one_read_of_a_look_and_not_for_all_of_it() -> None:
    # A look that reads everything (what the PC is, how its KVM is set up: some twenty questions) on an engine that takes its
    # time over each: a button pressed during it goes between two of its reads, and is done before the look is.
    pc = FakeAmt(AmtState(sign_in_takes=0.2)).start()

    async def run() -> list[str]:
        device = AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=pc.url, username="admin", password="secret", kind="amt", machine=own_number(GUID)))
        ended: list[str] = []
        try:
            await device.status()
            await asyncio.gather(*[task for task in (device._status_task,) if task is not None])  # (the first look over)
            device._about_at, device._kvm_at = float("-inf"), float("-inf")
            asked = len(pc.state.requests)

            async def looking() -> None:
                await device._read_status()
                ended.append("the look")

            async def pressing() -> None:
                await device.act("atx_reset")
                ended.append("the button")

            look = asyncio.create_task(looking())
            while len(pc.state.requests) < asked + 3:  # (the look is under way: some of its questions are answered)
                await asyncio.sleep(0.01)
            await asyncio.gather(look, pressing())
        finally:
            await device.close()
        return ended

    try:
        assert asyncio.run(run()) == ["the button", "the look"]
        assert pc.state.actions == [amt.RESET]
    finally:
        pc.stop()


@pytest.mark.parametrize("how", ["no answer", "the tile is changed meanwhile"])
def test_a_kvm_switch_whose_question_which_pc_answers_fails_says_that_nothing_was_sent(how: str) -> None:
    pc = FakeAmt(AmtState(kvm="disabled", listener=False)).start()

    async def run() -> KvmError:
        device = AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=pc.url, username="admin", password="secret", kind="amt", machine=own_number(GUID)))
        try:
            await device.status()
            sent = device._send

            async def failing(client: httpx.AsyncClient, request: httpx.Request, limit: int, within: float | None = None) -> httpx.Response:
                if b"CIM_ComputerSystemPackage" in request.content:
                    if how == "no answer":
                        raise httpx.ReadTimeout("no answer")
                    await device.close()
                return await sent(client, request, limit, within)

            device._send = failing  # type: ignore[method-assign]
            with pytest.raises(KvmError) as refused:
                await device.switch_kvm(True)
            return refused.value
        finally:
            await device.close()

    try:
        refused = asyncio.run(run())
        assert refused is not kvm.RETIRED and refused.message.startswith("Nothing was sent: "), refused.message
        assert pc.state.changes == []
    finally:
        pc.stop()


@pytest.mark.parametrize("what", ["the power command", "the listener's Put"])
def test_a_command_whose_answer_runs_past_the_walls_own_time_may_have_been_done(what: str) -> None:
    # The command went out, and its answer came so slowly that the wall's own time for a whole answer ran out (kvm.bounded's
    # time-out, not the HTTP library's): it may have been done, and is said so.
    pc = FakeAmt(AmtState(kvm="disabled", listener=False)).start()

    async def run() -> KvmError:
        device = AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=pc.url, username="admin", password="secret", kind="amt", machine=own_number(GUID)))
        try:
            await device.status()
            sent = device._send
            marked = b"RequestPowerStateChange" if what == "the power command" else b"transfer/Put"

            async def too_slow(client: httpx.AsyncClient, request: httpx.Request, limit: int, within: float | None = None) -> httpx.Response:
                reply = await sent(client, request, limit, within)
                if marked in request.content:
                    raise KvmError("timeout", "Device did not respond in time", 504)  # (as kvm.bounded says it)
                return reply

            device._send = too_slow  # type: ignore[method-assign]
            with pytest.raises(KvmError) as refused:
                if what == "the power command":
                    await device.act("atx_reset")
                else:
                    await device.switch_kvm(True)
            return refused.value
        finally:
            await device.close()

    try:
        refused = asyncio.run(run())
        assert refused.code == "timeout", refused.message
        if what == "the power command":
            assert "it may have been done" in refused.message and pc.state.actions == [amt.RESET]
        else:
            assert refused.message.startswith("Its KVM was switched on on the engine, and whether its redirection listener was is not known"), refused.message
    finally:
        pc.stop()


def watched(device: AmtDevice, marks: bytes, seen: asyncio.Event) -> None:
    """`seen` is set as `device` sends a request with all of `marks` in it (a class, an action)."""
    sent = device._send

    async def watching(client: httpx.AsyncClient, request: httpx.Request, limit: int, within: float | None = None) -> httpx.Response:
        if all(mark in request.content for mark in marks.split(b" ")):
            seen.set()
        return await sent(client, request, limit, within)

    device._send = watching  # type: ignore[method-assign]


@pytest.mark.parametrize("on", [True, False])
def test_a_kvm_switched_while_a_look_reads_how_it_is_set_up_is_seen_switched(on: bool) -> None:
    # (The sixth reviewer's probe.) An admin switches the PC's KVM while a look is reading how it is set up, right after its
    # read of the access point: the switch goes between two of the look's reads. The look is read again at once, and the tile
    # says the KVM as it is now (it kept the access point as it was before, "switched off", for a minute).
    pc = FakeAmt(AmtState(sign_in_takes=0.2, kvm="disabled" if on else "enabled", listener=not on)).start()

    async def run() -> tuple[str, bool]:
        device = AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=pc.url, username="admin", password="secret", kind="amt", machine=own_number(GUID)))
        try:
            await device.status()
            await asyncio.gather(*[task for task in (device._status_task,) if task is not None])
            device._kvm_at = float("-inf")  # (the next look reads how the KVM is set up, as every minute)
            access_point = asyncio.Event()
            watched(device, b"CIM_KVMRedirectionSAP transfer/Get", access_point)
            look = device._refresh_soon()
            await access_point.wait()
            await device.switch_kvm(on)
            await look
            return str(device._kvm.get("kvm")), bool(device._status and device._status.get("screen"))
        finally:
            await device.close()

    try:
        assert asyncio.run(run()) == (("enabled", True) if on else ("disabled", False))
    finally:
        pc.stop()


@pytest.mark.parametrize("which", ["another PC answered at the last look", "a look that reads what the PC is"])
def test_a_power_cut_while_a_look_reads_the_power_leaves_the_pc_off_on_its_tile(which: str) -> None:
    # (The sixth reviewer's probe.) The power cut is pressed while a look reads the PC's power. Where the look also asks which
    # PC answers, the power it read before the cut was noted after it: the tile said "On", and let a session to the screen be
    # opened to a PC that was off. Where it reads what the PC is, the tile said "On" until the next look.
    pc = FakeAmt(AmtState(sign_in_takes=0.2)).start()

    async def run() -> tuple[bool | None, str, str]:
        device = AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=pc.url, username="admin", password="secret", kind="amt", machine=own_number(GUID)))
        try:
            await device.status()
            await asyncio.gather(*[task for task in (device._status_task,) if task is not None])
            if which.startswith("another PC"):
                device._unsure = True  # (as a challenge in another realm leaves it: the look asks which PC answers too)
            else:
                device._about_at = float("-inf")
            power_read = asyncio.Event()
            watched(device, b"CIM_AssociatedPowerManagementService Enumerate", power_read)
            look = device._refresh_soon()
            await power_read.wait()
            await device.act("atx_power_long")
            await look
            await asyncio.gather(*[task for task in (device._status_task,) if task is not None])  # (and the look the command asked for)
            try:
                await device._screen_allowed()
                gate = "a session may be opened"
            except KvmError as ex:
                gate = ex.message
            return device._power_on, str((device._status or {}).get("state")), gate
        finally:
            await device.close()

    try:
        assert asyncio.run(run()) == (False, "no_signal", "The PC is off")
        assert pc.state.power == 8
    finally:
        pc.stop()


@pytest.mark.parametrize(
    ("when", "said"),
    [
        ("as its Put is out", "whether its redirection listener was is not known: this tile was being changed meanwhile"),
        ("as its Put is about to go", "its redirection listener was not: this tile was being changed meanwhile"),
        ("before its Put", "its redirection listener was not: this tile was being changed meanwhile"),
    ],
)
def test_a_kvm_switch_whose_tile_is_changed_in_its_second_half_says_what_is_known(when: str, said: str) -> None:
    pc = FakeAmt(AmtState(kvm="disabled", listener=False)).start()

    async def run() -> KvmError:
        device = AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=pc.url, username="admin", password="secret", kind="amt", machine=own_number(GUID)))
        try:
            await device.status()
            sent = device._send

            async def changed(client: httpx.AsyncClient, request: httpx.Request, limit: int, within: float | None = None) -> httpx.Response:
                if when == "as its Put is out" and b"transfer/Put" in request.content:
                    await sent(client, request, limit, within)
                    device._closed = True  # (the tile edited: its connection taken away while the answer was on its way)
                    raise kvm.RETIRED
                if when == "before its Put" and b"transfer/Get" in request.content and b"AMT_RedirectionService" in request.content:
                    device._closed = True
                    raise kvm.RETIRED
                return await sent(client, request, limit, within)

            device._send = changed  # type: ignore[method-assign]
            signed = device._signed

            def about_to_go(client: httpx.AsyncClient, envelope: bytes, challenge: Any, timeout: Any = None) -> httpx.Request:
                if when == "as its Put is about to go" and b"transfer/Put" in envelope:
                    device._closed = True  # (the tile edited: signed, and not yet sent; "not known" was said)
                return signed(client, envelope, challenge, timeout)

            device._signed = about_to_go  # type: ignore[method-assign]
            with pytest.raises(KvmError) as refused:
                await device.switch_kvm(True)
            return refused.value
        finally:
            await device.close()

    try:
        refused = asyncio.run(run())
        assert refused is not kvm.RETIRED and refused.message == f"Its KVM was switched on on the engine, and {said}", refused.message
        assert len(pc.state.changes) == (2 if when == "as its Put is out" else 1)
    finally:
        pc.stop()


def test_a_look_that_fails_after_a_command_does_not_say_the_pc_as_it_was_before_it(monkeypatch: pytest.MonkeyPatch) -> None:
    # (The seventh reviewer's probe.) A look that fails for a moment stands in with the last good one (HICCUP), but not where a
    # command went out since that look began: after a reset the tile said "On" as before it, where the engine says nothing
    # just now; it says what the failed look found instead.
    monkeypatch.setattr(amt, "HICCUP", 45.0)
    pc = FakeAmt().start()

    async def run() -> dict[str, Any]:
        device = AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=pc.url, username="admin", password="secret", kind="amt", machine=own_number(GUID)))
        try:
            assert (await device.status())["state"] == "online"
            await asyncio.gather(*[task for task in (device._status_task,) if task is not None])
            sent = device._send

            async def then_unwell(client: httpx.AsyncClient, request: httpx.Request, limit: int, within: float | None = None) -> httpx.Response:
                reply = await sent(client, request, limit, within)
                if b"RequestPowerStateChange" in request.content:
                    pc.state.odd = {"CIM_AssociatedPowerManagementService": "fault_other"}  # (the engine, busy while its PC restarts)
                return reply

            device._send = then_unwell  # type: ignore[method-assign]
            await device.act("atx_reset")
            await asyncio.gather(*[task for task in (device._status_task,) if task is not None])
            return dict(device._status or {})
        finally:
            await device.close()

    try:
        status = asyncio.run(run())
        assert status["state"] == "error" and "internal processing errors" in status["error"]["message"], status
        assert pc.state.actions == [amt.RESET]
    finally:
        pc.stop()


def test_a_failing_question_which_pc_answers_is_neither_the_tiles_failure_nor_the_redirection_ports(monkeypatch: pytest.MonkeyPatch) -> None:
    # Before a session to the screen, the question which PC answers times out (WS-Management's port, busy while the PC starts):
    # no session is opened, and that is counted neither against the redirection port (whose tile would say "Its redirection
    # port: ..." after three) nor as the tile's own failure (which would hold its looks back).
    monkeypatch.setattr(kvm, "TRANSFER_TIME", 1.0)
    monkeypatch.setattr(kvm, "WAITS", httpx.Timeout(1.0, connect=1.0))
    pc = FakeAmt().start()

    async def run() -> tuple[int, int, int]:
        device = AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=pc.url, username="admin", password="secret", kind="amt", machine=own_number(GUID)))
        try:
            assert (await device.status())["state"] == "online"
            pc.state.odd = {"CIM_ComputerSystemPackage": "slow"}
            for _ in range(3):
                with pytest.raises(KvmError):
                    await device._screen.ready(10.0)
            return device._screen._failures, device._failures, pc.state.redirections
        finally:
            await device.close()

    try:
        assert asyncio.run(run()) == (0, 0, 0)
    finally:
        pc.stop()


def test_a_file_whose_number_for_a_machine_is_none_leaves_that_device_out(tmp_path: Path) -> None:
    # What a tile checks before anything is sent to its machine: one that is no such number is not "none", which would have
    # the tile take whatever answers first. The device is left out, and the list of what was left out says why.
    file = json.dumps({"format": exchange.FORMAT, "version": 1, "devices": [
        {"url": "https://pc-1.invalid:16993", "kind": "amt", "machine": "amt:" + "ab" * 16},
        {"url": "https://pc-2.invalid:16993", "kind": "amt", "machine": "amt:not a number"},
        {"url": "https://pc-3.invalid:16993", "kind": "amt", "machine": 7},
    ]})  # fmt: skip
    with wall(tmp_path) as admin:
        taken = admin.post("/api/v1/import", json={"file": file, "passphrase": "", "take": ["devices"]})
        assert taken.status_code == 200 and taken.json()["devices"] == 1, taken.text
        assert [line for line in taken.json()["left_out"] if "the number its machine gave for itself is not one" in line] and len(taken.json()["left_out"]) == 2
        assert [record.machine for record in admin.core.store.devices] == ["amt:" + "ab" * 16]  # type: ignore[attr-defined]


def test_the_pc_a_tile_was_added_for_goes_with_it_into_an_export_file_also_beside_its_twin(tmp_path: Path) -> None:
    # A tile kept beside its twin (the same PC at another address) does not carry the PC's number as what it is (`ident`):
    # the file carries it all the same, and the wall it is taken to knows the PC by it, and no other.
    machines = [FakeAmt().start()]
    passphrase = "a passphrase of the tests"
    try:
        with wall(tmp_path / "one") as admin:
            add(admin, machines[0].url, name="Desk 7")
            twin = admin.post("/api/v1/devices", json={"url": machines[0].url.replace("127.0.0.1", "localhost"), "password": "secret", "name": "Desk 7 again", "keep_both": True})
            assert twin.status_code == 201, twin.text
            assert admin.core.store.device(twin.json()["device"]["id"]).ident.startswith("own:")  # type: ignore[attr-defined]
            made = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": passphrase, "parts": ["devices"]})
            assert made.status_code == 200, made.text
        # Another PC answers at the address by the time the file is taken in: a tile that remembered no PC would take it.
        machines.append(swap_in(machines[0], another_pc()))
        with wall(tmp_path / "two") as admin:
            taken = admin.post("/api/v1/import", json={"file": made.text, "passphrase": passphrase, "take": ["devices"]})
            assert taken.status_code == 200 and taken.json()["devices"] == 2, taken.text
            records = list(admin.core.store.devices)  # type: ignore[attr-defined]
            assert [record.machine for record in records] == [own_number(GUID)] * 2
            for record in records:
                refused = admin.post(f"/api/v1/devices/{record.id}/actions", json={"action": "atx_power_long"})
                assert (refused.status_code, refused.json().get("code")) == (502, "another_machine"), (record.name, refused.text)
            assert machines[-1].state.actions == []
    finally:
        machines[-1].stop()


def test_found_on_the_network_at_its_plain_address_only_where_nothing_listens_on_its_tls_port(tmp_path: Path, pc: FakeAmt, monkeypatch: pytest.MonkeyPatch) -> None:
    # As for an address typed without a port: where something on the TLS port is slow, or fails the TLS handshake, the PC is
    # listed at its TLS address (adding it says what is wrong there, and the plain way is the person's to type); where
    # something that is no engine answers there, it is not listed. Listed at its plain address, it was added that way, with
    # its port written out, and asked nothing more.
    from tests.fake_kvm import FakeKvm

    nowhere = "http://127.0.0.1:9"
    monkeypatch.setattr(discover, "targets", lambda: ([discover.Target("127.0.0.1", nowhere, nowhere, "desk")], ["test network"]))
    slow = socket.socket()
    slow.bind(("127.0.0.1", 0))
    slow.listen(16)  # (never accepted; room for the scan and for the bare connection that asks whether anything listens)
    other = FakeKvm(tls_dir=tmp_path / "other").start()
    try:
        with wall(tmp_path / "wall") as admin, tls_that_fails() as failing:
            for port, listed in ((failing, f"https://127.0.0.1:{failing}"), (slow.getsockname()[1], f"https://127.0.0.1:{slow.getsockname()[1]}"), (other.port, None), (closed_port(), pc.url)):
                monkeypatch.setattr(discover, "AMT_PORTS", (("https", port), ("http", pc.port)))
                found = [one["url"] for one in admin.post("/api/v1/discover").json()["found"] if one["kind"] == "amt"]
                assert found == ([listed] if listed else []), (port, found)
        assert pc.state.logins == 0
    finally:
        other.stop()
        slow.close()


def test_an_edit_takes_the_pc_that_answers_now_only_where_its_password_is_typed(tmp_path: Path) -> None:
    machines = [FakeAmt().start()]
    try:
        with wall(tmp_path) as client:
            device = add(client, machines[0].url, name="Desk 7")
            machines.append(swap_in(machines[0], another_pc()))
            other = machines[-1]
            # Saved again with nothing typed but a name: what answers is checked, and it is another PC.
            renamed = client.put(f"/api/v1/devices/{device}", json={"url": other.url, "name": "Desk 7, by the window"})
            assert (renamed.status_code, renamed.json().get("code")) == (422, "another_machine") and "type its password" in renamed.json()["message"]
            assert client.core.store.device(device).name == "Desk 7"  # type: ignore[attr-defined]
            # With the password typed: whoever types it says that this is the PC the tile is for now.
            taken = client.put(f"/api/v1/devices/{device}", json={"url": other.url, "name": "Desk 8", "password": "secret"})
            assert taken.status_code == 200, taken.text
            assert client.core.store.device(device).machine == own_number(OTHER_GUID)  # type: ignore[attr-defined]
            status_of(client, device, state="online")
            assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power_long"}).status_code == 200 and other.state.actions == [8]
    finally:
        machines[-1].stop()


def test_a_tile_that_remembers_no_pc_takes_the_first_it_sees_and_keeps_it(tmp_path: Path) -> None:
    # A tile saved before its PC's number was kept with it (as a settings file of a build before this one has it, a tile
    # added while its PC could not be reached, or one from a file that had none): the first look takes the number the PC
    # gives for itself, as a certificate is taken on first contact, and keeps it; another PC is told apart from then on.
    machines = [FakeAmt().start()]
    try:
        with wall(tmp_path) as client:
            device = add(client, machines[0].url)
        for name in ("qkvm.json", "qkvm.bak"):
            saved = json.loads(settings_text(tmp_path / name, encoding="utf-8"))
            assert saved["devices"][0]["machine"] == own_number(GUID), name
            del saved["devices"][0]["machine"]
            write_settings_text(tmp_path / name, json.dumps(saved, indent=2), encoding="utf-8")

        def kept() -> object:
            return json.loads(settings_text(tmp_path / "qkvm.json", encoding="utf-8"))["devices"][0].get("machine")

        with wall(tmp_path) as client:
            assert client.core.store.device(device).machine == ""  # type: ignore[attr-defined]
            status_of(client, device, state="online")
            wait_until(lambda: kept() == own_number(GUID), "the number the PC gives for itself was not kept")
            machines.append(swap_in(machines[0], another_pc()))
            refused = client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power_long"})
            assert (refused.status_code, refused.json().get("code")) == (502, "another_machine") and machines[-1].state.actions == []
    finally:
        machines[-1].stop()


# --- the few lines of the standard, by themselves ----------------------------------------------------------


def test_the_digest_answer_is_the_standards_own_example() -> None:
    # RFC 2617, section 3.5 (and RFC 7616, 3.9.1): the one worked example everybody checks against.
    challenge = Challenge(realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41", algorithm="MD5", qop=True, stale=False)
    header = answer_to(challenge, 1, "Mufasa", "Circle Of Life", "GET", "/dir/index.html", cnonce="0a4f113b")
    assert 'response="6629fae49393a05397450978507c4ef1"' in header
    assert header.startswith('Digest username="Mufasa", realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="/dir/index.html"')
    assert 'opaque="5ccc069c403ebaf9f0171e9517f40e41"' in header and "qop=auth, nc=00000001" in header


def test_a_challenge_is_read_as_the_standard_writes_it_and_refused_where_it_cannot_be_answered() -> None:
    read = challenge_from(['Basic realm="first"', 'Digest realm="Digest:ABCD1234", nonce="n1", stale=true, qop="auth,auth-int", opaque="o", algorithm=MD5'])
    assert read == Challenge("Digest:ABCD1234", "n1", "o", "MD5", True, True)
    assert challenge_from(['Digest realm="a \\"quoted\\" realm", nonce="n2"']) is None  # read as the standard writes it, and refused: it could not be sent back as it is
    assert challenge_from(['Digest realm="a realm with spaces", nonce="n2"']) == Challenge("a realm with spaces", "n2", None, "MD5", False, False)
    assert challenge_from(['Digest realm="r", nonce="n", algorithm=SHA-256']) == Challenge("r", "n", None, "SHA-256", False, False)
    assert challenge_from(['Digest realm="r", nonce="n", algorithm=sha-256-sess, qop=auth']) == Challenge("r", "n", None, "SHA-256-SESS", True, False)
    assert challenge_from(['Negotiate', 'Basic realm="x"']) is None
    assert challenge_from(['Digest nonce="n"']) is None  # no realm
    assert challenge_from(['Digest realm="r", nonce="n", qop="auth-int"']) is None  # a kind this program does not do
    assert challenge_from(['Digest realm="r", nonce="n", algorithm=SHA-512-256']) is None  # a hash it has not got
    assert challenge_from(['Digest realm="r\r\nX-Injected: 1", nonce="n"']) is None  # what could end the header line
    assert challenge_from([f'Digest realm="r", nonce="{"n" * 2000}"']) is None  # and what is far longer than a nonce
    assert challenge_from(["Digest realm=plain, nonce=bare"]) == Challenge("plain", "bare", None, "MD5", False, False)


def test_what_the_machine_says_is_taken_by_kind() -> None:
    import xml.etree.ElementTree as ET

    instance = ET.fromstring(
        '<g:CIM_Processor xmlns:g="x"><g:Family>205</g:Family><g:MaxClockSpeed>3400</g:MaxClockSpeed><g:Many>1</g:Many><g:Many>2</g:Many>'
        "<g:Deep><g:Inside>text</g:Inside></g:Deep><g:Blank></g:Blank><g:Odd>not a number</g:Odd><g:Big>99999999999999999999999</g:Big></g:CIM_Processor>"
    )
    fields = fields_of(instance)
    assert fields == {"Family": "205", "MaxClockSpeed": "3400", "Many": ["1", "2"], "Blank": "", "Odd": "not a number", "Big": "99999999999999999999999"}
    assert int_of(fields, "Family", 1, 65535) == 205 and int_of(fields, "Odd") is None and int_of(fields, "Big") is None and int_of(fields, "Many") is None
    assert family_of(fields) == "Intel Core i5, 3.4 GHz"
    assert family_of({"Family": "1", "OtherFamilyDescription": "Example Processor X", "MaxClockSpeed": "800"}) == "Example Processor X, 800 MHz"
    assert family_of({"Family": "999"}) == "processor family 999" and family_of({"Family": "0"}) is None
    assert own_number(GUID) == "amt:" + own_number(GUID)[4:] and own_number("0" * 32) is None and own_number("0") is None and own_number(None) is None
    assert own_number(GUID.lower()) == own_number(GUID)


def test_an_answer_written_another_way_is_refused_before_it_is_parsed() -> None:
    # The declarations that unfold to gigabytes are looked for as bytes: an answer in UTF-16 would carry them
    # past that look, and the parser reads UTF-16 by the first bytes. So nothing but what those bytes can be
    # looked for in is parsed at all.
    bomb = '<!DOCTYPE a [<!ENTITY x "xxxxxxxxxx"><!ENTITY y "&x;&x;&x;&x;&x;&x;&x;&x;&x;&x;">]>' + f'<s:Envelope xmlns:s="{amt.SOAP}"><s:Body>&y;</s:Body></s:Envelope>'
    request = httpx.Request("POST", "http://127.0.0.1/wsman")
    for data in (bomb.encode("utf-16"), bomb.encode("utf-16-le"), bomb.encode("utf-16-be"), b"\xef\xbb\xbf" + bomb.encode(), ("<!--" + " " * 5000 + "-->" + bomb).encode()):
        reply = httpx.Response(200, headers={"Content-Type": "application/soap+xml"}, content=data, request=request)
        with pytest.raises(KvmError) as refused:
            body_of(reply)
        assert refused.value.code == "bad_response", data[:8]
    # (A plain answer with a byte order mark is read as the parser reads it.)
    fine = b"\xef\xbb\xbf" + f'<s:Envelope xmlns:s="{amt.SOAP}"><s:Body><a/></s:Body></s:Envelope>'.encode()
    assert len(body_of(httpx.Response(200, headers={"Content-Type": "application/soap+xml"}, content=fine, request=request))) == 1


def test_a_faults_words_are_one_printable_line() -> None:
    request = httpx.Request("POST", "http://127.0.0.1/wsman")
    fault = (
        f'<s:Envelope xmlns:s="{amt.SOAP}"><s:Body><s:Fault><s:Code><s:Value>s:Sender</s:Value><s:Subcode><s:Value>x:AccessDenied\n2026-10-14 FORGED login ok\x85tail</s:Value></s:Subcode></s:Code>'
        "<s:Reason><s:Text></s:Text></s:Reason></s:Fault></s:Body></s:Envelope>"
    )
    with pytest.raises(KvmError) as refused:
        body_of(httpx.Response(400, headers={"Content-Type": "application/soap+xml"}, content=fault.encode(), request=request))
    assert "\n" not in refused.value.message and "\x85" not in refused.value.message and refused.value.message.startswith("The machine answered: AccessDenied 2026-10-14 FORGED")


def test_an_answer_nested_thousands_deep_is_read_or_refused_without_a_crash() -> None:
    deep = 20000
    xml = f'<s:Envelope xmlns:s="{amt.SOAP}"><s:Body>' + "<a>" * deep + "</a>" * deep + "</s:Body></s:Envelope>"
    reply = httpx.Response(200, headers={"Content-Type": "application/soap+xml"}, content=xml.encode(), request=httpx.Request("POST", "http://127.0.0.1/wsman"))
    body = body_of(reply)
    assert fields_of(body) == {}  # (a record inside a record is not a text, and is "not said")
    for wrong in (b"<html>", b"<s:Envelope xmlns:s='x'><s:Body/></s:Envelope>", b"", b"\xff\xfe"):
        reply = httpx.Response(200, headers={"Content-Type": "application/soap+xml"}, content=wrong, request=httpx.Request("POST", "http://127.0.0.1/wsman"))
        with pytest.raises(KvmError) as refused:
            body_of(reply)
        assert refused.value.code == "bad_response"


def test_the_family_tests_of_every_driver_include_this_one() -> None:
    # The pacing of a rejected password is tested for every driver in one place; this one is among them.
    from tests.test_a_password_a_device_rejects_again_and_again import KINDS

    assert "an Intel AMT PC" in KINDS
    assert SCALE and TICK  # (used there)
    assert "amt" in exchange.KINDS
