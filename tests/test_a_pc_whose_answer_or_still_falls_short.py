"""A PC with Intel AMT: a command whose answer cannot be read, a still that gives up on its session, and a Start into BIOS
setup that runs out of time. From the final review of 0.2.0.

A power command answered without its ReturnValue, or with something that is not SOAP, after it went out was "failed" (502),
kept as failed, and offered for "Retry failed": a reset pressed twice. A still that gave up waiting for its session left the
session it began to open, and held, for a minute, Intel's border on the PC's own screen. And Start into BIOS setup had no
deadline over AMT, where Redfish's has two minutes.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest

from qkvm import amt, kvm, update, vault
from qkvm.kvm import DeviceSpec, KvmError
from tests.fake_amt import AmtState, FakeAmt
from tests.test_redfish import status_of
from tests.test_wall import add, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(amt, "LOOK_EVERY", 0)
    monkeypatch.setattr(amt, "FOLLOW_UP", ())
    monkeypatch.setattr(amt, "HICCUP", 0)
    monkeypatch.setattr(amt, "CONFIRM_EVERY", 0.05)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def pressed(client: object, device: str, action: str) -> tuple[int, str, str]:
    reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": action})  # type: ignore[attr-defined]
    said = reply.json()
    return reply.status_code, str(said.get("code")), str(said.get("message"))


# --- F4: an answer that cannot be read is "perhaps done" -------------------------------------------------------------


def test_a_reset_whose_answer_says_neither_yes_nor_no_may_have_been_done(tmp_path: Path) -> None:
    pc = FakeAmt(AmtState(power_answer_empty=True)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, pc.url)
            status_of(client, device, state="online")
            status, code, message = pressed(client, device, "atx_reset")
            assert (status, code) == (504, "timeout") and "may have been done" in message, message
            assert pc.state.actions == [10]  # (taken by the engine)
    finally:
        pc.stop()


def test_a_power_command_answered_with_what_is_not_soap_may_have_been_done_and_the_pc_is_not_said_to_be_down(tmp_path: Path) -> None:
    pc = FakeAmt().start()
    try:
        with wall(tmp_path) as client:
            device = add(client, pc.url)
            status_of(client, device, state="online")
            pc.state.odd["CIM_PowerManagementService"] = "html"
            status, code, message = pressed(client, device, "atx_power_long")
            assert (status, code) == (504, "timeout") and "could not be read" in message, message
            del pc.state.odd["CIM_PowerManagementService"]
            assert status_of(client, device, state="online")["error"] is None  # (it answered: not taken for an engine that is down)
    finally:
        pc.stop()


@pytest.mark.parametrize("how", ["refused_page", "fault"])
def test_a_power_command_the_engine_refuses_is_a_no(tmp_path: Path, how: str) -> None:
    # (What stays a refusal: a SOAP fault, or an answer of the 4xx kind.)
    pc = FakeAmt().start()
    try:
        with wall(tmp_path) as client:
            device = add(client, pc.url)
            status_of(client, device, state="online")
            pc.state.odd["CIM_PowerManagementService"] = how
            status, code, _ = pressed(client, device, "atx_power_long")
            assert status == 502 and code != "timeout"
    finally:
        pc.stop()


# --- F6: a still that gives up on its session closes what it began ----------------------------------------------------


def run_a_still_that_gives_up(pc: FakeAmt, watch_for: float) -> tuple[float, float, int, bool]:
    """A shown tile's first look begins a still, which gives up on its session: (when the still ended, when the engine last
    had a redirection connection open within `watch_for` after it, the stills that failed, whether the session the still
    began was over on the wall's side the moment the still was)."""

    async def run() -> tuple[float, float, int, bool]:
        device = amt.AmtDevice(DeviceSpec(id="ab12", name="PC", base_url=pc.url, username="admin", password="secret", kind="amt"))
        try:
            await device.status()
            with pytest.raises(KvmError):
                await device.snapshot(640)  # (a shown tile's first look: a still is begun in the background)
            taking = device._screen._taking
            assert taking is not None
            await asyncio.wait({taking}, timeout=10)
            ended = last_open = time.monotonic()
            session = device._screen._task
            over = session is None or session.done()
            while time.monotonic() < ended + watch_for:
                if pc.state.redirection_open:
                    last_open = time.monotonic()
                await asyncio.sleep(0.02)
            return ended, last_open, device._screen._still_fails, over
        finally:
            await device.close()

    return asyncio.run(run())


def test_a_still_that_gives_up_on_its_session_stops_it(monkeypatch: pytest.MonkeyPatch) -> None:
    # Scaled: the still waits 0.5 s; the engine's RFB greeting comes 1.0 s after Intel's handshake (a slow engine, inside the
    # handshake's own time). The session the still began is stopped as the still gives up (its sign-in was taken already),
    # not held for LET_GO_AFTER after it.
    monkeypatch.setattr(amt.AmtScreen, "STILL_WAIT", 0.5)
    monkeypatch.setattr(amt.AmtScreen, "LET_GO_AFTER", 4.0)
    monkeypatch.setattr(amt.AmtScreen, "LOOK_PACE", 0.05)
    pc = FakeAmt().start()
    try:
        pc.state.screen.stall = 1.0
        ended, last_open, fails, over = run_a_still_that_gives_up(pc, 3.0)
        assert fails == 1 and over  # (stopped by the still as it gave up: the wall's side is closed at once)
        # (The engine notices the closed connection when its stall is over: within a second, never the four of LET_GO_AFTER.)
        assert last_open - ended < 1.5, f"the session the still began was held {last_open - ended:.1f} s after it gave up"
    finally:
        pc.stop()


def test_a_still_that_gives_up_while_its_sign_in_is_on_its_way_lets_the_session_go_once_it_is_open(monkeypatch: pytest.MonkeyPatch) -> None:
    # The password went out and its answer takes its time: the session is not cut off there (that would leave the password held
    # back, and the try uncounted). It is let go of the moment it is open, not LET_GO_AFTER later.
    monkeypatch.setattr(amt.AmtScreen, "STILL_WAIT", 0.5)
    monkeypatch.setattr(amt.AmtScreen, "LET_GO_AFTER", 4.0)
    monkeypatch.setattr(amt.AmtScreen, "LOOK_PACE", 0.05)
    pc = FakeAmt(AmtState(answer_takes=1.0)).start()
    try:
        ended, last_open, _, over = run_a_still_that_gives_up(pc, 3.5)
        assert not over  # (not cut off while its sign-in was on its way)
        assert pc.state.redirection_logins == 1 and pc.state.redirection_rejections == 0
        assert last_open - ended < 2.0, f"the session the still began was held {last_open - ended:.1f} s after it gave up"
        spec = DeviceSpec(id="ab12", name="PC", base_url=pc.url, username="admin", password="secret", kind="amt")
        assert kvm.REJECTED.wait_left(kvm.REJECTED.what("login", spec)) <= 0  # (the sign-in was answered, and nothing is held back)
    finally:
        pc.stop()


# --- F7: Start into BIOS setup has a deadline over AMT too --------------------------------------------------------------


def test_a_bios_setup_that_runs_out_of_time_sends_nothing_more_and_clears_what_it_armed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(amt, "SETUP_WITHIN", 1.0)
    pc = FakeAmt(AmtState(boot_put_takes=1.5)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, pc.url)
            status_of(client, device, state="online")
            status, code, message = pressed(client, device, "bios_setup")
            assert (status, code) == (502, "action_failed") and "took more than" in message and "cleared again" in message, message
            assert pc.state.actions == [] and pc.state.boot_role_set == 0 and pc.state.bios_setup_armed is False
            assert [v for c, v in pc.state.changes if c == "AMT_BootSettingData"] == ["BIOSSetup=true", "BIOSSetup=false"]
    finally:
        pc.stop()
