"""A JetKVM press that never went out is said to be not done, not "may have been done".

Every key, text and press goes to a JetKVM over its video connection. Where none is to be had (its WebRTC never connects, it
is taking too long, the channel it is asked over closed a moment before), nothing was sent: answered with "timeout" (504) or
"dropped", the page said "No answer. It may have been done", left it out of "Retry failed", and the history kept a power press
as unknown (the review's probe devices/jetkvm/probe_press_without_connection.py). Only a press that went out and had no answer
may have been done.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

import pytest

from qkvm import jetkvm, kvm, update, vault
from qkvm.kvm import DeviceSpec, KvmError
from tests.fake_jetkvm import FakeJetKvm, JetState
from tests.test_wall import add, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(jetkvm, "CONNECT_TIMEOUT", 1.0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.mark.parametrize("action", ["atx_power", "atx_power_long", "reboot", "keys", "text", "wol", "jiggler_on"])
def test_a_press_on_a_jetkvm_whose_video_connection_never_comes_about_is_not_done(action: str) -> None:
    state = JetState(extension="atx-power", answers_offers=False)
    jet = FakeJetKvm(state).start()

    async def run() -> KvmError:
        device = jetkvm.JetKvmDevice(DeviceSpec("j9", "jet", jet.url, "", "secret", kind="jetkvm"))
        try:
            with pytest.raises(KvmError) as refused:
                await device.act(action, keys="Enter", text="ok", mac="AA:BB:CC:DD:EE:FF")
            return refused.value
        finally:
            await device.close()

    try:
        said = asyncio.run(run())
        assert said.code == "action_failed" and said.status == 502, (said.code, said.status, said.message)
        assert said.message.startswith("Nothing was typed" if action == "text" else "It was not done"), said.message
        assert state.actions == [] and state.typed == []
    finally:
        jet.stop()


@pytest.mark.parametrize("action", ["atx_power", "reboot", "wol", "jiggler_on"])
def test_a_press_whose_call_could_not_go_out_is_not_done(monkeypatch: pytest.MonkeyPatch, action: str) -> None:
    # The connection is there, and the call that presses cannot be sent (the channel it is asked over closed in that moment):
    # "dropped", which `_call` says only of a call that did not go out. (A restart was even said to be done then.)
    monkeypatch.setattr(jetkvm, "CONNECT_TIMEOUT", 15.0)  # (it comes about here: given the wall's own time for it)
    state = JetState(extension="atx-power")
    jet = FakeJetKvm(state).start()
    pressing = {"atx_power": "setATXPowerAction", "reboot": "reboot", "wol": "sendWOLMagicPacket", "jiggler_on": "setJigglerState"}[action]
    real = jetkvm.JetKvmDevice._call

    async def call(self: Any, session: Any, method: str, params: Any = None, within: Any = None) -> Any:
        if method == pressing:
            raise KvmError("dropped", "The JetKVM closed the channel it is asked over")
        return await real(self, session, method, params, within)

    monkeypatch.setattr(jetkvm.JetKvmDevice, "_call", call)

    async def run() -> KvmError:
        device = jetkvm.JetKvmDevice(DeviceSpec("j9", "jet", jet.url, "", "secret", kind="jetkvm"))
        try:
            await device._connected(urgent=True)
            with pytest.raises(KvmError) as refused:
                await device.act(action, mac="AA:BB:CC:DD:EE:FF")
            return refused.value
        finally:
            await device.close()

    try:
        said = asyncio.run(run())
        assert (said.code, said.status) == ("action_failed", 502) and said.message.startswith("It was not done"), (said.code, said.message)
        assert state.actions == []
    finally:
        jet.stop()


def test_the_history_keeps_a_power_press_that_never_went_out_as_not_pressed(tmp_path: Path) -> None:
    state = JetState(extension="atx-power")
    jet = FakeJetKvm(state).start()
    try:
        with wall(tmp_path / "wall") as client:
            device = add(client, jet.url)
            state.answers_offers = False
            reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power"})
            assert (reply.status_code, reply.json()["code"]) == (502, "action_failed"), reply.text
            assert reply.json()["message"].startswith("It was not done")
            deadline = time.monotonic() + 10
            while True:
                rows = client.get(f"/api/v1/devices/{device}/history", params={"what": "events"}).json()["rows"]
                pressed = [(row["kind"], row["what"], row["ok"], row["note"]) for row in rows if row["kind"] == "pressed"]
                if pressed or time.monotonic() > deadline:
                    break
                time.sleep(0.1)
            assert pressed == [("pressed", "atx_power", False, "action_failed")], rows  # (not pressed; None: may have been)
            assert state.actions == []
    finally:
        jet.stop()


def test_a_text_whose_connection_ended_while_it_waited_its_turn_was_not_typed_and_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    # (The second review.) Over JSON-RPC, an action that waits for its turn to type (another typing, keys of the live view on
    # their way) and whose connection ends meanwhile: its first key's call was refused as the connection was no longer up, and
    # said "dropped", which the page shows as "may have been done", of a text nothing of which went. Said as the hidrpc road
    # says it: not done.
    monkeypatch.setattr(jetkvm, "CONNECT_TIMEOUT", 15.0)
    monkeypatch.setattr(jetkvm, "HID_SHAKE_WITHIN", 0.3)  # (an older JetKVM, without hidrpc: keys over JSON-RPC)
    state = JetState(hidrpc=False)
    jet = FakeJetKvm(state).start()

    async def run() -> KvmError:
        device = jetkvm.JetKvmDevice(DeviceSpec("j9", "jet", jet.url, "", "secret", kind="jetkvm"))
        try:
            held = await device.input_ready()
            assert held.road == "rpc"
            async with device._typing:  # (another action types meanwhile)
                typing = asyncio.ensure_future(device.act("text", text="ab"))
                await asyncio.sleep(0.5)
                jet.drop()
                deadline = time.monotonic() + 10
                while held.live and time.monotonic() < deadline:
                    await asyncio.sleep(0.05)
                assert not held.live
            with pytest.raises(KvmError) as refused:
                await typing
            return refused.value
        finally:
            await device.close()

    try:
        said = asyncio.run(run())
        assert (said.code, said.status) == ("action_failed", 502) and said.message.startswith("It was not done"), (said.code, said.message)
        assert state.typed == []
    finally:
        jet.stop()


def test_a_text_over_json_rpc_stops_at_the_next_key_where_the_wall_begins_to_close(monkeypatch: pytest.MonkeyPatch) -> None:
    # (Register row 15, from W14d's third review.) The hidrpc road stops typing at the next key once the tile is being closed
    # (edited, removed, the wall locking itself); over JSON-RPC the text went on, key after key, while the close let go and
    # waited, until the connection was gone under it, and said "dropped" between two keys. It stops at the next key now, and
    # says after how many.
    monkeypatch.setattr(jetkvm, "CONNECT_TIMEOUT", 15.0)
    monkeypatch.setattr(jetkvm, "HID_SHAKE_WITHIN", 0.3)  # (an older JetKVM, without hidrpc: keys over JSON-RPC)
    monkeypatch.setattr(jetkvm, "KEY_PAUSE", 0.05)
    state = JetState(hidrpc=False)
    jet = FakeJetKvm(state).start()

    async def run() -> tuple[KvmError, int]:
        device = jetkvm.JetKvmDevice(DeviceSpec("j9", "jet", jet.url, "", "secret", kind="jetkvm"))
        held = await device.input_ready()
        assert held.road == "rpc"
        typing = asyncio.ensure_future(device.act("text", text="abcdefghijklmnopqrstuvwxyz" * 4))
        while len(state.typed) < 3:
            await asyncio.sleep(0.01)
        closing = asyncio.ensure_future(device.close())
        with pytest.raises(KvmError) as stopped:
            await typing
        typed_by_then = len(state.typed)
        await closing
        await asyncio.sleep(0.3)
        assert len(state.typed) == typed_by_then  # (nothing more went after it stopped)
        return stopped.value, typed_by_then

    try:
        said, typed = asyncio.run(run())
        assert (said.code, said.status) == ("action_failed", 502), (said.code, said.message)
        assert said.message.startswith("Typing was stopped after") and "edited or removed" in said.message, said.message
        assert typed < 10 and state.down == [] and state.modifier == 0
    finally:
        jet.stop()
