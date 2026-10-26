"""Type text on a VNC server, and on the PCs with Intel AMT and the Proxmox guests whose screens are typed into the same
way (the review of 850745e, L-W3).

A character a VNC server cannot be sent was named in the answer (`'\\x07' cannot be typed on a VNC server`), and the
answer goes into the activity log: a piece of a typed text, which may be a saved password, was written down. It is told
by its place now, as a server's console and a JetKVM already tell it. And whether whoever asked may still have it done
was asked once, before up to 2000 characters were typed: now before every piece that goes out.
"""
from __future__ import annotations

import asyncio

import pytest

from qkvm import vncdevice
from qkvm.kvm import DeviceSpec, KvmError
from qkvm.vncdevice import VncDevice


def test_a_character_that_cannot_be_sent_is_told_by_its_place_and_not_by_itself() -> None:
    with pytest.raises(KvmError) as said:
        vncdevice.text_events("pa55\x07word")
    message = said.value.message
    assert "Character 5 of the text" in message
    assert "\x07" not in message and "\\x07" not in message and "pa55" not in message and "word" not in message


def test_typing_stops_between_pieces_once_whoever_asked_may_no_longer(monkeypatch: pytest.MonkeyPatch) -> None:
    device = VncDevice(DeviceSpec(id="v1", name="box", base_url="vnc://127.0.0.1:5900", username="", password="secret", kind="vnc"))
    sent: list[int] = []
    allowed = [True]

    class Client:
        async def keys(self, events: list[tuple[int, bool]]) -> None:
            sent.append(len(events))
            allowed[0] = False  # (signed out, or no longer an operator, while the first piece went out)

    monkeypatch.setattr(device, "_connected", lambda urgent=False: Client())

    async def run() -> None:
        with pytest.raises(KvmError) as said:
            await device.act("text", text="x" * 200, still=lambda: allowed[0])
        assert said.value.code == "stopped"

    try:
        asyncio.run(run())
    finally:
        asyncio.run(device.close())
    assert sent == [vncdevice.KEYS_AT_ONCE]  # (the first piece only: 200 characters are 400 events, 13 pieces)
