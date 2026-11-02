"""A message on a JetKVM's data channel larger than any a JetKVM sends is not read, and ends the connection.

The WebRTC library hands the wall a data channel message of any size, past the 64 KiB the wall says it takes
(a=max-message-size): the review's probe had one of 32 MiB delivered, and parsed on the event loop, its contents kept as the
video's state. What a JetKVM says there is a few hundred bytes (its answers, and events such as videoInputState), its list of
machines saved for Wake-on-LAN a few kilobytes: the stand-in says what the real one does (tests/fake_jetkvm.py).
"""

from __future__ import annotations

import asyncio
import json
import time

import pytest

from qkvm import jetkvm, kvm, vault
from qkvm.kvm import DeviceSpec
from tests.fake_jetkvm import FakeJetKvm


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)


def event(**params: object) -> str:
    return json.dumps({"jsonrpc": "2.0", "method": "videoInputState", "params": {"ready": True, "width": 640, "height": 360, "fps": 60, **params}})


async def until(happened: object, seconds: float = 10.0) -> bool:
    deadline = time.monotonic() + seconds
    while not happened():  # type: ignore[operator]
        if time.monotonic() > deadline:
            return False
        await asyncio.sleep(0.02)
    return True


def test_a_message_larger_than_any_a_jetkvm_sends_is_not_read_and_ends_the_connection() -> None:
    jet = FakeJetKvm().start()

    async def run() -> None:
        device = jetkvm.JetKvmDevice(DeviceSpec("j", "jet", jet.url, "", "secret", kind="jetkvm"))
        try:
            session = await device._connected(urgent=True)
            assert (await device._read_status())["state"] == "online"
            # One the size of a long list of machines saved for Wake-on-LAN, and more: read, as ever.
            jet.say_on_rpc(event(note="x" * 30_000))
            assert await until(lambda: len(str(session.video.get("note", ""))) == 30_000), "a message of 30 kB was not read"
            assert session.live
            # A megabyte: not read, and the connection is ended.
            jet.say_on_rpc(event(note="y" * 1_000_000))
            assert await until(lambda: session.lost is not None or session.done.is_set()), "the connection went on"
            assert session.lost is not None and session.lost.code == "bad_response" and "KiB" in session.lost.message, session.lost
            assert "y" not in str(session.video.get("note", ""))[:1]
            await asyncio.wait_for(session.done.wait(), 10)
            # The next look makes a new connection, over which it answers again.
            deadline = time.monotonic() + 20
            while (await device._read_status())["state"] != "online":
                assert time.monotonic() < deadline, "no new connection was made"
                await asyncio.sleep(0.2)
            assert device._session is not session
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        jet.stop()


def test_a_message_larger_than_any_is_not_parsed_whatever_it_holds() -> None:
    # (Handed to the driver as the channel hands it: text or bytes. Neither is read: what would be read is not looked at.)
    device = jetkvm.JetKvmDevice(DeviceSpec("j", "jet", "http://127.0.0.1:9", "", "", kind="jetkvm"))
    for message in (event(note="z" * 2_000_000), b"\x00" * 2_000_000, "[" * 2_000_000):
        session = jetkvm._Session()
        session.ready.set()
        device._on_message(session, message)
        assert session.lost is not None and session.lost.code == "bad_response", type(message)
        assert session.video == {} and not session.live
