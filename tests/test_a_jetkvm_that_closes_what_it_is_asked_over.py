"""A JetKVM that closes the channel it is asked over, and goes on sending its picture.

Its picture comes over one part of the connection and it is asked (how it is, to press a key) over another.
The second can be closed by the device while the first carries on. Found by an outside reviewer, with the
real WebRTC library on both sides.
"""

from __future__ import annotations

import asyncio
import base64
import json
import random
import time
from pathlib import Path
from typing import Any

import pytest
from aiortc import RTCDataChannel

from qkvm import jetkvm, kvm, update, vault
from qkvm.kvm import DeviceSpec, KvmError
from tests.fake_jetkvm import FakeJetKvm
from tests.test_wall import add, snap, wait_until, wall
from tests.conftest import TICK


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def closes_once(monkeypatch: pytest.MonkeyPatch) -> list[RTCDataChannel]:
    """The stand-in closes the channel it is asked over, half a second after it has said how its USB is: the
    first time only. What it closed is in the list."""
    real = RTCDataChannel.send
    closed: list[RTCDataChannel] = []

    def send(channel: RTCDataChannel, data: Any) -> None:
        real(channel, data)
        if isinstance(data, str) and '"usbState"' in data and not closed:
            closed.append(channel)
            asyncio.get_running_loop().call_later(0.5, channel.close)

    monkeypatch.setattr(RTCDataChannel, "send", send)
    return closed


def test_what_it_was_asked_does_not_wait_for_ever_and_it_is_not_called_online(closes_once: list[RTCDataChannel]) -> None:
    # Each question was noted as waiting for its answer, then sent; the sending failed, in the library's own
    # words, and the note stayed for good: three more at every look at the device. None of the three was an
    # error the driver knew, so the device was "online", with a picture, and nobody to ask.
    fake = FakeJetKvm().start()

    async def check() -> None:
        device = jetkvm.JetKvmDevice(DeviceSpec("jet", "A JetKVM", fake.url, "", "secret", kind="jetkvm"))
        try:
            await device.identify()
            session = await device._connected(urgent=True)
            until = time.monotonic() + 10
            while session.rpc.readyState != "closed" and time.monotonic() < until:
                await asyncio.sleep(0.05)
            assert session.rpc.readyState == "closed" and session.pc.connectionState == "connected"  # the picture's part is still there
            await asyncio.sleep(0.3)
            assert session.lost is not None and session.lost.code == "dropped"  # noticed by itself, before anybody asks
            # Asked over what is closed: an error of the device's, each time, and nothing left waiting.
            for _ in range(5):
                with pytest.raises(KvmError) as refused:
                    await device._call(session, "getUSBState")
                assert refused.value.code == "dropped"
            assert session.pending == {}
            assert not session.live
            # The connection is ended like one that went quiet...
            await asyncio.wait_for(session.done.wait(), 10)
            # ...and the next look makes a new one, over which it answers again.
            states = []
            until = time.monotonic() + 20
            while time.monotonic() < until:
                states.append((await device._read_status())["state"])
                if states[-1] == "online":
                    break
                await asyncio.sleep(0.3)
            assert states[-1] == "online", states
            again = await device._connected(urgent=True)
            assert again is not session and again.rpc.readyState == "open"
            await device.act("keys", keys="Enter")
            assert fake.state.typed[-1] == (0, [40])
        finally:
            await device.close()

    try:
        asyncio.run(check())
    finally:
        fake.stop()


def test_a_question_that_cannot_be_sent_is_the_devices_fault_and_is_not_left_waiting() -> None:
    # (Asked in the moment between the channel closing and the driver hearing of it: the library refuses to
    # send, in words of its own. That is the device having dropped out, and the question waits for nothing.)
    from aiortc.exceptions import InvalidStateError

    class Closed:
        readyState = "closed"

        def send(self, data: str) -> None:
            raise InvalidStateError

    async def check() -> None:
        device = jetkvm.JetKvmDevice(DeviceSpec("jet", "A JetKVM", "http://127.0.0.1:18901", "", "", kind="jetkvm"))
        session = jetkvm._Session()
        session.rpc = Closed()
        session.ready.set()
        assert session.live
        for _ in range(3):
            with pytest.raises(KvmError) as refused:
                await device._call(session, "getUSBState")
            assert refused.value.code == "dropped"
        assert session.pending == {} and session.lost is not None and not session.live

    asyncio.run(check())


def test_a_key_pressed_meanwhile_is_answered_as_the_devices_fault_and_works_again_after(tmp_path: Path, closes_once: list[RTCDataChannel]) -> None:
    # On the page: Enter pressed on such a JetKVM was "something went wrong inside QKVM" (500), with its picture
    # still coming. It is the device that dropped out, and is said so; a moment later the key goes through.
    fake = FakeJetKvm().start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url, kind="jetkvm")
            wait_until(lambda: admin.get(snap(device)).status_code == 200, "no picture came from the JetKVM", timeout=30)
            wait_until(lambda: bool(closes_once) and closes_once[0].readyState == "closed", "the channel was never closed", timeout=15)
            answers = []
            until = time.monotonic() + 30
            while time.monotonic() < until:
                reply = admin.post(f"/api/v1/devices/{device}/actions", json={"action": "keys", "keys": "Enter"})
                answers.append(reply.status_code)
                assert reply.status_code != 500, reply.text
                if reply.status_code == 200:
                    break
                assert reply.json()["code"] in ("dropped", "timeout", "busy", "no_stream", "unreachable"), reply.text
                time.sleep(0.4)
            assert answers[-1] == 200, answers
            assert fake.state.typed[-1] == (0, [40])
            assert admin.get("/healthz").status_code == 200
    finally:
        fake.stop()


# --- found when these were read by somebody else --------------------------------------------------------------


@pytest.fixture
def channels(monkeypatch: pytest.MonkeyPatch) -> list[tuple[RTCDataChannel, asyncio.AbstractEventLoop]]:
    """The stand-in's ends of the channels it is asked over, each with the loop it lives in (to close it from here)."""
    real = RTCDataChannel.send
    made: list[tuple[RTCDataChannel, asyncio.AbstractEventLoop]] = []

    def send(channel: RTCDataChannel, data: Any) -> None:
        real(channel, data)
        if isinstance(data, str) and '"usbState"' in data and '"method"' in data:
            made.append((channel, asyncio.get_running_loop()))

    monkeypatch.setattr(RTCDataChannel, "send", send)
    return made


def test_what_is_asked_in_the_moment_after_it_closed_is_the_devices_fault_and_not_a_wait(channels: list[tuple[RTCDataChannel, asyncio.AbstractEventLoop]]) -> None:
    # Between the channel closing and the connection being ended (up to a second), a key pressed was
    # answered at once with "taking too long to connect", which is what is said after ten seconds of
    # waiting: the page shows that as "No answer. It may have been done", and leaves it out of what can be
    # tried again. Nothing had been sent. It is the device that dropped out, and is said so.
    fake = FakeJetKvm().start()

    async def check() -> None:
        device = jetkvm.JetKvmDevice(DeviceSpec("jet", "A JetKVM", fake.url, "", "secret", kind="jetkvm"))
        try:
            for _ in range(5):  # (the moment is up to a second long; where it was over before it was seen, once more)
                session = await device._connected(urgent=True)
                assert (await device._read_status())["state"] == "online"
                channel, loop = channels[-1]
                loop.call_soon_threadsafe(channel.close)
                until = time.monotonic() + 5
                while session.lost is None and not session.done.is_set() and time.monotonic() < until:
                    await asyncio.sleep(0.002)
                if session.lost is not None and not session.done.is_set():
                    break
                await asyncio.wait_for(session.done.wait(), 10)
            else:
                raise AssertionError("the moment between the closing and the end of the connection was never met")
            began = time.monotonic()
            with pytest.raises(KvmError) as refused:
                await device.act("keys", keys="Enter")
            assert time.monotonic() - began < 2  # answered at once: nobody waited ten seconds for this
            assert (refused.value.code, refused.value.status) == ("dropped", 502), (refused.value.code, refused.value.status, refused.value.message)
            assert fake.state.typed == []
        finally:
            await device.close()

    try:
        asyncio.run(check())
    finally:
        fake.stop()


def test_one_that_ends_every_connection_at_once_is_tried_less_and_less_often(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    # It lets a video connection be arranged, and closes the channel it is asked over in the moment that
    # opens: never one answer. Having let the connection be arranged counted as "reachable again", every
    # time, so the count of failures in a row began anew with each attempt: a new connection every 2.6
    # seconds for as long as somebody looked at the wall, with two lines in the log for each.
    real = RTCDataChannel.send
    closed: set[int] = set()

    def send(channel: RTCDataChannel, data: Any) -> None:
        if isinstance(data, str) and '"localVersion"' in data and '"method"' in data:
            closed.add(id(channel))
            channel.close()  # in the moment it is opened, before a word is said over it
            return
        if id(channel) not in closed:
            real(channel, data)

    monkeypatch.setattr(RTCDataChannel, "send", send)
    fake = FakeJetKvm().start()
    seen: dict[str, Any] = {}

    async def check() -> None:
        device = jetkvm.JetKvmDevice(DeviceSpec("jet", "A JetKVM", fake.url, "", "secret", kind="jetkvm"))
        began = time.monotonic()
        try:
            while time.monotonic() - began < 16:
                await device.status()
                try:
                    await device.snapshot(640)
                except KvmError:
                    pass
                await asyncio.sleep(0.25)
            seen["failures"], seen["connections"] = device._failures, fake.state.sessions
        finally:
            await device.close()

    import logging

    with caplog.at_level(logging.INFO, logger="qkvm"):
        try:
            asyncio.run(check())
        finally:
            fake.stop()
    again = [record.getMessage() for record in caplog.records if "reachable again" in record.getMessage()]
    assert seen["failures"] >= 3, seen  # counted in a row, since it never answered anything
    assert 2 <= seen["connections"] <= 6, seen  # (at a steady 2.6 s it was seven and more in this time)
    assert again == [], again  # and it is not called reachable for having let itself be connected to


@pytest.mark.parametrize("says", ["inf", "1e308", "999999999", "nan", "-5", "soon", "", "120"])
def test_one_that_refuses_logins_says_for_how_long_and_is_believed_up_to_an_hour(says: str) -> None:
    # After too many wrong passwords a JetKVM refuses logins for a while, and says for how long. "inf"
    # there was taken as it stood: the tile said that logins are refused, for good, until its settings
    # were opened and saved again.
    fake = FakeJetKvm().start()
    fake.state.locked_for = says

    async def check() -> None:
        device = jetkvm.JetKvmDevice(DeviceSpec("jet", "A JetKVM", fake.url, "", "secret", kind="jetkvm"))
        try:
            with pytest.raises(KvmError) as refused:
                await device._login()
            assert refused.value.code == "auth_failed"
            wait = device._login_retry_at - time.monotonic()
            assert kvm.LOGIN_BACKOFF - 5 <= wait <= jetkvm.LOGIN_WAIT_MOST + TICK, wait
            if says == "120":
                assert 100 <= wait <= 120 + TICK or wait >= kvm.LOGIN_BACKOFF - 5  # what it asks for, where that is more than the wall waits anyway
        finally:
            await device.close()

    try:
        asyncio.run(check())
    finally:
        fake.stop()


# --- what it says, one wrong value at a time ----------------------------------------------------------------

ODD: list[Any] = [None, False, True, 0, -1, 1e100, "", "text", [], {}, ["x"], {"x": 1}]


def odd_values(seed: int) -> list[Any]:
    rng = random.Random(seed)
    return ODD + ["".join(chr(rng.randrange(32, 127)) for _ in range(rng.randrange(1, 100))) for _ in range(50)]


def test_a_message_nested_thousands_deep_is_not_an_error_of_the_program() -> None:
    # Python's reader of JSON gives up on brackets within brackets with an error of its own kind, on the
    # Pythons before 3.13 at a thousand deep. The reader of the signalling took that; the reader of what a
    # JetKVM says over its channel did not, nor the one of its answer to an offer. (Seen on 3.11 only: the
    # newest Python reads this without a word, and with it every run on a developer's own machine.)
    deep = "[" * 100_000 + "0" + "]" * 100_000
    device = jetkvm.JetKvmDevice(DeviceSpec("jet", "A JetKVM", "http://127.0.0.1:18901", "", "", kind="jetkvm"))
    device._on_message(jetkvm._Session(), deep)
    device._on_message(jetkvm._Session(), '{"id": 1, "result": ' + deep + "}")

    class Heard:
        async def message(self, within: float) -> str:
            return json.dumps({"type": "answer", "data": base64.b64encode(deep.encode()).decode()})

    async def answered() -> None:
        with pytest.raises(KvmError) as refused:
            await jetkvm._await_answer(Heard())  # type: ignore[arg-type]
        assert refused.value.code == "bad_response"

    asyncio.run(answered())


def test_every_field_of_what_a_jetkvm_tells_with_one_wrong_value_at_a_time() -> None:
    device = jetkvm.JetKvmDevice(DeviceSpec("jet", "A JetKVM", "http://127.0.0.1:18901", "", "", kind="jetkvm"))
    tried = 0
    for method in ("videoInputState", "usbState", "atxState", "localVersion", "otherSessionConnected"):
        for part in ("id", "method", "params"):
            for value in odd_values(54301):
                message = {"jsonrpc": "2.0", "method": method, "params": {"ready": True, "width": 640, "height": 360}, "id": 0}
                message[part] = value
                device._on_message(jetkvm._Session(), json.dumps(message))  # (raises nothing, whatever it is)
                tried += 1
    assert tried == 5 * 3 * 62


def test_every_field_of_how_a_jetkvm_answers_an_offer_with_one_wrong_value_at_a_time() -> None:
    sdp = "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:0\r\n"
    good = {"type": "answer", "data": base64.b64encode(json.dumps({"sdp": sdp}).encode()).decode()}

    class Heard:
        def __init__(self, messages: list[Any]) -> None:
            self.messages = iter(messages)

        async def message(self, within: float) -> str:
            try:
                return json.dumps(next(self.messages))
            except StopIteration:
                raise TimeoutError from None

    async def check() -> int:
        tried = 0
        for part in ("type", "data", "sdp", "candidate"):
            for value in odd_values(54302):
                message: dict[str, Any] = dict(good)
                if part == "sdp":
                    message["data"] = base64.b64encode(json.dumps({"sdp": value}).encode()).decode()
                elif part == "candidate":
                    message = {"type": "new-ice-candidate", "data": {"candidate": value}}
                else:
                    message[part] = value
                try:
                    answer, candidates = await jetkvm._await_answer(Heard([message, good]))  # type: ignore[arg-type]
                except KvmError:
                    pass  # refused, as something a device has no business sending
                else:
                    assert isinstance(answer, str) and len(candidates) <= jetkvm.MAX_CANDIDATES
                    assert all(isinstance(each, str) and len(each) <= 1000 for each in candidates)
                    assert isinstance(jetkvm.with_candidates(answer, candidates), str)
                tried += 1
        return tried

    assert asyncio.run(check()) == 4 * 62
