"""Intel AMT on a real machine, where one is named in the environment; skipped everywhere else (CI included).

    QKVM_TEST_AMT_URL         the engine's address as the wall would keep it: https://192.168.1.60:16993
    QKVM_TEST_AMT_PASSWORD    its password (the account is QKVM_TEST_AMT_USER, `admin` where not given)
    QKVM_TEST_COMET_URL       optional: a kvmd KVM (a GL.iNet Comet) showing the same PC's screen over HDMI,
    QKVM_TEST_COMET_PASSWORD  and its password: its picture is compared with the engine's

Nothing is pressed: no key, no button, no power. The engine is asked how it is, and its screen is looked at through its
KVM (which shows Intel's border on the PC's own monitor for the seconds that takes). Intel AMT locks an account after a
few wrong passwords: give it the right one, or none. Nobody else may hold its KVM meanwhile (one session at a time).
"""

from __future__ import annotations

import asyncio
import os
import time

import av
import pytest

from qkvm import amt, amtserial
from qkvm.amt import AmtDevice
from qkvm.amtserial import SerialConsole
from qkvm.kvm import DeviceSpec, KvmDevice, KvmError, Snapshot

AMT_URL = os.environ.get("QKVM_TEST_AMT_URL", "")
AMT_USER = os.environ.get("QKVM_TEST_AMT_USER", "admin")
AMT_PASSWORD = os.environ.get("QKVM_TEST_AMT_PASSWORD", "")
COMET_URL = os.environ.get("QKVM_TEST_COMET_URL", "")
COMET_PASSWORD = os.environ.get("QKVM_TEST_COMET_PASSWORD", "")

pytestmark = pytest.mark.skipif(not (AMT_URL and AMT_PASSWORD), reason="no real Intel AMT machine named (QKVM_TEST_AMT_URL, QKVM_TEST_AMT_PASSWORD)")


def the_pc() -> AmtDevice:
    return AmtDevice(DeviceSpec(id="real-amt", name="the real PC", base_url=AMT_URL, username=AMT_USER, password=AMT_PASSWORD, kind="amt"))


async def picture_of(device: AmtDevice, within: float = 60.0) -> Snapshot:
    deadline = time.monotonic() + within
    while True:
        try:
            return await device.snapshot(4000)
        except KvmError as ex:
            if ex.code != "no_stream" or time.monotonic() > deadline:
                raise
        await asyncio.sleep(0.5)


def small(jpeg: bytes, width: int = 160, height: int = 90) -> bytes:
    """A picture as three bytes a pixel at a small size (where two pictures of one screen can be compared without their detail)."""
    codec = av.CodecContext.create("mjpeg", "r")
    frame = (codec.decode(av.Packet(jpeg)) + codec.decode(None))[0]
    plane = frame.reformat(width=width, height=height, format="rgb24").planes[0]
    row = 3 * width
    raw = bytes(plane)
    return b"".join(raw[y * plane.line_size : y * plane.line_size + row] for y in range(height))


def size_of(jpeg: bytes) -> tuple[int, int]:
    codec = av.CodecContext.create("mjpeg", "r")
    frame = (codec.decode(av.Packet(jpeg)) + codec.decode(None))[0]
    return frame.width, frame.height


def test_a_real_engine_is_recognised_and_says_how_it_is() -> None:
    async def run() -> None:
        found = await amt.detect(AMT_URL, True, None)
        assert found is not None and found[0] == "amt"
        device = the_pc()
        try:
            status = await device.status()
            for _ in range(20):
                if status["state"] != "connecting":
                    break
                await asyncio.sleep(0.5)
                status = await device.status()
            assert status["state"] in ("online", "no_signal"), status
            said = status["server"]["amt"]
            assert said["control"] in ("admin", "client", "none") and said["kvm"] in ("enabled", "disabled", "mebx", "absent")
            assert isinstance(said["listener"], bool) and isinstance(said["session_timeout"], int)
            assert status["screen"] is (status["server"]["no_screen"] is None and status["state"] == "online")
        finally:
            await device.close()

    asyncio.run(run())


def test_a_real_engines_screen_comes_through_its_kvm_and_matches_the_kvm_in_front_of_it() -> None:
    async def run() -> None:
        device = the_pc()
        try:
            status = await device.status()
            for _ in range(20):
                if status["state"] != "connecting":
                    break
                await asyncio.sleep(0.5)
                status = await device.status()
            if not status.get("screen"):
                pytest.skip(f"its screen cannot be had: {status.get('server', {}).get('no_screen') or status.get('state')}")
            snap = await picture_of(device)
            assert snap.content_type == "image/jpeg"
            width, height = size_of(snap.data)
            assert (width, height) == device._screen.size()
            if not (COMET_URL and COMET_PASSWORD):
                return
            comet = KvmDevice(DeviceSpec(id="real-comet", name="the KVM in front", base_url=COMET_URL, username="admin", password=COMET_PASSWORD, kind="kvmd"))
            try:
                theirs = None
                for _ in range(20):
                    try:
                        theirs = await comet.snapshot(4000)
                        break
                    except KvmError:
                        await asyncio.sleep(0.5)
                assert theirs is not None, "the KVM gave no picture"
            finally:
                await comet.close()
            assert size_of(theirs.data) == (width, height)
            ours, its = small(snap.data), small(theirs.data)
            difference = sum(abs(a - b) for a, b in zip(ours, its, strict=True)) / len(ours)
            # Seen on one: about 10 of 255 at this size (a tone of the HDMI capture's, and 16-bit colour); a picture of another
            # screen, or one the wrong way round, is far more.
            assert difference < 30, f"the engine's picture and the KVM's differ by {difference:.1f} of 255 on average"
        finally:
            await device.close()

    asyncio.run(run())


def test_a_real_engines_serial_console_opens_stays_open_and_is_ended_as_it_expects() -> None:
    async def run() -> None:
        device = the_pc()
        try:
            await device.status()  # (its certificate remembered on first contact, as the tile does it)
        finally:
            await device.close()
        console = SerialConsole(device.spec)
        stop = asyncio.Event()
        running = asyncio.create_task(console.run(stop))
        await asyncio.sleep(amtserial.QUIET_WITHIN + 2)  # (longer than the reader waits for a word of the engine's: its pongs)
        assert not running.done(), running.exception()
        stop.set()
        await running  # (ended as the engine expects; what the PC wrote meanwhile, if anything, is in console.kept)

    asyncio.run(run())
