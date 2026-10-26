"""A real Proxmox VE, where one is named in the environment; skipped everywhere else (CI included).

    QKVM_TEST_PROXMOX           its address: https://192.168.1.5:8006
    QKVM_TEST_PROXMOX_TOKEN     an API token, as Proxmox writes it: user@realm!name=secret
    QKVM_TEST_PROXMOX_RUNNING   optional: the ID of a running guest to look at (else the first running one the token sees)
    QKVM_TEST_PROXMOX_TYPE      "1": letters may be typed into that guest (at a login prompt: they are taken back after)
    QKVM_TEST_PROXMOX_STOPPED   optional: the ID of a stopped guest whose power buttons may be pressed: it is
                                switched on, looked at, asked to shut down, and stopped again
    QKVM_TEST_PROXMOX_PICTURES  optional: a folder the pictures are kept in, to be looked at

Only with the owner's word for that Proxmox and those guests: every console opened is a task in the node's log, and
the power buttons are pressed for real. The token needs VM.Audit and VM.Console on the guests, and VM.PowerMgmt for the
stopped one.
"""

from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path

import av
import pytest

from qkvm import proxmox
from qkvm.kvm import DeviceSpec, KvmError, Snapshot
from qkvm.proxmox import ProxmoxGuest

ADDRESS = os.environ.get("QKVM_TEST_PROXMOX", "")
TOKEN = os.environ.get("QKVM_TEST_PROXMOX_TOKEN", "")
RUNNING = os.environ.get("QKVM_TEST_PROXMOX_RUNNING", "")
TYPE = os.environ.get("QKVM_TEST_PROXMOX_TYPE", "") == "1"
STOPPED = os.environ.get("QKVM_TEST_PROXMOX_STOPPED", "")
PICTURES = os.environ.get("QKVM_TEST_PROXMOX_PICTURES", "")

pytestmark = pytest.mark.skipif(not (ADDRESS and "=" in TOKEN), reason="no real Proxmox named (QKVM_TEST_PROXMOX, QKVM_TEST_PROXMOX_TOKEN)")


def token() -> tuple[str, str]:
    token_id, _, secret = TOKEN.partition("=")
    return token_id, secret


def keep(name: str, picture: Snapshot) -> None:
    if PICTURES:
        Path(PICTURES).mkdir(parents=True, exist_ok=True)
        (Path(PICTURES) / f"{name}.jpg").write_bytes(picture.data)


def pixels(jpeg: bytes) -> tuple[int, int, bytes]:
    codec = av.CodecContext.create("mjpeg", "r")
    frame = (codec.decode(av.Packet(jpeg)) + codec.decode(None))[0]
    plane = frame.reformat(format="rgb24").planes[0]
    row = 3 * frame.width
    raw = bytes(plane)
    return frame.width, frame.height, b"".join(raw[y * plane.line_size : y * plane.line_size + row] for y in range(frame.height))


def differ(before: bytes, after: bytes) -> int:
    """How many pixels differ by more than a little between two pictures of one screen."""
    _, _, one = pixels(before)
    _, _, two = pixels(after)
    return sum(1 for at in range(0, min(len(one), len(two)), 3) if abs(one[at] - two[at]) + abs(one[at + 1] - two[at + 1]) + abs(one[at + 2] - two[at + 2]) > 90)


async def guests() -> list[dict[str, object]]:
    token_id, secret = token()
    listed, _, _ = await proxmox.guests(ADDRESS, token_id, secret, typed=True)
    return listed


def the_guest(url: str) -> ProxmoxGuest:
    token_id, secret = token()
    return ProxmoxGuest(DeviceSpec(id="real-pve", name="the real guest", base_url=url, username=token_id, password=secret, kind="proxmox"))


async def picture_of(device: ProxmoxGuest, within: float = 30.0) -> Snapshot:
    deadline = time.monotonic() + within
    while True:
        try:
            return await device.snapshot(4000, fresh=0)
        except KvmError as ex:
            if ex.code != "no_stream" or time.monotonic() > deadline:
                raise
        await asyncio.sleep(0.2)


async def fresh_picture(device: ProxmoxGuest, after: float = 1.0) -> Snapshot:
    """A picture made after `after` seconds more, of what the screen shows by then."""
    await asyncio.sleep(after)
    return await picture_of(device)


async def online(device: ProxmoxGuest, want: str, within: float = 30.0) -> dict[str, object]:
    deadline = time.monotonic() + within
    while True:
        device._status_at = 0.0
        await device.status()
        await asyncio.sleep(0.5)
        status = await device.status()
        if status["state"] == want or time.monotonic() > deadline:
            return status


def test_a_real_proxmox_lists_its_guests_and_shows_a_running_ones_screen() -> None:
    async def run() -> None:
        listed = await guests()
        assert listed and all(isinstance(guest["url"], str) and proxmox.is_guest(str(guest["url"])) for guest in listed)
        running = [guest for guest in listed if guest["status"] == "running" and (not RUNNING or str(guest["vmid"]) == RUNNING)]
        assert running, "no running guest the token may see"
        device = the_guest(str(running[0]["url"]))
        try:
            about = await device.identify()
            assert about["model"] == f"VM {running[0]['vmid']} on {running[0]['node']}" and str(about["version"]).startswith("Proxmox VE ")
            status = await device.status()
            assert status["state"] == "online" and status["screen"] is True and status["atx"]["power"] is True
            began = time.monotonic()
            shown = await picture_of(device)
            first = time.monotonic() - began
            assert shown.data[:2] == b"\xff\xd8" and first < 10, first
            keep(f"guest{running[0]['vmid']}", shown)
            width, height, _ = pixels(shown.data)
            assert (width, height) == device.screen_size()
        finally:
            await device.close()

    asyncio.run(run())


@pytest.mark.skipif(not TYPE, reason="typing into the guest was not allowed (QKVM_TEST_PROXMOX_TYPE)")
def test_letters_typed_at_a_real_guests_prompt_arrive_and_are_taken_back() -> None:
    async def run() -> None:
        listed = await guests()
        running = [guest for guest in listed if guest["status"] == "running" and (not RUNNING or str(guest["vmid"]) == RUNNING)]
        device = the_guest(str(running[0]["url"]))
        try:
            await device.status()
            before = await picture_of(device)
            keep("before-typing", before)
            await device.act("text", text="qkvm")
            typed = await fresh_picture(device)
            keep("typed", typed)
            assert differ(before.data, typed.data) > 20, "the letters were not seen on the guest's screen"
            await device.act("keys", keys="Backspace")
            for _ in range(3):
                await device.act("keys", keys="Backspace")
            after = await fresh_picture(device)
            keep("taken-back", after)
            assert differ(before.data, after.data) < differ(before.data, typed.data)
        finally:
            await device.close()

    asyncio.run(run())


@pytest.mark.skipif(not STOPPED, reason="no stopped guest whose power buttons may be pressed (QKVM_TEST_PROXMOX_STOPPED)")
def test_the_power_buttons_of_a_real_guest() -> None:
    async def run() -> None:
        listed = await guests()
        chosen = [guest for guest in listed if str(guest["vmid"]) == STOPPED]
        assert chosen and chosen[0]["status"] == "stopped", "the guest named is not stopped"
        device = the_guest(str(chosen[0]["url"]))
        try:
            assert (await online(device, "no_signal"))["state"] == "no_signal"
            with pytest.raises(KvmError) as off:
                await device.snapshot(640)
            assert off.value.code == "no_picture"
            await device.act("power_on")  # waited for: done means seen running
            status = await online(device, "online")
            assert status["state"] == "online" and status["atx"]["power"] is True
            keep("switched-on", await picture_of(device, within=60))
            await asyncio.sleep(20)  # (time to boot to a prompt that would hear a request to shut down, if it does)
            keep("booted", await fresh_picture(device))
            await device.act("power_off")  # asked: whether the guest hears it is the guest's business
            status = await online(device, "no_signal", within=60)
            if status["state"] != "no_signal":
                await device.act("atx_power_long")  # not heard: stopped at once, waited for
            assert (await online(device, "no_signal"))["state"] == "no_signal"
        finally:
            await device.close()

    asyncio.run(run())
