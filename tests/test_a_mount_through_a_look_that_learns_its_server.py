"""A server's mount kept through a look that learns more of the same server, as the outside review's third round
(Codex) found it ended: the look adopted the server's numbers (none at first, or its computer's alone, then its
controller's too), the saved record changed, and the wall took it for another controller. Learning more of the same
controller keeps a mount; another controller ends it (tests/test_a_mount_after_its_tile_was_given_another_controller.py).
"""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path

import pytest
from qkvm import redfish
from tests.fake_redfish import BmcState, FakeBmc
from tests.test_live import Wall
from tests.test_redfish import fast  # noqa: F401 (short polling, no external release checks)
from tests.test_virtual_media_on_a_server import a_server, media_settings, mount, reader
from tests.test_wall import wait_until


SYSTEM = "ec54c657-4485-4a29-93a5-cc467e3a62df"
CONTROLLER = "ffff3a20-8757-42c6-94bb-43c758608fb2"
PAYLOAD = b"ordinary first-read bytes"
NAME = "review.iso"


def folder(tmp_path: Path) -> Path:
    image_dir = tmp_path / "images"
    image_dir.mkdir()
    (image_dir / NAME).write_bytes(PAYLOAD)
    return image_dir


@pytest.mark.parametrize("initial", ["no-numbers", "computer-only", "both-control"])
def test_first_ordinary_look_after_mount(tmp_path: Path, initial: str) -> None:
    fake = FakeBmc(BmcState(uuid=None if initial == "no-numbers" else SYSTEM,
                            root_uuid=CONTROLLER if initial == "both-control" else None,
                            virtual_media="standard")).start()
    try:
        with Wall(tmp_path / "wall") as live, reader() as controller:
            admin = live.browser()
            media_settings(admin, folder(tmp_path), live.url)
            tile = a_server(admin, fake)
            old = live.core.store.device(tile).machine
            result = mount(admin, tile, NAME)
            assert result.status_code == 200, result.text
            loan = live.core.served.of(tile)
            assert loan.identity[1] == old
            address = fake.state.media_said[-1]["Image"]
            before = controller.get(address)
            assert (before.status_code, before.content) == (200, PAYLOAD)

            # Same process, same host, same computer and controller. The numbers
            # become readable on the next Redfish session, as firmware starts up.
            fake.state.uuid = SYSTEM
            fake.state.root_uuid = CONTROLLER
            fake.state.tokens.clear()
            expected = redfish.own_number({"UUID": SYSTEM}) + redfish.controller_number({"UUID": CONTROLLER})
            def looked():
                admin.get("/api/v1/status").raise_for_status()
                return live.core.store.device(tile).machine == expected
            wait_until(looked, "the ordinary status look never saved the identity", 10)
            after = controller.get(address)
            print(f"identity {initial}: mount={result.status_code}, before={before.status_code}, "
                  f"after={after.status_code}, ended={loan.ended}, identity_changed={old != expected}")
            if initial == "no-numbers":
                # (Known by nothing when it was mounted: nothing tells this controller from another one put at its address,
                # whose numbers these may be. Its first identity ends the mount, and it is mounted again: the outside
                # review's fourth round, R4-M1, which found the other one served.)
                assert after.status_code == 404 and loan.ended
            else:
                assert after.status_code == 200 and after.content == PAYLOAD and not loan.ended  # (learned: the same one)
    finally:
        fake.stop()


def test_mount_while_the_identity_save_waits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Delay only the next identity-save coroutine, the equivalent of waiting
    # for another settings change in the single-writer lock. The driver, HTTP
    # checks, real store update and localhost device traffic all remain real.
    from qkvm.core import DeviceManager

    pending, release = threading.Event(), threading.Event()
    known = DeviceManager._known
    async def delayed(self, device_id, url, was, mark, *rest):
        previous = self.known
        assert previous is not None
        async def after_busy_writer(*args):
            pending.set()
            for _ in range(1000):
                if release.is_set():
                    break
                await asyncio.sleep(.02)
            assert release.is_set(), "save gate timed out"
            await previous(*args)
        self.known = after_busy_writer
        try:
            await known(self, device_id, url, was, mark, *rest)
        finally:
            self.known = previous
    monkeypatch.setattr(DeviceManager, "_known", delayed)
    fake = FakeBmc(BmcState(uuid=SYSTEM, root_uuid=None, virtual_media="standard")).start()
    try:
        with Wall(tmp_path / "wall") as live, reader() as controller:
            admin = live.browser()
            media_settings(admin, folder(tmp_path), live.url)
            tile = a_server(admin, fake)
            short = redfish.own_number({"UUID": SYSTEM})
            full = short + redfish.controller_number({"UUID": CONTROLLER})
            assert live.core.store.device(tile).machine == short
            fake.state.root_uuid = CONTROLLER
            fake.state.tokens.clear()
            def detected():
                admin.get("/api/v1/status").raise_for_status()
                return pending.is_set()
            wait_until(detected, "the real look never discovered the controller number", 10)
            try:
                result = mount(admin, tile, NAME)
                assert result.status_code == 200, result.text
                loan = live.core.served.of(tile)
                assert loan.identity[1] == short
                address = fake.state.media_said[-1]["Image"]
                before = controller.get(address)
                assert (before.status_code, before.content) == (200, PAYLOAD)
            finally:
                release.set()
            wait_until(lambda: live.core.store.device(tile).machine == full, "real save never landed", 10)
            after = controller.get(address)
            print(f"identity-save queued: mount={result.status_code}, before={before.status_code}, "
                  f"after={after.status_code}, ended={loan.ended}")
            assert after.status_code == 200 and after.content == PAYLOAD and not loan.ended  # (learned: the same one)
    finally:
        release.set()
        fake.stop()
