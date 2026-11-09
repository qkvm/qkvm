"""A failed edit says what it did not take back (the outside review's fifth round, a LOW).

An edit to another controller ends what is lent to the tile before it is saved, for whichever controller it was to be.
Where the save then fails (507), the record and its driver are put back, and the mount stays ended (fail-closed, kept
so); the answer said only "nothing was changed". It says the image is served no more, to be mounted again.
"""

from __future__ import annotations

from typing import Any

import pytest

from tests.fake_redfish import BmcState, FakeBmc
from tests.test_live import Wall
from tests.test_redfish import fast  # noqa: F401 (short polling, no external release checks)
from tests.test_virtual_media_on_a_server import a_server, media_settings, mount, reader


def test_an_edit_whose_save_failed_says_the_image_mounted_on_it_is_served_no_more(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    host = FakeBmc(BmcState(virtual_media="standard", media_fetch=False)).start()
    try:
        with Wall(tmp_path / "wall") as wall, reader() as controller:
            admin = wall.browser()
            tile = a_server(admin, host)
            folder = tmp_path / "images"
            folder.mkdir()
            (folder / "review.iso").write_bytes(b"rollback fixture")
            media_settings(admin, folder, wall.url)
            assert mount(admin, tile, "review.iso").status_code == 200
            url = host.state.media_said[-1]["Image"]
            original = wall.core.store.device(tile)
            assert controller.get(url).content == b"rollback fixture"
            # Another controller answers at the address (other numbers), and the edit that takes it cannot be saved.
            host.state.uuid = "76543210-1234-4978-ace1-1030507090af"
            host.state.tokens.clear()
            write = wall.core.store.write

            def refused(data: Any) -> Any:
                if any(record["id"] == tile and record["name"] == "Rollback fixture" for record in data["devices"]):
                    raise OSError("the disk is full")
                return write(data)

            monkeypatch.setattr(wall.core.store, "write", refused)
            reply = admin.put(f"/api/v1/devices/{tile}", json={"kind": "redfish", "url": host.url, "username": "admin", "password": "secret", "name": "Rollback fixture"}, timeout=16)
            assert reply.status_code == 507, reply.text
            assert wall.core.store.device(tile) is original
            said = reply.json()["message"]
            assert "nothing was changed" in said and "review.iso" in said and "mount it again" in said, said
            assert controller.get(url).status_code == 404  # (ended, and not given back: fail-closed)
    finally:
        host.stop()
