"""A server's mount whose controller was known by nothing when it was mounted (no pinned certificate, no numbers), as the
outside review's fourth round (Codex, R4-M1) found it: a mount under way during an edit to another controller, and a
look that learned another controller's numbers at the same address, each left the old one reading the image. Known by
nothing, its first identity ends the mount; a change of the tile's controller ends it, and a mount under way hands out
nothing. A name or a group changed with nothing else keeps it, where the controller was known.
"""
import pytest
from qkvm import redfish
from tests.fake_redfish import BmcState, FakeBmc, make_fake_bmc
from tests.test_a_mount_after_its_tile_was_given_another_controller import (
    test_obsolete_mount_cannot_bind_as_the_replacement as old_schedule,
)
from tests import test_a_mount_after_its_tile_was_given_another_controller as scheduled
from tests.test_live import Wall
from tests.test_redfish import fast  # noqa: F401 (short polling, no external release checks)
from tests.test_virtual_media_on_a_server import a_server, media_settings, mount, reader
from tests.test_wall import wait_until

DATA = b"Round four fixture image."
def begin(wall, host, folder):
    folder.mkdir()
    (folder / "review.iso").write_bytes(DATA)
    admin = wall.browser()
    tile = a_server(admin, host)
    media_settings(admin, folder, wall.url)
    return admin, tile

def test_in_progress_mount_from_unidentified_controller(tmp_path, monkeypatch):
    # Reuse the candidate's M1 schedule, changing only the initial fixture identity.
    def setup(wall, gateway, folder):
        gateway.a.uuid = gateway.a.root_uuid = None
        admin, tile = begin(wall, gateway.host, folder)
        initial = wall.core._tile_identity(tile)
        assert initial == (None, "", "")
        return admin, tile, initial, DATA
    monkeypatch.setattr(scheduled, "setup", setup)
    old_schedule(tmp_path, monkeypatch)

def test_first_numbers_from_distinct_backend(tmp_path):
    # One local front address dispatches to two independent synthetic board sessions.
    a = BmcState(uuid=None, root_uuid=None, virtual_media="standard", media_fetch=False)
    b = BmcState(virtual_media="standard", media_fetch=False)
    host = FakeBmc(a)
    apps = [host._server.config.app, make_fake_bmc(b)]
    selected = [0]
    async def front(scope, receive, send):
        index = selected[0] if scope["type"] == "http" else 0
        await apps[index](scope, receive, send)
    host._server.config.app = front
    host.start()
    try:
        with Wall(tmp_path / "wall") as wall, reader() as device_reader:
            admin, tile = begin(wall, host, tmp_path / "images")
            assert wall.core._tile_identity(tile) == (None, "", "")
            assert mount(admin, tile, "review.iso").status_code == 200
            address = a.media_said[-1]["Image"]
            loan = wall.core.served.of(tile)
            assert device_reader.get(address).content == DATA
            selected[0] = 1
            expected = redfish.own_number({"UUID": b.uuid}) + redfish.controller_number({"UUID": b.root_uuid})
            def looked():
                admin.get("/api/v1/status").raise_for_status()
                return wall.core._tile_identity(tile)[1] == expected
            wait_until(looked, "new same-address board's numbers never saved", 10)
            reply = device_reader.get(address)
            print(f"new backend learned without edit: B number saved, B insertions={len(b.media_said)}, old grant={reply.status_code}, fixture_bytes={reply.content == DATA}, ended={loan.ended}")
            assert not b.media_said
            assert reply.status_code == 404
    finally:
        host.stop()

@pytest.mark.parametrize("late", [False, True], ids=["known", "first-numbers"])
def test_cosmetic_edit_preserves_working_mount(tmp_path, late):
    state = BmcState(virtual_media="standard", media_fetch=False)
    sys_id, controller_id = state.uuid, state.root_uuid
    if late:
        state.uuid = state.root_uuid = None
    host = FakeBmc(state).start()
    try:
        with Wall(tmp_path / "wall") as wall, reader() as controller:
            admin, tile = begin(wall, host, tmp_path / "images")
            assert mount(admin, tile, "review.iso").status_code == 200
            address = state.media_said[-1]["Image"]
            assert controller.get(address).content == DATA
            initial = wall.core._tile_identity(tile)
            # Only a display name/group changes in the API. The board can now report numbers.
            state.uuid, state.root_uuid = sys_id, controller_id
            reply = admin.put(f"/api/v1/devices/{tile}", json={"url": host.url, "kind": "redfish", "name": "Renamed", "group":"Lab", "username":"admin"}, timeout=12)
            assert reply.status_code == 200, reply.text
            subsequent = controller.get(address)
            print(f"rename and group, late_numbers={late}, edit=200, identity_changed={initial != wall.core._tile_identity(tile)}, freshGET={subsequent.status_code}")
            if late:
                # (Known by nothing when it was mounted: the numbers the edit learned may be another controller's, and the
                # mount ends; it is mounted again. The review's LOW of the same name, decided so with R4-M1.)
                assert subsequent.status_code == 404
            else:
                assert subsequent.status_code == 200 and subsequent.content == DATA
    finally:
        host.stop()
