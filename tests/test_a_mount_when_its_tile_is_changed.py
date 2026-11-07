"""A server's mount when its tile is changed to another kind at the same address, and a replaced driver's late word, as the
outside review's fourth round (Codex, R4-M2 and a LOW) found them: the old controller still read the image after the
tile became a kvmd KVM; and a number or a certificate a replaced driver saw was saved to the record that took its place.
"""
import asyncio
from dataclasses import replace
import pytest
from qkvm import core as core_module, server
from tests.fake_redfish import BmcState, FakeBmc
from tests.test_live import Wall
from tests.test_served_images_as_the_outside_review_read_them import a_wall_lending
from tests.test_virtual_media_on_a_server import a_server, media_settings, mount, reader

def test_changing_kind_while_unavailable_ends_image(tmp_path):
    host = FakeBmc(BmcState(virtual_media="standard", media_fetch=False)).start()
    try:
        with Wall(tmp_path / "wall") as wall, reader() as controller:
            admin = wall.browser()
            tile = a_server(admin, host)
            folder = tmp_path / "images"
            folder.mkdir()
            payload = b"fixture bytes for old Redfish board"
            (folder / "review.iso").write_bytes(payload)
            media_settings(admin, folder, wall.url)
            assert mount(admin, tile, "review.iso").status_code == 200
            address = host.state.media_said[-1]["Image"]
            before = wall.core._tile_identity(tile)
            assert controller.get(address).content == payload
            # This URL speaks Redfish, so the replacement kvmd driver cannot verify itself.
            change = admin.put(f"/api/v1/devices/{tile}", json={"url": host.url, "kind": "kvmd", "name":"replacement", "username":"admin", "password":"secret", "force":True}, timeout=20)
            assert change.status_code == 200, change.text
            assert wall.core.store.device(tile).kind == "kvmd"
            later = controller.get(address)
            print(f"kind redfish -> kvmd; forced edit=200, same tuple={wall.core._tile_identity(tile) == before}, former reader={later.status_code}, exact payload={later.content == payload}")
            assert later.status_code == 404
    finally:
        host.stop()

@pytest.mark.parametrize("which", ["number", "pin"])
def test_prior_driver_callback_updates_new_record(tmp_path, monkeypatch, which):
    # Exercise the real installed callbacks, with the same scheduling opportunity
    # as adopt installing the replacement before previous-driver retirement completes.
    managers=[]
    class Capture(core_module.DeviceManager):
        def __init__(self, *args):
            super().__init__(*args)
            managers.append(self)
    monkeypatch.setattr(server, "DeviceManager", Capture)
    async def run():
        core, _, record, _ = a_wall_lending(tmp_path, b"tiny", tls="pinned")
        record.url="https://127.0.0.1:18457"
        manager=managers[-1]
        old=manager.client(record, "secret")
        manager._install(old)
        current = replace(record, name="replacement")
        core.store.devices[core.store.devices.index(record)]=current
        new=manager.client(current, "secret")
        if which == "number":
            await old.on_known("", "server:" + "a"*32)
        manager._install(new)
        if which == "pin":
            await old.on_pin("synthetic previous-driver pin")
        await asyncio.gather(*manager._saving)
        updated=core.store.device(current.id)
        value=updated.machine if which=="number" else updated.cert_pem
        print(f"old callback={which}; new driver current={manager.devices[current.id] is new}, old value entered new record={bool(value)}")
        assert not value
    asyncio.run(run())


def test_working_kvmd_replaces_redfish_and_revokes_old_image(tmp_path):
    from tests.fake_kvm import FakeState, make_fake_kvm
    state = BmcState(virtual_media="standard", media_fetch=False)
    host = FakeBmc(state)
    backends = [host._server.config.app, make_fake_kvm(FakeState())]
    side = [0]
    kvmd_requests = []
    async def switch(scope, receive, send):
        index = side[0] if scope["type"] in ("http", "websocket") else 0
        if index and scope["type"] == "http":
            kvmd_requests.append(scope["path"])
        await backends[index](scope, receive, send)
    host._server.config.app = switch
    host.start()
    try:
        with Wall(tmp_path / "wall") as wall, reader() as old_reader:
            admin = wall.browser()
            tile = a_server(admin, host)
            folder = tmp_path / "images"
            folder.mkdir()
            payload = b"bounded fixture for live kind edit"
            (folder / "review.iso").write_bytes(payload)
            media_settings(admin, folder, wall.url)
            assert mount(admin, tile, "review.iso").status_code == 200
            before = wall.core._tile_identity(tile)
            url = state.media_said[-1]["Image"]
            assert old_reader.get(url).content == payload
            side[0] = 1
            # Normal edit with the wall's existing password and a working new backend.
            edit = admin.put(f"/api/v1/devices/{tile}", json={"url":host.url,"kind":"kvmd","name":"Verified kvmd","username":"admin"})
            assert edit.status_code == 200, edit.text
            assert wall.core.store.device(tile).kind == "kvmd" and "/api/auth/check" in kvmd_requests
            reply = old_reader.get(url)
            print(f"live replacement: edit={edit.status_code}, kvmd auth checked=True, identity tuple retained={before == wall.core._tile_identity(tile)}, old Redfish grant={reply.status_code}, exact payload={reply.content == payload}")
            assert reply.status_code == 404
    finally:
        host.stop()
