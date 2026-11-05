"""A server's mount after its tile was given another controller at the same address, as the outside review's third
round (Codex) found it: an edit racing a mount bound what was lent to the new controller while the old one was handed
the address, and read the image; and a mount the old controller held stayed good across an edit to another one and
back. What is lent is the controller's that the mounting driver itself checked, and an edit that changes a tile's
controller ends it.
"""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor

from qkvm import live as live_module, redfish
from tests.fake_redfish import BmcState, FakeBmc, make_fake_bmc
from tests.test_live import Wall
from tests.test_virtual_media_on_a_server import a_server, media_settings, mount, reader


class Gateway:
    def __init__(self):
        self.a = BmcState(virtual_media="standard", keeps_idle=40, media_fetch=False)
        self.b = BmcState(virtual_media="standard", keeps_idle=40, media_fetch=False)
        self.host = FakeBmc(self.a)
        self.active = "a"
        backends = {"a": self.host._server.config.app, "b": make_fake_bmc(self.b)}
        peers = {}

        async def dispatch(scope, receive, send):
            if scope["type"] == "lifespan":
                return await backends["a"](scope, receive, send)
            peer = tuple(scope["client"])
            side = peers.setdefault(peer, self.active)
            await backends[side](scope, receive, send)

        self.host._server.config.app = dispatch
        self.host.url = self.host.url.replace("127.0.0.1", "localhost")

    def __enter__(self):
        self.host.start()
        return self

    def __exit__(self, *_):
        self.host.stop()


def setup(wall, gateway, folder):
    folder.mkdir()
    payload = b"qKVM round three, same-address host fixture.\n" * 120
    (folder / "review.iso").write_bytes(payload)
    admin = wall.browser()
    tile = a_server(admin, gateway.host)
    media_settings(admin, folder, wall.url)
    initial = wall.core._tile_identity(tile)
    assert redfish.own_number({"UUID": gateway.a.uuid}) in initial[1] and redfish.own_number({"UUID": gateway.a.uuid}) in initial[2]
    return admin, tile, initial, payload


def change(admin, gateway, tile, side):
    gateway.active = side
    reply = admin.put(f"/api/v1/devices/{tile}", json={
        "url": gateway.host.url, "kind": "redfish", "name": admin.machine,
        "username": "admin", "password": "secret",
    }, timeout=16)
    assert reply.status_code == 200, (side, reply.status_code, reply.text)


def test_obsolete_mount_cannot_bind_as_the_replacement(tmp_path, monkeypatch):
    with Gateway() as gateway, Wall(tmp_path / "wall") as wall:
        admin, tile, initial, payload = setup(wall, gateway, tmp_path / "images")
        in_dns, in_retirement, mount_finished = (threading.Event() for _ in range(3))
        resolve = redfish.addresses_of
        settle = live_module.Lines._settle

        async def wait_dns(url):
            if url == gateway.host.url:
                in_dns.set()
                assert await asyncio.to_thread(in_retirement.wait, 8), "replacement never reached retirement"
            return await resolve(url)

        async def with_key_release(lines, device_id):
            if device_id != tile or not in_dns.is_set() or in_retirement.is_set():
                return await settle(lines, device_id)
            # Simulate one outstanding keyboard release. Run the real bounded
            # Lines._settle so the old connection stays usable only as in qKVM.
            assert redfish.own_number({"UUID": gateway.b.uuid}) in lines.manager.core._tile_identity(tile)[1]
            owed = asyncio.create_task(asyncio.to_thread(mount_finished.wait, 8))
            bucket = lines._owed.setdefault(tile, set())
            bucket.add(owed)
            in_retirement.set()
            try:
                await settle(lines, tile)
            finally:
                bucket.discard(owed)
                if not owed.done():
                    owed.cancel()

        monkeypatch.setattr(redfish, "addresses_of", wait_dns)
        monkeypatch.setattr(live_module.Lines, "_settle", with_key_release)

        def do_mount():
            try:
                return mount(admin, tile, "review.iso")
            finally:
                mount_finished.set()

        with ThreadPoolExecutor(max_workers=1) as clients:
            pending = clients.submit(do_mount)
            try:
                assert in_dns.wait(8), "old mount never reached address resolution"
                change(admin, gateway, tile, "b")
                reply = pending.result(timeout=10)
            finally:
                mount_finished.set()
                in_retirement.set()
        assert redfish.own_number({"UUID": gateway.b.uuid}) in wall.core._tile_identity(tile)[1]
        assert initial != wall.core._tile_identity(tile)
        assert not gateway.b.media_said
        if not gateway.a.media_said:
            assert reply.status_code != 200
            print("old driver was cut off before the previous controller received a token", reply.status_code)
            return
        address = gateway.a.media_said[-1]["Image"]
        lending = wall.core.served.find(address.split("/")[-2])
        with reader() as former:
            got = former.get(address)
        print("obsolete mount: edit=200 mount=", reply.status_code,
              "A_insertions=", len(gateway.a.media_said), "B_insertions=", len(gateway.b.media_said),
              "grant_matches_B=", lending is not None and lending.identity == wall.core._tile_identity(tile),
              "old_controller_read=", got.status_code, "bytes=", len(got.content))
        if got.status_code == 200:
            assert got.content == payload
        assert got.status_code == 404, "the previous controller can read the image while the replacement is current"


def test_unused_old_mount_is_revoked_across_two_edits(tmp_path):
    with Gateway() as gateway, Wall(tmp_path / "wall") as wall:
        admin, tile, initial, payload = setup(wall, gateway, tmp_path / "images")
        reply = mount(admin, tile, "review.iso")
        assert reply.status_code == 200, reply.text
        address = gateway.a.media_said[-1]["Image"]
        with reader() as former:
            assert former.get(address).content == payload
            change(admin, gateway, tile, "b")
            assert redfish.own_number({"UUID": gateway.b.uuid}) in wall.core._tile_identity(tile)[1]
            assert wall.core._tile_identity(tile) != initial
            # No one asks for this token while B is current. Switch new
            # connections back to A and have the administrator confirm A.
            change(admin, gateway, tile, "a")
            assert wall.core._tile_identity(tile) == initial
            got = former.get(address)
        print("A -> B -> A: both password-bearing edits=200; fresh GET using old token=",
              got.status_code, "bytes=", len(got.content))
        if got.status_code == 200:
            assert got.content == payload
        assert got.status_code == 404, "intervening replacement did not permanently invalidate the old token"
