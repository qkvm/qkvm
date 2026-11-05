"""A mount on a tile kept beside another at its address ("Keep both"), as the outside review's fifth round (Codex, R5-M1)
found it: the tile's own label (`own:<id>`, qKVM's, which no controller said) counted as something known of its
controller, and a mount known by nothing else learned another controller's numbers, by a look or by an edit, and its
old address still read the image. The label is compared, and is no evidence of the controller.
"""
import pytest

from qkvm import redfish, served
from tests.fake_redfish import BmcState, FakeBmc, make_fake_bmc
from tests.test_live import Wall
from tests.test_redfish import fast, status_of  # noqa: F401 (fast: short polling, by name)
from tests.test_virtual_media_on_a_server import media_settings, mount, reader
from tests.test_wall import add, wait_until

DATA = b"Round five own-label fixture image.\n"


@pytest.mark.parametrize("transition", ["look", "edit"])
def test_tile_own_label_is_not_a_controller_anchor(tmp_path, transition):
    a = BmcState(virtual_media="standard", media_fetch=False)
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
        with Wall(tmp_path / "wall") as wall, reader() as former:
            admin = wall.browser()
            add(admin, host.url, kind="redfish", username="admin")
            alias = host.url.replace("127.0.0.1", "localhost")
            tile = add(admin, alias, kind="redfish", username="admin", name="Own alias", keep_both=True)
            own = f"own:{tile}"
            assert wall.core._tile_identity(tile)[2] == own

            # The owner accepts a reachable controller that supplies no numbers.
            # Keep-both is a persistent tile label, so the real edit preserves it.
            a.uuid = a.root_uuid = None
            form = {"url": alias, "kind": "redfish", "name": "Own alias",
                    "username": "admin", "password": "secret"}
            reply = admin.put(f"/api/v1/devices/{tile}", json=form, timeout=16)
            assert reply.status_code == 200, reply.text
            assert wall.core._tile_identity(tile) == (None, "", own)
            wait_until(lambda: "media" in status_of(admin, tile)["can"], "media was not found", 10)
            folder = tmp_path / "images"
            folder.mkdir()
            (folder / "review.iso").write_bytes(DATA)
            media_settings(admin, folder, wall.url)
            admin.machine = "Own alias"
            reply = mount(admin, tile, "review.iso")
            assert reply.status_code == 200, reply.text
            address = a.media_said[-1]["Image"]
            loan = wall.core.served.of(tile)
            assert former.get(address).content == DATA
            before_epoch = wall.core.served.epoch(tile)

            # A different independently authenticated fixture now answers at the
            # exact same controller address. It never receives a mount command.
            selected[0] = 1
            expected = redfish.own_number({"UUID": b.uuid}) + redfish.controller_number({"UUID": b.root_uuid})
            if transition == "edit":
                reply = admin.put(f"/api/v1/devices/{tile}", json=form, timeout=16)
                assert reply.status_code == 200, reply.text
            else:
                def looked():
                    admin.get("/api/v1/status").raise_for_status()
                    return wall.core._tile_identity(tile)[1] == expected
                wait_until(looked, "replacement's numbers were not saved", 10)
            assert wall.core._tile_identity(tile) == (None, expected, own)
            assert not b.media_said
            got = former.get(address)
            print(f"own label {transition}: B numbers saved, B insertions=0, "
                  f"epoch={before_epoch}->{wall.core.served.epoch(tile)}, "
                  f"old GET={got.status_code}, fixture bytes={got.content == DATA}, ended={loan.ended}")
            assert got.status_code == 404, "tile's own label was mistaken for evidence of controller continuity"
    finally:
        host.stop()


def test_anchor_shape_controls():
    computer = "server:" + "a" * 32
    controller = "b" * 32
    for prefix in ("amt:", "jetkvm:", "proxmox:"):
        mark = prefix + "a" * 32
        assert served.identity_follows((None, mark, ""), (None, mark, "")) == (None, mark, "")
        assert served.identity_follows((None, mark, ""), (None, mark + controller, "")) is None
    assert served.identity_follows((None, computer, ""), (None, computer + controller, "")) == (None, computer + controller, "")
    assert served.identity_follows((None, "", ""), (None, computer, "")) is None
    assert served.identity_follows(("checked certificate", "", ""), ("checked certificate", computer, "")) == ("checked certificate", computer, "")
    assert served.identity_follows(("checked certificate", "", ""), ("other certificate", computer, "")) is None

