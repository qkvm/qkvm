"""Virtual media on a kvmd KVM, a GL.iNet Comet or a PiKVM (0.3.0, A2): the KVM's own image storage, one image of it in its
drive as a CD-ROM drive or a USB flash drive (read-only unless the person chooses it writable), an image carried through
qKVM into that storage (streamed as it comes, hashed on its way, kept nowhere), and one deleted from it.

Against the stand-in (fake_kvm.py), grown from kvmd's own source for this (GL.iNet's tree, 4.16, and stock kvmd's): GET
/api/msd, set_params, set_connected, write, remove, and the `msd` event on the line for events. What is shared with every
family (the right, the confirmation, one thing at a time) is in test_virtual_media_on_a_proxmox_guest.py; what is asked
here is what a KVM adds to it, and what its uploads need of the wall: their own rule for their length (16 GB), a cut-off
or stalled one leaving nothing on the KVM, memory that does not grow with the image.
"""

from __future__ import annotations

import gc
import hashlib
import json
import re
import socket
import threading
import time
import tracemalloc
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from qkvm import kvm, server
from qkvm.kvm import IMAGE_NAME, MEDIA_NOTES, MOST_UPLOAD
from tests.fake_kvm import FakeKvm, FakeState
from tests.test_live import Wall
from tests.test_proxmox import state_of
from tests.test_users import OTHER, account, browser
from tests.test_wall import add, wait_until, wall

DEBIAN = "debian-13.iso"
OFFER = {
    "drives": ["cd", "flash"], "boot": [], "restart": False, "upload": True, "where": "device", "writable": ["flash"], "delete": True,
    "drops_input": False,
}  # fmt: skip


@pytest.fixture(autouse=True)
def forgotten(monkeypatch: pytest.MonkeyPatch) -> None:
    MEDIA_NOTES.mounted.clear()
    MEDIA_NOTES.hashes.clear()
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(kvm, "MSD_EVERY", 0)  # (a look asks its drive every time: the line's event is asked about on its own)


def images(sizes: dict[str, int]) -> dict[str, dict[str, Any]]:
    return {name: {"complete": True, "removable": True, "size": size, "mod_ts": 1_700_000_000.0, "sha256": ""} for name, size in sizes.items()}


@pytest.fixture(params=["glinet", "stock"])
def comet(request: pytest.FixtureRequest) -> Iterator[FakeKvm]:
    """A kvmd KVM with its drive switched on and two images on it: GL.iNet's firmware, and stock kvmd's."""
    fake = FakeKvm(FakeState(msd=True, msd_images=images({DEBIAN: 700_000_000, "alpine-3.21.iso": 62_000_000}), stock=request.param == "stock")).start()
    yield fake
    fake.stop()


def media(device: str) -> str:
    return f"/api/v1/devices/{device}/media"


def mount(client: Any, device: str, image: str = DEBIAN, machine: str = "glkvm", **more: Any) -> Any:
    return client.post(media(device), json={"image": image, "machine": machine, **more})


def unmount(client: Any, device: str, image: str = DEBIAN, machine: str = "glkvm") -> Any:
    return client.post(media(device) + "/unmount", json={"image": image, "machine": machine})


def delete(client: Any, device: str, image: str, machine: str = "glkvm") -> Any:
    return client.post(media(device) + "/delete", json={"image": image, "machine": machine})


def entries(client: Any, *events: str) -> list[dict[str, Any]]:
    found = client.get("/api/v1/audit", params={"kind": "action", "limit": 500}).json()["entries"]
    return [entry for entry in reversed(found) if entry["event"] in events]


def a_kvm(client: Any, fake: FakeKvm, name: str = "glkvm") -> str:
    device = add(client, fake.url, name=name)
    wait_until(lambda: "media" in state_of(client, device).get("can", []), "the KVM's drive was never found")
    return device


# --- the stand-in, as kvmd's source says ------------------------------------------------------------------------


def test_the_stand_in_keeps_kvmds_rules_for_its_drive_and_storage() -> None:
    fake = FakeKvm(FakeState(msd=True, msd_images=images({DEBIAN: 700_000}), msd_free=1000)).start()
    try:
        with httpx.Client(base_url=fake.url, timeout=10) as asker:
            token = asker.post("/api/auth/login", data={"user": "admin", "passwd": "secret"}).json()["result"]["token"]
            asker.cookies.set("auth_token", token)
            said = asker.get("/api/msd").json()["result"]
            assert (said["enabled"], said["online"], said["busy"], said["drive"]["connected"]) == (True, True, False, False)
            assert said["storage"]["images"][DEBIAN] == {"complete": True, "removable": True, "size": 700_000, "mod_ts": 1_700_000_000.0}
            assert said["storage"]["parts"][""]["free"] == 1000 and said["drive_partition"]["connected"] is False
            # A CD-ROM drive is read-only; a writable one is no CD-ROM drive (GL.iNet's); nothing changed while connected.
            assert asker.post("/api/msd/set_params", params={"image": DEBIAN, "cdrom": "1", "rw": "1"}).status_code == 200
            assert fake.state.msd_drive == {"image": DEBIAN, "connected": False, "cdrom": False, "rw": True}
            assert asker.post("/api/msd/set_params", params={"cdrom": "1"}).status_code == 200
            assert fake.state.msd_drive["rw"] is False
            assert asker.post("/api/msd/set_connected", params={"connected": "1"}).status_code == 200
            refused = asker.post("/api/msd/set_params", params={"image": DEBIAN})
            assert (refused.status_code, refused.json()["result"]["error"]) == (400, "MsdConnectedError")
            assert asker.post("/api/msd/remove", params={"image": DEBIAN}).json()["result"]["error"] == "MsdImageInUseError"
            assert asker.post("/api/msd/set_connected", params={"connected": "0"}).status_code == 200
            # A write: its length said in advance, no more than is free, no name twice; one cut off removed where asked.
            assert asker.post("/api/msd/write", params={"image": "x.iso"}, content=iter([b"x" * 10])).json()["result"]["error"] == "ValidatorError"
            assert asker.post("/api/msd/write", params={"image": "big.iso"}, content=b"x" * 1001).status_code == 507
            assert asker.post("/api/msd/write", params={"image": DEBIAN}, content=b"x").json()["result"]["error"] == "MsdImageExistsError"
            written = asker.post("/api/msd/write", params={"image": "small.iso", "remove_incomplete": "1"}, content=b"y" * 100)
            assert written.json()["result"] == {"image": {"name": "small.iso", "size": 100, "written": 100}}
            assert fake.state.msd_images["small.iso"]["sha256"] == hashlib.sha256(b"y" * 100).hexdigest() and fake.state.msd_free == 900
        cut_off(fake.port, "/api/msd/write?image=cut.iso&remove_incomplete=1", f"Cookie: auth_token={token}", 500, 200)
        wait_until(lambda: fake.state.msd_writes[-1]["removed"], "what a cut-off write left was not removed")
        assert "cut.iso" not in fake.state.msd_images and fake.state.msd_free == 900
        assert fake.state.msd_never == []
    finally:
        fake.stop()


def cut_off(port: int, path: str, header: str, said: int, sent: int) -> None:
    """A request that says its body is `said` bytes long, sends `sent` of them, and goes."""
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        sock.sendall(f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {said}\r\nX-QKVM: 1\r\n{header}\r\n\r\n".encode() + b"z" * sent)
        time.sleep(0.3)


# --- what a KVM's drive offers, and mounting ---------------------------------------------------------------------


def test_a_kvm_lists_its_images_and_mounts_one_as_a_read_only_cd_and_says_so(tmp_path: Path, comet: FakeKvm) -> None:
    with wall(tmp_path) as admin:
        device = a_kvm(admin, comet)
        body = admin.get(media(device)).json()
        assert [(one["id"], one["name"], one["where"], one["size"], one["partial"], one["sha256"]) for one in body["images"]] == [
            ("alpine-3.21.iso", "alpine-3.21.iso", None, 62_000_000, False, None), (DEBIAN, DEBIAN, None, 700_000_000, False, None),
        ]  # fmt: skip
        assert body["offers"] == OFFER and body["space"] == {"free": 6_000_000_000, "size": 8_000_000_000}
        assert (body["mounted"], body["unseen"], body["notes"], body["left_out"], body["uploading"]) == (None, [], [], 0, None)
        reply = mount(admin, device)
        assert reply.status_code == 200, reply.text
        assert comet.state.msd_drive == {"image": DEBIAN, "connected": True, "cdrom": True, "rw": False}
        mounted = reply.json()["mounted"]
        assert {key: mounted[key] for key in ("drive", "image", "name", "where", "read_only", "first", "by", "sha256")} == {
            "drive": "cd", "image": DEBIAN, "name": DEBIAN, "where": None, "read_only": True, "first": None, "by": "admin", "sha256": None,
        }  # fmt: skip
        wait_until(lambda: (state_of(admin, device).get("media") or {}).get("name") == DEBIAN, "the tile does not say what is in the drive")
        (entry,) = entries(admin, "media_mounted")
        assert {key: entry[key] for key in ("user", "device_id", "image", "drive", "writable", "boot", "restart")} == {
            "user": "admin", "device_id": device, "image": DEBIAN, "drive": "cd", "writable": False, "boot": "none", "restart": False,
        }  # fmt: skip
        # One at a time: another is refused while this one is in, and nothing is changed.
        reply = mount(admin, device, image="alpine-3.21.iso")
        assert (reply.status_code, reply.json()["code"]) == (409, "changed") and "unmount it first" in reply.json()["message"]
        assert comet.state.msd_drive["image"] == DEBIAN
        # A KVM is no firmware: it cannot be told to start from it; and without a power board it is not restarted from here.
        for asked in ({"boot": "once"}, {"boot": "until_unmounted"}, {"restart": True}):
            reply = mount(admin, device, image="alpine-3.21.iso", **asked)
            assert reply.status_code == 422, reply.text
        reply = unmount(admin, device)
        assert (reply.status_code, reply.json()["mounted"]) == (200, None), reply.text
        assert comet.state.msd_drive["connected"] is False and entries(admin, "media_unmounted")[0]["image"] == DEBIAN
        assert unmount(admin, device).json()["note"] == "nothing was mounted"
    assert comet.state.msd_never == []


def test_a_usb_flash_drive_is_read_only_unless_it_is_chosen_writable(tmp_path: Path, comet: FakeKvm) -> None:
    with wall(tmp_path) as admin:
        device = a_kvm(admin, comet)
        assert mount(admin, device, drive="flash").status_code == 200
        assert comet.state.msd_drive == {"image": DEBIAN, "connected": True, "cdrom": False, "rw": False}
        assert admin.get(media(device)).json()["mounted"]["read_only"] is True
        assert unmount(admin, device).status_code == 200
        reply = mount(admin, device, drive="flash", writable=True)
        assert reply.status_code == 200, reply.text
        assert comet.state.msd_drive["rw"] is True and reply.json()["mounted"]["read_only"] is False
        assert entries(admin, "media_mounted")[-1]["writable"] is True
        assert unmount(admin, device).status_code == 200
        # A CD-ROM drive is never writable, and a disk is no KVM's.
        for asked in ({"drive": "cd", "writable": True}, {"drive": "disk"}):
            reply = mount(admin, device, **asked)
            assert (reply.status_code, reply.json()["code"]) == (422, "invalid"), reply.text
        assert comet.state.msd_drive["connected"] is False


def test_an_image_too_small_for_a_cd_rom_drive_is_said_so_before_the_kvm_is_asked(tmp_path: Path, comet: FakeKvm) -> None:
    # (Its drive is Linux's USB gadget, as a JetKVM's, which takes a CD-ROM image of 300 sectors of 2048 bytes at least.)
    comet.state.msd_images["tiny.iso"] = {"complete": True, "removable": True, "size": 376_832, "mod_ts": 1.0, "sha256": ""}
    with wall(tmp_path) as admin:
        device = a_kvm(admin, comet)
        reply = mount(admin, device, image="tiny.iso")
        assert (reply.status_code, reply.json()["code"]) == (422, "invalid"), reply.text
        assert reply.json()["message"] == (
            "tiny.iso is 376,832 bytes, and a CD-ROM drive takes an image of 614,400 bytes at least (300 sectors of 2,048 "
            "bytes): mount it as a USB flash drive."
        )
        assert not any(call.startswith(("set_params", "set_connected")) for call in comet.state.msd_calls)
        reply = mount(admin, device, image="tiny.iso", drive="flash")  # (a flash drive takes it)
        assert reply.status_code == 200, reply.text
        assert unmount(admin, device, image="tiny.iso").status_code == 200


def test_a_kvm_that_mounts_otherwise_than_it_was_asked_has_it_taken_out_again(tmp_path: Path) -> None:
    fake = FakeKvm(FakeState(msd=True, msd_images=images({DEBIAN: 700}), msd_always_rw=True)).start()
    try:
        with wall(tmp_path) as admin:
            device = a_kvm(admin, fake)
            reply = mount(admin, device, drive="flash")
            assert (reply.status_code, reply.json()["code"], reply.json()["mounted"]) == (502, "action_failed", False), reply.text
            assert fake.state.msd_drive["connected"] is False  # (writable where it was to be read-only: not left in)
            assert "media_mount_failed" in [entry["event"] for entry in entries(admin, "media_mount_failed")]
    finally:
        fake.stop()


def test_what_stands_against_a_change_is_said_and_nothing_is_sent(tmp_path: Path, comet: FakeKvm) -> None:
    with wall(tmp_path) as admin:
        device = a_kvm(admin, comet)
        sent = len(comet.state.msd_calls)
        comet.state.msd_busy = True
        assert (mount(admin, device).status_code, mount(admin, device).json()["code"]) == (409, "busy")
        comet.state.msd_busy, comet.state.msd_online = False, False
        reply = mount(admin, device)
        assert (reply.status_code, reply.json()["code"]) == (409, "action_failed") and "offline" in reply.json()["message"]
        comet.state.msd_online = True
        if not comet.state.stock:
            comet.state.msd_sharing = True  # (GL.iNet's File Sharing: the whole storage open to the machine, read-write)
            reply = mount(admin, device)
            assert "File Sharing" in reply.json()["message"] and "File Sharing" in admin.get(media(device)).json()["notes"][0]
            comet.state.msd_sharing = False
        assert len(comet.state.msd_calls) == sent
        # An image that is not on it any more, or not whole, or no name the KVM lists: changed or invalid, and nothing sent.
        comet.state.msd_images["cut.iso"] = {"complete": False, "removable": True, "size": 5, "mod_ts": 1.0, "sha256": ""}
        for image, code in (("gone.iso", "changed"), ("cut.iso", "changed"), ("../etc/shadow", "invalid"), ("http://192.0.2.9/x.iso", "invalid"), (".hidden.iso", "invalid")):
            reply = mount(admin, device, image=image)
            assert (reply.json()["code"], reply.status_code) == (code, 409 if code == "changed" else 422), (image, reply.text)
        assert len(comet.state.msd_calls) == sent
        assert next(one for one in admin.get(media(device)).json()["images"] if one["id"] == "cut.iso")["partial"] is True


def test_a_kvm_whose_drive_is_switched_off_offers_nothing_and_is_asked_nothing(tmp_path: Path) -> None:
    fake = FakeKvm(FakeState()).start()  # (msd off: kvmd's drive switched off in its settings)
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url)
            wait_until(lambda: state_of(admin, device).get("state") == "online", "the KVM never came online")
            assert "media" not in state_of(admin, device)["can"] and state_of(admin, device)["media"] is None
            for reply in (admin.get(media(device)), mount(admin, device), admin.post(media(device) + "/upload?name=x.iso&machine=glkvm", content=b"x")):
                assert (reply.status_code, reply.json()["code"]) == (404, "no_virtual_media"), reply.text
            assert fake.state.msd_calls == [] and fake.state.msd_never == []
            # Switched on in its settings (here: as a look finds it), it is offered from the next look.
            fake.state.msd = True
            wait_until(lambda: "media" in state_of(admin, device).get("can", []), "the drive switched on was never found")
    finally:
        fake.stop()


def test_a_kvm_with_a_power_board_is_restarted_for_its_firmware_to_find_the_image(tmp_path: Path) -> None:
    fake = FakeKvm(FakeState(msd=True, msd_images=images({DEBIAN: 700_000}), atx=True)).start()
    try:
        with wall(tmp_path) as admin:
            device = a_kvm(admin, fake)
            wait_until(lambda: admin.get(media(device)).json()["offers"]["restart"] is True, "the power board was never found")
            reply = mount(admin, device, restart=True)
            assert reply.status_code == 200, reply.text
            assert "reset button" in reply.json()["note"] and "boot menu" in reply.json()["note"]
            assert "atx reset" in fake.state.actions and "atx power" not in fake.state.actions, fake.state.actions
            assert [entry["event"] for entry in entries(admin, "media_mounted", "media_restarted")] == ["media_mounted", "media_restarted"]
            # A way of starting from it is still none of a KVM's: refused before anything is mounted.
            assert unmount(admin, device).status_code == 200
            assert mount(admin, device, boot="once").status_code == 422 and fake.state.msd_drive["connected"] is False
    finally:
        fake.stop()


def test_what_is_mounted_at_the_kvms_own_page_is_said_from_its_line_while_it_is_watched(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "MSD_EVERY", 3600)  # (not asked at a look: what the tile says comes from the line)
    fake = FakeKvm(FakeState(msd=True, msd_images=images({DEBIAN: 700}))).start()
    try:
        with wall(tmp_path) as admin:
            device = a_kvm(admin, fake)
            assert admin.get(f"/api/v1/devices/{device}/snapshot").status_code == 200  # (watched: the keepalive holds its line)
            wait_until(lambda: fake.state.streams > 0, "the line for events was never held")
            asked = sum(1 for one in fake.state.asked if one == "GET /api/msd")
            fake.state.msd_drive.update({"image": DEBIAN, "connected": True, "cdrom": False, "rw": True})  # (on the KVM's own page)
            wait_until(lambda: (state_of(admin, device).get("media") or {}).get("read_only") is False, "the line's `msd` event was not heard")
            assert state_of(admin, device)["media"]["by"] is None  # (not mounted from qKVM: nobody's name)
            assert sum(1 for one in fake.state.asked if one == "GET /api/msd") == asked
    finally:
        fake.stop()


def test_what_the_line_says_of_the_drive_is_kept_of_what_qkvm_reads_and_no_more() -> None:
    # kvmd's `msd` events say a whole state as the line opens, then a part of one: each part kept of the keys qKVM reads
    # and nothing else, however many others a KVM says (it would otherwise grow with every word), and the tile looked at
    # again only where what it says of the drive changed.
    device = kvm.KvmDevice(kvm.DeviceSpec(id="x", name="x", base_url="http://127.0.0.1:9", username="admin", password="p"))
    whole = {"enabled": True, "online": True, "busy": False, "drive": {"connected": False}, "storage": {"images": {}, "parts": {}}}
    device._msd_said({**whole, "odd": 1})
    assert device._msd == whole
    for round_ in range(5):
        device._status_at = 123.0
        device._msd_said({**{f"k{round_}_{n}": 0 for n in range(1000)}, "busy": round_ % 2 == 1, "storage": {f"s{round_}_{n}": 0 for n in range(1000)}})
        assert device._status_at == 123.0  # (nothing the tile says of the drive)
    assert set(device._msd or {}) == {"enabled", "online", "busy", "drive", "storage"} and set(device._msd["storage"]) == {"images", "parts"}
    device._msd_said({"drive": {"connected": True, "image": {"name": "a.iso"}}, "storage": {"images": {"a.iso": {"size": 1}}}})
    assert device._status_at == 0.0  # (what is in its drive changed: looked at again when next asked)
    assert device._msd["storage"] == {"images": {"a.iso": {"size": 1}}, "parts": {}}
    assert (device.media_now() or {}).get("image") == "a.iso"


def test_an_image_is_deleted_from_the_kvm_and_not_while_it_is_mounted(tmp_path: Path, comet: FakeKvm) -> None:
    with wall(tmp_path) as admin:
        device = a_kvm(admin, comet)
        assert mount(admin, device).status_code == 200
        reply = delete(admin, device, DEBIAN)
        assert (reply.status_code, reply.json()["code"]) == (409, "busy") and DEBIAN in comet.state.msd_images
        reply = delete(admin, device, "alpine-3.21.iso", machine="another")
        assert (reply.status_code, reply.json()["code"]) == (409, "changed") and "alpine-3.21.iso" in comet.state.msd_images
        reply = delete(admin, device, "alpine-3.21.iso")
        assert (reply.status_code, reply.json()["note"]) == (200, None), reply.text
        assert "alpine-3.21.iso" not in comet.state.msd_images
        assert delete(admin, device, "alpine-3.21.iso").json()["note"] == "it was not on the KVM any more"
        assert [(entry["event"], entry["image"]) for entry in entries(admin, "media_deleted", "media_delete_failed")] == [
            ("media_delete_failed", DEBIAN), ("media_deleted", "alpine-3.21.iso"), ("media_deleted", "alpine-3.21.iso"),
        ]  # fmt: skip


def test_the_media_of_a_kvm_is_an_admins_in_person(tmp_path: Path, comet: FakeKvm) -> None:
    with wall(tmp_path) as admin:
        device = a_kvm(admin, comet)
        account(admin, "olga", "operator")
        olga = browser(admin, "olga", port=50061)
        token = admin.post("/api/v1/tokens", json={"name": "script", "role": "operator"}).json()["token"]
        robot = admin.__class__(admin.app, headers={"Authorization": f"Bearer {token}"}, client=("192.0.2.50", 51061))
        robot.portal = admin.portal
        for who in (olga, robot):
            for reply in (
                who.get(media(device)), mount(who, device), delete(who, device, DEBIAN), who.get(media(device) + "/upload"),
                who.post(media(device) + "/upload?name=x.iso&machine=glkvm", content=b"x"),
            ):  # fmt: skip
                assert (reply.status_code, reply.json()["code"]) == (403, "not_allowed"), reply.text
        assert comet.state.msd_calls == []


# --- carried through: an image into the KVM's own storage ---------------------------------------------------------


@pytest.fixture
def live_wall(tmp_path: Path) -> Iterator[Wall]:
    with Wall(tmp_path) as running:
        yield running


def upload(client: httpx.Client, device: str, body: Any, name: str = "new.iso", machine: str = "glkvm", length: int | None = None) -> httpx.Response:
    headers = {} if length is None else {"Content-Length": str(length)}
    return client.post(media(device) + "/upload", params={"name": name, "machine": machine}, content=body, headers=headers, timeout=120)


def refused_before_its_bytes(live_wall: Wall, client: httpx.Client, device: str, length: int, name: str = "new.iso", machine: str = "glkvm") -> tuple[int, dict[str, Any]]:
    """An upload the wall refuses before it reads a byte of it: its headers alone are sent, and the answer read whole.
    (Sent with its bytes as well, the connection is closed under a sender still sending, which may then see it reset and
    lose the answer: WinError 10054 on Windows 3.11, the requalification of 0.3.0. The page says these itself first.)"""
    cookie = "; ".join(f"{key}={value}" for key, value in client.cookies.items())
    with socket.create_connection(("127.0.0.1", live_wall.port), timeout=30) as sock:
        sock.sendall(f"POST {media(device)}/upload?name={name}&machine={machine} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {length}\r\nX-QKVM: 1\r\nCookie: {cookie}\r\n\r\n".encode())
        answer = b""
        while True:
            head, gap, body = answer.partition(b"\r\n\r\n")
            said = re.search(rb"(?im)^content-length:\s*(\d+)", head) if gap else None
            if said is not None and len(body) >= int(said.group(1)):
                break
            came = sock.recv(65536)
            assert came, answer
            answer += came
    return int(head.split()[1]), json.loads(body[: int(said.group(1))])


def pieces(total: int, size: int = 1 << 20, seed: bytes = b"qkvm") -> Iterator[bytes]:
    """`total` bytes of an image, made as they are sent (never held whole), the same each time for the same seed."""
    block = hashlib.sha256(seed).digest() * (size // 32)
    sent = 0
    while sent < total:
        piece = block[: min(size, total - sent)]
        sent += len(piece)
        yield piece


def hash_of(total: int, seed: bytes = b"qkvm") -> str:
    digest = hashlib.sha256()
    for piece in pieces(total, seed=seed):
        digest.update(piece)
    return digest.hexdigest()


def test_an_image_is_carried_into_the_kvm_hashed_on_its_way_and_its_hash_follows_it(live_wall: Wall, comet: FakeKvm) -> None:
    admin = live_wall.browser()
    device = live_wall.add(admin, comet.url, name="glkvm")
    wait_until(lambda: "media" in admin.get("/api/v1/status").json()[device].get("can", []), "the KVM's drive was never found", 10)
    size = 5_000_000
    reply = upload(admin, device, pieces(size), length=size)
    assert reply.status_code == 200, reply.text
    said = reply.json()
    assert said["sha256"] == hash_of(size) == comet.state.msd_images["new.iso"]["sha256"]
    assert {key: said["image"][key] for key in ("id", "size", "partial", "sha256")} == {"id": "new.iso", "size": size, "partial": False, "sha256": hash_of(size)}
    assert comet.state.msd_writes[-1] == {"name": "new.iso", "said": size, "received": size, "complete": True, "removed": False}
    assert comet.state.msd_calls[-1] == "write new.iso remove_incomplete=1"
    (entry,) = [one for one in live_wall.audit(admin, "media_uploaded")]
    assert {key: entry[key] for key in ("user", "device_id", "image", "size", "sha256")} == {"user": "admin", "device_id": device, "image": "new.iso", "size": size, "sha256": hash_of(size)}
    # Listed with its hash; mounted, the activity log says it of the mount too, and the status of what is in the drive.
    listed = admin.get(media(device)).json()["images"]
    assert next(one for one in listed if one["id"] == "new.iso")["sha256"] == hash_of(size)
    assert mount(admin, device, image="new.iso").status_code == 200
    assert live_wall.audit(admin, "media_mounted")[-1]["sha256"] == hash_of(size)
    assert admin.get(media(device)).json()["mounted"]["sha256"] == hash_of(size)
    # Another image of that name put there on the KVM itself is not said to be it.
    assert unmount(admin, device, image="new.iso").status_code == 200
    comet.state.msd_images["new.iso"]["mod_ts"] += 60
    assert next(one for one in admin.get(media(device)).json()["images"] if one["id"] == "new.iso")["sha256"] is None
    assert comet.state.msd_never == []


def test_an_image_kvmd_lists_a_moment_after_its_write_is_taken_as_written(live_wall: Wall, comet: FakeKvm) -> None:
    # (kvmd's own test environment, before the release of 0.3.0: a write answered whole, and the image listed some two
    # seconds later. The upload was said to have failed, "Nothing of it is left on the KVM", and it was there, whole.)
    comet.state.msd_lists_after = 2.0
    admin = live_wall.browser()
    device = live_wall.add(admin, comet.url, name="glkvm")
    wait_until(lambda: "media" in admin.get("/api/v1/status").json()[device].get("can", []), "the KVM's drive was never found", 10)
    size = 3_000_000
    reply = upload(admin, device, pieces(size), length=size)
    assert reply.status_code == 200, reply.text
    assert reply.json()["sha256"] == hash_of(size) and reply.json()["image"]["id"] == "new.iso"
    assert comet.state.msd_images["new.iso"]["complete"] and not any(call.startswith("remove") for call in comet.state.msd_calls)
    # Deleted, it is listed a moment longer, as it was: the delete is not said to have failed for it.
    reply = admin.post(media(device) + "/delete", json={"image": "new.iso", "machine": "glkvm"})
    assert reply.status_code == 200, reply.text
    assert "new.iso" not in comet.state.msd_images


def test_an_image_on_the_kvm_whole_after_a_failed_upload_is_not_said_to_be_gone(live_wall: Wall, comet: FakeKvm) -> None:
    # (kvmd says it wrote less than it was sent, and lists the image whole all the same: it stays, and is said to.)
    comet.state.msd_says_written = 1
    admin = live_wall.browser()
    device = live_wall.add(admin, comet.url, name="glkvm")
    wait_until(lambda: "media" in admin.get("/api/v1/status").json()[device].get("can", []), "the KVM's drive was never found", 10)
    reply = upload(admin, device, pieces(2_000_000), length=2_000_000)
    assert reply.status_code == 502, reply.text
    message = reply.json()["message"]
    assert "Nothing of it is left" not in message and "is on the KVM whole all the same" in message, message
    assert comet.state.msd_images["new.iso"]["complete"]


def test_an_image_kvmd_answered_whole_is_never_deleted_for_a_listing_that_lags(live_wall: Wall, comet: FakeKvm) -> None:
    # (The delta review of 0.3.0, M1: kvmd lists what its watch on the storage last saw. Where that was mid-write, the
    # image is listed incomplete for a moment after its write is answered whole: it was judged not whole and deleted.)
    comet.state.msd_lists_after, comet.state.msd_lists_stale = 2.0, True
    admin = live_wall.browser()
    device = live_wall.add(admin, comet.url, name="glkvm")
    wait_until(lambda: "media" in admin.get("/api/v1/status").json()[device].get("can", []), "the KVM's drive was never found", 10)
    size = 3_000_000
    reply = upload(admin, device, pieces(size), length=size)
    assert reply.status_code == 200, reply.text
    assert reply.json()["sha256"] == hash_of(size) and reply.json()["image"]["size"] == size
    assert "new.iso" in comet.state.msd_images and not any(call.startswith("remove") for call in comet.state.msd_calls)


def test_a_kvm_that_says_no_number_for_a_size_gets_an_answer_and_an_activity_entry(live_wall: Wall, comet: FakeKvm) -> None:
    # (The delta review, M2: the sentence of what a failed upload left formatted the KVM's size as a number, and a KVM
    # that said none raised TypeError: HTTP 500, and no media_upload_failed entry.)
    comet.state.msd_says_written, comet.state.msd_size_said = 1, "a lot"
    admin = live_wall.browser()
    device = live_wall.add(admin, comet.url, name="glkvm")
    wait_until(lambda: "media" in admin.get("/api/v1/status").json()[device].get("can", []), "the KVM's drive was never found", 10)
    reply = upload(admin, device, pieces(2_000_000), length=2_000_000)
    assert reply.status_code == 502, reply.text
    assert "is on the KVM whole all the same" in reply.json()["message"]
    assert live_wall.audit(admin, "media_upload_failed")


def test_an_upload_cut_off_by_its_tile_moved_to_another_kvm_takes_nothing_off_that_one(tmp_path: Path) -> None:
    # (The outside review of 0.3.0, Codex's M3: the tile was moved to another KVM while its upload ran; the cut-off
    # upload's leftovers were "taken off" by the client that took the tile's place, on the other KVM: a partial image of
    # the same name there, which was none of this upload's, was deleted.)
    original = FakeKvm(FakeState(msd=True, msd_write_pause=0.05, msd_keeps_incomplete=True)).start()
    theirs = images({"edit.iso": 987_654})
    theirs["edit.iso"]["complete"] = False
    other = FakeKvm(FakeState(msd=True, msd_images=theirs)).start()
    answers: list[httpx.Response] = []
    sending: threading.Thread | None = None
    try:
        with Wall(tmp_path / "wall") as live:
            admin = live.browser()
            device = live.add(admin, original.url, name="original")
            wait_until(lambda: "media" in admin.get("/api/v1/status").json()[device].get("can", []), "the KVM's drive was never found", 10)
            sending = threading.Thread(target=lambda: answers.append(upload(admin, device, pieces(20_000_000, size=65536), name="edit.iso", machine="original", length=20_000_000)))
            sending.start()
            wait_until(lambda: (admin.get(media(device) + "/upload").json()["uploading"] or {}).get("sent", 0) > 1_000_000, "the upload never began", 10)
            changed = admin.put(f"/api/v1/devices/{device}", json={"name": "replacement", "url": other.url, "password": "secret"})
            assert changed.status_code == 200, changed.text
            sending.join(40)
            assert not sending.is_alive() and answers, "the upload never ended"
            assert "edit.iso" in other.state.msd_images and not any(call.startswith("remove") for call in other.state.msd_calls), other.state.msd_calls
            message = answers[0].json()["message"]
            assert "may be on the device it was going to" in message and original.url in message, message
    finally:
        if sending is not None:
            sending.join(10)
        original.stop()
        other.stop()


def test_what_an_upload_may_not_be_is_refused_before_anything_reaches_the_kvm(live_wall: Wall, comet: FakeKvm, tmp_path: Path) -> None:
    admin = live_wall.browser()
    device = live_wall.add(admin, comet.url, name="glkvm")
    wait_until(lambda: "media" in admin.get("/api/v1/status").json()[device].get("can", []), "the KVM's drive was never found", 10)
    for name in ("../x.iso", ".hidden.iso", "a/b.iso", "trailing.iso ", "x.iso.incomplete", "été.iso", "x" * 201):
        reply = upload(admin, device, b"x" * 10, name=name)
        assert (reply.status_code, reply.json()["code"]) == (422, "invalid"), (name, reply.text)
    assert IMAGE_NAME.fullmatch("Win11_24H2_English_x64 (1).iso") and IMAGE_NAME.fullmatch("ubuntu-24.04.3-live-server-amd64.iso")
    reply = upload(admin, device, b"x" * 10, name=DEBIAN)
    assert (reply.status_code, reply.json()["code"]) == (409, "duplicate")
    status, said = refused_before_its_bytes(live_wall, admin, device, 7_000_000_000)  # (more than is free: refused before a byte goes)
    assert (status, said["code"]) == (507, "no_space"), said
    reply = upload(admin, device, b"x" * 10, machine="another")
    assert (reply.status_code, reply.json()["code"]) == (409, "changed")
    assert upload(admin, device, b"").json()["code"] == "invalid"
    assert comet.state.msd_writes == []
    # Its own rule for its length: said in advance, and 16 GB at the most, refused before it is read.
    with socket.create_connection(("127.0.0.1", live_wall.port), timeout=10) as sock:
        cookie = "; ".join(f"{key}={value}" for key, value in admin.cookies.items())
        sock.sendall(f"POST {media(device)}/upload?name=big.iso&machine=glkvm HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {MOST_UPLOAD + 1}\r\nX-QKVM: 1\r\nCookie: {cookie}\r\n\r\n".encode())
        answer = ""
        while "}" not in answer:  # (the answer whole: its headers come first, its words after)
            came = sock.recv(4096).decode()
            assert came, answer
            answer += came
    assert answer.startswith("HTTP/1.1 413") and "too_large" in answer and "16 GB" in answer
    reply = admin.post(media(device) + "/upload", params={"name": "x.iso", "machine": "glkvm"}, content=iter([b"x" * 10]))  # (chunked: no length)
    assert reply.status_code == 411
    # And the rest of the wall keeps its 64 KiB.
    assert admin.post(media(device), content=b"{" + b" " * 70_000 + b"}", headers={"Content-Type": "application/json"}).status_code == 413
    assert comet.state.msd_writes == []


@pytest.mark.parametrize("keeps", [False, True], ids=["kvmd_removes_it", "qkvm_removes_it"])
def test_an_upload_cut_off_leaves_nothing_on_the_kvm(live_wall: Wall, comet: FakeKvm, keeps: bool) -> None:
    comet.state.msd_keeps_incomplete = keeps  # (a kvmd that leaves what a cut write wrote: qKVM removes it)
    admin = live_wall.browser()
    device = live_wall.add(admin, comet.url, name="glkvm")
    wait_until(lambda: "media" in admin.get("/api/v1/status").json()[device].get("can", []), "the KVM's drive was never found", 10)
    cookie = "; ".join(f"{key}={value}" for key, value in admin.cookies.items())
    cut_off(live_wall.port, f"{media(device)}/upload?name=cut.iso&machine=glkvm", f"Cookie: {cookie}", 3_000_000, 1_000_000)
    wait_until(lambda: live_wall.audit(admin, "media_upload_failed"), "the cut-off upload was not written down", 20)
    (entry,) = live_wall.audit(admin, "media_upload_failed")
    assert (entry["image"], entry["size"]) == ("cut.iso", 3_000_000) and 0 < entry["sent"] < 3_000_000
    assert "stopped before the image came in full" in entry["error"] and "sha256" not in entry
    wait_until(lambda: "cut.iso" not in comet.state.msd_images, "what the cut-off upload wrote is on the KVM still", 10)
    assert comet.state.msd_writes[-1]["complete"] is False
    assert (comet.state.msd_calls[-1] == "remove cut.iso") is keeps
    assert admin.get(media(device) + "/upload").json() == {"uploading": None}


def test_an_upload_that_goes_quiet_is_cut_off_and_its_progress_is_said_meanwhile(live_wall: Wall, comet: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "UPLOAD_QUIET", 1.5)
    admin = live_wall.browser()
    device = live_wall.add(admin, comet.url, name="glkvm")
    wait_until(lambda: "media" in admin.get("/api/v1/status").json()[device].get("can", []), "the KVM's drive was never found", 10)
    go_on = threading.Event()

    def slow() -> Iterator[bytes]:
        yield b"a" * 2_000_000
        go_on.wait(20)  # (and then nothing, for longer than an upload may say nothing)

    answers: list[httpx.Response] = []
    sending = threading.Thread(target=lambda: answers.append(upload(admin, device, slow(), name="slow.iso", length=4_000_000)))
    sending.start()
    try:
        wait_until(lambda: (admin.get(media(device) + "/upload").json()["uploading"] or {}).get("sent") == 2_000_000, "the upload's progress was not said", 10)
        said = admin.get(media(device) + "/upload").json()["uploading"]
        assert {key: said[key] for key in ("name", "size", "by")} == {"name": "slow.iso", "size": 4_000_000, "by": "admin"}
        assert admin.get(media(device)).json()["uploading"]["name"] == "slow.iso"
        # Another upload to the same KVM meanwhile waits for it; a mount of it is refused.
        assert upload(admin, device, b"x", name="other.iso").json()["code"] == "busy"
        assert mount(admin, device, image="slow.iso").json()["code"] == "busy"
        wait_until(lambda: live_wall.audit(admin, "media_upload_failed"), "the quiet upload was never cut off", 15)
    finally:
        go_on.set()
        sending.join(30)
    assert "for 2 seconds" in live_wall.audit(admin, "media_upload_failed")[0]["error"] and "slow.iso" not in comet.state.msd_images


def test_an_upload_takes_no_more_memory_however_large_the_image(live_wall: Wall, comet: FakeKvm, tmp_path: Path) -> None:
    # The wall and the stand-in run in this process: what the whole of it holds at the most while 128 MB go through, against
    # what it holds otherwise. Neither keeps more than a piece or two of the image at a time.
    admin = live_wall.browser()
    device = live_wall.add(admin, comet.url, name="glkvm")
    wait_until(lambda: "media" in admin.get("/api/v1/status").json()[device].get("can", []), "the KVM's drive was never found", 10)
    peaks = {}
    for size in (8 * 1024 * 1024, 128 * 1024 * 1024):
        gc.collect()
        tracemalloc.start()
        try:
            before = tracemalloc.get_traced_memory()[0]
            tracemalloc.reset_peak()
            reply = upload(admin, device, pieces(size, size=256 * 1024), name=f"large-{size}.iso", length=size)
            peaks[size] = tracemalloc.get_traced_memory()[1] - before
        finally:
            tracemalloc.stop()
        assert reply.status_code == 200, reply.text
        assert reply.json()["sha256"] == comet.state.msd_images[f"large-{size}.iso"]["sha256"] == hash_of(size)
    # Sixteen times the image, and what is held at the most hardly more: nothing of it piles up anywhere on its way. (Through
    # the guard's middleware the body grew by some 45 KB a megabyte, 5.4 MB more for this one: see server.CarriedThrough.)
    assert peaks[128 * 1024 * 1024] - peaks[8 * 1024 * 1024] < 1024 * 1024, peaks
    assert peaks[128 * 1024 * 1024] < 8 * 1024 * 1024, peaks
    # Nothing was kept on the wall's disk either: no file of that size anywhere in its folder.
    assert not [path for path in tmp_path.rglob("*") if path.is_file() and path.stat().st_size >= 1_000_000]


def test_an_upload_from_somebody_who_may_no_longer_is_stopped(live_wall: Wall, comet: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "UPLOAD_ASK_EVERY", 0.2)
    admin = live_wall.browser()
    device = live_wall.add(admin, comet.url, name="glkvm")
    wait_until(lambda: "media" in admin.get("/api/v1/status").json()[device].get("can", []), "the KVM's drive was never found", 10)
    assert admin.post("/api/v1/users", json={"name": "ada", "role": "admin", "password": OTHER}).status_code == 201
    ada = live_wall.browser("ada", OTHER)
    demoted = threading.Event()

    def until_demoted() -> Iterator[bytes]:
        yield b"a" * 1_000_000
        demoted.wait(20)
        time.sleep(0.5)
        yield b"a" * 1_000_000

    answers: list[httpx.Response] = []
    sending = threading.Thread(target=lambda: answers.append(upload(ada, device, until_demoted(), name="ada.iso", length=3_000_000)))
    sending.start()
    try:
        wait_until(lambda: (admin.get(media(device) + "/upload").json()["uploading"] or {}).get("sent") == 1_000_000, "the upload never began", 10)
        ada_id = next(one["id"] for one in admin.get("/api/v1/users").json()["users"] if one["name"] == "ada")
        assert admin.put(f"/api/v1/users/{ada_id}", json={"name": "ada", "role": "operator"}).status_code == 200
        demoted.set()
        wait_until(lambda: live_wall.audit(admin, "media_upload_failed"), "the upload went on", 15)
    finally:
        demoted.set()
        sending.join(30)
    assert "may no longer" in live_wall.audit(admin, "media_upload_failed")[0]["error"] and "ada.iso" not in comet.state.msd_images


def test_an_image_carried_to_a_tile_edited_meanwhile_is_taken_off_by_the_client_that_took_its_place(live_wall: Wall, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeKvm(FakeState(msd=True, msd_write_pause=0.05, msd_keeps_incomplete=True)).start()
    try:
        admin = live_wall.browser()
        device = live_wall.add(admin, fake.url, name="glkvm")
        wait_until(lambda: "media" in admin.get("/api/v1/status").json()[device].get("can", []), "the KVM's drive was never found", 10)
        answers: list[httpx.Response] = []
        sending = threading.Thread(target=lambda: answers.append(upload(admin, device, pieces(20_000_000, size=65536), name="edit.iso", length=20_000_000)))
        sending.start()
        wait_until(lambda: (admin.get(media(device) + "/upload").json()["uploading"] or {}).get("sent", 0) > 1_000_000, "the upload never began", 10)
        renamed = admin.put(f"/api/v1/devices/{device}", json={"name": "glkvm-1", "url": fake.url, "password": ""})
        assert renamed.status_code == 200, renamed.text
        sending.join(60)
        assert answers and answers[0].status_code == 504, answers and answers[0].text
        assert "edit.iso" not in fake.state.msd_images and fake.state.msd_calls[-1] == "remove edit.iso"
    finally:
        fake.stop()


def test_names_left_out_of_a_kvms_listing_are_counted_and_never_handed_back(tmp_path: Path) -> None:
    odd = {name: {"complete": True, "removable": True, "size": 1, "mod_ts": 1.0, "sha256": ""} for name in (".hidden", "a\nb.iso", "x" * 300, "été.iso", "../up.iso")}
    fake = FakeKvm(FakeState(msd=True, msd_images={**images({DEBIAN: 700_000}), **odd, "folder/inside.iso": {"complete": True, "removable": True, "size": 700_000, "mod_ts": 1.0, "sha256": ""}})).start()
    try:
        with wall(tmp_path) as admin:
            device = a_kvm(admin, fake)
            body = admin.get(media(device)).json()
            assert [one["id"] for one in body["images"]] == [DEBIAN, "folder/inside.iso"] and body["left_out"] == 5
            assert mount(admin, device, image="folder/inside.iso").status_code == 200
            assert fake.state.msd_drive["image"] == "folder/inside.iso"
    finally:
        fake.stop()
