"""Virtual media on a JetKVM (0.3.0, A3): its own image storage, one image of it in its drive as a CD-ROM drive or a disk
(read-only either way), an image carried through qKVM into that storage, one deleted from it; over the connection the wall
holds, which is only ever to the JetKVM the tile was added for, and an upload's own connection only after the JetKVM that
answers at the address was asked again which it is.

Against the stand-in (fake_jetkvm.py), grown from the firmware's source for this (jsonrpc.go, usb_mass_storage.go at dev
d646be8, as in release 0.5.9). What is shared with every family is in test_virtual_media_on_a_proxmox_guest.py and
test_virtual_media_on_a_kvm.py (an upload's length, a cut-off or quiet one, its memory).
"""

from __future__ import annotations

import asyncio
import socket
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from qkvm import jetkvm, kvm
from qkvm.kvm import MEDIA_NOTES, DeviceSpec
from tests.fake_jetkvm import FakeJetKvm, JetState, no_long_handshake
from tests.test_live import Wall
from tests.test_proxmox import state_of
from tests.test_users import OTHER
from tests.test_virtual_media_on_a_kvm import hash_of, pieces, refused_before_its_bytes
from tests.test_wall import add, wait_until, wall

DEBIAN = "debian-13.iso"
OFFER = {
    "drives": ["cd", "disk"], "boot": [], "restart": False, "upload": True, "where": "device", "writable": [], "delete": True,
    "drops_input": True,
}  # fmt: skip
STAMP = "2026-10-30T09:12:44.000000+00:00"


@pytest.fixture(autouse=True)
def forgotten(monkeypatch: pytest.MonkeyPatch) -> None:
    MEDIA_NOTES.mounted.clear()
    MEDIA_NOTES.hashes.clear()
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 20)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)


def files(sizes: dict[str, int]) -> dict[str, dict[str, Any]]:
    return {name: {"size": size, "createdAt": STAMP, "sha256": ""} for name, size in sizes.items()}


@pytest.fixture
def jet() -> Iterator[FakeJetKvm]:
    fake = FakeJetKvm(JetState(files=files({DEBIAN: 700_000_000, "alpine-3.21.iso": 62_000_000}))).start()
    yield fake
    fake.stop()


def media(device: str) -> str:
    return f"/api/v1/devices/{device}/media"


def mount(client: Any, device: str, image: str = DEBIAN, machine: str = "jet", **more: Any) -> Any:
    return client.post(media(device), json={"image": image, "machine": machine, **more})


def unmount(client: Any, device: str, image: str = DEBIAN, machine: str = "jet") -> Any:
    return client.post(media(device) + "/unmount", json={"image": image, "machine": machine})


def entries(client: Any, *events: str) -> list[dict[str, Any]]:
    found = client.get("/api/v1/audit", params={"kind": "action", "limit": 500}).json()["entries"]
    return [entry for entry in reversed(found) if entry["event"] in events]


def a_jetkvm(client: Any, fake: FakeJetKvm) -> str:
    device = add(client, fake.url, name="jet")
    wait_until(lambda: "media" in state_of(client, device).get("can", []), "the JetKVM's storage was never found", 30)
    return device


# --- the stand-in, as the firmware's source says ------------------------------------------------------------------


def test_the_stand_in_keeps_the_firmwares_rules_for_its_storage_and_drive(jet: FakeJetKvm) -> None:
    async def asked() -> None:
        device = jetkvm.JetKvmDevice(DeviceSpec("x", "jet", jet.url, "", "secret", kind="jetkvm"))
        try:
            session = await device._connected(urgent=True)

            async def call(method: str, **params: Any) -> Any:
                return await device._call(session, method, params)

            assert await call("getVirtualMediaState") is None
            listed = await call("listStorageFiles")
            assert {one["filename"] for one in listed["files"]} == {DEBIAN, "alpine-3.21.iso"}
            assert await call("getStorageSpace") == {"bytesUsed": 762_000_000, "bytesFree": 6_238_000_000}
            # One image at a time; the drive's kind changed binds its USB device anew, and only then.
            await call("mountWithStorage", filename=DEBIAN, mode="CDROM")
            assert jet.state.rebinds == 0 and (await call("getVirtualMediaState"))["filename"] == DEBIAN
            with pytest.raises(kvm.KvmError, match="another virtual media is already mounted"):
                await call("mountWithStorage", filename="alpine-3.21.iso", mode="CDROM")
            await call("unmountImage")
            await call("mountWithStorage", filename="alpine-3.21.iso", mode="Disk")
            assert jet.state.rebinds == 1 and jet.state.cdrom_mode is False
            await call("unmountImage")
            # An upload: refused where the file is there; opened as `.incomplete`, said back where it was cut off before.
            with pytest.raises(kvm.KvmError, match="file already exists"):
                await call("startStorageFileUpload", filename=DEBIAN, size=10)
            started = await call("startStorageFileUpload", filename="new.iso", size=10)
            assert started["alreadyUploadedBytes"] == 0 and jetkvm.UPLOAD_ID.fullmatch(started["dataChannel"])
            assert "new.iso.incomplete" in jet.state.files
            # A path is cut to its last part (sanitizeFilename), and what is not there is said so.
            with pytest.raises(kvm.KvmError, match="file does not exist"):
                await call("deleteStorageFile", filename="folder/gone.iso")
        finally:
            await device.close()

    asyncio.run(asked())
    upload_id = next(iter(jet.state.uploads_open))
    with httpx.Client(base_url=jet.url, timeout=10) as asker:
        assert asker.post("/storage/upload", params={"uploadId": upload_id}, content=b"x").status_code == 401  # (signed in, or nothing)
        asker.cookies.set("authToken", jet.state.token or "")
        # It answers "Upload completed" to a body that ended early, and keeps what came as `.incomplete`.
        assert asker.post("/storage/upload", params={"uploadId": upload_id}, content=b"12345").json() == {"message": "Upload completed"}
        assert "new.iso" not in jet.state.files and jet.state.files["new.iso.incomplete"]["size"] == 5
        assert asker.post("/storage/upload", params={"uploadId": upload_id}, content=b"x").status_code == 404  # (claimed once)
    assert jet.state.media_never == []


# --- mounting ------------------------------------------------------------------------------------------------------


def test_a_jetkvm_lists_its_images_and_mounts_one_read_only_as_a_cd_or_a_disk(tmp_path: Path, jet: FakeJetKvm) -> None:
    with wall(tmp_path) as admin:
        device = a_jetkvm(admin, jet)
        body = admin.get(media(device)).json()
        assert [(one["id"], one["name"], one["size"], one["partial"]) for one in body["images"]] == [
            ("alpine-3.21.iso", "alpine-3.21.iso", 62_000_000, False), (DEBIAN, DEBIAN, 700_000_000, False),
        ]  # fmt: skip
        assert body["offers"] == OFFER and body["space"] == {"free": 6_238_000_000, "size": 7_000_000_000} and body["mounted"] is None
        reply = mount(admin, device)
        assert reply.status_code == 200, reply.text
        assert jet.state.mounted == {"source": "Storage", "mode": "CDROM", "filename": DEBIAN, "size": 700_000_000} and jet.state.rebinds == 0
        mounted = reply.json()["mounted"]
        assert {key: mounted[key] for key in ("drive", "image", "read_only", "first", "by")} == {"drive": "cd", "image": DEBIAN, "read_only": True, "first": None, "by": "admin"}
        wait_until(lambda: (state_of(admin, device).get("media") or {}).get("name") == DEBIAN, "the tile does not say what is in the drive")
        assert entries(admin, "media_mounted")[0]["drive"] == "cd"
        # One at a time, and never writable: its drive has no such way, whatever is asked.
        assert mount(admin, device, image="alpine-3.21.iso").json()["code"] == "changed"
        assert unmount(admin, device).status_code == 200 and jet.state.mounted is None
        for asked in ({"drive": "disk", "writable": True}, {"drive": "flash"}, {"boot": "once"}, {"restart": True}):
            reply = mount(admin, device, **asked)
            assert (reply.status_code, reply.json()["code"]) == (422, "invalid"), (asked, reply.text)
        # As a disk: its USB device bound anew (keyboard and mouse drop for a moment, as the offer says).
        reply = mount(admin, device, drive="disk")
        assert reply.status_code == 200, reply.text
        assert jet.state.mounted["mode"] == "Disk" and jet.state.rebinds == 1 and reply.json()["mounted"]["drive"] == "disk"
        assert unmount(admin, device).status_code == 200
    assert jet.state.media_never == []
    assert not any(call.startswith(("mountWithHTTP", "checkMountUrl")) for call in jet.state.media_calls)


def test_an_image_too_small_for_a_cd_rom_drive_is_said_so_before_the_jetkvm_is_asked(tmp_path: Path, jet: FakeJetKvm) -> None:
    # (A trial on a real JetKVM before the release of 0.3.0: a 368 KB image mounted as a CD-ROM drive was refused with
    # the kernel's own words, "... lun.0/file: errno 525", and the box showed them as they came.)
    jet.state.files["tiny.iso"] = {"size": 376_832, "createdAt": STAMP, "sha256": ""}
    with wall(tmp_path) as admin:
        device = a_jetkvm(admin, jet)
        reply = mount(admin, device, image="tiny.iso")
        assert (reply.status_code, reply.json()["code"]) == (422, "invalid"), reply.text
        assert reply.json()["message"] == (
            "tiny.iso is 376,832 bytes, and a CD-ROM drive takes an image of 614,400 bytes at least (300 sectors of 2,048 "
            "bytes): mount it as a disk."
        )
        assert not any(call.startswith("mountWithStorage") for call in jet.state.media_calls) and jet.state.mounted is None
        reply = mount(admin, device, image="tiny.iso", drive="disk")  # (a disk takes it)
        assert reply.status_code == 200, reply.text
        assert unmount(admin, device, image="tiny.iso").status_code == 200


def test_what_is_mounted_at_the_jetkvms_own_page_from_an_address_is_said_without_the_address(tmp_path: Path, jet: FakeJetKvm) -> None:
    jet.state.mounted = {"source": "HTTP", "mode": "CDROM", "url": "https://user:secret@192.0.2.7/boot.iso", "size": 1}
    with wall(tmp_path) as admin:
        device = a_jetkvm(admin, jet)
        said = admin.get(media(device)).json()["mounted"]
        assert said["image"] == "(an address)" and "192.0.2.7" not in str(said) and "secret" not in str(state_of(admin, device))
        assert mount(admin, device).json()["code"] == "changed"  # (one at a time)
        assert unmount(admin, device, image="(an address)").status_code == 200 and jet.state.mounted is None


def test_an_older_jetkvm_without_storage_offers_nothing(tmp_path: Path) -> None:
    fake = FakeJetKvm(JetState(storage=False)).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url)
            wait_until(lambda: state_of(admin, device).get("state") == "online", "the JetKVM never came online", 30)
            assert "media" not in state_of(admin, device)["can"] and state_of(admin, device)["media"] is None
            assert admin.get(media(device)).json()["code"] == "no_virtual_media"
    finally:
        fake.stop()


def test_a_jetkvm_with_its_atx_extension_is_restarted_for_the_image(tmp_path: Path) -> None:
    fake = FakeJetKvm(JetState(extension="atx-power", files=files({DEBIAN: 7_000_000}))).start()
    try:
        with wall(tmp_path) as admin:
            device = a_jetkvm(admin, fake)
            wait_until(lambda: admin.get(media(device)).json()["offers"]["restart"] is True, "the ATX extension was never found", 20)
            reply = mount(admin, device, restart=True)
            assert reply.status_code == 200, reply.text
            assert fake.state.actions[-1] == "atx reset" and "boot menu" in reply.json()["note"]
            assert [entry["event"] for entry in entries(admin, "media_mounted", "media_restarted")] == ["media_mounted", "media_restarted"]
    finally:
        fake.stop()


def test_an_image_is_deleted_from_the_jetkvm_and_not_while_it_is_mounted(tmp_path: Path, jet: FakeJetKvm) -> None:
    jet.state.files["cut.iso.incomplete"] = {"size": 5, "createdAt": STAMP, "sha256": ""}
    with wall(tmp_path) as admin:
        device = a_jetkvm(admin, jet)
        listed = admin.get(media(device)).json()["images"]
        assert next(one for one in listed if one["id"] == "cut.iso.incomplete") == {"id": "cut.iso.incomplete", "name": "cut.iso", "where": None, "size": 5, "partial": True, "sha256": None}
        assert mount(admin, device, image="cut.iso.incomplete").json()["code"] == "invalid"  # (a part of one: only to delete)
        assert mount(admin, device).status_code == 200
        assert admin.post(media(device) + "/delete", json={"image": DEBIAN, "machine": "jet"}).json()["code"] == "busy"
        for image in ("cut.iso.incomplete", "alpine-3.21.iso"):
            reply = admin.post(media(device) + "/delete", json={"image": image, "machine": "jet"})
            assert reply.status_code == 200, reply.text
        assert set(jet.state.files) == {DEBIAN}


# --- carried through: an image into the JetKVM's own storage --------------------------------------------------------


@pytest.fixture
def live_wall(tmp_path: Path) -> Iterator[Wall]:
    with Wall(tmp_path) as running:
        yield running


def upload(client: httpx.Client, device: str, body: Any, name: str = "new.iso", length: int | None = None) -> httpx.Response:
    headers = {} if length is None else {"Content-Length": str(length)}
    return client.post(media(device) + "/upload", params={"name": name, "machine": "jet"}, content=body, headers=headers, timeout=120)


def ready(live_wall: Wall, fake: FakeJetKvm) -> tuple[httpx.Client, str]:
    admin = live_wall.browser()
    device = live_wall.add(admin, fake.url, name="jet")
    wait_until(lambda: "media" in admin.get("/api/v1/status").json()[device].get("can", []), "the JetKVM's storage was never found", 30)
    return admin, device


def test_an_image_is_carried_into_the_jetkvm_after_it_is_asked_which_it_is(live_wall: Wall, jet: FakeJetKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    admin, device = ready(live_wall, jet)
    asked: list[str] = []
    real = jetkvm.JetKvmDevice._same_jetkvm

    async def noted(self: Any, token: Any, taking: bool = False) -> None:
        asked.append(f"asked, with {len(jet.state.uploads_open)} upload(s) open")
        await real(self, token, taking)

    monkeypatch.setattr(jetkvm.JetKvmDevice, "_same_jetkvm", noted)
    size = 3_000_000
    reply = upload(admin, device, pieces(size), length=size)
    assert reply.status_code == 200, reply.text
    assert reply.json()["sha256"] == hash_of(size) == jet.state.files["new.iso"]["sha256"]
    assert asked == ["asked, with 1 upload(s) open"]  # (after the upload was opened over the connection, before its bytes went)
    assert jet.state.uploads[-1]["complete"] is True and "new.iso.incomplete" not in jet.state.files
    assert live_wall.audit(admin, "media_uploaded")[0]["sha256"] == hash_of(size)
    assert mount(admin, device, image="new.iso").status_code == 200
    assert live_wall.audit(admin, "media_mounted")[-1]["sha256"] == hash_of(size)
    assert jet.state.media_never == []


def test_another_jetkvm_at_the_address_is_sent_none_of_the_image(live_wall: Wall, jet: FakeJetKvm) -> None:
    admin, device = ready(live_wall, jet)
    assert admin.get(media(device)).status_code == 200  # (the connection held, to the JetKVM this tile was added for)
    jet.state.device_id = "0a0b0c0d0e0f1011"  # (another one answers at the address now, as after a new lease)
    reply = upload(admin, device, b"x" * 1000)
    assert (reply.status_code, reply.json()["code"]) == (502, "another_machine"), reply.text
    assert jet.state.uploads == [] and "new.iso.incomplete" not in jet.state.files  # (opened over the connection, and taken off again)


def test_what_a_jetkvm_upload_may_not_be_is_refused(live_wall: Wall, jet: FakeJetKvm) -> None:
    jet.state.files["half.iso.incomplete"] = {"size": 5, "createdAt": STAMP, "sha256": ""}
    admin, device = ready(live_wall, jet)
    assert upload(admin, device, b"x", name=DEBIAN).json()["code"] == "duplicate"
    reply = upload(admin, device, b"x", name="half.iso")  # (resumed, the JetKVM would add to what an earlier one left)
    assert reply.json()["code"] == "duplicate" and "earlier upload" in reply.json()["message"]
    status, said = refused_before_its_bytes(live_wall, admin, device, 6_500_000_000, machine="jet")
    assert (status, said["code"]) == (507, "no_space"), said
    assert [call for call in jet.state.media_calls if call.startswith("startStorageFileUpload")] == []


def test_an_upload_to_a_jetkvm_cut_off_leaves_nothing_there(live_wall: Wall, jet: FakeJetKvm) -> None:
    jet.state.upload_pause = 0.01
    admin, device = ready(live_wall, jet)
    cookie = "; ".join(f"{key}={value}" for key, value in admin.cookies.items())
    with socket.create_connection(("127.0.0.1", live_wall.port), timeout=10) as sock:
        sock.sendall(f"POST {media(device)}/upload?name=cut.iso&machine=jet HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 3000000\r\nX-QKVM: 1\r\nCookie: {cookie}\r\n\r\n".encode() + b"z" * 1_000_000)
        time.sleep(0.5)
    wait_until(lambda: live_wall.audit(admin, "media_upload_failed"), "the cut-off upload was not written down", 20)
    wait_until(lambda: not any(name.startswith("cut.iso") for name in jet.state.files), "what the cut-off upload wrote is on the JetKVM still", 10)
    assert jet.state.uploads[-1]["complete"] is False


def test_the_part_of_an_upload_under_way_is_not_deleted_meanwhile(live_wall: Wall, jet: FakeJetKvm) -> None:
    # (The final review of 0.3.0: the JetKVM lists an upload under way as `<name>.incomplete`, which was not taken for it.)
    jet.state.upload_pause = 0.01
    admin, device = ready(live_wall, jet)
    cookie = "; ".join(f"{key}={value}" for key, value in admin.cookies.items())
    with socket.create_connection(("127.0.0.1", live_wall.port), timeout=10) as sock:
        sock.sendall(f"POST {media(device)}/upload?name=slow.iso&machine=jet HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 3000000\r\nX-QKVM: 1\r\nCookie: {cookie}\r\n\r\n".encode() + b"z" * 1_000_000)
        wait_until(lambda: "slow.iso.incomplete" in jet.state.files, "the upload was never opened on the JetKVM", 20)
        for image in ("slow.iso.incomplete", "slow.iso"):
            reply = admin.post(media(device) + "/delete", json={"image": image, "machine": "jet"})
            assert (reply.status_code, reply.json()["code"]) == (409, "busy"), (image, reply.text)
        assert "slow.iso.incomplete" in jet.state.files
    wait_until(lambda: live_wall.audit(admin, "media_upload_failed"), "the cut-off upload was not written down", 20)


def test_a_mount_that_drops_the_keyboard_waits_for_somebody_else_who_has_it(live_wall: Wall, jet: FakeJetKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    no_long_handshake(monkeypatch, jet.state.hidrpc)
    admin, device = ready(live_wall, jet)
    assert admin.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": OTHER}).status_code == 201
    olga = live_wall.browser("olga", OTHER)
    line = live_wall.line(olga, device, max_fps=5)
    line.picture(timeout=30)
    line.say(t="control", on=True)
    assert line.word("control")["on"] is True
    for asked in (mount(admin, device), mount(admin, device, drive="disk"), unmount(admin, device)):
        assert (asked.status_code, asked.json()["code"], asked.json()["by"]) == (409, "busy", "olga"), asked.text
    assert jet.state.mounted is None
    # Uploads and deletions touch no USB device: they go on.
    assert upload(admin, device, b"y" * 1000, name="small.iso").status_code == 200
    line.close()
