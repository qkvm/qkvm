"""Virtual media on a server (0.3.0, A4): an ISO image of the folder the admin names, mounted in the server's virtual
CD-ROM drive over Redfish (InsertMedia, EjectMedia), and the server started from it once or until it is unmounted (the
"Cd" boot override, Once or Continuous). The controller reads the image from qKVM, by an address made for that mount alone
(served.py): with a range, from its own address alone, with the user and password of the mount over HTTPS, and not after
the image is taken out. AMI's controller first has its remote media switched on (Oem AMIVirtualMedia.EnableRMedia), takes
HTTPS alone, and answers with a task. What every family shares holds as for the others: an admin's in person, the
confirmation naming the machine and the image, the activity log, and the server the tile was added for and no other.

Against the stand-in (fake_redfish.py), grown for this from the standard's VirtualMedia (v1.7) and AMI's documented
actions; it reads the image back from the wall over a real connection, as a controller does.
"""

from __future__ import annotations

from urllib.parse import urlsplit
import socket
import asyncio
import base64
import contextlib
import hashlib
import io
import logging
import os
import threading
import time
import types
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from qkvm import kvm, redfish, served, server
from qkvm.served import address_of, basic_matches, byte_range, listing, url_name
from tests.fake_kvm import make_device_certificate
from tests.fake_redfish import BmcState, FakeBmc
from tests.test_live import Wall
from tests.test_redfish import fast, status_of  # noqa: F401  (`fast`: the same short waits, by name)
from tests.test_users import OTHER, account, browser
from tests.test_wall import CSRF, PASSWORD, add, wait_until, wall

DEBIAN, ALPINE = "debian-13.iso", "alpine 3.21.iso"
SIZE = 300_000


def iso(seed: str, size: int = SIZE) -> bytes:
    """`size` bytes standing for an image, the same for the same seed."""
    return (hashlib.sha256(seed.encode()).digest() * (size // 32 + 1))[:size]


@pytest.fixture(autouse=True)
def quick(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(redfish, "MEDIA_LOOK_EVERY", 0)  # (every look at the server reads its drive)
    monkeypatch.setattr(redfish, "TASK_EVERY", 0.05)
    monkeypatch.setattr(redfish, "CONFIRM_WITHIN", 3.0)


@pytest.fixture
def images(tmp_path: Path) -> Path:
    folder = tmp_path / "images"
    folder.mkdir()
    (folder / DEBIAN).write_bytes(iso(DEBIAN))
    (folder / ALPINE).write_bytes(iso(ALPINE, 40_000))
    (folder / "notes.txt").write_text("not an image")  # (no image: not listed, and not counted)
    (folder / ".hidden.iso").write_bytes(b"x")  # (a name qKVM hands on to nobody: left out)
    (folder / "old.iso").mkdir()  # (a folder: left out)
    return folder


@pytest.fixture
def bmc() -> Iterator[FakeBmc]:
    fake = FakeBmc(BmcState(virtual_media="standard")).start()
    yield fake
    fake.stop()


def media(device: str) -> str:
    return f"/api/v1/devices/{device}/media"


def mount(client: Any, device: str, image: str = DEBIAN, machine: str | None = None, **more: Any) -> Any:
    return client.post(media(device), json={"image": image, "machine": machine or client.machine, **more}, timeout=60)


def unmount(client: Any, device: str, image: str = DEBIAN, machine: str | None = None) -> Any:
    return client.post(media(device) + "/unmount", json={"image": image, "machine": machine or client.machine}, timeout=60)


def entries(client: Any, *events: str) -> list[dict[str, Any]]:
    """The activity log's entries of these events, oldest first."""
    found = client.get("/api/v1/audit", params={"kind": "action", "limit": 500}).json()["entries"]
    return [entry for entry in reversed(found) if entry["event"] in events]


def media_settings(client: Any, folder: Path | str, address: str) -> None:
    reply = client.put("/api/v1/settings/media", json={"folder": str(folder), "address": address})
    assert reply.status_code == 200, reply.text


def a_server(client: Any, fake: FakeBmc) -> str:
    """The server on the wall, once a look at it has found its virtual media (the confirmation's name kept as `machine`)."""
    device = add(client, fake.url)
    client.machine = client.get("/api/v1/wall").json()["devices"][0]["name"]
    wait_until(lambda: "media" in status_of(client, device)["can"], "the server's virtual media was never found", 10)
    return device


def sent(fake: FakeBmc, *what: str) -> list[str]:
    """The requests of these kinds the controller was sent ("InsertMedia", "EjectMedia", "EnableRMedia", "PATCH", "Reset")."""
    return [one for one in fake.state.requests if any(word in one for word in what) and (not one.startswith("GET"))]


def reader(local: str = "127.0.0.1", verify: bool = False) -> httpx.Client:
    """A client that reads from where a controller would (or from another of this computer's addresses)."""
    return httpx.Client(transport=httpx.HTTPTransport(local_address=local, verify=verify), verify=verify, timeout=10)


# --- what the served part does, on its own ---------------------------------------------------------------------------


def test_ranges_credentials_addresses_and_the_folder_are_read_as_meant(images: Path) -> None:
    assert byte_range(None, 100) == (0, 99, False) and byte_range("", 100) == (0, 99, False)
    assert byte_range("bytes=0-9", 100) == (0, 9, True) and byte_range("bytes=90-", 100) == (90, 99, True)
    assert byte_range("bytes=-10", 100) == (90, 99, True) and byte_range("bytes=-500", 100) == (0, 99, True)
    assert byte_range("bytes=50-5000", 100) == (50, 99, True)
    for whole in ("bytes=0-1,5-9", "items=0-9", "bytes=9-1", "bytes=-", "bytes=x-1"):
        assert byte_range(whole, 100) == (0, 99, False), whole  # (not one range of bytes: the whole, as HTTP lets a server answer)
    for past in ("bytes=100-", "bytes=500-600", "bytes=-0"):
        assert byte_range(past, 100) is None, past
    good = ("qkvm-1234", "s3cret:with:colons")
    said ="Basic " + base64.b64encode(b"qkvm-1234:s3cret:with:colons").decode()
    assert basic_matches(said, good) and basic_matches(said.replace("Basic", "basic"), good)
    for wrong in ("", "Bearer x", "Basic " + base64.b64encode(b"qkvm-1234:s3cret").decode(), "Basic !!", "Basic " + base64.b64encode(b"qkvm-1234").decode()):
        assert not basic_matches(wrong, good), wrong
    assert address_of("https://192.168.1.10:8787") == "https://192.168.1.10:8787" and address_of("http://KVM.lan/") == "http://kvm.lan"
    assert address_of("https://[fd00::5]:8787") == "https://[fd00::5]:8787"
    for odd in ("ftp://x", "https://x/a", "https://x?y", "https://u:p@x", "x:8787", "https://", "https://x:0", "https://[zz]:1", "https://a b"):
        assert address_of(odd) is None, odd
    assert url_name(ALPINE) == "alpine_3.21.iso" and url_name("a[1]+b~.iso") == "a_1__b_.iso"
    found, unseen, left_out = listing(str(images))
    assert [one.name for one in found] == [ALPINE, DEBIAN] and unseen == [] and left_out == 2
    assert [one.size for one in found] == [40_000, SIZE]
    assert listing("")[1] and listing("images")[1] and "not there" in listing(str(images / "nope"))[1][0]
    # A controller's virtual drives, as the driver reads them.
    assert redfish.is_cd({"MediaTypes": ["CD", "DVD"]}) and redfish.is_cd({"Id": "CD1"}) and redfish.is_cd({"MediaTypes": ["DVD"], "Id": "X"})
    for odd in ({"MediaTypes": ["USBStick"], "Id": "CD1"}, {"Id": "USB1"}, {"MediaTypes": []}, None, "CD1"):
        assert not redfish.is_cd(odd), odd
    token = "T" * 43
    ours = {"Inserted": True, "Image": f"https://10.0.0.5:8787/media/{token}/{DEBIAN}", "ImageName": DEBIAN}
    assert redfish.holds(ours, token, (DEBIAN,)) is True and redfish.holds({**ours, "Inserted": False}, token, (DEBIAN,)) is False
    assert redfish.holds({**ours, "Image": ours["Image"].replace(token, "U" * 43)}, token, (DEBIAN,)) is False  # (another of qKVM's)
    assert redfish.stale({**ours, "Image": ours["Image"].replace(token, "U" * 43)}, token) and not redfish.stale(ours, token)
    assert redfish.holds({"Inserted": True, "ImageName": DEBIAN}, token, (DEBIAN,)) is True  # (its name alone, as some show it)
    assert redfish.holds({"Inserted": True, "Image": "nfs://192.0.2.7/x/rescue.iso"}, token, (DEBIAN,)) is False
    assert redfish.holds({"Inserted": True}, token, (DEBIAN,)) is None and redfish.holds({"ConnectedVia": "URI"}, token, (DEBIAN,)) is None
    assert redfish.image_said({"Image": "https://user:pw@192.0.2.7/share/rescue%20x.iso?token=abc"}) == "rescue x.iso"
    assert redfish.image_said({"ImageName": "debian.iso", "Image": "https://192.0.2.7/a.iso"}) == "debian.iso"
    assert redfish.image_said({}) == "an image put there elsewhere"
    # What a controller says back of a mount (its address, its token, its user and password) is never said on (the final
    # review of 0.3.0): as the name of what is in its drive, or in its words of a refusal.
    assert redfish.image_said({"ImageName": ours["Image"]}) == DEBIAN  # (its address given as its name: said as an address is)
    assert redfish.image_said({"Image": f"https://10.0.0.5:8787/media/{token}"}) == "(hidden)"
    assert redfish.image_said({"ImageName": f"{DEBIAN} {token}"}) == f"{DEBIAN} (hidden)"
    password = "p" * 32
    lent = served.Lending(token, "d", "http://x", frozenset(), served.FolderImage(DEBIAN, "x", 1, (0, 0, 0)), ("qkvm-1234", password), ours["Image"], "admin")
    assert served.scrubbed(f"{ours['Image']} as qkvm-1234 with {password}", lent) == "(hidden) as (hidden) with (hidden)"
    assert served.scrubbed(f"at {ours['Image'].upper()} and {'U' * 43}.") == f"at HTTPS://10.0.0.5:8787/MEDIA/(hidden)/{DEBIAN.upper()} and (hidden)."
    assert served.scrubbed("a" * 44) == "a" * 44  # (a longer run of such letters is no token of qKVM's)


def test_the_walls_address_for_the_controllers_is_one_they_reach(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Where the settings name none: the first place it listens on the network. On all of the computer's addresses (IPv6's
    # "::", the final review of 0.3.0, as 0.0.0.0 is): its address on the network, not "[::]", which no controller reaches.
    from qkvm import core as core_module

    monkeypatch.setattr(core_module, "lan_ip", lambda: "192.168.1.20")
    wall_core = core_module.Core(tmp_path / "data")
    wall_core.listening = ["http://127.0.0.1:8787/", "http://[::]:8787/"]
    assert wall_core.media_address() == "http://192.168.1.20:8787"
    wall_core.listening = ["https://127.0.0.1:8787/", "https://192.168.1.5:8787/", "https://[::]:8787/"]
    assert wall_core.media_address() == "https://192.168.1.5:8787"
    monkeypatch.setattr(core_module, "lan_ip", lambda: None)
    wall_core.listening = ["http://127.0.0.1:8787/", "http://[::]:8787/"]
    assert wall_core.media_address() is None


# --- mounting, reading, and what is said of it ------------------------------------------------------------------------


def test_an_admin_mounts_an_image_its_controller_reads_it_from_qkvm_and_the_tile_and_the_log_say_so(tmp_path: Path, images: Path, bmc: FakeBmc) -> None:
    with Wall(tmp_path / "wall") as live:
        admin = live.browser()
        device = a_server(admin, bmc)
        media_settings(admin, images, live.url)
        wait_until(lambda: "media" in status_of(admin, device, state="online")["can"], "the server's drive was never found", 10)
        listed = admin.get(media(device))
        assert listed.status_code == 200, listed.text
        body = listed.json()
        assert [(one["id"], one["name"], one["where"], one["size"]) for one in body["images"]] == [(ALPINE, ALPINE, None, 40_000), (DEBIAN, DEBIAN, None, SIZE)]
        assert body["offers"] == {
            "drives": ["cd"], "boot": ["once", "until_unmounted"], "restart": True, "upload": False, "where": "qkvm",
            "writable": [], "delete": False, "drops_input": False,
        }  # fmt: skip
        assert (body["mounted"], body["unseen"], body["notes"], body["left_out"], body["served_from"]) == (None, [], [], 2, live.url)

        reply = mount(admin, device)
        assert reply.status_code == 200, reply.text
        (said,) = bmc.state.media_said
        address = said["Image"]
        assert address.startswith(f"{live.url}/media/") and address.endswith(f"/{DEBIAN}") and len(address.split("/")[-2]) == 43
        assert {key: said[key] for key in said if key != "Image"} == {"TransferProtocolType": "HTTP", "Inserted": True, "WriteProtected": True, "TransferMethod": "Stream"}
        # It read the image from qKVM before it showed it, a piece at a time, and got what is in the file.
        whole = iso(DEBIAN)
        assert [(status, asked) for status, asked, _ in bmc.state.media_read] == [(206, "bytes=0-2047"), (206, f"bytes={SIZE - 2048}-")]
        assert [got for _, _, got in bmc.state.media_read] == [whole[:2048], whole[-2048:]]
        mounted = reply.json()["mounted"]
        assert {key: mounted[key] for key in ("drive", "image", "name", "where", "read_only", "by", "sha256")} == {
            "drive": "cd", "image": DEBIAN, "name": DEBIAN, "where": "qKVM", "read_only": True, "by": "admin", "sha256": None,
        }  # fmt: skip
        (entry,) = (one for one in live.audit(admin, "media_mounted") if one["event"] == "media_mounted")
        assert (entry["user"], entry["device_id"], entry["image"], entry["boot"]) == ("admin", device, DEBIAN, "none")
        assert address not in str(live.audit(admin, "media"))  # (the address, with its token, is said to the controller and to nobody else)
        # Said to everybody who sees the tile, a viewer as well; the address never.
        account(admin, "victor", "viewer")
        victor = live.browser("victor", password=OTHER)
        wait_until(lambda: (status_of(victor, device).get("media") or {}).get("name") == DEBIAN, "the tile does not say what is in the drive")
        assert address.split("/")[-2] not in victor.get("/api/v1/status").text

        with reader() as controller:
            # As the controller reads it: by the address it was given, from its own address, a range at a time.
            head = controller.head(address)
            assert (head.status_code, head.headers["content-length"], head.headers["accept-ranges"]) == (200, str(SIZE), "bytes")
            part = controller.get(address, headers={"Range": "bytes=-10"})
            assert (part.status_code, part.headers["content-range"], part.content) == (206, f"bytes {SIZE - 10}-{SIZE - 1}/{SIZE}", whole[-10:])
            assert controller.get(address).content == whole
            assert controller.get(address, headers={"Range": f"bytes={SIZE}-"}).status_code == 416
            # Another token, another name, the other image: there is nothing at those addresses.
            token = address.split("/")[-2]
            for odd in (address.replace(token, "A" * 43), address.replace(DEBIAN, url_name(ALPINE)), address.rsplit("/", 1)[0], f"{live.url}/media/"):
                assert controller.get(odd).status_code == 404, odd
        with reader("127.0.0.2") as stranger:
            # From another address than the controller's: nothing, whatever it brings.
            refused = stranger.get(address, headers={"Range": "bytes=0-9"})
            assert (refused.status_code, refused.content) == (404, b"There is nothing at this address.")

        reply = unmount(admin, device)
        assert reply.status_code == 200, reply.text
        assert (reply.json()["note"], reply.json()["mounted"]) == (None, None)
        assert bmc.state.media_ejects == 1 and not bmc.state.media_inserted
        with reader() as controller:
            assert controller.get(address, headers={"Range": "bytes=0-9"}).status_code == 404  # (taken out: the address is gone with it)
        (entry,) = (one for one in live.audit(admin, "media_unmounted") if one["event"] == "media_unmounted")
        assert (entry["user"], entry["device_id"], entry["image"]) == ("admin", device, DEBIAN)
        again = unmount(admin, device)
        assert (again.status_code, again.json()["note"]) == (200, "nothing was mounted") and bmc.state.media_ejects == 1


def test_a_server_starts_from_its_image_once_or_until_it_is_unmounted(tmp_path: Path, images: Path, bmc: FakeBmc) -> None:
    bmc.state.media_fetch = False  # (not read back: this wall answers in-process, at no address)
    with wall(tmp_path) as admin:
        device = a_server(admin, bmc)
        media_settings(admin, images, "http://127.0.0.1:9")
        # Once: the "Cd" override for its next start, and the server restarted (one that is on); it starts from the image, and
        # its controller clears that override as it starts.
        reply = mount(admin, device, boot="once")
        assert reply.status_code == 200, reply.text
        assert "this once" in reply.json()["note"]
        assert {"Boot": {"BootSourceOverrideEnabled": "Once", "BootSourceOverrideTarget": "Cd"}} in bmc.state.changes
        assert bmc.state.actions == ["system ForceRestart"] and bmc.state.booted == [f"cd {DEBIAN}"] and bmc.state.boot_override == ("Disabled", "None")
        assert [one["event"] for one in entries(admin, "media_mounted", "media_booted")] == ["media_mounted", "media_booted"]
        assert unmount(admin, device).status_code == 200
        assert bmc.state.boot_override == ("Disabled", "None") and not bmc.state.media_inserted
        # Until it is unmounted, without a restart: "Continuous", and nothing pressed; at the unmount, set back.
        changes = len(bmc.state.changes)
        reply = mount(admin, device, boot="until_unmounted")
        assert reply.status_code == 200, reply.text
        assert "next start" in reply.json()["note"] and reply.json()["mounted"]["first"] is True
        assert bmc.state.boot_override == ("Continuous", "Cd") and bmc.state.actions == ["system ForceRestart"]
        reply = unmount(admin, device)
        assert reply.status_code == 200, reply.text
        assert bmc.state.boot_override[0] == "Disabled" and bmc.state.changes[changes:] == [
            {"Boot": {"BootSourceOverrideEnabled": "Continuous", "BootSourceOverrideTarget": "Cd"}}, {"Boot": {"BootSourceOverrideEnabled": "Disabled"}},
        ]  # fmt: skip
        # ...with a restart, of a server that is off: switched on, from the image.
        bmc.state.power = "Off"
        reply = mount(admin, device, boot="until_unmounted", restart=True)
        assert reply.status_code == 200, reply.text
        assert bmc.state.actions[-1] == "system On" and bmc.state.booted[-1] == f"cd {DEBIAN}" and bmc.state.boot_override == ("Continuous", "Cd")
        assert unmount(admin, device).status_code == 200 and bmc.state.boot_override[0] == "Disabled"
        # Another tool's override is not replaced: the image is mounted, the start from it refused, and both said.
        bmc.state.boot_override = ("Once", "Pxe")
        reply = mount(admin, device, boot="once")
        assert (reply.status_code, reply.json()["mounted"]) == (409, True) and "boot override set already (Pxe, Once)" in reply.json()["message"]
        assert bmc.state.boot_override == ("Once", "Pxe") and bmc.state.media_inserted
        assert [entry["event"] for entry in entries(admin, "media_boot_failed")] == ["media_boot_failed"]
        assert unmount(admin, device).status_code == 200 and bmc.state.boot_override == ("Once", "Pxe")  # (not qKVM's: left as it is)
        # A controller that allows no "Cd" override is offered no start from it: restarted, for its firmware to find the drive.
        bmc.state.boot_targets = ["None", "Pxe", "Hdd", "BiosSetup"]
        bmc.state.boot_override = ("Disabled", "None")
        wait_until(lambda: admin.get(media(device)).json()["offers"]["boot"] == [], "the start from the image is still offered")
        assert mount(admin, device, boot="once").status_code == 422
        reply = mount(admin, device, restart=True)
        assert reply.status_code == 200, reply.text
        assert bmc.state.actions[-1] == "system ForceRestart" and [entry["event"] for entry in entries(admin, "media_restarted")] == ["media_restarted"]


def test_amis_controller_has_its_remote_media_switched_on_and_reads_the_image_over_https_with_its_own_user_and_password(tmp_path: Path, images: Path) -> None:
    cert, key = make_device_certificate(tmp_path / "tls")
    fake = FakeBmc(BmcState(virtual_media="ami", rmedia_shows_after=0.3)).start()
    try:
        with Wall(tmp_path / "wall", serving={"ssl_certfile": str(cert), "ssl_keyfile": str(key)}) as live:
            live.url = live.url.replace("http://", "https://")  # (the wall serves HTTPS, with a certificate of its own made here)
            admin = httpx.Client(base_url=live.url, headers=CSRF, verify=False, timeout=60)
            live.clients.append(admin)
            assert admin.post("/api/v1/setup", json={"password": PASSWORD}).status_code == 200
            device = a_server(admin, fake)
            # Its remote media is off: no drive shows, and its manager names the switch for it. Offered all the same; over
            # plain HTTP refused before anything is sent (AMI's takes HTTPS alone), its remote media left as it is.
            # (Before the release of 0.3.0 it was refused before its remote media was switched on, AMI's taken to take HTTPS
            # alone: a real AMI board, whose drive is the standard's kind, refused HTTPS and took HTTP. The drive says it now.)
            media_settings(admin, images, live.url.replace("https://", "http://"))
            assert admin.get(media(device)).json()["notes"] == []  # (no drive seen yet: nothing assumed)
            reply = mount(admin, device)
            assert (reply.status_code, reply.json()["code"]) == (409, "action_failed"), reply.text
            assert "takes an image over HTTPS only" in reply.json()["message"] and "Remote media was switched on" in reply.json()["message"]
            assert fake.state.rmedia_switches == 1 and fake.state.media_said == []
            assert "HTTPS only" in admin.get(media(device)).json()["notes"][0]  # (its drive seen: it says so from now on)
            media_settings(admin, images, live.url)
            assert admin.get(media(device)).json()["notes"] == []
            reply = mount(admin, device)
            assert reply.status_code == 200, reply.text
            assert reply.json()["note"] is None  # (on already)
            assert fake.state.rmedia_switches == 1
            (said,) = fake.state.media_said
            assert set(said) == {"Image", "TransferProtocolType", "UserName", "Password"} and said["TransferProtocolType"] == "HTTPS"
            assert said["Image"].startswith(f"{live.url}/media/") and said["UserName"].startswith("qkvm-") and len(said["Password"]) >= 32
            assert [status for status, _, _ in fake.state.media_read] == [206, 206]  # (read with them, over HTTPS, its certificate unchecked)
            assert said["Password"] not in str(live.audit(admin, "media")) and said["Password"] not in admin.get("/api/v1/status").text
            with reader() as controller:
                assert controller.get(said["Image"], headers={"Range": "bytes=0-9"}).status_code == 401  # (without them)
                wrong = controller.get(said["Image"], headers={"Range": "bytes=0-9"}, auth=(said["UserName"], said["Password"] + "x"))
                assert wrong.status_code == 401
                right = controller.get(said["Image"], headers={"Range": "bytes=0-9"}, auth=(said["UserName"], said["Password"]))
                assert (right.status_code, right.content) == (206, iso(DEBIAN)[:10])
            reply = unmount(admin, device)
            assert reply.status_code == 200, reply.text
            assert fake.state.media_ejects == 1
            with reader() as controller:
                assert controller.get(said["Image"], auth=(said["UserName"], said["Password"])).status_code == 404
            # Over plain HTTP it is refused before anything is sent: AMI's takes HTTPS alone.
            media_settings(admin, images, live.url.replace("https://", "http://"))
            before = len(sent(fake, "InsertMedia", "EnableRMedia"))
            reply = mount(admin, device)
            assert (reply.status_code, reply.json()["code"]) == (409, "action_failed") and "HTTPS only" in reply.json()["message"]
            assert reply.json()["message"].startswith("Nothing was sent") and len(sent(fake, "InsertMedia", "EnableRMedia")) == before
            assert "HTTPS only" in admin.get(media(device)).json()["notes"][0]
            # A controller that cannot read the image (it asks from another address): its task ends in an exception, nothing is
            # mounted, and the address made for it is gone.
            media_settings(admin, images, live.url)
            fake.state.media_reads_from = "127.0.0.2"
            reply = mount(admin, device)
            assert (reply.status_code, reply.json()["code"]) == (502, "action_failed"), reply.text
            assert "could not be read (HTTP 404)" in reply.json()["message"] and not fake.state.media_inserted
            with reader() as controller:
                assert controller.get(fake.state.media_said[-1]["Image"], auth=(said["UserName"], said["Password"])).status_code == 404
    finally:
        fake.stop()


# --- the rules every family's virtual media keeps ----------------------------------------------------------------------


def test_amis_drive_that_shows_late_is_found_at_the_next_mount_and_a_switch_already_on_is_taken_as_on(tmp_path: Path, images: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (Test server .23, an AMI board, before the release of 0.3.0: its CD1 showed some 44 s after its remote media was
    # switched on, past the 20 s waited; the next mount found no drive, asked for the switch again, and was refused:
    # "RMediaState is already enabled and can no longer take incoming requests". Twice.)
    monkeypatch.setattr(redfish, "RMEDIA_WITHIN", 1.0)
    cert, key = make_device_certificate(tmp_path / "tls")
    fake = FakeBmc(BmcState(virtual_media="ami", rmedia_shows_after=2.0, media_linked_once_on=True)).start()
    try:
        with Wall(tmp_path / "wall", serving={"ssl_certfile": str(cert), "ssl_keyfile": str(key)}) as live:
            live.url = live.url.replace("http://", "https://")
            admin = httpx.Client(base_url=live.url, headers=CSRF, verify=False, timeout=60)
            live.clients.append(admin)
            assert admin.post("/api/v1/setup", json={"password": PASSWORD}).status_code == 200
            device = a_server(admin, fake)  # (read while its remote media is off: its manager links no virtual media then)
            media_settings(admin, images, live.url)
            reply = mount(admin, device)
            assert (reply.status_code, reply.json()["code"]) == (409, "action_failed") and "no virtual CD-ROM drive showed" in reply.json()["message"]
            wait_until(lambda: fake.state.rmedia, "its remote media never came on", 10)
            reply = mount(admin, device)  # (its drive there by now: found, and the switch not asked for again)
            assert reply.status_code == 200, reply.text
            assert fake.state.rmedia_switches == 1 and len(fake.state.media_said) == 1
            assert unmount(admin, device).status_code == 200
            # Its drives not listed for a moment while its remote media is on: the switch answers "already enabled", which is
            # taken as on, and the drive waited for.
            monkeypatch.setattr(redfish, "RMEDIA_WITHIN", 10.0)
            fake.state.drives_hidden_until = time.monotonic() + 1.5
            reply = mount(admin, device)
            assert reply.status_code == 200, reply.text
            assert fake.state.rmedia_switches == 1 and len(fake.state.media_said) == 2
            assert unmount(admin, device).status_code == 200
    finally:
        fake.stop()


def test_a_look_at_an_ami_server_that_guesses_where_its_drives_are_is_never_a_refused_session(tmp_path: Path, images: Path) -> None:
    # (The delta review, L3: the place AMI documents, read at every look where the manager links none, answered 401 on a
    # board whose remote media is off: a refused session, signed in anew, at every look. A 401 there is nothing there.)
    with wall(tmp_path) as admin:
        fake = FakeBmc(BmcState(virtual_media="ami", media_linked_once_on=True, media_unlinked_401=True)).start()
        try:
            device = a_server(admin, fake)
            media_settings(admin, images, "https://127.0.0.1:9")
            logins = fake.state.logins
            for _ in range(4):
                status_of(admin, device)
                time.sleep(0.3)
            assert fake.state.logins == logins, (logins, fake.state.logins)  # (its place guessed, answered 401: nothing signed in anew)
            assert status_of(admin, device)["state"] == "online"
        finally:
            fake.stop()


def test_a_controller_asking_for_its_image_and_a_read_refused_are_each_said_once_in_the_log(tmp_path: Path, images: Path, bmc: FakeBmc) -> None:
    # (A trial on a real AMI board before the release of 0.3.0: it took the mount over plain HTTP and showed nothing in its
    # drive, and the log could not say whether it had asked for the image at all: a read is said only once it is whole.)
    said_lines: list[str] = []
    handler = logging.Handler()
    handler.emit = lambda record: said_lines.append(record.getMessage())  # type: ignore[method-assign]
    ours = logging.getLogger("qkvm")
    level = ours.level
    ours.setLevel(logging.INFO)  # (as the program sets it, started without --log-level)
    ours.addHandler(handler)
    try:
        with Wall(tmp_path / "wall") as live:
            admin = live.browser()
            device = a_server(admin, bmc)
            media_settings(admin, images, live.url)
            wait_until(lambda: "media" in status_of(admin, device, state="online")["can"], "the server's drive was never found", 10)
            assert mount(admin, device).status_code == 200
            (said,) = bmc.state.media_said
            with reader() as controller:
                for _ in range(2):
                    assert controller.get(said["Image"], headers={"Range": f"bytes={SIZE * 4}-"}).status_code == 416
            wait_until(lambda: any("could not be read as asked" in line for line in said_lines), "the refused read was not said", 10)
    finally:
        ours.removeHandler(handler)
        ours.setLevel(level)
    asked = [line for line in said_lines if "its controller asks for" in line]
    assert asked == [f"db-01: its controller asks for {DEBIAN} (GET, bytes=0-2047)"] or (len(asked) == 1 and DEBIAN in asked[0]), asked
    assert len([line for line in said_lines if "could not be read as asked" in line]) == 1, said_lines


def test_an_ami_board_whose_drive_is_the_standards_takes_its_image_over_http(tmp_path: Path, images: Path) -> None:
    # (A real AMI board before the release of 0.3.0: its manager never linked its virtual media, whose CD1 was at the place
    # AMI documents; the CD1 was the standard's kind and said no protocols; it refused HTTPS ("not in the list of acceptable
    # values") and took HTTP. The box said "HTTPS only", assumed of every AMI board, and refused before anything was sent.)
    fake = FakeBmc(BmcState(virtual_media="ami", ami_standard_drive=True, rmedia_shows_after=0.3)).start()
    try:
        with Wall(tmp_path / "wall") as live:  # (plain HTTP)
            admin = live.browser()
            device = a_server(admin, fake)
            media_settings(admin, images, live.url)
            logins = fake.state.logins
            assert admin.get(media(device)).json()["notes"] == []
            reply = mount(admin, device)
            assert reply.status_code == 200, reply.text
            assert reply.json()["note"] == "Remote media was switched on in the controller's settings for it, and stays on."
            (said,) = fake.state.media_said
            assert said["TransferProtocolType"] == "HTTP" and "UserName" not in said and said["Image"].startswith(live.url)
            assert fake.state.media_read and all(status == 206 for status, _, _ in fake.state.media_read)
            assert fake.state.logins == logins  # (its place guessed while it was off, answered 401: no session refused for it)
            wait_until(lambda: (status_of(admin, device).get("media") or {}).get("name") == DEBIAN, "the tile does not say what is in the drive", 10)
            assert unmount(admin, device).status_code == 200
    finally:
        fake.stop()



def test_an_ami_board_that_describes_its_mount_takes_its_image_over_http(tmp_path: Path, images: Path) -> None:
    # (A second real AMI board, 2026-11-04: its CD1 had AMI's Oem part and listed no protocols; its InsertMedia's
    # description (ActionInfo) listed HTTP and HTTPS. The box said "HTTPS only", guessed of AMI's kind of drive, and refused
    # before anything was sent; the board itself took a plain HTTP address, and refused every HTTPS one.)
    fake = FakeBmc(BmcState(virtual_media="ami", ami_standard_drive=True, ami_described=True, rmedia=True)).start()
    try:
        with Wall(tmp_path / "wall") as live:  # (plain HTTP)
            admin = live.browser()
            device = a_server(admin, fake)
            media_settings(admin, images, live.url)
            assert admin.get(media(device)).json()["notes"] == []
            reply = mount(admin, device)
            assert reply.status_code == 200, reply.text
            (said,) = fake.state.media_said
            assert said["TransferProtocolType"] == "HTTP" and "UserName" not in said and said["Image"].startswith(live.url)
            assert fake.state.media_read and all(status == 206 for status, _, _ in fake.state.media_read)
            assert unmount(admin, device).status_code == 200
    finally:
        fake.stop()


def test_an_ami_board_that_reads_from_port_80_alone_is_said_so(tmp_path: Path, images: Path) -> None:
    # (The same board took the plain HTTP address and asked for the image at port 80, though the address named another
    # port: nothing answered there, and the mount failed with no word of why.)
    with socket.socket() as closed:
        closed.bind(("127.0.0.1", 0))
        nobody = closed.getsockname()[1]
    fake = FakeBmc(BmcState(virtual_media="ami", ami_standard_drive=True, ami_described=True, rmedia=True, media_reads_port=nobody)).start()
    try:
        with Wall(tmp_path / "wall") as live:
            admin = live.browser()
            device = a_server(admin, fake)
            media_settings(admin, images, live.url)
            reply = mount(admin, device)
            assert reply.status_code != 200, reply.text
            said = reply.json()["message"]
            assert "port 80 alone" in said and f"({urlsplit(live.url).port} here)" in said, said
            assert "Settings, Server images" in said
    finally:
        fake.stop()



def test_an_ami_board_whose_remote_media_stays_off_is_said_so(tmp_path: Path, images: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (A real ASRock Rack board, 2026-11-04: it answered the switch of its remote media "initiated successfully", and its
    # RMediaStatus stayed "Disabled": its settings keep it off without an image share of their own. qKVM waited 90 seconds
    # and said only that no drive showed.)
    monkeypatch.setattr(redfish, "RMEDIA_SAYS_WITHIN", 0.5)
    fake = FakeBmc(BmcState(virtual_media="ami", rmedia_stays_off=True)).start()
    try:
        with Wall(tmp_path / "wall") as live:
            admin = live.browser()
            device = add(admin, fake.url)
            admin.machine = admin.get("/api/v1/wall").json()["devices"][0]["name"]
            media_settings(admin, images, live.url)
            began = time.monotonic()
            reply = mount(admin, device)
            assert (reply.status_code, reply.json()["code"]) == (409, "action_failed"), reply.text
            assert "says it is still off" in reply.json()["message"] and "General Settings" in reply.json()["message"]
            assert time.monotonic() - began < redfish.RMEDIA_WITHIN / 2 and fake.state.rmedia_switches == 1
            assert fake.state.media_said == []
    finally:
        fake.stop()


def httpfs2_reads(answer: bytes) -> tuple[bool, bool]:
    """What httpfs2 0.1.5a finds in an answer's head, as it looks for it: (a length, reading in parts)."""
    lines = answer.split(b"\r\n\r\n", 1)[0].split(b"\r\n")[1:]
    length = any(line.startswith(b"Content-Length: ") and line[16:17].isdigit() for line in lines)
    parts = any(line.startswith((b"Accept-Ranges: bytes", b"Content-Range: bytes")) for line in lines)
    return length, parts


def test_a_served_image_is_answered_as_httpfs2_reads_it(tmp_path: Path, images: Path, bmc: FakeBmc) -> None:
    # (Test server .23, 2026-11-04: its controller reads an image with httpfs2 0.1.5a, which asked HEAD, found
    # "content-length" and "accept-ranges: bytes" in lowercase, did not take them, asked nothing more, and its mount failed
    # "Error code: 416. Error while redirecting the image".)
    with Wall(tmp_path / "wall") as live:
        admin = live.browser()
        device = a_server(admin, bmc)
        media_settings(admin, images, live.url)
        assert mount(admin, device).status_code == 200
        address = urlsplit(bmc.state.media_said[-1]["Image"])
        for asked in (f"HEAD {address.path} HTTP/1.1\r\nHost: {address.netloc}\r\nUser-Agent: httpfs2.c 0.1.5a\r\n\r\n",
                      f"GET {address.path} HTTP/1.1\r\nHost: {address.netloc}\r\nRange: bytes=0-2047\r\nConnection: close\r\n\r\n"):
            with socket.create_connection((address.hostname, address.port), timeout=10) as line:
                line.sendall(asked.encode())
                answer = b""
                while b"\r\n\r\n" not in answer:
                    piece = line.recv(4096)
                    assert piece, answer
                    answer += piece
            assert answer.startswith((b"HTTP/1.1 200 ", b"HTTP/1.1 206 ")), answer[:200]
            assert httpfs2_reads(answer) == (True, True), answer.split(b"\r\n\r\n", 1)[0]
        assert unmount(admin, device).status_code == 200

def test_a_mount_whose_task_ends_in_an_exception_is_said_in_the_controllers_words(tmp_path: Path, images: Path) -> None:
    # (The real AMI board, before the release of 0.3.0: its InsertMedia task ended in Exception, "Error code: 403. Error
    # in setting CD Media Configuration, hence InsertMedia action is unsuccessful", its TaskStatus "OK", and its 202 named
    # a task monitor in Location, which answers 202 while the task runs and the failed action's 403 after. qKVM followed
    # the monitor, took its 403 for a task that could not be read, and said "took the mount, and does not show the image".)
    words = "Error code: 403. Error in setting CD Media Configuration, hence InsertMedia action is unsuccessful "
    fake = FakeBmc(BmcState(virtual_media="ami", ami_standard_drive=True, rmedia=True, media_task_fails=words)).start()
    try:
        with Wall(tmp_path / "wall") as live:
            admin = live.browser()
            device = a_server(admin, fake)
            media_settings(admin, images, live.url)
            reply = mount(admin, device)
            assert (reply.status_code, reply.json()["code"]) == (502, "action_failed"), reply.text
            assert "Error in setting CD Media Configuration" in reply.json()["message"], reply.text
            assert "does not show the image" not in reply.json()["message"]
    finally:
        fake.stop()


def test_a_controllers_refusal_is_scrubbed_of_a_mounts_password_before_it_is_shortened() -> None:
    # (The outside review's second round, R2-L3: a task monitor's error was shortened to its length first, and a password
    # cut by it was no longer found whole to be taken out: 31 of its 32 characters were left in the words.)
    password = "bQ7x_-A29mRt65PsyKaN84UwcE16FjZd"
    lending = types.SimpleNamespace(url="https://127.0.0.1/media/" + "T" * 43 + "/x.iso", token="T" * 43, credentials=("qkvm-12345678", password))
    echoed = "x" * 168 + " " + password

    async def request(method: str, path: str, **kwargs: Any) -> httpx.Response:
        return httpx.Response(403, json={"error": {"message": echoed}})

    async def run() -> str:
        target = types.SimpleNamespace(_request=request, _said=redfish.RedfishDevice._said)
        with pytest.raises(kvm.KvmError) as refusal:
            await redfish.RedfishDevice._task_done(target, httpx.Response(202, headers={"Location": "/redfish/v1/TaskService/TaskMonitors/42"}), "mount it", lending)  # type: ignore[arg-type]
        return refusal.value.message

    said = asyncio.run(run())
    assert password[:8] not in said, said


def test_virtual_media_on_a_server_is_an_admins_in_person(tmp_path: Path, images: Path, bmc: FakeBmc) -> None:
    bmc.state.media_fetch = False
    with wall(tmp_path) as admin:
        device = a_server(admin, bmc)
        media_settings(admin, images, "http://127.0.0.1:9")
        account(admin, "olga", "operator")
        account(admin, "victor", "viewer")
        olga, victor = browser(admin, "olga", port=50032), browser(admin, "victor", port=50033)
        token = admin.post("/api/v1/tokens", json={"name": "script", "role": "operator"}).json()["token"]
        robot = admin.__class__(admin.app, headers={"Authorization": f"Bearer {token}"}, client=("192.0.2.50", 51031))
        robot.portal = admin.portal
        for who in (olga, victor):
            for reply in (who.get(media(device)), mount(who, device, machine=admin.machine), unmount(who, device, machine=admin.machine)):
                assert (reply.status_code, reply.json()["code"]) == (403, "not_allowed"), reply.text
        for reply in (robot.get(media(device)), mount(robot, device, machine=admin.machine)):
            assert (reply.status_code, reply.json()["code"]) == (403, "not_allowed"), reply.text
        for who in (olga, victor, robot):
            assert (who.get("/api/v1/settings/media").status_code, who.put("/api/v1/settings/media", json={"folder": "", "address": ""}).status_code) == (403, 403)
        assert bmc.state.media_said == [] and entries(admin, "media_mounted", "media_mount_failed") == []


def test_the_confirmation_names_the_machine_and_the_image_or_nothing_is_sent(tmp_path: Path, images: Path, bmc: FakeBmc) -> None:
    bmc.state.media_fetch = False
    with wall(tmp_path) as admin:
        device = a_server(admin, bmc)
        media_settings(admin, images, "http://127.0.0.1:9")
        reply = mount(admin, device, machine="db")
        assert (reply.status_code, reply.json()["code"]) == (409, "changed")
        for image, code in (
            ("ubuntu-24.04.iso", "changed"), ("../images/debian-13.iso", "invalid"), ("http://192.0.2.9/boot.iso", "invalid"),
            ("notes.txt", "invalid"), (".hidden.iso", "invalid"), ("old.iso", "changed"), (str(images / DEBIAN), "invalid"),
        ):  # fmt: skip
            reply = mount(admin, device, image=image)
            assert (reply.status_code, reply.json()["code"]) == ((409 if code == "changed" else 422), code), (image, reply.text)
        for more in ({"drive": "flash"}, {"drive": "disk"}, {"writable": True}):
            assert mount(admin, device, **more).status_code == 422, more
        assert bmc.state.media_said == [] and sent(bmc, "InsertMedia", "PATCH", "Reset") == []
        # Unmounted by the name of another image than the one in the drive, or of another machine: nothing is taken out.
        assert mount(admin, device).status_code == 200
        for image, machine in ((ALPINE, admin.machine), (DEBIAN, "db")):
            reply = unmount(admin, device, image=image, machine=machine)
            assert (reply.status_code, reply.json()["code"]) == (409, "changed"), reply.text
        assert bmc.state.media_ejects == 0 and bmc.state.media_inserted
        # Another image in the drive (put there at the controller's own page): a mount is refused, and it is said by its name.
        assert unmount(admin, device).status_code == 200
        bmc.state.media_inserted, bmc.state.media_image, bmc.state.media_name = True, "nfs://192.0.2.7/secret/token=abc/rescue.iso", "rescue.iso"
        wait_until(lambda: (status_of(admin, device).get("media") or {}).get("name") == "rescue.iso", "the tile does not say what is in the drive")
        assert "192.0.2.7" not in admin.get("/api/v1/status").text  # (its address may hold a password: never said)
        reply = mount(admin, device)
        assert (reply.status_code, reply.json()["code"]) == (409, "busy") and "rescue.iso" in reply.json()["message"]
        assert len(bmc.state.media_said) == 1
        # ...and is taken out by its name, as it was shown.
        assert unmount(admin, device, image="rescue.iso").status_code == 200 and not bmc.state.media_inserted


def test_another_server_at_the_address_is_sent_nothing(tmp_path: Path, images: Path, bmc: FakeBmc) -> None:
    bmc.state.media_fetch = False
    with wall(tmp_path) as admin:
        device = a_server(admin, bmc)
        media_settings(admin, images, "http://127.0.0.1:9")
        status_of(admin, device, state="online")
        bmc.state.uuid = "11111111-2222-3333-4444-555555555555"  # (the computer now at the address is another)
        reply = mount(admin, device)
        assert reply.json()["code"] == "another_machine", reply.text
        assert bmc.state.media_said == [] and sent(bmc, "InsertMedia", "EjectMedia", "PATCH") == []
        assert entries(admin, "media_mount_failed")[-1]["image"] == DEBIAN


def test_what_qkvm_serves_ends_with_the_mount_the_file_and_the_tile(tmp_path: Path, images: Path, bmc: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(redfish, "LEND_GRACE", 1.0)  # (a look begun within a second of a mount says nothing of it)
    with Wall(tmp_path / "wall") as live:
        admin = live.browser()
        device = a_server(admin, bmc)
        media_settings(admin, images, live.url)
        with reader() as controller:
            # The file changed in the folder while it is mounted: what is served is the image that was mounted, or nothing.
            assert mount(admin, device).status_code == 200
            address = bmc.state.media_said[-1]["Image"]
            assert controller.get(address, headers={"Range": "bytes=0-9"}).status_code == 206
            with open(images / DEBIAN, "ab") as grown:
                grown.write(b"more")
            assert controller.get(address, headers={"Range": "bytes=0-9"}).status_code == 410
            os.utime(images / DEBIAN, ns=(0, 0))
            assert controller.get(address, headers={"Range": "bytes=0-9"}).status_code == 410
            assert unmount(admin, device).status_code == 200
            # Taken out at the controller's own page: a look that finds the drive empty ends it.
            assert mount(admin, device, image=ALPINE).status_code == 200
            address = bmc.state.media_said[-1]["Image"]
            assert controller.get(address, headers={"Range": "bytes=0-9"}).status_code == 206
            bmc.state.media_inserted = False

            def gone() -> bool:
                status_of(admin, device)  # (a look at the server, which reads its drive)
                try:
                    return controller.get(address, headers={"Range": "bytes=0-9"}).status_code == 404
                except httpx.RemoteProtocolError:
                    return False  # (cut off as it ended, between its head and its first piece: asked again)

            wait_until(gone, "an image taken out elsewhere is still served", 10)
            # So many reads of it at once, and the next is told to come back in a moment.
            bmc.state.media_inserted = False
            assert mount(admin, device, image=ALPINE).status_code == 200
            address = bmc.state.media_said[-1]["Image"]
            monkeypatch.setattr(server, "MOST_AT_ONCE", 0)
            busy = controller.get(address, headers={"Range": "bytes=0-9"})
            assert (busy.status_code, busy.headers["retry-after"]) == (503, "1")
            monkeypatch.setattr(server, "MOST_AT_ONCE", served.MOST_AT_ONCE)
            # The tile at another address now (the same controller, by another name): not that tile's server's image any more.
            assert controller.get(address, headers={"Range": "bytes=0-9"}).status_code == 206
            moved = admin.put(f"/api/v1/devices/{device}", json={"name": admin.machine, "url": bmc.url.replace("127.0.0.1", "localhost"), "password": "secret"})
            assert moved.status_code == 200, moved.text
            # (The tile says what is in the drive, and no more that it was mounted from here: another tile's mount, as it were.)
            wait_until(lambda: (status_of(admin, device).get("media") or {}).get("name") == url_name(ALPINE), "the tile says the image is still served")
            assert status_of(admin, device)["media"]["by"] is None
            assert controller.get(address, headers={"Range": "bytes=0-9"}).status_code == 404
            # The tile removed: nothing at its address any more.
            assert admin.put(f"/api/v1/devices/{device}", json={"name": admin.machine, "url": bmc.url, "password": "secret"}).status_code == 200
            bmc.state.media_inserted = False
            wait_until(lambda: "media" in status_of(admin, device, state="online")["can"], "the server's media was never found again", 10)
            assert mount(admin, device, image=ALPINE).status_code == 200
            address = bmc.state.media_said[-1]["Image"]
            assert controller.get(address, headers={"Range": "bytes=0-9"}).status_code == 206
            assert admin.delete(f"/api/v1/devices/{device}").status_code == 200
            assert controller.get(address, headers={"Range": "bytes=0-9"}).status_code == 404


def test_what_a_controller_says_back_of_a_mount_is_never_said_on(tmp_path: Path, images: Path, bmc: FakeBmc) -> None:
    # The final review of 0.3.0: a controller that says back what it was handed in its refusal had the mount's address
    # and token said to the page and written in the activity log (over HTTPS, its user and password with them).
    bmc.state.media_echo = True
    with Wall(tmp_path / "wall") as live:
        admin = live.browser()
        device = a_server(admin, bmc)
        media_settings(admin, images, live.url)
        reply = mount(admin, device)
        (said,) = bmc.state.media_said
        token = said["Image"].split("/")[-2]
        assert reply.json()["code"] == "action_failed" and "could not be read at (hidden)" in reply.json()["message"], reply.text
        written = str(entries(admin, "media_mount_failed"))
        assert "could not be read at (hidden)" in written and token not in written and token not in reply.text


class Stalling(io.RawIOBase):
    """The image on a share that stalls: every read takes `takes` seconds, then gives what is there (and says its thread)."""

    def __init__(self, path: str, takes: float, threads: list[str]) -> None:
        self._file = open(path, "rb", buffering=0)
        self._takes, self._threads = takes, threads

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def seek(self, at: int, whence: int = 0) -> int:
        return self._file.seek(at, whence)

    def readinto(self, buffer: Any) -> int:
        self._threads.append(threading.current_thread().name)
        time.sleep(self._takes)
        return self._file.readinto(buffer)

    def close(self) -> None:
        self._file.close()
        super().close()


def test_a_read_cut_off_on_a_share_that_stalls_holds_up_nothing_but_itself(tmp_path: Path, images: Path, bmc: FakeBmc, monkeypatch: pytest.MonkeyPatch) -> None:
    # The controller gives up on a read (its own timeout) while qKVM's read of the file is still under way: the file is let
    # go of in a thread of the images' own (a file's close waits for the read that holds it), not on the wall's loop, and
    # the read's place among MOST_AT_ONCE is given back once that thread has returned, not before.
    takes, threads = 3.0, list[str]()
    with Wall(tmp_path / "wall") as live:
        admin = live.browser()
        device = a_server(admin, bmc)
        media_settings(admin, images, live.url)
        assert mount(admin, device).status_code == 200
        address = bmc.state.media_said[-1]["Image"]
        lending = live.core.served.find(address.split("/")[-2])
        assert lending is not None
        monkeypatch.setattr(served.Lending, "opened", lambda self: io.BufferedReader(Stalling(self.image.path, takes, threads)))
        gave_up = threading.Event()

        def controller() -> None:
            with reader() as asking, contextlib.suppress(httpx.TimeoutException):
                asking.get(address, headers={"Range": "bytes=0-9"}, timeout=1.0)
            gave_up.set()

        threading.Thread(target=controller, daemon=True).start()
        assert gave_up.wait(10)
        time.sleep(0.3)  # (the wall sees the connection gone, and ends the answer)
        with httpx.Client(timeout=10) as other:
            began = time.monotonic()
            assert other.get(f"{live.url}/healthz").status_code == 200
            took = time.monotonic() - began
        assert took < 1.0, f"the wall was held up {took:.2f} s by the close of a file a thread was still reading"
        assert lending.at_once == 1  # (its thread is still reading: its place is still taken)
        wait_until(lambda: lending.at_once == 0, "the read's place was never given back", 10)
        assert threads and all(name.startswith("served") for name in threads), threads  # (not the wall's shared threads)


def test_an_answer_that_does_not_come_is_a_maybe_and_a_refusal_is_a_no(tmp_path: Path, images: Path, bmc: FakeBmc) -> None:
    with Wall(tmp_path / "wall") as live:
        admin = live.browser()
        device = a_server(admin, bmc)
        media_settings(admin, images, live.url)
        bmc.state.media_insert_status = 400  # (refused, for certain: the address made for it is gone)
        reply = mount(admin, device)
        assert (reply.status_code, reply.json()["code"]) == (502, "action_failed"), reply.text
        assert "did not mount it" in reply.json()["message"]
        with reader() as controller:
            assert controller.get(bmc.state.media_said[-1]["Image"]).status_code == 404
        bmc.state.media_insert_status = 500  # (an error of its own: it may have been mounted, and it is served on meanwhile)
        reply = mount(admin, device)
        assert (reply.status_code, reply.json()["code"]) == (504, "timeout") and "may or may not have been mounted" in reply.json()["message"]
        with reader() as controller:
            assert controller.get(bmc.state.media_said[-1]["Image"], headers={"Range": "bytes=0-9"}).status_code == 206
        bmc.state.media_insert_status = None
        # One mounted from qKVM before it was restarted (an address of qKVM's it does not serve now): said, and taken out.
        bmc.state.media_inserted, bmc.state.media_image, bmc.state.media_name = True, f"{live.url}/media/{'B' * 43}/{DEBIAN}", DEBIAN
        notes = admin.get(media(device)).json()["notes"]
        assert any("before qKVM was restarted" in note for note in notes), notes
        assert unmount(admin, device).status_code == 200 and not bmc.state.media_inserted


def test_a_mount_whose_right_is_lost_before_it_goes_sends_nothing_and_serves_nothing(images: Path, bmc: FakeBmc) -> None:
    # Asked before the mount goes out (as before every change): whoever asked may no longer. Nothing is sent, and the address
    # made for it is gone at once; said as a mount that was not done.
    async def run() -> tuple[kvm.KvmError, Any]:
        device = redfish.RedfishDevice(kvm.DeviceSpec(id="t7", name="server", base_url=bmc.url, username="admin", password="secret", kind="redfish"))
        device.served = served.Served(lambda: str(images), lambda: "http://127.0.0.1:9")
        try:
            assert [one["id"] for one in (await device.media_images())["images"]] == [ALPINE, DEBIAN]
            assert device.media_offer() is not None
            with pytest.raises(kvm.KvmError) as refused:
                await device.media_mount(DEBIAN, by="admin", still=lambda: False)
            return refused.value, device.served.of("t7")
        finally:
            await device.close()

    said, left = asyncio.run(run())
    assert said.code == "stopped" and redfish.never_sent(said) and left is None
    assert bmc.state.media_said == [] and sent(bmc, "InsertMedia", "EnableRMedia") == []


def test_the_settings_name_a_folder_and_an_address_and_refuse_what_is_neither(tmp_path: Path, images: Path) -> None:
    with wall(tmp_path / "w") as admin:
        said = admin.get("/api/v1/settings/media").json()
        assert said == {"folder": "", "address": "", "serving_at": None, "https": False}  # (in-process: it listens nowhere)
        for folder, address in (
            ("images", ""), (str(images / "nope"), ""), (str(images / DEBIAN), ""), ("", "ftp://x"), ("", "https://10.0.0.5:8787/qkvm"),
            ("", "kvm.example.com:8787"), ("", "https://kvm.example.com:8787"),
        ):  # fmt: skip
            reply = admin.put("/api/v1/settings/media", json={"folder": folder, "address": address})
            assert (reply.status_code, reply.json()["code"]) == (422, "invalid"), (folder, address, reply.text)
        reply = admin.put("/api/v1/settings/media", json={"folder": str(images), "address": " https://10.0.0.5:8787/ "})
        assert reply.status_code == 200 and reply.json()["serving_at"] == "https://10.0.0.5:8787"
        assert admin.get("/api/v1/settings/media").json()["folder"] == str(images)
        found = admin.get("/api/v1/audit", params={"limit": 50}).json()["entries"]
        assert any(one["event"] == "media_settings_changed" and one["address"] == "https://10.0.0.5:8787" for one in found)
    assert served.address_of("https://kvm.lan:8787") == "https://kvm.lan:8787"
