"""Virtual media on a guest of Proxmox VE (0.3.0, A1): what every family's virtual media shares (the right, the
confirmation that names the machine and the image, the activity log, the guest it was added for and no other), and an ISO
image on one of Proxmox's storages in the guest's CD-ROM drive, started from once or until it is unmounted.

Against the stand-in (fake_proxmox.py), grown from Proxmox's own source for this: the storages and their images, the
guest's drives and boot order with the digest of its settings, the PUT and POST of those, and Proxmox's refusal for each
privilege the token lacks.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from qkvm import proxmox
from qkvm.proxmox import ISO_VOLUME, ProxmoxGuest, boot_order, cd_of, drive_of
from tests.fake_kvm import FakeKvm, FakeState
from tests.fake_proxmox import API, SECRET, TOKEN_ID, FakeProxmox, Guest, PveState, Storage, digest_of
from tests.test_meanwhile import in_background
from tests.test_proxmox import TOKEN, fast, state_of  # noqa: F401  (`fast`: the same short waits, by name)
from tests.test_users import OTHER, account, browser
from tests.test_wall import add, wait_until, wall

DEBIAN, ALPINE = "local:iso/debian-13.iso", "local:iso/alpine-3.21.iso"
FIRST_ORDER = "order=scsi0;ide2;net0"  # the stand-in's guests', as Proxmox's own page writes a new one's


@pytest.fixture(autouse=True)
def forgotten() -> None:
    proxmox._MOUNTED.clear()
    proxmox._BOOT_WAS.clear()


@pytest.fixture
def pve(tmp_path: Path) -> Iterator[FakeProxmox]:
    fake = FakeProxmox(PveState(guests={100: Guest(100, "web"), 101: Guest(101, "db", status="stopped")}), tls_dir=tmp_path / "pve").start()
    yield fake
    fake.stop()


def a_guest(client: Any, fake: FakeProxmox, vmid: int = 100) -> str:
    reply = client.post("/api/v1/devices", json={"url": fake.guest_url(vmid), **TOKEN})
    assert reply.status_code == 201, reply.text
    return str(reply.json()["device"]["id"])


def media(device: str) -> str:
    return f"/api/v1/devices/{device}/media"


def mount(client: Any, device: str, image: str = DEBIAN, machine: str = "web", **more: Any) -> Any:
    return client.post(media(device), json={"image": image, "machine": machine, **more})


def unmount(client: Any, device: str, image: str = DEBIAN, machine: str = "web") -> Any:
    return client.post(media(device) + "/unmount", json={"image": image, "machine": machine})


def entries(client: Any, *events: str) -> list[dict[str, Any]]:
    """The activity log's entries of these events, oldest first."""
    found = client.get("/api/v1/audit", params={"kind": "action", "limit": 500}).json()["entries"]
    return [entry for entry in reversed(found) if entry["event"] in events]


def power_tasks(fake: FakeProxmox) -> list[str]:
    return [task["type"] for task in fake.state.tasks if task["type"].startswith("qm") and task["type"] != "qmconfig"]


def fetched_or_sent_anything(fake: FakeProxmox) -> list[str]:
    """Requests that had Proxmox fetch an address, or carried an image to it: there are to be none."""
    return [one for one in fake.state.requests if "download-url" in one or "/upload" in one or "oci-registry-pull" in one]


# --- the stand-in, as Proxmox's source says ----------------------------------------------------------------------


def test_the_stand_in_keeps_proxmoxs_rules_for_a_guests_drive_and_boot_order(pve: FakeProxmox) -> None:
    # What the tests below rest on, asked of the stand-in as qKVM asks Proxmox: every rule is one of Qemu.pm's or Storage.pm's.
    headers = {"Authorization": f"PVEAPIToken={TOKEN_ID}={SECRET}"}
    with httpx.Client(base_url=pve.url + API, headers=headers, verify=False, timeout=10) as asker:  # (its own certificate)
        assert [one["storage"] for one in asker.get("/nodes/pve1/storage", params={"content": "iso"}).json()["data"]] == ["local"]
        listed = asker.get("/nodes/pve1/storage/local/content", params={"content": "iso"}).json()["data"]
        assert {one["volid"] for one in listed} == {DEBIAN, ALPINE} and all(one["content"] == "iso" for one in listed)
        guest = pve.state.guests[100]
        said = asker.get("/nodes/pve1/qemu/100/config").json()["data"]
        assert (said["ide2"], said["boot"], said["digest"]) == ("none,media=cdrom", FIRST_ORDER, digest_of(guest))

        def change(how: str = "PUT", **values: str) -> httpx.Response:
            return asker.request(how, "/nodes/pve1/qemu/100/config", data=values)

        # A digest that is not the file's is refused, and nothing is changed.
        refused = change(ide2=f"{DEBIAN},media=cdrom", digest="0" * 40)
        assert (refused.status_code, "checksum mismatch" in refused.json()["message"]) == (500, True) and guest.config["ide2"] == "none,media=cdrom"
        # Each privilege where Proxmox asks for it: the disc VM.Config.CDROM, the order VM.Config.Disk, the image Datastore.Audit.
        guest.may_cdrom = False
        assert "VM.Config.CDROM" in change(ide2=f"{DEBIAN},media=cdrom").json()["message"]
        guest.may_cdrom, guest.may_disk = True, False
        assert "VM.Config.Disk" in change(boot="order=ide2;scsi0;net0").json()["message"]
        guest.may_disk = True
        pve.state.storages["local"].may_see = False
        assert "Datastore.Audit" in change(ide2=f"{DEBIAN},media=cdrom").json()["message"]
        assert asker.get("/nodes/pve1/storage", params={"content": "iso"}).json()["data"] == []  # (not even named)
        assert asker.get("/nodes/pve1/storage/local/content").status_code == 403
        pve.state.storages["local"].may_see = True
        assert pve.state.changes == []
        # A running guest: its disc changes at once, its boot order at its next start; a reset begins from what it began with.
        assert change(ide2=f"{DEBIAN},media=cdrom", digest=digest_of(guest)).json() == {"data": None}
        assert change("POST", boot="order=ide2;scsi0;net0").json()["data"].startswith("UPID:pve1:")  # (POST: answered with a task)
        assert guest.config["ide2"] == f"{DEBIAN},media=cdrom" and guest.config["boot"] == FIRST_ORDER and guest.pending == {"boot": "order=ide2;scsi0;net0"}
        assert asker.get("/nodes/pve1/qemu/100/config").json()["data"]["boot"] == "order=ide2;scsi0;net0"  # (what is pending, merged in)
        assert asker.post("/nodes/pve1/qemu/100/status/reset").status_code == 200
        assert guest.booted == ["scsi0"]
        assert asker.post("/nodes/pve1/qemu/100/status/stop").status_code == 200
        assert asker.post("/nodes/pve1/qemu/100/status/start").status_code == 200
        assert guest.booted == ["scsi0", f"ide2 {DEBIAN}"] and guest.pending == {}
        # An empty CD-ROM drive first is passed over.
        assert change(ide2="none,media=cdrom").status_code == 200
        assert asker.post("/nodes/pve1/qemu/100/status/reset").status_code == 200
        assert guest.booted[-1] == "scsi0"
    assert fetched_or_sent_anything(pve) == []


def test_a_drive_and_a_boot_order_are_read_as_proxmox_writes_them() -> None:
    assert drive_of("local:iso/debian-13.iso,media=cdrom,size=700M") == ("local:iso/debian-13.iso", {"media": "cdrom", "size": "700M"})
    assert drive_of("file=local:iso/a.iso,media=cdrom") == ("local:iso/a.iso", {"media": "cdrom"})
    assert drive_of("none,media=cdrom") == ("none", {"media": "cdrom"})
    for odd in (None, 5, "", "a,b", "x" * 3000, ["none"]):
        assert drive_of(odd) is None, odd
    assert cd_of({"ide2": "none,media=cdrom"}) == ("ide2", "none")
    assert cd_of({"ide2": "none,media=cdrom", "sata1": f"{DEBIAN},media=cdrom"}) == ("sata1", DEBIAN)  # (the one that holds something)
    assert cd_of({"ide2": "local-lvm:vm-100-disk-1,size=4G", "scsi0": "local-lvm:vm-100-disk-0"}) == (None, None)  # (disks, no CD-ROM drive)
    assert boot_order({"boot": "order=scsi0;ide2;net0"}) == ["scsi0", "ide2", "net0"]
    for odd in ({}, {"boot": "cdn"}, {"boot": "order=scsi0;scsi0"}, {"boot": "order=scsi0,legacy=cdn"}, {"boot": "order=../x"}, {"boot": 5}):
        assert boot_order(odd) is None, odd
    # What is handed back to Proxmox as an image: a name of the characters Proxmox leaves in one, and no comma, slash or space.
    assert ISO_VOLUME.fullmatch(DEBIAN) and ISO_VOLUME.fullmatch("nas-1:iso/Win11_24H2_English_x64.iso")
    for odd in ("local:iso/a.iso,media=disk", "local:iso/../a.iso", "local:iso/a b.iso", "local:images/vm-100-disk-0.raw", "http://x/a.iso", "local:iso/.iso", "/dev/sr0"):
        assert not ISO_VOLUME.fullmatch(odd), odd


# --- mounting, and what is said of it ------------------------------------------------------------------------------


def test_an_admin_mounts_an_image_and_the_tile_and_the_activity_log_say_so(tmp_path: Path, pve: FakeProxmox) -> None:
    with wall(tmp_path) as admin:
        device = a_guest(admin, pve)
        listed = admin.get(media(device))
        assert listed.status_code == 200, listed.text
        body = listed.json()
        assert [(one["id"], one["name"], one["where"], one["size"]) for one in body["images"]] == [
            (ALPINE, "alpine-3.21.iso", "local", 62_000_000), (DEBIAN, "debian-13.iso", "local", 700_000_000),
        ]  # fmt: skip
        assert body["offers"] == {
            "drives": ["cd"], "boot": ["once", "until_unmounted"], "restart": True, "upload": False, "where": "proxmox",
            "writable": [], "delete": False, "drops_input": False,  # (0.3.0, A2: what a KVM's own storage adds, none of it a guest's)
        }  # fmt: skip
        assert (body["mounted"], body["unseen"], body["left_out"], body["space"], body["uploading"]) == (None, [], 0, None, None)
        assert "media" in state_of(admin, device)["can"] and state_of(admin, device)["media"] is None

        before = time.time()
        reply = mount(admin, device)
        assert reply.status_code == 200, reply.text
        assert reply.json()["note"] is None
        guest = pve.state.guests[100]
        assert guest.config["ide2"] == f"{DEBIAN},media=cdrom" and guest.config["boot"] == FIRST_ORDER and guest.pending == {}
        assert pve.state.changes == [{"vmid": 100, "ide2": f"{DEBIAN},media=cdrom"}] and guest.booted == [] and power_tasks(pve) == []
        mounted = reply.json()["mounted"]
        assert {key: mounted[key] for key in ("drive", "image", "name", "where", "read_only", "first", "by")} == {
            "drive": "cd", "image": DEBIAN, "name": "debian-13.iso", "where": "local", "read_only": True, "first": False, "by": "admin",
        }  # fmt: skip
        assert before <= mounted["at"] <= time.time()
        # Said to everybody who sees the tile, a viewer as well.
        account(admin, "victor", "viewer")
        victor = browser(admin, "victor", port=50031)
        wait_until(lambda: (state_of(victor, device).get("media") or {}).get("name") == "debian-13.iso", "the tile does not say what is in the drive")
        assert admin.get(media(device)).json()["mounted"] == mounted

        (entry,) = entries(admin, "media_mounted")
        assert {key: entry[key] for key in ("user", "device", "device_id", "image", "boot", "restart")} == {
            "user": "admin", "device": "web", "device_id": device, "image": DEBIAN, "boot": "none", "restart": False,
        }  # fmt: skip

        reply = unmount(admin, device)
        assert reply.status_code == 200, reply.text
        assert (reply.json()["note"], reply.json()["mounted"]) == (None, None)
        assert guest.config["ide2"] == "none,media=cdrom" and guest.config["boot"] == FIRST_ORDER
        (entry,) = entries(admin, "media_unmounted")
        assert (entry["user"], entry["device_id"], entry["image"]) == ("admin", device, DEBIAN)
        wait_until(lambda: state_of(admin, device).get("media") is None, "the tile still says an image is in the drive")
        # Nothing in it: said so, and nothing is sent.
        sent = len(pve.state.changes)
        reply = unmount(admin, device)
        assert (reply.status_code, reply.json()["note"]) == (200, "nothing was mounted") and len(pve.state.changes) == sent
    assert fetched_or_sent_anything(pve) == []


def test_virtual_media_is_an_admins_in_person(tmp_path: Path, pve: FakeProxmox) -> None:
    with wall(tmp_path) as admin:
        device = a_guest(admin, pve)
        account(admin, "olga", "operator")
        account(admin, "victor", "viewer")
        olga, victor = browser(admin, "olga", port=50032), browser(admin, "victor", port=50033)
        token = admin.post("/api/v1/tokens", json={"name": "script", "role": "operator"}).json()["token"]
        robot = admin.__class__(admin.app, headers={"Authorization": f"Bearer {token}"}, client=("192.0.2.50", 51031))
        robot.portal = admin.portal
        assert olga.post(f"/api/v1/devices/{device}/actions", json={"action": "power_on"}).status_code == 200  # (an operator presses power buttons)
        for who in (olga, victor, robot):
            for reply in (who.get(media(device)), mount(who, device), unmount(who, device)):
                assert (reply.status_code, reply.json()["code"]) == (403, "not_allowed"), reply.text
        assert pve.state.changes == [] and entries(admin, "media_mounted", "media_mount_failed") == []
        # The page hides it from them as well: the box is opened from Actions, for an admin (static/app.js, `canDo(single, 'media')`).


def test_the_confirmation_names_the_machine_and_the_image_or_nothing_is_done(tmp_path: Path, pve: FakeProxmox) -> None:
    pve.state.storages["isos"] = Storage({"ubuntu-24.04.iso": 3_000_000_000}, nodes=["pve2"])  # (on another node: not the guest's)
    with wall(tmp_path) as admin:
        device = a_guest(admin, pve)
        # The machine named otherwise than it is called now (renamed while the box was open, or another tile's name).
        reply = mount(admin, device, machine="db")
        assert (reply.status_code, reply.json()["code"]) == (409, "changed") and "called web" in reply.json()["message"]
        # What is no image listed for it, now: typed, an address, another node's, another kind, an option smuggled in.
        for image, code in (
            ("local:iso/ubuntu-24.04.iso", "changed"), ("isos:iso/ubuntu-24.04.iso", "changed"), ("http://192.0.2.9/boot.iso", "invalid"),
            ("local:iso/../../etc/shadow.iso", "invalid"), (f"{DEBIAN},media=disk", "invalid"), ("local:images/vm-101-disk-0.raw", "invalid"),
            ("/dev/sda", "invalid"), ("cdrom", "invalid"),
        ):  # fmt: skip
            reply = mount(admin, device, image=image)
            assert (reply.status_code, reply.json()["code"]) == ((409 if code == "changed" else 422), code), (image, reply.text)
        assert pve.state.changes == [] and pve.state.guests[100].config["ide2"] == "none,media=cdrom"
        assert [entry["image"] for entry in entries(admin, "media_mount_failed")] == ["local:iso/ubuntu-24.04.iso", "isos:iso/ubuntu-24.04.iso", "http://192.0.2.9/boot.iso", "local:iso/../../etc/shadow.iso", f"{DEBIAN},media=disk", "local:images/vm-101-disk-0.raw", "/dev/sda", "cdrom"]
        # Unmounted by the name of another image than the one in the drive: nothing is taken out.
        assert mount(admin, device).status_code == 200
        for image, machine in ((ALPINE, "web"), (DEBIAN, "Web")):
            reply = unmount(admin, device, image=image, machine=machine)
            assert (reply.status_code, reply.json()["code"]) == (409, "changed"), reply.text
        assert pve.state.guests[100].config["ide2"] == f"{DEBIAN},media=cdrom"
        # Renamed: the old name is no confirmation any more.
        renamed = admin.put(f"/api/v1/devices/{device}", json={"name": "web-1", "url": pve.guest_url(100), "username": TOKEN_ID, "password": ""})
        assert renamed.status_code == 200, renamed.text
        assert unmount(admin, device).status_code == 409 and unmount(admin, device, machine="web-1").status_code == 200
    assert fetched_or_sent_anything(pve) == []


# --- starting from it ----------------------------------------------------------------------------------------------


def test_a_guest_started_from_an_image_once_is_started_anew_and_has_its_boot_order_back(tmp_path: Path, pve: FakeProxmox) -> None:
    with wall(tmp_path) as admin:
        device = a_guest(admin, pve)
        guest = pve.state.guests[100]
        reply = mount(admin, device, boot="once")
        assert reply.status_code == 200, reply.text
        assert "inside the guest" in reply.json()["note"]
        # Stopped at once and started (a reset would have begun from the order it began with), from the image.
        assert power_tasks(pve) == ["qmstop", "qmstart"] and guest.status == "running" and guest.booted == [f"ide2 {DEBIAN}"]
        # Its order as before for every start by Proxmox after this one: pending, as on a running guest.
        assert guest.running_order == "order=ide2;scsi0;net0" and {**guest.config, **guest.pending}["boot"] == FIRST_ORDER
        assert reply.json()["mounted"]["first"] is False
        # A restart from inside the guest (a reset of the same process) starts from the image again, as the box says.
        guest.booted.clear()
        assert admin.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_reset"}).status_code == 200
        assert guest.booted == [f"ide2 {DEBIAN}"]
        # A start by Proxmox does not.
        assert admin.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power_long"}).status_code == 200
        assert admin.post(f"/api/v1/devices/{device}/actions", json={"action": "power_on"}).status_code == 200
        assert guest.booted[-1] == "scsi0"
        assert [entry["event"] for entry in entries(admin, "media_mounted", "media_booted")] == ["media_mounted", "media_booted"]
        assert {key: entries(admin, "media_booted")[0][key] for key in ("user", "image", "boot", "restart")} == {"user": "admin", "image": DEBIAN, "boot": "once", "restart": True}
        # Stopped, a guest is started from it (no stop first).
        assert admin.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power_long"}).status_code == 200
        del pve.state.tasks[:]
        assert mount(admin, device, boot="once").status_code == 200
        assert power_tasks(pve) == ["qmstart"] and guest.booted[-1] == f"ide2 {DEBIAN}"


def test_a_guest_started_from_an_image_until_it_is_unmounted_has_its_order_back_at_the_unmount(tmp_path: Path, pve: FakeProxmox) -> None:
    with wall(tmp_path) as admin:
        # Stopped: the order is its own at once, and its next start is from the image.
        device = a_guest(admin, pve, 101)
        guest = pve.state.guests[101]
        reply = mount(admin, device, machine="db", boot="until_unmounted")
        assert reply.status_code == 200, reply.text
        assert "next start" in reply.json()["note"] and power_tasks(pve) == []
        assert guest.config["boot"] == "order=ide2;scsi0;net0" and reply.json()["mounted"]["first"] is True
        assert admin.post(f"/api/v1/devices/{device}/actions", json={"action": "power_on"}).status_code == 200
        assert guest.booted == [f"ide2 {DEBIAN}"]
        reply = unmount(admin, device, machine="db")
        assert (reply.status_code, reply.json()["note"]) == (200, None), reply.text
        assert guest.config["ide2"] == "none,media=cdrom" and {**guest.config, **guest.pending}["boot"] == FIRST_ORDER
        # Running, and restarted now: from the image at once; and its order back at the unmount, for its next start.
        other = a_guest(admin, pve, 100)
        web = pve.state.guests[100]
        reply = mount(admin, other, boot="until_unmounted", restart=True)
        assert reply.status_code == 200, reply.text
        assert power_tasks(pve) == ["qmstart", "qmstop", "qmstart"] and web.booted == [f"ide2 {DEBIAN}"]
        assert {**web.config, **web.pending}["boot"] == "order=ide2;scsi0;net0"
        assert unmount(admin, other).status_code == 200
        assert {**web.config, **web.pending}["boot"] == FIRST_ORDER and web.config["ide2"] == "none,media=cdrom"
        assert [entry["event"] for entry in entries(admin, "media_mounted", "media_booted", "media_unmounted")] == ["media_mounted", "media_booted", "media_unmounted"] * 2
        # A restart without starting from it is a power button's; and a way of starting it does not know is none.
        for asked in ({"boot": "none", "restart": True}, {"boot": "now"}):
            reply = mount(admin, other, **asked)
            assert reply.status_code == 422, reply.text


def test_an_order_it_set_is_left_and_said_where_qkvm_does_not_know_the_one_before(tmp_path: Path, pve: FakeProxmox) -> None:
    with wall(tmp_path) as admin:
        device = a_guest(admin, pve, 101)
        assert mount(admin, device, machine="db", boot="until_unmounted").status_code == 200
        proxmox._BOOT_WAS.clear()  # (as after a restart of qKVM)
        reply = unmount(admin, device, machine="db")
        assert reply.status_code == 200 and "still begins with the CD-ROM drive" in reply.json()["note"]
        guest = pve.state.guests[101]
        assert guest.config["boot"] == "order=ide2;scsi0;net0" and guest.config["ide2"] == "none,media=cdrom"
        # And one changed on Proxmox since it was set is left as it is: its own words, no "put back" over them.
        assert mount(admin, device, machine="db", boot="until_unmounted").status_code == 200
        guest.config["boot"] = "order=ide2;net0;scsi0"
        assert unmount(admin, device, machine="db").status_code == 200
        assert guest.config["boot"] == "order=ide2;net0;scsi0"


def test_a_boot_order_written_the_old_way_is_not_changed(tmp_path: Path, pve: FakeProxmox) -> None:
    pve.state.guests[100].config["boot"] = "cdn"
    with wall(tmp_path) as admin:
        device = a_guest(admin, pve)
        reply = mount(admin, device, boot="once")
        assert (reply.status_code, reply.json()["code"], reply.json()["mounted"]) == (409, "action_failed", True), reply.text
        assert "Boot Order" in reply.json()["message"] and reply.json()["message"].startswith("The image is mounted")
        guest = pve.state.guests[100]
        assert guest.config["boot"] == "cdn" and guest.config["ide2"] == f"{DEBIAN},media=cdrom" and power_tasks(pve) == []
        assert [entry["event"] for entry in entries(admin, "media_mounted", "media_boot_failed")] == ["media_mounted", "media_boot_failed"]


def test_a_guest_without_a_cd_rom_drive_is_given_one(tmp_path: Path, pve: FakeProxmox) -> None:
    del pve.state.guests[100].config["ide2"]
    pve.state.guests[101].config["ide2"] = "local-lvm:vm-101-disk-1,size=4G"  # (its ide2 a disk: the drive goes beside it)
    with wall(tmp_path) as admin:
        device = a_guest(admin, pve)
        reply = mount(admin, device)
        assert reply.status_code == 200, reply.text
        assert "no CD-ROM drive: one was added (ide2)" in reply.json()["note"]
        guest = pve.state.guests[100]
        assert guest.pending == {"ide2": f"{DEBIAN},media=cdrom"} and "ide2" not in guest.config  # (running: from its next start)
        stopped = a_guest(admin, pve, 101)
        assert mount(admin, stopped, machine="db").status_code == 200
        assert pve.state.guests[101].config["ide0"] == f"{DEBIAN},media=cdrom" and pve.state.guests[101].config["ide2"].startswith("local-lvm:")


# --- what the token may, and which guest --------------------------------------------------------------------------


def test_what_the_token_lacks_is_said_in_proxmoxs_words_and_nothing_else_is_done(tmp_path: Path, pve: FakeProxmox) -> None:
    pve.state.storages["hidden"] = Storage({"secret-install.iso": 1}, may_see=False)  # (no Datastore.Audit: not even named)
    pve.state.storages["nas"] = Storage({"windows.iso": 6_000_000_000}, active=False)
    guest = pve.state.guests[100]
    with wall(tmp_path) as admin:
        device = a_guest(admin, pve)
        body = admin.get(media(device)).json()
        assert [one["name"] for one in body["images"]] == ["alpine-3.21.iso", "debian-13.iso"]
        assert body["unseen"] == ["nas: Proxmox says it is not active"] and "hidden" not in str(body)
        reply = mount(admin, device, image="hidden:iso/secret-install.iso")
        assert (reply.status_code, reply.json()["code"]) == (409, "changed")
        # No VM.Config.CDROM: nothing is mounted.
        guest.may_cdrom = False
        reply = mount(admin, device)
        assert (reply.status_code, reply.json()["mounted"]) == (502, False) and "VM.Config.CDROM" in reply.json()["message"], reply.text
        assert pve.state.changes == [] and "VM.Config.CDROM" in entries(admin, "media_mount_failed")[-1]["error"]
        # No VM.Config.Disk: mounted, and its boot order left as it was, and said.
        guest.may_cdrom, guest.may_disk = True, False
        reply = mount(admin, device, boot="until_unmounted")
        assert (reply.status_code, reply.json()["mounted"]) == (502, True) and "VM.Config.Disk" in reply.json()["message"], reply.text
        assert guest.config["ide2"] == f"{DEBIAN},media=cdrom" and {**guest.config, **guest.pending}["boot"] == FIRST_ORDER
        # No VM.PowerMgmt: not restarted, and the order it set for the start that did not come about put back.
        guest.may_disk, guest.may_power = True, False
        reply = mount(admin, device, boot="once")
        assert (reply.status_code, reply.json()["mounted"]) == (502, True) and "VM.PowerMgmt" in reply.json()["message"], reply.text
        assert {**guest.config, **guest.pending}["boot"] == FIRST_ORDER and power_tasks(pve) == []
    assert fetched_or_sent_anything(pve) == []


def test_another_vm_under_the_guests_number_is_sent_nothing(tmp_path: Path, pve: FakeProxmox) -> None:
    with wall(tmp_path) as admin:
        device = a_guest(admin, pve)
        assert mount(admin, device).status_code == 200
        pve.delete_guest(100)
        pve.make_guest("intruder")  # (Proxmox gives it the lowest number that is free: the guest's)
        for reply in (admin.get(media(device)), mount(admin, device, image=ALPINE), unmount(admin, device), mount(admin, device, boot="once")):
            assert (reply.status_code, reply.json()["code"]) == (502, "another_machine"), reply.text
        intruder = pve.state.guests[100]
        assert intruder.config["ide2"] == "none,media=cdrom" and intruder.config["boot"] == FIRST_ORDER and power_tasks(pve) == []
        assert len(pve.state.changes) == 1  # (the first mount, of the guest itself)
        wait_until(lambda: state_of(admin, device).get("media") is None, "the tile says the other one's drive is the guest's")


def test_settings_changed_on_proxmox_between_the_read_and_the_change_are_not_written_over(tmp_path: Path, pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    read = ProxmoxGuest._this_guest
    reads = 0

    async def and_then_somebody_changes_it(self: ProxmoxGuest) -> dict[str, Any]:
        nonlocal reads
        config = await read(self)
        reads += 1
        pve.state.guests[100].config["net0"] = f"virtio=BC:24:11:5E:1A:01,bridge=vmbr{reads}"  # (on Proxmox's own page, a moment later)
        return config

    with wall(tmp_path) as admin:
        device = a_guest(admin, pve)
        monkeypatch.setattr(ProxmoxGuest, "_this_guest", and_then_somebody_changes_it)
        reply = mount(admin, device)
        assert (reply.status_code, reply.json()["code"]) == (409, "changed"), reply.text
        assert pve.state.changes == [] and pve.state.guests[100].config["ide2"] == "none,media=cdrom"


def test_what_a_proxmox_lists_is_taken_by_kind(tmp_path: Path, pve: FakeProxmox) -> None:
    pve.state.hostile = "odd_images"
    pve.state.storages["local"].images.update({"with space.iso": 1, "comma,media=disk.iso": 1, "notes.txt": 1})
    with wall(tmp_path) as admin:
        device = a_guest(admin, pve)
        body = admin.get(media(device)).json()
        assert [one["id"] for one in body["images"]] == [ALPINE, DEBIAN, "local:iso/odd.iso"] and body["left_out"] == 10
        assert next(one for one in body["images"] if one["name"] == "odd.iso")["size"] is None  # (a size that is no number is none)
        pve.state.hostile = "odd_storages"
        body = admin.get(media(device)).json()
        assert {one["where"] for one in body["images"]} == {"local"} and body["unseen"] == ["zz: Proxmox says it is not active"]


def test_a_machine_without_virtual_media_says_so_and_is_sent_nothing(tmp_path: Path) -> None:
    fake = FakeKvm(FakeState()).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url)
            assert "media" not in admin.get("/api/v1/wall").json()["devices"][0]["can"]
            for reply in (admin.get(media(device)), mount(admin, device, machine="x"), unmount(admin, device, machine="x")):
                assert (reply.status_code, reply.json()["code"]) == (404, "no_virtual_media"), reply.text
            assert admin.get("/api/v1/devices/nosuch01/media").json()["code"] == "not_found"
    finally:
        fake.stop()


def test_one_thing_at_a_time_on_a_machine(tmp_path: Path, pve: FakeProxmox) -> None:
    pve.state.power_takes = 1.5  # (a start seen a moment after its task)
    with wall(tmp_path) as admin:
        device = a_guest(admin, pve, 101)
        thread, answers = in_background(lambda: admin.post(f"/api/v1/devices/{device}/actions", json={"action": "power_on"}))
        wait_until(lambda: "qmstart" in power_tasks(pve), "the start never went out")
        reply = mount(admin, device, machine="db")
        assert (reply.status_code, reply.json()["code"]) == (409, "busy"), reply.text
        thread.join(30)
        assert answers[0].status_code == 200 and pve.state.changes == []
        assert mount(admin, device, machine="db").status_code == 200


def test_a_restart_from_the_media_waits_for_whoever_has_the_keyboard_and_a_mount_does_not(tmp_path: Path, pve: FakeProxmox) -> None:
    from tests.test_live import Wall

    with Wall(tmp_path) as live_wall:
        admin = live_wall.browser()
        device = live_wall.add(admin, pve.guest_url(100), **{**TOKEN, "password": SECRET})
        assert admin.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": OTHER}).status_code == 201
        olga = live_wall.browser("olga", OTHER)
        line = live_wall.line(olga, device, max_fps=5)
        assert line.picture(timeout=20).kind == 2
        line.say(t="control", on=True)
        assert line.word("control")["on"] is True
        # A restart is a power button's: not while somebody is at the keyboard, and they are named.
        for asked in ({"boot": "once"}, {"boot": "until_unmounted", "restart": True}):
            reply = mount(admin, device, **asked)
            assert (reply.status_code, reply.json()["code"], reply.json()["by"]) == (409, "busy", "olga"), reply.text
        assert pve.state.changes == [] and power_tasks(pve) == []
        # Putting an image in the drive touches no keyboard: it is done.
        assert mount(admin, device).status_code == 200 and pve.state.guests[100].config["ide2"] == f"{DEBIAN},media=cdrom"
        line.close()


def test_a_token_is_refused_whichever_role_the_right_is_given(tmp_path: Path, pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # A token is made a viewer or an operator; the media routes refuse one besides, whatever it is taken for.
    from qkvm import server

    with wall(tmp_path) as admin:
        device = a_guest(admin, pve)
        token = admin.post("/api/v1/tokens", json={"name": "script", "role": "operator"}).json()["token"]
        monkeypatch.setattr(server, "MEDIA_ROLE", "operator")  # (were the right ever opened to operators: still a person's)
        robot = admin.__class__(admin.app, headers={"Authorization": f"Bearer {token}"}, client=("192.0.2.50", 51032))
        robot.portal = admin.portal
        account(admin, "olga", "operator")
        olga = browser(admin, "olga", OTHER, port=50034)
        reply = robot.get(media(device))
        assert (reply.status_code, reply.json()["code"]) == (403, "not_allowed") and "person" in reply.json()["message"]
        assert olga.get(media(device)).status_code == 200  # (the right is the role's, one place: MEDIA_ROLE)
