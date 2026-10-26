"""A virtual machine on Proxmox VE: its address, its token, its state and power buttons, its screen through the console
Proxmox hands out (a ticket, a WebSocket, RFB), what that costs Proxmox, and what a Proxmox can make of it.

Against the stand-in (fake_proxmox.py), typed from what a real Proxmox VE 9.2 answered; test_real_proxmox.py asks a
real one again where one is named in the environment.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import pytest

from qkvm import cli, kvm, proxmox, rfb, update, vault, vncdevice
from qkvm.kvm import REJECTED, DeviceSpec, KvmError
from qkvm.proxmox import Address, ProxmoxGuest, address_of
from tests.fake_proxmox import SECRET, TOKEN_ID, FakeProxmox, Guest, PveState
from tests.fake_vnc import VncState
from tests.test_users import OTHER, account, visitor
from tests.test_wall import snap, wait_until, wall

TOKEN = {"username": TOKEN_ID, "password": SECRET, "kind": "proxmox"}


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(proxmox, "LOOK_EVERY", 0)
    monkeypatch.setattr(proxmox, "FOLLOW_UP", ())
    monkeypatch.setattr(proxmox, "CONFIRM_EVERY", 0.05)
    monkeypatch.setattr(proxmox.ProxmoxConsole, "LOOK_PACE", 0.05)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")
    REJECTED.clear()
    vncdevice._PACED.clear()
    proxmox._NODES.clear()
    proxmox._LISTED_FOR.clear()


def two_guests() -> PveState:
    return PveState(guests={
        100: Guest(100, "web", screen=VncState(width=320, height=200, name="QEMU (web)")),
        101: Guest(101, "db", status="stopped", screen=VncState(width=640, height=480, name="QEMU (db)", seed=2)),
    })  # fmt: skip


@pytest.fixture
def caplog(caplog: pytest.LogCaptureFixture) -> Iterator[pytest.LogCaptureFixture]:
    # CLI tests deliberately configure qkvm not to propagate to the root logger.
    # Hear the application's real logger directly, including after those tests.
    logger = logging.getLogger("qkvm")
    logger.addHandler(caplog.handler)
    try:
        yield caplog
    finally:
        logger.removeHandler(caplog.handler)


@pytest.fixture
def pve(tmp_path: Path) -> Iterator[FakeProxmox]:
    fake = FakeProxmox(two_guests(), tls_dir=tmp_path / "pve").start()
    yield fake
    fake.stop()


def a_guest(fake: FakeProxmox, vmid: int = 100, **spec: Any) -> ProxmoxGuest:
    return ProxmoxGuest(DeviceSpec(id="ab12", name="guest", base_url=fake.guest_url(vmid), **{"username": TOKEN_ID, "password": SECRET, "kind": "proxmox", **spec}))


async def picture_of(device: Any, within: float = 15.0) -> kvm.Snapshot:
    """The first picture a tile gets, asked for as a tile asks: again and again until it comes."""
    deadline = time.monotonic() + within
    while True:
        try:
            return await device.snapshot(4000)
        except KvmError as ex:
            if ex.code != "no_stream" or time.monotonic() > deadline:
                raise
        await asyncio.sleep(0.05)


def state_of(client: Any, device: str) -> dict[str, Any]:
    return dict(client.get("/api/v1/status").json()[device])


def picture(client: Any, device: str) -> Any:
    reply = None

    def arrived() -> bool:
        nonlocal reply
        reply = client.get(snap(device))
        return bool(reply.status_code == 200)

    wait_until(arrived, "the guest's screen never came", timeout=20)
    return reply


def consoles_opened(fake: FakeProxmox) -> int:
    """How many tasks Proxmox wrote for consoles asked for: what its owner sees in the node's task log."""
    return sum(1 for task in fake.state.tasks if task["type"] == "vncproxy")


# --- addresses ---------------------------------------------------------------------------------------------------


def test_how_a_guests_address_is_read_and_written() -> None:
    assert address_of("pve.lan") == Address("https://pve.lan:8006")
    assert address_of(" PVE.lan:8006/ ") == Address("https://pve.lan:8006")
    assert address_of("https://192.168.1.5:443/") == Address("https://192.168.1.5")
    assert address_of("pve.lan/100") == Address("https://pve.lan:8006", None, 100)
    assert address_of("pve.lan:8006/pve1/101") == Address("https://pve.lan:8006", "pve1", 101)
    assert address_of("https://pve.lan:8006/nodes/pve1/qemu/100") == Address("https://pve.lan:8006", "pve1", 100)
    # The addresses Proxmox's own page shows: a guest picked in its tree, and its console.
    assert address_of("https://pve.lan:8006/#v1:0:=qemu%2F105:4:::::::") == Address("https://pve.lan:8006", None, 105)
    assert address_of("https://pve.lan:8006/?console=kvm&novnc=1&vmid=107&vmname=x&node=pve2&resize=off&cmd=") == Address("https://pve.lan:8006", "pve2", 107)
    assert address_of("[::1]:8006/100") == Address("https://[::1]:8006", None, 100)
    for bad in ("", "http://pve.lan", "pve.lan:x", "user@pve.lan", "pve.lan/99", "pve.lan/abc", "pve.lan/pve_1/100", "pve.lan/a/b/c",
                "pve.lan/nodes/pve1/qemu/1000000000", "https://pve.lan:8006/nodes/pve1/lxc/200", "https://pve.lan:8006/#v1:0:=lxc%2F200:4",
                "https://pve.lan:8006/?console=lxc&vmid=200&node=pve1"):  # fmt: skip
        with pytest.raises(ValueError):
            address_of(bad)
    assert proxmox.guest_url("https://pve.lan:8006", "pve1", 100) == "https://pve.lan:8006/nodes/pve1/qemu/100"
    assert proxmox.is_guest("https://pve.lan:8006/nodes/pve1/qemu/100") and not proxmox.is_guest("https://pve.lan:8006/100")
    assert proxmox.console_page("https://pve.lan:8006/nodes/pve1/qemu/100") == "https://pve.lan:8006/?console=kvm&novnc=1&vmid=100&node=pve1&resize=scale"
    assert proxmox.console_page("no address at all") == "no address at all"  # (never fails: the list of tiles is drawn whatever is saved)


def test_what_a_proxmox_lists_is_taken_by_kind() -> None:
    listed, containers = proxmox.guests_in([
        {"type": "qemu", "vmid": 101, "node": "pve1", "name": "db", "status": "stopped"},
        {"type": "qemu", "vmid": 100, "node": "pve2", "name": "web\nforged line", "status": "running"},
        {"type": "qemu", "vmid": 100, "node": "pve1", "name": "twice"},  # (the first one counts)
        {"type": "qemu", "vmid": 102, "node": "pve1", "template": 1},  # a template: no guest to look at
        {"type": "lxc", "vmid": 200, "node": "pve1"},
        {"type": "qemu", "vmid": "103", "node": "pve1"}, {"type": "qemu", "vmid": 104, "node": "bad node"},
        {"type": "qemu", "vmid": 99, "node": "pve1"}, {"type": "qemu", "vmid": True, "node": "pve1"},
        {"type": "node", "node": "pve1"}, "nothing", None, [1, 2],
    ])  # fmt: skip
    assert listed == [
        {"vmid": 100, "node": "pve2", "name": "web forged line", "status": "running"},
        {"vmid": 101, "node": "pve1", "name": "db", "status": "stopped"},
    ] and containers == 1
    assert proxmox.guests_in({"data": "not a list"}) == ([], 0)
    assert proxmox.own_number({"smbios1": "uuid=23e4e388-cf47-451b-b791-20054c233cc6,manufacturer=QEMU"}) == proxmox.own_number({"smbios1": "uuid=23E4E388-CF47-451B-B791-20054C233CC6"})
    assert str(proxmox.own_number({"smbios1": "uuid=23e4e388-cf47-451b-b791-20054c233cc6"})).startswith("proxmox:")
    for none in ({}, {"smbios1": "manufacturer=x"}, {"smbios1": "uuid=00000000-0000-0000-0000-000000000000"}, {"smbios1": 5}, None, {"smbios1": "uuid=" + "a" * 5000}):
        assert proxmox.own_number(none) is None


# --- adding it, and what its tile says ------------------------------------------------------------------------------


def test_a_guest_is_added_and_shows_its_screen(tmp_path: Path, pve: FakeProxmox) -> None:
    with wall(tmp_path) as client:
        reply = client.post("/api/v1/devices", json={"url": pve.guest_url(100), **TOKEN})
        assert reply.status_code == 201, reply.text
        body = reply.json()
        device = body["device"]["id"]
        assert body["device"]["kind"] == "proxmox" and body["device"]["picture"] is False
        assert body["device"]["name"] == "web" and body["device"]["url"] == pve.guest_url(100)  # named after the guest
        assert body["device"]["host"] == f"127.0.0.1:{pve.port}"
        assert body["device"]["open_url"] == f"{pve.url}/?console=kvm&novnc=1&vmid=100&node=pve1&resize=scale"  # Proxmox's own console
        assert body["about"] == {"model": "VM 100 on pve1", "version": "Proxmox VE 9.2.21", "hostname": "web"}
        assert consoles_opened(pve) == 0  # adding it reads its state: no console, and no task in Proxmox's log
        status = state_of(client, device)
        assert status["state"] == "online" and status["screen"] is True and status["atx"] == {"enabled": True, "power": True, "hdd": None}
        assert status["can"] == ["screen", "keys", "text", "power", "reset", "power_state", "live", "control"]
        assert status["server"]["proxmox"] == {"node": "pve1", "vmid": 100, "status": "running", "qmpstatus": "running", "uptime": 1234}
        assert (status["server"]["power"], status["server"]["processors"], status["server"]["memory_gib"]) == ("Running", 2, 2.0)
        frame = picture(client, device)
        assert frame.content[:3] == b"\xff\xd8\xff"
        wait_until(lambda: state_of(client, device)["video"]["width"] == 320, "the screen's size is not said")
        # One console, one task; its ticket used once, at once; its password the one Proxmox handed out with it, and
        # the token in a header of every request, never in an address.
        assert consoles_opened(pve) == 1 and pve.state.upgrades == 1 and pve.state.consoles == 1
        guest = pve.state.guests[100].screen
        assert (guest.password_tries, guest.rejected, guest.shared) == (1, 0, [1])
        assert pve.state.in_the_clear == [] and pve.state.refused == 0
    # Taken off the wall (the wall stopped), its console is given back.
    wait_until(lambda: pve.state.consoles == 0, "the console was left open")
    assert [task["status"] for task in pve.state.tasks] == ["OK"]


def test_the_guests_a_token_may_see_are_listed_to_pick_from(tmp_path: Path, pve: FakeProxmox) -> None:
    pve.state.guests[102] = Guest(102, "hidden", may_see=False)
    pve.state.containers = [300]
    with wall(tmp_path) as admin:
        reply = admin.post("/api/v1/proxmox/guests", json={"url": f"127.0.0.1:{pve.port}", "username": TOKEN_ID, "password": SECRET})
        assert reply.status_code == 200, reply.text
        said = reply.json()
        assert said["named"] is None and said["containers"] == 1
        assert said["guests"] == [
            {"vmid": 100, "node": "pve1", "name": "web", "status": "running", "url": pve.guest_url(100), "known_as": None},
            {"vmid": 101, "node": "pve1", "name": "db", "status": "stopped", "url": pve.guest_url(101), "known_as": None},
        ]  # (not the one the token may not see, nor the container)
        assert admin.post("/api/v1/devices", json={"url": pve.guest_url(101), **TOKEN}).status_code == 201
        again = admin.post("/api/v1/proxmox/guests", json={"url": f"{pve.url}/101", "username": TOKEN_ID, "password": SECRET}).json()
        assert again["named"] == pve.guest_url(101) and again["guests"][1]["known_as"] == "db"
        unseen = admin.post("/api/v1/proxmox/guests", json={"url": f"{pve.url}/102", "username": TOKEN_ID, "password": SECRET})
        assert unseen.status_code == 422 and "sees no virtual machine 102" in unseen.json()["message"]
        wrong = admin.post("/api/v1/proxmox/guests", json={"url": pve.url, "username": TOKEN_ID, "password": "00000000-0000-0000-0000-000000000000"})
        assert (wrong.status_code, wrong.json()["code"]) == (422, "auth_failed")
        not_a_token = admin.post("/api/v1/proxmox/guests", json={"url": pve.url, "username": "root@pam", "password": "a password"})
        assert (not_a_token.status_code, not_a_token.json()["code"]) == (422, "invalid")
        assert pve.state.refused == 1  # (what is no token was sent nowhere)
        account(admin, "olga", "operator")
        operator = visitor(admin, 50012)
        assert operator.post("/api/v1/login", json={"name": "olga", "password": OTHER}).status_code == 200
        assert operator.post("/api/v1/proxmox/guests", json={"url": pve.url, "username": TOKEN_ID, "password": SECRET}).status_code == 403  # adding is for admins


def test_a_guest_named_by_its_number_alone_gets_its_node_looked_up(tmp_path: Path, pve: FakeProxmox) -> None:
    pve.state.nodes = ["pve1", "pve2"]
    pve.state.guests[100].node = "pve2"
    with wall(tmp_path) as client:
        reply = client.post("/api/v1/devices", json={"url": f"127.0.0.1:{pve.port}/100", **TOKEN})
        assert reply.status_code == 201, reply.text
        assert reply.json()["device"]["url"] == pve.guest_url(100, "pve2")
        twice = client.post("/api/v1/devices", json={"url": f"{pve.url}/pve2/100", **TOKEN})
        assert (twice.status_code, twice.json()["code"]) == (409, "duplicate")
        nothing = client.post("/api/v1/devices", json={"url": f"{pve.url}", **TOKEN})
        assert nothing.status_code == 422 and "Name the guest" in nothing.json()["message"]
        # An edit that names the guest by its number again, the token not typed: the saved one is used to look its node
        # up, at the Proxmox it was saved for.
        device = reply.json()["device"]["id"]
        edit = client.put(f"/api/v1/devices/{device}", json={"url": f"{pve.url}/100", "username": TOKEN_ID, "password": "", "kind": "proxmox"})
        assert edit.status_code == 200, edit.text
        assert edit.json()["device"]["url"] == pve.guest_url(100, "pve2")


def test_the_saved_token_is_not_sent_to_another_proxmox_to_look_a_node_up(tmp_path: Path, pve: FakeProxmox) -> None:
    other = FakeProxmox(two_guests(), tls_dir=tmp_path / "other").start()
    try:
        with wall(tmp_path) as client:
            device = client.post("/api/v1/devices", json={"url": pve.guest_url(100), **TOKEN}).json()["device"]["id"]
            moved = client.put(f"/api/v1/devices/{device}", json={"url": f"{other.url}/100", "username": TOKEN_ID, "password": "", "kind": "proxmox"})
            assert moved.status_code == 422, moved.text
            assert other.state.requests == [] and other.state.refused == 0  # nothing went there, the token least of all
    finally:
        other.stop()


def test_the_saved_token_is_not_carried_to_another_host_that_shows_the_same_certificate(tmp_path: Path, pve: FakeProxmox) -> None:
    # A certificate remembered for a guest vouched for the new address of a tile moved without its token typed, as it does
    # for a KVM, whose certificate is its own. A guest's is its Proxmox's, or a proxy's in front of it, or a wildcard that
    # other hosts show as well: whatever answered there with that certificate was sent the saved token.
    other = FakeProxmox(two_guests(), tls_dir=tmp_path / "pve").start()  # (another host, with the same certificate and key)
    try:
        with wall(tmp_path / "data") as client:
            device = client.post("/api/v1/devices", json={"url": pve.guest_url(100), **TOKEN}).json()["device"]["id"]
            for force in (False, True):
                moved = client.put(f"/api/v1/devices/{device}", json={"url": other.guest_url(100), "username": TOKEN_ID, "password": "", "kind": "proxmox", "force": force})
                assert (moved.status_code, moved.json().get("code")) == (422, "password_needed"), moved.text
            assert other.state.requests == [] and other.state.refused == 0  # nothing went there, the token least of all
            # Whoever types the token says "this is the guest, at this address".
            typed = client.put(f"/api/v1/devices/{device}", json={"url": other.guest_url(100), "username": TOKEN_ID, "password": SECRET, "kind": "proxmox"})
            assert typed.status_code == 200, typed.text
    finally:
        other.stop()


def test_two_guests_of_one_proxmox_are_two_machines_and_one_guest_twice_is_one(tmp_path: Path, pve: FakeProxmox) -> None:
    with wall(tmp_path) as client:
        first = client.post("/api/v1/devices", json={"url": pve.guest_url(100), **TOKEN})
        second = client.post("/api/v1/devices", json={"url": pve.guest_url(101), **TOKEN})
        assert (first.status_code, second.status_code) == (201, 201), second.text  # (one certificate, two guests)
        # The same guest by another address of the same Proxmox: the number it gives for itself says so.
        again = client.post("/api/v1/devices", json={"url": f"https://localhost:{pve.port}/nodes/pve1/qemu/100", **TOKEN})
        assert (again.status_code, again.json()["code"]) == (409, "same_device"), again.text


def test_a_stopped_guest_is_said_off_and_no_console_is_asked_for(tmp_path: Path, pve: FakeProxmox) -> None:
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pve.guest_url(101), **TOKEN}).json()["device"]["id"]
        status = state_of(client, device)
        assert status["state"] == "no_signal" and status["screen"] is False and status["atx"]["power"] is False
        assert status["can"] == ["power", "reset", "power_state"] and status["server"]["power"] == "Stopped"
        assert status["health"] == {"temp": None, "cpu": None, "mem": None}
        for _ in range(5):
            reply = client.get(snap(device))
            assert (reply.status_code, reply.json()["code"]) == (404, "no_picture")
        assert consoles_opened(pve) == 0  # (Proxmox would hand out a ticket all the same, and write a failed task)


def test_a_wrong_token_is_a_no_and_is_not_offered_again_and_again(tmp_path: Path, pve: FakeProxmox) -> None:
    wrong = {**TOKEN, "password": "00000000-0000-0000-0000-000000000000"}
    with wall(tmp_path) as client:
        reply = client.post("/api/v1/devices", json={"url": pve.guest_url(100), **wrong})
        assert (reply.status_code, reply.json()["code"]) == (422, "auth_failed"), reply.text
        assert "token" in reply.json()["message"]
        # Saved all the same, with a second guest of the same Proxmox: both tiles say so, and the token goes out no more.
        for vmid in (100, 101):
            assert client.post("/api/v1/devices", json={"url": pve.guest_url(vmid), **wrong, "force": True}).status_code == 201
        devices = [d["id"] for d in client.get("/api/v1/wall").json()["devices"]]
        for device in devices:
            wait_until(lambda device=device: state_of(client, device)["state"] == "auth", "the tile never said that the token was rejected")
            assert client.get(snap(device)).status_code != 200
        time.sleep(1.0)
        # Typed by a person three times, tried at once each time; then held back, for both guests, whatever they ask.
        assert pve.state.refused == 3 and consoles_opened(pve) == 0
        fixed = client.put(f"/api/v1/devices/{devices[0]}", json={"url": pve.guest_url(100), **TOKEN})
        assert fixed.status_code == 200, fixed.text
        wait_until(lambda: state_of(client, devices[0])["state"] == "online", "the right token did not let the wall in")


def test_what_is_no_token_is_sent_nowhere(tmp_path: Path, pve: FakeProxmox) -> None:
    with wall(tmp_path) as client:
        for username, password in (("root@pam", SECRET), (TOKEN_ID, "a password"), (TOKEN_ID + "\r\nX: y", SECRET), (TOKEN_ID, SECRET + "\r\n")):
            reply = client.post("/api/v1/devices", json={"url": pve.guest_url(100), "kind": "proxmox", "username": username, "password": password})
            assert reply.status_code == 422, reply.text
        assert pve.state.requests == [] and pve.state.refused == 0


def test_the_token_goes_in_a_header_and_into_no_log(tmp_path: Path, pve: FakeProxmox) -> None:
    # The program's own log, as it writes it, at its finest (a library that names what it sends, at its own finer levels,
    # is kept to its warnings there: see cli.setup_logging).
    names = ("qkvm", "uvicorn.error", "httpx", "httpcore", "websockets", "asyncio")
    before = {name: (logging.getLogger(name).handlers[:], logging.getLogger(name).propagate, logging.getLogger(name).level) for name in names}
    cli.setup_logging(tmp_path, "debug")
    try:
        with wall(tmp_path / "wall") as client:
            device = client.post("/api/v1/devices", json={"url": pve.guest_url(100), **TOKEN}).json()["device"]["id"]
            picture(client, device)
            assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "text", "text": "root"}).status_code == 200
            wrong = client.post("/api/v1/devices", json={"url": pve.guest_url(101), **TOKEN, "password": "00000000-0000-0000-0000-000000000000"})
            assert wrong.status_code == 422
    finally:
        cli.stop_logging()
        for name, (handlers, propagate, level) in before.items():
            logger = logging.getLogger(name)
            logger.handlers[:], logger.propagate = handlers, propagate
            logger.setLevel(level)
    # (Less the lines of the web server's logger, which here are the stand-in's own: it runs in this process, and its web
    # server writes what it is sent at its finest level. The wall here has no web server of its own: a test client.)
    written = "\n".join(line for line in (tmp_path / "qkvm.log").read_text(encoding="utf-8").splitlines() if " uvicorn.error: " not in line)
    assert "rejected the API token" in written  # (the log was written: what is not in it was not left out by accident)
    assert pve.state.in_the_clear == []
    assert SECRET not in written and "PVEVNC" not in written
    assert all(ticket.password not in written for ticket in pve.state.tickets)


# --- the console, and what it costs Proxmox --------------------------------------------------------------------------


def test_one_console_is_held_while_somebody_looks_and_let_go_of_after(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(proxmox.ProxmoxConsole, "LET_GO_AFTER", 1.0)

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            await picture_of(device)
            for _ in range(30):  # three seconds of a tile that is looked at: one console all along
                await device.snapshot(640)
                await asyncio.sleep(0.1)
            assert consoles_opened(pve) == 1 and pve.state.consoles == 1
            deadline = time.monotonic() + 5
            while pve.state.consoles and time.monotonic() < deadline:  # nobody looks: let go of a second after
                await asyncio.sleep(0.05)
            assert pve.state.consoles == 0 and consoles_opened(pve) == 1
            await device.status()
            assert (await device.status())["state"] == "online"  # (its state is read without a console)
            assert consoles_opened(pve) == 1
            await picture_of(device)  # somebody looks again: a console again
            assert consoles_opened(pve) == 2
            assert all(ticket.used for ticket in pve.state.tickets) and pve.state.hung == 0
        finally:
            await device.close()

    asyncio.run(run())


def test_a_console_that_fails_is_asked_for_less_and_less_often(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(proxmox, "CONSOLE_RETRY", (0.3, 0.6, 1.2, 60.0))
    pve.state.guests[100].console_fails = True  # its worker fails: the upgrade is taken, and closed without a greeting

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            began = time.monotonic()
            deadline = began + 5.0
            while time.monotonic() < deadline:
                try:
                    await device.snapshot(640)
                except KvmError:
                    pass
                await asyncio.sleep(0.05)
            # Asked for a picture a hundred times: four consoles (each failing half a second after it was opened, then left
            # alone 0.3, 0.6 and 1.2 s), then left alone for a minute.
            assert consoles_opened(pve) == 4, [round(task["at"] - began, 2) for task in pve.state.tasks]
            assert [task["status"] for task in pve.state.tasks] == ["Failed to run vncproxy."] * 4
            status = await device.status()
            for _ in range(40):  # (the status is read again in the background: the one just handed over may be older)
                if status["server"]["no_screen"] is not None:
                    break
                await asyncio.sleep(0.05)
                status = await device.status()
            assert status["server"]["no_screen"] is not None and status["screen"] is False  # said on the tile, after three
            assert "live" not in status["can"] and "control" not in status["can"]
        finally:
            await device.close()

    asyncio.run(run())


def test_a_guest_stopped_and_started_again_shows_its_screen_at_once(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # A console that ended because its guest stopped did not fail: once the guest runs again its screen is asked for at
    # once, not after the pause of a console that keeps failing.
    monkeypatch.setattr(proxmox, "CONSOLE_RETRY", (60.0,))

    async def looked_at_until(device: ProxmoxGuest, state: str) -> None:
        for _ in range(100):
            device._status_at = 0.0
            await device.status()
            await asyncio.sleep(0.05)
            if (await device.status())["state"] == state:
                return
        raise AssertionError(f"the guest was never seen {state}")

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            await picture_of(device)
            pve.stop_guest(100)
            for _ in range(100):
                if device._console._connected_or_none() is None:
                    break
                await asyncio.sleep(0.05)
            await looked_at_until(device, "no_signal")
            pve.state.guests[100].status = "running"
            await looked_at_until(device, "online")
            await picture_of(device, within=5)
            assert consoles_opened(pve) == 2
        finally:
            await device.close()

    asyncio.run(run())


def test_an_upgrade_that_gets_no_answer_is_given_up_on_in_time(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(proxmox, "UPGRADE_WAIT", 1.0)
    monkeypatch.setattr(proxmox, "CONSOLE_RETRY", (0.2, 60.0))
    pve.state.hostile = "silent_upgrade"  # as Proxmox does after the port's ten seconds, or for a ticket used twice

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            began = time.monotonic()
            with pytest.raises(KvmError) as failed:
                await picture_of(device, within=10)
            assert failed.value.code == "timeout" and time.monotonic() - began < 3
            deadline = time.monotonic() + 5
            while pve.state.hung < 2 and time.monotonic() < deadline:
                with pytest.raises(KvmError):
                    await device.snapshot(640)  # (asked again after its pause: another console is asked for, in the background)
                await asyncio.sleep(0.1)
            assert pve.state.hung == 2 and consoles_opened(pve) == 2  # each try its own ticket: none used twice
            assert len({ticket.ticket for ticket in pve.state.tickets}) == 2
        finally:
            await device.close()

    asyncio.run(run())


def test_the_stand_in_keeps_proxmoxs_window_and_ticket(pve: FakeProxmox) -> None:
    # What the driver is built against, held to what a real one did: a ticket opens its console once, within the port's
    # window; after that the upgrade gets no answer; another port, or a ticket for another guest, is refused.
    from websockets.asyncio.client import connect
    from websockets.exceptions import InvalidStatus

    from qkvm.kvm import unverified_context

    pve.state.window = 60.0  # (for the first ticket: what is tried with it is not hurried by a busy machine)

    def ticket() -> tuple[str, str]:
        import httpx

        with httpx.Client(verify=False, headers={"Authorization": f"PVEAPIToken={TOKEN_ID}={SECRET}"}) as api:
            said = api.post(f"{pve.url}/api2/json/nodes/pve1/qemu/100/vncproxy", data={"websocket": "1"}).json()["data"]
        return said["port"], said["ticket"]

    def upgrade(port: str, given: str, vmid: int = 100, token: bool = True, within: float = 5.0, tries: int = 3) -> str:
        from urllib.parse import quote, urlencode

        uri = f"wss://127.0.0.1:{pve.port}/api2/json/nodes/pve1/qemu/{vmid}/vncwebsocket?" + urlencode({"port": port, "vncticket": given}, quote_via=quote)

        async def once() -> str:
            # (The client of the websockets library that reads in a thread of its own crashed CPython 3.13's ssl module once,
            # in the lab, as the stand-in closed a connection: asyncio's reads in this one.)
            headers = {"Authorization": f"PVEAPIToken={TOKEN_ID}={SECRET}"} if token else {}
            async with connect(uri, ssl=unverified_context(), additional_headers=headers, open_timeout=within, close_timeout=1) as ws:
                async with asyncio.timeout(5):
                    said = await ws.recv()
            assert isinstance(said, bytes)  # (Proxmox's console speaks in binary frames)
            return said[:12].decode()

        for _ in range(tries):
            try:
                return asyncio.run(once())
            except InvalidStatus as ex:
                return f"HTTP {ex.response.status_code}"
            except TimeoutError:
                # (The stand-in's own web server, with TLS on Linux, now and then leaves a connection unanswered that came
                # right after an upgrade it refused: about one in fifteen, never the stand-in's handler, which is not
                # reached. Asked again where an answer is what is tested.)
                continue
        return "no answer"

    port, given = ticket()
    assert upgrade(port, given, token=False) == "HTTP 401"
    assert upgrade(str(int(port) + 1), given) == "HTTP 401" and upgrade(port, given, vmid=101) == "HTTP 401"
    assert upgrade(port, given) == "RFB 003.008\n"
    assert upgrade(port, given, within=3, tries=1) == "no answer"  # used once already
    pve.state.window = 0.5
    port, given = ticket()
    time.sleep(1.0)
    assert upgrade(port, given, within=3, tries=1) == "no answer"  # the window is over
    assert [task["status"] for task in pve.state.tasks] == ["OK", "connection timed out"]


def test_the_consoles_password_is_the_one_handed_out_and_counted_nowhere(pve: FakeProxmox) -> None:
    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            await picture_of(device)
            screen = pve.state.guests[100].screen
            assert screen.password_tries == 1 and screen.rejected == 0
            assert device._console._session is not None and device._console._session.one_time is None  # used, and not kept
            client = device._console._connected_or_none()
            assert client is not None and client.password is None
            assert REJECTED.times(device._offered()) == 0 and REJECTED.wait_left(device._offered()) == 0
        finally:
            await device.close()

    asyncio.run(run())


def test_a_console_that_refuses_its_own_password_is_left_alone_and_the_token_is_not_blamed(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(proxmox, "CONSOLE_RETRY", (60.0,))
    pve.state.password_life = 0.0  # the password runs out before it is used: the console says no to it

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            with pytest.raises(KvmError) as refused:
                await picture_of(device, within=5)
            assert refused.value.code == "bad_response" and "does not let qKVM in" in refused.value.message
            assert consoles_opened(pve) == 1
            status = await device.status()
            assert status["state"] == "online" and status["error"] is None  # the tile says how the guest is; the token stands
            assert REJECTED.times(device._offered()) == 0
            for _ in range(10):
                with pytest.raises(KvmError):
                    await device.snapshot(640)
            assert consoles_opened(pve) == 1  # not asked for again meanwhile
        finally:
            await device.close()

    asyncio.run(run())


# --- the power buttons --------------------------------------------------------------------------------------------


def test_the_power_buttons(tmp_path: Path, pve: FakeProxmox) -> None:
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pve.guest_url(101), **TOKEN}).json()["device"]["id"]

        def press(action: str) -> Any:
            return client.post(f"/api/v1/devices/{device}/actions", json={"action": action})

        assert (press("atx_reset").status_code, press("atx_reset").json()["code"]) == (502, "action_failed")  # nothing to reset
        assert press("power_off").json()["note"] == "already off"
        reply = press("power_on")
        assert reply.status_code == 200 and reply.json()["note"] is None, reply.text
        wait_until(lambda: state_of(client, device)["state"] == "online", "the guest was not seen running")
        assert press("power_on").json()["note"] == "already on"
        assert press("atx_reset").status_code == 200
        assert press("power_off").status_code == 200  # asked to shut down
        assert pve.state.guests[101].status == "stopped"
        assert press("atx_power").status_code == 200  # the power button: it is off, so on
        assert press("atx_power_long").status_code == 200  # held: stopped at once
        assert pve.state.guests[101].status == "stopped"
        refused = press("reboot")
        assert (refused.status_code, refused.json()["code"]) == (422, "invalid")
        assert [task["type"] for task in pve.state.tasks] == ["qmstart", "qmreset", "qmshutdown", "qmstart", "qmstop"]
        # Asked to shut down, a guest with nothing in it to hear that goes on running: said, not waited for.
        pve.state.guests[101].ignores_shutdown = True
        assert press("power_on").status_code == 200 and press("power_off").status_code == 200
        assert pve.state.guests[101].status == "running"
        audit = client.get("/api/v1/audit", params={"q": "action"}).json()["entries"]
        assert len(audit) >= 8


def test_a_power_command_that_is_not_carried_out_is_said_so(tmp_path: Path, pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(proxmox, "CONFIRM_WITHIN", 1.0)
    pve.state.power_takes = 60.0  # taken, and not done within the time
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pve.guest_url(101), **TOKEN}).json()["device"]["id"]
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "power_on"})
        assert (reply.status_code, reply.json()["code"]) == (502, "action_failed") and "still stopped" in reply.json()["message"]


def pressed(client: Any, device: str) -> dict[str, Any]:
    """The one press of a power button the history keeps for the tile."""
    wait_until(lambda: client.get(f"/api/v1/devices/{device}/history?what=events").json()["rows"], "the press never reached the history")
    (press,) = client.get(f"/api/v1/devices/{device}/history?what=events").json()["rows"]
    return dict(press)


def test_a_start_whose_task_takes_its_time_is_waited_for_while_the_task_runs(tmp_path: Path, pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # A guest with much memory, or devices of the host's, takes its time to start: Proxmox's task runs meanwhile. Said "not
    # carried out" after CONFIRM_WITHIN, the history kept a failure of a start that came seconds later. And the guest is seen
    # running a moment after its task ended (here 0.8 s): it is given CONFIRM_WITHIN from that end, not from the press.
    # (Counted from the press, a guest read just before the task ended, and a task read just after, said "not carried out".)
    monkeypatch.setattr(proxmox, "CONFIRM_WITHIN", 2.5)
    monkeypatch.setattr(proxmox, "TASK_WITHIN", 15.0)
    pve.state.task_takes, pve.state.power_takes = 3.0, 0.8
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pve.guest_url(101), **TOKEN}).json()["device"]["id"]
        began = time.monotonic()
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "power_on"})
        assert reply.status_code == 200, reply.text
        assert 3.0 < time.monotonic() - began < 15 and pve.state.guests[101].status == "running"
        assert any(asked.startswith("GET /nodes/pve1/tasks/UPID:") for asked in pve.state.requests)  # (asked of the node its name gives)
        assert pressed(client, device)["ok"] is True


def guest_reads_after_the_command(monkeypatch: pytest.MonkeyPatch, how: str) -> None:
    """After the power command went out, every read of the guest's state is `how`: "slow" (three seconds each) or "lost"."""
    real = ProxmoxGuest._guest
    commanded = []

    async def reading(self: ProxmoxGuest, method: str, step: str, what: str, **options: Any) -> Any:
        if method == "POST" and step.startswith("status/"):
            commanded.append(step)
        elif commanded and step == "status/current":
            if how == "lost":
                raise KvmError("timeout", "Device did not respond in time", 504)
            await asyncio.sleep(3.0)
        return await real(self, method, step, what, **options)

    monkeypatch.setattr(ProxmoxGuest, "_guest", reading)


def test_a_start_whose_guest_could_not_be_read_since_its_task_ended_is_not_said_to_have_failed(tmp_path: Path, pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The eighth reviewer's probe.) The task ended well and the guest started, but no read of it came back since: that is not
    # "not carried out" (the history kept a failure of a start that was done), it is not known.
    monkeypatch.setattr(proxmox, "CONFIRM_WITHIN", 0.5)
    pve.state.task_takes = 0.2
    guest_reads_after_the_command(monkeypatch, "lost")
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pve.guest_url(101), **TOKEN}).json()["device"]["id"]
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "power_on"})
        assert (reply.status_code, reply.json()["code"]) == (504, "timeout"), reply.text
        assert "could not be read since" in reply.json()["message"] and pve.state.guests[101].status == "running"
        assert pressed(client, device)["ok"] is None


def test_the_wait_for_a_guest_has_one_bound_from_the_press_however_slowly_proxmox_answers(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # Reads of the guest that take three seconds each: the wait after the task's end would go on past TASK_WITHIN and
    # CONFIRM_WITHIN together, and a Proxmox slow enough kept the button past the page's patience. It ends at that bound, and
    # says that the guest is not running yet, not that it was not started (its whole wait was not had).
    monkeypatch.setattr(proxmox, "TASK_WITHIN", 1.0)
    monkeypatch.setattr(proxmox, "CONFIRM_WITHIN", 5.0)
    pve.state.task_takes, pve.state.power_takes = 0.5, 60.0
    guest_reads_after_the_command(monkeypatch, "slow")

    async def run() -> tuple[KvmError, float]:
        device = a_guest(pve, 101)
        try:
            await device.status()
            began = time.monotonic()
            with pytest.raises(KvmError) as refused:
                await device.act("power_on")
            return refused.value, time.monotonic() - began
        finally:
            await device.close()

    refused, took = asyncio.run(run())
    assert refused.code == "timeout" and "is not running yet" in refused.message, refused.message
    assert took < 15


def test_the_wait_for_a_start_counts_from_the_press_and_not_from_the_command(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The final review's F4.) The questions a press is decided by were not counted in its wait: a Proxmox slow to answer
    # them added their time to the whole wait after the command, past the page's patience (ACTION_PATIENCE). From the press,
    # a start whose task runs on is said to be under way TASK_WITHIN after the press, not after the command.
    monkeypatch.setattr(proxmox, "TASK_WITHIN", 5.0)
    monkeypatch.setattr(proxmox, "CONFIRM_WITHIN", 1.0)
    pve.state.task_takes = 60.0
    real = ProxmoxGuest._guest

    async def slow_before_the_command(self: ProxmoxGuest, method: str, step: str, what: str, **options: Any) -> Any:
        if method == "GET" and step == "status/current" and not pve.state.tasks:
            await asyncio.sleep(6.0)  # (the question the button is decided by)
        return await real(self, method, step, what, **options)

    async def run() -> tuple[KvmError, float]:
        device = a_guest(pve, 101)
        try:
            await device.status()
            monkeypatch.setattr(ProxmoxGuest, "_guest", slow_before_the_command)
            began = time.monotonic()
            with pytest.raises(KvmError) as refused:
                await device.act("power_on")
            return refused.value, time.monotonic() - began
        finally:
            await device.close()

    refused, took = asyncio.run(run())
    assert refused.code == "timeout" and "still running" in refused.message, refused.message
    assert took < 9.5, took  # six seconds of the question, and what is left of five from the press: not six and five


def test_a_read_in_the_wait_for_a_start_is_not_waited_for_past_its_bound(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The final review's F4.) Each read in the wait was given a request's whole time (here 22 s: connect, read and
    # TRANSFER_TIME), whatever was left of the wait: a Proxmox that answers a look a byte at a time kept the button that long
    # past its bound. Now no longer than what is left (and never less than getting a connection may take: 2.5 s here).
    monkeypatch.setattr(proxmox, "TASK_WITHIN", 1.0)
    monkeypatch.setattr(proxmox, "CONFIRM_WITHIN", 1.0)
    monkeypatch.setattr(kvm, "WAITS", httpx.Timeout(1.0, connect=1.0))
    pve.state.task_takes = 60.0
    real = ProxmoxGuest._guest

    async def a_byte_at_a_time_after_the_command(self: ProxmoxGuest, method: str, step: str, what: str, **options: Any) -> Any:
        said = await real(self, method, step, what, **options)
        if method == "POST" and step.startswith("status/"):
            pve.state.hostile = "trickle"  # every look at the guest from now on answers a byte every quarter second
        return said

    async def run() -> tuple[KvmError, float]:
        device = a_guest(pve, 101)
        try:
            await device.status()
            monkeypatch.setattr(ProxmoxGuest, "_guest", a_byte_at_a_time_after_the_command)
            began = time.monotonic()
            with pytest.raises(KvmError) as refused:
                await device.act("power_on")
            return refused.value, time.monotonic() - began
        finally:
            pve.state.hostile = ""
            await device.close()

    refused, took = asyncio.run(run())
    assert refused.code == "timeout" and "still running" in refused.message, refused.message
    assert took < 12, took


def test_a_read_in_the_wait_is_never_given_longer_than_a_request_has_of_its_own(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # The bound from the press shortens a read's wait where little is left of it; where much is left, a read waits what any
    # request waits (connect, read and TRANSFER_TIME: 32 s), and not the minute and more that is left.
    pve.state.task_takes = pve.state.power_takes = 0.3
    given: list[tuple[str, float | None]] = []
    real = ProxmoxGuest._send

    async def noted(self: ProxmoxGuest, client: httpx.AsyncClient, request: httpx.Request, limit: int, within: float | None = None) -> httpx.Response:
        given.append((request.url.path, within))
        return await real(self, client, request, limit, within)

    async def run() -> None:
        device = a_guest(pve, 101)
        try:
            await device.status()
            monkeypatch.setattr(ProxmoxGuest, "_send", noted)
            await device.act("power_on")
        finally:
            await device.close()

    asyncio.run(run())
    bounded = [within for path, within in given if within is not None]
    whole = kvm.WAITS.connect + kvm.WAITS.read + kvm.TRANSFER_TIME  # type: ignore[operator]
    assert bounded and all(within <= whole for within in bounded), given


def test_a_guest_changed_while_its_start_is_waited_for_is_said_to_have_perhaps_been_started(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # The tile is edited (its connection taken away) while the start is waited for, after its task ended: whether it was carried
    # out was not seen, and that is what is said (RETIRED: "may have been done"), not "not carried out".
    monkeypatch.setattr(proxmox, "CONFIRM_WITHIN", 30.0)
    pve.state.task_takes, pve.state.power_takes = 0.2, 60.0

    async def run() -> BaseException | None:
        device = a_guest(pve, 101)
        try:
            await device.status()
            starting = asyncio.create_task(device.act("power_on"))
            while not any(task["type"] == "qmstart" and task["status"] == "OK" for task in pve.state.tasks):
                await asyncio.sleep(0.05)
            await asyncio.sleep(0.3)  # (the wall has seen the task's end, and waits for the guest)
            await device.close()
            try:
                await starting
            except BaseException as ex:  # (what it ended with is the point)
                return ex
            return None
        finally:
            await device.close()

    assert asyncio.run(run()) is kvm.RETIRED


def test_a_task_that_still_runs_is_said_to_be_running_and_not_to_have_failed(tmp_path: Path, pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(proxmox, "CONFIRM_WITHIN", 0.5)
    monkeypatch.setattr(proxmox, "TASK_WITHIN", 1.5)
    pve.state.task_takes = 60.0
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pve.guest_url(101), **TOKEN}).json()["device"]["id"]
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "power_on"})
        assert (reply.status_code, reply.json()["code"]) == (504, "timeout"), reply.text
        assert "still running" in reply.json()["message"] and "not running yet" in reply.json()["message"]
        assert pressed(client, device)["ok"] is None  # (it may yet be done: nobody knows)


def test_a_task_that_ends_in_an_error_is_said_at_once_in_proxmoxs_words(tmp_path: Path, pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(proxmox, "CONFIRM_WITHIN", 8.0)
    pve.state.task_takes, pve.state.task_fails = 0.3, "start failed: QEMU exited with code 1"
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pve.guest_url(101), **TOKEN}).json()["device"]["id"]
        began = time.monotonic()
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "power_on"})
        assert (reply.status_code, reply.json()["code"]) == (502, "action_failed"), reply.text
        assert reply.json()["message"] == "Proxmox could not start the guest: start failed: QEMU exited with code 1"
        assert time.monotonic() - began < 5 and pve.state.guests[101].status == "stopped"
        assert pressed(client, device)["ok"] is False


def test_a_task_that_ended_with_warnings_is_done(tmp_path: Path, pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # Proxmox counts a task that ended with warnings ("WARNINGS: 1") as done, as its own page does: the guest is waited for,
    # not said to have failed to start because it was not yet seen running when the task's end was read.
    monkeypatch.setattr(proxmox, "CONFIRM_WITHIN", 8.0)
    pve.state.task_takes, pve.state.task_fails, pve.state.power_takes = 0.3, "WARNINGS: 1", 0.6
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pve.guest_url(101), **TOKEN}).json()["device"]["id"]
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "power_on"})
        assert reply.status_code == 200 and pve.state.guests[101].status == "running", reply.text
        assert pressed(client, device)["ok"] is True


def test_a_guest_under_proxmoxs_high_availability_is_waited_for_as_long_as_a_task(tmp_path: Path, pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # Started by Proxmox's HA: the command's own task (hastart) ends at once, and the guest is started by HA a while later.
    monkeypatch.setattr(proxmox, "CONFIRM_WITHIN", 0.5)
    monkeypatch.setattr(proxmox, "TASK_WITHIN", 15.0)
    pve.state.guests[101].ha, pve.state.power_takes = True, 2.0
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pve.guest_url(101), **TOKEN}).json()["device"]["id"]
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "power_on"})
        assert reply.status_code == 200 and pve.state.guests[101].status == "running", reply.text
        assert [task["type"] for task in pve.state.tasks] == ["hastart"]
        # And one that HA does not carry out in the time: said to be under way, not to have failed.
        monkeypatch.setattr(proxmox, "TASK_WITHIN", 1.0)
        pve.state.power_takes = 60.0
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power_long"})
        assert (reply.status_code, reply.json()["code"]) == (504, "timeout") and "high availability" in reply.json()["message"], reply.text


def test_a_task_the_token_may_not_read_leaves_it_unknown_and_not_failed(tmp_path: Path, pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(proxmox, "CONFIRM_WITHIN", 0.5)
    pve.state.tasks_hidden, pve.state.task_takes = True, 60.0
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pve.guest_url(101), **TOKEN}).json()["device"]["id"]
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "power_on"})
        assert (reply.status_code, reply.json()["code"]) == (504, "timeout") and "did not say how its task went" in reply.json()["message"], reply.text


def test_a_token_without_the_right_to_switch_is_told_by_proxmoxs_words(tmp_path: Path, pve: FakeProxmox) -> None:
    pve.state.guests[100].may_power = False
    pve.state.guests[100].may_console = False
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pve.guest_url(100), **TOKEN}).json()["device"]["id"]
        reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power_long"})
        assert reply.status_code == 502 and "VM.PowerMgmt" in reply.json()["message"]
        assert pve.state.guests[100].status == "running" and pve.state.tasks == []
        shown = client.get(snap(device))
        assert shown.status_code != 200
        wait_until(lambda: client.get(snap(device)).json().get("message", "").find("VM.Console") >= 0, "the tile does not say what the token lacks")
        assert consoles_opened(pve) == 0  # (a refusal writes no task)


# --- where the guest is, and what Proxmox answers --------------------------------------------------------------------


def test_a_guest_moved_to_another_node_is_followed(pve: FakeProxmox) -> None:
    pve.state.nodes = ["pve1", "pve2"]

    async def run() -> None:
        device = a_guest(pve)
        try:
            assert (await device.status())["state"] == "online"
            pve.state.guests[100].node = "pve2"  # migrated within its cluster
            device._status_at = 0
            status = await device.status()
            for _ in range(50):
                if status["state"] == "online" and status["server"]["proxmox"]["node"] == "pve2":
                    break
                await asyncio.sleep(0.05)
                status = await device.status()
            assert status["state"] == "online" and status["server"]["proxmox"]["node"] == "pve2"
            await picture_of(device)  # its console comes from where it is now
            pve.state.guests.pop(100)  # gone altogether
            await asyncio.sleep(0.1)
            status = await device.status()
            for _ in range(50):
                if status["state"] == "error":
                    break
                await asyncio.sleep(0.05)
                status = await device.status()
            assert status["state"] == "error" and "VM.Audit" in status["error"]["message"]
        finally:
            await device.close()

    asyncio.run(run())


def test_what_a_hostile_proxmox_sends_takes_no_more_than_its_share(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(proxmox, "CONSOLE_RETRY", (60.0,))
    monkeypatch.setattr(kvm, "TRANSFER_TIME", 2.0)
    monkeypatch.setattr(kvm, "WAITS", kvm.httpx.Timeout(1.0, connect=1.0))

    async def outcome(hostile: str, what: str) -> str:
        pve.state.hostile = hostile
        device = a_guest(pve)
        began = time.monotonic()
        try:
            if what == "list":
                await device.listing()
            elif what == "look":
                status = await device.status()
                return f"{status['state']} {status['error']['code'] if status['error'] else ''}".strip()
            else:
                await device.status()
                await picture_of(device, within=8)
            return "fine"
        except KvmError as ex:
            assert time.monotonic() - began < 8, hostile
            return ex.code
        finally:
            await device.close()
            pve.state.hostile = ""

    async def run() -> None:
        assert await outcome("huge_list", "list") == "dropped"  # (far more than a list of guests: not read past the limit)
        REJECTED.clear()
        assert await outcome("not_proxmox", "look") == "error no_sign_in"
        REJECTED.clear()
        assert await outcome("trickle", "look") == "offline timeout"
        for hostile in ("bad_ticket", "bad_port", "no_password", "redirect", "text_frame", "huge_frame"):
            REJECTED.clear()
            assert await outcome(hostile, "picture") in ("bad_response", "dropped"), hostile
        assert pve.state.in_the_clear == []

    asyncio.run(run())


def test_an_answer_nested_beyond_reading_is_no_answer(pve: FakeProxmox) -> None:
    pve.state.hostile = "deep"

    async def run() -> None:
        device = a_guest(pve)
        try:
            status = await device.status()
            assert status["state"] == "error" and status["error"]["code"] == "no_sign_in"  # neither a yes nor a no
            assert REJECTED.times(device._offered()) == 0
        finally:
            await device.close()

    asyncio.run(run())


# --- a live line ----------------------------------------------------------------------------------------------------


def test_a_guests_screen_live_with_its_keys_and_pointer(tmp_path: Path, pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.test_live import Wall

    monkeypatch.setattr(proxmox.ProxmoxConsole, "LIVE_PACE", 0.02)
    with Wall(tmp_path / "wall") as live_wall:
        admin = live_wall.browser()
        device = live_wall.add(admin, pve.guest_url(100), **TOKEN)
        wait_until(lambda: admin.get("/api/v1/status").json()[device].get("screen") is True, "the guest's screen is not said to be there")
        line = live_wall.line(admin, device, max_fps=5)
        assert line.word("video", timeout=20) == {"t": "video", "codec": "jpeg", "w": 320, "h": 200}
        came = line.picture(timeout=20)
        assert came.kind == 2 and came.key and came.data[:2] == b"\xff\xd8"
        screen = pve.state.guests[100].screen
        screen.dirty.append((0, 0, 32, 32))  # something changes on the guest's screen: a picture of it comes
        assert line.picture(timeout=10).counter > came.counter
        line.say(t="control", on=True)
        assert line.word("control") == {"t": "control", "on": True}
        line.say(t="k", u=0xE1, d=True)  # ShiftLeft
        line.say(t="k", u=0x04, d=True)
        line.say(t="k", u=0x04, d=False)
        line.say(t="m", x=32767, y=16384)
        line.say(t="mb", b=1, d=True)
        line.say(t="mb", b=1, d=False)
        wait_until(lambda: len(screen.pointers) >= 3 and len(screen.keys) >= 3, f"the guest got {screen.keys} {screen.pointers}")
        assert screen.keys == [(0xFFE1, True), (0x61, True), (0x61, False)]
        assert screen.pointers == [(319, 99, 0), (319, 99, 1), (319, 99, 0)]
        line.close()  # with Shift still down: let go of in the guest
        wait_until(lambda: screen.keys[-1] == (0xFFE1, False), f"Shift was not let go of: {screen.keys}")
    assert consoles_opened(pve) == 1  # the tile's console and the live line's are one


# --- what is kept --------------------------------------------------------------------------------------------------


def test_a_guest_goes_into_an_export_file_and_comes_out_of_it(tmp_path: Path, pve: FakeProxmox) -> None:
    from tests.test_wall import PASSWORD

    with wall(tmp_path / "one") as client:
        assert client.post("/api/v1/devices", json={"url": pve.guest_url(100), **TOKEN}).status_code == 201
        exported = client.post("/api/v1/export", json={"password": PASSWORD, "parts": ["devices"], "passphrase": "a passphrase of ours"})
        assert exported.status_code == 200, exported.text
        file = exported.text
    with wall(tmp_path / "two") as client:
        read = client.post("/api/v1/import/read", json={"file": file, "passphrase": "a passphrase of ours"}).json()
        assert [(d["kind"], d["new"], d["password"]) for d in read["devices"]] == [("proxmox", True, True)]
        taken = client.post("/api/v1/import", json={"file": file, "passphrase": "a passphrase of ours", "take": ["devices"]})
        assert taken.status_code == 200 and taken.json()["devices"] == 1, taken.text
        listed = client.get("/api/v1/wall").json()["devices"]
        assert [(d["kind"], d["url"]) for d in listed] == [("proxmox", pve.guest_url(100))]
        wait_until(lambda: state_of(client, listed[0]["id"])["state"] == "online", "the guest from the file does not answer")


def test_a_password_typed_again_is_tried_again_for_every_guest_of_its_proxmox() -> None:
    spec = DeviceSpec(id="x", name="x", base_url="https://pve.lan:8006/nodes/pve1/qemu/100", username=TOKEN_ID, password=SECRET, kind="proxmox")
    whole = DeviceSpec(id="x", name="x", base_url="https://pve.lan:8006", username=TOKEN_ID, password=SECRET, kind="proxmox")
    mark = REJECTED.what("login", whole)
    REJECTED.said_no(mark)
    assert REJECTED.wait_left(mark) > 0
    REJECTED.forget(spec)
    assert REJECTED.wait_left(mark) == 0


def test_a_one_time_password_given_to_rfb_is_not_the_saved_ones_to_count(monkeypatch: pytest.MonkeyPatch) -> None:
    # The door of vncdevice: a password handed out for one connection goes to RFB in place of the saved one, and what
    # RFB says to it is not counted for the saved one (a VNC server's tile counts its own, as before).
    from tests.fake_vnc import FakeVnc

    server = FakeVnc(VncState(password="once")).start()
    try:

        class Door(vncdevice.VncDevice):
            async def _open(self) -> rfb.Stream:
                assert self._session is not None
                self._session.one_time = "once"
                return await super()._open()

        async def run() -> None:
            device = Door(DeviceSpec(id="d", name="d", base_url=server.url, username="", password="the saved one", kind="vnc"))
            try:
                await picture_of(device)
                assert server.state.password_tries == 1 and server.state.rejected == 0
                assert REJECTED.wait_left(REJECTED.what("login", device.spec)) == 0
            finally:
                await device.close()

        asyncio.run(run())
    finally:
        server.stop()


# --- what the fresh reviewer found (each seen to fail on the code before its fix) ------------------------------------


def test_a_console_that_ends_at_once_is_not_opened_again_for_every_picture_key_or_move_of_a_live_line(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # A live line, a key and the pointer are in a hurry, and open a console at once where none is: after a failure, not
    # after two in a row. A console that lets qKVM in and ends at once was opened anew at every one of them, a task each.
    monkeypatch.setattr(proxmox, "CONSOLE_RETRY", (0.3, 60.0))
    monkeypatch.setattr(proxmox, "LIVE_WAIT", 0.5)
    pve.state.guests[100].screen.hostile = "drop_after_handshake"

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                for asked in (device.live_screen(), device.pointer(10, 10, 1), device.press(0x04, True)):
                    try:
                        await asked
                    except KvmError:
                        pass
                await asyncio.sleep(0.1)
            assert consoles_opened(pve) <= 3, f"{consoles_opened(pve)} consoles opened in three seconds"
            assert device._console.refused_now() is not None  # (and the tile says why there is no screen)
        finally:
            await device.close()

    asyncio.run(run())


def test_a_message_begun_and_never_ended_is_not_kept_piece_by_piece() -> None:
    # A console that begins a message and sends it on in empty pieces, slower than any limit on frames a second, and
    # never ends it: the library kept every piece until the end, which never came. Pieces are counted as they come.
    from websockets.asyncio.server import serve

    from qkvm.kvm import ws_connect

    async def endless(ws: Any) -> None:
        async def pieces() -> Any:
            # (Twice the pieces the reader takes in one message, as fast as this computer sends them, and then one now and
            # then, never the end. Waited for eight seconds, a busy computer had not sent the reader's 4096 yet.)
            yield b"R"
            sent = 0
            while True:
                for _ in range(40):
                    yield b""
                sent += 40
                await asyncio.sleep(0.02 if sent < 2 * rfb.MOST_PIECES else 0.5)

        try:
            await ws.send(pieces())
        except Exception:
            pass

    async def run() -> str:
        async with serve(endless, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            ws = await ws_connect(f"ws://127.0.0.1:{port}", open_timeout=5, ping_interval=None, max_size=proxmox.MOST_FRAME)
            stream = rfb.WebSocketStream(ws)
            try:
                async with asyncio.timeout(120):  # (see above: by then a reader that kept every piece is still reading)
                    await stream.read(1, None)  # (a server with nothing to say is waited for as long as it takes)
            except rfb.RfbError as ex:
                return ex.code
            except TimeoutError:
                return "still reading, every piece kept"
            finally:
                await stream.close()
        return "read"

    assert asyncio.run(run()) == rfb.LIMIT


def test_a_proxmox_that_says_not_here_at_every_look_has_its_list_read_once_a_minute(pve: FakeProxmox) -> None:
    pve.state.hostile = "lost_guest"  # "not on this node", and listed on it all the same

    async def run() -> None:
        device = a_guest(pve)
        try:
            for _ in range(10):
                device._status_at = 0.0
                await device.status()
                await asyncio.sleep(0.05)
            status = await device.status()
            assert status["state"] == "error" and "nor on another node" in status["error"]["message"]
            lists = sum(1 for asked in pve.state.requests if asked == "GET /cluster/resources")
            assert lists == 1, f"the cluster's list read {lists} times in ten looks"
        finally:
            await device.close()

    asyncio.run(run())


def test_a_guests_state_said_in_a_kind_of_its_own_is_no_state(tmp_path: Path, pve: FakeProxmox) -> None:
    pve.state.hostile = "odd_status"  # a list where the word belongs, a record where a number does

    async def run() -> None:
        device = a_guest(pve)
        try:
            status = await device.status()
            assert status["state"] == "online" and status["error"] is None and status["screen"] is False  # (not known to run)
            assert status["server"]["power"] is None and status["server"]["proxmox"]["status"] is None
            listed, _ = await device.listing()
            assert [guest["status"] for guest in listed] == [None, None]
        finally:
            await device.close()

    asyncio.run(run())
    with wall(tmp_path) as client:
        reply = client.post("/api/v1/proxmox/guests", json={"url": pve.url, "username": TOKEN_ID, "password": SECRET})
        assert reply.status_code == 200, reply.text


def test_a_power_button_is_not_pressed_on_a_guess(pve: FakeProxmox) -> None:
    pve.state.hostile = "null_status"  # Proxmox says nothing of whether the guest runs

    async def run() -> None:
        device = a_guest(pve)
        try:
            for action in ("power_off", "power_on", "atx_reset"):
                with pytest.raises(KvmError) as refused:
                    await device.act(action)
                assert refused.value.code == "bad_response", (action, refused.value.message)
            assert pve.state.tasks == []
        finally:
            await device.close()

    asyncio.run(run())


def test_a_console_failing_is_paced_also_across_the_tile_being_made_anew(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # A tile is made anew when it is edited, its certificate trusted, or the saved passwords locked and opened again:
    # how its console was paced is kept beside it, not in it.
    monkeypatch.setattr(proxmox, "CONSOLE_RETRY", (60.0,))
    pve.state.guests[100].console_fails = True

    async def looked_at(device: ProxmoxGuest, seconds: float) -> None:
        await device.status()
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                await device.snapshot(640)
            except KvmError:
                pass
            await asyncio.sleep(0.05)

    async def run() -> None:
        first = a_guest(pve)
        try:
            await looked_at(first, 1.5)
        finally:
            await first.close()
        assert consoles_opened(pve) == 1
        second = a_guest(pve)
        try:
            await looked_at(second, 1.5)
        finally:
            await second.close()
        assert consoles_opened(pve) == 1  # (was 2: the new tile began at nothing)

    asyncio.run(run())


def test_the_token_is_never_answered_to_a_console_that_asks_for_a_password_the_door_did_not_hand_out(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # Behind the door RFB is answered with the password Proxmox handed out with the ticket, or with nothing: never with the
    # saved secret, which is the API token's (its first eight characters as a VNC answer could be tried at leisure).
    async def handed_nothing(self: proxmox.ProxmoxConsole) -> rfb.Stream:
        port, ticket, _ = await self._guest.console_ticket()
        return rfb.WebSocketStream(await self._guest.console_socket(port, ticket))

    monkeypatch.setattr(proxmox.ProxmoxConsole, "_open", handed_nothing)

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            with pytest.raises(KvmError):
                await picture_of(device, within=5)
            assert pve.state.guests[100].screen.password_tries == 0
        finally:
            await device.close()

    asyncio.run(run())


def test_what_the_websocket_library_says_at_its_finest_names_no_token(pve: FakeProxmox) -> None:
    # The library logs every header it sends at its finest level. Whatever level its loggers are set to (here: all
    # of it), a device's connection says nothing finer than a warning.
    said: list[str] = []

    class Heard(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            said.append(record.getMessage())

    library = logging.getLogger("websockets")
    level, heard = library.level, Heard(logging.DEBUG)
    library.setLevel(logging.DEBUG)
    logging.getLogger().addHandler(heard)

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            await picture_of(device)
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        logging.getLogger().removeHandler(heard)
        library.setLevel(level)
    assert not any(SECRET in line or "PVEVNC" in line for line in said), [line[:60] for line in said if "Authorization" in line]


# --- what the second fresh reviewer found in those fixes (each seen to fail on the code before) -----------------------


def test_a_console_that_fails_before_its_handshake_is_not_opened_again_at_every_move_of_the_pointer(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # Each session that fails counts, also one asked for in a hurry within the pause after the one before: counted once
    # for all that failed within a pause, the console was opened again at every move of the pointer.
    monkeypatch.setattr(proxmox, "CONSOLE_RETRY", (0.5, 60.0))
    monkeypatch.setattr(proxmox, "LIVE_WAIT", 1.0)
    pve.state.guests[100].console_fails = True  # taken, and closed with no greeting

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            deadline = time.monotonic() + 4.0
            while time.monotonic() < deadline:
                try:
                    await device.pointer(10, 10, 0)
                except KvmError:
                    pass
                await asyncio.sleep(0.2)
            assert consoles_opened(pve) <= 3, f"{consoles_opened(pve)} consoles in four seconds"
            assert device._console.refused_now() is not None
        finally:
            await device.close()

    asyncio.run(run())


def test_a_guest_that_moves_after_another_of_its_proxmox_was_found_is_found_too(pve: FakeProxmox) -> None:
    pve.state.nodes = ["pve1", "pve2"]
    pve.state.guests[101].status = "running"

    async def looked_at(device: ProxmoxGuest) -> dict[str, Any]:
        device._status_at = 0.0
        await device.status()
        for _ in range(50):
            await asyncio.sleep(0.05)
            status = await device.status()
            if status["state"] in ("online", "error") and device._status_at:
                return dict(status)
        return dict(await device.status())

    async def run() -> None:
        first, second = a_guest(pve, 100), a_guest(pve, 101)
        try:
            assert (await looked_at(first))["state"] == "online" and (await looked_at(second))["state"] == "online"
            pve.state.guests[100].node = "pve2"
            assert (await looked_at(first))["server"]["proxmox"]["node"] == "pve2"
            pve.state.guests[101].node = "pve2"  # moved after the list was read for the first: that list says pve1
            status = await looked_at(second)
            assert status["state"] == "online" and status["server"]["proxmox"]["node"] == "pve2", status["error"]
        finally:
            await first.close()
            await second.close()

    asyncio.run(run())


def test_a_token_typed_again_after_its_rights_were_put_right_shows_the_screen_at_once(tmp_path: Path, pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(proxmox, "CONSOLE_RETRY", (600.0,))
    pve.state.guests[100].may_console = False
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pve.guest_url(100), **TOKEN}).json()["device"]["id"]
        wait_until(lambda: "VM.Console" in client.get(snap(device)).json().get("message", ""), "the tile does not say what the token lacks")
        pve.state.guests[100].may_console = True  # its owner gives the token the right, and types it again on the tile
        edit = client.put(f"/api/v1/devices/{device}", json={"url": pve.guest_url(100), **TOKEN})
        assert edit.status_code == 200, edit.text
        picture(client, device)  # at once, not after the ten minutes a refusal is left alone


def test_a_session_that_let_qkvm_in_is_written_down_as_that(pve: FakeProxmox) -> None:
    # A refusal that stood is over once a console lets qKVM in: a tile made anew after that asks for its console at once.
    # (How many came in a row is kept until a console has served a while: one that lets qKVM in and then sends what qKVM
    # does not take climbs its ladder; see the test after the fifth review's.)
    vncdevice._PACED[f"proxmox\0{pve.guest_url(100)}"] = (0, 0.0, "", "", 502, 3, 0.0, "refused a while ago", False, False, False, float("-inf"))

    async def run() -> None:
        first = a_guest(pve)
        try:
            await first.status()
            await picture_of(first)
        finally:
            await first.close()
        second = a_guest(pve)
        try:
            assert second._console._refusal is None and second._console.refused_now() is None
        finally:
            await second.close()

    asyncio.run(run())


def test_a_key_that_does_not_get_through_as_a_console_ends_is_not_one_more_failure(pve: FakeProxmox) -> None:
    # The session it was sent on is ending, and that end is what counts: counted as well, a viewer typing as a console
    # ended found the live line held back a whole rung (a minute, for Proxmox) for nothing.
    async def run() -> None:
        device = a_guest(pve)
        try:
            console = device._console
            console._not_taken(rfb.RfbError(rfb.CLOSED, "the connection to the server ended"))
            assert console._failures == 0 and console._down_error is None
            console._failed(KvmError("dropped", "the connection ended"))  # (the session's own end)
            assert console._failures == 1
        finally:
            await device.close()

    asyncio.run(run())


# --- what the third fresh reviewer found in those fixes (each seen to fail on the code before) ------------------------


def test_a_live_line_waits_out_a_console_that_ended_and_failed_once_more(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # A console that served for a while ends (Proxmox ended it), and the one opened at once after it fails: two in a row.
    # The live line waits that pause out; it is not told that the guest has no screen to be had.
    monkeypatch.setattr(vncdevice, "SETTLED", 0.5)
    monkeypatch.setattr(proxmox, "CONSOLE_RETRY", (0.5, 0.5, 60.0))

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            await picture_of(device)
            await asyncio.sleep(0.7)  # (it served long enough to have been well)
            pve.state.guests[100].console_fails = True
            pve.end_consoles(100)
            for _ in range(60):
                try:
                    await device.live_screen()
                except KvmError:
                    pass
                if device._console._failures >= 2:
                    break
                await asyncio.sleep(0.05)
            assert device._console._failures >= 2
            assert device.console_readable is True  # (a live line goes on, and asks again after the pause)
            pve.state.guests[100].console_fails = False
            deadline = time.monotonic() + 10
            while True:
                try:
                    await device.live_screen()
                    break
                except KvmError:
                    assert time.monotonic() < deadline, "the live line never got the screen back"
                    await asyncio.sleep(0.1)
        finally:
            await device.close()

    asyncio.run(run())


def test_a_console_that_lasted_on_a_still_screen_is_well_again_when_it_is_let_go_of(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # Failures before it, then a session that lasted on a screen that did not change (no request answered in that time) and
    # was let go of because nobody looked: well again, not two failures that the next ordinary end climbs on from.
    monkeypatch.setattr(vncdevice, "SETTLED", 0.5)
    monkeypatch.setattr(proxmox.ProxmoxConsole, "LET_GO_AFTER", 1.5)
    vncdevice._PACED[f"proxmox\0{pve.guest_url(100)}"] = (2, 0.0, "dropped", "it ended", 502, 0, 0.0, "", False, False, False, float("-inf"))

    async def run() -> None:
        device = a_guest(pve)
        try:
            assert device._console._failures == 2
            await device.status()
            await picture_of(device)
            deadline = time.monotonic() + 10
            while pve.state.consoles and time.monotonic() < deadline:  # nobody looks: let go of
                await asyncio.sleep(0.1)
            assert pve.state.consoles == 0
            assert device._console._failures == 0 and f"proxmox\0{pve.guest_url(100)}" not in vncdevice._PACED
        finally:
            await device.close()

    asyncio.run(run())


def test_the_first_console_after_the_api_sat_idle_comes_at_once(pve: FakeProxmox) -> None:
    # Proxmox closes a connection that sat idle for some seconds. The question asked just before the console (which may be
    # asked again) is the one that meets that, not the vncproxy after it, which is not sent twice and failed as "dropped".
    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            await asyncio.sleep(6.5)  # (the stand-in's web server closes an idle connection after five seconds)
            began = time.monotonic()
            await picture_of(device, within=5)
            assert time.monotonic() - began < 5 and consoles_opened(pve) == 1
        finally:
            await device.close()

    asyncio.run(run())


def test_a_tile_saved_again_asks_for_its_console_at_once(tmp_path: Path, pve: FakeProxmox) -> None:
    # Saved again by a person (its certificate check changed, say, without the token typed): what kept its console away
    # is not waited out.
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pve.guest_url(100), **TOKEN}).json()["device"]["id"]
        vncdevice._PACED[f"proxmox\0{pve.guest_url(100)}"] = (3, time.monotonic() + 600, "cert_mismatch", "Certificate does not match the one saved for this device", 502, 0, 0.0, "", False, False, False, float("-inf"))
        edit = client.put(f"/api/v1/devices/{device}", json={"url": pve.guest_url(100), "username": TOKEN_ID, "password": ""})
        assert edit.status_code == 200, edit.text
        picture(client, device)


# --- what the fourth fresh reviewer found in those fixes (each seen to fail on the code before) -----------------------


def test_a_console_that_lets_qkvm_in_and_answers_nothing_is_not_reopened_at_once_for_good(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # Served for a while is: let in that long ago, and answered something since. A console that answers no request, ended
    # by the heartbeat, is a console that failed, on the ladder; not an ordinary end, reopened at once, again and again.
    monkeypatch.setattr(vncdevice, "SETTLED", 0.3)
    monkeypatch.setattr(vncdevice, "HEARTBEAT", 0.3)
    monkeypatch.setattr(proxmox.ProxmoxConsole, "HEARTBEAT_AFTER", 0.3, raising=False)
    monkeypatch.setattr(rfb, "MESSAGE_WITHIN", 0.3)
    monkeypatch.setattr(proxmox, "CONSOLE_RETRY", (0.3, 60.0))
    pve.state.guests[100].screen.hostile = "silent"

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                try:
                    await device.snapshot(640)
                except KvmError:
                    pass
                await asyncio.sleep(0.05)
            assert consoles_opened(pve) <= 2, f"{consoles_opened(pve)} consoles in five seconds"
        finally:
            await device.close()

    asyncio.run(run())


def test_a_console_cut_after_a_while_twice_is_waited_for_the_second_time(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # One that served and ended is opened again at once; a second such end soon after is one more failure (a proxy in
    # front that cuts every quiet console after a minute would have a console opened every minute, for good).
    monkeypatch.setattr(vncdevice, "SETTLED", 0.3)
    monkeypatch.setattr(proxmox, "CONSOLE_RETRY", (60.0,))

    async def ended_after_a_while(device: ProxmoxGuest) -> None:
        await picture_of(device)
        await asyncio.sleep(0.5)
        pve.end_consoles(100)
        for _ in range(100):
            if device._console._connected_or_none() is None:
                return
            await asyncio.sleep(0.02)

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            await ended_after_a_while(device)
            await ended_after_a_while(device)  # (opened again at once after the first)
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                try:
                    await device.snapshot(640)
                except KvmError:
                    pass
                await asyncio.sleep(0.05)
            assert consoles_opened(pve) == 2, f"{consoles_opened(pve)} consoles"
        finally:
            await device.close()

    asyncio.run(run())


async def cut_whenever_served(pve: FakeProxmox, device: ProxmoxGuest, served: float, seconds: float, live: bool = False, once: bool = False) -> None:
    """Ask for the guest's screen as a tile does (or as a live line, `live`) for `seconds`, and cut every console Proxmox
    holds once it has served `served` seconds: a proxy in front with a limit of its own. `once`: the first cut ends it."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            await (device.live_screen() if live else device.snapshot(640))
        except KvmError:
            pass
        session = device._console._session
        if session is not None and session.let_in_at is not None and not session.done.is_set() and time.monotonic() - session.let_in_at >= served:
            pve.end_consoles(100)
            for _ in range(100):
                if device._console._connected_or_none() is None:
                    break
                await asyncio.sleep(0.02)
            if once:
                return
        await asyncio.sleep(0.05)
    assert not once, "no console served long enough to be cut"


@pytest.mark.parametrize("live", [False, True], ids=["tile", "live"])
def test_a_console_cut_again_and_again_after_it_served_climbs_the_ladder(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch, live: bool) -> None:
    # Served and cut (a proxy in front with a hard limit, here 0.6 s for a minute): the first is opened again at once, the
    # next ones climb the ladder, and the live line ends at the third. (Settled at SETTLED, each was the first failure
    # again: a console every minute and a quarter for good, and every forty seconds while somebody watched live.)
    monkeypatch.setattr(vncdevice, "SETTLED", 0.3)
    monkeypatch.setattr(proxmox.ProxmoxConsole, "HEARTBEAT_AFTER", 0.2)  # (a still screen answers no request until asked a dot)
    monkeypatch.setattr(proxmox, "LIVE_WAIT", 0.3)
    monkeypatch.setattr(proxmox, "CONSOLE_RETRY", (0.4, 0.8, 60.0))

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            await cut_whenever_served(pve, device, served=0.6, seconds=7.0, live=live)
            assert consoles_opened(pve) == 3, f"{consoles_opened(pve)} consoles"
            assert device._console._failures == 3
            assert device.console_readable is False
        finally:
            await device.close()

    asyncio.run(run())


def test_a_run_of_cut_consoles_is_over_once_one_serves_long_enough(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vncdevice, "SETTLED", 0.3)
    monkeypatch.setattr(proxmox.ProxmoxConsole, "HEARTBEAT_AFTER", 0.2)  # (a still screen answers no request until asked a dot)
    monkeypatch.setattr(proxmox.ProxmoxConsole, "AGAIN_SOON", 1.0)
    monkeypatch.setattr(proxmox, "CONSOLE_RETRY", (60.0,))

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            await cut_whenever_served(pve, device, served=0.6, seconds=5.0, once=True)  # (cut: opened again at once)
            await cut_whenever_served(pve, device, served=1.5, seconds=5.0, once=True)  # (served long enough, and cut: at once again)
            await cut_whenever_served(pve, device, served=99, seconds=1.0)
            assert consoles_opened(pve) == 3, f"{consoles_opened(pve)} consoles"
            assert device._console._failures <= 1
        finally:
            await device.close()

    asyncio.run(run())


def test_a_run_of_cut_consoles_outlives_the_tile_being_made_anew(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vncdevice, "SETTLED", 0.3)
    monkeypatch.setattr(proxmox.ProxmoxConsole, "HEARTBEAT_AFTER", 0.2)  # (a still screen answers no request until asked a dot)
    monkeypatch.setattr(proxmox, "CONSOLE_RETRY", (0.4, 60.0))

    async def run() -> None:
        first = a_guest(pve)
        try:
            await first.status()
            await cut_whenever_served(pve, first, served=0.6, seconds=5.0, once=True)
            assert first._console._failures == 1
        finally:
            await first.close()
        again = a_guest(pve)  # (the tile edited, its certificate trusted, or the saved passwords locked and opened)
        try:
            await again.status()
            await cut_whenever_served(pve, again, served=0.6, seconds=5.0, once=True)
            assert again._console._failures == 2  # (not forgiven a second time as a first cut)
        finally:
            await again.close()

    asyncio.run(run())


def test_a_live_viewer_waits_out_a_moment_of_proxmoxs_own_with_the_tile(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # A live line asked again at once and fell into the same moment: a second failure, and a minute without a screen.
    monkeypatch.setattr(proxmox, "LIVE_WAIT", 0.3)
    monkeypatch.setattr(proxmox, "CONSOLE_RETRY", (0.6, 60.0))

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            pve.state.unwell_until = time.monotonic() + 0.4
            shown = None
            deadline = time.monotonic() + 3.0
            while shown is None and time.monotonic() < deadline:
                try:
                    shown = await device.live_screen()
                except KvmError:
                    await asyncio.sleep(0.05)
            assert shown is not None and device._console._failures <= 1
        finally:
            await device.close()

    asyncio.run(run())


def test_an_upgrade_proxmox_answers_with_an_error_of_its_own_is_a_failure_and_no_refusal(pve: FakeProxmox) -> None:
    pve.state.hostile = "upgrade_500"

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            with pytest.raises(KvmError):
                await picture_of(device, within=1.0)
            assert device._console._refusal is None and device._console._failures == 1
        finally:
            await device.close()

    asyncio.run(run())


def test_a_proxmox_that_says_the_token_back_does_not_put_it_in_the_log_or_on_the_tile(pve: FakeProxmox, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    pve.state.hostile = "echo"

    async def run() -> None:
        device = a_guest(pve)
        try:
            status = await device.status()
            said = str(status.get("error"))
            assert "(the token)" in said, said
            assert SECRET not in said and TOKEN_ID not in said
            pve.state.hostile = ""
            await device.status()
            pve.state.hostile = "echo"
            with pytest.raises(KvmError) as failed:
                await picture_of(device, within=1.0)
            assert SECRET not in failed.value.message and TOKEN_ID not in failed.value.message
            assert SECRET not in str(device._console.refused_now()) and SECRET not in str(device._console._down_error)
        finally:
            await device.close()

    asyncio.run(run())
    logged = "\n".join(record.getMessage() for record in caplog.records if record.name != "uvicorn.error")
    assert SECRET not in logged and SECRET.upper() not in logged


def test_cuts_far_apart_are_each_forgiven_on_a_wall_looked_at_in_short_visits(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # No session of a short visit serves AGAIN_SOON: a cut a day after the last one was one more rung, up to the top.
    monkeypatch.setattr(vncdevice, "SETTLED", 0.3)
    monkeypatch.setattr(proxmox.ProxmoxConsole, "HEARTBEAT_AFTER", 0.2)
    monkeypatch.setattr(proxmox.ProxmoxConsole, "QUIET_AFTER", 1.5)
    monkeypatch.setattr(proxmox, "CONSOLE_RETRY", (60.0,))

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            for visit in range(3):
                await cut_whenever_served(pve, device, served=0.6, seconds=5.0, once=True)
                assert device._console._failures == 1, f"visit {visit + 1}"
                await asyncio.sleep(1.6)  # (nobody looks for longer than QUIET_AFTER)
            assert consoles_opened(pve) == 3
        finally:
            await device.close()

    asyncio.run(run())


def test_a_run_of_cuts_goes_on_through_failures_of_another_kind(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # A proxy that cuts consoles and now and then fails the next one too: ended by that failure, the run began again at
    # every cut, and a console was opened every minute or two for good.
    monkeypatch.setattr(vncdevice, "SETTLED", 0.3)
    monkeypatch.setattr(proxmox.ProxmoxConsole, "HEARTBEAT_AFTER", 0.2)
    monkeypatch.setattr(proxmox, "CONSOLE_RETRY", (0.2,))

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            await cut_whenever_served(pve, device, served=0.6, seconds=5.0, once=True)
            pve.state.guests[100].console_fails = True
            deadline = time.monotonic() + 5.0
            while device._console._failures < 3 and time.monotonic() < deadline:
                try:
                    await device.snapshot(640)
                except KvmError:
                    pass
                await asyncio.sleep(0.05)
            assert device._console._failures >= 3
            pve.state.guests[100].console_fails = False
            before = device._console._failures
            await cut_whenever_served(pve, device, served=0.6, seconds=5.0, once=True)
            assert device._console._failures > before  # (not forgiven at SETTLED, and the cut not a first one)
        finally:
            await device.close()

    asyncio.run(run())


def test_a_console_that_lets_qkvm_in_and_then_sends_what_it_does_not_take_climbs_its_ladder(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # Counted from nothing again at every handshake, it was asked for again on the first rung for good (four a minute).
    monkeypatch.setattr(proxmox, "CONSOLE_RETRY", (0.4, 60.0))
    pve.state.guests[100].screen.hostile = "unknown_message"

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                try:
                    await device.snapshot(640)
                except KvmError:
                    pass
                await asyncio.sleep(0.05)
            assert consoles_opened(pve) == 2, f"{consoles_opened(pve)} consoles"
        finally:
            await device.close()

    asyncio.run(run())


def test_the_token_said_back_in_another_spelling_is_not_said_at_all() -> None:
    def said_back(message: str) -> str:
        request = httpx.Request("GET", "https://pve.example:8006/api2/json/version", headers={"Authorization": f"PVEAPIToken={TOKEN_ID}={SECRET}"})
        return proxmox._said(httpx.Response(503, json={"message": message}, request=request))

    assert said_back("unable to read file: busy") == "unable to read file: busy"  # (Proxmox's own words, as they are)
    assert said_back(f"it had PVEAPIToken={TOKEN_ID}={SECRET}") == "it had (the token)"
    spellings = (
        SECRET[:10] + "\n" + SECRET[10:],
        SECRET[:10] + "\t" + SECRET[10:],
        SECRET.replace("-", ""),
        SECRET.upper().replace("-", " "),
        quote(TOKEN_ID, safe=""),
        quote(f"PVEAPIToken={TOKEN_ID}={SECRET}", safe=""),
        quote(quote(TOKEN_ID, safe=""), safe=""),
    )
    for spelling in spellings:
        assert said_back(f"upstream failed for {spelling}") == proxmox.SAID_THE_TOKEN, spelling


async def misbehave_whenever_served(pve: FakeProxmox, device: ProxmoxGuest, how: str, served: float, seconds: float) -> None:
    """Ask for the guest's screen as a tile does for `seconds`; every console that has served `served` seconds then
    misbehaves (`how`, the VNC stand-in's way), and the next one serves well again until it has served as long."""
    screen = pve.state.guests[100].screen
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        session = device._console._session
        if session is None or session.done.is_set():
            screen.hostile = ""
        try:
            await device.snapshot(640)
        except KvmError:
            pass
        session = device._console._session
        if session is not None and not session.done.is_set() and session.let_in_at is not None and time.monotonic() - session.let_in_at >= served:
            screen.hostile = how
        await asyncio.sleep(0.05)


@pytest.mark.parametrize("how", ["silent", "unknown_message"], ids=["hangs", "sends-what-is-not-taken"])
def test_a_console_that_serves_a_while_and_then_fails_climbs_its_ladder(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch, how: str) -> None:
    # Served a while, then hung (ended by the heartbeat) or sent what qKVM does not take: counted from nothing again at
    # each settle, it was opened again every minute or two for good.
    monkeypatch.setattr(vncdevice, "SETTLED", 0.3)
    monkeypatch.setattr(proxmox.ProxmoxConsole, "HEARTBEAT_AFTER", 0.2)
    monkeypatch.setattr(rfb, "MESSAGE_WITHIN", 0.3)
    monkeypatch.setattr(proxmox, "CONSOLE_RETRY", (0.3, 0.6, 60.0))

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            await misbehave_whenever_served(pve, device, how, served=0.6, seconds=8.0)
            assert consoles_opened(pve) == 3, f"{consoles_opened(pve)} consoles"
        finally:
            await device.close()

    asyncio.run(run())


def test_a_guest_proxmox_started_again_is_no_run_of_cuts(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # Proxmox's own Reboot, HA starting it again: the guest's process begins again and its console ends with it. A look
    # that finds it began again explains that end, as a look that finds it stopped does; a restart with a moment of
    # Proxmox's own after it climbed the ladder, and a few restarts ended the live line.
    monkeypatch.setattr(vncdevice, "SETTLED", 0.3)
    monkeypatch.setattr(proxmox.ProxmoxConsole, "HEARTBEAT_AFTER", 0.2)
    monkeypatch.setattr(proxmox.ProxmoxConsole, "RESTART_FORGIVEN_EVERY", 0.0)
    monkeypatch.setattr(proxmox, "CONSOLE_RETRY", (0.2, 60.0))

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            for restart in range(3):
                await cut_whenever_served(pve, device, served=0.6, seconds=5.0, once=True)  # (its console ends with it)
                pve.state.guests[100].uptime = 1  # (and the next look finds it began again, a second ago)
                await device._refresh_status()
                assert device._console._failures == 0, f"restart {restart + 1}"
                pve.state.guests[100].uptime = 1234
                await device._refresh_status()  # (running on since)
            assert device.console_readable is True
        finally:
            await device.close()

    asyncio.run(run())


def test_the_consoles_own_look_finds_a_guest_that_began_again(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vncdevice, "SETTLED", 0.3)
    monkeypatch.setattr(proxmox.ProxmoxConsole, "HEARTBEAT_AFTER", 0.2)

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            await cut_whenever_served(pve, device, served=0.6, seconds=5.0, once=True)
            assert device._console._cut_in_run
            pve.state.guests[100].uptime = 1  # (no look of the tile's between: the console's own finds it)
            await picture_of(device, within=5.0)
            assert device._console._failures == 0 and not device._console._cut_in_run
        finally:
            await device.close()

    asyncio.run(run())


def test_a_proxmox_that_says_at_every_look_that_the_guest_began_again_does_not_undo_the_ladder(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # Forgiven at every look, consoles that never let qKVM in were asked for again at once for good (about 840 an hour), and
    # the live line never ended. A restart explains consoles that served and ended with it, once in a while; not those.
    monkeypatch.setattr(proxmox, "CONSOLE_RETRY", (0.2, 0.2, 60.0))
    pve.state.guests[100].uptime = 10**6
    pve.state.guests[100].uptime_falls = True
    pve.state.guests[100].console_fails = True

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            deadline = time.monotonic() + 4.0
            while time.monotonic() < deadline:
                await device._refresh_status()
                try:
                    await device.snapshot(640)
                except KvmError:
                    pass
                await asyncio.sleep(0.1)
            assert consoles_opened(pve) == 3, f"{consoles_opened(pve)} consoles"
            assert device.console_readable is False
        finally:
            await device.close()

    asyncio.run(run())


def test_a_proxmox_whose_uptime_falls_at_every_look_does_not_undo_the_ladder_of_consoles_that_serve(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # A process said to have begun long before the console ended explains nothing of it.
    monkeypatch.setattr(vncdevice, "SETTLED", 0.3)
    monkeypatch.setattr(proxmox.ProxmoxConsole, "HEARTBEAT_AFTER", 0.2)
    monkeypatch.setattr(proxmox, "CONSOLE_RETRY", (0.2, 0.4, 60.0))
    pve.state.guests[100].uptime = 10**6
    pve.state.guests[100].uptime_falls = True

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            deadline = time.monotonic() + 8.0
            while time.monotonic() < deadline:
                await device._refresh_status()
                await cut_whenever_served(pve, device, served=0.6, seconds=0.1)
            # (cut, opened again at once; cut, 0.4 s; cut, 60 s)
            assert consoles_opened(pve) == 3, f"{consoles_opened(pve)} consoles"
        finally:
            await device.close()

    asyncio.run(run())


def test_a_guest_said_to_begin_again_after_every_cut_is_forgiven_once_a_minute(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # What says so is Proxmox's word: said after every cut, it would forgive every cut.
    monkeypatch.setattr(vncdevice, "SETTLED", 0.3)
    monkeypatch.setattr(proxmox.ProxmoxConsole, "HEARTBEAT_AFTER", 0.2)
    monkeypatch.setattr(proxmox, "CONSOLE_RETRY", (0.2, 0.2, 60.0))

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            after = []
            for _ in range(3):
                await cut_whenever_served(pve, device, served=0.6, seconds=5.0, once=True)
                pve.state.guests[100].uptime = 1
                await device._refresh_status()
                after.append(device._console._failures)
                pve.state.guests[100].uptime = 1234
                await device._refresh_status()
            assert after == [0, 1, 2]
        finally:
            await device.close()

    asyncio.run(run())


def test_a_guest_begun_again_soon_after_its_console_opened_is_forgiven(pve: FakeProxmox) -> None:
    # Proxmox's Reboot pressed half a minute or less after the tile was first looked at: the console that ended with it had
    # not served long enough to count as one that served, and was held against the next.
    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            await cut_whenever_served(pve, device, served=0.6, seconds=5.0, once=True)
            assert device._console._failures == 1
            pve.state.guests[100].uptime = 1
            await device._refresh_status()
            assert device._console._failures == 0
        finally:
            await device.close()

    asyncio.run(run())


def test_a_console_asked_for_a_guest_found_stopped_forgives_what_failed_before(pve: FakeProxmox) -> None:
    # A guest truly stopped: its console ended with it and did not fail, so what failed before is forgiven and the next one,
    # once it runs again, is asked for at once. (Capped at once in five minutes, which this single stop is well within.)
    vncdevice._PACED[f"proxmox\0{pve.guest_url(100)}"] = (2, 0.0, "dropped", "it ended", 502, 0, 0.0, "", True, False, False, time.monotonic())

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            assert device._console._failures == 2
            pve.state.guests[100].status = "stopped"  # (stopped since the tile's last look)
            with pytest.raises(KvmError):
                await picture_of(device, within=1.0)
            assert device._console._failures == 0 and not device._console._cut_in_run
        finally:
            await device.close()

    asyncio.run(run())


def test_a_guests_console_is_held_five_minutes_after_its_last_viewer() -> None:
    # The owner's standard (2026-10-18), where it was a minute: each console opened is a task in the node's log.
    assert proxmox.ProxmoxConsole.LET_GO_AFTER == kvm.STANDARD_HOLD == 300.0
    assert proxmox.ProxmoxConsole.STOPPED_FORGIVEN_EVERY == 300.0
    from qkvm import openbmc

    assert openbmc.OpenBmcScreen.LET_GO_AFTER == 60.0  # (a controller's console is one of its four seats: not held longer)


def test_a_guest_found_stopped_forgives_at_most_once_in_five_minutes(pve: FakeProxmox) -> None:
    # A real stop forgives fully; a Proxmox that says "stopped" by turns, about a console that keeps failing, cannot reset
    # the ladder at every look (at most once in five minutes).
    async def run() -> None:
        device = a_guest(pve)
        console = device._console
        try:
            console._failures = 3
            console.guest_stopped()
            assert console._failures == 0  # (forgiven in full)
            console._failures = 4
            console.guest_stopped()  # (a minute later, say: not again, since the budget was just spent)
            assert console._failures == 4
            console._stopped_forgiven_at -= 301.0
            console.guest_stopped()  # (five minutes after the last)
            assert console._failures == 0
            # Nothing to forgive: a no-op that does not spend the once-in-five-minutes budget.
            console._stopped_forgiven_at -= 301.0
            spent = console._stopped_forgiven_at
            console.guest_stopped()  # (failures 0: nothing to forgive)
            assert console._stopped_forgiven_at == spent
        finally:
            await device.close()

    asyncio.run(run())


def test_a_proxmox_that_says_stopped_and_running_by_turns_has_consoles_opened_on_the_ladder_only(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # W10b's question 5, the owner's answer of 2026-10-18: forgiven at every "stopped", a console that keeps failing was
    # opened at every other look, about 360 times an hour. Now at most once in five minutes besides its own ladder.
    monkeypatch.setattr(proxmox, "CONSOLE_RETRY", (0.2, 0.2, 60.0))
    pve.state.guests[100].console_fails = True
    pve.state.guests[100].stopped_by_turns = 0.3

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            deadline = time.monotonic() + 4.0
            while time.monotonic() < deadline:
                await device._refresh_status()
                try:
                    await device.snapshot(640)
                except KvmError:
                    pass
                await asyncio.sleep(0.05)
            assert pve.state.guests[100].said_stopped >= 10  # (it did say so, again and again)
            # On the ladder, forgiven at most once in five minutes: a small number, not one per "running" turn (which would
            # be well over a dozen in four seconds, about 360 an hour).
            assert consoles_opened(pve) <= 8, f"{consoles_opened(pve)} consoles"
        finally:
            await device.close()

    asyncio.run(run())


def test_an_hour_after_the_last_failure_the_ladder_begins_again(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # An evening on the top rung, a quiet night, and a moment of Proxmox's own at the morning's first console: it counted
    # on from the evening's rung (half an hour without a screen, and the live line ended at once).
    monkeypatch.setattr(proxmox.ProxmoxConsole, "QUIET_AFTER", 5.0)
    monkeypatch.setattr(proxmox, "CONSOLE_RETRY", (0.5, 60.0))
    evening = time.monotonic() - 10.0
    vncdevice._PACED[f"proxmox\0{pve.guest_url(100)}"] = (5, 0.0, "dropped", "it ended", 502, 0, 0.0, "", True, False, False, evening)

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            pve.state.unwell_until = time.monotonic() + 0.3
            with pytest.raises(KvmError):
                await picture_of(device, within=0.2)
            for _ in range(40):
                down = device._console._down_error
                if down is not None and "busy" in down.message:
                    break
                await asyncio.sleep(0.05)
            assert device._console._failures == 1 and device.console_readable is True
            shown, deadline = None, time.monotonic() + 3.0
            while shown is None and time.monotonic() < deadline:  # (after the first rung)
                try:
                    shown = await device.snapshot(640)
                except KvmError:
                    await asyncio.sleep(0.05)
            assert shown is not None
        finally:
            await device.close()

    asyncio.run(run())


def test_a_live_line_ends_for_a_console_that_failed_three_times_in_a_row(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(proxmox, "CONSOLE_RETRY", (0.2, 0.2, 60.0))
    pve.state.guests[100].console_fails = True

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            deadline = time.monotonic() + 6.0
            while time.monotonic() < deadline and device._console._failures < 3:
                try:
                    await device.snapshot(640)
                except KvmError:
                    pass
                await asyncio.sleep(0.05)
            assert device._console._failures >= 3
            assert device.console_readable is False  # (a live line ends, and says why, where it waited before)
        finally:
            await device.close()

    asyncio.run(run())


def test_a_moment_of_proxmoxs_own_at_the_console_is_waited_for_and_no_refusal(pve: FakeProxmox) -> None:
    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.status()
            pve.state.unwell_until = time.monotonic() + 0.5  # "unable to read file: busy", to everything
            with pytest.raises(KvmError):
                await picture_of(device, within=0.3)
            for _ in range(40):
                if device._console._failures or device._console._refusal:
                    break
                await asyncio.sleep(0.05)
            assert device._console._refusal is None and device._console._failures == 1
            assert device.console_readable is True  # (the live line waits; it is not told the screen is turned away)
        finally:
            await device.close()

    asyncio.run(run())


def test_no_live_line_is_kept_waiting_for_a_guest_whose_proxmox_does_not_take_the_token(pve: FakeProxmox) -> None:
    async def run() -> None:
        device = a_guest(pve, password="00000000-0000-0000-0000-000000000000")
        try:
            status = await device.status()
            assert status["state"] == "auth"
            assert device.console_readable is False
        finally:
            await device.close()

    asyncio.run(run())


# --- which virtual machine has the guest's number --------------------------------------------------------------------

BUTTONS = ("power_on", "power_off", "atx_power", "atx_power_long", "atx_reset")


def number_of(guest: Guest) -> str:
    """The number a guest gives for itself, as the wall keeps it (DeviceSpec.machine)."""
    return str(proxmox.own_number({"smbios1": f"uuid={guest.uuid}"}))


async def look(device: ProxmoxGuest) -> dict[str, Any]:
    """One look at the guest, waited for (status() answers what the last one found, and has the next one made meanwhile)."""
    device._status_at = 0.0
    await device._refresh_soon()
    return dict(device._status or {})


def typed(client: Any, device: str, body: dict[str, Any]) -> Any:
    """An action that goes through the guest's console, asked again while the console is being opened (as the page does)."""
    for _ in range(100):
        reply = client.post(f"/api/v1/devices/{device}/actions", json=body)
        if reply.status_code != 503:
            return reply
        time.sleep(0.1)
    return reply


@pytest.mark.parametrize("node", ["pve1", "pve2"], ids=["on-its-node", "on-another-node"])
def test_a_vm_given_a_deleted_guests_number_is_sent_no_power_command_no_key_and_shows_no_screen(tmp_path: Path, pve: FakeProxmox, node: str) -> None:
    # (The final review's F2.) Proxmox gives a new virtual machine the lowest free number: "web" (100) deleted and "prod-db"
    # made, on its node or on another, has 100. The tile, still named "web", went green again and showed prod-db's screen,
    # pressed its power buttons and typed Send keys, Type text and saved texts into its console; on another node it followed
    # the number there without a word.
    pve.state.nodes = ["pve1", "pve2"]
    with wall(tmp_path) as client:
        reply = client.post("/api/v1/devices", json={"url": pve.guest_url(100), **TOKEN})
        assert reply.status_code == 201, reply.text
        device = reply.json()["device"]["id"]
        record = client.core.store.device(device)  # type: ignore[attr-defined]
        assert record.machine == number_of(pve.state.guests[100]) == record.ident  # remembered when it was added
        pve.delete_guest(100)
        other = pve.make_guest("prod-db", node=node, screen=VncState(width=320, height=200, name="QEMU (prod-db)", seed=7))
        assert other.vmid == 100 and other.uuid != ""
        for action in BUTTONS:
            refused = client.post(f"/api/v1/devices/{device}/actions", json={"action": action})
            assert (refused.status_code, refused.json().get("code")) == (502, "another_machine"), (action, refused.text)
            assert "Another virtual machine has this guest's number" in refused.json()["message"]
        for body in ({"action": "text", "text": "s3cret"}, {"action": "keys", "keys": "ControlLeft,AltLeft,Delete"}, {"action": "ctrl_alt_del"}):
            refused = typed(client, device, body)
            assert (refused.status_code, refused.json().get("code")) == (502, "another_machine"), (body, refused.text)
        shown = client.get(snap(device))
        assert (shown.status_code, shown.json().get("code")) == (502, "another_machine"), shown.text
        status = state_of(client, device)
        assert (status["state"], status["error"]["code"]) == ("error", "another_machine"), status
        # Nothing was sent to it: no power command, no console (each a task in its Proxmox's log), no key.
        assert other.status == "running" and pve.state.tasks == [] and other.screen.keys == []
        assert [asked for asked in pve.state.requests if not asked.startswith("GET ")] == []
        # The tile does not say what it read of the other one (its power, its processors) as this guest's.
        assert status.get("server") is None and status.get("atx") is None


def test_the_tile_says_that_another_vm_has_the_number_before_anybody_presses(tmp_path: Path, pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    monkeypatch.setattr(proxmox, "SAME_GUEST_EVERY", 0.5)
    caplog.set_level(logging.INFO, logger="qkvm")
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pve.guest_url(100), **TOKEN}).json()["device"]["id"]
        wait_until(lambda: state_of(client, device)["state"] == "online", "the guest is not seen")
        pve.delete_guest(100)
        pve.make_guest("prod-db")
        wait_until(lambda: (state_of(client, device).get("error") or {}).get("code") == "another_machine", "the tile does not say it", timeout=15)
        assert any("Another virtual machine has this guest's number" in line.getMessage() for line in caplog.records if line.levelno == logging.WARNING)
        assert consoles_opened(pve) == 0 and client.get(snap(device)).json()["code"] == "another_machine"


def test_a_look_asks_which_vm_has_the_number_once_a_minute_and_no_more_while_another_has_it(pve: FakeProxmox) -> None:
    def asked(what: str) -> int:
        return sum(1 for one in pve.state.requests if one == f"GET /nodes/pve1/qemu/100/{what}")

    async def run() -> None:
        device = a_guest(pve)
        try:
            for _ in range(20):
                assert (await look(device))["state"] == "online"
            assert (asked("config"), asked("status/current")) == (1, 20)  # the first look took its number; none since
            pve.delete_guest(100)
            pve.make_guest("prod-db")
            device._judged_at = float("-inf")  # (a minute later)
            for _ in range(20):
                status = await look(device)
                assert status["error"]["code"] == "another_machine"
            # Asked once (after its state, as every look reads it), and said from then on until the minute is over: not at
            # every look, and nothing else asked of it.
            assert (asked("config"), asked("status/current")) == (2, 21)
        finally:
            await device.close()

    asyncio.run(run())


@pytest.mark.parametrize("made", ["stopped", "running"])
def test_a_look_that_finds_the_guest_stopped_started_or_begun_anew_asks_at_once_which_vm_has_the_number(pve: FakeProxmox, made: str) -> None:
    # (The fresh reviewer's L1.) Until the minute was over, the tile said a new VM's state as this guest's: its power, its
    # processors and memory, its screen offered, and a stopped new one as "the guest is stopped" (and nothing found out
    # sooner, since nothing asks a stopped guest for its console). A VM made under the guest's number runs a process of its
    # own, or none: a look that finds the guest stopped where it ran, or running a process begun since, asks at once.
    async def run() -> None:
        device = a_guest(pve)
        try:
            assert (await look(device))["state"] == "online"
            # Deleted, and another made under its number, stopped as a new one is, or started at once.
            pve.delete_guest(100)
            pve.make_guest("prod-db", status=made, uptime=1)
            status = await look(device)
            assert (status["state"], (status["error"] or {}).get("code")) == ("error", "another_machine"), status
            assert "server" not in status and device._power_on is None  # (nothing of the other one said of this guest)
        finally:
            await device.close()

    asyncio.run(run())


def test_the_first_look_after_a_tile_is_added_or_edited_asks_which_vm_has_the_number(pve: FakeProxmox) -> None:
    # (The second reviewer's L2.) Adding or editing a tile asks which VM has the number (identify), and its first look then
    # knew nothing of the guest's state to compare with: it took whatever VM had the number as the guest until the minute
    # was over, here one made in that moment that runs as the guest did, for as long as it did.
    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.identify()
            pve.delete_guest(100)
            pve.make_guest("prod-db")  # (running, its uptime as the guest's was: nothing in its state tells it apart)
            status = await look(device)
            assert (status["state"], (status["error"] or {}).get("code")) == ("error", "another_machine"), status
        finally:
            await device.close()

    asyncio.run(run())


def test_a_vm_made_under_the_number_between_a_looks_two_questions_is_found_at_the_next_look(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The second reviewer's N2.) A look asked which VM has the number first and read the state after: a VM made under the
    # number between the two was read as the guest, and became what the next looks compared with, for the minute. The state
    # is read first now, as before a button and a console, and the next look finds a process begun since.
    real = ProxmoxGuest._guest
    armed = [False]

    async def replaced_after_the_question(self: ProxmoxGuest, method: str, step: str, what: str, **options: Any) -> Any:
        said = await real(self, method, step, what, **options)
        if step == "config" and armed[0]:
            armed[0] = False
            pve.delete_guest(100)
            pve.make_guest("prod-db", uptime=1)  # (a new VM runs a process of its own)
        return said

    async def run() -> None:
        device = a_guest(pve)
        try:
            assert (await look(device))["state"] == "online"
            monkeypatch.setattr(ProxmoxGuest, "_guest", replaced_after_the_question)
            armed[0], device._judged_at = True, float("-inf")  # (the minute is over: this look asks again)
            await look(device)
            status = await look(device)
            assert (status["state"], (status["error"] or {}).get("code")) == ("error", "another_machine"), status
        finally:
            await device.close()

    asyncio.run(run())


def test_a_look_within_one_step_of_a_coarse_clock_still_asks_where_the_guest_was_replaced(pve: FakeProxmox, monkeypatch: pytest.MonkeyPatch) -> None:
    # The whole suite on Python 3.11 (Windows' clock before 3.13 moves in steps of 15.6 ms) found this: a look told a question
    # its own state's read had asked (following the guest) from the last look's by the time, and a look within one step of
    # the last one's question asked nothing. Here proxmox.py alone is given a clock that moves in whole seconds.
    from types import SimpleNamespace

    monkeypatch.setattr(proxmox, "time", SimpleNamespace(monotonic=lambda: float(int(time.monotonic()))))

    async def run() -> None:
        device = a_guest(pve)
        try:
            assert (await look(device))["state"] == "online"
            pve.delete_guest(100)
            pve.make_guest("prod-db", status="stopped")
            status = await look(device)  # (in the same second as the first look's question, more often than not)
            assert (status["state"], (status["error"] or {}).get("code")) == ("error", "another_machine"), status
        finally:
            await device.close()

    for _ in range(3):
        asyncio.run(run())
        pve.delete_guest(100)
        pve.make_guest("web")


def test_the_guest_itself_stopped_and_started_is_asked_once_at_each_change_and_never_refused(pve: FakeProxmox) -> None:
    def configs() -> int:
        return sum(1 for one in pve.state.requests if one == "GET /nodes/pve1/qemu/100/config")

    async def run() -> None:
        device = a_guest(pve)
        try:
            assert (await look(device))["state"] == "online"
            asked = configs()
            pve.state.guests[100].status = "stopped"
            assert (await look(device))["state"] == "no_signal"
            pve.state.guests[100].status, pve.state.guests[100].uptime = "running", 2
            assert (await look(device))["state"] == "online"
            assert (await look(device))["state"] == "online" and configs() == asked + 2
            await picture_of(device)
        finally:
            await device.close()

    asyncio.run(run())


def test_the_guest_this_tile_was_added_for_is_followed_to_another_node_and_another_vm_there_is_not(pve: FakeProxmox) -> None:
    pve.state.nodes = ["pve1", "pve2"]
    pve.state.guests[101].status = "running"

    async def run() -> None:
        device = a_guest(pve)
        try:
            await device.identify()
            known = device.spec.machine
            assert known == number_of(pve.state.guests[100])
            # Moved within its cluster (live migration: the same guest, the same number for itself): followed, and acted on.
            pve.state.guests[100].node = "pve2"
            await device.act("atx_reset")
            assert device._node == "pve2" and [task["type"] for task in pve.state.tasks] == ["qmreset"]
            await picture_of(device)
            assert device.spec.machine == known  # (the right guest is never refused, nor its number taken anew)
            # Deleted there, and another made on its first node, which Proxmox gives the freed number: not followed back.
            pve.delete_guest(100)
            pve.make_guest("prod-db", node="pve1")
            device._status_at, proxmox._NODES, proxmox._LISTED_FOR = 0.0, {}, {}
            with pytest.raises(KvmError) as refused:
                await device.act("atx_power_long")
            assert refused.value.code == "another_machine" and device._node == "pve2"
            assert [task["type"] for task in pve.state.tasks] == ["qmreset", "vncproxy"]  # (the console of the guest itself)
        finally:
            await device.close()

    asyncio.run(run())


def test_an_edit_takes_the_vm_that_has_the_number_now_only_where_the_tokens_secret_is_typed(tmp_path: Path, pve: FakeProxmox) -> None:
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pve.guest_url(100), **TOKEN}).json()["device"]["id"]
        pve.delete_guest(100)
        other = pve.make_guest("prod-db")
        edit = {"url": pve.guest_url(100), "username": TOKEN_ID, "password": "", "kind": "proxmox", "name": "web renamed"}
        renamed = client.put(f"/api/v1/devices/{device}", json=edit)
        assert (renamed.status_code, renamed.json().get("code")) == (422, "another_machine") and "type its token's secret" in renamed.json()["message"]
        # "Save anyway" saves the rest and keeps the number: the other one is still not this tile's guest.
        anyway = client.put(f"/api/v1/devices/{device}", json={**edit, "force": True})
        assert anyway.status_code == 200, anyway.text
        assert client.core.store.device(device).machine != number_of(other)  # type: ignore[attr-defined]
        assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power_long"}).json()["code"] == "another_machine"
        # Whoever types the token's secret says "this is it".
        taken = client.put(f"/api/v1/devices/{device}", json={**edit, "password": SECRET})
        assert taken.status_code == 200, taken.text
        assert client.core.store.device(device).machine == number_of(other)  # type: ignore[attr-defined]
        wait_until(lambda: state_of(client, device)["state"] == "online", "the tile does not take the guest it was given")
        assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power_long"}).status_code == 200
        assert other.status == "stopped"


def test_a_vm_that_gives_no_number_where_the_guest_gave_one_is_sent_nothing(tmp_path: Path, pve: FakeProxmox) -> None:
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pve.guest_url(100), **TOKEN}).json()["device"]["id"]
        pve.delete_guest(100)
        other = pve.make_guest("old-one", uuid="")
        refused = client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power_long"})
        assert (refused.status_code, refused.json()["code"]) == (502, "another_machine") and "gives no SMBIOS UUID" in refused.json()["message"]
        assert other.status == "running" and pve.state.tasks == []


def test_a_guest_that_gives_no_number_and_was_remembered_by_none_works_as_before(tmp_path: Path, pve: FakeProxmox) -> None:
    pve.state.guests[101].uuid = ""  # (made before Proxmox gave every new guest one: nothing to tell it apart by)
    with wall(tmp_path) as client:
        device = client.post("/api/v1/devices", json={"url": pve.guest_url(101), **TOKEN}).json()["device"]["id"]
        assert client.core.store.device(device).machine == ""  # type: ignore[attr-defined]
        assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "power_on"}).status_code == 200
        assert pve.state.guests[101].status == "running"


def test_a_tile_that_remembers_no_number_takes_the_first_it_sees_and_keeps_it(pve: FakeProxmox, caplog: pytest.LogCaptureFixture) -> None:
    # A tile taken from a file without one, or saved while its Proxmox could not be reached: the first look takes the number
    # (trust on first use, as a certificate is), says so in the log, and has it kept with the tile.
    caplog.set_level(logging.INFO, logger="qkvm")
    kept: list[str] = []

    async def note(was: str, mark: str) -> None:  # (what was remembered, "" here, and the number to keep: as the server's hook)
        assert was == ""
        kept.append(mark)

    async def run() -> None:
        device = a_guest(pve)
        device.on_known = note
        try:
            assert (await look(device))["state"] == "online"
            assert device.spec.machine == number_of(pve.state.guests[100]) and kept == [device.spec.machine]
            pve.delete_guest(100)
            pve.make_guest("prod-db")
            device._judged_at = float("-inf")
            assert (await look(device))["error"]["code"] == "another_machine" and len(kept) == 1
        finally:
            await device.close()

    asyncio.run(run())
    assert any("known by the number it gives for itself" in line.getMessage() for line in caplog.records)


def test_the_number_a_guest_gives_goes_into_an_export_file_and_comes_out_of_it(tmp_path: Path, pve: FakeProxmox) -> None:
    from tests.test_wall import PASSWORD

    with wall(tmp_path / "one") as client:
        device = client.post("/api/v1/devices", json={"url": pve.guest_url(100), **TOKEN}).json()["device"]["id"]
        known = client.core.store.device(device).machine  # type: ignore[attr-defined]
        assert known == number_of(pve.state.guests[100])
        file = client.post("/api/v1/export", json={"password": PASSWORD, "parts": ["devices"], "passphrase": "a passphrase of ours"}).text
    with wall(tmp_path / "two") as client:
        taken = client.post("/api/v1/import", json={"file": file, "passphrase": "a passphrase of ours", "take": ["devices"]})
        assert taken.status_code == 200, taken.text
        (record,) = client.core.store.devices  # type: ignore[attr-defined]
        assert record.machine == known
        pve.delete_guest(100)
        pve.make_guest("prod-db")
        refused = client.post(f"/api/v1/devices/{record.id}/actions", json={"action": "atx_power_long"})
        assert (refused.status_code, refused.json()["code"]) == (502, "another_machine") and pve.state.tasks == []
