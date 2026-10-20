"""A VNC server on the wall: added by its address or by the kind chosen, its picture and state, its keys, its password, its certificate."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

from qkvm import discover, kvm, update, vault, vncdevice
from qkvm.discover import Target
from qkvm.kvm import DeviceSpec, KvmError
from qkvm.store import Store
from qkvm.vncdevice import VncDevice, vnc_url
from tests.fake_vnc import FakeVnc, VncState
from tests.test_wall import snap, wait_until, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 20)  # tests want the real status, not "connecting"
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def vnc() -> Iterator[FakeVnc]:
    server = FakeVnc(VncState(width=160, height=100)).start()
    yield server
    server.stop()


def picture(client: Any, device: str) -> Any:
    """Ask for the tile's picture until the connection has delivered one."""
    reply = None

    def arrived() -> bool:
        nonlocal reply
        reply = client.get(snap(device))
        return bool(reply.status_code == 200)

    wait_until(arrived, "the VNC server never produced a picture", timeout=20)
    return reply


def state_of(client: Any, device: str) -> dict[str, Any]:
    return dict(client.get("/api/v1/status").json()[device])


def test_a_vnc_server_is_added_by_its_address_and_shows_its_screen(tmp_path: Path, vnc: FakeVnc) -> None:
    with wall(tmp_path) as client:
        reply = client.post("/api/v1/devices", json={"url": vnc.url, "password": "secret"})
        assert reply.status_code == 201, reply.text
        body = reply.json()
        device = body["device"]["id"]
        assert body["device"]["kind"] == "vnc" and body["device"]["picture"] is True
        assert body["device"]["name"] == "stand-in VNC"  # named after what the server calls itself
        assert body["device"]["host"] == f"127.0.0.1:{vnc.port}" and body["device"]["url"] == vnc.url
        assert body["about"] == {"model": "stand-in VNC", "version": "RFB 3.8", "hostname": "stand-in VNC"}

        frame = picture(client, device)
        assert frame.content[:3] == b"\xff\xd8\xff" and frame.headers["x-kvm-signal"] == "1"
        status = state_of(client, device)
        assert status["state"] == "online" and status["video"] == {"signal": True, "width": 160, "height": 100, "fps": None}
        assert status["about"] == {"model": "stand-in VNC", "version": "RFB 3.8"} and status["atx"]["enabled"] is False
        listed = client.get("/api/v1/wall").json()["devices"]
        assert [d["kind"] for d in listed] == ["vnc"]
        assert vnc.state.shared == [1]  # the connection that checked it is the wall's: made once, and nobody at the server was thrown out
    assert vnc.state.password_tries == 1


def test_the_kind_can_be_chosen_instead_of_written_into_the_address(tmp_path: Path, vnc: FakeVnc) -> None:
    with wall(tmp_path) as client:
        reply = client.post("/api/v1/devices", json={"url": f"127.0.0.1:{vnc.port}", "kind": "vnc", "password": "secret", "name": "Box"})
        assert reply.status_code == 201, reply.text
        assert reply.json()["device"]["url"] == vnc.url and reply.json()["device"]["kind"] == "vnc"
        again = client.post("/api/v1/devices", json={"url": vnc.url, "password": "secret"})
        assert again.status_code == 409  # the same server, written another way, is on the wall already
        device = reply.json()["device"]["id"]
        # An edit keeps the kind, whichever way the address is written.
        edit = client.put(f"/api/v1/devices/{device}", json={"name": "Box 2", "url": f"127.0.0.1:{vnc.port}", "password": "secret"})
        assert edit.status_code == 200, edit.text
        assert edit.json()["device"]["kind"] == "vnc" and edit.json()["device"]["name"] == "Box 2"


def test_how_a_vnc_address_is_written() -> None:
    assert vnc_url("192.168.1.20") == "vnc://192.168.1.20"
    assert vnc_url(" 192.168.1.20:5900 ") == "vnc://192.168.1.20"
    assert vnc_url("192.168.1.20:5901") == "vnc://192.168.1.20:5901"
    assert vnc_url("VNC://Box.lan.:5902") == "vnc://box.lan:5902"
    assert vnc_url("vncs://box.lan") == "vncs://box.lan"
    assert vnc_url("[::1]:5901") == "vnc://[::1]:5901"
    assert vnc_url("vnc://box.lan/some/path") == "vnc://box.lan"
    for bad in ("", "a b", "box:0", "box:70000", "http://box", "user@box", "box:x", "vnc://"):
        with pytest.raises(ValueError):
            vnc_url(bad)
    assert vncdevice.address_of("vnc://box.lan") == ("box.lan", 5900, False)
    assert vncdevice.address_of("vncs://[::1]:5901") == ("::1", 5901, True)
    # Where a vncs:// server's certificate is asked for: its own host and port, never 443.
    assert vncdevice.certificate_address("vncs://box.lan") == "https://box.lan:5900"
    assert vncdevice.certificate_address("vncs://[::1]:5901") == "https://[::1]:5901"


def test_a_wrong_password_is_said_and_not_offered_again_and_again(tmp_path: Path, vnc: FakeVnc) -> None:
    with wall(tmp_path) as client:
        reply = client.post("/api/v1/devices", json={"url": vnc.url, "password": "wrong"})
        assert reply.status_code == 422 and reply.json()["code"] == "auth_failed", reply.text
        assert vnc.state.password_tries == 1
        # Saved all the same ("Add anyway"), its tile says so, and the password is not sent again meanwhile.
        reply = client.post("/api/v1/devices", json={"url": vnc.url, "password": "wrong", "force": True})
        assert reply.status_code == 201, reply.text
        device = reply.json()["device"]["id"]
        wait_until(lambda: state_of(client, device)["state"] == "auth", "the tile never said that the login was rejected")
        assert state_of(client, device)["error"]["code"] == "auth_failed"
        time.sleep(1.5)
        assert vnc.state.password_tries == 2  # (typed twice by a person, tried at once both times; then held back a minute, whatever the tiles ask)
        # Update login: the right password is tried at once.
        fixed = client.put(f"/api/v1/devices/{device}", json={"url": vnc.url, "password": "secret"})
        assert fixed.status_code == 200, fixed.text
        wait_until(lambda: state_of(client, device)["state"] == "online", "the right password did not let the wall in")
        picture(client, device)


def test_a_server_that_wants_a_password_nobody_saved_is_said_as_that(tmp_path: Path, vnc: FakeVnc) -> None:
    with wall(tmp_path) as client:
        reply = client.post("/api/v1/devices", json={"url": vnc.url, "password": ""})
        assert reply.status_code == 422 and reply.json()["code"] == "no_password", reply.text
        assert vnc.state.password_tries == 0  # nothing was sent for a password that is not there


def test_a_server_that_asks_for_no_password_is_added_without_one(tmp_path: Path) -> None:
    server = FakeVnc(VncState(password=None, width=64, height=48)).start()
    try:
        with wall(tmp_path) as client:
            reply = client.post("/api/v1/devices", json={"url": server.url, "password": ""})
            assert reply.status_code == 201, reply.text
            device = reply.json()["device"]["id"]
            assert reply.json()["device"]["has_password"] is False
            picture(client, device)
            assert state_of(client, device)["state"] == "online"
    finally:
        server.stop()


def test_a_server_that_goes_away_is_offline_and_back_when_it_returns(tmp_path: Path, vnc: FakeVnc) -> None:
    with wall(tmp_path) as client:
        reply = client.post("/api/v1/devices", json={"url": vnc.url, "password": "secret"})
        assert reply.status_code == 201, reply.text
        device = reply.json()["device"]["id"]
        picture(client, device)
        vnc.stop()
        wait_until(lambda: state_of(client, device)["state"] == "offline", "the tile never said offline", timeout=20)
        assert client.get(snap(device)).status_code in (502, 503, 504)
        again = FakeVnc(VncState(width=160, height=100), port=vnc.port).start()
        try:
            wait_until(lambda: state_of(client, device)["state"] == "online", "the tile never came back", timeout=30)
            picture(client, device)
        finally:
            again.stop()


def test_keys_text_and_ctrl_alt_del_reach_the_server_and_nothing_else_is_offered(tmp_path: Path, vnc: FakeVnc) -> None:
    with wall(tmp_path) as client:
        reply = client.post("/api/v1/devices", json={"url": vnc.url, "password": "secret"})
        assert reply.status_code == 201, reply.text
        device = reply.json()["device"]["id"]
        picture(client, device)
        act = f"/api/v1/devices/{device}/actions"
        assert client.post(act, json={"action": "keys", "keys": "MetaLeft,KeyL"}).status_code == 200
        assert client.post(act, json={"action": "keys", "keys": "not keys!"}).status_code == 422
        assert client.post(act, json={"action": "keys", "keys": "Lang1"}).status_code == 422  # a name there is no key for
        assert client.post(act, json={"action": "text", "text": "Hi!", "enter": True}).status_code == 200
        assert client.post(act, json={"action": "text", "text": "café €"}).status_code == 200  # keysyms: the server's layout decides
        assert client.post(act, json={"action": "text", "text": ""}).status_code == 422
        assert client.post(act, json={"action": "ctrl_alt_del"}).status_code == 200
        for other in ("jiggler_on", "atx_power", "reboot", "wol", "port"):
            reply = client.post(act, json={"action": other, "mac": "AA:BB:CC:DD:EE:FF"})
            assert reply.status_code == 422, (other, reply.text)
        assert client.get(f"/api/v1/devices/{device}/wol").json() == {"targets": []}
        wait_until(lambda: len(vnc.state.keys) >= 4 + 8 + 12 + 6, "the keys never all arrived")
    keys = vnc.state.keys
    assert keys[:4] == [(0xFFEB, True), (0x6C, True), (0x6C, False), (0xFFEB, False)]  # Super_L, l
    assert keys[4:12] == [(0x48, True), (0x48, False), (0x69, True), (0x69, False), (0x21, True), (0x21, False), (0xFF0D, True), (0xFF0D, False)]
    typed = [keysym for keysym, down in keys[12:24] if down]
    assert typed == [0x63, 0x61, 0x66, 0xE9, 0x20, 0x01000000 + 0x20AC]
    assert keys[24:30] == [(0xFFE3, True), (0xFFE9, True), (0xFFFF, True), (0xFFFF, False), (0xFFE9, False), (0xFFE3, False)]


def test_the_network_search_finds_a_vnc_server_without_sending_it_anything(tmp_path: Path, vnc: FakeVnc, monkeypatch: pytest.MonkeyPatch) -> None:
    nowhere = "http://127.0.0.1:9"
    monkeypatch.setattr(discover, "VNC_PORTS", (vnc.port,))
    monkeypatch.setattr(discover, "targets", lambda: ([Target("127.0.0.1", nowhere, nowhere, "box")], ["test network"]))
    with wall(tmp_path) as admin:
        result = admin.post("/api/v1/discover").json()
        assert result["found"] == [
            {"address": "127.0.0.1", "kind": "vnc", "url": vnc.url, "name": "box", "known": False, "known_as": None, "known_id": None, "moved_from": None, "also": []}
        ]
        assert vnc.state.versions == [] and vnc.state.password_tries == 0  # looked at, not spoken to


def test_over_tls_the_certificate_is_remembered_and_another_one_is_refused_the_password(tmp_path: Path) -> None:
    first = FakeVnc(VncState(width=64, height=48), tls_dir=tmp_path / "first").start()
    port = first.port
    try:
        with wall(tmp_path / "data") as client:
            reply = client.post("/api/v1/devices", json={"url": first.url, "password": "secret"})
            assert reply.status_code == 201, reply.text
            device = reply.json()["device"]["id"]
            assert reply.json()["device"]["url"] == f"vncs://127.0.0.1:{port}"
            assert reply.json()["device"]["fingerprint"]  # remembered on first contact
            picture(client, device)
            first.stop()
            other = FakeVnc(VncState(width=64, height=48), port=port, tls_dir=tmp_path / "other").start()
            try:
                wait_until(lambda: state_of(client, device)["error"] is not None and state_of(client, device)["error"]["code"] == "cert_mismatch", "the other certificate was not refused", timeout=20)
                assert state_of(client, device)["state"] == "error"
                time.sleep(0.5)
                assert other.state.password_tries == 0 and other.state.versions == []  # it never got as far as the protocol
            finally:
                other.stop()
    finally:
        first.stop()


def test_a_wall_with_vnc_servers_on_it_starts_again_with_them(tmp_path: Path, vnc: FakeVnc, monkeypatch: pytest.MonkeyPatch) -> None:
    # The settings file took a VNC server's address (vnc://, vncs://) and its reader at a start did not: a wall with one
    # on it did not start again, after any restart, and said to move both copies of its settings aside.
    secure = FakeVnc(VncState(width=64, height=48), tls_dir=tmp_path / "tls").start()
    try:
        with wall(tmp_path / "data") as client:
            plain = client.post("/api/v1/devices", json={"url": vnc.url, "password": "secret", "name": "Plain"})
            over_tls = client.post("/api/v1/devices", json={"url": secure.url, "password": "secret", "name": "Over TLS"})
            assert plain.status_code == 201 and over_tls.status_code == 201, (plain.text, over_tls.text)
            ids = {plain.json()["device"]["id"]: vnc.url, over_tls.json()["device"]["id"]: secure.url}
            remembered = over_tls.json()["device"]["fingerprint"]
            assert remembered
        read = Store(tmp_path / "data" / "qkvm.json")  # as a start reads it, by itself
        assert read.restored is False
        assert {d.id: (d.kind, d.url) for d in read.devices} == {i: ("vnc", url) for i, url in ids.items()}
        kept = next(d for d in read.devices if d.url == secure.url)
        assert kept.tls == "pinned" and kept.cert_pem  # (its certificate was kept with it, and is what it is checked by)

        # After the restart the one over TLS is reached by the certificate remembered for it, and by nothing it is shown anew.
        async def shown_anew(address: str) -> str:
            raise AssertionError(f"the certificate at {address} was trusted anew after the restart")

        monkeypatch.setattr(vncdevice, "fetch_certificate", shown_anew)
        with wall(tmp_path / "data") as client:
            tiles = {d["id"]: d for d in client.get("/api/v1/wall").json()["devices"]}
            assert {i: d["url"] for i, d in tiles.items()} == ids
            assert tiles[over_tls.json()["device"]["id"]]["fingerprint"] == remembered
            for device, url in ids.items():
                wait_until(lambda device=device: state_of(client, device)["state"] == "online", f"{url} was not reached again after the restart", timeout=20)
    finally:
        secure.stop()


def test_over_tls_a_certificate_that_changed_is_shown_and_can_be_trusted_again(tmp_path: Path) -> None:
    # (The final review's F3.) The certificate dialog was answered nothing for an address that is not https://, and Trust
    # fetched the certificate at the address as if it were one, at port 443: a vncs:// server whose certificate changed (a
    # new one after a reinstall, say) could not be trusted again from the page, only taken off the wall and added again.
    first = FakeVnc(VncState(width=64, height=48), tls_dir=tmp_path / "first").start()
    port = first.port
    other: FakeVnc | None = None
    try:
        with wall(tmp_path / "data") as client:
            reply = client.post("/api/v1/devices", json={"url": first.url, "password": "secret"})
            assert reply.status_code == 201, reply.text
            device, remembered = reply.json()["device"]["id"], reply.json()["device"]["fingerprint"]
            picture(client, device)
            first.stop()
            other = FakeVnc(VncState(width=64, height=48, name="reinstalled"), port=port, tls_dir=tmp_path / "other").start()
            wait_until(lambda: (state_of(client, device)["error"] or {}).get("code") == "cert_mismatch", "the other certificate was not said", timeout=20)
            shown = client.get(f"/api/v1/devices/{device}/certificate").json()
            assert shown["saved"] == remembered and shown["presented"] not in (None, remembered), shown
            assert other.state.password_tries == 0  # (shown, not yet trusted: it has been told nothing)
            stale = client.post(f"/api/v1/devices/{device}/trust", json={"fingerprint": remembered})
            assert stale.status_code == 409  # only what was shown is trusted
            trusted = client.post(f"/api/v1/devices/{device}/trust", json={"fingerprint": shown["presented"]})
            assert trusted.status_code == 200, trusted.text
            assert trusted.json()["device"]["fingerprint"] == shown["presented"]
            picture(client, device)
            assert other.state.password_tries >= 1 and state_of(client, device)["state"] == "online"
    finally:
        first.stop()
        if other is not None:
            other.stop()


def test_over_tls_a_server_whose_password_is_held_back_is_asked_whether_it_is_there_inside_tls(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # While a rejected password waits to be offered again, the wall asks now and then whether the server is there at all,
    # by its greeting. A server at a vncs:// address greets inside TLS and never in the open: asked in the open it said
    # nothing, and its tile went from "the password was rejected" to "unreachable" (and an alert said it was gone).
    monkeypatch.setattr(vncdevice, "STILL_THERE_EVERY", 0.3)
    monkeypatch.setattr(vncdevice, "CONNECT_WAIT", 2.0)
    server = FakeVnc(VncState(width=64, height=48), tls_dir=tmp_path / "tls").start()
    try:
        with wall(tmp_path / "data") as client:
            reply = client.post("/api/v1/devices", json={"url": server.url, "password": "wrong", "force": True})
            assert reply.status_code == 201, reply.text
            device = reply.json()["device"]["id"]
            wait_until(lambda: state_of(client, device)["state"] in ("auth", "offline"), "the tile never said how the server is")
            tries, connections = server.state.password_tries, server.state.connections
            until = time.monotonic() + 4.0
            while time.monotonic() < until:
                assert state_of(client, device)["state"] == "auth", state_of(client, device)
                time.sleep(0.2)
            assert server.state.connections > connections  # it was asked, over TLS...
            assert server.state.password_tries == tries  # ...and the password was not offered meanwhile
            # Another certificate at that address meanwhile is said as that, as for every connection to it.
            port = server.port
            server.stop()
            server = FakeVnc(VncState(width=64, height=48), port=port, tls_dir=tmp_path / "other").start()
            wait_until(lambda: (state_of(client, device)["error"] or {}).get("code") == "cert_mismatch", "the other certificate was not said", timeout=20)
            assert server.state.versions == [] and server.state.password_tries == 0
    finally:
        server.stop()


def test_over_tls_at_an_ipv6_address_the_certificate_is_asked_for_at_that_address(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Remembered on first contact from https://host:port, written without brackets: an IPv6 address was no address at all
    # (ValueError), and such a server could never be trusted.
    from tests.fake_kvm import make_device_certificate

    pem = make_device_certificate(tmp_path)[0].read_text()
    asked: list[tuple[str | None, int | None]] = []

    async def fetched(url: str) -> str:
        parts = urlsplit(url)
        asked.append((parts.hostname, parts.port))
        return pem

    monkeypatch.setattr(vncdevice, "fetch_certificate", fetched)

    async def go() -> None:
        device = VncDevice(DeviceSpec(id="v6", name="box", base_url=vnc_url("vncs://[fe80::1]:5901"), username="", password="secret", kind="vnc"))
        try:
            await device._tls_for_vnc()
            assert asked == [("fe80::1", 5901)] and device.spec.cert_pem == pem
        finally:
            await device.close()

    asyncio.run(go())


# --- the device by itself: what a live line gets from it ---------------------------------------------------------------


def test_a_server_that_sends_what_is_not_taken_is_left_alone_longer_each_time_up_to_four_minutes() -> None:
    # Fifteen seconds, then twice as long each time it does so again, four minutes at the most (as the README says, and as
    # the reader's track meant it): the hold was cut to fifteen seconds every time by the limit of a device that is down.
    async def go() -> None:
        device = VncDevice(DeviceSpec(id="v1", name="box", base_url="vnc://127.0.0.1:5900", username="", password="secret", kind="vnc"))
        try:
            holds = []
            for _ in range(7):
                device._left_alone(KvmError("bad_response", "The VNC server sent what qKVM does not take: made up"))
                holds.append(round(device._refusal_until - time.monotonic()))
            assert holds == [15, 30, 60, 120, 240, 240, 240]
        finally:
            await device.close()

    asyncio.run(go())


def test_the_seam_for_a_live_line(vnc: FakeVnc) -> None:
    spec = DeviceSpec(id="v1", name="box", base_url=vnc.url, username="", password="secret", kind="vnc")

    async def go() -> None:
        device = VncDevice(spec)
        try:
            about = await device.identify()
            assert about["model"] == "stand-in VNC"
            device.live(True)
            async with asyncio.timeout(10):
                while device.screen() is None:
                    await asyncio.sleep(0.02)
            screen = device.screen()
            assert screen is not None
            frames, width, height, rgb = screen
            assert (width, height) == (160, 100) and bytes(rgb) == vnc.state.picture
            await device.press(0x04, True)
            await device.press(0x04, False)
            await device.pointer(3, 4, 1)
            with pytest.raises(KvmError):
                await device.press(0x66, True)  # the power key has no keysym
            # A frame newer than the one in hand, when the screen changes.
            vnc.state.picture = bytes(reversed(vnc.state.picture))
            vnc.state.dirty.append((0, 0, 160, 100))
            newer = await device.next_frame(frames, within=5)
            assert newer is not None and newer > frames
            assert device.screen() is not None and bytes(device.screen()[3]) == vnc.state.picture  # type: ignore[index]
            assert await device.next_frame(newer, within=0.2) is None  # nothing changed: nothing newer
            device.live(False)
            async with asyncio.timeout(5):
                while not (len(vnc.state.keys) == 2 and vnc.state.pointers):
                    await asyncio.sleep(0.02)
            assert vnc.state.keys == [(0x61, True), (0x61, False)] and vnc.state.pointers == [(3, 4, 1)]
        finally:
            await device.close()

    asyncio.run(go())
    # Closed means closed: the stand-in, in a thread of its own, counts the connection closed when it notices
    # the end of the stream, which on a loaded machine is a moment after the device has let go of it.
    wait_until(lambda: vnc.state.open == 0, "the VNC server still had the connection after the device was closed")


def test_while_nobody_looks_frames_are_let_go_of_and_the_screen_is_whole_again_when_somebody_does(monkeypatch: pytest.MonkeyPatch) -> None:
    server = FakeVnc(VncState(width=64, height=48, pushes=True, push_every=0.01)).start()
    monkeypatch.setattr(vncdevice, "KEEPALIVE_IDLE", 0.3)
    spec = DeviceSpec(id="v2", name="pushy", base_url=server.url, username="", password="secret", kind="vnc")

    async def go() -> None:
        device = VncDevice(spec)
        try:
            await device.identify()
            snap = None
            async with asyncio.timeout(10):
                while snap is None:
                    try:
                        snap = await device.snapshot(640)
                    except KvmError as ex:
                        assert ex.code == "no_stream", ex.message
                        await asyncio.sleep(0.05)
            client = device._connected()
            async with asyncio.timeout(10):  # nobody asks for a picture any more: what the server pushes is read and let go of
                while client.drawing:
                    await asyncio.sleep(0.02)
            drawn, updates = client.frames, client.updates
            await asyncio.sleep(0.5)
            assert client.drawing is False and client.frames == drawn and client.stale
            assert client.updates > updates  # (they came all the same)
            await device.snapshot(640, fresh=0)  # somebody looks again
            async with asyncio.timeout(10):
                while client.frames == drawn:
                    await asyncio.sleep(0.02)
            assert client.drawing is True and not client.stale
            assert server.state.requests[-1][0] is False  # asked for the whole screen, not for what changed
        finally:
            await device.close()

    try:
        asyncio.run(go())
    finally:
        server.stop()


def test_a_server_that_answers_the_handshake_and_then_nothing_is_said_to_be_gone_in_time(monkeypatch: pytest.MonkeyPatch) -> None:
    from qkvm import rfb

    server = FakeVnc(VncState(width=32, height=32, hostile="silent")).start()
    monkeypatch.setattr(vncdevice, "HEARTBEAT", 0.5)
    monkeypatch.setattr(rfb, "MESSAGE_WITHIN", 0.5)
    spec = DeviceSpec(id="v3", name="mute", base_url=server.url, username="", password="secret", kind="vnc")

    async def go() -> None:
        device = VncDevice(spec)
        try:
            await device.identify()
            status: dict[str, Any] = {}
            async with asyncio.timeout(10):
                while status.get("state") != "offline":
                    status = await device.status()
                    await asyncio.sleep(0.1)
            assert status["error"]["code"] == "timeout" and "answer" in status["error"]["message"], status
        finally:
            await device.close()

    try:
        asyncio.run(go())
    finally:
        server.stop()


def test_a_server_that_hangs_up_after_every_handshake_is_connected_to_less_and_less_often(monkeypatch: pytest.MonkeyPatch) -> None:
    server = FakeVnc(VncState(width=32, height=32, hostile="drop_after_handshake")).start()
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0.2)
    spec = DeviceSpec(id="v4", name="flighty", base_url=server.url, username="", password="secret", kind="vnc")

    async def go() -> None:
        device = VncDevice(spec)
        try:
            await device.identify()
            started = time.monotonic()
            while time.monotonic() - started < 3.0:  # the tiles ask on, as they do
                try:
                    await device.snapshot(640)
                except KvmError:
                    pass
                await asyncio.sleep(0.05)
            # Let in and hung up on each time: that is one failure after another, not a fresh start each time, so the
            # holds climb (0.2, 0.4, 0.8, 1.6 s) and the password goes out a handful of times in three seconds, not fifteen.
            assert device._failures >= 3, device._failures
        finally:
            await device.close()

    try:
        asyncio.run(go())
        assert 2 <= server.state.connections <= 7, server.state.connections
    finally:
        server.stop()


def test_a_server_that_draws_one_frame_and_hangs_up_every_time_is_connected_to_less_and_less_often(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    # (The final review's F1, the sibling of the test above.) The frame was taken for the server being well again: its
    # failures went back to none, each hang-up was the first failure again, and the hold never grew past a second. A
    # connection, the password's answer and three lines of the log every second, for good. A frame settles a connection
    # once it has lasted KEEPALIVE_LASTS as well.
    monkeypatch.setattr(kvm, "ERROR_HOLD", 1.0)  # (the program's own: a second, twice as long after each failure in a row)
    caplog.set_level(logging.INFO, logger="qkvm")
    server = FakeVnc(VncState(width=32, height=32, hostile="one_frame_then_hang_up")).start()
    spec = DeviceSpec(id="v4", name="one frame", base_url=server.url, username="", password="secret", kind="vnc")

    async def go() -> int:
        device = VncDevice(spec)
        most = 0
        try:
            started = time.monotonic()
            while time.monotonic() - started < 8.0:  # a tile that is looked at asks on, as it does
                try:
                    await device.snapshot(640)
                except KvmError:
                    pass
                most = max(most, device._failures)
                await asyncio.sleep(0.05)
        finally:
            await device.close()
        return most

    try:
        most = asyncio.run(go())
        lines = sum(1 for record in caplog.records if "one frame" in record.getMessage())
        # Less and less often: holds of 1, 2 and 4 s are four or five connections in eight seconds, not eight or more.
        assert server.state.connections <= 5 and server.state.password_tries <= 5, (server.state.connections, most, lines)
        assert most >= 2, most  # (the failures climb: before, the frame put them back to none, and each hang-up was the first)
    finally:
        server.stop()


def test_a_server_that_draws_a_frame_and_stays_is_well_again_once_it_has_lasted_a_few_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    # The other side of the test above: a server that comes back is said to be there again a few seconds after its first
    # frame (KEEPALIVE_LASTS), not after SETTLED, where its screen changes.
    monkeypatch.setattr(vncdevice, "SETTLED", 600.0)
    server = FakeVnc(VncState(width=32, height=32)).start()
    spec = DeviceSpec(id="v6", name="back", base_url=server.url, username="", password="secret", kind="vnc")

    async def go() -> float:
        device = VncDevice(spec)
        device._failures = 4  # (down for a while before this connection)
        try:
            started = time.monotonic()
            while device._failures and time.monotonic() - started < 20:
                server.state.dirty.append((0, 0, 4, 4))  # its screen changes: every request is answered
                try:
                    await device.snapshot(640)
                except KvmError:
                    pass
                await asyncio.sleep(0.1)
            assert device._failures == 0
            return time.monotonic() - started
        finally:
            await device.close()

    try:
        took = asyncio.run(go())
        assert kvm.KEEPALIVE_LASTS <= took < kvm.KEEPALIVE_LASTS + 10, took
    finally:
        server.stop()


def test_after_the_device_is_closed_no_connection_is_made_by_a_late_look(vnc: FakeVnc) -> None:
    spec = DeviceSpec(id="v5", name="late", base_url=vnc.url, username="", password="secret", kind="vnc")

    async def go() -> None:
        device = VncDevice(spec)
        await device.identify()
        await device.close()
        before = vnc.state.connections
        status = await device._read_status()  # a status refresh that was under way when the device was retired
        await asyncio.sleep(0.3)
        assert vnc.state.connections == before and status["state"] != "online"
        assert device._task is None or device._task.done()

    asyncio.run(go())


def test_export_and_import_carry_a_vnc_server(tmp_path: Path, vnc: FakeVnc) -> None:
    with wall(tmp_path / "one") as client:
        reply = client.post("/api/v1/devices", json={"url": vnc.url, "password": "secret", "name": "Box"})
        assert reply.status_code == 201, reply.text
        from tests.test_wall import PASSWORD

        out = client.post("/api/v1/export", json={"password": PASSWORD, "passphrase": "carry it along", "parts": ["devices"]})
        assert out.status_code == 200, out.text
        file = out.text
    with wall(tmp_path / "two") as other:
        taken = other.post("/api/v1/import", json={"file": file, "passphrase": "carry it along", "take": ["devices"]})
        assert taken.status_code == 200, taken.text
        listed = other.get("/api/v1/wall").json()["devices"]
        assert [(d["name"], d["kind"], d["url"]) for d in listed] == [("Box", "vnc", vnc.url)]
        picture(other, listed[0]["id"])  # with its password
