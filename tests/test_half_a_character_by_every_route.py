"""What the guard (test_every_route_then_a_restart.py) does not send.

The check at a start refuses a text that cannot be written as UTF-8 (half a character, which
JSON spells "\\ud800"). The guard drives every changing route with ordinary values and odd numbers; it sends
half a character to none of them. Here every text a changing route takes is sent with half a character in
it, one at a time, and after each the settings file as it lies on disk is read by `Store` by itself, as a
start reads it. A form may refuse the value (422) or take it apart; what it may not do is save something a
start refuses, in both copies.

What a device says of itself is asked too: what the program keeps of words with half a character in them, and
a stand-in KVM whose host name is a line break and a direction mark.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from qkvm import exchange, kvm, update, vault
from qkvm.core import Core
from qkvm.store import Store, StoreError
from tests.fake_kvm import FakeKvm, FakeState
from tests.fake_redfish import FakeBmc
from tests.test_wall import PASSWORD, add, closed_port, wall

HALF = "\\ud800"  # as JSON spells half a character out
F = {"format": exchange.FORMAT, "version": 1}


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 5)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 5)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")
    monkeypatch.setattr(Core, "request_restart", lambda self: None)  # (the listeners of a test are not reopened)


def read_alone(folder: Path, scratch: Path) -> str | None:
    """What a start says of the settings file as it lies there, by itself; None where it reads it."""
    shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir()
    shutil.copy2(folder / "qkvm.json", scratch / "qkvm.json")
    try:
        assert Store(scratch / "qkvm.json").restored is False
    except StoreError as ex:
        said = str(ex)
        return said[said.index("cannot be read") :][:150]
    return None


def test_half_a_character_sent_to_every_text_a_changing_route_takes(tmp_path: Path) -> None:
    folder = tmp_path / "data"
    live = FakeKvm(FakeState(hostname="rack-3 kvm")).start()
    try:
        with wall(folder) as admin:
            port = admin.core.store.server.port  # type: ignore[attr-defined]
            device = add(admin, live.url, name="Live", group="Rack 1")
            other = add(admin, f"http://127.0.0.1:{closed_port()}", force=True, kind="kvmd", name="Down")
            olga = admin.post("/api/v1/users", json={"name": "olga", "role": "viewer", "password": "another long password", "devices": [device]}).json()["user"]["id"]
            lock = admin.post("/api/v1/actions", json={"name": "Lock", "kind": "keys", "keys": "MetaLeft,KeyL"}).json()["action"]["id"]
            url = f'"http://127.0.0.1:{closed_port()}"'
            file = {**F, "devices": [{"url": "https://kvm.invalid", "kind": "kvmd", "name": "HALF", "group": "g", "username": "u", "open_url": "https://console.invalid/x", "ident": "sn:" + "ab" * 16}],
                    "actions": [{"name": "A HALF", "kind": "keys", "keys": "F1"}], "alerts": {"format": "HALF"}, "wall": {"interval": 2}}  # fmt: skip
            sent: list[tuple[str, str, str, str]] = [
                # (what, method, path, the body as JSON text)
                ("a device's name", "POST", "/api/v1/devices", f'{{"url": {url}, "password": "x", "force": true, "kind": "kvmd", "name": "a {HALF} b"}}'),
                ("a device's group", "POST", "/api/v1/devices", f'{{"url": {url}, "password": "x", "force": true, "kind": "kvmd", "group": "{HALF}"}}'),
                ("a device's user name", "POST", "/api/v1/devices", f'{{"url": {url}, "password": "x", "force": true, "kind": "kvmd", "username": "ad{HALF}min"}}'),
                ("a device's console link", "POST", "/api/v1/devices", f'{{"url": {url}, "password": "x", "force": true, "kind": "kvmd", "open_url": "https://console.invalid/{HALF}"}}'),
                ("a device's address", "POST", "/api/v1/devices", f'{{"url": "http://127.0.0.1{HALF}:9", "password": "x", "force": true, "kind": "kvmd"}}'),
                ("a device's password", "POST", "/api/v1/devices", f'{{"url": {url}, "password": "{HALF}", "force": true, "kind": "kvmd"}}'),
                ("an edit of a device's name", "PUT", f"/api/v1/devices/{other}", f'{{"url": "{live.url}0", "name": "{HALF}", "force": true}}'),
                ("an account's name", "POST", "/api/v1/users", f'{{"name": "mal{HALF}", "role": "viewer", "password": "another long password"}}'),
                ("an account's devices", "POST", "/api/v1/users", f'{{"name": "mallory", "role": "viewer", "password": "another long password", "devices": ["{HALF}", "{device}"]}}'),
                ("an account's groups", "POST", "/api/v1/users", f'{{"name": "mallory2", "role": "viewer", "password": "another long password", "devices": [], "groups": ["{HALF}"]}}'),
                ("an account's password", "POST", "/api/v1/users", f'{{"name": "mallory3", "role": "viewer", "password": "another long {HALF} password"}}'),
                ("an edit of an account's groups", "PUT", f"/api/v1/users/{olga}", f'{{"name": "olga", "role": "viewer", "devices": [], "groups": ["Rack 1", "{HALF}"]}}'),
                ("a token's name", "POST", "/api/v1/tokens", f'{{"name": "a {HALF} script"}}'),
                ("a token's devices", "POST", "/api/v1/tokens", f'{{"name": "a script", "devices": ["{HALF}"]}}'),
                ("a token's groups", "POST", "/api/v1/tokens", f'{{"name": "a script 2", "devices": [], "groups": ["{HALF}"]}}'),
                ("a saved action's name", "POST", "/api/v1/actions", f'{{"name": "Lo{HALF}ck", "kind": "keys", "keys": "F1"}}'),
                ("a saved action's keys", "POST", "/api/v1/actions", f'{{"name": "Keys", "kind": "keys", "keys": "F1,{HALF}"}}'),
                ("a saved action's text", "POST", "/api/v1/actions", f'{{"name": "Text", "kind": "text", "text": "hunter{HALF}2"}}'),
                ("an edit of a saved action", "PUT", f"/api/v1/actions/{lock}", f'{{"name": "{HALF}", "kind": "keys", "keys": "F1"}}'),
                ("the alert address", "PUT", "/api/v1/alerts", f'{{"enabled": true, "webhook": "http://127.0.0.1:9/{HALF}"}}'),
                ("the link in alerts", "PUT", "/api/v1/alerts", f'{{"enabled": true, "link": "http://127.0.0.1:9/{HALF}"}}'),
                ("the order of the tiles", "PUT", "/api/v1/wall/order", f'{{"ids": ["{HALF}", "{device}"]}}'),
                ("the machines to remove at once", "POST", "/api/v1/devices/remove", f'{{"ids": ["{HALF}", "{other}"]}}'),
                ("where the wall listens: a name", "PUT", "/api/v1/settings", f'{{"bind": ["lo{HALF}cal"], "port": {port}, "https": false, "interval": 1}}'),
                ("where the wall listens: an address with a zone", "PUT", "/api/v1/settings", f'{{"bind": ["fe80::1%{HALF}"], "port": {port}, "https": false, "interval": 1}}'),
                ("who has to have a second step", "PUT", "/api/v1/security", f'{{"require_totp": "{HALF}"}}'),
                ("a file: a device's name", "POST", "/api/v1/import", json.dumps({"file": json.dumps(file).replace("HALF", HALF), "take": list(exchange.PARTS)})),
                ("a new password of one's own", "POST", "/api/v1/password", f'{{"current": "{PASSWORD}", "new": "a brand new {HALF} password"}}'),
            ]
            refused: list[str] = []
            for what, method, path, body in sent:
                try:
                    reply = admin.request(method, path, content=body.encode("ascii"), headers={"Content-Type": "application/json"})
                    answer = str(reply.status_code)
                except Exception as ex:  # (the test's client hands on what the program did not catch)
                    answer = f"raised {type(ex).__name__}"
                said = read_alone(folder, tmp_path / "alone")
                print(f">>> half a character in {what}: answered {answer}; the file as it lies there: {'READ' if said is None else 'REFUSED AT THE NEXT START: ' + said}")
                if said is not None:
                    refused.append(f"{what} (answered {answer}): {said}")
                    # (Put right by hand, as its owner would have to, so that the routes after it are asked as well.)
                    store = admin.core.store  # type: ignore[attr-defined]
                    store.server.bind = [name for name in store.server.bind if name.isascii()]
                    for user in store.users:
                        user.groups = [group for group in user.groups if group.isascii()]
                    store.save()
            assert not refused, "saved by the program, and refused by its own start:\n" + "\n".join(refused)
    finally:
        live.stop()


def test_what_a_device_says_of_itself_is_a_text_a_start_takes() -> None:
    # A tile added without a name is named by the device, and a server is known by the number it gives.
    # A device's JSON can spell half a character out; what the program keeps of it (kvm.plain, redfish.named,
    # redfish.own_number) is asked here directly, because the stand-in devices cannot send one.
    from qkvm import redfish, store

    said = json.loads('{"hostname": "rack\\ud800 3", "HostName": "\\ud800 bmc \\udfff", "UUID": "1234\\ud800-0000"}')
    kept = [kvm.plain(said["hostname"]), redfish.named(said["HostName"]), redfish.own_number(said)]
    print(f">>> of a device's words with half a character in them, kept: {kept!r}")
    assert all(text is None or store._a_text(text) for text in kept), kept


@pytest.mark.parametrize("hostname", ["a\nb" + chr(0x202E) + "c", 12345, ["x"], None])
def test_a_device_names_itself_oddly(tmp_path: Path, hostname: Any) -> None:
    # (The stand-ins as they are: a line break and a direction mark, a number, a list, nothing.)
    device = FakeKvm(FakeState(hostname=hostname)).start()
    bmc = FakeBmc(tls_dir=tmp_path / "bmc").start()
    try:
        bmc.state.hostname = hostname if hasattr(bmc.state, "hostname") else None  # type: ignore[attr-defined]
        with wall(tmp_path / "data") as admin:
            add(admin, device.url)
            admin.post("/api/v1/devices", json={"url": bmc.url, "username": "admin", "password": bmc.state.password})
            names = [tile["name"] for tile in admin.get("/api/v1/wall").json()["devices"]]
        said = read_alone(tmp_path / "data", tmp_path / "alone")
        print(f">>> a device that calls itself {hostname!r}: its tile is called {names!r}; the file: {'read' if said is None else said}")
        assert said is None, said
    finally:
        device.stop()
        bmc.stop()
