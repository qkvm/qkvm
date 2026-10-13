"""A wall handing itself out as a file, and taking one in: who may ask, what it costs to ask, what a file adds and what it never touches."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from qkvm import exchange, kvm, update, vault
from qkvm.store import Store
from tests.fake_kvm import FakeKvm
from tests.test_tokens import script as a_script
from tests.test_users import account, browser, visitor
from tests.test_wall import PASSWORD, add, wait_until, wall

PASSPHRASE = "a passphrase for the file"


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def fake() -> Iterator[FakeKvm]:
    server = FakeKvm().start()
    yield server
    server.stop()


def filled(admin: TestClient, fake: FakeKvm) -> str:
    """Put a device, two saved actions and alert settings on the wall. Returns the device's id."""
    device = add(admin, fake.url, name="Rack KVM", group="rack 1")
    assert admin.post("/api/v1/actions", json={"name": "Lock the screen", "kind": "keys", "keys": "MetaLeft,KeyL"}).status_code == 201
    assert admin.post("/api/v1/actions", json={"name": "Unlock disk", "kind": "text", "text": "THE-PASSPHRASE", "enter": True}).status_code == 201
    assert admin.put("/api/v1/alerts", json={"enabled": True, "webhook": "https://hooks.example/T0KEN", "recovered": False}).status_code == 200
    return device


def exported(admin: TestClient, passphrase: str = PASSPHRASE, parts: tuple[str, ...] = exchange.PARTS) -> Any:
    return admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": passphrase, "parts": list(parts)})


def test_a_wall_is_taken_to_another_and_its_devices_work_there(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path / "one") as admin:
        filled(admin, fake)
        reply = exported(admin)
        assert reply.status_code == 200 and reply.headers["content-disposition"].endswith('.qkvm"') and reply.headers["cache-control"] == "no-store"
        file = reply.text
        for secret in ("secret", "THE-PASSPHRASE", "T0KEN", "Rack KVM", fake.url):
            assert secret not in file
        made = [entry for entry in admin.get("/api/v1/audit").json()["entries"] if entry["event"] == "export_made"]
        assert len(made) == 1 and made[0]["encrypted"] is True and made[0]["devices"] == 1 and made[0]["user"] == "admin"
    with wall(tmp_path / "two") as admin:
        there = admin.post("/api/v1/import/read", json={"file": file, "passphrase": PASSPHRASE}).json()
        assert there["encrypted"] and there["secrets"] and there["left_out"] == []
        assert there["devices"] == [
            {"name": "Rack KVM", "host": fake.url.split("//")[1], "kind": "kvmd", "group": "rack 1", "password": True, "tls": "", "open_url": "", "new": True, "same_as": ""}
        ]
        assert [(a["name"], a["kind"], a["text"], a["enter"], a["new"]) for a in there["actions"]] == [("Lock the screen", "keys", "", False, True), ("Unlock disk", "text", "THE-PASSPHRASE", True, True)]
        assert there["alerts"] == {"enabled": True, "address": True, "host": "hooks.example", "format": "auto", "kinds": ["offline", "no_signal", "problem"]}
        assert there["wall"] == {"interval": 1.0, "update_check": True}
        assert admin.get("/api/v1/wall").json()["devices"] == []  # looking changes nothing
        asked = fake.state.logins
        taken = admin.post("/api/v1/import", json={"file": file, "passphrase": PASSPHRASE, "take": list(exchange.PARTS)})
        assert taken.status_code == 200 and taken.json() == {"devices": 1, "actions": 2, "alerts": True, "wall": True, "left_out": []}
        devices = admin.get("/api/v1/wall").json()["devices"]
        assert [(d["name"], d["url"], d["group"], d["has_password"]) for d in devices] == [("Rack KVM", fake.url, "rack 1", True)]
        device = devices[0]["id"]
        # The tile works with the password that came in the file: nobody typed it here.
        wait_until(lambda: admin.get("/api/v1/status").json()[device]["state"] == "online", "the device that was taken in never answered")
        assert fake.state.logins > asked
        typed = admin.post(f"/api/v1/devices/{device}/actions", json={"action": "custom", "custom_id": next(a["id"] for a in admin.get("/api/v1/actions").json()["actions"] if a["kind"] == "text")})
        assert typed.status_code == 200 and fake.state.actions[-1] == "type 'THE-PASSPHRASE\\n'"
        alerts = admin.get("/api/v1/alerts").json()
        assert alerts["enabled"] and alerts["has_webhook"] and alerts["recovered"] is False
        entries = admin.get("/api/v1/audit").json()["entries"]
        done = [entry for entry in entries if entry["event"] == "import_done"]
        assert len(done) == 1 and (done[0]["devices"], done[0]["actions"], done[0]["encrypted"]) == (1, 2, True)
        # ...and the device is in the log by name and address, as one that was typed in is.
        assert [(entry["device"], entry["url"], entry["note"]) for entry in entries if entry["event"] == "device_added"] == [("Rack KVM", fake.url, "from a file")]
    # And it is there after a restart, sealed with this wall's own key under ids of this wall's making.
    saved = json.loads((tmp_path / "two" / "qkvm.json").read_text(encoding="utf-8"))
    assert [d["name"] for d in saved["devices"]] == ["Rack KVM"] and saved["devices"][0]["secret"] and "secret" not in json.dumps(saved["devices"][0]["secret"])
    assert len({record["id"] for record in (*saved["devices"], *saved["actions"])}) == 3


def test_taking_a_file_in_twice_adds_nothing_twice_and_changes_nothing_that_is_here(tmp_path: Path, fake: FakeKvm) -> None:
    other = FakeKvm().start()
    try:
        with wall(tmp_path / "one") as admin:
            filled(admin, fake)
            add(admin, other.url, name="Second")
            file = exported(admin).text
        with wall(tmp_path / "two") as admin:
            mine = add(admin, fake.url, name="My own name for it", group="mine")
            assert admin.put("/api/v1/alerts", json={"enabled": False, "webhook": "https://mine.example/hook"}).status_code == 200
            there = admin.post("/api/v1/import/read", json={"file": file, "passphrase": PASSPHRASE}).json()
            assert [(d["name"], d["new"]) for d in there["devices"]] == [("Rack KVM", False), ("Second", True)]
            first = admin.post("/api/v1/import", json={"file": file, "passphrase": PASSPHRASE, "take": ["devices", "actions"]}).json()
            assert (first["devices"], first["actions"], first["alerts"], first["wall"]) == (1, 2, False, False)
            again = admin.post("/api/v1/import", json={"file": file, "passphrase": PASSPHRASE, "take": ["devices", "actions"]}).json()
            assert (again["devices"], again["actions"]) == (0, 0)
            devices = {d["id"]: d for d in admin.get("/api/v1/wall").json()["devices"]}
            assert len(devices) == 2 and (devices[mine]["name"], devices[mine]["group"]) == ("My own name for it", "mine")  # what was here is as it was
            assert len(admin.get("/api/v1/actions").json()["actions"]) == 2
            # The alert settings were not asked for, and are this wall's own still.
            assert admin.get("/api/v1/alerts").json()["enabled"] is False
            # Taken, they replace what is set; an address in the file replaces the address.
            assert admin.post("/api/v1/import", json={"file": file, "passphrase": PASSPHRASE, "take": ["alerts"]}).json()["alerts"] is True
            assert admin.get("/api/v1/alerts").json()["enabled"] is True
    finally:
        other.stop()


def test_a_plain_file_has_no_secret_in_it_and_adds_devices_that_ask_for_their_password(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path / "one") as admin:
        filled(admin, fake)
        reply = exported(admin, passphrase="")
        assert reply.status_code == 200 and reply.headers["content-disposition"].endswith('.json"')
        file = reply.text
        said = json.loads(file)
        assert "THE-PASSPHRASE" not in file and "T0KEN" not in file and "password" not in said["devices"][0] and [a["name"] for a in said["actions"]] == ["Lock the screen"]
    with wall(tmp_path / "two") as admin:
        assert admin.put("/api/v1/alerts", json={"enabled": False, "webhook": "https://mine.example/hook"}).status_code == 200
        there = admin.post("/api/v1/import/read", json={"file": file}).json()
        assert not there["encrypted"] and not there["secrets"] and there["devices"][0]["password"] is False
        assert (there["alerts"]["address"], there["alerts"]["host"]) == (False, "")
        assert admin.post("/api/v1/import", json={"file": file, "take": list(exchange.PARTS)}).json()["devices"] == 1
        device = admin.get("/api/v1/wall").json()["devices"][0]
        assert device["has_password"] is False
        wait_until(lambda: admin.get("/api/v1/status").json()[device["id"]]["state"] == "auth", "a tile without a password did not say so")
        assert admin.get("/api/v1/status").json()[device["id"]]["error"]["code"] == "no_password"
        # The file had no address for alerts: the one this wall has is kept.
        assert admin.get("/api/v1/alerts").json()["has_webhook"] is True and admin.get("/api/v1/alerts").json()["enabled"] is True


def test_who_may_ask_for_the_file_and_what_it_takes(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as admin:
        filled(admin, fake)
        account(admin, "olga", "operator")
        account(admin, "vik", "viewer")
        for name in ("olga", "vik"):
            lesser = browser(admin, name)
            assert lesser.post("/api/v1/export", json={"password": "another password!", "passphrase": PASSPHRASE, "parts": ["devices"]}).status_code == 403
            assert lesser.post("/api/v1/import/read", json={"file": "{}"}).status_code == 403
            assert lesser.post("/api/v1/import", json={"file": "{}", "take": ["devices"]}).status_code == 403
        token = admin.post("/api/v1/tokens", json={"name": "a script", "role": "operator"}).json()["token"]
        script = a_script(admin, token)
        assert script.post("/api/v1/export", json={"password": PASSWORD, "passphrase": PASSPHRASE, "parts": ["devices"]}).status_code == 403
        stranger = visitor(admin, 50041)
        assert stranger.post("/api/v1/export", json={"password": PASSWORD, "passphrase": PASSPHRASE, "parts": ["devices"]}).status_code == 401
        # An admin, and the password typed again: a session left open at somebody's desk is not enough.
        wrong = admin.post("/api/v1/export", json={"password": "not the password", "passphrase": PASSPHRASE, "parts": ["devices"]})
        assert (wrong.status_code, wrong.json()["code"]) == (401, "bad_password")
        short = exported(admin, passphrase="too short")
        assert (short.status_code, short.json()["code"]) == (422, "invalid")
        assert admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": PASSPHRASE, "parts": []}).status_code == 422
        assert admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": PASSPHRASE, "parts": ["accounts"]}).status_code == 422
        assert [entry["event"] for entry in admin.get("/api/v1/audit").json()["entries"]].count("export_made") == 0
        assert exported(admin, parts=("devices",)).status_code == 200


def test_a_file_that_does_not_open_changes_nothing_and_says_why(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path / "one") as admin:
        filled(admin, fake)
        file = exported(admin).text
    with wall(tmp_path / "two") as admin:
        for sent, code in (
            ({"file": file}, "passphrase_needed"),
            ({"file": file, "passphrase": "another passphrase"}, "wrong_passphrase"),
            ({"file": "not a file"}, "not_a_file"),
            ({"file": json.dumps({"format": exchange.FORMAT, "version": 99})}, "newer"),
        ):
            for route in ("/api/v1/import/read", "/api/v1/import"):
                reply = admin.post(route, json={**sent, "take": list(exchange.PARTS)})
                assert (reply.status_code, reply.json()["code"]) == (422, code), (route, code)
        assert admin.get("/api/v1/wall").json()["devices"] == [] and admin.get("/api/v1/actions").json()["actions"] == []
        # Larger than any such file is: refused before it is read, as every over-long request is.
        assert admin.post("/api/v1/import/read", content=b'{"file": "' + b"x" * (2 * exchange.MAX_FILE + 70_000) + b'"}', headers={"Content-Type": "application/json"}).status_code == 413
        assert admin.post("/api/v1/actions", content=b'{"name": "' + b"x" * 70_000 + b'"}', headers={"Content-Type": "application/json"}).status_code == 413  # and only for a file is more let in


def test_what_a_file_holds_that_could_not_be_saved_is_not_on_the_wall(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    with wall(tmp_path / "one") as admin:
        filled(admin, fake)
        file = exported(admin).text
    with wall(tmp_path / "two") as admin:
        assert admin.put("/api/v1/alerts", json={"enabled": False}).status_code == 200

        def full(self: Store, data: dict[str, Any]) -> None:
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(Store, "write", full)
        refused = admin.post("/api/v1/import", json={"file": file, "passphrase": PASSPHRASE, "take": list(exchange.PARTS)})
        assert (refused.status_code, refused.json()["code"]) == (507, "not_saved")
        monkeypatch.undo()
        assert admin.get("/api/v1/wall").json()["devices"] == [] and admin.get("/api/v1/status").json() == {}
        assert admin.get("/api/v1/actions").json()["actions"] == [] and admin.get("/api/v1/alerts").json()["enabled"] is False
        assert admin.get("/api/v1/settings").json()["interval"] == 1.0
        assert "import_done" not in [entry["event"] for entry in admin.get("/api/v1/audit").json()["entries"]]


def test_a_file_cannot_make_a_wall_do_what_an_admin_could_not_type(tmp_path: Path) -> None:
    hostile = {
        "format": exchange.FORMAT,
        "version": 1,
        "devices": [
            {"url": "https://192.168.1.20", "kind": "kvmd", "id": "alerts:webhook", "secret": {"nonce": "AAAA", "data": "AAAA"}, "ident": "own:deadbeef"},
            {"url": "https://user:pw@192.168.1.21", "kind": "kvmd"},
            {"url": "https://192.168.1.22", "kind": "kvmd", "open_url": "javascript:alert(1)"},
        ],
        "users": [{"id": "admin2", "name": "intruder", "role": "admin", "auth": {}}],
        "tokens": [{"id": "t", "name": "x", "role": "operator"}],
        "server": {"bind": ["all"], "require_totp": "", "allowed_hosts": ["evil.example"]},
        "recovery": {"kdf": {}, "key": {}},
        "wall": {"interval": 5, "bind": ["all"], "port": 1, "https": False},
    }
    with wall(tmp_path) as admin:
        before = admin.get("/api/v1/settings").json()
        taken = admin.post("/api/v1/import", json={"file": json.dumps(hostile), "take": list(exchange.PARTS)})
        assert taken.status_code == 200 and taken.json()["devices"] == 1 and len(taken.json()["left_out"]) == 2
        assert [u["name"] for u in admin.get("/api/v1/users").json()["users"]] == ["admin"] and admin.get("/api/v1/tokens").json()["tokens"] == []
        after = admin.get("/api/v1/settings").json()
        # (But for how long the program has run, which is a clock: a second later than "before" on a slow day.)
        same = lambda settings: {k: v for k, v in settings.items() if k not in ("interval", "uptime")}  # noqa: E731
        assert after["interval"] == 5 and same(after) == same(before)
    saved = json.loads((tmp_path / "qkvm.json").read_text(encoding="utf-8"))
    device = saved["devices"][0]
    assert device["id"] != "alerts:webhook" and len(device["id"]) == 8 and device["secret"] is None and device["ident"] == ""
    assert saved["server"]["allowed_hosts"] == [] and saved["recovery"] is not None and len(saved["users"]) == 1
