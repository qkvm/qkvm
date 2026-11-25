""""Open in" on a tile's menu: a machine's page on MeshCentral, its RustDesk ID, its Remote Desktop host (X1 of 0.4.0).

Plain links: an admin sets them (PUT /api/v1/devices/{id}/open-in, the page's own), operators and admins see them on the
wall, a viewer does not. No secret is stored or sent for them and the wall fetches nothing from them; each is checked
strictly where it is set and again where it is read (the settings file, an import), so that nothing else reaches a page as
a link, or an .rdp file as a line of its own. They go with the machine in an export, and come with it in an import.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from qkvm import exchange, kvm, open_in, update, vault
from tests.fake_kvm import FakeKvm
from tests.settings_file import settings_text, write_settings_text
from tests.test_users import account, browser
from tests.test_wall import PASSWORD, add, wall

LINKS = {"meshcentral": "https://mesh.example.org/?gotonode=AbCd12@$Ef&viewmode=10", "rustdesk": "123456789", "rdp": "pc-7.example.org"}


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def fake() -> Iterator[FakeKvm]:
    server = FakeKvm().start()
    yield server
    server.stop()


def links_of(client: TestClient, device: str) -> Any:
    return next(one for one in client.get("/api/v1/wall").json()["devices"] if one["id"] == device).get("open_in")


def set_links(client: TestClient, device: str, **links: str) -> Any:
    return client.put(f"/api/v1/devices/{device}/open-in", json=links)


# --- what is taken, and as what ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kind, typed, kept",
    [
        ("meshcentral", " https://Mesh.Example.org/?gotonode=AbCd12@$Ef&viewmode=10 ", "https://mesh.example.org/?gotonode=AbCd12@$Ef&viewmode=10"),
        ("meshcentral", "https://mesh.example.org:443/", "https://mesh.example.org/"),
        ("meshcentral", "https://192.168.1.5:8443/#device", "https://192.168.1.5:8443/#device"),
        ("rustdesk", "123 456 789", "123456789"),
        ("rustdesk", "office-pc_7", "office-pc_7"),
        ("rdp", "PC-7.example.org", "pc-7.example.org"),
        ("rdp", "pc7:3390", "pc7:3390"),
        ("rdp", "pc7:3389", "pc7"),
        ("rdp", "192.168.1.20", "192.168.1.20"),
        ("rdp", "[fe80::1]:3390", "[fe80::1]:3390"),
        ("rdp", "fe80::1", "[fe80::1]"),
        ("rdp", "build_box", "build_box"),
        ("rdp", "", ""),
        ("rustdesk", "   ", ""),
    ],
)
def test_a_link_is_kept_in_one_way_of_writing_it(kind: str, typed: str, kept: str) -> None:
    assert open_in.checked(kind, typed) == kept


@pytest.mark.parametrize(
    "kind, typed",
    [
        ("meshcentral", "http://mesh.example.org/"),  # https only
        ("meshcentral", "javascript:alert(1)"),
        ("meshcentral", "https://admin:secret@mesh.example.org/"),  # no user name or password in it
        ("meshcentral", "https://mesh.example.org/?login=a1b2c3"),  # nor MeshCentral's login token
        ("meshcentral", "https://mesh.example.org/?gotonode=x&PASSWORD=y"),
        ("meshcentral", "https://mesh.example.org/a b"),  # one line of printable characters
        ("meshcentral", "https://mesh.example.org/\nx"),
        ("meshcentral", "https://mesh.example.org/" + "a" * 600),
        ("meshcentral", "https://127.1/"),  # numbers that are no address as written
        ("meshcentral", "https://mesh.example.org:0/"),
        ("meshcentral", "https:///nothing"),
        ("rustdesk", "12345"),  # too short for an ID
        ("rustdesk", "rustdesk://123456789"),
        ("rustdesk", "123456789?password=x"),
        ("rustdesk", "123456789@rs.example.org"),
        ("rustdesk", "-123456789"),
        ("rustdesk", "1" * 33),
        ("rdp", "pc7\r\nalternate shell:s:cmd.exe"),  # never a second line in an .rdp file
        ("rdp", "pc7;x"),
        ("rdp", "pc 7"),
        ("rdp", "pc7:0"),
        ("rdp", "pc7:99999"),
        ("rdp", "pc7:abc"),
        ("rdp", "-pc7"),
        ("rdp", "pc7.-x"),
        ("rdp", "https://pc7"),
        ("rdp", "[fe80::1"),
        # An IPv6 zone id: Python's address takes one of any punctuation after "%", which the API and an export then hand to
        # every client as a host (review of wave 3, L2). None is taken, in brackets or without, nor in a MeshCentral host.
        ("rdp", "[fe80::1%x;y=z]:3390"),
        ("rdp", "[fe80::1%eth0]"),
        ("rdp", "fe80::1%eth0"),
        ("rdp", "fe80::1%25"),
        ("meshcentral", "https://[fe80::1%25eth0]/"),
        ("meshcentral", "https://[fe80::1%x;y=z]:8443/"),
        ("rdp", "010.1.1.1"),
        ("rdp", "a" * 64 + ".example.org"),
        ("other", "x"),
    ],
)
def test_what_is_no_such_link_is_refused(kind: str, typed: str) -> None:
    with pytest.raises(ValueError):
        open_in.checked(kind, typed)


def test_what_is_read_keeps_only_what_is_a_link() -> None:
    assert open_in.kept({"rdp": "pc7\nfull address:s:evil", "rustdesk": "123456789", "meshcentral": 5, "telnet": "x"}) == {"rustdesk": "123456789"}
    # A zone id in what was saved (a file of before this was refused, or written by hand): left out where it is read.
    assert open_in.kept({"rdp": "[fe80::1%x;y=z]:3390", "meshcentral": "https://[fe80::1%25eth0]/", "rustdesk": "123456789"}) == {"rustdesk": "123456789"}
    for nothing in (None, [], "rdp", {"rdp": None}):
        assert open_in.kept(nothing) == {}


# --- set by an admin, seen by an operator ---------------------------------------------------------------------------


def test_an_admin_sets_them_an_operator_sees_them_and_a_viewer_does_not(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as admin:
        device = add(admin, fake.url)
        assert links_of(admin, device) is None  # (none set: not in the answer at all, as before 0.4.0)
        reply = set_links(admin, device, **LINKS)
        assert (reply.status_code, reply.json()) == (200, {"ok": True, "open_in": LINKS}), reply.text
        assert links_of(admin, device) == LINKS
        account(admin, "olga", "operator")
        account(admin, "victor", "viewer")
        olga, victor = browser(admin, "olga"), browser(admin, "victor", port=50002)
        assert links_of(olga, device) == LINKS
        assert links_of(victor, device) is None
        # Only an admin sets them.
        for who in (olga, victor):
            assert set_links(who, device, rdp="elsewhere").status_code == 403
        assert links_of(admin, device) == LINKS
        # In the activity log: who, which machine, and what they are now.
        entry = admin.get("/api/v1/audit?q=open_in_changed").json()["entries"][0]
        assert (entry["event"], entry["device_id"], entry["user"], entry["open_in"]) == ("open_in_changed", device, "admin", LINKS), entry
        # Left out, or empty: none of that kind.
        assert set_links(admin, device, rustdesk="").json()["open_in"] == {}
        assert links_of(admin, device) is None


def test_one_that_is_no_link_is_refused_and_nothing_is_changed(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as admin:
        device = add(admin, fake.url)
        assert set_links(admin, device, rdp="pc7").status_code == 200
        reply = set_links(admin, device, rdp="pc8", meshcentral="http://mesh.example.org/")
        assert (reply.status_code, reply.json()["code"]) == (422, "invalid"), reply.text
        assert "MeshCentral" in reply.json()["message"] and "https://" in reply.json()["message"]
        reply = set_links(admin, device, rdp="pc8\r\nalternate shell:s:cmd.exe")
        assert (reply.status_code, reply.json()["code"]) == (422, "invalid") and "Remote Desktop" in reply.json()["message"]
        assert set_links(admin, device, telnet="pc8").status_code == 422  # (a kind this version does not know)
        assert set_links(admin, device, rdp=["pc8"]).status_code == 422  # type: ignore[arg-type]
        assert links_of(admin, device) == {"rdp": "pc7"}
        assert set_links(admin, "nope", rdp="pc8").status_code == 404


def test_they_are_kept_with_the_machine_and_what_a_hand_put_in_the_file_is_checked_again(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as admin:
        device = add(admin, fake.url)
        assert set_links(admin, device, **LINKS).status_code == 200
    settings = tmp_path / "qkvm.json"
    said = json.loads(settings_text(settings))
    assert said["devices"][0]["open_in"] == LINKS
    with wall(tmp_path) as admin:
        assert links_of(admin, device) == LINKS
    # Written by hand, a line after the host: not handed to any page, nor into an .rdp file.
    said["devices"][0]["open_in"] = {**LINKS, "rdp": "pc7\r\nalternate shell:s:cmd.exe"}
    write_settings_text(settings, json.dumps(said))
    with wall(tmp_path) as admin:
        assert links_of(admin, device) == {"meshcentral": LINKS["meshcentral"], "rustdesk": LINKS["rustdesk"]}


def test_they_go_with_the_machine_in_an_export_and_come_with_it_in_an_import(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path / "one") as admin:
        device = add(admin, fake.url)
        assert set_links(admin, device, **LINKS).status_code == 200
        reply = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": "", "parts": ["devices"]})
        file = reply.text
    assert json.loads(file)["devices"][0]["open_in"] == LINKS
    with wall(tmp_path / "two") as admin:
        assert admin.post("/api/v1/import", json={"file": file, "take": ["devices"]}).json()["devices"] == 1
        there = admin.get("/api/v1/wall").json()["devices"][0]
        assert there["open_in"] == LINKS
    # A file whose link is none: the machine is left out, and said why, as for anything else of it that is not what it says.
    entry = json.loads(file)["devices"][0]
    hostile = json.dumps({**json.loads(file), "devices": [{**entry, "open_in": {"rdp": "pc7\nalternate shell:s:cmd.exe"}}]})
    with wall(tmp_path / "three") as admin:
        answer = admin.post("/api/v1/import", json={"file": hostile, "take": ["devices"]}).json()
        assert answer["devices"] == 0 and "Remote Desktop" in " ".join(answer["left_out"]), answer
    # A file of a version before 0.4.0 has none: taken in without.
    older = json.dumps({**json.loads(file), "devices": [{key: value for key, value in entry.items() if key != "open_in"}]})
    with wall(tmp_path / "four") as admin:
        assert admin.post("/api/v1/import", json={"file": older, "take": ["devices"]}).json()["devices"] == 1
        assert admin.get("/api/v1/wall").json()["devices"][0].get("open_in") is None


def test_exchange_reads_a_files_links_as_the_route_does() -> None:
    entry = {"url": "https://127.0.0.1:9", "kind": "kvmd", "open_in": {"rdp": "PC7:3389", "rustdesk": "123 456 789"}}
    left_out: list[str] = []
    devices = exchange._devices([entry], left_out)
    assert left_out == [] and devices[0].open_in == {"rustdesk": "123456789", "rdp": "pc7"}
    # One with a zone id in its host: the machine is left out of the import, and said why.
    entry = {**entry, "open_in": {"rdp": "[fe80::1%x;y=z]:3390"}}
    assert exchange._devices([entry], left_out) == [] and "Remote Desktop" in left_out[0], left_out
