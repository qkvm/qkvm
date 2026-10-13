"""One device whose remembered certificate is damaged, and the rest of the wall is there.

The certificate remembered for a device (`cert_pem`) is read by `server.view` (its fingerprint) and
`core.identity` (its mark) every time the list of tiles is asked for, by anybody. Cut short or mistyped
in the settings file, as a hand or a disk leaves it, the wall started, the sign-in worked, and then:

* GET /api/v1/wall was a 500 for every account, at every look: no tile was drawn, of any device.
* An import, and adding a device by hand, were a 500 as well (both ask every device for its mark), so
  the way the page offers to put it right (edit the tile, look at its certificate) could not be reached
  from a page that had no tiles.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from qkvm import exchange, kvm, update, vault
from tests.test_largest_file import rsa_certificate
from tests.test_wall import PASSWORD, add, closed_port, wall

F = {"format": exchange.FORMAT, "version": 1}

DAMAGED: dict[str, Any] = {
    "cut short": lambda pem: pem[:400],
    "a letter that is no base64": lambda pem: pem[:200] + "!" + pem[201:],
    "its first line gone": lambda pem: pem.split(chr(10), 1)[1],
    "not a text": lambda pem: 5,
}


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 2)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 2)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def a_wall_with_three_devices(folder: Path) -> None:
    devices = [{"url": f"https://127.0.0.1:{closed_port()}", "kind": "kvmd", "name": f"KVM {number}", "password": "secret", "cert_pem": rsa_certificate(2048)} for number in range(3)]
    with wall(folder) as admin:
        assert admin.post("/api/v1/import", json={"file": json.dumps({**F, "devices": devices}), "take": ["devices"]}).json()["devices"] == 3


@pytest.mark.parametrize("how", list(DAMAGED))
def test_with_one_remembered_certificate_damaged_the_rest_of_the_wall_is_there(tmp_path: Path, how: str) -> None:
    a_wall_with_three_devices(tmp_path)
    saved = json.loads((tmp_path / "qkvm.json").read_text(encoding="utf-8"))
    saved["devices"][0]["cert_pem"] = DAMAGED[how](saved["devices"][0]["cert_pem"])
    (tmp_path / "qkvm.json").write_text(json.dumps(saved), encoding="utf-8")
    (tmp_path / "qkvm.bak").unlink(missing_ok=True)
    with wall(tmp_path, sign_in=False) as visitor:  # it starts,
        assert visitor.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200  # and is signed in to
        tiles = visitor.get("/api/v1/wall")
        states = visitor.get("/api/v1/status")
        more = visitor.post("/api/v1/import/read", json={"file": json.dumps({**F, "devices": [{"url": f"https://127.0.0.1:{closed_port()}", "kind": "kvmd"}]})})
        removed = visitor.delete(f"/api/v1/devices/{saved['devices'][0]['id']}")
        after = visitor.get("/api/v1/wall")
    print(f">>> one certificate {how}: /api/v1/wall {tiles.status_code}, /api/v1/status {states.status_code}, reading a file {more.status_code}; removing that device {removed.status_code}, then /api/v1/wall {after.status_code}")
    assert tiles.status_code == 200 and len(tiles.json()["devices"]) == 3, f"one damaged value of one device, and the list of tiles is answered {tiles.status_code} for all of them"


# --- fields of the settings file that hold what they cannot hold -------------------------------------------------------------


def _edited(folder: Path, change: Any) -> None:
    saved = json.loads((folder / "qkvm.json").read_text(encoding="utf-8"))
    change(saved)
    (folder / "qkvm.json").write_text(json.dumps(saved), encoding="utf-8")


@pytest.mark.parametrize(
    "what,change",
    [
        ("a device's address that is a number", lambda saved: saved["devices"][0].__setitem__("url", 7)),
        ("a device's name that is a list", lambda saved: saved["devices"][0].__setitem__("name", ["KVM"])),
        ("a pause of alerts that is a word", lambda saved: saved["alerts"].__setitem__("paused_until", "tomorrow")),
        ("allowed host names that are a number", lambda saved: saved["server"].__setitem__("allowed_hosts", 5)),
    ],
    ids=["an address that is a number", "a name that is a list", "a pause that is a word", "host names that are a number"],
)
def test_a_settings_file_with_something_else_where_a_text_or_a_number_belongs_is_not_used(tmp_path: Path, what: str, change: Any) -> None:
    # Such a file was read, the program started, and the list of tiles (or the alert settings) was an
    # error for everybody from then on. It is a file that cannot be used: the second copy is, which is what
    # was saved last, and the edited one is set aside to be looked at.
    with wall(tmp_path) as admin:
        add(admin, f"http://127.0.0.1:{closed_port()}", force=True, kind="kvmd", name="The one device")
    assert (tmp_path / "qkvm.bak").exists()
    _edited(tmp_path, change)
    with wall(tmp_path, sign_in=False) as anybody:
        assert anybody.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
        tiles = anybody.get("/api/v1/wall")
        assert tiles.status_code == 200 and [tile["name"] for tile in tiles.json()["devices"]] == ["The one device"], (what, tiles.text[:200])
        assert anybody.get("/api/v1/alerts").status_code == 200
    assert [file.name for file in tmp_path.glob("qkvm.damaged-*.json")], "the edited file was not set aside"


def test_one_allowed_host_name_written_without_its_brackets_is_that_name_and_nothing_else(tmp_path: Path) -> None:
    # The README sends people into qkvm.json for this one. Written as a text where a list of texts belongs,
    # it was looked for inside: "e.org" is in "wall.example.org", and so was every other piece of the name.
    from qkvm.security import host_allowed

    with wall(tmp_path):
        pass
    _edited(tmp_path, lambda saved: saved["server"].__setitem__("allowed_hosts", "wall.example.org"))
    with wall(tmp_path, sign_in=False) as anybody:
        allowed = anybody.core.store.server.allowed_hosts  # type: ignore[attr-defined]
        assert allowed == ["wall.example.org"]
        assert host_allowed("wall.example.org", allowed) is True
        for piece in ("e.org", "example.org", "wall.example", "all.example.org"):
            assert host_allowed(piece, allowed) is False, piece
