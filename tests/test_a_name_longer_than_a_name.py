"""No name is saved that is longer than a name may be: not by a file either.

The form counts a name as it is kept (80 for a device), and where it names a device by its address it
cuts the address to 80. A file did not: an entry without a name was named by its address, whole, and an
address may have 255 characters. Such a tile was then

* left out of the wall's own export when that was read back (a name of more than 80 is "not a short line"),
* refused by the form at every edit that left the name as it was.

(No address here is one anything answers at: a name under .invalid, and nothing connects to a device that
came from a file. The edit is asked of the form's own check, not sent.)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from qkvm import exchange, kvm, update, vault
from qkvm.server import DeviceIn
from tests.test_wall import PASSWORD, wall

F = {"format": exchange.FORMAT, "version": 1}
# A name as a DNS would carry it: labels of at most 63, 253 in all. More than 80 characters, and a port.
LONG = "kvm-07.rack-12.row-c.hall-2.frankfurt-1.datacentres.emea.infrastructure.holdings-international.invalid"


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 2)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 2)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def test_a_device_from_a_file_is_not_named_longer_than_a_name_may_be(tmp_path: Path) -> None:
    assert len(LONG) > 80 and all(len(label) <= 63 for label in LONG.split("."))
    file = json.dumps({**F, "devices": [{"url": f"http://{LONG}:8080", "kind": "kvmd"}]})
    with wall(tmp_path) as admin:
        assert admin.post("/api/v1/import", json={"file": file, "take": ["devices"]}).json()["devices"] == 1
        tile = admin.get("/api/v1/wall").json()["devices"][0]
    try:
        DeviceIn(url=tile["url"], name=tile["name"], group="Rack 1")  # what the page sends for an edit that gives it a group
        edit = "taken"
    except ValidationError as ex:
        edit = f"refused ({ex.errors()[0]['msg']})"
    print(f">>> named by the file's reader: {len(tile['name'])} characters; an edit by the form that leaves the name as it is: {edit}")
    assert len(tile["name"]) <= 80, f"a device is on the wall under a name of {len(tile['name'])} characters; the form's limit, and the file reader's, is 80"


def test_what_a_wall_holds_after_a_file_it_reads_back_from_its_own_export(tmp_path: Path) -> None:
    file = json.dumps({**F, "devices": [{"url": f"http://{LONG}:8080", "kind": "kvmd"}]})
    with wall(tmp_path) as admin:
        assert admin.post("/api/v1/import", json={"file": file, "take": ["devices"]}).json()["devices"] == 1
        again = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": "", "parts": ["devices"]}).text
    back = exchange.unpack(again, "")
    print(f">>> the wall's own export, read back: {len(back.devices or [])} of 1 device; left out: {back.left_out}")
    assert len(back.devices or []) == 1, f"the wall wrote a device into its file that it does not read back: {back.left_out}"
