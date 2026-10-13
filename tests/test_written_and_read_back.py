"""What a wall writes into a file, it reads back from it: names, and how many.

* A name. The form and a file have one rule for the name of a device or a saved action (`store.as_a_line`).
  A file was held to "printable", which to Python leaves out every blank but the plain one (the no-break
  space French and German typing puts before a unit or after "No.", the wide blank of Japanese and Chinese
  text) and the joiner inside one emoji in three (a person at a computer, a flag). Such a device was
  written into the file and left out when the file was read, its password with it; from a sealed file,
  which nobody can edit, there was no way to it.
* A count. A wall may have any number of devices; a file is read up to exchange.MOST_DEVICES of them, and
  is not written with more.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from qkvm import exchange, kvm, update, vault
from qkvm.store import as_a_line
from tests.test_wall import PASSWORD, add, closed_port, wall

PASSPHRASE = "a passphrase for the file"

NAMES = {
    # (Written by their numbers: three of the four cannot be seen in a line of source.)
    "a no-break space": "Serveur n" + chr(0xB0) + chr(0xA0) + "3",  # as it is typed in French, and pasted from anywhere
    "the wide blank of Japanese text": chr(0x6771) + chr(0x4EAC) + chr(0x3000) + "KVM",
    "an emoji that is two joined": "Build box " + chr(0x1F468) + chr(0x200D) + chr(0x1F4BB),  # man technologist: man, joiner, computer
    "a mark that says which way text runs": chr(0x5E9) + chr(0x5E8) + chr(0x5EA) + " " + chr(0x200F) + "KVM",  # Hebrew, with the mark a keyboard puts after it
}


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.mark.parametrize("what", list(NAMES))
@pytest.mark.parametrize("passphrase", ["", PASSPHRASE], ids=["plain", "sealed"])
def test_a_device_whose_name_the_wall_took_is_read_back_from_the_walls_own_file(tmp_path: Path, what: str, passphrase: str) -> None:
    name = NAMES[what]
    with wall(tmp_path / "one") as admin:
        device = add(admin, f"http://127.0.0.1:{closed_port()}", force=True, name=name)
        assert next(tile["name"] for tile in admin.get("/api/v1/wall").json()["devices"] if tile["id"] == device) == name, "the wall did not take the name as typed"
        assert admin.post("/api/v1/actions", json={"name": name, "kind": "keys", "keys": "MetaLeft,KeyL"}).status_code == 201
        made = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": passphrase, "parts": ["devices", "actions"]})
        assert made.status_code == 200
    with wall(tmp_path / "two") as other:
        there = other.post("/api/v1/import/read", json={"file": made.text, "passphrase": passphrase}).json()
        print(f">>> {what} ({name!a}): devices read {len(there['devices'])} of 1, actions read {len(there['actions'])} of 1; left out: {there['left_out']}")
        assert [entry["name"] for entry in there["devices"]] == [name], f"the wall's own file was read without the device: {there['left_out']}"
        assert [entry["name"] for entry in there["actions"]] == [name], f"the wall's own file was read without the saved action: {there['left_out']}"


def test_a_wall_with_more_devices_than_a_file_is_read_for_is_told_so_when_it_writes_one(tmp_path: Path) -> None:
    # exchange.pack refuses to write what is too long to be read back. What is too many to be read back is
    # written, and the day it is needed the file is read without its end.
    from qkvm.store import DeviceRecord

    with wall(tmp_path / "one") as admin:
        store = admin.core.store  # type: ignore[attr-defined]
        store.devices.extend(DeviceRecord(id=f"{number:08x}", name=f"KVM {number}", url=f"http://192.168.{number // 250}.{number % 250 + 1}", kind="jetkvm") for number in range(exchange.MOST_DEVICES + 5))
        made = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": "", "parts": ["devices"]})
    wrote = made.status_code == 200
    read = exchange.unpack(made.text, "") if wrote else None
    print(f">>> a wall of {exchange.MOST_DEVICES + 5} devices: export answered {made.status_code}, {len(made.content)} bytes; read back: {len(read.devices or []) if read else '-'} devices; left out: {read.left_out if read else '-'}")
    assert not wrote or (read is not None and len(read.devices or []) == exchange.MOST_DEVICES + 5), "a file was written that is read back without its last devices"


# What is no name, for the form and for a file alike: what ends a line or moves the cursor, half a
# character, and what turns round the direction of the text after it.
NO_NAMES = {
    "a line break": "Rack" + chr(10) + "KVM",
    "a character that ends nothing and shows nothing": "Rack" + chr(0) + "KVM",
    "a line separator": "Rack" + chr(0x2028) + "KVM",
    "a turn of direction": "Rack " + chr(0x202E) + "MVK",
    "an isolate": "Rack " + chr(0x2066) + "KVM" + chr(0x2069),
}


@pytest.mark.parametrize("what", list(NO_NAMES))
def test_what_is_no_name_is_none_for_the_form_and_for_a_file(tmp_path: Path, what: str) -> None:
    name = NO_NAMES[what]
    assert as_a_line(name) is None and as_a_line("Rack KVM") == "Rack KVM"
    with wall(tmp_path) as admin:
        typed = admin.post("/api/v1/devices", json={"url": "https://192.168.1.20", "name": name, "password": "secret", "force": True})
        assert typed.status_code == 422, typed.text
        assert name not in typed.text  # (the rule is named, never what was typed)
        action = admin.post("/api/v1/actions", json={"name": name, "kind": "keys", "keys": "KeyA"})
        assert action.status_code == 422, action.text
        file = json.dumps({"format": exchange.FORMAT, "version": 1, "devices": [{"url": "https://192.168.1.21", "kind": "kvmd", "name": name}]})
        seen = admin.post("/api/v1/import/read", json={"file": file}).json()
        assert seen["devices"] == [] and len(seen["left_out"]) == 1, seen
        assert admin.get("/api/v1/wall").json()["devices"] == []
