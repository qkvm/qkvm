"""A name as a line, where a file's reader asks and where the form does.

* A file's reader takes the blanks around a name away first and then asks whether it is a line. Asked
  first, a line break at the end of a name was no blank: an entry whose name, user name or group ended
  in one (a file put together by a script that read its names from a list, a line each) was left out.
  A saved action with such a name was left out as having "no name".
* The form counts a name's length once the blanks of no width are taken out of it, as a file does:
  eighty letters with five such blanks between them are a name to both.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from qkvm import exchange, kvm, update, vault
from tests.test_wall import closed_port, wall

F = {"format": exchange.FORMAT, "version": 1}
BREAKS = {"a line feed after it": "{}\n", "a carriage return and a line feed after it": "{}\r\n", "a line feed before it": "\n{}"}


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.mark.parametrize("how", list(BREAKS))
@pytest.mark.parametrize("field", ["name", "username", "group"])
def test_a_line_break_around_a_name_in_a_file_is_a_blank_around_it(field: str, how: str) -> None:
    entry = {"url": "https://192.168.1.20", "kind": "kvmd", field: BREAKS[how].format("Rack 1")}
    read = exchange.unpack(json.dumps({**F, "devices": [entry]}), "")
    print(f">>> a device whose {field} has {how}: taken {len(read.devices or [])} of 1; {read.left_out}")
    assert [getattr(device, field) for device in read.devices or []] == ["Rack 1"], read.left_out


def test_a_saved_action_whose_name_ends_in_a_line_break_has_a_name() -> None:
    read = exchange.unpack(json.dumps({**F, "actions": [{"name": "Lock the screen\n", "kind": "keys", "keys": "MetaLeft,KeyL"}]}), "")
    print(f">>> a saved action whose name ends in a line feed: {[action.name for action in read.actions or []]}; {read.left_out}")
    assert [action.name for action in read.actions or []] == ["Lock the screen"], read.left_out


def test_a_name_is_as_long_for_the_form_as_it_is_for_a_file(tmp_path: Path) -> None:
    name = ("abcdefghij" + chr(0x200B)) * 5 + "k" * 30  # eighty letters; a blank of no width after every tenth of the first fifty
    read = exchange.unpack(json.dumps({**F, "devices": [{"url": "https://192.168.1.20", "kind": "kvmd", "name": name}]}), "")
    with wall(tmp_path) as admin:
        typed = admin.post("/api/v1/devices", json={"url": f"http://127.0.0.1:{closed_port()}", "kind": "kvmd", "name": name, "password": "secret", "force": True})
    print(f">>> eighty letters with five blanks of no width: a file: {'taken, ' + str(len(read.devices[0].name)) + ' characters' if read.devices else read.left_out}; the form: {typed.status_code} {typed.json().get('message', '')[:70]}")
    assert bool(read.devices) == (typed.status_code == 201), "the form and a file do not go by one rule for how long a name may be"
