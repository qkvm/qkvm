"""Names a person types or pastes: a blank of no width or a tab in one is no reason to refuse it.

* Khmer is written without blanks between words, and its keyboard gives U+200B for the space bar: it is
  how the words of a Khmer name are told apart for breaking a line.
* Text copied from a chat program or a web page ends in one, or begins with U+FEFF, more often than
  anybody sees; a name copied out of a table brings its tab along.

The form takes such a name and keeps it without what is not seen (as the blanks around a name are left
out), a file is read the same way, and so the wall's own file is read back with the device.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from qkvm import kvm, update, vault
from tests.test_wall import PASSWORD, closed_port, wall

NAMES = {
    "Khmer, as its keyboard types it (U+200B between the words)": chr(0x1798) + chr(0x17C9) + chr(0x17B6) + chr(0x179F) + chr(0x17CA) + chr(0x17B8) + chr(0x1793) + chr(0x200B) + chr(0x1798) + chr(0x17C1),
    "pasted from a chat, with a blank of no width at its end": "Build server" + chr(0x200B),
    "pasted from a file, with the mark a file begins with": chr(0xFEFF) + "Build server",
}


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.mark.parametrize("what", list(NAMES))
def test_a_name_a_person_types_or_pastes_is_taken_and_read_back(tmp_path: Path, what: str) -> None:
    name = NAMES[what]
    with wall(tmp_path / "one") as admin:
        typed = admin.post("/api/v1/devices", json={"url": f"http://127.0.0.1:{closed_port()}", "kind": "kvmd", "name": name, "password": "secret", "force": True})
        print(f">>> {what}: the form answers {typed.status_code} {typed.json().get('message', '')!r}")
        assert typed.status_code == 201, f"refused, and not told what is wrong with it: {typed.json()['message']}"
        kept = typed.json()["device"]["name"]
        made = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": "", "parts": ["devices"]})
    with wall(tmp_path / "two") as other:
        there = other.post("/api/v1/import/read", json={"file": made.text}).json()
    assert [entry["name"] for entry in there["devices"]] == [kept], there["left_out"]
