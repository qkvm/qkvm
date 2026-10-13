"""Four more things that could be undone without another test failing; each of these fails then.

* The rule for a line is asked of a device's user name and group too: with the rule left on the name
  alone, no test failed.
* A file is not written with more saved actions than a file is read for (`exchange.pack`): with only
  the devices counted, no test failed.
* The names an export's log line holds go through `kvm.plain`, twenty of them at the most: written as
  they are, no test failed.
* Every character that makes a text no line, and every one that is left out of it, by itself.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from qkvm import exchange, kvm, update, vault
from qkvm.store import ActionRecord, as_a_line
from tests.test_wall import PASSWORD, closed_port, wall

PASSPHRASE = "a passphrase for the file"


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.mark.parametrize("field", ["username", "group"])
def test_a_user_name_and_a_group_are_held_to_the_rule_for_a_line(tmp_path: Path, field: str) -> None:
    with wall(tmp_path) as admin:
        body = {"url": f"http://127.0.0.1:{closed_port()}", "kind": "kvmd", "password": "secret", "force": True, field: "Rack" + chr(0x202E) + "KVM"}
        refused = admin.post("/api/v1/devices", json=body)
        assert refused.status_code == 422 and refused.json()["message"].startswith(f"{field}:"), refused.text
        assert admin.get("/api/v1/wall").json()["devices"] == []


@pytest.mark.parametrize("number", [0x2028, 0x2029, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x85, 0x7F, 0x0A, 0x00])
def test_each_character_that_makes_it_no_line(number: int) -> None:
    assert as_a_line("Rack" + chr(number) + "KVM") is None, hex(number)


@pytest.mark.parametrize("number", [0x200B, 0x2060, 0xFEFF])
def test_each_blank_of_no_width_is_gone_without_a_word(number: int) -> None:
    assert as_a_line("Rack" + chr(number) + "KVM") == "RackKVM", hex(number)
    assert as_a_line("Rack" + chr(9) + "KVM") == "Rack KVM"  # and a tab is a blank


def test_a_wall_with_more_saved_actions_than_a_file_is_read_for_is_told_so_when_it_writes_one(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        store = admin.core.store  # type: ignore[attr-defined]
        store.actions.extend(ActionRecord(id=f"{number:08x}", name=f"Action {number}", kind="keys", keys="KeyA") for number in range(exchange.MOST_ACTIONS + 5))
        made = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": "", "parts": ["actions"]})
    wrote = made.status_code == 200
    read = exchange.unpack(made.text, "") if wrote else None
    assert not wrote or (read is not None and len(read.actions or []) == exchange.MOST_ACTIONS + 5), "a file was written that is read back without its last saved actions"


class Heard(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage())


def test_the_names_in_an_exports_log_line_are_a_line_and_not_all_of_them(tmp_path: Path) -> None:
    # (A name with a line break in it is not taken by the form or from a file any more. One that is in a
    # settings file already, or was put there by hand, is read as it stands.)
    heard = Heard()
    logging.getLogger("qkvm").addHandler(heard)
    try:
        with wall(tmp_path) as admin:
            store, core = admin.core.store, admin.core  # type: ignore[attr-defined]
            from qkvm.store import DeviceRecord

            for number in range(40):
                name = f"KVM {number}" + (chr(10) + "2026-10-11 00:00:00,000 ERROR   qkvm: a line that nobody wrote" if number == 0 else "")
                record = DeviceRecord(id=f"{number:08x}", name=name, url=f"http://127.0.0.1:{10000 + number}", kind="jetkvm")
                record.secret = {"nonce": "!", "data": core.vault.encrypt("secret", record.id)["data"]}
                store.devices.append(record)
            made = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": PASSPHRASE, "parts": ["devices"]})
            assert made.status_code == 200 and made.headers["x-qkvm-not-opened"] == "40"
    finally:
        logging.getLogger("qkvm").removeHandler(heard)
    told = [line for line in heard.lines if "does not open any more (40)" in line]
    assert len(told) == 1, heard.lines
    assert chr(10) not in told[0], "a name made a second line in the log"
    assert "KVM 19" in told[0] and "KVM 20" not in told[0], "more names than twenty in one line"
