"""The group names of an account's or a token's limits, as the form asks them.

`server._group_names` puts each name through `store.as_a_line` as it stands. The rule it was copied from
(`server._a_line`, for a device's group; `exchange._short`, for a file's) takes the blanks around the name
away FIRST, "a line break at its end among them, which a list of names written by a script has after every
one". So the same group, written the same way, is taken for a device and refused for an account; the build
before took it for both.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from qkvm import kvm, update, vault
from tests.test_users import OTHER, browser
from tests.test_wall import closed_port, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 2)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 2)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.mark.parametrize("written", ["Rack 1\n", "\r\nRack 1", " Rack 1 \r\n"])
def test_a_group_written_with_a_line_break_after_it_is_one_group_for_a_device_and_for_an_account(tmp_path: Path, written: str) -> None:
    with wall(tmp_path) as admin:
        device = admin.post("/api/v1/devices", json={"url": f"http://127.0.0.1:{closed_port()}", "password": "x", "force": True, "kind": "kvmd", "group": written})
        account = admin.post("/api/v1/users", json={"name": "olga", "role": "viewer", "password": OTHER, "devices": [], "groups": [written]})
        token = admin.post("/api/v1/tokens", json={"name": "a script", "devices": [], "groups": [written]})
        print(f">>> the group {written!r}: for a device {device.status_code} (kept as {device.json().get('device', {}).get('group')!r}); for an account {account.status_code}; for a token {token.status_code}")
        assert device.status_code == 201 and device.json()["device"]["group"] == "Rack 1"
        assert (account.status_code, token.status_code) == (201, 201), "what the form takes for a device's group, and the build before took for an account's, is refused for an account's"
        assert len(browser(admin, "olga").get("/api/v1/wall").json()["devices"]) == 1

