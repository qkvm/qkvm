"""Five more things that could be undone without another test failing; each of these fails then.

* The certificate dialog of a tile whose remembered certificate is damaged (`GET
  /api/v1/devices/{id}/certificate`): with `fingerprint(...)` in it, it was an error, and that dialog is
  the page's one way to put the certificate right.
* `allowed_hosts` that is a list with something in it that is no text.
* `paused_until` that is `true`.
* Where the second step's key does not open, a guess is counted against the account, and against the
  address: either of the two could be taken out alone (forty guesses from one address are answered 429
  by whichever count is left).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from qkvm import kvm, update, vault
from qkvm.store import Store, StoreError
from tests.fake_kvm import FakeKvm
from tests.test_totp import switch_on
from tests.test_wall import CSRF, PASSWORD, add, closed_port, snap, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def test_the_certificate_dialog_of_a_tile_whose_certificate_is_damaged_is_the_way_out(tmp_path: Path) -> None:
    device = FakeKvm(tls_dir=tmp_path / "device").start()
    try:
        with wall(tmp_path / "wall") as admin:
            tile = add(admin, device.url, name="Build server")
            real = admin.get("/api/v1/wall").json()["devices"][0]["fingerprint"]
        saved = json.loads((tmp_path / "wall" / "qkvm.json").read_text(encoding="utf-8"))
        saved["devices"][0]["cert_pem"] = saved["devices"][0]["cert_pem"][:400]  # cut short
        (tmp_path / "wall" / "qkvm.json").write_text(json.dumps(saved), encoding="utf-8")
        (tmp_path / "wall" / "qkvm.bak").unlink()
        before = device.state.logins
        with wall(tmp_path / "wall") as admin:
            asked = admin.get(f"/api/v1/devices/{tile}/certificate")
            assert asked.status_code == 200 and asked.json() == {"saved": None, "presented": real}, asked.text
            assert device.state.logins == before  # (nothing was sent to it on the strength of a certificate that is none)
            assert admin.post(f"/api/v1/devices/{tile}/trust", json={"fingerprint": real}).status_code == 200
            assert admin.get(snap(tile)).status_code == 200
    finally:
        device.stop()


def a_second_step_that_does_not_open(admin: TestClient) -> None:
    switch_on(admin, PASSWORD)
    user = admin.core.store.users[0]  # type: ignore[attr-defined]
    user.totp = {"nonce": "!", "data": user.totp["data"]}


def guess(admin: TestClient, address: str, **body: str) -> tuple[int, str]:
    caller = TestClient(admin.app, headers=CSRF, client=(address, 50060))
    caller.portal = admin.portal
    reply = caller.post("/api/v1/login", json=body)
    return reply.status_code, reply.json()["code"]


def test_where_the_second_step_does_not_open_guesses_from_many_addresses_hold_the_account(tmp_path: Path) -> None:
    # (test_second_step_that_does_not_open makes its forty guesses from one address: they are answered 429
    # whether it is the address or the account that is counted, and either count alone could be taken out.)
    with wall(tmp_path) as admin:
        a_second_step_that_does_not_open(admin)
        assert [guess(admin, f"198.51.100.{n}", password=PASSWORD, code="00000-00000") for n in range(1, 6)] == [(409, "no_second_step")] * 5
        held = guess(admin, "198.51.100.77", password=PASSWORD, code="00000-00000")
        assert held[0] == 429, f"five guesses at the one-time codes from five addresses, and the sixth address is answered {held}"


def test_where_the_second_step_does_not_open_guesses_count_against_the_address_too(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        a_second_step_that_does_not_open(admin)
        assert admin.post("/api/v1/users", json={"name": "olga", "role": "viewer", "password": "another good password"}).status_code == 201
        for _ in range(5):
            assert guess(admin, "198.51.100.9", name="admin", password=PASSWORD, code="00000-00000") == (409, "no_second_step")
        # the same address, at another account: it is the address that has had its tries
        other = guess(admin, "198.51.100.9", name="olga", password="another good password")
        assert other == (429, "rate_limited"), other


def edited(folder: Path, change: Any) -> None:
    with wall(folder) as admin:
        add(admin, f"http://127.0.0.1:{closed_port()}", force=True, kind="kvmd", name="The one device")
    for name in ("qkvm.json", "qkvm.bak"):
        saved = json.loads((folder / name).read_text(encoding="utf-8"))
        change(saved)
        (folder / name).write_text(json.dumps(saved), encoding="utf-8")


def test_allowed_host_names_with_something_among_them_that_is_no_name_are_not_used(tmp_path: Path) -> None:
    edited(tmp_path, lambda saved: saved["server"].__setitem__("allowed_hosts", ["wall.example.org", 5]))
    with pytest.raises(StoreError, match="allowed_hosts"):
        Store(tmp_path / "qkvm.json")


def test_a_pause_of_alerts_that_is_true_is_no_time(tmp_path: Path) -> None:
    edited(tmp_path, lambda saved: saved["alerts"].__setitem__("paused_until", True))
    with pytest.raises(StoreError, match="paused"):
        Store(tmp_path / "qkvm.json")
