"""Failed and cut-off writes, continued: what holds as it should."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from qkvm import kvm, unlock, update, vault
from qkvm.store import Store
from tests.test_totp import code_for, switch_on
from tests.test_unlock import fits, kept_sign_in, let_in
from tests.test_users import OTHER, account, browser, visitor
from tests.test_wall import PASSWORD, wait_until, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def refuse_writes(monkeypatch: pytest.MonkeyPatch) -> dict[str, bool]:
    disk = {"full": False}
    real_write = Store.write

    def write(self: Store, data: dict[str, Any]) -> None:
        if disk["full"]:
            raise OSError(28, "No space left on device")
        real_write(self, data)

    monkeypatch.setattr(Store, "write", write)
    return disk


def test_what_takes_access_away_through_saved_is_refused_and_put_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = tmp_path / "data"
    disk = refuse_writes(monkeypatch)
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        token = admin.post("/api/v1/tokens", json={"name": "a script"}).json()
        link = admin.post("/api/v1/tokens", json={"name": "a screen", "kind": "display"}).json()
        olga = account(admin, "olga", "operator")
        hers = browser(admin, "olga")
        secret = switch_on(admin, PASSWORD)
        collector = admin.post("/api/v1/metrics/token").json()["token"]
        assert admin.put("/api/v1/security", json={"require_totp": "admin"}).status_code == 200

        disk["full"] = True
        answers = {
            "token removed": admin.delete(f"/api/v1/tokens/{token['record']['id']}"),
            "display link removed": admin.delete(f"/api/v1/tokens/{link['record']['id']}"),
            "token made": admin.post("/api/v1/tokens", json={"name": "another"}),
            "account suspended": admin.put(f"/api/v1/users/{olga}", json={"name": "olga", "role": "operator", "suspended": True}),
            "account made viewer": admin.put(f"/api/v1/users/{olga}", json={"name": "olga", "role": "viewer"}),
            "account removed": admin.delete(f"/api/v1/users/{olga}"),
            "second step off": admin.post("/api/v1/totp/disable", json={"password": PASSWORD}),
            "new one-time codes": admin.post("/api/v1/totp/codes", json={"password": PASSWORD}),
            "rule lifted": admin.put("/api/v1/security", json={"require_totp": ""}),
            "metrics off": admin.delete("/api/v1/metrics/token"),
            "metrics token replaced": admin.post("/api/v1/metrics/token"),
            "recovery key renewed": admin.post("/api/v1/recovery", json={"password": PASSWORD}),
            "order": admin.put("/api/v1/wall/order", json={"ids": []}),
        }
        for what, answer in answers.items():
            assert (answer.status_code, answer.json()["code"]) == (507, "not_saved"), what
            assert not {"token", "recovery_key", "recovery_codes"} & set(answer.json()), what  # and nothing new is shown to anybody
        disk["full"] = False
        # As it was, while qKVM runs ...
        assert admin.get("/api/v1/wall", headers={"Authorization": f"Bearer {token['token']}"}).status_code == 200
        assert hers.get("/api/v1/session").json()["user"]["role"] == "operator"
        assert admin.get("/api/v1/session").json()["user"]["totp"] is True
        assert admin.get("/api/v1/security").json()["require_totp"] == "admin"
        assert admin.get("/metrics", headers={"Authorization": f"Bearer {collector}"}).status_code == 200
        assert len(admin.get("/api/v1/tokens").json()["tokens"]) == 2
        # ... and something unrelated that is saved afterwards makes none of it permanent.
        assert admin.put("/api/v1/alerts", json={"enabled": False}).status_code == 200
    saved = json.loads((data / "qkvm.json").read_text(encoding="utf-8"))
    assert len(saved["tokens"]) == 2 and [u["name"] for u in saved["users"]] == ["admin", "olga"]
    assert saved["users"][0]["totp"] and saved["server"]["require_totp"] == "admin" and saved["server"]["metrics_token"]
    assert (saved["users"][1]["role"], saved["users"][1]["suspended"]) == ("operator", False)
    with wall(data, sign_in=False) as later:
        guest = visitor(later, 50041)
        assert guest.post("/api/v1/display", json={"key": link["token"]}).status_code == 200
        assert guest.post("/api/v1/login", json={"name": "admin", "password": PASSWORD}).json()["code"] == "code_required"
        assert guest.post("/api/v1/login", json={"name": "admin", "password": PASSWORD, "code": code_for(secret, steps_from_now=1)}).status_code == 200
        assert visitor(later, 50042).post("/api/v1/login", json={"name": "olga", "password": OTHER}).status_code == 200


def test_a_key_cut_short_or_another_key_lets_nobody_in_and_loses_nothing(tmp_path: Path) -> None:
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        cookie = kept_sign_in(admin)
        admin.core.sessions.flush()  # type: ignore[attr-defined]
    # The key file was being written when the power went: it is there, and empty.
    (data / unlock.OWN).write_text("", encoding="ascii")
    with wall(data, sign_in=False) as later:
        assert later.get("/healthz").json()["locked"] is True  # nothing opens by itself
        assert later.get("/api/v1/wall").status_code == 401  # and nobody is let in for it
        assert len((data / unlock.OWN).read_text(encoding="ascii").strip()) >= unlock.SHORTEST  # another was made
        assert not let_in(later, cookie)  # nor a browser that was kept signed in: nothing would ask it for the sign-in that opens the wall
        assert later.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200  # the password still opens everything
        wait_until(lambda: fits(later), "never made to fit again")
    with wall(data, sign_in=False) as again:
        assert again.get("/healthz").json()["locked"] is False


def test_an_update_whose_marker_was_never_written_is_not_run(tmp_path: Path) -> None:
    from qkvm import __main__ as starter

    data = tmp_path / "data"
    package = data / "updates" / "9.9.9" / "qkvm"
    package.mkdir(parents=True)
    (package / "_version.py").write_text('__version__ = "9.9.9"\n', encoding="utf-8")
    assert starter.active_update(data) is None  # files there, marker not: the copy that shipped runs
    (data / "updates" / "current.tmp").write_text(json.dumps({"version": "9.9.9", "previous": None}), encoding="utf-8")
    (data / "updates" / "9.9.10.tmp" / "qkvm").mkdir(parents=True)
    assert starter.active_update(data) is None  # nor is anything half-made picked up
    (data / "updates" / "current.json").write_text('{"version": "9.9', encoding="utf-8")
    assert starter.active_update(data) is None  # a marker cut short names nothing
