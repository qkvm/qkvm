"""A saved secret that does not open, on the wall itself.

Sealed under a key from before a reset, or not what this program writes (a settings file that was edited
by hand, or damaged): as good as not saved, for an export and for the wall alike (`Vault.read`). With one
device whose saved password was damaged,

* started the usual way (the key in the data folder opens the saved passwords at start), the program
  did not start: the web server's start-up failed on that device;
* started with --locked-start, nobody could sign in: the password was right, and the answer a 500.

And an export that leaves a password out says so: in its answer, in the activity log, and by name in qkvm.log.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest

from qkvm import exchange, kvm, update, vault
from tests.fake_kvm import FakeKvm
from tests.test_totp import code_for, switch_on
from tests.test_wall import PASSWORD, add, wall

F = {"format": exchange.FORMAT, "version": 1}
PASSPHRASE = "a passphrase for the file"

# What stands in qkvm.json for the device's saved password, each a thing a hand or a bad disk can leave there.
DAMAGED: dict[str, Any] = {
    "a nonce that is no base64 (ValueError)": lambda secret: {**secret, "nonce": "!"},
    "a nonce of the wrong length (ValueError)": lambda secret: {**secret, "nonce": "AAAA"},
    "no data (KeyError)": lambda secret: {"nonce": secret["nonce"]},
    "numbers for texts (TypeError)": lambda secret: {"nonce": 1, "data": 2},
}


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def a_wall_with_two_devices(folder: Path, **options: Any) -> None:
    file = json.dumps({**F, "devices": [{"url": f"https://192.168.1.{last}", "kind": "kvmd", "name": f"KVM {last}", "password": "secret"} for last in (20, 21)]})
    with wall(folder, **options) as admin:
        assert admin.post("/api/v1/import", json={"file": file, "take": ["devices"]}).json()["devices"] == 2


def damage(folder: Path, how: str) -> None:
    saved = json.loads((folder / "qkvm.json").read_text(encoding="utf-8"))
    saved["devices"][0]["secret"] = DAMAGED[how](saved["devices"][0]["secret"])
    (folder / "qkvm.json").write_text(json.dumps(saved), encoding="utf-8")
    (folder / "qkvm.bak").unlink(missing_ok=True)


@pytest.mark.parametrize("how", list(DAMAGED))
def test_a_wall_with_one_saved_password_that_does_not_open_still_starts(tmp_path: Path, how: str) -> None:
    a_wall_with_two_devices(tmp_path)
    damage(tmp_path, how)
    try:
        with wall(tmp_path, sign_in=False) as anybody:  # (as the program starts: the key in the data folder opens the saved passwords)
            started = anybody.get("/healthz").status_code
    except Exception as ex:
        pytest.fail(f"the program did not start: {type(ex).__name__}: {ex}")
    assert started == 200


@pytest.mark.parametrize("how", list(DAMAGED))
def test_on_a_wall_with_one_saved_password_that_does_not_open_the_right_password_signs_in(tmp_path: Path, how: str) -> None:
    a_wall_with_two_devices(tmp_path, locked_start=True)
    damage(tmp_path, how)
    with wall(tmp_path, sign_in=False, locked_start=True) as visitor:
        answer = visitor.post("/api/v1/login", json={"password": PASSWORD})
        print(f">>> {how}: sign-in with the right password answered {answer.status_code} {answer.text[:120]}")
        assert answer.status_code == 200, (answer.status_code, answer.text[:200])
        tiles = visitor.get("/api/v1/wall")
        assert tiles.status_code == 200 and len(tiles.json()["devices"]) == 2


class Heard(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage())


def test_an_export_that_leaves_a_password_out_says_so_somewhere(tmp_path: Path) -> None:
    heard = Heard()
    logging.getLogger("qkvm").addHandler(heard)
    try:
        with wall(tmp_path) as admin:
            file = json.dumps({**F, "devices": [{"url": "https://192.168.1.20", "kind": "kvmd", "name": "KVM 20", "password": "secret"}]})
            assert admin.post("/api/v1/import", json={"file": file, "take": ["devices"]}).json()["devices"] == 1
            record = admin.core.store.devices[0]  # type: ignore[attr-defined]
            record.secret = {"nonce": "!", "data": record.secret["data"]}
            made = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": PASSPHRASE, "parts": ["devices"]})
            assert made.status_code == 200
            back = exchange.unpack(made.text, PASSPHRASE)
            assert [device.password for device in back.devices or []] == [""], "the password is in the file after all"
            written = [entry for entry in admin.get("/api/v1/audit").json()["entries"] if entry["event"] == "export_made"]
    finally:
        logging.getLogger("qkvm").removeHandler(heard)
    said = {"the answer's headers": dict(made.headers), "the activity log": written, "qkvm.log": heard.lines}
    print(f">>> an export without one of its passwords: {said}")
    told = [where for where, what in said.items() if any(word in json.dumps(what, default=str).lower() for word in ("without", "left out", "not saved", "could not be opened", "missing", "does not open"))]
    assert told, "a file meant to hold every password was written without one, and nothing anywhere says so"


def test_an_export_without_a_password_says_how_many_and_which(tmp_path: Path) -> None:
    # Said where each reader looks: the page reads the number off the answer, the activity log keeps it,
    # and qkvm.log has the names, so that they can be given again on the wall before the file is relied on.
    heard = Heard()
    logging.getLogger("qkvm").addHandler(heard)
    try:
        with wall(tmp_path) as admin:
            file = json.dumps({**F, "devices": [{"url": f"https://192.168.1.{last}", "kind": "kvmd", "name": f"KVM {last}", "password": "secret"} for last in (20, 21, 22)]})
            assert admin.post("/api/v1/import", json={"file": file, "take": ["devices"]}).json()["devices"] == 3
            whole = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": PASSPHRASE, "parts": ["devices"]})
            assert whole.headers["x-qkvm-not-opened"] == "0"
            for record in admin.core.store.devices[:2]:  # type: ignore[attr-defined]
                record.secret = {"nonce": "!", "data": record.secret["data"]}
            made = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": PASSPHRASE, "parts": ["devices"]})
            plain = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": "", "parts": ["devices"]})
            entries = [entry for entry in admin.get("/api/v1/audit").json()["entries"] if entry["event"] == "export_made"]
    finally:
        logging.getLogger("qkvm").removeHandler(heard)
    assert made.status_code == 200 and made.headers["x-qkvm-not-opened"] == "2"
    assert [device.password for device in exchange.unpack(made.text, PASSPHRASE).devices or []] == ["", "", "secret"]
    assert sorted(entry.get("not_opened", 0) for entry in entries) == [0, 0, 2]
    told = [line for line in heard.lines if "does not open any more (2)" in line]
    assert len(told) == 1 and "KVM 20" in told[0] and "KVM 21" in told[0] and "KVM 22" not in told[0], heard.lines
    # (A plain file holds no password to begin with: it is without none of them.)
    assert plain.headers["x-qkvm-not-opened"] == "0"


def test_a_saved_text_that_does_not_open_is_said_and_not_typed(tmp_path: Path) -> None:
    device = FakeKvm().start()
    try:
        with wall(tmp_path) as admin:
            tile = add(admin, device.url)
            action = admin.post("/api/v1/actions", json={"name": "Unlock disk", "kind": "text", "text": "THE-PASSPHRASE"}).json()["action"]
            saved = admin.core.store.actions[0]  # type: ignore[attr-defined]
            saved.secret = {"nonce": "AAAA", "data": saved.secret["data"]}
            ran = admin.post(f"/api/v1/devices/{tile}/actions", json={"action": "custom", "custom_id": action["id"]})
            assert (ran.status_code, ran.json()["code"]) == (409, "no_text"), ran.text
            assert "Unlock disk" in ran.json()["message"]
            assert admin.get("/api/v1/actions").status_code == 200  # and the list of them is still there
    finally:
        device.stop()


def test_an_alert_address_that_does_not_open_is_no_address(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        assert admin.put("/api/v1/alerts", json={"enabled": True, "webhook": "https://hooks.example/T0KEN"}).status_code == 200
        admin.core.store.alerts.webhook = {"nonce": "!", "data": "x"}  # type: ignore[attr-defined]
        seen = admin.get("/api/v1/alerts")
        assert seen.status_code == 200 and "T0KEN" not in seen.text
        assert admin.post("/api/v1/alerts/test").status_code in (400, 409, 422)  # nowhere to send one to: said, not an error inside
        assert admin.get("/api/v1/wall").status_code == 200


def test_a_second_step_whose_key_does_not_open_is_said_as_that(tmp_path: Path) -> None:
    heard = Heard()
    logging.getLogger("qkvm").addHandler(heard)
    try:
        with wall(tmp_path) as admin:
            secret = switch_on(admin, PASSWORD)
            user = admin.core.store.users[0]  # type: ignore[attr-defined]
            user.totp = {"nonce": "!", "data": user.totp["data"]}
            for _ in range(3):
                answer = admin.post("/api/v1/login", json={"password": PASSWORD, "code": code_for(secret)})
                assert (answer.status_code, answer.json()["code"]) == (409, "no_second_step"), answer.text
            assert "--disable-2fa" in answer.json()["message"]
            # Not counted as wrong codes: the way back in is not locked on top of it.
            wrong = admin.post("/api/v1/login", json={"password": "not the password", "code": "000000"})
            assert wrong.status_code == 401
    finally:
        logging.getLogger("qkvm").removeHandler(heard)
    assert any("second step does not open" in line for line in heard.lines), heard.lines
