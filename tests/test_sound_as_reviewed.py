"""Things that were tried against the sign-in, the settings file and the alerts, and held: kept as tests so that they go on holding."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from qkvm import alerts, kvm, update, vault
from qkvm.core import Core
from qkvm.security import COOKIE
from qkvm.store import Store, StoreError
from qkvm.vault import Vault
from tests.test_sso import PROXY, STARTED, through_proxy
from tests.test_unlock import fits
from tests.test_users import OTHER, account, visitor
from tests.test_wall import PASSWORD, wait_until, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def in_background(call: Any) -> tuple[threading.Thread, list[Any]]:
    answers: list[Any] = []

    def run() -> None:
        try:
            answers.append(call())
        except BaseException as ex:
            answers.append(ex)

    thread = threading.Thread(target=run)
    thread.start()
    return thread, answers


# --- the identity proxy ---------------------------------------------------------------------------------------


def test_a_session_made_on_the_proxys_word_is_good_only_with_the_proxys_word(tmp_path: Path) -> None:
    with wall(tmp_path, **STARTED) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        assert admin.post("/api/v1/users", json={"name": "olga", "role": "admin"}).status_code == 201
        assert admin.post("/api/v1/users", json={"name": "victor", "role": "viewer"}).status_code == 201

        def signed_in_by_the_proxy() -> tuple[TestClient, str]:
            hers = through_proxy(admin, "olga")
            assert hers.get("/api/v1/session").json()["user"]["name"] == "olga"
            assert hers.get("/api/v1/users").status_code == 200
            return hers, str(hers.cookies.get(COOKIE))

        def with_cookie(cookie: str, address: str, headers: dict[str, str]) -> TestClient:
            client = TestClient(admin.app, headers=headers, client=(address, 53000))
            client.portal = admin.portal
            client.cookies.set(COOKIE, cookie)
            return client

        # 1: the cookie alone, from the proxy's address, with no header: nobody, and the session is gone for good.
        hers, cookie = signed_in_by_the_proxy()
        assert with_cookie(cookie, PROXY, {"X-QKVM": "1"}).get("/api/v1/users").status_code == 401
        assert with_cookie(cookie, PROXY, {"X-QKVM": "1", "Remote-User": "olga"}).get("/api/v1/users").status_code == 401  # not revived by saying the name again
        # 2: the cookie and the header, from an address that is not the proxy.
        hers, cookie = signed_in_by_the_proxy()
        assert with_cookie(cookie, "192.0.2.77", {"X-QKVM": "1", "Remote-User": "olga"}).get("/api/v1/users").status_code == 401
        # 3: from this computer itself, which is believed about addresses and not about who somebody is.
        hers, cookie = signed_in_by_the_proxy()
        assert with_cookie(cookie, "127.0.0.1", {"X-QKVM": "1", "Remote-User": "olga"}).get("/api/v1/users").status_code == 401
        # 4: the header twice (the visitor's own line, and the proxy's added to it).
        hers, cookie = signed_in_by_the_proxy()
        twice = with_cookie(cookie, PROXY, {"X-QKVM": "1"})
        sent = twice.get("/api/v1/users", headers=[("Remote-User", "olga"), ("Remote-User", "olga")])
        assert sent.request.headers.get_list("remote-user") == ["olga", "olga"] and sent.status_code == 401
        # 5: victor's browser, through the proxy, with olga's cookie: he is victor, and her session is ended.
        hers, cookie = signed_in_by_the_proxy()
        his = with_cookie(cookie, PROXY, {"X-QKVM": "1", "Remote-User": "victor"})
        assert his.get("/api/v1/users").status_code == 401
        assert his.get("/api/v1/session").json()["user"]["name"] == "victor"
        assert hers.get("/api/v1/users").status_code == 401  # (the page then asks /api/v1/session, and is signed in again as whoever the proxy names)
        # 6: a change that was let in as olga does not go through once the proxy's word is another at its turn:
        # the same request cannot carry two words, so this is the plain case: a POST without the header.
        hers, cookie = signed_in_by_the_proxy()
        assert with_cookie(cookie, PROXY, {"X-QKVM": "1"}).post("/api/v1/tokens", json={"name": "x"}).status_code == 401
        assert len(admin.get("/api/v1/tokens").json()["tokens"]) == 0


# --- one password check at a time from an address ----------------------------------------------------------------


def test_an_address_is_not_kept_as_being_checked_after_a_check_that_broke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real_open = Vault.open

    def broken(record: Any, password: str) -> Any:
        if password == "this one breaks":
            raise RuntimeError("the check itself failed")
        return real_open(record, password)

    with wall(tmp_path, sign_in=False) as client:
        assert client.post("/api/v1/setup", json={"password": PASSWORD}).status_code == 200
        monkeypatch.setattr(Vault, "open", staticmethod(broken))
        assert visitor(client, 50010).post("/api/v1/login", json={"password": "this one breaks"}).status_code == 500
        assert visitor(client, 50011).post("/api/v1/login", json={"password": PASSWORD}).status_code == 200


def test_being_told_to_wait_for_another_check_counts_as_no_wrong_guess(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    started, go_on = threading.Event(), threading.Event()
    real_open = Vault.open

    def open_and_wait(record: Any, password: str) -> Any:
        if password == OTHER:
            started.set()
            go_on.wait(20)
        return real_open(record, password)

    with wall(tmp_path) as admin:
        account(admin, "victor", "viewer")
        monkeypatch.setattr(Vault, "open", staticmethod(open_and_wait))
        his, _ = in_background(lambda: visitor(admin, 50020).post("/api/v1/login", json={"name": "victor", "password": OTHER}))
        assert started.wait(10)
        said = [visitor(admin, 50021 + n).post("/api/v1/login", json={"name": "admin", "password": PASSWORD}) for n in range(8)]
        print("\nthe admin, from the same address, while victor's own password is being checked:", sorted({(a.status_code, a.json()["code"]) for a in said}))
        assert {(a.status_code, a.json()["code"]) for a in said} == {(429, "busy")}
        go_on.set()
        his.join(20)
        assert visitor(admin, 50040).post("/api/v1/login", json={"name": "admin", "password": PASSWORD}).status_code == 200  # held up, not locked out


# --- the settings file -----------------------------------------------------------------------------------------


def test_a_second_copy_that_is_a_folder_is_neither_a_new_wall_nor_a_start_that_loses_anything(tmp_path: Path) -> None:
    import logging

    said: list[str] = []

    class Heard(logging.Handler):  # (its own: the program's logger is set not to pass lines on once cli.main has run in this process)
        def emit(self, record: logging.LogRecord) -> None:
            said.append(record.getMessage())

    heard = Heard()
    logging.getLogger("qkvm").addHandler(heard)
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
    (data / "qkvm.bak").unlink()
    (data / "qkvm.bak").mkdir()
    try:
        with wall(data) as again:  # the settings file is there: read, and saved to
            assert again.put("/api/v1/alerts", json={"enabled": False}).status_code == 200
            assert again.core.store.backup_is_old is True  # type: ignore[attr-defined]
    finally:
        logging.getLogger("qkvm").removeHandler(heard)
    assert any("second copy" in line for line in said)
    (data / "qkvm.json").unlink()
    with pytest.raises(StoreError):  # no settings file, and a second copy that cannot be read: not a first run for whoever comes
        Core(data)


def test_what_is_carried_along_shadows_nothing_this_version_knows(tmp_path: Path) -> None:
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        account(admin, "olga", "viewer")
    path = data / "qkvm.json"
    said = json.loads(path.read_text(encoding="utf-8"))
    olga = said["users"][1]
    # A second entry with olga's id, as an admin with no password and no second step, and things this version does not know.
    said["users"].append({**olga, "role": "admin", "name": "olga2", "later": {"role": "admin"}})
    said["users"][1]["later"] = {"role": "admin", "suspended": False}
    said["server"]["later"] = {"require_totp": ""}
    said["later"] = {"users": [], "version": 99}
    path.write_text(json.dumps(said), encoding="utf-8")
    store = Store(path)
    store.save()
    after = json.loads(path.read_text(encoding="utf-8"))
    assert [(u["name"], u["role"]) for u in after["users"]] == [("admin", "admin"), ("olga", "viewer"), ("olga2", "admin")]  # as the file said, no more
    assert after["version"] == 1 and after["later"] == {"users": [], "version": 99} and after["server"]["require_totp"] == ""
    assert all(set(u) >= {"id", "name", "role", "auth"} for u in after["users"])


# --- alerts over a restart ---------------------------------------------------------------------------------------


def test_what_is_written_down_of_the_machines_is_taken_for_no_more_than_states(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file = tmp_path / "watch.json"
    many = {f"{n:08x}": "offline" for n in range(20_000)}
    file.write_text(json.dumps({"stable": {**many, "x" * 65: "online", "odd": "on fire", "list": ["offline"]}, "held": {"gone": "online", "bad": 7}, "webhook": "https://example.invalid/hook"}), encoding="ascii")
    watcher = alerts.Watcher(file)
    assert len(watcher._stable) == alerts.MOST_WATCHED and set(watcher._stable.values()) == {"offline"}
    assert watcher.held == {"gone": "online"}
    # Within the first while after a start, nothing that differs from what was written down is a change.
    assert all(watcher.observe("00000001", "online") is None for _ in range(5))
    forward = time.monotonic
    monkeypatch.setattr(time, "monotonic", lambda: forward() + alerts.STARTING + 1)
    assert [watcher.observe("00000001", "online") for _ in range(3)] == [None, ("offline", "online"), None]  # then once, and no more
    text = watcher.to_write()
    assert text is not None and "webhook" not in text and "example" not in text  # what is written holds ids and states, nothing else
    for file in (tmp_path / "is-a-folder",):
        file.mkdir()
        assert alerts.Watcher(file)._stable == {}
