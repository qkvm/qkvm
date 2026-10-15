"""A change that is answered as not saved is not kept, in memory or on disk; what was erased is in no other file of the folder; a start that cannot write says so in a sentence."""

from __future__ import annotations

import gc
import json
import os
import shutil
import signal
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from qkvm import cli, kvm, update, vault
from qkvm.core import Core, DeviceManager
from qkvm.store import Store, StoreError
from qkvm.tlscert import ensure_certificate
from qkvm.vault import Vault
from tests.fake_kvm import FakeKvm
from tests.test_unlock import fits
from tests.test_users import OTHER, account, browser, visitor
from tests.test_wall import CSRF, PASSWORD, add, closed_port, wait_until, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def fake() -> Iterator[FakeKvm]:
    server = FakeKvm().start()
    yield server
    server.stop()


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


# --- S1: what a later version wrote, carried along (_beyond), and a save that fails otherwise than by the disk ---


def test_a_change_that_is_answered_as_failed_is_not_kept_until_the_restart(tmp_path: Path) -> None:
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        token = admin.post("/api/v1/tokens", json={"name": "a script"}).json()
        olga = account(admin, "olga", "operator")
    # The settings file as a later version might leave it (or a backup that somebody could write to before it
    # was restored): one more setting, which this version has not heard of and carries along. It is nested deep.
    path = data / "qkvm.json"
    path.write_text(path.read_text(encoding="utf-8").replace("{", '{"later": ' + "[" * 600 + "]" * 600 + ",", 1), encoding="utf-8")
    bearer = {"Authorization": f"Bearer {token['token']}"}
    with wall(data, sign_in=False) as old:
        assert old.post("/api/v1/login", json={"name": "admin", "password": PASSWORD}).status_code == 200
        taken_back = old.delete(f"/api/v1/tokens/{token['record']['id']}")
        removed = old.delete(f"/api/v1/users/{olga}")
        works_at_once = visitor(old, 50005).get("/api/v1/wall", headers=bearer).status_code
        there_at_once = [u["name"] for u in old.get("/api/v1/users").json()["users"]]
        print("\ntoken taken back:", taken_back.status_code, taken_back.json(), "| account removed:", removed.status_code, removed.json().get("code"))
        print("at once: the token is answered", works_at_once, "| accounts:", there_at_once)
    with wall(data, sign_in=False) as later:
        works_later = visitor(later, 50006).get("/api/v1/wall", headers=bearer).status_code
        hers = visitor(later, 50007).post("/api/v1/login", json={"name": "olga", "password": OTHER}).status_code
        print("after a restart: the token is answered", works_later, "| olga signs in:", hers)
    assert works_at_once == works_later, "taken back while qKVM ran (and answered 500), and working again after the restart"


def test_a_settings_file_nested_too_deep_to_read_is_a_damaged_file_like_any_other(tmp_path: Path) -> None:
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
    (data / "qkvm.json").write_text("[" * 100_000, encoding="utf-8")
    try:
        core = Core(data)
    except StoreError as ex:
        print("\nrefused in a sentence:", ex)
        return
    assert core.store.restored  # or read from the second copy, which is whole


# --- S2: what --reset-password leaves in the folder --------------------------------------------------------------


def test_reset_password_leaves_nothing_in_the_folder_that_the_key_in_the_folder_opens(tmp_path: Path, fake: FakeKvm) -> None:
    data = tmp_path / "data"
    with wall(data) as admin:
        add(admin, fake.url)  # saved with the password "secret"
        wait_until(lambda: fits(admin), "never made to fit")
        assert admin.put("/api/v1/alerts", json={"enabled": False}).status_code == 200
    path = data / "qkvm.json"
    path.write_text(path.read_text(encoding="utf-8") + "}", encoding="utf-8")  # a hand edit that left one brace too many
    with wall(data, sign_in=False) as later:
        assert later.core.store.restored  # type: ignore[attr-defined]
    assert cli.main(["--data-dir", str(data), "--reset-password"]) == 0  # "Accounts cleared."
    key = (data / "unlock.key").read_text(encoding="ascii").strip()
    read: list[str] = []
    for file in sorted(p for p in data.iterdir() if p.is_file()):
        text = file.read_text(encoding="utf-8", errors="replace")
        for candidate in (text, text.rstrip()[:-1]):
            try:
                said = json.loads(candidate)
            except ValueError:
                continue
            record = said.get("unlock") if isinstance(said, dict) else None
            data_key = Vault.open(record, key) if record else None
            if data_key is not None:
                opened = Vault()
                opened.adopt(data_key)
                read += [f"{file.name}: {d['name']} -> {opened.decrypt(d['secret'], d['id'])!r}, accounts {[u['name'] for u in said['users']]}" for d in said["devices"] if d.get("secret")]
    print("\nafter --reset-password, read from the data folder with the key that lies in it:", read)
    assert not read


def test_reset_password_on_a_disk_that_takes_no_write_ends_in_a_sentence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")

    def full(self: Store, data: dict[str, Any]) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(Store, "write", full)
    for options in (["--reset-password"], ["--disable-2fa", "admin"]):
        try:
            status: Any = cli.main(["--data-dir", str(data), *options])
        except OSError as ex:
            status = f"a traceback: {type(ex).__name__}: {ex}"
        print(f"\n{' '.join(options)} ended in:", status)
        assert status in (1, 2), options


# --- S3: a start that cannot write, with HTTPS on -------------------------------------------------------------------


def test_an_installed_update_is_not_taken_back_because_the_certificate_could_not_be_written_at_start(tmp_path: Path, capfd: pytest.CaptureFixture[str]) -> None:
    import qkvm
    from qkvm import __main__ as starter

    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
    package = data / "updates" / "9.9.9" / "qkvm"
    shutil.copytree(Path(qkvm.__file__).parent, package, ignore=shutil.ignore_patterns("__pycache__"))
    (package / "_version.py").write_text('__version__ = "9.9.9"\n', encoding="utf-8")
    (data / "updates" / "current.json").write_text(json.dumps({"version": "9.9.9", "previous": None}), encoding="utf-8")
    # Started with --https, and the certificate cannot be written at that moment: here, because something lies
    # where its folder goes. (test_failed_writes names this case: "and so does a certificate that cannot be
    # written where HTTPS is on".)
    (data / "tls").write_text("", encoding="utf-8")
    before = signal.getsignal(signal.SIGTERM)
    try:
        status = starter.supervise(["--data-dir", str(data), "--https", "--bind", "local", "--port", str(closed_port())])
    finally:
        signal.signal(signal.SIGTERM, before)
    said = capfd.readouterr().err
    print("exit status:", status)
    print("said:", [line for line in said.splitlines() if line.startswith("qkvm:") or "Error" in line])
    print("updates/current.json still there:", (data / "updates" / "current.json").exists())
    assert (data / "updates" / "current.json").exists(), "the update was taken back, and it was the disk that would not be written to"


# --- S4: a change that is saved by somebody else's save, and then taken back --------------------------------------


def test_a_change_that_was_refused_is_not_what_the_next_start_finds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    new = "replaced by the admin"
    making, go_on = threading.Event(), threading.Event()
    real_rewrap, real_write = Vault.rewrap, Store.write
    disk = {"full": False}

    def rewrap_and_wait(self: Vault, password: str) -> Any:
        if password == new:
            making.set()
            go_on.wait(20)
        return real_rewrap(self, password)

    def write(self: Store, data: dict[str, Any]) -> None:
        if disk["full"]:
            raise OSError(28, "No space left on device")
        real_write(self, data)

    data = tmp_path / "data"
    pem = ensure_certificate(tmp_path / "some", ["127.0.0.1"])[0].read_text(encoding="ascii")
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        sam = account(admin, "sam", "viewer")
        assert admin.put(f"/api/v1/users/{sam}", json={"name": "sam", "role": "viewer", "suspended": True}).status_code == 200  # his password got out
        # A KVM that does not answer yet, added all the same: its certificate is remembered when it first does.
        url = f"https://127.0.0.1:{closed_port()}"
        made = admin.post("/api/v1/devices", json={"url": url, "password": "secret", "kind": "kvmd", "force": True})
        assert made.status_code == 201, made.text
        device = made.json()["device"]["id"]
        manager = next(o for o in gc.get_objects() if isinstance(o, DeviceManager) and o.core is admin.core)  # type: ignore[attr-defined]
        monkeypatch.setattr(Vault, "rewrap", rewrap_and_wait)
        monkeypatch.setattr(Store, "write", write)

        # The admin gives sam a new password, lifts the suspension and makes him an admin, in one form.
        changing, changed = in_background(lambda: admin.put(f"/api/v1/users/{sam}", json={"name": "sam", "role": "admin", "suspended": False, "password": new}))
        assert making.wait(10)  # the form is half applied: role and suspension in memory, the new password still being made
        # In that moment the KVM answers for the first time, and its certificate is saved (DeviceManager._pinned,
        # which waits for nobody's turn).
        admin.portal.call(manager._pinned, device, url, pem)  # type: ignore[union-attr]
        on_disk = next(u for u in json.loads((data / "qkvm.json").read_text(encoding="utf-8"))["users"] if u["name"] == "sam")
        print("\nwritten by the certificate's save, while the admin's change was half made: sam is", on_disk["role"], "| suspended:", on_disk["suspended"])
        disk["full"] = True  # ...and the admin's own save, a moment later, is refused
        go_on.set()
        changing.join(20)
        answer = changed[0]
        shown = next(u for u in admin.get("/api/v1/users").json()["users"] if u["name"] == "sam")
        print("the admin is answered:", answer.status_code, answer.json()["message"], "| and shown: sam is", shown["role"], "| suspended:", shown["suspended"])
        assert answer.status_code == 507 and (shown["role"], shown["suspended"]) == ("viewer", True)
    monkeypatch.setattr(Vault, "rewrap", real_rewrap)
    with wall(data, sign_in=False) as later:  # restarted before anything else could be saved
        his = visitor(later, 50008)
        signed_in = his.post("/api/v1/login", json={"name": "sam", "password": OTHER})
        role = signed_in.json().get("user", {}).get("role")
        print("after a restart, sam signs in with the password that got out:", signed_in.status_code, "| as:", role, "| the list of accounts:", his.get("/api/v1/users").status_code)
        assert signed_in.status_code != 200, "refused, 'so nothing was changed', and after a restart the suspended viewer is an admin with his old password"


# --- S5: a saved action's count of edits, taken back with a refused edit ------------------------------------------


def test_a_button_that_showed_a_refused_edit_does_not_run_what_the_action_became_later(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    holding, go_on = threading.Event(), threading.Event()
    real_write = Store.write
    disk = {"held": False}

    def write(self: Store, data: dict[str, Any]) -> None:
        if disk["held"]:
            holding.set()
            go_on.wait(20)
            raise OSError(28, "No space left on device")
        real_write(self, data)

    with wall(tmp_path) as admin:
        device = add(admin, fake.url)
        account(admin, "olga", "operator")
        olga = browser(admin, "olga")
        action = admin.post("/api/v1/actions", json={"name": "Lock the screen", "kind": "keys", "keys": "MetaLeft,KeyL"}).json()["action"]
        monkeypatch.setattr(Store, "write", write)
        disk["held"] = True
        editing, edited = in_background(lambda: admin.put(f"/api/v1/actions/{action['id']}", json={"name": "Lock the screen (Win+L)", "kind": "keys", "keys": "MetaLeft,KeyL"}))
        assert holding.wait(10)
        seen = olga.get("/api/v1/actions").json()["actions"][0]  # olga opens the list in that moment
        disk["held"] = False
        go_on.set()
        editing.join(20)
        assert edited[0].status_code == 507
        # Later the admin makes something else of it.
        assert admin.put(f"/api/v1/actions/{action['id']}", json={"name": "Shut down", "kind": "text", "text": "shutdown -h now", "enter": True, "danger": True}).status_code == 200
        ran = olga.post(f"/api/v1/devices/{device}/actions", json={"action": "custom", "custom_id": action["id"], "custom_changed": seen["changed"]})
        print(f"\nolga saw: {seen['name']!r} ({seen['kind']}, edit {seen['changed']}); clicked it later: {ran.status_code}; the machine got: {fake.state.actions}")
        assert ran.status_code == 409, "the button showed a key combination; what ran was a text that was put there since"


# --- S6: one password check at a time from an address, and the addresses of one IPv6 network ----------------------


def test_six_wrong_passwords_from_one_ipv6_network_are_not_all_checked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # README: "the addresses of one IPv6 network count as one". test_meanwhile has this for one IPv4 address.
    started, go_on = threading.Event(), threading.Event()
    real_open = Vault.open
    checked: list[str] = []

    def open_and_wait(record: Any, password: str) -> Any:
        if password.startswith("guess"):
            started.set()
            go_on.wait(20)
            checked.append(password)
        return real_open(record, password)

    with wall(tmp_path) as admin:
        monkeypatch.setattr(Vault, "open", staticmethod(open_and_wait))
        guesses = []
        for number in range(6):
            guesser = TestClient(admin.app, headers=CSRF, client=(f"2001:db8:0:7::{number + 1:x}", 42000 + number))  # six addresses of one /64
            guesser.portal = admin.portal
            guesses.append(in_background(lambda guesser=guesser, number=number: guesser.post("/api/v1/login", json={"password": f"guess number {number}"})))
        assert started.wait(10)
        time.sleep(0.5)
        go_on.set()
        for thread, _ in guesses:
            thread.join(20)
        said = [answers[0].status_code for _, answers in guesses]
        print(f"\nsix guesses sent at once from six addresses of one IPv6 network: {said}; passwords that were checked: {len(checked)}")
        assert len(checked) <= 5, "six wrong passwords from one IPv6 network were all checked, where the fifth locks it out"


def test_a_leftover_second_copy_in_the_making_is_not_left_with_what_was_erased(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = tmp_path / "data"
    real_replace, real_unlink, real_copy = os.replace, os.unlink, shutil.copy2
    held = {"bak": False, "new": False}

    def replace(source: Any, target: Any, *args: Any, **kwargs: Any) -> None:
        if held["bak"] and str(target).endswith("qkvm.bak"):
            raise PermissionError(13, "Permission denied")
        real_replace(source, target, *args, **kwargs)

    def unlink(path: Any, *args: Any, **kwargs: Any) -> None:
        if held["bak"] and str(path).endswith("qkvm.bak"):
            raise PermissionError(13, "Permission denied")
        real_unlink(path, *args, **kwargs)

    def copy(source: Any, target: Any, *args: Any, **kwargs: Any) -> Any:
        if held["new"] and str(target).endswith("qkvm.bak.new"):
            raise PermissionError(13, "Permission denied")
        return real_copy(source, target, *args, **kwargs)

    monkeypatch.setattr(os, "replace", replace)
    monkeypatch.setattr(os, "unlink", unlink)
    monkeypatch.setattr(shutil, "copy2", copy)
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        held["bak"] = True  # something has qkvm.bak open for a while (a backup program, on Windows)
        assert admin.put("/api/v1/alerts", json={"enabled": False}).status_code == 200
        held["bak"] = False
    left = sorted(p.name for p in data.iterdir() if p.name.startswith("qkvm."))
    held["new"] = True  # at the reset, it is the copy in the making that cannot be written
    status = cli.main(["--data-dir", str(data), "--reset-password"])
    copies = [data / name for name in ("qkvm.json", "qkvm.bak", "qkvm.bak.new", "qkvm.tmp") if (data / name).exists()]
    still = {p.name: [u["name"] for u in json.loads(p.read_text(encoding="utf-8")).get("users", [])] for p in copies}
    print("\nleft by the run before:", left, "| --reset-password ended in:", status, "| accounts in each file after it:", still)
    assert status != 0 or not any(still.values()), "'Accounts cleared', status 0, and a file in the folder that still holds them"
