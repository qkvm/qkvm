"""Over a restart, continued: what was held back while alerts were paused, tokens and links that ran out, settings a later version wrote."""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from qkvm import alerts, kvm, update, vault
from qkvm.security import COOKIE
from qkvm.vault import Vault, tidy_recovery_key
from tests.fake_kvm import FakeKvm
from tests.test_sso import STARTED, through_proxy
from tests.test_tokens import screen, script
from tests.test_totp import switch_on
from tests.test_unlock import SECRET, fits, kept_sign_in, let_in
from tests.test_users import visitor
from tests.test_wall import PASSWORD, add, wait_until, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(alerts, "CHECK_EVERY", 0.05)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")
    monkeypatch.setattr(alerts, "STARTING", 0.3)  # (two minutes, as it comes: how long a start is given to find its network)


@pytest.fixture
def fake() -> Iterator[FakeKvm]:
    server = FakeKvm().start()
    yield server
    server.stop()


def test_turning_the_second_step_on_ends_what_was_signed_in_with_the_password_alone(tmp_path: Path) -> None:
    # README: "signing in then asks for the password and for a 6-digit code". A browser kept signed in before
    # that never gave one.
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        elsewhere = kept_sign_in(visitor(admin, 50002))  # the same account, kept signed in on another computer
        switch_on(admin, PASSWORD)
        still = let_in(visitor(admin, 50003), elsewhere)
    with wall(data, sign_in=False) as later:
        after = let_in(later, elsewhere)
        print("\nthe browser kept signed in with the password alone: still in at once", still, "| still in after a restart", after)
        assert not after


def test_a_sign_in_by_the_identity_proxy_is_written_down_nowhere(tmp_path: Path) -> None:
    data = tmp_path / "data"
    with wall(data, **STARTED) as admin:
        wait_until(lambda: admin.core.store.unlock is not None, "never made to fit")  # type: ignore[attr-defined]
        assert admin.post("/api/v1/users", json={"name": "olga", "role": "operator"}).status_code == 201
        hers = through_proxy(admin, "olga")
        assert hers.get("/api/v1/session").json()["authenticated"] is True
        cookie = str(hers.cookies.get(COOKIE))
        kept_sign_in(admin, name="admin")  # so that there is a file at all
        admin.core.sessions.flush()  # type: ignore[attr-defined]
    written = json.loads((data / "sessions.json").read_text(encoding="ascii"))
    assert len(written) == 1  # the admin's, and not hers
    with wall(data, sign_in=False, **STARTED) as later:
        assert not let_in(later, cookie)
    with wall(data, sign_in=False, unlock_secret=SECRET) as later:  # started without the proxy's say
        assert not let_in(later, cookie)


def test_a_display_link_that_ran_out_or_was_taken_back_lets_no_screen_in_after_a_restart(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    data = tmp_path / "data"
    real = time.time
    offset = {"by": 0.0}
    monkeypatch.setattr(time, "time", lambda: real() + offset["by"])
    with wall(data) as admin:
        add(admin, fake.url)
        wait_until(lambda: fits(admin), "never made to fit")
        link = admin.post("/api/v1/tokens", json={"name": "hall", "kind": "display", "days": 1}).json()
        token = admin.post("/api/v1/tokens", json={"name": "nightly", "days": 1}).json()
        gone = admin.post("/api/v1/tokens", json={"name": "lab", "kind": "display"}).json()
        hall, lab = screen(admin, 51010), screen(admin, 51011)
        assert hall.post("/api/v1/display", json={"key": link["token"]}).status_code == 200
        assert lab.post("/api/v1/display", json={"key": gone["token"]}).status_code == 200
        cookies = str(hall.cookies.get(COOKIE)), str(lab.cookies.get(COOKIE))
        assert admin.delete(f"/api/v1/tokens/{gone['record']['id']}").status_code == 200
        admin.core.sessions.flush()  # type: ignore[attr-defined]
    assert not (data / "sessions.json").exists() or "token:" not in (data / "sessions.json").read_text(encoding="ascii")
    offset["by"] = 2 * 86400.0  # two days later
    with wall(data, sign_in=False) as later:
        assert not let_in(later, cookies[0]) and not let_in(later, cookies[1])
        assert screen(later, 51012).post("/api/v1/display", json={"key": link["token"]}).status_code == 401  # ran out
        assert screen(later, 51013).post("/api/v1/display", json={"key": gone["token"]}).status_code == 401  # taken back
        assert script(later, token["token"]).get("/api/v1/wall").status_code == 401


def test_a_settings_file_that_was_damaged_does_not_bring_back_what_was_taken_away_last(tmp_path: Path, fake: FakeKvm) -> None:
    # README: "an admin can take either back at any moment" and "If qkvm.json is ever unreadable, QKVM starts
    # from the backup". The backup is the file as it was before the last change.
    data = tmp_path / "data"
    with wall(data) as admin:
        add(admin, fake.url)
        wait_until(lambda: fits(admin), "never made to fit")
        made = admin.post("/api/v1/tokens", json={"name": "nightly", "role": "operator"}).json()
        assert script(admin, made["token"]).get("/api/v1/wall").status_code == 200
        assert admin.delete(f"/api/v1/tokens/{made['record']['id']}").status_code == 200  # the laptop it was on is lost
        assert script(admin, made["token"]).get("/api/v1/wall").status_code == 401
    (data / "qkvm.json").write_bytes((data / "qkvm.json").read_bytes()[:200])  # cut short, as a disk that failed leaves it
    with wall(data, sign_in=False) as later:
        answer = script(later, made["token"]).get("/api/v1/wall").status_code
        print("\nthe token that was taken back answers, after the settings file was found damaged:", answer)
        assert answer == 401


def test_the_recovery_key_that_was_replaced_opens_nothing_that_is_left_in_the_folder(tmp_path: Path) -> None:
    # README: "an admin can make a new one under Settings -> Security, which cancels the old one."
    data = tmp_path / "data"
    with wall(data, sign_in=False, locked_start=True) as admin:
        old = admin.post("/api/v1/setup", json={"password": PASSWORD}).json()["recovery_key"]
        assert admin.post("/api/v1/recovery", json={"password": PASSWORD}).status_code == 200
    found = []
    for name in ("qkvm.json", "qkvm.bak"):
        record = json.loads((data / name).read_text(encoding="utf-8")).get("recovery")
        if record and Vault.open(record, tidy_recovery_key(old)) is not None:
            found.append(name)
    print("\nthe cancelled recovery key still opens the key to everything in:", found)
    assert not found


def test_a_program_that_is_gone_back_to_keeps_what_the_newer_one_wrote(tmp_path: Path) -> None:
    # README: "If the new version won't start, QKVM goes back to the previous one by itself." 0.1.0 is the
    # version every later one goes back to. What it does with a settings file a later version wrote:
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
    path = data / "qkvm.json"
    newer = json.loads(path.read_text(encoding="utf-8"))
    newer["version"] = 2
    newer["server"]["sign_in_ends_after_hours"] = 1  # a rule a later version has, and this one has not heard of
    newer["users"][0]["must_change_password"] = True
    newer["banned_addresses"] = ["203.0.113.0/24"]
    path.write_text(json.dumps(newer, indent=2), encoding="utf-8")
    with wall(data) as old:  # the older program is started on it (gone back to, by itself), and one thing is changed
        assert old.put("/api/v1/alerts", json={"enabled": False}).status_code == 200
    after = json.loads(path.read_text(encoding="utf-8"))
    lost = [name for name, there in (
        ("version 2", after["version"] == 2),
        ("server.sign_in_ends_after_hours", "sign_in_ends_after_hours" in after["server"]),
        ("users[0].must_change_password", "must_change_password" in after["users"][0]),
        ("banned_addresses", "banned_addresses" in after),
    ) if not there]  # fmt: skip
    print("\ngone from the settings file after the older program saved once:", lost)
    assert not lost


def test_a_used_code_of_the_app_is_not_usable_again_when_the_clock_is_set_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Expected to pass: which code was used last is kept as its time step, and no clock brings an older one back.
    from qkvm import totp

    real = time.time
    offset = {"by": 0.0}
    monkeypatch.setattr(time, "time", lambda: real() + offset["by"])
    with wall(tmp_path) as admin:
        secret = switch_on(admin, PASSWORD).replace(" ", "")
        step = int(real() // totp.STEP)
        used = totp.code_at(secret, step + 1)  # the next one: the one that switched it on is used up
        guest = visitor(admin, 50002)
        assert guest.post("/api/v1/login", json={"password": PASSWORD, "code": used}).status_code == 200
        answers = []
        for back in (0.0, -30.0, -60.0, -3600.0, -365 * 86400.0):
            offset["by"] = back
            now_step = int((real() + back) // totp.STEP)
            again = visitor(admin, 50100 + len(answers))
            admin.core.limiter._failures.clear()  # type: ignore[attr-defined]  # (the throttle is another test's subject)
            answers.append((
                back,
                again.post("/api/v1/login", json={"password": PASSWORD, "code": used}).status_code,  # the used one
                again.post("/api/v1/login", json={"password": PASSWORD, "code": totp.code_at(secret, now_step)}).status_code,  # the one the clock now calls current
            ))  # fmt: skip
        offset["by"] = 0.0
        print("\nclock set back by, the used code, the code of the clock's own moment:", answers)
        assert all(used_again != 200 and of_that_moment != 200 for _, used_again, of_that_moment in answers)


def test_going_from_one_way_of_starting_to_another_leaves_nothing_that_opens_the_folder(tmp_path: Path, fake: FakeKvm) -> None:
    # README: "What the key before opened the folder with is taken out at that start, so a copy of it that
    # somebody kept opens nothing afterwards." Every key that was ever in use is kept here, and tried on
    # everything that lies in the folder after each change.
    data = tmp_path / "data"
    kept_keys: dict[str, str] = {}

    def opens_with_a_key_that_was_kept(but_not: str = "") -> list[str]:
        found = []
        for path in sorted(p for p in data.rglob("*") if p.is_file()):
            try:
                said = json.loads(path.read_text(encoding="utf-8"))
            except (ValueError, UnicodeDecodeError, OSError):
                continue
            record = said.get("unlock") if isinstance(said, dict) else None
            for name, secret in kept_keys.items():
                if record and name != but_not and Vault.open(record, secret) is not None:
                    found.append(f"{path.name} opens with the key of {name}")
        return found

    with wall(data) as admin:  # 1: as it comes
        add(admin, fake.url)
        cookie = kept_sign_in(admin)
        wait_until(lambda: fits(admin), "never made to fit")
    kept_keys["step 1"] = (data / "unlock.key").read_text(encoding="ascii").strip()
    assert "qkvm.json opens with the key of step 1" in opens_with_a_key_that_was_kept()

    with wall(data, sign_in=False, locked_start=True) as locked:  # 2: locked
        assert locked.get("/healthz").json()["locked"] is True and not let_in(locked, cookie)
    assert not (data / "unlock.key").exists() and not (data / "sessions.json").exists()
    assert opens_with_a_key_that_was_kept() == []

    with wall(data, sign_in=False) as plain:  # 3: as it comes again, nobody signs in
        assert plain.get("/healthz").json()["locked"] is True and not let_in(plain, cookie)
    assert opens_with_a_key_that_was_kept() == []
    with wall(data) as plain:  # ...and then somebody does
        wait_until(lambda: fits(plain), "never made to fit")
    kept_keys["step 3"] = (data / "unlock.key").read_text(encoding="ascii").strip()
    assert kept_keys["step 3"] != kept_keys["step 1"]
    assert opens_with_a_key_that_was_kept(but_not="step 3") == []

    kept_keys["file"] = SECRET
    with wall(data, sign_in=False, unlock_secret=SECRET) as filed:  # 4: with an unlock file
        assert filed.get("/healthz").json()["locked"] is True
    assert not (data / "unlock.key").exists() and opens_with_a_key_that_was_kept() == []
    with wall(data, unlock_secret=SECRET) as filed:
        wait_until(lambda: fits(filed), "never made to fit")
    assert opens_with_a_key_that_was_kept(but_not="file") == []

    with wall(data, sign_in=False, unlock_secret="another-file-than-the-one-that-fits-this-folder") as other:  # 5: a file that does not fit
        assert other.get("/healthz").json()["locked"] is True
    assert opens_with_a_key_that_was_kept() == []  # the right file opens nothing any more either, until the next sign-in

    with wall(data, sign_in=False, locked_start=True) as locked:  # 6: locked again
        assert locked.get("/healthz").json()["locked"] is True
    assert opens_with_a_key_that_was_kept() == []
    print("\nfiles in the data folder at the end:", sorted(p.name for p in data.iterdir()))
