"""Carrying on by itself after a restart: the saved passwords opened at start by a key of qKVM's own (as it comes),
by one in a file kept elsewhere (--unlock-file), or by nobody but whoever signs in (--locked-start)."""

from __future__ import annotations

import errno
import os
import stat
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from qkvm import cli, kvm, security, unlock, update, vault
from qkvm.security import COOKIE
from qkvm.store import Store
from tests.fake_kvm import FakeKvm
from tests.test_users import OTHER, account, browser, visitor
from tests.test_wall import PASSWORD, add, wait_until, wall

SECRET = "what-is-in-the-file-that-is-kept-somewhere-else"


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def fake() -> Iterator[FakeKvm]:
    server = FakeKvm().start()
    yield server
    server.stop()


def fits(client: object) -> bool:
    return client.core.store.unlock is not None  # type: ignore[attr-defined]


def test_started_with_its_unlock_file_a_wall_watches_without_anybody_signing_in(tmp_path: Path, fake: FakeKvm) -> None:
    # After a restart qKVM can reach no device until somebody signs in: the devices' passwords are encrypted
    # and only an account's password opens them. After a power cut, at three in the morning, that is when it
    # was wanted. Started with an unlock file it opens them itself, from the second start on: the first
    # sign-in is what makes the file fit this data folder.
    data = tmp_path / "data"
    with wall(data, unlock_secret=SECRET) as admin:
        assert admin.get("/healthz").json()["locked"] is False
        device = add(admin, fake.url)
        token = admin.post("/api/v1/metrics/token").json()["token"]
        wait_until(lambda: fits(admin), "the unlock file was never made to fit this data folder")
        assert admin.get("/api/v1/session").json()["unlocks_at_start"] is True
        events = [entry["event"] for entry in admin.core.audit.tail(20)]  # type: ignore[attr-defined]
        assert "unlock_at_start_on" in events

    collector = {"Authorization": f"Bearer {token}"}
    with wall(data, sign_in=False, unlock_secret=SECRET) as nobody:  # restarted; nobody has been by
        assert nobody.get("/healthz").json()["locked"] is False
        assert nobody.get("/api/v1/wall").status_code == 401  # opened for the program, not for whoever asks

        def seen() -> bool:
            return f'qkvm_device_up{{id="{device}"' in nobody.get("/metrics", headers=collector).text

        wait_until(seen, "the device was not looked at although the wall had unlocked itself")
        text = nobody.get("/metrics", headers=collector).text
        assert "qkvm_unlocked 1" in text and "qkvm_sessions 0" in text
        assert fake.state.logins >= 1  # signed in to the KVM with the password that was saved
        assert "unlocked_at_start" in [entry["event"] for entry in nobody.core.audit.tail(5)]  # type: ignore[attr-defined]

    with wall(data, sign_in=False) as nobody:  # started without the file: the key qKVM then keeps for itself is another one
        assert nobody.get("/healthz").json()["locked"] is True
        assert "qkvm_unlocked 0" in nobody.get("/metrics", headers=collector).text
        # And the file opens nothing any more: taking the option away is how it is switched off.
        assert not fits(nobody) and Store(data / "qkvm.json").unlock is None

    with wall(data, sign_in=False, unlock_secret=SECRET) as later:  # given again, it takes one sign-in to fit again
        assert later.get("/healthz").json()["locked"] is True
        assert later.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
        wait_until(lambda: fits(later), "the unlock file was not made to fit again")


def test_another_file_than_the_one_that_fits_opens_nothing(tmp_path: Path) -> None:
    data = tmp_path / "data"
    with wall(data, unlock_secret=SECRET) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
    with wall(data, sign_in=False, unlock_secret=SECRET.upper()) as nobody:  # the file was replaced, or belongs to another folder
        assert nobody.get("/healthz").json()["locked"] is True
        assert not fits(nobody)  # what the old file opened it with is not kept around
        assert nobody.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
        wait_until(lambda: fits(nobody), "the new file was not made to fit")
    with wall(data, sign_in=False, unlock_secret=SECRET.upper()) as nobody:
        assert nobody.get("/healthz").json()["locked"] is False  # that is how the file is replaced by another
    with wall(data, sign_in=False, unlock_secret=SECRET) as nobody:
        assert nobody.get("/healthz").json()["locked"] is True  # and the old one is of no use to whoever kept a copy


def test_with_an_unlock_file_the_last_sign_out_locks_nothing(tmp_path: Path) -> None:
    for number, (options, stays_open) in enumerate((({"unlock_secret": SECRET}, True), ({}, True), ({"locked_start": True}, False))):
        with wall(tmp_path / str(number), **options) as admin:
            if stays_open:
                wait_until(lambda admin=admin: fits(admin), "never made to fit")
            assert admin.post("/api/v1/logout", json={}).status_code == 200
            assert admin.core.vault.unlocked is stays_open  # type: ignore[attr-defined]
            assert admin.get("/healthz").json()["locked"] is not stays_open


def test_the_secret_itself_is_written_nowhere_in_the_data_folder(tmp_path: Path, fake: FakeKvm) -> None:
    data = tmp_path / "data"
    with wall(data, unlock_secret=SECRET) as admin:
        add(admin, fake.url)
        olga = browser(admin, "olga") if account(admin, "olga", "operator") else None
        assert olga is not None and olga.get("/api/v1/session").json()["unlocks_at_start"] in (True, False)
        wait_until(lambda: fits(admin), "never made to fit")
        admin.core.audit.flush()  # type: ignore[attr-defined]
    for path in data.rglob("*"):
        if path.is_file():
            assert SECRET.encode() not in path.read_bytes(), path.name
    assert OTHER  # (the account above signed in with it)


def test_a_new_password_for_everything_makes_the_file_fit_nothing(tmp_path: Path) -> None:
    data = tmp_path / "data"
    with wall(data, unlock_secret=SECRET) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
    # Two-factor switched off from the command line, without saying --unlock-file: that is no start of the
    # wall, and takes nothing away.
    assert cli.main(["--data-dir", str(data), "--disable-2fa", "admin"]) == 0
    assert Store(data / "qkvm.json").unlock is not None
    assert cli.main(["--data-dir", str(data), "--reset-password"]) == 0  # the saved passwords are erased with the accounts
    assert Store(data / "qkvm.json").unlock is None


def test_a_wall_stopped_right_after_the_first_sign_in_still_opens_by_itself_the_next_time(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The note that opens the saved passwords at the next start is made after the first sign-in, in the
    # background (it takes as long as checking a password does), and then written. A wall that was stopped in
    # that moment cut it off: it had been signed in to, was restarted, and stood locked. Seen on a slow
    # machine, where two tests here ended in that moment; what a sign-in set going is finished now.
    as_it_is = vault.Vault.rewrap

    def taking_its_time(self: vault.Vault, secret: str) -> Any:
        time.sleep(0.5)
        return as_it_is(self, secret)

    monkeypatch.setattr(vault.Vault, "rewrap", taking_its_time)
    data = tmp_path / "data"
    with wall(data) as admin:
        assert admin.get("/api/v1/session").json()["user"]["name"]  # signed in, and stopped at once
    assert Store(data / "qkvm.json").unlock is not None
    with wall(data, sign_in=False) as later:
        assert later.get("/healthz").json()["locked"] is False


def test_the_unlock_file_is_made_if_it_is_not_there_and_refused_if_it_cannot_do_its_job(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = tmp_path / "data"
    data.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    made = elsewhere / "qkvm-unlock.key"
    secret, new = unlock.secret_in(made, data)
    assert new is True and len(secret) >= unlock.SHORTEST and made.read_text(encoding="ascii").strip() == secret
    if os.name == "posix":
        assert stat.S_IMODE(made.stat().st_mode) == 0o600  # its owner's alone
        assert unlock.open_to_others(made) is False
        made.chmod(0o644)
        assert unlock.open_to_others(made) is True
    assert unlock.secret_in(made, data) == (secret, False)  # the same one at every later start

    own = elsewhere / "own.key"
    own.write_text("  one-that-somebody-made-themselves-and-long-enough  \n", encoding="utf-8")
    assert unlock.secret_in(own, data) == ("one-that-somebody-made-themselves-and-long-enough", False)

    # In the data folder it would be copied with it, and open whatever copy is taken.
    with pytest.raises(ValueError, match="data folder"):
        unlock.secret_in(data / "unlock.key", data)
    with pytest.raises(ValueError, match="data folder"):
        unlock.secret_in(data / "tls" / ".." / "deeper" / "unlock.key", data)
    assert not (data / "unlock.key").exists()
    short = elsewhere / "short.key"
    short.write_text("hunter2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="too short"):
        unlock.secret_in(short, data)
    with pytest.raises(ValueError, match="cannot be"):
        unlock.secret_in(elsewhere / "no such folder" / "unlock.key", data)

    # Said at start, in a sentence, by the program as it is started.
    assert cli.main(["--data-dir", str(data), "--unlock-file", str(data / "unlock.key"), "--disable-2fa", "nobody"]) == 2
    assert "data folder" in capsys.readouterr().err


def test_the_unlock_file_is_known_for_being_in_the_data_folder_however_its_path_is_written(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    inside = (data / "deep" / "unlock.key")
    inside.parent.mkdir()
    spellings = [str(inside)]
    if os.name == "nt":
        spellings += ["\\\\?\\" + str(inside.resolve()), "\\\\localhost\\" + str(inside.resolve()).replace(":", "$", 1)]
    else:
        (tmp_path / "another way in").symlink_to(data, target_is_directory=True)
        spellings.append(str(tmp_path / "another way in" / "deep" / "unlock.key"))
    for path in spellings:
        with pytest.raises(ValueError, match="data folder"):
            unlock.secret_in(Path(path), data)
        assert not inside.exists(), path
    huge = tmp_path / "huge.key"
    huge.write_bytes(b"x" * 100_000)
    with pytest.raises(ValueError, match="too long"):  # a secret is a line, not whatever file the option was pointed at
        unlock.secret_in(huge, data)


def test_switched_off_the_unlock_file_opens_no_copy_that_is_still_lying_there(tmp_path: Path) -> None:
    import json

    data = tmp_path / "data"
    with wall(data, unlock_secret=SECRET) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        assert admin.put("/api/v1/alerts", json={"enabled": False}).status_code == 200  # (the copy from before a change has it by now)
    assert json.loads((data / "qkvm.bak").read_text(encoding="utf-8")).get("unlock")
    with wall(data, sign_in=False) as nobody:  # started without the option
        assert not fits(nobody)
    for name in ("qkvm.json", "qkvm.bak"):  # what the file opened is gone from the copy qKVM keeps of its settings too
        assert not json.loads((data / name).read_text(encoding="utf-8")).get("unlock"), name


# --- as it comes: a key of its own, and browsers that asked to be kept --------------------------------------------
# On the first day of three walls that had been restarted for one update after another, "Keep this browser
# signed in for 30 days" was found not to do what it says: ticked or not, every restart meant signing in
# again. What a restart does as the program comes was decided then: it carries on by itself.


def kept_sign_in(client: object, **who: str) -> str:
    """Sign in with "keep this browser signed in" ticked. Returns the cookie the browser then holds."""
    reply = client.post("/api/v1/login", json={"password": PASSWORD, "remember": True, **who})  # type: ignore[attr-defined]
    assert reply.status_code == 200, reply.text
    return str(client.cookies.get(COOKIE))  # type: ignore[attr-defined]


def let_in(client: object, cookie: str) -> bool:
    """Whether a browser that holds this cookie is taken for signed in."""
    client.cookies.clear()  # type: ignore[attr-defined]
    client.cookies.set(COOKIE, cookie)  # type: ignore[attr-defined]
    try:
        return bool(client.get("/api/v1/wall").status_code == 200)  # type: ignore[attr-defined]
    finally:
        client.cookies.clear()  # type: ignore[attr-defined]


def test_as_it_comes_a_wall_carries_on_by_itself_after_a_restart(tmp_path: Path, fake: FakeKvm) -> None:
    data = tmp_path / "data"
    with wall(data) as admin:
        device = add(admin, fake.url)
        ordinary = str(admin.cookies.get(COOKIE))  # the sign-in `wall` made: without the box ticked
        cookie = kept_sign_in(admin)
        wait_until(lambda: fits(admin), "qKVM's own key was never made to fit this data folder")
        assert admin.get("/api/v1/session").json()["unlocks_at_start"] is True
    assert (data / "unlock.key").is_file() and len((data / "unlock.key").read_text(encoding="ascii").strip()) >= unlock.SHORTEST
    written = (data / "sessions.json").read_text(encoding="ascii")
    assert cookie not in written and ordinary not in written  # a hash of the cookie is kept, never the cookie

    with wall(data, sign_in=False) as later:  # restarted; nobody has typed anything
        assert later.get("/healthz").json()["locked"] is False  # it watches, alerts and answers a collector again
        assert "unlocked_at_start" in [entry["event"] for entry in later.core.audit.tail(5)]  # type: ignore[attr-defined]
        assert later.get("/api/v1/wall").status_code == 401  # opened for the program, not for whoever comes by
        assert let_in(later, cookie)  # the browser that asked to be kept is still signed in
        assert not let_in(later, ordinary)  # one that did not ask is asked again, as before
        later.cookies.set(COOKIE, cookie)
        assert [entry["id"] for entry in later.get("/api/v1/wall").json()["devices"]] == [device]
        assert later.post("/api/v1/logout", json={}).status_code == 200
    with wall(data, sign_in=False) as again:
        assert not let_in(again, cookie)  # signed out is signed out, a restart later too


def test_a_browser_kept_signed_in_is_not_let_in_after_a_restart_once_it_should_not_be(tmp_path: Path) -> None:
    # What is written down to outlast a restart is not what decides: the accounts as they are saved do.
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        ids = {name: account(admin, name, "viewer") for name in ("vera", "sam", "rosa", "kim")}
        cookies = {name: kept_sign_in(browser(admin, name), name=name, password=OTHER) for name in ids}
        admin.core.sessions.flush()  # type: ignore[attr-defined]
        written = (data / "sessions.json").read_bytes()
        # Each of these also ends the sign-in at once; the file is put back afterwards as it was before,
        # as if it had not been written again (a disk that was full at that moment).
        assert admin.put(f"/api/v1/users/{ids['vera']}", json={"name": "vera", "role": "viewer", "password": "a new one, long enough"}).status_code == 200
        assert admin.put(f"/api/v1/users/{ids['sam']}", json={"name": "sam", "role": "viewer", "suspended": True}).status_code == 200
        assert admin.delete(f"/api/v1/users/{ids['rosa']}").status_code == 200
    (data / "sessions.json").write_bytes(written)
    with wall(data, sign_in=False) as later:
        assert later.get("/healthz").json()["locked"] is False
        assert let_in(later, cookies["kim"])  # nothing changed for this one
        assert not let_in(later, cookies["vera"])  # a password that was changed ends what was signed in with the old one
        assert not let_in(later, cookies["sam"])  # suspended
        assert not let_in(later, cookies["rosa"])  # no longer an account


def test_what_is_written_down_of_a_sign_in_is_not_believed_beyond_what_it_can_show(tmp_path: Path) -> None:
    import hashlib
    import json
    import time

    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        user = admin.get("/api/v1/session").json()["user"]["id"]
    made_up = "a-cookie-somebody-made-up"
    key = hashlib.sha256(made_up.encode()).hexdigest()
    for said in ([time.time(), user, "not-the-mark"], [time.time() - 40 * 86400, user, "x"], ["yesterday", user, "x"], [time.time(), 7, "x"], "admin"):
        (data / "sessions.json").write_text(json.dumps({key: said, "not a hash": [time.time(), user, "x"]}), encoding="ascii")
        with wall(data, sign_in=False) as later:
            assert not let_in(later, made_up), said
    (data / "sessions.json").write_bytes(b"[" * 5000)  # not a list of sign-ins at all
    with wall(data, sign_in=False) as later:
        assert later.get("/healthz").json()["locked"] is False and not let_in(later, made_up)


def test_started_locked_a_wall_keeps_no_key_and_no_sign_in(tmp_path: Path) -> None:
    # The way it was, for whoever wants it: nothing in the data folder opens the saved passwords, a copy of
    # the folder is worth nothing without an account's password, and after a restart somebody signs in.
    data = tmp_path / "data"
    with wall(data, locked_start=True) as admin:
        cookie = kept_sign_in(admin)
        assert admin.get("/api/v1/session").json()["unlocks_at_start"] is False
        assert admin.core.unlock_secret is None and not fits(admin)  # type: ignore[attr-defined]
    assert not (data / "unlock.key").exists() and not (data / "sessions.json").exists()
    with wall(data, sign_in=False, locked_start=True) as later:
        assert later.get("/healthz").json()["locked"] is True and not let_in(later, cookie)

    # A wall that ran as it comes and is then started locked: what carried it on is taken out of the folder.
    carried = tmp_path / "carried"
    with wall(carried) as admin:
        cookie = kept_sign_in(admin)
        wait_until(lambda: fits(admin), "never made to fit")
    assert (carried / "unlock.key").exists() and (carried / "sessions.json").exists()
    with wall(carried, sign_in=False, locked_start=True) as later:
        assert later.get("/healthz").json()["locked"] is True and not let_in(later, cookie)
        assert not fits(later) and Store(carried / "qkvm.json").unlock is None
    assert not (carried / "unlock.key").exists() and not (carried / "sessions.json").exists()


def test_a_key_kept_elsewhere_leaves_none_in_the_data_folder(tmp_path: Path) -> None:
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
    assert (data / "unlock.key").exists()
    with wall(data, sign_in=False, unlock_secret=SECRET) as later:  # from now on with --unlock-file
        assert not (data / "unlock.key").exists()
        assert later.get("/healthz").json()["locked"] is True  # the file fits from the next sign-in on, as it says
        cookie = kept_sign_in(later)
        wait_until(lambda: fits(later), "the unlock file was never made to fit")
    with wall(data, sign_in=False, unlock_secret=SECRET) as later:
        assert later.get("/healthz").json()["locked"] is False and let_in(later, cookie)  # kept signed in there too


def test_locked_start_and_an_unlock_file_cannot_both_be_asked_for(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--data-dir", str(tmp_path / "data"), "--locked-start", "--unlock-file", str(tmp_path / "key")]) == 2
    assert "opposite" in capsys.readouterr().err and not (tmp_path / "key").exists()


def test_a_sign_out_is_not_undone_by_a_restart_when_it_could_not_be_written_down(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Whoever kept a copy of a cookie must not get in with it after its owner signed out, a restart later either.
    data = tmp_path / "data"
    disk = {"full": False, "held": False}
    real_open, real_unlink = os.open, os.unlink

    def open_while_there_is_room(path: Any, *args: Any, **kwargs: Any) -> int:
        if disk["full"] and str(path).endswith("sessions.json.new"):
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_open(path, *args, **kwargs)

    def unlink_what_is_not_held(path: Any, *args: Any, **kwargs: Any) -> None:
        if disk["held"] and str(path).endswith("sessions.json"):
            raise PermissionError(errno.EACCES, "Permission denied")
        real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", open_while_there_is_room)
    monkeypatch.setattr(os, "unlink", unlink_what_is_not_held)

    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        elsewhere = kept_sign_in(visitor(admin, 50002))  # the same account, in another browser
        cookie = kept_sign_in(admin)
        admin.core.sessions.flush()  # type: ignore[attr-defined]
        assert (data / "sessions.json").is_file()
        disk["full"] = True  # from here on nothing new can be written
        assert admin.post("/api/v1/logout", json={"scope": "this"}).status_code == 200
        assert not let_in(admin, cookie) and let_in(admin, elsewhere)
    with wall(data, sign_in=False) as later:
        assert not let_in(later, cookie)  # what named it could not be replaced, so it was taken away
        assert not let_in(later, elsewhere)  # the price: whoever asked to be kept signs in once more

    # Neither written nor taken away (a folder that has become read-only): then it is said, and not answered with "done".
    disk["full"] = False
    with wall(data) as admin:
        me = admin.get("/api/v1/session").json()["user"]["id"]
        other = kept_sign_in(visitor(admin, 50003))
        cookie = kept_sign_in(admin)
        admin.core.sessions.flush()  # type: ignore[attr-defined]
        disk.update(full=True, held=True)
        everywhere = admin.post(f"/api/v1/users/{me}/logout")
        assert (everywhere.status_code, everywhere.json()["code"]) == (507, "not_saved") and "restart" in everywhere.json()["message"]
        assert not let_in(visitor(admin, 50004), other)  # signed out all the same, for as long as qKVM runs
        admin.cookies.set(COOKIE, cookie)
        refused = admin.post("/api/v1/logout", json={"scope": "this"})
        assert (refused.status_code, refused.json()["code"]) == (507, "not_saved") and "restart" in refused.json()["message"]
        assert not let_in(admin, cookie)
        # The disk takes writes again: the next thing to be written down puts it right.
        disk.update(full=False, held=False)
        newer = kept_sign_in(admin)
    with wall(data, sign_in=False) as later:
        assert not let_in(later, cookie) and not let_in(later, other)
        assert let_in(later, newer)


def test_the_browser_a_password_was_changed_in_stays_signed_in_over_a_restart(tmp_path: Path) -> None:
    # Changing your own password signs the account out everywhere but in the browser it was done in. That one
    # was let in again after a restart only as long as the password was the old one: so it was kept, and then not.
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        other = kept_sign_in(visitor(admin, 50002))
        cookie = kept_sign_in(admin)
        assert admin.post("/api/v1/password", json={"current": PASSWORD, "new": "a newer one, long enough"}).status_code == 200
        assert let_in(visitor(admin, 50003), cookie) and not let_in(visitor(admin, 50004), other)
    with wall(data, sign_in=False) as later:
        assert let_in(later, cookie)
        assert not let_in(later, other)


def test_a_sign_out_waits_for_the_disk_only_where_its_sign_in_was_written_down(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # While what is on disk cannot be put right, "signed out, but a restart would undo it" is true of a browser
    # that was written down, and of no other: not of one that never asked to be kept, nor of a wall screen
    # (which, told so, signed itself in again).
    data = tmp_path / "data"
    disk = {"takes": True}
    real_open, real_unlink = os.open, os.unlink

    def open_if_it_takes(path: Any, *args: Any, **kwargs: Any) -> int:
        if not disk["takes"] and str(path).endswith("sessions.json.new"):
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_open(path, *args, **kwargs)

    def unlink_if_it_takes(path: Any, *args: Any, **kwargs: Any) -> None:
        if not disk["takes"] and str(path).endswith("sessions.json"):
            raise PermissionError(errno.EACCES, "Permission denied")
        real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", open_if_it_takes)
    monkeypatch.setattr(os, "unlink", unlink_if_it_takes)
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        key = admin.post("/api/v1/tokens", json={"name": "screen in the hall", "kind": "display"}).json()["token"]
        kept = visitor(admin, 50002)
        kept_sign_in(kept)
        admin.core.sessions.flush()  # type: ignore[attr-defined]
        ordinary = visitor(admin, 50003)
        assert ordinary.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
        screen = visitor(admin, 50004)
        assert screen.post("/api/v1/display", json={"key": key}).status_code == 200
        disk["takes"] = False
        assert kept.post("/api/v1/logout", json={"scope": "this"}).status_code == 507
        assert ordinary.post("/api/v1/logout", json={"scope": "this"}).status_code == 200
        assert screen.post("/api/v1/logout", json={"scope": "this"}).status_code == 200


def test_a_disk_that_does_not_answer_holds_no_thread_for_good(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Whoever signs out waits for the disk, in a thread. A disk that takes a write and never comes back with it
    # held that thread for good, one for every sign-out, until none was left to check a password in.
    from qkvm import server

    data = tmp_path / "data"
    hangs, let_go, real_replace = threading.Event(), threading.Event(), os.replace

    def replace_or_hang(source: Any, target: Any, *args: Any, **kwargs: Any) -> None:
        if hangs.is_set() and str(target).endswith("sessions.json"):
            let_go.wait(60)
        real_replace(source, target, *args, **kwargs)

    monkeypatch.setattr(os, "replace", replace_or_hang)
    monkeypatch.setattr(server, "SAVE_WITHIN", 0.2)  # (ten seconds as it comes)
    monkeypatch.setattr(security, "MOST_KEPT_OF_ONE", 100)  # (all of these are one account's, and all are to be written down)
    threads = min(32, (os.cpu_count() or 1) + 4)  # what asyncio has to do such waiting in
    try:
        with wall(data) as admin:
            wait_until(lambda: fits(admin), "never made to fit")
            browsers = [visitor(admin, 52000 + number) for number in range(threads + 2)]
            for other in browsers:
                kept_sign_in(other)
            admin.core.sessions.flush()  # type: ignore[attr-defined]
            hangs.set()
            answers = {other.post("/api/v1/logout", json={"scope": "this"}).status_code for other in browsers}
            assert answers == {507}  # said, each after a fifth of a second, and each thread given back
            assert visitor(admin, 53000).post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
            let_go.set()
    finally:
        let_go.set()


def test_a_disk_that_stays_full_is_said_once_and_tried_now_and_then(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from qkvm import security

    attempts, said = [], []
    real_open = os.open

    def no_room(path: Any, *args: Any, **kwargs: Any) -> int:
        if str(path).endswith("sessions.json.new"):
            attempts.append(1)
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", no_room)
    monkeypatch.setattr(security.log, "warning", lambda *args, **kwargs: said.append(args))
    sessions = security.Sessions(tmp_path / "sessions.json")
    sessions.create("203.0.113.9", remember=True, user="ab12cd34", mark="m")
    sessions.settled()
    for _ in range(20):
        len(sessions)  # every look at how many are signed in was an occasion for one more attempt, and one more warning
    sessions.settled()
    assert len(attempts) == 1 and len(said) == 1
    monkeypatch.setattr(security, "TRY_AGAIN", 0.0)
    sessions.create("203.0.113.9", remember=True, user="ab12cd34", mark="m")  # a change is an occasion
    sessions.settled()
    assert len(attempts) == 2 and len(said) == 1
    assert not (tmp_path / "sessions.json.new").exists()
