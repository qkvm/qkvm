"""A browser kept signed in, continued: the second step switched on and off again, a file that could not be written, a clock that was ahead for a moment, many sign-ins of a few accounts."""

from __future__ import annotations

import errno
import json
import os
import time
from pathlib import Path
from typing import Any

import pytest

from qkvm import kvm, security, unlock, update, vault
from qkvm.cli import main as run_cli
from qkvm.security import COOKIE, Sessions
from tests.test_totp import code_for, switch_on
from tests.test_unlock import fits, kept_sign_in, let_in
from tests.test_users import OTHER, account, browser, visitor
from tests.test_wall import PASSWORD, wait_until, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def held_disk(monkeypatch: pytest.MonkeyPatch) -> dict[str, bool]:
    """sessions.json can be neither written anew nor removed while disk['held'] (a folder gone read-only)."""
    disk = {"held": False}
    real_open, real_unlink = os.open, os.unlink

    def open_unless_held(path: Any, *args: Any, **kwargs: Any) -> int:
        if disk["held"] and str(path).endswith("sessions.json.new"):
            raise OSError(errno.EROFS, "Read-only file system")
        return real_open(path, *args, **kwargs)

    def unlink_unless_held(path: Any, *args: Any, **kwargs: Any) -> None:
        if disk["held"] and str(path).endswith("sessions.json"):
            raise PermissionError(errno.EACCES, "Permission denied")
        real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", open_unless_held)
    monkeypatch.setattr(os, "unlink", unlink_unless_held)
    return disk


# --- 1. the second step: on, then off again -------------------------------------------------------------------


def test_a_browser_signed_out_by_the_second_step_stays_out_when_the_step_is_switched_off_again(tmp_path: Path) -> None:
    # The standard of test_kept_signins.test_a_second_step_ends_a_kept_sign_in_whether_or_not_the_file_was_written_since:
    # "as if it had not been written again". The mark with no second step is the mark from before it was on.
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        cookie = kept_sign_in(visitor(admin, 50002))
        admin.core.sessions.flush()  # type: ignore[attr-defined]
        written = (data / "sessions.json").read_bytes()
        switch_on(admin, PASSWORD)  # signs every other browser of the account out
        assert not let_in(visitor(admin, 50003), cookie)
        assert admin.post("/api/v1/totp/disable", json={"password": PASSWORD}).status_code == 200
        assert not let_in(visitor(admin, 50004), cookie)  # still out, while it runs
    (data / "sessions.json").write_bytes(written)  # as if it had not been written again
    with wall(data, sign_in=False) as later:
        back = let_in(later, cookie)
        print("\n[1] signed out when the second step was switched on; step switched off again; file as before: let in after restart:", back)
        assert not back


def test_second_step_on_then_off_with_a_disk_that_takes_nothing_and_nobody_is_told(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = tmp_path / "data"
    disk = held_disk(monkeypatch)
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        elsewhere = kept_sign_in(visitor(admin, 50002))
        admin.core.sessions.flush()  # type: ignore[attr-defined]
        disk["held"] = True
        secret = str(admin.post("/api/v1/totp/begin", json={"password": PASSWORD}).json()["secret"])
        on = admin.post("/api/v1/totp/enable", json={"code": code_for(secret)})
        off = admin.post("/api/v1/totp/disable", json={"password": PASSWORD})
        admin.core.sessions.flush()  # type: ignore[attr-defined]
    disk["held"] = False
    with wall(data, sign_in=False) as later:
        back = let_in(later, elsewhere)
        print(f"\n[1b] on: {on.status_code}, off: {off.status_code}; the browser signed out by 'on' is let in after a restart: {back}")
        assert (on.status_code, off.status_code) != (200, 200) or not back


# --- 2. what stays: the browser the step was switched on in, and all of them when it is switched off --------------


def test_the_browser_the_second_step_was_switched_on_in_stays_over_a_restart(tmp_path: Path) -> None:
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        here = kept_sign_in(admin)
        other = kept_sign_in(visitor(admin, 50002))
        switch_on(admin, PASSWORD)
    with wall(data, sign_in=False) as later:
        print("\n[2] enabling browser kept:", let_in(later, here), "| other browser kept:", let_in(later, other))
        assert let_in(later, here) and not let_in(later, other)


def test_switching_the_second_step_off_keeps_the_accounts_browsers_over_a_restart(tmp_path: Path) -> None:
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        victor = account(admin, "victor", "viewer")
        first = browser(admin, "victor", port=50011)
        secret = switch_on(first, OTHER)
        second = visitor(admin, 50012)
        reply = second.post("/api/v1/login", json={"name": "victor", "password": OTHER, "code": code_for(secret, 1), "remember": True})
        assert reply.status_code == 200, reply.text
        kept = str(second.cookies.get(COOKIE))
        assert admin.put(f"/api/v1/users/{victor}", json={"name": "victor", "role": "viewer", "totp_off": True}).status_code == 200  # an admin, for a lost phone
        mine = kept_sign_in(admin, name="admin")
        switch_on(admin, PASSWORD)
        assert admin.post("/api/v1/totp/disable", json={"password": PASSWORD}).status_code == 200  # oneself
    with wall(data, sign_in=False) as later:
        print("\n[2b] admin switched victor's step off, victor's kept browser:", let_in(later, kept), "| own step off, own kept browser:", let_in(later, mine))
        assert let_in(later, kept) and let_in(later, mine)


def test_disable_2fa_from_the_command_line_and_the_accounts_kept_browsers(tmp_path: Path, capsys: Any) -> None:
    # In the page, switching the second step off keeps the account's browsers ("less is asked of them than they
    # gave"): the running program gives each of them the account's new mark. The command line has no running
    # program to do that in, and is what somebody uses who cannot sign in: the account's kept browsers sign
    # in once more, with the password alone.
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        here = kept_sign_in(admin)
        switch_on(admin, PASSWORD)
    assert run_cli(["--data-dir", str(data), "--disable-2fa", "admin"]) == 0
    capsys.readouterr()
    with wall(data, sign_in=False) as later:
        stays = let_in(later, here)
        assert not stays
        assert later.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200  # and no code is asked for


# --- 3. a start that could not write, and a sign-out in it --------------------------------------------------------


def test_signing_out_everywhere_is_not_answered_as_done_while_the_file_names_what_was_not_taken_up(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # test_kept_signins.test_a_sign_in_not_taken_up_at_one_start_is_not_taken_up_at_the_next_after_signing_out_everywhere,
    # at a start whose rewrite of the file fails and the file cannot be removed either.
    real = time.time
    clock = {"off": 0.0}
    monkeypatch.setattr(time, "time", lambda: real() + clock["off"])
    disk = held_disk(monkeypatch)
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        cookie = kept_sign_in(visitor(admin, 50002))
        admin.core.sessions.flush()  # type: ignore[attr-defined]
    clock["off"] = -3600.0
    disk["held"] = True
    with wall(data) as early:
        assert not let_in(visitor(early, 50003), cookie)
        early.core.sessions.settled()  # type: ignore[attr-defined]
        stale = early.core.sessions._stale  # type: ignore[attr-defined]
        me = early.get("/api/v1/session").json()["user"]["id"]
        everywhere = early.post(f"/api/v1/users/{me}/logout")
        out = early.post("/api/v1/logout", json={"scope": "all"})
    disk["held"] = False
    clock["off"] = 0.0
    with wall(data, sign_in=False) as later:
        back = let_in(later, cookie)
        print(f"\n[3] the program knows the file is stale ({stale!r}); sign out everywhere answered {everywhere.status_code}/{out.status_code}; let in at the next start: {back}")
        assert not back or 507 in (everywhere.status_code, out.status_code)


# --- 4. the clock -------------------------------------------------------------------------------------------------


def test_a_clock_that_was_ahead_for_a_moment_ends_no_sign_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real = time.time
    clock = {"off": 0.0}
    monkeypatch.setattr(time, "time", lambda: real() + clock["off"])
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        ordinary = str(admin.cookies.get(COOKIE))  # a twelve-hour sign-in, made a second ago
        kept = kept_sign_in(visitor(admin, 50002))
        admin.core.sessions.flush()  # type: ignore[attr-defined]
        clock["off"] = 31 * 86400.0  # the clock is put a month ahead by mistake ...
        len(admin.core.sessions)  # type: ignore[attr-defined]  # ... one round of housekeeping (every 30 s) ...
        clock["off"] = 0.0  # ... and it is put right
        still = (let_in(visitor(admin, 50003), ordinary), let_in(visitor(admin, 50004), kept))
        admin.core.sessions.flush()  # type: ignore[attr-defined]
        on_disk = json.loads((data / "sessions.json").read_text(encoding="ascii")) if (data / "sessions.json").exists() else None
        print(f"\n[4] after the clock was a month ahead for one housekeeping round: ordinary sign-in alive {still[0]}, kept one alive {still[1]}, sessions.json: {on_disk}")
        assert still == (True, True)


# --- 5. how many --------------------------------------------------------------------------------------------------


def test_one_accounts_sign_ins_end_nobody_elses(tmp_path: Path) -> None:
    sessions = Sessions(tmp_path / "sessions.json")
    admin = sessions.create("192.0.2.1", True, "aaaaaaaa", mark="m")
    screen = sessions.create("192.0.2.2", True, "token:bbbbbbbb", mark="m")
    for _ in range(security.MOST_OF_ONE + 50):
        sessions.create("192.0.2.9", True, "cccccccc", mark="m")
    counts = sessions.counts()
    print("\n[5] after 150 sign-ins of one account:", counts)
    assert sessions.get(admin) is not None and sessions.get(screen) is not None and counts["cccccccc"] == security.MOST_OF_ONE


def test_low_accounts_cannot_push_an_admins_kept_sign_in_out_of_the_file(tmp_path: Path) -> None:
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        mine = kept_sign_in(visitor(admin, 50002))
        names = [f"low{number}" for number in range(5)]
        for name in names:
            account(admin, name, "viewer")
        guest = visitor(admin, 50003)
        began = time.monotonic()
        for name in names:
            for _ in range(security.MOST_OF_ONE):
                assert guest.post("/api/v1/login", json={"name": name, "password": OTHER, "remember": True}).status_code == 200
        took = time.monotonic() - began
        assert let_in(visitor(admin, 50004), mine)  # while it runs, nothing happened to it
        admin.core.sessions.flush()  # type: ignore[attr-defined]
        written = json.loads((data / "sessions.json").read_text(encoding="ascii"))
    with wall(data, sign_in=False) as later:
        back = let_in(later, mine)
        print(f"\n[5b] 5 viewer accounts x {security.MOST_OF_ONE} kept sign-ins ({took:.0f} s at test cost); file names {len(written)}; the admin's kept browser after a restart: {back}")
        assert back


# --- 5c. suspended over a restart, then resumed -------------------------------------------------------------------


def test_a_browser_of_an_account_suspended_over_a_restart_is_not_back_when_the_account_is(tmp_path: Path) -> None:
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        sam = account(admin, "sam", "viewer")
        his = kept_sign_in(browser(admin, "sam"), name="sam", password=OTHER)
        admin.core.sessions.flush()  # type: ignore[attr-defined]
        written = (data / "sessions.json").read_bytes()
        assert admin.put(f"/api/v1/users/{sam}", json={"name": "sam", "role": "viewer", "suspended": True}).status_code == 200
    (data / "sessions.json").write_bytes(written)  # as if it had not been written again
    with wall(data, sign_in=False) as while_suspended:
        assert not let_in(while_suspended, his)
        assert while_suspended.post("/api/v1/login", json={"name": "admin", "password": PASSWORD}).status_code == 200
        assert while_suspended.put(f"/api/v1/users/{sam}", json={"name": "sam", "role": "viewer", "suspended": False}).status_code == 200
    with wall(data, sign_in=False) as later:
        back = let_in(later, his)
        print("\n[5c] suspended, restarted, resumed, restarted: the browser from before the suspension is let in:", back)
        assert not back


# --- 6. a start whose key could not be read ---------------------------------------------------------------------


def test_what_a_start_without_its_key_says_about_the_kept_sign_ins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        cookie = kept_sign_in(visitor(admin, 50002))
        admin.core.sessions.flush()  # type: ignore[attr-defined]

    def key_not_readable(folder: Path) -> str:
        raise PermissionError(errno.EACCES, "Permission denied", str(folder / unlock.OWN))

    from qkvm.core import Core

    with monkeypatch.context() as once:
        once.setattr(unlock, "own_secret", key_not_readable)
        core = Core(data)
        told = core.unlock_at_start()
    gone = not (data / "sessions.json").exists()
    print(f"\n[6] key unreadable once: sessions.json removed: {gone}; what is said at start: {told!r}")
    with wall(data, sign_in=False) as later:
        print("    the next start (key readable): kept browser let in:", let_in(later, cookie))
    assert not gone or (told is not None and "sign" in told and "kept" in told)
