"""A browser kept signed in over a restart: what one start did not take up no later one does, a second step switched on since ends it, and neither clock keeps it past its time."""

from __future__ import annotations

import errno
import json
import time
from pathlib import Path

import pytest

from qkvm import kvm, unlock, update, vault
from tests.test_totp import switch_on
from tests.test_unlock import fits, kept_sign_in, let_in
from tests.test_users import visitor
from tests.test_wall import PASSWORD, wait_until, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def key_not_readable(folder: Path) -> str:
    raise PermissionError(errno.EACCES, "Permission denied", str(folder / unlock.OWN))


# --- A: a start in which the key could not be read (Sessions.set_aside) ---------------------------------------


def test_signed_out_everywhere_in_a_start_whose_key_could_not_be_read_stays_signed_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        cookie = kept_sign_in(visitor(admin, 50002))  # another computer of the admin's, kept signed in; its cookie is the one in doubt
        admin.core.sessions.flush()  # type: ignore[attr-defined]
    with monkeypatch.context() as once:
        once.setattr(unlock, "own_secret", key_not_readable)
        with wall(data) as hindered:  # the key cannot be read at this start; the admin signs in with the password
            me = hindered.get("/api/v1/session").json()["user"]["id"]
            everywhere = hindered.post(f"/api/v1/users/{me}/logout")
            out = hindered.post("/api/v1/logout", json={"scope": "all"})
            print("\nsign out everywhere:", everywhere.status_code, everywhere.json(), "| and this browser:", out.status_code, out.json())
            assert (everywhere.status_code, out.status_code) == (200, 200)
    print("sessions.json after that run:", (data / "sessions.json").exists())
    with wall(data, sign_in=False) as later:  # the next start, with nothing in its way
        back = let_in(later, cookie)
        print("the browser that was kept signed in before is let in again:", back)
        assert not back, "signed out everywhere, answered 200, and let in again after the next start"


def test_a_second_step_switched_on_in_a_start_whose_key_could_not_be_read_is_asked_of_the_kept_browser(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        cookie = kept_sign_in(visitor(admin, 50002))
        admin.core.sessions.flush()  # type: ignore[attr-defined]
    with monkeypatch.context() as once:
        once.setattr(unlock, "own_secret", key_not_readable)
        with wall(data) as hindered:
            switch_on(hindered, PASSWORD)  # "switched on against somebody who has the password"
    with wall(data, sign_in=False) as later:
        assert later.post("/api/v1/login", json={"password": PASSWORD}).json()["code"] == "code_required"  # the account has it
        back = let_in(later, cookie)
        print("\nthe account asks for a code; the browser kept signed in with the password alone is let in:", back)
        assert not back


# --- A2: the second step and what is written down (the same standard as test_unlock's password, suspension, removal) ---


def test_a_second_step_ends_a_kept_sign_in_whether_or_not_the_file_was_written_since(tmp_path: Path) -> None:
    # test_unlock: "What is written down to outlast a restart is not what decides: the accounts as they are saved do."
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        cookie = kept_sign_in(visitor(admin, 50002))
        admin.core.sessions.flush()  # type: ignore[attr-defined]
        written = (data / "sessions.json").read_bytes()
        switch_on(admin, PASSWORD)
    (data / "sessions.json").write_bytes(written)  # as if it had not been written again (killed before the writer's turn; a file that was held)
    with wall(data, sign_in=False) as later:
        back = let_in(later, cookie)
        print("\nkept with the password alone, the second step switched on since: let in after a restart:", back)
        assert not back


# --- B: the clock at start ------------------------------------------------------------------------------------


def test_a_kept_sign_in_does_not_live_longer_because_the_clock_was_behind_at_start(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A computer with no clock of its own starts at the time it last wrote down, and is put right a moment later.
    real = time.time
    clock = {"off": 0.0}
    monkeypatch.setattr(time, "time", lambda: real() + clock["off"])
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        cookie = kept_sign_in(admin)
        admin.core.sessions.flush()  # type: ignore[attr-defined]
    # It was switched off right after, and stood for sixty days. It starts with the clock where it was, ...
    clock["off"] = 60.0
    with wall(data, sign_in=False) as later:
        clock["off"] = 60 * 86400.0  # ... and the time server puts it right: sixty days have passed
        back = let_in(later, cookie)
        age = max((s.age() for s in later.core.sessions._sessions.values()), default=0.0)  # type: ignore[attr-defined]
        print(f"\nsixty days after the sign-in: let in {back}; taken to be {age / 86400:.2f} days old")
        assert not back, "kept for 30 days, and let in on the sixtieth"


def test_a_sign_in_not_taken_up_at_one_start_is_not_taken_up_at_the_next_after_signing_out_everywhere(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real = time.time
    clock = {"off": 0.0}
    monkeypatch.setattr(time, "time", lambda: real() + clock["off"])
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        cookie = kept_sign_in(visitor(admin, 50002))
        admin.core.sessions.flush()  # type: ignore[attr-defined]
    clock["off"] = -3600.0  # this start finds the clock an hour behind (no battery, no time server yet)
    with wall(data) as early:
        assert not let_in(visitor(early, 50003), cookie)  # "made in the future": not taken up
        me = early.get("/api/v1/session").json()["user"]["id"]
        everywhere = early.post(f"/api/v1/users/{me}/logout")
        out = early.post("/api/v1/logout", json={"scope": "all"})
        assert (everywhere.status_code, out.status_code) == (200, 200)
    left = json.loads((data / "sessions.json").read_text(encoding="ascii")) if (data / "sessions.json").exists() else {}
    clock["off"] = 0.0
    with wall(data, sign_in=False) as later:
        back = let_in(later, cookie)
        print(f"\nsessions.json after signing out everywhere still names {len(left)} browser(s); let in at the next start: {back}")
        assert not back


def test_a_second_step_whose_signing_out_could_not_be_written_down_is_said_as_a_sign_out_is(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # As test_unlock's "neither written nor taken away (a folder that has become read-only): then it is said".
    import os
    from typing import Any

    from tests.test_totp import code_for

    data = tmp_path / "data"
    disk = {"held": False}
    real_open, real_unlink = os.open, os.unlink

    def open_unless_held(path: Any, *args: Any, **kwargs: Any) -> int:
        if disk["held"] and str(path).endswith("sessions.json.new"):
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_open(path, *args, **kwargs)

    def unlink_unless_held(path: Any, *args: Any, **kwargs: Any) -> None:
        if disk["held"] and str(path).endswith("sessions.json"):
            raise PermissionError(errno.EACCES, "Permission denied")
        real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", open_unless_held)
    monkeypatch.setattr(os, "unlink", unlink_unless_held)
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        elsewhere = kept_sign_in(visitor(admin, 50002))  # whoever has the password, kept signed in
        admin.core.sessions.flush()  # type: ignore[attr-defined]
        disk["held"] = True
        secret = str(admin.post("/api/v1/totp/begin", json={"password": PASSWORD}).json()["secret"])
        enabled = admin.post("/api/v1/totp/enable", json={"code": code_for(secret)})
        assert not let_in(visitor(admin, 50003), elsewhere)  # out at once
        admin.core.sessions.flush()  # type: ignore[attr-defined]
        print("\nsecond step switched on, with sessions.json neither to be written nor removed:", enabled.status_code, sorted(enabled.json()))
    disk["held"] = False
    with wall(data, sign_in=False) as later:
        back = let_in(later, elsewhere)
        print("after a restart the browser that never gave a code is let in:", back)
        assert enabled.status_code != 200 or not back, "answered 200 with nothing said, and the browser signed in with the password alone is back after a restart"
