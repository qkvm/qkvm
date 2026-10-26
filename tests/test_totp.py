from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from qkvm import kvm, totp, update, vault
from qkvm.cli import main as run_cli
from tests.test_users import OTHER, account, visitor
from tests.test_wall import PASSWORD, wall
from tests.settings_file import settings_text


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def code_for(spaced_secret: str, steps_from_now: int = 0) -> str:
    """What the person's authenticator app would show."""
    return totp.code_at(spaced_secret.replace(" ", ""), int(time.time() // totp.STEP) + steps_from_now)


def switch_on(client: TestClient, password: str) -> str:
    """Turn two-factor sign-in on for the signed-in account; returns the key their app now holds."""
    begun = client.post("/api/v1/totp/begin", json={"password": password})
    assert begun.status_code == 200, begun.text
    secret = str(begun.json()["secret"])
    assert client.post("/api/v1/totp/enable", json={"code": code_for(secret)}).status_code == 200
    return secret


def test_codes_match_the_standard() -> None:
    # RFC 6238, appendix B (SHA-1 key "12345678901234567890"), shortened to six digits.
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert totp.code_at(secret, 59 // 30) == "287082"
    assert totp.code_at(secret, 1111111109 // 30) == "081804"
    assert totp.code_at(secret, 20000000000 // 30) == "353130"
    assert totp.matching_step(secret, "287 082", now=59) == 1
    assert totp.matching_step(secret, "287082", now=59 + 30) == 1  # one step late still counts
    assert totp.matching_step(secret, "287082", now=59 + 90) is None
    assert totp.matching_step(secret, "28708", now=59) is None
    assert totp.matching_step(secret, "".join(chr(0x660 + int(d)) for d in "287082"), now=59) is None  # other scripts' digits
    assert totp.setup_uri("ABCD", "olga").startswith("otpauth://totp/qKVM%3Aolga?secret=ABCD&issuer=qKVM")
    assert len(totp.new_secret()) == 32 and totp.spaced("ABCDEFGH") == "ABCD EFGH"


def test_signing_in_then_needs_the_code_as_well(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        assert admin.get("/api/v1/session").json()["user"]["totp"] is False
        assert admin.post("/api/v1/totp/begin", json={"password": "not my password"}).status_code == 401
        begun = admin.post("/api/v1/totp/begin", json={"password": PASSWORD}).json()
        assert begun["uri"].startswith("otpauth://totp/qKVM%3Aadmin?secret=")
        # Not on until the app has proven it holds the key.
        assert admin.post("/api/v1/totp/enable", json={"code": "000000"}).status_code == 401
        assert admin.get("/api/v1/session").json()["user"]["totp"] is False
        assert admin.post("/api/v1/totp/enable", json={"code": code_for(begun["secret"])}).json()["user"]["totp"] is True
        assert admin.post("/api/v1/totp/begin", json={"password": PASSWORD}).status_code == 409
        secret = begun["secret"]
        assert secret.replace(" ", "") not in settings_text(tmp_path / "qkvm.json")  # the key is stored encrypted

    with wall(tmp_path, sign_in=False, locked_start=True) as client:  # restarted, and started locked: nothing is open until somebody is let in
        first = client.post("/api/v1/login", json={"password": PASSWORD})
        assert (first.status_code, first.json()["code"]) == (401, "code_required")
        assert client.get("/api/v1/wall").status_code == 401  # the right password alone opens nothing
        assert client.core.vault.unlocked is False  # type: ignore[attr-defined]
        assert client.post("/api/v1/login", json={"password": PASSWORD, "code": "123456"}).json()["code"] == "bad_code"
        wrong = client.post("/api/v1/login", json={"password": "wrong password!", "code": code_for(secret)})
        assert wrong.json()["code"] == "bad_password"
        # The code used while switching it on has been used; the next one works, once.
        code = code_for(secret, steps_from_now=1)
        assert client.post("/api/v1/login", json={"password": PASSWORD, "code": code}).status_code == 200
        assert client.get("/api/v1/wall").status_code == 200
        again = visitor(client, 50007)
        assert again.post("/api/v1/login", json={"password": PASSWORD, "code": code}).json()["code"] == "bad_code"

        # Switching it off takes the password, and then the password alone signs in again.
        assert client.post("/api/v1/totp/disable", json={"password": "nope nope nope"}).status_code == 401
        assert client.post("/api/v1/totp/disable", json={"password": PASSWORD}).json()["user"]["totp"] is False
        assert again.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
        events = [e["event"] for e in client.get("/api/v1/audit").json()["entries"]]
    assert "totp_enabled" in events and "totp_disabled" in events


def test_an_admin_or_the_command_line_can_switch_it_off_for_a_lost_phone(tmp_path: Path, capsys: Any) -> None:
    with wall(tmp_path) as admin:
        user = account(admin, "victor", "viewer")
        viewer = visitor(admin, 50008)
        assert viewer.post("/api/v1/login", json={"name": "victor", "password": OTHER}).status_code == 200
        switch_on(viewer, OTHER)  # a viewer may protect their own account
        listed = {u["name"]: u for u in admin.get("/api/v1/users").json()["users"]}
        assert listed["victor"]["totp"] is True and listed["admin"]["totp"] is False

        guest = visitor(admin, 50009)
        assert guest.post("/api/v1/login", json={"name": "victor", "password": OTHER}).json()["code"] == "code_required"
        edit = {"name": "victor", "role": "viewer", "totp_off": True}
        assert admin.put(f"/api/v1/users/{user}", json=edit).status_code == 200
        assert guest.post("/api/v1/login", json={"name": "victor", "password": OTHER}).status_code == 200

        switch_on(admin, PASSWORD)  # ...and the only admin loses their phone

    assert run_cli(["--data-dir", str(tmp_path), "--disable-2fa", "nobody"]) == 2
    assert run_cli(["--data-dir", str(tmp_path), "--disable-2fa", "admin"]) == 0
    assert "off for admin" in capsys.readouterr().out
    with wall(tmp_path, sign_in=False) as client:
        assert client.post("/api/v1/login", json={"name": "admin", "password": PASSWORD}).status_code == 200


def test_one_time_codes_stand_in_for_a_phone_that_is_not_at_hand(tmp_path: Path) -> None:
    # A lost phone used to mean asking an admin, or, for the only admin, the command line on the computer
    # qKVM runs on. Switching the second step on now hands out ten codes, each good for one sign-in.
    with wall(tmp_path) as admin:
        begun = admin.post("/api/v1/totp/begin", json={"password": PASSWORD}).json()
        enabled = admin.post("/api/v1/totp/enable", json={"code": code_for(begun["secret"])}).json()
        codes = enabled["recovery_codes"]
        assert len(codes) == len(set(codes)) == 10 and all(len(code) == 11 and code[5] == "-" for code in codes)
        assert enabled["user"]["recovery_codes"] == 10
        saved = settings_text(tmp_path / "qkvm.json")
        assert not any(code in saved or code.replace("-", "") in saved for code in codes)  # only what recognises them is kept

    with wall(tmp_path, sign_in=False) as client:  # restarted, and the phone is in a taxi
        assert client.post("/api/v1/login", json={"password": PASSWORD, "code": "aaaaa-bbbbb"}).json()["code"] == "bad_code"
        typed = codes[3].upper().replace("-", " ")  # however it is typed
        assert client.post("/api/v1/login", json={"password": PASSWORD, "code": typed}).status_code == 200
        assert client.get("/api/v1/session").json()["user"]["recovery_codes"] == 9
        again = visitor(client, 50021)
        assert again.post("/api/v1/login", json={"password": PASSWORD, "code": codes[3]}).json()["code"] == "bad_code"  # once
        assert again.post("/api/v1/login", json={"password": "not the password", "code": codes[4]}).json()["code"] == "bad_password"
        assert again.post("/api/v1/login", json={"password": PASSWORD, "code": codes[4]}).status_code == 200
        used = [e for e in client.get("/api/v1/audit").json()["entries"] if e["event"] == "login" and e.get("recovery_code")]
        assert [e["codes_left"] for e in used] == [8, 9]  # written down: somebody got in without the phone

        # New ones replace those that are left, for the price of the password.
        assert client.post("/api/v1/totp/codes", json={"password": "not it not it"}).status_code == 401
        fresh = client.post("/api/v1/totp/codes", json={"password": PASSWORD}).json()["recovery_codes"]
        assert len(fresh) == 10 and not set(fresh) & set(codes)
        assert again.post("/api/v1/logout", json={}).status_code == 200
        assert again.post("/api/v1/login", json={"password": PASSWORD, "code": codes[5]}).json()["code"] == "bad_code"
        assert again.post("/api/v1/login", json={"password": PASSWORD, "code": fresh[0]}).status_code == 200

    with wall(tmp_path, sign_in=False) as client:  # what was used stays used across a restart
        assert client.post("/api/v1/login", json={"password": PASSWORD, "code": fresh[0]}).json()["code"] == "bad_code"
        assert client.post("/api/v1/login", json={"password": PASSWORD, "code": fresh[1]}).status_code == 200
        # Switched off, the codes go with it; switched on again there are ten new ones.
        assert client.post("/api/v1/totp/disable", json={"password": PASSWORD}).json()["user"]["recovery_codes"] == 0
        assert client.post("/api/v1/totp/codes", json={"password": PASSWORD}).status_code == 409


def test_two_factor_sign_in_can_be_required(tmp_path: Path) -> None:
    # "Everybody who can press a power button has a second step": until now each account decided that for
    # itself, and nothing could be said about the wall as a whole.
    with wall(tmp_path) as admin:
        olga, victor = account(admin, "olga", "operator"), account(admin, "victor", "viewer")
        hers, his = visitor(admin, 50031), visitor(admin, 50032)
        assert hers.post("/api/v1/login", json={"name": "olga", "password": OTHER}).status_code == 200
        assert admin.get("/api/v1/security").json() == {"require_totp": "", "without": []}
        assert hers.put("/api/v1/security", json={"require_totp": "viewer"}).status_code == 403
        assert admin.put("/api/v1/security", json={"require_totp": "everybody"}).status_code == 422

        # Whoever sets it has it first: an admin cannot require of others what they have not done themselves.
        refused = admin.put("/api/v1/security", json={"require_totp": "operator"})
        assert (refused.status_code, refused.json()["code"]) == (409, "own_first")
        switch_on(admin, PASSWORD)
        set_to = admin.put("/api/v1/security", json={"require_totp": "operator"})
        assert set_to.status_code == 200 and set_to.json() == {"require_totp": "operator", "without": ["olga"]}

        # Olga is signed in, and from this moment can do one thing: set it up.
        assert hers.get("/api/v1/session").json()["user"]["must_enroll"] is True
        blocked = hers.get("/api/v1/wall")
        assert (blocked.status_code, blocked.json()["code"]) == (403, "totp_required")
        assert hers.get("/api/v1/actions").status_code == 403
        secret = switch_on(hers, OTHER)
        assert hers.get("/api/v1/session").json()["user"]["must_enroll"] is False and hers.get("/api/v1/wall").status_code == 200
        assert admin.get("/api/v1/security").json()["without"] == []
        # A viewer is not asked for it under this rule.
        assert his.post("/api/v1/login", json={"name": "victor", "password": OTHER}).status_code == 200
        assert his.get("/api/v1/wall").status_code == 200 and his.get("/api/v1/session").json()["user"]["must_enroll"] is False

        # Switching it off is still hers to do (a new phone), and leaves her where she started: setting it up.
        assert hers.post("/api/v1/totp/disable", json={"password": OTHER}).status_code == 200
        assert hers.get("/api/v1/wall").json()["code"] == "totp_required"
        switch_on(hers, OTHER)
        # An admin takes it off her account (the phone is gone): the next sign-in is by password, and to set it up.
        assert admin.put(f"/api/v1/users/{olga}", json={"name": "olga", "role": "operator", "totp_off": True}).status_code == 200
        later = visitor(admin, 50033)
        assert later.post("/api/v1/login", json={"name": "olga", "password": OTHER}).json()["user"]["must_enroll"] is True
        assert later.get("/api/v1/wall").status_code == 403 and later.post("/api/v1/logout", json={}).status_code == 200
        # Made an operator, the viewer is asked for it too; the rule lifted, nobody is.
        assert admin.put(f"/api/v1/users/{victor}", json={"name": "victor", "role": "operator"}).status_code == 200
        assert his.get("/api/v1/wall").json()["code"] == "totp_required"
        assert admin.put("/api/v1/security", json={"require_totp": ""}).status_code == 200
        assert his.get("/api/v1/wall").status_code == 200
        assert secret and "security_changed" in [e["event"] for e in admin.get("/api/v1/audit").json()["entries"]]


def test_codes_cannot_be_guessed_from_many_addresses(tmp_path: Path) -> None:
    # Wrong passwords are counted against the address they come from. For the second step that is not
    # enough: whoever has the password and a network to come from had five guesses at the code from each
    # of its addresses, and a code is one in a million.
    with wall(tmp_path) as admin:
        secret = switch_on(admin, PASSWORD)
        core = admin.core  # type: ignore[attr-defined]

        def guess(address: str, code: str) -> int:
            caller = TestClient(admin.app, headers={"X-QKVM": "1"}, client=(address, 50060))
            caller.portal = admin.portal
            return caller.post("/api/v1/login", json={"password": PASSWORD, "code": code}).status_code

        assert [guess(f"198.51.100.{n}", "000000") for n in range(1, 6)] == [401] * 5  # five addresses, a guess each
        assert guess("198.51.100.77", "000000") == 429  # from the sixth on it is the account that is held, whoever asks
        assert guess("198.51.100.78", code_for(secret, 1)) == 429  # the right code as well, for as long as that lasts
        wrong_password = TestClient(admin.app, headers={"X-QKVM": "1"}, client=("198.51.100.79", 50061))
        wrong_password.portal = admin.portal
        assert wrong_password.post("/api/v1/login", json={"password": "not the password", "code": "000000"}).status_code == 401  # says nothing about it
        core.limiter._failures.clear()  # the hold runs out
        assert guess("198.51.100.80", code_for(secret, 1)) == 200
        assert guess("198.51.100.81", "000000") == 401  # and a slip after a good sign-in starts from nothing again


def test_what_is_kept_of_a_one_time_code_is_of_no_use_without_the_data_key(tmp_path: Path) -> None:
    import hashlib

    with wall(tmp_path) as admin:
        begun = admin.post("/api/v1/totp/begin", json={"password": PASSWORD}).json()
        codes = admin.post("/api/v1/totp/enable", json={"code": code_for(begun["secret"])}).json()["recovery_codes"]
        me = admin.get("/api/v1/session").json()["user"]["id"]
    saved = settings_text(tmp_path / "qkvm.json")
    # Forty random bits can be tried through in minutes by whoever has the file, if all it takes is a hash.
    for code in codes:
        assert hashlib.sha256(f"{me}:{code.replace('-', '')}".encode()).hexdigest() not in saved


def test_an_admin_changes_their_own_password_where_the_current_one_is_asked_for(tmp_path: Path) -> None:
    # The accounts page let an admin give their own account a new password and take its second step off
    # without the current password: a browser left open for a minute was an account taken over for good.
    with wall(tmp_path) as admin:
        me = admin.get("/api/v1/session").json()["user"]["id"]
        switch_on(admin, PASSWORD)
        for change in ({"password": "a new one of their own"}, {"totp_off": True}):
            refused = admin.put(f"/api/v1/users/{me}", json={"name": "admin", "role": "admin", **change})
            assert (refused.status_code, refused.json()["code"]) == (409, "own_account"), change
        assert admin.get("/api/v1/session").json()["user"]["totp"] is True
        assert admin.put(f"/api/v1/users/{me}", json={"name": "root", "role": "admin"}).status_code == 200  # a name is another matter
        assert admin.post("/api/v1/password", json={"current": PASSWORD, "new": "a new one of their own"}).status_code == 200


def codes_around_now(spaced_secret: str) -> tuple[str, str, str]:
    """The code of the time step before this one, of this one and of the next: all three count as "now" (clocks differ).

    Taken where at least three seconds of this step are left, or else just after the next one has begun: where a step
    ended between taking the codes and the wall checking one, the one before was two steps old by then and refused,
    rightly (Windows with Python 3.11, loaded, on 2026-10-15: switching the second step on was answered 401)."""
    left = totp.STEP - time.time() % totp.STEP
    if left < 3:
        time.sleep(left + 0.05)
    key, step = spaced_secret.replace(" ", ""), int(time.time() // totp.STEP)
    return totp.code_at(key, step - 1), totp.code_at(key, step), totp.code_at(key, step + 1)


def test_a_code_that_was_used_stays_used_over_a_restart(tmp_path: Path) -> None:
    # Which code was accepted last was only remembered while qKVM ran. Somebody who had the password and had
    # seen a code being typed could use that code again after a restart, while its half minute lasted.
    with wall(tmp_path) as admin:
        secret = str(admin.post("/api/v1/totp/begin", json={"password": PASSWORD}).json()["secret"])
        first, second, third = codes_around_now(secret)
        assert admin.post("/api/v1/totp/enable", json={"code": first}).status_code == 200
        assert visitor(admin, 50002).post("/api/v1/login", json={"password": PASSWORD, "code": second}).status_code == 200
        assert visitor(admin, 50003).post("/api/v1/login", json={"password": PASSWORD, "code": second}).status_code == 401
    with wall(tmp_path, sign_in=False) as later:
        for used in (first, second):  # the one that switched it on, and the one that signed in
            again = visitor(later, 50004).post("/api/v1/login", json={"password": PASSWORD, "code": used})
            assert (again.status_code, again.json()["code"]) == (401, "bad_code")
        assert later.post("/api/v1/login", json={"password": PASSWORD, "code": third}).status_code == 200  # one nobody has used
    with wall(tmp_path, sign_in=False) as later:  # ...and that one too, once it has been
        assert later.post("/api/v1/login", json={"password": PASSWORD, "code": third}).status_code == 401


def test_nobody_is_let_in_on_a_code_that_could_not_be_written_down_as_used(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from qkvm.store import Store

    with wall(tmp_path) as admin:
        secret = str(admin.post("/api/v1/totp/begin", json={"password": PASSWORD}).json()["secret"])
        first, second, _ = codes_around_now(secret)
        assert admin.post("/api/v1/totp/enable", json={"code": first}).status_code == 200
        real_write = Store.write

        def full(self: Store, data: Any) -> None:
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(Store, "write", full)
        guest = visitor(admin, 50002)
        refused = guest.post("/api/v1/login", json={"password": PASSWORD, "code": second})
        assert (refused.status_code, refused.json()["code"]) == (507, "not_saved")
        assert guest.get("/api/v1/wall").status_code == 401
        monkeypatch.setattr(Store, "write", real_write)
        # It was not used, then: with room on the disk again it signs in, once.
        assert guest.post("/api/v1/login", json={"password": PASSWORD, "code": second}).status_code == 200
        assert visitor(admin, 50003).post("/api/v1/login", json={"password": PASSWORD, "code": second}).status_code == 401
