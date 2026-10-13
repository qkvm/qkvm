"""The second step of signing in, and a sign-in that waits its turn: what holds when two things happen at once, when the disk is full, and when the clock was wrong."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from qkvm import totp
from qkvm.vault import Vault
from tests.test_totp import codes_around_now
from tests.test_users import OTHER, account, browser, visitor
from tests.test_wall import PASSWORD, fast, wait_until, wall  # noqa: F401


def test_a_sign_in_with_a_second_step_that_waits_its_turn_behind_an_admins_change(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The test that came with the fix signs in to accounts without a second step. With one, the sign-in waits
    # twice more: for its turn to change what is saved, and for the save. An admin's change that holds the turn
    # (its new password is still being made) lets the sign-in pass the first check and queue up behind it.
    making, go_on = threading.Event(), threading.Event()
    real_rewrap = Vault.rewrap

    def rewrap_and_wait(self: Vault, password: str) -> Any:
        if password == "replaced by the admin":
            making.set()
            go_on.wait(10)
        return real_rewrap(self, password)

    with wall(tmp_path) as admin:
        for port, (name, how) in enumerate({"olga": "app", "rosa": "one-time"}.items(), start=50010):
            who = account(admin, name, "operator")
            hers = browser(admin, name, port=port)
            secret = str(hers.post("/api/v1/totp/begin", json={"password": OTHER}).json()["secret"])
            first, second, _ = codes_around_now(secret)
            enabled = hers.post("/api/v1/totp/enable", json={"code": first})
            assert enabled.status_code == 200
            code = second if how == "app" else enabled.json()["recovery_codes"][0]
            step_before = admin.core.store.user(who).totp_step  # type: ignore[attr-defined]
            codes_before = len(admin.core.store.user(who).totp_codes)  # type: ignore[attr-defined]
            monkeypatch.setattr(Vault, "rewrap", rewrap_and_wait)
            making.clear(), go_on.clear()
            changed: list[Any] = []
            changing = threading.Thread(target=lambda who=who, name=name, changed=changed: changed.append(admin.put(f"/api/v1/users/{who}", json={"name": name, "role": "operator", "password": "replaced by the admin"})))
            changing.start()
            assert making.wait(10)  # the admin's change has the turn, and the password is still the old one
            late, answers = visitor(admin, port + 100), []
            signing_in = threading.Thread(target=lambda late=late, name=name, code=code, answers=answers: answers.append(late.post("/api/v1/login", json={"name": name, "password": OTHER, "code": code, "remember": True})))
            signing_in.start()
            time.sleep(1.0)  # its password is checked and found right; it now waits for its turn
            assert not answers
            go_on.set()
            changing.join(10), signing_in.join(10)
            monkeypatch.setattr(Vault, "rewrap", real_rewrap)
            user = admin.core.store.user(who)  # type: ignore[attr-defined]
            print()
            print(f"{name} ({how} code): the admin's change {changed[0].status_code}; the sign-in {answers[0].status_code} {answers[0].json().get('code')}; "
                  f"cookie set: {'set-cookie' in answers[0].headers}; step {step_before} -> {user.totp_step}; one-time codes {codes_before} -> {len(user.totp_codes)}")  # fmt: skip
            assert changed[0].status_code == 200
            assert (answers[0].status_code, answers[0].json()["code"]) == (401, "bad_password")
            assert "set-cookie" not in answers[0].headers and late.get("/api/v1/wall").status_code == 401
            assert (user.totp_step, len(user.totp_codes)) == (step_before, codes_before)  # and no code was used up by it


def test_the_same_code_sent_twice_at_once_signs_in_once(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        secret = str(admin.post("/api/v1/totp/begin", json={"password": PASSWORD}).json()["secret"])
        first, second, _ = codes_around_now(secret)
        assert admin.post("/api/v1/totp/enable", json={"code": first}).status_code == 200
        answers: list[int] = []
        both = [threading.Thread(target=lambda port=port: answers.append(visitor(admin, port).post("/api/v1/login", json={"password": PASSWORD, "code": second}).status_code)) for port in (50020, 50021, 50022, 50023)]
        for one in both:
            one.start()
        for one in both:
            one.join(20)
        print()
        print("four sign-ins at once with the same code:", sorted(answers))
        # Once. The others are refused: for the code having been used, or, sent from the one address at the very
        # same moment, for a password of that address being checked already.
        assert sorted(answers)[0] == 200 and all(answer in (401, 429) for answer in sorted(answers)[1:])


def test_settings_from_before_have_no_step_and_are_read(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        secret = str(admin.post("/api/v1/totp/begin", json={"password": PASSWORD}).json()["secret"])
        first, second, third = codes_around_now(secret)
        assert admin.post("/api/v1/totp/enable", json={"code": first}).status_code == 200
    saved = json.loads((tmp_path / "qkvm.json").read_text(encoding="utf-8"))
    assert saved["users"][0].pop("totp_step") > 0  # as the version before wrote it: without
    (tmp_path / "qkvm.json").write_text(json.dumps(saved), encoding="utf-8")
    with wall(tmp_path, sign_in=False) as later:
        assert later.core.store.users[0].totp_step == 0  # type: ignore[attr-defined]
        assert later.post("/api/v1/login", json={"password": PASSWORD, "code": second}).status_code == 200
        assert visitor(later, 50030).post("/api/v1/login", json={"password": PASSWORD, "code": second}).status_code == 401
    with wall(tmp_path, sign_in=False) as again:
        assert again.post("/api/v1/login", json={"password": PASSWORD, "code": second}).status_code == 401
        assert again.post("/api/v1/login", json={"password": PASSWORD, "code": third}).status_code == 200


def test_a_clock_that_was_ahead_and_is_put_right_locks_nobody_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # What is kept is the step of the code that was typed (the phone's time), not the step the server thought it was.
    real_time = time.time
    ahead = [0.0]

    class Clock:
        @staticmethod
        def time() -> float:
            return real_time() + ahead[0]

    with wall(tmp_path) as admin:
        secret = str(admin.post("/api/v1/totp/begin", json={"password": PASSWORD}).json()["secret"])
        key, phone = secret.replace(" ", ""), int(real_time() // totp.STEP)
        assert admin.post("/api/v1/totp/enable", json={"code": totp.code_at(key, phone - 1)}).status_code == 200
        monkeypatch.setattr(totp, "time", Clock)
        ahead[0] = 30.0  # the server is half a minute ahead of the phone
        assert visitor(admin, 50040).post("/api/v1/login", json={"password": PASSWORD, "code": totp.code_at(key, phone)}).status_code == 200
        kept = admin.core.store.users[0].totp_step  # type: ignore[attr-defined]
        ahead[0] = 0.0  # ...and is put right
        print()
        print(f"the phone's step {phone}; kept as used {kept}; the server thought it was step {phone + 1}")
        assert kept == phone
        assert visitor(admin, 50041).post("/api/v1/login", json={"password": PASSWORD, "code": totp.code_at(key, phone + 1)}).status_code == 200


def test_a_full_disk_lets_nobody_with_a_second_step_in_and_everybody_without(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Said by the commit ("a code that cannot be written down as used lets nobody in"); here is what it comes to.
    from qkvm.store import Store

    with wall(tmp_path) as admin:
        account(admin, "victor", "viewer")
        secret = str(admin.post("/api/v1/totp/begin", json={"password": PASSWORD}).json()["secret"])
        first, second, _ = codes_around_now(secret)
        one_time = admin.post("/api/v1/totp/enable", json={"code": first}).json()["recovery_codes"][0]

        def full(self: Store, data: Any) -> None:
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(Store, "write", full)
        print()
        for what, body in (("the admin, code of the app", {"name": "admin", "password": PASSWORD, "code": second}), ("the admin, one-time code", {"name": "admin", "password": PASSWORD, "code": one_time}), ("a viewer without a second step", {"name": "victor", "password": OTHER})):  # fmt: skip
            answer = visitor(admin, 50050).post("/api/v1/login", json=body)
            print(f"{what}: {answer.status_code} {answer.json().get('code', 'signed in')}")


def test_the_code_that_switched_it_on_does_not_sign_in(tmp_path: Path) -> None:
    # The commit's test signs in with a later code first, after which the earlier one is refused for being
    # earlier, whether or not switching on marked it as used. Here nothing comes between.
    with wall(tmp_path) as admin:
        secret = str(admin.post("/api/v1/totp/begin", json={"password": PASSWORD}).json()["secret"])
        _, now, _ = codes_around_now(secret)
        assert admin.post("/api/v1/totp/enable", json={"code": now}).status_code == 200
        again = visitor(admin, 50060).post("/api/v1/login", json={"password": PASSWORD, "code": now})
        print()
        print("signing in with the code that switched two-factor sign-in on:", again.status_code, again.json().get("code"))
        assert (again.status_code, again.json()["code"]) == (401, "bad_code")
    with wall(tmp_path, sign_in=False) as later:
        assert later.post("/api/v1/login", json={"password": PASSWORD, "code": now}).status_code == 401
