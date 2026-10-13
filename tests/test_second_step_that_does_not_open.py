"""A second step whose key does not open, from the side of whoever has the password only.

The sign-in is answered 409 `no_second_step`. For somebody who has an account's password and not its
second step, that answer is counted and written down as a wrong code is:

* The one-time codes are compared first, and a code that is none of them falls through to the 409: it
  counts toward the lock on wrong codes, which the forty bits of a one-time code are "behind"
  (totp.new_one_time_codes).
* It is a line in qkvm.log once a minute for an account, not at every attempt, and each attempt is in
  the activity log, where the README says refused sign-ins are. So is a right password that was not
  followed by a code.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from qkvm import kvm, update, vault
from tests.test_totp import switch_on
from tests.test_wall import PASSWORD, wall

ATTEMPTS = 40


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


class Heard(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.lines: list[tuple[int, str]] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append((record.levelno, record.getMessage()))


def guesses(tmp_path: Path) -> tuple[list[int], list[tuple[int, str]], list[dict[str, object]]]:
    """Somebody who has the password guesses at the one-time codes, ATTEMPTS times: (answers, log lines, activity log)."""
    heard = Heard()
    logging.getLogger("qkvm").addHandler(heard)
    try:
        with wall(tmp_path) as admin:
            switch_on(admin, PASSWORD)
            user = admin.core.store.users[0]  # type: ignore[attr-defined]
            user.totp = {"nonce": "!", "data": user.totp["data"]}
            assert len(user.totp_codes) == 10
            heard.lines.clear()
            answers = [admin.post("/api/v1/login", json={"password": PASSWORD, "code": f"{number:05x}-{number:05x}"}).status_code for number in range(ATTEMPTS)]
            entries = [entry for entry in admin.get("/api/v1/audit?limit=500").json()["entries"] if entry["event"] == "login_failed"]
    finally:
        logging.getLogger("qkvm").removeHandler(heard)
    return answers, heard.lines, entries


def test_wrong_one_time_codes_are_counted_where_the_second_step_does_not_open(tmp_path: Path) -> None:
    answers, _, _ = guesses(tmp_path)
    print(f">>> {ATTEMPTS} wrong one-time codes with the right password: answers {sorted(set(answers))}, of which 429: {answers.count(429)}")
    # On an account whose key opens, the sixth wrong code is answered 429 (test_totp.py, test_second_step.py).
    assert 429 in answers, f"{ATTEMPTS} guesses at the one-time codes, and none was counted: the lock they are behind is not there"


def test_a_second_step_that_does_not_open_is_not_a_line_in_the_log_for_every_attempt(tmp_path: Path) -> None:
    _, lines, _ = guesses(tmp_path)
    said = [line for level, line in lines if "second step does not open" in line]
    print(f">>> {ATTEMPTS} sign-in attempts: {len(said)} lines at ERROR in qkvm.log (and on the terminal)")
    assert 1 <= len(said) <= 2, f"{len(said)} lines for {ATTEMPTS} attempts: whoever has the password writes the log's history out of it"


def test_a_right_password_without_its_code_is_in_the_activity_log(tmp_path: Path) -> None:
    # Somebody who has an account's password and tries it finds out that it is right ("code_required").
    # Of that try nothing was kept: a wrong password was written down and counted, the right one was not.
    # (Written down once a minute for an account: forty tries are one entry, not forty.)
    with wall(tmp_path) as admin:
        switch_on(admin, PASSWORD)
        before = len(admin.get("/api/v1/audit?limit=500").json()["entries"])
        replies = [admin.post("/api/v1/login", json={"password": PASSWORD}).json() for _ in range(ATTEMPTS)]
        entries = admin.get("/api/v1/audit?limit=500").json()["entries"]
    answers = [reply["code"] for reply in replies]
    print(f">>> {ATTEMPTS} sign-ins with the right password and no code: answered {sorted(set(answers))}; new entries in the activity log: {len(entries) - before}")
    # (Once, in one whole run on a busy Windows machine, one of the forty was "busy", and which of the three
    # answers of that name it was could not be told afterwards: the sentence is kept with it now.)
    otherwise = [(number, reply) for number, reply in enumerate(replies) if reply["code"] != "code_required"]
    assert not otherwise, f"answered otherwise, as try number and in these words: {otherwise[:3]}"
    assert len(answers) == ATTEMPTS
    assert len(entries) == before + 1, "the password of an account with a second step was tried, was right, and the activity log says nothing (or says it at every try)"
    assert entries[0]["event"] == "login_code_asked" or any(entry["event"] == "login_code_asked" for entry in entries)


def test_a_sign_in_refused_for_its_second_step_is_in_the_activity_log(tmp_path: Path) -> None:
    # README: "Sign-ins, refused ones too, are in the activity log." SECURITY.md says the same of audit.log.
    _, _, entries = guesses(tmp_path)
    print(f">>> {ATTEMPTS} refused sign-ins with the right password: {len(entries)} entries in the activity log")
    assert entries, "somebody had the password right, forty times, from some address, and the activity log knows of none of it"
