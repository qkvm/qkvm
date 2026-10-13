"""The file of browsers that are kept signed in, read back: one that is damaged, one that holds more than is kept, one with numbers that are no dates."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import pytest

from qkvm import kvm, security, update, vault
from qkvm.core import Core, auth_mark
from qkvm.security import Sessions
from tests.test_unlock import fits, kept_sign_in, let_in
from tests.test_wall import wait_until, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def key_of(cookie: str) -> str:
    return hashlib.sha256(cookie.encode()).hexdigest()


def test_a_file_that_is_not_one_is_replaced_and_what_is_good_in_a_mixed_one_is_kept(tmp_path: Path) -> None:
    path = tmp_path / "sessions.json"
    now = time.time()
    good = {key_of("good"): [now - 60, "aaaaaaaa", "m"]}
    for what, text in (
        ("cut off", json.dumps(good)[:-5]),
        ("too long to be read", json.dumps({**good, "pad": "x" * 1_100_000})),
        ("not a table", json.dumps([1, 2, 3])),
        ("nested", "[" * 100_000),
    ):
        path.write_text(text, encoding="ascii")
        sessions = Sessions(path)
        sessions.load(lambda user, mark: True)
        sessions.flush()
        assert sessions.get("good") is None and json.loads(path.read_text(encoding="ascii")) == {}, what
    mixed = {
        **good,
        key_of("future"): [now + 3600, "aaaaaaaa", "m"],
        key_of("old"): [now - 31 * 86400, "aaaaaaaa", "m"],
        key_of("nan"): [float("nan"), "aaaaaaaa", "m"],
        key_of("no mark"): [now, "aaaaaaaa", ""],
        key_of("gone"): [now, "bbbbbbbb", "m"],
        "junk": 7,
    }
    path.write_text(json.dumps(mixed), encoding="ascii")
    sessions = Sessions(path)
    sessions.load(lambda user, mark: user == "aaaaaaaa")
    sessions.flush()
    left = json.loads(path.read_text(encoding="ascii"))
    print("\n[file] of seven entries, taken up and left in the file:", len(left))
    assert list(left) == [key_of("good")] and sessions.get("good") is not None and sessions.get("future") is None


def on_disk(sessions: Sessions) -> None:
    """Everything that was to be written down is, however slow the disk.

    `flush` waits ten seconds and comes back, written or not. Each of the hundreds of sign-ins below is a
    file written anew: on a slow disk that took longer, and the test read a file with 80 entries where 140
    were to come, or 57 of 500. Found by an outside reviewer, whose disk was that slow.
    """
    assert sessions.settled(within=300) is None


def test_flush_says_so_when_it_did_not_get_there(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import threading

    sessions = Sessions(tmp_path / "sessions.json")
    begun, let_go = threading.Event(), threading.Event()
    write = sessions._write

    def slowly(text: str) -> None:
        begun.set()
        assert let_go.wait(20)
        write(text)

    monkeypatch.setattr(sessions, "_write", slowly)
    sessions.create("192.0.2.1", True, "00000001", mark="m")
    try:
        assert begun.wait(5)
        assert sessions.flush(within=0.3) == "the disk does not answer"  # back, and not written: said
        assert not (tmp_path / "sessions.json").exists()
    finally:
        let_go.set()
    assert sessions.flush() is None and len(json.loads((tmp_path / "sessions.json").read_text(encoding="ascii"))) == 1


def test_more_than_are_kept(tmp_path: Path) -> None:
    # Of one account, the newest few: a person has a handful of browsers, and a few accounts signing in over
    # and over must not fill the file between them and leave everybody else to sign in again after a restart.
    path = tmp_path / "sessions.json"
    sessions = Sessions(path)
    tokens: dict[str, list[str]] = {}
    for number in range(7 * (security.MOST_KEPT_OF_ONE + 5)):
        user = f"{number % 7:08x}"
        tokens.setdefault(user, []).append(sessions.create("192.0.2.1", True, user, mark="m"))
    on_disk(sessions)
    assert len(json.loads(path.read_text(encoding="ascii"))) == 7 * security.MOST_KEPT_OF_ONE
    again = Sessions(path)
    again.load(lambda user, mark: True)
    on_disk(again)
    for mine in tokens.values():
        kept = [again.get(token) is not None for token in mine]
        assert not any(kept[:5]) and all(kept[5:])  # the oldest five of each are the ones left out

    # And of all accounts together, no more than are read back.
    crowded = Sessions(tmp_path / "crowded.json")
    for number in range(security.MOST_KEPT + 40):
        crowded.create("192.0.2.1", True, f"{number:08x}", mark="m")
    on_disk(crowded)
    written = json.loads((tmp_path / "crowded.json").read_text(encoding="ascii"))
    assert len(written) == security.MOST_KEPT and len((tmp_path / "crowded.json").read_bytes()) < 1_000_000


def test_a_number_too_large_in_the_file_does_not_end_the_start(tmp_path: Path) -> None:
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        cookie = kept_sign_in(admin)
        admin.core.sessions.flush()  # type: ignore[attr-defined]
    said = json.loads((data / "sessions.json").read_text(encoding="ascii"))
    said[key_of("made up")] = [10**400, "aaaaaaaa", "m"]  # a date no clock has
    (data / "sessions.json").write_text(json.dumps(said), encoding="ascii")
    core = Core(data)
    try:
        told: object = core.unlock_at_start()
    except Exception as ex:
        told = f"a traceback: {type(ex).__name__}: {ex}"
    print("\n[file] a start with such a file:", told)
    assert not str(told).startswith("a traceback")
    del cookie


def test_who_was_kept_signed_in_by_the_version_before_is_still_kept(tmp_path: Path) -> None:
    # The mark was of the password alone (05b3d2d); it is of the password and the second step's key now.
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        cookie = kept_sign_in(admin)
        admin.core.sessions.flush()  # type: ignore[attr-defined]
        user = admin.core.store.users[0]  # type: ignore[attr-defined]
        before = hashlib.sha256(json.dumps(user.auth, sort_keys=True, default=str).encode()).hexdigest()[:24]  # auth_mark as it was
        now = auth_mark(user)
    said = json.loads((data / "sessions.json").read_text(encoding="ascii"))
    for entry in said.values():
        assert entry[2] == now
        entry[2] = before  # as the version before wrote it down
    (data / "sessions.json").write_text(json.dumps(said), encoding="ascii")
    with wall(data, sign_in=False) as later:
        back = let_in(later, cookie)
        print(f"\n[mark] kept signed in by the version before (mark {before[:8]}..., now {now[:8]}...): let in after the update: {back}")
        assert back
