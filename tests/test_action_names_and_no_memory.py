"""When two saved actions have "the same name", and what is answered as "no memory"."""

from __future__ import annotations

import json
import logging
import unicodedata
from pathlib import Path
from typing import Any

import pytest

from qkvm import exchange, kvm, update, vault
from tests.test_wall import PASSWORD, wall

F = {"format": exchange.FORMAT, "version": 1}


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def plain(**parts: Any) -> str:
    return json.dumps({**F, **parts})


# Pairs of names that are two words to whoever reads the language, and differ only in a mark that
# Unicode files under "Mn" (a vowel sign, a tone): what `server.called` throws away before it compares.
TWO_NAMES = [
    ("กิน", "กัน"),  # Thai: "kin" (eat) and "kan" (together)
    ("कुल", "कूल"),  # Hindi: "kul" and "kool"
    ("סֵפֶר", "סַפָּר"),  # Hebrew, pointed: "sefer" (book) and "sapar" (barber)
    ("كَتَبَ", "كُتِبَ"),  # Arabic: "kataba" (he wrote) and "kutiba" (it was written)
    ("កុ", "កិ"),  # Khmer: two syllables
]


@pytest.mark.parametrize("here,in_file", TWO_NAMES, ids=ascii)
def test_two_names_that_are_two_words_are_two_saved_actions(tmp_path: Path, here: str, in_file: str) -> None:
    # (That they are two names as they are drawn: neither is the other after the forms of a letter are made one.)
    assert unicodedata.normalize("NFKC", here).casefold() != unicodedata.normalize("NFKC", in_file).casefold()
    with wall(tmp_path) as admin:
        assert admin.post("/api/v1/actions", json={"name": here, "kind": "keys", "keys": "MetaLeft,KeyL"}).status_code == 201
        file = plain(actions=[{"name": in_file, "kind": "keys", "keys": "ControlLeft,KeyA"}])
        there = admin.post("/api/v1/import/read", json={"file": file}).json()
        assert [action["new"] for action in there["actions"]] == [True], "an action of another name is said to be on the wall already"
        assert admin.post("/api/v1/import", json={"file": file, "take": ["actions"]}).json()["actions"] == 1
        assert len(admin.get("/api/v1/actions").json()["actions"]) == 2


def test_two_actions_of_one_file_that_differ_in_a_vowel_are_both_taken(tmp_path: Path) -> None:
    # The same within one file, on a wall that has neither: the second is dropped, and nothing says so.
    with wall(tmp_path) as admin:
        first, second = TWO_NAMES[0]
        file = plain(actions=[{"name": first, "kind": "keys", "keys": "KeyA"}, {"name": second, "kind": "keys", "keys": "KeyB"}])
        there = admin.post("/api/v1/import/read", json={"file": file}).json()
        assert [action["new"] for action in there["actions"]] == [True, True] or there["left_out"], "one of two is left out, and no line says so"
        assert admin.post("/api/v1/import", json={"file": file, "take": ["actions"]}).json()["actions"] == 2


def test_a_name_in_the_letters_of_another_alphabet_is_another_name(tmp_path: Path) -> None:
    # What is compared is the name without what is not drawn. It is not "the name as it looks": the same
    # word with one letter from another alphabet looks the same and is another name, here as in every
    # program that has no table of which letters of the world look alike. Said, so that the first sentence
    # is not taken for more than it is: whoever takes actions from a file reads what each one does.
    with wall(tmp_path) as admin:
        assert admin.post("/api/v1/actions", json={"name": "Lock the screen", "kind": "keys", "keys": "MetaLeft,KeyL"}).status_code == 201
        alike = "L" + chr(0x43E) + "ck the screen"  # the o is Cyrillic
        file = plain(actions=[{"name": alike, "kind": "text", "text": "something else"}])
        there = admin.post("/api/v1/import/read", json={"file": file}).json()
        assert [action["new"] for action in there["actions"]] == [True]


# --- "no memory" ---------------------------------------------------------------------------------------------------------------


class Heard(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage())


def test_an_export_that_meets_a_damaged_secret_is_not_answered_as_no_memory(tmp_path: Path) -> None:
    # Every ValueError around a password check or the sealing of a file was answered as "this computer has
    # no memory to spare", and written into the log as that. A saved secret that does not open (a settings
    # file that was edited, or damaged) is a ValueError as well, and is no lack of memory: it is as good as
    # not saved, and the file is written without it.
    heard = Heard()
    logging.getLogger("qkvm").addHandler(heard)
    try:
        with wall(tmp_path) as admin:
            assert admin.post("/api/v1/import", json={"file": plain(devices=[{"url": "https://192.168.1.20", "kind": "kvmd", "password": "secret"}]), "take": ["devices"]}).json()["devices"] == 1
            record = admin.core.store.devices[0]  # type: ignore[attr-defined]
            record.secret = {"nonce": "!", "data": record.secret["data"]}  # as a file that was edited by hand has it
            made = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": "a passphrase for the file", "parts": ["devices"]})
            said = made.json() if made.headers.get("content-type", "").startswith("application/json") and made.status_code != 200 else {}
            assert "memory" not in said.get("message", ""), (made.status_code, said)
            assert made.status_code == 200, made.text[:300]
            back = admin.post("/api/v1/import/read", json={"file": made.text, "passphrase": "a passphrase for the file"}).json()
            assert [(device["host"], device["password"]) for device in back["devices"]] == [("192.168.1.20", False)], back["devices"]
    finally:
        logging.getLogger("qkvm").removeHandler(heard)
    assert not [line for line in heard.lines if "memory" in line], heard.lines


def test_a_password_with_half_a_character_in_it_is_not_answered_as_no_memory(tmp_path: Path) -> None:
    # A password that cannot be written as bytes is turned away as no text, before any check: it is not a
    # check that could not be made.
    heard = Heard()
    logging.getLogger("qkvm").addHandler(heard)
    try:
        with wall(tmp_path) as admin:
            body = b'{"password": "\\ud800 half a character"}'
            answer = admin.post("/api/v1/login", content=body, headers={"Content-Type": "application/json"})
            assert answer.status_code in (401, 422), (answer.status_code, answer.text)
    finally:
        logging.getLogger("qkvm").removeHandler(heard)
    assert not [line for line in heard.lines if "memory" in line], heard.lines


def test_a_check_that_has_no_memory_is_said_as_that_and_as_nothing_else(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The one case that is "no memory": the work of the check itself not getting done. Python's own error
    # for it, or the library's, which comes as a ValueError like so much else.
    import hashlib

    with wall(tmp_path) as admin:
        for error in (MemoryError(), ValueError("[digital envelope routines] malloc failure")):

            def no_room(*given: Any, error: BaseException = error, **named: Any) -> bytes:
                raise error

            with monkeypatch.context() as patched:
                patched.setattr(hashlib, "scrypt", no_room)
                with pytest.raises(vault.NoMemory):
                    vault.Vault.open(admin.core.store.users[0].auth, PASSWORD)  # type: ignore[attr-defined]
                answer = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": "", "parts": ["devices"]})
                assert (answer.status_code, answer.json()["code"]) == (503, "busy"), answer.text
        # And once there is memory again, the same password is the right one: it was never counted as wrong.
        assert admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": "", "parts": ["devices"]}).status_code == 200
