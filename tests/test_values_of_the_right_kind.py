"""Values of the right kind that a look at the wall still fell over.

`store._as_declared` asks each field for its kind. These were of the right kind, were read, the program
started, and then:

* a device's address that is no address (`"http://["`): the list of tiles was an error for everybody;
* half a character (`"\\ud800"`, a lone surrogate) in a device's name, address, group, kind, tls, user
  name or console link: the same; in any other text, the page that shows it;
* an account's role that is none of the three (`"Admin"`, `""`): every request of that account was an
  error, and where it was the admin's, nobody administered the wall;
* a port that is a whole number and no port (`70000`, `-1`): the start itself ended in a traceback, with
  exit status 1 where "could not start" is 2 (the starter takes an update back for 1, not for 2).

All of them take a hand, or a script, in the data folder; none is written by the program.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import qkvm
from qkvm import kvm, update, vault
from qkvm.store import Store, StoreError
from tests.test_users import OTHER
from tests.test_wall import PASSWORD, add, closed_port, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 2)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 2)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def a_wall(folder: Path, change: Any) -> None:
    with wall(folder) as admin:
        add(admin, f"http://127.0.0.1:{closed_port()}", force=True, kind="kvmd", name="The one device")
        assert admin.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": OTHER}).status_code == 201
    for name in ("qkvm.json", "qkvm.bak"):
        saved = json.loads((folder / name).read_text(encoding="utf-8"))
        change(saved)
        (folder / name).write_text(json.dumps(saved, indent=2), encoding="utf-8")


def looked_at(folder: Path) -> dict[str, int] | None:
    """What a wall started on `folder` answers; None where the start refuses the file in a sentence."""
    try:
        Store(folder / "qkvm.json")
    except StoreError:
        return None
    with wall(folder, sign_in=False) as admin:
        answers = {"sign-in": admin.post("/api/v1/login", json={"name": "admin", "password": PASSWORD}).status_code}
        for path in ("/api/v1/wall", "/api/v1/status", "/api/v1/users", "/api/v1/settings"):
            answers[path] = admin.get(path).status_code
    with wall(folder, sign_in=False) as other:
        answers["olga's sign-in"] = other.post("/api/v1/login", json={"name": "olga", "password": OTHER}).status_code
        answers["olga's wall"] = other.get("/api/v1/wall").status_code
    return answers


CASES: dict[str, Any] = {
    'a device\'s "url": "http://["': lambda saved: saved["devices"][0].__setitem__("url", "http://["),
    'a device\'s "name" with half a character in it': lambda saved: saved["devices"][0].__setitem__("name", "Build \ud800 server"),
    'a device\'s "group" with half a character in it': lambda saved: saved["devices"][0].__setitem__("group", "\ud800"),
    'the admin\'s "role": "Admin"': lambda saved: saved["users"][0].__setitem__("role", "Admin"),
    'an operator\'s "role": ""': lambda saved: saved["users"][1].__setitem__("role", ""),
}


@pytest.mark.parametrize("what", list(CASES))
def test_a_value_of_the_right_kind_is_refused_at_start_or_does_no_harm(tmp_path: Path, what: str) -> None:
    a_wall(tmp_path, CASES[what])
    answers = looked_at(tmp_path)
    wrong = {name: code for name, code in (answers or {}).items() if code >= 500}
    print(f">>> {what}: {'refused at start, in a sentence' if answers is None else answers}")
    assert not wrong, f"{what}: the wall starts, and then answers {wrong}"


@pytest.mark.parametrize("port", [70000, -1])
def test_a_port_that_is_none_ends_the_start_in_a_sentence(tmp_path: Path, port: int) -> None:
    # The real program. (No port is given on the command line: the one in the file is one nothing can listen on.)
    a_wall(tmp_path, lambda saved: saved["server"].__setitem__("port", port))
    env = {**os.environ, "PYTHONPATH": str(Path(qkvm.__file__).resolve().parent.parent), "QKVM_UPDATE_REPO": "", "QKVM_UPDATE_API": "http://127.0.0.1:9"}
    env.pop("QKVM_CHILD", None)
    done = subprocess.run([sys.executable, "-P", "-m", "qkvm", "--data-dir", str(tmp_path), "--bind", "local"], env=env, capture_output=True, text=True, timeout=120)
    said = (done.stdout + done.stderr).strip().splitlines()
    print(f'>>> "port": {port}: exit status {done.returncode}; the last line said: {said[-1][:120] if said else ""}')
    assert "Traceback" not in done.stdout + done.stderr, "the start ended in a traceback"
    assert done.returncode == 2, f"exit status {done.returncode}: the starter takes that for a version that does not work, and an update back for it"
