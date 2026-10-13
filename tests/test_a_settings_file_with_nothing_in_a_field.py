"""Nothing in a field of the settings file (null) is the field as nobody set it, and no reason not to start.

`null` where a text or a list belongs is what somebody writes who fills `qkvm.json` in by hand, or
with a script that has nothing to say for a field. Every save writes the value into both copies, so a
start that refused it had no second copy to go on from, and the wall did not start:

* `"allowed_hosts": null` in the server's settings (the one setting the README sends people into the
  file for);
* `"open_url": null`, `"group": null` or `"ident": null` of a device.

And two things about what is said:

* A refusal names the record and the field: for a `group` that is a number, not "a device's name or
  address".
* Where the second copy is there and is used, whoever edited the file is told what was wrong with it:
  on the terminal, in the log and in the activity log.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

import pytest

import qkvm
from qkvm import kvm, update, vault
from qkvm.store import Store, StoreError
from tests.test_wall import PASSWORD, add, closed_port, wall

EDITS: dict[str, Any] = {
    "allowed_hosts that is null": lambda saved: saved["server"].__setitem__("allowed_hosts", None),
    "a device's console link that is null": lambda saved: saved["devices"][0].__setitem__("open_url", None),
    "a device's group that is null": lambda saved: saved["devices"][0].__setitem__("group", None),
    "a device's ident that is null": lambda saved: saved["devices"][0].__setitem__("ident", None),
}


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 2)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 2)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def a_wall(folder: Path) -> None:
    with wall(folder) as admin:
        add(admin, f"http://127.0.0.1:{closed_port()}", force=True, kind="kvmd", name="The one device")


def edit(folder: Path, change: Any, both: bool) -> None:
    for name in ("qkvm.json", "qkvm.bak") if both else ("qkvm.json",):
        saved = json.loads((folder / name).read_text(encoding="utf-8"))
        change(saved)
        (folder / name).write_text(json.dumps(saved, indent=2), encoding="utf-8")


@pytest.mark.parametrize("what", list(EDITS))
def test_a_wall_that_ran_with_null_in_its_file_still_starts(tmp_path: Path, what: str) -> None:
    a_wall(tmp_path)
    edit(tmp_path, EDITS[what], both=True)  # (as one run of the build before leaves the two copies: every save writes both)
    try:
        with wall(tmp_path, sign_in=False) as anybody:
            assert anybody.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
            tiles = anybody.get("/api/v1/wall")
            assert tiles.status_code == 200 and [tile["name"] for tile in tiles.json()["devices"]] == ["The one device"]
    except StoreError as ex:
        pytest.fail(f"{what}: the wall does not start: {str(ex)[-170:]}")


def test_the_refusal_names_the_device_and_the_field(tmp_path: Path) -> None:
    a_wall(tmp_path)
    edit(tmp_path, lambda saved: saved["devices"][0].__setitem__("group", 7), both=True)
    with pytest.raises(StoreError) as refused:
        Store(tmp_path / "qkvm.json")
    said = str(refused.value)
    print(f">>> a device's group that is a number: {said[said.index('cannot be read'):][:90]}")
    assert "group" in said, "the owner is told to look at a name or an address, and it is the group"


def test_whoever_edited_the_file_is_told_which_value_was_refused(tmp_path: Path) -> None:
    # The real program, started on a file with one refused value and a second copy beside it.
    a_wall(tmp_path)
    edit(tmp_path, lambda saved: saved["alerts"].__setitem__("paused_until", "tomorrow"), both=False)
    port = closed_port()
    env = {**os.environ, "PYTHONPATH": str(Path(qkvm.__file__).resolve().parent.parent), "QKVM_UPDATE_REPO": ""}
    env.pop("QKVM_CHILD", None)
    words = [sys.executable, "-P", "-m", "qkvm", "--data-dir", str(tmp_path), "--bind", "local"]
    running = subprocess.Popen([*words, "--port", str(port)], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline and running.poll() is None:
            try:
                with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(f"http://127.0.0.1:{port}/healthz", timeout=2):
                    break
            except OSError:
                time.sleep(0.2)
    finally:
        subprocess.run([sys.executable, "-P", "-m", "qkvm", "stop", "--data-dir", str(tmp_path)], env=env, capture_output=True, text=True, timeout=60)
        try:
            said, _ = running.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            running.kill()
            said, _ = running.communicate()
    about = [line for line in said.splitlines() if "second copy" in line]
    print(f">>> said at start: {about}")
    assert about and list(tmp_path.glob("qkvm.damaged-*.json")), said[-600:]
    assert "paused" in about[0], "the edit was set aside, and nothing says which value the file was refused for"
