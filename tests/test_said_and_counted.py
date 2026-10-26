"""Three small things: what is said of a settings file that was set aside, how a group is counted, and 0 for no.

* Whoever edited the settings file is told what was wrong with it, on the page as well: the Activity
  tab's line for "read from its second copy" names the file that was kept and what was wrong with it.
* A group's name is kept with its runs of blanks made one, and is counted after that by the form as by a file.
* 0 and 1 where true or false belongs are what a hand writes, and are no and yes.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

import qkvm
from qkvm import exchange, kvm, update, vault
from qkvm.store import Store, StoreError
from tests.test_wall import add, closed_port, wall
from tests.settings_file import settings_text, write_settings_text

F = {"format": exchange.FORMAT, "version": 1}


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 2)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 2)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def test_the_page_shows_what_was_wrong_with_a_file_that_was_set_aside(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        add(admin, f"http://127.0.0.1:{closed_port()}", force=True, kind="kvmd")
    saved = json.loads(settings_text(tmp_path / "qkvm.json", encoding="utf-8"))
    saved["alerts"]["paused_until"] = "tomorrow"
    write_settings_text(tmp_path / "qkvm.json", json.dumps(saved), encoding="utf-8")
    with wall(tmp_path) as admin:
        entry = next(e for e in admin.get("/api/v1/audit?limit=500").json()["entries"] if e["event"] == "settings_restored")
    page = (Path(qkvm.__file__).parent / "static" / "app.js").read_text(encoding="utf-8")
    detail = page[page.index("const detail = entry => [") : page.index("].filter(Boolean).join(' · ');")]
    # (a line of `detail` that begins "entry.event === 'x' &&" is for entries of that event only)
    for_it = [line for line in detail.splitlines() if "entry.event ===" not in line or "'settings_restored'" in line]
    shown = sorted(set(re.findall(r"entry\.(\w+)", "\n".join(for_it))) & (set(entry) - {"event", "time", "ip"}))
    print(f">>> the entry as written: {entry}")
    print(f">>> of 'damaged' and 'why', the page's line for it shows: {shown or 'neither'}")
    assert "paused_until" in entry["why"]
    assert shown, "the Activity tab shows neither which file was set aside nor what was wrong with it"


def test_a_group_is_counted_by_the_form_as_it_is_kept(tmp_path: Path) -> None:
    spaced = "Rack" + " " * 40 + "1"  # kept as "Rack 1"
    read = exchange.unpack(json.dumps({**F, "devices": [{"url": "https://192.168.1.20", "kind": "kvmd", "group": spaced}]}), "")
    with wall(tmp_path) as admin:
        typed = admin.post("/api/v1/devices", json={"url": f"http://127.0.0.1:{closed_port()}", "password": "x", "force": True, "kind": "kvmd", "group": spaced})
    print(f">>> a group typed with a run of blanks in it: a file's reader keeps {[device.group for device in read.devices or []]}; the form answers {typed.status_code} {typed.json().get('message', '')}")
    assert [device.group for device in read.devices or []] == ["Rack 1"]
    assert typed.status_code == 201, "what a file is read with, the form refuses"


ONES_AND_NOUGHTS: dict[str, Any] = {
    'a device\'s "alerts": 0': lambda saved: saved["devices"][0].__setitem__("alerts", 0),
    '"https": 0': lambda saved: saved["server"].__setitem__("https", 0),
    'the alerts\' "enabled": 1': lambda saved: saved["alerts"].__setitem__("enabled", 1),
}


@pytest.mark.parametrize("what", list(ONES_AND_NOUGHTS))
def test_a_wall_that_ran_with_0_or_1_for_no_or_yes_in_its_file_still_starts(tmp_path: Path, what: str) -> None:
    with wall(tmp_path) as admin:
        add(admin, f"http://127.0.0.1:{closed_port()}", force=True, kind="kvmd", name="The one device")
    for name in ("qkvm.json", "qkvm.bak"):  # (as one run of the build before the checks leaves the two copies: every save writes both)
        saved = json.loads(settings_text(tmp_path / name, encoding="utf-8"))
        ONES_AND_NOUGHTS[what](saved)
        write_settings_text(tmp_path / name, json.dumps(saved, indent=2), encoding="utf-8")
    try:
        Store(tmp_path / "qkvm.json")
    except StoreError as ex:
        said = str(ex)
        print(f">>> {what}: {said[said.index('cannot be read'):][:140]}")
        pytest.fail(f"{what}: the wall does not start")
