"""What a server's controller sent where a list belongs, and how it says that the monitor goes dark.

Found by a reviewer who put one odd value at a time into everything the stand-in controller answers
(seven thousand of them). No nesting is needed for these: a number is enough.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

from qkvm import kvm, redfish, update, vault
from qkvm.redfish import said_yes
from tests.fake_redfish import BmcState, FakeBmc
from tests.test_redfish import a_screen, picture_of, status_of
from tests.test_wall import add, snap, wait_until, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(redfish, "LOOK_EVERY", 0)
    monkeypatch.setattr(redfish, "FOLLOW_UP", ())
    monkeypatch.setattr(redfish, "HICCUP", 0)
    monkeypatch.setattr(redfish, "CONFIRM_EVERY", 0.05)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def answering(monkeypatch: pytest.MonkeyPatch, changed: Callable[[str, Any], None]) -> None:
    """What the driver reads of the controller's answers is handed to `changed` first (the path asked, what was said)."""
    real = kvm.read_json

    def read(reply: Any) -> Any:
        said = real(reply)
        changed(urlsplit(str(reply.url)).path, said)
        return said

    monkeypatch.setattr(redfish, "read_json", read)


ODD: dict[str, Any] = {"a number": 5, "yes": True, "a record": {"a": 1}, "a part of a number": 1.5, "a text": "abc"}


@pytest.mark.parametrize("what", ["Temperatures", "Fans"])
@pytest.mark.parametrize("kind", list(ODD))
def test_its_temperatures_or_its_fans_are_no_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, what: str, kind: str) -> None:
    # The tile said "something went wrong inside qKVM", with the whole error in the log at every look.
    # A controller that says so has no temperatures to show: the server is there all the same.
    on = [False]

    def changed(path: str, said: Any) -> None:
        if on[0] and path.endswith("/Thermal"):
            said[what] = ODD[kind]

    answering(monkeypatch, changed)
    bmc = FakeBmc().start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, bmc.url)
            status_of(admin, device, state="online")
            on[0] = True
            seen = []
            until = time.monotonic() + 2
            while time.monotonic() < until:
                seen.append(admin.get("/api/v1/status").json()[device])
                time.sleep(0.2)
            states = {(status["state"], (status.get("error") or {}).get("code")) for status in seen}
            assert states == {("online", None)}, states
    finally:
        bmc.stop()


@pytest.mark.parametrize("where", ["on the action", "the parameters of its description", "in its description"])
@pytest.mark.parametrize("kind", ["a number", "yes", "a part of a number"])
def test_a_power_button_where_the_kinds_it_offers_are_no_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, where: str, kind: str) -> None:
    # Pressed, a power button was "something went wrong inside qKVM", and the press was in no log. A
    # controller that does not say which kinds of reset it takes is asked for the usual one, as always.
    def changed(path: str, said: Any) -> None:
        if path.endswith("/Systems/Self") and where == "on the action":
            said["Actions"]["#ComputerSystem.Reset"]["ResetType@Redfish.AllowableValues"] = ODD[kind]
        if path.endswith("/ResetActionInfo"):
            if where == "the parameters of its description":
                said["Parameters"] = ODD[kind]
            elif where == "in its description":
                said["Parameters"][0]["AllowableValues"] = ODD[kind]

    bmc = FakeBmc().start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, bmc.url)
            status_of(admin, device, state="online")
            answering(monkeypatch, changed)
            reply = admin.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_reset"})
            assert reply.status_code != 500, reply.text[:300]
            assert reply.status_code == 200 or reply.json()["code"] in ("action_failed", "not_supported", "bad_response"), reply.text[:300]
            events = [entry["event"] for entry in admin.get("/api/v1/audit?limit=50").json()["entries"]]
            assert any(event.startswith("action") or "atx" in event for event in events), events  # and the press is in the activity log
    finally:
        bmc.stop()


# --- the two words for "the server's own monitor goes dark while a console is open" ----------------------------

YES: list[Any] = [1, "1", True, 1.0, "true", "on", "On", "enabled", 2, ["x"], {"a": 1}]
NO: list[Any] = [0, "0", False, 0.0, "false", "off", "", "no", " 0 ", None]


def test_which_words_are_a_plain_no() -> None:
    assert [said_yes(word) for word in YES] == [True] * len(YES)
    assert [said_yes(word) for word in NO] == [False] * len(NO)


@pytest.fixture
def with_screen() -> Iterator[FakeBmc]:
    server = FakeBmc(BmcState(own_console=True, screen=a_screen(), piece=50)).start()
    yield server
    server.stop()


@pytest.mark.parametrize(
    ("first", "second", "dark"),
    [
        (1, 1, True), ("1", "1", True),
        # Said some other way than a real board was seen to say it. It was taken for "no", and the console
        # was opened: whoever stood at the server saw its monitor go dark. Not a plain no is not a no.
        (True, True, True), (1.0, 1.0, True), ("true", "on", True), (1, ["unreadable"], True), ({"a": 1}, 1, True),
        (0, 0, False), (1, 0, False), (0, 1, False), ("0", "false", False), (False, 1, False), (1, "", False), ("off", "on", False),
        (1, "missing", False), ("missing", "missing", False),
    ],
)  # fmt: skip
def test_the_console_is_left_alone_unless_the_monitor_stays_on(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, with_screen: FakeBmc, first: Any, second: Any, dark: bool) -> None:
    def changed(path: str, said: Any) -> None:
        if path == "/api/kvm/token":
            for name, word in (("automatic_off", first), ("local_monitor_off", second)):
                if word == "missing":
                    said.pop(name, None)
                else:
                    said[name] = word

    answering(monkeypatch, changed)
    with wall(tmp_path) as admin:
        device = add(admin, with_screen.url)
        if dark:
            wait_until(lambda: admin.get(snap(device)).status_code == 404, "it was never said that there is no picture")
            assert "monitor" in admin.get(snap(device)).json()["message"]
            assert with_screen.state.heard == []  # the console was never opened
        else:
            assert picture_of(admin, device)[:2] == bytes([0xFF, 0xD8])
