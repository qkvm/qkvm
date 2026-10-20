"""What one account may do to keyboard and mouse over the live line (the final review of 0.2.0, part A, findings 3 and 4).

Taking and giving back was counted per line: one operator's script that opened its lines anew took them 1680 times in
ten seconds, which made 19,800 lines at INFO and as many activity entries a minute, and an event WebSocket to the KVM for
every taking. And the line took usage 0x66, the keyboard's Power key, which the page never sends: it shuts a machine down
without the question every other power action is asked first.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest

from qkvm import live
from tests.fake_kvm import FakeKvm
from tests.test_live import Viewer, Wall, comet, fast, pytestmark  # noqa: F401  (the fixtures, and what is said of a line held open)
from tests.test_wall import wait_until

OLGA = "olga may act here"


def answer(line: Viewer) -> dict[str, Any]:
    """The line's answer to an asking for keyboard and mouse, or its goodbye (its words about the picture left aside)."""
    while True:
        said = line.word()
        if said["t"] in ("control", "bye"):
            return said


def test_one_account_takes_and_gives_back_keyboard_and_mouse_so_many_times_a_minute_whatever_its_lines(tmp_path: Path, comet: FakeKvm, caplog: pytest.LogCaptureFixture) -> None:  # noqa: F811
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        assert admin.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": OLGA}).status_code == 201
        olga = wall.browser("olga", OLGA)
        caplog.set_level(logging.INFO, logger="qkvm")
        taken = 0
        for _ in range(3):
            line = wall.line(olga, device)
            said = None
            for _ in range(live.MOST_CONTROL_A_MINUTE // 2):
                line.say(t="control", on=True)
                said = answer(line)
                if said["t"] != "control":
                    break
                assert said["on"] is True, said
                taken += 1
                line.say(t="control", on=False)
                assert line.word("control") == {"t": "control", "on": False}
            if said is not None and said["t"] == "bye":
                assert said["code"] == "flooding", said
                line.closed()
                continue
            line.close()
        # A line anew is no new allowance: the account's sixty a minute were used up by its first line.
        assert taken == live.MOST_CONTROL_A_MINUTE // 2, f"one account took keyboard and mouse {taken} times within the minute"
        wall.core.audit.flush()
        entries = [entry for entry in wall.audit(admin, "live_control") if entry.get("user") == "olga"]
        assert len(entries) <= live.MOST_CONTROL_A_MINUTE, f"{len(entries)} activity entries of one account's takings within the minute"
        opened = len([stream for stream in comet.state.ws_streams if stream == "0"])
        assert opened <= live.MOST_CONTROL_A_MINUTE // 2, f"{opened} lines for keys opened to the KVM"
        # (What is in the activity log is not said again in the program's log for each one: only at DEBUG.)
        said_at_info = [record.getMessage() for record in caplog.records if "keyboard and mouse" in record.getMessage() and record.levelno >= logging.INFO]
        assert not said_at_info, said_at_info[:3]
        # Another account's are its own.
        mine = wall.line(admin, device)
        mine.say(t="control", on=True)
        assert mine.word("control")["on"] is True
        mine.close()


def test_the_keyboards_power_key_is_not_sent_to_a_machine(tmp_path: Path, comet: FakeKvm) -> None:  # noqa: F811
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        line = wall.line(admin, device)
        line.say(t="control", on=True)
        assert line.word("control")["on"] is True
        for usage in (0x66, 0x04):  # Power, then A
            line.say(t="k", u=usage, d=True)
            line.say(t="k", u=usage, d=False)
        wait_until(lambda: len(comet.state.hid) >= 2, f"the A did not arrive: {comet.state.hid}")
        keys = [(event["event"]["key"], event["event"]["state"]) for event in comet.state.hid if event["event_type"] == "key"]
        assert keys == [("KeyA", True), ("KeyA", False)], keys
        line.close()


def test_a_key_combination_with_the_keyboards_power_key_is_refused(tmp_path: Path, comet: FakeKvm) -> None:  # noqa: F811
    # Nor as a key combination: a kvmd KVM is told the names as they come, and has a Power key. (Any other driver has no
    # such name in its table, and refuses it as a key it has not got.)
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        refused = admin.post(f"/api/v1/devices/{device}/actions", json={"action": "keys", "keys": "Power"})
        assert (refused.status_code, refused.json()["code"]) == (422, "invalid"), refused.text
        assert not [action for action in comet.state.actions if "Power" in action], comet.state.actions
