"""What one account may do to keyboard and mouse over the live line (the final review of 0.2.0, part A, findings 3 and 4).

Taking and giving back was counted per line: one operator's script that opened its lines anew took them 1680 times in
ten seconds, which made 19,800 lines at INFO and as many activity entries a minute, and an event WebSocket to the KVM for
every taking. And the line took usage 0x66, the keyboard's Power key, which the page never sends: it shuts a machine down
without the question every other power action is asked first.
"""

from __future__ import annotations

import json
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


def test_a_saved_action_with_the_keyboards_power_key_is_refused_when_it_is_saved(tmp_path: Path) -> None:
    # Register row 11 of 0.2.1 (fx-a N5): saved, by the API or from a file, it was taken, and refused at every run on every
    # machine after (422 on a kvmd KVM, which is told the names as they come; a key it has not got on every other). Now it
    # is refused where it is saved, with the reason a run gives, and left out of a file with it: one rule for both.
    from qkvm import exchange

    with Wall(tmp_path) as wall:
        admin = wall.browser()
        for keys in ("Power", "ControlLeft,Power"):
            refused = admin.post("/api/v1/actions", json={"name": "Off", "kind": "keys", "keys": keys})
            assert refused.status_code == 422, refused.text
            assert refused.json()["code"] == "invalid" and "Power key is not sent" in refused.json()["message"]
        kept = admin.post("/api/v1/actions", json={"name": "Lock", "kind": "keys", "keys": "MetaLeft,KeyL"})
        assert kept.status_code == 201
        changed = admin.put(f"/api/v1/actions/{kept.json()['action']['id']}", json={"name": "Lock", "kind": "keys", "keys": "MetaLeft,Power"})
        assert changed.status_code == 422 and "Power key is not sent" in changed.json()["message"]
        assert [(action["name"], action["keys"]) for action in admin.get("/api/v1/actions").json()["actions"]] == [("Lock", "MetaLeft,KeyL")]
    read = exchange.unpack(json.dumps({"format": exchange.FORMAT, "version": 1, "actions": [
        {"name": "Off", "kind": "keys", "keys": "Power"}, {"name": "Lock", "kind": "keys", "keys": "MetaLeft,KeyL"},
    ]}), "")  # fmt: skip
    assert [action.name for action in read.actions or []] == ["Lock"]
    assert len(read.left_out) == 1 and read.left_out[0].startswith("Saved action 1:") and "Power key" in read.left_out[0]


def test_the_count_of_takings_a_minute_outlasts_the_listeners_being_opened_again(tmp_path: Path) -> None:
    # The coordinator's decision on 0.2.1's sweep (beside register row 22): an account's takings and givings back of keyboard
    # and mouse are counted a minute at a time (MOST_CONTROL_A_MINUTE), and the count lived in the live lines' object, which
    # the listeners make: opened again (a change of the network settings), it started from nothing. It is the program's now.
    import gc

    from fastapi.testclient import TestClient

    from qkvm.core import Core
    from qkvm.server import create_app
    from tests.test_wall import CSRF

    core = Core(tmp_path)
    core.unlock_at_start()

    def lines_of(app: object) -> live.Lines:
        return next(o for o in gc.get_objects() if type(o) is live.Lines and o.manager.core is core and o not in seen)

    holder = live.Holder("u1", "olga", True, "127.0.0.1")
    seen: list[live.Lines] = []
    with TestClient(create_app(core), headers=CSRF):
        first = lines_of(None)
        seen.append(first)
        assert all(first.control_said(holder) for _ in range(live.MOST_CONTROL_A_MINUTE))
        assert first.control_said(holder) is False  # (spent for this minute)
    with TestClient(create_app(core), headers=CSRF):  # the listeners opened again, the program the same
        again = lines_of(None)
        assert again is not first
        assert again.control_said(holder) is False, "the listeners opened again gave the account a whole minute's takings back"
