"""An asking for keyboard and mouse is answered within the server's longest way in (the final review of 0.2.0, part A, finding 2).

The page gave an answer five seconds; the way in to a machine's keyboard takes up to ten and a half on a PC with Intel AMT
between two sessions, some forty-seven on a JetKVM connected anew. A take-over the page had given up on went on at the
server and left nobody holding the machine. The page waits a little longer than live.WAY_IN_WITHIN now (the browser
tests), and the server answers within it: a way in not made by then is answered `timeout`, takes nothing from whoever
holds the machine, and is closed once it is made.
"""

from __future__ import annotations

import asyncio
import re
import time
from pathlib import Path

import pytest
from websockets.exceptions import ConnectionClosed

from qkvm import live
from tests.fake_kvm import FakeKvm
from tests.test_live import Viewer, Wall, comet, fast, pytestmark  # noqa: F401  (the fixtures, and what is said of a line held open)
from tests.test_wall import wait_until

OLGA = "olga may act here"
APP_JS = Path(live.__file__).parent / "static" / "app.js"


def heard(line: Viewer, seconds: float) -> None:
    """What comes down the line for this long is read, as a browser reads it (its words kept in `line.words`)."""
    until = time.monotonic() + seconds
    line.until(lambda: time.monotonic() > until, "", timeout=seconds + 5)


def test_the_page_waits_longer_for_an_answer_than_the_server_takes_to_give_one() -> None:
    said = re.search(r"^const CONTROL_ANSWER = (\d+);", APP_JS.read_text(encoding="utf-8"), re.MULTILINE)
    assert said is not None, "the page's wait for an answer to Control is not where it was"
    assert live.WAY_IN_WITHIN * 1000 < int(said.group(1)) <= live.WAY_IN_WITHIN * 1000 + 10_000, said.group(1)


def test_a_way_in_not_made_in_time_is_answered_takes_nothing_from_the_holder_and_is_closed_once_made(tmp_path: Path, comet: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    monkeypatch.setattr(live, "WAY_IN_WITHIN", 1.0, raising=False)
    real_open = live.KvmdHid.open
    slow = {"on": False}

    async def slow_open(self: live.KvmdHid) -> None:
        if slow["on"]:
            await asyncio.sleep(2.5)
        await real_open(self)

    monkeypatch.setattr(live.KvmdHid, "open", slow_open)
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        assert admin.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": OLGA}).status_code == 201
        olga = wall.browser("olga", OLGA)
        hers = wall.line(olga, device)
        hers.say(t="control", on=True)
        assert hers.word("control")["on"] is True
        wait_until(lambda: comet.state.key_lines == 1, "her line for keys was never opened")
        slow["on"] = True
        mine = wall.line(admin, device)
        mine.say(t="control", on=True, take=True, **{"from": "olga"})
        answer = mine.word("control", timeout=2.0)  # (within the second, not after the way in's two and a half)
        assert answer["on"] is False and answer["code"] == "timeout", answer
        # She holds them still, and was told nothing.
        hers.say(t="k", u=0x04, d=True)
        hers.say(t="k", u=0x04, d=False)
        wait_until(lambda: len(comet.state.hid) == 2, f"her key did not arrive: {comet.state.hid}")
        heard(hers, 0.5)
        assert not [said for said in hers.words if said["t"] == "control"], hers.words
        assert admin.post(f"/api/v1/devices/{device}/actions", json={"action": "ctrl_alt_del"}).json().get("by") == "olga"
        # The way in made for the asking after all is closed again, and nothing went through it.
        wait_until(lambda: comet.state.ws_streams.count("0") == 2, f"the way in was never made: {comet.state.ws_streams}", timeout=5)
        wait_until(lambda: comet.state.key_lines == 1, "the way in made too late stayed open", timeout=5)
        assert [entry.get("from") for entry in wall.audit(admin, "live_control")] == [None], wall.audit(admin, "live_control")
        hers.close()
        mine.close()


@pytest.mark.parametrize("meanwhile", ["nothing", "seventy sizes", "seventy keys"])
def test_a_take_over_whose_asker_went_away_while_its_way_in_was_made_takes_nothing(tmp_path: Path, comet: FakeKvm, monkeypatch: pytest.MonkeyPatch, meanwhile: str) -> None:  # noqa: F811
    # (The first review of this track.) The line that asked was not read while the way in was made: an admin who gave up
    # on a slow machine and closed the view still took the keyboard from its holder, for a line that was gone, and then let
    # go of it as that line ended. The holder was told "admin took over", and nobody held the machine. (The second review:
    # and once 64 words had come meanwhile, the line was no longer read: a page sends its size at every step of a window
    # being dragged. Sizes are folded into one; seventy other words are flooding, and end the line all the same.)
    real_open = live.KvmdHid.open
    slow = {"on": False}

    async def slow_open(self: live.KvmdHid) -> None:
        if slow["on"]:
            await asyncio.sleep(2.0)
        await real_open(self)

    monkeypatch.setattr(live.KvmdHid, "open", slow_open)
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        assert admin.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": OLGA}).status_code == 201
        olga = wall.browser("olga", OLGA)
        hers = wall.line(olga, device)
        hers.say(t="control", on=True)
        assert hers.word("control")["on"] is True
        slow["on"] = True
        mine = wall.line(admin, device)
        mine.say(t="control", on=True, take=True, **{"from": "olga"})
        time.sleep(0.3)
        try:
            for step in range(70 if meanwhile != "nothing" else 0):
                if meanwhile == "seventy sizes":
                    mine.say(t="shape", max_w=640 + step, max_fps=30)
                else:
                    mine.say(t="k", u=0x04, d=step % 2 == 0)  # (a page sends none while it is asking: a program that does)
        except ConnectionClosed:
            assert meanwhile == "seventy keys"  # (hung up on for flooding before the last of them went: as it should be)
        time.sleep(0.2)
        mine.close()  # (the view closed while the machine was being asked)
        wait_until(lambda: comet.state.ws_streams.count("0") == 2, f"the way in was never made: {comet.state.ws_streams}", timeout=5)
        wait_until(lambda: comet.state.key_lines == 1, "the way in made for a line that went away stayed open", timeout=5)
        heard(hers, 0.5)
        assert not [said for said in hers.words if said["t"] == "control"], hers.words
        acted = admin.post(f"/api/v1/devices/{device}/actions", json={"action": "ctrl_alt_del"})
        assert (acted.status_code, acted.json().get("by")) == (409, "olga"), acted.text
        assert [(entry.get("user"), entry.get("on")) for entry in wall.audit(admin, "live_control")] == [("olga", True)], wall.audit(admin, "live_control")
        hers.say(t="k", u=0x04, d=True)
        hers.say(t="k", u=0x04, d=False)
        wait_until(lambda: len(comet.state.hid) == 2, f"her key did not arrive: {comet.state.hid}")
        hers.close()
