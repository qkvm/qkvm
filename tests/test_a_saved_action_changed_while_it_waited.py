"""A saved action that waits for the last holder's letting go is asked again afterwards (W2c's open item 3).

An action from the page waits up to sixteen seconds for what the last holder of a machine's keyboard and mouse had down
to be let go of. A saved action was looked up before that wait: edited meanwhile (it types now, where it pressed a key;
it wants a question it did not want before), or removed, it ran as it was when it was clicked.
"""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from typing import Any

import httpx
import pytest

from qkvm import live
from tests.fake_kvm import FakeKvm
from tests.test_live import Wall, comet, fast, pytestmark  # noqa: F401  (the fixtures, and what is said of a line held open)
from tests.test_wall import wait_until


@pytest.mark.parametrize("then", ["edited", "removed"])
def test_a_saved_action_edited_or_removed_while_it_waited_for_a_letting_go_sends_nothing(tmp_path: Path, comet: FakeKvm, monkeypatch: pytest.MonkeyPatch, then: str) -> None:  # noqa: F811
    release = threading.Event()
    real_say_key = live.KvmdHid._say_key

    async def held_up(self: live.KvmdHid, usage: int, down: bool) -> None:
        while not down and not release.is_set():
            await asyncio.sleep(0.01)
        await real_say_key(self, usage, down)

    monkeypatch.setattr(live.KvmdHid, "_say_key", held_up)
    waiting = threading.Event()
    real_handed_over = live.Lines.handed_over

    async def noted(self: live.Lines, device_id: str) -> bool:
        waiting.set()
        return await real_handed_over(self, device_id)

    monkeypatch.setattr(live.Lines, "handed_over", noted)
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        made = admin.post("/api/v1/actions", json={"name": "Lock the screen", "kind": "keys", "keys": "MetaLeft,KeyL"})
        assert made.status_code == 201, made.text
        saved = made.json()["action"]
        line = wall.line(admin, device)
        line.say(t="control", on=True)
        assert line.word("control")["on"] is True
        line.say(t="k", u=0xE2, d=True)  # AltLeft, held down; its letting go is held up until the test says
        wait_until(lambda: len(comet.state.hid) == 1, "the key did not arrive")
        line.say(t="control", on=False)
        assert line.word("control") == {"t": "control", "on": False}
        answers: list[httpx.Response] = []
        clicked = {"action": "custom", "custom_id": saved["id"], "custom_changed": saved["changed"]}
        acting = threading.Thread(target=lambda: answers.append(admin.post(f"/api/v1/devices/{device}/actions", json=clicked)))
        acting.start()
        assert waiting.wait(5), "the action never came to the wait"
        if then == "edited":
            changed = admin.put(f"/api/v1/actions/{saved['id']}", json={"name": "Lock the screen", "kind": "keys", "keys": "ControlLeft,AltLeft,Delete"})
            assert changed.status_code == 200, changed.text
        else:
            assert admin.delete(f"/api/v1/actions/{saved['id']}").status_code == 200
        release.set()  # the Alt is let go of now
        acting.join(10)
        assert answers, "the action was never answered"
        said: dict[str, Any] = answers[0].json()
        assert answers[0].status_code == 409 and said["code"] == "changed" and "Nothing was sent" in said["message"], said
        wait_until(lambda: len(comet.state.hid) == 2, "the Alt was never let go of")
        assert [action for action in comet.state.actions if action.startswith("shortcut")] == [], comet.state.actions
        line.close()
