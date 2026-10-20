"""A power board's press that got no clear answer (the final review of 0.2.0, part A, finding 1).

A KVM's web server answers 502, 503 or 504 while kvmd restarts behind it, and kvmd itself 500: after the board may have
been told. Every answer but 200 was "did not press" (502 `action_failed`), the history kept it as not pressed, the page
offered it under "Retry failed", and a second press went straight to the board: a power button pressed twice undoes
itself. As for a Fingerbot: only a 4xx is a no; anything else that is not the board's yes may have pressed, and the board
is left alone, whoever asks, for as long as a click taken then can still be pressed and held.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from qkvm import kvm
from qkvm.kvm import DeviceSpec, KvmDevice, KvmError
from tests.fake_kvm import FakeKvm, FakeState
from tests.test_history import hist
from tests.test_wall import add, wait_until, wall


@pytest.fixture(autouse=True)
def looked_at_often(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)


@pytest.fixture
def quick(monkeypatch: pytest.MonkeyPatch) -> dict[str, float]:
    """The board's holds made short, and its answer waited for half a second (raising=False: on a program without that
    wait the tests run all the same, and fail on what they prove)."""
    held = {"atx_power": 0.3, "atx_power_long": 1.2, "atx_reset": 0.3}
    monkeypatch.setattr(kvm, "HELD", held)
    monkeypatch.setattr(kvm, "SEEN_WITHIN", 2.0)
    monkeypatch.setattr(kvm, "SEEN_EVERY", 0.1)
    monkeypatch.setattr(kvm, "BOARD_ANSWER", 0.5, raising=False)
    return {"power": held["atx_power"], "power_long": held["atx_power_long"], "reset": held["atx_reset"]}


def press(client: Any, device: str, action: str) -> tuple[float, Any]:
    began = time.monotonic()
    reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": action})
    return time.monotonic() - began, reply


def pressed_rows(client: Any, device: str) -> list[Any]:
    return [row["ok"] for row in client.get(hist(device, what="events")).json()["rows"] if row["kind"] == "pressed"]


def a_board(**how: Any) -> FakeKvm:
    return FakeKvm(FakeState(atx=True, holds={"power": 0.3, "power_long": 1.2, "reset": 0.3}, **how)).start()


@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_a_press_answered_with_a_5xx_may_have_pressed_and_is_not_pressed_again_until_it_cannot_be_pressing(tmp_path: Path, quick: dict[str, float], status: int) -> None:
    fake = a_board(atx_reply=(status, f"<html><body>{status} Bad Gateway</body></html>"))
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: client.get("/api/v1/status").json()[device]["atx"]["enabled"] is True, "the board was never seen")
            _, first = press(client, device, "atx_power")
            answered = time.monotonic()
            assert fake.state.actions == ["atx power"], fake.state.actions  # (the board pressed)
            said = first.json()
            # The page takes `timeout` as no answer ("It may have been done"), and offers no retry of it.
            assert (first.status_code, said["code"]) == (504, "timeout"), first.text
            assert "may have" in said["message"] and f"HTTP {status}" in said["message"], said
            wait_until(lambda: pressed_rows(client, device) == [None], f"the history says {pressed_rows(client, device)}, where nobody can tell")
            # A second press (the page's, another person's, a script's), and a Fingerbot's on the same machine, while the
            # first may still be pressing: refused, nothing sent.
            fake.state.atx_reply = None
            for action in ("atx_power", "atx_reset", "fingerbot_power"):
                _, again = press(client, device, action)
                assert (again.status_code, again.json()["code"]) == (409, "busy"), (action, again.text)
                assert "may still be pressing" in again.json()["message"], again.text
            assert fake.state.actions == ["atx power"] and fake.state.presses == [], (fake.state.actions, fake.state.presses)
            # Not for ever: the answer's time and the button's hold, from the answer.
            time.sleep(max(0.0, answered + 0.5 + quick["power"] + 0.2 - time.monotonic()))
            _, after = press(client, device, "atx_power")
            assert (after.status_code, after.json()) == (200, {"ok": True, "note": None}), after.text
            assert fake.state.actions == ["atx power", "atx power"]
    finally:
        fake.stop()


def test_a_refusal_of_the_board_is_a_no_and_holds_nothing(tmp_path: Path, quick: dict[str, float]) -> None:
    # (A guard: a 4xx is the KVM saying it did not press. Said as such, and the next press goes at once.)
    fake = a_board(atx_reply=(409, '{"ok": false, "result": {"error": "AtxOperationError", "error_msg": "The board is busy"}}'))
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: client.get("/api/v1/status").json()[device]["atx"]["enabled"] is True, "the board was never seen")
            _, first = press(client, device, "atx_power")
            assert (first.status_code, first.json()) == (502, {"code": "action_failed", "message": "The board is busy"}), first.text
            wait_until(lambda: pressed_rows(client, device) == [False], "the history does not say it was not pressed")
            fake.state.atx_reply = None
            assert press(client, device, "atx_power")[1].status_code == 200
    finally:
        fake.stop()


def test_a_press_never_answered_or_broken_off_holds_the_board_from_when_it_was_given_up_on(tmp_path: Path, quick: dict[str, float], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "BOARD_ANSWER", 1.0, raising=False)
    fake = a_board(slow_action=3.0)
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: client.get("/api/v1/status").json()[device]["atx"]["enabled"] is True, "the board was never seen")
            _, first = press(client, device, "atx_power")
            gave_up = time.monotonic()
            assert (first.status_code, first.json()["code"]) == (504, "timeout") and "may have" in first.json()["message"], first.text
            fake.state.slow_action = 0.0
            for wait in (0.0, 0.8):  # (held: the answer's time and the hold, 1.0 + 0.3, from when it was given up on)
                time.sleep(max(0.0, gave_up + wait - time.monotonic()))
                _, again = press(client, device, "atx_power")
                assert (again.status_code, again.json()["code"]) == (409, "busy"), (wait, again.text)
            time.sleep(max(0.0, gave_up + 1.5 - time.monotonic()))
            assert press(client, device, "atx_power")[1].status_code == 200
            # Broken off on its way: it may have pressed as well.
            fake.state.atx_reply = (0, "")
            _, broken = press(client, device, "atx_reset")
            assert (broken.status_code, broken.json()["code"]) == (502, "dropped") and "may have" in broken.json()["message"], broken.text
            fake.state.atx_reply = None
            assert press(client, device, "atx_reset")[1].json()["code"] == "busy"
            assert fake.state.actions == ["atx power", "atx power", "atx reset"], fake.state.actions
            # (Each refusal while it was held is a press not made: "busy".)
            rows = [None, False, False, True, None, False]
            wait_until(lambda: pressed_rows(client, device) == rows, f"the history says {pressed_rows(client, device)}, not {rows}")
    finally:
        fake.state.slow_action = 0.0
        fake.stop()


def test_a_tile_saved_anew_while_its_press_is_out_leaves_the_board_alone_in_the_new_client_too(tmp_path: Path, quick: dict[str, float], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "BOARD_ANSWER", 5.0, raising=False)
    fake = a_board(slow_action=3.0)
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: client.get("/api/v1/status").json()[device]["atx"]["enabled"] is True, "the board was never seen")
            answers: list[Any] = []
            pressing = threading.Thread(target=lambda: answers.append(press(client, device, "atx_power")))
            pressing.start()
            wait_until(lambda: "atx power" in fake.state.actions, "the button was never pressed")
            assert client.put(f"/api/v1/devices/{device}", json={"url": fake.url, "name": "Renamed"}).status_code == 200
            pressing.join(15)
            assert answers[0][1].json()["code"] == "timeout" and "may have been done" in answers[0][1].json()["message"], answers[0][1].text
            fake.state.slow_action = 0.0
            _, after = press(client, device, "atx_power")
            assert (after.status_code, after.json()["code"]) == (409, "busy"), after.text
            assert fake.state.actions == ["atx power"]
    finally:
        fake.state.slow_action = 0.0
        fake.stop()


def test_a_press_cut_off_while_its_click_is_out_leaves_the_board_alone(quick: dict[str, float], monkeypatch: pytest.MonkeyPatch) -> None:
    # (qKVM stopping, or its listeners reopened: the request is stopped while the click is on its way. Whatever comes next
    # through the same connection to the KVM waits as after any press with no clear answer.)
    monkeypatch.setattr(kvm, "BOARD_ANSWER", 5.0, raising=False)
    fake = a_board(slow_action=3.0)

    async def run() -> None:
        device = KvmDevice(DeviceSpec("dev", "A Comet", fake.url, "admin", "secret"))
        try:
            pressing = asyncio.ensure_future(device.act("atx_power"))
            while "atx power" not in fake.state.actions:
                await asyncio.sleep(0.02)
            pressing.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await pressing
            fake.state.slow_action = 0.0
            with pytest.raises(KvmError) as refused:
                await device.act("atx_power")
            assert (refused.value.code, refused.value.status) == ("busy", 409), refused.value.message
            assert fake.state.actions == ["atx power"]
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        fake.state.slow_action = 0.0
        fake.stop()
