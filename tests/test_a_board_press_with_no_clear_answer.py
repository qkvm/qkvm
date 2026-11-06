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
from types import SimpleNamespace
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


def a_board(tls_dir: Path | None = None, **how: Any) -> FakeKvm:
    return FakeKvm(FakeState(atx=True, holds={"power": 0.3, "power_long": 1.2, "reset": 0.3}, **how), tls_dir=tls_dir).start()


@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_a_press_answered_with_a_5xx_may_have_pressed_and_is_not_pressed_again_until_it_cannot_be_pressing(tmp_path: Path, quick: dict[str, float], status: int, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = a_board(atx_reply=(status, f"<html><body>{status} Bad Gateway</body></html>"))
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: client.get("/api/v1/status").json()[device]["atx"]["enabled"] is True, "the board was never seen")
            # Keep the short cooldown open while HTTP/history work is scheduled. A slow runner
            # must not turn a correctly expired cooldown into a failed safety assertion.
            now = time.monotonic()
            monkeypatch.setattr(kvm, "time", SimpleNamespace(monotonic=lambda: now, time=time.time))
            _, first = press(client, device, "atx_power")
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
                assert (again.status_code, again.json().get("code")) == (409, "busy"), (action, again.text)
                assert "may still be pressing" in again.json()["message"], again.text
            assert fake.state.actions == ["atx power"] and fake.state.presses == [], (fake.state.actions, fake.state.presses)
            # Advance beyond the answer's time plus the button hold, then let the device clock
            # progress normally again for the successful press and its status polling.
            offset = now + 0.5 + quick["power"] + 0.2 - time.monotonic()
            monkeypatch.setattr(kvm, "time", SimpleNamespace(monotonic=lambda: time.monotonic() + offset, time=time.time))
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


def test_a_press_that_never_went_out_says_nothing_was_pressed_and_holds_nothing(quick: dict[str, float], monkeypatch: pytest.MonkeyPatch) -> None:
    # Register row 4 of 0.2.1 (fx-a N2, w16c): a press refused before its click reached the KVM was said "may have pressed"
    # and held the board (and a Fingerbot on the same machine) for seconds, though nothing had gone out: the tile saved anew
    # (or the wall letting go of the KVM) before it was sent, or no connection to the KVM to be had in time (all of them in
    # use, httpx's PoolTimeout). Now it says nothing was pressed, and the next press goes out at once.
    monkeypatch.setattr(kvm, "WAITS", kvm.httpx.Timeout(8.0, connect=4.0, pool=0.5))  # (a question waits half a second for a connection)
    monkeypatch.setattr(kvm.KvmDevice, "LIMITS", kvm.httpx.Limits(max_connections=1, max_keepalive_connections=1, keepalive_expiry=30.0))
    fake = a_board()

    async def run() -> None:
        spec = DeviceSpec("dev", "A Comet", fake.url, "admin", "secret")
        old = KvmDevice(spec)
        await old.status()
        await old.close()  # saved anew (retired) just before the press goes out
        with pytest.raises(KvmError) as retired:
            await old.act("atx_power")
        assert retired.value.code == "action_failed" and "Nothing was pressed" in retired.value.message, retired.value.message
        new = KvmDevice(spec)
        new.takes_over(old)  # (what holds the board is shared with the client that replaces it)
        try:
            await new.status()
            await new.act("atx_power")  # held by nothing: pressed at once
            assert fake.state.actions == ["atx power"]
            # Every connection to the KVM in use (a picture that takes long): the click waits for one, and gets none.
            fake.state.slow["/api/streamer/snapshot"] = 3.0
            picture = asyncio.ensure_future(new.snapshot(640))
            while "GET /api/streamer/snapshot" not in fake.state.asked:
                await asyncio.sleep(0.02)
            with pytest.raises(KvmError) as no_connection:
                await new.act("atx_reset")
            assert no_connection.value.code == "action_failed" and "Nothing was pressed" in no_connection.value.message, no_connection.value.message
            assert fake.state.actions == ["atx power"]
            del fake.state.slow["/api/streamer/snapshot"]
            with contextlib.suppress(KvmError):
                await picture
            await new.act("atx_reset")  # held by nothing
            assert fake.state.actions == ["atx power", "atx reset"]
        finally:
            await new.close()

    try:
        asyncio.run(run())
    finally:
        fake.state.slow.clear()
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


def test_a_board_that_may_be_pressing_stays_left_alone_through_a_client_made_anew(tmp_path: Path, quick: dict[str, float], monkeypatch: pytest.MonkeyPatch) -> None:
    # Register row 10 of 0.2.1 (fx-a L2): the hold lived in the client and in its successor at the same address, so that the
    # wall locked and opened again (the last person signed out, somebody signs in), an edit to another address of the KVM,
    # or the tile removed and added again, made a client that pressed at once, a second after a press with no clear answer.
    # (Over HTTPS since 0.3.0: the KVM at another address is known for the same one by its certificate, see the next test.)
    from tests.test_wall import PASSWORD

    monkeypatch.setattr(kvm, "BOARD_ANSWER", 30.0, raising=False)  # (held for longer than everything below takes)
    fake = a_board(tls_dir=tmp_path / "kvm", atx_reply=(502, "<html><body>502 Bad Gateway</body></html>"))
    try:
        with wall(tmp_path, locked_start=True) as client:  # (no key of its own: the last person to sign out locks it)
            device = add(client, fake.url)
            wait_until(lambda: client.get("/api/v1/status").json()[device]["atx"]["enabled"] is True, "the board was never seen")
            _, first = press(client, device, "atx_power")
            assert (first.status_code, first.json()["code"]) == (504, "timeout"), first.text
            fake.state.atx_reply = None
            # The wall locked and opened again.
            assert client.post("/api/v1/logout", json={}).status_code == 200
            assert not client.core.vault.unlocked  # type: ignore[attr-defined]
            assert client.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
            _, after_lock = press(client, device, "atx_power")
            assert (after_lock.status_code, after_lock.json()["code"]) == (409, "busy"), after_lock.text
            # Edited to another address of the same KVM (its certificate, the KVM's own, shown there too).
            elsewhere = fake.url.replace("127.0.0.1", "localhost")
            assert client.put(f"/api/v1/devices/{device}", json={"url": elsewhere, "name": "Renamed", "password": "secret"}).status_code == 200
            _, after_edit = press(client, device, "atx_power")
            assert (after_edit.status_code, after_edit.json()["code"]) == (409, "busy"), after_edit.text
            # Removed, and added again at the address it had.
            assert client.delete(f"/api/v1/devices/{device}").status_code == 200
            again = add(client, elsewhere, name="Added again")
            _, after_add = press(client, again, "atx_power")
            assert (after_add.status_code, after_add.json()["code"]) == (409, "busy"), after_add.text
            assert fake.state.actions == ["atx power"], fake.state.actions
    finally:
        fake.stop()


def test_kvms_behind_one_front_door_do_not_share_what_paces_their_power_buttons(tmp_path: Path, quick: dict[str, float], monkeypatch: pytest.MonkeyPatch) -> None:
    # (The final review of 0.3.0, core L7.) Two KVMs reached through one front door show its certificate, both pinned: the
    # second is kept beside the first as a device of its own ("own:", see core.identity), and was found by that certificate
    # all the same. A press of the first with no clear answer had the second "busy", and the second told what the first
    # said of its Fingerbot. The certificate counts only for a tile known by it; the one edited to another address of the
    # KVM (the test before) still is.
    monkeypatch.setattr(kvm, "BOARD_ANSWER", 30.0, raising=False)
    door = tmp_path / "door"
    first = a_board(tls_dir=door, atx_reply=(502, "<html><body>502 Bad Gateway</body></html>"))
    second = a_board(tls_dir=door)
    try:
        with wall(tmp_path / "wall") as client:
            one = add(client, first.url)
            other = client.post("/api/v1/devices", json={"url": second.url, "password": "secret"})
            assert (other.status_code, other.json()["code"]) == (409, "same_device"), other.text  # (one certificate: asked)
            two = add(client, second.url, keep_both=True)
            for device in (one, two):
                wait_until(lambda device=device: client.get("/api/v1/status").json()[device]["atx"]["enabled"] is True, "the board was never seen")
            _, pressed = press(client, one, "atx_power")
            assert (pressed.status_code, pressed.json()["code"]) == (504, "timeout"), pressed.text
            _, there = press(client, two, "atx_power")
            assert there.status_code == 200, there.text
            assert second.state.actions == ["atx power"] and first.state.actions == ["atx power"]
            _, again = press(client, one, "atx_power")
            assert (again.status_code, again.json()["code"]) == (409, "busy"), again.text  # (the first is held as before)
    finally:
        first.stop()
        second.stop()


@pytest.mark.parametrize("other", ["another KVM", "the same KVM over plain HTTP"])
def test_a_tile_edited_to_a_kvm_not_known_for_the_one_that_may_be_pressing_starts_afresh(tmp_path: Path, quick: dict[str, float], monkeypatch: pytest.MonkeyPatch, other: str) -> None:
    # (0.3.0, section 5.) The hold was found by the tile's id as well, and followed the tile to whatever it was edited to: a
    # tile pointed at another KVM after a press with no clear answer was refused "busy" there, for a press that KVM never had,
    # and was told what the KVM before said of its Fingerbot. It is the KVM's: found by its address, and by its certificate
    # where one is pinned (as core.identity knows a KVM at another address). Where nothing tells the KVM at the new address
    # from another (plain HTTP), it starts afresh, as its saved password is typed again there.
    monkeypatch.setattr(kvm, "BOARD_ANSWER", 30.0, raising=False)  # (held for longer than everything below takes)
    fake = a_board(atx_reply=(502, "<html><body>502 Bad Gateway</body></html>"))
    another = a_board() if other == "another KVM" else None
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: client.get("/api/v1/status").json()[device]["atx"]["enabled"] is True, "the board was never seen")
            _, first = press(client, device, "atx_power")
            assert (first.status_code, first.json()["code"]) == (504, "timeout"), first.text
            fake.state.atx_reply = None
            to = another.url if another is not None else fake.url.replace("127.0.0.1", "localhost")
            assert client.put(f"/api/v1/devices/{device}", json={"url": to, "name": "Renamed", "password": "secret"}).status_code == 200
            _, there = press(client, device, "atx_power")
            assert there.status_code == 200, there.text
            assert (another or fake).state.actions[-1] == "atx power", (another or fake).state.actions
    finally:
        fake.stop()
        if another is not None:
            another.stop()
