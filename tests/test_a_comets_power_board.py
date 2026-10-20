"""What a real Comet with its ATX power board taught (2026-10-14), against a stand-in that answers as that board did.

The board says how the computer is in a word of its own while its light stays false; it answers one asker at a time and
tells whoever asks meanwhile that there is no board.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

from qkvm import alerts, kvm
from qkvm.kvm import power_said
from tests.fake_kvm import FakeKvm, FakeState
from tests.test_alerts import Inbox, baseline
from tests.test_history import hist
from tests.test_wall import add, wait_until, wall


@pytest.fixture(autouse=True)
def looked_at_often(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)


def test_what_the_board_says_of_the_computer_is_taken_by_its_word_and_by_kind() -> None:
    # A Comet: the word, and its light false beside it whatever the computer does.
    assert power_said({"enabled": True, "power": "on", "leds": {"power": False}}) is True
    assert power_said({"enabled": True, "power": "sleep", "leds": {"power": False}}) is True  # asleep is on: a press wakes it
    assert power_said({"enabled": True, "power": "off", "leds": {"power": False}}) is False
    # A word not known, or one of another kind, says nothing; the light beside it is no witness where there is a word.
    for word in ("standby", "ON", "", 1, 0, True, False, None, ["on"], {"on": True}):
        assert power_said({"power": word, "leds": {"power": True}}) is None, word
    # Stock kvmd: no word, the light.
    assert power_said({"enabled": True, "leds": {"power": True}}) is True
    assert power_said({"enabled": True, "leds": {"power": False}}) is False
    assert power_said({"enabled": True, "leds": {"power": "yes"}}) is None
    for nothing in (None, [], "on", {"leds": None}):
        assert power_said(nothing) is None


def test_the_tile_says_the_computers_power_as_a_comets_board_says_it(tmp_path: Path) -> None:
    fake = FakeKvm(FakeState(atx=True)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)

            def atx() -> dict[str, Any]:
                found: dict[str, Any] = client.get("/api/v1/status").json()[device]["atx"]
                return found

            wait_until(lambda: atx()["power"] is True, "a running computer was never said to be on")
            assert atx() == {"enabled": True, "power": True, "hdd": False}
            fake.state.computer_on = False
            wait_until(lambda: atx()["power"] is False, "a computer switched off was never said to be off")
            fake.state.computer_on, fake.state.asleep = True, True
            wait_until(lambda: atx()["power"] is True, "a computer asleep was never said to be on")
            # And as stock kvmd says it, by its light.
            fake.state.asleep, fake.state.atx_words, fake.state.computer_on = False, False, False
            wait_until(lambda: atx()["power"] is False, "a computer off, by its light, was never said to be off")
            fake.state.computer_on = True
            wait_until(lambda: atx()["power"] is True, "a computer on, by its light, was never said to be on")
            # The history has it as it was: on, off, on (asleep is on), and on by the light.
            wait_until(lambda: client.get(hist(device)).json()["power"] == "on", "the history never had the computer on")
            events = client.get(hist(device, what="events")).json()["rows"]
            assert [(row["kind"], row["what"]) for row in events] == [("power", "off"), ("power", "on"), ("power", "off"), ("power", "on")]
    finally:
        fake.stop()


def test_a_kvm_without_a_board_says_nothing_of_a_computers_power(tmp_path: Path) -> None:
    fake = FakeKvm(FakeState(atx=False)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            status = client.get("/api/v1/status").json()[device]
            wait_until(lambda: client.get("/api/v1/status").json()[device]["state"] == "online", "the KVM was never looked at")
            status = client.get("/api/v1/status").json()[device]
            assert status["atx"] == {"enabled": False, "power": None, "hdd": None}
            assert "power" not in status["can"] and "reset" not in status["can"]
    finally:
        fake.stop()


def asking_beside(fake: FakeKvm, stop: threading.Event) -> threading.Thread:
    """Somebody else asking the KVM's board every tenth of a second (its own page, another wall, a script)."""
    token = "somebody-else"
    fake.state.tokens.add(token)

    def ask() -> None:
        with httpx.Client(base_url=fake.url, cookies={"auth_token": token}, timeout=5) as other:
            while not stop.is_set():
                other.get("/api/atx")
                time.sleep(0.1)

    thread = threading.Thread(target=ask, daemon=True)
    thread.start()
    return thread


@pytest.mark.parametrize("words", [True, False], ids=["as a Comet says it", "by its light"])
def test_a_board_that_says_there_is_none_while_it_answers_somebody_else_keeps_its_buttons(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, words: bool) -> None:
    # A Comet's board answers one asker at a time and tells whoever asks meanwhile "no board, computer off". With one
    # other asker, one answer in five said so on a real one, and each time the tile lost its power buttons (for the
    # four seconds until the next look) and the history had the running computer switched off and on again.
    monkeypatch.setattr(kvm, "BOARD_KEPT", 3.0)
    # (Asked at /api/atx: a KVM whose events do not carry its board. On the line for events: test_a_comets_board_on_its_line_for_events.py.)
    fake = FakeKvm(FakeState(atx=True, atx_answer=0.05, atx_words=words, atx_events=False)).start()
    stop = threading.Event()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: client.get("/api/v1/status").json()[device]["atx"]["power"] is True, "the board was never heard")
            other = asking_beside(fake, stop)
            said = []
            # (Four seconds, and on until the board was asked twice at once more than five times: in four seconds alone a
            # busy computer asked it so too seldom, and the test proved nothing.)
            until, give_up = time.monotonic() + 4, time.monotonic() + 60
            while (time.monotonic() < until or fake.state.atx_overlaps <= 5) and time.monotonic() < give_up:
                status = client.get("/api/v1/status").json()[device]
                said.append((status["atx"]["enabled"], status["atx"]["power"], "power" in status["can"] and "reset" in status["can"]))
                time.sleep(0.02)
            stop.set()
            other.join(10)
            assert fake.state.atx_overlaps > 5, "the board was never asked twice at once: the test proves nothing"
            assert {enabled for enabled, _, _ in said} == {True}, "the board was said to be gone while it answered somebody else"
            assert all(buttons for _, _, buttons in said), "the tile lost its power buttons while the board answered somebody else"
            assert {power for _, power, _ in said} == {True}, "the running computer was said to be off, or not known, while the board answered somebody else"
            assert [row for row in client.get(hist(device, what="events")).json()["rows"] if row["kind"] == "power"] == []
            # A board that is gone for longer than that is gone: its buttons go with it.
            fake.state.atx = False
            wait_until(lambda: "power" not in client.get("/api/v1/status").json()[device]["can"], "the buttons of a board that is gone stayed", timeout=10)
            assert client.get("/api/v1/status").json()[device]["atx"] == {"enabled": False, "power": None, "hdd": None}
    finally:
        stop.set()
        fake.stop()


# --- the buttons: held on after the click is answered, and seen done ----------------------------------------------------


@pytest.fixture
def quick(monkeypatch: pytest.MonkeyPatch) -> dict[str, float]:
    """The board's holds and the waits for what a press changes, made short; the same holds for the stand-in."""
    held = {"atx_power": 0.3, "atx_power_long": 1.2, "atx_reset": 0.3}
    monkeypatch.setattr(kvm, "HELD", held)
    monkeypatch.setattr(kvm, "SEEN_WITHIN", 2.0)
    monkeypatch.setattr(kvm, "SEEN_EVERY", 0.1)
    return {"power": held["atx_power"], "power_long": held["atx_power_long"], "reset": held["atx_reset"]}


def press(client: Any, device: str, action: str) -> tuple[float, Any]:
    began = time.monotonic()
    reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": action})
    return time.monotonic() - began, reply


def test_a_button_the_board_holds_after_answering_is_one_thing_at_a_time(tmp_path: Path, quick: dict[str, float], monkeypatch: pytest.MonkeyPatch) -> None:
    # A Comet answers the click at once and holds the button on (six and a half seconds for the long press). The wall
    # let go of the machine at the answer, and a second press sent meanwhile went to the board, which took it as well.
    # (Reset: nothing is waited for after it is let go, so what holds the machine here is the hold alone.)
    monkeypatch.setattr(kvm, "HELD", {**kvm.HELD, "atx_reset": 1.2})
    fake = FakeKvm(FakeState(atx=True, holds={**quick, "reset": 1.2}, busy_for=0.1)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            first: list[Any] = []
            pressing = threading.Thread(target=lambda: first.append(press(client, device, "atx_reset")))
            pressing.start()
            wait_until(lambda: "atx reset" in fake.state.actions, "the button was never pressed")
            time.sleep(0.3)  # the click has long been answered, and the board said busy for a tenth of a second; it holds on
            second = press(client, device, "atx_power")[1]
            assert (second.status_code, second.json()["code"]) == (409, "busy"), second.text
            pressing.join(20)
            took, answer = first[0]
            assert (answer.status_code, answer.json()) == (200, {"ok": True, "note": None}), answer.text
            assert took >= 1.2, f"the reset was said done after {took:.2f} s, while the board held the button 1.2 s"
            assert fake.state.actions == ["atx reset"] and fake.state.held_over == 0
            assert press(client, device, "atx_power")[1].status_code == 200  # let go, the next one goes through
    finally:
        fake.stop()


def test_what_the_board_says_before_a_press_is_asked_again_once_where_it_said_no_board(tmp_path: Path, quick: dict[str, float]) -> None:
    # Asked while it answered somebody else, the board says "no board" and nothing of the computer: the press would not be
    # waited for until it is seen. Asked again at once, it says. (Asked at /api/atx: a KVM whose events do not carry it.)
    fake = FakeKvm(FakeState(atx=True, holds=quick, computer_follows=True, computer_on=False, signal=False, atx_lag=0.5, atx_events=False)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: client.get("/api/v1/status").json()[device]["atx"]["power"] is False, "the computer was never seen off")
            fake.state.atx_none_next = 1
            took, reply = press(client, device, "atx_power")
            assert (reply.status_code, reply.json()) == (200, {"ok": True, "note": None}), reply.text
            assert fake.state.atx_none_next == 0 and took >= 0.5, f"answered after {took:.2f} s: the board's word was not waited for"
    finally:
        fake.stop()


def test_a_press_whose_board_says_nothing_afterwards_says_so_within_the_time(tmp_path: Path, quick: dict[str, float], monkeypatch: pytest.MonkeyPatch) -> None:
    # The board answers the click, and then no question about the computer within the time: "still off" would be a guess.
    # (Asked at /api/atx: a KVM whose events do not carry its board.)
    monkeypatch.setattr(kvm, "HELD", {**kvm.HELD, "atx_power": 1.0})
    fake = FakeKvm(FakeState(atx=True, holds={**quick, "power": 1.0}, computer_on=False, signal=False, atx_events=False)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: client.get("/api/v1/status").json()[device]["atx"]["power"] is False, "the computer was never seen off")
            answers: list[Any] = []
            pressing = threading.Thread(target=lambda: answers.append(press(client, device, "atx_power")))
            pressing.start()
            wait_until(lambda: "atx power" in fake.state.actions, "the button was never pressed")
            fake.state.slow["/api/atx"] = 30.0  # from now on, every question about the board is left unanswered
            pressing.join(30)
            took, reply = answers[0]
            assert (reply.status_code, reply.json()) == (200, {"ok": True, "note": "pressed; its board has not said since"}), reply.text
            assert took < 1.0 + kvm.SEEN_WITHIN + 1.5, f"a wait of {kvm.SEEN_WITHIN} s after the hold took {took:.2f} s"
    finally:
        fake.state.slow.clear()
        fake.stop()


def test_a_press_whose_tile_is_changed_while_its_change_is_waited_for_is_said_pressed(tmp_path: Path, quick: dict[str, float]) -> None:
    # The click was answered: the button was pressed. That the tile was saved again meanwhile ends the waiting, and is
    # not "it may have been done".
    fake = FakeKvm(FakeState(atx=True, holds=quick, computer_on=False, signal=False)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: client.get("/api/v1/status").json()[device]["atx"]["power"] is False, "the computer was never seen off")
            answers: list[Any] = []
            pressing = threading.Thread(target=lambda: answers.append(press(client, device, "atx_power")))
            pressing.start()
            wait_until(lambda: "atx power" in fake.state.actions, "the button was never pressed")
            time.sleep(quick["power"] + 0.3)  # let go, and the change is being waited for
            edited = client.put(f"/api/v1/devices/{device}", json={"url": fake.url, "name": "Renamed"})
            assert edited.status_code == 200, edited.text
            pressing.join(30)
            reply = answers[0][1]
            assert (reply.status_code, reply.json()) == (200, {"ok": True, "note": "pressed; not seen: its connection ended"}), reply.text
            assert fake.state.actions == ["atx power"]
    finally:
        fake.stop()


def test_a_press_cut_off_by_qkvm_stopping_while_the_button_is_held_is_written_down_as_pressed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The web server gives a request three seconds when qKVM stops, and the board holds the long press six and a half:
    # the request is cut off while the button is held. It was pressed: "may have been done" in the log, and in the page
    # a failure offered for a retry, would have it pressed again.
    from qkvm import cli
    from tests.test_hardening import LiveWall
    from tests.test_wall import CSRF, PASSWORD

    monkeypatch.setattr(kvm, "HELD", {**kvm.HELD, "atx_power_long": 6.5})
    fake = FakeKvm(FakeState(atx=True, holds={"power": 0.5, "power_long": 6.5, "reset": 0.5})).start()
    data = tmp_path / "data"
    answers: list[Any] = []
    try:
        with LiveWall(data, **cli.SERVER_OPTIONS) as live, httpx.Client(base_url=live.url, headers=CSRF, timeout=30) as admin:
            assert admin.post("/api/v1/setup", json={"password": PASSWORD}).status_code == 200
            device = admin.post("/api/v1/devices", json={"url": fake.url, "password": "secret"}).json()["device"]["id"]

            def hold() -> None:
                try:
                    answers.append(admin.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power_long"}).status_code)
                except httpx.HTTPError as ex:
                    answers.append(type(ex).__name__)

            pressing = threading.Thread(target=hold)
            pressing.start()
            wait_until(lambda: "atx power_long" in fake.state.actions, "the button was never pressed")
            time.sleep(0.5)  # the click was answered; the board holds the button
            live._server.should_exit = True
            pressing.join(30)
        lines = [json.loads(line) for line in (data / "audit.log").read_text(encoding="utf-8").splitlines()]
        pressed = [line for line in lines if line["event"] in ("action", "action_failed")]
        assert [(line["event"], line.get("note")) for line in pressed] == [("action", "qKVM was stopped after the KVM had taken the press: it was pressed")], pressed
        assert fake.state.actions == ["atx power_long"]
    finally:
        fake.stop()


def test_a_press_cut_off_by_qkvm_stopping_before_the_kvm_answered_it_may_have_been_done(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The other way round: the click went out and its answer had not come when qKVM stopped. Nobody knows whether the
    # board took it, and that is what is written down.
    from qkvm import cli
    from tests.test_hardening import LiveWall
    from tests.test_wall import CSRF, PASSWORD

    fake = FakeKvm(FakeState(atx=True, slow_action=10.0)).start()
    data = tmp_path / "data"
    answers: list[Any] = []
    try:
        with LiveWall(data, **cli.SERVER_OPTIONS) as live, httpx.Client(base_url=live.url, headers=CSRF, timeout=30) as admin:
            assert admin.post("/api/v1/setup", json={"password": PASSWORD}).status_code == 200
            device = admin.post("/api/v1/devices", json={"url": fake.url, "password": "secret"}).json()["device"]["id"]

            def hold() -> None:
                try:
                    answers.append(admin.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_power_long"}).status_code)
                except httpx.HTTPError as ex:
                    answers.append(type(ex).__name__)

            pressing = threading.Thread(target=hold)
            pressing.start()
            wait_until(lambda: "atx power_long" in fake.state.actions, "the button was never pressed")
            time.sleep(0.3)  # the click is with the KVM, which takes its time over the answer
            live._server.should_exit = True
            pressing.join(30)
        lines = [json.loads(line) for line in (data / "audit.log").read_text(encoding="utf-8").splitlines()]
        pressed = [(line["event"], line.get("error", "")) for line in lines if line["event"] in ("action", "action_failed")]
        assert pressed == [("action_failed", "qKVM was stopped or restarted before the machine answered: it may have been done")], pressed
    finally:
        fake.state.slow_action = 0.0
        fake.stop()


def test_a_look_after_a_press_is_not_cut_off_where_it_has_to_sign_in_again(tmp_path: Path, quick: dict[str, float]) -> None:
    # The KVM forgot the wall's session after the click, and takes longer to let it in again than the time left to wait.
    # Cut off with the look, that sign-in counted as one that came to nothing, and the tile of a KVM in good health said
    # "does not sign qKVM in" for the ten seconds after; let go on by itself, it ends, and the tile goes on as it was.
    # (Asked at /api/atx: a KVM whose events do not carry its board.)
    fake = FakeKvm(FakeState(atx=True, holds=quick, computer_on=False, signal=False, atx_events=False)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: client.get("/api/v1/status").json()[device]["atx"]["power"] is False, "the computer was never seen off")
            answers: list[Any] = []
            pressing = threading.Thread(target=lambda: answers.append(press(client, device, "atx_power")))
            pressing.start()
            wait_until(lambda: "atx power" in fake.state.actions, "the button was never pressed")
            fake.state.slow_login = kvm.SEEN_WITHIN + 1.0
            fake.state.tokens.clear()  # the session is forgotten: the next look signs in again, slowly
            pressing.join(30)
            took, reply = answers[0]
            assert (reply.status_code, reply.json()) == (200, {"ok": True, "note": "pressed; its board has not said since"}), reply.text
            assert took < quick["power"] + kvm.SEEN_WITHIN + 1.0, f"answered after {took:.2f} s"
            seen: list[str] = []

            def well_again() -> bool:
                seen.append(client.get("/api/v1/status").json()[device]["state"])
                return seen[-1] == "no_signal" and fake.state.tokens != set()

            wait_until(well_again, "the KVM's tile did not come back after the sign-in it was in the middle of", timeout=6)
            assert "error" not in seen, seen
    finally:
        fake.state.slow_login = 0.0
        fake.stop()


def test_a_press_the_board_is_busy_with_already_is_not_sent(tmp_path: Path, quick: dict[str, float]) -> None:
    # Pressed from the KVM's own page, or by another program, a moment before: the board says it is busy.
    fake = FakeKvm(FakeState(atx=True, holds={**quick, "power_long": 3.0}, busy_for=3.0)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            fake.state.tokens.add("its-own-page")
            with httpx.Client(base_url=fake.url, cookies={"auth_token": "its-own-page"}) as own_page:
                assert own_page.post("/api/atx/click", params={"button": "power_long"}).status_code == 200
            reply = press(client, device, "atx_power")[1]
            assert (reply.status_code, reply.json()["code"]) == (409, "busy"), reply.text
            assert fake.state.actions == ["atx power_long"]
    finally:
        fake.stop()


def test_a_press_that_must_change_the_power_is_done_when_the_board_shows_it(tmp_path: Path, quick: dict[str, float]) -> None:
    # Off, a short press switches the computer on; on, the long one cuts its power. Either is answered once the board
    # shows it (a real Comet's word came three or four seconds after the computer), not when the click was answered.
    fake = FakeKvm(FakeState(atx=True, holds=quick, computer_follows=True, computer_on=False, signal=False, atx_lag=0.5)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: client.get("/api/v1/status").json()[device]["atx"]["power"] is False, "the computer was never seen off")
            took, reply = press(client, device, "atx_power")
            assert (reply.status_code, reply.json()) == (200, {"ok": True, "note": None}), reply.text
            assert took >= 0.5, f"switching on was said done after {took:.2f} s, before the board showed it"
            wait_until(lambda: client.get("/api/v1/status").json()[device]["atx"]["power"] is True, "the tile never showed the computer on")
            took, reply = press(client, device, "atx_power_long")
            assert (reply.status_code, reply.json()) == (200, {"ok": True, "note": None}), reply.text
            assert took >= quick["power_long"] + 0.5, f"the power cut was said done after {took:.2f} s, before the board showed it (let go at {quick['power_long']} s, shown half a second later)"
            wait_until(lambda: client.get("/api/v1/status").json()[device]["atx"]["power"] is False, "the tile never showed the computer off")
            # A short press on a running computer asks its system to shut down, which takes the time it takes: done when
            # the button is let go. So is reset.
            fake.state.computer_on = fake.state.signal = True
            fake.state.shuts_down_after = 30.0
            wait_until(lambda: client.get("/api/v1/status").json()[device]["atx"]["power"] is True, "the computer was never seen on")
            for action in ("atx_power", "atx_reset"):
                took, reply = press(client, device, action)
                assert (reply.status_code, reply.json()) == (200, {"ok": True, "note": None}), reply.text
                assert took < kvm.SEEN_WITHIN, f"{action} on a running computer was waited for {took:.2f} s"
    finally:
        fake.stop()


def test_a_press_whose_change_is_not_seen_says_so_and_is_no_failure(tmp_path: Path, quick: dict[str, float]) -> None:
    # The board pressed the button, and the computer did not come on (its power supply switched off at the back, say):
    # said, as a word with the answer. Not a failure: "Retry failed" would press the button again on a computer that
    # may be on its way all the same.
    fake = FakeKvm(FakeState(atx=True, holds=quick, computer_on=False, signal=False)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: client.get("/api/v1/status").json()[device]["atx"]["power"] is False, "the computer was never seen off")
            took, reply = press(client, device, "atx_power")
            assert (reply.status_code, reply.json()) == (200, {"ok": True, "note": "pressed, but the computer is still off"}), reply.text
            assert took >= kvm.SEEN_WITHIN
            fake.state.computer_on = fake.state.signal = True  # (a computer that does not take the long press either)
            wait_until(lambda: client.get("/api/v1/status").json()[device]["atx"]["power"] is True, "the computer was never seen on")
            took, reply = press(client, device, "atx_power_long")
            assert (reply.status_code, reply.json()) == (200, {"ok": True, "note": "held, but the computer is still on"}), reply.text
            wait_until(lambda: len(client.get(hist(device, what="events")).json()["rows"]) >= 3, "the presses never reached the history")
            pressed = [(row["what"], row["ok"], row["note"]) for row in client.get(hist(device, what="events")).json()["rows"] if row["kind"] == "pressed"]
            assert pressed == [("atx_power", True, "pressed, but the computer is still off"), ("atx_power_long", True, "held, but the computer is still on")]
            log = [entry for entry in client.get("/api/v1/audit").json()["entries"] if entry["event"] == "action"]
            assert [entry.get("note") for entry in log[:2]] == ["held, but the computer is still on", "pressed, but the computer is still off"]
    finally:
        fake.stop()


def test_a_light_that_says_off_beside_a_picture_is_no_witness_of_a_press(tmp_path: Path, quick: dict[str, float]) -> None:
    # Stock kvmd's light, not wired up: "off" while the computer sends its picture. What a press does is not waited for
    # there: the light would never say it.
    fake = FakeKvm(FakeState(atx=True, holds=quick, atx_words=False, computer_on=False, signal=True)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: client.get("/api/v1/status").json()[device]["state"] == "online", "the KVM was never looked at")
            took, reply = press(client, device, "atx_power")
            assert (reply.status_code, reply.json()) == (200, {"ok": True, "note": None}), reply.text
            assert took < kvm.SEEN_WITHIN, f"a press beside a light that is no witness was waited for {took:.2f} s"
    finally:
        fake.stop()


@pytest.mark.parametrize("words", [True, False], ids=["as a Comet says it", "by its light"])
def test_the_alert_says_a_computer_is_off_or_asleep_where_its_kvms_board_says_so(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, words: bool) -> None:
    # A Comet whose board saw the computer switched off was told of as "has no video signal: the computer is off, asleep
    # or no longer plugged into the KVM", which the board could have said better: its light is out, so the computer is
    # off or asleep (a real PC put its light out asleep, and its Comet said "off"), and no cable came loose. Without a board, or with one that
    # says the computer is on (a screen asleep), the signal is what is told of, as before.
    monkeypatch.setattr(alerts, "CHECK_EVERY", 0.05)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    fake = FakeKvm(FakeState(atx=True, atx_words=words)).start()
    inbox = Inbox()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url, name="Demo PC")
            assert admin.put("/api/v1/alerts", json={"enabled": True, "webhook": inbox.url}).status_code == 200
            wait_until(lambda: admin.get("/api/v1/status").json()[device]["atx"]["power"] is True, "the computer was never seen on")
            baseline()
            fake.state.computer_on = fake.state.signal = False
            wait_until(lambda: "Demo PC is off or asleep" in inbox.titles(), "no alert that the computer was switched off")
            said = [json.loads(item["body"]) for item in inbox.received]
            assert said[-1]["message"] == "The KVM's power board shows the computer's power light out." and said[-1]["event"] == "no_signal"
            fake.state.computer_on = fake.state.signal = True
            wait_until(lambda: "Demo PC has a picture again" in inbox.titles(), "no alert for the computer back on")
            fake.state.signal = False  # the screen asleep, the computer on
            wait_until(lambda: "Demo PC has no video signal" in inbox.titles(), "no alert for the screen gone dark")
            assert inbox.titles().count("Demo PC is off or asleep") == 1
    finally:
        inbox.close()
        fake.stop()


def test_a_computer_that_came_on_has_its_keyboard_found_again_and_is_not_said_to_have_none(tmp_path: Path, quick: dict[str, float]) -> None:
    # A real Comet said "no keyboard" of the computer behind it after the computer came on, until a key was sent (the
    # first Shift found it): the tile said "USB not connected" of a running computer with its cable in. As after a
    # multi-port KVM's switch, that is not knowing.
    fake = FakeKvm(FakeState(atx=True, holds=quick, computer_follows=True, computer_on=False, signal=False, forgets_keyboard=True)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: client.get("/api/v1/status").json()[device]["atx"]["power"] is False, "the computer was never seen off")
            assert press(client, device, "atx_power")[1].json() == {"ok": True, "note": None}
            wait_until(lambda: client.get("/api/v1/status").json()[device]["state"] == "online", "the computer's picture never came")
            assert fake.state.keyboard_online is False
            assert client.get("/api/v1/status").json()[device]["usb"] == {"keyboard": None, "mouse": None}
            assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "keys", "keys": "ShiftLeft"}).status_code == 200
            wait_until(lambda: client.get("/api/v1/status").json()[device]["usb"]["keyboard"] is True, "the keyboard was never found")
            # A keyboard that is gone while the computer runs on is said as gone.
            fake.state.keyboard_online = False
            wait_until(lambda: client.get("/api/v1/status").json()[device]["usb"]["keyboard"] is False, "a keyboard that went was never said to be gone")
    finally:
        fake.stop()
