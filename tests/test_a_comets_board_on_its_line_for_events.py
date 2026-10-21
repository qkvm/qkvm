"""A KVM's power board as it says itself on the KVM's line for events (a real Comet, 2026-10-18), not asked at /api/atx.

Asked, a Comet's board answers one asker at a time and tells whoever asks meanwhile that there is none: the wall's own
questions took it from a second wall or a script beside it. Its own page reads the `atx` event of /api/ws instead, which
the board sends at once and at every change. So does the wall now, on the line it holds anyway while somebody watches the
KVM's picture (the keepalive), and asks only where no event has come (no picture watched, a KVM whose events do not carry
it, a line that is down or quiet) or where the line says "no board" (which a Comet's line says too while somebody else
asks). It opens no line for the board alone: three times the sleeping PC behind the real one woke soon after a line was
opened.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

from qkvm import kvm
from qkvm.kvm import power_said
from tests.fake_kvm import FakeKvm, FakeState
from tests.test_a_comets_power_board import press
from tests.test_history import hist
from tests.test_wall import add, wait_until, wall


@pytest.fixture(autouse=True)
def looked_at_often(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)


@pytest.fixture
def quick(monkeypatch: pytest.MonkeyPatch) -> dict[str, float]:
    """The board's holds and the waits for what a press changes, made short; the same holds for the stand-in."""
    held = {"atx_power": 0.3, "atx_power_long": 1.2, "atx_reset": 0.3}
    monkeypatch.setattr(kvm, "HELD", held)
    monkeypatch.setattr(kvm, "SEEN_WITHIN", 2.0)
    monkeypatch.setattr(kvm, "SEEN_EVERY", 0.1)
    return {"power": held["atx_power"], "power_long": held["atx_power_long"], "reset": held["atx_reset"]}


def asked(fake: FakeKvm) -> int:
    """How often the board was asked at /api/atx, by anybody, so far."""
    return sum(1 for question in list(fake.state.asked) if question == "GET /api/atx")


def board_of(client: Any, device: str) -> dict[str, Any]:
    status: dict[str, Any] = client.get("/api/v1/status").json()[device]
    return {**status["atx"], "buttons": "power" in status["can"] and "reset" in status["can"]}


def watched(client: Any, device: str) -> dict[str, Any]:
    """The tile looked at as a page that shows it looks: its picture asked for (which has the wall hold the KVM's line), and how it is."""
    client.get(f"/api/v1/devices/{device}/snapshot", params={"w": 480})
    return board_of(client, device)


def heard_on_its_line(client: Any, fake: FakeKvm, device: str, then: bool = True) -> None:
    """Until the wall holds the KVM's line for its picture, has heard the board there, and no longer asks it.

    `then=False`: watched for as long, and on whatever is the case then (a test that proves its own point on a program
    that does not hear the board there, rather than failing here).
    """
    seen: list[int] = []

    def heard() -> bool:
        watched(client, device)
        seen.append(asked(fake))
        return fake.state.streams == 1 and fake.state.atx_events_sent >= 1 and len(seen) > 5 and seen[-1] == seen[-6]

    if then:
        wait_until(heard, "the wall went on asking the board beside the line it holds for the picture, which says it", timeout=15)
        return
    until = time.monotonic() + 2.0
    while not heard() and time.monotonic() < until:
        time.sleep(0.05)


def test_what_a_line_for_events_says_of_the_board_is_read_by_kind() -> None:
    board_heard, event_of = kvm.board_heard, kvm.event_of
    # The `atx` event of a real Comet, and of stock kvmd (by its source: `acts` beside the rest, no word).
    comet = {"enabled": True, "busy": False, "power": "on", "leds": {"power": False, "hdd": False}}
    assert board_heard(comet) == {"enabled": True, "busy": False, "power": "on", "leds": {"power": False, "hdd": False}}
    assert power_said(board_heard(comet)) is True
    stock = {"enabled": True, "busy": True, "acts": {"power": True, "reset": False}, "leds": {"power": True, "hdd": False}}
    assert board_heard(stock) == {"enabled": True, "busy": True, "leds": {"power": True, "hdd": False}}
    assert power_said(board_heard(stock)) is True
    # What is of another kind says nothing; a word that is no word says nothing, and the light beside it is no witness.
    odd = board_heard({"enabled": "yes", "busy": 1, "power": "ON", "leds": {"power": "on", "hdd": None}})
    assert odd == {"enabled": None, "busy": None, "power": None, "leds": {"power": None, "hdd": None}}
    assert power_said(odd) is None
    assert board_heard({"enabled": True, "power": ["on"], "leds": [True]}) == {"enabled": True, "busy": None, "power": None, "leds": {}}
    for nothing in (None, [], "atx", 1, True):
        assert board_heard(nothing) is None
    # A message that is no event, or nested past what can be read, is nothing; text only.
    assert event_of('{"event_type": "atx", "event": {"enabled": true}}') == ("atx", {"enabled": True})
    for message in ("[1]", "{}", '{"event_type": 5}', "not json", b'{"event_type": "atx"}', "[" * 100_000 + "]" * 100_000):
        assert event_of(message) is None


def test_a_board_is_heard_on_the_kvms_line_for_events_and_not_asked(tmp_path: Path) -> None:
    # Asked at every look, the board was taken from whoever else asked it in that moment; and the wall heard of a change at
    # its next look. On the line the wall holds for the picture, the change comes when the board says it.
    fake = FakeKvm(FakeState(atx=True)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: board_of(client, device)["power"] is True, "a running computer was never said to be on")
            heard_on_its_line(client, fake, device)
            before = asked(fake)
            fake.state.computer_on = False
            wait_until(lambda: watched(client, device)["power"] is False, "a computer switched off was never said to be off")
            fake.state.computer_on = fake.state.asleep = True
            wait_until(lambda: watched(client, device)["power"] is True, "a computer asleep was never said to be on")
            assert asked(fake) == before, "the board was asked, while its line for events said it all"
            assert board_of(client, device) == {"enabled": True, "power": True, "hdd": False, "buttons": True}
            wait_until(lambda: client.get(hist(device)).json()["power"] == "on", "the history never had the computer on")
            events = client.get(hist(device, what="events")).json()["rows"]
            assert [(row["kind"], row["what"]) for row in events] == [("power", "off"), ("power", "on")]
    finally:
        fake.stop()


def test_a_word_of_the_board_that_comes_while_the_tile_is_looked_at_is_not_left_for_the_next_look(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A look reads the board from its line at once, and its other questions take their time; the board's next word came
    # in between, and the look's end marked the tile fresh with the word before it, until the next look.
    fake = FakeKvm(FakeState(atx=True)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            heard_on_its_line(client, fake, device)
            monkeypatch.setattr(kvm, "STATUS_TTL", 30.0)  # (from now on the tile is looked at again only when it is out of date)
            fake.state.slow["/api/info"] = 1.0
            fake.state.asleep = True  # (a word of the board: the tile is looked at again when next asked)
            time.sleep(0.2)
            board_of(client, device)  # (which begins that look; it reads the board at once, and waits a second for the rest)
            time.sleep(0.4)
            fake.state.computer_on = False  # (said on the line while the look waits for its other answers)
            wait_until(lambda: board_of(client, device)["power"] is False, "the tile kept the word from before the look until the next one")
    finally:
        fake.state.slow.clear()
        fake.stop()


def test_no_line_is_opened_for_the_board_where_nobody_watches_the_kvms_picture(tmp_path: Path) -> None:
    # Three times the sleeping PC behind a real Comet woke within seconds of a line being opened to it. A wall that only
    # looks at a tile (its alerts do, every fifteen seconds) opens none, and asks the board as it always did.
    fake = FakeKvm(FakeState(atx=True)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: board_of(client, device)["power"] is True, "a running computer was never said to be on")
            until = time.monotonic() + 1.5
            while time.monotonic() < until:
                board_of(client, device)
                time.sleep(0.05)
            assert fake.state.ws_streams == [] and fake.state.viewers == 0, "a line was opened to a KVM whose picture nobody watched"
            before = asked(fake)
            fake.state.computer_on = False
            wait_until(lambda: board_of(client, device)["power"] is False, "a computer switched off was never said to be off")
            assert asked(fake) > before
    finally:
        fake.stop()


def test_stock_kvmds_board_is_heard_by_its_light_on_its_line_for_events(tmp_path: Path) -> None:
    # Stock kvmd sends the board's state on its line too (its poller yields the whole of it), with the light and no word;
    # and its session is never put in the address of that line, which its log writes down.
    fake = FakeKvm(FakeState(stock=True, atx=True, atx_words=False)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: board_of(client, device)["power"] is True, "a computer on, by its light, was never said to be on")
            heard_on_its_line(client, fake, device)
            before = asked(fake)
            fake.state.computer_on = False
            wait_until(lambda: watched(client, device)["power"] is False, "a computer off, by its light, was never said to be off")
            assert asked(fake) == before
            assert [query for query in fake.state.ws_queries if "auth_token" in query] == []
    finally:
        fake.stop()


def test_the_board_said_on_its_line_stays_said_while_every_answer_at_api_atx_says_there_is_none(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Somebody else asks the board all the while, and every answer this wall would get at /api/atx says "no board, off".
    # Its line for events goes on saying how it is, and so does the tile: the power past the ten seconds a board's last
    # word is kept through such answers, and the buttons.
    monkeypatch.setattr(kvm, "POWER_KEPT", 1.0)
    fake = FakeKvm(FakeState(atx=True)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            heard_on_its_line(client, fake, device, then=False)
            fake.state.atx_none_next = 10**9
            said = []
            until = time.monotonic() + 2.5
            while time.monotonic() < until:
                said.append(watched(client, device))
                time.sleep(0.05)
            assert {(each["enabled"], each["power"], each["buttons"]) for each in said} == {(True, True, True)}, said[-1]
    finally:
        fake.stop()


@pytest.mark.parametrize("words", [True, False], ids=["as a Comet says it", "by its light"])
def test_a_moments_no_board_on_the_line_for_events_takes_nothing_away(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, words: bool) -> None:
    # A Comet's line says "no board, off" while the board answers somebody else at /api/atx (on a real one, for as long as
    # two others asked). That is no word on the computer: the buttons stay, and the power the board said last, as through
    # such an answer to a question (BOARD_KEPT, POWER_KEPT); a board gone for longer is gone.
    monkeypatch.setattr(kvm, "BOARD_KEPT", 3.0)
    fake = FakeKvm(FakeState(atx=True, atx_words=words)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            heard_on_its_line(client, fake, device)
            fake.state.atx_event_none = True
            fake.state.atx_none_next = 10**9  # (and asked, it says the same)
            said = []
            until = time.monotonic() + 1.5
            while time.monotonic() < until:
                said.append(watched(client, device))
                time.sleep(0.05)
            assert {(each["enabled"], each["power"], each["buttons"]) for each in said} == {(True, True, True)}, said
            assert [row for row in client.get(hist(device, what="events")).json()["rows"] if row["kind"] == "power"] == []
            wait_until(lambda: not watched(client, device)["buttons"], "the buttons of a board that is gone stayed", timeout=10)
            assert board_of(client, device) == {"enabled": False, "power": None, "hdd": None, "buttons": False}
            # Back on its line, back on the tile.
            fake.state.atx_event_none, fake.state.atx_none_next = False, 0
            wait_until(lambda: watched(client, device)["buttons"], "the board was never back")
    finally:
        fake.stop()


def test_a_press_is_answered_as_soon_as_the_line_for_events_says_the_change(tmp_path: Path, quick: dict[str, float], monkeypatch: pytest.MonkeyPatch) -> None:
    # Asked, the board was looked at again a second later at the soonest, and the press answered then. On its line the
    # change is said when the board sees it. (The asking every five seconds, and eight to wait at the most: an answer that
    # came at the next asking, or at the end of the wait, would come late enough to be told apart.)
    monkeypatch.setattr(kvm, "SEEN_EVERY", 5.0)
    monkeypatch.setattr(kvm, "SEEN_WITHIN", 8.0)
    fake = FakeKvm(FakeState(atx=True, holds=quick, computer_follows=True, computer_on=False, signal=False, atx_lag=0.5)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: board_of(client, device)["power"] is False, "the computer was never seen off")
            heard_on_its_line(client, fake, device)
            before = asked(fake)
            took, reply = press(client, device, "atx_power")
            assert (reply.status_code, reply.json()) == (200, {"ok": True, "note": None}), reply.text
            assert 0.5 <= took < 1.8, f"switching on was said done after {took:.2f} s; the board said it after 0.5 s"
            wait_until(lambda: board_of(client, device)["power"] is True, "the tile never showed the computer on")
            took, reply = press(client, device, "atx_power_long")
            assert (reply.status_code, reply.json()) == (200, {"ok": True, "note": None}), reply.text
            assert quick["power_long"] + 0.5 <= took < quick["power_long"] + 1.5, f"the power cut was said done after {took:.2f} s"
            # Asked once before each press (whether it is pressing one already: see below), and once after it was let go,
            # while the line had said nothing since the click (what it said before is from before the press): no more.
            assert asked(fake) - before <= 4, f"the board was asked {asked(fake) - before} times for two presses its line told of"
            assert fake.state.actions == ["atx power", "atx power_long"]
    finally:
        fake.stop()


def test_what_the_line_said_before_the_press_is_no_witness_of_what_it_did(tmp_path: Path, quick: dict[str, float]) -> None:
    # A Comet reads its board for the line about every second and a quarter: the computer had gone off a moment before the
    # press, and the line still said "on". Asked before the press, the board said "off", so the short press must bring
    # it on; the line's "on" from before the press was taken as that, and the press said done of a computer still off.
    fake = FakeKvm(FakeState(atx=True, holds=quick, line_every=30.0)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            heard_on_its_line(client, fake, device)
            fake.state.computer_on = fake.state.signal = False  # (asked, it says so; its line has not read it yet)
            wait_until(lambda: client.get("/api/v1/status").json()[device]["video"]["signal"] is False, "the picture never went")
            assert board_of(client, device)["power"] is True  # (the line's word, from before)
            took, reply = press(client, device, "atx_power")
            assert (reply.status_code, reply.json()) == (200, {"ok": True, "note": "pressed, but the computer is still off"}), reply.text
            assert took >= kvm.SEEN_WITHIN
    finally:
        fake.stop()


def test_a_no_board_on_the_line_while_a_press_is_waited_for_is_no_word_on_the_computer(tmp_path: Path, quick: dict[str, float]) -> None:
    # A Comet's line says "no board, off" while the board answers somebody else's question, the wall's own included: the
    # wall asks the board while it waits for a press's change (until the line has said something since the click), and
    # the line says "no board, off" after the click. The long press waits for the computer to go off: that "off" is no
    # such word, and the computer stays on here. (Said after the click and for the rest of the wait here, so that the
    # wall's next look is sure to meet it.)
    fake = FakeKvm(FakeState(atx=True, holds=quick)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            heard_on_its_line(client, fake, device)
            answers: list[Any] = []
            pressing = threading.Thread(target=lambda: answers.append(press(client, device, "atx_power_long")))
            pressing.start()
            wait_until(lambda: "atx power_long" in fake.state.actions, "the button was never pressed")
            fake.state.atx_event_none = True
            pressing.join(30)
            took, reply = answers[0]
            assert (reply.status_code, reply.json()) == (200, {"ok": True, "note": "held, but the computer is still on"}), reply.text
            assert took >= quick["power_long"] + kvm.SEEN_WITHIN
    finally:
        fake.stop()


def test_a_no_board_on_the_line_has_the_board_asked_and_the_tile_keeps_what_it_answers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The line says "no board" (somebody else asks the board all the while); asked, the board is there and the computer
    # on. The tile says so past the time a board's last word is kept, and the board was asked for it.
    monkeypatch.setattr(kvm, "POWER_KEPT", 1.0)
    fake = FakeKvm(FakeState(atx=True)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            heard_on_its_line(client, fake, device)
            fake.state.atx_event_none = True
            before = asked(fake)
            said = []
            until = time.monotonic() + 2.5
            while time.monotonic() < until:
                said.append(watched(client, device))
                time.sleep(0.05)
            assert {(each["enabled"], each["power"], each["buttons"]) for each in said} == {(True, True, True)}, said[-1]
            assert asked(fake) > before
    finally:
        fake.stop()


def test_a_line_that_says_busy_refuses_a_press_where_the_question_does_not(tmp_path: Path, quick: dict[str, float]) -> None:
    # Stock kvmd's line says busy for the whole of a hold; asked in another moment, a board may say otherwise. Busy where
    # either says so.
    fake = FakeKvm(FakeState(atx=True, holds=quick)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            heard_on_its_line(client, fake, device)
            fake.state.atx_event_busy = True
            time.sleep(1.0)  # (said on the line within a fiftieth of a second; a loaded PC is given longer)
            reply = press(client, device, "atx_power")[1]
            assert (reply.status_code, reply.json().get("code")) == (409, "busy"), reply.text
            assert fake.state.actions == []
    finally:
        fake.stop()


def test_a_press_asks_the_board_before_it_is_sent_beside_a_line_that_does_not_say_it_is_busy(tmp_path: Path, quick: dict[str, float]) -> None:
    # A Comet's board says busy for the first half second of a press, and its line says what it read about every second
    # and a quarter: on the real one the line never said busy. Pressed from the KVM's own page a moment before, the board
    # is pressing; the wall asks it before its own press is sent, beside the line, and refuses.
    fake = FakeKvm(FakeState(atx=True, holds={**quick, "power_long": 3.0}, busy_for=1.5)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            heard_on_its_line(client, fake, device)
            fake.state.tokens.add("its-own-page")
            with httpx.Client(base_url=fake.url, cookies={"auth_token": "its-own-page"}) as own_page:
                assert own_page.post("/api/atx/click", params={"button": "power_long"}).status_code == 200
            before = asked(fake)
            reply = press(client, device, "atx_power")[1]
            assert (reply.status_code, reply.json().get("code")) == (409, "busy"), f"a second press was sent to a board pressing one: {reply.text}"
            assert fake.state.actions == ["atx power_long"], "a second press went to a board that was pressing one"
            assert asked(fake) > before
    finally:
        fake.stop()


def test_a_board_that_says_the_same_again_on_its_line_has_the_tile_looked_at_no_more_often(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (A real Comet says the board's state only when it changed. One that says it again and again, changed or not, would
    # have had the tile looked at anew at every word: every question of a look, at that pace.)
    fake = FakeKvm(FakeState(atx=True, atx_resend=0.1)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            heard_on_its_line(client, fake, device)
            monkeypatch.setattr(kvm, "STATUS_TTL", 4.0)
            looks = sum(1 for question in list(fake.state.asked) if question == "GET /api/streamer")
            sent = fake.state.atx_events_sent
            until = time.monotonic() + 3.0
            while time.monotonic() < until:
                watched(client, device)
                time.sleep(0.1)
            assert fake.state.atx_events_sent >= sent + 20, "the stand-in did not say it again: the test proves nothing"
            more = sum(1 for question in list(fake.state.asked) if question == "GET /api/streamer") - looks
            assert more <= 2, f"the tile was looked at {more} times in three seconds while the board said the same again"
    finally:
        fake.stop()


def test_a_kvm_that_ends_the_line_at_a_ping_is_not_given_one_again_at_every_picture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A KVM (or a door before it) that does not know kvmd's `ping` and ends the line at one: the line had lasted as long as
    # the first ping took to come, which counted as a line that held, and a new one was opened at the next picture.
    monkeypatch.setattr(kvm, "EVENTS_PING", 0.3)
    monkeypatch.setattr(kvm, "KEEPALIVE_LASTS", 0.3)
    fake = FakeKvm(FakeState(atx=True, close_on_ping=True)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            until = time.monotonic() + 4.0
            while time.monotonic() < until:
                client.get(f"/api/v1/devices/{device}/snapshot", params={"w": 480})
                time.sleep(0.05)
            lines = fake.state.ws_streams.count("1")
            assert 1 <= lines <= 5, f"{lines} lines in four seconds to a KVM that ends each at its first ping"
    finally:
        fake.stop()


def test_a_kvm_whose_events_do_not_carry_its_board_is_asked_as_before(tmp_path: Path) -> None:
    fake = FakeKvm(FakeState(atx=True, atx_events=False)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            wait_until(lambda: board_of(client, device)["power"] is True, "a running computer was never said to be on")
            before = asked(fake)
            fake.state.computer_on = False
            wait_until(lambda: board_of(client, device)["power"] is False, "a computer switched off was never said to be off")
            assert asked(fake) > before
    finally:
        fake.stop()


def test_what_a_line_that_went_quiet_said_of_the_board_no_longer_counts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A line whose KVM has stopped saying anything, its own `pong` included (gone from the network, say), would go on
    # standing for what the board said last: it counts for EVENTS_QUIET, and then the board is asked.
    monkeypatch.setattr(kvm, "EVENTS_PING", 0.2)
    monkeypatch.setattr(kvm, "EVENTS_QUIET", 1.0)
    fake = FakeKvm(FakeState(atx=True)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            heard_on_its_line(client, fake, device)
            assert fake.state.pings >= 1, "the line was never asked whether it is there"
            before = asked(fake)
            fake.state.pongs = False  # (nothing more on the line, no answer to its pings)
            fake.state.computer_on = False
            wait_until(lambda: watched(client, device)["power"] is False, "the board was not asked once its line had gone quiet")
            assert asked(fake) > before
    finally:
        fake.stop()


def test_once_nobody_watches_the_picture_the_board_is_asked_again(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The line is the picture's: let go of once nobody has asked for a picture for a while (KEEPALIVE_IDLE), and with it
    # what the board said there. From then on the board is asked, as before; and the tile taken off the wall lets go of it.
    monkeypatch.setattr(kvm, "KEEPALIVE_IDLE", 1.0)
    monkeypatch.setattr(kvm, "EVENTS_PING", 0.2)
    fake = FakeKvm(FakeState(atx=True)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            heard_on_its_line(client, fake, device)
            wait_until(lambda: bool(board_of(client, device)) and fake.state.streams == 0, "the line was held while nobody watched the picture")
            before = asked(fake)
            fake.state.computer_on = False
            # Closing the event line and refreshing the status happen in separate
            # tasks. A final event can report the power change before the first
            # fallback poll completes; require both observations within the bound.
            wait_until(
                lambda: board_of(client, device)["power"] is False and asked(fake) > before,
                "the board was not asked once nobody watched",
            )
            heard_on_its_line(client, fake, device)
            assert client.delete(f"/api/v1/devices/{device}").status_code == 200
            wait_until(lambda: fake.state.viewers == 0, "the line outlived its tile")
    finally:
        fake.stop()


def test_a_line_for_events_that_sends_far_more_than_a_kvm_would_is_hung_up_on(tmp_path: Path) -> None:
    # What a device sends there is read within the same bounds as on every other line of it (Listening, MOST_EVENT): a
    # message far longer than any of a KVM's (a Comet's longest is a few kilobytes) ends the line; the board is asked.
    fake = FakeKvm(FakeState(atx=True)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            heard_on_its_line(client, fake, device)
            lines, before = fake.state.ws_streams.count("1"), asked(fake)
            fake.state.atx_events = False  # (and what comes on the next line says nothing of the board)
            fake.state.computer_on = False
            fake.state.event_junk = "x" * (kvm.MOST_EVENT + 10)
            wait_until(lambda: watched(client, device)["power"] is False, "the board was not asked once its line was hung up on")
            assert asked(fake) > before
            wait_until(lambda: bool(watched(client, device)) and fake.state.ws_streams.count("1") > lines, "no line was held anew after the one that was hung up on")
    finally:
        fake.stop()


def test_the_events_a_kvm_sent_are_json_the_stand_in_answers_as_a_comet(tmp_path: Path) -> None:
    # (The stand-in, against what a real Comet sent: the board's state at once on a new line, then whether a Fingerbot is
    # paired with it, and a `pong` to a `ping`.)
    import asyncio

    from websockets.asyncio.client import connect

    fake = FakeKvm(FakeState(atx=True)).start()
    fake.state.tokens.add("token")

    async def talk() -> list[Any]:
        async with connect(f"ws://127.0.0.1:{fake.port}/api/ws?stream=0", additional_headers={"Cookie": "auth_token=token"}) as ws:
            first, fingerbot = json.loads(await ws.recv()), json.loads(await ws.recv())
            await ws.send('{"event_type": "ping", "event": {}}')
            second = json.loads(await ws.recv())
            return [first, fingerbot, second]

    try:
        first, fingerbot, second = asyncio.run(talk())
        assert first == {"event_type": "atx", "event": {"enabled": True, "busy": False, "leds": {"power": False, "hdd": False}, "power": "on"}}
        assert fingerbot == {"event_type": "fingerbot", "event": {"exist": False}}
        assert second == {"event_type": "pong", "event": {}}
    finally:
        fake.stop()
