"""A JetKVM whose computer's screen goes and comes back, as a real one showed it through the wall (release check R2).

A real JetKVM says at once that its input is back (`videoInputState`, ready) when its computer wakes or its screen does,
and sends its first picture of it a moment later (within a second or so, now and then some seconds). Through the wall:

* With a picture from before the screen went to sleep, the wall took that moment for a JetKVM that had stopped sending
  video: the last picture was minutes old, and the signal was back. It ended the connection, called the JetKVM offline
  for some seconds (written in its history as a time it was down) and connected again; once in four wakes on the real
  one, as the first picture came before or after the wall's look a second later.
* A connection made while the computer was asleep got no picture at all once the computer had been woken by a press of
  its power button: "Waiting for the first picture" through two spells of a screen that was on, close to a minute each,
  until the tile was saved again and the new connection had the picture at once. Seen once; later wakes from sleep had
  their picture on the connection they had.

Now: once the JetKVM has said its screen is back, the picture from before is not the screen (a tile waits, a live view
that opens or asks for a picture is given none), and the first one of the screen is waited for, for PICTURE_AFTER_SIGNAL,
in place of FRAME_STALE; where none comes by then, the JetKVM is taken for one that stopped sending video, as by
FRAME_STALE, and the wall connects again. An answer about the screen that was asked before the JetKVM said, in an event,
that it went or came, changes nothing of that. A JetKVM that stops sending pictures of a screen it has been showing is
still taken for one that stopped, after FRAME_STALE, as before.
"""

from __future__ import annotations

import asyncio
import threading
import time
from pathlib import Path

import pytest

from qkvm import jetkvm
from qkvm.kvm import DeviceSpec
from tests.fake_jetkvm import FakeJetKvm, JetState
from tests.test_jetkvm import fast, picture  # noqa: F401  (the fixture)
from tests.test_live import Picture, Wall
from tests.test_wall import add, snap, wait_until, wall

pytestmark = pytest.mark.filterwarnings(r"ignore:connect\(\) must be used as a context manager:DeprecationWarning")


def states_for(client: object, device: str, seconds: float) -> list[str]:
    """The state the wall says of the machine, looked at ten times a second for that long."""
    seen: list[str] = []
    began = time.monotonic()
    while time.monotonic() - began < seconds:
        seen.append(client.get("/api/v1/status").json()[device]["state"])  # type: ignore[attr-defined]
        time.sleep(0.1)
    return seen


def said(client: object, device: str, state: str) -> bool:
    return bool(client.get("/api/v1/status").json()[device]["state"] == state)  # type: ignore[attr-defined]


def history_states(client: object, device: str) -> list[str]:
    rows = client.get(f"/api/v1/devices/{device}/history", params={"what": "states"}).json()["rows"]  # type: ignore[attr-defined]
    return [row["state"] for row in rows]


def screen_shown(client: object, device: str) -> bool:
    reply = client.get(snap(device))  # type: ignore[attr-defined]
    return bool(reply.status_code == 200 and reply.headers["x-kvm-signal"] == "1" and reply.content[:3] == b"\xff\xd8\xff")


def test_a_screen_that_comes_back_is_given_its_first_picture_and_the_jetkvm_is_not_called_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jetkvm, "FRAME_STALE", 2.0)
    jet = FakeJetKvm(JetState(frames_after_signal=3.0)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, jet.url)
            picture(client, device)
            connections = jet.state.sessions
            jet.say_signal(False)  # the computer's screen goes to sleep
            wait_until(lambda: said(client, device, "no_signal"), "the screen asleep was not said")
            time.sleep(2.5)  # (the last picture is older than FRAME_STALE now)
            jet.say_signal(True)  # ...and wakes: said at once, its first picture 3 s later
            seen = states_for(client, device, 5.0)
            assert jet.state.sessions == connections, seen  # the connection it had: nothing was ended
            assert "offline" not in seen, seen
            wait_until(lambda: screen_shown(client, device), "the picture of the screen did not come", timeout=10)
            assert "offline" not in history_states(client, device)  # no time written down as down
    finally:
        jet.stop()


def test_a_picture_from_before_the_screen_came_back_is_not_passed_off_as_the_screen(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jetkvm, "FRAME_STALE", 30.0)  # (the picture from before is young: only being from before tells it)
    jet = FakeJetKvm(JetState(frames_after_signal=12.0)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, jet.url)
            picture(client, device)
            jet.say_signal(False)  # a moment without signal (a screen that changes its mode, a short sleep)...
            wait_until(lambda: said(client, device, "no_signal"), "the screen asleep was not said")
            jet.say_signal(True)  # ...and back, the last picture well within FRAME_STALE: it is from before all the same
            wait_until(lambda: said(client, device, "online"), "the screen back was not said")
            reply = client.get(snap(device), params={"age": 0})
            assert reply.status_code == 503 and reply.json()["message"] == "Waiting for the JetKVM's video", reply.headers
            wait_until(lambda: screen_shown(client, device), "the picture of the screen did not come", timeout=20)
    finally:
        jet.stop()


def test_a_connection_that_gets_no_picture_once_the_screen_is_back_is_taken_for_one_that_stopped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jetkvm, "PICTURE_AFTER_SIGNAL", 2.0)
    # The computer is asleep as the wall connects, and the connection it gets sends no picture once it wakes.
    jet = FakeJetKvm(JetState(signal=False, silent_screens=1)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, jet.url)
            asleep = picture(client, device)
            assert asleep.headers["x-kvm-signal"] == "0"  # type: ignore[attr-defined]
            connections = jet.state.sessions
            jet.say_signal(True)
            wait_until(lambda: screen_shown(client, device), "no picture came once the screen was back", timeout=20)
            assert jet.state.sessions == connections + 1  # connected again, once
    finally:
        jet.stop()


def test_a_jetkvm_that_stops_sending_pictures_of_a_screen_it_shows_is_still_taken_for_one_that_stopped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jetkvm, "FRAME_STALE", 1.0)
    jet = FakeJetKvm(JetState(frames_after_signal=0.5)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, jet.url)
            picture(client, device)
            jet.say_signal(False)
            wait_until(lambda: said(client, device, "no_signal"), "the screen asleep was not said")
            # (Asleep longer than FRAME_STALE: a picture younger than that is still handed out while there is no signal,
            # and would pass for the screen that came back in the wait below.)
            time.sleep(1.5)
            jet.say_signal(True)
            # (A JPEG with a signal is a picture of the screen that came back: the one from before is not handed out.)
            wait_until(lambda: screen_shown(client, device), "the picture did not come back")
            connections = jet.state.sessions
            jet.state.frames_from = float("inf")  # then its video stops, while it goes on answering what it is asked
            began = time.monotonic()

            def ended() -> bool:
                # (Its connection is ended by the stall rule, FRAME_STALE: nothing else ends it here, with every question
                # answered. The next one is made when its picture is asked for, as a tile asks for it here.)
                client.get(snap(device))
                return jet.state.sessions > connections

            wait_until(ended, "its last picture went on being taken for the screen", timeout=15)
            assert time.monotonic() - began < 10
    finally:
        jet.stop()


def test_the_live_line_hands_out_no_picture_from_before_the_screen_came_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jetkvm, "FRAME_STALE", 30.0)  # (the picture from before is young: only being from before tells it)
    jet = FakeJetKvm(JetState(frames_after_signal=12.0)).start()
    try:
        with Wall(tmp_path) as live:
            admin = live.browser()
            device = live.add(admin, jet.url)
            first = live.line(admin, device, max_fps=5)
            before = first.picture(timeout=20)
            jet.say_signal(False)
            first.until(lambda: admin.get("/api/v1/status").json()[device]["state"] == "no_signal", "the screen asleep was not said")
            jet.say_signal(True)
            first.until(lambda: admin.get("/api/v1/status").json()[device]["state"] == "online", "the screen back was not said")
            second = live.line(admin, device, max_fps=5)  # somebody opens the live view in the moment before the first picture
            came: list[Picture] = []
            end = time.monotonic() + 3.0
            while time.monotonic() < end:
                try:
                    message = second.next(max(0.01, end - time.monotonic()))
                except TimeoutError:
                    break
                if isinstance(message, Picture):
                    came.append(message)
            assert came == [], [picture.counter for picture in came]  # nothing from before the screen came back
            second.say(t="key_frame")  # ...nor when it asks for a picture again
            came_again: list[Picture] = []
            end = time.monotonic() + 1.0
            while time.monotonic() < end:
                try:
                    message = second.next(max(0.01, end - time.monotonic()))
                except TimeoutError:
                    break
                if isinstance(message, Picture):
                    came_again.append(message)
            assert came_again == [], [picture.counter for picture in came_again]
            after = second.picture(timeout=20)
            assert after.counter > before.counter
    finally:
        jet.stop()


def test_an_answer_about_the_screen_asked_before_it_went_to_sleep_does_not_wake_it(tmp_path: Path) -> None:
    jet = FakeJetKvm().start()
    try:
        with wall(tmp_path) as client:
            device = add(client, jet.url)
            picture(client, device)  # (a picture, no status yet: the first status asked waits for its own read)
            jet.state.video_answer_late = 1.5  # a busy JetKVM: its answer to that read's question comes late...
            threading.Timer(0.5, jet.say_signal, [False]).start()  # ...after it said, in an event, that the screen went
            look = client.get("/api/v1/status").json()[device]
            jet.state.video_answer_late = 0.0
            assert look["state"] == "no_signal", look  # the event is newer than the answer
    finally:
        jet.stop()


def test_a_frame_read_across_a_signal_change_is_not_marked_as_a_new_picture() -> None:
    from aiortc.mediastreams import MediaStreamError

    async def run() -> None:
        device = jetkvm.JetKvmDevice(DeviceSpec("jet", "A JetKVM", "http://127.0.0.1:18901", "", "", kind="jetkvm"))
        session = jetkvm._Session()
        previous, delayed, fresh = object(), object(), object()
        session.frame = previous
        session.frame_at = 1.0
        session.ready_said = True

        class Track:
            calls = 0

            async def recv(self) -> object:
                self.calls += 1
                if self.calls == 1:
                    # A decode already in flight when the screen goes and returns
                    # cannot establish that its result belongs to the new signal.
                    jetkvm._video_said(session, {"ready": False})
                    jetkvm._video_said(session, {"ready": True})
                    await asyncio.sleep(0)
                    return delayed
                if self.calls == 2:
                    assert session.frame is previous
                    assert session.frame_at == 1.0
                    return fresh
                assert session.frame is fresh
                assert session.frame_at >= session.signal_at
                raise MediaStreamError

        track = Track()
        await device._watch(session, track)
        assert track.calls == 3

    asyncio.run(run())
