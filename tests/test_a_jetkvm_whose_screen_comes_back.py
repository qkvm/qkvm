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

# How long a screen here is dark at the least: longer than a tick of the wall's clock. On Windows before Python 3.13 that
# tick is 15.6 ms, and a moment without signal shorter than it gave the last picture from before and the screen's return
# the same time, which no real screen does: the picture from before was then taken for the screen (GitHub's Windows
# runner, 3.11 and 3.12; on a VM, 2 rounds in 30, each one such a tie).
DARK_AT_LEAST = 0.05


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
    # The stand-in sends its first picture of the screen 60 s after the signal is back, unless the test asks for it sooner
    # (below), and the wall waits 120 s for it. On a slow runner the wall said "online" after the 12 s the stand-in was given
    # at first, and the picture was asked for after the 20 s it was given next, the same 20 s as the wall's own wait
    # (PICTURE_AFTER_SIGNAL): the new picture had come, or the wall had rightly connected again for one, and either was rightly
    # served. With the wall's wait well above the stand-in's, the wall never connects again here; and a runner has a minute.
    # Twice more on that runner (Windows, 3.11, 2026-11-16) a picture was served 0.1 s after the screen came back: the wall's
    # look at its pictures came late, and the stand-in's encoder still had a picture from before the screen went, whose first
    # packet let the one before it go (the WebRTC library lets a picture go only then), stamped as it was let go of. Now a
    # picture is stamped with when its first packet came (the busy wall's test above), and the stand-in says the screen went
    # once the picture it was sending has gone out, as a real one does (fake_jetkvm.tell_video_in_turn).
    stand_in, patience = 60.0, 120.0
    monkeypatch.setattr(jetkvm, "PICTURE_AFTER_SIGNAL", patience)
    jet = FakeJetKvm(JetState(frames_after_signal=stand_in)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, jet.url)
            picture(client, device)
            jet.say_signal(False)  # a moment without signal (a screen that changes its mode, a short sleep)...
            wait_until(lambda: said(client, device, "no_signal"), "the screen asleep was not said")
            time.sleep(DARK_AT_LEAST)
            back = time.monotonic()
            jet.say_signal(True)  # ...and back, the last picture well within FRAME_STALE: it is from before all the same
            wait_until(lambda: said(client, device, "online"), "the screen back was not said")
            online = time.monotonic() - back
            reply = client.get(snap(device), params={"age": 0})
            asked = time.monotonic() - back
            timings = (
                f"'online' was said {online:.1f} s after the screen came back and the picture asked for at {asked:.1f} s; "
                f"the stand-in's first picture of it comes at {stand_in:g} s, and the wall waits {patience:g} s for one"
            )
            assert reply.status_code == 503 and reply.json()["message"] == "Waiting for the JetKVM's video", f"{timings}: {reply.headers}"
            jet.state.frames_from = time.monotonic()  # (the first picture of the screen, now)
            wait_until(lambda: screen_shown(client, device), "the picture of the screen did not come", timeout=20)
    finally:
        jet.stop()


class LateLooks:
    """The track the wall's connection takes its pictures from, looked at late, as by a busy wall (set from the test's thread).

    "through": as it is. "keep": the pictures that come are taken from it and kept, and the newest handed over once that
    ends (to the look that asked for one while they were kept: `handed` says it has been). "one": one picture more, then
    "after one": none until that ends (`judged`: the look that asked for that one is over, and asks for the next)."""

    def __init__(self) -> None:
        self.mode = "through"
        self.kept, self.handed, self.judged = threading.Event(), threading.Event(), threading.Event()

    def track(self, track: object) -> object:
        late = self

        class Late:
            kind = "video"

            async def recv(self) -> object:
                kept = None
                while late.mode == "keep":
                    try:
                        kept = await asyncio.wait_for(track.recv(), 0.05)  # type: ignore[attr-defined]
                        late.kept.set()
                    except TimeoutError:
                        pass
                if kept is not None:
                    late.handed.set()
                    return kept
                if late.mode == "one":
                    late.mode = "after one"
                elif late.mode == "after one":
                    late.judged.set()
                    while late.mode == "after one":
                        await asyncio.sleep(0.01)
                return await track.recv()  # type: ignore[attr-defined]

        return Late()


def test_the_last_picture_before_the_screen_went_is_not_taken_for_it_when_the_screen_comes_back_to_a_busy_wall(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The WebRTC library lets a picture go only once the first packet of the next has come: the last one before a JetKVM's
    # screen went dark is let go of when the first one of the screen that came back arrives. A wall that looks at its
    # pictures as they come takes it with the look it began before the screen came back, and lets it go (see _watch). A
    # busy wall, whose look comes late, began the look after: stamped as it was let go of, the picture from before was
    # taken for the screen until the next was let go of (how the stand-in's test below failed on GitHub's slow runner).
    late = LateLooks()
    on_track = jetkvm.JetKvmDevice._on_track
    monkeypatch.setattr(jetkvm.JetKvmDevice, "_on_track", lambda self, session, track: on_track(self, session, late.track(track)))
    monkeypatch.setattr(jetkvm, "FRAME_STALE", 30.0)  # (the picture from before is young: only being from before tells it)
    monkeypatch.setattr(jetkvm, "PICTURE_AFTER_SIGNAL", 120.0)
    jet = FakeJetKvm(JetState(frames_after_signal=600.0)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, jet.url)
            picture(client, device)
            late.mode = "keep"  # the wall is busy: what comes waits for its look...
            assert late.kept.wait(20), "no picture came while the wall was busy"
            jet.say_signal(False)  # ...as the screen goes dark
            wait_until(lambda: said(client, device, "no_signal"), "the screen asleep was not said")
            time.sleep(DARK_AT_LEAST)
            jet.say_signal(True)  # ...and comes back, its first picture not yet sent
            wait_until(lambda: said(client, device, "online"), "the screen back was not said")
            late.mode = "one"  # the wall's look at last: the newest of what waited (from before, and let go of as such)...
            assert late.handed.wait(20), "what waited was not looked at"
            jet.state.frames_from = time.monotonic()  # ...then the screen's first picture, whose first packet lets the last
            assert late.judged.wait(20), "the last picture from before was not let go of"  # one from before go, looked at now
            reply = client.get(snap(device), params={"age": 0})
            assert reply.status_code == 503 and reply.json()["message"] == "Waiting for the JetKVM's video", reply.headers
            late.mode = "through"
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
            time.sleep(DARK_AT_LEAST)
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
                    # (The first picture of the screen comes a tick of the clock after its return at the least: one stamped in
                    # the same tick counts as from before, see the tests of that below. On Windows before Python 3.13 a
                    # tick is 15.6 ms.)
                    await asyncio.sleep(DARK_AT_LEAST)
                    return fresh
                assert session.frame is fresh
                assert session.frame_at > session.signal_at
                raise MediaStreamError

        track = Track()
        await device._watch(session, track)
        assert track.calls == 3

    asyncio.run(run())


def test_frames_queued_before_the_signal_returns_are_not_new_pictures() -> None:
    from types import SimpleNamespace
    from aiortc.mediastreams import MediaStreamError

    async def run() -> None:
        device = jetkvm.JetKvmDevice(DeviceSpec("jet", "A JetKVM", "http://127.0.0.1:18901", "", "", kind="jetkvm"))
        session = jetkvm._Session()
        previous = object()
        delayed = SimpleNamespace(received_at=10.0)
        fresh = SimpleNamespace(received_at=12.0)
        session.frame, session.frame_at = previous, 9.0
        session.ready_said, session.signal_at = True, 11.0

        class Track:
            calls = 0

            async def recv(self) -> object:
                self.calls += 1
                if self.calls <= 2:
                    assert session.frame is previous and session.frame_at == 9.0
                    return delayed  # even several old decodes must be discarded
                if self.calls == 3:
                    assert session.frame is previous
                    return fresh
                assert session.frame is fresh and session.frame_at == 12.0
                raise MediaStreamError

        track = Track()
        await device._watch(session, track)
        assert track.calls == 4

    asyncio.run(run())


def test_a_frame_let_go_of_when_the_next_one_comes_is_stamped_with_when_its_own_packets_came() -> None:
    # The WebRTC library lets a picture go to the decoder only once the first packet of the next one has come. Stamped as it
    # was let go of, the last picture before a screen went dark bore the moment the first picture of the screen that came
    # back arrived, and was taken for that screen until the next one was let go of: a real JetKVM sends nothing while its
    # screen is dark, so at every return of its screen (seen with the stand-in, 0.4.0: the last picture from before was let
    # go of 2.03 s after the screen came back, when its first picture came).
    from aiortc import rtcrtpreceiver
    from aiortc.rtp import RtpPacket

    from qkvm.video import BoundedDecoderQueue, install_aiortc_boundary

    install_aiortc_boundary()  # (as the wall does before it connects to a JetKVM: the receiver's jitter buffer is the wall's)
    buffer = rtcrtpreceiver.JitterBuffer(capacity=128, is_video=True)
    decoding = BoundedDecoderQueue()

    def packet(sequence: int, timestamp: int) -> RtpPacket:
        made = RtpPacket(payload_type=96, sequence_number=sequence, timestamp=timestamp)
        made._data = b"\x00\x00\x00\x01\x41\x9a"  # type: ignore[attr-defined]  (as the receiver leaves it: a piece of a picture)
        return made

    for sequence in (1, 2):
        assert buffer.add(packet(sequence, 9000))[1] is None  # the last picture before the screen went, in two packets: held
    whole = time.monotonic()
    time.sleep(0.05)  # (the screen is dark: longer than a tick of the clock, so that a stamp made at the end is later)
    _, last = buffer.add(packet(3, 18000))  # the first packet of the screen that came back lets it go
    assert last is not None and last.timestamp == 9000
    decoding.put(("video/H264", last))
    _, _, stamped = decoding.get_nowait()
    assert stamped <= whole, (stamped - whole)


# --- the fourth review's lows and notes of R2 (register row 17) ------------------------------------------------------


def test_a_connection_opened_with_a_signal_that_never_sends_a_first_picture_is_taken_for_one_that_stopped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # (a) A connection opened while the computer's screen was on (or as it woke, before any "no") that never got a picture
    # waited until nobody had watched for five minutes: the tile said "Waiting for the first picture" all that while. Its first
    # picture is waited for PICTURE_AFTER_SIGNAL from the connection's opening, and where none comes the wall connects again.
    monkeypatch.setattr(jetkvm, "PICTURE_AFTER_SIGNAL", 2.0)
    jet = FakeJetKvm(JetState(silent_screens=1)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, jet.url)
            wait_until(lambda: screen_shown(client, device), "no picture came on a new connection", timeout=20)
            assert jet.state.sessions == 2  # (the first, silent, given up on; the second shows the screen)
    finally:
        jet.stop()


def test_the_status_does_not_say_online_over_a_blank_tile_where_the_jetkvm_said_no_signal_last(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # (b) The status read the newest of what the JetKVM said of its input, and where that did not say whether there is a
    # signal, fell back to "has a picture": a JetKVM that said no and then never a yes or no again was online over a blank
    # tile, where the tile and the stall rule read the last yes or no it said.
    jet = FakeJetKvm(JetState()).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, jet.url)
            picture(client, device)
            jet.say_signal(False)  # (the computer's screen goes to sleep: said in an event)
            wait_until(lambda: said(client, device, "no_signal"), "the screen going was not said", timeout=10)
            jet.state.video_state_says_ready = False  # (from now on its answers say no more whether there is a signal)
            seen = states_for(client, device, 2.0)
            assert "online" not in seen, seen
    finally:
        jet.stop()


def test_the_live_line_does_not_hand_out_the_picture_from_before_after_the_first_new_frame() -> None:
    # (c) A live line hid the picture from before only while the first new one was awaited: in the moment after that first
    # frame came and before the line's loop had made a JPEG of it (one turn of the loop), a viewer that came was handed the
    # old picture. It is hidden wherever the JetKVM said its screen was back after the frame it was made of.
    from qkvm import live

    device = jetkvm.JetKvmDevice(DeviceSpec("j", "jet", "http://127.0.0.1:18901", "", "", kind="jetkvm"))
    session = jetkvm._Session()
    device._session = session
    source = live.JetSource(live.Machine(None, "j", device))  # type: ignore[arg-type]
    session.frame, session.frame_at = object(), 10.0
    source.offer(1, True, b"the picture of a frame from 10.0")
    source.made_of_at = 10.0  # (the time of the frame it was made of, as the line's loop keeps it)
    assert source.last is not None
    session.ready_said, session.signal_at = True, 11.0  # the JetKVM says its screen is back...
    assert source.last is None
    session.frame_at = 12.0  # ...and its first new frame comes, not yet made into a picture by the loop
    assert source.last is None, "the picture from before was handed out after the first new frame"


# --- a picture stamped in the same tick of the clock as the screen's return (0.4.0's hold round) ---------------------
#
# Each comparison of a picture's stamp with the moment the JetKVM said its screen was back counted a tie as new: on a clock
# of coarse ticks (Windows before Python 3.13: 15.6 ms), the last picture before a screen that was dark for less than a tick
# bore the moment it came back, and passed for that screen. A tie counts as from before (it errs early, as
# video._stamping promises). Each test reads the wall's clock as one that gives the same stamp twice.


class OneTick:
    """The wall's clock (jetkvm's `time`) as it reads within one tick: every reading the same stamp, until it is moved on."""

    def __init__(self, at: float) -> None:
        self.at = at

    def monotonic(self) -> float:
        return self.at

    def __getattr__(self, name: str) -> object:
        return getattr(time, name)


def dark_for_less_than_a_tick(session: jetkvm._Session) -> None:
    """The JetKVM says its screen went, and that it is back, within one tick of the wall's clock."""
    jetkvm._video_said(session, {"ready": False})
    jetkvm._video_said(session, {"ready": True})


def test_a_picture_stamped_in_the_tick_the_screen_came_back_is_not_taken_for_the_screen(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    from aiortc.mediastreams import MediaStreamError

    monkeypatch.setattr(jetkvm, "time", OneTick(100.0))

    async def run() -> int:
        device = jetkvm.JetKvmDevice(DeviceSpec("jet", "A JetKVM", "http://127.0.0.1:18901", "", "", kind="jetkvm"))
        session = jetkvm._Session()
        previous = SimpleNamespace(received_at=99.0)
        session.frame, session.frame_at, session.ready_said = previous, 99.0, True
        dark_for_less_than_a_tick(session)
        assert session.signal_at == 100.0
        last = SimpleNamespace(received_at=100.0)  # the last picture from before: its first packet came in that same tick
        fresh = SimpleNamespace(received_at=100.0156)  # the first picture of the screen, a tick later

        class Track:
            calls = 0

            async def recv(self) -> object:
                self.calls += 1
                if self.calls == 1:
                    return last
                if self.calls == 2:
                    assert session.frame is previous, "a picture stamped as the screen came back was taken for the screen"
                    return fresh
                assert session.frame is fresh and session.frame_at == 100.0156
                raise MediaStreamError

        track = Track()
        await device._watch(session, track)
        return track.calls

    assert asyncio.run(run()) == 3


def test_a_tile_and_the_live_line_are_not_handed_a_picture_stamped_in_the_tick_the_screen_came_back(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    from qkvm import live
    from qkvm.kvm import KvmError

    monkeypatch.setattr(jetkvm, "time", OneTick(100.0))
    monkeypatch.setattr(jetkvm, "encode_jpeg", lambda frame, target, quantizer: b"\xff\xd8 a picture \xff\xd9")

    async def run() -> None:
        device = jetkvm.JetKvmDevice(DeviceSpec("jet", "A JetKVM", "http://127.0.0.1:18901", "", "", kind="jetkvm"))
        session = device._session = jetkvm._Session()
        session.ready.set()  # (a connection that is up)
        session.frame, session.frame_at, session.ready_said = SimpleNamespace(width=1280, height=720), 100.0, True
        source = live.JetSource(live.Machine(None, "jet", device))  # type: ignore[arg-type]
        source.offer(1, True, b"the picture of the frame stamped 100.0")
        source.made_of_at = 100.0
        dark_for_less_than_a_tick(session)  # (said in the tick that picture's first packet came)
        with pytest.raises(KvmError) as refused:
            await device.snapshot(640)
        assert refused.value.code == "no_stream" and "Waiting for the JetKVM's video" in refused.value.message, refused.value
        assert device.picture_awaited() and device.screen_back_since(100.0)
        assert await device.live_frame() == (None, 0.0)
        assert source.last is None, "the live line handed out a picture stamped in the tick the screen came back"

    asyncio.run(run())


def test_a_connection_waits_for_the_first_picture_of_a_screen_that_came_back_in_the_tick_of_its_last(monkeypatch: pytest.MonkeyPatch) -> None:
    # Taken for a picture of the screen, the last one from before was FRAME_STALE old some seconds later, and the connection
    # was ended as one whose JetKVM stopped sending video (its tile said "offline", and the wall connected again), where the
    # first picture of a screen that comes back is given PICTURE_AFTER_SIGNAL.
    clock = OneTick(100.0)
    monkeypatch.setattr(jetkvm, "time", clock)
    session = jetkvm._Session()
    session.ready.set()
    session.frame, session.frame_at, session.ready_said = object(), 100.0, True
    dark_for_less_than_a_tick(session)
    clock.at = 100.0 + jetkvm.FRAME_STALE + 1.0
    assert not jetkvm._picture_overdue(session), "the picture from before was taken for the screen, and found too old"
    clock.at = 100.0 + jetkvm.PICTURE_AFTER_SIGNAL + 1.0
    assert jetkvm._picture_overdue(session)  # (and where no picture of the screen comes, it is overdue as ever)
