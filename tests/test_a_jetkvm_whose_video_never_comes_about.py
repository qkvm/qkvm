"""A JetKVM whose HTTP answers and whose video connection never comes about (UDP blocked between the two, ICE failing).

Every offer of a video connection takes the JetKVM's one viewer from whoever has it, its own page included, and the wall
never hears that somebody else had it over a connection that never opened. A tile that was shown offered one again at every
round of its back-off, about every half minute for as long as it was on screen (the desktop's item 9, confirmed by the
review's probe). As the desktop decided (2026-10-31): after an offer that came to nothing, a tile offered no other; what a
person asks for does (the enlarged view, the live view, a key or a button, "Show here"), and once a connection has come about
the tile goes on as ever. A tile that a busy computer had seen come to nothing once (the soak farm, under overload) then
stayed red until somebody opened it: for 0.4.0 (the owner) a tile on screen offers again by itself after a pause that
doubles with each offer that comes to nothing in a row (jetkvm.OFFER_AGAIN_FIRST up to OFFER_AGAIN_MOST), and says so.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from qkvm import jetkvm, kvm, update, vault, video
from qkvm.kvm import DeviceSpec, KvmError
from tests.fake_jetkvm import FakeJetKvm, JetState
from tests.test_wall import add, snap, wait_until, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(jetkvm, "CONNECT_TIMEOUT", 1.0)  # (fifteen seconds for an answer to the offer: here, one; see `comes_about`)
    # (The pause before a tile offers again by itself, five seconds at first: here a minute, beyond what every test looks for
    # but the ones below that wait it out, each with a pause of its own.)
    monkeypatch.setattr(jetkvm, "OFFER_AGAIN_FIRST", 60.0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0.05)
    monkeypatch.setattr(kvm, "BACKOFF_MAX", 0.2)  # (the back-off's cap is fifteen seconds: here, a fifth of one)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def comes_about(state: JetState, monkeypatch: pytest.MonkeyPatch) -> None:
    """From now on the JetKVM's video connection comes about, given the time a connection takes (the wall's own fifteen
    seconds: one is too little for a busy computer to make one in)."""
    state.answers_offers = True
    monkeypatch.setattr(jetkvm, "CONNECT_TIMEOUT", 15.0)


async def shown(device: jetkvm.JetKvmDevice, seconds: float) -> None:
    """A tile on screen: its status and its picture asked for, as the page asks (here, twenty times a second)."""
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        await device.status()
        try:
            await device.snapshot(640)
        except KvmError:
            pass
        await asyncio.sleep(0.05)


# What the tile says once the first offer came to nothing (its own words, kept in what it says from then on).
NO_ANSWER = "did not answer the request for video"


async def first_came_to_nothing(device: jetkvm.JetKvmDevice, seconds: float = 30.0) -> None:
    """A tile on screen until its JetKVM's first video connection came to nothing (its look says why). Starting one takes its
    time: the decoder's process is made first, seconds on a busy computer."""
    until = time.monotonic() + seconds
    while NO_ANSWER not in str(((await device._read_status()).get("error") or {}).get("message")):
        assert time.monotonic() < until, "the first video connection never came to nothing"
        await shown(device, 0.2)


async def enlarged(device: jetkvm.JetKvmDevice, seconds: float) -> bool:
    """The machine's enlarged view: its picture asked for as the large view asks; whether one came."""
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        try:
            await device.snapshot(1280, big=True)
            return True
        except KvmError:
            await asyncio.sleep(0.05)
    return False


def test_a_tile_offers_no_second_video_connection_after_one_that_came_to_nothing_before_its_pause(monkeypatch: pytest.MonkeyPatch, a_video_worker_first: None) -> None:
    state = JetState(answers_offers=False)
    jet = FakeJetKvm(state).start()

    async def run() -> None:
        device = jetkvm.JetKvmDevice(DeviceSpec("j9", "jet", jet.url, "", "secret", kind="jetkvm"))
        try:
            # (Each connection starts a video worker of its own before it is offered: up to 18 s on the Windows test VM running
            # 16 test files at a time, and one past its own time is tried again after a pause. The first offer and the enlarged
            # view's picture are waited for as conditions: two minutes, room only.)
            await first_came_to_nothing(device, 120)
            await shown(device, 5.0)  # (long enough for a dozen rounds of the back-off as it is set here)
            assert len(state.video_offers) == 1, f"offers made by a tile on screen: {len(state.video_offers)}"
            status = await device._read_status()  # (what the next look says)
            assert status["state"] == "error" and "open it large" in status["error"]["message"], status
            # What a person asks for offers again: the enlarged view. (It comes about now.)
            comes_about(state, monkeypatch)
            assert await enlarged(device, 120), "the enlarged view never got a picture"
            assert len(state.video_offers) == 2
            # A connection came about: the tile goes on as ever, and asks again where that one ends. (Shown for five and a
            # half seconds, and on until it has a connection again: the next one's worker, as above, had not been started in
            # those on the test VM.)
            jet.drop()
            dropped = time.monotonic()
            await asyncio.sleep(1.5)
            while time.monotonic() - dropped < 5.5 or len(state.video_offers) < 3 or (await device.status())["state"] != "online":
                assert time.monotonic() - dropped < 120, f"no connection again after the one that came about ended: {len(state.video_offers)} offers"  # (room only)
                await shown(device, 0.2)
            assert len(state.video_offers) == 3 and (await device.status())["state"] == "online"
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        jet.stop()


async def said_after_a_while(device: jetkvm.JetKvmDevice, words: str, seconds: float) -> dict[str, Any]:
    """A tile on screen until its look says `words` (its error's message): that look."""
    until = time.monotonic() + seconds
    while True:
        status = await device._read_status()
        if words in str((status.get("error") or {}).get("message")):
            return status
        assert time.monotonic() < until, f"its tile never said {words!r}: {status}"
        await shown(device, 0.2)


# --- offers the JetKVM refused in so many words ({"error": ...}: it took nothing from anybody) ------------------------

REFUSED = "refused the request for video"


def test_a_tile_whose_offer_the_jetkvm_refused_offers_again_by_itself_after_a_pause_and_comes_back(monkeypatch: pytest.MonkeyPatch, a_video_worker_first: None) -> None:
    # (The soak farm, 500 machines on one wall under overload: a tile whose offer came to nothing stayed red until somebody
    # opened it large.) An offer the JetKVM refused took nothing from anybody: the tile offers again by itself once its
    # pause is over, and says meanwhile that it will.
    monkeypatch.setattr(jetkvm, "OFFER_AGAIN_FIRST", 3.0)
    state = JetState(refuses_offers=True)
    jet = FakeJetKvm(state).start()

    async def run() -> None:
        device = jetkvm.JetKvmDevice(DeviceSpec("j9", "jet", jet.url, "", "secret", kind="jetkvm"))
        try:
            status = await said_after_a_while(device, REFUSED, 120)  # (room only: each offer starts a video worker first)
            assert status["state"] == "error" and "tries again by itself" in status["error"]["message"], status
            state.refuses_offers = False
            comes_about(state, monkeypatch)  # (the next offer is taken)
            until = time.monotonic() + 120  # (room only)
            while (await device.status())["state"] != "online":
                assert time.monotonic() < until, f"the tile never came back by itself: {len(state.video_offers)} offers"
                await shown(device, 0.2)
            assert len(state.video_offers) == 2, len(state.video_offers)
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        jet.stop()


def test_a_tile_whose_offers_the_jetkvm_refuses_offers_again_less_and_less_often(monkeypatch: pytest.MonkeyPatch, a_video_worker_first: None) -> None:
    # Never in a tight loop, though none of them takes anything from anybody: the pause doubles with each offer that comes to
    # nothing in a row, up to its longest, and the tile goes on offering. (The stand-in notes when each offer came, before
    # it refuses it: offers_at holds the refused ones too.)
    monkeypatch.setattr(jetkvm, "OFFER_AGAIN_FIRST", 1.0)
    monkeypatch.setattr(jetkvm, "OFFER_AGAIN_MOST", 4.0)
    state = JetState(refuses_offers=True)
    jet = FakeJetKvm(state).start()

    async def run() -> None:
        device = jetkvm.JetKvmDevice(DeviceSpec("j9", "jet", jet.url, "", "secret", kind="jetkvm"))
        try:
            await said_after_a_while(device, REFUSED, 120)
            until = time.monotonic() + 180  # (room only: each offer starts a video worker of its own first)
            while len(state.offers_at) < 5:
                assert time.monotonic() < until, f"only {len(state.offers_at)} offers"
                await shown(device, 0.2)
            gaps = [later - earlier for earlier, later in itertools.pairwise(state.offers_at)]
            for number, gap in enumerate(gaps):
                assert gap >= min(4.0, 2.0**number), f"offer {number + 2} came {gap:.2f} s after the one before: {gaps}"
            status = await device._read_status()
            assert status["state"] == "error" and "tries again by itself" in status["error"]["message"], status
            assert state.hand_overs == 0  # (and none took a viewer)
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        jet.stop()


def test_only_a_tiles_picture_offers_again_not_a_look_at_its_status(monkeypatch: pytest.MonkeyPatch, a_video_worker_first: None) -> None:
    # (The review of the hold round, L3.) The page asks every tile's status every few seconds, shown or not, and so may a
    # script with an API token: those looks made the offers, the ones that take a viewer among them. Only the tile's
    # picture, which the page asks only of a tile on screen, makes the next one once the pause is over.
    monkeypatch.setattr(jetkvm, "OFFER_AGAIN_FIRST", 0.5)
    monkeypatch.setattr(jetkvm, "OFFER_AGAIN_MOST", 0.5)
    state = JetState(refuses_offers=True)
    jet = FakeJetKvm(state).start()

    async def run() -> None:
        device = jetkvm.JetKvmDevice(DeviceSpec("j9", "jet", jet.url, "", "secret", kind="jetkvm"))
        try:
            await said_after_a_while(device, REFUSED, 120)
            offers = len(state.offers_at)
            until = time.monotonic() + 4  # (eight of its pauses)
            while time.monotonic() < until:
                status = await device.status()  # (its status only, no picture)
                await asyncio.sleep(0.1)
            assert len(state.offers_at) == offers, f"offers made by looks at its status alone: {len(state.offers_at) - offers}"
            assert status["state"] == "error", status
            until = time.monotonic() + 120  # (room only)
            while len(state.offers_at) == offers:
                assert time.monotonic() < until, "its picture made no offer"
                with contextlib.suppress(KvmError):
                    await device.snapshot(640)  # (its picture, as a tile on screen asks it)
                await asyncio.sleep(0.1)
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        jet.stop()


# --- offers the JetKVM may have taken (any other that went out) ---------------------------------------------------------
#
# Each may have taken its one viewer from whoever had it, its own page among them, and the wall never hears of that: one it
# answered and whose connection never came up, one whose answer came too late or could not be read, one whose signalling
# closed after it went. Where UDP is blocked between the two, every offer meets the same: a tile that offered again by
# itself took the viewer again and again, every two minutes at the longest. After such an offer it makes one more by itself;
# where that one comes to nothing too, it says why and waits to be opened, as before 0.4.0.

TOOK_IT = "after it may have taken the offer"
NO_MORE = "does not offer another by itself"


def test_a_tile_whose_offers_the_jetkvm_takes_and_that_never_come_up_makes_one_more_and_then_waits_to_be_opened(monkeypatch: pytest.MonkeyPatch, a_video_worker_first: None) -> None:
    monkeypatch.setattr(jetkvm, "OFFER_AGAIN_FIRST", 0.5)
    monkeypatch.setattr(jetkvm, "CANDIDATE_WAIT", 0.3)  # (the wait for the addresses an answer has none of: three seconds)
    state = JetState(connects=False)
    jet = FakeJetKvm(state).start()

    async def run() -> None:
        device = jetkvm.JetKvmDevice(DeviceSpec("j9", "jet", jet.url, "", "secret", kind="jetkvm"))
        try:
            status = await said_after_a_while(device, TOOK_IT, 120)  # (room only: each offer starts a video worker first)
            assert status["state"] == "error" and "tries once more" in status["error"]["message"], status
            assert len(state.offers_at) == 1
            status = await said_after_a_while(device, NO_MORE, 120)
            assert status["state"] == "error" and "open it large" in status["error"]["message"], status
            assert len(state.offers_at) == 2
            await shown(device, 4.0)  # (several of the pauses there were, and more than one offer's time)
            assert len(state.offers_at) == 2, f"offers the JetKVM took, made by a tile on screen: {len(state.offers_at)}"
            assert (await device._read_status())["state"] == (await device.probe()) == "error"
            # What a person asks for offers again: the enlarged view. (It comes about now, and the tile goes on as ever.)
            state.connects = True
            comes_about(state, monkeypatch)
            assert await enlarged(device, 120), "the enlarged view never got a picture"
            assert len(state.offers_at) == 3
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        jet.stop()


@pytest.mark.parametrize("ending", ["no answer in time", "the signalling closed"])
def test_a_tile_whose_offers_the_jetkvm_takes_and_never_answers_makes_one_more_and_then_waits_to_be_opened(monkeypatch: pytest.MonkeyPatch, a_video_worker_first: None, ending: str) -> None:
    # (The review of the hold round, M1.) An offer whose answer never reached the wall was taken for one the JetKVM did not
    # take, and offered again without end, each time taking the viewer back from somebody at its own page. The stand-in takes
    # every offer, as a JetKVM whose answer comes too late (a slow one, a starved wall) or whose signalling closes after it.
    monkeypatch.setattr(jetkvm, "OFFER_AGAIN_FIRST", 0.5)
    state = JetState(answers_offers=False) if ending == "no answer in time" else JetState(closes_on_offer=True)
    jet = FakeJetKvm(state).start()

    async def run() -> None:
        device = jetkvm.JetKvmDevice(DeviceSpec("j9", "jet", jet.url, "", "secret", kind="jetkvm"))
        try:
            status = await said_after_a_while(device, TOOK_IT, 120)  # (room only: each offer starts a video worker first)
            assert "tries once more" in status["error"]["message"] and len(state.offers_at) == 1, status
            status = await said_after_a_while(device, NO_MORE, 120)
            assert status["state"] == "error" and "open it large" in status["error"]["message"], status
            await shown(device, 4.0)  # (eight of the pauses there were)
            assert len(state.offers_at) == 2, f"offers the JetKVM took, made by a tile on screen: {len(state.offers_at)}"
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        jet.stop()


def test_an_edit_of_a_tile_that_waits_to_be_opened_makes_it_offer_no_more(monkeypatch: pytest.MonkeyPatch, a_video_worker_first: None) -> None:
    # (The review of the hold round, L2.) An edit (a new name) made a new client that started counting again: two more offers
    # by itself, each taking the JetKVM's viewer. What its offers came to is carried over, where it is the same address.
    monkeypatch.setattr(jetkvm, "OFFER_AGAIN_FIRST", 0.5)
    monkeypatch.setattr(jetkvm, "CANDIDATE_WAIT", 0.3)
    state = JetState(connects=False)
    jet = FakeJetKvm(state).start()

    async def run() -> None:
        before = jetkvm.JetKvmDevice(DeviceSpec("j9", "jet", jet.url, "", "secret", kind="jetkvm"))
        after = jetkvm.JetKvmDevice(DeviceSpec("j9", "jet renamed", jet.url, "", "secret", kind="jetkvm"))
        try:
            await said_after_a_while(before, NO_MORE, 120)
            offers = len(state.offers_at)
            after.takes_over(before)  # (as the wall's manager does for an edit at the same address)
            await before.close()
            await shown(after, 4.0)
            assert len(state.offers_at) == offers, f"offers made by itself after the edit: {len(state.offers_at) - offers}"
            status = await after._read_status()
            assert status["state"] == "error" and NO_MORE in status["error"]["message"], status
        finally:
            await after.close()
            await before.close()

    try:
        asyncio.run(run())
    finally:
        jet.stop()


def test_a_tile_whose_offer_the_jetkvm_took_comes_back_where_its_one_more_comes_about(monkeypatch: pytest.MonkeyPatch, a_video_worker_first: None) -> None:
    # (A busy computer that made no connection in time once: the next one comes about, and the tile is as it was.)
    monkeypatch.setattr(jetkvm, "OFFER_AGAIN_FIRST", 0.5)
    monkeypatch.setattr(jetkvm, "CANDIDATE_WAIT", 0.3)
    state = JetState(connects=False)
    jet = FakeJetKvm(state).start()

    async def run() -> None:
        device = jetkvm.JetKvmDevice(DeviceSpec("j9", "jet", jet.url, "", "secret", kind="jetkvm"))
        try:
            await said_after_a_while(device, TOOK_IT, 120)
            state.connects = True
            comes_about(state, monkeypatch)
            until = time.monotonic() + 120  # (room only)
            while (await device.status())["state"] != "online":
                assert time.monotonic() < until, f"the tile never came back by itself: {len(state.offers_at)} offers"
                await shown(device, 0.2)
            assert len(state.offers_at) == 2 and device._offer_failed is None
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        jet.stop()


def test_a_tile_offers_none_by_itself_while_the_jetkvms_own_page_has_its_viewer(monkeypatch: pytest.MonkeyPatch, a_video_worker_first: None) -> None:
    # Coming back by itself takes no viewer the wall knows somebody else holds: once its own page took the JetKVM, its tile
    # waits to be asked back ("Show here"), as ever, however long it is shown and whatever came to nothing before.
    monkeypatch.setattr(jetkvm, "OFFER_AGAIN_FIRST", 0.5)
    state = JetState(answers_offers=False)
    jet = FakeJetKvm(state).start()

    async def run() -> None:
        device = jetkvm.JetKvmDevice(DeviceSpec("j9", "jet", jet.url, "", "secret", kind="jetkvm"))
        try:
            await first_came_to_nothing(device, 120)
            comes_about(state, monkeypatch)
            until = time.monotonic() + 120  # (room only)
            while (await device.status())["state"] != "online":
                assert time.monotonic() < until, "the tile never came back by itself"
                await shown(device, 0.2)
            jet.hand_over()  # (somebody opens the JetKVM's own page)
            until = time.monotonic() + 30
            while (await device.status())["state"] != "busy":
                assert time.monotonic() < until, "the hand-over was never heard"
                await shown(device, 0.2)
            offers = len(state.video_offers)
            await shown(device, 3.0)  # (several of the pauses there were)
            assert len(state.video_offers) == offers and (await device.status())["state"] == "busy"
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        jet.stop()


@pytest.mark.parametrize("asked", ["a key", "the live view"])
def test_a_key_or_the_live_view_offers_again_after_one_that_came_to_nothing(monkeypatch: pytest.MonkeyPatch, asked: str) -> None:
    state = JetState(answers_offers=False)
    jet = FakeJetKvm(state).start()

    async def run() -> None:
        device = jetkvm.JetKvmDevice(DeviceSpec("j9", "jet", jet.url, "", "secret", kind="jetkvm"))
        try:
            await first_came_to_nothing(device)
            await shown(device, 2.0)
            assert len(state.video_offers) == 1
            comes_about(state, monkeypatch)
            await asyncio.sleep(0.3)  # (past the back-off: what a person asks for waits for nothing else)
            if asked == "a key":
                await device.act("keys", keys="Enter")
                assert state.typed == [(0, [0x28])]
            else:
                deadline = time.monotonic() + 20
                while (await device.live_frame())[0] is None:
                    assert time.monotonic() < deadline, "the live view never got a picture"
                    await asyncio.sleep(0.05)
            assert len(state.video_offers) == 2
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        jet.stop()


def test_the_wall_says_so_on_the_tile_and_its_enlarged_view_offers_again(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = JetState(answers_offers=False)
    jet = FakeJetKvm(state).start()
    try:
        with wall(tmp_path / "wall") as client:
            device = add(client, jet.url)
            wait_until(lambda: (client.get(snap(device)), NO_ANSWER in str(client.get("/api/v1/status").json()[device]["error"]))[1], "the first video connection never came to nothing", 30)
            until = time.monotonic() + 4
            while time.monotonic() < until:
                client.get("/api/v1/status")
                client.get(snap(device))
                time.sleep(0.1)
            assert len(state.video_offers) == 1
            said = client.get("/api/v1/status").json()[device]
            assert said["state"] == "error" and "open it large" in said["error"]["message"], said
            comes_about(state, monkeypatch)
            wait_until(lambda: client.get(snap(device), params={"big": 1}).status_code == 200, "the enlarged view never got a picture", 20)
            assert len(state.video_offers) == 2
    finally:
        jet.stop()


def test_while_a_tile_offers_no_other_its_look_and_the_alerts_say_the_same_of_the_jetkvm() -> None:
    # (Pulled back from 0.3.0.) Each look at the tile said "offline" (the code of its failure) while the look the alerts and the
    # history take, which makes no connection, found the JetKVM answering and said "online": the history went from one to
    # the other at every look, and no alert said a thing. The JetKVM answers and its picture does not come about: each says
    # that it has a problem, in the tile's words; and where the JetKVM is gone, each says it is offline.
    state = JetState(answers_offers=False)
    jet = FakeJetKvm(state).start()
    stopped = False

    async def run() -> None:
        nonlocal stopped
        device = jetkvm.JetKvmDevice(DeviceSpec("j9", "jet", jet.url, "", "secret", kind="jetkvm"))
        try:
            await first_came_to_nothing(device)
            await shown(device, 1.0)
            for _ in range(3):
                status, probe, glance = await device._read_status(), await device.probe(), await device.glance()
                assert status["state"] == probe == glance["state"] == "error", (status, probe, glance)
                assert "open it large" in status["error"]["message"] and "open it large" in glance["error"]["message"], (status, glance)
            jet.stop()
            stopped = True
            probe = await device.probe()
            status = await device._read_status()
            assert probe == status["state"] == "offline", (probe, status)
            assert len(state.video_offers) == 1
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        if not stopped:
            jet.stop()


def test_a_look_that_waited_for_the_connection_that_came_to_nothing_says_what_the_looks_after_it_say(monkeypatch: pytest.MonkeyPatch) -> None:
    # (0.2.2, a loaded Windows runner: the history of the test below went error, offline, error within a fifth of a second.) A
    # tile's look that came while the first video connection was being made waited for it. That connection came to nothing,
    # and the look said how it ended ("timeout": "offline") of a JetKVM that answers, where every look after it says that it
    # has a problem, in the tile's words; and the history kept that look's "offline" between the "error" of its own looks.
    state = JetState(answers_offers=False)
    jet = FakeJetKvm(state).start()

    async def run() -> None:
        device = jetkvm.JetKvmDevice(DeviceSpec("j9", "jet", jet.url, "", "secret", kind="jetkvm"))
        try:
            try:
                await device.snapshot(640)  # (the tile's picture: it offers the connection)
            except KvmError:
                pass
            until = time.monotonic() + 30  # (the decoder's process is made first: seconds on a busy computer)
            while not state.video_offers:
                assert time.monotonic() < until, "no video connection was offered"
                await asyncio.sleep(0.01)
            await asyncio.sleep(0.2)  # (the offer's answer is waited for from now on, a second here)
            monkeypatch.setattr(jetkvm, "CONNECT_TIMEOUT", 5.0)  # (and the look waits longer than that)
            look = await device._read_status()
            assert NO_ANSWER in look["error"]["message"], look  # (it waited for that connection, and heard how it ended)
            after = await device._read_status()
            assert look["state"] == after["state"] == await device.probe() == "error", (look, after)
            assert "open it large" in look["error"]["message"], look
            assert len(state.video_offers) == 1
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        jet.stop()


def test_while_a_tile_offers_no_other_the_history_keeps_one_state_of_the_jetkvm(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The same, on a wall: the history keeps what every look at the tile says and what its own look says, once a second here.)
    from qkvm import server

    monkeypatch.setattr(server, "HISTORY_LOOK_EVERY", 0.2)
    state = JetState(answers_offers=False)
    jet = FakeJetKvm(state).start()
    try:
        with wall(tmp_path / "wall") as client:
            device = add(client, jet.url)
            wait_until(lambda: (client.get(snap(device)), NO_ANSWER in str(client.get("/api/v1/status").json()[device]["error"]))[1], "the first video connection never came to nothing", 30)
            since = time.time()
            until = time.monotonic() + 3
            while time.monotonic() < until:
                client.get("/api/v1/status")
                client.get(snap(device))
                time.sleep(0.1)
            client.core.history.flush()  # type: ignore[attr-defined]
            rows = client.get(f"/api/v1/devices/{device}/history", params={"what": "states", "since": since}).json()["rows"]
            assert [row["state"] for row in rows] in ([], ["error"]), rows
            assert client.get(f"/api/v1/devices/{device}/history").json()["state"] == "error"
            assert len(state.video_offers) == 1
    finally:
        jet.stop()


@pytest.mark.parametrize("slow", ["past its own time", "past the connection's", "nearly the connection's"])
def test_a_connection_whose_video_worker_is_slow_to_start_is_not_the_jetkvm_going_offline(monkeypatch: pytest.MonkeyPatch, slow: str) -> None:
    # (Found for 0.4.0 on the Windows test VM running 16 test files at a time, where a video worker took up to 18 s to start.)
    # A connection starts its video worker before anything is asked of the JetKVM. One that took longer than its own start is
    # given ("not yet": a computer under load; the next look tries again) ended the connection; one that took longer than the
    # connection is given ran out its time as a JetKVM that is "taking too long to connect", and so did one that took nearly
    # that long, leaving the JetKVM a moment. Each way the look said "offline" of a JetKVM nothing had been asked of: the tile
    # and its live line said so, its history went offline and back between the looks the alerts take, which found it there,
    # and a look that says "offline" asks, after a while, whether it answers the other way. Nothing was heard of the JetKVM:
    # what was known of it stands until a connection is made, and the JetKVM has the connection's time from then.
    state = JetState()
    comes_about(state, monkeypatch)
    jet = FakeJetKvm(state).start()
    slow_left = [0]
    starts: list[str] = []
    released = threading.Event()

    class SlowToStart(video.Worker):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            if slow_left[0]:
                slow_left[0] -= 1
                if slow == "past its own time":
                    starts.append("slow, given up")
                    raise video.VideoUnavailable("the video worker did not answer within 15 seconds", lasting=False)
                starts.append("slow")
                if slow == "nearly the connection's":
                    began = time.monotonic()  # (started, and the rest of the time waited out, in its own thread as a worker starts)
                    super().__init__(*args, **kwargs)
                    time.sleep(max(0.0, jetkvm.CONNECT_TIMEOUT - 0.01 - (time.monotonic() - began)))
                    starts.append("started")
                    return
                released.wait(30)
            super().__init__(*args, **kwargs)
            starts.append("started")

    monkeypatch.setattr(video, "Worker", SlowToStart)

    async def run() -> tuple[list[tuple[str, Any]], list[bool]]:
        device = jetkvm.JetKvmDevice(DeviceSpec("j9", "jet", jet.url, "", "secret", kind="jetkvm"))
        other_way: list[bool] = []
        monkeypatch.setattr(device, "_look_the_other_way", lambda down: other_way.append(down))
        said: list[tuple[str, Any]] = []

        async def look() -> None:
            status = await device.status()
            now = (status["state"], (status.get("error") or {}).get("code"))
            if not said or said[-1] != now:
                said.append(now)
            await asyncio.sleep(0.05)

        try:
            until = time.monotonic() + 60  # (room only: a busy computer's first worker)
            while (await device.status())["state"] != "online":
                assert time.monotonic() < until, "the JetKVM was never online"
                await asyncio.sleep(0.05)
            slow_left[0] = 1
            if slow == "past the connection's":
                monkeypatch.setattr(jetkvm, "CONNECT_TIMEOUT", 0.5)
            elif slow == "nearly the connection's":
                monkeypatch.setattr(jetkvm, "CONNECT_TIMEOUT", 3.0)  # (and the JetKVM is to have all of it from then)
            assert device._session is not None
            device._make_anew(device._session, "a key it was sent was not answered in time")  # (the next one's worker is slow)
            if slow == "past the connection's":
                until = time.monotonic() + 3  # (the looks' waits for the connection run out again and again meanwhile)
                while time.monotonic() < until:
                    await look()
                assert starts[-1:] == ["slow"], starts
                monkeypatch.setattr(jetkvm, "CONNECT_TIMEOUT", 15.0)
                for _ in range(20):  # (a wait begun before runs out first)
                    await look()
                released.set()
            until = time.monotonic() + 60  # (room only)
            while state.sessions < 2 or device._session is None or not device._session.live:
                assert time.monotonic() < until, f"no connection again once a worker started: {said}, {starts}"
                await look()
            for _ in range(10):  # (and what the looks that waited for it say)
                await look()
        finally:
            released.set()
            await device.close()
        return said, other_way

    try:
        said, other_way = asyncio.run(run())
    finally:
        jet.stop()
    assert {state for state, _ in said} == {"online"} and starts[-2:] in (["slow, given up", "started"], ["slow", "started"]), (said, starts)
    assert True not in other_way, said


def test_an_https_jetkvm_whose_video_never_comes_about_is_not_said_to_answer_over_plain_http_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The second review's F6, from 0.2.0, made to last by the rule above.) Each look at such a tile was "offline" (the code of
    # its failure), and an offline look asked, after two minutes, whether it answers the other way: plain HTTP answered, and the
    # tile said "This JetKVM no longer answers over HTTPS, only over plain HTTP", of one whose HTTPS answered all along. That
    # is said only where HTTPS itself does not answer (tests/test_jetkvm.py: its HTTPS mode switched off).
    from tests.test_jetkvm import other_ways

    monkeypatch.setattr(jetkvm, "WAY_PATIENCE", 1.0)  # (two minutes: here, one second)
    monkeypatch.setattr(jetkvm, "WAY_WHEN_DOWN", 0.2)
    state = JetState()
    plain, secure = FakeJetKvm(state).start(), FakeJetKvm(state, tls_dir=tmp_path / "jet").start()
    other_ways(monkeypatch, {plain.url: secure.url})
    try:
        with wall(tmp_path / "wall") as client:
            device = add(client, secure.url)
            state.answers_offers = False
            said: list[tuple[str, str]] = []
            until = time.monotonic() + 8
            while time.monotonic() < until:
                status = client.get("/api/v1/status").json()[device]
                said.append((str(status.get("state")), str((status.get("error") or {}).get("code"))))
                client.get(snap(device))
                time.sleep(0.2)
            assert ("error", "plain_only") not in said, said
            message = (client.get("/api/v1/status").json()[device].get("error") or {}).get("message", "")
            assert "open it large" in message, message
            assert "http" not in state.passwords_over
    finally:
        plain.stop()
        secure.stop()
