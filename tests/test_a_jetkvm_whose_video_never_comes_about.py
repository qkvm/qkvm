"""A JetKVM whose HTTP answers and whose video connection never comes about (UDP blocked between the two, ICE failing).

Every offer of a video connection takes the JetKVM's one viewer from whoever has it, its own page included, and the wall
never hears that somebody else had it over a connection that never opened. A tile that was shown offered one again at every
round of its back-off, about every half minute for as long as it was on screen (the desktop's item 9, confirmed by the
review's probe). As the desktop decided (2026-10-31): after an offer that came to nothing, a tile offers no other; what a
person asks for does (the enlarged view, the live view, a key or a button, "Show here"), and once a connection has come about
the tile goes on as ever.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest

from qkvm import jetkvm, kvm, update, vault
from qkvm.kvm import DeviceSpec, KvmError
from tests.fake_jetkvm import FakeJetKvm, JetState
from tests.test_wall import add, snap, wait_until, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(jetkvm, "CONNECT_TIMEOUT", 1.0)  # (fifteen seconds for an answer to the offer: here, one; see `comes_about`)
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


def test_a_tile_offers_no_second_video_connection_after_one_that_came_to_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    state = JetState(answers_offers=False)
    jet = FakeJetKvm(state).start()

    async def run() -> None:
        device = jetkvm.JetKvmDevice(DeviceSpec("j9", "jet", jet.url, "", "secret", kind="jetkvm"))
        try:
            await first_came_to_nothing(device)
            await shown(device, 5.0)  # (long enough for a dozen rounds of the back-off as it is set here)
            assert len(state.video_offers) == 1, f"offers made by a tile on screen: {len(state.video_offers)}"
            status = await device._read_status()  # (what the next look says)
            assert status["state"] == "error" and "open it large" in status["error"]["message"], status
            # What a person asks for offers again: the enlarged view. (It comes about now.)
            comes_about(state, monkeypatch)
            assert await enlarged(device, 20.0), "the enlarged view never got a picture"
            assert len(state.video_offers) == 2
            # A connection came about: the tile goes on as ever, and asks again where that one ends.
            jet.drop()
            await asyncio.sleep(1.5)
            await shown(device, 4.0)
            assert len(state.video_offers) == 3 and (await device.status())["state"] == "online"
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
