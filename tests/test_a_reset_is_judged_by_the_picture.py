"""A KVM's reset button, judged by the machine's picture, against a stand-in that answers as a real Comet's board did.

The power stays on through a reset, so the board says nothing of it; and a real Comet's computer (on GL.iNet's newer
firmware, 2026-11-16) kept its HDMI signal up through its restart and its firmware's screens, so neither does the signal. A
look at that signal made a reset that worked look like one that did nothing. The picture is the witness: a restart clears
the screen and shows the maker's logo or the firmware's in much of it. A reset is done once the screen is seen to change
(its signal goes or comes, its size changes, or the picture changes in much of it); where it is not, within the time a
press is looked for, the answer says it was pressed and the restart not seen, never that it was not carried out. Where the
screen cannot be compared (no picture before the press that the wall can read), nothing is looked for, as before.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

import pytest

from qkvm import kvm, video
from tests.fake_kvm import FakeKvm, FakeState
from tests.test_live import a_jpeg
from tests.test_wall import add, wait_until, wall

BLUE, BLACK = (32, 74, 135), (0, 0, 0)


@pytest.fixture(autouse=True)
def quick(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(kvm, "SEEN_WITHIN", 3.0)
    monkeypatch.setattr(kvm, "RESET_LOOK_EVERY", 0.1)


@pytest.fixture(scope="module", autouse=True)
def a_video_worker_first() -> None:
    # The pictures are compared in the isolated video worker. The first of a process may take seconds to start on Windows
    # (see test_a_comets_keys_and_mouse_as_the_real_one_took_them.py): made before the first press, for as long as that takes.
    def started() -> bool:
        try:
            video.Worker().close()
        except video.VideoError:
            return False
        return True

    wait_until(started, "no isolated video worker could be started", timeout=300)


def press(client: Any, device: str) -> tuple[float, Any]:
    began = time.monotonic()
    reply = client.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_reset"})
    return time.monotonic() - began, reply


def after_the_press(fake: FakeKvm, then: Any) -> threading.Thread:
    """`then()` once the stand-in's board has been told to press reset."""

    def run() -> None:
        wait_until(lambda: "atx reset" in fake.state.actions, "reset was never pressed")
        time.sleep(0.3)
        then()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def a_comet(**more: Any) -> FakeKvm:
    return FakeKvm(FakeState(atx=True, computer_follows=True, picture=a_jpeg(BLUE), picture_type="image/jpeg", **more)).start()


def test_a_reset_is_done_once_the_picture_changes_while_the_signal_stays(tmp_path: Path) -> None:
    fake = a_comet(restarts_to=a_jpeg(BLACK), restart_after=0.5)
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            took, reply = press(client, device)
            assert (reply.status_code, reply.json()) == (200, {"ok": True, "note": None}), reply.text
            # (Waited for: the picture changed half a second after the button was let go.)
            assert 0.5 <= took < kvm.SEEN_WITHIN, f"a reset whose picture changed half a second after was answered after {took:.2f} s"
            assert fake.state.signal is True  # (the witness was the picture alone)
            entry = next(one for one in client.get("/api/v1/audit?kind=action").json()["entries"] if one.get("action") == "atx_reset")
            assert entry["event"] == "action" and "note" not in entry, entry
    finally:
        fake.stop()


def test_a_reset_whose_picture_stays_as_it_was_is_said_pressed_and_not_seen(tmp_path: Path) -> None:
    fake = a_comet()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            took, reply = press(client, device)
            assert reply.status_code == 200, reply.text
            note = reply.json()["note"]
            assert note == (
                "pressed; its screen was not seen to change within 3 seconds, and some machines keep their picture a while "
                "through a restart: look at it before pressing again"
            ), note
            assert took >= kvm.SEEN_WITHIN, f"said not seen after {took:.2f} s"
            assert fake.state.actions == ["atx reset"]  # (pressed once, and only once)
            # Done, with the word: never "not carried out", never a failure whose retry would reset it a second time.
            entry = next(one for one in client.get("/api/v1/audit?kind=action").json()["entries"] if one.get("action") == "atx_reset")
            assert (entry["event"], entry["note"]) == ("action", note), entry
    finally:
        fake.stop()


@pytest.mark.parametrize("witness", ["signal", "size"])
def test_a_reset_is_seen_where_the_signal_goes_or_the_pictures_size_changes(tmp_path: Path, witness: str) -> None:
    fake = a_comet()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)

            def restart() -> None:
                if witness == "signal":
                    fake.state.signal = False
                else:
                    fake.state.width, fake.state.height = 1024, 768  # (the firmware's screen, in a mode of its own)

            after_the_press(fake, restart)
            took, reply = press(client, device)
            assert (reply.status_code, reply.json()) == (200, {"ok": True, "note": None}), reply.text
            assert 0.3 <= took < kvm.SEEN_WITHIN, took  # (waited for the change, a third of a second after the press)
    finally:
        fake.stop()


def test_a_reset_of_a_dark_screen_is_seen_when_a_picture_comes_and_said_where_none_does(tmp_path: Path) -> None:
    fake = a_comet(signal=False)
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            took, reply = press(client, device)
            assert (reply.status_code, reply.json()["note"]) == (200, "pressed; its screen stayed dark, so a restart was not seen: look at it before pressing again"), reply.text
            assert took >= kvm.SEEN_WITHIN
            # The machine's firmware puts a picture on a screen that was asleep: that is the restart.
            fake.state.actions.clear()
            after_the_press(fake, lambda: setattr(fake.state, "signal", True))
            took, reply = press(client, device)
            assert (reply.status_code, reply.json()) == (200, {"ok": True, "note": None}), reply.text
            assert 0.3 <= took < kvm.SEEN_WITHIN, took
    finally:
        fake.stop()


def test_a_screen_the_wall_cannot_compare_is_not_looked_at(tmp_path: Path) -> None:
    # A picture that is no JPEG (no KVM sends one of a screen with a signal: the stand-in's own): nothing to compare it by,
    # so nothing is looked for, and the press is done once the board has let go of the button, as before.
    fake = FakeKvm(FakeState(atx=True)).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            took, reply = press(client, device)
            assert (reply.status_code, reply.json()) == (200, {"ok": True, "note": None}), reply.text
            assert took < kvm.SEEN_WITHIN
    finally:
        fake.stop()


def test_a_restart_for_virtual_media_whose_picture_stays_says_pressed_not_restarted(tmp_path: Path) -> None:
    # The media box's "Restart it now" presses reset where the machine is on: said "restarted" only once that is seen.
    from tests.test_virtual_media_on_a_kvm import DEBIAN, a_kvm, images, mount

    fake = a_comet(msd=True, msd_images=images({DEBIAN: 700_000}))
    try:
        with wall(tmp_path) as admin:
            device = a_kvm(admin, fake)
            reply = mount(admin, device, restart=True)
            assert reply.status_code == 200, reply.text
            assert reply.json()["note"] == (
                "Its reset button was pressed; its screen was not seen to change within 3 seconds, and some machines keep their "
                "picture a while through a restart: look at it before pressing again; then pick the KVM's drive in its boot menu "
                "where it does not start from it by itself."
            ), reply.json()["note"]
            assert fake.state.actions.count("atx reset") == 1
    finally:
        fake.stop()
