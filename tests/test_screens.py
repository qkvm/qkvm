"""The screen watch (screens.py): how pictures are compared, when a watch goes off and when it is over, and what is kept."""

from __future__ import annotations

import asyncio
import json
import os
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from qkvm import screens
from qkvm.kvm import Snapshot
from qkvm.screens import NO_SIGNAL, UNCHANGED, ScreenWatch, Watched
from qkvm.video import RGBFrame, VideoSession, decode_jpeg, encode_jpeg

ID = "ab12cd34"
WORKER: dict[str, Any] = {}  # the video worker this file makes its pictures with, and shrinks them through: one for all of it


@pytest.fixture(scope="module", autouse=True)
def worker() -> Iterator[None]:
    WORKER["session"] = VideoSession()
    yield
    WORKER.pop("session").close()


@pytest.fixture(autouse=True)
def quick(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(screens, "MINUTE", 0.2)  # (a minute is a fifth of a second here)


def screen(width: int = 640, height: int = 360, blocks: tuple[tuple[int, int, int, int, int], ...] = (), noise: int = 0, seed: int = 1) -> bytes:
    """A desktop of two shades with a taskbar, as RGB; `blocks`: (x, y, w, h, shade) drawn on it; `noise`: each pixel moved
    by up to that much, as an analog capture moves it."""
    rows = []
    state = seed
    for y in range(height):
        shade = 40 if y < height * 9 // 10 else 200
        line = bytearray([shade, shade + 10, shade + 20] * width)
        for x, top, w, h, value in blocks:
            if top <= y < top + h:
                line[x * 3 : (x + w) * 3] = bytes([value]) * (w * 3)
        if noise:
            for i in range(0, len(line), 7):
                state = (state * 1103515245 + 12345) % 2**31
                line[i] = max(0, min(255, line[i] + state % (2 * noise + 1) - noise))
        rows.append(bytes(line))
    return b"".join(rows)


def jpeg(rgb: bytes, width: int = 640, height: int = 360) -> bytes:
    return encode_jpeg(RGBFrame(width, height, rgb), None, 3, WORKER["session"])


def shrunk(data: bytes, width: int = 640, height: int = 360) -> bytes:
    return screens.fingerprint(decode_jpeg(data, width, height, WORKER["session"]), width, height)


def test_the_same_screen_through_noise_and_jpeg_is_the_same_and_a_small_change_is_another() -> None:
    plain = shrunk(jpeg(screen()))
    assert len(plain) == screens.GRID[0] * screens.GRID[1]
    assert not screens.differs(plain, shrunk(jpeg(screen(noise=6))))  # a noisy capture of the same screen
    assert not screens.differs(plain, shrunk(encode_jpeg(RGBFrame(640, 360, screen()), None, 12, WORKER["session"])))  # coarser JPEG
    # The same screen at another size (a tile's picture beside the large view's): the same.
    big = shrunk(jpeg(screen(1920, 1080), 1920, 1080), 1920, 1080)
    assert not screens.differs(plain, big)
    # A pointer moved (from one place to another: two squares), a clock's digits that changed, a line of text: another.
    assert screens.differs(plain, shrunk(jpeg(screen(blocks=((100, 100, 8, 12, 255), (400, 200, 8, 12, 255))))))
    assert screens.differs(plain, shrunk(jpeg(screen(blocks=((590, 330, 24, 8, 255),)))))
    assert screens.differs(plain, shrunk(jpeg(screen(blocks=((20, 50, 300, 6, 230),)))))
    # One square that moves a little is not (a cursor's blink: within one square, not far enough).
    assert not screens.differs(plain, shrunk(jpeg(screen(blocks=((101, 101, 3, 1, 255),)))))
    assert screens.differs(plain, plain[:-1])  # (another size altogether: another screen)


def test_what_an_alert_of_a_watch_says() -> None:
    from qkvm.alerts import describe_watch, lasted

    assert [lasted(s) for s in (10, 59 * 60, 61 * 60, 2 * 3600, 26 * 3600, 49 * 3600)] == ["1 min", "59 min", "1 h 1 min", "2 h", "1 d 2 h", "2 d 1 h"]
    dark = describe_watch("Office PC", "10.0.0.5", NO_SIGNAL, 10, False, 600, kept=True)
    assert (dark.kind, dark.state, dark.title) == ("no_signal", "no_signal", "Office PC has had no video signal for 10 min") and "kept" in dark.text
    assert "kept" not in describe_watch("Office PC", "", NO_SIGNAL, 10, False).text  # (the wall had no picture of it)
    back = describe_watch("Office PC", "", NO_SIGNAL, 10, True, 3700)
    assert (back.kind, back.previous, back.title, back.text) == ("recovered", "no_signal", "Office PC has a picture again", "The video signal is back, after 1 h 2 min without.")
    same = describe_watch("Build", "", UNCHANGED, 30, False, 1800, kept=True)
    assert (same.kind, same.state, same.title) == ("unchanged", "unchanged", "Build: screen unchanged for 30 min") and "not always a hang" in same.text
    again = describe_watch("Build", "", UNCHANGED, 30, True, 7200)
    assert (again.kind, again.title, again.text) == ("recovered", "Build: the screen changes again", "Its screen changed after looking the same for 2 h.")


def test_minutes_are_whole_and_a_day_at_the_most() -> None:
    assert [screens.minutes(value) for value in (None, 0, -5, 1, 30, 1440, 5000, 2.5, "10", True)] == [0, 0, 0, 1, 30, 1440, 1440, 0, 0, 0]


def a_round(watch: ScreenWatch, *machines: Watched, paused: bool = False) -> list[screens.Event]:
    return asyncio.run(watch.round(list(machines), {machine.device_id for machine in machines}, paused))


class Tile:
    """A tile on a screen somewhere: its pictures handed out one after the other, as the wall hands them out."""

    def __init__(self, watch: ScreenWatch, device_id: str = ID) -> None:
        self.watch, self.device_id = watch, device_id

    def shows(self, data: bytes, signal: bool = True, kind: str = "image/jpeg") -> None:
        # (Each a picture of its own, as each one asked of a device is: the same one handed out again is not compared again.)
        self.watch.saw(self.device_id, Snapshot(bytes(bytearray(data)), kind, signal, time.monotonic()))


def test_a_screen_that_looks_the_same_goes_off_after_its_minutes_and_is_over_when_it_changes(tmp_path: Path) -> None:
    watch = ScreenWatch(tmp_path)
    tile, same = Tile(watch), Watched(ID, "online", 0, 1)
    first, other = jpeg(screen()), jpeg(screen(blocks=((300, 100, 60, 20, 255),)))
    told: list[screens.Event] = []
    a_round(watch, same)  # (the first round: from now on its pictures are noted)
    began = time.monotonic()
    while not told:
        assert time.monotonic() - began < 5, "the screen that looked the same was never told"
        tile.shows(first)
        told = a_round(watch, same)
        time.sleep(0.03)
    assert time.monotonic() - began >= screens.MINUTE
    event = told[0]
    assert (event.watch, event.back, event.minutes, event.picture and event.picture.data) == (UNCHANGED, False, 1, first)
    assert event.lasted >= screens.MINUTE and event.stamp
    assert watch.picture(ID, event.stamp) == (first, "image/jpeg")  # kept, under its stamp
    assert watch.standing(ID) == [UNCHANGED]
    for _ in range(3):  # told once
        tile.shows(first)
        assert a_round(watch, same) == []
    tile.shows(other)
    over = a_round(watch, same)
    assert [(e.watch, e.back, e.picture) for e in over] == [(UNCHANGED, True, None)] and over[0].lasted >= screens.MINUTE
    assert watch.standing(ID) == []


def test_a_picture_handed_out_again_is_not_compared_again_and_two_of_one_moment_are_two(tmp_path: Path) -> None:
    watch = ScreenWatch(tmp_path)
    same = Watched(ID, "online", 0, 1)
    a_round(watch, same)
    frame = Snapshot(jpeg(screen()), "image/jpeg", True, 100.0)
    watch.saw(ID, frame)
    a_round(watch, same)
    machine = watch._machines[ID]
    assert machine.pending is None and machine.last_lit is not None and machine.last_lit.data is frame.data
    watch.saw(ID, frame)  # (a still, or a frame several viewers share, handed out again)
    assert machine.pending is None
    watch.saw(ID, Snapshot(jpeg(screen()), "image/jpeg", True, 99.0))  # (one asked for before it, that came late)
    assert machine.pending is None
    # Asked for in the same moment by the clock (on Windows before Python 3.13, within 15.6 ms), and another picture.
    other = Snapshot(jpeg(screen(blocks=((300, 100, 60, 20, 255),))), "image/jpeg", True, 100.0)
    watch.saw(ID, other)
    assert machine.pending is not None and machine.pending.data is other.data


def test_a_picture_handed_out_while_another_is_compared_is_the_next_rounds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    watch = ScreenWatch(tmp_path)
    tile, same = Tile(watch), Watched(ID, "online", 0, 1)
    first, other = jpeg(screen()), jpeg(screen(blocks=((300, 100, 60, 20, 255),)))
    a_round(watch, same)
    work = ScreenWatch._work

    def meanwhile(self: ScreenWatch, *asked: Any) -> dict[str, bytes | None]:
        found = work(self, *asked)
        tile.shows(other)  # (a tile's picture, handed out while the first was being compared)
        return found

    monkeypatch.setattr(ScreenWatch, "_work", meanwhile)
    tile.shows(first)
    assert a_round(watch, same) == []
    machine = watch._machines[ID]
    assert machine.pending is not None and machine.pending.data == other and machine.last_lit is not None and machine.last_lit.data == first
    monkeypatch.setattr(ScreenWatch, "_work", work)
    time.sleep(screens.MINUTE * 0.5)
    assert a_round(watch, same) == [] and machine.pending is None  # (another screen: the run begins again with it)


def test_without_pictures_for_a_while_or_with_a_placeholder_of_no_signal_the_run_starts_again(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(screens, "GAP_MINUTES", 2)
    watch = ScreenWatch(tmp_path)
    tile, same = Tile(watch), Watched(ID, "online", 0, 3)
    first = jpeg(screen())
    a_round(watch, same)
    tile.shows(first)
    assert a_round(watch, same) == []
    time.sleep(screens.MINUTE * 2.5)  # nobody had the tile on a screen: no pictures, longer than the gap
    assert a_round(watch, same) == []
    tile.shows(first)
    assert a_round(watch, same) == []  # the run begins again here, three minutes before it goes off
    time.sleep(screens.MINUTE * 1.5)
    tile.shows(jpeg(screen()), signal=False)  # the KVM's placeholder: no signal
    assert a_round(watch, same) == []
    time.sleep(screens.MINUTE * 1.6)
    tile.shows(first)
    assert a_round(watch, same) == []  # (three minutes since the first picture, but the run began again at the placeholder)


def test_no_signal_for_its_minutes_goes_off_with_the_last_picture_and_is_over_with_the_signal(tmp_path: Path) -> None:
    watch = ScreenWatch(tmp_path)
    tile = Tile(watch)
    lit = jpeg(screen(blocks=((10, 10, 100, 40, 250),)))
    a_round(watch, Watched(ID, "online", 1, 0))
    tile.shows(lit)
    assert a_round(watch, Watched(ID, "online", 1, 0)) == []
    tile.shows(jpeg(screen()), signal=False)  # (its placeholder is no picture of its screen)
    assert a_round(watch, Watched(ID, "no_signal", 1, 0)) == []
    time.sleep(screens.MINUTE * 0.6)
    assert a_round(watch, Watched(ID, "offline", 1, 0)) == []  # it did not answer: not known to be dark, the run is over
    assert a_round(watch, Watched(ID, "no_signal", 1, 0)) == []
    time.sleep(screens.MINUTE * 0.6)
    assert a_round(watch, Watched(ID, "no_signal", 1, 0)) == []  # (a minute in all, but not in one run)
    time.sleep(screens.MINUTE * 0.5)
    told = a_round(watch, Watched(ID, "no_signal", 1, 0))
    assert [(e.watch, e.back) for e in told] == [(NO_SIGNAL, False)]
    assert told[0].picture is not None and told[0].picture.data == lit and watch.picture(ID, told[0].stamp) == (lit, "image/jpeg")
    assert a_round(watch, Watched(ID, "no_signal", 1, 0)) == []  # told once
    assert a_round(watch, Watched(ID, "offline", 1, 0)) == []  # gone: what went off stands
    assert [(e.watch, e.back) for e in a_round(watch, Watched(ID, "online", 1, 0))] == [(NO_SIGNAL, True)]
    assert watch.standing(ID) == []


def test_while_alerts_are_paused_nothing_goes_off_and_what_is_so_afterwards_is_told_then(tmp_path: Path) -> None:
    watch = ScreenWatch(tmp_path)
    a_round(watch, Watched(ID, "no_signal", 1, 0), paused=True)
    time.sleep(screens.MINUTE * 1.2)
    assert a_round(watch, Watched(ID, "no_signal", 1, 0), paused=True) == []
    told = a_round(watch, Watched(ID, "no_signal", 1, 0))
    assert [(e.watch, e.back, e.picture, e.stamp) for e in told] == [(NO_SIGNAL, False, None, "")]  # (the wall had no picture of it)
    assert a_round(watch, Watched(ID, "online", 1, 0), paused=True) == []
    assert watch.standing(ID) == [NO_SIGNAL]  # (what is over in a pause is told after it)
    assert [(e.watch, e.back) for e in a_round(watch, Watched(ID, "online", 1, 0))] == [(NO_SIGNAL, True)]


def test_what_stands_is_written_down_and_is_over_after_a_restart_as_well(tmp_path: Path) -> None:
    watch = ScreenWatch(tmp_path)
    a_round(watch, Watched(ID, "no_signal", 1, 0), Watched("other", "online", 1, 0))
    time.sleep(screens.MINUTE * 1.2)
    assert len(a_round(watch, Watched(ID, "no_signal", 1, 0), Watched("other", "online", 1, 0))) == 1
    assert json.loads((tmp_path / screens.FILE).read_text(encoding="ascii")) == {"told": {ID: [NO_SIGNAL]}}
    again = ScreenWatch(tmp_path)  # (qKVM started again)
    assert again.standing(ID) == [NO_SIGNAL]
    assert [(e.device_id, e.watch, e.back) for e in a_round(again, Watched(ID, "online", 1, 0), Watched("other", "online", 1, 0))] == [(ID, NO_SIGNAL, True)]
    assert json.loads((tmp_path / screens.FILE).read_text(encoding="ascii")) == {"told": {}}
    # A watch switched off is over without a word; what the file says that is no watch or no machine is not taken up.
    (tmp_path / screens.FILE).write_text(json.dumps({"told": {ID: ["unchanged", "hung"], "x y": ["no_signal"], "z": "no_signal"}}), encoding="ascii")
    third = ScreenWatch(tmp_path)
    assert (third.standing(ID), third.standing("x y"), third.standing("z")) == ([UNCHANGED], [], [])
    assert a_round(third, Watched(ID, "online", 1, 0)) == [] and third.standing(ID) == []
    (tmp_path / screens.FILE).write_text("[" * 100_000, encoding="ascii")
    assert ScreenWatch(tmp_path).standing(ID) == []


def test_one_picture_is_kept_of_each_machine_and_it_goes_with_the_machine_and_with_time(tmp_path: Path) -> None:
    watch = ScreenWatch(tmp_path)
    seen = screens.Seen(b"\xff\xd8 one", "image/jpeg", True, time.monotonic(), time.time(), 1)
    first = watch.keep(ID, seen)
    time.sleep(0.002)
    second = watch.keep(ID, screens.Seen(b"\x89PNG two", "image/png", True, time.monotonic(), time.time(), 1))
    other = watch.keep("ef56ab78", seen)
    assert first and second and first != second
    assert watch.picture(ID, first) is None and watch.picture(ID, second) == (b"\x89PNG two", "image/png")  # the last one only
    folder = tmp_path / screens.FOLDER
    assert sorted(path.name for path in folder.iterdir()) == sorted([f"{ID}-{second}.png", f"ef56ab78-{other}.jpg"])
    if os.name == "posix":
        assert folder.stat().st_mode & 0o777 == 0o700 and (folder / f"{ID}-{second}.png").stat().st_mode & 0o777 == 0o600
    for odd in ("../x", "1;2", "", "1" * 17):
        assert watch.picture(ID, odd) is None
    assert watch.picture("../ab12cd34", second) is None
    watch.forget(ID)
    a_round(watch, Watched("ef56ab78", "online", 1, 0))
    assert sorted(path.name for path in folder.iterdir()) == [f"ef56ab78-{other}.jpg"]
    old = time.time() - (screens.KEEP_DAYS + 1) * screens.DAY
    os.utime(folder / f"ef56ab78-{other}.jpg", (old, old))
    watch._swept_at = -1e9  # (looked through once an hour: now)
    a_round(watch, Watched("ef56ab78", "online", 1, 0))
    assert list(folder.iterdir()) == []


def test_a_machine_that_is_not_watched_costs_nothing(tmp_path: Path) -> None:
    watch = ScreenWatch(tmp_path)
    a_round(watch, Watched(ID, "online", 0, 0))
    Tile(watch).shows(jpeg(screen()))
    assert watch._machines == {} and watch._session is None
    assert not (tmp_path / screens.FOLDER).exists()
