"""What a VNC server's bytes cost the program that reads them: the event loop's time, the drawing threads' time, memory.

A few kilobytes can say "draw this" in ways that cost seconds: rectangles with no pixels in them, Hextile tiles one pixel
wide, runs of one pixel, Tight's gradient filter, JPEGs of a tile each. What is held here, against servers made of bytes
(test_rfb.Scripted, every byte there at once, as a full network buffer has them): what such bytes are counted as, that the
event loop is let go of while they are read, and that the drawing threads give each server its share of their time and no
more, a slice at a time. Bounds on what is counted, or on shares of time measured beside the work, never on how fast this
machine is: a slower one draws less in a share, and is held to the same share.
"""

from __future__ import annotations

import asyncio
import itertools
import struct
import sys
import threading
import time
import tracemalloc
import zlib
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

from qkvm import rfb
from qkvm.rfb import Client, RfbError
from tests import fake_vnc
from tests.fake_vnc import PixelFormat, rectangle_header, update_message
from tests.test_rfb import Scripted, run

FORMAT = PixelFormat.read(rfb.PIXEL_FORMAT)


def screen(width: int, height: int) -> bytes:
    """The handshake of a scripted server (3.8, no password) whose screen is `width` by `height`."""
    name = b"scripted"
    return b"RFB 003.008\n" + bytes([1, 1]) + struct.pack(">I", 0) + struct.pack(">HH", width, height) + FORMAT.pack() + struct.pack(">I", len(name)) + name


async def served(client: Client) -> RfbError:
    await client.handshake()
    try:
        await client.serve()
    except RfbError as ex:
        return ex
    raise AssertionError("it did not end")


def frozen() -> Callable[[], float]:
    """A clock that stands still: everything the server sends arrives in one second, as far as the limits can tell."""
    return lambda: 10.0


# --- what bytes are counted as --------------------------------------------------------------------------------------


def test_a_hextile_rectangle_with_no_pixels_reads_no_tiles_and_costs_a_rectangle_all_the_same() -> None:
    # A Hextile rectangle 0 pixels wide and 8192 tall was taken row of tiles by row of tiles, 512 of them, none of which
    # holds a tile, each handed on to be drawn: 20,000 of them on a screen 1 by 8192, 240 KB on the wire, took 1.4 GB and
    # held the event loop for seconds. And as nothing on the screen, it cost nothing against the limits.
    script = screen(1, 8192) + update_message([rectangle_header((0, 0, 0, 8192), rfb.HEXTILE)] * 2000) + update_message([rectangle_header((0, 0, 1, 1), rfb.RAW) + b"\1\2\3\0"])
    client = Client(Scripted(script), None, clock=frozen())
    tracemalloc.start()
    try:
        ended = run(served(client))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert ended.code == rfb.CLOSED and client.frames == 1 and bytes(client.rgb[:3]) == b"\1\2\3"
    assert peak < 4 * 1024 * 1024, peak  # (the script itself, and the screen: nothing a tile at a time)
    assert client._work == 2001 * rfb.RECTANGLE_WORK  # each one a rectangle's worth, as the one pixel after them
    # ...so that a flood of them is refused like any other: 40,000 in a second is more work than a small screen's second holds.
    flood = screen(64, 64) + update_message([rectangle_header((0, 0, 0, 64), rfb.HEXTILE)] * 40_000)
    ended = run(served(Client(Scripted(flood), None, clock=frozen())))
    assert ended.code == rfb.LIMIT, ended.message


def test_a_hextile_rectangle_is_charged_by_its_tiles_however_thin() -> None:
    # One pixel wide and a screen tall: 68 tiles of a byte each, drawn tile by tile, and counted as the 1,080 pixels they
    # cover. 2,000 of them in a second were within the limit of a 1080p screen, and took seconds of CPU.
    thin = rectangle_header((0, 0, 1, 1080), rfb.HEXTILE) + bytes(68)
    script = screen(1920, 1080) + update_message([thin] * 2000)
    client = Client(Scripted(script), None, clock=frozen())
    client.drawing = False  # (what is counted is the point here, not the drawing)
    ended = run(served(client))
    assert ended.code == rfb.LIMIT and "pixels" in ended.message, ended.message
    # 68 tiles of a full tile's work each: refused once a 1080p screen's second of work (16 screens of it) is used up.
    assert client._work <= 16 * 1920 * 1080 + 68 * rfb.TILE_WORK


def test_hextile_tiles_count_against_the_rectangles_a_second() -> None:
    # Each tile is taken apart on the event loop, as each rectangle is: a screen of them counts as rectangles too (eight
    # tiles to one, as they cost to read), not as one. Twelve screens of 4096 by 2048 in tiles of a byte are within a second's
    # rectangles; thirteen are not, though within the second's pixels.
    width, height = 4096, 2048
    tiles = (width // 16) * (height // 16)
    whole = rectangle_header((0, 0, width, height), rfb.HEXTILE) + bytes([2]) + b"\1\2\3\0" + bytes(tiles - 1)

    def counted(screens: int) -> RfbError:
        updates = b"".join(update_message([whole] * min(4, screens - at)) for at in range(0, screens, 4))
        client = Client(Scripted(screen(width, height) + updates), None, clock=frozen())
        client.drawing = False
        return run(served(client))

    assert counted(12).code == rfb.CLOSED
    ended = counted(13)
    assert ended.code == rfb.LIMIT and "far more" in ended.message, ended.message


# --- the event loop is let go of ----------------------------------------------------------------------------------


def ticked_while(client: Client) -> tuple[RfbError, int]:
    """Serve `client` to its end, with a task beside it that counts the times it got the loop."""
    ticks = [0]

    async def go() -> RfbError:
        async def ticker() -> None:
            while True:
                ticks[0] += 1
                await asyncio.sleep(0)

        await client.handshake()
        counting = asyncio.create_task(ticker())
        await asyncio.sleep(0)
        ticks[0] = 0
        try:
            await client.serve()
        except RfbError as ex:
            return ex
        finally:
            counting.cancel()
        raise AssertionError("it did not end")

    return run(go()), ticks[0]


def colour_map(count: int) -> bytes:
    return struct.pack(">BxHH", rfb.COLOUR_MAP, 0, count) + bytes(6 * count)


@pytest.mark.parametrize(
    "what",
    ["rectangles", "hextile rows", "raw rows", "a colour map", "a clipboard", "bells"],
)
def test_no_loop_over_what_a_server_says_holds_the_event_loop(what: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # Every byte here is in the buffer already, so reading it never waits, and nothing else on the loop ran until the whole
    # of it was read: a message of 65,535 rectangles, or of rows of Hextile tiles, held every other tile, every page and
    # every live line for as long as it took. Let go of every so often (here: at every chance).
    monkeypatch.setattr(rfb, "BREATHE", 0.0, raising=False)
    width, height = 1920, 1080
    if what == "rectangles":
        script, least = update_message([rectangle_header((0, 0, 1, 1), rfb.COPY_RECT) + bytes(4)] * 40_000), 40_000
    elif what == "hextile rows":
        script, least = update_message([rectangle_header((0, 0, 1920, 1024), rfb.HEXTILE) + bytes([2]) + b"\1\2\3\0" + bytes(120 * 64 - 1)]), 64
    elif what == "raw rows":
        script, least = update_message([rectangle_header((0, 0, 1024, 1024), rfb.RAW) + bytes(4 * 1024 * 1024)]), 64
    elif what == "a colour map":
        script, least = colour_map(65535), 6
    elif what == "a clipboard":
        script, least = struct.pack(">B3xI", rfb.SERVER_CUT_TEXT, rfb.MOST_CUT_TEXT) + bytes(rfb.MOST_CUT_TEXT), 16
    else:
        script, least = bytes([rfb.BELL]) * 1500, 1500
    client = Client(Scripted(screen(width, height) + script), None, clock=frozen())
    client.drawing = False
    ended, ticks = ticked_while(client)
    assert ended.code == rfb.CLOSED, ended.message
    assert ticks >= least, (ticks, least)


def test_with_its_own_pace_the_loop_is_let_go_of_in_a_long_message() -> None:
    # The same, at the pace the reader keeps by itself: a few milliseconds at a time, however fast the machine.
    script = screen(1920, 1080) + update_message([rectangle_header((0, 0, 1, 1), rfb.COPY_RECT) + bytes(4)] * 40_000)
    client = Client(Scripted(script), None, clock=frozen())
    client.drawing = False
    ended, ticks = ticked_while(client)
    assert ended.code == rfb.CLOSED and ticks >= 5, (ended.message, ticks)


# --- the drawing threads: each server its share, a slice at a time --------------------------------------------------


class Timed(ThreadPoolExecutor):
    """A pool of two drawing threads that notes how long each piece of work it was given took (`took`, by the clock, as
    the program counts it), and how much of a core it took (`worked`: the thread's own time, which a busy computer's
    other threads and processes do not add to)."""

    def __init__(self) -> None:
        super().__init__(max_workers=2, thread_name_prefix="rfb-timed")
        self.took: list[float] = []
        self.worked: list[float] = []
        self._lock = threading.Lock()

    def submit(self, fn: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Any:
        def timed() -> Any:
            began, working = time.perf_counter(), time.thread_time()
            try:
                return fn(*args, **kwargs)
            finally:
                with self._lock:
                    self.took.append(time.perf_counter() - began)
                    self.worked.append(time.thread_time() - working)

        return super().submit(timed)


def tight_gradient(width: int, height: int, count: int) -> bytes:
    """`count` updates of one Tight rectangle through the gradient filter: a few kilobytes each, a sample at a time to undo."""
    plain = bytes(3 * width * height)
    packer = zlib.compressobj()
    updates = []
    for _ in range(count):
        data = packer.compress(plain) + packer.flush(zlib.Z_SYNC_FLUSH)
        updates.append(update_message([rectangle_header((0, 0, width, height), rfb.TIGHT) + bytes([0x40, 2]) + fake_vnc.compact_length(len(data)) + data]))
    return b"".join(updates)


def zrle_runs(width: int, height: int, count: int) -> bytes:
    """ZRLE tiles of plain runs one pixel long: four bytes a pixel before zlib, a few kilobytes after, a run at a time to draw."""
    tiles = b"".join(
        b"\x80" + b"\x10\x20\x30\x00" * (min(64, width - left) * min(64, height - top)) for top in range(0, height, 64) for left in range(0, width, 64)
    )
    stream = fake_vnc.ZrleStream()
    return b"".join(update_message([rectangle_header((0, 0, width, height), rfb.ZRLE) + stream.rectangle(tiles)]) for _ in range(count))


def hextile_subrectangles(width: int, height: int, count: int) -> bytes:
    """Hextile tiles of 255 subrectangles of one pixel each: two bytes on the wire, a fill to draw. (A megabyte a screen: six
    of them at the most, more than a thread draws in the time a test looks.)"""
    tile = bytes([2 | 4 | 8]) + b"\1\2\3\0" + b"\4\5\6\0" + bytes([255]) + b"\x00\x00" * 255
    rect = rectangle_header((0, 0, width, height), rfb.HEXTILE) + tile * ((width // 16) * (height // 16))
    return update_message([rect]) * min(count, 6)


def small_jpegs(width: int, height: int, count: int) -> bytes:
    """Tight JPEGs of a tile each: some hundred bytes, and a decoder and its colour conversion made for each."""
    picture = fake_vnc.jpeg_of(fake_vnc.known_picture(16, 16, 3), 16, 16, 8)
    rect = bytes([0x90]) + fake_vnc.compact_length(len(picture)) + picture
    rects = [rectangle_header(((i % (width // 16)) * 16, (i // (width // 16)) % (height // 16) * 16, 16, 16), rfb.TIGHT) + rect for i in range(500)]
    return update_message(rects) * count


COSTLY = {"tight gradient": tight_gradient, "zrle runs": zrle_runs, "hextile subrectangles": hextile_subrectangles, "small jpegs": small_jpegs}


@pytest.mark.parametrize("kind", sorted(COSTLY))
def test_a_server_whose_pictures_cost_much_to_draw_gets_its_share_of_the_drawing_threads_and_no_more(kind: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # Kilobytes that cost a drawing thread a second each: one such server kept a thread busy for as long as it sent them,
    # three kept both, and every other tile's picture waited behind them. Held to its share of the threads' time, a
    # slice at a time, whatever the bytes are and however fast the machine is. (JPEGs are decoded and drawn in their
    # server's own thread since round 3, in no drawing thread: there, what the share holds is what its worker works.)
    monkeypatch.setattr(rfb, "DRAWING_SHARE", 0.2, raising=False)
    monkeypatch.setattr(rfb, "DRAWING_BURST", 0.1, raising=False)
    pool = Timed()
    monkeypatch.setattr(rfb, "_DRAWERS", pool)
    width, height = 1024, 512  # (on a screen four times as large: the limit of pixels a second is not what is tried here)
    client = Client(Scripted(screen(2 * width, 2 * height) + COSTLY[kind](width, height, 40)), None)
    window = 2.0
    went: list[float] = []

    async def go() -> None:
        await client.handshake()
        if kind == "small jpegs":
            # Measure steady-state drawing, not the one-time OS sandbox launch.
            # Startup has its own deadline; drawing share is unchanged afterward.
            sample = fake_vnc.jpeg_of(fake_vnc.known_picture(16, 16, 3), 16, 16, 8)
            await asyncio.to_thread(rfb.decode_jpeg, sample, 16, 16, client._video_decoder)
        began, (_, used) = time.monotonic(), client._video_decoder.cpu_seconds()
        serving = asyncio.create_task(client.serve())
        await asyncio.sleep(window)
        assert not serving.done(), serving.exception()  # (still at it: what it sends is no error, only costly)
        serving.cancel()
        await asyncio.gather(serving, return_exceptions=True)
        went.append(time.monotonic() - began)
        if kind == "small jpegs":
            _, used_now = client._video_decoder.cpu_seconds()
            assert used is not None and used_now is not None
            worked.append(used_now - used)

    worked: list[float] = []
    try:
        run(go())
    finally:
        pool.shutdown(wait=True)
        if kind == "small jpegs":
            run(client.close())
    if kind == "small jpegs":
        assert worked[0] > 0, "nothing was decoded"
        assert worked[0] <= 0.2 * went[0] + 0.1 + 0.25, (worked[0], went[0])
        return
    assert pool.took, "nothing was drawn"
    # (Against the time that went by, not the window asked for: on a busy machine the event loop wakes late, and the
    # share grows with every second the server was served, as the program counts it.)
    assert sum(pool.took) <= 0.2 * went[0] + 0.1 + 0.25, (sum(pool.took), len(pool.took), went[0])
    # (A slice at a time: no single piece of work holds a thread for long. Counted in the thread's own time: by the clock, a
    # piece on a busy computer took 0.266 s, the thread waiting for a core most of it.)
    assert max(pool.worked) < 0.25, (max(pool.worked), max(pool.took))


def test_a_server_that_costs_little_is_drawn_at_once_while_three_others_cost_the_threads_all_they_have(monkeypatch: pytest.MonkeyPatch) -> None:
    # Three servers sending gradients (a second of a thread's time each, from a few kilobytes) and a fourth sending small
    # pictures: the fourth's waited behind theirs, a second and more each, for as long as they sent; and the two threads,
    # drawing in Python, which runs one thread at a time, left the event loop a quarter of the time or less.
    monkeypatch.setattr(rfb, "_ALL", [getattr(rfb, "DRAWING_BURST", 0.0), 0.0], raising=False)  # (what tests before took counts for nothing here)
    pool = Timed()
    monkeypatch.setattr(rfb, "_DRAWERS", pool)
    width, height = 1024, 512
    costly = [Client(Scripted(screen(2 * width, 2 * height) + tight_gradient(width, height, 40)), None) for _ in range(3)]
    small = fake_vnc.TightStreams()
    picture = fake_vnc.known_picture(64, 64, 5)
    cheap = Client(Scripted(screen(64, 64) + b"".join(update_message([rectangle_header((0, 0, 64, 64), rfb.TIGHT) + small.basic(picture, 0, None)]) for _ in range(20))), None)

    async def go() -> tuple[float, float]:
        for client in (*costly, cheap):
            await client.handshake()
        started = time.monotonic()
        busy = [asyncio.create_task(client.serve()) for client in costly]
        await asyncio.sleep(0.3)  # (all three at it)
        began = time.monotonic()
        try:
            async with asyncio.timeout(30):
                ended = await served_from(cheap)
        finally:
            for task in busy:
                task.cancel()
            await asyncio.gather(*busy, return_exceptions=True)
        assert ended.code == rfb.CLOSED and cheap.frames == 20, ended.message
        return time.monotonic() - began, time.monotonic() - started

    try:
        took, lasted = run(go())
    finally:
        pool.shutdown(wait=True)
    assert took < 5.0, took
    # ...and every server together had the threads for the share of all of them, however many there are.
    assert sum(pool.took) <= rfb.DRAWING_ALL * lasted + rfb.DRAWING_BURST + 0.25, (sum(pool.took), lasted)


def test_one_long_step_of_a_costly_server_does_not_hold_up_every_other_server(monkeypatch: pytest.MonkeyPatch) -> None:
    # A JPEG of a whole large screen is decoded in one call: a slice of a few milliseconds that takes tens of them, charged in
    # full to its server and to everybody's share. Another server's pictures are drawn all the same, between such steps.
    # (Charged to everybody's share as a few slices only, the costly servers drew more, and the cheap one waited behind
    # their steps four times as long: measured with three of them. Since 0.2.1 everybody's share is charged a step up to
    # STEP_ALLOWANCE past the slice, a tenth of a second, which these steps of tens of milliseconds are within; a step of
    # seconds, a picture waited for in its server's video worker, is its server's alone: see
    # test_a_picture_that_takes_seconds_to_draw_holds_up_its_own_server_and_no_other.)
    monkeypatch.setattr(rfb, "_ALL", [getattr(rfb, "DRAWING_BURST", 0.0), 0.0], raising=False)
    width, height = 2048, 7800
    picture = fake_vnc.jpeg_of(bytes(3 * width * height), width, height, 8)
    large = update_message([rectangle_header((0, 0, width, height), rfb.TIGHT) + bytes([0x90]) + fake_vnc.compact_length(len(picture)) + picture])
    costly = Client(Scripted(screen(width, height) + large * 40), None)
    small = fake_vnc.TightStreams()
    cheap_picture = fake_vnc.known_picture(64, 64, 5)
    cheap = Client(Scripted(screen(64, 64) + b"".join(update_message([rectangle_header((0, 0, 64, 64), rfb.TIGHT) + small.basic(cheap_picture, 0, None)]) for _ in range(20))), None)

    async def go() -> float:
        for client in (costly, cheap):
            await client.handshake()
        busy = asyncio.create_task(costly.serve())
        await asyncio.sleep(1.5)  # (its burst used up: from here on it draws a large JPEG now and then, at its share)
        began = time.monotonic()
        try:
            async with asyncio.timeout(30):
                ended = await served_from(cheap)
            took = time.monotonic() - began
        finally:
            busy.cancel()
            await asyncio.gather(busy, return_exceptions=True)
            await costly.close()
            await cheap.close()
        assert ended.code == rfb.CLOSED and cheap.frames == 20, ended.message
        assert costly.frames >= 2  # (it was drawn, as often as its share lets it)
        return took

    # Canceling an asyncio future cannot stop an already running drawing thread.
    # Own and drain this test's pool so its large JPEG cannot be allocated during
    # the next test's process-wide memory measurement.
    with ThreadPoolExecutor(max_workers=2) as pool:
        monkeypatch.setattr(rfb, "_DRAWERS", pool)
        assert run(go()) < 3.0


def test_a_copy_and_a_change_of_size_of_a_large_screen_are_drawn_in_steps(monkeypatch: pytest.MonkeyPatch) -> None:
    # Each was one step: 77 ms and 35 ms of a drawing thread over a screen of 16 million pixels (a reviewer's measure),
    # during which every other server's next slice waited.
    client = Client(Scripted(b""), None)
    client._fit(4096, 3900)
    copy = (rfb.COPY_RECT, 0, 1, 4096, 3899, struct.pack(">HH", 0, 0))
    assert sum(1 for _ in client._drawing([copy])) >= 3899 * 4096 // rfb.STEP_PIXELS
    assert sum(1 for _ in client._fitting(3900, 4096)) >= 3900 * 3900 // rfb.STEP_PIXELS
    assert (client.width, client.height) == (3900, 4096)
    # ...and a copy onto itself, moved down, up, left or right, comes out as it would in one go, a few rows a step.
    monkeypatch.setattr(rfb, "STEP_PIXELS", 3 * 40)
    width, height = 40, 30
    picture = fake_vnc.known_picture(width, height, 9)
    for source, target in (((0, 0), (0, 7)), ((0, 7), (0, 0)), ((0, 2), (3, 2)), ((3, 2), (0, 2)), ((1, 1), (4, 6)), ((4, 6), (1, 1))):
        client = Client(Scripted(b""), None)
        client._fit(width, height)
        client.rgb[:] = picture
        w, h = width - 4, height - 7
        expected = bytearray(picture)
        moved = fake_vnc.crop(picture, width, (*source, w, h))
        for r in range(h):
            at = 3 * ((target[1] + r) * width + target[0])
            expected[at : at + 3 * w] = moved[3 * w * r : 3 * w * (r + 1)]
        steps = sum(1 for _ in client._drawing([(rfb.COPY_RECT, *target, w, h, struct.pack(">HH", *source))]))
        assert steps >= h // 3 and bytes(client.rgb) == bytes(expected), (source, target, steps)


async def served_from(client: Client) -> RfbError:
    try:
        await client.serve()
    except RfbError as ex:
        return ex
    raise AssertionError("it did not end")


def test_an_expensive_first_drawing_slice_is_paid_before_more_work(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    clock = [1.0]
    calls: list[float] = []
    waits: list[float] = []
    monkeypatch.setattr(rfb, "time", SimpleNamespace(monotonic=lambda: clock[0], perf_counter=time.perf_counter))
    monkeypatch.setattr(rfb, "DRAWING_SHARE", 0.2)
    monkeypatch.setattr(rfb, "DRAWING_BURST", 0.1)
    monkeypatch.setattr(rfb, "DRAWING_ALL", 10.0)
    monkeypatch.setattr(rfb, "_ALL", [0.1, clock[0]])

    async def sleep(seconds: float) -> None:
        waits.append(seconds)
        clock[0] += seconds

    client = Client(Scripted(b""), None)
    monkeypatch.setattr(rfb, "asyncio", SimpleNamespace(get_running_loop=asyncio.get_running_loop, sleep=sleep))

    def advance(steps: object, most: float) -> tuple[bool, float, float]:  # (by the clock, and the thread's own work)
        calls.append(clock[0])
        return (False, 0.8, 0.8) if len(calls) == 1 else (True, 0.01, 0.01)

    monkeypatch.setattr(rfb, "_advance", advance)
    run(client._drawn(iter(())))
    assert len(calls) == 2 and waits
    assert calls[1] - calls[0] == pytest.approx((0.8 - 0.1) / 0.2)


# --- a step that takes seconds: its own server's, not every server's -------------------------------------------------


class Paced(Scripted):
    """A scripted server that sends its updates one at a time, `every` seconds apart, as a screen that changes does."""

    def __init__(self, handshake: bytes, updates: list[bytes], every: float) -> None:
        super().__init__(handshake)
        self.updates, self.every = list(updates), every
        self.due: float | None = None

    async def read(self, size: int, within: float | None) -> bytes:
        while len(self.incoming) < size and self.updates:
            if self.due is not None:
                await asyncio.sleep(max(0.0, self.due - time.monotonic()))
            self.incoming += self.updates.pop(0)
            self.due = time.monotonic() + self.every
        return await super().read(size, within)


def jpeg_updates(width: int, height: int, count: int) -> bytes:
    """`count` updates of one Tight JPEG over the whole of a `width` by `height` screen."""
    picture = fake_vnc.jpeg_of(fake_vnc.known_picture(width, height, 4), width, height, 8)
    return update_message([rectangle_header((0, 0, width, height), rfb.TIGHT) + bytes([0x90]) + fake_vnc.compact_length(len(picture)) + picture]) * count


def slow_pictures(monkeypatch: pytest.MonkeyPatch, seconds: float, starting: float = 0.0) -> list[float]:
    """Every JPEG takes `seconds` in its video worker, as one with tens of thousands of scans does (a few kilobytes that
    decode for up to video.WORK_WITHIN); `starting` of them, first, are its session starting a worker. The list says when
    each began."""
    from qkvm import video

    began: list[float] = []

    def decode(data: bytes, width: int, height: int, session: Any = None) -> bytes:
        began.append(time.monotonic())
        if starting:
            session.starting += starting
        time.sleep(seconds)
        # (What the worker worked by the system's count, starting it aside: this stand-in has no worker, and waits instead.)
        session.stand_in_work = getattr(session, "stand_in_work", 0.0) + seconds - starting
        return bytes(3 * width * height)

    monkeypatch.setattr(video, "decode_jpeg", decode)
    # ...as the session tells it (VideoSession.cpu_seconds: its worker, and what that worker has used so far).
    monkeypatch.setattr(video.VideoSession, "cpu_seconds", lambda session: (session, getattr(session, "stand_in_work", 0.0)), raising=False)
    return began


def lock_holder(seconds: float) -> Callable[[], None]:
    """A call that holds Python's lock for about `seconds` without a break (a builtin's long loop), as a long collection
    of garbage does: no other thread of the program runs meanwhile."""
    n, took = 1 << 20, 0.0
    while took < 0.05:
        n *= 2
        began = time.perf_counter()
        sum(range(n))
        took = time.perf_counter() - began
    count = int(n * seconds / took)

    def hold() -> None:
        sum(range(count))

    return hold


def test_a_picture_that_takes_seconds_to_draw_holds_up_its_own_server_and_no_other(monkeypatch: pytest.MonkeyPatch) -> None:
    # A hostile server's Tight JPEG decoded for seconds in its video worker, waited for in a drawing thread, and all of that
    # wait was charged to every server's share of the drawing threads: when it came back, every VNC, AMT, Proxmox and
    # OpenBMC screen waited for (seconds - DRAWING_BURST) / DRAWING_ALL, again at each such picture (a probe: 19.5 s of 40
    # without a frame of an ordinary server beside one such). Charged to its own server only, two such servers still held
    # both drawing threads at once (a probe: 8.8 s of 40). Its own server pays for it and waits for it; the others go on
    # being drawn.
    monkeypatch.setattr(rfb, "_ALL", [rfb.DRAWING_BURST, 0.0])
    slow_pictures(monkeypatch, 2.5)
    hostiles = [Client(Scripted(screen(256, 256) + jpeg_updates(256, 256, 3)), None) for _ in range(2)]
    small = fake_vnc.TightStreams()
    picture = fake_vnc.known_picture(64, 64, 5)
    ordinary = Client(Paced(screen(64, 64), [update_message([rectangle_header((0, 0, 64, 64), rfb.TIGHT) + small.basic(picture, 0, None)]) for _ in range(150)], 0.04), None)
    drawn: list[float] = []

    async def go() -> None:
        for client in (*hostiles, ordinary):
            await client.handshake()
        serving = [asyncio.create_task(client.serve()) for client in (ordinary, *hostiles)]
        began, seen = time.monotonic(), 0
        try:
            while time.monotonic() - began < 5.5:
                await asyncio.sleep(0.005)
                if ordinary.frames != seen:
                    seen = ordinary.frames
                    drawn.append(time.monotonic())
            # (They are drawn, at their servers' share.)
            assert all(hostile.frames >= 1 for hostile in hostiles), "the slow pictures were not drawn at all"
        finally:
            for task in serving:
                task.cancel()
            await asyncio.gather(*serving, return_exceptions=True)
            for client in (*hostiles, ordinary):
                await client.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        monkeypatch.setattr(rfb, "_DRAWERS", pool)
        run(go())
    gaps = [later - earlier for earlier, later in itertools.pairwise(drawn)]
    assert len(drawn) > 50 and max(gaps) < 0.5, (len(drawn), max(gaps, default=None))


def test_everybodys_share_is_charged_a_long_step_up_to_an_allowance_and_its_server_in_full(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    clock = [1.0]
    monkeypatch.setattr(rfb, "time", SimpleNamespace(monotonic=lambda: clock[0], perf_counter=time.perf_counter))
    monkeypatch.setattr(rfb, "_ALL", [rfb.DRAWING_BURST, clock[0]])
    client = Client(Scripted(b""), None)
    client._credit, client._credit_at = rfb.DRAWING_BURST, clock[0]
    monkeypatch.setattr(rfb, "_advance", lambda steps, most: (True, 3.0, 3.0))
    run(client._drawn(iter(())))
    assert client._credit == pytest.approx(rfb.DRAWING_BURST - 3.0)
    assert rfb._ALL[0] == pytest.approx(rfb.DRAWING_BURST - rfb.DRAWING_SLICE - rfb.STEP_ALLOWANCE)


class Counting(ThreadPoolExecutor):
    """A server's own thread for its pictures that counts what is handed to it (a hop each)."""

    def __init__(self) -> None:
        super().__init__(max_workers=1, thread_name_prefix="rfb-jpeg")
        self.hops = 0

    def submit(self, fn: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Any:
        self.hops += 1
        return super().submit(fn, *args, **kwargs)


def test_a_server_of_many_pictures_takes_a_turn_and_a_hop_a_batch_not_a_picture(monkeypatch: pytest.MonkeyPatch) -> None:
    # Each Tight JPEG took a turn of its own in the line for every server's share, a hop of its own to the server's own
    # thread, and a slice's place in line, though it decodes in a millisecond or two; and every picture waited for a
    # drawing of what came before it where others waited. A 4K desktop's 128 pictures a refresh were some 150 turns where
    # 0.2.0 had some 28 slices: beside other servers it was drawn two to four times less often than on 0.2.0 (the round 2
    # review's harness). A batch's pictures go to the server's own thread in one hop, at one turn: turns and hops a batch,
    # not a picture, whatever this machine's speed.
    monkeypatch.setattr(rfb, "_ALL", [rfb.DRAWING_BURST, time.monotonic()])
    slow_pictures(monkeypatch, 0.0)  # (a picture is no work here: what is counted is the turns and the hops)
    pictures, updates = 64, 6
    jpeg = [fake_vnc.jpeg_of(fake_vnc.known_picture(64, 64, k), 64, 64, 8) for k in range(4)]
    update = update_message(
        [rectangle_header(((i % 8) * 64, (i // 8) * 64, 64, 64), rfb.TIGHT) + bytes([0x90]) + fake_vnc.compact_length(len(jpeg[i % 4])) + jpeg[i % 4] for i in range(pictures)]
    )
    assert pictures * max(map(len, jpeg)) < rfb.BATCH_BYTES  # (the pictures of an update are one batch)
    desktop = Client(Scripted(screen(512, 512) + update * updates), None)
    desktop._decoding = lane = Counting()
    small = fake_vnc.TightStreams()
    picture = fake_vnc.known_picture(64, 64, 5)
    others = [Client(Paced(screen(64, 64), [update_message([rectangle_header((0, 0, 64, 64), rfb.TIGHT) + small.basic(picture, 0, None)])] * 400, 0.005), None) for _ in range(3)]
    turns: dict[str, int] = {}
    real_turn = Client._turn

    async def counted_turn(self: Client, taking: float) -> bool:
        if self is desktop:
            caller = sys._getframe(1).f_code.co_name  # (_drawn: a slice of drawing; _breathe: reading; else: for its pictures)
            turns[caller] = turns.get(caller, 0) + 1
        return await real_turn(self, taking)

    monkeypatch.setattr(Client, "_turn", counted_turn)

    async def go() -> RfbError:
        for client in (desktop, *others):
            await client.handshake()
        beside = [asyncio.create_task(client.serve()) for client in others]  # (the line is not empty: others are at it)
        try:
            async with asyncio.timeout(30):
                return await served_from(desktop)
        finally:
            for task in beside:
                task.cancel()
            await asyncio.gather(*beside, return_exceptions=True)
            await desktop.close()

    ended = run(go())
    assert ended.code == rfb.CLOSED and desktop.frames == updates, ended.message
    for_pictures = sum(count for caller, count in turns.items() if caller not in ("_drawn", "_breathe"))
    assert lane.hops <= updates and for_pictures <= updates, (lane.hops, turns)


def test_a_server_waits_for_its_pictures_within_its_own_share(monkeypatch: pytest.MonkeyPatch) -> None:
    # Out of the drawing threads, the waits for a server's video worker are held to its share all the same: JPEGs that
    # take a tenth of a second each, one after another, take a fifth of the time that goes by, and no more.
    monkeypatch.setattr(rfb, "DRAWING_SHARE", 0.2)
    monkeypatch.setattr(rfb, "DRAWING_BURST", 0.1)
    began = slow_pictures(monkeypatch, 0.1)
    client = Client(Scripted(screen(64, 64) + jpeg_updates(64, 64, 100)), None)
    client._credit = 0.1
    went: list[float] = []

    async def go() -> None:
        await client.handshake()
        start = time.monotonic()
        serving = asyncio.create_task(client.serve())
        await asyncio.sleep(2.5)
        assert not serving.done(), serving.exception()
        serving.cancel()
        await asyncio.gather(serving, return_exceptions=True)
        went.append(time.monotonic() - start)
        await client.close()

    run(go())
    assert began, "nothing was decoded"
    assert 0.1 * len(began) <= 0.2 * went[0] + 0.1 + 0.25, (len(began), went[0])


def test_a_long_step_is_two_seconds_of_work() -> None:
    # The coordinator's point after the round 5 review: a 5K screen's whole-screen ZRLE inflate is a step of 156 ms on the
    # PC these tests were written on, and a Raspberry Pi class host is 5 to 10 times slower: a server that is well came near
    # a second a step there, and more than MOST_LONG_STEPS of those within LONG_STEPS_WITHIN refused it. Two seconds.
    assert rfb.LONG_STEP == 2.0


def test_a_server_whose_pictures_keep_taking_too_long_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    # Held to its own share, such a server still held a drawing thread for seconds at a time, for as long as it was
    # connected: after MOST_LONG_STEPS of them within LONG_STEPS_WITHIN, the next ends its connection, as anything else
    # it has no reason to send does (and the device leaves it alone for a while, longer each time).
    monkeypatch.setattr(rfb, "LONG_STEP", 0.2, raising=False)
    slow_pictures(monkeypatch, 0.25)
    client = Client(Scripted(screen(64, 64) + jpeg_updates(64, 64, 10)), None)
    ended = run(served(client))
    assert ended.code == rfb.LIMIT and "too long" in ended.message, ended.message
    assert client.frames == rfb.MOST_LONG_STEPS


def test_starting_a_video_worker_is_no_picture_that_takes_too_long(monkeypatch: pytest.MonkeyPatch) -> None:
    # The first JPEG of a session starts its worker (3.4 s on a Windows PC, its sandbox made), and so does the next after
    # a worker died: that is not the server's picture taking long.
    monkeypatch.setattr(rfb, "LONG_STEP", 0.2, raising=False)
    monkeypatch.setattr(rfb, "MOST_LONG_STEPS", 0, raising=False)
    slow_pictures(monkeypatch, 0.25, starting=0.24)
    client = Client(Scripted(screen(64, 64) + jpeg_updates(64, 64, 3)), None)
    ended = run(served(client))
    assert ended.code == rfb.CLOSED and client.frames == 3, ended.message


def test_the_programs_own_stalls_are_not_taken_for_pictures_that_take_long(monkeypatch: pytest.MonkeyPatch) -> None:
    # A picture's time was measured on the event loop, from handing it on to taking it back, so it held whatever else kept
    # the loop meanwhile (probe p4b: pictures of 0.2 s, the loop held 1.2 s five times by something else: the server was
    # refused as one whose pictures take far too long, though none took more than 0.201 s; a paused VM, a starved
    # container or a long collection of garbage does that, and a refused server is held off 15 s, doubling to 240 s).
    # Timed in the thread that waits for it, as a slice of drawing is.
    monkeypatch.setattr(rfb, "DRAWING_SHARE", 1.0)  # (a server alone on a quiet wall: its shares are not in the way)
    monkeypatch.setattr(rfb, "DRAWING_ALL", 1.0)
    monkeypatch.setattr(rfb, "_ALL", [rfb.DRAWING_BURST, time.monotonic()])
    monkeypatch.setattr(rfb, "LONG_STEP", 0.5)
    slow_pictures(monkeypatch, 0.2)
    client = Client(Scripted(screen(64, 64) + jpeg_updates(64, 64, 500)), None)

    def stall() -> None:  # (the loop held by something else, while a picture is being decoded)
        time.sleep(0.7)

    async def go() -> None:
        await client.handshake()
        serving = asyncio.create_task(client.serve())
        try:
            for _ in range(rfb.MOST_LONG_STEPS + 2):
                await asyncio.sleep(0.3)
                stall()
            await asyncio.sleep(0.3)
            assert not serving.done(), serving.exception()
        finally:
            serving.cancel()
            await asyncio.gather(serving, return_exceptions=True)
            await client.close()

    run(go())
    assert client.frames > 0 and not client._long_steps, (client.frames, client._long_steps)


def test_a_stall_that_holds_pythons_lock_is_not_taken_for_pictures_that_take_long(monkeypatch: pytest.MonkeyPatch) -> None:
    # The test above stalls the loop with a sleep, which lets the thread that waits for the picture run on. A stall that
    # holds Python's lock (a long collection of garbage, a builtin's long loop) kept that thread from taking the time the
    # picture ended until the stall was over: the server was refused, its pictures of 0.2 s taken for 0.7 s ones (probe
    # p4c). A picture is the work its worker did, by the system's count of the worker's time.
    monkeypatch.setattr(rfb, "DRAWING_SHARE", 1.0)
    monkeypatch.setattr(rfb, "DRAWING_ALL", 1.0)
    monkeypatch.setattr(rfb, "_ALL", [rfb.DRAWING_BURST, time.monotonic()])
    monkeypatch.setattr(rfb, "LONG_STEP", 0.5)
    slow_pictures(monkeypatch, 0.2)
    stall = lock_holder(0.7)
    client = Client(Scripted(screen(64, 64) + jpeg_updates(64, 64, 500)), None)

    async def go() -> None:
        await client.handshake()
        serving = asyncio.create_task(client.serve())
        try:
            for _ in range(rfb.MOST_LONG_STEPS + 2):
                await asyncio.sleep(0.3)
                stall()
            await asyncio.sleep(0.3)
            assert not serving.done(), serving.exception()
        finally:
            serving.cancel()
            await asyncio.gather(serving, return_exceptions=True)
            await client.close()

    run(go())
    assert client.frames > 0 and not client._long_steps, (client.frames, client._long_steps)


def test_a_slice_of_drawing_is_the_work_its_thread_did_not_the_time_it_waited_for_pythons_lock() -> None:
    # A slice was timed by the clock in its drawing thread, from its start to its end: a stall that held Python's lock
    # meanwhile (the event loop's, a collection of garbage) was in it, and counted towards LONG_STEP. What LONG_STEP counts
    # is the work the thread did, its own time; the shares are charged by the clock still (see rfb._advance).
    stall = lock_holder(0.6)
    started = threading.Event()

    def steps() -> Iterator[None]:
        started.set()
        for _ in range(50):
            sum(range(500_000))  # (some milliseconds a step, a few hundred in all: the stall falls among them)
            yield

    out: list[tuple[bool, float, float]] = []
    drawing = threading.Thread(target=lambda: out.append(rfb._advance(steps(), 5.0)))
    began = time.perf_counter()
    drawing.start()
    started.wait(5)
    stall()  # (Python's lock held here, the drawing thread waiting for it)
    drawing.join(10)
    went = time.perf_counter() - began
    (done, took, worked) = out[0]
    # (The stall is in the clock, what the shares are charged, and not in the work, what LONG_STEP counts.)
    assert done and went >= 0.5 and took - worked >= 0.4, (done, round(went, 3), round(took, 3), round(worked, 3))


def test_a_picture_that_came_while_nobody_looked_is_never_decoded_in_the_drawing_threads(monkeypatch: pytest.MonkeyPatch) -> None:
    # Whether a JPEG went to its server's own thread was decided when it came; one gathered while nobody looked, and drawn
    # after somebody began to look (the pacer sets `drawing` at any moment), was decoded in a drawing thread every server
    # shares (probe p1: three of them, all in rfb_0), each holding it up to video.WORK_WITHIN. Never decoded there: since
    # round 3 a batch's pictures are decoded when it is drawn, in the server's own thread, where somebody looks then; and
    # one drawn without its picture (nobody looked when its batch was decoded) marks the screen stale, and the next request
    # asks for all of it.
    where: list[str] = []
    from qkvm import video

    def decode(data: bytes, width: int, height: int, session: Any = None) -> bytes:
        where.append(threading.current_thread().name)
        time.sleep(0.3)  # (a JPEG of tens of thousands of scans takes up to video.WORK_WITHIN)
        return bytes(3 * width * height)

    monkeypatch.setattr(video, "decode_jpeg", decode)
    picture = fake_vnc.jpeg_of(fake_vnc.known_picture(64, 64, 4), 64, 64, 8)
    jpeg = rectangle_header((0, 0, 64, 64), rfb.TIGHT) + bytes([0x90]) + fake_vnc.compact_length(len(picture)) + picture
    fill = rectangle_header((0, 0, 1, 1), rfb.TIGHT) + bytes([0x80]) + b"\x01\x02\x03"
    update = update_message([jpeg] * 3 + [fill])  # (the three come while nobody looks; the fill after somebody begins to)

    class Looked(Scripted):
        """Sends all but the last rectangle at once, and the last once somebody looks, as the pacer has it."""

        def __init__(self, first: bytes, later: bytes) -> None:
            super().__init__(first)
            self.later = later

        async def read(self, size: int, within: float | None) -> bytes:
            if len(self.incoming) < size and self.later:
                await asyncio.sleep(0.05)
                client.drawing = True
                self.incoming += self.later
                self.later = b""
            return await super().read(size, within)

    client = Client(Looked(screen(64, 64) + update[: -len(fill)], update[-len(fill) :]), None)

    async def go() -> RfbError:
        await client.handshake()
        client.drawing = False
        try:
            return await served_from(client)
        finally:
            await client.close()

    ended = run(go())
    assert ended.code == rfb.CLOSED, ended.message
    assert where and not [name for name in where if not name.startswith("rfb-jpeg")], where  # (the server's own thread alone)
    assert client.frames == 1 and bytes(client.rgb[:3]) == b"\x01\x02\x03"
    # ...and one drawn without its picture is not decoded where it is drawn: the screen is stale.
    where.clear()
    still = Client(Scripted(b""), None)
    still._fit(64, 64)
    assert sum(1 for _ in still._drawing([(rfb.TIGHT, 0, 0, 64, 64, bytes([0x90]) + picture)])) >= 1
    assert still.stale and not where


# --- every server together: the wall's share of the program's time, and of its memory ----------------------------------


def stored_zrle(width: int, height: int, rectangles: int = 1, updates: int = 1) -> bytes:
    """`updates` updates of `rectangles` ZRLE rectangles side by side over a screen `width` by `height`, raw tiles, stored
    by zlib and not compressed (one stream for all of them, as a connection has it): as large on the wire as the screen
    is, the largest such an update may be."""
    across = width // rectangles
    packer = zlib.compressobj(0)
    tiles = b"".join(b"\x00" + bytes(3 * min(64, across - left) * min(64, height - top)) for top in range(0, height, 64) for left in range(0, across, 64))
    out = []
    for _ in range(updates):
        parts = []
        for number in range(rectangles):
            data = packer.compress(tiles) + packer.flush(zlib.Z_SYNC_FLUSH)
            parts.append(rectangle_header((number * across, 0, across, height), rfb.ZRLE) + struct.pack(">I", len(data)) + data)
        out.append(update_message(parts))
    return b"".join(out)


def test_a_wait_for_the_network_is_not_charged_as_holding_the_loop_however_short() -> None:
    # Only a read that took a millisecond or more was taken to have let the loop go while it waited for the server; a
    # shorter wait, with the loop idle meanwhile, was charged to the server's share and every server's as time it held the
    # loop (probe p6: 160 of 480 waits of 0.6 to 1 ms charged). On a link of half a gigabit or more most of a reader's
    # waits are that short, and most of the link's time was charged, as if it read all the while. A read that let the
    # loop go is not the reader's while it waited, however short; one that found its bytes there is.
    import queue

    jobs: queue.Queue[tuple[asyncio.AbstractEventLoop, asyncio.Future[None]] | None] = queue.Queue()

    def arrive() -> None:  # (a piece of the server's bytes comes a moment after it is asked for, the loop idle meanwhile)
        while (job := jobs.get()) is not None:
            loop, future = job
            time.sleep(0.0003)
            loop.call_soon_threadsafe(lambda future=future: future.done() or future.set_result(None))

    waited: list[float] = []

    class Link(Scripted):
        async def read(self, size: int, within: float | None) -> bytes:
            if size >= 1024:  # (a piece of a rectangle's pixels)
                future = asyncio.get_running_loop().create_future()
                began = time.perf_counter()
                jobs.put((asyncio.get_running_loop(), future))
                await future
                waited.append(time.perf_counter() - began)
            return await super().read(size, within)

    charged = [0.0]

    class Counted(Client):
        async def _breathe(self) -> None:
            held = self._held_loop + time.perf_counter() - self._since
            if held >= rfb.BREATHE:
                charged[0] += held
            await super()._breathe()

    width = height = 512
    frame = update_message([rectangle_header((0, 0, width, height), rfb.RAW) + bytes(4 * width * height)])
    client = Counted(Link(screen(width, height) + frame * 20), None)
    helper = threading.Thread(target=arrive, daemon=True)
    helper.start()

    async def go() -> RfbError:
        await client.handshake()
        client.drawing = False
        ended = await served_from(client)
        charged[0] += client._held_loop + time.perf_counter() - client._since  # (and what was not charged yet)
        return ended

    try:
        ended = run(go())
    finally:
        jobs.put(None)
        helper.join(5)
    assert ended.code == rfb.CLOSED and client.updates == 20, ended.message
    # (What the reader did itself, taking 64 KB at a time out of a buffer, is a small part of the time it waited.)
    assert len(waited) >= 300 and charged[0] < 0.25 * sum(waited), (round(charged[0], 4), round(sum(waited), 4), len(waited), round(sorted(waited)[len(waited) // 2] * 1e3, 2))


def test_many_servers_each_within_its_limits_take_no_more_than_every_servers_share_of_the_event_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    # Each server was held to its own counts, and the event loop to nothing: four within every limit of their own (forty
    # thousand rectangles a second each) kept the loop busy 98% of the time, and a page's request waited 40 ms behind them
    # (probe p4). Reading what servers send is charged to every server's share with their drawing (DRAWING_ALL): what is
    # left is the rest of the program's, however many servers there are and however fast the machine.
    monkeypatch.setattr(rfb, "_ALL", [0.0, time.monotonic()])
    # (What one server may send in a second is not what is tried here: on a slower machine as much takes more of the loop.)
    monkeypatch.setattr(rfb, "MOST_RECTANGLES_A_SECOND", 10**9)
    monkeypatch.setattr(rfb, "MOST_MESSAGES_A_SECOND", 10**9)
    flood = update_message([rectangle_header((i % 64, 0, 1, 1), rfb.RAW) + b"\x10\x20\x30\x00" for i in range(1000)]) * 400
    clients = [Client(Scripted(screen(1920, 1080) + flood), None) for _ in range(8)]
    window = 3.0
    got = [0.0]

    async def go() -> None:
        for client in clients:
            await client.handshake()
        serving = [asyncio.create_task(client.serve()) for client in clients]
        began = time.monotonic()
        try:
            while time.monotonic() - began < window:
                # The rest of the program: a millisecond of work at a time, as often as it gets the loop.
                start = time.perf_counter()
                while time.perf_counter() - start < 0.001:
                    pass
                got[0] += time.perf_counter() - start
                await asyncio.sleep(0)
            assert not any(task.done() for task in serving), [task.exception() for task in serving if task.done()]
        finally:
            for task in serving:
                task.cancel()
            await asyncio.gather(*serving, return_exceptions=True)

    run(go())
    # (Every server's share is DRAWING_ALL of the time; the rest, a quarter, went to the rest, and a little more where the
    # servers waited. Measured beside the work, not against how fast this machine is.)
    assert got[0] >= 0.6 * (1 - rfb.DRAWING_ALL) * window, got[0]


def test_an_ordinary_server_is_drawn_beside_servers_that_flood_what_is_read(monkeypatch: pytest.MonkeyPatch) -> None:
    # Reading and drawing were charged to every server's share alike, and waited for it by two rules: a reader slept once
    # and read on, the drawing waited until the share was above nought. Servers that only flood what is read kept it just
    # below nought, and another server's drawing seldom got in (probe p8, this test: six servers of one-pixel Raw
    # rectangles, 46,500 a second each, within every limit of their own, beside an ordinary server at 20 updates a second:
    # 12 to 26 of its 120 frames in 6 s, gaps of 3.4 to 4.2 s; 0.2.0, which charged no reading: 92 to 98 frames, gaps of
    # 0.14 to 0.17 s). Every server waits by one rule, and in turn: an ordinary server beside such servers is drawn about
    # as it was before reading was charged. (On this PC six such servers want more than every server's share, four do
    # not; a slower machine needs fewer.)
    monkeypatch.setattr(rfb, "_ALL", [rfb.DRAWING_BURST, time.monotonic()])
    one = update_message([rectangle_header((i % 64, 0, 1, 1), rfb.RAW) + b"\x10\x20\x30\x00" for i in range(1000)])
    flooders = [Client(Paced(screen(1920, 1080), [one] * 400, 0.0215), None) for _ in range(6)]
    small = fake_vnc.TightStreams()
    picture = fake_vnc.known_picture(64, 64, 5)
    pace, window = 0.05, 5.0
    ordinary = Client(Paced(screen(64, 64), [update_message([rectangle_header((0, 0, 64, 64), rfb.TIGHT) + small.basic(picture, 0, None)]) for _ in range(200)], pace), None)
    drawn: list[float] = []

    async def go() -> None:
        for client in (*flooders, ordinary):
            await client.handshake()
        serving = [asyncio.create_task(client.serve()) for client in (ordinary, *flooders)]
        began, seen = time.monotonic(), 0
        try:
            while time.monotonic() - began < window:
                await asyncio.sleep(0.005)
                if ordinary.frames != seen:
                    seen = ordinary.frames
                    drawn.append(time.monotonic() - began)
            assert not any(task.done() for task in serving), [task.exception() for task in serving if task.done()]
        finally:
            for task in serving:
                task.cancel()
            await asyncio.gather(*serving, return_exceptions=True)

    run(go())
    gaps = [later - earlier for earlier, later in itertools.pairwise([0.0, *drawn, window])]
    # (Two fifths at the least: with other jobs beside it on the test machine, as many as 44 to 49 of the 100 were drawn,
    # and a2003ee drew 12 to 26, with gaps of 3 s and more.)
    assert len(drawn) >= 0.4 * window / pace and max(gaps) < 1.0, (len(drawn), round(max(gaps), 2))


def test_a_turn_moves_its_servers_place_by_the_work_it_was_where_that_is_more(monkeypatch: pytest.MonkeyPatch) -> None:
    # By turns alone, a run of JPEGs of some 35 ms of the program was one turn as a slice of 5 is, and moved its server in
    # line as little. A turn moves its server's place by what it took in advance, or by its work where that is more: the
    # thread's own time, never a wait for Python's lock (by the clock, an ordinary server's slice that waited for the lock
    # sent it back as far: round 2).
    monkeypatch.setattr(rfb, "_ALL", [rfb.DRAWING_BURST, time.monotonic()])
    monkeypatch.setattr(rfb, "_LINE", rfb._Line())
    for clock, work, moved in ((0.05, 0.04, 0.04), (0.05, 0.0, rfb.DRAWING_SLICE)):  # (work; and a slice whose work read nought)
        client = Client(Scripted(b""), None)
        client._place = rfb._LINE.given
        before = client._place
        monkeypatch.setattr(rfb, "_advance", lambda steps, most, clock=clock, work=work: (True, clock, work))
        run(client._drawn(iter(())))
        assert client._place - before == pytest.approx(moved), (clock, work, client._place - before)


def test_servers_waiting_for_every_servers_share_take_turns_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    # The rule the test above stands on: in line for every server's share, a server that has had fewer turns goes first,
    # of two that have had as many the one that came first, and one that has just had its turn comes after one that waits;
    # one that stops waiting (its connection closed) hands the line on, and leaves nothing behind.
    monkeypatch.setattr(rfb, "_ALL", [-0.02, time.monotonic()])  # (used up: every turn waits for it)
    monkeypatch.setattr(rfb, "_LINE", rfb._Line())
    heavy = [Client(Scripted(b""), None) for _ in range(2)]
    light, gone = Client(Scripted(b""), None), Client(Scripted(b""), None)
    for client in heavy:
        client._place = 10 * rfb.BREATHE  # (they have had ten turns more than the others)
    order: list[str] = []

    async def turns(client: Client, name: str, count: int) -> None:
        for _ in range(count):
            await client._turn(rfb.BREATHE)
            order.append(name)

    async def go() -> None:
        leaving = asyncio.create_task(turns(gone, "gone", 1))  # (first in line, and then not there any more)
        await asyncio.sleep(0)
        first = asyncio.create_task(turns(heavy[0], "first", 2))
        await asyncio.sleep(0)
        second = asyncio.create_task(turns(heavy[1], "second", 2))
        await asyncio.sleep(0)
        later = asyncio.create_task(turns(light, "light", 1))
        await asyncio.sleep(0)
        leaving.cancel()
        async with asyncio.timeout(10):
            await asyncio.gather(first, second, later)
        await asyncio.gather(leaving, return_exceptions=True)

    run(go())
    assert order == ["light", "first", "second", "first", "second"], order
    assert not rfb._LINE.waiting


def test_every_servers_updates_together_hold_no_more_than_the_walls_share_of_memory(monkeypatch: pytest.MonkeyPatch) -> None:
    # Each update was held to its own screen: one held about 3.4 times its 48 MB screen on its way to it, and four such
    # servers at once raised the program by 467 MB (probe p5), with nothing to stop more. What every server's updates hold
    # together beyond their screens is held to HELD_ALL: an update that does not fit waits for one that does to be drawn.
    monkeypatch.setattr(rfb, "HELD_ALL", 16 * 1024 * 1024, raising=False)
    width, height = 768, 768
    update = stored_zrle(width, height)
    clients = [Client(Scripted(screen(width, height) + update), None) for _ in range(12)]

    async def go() -> tuple[list[RfbError], int]:
        for client in clients:
            await client.handshake()  # (the screens, 1.7 MB each, are there before what is measured)
        tracemalloc.start()
        try:
            base, _ = tracemalloc.get_traced_memory()
            tracemalloc.reset_peak()
            ended = await asyncio.gather(*(served_from(client) for client in clients))
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        return list(ended), peak - base

    ended, held = run(go())
    assert all(end.code == rfb.CLOSED for end in ended) and all(client.frames == 1 for client in clients), [end.message for end in ended]
    assert held <= 16 * 1024 * 1024 + 1024 * 1024, held / 1e6


def test_updates_that_wait_for_the_walls_memory_neither_wait_for_good_nor_are_blamed_for_it(monkeypatch: pytest.MonkeyPatch) -> None:
    # Updates of several large rectangles, more than fit at once, from more servers than fit at once: every one is drawn
    # (an update waits holding nothing, so none waits for another that waits), and the time one waits for the others is
    # not counted against the time its server has to send its message in.
    monkeypatch.setattr(rfb, "HELD_ALL", 4 * 1024 * 1024, raising=False)
    monkeypatch.setattr(rfb, "MESSAGE_WITHIN", 0.3)
    width, height = 512, 512
    clients = [Client(Scripted(screen(width, height) + stored_zrle(width, height, 4, 3)), None) for _ in range(8)]

    async def go() -> list[RfbError]:
        for client in clients:
            await client.handshake()
        async with asyncio.timeout(30):
            return list(await asyncio.gather(*(served_from(client) for client in clients)))

    ended = run(go())
    assert [end.code for end in ended] == [rfb.CLOSED] * len(clients), [end.message for end in ended]
    assert [client.frames for client in clients] == [3] * len(clients)
    assert rfb._HELD.held == 0 and not rfb._HELD.waiting  # (and nothing is left held when they are over)


def test_room_is_handed_on_in_order_to_each_that_fits_and_one_that_fits_waits_for_none(monkeypatch: pytest.MonkeyPatch) -> None:
    # The rules the test below stands on, one step at a time: a server holds a quarter of HELD_ALL at the most, a rectangle
    # larger than that alone and one server at a time; one that does not fit waits, holding nothing, and one that fits is
    # given room at once whoever waits; room let go of is handed on at once, in order, to each that fits.
    mb = 1024 * 1024
    monkeypatch.setattr(rfb, "HELD_ALL", 8 * mb)
    monkeypatch.setattr(rfb, "_HELD", rfb._Held())
    first, second, third, fourth = (Client(Scripted(b""), None) for _ in range(4))
    drawn: list[Client] = []

    def gathered(client: Client) -> Callable[[], Any]:
        async def draw() -> None:  # (as the update's own flush: what it gathered is drawn, and let go of)
            if client._gathered:
                drawn.append(client)
            client._let_go(pending=False)

        return draw

    def read(client: Client) -> None:  # (as the update gathers a rectangle read: it waits to be drawn)
        client._gathered, client._pending = client._gathered + client._pending, 0

    async def go() -> None:
        await first._room(4 * mb, gathered(first))  # (larger than a quarter: alone, and the one such)
        assert rfb._HELD.large is first and rfb._HELD.held == 4 * mb
        await second._room(mb, gathered(second))
        read(second)
        await second._room(mb, gathered(second))  # (two of a quarter: within it)
        read(second)
        assert second._gathered == 2 * mb and not drawn
        await second._room(mb, gathered(second))  # (a third would be more: what it gathered is drawn and let go of first)
        assert drawn == [second] and second._pending == mb and rfb._HELD.held == 5 * mb
        waiting = asyncio.create_task(third._room(3 * mb, gathered(third)))  # (larger than a quarter, and one such is held)
        await asyncio.sleep(0.05)
        assert not waiting.done() and len(rfb._HELD.waiting) == 1
        async with asyncio.timeout(1):
            await fourth._room(2 * mb, gathered(fourth))  # (fits: given at once, though another waits)
        assert rfb._HELD.held == 7 * mb
        first._let_go(pending=True)  # (drawn: its room is handed on at once, to the one that waits)
        assert rfb._HELD.large is third and rfb._HELD.held == 6 * mb and not rfb._HELD.waiting
        await waiting
        for client in (second, third, fourth):
            client._let_go(pending=True)
        assert rfb._HELD.held == 0 and rfb._HELD.large is None

    run(go())


class Trickle(Scripted):
    """A server that sends the headers of its messages at once and the bytes of its rectangles a piece at a time, `pause`
    seconds apart: one whose updates take long to come, each of them valid."""

    def __init__(self, data: bytes, pause: float) -> None:
        super().__init__(data)
        self.pause = pause

    async def read(self, size: int, within: float | None) -> bytes:
        if size >= 1024:
            await asyncio.sleep(self.pause)
        return await super().read(size, within)


class Lan(Scripted):
    """A server whose every piece waits a moment for the network, as on a LAN (others have the loop meanwhile)."""

    async def read(self, size: int, within: float | None) -> bytes:
        await asyncio.sleep(0.002)
        return await super().read(size, within)


@pytest.mark.parametrize("hostile", ["the largest rectangles", "a quarter each, and a larger one waiting"])
def test_servers_that_hold_their_share_of_memory_while_their_bytes_come_slowly_hold_up_no_other(hostile: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # Two or three servers whose updates came slowly, each holding up to half of HELD_ALL meanwhile, left no room for a
    # third; it waited first in line, and every other server's next rectangle went behind it, whether it fitted or not:
    # one of their slow messages a rectangle (probe p2, scaled down: an ordinary update of eight rectangles 0.54 s alone,
    # 9.3 s beside two such servers). At real timing, a message of up to a minute a rectangle: an update of four or more
    # outlasted the pacer's two minutes, and the server was dropped as not answering, again and again. A server holds a
    # quarter of HELD_ALL at the most, a rectangle larger than that only alone and one server at a time, and a request that
    # fits is not queued behind one that does not. Scaled down: a slow message 1.5 s, the pacer's wait 2 + 3 s.
    from qkvm import vncdevice
    from qkvm.kvm import DeviceSpec

    monkeypatch.setattr(rfb, "HELD_ALL", 8 * 1024 * 1024)
    monkeypatch.setattr(rfb, "_HELD", rfb._Held())
    monkeypatch.setattr(rfb, "_ALL", [rfb.DRAWING_BURST, time.monotonic()])
    # (A slow message has 3 s, not 2: on Windows each of its pieces' waits ends on a tick of the clock, and its 1.5 s came
    # near 2 s now and then. The pacer waits 2 + 3 s; an ordinary update beside them on a2003ee took 9 s and more.)
    monkeypatch.setattr(rfb, "MESSAGE_WITHIN", 3.0)
    monkeypatch.setattr(vncdevice, "HEARTBEAT", 2.0)
    slow = 1.5  # seconds a hostile server's update takes to come
    largest = (1024, 1024, 1, 49)  # (one rectangle an update, larger than the most one server may hold at once; pieces of it)
    quarter = (768, 384, 2, 14)  # (two rectangles an update, just under a quarter of HELD_ALL each, the first held while the second comes)
    kinds = [largest] * 3 if hostile == "the largest rectangles" else [quarter] * 4 + [largest]
    hostiles = [Client(Trickle(screen(width, height) + stored_zrle(width, height, rectangles, 40), slow / pieces), None) for width, height, rectangles, pieces in kinds]
    ordinary = Client(Lan(screen(512, 512) + stored_zrle(512, 512, 8, 4)), None)
    took: list[float] = []

    async def go() -> None:
        device = vncdevice.VncDevice(DeviceSpec(id="o", name="ordinary", base_url="vnc://127.0.0.1:5999", username="", password="", kind="vnc"))
        for client in (*hostiles, ordinary):
            await client.handshake()
        serving = []
        for client in hostiles:
            serving.append(asyncio.create_task(client.serve()))
            await asyncio.sleep(slow / len(hostiles))  # (one after another)
        await asyncio.sleep(slow)  # (all of them at it)
        assert rfb._HELD.held > 0
        serving.append(asyncio.create_task(ordinary.serve()))
        try:
            for _ in range(4):
                began, seen = time.monotonic(), ordinary.updates
                await device._answered_within(ordinary, seen, vncdevice.HEARTBEAT, heartbeat=True)  # (as the pacer waits)
                took.append(time.monotonic() - began)
            assert not any(task.done() for task in serving[:-1]), [task.exception() for task in serving if task.done()]
        finally:
            for task in serving:
                task.cancel()
            await asyncio.gather(*serving, return_exceptions=True)

    run(go())
    # (Alone, an update takes about half a second.)
    assert len(took) == 4 and max(took) < 1.5, took
    assert rfb._HELD.held == 0 and not rfb._HELD.waiting


def quarter_holders(count: int, slow: float) -> list[Client]:
    """`count` servers whose every update is one ZRLE rectangle as near a quarter of an 8 MiB HELD_ALL as can be (416 by 384
    stored tiles: 2,093,032 bytes of room), each taking `slow` seconds to come: holding their quarter all the while."""
    return [Client(Trickle(screen(416, 384) + stored_zrle(416, 384, 1, 60), slow / 14), None) for _ in range(count)]


async def holding(servers: list[Client], slow: float) -> list[asyncio.Task[None]]:
    for client in servers:
        await client.handshake()
    tasks = []
    for client in servers:
        tasks.append(asyncio.create_task(client.serve()))
        await asyncio.sleep(slow / len(servers))  # (one after another)
    await asyncio.sleep(slow)  # (all of them at it, the room full)
    return tasks


def test_room_a_server_lets_go_of_in_its_update_serves_it_first(monkeypatch: pytest.MonkeyPatch) -> None:
    # Four slow servers each holding exactly a quarter: the room an ordinary server let go of by drawing what it gathered
    # (it would have held more than its quarter) was handed at once to one of them, which waited, and the ordinary server
    # waited for the next slow message, again and again within one update (the review's q4, scaled down: an update of 24
    # rectangles 7.4 s each beside four slow servers of 3 s messages, 1.9 s beside three). What a server lets go of in its
    # update serves it first; what it lets go of at the update's end is handed on.
    monkeypatch.setattr(rfb, "HELD_ALL", 8 * 1024 * 1024)
    monkeypatch.setattr(rfb, "_HELD", rfb._Held())
    monkeypatch.setattr(rfb, "_ALL", [rfb.DRAWING_BURST, time.monotonic()])
    monkeypatch.setattr(rfb, "MESSAGE_WITHIN", 30.0)
    slow = 1.5
    holders = quarter_holders(4, slow)
    ordinary = Client(Lan(screen(1536, 768) + stored_zrle(1536, 768, 24, 3)), None)
    done: list[float] = []

    async def go() -> None:
        tasks = await holding(holders, slow)
        await ordinary.handshake()
        assert rfb._HELD.held > rfb.HELD_ALL - 64 * 1024  # (the room full: less free than one of its rectangles needs)
        serving = asyncio.create_task(ordinary.serve())
        began, seen = time.monotonic(), 0
        try:
            async with asyncio.timeout(40):
                while ordinary.updates < 3 and not serving.done():
                    await asyncio.sleep(0.01)
                    if ordinary.updates != seen:
                        seen = ordinary.updates
                        done.append(time.monotonic() - began)
        finally:
            for task in (*tasks, serving):
                task.cancel()
            await asyncio.gather(*tasks, serving, return_exceptions=True)

    run(go())
    # (At its start each update waits for one slow message to end, for the room is full; then it goes on, within its own.)
    gaps = [later - earlier for earlier, later in itertools.pairwise([0.0, *done])]
    assert len(done) == 3 and max(gaps) < 2 * slow, done
    assert rfb._HELD.held == 0 and not rfb._HELD.waiting


def test_a_request_larger_than_a_quarter_that_has_waited_is_not_passed_for_good(monkeypatch: pytest.MonkeyPatch) -> None:
    # A rectangle that needs more than a quarter waited for two quarters to be free at once; four slow servers let go of one
    # at a time and asked again at once, and the quarter each let go of fitted its own next request, which went ahead: the
    # larger one waited until their streams ended (the review's q4, scaled down: some 100 s). One that has waited
    # ROOM_PASSED_FOR is passed no more: room is set aside for it as it is let go of.
    monkeypatch.setattr(rfb, "HELD_ALL", 8 * 1024 * 1024)
    monkeypatch.setattr(rfb, "_HELD", rfb._Held())
    monkeypatch.setattr(rfb, "_ALL", [rfb.DRAWING_BURST, time.monotonic()])
    monkeypatch.setattr(rfb, "MESSAGE_WITHIN", 30.0)
    monkeypatch.setattr(rfb, "ROOM_PASSED_FOR", 1.0, raising=False)
    slow = 1.5
    holders = quarter_holders(4, slow)
    large = Client(Lan(screen(768, 768) + stored_zrle(768, 768, 1, 2)), None)  # (one rectangle a refresh: half of the room)
    done: list[float] = []

    async def go() -> None:
        tasks = await holding(holders, slow)
        await large.handshake()
        serving = asyncio.create_task(large.serve())
        began, seen = time.monotonic(), 0
        try:
            async with asyncio.timeout(15):
                while large.updates < 2 and not serving.done():
                    await asyncio.sleep(0.01)
                    if large.updates != seen:
                        seen = large.updates
                        done.append(time.monotonic() - began)
        except TimeoutError:
            pass
        finally:
            for task in (*tasks, serving):
                task.cancel()
            await asyncio.gather(*tasks, serving, return_exceptions=True)

    run(go())
    # (It waits ROOM_PASSED_FOR, then for two of the slow messages to end: some 4 s an update here.)
    assert len(done) == 2 and done[-1] < 12, done
    assert rfb._HELD.held == 0 and not rfb._HELD.waiting
