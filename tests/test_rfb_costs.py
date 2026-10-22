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
import struct
import threading
import time
import tracemalloc
import zlib
from collections.abc import Callable
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
    # slice at a time, whatever the bytes are and however fast the machine is.
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
        began = time.monotonic()
        serving = asyncio.create_task(client.serve())
        await asyncio.sleep(window)
        assert not serving.done(), serving.exception()  # (still at it: what it sends is no error, only costly)
        serving.cancel()
        await asyncio.gather(serving, return_exceptions=True)
        went.append(time.monotonic() - began)

    try:
        run(go())
    finally:
        pool.shutdown(wait=True)
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
    # their steps four times as long: measured with three of them.)
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
