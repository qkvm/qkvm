"""What a server's bytes can make the reader do: nothing but end with a named error, within its bounds.

The known breakages (a rectangle outside the screen, a Tight rectangle wider than its rules allow, a zlib
stream that inflates past its rectangle, a resize in the middle of an update, a message of unknown kind,
floods, stalls), made-up bytes, and real sessions with bytes changed at random. A fresh reviewer reads
this with the question "what can a hostile server's bytes make this reader do".
"""

from __future__ import annotations

import asyncio
import random
import struct
import tracemalloc
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from qkvm import rfb
from qkvm.rfb import Client, RfbError
from tests import fake_vnc
from tests.fake_vnc import FakeVnc, PixelFormat, VncState, known_picture
from tests.test_rfb import Scripted, connect, first_frame, run

# What each misbehaviour of the stand-in must end in: the code of the named error.
AFTER_THE_HANDSHAKE = {
    "rect_outside": rfb.PROTOCOL,
    "copy_from_outside": rfb.PROTOCOL,
    "unknown_encoding": rfb.PROTOCOL,
    "unknown_message": rfb.PROTOCOL,
    "zlib_bomb": rfb.LIMIT,
    "tight_bomb": rfb.LIMIT,
    "zlib_claims_more": rfb.LIMIT,
    "tight_wide": rfb.PROTOCOL,
    "resize_mid_update": rfb.PROTOCOL,
    "close_mid_rect": rfb.CLOSED,
    "message_flood": rfb.LIMIT,
    "rectangle_flood": rfb.LIMIT,
    "cut_text_huge": rfb.LIMIT,
    "jpeg_wrong_size": rfb.PROTOCOL,
    "jpeg_garbage": rfb.PROTOCOL,
    "hextile_sub_outside": rfb.PROTOCOL,
    "zrle_bad_sub": rfb.PROTOCOL,
    "zrle_leftover": rfb.PROTOCOL,
    "zrle_short": rfb.PROTOCOL,
    "zrle_not_zlib": rfb.PROTOCOL,
    "palette_index_past": rfb.PROTOCOL,
    "tight_bad_filter": rfb.PROTOCOL,
    "tight_bad_method": rfb.PROTOCOL,
    "desktop_size_huge": rfb.LIMIT,
}
AT_THE_HANDSHAKE = {"huge_screen": rfb.LIMIT, "zero_screen": rfb.LIMIT, "huge_name": rfb.LIMIT}
WIDTHS = {"tight_wide": (2200, 4)}  # a screen wide enough for the rectangle to lie inside it


@pytest.fixture
def fake() -> Iterator[Callable[..., FakeVnc]]:
    made: list[FakeVnc] = []

    def start(**state: Any) -> FakeVnc:
        server = FakeVnc(VncState(**state)).start()
        made.append(server)
        return server

    yield start
    for server in made:
        server.stop()


@pytest.mark.parametrize("how", sorted(AFTER_THE_HANDSHAKE))
def test_a_known_breakage_ends_with_the_named_error_and_nothing_else(fake: Callable[..., FakeVnc], how: str) -> None:
    width, height = WIDTHS.get(how, (320, 200))
    server = fake(width=width, height=height, hostile=how)

    async def go() -> None:
        client = await connect(server)
        tracemalloc.start()
        try:
            with pytest.raises(RfbError) as ended:
                async with asyncio.timeout(15):
                    await first_frame(client)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert ended.value.code == AFTER_THE_HANDSHAKE[how], ended.value.message
        assert len(client.rgb) == 3 * client.width * client.height  # the screen is what it says
        assert client.width * client.height <= rfb.MOST_PIXELS
        # Two screens' worth and a little: a bomb of 50 MB inflated to no more than its bound (the stand-in made its bombs before the measuring began).
        assert peak < 2 * 3 * width * height + 6 * 1024 * 1024, peak
        await client.close()

    run(go())


@pytest.mark.parametrize("how", sorted(AT_THE_HANDSHAKE))
def test_a_screen_or_a_name_past_the_bounds_is_refused_before_room_is_taken(fake: Callable[..., FakeVnc], how: str) -> None:
    server = fake(hostile=how)

    async def go() -> None:
        stream = await rfb.open_tcp("127.0.0.1", server.port, None, 5.0)
        client = Client(stream, "secret")
        tracemalloc.start()
        try:
            with pytest.raises(RfbError) as ended:
                await client.handshake()
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert ended.value.code == AT_THE_HANDSHAKE[how], ended.value.message
        assert len(client.rgb) == 0 and peak < 4 * 1024 * 1024, peak
        await stream.close()

    run(go())


def test_a_server_that_hangs_up_after_the_handshake_is_closed_not_a_mystery(fake: Callable[..., FakeVnc]) -> None:
    server = fake()

    async def go() -> None:
        client = await connect(server)
        server.drop_everybody()
        with pytest.raises(RfbError) as ended:
            async with asyncio.timeout(15):
                await client.serve()
        assert ended.value.code == rfb.CLOSED
        await client.close()

    run(go())


# --- sessions as bytes, and what random changes to them do -------------------------------------------------------


def session(encoding: str, seed: int, width: int = 48, height: int = 32, resets: bool = False) -> tuple[bytes, bytes]:
    """The bytes a server sends in one session (3.8, no password, one full update in `encoding`), and the picture it shows.

    The reader's own writes are not in it: a script of bytes hears nothing, and the update comes as if asked for.
    """
    fmt = PixelFormat.read(rfb.PIXEL_FORMAT)
    picture = known_picture(width, height, seed)
    name = b"scripted"
    head = b"RFB 003.008\n" + bytes([1, 1]) + struct.pack(">I", 0) + struct.pack(">HH", width, height) + fmt.pack() + struct.pack(">I", len(name)) + name
    whole = (0, 0, width, height)
    rectangles: list[bytes] = []
    zrle, tight = fake_vnc.ZrleStream(), fake_vnc.TightStreams(resets)
    if encoding == "raw":
        rectangles.append(fake_vnc.rectangle_header(whole, rfb.RAW) + fake_vnc.encode_raw(picture, width, height, fmt))
    elif encoding == "hextile":
        rectangles.append(fake_vnc.rectangle_header(whole, rfb.HEXTILE) + fake_vnc.encode_hextile(picture, width, height, fmt))
    elif encoding == "zrle":
        rectangles.append(fake_vnc.rectangle_header(whole, rfb.ZRLE) + zrle.rectangle(fake_vnc.encode_zrle_tiles(picture, width, height, fmt)))
    elif encoding == "pieces":  # several rectangles, each in another encoding, with a copy among them
        half = width // 2
        left, right = fake_vnc.crop(picture, width, (0, 0, half, height)), fake_vnc.crop(picture, width, (half, 0, width - half, height))
        rectangles.append(fake_vnc.rectangle_header((0, 0, half, height), rfb.TIGHT) + tight.rectangle(left, half, height, "tight"))
        rectangles.append(fake_vnc.rectangle_header((half, 0, width - half, height), rfb.ZRLE) + zrle.rectangle(fake_vnc.encode_zrle_tiles(right, width - half, height, fmt)))
        rectangles.append(fake_vnc.rectangle_header((0, 0, 8, 8), rfb.COPY_RECT) + struct.pack(">HH", 0, 0))
    else:
        rectangles.append(fake_vnc.rectangle_header(whole, rfb.TIGHT) + tight.rectangle(picture, width, height, encoding))
    return head + fake_vnc.update_message(rectangles), picture


async def play(script: bytes, within: float = 10.0) -> tuple[Client, BaseException | None]:
    """Run a script of bytes through the reader: the client as it ended, and what ended it (None: nothing did, yet)."""
    client = Client(Scripted(script), None)
    try:
        async with asyncio.timeout(within):
            await client.handshake()
            await client.request(incremental=False)
            await client.serve()
    except BaseException as ex:
        return client, ex
    return client, None


@pytest.mark.parametrize("encoding", ["raw", "hextile", "zrle", "tight", "tight-gradient", "tight-jpeg", "pieces"])
def test_a_session_as_bytes_plays_back_to_the_picture(encoding: str) -> None:
    script, picture = session(encoding, seed=4)
    client, ended = run(play(script))
    assert isinstance(ended, RfbError) and ended.code == rfb.CLOSED  # the script ran out: nothing else was wrong
    assert client.frames == 1
    if encoding == "tight-jpeg":
        assert sum(abs(a - b) for a, b in zip(bytes(client.rgb), picture, strict=True)) / len(picture) < 12
    else:
        assert bytes(client.rgb) == picture


def mutated(script: bytes, rng: random.Random, after: int) -> bytes:
    """`script` with a few bytes changed, inserted or cut, past its first `after` bytes."""
    data = bytearray(script)
    for _ in range(rng.randint(1, 6)):
        what = rng.random()
        at = rng.randrange(after, len(data)) if len(data) > after else after
        if what < 0.6 and at < len(data):
            data[at] = rng.randrange(256)
        elif what < 0.8:
            data[at:at] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 8)))
        elif at < len(data):
            del data[at : at + rng.randint(1, 16)]
    return bytes(data)


@pytest.mark.parametrize("encoding", ["raw", "hextile", "zrle", "tight", "tight-gradient", "tight-jpeg", "pieces"])
def test_real_sessions_with_bytes_changed_at_random_end_with_a_named_error_within_their_bounds(encoding: str) -> None:
    script, _ = session(encoding, seed=6)
    handshake = len(script) - len(fake_vnc.update_message([])) - (len(script) - script.index(b"\x00\x00\x00\x01", 20))
    handshake = script.index(b"scripted") + len(b"scripted")  # the update begins after the name
    rng = random.Random(encoding)
    codes: set[str] = set()
    for round_number in range(60):
        changed = mutated(script, rng, handshake if round_number % 4 else 0)
        client, ended = run(play(changed))
        assert ended is not None, "a script that ran out and did not say so"
        assert isinstance(ended, RfbError), f"round {round_number}: {type(ended).__name__}: {ended}"
        codes.add(ended.code)
        assert len(client.rgb) == 3 * client.width * client.height
        assert client.width * client.height <= rfb.MOST_PIXELS
    assert codes & {rfb.PROTOCOL, rfb.LIMIT} and rfb.CLOSED in codes, codes  # refused for what the bytes were, and run out of


def test_made_up_bytes_after_the_handshake_end_with_a_named_error() -> None:
    script, _ = session("raw", seed=1)
    handshake = script.index(b"scripted") + len(b"scripted")
    rng = random.Random(7)
    for _ in range(60):
        noise = bytes(rng.randrange(256) for _ in range(rng.randint(0, 400)))
        _, ended = run(play(script[:handshake] + noise))
        assert isinstance(ended, RfbError), f"{type(ended).__name__}: {ended}"


def test_made_up_bytes_from_the_very_first_one_end_with_a_named_error() -> None:
    rng = random.Random(8)
    for _ in range(60):
        noise = bytes(rng.randrange(256) for _ in range(rng.randint(0, 200)))
        _, ended = run(play(noise))
        assert isinstance(ended, RfbError), f"{type(ended).__name__}: {ended}"


def test_a_reset_bit_in_the_middle_of_the_stream_is_honoured_and_a_stream_that_is_not_reset_as_told_is_an_error() -> None:
    # Two rectangles on one Tight stream, the second with its reset bit set and made on a fresh stream: decodes.
    script, picture = session("tight", seed=2, resets=True)
    client, ended = run(play(script))
    assert isinstance(ended, RfbError) and ended.code == rfb.CLOSED and bytes(client.rgb) == picture
    # The same second rectangle with the reset bit taken away does not inflate on the stream as it stands.
    fmt = PixelFormat.read(rfb.PIXEL_FORMAT)
    width, height = 48, 32
    tight = fake_vnc.TightStreams(reset_each_time=True)
    first = tight.rectangle(picture, width, height, "tight-gradient")
    second = tight.rectangle(known_picture(width, height, 3), width, height, "tight-gradient")
    assert second[0] & 0x04  # (stream 2's reset bit)
    broken = bytes([second[0] & ~0x04]) + second[1:]
    head = script[: script.index(b"scripted") + len(b"scripted")]
    rectangles = [fake_vnc.rectangle_header((0, 0, width, height), rfb.TIGHT) + first, fake_vnc.rectangle_header((0, 0, width, height), rfb.TIGHT) + broken]
    _, ended = run(play(head + fake_vnc.update_message(rectangles)))
    assert isinstance(ended, RfbError) and ended.code in (rfb.PROTOCOL, rfb.LIMIT)
    assert fmt.pack() == rfb.PIXEL_FORMAT


def test_what_is_read_for_a_rectangle_is_bounded_by_the_screen_not_by_what_the_server_claims() -> None:
    # A ZRLE rectangle of 8 by 8 saying it holds a megabyte: refused by its length, before a byte of it is read.
    script, _ = session("raw", seed=1)
    head = script[: script.index(b"scripted") + len(b"scripted")]
    claim = fake_vnc.rectangle_header((0, 0, 8, 8), rfb.ZRLE) + struct.pack(">I", 1024 * 1024)
    _, ended = run(play(head + fake_vnc.update_message([claim]) + b"\0" * 2000))
    assert isinstance(ended, RfbError) and ended.code == rfb.LIMIT and "more than it could hold" in ended.message
    # ...and a Tight JPEG, the same.
    claim = fake_vnc.rectangle_header((0, 0, 8, 8), rfb.TIGHT) + bytes([0x90]) + fake_vnc.compact_length(500_000)
    _, ended = run(play(head + fake_vnc.update_message([claim]) + b"\0" * 2000))
    assert isinstance(ended, RfbError) and ended.code == rfb.LIMIT


def test_a_rectangle_in_an_encoding_not_asked_for_is_not_guessed_at() -> None:
    script, _ = session("raw", seed=1)
    head = script[: script.index(b"scripted") + len(b"scripted")]
    for encoding in (2, 4, 6, 15, -239, -224, -308, 21, 0x574D5600):
        packed = struct.pack(">HHHHI", 0, 0, 8, 8, encoding & 0xFFFFFFFF)
        _, ended = run(play(head + fake_vnc.update_message([packed]) + b"\0" * 300))
        assert isinstance(ended, RfbError) and ended.code == rfb.PROTOCOL and "did not ask for" in ended.message, encoding


def test_the_reason_a_server_gives_is_one_short_line_however_it_was_written() -> None:
    reason = ("no\nentry\x00for you " * 40).encode()
    script = b"RFB 003.008\n" + bytes([0]) + struct.pack(">I", len(reason)) + reason
    _, ended = run(play(script))
    assert isinstance(ended, RfbError) and ended.code == rfb.REFUSED
    assert "\n" not in ended.message and "\x00" not in ended.message and len(ended.message) < 260
    script = b"RFB 003.008\n" + bytes([0]) + struct.pack(">I", 2**31)
    _, ended = run(play(script))
    assert isinstance(ended, RfbError) and ended.code == rfb.LIMIT


# --- what a reviewer asked: time on the one thread that reads, and what the fuzzing had not reached -----------------


def head_of(script: bytes) -> bytes:
    """The handshake of a scripted session, up to and including the server's name."""
    return script[: script.index(b"scripted") + len(b"scripted")]


async def served(client: Client) -> RfbError:
    await client.handshake()
    await client.request(incremental=False)
    try:
        await client.serve()
    except RfbError as ex:
        return ex
    raise AssertionError("it did not end")


def test_copyrect_is_drawn_where_the_other_encodings_are_drawn_and_not_on_the_thread_that_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    import threading

    where: list[str] = []
    original = Client._copy

    def noted(self: Client, *args: Any) -> Any:
        where.append(threading.current_thread().name)
        yield from original(self, *args)

    monkeypatch.setattr(Client, "_copy", noted)
    script, picture = session("pieces", seed=4)
    client, ended = run(play(script))
    assert isinstance(ended, RfbError) and ended.code == rfb.CLOSED and bytes(client.rgb) == picture
    assert where and threading.main_thread().name not in where, where


def test_more_pixels_than_a_screen_could_change_in_one_update_are_refused() -> None:
    # Four screens' worth of fill rectangles in one update is taken (rectangles may overlap); five is no update.
    script, _ = session("raw", seed=1)
    fill = fake_vnc.rectangle_header((0, 0, 48, 32), rfb.TIGHT) + bytes([0x80, 1, 2, 3])
    client, ended = run(play(head_of(script) + fake_vnc.update_message([fill] * 4)))
    assert isinstance(ended, RfbError) and ended.code == rfb.CLOSED and client.frames == 1
    _, ended = run(play(head_of(script) + fake_vnc.update_message([fill] * 5)))
    assert isinstance(ended, RfbError) and ended.code == rfb.LIMIT and "pixels" in ended.message


def test_more_pixels_than_a_screen_could_change_in_a_second_are_refused_and_gradients_count_for_more() -> None:
    # A screen of half a million pixels: its second's worth is the floor of eight million, sixteen screens.
    width, height = 1024, 512
    script, _ = session("raw", seed=1, width=width, height=height)
    whole = fake_vnc.rectangle_header((0, 0, width, height), rfb.TIGHT)
    flat = bytes(3 * width * height)

    def twenty_screens() -> bytes:
        """Five updates of four screens each in the copy filter, a few kilobytes apiece, in order on one zlib stream."""
        tight = fake_vnc.TightStreams()
        rects = [whole + tight.basic(flat, 0, None) for _ in range(20)]
        return b"".join(fake_vnc.update_message(rects[at : at + 4]) for at in range(0, 20, 4))

    now = [10.0]
    ended = run(served(Client(Scripted(head_of(script) + twenty_screens()), None, clock=lambda: now[0])))
    assert ended.code == rfb.LIMIT and "pixels" in ended.message
    # The same spread over seconds is nothing.
    tick = Client(Scripted(head_of(script) + twenty_screens()), None, clock=lambda: now[0])
    original = tick.stream.read

    async def read(size: int, within: float | None) -> bytes:
        now[0] += 0.1
        return await original(size, within)

    tick.stream.read = read  # type: ignore[method-assign]
    assert run(served(tick)).code == rfb.CLOSED
    # A gradient rectangle costs the drawing thread many times what a copy does, and is counted so: three screens of it in one second is too much, one is not.
    gradient = fake_vnc.TightStreams()
    rects = [whole + gradient.basic(flat, 2, 2) for _ in range(3)]
    ended = run(served(Client(Scripted(head_of(script) + fake_vnc.update_message(rects)), None, clock=lambda: now[0])))
    assert ended.code == rfb.LIMIT and "pixels" in ended.message
    one = whole + fake_vnc.TightStreams().basic(flat, 2, 2)
    assert run(served(Client(Scripted(head_of(script) + fake_vnc.update_message([one])), None, clock=lambda: now[0]))).code == rfb.CLOSED
    # Fills and JPEGs are cheap for the thread, and may come by the dozen.
    fills = [whole + bytes([0x80, 1, 2, 3])] * 64
    assert run(served(Client(Scripted(head_of(script) + fake_vnc.update_message(fills[:4]) * 16), None, clock=lambda: now[0]))).code == rfb.CLOSED


def test_resizes_by_the_dozen_in_a_second_are_refused() -> None:
    script, _ = session("raw", seed=1)
    now = [10.0]
    sizes = [fake_vnc.rectangle_header((0, 0, 40 + (i % 2), 32), rfb.DESKTOP_SIZE) for i in range(rfb.MOST_RESIZES_A_SECOND + 1)]
    ended = run(served(Client(Scripted(head_of(script) + fake_vnc.update_message(sizes)), None, clock=lambda: now[0])))
    assert ended.code == rfb.LIMIT and "size" in ended.message
    ended = run(served(Client(Scripted(head_of(script) + fake_vnc.update_message(sizes[:-1])), None, clock=lambda: now[0])))
    assert ended.code == rfb.CLOSED


def test_a_hextile_rectangle_is_read_in_pieces_and_not_tile_by_tile(fake: Callable[..., FakeVnc]) -> None:
    server = fake(width=512, height=512, encoding="hextile", picture=bytes([1, 2, 3]) * (512 * 512))  # one colour: 1024 tiles of five bytes

    async def go() -> None:
        client = await connect(server)
        reads = [0]
        for name in ("read", "read_some"):
            original = getattr(client.stream, name)

            async def counted(size: int, within: float | None, original: Any = original) -> bytes:
                reads[0] += 1
                return await original(size, within)

            setattr(client.stream, name, counted)
        await first_frame(client)
        assert bytes(client.rgb) == server.state.picture
        assert reads[0] < 64, reads[0]  # a few kilobytes: a handful of reads, not one awaited read per tile
        await client.close()

    run(go())


@pytest.mark.parametrize("over", ["tcp", "websocket"])
def test_what_was_read_ahead_for_a_hextile_rectangle_is_where_the_next_message_begins(over: str) -> None:
    # A Hextile rectangle is read ahead a chunk at a time, and the messages after it came along in that chunk: the next
    # message's first byte was read from the connection all the same, past them. The Raw update after a Bell was never
    # drawn; with more behind it, the session ended as "sent what qKVM does not take", and a server that is well was left
    # alone for fifteen seconds and more. Over a WebSocket (OpenBMC's console, Proxmox's) messages straddle its own.
    from websockets.asyncio.client import connect as ws_connect

    server = FakeVnc(VncState(width=64, height=32, password=None, hostile="read_ahead"), websocket=over == "websocket").start()

    async def go() -> None:
        if over == "websocket":
            ws = await ws_connect(f"ws://127.0.0.1:{server.port}/", max_size=2**24)
            client = Client(rfb.WebSocketStream(ws), None)
            await client.handshake()
        else:
            client = await connect(server, None)
        serving = asyncio.create_task(client.serve())
        try:
            await client.request(incremental=False)
            async with asyncio.timeout(5):
                while client.frames < 2 and not serving.done():
                    await asyncio.sleep(0.01)
            assert not serving.done(), serving.exception()
            assert client.frames == 2 and bytes(client.rgb) == server.state.picture  # the Raw update, drawn over the tile
        finally:
            serving.cancel()
            await asyncio.gather(serving, return_exceptions=True)
            await client.close()

    try:
        run(go())
    finally:
        server.stop()


def test_time_spent_drawing_is_not_counted_against_the_server(monkeypatch: pytest.MonkeyPatch) -> None:
    import time

    monkeypatch.setattr(rfb, "MESSAGE_WITHIN", 0.3)
    monkeypatch.setattr(rfb, "BATCH_BYTES", 1)  # every rectangle is drawn before the next is read
    original = Client._drawing

    def slowly(self: Client, rectangles: Any) -> Any:
        time.sleep(0.2)
        yield from original(self, rectangles)

    monkeypatch.setattr(Client, "_drawing", slowly)
    script, picture = session("pieces", seed=4)  # three rectangles: 0.6 s of drawing in a message allowed 0.3 s of arriving
    client, ended = run(play(script))
    assert isinstance(ended, RfbError) and ended.code == rfb.CLOSED, ended
    assert bytes(client.rgb) == picture


def test_runs_and_indices_in_zrle_tiles_and_tight_palettes_that_the_fuzzing_had_not_reached() -> None:
    script, _ = session("raw", seed=1, width=8, height=8)
    head = head_of(script)
    cases = [
        ("a run past the end of its tile", bytes([128]) + b"\1\2\3" + fake_vnc._lengths(65)),  # plain RLE: 65 pixels in a tile of 64
        ("an index past the palette", bytes([130]) + b"\1\2\3\4\5\6" + bytes([0x82]) + fake_vnc._lengths(64)),  # two colours, index 2
        ("a run past the end of its tile", bytes([130]) + b"\1\2\3\4\5\6" + bytes([0x81]) + fake_vnc._lengths(65)),
        ("an index past the palette", bytes([3]) + b"\1\2\3\4\5\6\7\x08\x09" + b"\xff" * 16),  # three colours at two bits an index: index 3
    ]
    for said, tiles in cases:
        rect = fake_vnc.rectangle_header((0, 0, 8, 8), rfb.ZRLE) + fake_vnc.ZrleStream().rectangle(tiles)
        _, ended = run(play(head + fake_vnc.update_message([rect])))
        assert isinstance(ended, RfbError) and ended.code == rfb.PROTOCOL and said in ended.message, (said, ended)
    # Tight: a palette of one colour and an index of 1 in it, on the short path of under twelve bytes.
    one = fake_vnc.rectangle_header((0, 0, 8, 1), rfb.TIGHT) + bytes([0x40, 1, 0]) + b"\1\2\3" + bytes([0x80])
    _, ended = run(play(head + fake_vnc.update_message([one])))
    assert isinstance(ended, RfbError) and ended.code == rfb.PROTOCOL and "palette" in ended.message
    # ...and the short path drawn: nine bytes of pixels, sent as they are.
    short = fake_vnc.rectangle_header((0, 0, 3, 1), rfb.TIGHT) + bytes([0x00]) + b"\1\2\3\4\5\6\7\x08\x09"
    client, ended = run(play(head + fake_vnc.update_message([short])))
    assert isinstance(ended, RfbError) and ended.code == rfb.CLOSED and bytes(client.rgb[:9]) == b"\1\2\3\4\5\6\7\x08\x09"


def test_a_no_after_none_and_a_huge_reason_at_the_result_are_named() -> None:
    # 3.8, security None, then "failed" with a reason: refused, and no verdict on a password (none went out).
    reason = b"not now"
    script = b"RFB 003.008\n" + bytes([1, 1]) + struct.pack(">I", 1) + struct.pack(">I", len(reason)) + reason
    _, ended = run(play(script))
    assert isinstance(ended, RfbError) and ended.code == rfb.REFUSED and "not now" in ended.message
    script = b"RFB 003.008\n" + bytes([1, 1]) + struct.pack(">I", 1) + struct.pack(">I", 2**31)
    _, ended = run(play(script))
    assert isinstance(ended, RfbError) and ended.code == rfb.LIMIT


def test_a_websocket_that_sends_text_or_too_much_at_once_is_named() -> None:
    class Ws:
        def __init__(self, messages: list[Any]) -> None:
            self.messages = messages

        async def recv(self) -> Any:
            if not self.messages:
                raise ConnectionError("closed")
            return self.messages.pop(0)

        async def send(self, data: bytes) -> None:
            pass

        async def close(self) -> None:
            pass

    async def go() -> None:
        stream = rfb.WebSocketStream(Ws(["hello"]))
        with pytest.raises(RfbError) as ended:
            await stream.read(1, 1.0)
        assert ended.value.code == rfb.PROTOCOL
        stream = rfb.WebSocketStream(Ws([b"\0" * (rfb.WebSocketStream.MOST_HELD + 2)]))
        with pytest.raises(RfbError) as ended:
            await stream.read(1, 1.0)
        assert ended.value.code == rfb.LIMIT
        stream = rfb.WebSocketStream(Ws([b"ab", b"c"]))
        assert await stream.read(3, 1.0) == b"abc"
        with pytest.raises(RfbError) as ended:
            await stream.read(1, 1.0)
        assert ended.value.code == rfb.CLOSED

    run(go())


DECODED = ("cut short", "run past", "index past", "longer than its tiles", "subrectangle", "holds less", "longer than its pixels", "there is none of")


def plain_session(encoding: str, rng: random.Random, width: int = 48, height: int = 32) -> bytes:
    """A session whose tile bytes were changed at random before compression: what reaches the decoders, past zlib's checksum."""
    fmt = PixelFormat.read(rfb.PIXEL_FORMAT)
    picture = known_picture(width, height, 11)
    name = b"scripted"
    head = b"RFB 003.008\n" + bytes([1, 1]) + struct.pack(">I", 0) + struct.pack(">HH", width, height) + fmt.pack() + struct.pack(">I", len(name)) + name
    header = fake_vnc.rectangle_header((0, 0, width, height), rfb.TIGHT if encoding.startswith("tight") else rfb.ZRLE if encoding == "zrle" else rfb.HEXTILE)
    tight = fake_vnc.TightStreams()
    if encoding == "zrle":
        rect = header + fake_vnc.ZrleStream().rectangle(mutated(fake_vnc.encode_zrle_tiles(picture, width, height, fmt), rng, 0))
    elif encoding == "hextile":
        rect = header + mutated(fake_vnc.encode_hextile(picture, width, height, fmt), rng, 0)
    elif encoding == "tight-palette":
        colours = [bytes((i * 16, 255 - i * 16, i * 7)) for i in range(16)]
        indices = bytes((x // 4 + y // 4) % 16 for y in range(height) for x in range(width))
        rect = header + tight.basic(mutated(indices, rng, 0), 1, 1, bytes([15]) + b"".join(colours))
    elif encoding == "tight-gradient":
        rect = header + tight.basic(mutated(fake_vnc.gradient(picture, width, height), rng, 0), 2, 2)
    else:
        rect = header + tight.basic(mutated(picture, rng, 0), 0, None)
    return head + fake_vnc.update_message([rect])


@pytest.mark.parametrize("encoding", ["zrle", "hextile", "tight-palette", "tight-gradient", "tight-copy"])
def test_tile_bytes_changed_before_compression_reach_the_decoders_and_end_with_a_named_error(encoding: str) -> None:
    rng = random.Random(encoding + " plain")
    reached = 0
    for round_number in range(80):
        client, ended = run(play(plain_session(encoding, rng)))
        assert isinstance(ended, RfbError), f"round {round_number}: {type(ended).__name__}: {ended}"
        assert len(client.rgb) == 3 * client.width * client.height
        # Decoded without complaint (the picture is another one, which is no error), or refused by a decoder's own check.
        if ended.code == rfb.CLOSED or (ended.code == rfb.PROTOCOL and any(word in ended.message for word in DECODED)):
            reached += 1
    assert reached >= 40, reached
