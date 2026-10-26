"""Ended compression streams cannot accumulate attacker-supplied bytes between updates."""

from __future__ import annotations

import struct
import zlib
from typing import Any

import pytest

from qkvm import rfb
from tests.fake_vnc import compact_length, rectangle_header
from tests.test_rfb import Scripted, run


STREAMS = [(rfb.ZRLE, 0)] + [(rfb.TIGHT, stream) for stream in range(4)]


def client_for(drawing: bool) -> rfb.Client:
    client = rfb.Client(Scripted(b""))
    client._fit(8, 8)
    client.drawing = drawing
    return client


def inflater(client: rfb.Client, encoding: int, stream: int) -> Any:
    return client._zrle if encoding == rfb.ZRLE else client._tight[stream]


def pixels(encoding: int, width: int = 8, height: int = 8) -> bytes:
    if not width or not height:
        return b""
    return b"\x01\x11\x22\x33" if encoding == rfb.ZRLE else b"\x11\x22\x33" * (width * height)


async def update(client: rfb.Client, encoding: int, compressed: bytes, stream: int = 0, width: int = 8, height: int = 8, reset: bool = False) -> None:
    if encoding == rfb.ZRLE:
        payload = struct.pack(">I", len(compressed)) + compressed
    else:
        control = (stream << 4) | ((1 << stream) if reset else 0)
        payload = bytes([control]) + compact_length(len(compressed)) + compressed
    client.stream = Scripted(struct.pack(">xH", 1) + rectangle_header((0, 0, width, height), encoding) + payload)
    await client._update(client.clock() + 5)


@pytest.mark.parametrize("encoding,stream", STREAMS)
@pytest.mark.parametrize("drawing", [True, False])
def test_bytes_after_the_end_in_one_compressed_rectangle_are_refused(encoding: int, stream: int, drawing: bool) -> None:
    client = client_for(drawing)
    # Both the valid picture and the extra input are tiny: the test never needs a large allocation.
    compressed = zlib.compress(pixels(encoding)) + b"trailing input" * 4
    with pytest.raises(rfb.RfbError) as ended:
        run(update(client, encoding, compressed, stream))
    assert ended.value.code == rfb.PROTOCOL
    assert client.updates == 0


@pytest.mark.parametrize("encoding,stream", STREAMS)
@pytest.mark.parametrize("drawing", [True, False])
def test_a_finished_stream_cannot_retain_input_from_later_rectangles(encoding: int, stream: int, drawing: bool) -> None:
    client = client_for(drawing)
    run(update(client, encoding, zlib.compress(pixels(encoding)), stream))
    state = inflater(client, encoding, stream)
    assert state.eof and state.unused_data == b""
    for _ in range(3):
        with pytest.raises(rfb.RfbError) as ended:
            run(update(client, encoding, b"unconsumed input" * 4, stream))
        assert ended.value.code == rfb.PROTOCOL
        # A size limit on inflated output alone does not prevent zlib accumulating this input.
        assert state.unused_data == b""
    assert client.updates == 1


@pytest.mark.parametrize("width,height", [(0, 8), (8, 0), (0, 0)])
@pytest.mark.parametrize("drawing", [True, False])
def test_zero_area_zrle_rectangles_cannot_keep_feeding_a_finished_stream(width: int, height: int, drawing: bool) -> None:
    client = client_for(drawing)
    run(update(client, rfb.ZRLE, zlib.compress(b""), width=width, height=height))
    assert client._zrle.eof and client._zrle.unused_data == b""
    for _ in range(3):
        with pytest.raises(rfb.RfbError) as ended:
            run(update(client, rfb.ZRLE, b"unconsumed input" * 4, width=width, height=height))
        assert ended.value.code == rfb.PROTOCOL
        assert client._zrle.unused_data == b""
    assert client.updates == 1


@pytest.mark.parametrize("encoding,stream", STREAMS)
def test_sync_flushed_streams_continue_when_an_idle_viewer_resumes(encoding: int, stream: int) -> None:
    client = client_for(False)
    compressor = zlib.compressobj()
    plain = pixels(encoding)
    run(update(client, encoding, compressor.compress(plain) + compressor.flush(zlib.Z_SYNC_FLUSH), stream))
    client.drawing = True
    run(update(client, encoding, compressor.compress(plain) + compressor.flush(zlib.Z_SYNC_FLUSH), stream))
    assert not inflater(client, encoding, stream).eof
    assert client.updates == 2 and client.frames == 1
    assert bytes(client.rgb) == b"\x11\x22\x33" * 64


@pytest.mark.parametrize("stream", range(4))
@pytest.mark.parametrize("drawing", [True, False])
def test_a_tight_reset_can_replace_a_finished_stream(stream: int, drawing: bool) -> None:
    client = client_for(drawing)
    compressed = zlib.compress(pixels(rfb.TIGHT))
    run(update(client, rfb.TIGHT, compressed, stream))
    original = client._tight[stream]
    assert original.eof
    run(update(client, rfb.TIGHT, compressed, stream, reset=True))
    assert client._tight[stream] is not original
    assert client._tight[stream].eof and client._tight[stream].unused_data == b""
    assert client.updates == 2
    if drawing:
        assert bytes(client.rgb) == b"\x11\x22\x33" * 64


@pytest.mark.parametrize("stream", range(4))
@pytest.mark.parametrize("drawing", [True, False])
def test_a_zero_area_tight_fill_can_reset_a_finished_stream(stream: int, drawing: bool) -> None:
    client = client_for(drawing)
    compressed = zlib.compress(pixels(rfb.TIGHT))
    run(update(client, rfb.TIGHT, compressed, stream))
    original = client._tight[stream]
    # Reset bits apply even on a fill, which has no compressed data, and when no pixels are drawn.
    fill = bytes([0x80 | (1 << stream), 0x11, 0x22, 0x33])
    client.stream = Scripted(struct.pack(">xH", 1) + rectangle_header((0, 0, 0, 0), rfb.TIGHT) + fill)
    run(client._update(client.clock() + 5))
    assert client._tight[stream] is not original and not client._tight[stream].eof
    run(update(client, rfb.TIGHT, compressed, stream))
    assert client.updates == 3 and client._tight[stream].unused_data == b""
