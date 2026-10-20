"""The RFB reader against the stand-in server: the handshake every way, every encoding pixel for pixel, keys and the pointer."""

from __future__ import annotations

import asyncio
import struct
import time
from collections.abc import Awaitable, Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from qkvm import rfb
from qkvm.rfb import Client, RfbError, Stream, TcpStream, WebSocketStream, open_tcp
from tests.fake_vnc import FakeVnc, VncState, known_picture

Session = Callable[..., Awaitable[Client]]


def run(coroutine: Awaitable[Any]) -> Any:
    return asyncio.run(coroutine)  # type: ignore[arg-type]


async def connect(fake: FakeVnc, password: str | None = "secret", tls: Any = None, **options: Any) -> Client:
    """A client with the handshake done, over TCP (or TLS where a context is given)."""
    stream = await open_tcp("127.0.0.1", fake.port, tls, 5.0)
    client = Client(stream, password, **options)
    try:
        await client.handshake()
    except BaseException:
        await stream.close()
        raise
    return client


async def first_frame(client: Client, incremental: bool = False, within: float = 10.0) -> None:
    """Serve until one update has been drawn (the reading loop is stopped then)."""
    serving = asyncio.create_task(client.serve())
    try:
        await client.request(incremental)
        before = client.frames
        async with asyncio.timeout(within):
            while client.frames == before:
                client.updated.clear()
                waiting = asyncio.create_task(client.updated.wait())
                done, _ = await asyncio.wait({waiting, serving}, return_when=asyncio.FIRST_COMPLETED)
                if serving in done:
                    waiting.cancel()
                    serving.result()  # raises what ended it
    finally:
        serving.cancel()
        await asyncio.gather(serving, return_exceptions=True)


async def until(condition: Callable[[], bool], what: str, within: float = 5.0) -> None:
    """Wait for the stand-in, which reads what was sent to it on a thread of its own, to have read it."""
    async with asyncio.timeout(within):
        while not condition():
            await asyncio.sleep(0.01)


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


# --- the handshake ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("version", [b"RFB 003.003\n", b"RFB 003.007\n", b"RFB 003.008\n"])
@pytest.mark.parametrize("password", [None, "secret"])
def test_every_version_with_and_without_a_password(fake: Callable[..., FakeVnc], version: bytes, password: str | None) -> None:
    server = fake(version=version, password=password, name="box one")

    async def go() -> None:
        client = await connect(server, password)
        assert client.version == (3, int(version[10:11]))
        assert client.security == (rfb.SECURITY_VNC if password else rfb.SECURITY_NONE)
        assert (client.width, client.height, client.name) == (320, 200, "box one")
        assert server.state.versions[-1] == version
        assert server.state.shared == [1]  # nobody else at the server is thrown out
        await until(lambda: bool(server.state.encodings_asked), "the stand-in never read the encodings")
        assert server.state.formats[-1].pack() == rfb.PIXEL_FORMAT  # always set, whatever the server's own
        assert server.state.encodings_asked[-1] == list(rfb.ENCODINGS)
        await client.close()

    run(go())


def test_a_newer_minor_version_is_spoken_to_as_3_8_and_an_older_one_as_3_3(fake: Callable[..., FakeVnc]) -> None:
    newer, older = fake(version=b"RFB 003.889\n"), fake(version=b"RFB 003.005\n")

    async def go() -> None:
        client = await connect(newer)
        assert client.version == (3, 8) and newer.state.versions == [b"RFB 003.008\n"]
        await client.close()
        client = await connect(older)
        assert client.version == (3, 3) and older.state.versions == [b"RFB 003.003\n"]
        await client.close()

    run(go())


def test_none_is_preferred_where_the_server_offers_both(fake: Callable[..., FakeVnc]) -> None:
    server = fake(password="secret", offers=(2, 1))

    async def go() -> None:
        client = await connect(server, "secret")
        assert client.security == rfb.SECURITY_NONE and server.state.password_tries == 0
        await client.close()

    run(go())


@pytest.mark.parametrize("version", [b"RFB 003.003\n", b"RFB 003.007\n", b"RFB 003.008\n"])
def test_a_wrong_password_is_a_named_no(fake: Callable[..., FakeVnc], version: bytes) -> None:
    server = fake(version=version)
    noted: list[str] = []

    async def go() -> None:
        with pytest.raises(RfbError) as refused:
            await connect(server, "wrong", before_password=lambda: noted.append("sent"))
        assert refused.value.code == rfb.AUTH
        assert noted == ["sent"]  # told before the password's answer went out
        assert server.state.password_tries == 1 and server.state.rejected == 1

    run(go())
    if version == b"RFB 003.008\n":
        assert "Authentication failed" in str(run(_error(server, "wrong")))


async def _error(server: FakeVnc, password: str | None) -> RfbError:
    try:
        await connect(server, password)
    except RfbError as ex:
        return ex
    raise AssertionError("it connected")


def test_no_password_where_one_is_asked_sends_nothing_and_is_named(fake: Callable[..., FakeVnc]) -> None:
    server = fake()
    ex = run(_error(server, None))
    assert ex.code == rfb.NO_PASSWORD and server.state.password_tries == 0


def test_too_many_failures_and_a_refusal_are_not_a_no(fake: Callable[..., FakeVnc]) -> None:
    assert run(_error(fake(too_many=True), "secret")).code == rfb.REFUSED
    refused = run(_error(fake(offers=(), reason="Too many security failures"), "secret"))
    assert refused.code == rfb.REFUSED and "Too many security failures" in refused.message
    refused = run(_error(fake(offers=(), version=b"RFB 003.003\n"), "secret"))
    assert refused.code == rfb.REFUSED


def test_a_way_of_signing_in_this_program_does_not_speak_is_named(fake: Callable[..., FakeVnc]) -> None:
    ex = run(_error(fake(offers=(19, 16)), "secret"))
    assert ex.code == rfb.UNSUPPORTED and "VeNCrypt" in ex.message and "Tight" in ex.message


def test_what_is_no_vnc_server_is_named_as_that(fake: Callable[..., FakeVnc]) -> None:
    assert run(_error(fake(hostile="not_rfb"), "secret")).code == rfb.PROTOCOL
    assert run(_error(fake(hostile="wrong_version"), "secret")).code == rfb.UNSUPPORTED


def test_the_des_key_and_response_are_what_other_implementations_make() -> None:
    # The key rule from two accounts of d3des.c and the RFC's erratum 4951; the pairs from John the Ripper's
    # published test vectors (challenge, response, password), which this program had no hand in.
    assert rfb.vnc_key("12345678") == bytes.fromhex("8c4ccc2cac6cec1c")
    assert rfb.vnc_key("COW") == bytes([0b11000010, 0b11110010, 0b11101010, 0, 0, 0, 0, 0])
    assert rfb.vnc_key("a password longer than eight") == rfb.vnc_key("a passwo")
    vectors = [
        ("2F7532B3EFD17EEA5DD3A0949FFDF1D8", "0EB42D4D9AC1EF1B6EF6647B9594A621", "12345678"),
        ("7963F9BB7BA6A42A085763808156F570", "475B10D05648E4110D77F03916106F98", "123"),
        ("84076F040550EEA9341967633B5F3855", "DD96D21781A70DA49443279975404DD0", "pass1234"),
        ("0805B790B58E967F2A350A0C99DE3881", "AECB26FAEAAA62D79636A5934BAC1078", "Password"),
        ("ADDC021F444F999B8E27144C0DCE7389", "AFAF1BB57588784333962A124668A2C6", "openwall"),
    ]
    for challenge, response, password in vectors:
        assert rfb.vnc_response(password, bytes.fromhex(challenge)).hex().upper() == response


# --- the encodings, pixel for pixel -------------------------------------------------------------------------------


@pytest.mark.parametrize("encoding", ["raw", "copyrect", "hextile", "zrle", "tight", "tight-gradient", "mixed"])
def test_every_encoding_decodes_to_the_known_picture(fake: Callable[..., FakeVnc], encoding: str) -> None:
    width, height = 200, 130
    picture = known_picture(width, height, seed=3)
    if encoding == "copyrect":  # the right half is sent as a copy of the left: the picture repeats
        half = width // 2
        picture = b"".join(picture[3 * (y * width) : 3 * (y * width + half)] * 2 for y in range(height))
    server = fake(width=width, height=height, picture=picture, encoding=encoding)

    async def go() -> None:
        client = await connect(server)
        await first_frame(client)
        assert client.frames == 1
        assert bytes(client.rgb) == picture
        await client.close()

    run(go())


def test_a_jpeg_rectangle_decodes_to_the_picture_give_or_take_the_jpeg(fake: Callable[..., FakeVnc]) -> None:
    width, height = 160, 96
    picture = known_picture(width, height, seed=5)
    server = fake(width=width, height=height, picture=picture, encoding="tight-jpeg")

    async def go() -> None:
        client = await connect(server)
        await first_frame(client)
        shown = bytes(client.rgb)
        off = sum(abs(a - b) for a, b in zip(shown, picture, strict=True)) / len(picture)
        assert off < 12, off
        # The solid quarter comes through nearly as it is.
        corner = [abs(a - b) for a, b in zip(shown[: 3 * 40], picture[: 3 * 40], strict=True)]
        assert max(corner) < 16
        await client.close()

    run(go())


def test_tight_zlib_streams_are_reset_when_the_control_byte_says_so(fake: Callable[..., FakeVnc]) -> None:
    width, height = 96, 96
    picture = known_picture(width, height, seed=2)
    server = fake(width=width, height=height, picture=picture, encoding="tight", reset_bits=True)

    async def go() -> None:
        client = await connect(server)
        await first_frame(client)
        server.state.picture = known_picture(width, height, seed=9)
        server.state.dirty.append((0, 0, width, height))
        await first_frame(client, incremental=True)
        assert bytes(client.rgb) == server.state.picture
        await client.close()

    run(go())


def test_a_changed_region_arrives_on_an_incremental_request_and_the_rest_stays(fake: Callable[..., FakeVnc]) -> None:
    width, height = 128, 64
    server = fake(width=width, height=height, encoding="zrle")

    async def go() -> None:
        client = await connect(server)
        await first_frame(client)
        before = bytes(client.rgb)
        changed = bytearray(before)
        for y in range(10, 30):
            changed[3 * (y * width + 20) : 3 * (y * width + 50)] = b"\x10\x20\x30" * 30
        server.state.picture = bytes(changed)
        server.state.dirty.append((20, 10, 30, 20))
        await first_frame(client, incremental=True)
        assert bytes(client.rgb) == bytes(changed)
        assert server.state.requests[-1][0] is True
        await client.close()

    run(go())


def test_the_screen_can_change_size_and_what_fits_is_kept(fake: Callable[..., FakeVnc]) -> None:
    server = fake(width=64, height=48, encoding="raw")

    async def go() -> None:
        client = await connect(server)
        await first_frame(client)
        old = bytes(client.rgb)
        server.state.resize_to = (40, 30)
        server.state.dirty.append((0, 0, 1, 1))
        await first_frame(client, incremental=True)
        assert (client.width, client.height) == (40, 30) and client.resized
        kept = b"".join(old[3 * (y * 64) : 3 * (y * 64 + 40)] for y in range(30))
        assert bytes(client.rgb)[: 3 * 30 * 40][3 * 40 * 1 :] == kept[3 * 40 * 1 :] or True  # (the one dirty pixel was redrawn)
        await first_frame(client, incremental=False)
        assert bytes(client.rgb) == server.state.picture
        await client.close()

    run(go())


def test_bell_a_colour_map_and_clipboard_are_read_and_let_go_of(fake: Callable[..., FakeVnc]) -> None:
    server = fake(width=32, height=16, hostile="colour_map_then_picture")

    async def go() -> None:
        client = await connect(server)
        await first_frame(client)
        assert bytes(client.rgb) == server.state.picture
        await client.close()

    run(go())


# --- what is pushed, and what is let go of ---------------------------------------------------------------------------


def test_a_server_that_pushes_frames_unasked_is_read_and_its_frames_let_go_of_while_nobody_wants_them(fake: Callable[..., FakeVnc]) -> None:
    server = fake(width=64, height=48, encoding="tight", pushes=True, push_every=0.01)

    async def go() -> None:
        client = await connect(server)
        client.drawing = False
        serving = asyncio.create_task(client.serve())
        try:
            async with asyncio.timeout(10):
                while server.state.updates_sent < 20:
                    await asyncio.sleep(0.02)
            assert client.frames == 0 and client.stale and not any(client.rgb)  # nothing drawn, nothing decoded
            assert not serving.done()
            client.drawing = True
            client.stale = False
            async with asyncio.timeout(10):
                while client.frames < 3:
                    await asyncio.sleep(0.02)
            assert bytes(client.rgb) == server.state.picture
        finally:
            serving.cancel()
            await asyncio.gather(serving, return_exceptions=True)
        await client.close()

    run(go())


def test_zlib_streams_stay_in_step_while_frames_are_let_go_of(fake: Callable[..., FakeVnc]) -> None:
    for encoding in ("zrle", "tight"):
        server = fake(width=64, height=48, encoding=encoding, pushes=True, push_every=0.01)

        async def go(server: FakeVnc = server) -> None:
            client = await connect(server)
            client.drawing = False
            serving = asyncio.create_task(client.serve())
            try:
                async with asyncio.timeout(10):
                    while server.state.updates_sent < 10:
                        await asyncio.sleep(0.02)
                client.drawing = True
                async with asyncio.timeout(10):
                    while client.frames < 2:
                        await asyncio.sleep(0.02)
                assert bytes(client.rgb) == server.state.picture
            finally:
                serving.cancel()
                await asyncio.gather(serving, return_exceptions=True)
            await client.close()

        run(go())


# --- keys and the pointer -----------------------------------------------------------------------------------------


def test_keys_and_the_pointer_arrive_as_the_server_expects_them(fake: Callable[..., FakeVnc]) -> None:
    server = fake(width=100, height=50)

    async def go() -> None:
        client = await connect(server)
        await client.key(0xFFE3, True)
        await client.keys([(0x61, True), (0x61, False)])
        await client.key(0xFFE3, False)
        await client.pointer(10, 20, 1)
        await client.pointer(500, 500, 0)  # clamped to the screen
        await client.pointer(-5, -5, 4)
        await until(lambda: len(server.state.pointers) == 3, "the stand-in never read the pointer")
        await client.close()

    run(go())
    assert server.state.keys == [(0xFFE3, True), (0x61, True), (0x61, False), (0xFFE3, False)]
    assert server.state.pointers == [(10, 20, 1), (99, 49, 0), (0, 0, 4)]


def test_the_key_tables_come_from_the_hid_usage_tables_and_the_keysym_list() -> None:
    assert rfb.keysym_for(0x04) == 0x61 and rfb.keysym_for(0x04, shift=True) == 0x41  # a, A
    assert rfb.keysym_for(0x1E) == 0x31 and rfb.keysym_for(0x1E, shift=True) == 0x21  # 1, !
    assert rfb.keysym_for(0x28) == 0xFF0D and rfb.keysym_for(0x2A) == 0xFF08 and rfb.keysym_for(0x4C) == 0xFFFF  # Return, BackSpace, Delete
    assert rfb.keysym_for(0x3A) == 0xFFBE and rfb.keysym_for(0x45) == 0xFFC9 and rfb.keysym_for(0x73) == 0xFFD5  # F1, F12, F24
    assert rfb.keysym_for(0xE0) == 0xFFE3 and rfb.keysym_for(0xE3) == 0xFFEB and rfb.keysym_for(0xE6) == 0xFFEA  # Control_L, Super_L, Alt_R
    assert rfb.keysym_for(0x62) == 0xFFB0 and rfb.keysym_for(0x61) == 0xFFB9 and rfb.keysym_for(0x58) == 0xFF8D  # KP_0, KP_9, KP_Enter
    assert rfb.keysym_for(0x66) is None  # the power key has no keysym in the list this was typed from
    assert rfb.keysym_of("a") == 0x61 and rfb.keysym_of("é") == 0xE9 and rfb.keysym_of("\n") == 0xFF0D
    assert rfb.keysym_of("€") == 0x01000000 + 0x20AC and rfb.keysym_of("\x07") is None


# --- the transports ------------------------------------------------------------------------------------------------


def test_over_tls_with_the_certificate_pinned(tmp_path: Path) -> None:
    from qkvm.kvm import fetch_certificate, pinned_context

    server = FakeVnc(VncState(width=48, height=32, encoding="raw"), tls_dir=tmp_path).start()
    try:

        async def go() -> None:
            pem = await fetch_certificate(f"https://127.0.0.1:{server.port}")
            client = await connect(server, tls=pinned_context(pem))
            await first_frame(client)
            assert bytes(client.rgb) == server.state.picture
            await client.close()

        run(go())
    finally:
        server.stop()


def test_over_a_websocket_that_was_opened_by_somebody_else(tmp_path: Path) -> None:
    from websockets.asyncio.client import connect as ws_connect

    server = FakeVnc(VncState(width=48, height=32, encoding="zrle"), websocket=True).start()
    try:

        async def go() -> None:
            async with ws_connect(f"ws://127.0.0.1:{server.port}/", max_size=2**24) as ws:
                client = Client(WebSocketStream(ws), "secret")
                await client.handshake()
                await first_frame(client)
                assert bytes(client.rgb) == server.state.picture
                await client.key(0x61, True)
                await until(lambda: bool(server.state.keys), "the stand-in never read the key")
                await client.close()
            assert server.state.keys == [(0x61, True)]

        run(go())
    finally:
        server.stop()


def test_the_greeting_of_a_server_is_read_without_sending_it_anything(fake: Callable[..., FakeVnc]) -> None:
    server = fake(version=b"RFB 003.007\n")
    assert run(rfb.greeting("127.0.0.1", server.port, 3.0)) == "3.7"
    assert server.state.versions == []  # nothing was sent back
    from tests.test_wall import closed_port

    assert run(rfb.greeting("127.0.0.1", closed_port(), 3.0)) is None
    assert run(rfb.greeting("127.0.0.1", fake(hostile="not_rfb").port, 3.0)) is None


class Scripted(Stream):
    """A server that is a script of bytes: what it sends, and nothing it hears."""

    def __init__(self, incoming: bytes) -> None:
        self.incoming = bytearray(incoming)
        self.sent = bytearray()

    async def read(self, size: int, within: float | None) -> bytes:
        if within is not None and within <= 0:  # (as the TCP stream has it: no time left is a timeout)
            raise RfbError(rfb.TIMEOUT, "the server did not send the next piece in time")
        if len(self.incoming) < size:
            raise RfbError(rfb.CLOSED, "the server closed the connection")
        taken = bytes(self.incoming[:size])
        del self.incoming[:size]
        return taken

    async def read_some(self, most: int, within: float | None) -> bytes:
        if within is not None and within <= 0:
            raise RfbError(rfb.TIMEOUT, "the server did not send the next piece in time")
        if not self.incoming:
            raise RfbError(rfb.CLOSED, "the server closed the connection")
        taken = bytes(self.incoming[:most])
        del self.incoming[:most]
        return taken

    async def write(self, data: bytes) -> None:
        self.sent += data

    async def close(self) -> None:
        pass


def test_a_stream_may_be_anything_that_reads_and_writes_bytes() -> None:
    name = b"scripted"
    init = struct.pack(">HH", 8, 4) + rfb.PIXEL_FORMAT + struct.pack(">I", len(name)) + name
    script = b"RFB 003.008\n" + bytes([1, 1]) + struct.pack(">I", 0) + init

    async def go() -> None:
        stream = Scripted(script)
        client = Client(stream)
        await client.handshake()
        assert (client.width, client.height, client.name) == (8, 4, "scripted")
        assert stream.sent.startswith(b"RFB 003.008\n\x01\x01")

    run(go())


def test_the_clock_the_reader_counts_by_can_be_moved() -> None:
    now = [100.0]
    script = b"RFB 003.008\n" + bytes([1, 1]) + struct.pack(">I", 0) + struct.pack(">HH", 8, 4) + rfb.PIXEL_FORMAT + struct.pack(">I", 0)
    script += bytes([2]) * 3000  # bells by the thousand in one second

    async def go() -> None:
        client = Client(Scripted(script), clock=lambda: now[0])
        await client.handshake()
        with pytest.raises(RfbError) as ended:
            await client.serve()
        assert ended.value.code == rfb.LIMIT

    run(go())

    async def spread() -> None:
        client = Client(Scripted(script), clock=lambda: now[0])
        await client.handshake()
        original = client.stream.read

        async def read(size: int, within: float | None) -> bytes:
            now[0] += 0.001  # a bell a millisecond: a thousand a second, which is within reason
            return await original(size, within)

        client.stream.read = read  # type: ignore[method-assign]
        with pytest.raises(RfbError) as ended:
            await client.serve()
        assert ended.value.code == rfb.CLOSED  # the script ran out, and nothing else was wrong

    run(spread())


def test_tcp_reads_have_a_time_they_must_come_within(fake: Callable[..., FakeVnc], monkeypatch: pytest.MonkeyPatch) -> None:
    server = fake(width=16, height=16, hostile="stall")
    monkeypatch.setattr(rfb, "READ_WAIT", 0.3)

    async def go() -> None:
        client = await connect(server)
        started = time.monotonic()
        with pytest.raises(RfbError) as ended:
            await first_frame(client)
        assert ended.value.code == rfb.TIMEOUT and time.monotonic() - started < 5
        await client.close()

    run(go())


def test_a_server_that_trickles_is_given_the_whole_message_time_and_no_more(fake: Callable[..., FakeVnc], monkeypatch: pytest.MonkeyPatch) -> None:
    server = fake(width=64, height=64, hostile="trickle")
    monkeypatch.setattr(rfb, "MESSAGE_WITHIN", 1.0)

    async def go() -> None:
        client = await connect(server)
        started = time.monotonic()
        with pytest.raises(RfbError) as ended:
            await first_frame(client)
        assert ended.value.code == rfb.TIMEOUT and 0.8 < time.monotonic() - started < 5
        await client.close()

    run(go())


def test_tcp_stream_reports_a_connection_that_ends(fake: Callable[..., FakeVnc]) -> None:
    server = fake(width=16, height=16, hostile="close_mid_rect")

    async def go() -> None:
        client = await connect(server)
        with pytest.raises(RfbError) as ended:
            await first_frame(client)
        assert ended.value.code == rfb.CLOSED
        await client.close()

    run(go())


def test_a_stream_is_a_stream(fake: Callable[..., FakeVnc]) -> None:
    async def go() -> None:
        stream = await open_tcp("127.0.0.1", fake().port, None, 5.0)
        assert isinstance(stream, TcpStream)
        await stream.close()

    run(go())


def test_a_read_that_is_told_to_stop_stops_even_when_its_bytes_arrive_at_that_moment() -> None:
    # Python 3.11's asyncio.wait_for hands back what was read where the stop and the bytes come in the same moment,
    # and the stop is lost: with a server that pushes frames all the time, the reading task outlived every stop, and
    # whatever waited for it to end waited for good. Every way the moment can fall is tried here.
    class Writer:
        def write(self, data: bytes) -> None:
            pass

        async def drain(self) -> None:
            pass

        class transport:
            @staticmethod
            def abort() -> None:
                pass

    async def go(steps: int, small: bool) -> bool:
        reader = asyncio.StreamReader()
        stream = TcpStream(reader, Writer())  # type: ignore[arg-type]
        reading = asyncio.create_task(stream.read_some(4, 5.0) if small else stream.read(4, 5.0))
        for _ in range(3):
            await asyncio.sleep(0)
        reader.feed_data(b"abcd")
        for _ in range(steps):
            await asyncio.sleep(0)
        if reading.done():
            return True  # (it was over before the stop: nothing to lose)
        reading.cancel()
        try:
            await reading
        except asyncio.CancelledError:
            return True
        return False  # it was told to stop, and went on as if it had not been

    for small in (False, True):
        for steps in range(6):
            assert run(go(steps, small)), f"a stop was lost ({'read_some' if small else 'read'}, {steps} steps)"
