"""A stand-in VNC server: enough of RFB for the reader, every encoding it reads, and the ways a server misbehaves.

It serves a known picture (`known_picture`), so that what the reader decodes can be compared pixel for
pixel, in whichever encoding a test asks for; it honours the pixel format the client sets, as a server
does; it can push full frames at its own pace and ignore the incremental flag, as obmc-ikvm does; and it
can be told to misbehave in the ways a hostile or broken server does (`hostile`). Its encoders are plain
functions, so that a test can build a session's bytes without a socket and mutate them.
"""

from __future__ import annotations

import asyncio
import os
import random
import socket
import ssl
import struct
import threading
import zlib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from qkvm.rfb import COPY_RECT, DESKTOP_SIZE, HEXTILE, RAW, TIGHT, ZRLE, vnc_response
from tests import local_socket
from tests.fake_kvm import make_device_certificate

Region = tuple[int, int, int, int]  # x, y, width, height


@dataclass
class PixelFormat:
    """The client's pixel format, as the sixteen bytes of SetPixelFormat say it."""

    bpp: int = 32
    depth: int = 24
    big_endian: bool = False
    true_colour: bool = True
    red_max: int = 255
    green_max: int = 255
    blue_max: int = 255
    red_shift: int = 16
    green_shift: int = 8
    blue_shift: int = 0

    @classmethod
    def read(cls, data: bytes) -> PixelFormat:
        bpp, depth, big, true, rmax, gmax, bmax, rs, gs, bs = struct.unpack(">BBBBHHHBBB3x", data)
        return cls(bpp, depth, big != 0, true != 0, rmax, gmax, bmax, rs, gs, bs)

    def pack(self) -> bytes:
        return struct.pack(">BBBBHHHBBB3x", self.bpp, self.depth, self.big_endian, self.true_colour, self.red_max, self.green_max, self.blue_max, self.red_shift, self.green_shift, self.blue_shift)

    def pixel(self, r: int, g: int, b: int) -> bytes:
        value = (r * self.red_max // 255) << self.red_shift | (g * self.green_max // 255) << self.green_shift | (b * self.blue_max // 255) << self.blue_shift
        return value.to_bytes(self.bpp // 8, "big" if self.big_endian else "little")

    def pixels(self, rgb: bytes) -> bytes:
        """A run of three-byte pixels in this format."""
        if self.bpp == 32 and (self.red_max, self.green_max, self.blue_max) == (255, 255, 255) and {self.red_shift, self.green_shift, self.blue_shift} <= {0, 8, 16, 24}:
            out = bytearray(len(rgb) // 3 * 4)
            for shift, plane in ((self.red_shift, rgb[0::3]), (self.green_shift, rgb[1::3]), (self.blue_shift, rgb[2::3])):
                at = 3 - shift // 8 if self.big_endian else shift // 8
                out[at::4] = plane
            return bytes(out)
        return b"".join(self.pixel(rgb[i], rgb[i + 1], rgb[i + 2]) for i in range(0, len(rgb), 3))

    def three(self) -> bool:
        """Whether ZRLE's pixel is three bytes in this format (RFC 6143, 7.7.5), and which three."""
        return self.bpp == 32 and self.depth <= 24 and self.true_colour


def known_picture(width: int, height: int, seed: int = 1) -> bytes:
    """A picture with something for every encoding: a solid quarter, two-colour text-like noise, a few-colour
    block pattern, a smooth gradient, and a strip of noise in every colour. Three bytes a pixel."""
    rng = random.Random(seed)
    solid = bytes((rng.randrange(256), rng.randrange(256), rng.randrange(256)))
    ink, paper = bytes((20, 20, 30)), bytes((235, 235, 225))
    few = [bytes((rng.randrange(256), rng.randrange(256), rng.randrange(256))) for _ in range(12)]
    half_w, half_h = width // 2, height // 2
    rows = []
    for y in range(height):
        row = bytearray()
        for x in range(width):
            if x < half_w and y < half_h:
                row += solid
            elif y < half_h:
                row += ink if rng.random() < 0.3 else paper
            elif x < half_w:
                row += few[(x // 4 + y // 4 * 7) % len(few)] if y < height - 8 else bytes((rng.randrange(256), rng.randrange(256), rng.randrange(256)))
            else:
                row += bytes(((x * 255) // max(1, width - 1), (y * 255) // max(1, height - 1), ((x + y) * 255) // max(2, width + height - 2)))
        rows.append(bytes(row))
    return b"".join(rows)


def crop(rgb: bytes, width: int, region: Region) -> bytes:
    x, y, w, h = region
    return b"".join(rgb[3 * ((y + r) * width + x) : 3 * ((y + r) * width + x + w)] for r in range(h))


# --- the encoders -------------------------------------------------------------------------------------------------


def _lengths(value: int) -> bytes:
    """A ZRLE run length as bytes: one less than the run, 255 meaning more follows."""
    value -= 1
    out = bytearray()
    while value >= 255:
        out.append(255)
        value -= 255
    out.append(value)
    return bytes(out)


def _runs(pixels: list[bytes]) -> list[tuple[bytes, int]]:
    runs: list[tuple[bytes, int]] = []
    for pixel in pixels:
        if runs and runs[-1][0] == pixel:
            runs[-1] = (pixel, runs[-1][1] + 1)
        else:
            runs.append((pixel, 1))
    return runs


def encode_raw(rgb: bytes, width: int, height: int, fmt: PixelFormat) -> bytes:
    return fmt.pixels(rgb)


def encode_hextile(rgb: bytes, width: int, height: int, fmt: PixelFormat, variety: int = 0) -> bytes:
    """Hextile: tiles of one colour as a background, of two as background, foreground and subrectangles, of more as
    coloured subrectangles where they fit (every other tile) and raw otherwise."""
    out = bytearray()
    tile_number = 0
    for top in range(0, height, 16):
        th = min(16, height - top)
        for left in range(0, width, 16):
            tw = min(16, width - left)
            tile = crop(rgb, width, (left, top, tw, th))
            pixels = [tile[i : i + 3] for i in range(0, len(tile), 3)]
            counted = Counter(pixels)
            tile_number += 1
            if len(counted) == 1:
                out += bytes([2]) + fmt.pixels(pixels[0])
                continue
            background = counted.most_common(1)[0][0]
            subrects: list[tuple[bytes, int, int, int, int]] = []
            for y in range(th):
                x = 0
                while x < tw:
                    pixel = pixels[y * tw + x]
                    if pixel == background:
                        x += 1
                        continue
                    run = 1
                    while x + run < tw and pixels[y * tw + x + run] == pixel:
                        run += 1
                    subrects.append((pixel, x, y, run, 1))
                    x += run
            two = len(counted) == 2
            if len(subrects) > 255 or (not two and (tile_number + variety) % 2 == 0):
                out += bytes([1]) + fmt.pixels(tile)
                continue
            sub = 2 | 8 | (0 if two else 16)
            if two:
                sub |= 4
            out += bytes([sub]) + fmt.pixels(background)
            if two:
                out += fmt.pixels(subrects[0][0])
            out += bytes([len(subrects)])
            for pixel, x, y, w, h in subrects:
                if not two:
                    out += fmt.pixels(pixel)
                out += bytes([(x << 4) | y, ((w - 1) << 4) | (h - 1)])
    return bytes(out)


def encode_zrle_tiles(rgb: bytes, width: int, height: int, fmt: PixelFormat, variety: int = 0) -> bytes:
    """The tiles of a ZRLE rectangle before zlib: solid, packed palette, palette RLE, plain RLE and raw, by what each tile holds."""
    cpixel = (lambda p: fmt.pixels(p)[:3]) if fmt.three() else fmt.pixels
    out = bytearray()
    tile_number = 0
    for top in range(0, height, 64):
        th = min(64, height - top)
        for left in range(0, width, 64):
            tw = min(64, width - left)
            tile = crop(rgb, width, (left, top, tw, th))
            pixels = [tile[i : i + 3] for i in range(0, len(tile), 3)]
            colours = list(dict.fromkeys(pixels))
            tile_number += 1
            if len(colours) == 1:
                out += bytes([1]) + cpixel(colours[0])
            elif len(colours) <= 16 and (tile_number + variety) % 3:
                bits = 1 if len(colours) == 2 else 2 if len(colours) <= 4 else 4
                out += bytes([len(colours)]) + b"".join(cpixel(c) for c in colours)
                for y in range(th):
                    acc, filled = 0, 0
                    for x in range(tw):
                        acc = (acc << bits) | colours.index(pixels[y * tw + x])
                        filled += bits
                        if filled == 8:
                            out.append(acc)
                            acc, filled = 0, 0
                    if filled:
                        out.append(acc << (8 - filled))
            elif len(colours) <= 127 and (tile_number + variety) % 2:
                out += bytes([128 + len(colours)]) + b"".join(cpixel(c) for c in colours)
                for pixel, run in _runs(pixels):
                    index = colours.index(pixel)
                    out += bytes([index]) if run == 1 else bytes([index | 0x80]) + _lengths(run)
            elif len(colours) <= 200:
                out += bytes([128])
                for pixel, run in _runs(pixels):
                    out += cpixel(pixel) + _lengths(run)
            else:
                out += bytes([0]) + b"".join(cpixel(p) for p in pixels)
    return bytes(out)


class ZrleStream:
    """The one zlib stream of a connection's ZRLE rectangles."""

    def __init__(self) -> None:
        self._zlib = zlib.compressobj()

    def rectangle(self, tiles: bytes) -> bytes:
        data = self._zlib.compress(tiles) + self._zlib.flush(zlib.Z_SYNC_FLUSH)
        return struct.pack(">I", len(data)) + data


def compact_length(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def gradient(rgb: bytes, width: int, height: int) -> bytes:
    """Tight's gradient filter applied: each sample as its difference from a guess made of its neighbours."""
    row = 3 * width
    out = bytearray(len(rgb))
    for y in range(height):
        for i in range(0, row, 3):
            for c in range(3):
                left = rgb[y * row + i + c - 3] if i else 0
                up = rgb[(y - 1) * row + i + c] if y else 0
                up_left = rgb[(y - 1) * row + i + c - 3] if y and i else 0
                guess = min(255, max(0, left + up - up_left))
                out[y * row + i + c] = (rgb[y * row + i + c] - guess) & 0xFF
    return bytes(out)


class TightStreams:
    """The four zlib streams of a connection's Tight rectangles, and how a rectangle is made with them."""

    def __init__(self, reset_each_time: bool = False) -> None:
        self._zlib = [zlib.compressobj() for _ in range(4)]
        self.reset_each_time = reset_each_time
        self.jpeg_quality = 8

    def fill(self, pixel: bytes) -> bytes:
        return bytes([0x80]) + pixel

    def jpeg(self, rgb: bytes, width: int, height: int) -> bytes:
        return bytes([0x90]) + compact_length(len(data := jpeg_of(rgb, width, height, self.jpeg_quality))) + data

    def basic(self, filtered: bytes, stream: int, filter_id: int | None, head: bytes = b"") -> bytes:
        """A rectangle with filter `filter_id` (None: the copy filter without saying so) on `stream`; `head` is the palette."""
        control = (stream << 4) | (0x40 if filter_id is not None else 0)
        reset = b""
        if self.reset_each_time:
            control |= 1 << stream
            self._zlib[stream] = zlib.compressobj()
        out = bytes([control]) + reset + (bytes([filter_id]) if filter_id is not None else b"") + head
        if len(filtered) < 12:
            return out + filtered
        data = self._zlib[stream].compress(filtered) + self._zlib[stream].flush(zlib.Z_SYNC_FLUSH)
        return out + compact_length(len(data)) + data

    def rectangle(self, rgb: bytes, width: int, height: int, kind: str = "tight") -> bytes:
        """One rectangle, in whatever of Tight suits the pixels (`kind` "tight"), or as a JPEG, or through the gradient filter."""
        pixels = [rgb[i : i + 3] for i in range(0, len(rgb), 3)]
        colours = list(dict.fromkeys(pixels))
        if kind == "tight-jpeg":
            return self.jpeg(rgb, width, height)
        if kind == "tight-gradient":
            return self.basic(gradient(rgb, width, height), 2, 2)
        if len(colours) == 1:
            return self.fill(colours[0])
        if len(colours) <= 256:
            head = bytes([len(colours) - 1]) + b"".join(colours)
            if len(colours) <= 2:
                rows = bytearray()
                for y in range(height):
                    acc, filled = 0, 0
                    for x in range(width):
                        acc = (acc << 1) | colours.index(pixels[y * width + x])
                        filled += 1
                        if filled == 8:
                            rows.append(acc)
                            acc, filled = 0, 0
                    if filled:
                        rows.append(acc << (8 - filled))
                return self.basic(bytes(rows), 1, 1, head)
            return self.basic(bytes(colours.index(p) for p in pixels), 1, 1, head)
        return self.basic(rgb, 0, 0 if len(colours) % 2 else None)


def jpeg_of(rgb: bytes, width: int, height: int, quality: int) -> bytes:
    """`rgb` as a JPEG, through the video library (which the reader also decodes with)."""
    import av

    frame = av.VideoFrame(width, height, "rgb24")
    plane = frame.planes[0]
    row = 3 * width
    if plane.line_size == row:
        plane.update(rgb)
    else:
        padded = bytearray(plane.line_size * height)
        for y in range(height):
            padded[y * plane.line_size : y * plane.line_size + row] = rgb[y * row : (y + 1) * row]
        plane.update(bytes(padded))
    frame = frame.reformat(format="yuvj420p")
    codec: Any = av.CodecContext.create("mjpeg", "w")
    codec.width, codec.height, codec.pix_fmt = width, height, "yuvj420p"
    quantizer = max(2, 12 - quality)
    codec.options = {"qmin": str(quantizer), "qmax": str(quantizer)}
    frame.pts = 0
    packets = codec.encode(frame) + codec.encode(None)
    return bytes(packets[0])


def rectangle_header(region: Region, encoding: int) -> bytes:
    x, y, w, h = region
    return struct.pack(">HHHHi", x, y, w, h, encoding)


def update_message(rectangles: list[bytes]) -> bytes:
    return struct.pack(">BxH", 0, len(rectangles)) + b"".join(rectangles)


# --- the server ------------------------------------------------------------------------------------------------------


@dataclass
class VncState:
    password: str | None = "secret"  # the VNC password; None: the server asks for none (security type None)
    version: bytes = b"RFB 003.008\n"
    offers: tuple[int, ...] | None = None  # security types offered (3.7 and up); None: VNC authentication with a password, None without
    width: int = 320
    height: int = 200
    name: str = "stand-in VNC"
    seed: int = 1
    picture: bytes = b""  # three bytes a pixel; made from the seed when left empty
    encoding: str = "tight"  # raw | copyrect | hextile | zrle | tight | tight-jpeg | tight-gradient | mixed
    pushes: bool = False  # like obmc-ikvm: full frames at its own pace, the incremental flag ignored
    push_every: float = 0.05
    hostile: str = ""  # a way to misbehave (see FakeVnc._misbehave)
    stall: float = 0.0  # seconds the server stalls before answering anything
    reset_bits: bool = False  # Tight: reset the zlib stream with every rectangle, as the control byte allows
    resize_to: tuple[int, int] | None = None  # when set, the next update ends with a new screen size (then the picture is made anew)
    too_many: bool = False  # answer every sign-in with "too many failures" (2)
    reason: str = "Too many security failures"  # what is said with a refusal
    # Manners of Intel AMT's KVM, seen on a real one: its own format in ServerInit (RGB565), the connection reset at a
    # SetPixelFormat of another number of bits, a Bell before the first answer, and the first request answered with
    # the screen's size alone (the whole screen comes with the next request, incremental or not).
    server_format: PixelFormat | None = None
    takes_bpp: tuple[int, ...] | None = None
    bell_first: bool = False
    size_first: bool = False
    drops_keys_for: float = 0.0  # seconds after its ServerInit during which key events are dropped
    # What happened, for the tests to look at.
    connections: int = 0
    handshakes: int = 0  # completed, screen size and name sent
    password_tries: int = 0
    rejected: int = 0
    versions: list[bytes] = field(default_factory=list)
    shared: list[int] = field(default_factory=list)
    formats: list[PixelFormat] = field(default_factory=list)
    encodings_asked: list[list[int]] = field(default_factory=list)
    requests: list[tuple[bool, int, int, int, int]] = field(default_factory=list)
    keys: list[tuple[int, bool]] = field(default_factory=list)
    pointers: list[tuple[int, int, int]] = field(default_factory=list)
    cut_texts: list[bytes] = field(default_factory=list)
    dirty: list[Region] = field(default_factory=list)  # changed since the last update: an incremental request is answered with these
    updates_sent: int = 0
    open: int = 0  # connections open right now

    bombs: dict[str, bytes] = field(default_factory=dict)  # made here, before a test measures the reader's memory

    def __post_init__(self) -> None:
        if not self.picture:
            self.picture = known_picture(self.width, self.height, self.seed)
        if self.hostile == "zlib_bomb":
            self.bombs["zrle"] = zlib.compress(b"\0" * (50 * 1024 * 1024), 9)
        if self.hostile == "tight_bomb":
            packer = zlib.compressobj(9)
            self.bombs["tight"] = packer.compress(b"\0" * (50 * 1024 * 1024)) + packer.flush(zlib.Z_SYNC_FLUSH)
        if self.hostile == "rectangle_flood":
            # (Made here as well: made after the handshake, in the stand-in's thread of the same process, a busy computer
            # made it while the reader's memory was being measured, and the measure counted its 7.9 MB.)
            self.bombs["rectangles"] = update_message([rectangle_header((0, 0, 0, 0), RAW)] * 65535) * 2


class _Wire:
    """What a connection is to the handler: exact reads and writes, over TCP or a WebSocket."""

    async def read(self, size: int) -> bytes:
        raise NotImplementedError

    async def write(self, data: bytes) -> None:
        raise NotImplementedError

    async def close(self) -> None:
        raise NotImplementedError


class _Tcp(_Wire):
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader, self.writer = reader, writer

    async def read(self, size: int) -> bytes:
        return await self.reader.readexactly(size)

    async def write(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()

    async def close(self) -> None:
        self.writer.close()


class _WebSocket(_Wire):
    def __init__(self, ws: Any) -> None:
        self.ws = ws
        self.held = bytearray()

    async def read(self, size: int) -> bytes:
        while len(self.held) < size:
            self.held += await self.ws.recv()
        taken = bytes(self.held[:size])
        del self.held[:size]
        return taken

    async def write(self, data: bytes) -> None:
        await self.ws.send(data)

    async def close(self) -> None:
        await self.ws.close()


class FakeVnc:
    """Runs a stand-in VNC server on a localhost port in a thread of its own. `tls_dir`: serve TLS with a made certificate.
    `websocket`: serve the same bytes as the binary messages of a WebSocket."""

    def __init__(self, state: VncState | None = None, port: int = 0, tls_dir: Path | None = None, websocket: bool = False, sock: socket.socket | None = None) -> None:
        self.state = state or VncState()
        self._sock = sock if sock is not None else local_socket(port)  # (`sock`: one bound already, where the port had to be a particular one)
        self.port: int = self._sock.getsockname()[1]
        self._tls: ssl.SSLContext | None = None
        if tls_dir is not None:
            cert, key = make_device_certificate(tls_dir)
            self._tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._tls.load_cert_chain(cert, key)
        self._websocket = websocket
        scheme = "vncs" if tls_dir is not None else "vnc"
        self.url = f"{scheme}://127.0.0.1:{self.port}"
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop: asyncio.Event | None = None
        self._started = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._connections: set[asyncio.Task[None]] = set()

    def start(self) -> FakeVnc:
        self._thread.start()
        if not self._started.wait(10):
            raise RuntimeError("fake VNC server did not start")
        return self

    def stop(self) -> None:
        """Ends the server; a server that is stopped already stays so."""
        if self._loop is not None and self._stop is not None and not self._loop.is_closed():
            self._loop.call_soon_threadsafe(self._stop.set)
        if self._thread.is_alive():
            self._thread.join(timeout=10)

    def drop_everybody(self) -> None:
        """End every connection there is, as a server that restarts does."""
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._drop)

    def _drop(self) -> None:
        for task in list(self._connections):
            task.cancel()

    def _run(self) -> None:
        asyncio.run(self._main())

    async def _main(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._stop = asyncio.Event()
        # (Leaving the server's `async with` waits for every connection to end: they are ended first.)
        if self._websocket:
            from websockets.asyncio.server import serve

            async with serve(self._ws_handler, sock=self._sock, ssl=self._tls, max_size=2**24):
                self._started.set()
                await self._stop.wait()
                await self._ended()
        else:
            server = await asyncio.start_server(self._tcp_handler, sock=self._sock, ssl=self._tls)
            async with server:
                self._started.set()
                await self._stop.wait()
                await self._ended()

    async def _ended(self) -> None:
        self._drop()
        if self._connections:
            await asyncio.wait(self._connections, timeout=2)

    async def _tcp_handler(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await self._handle(_Tcp(reader, writer))

    async def _ws_handler(self, ws: Any) -> None:
        await self._handle(_WebSocket(ws))

    async def _handle(self, wire: _Wire) -> None:
        task = asyncio.current_task()
        assert task is not None
        self._connections.add(task)
        self.state.connections += 1
        self.state.open += 1
        try:
            await self._session(wire)
        except (asyncio.IncompleteReadError, ConnectionError, OSError, asyncio.CancelledError):
            pass
        except Exception as ex:  # (a WebSocket's own "closed", and anything a test did not foresee)
            if type(ex).__name__ not in ("ConnectionClosedOK", "ConnectionClosedError", "ConnectionClosed"):
                raise
        finally:
            self.state.open -= 1
            self._connections.discard(task)
            try:
                await wire.close()
            except Exception:
                pass

    async def _session(self, wire: _Wire) -> None:
        state = self.state
        if state.stall:
            await asyncio.sleep(state.stall)
        if state.hostile == "not_rfb":
            await wire.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return
        if state.hostile == "wrong_version":
            await wire.write(b"RFB 004.000\n")
            await wire.read(12)
            return
        await wire.write(state.version)
        theirs = await wire.read(12)
        state.versions.append(theirs)
        minor = int(theirs[8:11])
        if state.password is None:
            offers: tuple[int, ...] = (1,)
        else:
            offers = (2,)
        if state.offers is not None:
            offers = state.offers
        if minor == 3:
            chosen = 0 if not offers else offers[0]
            await wire.write(struct.pack(">I", chosen))
            if chosen == 0:
                await self._reason(wire)
                return
        else:
            await wire.write(bytes([len(offers), *offers]))
            if not offers:
                await self._reason(wire)
                return
            chosen = (await wire.read(1))[0]
            if chosen not in offers:
                return
        if chosen == 2:
            challenge = os.urandom(16)
            await wire.write(challenge)
            answer = await wire.read(16)
            state.password_tries += 1
            if state.too_many:
                await wire.write(struct.pack(">I", 2))
                return
            if state.password is None or answer != vnc_response(state.password, challenge):
                state.rejected += 1
                await wire.write(struct.pack(">I", 1))
                if minor == 8:
                    await self._reason(wire, "Authentication failed")
                return
            await wire.write(struct.pack(">I", 0))
        elif minor == 8:
            await wire.write(struct.pack(">I", 0))
        state.shared.append((await wire.read(1))[0])
        if state.hostile == "huge_screen":
            await wire.write(struct.pack(">HH", 60000, 60000) + PixelFormat().pack() + struct.pack(">I", 4) + b"huge")
            return
        if state.hostile == "zero_screen":
            await wire.write(struct.pack(">HH", 0, 0) + PixelFormat().pack() + struct.pack(">I", 4) + b"none")
            return
        if state.hostile == "huge_name":
            await wire.write(struct.pack(">HH", 64, 64) + PixelFormat().pack() + struct.pack(">I", 2**31))
            return
        name = state.name.encode()
        await wire.write(struct.pack(">HH", state.width, state.height) + (state.server_format or PixelFormat()).pack() + struct.pack(">I", len(name)) + name)
        state.handshakes += 1
        if state.hostile == "drop_after_handshake":
            return  # lets the client in, and hangs up at once
        await self._messages(wire)

    async def _reason(self, wire: _Wire, text: str | None = None) -> None:
        said = (text or self.state.reason).encode()
        await wire.write(struct.pack(">I", len(said)) + said)

    async def _messages(self, wire: _Wire) -> None:
        state = self.state
        fmt = PixelFormat()
        zrle = ZrleStream()
        tight = TightStreams(state.reset_bits)
        pending: tuple[bool, Region] | None = None
        answered = False  # (the first request is answered as `bell_first` and `size_first` say)
        taking_keys_at = asyncio.get_running_loop().time() + state.drops_keys_for
        pusher: asyncio.Task[None] | None = None
        rectangles_sent = 0

        async def send(regions: list[Region], full: bool) -> None:
            nonlocal rectangles_sent, answered
            if not answered:
                answered = True
                if state.bell_first:
                    await wire.write(bytes([2]))
                if state.size_first:
                    state.dirty = [(0, 0, state.width, state.height)]
                    state.updates_sent += 1
                    await wire.write(update_message([rectangle_header((0, 0, state.width, state.height), DESKTOP_SIZE)]))
                    return
            rectangles: list[bytes] = []
            for number, region in enumerate(regions):
                x, y, w, h = region
                rgb = crop(state.picture, state.width, region)
                kind = state.encoding
                if kind == "mixed":
                    kind = ("raw", "hextile", "zrle", "tight", "tight-jpeg", "tight-gradient")[(rectangles_sent + number) % 6]
                if kind == "raw":
                    rectangles.append(rectangle_header(region, RAW) + encode_raw(rgb, w, h, fmt))
                elif kind == "copyrect" and full and w >= 2:
                    half = w // 2
                    left = crop(rgb, w, (0, 0, half, h))
                    rectangles.append(rectangle_header((x, y, half, h), RAW) + encode_raw(left, half, h, fmt))
                    rectangles.append(rectangle_header((x + half, y, w - half, h), COPY_RECT) + struct.pack(">HH", x, y))
                elif kind == "copyrect":
                    rectangles.append(rectangle_header(region, RAW) + encode_raw(rgb, w, h, fmt))
                elif kind == "hextile":
                    rectangles.append(rectangle_header(region, HEXTILE) + encode_hextile(rgb, w, h, fmt, rectangles_sent))
                elif kind == "zrle":
                    rectangles.append(rectangle_header(region, ZRLE) + zrle.rectangle(encode_zrle_tiles(rgb, w, h, fmt, rectangles_sent)))
                else:
                    rectangles.append(rectangle_header(region, TIGHT) + tight.rectangle(rgb, w, h, kind))
            if state.resize_to is not None:
                new_w, new_h = state.resize_to
                state.resize_to = None
                state.width, state.height = new_w, new_h
                state.picture = known_picture(new_w, new_h, state.seed + 1)
                rectangles.append(rectangle_header((0, 0, new_w, new_h), DESKTOP_SIZE))
            rectangles_sent += len(rectangles)
            state.updates_sent += 1
            await wire.write(update_message(rectangles))

        async def push() -> None:
            while True:
                await asyncio.sleep(state.push_every)
                await send([(0, 0, state.width, state.height)], True)

        if state.pushes:
            pusher = asyncio.create_task(push())
        try:
            while True:
                if pending is not None and not state.pushes:
                    incremental, region = pending
                    if not incremental:
                        pending = None
                        await send([region], True)
                        continue
                    if state.dirty:
                        regions, state.dirty = list(state.dirty), []
                        pending = None
                        await send(regions, False)
                        continue
                    # (Nothing changed: the request stays open, as a server keeps it, and is looked at again shortly.)
                    try:
                        async with asyncio.timeout(0.02):  # (not wait_for, which loses a stop up to Python 3.11)
                            kind = (await wire.read(1))[0]
                    except TimeoutError:
                        continue
                else:
                    kind = (await wire.read(1))[0]
                if kind == 0:  # SetPixelFormat
                    fmt = PixelFormat.read((await wire.read(19))[3:])
                    state.formats.append(fmt)
                    if state.takes_bpp is not None and fmt.bpp not in state.takes_bpp:
                        return  # (hung up on, as Intel AMT's KVM does at a format it does not take)
                elif kind == 2:  # SetEncodings
                    (count,) = struct.unpack(">xH", await wire.read(3))
                    asked = list(struct.unpack(f">{count}i", await wire.read(4 * count)))
                    state.encodings_asked.append(asked)
                    for level in asked:
                        if -32 <= level <= -23:
                            tight.jpeg_quality = level + 32
                elif kind == 3:  # FramebufferUpdateRequest
                    incremental, x, y, w, h = struct.unpack(">BHHHH", await wire.read(9))
                    state.requests.append((incremental != 0, x, y, w, h))
                    if state.hostile and not state.pushes:
                        await self._misbehave(wire, fmt, zrle, tight)
                        return
                    if not state.pushes:
                        pending = (incremental != 0, (0, 0, state.width, state.height))
                elif kind == 4:  # KeyEvent
                    down, keysym = struct.unpack(">BxxI", await wire.read(7))
                    if asyncio.get_running_loop().time() >= taking_keys_at:
                        state.keys.append((keysym, down != 0))
                elif kind == 5:  # PointerEvent
                    buttons, x, y = struct.unpack(">BHH", await wire.read(5))
                    state.pointers.append((x, y, buttons))
                elif kind == 6:  # ClientCutText
                    (length,) = struct.unpack(">3xI", await wire.read(7))
                    state.cut_texts.append(await wire.read(length))
                else:
                    return
        finally:
            if pusher is not None:
                pusher.cancel()

    async def _misbehave(self, wire: _Wire, fmt: PixelFormat, zrle: ZrleStream, tight: TightStreams) -> None:
        """What a hostile or broken server sends after the handshake, by `state.hostile`."""
        state = self.state
        how = state.hostile
        w, h = state.width, state.height
        whole = (0, 0, w, h)
        rgb = state.picture
        if how == "rect_outside":
            await wire.write(update_message([rectangle_header((w - 10, 0, 20, 10), RAW) + encode_raw(crop(rgb, w, (0, 0, 20, 10)), 20, 10, fmt)]))
        elif how == "copy_from_outside":
            await wire.write(update_message([rectangle_header((0, 0, 20, 10), COPY_RECT) + struct.pack(">HH", w - 10, 0)]))
        elif how == "unknown_encoding":
            await wire.write(update_message([rectangle_header(whole, 2) + b"\0" * 8]))
        elif how == "unknown_message":
            await wire.write(bytes([99]) + b"\0" * 20)
        elif how == "zlib_bomb":
            bomb = state.bombs["zrle"]
            await wire.write(update_message([rectangle_header(whole, ZRLE) + struct.pack(">I", len(bomb)) + bomb]))
        elif how == "tight_bomb":
            bomb = state.bombs["tight"]
            await wire.write(update_message([rectangle_header(whole, TIGHT) + bytes([0x00]) + compact_length(len(bomb)) + bomb]))
        elif how == "silent":
            await asyncio.sleep(3600)  # answers no request, ever
        elif how == "zlib_claims_more":
            await wire.write(update_message([rectangle_header(whole, ZRLE) + struct.pack(">I", 2**31)]))
        elif how == "tight_wide":
            await wire.write(update_message([rectangle_header((0, 0, 2100, 1), TIGHT) + bytes([0x80, 1, 2, 3])]))
        elif how == "resize_mid_update":
            first = rectangle_header(whole, RAW) + encode_raw(rgb, w, h, fmt)
            smaller = rectangle_header((0, 0, w // 2, h // 2), DESKTOP_SIZE)
            again = rectangle_header(whole, RAW) + encode_raw(rgb, w, h, fmt)
            await wire.write(update_message([first, smaller, again]))
        elif how == "stall":
            await wire.write(update_message([rectangle_header(whole, RAW)]))  # ...and then nothing
            await asyncio.sleep(3600)
        elif how == "one_frame_then_hang_up":
            # A whole frame, sent and drained, and then it hangs up at once: every time it lets the client in.
            await wire.write(update_message([rectangle_header(whole, RAW) + encode_raw(rgb, w, h, fmt)]))
            return
        elif how == "trickle":
            data = update_message([rectangle_header(whole, RAW) + encode_raw(rgb, w, h, fmt)])
            for i in range(0, len(data), 64):
                await wire.write(data[i : i + 64])
                await asyncio.sleep(0.5)
        elif how == "close_mid_rect":
            data = rectangle_header(whole, RAW) + encode_raw(rgb, w, h, fmt)
            await wire.write(update_message([data])[: len(data) // 2])
        elif how == "message_flood":
            await wire.write(bytes([2]) * 5000)
        elif how == "rectangle_flood":
            await wire.write(state.bombs["rectangles"])
        elif how == "cut_text_huge":
            await wire.write(struct.pack(">B3xI", 3, 2**31))
        elif how == "jpeg_wrong_size":
            picture = jpeg_of(crop(rgb, w, (0, 0, 16, 16)), 16, 16, 8)
            await wire.write(update_message([rectangle_header((0, 0, 32, 32), TIGHT) + bytes([0x90]) + compact_length(len(picture)) + picture]))
        elif how == "jpeg_garbage":
            await wire.write(update_message([rectangle_header((0, 0, 32, 32), TIGHT) + bytes([0x90]) + compact_length(300) + b"\xff\xd8" + b"\0" * 298]))
        elif how == "hextile_sub_outside":
            tile = bytes([8 | 2]) + fmt.pixels(b"\1\2\3") + bytes([1, 0xF0, 0x7F])  # one subrectangle at x 15 of width 8
            await wire.write(update_message([rectangle_header((0, 0, 16, 16), HEXTILE) + tile]))
        elif how == "zrle_bad_sub":
            await wire.write(update_message([rectangle_header((0, 0, 8, 8), ZRLE) + zrle.rectangle(bytes([50]) + b"\0" * 200)]))
        elif how == "zrle_leftover":
            await wire.write(update_message([rectangle_header((0, 0, 8, 8), ZRLE) + zrle.rectangle(bytes([1, 9, 9, 9]) + b"\0" * 10)]))
        elif how == "zrle_short":
            await wire.write(update_message([rectangle_header((0, 0, 8, 8), ZRLE) + zrle.rectangle(bytes([0]) + b"\0" * 10)]))
        elif how == "zrle_not_zlib":
            await wire.write(update_message([rectangle_header((0, 0, 8, 8), ZRLE) + struct.pack(">I", 20) + b"\xff" * 20]))
        elif how == "palette_index_past":
            head = bytes([2]) + b"\1\1\1\2\2\2\3\3\3"  # three colours...
            await wire.write(update_message([rectangle_header((0, 0, 4, 1), TIGHT) + tight.basic(bytes([0, 1, 7, 2]), 1, 1, head)]))
        elif how == "tight_bad_filter":
            await wire.write(update_message([rectangle_header((0, 0, 4, 1), TIGHT) + bytes([0x40, 9]) + b"\0" * 12]))
        elif how == "tight_bad_method":
            await wire.write(update_message([rectangle_header((0, 0, 4, 1), TIGHT) + bytes([0xA0]) + b"\0" * 12]))
        elif how == "colour_map_then_picture":
            entries = struct.pack(">BxHH", 1, 0, 100) + b"\0" * 600
            await wire.write(entries + bytes([2]) + struct.pack(">B3xI", 3, 5) + b"hello" + update_message([rectangle_header(whole, RAW) + encode_raw(rgb, w, h, fmt)]))
            await asyncio.sleep(3600)
        elif how == "desktop_size_huge":
            await wire.write(update_message([rectangle_header((0, 0, 9000, 9000), DESKTOP_SIZE)]))
        elif how == "read_ahead":
            # Three messages back to back, as a server may send them: an update of one Hextile tile, a Bell, and the whole
            # screen in Raw; cut where a WebSocket's message (or a TCP segment) may end, in the middle of the third.
            first = update_message([rectangle_header((0, 0, 16, 16), HEXTILE) + bytes([2]) + fmt.pixels(b"\x10\x20\x30")])
            data = first + bytes([2]) + update_message([rectangle_header(whole, RAW) + encode_raw(rgb, w, h, fmt)])
            cut = len(first) + 1 + 5
            await wire.write(data[:cut])
            await wire.write(data[cut:])
        else:
            raise AssertionError(f"no such misbehaviour: {how}")
        await asyncio.sleep(2)  # (the reader has ended the connection by then; a server that is gone is not what is tested)


# --- the same server, behind another program's WebSocket ----------------------------------------------------------


class Behind(FakeVnc):
    """The stand-in VNC server with no port of its own: spoken to over a WebSocket another stand-in accepted (a
    Proxmox console's, OpenBMC's /kvm/0), by `await Behind(state).serve(websocket)`."""

    def __init__(self, state: VncState) -> None:  # (FakeVnc's own makes a socket and a thread: neither is wanted here)
        self.state = state
        self._connections: set[asyncio.Task[None]] = set()

    async def serve(self, websocket: Any, most: int = 2**20) -> None:
        """One session over a Starlette WebSocket that is accepted already, in binary frames of at most `most` bytes."""
        await self._handle(_StarletteWire(websocket, most))


class _StarletteWire(_Wire):
    def __init__(self, ws: Any, most: int) -> None:
        self.ws, self.most = ws, most
        self.held = bytearray()

    async def read(self, size: int) -> bytes:
        while len(self.held) < size:
            try:
                came = await self.ws.receive_bytes()
            except Exception as ex:  # (Starlette's "disconnected", a text frame, a socket gone: the client went away)
                raise ConnectionError("the client went away") from ex
            self.held += came
        taken = bytes(self.held[:size])
        del self.held[:size]
        return taken

    async def write(self, data: bytes) -> None:
        try:
            for at in range(0, len(data), self.most):
                await self.ws.send_bytes(data[at : at + self.most])
        except Exception as ex:
            raise ConnectionError("the client went away") from ex

    async def close(self) -> None:
        try:
            await self.ws.close()
        except Exception:
            pass
