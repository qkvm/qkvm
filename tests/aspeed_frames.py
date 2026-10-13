"""Frames in ASPEED's video format, made for the tests: what a management controller's chip would send.

The other half of qkvm.aspeed, written from the same description of the format. A frame is built block
by block and comes out as the bytes a controller would send, with the header that goes with them.
"""

from __future__ import annotations

import struct

from qkvm.aspeed import _AC_CHROMA, _AC_LUMA, _DC_CHROMA, _DC_LUMA, _ORDER, FrameHeader

Plane = list[int]  # the 64 quantized coefficients of one 8x8 plane, row after row


def _codes(table: tuple[tuple[int, ...], tuple[int, ...]]) -> dict[int, tuple[int, int]]:
    """What each value is written as: (code, its length in bits)."""
    counts, values = table
    found, code, at = {}, 0, 0
    for length, count in enumerate(counts, start=1):
        for _ in range(count):
            found[values[at]] = (code, length)
            code, at = code + 1, at + 1
        code <<= 1
    return found


_DC = {"luma": _codes(_DC_LUMA), "chroma": _codes(_DC_CHROMA)}
_AC = {"luma": _codes(_AC_LUMA), "chroma": _codes(_AC_CHROMA)}


class Frame:
    """One frame being written. Blocks go in the order they are added; `data` is the finished frame."""

    def __init__(
        self,
        width: int,
        height: int,
        *,
        half_colour: bool = False,
        strength: int = 4,
        correction_strength: int = 7,
        luma_for_colour: bool = False,
    ) -> None:
        side = 16 if half_colour else 8
        self.header = FrameHeader(
            width=width,
            height=height,
            grid_width=-(-width // side) * side,
            grid_height=-(-height // side) * side,
            half_colour=half_colour,
            strength=strength,
            correction_strength=correction_strength,
            luma_for_colour=luma_for_colour,
        )
        self._bits = 0
        self._length = 0
        self._before = {"y": 0, "cb": 0, "cr": 0}  # each plane's first coefficient counts on from the last one's

    def _put(self, value: int, length: int) -> None:
        self._bits = (self._bits << length) | (value & ((1 << length) - 1))
        self._length += length

    def _start(self, kind: int, at: tuple[int, int] | None) -> None:
        if at is None:
            self._put(kind, 4)
        else:
            self._put(kind | 0x8, 4)
            self._put(at[0], 8)
            self._put(at[1], 8)

    def _plane(self, coefficients: Plane, which: str) -> None:
        tables = "luma" if which == "y" else "chroma"
        difference = coefficients[0] - self._before[which]
        self._before[which] = coefficients[0]
        size = abs(difference).bit_length()
        self._put(*_DC[tables][size])
        if size:
            self._put(difference if difference > 0 else difference + (1 << size) - 1, size)
        run = 0
        last = max((k for k in range(1, 64) if coefficients[_ORDER[k]]), default=0)
        for k in range(1, last + 1):
            value = coefficients[_ORDER[k]]
            if not value:
                run += 1
                continue
            while run > 15:
                self._put(*_AC[tables][0xF0])  # sixteen zeros
                run -= 16
            size = abs(value).bit_length()
            self._put(*_AC[tables][(run << 4) | size])
            self._put(value if value > 0 else value + (1 << size) - 1, size)
            run = 0
        if last < 63:
            self._put(*_AC[tables][0x00])  # the rest is zero

    def jpeg(self, y: Plane | list[Plane], cb: Plane, cr: Plane, at: tuple[int, int] | None = None, *, fine: bool = False, correction: bool = False) -> None:
        """A JPEG block: its planes' coefficients. With colour at half the detail, `y` is four planes."""
        self._start(0x2 if correction else 0x4 if fine else 0x0, at)
        for plane in y if isinstance(y[0], list) else [y]:
            self._plane(plane, "y")  # type: ignore[arg-type]
        self._plane(cb, "cb")
        self._plane(cr, "cr")

    def colours(self, listed: list[tuple[int, int | None]], pixels: list[int] | None = None, at: tuple[int, int] | None = None) -> None:
        """A block of one, two or four colours: for each, which of the four known ones it is and, if it is
        to be a new colour from now on, that colour (Y, Cb, Cr in one number); then which one every pixel is."""
        self._start({1: 0x5, 2: 0x6, 4: 0x7}[len(listed)], at)
        for which, colour in listed:
            self._put(0 if colour is None else 1, 1)
            self._put(which, 2)
            if colour is not None:
                self._put(colour, 24)
        if len(listed) > 1:
            assert pixels is not None and len(pixels) == 64
            for pixel in pixels:
                self._put(pixel, 1 if len(listed) == 2 else 2)

    def odd(self, kind: int) -> None:
        """A block of no kind there is (its first three bits; the sender's decoder takes no more of it)."""
        self._put(kind >> 1, 3)

    @property
    def data(self) -> bytes:
        bits, length = (self._bits << 4) | 0x9, self._length + 4  # the end mark
        spare = -length % 32
        words = (length + spare) // 32
        bits <<= spare
        found = [(bits >> (32 * (words - 1 - i))) & 0xFFFFFFFF for i in range(words)]
        return struct.pack(f"<{words + 3}I", *found, 0, 0, 0)  # (no block begins in a frame's last two words)


def console_screen(width: int = 800, height: int = 600, lines: int = 14, seed: int = 1) -> Frame:
    """A screen that looks like a server's text console from across the room: a title bar, and lines of "text"."""
    state = seed

    def below(limit: int) -> int:
        nonlocal state
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF
        return (state >> 8) % limit

    dark, bar, ink = 0x108080, 0x5A9A70, 0xD08080  # nearly black, a muted blue, light grey
    frame = Frame(width, height)
    across, down = -(-width // 8), -(-height // 8)
    lengths = {2 + 2 * line: 6 + below(across - 12) for line in range(lines)}
    for y in range(down):
        for x in range(across):
            if y == 0:
                frame.colours([(1, bar)])
            elif y in lengths and 1 <= x <= lengths[y] and below(6):
                # A letter, more or less: a few strokes in a box of 8 by 8, light on dark.
                strokes = [below(256) & below(256) for _ in range(5)]
                pixels = [(strokes[min(row - 1, 4)] >> col) & 1 if 1 <= row <= 6 and col < 6 else 0 for row in range(8) for col in range(8)]
                frame.colours([(0, dark), (2, ink)], pixels)
            else:
                frame.colours([(0, dark)])
    return frame
