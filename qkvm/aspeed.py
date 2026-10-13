"""The picture a server's management controller sends, decoded: ASPEED's video format.

Most management controllers are built on a chip by ASPEED, and that chip compresses the server's screen
in a format of its own before the controller sends it to its console. This reads that format and keeps
the screen as it stands, as plain RGB.

The format, as far as this file needs to know it:

* A frame is a run of 32-bit words, least significant byte first; bits are taken from each word from
  the top down. It is a list of blocks, each beginning with four bits that say what kind it is, and
  ends with an end mark. A frame only brings the blocks that changed: everything else stays as it was.
* A block is 8x8 pixels (or 16x16, where colour is sent at half the detail). It follows the one
  before it, left to right and top to bottom, unless it says where it is.
* A block is either JPEG as the standard has it (the same Huffman tables, the same order of
  coefficients, the standard's quantization tables at one of eight strengths), or a list of one, two
  or four colours and, for every pixel, which of them it is. Colours are YCbCr.
* A JPEG block may be a correction to be added to what is there already ("pass two").

Nothing here trusts what it is given: a frame that makes no sense is refused or runs out, a block that
says it is outside the screen is not drawn, and no frame takes longer than its own length allows.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

# What a frame may cost. A controller is not trusted, and one in the wrong hands sends what it likes, for as
# long as somebody looks at the wall: nothing it sends takes more time or room than a screen of its size could.
LARGEST = 2048  # no screen is wider or taller than this (the chip that makes these pictures stops at 1920 by 1200)
LONGEST = 8 * 1024 * 1024  # nor does one screenful take more bytes than this, and none more than twice what it is unpacked
SPARE = 64  # blocks a frame may carry beyond two for every one its screen has


class Garbled(Exception):
    """What arrived is not a frame this decoder can make a picture of."""


@dataclass(frozen=True)
class FrameHeader:
    """What comes with a frame's data and says how to read it."""

    width: int  # the screen
    height: int
    grid_width: int  # the same, as the blocks are counted (rounded up by the sender)
    grid_height: int
    half_colour: bool  # colour at half the detail (4:2:0): blocks of 16x16
    strength: int  # which of the eight quantization strengths, 0 the coarsest
    correction_strength: int  # the same for blocks that are a correction
    luma_for_colour: bool  # the colour planes use the brightness plane's table


# --- from the JPEG standard (ITU T.81, Annex K) ---------------------------------------------------------

# The position in a block of the coefficient that arrives first, second, ... (with room past the end
# for a run that goes too far: a damaged frame is not to write outside the block).
_ORDER = (
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6, 7, 14, 21, 28,
    35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
) + (63,) * 32  # fmt: skip

# Huffman tables: how many codes there are of each length from 1 to 16 bits, and what they stand for.
_DC_LUMA = ((0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0), tuple(range(12)))
_DC_CHROMA = ((0, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0), tuple(range(12)))
_AC_LUMA_VALUES = (
    0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07, 0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xA1, 0x08, 0x23, 0x42, 0xB1,
    0xC1, 0x15, 0x52, 0xD1, 0xF0, 0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0A, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A,
    0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0xA2, 0xA3,
    0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xD2, 0xD3,
    0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA,
)  # fmt: skip
_AC_CHROMA_VALUES = (
    0x00, 0x01, 0x02, 0x03, 0x11, 0x04, 0x05, 0x21, 0x31, 0x06, 0x12, 0x41, 0x51, 0x07, 0x61, 0x71, 0x13, 0x22, 0x32, 0x81, 0x08, 0x14, 0x42, 0x91, 0xA1, 0xB1, 0xC1,
    0x09, 0x23, 0x33, 0x52, 0xF0, 0x15, 0x62, 0x72, 0xD1, 0x0A, 0x16, 0x24, 0x34, 0xE1, 0x25, 0xF1, 0x17, 0x18, 0x19, 0x1A, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x35, 0x36,
    0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
    0x6A, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A,
    0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
    0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA,
)  # fmt: skip
_AC_LUMA = ((0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 125), _AC_LUMA_VALUES)
_AC_CHROMA = ((0, 2, 1, 2, 4, 4, 3, 4, 7, 5, 4, 4, 0, 1, 2, 119), _AC_CHROMA_VALUES)

_LUMA_QUANT = (
    16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40, 57, 69, 56, 14, 17, 22, 29, 51, 87, 80, 62,
    18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113, 92, 49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99,
)  # fmt: skip
_CHROMA_QUANT = (
    17, 18, 24, 47, 99, 99, 99, 99, 18, 21, 26, 66, 99, 99, 99, 99, 24, 26, 56, 99, 99, 99, 99, 99, 47, 66, 99, 99, 99, 99, 99, 99,
) + (99,) * 32  # fmt: skip

# --- ASPEED's own -----------------------------------------------------------------------------------------

# The eight strengths: the standard's table times this many thirty-seconds, the coarsest first.
_LUMA_STRENGTHS = (40, 35, 29, 23, 18, 12, 6, 4)
_CHROMA_STRENGTHS = (60, 52, 43, 35, 26, 18, 9, 6)

# The colours a block of "one of these few colours" starts out knowing, as Y, Cb, Cr in one number.
_FIRST_COLOURS = (0x008080, 0xFF8080, 0x808080, 0xC08080)

# What the first four bits of a block say.
_END = 0x9
_PLACED = 0x8  # set: the block says where it is; clear: it follows the one before
_KINDS = {0x0: "jpeg", 0x4: "jpeg-fine", 0x2: "correction", 0x5: "colours-1", 0x6: "colours-2", 0x7: "colours-4"}

# The inverse transform works on coefficients that were scaled beforehand (Arai, Agui and Nakajima's
# method, as in the JPEG group's own fast decoder): these are the factors, by row and by column.
_SCALE = (1.0, 1.387039845, 1.306562965, 1.175875602, 1.0, 0.785694958, 0.541196100, 0.275899379)


def _lookup(counts: tuple[int, ...], values: tuple[int, ...]) -> list[int]:
    """For every 16 bits that may come next: the length of the code they begin with, and what it stands for."""
    table = [0] * 65536
    code, at = 0, 0
    for length, count in enumerate(counts, start=1):
        for _ in range(count):
            first = code << (16 - length)
            table[first : first + (1 << (16 - length))] = [(length << 8) | values[at]] * (1 << (16 - length))
            code, at = code + 1, at + 1
        code <<= 1
    return table


def _quantizers(standard: tuple[int, ...], thirty_seconds: int) -> list[int]:
    """One strength of a quantization table, with the transform's scaling worked in."""
    return [int(max(1, min(255, q * thirty_seconds // 32)) * _SCALE[at // 8] * _SCALE[at % 8]) for at, q in enumerate(standard)]


# A sample as the transform leaves it (ten bits, signed, around zero) as a byte around 128.
_SAMPLE = bytes(min(255, 128 + v) if v < 512 else max(0, v - 896) for v in range(1024))

# YCbCr (ITU-R 601, as video has it: black at 16) to RGB, in sixteenth-bit fixed point as the sender's
# own decoder does it, and a table that keeps the result between 0 and 255.
_Y = [((76284 * (y - 16) + 32768) >> 16) + 512 for y in range(256)]  # 1.164 times (y - 16); 512 more, see _BYTE
_CR_R = [(int(1.597656 * 65536) * (c - 128) + 32768) >> 16 for c in range(256)]
_CB_B = [(int(2.015625 * 65536) * (c - 128) + 32768) >> 16 for c in range(256)]
_CR_G = [(int(-0.8125 * 65536) * (c - 128) + 32768) >> 16 for c in range(256)]
_CB_G = [(int(-0.390625 * 65536) * (c - 128) + 32768) >> 16 for c in range(256)]
_BYTE = bytes(min(255, max(0, v - 512)) for v in range(1600))

_tables: dict[str, list[int]] = {}


def _huffman(name: str) -> list[int]:
    if name not in _tables:
        _tables[name] = _lookup(*{"dc-luma": _DC_LUMA, "dc-chroma": _DC_CHROMA, "ac-luma": _AC_LUMA, "ac-chroma": _AC_CHROMA}[name])
    return _tables[name]


def _inverse(c: list[int], q: list[int]) -> list[int]:
    """The 64 samples of a block from its 64 coefficients: the inverse cosine transform, in whole numbers."""
    w = [0] * 64
    for x in range(8):
        c1, c2, c3, c4, c5, c6, c7 = c[x + 8], c[x + 16], c[x + 24], c[x + 32], c[x + 40], c[x + 48], c[x + 56]
        if not (c1 or c2 or c3 or c4 or c5 or c6 or c7):
            w[x] = w[x + 8] = w[x + 16] = w[x + 24] = w[x + 32] = w[x + 40] = w[x + 48] = w[x + 56] = q[x] * c[x]
            continue
        t0, t1, t2, t3 = q[x] * c[x], q[x + 16] * c2, q[x + 32] * c4, q[x + 48] * c6
        t10, t11, t13 = t0 + t2, t0 - t2, t1 + t3
        t12 = (((t1 - t3) * 362) >> 8) - t13
        t0, t3, t1, t2 = t10 + t13, t10 - t13, t11 + t12, t11 - t12
        t4, t5, t6, t7 = q[x + 8] * c1, q[x + 24] * c3, q[x + 40] * c5, q[x + 56] * c7
        z13, z10, z11, z12 = t6 + t5, t6 - t5, t4 + t7, t4 - t7
        t7 = z11 + z13
        t11 = ((z11 - z13) * 362) >> 8
        z5 = ((z10 + z12) * 473) >> 8
        t10 = ((z12 * 277) >> 8) - z5
        t12 = ((z10 * -669) >> 8) + z5
        t6 = t12 - t7
        t5 = t11 - t6
        t4 = t10 + t5
        w[x], w[x + 56] = t0 + t7, t0 - t7
        w[x + 8], w[x + 48] = t1 + t6, t1 - t6
        w[x + 16], w[x + 40] = t2 + t5, t2 - t5
        w[x + 32], w[x + 24] = t3 + t4, t3 - t4
    out = [0] * 64
    sample = _SAMPLE
    for row in range(0, 64, 8):
        w0, w1, w2, w3, w4, w5, w6, w7 = w[row : row + 8]
        t10, t11, t13 = w0 + w4, w0 - w4, w2 + w6
        t12 = (((w2 - w6) * 362) >> 8) - t13
        t0, t3, t1, t2 = t10 + t13, t10 - t13, t11 + t12, t11 - t12
        z13, z10, z11, z12 = w5 + w3, w5 - w3, w1 + w7, w1 - w7
        t7 = z11 + z13
        t11 = ((z11 - z13) * 362) >> 8
        z5 = ((z10 + z12) * 473) >> 8
        t10 = ((z12 * 277) >> 8) - z5
        t12 = ((z10 * -669) >> 8) + z5
        t6 = t12 - t7
        t5 = t11 - t6
        t4 = t10 + t5
        out[row : row + 8] = (
            sample[((t0 + t7) >> 3) & 1023], sample[((t1 + t6) >> 3) & 1023], sample[((t2 + t5) >> 3) & 1023], sample[((t3 - t4) >> 3) & 1023],
            sample[((t3 + t4) >> 3) & 1023], sample[((t2 - t5) >> 3) & 1023], sample[((t1 - t6) >> 3) & 1023], sample[((t0 - t7) >> 3) & 1023],
        )  # fmt: skip
    return out


# A plane of a block: one number where it is the same all over (which most of a screen is), else 64 of them.
Plane = int | list[int]
# ...and as it is kept for a correction that may come: 64 bytes, not a list of 64 numbers (a tenth of the room).
Kept = int | bytes


class Screen:
    """A server's screen as it stands, kept up to date frame by frame.

    `rgb` is the picture: three bytes a pixel, row after row, `width` by `height`. Empty until the first
    frame has been read. `shown` is the three together, for whoever makes a picture of the screen in
    another thread than the one that reads frames into it: taken in one look they are of one screen,
    whatever size the next frame is of. `given_up`: set by whoever no longer waits for the frame being read.
    """

    def __init__(self) -> None:
        self.width = self.height = 0
        self.rgb = bytearray()
        self.shown: tuple[int, int, bytearray] = (0, 0, self.rgb)
        self.given_up = False
        self._header: FrameHeader | None = None
        self._across = self._down = 0  # blocks, as the sender counts them
        self._quant: list[list[int]] = []
        self._colours = list(_FIRST_COLOURS)
        self._chosen = [0, 1, 2, 3]
        self._planes: dict[int, tuple[Kept, Kept, Kept]] = {}  # what each block was last, for corrections to it

    def _fit(self, header: FrameHeader) -> None:
        """Make ready for frames like this one: a screen of its size, and its tables."""
        if not (0 < header.width <= LARGEST and 0 < header.height <= LARGEST):
            raise Garbled(f"a screen of {header.width} by {header.height}")
        if not (0 <= header.strength < 8 and 0 <= header.correction_strength < 8):
            raise Garbled("a quantization strength there is none of")
        side = 16 if header.half_colour else 8
        before = self._header
        if before is None or (before.width, before.height, before.half_colour) != (header.width, header.height, header.half_colour):
            rgb = bytearray(3 * header.width * header.height)
            self.width, self.height, self.rgb = header.width, header.height, rgb
            self.shown = (header.width, header.height, rgb)
            self._planes = {}
        self._across = max(1, -(-max(header.grid_width, 1) // side))
        self._down = max(1, -(-max(header.grid_height, 1) // side))
        if before is None or (before.strength, before.correction_strength, before.luma_for_colour) != (
            header.strength,
            header.correction_strength,
            header.luma_for_colour,
        ):
            colour, colour_strengths = (_LUMA_QUANT, _LUMA_STRENGTHS) if header.luma_for_colour else (_CHROMA_QUANT, _CHROMA_STRENGTHS)
            self._quant = [
                _quantizers(_LUMA_QUANT, _LUMA_STRENGTHS[header.strength]),
                _quantizers(colour, colour_strengths[header.strength]),
                _quantizers(_LUMA_QUANT, _LUMA_STRENGTHS[header.correction_strength]),
                _quantizers(colour, colour_strengths[header.correction_strength]),
            ]
        self._header = header

    def read(self, header: FrameHeader, data: bytes) -> int:
        """Take in one frame. Returns how many blocks of the screen it changed."""
        if len(data) > LONGEST:
            raise Garbled("a frame longer than a screen can be")
        self._fit(header)
        if len(data) > 2 * 3 * header.width * header.height + 4096:
            raise Garbled("a frame longer than its screen could take")
        # Blocks it may bring: two for every one its screen has, and a few. Every block is in order by
        # itself, and megabytes of them for a screen of four would be read for minutes.
        side = 16 if header.half_colour else 8
        allowed = 2 * (-(-header.width // side)) * (-(-header.height // side)) + SPARE
        blocks = 0
        count = len(data) // 4
        words: list[int] = [*struct.unpack_from(f"<{count}I", data), *([0] * 80)]  # past its end a frame reads as nothing
        end = 32 * (count - 2)  # no block begins in a frame's last two words
        acc: int = (words[0] << 32) | words[1]
        nbits, wi = 64, 2
        dc_luma, dc_chroma, ac_luma, ac_chroma = _huffman("dc-luma"), _huffman("dc-chroma"), _huffman("ac-luma"), _huffman("ac-chroma")
        order, sample = _ORDER, _SAMPLE
        quant = self._quant
        half, across, down = header.half_colour, self._across, self._down
        colours, chosen = self._colours, self._chosen
        dc_y = dc_cb = dc_cr = 0
        tx = ty = 0
        changed = 0

        def take(k: int) -> int:
            """The next k bits (k up to 32)."""
            nonlocal acc, nbits, wi
            nbits -= k
            value = acc >> nbits
            acc &= (1 << nbits) - 1
            if nbits < 32:
                acc, nbits, wi = (acc << 32) | words[wi], nbits + 32, wi + 1
            return value

        def plane(dc: list[int], ac: list[int], before: int, q: list[int]) -> tuple[Plane, int]:
            """One 8x8 plane of a JPEG block: its samples, and its first coefficient for the next one to count from."""
            nonlocal acc, nbits, wi
            entry = dc[(acc >> (nbits - 16)) & 0xFFFF]
            if not entry:
                raise Garbled("a code that stands for nothing")
            nbits -= entry >> 8
            acc &= (1 << nbits) - 1
            if nbits < 32:
                acc, nbits, wi = (acc << 32) | words[wi], nbits + 32, wi + 1
            size = entry & 255
            if size:
                nbits -= size
                value = acc >> nbits
                acc &= (1 << nbits) - 1
                if nbits < 32:
                    acc, nbits, wi = (acc << 32) | words[wi], nbits + 32, wi + 1
                before += value if value >> (size - 1) else value + 1 - (1 << size)
            coefficients: list[int] | None = None
            at = 1
            while at < 64:
                entry = ac[(acc >> (nbits - 16)) & 0xFFFF]
                if not entry:
                    raise Garbled("a code that stands for nothing")
                nbits -= entry >> 8
                acc &= (1 << nbits) - 1
                if nbits < 32:
                    acc, nbits, wi = (acc << 32) | words[wi], nbits + 32, wi + 1
                size = entry & 15
                if not size:
                    if entry & 0xF0 != 0xF0:
                        break  # the rest of the block is zero
                    at += 16
                    continue
                at += (entry >> 4) & 15
                nbits -= size
                value = acc >> nbits
                acc &= (1 << nbits) - 1
                if nbits < 32:
                    acc, nbits, wi = (acc << 32) | words[wi], nbits + 32, wi + 1
                if coefficients is None:
                    coefficients = [0] * 64
                coefficients[order[at]] = value if value >> (size - 1) else value + 1 - (1 << size)
                at += 1
            if coefficients is None:
                return sample[((q[0] * before) >> 3) & 1023], before  # only its average: the same all over
            coefficients[0] = before
            return _inverse(coefficients, q), before

        def colour() -> int:
            """One entry of a colour block's list: which of the four known colours, and perhaps what that one is from now on."""
            new, which = take(1), take(2)
            if new:
                colours[which] = take(24)
            return which

        while 32 * wi - nbits < end:
            kind = (acc >> (nbits - 4)) & 15
            if kind == _END:
                break
            blocks += 1
            if blocks > allowed:
                raise Garbled("a frame of more blocks than its screen has twice over")
            if not blocks & 63 and self.given_up:
                raise Garbled("a frame nobody waits for any more")
            name = _KINDS.get(kind & 0x7)
            if name is None:
                take(3)  # not a kind of block there is: the sender's own decoder steps three bits on, and to the next block
            else:
                take(4)
                if kind & _PLACED:
                    tx, ty = take(8), take(8)
            if name is None:
                pass
            elif name in ("jpeg", "jpeg-fine", "correction"):
                tables = quant[2:] if name != "jpeg" else quant
                if half and name != "correction":
                    ys: list[Plane] = []
                    for _ in range(4):
                        y, dc_y = plane(dc_luma, ac_luma, dc_y, tables[0])
                        ys.append(y)
                    cb, dc_cb = plane(dc_chroma, ac_chroma, dc_cb, tables[1])
                    cr, dc_cr = plane(dc_chroma, ac_chroma, dc_cr, tables[1])
                    changed += self._draw_large(tx, ty, ys, cb, cr)
                else:
                    y, dc_y = plane(dc_luma, ac_luma, dc_y, tables[0])
                    cb, dc_cb = plane(dc_chroma, ac_chroma, dc_cb, tables[1])
                    cr, dc_cr = plane(dc_chroma, ac_chroma, dc_cr, tables[1])
                    if name == "correction":
                        y, cb, cr = self._corrected(tx, ty, y, cb, cr)
                    if not half:
                        # (A correction is to what the block was sent as. The next one is too, not to this one's result.)
                        changed += self._draw(tx, ty, y, cb, cr, keep=name != "correction")
            else:
                listed = int(name[-1])
                chosen[:listed] = [colour() for _ in range(listed)]
                if listed == 1:
                    one = colours[chosen[0]]
                    y, cb, cr = one >> 16, (one >> 8) & 255, one & 255
                else:
                    each = 1 if listed == 2 else 2  # bits a pixel
                    picked = [colours[chosen[take(each)]] for _ in range(64)]
                    y, cb, cr = [p >> 16 for p in picked], [(p >> 8) & 255 for p in picked], [p & 255 for p in picked]
                if not half:  # (they are not sent with colour at half the detail)
                    changed += self._draw(tx, ty, y, cb, cr)
            tx += 1
            if tx >= across:
                tx, ty = 0, ty + 1
                if ty >= down:
                    ty = 0
        return changed

    def _corrected(self, tx: int, ty: int, y: Plane, cb: Plane, cr: Plane) -> tuple[Plane, Plane, Plane]:
        """A block that is a correction, added to what the block was."""
        was = self._planes.get(ty * 1024 + tx, (0, 128, 128))

        def add(old: Kept, change: Plane) -> Plane:
            if isinstance(old, int) and isinstance(change, int):
                return min(255, max(0, old + change - 128))
            olds: bytes | list[int] = [old] * 64 if isinstance(old, int) else old
            changes = [change] * 64 if isinstance(change, int) else change
            return [min(255, max(0, a + b - 128)) for a, b in zip(olds, changes, strict=True)]

        return add(was[0], y), add(was[1], cb), add(was[2], cr)

    def _draw(self, tx: int, ty: int, y: Plane, cb: Plane, cr: Plane, keep: bool = True) -> int:
        """Put an 8x8 block on the screen. Returns 1 if it is on it, 0 if it lies outside."""
        left, top = tx * 8, ty * 8
        wide, high = min(8, self.width - left), min(8, self.height - top)
        if wide <= 0 or high <= 0:
            return 0
        if keep:
            self._planes[ty * 1024 + tx] = (
                y if isinstance(y, int) else bytes(y),
                cb if isinstance(cb, int) else bytes(cb),
                cr if isinstance(cr, int) else bytes(cr),
            )
        rgb, row, byte = self.rgb, 3 * self.width, _BYTE
        at = 3 * (top * self.width + left)
        if isinstance(y, int) and isinstance(cb, int) and isinstance(cr, int):
            light = _Y[y]
            line = bytes((byte[light + _CR_R[cr]], byte[light + _CB_G[cb] + _CR_G[cr]], byte[light + _CB_B[cb]])) * wide
            for _ in range(high):
                rgb[at : at + 3 * wide] = line
                at += row
            return 1
        ys = [y] * 64 if isinstance(y, int) else y
        cbs = [cb] * 64 if isinstance(cb, int) else cb
        crs = [cr] * 64 if isinstance(cr, int) else cr
        lights, to_r, to_b, cr_g, cb_g = _Y, _CR_R, _CB_B, _CR_G, _CB_G
        for start in range(0, 8 * high, 8):
            pixels: list[int] = []
            for i in range(start, start + wide):
                light, b, r = lights[ys[i]], cbs[i], crs[i]
                pixels += (byte[light + to_r[r]], byte[light + cb_g[b] + cr_g[r]], byte[light + to_b[b]])
            rgb[at : at + 3 * wide] = bytes(pixels)
            at += row
        return 1

    def _draw_large(self, tx: int, ty: int, ys: list[Plane], cb: Plane, cr: Plane) -> int:
        """Put a 16x16 block on the screen: four planes of brightness, and colour at half the detail."""
        left, top = tx * 16, ty * 16
        wide, high = min(16, self.width - left), min(16, self.height - top)
        if wide <= 0 or high <= 0:
            return 0
        quarters = [[q] * 64 if isinstance(q, int) else q for q in ys]
        cbs = [cb] * 64 if isinstance(cb, int) else cb
        crs = [cr] * 64 if isinstance(cr, int) else cr
        rgb, row, byte = self.rgb, 3 * self.width, _BYTE
        at = 3 * (top * self.width + left)
        for j in range(high):
            line = bytearray()
            for i in range(wide):
                light = _Y[quarters[(j >> 3) * 2 + (i >> 3)][(j & 7) * 8 + (i & 7)]]
                b, r = cbs[(j >> 1) * 8 + (i >> 1)], crs[(j >> 1) * 8 + (i >> 1)]
                line += bytes((byte[light + _CR_R[r]], byte[light + _CB_G[b] + _CR_G[r]], byte[light + _CB_B[b]]))
            rgb[at : at + 3 * wide] = line
            at += row
        return 1
