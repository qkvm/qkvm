"""QR codes, just enough of them: a short text (up to 134 bytes) at error correction level L.

That covers what this program shows as a QR code, the address an authenticator app reads
to add an account, without pulling in an imaging library. Versions 1 to 6 only, which
keeps out the parts of the standard that larger codes need.
"""

from __future__ import annotations

# version -> (data codewords per block, blocks, error correction codewords per block), level L
_BLOCKS = {1: (19, 1, 7), 2: (34, 1, 10), 3: (55, 1, 15), 4: (80, 1, 20), 5: (108, 1, 26), 6: (68, 2, 18)}
_FORMAT_LEVEL_L = 0b01

# Arithmetic in GF(256), reduced by x^8 + x^4 + x^3 + x^2 + 1, as Reed-Solomon in QR codes wants it.
_EXP = [0] * 512
_LOG = [0] * 256
_value = 1
for _power in range(255):
    _EXP[_power] = _value
    _LOG[_value] = _power
    _value <<= 1
    if _value & 0x100:
        _value ^= 0x11D
for _power in range(255, 512):
    _EXP[_power] = _EXP[_power - 255]

_MASKS = (
    lambda r, c: (r + c) % 2 == 0,
    lambda r, c: r % 2 == 0,
    lambda r, c: c % 3 == 0,
    lambda r, c: (r + c) % 3 == 0,
    lambda r, c: (r // 2 + c // 3) % 2 == 0,
    lambda r, c: (r * c) % 2 + (r * c) % 3 == 0,
    lambda r, c: ((r * c) % 2 + (r * c) % 3) % 2 == 0,
    lambda r, c: ((r + c) % 2 + (r * c) % 3) % 2 == 0,
)


def _multiply(a: int, b: int) -> int:
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def _check_words(data: list[int], count: int) -> list[int]:
    """The Reed-Solomon error correction codewords for one block."""
    generator = [1]
    for power in range(count):  # times (x - a^power)
        longer = [0] * (len(generator) + 1)
        for index, coefficient in enumerate(generator):
            longer[index] ^= coefficient
            longer[index + 1] ^= _multiply(coefficient, _EXP[power])
        generator = longer
    remainder = [0] * count
    for word in data:
        factor = word ^ remainder[0]
        remainder = remainder[1:] + [0]
        for index in range(count):
            remainder[index] ^= _multiply(generator[index + 1], factor)
    return remainder


def _codewords(data: bytes, version: int) -> list[int]:
    """The text as the final sequence of codewords: data, padding and error correction, interleaved."""
    per_block, blocks, checks = _BLOCKS[version]
    capacity = per_block * blocks
    bits = [0, 1, 0, 0] + [(len(data) >> shift) & 1 for shift in range(7, -1, -1)]  # byte mode, then the length
    for byte in data:
        bits += [(byte >> shift) & 1 for shift in range(7, -1, -1)]
    bits += [0] * min(4, capacity * 8 - len(bits))
    bits += [0] * (-len(bits) % 8)
    words = [sum(bit << (7 - place) for place, bit in enumerate(bits[at : at + 8])) for at in range(0, len(bits), 8)]
    words += [(0xEC, 0x11)[index % 2] for index in range(capacity - len(words))]
    chunks = [words[index * per_block : (index + 1) * per_block] for index in range(blocks)]
    corrections = [_check_words(chunk, checks) for chunk in chunks]
    return [chunk[index] for index in range(per_block) for chunk in chunks] + [
        correction[index] for index in range(checks) for correction in corrections
    ]


def _format_bits(mask: int) -> int:
    """The 15 bits that tell a reader the error correction level and the mask."""
    data = (_FORMAT_LEVEL_L << 3) | mask
    remainder = data << 10
    for shift in range(14, 9, -1):
        if (remainder >> shift) & 1:
            remainder ^= 0x537 << (shift - 10)
    return ((data << 10) | remainder) ^ 0x5412


def _penalty(dark: list[list[bool]]) -> int:
    """How hard this pattern would be to read; the standard's four rules."""
    size = len(dark)
    lines = [row for row in dark] + [[dark[r][c] for r in range(size)] for c in range(size)]
    score = 0
    finder = [True, False, True, True, True, False, True, False, False, False, False]
    for line in lines:
        run = 1
        for index in range(1, size + 1):
            if index < size and line[index] == line[index - 1]:
                run += 1
            else:
                if run >= 5:
                    score += run - 2
                run = 1
        for index in range(size - 10):
            window = line[index : index + 11]
            if window == finder or window == finder[::-1]:
                score += 40
    for r in range(size - 1):
        for c in range(size - 1):
            if dark[r][c] == dark[r][c + 1] == dark[r + 1][c] == dark[r + 1][c + 1]:
                score += 3
    filled = sum(sum(row) for row in dark)
    score += 10 * (abs(filled * 20 - size * size * 10) // (size * size))
    return score


def _build(data: bytes, version: int, mask: int) -> list[list[bool]]:
    size = 17 + 4 * version
    dark = [[False] * size for _ in range(size)]
    fixed = [[False] * size for _ in range(size)]  # modules that are part of the pattern, not of the data

    def put(r: int, c: int, value: bool) -> None:
        dark[r][c] = value
        fixed[r][c] = True

    for top, left in ((0, 0), (0, size - 7), (size - 7, 0)):  # the three finder squares and their margins
        for r in range(-1, 8):
            for c in range(-1, 8):
                if 0 <= top + r < size and 0 <= left + c < size:
                    ring = 0 <= r <= 6 and 0 <= c <= 6 and (r in (0, 6) or c in (0, 6))
                    put(top + r, left + c, ring or (2 <= r <= 4 and 2 <= c <= 4))
    for index in range(8, size - 8):  # timing lines
        put(6, index, index % 2 == 0)
        put(index, 6, index % 2 == 0)
    if version >= 2:  # the small alignment square
        centre = 4 * version + 10
        for r in range(-2, 3):
            for c in range(-2, 3):
                put(centre + r, centre + c, max(abs(r), abs(c)) != 1)

    bits = _format_bits(mask)

    def bit(index: int) -> bool:
        return bool((bits >> index) & 1)

    for index in range(6):
        put(index, 8, bit(index))
    put(7, 8, bit(6))
    put(8, 8, bit(7))
    put(8, 7, bit(8))
    for index in range(9, 15):
        put(8, 14 - index, bit(index))
    for index in range(8):
        put(8, size - 1 - index, bit(index))
    for index in range(8, 15):
        put(size - 15 + index, 8, bit(index))
    put(size - 8, 8, True)  # always dark

    stream = [(word >> shift) & 1 for word in _codewords(data, version) for shift in range(7, -1, -1)]
    at = 0
    column = size - 1
    upward = True
    while column > 0:
        if column == 6:  # the vertical timing line takes a whole column
            column -= 1
        for r in range(size - 1, -1, -1) if upward else range(size):
            for c in (column, column - 1):
                if not fixed[r][c]:
                    value = bool(stream[at]) if at < len(stream) else False
                    dark[r][c] = value != _MASKS[mask](r, c)
                    at += 1
        upward = not upward
        column -= 2
    return dark


def matrix(text: str) -> list[str]:
    """The QR code for `text`, row by row, "1" for a dark module. ValueError if the text is too long."""
    data = text.encode("utf-8")
    version = next((v for v, (per_block, blocks, _) in _BLOCKS.items() if len(data) <= per_block * blocks - 2), None)
    if version is None:
        raise ValueError("too long for a QR code")
    best = min((_build(data, version, mask) for mask in range(8)), key=_penalty)
    return ["".join("1" if module else "0" for module in row) for row in best]
