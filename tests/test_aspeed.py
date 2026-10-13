"""The picture a management controller sends: ASPEED's video format, read."""

from __future__ import annotations

import hashlib
import time

import pytest

from qkvm.aspeed import FrameHeader, Garbled, Screen
from tests.aspeed_frames import Frame

# Colours as video has them: brightness, blue difference, red difference, in one number.
WHITE, BLACK, RED, GREEN, BLUE = 0xEB8080, 0x108080, 0x515AF0, 0x913622, 0x29F06E
FLAT = [0] * 64


def at(screen: Screen, x: int, y: int) -> tuple[int, ...]:
    start = 3 * (y * screen.width + x)
    return tuple(screen.rgb[start : start + 3])


def near(colour: tuple[int, ...], wanted: tuple[int, int, int], within: int = 3) -> bool:
    return all(abs(a - b) <= within for a, b in zip(colour, wanted, strict=True))


def shade(level: int) -> list[int]:
    """The coefficients of a plane that is one shade all over."""
    return [level, *([0] * 63)]


def read(*frames: Frame) -> Screen:
    screen = Screen()
    for frame in frames:
        screen.read(frame.header, frame.data)
    return screen


def test_a_block_of_one_colour_is_that_colour() -> None:
    frame = Frame(40, 8)
    for colour in (WHITE, BLACK, RED, GREEN, BLUE):
        frame.colours([(0, colour)])
    screen = read(frame)
    assert (screen.width, screen.height) == (40, 8)
    for block, wanted in enumerate([(255, 255, 255), (0, 0, 0), (255, 0, 0), (0, 255, 0), (0, 0, 255)]):
        assert near(at(screen, 8 * block + 3, 4), wanted), (block, at(screen, 8 * block + 3, 4))
        assert at(screen, 8 * block, 0) == at(screen, 8 * block + 7, 7)  # the same all over


def test_two_and_four_colours_say_which_one_every_pixel_is() -> None:
    frame = Frame(16, 8)
    stripes = [x % 2 for _ in range(8) for x in range(8)]
    quarters = [(y // 4) * 2 + x // 4 for y in range(8) for x in range(8)]
    frame.colours([(0, WHITE), (1, BLACK)], stripes)
    frame.colours([(0, RED), (1, GREEN), (2, BLUE), (3, WHITE)], quarters)
    screen = read(frame)
    assert near(at(screen, 0, 5), (255, 255, 255)) and near(at(screen, 1, 5), (0, 0, 0)) and near(at(screen, 6, 0), (255, 255, 255))
    assert near(at(screen, 9, 1), (255, 0, 0)) and near(at(screen, 14, 1), (0, 255, 0))
    assert near(at(screen, 9, 6), (0, 0, 255)) and near(at(screen, 14, 6), (255, 255, 255))


def test_a_colour_that_is_known_is_named_and_not_sent_again() -> None:
    # A screen of text is two colours, thousands of times: the sender says each once and then only which.
    first = Frame(24, 8)
    first.colours([(2, RED)])
    first.colours([(2, None)])
    first.colours([(1, BLUE), (2, None)], [x % 2 for _ in range(8) for x in range(8)])
    second = Frame(24, 8)
    second.colours([(1, None)])  # ...and it is still known when the next frame comes
    screen = read(first, second)
    assert near(at(screen, 4, 4), (0, 0, 255))  # the second frame's block
    assert near(at(screen, 12, 4), (255, 0, 0))
    assert near(at(screen, 16, 4), (0, 0, 255)) and near(at(screen, 17, 4), (255, 0, 0))


def test_blocks_follow_one_another_unless_they_say_where_they_are() -> None:
    frame = Frame(24, 16)
    for colour in (RED, GREEN, BLUE, WHITE):  # three across, and the fourth begins the next row
        frame.colours([(0, colour)])
    frame.colours([(0, BLUE)], None, (2, 1))  # one that says where
    frame.colours([(0, RED)])  # ...and the one after it follows from there, round to the top
    screen = read(frame)
    assert near(at(screen, 4, 12), (255, 255, 255)) and near(at(screen, 20, 12), (0, 0, 255))
    assert near(at(screen, 4, 4), (255, 0, 0)) and near(at(screen, 12, 4), (0, 255, 0))


def test_a_frame_brings_only_what_changed() -> None:
    whole = Frame(16, 16)
    for _ in range(4):
        whole.colours([(0, WHITE)])
    change = Frame(16, 16)
    change.colours([(0, BLACK)], None, (1, 0))
    screen = Screen()
    assert screen.read(whole.header, whole.data) == 4
    assert screen.read(change.header, change.data) == 1
    assert near(at(screen, 12, 3), (0, 0, 0)) and all(near(at(screen, x, y), (255, 255, 255)) for x, y in ((3, 3), (3, 12), (12, 12)))


def test_a_jpeg_block_of_one_shade_and_one_with_detail() -> None:
    frame = Frame(24, 8, strength=4)
    frame.jpeg(shade(0), FLAT, FLAT)  # the middle of the range
    frame.jpeg(shade(40), FLAT, FLAT)  # brighter (each plane counts on from the one before it)
    across = list(FLAT)
    across[0], across[1] = 0, 30  # brightness falling from left to right, the same down every column
    frame.jpeg(across, FLAT, FLAT)
    screen = read(frame)
    grey = at(screen, 3, 3)
    assert grey[0] == grey[1] == grey[2] and 120 <= grey[0] <= 136 and at(screen, 0, 0) == at(screen, 7, 7)
    assert at(screen, 11, 3)[0] > grey[0] + 30
    row = [at(screen, x, 2)[0] for x in range(16, 24)]
    assert row == sorted(row, reverse=True) and row[0] > row[7] + 40
    assert [at(screen, x, 6)[0] for x in range(16, 24)] == row


def test_colour_at_half_the_detail_comes_in_blocks_of_sixteen() -> None:
    frame = Frame(32, 16, half_colour=True)
    frame.jpeg([shade(-60), shade(-20), shade(20), shade(60)], FLAT, FLAT)  # four shades, one a quarter
    frame.jpeg([shade(0)] * 4, shade(0), shade(60))  # and a block that is reddish all over
    screen = read(frame)
    quarters = [at(screen, 3, 3)[0], at(screen, 12, 3)[0], at(screen, 3, 12)[0], at(screen, 12, 12)[0]]
    assert quarters == sorted(quarters) and len(set(quarters)) == 4
    red, green, blue = at(screen, 24, 8)
    assert red > green + 40 and red > blue + 20 and at(screen, 17, 1) == at(screen, 30, 14)


def test_a_correction_is_added_to_what_the_block_was_sent_as() -> None:
    sent = Frame(8, 8, strength=4, correction_strength=4)
    sent.jpeg(shade(0), FLAT, FLAT)
    brighter = Frame(8, 8, strength=4, correction_strength=4)
    brighter.jpeg(shade(10), FLAT, FLAT, correction=True)
    screen = read(sent)
    was = at(screen, 3, 3)[0]
    screen.read(brighter.header, brighter.data)
    once = at(screen, 3, 3)[0]
    assert once > was + 5
    screen.read(brighter.header, brighter.data)  # the same correction again: to the block as sent, not to the corrected one
    assert at(screen, 3, 3)[0] == once


def test_a_screen_need_not_be_a_whole_number_of_blocks() -> None:
    frame = Frame(21, 11)
    for _ in range(6):
        frame.colours([(0, WHITE)])
    screen = read(frame)
    assert len(screen.rgb) == 3 * 21 * 11 and near(at(screen, 20, 10), (255, 255, 255)) and near(at(screen, 0, 0), (255, 255, 255))


def test_a_block_that_says_it_is_off_the_screen_is_not_drawn() -> None:
    frame = Frame(16, 8)
    frame.colours([(0, WHITE)])
    frame.colours([(0, RED)], None, (200, 3))
    frame.colours([(0, RED)], None, (1, 150))
    screen = Screen()
    assert screen.read(frame.header, frame.data) == 1
    assert near(at(screen, 3, 3), (255, 255, 255)) and at(screen, 12, 3) == (0, 0, 0)


def test_a_new_size_of_screen_is_a_new_picture() -> None:
    small, large = Frame(8, 8), Frame(16, 8)
    small.colours([(0, WHITE)])
    large.colours([(0, RED)], None, (1, 0))
    screen = read(small, large)
    assert (screen.width, screen.height) == (16, 8) and at(screen, 3, 3) == (0, 0, 0) and near(at(screen, 12, 3), (255, 0, 0))


def numbers(seed: int) -> object:
    """Numbers that look like chance and are the same on every computer and every Python."""
    state = seed

    def below(limit: int) -> int:
        nonlocal state
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF
        return (state >> 8) % limit

    return below


def a_mixed_screen() -> list[Frame]:
    """Three frames with every kind of block in them, many times over."""
    below = numbers(2026)

    def plane(most: int, busy: int) -> list[int]:
        found = [below(2 * most + 1) - most, *([0] * 63)]
        for position in range(1, 64):
            if below(100) < busy:
                found[position] = below(61) - 30
        return found

    def colour() -> int:
        return (below(256) << 16) | (below(256) << 8) | below(256)

    frames = []
    for number in range(3):
        frame = Frame(101, 59, strength=below(8), correction_strength=below(8), luma_for_colour=bool(number == 1))
        frames.append(frame)
        for y in range(8):
            for x in range(13):
                if number and below(3):
                    continue  # a later frame leaves most of the screen as it is
                where = (x, y) if number or below(4) == 0 else None
                kind = below(10)
                if kind < 4:
                    frame.jpeg(plane(80, below(30)), plane(40, below(12)), plane(40, below(12)), where if where or (x, y) != (0, 0) else None, fine=below(5) == 0)
                elif kind == 4 and number:
                    frame.jpeg(plane(15, below(10)), plane(8, below(5)), plane(8, below(5)), where, correction=True)
                elif kind < 7:
                    frame.colours([(below(4), colour() if below(3) else None)], None, where)
                elif kind < 9:
                    frame.colours([(below(4), colour() if below(2) else None) for _ in range(2)], [below(2) for _ in range(64)], where)
                else:
                    frame.colours([(below(4), colour() if below(2) else None) for _ in range(4)], [below(4) for _ in range(64)], where)
    return frames


def a_coarse_screen() -> list[Frame]:
    below = numbers(7)
    frame = Frame(96, 48, half_colour=True, strength=below(8))
    for _ in range(18):
        frame.jpeg([[below(121) - 60, *[below(41) - 20 if below(10) == 0 else 0 for _ in range(63)]] for _ in range(4)],
                   [below(61) - 30, *([0] * 63)], [below(61) - 30, *([0] * 63)])  # fmt: skip
    return [frame]


def test_the_picture_is_the_one_the_controllers_own_reader_makes() -> None:
    # These frames were also given to the reader in a real controller's own web page (with the two
    # places put right where that one is wrong: the green that the red difference gives, and a correction
    # that goes below zero). The pictures were the same, byte for byte, as were those of a thousand
    # frames made by chance. This holds this one fast.
    mixed, coarse = read(*a_mixed_screen()), read(*a_coarse_screen())
    assert hashlib.sha256(bytes(mixed.rgb)).hexdigest() == "f19a96cac01b1c48099f5cf0d232465f9957ce48b68b520d2bf15641d00b2386"
    assert hashlib.sha256(bytes(coarse.rgb)).hexdigest() == "50dbb5c74894e251f2c81a773d90d621fda79562cd0b301a53f8430ea947a095"


def test_what_is_not_a_frame_is_refused_or_runs_out_and_is_never_long_about_it() -> None:
    # What a controller sends is not believed: it may be damaged, another version's, or somebody's idea of a joke.
    below = numbers(99)
    header = FrameHeader(width=640, height=480, grid_width=640, grid_height=480, half_colour=False, strength=3, correction_strength=5, luma_for_colour=False)
    screen = Screen()
    began = time.perf_counter()
    for length in (0, 1, 3, 4, 8, 12, 40, 400, 4000, 40000):
        for _ in range(4):
            noise = bytes(below(256) for _ in range(length))
            try:
                screen.read(header, noise)
            except Garbled:
                pass
    assert time.perf_counter() - began < 20
    assert len(screen.rgb) == 3 * 640 * 480  # ...and the picture is still a picture
    real = a_mixed_screen()[0]
    for cut in (5, 37, len(real.data) // 2):  # a real frame, cut short
        try:
            Screen().read(real.header, real.data[:cut])
        except Garbled:
            pass


@pytest.mark.parametrize(
    "said",
    [{"width": 0}, {"height": 0}, {"width": 70000}, {"height": 5000}, {"strength": 8}, {"correction_strength": 200}],
)
def test_a_frame_that_says_something_impossible_of_itself_is_refused(said: dict[str, int]) -> None:
    usual = {"width": 64, "height": 48, "grid_width": 64, "grid_height": 48, "half_colour": False, "strength": 3, "correction_strength": 5, "luma_for_colour": False}
    with pytest.raises(Garbled):
        Screen().read(FrameHeader(**{**usual, **said}), bytes(64))  # type: ignore[arg-type]


# --- what a frame may cost ----------------------------------------------------------------------------------------
# Found by a review that fed the reader what a controller in the wrong hands could send. Nothing made it fall
# over or write where it should not; these are about how long and how much.


def test_no_frame_costs_more_than_drawing_its_screen_twice() -> None:
    # Sixteen megabytes of blocks that are each in order, for a screen of four, kept one thread at it for seven minutes.
    frame = Frame(16, 16)
    for _ in range(2 * 4 + 64 + 1):
        frame.colours([(0, WHITE)])
    with pytest.raises(Garbled, match="more blocks"):
        Screen().read(frame.header, frame.data)
    fits = Frame(16, 16)
    for _ in range(8):
        fits.colours([(0, WHITE)])
    assert Screen().read(fits.header, fits.data) == 8


def test_no_frame_is_longer_than_its_screen_could_take() -> None:
    small = Frame(16, 16)
    small.colours([(0, WHITE)])
    with pytest.raises(Garbled, match="longer"):
        Screen().read(small.header, small.data + bytes(2 * 3 * 16 * 16 + 4096))


def test_a_screen_is_no_larger_than_the_ones_a_controller_has() -> None:
    # Kept for every block: what it was last. At 4096 by 4096 that came to half a gigabyte for one screen.
    wide = Frame(2048, 8)
    wide.colours([(0, WHITE)])
    assert Screen().read(wide.header, wide.data) == 1
    wider = Frame(2056, 8)
    wider.colours([(0, WHITE)])
    with pytest.raises(Garbled):
        Screen().read(wider.header, wider.data)


def test_what_is_kept_of_a_block_is_kept_small() -> None:
    frame = Frame(16, 8)
    across = list(FLAT)
    across[0], across[1] = 0, 30
    frame.jpeg(across, FLAT, FLAT)
    frame.jpeg(shade(40), FLAT, FLAT)
    kept = [plane for planes in read(frame)._planes.values() for plane in planes]
    assert len(kept) == 6 and all(isinstance(plane, (int, bytes)) for plane in kept)  # not a list of sixty-four numbers each


def test_the_picture_and_its_size_are_handed_out_together() -> None:
    # A picture is made of the screen by one thread while another reads the next frame into it. Its width, its
    # height and its bytes were three things looked at one after the other: with a new size of screen in between
    # they were of two screens, and the request for the picture ended in an error.
    first, second = Frame(64, 32), Frame(32, 16)
    first.colours([(0, WHITE)])
    second.colours([(0, BLACK)])
    screen = Screen()
    screen.read(first.header, first.data)
    before = screen.shown
    screen.read(second.header, second.data)
    after = screen.shown
    assert (before[0], before[1], len(before[2])) == (64, 32, 3 * 64 * 32)  # what was handed out is still whole
    assert (after[0], after[1], len(after[2])) == (32, 16, 3 * 32 * 16) and after[2] is screen.rgb


def test_a_frame_that_nobody_waits_for_any_more_is_let_go_of() -> None:
    # A thread cannot be told to stop. One that was reading a long frame for a console that had been closed
    # read it to its end, and the program waited for it on its way out.
    frame = Frame(640, 480)
    for _ in range(300):
        frame.colours([(0, WHITE)])
    screen = Screen()
    screen.given_up = True
    with pytest.raises(Garbled):
        screen.read(frame.header, frame.data)
