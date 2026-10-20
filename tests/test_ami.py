"""The console of a controller with AMI's firmware: what is sent, what arrives, how a frame is put together."""

from __future__ import annotations

import pytest

from qkvm import ami
from qkvm.aspeed import Garbled, Screen
from tests.aspeed_frames import Frame


def test_messages_arrive_in_any_pieces_and_come_out_whole() -> None:
    sent = ami.message(ami.ALLOWED) + ami.message(ami.PASS_SEEN, 0, bytes([1, 3])) + ami.message(ami.VIDEO, 7, bytes(range(40)))
    for step in (1, 3, 8, 11, len(sent)):
        arriving, found = ami.Messages(), []
        for start in range(0, len(sent), step):
            found += arriving.feed(sent[start : start + step])
        assert [(m.kind, m.status, len(m.body)) for m in found] == [(ami.ALLOWED, 0, 0), (ami.PASS_SEEN, 0, 2), (ami.VIDEO, 7, 40)], step
        assert found[2].body == bytes(range(40))


def test_a_message_that_says_it_is_longer_than_any_is_not_waited_for() -> None:
    # Believed, it would have qKVM keep whatever arrives for as long as the controller cares to send.
    with pytest.raises(Garbled):
        ami.Messages().feed(bytes([ami.VIDEO, 0]) + (ami.LONGEST + 1).to_bytes(4, "little") + bytes(2))


def test_the_answer_to_allowed_is_the_pass_and_send_the_picture() -> None:
    first, second = ami.Messages().feed(ami.hello("a-console-pass", "192.168.1.20", "192.168.1.50"))
    assert (first.kind, first.status, len(first.body)) == (ami.PASS, 1, 438) and (second.kind, second.body) == (ami.RESUME, b"")
    assert first.body[0] == 0 and first.body[1:130].rstrip(b"\0") == b"a-console-pass"
    assert first.body[130:195].rstrip(b"\0") == b"192.168.1.20" and first.body[195:324].rstrip(b"\0") == b"domain/username"
    assert first.body[373:438].rstrip(b"\0") == b"192.168.1.50"
    # A field is never filled to its last byte: what reads it there looks for the zero that ends it.
    assert ami.Messages().feed(ami.hello("p" * 500, "", ""))[0].body[129] == 0


def test_firmware_that_lets_a_console_reconnect_is_told_the_connection_is_complete_first() -> None:
    # A real controller said "allowed", was shown the pass, and closed without a word: its firmware wants this first.
    kinds = [(m.kind, m.status, len(m.body)) for m in ami.Messages().feed(ami.hello("a-pass", "192.168.1.20", "192.168.1.50", complete_first=True))]
    assert kinds == [(ami.COMPLETE, 1, 0), (ami.PASS, 1, 438), (ami.RESUME, 0, 0)]
    assert [(m.kind, m.status, m.body) for m in ami.Messages().feed(ami.goodbye())] == [(ami.STOP, 0, b"")]


def facts(frame: Frame) -> bytes:
    header, found = frame.header, bytearray(86)
    found[4:6], found[6:8] = header.width.to_bytes(2, "little"), header.height.to_bytes(2, "little")
    found[13:15], found[15:17] = header.grid_width.to_bytes(2, "little"), header.grid_height.to_bytes(2, "little")
    found[44], found[45], found[47], found[55] = header.strength, int(header.luma_for_colour), header.correction_strength, int(header.half_colour)
    found[69:72] = len(frame.data).to_bytes(3, "little")
    return bytes(found)


def test_whoever_asks_for_the_console_is_let_in_the_way_the_controllers_own_page_does_it() -> None:
    # Said twice over, with who is asking as the controller named them: once as the answer, once as "theirs now".
    who = b"admin".ljust(64, b"\0") + b"192.168.1.60".ljust(70, b"\0")
    said = [(m.kind, m.status, m.body) for m in ami.Messages().feed(ami.let_in(who))]
    assert said == [(ami.SHARING, 1, who), (ami.NEXT_HOLDER, 1, who)]
    # What the numbers in a real board's own words were: "the one who held it is coming back" came as 1796.
    assert ami.ANSWERED | ami.HOLDER_RETURNING << 8 == 1796


def test_a_frame_is_put_together_from_its_pieces() -> None:
    frame = Frame(24, 8, strength=2, correction_strength=6, luma_for_colour=True)
    for colour in (0xEB8080, 0x108080, 0x515AF0):
        frame.colours([(0, colour)])
    data, frames = frame.data, ami.Frames()
    assert frames.piece(bytes(2) + facts(frame) + data[:5]) is None
    assert frames.piece(bytes(2) + data[5:9]) is None
    header, whole = frames.piece(bytes(2) + data[9:]) or (None, b"")
    assert header == frame.header and whole == data
    screen = Screen()
    assert screen.read(header, whole) == 3 and screen.rgb[:3] == bytes([255, 255, 255])
    # ...and the next piece begins the next frame.
    again = frames.piece(bytes(2) + facts(frame) + data)
    assert again is not None and again[1] == data


def test_a_picture_that_is_sent_encrypted_is_said_to_be_so() -> None:
    frame = Frame(8, 8)
    frame.colours([(0, 0x108080)])
    locked = bytearray(facts(frame))
    locked[53] = 1
    with pytest.raises(Garbled, match="encrypted"):
        ami.Frames().piece(bytes(2) + bytes(locked) + frame.data)
    with pytest.raises(Garbled):
        ami.Frames().piece(bytes(2) + bytes(20))  # a first piece too short to say how the frame is to be read


def test_more_messages_at_once_than_a_console_sends_are_not_taken_in() -> None:
    # Found by a review, and measured: one thing sent over the connection may be megabytes, the smallest message
    # is eight bytes, and every one of four million was made into an object, on the thread that serves every
    # browser. Nothing was served for nine seconds.
    assert len(ami.Messages().feed(ami.message(ami.STILL_THERE) * ami.MOST_AT_ONCE)) == ami.MOST_AT_ONCE
    with pytest.raises(Garbled):
        ami.Messages().feed(ami.message(ami.STILL_THERE) * (ami.MOST_AT_ONCE + 1))
    arriving = ami.Messages()  # (what is left over from one time is the beginning of the next, as before)
    whole = ami.message(ami.VIDEO, 0, bytes(range(50)))
    assert arriving.feed(ami.message(ami.ALLOWED) + whole[:20]) and [m.body for m in arriving.feed(whole[20:])] == [bytes(range(50))]


def test_a_frame_that_says_it_is_longer_than_any_is_not_collected() -> None:
    # Its pieces were put together up to sixteen megabytes before anything looked at how long that is.
    frame = Frame(24, 8)
    frame.colours([(0, 0xEB8080)])
    said = bytearray(facts(frame))
    said[69:72] = (ami.LONGEST + 1).to_bytes(3, "little")
    with pytest.raises(Garbled):
        ami.Frames().piece(bytes(2) + bytes(said) + frame.data)


def one_hid(packet: bytes) -> tuple[bytes, bytes]:
    """The one HID message `packet` is, as (the thirty-two byte IUSB header, the report after its length byte)."""
    found = ami.Messages().feed(packet)
    assert len(found) == 1 and found[0].kind == ami.HID, found
    body = found[0].body
    assert body[:8] == b"IUSB    " and sum(body[:32]) & 0xFF == 0, "the header names IUSB and sums to zero"
    assert body[32] == len(body[33:]), "the report length byte matches"
    return body[:32], body[33:]


def test_a_keyboard_report_is_the_modifiers_and_the_keys_down() -> None:
    header, report = one_hid(ami.keyboard(0x05, [0x04, 0x05], 7))
    assert header[17] == 0x30 and header[18] == 0x10, "a keyboard report, for the virtual USB keyboard"
    assert report == bytes([0x05, 0, 0x04, 0x05, 0, 0, 0, 0]), "the modifier byte, a reserved zero, then the keys down in six slots"
    # The whole keyboard every time: nothing down is an empty report, and no more than six keys go (the first six
    # given; the live line hands over the six newest, dropping the oldest as a keyboard does: live.RedfishHid).
    assert one_hid(ami.keyboard(0, []))[1] == bytes(8)
    assert list(one_hid(ami.keyboard(0, [4, 5, 6, 7, 8, 9, 10]))[1][2:]) == [4, 5, 6, 7, 8, 9]


def test_the_sequence_number_goes_up_and_the_checksum_catches_a_changed_byte() -> None:
    # The controller checks the header sums to zero; a byte flipped on the way would be caught. And every report
    # carries a number one higher than the last, as the controller's own viewer sends them.
    assert ami.keyboard(0, [4], 1) != ami.keyboard(0, [4], 2)  # the sequence number is in the header
    bad = bytearray(ami.keyboard(0, [4], 1))
    bad[8 + 20] ^= 0x01  # a byte of the IUSB header (past the message's own eight-byte head)
    assert sum(bad[8 : 8 + 32]) & 0xFF != 0, "the header no longer sums to zero"


def test_an_absolute_mouse_report_carries_the_place_and_a_relative_one_the_move() -> None:
    header, report = one_hid(ami.mouse_abs(0x01, 16384, 32767, 0, 3))
    assert header[17] == 0x31 and header[18] == 0x20, "a mouse report, for the virtual USB mouse"
    import struct

    buttons, x, y, wheel = struct.unpack("<BHHb", report)
    assert (buttons, x, y, wheel) == (0x01, 16384, 32767, 0)
    # A place past the far edge is held at it; a relative report is four bytes of buttons and a signed move.
    assert struct.unpack("<BHHb", one_hid(ami.mouse_abs(0, 99999, -5, -1))[1]) == (0, 0x7FFF, 0, -1)
    assert struct.unpack("<Bbbb", one_hid(ami.mouse_rel(0x04, -3, 7, 1))[1]) == (0x04, -3, 7, 1)
