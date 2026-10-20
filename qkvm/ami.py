"""The console of a management controller that runs AMI's firmware (MegaRAC), as far as its picture goes.

Redfish says how a server is; it has no request for what is on its screen. The screen is in the
controller's own console, the one its web page opens: a WebSocket at /kvm that speaks a protocol of
AMI's, with the picture in the format of the chip that takes it (see aspeed.py). This file is that
protocol, without the network: what is sent, what arrives, and how a frame is put together from it.

How a console session goes:

* Sign in to the controller's web interface (POST /api/session) and ask it for a console pass
  (GET /api/kvm/token). Both are done by whoever uses this file.
* Open the WebSocket. The controller says the connection is allowed; it is answered with the pass
  (`hello`), and says whether the pass is good. Firmware that lets a console reconnect after a
  break wants to be told "connection complete" before the pass, and closes on whoever does not.
* From then on it sends the screen: a full frame first, then what changes. Every frame comes in
  pieces (`Frames` puts them together). Now and then it asks whether anybody is still there, and is
  told so.

The same connection carries keys and the mouse, as USB HID reports the controller hands to the server
(`keyboard`, `mouse_abs`, `mouse_rel`), and the power buttons, which nothing here sends (the wall's power
buttons are Redfish's). A session is ended by saying so (`goodbye`), as the controller's own page does when
its window is closed: a console that just goes away leaves the controller waiting for it.

A console is shared. Whoever opened it first holds it; when another comes, the controller asks the
holder whether they may have it (keys and all, the picture only, or not at all), tells the newcomer
to wait, and gives the console to the newcomer if no answer comes in half a minute. Whoever only
looks, and has nobody sitting at it to answer, must not be in a person's way on either side of that:
see `let_in`, and what is done with `WAITING` by whoever uses this file.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .aspeed import LONGEST as _FRAME_LONGEST
from .aspeed import FrameHeader, Garbled

# What every message begins with: its kind, how many bytes follow, and a number whose meaning is the kind's.
_HEAD = struct.Struct("<HIH")

# The kinds of message that matter for looking (the numbers are the protocol's).
HID = 1  # a keyboard or mouse report, going up to the controller (CMD_SEND_HID_PACKET)
RESUME = 6  # "send the picture"
STOP = 8  # the controller ends the session (its status says why)
MOUSE_MODE = 10  # the controller says which mouse the server shows: absolute or relative
FULL_SCREEN = 11  # "send the whole screen, not only what changes"
PASS = 18  # the console pass, shown to the controller
PASS_SEEN = 19  # ...and what it makes of it
WEB_SESSION = 21  # which web session this console belongs to
TOO_MANY = 22  # every console seat is taken
ALLOWED = 23  # the first thing the controller says
VIDEO = 25  # a piece of a frame
SHARING = 32  # who may use the console when more than one has it open: asked, told to wait, answered
OTHERS = 39  # who else has the console open
NEXT_HOLDER = 50  # the same, about who holds the console from now on
LICENCE = 53  # what the controller is licensed for; the web page answers it with its web session
STILL_THERE = 57  # asked by the controller, and echoed
COMPLETE = 58  # "the connection is complete": said first, to firmware that lets a console reconnect
REFUSED = 59
BEHIND = 60  # how many frames the viewer has not drawn yet (it is told: none)

# Why the controller ends a session (the number of its STOP), in words for the log. One of them is no fault:
TIME_UP = 9  # the session's time is up (half an hour in which no key was pressed, as a rule)
ENDED = {
    2: "its console service was restarted",
    5: "its console settings were changed",
    7: "its web session was signed out",
    8: "its licence for the console ran out",
    TIME_UP: "the session's time was up",
    10: "the session was ended at the controller",
    11: "its web server was restarted",
    12: "the controller was restarted",
    13: "the controller was put back to how it came",
}

# What a message about sharing is about (the low byte of its number)...
ASKED = 1  # whoever holds the console is asked whether another may have it; the body says who that is
WAITING = 2  # ...and that other is told to wait for the answer
ANSWERED = 4  # the answer, to the one who waited
# ...and the answer it carries (the high byte).
LET_IN = 0
TURNED_AWAY = 1
PICTURE_ONLY = 2
HOLDER_RETURNING = 7  # nobody answered: the holder's console dropped, and they may come back
SHUT_OUT = 8  # the holder has set that nobody else comes in
# The number a PASS_SEEN comes with where this is the first console session there is: the controller attaches its
# virtual keyboard and mouse to the server only now (where it is set to save power), and they take moments to appear.
FIRST_SESSION = 2

# The low byte of a sharing message that says this console is now the one that holds the keyboard and mouse
# ("the console is yours"): a lone session is greeted with it (NEXT_HOLDER, status 6).
BECAME_MASTER = 6

# Which mouse the server shows, as the controller names it (the body of a MOUSE_MODE message; the viewer's own
# word). Absolute is what AMI's own web viewer uses and most boards default to; relative is the other.
ABSOLUTE = 2
RELATIVE = 1

LONGEST = _FRAME_LONGEST  # no message is longer than a frame may be, and a controller that says one is, is not believed
# ...nor do more than this many arrive in one go. The smallest is eight bytes: megabytes of those, every one made
# into an object on the thread that serves every browser, and nothing was served for nine seconds.
MOST_AT_ONCE = 256

# Sizes of the fields of the pass message (text, padded with zeros).
_PASS, _ADDRESS, _NAME, _MAC = 129, 65, 129, 49

# Where in a frame's first piece the facts about the frame stand (after the two bytes every piece begins with).
_FRAME_FACTS = 86


@dataclass(frozen=True)
class Message:
    kind: int
    status: int
    body: bytes


def message(kind: int, status: int = 0, body: bytes = b"") -> bytes:
    """One message, as it is sent."""
    return _HEAD.pack(kind, len(body), status) + body


def _text(value: str, size: int) -> bytes:
    return value.encode("ascii", "replace")[: size - 1].ljust(size, b"\0")


# What the controller's own page calls its user (it has no way of knowing who that is), and so what a controller is used to.
NAME = "domain/username"
# Firmware that lets a console reconnect after a break says so in the list of what it can do.
RECONNECTS = "KVM_SESSION_RECONNECT"


def hello(console_pass: str, own_address: str, controller_address: str, name: str = NAME, complete_first: bool = False) -> bytes:
    """What the controller is answered with when it says the connection is allowed: the pass, and "send the picture".

    `complete_first`: begin with "the connection is complete", as firmware that lets a console reconnect expects.
    """
    body = b"\0" + _text(console_pass, _PASS) + _text(own_address, _ADDRESS) + _text(name, _NAME) + _text("00-00-00-00-00-00", _MAC)
    first = message(COMPLETE, 1) if complete_first else b""
    return first + message(PASS, 1, body + _text(controller_address, _ADDRESS)) + message(RESUME)


def let_in(who: bytes) -> bytes:
    """What the console's holder says to let another have it, keys and all. `who`: as the controller named them when it asked.

    Said twice over, as the controller's own page says it: once as the answer, once as "the console is theirs now".
    """
    number = ASKED | LET_IN << 8
    return message(SHARING, number, who) + message(NEXT_HOLDER, number, who)


def goodbye() -> bytes:
    """What ends a session, said before the connection is closed."""
    return message(STOP)


# --- keys and the mouse, as HID reports the controller passes to the server's USB ------------------------
# A keyboard or mouse report goes up in a HID message (CMD_SEND_HID_PACKET). Its body is an "IUSB" packet: a
# 32-byte header that names which virtual USB device it is for and carries a checksum, then one byte saying how
# long the report is, then the report itself. The header's layout, the field values and the checksum are the
# controller's (read from AMI's own web viewer, which is how the real boards are driven); the report bodies are
# the USB HID boot keyboard and mouse reports of the USB HID standard. Nothing here touches the network.
_IUSB = b"IUSB    "  # the eight bytes an IUSB packet begins with
_IUSB_HDR = 32  # the header's length
_MAJOR, _MINOR = 1, 0
_FROM_REMOTE = 0x80  # the report is going to the server, not coming from it
_DEV_KEYBD, _DEV_MOUSE = 0x30, 0x31  # which virtual USB device the report is for
_PROTO_KEYBD, _PROTO_MOUSE = 0x10, 0x20
_KEYBD_DEVNUM, _KEYBD_IFNUM = 2, 0
_MOUSE_DEVNUM, _MOUSE_IFNUM = 2, 1
MOST_KEYS = 6  # keys one keyboard report holds, beside the modifiers (a USB boot keyboard's own limit)


def _iusb_packet(dev_type: int, proto: int, dev_num: int, if_num: int, seq: int, report: bytes) -> bytes:
    """One HID message: the IUSB header (with its checksum) that names the virtual USB device, then `report`."""
    header = bytearray(_IUSB)
    header += bytes((_MAJOR, _MINOR, _IUSB_HDR, 0))  # ...major, minor, header length, and a space for the checksum
    header += struct.pack("<i", len(report) + 1)  # the report and its one length byte
    header += bytes((0, dev_type, proto, _FROM_REMOTE, dev_num, if_num, 0, 0))
    header += struct.pack("<i", seq & 0x7FFFFFFF)
    header += bytes(4)  # (the header is thirty-two bytes to here)
    header[11] = (-sum(header)) & 0xFF  # so the thirty-two bytes sum to zero, as the controller checks
    return message(HID, 0, bytes(header) + bytes((len(report),)) + report)


def keyboard(modifiers: int, keys: list[int], seq: int = 0) -> bytes:
    """A keyboard report: the modifier bits held (USB HID: bit 0 left Ctrl ... bit 7 right Meta) and up to six keys
    down, by their USB HID usage. The whole state of the keyboard, as a USB boot keyboard reports it; a key no
    longer in it is let go of. The second byte is reserved (held at zero: the auto-release the viewer puts there is
    not used, so that a key stays down until a report without it, which is what holding a combination needs)."""
    held = [usage & 0xFF for usage in keys[:MOST_KEYS]]
    report = bytes((modifiers & 0xFF, 0)) + bytes(held).ljust(MOST_KEYS, b"\0")
    return _iusb_packet(_DEV_KEYBD, _PROTO_KEYBD, _KEYBD_DEVNUM, _KEYBD_IFNUM, seq, report)


def mouse_abs(buttons: int, x: int, y: int, wheel: int = 0, seq: int = 0) -> bytes:
    """An absolute mouse report: the buttons held (bit 0 left, bit 1 right, bit 2 middle), where the pointer is
    (0 to 32767 across the screen and down it), and a turn of the wheel (a signed step). This is what AMI's own
    viewer sends, and what a board set to an absolute mouse takes."""
    place = max(0, min(0x7FFF, x)), max(0, min(0x7FFF, y))
    report = struct.pack("<BHHb", buttons & 0xFF, place[0], place[1], max(-127, min(127, wheel)))
    return _iusb_packet(_DEV_MOUSE, _PROTO_MOUSE, _MOUSE_DEVNUM, _MOUSE_IFNUM, seq, report)


def mouse_rel(buttons: int, dx: int, dy: int, wheel: int = 0, seq: int = 0) -> bytes:
    """A relative mouse report: the buttons held and how far the pointer moved (a signed step each way), for a board
    set to a relative mouse. (AMI's own viewer sends only absolute; this is the other way, for a board that asks for it.)"""
    report = struct.pack("<Bbbb", buttons & 0xFF, max(-127, min(127, dx)), max(-127, min(127, dy)), max(-127, min(127, wheel)))
    return _iusb_packet(_DEV_MOUSE, _PROTO_MOUSE, _MOUSE_DEVNUM, _MOUSE_IFNUM, seq, report)


class Messages:
    """What arrives over the connection, cut into the messages it is made of (they need not arrive whole)."""

    def __init__(self) -> None:
        self._waiting = bytearray()

    def feed(self, data: bytes) -> list[Message]:
        self._waiting += data
        found: list[Message] = []
        at = 0
        with memoryview(self._waiting) as waiting:
            while len(waiting) - at >= _HEAD.size:
                kind, length, status = _HEAD.unpack_from(waiting, at)
                if length > LONGEST:
                    raise Garbled(f"a message of {length} bytes")
                if len(waiting) - at < _HEAD.size + length:
                    break
                if len(found) >= MOST_AT_ONCE:
                    raise Garbled("more messages at once than a console sends")
                found.append(Message(kind, status, bytes(waiting[at + _HEAD.size : at + _HEAD.size + length])))
                at += _HEAD.size + length
        del self._waiting[:at]  # once, and not after every message: what is left is moved up each time
        return found


class Frames:
    """Frames, put together from the pieces they are sent in.

    A frame's first piece says how the frame is to be read and how long it is; the pieces that follow
    are more of its data, until that many bytes are there.
    """

    def __init__(self) -> None:
        self._header: FrameHeader | None = None
        self._wanted = 0
        self._data = bytearray()

    def piece(self, body: bytes) -> tuple[FrameHeader, bytes] | None:
        """Take one video message. Returns a frame when this piece completes one."""
        data = body[2:]
        if self._header is None:
            if len(data) < _FRAME_FACTS:
                raise Garbled("a frame that begins with less than what says how to read it")
            facts, data = data[:_FRAME_FACTS], data[_FRAME_FACTS:]
            if facts[53]:
                raise Garbled("a picture that is sent encrypted: this is not read yet")
            self._wanted = int.from_bytes(facts[69:72], "little")
            if self._wanted > LONGEST:
                raise Garbled("a frame longer than a screen can be")  # said here, before its pieces are collected
            self._header = FrameHeader(
                width=int.from_bytes(facts[4:6], "little"),
                height=int.from_bytes(facts[6:8], "little"),
                grid_width=int.from_bytes(facts[13:15], "little"),
                grid_height=int.from_bytes(facts[15:17], "little"),
                half_colour=facts[55] == 1,
                strength=facts[44],
                correction_strength=facts[47],
                luma_for_colour=facts[45] == 1,
            )
            self._data = bytearray()
        self._data += data
        if len(self._data) < self._wanted:
            return None
        header, self._header = self._header, None
        return header, bytes(self._data[: self._wanted])
