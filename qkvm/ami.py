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

Only looking is done here. The same connection carries keys, the mouse and the power buttons; nothing
in this file sends any of them. A session is ended by saying so (`goodbye`), as the controller's own
page does when its window is closed: a console that just goes away leaves the controller waiting for it.

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
RESUME = 6  # "send the picture"
STOP = 8  # the controller ends the session (its status says why)
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
