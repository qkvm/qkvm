"""The screen of a server whose management controller runs OpenBMC: its console, the WebSocket `/kvm/0`, carrying RFB.

bmcweb (OpenBMC's web server) announces the console in its manager as a graphical console of the KVM-over-IP kind
(see redfish.rfb_console), and hands what comes over the WebSocket on to obmc-ikvm, a VNC server that sends the
picture its video engine takes of the server's screen. The upgrade is signed in to as any request of bmcweb's: here
with the Redfish session the server's tile holds already (its X-Auth-Token header), so no second sign-in is made.

Built from bmcweb's source (features/kvm/kvm_websocket.hpp: the route, its privileges, four sessions at the most, the
connection to obmc-ikvm on the controller's own loopback) and obmc-ikvm's (no password of its own; it sends frames
at its own pace, whatever is asked). Tried on OpenBMC's romulus image in QEMU (2026-10-15): there the upgrade is
signed in to with the session's token (and refused without one, or with a session that was given back), and that
build of bmcweb has no console (no graphical console announced, and the path answers "not found" to a signed-in
upgrade), so no picture ever came from a real OpenBMC. The pictures are the stand-in's (tests/fake_redfish.py).

Keys and the pointer go the way they go to a VNC server (vncdevice.ScreenInput): RFB's key and pointer events, over the
console the screen comes on. bmcweb hands on what comes over the WebSocket as it comes, both ways, to whoever may open
the console at all (its route asks ConfigureComponents or ConfigureManager: an account that may not is refused the
console, picture and keys together); obmc-ikvm turns the events into the reports of the USB keyboard and the absolute
mouse it gives the server, and drops what comes in a client's first frames (about a second): input waits that long
after the console opens (INPUT_AFTER). Where a build has no USB keyboard for obmc-ikvm to write to, the keys go nowhere,
and nothing on the console says so. None of this has been seen on a real controller.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from . import rfb
from .kvm import DOWN_CODES, DeviceSpec, KvmError
from .vncdevice import DoorScreen

if TYPE_CHECKING:
    from .redfish import RedfishDevice


class OpenBmcScreen(DoorScreen):
    """The server's screen through OpenBMC's console, held while somebody looks (one of the controller's four seats)."""

    kind = "redfish"
    THING = "the server's console"
    # obmc-ikvm asks for no password. One that asks for VNC authentication is answered nothing: the only password here
    # is the controller's own, which goes to the controller's sign-in and to nothing else.
    SIGNS_IN = (rfb.SECURITY_NONE,)
    # Every session is a seat of four: a console that gives a picture and ends, every time, is not well; only one that
    # lasted half a minute is.
    SETTLED_BY_A_FRAME = False
    LOOK_PACE = 1.0  # (it sends frames at its own pace whatever is asked: asking often adds nothing)
    # obmc-ikvm takes no keys and no pointer from a client for its first frames (`skipFrame`, as many as its frame rate,
    # thirty by default): they wait this long after the handshake.
    INPUT_AFTER = 1.5
    # obmc-ikvm makes each keysym into the key of its USB keyboard the keysym is on ('A' and 'a' the A key, '!' the 1 key:
    # ikvm_input.cpp, keyToScancode) and sets Shift only from a Shift key's own events (keyToMod): typed text goes with
    # the US layout's Shift around what needs it, and what that layout cannot type is refused (vncdevice.text_events).
    US_SHIFT = True

    def __init__(self, spec: DeviceSpec, server: RedfishDevice) -> None:
        super().__init__(spec)
        self._server = server

    def _retry(self) -> tuple[float, ...]:
        from .redfish import CONSOLE_RETRY  # (a controller's console seats are few: as for its other console)

        return CONSOLE_RETRY

    async def _open(self) -> rfb.Stream:
        """The console's WebSocket, signed in with the server's Redfish session: what follows is RFB."""
        try:
            ws: Any = await self._server.rfb_socket()
        except KvmError as ex:
            # On this console's own ladder, as a session that failed later is: not asked for again at every picture.
            # (A no to the controller's password is the tile's to say: asking again costs nothing then.)
            if ex.code in DOWN_CODES:
                raise self._failed(ex) from None
            if ex.code == "bad_response":
                raise self._left_alone(ex) from None
            raise
        return rfb.WebSocketStream(ws)

    def _ended(self, session: Any, offered: str, ex: rfb.RfbError) -> KvmError:
        if ex.code in (rfb.REFUSED, rfb.UNSUPPORTED, rfb.AUTH, rfb.NO_PASSWORD):
            # Nothing to do with the controller's password (which was not offered here): said, and left alone.
            return self._left_alone(KvmError("bad_response", f"The server's console does not let qKVM in: {ex.message}"))
        return super()._ended(session, offered, ex)
