"""The serial console of a PC with Intel AMT (Serial over LAN): what the PC writes to its engine's serial port, read.

The engine carries it on its redirection port, as it carries the KVM: the same handshake and Digest sign-in (amt.signed_in),
asked for "SOL " where the KVM asks for "KVMR"; then a start message with the session's settings, the text the PC writes in
messages of their own, and a ping the console sends and the engine answers. The message codes are Intel's, as the published
sources of MeshCommander and amtterm name them (read to learn them, not copied), and what a real engine (AMT 16) answered:
the start of the session, its settings' answer of 23 bytes, a pong to every ping, nothing else while the PC wrote nothing.

Read only: nothing is ever sent to the PC. What comes is kept in a bounded buffer (the last MOST_KEPT bytes, a terminal's
bytes as the PC wrote them, escape sequences and all). Every read has a size limit and a time limit, a flood is cut off, and
the reader gives the loop its turn after every message: what answers on that port may be no engine at all.

What a real PC sent over it: nothing, while Windows ran or started; started into its BIOS setup with Serial over LAN asked
for (the engine's boot options), a graphical BIOS sent the codes that clear a terminal and set it to 80 by 25, and no text.
So this is built and tried against the stand-in, and nothing on the wall shows it yet (see the README).
"""

from __future__ import annotations

import asyncio
import logging
import struct
import time
from typing import Any

from . import amt, rfb
from .kvm import NO_SAID, REJECTED, DeviceSpec, KvmError
from .vncdevice import CONNECT_WAIT, VncDevice

log = logging.getLogger("qkvm")

START_SOL = bytes((0x10, 0x00, 0x00, 0x00)) + b"SOL "  # "a redirection session, for the serial console"
WORDS = ("its serial console", "a serial console session")
SOL_START, SOL_STARTED, SOL_END, SOL_ENDED = 0x20, 0x21, 0x22, 0x23
PING, PONG = 0x24, 0x25  # the console asks whether the engine is there; it answers
CONTROLS, FROM_PC, HEARTBEAT = 0x29, 0x2A, 0x2B  # (0x28 carries text to the PC: never sent here)
END_SESSION = bytes((0x12, 0x00, 0x00, 0x00))
STARTED_LENGTH = 23  # the answer to the start message, as a real engine sent it
# The session's settings, as the console asks for them: the most it sends at once and how long it holds that back (ms), the
# same for an overflow, how long the engine waits for a word of the console's before it ends the session (ms), how long it
# holds what the PC wrote before it sends it (ms), and a heartbeat (0: none; the pings do that).
SETTINGS = (10000, 100, 0, 10000, 100, 0)
PING_EVERY = 2.0  # seconds between pings (a real engine answered each at once)
QUIET_WITHIN = 10.0  # seconds without any message (a pong answers every ping) after which the engine is taken to be gone
STEP = 8.0  # seconds the rest of a message has to come in once its first byte has
END_WAIT = 2.0  # seconds the engine has to answer the console's end
ENDED = "the engine ended the serial console"
MOST_MESSAGE = 16 * 1024  # bytes one message of text may say it carries (a serial port's text comes in small pieces)
MOST_KEPT = 64 * 1024  # bytes of what the PC wrote that are kept, the newest
# A serial port at 115200 baud writes about 11 kB a second: what sends far more than that is no serial console.
MOST_A_SECOND = 256 * 1024
MESSAGES_A_SECOND = 4000


def start_message(sequence: int) -> bytes:
    """The start of the serial console, with the session's settings (24 bytes, little-endian)."""
    return struct.pack("<B3xIHHHHHHI", SOL_START, sequence, *SETTINGS, 0)


def short_message(code: int, sequence: int) -> bytes:
    """A message of the console's that carries nothing but its sequence number (a ping, the end of the console)."""
    return struct.pack("<B3xI", code, sequence)


class Kept:
    """What the PC wrote, the last `most` bytes of it, and how much came in all. Trimmed when it holds twice that: each byte
    is moved once at the most, whatever size the pieces come in."""

    def __init__(self, most: int = MOST_KEPT) -> None:
        self.most = most
        self._data = bytearray()
        self.total = 0  # bytes that came, kept or not

    def add(self, data: bytes) -> None:
        self.total += len(data)
        self._data += data
        if len(self._data) > 2 * self.most:
            del self._data[: len(self._data) - self.most]

    def last(self) -> bytes:
        """The newest `most` bytes (a copy)."""
        return bytes(self._data[-self.most :])


async def read_console(stream: rfb.Stream, kept: Kept, quiet_within: float = QUIET_WITHIN) -> None:
    """What the engine sends once the serial console has begun, into `kept`, until it ends: never returns, rfb.RfbError says
    how it ended (CLOSED; ENDED as CLOSED where the engine ended the console; TIMEOUT where nothing came for `quiet_within`
    seconds; PROTOCOL for a message no engine sends; LIMIT for one larger than any, or a flood)."""
    window, sent, messages = time.monotonic(), 0, 0
    while True:
        code = (await stream.read(1, quiet_within))[0]
        size = 1
        if code == FROM_PC:
            head = await stream.read(9, STEP)
            length = int.from_bytes(head[7:9], "little")
            if length > MOST_MESSAGE:
                raise rfb.RfbError(rfb.LIMIT, f"the engine says a piece of the serial console's text is {length} bytes long, which none is")
            data = await stream.read(length, STEP) if length else b""
            kept.add(data)
            size += 9 + length
        elif code == CONTROLS:
            await stream.read(9, STEP)  # (the PC's modem lines and the port's state: nothing this program shows)
            size += 9
        elif code in (PONG, HEARTBEAT):
            await stream.read(7, STEP)
            size += 7
        elif code == amt.RECORDED:
            pass  # ("this session is being recorded": one byte)
        elif code == SOL_ENDED:
            await stream.read(7, STEP)
            raise rfb.RfbError(rfb.CLOSED, ENDED)
        else:
            raise rfb.RfbError(rfb.PROTOCOL, f"the engine sent {code:#04x}, which is no message of a serial console")
        now = time.monotonic()
        if now - window >= 1.0:
            window, sent, messages = now, 0, 0
        sent, messages = sent + size, messages + 1
        if sent > MOST_A_SECOND or messages > MESSAGES_A_SECOND:
            raise rfb.RfbError(rfb.LIMIT, "the engine sends more than a serial console writes")
        await asyncio.sleep(0)  # (a full buffer is read without waiting: the loop has its turn after every message)


class SerialConsole:
    """A PC's serial console through its engine, one session at a time: `run` opens it, keeps what the PC writes in `kept`
    until the session ends or `stop` is set (then it is ended as the engine expects), and raises KvmError where it could not
    be had or ended otherwise. The password is counted as for every sign-in of this PC's (kvm.REJECTED, the same mark as
    its tile's): offered only where no no stands, and a no here is a no there."""

    def __init__(self, spec: DeviceSpec, kept: Kept | None = None) -> None:
        self.spec = spec
        self.kept = kept or Kept()

    async def run(self, stop: asyncio.Event | None = None, quiet_within: float = QUIET_WITHIN) -> None:
        spec = self.spec
        if not spec.password:
            raise KvmError("no_password", "No password saved for this device")
        offered = REJECTED.what("login", spec)
        self._not_now(offered)
        try:
            host, port, tls = amt.redirection_address(spec.base_url)
        except ValueError:
            raise KvmError("bad_response", "Its redirection port would be its WS-Management port and two, and there is no such port above 65535") from None
        context = await amt.redirection_tls(spec) if tls else None
        try:
            stream = await rfb.open_tcp(host, port, context, CONNECT_WAIT)
        except (OSError, TimeoutError) as ex:
            raise VncDevice._connect_error(ex, spec.tls) from None
        sequence = 1

        def sending() -> None:
            # Asked again the moment before the answer goes out: a no heard on another road meanwhile stands here too.
            self._not_now(offered)
            REJECTED.sent(offered)

        def taken() -> None:
            REJECTED.accepted(offered)

        tasks: list[asyncio.Task[Any]] = []
        try:
            async with asyncio.timeout(amt.REDIRECTION_WITHIN):
                await amt.signed_in(stream, START_SOL, WORDS, spec.username, spec.password, sending, taken=taken)
                await stream.write(start_message(sequence))
                sequence += 1
                for _ in range(amt.MOST_RECORDED + 1):  # ("this session is being recorded" may come first, as for the KVM)
                    first = await stream.read(1, STEP)
                    if first[0] != amt.RECORDED:
                        break
                answer = first + await stream.read(STARTED_LENGTH - 1, STEP)
            if answer[0] != SOL_STARTED:
                raise rfb.RfbError(rfb.PROTOCOL, f"the engine answered the start of its serial console with {answer[0]:#04x}")
            if answer[1] != 0:
                raise rfb.RfbError(rfb.REFUSED, f"the engine does not start its serial console (it answers {answer[1]})")
            log.info("%s: the serial console is open", spec.name)

            async def ping() -> None:
                nonlocal sequence
                while True:
                    await asyncio.sleep(PING_EVERY)
                    sequence += 1  # (taken before it goes: a ping cut short leaves its number used)
                    await stream.write(short_message(PING, sequence - 1))

            pinging = asyncio.create_task(ping())
            reading = asyncio.create_task(read_console(stream, self.kept, quiet_within))
            tasks = [pinging, reading]
            if stop is not None:
                tasks.append(asyncio.create_task(stop.wait()))
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            if reading in done or pinging in done:
                (reading if reading in done else pinging).result()  # (raises what ended it: neither returns)
            # Stopped: the console is ended as the engine expects it (its end, the engine's answer, then the session's end).
            pinging.cancel()
            await self._end(stream, reading, sequence)
        except TimeoutError:
            raise KvmError("timeout", "The engine did not finish starting its serial console in time", 504) from None
        except rfb.RfbError as ex:
            raise self._ended(offered, ex) from None
        finally:
            for task in tasks:
                task.cancel()
            await stream.close()  # (first: it is done at once, and a second stop during the wait below must not leave it open)
            await asyncio.gather(*tasks, return_exceptions=True)

    @staticmethod
    async def _end(stream: rfb.Stream, reading: asyncio.Task[None], sequence: int) -> None:
        """End the console the way the engine expects: its end, read on until the engine has answered it (what came meanwhile is
        kept as ever), then the session's end. Never more than END_WAIT in all, and nothing of it is a failure: it was stopped."""
        try:
            async with asyncio.timeout(END_WAIT):
                await stream.write(short_message(SOL_END, sequence))
                await asyncio.wait([reading])
                answered = isinstance(error := reading.exception(), rfb.RfbError) and error.message == ENDED
                if answered:
                    await stream.write(END_SESSION)
        except (TimeoutError, rfb.RfbError):
            pass

    @staticmethod
    def _not_now(offered: str) -> None:
        """Raise what stands against offering the password now: a no, or a sign-in that came to nothing a moment ago."""
        if REJECTED.wait_left(offered) > 0:
            if REJECTED.times(offered):
                raise KvmError("auth_failed", NO_SAID)
            raise KvmError("no_sign_in", "A sign-in to it came to nothing a moment ago. It is asked again shortly.", 503)

    def _ended(self, offered: str, ex: rfb.RfbError) -> KvmError:
        """What a session that ended this way says, and what it means for the password."""
        if ex.code == rfb.AUTH:
            REJECTED.said_no(offered)
            log.warning("%s: login rejected on its redirection port", self.spec.name)
            return KvmError("auth_failed", NO_SAID)
        if ex.code == rfb.TIMEOUT:
            return KvmError("timeout", f"Its serial console: {ex.message}", 504)
        if ex.code == rfb.CLOSED:
            return KvmError("dropped", f"Its serial console: {ex.message}", 502)
        # (A sign-in that came to nothing after the password went out stays as `sent` noted it: not offered again at once.)
        return KvmError("bad_response", f"Its serial console: {ex.message}")
