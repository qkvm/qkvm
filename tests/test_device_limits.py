"""What a device's end of a connection is not let do: pack what it sends, be answered without reading, or have the password sent to it over and over."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import socket
import struct
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from websockets.exceptions import WebSocketException

from qkvm import jetkvm, kvm, update, vault
from qkvm.kvm import DeviceSpec, KvmDevice, KvmError, bounded
from tests.fake_kvm import FakeKvm
from tests.test_hardening import AsItCame
from tests.test_wall import add, wall
from tests.settings_file import settings_text

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def frame(opcode: int, payload: bytes = b"") -> bytes:
    """One whole WebSocket frame, as a device's end sends it."""
    size = len(payload)
    if size < 126:
        head = bytes([0x80 | opcode, size])
    elif size < 65536:
        head = bytes([0x80 | opcode, 126]) + struct.pack(">H", size)
    else:
        head = bytes([0x80 | opcode, 127]) + struct.pack(">Q", size)
    return head + payload


class OddDevice:
    """A device's WebSocket end written by hand, in threads of its own: it does what no library's would."""

    def __init__(self, talk: Callable[[socket.socket], None], packs: bool = False) -> None:
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._talk, self._packs = talk, packs
        self.asked: list[str] = []  # the request each caller opened with
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn: socket.socket) -> None:
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                more = conn.recv(4096)
                if not more:
                    return
                data += more
            head = data.split(b"\r\n\r\n")[0].decode("latin1")
            self.asked.append(head)
            key = next(line.split(":", 1)[1].strip() for line in head.split("\r\n") if line.lower().startswith("sec-websocket-key"))
            accept = base64.b64encode(hashlib.sha1(key.encode() + GUID).digest()).decode()
            lines = ["HTTP/1.1 101 Switching Protocols", "Upgrade: websocket", "Connection: Upgrade", f"Sec-WebSocket-Accept: {accept}"]
            if self._packs:
                lines.append("Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover")
            conn.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
            self._talk(conn)
        except OSError:  # hung up on, as it is meant to be
            pass
        finally:
            conn.close()

    def stop(self) -> None:
        self._sock.close()


def test_a_device_is_not_asked_to_pack_what_it_sends_and_is_not_let() -> None:
    # Offered the chance, a device sent a kilobyte that unpacked to a megabyte, a thousand times a second and
    # within every limit there was: the unpacking is done by the library, on the one thread there is, before
    # anything of this program's counts. The whole wall stood still for seconds at a time.
    said_hello = OddDevice(lambda conn: conn.sendall(frame(0x1, b"hello")))
    packs_anyway = OddDevice(lambda conn: conn.sendall(frame(0x1, b"hello")), packs=True)

    async def run() -> None:
        async with kvm.ws_connect(f"ws://127.0.0.1:{said_hello.port}/") as ws:
            assert await kvm.Listening(ws, 1000).message(5) == "hello"
        assert "sec-websocket-extensions" not in said_hello.asked[0].lower()
        with pytest.raises(WebSocketException):  # packing that nobody asked for is not a connection at all
            async with kvm.ws_connect(f"ws://127.0.0.1:{packs_anyway.port}/"):
                pass

    try:
        asyncio.run(run())
    finally:
        said_hello.stop()
        packs_anyway.stop()


def test_a_device_that_pings_and_takes_no_answer_is_hung_up_on() -> None:
    # Every ping is answered by the library, by itself. A device that sent them as fast as it could and read
    # nothing had the answers pile up here, a hundred megabytes in half a minute: a ping is no message, and no
    # limit on messages ever saw one.
    sent = 0

    def pings(conn: socket.socket) -> None:
        nonlocal sent
        burst = frame(0x9, b"p" * 125) * 512
        while sent < 64 * 2**20:  # (the stand-in stops by itself; what it shows would not)
            conn.sendall(burst)
            sent += len(burst)
        time.sleep(30)

    device = OddDevice(pings)

    async def run() -> int:
        most = 0
        async with kvm.ws_connect(f"ws://127.0.0.1:{device.port}/", close_timeout=1) as ws:

            async def watch() -> None:
                nonlocal most
                while True:
                    most = max(most, ws.transport.get_write_buffer_size())
                    await asyncio.sleep(0.01)

            watching = asyncio.ensure_future(watch())
            try:
                with pytest.raises(WebSocketException):
                    await kvm.Listening(ws, 2**20).message(8)
            finally:
                watching.cancel()
        return most

    try:
        most = asyncio.run(run())
    finally:
        device.stop()
    assert most < 4 * kvm.MOST_UNSENT, f"{most / 2**20:.0f} MiB of answers were waiting for a device that reads none"
    # (That it was hung up on is what `raises` above says. How far the stand-in got with its sending says
    # nothing of it: that goes into the system's buffers, and on for a moment after the wall has gone.)


@pytest.mark.parametrize("sends", ["pings and reads the answers", "pings and reads nothing", "pongs nobody asked for"])
def test_a_flood_of_pings_or_pongs_of_no_bytes_ends_the_connection(sends: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # Two bytes each, a hundred thousand to one read from the network, each worked through and answered by the
    # library on the one thread there is: the wall stood still for as long as a device kept that up, and what
    # was owed to the device never came to the megabyte at which it would have been hung up on.
    sent = 0

    def reads(conn: socket.socket) -> None:
        try:
            while conn.recv(65536):
                pass
        except OSError:
            pass  # hung up on, as it is meant to be

    def flood(conn: socket.socket) -> None:
        nonlocal sent
        if sends == "pings and reads the answers":
            threading.Thread(target=reads, args=(conn,), daemon=True).start()
        burst = frame(0xA if sends == "pongs nobody asked for" else 0x9) * 8192
        while sent < 64 * 2**20:
            conn.sendall(burst)
            sent += len(burst)
        time.sleep(30)

    device = OddDevice(flood)
    worked_through = 0  # frames the wall took in, counted here (the wall's own count is of the second it is in)
    real = kvm._ToADevice.process_event

    def counted(self: kvm._ToADevice, event: Any) -> None:
        nonlocal worked_through
        if getattr(event, "opcode", None) is not None:
            worked_through += 1
        real(self, event)

    monkeypatch.setattr(kvm._ToADevice, "process_event", counted)

    async def run() -> float:
        began = time.monotonic()
        async with kvm.ws_connect(f"ws://127.0.0.1:{device.port}/", close_timeout=1) as ws:
            with pytest.raises(WebSocketException):
                await kvm.Listening(ws, 2**20).message(8)
        return time.monotonic() - began

    try:
        took = asyncio.run(run())
    finally:
        device.stop()
    # Hung up on at once, and within the first piece or two of what arrived (a piece of AT_A_TIME bytes holds
    # half as many frames of two; two pieces, because the wall counts pings by the second and the second can
    # turn within a piece, leaving that piece's count under MOST_PINGS_A_SECOND, and the next piece trips it
    # whatever its count): counted where the wall works through it. (How much the stand-in had sent
    # by then says nothing of that. It sends into the system's buffers, and for a moment after the wall has
    # gone: on a machine of somebody else's that was 58 MiB in seven hundredths of a second, of which the wall
    # had worked through two thousand frames.)
    assert took < 4 and worked_through <= 2 * (kvm.AT_A_TIME // 2), f"{worked_through} frames were worked through in {took:.1f} s, and {sent / 2**20:.0f} MiB sent"


def test_a_device_that_pings_as_devices_do_is_listened_to() -> None:
    def talk(conn: socket.socket) -> None:
        for _ in range(kvm.MOST_PINGS_A_SECOND // 2):
            conn.sendall(frame(0x9, b"still there?") + frame(0xA))
        conn.sendall(frame(0x1, b"hello"))
        time.sleep(2)

    device = OddDevice(talk)

    async def run() -> None:
        async with kvm.ws_connect(f"ws://127.0.0.1:{device.port}/", close_timeout=1) as ws:
            assert await kvm.Listening(ws, 1000).message(5) == "hello"

    try:
        asyncio.run(run())
    finally:
        device.stop()


def answers(reply: Callable[[httpx.Request], httpx.Response]) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(reply), base_url="http://device")


def said(status: int, body: bytes = b"{}", cookies: tuple[str, ...] = ()) -> httpx.Response:
    headers = [("content-length", str(len(body))), ("content-type", "application/json"), *(("set-cookie", cookie) for cookie in cookies)]
    return httpx.Response(status, stream=AsItCame(body), headers=headers, request=httpx.Request("GET", "http://device/"))


TWICE = ("auth_token=aaaa; Path=/", "auth_token=bbbb; Path=/api")


def test_one_cookie_set_twice_is_no_sign_in_and_not_an_error_of_the_program() -> None:
    # The HTTP library refuses to choose between two cookies of one name, with an error of its own that nothing
    # here expected: the tile showed an internal error, every look sent the password again, a second apart,
    # and every one of them wrote a traceback into the log.
    assert kvm.said_cookie(said(200, cookies=TWICE), "auth_token") is None
    assert kvm.said_cookie(said(200, cookies=TWICE[:1]), "auth_token") == "aaaa"
    assert kvm.said_cookie(said(200), "auth_token") is None
    signed_in: list[float] = []

    def reply(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth/login":
            signed_in.append(time.monotonic())
            return said(200, b'{"ok": true, "result": {}}', TWICE)
        return said(401)

    async def run() -> None:
        device = KvmDevice(DeviceSpec("d", "odd", "http://device", "admin", "secret", tls="insecure"))
        device._client = answers(reply)
        for _ in range(5):
            with pytest.raises(KvmError) as refused:
                await device._request("GET", "/api/auth/check", urgent=True)
            assert refused.value.code == "no_sign_in" and "no session token" in refused.value.message
        await device.close()

    asyncio.run(run())
    assert len(signed_in) == 1, "the password went out again although the device had just shown it signs nobody in"


def test_a_jetkvm_that_sets_its_cookie_twice_signs_nobody_in() -> None:
    signed_in = 0

    def reply(request: httpx.Request) -> httpx.Response:
        nonlocal signed_in
        signed_in += 1
        return said(200, cookies=("authToken=aaaa; Path=/", "authToken=bbbb; Path=/device"))

    async def run() -> None:
        device = jetkvm.JetKvmDevice(DeviceSpec("d", "odd", "http://device", "", "secret", tls="insecure", kind="jetkvm"))
        device._client = answers(reply)
        for _ in range(3):
            with pytest.raises(KvmError) as refused:
                await device._login()
            assert refused.value.code == "no_sign_in" and "Login failed" in refused.value.message
        await device.close()

    asyncio.run(run())
    assert signed_in == 1


def test_a_session_that_is_refused_as_soon_as_it_is_given_is_not_asked_for_every_second() -> None:
    # The sign-in works, and what it gives is turned away at the next request: a device that forgot how to keep
    # a session, or one that wants to see the password often. It saw it at every look, a second apart.
    signed_in = 0

    def reply(request: httpx.Request) -> httpx.Response:
        nonlocal signed_in
        if request.url.path == "/api/auth/login":
            signed_in += 1
            return said(200, b'{"ok": true, "result": {"token": "tok%d"}}' % signed_in)
        return said(401)

    async def run() -> None:
        device = KvmDevice(DeviceSpec("d", "odd", "http://device", "admin", "secret", tls="insecure"))
        device._client = answers(reply)
        for _ in range(6):
            with pytest.raises(KvmError) as refused:
                await device._request("GET", "/api/auth/check", urgent=True)
            assert refused.value.code == "auth_failed"
        await device.close()

    asyncio.run(run())
    assert signed_in <= 2, f"the password was sent {signed_in} times to a device that refuses the session it gives"


def test_being_sent_on_to_an_address_that_is_none_is_a_wrong_answer() -> None:
    # The HTTP library works out where "Location" leads also when it is told to go nowhere, and for
    # "http:x" fails at it with an error that is none of its usual ones: nothing here caught it.
    def reply(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, stream=AsItCame(b""), headers={"content-length": "0", "location": "http:x"})

    async def run() -> None:
        async with answers(reply) as client:
            with pytest.raises(KvmError) as refused:
                await bounded(client, client.build_request("GET", "/"), 1000)
            assert refused.value.code == "bad_response"

    asyncio.run(run())


class Kept(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def test_an_error_nobody_foresaw_is_in_the_log_in_full_once_and_not_at_every_look(monkeypatch: pytest.MonkeyPatch) -> None:
    kept = Kept()
    logging.getLogger("qkvm").addHandler(kept)

    async def run() -> None:
        device = KvmDevice(DeviceSpec("d", "odd", "http://device", "admin", "secret", tls="insecure"))

        async def read() -> dict[str, Any]:
            raise RuntimeError("what a device made happen")

        monkeypatch.setattr(device, "_read_status", read)
        for _ in range(50):
            await device._refresh_status()
        assert device._status is not None and device._status["state"] == "error"

        # Nor where it is two kinds of error in turn: each new kind was written in full, every time.
        turn = 0

        async def read_in_turn() -> dict[str, Any]:
            nonlocal turn
            turn += 1
            raise (KeyError if turn % 2 else LookupError)("what a device made happen")

        monkeypatch.setattr(device, "_read_status", read_in_turn)
        for _ in range(50):
            await device._refresh_status()
        monkeypatch.setattr(kvm, "SAY_AGAIN", 0.0)
        monkeypatch.setattr(device, "_read_status", read)
        await device._refresh_status()
        await device.close()

    try:
        asyncio.run(run())
    finally:
        logging.getLogger("qkvm").removeHandler(kept)
    assert len([record for record in kept.records if record.exc_info]) == 1
    assert len(kept.records) == 2  # and, once the time for it has come, a line that it still goes on


def test_a_device_that_cannot_be_said_goodbye_to_is_removed_all_the_same(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Closing a connection asks some devices something once more (to sign out). What came back was not
    # foreseen, and the removal ended in the middle: gone from the wall, still in the file with its password,
    # and back after the next restart.
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")
    fake = FakeKvm().start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)

            async def close(self: Any) -> None:
                raise RuntimeError("what a device made happen")

            monkeypatch.setattr(KvmDevice, "close", close)
            removed = client.delete(f"/api/v1/devices/{device}")
            assert removed.status_code == 200, removed.text
            assert [d["id"] for d in json.loads(settings_text(tmp_path / "qkvm.json", encoding="utf-8"))["devices"]] == []
            monkeypatch.undo()
    finally:
        fake.stop()
