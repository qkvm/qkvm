"""The case beside the one a fix closed: what the reading of two fix commits found, each as it is now."""

from __future__ import annotations

import asyncio
import logging
import logging.handlers
import socket
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from qkvm import cli, exchange, kvm, update, vault
from qkvm.kvm import DeviceSpec, KvmDevice, KvmError
from qkvm.store import Store
from qkvm.vault import Vault
from tests.fake_kvm import FakeKvm, make_device_certificate
from tests.test_device_limits import OddDevice, frame
from tests.test_unlock import fits, kept_sign_in
from tests.test_users import account, visitor
from tests.test_wall import PASSWORD, wait_until, wall

F = {"format": exchange.FORMAT, "version": 1}


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def fake() -> Iterator[FakeKvm]:
    server = FakeKvm().start()
    yield server
    server.stop()


def plain(**parts: Any) -> str:
    import json

    return json.dumps({**F, **parts})


def taken(admin: Any, file: str, take: tuple[str, ...] = exchange.PARTS) -> Any:
    return admin.post("/api/v1/import", json={"file": file, "take": list(take)})


def looked(admin: Any, file: str) -> Any:
    return admin.post("/api/v1/import/read", json={"file": file})


# --- a device's connection ----------------------------------------------------------------------------------------------------


def test_frames_of_no_bytes_by_the_hundred_thousand_end_the_connection_though_nobody_reads() -> None:
    # Pings were counted; frames of a message were not, and the library works through each of those as well,
    # on the one thread there is, before any of them is a message that somebody's limit could see.
    sent = 0

    def flood(conn: socket.socket) -> None:
        nonlocal sent
        conn.sendall(frame(0x1, b"x")[:1] and bytes([0x01, 0x00]))  # a message begins, and does not end
        burst = bytes([0x00, 0x00]) * 16384  # ...in pieces of no bytes
        while sent < 32 * 2**20:
            conn.sendall(burst)
            sent += len(burst)
        time.sleep(30)

    device = OddDevice(flood)

    async def run() -> bool:
        async with kvm.ws_connect(f"ws://127.0.0.1:{device.port}/", close_timeout=1) as ws:
            for _ in range(300):
                if ws.transport.is_closing():
                    return True
                await asyncio.sleep(0.01)
            return False

    try:
        assert asyncio.run(run()), "the connection was left open, with its reading only paused"
    finally:
        device.stop()


def test_what_was_read_before_this_program_hung_up_is_not_worked_through_after() -> None:
    # (On Windows a read that had finished is handed over after the connection was ended. Every ping in it was
    # answered into a connection that was gone, and the event loop writes a line for each such answer.)
    # What a device sent before it ended the connection itself is worked through, though: asked "is it
    # closing?" instead of "did we hang up?", the last words of a device that resets were thrown away.
    fed: list[int] = []

    class Closing:
        def is_closing(self) -> bool:
            return True

        def get_write_buffer_size(self) -> int:
            return 0

    class Ended(kvm._ToADevice):
        def __init__(self) -> None:  # (not a connection: only what data_received looks at)
            self.transport = Closing()  # type: ignore[assignment]

    real = kvm.ClientConnection.data_received
    try:
        kvm.ClientConnection.data_received = lambda self, data: fed.append(len(data))  # type: ignore[method-assign]
        by_the_device, by_us = Ended(), Ended()
        by_us._hung_up = True
        by_us.data_received(bytes(3 * kvm.AT_A_TIME))
        assert fed == []
        by_the_device.data_received(bytes(3 * kvm.AT_A_TIME))
    finally:
        kvm.ClientConnection.data_received = real  # type: ignore[method-assign]
    assert fed == [kvm.AT_A_TIME] * 3


def test_what_the_event_loop_says_is_in_the_log_once_a_minute_and_not_on_the_terminal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Two thousand lines a connection, and a new connection twice a second: the log's history was gone in half
    # a minute, and the same lines went to the terminal, which is not kept to any size.
    now = [1000.0]
    monkeypatch.setattr(cli.time, "monotonic", lambda: now[0])
    once = cli._OnceAMinute()

    def said(message: str, name: str = "asyncio") -> logging.LogRecord:
        return logging.LogRecord(name, logging.WARNING, __file__, 1, message, None, None)

    assert [once.filter(said("socket.send() raised exception.")) for _ in range(2000)].count(True) == 1
    assert once.filter(said("something else the loop says")) is True
    now[0] += 61
    assert once.filter(said("socket.send() raised exception.")) is True
    assert cli._Unsaid().filter(said("socket.send() raised exception.")) is False  # not for the terminal
    assert cli._Unsaid().filter(said("keepalive ping failed", "websockets.client")) is False  # nor what a library says
    assert cli._Unsaid().filter(said("the device is down", "qkvm")) is True
    assert cli._Unsaid().filter(said("Invalid HTTP request received.", "uvicorn.error")) is True
    # The same words from two that say them are two kinds; and a kind is the first line, not what follows it.
    assert once.filter(said("keepalive ping failed", "websockets.client")) is True
    assert once.filter(said("keepalive ping failed", "websockets.server")) is True
    assert once.filter(said("keepalive ping failed", "websockets.client")) is False
    first, second = (said("Task exception was never retrieved" + chr(10) + f"future: <Task finished name='Task-{n}'>") for n in (1, 2))
    assert (once.filter(first), once.filter(second)) == (True, False)
    # Nor is it a kind of its own for the number or the address in its first line.
    assert [once.filter(said(f"Exception in callback <Handle at 0x{n:012x}> task {n}")) for n in (4096, 8192, 12288)] == [True, False, False]

    # An error is a kind by what it is and where it was raised: two places are two lines, one place is one.
    def failed(where: int) -> logging.LogRecord:
        try:
            if where == 1:
                raise ValueError("the first place")
            raise ValueError("the second place")
        except ValueError as error:
            return logging.LogRecord("uvicorn.error", logging.ERROR, __file__, 1, "Exception in ASGI application" + chr(10), None, (ValueError, error, error.__traceback__))

    assert [once.filter(failed(where)) for where in (1, 2, 1, 2)] == [True, True, False, False]
    # And so many kinds in one minute are no kinds any more: the table is full, and nothing further is let through.
    crowded = cli._OnceAMinute()
    assert [crowded.filter(said(f"kind {chr(65 + n // 26)}{chr(65 + n % 26)}")) for n in range(cli._OnceAMinute.MOST + 50)].count(True) == cli._OnceAMinute.MOST
    now[0] += 61
    assert crowded.filter(said("something new")) is True
    monkeypatch.undo()
    loop_says, everybody = logging.getLogger("asyncio"), logging.getLogger()
    before = (loop_says.handlers[:], loop_says.filters[:], loop_says.propagate, loop_says.level)

    def theirs() -> list[logging.Handler]:
        return [handler for handler in everybody.handlers if any(isinstance(each, cli._OnceAMinute) for each in handler.filters)]

    try:
        cli.setup_logging(tmp_path, "info")
        # What is not this program's own to say has one place to go, which lets each kind through once a
        # minute; the event loop's lines go there too, and of those only errors are made at all.
        assert len(theirs()) == 1 and isinstance(theirs()[0], logging.handlers.QueueHandler) and theirs()[0].level == logging.WARNING
        assert loop_says.propagate is True and not loop_says.handlers and loop_says.level == logging.ERROR
        # The web server's lines are held to it as well; this program's own are not.
        held = {name: [any(isinstance(each, cli._OnceAMinute) for each in handler.filters) for handler in logging.getLogger(name).handlers] for name in ("qkvm", "uvicorn.error")}
        assert held == {"qkvm": [False], "uvicorn.error": [True]}
        cli.setup_logging(tmp_path, "info")
        assert len(theirs()) == 1  # set up again, it is not there twice
    finally:
        cli.stop_logging()
        loop_says.handlers[:], loop_says.filters[:], loop_says.propagate = before[0], before[1], before[2]
        loop_says.setLevel(before[3])
    assert theirs() == []  # and it is taken away again with the rest


def test_a_saved_address_that_is_none_is_a_device_that_cannot_be_reached() -> None:
    async def run() -> None:
        device = KvmDevice(DeviceSpec("d", "odd", "http://10.01.000.001", "admin", "secret", tls="insecure"))
        for _ in range(3):
            with pytest.raises(KvmError) as refused:
                await device._http()
            assert refused.value.code == "unreachable"
        await device.close()

    with pytest.raises(httpx.InvalidURL):
        httpx.AsyncClient(base_url="http://10.01.000.001")
    asyncio.run(run())


# --- a file --------------------------------------------------------------------------------------------------------------


def test_a_file_puts_no_tile_at_an_address_that_cannot_be_connected_to(tmp_path: Path) -> None:
    odd = [{"url": url, "kind": "kvmd"} for url in ("http://10.01.000.001", "https://999.1.1.1", "https://xn--", "https://127.1")]
    with wall(tmp_path) as admin:
        there = looked(admin, plain(devices=[*odd, {"url": "https://192.168.1.20", "kind": "kvmd"}])).json()
        assert [d["host"] for d in there["devices"]] == ["192.168.1.20"] and len(there["left_out"]) == 4
        assert taken(admin, plain(devices=odd), ("devices",)).json()["devices"] == 0


def test_a_jetkvm_the_wall_has_followed_to_https_is_not_added_again_the_plain_way(tmp_path: Path) -> None:
    # The file was made while it was on plain HTTP. The wall has since followed it to HTTPS, as it does by
    # itself; taken in again, the plain address was "new", and a second tile signed in to it in the clear.
    with wall(tmp_path) as admin:
        assert taken(admin, plain(devices=[{"url": "https://192.168.1.50", "kind": "jetkvm", "name": "Bench"}]), ("devices",)).json()["devices"] == 1
        again = plain(devices=[{"url": "http://192.168.1.50", "kind": "jetkvm", "name": "Bench, as it was"}, {"url": "http://192.168.1.51", "kind": "jetkvm"}, {"url": "https://192.168.1.51", "kind": "jetkvm"}])
        there = looked(admin, again).json()["devices"]
        assert [(d["new"], d["same_as"]) for d in there] == [(False, "Bench"), (True, ""), (False, "192.168.1.51")]
        assert taken(admin, again, ("devices",)).json()["devices"] == 1
        assert len(admin.get("/api/v1/wall").json()["devices"]) == 2


def test_a_device_is_known_by_its_certificate_also_beside_a_mark_a_file_made_up(tmp_path: Path) -> None:
    pem = make_device_certificate(tmp_path / "its-own")[0].read_text(encoding="ascii")
    with wall(tmp_path / "data") as admin:
        assert taken(admin, plain(devices=[{"url": "https://192.168.1.20", "kind": "kvmd", "cert_pem": pem, "name": "Rack KVM"}]), ("devices",)).json()["devices"] == 1
        second = plain(devices=[{"url": "https://kvm.example", "kind": "kvmd", "cert_pem": pem, "ident": "aa:" + "0" * 16}])
        assert [(d["new"], d["same_as"]) for d in looked(admin, second).json()["devices"]] == [(False, "Rack KVM")]
        assert taken(admin, second, ("devices",)).json()["devices"] == 0


def test_a_name_is_the_name_it_looks_like(tmp_path: Path) -> None:
    # "Lock the screen" with a mark behind it that is not drawn, or with a letter in it that is a blank, was
    # another name, and so another action under what reads as the same button.
    with wall(tmp_path) as admin:
        assert admin.post("/api/v1/actions", json={"name": "Lock the screen", "kind": "keys", "keys": "MetaLeft,KeyL"}).status_code == 201
        # (Written by their numbers: a mark that is not drawn, a blank of no width, a wide L, a letter that is a blank.)
        alike = ["Lock the screen" + chr(0xFE0F), "Lock" + chr(0x200B) + " the screen", "LOCK  THE SCREEN", chr(0xFF2C) + "ock the screen", "Lock the screen" + chr(0x3164)]
        file = plain(actions=[{"name": name, "kind": "text", "text": "something else"} for name in alike] + [{"name": "Lock the door", "kind": "keys", "keys": "KeyA"}])
        there = looked(admin, file).json()
        new = [a["name"] for a in there["actions"] if a["new"]]
        assert new == ["Lock the door"], (new, there["left_out"])
        assert taken(admin, file, ("actions",)).json()["actions"] == 1


def test_the_largest_file_that_is_taken_in_can_also_be_made_and_read_back(tmp_path: Path) -> None:
    pem = make_device_certificate(tmp_path / "its-own")[0].read_text(encoding="ascii")
    devices = [{"url": f"https://kvm{number}.example", "kind": "kvmd", "name": f"KVM {number}", "password": "p" * 30, "cert_pem": pem, "keep_both": True} for number in range(exchange.MOST_DEVICES)]
    sealed = exchange.pack({"devices": devices}, "a passphrase for the file", "0.1.0")
    assert len(sealed) < exchange.MAX_FILE
    back = exchange.unpack(sealed, "a passphrase for the file")
    assert back.devices is not None and len(back.devices) == exchange.MOST_DEVICES


# --- a password that cannot be checked ------------------------------------------------------------------------------------------


def test_a_record_with_numbers_that_are_none_is_a_record_nothing_opens() -> None:
    record = Vault().create("right")
    for change in ({"n": 1e999}, {"n": 65536, "r": 1}, {"n": float("nan")}, {"r": 1e999}):
        assert Vault.open({**record, "kdf": {**record["kdf"], **change}}, "right") is None, change


def test_a_password_that_cannot_be_checked_is_answered_as_that_and_said_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # No memory for the work: answered as an error inside the program, with a page in the log for every
    # attempt, by anybody who can reach the sign-in page.
    lines: list[logging.LogRecord] = []

    class Heard(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            lines.append(record)

    heard = Heard()
    logging.getLogger("qkvm").addHandler(heard)
    try:
        with wall(tmp_path) as admin:
            account(admin, "olga", "operator")

            def no_memory(record: dict[str, Any], password: str) -> bytes | None:
                raise MemoryError

            monkeypatch.setattr(Vault, "open", staticmethod(no_memory))
            guest = visitor(admin, 50051)
            answers = [guest.post("/api/v1/login", json={"name": "olga", "password": "whatever it is"}) for _ in range(8)]
            assert {(a.status_code, a.json()["code"]) for a in answers} == {(503, "busy")}  # and not "wrong", counted towards a lock-out
            recovered = guest.post("/api/v1/recover", json={"name": "olga", "recovery_key": "x" * 20, "new_password": "another password!"})
            assert (recovered.status_code, recovered.json()["code"]) == (503, "busy")
            read = admin.post("/api/v1/import/read", json={"file": exchange.pack({"devices": []}, "a passphrase for the file", "0.1.0"), "passphrase": "a passphrase for the file"})
            assert read.status_code == 503
            monkeypatch.undo()
            monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
            assert guest.post("/api/v1/login", json={"name": "olga", "password": "another password!"}).status_code in (200, 401)  # not locked out by it
    finally:
        logging.getLogger("qkvm").removeHandler(heard)
    about = [record for record in lines if "could not be checked" in record.getMessage()]
    assert len(about) == 1 and about[0].exc_info is None


# --- signed in ------------------------------------------------------------------------------------------------------------------


def test_a_second_step_that_an_admin_could_not_switch_off_leaves_the_account_as_it_was(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        who = account(admin, "olga", "operator")
        hers = visitor(admin, 50061)
        assert hers.post("/api/v1/login", json={"name": "olga", "password": "another password!"}).status_code in (200, 401)
        user = admin.core.store.user(who)  # type: ignore[attr-defined]
        user.totp, before = {"nonce": "x", "data": "y"}, user.totp_changes
        real = Store.write

        def full(self: Store, data: dict[str, Any]) -> None:
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(Store, "write", full)
        refused = admin.put(f"/api/v1/users/{who}", json={"name": "olga", "role": "operator", "totp_off": True})
        assert refused.status_code == 507
        monkeypatch.setattr(Store, "write", real)
        assert user.totp is not None and user.totp_changes == before  # (counted up and not put back, her kept browsers were out at the next restart)


def test_signing_out_here_says_so_where_the_file_may_still_name_this_browser(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A browser that asked to be kept, and is not among the newest of its account that are written down now:
    # the file was written when it was, and where the file can be neither written nor removed it names it still.
    from qkvm import security

    monkeypatch.setattr(security, "MOST_KEPT_OF_ONE", 2)
    data = tmp_path / "data"
    with wall(data) as admin:
        wait_until(lambda: fits(admin), "never made to fit")
        old = visitor(admin, 50071)
        cookie = kept_sign_in(old)
        admin.core.sessions.flush()  # type: ignore[attr-defined]
        for port in (50072, 50073):
            kept_sign_in(visitor(admin, port))
        sessions = admin.core.sessions  # type: ignore[attr-defined]
        sessions.flush()
        assert not sessions.kept(cookie) and sessions.of_the_kept_kind(cookie)
        sessions._stale = "Read-only file system"
        out = old.post("/api/v1/logout", json={"scope": "this"})
        assert (out.status_code, out.json()["code"]) == (507, "not_saved")
        sessions._stale = None
        # One that never asked to be kept waits for no disk, whatever the file is like (as before).
        plainly = visitor(admin, 50074)
        assert plainly.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
        sessions._stale = "Read-only file system"
        assert plainly.post("/api/v1/logout", json={"scope": "this"}).status_code == 200
        sessions._stale = None


# --- settings -------------------------------------------------------------------------------------------------------------------


def test_settings_that_could_not_be_saved_show_the_certificate_that_is_served(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with wall(tmp_path) as admin:
        core = admin.core  # type: ignore[attr-defined]
        monkeypatch.setattr(core, "request_restart", lambda: None)
        settings = {"bind": ["local"], "port": 8787, "https": True, "interval": 2}
        assert admin.put("/api/v1/settings", json=settings).status_code == 200
        shown = admin.get("/api/v1/settings").json()["cert_fingerprint"]

        def another(addresses: list[str]) -> Any:
            # Another first byte than the real one's: a fingerprint that begins with AA by chance (one in 256) is no other.
            core.cert_fingerprint = ("AB:" if shown.startswith("AA:") else "AA:") + shown[3:]
            return tmp_path / "tls" / "cert.pem", tmp_path / "tls" / "key.pem"

        def full(self: Store, data: dict[str, Any]) -> None:
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(core, "prepare_tls", another)
        monkeypatch.setattr(Store, "write", full)
        assert admin.put("/api/v1/settings", json={**settings, "interval": 5}).status_code == 507
        monkeypatch.undo()
        said = admin.get("/api/v1/settings").json()
        assert said["cert_fingerprint"] == shown and said["interval"] == 2

        def odd(addresses: list[str]) -> Any:
            raise RuntimeError("whatever else can go wrong in the making of one")

        monkeypatch.setattr(core, "prepare_tls", odd)
        refused = admin.put("/api/v1/settings", json={**settings, "interval": 7})
        assert (refused.status_code, refused.json()["code"]) == (507, "no_certificate") and admin.get("/api/v1/settings").json()["interval"] == 2

