"""Five things that could be undone without another test failing; each of these fails then.

* what a library says arrives in qkvm.log at all (the handler for it could write to a queue nobody reads);
* why a device's stream ended is written once a minute, and not once a connection;
* a wall with more in it than a file holds is told so by /api/v1/export (and not answered with a 500);
* a start at which the password work has no memory is said as that, and the key is kept for the next;
* what is sealed in a file is held to what a plain file may be.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import struct
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from qkvm import cli, exchange, kvm, update, vault
from qkvm.core import Core
from tests.test_device_limits import OddDevice, frame
from tests.test_wall import PASSWORD, wall
from tests.test_what_a_library_says import Terminal, a_kvm_at
from tests.settings_file import settings_text

F = {"format": exchange.FORMAT, "version": 1}
PASSPHRASE = "a passphrase for the file"


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def logged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    names = ("asyncio", "qkvm", "uvicorn.error", "websockets", "httpx", "httpcore", "aiortc", "aioice")
    before = {name: (logging.getLogger(name).handlers[:], logging.getLogger(name).filters[:], logging.getLogger(name).propagate, logging.getLogger(name).level) for name in names}
    terminal = Terminal()
    monkeypatch.setattr(sys, "stderr", terminal)
    cli.setup_logging(tmp_path, "info")
    try:
        yield terminal, tmp_path
    finally:
        cli.stop_logging()
        for name, (handlers, filters, propagate, level) in before.items():
            logger = logging.getLogger(name)
            logger.handlers[:], logger.filters[:], logger.propagate = handlers, filters, propagate
            logger.setLevel(level)


def test_what_a_library_says_is_in_the_log_once_and_not_on_the_terminal(logged: tuple[Terminal, Path]) -> None:
    # The line all this is about, said the way the library says it, from the thread of the event loop,
    # with the program's logging as the program sets it up (and nothing taken off the root of all loggers).
    terminal, folder = logged

    async def run() -> None:
        for _ in range(3):
            try:
                raise ConnectionError("the connection is over")
            except ConnectionError:
                logging.getLogger("websockets.client").error("keepalive ping failed", exc_info=True)
        logging.getLogger("some.library.nobody.thought.of").warning("something %s", "else")
        logging.getLogger("httpx").info("HTTP Request: GET https://192.168.1.20/api/auth?token=SECRET")  # (finer than a warning: not written at all)

    asyncio.run(run())
    cli.stop_logging()
    log = (folder / "qkvm.log").read_text(encoding="utf-8")
    print(f">>> qkvm.log: {log.count('keepalive ping failed')} times 'keepalive ping failed', {len(log.splitlines())} lines; the terminal: {terminal.getvalue()!r}")
    assert log.count("ERROR   websockets.client: keepalive ping failed") == 1, log
    assert "ConnectionError: the connection is over" in log, "the line is there without where it came from"
    assert "WARNING some.library.nobody.thought.of: something else" in log
    assert "SECRET" not in log
    assert terminal.getvalue() == "" and terminal.from_the_loop == 0


def test_why_a_devices_stream_ended_is_written_once_a_minute(logged: tuple[Terminal, Path]) -> None:
    _, folder = logged
    device = OddDevice(lambda conn: (conn.sendall(frame(0x8, struct.pack(">H", 1000) + b"bye")), time.sleep(0.2)))

    async def run() -> None:
        kvmd = a_kvm_at(device.port)
        for _ in range(6):
            kvmd._wanted_at = time.monotonic()
            await kvmd._hold_stream_open()
        await kvmd.close()

    try:
        asyncio.run(run())
    finally:
        device.stop()
    cli.stop_logging()
    lines = [line for line in (folder / "qkvm.log").read_text(encoding="utf-8").splitlines() if "stream keepalive ended" in line]
    print(f">>> six connections that the device ended: {len(lines)} lines about it in qkvm.log")
    assert len(lines) == 1, lines


@pytest.mark.parametrize("passphrase", ["", PASSPHRASE], ids=["plain", "sealed"])
def test_a_wall_with_more_in_it_than_a_file_holds_is_told_so_by_the_export(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, passphrase: str) -> None:
    with wall(tmp_path) as admin:
        file = json.dumps({**F, "devices": [{"url": f"https://192.168.1.{last}", "kind": "kvmd", "name": f"KVM {last}"} for last in range(1, 60)]})
        assert admin.post("/api/v1/import", json={"file": file, "take": ["devices"]}).json()["devices"] == 59
        monkeypatch.setattr(exchange, "MAX_FILE", 4000)
        answer = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": passphrase, "parts": ["devices"]})
        assert (answer.status_code, answer.json()["code"], answer.json()["message"]) == (422, "too_large", exchange.TOO_MUCH), answer.text[:300]
        assert not [entry for entry in admin.get("/api/v1/audit").json()["entries"] if entry["event"] == "export_made"], "written down as made"


@pytest.mark.parametrize("error", [MemoryError(), ValueError("[digital envelope routines] malloc failure")], ids=["MemoryError", "the library's ValueError"])
def test_a_start_at_which_the_password_work_has_no_memory_says_so_and_keeps_the_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: BaseException) -> None:
    with wall(tmp_path) as admin:  # (signed in once: from here on the key in the data folder opens the saved passwords at start)
        deadline = time.monotonic() + 10
        while admin.core.store.unlock is None:  # type: ignore[attr-defined]
            assert time.monotonic() < deadline, "the key in the data folder was never made to fit"
            time.sleep(0.05)
    fitted = json.loads(settings_text(tmp_path / "qkvm.json", encoding="utf-8"))["unlock"]
    assert fitted is not None

    def no_room(*given: Any, **named: Any) -> bytes:
        raise error

    with monkeypatch.context() as patched:
        patched.setattr(hashlib, "scrypt", no_room)
        core = Core(tmp_path)
        told = core.unlock_at_start()  # (not caught, this ended the start in a traceback)
        assert told is not None and "could not be opened at this start" in told and "memory" in told, told
        assert not core.vault.unlocked
        assert core.store.unlock == fitted, "what the key fits was taken out of the settings for a check that could not be made"
    again = Core(tmp_path)
    assert again.unlock_at_start() is None and again.vault.unlocked, "with memory again, the next start does not open the saved passwords"


def test_what_is_sealed_in_a_file_is_held_to_what_a_plain_file_may_be(monkeypatch: pytest.MonkeyPatch) -> None:
    devices = [{"url": f"https://192.168.1.{last}", "kind": "kvmd", "name": "K" * 60} for last in range(1, 40)]
    sealed = exchange.pack({"devices": devices}, PASSPHRASE, "0.1.0")  # written while a file may be long
    inside = len(json.dumps({**F, "made": 0, "program": "0.1.0", "devices": devices}, separators=(",", ":")))
    monkeypatch.setattr(exchange, "MAX_FILE", inside - 200)
    monkeypatch.setattr(exchange, "MAX_SEALED", len(sealed) + 10)
    with pytest.raises(exchange.ExchangeError) as refused:
        exchange.unpack(sealed, PASSPHRASE)
    assert refused.value.code == "too_large"
