"""A server's image as qKVM serves it to the server's controller (served.py, the route `/media/<token>/<name>`), as the
outside review of 0.3.0 read it (Codex's, from its probes):

M1: reads that come together are counted together. The slot was counted only after the file was open (and never for a
HEAD): 32 reads at once were all taken, where eight are the most (MOST_AT_ONCE).

M2: a tile removed (or moved to another address) ends what is served to its controller at once, a reading under way
included. It went on to the end of the reading, and only a new one found the tile gone.

The second round, R2-M1: the places of reads cut off while their files were being opened were given back by the
listener's loop, which a restart of the listeners ends first: the eight places stayed taken, and every read after was
refused. R2-M2: another controller accepted at the same address (its certificate trusted, its numbers taken) did not end
what was lent to the one before.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from starlette.requests import Request

from qkvm import served, server
from qkvm.core import Core
from qkvm.store import DeviceRecord


def a_wall_lending(tmp_path: Any, payload: bytes, **known: Any) -> tuple[Core, Any, DeviceRecord, Any]:
    core = Core(tmp_path / "data", locked_start=True)
    core.store.server.media_address = "http://127.0.0.1:18456"
    (tmp_path / "image.iso").write_bytes(payload)
    found = served.listing(str(tmp_path))[0][0]
    record = DeviceRecord(id="ab12", url="http://127.0.0.1:18457", name="db-01", kind="redfish", **known)
    core.store.devices.append(record)
    lending = core.served.lend(record.id, record.url, frozenset({"127.0.0.1"}), found, base=core.served.base() or "", by="admin", identity=(record.cert_pem, record.machine, record.ident))
    return core, server.create_app(core), record, lending


def route(app: Any, path: str, method: str) -> Any:
    return next(one.endpoint for one in app.routes if getattr(one, "path", "") == path and method in getattr(one, "methods", ()))


def asked(app: Any, method: str, path: str) -> Request:
    return Request({"type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"}, "method": method, "path": path, "headers": [],
                    "client": ("127.0.0.1", 40000), "server": ("127.0.0.1", 18456), "scheme": "http", "app": app})


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_reads_that_come_together_are_counted_together(tmp_path: Any, monkeypatch: pytest.MonkeyPatch, method: str) -> None:
    async def run() -> None:
        _, app, _, lending = a_wall_lending(tmp_path, b"an image")
        image = route(app, "/media/{token}/{name}", method)
        release, entered = threading.Event(), threading.Event()
        opened = served.Lending.opened

        def slow_open(self: Any) -> Any:  # (a share that is slow to open the file)
            entered.set()
            assert release.wait(5)
            return opened(self)

        monkeypatch.setattr(served.Lending, "opened", slow_open)
        count = served.MOST_AT_ONCE * 4
        path = f"/media/{lending.token}/{lending.url_name}"
        reads = [asyncio.create_task(image(lending.token, lending.url_name, asked(app, method, path))) for _ in range(count)]
        try:
            for _ in range(100):
                if entered.is_set():
                    break
                await asyncio.sleep(0.01)
            await asyncio.sleep(0.05)
            assert lending.at_once <= served.MOST_AT_ONCE  # (counted before the first wait)
            release.set()
            replies = await asyncio.wait_for(asyncio.gather(*reads), 5)
            taken = sum(reply.status_code in (200, 206) for reply in replies)
            assert taken <= served.MOST_AT_ONCE, taken
            assert sum(reply.status_code == 503 for reply in replies) == count - taken
        finally:
            release.set()
            for read in reads:
                if read.done() and not read.cancelled() and read.exception() is None:
                    done = getattr(read.result(), "_done", None)
                    if done is not None:
                        done()
            for _ in range(200):
                if lending.at_once == 0:
                    break
                await asyncio.sleep(0.01)
            assert lending.at_once == 0  # (every place given back: the opened, the HEAD, the refused)

    asyncio.run(run())


@pytest.mark.parametrize("how", ["removed", "moved", "certificate", "machine"])
def test_a_tile_removed_or_moved_ends_the_reading_under_way(tmp_path: Any, how: str) -> None:
    async def run() -> None:
        # (Mounted on a controller known by its certificate and its numbers: another's, at the same address, is not it.)
        known = {"tls": "pinned", "cert_pem": "controller A's certificate", "machine": "server:A"}
        core, app, record, lending = a_wall_lending(tmp_path, b"A" * (served.PIECE * 3), **known)
        image = route(app, "/media/{token}/{name}", "GET")
        remove = route(app, "/api/v1/devices/{device_id}", "DELETE")
        path = f"/media/{lending.token}/{lending.url_name}"
        reply = await image(lending.token, lending.url_name, asked(app, "GET", path))
        assert reply.status_code == 200
        before = after = 0
        changed = False

        async def receive() -> dict[str, Any]:
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message: dict[str, Any]) -> None:
            nonlocal before, after, changed
            body = message.get("body", b"")
            if not body:
                return
            if changed:
                after += len(body)
                return
            before += len(body)
            if how == "removed":
                answer = await remove(record.id, asked(app, "DELETE", f"/api/v1/devices/{record.id}"))
                assert answer.status_code == 200 and core.store.device(record.id) is None
            elif how == "moved":
                record.url = "http://127.0.0.1:18458"  # (as an edit leaves it: another address)
            elif how == "certificate":
                record.cert_pem = "another controller's certificate, trusted at the same address"
            else:
                record.machine = "server:another machine at the same address"
            changed = True

        await server.SentOnlyWhile(reply)(asked(app, "GET", path).scope, receive, send)
        assert (before, after) == (served.PIECE, 0)
        assert lending.ended and core.served.find(lending.token) is None
        for _ in range(200):
            if lending.at_once == 0:
                break
            await asyncio.sleep(0.01)
        assert lending.at_once == 0

    asyncio.run(run())


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_reads_cut_off_with_their_listener_give_their_places_back_all_the_same(tmp_path: Any, monkeypatch: pytest.MonkeyPatch, method: str) -> None:
    core, app, _, lending = a_wall_lending(tmp_path, b"an image")
    image = route(app, "/media/{token}/{name}", method)
    release, entered = threading.Event(), threading.Event()
    opened, handles = served.Lending.opened, []
    readers = ThreadPoolExecutor(max_workers=4)
    monkeypatch.setattr(server, "SERVED_READERS", readers)

    def slow_open(self: Any) -> Any:  # (a share that stalls)
        entered.set()
        assert release.wait(5)
        held = opened(self)
        handles.append(held)
        return held

    monkeypatch.setattr(served.Lending, "opened", slow_open)
    path = f"/media/{lending.token}/{lending.url_name}"
    loop = asyncio.new_event_loop()

    async def first_listener() -> None:
        reads = [asyncio.create_task(image(lending.token, lending.url_name, asked(app, method, path))) for _ in range(served.MOST_AT_ONCE)]
        for _ in range(500):
            if entered.is_set():
                break
            await asyncio.sleep(0.01)
        assert lending.at_once == served.MOST_AT_ONCE
        for read in reads:
            read.cancel()
        await asyncio.gather(*reads, return_exceptions=True)

    try:
        loop.run_until_complete(first_listener())
        loop.close()  # (the listeners restarted: this loop is over; the wall, its Core and its mounts go on)
        release.set()
        readers.shutdown(wait=True)
        assert lending.at_once == 0 and all(held.closed for held in handles)  # (given back, and let go of, by the threads)
        monkeypatch.setattr(server, "SERVED_READERS", ThreadPoolExecutor(max_workers=4))

        async def next_listener() -> None:
            again = route(server.create_app(core), "/media/{token}/{name}", method)
            reply = await again(lending.token, lending.url_name, asked(app, method, path))
            assert reply.status_code in (200, 206), reply.status_code
            done = getattr(reply, "_done", None)
            if done is not None:
                done()

        asyncio.run(next_listener())
    finally:
        release.set()
        if not loop.is_closed():
            loop.close()
        readers.shutdown(wait=True)
        for held in handles:
            held.close()


def test_what_a_controller_puts_in_its_range_reaches_the_log_without_the_mounts_secrets(tmp_path: Any) -> None:
    # (The outside review's second round, R2-L2: the Range header was written in the log as it came, before anything
    # else was asked of it: a controller could put the mount's token, or its user and password, there.)
    async def run() -> tuple[list[str], str]:
        _, app, _, lending = a_wall_lending(tmp_path, b"an image")
        lines: list[str] = []
        handler = logging.Handler()
        handler.emit = lambda line: lines.append(line.getMessage())  # type: ignore[method-assign]
        ours = logging.getLogger("qkvm")
        level = ours.level
        ours.setLevel(logging.INFO)
        ours.addHandler(handler)
        try:
            scope = dict(asked(app, "GET", f"/media/{lending.token}/{lending.url_name}").scope)
            scope["headers"] = [(b"range", f"bytes={lending.token}".encode())]
            request = Request(scope)
            reply = await route(app, "/media/{token}/{name}", "GET")(lending.token, lending.url_name, request)
            assert reply.status_code == 200  # (a range that reads as none is no range: the whole image, as HTTP has it)
            reply._done()  # type: ignore[attr-defined]
        finally:
            ours.removeHandler(handler)
            ours.setLevel(level)
        return lines, lending.token

    lines, token = asyncio.run(run())
    assert any("its controller asks for" in line for line in lines), lines
    assert not any(token[:12] in line for line in lines), lines


COMPUTER = "server:" + "a" * 32
CONTROLLER = "b" * 32


@pytest.mark.parametrize(("how", "kept"), [
    ("first numbers, its certificate known", True), ("its controller's number after its computer's", True),
    ("first numbers, nothing known", False), ("a first certificate where none was bound", False),
])  # fmt: skip
def test_what_is_learned_of_the_same_controller_keeps_the_reading(tmp_path: Any, how: str, kept: bool) -> None:
    """What was not known of the controller when it was mounted, and is learned after, is the same controller's where
    something else known of it still matches (its certificate; its computer's number, to which its controller's is
    added): the reading goes on, and the mount is bound to what was learned. Known by nothing, it may be another one's,
    and the mount ends; a certificate where none was bound is another one's (the outside review's third and fourth
    rounds)."""

    async def run() -> None:
        known: dict[str, Any] = {"tls": "pinned"}
        if how == "first numbers, its certificate known":
            known["cert_pem"] = "controller A's certificate"
        elif how == "its controller's number after its computer's":
            known["machine"] = COMPUTER
        core, app, record, lending = a_wall_lending(tmp_path, b"A" * (served.PIECE * 3), **known)
        image = route(app, "/media/{token}/{name}", "GET")
        path = f"/media/{lending.token}/{lending.url_name}"
        reply = await image(lending.token, lending.url_name, asked(app, "GET", path))
        assert reply.status_code == 200
        got = 0
        learned = False

        async def receive() -> dict[str, Any]:
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message: dict[str, Any]) -> None:
            nonlocal got, learned
            got += len(message.get("body", b""))
            if got and not learned:
                if how == "a first certificate where none was bound":
                    record.cert_pem = "a certificate"
                elif how == "its controller's number after its computer's":
                    record.machine = COMPUTER + CONTROLLER
                else:
                    record.machine = COMPUTER
                learned = True

        await server.SentOnlyWhile(reply)(asked(app, "GET", path).scope, receive, send)
        if not kept:
            assert got == served.PIECE and lending.ended and core.served.find(lending.token) is None
            return
        assert got == served.PIECE * 3 and not lending.ended and core.served.find(lending.token) is lending
        assert lending.identity == (record.cert_pem, record.machine, record.ident)
        record.machine = "server:" + "c" * 32  # (and what it learned is held to from then on: another's ends it)
        again = await image(lending.token, lending.url_name, asked(app, "GET", path))
        assert again.status_code == 404 and lending.ended

    asyncio.run(run())


def test_what_follows_and_what_does_not() -> None:
    """served.identity_follows, case by case (the outside review's fourth round)."""
    cert, other = "controller A's certificate", "controller B's certificate"
    assert served.identity_follows((cert, "", ""), (cert, COMPUTER, "")) == (cert, COMPUTER, "")
    assert served.identity_follows((None, COMPUTER, ""), (None, COMPUTER + CONTROLLER, "")) == (None, COMPUTER + CONTROLLER, "")
    assert served.identity_follows((None, "", ""), (None, COMPUTER, "")) is None  # (known by nothing)
    assert served.identity_follows((None, "", ""), (cert, "", "")) is None
    assert served.identity_follows((cert, "", ""), (other, "", "")) is None
    assert served.identity_follows((None, COMPUTER, ""), (None, "server:" + "c" * 32, "")) is None
    assert served.identity_follows((None, COMPUTER, ""), (None, COMPUTER + "x", "")) is None  # (grows by a whole number alone)
    assert served.identity_follows((None, COMPUTER + CONTROLLER, ""), (None, COMPUTER, "")) is None
    assert served.identity_follows(("", "jetkvm:" + "d" * 32, ""), ("", "jetkvm:" + "d" * 32 + "e", "")) is None
    assert served.identity_follows((None, "", "own:ab12"), (None, COMPUTER, "own:ab12")) is None  # (qKVM's own label: no anchor)
    assert served.identity_follows((cert, "", "own:ab12"), (cert, COMPUTER, "own:ab12")) == (cert, COMPUTER, "own:ab12")
    assert served.identity_follows((None, COMPUTER, ""), (None, COMPUTER, "own:ab12")) == (None, COMPUTER, "own:ab12")
    assert served.identity_follows((None, COMPUTER, "own:ab12"), (None, COMPUTER, "own:cd34")) is None
