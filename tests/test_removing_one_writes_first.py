"""One machine taken off the wall (DELETE /api/v1/devices/{id}) the way several are (POST /api/v1/devices/remove): the
settings file is written without it first, and only then is it taken off the wall and its connection closed.

It was taken off first and put back when the write failed: meanwhile its live lines had been told that it was gone and
had let go of their keys, an action on its way had been cut off ("it may have been done"), and a new connection had
signed in to it, after which the answer said that nothing was changed. And a request cut off while its write was under way
(qKVM stopping) left the wall without the machine, with no line in the activity log and its history kept. The answers of
the route are as they were: `{"ok": true}`, 404 `not_found`, 507 `not_saved`.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from starlette.requests import Request

from qkvm import server
from qkvm.store import Store
from tests.fake_kvm import FakeKvm, FakeState
from tests.test_live import Wall, a_jpeg
from tests.test_removing_several_at_once import down, fake, fast, in_the_file, on_the_wall, removed_lines, rows_of  # noqa: F401  (the fixtures)
from tests.test_wall import add, wait_until, wall

pytestmark = pytest.mark.filterwarnings(r"ignore:connect\(\) must be used as a context manager:DeprecationWarning")


def test_a_write_that_fails_cuts_off_nothing_on_the_machine_it_leaves_on_the_wall(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A write that takes its time before it fails, as one that hangs does.
    disk = {"full": False}
    real_write = Store.write

    def slow_refusal(self: Store, saved: dict[str, Any]) -> None:
        if disk["full"]:
            time.sleep(1.5)
            raise OSError(28, "No space left on device")
        real_write(self, saved)

    monkeypatch.setattr(Store, "write", slow_refusal)
    held = FakeKvm(FakeState(picture=a_jpeg((32, 74, 135)), picture_type="image/jpeg")).start()
    try:
        with Wall(tmp_path) as live_wall:
            admin = live_wall.browser()
            device = live_wall.add(admin, held.url)
            name = admin.get("/api/v1/wall").json()["devices"][0]["name"]
            line = live_wall.line(admin, device)
            assert line.picture().kind == 2
            line.say(t="control", on=True)
            assert line.word("control")["on"] is True
            line.say(t="k", u=0xE0, d=True)  # ControlLeft, held down
            wait_until(lambda: len(held.state.hid) == 1, f"the key did not arrive: {held.state.hid}")
            signed_in = held.state.logins

            disk["full"] = True
            reply = admin.delete(f"/api/v1/devices/{device}")
            disk["full"] = False
            assert reply.status_code == 507, reply.text
            assert reply.json() == {"code": "not_saved", "message": f"Removing {name} could not be saved (No space left on device), so nothing was changed."}
            assert [d["id"] for d in admin.get("/api/v1/wall").json()["devices"]] == [device]
            # The line goes on as it was: not told to go, its key still down, and what it sends still arrives.
            until = time.monotonic() + 1.0
            while time.monotonic() < until:
                with contextlib.suppress(TimeoutError):
                    came = line.next(0.2)
                    assert not (isinstance(came, dict) and came["t"] == "bye"), came
            assert held.state.hid == [{"event_type": "key", "event": {"key": "ControlLeft", "state": True}}], held.state.hid
            line.say(t="k", u=0x06, d=True)  # KeyC
            wait_until(lambda: len(held.state.hid) == 2, f"the line no longer reaches the machine: {held.state.hid}")
            assert held.state.logins == signed_in, "the wall signed in to the machine anew"
            assert removed_lines(admin) == []
            line.close()
    finally:
        held.stop()


def test_nothing_on_the_wall_changes_until_the_file_has_it_and_then_everything_goes_as_it_went(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    writing, release = threading.Event(), threading.Event()
    hold = {"on": False}
    real_write = Store.write

    def held_write(self: Store, saved: dict[str, Any]) -> None:
        if hold["on"]:
            writing.set()
            release.wait(10)
        real_write(self, saved)

    monkeypatch.setattr(Store, "write", held_write)
    held = FakeKvm(FakeState(picture=a_jpeg((32, 74, 135)), picture_type="image/jpeg")).start()
    try:
        with Wall(tmp_path) as live_wall:
            admin = live_wall.browser()
            device = live_wall.add(admin, held.url)
            line = live_wall.line(admin, device)
            assert line.picture().kind == 2
            line.say(t="control", on=True)
            assert line.word("control")["on"] is True
            line.say(t="k", u=0xE0, d=True)
            wait_until(lambda: len(held.state.hid) == 1, f"the key did not arrive: {held.state.hid}")
            assert admin.get(f"/api/v1/devices/{device}/history").status_code == 200

            answers: list[Any] = []
            hold["on"] = True
            removing = threading.Thread(target=lambda: answers.append(admin.delete(f"/api/v1/devices/{device}")))
            removing.start()
            assert writing.wait(10), "the settings were never written"
            # While the file is being written, the machine is on the wall as it was: listed, looked at, its line untold.
            assert [d["id"] for d in admin.get("/api/v1/wall").json()["devices"]] == [device]
            assert device in admin.get("/api/v1/status").json()
            until = time.monotonic() + 1.2  # (longer than the line's own look, once a second, at whether its machine is there)
            while time.monotonic() < until:
                with contextlib.suppress(TimeoutError):
                    came = line.next(0.2)
                    assert not (isinstance(came, dict) and came["t"] == "bye"), f"the line was told before the file had it: {came}"
            assert len(held.state.hid) == 1, f"its key was let go of before the file had it: {held.state.hid}"
            hold["on"] = False
            release.set()
            removing.join(10)
            assert answers and answers[0].status_code == 200 and answers[0].json() == {"ok": True}, answers
            # Written down, then off the wall, its line told and its key let go of first, its log line written once.
            assert in_the_file(tmp_path) == []
            assert admin.get("/api/v1/wall").json()["devices"] == []
            assert held.state.hid[1:] == [{"event_type": "key", "event": {"key": "ControlLeft", "state": False}}], held.state.hid
            assert line.word("bye")["code"] == "gone"
            line.closed()
            wait_until(lambda: len(removed_lines(admin)) == 1, "the removal is not in the activity log once")
            assert removed_lines(admin)[0]["device"] and removed_lines(admin)[0]["user"] == "admin"
            assert admin.delete(f"/api/v1/devices/{device}").json() == {"code": "not_found", "message": "Unknown device"}
            assert admin.post(f"/api/v1/devices/{device}/live").status_code == 404
    finally:
        held.stop()


@pytest.mark.parametrize("write", ["goes through", "fails"])
def test_a_removal_cut_off_while_its_write_is_under_way_ends_as_the_write_does(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch, write: str) -> None:  # noqa: F811
    # qKVM stopping, or its listeners opened anew, cuts off a request that is still running. Cut off, the request lets go
    # of the removal, which ends as its write does. Through: gone, written down, forgotten, its connection closed. Failed:
    # nothing changed.
    data = tmp_path / "data"
    with wall(data) as admin:
        core = admin.core  # type: ignore[attr-defined]
        wait_until(lambda: core.store.unlock is not None, "the key of its own was never fitted")
        first, second = add(admin, fake.url, name="Build server"), down(admin, "Mail server")
        wait_until(lambda: admin.get("/api/v1/status").json()[first]["state"] == "online", "the machine never came online", timeout=15)
        assert admin.put("/api/v1/wall/order", json={"ids": []}).status_code == 200  # (one change after the key's own: that write is over)
        signed_in = fake.state.logins
        core.history.pressed(first, "atx_power", True)
        core.history.flush()
        writing, release, done = threading.Event(), threading.Event(), threading.Event()
        real_write = Store.write

        def held_write(self: Store, saved: dict[str, Any]) -> None:
            writing.set()
            release.wait(10)
            try:
                if write == "fails":
                    raise OSError(28, "No space left on device")
                real_write(self, saved)
            finally:
                done.set()

        monkeypatch.setattr(Store, "write", held_write)
        path = "/api/v1/devices/{device_id}"
        endpoint = next(route.endpoint for route in admin.app.routes if getattr(route, "path", "") == path and "DELETE" in route.methods)  # type: ignore[attr-defined]
        request = Request({"type": "http", "method": "DELETE", "path": f"/api/v1/devices/{first}", "headers": [], "query_string": b"", "client": ("127.0.0.1", 50000), "app": admin.app})
        cut: list[bool] = []

        async def cut_off() -> None:
            who = server.acting.set("admin")  # (as the guard sets it for the request it lets through)
            task = asyncio.ensure_future(endpoint(first, request))
            server.acting.reset(who)
            while not writing.is_set():
                await asyncio.sleep(0.01)
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            cut.append(task.cancelled())

        admin.portal.call(cut_off)  # type: ignore[attr-defined]
        assert cut == [True]
        assert on_the_wall(admin) == [first, second]  # (nothing changes before the file has it)
        release.set()
        assert done.wait(10)
        if write == "goes through":
            wait_until(lambda: on_the_wall(admin) == [second], "the removal was not finished after its request was cut off")
            assert in_the_file(data) == [second]
            assert set(admin.get("/api/v1/status").json()) == {second}
            wait_until(lambda: len(removed_lines(admin)) == 1, "removed, and not written down")
            assert [(line["device"], line["user"]) for line in removed_lines(admin)] == [("Build server", "admin")]
            core.history.flush()
            assert rows_of(data, first) == 0, "the history of a machine that is gone was kept"
            assert core.watcher.state(first) is None
        else:
            time.sleep(0.5)  # (what would follow a failed write has had its moment)
            assert on_the_wall(admin) == [first, second] and in_the_file(data) == [first, second]
            assert admin.get("/api/v1/status").json()[first]["state"] == "online" and fake.state.logins == signed_in  # (the connection it had)
            assert removed_lines(admin) == []
            core.history.flush()
            assert rows_of(data, first) > 0
