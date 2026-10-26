"""Several machines taken off the wall in one go (POST /api/v1/devices/remove): every one of them, or none.

Each as DELETE /api/v1/devices/{id} takes one: gone from the wall and from the settings file, its saved password with it,
its history and what alerts knew of it forgotten, a line for it in the activity log. The settings are written once for
all of them; a write that fails puts every one back where it stood, and an id that is not on the wall removes nothing.
Only an admin may, never a token. What is being done to one of them at that moment does not keep it: the action is
answered "it may have been done", and a live line lets go of the keys it held before its connection goes.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from starlette.requests import Request

from qkvm import history, kvm, live, server, update, vault
from qkvm.alerts import SETTLE
from qkvm.core import DeviceManager
from qkvm.store import Store
from tests.fake_kvm import FakeKvm, FakeState
from tests.test_failed_writes import refuse_writes
from tests.test_live import Wall, a_jpeg
from tests.test_meanwhile import in_background
from tests.test_tokens import script
from tests.test_users import account, browser, visitor
from tests.test_wall import add, closed_port, wait_until, wall
from tests.settings_file import settings_text

REMOVE = "/api/v1/devices/remove"
# (A live line is opened and held by test_live's `Viewer` for as long as a test wants it, not in a `with`: the library would rather it were.)
pytestmark = pytest.mark.filterwarnings(r"ignore:connect\(\) must be used as a context manager:DeprecationWarning")


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")
    monkeypatch.setattr(live, "STANDING_EVERY", 0.2)


@pytest.fixture
def fake() -> Iterator[FakeKvm]:
    device = FakeKvm(FakeState(atx=True)).start()
    yield device
    device.stop()


def down(admin: Any, name: str) -> str:
    """A machine on the wall that does not answer: saved all the same, with a password."""
    return add(admin, f"http://127.0.0.1:{closed_port()}", force=True, kind="kvmd", name=name)


def on_the_wall(admin: Any) -> list[str]:
    return [device["id"] for device in admin.get("/api/v1/wall").json()["devices"]]


def in_the_file(data: Path) -> list[str]:
    return [device["id"] for device in json.loads(settings_text(data / "qkvm.json", encoding="utf-8"))["devices"]]


def removed_lines(admin: Any) -> list[dict[str, Any]]:
    """The activity log's lines of machines taken off the wall, oldest first (as they were written, whatever the clock says)."""
    entries = admin.get("/api/v1/audit", params={"q": "device_removed", "limit": 500}).json()["entries"]
    return [entry for entry in reversed(entries) if entry["event"] == "device_removed"]


def rows_of(data: Path, device_id: str) -> int:
    """How many rows the history file holds of this machine, in all its tables."""
    conn = sqlite3.connect(data / history.FILE)
    try:
        return sum(conn.execute(f"SELECT COUNT(*) FROM {table} WHERE device = ?", (device_id,)).fetchone()[0] for table in ("states", "samples", "events", "devices"))
    finally:
        conn.close()


@contextmanager
def counted_writes() -> Iterator[list[int]]:
    """Counts the writes of the settings file while it is held: one entry per write."""
    writes: list[int] = []
    real_write = Store.write

    def write(self: Store, data: dict[str, Any]) -> None:
        writes.append(1)
        real_write(self, data)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(Store, "write", write)
        yield writes


def test_several_go_in_one_request_each_written_down_with_its_history_and_its_alerts_forgotten(tmp_path: Path, fake: FakeKvm) -> None:
    data = tmp_path / "data"
    with wall(data) as admin:
        core = admin.core  # type: ignore[attr-defined]
        wait_until(lambda: core.store.unlock is not None, "the key of its own was never fitted")  # (a write of its own, not to be counted below)
        first = add(admin, fake.url, name="Build server")
        second, third, fourth = down(admin, "Mail server"), down(admin, "Backup"), down(admin, "Printer")
        urls = {device["id"]: device["url"] for device in admin.get("/api/v1/wall").json()["devices"]}
        for device_id in (first, second, third, fourth):
            core.history.pressed(device_id, "atx_power", True)
            for _ in range(SETTLE):
                core.watcher.observe(device_id, "offline")
        core.history.flush()
        assert all(rows_of(data, device_id) for device_id in (first, second, third, fourth))
        assert all(core.watcher.state(device_id) is not None for device_id in (first, second, third, fourth))

        with counted_writes() as writes:
            # Asked in another order than the wall's, and one of them twice: each goes once, and is answered in the wall's order.
            reply = admin.post(REMOVE, json={"ids": [fourth, first, second, fourth]})
        assert reply.status_code == 200, reply.text
        assert reply.json() == {"ok": True, "removed": [first, second, fourth]}
        assert len(writes) == 1, f"the settings were written {len(writes)} times for one removal"

        assert on_the_wall(admin) == [third]
        assert in_the_file(data) == [third]
        assert set(admin.get("/api/v1/status").json()) == {third}  # (the clients went with them)
        lines = removed_lines(admin)
        assert [(line["device"], line["url"]) for line in lines] == [("Build server", urls[first]), ("Mail server", urls[second]), ("Printer", urls[fourth])]
        assert all(line["note"] == "one of 3 removed together" and line["user"] == "admin" for line in lines)
        for device_id in (first, second, fourth):
            assert admin.get(f"/api/v1/devices/{device_id}/history").status_code == 404
            assert core.watcher.state(device_id) is None, "alerts still know a machine that is gone"
        core.history.flush()
        assert [rows_of(data, device_id) for device_id in (first, second, fourth)] == [0, 0, 0], "the history of a removed machine was kept"
        assert rows_of(data, third) > 0 and core.watcher.state(third) is not None  # (the one left keeps its own)

        # One alone is taken the same way, and said without "together".
        only = admin.post(REMOVE, json={"ids": [third]})
        assert only.status_code == 200 and only.json()["removed"] == [third]
        assert on_the_wall(admin) == [] and "note" not in removed_lines(admin)[-1]

    with wall(data) as later:
        assert on_the_wall(later) == []  # (nothing comes back with a restart)


def test_an_id_that_is_not_on_the_wall_removes_nothing_and_is_named(tmp_path: Path) -> None:
    data = tmp_path / "data"
    with wall(data) as admin:
        first, second, third = down(admin, "One"), down(admin, "Two"), down(admin, "Three")
        with counted_writes() as writes:
            reply = admin.post(REMOVE, json={"ids": [first, "nosuch01", second, "gone0002", "nosuch01"]})
        assert reply.status_code == 404, reply.text
        said = reply.json()
        assert said["code"] == "not_found" and said["unknown"] == ["nosuch01", "gone0002"]
        assert "nosuch01" in said["message"] and "gone0002" in said["message"] and "Nothing was removed" in said["message"]
        assert writes == [] and on_the_wall(admin) == [first, second, third] and in_the_file(data) == [first, second, third]
        assert removed_lines(admin) == []

        # Taken off by somebody else a moment before: the rest of what was asked for stays as well.
        assert admin.delete(f"/api/v1/devices/{first}").status_code == 200
        again = admin.post(REMOVE, json={"ids": [first, second]})
        assert (again.status_code, again.json()["code"], again.json()["unknown"]) == (404, "not_found", [first])
        assert again.json()["message"].startswith("This is not on the wall")
        assert on_the_wall(admin) == [second, third]
        assert [line["device"] for line in removed_lines(admin)] == ["One"]

        # Many unknown: the sentence names five, the field all of them.
        many = [f"nosuch{n:02d}" for n in range(12)]
        lots = admin.post(REMOVE, json={"ids": [second, *many]})
        assert lots.status_code == 404 and lots.json()["unknown"] == many and "and 7 more" in lots.json()["message"]
        assert on_the_wall(admin) == [second, third]


def test_a_write_that_fails_leaves_every_one_where_it_stood(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    data = tmp_path / "data"
    disk = refuse_writes(monkeypatch)
    with wall(data) as admin:
        core = admin.core  # type: ignore[attr-defined]
        ids = [down(admin, "A"), add(admin, fake.url, name="B"), down(admin, "C"), down(admin, "D"), down(admin, "E")]
        for device_id in ids:
            core.history.pressed(device_id, "atx_power", True)
        core.history.flush()
        wait_until(lambda: admin.get("/api/v1/status").json()[ids[1]]["state"] == "online", "the machine never came online", timeout=10)
        signed_in = fake.state.logins
        disk["full"] = True
        reply = admin.post(REMOVE, json={"ids": [ids[4], ids[1], ids[3]]})
        assert reply.status_code == 507, reply.text
        assert reply.json()["code"] == "not_saved" and reply.json()["message"].startswith("Removing 3 KVMs could not be saved")
        assert "nothing was changed" in reply.json()["message"]
        # Every one where it stood, with the connection it had (the status asks the connections; a new one signs in anew).
        assert on_the_wall(admin) == ids
        assert set(admin.get("/api/v1/status").json()) == set(ids)
        assert admin.get("/api/v1/status").json()[ids[1]]["state"] == "online" and fake.state.logins == signed_in
        assert removed_lines(admin) == []
        core.history.flush()
        assert all(rows_of(data, device_id) for device_id in ids), "the history of machines that were not removed was forgotten"

        one = admin.post(REMOVE, json={"ids": [ids[2]]})
        assert one.status_code == 507 and one.json()["message"].startswith("Removing C could not be saved")
        assert on_the_wall(admin) == ids
        disk["full"] = False
    with wall(data) as later:
        assert on_the_wall(later) == ids and in_the_file(data) == ids  # (the file never lost them)
        assert later.post(REMOVE, json={"ids": [ids[3], ids[0]]}).status_code == 200
        assert on_the_wall(later) == [ids[1], ids[2], ids[4]]


def test_only_an_admin_may_never_a_token_nor_a_page_of_another_site(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as admin:
        first, second = add(admin, fake.url, name="Build server"), down(admin, "Mail server")
        account(admin, "olga", "operator")
        account(admin, "victor", "viewer")
        operator, viewer = browser(admin, "olga", port=50101), browser(admin, "victor", port=50102)
        token = admin.post("/api/v1/tokens", json={"name": "nightly", "role": "operator"}).json()["token"]
        robot = script(admin, token)
        for who in (operator, viewer, robot):
            refused = who.post(REMOVE, json={"ids": [first, second]})
            assert (refused.status_code, refused.json()["code"]) == (403, "not_allowed"), refused.text
        # Not signed in; and an admin's browser made to send it by a page of another site (without the page's header).
        assert visitor(admin, 50105).post(REMOVE, json={"ids": [first]}).status_code == 401
        elsewhere = admin.post(REMOVE, json={"ids": [first]}, headers={"X-QKVM": "", "Origin": "https://elsewhere.example"})
        assert (elsewhere.status_code, elsewhere.json()["code"]) == (403, "forbidden")
        assert on_the_wall(admin) == [first, second] and removed_lines(admin) == []
        # (Refused above by the rule that whatever is not listed takes an admin, which holds for a path nobody serves as
        # well. That it is this request that was refused, and that an admin may make it, is seen here.)
        assert admin.post(REMOVE, json={"ids": [first, second]}).status_code == 200
        assert on_the_wall(admin) == [] and [line["user"] for line in removed_lines(admin)] == ["admin", "admin"]


def test_what_is_no_id_is_refused_and_not_said_back(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        first = down(admin, "One")
        for body in (
            '{"ids": []}',
            '{"ids": ["\\ud800"]}',  # half a character
            '{"ids": ["ab:12cd34"]}',  # (a colon: no id of this program's has one, see store._ID)
            '{"ids": ["' + "a" * 65 + '"]}',
            '{"ids": ["' + first + '\\n"]}',
            '{"ids": [12345678]}',
            '{"ids": "' + first + '"}',
            '{"ids": [' + ", ".join('"ab12cd34"' for _ in range(5001)) + "]}",
            "{}",
        ):
            reply = admin.post(REMOVE, content=body.encode("ascii"), headers={"Content-Type": "application/json"})
            assert (reply.status_code, reply.json()["code"]) == (422, "invalid"), (body[:40], reply.text[:200])
            assert "\\ud800" not in reply.text and "ab:12" not in reply.text and "a" * 65 not in reply.text
        assert on_the_wall(admin) == [first]


def test_a_machine_with_an_action_or_a_text_on_its_way_is_removed_all_the_same(tmp_path: Path) -> None:
    # (Refused instead, somebody who typed to a machine again and again could keep it on the wall against an admin's word.)
    keys = FakeKvm(FakeState(slow={"/api/hid/events/send_shortcut": 30.0})).start()
    typing = FakeKvm(FakeState(slow={"/api/hid/print": 30.0})).start()
    try:
        with wall(tmp_path) as admin:
            pressed, typed = add(admin, keys.url, name="Pressed"), add(admin, typing.url, name="Typed to")
            wait_until(lambda: all(s["state"] == "online" for s in admin.get("/api/v1/status").json().values()), "the two never came online", timeout=15)
            account(admin, "olga", "operator")
            olga, hers = browser(admin, "olga", port=50103), browser(admin, "olga", port=50104)
            first, answers = in_background(lambda: olga.post(f"/api/v1/devices/{pressed}/actions", json={"action": "keys", "keys": "ControlLeft,AltLeft,Delete"}))
            second, more = in_background(lambda: hers.post(f"/api/v1/devices/{typed}/actions", json={"action": "text", "text": "shutdown now", "enter": True}))
            wait_until(lambda: "POST /api/hid/events/send_shortcut" in keys.state.asked and "POST /api/hid/print" in typing.state.asked, "the two never reached their machines", timeout=10)
            # Both machines are busy, and the wall says so to anybody who asks for something else.
            assert admin.post(f"/api/v1/devices/{pressed}/actions", json={"action": "keys", "keys": "Enter"}).json()["code"] == "busy"

            reply = admin.post(REMOVE, json={"ids": [pressed, typed]})
            assert reply.status_code == 200, reply.text
            keys.state.slow.clear()  # (the stand-ins stop waiting: what they would have answered nobody hears any more)
            typing.state.slow.clear()
            first.join(10)
            second.join(10)
            assert not first.is_alive() and not second.is_alive(), "an action went on waiting for a machine that is gone"
            for answer in (answers[0], more[0]):
                assert answer.status_code == 504 and answer.json()["code"] == "timeout", answer.text
                assert "may have been done" in answer.json()["message"]
            assert on_the_wall(admin) == []
            failed = [entry for entry in admin.get("/api/v1/audit").json()["entries"] if entry["event"] == "action_failed"]
            assert {entry["device"] for entry in failed} == {"Pressed", "Typed to"}
            assert {line["device"] for line in removed_lines(admin)} == {"Pressed", "Typed to"}
    finally:
        keys.stop()
        typing.stop()


@pytest.mark.parametrize("how", ["alone", "with others"])
def test_a_power_button_still_held_when_its_machine_is_removed_leaves_no_history_behind(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, how: str) -> None:
    # The wall holds a machine for as long as its board holds the button (six and a half seconds for a long press), and
    # writes the press into the history when that is over: by then the machine and its history were gone, and the press
    # came back as a row of a machine that is not on the wall. (So it did after DELETE /api/v1/devices/{id} as well.)
    monkeypatch.setattr(kvm, "HELD", dict.fromkeys(kvm.HELD, 2.0))
    data = tmp_path / "data"
    board = FakeKvm(FakeState(atx=True)).start()
    try:
        with wall(data) as admin:
            device, other = add(admin, board.url, name="Pressed"), down(admin, "Beside")
            wait_until(lambda: admin.get("/api/v1/status").json()[device]["state"] == "online", "the machine never came online", timeout=15)
            pressing, answers = in_background(lambda: admin.post(f"/api/v1/devices/{device}/actions", json={"action": "atx_reset"}))
            wait_until(lambda: "atx reset" in board.state.actions, "the button was never pressed", timeout=10)
            if how == "alone":
                assert admin.delete(f"/api/v1/devices/{device}").status_code == 200
            else:
                assert admin.post(REMOVE, json={"ids": [device, other]}).status_code == 200
            pressing.join(15)
            # (Pressed: the board had taken it. Or, where the removal came between the press and the board's answer to it,
            # cut off with it: "it may have been done". Either way nothing of it is to be kept.)
            assert answers and answers[0].status_code in (200, 504), answers
            admin.core.history.flush()  # type: ignore[attr-defined]
            assert rows_of(data, device) == 0, "a press came back into the history of a machine that is gone"
    finally:
        board.stop()


def test_a_write_that_fails_cuts_off_nothing_on_the_machines_it_leaves_on_the_wall(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Nothing on the wall changes until the file says that they are gone. (Taken off first, a write that failed had told
    # every live line "gone", let go of its keys, answered every action "it may have been done" and signed in anew, to then
    # say that nothing was changed; and with only their connections taken out before the write, a line's own look, once a
    # second, found its machine gone while a slow write was under way.) This write takes its time before it fails, as one
    # that hangs does.
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
            other = live_wall.add(admin, f"http://127.0.0.1:{closed_port()}", force=True, kind="kvmd")
            line = live_wall.line(admin, device)
            assert line.picture().kind == 2
            line.say(t="control", on=True)
            assert line.word("control")["on"] is True
            line.say(t="k", u=0xE0, d=True)  # ControlLeft, held down
            wait_until(lambda: len(held.state.hid) == 1, f"the key did not arrive: {held.state.hid}")
            signed_in = held.state.logins

            disk["full"] = True
            reply = admin.post(REMOVE, json={"ids": [device, other]})
            assert (reply.status_code, reply.json()["code"]) == (507, "not_saved"), reply.text
            disk["full"] = False
            assert [d["id"] for d in admin.get("/api/v1/wall").json()["devices"]] == [device, other]
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
            line.close()
    finally:
        held.stop()


@pytest.mark.parametrize("write", ["goes through", "fails"])
def test_a_removal_cut_off_while_its_write_is_under_way_ends_as_the_write_does(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch, write: str) -> None:
    # qKVM stopping, or its listeners opened anew, cuts off a request that is still running, and nothing it then waits for
    # is sure to finish. The removal is a task of its own that the request waits for: cut off, the request lets go of it,
    # and it ends as the write does. Through: gone, written down, forgotten, their connections closed. Failed: nothing changed.
    data = tmp_path / "data"
    with wall(data) as admin:
        core = admin.core  # type: ignore[attr-defined]
        wait_until(lambda: core.store.unlock is not None, "the key of its own was never fitted")
        first, second, third = add(admin, fake.url, name="Build server"), down(admin, "Mail server"), down(admin, "Backup")
        wait_until(lambda: admin.get("/api/v1/status").json()[first]["state"] == "online", "the machine never came online", timeout=15)
        assert admin.put("/api/v1/wall/order", json={"ids": []}).status_code == 200  # (one change after the key's own: that write is over)
        signed_in = fake.state.logins
        core.history.pressed(first, "atx_power", True)
        core.history.flush()
        for _ in range(SETTLE):
            core.watcher.observe(second, "offline")
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
                done.set()  # (waited for, not looked for in the file: on Windows a reader of the file makes its replacement fail)

        monkeypatch.setattr(Store, "write", held_write)
        # Asked of the route itself, as the request would, so that it can be cut off where a stop would cut it off.
        endpoint = next(route.endpoint for route in admin.app.routes if getattr(route, "path", "") == REMOVE and "POST" in route.methods)  # type: ignore[attr-defined]
        request = Request({"type": "http", "method": "POST", "path": REMOVE, "headers": [], "query_string": b"", "client": ("127.0.0.1", 50000), "app": admin.app})
        cut: list[bool] = []

        async def cut_off() -> None:
            who = server.acting.set("admin")  # (as the guard sets it for the request it lets through)
            task = asyncio.ensure_future(endpoint(server.RemoveIn(ids=[first, second]), request))
            server.acting.reset(who)
            while not writing.is_set():
                await asyncio.sleep(0.01)
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            cut.append(task.cancelled())

        admin.portal.call(cut_off)  # type: ignore[attr-defined]
        assert cut == [True]
        assert on_the_wall(admin) == [first, second, third]  # (nothing changes before the file has it)
        release.set()
        assert done.wait(10)
        if write == "goes through":
            wait_until(lambda: on_the_wall(admin) == [third], "the removal was not finished after its request was cut off")
            assert in_the_file(data) == [third]
            assert set(admin.get("/api/v1/status").json()) == {third}
            wait_until(lambda: len(removed_lines(admin)) == 2, "removed, and not written down")
            assert [(line["device"], line["user"]) for line in removed_lines(admin)] == [("Build server", "admin"), ("Mail server", "admin")]
            core.history.flush()
            assert rows_of(data, first) == 0, "the history of a machine that is gone was kept"
            assert core.watcher.state(second) is None
        else:
            time.sleep(0.5)  # (what would follow a failed write has had its moment)
            assert on_the_wall(admin) == [first, second, third] and in_the_file(data) == [first, second, third]
            assert admin.get("/api/v1/status").json()[first]["state"] == "online" and fake.state.logins == signed_in  # (the connection it had)
            assert removed_lines(admin) == []
            core.history.flush()
            assert rows_of(data, first) > 0 and core.watcher.state(second) == "offline"


def test_a_machine_whose_keyboard_is_held_over_a_live_line_is_removed_and_its_keys_let_go_of_first(tmp_path: Path) -> None:
    held = FakeKvm(FakeState(picture=a_jpeg((32, 74, 135)), picture_type="image/jpeg")).start()
    other = FakeKvm(FakeState(picture=a_jpeg((135, 74, 32)), picture_type="image/jpeg")).start()
    try:
        with Wall(tmp_path) as live_wall:
            admin = live_wall.browser()
            device, beside = live_wall.add(admin, held.url), live_wall.add(admin, other.url)
            line = live_wall.line(admin, device)
            assert line.picture().kind == 2
            line.say(t="control", on=True)
            assert line.word("control")["on"] is True
            line.say(t="k", u=0xE0, d=True)  # ControlLeft
            line.say(t="mb", b=1, d=True)
            wait_until(lambda: len(held.state.hid) == 2, f"the key and the button did not arrive: {held.state.hid}")
            watching = live_wall.line(admin, beside)  # (and one more line, only looking, on the other machine)
            assert watching.picture().kind == 2

            reply = admin.post(REMOVE, json={"ids": [device, beside]})
            assert reply.status_code == 200, reply.text
            # Let go of through the machine's own connection, before that went: by the time the answer came.
            assert held.state.hid[2:] == [
                {"event_type": "key", "event": {"key": "ControlLeft", "state": False}},
                {"event_type": "mouse_button", "event": {"button": "left", "state": False}},
            ], held.state.hid
            assert line.word("bye")["code"] == "gone"
            assert watching.word("bye")["code"] == "gone"
            line.closed()
            watching.closed()
            assert admin.get("/api/v1/wall").json()["devices"] == []
            assert admin.post(f"/api/v1/devices/{device}/live").status_code == 404
    finally:
        held.stop()
        other.stop()


def test_removing_several_waits_its_turn_behind_every_other_change(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    # Another change holds the turn without having reached the disk yet (an edit, at the moment it puts its new connection in
    # place): the removal waits for it, and neither writes nor touches anything meanwhile. (The disk's own one write at a
    # time would not keep it back here: nobody is writing.)
    data = tmp_path / "data"
    with wall(data) as admin:
        core = admin.core  # type: ignore[attr-defined]
        wait_until(lambda: core.store.unlock is not None, "the key of its own was never fitted")
        edited, first, second = add(admin, fake.url, name="Build server"), down(admin, "One"), down(admin, "Two")
        held, release = threading.Event(), threading.Event()
        real_adopt = DeviceManager.adopt

        async def held_adopt(self: DeviceManager, device: Any) -> None:
            held.set()
            await asyncio.to_thread(release.wait, 10)
            await real_adopt(self, device)

        monkeypatch.setattr(DeviceManager, "adopt", held_adopt)
        editing, edit = in_background(lambda: admin.put(f"/api/v1/devices/{edited}", json={"url": fake.url, "name": "Renamed"}))
        assert held.wait(10), "the edit never got as far as its turn"
        with counted_writes() as writes:
            removing, removed = in_background(lambda: admin.post(REMOVE, json={"ids": [first, second]}))
            removing.join(0.5)
            assert removing.is_alive(), "the removal did not wait for the change before it"
            assert writes == [] and [device.id for device in core.store.devices] == [edited, first, second]  # (and touched nothing)
            release.set()
            editing.join(10)
            removing.join(10)
        assert edit[0].status_code == 200 and removed[0].status_code == 200, (edit, removed)
        assert len(writes) == 2  # (the edit's, then the removal's)
        assert [(device["id"], device["name"]) for device in admin.get("/api/v1/wall").json()["devices"]] == [(edited, "Renamed")]
        assert in_the_file(data) == [edited]
