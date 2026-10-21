"""Many KVMs, many viewers, things happening at the same time: nothing waits that need not, and nothing is kept that is not needed."""

from __future__ import annotations

import asyncio
import json
import socket
import threading
import time
from collections.abc import AsyncIterator, Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest

from qkvm import alerts, cli, kvm, server, update, vault
from qkvm.core import Core, DeviceManager
from qkvm.kvm import Device, DeviceSpec, KvmDevice, KvmError, bounded
from qkvm.store import DeviceRecord, Store
from tests.fake_kvm import FakeKvm
from tests.test_a_password_a_device_rejects_again_and_again import that_long_has_passed
from tests.test_alerts import Inbox, baseline
from tests.test_hardening import LiveWall
from tests.test_users import OTHER, account, browser, visitor
from tests.test_wall import CSRF, PASSWORD, add, snap, wait_until, wall


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


@pytest.fixture
def fake() -> Iterator[FakeKvm]:
    server = FakeKvm().start()
    yield server
    server.state.stall = 0  # whatever it still holds back may go
    server.stop()


def spec(url: str) -> DeviceSpec:
    return DeviceSpec(id="ab12", name="KVM", base_url=url, username="admin", password="secret")


# --- a KVM that is down ---------------------------------------------------------


def test_a_kvm_that_went_silent_holds_up_no_tile(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    # (A request that went to the KVM would take as long as giving up on it takes, `give_up`; one answered from what is known
    # takes a round trip through the wall. Half a second against 0.4 left a busy computer no room: one request took 0.77 s.
    # So giving up takes two seconds here, and a request that waited would take at least that.)
    give_up = 2.0
    monkeypatch.setattr(kvm, "WAITS", httpx.Timeout(give_up))
    monkeypatch.setattr(kvm, "ERROR_HOLD", 1.0)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 0.1)
    with wall(tmp_path) as client:
        device = add(client, fake.url)
        assert client.get(snap(device)).status_code == 200
        fake.state.stall = 30  # still there, but answers nothing any more
        assert client.get(snap(device)).json()["code"] == "timeout"  # the one request that finds out

        # From here on its tile is answered from what is known. Had each request gone to the KVM
        # to see for itself, each would have taken the time it takes to give up.
        asked = fake.state.requests
        for _ in range(10):
            began = time.monotonic()
            assert client.get(snap(device)).json()["code"] == "timeout"
            assert time.monotonic() - began < give_up / 2
        assert fake.state.requests == asked  # nobody even looks before the pause after the failure is over

        # When it is, the status refresh looks, in the background. The first such look gets a moment
        # (the KVM may have had a hiccup, no more); once that one has failed too, nothing waits at all.
        time.sleep(1.1)
        for _ in range(2):
            began = time.monotonic()
            assert client.get(snap(device)).json()["code"] == "timeout"
            assert time.monotonic() - began < give_up / 2
            time.sleep(give_up + 0.2)  # the look gives up after `give_up`
        assert 1 <= fake.state.requests - asked <= 2

        fake.state.stall = 0  # and that refresh is what notices that it is back
        wait_until(lambda: client.get(snap(device)).status_code == 200, "the KVM coming back was not noticed", timeout=10)


def test_one_request_that_failed_does_not_black_out_a_kvm_that_is_there(
    tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0.2)
    monkeypatch.setattr(kvm, "STATUS_TTL", 30)  # nothing else looks at the KVM during this test
    # (Every request is given two seconds, the press that hangs thirty: given 0.3 s, a busy computer's ordinary answer
    # took longer, and the picture asked for after it was a 504.)
    monkeypatch.setattr(kvm, "WAITS", httpx.Timeout(2.0))
    with wall(tmp_path) as client:
        device = add(client, fake.url)
        assert client.get(snap(device)).status_code == 200
        assert client.get("/api/v1/status").json()[device]["state"] == "online"
        fake.state.slow["/api/hid/events/send_shortcut"] = 30  # the KVM is slow to press keys, this once
        pressed = client.post(f"/api/v1/devices/{device}/actions", json={"action": "ctrl_alt_del"})
        assert pressed.json()["code"] == "timeout"
        fake.state.slow.clear()
        time.sleep(0.3)  # the short pause after a failure
        # The next tile request has the KVM looked at, finds it there, and gets its picture.
        assert client.get(snap(device)).status_code == 200


def test_a_detail_of_the_status_that_hangs_does_not_take_the_pictures_away(
    tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(kvm, "ERROR_HOLD", 1.0)
    # (Every request is given two seconds, the detail that hangs thirty, and the page looks for three times the two: given
    # 0.3 s, a busy computer's ordinary answer took longer, and a picture was a 504.)
    monkeypatch.setattr(kvm, "WAITS", httpx.Timeout(2.0))
    with wall(tmp_path) as client:
        device = add(client, fake.url)
        assert client.get(snap(device)).status_code == 200
        fake.state.slow["/api/atx"] = 30  # one of the things the status is made of never arrives in time
        began = time.monotonic()
        while time.monotonic() - began < 6.0:  # the page: status and pictures, over and over
            assert client.get("/api/v1/status").json()[device]["state"] == "online"
            assert client.get(snap(device)).status_code == 200
            time.sleep(0.1)
        assert client.get("/api/v1/status").json()[device]["atx"]["enabled"] is False  # just the detail is missing


def test_a_kvm_never_heard_from_is_not_waited_for(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "WAITS", httpx.Timeout(3.0))
    with wall(tmp_path) as client:
        device = add(client, fake.url)
    fake.state.stall = 30
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 0.2)
    with wall(tmp_path) as client:  # qKVM starts again, and this time the KVM says nothing
        for _ in range(3):
            began = time.monotonic()
            reply = client.get(snap(device))
            assert time.monotonic() - began < 1.0  # not the three seconds it takes to give up on it
            assert (reply.status_code, reply.json()["code"]) == (503, "no_stream")  # the tile shows "connecting"
        fake.state.stall = 0
        wait_until(lambda: client.get(snap(device)).status_code == 200, "no picture once the KVM answered", timeout=10)


def test_requests_that_fail_together_count_as_one_failed_attempt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "ERROR_HOLD", 1.0)
    device = Device(spec("http://127.0.0.1:9"))
    for _ in range(6):  # a status read and five tiles, all under way when the KVM went down
        device._failed(KvmError("unreachable", "Device is unreachable"))
    assert device._failures == 1
    assert device._down_until - time.monotonic() <= 1.0  # tried again in a second, not in half a minute
    device._down_until = time.monotonic() - 0.01  # the wait is over, and the next attempt fails as well
    device._failed(KvmError("unreachable", "Device is unreachable"))
    assert device._failures == 2
    assert 1.5 < device._down_until - time.monotonic() <= 2.0


# --- things happening at the same time --------------------------------------------


@pytest.mark.parametrize("change", ["edit", "remove", "sign out"])
def test_a_picture_under_way_survives_its_kvm_being_changed(tmp_path: Path, fake: FakeKvm, change: str) -> None:
    # (The last sign-out takes the connections to the KVMs away where qKVM was started locked. As it comes, it
    # goes on watching, and a picture under way simply arrives.)
    with wall(tmp_path, locked_start=change == "sign out") as admin:
        device = add(admin, fake.url)
        viewer = visitor(admin, 50060)
        assert viewer.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
        assert viewer.get(snap(device)).status_code == 200
        fake.state.slow_snapshot = 1.0
        with ThreadPoolExecutor(max_workers=1) as pool:
            picture = pool.submit(viewer.get, snap(device))
            wait_until(lambda: len(fake.state.snapshot_queries) == 2, "the picture was never asked for")
            fake.state.slow_snapshot = 0
            if change == "edit":
                edited = admin.put(f"/api/v1/devices/{device}", json={"url": fake.url, "name": "Renamed"})
                assert edited.status_code == 200, edited.text
            elif change == "remove":
                assert admin.delete(f"/api/v1/devices/{device}").status_code == 200
            else:  # both browsers are signed in to the one account: this signs out the last of them
                assert admin.post("/api/v1/logout", json={"scope": "all"}).status_code == 200
            reply = picture.result(timeout=10)
        # The connection it was coming over is gone. The tile is told to ask again; nothing "went wrong inside qKVM".
        assert (reply.status_code, reply.json()["code"]) == (503, "no_stream"), reply.text
        if change == "edit":
            assert admin.get(snap(device)).status_code == 200  # and the next request finds the new connection


def test_requests_waiting_for_a_connection_do_not_go_out_once_the_kvm_is_retired(fake: FakeKvm) -> None:
    async def run() -> None:
        device = KvmDevice(spec(fake.url))
        await device.snapshot(640)  # signed in, and the status is known
        fake.state.stall = 30
        before = fake.state.requests
        asking = [asyncio.ensure_future(device._get_result("/api/info", urgent=True)) for _ in range(14)]
        # Eight are with the KVM, six wait for one of the eight connections. (Waited for: after a fixed 0.4 s a busy
        # computer had only seven there, and the eighth, on its way already, reached the KVM after the count was taken.)
        for _ in range(3000):
            if fake.state.requests - before >= 8:
                break
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.2)  # (and a moment for a ninth, which must not come)
        reached = fake.state.requests
        assert reached - before == 8, f"{reached - before} requests reached the KVM, of fourteen over eight connections"
        await device.close()
        fake.state.stall = 0  # the eight are let go: connections come free
        answers = await asyncio.gather(*asking, return_exceptions=True)
        await asyncio.sleep(0.4)
        assert [getattr(answer, "code", answer) for answer in answers] == ["no_stream"] * 14  # all told to ask again
        assert fake.state.requests == reached  # and none of the six went out to the KVM after all

    asyncio.run(run())


def test_a_retired_client_saves_no_certificate(tmp_path: Path) -> None:
    device = FakeKvm(tls_dir=tmp_path / "cert").start()
    try:

        async def run() -> None:
            core = Core(tmp_path / "data")
            core.vault.create(PASSWORD)
            saves = 0

            async def save() -> None:
                nonlocal saves
                saves += 1

            manager = DeviceManager(core, save)
            record = DeviceRecord(id="ab12", name="KVM", url=device.url)
            core.store.devices.append(record)
            manager.load()
            first = manager.devices["ab12"]

            # The KVM is moved to another address while the first client is still about to look at its certificate.
            moved = DeviceRecord(id="ab12", name="KVM", url="https://127.0.0.1:9")
            core.store.devices[0] = moved
            await manager.replace(moved)
            assert (await first._tls_context()) is not None  # it looks, and trusts what it sees for itself
            assert first.spec.cert_pem and moved.cert_pem is None and saves == 0  # but that goes nowhere

            # And one that is not retired, but whose record no longer says what it was made for, saves nothing either.
            assert first.on_pin is not None
            await first.on_pin(first.spec.cert_pem)
            assert moved.cert_pem is None and saves == 0
            await manager.close()

        asyncio.run(run())
    finally:
        device.stop()


def test_a_request_parked_by_an_account_that_was_then_removed_changes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(server, "BODY_TIMEOUT", 5.0)
    with LiveWall(tmp_path) as live, httpx.Client(base_url=live.url, headers=CSRF, timeout=10) as admin:
        assert admin.post("/api/v1/setup", json={"password": PASSWORD}).status_code == 200
        created = admin.post("/api/v1/users", json={"name": "anna", "role": "admin", "password": OTHER})
        assert created.status_code == 201
        with httpx.Client(base_url=live.url, headers=CSRF, timeout=10) as anna:
            assert anna.post("/api/v1/login", json={"name": "anna", "password": OTHER}).status_code == 200
            cookie = "; ".join(f"{name}={value}" for name, value in anna.cookies.items())
        # Anna starts a request that makes a new admin, and holds the last of it back.
        body = json.dumps({"name": "mallory", "role": "admin", "password": OTHER}).encode()
        head = (
            "POST /api/v1/users HTTP/1.1|Host: 127.0.0.1|X-QKVM: 1|Content-Type: application/json|"
            f"Cookie: {cookie}|Content-Length: {len(body)}||"
        ).replace("|", chr(13) + chr(10))
        parked = socket.create_connection(("127.0.0.1", live.port))
        parked.sendall(head.encode() + body[:-1])
        time.sleep(0.3)
        assert admin.delete(f"/api/v1/users/{created.json()['user']['id']}").status_code == 200
        parked.sendall(body[-1:])  # ...and sends it once her account is gone
        parked.settimeout(8)
        assert parked.recv(32).startswith(b"HTTP/1.1 401")
        parked.close()
        assert [user["name"] for user in admin.get("/api/v1/users").json()["users"]] == ["admin"]


def test_a_slow_kvm_being_added_does_not_hold_up_other_changes(tmp_path: Path, fake: FakeKvm) -> None:
    fake.state.slow_login = 1.5
    with wall(tmp_path) as admin:
        other = visitor(admin, 50061)
        assert other.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
        with ThreadPoolExecutor(max_workers=1) as pool:
            adding = pool.submit(admin.post, "/api/v1/devices", json={"url": fake.url, "password": "secret"})
            wait_until(lambda: fake.state.logins == 1, "the KVM was never contacted")
            began = time.monotonic()
            assert other.put("/api/v1/alerts", json={"enabled": False}).status_code == 200
            assert time.monotonic() - began < 1.0  # at once, not when the KVM has finally answered
            assert adding.result(timeout=10).status_code == 201


@pytest.mark.parametrize("meanwhile", ["demoted", "removed"])
def test_an_account_that_lost_its_rights_while_a_kvm_was_slow_adds_nothing(tmp_path: Path, fake: FakeKvm, meanwhile: str) -> None:
    fake.state.slow_login = 1.0
    with wall(tmp_path) as admin:
        anna = account(admin, "anna", "admin")
        hers = browser(admin, "anna", port=50063)
        with ThreadPoolExecutor(max_workers=1) as pool:
            adding = pool.submit(hers.post, "/api/v1/devices", json={"url": fake.url, "password": "secret"})
            wait_until(lambda: fake.state.logins == 1, "the KVM was never contacted")
            if meanwhile == "demoted":
                assert admin.put(f"/api/v1/users/{anna}", json={"name": "anna", "role": "viewer"}).status_code == 200
            else:
                assert admin.delete(f"/api/v1/users/{anna}").status_code == 200
            reply = adding.result(timeout=10)
        # Allowed when the request came in, no longer allowed when it was time to change something.
        assert reply.status_code == (403 if meanwhile == "demoted" else 401), reply.text
        assert admin.get("/api/v1/wall").json()["devices"] == []
        assert json.loads((tmp_path / "qkvm.json").read_text())["devices"] == []


def test_the_same_kvm_added_twice_at_once_ends_up_on_the_wall_once(tmp_path: Path, fake: FakeKvm) -> None:
    fake.state.slow_login = 0.5  # long enough for both to be past "is it on the wall already?"
    with wall(tmp_path) as admin:
        other = visitor(admin, 50062)
        assert other.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
        new = {"url": fake.url, "password": "secret"}
        with ThreadPoolExecutor(max_workers=2) as pool:
            replies = list(pool.map(lambda browser: browser.post("/api/v1/devices", json=new), [admin, other]))
        assert sorted(reply.status_code for reply in replies) == [201, 409]
        assert len(admin.get("/api/v1/wall").json()["devices"]) == 1
        assert len(json.loads((tmp_path / "qkvm.json").read_text())["devices"]) == 1


def test_settings_written_from_many_threads_at_once_stay_whole(tmp_path: Path) -> None:
    store = Store(tmp_path / "qkvm.json")
    failures: list[BaseException] = []

    def write() -> None:
        try:
            for _ in range(25):
                store.write(store.snapshot())
        except BaseException as ex:
            failures.append(ex)

    threads = [threading.Thread(target=write) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert failures == []
    assert Store(tmp_path / "qkvm.json").server.port == store.server.port  # and what is on disk can be read


def test_a_certificate_trusted_on_first_contact_is_saved(tmp_path: Path) -> None:
    device = FakeKvm(tls_dir=tmp_path / "cert")  # has its address, but is not switched on yet

    def saved() -> str | None:
        return json.loads((tmp_path / "data" / "qkvm.json").read_text())["devices"][0]["cert_pem"]  # type: ignore[no-any-return]

    with wall(tmp_path / "data") as client:
        added = add(client, device.url, force=True)
        assert client.get("/api/v1/wall").json()["devices"][0]["fingerprint"] is None
        device.start()
        try:
            wait_until(lambda: client.get(snap(added)).status_code == 200, "no picture once the KVM was on", timeout=30)
            # Trusted as it was seen for the first time, and written down without the tiles waiting for the disk.
            wait_until(lambda: saved() is not None, "the certificate was not saved")
            assert client.get("/api/v1/wall").json()["devices"][0]["fingerprint"] == kvm.fingerprint(saved() or "")
        finally:
            device.stop()


# --- several viewers ------------------------------------------------------------------


def test_viewers_that_refresh_slowly_share_a_picture(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as client:
        device = add(client, fake.url)
        for _ in range(4):  # four browsers whose turn to refresh comes within the same second
            assert client.get(snap(device), params={"age": 0.8}).status_code == 200
        assert len(fake.state.snapshot_queries) == 1  # the KVM was asked once
        assert client.get(snap(device)).status_code == 200  # the enlarged view wants a picture of its own
        assert len(fake.state.snapshot_queries) == 2
        assert client.get(snap(device), params={"age": -1}).status_code == 422
        assert kvm.share_window(3600) == kvm.MAX_SHARED_AGE  # however long is asked for, a picture is never that stale


def test_a_viewer_on_a_slow_link_is_not_handed_its_own_last_picture(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as client:
        device = add(client, fake.url)
        fake.state.slow_snapshot = 0.3  # the KVM is far away
        began = time.monotonic()
        assert client.get(snap(device), params={"age": 0.4}).status_code == 200
        time.sleep(max(0.0, began + 0.5 - time.monotonic()))  # the tile's next turn, half a second after the first
        assert client.get(snap(device), params={"age": 0.4}).status_code == 200
        # The first picture arrived 0.2 s ago but was asked for 0.5 s ago: too old to pass off as a new one.
        assert len(fake.state.snapshot_queries) == 2


def test_a_kvm_that_is_slow_with_its_picture_keeps_no_tile_waiting(
    tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = threading.Event()
    fetching: list[KvmDevice] = []
    original = KvmDevice._fetch_snapshot

    async def held(device: KvmDevice, size: str, asked: float) -> kvm.Snapshot:
        fetching.append(device)
        assert await asyncio.to_thread(release.wait, 20), "picture was never released"
        return await original(device, size, asked)

    monkeypatch.setattr(KvmDevice, "_fetch_snapshot", held)
    with wall(tmp_path) as client:
        try:
            device = add(client, fake.url)
            assert client.get("/api/v1/status").json()[device]["state"] == "online"
            monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 0.3)
            waiting = AsyncMock(wraps=asyncio.wait)
            with monkeypatch.context() as patch:
                patch.setattr(asyncio, "wait", waiting)
                reply = client.get(snap(device))
            assert (reply.status_code, reply.json()["code"]) == (503, "no_stream")
            picture_waits = [call for call in waiting.await_args_list if any(
                task.get_coro().__qualname__ == "KvmDevice._fetch" for task in call.args[0]
            )]
            assert len(picture_waits) == 1
            assert 0 < picture_waits[0].kwargs["timeout"] <= 0.3
            assert len(fetching) == 1
            machine = fetching[0]
            pending = next(iter(machine._fetching.values()))
            assert not pending.done()
            # Windows timers may wake just before the monotonic deadline. Ensure
            # it has expired before checking that later callers do not wait again.
            deadline = next(iter(machine._fetching_since.values())) + kvm.PICTURE_PATIENCE
            wait_until(lambda: time.monotonic() >= deadline, "picture budget did not expire")
            waiting.reset_mock()
            with monkeypatch.context() as patch:
                patch.setattr(asyncio, "wait", waiting)
                assert client.get(snap(device)).status_code == 503
            assert not any(
                task.get_coro().__qualname__ == "KvmDevice._fetch"
                for call in waiting.await_args_list for task in call.args[0]
            )
            assert not pending.done()
            assert len(fetching) == 1
            release.set()
            wait_until(pending.done, "released picture did not finish")
            assert client.get(snap(device)).status_code == 200
            assert len(fake.state.snapshot_queries) == 1
            assert client.get(snap(device)).status_code == 200
            assert len(fake.state.snapshot_queries) == 2
        finally:
            release.set()


def test_a_tile_whose_turn_came_late_is_not_handed_its_own_last_picture(fake: FakeKvm) -> None:
    async def run() -> None:
        device = KvmDevice(spec(fake.url))
        try:
            await device.snapshot(640)
            # A tile that refreshes every half second and settles for a picture up to 0.4 s old.
            fake.state.slow_snapshot = 0.65
            began = time.monotonic()
            other = asyncio.ensure_future(device.snapshot(640))  # somebody else's request, slow to be answered
            await asyncio.sleep(0.1)
            fake.state.slow_snapshot = 0
            await asyncio.sleep(began + 0.45 - time.monotonic())
            asked = time.monotonic()
            first = await device.snapshot(640, 0.4)  # waits 0.2 s for its turn, then has the KVM asked
            assert first is not await other
            await asyncio.sleep(asked + 0.5 - time.monotonic())
            # Its next turn: half a second after it asked, though only 0.3 s after the KVM was asked for it.
            assert await device.snapshot(640, 0.4) is not first
        finally:
            await device.close()

    asyncio.run(run())


def test_a_picture_from_before_the_kvm_was_switched_is_not_kept_for_others(tmp_path: Path, fake: FakeKvm) -> None:
    fake.state.ports = [(32, 74, 135), (135, 74, 32)]
    with wall(tmp_path) as client:
        device = add(client, fake.url)
        other = visitor(client, 50064)
        assert other.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
        wait_until(lambda: (client.get("/api/v1/status").json()[device].get("ports") or {}).get("list"), "no ports listed")
        fake.state.slow_snapshot = 0.6
        with ThreadPoolExecutor(max_workers=1) as pool:
            before = pool.submit(other.get, snap(device), params={"age": 5})
            wait_until(lambda: len(fake.state.snapshot_queries) == 1, "the picture was never asked for")
            fake.state.slow_snapshot = 0
            assert client.post(f"/api/v1/devices/{device}/actions", json={"action": "port", "port": 1}).status_code == 200
            assert before.result(timeout=10).status_code == 200
        # Whoever asked before the switch got what was there. A viewer asking now gets a picture taken now,
        # however old a one it would settle for.
        assert client.get(snap(device), params={"age": 5}).status_code == 200
        assert len(fake.state.snapshot_queries) == 2


def test_pictures_are_let_go_of_once_nobody_is_watching(fake: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    async def run() -> None:
        device = KvmDevice(spec(fake.url))
        try:
            await device.snapshot(640)
            device.tidy()
            assert len(device._frames) == 1  # somebody looked a moment ago: kept, for the next viewer to share
            monkeypatch.setattr(kvm, "KEEPALIVE_IDLE", 0)
            device.tidy()
            assert device._frames == {}
        finally:
            await device.close()
        with pytest.raises(KvmError) as retired:  # and once retired, it starts nothing new
            await device.snapshot(640)
        assert retired.value.code == "no_stream"

    asyncio.run(run())


def test_a_picture_that_was_let_go_of_is_gone(fake: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    # "Need not be kept" has to mean that the memory is free again. The request that fetched a picture, long
    # over, still held it: up to four sizes of the last frame of every device, for as long as the program ran.
    import gc
    import weakref

    async def run() -> None:
        device = KvmDevice(spec(fake.url))
        try:
            kept = weakref.ref(await device.snapshot(640))
            monkeypatch.setattr(kvm, "KEEPALIVE_IDLE", 0)
            device.tidy()
            gc.collect()
            assert kept() is None
            assert (await device.snapshot(640)).data  # and the next one who looks gets a picture as before
        finally:
            await device.close()

    asyncio.run(run())


def test_a_sign_in_that_fails_for_another_reason_than_the_password_is_not_repeated_at_every_look(
    fake: FakeKvm, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Something at the KVM's address answers the sign-in with an error of its own (the KVM's software is
    # broken, or it is not the KVM). A rejected password is not sent again for a minute; this used to be
    # sent again with every refresh of every tile, the saved password with it, for as long as anybody looked.
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    fake.state.login_status = 500

    async def run() -> None:
        device = KvmDevice(spec(fake.url))
        try:
            for _ in range(6):
                with pytest.raises(KvmError) as failed:
                    await device.snapshot(640)
                # (Said as what it is from the first: the KVM is there, and signs nobody in. As the error it
                # answered, its tile was "offline" for as long as the next try was held back.)
                assert failed.value.code == "no_sign_in" and "500" in failed.value.message
            assert fake.state.logins == 1
            # Later, and mended meanwhile: it is tried again, and works. (How long it is left alone is kept
            # beside the connections since: a connection made anew does not send the password again at once.)
            fake.state.login_status = 200
            that_long_has_passed(device)
            assert (await device.snapshot(640)).data and fake.state.logins == 2
        finally:
            await device.close()

    asyncio.run(run())


# --- answers that never end -----------------------------------------------------------


class Drip(httpx.AsyncByteStream):
    """An answer that arrives a byte at a time, for ever: each piece comes long before any wait for it runs out."""

    async def __aiter__(self) -> AsyncIterator[bytes]:
        while True:
            await asyncio.sleep(0.02)
            yield b"x"


def test_an_answer_that_trickles_in_for_ever_is_given_up_on() -> None:
    async def run() -> None:
        transport = httpx.MockTransport(lambda request: httpx.Response(200, stream=Drip()))
        async with httpx.AsyncClient(transport=transport, timeout=httpx.Timeout(5.0, connect=0.1, pool=0.1)) as client:
            began = time.monotonic()
            with pytest.raises(KvmError) as slow:
                await bounded(client, client.build_request("GET", "http://kvm.test/"), 1_000_000, within=0.9)
            assert slow.value.code == "timeout"
            assert 0.8 < time.monotonic() - began < 3

    asyncio.run(run())


def test_the_time_for_an_answer_follows_from_the_waits_of_its_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "TRANSFER_TIME", 1.0)

    async def run() -> None:
        transport = httpx.MockTransport(lambda request: httpx.Response(200, stream=Drip()))
        async with httpx.AsyncClient(transport=transport) as client:
            waits = httpx.Timeout(0.2, connect=0.1, pool=0.1)
            began = time.monotonic()
            with pytest.raises(KvmError):
                await bounded(client, client.build_request("GET", "http://kvm.test/", timeout=waits), 1_000_000)
            assert 1.2 < time.monotonic() - began < 3  # 0.1 to connect + 0.2 for it to begin + 1.0 to arrive

            # Never less than getting a connection can take: the clock must not run out during that (see bounded).
            waits = httpx.Timeout(0.2, connect=0.3, pool=0.3)
            began = time.monotonic()
            with pytest.raises(KvmError):
                await bounded(client, client.build_request("GET", "http://kvm.test/", timeout=waits), 1_000_000, within=0.01)
            assert 1.0 < time.monotonic() - began < 3  # 0.3 for a free connection + 0.3 to connect + the margin

    asyncio.run(run())


# --- alerts -----------------------------------------------------------------------------


def test_an_alert_is_sent_again_when_the_service_was_away(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(alerts, "CHECK_EVERY", 0.05)
    monkeypatch.setattr(alerts, "RETRY_AFTER", (0.05, 0.05, 0.05))
    inbox = Inbox(fail_first=2)
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url, name="NAS")
            admin.put("/api/v1/alerts", json={"enabled": True, "webhook": inbox.url})
            assert admin.get(snap(device)).status_code == 200
            baseline()
            fake.state.signal = False
            wait_until(lambda: len(inbox.received) == 3, "the alert was not tried again")
            assert inbox.titles() == ["NAS has no video signal"] * 3  # refused twice, taken the third time
            wait_until(lambda: admin.get("/api/v1/alerts").json()["last_error"] is None, "the delivery was not noted")
            assert admin.get("/api/v1/alerts").json()["last_sent"] is not None
    finally:
        inbox.close()


def test_an_alert_the_service_refuses_is_not_sent_over_and_over(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(alerts, "CHECK_EVERY", 0.05)
    monkeypatch.setattr(alerts, "RETRY_AFTER", (0.05, 0.05, 0.05))
    inbox = Inbox(status=404)  # the address is wrong: asking again will not make it right
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url, name="NAS")
            admin.put("/api/v1/alerts", json={"enabled": True, "webhook": inbox.url})
            assert admin.get(snap(device)).status_code == 200
            baseline()
            fake.state.signal = False
            wait_until(lambda: "HTTP 404" in (admin.get("/api/v1/alerts").json()["last_error"] or ""), "the refusal was not noted")
            time.sleep(0.5)
            assert len(inbox.received) == 1
    finally:
        inbox.close()


def test_alerts_wait_in_line_and_the_oldest_give_way() -> None:
    async def run() -> None:
        outbox = alerts.Outbox(lambda: None, lambda problem: None)
        for number in range(alerts.MAX_WAITING + 5):
            outbox.put(alerts.Alert("offline", f"KVM {number}", "", "offline", "online", f"KVM {number} is offline", ""))
        assert outbox._waiting.qsize() == alerts.MAX_WAITING
        assert outbox._waiting.get_nowait().device == "KVM 5"
        await outbox.close()

    asyncio.run(run())


# --- the rest ---------------------------------------------------------------------------


def test_the_trusted_authorities_are_read_once_and_checked_against() -> None:
    async def run() -> None:
        for trusted in (kvm.system_context, kvm.public_context):
            first, second = await asyncio.gather(trusted(), trusted())
            assert first is second is await trusted()
            assert first.check_hostname and first.verify_mode.name == "CERT_REQUIRED"
        # Two lists, as before they were read ahead of time: the system's for a KVM, the HTTP library's for
        # services on the internet. Neither is widened by the other.
        assert await kvm.system_context() is not await kvm.public_context()
        assert (await kvm.public_context()).cert_store_stats()["x509_ca"] > 50  # something to check against

    asyncio.run(run())
    assert kvm.unverified_context().verify_mode.name == "CERT_NONE"  # the one that is for looking only


def test_services_on_the_internet_are_checked_against_the_list_the_admin_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # SSL_CERT_FILE narrows what the alert address and the update server are checked against, as it always did.
    from tests.fake_kvm import make_device_certificate

    cert, _ = make_device_certificate(tmp_path)
    monkeypatch.setenv("SSL_CERT_FILE", str(cert))
    narrowed = httpx.create_ssl_context()  # what public_context is made by, the first time it is asked for
    assert narrowed.cert_store_stats()["x509_ca"] == 1


def test_raising_the_allowance_for_open_files_never_fails() -> None:
    cli.raise_file_limit()  # whatever the system says: more if it may, as before if it may not


def test_a_log_line_does_not_wait_for_whatever_it_is_written_to(tmp_path: Path) -> None:
    # A warning is written from wherever in the program something goes wrong, which is the one thread that
    # serves every browser and looks at every device. On Windows, a click into the window qKVM was started
    # in stops everything written to that window until a key is pressed: the wall with it, every tile.
    import logging

    cli.setup_logging(tmp_path, "info")
    try:
        logger = logging.getLogger("qkvm")
        assert [type(handler).__name__ for handler in logger.handlers] == ["QueueHandler"]

        class Stuck(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                time.sleep(1.0)

        cli._listener.handlers = (*cli._listener.handlers, Stuck())  # type: ignore[union-attr]
        began = time.monotonic()
        for number in range(5):
            logger.warning("device %d went away", number)
        assert time.monotonic() - began < 0.3
    finally:
        cli.stop_logging()  # writes what is still waiting
    written = (tmp_path / "qkvm.log").read_text(encoding="utf-8")
    assert "device 0 went away" in written and "device 4 went away" in written
