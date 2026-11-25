"""What the last look at 0.4.0's hold round, merged, found (review-final-hold): a status of many tiles that walked the list of
tiles once per tile, a several-inputs mark carried over a trusted certificate that was never let go of, a switch read cut
off by a lock taken for a break of kvmd's word, and the Windows quieting of resets left to the starter alone."""

from __future__ import annotations

import ast
import asyncio
import contextlib
import time
from pathlib import Path
from typing import Any

import pytest

from qkvm import core as core_module
from qkvm import kvm, update, vault
from qkvm.kvm import SEVERAL_SEEN, DeviceSpec, KvmDevice, KvmError, _several_mark, several_mark
from qkvm.store import DeviceRecord
from tests.fake_kvm import FakeKvm, FakeState
from tests.test_wall import wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def test_a_status_of_many_tiles_does_not_walk_the_list_of_tiles_once_per_tile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (Each row's `target` was taken by store.device(), which walks the list: a status of 10,000 tiles took 1.6 s on the event
    # loop, every 4 s for every page open, where it took 0.14 s.)
    managers: list[Any] = []
    original = core_module.DeviceManager.__init__

    def keep(self: Any, *args: Any, **kwargs: Any) -> None:
        original(self, *args, **kwargs)
        managers.append(self)

    monkeypatch.setattr(core_module.DeviceManager, "__init__", keep)
    with wall(tmp_path) as client:
        manager = managers[-1]
        store = client.core.store  # type: ignore[attr-defined]
        for i in range(200):
            # (A kind this version has no driver for: its status asks nothing of any address.)
            record = DeviceRecord(id=f"{i:08x}", name=f"m{i}", url=f"https://10.0.{i // 250}.{i % 250 + 1}", kind="zzz")
            store.devices.append(record)
            manager._install(manager.client(record), record)
        looked: list[str] = []
        by_id = store.device

        def counted(device_id: str) -> Any:
            looked.append(device_id)
            return by_id(device_id)

        monkeypatch.setattr(store, "device", counted)
        reply = client.get("/api/v1/status")
        assert reply.status_code == 200 and len(reply.json()) == 200
        assert len(looked) < 10, f"a status of 200 tiles looked up a tile's record {len(looked)} times, walking the list each time"


def test_a_mark_carried_over_a_trusted_certificate_is_let_go_of_as_any(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "NO_SWITCH_LETS_GO", 0.3)
    SEVERAL_SEEN.clear()
    url = "https://127.0.0.1:1"
    before = KvmDevice(DeviceSpec("t1", "rack kvm", url, "admin", "secret", tls="pinned", cert_pem="OLD"))
    before._saw_several()
    after = KvmDevice(DeviceSpec("t1", "rack kvm", url, "admin", "secret", tls="pinned", cert_pem="NEW"))
    after.takes_over(before)  # (a certificate trusted anew at the same address: carried, fail closed)
    before.forget_several()  # (DeviceManager.adopt: the old mark goes)
    assert after.has_shown_several()
    assert several_mark(url, "kvmd", "pinned", "NEW", "", "") in SEVERAL_SEEN, "the mark carried over is not kept as the new one's"
    for _ in range(8):  # (kvmd's word of no switch at every read from now on)
        after._heard_switch(True)
        time.sleep(0.1)
    assert not after.has_shown_several(), "a mark carried over a trust was never let go of in this run"


def test_a_switch_read_cut_off_by_a_lock_does_not_start_the_ten_minutes_again() -> None:
    SEVERAL_SEEN.clear()
    switch = FakeKvm(FakeState(ports=[(150, 80, 40), (40, 110, 130)])).start()

    async def run() -> None:
        spec = DeviceSpec("t3", "rack", switch.url, "admin", "secret")
        mark = _several_mark(spec)
        client = KvmDevice(spec)
        try:
            await client._switch_said()  # (two inputs listed: held to several)
            client._saw_several()
            switch.state.switch_reply = "unavailable"  # (kvmd's word of no switch from now on)
            for _ in range(3):
                await client._switch_said()
                await asyncio.sleep(0.2)
            held = SEVERAL_SEEN._runs.get(mark)
            assert held is not None
            switch.state.switch_reply = "trickle"  # (a look's read under way as the wall locks: its client closed under it)
            reading = asyncio.ensure_future(client._switch_said())
            await asyncio.sleep(0.6)
        finally:
            await client.close()
        with contextlib.suppress(KvmError):
            await reading
        assert SEVERAL_SEEN._runs.get(mark) == held, "a read cut off by the lock was taken for a break: the ten minutes start again"

    try:
        asyncio.run(run())
    finally:
        switch.state.switch_reply = ""
        switch.stop()


def test_the_quieting_of_resets_is_put_on_once_and_by_the_wall_too(monkeypatch: pytest.MonkeyPatch) -> None:
    # (A wall that came to 0.4.0 from inside the app runs the starter it was installed with: the wall itself puts the quieting
    # on, on Windows, as it does malloc's settings. Put on twice, by both, it is one.)
    from asyncio import base_events, proactor_events

    from qkvm import __main__ as starter
    from qkvm import _resets

    loop = proactor_events.BaseProactorEventLoop
    # (The loop's own handler, not the one on the class now: in a run of the whole suite in one process, an earlier
    # test's wall has put the quieting on already.)
    plain = base_events.BaseEventLoop.default_exception_handler
    assert not getattr(plain, _resets.MARK, False)
    for first, then in ((starter.quiet_resets, _resets.quiet_resets), (_resets.quiet_resets, starter.quiet_resets)):
        monkeypatch.setattr(loop, "default_exception_handler", plain)
        first()
        once = loop.default_exception_handler
        assert once is not plain
        first()
        then()
        assert loop.default_exception_handler is once, "put on twice, the quieting wrapped itself"
    source = (Path(starter.__file__).parent / "cli.py").read_text(encoding="utf-8")
    main = next(node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef) and node.name == "main")
    calls = [node for node in ast.walk(main) if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "quiet_resets"]
    assert calls, "the wall does not put the quieting of resets on itself (a wall updated from inside the app has a starter without it)"
