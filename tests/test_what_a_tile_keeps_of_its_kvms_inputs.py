"""What a tile keeps of its KVM's inputs (DeviceRecord.several_inputs_at, SEVERAL_SEEN), driver and manager alone: what its
load costs, a removal, a trust, the empty state (the narrow re-reviews of HB's second and third rounds). Through a wall: in
test_keys_for_one_input_go_only_on_the_kvms_own_word.py."""

from __future__ import annotations

import asyncio
import dataclasses
from types import SimpleNamespace
from typing import Any

import pytest

from qkvm import kvm
from qkvm.core import DeviceManager, several_mark_of
from qkvm.store import DeviceRecord, Store
from tests.fake_kvm import FakeKvm, FakeState


def test_the_clients_of_a_wall_are_made_without_looking_each_tile_up_again(monkeypatch: pytest.MonkeyPatch) -> None:
    # (L5.) Making the clients of a wall's tiles (an unlock, a start) looked each tile's record up in the list of all of them
    # once more, to see what it keeps of its inputs: a walk of the list per tile, 1.4 s on the event loop for 10,000. Each is
    # given its record.
    store = Store.__new__(Store)
    store.devices = [DeviceRecord(id=f"{i:08x}", name=f"kvm {i}", url=f"http://10.0.{i // 250}.{i % 250}") for i in range(2000)]
    looked_up: list[str] = []
    found = Store.device

    def device(self: Store, device_id: str) -> Any:
        looked_up.append(device_id)
        return found(self, device_id)

    monkeypatch.setattr(Store, "device", device)
    core = SimpleNamespace(vault=SimpleNamespace(unlocked=True, read=lambda *given: ""), store=store, served=None)

    async def save() -> None:
        return None

    manager = DeviceManager(core, save)  # type: ignore[arg-type]
    manager.load()
    assert len(manager.devices) == 2000
    assert looked_up == [], f"{len(looked_up)} tiles looked up again"


def a_manager(records: list[DeviceRecord]) -> DeviceManager:
    store = Store.__new__(Store)
    store.devices = records
    core = SimpleNamespace(vault=SimpleNamespace(unlocked=True, read=lambda *given: ""), store=store, served=None)

    async def save() -> None:
        return None

    return DeviceManager(core, save)  # type: ignore[arg-type]


def test_the_empty_state_says_at_least_its_units_or_its_ports() -> None:
    # (L4.) Taken as tolerant of what a stock kvmd may leave out, {"model": {}} was its word of no switch, with input 2 named on
    # screen too. kvmd 4.226 gives both its units and its ports: one of them at least is to be said.
    assert not kvm._no_switch_there({"model": {}})
    assert not kvm._no_switch_there({"model": {}, "summary": {"active_port": 1}})
    assert kvm._no_switch_there({"model": {"units": [], "ports": []}, "summary": {"active_port": 1, "synced": True}})
    assert kvm._no_switch_there({"model": {"ports": []}})
    assert kvm._no_switch_there({"model": {"units": []}, "summary": {"synced": None}})
    assert not kvm._no_switch_there({"model": {"units": [], "ports": None}})
    assert not kvm._no_switch_there({"summary": {"active_port": -1}})


def test_a_removed_tiles_look_under_way_puts_back_no_mark() -> None:
    # (The narrow re-review of HB's third round, L2.) A tile removed lets go of its mark before its client is closed, which
    # waits for its live lines to let go: a look of that client whose switch read answered meanwhile put the mark back, and a
    # tile added at that address was held to several inputs.
    switch = FakeKvm(FakeState(ports=[(150, 80, 40), (40, 110, 130)])).start()

    async def asked() -> None:
        device = kvm.KvmDevice(kvm.DeviceSpec("0", "rack 1", switch.url, "admin", "secret"))
        try:
            assert await device._read_ports() is not None and device.has_shown_several()
            mark = kvm._several_mark(device.spec)
            switch.state.slow["/api/switch"] = 0.6
            look = asyncio.ensure_future(device._read_ports())
            await asyncio.sleep(0.3)  # (its switch being read)
            device.forget_several()  # (as DeviceManager.take and remove do, before the client is closed)
            await look
            assert mark not in kvm.SEVERAL_SEEN, "the removed client's look put its mark back"
        finally:
            switch.state.slow.clear()
            await device.close()

    try:
        asyncio.run(asked())
    finally:
        switch.stop()


@pytest.mark.parametrize("checked_before", ["pinned", "system", "insecure"])
def test_a_certificate_pinned_by_a_trust_keeps_the_mark_whatever_check_the_tile_had(checked_before: str) -> None:
    # (The narrow re-review of HB's third round, L3.) A trust pins the certificate shown (tls "pinned"): from the system's list
    # or no check before, the client made anew was taken for one of a single input while its switch was not up. A trust that
    # pins carries the mark, whatever check came before (another check after a pin, a machine or an identity remembered anew
    # are still another KVM: test_a_power_light_that_is_not_wired).
    async def asked() -> None:
        record = DeviceRecord(id="k1", name="rack 1", url="https://127.0.0.1:9", tls=checked_before, cert_pem="OLD" if checked_before == "pinned" else None)
        record.several_inputs_at = several_mark_of(record)
        manager = a_manager([record])
        manager.load()
        assert manager.devices["k1"].several_inputs()
        trusted = dataclasses.replace(record, cert_pem="NEW", tls="pinned")  # (as the trust makes it)
        manager.core.store.devices[0] = trusted
        await manager.replace(trusted)
        try:
            assert trusted.several_inputs_at == several_mark_of(trusted), "the record let go of it"
            assert manager.devices["k1"].several_inputs()
        finally:
            await manager.close()

    asyncio.run(asked())
