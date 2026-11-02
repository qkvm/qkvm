"""Where a server's controller closes an idle connection within moments, its tile does not make a line ready ahead that the
controller closes before it is used (the final review of 0.2.1, the drivers half: review-final-drivers\\probes\\p_idle.py).

Each line a tile sends its session's token on is compared as it is made: its controller's open root read on it first. Where
a request took the last line that waited, another was made ready beside it; a controller that closes connections idle for
a few seconds closed that one before the next look, and every look and every press read the root twice (on a controller
whose root takes 4 s: 4 s a look where 0.2.0 took none). Once the controller closed a line kept ready before it was used,
none is made ahead: such a controller pays one root read for each look and press.
"""

from __future__ import annotations

import asyncio
import hashlib

import httpx
import pytest

from qkvm import redfish
from qkvm.kvm import DeviceSpec
from tests.fake_redfish import BmcState, FakeBmc

A_SYSTEM, A_ROOT = "4c4c4544-0042-3510-8054-b9c04f4a3532", "1a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d"
A_MARK = "server:" + hashlib.sha256(A_SYSTEM.lower().encode()).hexdigest()[:32] + hashlib.sha256(A_ROOT.lower().encode()).hexdigest()[:32]


def test_a_controller_that_closes_idle_connections_soon_is_not_made_a_line_ahead_at_every_look(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(redfish.RedfishDevice, "WAITS", httpx.Timeout(5.0))
    state = BmcState(uuid=A_SYSTEM, root_uuid=A_ROOT, keeps_idle=0.5)
    bmc = FakeBmc(state).start()
    roots: list[int] = []

    async def run() -> None:
        device = redfish.RedfishDevice(DeviceSpec(id="ab12", name="db-01", base_url=bmc.url, username="admin", password="secret", kind="redfish", tls="insecure", machine=A_MARK))
        try:
            assert (await device._read_status())["state"] == "online"
            for _ in range(4):
                await asyncio.sleep(1.2)  # (the controller closes what sat idle half a second)
                before = state.roots_unsigned
                assert (await device._read_status())["state"] == "online"
                await asyncio.sleep(0.2)  # (a line made ahead, where one is, is made by now)
                roots.append(state.roots_unsigned - before)
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        bmc.stop()
    assert roots[-2:] == [1, 1], f"roots read a look: {roots}"
