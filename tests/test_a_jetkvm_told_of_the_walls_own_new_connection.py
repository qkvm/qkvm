"""A JetKVM's "otherSessionConnected" on a connection of the wall's that is no longer its own (W1b's third reviewer, low 1),
and that reviewer's other lows (register row 18).

A connection of the wall's that is slow to close hears that another viewer took the JetKVM: the wall's own new
connection. The wall took that as the JetKVM's own page having taken it, and said "in use" of a JetKVM it was watching,
until somebody clicked "Show here".
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from qkvm import jetkvm, kvm
from qkvm.kvm import DeviceSpec
from tests.fake_jetkvm import FakeJetKvm, JetState

TAKEN = json.dumps({"jsonrpc": "2.0", "method": "otherSessionConnected", "params": None})


def test_an_old_connection_told_of_the_walls_own_new_one_leaves_the_jetkvm_as_it_is() -> None:
    async def run() -> None:
        device = jetkvm.JetKvmDevice(DeviceSpec("jet", "A JetKVM", "http://127.0.0.1:18901", "", "", kind="jetkvm"))
        old, new = jetkvm._Session(), jetkvm._Session()
        device._session = new  # (the wall's connection now: the old one is on its way out)
        device._on_message(old, TAKEN)
        assert old.taken, "the old connection is no viewer any more: nothing more of ours goes over it"
        assert not device._displaced and not new.taken, "the wall's own new connection was taken for somebody else's"
        assert (device._status or {}).get("state") != "busy", device._status
        # Said on the connection that is the wall's own: somebody else has the JetKVM.
        device._on_message(new, TAKEN)
        assert new.taken and device._displaced
        assert (device._status or {}).get("state") == "busy"

    asyncio.run(run())


def test_an_old_connection_told_so_after_the_new_one_is_over_says_the_jetkvm_is_in_use() -> None:
    # (The first review of this track, a note.) Where the wall's newest connection has ended already (failed), what the old
    # one hears is not the wall's own doing: it is said as ever.
    async def run() -> None:
        device = jetkvm.JetKvmDevice(DeviceSpec("jet", "A JetKVM", "http://127.0.0.1:18901", "", "", kind="jetkvm"))
        old, new = jetkvm._Session(), jetkvm._Session()
        device._session = new
        new.done.set()
        device._on_message(old, TAKEN)
        assert old.taken and device._displaced

    asyncio.run(run())


# --- the third reviewer's lows of W1b (register row 18) --------------------------------------------------------------


def test_a_tiles_look_beside_an_alerts_look_is_somebody_watching() -> None:
    # (3) Whether a look is the alerts' (which is nobody watching, and keeps no connection) was told by a count on the whole
    # device: a tile's look that came while an alerts' look was under way was taken for nobody watching too (it did not keep
    # the connection, nor ask again over a connection made anew under it). It is told by the look's own context now.
    jet = FakeJetKvm(JetState()).start()

    async def run() -> None:
        device = jetkvm.JetKvmDevice(kvm.DeviceSpec("j", "jet", jet.url, "", "secret", kind="jetkvm"))
        try:
            await device._connected(urgent=True)
            entered, release = asyncio.Event(), asyncio.Event()
            real = device._refresh_status

            async def slow_refresh() -> None:
                entered.set()
                await release.wait()
                await real()

            device._refresh_status = slow_refresh  # type: ignore[method-assign]
            alerts_look = asyncio.ensure_future(device.probe())
            await entered.wait()  # (the alerts' look is under way)
            device._wanted_at = 0.0
            await device._connected()  # a tile's look, meanwhile
            assert device._wanted_at > 0.0, "a tile's look beside the alerts' was taken for nobody watching"
            release.set()
            await alerts_look
            device._wanted_at = 0.0
            device._refresh_status = real  # type: ignore[method-assign]
            await device.probe()  # (the alerts' own look is still nobody watching)
            assert device._wanted_at == 0.0
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        jet.stop()


def test_a_client_being_retired_does_not_say_the_jetkvm_is_offline() -> None:
    # (5) A client being retired (its tile edited or removed, the wall locking itself) whose look was cut off said the JetKVM
    # was offline: nothing was heard of it. What was known stands, as for a look cut off by a connection made anew.
    jet = FakeJetKvm(JetState()).start()

    async def run() -> dict[str, object]:
        device = jetkvm.JetKvmDevice(kvm.DeviceSpec("j", "jet", jet.url, "", "secret", kind="jetkvm"))
        try:
            await device._refresh_status()
            assert (device._status or {}).get("state") == "online"
            jet.drop()
            while device._session is not None and device._session.live:
                await asyncio.sleep(0.02)
            device._closed = True  # (as close() begins: whatever is under way on it ends)
            return await device._read_status()
        finally:
            await device.close()

    try:
        said = asyncio.run(run())
        assert said["state"] != "offline", said
    finally:
        jet.stop()


def test_show_here_asked_as_a_connection_made_anew_ends_while_the_page_takes_the_viewer_is_not_refused() -> None:
    # (7) "Show here" asked in the moment a connection the wall made anew is ending, and the JetKVM's own page takes the viewer
    # from that connection meanwhile: it was refused with 409 "in use". "Show here" takes the viewer back from that page, as
    # at any other moment.
    jet = FakeJetKvm(JetState()).start()

    async def run() -> None:
        device = jetkvm.JetKvmDevice(kvm.DeviceSpec("j", "jet", jet.url, "", "secret", kind="jetkvm"))
        try:
            session = await device._connected(urgent=True)
            gate = asyncio.Event()
            real = jetkvm.JetKvmDevice._let_go_before_closing

            async def held_end(self: Any, ending: Any, wait: bool) -> None:
                await gate.wait()  # (the end takes its time: the letting go leaving)
                await real(self, ending, wait)

            device._let_go_before_closing = held_end.__get__(device)  # type: ignore[method-assign]
            device._make_anew(session, "a test made it anew")
            resume = asyncio.ensure_future(device.act("resume"))
            await asyncio.sleep(0.3)  # ("Show here" waits for the connection that is ending)
            device._on_message(session, json.dumps({"jsonrpc": "2.0", "method": "otherSessionConnected", "params": None}))
            assert device._displaced  # (its own page took the viewer from the connection that was ending)
            gate.set()
            await asyncio.wait_for(resume, 30)
            assert device._session is not session and device._session is not None and device._session.live
            assert not device._displaced
        finally:
            await device.close()

    try:
        asyncio.run(run())
    finally:
        jet.stop()
