"""A JetKVM's "otherSessionConnected" on a connection of the wall's that is no longer its own (W1b's third reviewer, low 1).

A connection of the wall's that is slow to close hears that another viewer took the JetKVM: the wall's own new
connection. The wall took that as the JetKVM's own page having taken it, and said "in use" of a JetKVM it was watching,
until somebody clicked "Show here".
"""

from __future__ import annotations

import asyncio
import json

from qkvm import jetkvm
from qkvm.kvm import DeviceSpec

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
