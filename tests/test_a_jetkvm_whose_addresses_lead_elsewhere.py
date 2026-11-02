"""The network addresses a JetKVM offers for its video connection (ICE candidates) are tried only where it is reached.

The wall sends connectivity checks (STUN) to every address a JetKVM offers: before this, to whatever it named, anywhere, and a
name ending in .local was looked up with mDNS. Whatever answers at a JetKVM's address (it serves plain HTTP out of its box) could
aim those checks at any host and port it liked. Now an address is tried only where it is one the JetKVM is reached at here: its
host as written, or what its name resolves to (for one on this very computer, this computer's own addresses, which are what it
offers), over UDP, written as an address. A real JetKVM offers the address it is reached at among its own.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
from typing import Any

import aiortc
import pytest

from qkvm import jetkvm, kvm, vault
from qkvm.kvm import DeviceSpec
from tests.fake_jetkvm import FakeJetKvm, JetState

ELSEWHERE = "127.0.0.2"  # (on this computer, nothing listens there: a stand-in for an address that leads anywhere else)
LATE = "127.0.0.3"


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)


def candidate(address: str, port: int = 9, transport: str = "udp") -> str:
    return f"candidate:9 1 {transport} 2130706431 {address} {port} typ host"


def test_which_addresses_a_jetkvm_offers_are_tried() -> None:
    allowed = frozenset({ipaddress.ip_address("192.168.1.40"), ipaddress.ip_address("fd00::40")})
    assert jetkvm.allowed_candidate(candidate("192.168.1.40", 51234), allowed)
    assert jetkvm.allowed_candidate(candidate("fd00::40", 51234), allowed)
    for elsewhere in (
        candidate("192.168.1.41"),  # another host of its network
        candidate("10.0.0.1"),
        candidate("8.8.8.8", 53),
        candidate("192.168.1.40", 22, "tcp"),  # (UDP only)
        candidate("4b1e2f3a-9c8d-4e5f-a1b2-c3d4e5f60718.local"),  # a name, looked up with mDNS
        candidate("jet.example.org"),
        "candidate:9 1 udp 2130706431 192.168.1.40",  # cut short
        "a=candidate:9 1 udp 2130706431 192.168.1.40 9 typ host",  # (an SDP line, not a candidate as the JetKVM sends it)
        "",
    ):
        assert not jetkvm.allowed_candidate(elsewhere, allowed), elsewhere


def test_a_jetkvm_reached_by_its_name_is_tried_at_what_the_name_resolves_to() -> None:
    async def run() -> frozenset[Any]:
        device = jetkvm.JetKvmDevice(DeviceSpec("j", "jet", "http://localhost:18901", "", "", kind="jetkvm"))
        return await device._candidate_addresses()

    found = asyncio.run(run())
    assert ipaddress.ip_address("127.0.0.1") in found or ipaddress.ip_address("::1") in found
    assert ipaddress.ip_address(ELSEWHERE) not in found


def test_addresses_a_jetkvm_offers_elsewhere_are_not_tried(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []
    real_set, real_add = aiortc.RTCPeerConnection.setRemoteDescription, aiortc.RTCPeerConnection.addIceCandidate

    async def set_remote(self: Any, description: Any) -> None:
        if description.type == "answer":  # (the wall's: the stand-in sets the offer)
            seen.extend(line[2:] for line in description.sdp.splitlines() if line.startswith("a=candidate:"))
        await real_set(self, description)

    async def add(self: Any, found: Any) -> None:
        seen.append(f"late {found.ip}")
        await real_add(self, found)

    monkeypatch.setattr(aiortc.RTCPeerConnection, "setRemoteDescription", set_remote)
    monkeypatch.setattr(aiortc.RTCPeerConnection, "addIceCandidate", add)
    late = json.dumps({"type": "new-ice-candidate", "data": {"candidate": candidate(LATE), "sdpMid": "0", "sdpMLineIndex": 0}})
    state = JetState(
        # (No name ending in .local here: on the code before, it was looked up with mDNS, on the network. See the test above.)
        extra_candidates=[candidate(ELSEWHERE), candidate(ELSEWHERE, 22, "tcp")],
        also_says=[late],
        also_after=1.0,  # (a second after its addresses: the connection has been made by then, and it is tried as it comes)
    )
    jet = FakeJetKvm(state).start()

    async def run() -> None:
        device = jetkvm.JetKvmDevice(DeviceSpec("j", "jet", jet.url, "", "secret", kind="jetkvm"))
        try:
            await device._connected(urgent=True)  # (it comes about over the addresses it has on this computer)
            assert (await device._read_status())["state"] == "online"
            await asyncio.sleep(1.5)  # (the late one is said a moment after its addresses)
        finally:
            await device.close()

    try:
        asyncio.run(run())
        assert state.also_said == 1 and seen, seen
        assert not [found for found in seen if ELSEWHERE in found or LATE in found or ".local" in found], seen
    finally:
        jet.stop()
