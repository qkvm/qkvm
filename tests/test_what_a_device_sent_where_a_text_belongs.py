"""What a device sent where a text belongs, and is no text: a list within a list, tens of thousands deep.

A Python from 3.13 on reads that from an answer without a word, and cannot write it out: `str()` of it is
an error of Python's own kind (RecursionError). Eight places wrote out whatever a device had sent before
looking what it was: the address in a KVM's and a JetKVM's list of machines to wake, a JetKVM's network
addresses (in two places), the description in its answer, four values of a controller's pass to its console,
and the kind of its way in. Found by putting one such value into every place of what the three stand-ins
answer, one at a time, after the suite's run on the oldest Python had found the reading half of the same
(`test_what_is_read_nested_thousands_deep.py`).
"""

from __future__ import annotations

import asyncio
import base64
import json
import subprocess
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

from qkvm import discover, jetkvm, kvm, redfish, update, vault
from qkvm.kvm import DeviceSpec, KvmError, as_text
from tests.fake_jetkvm import FakeJetKvm
from tests.fake_kvm import FakeKvm
from tests.fake_redfish import BmcState, FakeBmc
from tests.test_redfish import a_screen, picture_of, status_of
from tests.test_wall import add, snap, wait_until, wall

# How deep a Python reads, and how deep it can write out again, differs from one version and one system to
# the next: 3.11 reads no deeper than a thousand, 3.14 on Windows read sixty thousand and could not write
# them out. So what arrives as text is tried at several depths, and each test holds at every one of them.
DEPTHS = (1_500, 20_000, 60_000, 100_000)


def deep(depth: int) -> str:
    """As a device writes it."""
    return "[" * depth + "0" + "]" * depth


def nested() -> Any:
    """The same as it is once read. (Made here, since no reader reads it on every Python.)"""
    value: Any = 0
    for _ in range(DEPTHS[-1]):
        value = [value]
    return value


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(redfish, "LOOK_EVERY", 0)
    monkeypatch.setattr(redfish, "FOLLOW_UP", ())
    monkeypatch.setattr(redfish, "HICCUP", 0)
    monkeypatch.setattr(redfish, "CONFIRM_EVERY", 0.05)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def answering(monkeypatch: pytest.MonkeyPatch, module: Any, changed: Callable[[str, Any], None]) -> None:
    """What `module` reads of a device's answers is handed to `changed` first (the path asked, what was said)."""
    real = kvm.read_json

    def read(reply: Any) -> Any:
        said = real(reply)
        changed(urlsplit(str(reply.url)).path, said)
        return said

    monkeypatch.setattr(module, "read_json", read)


def test_what_is_a_text_and_what_is_none() -> None:
    assert [as_text(value) for value in ("a b", "", 5, 1.5, 0)] == ["a b", "", "5", "1.5", "0"]
    for value in (None, True, False, [], {}, ["a"], {"a": "b"}, b"a", nested(), {"a": nested()}):
        assert as_text(value) == ""


# --- a KVM ---------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("part", ["mac", "name"])
def test_a_kvms_list_of_machines_to_wake(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, part: str) -> None:
    fake = FakeKvm().start()
    fake.state.wol = [{"mac": "AA:BB:CC:DD:EE:FF", "name": "nas"}, {"mac": "11:22:33:44:55:66", "name": "another"}]

    def changed(path: str, said: Any) -> None:
        if path == "/api/wol/list":
            said["result"]["devices"][0][part] = nested()

    answering(monkeypatch, kvm, changed)
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url)
            reply = admin.get(f"/api/v1/devices/{device}/wol")
            assert reply.status_code == 200, reply.text[:300]
            first = [] if part == "mac" else [{"mac": "AA:BB:CC:DD:EE:FF", "name": ""}]  # no address: not a machine; no name: one without
            assert reply.json() == {"targets": [*first, {"mac": "11:22:33:44:55:66", "name": "another"}]}
    finally:
        fake.stop()


# --- a JetKVM ------------------------------------------------------------------------------------------------


def a_jetkvm(url: str = "http://127.0.0.1:18901") -> jetkvm.JetKvmDevice:
    return jetkvm.JetKvmDevice(DeviceSpec("jet", "A JetKVM", url, "", "secret", kind="jetkvm"))


def test_a_jetkvms_list_of_machines_to_wake(monkeypatch: pytest.MonkeyPatch) -> None:
    device = a_jetkvm()

    async def connected(urgent: bool = False) -> jetkvm._Session:
        return jetkvm._Session()

    async def call(session: jetkvm._Session, method: str, params: Any = None) -> Any:
        assert method == "getWakeOnLanDevices"
        return [
            {"macAddress": nested(), "name": "a list for an address"},
            {"macAddress": "aa:bb:cc:dd:ee:ff", "name": nested()},
            nested(),
            {"macAddress": "11:22:33:44:55:66", "name": "A PC"},
        ]

    monkeypatch.setattr(device, "_connected", connected)
    monkeypatch.setattr(device, "_call", call)
    assert asyncio.run(device.wol_targets()) == [{"mac": "aa:bb:cc:dd:ee:ff", "name": ""}, {"mac": "11:22:33:44:55:66", "name": "A PC"}]


class Heard:
    """What comes over the signalling, word for word; then nothing more."""

    def __init__(self, *messages: str) -> None:
        self.messages = iter(messages)

    async def message(self, within: float) -> str:
        try:
            return next(self.messages)
        except StopIteration:
            raise TimeoutError from None


MARKED = json.dumps({"type": "new-ice-candidate", "data": {"candidate": "(nested, once read)"}})


@pytest.fixture
def read_as_nested(monkeypatch: pytest.MonkeyPatch) -> None:
    """An address sent as MARKED is, once the message is read, a list nested as deep as `nested()`.

    Sent as text, which depth is read and then cannot be written out differs between versions, systems and
    even two threads of one program; this way the test says the same everywhere.
    """
    real = jetkvm._parse

    def parse(raw: Any) -> dict[str, Any]:
        said = real(raw)
        if raw == MARKED:
            said["data"]["candidate"] = nested()
        return said

    monkeypatch.setattr(jetkvm, "_parse", parse)


SDP = "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:0\r\n"
ANSWER = json.dumps({"type": "answer", "data": base64.b64encode(json.dumps({"sdp": SDP}).encode()).decode()})


@pytest.mark.parametrize("depth", [0, *DEPTHS])
def test_a_network_address_of_a_jetkvm_that_is_no_text(read_as_nested: None, depth: int) -> None:
    odd = '{"type": "new-ice-candidate", "data": {"candidate": ' + deep(depth) + "}}" if depth else MARKED
    good = json.dumps({"type": "new-ice-candidate", "data": {"candidate": "candidate:1 1 udp 1 192.0.2.1 9 typ host"}})

    async def check() -> None:
        answer, candidates = await jetkvm._await_answer(Heard(ANSWER, odd, good))  # type: ignore[arg-type]
        assert answer == SDP and candidates == ["candidate:1 1 udp 1 192.0.2.1 9 typ host"]

    asyncio.run(check())


@pytest.mark.parametrize("sdp", [*map(deep, DEPTHS), "[]", "{}", "null", "true", '""'], ids=[*(f"nested {depth}" for depth in DEPTHS), "a list", "a record", "null", "true", "no text"])
def test_an_answer_of_a_jetkvm_whose_description_is_no_text(sdp: str) -> None:
    # (Written out whatever it was, it went on to the video library as "[]" or "None", and was refused there
    # in that library's words. It is refused here, as an answer that cannot be read.)
    said = json.dumps({"type": "answer", "data": base64.b64encode(('{"sdp": ' + sdp + "}").encode()).decode()})

    async def check() -> None:
        with pytest.raises(KvmError) as refused:
            await jetkvm._await_answer(Heard(said))  # type: ignore[arg-type]
        assert refused.value.code == "bad_response"

    asyncio.run(check())


def test_a_network_address_sent_late_that_is_no_text_does_not_end_the_connection(read_as_nested: None) -> None:
    # Addresses that come after the connection is made are read in another place: the same there. It ended
    # the connection, picture and all, in the middle of being used; the next look made a new one, and the
    # JetKVM could end that one the same way.
    fake = FakeJetKvm().start()
    fake.state.also_says = [MARKED, *('{"type": "new-ice-candidate", "data": {"candidate": ' + deep(depth) + "}}" for depth in DEPTHS)]
    fake.state.also_after = 0.6

    async def check() -> None:
        device = a_jetkvm(fake.url)
        try:
            await device.identify()
            began = time.monotonic()
            try:
                session = await device._connected(urgent=True)
            except KvmError as ex:
                # (Once, on a slow machine of somebody else's, this connection was not made within its fifteen
                # seconds, and nothing said why. Should it happen again, this does.)
                tried, pc = device._session, getattr(device._session, "pc", None)
                raise AssertionError(
                    f"no connection to the stand-in after {time.monotonic() - began:.1f} s: {ex.code} ({ex.message}); "
                    f"the stand-in has had {fake.state.sessions} connection(s) and said {fake.state.also_said} of its late addresses; "
                    f"this side: ready={getattr(tried, 'ready', None) and tried.ready.is_set()} done={getattr(tried, 'done', None) and tried.done.is_set()} "
                    f"error={getattr(tried, 'error', None)} lost={getattr(tried, 'lost', None)} "
                    f"connection={getattr(pc, 'connectionState', None)} ice={getattr(pc, 'iceConnectionState', None)} "
                    f"gathering={getattr(pc, 'iceGatheringState', None)} signalling={getattr(pc, 'signalingState', None)}"
                ) from ex
            until = time.monotonic() + 10
            while not fake.state.also_said and time.monotonic() < until:
                await asyncio.sleep(0.05)
            until = time.monotonic() + 10
            while fake.state.also_said < len(fake.state.also_says) and time.monotonic() < until:
                await asyncio.sleep(0.05)
            assert fake.state.also_said == len(fake.state.also_says)
            await asyncio.sleep(1.5)  # (read, and whatever that does is done)
            assert session.live and not session.done.is_set()
            assert (await device._read_status())["state"] == "online"
            assert await device._connected(urgent=True) is session and fake.state.sessions == 1
            await device.act("keys", keys="Enter")
            assert fake.state.typed[-1] == (0, [40])
        finally:
            await device.close()

    try:
        asyncio.run(check())
    finally:
        fake.stop()


# --- a server's controller -------------------------------------------------------------------------------------


@pytest.fixture
def with_screen() -> Iterator[FakeBmc]:
    server = FakeBmc(BmcState(own_console=True, screen=a_screen(), piece=50)).start()
    yield server
    server.stop()


@pytest.mark.parametrize("part", ["client_ip", "session", "server_ip", "automatic_off", "local_monitor_off", "local_monitor_off, beside a yes", "kvm_service_status"])
def test_the_pass_to_a_controllers_console(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, with_screen: FakeBmc, part: str) -> None:
    # (What it says beside the pass itself: who it takes the wall for, where it is, whether the server's own
    # monitor goes dark. None of these, as something that is no text, is an error of the program.)
    dark = part.endswith("beside a yes")
    if dark:
        # Two words say that the monitor goes dark, and the second is looked at only where the first says
        # yes. A second word that cannot be read is not a plain no (redfish.said_yes): the console is left alone.
        with_screen.state.monitor_goes_dark, part = True, "local_monitor_off"

    def changed(path: str, said: Any) -> None:
        if path == "/api/kvm/token":
            said[part] = nested()

    answering(monkeypatch, redfish, changed)
    with wall(tmp_path) as admin:
        device = add(admin, with_screen.url)
        if dark:
            wait_until(lambda: admin.get(snap(device)).status_code == 404, "it was never said that there is no picture")
            assert "monitor" in admin.get(snap(device)).json()["message"] and with_screen.state.heard == []
            return
        assert picture_of(admin, device)[:2] == bytes([0xFF, 0xD8])
        assert status_of(admin, device, screen=True)["server"]["no_screen"] is None


@pytest.mark.parametrize("kind", ["nested", "a list", "a number", "missing", "nothing", "HTML 5"])
def test_the_kind_of_way_into_a_controllers_console(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    said_instead: dict[str, Any] = {"nested": nested(), "a list": ["html"], "a number": 5, "nothing": "", "HTML 5": "HTML 5"}

    def changed(path: str, said: Any) -> None:
        if isinstance(said, dict) and "Interface" in said:
            if kind == "missing":
                del said["Interface"]
            else:
                said["Interface"] = said_instead[kind]

    answering(monkeypatch, redfish, changed)
    bmc = FakeBmc().start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, bmc.url)
            reply = admin.post(f"/api/v1/devices/{device}/console")
            if kind in ("missing", "nothing", "HTML 5"):  # a page, or nothing said of what it is: handed on
                assert reply.status_code == 200 and "/viewer.html?" in reply.json()["url"], reply.text[:300]
            else:  # said, and not as a text that names a page: not handed on
                assert reply.status_code != 500 and reply.json()["code"] == "bad_response", reply.text[:300]
    finally:
        bmc.stop()


# --- the other machines of a tailnet -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("printed", "found"),
    [
        ('{"Peer": [1, 2]}', []),
        ('{"Peer": {"a": 1, "b": [2], "c": null}}', []),
        ('{"Peer": {"a": {"Online": true, "TailscaleIPs": 5}}}', []),
        ('{"Peer": {"a": {"Online": true, "TailscaleIPs": [7, null, ["100.64.0.9"], "100.64.0.1", "fd7a::1"], "HostName": "nas"}}}', [("100.64.0.1", "nas")]),
        *(('{"Peer": {"a": {"Online": true, "TailscaleIPs": ["100.64.0.2"], "HostName": ' + deep(depth) + "}}}", [("100.64.0.2", "")]) for depth in DEPTHS),
        *(('{"Peer": {"a": {"Online": true, "TailscaleIPs": [' + deep(depth) + ', "100.64.0.3"], "HostName": 7}}}', [("100.64.0.3", "7")]) for depth in DEPTHS),
        # What is asked is asked at an address: nothing else that stands where one belongs is asked anything.
        ('{"Peer": {"a": {"Online": true, "TailscaleIPs": ["100.64.0.4/x", "example.net", "100.64.0.4@example.net", " 100.64.0.5", "0100.64.0.6"]}}}', []),
        ('{"Peer": {"a": {"Online": true, "TailscaleIPs": ["100.64.0.7"], "HostName": "a\\nb\\u001b[2Jc"}}}', [("100.64.0.7", "a b [2Jc")]),
        ('{"Peer": {"a": {"Online": false, "TailscaleIPs": ["100.64.0.8"], "HostName": "off"}}}', []),
    ],
    ids=[
        "a list of them", "none a record", "addresses not a list", "addresses of every kind",
        *(f"a name nested {depth}" for depth in DEPTHS), *(f"an address nested {depth}" for depth in DEPTHS),
        "not addresses", "a name with a line break", "not online",
    ],
)
def test_what_the_tailscale_command_says_of_the_other_machines(monkeypatch: pytest.MonkeyPatch, printed: str, found: list[tuple[str, str]]) -> None:
    def ran(*asked: Any, **how: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(asked, 0, stdout=printed, stderr="")

    monkeypatch.setattr(discover, "tailscale_command", lambda: "tailscale")
    monkeypatch.setattr(discover.subprocess, "run", ran)
    said = discover._tailscale_peers()
    # (Nested deeper than this Python reads, the whole of what was printed is unreadable, and nobody is found.)
    assert said == found or ("[[[[" in printed and said == [])
