"""What the tailscale command prints, as it really arrives: bytes from another program.

The earlier tests of this handed the reader a text that was ready-made. The command writes UTF-8, and
Windows reads another program's text in its own code page unless told otherwise: a machine whose name has a u with dots
came out garbled, and one name with a letter the code page has nothing for (an A with an accent is enough; a person's
name in the tailnet counts too, it need not be a machine) left nothing read at all. The search for
devices was then an error inside the program, for as long as that name was in the tailnet. Found by a
reviewer, who put a real program in the command's place.

The stand-in for the command is this Python itself, run in a folder that holds a script called "status"
(or "ip"): `[command, "status", "--json"]` runs that script, which writes the bytes it was given.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from qkvm import discover, netbind, update, vault
from tests.test_wall import wall

WRITES = "import sys\nsys.stdout.buffer.write(open(sys.argv[0] + '.out', 'rb').read())\n"


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def prints(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Callable[[str, bytes], None]:
    """`prints("status", b"...")`: what the command answers to `tailscale status`, byte for byte."""
    work = tmp_path / "in place of tailscale"
    work.mkdir()
    monkeypatch.chdir(work)
    monkeypatch.setattr(discover, "tailscale_command", lambda: sys.executable)
    monkeypatch.setattr(netbind, "tailscale_command", lambda: sys.executable)

    def said(asked: str, answer: bytes) -> None:
        (work / asked).write_text(WRITES, encoding="ascii")
        (work / (asked + ".out")).write_bytes(answer)

    return said


def as_the_command_writes(status: dict[str, Any]) -> bytes:
    # A Go program: UTF-8, and letters of other alphabets as they are, not spelled out.
    return json.dumps(status, ensure_ascii=False).encode("utf-8")


def peer(name: str, address: str = "100.64.0.1", online: bool = True) -> dict[str, Any]:
    return {"HostName": name, "TailscaleIPs": [address, "fd7a:115c:a1e0::1"], "Online": online}


# (Made from their numbers: a letter outside ASCII typed into a test is one more thing to be read wrongly.)
U_WITH_DOTS, A_WITH_ACCENT, LI = chr(0xFC), chr(0xC1), chr(0x674E)
NOT_READ = chr(0xFFFD)  # what stands where a byte could not be read as text


@pytest.mark.parametrize(
    "name",
    ["nas", f"b{U_WITH_DOTS}ro-pc", f"{A_WITH_ACCENT}ngel-PC", f"{LI}-nas"],
    ids=["plain", "u with dots", "A with an accent", "another alphabet"],
)
def test_a_machine_is_called_what_it_is_called(prints: Callable[[str, bytes], None], name: str) -> None:
    prints("status", as_the_command_writes({"Peer": {"k1": peer(name), "k2": peer("other", "100.64.0.2")}}))
    assert discover._tailscale_peers() == [("100.64.0.1", name), ("100.64.0.2", "other")]


def test_a_person_of_the_tailnet_with_a_name_in_another_alphabet(prints: Callable[[str, bytes], None]) -> None:
    said = {"Peer": {"k1": peer("nas")}, "User": {"1": {"DisplayName": f"{LI} {A_WITH_ACCENT}", "LoginName": "li@example.invalid"}}}
    prints("status", as_the_command_writes(said))
    assert discover._tailscale_peers() == [("100.64.0.1", "nas")]


@pytest.mark.parametrize("printed", [b"\xff\xfe\x00\x81\x9d", b'{"Peer": {"k1": {"HostName": "a\x81\x9db", "TailscaleIPs": ["100.64.0.1"], "Online": true}}}', b"", b"null", b"7"], ids=["no text at all", "a name that is no text", "nothing", "null", "a number"])
def test_bytes_that_are_not_what_it_writes(prints: Callable[[str, bytes], None], printed: bytes) -> None:
    prints("status", printed)
    found = discover._tailscale_peers()
    assert found in ([], [("100.64.0.1", f"a{NOT_READ}{NOT_READ}b")])  # nobody, or the machine with what could not be read marked as that


def test_the_search_for_devices_with_such_a_name_in_the_tailnet(tmp_path: Path, prints: Callable[[str, bytes], None], monkeypatch: pytest.MonkeyPatch) -> None:
    # (Nobody is asked anything: this computer's own networks are left out, and the one machine is not online.)
    monkeypatch.setattr(discover, "_own_addresses", lambda: [])
    prints("status", as_the_command_writes({"Peer": {"k1": peer(f"{A_WITH_ACCENT}ngel-PC", online=False)}}))
    with wall(tmp_path / "wall") as admin:
        reply = admin.post("/api/v1/discover")
        assert reply.status_code == 200, reply.text[:300]


@pytest.mark.parametrize(
    ("address", "asked"),
    [
        ("100.64.0.1", True), ("100.100.100.100", True), ("100.127.255.254", True),
        ("127.0.0.1", False), ("0.0.0.0", False), ("169.254.169.254", False), ("255.255.255.255", False), ("224.0.0.1", False),
        ("192.168.1.1", False), ("10.0.0.1", False), ("8.8.8.8", False), ("100.63.255.255", False), ("100.128.0.1", False),
    ],
)  # fmt: skip
def test_only_an_address_of_a_tailnet_is_a_machine_of_it(prints: Callable[[str, bytes], None], address: str, asked: bool) -> None:
    # Whatever stands in the list of a machine's addresses becomes an address the search asks, over HTTPS and
    # over HTTP. This computer itself, the address a cloud keeps for its machines' own secrets, a router,
    # somewhere on the internet: none of them is what Tailscale gives a machine.
    prints("status", as_the_command_writes({"Peer": {"k1": peer("x", address)}}))
    assert discover._tailscale_peers() == ([(address, "x")] if asked else [])
    assert discover._an_address(address) is asked


@pytest.mark.parametrize("printed", [b"100.64.0.9\n", b"100.64.0.9\r\nfd7a:115c:a1e0::9\r\n"], ids=["one line", "as Windows ends a line"])
def test_this_computers_own_tailnet_address(prints: Callable[[str, bytes], None], printed: bytes) -> None:
    prints("ip", printed)
    assert netbind.tailscale_ip() == "100.64.0.9"


@pytest.mark.parametrize("printed", [b"\xff\xfe\x81\x9d\n", b"", b"\x81"], ids=["no text at all", "nothing", "one byte"])
def test_its_own_address_printed_as_something_that_is_none(prints: Callable[[str, bytes], None], printed: bytes) -> None:
    prints("ip", printed)
    found = netbind.tailscale_ip()  # (what it then finds by looking at this computer's own addresses is this computer's business)
    assert found is None or isinstance(found, str)
