"""The machines of a NetBird network, for "Find KVMs", from the NetBird client installed on this computer
(`netbird status --json`), beside Tailscale's.

The stand-in for the command is this Python itself, run in a folder that holds a script called "status": as in
test_what_the_tailscale_command_prints_as_it_arrives.py, `[command, "status", "--json"]` runs that script, which writes
the bytes it was given, as the command writes them (UTF-8).
"""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from qkvm import discover, netbind, tailnet, update, vault
from tests.conftest import THE_COMPUTERS_OWN

WRITES = "import sys\nsys.stdout.buffer.write(open(sys.argv[0] + '.out', 'rb').read())\n"
LI = chr(0x674E)  # (a letter of another alphabet, made from its number)


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")
    monkeypatch.setattr(tailnet, "tailscale_command", lambda: None)
    monkeypatch.setattr(tailnet, "SOCKETS", ())


@pytest.fixture
def prints(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Callable[[bytes], None]:
    """`prints(b"...")`: what the command answers to `netbird status --json`, byte for byte."""
    work = tmp_path / "in place of netbird"
    work.mkdir()
    monkeypatch.chdir(work)
    monkeypatch.setattr(tailnet, "netbird_command", lambda: sys.executable)

    def said(answer: bytes) -> None:
        (work / "status").write_text(WRITES, encoding="ascii")
        (work / "status.out").write_bytes(answer)

    return said


def peer(fqdn: str, address: str, status: str = "Connected") -> dict[str, Any]:
    return {"fqdn": fqdn, "netbirdIp": address, "publicKey": "AAAA", "status": status, "connectionType": "P2P"}


def overview(*peers: dict[str, Any]) -> bytes:
    said = {"peers": {"total": len(peers), "connected": len(peers), "details": list(peers)}, "netbirdIp": "100.92.0.1/16", "fqdn": "wall.netbird.cloud"}
    return json.dumps(said, ensure_ascii=False).encode("utf-8")


def peers() -> list[tuple[str, str]]:
    return asyncio.run(tailnet.netbird_peers())


def test_the_networks_machines_are_read_from_its_client(prints: Callable[[bytes], None]) -> None:
    prints(overview(peer("rack-kvm.netbird.cloud", "100.92.0.7"), peer(f"{LI}-nas.netbird.cloud", "100.92.0.8"), peer("lazy.netbird.cloud", "100.92.0.9", "Idle")))
    # (A peer NetBird shows as idle is one its client connects to with the first packet sent to it: asked as well.)
    assert peers() == [("100.92.0.7", "rack-kvm"), ("100.92.0.8", f"{LI}-nas"), ("100.92.0.9", "lazy")]


def test_without_its_client_nothing_is_asked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tailnet, "netbird_command", lambda: None)
    assert peers() == []


@pytest.mark.parametrize(
    "printed",
    [b"", b"null", b"not json", b"\xff\xfe\x81", b'{"peers": []}', b'{"peers": {"details": {"a": 1}}}', b'{"peers": {"details": [7, null, {"netbirdIp": 7}]}}', b"[" * 100_000],
    ids=["nothing", "null", "no JSON", "no text", "peers in a list", "details in a record", "details of other kinds", "nested too deep"],
)
def test_what_is_not_its_overview_lists_nobody(prints: Callable[[bytes], None], printed: bytes) -> None:
    prints(printed)
    assert peers() == []


@pytest.mark.parametrize(
    ("address", "asked"),
    [
        ("100.92.0.7", "100.92.0.7"), ("100.92.0.7/32", "100.92.0.7"), ("100.64.0.1", "100.64.0.1"),
        ("127.0.0.1", None), ("169.254.169.254", None), ("192.168.1.1", None), ("8.8.8.8", None), ("100.128.0.1", None),
        ("100.92.0.07", None), (" 100.92.0.7", None), ("fd00::1", None), ("", None),
    ],
)  # fmt: skip
def test_only_an_address_of_the_shared_space_is_a_machine_of_it(prints: Callable[[bytes], None], address: str, asked: str | None) -> None:
    prints(overview(peer("x.netbird.cloud", address)))
    assert peers() == ([(asked, "x")] if asked else [])


def test_a_name_is_its_first_part_on_one_short_line(prints: Callable[[bytes], None]) -> None:
    prints(overview(peer("rack\nforged entry." + "y" * 300, "100.92.0.7"), peer("", "100.92.0.8"), {"netbirdIp": "100.92.0.9", "fqdn": 7}))
    assert peers() == [("100.92.0.7", "rack forged entry"), ("100.92.0.8", ""), ("100.92.0.9", "")]


def test_at_most_so_many_machines_are_asked(prints: Callable[[bytes], None]) -> None:
    prints(overview(*(peer(f"m{n}.netbird.cloud", f"100.92.{n // 250}.{n % 250 + 1}") for n in range(400))))
    assert len(peers()) == tailnet.MOST_PEERS


def test_the_command_is_looked_up_as_tailscales_is(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Where it is installed, and never "." or a relative place on the way: on Windows that would run a file of that name
    # lying in the folder the program was started from.
    folder = tmp_path / "bin"
    folder.mkdir()
    name = "netbird.exe" if sys.platform == "win32" else "netbird"
    (folder / name).write_bytes(b"")
    monkeypatch.setenv("PATH", str(folder))
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "no such folder"))
    monkeypatch.setattr(netbind, "netbird_command", THE_COMPUTERS_OWN["netbird_command"])  # (the real lookup, over conftest's nothing)
    assert netbind.netbird_command() == str(folder / name)
    monkeypatch.chdir(folder)
    monkeypatch.setenv("PATH", ".")
    assert netbind.netbird_command() is None


def test_the_search_asks_both_tailnets_and_each_machine_once(monkeypatch: pytest.MonkeyPatch) -> None:
    async def tailscale() -> list[tuple[str, str]]:
        return [("100.64.0.7", "rack-kvm"), ("100.64.0.8", "nas")]

    async def netbird(api: object = None) -> list[tuple[str, str]]:
        return [("100.92.0.7", "office-kvm"), ("100.64.0.8", "the same address")]

    monkeypatch.setattr(discover, "_own_addresses", lambda: [])
    monkeypatch.setattr(tailnet, "tailscale_peers", tailscale)
    monkeypatch.setattr(tailnet, "netbird_peers", netbird)
    wanted = asyncio.run(discover.targets())
    assert wanted.networks == ["Tailscale", "NetBird"] and wanted.notes == []
    assert [(target.host, target.name) for target in wanted.targets] == [("100.64.0.7", "rack-kvm"), ("100.64.0.8", "nas"), ("100.92.0.7", "office-kvm")]
