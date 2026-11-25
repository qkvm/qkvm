"""No test asks the tailnet of the computer it runs on: not Tailscale's or NetBird's command, not Tailscale's local API at
its real place. A runner of the tests may be in a tailnet, with tailscaled running and its socket where qKVM looks for it
(GitHub's are not; the coordinator's Linux runner is): a test that left the search, or the certificate, to the real
lookups asked that tailnet's machines, and read what the runner's tailscaled said in place of the test's stand-in.

conftest.no_tailnet_of_the_computer stands all of it in with nothing, for every test; a test that wants a tailnet sets a
stand-in of its own over that (a command, a socket in a folder of its own). These pretend that Tailscale's socket and
commands are there, at their real places, and see that nothing is asked of them.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from qkvm import discover, netbind, tailcert, tailnet, update, vault
from tests.conftest import THE_COMPUTERS_OWN
from tests.test_wall import wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def everything_there(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Tailscale's socket at its real places, and both commands installed, as on a runner in a tailnet; what was asked of
    any of them is noted (and none of it is really asked)."""
    asked: list[str] = []
    real_exists = os.path.lexists

    def lexists(path: Any) -> bool:
        if str(path) in THE_COMPUTERS_OWN["sockets"]:
            asked.append(f"looked for {path}")
            return True
        return real_exists(path)

    async def connect(path: Any, *args: Any, **kwargs: Any) -> Any:
        asked.append(f"connected to {path}")
        raise ConnectionRefusedError("(a test's: nothing is connected to)")

    real_run = subprocess.run

    def run(command: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(command, list) and command and Path(str(command[0])).stem.lower() in ("tailscale", "netbird"):
            asked.append(f"ran {command[0]}")
            raise FileNotFoundError("(a test's: nothing is run)")
        return real_run(command, *args, **kwargs)

    monkeypatch.setattr(os.path, "lexists", lexists)
    if hasattr(asyncio, "open_unix_connection"):
        monkeypatch.setattr(asyncio, "open_unix_connection", connect)
    monkeypatch.setattr(subprocess, "run", run)
    return asked


def test_the_lookups_find_nothing_for_a_test() -> None:
    assert tailnet.SOCKETS == () and tailnet.local_api_socket() is None
    assert tailnet.tailscale_command() is None and tailnet.netbird_command() is None
    assert netbind.tailscale_command() is None and netbind.netbird_command() is None
    # (The real ones are kept, for the tests of the lookups themselves.)
    assert THE_COMPUTERS_OWN["sockets"] == ("/var/run/tailscale/tailscaled.sock", "/run/tailscale/tailscaled.sock")


def test_a_search_asks_nothing_of_the_computers_own_tailnet(tmp_path: Path, everything_there: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[str] = []

    async def what_is(client: Any, target: discover.Target) -> None:
        asked.append(target.host)

    monkeypatch.setattr(discover, "_own_addresses", lambda: [])
    monkeypatch.setattr(discover, "_what_is", what_is)
    with wall(tmp_path / "wall") as admin:
        result = admin.post("/api/v1/discover").json()
    assert result["networks"] == [] and result["notes"] == [] and asked == []
    assert everything_there == []


def test_a_certificate_is_asked_of_nothing_of_the_computers_own(tmp_path: Path, everything_there: list[str]) -> None:
    holder = tailcert.TailscaleCert(tmp_path / "tls")
    assert asyncio.run(holder.renew(within=5)) is False and holder.held is None
    assert everything_there == []
