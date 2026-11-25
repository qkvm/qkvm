"""The machines of a tailnet, from Tailscale's local API, where there is no tailscale command (qKVM in a container beside
Tailscale's own, the socket of its local API mounted in).

Asked over its socket on this computer only, and only where that is a socket, and Tailscale's (root's, or this account's);
what it answers is read up to a size and within a time; a refusal, an answer that is no answer, one too large, one that
never ends: each is a sentence for the admin who searched, never a hang, never an error of the search. And what is found
is a suggestion: nothing is added to the wall by a search.

Unix sockets: these run on Linux (and macOS). On Windows Tailscale keeps its local API behind a named pipe, which qKVM
does not ask (its command is there): the one test of that runs there.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from qkvm import discover, tailnet, update, vault
from tests.test_wall import wall

on_windows = sys.platform == "win32"
unix_only = pytest.mark.skipif(on_windows, reason="Tailscale's local API is a Unix socket here; on Windows a named pipe, not asked (see the module)")
STATUS = "/localapi/v0/status"


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")
    monkeypatch.setattr(tailnet, "tailscale_command", lambda: None)  # (the command is not there: a container)
    monkeypatch.setattr(tailnet, "netbird_command", lambda: None)


@pytest.fixture
def tailscaled(monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    from tests.fake_tailscaled import FakeTailscaled

    fake = FakeTailscaled().start()
    monkeypatch.setattr(tailnet, "SOCKETS", (str(fake.path),))
    yield fake
    fake.stop()


def peer(name: str, address: str, online: bool = True) -> dict[str, Any]:
    return {"HostName": name, "DNSName": f"{name}.example.ts.net.", "TailscaleIPs": [address, "fd7a:115c:a1e0::1"], "Online": online}


def status(*peers: dict[str, Any]) -> bytes:
    return json.dumps({"Self": peer("wall", "100.64.0.1"), "Peer": {f"key{n}": each for n, each in enumerate(peers)}}).encode()


def peers() -> list[tuple[str, str]]:
    return asyncio.run(tailnet.tailscale_peers())


def refused() -> str:
    with pytest.raises(tailnet.Unasked) as said:
        peers()
    return str(said.value)


@unix_only
def test_the_tailnets_machines_are_read_from_its_local_api_where_its_command_is_not_there(tailscaled: Any) -> None:
    tailscaled.answers[STATUS] = (200, status(peer("rack-kvm", "100.64.0.7"), peer("asleep", "100.64.0.8", online=False), peer("laptop", "100.100.3.4")))
    assert peers() == [("100.64.0.7", "rack-kvm"), ("100.100.3.4", "laptop")]
    # Asked once, for its status, by the Host its local API takes and no other (a web page's rebinding is refused there).
    assert [(method, target, said["host"]) for method, target, said in tailscaled.asked] == [("GET", STATUS, "local-tailscaled.sock")]


@unix_only
def test_its_command_is_asked_first_where_it_is_installed(tailscaled: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    tailscaled.answers[STATUS] = (200, status(peer("from-the-socket", "100.64.0.7")))
    monkeypatch.setattr(tailnet, "tailscale_command", lambda: "/usr/bin/tailscale")
    monkeypatch.setattr(tailnet, "_status_by_command", lambda command: json.loads(status(peer("from-the-command", "100.64.0.9"))))
    assert peers() == [("100.64.0.9", "from-the-command")]
    assert tailscaled.asked == []


def test_without_tailscale_nothing_is_asked_and_nothing_is_said(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tailnet, "SOCKETS", (str(tmp_path / "no such socket"),))
    assert tailnet.local_api_socket() is None
    assert peers() == []


@pytest.mark.skipif(not on_windows, reason="Windows only: elsewhere a socket at that place is Tailscale's local API")
def test_on_windows_no_socket_is_asked_whatever_lies_at_its_place(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    there = tmp_path / "tailscaled.sock"
    there.write_bytes(b"")
    monkeypatch.setattr(tailnet, "SOCKETS", (str(there),))
    assert tailnet.local_api_socket() is None
    assert peers() == []


@unix_only
@pytest.mark.parametrize("what", ["a file", "a link to the socket", "a socket of another account"])
def test_what_is_not_tailscales_socket_is_not_spoken_to(tailscaled: Any, monkeypatch: pytest.MonkeyPatch, what: str) -> None:
    tailscaled.answers[STATUS] = (200, status(peer("rack-kvm", "100.64.0.7")))
    if what == "a file":
        planted = tailscaled.folder / "planted"
        planted.write_bytes(b"HTTP/1.0 200 OK\r\n\r\n{}")
        monkeypatch.setattr(tailnet, "SOCKETS", (str(planted),))
        expected = "is not a socket"
    elif what == "a link to the socket":
        link = tailscaled.folder / "link.sock"
        link.symlink_to(tailscaled.path)
        monkeypatch.setattr(tailnet, "SOCKETS", (str(link),))
        expected = "is a link"
    else:
        # (Said to be owned by an account that is neither root nor the one asking, whoever runs the tests: root as well.)
        real_lstat, there = os.lstat, str(tailscaled.path)

        def lstat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
            found = real_lstat(path, *args, **kwargs)
            if str(path) != there:
                return found
            said = list(found[:10])
            said[4] = os.getuid() + 4242  # st_uid
            return os.stat_result(said)

        monkeypatch.setattr(os, "lstat", lstat)
        expected = "belongs to another account than root"
    said = refused()
    assert said.startswith("Tailscale's local API was not asked: ") and said.endswith(expected)
    assert tailscaled.asked == []


@unix_only
@pytest.mark.parametrize(
    ("body", "said"),
    [
        (b"not json at all", "answered with something that is not JSON"),
        (b"\xff\xfe\x81", "answered with something that is not JSON"),
        (b"[" * 200_000, "answered with JSON nested too deep to read"),
    ],
    ids=["no JSON", "no text", "nested too deep"],
)
def test_an_answer_that_cannot_be_read_is_said(tailscaled: Any, body: bytes, said: str) -> None:
    tailscaled.answers[STATUS] = (200, body)
    assert refused() == f"Tailscale's local API {said}"


@unix_only
@pytest.mark.parametrize(
    "body",
    [b"null", b"7", b'{"Peer": [1, 2]}', b'{"Peer": {"k": {"TailscaleIPs": "100.64.0.7", "Online": true}}}', b'{"Peer": {"k": {"TailscaleIPs": ["100.64.0.7"], "Online": "yes"}}}'],
    ids=["null", "a number", "peers in a list", "addresses in a text", "online in words"],
)
def test_json_of_another_shape_lists_nobody(tailscaled: Any, body: bytes) -> None:
    tailscaled.answers[STATUS] = (200, body)
    assert peers() == []


@unix_only
@pytest.mark.parametrize(
    "raw",
    [
        b"garbage\r\n\r\n{}",
        b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
        b"HTTP/1.0 200 OK\r\nContent-Length: twelve\r\n\r\n{}",
        b"HTTP/1.0 200 OK\r\nNo colon here\r\n\r\n{}",
        b"HTTP/1.0 200 OK\r\nX-Long: " + b"a" * 40_000 + b"\r\n\r\n{}",
        b"HTTP/1.0 200 OK\r\n",
    ],
    ids=["no status line", "in pieces", "a length in words", "a header without a colon", "headers that never end", "cut off in its headers"],
)
def test_an_answer_that_is_not_http_is_said(tailscaled: Any, raw: bytes) -> None:
    tailscaled.raw = raw
    assert refused() == "Tailscale's local API answered with something that is not HTTP"


@unix_only
def test_an_answer_cut_off_before_the_length_it_said_is_said(tailscaled: Any) -> None:
    tailscaled.raw = b"HTTP/1.0 200 OK\r\nContent-Length: 500\r\n\r\n{\"Peer\": {}}"
    assert refused() == "Tailscale's local API ended its answer before its end"


@unix_only
def test_an_answer_too_large_is_not_read_to_its_end(tailscaled: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tailnet, "STATUS_MOST", 64 * 1024)
    big = status(*(peer(f"machine-{n}", f"100.64.{n // 250}.{n % 250 + 1}") for n in range(2000)))
    assert len(big) > 4 * 64 * 1024
    tailscaled.answers[STATUS] = (200, big)
    assert refused() == "Tailscale's local API sent more than this program reads of it (64 KB)"
    # ...and where it says its length, by that alone, before anything of it is read.
    tailscaled.raw = b"HTTP/1.0 200 OK\r\nContent-Length: 999999999\r\n\r\n{}"
    assert refused() == "Tailscale's local API sent more than this program reads of it (64 KB)"


@unix_only
def test_a_length_of_more_digits_than_a_number_is_read_with_is_too_much(tailscaled: Any) -> None:
    # (Python reads no whole number of more than 4300 digits: it says so by a ValueError of its own, which went past every
    # refusal here, out of the search, and out of a renewal of the certificate at a start, which then did not start.)
    tailscaled.raw = b"HTTP/1.0 200 OK\r\nContent-Length: " + b"9" * 5000 + b"\r\n\r\n{}"
    assert refused() == "Tailscale's local API sent more than this program reads of it (8192 KB)"


@unix_only
@pytest.mark.parametrize("how", ["says nothing", "sends a byte at a time"])
def test_a_local_api_that_does_not_answer_in_time_is_given_up_on(tailscaled: Any, monkeypatch: pytest.MonkeyPatch, how: str) -> None:
    monkeypatch.setattr(tailnet, "ASK_WITHIN", 0.5)
    tailscaled.answers[STATUS] = (200, status())
    if how == "says nothing":
        tailscaled.hold = 60.0
    else:
        tailscaled.trickle = True
    began = time.monotonic()
    assert refused() == "Tailscale's local API did not answer within 0.5 seconds"
    assert time.monotonic() - began < 5.0  # (half a second, with room for a slow machine: not the minute it would hold)


@unix_only
def test_a_refusal_is_said_in_its_own_words_on_one_short_line(tailscaled: Any) -> None:
    tailscaled.answers[STATUS] = (403, b"status access denied\n\x1b[31mforged\nline " + b"x" * 500)
    said = refused()
    assert said.startswith("Tailscale's local API did not say who is in the tailnet (403: status access denied")
    assert said.isprintable() and len(said) < 200


@unix_only
def test_a_socket_nothing_listens_at_is_said(tailscaled: Any) -> None:
    tailscaled.stop()  # (its socket file is gone with its folder: one is made where nothing listens)
    import socket

    tailscaled.folder.mkdir()
    with socket.socket(socket.AF_UNIX) as left:
        left.bind(str(tailscaled.path))
    try:
        assert refused().startswith(f"Tailscale's local API could not be reached at {tailscaled.path} (")
    finally:
        tailscaled.path.unlink()
        tailscaled.folder.rmdir()


@unix_only
def test_the_search_lists_the_tailnets_kvms_and_adds_nothing(tmp_path: Path, tailscaled: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    tailscaled.answers[STATUS] = (200, status(peer("rack-kvm", "100.64.0.7"), peer("laptop", "100.64.0.8")))
    asked: list[str] = []

    async def what_is(client: Any, target: discover.Target) -> dict[str, Any] | None:
        # (In place of asking the address: no tailnet is reached from a test, whatever this computer is on.)
        asked.append(target.host)
        return {"address": target.host, "kind": "kvmd", "url": target.kvmd, "name": target.name} if target.name == "rack-kvm" else None

    monkeypatch.setattr(discover, "_own_addresses", lambda: [])
    monkeypatch.setattr(discover, "_what_is", what_is)
    with wall(tmp_path / "wall") as admin:
        result = admin.post("/api/v1/discover").json()
        assert result["networks"] == ["Tailscale"] and result["notes"] == [] and sorted(asked) == ["100.64.0.7", "100.64.0.8"]
        assert [(entry["address"], entry["name"], entry["known"]) for entry in result["found"]] == [("100.64.0.7", "rack-kvm", False)]
        assert admin.get("/api/v1/wall").json()["devices"] == []  # found is offered, and nothing more

        # Its local API there and saying no: the search is done all the same, and says why the tailnet was not in it.
        tailscaled.answers[STATUS] = (403, b"status access denied")
        asked.clear()
        result = admin.post("/api/v1/discover").json()
        assert result["networks"] == [] and result["found"] == [] and asked == []
        assert result["notes"] == ["Tailscale's local API did not say who is in the tailnet (403: status access denied)"]
