from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterator
from pathlib import Path

import pytest

from qkvm import discover, kvm, tailnet, update, vault
from qkvm.discover import Target, Wanted
from tests.fake_github import FakeGitHub
from tests.fake_kvm import FakeKvm
from tests.test_users import OTHER, account, visitor
from tests.test_wall import add, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def searched(targets: list[Target], networks: list[str], notes: list[str] | None = None) -> Callable[..., Awaitable[Wanted]]:
    """In place of discover.targets: these addresses, of these networks, and nothing else is asked (no tailnet either)."""

    async def wanted(netbird: object = None) -> Wanted:
        return Wanted(list(targets), list(networks), list(notes or []))

    return wanted


@pytest.fixture
def fake() -> Iterator[FakeKvm]:
    server = FakeKvm().start()
    yield server
    server.stop()


def test_finds_kvms_and_nothing_else(tmp_path: Path, fake: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    other = FakeGitHub().start()  # some web server that is not a KVM
    nowhere = "http://127.0.0.1:9"
    wanted = [
        Target("127.0.0.1", fake.url, nowhere, "rack-kvm"),
        Target("127.0.0.2", other.url, other.url),
        Target("127.0.0.3", nowhere, nowhere),
    ]
    monkeypatch.setattr(discover, "targets", searched(wanted, ["test network"]))
    with wall(tmp_path) as admin:
        result = admin.post("/api/v1/discover").json()
        assert result["scanned"] == 3 and result["networks"] == ["test network"] and result["notes"] == []
        assert result["found"] == [
            {"address": "127.0.0.1", "kind": "kvmd", "url": fake.url, "name": "rack-kvm", "known": False, "known_as": None, "known_id": None, "moved_from": None, "also": []}
        ]
        assert fake.state.logins == 0  # looking is not logging in

        add(admin, fake.url)
        assert admin.post("/api/v1/discover").json()["found"][0]["known"] is True  # already on the wall

        account(admin, "olga", "operator")
        operator = visitor(admin, 50012)
        assert operator.post("/api/v1/login", json={"name": "olga", "password": OTHER}).status_code == 200
        assert operator.post("/api/v1/discover").status_code == 403  # searching the network is for admins


def peers(*found: tuple[str, str]) -> object:
    async def listed(*given: object) -> list[tuple[str, str]]:
        return list(found)

    return listed


def test_only_this_computers_own_network_is_searched(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(discover, "lan_ip", lambda: "192.168.7.20")
    monkeypatch.setattr(tailnet, "tailscale_peers", peers(("100.64.0.9", "nas"), ("192.168.7.30", "dup")))
    monkeypatch.setattr(tailnet, "netbird_peers", peers())
    asked = asyncio.run(discover.targets())
    wanted, networks = asked.targets, asked.networks
    hosts = [target.host for target in wanted]
    assert networks == ["192.168.7.0/24", "Tailscale"]
    assert len(hosts) == 254 and "192.168.7.20" not in hosts  # the /24 without this computer, plus one peer
    assert hosts.count("192.168.7.30") == 1 and hosts[-1] == "100.64.0.9"
    assert next(t for t in wanted if t.host == "100.64.0.9") == Target("100.64.0.9", "https://100.64.0.9", "http://100.64.0.9", "nas")

    monkeypatch.setattr(discover, "lan_ip", lambda: "8.8.8.8")  # a public address: its neighbours are not ours to ask
    monkeypatch.setattr(tailnet, "tailscale_peers", peers())
    assert asyncio.run(discover.targets()) == Wanted([], [], [])


def test_an_error_of_the_programs_own_in_a_search_is_said_and_the_search_is_made(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    # Whatever goes wrong in asking a tailnet, or one address, is no unhandled error of the whole search (a 500 with nothing
    # said): the rest is asked, and the search says what could not be, by the kind of the error alone; the log has the rest.
    async def broken(*given: object) -> list[tuple[str, str]]:
        raise RuntimeError("a bug, with words of its own")

    async def what_is(client: object, target: Target) -> dict[str, object] | None:
        if target.host == "100.92.0.8":
            raise TypeError("another bug")
        return {"address": target.host, "kind": "kvmd", "url": target.kvmd, "name": target.name}

    monkeypatch.setattr(tailnet, "tailscale_peers", broken)
    monkeypatch.setattr(tailnet, "netbird_peers", peers(("100.92.0.7", "rack-kvm"), ("100.92.0.8", "odd")))
    monkeypatch.setattr(discover, "_own_addresses", lambda: [])
    monkeypatch.setattr(discover, "_what_is", what_is)
    with wall(tmp_path) as admin:
        reply = admin.post("/api/v1/discover")
        assert reply.status_code == 200, reply.text
        result = reply.json()
    assert [entry["address"] for entry in result["found"]] == ["100.92.0.7"] and result["networks"] == ["NetBird"]
    assert result["notes"] == [
        "Tailscale could not be asked: an error of qKVM's own (RuntimeError); qkvm.log has it",
        "1 address could not be asked: an error of qKVM's own (TypeError); qkvm.log has it",
    ]
    told = [record for record in caplog.records if record.levelname == "ERROR" and record.exc_info]
    assert {type(record.exc_info[1]).__name__ for record in told if record.exc_info} == {"RuntimeError", "TypeError"}


def test_kvms_can_be_put_in_groups(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as admin:
        device = add(admin, fake.url, group="  Rack   A ")
        listed = admin.get("/api/v1/wall").json()["devices"][0]
        assert listed["group"] == "Rack A"
        edit = {"name": "NAS", "url": fake.url, "group": "Office"}
        assert admin.put(f"/api/v1/devices/{device}", json=edit).json()["device"]["group"] == "Office"
        assert admin.put(f"/api/v1/devices/{device}", json={"name": "NAS", "url": fake.url}).json()["device"]["group"] == ""
        assert admin.put(f"/api/v1/devices/{device}", json={**edit, "group": "x" * 41}).status_code == 422
