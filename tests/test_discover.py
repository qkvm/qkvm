from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from qkvm import discover, kvm, update, vault
from qkvm.discover import Target
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
    monkeypatch.setattr(discover, "targets", lambda: (wanted, ["test network"]))
    with wall(tmp_path) as admin:
        result = admin.post("/api/v1/discover").json()
        assert result["scanned"] == 3 and result["networks"] == ["test network"]
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


def test_only_this_computers_own_network_is_searched(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(discover, "lan_ip", lambda: "192.168.7.20")
    monkeypatch.setattr(discover, "_tailscale_peers", lambda: [("100.64.0.9", "nas"), ("192.168.7.30", "dup")])
    wanted, networks = discover.targets()
    hosts = [target.host for target in wanted]
    assert networks == ["192.168.7.0/24", "Tailscale"]
    assert len(hosts) == 254 and "192.168.7.20" not in hosts  # the /24 without this computer, plus one peer
    assert hosts.count("192.168.7.30") == 1 and hosts[-1] == "100.64.0.9"
    assert next(t for t in wanted if t.host == "100.64.0.9") == Target("100.64.0.9", "https://100.64.0.9", "http://100.64.0.9", "nas")

    monkeypatch.setattr(discover, "lan_ip", lambda: "8.8.8.8")  # a public address: its neighbours are not ours to ask
    monkeypatch.setattr(discover, "_tailscale_peers", lambda: [])
    assert discover.targets() == ([], [])


def test_kvms_can_be_put_in_groups(tmp_path: Path, fake: FakeKvm) -> None:
    with wall(tmp_path) as admin:
        device = add(admin, fake.url, group="  Rack   A ")
        listed = admin.get("/api/v1/wall").json()["devices"][0]
        assert listed["group"] == "Rack A"
        edit = {"name": "NAS", "url": fake.url, "group": "Office"}
        assert admin.put(f"/api/v1/devices/{device}", json=edit).json()["device"]["group"] == "Office"
        assert admin.put(f"/api/v1/devices/{device}", json={"name": "NAS", "url": fake.url}).json()["device"]["group"] == ""
        assert admin.put(f"/api/v1/devices/{device}", json={**edit, "group": "x" * 41}).status_code == 422
