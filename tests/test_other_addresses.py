""""Does anything listen there", and when a JetKVM from a file is "already on the wall"."""

from __future__ import annotations

import asyncio
import json
import socket
from pathlib import Path
from typing import Any

import pytest

from qkvm import exchange, kvm, server, update, vault
from tests.test_wall import closed_port, wall

F = {"format": exchange.FORMAT, "version": 1}


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def plain(**parts: Any) -> str:
    return json.dumps({**F, **parts})


def test_a_port_that_takes_connections_at_the_fifth_address_of_a_name_is_not_a_port_with_nothing_on_it(monkeypatch: pytest.MonkeyPatch) -> None:
    # `listens` answers "nothing is there" (and the password typed for an HTTPS device then goes, in the
    # clear, to whatever says "JetKVM" on port 80) only where every address of the name plainly refuses. It
    # asks each address by itself, and only so many: of a name with more, the first four were asked and the
    # rest taken to refuse as well. A name with five: four on which nothing listens, and the one that does.
    listening = socket.socket()
    listening.bind(("127.0.0.1", 0))
    listening.listen(16)
    port = listening.getsockname()[1]
    real = socket.getaddrinfo

    def five(host: Any, *rest: Any, **more: Any) -> Any:
        if host == "many.test":
            # 127.0.0.2 to .5 are this computer as well, and nothing listens there on that port.
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (f"127.0.0.{last}", port)) for last in (2, 3, 4, 5, 1)]
        return real(host, *rest, **more)

    monkeypatch.setattr(socket, "getaddrinfo", five)
    try:
        assert asyncio.run(server.listens(f"https://127.0.0.1:{port}")) is True
        assert asyncio.run(server.listens(f"https://127.0.0.2:{closed_port()}")) is False
        assert asyncio.run(server.listens(f"https://many.test:{port}")) is True, "the one address of the name that takes connections was never asked"
    finally:
        listening.close()


def test_a_jetkvm_from_a_file_is_not_another_kind_of_device_that_is_at_its_other_address(tmp_path: Path) -> None:
    # A JetKVM from a file is "here already" where the wall has a JetKVM at its address the other way (plain
    # for HTTPS, HTTPS for plain): the one the wall has followed to HTTPS. Where what is at that other
    # address is another kind of device (behind one name whose two ports lead to two machines, the gateway
    # that `detect_kind` itself speaks of), the file's JetKVM is a device this wall does not have.
    with wall(tmp_path) as admin:
        took = admin.post("/api/v1/import", json={"file": plain(devices=[{"url": "https://192.168.1.50", "kind": "kvmd", "name": "Rack KVM"}]), "take": ["devices"]})
        assert took.json()["devices"] == 1
        file = plain(devices=[{"url": "http://192.168.1.50", "kind": "jetkvm", "name": "Bench JetKVM"}])
        there = admin.post("/api/v1/import/read", json={"file": file}).json()["devices"]
        assert [(device["new"], device["same_as"]) for device in there] == [(True, "")], there


def test_a_jetkvm_from_a_file_is_the_jetkvm_that_is_at_its_other_address(tmp_path: Path) -> None:
    # (The case the rule is for, beside the one above: also for two entries of one file.)
    with wall(tmp_path) as admin:
        took = admin.post("/api/v1/import", json={"file": plain(devices=[{"url": "https://192.168.1.50", "kind": "jetkvm", "name": "Bench"}]), "take": ["devices"]})
        assert took.json()["devices"] == 1
        file = plain(devices=[
            {"url": "http://192.168.1.50", "kind": "jetkvm", "name": "Bench, the plain way"},
            {"url": "http://192.168.1.60", "kind": "jetkvm", "name": "Second"},
            {"url": "https://192.168.1.60", "kind": "jetkvm", "name": "Second, over HTTPS"},
        ])  # fmt: skip
        there = admin.post("/api/v1/import/read", json={"file": file}).json()["devices"]
        assert [(device["new"], device["same_as"]) for device in there] == [(False, "Bench"), (True, ""), (False, "Second")], there
