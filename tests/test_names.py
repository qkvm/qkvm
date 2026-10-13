"""Addresses a device may really have: which are taken, how each is written, and which are not addresses here."""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Any

import pytest

from qkvm import kvm, update, vault
from qkvm.store import device_url
from tests.fake_kvm import FakeKvm
from tests.test_wall import add, snap, wait_until, wall

# What is typed, and the one way it is written down.
TAKEN = {
    "kvm1": "https://kvm1",
    "pikvm": "https://pikvm",
    "kvm.local": "https://kvm.local",
    "10gbe-kvm": "https://10gbe-kvm",
    "1kvm": "https://1kvm",
    "kvm-1.lan.": "https://kvm-1.lan",
    "KVM-Rack-2.Example.COM": "https://kvm-rack-2.example.com",
    "a.b.c.d.e.f.g": "https://a.b.c.d.e.f.g",
    "1.2.3.4.lan": "https://1.2.3.4.lan",
    "192.168.1.20": "https://192.168.1.20",
    "192.168.1.20:8443": "https://192.168.1.20:8443",
    "192.168.1.20.nip.io": "https://192.168.1.20.nip.io",
    "100.64.0.7": "https://100.64.0.7",
    "kvm.tail1234.ts.net": "https://kvm.tail1234.ts.net",
    "[fe80::1]": "https://[fe80::1]",
    "[fd7a:115c:a1e0::1]:8443": "https://[fd7a:115c:a1e0::1]:8443",
    "http://jetkvm.local": "http://jetkvm.local",
    "https://bmc-01.mgmt.example.com:8443/#/login": "https://bmc-01.mgmt.example.com:8443",
    "xn--kvm-bcher-q9a.example": "https://xn--kvm-bcher-q9a.example",
    "localhost:8080": "https://localhost:8080",
    # A name with an underscore is no host name by the book, and is what a router's list of names is full of
    # (a name given to a machine is handed on as it is). It was "not a usable device address", with no word
    # on what was wrong with it, for whoever had called their KVM so.
    "my_kvm": "https://my_kvm",
    "Rack_KVM.lan": "https://rack_kvm.lan",
    "_kvm.lan:8443": "https://_kvm.lan:8443",
    "http://living_room.local": "http://living_room.local",
}

# Not addresses here, and said to be none: what would be a second way to write one, or goes somewhere a
# person reading it would not expect.
REFUSED = (
    "[fe80::1%eth0]",  # an address that only means something on one network card
    "[fe80::1%25eth0]:443",
    "kvm" + chr(0xFC) + "cher.example",  # letters that are written the xn-- way where they are meant
    "my kvm",
    "x@kvm.lan",
    "user:pw@my_kvm.lan",
    "my_kvm.lan:0",
    "ftp://my_kvm.lan",
    "kvm\\.lan",
    "kvm,lan",
    "127.1",
    "0x7f.0.0.1",
    "",
)


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.mark.parametrize("typed", TAKEN, ids=ascii)
def test_an_address_a_device_may_have_is_taken_and_written_one_way(typed: str) -> None:
    written = device_url(typed)
    assert written == TAKEN[typed]
    assert device_url(written) == written  # and what is written down reads back as itself


@pytest.mark.parametrize("typed", REFUSED, ids=ascii)
def test_what_is_no_address_here_is_refused(typed: str) -> None:
    with pytest.raises(ValueError):
        device_url(typed)


def test_a_kvm_whose_name_has_an_underscore_is_a_kvm_like_any_other(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Taken as an address is one thing; that everything which then has to find the device by that name does
    # (the requests, the check of its certificate, the connection it reports over) is the other. The name is
    # one this computer is made to know, as a router's list would make it.
    device = FakeKvm(tls_dir=tmp_path / "cert").start()
    asked: list[str] = []
    real = socket.getaddrinfo

    def by_name(host: Any, *rest: Any, **more: Any) -> Any:
        if host in ("rack_kvm.test", b"rack_kvm.test"):  # (asked for as text by one library, as bytes by another)
            asked.append(str(host))
            host = "127.0.0.1"
        return real(host, *rest, **more)

    monkeypatch.setattr(socket, "getaddrinfo", by_name)
    try:
        with wall(tmp_path) as client:
            device_id = add(client, f"Rack_KVM.test:{device.port}")
            record = client.core.store.devices[0]  # type: ignore[attr-defined]
            assert record.url == f"https://rack_kvm.test:{device.port}" and record.cert_pem  # found, and its certificate kept
            wait_until(lambda: client.get(snap(device_id)).status_code == 200, "no picture from the KVM that was added by its name", timeout=15)
            assert asked, "the name was never asked for"
            # The same device typed another way is the same device: not a second tile.
            again = client.post("/api/v1/devices", json={"url": f"https://RACK_kvm.test.:{device.port}/", "password": "secret"})
            assert again.status_code == 409, again.text
            assert len(client.get("/api/v1/wall").json()["devices"]) == 1
    finally:
        device.stop()
