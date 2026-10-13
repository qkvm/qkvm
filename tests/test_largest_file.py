"""The largest file: what a wall writes it can read back, sealed as well, and what reading one costs."""

from __future__ import annotations

import asyncio
import datetime
import json
import time
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from qkvm import exchange, kvm, update, vault
from tests.test_wall import PASSWORD, wall

F = {"format": exchange.FORMAT, "version": 1}
PASSPHRASE = "a passphrase for the file"


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def rsa_certificate(bits: int = 2048) -> str:
    """A certificate as most devices make one for themselves: self-signed, RSA of 2048 bits."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "A maker of KVMs"), x509.NameAttribute(NameOID.COMMON_NAME, "kvm.local")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2036, 1, 1, tzinfo=datetime.timezone.utc))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("kvm.local")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def a_wall_of(count: int, pem: str) -> list[dict[str, Any]]:
    return [
        {"url": f"https://kvm{number}.example", "kind": "kvmd", "name": f"KVM {number}", "password": "p" * 30, "cert_pem": pem, "keep_both": True}
        for number in range(count)
    ]


@pytest.mark.parametrize("bits", [2048, 3072])
def test_the_largest_file_that_is_taken_in_can_be_read_back_sealed_with_the_certificates_devices_have(bits: int) -> None:
    # With a short key of the newer kind a certificate is about 600 characters; the RSA certificate of 2048
    # bits that most devices make themselves is about 1100, and one of 3072 bits about 1500. Two thousand
    # devices with those are a plain file that is taken in whole, and the same devices exported with a
    # passphrase were a file the program then refused to read: sealed, a file is a third larger than what
    # is in it, and the most that is read was the same number for both.
    pem = rsa_certificate(bits)
    devices = a_wall_of(exchange.MOST_DEVICES, pem)
    plain = json.dumps({**F, "devices": devices}, indent=2)
    assert len(plain) <= exchange.MAX_FILE, "not a file that is taken in to begin with"
    taken = exchange.unpack(plain, "")
    assert taken.devices is not None and len(taken.devices) == exchange.MOST_DEVICES and not taken.left_out
    sealed = exchange.pack({"devices": devices}, PASSPHRASE, "0.1.0")
    print(f">>> RSA {bits}: certificate {len(pem)} characters; plain file {len(plain)}; sealed file {len(sealed)}; the most that is read {exchange.MAX_FILE}")
    back = exchange.unpack(sealed, PASSPHRASE)  # ExchangeError("too_large") where it is larger than what is read
    assert back.devices is not None and len(back.devices) == exchange.MOST_DEVICES


def test_a_wall_can_read_back_what_it_exported(tmp_path: Path) -> None:
    # The same through the wall: a plain file that is taken in whole, exported again with a passphrase (which
    # is the copy that holds the passwords, the one a person keeps), and that copy read back.
    pem = rsa_certificate(3072)
    plain = json.dumps({**F, "devices": a_wall_of(exchange.MOST_DEVICES, pem)}, indent=2)
    assert len(plain) <= exchange.MAX_FILE
    with wall(tmp_path) as admin:
        took = admin.post("/api/v1/import", json={"file": plain, "take": ["devices"]})
        assert took.status_code == 200 and took.json()["devices"] == exchange.MOST_DEVICES, took.text[:300]
        made = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": PASSPHRASE, "parts": ["devices"]})
        assert made.status_code == 200, made.text[:300]
        back = admin.post("/api/v1/import/read", json={"file": made.text, "passphrase": PASSPHRASE})
        assert back.status_code == 200, (back.status_code, back.text[:300], len(made.text))


def test_reading_a_file_somebody_handed_over_does_not_stop_the_wall(tmp_path: Path) -> None:
    # A plain file is opened, and compared with what is on the wall, on the thread that serves everybody.
    # How long nothing else moves while the largest file there is is read.
    pem = rsa_certificate()
    actions = [{"name": f"Action {number}", "kind": "text", "text": "x" * 20} for number in range(exchange.MOST_ACTIONS)]
    plain = json.dumps({**F, "devices": a_wall_of(exchange.MOST_DEVICES, pem), "actions": actions})
    assert len(plain) <= exchange.MAX_FILE
    longest = [0.0]

    async def clock(stop: asyncio.Event) -> None:
        last = time.perf_counter()
        while not stop.is_set():
            await asyncio.sleep(0.005)
            now = time.perf_counter()
            longest[0] = max(longest[0], now - last - 0.005)
            last = now

    with wall(tmp_path) as admin:
        portal = admin.portal  # the thread and event loop the wall runs on in a test
        assert portal is not None
        stop = portal.call(asyncio.Event)
        ticking = portal.start_task_soon(clock, stop)
        time.sleep(0.2)
        longest[0] = 0.0
        started = time.perf_counter()
        seen = admin.post("/api/v1/import/read", json={"file": plain})
        took = time.perf_counter() - started
        portal.call(stop.set)
        ticking.result(5)
        assert seen.status_code == 200 and sum(device["new"] for device in seen.json()["devices"]) == exchange.MOST_DEVICES
    print(f">>> the request took {took:.2f} s; the longest that nothing else moved was {longest[0]:.2f} s")
    # (A measurement more than a test: a quarter of a second on the machine this was written on.)
    assert longest[0] < 2.0, f"nothing else on the wall moved for {longest[0]:.2f} s while one file was looked at"


def test_a_wall_with_more_in_it_than_a_file_holds_writes_none(monkeypatch: pytest.MonkeyPatch) -> None:
    # Nothing is written that would not be read back: a file that turns out to be too large on the day it is
    # needed is worse than none, and a line that says so.
    devices = a_wall_of(50, "")
    monkeypatch.setattr(exchange, "MAX_FILE", 4000)
    for passphrase in ("", PASSPHRASE):
        with pytest.raises(exchange.ExchangeError) as refused:
            exchange.pack({"devices": devices}, passphrase, "0.1.0")
        assert refused.value.code == "too_large"
    few = exchange.pack({"devices": devices[:5]}, PASSPHRASE, "0.1.0")
    assert len(exchange.unpack(few, PASSPHRASE).devices or []) == 5


def test_a_plain_file_is_held_to_what_a_plain_file_may_be(monkeypatch: pytest.MonkeyPatch) -> None:
    # A sealed file may be longer than a plain one, by what sealing adds. That is no way to hand over a
    # plain file of that length, nor a sealed one with more in it than a plain one may hold.
    monkeypatch.setattr(exchange, "MAX_FILE", 4000)
    monkeypatch.setattr(exchange, "MAX_SEALED", 4000 * 4 // 3 + 4096)
    long_one = json.dumps({**F, "devices": a_wall_of(30, "")}, indent=2)
    assert exchange.MAX_FILE < len(long_one) <= exchange.MAX_SEALED
    with pytest.raises(exchange.ExchangeError) as refused:
        exchange.unpack(long_one, "")
    assert refused.value.code == "too_large"
