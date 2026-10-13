"""What a file's certificate is taken for on OpenSSL's word, and what counts against the number that are asked.

* A certificate with other data after it, inside the one PEM block. The quick reader refuses it; OpenSSL
  reads the certificate and does not look at the rest, so the whole block became the "remembered
  certificate". Its fingerprint (what the tile's dialog shows, what `core.identity` knows the device by)
  was then that of the block, which no device ever presents, while `kvm.pinned_context` trusted the
  certificate at the front of it. It is one certificate and nothing after it, or none.
* What is base64 between the two lines and no certificate does not use up `exchange.MOST_ODD` for a
  certificate that only OpenSSL reads.
* One certificate on many devices (a maker's, on every board) is asked of OpenSSL once.
"""

from __future__ import annotations

import json
import ssl
from pathlib import Path

import pytest

from qkvm import exchange, kvm, update, vault
from tests.fake_kvm import FakeKvm
from tests.test_largest_file import rsa_certificate
from tests.test_wall import snap, wall
from tests.test_written_and_read_back_more import odd_certificate

F = {"format": exchange.FORMAT, "version": 1}


def read(devices: list[dict[str, object]]) -> exchange.Content:
    return exchange.unpack(json.dumps({**F, "devices": devices}), "")


def test_a_certificate_with_other_data_after_it_is_not_remembered_as_it_stands() -> None:
    real = rsa_certificate(2048)
    der = ssl.PEM_cert_to_DER_cert(real)
    padded = ssl.DER_cert_to_PEM_cert(der + b"\x00" * 3000 + b"whatever a file likes to put here")
    content = read([{"url": "https://192.168.1.20", "kind": "kvmd", "cert_pem": padded}])
    kept = [device.cert_pem for device in content.devices or []]
    print(f">>> a certificate with 3 kB after it: taken {len(kept)} of 1; left out {content.left_out}")
    if not kept:
        return  # (refused: nothing is remembered)
    shown, trusted = kvm.saved_fingerprint(kept[0]), kvm.fingerprint(real)
    print(f">>> remembered: {len(kept[0] or '')} characters; the tile shows {shown[:23] if shown else None}..., the device that is trusted presents {trusted[:23]}...")
    assert shown == trusted, "the fingerprint shown for the tile is of something no device presents, and the certificate inside it is trusted all the same"


def test_what_is_no_certificate_takes_nothing_from_the_ones_that_are() -> None:
    odd, _ = odd_certificate()
    dressed = "-----BEGIN CERTIFICATE-----" + chr(10) + "QUJD" * 16 + chr(10) + "-----END CERTIFICATE-----" + chr(10)
    devices: list[dict[str, object]] = [{"url": f"https://none{number}.example", "kind": "kvmd", "cert_pem": dressed} for number in range(exchange.MOST_ODD)]
    devices.append({"url": "https://kvm.example", "kind": "kvmd", "cert_pem": odd})
    content = read(devices)
    print(f">>> {exchange.MOST_ODD} entries that are no certificates, then one that OpenSSL reads: taken {[device.url for device in content.devices or []]}; the last line of what was left out: {content.left_out[-1:]}")
    assert [device.url for device in content.devices or []] == ["https://kvm.example"]


def test_one_certificate_on_many_devices_is_one_certificate() -> None:
    # A server's maker may have put one certificate on every board (core.identity says so); a wall of
    # seventy such servers writes all seventy into its file.
    odd, _ = odd_certificate()
    many = exchange.MOST_ODD + 6
    content = read([{"url": f"https://bmc{number}.example", "kind": "redfish", "cert_pem": odd, "password": "secret"} for number in range(many)])
    print(f">>> {many} servers with one certificate that only OpenSSL reads: read back {len(content.devices or [])}; left out {len(content.left_out)}, each with its password")
    assert len(content.devices or []) == many, content.left_out[:1]


def test_a_tile_from_a_file_shows_the_fingerprint_of_what_it_trusts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # End to end: the device is signed in to on the strength of the certificate at the front of the block,
    # and the tile, asked for its certificate, shows a fingerprint that is not the device's.
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")
    device = FakeKvm(tls_dir=tmp_path / "device").start()
    try:
        real = (tmp_path / "device" / "cert.pem").read_text(encoding="ascii")
        padded = ssl.DER_cert_to_PEM_cert(ssl.PEM_cert_to_DER_cert(real) + b"\x00" * 64)
        file = json.dumps({**F, "devices": [{"url": device.url, "kind": "kvmd", "name": "From the file", "password": "secret", "cert_pem": padded}]})
        with wall(tmp_path / "wall") as admin:
            took = admin.post("/api/v1/import", json={"file": file, "take": ["devices"]}).json()
            if took["devices"] == 0:
                return  # (refused: nothing is remembered)
            tile = admin.get("/api/v1/wall").json()["devices"][0]
            picture = admin.get(snap(tile["id"]))
            asked = admin.get(f"/api/v1/devices/{tile['id']}/certificate").json()
            # the same device, typed in at its other name: the form asks "the same device?" of one it knows
            again = admin.post("/api/v1/devices", json={"url": device.url.replace("127.0.0.1", "localhost"), "password": "secret", "kind": "kvmd", "tls": "pinned"})
        print(f">>> picture {picture.status_code}, signed in to {device.state.logins} time(s); remembered {asked['saved'][:23]}..., presented {asked['presented'][:23]}...; the same device typed in at another name: {again.status_code} {again.json().get('code', 'added as a second tile')}")
        assert picture.status_code == 200 and device.state.logins >= 1
        assert asked["saved"] == asked["presented"], "signed in to, with a picture, and the dialog says the device presents another certificate than the one remembered"
    finally:
        device.stop()
