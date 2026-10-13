"""A file's certificate whose length is written the long way round is none.

What a file gives as a certificate is kept as it was written only if it is one certificate and nothing
after it: kept with something after it, what the wall showed as its fingerprint was that of something no
device presents, while OpenSSL trusted the certificate inside.

The same held for a certificate whose length is written in more bytes than it takes (`30 83 00 LL LL`
where `30 82 LL LL` is the one way DER has): one piece by its own length, refused by the quick reader,
read by OpenSSL, and kept as written. The device was then signed in to and showed its picture, the
tile's dialog said it presents another certificate than the one remembered, and the wall did not know
the device again when it was added at its other address.
"""

from __future__ import annotations

import json
import ssl
from pathlib import Path

import pytest

from qkvm import exchange, kvm, update, vault
from tests.fake_kvm import FakeKvm
from tests.test_wall import snap, wall

F = {"format": exchange.FORMAT, "version": 1}


def the_long_way_round(pem: str) -> str:
    der = ssl.PEM_cert_to_DER_cert(pem)
    assert der[:2] == b"\x30\x82"
    return ssl.DER_cert_to_PEM_cert(b"\x30\x83\x00" + der[2:])


def test_a_tile_from_a_file_shows_the_fingerprint_of_what_it_trusts_however_its_length_is_written(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")
    device = FakeKvm(tls_dir=tmp_path / "device").start()
    try:
        real = (tmp_path / "device" / "cert.pem").read_text(encoding="ascii")
        odd = the_long_way_round(real)
        file = json.dumps({**F, "devices": [{"url": device.url, "kind": "kvmd", "name": "From the file", "password": "secret", "cert_pem": odd}]})
        with wall(tmp_path / "wall") as admin:
            took = admin.post("/api/v1/import", json={"file": file, "take": ["devices"]}).json()
            if took["devices"] == 0:
                print(f">>> a certificate whose length is written the long way round: not taken ({took['left_out']})")
                return  # (refused: nothing is remembered)
            tile = admin.get("/api/v1/wall").json()["devices"][0]
            picture = admin.get(snap(tile["id"]))
            asked = admin.get(f"/api/v1/devices/{tile['id']}/certificate").json()
            again = admin.post("/api/v1/devices", json={"url": device.url.replace("127.0.0.1", "localhost"), "password": "secret", "kind": "kvmd", "tls": "pinned"})
        print(f">>> one piece by its own length: {exchange._one_piece(ssl.PEM_cert_to_DER_cert(odd))}; picture {picture.status_code}, signed in to {device.state.logins} time(s)")
        print(f">>> remembered {asked['saved'][:23]}..., presented {asked['presented'][:23]}...; the same device typed in at its other name: {again.status_code} {again.json().get('code', 'added as a second tile')}")
        assert picture.status_code == 200 and device.state.logins >= 1
        assert asked["saved"] == asked["presented"], "signed in to, with a picture, and the dialog says the device presents another certificate than the one remembered"
    finally:
        device.stop()
