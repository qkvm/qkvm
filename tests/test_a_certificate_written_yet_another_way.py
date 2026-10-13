""""One way to write a length" was asked of one length.

A file's certificate was refused where its OUTERMOST length is written in more bytes than it takes
(`exchange._one_piece`). A certificate is three pieces in that one, and each has a length of its own. With
the length of the signature (or of the signature's algorithm) written the long way, and the outermost one
written the short way and right:

* the quick reader refuses it (it goes by the book), as before;
* `_one_piece` says it is one piece, written the one way;
* OpenSSL reads it, and takes the device's own certificate for the same one;
* so it is kept as written, the device is signed in to and shows its picture, and the fingerprint the wall
  shows as remembered is that of something no device presents. The dialog says the device presents another
  certificate than the one remembered, and the wall does not know the device again at its other address.

That is what tests/test_a_certificate_written_another_way.py describes, by another length.
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


def pieces(der: bytes) -> tuple[bytes, list[bytes]]:
    """(the outermost header, the pieces inside it, each with its own header)."""
    assert der[0] == 0x30 and der[1] == 0x82
    inside, found, at = der[4:], [], 0
    while at < len(inside):
        first = inside[at + 1]
        count = 0 if first < 0x80 else first & 0x7F
        length = first if first < 0x80 else int.from_bytes(inside[at + 2 : at + 2 + count], "big")
        end = at + 2 + count + length
        found.append(inside[at:end])
        at = end
    assert len(found) == 3 and at == len(inside)
    return der[:4], found


def the_long_way(piece: bytes) -> bytes:
    """The same piece, its length written in one byte more than it takes."""
    first = piece[1]
    if first < 0x80:
        return piece[:1] + b"\x81" + piece[1:]  # (LL -> 81 LL)
    count = first & 0x7F
    return piece[:1] + bytes([0x80 | (count + 1)]) + b"\x00" + piece[2:]  # (82 LL LL -> 83 00 LL LL)


def put_together(found: list[bytes]) -> bytes:
    inside = b"".join(found)
    assert 0x100 <= len(inside) <= 0xFFFF
    return b"\x30\x82" + len(inside).to_bytes(2, "big") + inside  # (the outermost length: the short way, and right)


@pytest.mark.parametrize("which", ["the signature", "the signature's algorithm"])
def test_a_certificate_with_an_inner_length_written_the_long_way_is_not_kept_as_written(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, which: str) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")
    device = FakeKvm(tls_dir=tmp_path / "device").start()
    try:
        real = (tmp_path / "device" / "cert.pem").read_text(encoding="ascii")
        _, found = pieces(ssl.PEM_cert_to_DER_cert(real))
        at = 2 if which == "the signature" else 1
        found[at] = the_long_way(found[at])
        odd_der = put_together(found)
        odd = ssl.DER_cert_to_PEM_cert(odd_der)
        assert odd_der != ssl.PEM_cert_to_DER_cert(real)
        file = json.dumps({**F, "devices": [{"url": device.url, "kind": "kvmd", "name": "From the file", "password": "secret", "cert_pem": odd}]})
        with wall(tmp_path / "wall") as admin:
            took = admin.post("/api/v1/import", json={"file": file, "take": ["devices"]}).json()
            print(f">>> {which} written the long way: one piece by its own word: {exchange._one_piece(odd_der)}; taken from the file: {took['devices']} device(s) {took['left_out']}")
            if took["devices"] == 0:
                return  # (refused: nothing is remembered that no device presents)
            tile = admin.get("/api/v1/wall").json()["devices"][0]
            picture = admin.get(snap(tile["id"]))
            asked = admin.get(f"/api/v1/devices/{tile['id']}/certificate").json()
            again = admin.post("/api/v1/devices", json={"url": device.url.replace("127.0.0.1", "localhost"), "password": "secret", "kind": "kvmd", "tls": "pinned"})
        print(f">>> picture {picture.status_code}, signed in to {device.state.logins} time(s); remembered {str(asked['saved'])[:23]}..., presented {str(asked['presented'])[:23]}...")
        print(f">>> the same device typed in at its other name: {again.status_code} {again.json().get('code', 'added as a second tile')}")
        if picture.status_code == 200:
            assert asked["saved"] == asked["presented"], "signed in to, with a picture, and the dialog says the device presents another certificate than the one remembered"
    finally:
        device.stop()
