"""What a wall writes into a file, it reads back from it: beside the characters of a name.

* A device whose certificate OpenSSL takes and the `cryptography` library does not. The wall remembers a
  device's certificate without ever reading it with that library (kvm.fingerprint, kvm.pinned_context are
  OpenSSL's); a file was read with it. Here: an extension whose "critical: FALSE" is written out, which
  DER says to leave out and which firmware that builds its certificate by hand writes all the same. Such
  a device was on the wall, with a picture, was written into the file with its password, and was left
  out when the file was read.
* A device named by its address, where the address is longer than a name may be (the form's 80).
* A saved action whose name is a blank: the form took it (one character) and kept "", which no file is read with.
* A user name that is a blank: taken, kept as "", and read back as "admin".
* A count: a wall that holds more than a file is written for is told which part that is, and how many.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any

import pytest

from qkvm import exchange, kvm, update, vault
from tests.fake_kvm import FakeKvm
from tests.test_wall import PASSWORD, add, closed_port, snap, wall

PASSPHRASE = "a passphrase for the file"
F = {"format": exchange.FORMAT, "version": 1}


# --- a certificate with "critical: FALSE" written out ---


def _length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _read(der: bytes, at: int) -> tuple[int, int, int]:
    """(tag, where the content starts, where it ends) of the element at `at`."""
    first = der[at + 1]
    if first < 0x80:
        return der[at], at + 2, at + 2 + first
    count = first & 0x7F
    return der[at], at + 2 + count, at + 2 + count + int.from_bytes(der[at + 2 : at + 2 + count], "big")


def _children(der: bytes, start: int, end: int) -> list[tuple[int, int, int, int]]:
    found, at = [], start
    while at < end:
        tag, inner, stop = _read(der, at)
        found.append((tag, at, inner, stop))
        at = stop
    return found


def _wrap(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _length(len(content)) + content


def odd_certificate() -> tuple[str, str]:
    """(certificate, key) as PEM: self-signed, with "critical: FALSE" written into its one extension.

    Its signature is wrong after that, which nobody looks at in a certificate that is trusted for being
    this very one (OpenSSL does not, and neither does the wall).
    """
    import datetime
    import ssl

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    made = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )  # fmt: skip
    der = made.public_bytes(serialization.Encoding.DER)
    _, c0, c1 = _read(der, 0)
    _, _, tbs_in, tbs_end = _children(der, c0, c1)[0]
    tag, ext_at, ext_in, ext_end = _children(der, tbs_in, tbs_end)[-1]
    assert tag == 0xA3
    _, _, seq_in, seq_end = _children(der, ext_in, ext_end)[0]
    (_, _, inner, stop), = _children(der, seq_in, seq_end)
    oid, value = _children(der, inner, stop)
    extension = _wrap(0x30, der[oid[1] : oid[3]] + bytes([0x01, 0x01, 0x00]) + der[value[1] : value[3]])
    tbs = _wrap(0x30, der[tbs_in:ext_at] + _wrap(0xA3, _wrap(0x30, extension)))
    odd = ssl.DER_cert_to_PEM_cert(_wrap(0x30, tbs + der[tbs_end:c1]))
    with pytest.raises(ValueError):
        x509.load_pem_x509_certificate(odd.encode("ascii"))  # (the library a file is read with does not take it)
    ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=odd)  # (OpenSSL does)
    return odd, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def test_a_device_whose_certificate_the_wall_remembers_is_read_back_from_the_walls_own_file(tmp_path: Path) -> None:
    odd, key = odd_certificate()
    (tmp_path / "device").mkdir()
    (tmp_path / "device" / "cert.pem").write_text(odd, encoding="ascii")
    (tmp_path / "device" / "key.pem").write_text(key, encoding="ascii")
    device = FakeKvm(tls_dir=tmp_path / "device").start()
    try:
        with wall(tmp_path / "one") as admin:
            tile = add(admin, device.url, name="Build server")
            picture = admin.get(snap(tile))
            assert picture.status_code == 200, picture.text  # on the wall, signed in to, with a picture
            assert admin.core.store.devices[0].cert_pem, "no certificate was remembered"  # type: ignore[attr-defined]
            made = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": PASSPHRASE, "parts": ["devices"]})
            assert made.status_code == 200 and made.headers["x-qkvm-not-opened"] == "0"
    finally:
        device.stop()
    with wall(tmp_path / "two") as other:
        there = other.post("/api/v1/import/read", json={"file": made.text, "passphrase": PASSPHRASE}).json()
    print(f">>> a device with a certificate OpenSSL takes: on the wall with a picture; its own file read back: {len(there['devices'])} of 1 devices; left out: {there['left_out']}")
    assert [entry["name"] for entry in there["devices"]] == ["Build server"], f"the wall's own file was read without the device, and its password: {there['left_out']}"


def test_a_device_named_by_its_address_is_read_back_from_the_walls_own_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Added without a name, a device that does not say one is named by its address (server.create_device).
    # An address may be 255 characters, a name 80. (Every name leads to this computer here: nothing is asked of a name server.)
    def here(host: Any, port: Any, *more: Any, **named: Any) -> list[Any]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", int(port or 0)))]

    monkeypatch.setattr(socket, "getaddrinfo", here)
    address = f"kvm-rack12-u07.mgmt.datacenter-frankfurt-2.infrastructure.example-company.com:{closed_port()}"
    with wall(tmp_path / "one") as admin:
        tile = add(admin, f"http://{address}", force=True, kind="kvmd")
        name = next(entry["name"] for entry in admin.get("/api/v1/wall").json()["devices"] if entry["id"] == tile)
        assert len(address) > 80 and name == address[:80]  # (cut to what a name may be)
        edit = admin.put(f"/api/v1/devices/{tile}", json={"name": name, "url": f"http://{address}", "group": "Rack 12", "force": True})
        made = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": PASSPHRASE, "parts": ["devices"]})
        assert made.status_code == 200
    with wall(tmp_path / "two") as other:
        there = other.post("/api/v1/import/read", json={"file": made.text, "passphrase": PASSPHRASE}).json()
    print(f">>> a device named by its address ({len(name)} characters): an edit that only sets its group answered {edit.status_code} {edit.text[:90]}; read back: {len(there['devices'])} of 1; left out: {there['left_out']}")
    assert [entry["name"] for entry in there["devices"]] == [name], f"the wall's own file was read without the device, and its password: {there['left_out']}"


def test_a_saved_action_the_form_took_is_read_back_from_the_walls_own_file(tmp_path: Path) -> None:
    with wall(tmp_path / "one") as admin:
        taken = admin.post("/api/v1/actions", json={"name": " ", "kind": "keys", "keys": "MetaLeft,KeyL"})
        assert taken.status_code in (201, 422)
        if taken.status_code == 422:
            return  # (refused by the form: then there is nothing to read back)
        made = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": "", "parts": ["actions"]})
    with wall(tmp_path / "two") as other:
        there = other.post("/api/v1/import/read", json={"file": made.text}).json()
    print(f">>> a saved action named with a blank: taken by the form as {taken.json()['action']['name']!r}; read back: {len(there['actions'])} of 1; left out: {there['left_out']}")
    assert len(there["actions"]) == 1, f"the form took it, the file holds it, and the file's reader does not: {there['left_out']}"


def test_a_user_name_the_form_took_is_read_back_as_it_was(tmp_path: Path) -> None:
    with wall(tmp_path / "one") as admin:
        taken = admin.post("/api/v1/devices", json={"url": f"http://127.0.0.1:{closed_port()}", "kind": "kvmd", "name": "KVM", "username": " ", "password": "secret", "force": True})
        assert taken.status_code in (201, 422), taken.text
        if taken.status_code == 422:
            return
        kept = admin.core.store.devices[0].username  # type: ignore[attr-defined]
        made = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": PASSPHRASE, "parts": ["devices"]})
    back = exchange.unpack(made.text, PASSPHRASE)
    print(f">>> a user name that is a blank: kept on the wall as {kept!r}, read back from the wall's own file as {[device.username for device in back.devices or []]}")
    assert [device.username for device in back.devices or []] == [kept]


def test_a_wall_that_took_in_two_files_can_still_be_written_into_one(tmp_path: Path) -> None:
    # Two files of saved actions, each as large as a file may be, taken in one after the other (what a
    # file adds is added to what is there). After that no file holds all of the wall, as the export dialog
    # asks for one with everything ticked: the answer says which part is too much, and by how many, and
    # the rest is written without it.
    def file(first: int) -> str:
        return json.dumps({**F, "actions": [{"name": f"Action {number}", "kind": "keys", "keys": "KeyA"} for number in range(first, first + exchange.MOST_ACTIONS)]})

    with wall(tmp_path) as admin:
        add(admin, f"http://127.0.0.1:{closed_port()}", force=True, kind="kvmd", name="The one device")
        for first in (0, exchange.MOST_ACTIONS):
            took = admin.post("/api/v1/import", json={"file": file(first), "take": ["actions"]})
            assert took.status_code == 200 and took.json()["actions"] == exchange.MOST_ACTIONS, took.text[:200]
        everything = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": PASSPHRASE, "parts": ["devices", "actions", "alerts", "wall"]})
        devices_only = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": PASSPHRASE, "parts": ["devices"]})
    print(f">>> a wall of 1 device and {2 * exchange.MOST_ACTIONS} saved actions: export of everything {everything.status_code} {everything.text[:120]!r}; of the devices alone {devices_only.status_code}")
    assert everything.status_code == 422 and everything.json()["code"] == "too_large", everything.text[:200]
    assert f"{2 * exchange.MOST_ACTIONS} saved actions" in everything.json()["message"] and str(exchange.MOST_ACTIONS) in everything.json()["message"]
    assert devices_only.status_code == 200


def test_so_many_different_certificates_of_one_file_are_tried_the_slow_way_and_no_more(monkeypatch: pytest.MonkeyPatch) -> None:
    # A certificate that only OpenSSL reads costs a quarter of a millisecond to find out about, on the thread
    # there is one of; a file may hold two thousand. So many different ones of a file are asked about, and
    # the rest are none: said for each, like everything else that is left out. (Three, here.)
    monkeypatch.setattr(exchange, "MOST_ODD", 3)
    several = [odd_certificate()[0] for _ in range(5)]
    assert len(set(several)) == 5
    file = json.dumps({**F, "devices": [{"url": f"https://kvm{number}.example", "kind": "kvmd", "cert_pem": odd} for number, odd in enumerate(several)]})
    read = exchange.unpack(file, "")
    assert [device.url for device in read.devices or []] == [f"https://kvm{number}.example" for number in range(3)] and len(read.left_out) == 2
    assert all("its certificate is not one" in line for line in read.left_out)
    # One that many devices share (a maker's, on every board of a rack) is asked once, and is one of the three.
    shared = json.dumps({**F, "devices": [{"url": f"https://board{number}.example", "kind": "kvmd", "cert_pem": several[0]} for number in range(70)]})
    read = exchange.unpack(shared, "")
    assert len(read.devices or []) == 70 and read.left_out == []
    # What is no certificate at all, in the dress of one, is found out before anything is asked: it takes
    # nothing from the ones that are.
    dressed = "-----BEGIN CERTIFICATE-----" + chr(10) + "QUJD" * 16 + chr(10) + "-----END CERTIFICATE-----" + chr(10)
    devices = [{"url": f"https://none{number}.example", "kind": "kvmd", "cert_pem": dressed} for number in range(5)]
    devices += [{"url": f"https://kvm{number}.example", "kind": "kvmd", "cert_pem": odd} for number, odd in enumerate(several[:3])]
    read = exchange.unpack(json.dumps({**F, "devices": devices}), "")
    assert [device.url for device in read.devices or []] == [f"https://kvm{number}.example" for number in range(3)] and len(read.left_out) == 5
