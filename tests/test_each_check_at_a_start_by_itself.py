"""The checks at a start that no test held by itself, each asked alone; and three values that had no check.

Taking each check out in turn, with the tests run after each, showed six that could go unnoticed: two that
hid each other in one test (a port that is none is refused by the settings reader, and by the listener after
it), and four that nothing asked. And three values had no rule: what a token may be, how often the wall
looks, and an address to listen on that names a network interface.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any

import pytest

from qkvm import exchange, kvm, netbind, update, vault
from qkvm.netbind import BindError
from qkvm.store import Store, StoreError
from tests.test_wall import add, closed_port, wall
from tests.settings_file import settings_text, write_settings_text


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 2)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 2)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def saved_with(folder: Path, change: Any) -> None:
    """A wall with a device, a token for a script and a link for a screen; then both copies of its file, edited."""
    with wall(folder) as admin:
        add(admin, f"http://127.0.0.1:{closed_port()}", force=True, kind="kvmd", name="The one device")
        assert admin.post("/api/v1/tokens", json={"name": "a script", "role": "operator"}).status_code == 201
        assert admin.post("/api/v1/tokens", json={"name": "a screen", "kind": "display"}).status_code == 201
    for name in ("qkvm.json", "qkvm.bak"):
        saved = json.loads(settings_text(folder / name, encoding="utf-8"))
        change(saved)
        write_settings_text(folder / name, json.dumps(saved), encoding="utf-8")


def refused(folder: Path) -> str:
    """What the start says of the file; "" where it reads it."""
    try:
        Store(folder / "qkvm.json")
    except StoreError as ex:
        return str(ex)
    return ""


@pytest.mark.parametrize("port", [0, -1, 65536, 70000, 2**62])
def test_a_port_that_is_none_is_refused_by_the_reader_of_the_settings(tmp_path: Path, port: int) -> None:
    # (By that reader, in a sentence that names the field. The listener refuses such a port as well, later
    # and in other words: with one test for both, either could be taken out and the other answered for it.)
    saved_with(tmp_path, lambda saved: saved["server"].__setitem__("port", port))
    assert '"port" has to be a number from 1 to 65535' in refused(tmp_path)


@pytest.mark.parametrize("port", [-1, 65536, 10**20])
def test_and_by_the_listener_whoever_asks_it(port: int) -> None:
    with pytest.raises(BindError, match="cannot listen on 127"):
        netbind.open_sockets(["127.0.0.1"], port)


@pytest.mark.parametrize("address", ["http://kvm.invalid:0", "ftp://kvm.invalid", "kvm.invalid", "https://", "//kvm.invalid"])
def test_a_device_whose_address_has_no_port_to_speak_of_or_another_way_than_the_web_is_refused(tmp_path: Path, address: str) -> None:
    saved_with(tmp_path, lambda saved: saved["devices"][0].__setitem__("url", address))
    assert '"url" is not an address' in refused(tmp_path)


@pytest.mark.parametrize(
    ("kind", "address", "read"),
    [
        ("vnc", "vnc://kvm.invalid", True),  # (as vncdevice.vnc_url keeps one at the usual port, 5900)
        ("vnc", "vnc://192.168.1.20:5901", True),
        ("vnc", "vncs://[fd00::20]:5901", True),
        ("vnc", "VNC://kvm.invalid", True),  # (a scheme is the same in either case, to the reader and to the driver)
        ("vnc", "vnc://kvm.invalid:0", False),
        ("vnc", "vnc://", False),
        ("vnc", "ftp://kvm.invalid", False),
        ("kvmd", "vnc://kvm.invalid", False),
        ("jetkvm", "vncs://kvm.invalid", False),
        ("redfish", "vnc://kvm.invalid", False),
        ("amt", "vnc://kvm.invalid", False),
        ("proxmox", "vncs://kvm.invalid:8006/nodes/pve1/qemu/100", False),
    ],
)
def test_a_vnc_servers_address_is_read_back_where_the_tile_is_a_vnc_servers_and_only_there(tmp_path: Path, kind: str, address: str, read: bool) -> None:
    # A VNC server is kept at vnc:// or vncs:// (the Add box, the network search, an import): taken at a start for no
    # address, a wall with one did not start again (6d0bed7), nor did --disable-2fa or --reset-password run on it.
    saved_with(tmp_path, lambda saved: saved["devices"][0].update(kind=kind, url=address))
    said = refused(tmp_path)
    assert (said == "") is read, said
    if not read:
        assert '"url" is not an address' in said


def test_where_both_copies_are_refused_the_start_says_why_of_each(tmp_path: Path) -> None:
    # It said only why the first was: a second copy refused for another reason (or missing) was not told apart.
    saved_with(tmp_path, lambda saved: saved["devices"][0].update(url="vnc://kvm.invalid"))  # (no VNC server's tile)
    write_settings_text(tmp_path / "qkvm.json", "{", encoding="utf-8")
    said = refused(tmp_path)
    assert "qkvm.json cannot be read (Expecting" in said and 'qkvm.bak (the device' in said and '"url" is not an address' in said, said


def test_a_token_is_never_an_admin_whatever_the_file_says(tmp_path: Path) -> None:
    # No form makes one: what manages qKVM itself takes a person. Written into the file by hand, a token
    # for a script administered: accounts, devices, other tokens, on the strength of a key and no password.
    saved_with(tmp_path, lambda saved: saved["tokens"][0].__setitem__("role", "admin"))
    said = refused(tmp_path)
    assert '"role" has to be viewer or operator' in said and "token" in said
    # (And one that is none of the three is refused as an account's is.)
    saved_with(tmp_path / "other", lambda saved: saved["tokens"][0].__setitem__("role", "root"))
    assert '"role" has to be one of' in refused(tmp_path / "other")
    # An operator's token is what it was.
    saved_with(tmp_path / "third", lambda saved: None)
    assert refused(tmp_path / "third") == ""


@pytest.mark.parametrize(("written", "taken"), [(0, 0.2), (-1, 0.2), (0.05, 0.2), (0.2, 0.2), (1, 1.0), (60, 60.0), (3600, 60.0), (1e299, 60.0)])
def test_how_often_the_wall_looks_is_within_what_the_form_takes(tmp_path: Path, written: float, taken: float) -> None:
    # Written by hand as 0, every browser opened on "Paused"; as less than nothing, every browser asked for
    # pictures without a pause. No reason not to start: the nearest that makes sense is taken.
    saved_with(tmp_path, lambda saved: saved["server"].__setitem__("interval", written))
    assert refused(tmp_path) == ""
    with wall(tmp_path, sign_in=True) as admin:
        assert admin.get("/api/v1/wall").json()["interval"] == taken
        assert admin.get("/api/v1/settings").json()["interval"] == taken


ZONES_THAT_ARE_NONE = ["fe80::1%a\nb", "fe80::1%" + "x" * 3000, "fe80::1%\x00", "fe80::1%\ud800", "fe80::1%eth 0", "fe80::1%", "::1%;rm"]


@pytest.mark.parametrize("address", ZONES_THAT_ARE_NONE, ids=ascii)
def test_what_follows_the_percent_sign_of_an_address_is_the_name_of_an_interface(address: str) -> None:
    with pytest.raises(BindError) as said:
        netbind.normalize([address])
    assert len(str(said.value)) < 300  # (and the answer does not hand three thousand letters back)


@pytest.mark.parametrize("address", ["fe80::1%eth0", "fe80::1%12", "fe80::1%en0.100", "FE80::1%Wi-Fi_2", "::1", "192.0.2.7"])
def test_and_an_address_that_names_one_is_taken_as_before(address: str) -> None:
    assert netbind.normalize([address])[1:] == [address.lower()]


def test_an_address_the_system_will_not_listen_on_is_a_sentence_and_no_traceback(monkeypatch: pytest.MonkeyPatch) -> None:
    # The system's own reader of addresses says no by a TypeError or a ValueError (a NUL in the name, a name
    # that cannot be written in bytes), not by an error of its own. Unanswered, either ended the program as
    # it went to listen, at that start and at every one after it.
    says: list[Exception] = [TypeError("host name must not contain null character"), ValueError("encoding of hostname failed")]

    class Refusing(socket.socket):
        def bind(self, where: Any) -> None:
            raise says[0]

    port = closed_port()
    monkeypatch.setattr(socket, "socket", Refusing)
    while says:
        with pytest.raises(BindError, match="cannot listen on"):
            netbind.open_sockets(["127.0.0.1"], port)
        says.pop(0)


def length(written: bytes) -> bytes:
    """A value of one byte whose length is `written`, inside a sequence whose own length is right."""
    inside = b"\x04" + written + b"\x00"
    return b"\x30" + bytes([len(inside)]) + inside


def test_a_length_of_under_128_has_one_spelling_at_every_depth() -> None:
    # (0x81 0x01 says "one byte follows that holds the length, and it is 1": the same as 0x01, written longer.
    # No certificate a device presents has it, so no test with a real certificate came by here.)
    assert exchange._one_piece(length(b"\x01"))
    assert not exchange._one_piece(length(b"\x81\x01"))  # in more bytes than it takes
    assert not exchange._one_piece(length(b"\x82\x00\x01"))  # with a nought in front
    long = bytes(128)  # (and where the length does take a byte of its own: one, and not two with a nought in front)
    assert exchange._one_piece(b"\x30\x81\x83\x04\x81\x80" + long)
    assert not exchange._one_piece(b"\x30\x81\x84\x04\x82\x00\x80" + long)
    assert not exchange._one_piece(b"\x30\x81\x03\x04\x01\x00")  # and so for the outermost
    assert not exchange._one_piece(b"\x30\x03\x04\x01\x00\x00")  # nor anything after it
    assert not exchange._one_piece(b"\x30\x04\x04\x01\x00")  # nor less than it says
    deep = b"\x04\x01\x00"
    for _ in range(40):
        deep = b"\x30" + bytes([len(deep)]) + deep
    assert not exchange._one_piece(deep)  # (and no deeper than a certificate goes)
