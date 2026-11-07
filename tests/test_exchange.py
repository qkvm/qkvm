"""A wall's devices and settings as a file, and reading one back: what is in it, what never is, and what a file cannot make a wall do."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from qkvm import exchange, vault
from qkvm.exchange import Content, ExchangeError, gather, is_sealed, pack, unpack
from qkvm.store import ActionRecord, DeviceRecord, Store
from qkvm.vault import Vault, VaultLocked
from tests.fake_kvm import make_device_certificate

PASSPHRASE = "a passphrase for the file"


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)


def a_wall(tmp_path: Path) -> tuple[Store, Vault, str]:
    """A wall's settings with a KVM, a server and two saved actions, and the vault they are sealed with."""
    store, safe = Store(tmp_path / "qkvm.json"), Vault()
    safe.create("the admin's password")
    pem = make_device_certificate(tmp_path / "its-own")[0].read_text(encoding="ascii")
    store.devices = [
        DeviceRecord(id="a1b2c3d4", name="Rack KVM", url="https://192.168.1.20", username="admin", cert_pem=pem, secret=safe.encrypt("KVM-PASSWORD", "a1b2c3d4"), group="rack 1"),
        DeviceRecord(id="e5f6a7b8", name="db-01", url="https://192.168.1.30", username="root", kind="redfish", secret=safe.encrypt("BMC-PASSWORD", "e5f6a7b8"), ident="server:" + "ab" * 12, alerts=False),
        DeviceRecord(id="0a0b0c0d", name="Bench", url="http://192.168.1.40", kind="jetkvm", open_url="https://bench.example/", ident="own:a1b2c3d4"),
    ]
    store.actions = [
        ActionRecord(id="11112222", name="Lock the screen", kind="keys", keys="MetaLeft,KeyL"),
        ActionRecord(id="33334444", name="Unlock disk", kind="text", secret=safe.encrypt("THE-PASSPHRASE", "action:33334444"), enter=True, danger=True),
    ]
    store.alerts.enabled, store.alerts.webhook, store.alerts.link = True, safe.encrypt("https://hooks.example/T0KEN", "alerts:webhook"), "https://wall.example"
    store.server.interval = 2.0
    return store, safe, pem


SECRETS = ("KVM-PASSWORD", "BMC-PASSWORD", "THE-PASSPHRASE", "T0KEN")


def test_a_sealed_file_brings_everything_back_and_shows_nothing(tmp_path: Path) -> None:
    store, safe, pem = a_wall(tmp_path)
    text = pack(gather(store, safe, set(exchange.PARTS), secrets=True), PASSPHRASE, "0.1.0")
    # Nothing of the wall can be read off the file: not a password, and not a name or an address either.
    for word in (*SECRETS, "192.168.1.", "Rack KVM", "db-01", "Unlock disk", "hooks.example", "BEGIN CERTIFICATE"):
        assert word not in text, word
    assert is_sealed(text) and json.loads(text).keys() == {"format", "version", "lock", "sealed"}
    back = unpack(text, PASSPHRASE)
    assert back.sealed and back.secrets and back.program == "0.1.0" and back.made > 0 and back.left_out == []
    assert back.devices is not None and [(d.name, d.url, d.username, d.password, d.kind, d.group, d.tls, d.alerts) for d in back.devices] == [
        ("Rack KVM", "https://192.168.1.20", "admin", "KVM-PASSWORD", "kvmd", "rack 1", "pinned", True),
        ("db-01", "https://192.168.1.30", "root", "BMC-PASSWORD", "redfish", "", "pinned", False),
        ("Bench", "http://192.168.1.40", "admin", "", "jetkvm", "", "pinned", True),
    ]
    assert back.devices[0].cert_pem == pem and back.devices[2].open_url == "https://bench.example/"
    # What a device says it is goes along; that somebody decided "keep both" on the wall it comes from does not.
    assert [d.ident for d in back.devices] == ["", "server:" + "ab" * 12, ""]
    assert back.actions is not None and [(a.name, a.kind, a.keys, a.text, a.enter, a.danger) for a in back.actions] == [
        ("Lock the screen", "keys", "MetaLeft,KeyL", "", False, False),
        ("Unlock disk", "text", "", "THE-PASSPHRASE", True, True),
    ]
    assert back.alerts is not None and back.alerts["webhook"] == "https://hooks.example/T0KEN" and back.alerts["enabled"] is True
    assert "link" not in back.alerts  # the link an alert carries is the address of the wall it comes from: not a setting to take along
    # A tile that was told to stay beside its twin ("own:...") goes along as that word, not as the mark of the wall it was made on.
    assert [d.keep_both for d in back.devices] == [False, False, True]
    assert back.wall == {"interval": 2.0, "update_check": True}
    assert "KVM-PASSWORD" not in repr(back) and "THE-PASSPHRASE" not in repr(back)  # nor does what was read show them, printed


def test_the_password_of_a_tile_of_a_kind_this_version_does_not_know_is_not_opened_for_a_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # (0.3.0, section 5; a low of 0.2.1's final review.) A tile of a kind this version does not know (a later version's
    # settings, or a file written by hand) is no device it talks to, and a file of this version is refused it on the way
    # in; its password was opened and written into a file with secrets all the same. It is left out, and said to be.
    store, safe, _ = a_wall(tmp_path)
    store.devices.append(DeviceRecord(id="99aa88bb", name="Later", url="https://192.168.1.50", kind="later", secret=safe.encrypt("LATER-PASSWORD", "99aa88bb")))
    opened: list[str] = []
    real = safe.read

    def read(blob: Any, context: str) -> Any:
        opened.append(context)
        return real(blob, context)

    monkeypatch.setattr(safe, "read", read)
    not_opened: list[str] = []
    devices = gather(store, safe, {"devices"}, secrets=True, not_opened=not_opened)["devices"]
    assert [device["password"] for device in devices] == ["KVM-PASSWORD", "BMC-PASSWORD", "", ""]
    assert "99aa88bb" not in opened and not_opened == ["Later"], (opened, not_opened)


def test_a_plain_file_holds_no_secret_and_reads_without_a_passphrase(tmp_path: Path) -> None:
    store, safe, pem = a_wall(tmp_path)
    text = pack(gather(store, safe, set(exchange.PARTS), secrets=False), "", "0.1.0")
    for word in SECRETS:
        assert word not in text, word
    assert "password" not in text and "webhook" not in text and "Unlock disk" not in text  # not even a place for one; a saved text without its text is left out
    assert not is_sealed(text) and "Rack KVM" in text  # readable, and meant to be
    back = unpack(text, "")
    assert not back.sealed and not back.secrets and back.left_out == []
    assert back.devices is not None and [d.password for d in back.devices] == ["", "", ""] and back.devices[0].cert_pem == pem
    assert back.actions is not None and [a.name for a in back.actions] == ["Lock the screen"]
    assert back.alerts is not None and back.alerts["webhook"] == "" and "wall.example" not in text
    # Without secrets it can be made while nobody has signed in; with them it cannot.
    locked = Vault()
    assert gather(store, locked, {"devices"}, secrets=False)["devices"][0]["name"] == "Rack KVM"
    with pytest.raises(VaultLocked):
        gather(store, locked, {"devices"}, secrets=True)


def test_only_what_was_asked_for_is_in_the_file(tmp_path: Path) -> None:
    store, safe, _ = a_wall(tmp_path)
    back = unpack(pack(gather(store, safe, {"devices"}, secrets=True), PASSPHRASE, "0.1.0"), PASSPHRASE)
    assert back.devices is not None and len(back.devices) == 3 and back.actions is None and back.alerts is None and back.wall is None
    back = unpack(pack(gather(store, safe, {"actions", "wall"}, secrets=False), "", "0.1.0"), "")
    assert back.devices is None and back.actions is not None and back.wall is not None and back.alerts is None


def refused(text: str, passphrase: str = "") -> str:
    with pytest.raises(ExchangeError) as error:
        unpack(text, passphrase)
    return error.value.code


def test_a_file_that_is_not_one_or_does_not_open_is_said_as_what_it_is(tmp_path: Path) -> None:
    store, safe, _ = a_wall(tmp_path)
    text = pack(gather(store, safe, set(exchange.PARTS), secrets=True), PASSPHRASE, "0.1.0")
    assert refused(text) == "passphrase_needed"
    assert refused(text, "another passphrase") == "wrong_passphrase"
    said = json.loads(text)
    for change in ({"format": "something-else"}, {"version": "1"}, {"version": 0}, {"version": True}):
        assert refused(json.dumps({**said, **change}), PASSPHRASE) == "not_a_file", change
    assert refused(json.dumps({**said, "version": exchange.VERSION + 1}), PASSPHRASE) == "newer"
    for nothing in ("", "[]", "{}", '"qkvm-export"', "not json at all", "[" * 100_000):
        assert refused(nothing, PASSPHRASE) == "not_a_file", nothing[:20]
    assert refused(" " * (exchange.MAX_SEALED + 1), PASSPHRASE) == "too_large"
    # Changed after it was made (one character of what is sealed, or what it is sealed for): it does not open as something else.
    data = said["sealed"]["data"]
    assert refused(json.dumps({**said, "sealed": {**said["sealed"], "data": ("B" if data[0] == "A" else "A") + data[1:]}}), PASSPHRASE) == "damaged"
    assert refused(json.dumps({**said, "sealed": said["lock"]["key"]}), PASSPHRASE) == "damaged"  # the file's own key, put where the content goes
    for lock in (None, {}, {"kdf": {}}, {**said["lock"], "kdf": {**said["lock"]["kdf"], "n": 2**20, "r": 8}}):
        assert refused(json.dumps({**said, "lock": lock}), PASSPHRASE) == "wrong_passphrase"  # (and no more work than a wrong password is)
    # A device's password of the wall it came from does not open as a file's content, nor the other way round.
    assert refused(json.dumps({**said, "sealed": store.devices[0].secret}), PASSPHRASE) == "damaged"


def read(parts: dict[str, Any]) -> Content:
    return unpack(json.dumps({"format": exchange.FORMAT, "version": 1, **parts}), "")


def test_what_does_not_pass_is_left_out_and_said_and_the_rest_is_read(tmp_path: Path) -> None:
    good = {"url": "https://192.168.1.20", "kind": "kvmd"}
    odd: list[Any] = [
        good,
        {**good, "url": "https://192.168.1.20"},  # the same address twice
        {**good, "url": "192.168.1.21"},  # written by qKVM, an address says how it is talked to
        {**good, "url": "https://user:pw@192.168.1.22"},
        {**good, "url": "ftp://192.168.1.23"},
        {**good, "url": "https://192.168.1.24", "kind": "something-new"},
        {**good, "url": "https://192.168.1.25", "tls": "trust-everything"},
        {**good, "url": "https://192.168.1.26", "name": "x" * 81},
        {**good, "url": "https://192.168.1.27", "name": "two\nlines"},
        {**good, "url": "https://192.168.1.28", "password": 12345},
        {**good, "url": "https://192.168.1.29", "cert_pem": "-----BEGIN CERTIFICATE-----\nnot one\n-----END CERTIFICATE-----\n"},
        {**good, "url": "https://192.168.1.30", "open_url": "javascript:alert(1)"},
        {**good, "url": "https://192.168.1.31", "group": "g" * 41},
        "not an entry",
        {**good, "url": "https://192.168.1.32", "id": "action:33334444", "secret": {"nonce": "x", "data": "y"}, "name": "  Spaced  ", "ident": "own:a1b2c3d4", "alerts": "yes"},
    ]
    back = read({"devices": odd})
    assert back.devices is not None and [d.url for d in back.devices] == ["https://192.168.1.20", "https://192.168.1.32"]
    assert len(back.left_out) == 13 and all(line.startswith("Device ") for line in back.left_out)
    last = back.devices[1]
    # What a file says beyond what an entry is made of (an id, something sealed) is not looked at at all.
    assert (last.name, last.ident, last.alerts, last.password, last.username) == ("Spaced", "", True, "", "admin")
    assert back.devices[0].name == "192.168.1.20"  # no name given: its address, as when it is added by hand
    # Over plain HTTP there is no certificate to check, whatever the file says about one.
    plain = read({"devices": [{"url": "http://192.168.1.40", "kind": "jetkvm", "tls": "insecure", "cert_pem": "x"}]})
    assert plain.devices is not None and (plain.devices[0].tls, plain.devices[0].cert_pem) == ("pinned", None)

    actions = read({"actions": [
        {"name": "Lock", "kind": "keys", "keys": "MetaLeft,KeyL"},
        {"name": "Lock", "kind": "keys", "keys": "not a key name"},
        {"name": "Type", "kind": "text", "text": ""},
        {"name": "Type", "kind": "text", "text": "x" * 2001},
        {"name": "", "kind": "keys", "keys": "KeyA"},
        {"name": "Run", "kind": "script", "text": "rm -rf /"},
        {"name": "Hello", "kind": "text", "text": "hello", "enter": True, "keys": "KeyA"},
    ]})  # fmt: skip
    assert actions.actions is not None and [(a.name, a.kind, a.keys, a.text, a.enter) for a in actions.actions] == [("Lock", "keys", "MetaLeft,KeyL", "", False), ("Hello", "text", "", "hello", True)]
    assert len(actions.left_out) == 5

    settings = read({"alerts": {"enabled": "yes", "format": "carrier-pigeon", "webhook": "file:///etc/passwd", "link": "not an address"}, "wall": {"interval": 0.001, "update_check": "no"}})
    assert settings.alerts == {"enabled": False, "format": "auto", "offline": True, "no_signal": True, "problem": True, "recovered": True, "webhook": ""}
    assert settings.wall == {} and len(settings.left_out) == 2
    for not_parts in ({"devices": {}}, {"actions": "x"}, {"alerts": []}, {"wall": 7}):
        assert read(not_parts).left_out, not_parts


def test_a_file_made_by_hand_may_hold_passwords_in_plain_text_and_that_is_seen() -> None:
    # A list of devices written by hand, to fill a new wall in one go: whoever writes passwords into it has chosen to.
    back = read({"devices": [{"url": "https://192.168.1.20", "kind": "kvmd", "password": "typed by hand"}]})
    assert back.devices is not None and back.devices[0].password == "typed by hand" and back.secrets and not back.sealed


def test_more_than_a_wall_holds_is_not_read_to_its_end() -> None:
    many = [{"url": f"https://kvm{number}.example", "kind": "kvmd"} for number in range(exchange.MOST_DEVICES + 5)]
    back = read({"devices": many})
    assert back.devices is not None and len(back.devices) == exchange.MOST_DEVICES and len(back.left_out) == 1


def test_half_a_character_is_no_file_and_what_is_not_printed_is_no_name() -> None:
    # A file can spell out half of a character ("\\ud800" by itself). Read, it is text that can be written
    # nowhere again: saved as a tile's console link, no browser could be sent the list of tiles any more.
    for where in ("name", "username", "group", "open_url", "password"):
        file = json.dumps({"format": exchange.FORMAT, "version": 1, "devices": [{"url": "https://192.168.1.20", "kind": "kvmd", where: "x\ud800"}]})
        assert "\\ud800" in file and refused(file) == "not_a_file", where
    sealed_in = pack({"actions": [{"name": "type", "kind": "text", "text": "x\ud800"}]}, PASSPHRASE, "0.1.0")
    assert refused(sealed_in, PASSPHRASE) == "damaged"
    # Nor is a name one that has in it a mark that turns the writing round. A blank of no width is left out
    # of the name it is in, as the blanks around a name are: the device is taken, under the name it reads as.
    odd = read({"devices": [{"url": "https://192.168.1.20", "kind": "kvmd", "name": "Rack\u202e KVM"}, {"url": "https://192.168.1.21", "kind": "kvmd", "group": "rack\u200b1"}]})
    assert [(device.url, device.group) for device in odd.devices or []] == [("https://192.168.1.21", "rack1")] and len(odd.left_out) == 1


def test_an_intel_amt_pc_written_without_a_port_is_taken_at_its_engines_port_as_an_add_takes_it() -> None:
    # Register row 12 of 0.2.1 (w11c Open): added or edited without a port, an engine is at 16993 with TLS and 16992
    # plain, where it answers (server.py's parse); a hand-written file's entry without one was kept at 443 or 80, where
    # no engine answers and its redirection port is not known. A port that is written stays, 443 too, as in the form.
    said = read({"devices": [
        {"url": "https://192.168.1.30", "kind": "amt"},
        {"url": "http://192.168.1.31/", "kind": "amt"},
        {"url": "https://192.168.1.32:443", "kind": "amt"},
        {"url": "https://192.168.1.33:16993", "kind": "amt"},
        {"url": "https://[fe80::5]", "kind": "amt"},
        {"url": "https://192.168.1.34", "kind": "kvmd"},
    ]})  # fmt: skip
    assert said.left_out == []
    assert [device.url for device in said.devices or []] == [
        "https://192.168.1.30:16993", "http://192.168.1.31:16992", "https://192.168.1.32", "https://192.168.1.33:16993",
        "https://[fe80::5]:16993", "https://192.168.1.34",
    ]  # fmt: skip


def test_a_console_link_is_kept_with_its_host_written_as_a_device_address_is() -> None:
    # I2 of the 0.2.1 review (pulled back into 0.2.1): the page and the server say whether a console link is on a host name
    # the wall is looked at under, and spelt that host differently: a browser reads 2130706433 or 127.1 as 127.0.0.1, Python
    # as no such thing, and a dot at the end of a name was the server's to drop and not the page's. The link is kept with
    # its host as an address is (small letters, no dot at the end, numbers one way, and none the system would read as
    # another host than it looks like), so that both read the same host from it. What follows the host is kept as typed.
    from qkvm.exchange import console_link

    for typed, kept in (
        ("https://KVM.Example.:8443/Some/Page?x=1#y", "https://kvm.example:8443/Some/Page?x=1#y"),
        ("https://kvm.example:443/a", "https://kvm.example/a"), ("http://kvm.example:80", "http://kvm.example"),
        ("https://[0:0:0:0:0:0:0:1]:9443/", "https://[::1]:9443/"), ("  http://192.168.1.20:8080/x  ", "http://192.168.1.20:8080/x"),
        ("https://bücher.example/", "https://xn--bcher-kva.example/"), ("", ""),
    ):  # fmt: skip
        assert console_link(typed) == kept, typed
    for none in ("http://2130706433/", "http://127.1:8080/", "https://0x7f.0.0.1/", "http://010.1.1.1/", "https://kvm.example:0/", "https://./"):
        with pytest.raises(ValueError):
            console_link(none)


def test_an_address_is_written_one_way() -> None:
    from qkvm.store import device_url

    for written, one in (
        ("HTTPS://KVM.Example", "https://kvm.example"), ("kvm.example:443", "https://kvm.example"), ("https://kvm.example:", "https://kvm.example"),
        ("https://kvm.example.:0443/", "https://kvm.example"), ("http://kvm.example:80", "http://kvm.example"), ("https://kvm.example:8443", "https://kvm.example:8443"),
        ("http://kvm.example:443", "http://kvm.example:443"), ("[FE80::1]:8443", "https://[fe80::1]:8443"), ("192.168.1.20", "https://192.168.1.20"),
        ("[0:0:0:0:0:0:0:1]", "https://[::1]"), ("[::0:1]:8443", "https://[::1]:8443"), ("http://[2001:DB8:0:0::7]", "http://[2001:db8::7]"),
    ):  # fmt: skip
        assert device_url(written) == one, written
    # Numbers that the system would read as another host than they look like, or that the library which has
    # to connect refuses: saved (a file was never connected to), every look at such a tile was an error inside
    # the program, with a page in the log.
    for none in ("127.1", "http://10.01.000.001", "https://999.1.1.1", "2130706433", "0x7f.0.0.1", "https://xn--", "https://1.2.3.4.5"):
        with pytest.raises(ValueError):
            device_url(none)
    for none in ("https://@kvm.example", "https://:@kvm.example", "https://user:pw@kvm.example", "https://kvm.example:0", "https://.", "https://kvm.example:99999"):
        with pytest.raises(ValueError):
            device_url(none)
