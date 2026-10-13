"""One device, one tile: a KVM that is reachable by two addresses is known to be the same one."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from qkvm import discover, kvm, redfish, update, vault
from qkvm.core import identity
from qkvm.discover import Target, once
from qkvm.redfish import own_number
from qkvm.store import DeviceRecord
from tests.fake_kvm import FakeKvm, FakeState, make_device_certificate
from tests.fake_redfish import BmcState, FakeBmc
from tests.test_users import account, browser
from tests.test_wall import add, snap, wait_until, wall

NOWHERE = "http://127.0.0.1:9"


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "FRAME_MIN_AGE", 0)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(redfish, "FOLLOW_UP", ())
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def comet(tmp_path: Path) -> Iterator[FakeKvm]:
    """A KVM with a certificate of its own making, as they come. It answers at 127.0.0.1 and, the same one, at localhost."""
    server = FakeKvm(FakeState(), tls_dir=tmp_path / "its-certificate").start()
    yield server
    server.stop()


def by_name(server: FakeKvm | FakeBmc) -> str:
    """The other address of the same device: its name, where `server.url` has its number."""
    return server.url.replace("127.0.0.1", "localhost")


def listed(client: object) -> list[dict]:
    return list(client.get("/api/v1/wall").json()["devices"])  # type: ignore[attr-defined]


def test_a_kvm_is_not_put_on_the_wall_twice_without_being_asked(tmp_path: Path, comet: FakeKvm) -> None:
    # What happened on a real wall: three KVMs added under their address on the network and, the same three,
    # under their address on the VPN. Sixteen pictures a second were then fetched from each of them twice.
    with wall(tmp_path / "data") as client:
        first = add(client, comet.url, name="Rack KVM")
        again = client.post("/api/v1/devices", json={"url": by_name(comet), "password": "secret"})
        assert again.status_code == 409
        host = comet.url.split("//")[1]
        assert again.json() == {
            "code": "same_device",
            "message": f"This is the same device as Rack KVM, which is on the wall already ({host})",
            "same_as": {"id": first, "name": "Rack KVM", "host": host},
        }
        assert [device["id"] for device in listed(client)] == [first]  # nothing was added
        # "Use this address instead": the tile that is there is given the new address, and is still one tile.
        moved = client.put(f"/api/v1/devices/{first}", json={"url": by_name(comet), "password": "secret"})
        assert moved.status_code == 200 and moved.json()["device"]["url"] == by_name(comet)
        assert [(device["id"], device["same_as"]) for device in listed(client)] == [(first, [])]
        assert client.get(snap(first)).status_code == 200


def test_whoever_wants_both_gets_both_and_is_not_asked_again(tmp_path: Path, comet: FakeKvm) -> None:
    with wall(tmp_path / "data") as client:
        first = add(client, comet.url)
        second = client.post("/api/v1/devices", json={"url": by_name(comet), "password": "secret", "keep_both": True})
        assert second.status_code == 201
        devices = listed(client)
        assert len(devices) == 2 and [device["same_as"] for device in devices] == [[], []]  # said to be two: treated as two
        for device in devices:
            assert client.get(snap(device["id"])).status_code == 200
        assert first != second.json()["device"]["id"]
    with wall(tmp_path / "data") as client:  # and it stays that way over a restart
        assert [device["same_as"] for device in listed(client)] == [[], []]


def test_tiles_that_were_added_twice_before_are_pointed_out_for_somebody_to_decide(tmp_path: Path, comet: FakeKvm) -> None:
    with wall(tmp_path / "data") as client:
        first = add(client, comet.url, name="by number")
        second = client.post("/api/v1/devices", json={"url": by_name(comet), "password": "secret", "name": "by name", "keep_both": True}).json()["device"]["id"]
        for record in client.core.store.devices:  # type: ignore[attr-defined]
            record.ident = ""  # as on a wall where both were added before anything looked
        twins = {device["id"]: device["same_as"] for device in listed(client)}
        host = comet.url.split("//")[1]
        assert twins[first] == [{"id": second, "name": "by name", "host": host.replace("127.0.0.1", "localhost")}]
        assert twins[second] == [{"id": first, "name": "by number", "host": host}]
        # An account that may see only one of them is told nothing about the other.
        account(client, "victor", "viewer", devices=[first])
        assert [(device["id"], device["same_as"]) for device in listed(browser(client, "victor"))] == [(first, [])]
        # "Keep both", said of one of them, settles it for the pair.
        kept = client.put(f"/api/v1/devices/{second}", json={"url": by_name(comet), "keep_both": True})
        assert kept.status_code == 200 and [device["same_as"] for device in listed(client)] == [[], []]
        # Or one of them is removed, and the other is simply a tile.
        for record in client.core.store.devices:  # type: ignore[attr-defined]
            record.ident = ""
        assert client.delete(f"/api/v1/devices/{second}").status_code == 200
        assert [(device["id"], device["same_as"]) for device in listed(client)] == [(first, [])]


def test_two_kvms_are_two_however_alike(tmp_path: Path, comet: FakeKvm) -> None:
    other = FakeKvm(FakeState(), tls_dir=tmp_path / "another-certificate").start()  # same make, same firmware, same name: its own certificate
    try:
        with wall(tmp_path / "data") as client:
            add(client, comet.url)
            add(client, other.url)
            assert [device["same_as"] for device in listed(client)] == [[], []]
    finally:
        other.stop()


def test_what_makes_a_device_the_one_it_is(tmp_path: Path) -> None:
    pem = make_device_certificate(tmp_path / "its-own")[0].read_text(encoding="ascii")
    # (What is remembered and is no certificate is no mark to know a device by.)
    assert identity(DeviceRecord(id="a1", name="x", url="https://192.168.1.20", cert_pem=kvm.ssl.DER_cert_to_PEM_cert(b"not much of a certificate"))) is None

    def device(**how: object) -> DeviceRecord:
        return DeviceRecord(id="a1", name="x", url="https://192.168.1.20", **how)  # type: ignore[arg-type]

    assert identity(device(cert_pem=pem)) == kvm.certificate_mark(pem) and identity(device(cert_pem=pem)).startswith("cert:")  # type: ignore[union-attr]
    assert identity(device()) is None  # nothing remembered yet
    # Behind somebody's front door the certificate is the door's, and every device behind it shows the same.
    assert identity(device(cert_pem=pem, tls="system")) is None and identity(device(cert_pem=pem, tls="insecure")) is None
    # A server's controller may carry the certificate its maker put on every board: a server is known by its own number.
    assert identity(device(cert_pem=pem, kind="redfish")) is None
    assert identity(device(cert_pem=pem, kind="redfish", ident="server:0123456789abcdef")) == "server:0123456789abcdef"
    assert identity(device(cert_pem=pem, ident="own:a1")) == "own:a1"  # said to be a device of its own: that settles it


def test_a_server_is_known_by_its_own_number(tmp_path: Path) -> None:
    number = "4c4c4544-0042-3510-8054-b9c04f4a3532"
    assert own_number({"UUID": number}) == own_number({"UUID": number.upper()}) and own_number({"UUID": number}).startswith("server:")  # type: ignore[union-attr]
    assert number not in str(own_number({"UUID": number}))  # compared, never shown: kept as a digest
    for none in ("00000000-0000-0000-0000-000000000000", "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF", "not a number at all", "", None, 7):
        assert own_number({"UUID": none}) is None, none
    one = FakeBmc(BmcState(uuid=number)).start()
    same_make = FakeBmc(BmcState(uuid="4c4c4544-0042-3510-8054-c7c04f4a3533")).start()
    unset_a, unset_b = FakeBmc(BmcState(uuid="00000000-0000-0000-0000-000000000000")).start(), FakeBmc(BmcState(uuid="00000000-0000-0000-0000-000000000000")).start()
    try:
        with wall(tmp_path) as client:
            added = client.post("/api/v1/devices", json={"url": one.url, "password": "secret", "name": "db-01"})
            assert added.status_code == 201 and "ident" not in added.json()["about"]  # for telling it apart, not for the page
            again = client.post("/api/v1/devices", json={"url": by_name(one), "password": "secret", "kind": "redfish"})
            assert (again.status_code, again.json()["code"], again.json()["same_as"]["name"]) == (409, "same_device", "db-01")
            # The sign-in that found this out was given back; the one the tile lives on is its own.
            assert (one.state.logins, one.state.signed_out, len(one.state.tokens)) == (2, 1, 1)
            add(client, same_make.url)  # another server of the same make is another server
            add(client, unset_a.url)
            add(client, unset_b.url)  # and two whose maker never gave them a number are not taken for one
            assert all(device["same_as"] == [] for device in listed(client)) and len(listed(client)) == 4
    finally:
        for server in (one, same_make, unset_a, unset_b):
            server.stop()


def test_a_search_lists_a_kvm_once_under_its_nearer_address(tmp_path: Path, comet: FakeKvm, monkeypatch: pytest.MonkeyPatch) -> None:
    other = FakeKvm(FakeState(), tls_dir=tmp_path / "another-certificate").start()
    wanted = [
        Target("127.0.0.1", comet.url, NOWHERE),  # on the network, which is asked first
        Target("127.0.0.2", other.url, NOWHERE),
        Target("localhost", by_name(comet), NOWHERE, "rack-kvm"),  # the first one again, over the VPN, where it has a name
    ]
    monkeypatch.setattr(discover, "targets", lambda: (wanted, ["test network", "Tailscale"]))
    try:
        with wall(tmp_path / "data") as client:
            found = client.post("/api/v1/discover").json()["found"]
            assert found == [
                {
                    "address": "127.0.0.1", "kind": "kvmd", "url": comet.url, "name": "rack-kvm", "known": False, "known_as": None,
                    "known_id": None, "moved_from": None,
                    "also": [{"address": "localhost", "url": by_name(comet), "name": "rack-kvm"}],
                },
                {"address": "127.0.0.2", "kind": "kvmd", "url": other.url, "name": "", "known": False, "known_as": None, "known_id": None, "moved_from": None, "also": []},
            ]  # fmt: skip
            assert comet.state.logins == other.state.logins == 0  # looking is not logging in
            # On the wall under the address it has on the VPN: it is not offered again under the one on the network.
            add(client, by_name(comet), name="Rack KVM")
            found = client.post("/api/v1/discover").json()["found"]
            assert [(entry["address"], entry["known"], entry["known_as"]) for entry in found] == [("127.0.0.1", True, "Rack KVM"), ("127.0.0.2", False, None)]
            # Nor when only its other address is found this time.
            monkeypatch.setattr(discover, "targets", lambda: (wanted[:1], ["test network"]))
            assert [(entry["known"], entry["known_as"]) for entry in client.post("/api/v1/discover").json()["found"]] == [(True, "Rack KVM")]
    finally:
        other.stop()


def test_a_kvm_that_answers_somewhere_else_now_is_offered_there(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # After a power cut the router hands out addresses anew, and a KVM comes back with another one. The wall
    # shows it Offline; the search finds it, knows it by its certificate for the one on the wall, and used to
    # leave it out for that very reason: "already on the wall".
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    its_own = tmp_path / "its-certificate"
    before = FakeKvm(FakeState(), tls_dir=its_own).start()
    after: FakeKvm | None = None
    try:
        with wall(tmp_path / "data") as client:
            device = add(client, before.url, name="Rack KVM")

            def search(at: FakeKvm) -> list[tuple[object, ...]]:
                monkeypatch.setattr(discover, "targets", lambda: ([Target("127.0.0.1", at.url, NOWHERE)], ["test network"]))
                found = client.post("/api/v1/discover").json()["found"]
                return [(e["known"], e["known_as"], e["known_id"], e["moved_from"]) for e in found]

            # Where the wall has it, it answers: on the wall, and nothing to do.
            assert search(before) == [(True, "Rack KVM", device, None)]
            before.stop()
            after = FakeKvm(FakeState(), tls_dir=its_own).start()  # the same KVM, at another address
            wait_until(lambda: client.get("/api/v1/status").json()[device]["state"] == "offline", "the tile never went offline")
            old = before.url.split("//")[1]
            assert search(after) == [(True, "Rack KVM", device, old)]
            # One request puts the tile where the device is. What was saved for it stays: no password is typed again.
            moved = client.put(f"/api/v1/devices/{device}", json={"name": "Rack KVM", "url": after.url, "password": ""})
            assert moved.status_code == 200, moved.text
            wait_until(lambda: client.get("/api/v1/status").json()[device]["state"] in ("online", "no_signal"), "the tile did not come back")
            assert after.state.logins >= 1
            assert search(after) == [(True, "Rack KVM", device, None)]
    finally:
        if after is not None:
            after.stop()


def test_what_cannot_be_told_apart_is_not_merged() -> None:
    plain = [{"address": f"192.168.1.{n}", "kind": "jetkvm", "url": f"http://192.168.1.{n}", "name": ""} for n in (20, 21)]
    assert [entry["address"] for entry in once([dict(entry) for entry in plain])] == ["192.168.1.20", "192.168.1.21"]
    marked = [{**entry, "kind": "kvmd", "mark": "cert:aa"} for entry in plain]
    merged = once(marked + [{**plain[0], "address": "192.168.1.30", "mark": "cert:bb"}])
    assert [(entry["address"], [other["address"] for other in entry["also"]]) for entry in merged] == [("192.168.1.20", ["192.168.1.21"]), ("192.168.1.30", [])]


def test_a_tile_follows_its_own_device_to_a_new_address_and_no_other(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A new address for a tile, and no password typed: the saved one is used. It was sent to whatever
    # answered at that address, whose certificate was then remembered in place of the device's own. With
    # "Use this address" one click away, somebody on the network who can stand in for a KVM gets its password.
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    real = FakeKvm(FakeState(), tls_dir=tmp_path / "its-own").start()
    other = FakeKvm(FakeState(), tls_dir=tmp_path / "somebody-elses").start()
    plain, plain_too = FakeKvm().start(), FakeKvm().start()  # two that show no certificate at all
    try:
        with wall(tmp_path / "data") as client:
            device = add(client, real.url, name="Rack KVM")
            asked = other.state.logins
            moved = client.put(f"/api/v1/devices/{device}", json={"name": "Rack KVM", "url": other.url, "password": ""})
            assert (moved.status_code, moved.json()["code"]) == (422, "cert_mismatch")
            assert other.state.logins == asked  # it was shown the door, not the password
            assert client.get("/api/v1/wall").json()["devices"][0]["host"] == real.url.split("//")[1]
            # "Save anyway" does not take the saved password along to an address that could not be checked. Saved
            # there, the tile said "another certificate", and "Trust" was one click from sending the password
            # to whatever answers there.
            forced = client.put(f"/api/v1/devices/{device}", json={"name": "Rack KVM", "url": other.url, "password": "", "force": True})
            assert (forced.status_code, forced.json()["code"]) == (422, "password_needed")
            assert client.get("/api/v1/wall").json()["devices"][0]["host"] == real.url.split("//")[1] and other.state.logins == asked
            shown = client.get(f"/api/v1/devices/{device}/certificate").json()
            assert shown["saved"] == shown["presented"]  # there is nothing to trust in its place: the tile is where it was
            # At an address where its own device answers, it is known again, and no password is asked for.
            assert client.put(f"/api/v1/devices/{device}", json={"name": "Rack KVM, moved", "url": by_name(real), "password": ""}).status_code == 200
            assert client.put(f"/api/v1/devices/{device}", json={"name": "Rack KVM", "url": real.url, "password": ""}).status_code == 200
            # Whoever types the password says "this is the device, at this address": that is theirs to say.
            said = client.put(f"/api/v1/devices/{device}", json={"name": "Rack KVM", "url": other.url, "password": "secret"})
            assert said.status_code == 200 and other.state.logins > asked

            # A device that shows no certificate cannot be known again at another address. The password has to be typed.
            bare = add(client, plain.url, name="Bare")
            asked = plain_too.state.logins
            refused = client.put(f"/api/v1/devices/{bare}", json={"name": "Bare", "url": plain_too.url, "password": ""})
            assert (refused.status_code, refused.json()["code"]) == (422, "password_needed")
            assert plain_too.state.logins == asked
            assert client.put(f"/api/v1/devices/{bare}", json={"name": "Bare", "url": plain_too.url, "password": "secret"}).status_code == 200
            # Changing anything else about a tile asks for nothing.
            assert client.put(f"/api/v1/devices/{bare}", json={"name": "Bare, renamed", "url": plain_too.url, "password": ""}).status_code == 200
    finally:
        for server in (real, other, plain, plain_too):
            server.stop()


def test_a_server_is_not_known_again_by_a_certificate_its_maker_may_have_put_on_every_board(tmp_path: Path) -> None:
    # Two controllers of one make, with the one certificate (and key) they left the factory with. A tile
    # moved from one to the other without a password took the first one's password to the second.
    one = FakeBmc(BmcState(uuid="4c4c4544-0042-3510-8054-b9c04f4a3532"), tls_dir=tmp_path / "the-makers").start()
    other = FakeBmc(BmcState(uuid="4c4c4544-0042-3510-8054-c7c04f4a3533"), tls_dir=tmp_path / "the-makers").start()
    try:
        with wall(tmp_path / "data") as client:
            device = add(client, one.url, name="db-01")
            asked = other.state.logins
            for force in (False, True):
                moved = client.put(f"/api/v1/devices/{device}", json={"name": "db-01", "url": other.url, "username": "admin", "password": "", "force": force})
                assert (moved.status_code, moved.json()["code"]) == (422, "password_needed"), moved.text
            assert other.state.logins == asked
            # Whoever types the password says "this is the server, at this address".
            assert client.put(f"/api/v1/devices/{device}", json={"name": "db-01", "url": other.url, "username": "admin", "password": "secret"}).status_code == 200
    finally:
        one.stop()
        other.stop()


def test_an_address_typed_with_nothing_in_front_is_not_taken_the_plain_way_while_something_answers_over_https(monkeypatch: pytest.MonkeyPatch) -> None:
    # Ports 80 and 443 of one address can be two parties (a gateway that forwards them to two machines,
    # somebody on the way who answers the plain one). What says "JetKVM" on 80 was believed before the device
    # on 443 was considered at all, and was sent, in the clear, the password typed for that device.
    import asyncio

    import httpx

    from qkvm import server
    from qkvm.kvm import KvmError

    there: dict[str, tuple[int, dict]] = {}

    async def answered(client: httpx.AsyncClient, request: httpx.Request, limit: int, within: float | None = None) -> httpx.Response:
        if str(request.url) not in there and not any(str(request.url).startswith(origin) for origin in there if origin.endswith("//kvm.test")):
            raise httpx.ConnectError("nothing answers there")
        status, body = there.get(str(request.url), (404, {}))
        return httpx.Response(status, json=body, request=request)

    monkeypatch.setattr(server, "bounded", answered)
    refused: dict[str, bool] = {"https": True}  # whether the HTTPS port says at once that nothing is there

    async def listens(url: str) -> bool:
        return not refused["https"]

    monkeypatch.setattr(server, "listens", listens)
    a_jetkvm = (200, {"isSetup": True})
    # A KVM over HTTPS, and something that says "JetKVM" the plain way beside it.
    there.update({"https://kvm.test": (404, {}), "http://kvm.test/device/status": a_jetkvm})
    assert asyncio.run(server.detect_kind("https://kvm.test", False)) == ("kvmd", "https://kvm.test")
    assert asyncio.run(server.detect_kind("https://kvm.test", True)) == ("kvmd", "https://kvm.test")
    assert asyncio.run(server.detect_kind("http://kvm.test", True)) == ("jetkvm", "http://kvm.test")  # typed that way: theirs to say
    # A JetKVM as it comes: plain HTTP, and nothing at all over HTTPS.
    there.clear()
    there.update({"http://kvm.test/device/status": a_jetkvm})
    assert asyncio.run(server.detect_kind("https://kvm.test", False)) == ("jetkvm", "http://kvm.test")
    with pytest.raises(KvmError) as turned_down:
        asyncio.run(server.detect_kind("https://kvm.test", True))
    assert turned_down.value.code == "plain_only"
    # The same, but the HTTPS port takes a connection and says nothing in time (a device slow to wake, or held
    # up by somebody on the way): that is not "nothing there", and the plain way is not taken unasked.
    refused["https"] = False
    with pytest.raises(KvmError) as unsure:
        asyncio.run(server.detect_kind("https://kvm.test", False))
    assert unsure.value.code == "plain_only" and "http://kvm.test" in unsure.value.message and "https://kvm.test" in unsure.value.message
    assert asyncio.run(server.detect_kind("http://kvm.test", True)) == ("jetkvm", "http://kvm.test")  # said, it is taken
    # With a port typed, the two ways are one port: what answers the plain way there is all that listens on it.
    there["http://kvm.test:8080/device/status"] = a_jetkvm
    assert asyncio.run(server.detect_kind("https://kvm.test:8080", False, 8080)) == ("jetkvm", "http://kvm.test:8080")
    del there["http://kvm.test:8080/device/status"]
    refused["https"] = True
    # A port that was typed is the port that is asked, also where it is the one every HTTPS address has and is
    # not written into one: "kvm.test:443" is not "kvm.test", whose plain way is port 80.
    assert asyncio.run(server.detect_kind("https://kvm.test", False, 443)) == ("kvmd", "https://kvm.test")
    there["http://kvm.test:443/device/status"] = a_jetkvm
    assert asyncio.run(server.detect_kind("https://kvm.test", False, 443)) == ("jetkvm", "http://kvm.test:443")
    del there["http://kvm.test:443/device/status"]
    # And an address comes back written the way the program writes addresses: typed with the port every plain
    # address has, a JetKVM was saved as "http://kvm.test:80", which the next edit of its tile took for a move.
    assert asyncio.run(server.detect_kind("https://kvm.test:80", False, 80)) == ("jetkvm", "http://kvm.test")
    # And one whose owner switched HTTPS on: used that way, whatever was typed.
    there.update({"https://kvm.test/device/status": a_jetkvm})
    for typed, given in (("https://kvm.test", False), ("https://kvm.test", True), ("http://kvm.test", True)):
        assert asyncio.run(server.detect_kind(typed, given)) == ("jetkvm", "https://kvm.test")


def test_a_port_that_takes_a_connection_or_lets_one_wait_is_not_a_port_with_nothing_on_it() -> None:
    import asyncio
    import socket

    from qkvm import server
    from tests.test_wall import closed_port

    listening = socket.socket()
    listening.bind(("127.0.0.1", 0))
    listening.listen(16)  # (nobody takes the callers in: on Windows the next one is refused once as many wait as this says)
    try:
        assert asyncio.run(server.listens(f"https://127.0.0.1:{listening.getsockname()[1]}")) is True
        assert asyncio.run(server.listens(f"https://127.0.0.1:{closed_port()}")) is False
        # A name with two addresses, both of which refuse: asked by name, the two refusals came back as one
        # error that did not say what it was made of, and "nothing is there" was taken for "something may be".
        assert asyncio.run(server.listens(f"https://localhost:{closed_port()}")) is False
        assert asyncio.run(server.listens(f"https://localhost:{listening.getsockname()[1]}")) is True
    finally:
        listening.close()
