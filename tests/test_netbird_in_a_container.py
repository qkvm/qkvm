"""NetBird's machines where its client is not on this computer (qKVM in a container beside NetBird's own): from NetBird's
management API, with a token an admin gives under Settings > Network.

The token is sealed by the vault, never handed back, never written to a log or into an export, and sent to the address
it was entered for and to no other. The address is HTTPS, and is judged by the wall's outbound rules (egress.py): a
private one only with its switch. Settings that do not work are not saved: the API is asked once first. And what it
lists is a suggestion, as every machine a search finds.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from qkvm import discover, exchange, tailnet, update, vault
from qkvm.core import Core
from qkvm.store import Store
from tests.fake_netbird import TOKEN, URL, FakeNetbird, peer
from tests.test_users import OTHER, account, visitor
from tests.test_wall import wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")
    monkeypatch.setattr(tailnet, "tailscale_command", lambda: None)
    monkeypatch.setattr(tailnet, "SOCKETS", ())
    monkeypatch.setattr(tailnet, "netbird_command", lambda: None)  # (in a container: no client)


@pytest.fixture
def management(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeNetbird]:
    fake = FakeNetbird(tmp_path / "netbird", monkeypatch)
    fake.peers = [peer("rack-kvm", "100.92.0.7"), peer("away", "100.92.0.8", connected=False), peer("odd", "192.168.1.9")]
    yield fake
    fake.stop()


def api(token: str = TOKEN, url: str = URL) -> tailnet.NetbirdApi:
    return tailnet.NetbirdApi(url, token, private=False, own=frozenset(), own_ports=frozenset())


def listed(netbird: tailnet.NetbirdApi | None) -> list[tuple[str, str]]:
    return asyncio.run(tailnet.netbird_peers(netbird))


def refused(netbird: tailnet.NetbirdApi) -> str:
    with pytest.raises(tailnet.Unasked) as said:
        listed(netbird)
    return str(said.value)


def test_the_connected_machines_are_read_from_the_management_api(management: FakeNetbird) -> None:
    assert listed(api()) == [("100.92.0.7", "rack-kvm")]
    assert management.asked == [("GET", "/api/peers", f"Token {TOKEN}")]


def test_its_client_is_asked_first_where_it_is_installed(management: FakeNetbird, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tailnet, "netbird_command", lambda: "/usr/bin/netbird")
    monkeypatch.setattr(tailnet, "_status_by_command", lambda command: {"peers": {"details": [{"netbirdIp": "100.92.0.5", "fqdn": "local.netbird.cloud"}]}})
    assert listed(api()) == [("100.92.0.5", "local")]
    assert management.asked == []


def test_without_either_nothing_is_asked() -> None:
    assert listed(None) == []


def test_a_token_it_does_not_take_is_said(management: FakeNetbird) -> None:
    said = refused(api(token="nbp_SomebodyElses"))
    assert said.startswith("NetBird's management API did not take the token (401)")
    assert "nbp_" not in said


@pytest.mark.parametrize(
    ("answer", "said"),
    [
        ((500, b"database down"), "NetBird's management API answered 500 (database down)"),
        ((200, b"<html>a login page</html>"), "NetBird's management API answered with something that is not JSON"),
    ],
    ids=["its own trouble", "no JSON"],
)
def test_an_answer_that_is_no_list_is_said(management: FakeNetbird, answer: tuple[int, bytes], said: str) -> None:
    management.answer = answer
    assert refused(api()) == said


def test_an_answer_nested_deeper_than_can_be_read_is_said(management: FakeNetbird) -> None:
    # Python 3.14 follows nesting as deep as the stack it has: on one deep enough, the reader gets to the end of the hundred
    # thousand brackets and finds no JSON there (GitHub's Linux machines). Either is said, never an unhandled error.
    management.answer = (200, b"[" * 100_000)
    assert refused(api()) in (
        "NetBird's management API answered with JSON nested too deep to read",
        "NetBird's management API answered with something that is not JSON",
    )


def test_json_nested_deeper_than_the_reader_follows_is_said_so(monkeypatch: pytest.MonkeyPatch) -> None:
    def too_deep(body: bytes | str) -> Any:
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(tailnet, "json", type("Reader", (), {"loads": staticmethod(too_deep)}))
    with pytest.raises(tailnet.Unasked, match=r"^NetBird's management API answered with JSON nested too deep to read$"):
        tailnet.read_json(b"[]", "NetBird's management API")


@pytest.mark.parametrize(
    "body",
    [b"null", b"{}", b'{"peers": []}', b'[7, null, {"ip": 7, "connected": true}, {"ip": "100.92.0.7", "connected": "yes"}]'],
    ids=["null", "a record", "a record of peers", "peers of other kinds"],
)
def test_json_of_another_shape_lists_nobody(management: FakeNetbird, body: bytes) -> None:
    management.answer = (200, body)
    assert listed(api()) == []


def test_an_answer_too_large_is_not_read_to_its_end(management: FakeNetbird, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tailnet, "API_MOST", 16 * 1024)
    management.peers = [peer(f"machine-{n}", f"100.92.{n // 250}.{n % 250 + 1}") for n in range(500)]
    assert refused(api()) == "NetBird's management API sent more than this program reads of it (16 KB)"


def test_a_management_api_that_is_not_there_is_said(management: FakeNetbird) -> None:
    management.stop()
    assert refused(api()).startswith("NetBird's management API could not be asked: ")


@pytest.mark.parametrize(
    "url",
    ["http://netbird.example.org", "netbird.example.org", "https://user:pw@netbird.example.org", "https://netbird.example.org/api?token=x", "https://"],
    ids=["plain HTTP", "no scheme", "a login in it", "a query", "no host"],
)
def test_only_an_https_address_without_more_in_it_is_taken(url: str) -> None:
    with pytest.raises(ValueError):
        tailnet.management_url(url)


@pytest.mark.parametrize(
    ("given", "kept"),
    [("https://api.netbird.io", "https://api.netbird.io"), ("https://api.netbird.io/", "https://api.netbird.io"), ("https://nb.example.org/api/", "https://nb.example.org"), (" https://nb.example.org:33073 ", "https://nb.example.org:33073")],
)
def test_an_address_is_kept_as_the_api_is_asked_under_it(given: str, kept: str) -> None:
    assert tailnet.management_url(given) == kept


@pytest.mark.parametrize("token", ["", "  ", "nbp_with a space", "nbp_" + "x" * 500, "nbp_line\nbreak", "nbp_" + chr(0xFC)])
def test_a_token_is_one_word_of_plain_signs(token: str) -> None:
    with pytest.raises(ValueError):
        tailnet.management_token(token)


def test_the_settings_are_an_admins_and_the_token_is_never_handed_back(tmp_path: Path, management: FakeNetbird, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    with wall(tmp_path / "wall") as admin:
        assert admin.get("/api/v1/netbird").json() == {"url": "", "has_token": False, "private": False, "client": False}
        reply = admin.put("/api/v1/netbird", json={"url": URL + "/api", "token": TOKEN, "private": False})
        assert reply.status_code == 200, reply.text
        assert reply.json() == {"url": URL, "has_token": True, "private": False, "client": False, "peers": 1}
        assert TOKEN not in reply.text and TOKEN not in admin.get("/api/v1/netbird").text
        core: Core = admin.core  # type: ignore[attr-defined]
        sealed = core.store.netbird.secret
        assert isinstance(sealed, dict) and TOKEN not in json.dumps(sealed) and core.vault.read(sealed, tailnet.SEALED_FOR) == TOKEN

        account(admin, "olga", "operator")
        operator = visitor(admin, 50013)
        assert operator.post("/api/v1/login", json={"name": "olga", "password": OTHER}).status_code == 200
        assert operator.get("/api/v1/netbird").status_code == 403
        assert operator.put("/api/v1/netbird", json={"url": "", "token": "", "private": False}).status_code == 403

        # Neither in what the activity log says of it, nor in the log, nor in an export of every part, with the secrets.
        entries = admin.get("/api/v1/audit").json()["entries"]
        changed = [entry for entry in entries if entry["event"] == "netbird_changed"]
        assert changed and changed[0]["url"] == URL and changed[0]["token"] == "replaced"
        assert TOKEN not in json.dumps(entries)
        assert all(TOKEN not in record.getMessage() for record in caplog.records)
        everything = exchange.gather(core.store, core.vault, {"devices", "actions", "alerts", "wall", "signin"}, secrets=True)
        assert TOKEN not in json.dumps(everything) and "netbird" not in json.dumps(everything).lower()


def test_settings_that_do_not_work_are_not_saved(tmp_path: Path, management: FakeNetbird) -> None:
    with wall(tmp_path / "wall") as admin:
        reply = admin.put("/api/v1/netbird", json={"url": URL, "token": "nbp_NotTheRightOne", "private": False})
        assert reply.status_code == 502 and reply.json()["code"] == "provider_refused" and "Nothing was saved" in reply.json()["message"]
        assert admin.get("/api/v1/netbird").json()["url"] == ""
        assert admin.put("/api/v1/netbird", json={"url": "http://netbird.example.org", "token": TOKEN, "private": False}).status_code == 422
        assert admin.put("/api/v1/netbird", json={"url": URL, "token": "", "private": False}).json()["message"].startswith("Enter the token")


def test_a_token_kept_goes_only_where_it_was_entered_for(tmp_path: Path, management: FakeNetbird) -> None:
    with wall(tmp_path / "wall") as admin:
        assert admin.put("/api/v1/netbird", json={"url": URL, "token": TOKEN, "private": False}).status_code == 200
        management.asked.clear()
        # The same address, the token left empty: kept, and asked with once more.
        assert admin.put("/api/v1/netbird", json={"url": URL, "token": "", "private": False}).status_code == 200
        assert [said for _, _, said in management.asked] == [f"Token {TOKEN}"]
        # Another address, the token left empty: not sent there, not kept.
        management.asked.clear()
        reply = admin.put("/api/v1/netbird", json={"url": "https://elsewhere.example.org", "token": "", "private": False})
        assert reply.status_code == 422 and "again" in reply.json()["message"] and management.asked == []
        assert admin.get("/api/v1/netbird").json()["url"] == URL
        # No address: off, and the token is gone with it.
        assert admin.put("/api/v1/netbird", json={"url": "", "token": "", "private": False}).json()["has_token"] is False
        core: Core = admin.core  # type: ignore[attr-defined]
        assert core.store.netbird.secret is None


def test_a_private_address_takes_its_switch(tmp_path: Path, management: FakeNetbird, monkeypatch: pytest.MonkeyPatch) -> None:
    from qkvm import egress

    real = egress.vetted

    async def on_the_network(host: str, port: int, *, private_ok: bool, own: frozenset[str], own_ports: frozenset[int] = frozenset()) -> tuple[list[str], int]:
        # (The management API at an address of the network, as a self-hosted one is: judged as such, then reached on loopback.)
        if host == "netbird.example.org":
            if (why := egress.judge("192.168.1.20", private_ok=private_ok, own=own)) is not None:
                raise egress.Refused(why)
            return ["127.0.0.1"], management.port
        return await real(host, port, private_ok=private_ok, own=own, own_ports=own_ports)

    monkeypatch.setattr(egress, "vetted", on_the_network)
    with wall(tmp_path / "wall") as admin:
        reply = admin.put("/api/v1/netbird", json={"url": URL, "token": TOKEN, "private": False})
        assert reply.status_code == 502 and management.asked == []
        assert admin.put("/api/v1/netbird", json={"url": URL, "token": TOKEN, "private": True}).status_code == 200


def test_the_search_lists_its_machines_and_says_why_not(tmp_path: Path, management: FakeNetbird, monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[str] = []

    async def what_is(client: Any, target: discover.Target) -> dict[str, Any] | None:
        asked.append(target.host)  # (in place of asking it: no network is reached from a test)
        return {"address": target.host, "kind": "kvmd", "url": target.kvmd, "name": target.name}

    monkeypatch.setattr(discover, "_own_addresses", lambda: [])
    monkeypatch.setattr(discover, "_what_is", what_is)
    with wall(tmp_path / "wall") as admin:
        assert admin.post("/api/v1/discover").json()["networks"] == []  # (nothing set up: nothing asked, nothing said)
        assert management.asked == []
        assert admin.put("/api/v1/netbird", json={"url": URL, "token": TOKEN, "private": False}).status_code == 200
        result = admin.post("/api/v1/discover").json()
        assert result["networks"] == ["NetBird"] and result["notes"] == [] and asked == ["100.92.0.7"]
        assert [(entry["address"], entry["name"], entry["known"]) for entry in result["found"]] == [("100.92.0.7", "rack-kvm", False)]
        assert admin.get("/api/v1/wall").json()["devices"] == []

        management.answer = (401, b'{"message":"token expired"}')
        result = admin.post("/api/v1/discover").json()
        assert result["networks"] == [] and len(result["notes"]) == 1 and result["notes"][0].startswith("NetBird's management API did not take the token (401)")


def parts_of(secret: str, length: int = 6) -> list[str]:
    """Every run of `length` characters of a secret: a part of it, wherever it stands."""
    return [secret[at : at + length] for at in range(len(secret) - length + 1)]


ECHOES = {
    "whole, as a debug page repeats its request": b"Debug error: Authorization: Token " + TOKEN.encode(),
    "in JSON": json.dumps({"message": f"token {TOKEN} is not valid here", "code": 500}).encode(),
    "its start, the rest cut off by the service": b"Debug error: Authorization: Token " + TOKEN.encode()[:14] + b"...",
    "its end, the start masked by the service": b"token ****" + TOKEN.encode()[-14:] + b" is not valid here",
    "across the bound of what is read, after blanks": b"error:" + b" " * 380 + TOKEN.encode(),
}


@pytest.mark.parametrize("echo", list(ECHOES))
def test_what_the_api_says_back_never_holds_the_token_whole_or_in_part(
    tmp_path: Path, management: FakeNetbird, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch, echo: str
) -> None:
    # The outside review of 0.4.0, L1: the management API's error was said in its own words, cut to a line; one that
    # repeated what it was sent handed the saved token back, to the browser of an admin who had left the token's box
    # empty, and into the search's notes. Nothing a request carried as a secret comes back in an error, a log line or an
    # answer, whole or in part.
    caplog.set_level(logging.DEBUG)
    monkeypatch.setattr(discover, "_own_addresses", lambda: [])  # (the search asks no network of this computer's: the tailnet alone)
    with wall(tmp_path / "wall") as admin:
        assert admin.put("/api/v1/netbird", json={"url": URL, "token": TOKEN, "private": False}).status_code == 200
        management.answer = (500, ECHOES[echo])
        again = admin.put("/api/v1/netbird", json={"url": URL, "token": "", "private": False})
        assert again.status_code == 502 and management.asked[-1][2] == f"Token {TOKEN}"
        assert again.json()["message"].startswith("NetBird's management API answered 500 (") and "[hidden]" in again.json()["message"]
        found = admin.post("/api/v1/discover").json()["notes"]
        assert found and found[0].startswith("NetBird's management API answered 500 ("), found
        said = [again.text, json.dumps(found), json.dumps(admin.get("/api/v1/audit").json()), *(record.getMessage() for record in caplog.records)]
    for text in said:
        assert TOKEN not in text
        # (Every part with a sign in it that is no hex digit: six digits may stand in a time or a head of the chain by chance.)
        assert not [part for part in parts_of(TOKEN) if part in text and set(part) - set("0123456789abcdef")], (echo, text)


def test_a_reset_of_the_accounts_forgets_the_token(tmp_path: Path, management: FakeNetbird) -> None:
    with wall(tmp_path / "wall") as admin:
        assert admin.put("/api/v1/netbird", json={"url": URL, "token": TOKEN, "private": False}).status_code == 200
    core = Core(tmp_path / "wall")
    core.reset_password()
    again = Store(tmp_path / "wall" / "qkvm.json", vault_key_file=core.store.key_file, protected=True)
    assert again.netbird.url == URL and again.netbird.secret is None


def test_settings_of_0_3_2_have_none_and_a_hand_edit_of_another_kind_is_refused(tmp_path: Path) -> None:
    from qkvm.store import NetbirdSettings, StoreError

    # (As 0.3.2 wrote its settings, its parts that matter here: no "netbird" at all. Read as a plain file, as the store reads
    # what its envelope holds.)
    of_0_3_2 = tmp_path / "of-0.3.2" / "qkvm.json"
    of_0_3_2.parent.mkdir()
    of_0_3_2.write_text(json.dumps({"version": 1, "server": {"bind": ["local"], "port": 8787}, "users": [], "devices": [], "alerts": {}}), encoding="utf-8")
    assert Store(of_0_3_2).netbird == NetbirdSettings()
    # ...and written back with it, and read again so.
    again = Store(of_0_3_2)
    again.netbird = NetbirdSettings(url=URL, private=True)
    again.save()
    assert Store(of_0_3_2).netbird == NetbirdSettings(url=URL, private=True)

    edited = tmp_path / "edited" / "qkvm.json"
    edited.parent.mkdir()
    edited.write_text(json.dumps({"version": 1, "netbird": {"url": 7, "secret": "not sealed", "private": "yes"}}), encoding="utf-8")
    with pytest.raises(StoreError, match='the settings under "netbird"'):
        Store(edited)
    # A sealed token that is no sealed text is kept as one that opens with no key: "nothing saved" where it is used.
    edited.write_text(json.dumps({"version": 1, "netbird": {"url": URL, "secret": "not sealed", "private": False}}), encoding="utf-8")
    assert Store(edited).netbird.secret == {"damaged": "not sealed"}
