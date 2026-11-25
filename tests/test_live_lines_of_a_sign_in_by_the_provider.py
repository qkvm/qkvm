"""A live line of somebody the identity provider signed in ends with that sign-in (review M1 of 0.4.0): when the sign-in has
lasted as long as one by the provider lasts, however much it was used, and when the wall's admin changes who gets what,
keyboard and mouse included. A line makes no requests of its own: it is looked at, every few seconds, whether the sign-in
it was opened with still holds (server.live_standing).
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from qkvm import oidc
from tests.fake_oidc import CLIENT, ISSUER, SECRET, FakeIdp
from tests.fake_kvm import FakeKvm
from tests.test_live import Wall, comet, fast  # noqa: F401  (fixtures, by name)
from tests.test_wall import CSRF, wait_until

ROLES = [{"group": "wall-ops", "role": "operator"}]


@pytest.fixture
def idp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeIdp]:
    fake = FakeIdp(tmp_path / "idp", monkeypatch)
    fake.person("olga", email="olga@example.org", groups=["wall-ops"])
    yield fake
    fake.close()


def set_up(wall: Wall, admin: httpx.Client, **more: object) -> None:
    reply = admin.put("/api/v1/oidc", json={
        "enabled": True, "name": "Team SSO", "issuer": ISSUER, "client_id": CLIENT, "client_secret": SECRET, "roles": ROLES,
        "redirect_uri": f"{wall.url}/api/v1/oidc/callback", **more,
    })  # fmt: skip
    assert reply.status_code == 200, reply.text


def signed_in(wall: Wall, idp: FakeIdp) -> httpx.Client:
    """A browser the provider signed in, the whole way (the button, the provider, and back)."""
    client = httpx.Client(base_url=wall.url, headers=CSRF, timeout=10)
    wall.clients.append(client)
    begun = client.post("/api/v1/oidc/begin")
    assert begun.status_code == 200, begun.text
    back = client.get(idp.authorize(begun.json()["url"], "olga"))
    assert back.status_code == 303 and back.headers["location"] == "/", back.headers.get("location")
    assert client.get("/api/v1/session").json()["authenticated"] is True
    return client


def test_a_line_ends_when_the_sign_in_has_lasted_its_time(tmp_path: Path, comet: FakeKvm, idp: FakeIdp, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    monkeypatch.setattr(oidc, "SIGNED_IN_FOR", 4.0)
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        set_up(wall, admin)
        hers = signed_in(wall, idp)
        line = wall.line(hers, device)
        line.say(t="control", on=True)
        assert line.word("control")["on"] is True
        # Whatever is done on the line meanwhile, and asked of the wall: the sign-in ends at its time, and the line with it.
        assert line.word("bye", timeout=15)["code"] == "signed_out"
        line.closed()
        assert hers.get("/api/v1/wall").status_code == 401


def test_a_line_asks_for_itself_whether_its_sign_in_still_holds(tmp_path: Path, comet: FakeKvm, idp: FakeIdp) -> None:  # noqa: F811
    # The save signs them out; a line asks besides, whatever changed the settings (here: changed behind the save's back).
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        set_up(wall, admin)
        hers = signed_in(wall, idp)
        line = wall.line(hers, device)
        line.say(t="control", on=True)
        assert line.word("control")["on"] is True
        store = wall.core.store
        store.oidc = dataclasses.replace(store.oidc, roles={"wall-ops": "viewer"})
        assert line.word("bye", timeout=10)["code"] == "signed_out"
        line.closed()


def test_a_line_ends_when_who_gets_what_is_changed(tmp_path: Path, comet: FakeKvm, idp: FakeIdp) -> None:  # noqa: F811
    with Wall(tmp_path) as wall:
        admin = wall.browser()
        device = wall.add(admin, comet.url)
        set_up(wall, admin)
        hers = signed_in(wall, idp)
        line = wall.line(hers, device)
        line.say(t="control", on=True)
        assert line.word("control")["on"] is True
        line.say(t="k", u=0x04, d=True)
        wait_until(lambda: any(each["event_type"] == "key" for each in comet.state.hid), "the key did not arrive")
        set_up(wall, admin, client_secret="", roles=[{"group": "wall-ops", "role": "viewer"}])  # her group gives less now
        assert line.word("bye", timeout=10)["code"] == "signed_out"
        line.closed()
        wait_until(lambda: comet.state.hid[-1]["event"]["state"] is False, "the key she had down was not let go of")
        assert hers.get("/api/v1/wall").status_code == 401
