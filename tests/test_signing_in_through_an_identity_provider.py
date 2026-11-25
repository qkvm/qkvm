"""Signing in through an identity provider by OpenID Connect (0.4.0): the team's provider says who somebody is, and its
groups say as what (oidc.py). Against a stand-in provider on loopback (fake_oidc.py), which holds a code to its PKCE
challenge, its client and its redirect address as a real one does.

What an ID token is held to, refusal by refusal, is tests/test_id_tokens_as_an_attacker_makes_them.py.
"""

from __future__ import annotations

import dataclasses
import json
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi.testclient import TestClient

from qkvm import kvm, oidc, update, vault
from qkvm.store import OidcSettings, Store, StoreError
from qkvm.vault_storage import key_path
from tests.fake_oidc import CLIENT, IDP, ISSUER, SECRET, FakeIdp
from tests.test_every_route_then_a_restart import Reads
from tests.test_totp import switch_on
from tests.test_users import OTHER, account, visitor
from tests.test_wall import CSRF, PASSWORD, wall

REDIRECT = "http://testserver/api/v1/oidc/callback"  # (the address a TestClient looks at the wall by)
ROLES = [{"group": "wall-admins", "role": "admin"}, {"group": "wall-ops", "role": "operator"}, {"group": "wall-viewers", "role": "viewer"}]


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def idp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeIdp]:
    fake = FakeIdp(tmp_path / "idp", monkeypatch)
    fake.person("olga", email="olga@example.org", name="Olga", groups=["wall-ops", "lunch-club"])
    yield fake
    fake.close()


def settings(**more: Any) -> dict[str, Any]:
    return {
        "enabled": True, "name": "Team SSO", "issuer": ISSUER, "client_id": CLIENT, "client_secret": SECRET, "scopes": "openid profile email",
        "groups_claim": "groups", "roles": ROLES, "anyone": "", "domain": "", "private": False, "redirect_uri": REDIRECT, **more,
    }  # fmt: skip


def set_up(admin: TestClient, **more: Any) -> dict[str, Any]:
    reply = admin.put("/api/v1/oidc", json=settings(**more))
    assert reply.status_code == 200, reply.text
    return dict(reply.json())


def stranger(admin: TestClient, port: int = 51000, address: str = "192.0.2.20") -> TestClient:
    """A browser of somebody who is not signed in to the wall, from another computer."""
    client = TestClient(admin.app, headers=CSRF, client=(address, port))
    client.portal = admin.portal
    return client


def begin(browser: TestClient) -> str:
    begun = browser.post("/api/v1/oidc/begin")
    assert begun.status_code == 200, begun.text
    return str(begun.json()["url"])


def come_back(browser: TestClient, back: str) -> httpx.Response:
    reply = browser.get(back, follow_redirects=False)
    assert reply.status_code == 303, reply.text
    return reply


def signed_in_by(browser: TestClient, idp: FakeIdp, login: str) -> httpx.Response:
    """The whole way: the button, the provider, and back. The answer the browser gets back at the wall."""
    return come_back(browser, idp.authorize(begin(browser), login))


def refused_as(reply: httpx.Response) -> str:
    """The word the page is sent back with where a sign-in was refused ("" where it was let in)."""
    where = reply.headers["location"]
    return where.split("#signin=", 1)[1] if "#signin=" in where else ""


def entries(admin: TestClient, event: str) -> list[dict[str, Any]]:
    return [entry for entry in admin.get("/api/v1/audit").json()["entries"] if entry["event"] == event]


def test_a_team_signs_in_with_its_provider_and_its_groups_give_the_role(tmp_path: Path, idp: FakeIdp) -> None:
    with wall(tmp_path) as admin:
        shown = set_up(admin)
        assert shown["has_secret"] is True and SECRET not in json.dumps(shown)  # sealed by the vault, and never handed back
        assert stranger(admin).get("/api/v1/oidc/offer").json() == {"on": True, "name": "Team SSO"}

        hers = stranger(admin)
        url = begin(hers)
        asked = {key: values[0] for key, values in parse_qs(urlsplit(url).query).items()}
        # The authorization code flow with PKCE (S256), a state and a nonce of its own, and the exact redirect address.
        assert asked["response_type"] == "code" and asked["client_id"] == CLIENT and asked["redirect_uri"] == REDIRECT
        assert asked["code_challenge_method"] == "S256" and len(asked["code_challenge"]) == 43 and asked["scope"] == "openid profile email"
        assert len(asked["state"]) == 43 and len(asked["nonce"]) == 43 and asked["state"] != asked["nonce"]
        cookie = hers.cookies.get(oidc.COOKIE)
        assert cookie and cookie not in url  # what binds it to this browser goes nowhere but into this browser
        back = come_back(hers, idp.authorize(url, "olga"))
        assert back.headers["location"] == "/" and "httponly" in back.headers["set-cookie"].lower() and "samesite=strict" in back.headers["set-cookie"].lower()

        session = hers.get("/api/v1/session").json()
        assert session["authenticated"] is True and session["user"]["role"] == "operator" and session["user"]["name"] == "olga@example.org"
        assert session["user"]["must_enroll"] is False and session["user"]["sso"] is False
        assert hers.get("/api/v1/wall").status_code == 200 and hers.get("/api/v1/users").status_code == 403

        # The token endpoint was given the code with the client secret and the PKCE verifier that fits the challenge.
        [exchanged] = idp.at("/realms/team/token")
        form = {key: values[0] for key, values in parse_qs(exchanged.body.decode()).items()}
        assert form["grant_type"] == "authorization_code" and form["redirect_uri"] == REDIRECT
        assert oidc.challenge_of(form["code_verifier"]) == asked["code_challenge"]
        assert exchanged.headers["Authorization"].startswith("Basic ")

        listed = {user["name"]: user for user in admin.get("/api/v1/users").json()["users"]}
        assert listed["olga@example.org"]["provider"] is True and listed["admin"]["provider"] is False
        [made] = entries(admin, "user_added")
        assert made["account"] == "olga@example.org" and made["role"] == "operator" and made["provider"] is True
        login = next(entry for entry in entries(admin, "login") if entry.get("provider"))
        assert login["user"] == "olga@example.org" and login["ip"] == "192.0.2.20"
        log = (tmp_path / "audit.log").read_text(encoding="utf-8")
        assert SECRET not in log and asked["state"] not in log and form["code"] not in log and form["code_verifier"] not in log

        # Moved into the admins' group at the provider: an admin at the next sign-in, and said so.
        idp.people["olga"].groups = ["wall-admins"]
        assert refused_as(signed_in_by(stranger(admin, 51001), idp, "olga")) == ""
        assert hers.get("/api/v1/users").status_code == 200  # (the role is the account's: her browser that was signed in has it too)
        changed = entries(admin, "user_changed")[0]
        assert changed["account"] == "olga@example.org" and changed["role"] == "admin" and changed["was"] == "operator" and changed["by"] == "provider"

        # Taken out of every group that gives a role: refused at the next sign-in, and the account keeps what it had.
        idp.people["olga"].groups = ["lunch-club"]
        assert refused_as(signed_in_by(stranger(admin, 51002), idp, "olga")) == "no_group"
        failed = [entry for entry in entries(admin, "login_failed") if entry.get("provider")]
        assert failed[0]["why"] == "no_group" and failed[0]["user"] == "olga@example.org"
        # A browser signed in before keeps its sign-in until it ends; an admin ends all of them at once.
        assert hers.get("/api/v1/wall").status_code == 200
        ended = admin.post("/api/v1/oidc/logout")
        assert ended.status_code == 200 and ended.json()["ended"] >= 2
        assert hers.get("/api/v1/wall").status_code == 401
        assert admin.get("/api/v1/wall").status_code == 200  # (the admin's own sign-in, by password, is not the provider's)
        assert entries(admin, "provider_signed_out")[0]["sessions"] >= 2


def test_nothing_but_the_provider_signs_such_an_account_in(tmp_path: Path, idp: FakeIdp) -> None:
    with wall(tmp_path) as admin:
        recovery = admin.post("/api/v1/recovery", json={"password": PASSWORD}).json()["recovery_key"]
        set_up(admin)
        assert refused_as(signed_in_by(stranger(admin), idp, "olga")) == ""
        olga = next(user for user in admin.get("/api/v1/users").json()["users"] if user["provider"])
        # No password works for it, whatever is typed: it has none, and gets none.
        direct = stranger(admin, 51010)
        for guess in ("", OTHER, "olga@example.org", SECRET):
            assert direct.post("/api/v1/login", json={"name": "olga@example.org", "password": guess}).status_code in (401, 422)
        refused = admin.put(f"/api/v1/users/{olga['id']}", json={"name": olga["name"], "role": "operator", "password": OTHER})
        assert (refused.status_code, refused.json()["code"]) == (409, "provider_account")
        refused = direct.post("/api/v1/recover", json={"name": "olga@example.org", "recovery_key": recovery, "new_password": OTHER})
        assert (refused.status_code, refused.json()["code"]) == (409, "provider_account")
        assert direct.post("/api/v1/login", json={"name": "olga@example.org", "password": OTHER}).status_code == 401
        # Its role is its groups': not changed here, where the next sign-in would undo it.
        refused = admin.put(f"/api/v1/users/{olga['id']}", json={"name": olga["name"], "role": "admin"})
        assert (refused.status_code, refused.json()["code"]) == (409, "provider_account")
        # Its machines are the wall's to limit, and stay limited over its sign-ins.
        limited = admin.put(f"/api/v1/users/{olga['id']}", json={"name": olga["name"], "role": "operator", "devices": [], "groups": ["lab"]})
        assert limited.status_code == 200, limited.text
        assert refused_as(signed_in_by(stranger(admin, 51011), idp, "olga")) == ""
        again = next(user for user in admin.get("/api/v1/users").json()["users"] if user["provider"])
        assert (again["devices"], again["groups"]) == ([], ["lab"])
        # Suspended here: the provider's word no longer signs it in.
        assert admin.put(f"/api/v1/users/{olga['id']}", json={"name": olga["name"], "role": "operator", "suspended": True}).status_code == 200
        assert refused_as(signed_in_by(stranger(admin, 51012), idp, "olga")) == "suspended"


def test_the_second_step_is_the_providers_for_those_it_signs_in(tmp_path: Path, idp: FakeIdp) -> None:
    with wall(tmp_path) as admin:
        switch_on(admin, PASSWORD)
        assert admin.put("/api/v1/security", json={"require_totp": "viewer"}).status_code == 200
        set_up(admin)
        hers = stranger(admin)
        assert refused_as(signed_in_by(hers, idp, "olga")) == ""
        assert hers.get("/api/v1/session").json()["user"]["must_enroll"] is False and hers.get("/api/v1/wall").status_code == 200
        assert admin.get("/api/v1/security").json()["without"] == []  # (nobody is waited for to set up what the provider does)


def test_a_way_back_in_always_stays_when_the_provider_is_down(tmp_path: Path, idp: FakeIdp) -> None:
    with wall(tmp_path) as admin:
        idp.people["olga"].groups = ["wall-admins"]
        set_up(admin)
        hers = stranger(admin)
        assert refused_as(signed_in_by(hers, idp, "olga")) == ""
        local = next(user for user in hers.get("/api/v1/users").json()["users"] if user["name"] == "admin")
        # The provider's admin cannot take away the last admin who signs in here: not removed, not demoted, not suspended.
        for reply in (
            hers.delete(f"/api/v1/users/{local['id']}"),
            hers.put(f"/api/v1/users/{local['id']}", json={"name": "admin", "role": "operator"}),
            hers.put(f"/api/v1/users/{local['id']}", json={"name": "admin", "role": "admin", "suspended": True}),
        ):
            assert (reply.status_code, reply.json()["code"]) == (409, "last_admin"), reply.text
        # With a second admin of its own, the wall can lose the first.
        second = account(admin, "victor", "admin")
        assert hers.put(f"/api/v1/users/{local['id']}", json={"name": "admin", "role": "admin", "suspended": True}).status_code == 200
        assert hers.delete(f"/api/v1/users/{second}").json()["code"] == "last_admin"


def test_the_settings_are_an_admins_and_the_secret_is_never_shown(tmp_path: Path, idp: FakeIdp) -> None:
    with wall(tmp_path) as admin:
        assert admin.get("/api/v1/oidc").json()["enabled"] is False and admin.get("/api/v1/oidc").json()["has_secret"] is False
        assert stranger(admin).get("/api/v1/oidc/offer").json() == {"on": False, "name": ""}
        assert stranger(admin).post("/api/v1/oidc/begin").json()["code"] == "not_offered"
        account(admin, "victor", "operator")
        his = visitor(admin, 51020)
        assert his.post("/api/v1/login", json={"name": "victor", "password": OTHER}).status_code == 200
        assert his.get("/api/v1/oidc").status_code == 403 and his.put("/api/v1/oidc", json=settings()).status_code == 403
        assert his.post("/api/v1/oidc/logout").status_code == 403

        # Switched on, the provider is asked what it is: one that calls itself otherwise is refused, and nothing is saved.
        refused = admin.put("/api/v1/oidc", json=settings(issuer=ISSUER + "/"))
        assert refused.status_code == 502 and refused.json()["code"] == "provider_refused"
        assert f"calls itself {ISSUER}" in refused.json()["message"] and admin.get("/api/v1/oidc").json()["enabled"] is False
        for wrong, why in (
            ({"issuer": f"http://{IDP}/realms/team"}, "https://"),
            ({"redirect_uri": "http://elsewhere.example:8787/api/v1/oidc/callback"}, "looked at by"),
            ({"redirect_uri": "http://testserver/somewhere"}, "/api/v1/oidc/callback"),
            ({"scopes": "profile email"}, "openid"),
            ({"roles": [{"group": "x", "role": "root"}]}, "role"),
            ({"roles": [], "anyone": ""}, "Nobody"),
            ({"client_secret": ""}, "client secret"),
        ):
            reply = admin.put("/api/v1/oidc", json=settings(**wrong))
            assert reply.status_code == 422 and why in reply.json()["message"], (wrong, reply.text)
        assert idp.at("/realms/team/.well-known/openid-configuration")  # (asked for the one whose form was right)

        set_up(admin)
        kept = admin.get("/api/v1/oidc").json()
        assert kept["has_secret"] is True and "client_secret" not in kept and SECRET not in json.dumps(kept)
        assert kept["redirect_uri"] == REDIRECT and kept["roles"] == ROLES
        # Saved again without the secret, the saved one is kept: for that provider and that client, and for no other, which
        # would be handed a secret that was never meant for it at the next sign-in.
        assert set_up(admin, client_secret="", name="Our login")["has_secret"] is True
        for other in ({"client_id": "another-client"}, {"issuer": ISSUER + "-two"}):
            reply = admin.put("/api/v1/oidc", json=settings(**other, client_secret=""))
            assert reply.status_code == 422 and "the client secret (again" in reply.json()["message"], (other, reply.text)
        assert admin.put("/api/v1/oidc", json=settings(client_id="another-client", client_secret="", enabled=False)).json()["has_secret"] is False
        set_up(admin, name="Our login")
        assert refused_as(signed_in_by(stranger(admin), idp, "olga")) == ""
        assert entries(admin, "oidc_changed")[0]["enabled"] is True

        # Begun from another address than the one the provider sends back to: said where to go instead.
        elsewhere = TestClient(admin.app, headers=CSRF, client=("192.0.2.21", 51021), base_url="http://192.0.2.1:8787")
        elsewhere.portal = admin.portal
        reply = elsewhere.post("/api/v1/oidc/begin")
        assert (reply.status_code, reply.json()["code"], reply.json()["at"]) == (409, "elsewhere", "http://testserver")

        # Switched off: the button goes, and so does every sign-in it made.
        hers = stranger(admin, 51022)
        assert refused_as(signed_in_by(hers, idp, "olga")) == ""
        assert set_up(admin, enabled=False, client_secret="")["enabled"] is False
        assert hers.get("/api/v1/wall").status_code == 401
        assert stranger(admin).get("/api/v1/oidc/offer").json()["on"] is False


def test_a_sign_in_is_taken_once_from_the_browser_that_began_it(tmp_path: Path, idp: FakeIdp) -> None:
    with wall(tmp_path) as admin:
        set_up(admin)
        hers = stranger(admin)
        back = idp.authorize(begin(hers), "olga")
        # Somebody else's browser, sent the same way back (a link in a mail): refused, and the sign-in is used up.
        other = stranger(admin, 51030, "192.0.2.30")
        assert refused_as(come_back(other, back)) == "browser"
        assert refused_as(come_back(hers, back)) == "state"  # (taken once, by whoever came first)
        # Her own, taken twice: the second is refused, as one that is not known.
        back = idp.authorize(begin(hers), "olga")
        assert refused_as(come_back(hers, back)) == ""
        assert refused_as(come_back(hers, back)) == "state"
        # A state that was never made, and none at all.
        assert refused_as(come_back(hers, "/api/v1/oidc/callback?code=abc&state=" + "A" * 43)) == "state"
        assert refused_as(come_back(hers, "/api/v1/oidc/callback")) == "state"
        # The provider's own no (the person said no there), said as its word, and the sign-in used up.
        url = begin(hers)
        state = parse_qs(urlsplit(url).query)["state"][0]
        assert refused_as(come_back(hers, f"/api/v1/oidc/callback?error=access_denied&state={state}")) == "provider_error"
        failed = [entry for entry in entries(admin, "login_failed") if entry.get("why") == "provider_error"]
        assert "access_denied" in failed[0]["said"]
        # A sign-in begun before the settings changed is not finished after.
        url = begin(hers)
        set_up(admin, client_id=CLIENT, client_secret="", name="Renamed")  # (the same provider and client: nothing that matters)
        assert refused_as(come_back(hers, idp.authorize(url, "olga"))) == ""
        url = begin(hers)
        set_up(admin, enabled=False, client_secret="")
        set_up(admin, client_secret="another-secret-entered")
        assert refused_as(come_back(hers, idp.authorize(url, "olga"))) == "changed"


def test_nobody_fills_the_wall_with_sign_ins_or_its_log_with_ways_back(tmp_path: Path, idp: FakeIdp) -> None:
    with wall(tmp_path) as admin:
        set_up(admin)
        # So many under way from one address, and no more: the oldest are not pushed out for new ones (whoever pressed the
        # button before is not sent back to nothing); another address still begins its own.
        flooding = stranger(admin, 51070, "192.0.2.70")
        for _ in range(oidc.MOST_UNDER_WAY_OF_ONE):
            begin(flooding)
        reply = flooding.post("/api/v1/oidc/begin")
        assert (reply.status_code, reply.json()["code"]) == (429, "busy")
        assert refused_as(signed_in_by(stranger(admin, 51071, "192.0.2.71"), idp, "olga")) == ""
        # Ways back that no sign-in here began, by the hundred: a line in the activity log for the first, not one for each.
        before = len(entries(admin, "login_failed"))
        for number in range(100):
            assert refused_as(come_back(flooding, f"/api/v1/oidc/callback?code=x&state={number:043d}")) == "state"
        assert len(entries(admin, "login_failed")) - before == 1
        assert len(idp.at("/realms/team/token")) == 1  # (and none of them was taken to the provider)


def test_what_changes_while_the_provider_is_asked_is_asked_again_before_anybody_is_let_in(tmp_path: Path, idp: FakeIdp) -> None:
    # The code is exchanged and the token checked for seconds perhaps, beside every change of the wall. An admin who
    # switched the provider off, or suspended the account, meanwhile is not overtaken by a sign-in that was under way.
    with wall(tmp_path) as admin:
        set_up(admin)
        assert refused_as(signed_in_by(stranger(admin), idp, "olga")) == ""
        olga = next(user for user in admin.get("/api/v1/users").json()["users"] if user["provider"])
        idp.before_token = lambda: admin.put(f"/api/v1/users/{olga['id']}", json={"name": olga["name"], "role": "operator", "suspended": True})
        assert refused_as(signed_in_by(stranger(admin, 51080), idp, "olga")) == "suspended"
        assert admin.put(f"/api/v1/users/{olga['id']}", json={"name": olga["name"], "role": "operator", "suspended": False}).status_code == 200
        # Her group's role changed meanwhile: what her role would be worked out by is gone, and nothing is written by it.
        idp.before_token = lambda: admin.put("/api/v1/oidc", json=settings(client_secret="", roles=[{"group": "wall-ops", "role": "viewer"}]))
        assert refused_as(signed_in_by(stranger(admin, 51082), idp, "olga")) == "changed"
        assert next(user for user in admin.get("/api/v1/users").json()["users"] if user["provider"])["role"] == "operator"
        idp.before_token = lambda: admin.put("/api/v1/oidc", json=settings(enabled=False, client_secret=""))
        hers = stranger(admin, 51081)
        assert refused_as(signed_in_by(hers, idp, "olga")) == "changed"
        assert hers.get("/api/v1/session").json()["authenticated"] is False
        # Two admins saving at once: the provider is asked for the one, the other saves meanwhile; the first is not saved
        # over what the second saved, and is told so.
        idp.before_token = None
        idp.before_discovery = lambda: admin.put("/api/v1/oidc", json=settings(enabled=False, client_secret="", name="Saved meanwhile"))
        reply = admin.put("/api/v1/oidc", json=settings(name="Saved first"))
        assert (reply.status_code, reply.json()["code"]) == (409, "changed")
        assert admin.get("/api/v1/oidc").json()["name"] == "Saved meanwhile"


def test_over_https_the_sign_ins_own_cookie_is_its_hosts_alone(tmp_path: Path, idp: FakeIdp) -> None:
    # Over HTTPS the cookie that binds a sign-in to its browser is a __Host- cookie: Secure, for the whole host (path /, as
    # the prefix asks) and no Domain, so a page on a name beside the wall's cannot set one for it (cookie tossing: a sign-in of
    # the attacker's own, finished in the victim's browser). Bound to the way back by its value, as before. Over plain HTTP
    # there is no such prefix, and it stays a cookie of the way back alone (the other tests).
    with wall(tmp_path) as admin:
        set_up(admin, redirect_uri="https://testserver/api/v1/oidc/callback")
        hers = TestClient(admin.app, headers=CSRF, client=("192.0.2.40", 51140), base_url="https://testserver")
        hers.portal = admin.portal
        begun = hers.post("/api/v1/oidc/begin")
        set_cookie = begun.headers["set-cookie"]
        assert set_cookie.startswith("__Host-qkvm_oidc="), set_cookie
        said = [part.strip().lower() for part in set_cookie.split(";")]
        assert {"httponly", "secure", "path=/", "samesite=lax"} <= set(said) and not any(part.startswith("domain") for part in said), set_cookie
        assert refused_as(come_back(hers, idp.authorize(begun.json()["url"], "olga"))) == ""
        assert hers.get("/api/v1/session").json()["authenticated"] is True
        assert "__Host-qkvm_oidc" not in hers.cookies  # (used once, and taken out of the browser)
        # The same value, set under the plain name (as a page beside the wall's could set it): not taken over HTTPS.
        other = TestClient(admin.app, headers=CSRF, client=("192.0.2.41", 51141), base_url="https://testserver")
        other.portal = admin.portal
        begun = other.post("/api/v1/oidc/begin")
        value = other.cookies.get("__Host-qkvm_oidc")
        assert value
        other.cookies.clear()
        other.cookies.set("qkvm_oidc", value, domain="testserver", path="/api/v1/oidc/callback")
        assert refused_as(come_back(other, idp.authorize(begun.json()["url"], "olga"))) == "browser"


def test_the_provider_must_say_its_name_on_the_way_back_where_it_says_it_does(tmp_path: Path, idp: FakeIdp) -> None:
    # A mix-up (RFC 9207): a code from another provider handed in on the way back from this one.
    with wall(tmp_path) as admin:
        set_up(admin)
        hers = stranger(admin)
        back = idp.authorize(begin(hers), "olga")
        assert refused_as(come_back(hers, back.replace("iss=https", "iss=https%3A%2F%2Fevil.example.org%2Fx&was=https"))) == "issuer"
        idp.said["authorization_response_iss_parameter_supported"] = True
        idp.says_iss = False  # (it says it puts iss there, and leaves it out)
        assert refused_as(come_back(hers, idp.authorize(begin(hers), "olga"))) == "issuer"
        # One that does not say it puts it there is not asked for it.
        idp.said["authorization_response_iss_parameter_supported"] = False
        set_up(admin, client_secret="", name="Again")  # (settings saved again: what the provider says of itself is asked anew)
        assert refused_as(come_back(hers, idp.authorize(begin(hers), "olga"))) == ""


def test_a_code_issued_for_another_pkce_challenge_is_refused_by_the_provider(tmp_path: Path, idp: FakeIdp) -> None:
    # A code taken from somebody else's sign-in (begun by an attacker, with a challenge of theirs) and handed in with this
    # browser's state: the provider holds the code to its challenge, and the wall's verifier is not that one's.
    with wall(tmp_path) as admin:
        set_up(admin)
        hers = stranger(admin)
        url = begin(hers)
        state = parse_qs(urlsplit(url).query)["state"][0]
        stolen = idp.code_for("olga", oidc.challenge_of("the attacker's own verifier, not the wall's"), "a nonce of theirs", REDIRECT)
        assert refused_as(come_back(hers, f"/api/v1/oidc/callback?code={stolen}&state={state}&iss={ISSUER}")) == "exchange"
        failed = [entry for entry in entries(admin, "login_failed") if entry.get("why") == "exchange"]
        assert "invalid_grant" in failed[0]["said"] and stolen not in json.dumps(failed)
        assert hers.get("/api/v1/session").json()["authenticated"] is False


def test_a_refusal_of_the_token_endpoint_never_says_back_what_was_sent_to_it(tmp_path: Path, idp: FakeIdp, caplog: pytest.LogCaptureFixture) -> None:
    # The outside review of 0.4.0, L1, swept through the provider: of its refusal only its code of OAuth is said (a word of
    # small letters and underscores), into the activity log. A client secret of such letters, or a part of it, is such a
    # word, and a provider that said it back as its "error" had it written there.
    caplog.set_level("DEBUG")
    secret = "zqkvx_wplmrt_yhgdfn_bcsjw"  # (small letters and underscores, and no word in it the log says anyway)
    with wall(tmp_path) as admin:
        set_up(admin, client_secret=secret)
        for port, said_back in enumerate((secret, secret[4:22], "invalid_grant"), start=51200):
            idp.answers = [(400, json.dumps({"error": said_back}).encode())]
            assert refused_as(signed_in_by(stranger(admin, port), idp, "olga")) == "exchange"
        failed = [entry for entry in entries(admin, "login_failed") if entry.get("why") == "exchange"]
        assert len(failed) == 3 and failed[0]["said"].endswith("(invalid_grant)"), failed  # (newest first: its own code is said)
        said = json.dumps(failed) + json.dumps(admin.get("/api/v1/audit").json()) + "".join(record.getMessage() for record in caplog.records)
    assert not [secret[at : at + 6] for at in range(len(secret) - 5) if secret[at : at + 6] in said], said


def test_who_may_sign_in_at_all(tmp_path: Path, idp: FakeIdp) -> None:
    idp.person("pete", email="pete@example.org", groups=["somewhere-else"])
    idp.person("gmail", email="gmail@gmail.example", groups=[])
    with wall(tmp_path) as admin:
        set_up(admin)
        # Only those in a group that gives a role, by default.
        assert refused_as(signed_in_by(stranger(admin), idp, "pete")) == "no_group"
        assert not any(user["provider"] for user in admin.get("/api/v1/users").json()["users"] if user["name"].startswith("pete"))
        # Anybody the provider signs in, where the admin says so, as what they say.
        set_up(admin, client_secret="", anyone="viewer")
        his = stranger(admin, 51040)
        assert refused_as(signed_in_by(his, idp, "pete")) == ""
        assert his.get("/api/v1/session").json()["user"]["role"] == "viewer"
        # An email domain (Google sends no groups): verified, at that domain, or nobody.
        set_up(admin, client_secret="", anyone="viewer", domain="example.org")
        assert refused_as(signed_in_by(stranger(admin, 51041), idp, "gmail")) == "email_domain"
        idp.people["pete"].email_verified = False
        assert refused_as(signed_in_by(stranger(admin, 51042), idp, "pete")) == "email_unverified"
        idp.people["pete"].email_verified = True
        idp.people["pete"].more = {"hd": "another.example"}
        assert refused_as(signed_in_by(stranger(admin, 51043), idp, "pete")) == "email_domain"
        idp.people["pete"].more = {}
        assert refused_as(signed_in_by(stranger(admin, 51044), idp, "pete")) == ""


GIVES = {"wall-admins": "admin", "wall-ops": "operator", "wall-viewers": "viewer"}


@pytest.mark.parametrize(
    "groups, anyone, role",
    [
        ([], "", None),  # in no group, and nobody else let in
        (["lunch-club"], "", None),
        (["Wall-Ops"], "", None),  # (another group: its case differs)
        ([], "viewer", "viewer"),  # in no group that gives a role: who else may sign in, as what it says
        (["lunch-club"], "admin", "admin"),
        (["Wall-Ops"], "operator", "operator"),
        (["wall-ops"], "", "operator"),  # in one group
        (["wall-viewers", "wall-ops"], "", "operator"),  # in several: the highest of them
        (["wall-viewers", "wall-admins", "wall-ops", "lunch-club"], "", "admin"),
        (["wall-viewers"], "admin", "viewer"),  # a group's role lower than who else's: the group's
        (["wall-viewers", "lunch-club"], "operator", "viewer"),
        (["wall-ops"], "admin", "operator"),
        (["wall-admins"], "viewer", "admin"),  # ...and higher: the group's too
        (["wall-ops", "wall-viewers"], "viewer", "operator"),
    ],
)  # fmt: skip
def test_a_group_gives_its_role_and_who_else_may_sign_in_is_for_those_in_none(groups: list[str], anyone: str, role: str | None) -> None:
    # (The outside review of 0.4.0, round 6.2, H1.) Who else may sign in was put beside the groups' roles and the
    # highest of them taken: with auditors as viewers and anybody else as an admin, an auditor signed in as an admin. A
    # person in a group that gives a role gets the highest of their groups' roles; who else may sign in is for a person in
    # none of them.
    assert oidc.role_for(groups, OidcSettings(roles=GIVES, anyone=anyone)) == role


def test_somebody_in_a_group_signs_in_with_its_role_whatever_anybody_else_gets(tmp_path: Path, idp: FakeIdp) -> None:
    # (H1, the whole way.) The role the account is made with and changed to at each sign-in is the group's.
    idp.person("audrey", email="audrey@example.org", groups=["wall-viewers"])
    idp.person("pete", email="pete@example.org", groups=["somewhere-else"])
    with wall(tmp_path) as admin:
        set_up(admin, anyone="admin")
        hers, his = stranger(admin, 51060), stranger(admin, 51061)
        assert refused_as(signed_in_by(hers, idp, "audrey")) == "" and refused_as(signed_in_by(his, idp, "pete")) == ""
        assert hers.get("/api/v1/session").json()["user"]["role"] == "viewer" and hers.get("/api/v1/users").status_code == 403
        assert his.get("/api/v1/session").json()["user"]["role"] == "admin"
        made = {entry["account"]: entry["role"] for entry in entries(admin, "user_added")}
        assert (made["audrey@example.org"], made["pete@example.org"]) == ("viewer", "admin")
        # Out of the group at the provider: anybody else's role at the next sign-in, and said so.
        idp.people["audrey"].groups = ["lunch-club"]
        assert refused_as(signed_in_by(stranger(admin, 51062), idp, "audrey")) == ""
        changed = entries(admin, "user_changed")[0]
        assert (changed["account"], changed["role"], changed["was"]) == ("audrey@example.org", "admin", "viewer")
        # ...and back in it: the group's again, though anybody else's is higher.
        idp.people["audrey"].groups = ["wall-viewers"]
        assert refused_as(signed_in_by(stranger(admin, 51063), idp, "audrey")) == ""
        assert entries(admin, "user_changed")[0]["role"] == "viewer"


def test_an_email_domain_is_compared_as_written_and_not_as_python_lowers_it(tmp_path: Path, idp: FakeIdp) -> None:
    # The Kelvin sign (U+212A) is lowered to the letter k: "olga@" + it + "vm.org" was taken for an address at kvm.org,
    # which its owner may not hold at all (review L2). An address that is not plain ASCII is no address at the domain.
    kelvin = chr(0x212A)
    idp.person("kelvin", email=f"olga@{kelvin}vm.org", groups=["wall-ops"])
    idp.person("plain", email="olga@KVM.org", groups=["wall-ops"])
    with wall(tmp_path) as admin:
        set_up(admin, domain="kvm.org")
        assert refused_as(signed_in_by(stranger(admin), idp, "kelvin")) == "email_domain"
        assert refused_as(signed_in_by(stranger(admin, 51120), idp, "plain")) == ""  # (capitals of plain letters are the same domain)
        # ...and so is Google's word for the domain (hd).
        idp.people["plain"].more = {"hd": f"{kelvin}vm.org"}
        assert refused_as(signed_in_by(stranger(admin, 51121), idp, "plain")) == "email_domain"


def test_anybody_else_without_an_email_domain_is_refused_for_google(tmp_path: Path, idp: FakeIdp) -> None:
    # Google signs in any Google account there is, of anybody in the world, where the consent screen is External: "anybody
    # else, as a viewer" without a domain would be anybody at all (review L1). Refused for Google's issuer; for every other
    # provider taken (its accounts are its organisation's), and the page warns (the browser test).
    with wall(tmp_path) as admin:
        reply = admin.put("/api/v1/oidc", json=settings(enabled=False, issuer=oidc.GOOGLE, anyone="viewer", domain="", client_secret=""))
        assert (reply.status_code, reply.json()["code"]) == (422, "invalid") and "email domain" in reply.json()["message"], reply.text
        taken = admin.put("/api/v1/oidc", json=settings(enabled=False, issuer=oidc.GOOGLE, anyone="viewer", domain="example.org", client_secret=""))
        assert taken.status_code == 200, taken.text
        assert admin.put("/api/v1/oidc", json=settings(enabled=False, issuer=oidc.GOOGLE, roles=[], anyone="", domain="", client_secret="")).status_code == 200
        assert admin.put("/api/v1/oidc", json=settings(anyone="viewer", domain="")).status_code == 200  # (another provider)


def test_groups_from_userinfo_and_too_many_groups(tmp_path: Path, idp: FakeIdp) -> None:
    with wall(tmp_path) as admin:
        set_up(admin)
        idp.groups_in_token = False  # (said by userinfo alone, as some providers do)
        hers = stranger(admin)
        assert refused_as(signed_in_by(hers, idp, "olga")) == ""
        assert hers.get("/api/v1/session").json()["user"]["role"] == "operator"
        assert idp.at("/realms/team/userinfo")[0].headers["Authorization"].startswith("Bearer ")
        # Userinfo that speaks of somebody else is not believed.
        idp.userinfo_extra = {"sub": "somebody-else"}
        assert refused_as(signed_in_by(stranger(admin, 51050), idp, "olga")) == "userinfo"
        idp.userinfo_extra = {}
        # Entra ID's "too many groups for the token, fetch them there": said, and not followed.
        idp.groups_in_token = True
        idp.people["olga"].more = {"_claim_names": {"groups": "src1"}, "_claim_sources": {"src1": {"endpoint": "https://graph.example.org/x"}}}
        idp.tamper = lambda header, claims: claims.pop("groups", None)
        assert refused_as(signed_in_by(stranger(admin, 51051), idp, "olga")) == "group_overage"
        failed = [entry for entry in entries(admin, "login_failed") if entry.get("why") == "group_overage"]
        assert "too many groups" in failed[0]["said"]


def test_a_provider_sign_in_needs_the_saved_passwords_open(tmp_path: Path, idp: FakeIdp) -> None:
    # Started locked (--locked-start), and nobody signed in since: the client secret is sealed with the rest, and the
    # provider's button says so instead of sending anybody off to the provider for nothing.
    with wall(tmp_path) as admin:
        set_up(admin)
    with wall(tmp_path, sign_in=False, locked_start=True) as admin:
        reply = stranger(admin).post("/api/v1/oidc/begin")
        assert (reply.status_code, reply.json()["code"]) == (503, "locked")
        assert admin.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
        assert refused_as(signed_in_by(stranger(admin), idp, "olga")) == ""


def test_what_the_provider_routes_save_is_read_by_a_start(tmp_path: Path, idp: FakeIdp) -> None:
    # After each change the settings file as it lies on disk is read by a start by itself, and so is its second copy (as
    # tests/test_every_route_then_a_restart.py reads them after every other route).
    folder, scratch = tmp_path / "data", tmp_path / "scratch"
    scratch.mkdir()
    reads = Reads(folder, scratch)
    with wall(folder) as admin:
        set_up(admin)
        reads("the provider set up")
        assert refused_as(signed_in_by(stranger(admin), idp, "olga")) == ""
        reads("an account the provider signed in for the first time")
        idp.people["olga"].groups = ["wall-admins"]
        assert refused_as(signed_in_by(stranger(admin, 51090), idp, "olga")) == ""
        reads("its role changed by its groups")
        olga = next(user for user in admin.get("/api/v1/users").json()["users"] if user["provider"])
        assert admin.put(f"/api/v1/users/{olga['id']}", json={"name": "Olga.K", "role": "admin", "suspended": True}).status_code == 200
        reads("the account renamed and suspended here")
        set_up(admin, enabled=False, client_secret="", roles=[], anyone="operator", domain="example.org", private=True, name="")
        reads("switched off, with other settings")
    assert not reads.refused, "\n".join(reads.refused)
    with wall(folder, sign_in=False) as admin:  # ...and started on it: all as it was saved
        assert admin.post("/api/v1/login", json={"name": "admin", "password": PASSWORD}).status_code == 200
        kept = admin.get("/api/v1/oidc").json()
        assert (kept["enabled"], kept["anyone"], kept["domain"], kept["private"], kept["has_secret"]) == (False, "operator", "example.org", True, True)
        listed = {user["name"]: user for user in admin.get("/api/v1/users").json()["users"]}
        assert listed["Olga.K"]["provider"] is True and listed["Olga.K"]["suspended"] is True


def test_a_wall_of_0_3_2_has_it_off_and_its_accounts_as_they_were(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        account(admin, "victor", "viewer")
    # What 0.3.2 wrote: no "oidc" part, and accounts without a provider.
    store = Store(tmp_path / "qkvm.json", vault_key_file=key_path(tmp_path), protected=True)
    document = store.snapshot()
    document.pop("oidc")
    for user in document["users"]:
        user.pop("issuer")
        user.pop("subject")
    store.write(document)
    with wall(tmp_path, sign_in=False) as admin:
        assert admin.post("/api/v1/login", json={"name": "admin", "password": PASSWORD}).status_code == 200
        assert admin.get("/api/v1/oidc").json()["enabled"] is False
        assert stranger(admin).get("/api/v1/oidc/offer").json() == {"on": False, "name": ""}
        users = admin.get("/api/v1/users").json()["users"]
        assert {(user["name"], user["role"], user["provider"]) for user in users} == {("admin", "admin", False), ("victor", "viewer", False)}
        assert visitor(admin, 51095).post("/api/v1/login", json={"name": "victor", "password": OTHER}).status_code == 200
        assert set_up_without_provider(admin)["enabled"] is False  # (and saved in this version's shape from then on)
    written = Store(tmp_path / "qkvm.json", vault_key_file=key_path(tmp_path), protected=True).snapshot()
    assert written["oidc"]["enabled"] is False and all(user["subject"] == "" for user in written["users"])


def set_up_without_provider(admin: TestClient) -> dict[str, Any]:
    reply = admin.put("/api/v1/oidc", json={"enabled": False, "name": "Later"})
    assert reply.status_code == 200, reply.text
    return dict(reply.json())


def test_a_role_written_by_hand_that_is_none_is_refused_at_the_start(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        set_up_without_provider(admin)
    path = tmp_path / "qkvm.json"
    for wrong, said in (({"roles": {"wall-ops": "root"}}, "roles"), ({"anyone": "everybody"}, "anyone"), ({"roles": ["wall-ops"]}, "roles")):
        store = Store(path, vault_key_file=key_path(tmp_path), protected=True)
        document = store.snapshot()
        document["oidc"].update(wrong)
        store.write(document)
        (tmp_path / "qkvm.bak").unlink()  # (by itself: no second copy to fall back on)
        with pytest.raises(StoreError) as refused:
            Store(path, vault_key_file=key_path(tmp_path), protected=True)
        assert said in str(refused.value), (wrong, str(refused.value))
        document["oidc"].update({"roles": {}, "anyone": ""})
        Store.write(store, document)


def test_a_sign_in_by_the_provider_lasts_so_long_at_the_most_however_much_it_is_used(tmp_path: Path, idp: FakeIdp, monkeypatch: pytest.MonkeyPatch) -> None:
    # The role is read at sign-in. Renewed by every request (and the open page asks every few seconds), a sign-in lasted 30
    # days, and somebody the provider took out of the admins' group stayed an admin all that time (review M1, probe p2).
    assert oidc.SIGNED_IN_FOR == 8 * 3600
    monkeypatch.setattr(oidc, "SIGNED_IN_FOR", 2.0)  # (so long, here: the test waits for its end)
    with wall(tmp_path) as admin:
        idp.people["olga"].groups = ["wall-admins"]
        set_up(admin)
        hers = stranger(admin)
        assert refused_as(signed_in_by(hers, idp, "olga")) == ""
        began = time.monotonic()
        assert hers.get("/api/v1/users").status_code == 200
        idp.people["olga"].groups = []  # taken out at the provider: her sign-in here ends within its time, used or not
        while hers.get("/api/v1/wall").status_code == 200:
            assert time.monotonic() - began < 15, "the sign-in went on past its time, renewed by its use"
            time.sleep(0.2)
        assert time.monotonic() - began >= 2.0
        assert hers.get("/api/v1/session").json()["authenticated"] is False
        assert admin.get("/api/v1/wall").status_code == 200  # (a sign-in with a password is not the provider's: as before)
        # The button signs her in again, with the role her groups give her now: none.
        assert refused_as(signed_in_by(stranger(admin, 51099), idp, "olga")) == "no_group"


CHANGES_OF_WHO_GETS_WHAT = {
    "a group's role taken away": {"roles": [each for each in ROLES if each["group"] != "wall-admins"]},
    "anybody else let in": {"anyone": "viewer"},
    "an email domain": {"domain": "example.org"},
    "another groups claim": {"groups_claim": "roles"},
    "other scopes": {"scopes": "openid email"},
    "another client": {"client_id": "another-client", "client_secret": "the other client's secret"},
}


@pytest.mark.parametrize("change", list(CHANGES_OF_WHO_GETS_WHAT))
def test_a_change_of_who_gets_what_signs_out_everybody_the_provider_signed_in(change: str, tmp_path: Path, idp: FakeIdp) -> None:
    with wall(tmp_path) as admin:
        idp.people["olga"].groups = ["wall-admins"]
        set_up(admin)
        hers = stranger(admin)
        assert refused_as(signed_in_by(hers, idp, "olga")) == ""
        set_up(admin, client_secret="", name="Renamed")  # (what decides nobody's role: she stays)
        assert hers.get("/api/v1/users").status_code == 200
        set_up(admin, **{"client_secret": "", **CHANGES_OF_WHO_GETS_WHAT[change]})
        assert hers.get("/api/v1/users").status_code == 401 and hers.get("/api/v1/wall").status_code == 401
        assert admin.get("/api/v1/users").status_code == 200


def test_a_change_of_who_gets_what_made_behind_the_saves_back_is_seen_at_the_next_request(tmp_path: Path, idp: FakeIdp) -> None:
    with wall(tmp_path) as admin:
        idp.people["olga"].groups = ["wall-admins"]
        set_up(admin)
        hers = stranger(admin)
        assert refused_as(signed_in_by(hers, idp, "olga")) == ""
        store = admin.core.store  # type: ignore[attr-defined]
        store.oidc = dataclasses.replace(store.oidc, roles={"wall-admins": "viewer"})
        assert hers.get("/api/v1/wall").status_code == 401


def test_a_sign_in_by_the_provider_holds_only_while_that_provider_is_the_walls(tmp_path: Path, idp: FakeIdp) -> None:
    # Whatever changes the settings (the page drops those sign-ins as it saves; this is asked of every request besides).
    with wall(tmp_path) as admin:
        set_up(admin)
        hers = stranger(admin)
        assert refused_as(signed_in_by(hers, idp, "olga")) == ""
        store = admin.core.store  # type: ignore[attr-defined]
        kept = store.oidc
        store.oidc = dataclasses.replace(kept, issuer=ISSUER + "-another")
        assert hers.get("/api/v1/wall").status_code == 401
        store.oidc = kept
        hers = stranger(admin, 51097)
        assert refused_as(signed_in_by(hers, idp, "olga")) == ""
        store.oidc = dataclasses.replace(kept, enabled=False)
        assert hers.get("/api/v1/wall").status_code == 401


def test_the_settings_go_into_a_file_and_come_in_switched_off(tmp_path: Path, idp: FakeIdp) -> None:
    with wall(tmp_path / "one") as admin:
        # A wall that never set one up says nothing of it (taken in, "none" would replace another wall's).
        assert "signin" not in json.loads(admin.post("/api/v1/export", json={"password": PASSWORD, "parts": ["signin", "wall"]}).text)
        set_up(admin)
        plain = admin.post("/api/v1/export", json={"password": PASSWORD, "parts": ["signin"]})
        assert plain.status_code == 200, plain.text
        said = json.loads(plain.text)["signin"]
        assert said["issuer"] == ISSUER and said["roles"] == ROLES and "client_secret" not in said and "redirect_uri" not in said
        sealed = admin.post("/api/v1/export", json={"password": PASSWORD, "parts": ["signin"], "passphrase": "a passphrase for the file"})
        assert sealed.status_code == 200 and SECRET not in sealed.text
    with wall(tmp_path / "two") as other:
        assert other.put("/api/v1/oidc", json={"enabled": False, "redirect_uri": REDIRECT}).status_code == 200  # (its own address)
        read = other.post("/api/v1/import/read", json={"file": sealed.text, "passphrase": "a passphrase for the file"}).json()
        assert read["secrets"] is True and read["signin"] == {
            "enabled": True, "name": "Team SSO", "issuer": ISSUER, "client_id": CLIENT, "password": True, "roles": ROLES, "anyone": "", "domain": "", "private": False,
        }  # fmt: skip
        taken = other.post("/api/v1/import", json={"file": sealed.text, "passphrase": "a passphrase for the file", "take": ["signin"]}).json()
        assert taken["signin"] is True and any("switched off" in line for line in taken["left_out"])
        kept = other.get("/api/v1/oidc").json()
        # A file never switches on a way into the wall: an admin does, in the page, where the provider is asked first.
        assert (kept["enabled"], kept["has_secret"], kept["redirect_uri"], kept["issuer"]) == (False, True, REDIRECT, ISSUER)
        assert other.put("/api/v1/oidc", json=settings(client_secret="")).status_code == 200  # (the secret from the file is kept)
        hers = stranger(other)
        assert refused_as(signed_in_by(hers, idp, "olga")) == ""
        # A plain file, for the same provider and client: the secret saved here stays; it comes in switched off, and whoever
        # the provider signed in is signed out.
        assert other.post("/api/v1/import", json={"file": plain.text, "take": ["signin"]}).json()["signin"] is True
        assert other.get("/api/v1/oidc").json()["has_secret"] is True and hers.get("/api/v1/wall").status_code == 401
        assert "signin" in entries(other, "import_done")[0]["parts"]
        # A plain file for another client: the secret saved here is not kept for it.
        another = json.loads(plain.text)
        another["signin"]["client_id"] = "another-client"
        assert other.post("/api/v1/import", json={"file": json.dumps(another), "take": ["signin"]}).json()["signin"] is True
        assert other.get("/api/v1/oidc").json()["has_secret"] is False
        # What a file says that the page would not take is left out, and said.
        wrong = json.dumps({"format": "qkvm-export", "version": 1, "signin": {"issuer": f"http://{IDP}/x", "client_id": "a b"}})
        read = other.post("/api/v1/import/read", json={"file": wrong}).json()
        assert "signin" not in read and read["left_out"][0].startswith("Sign-in settings: the issuer")


def test_an_account_is_the_providers_person_whatever_its_name(tmp_path: Path, idp: FakeIdp) -> None:
    # Named here by what the provider says (an email, a name), and known by the provider's `sub` with its issuer: a person
    # whose email is that of an account of the wall's own does not become that account, and two people are two accounts.
    with wall(tmp_path) as admin:
        account(admin, "olga@example.org", "admin")
        idp.person("twin", email="olga@example.org", groups=["wall-viewers"])
        set_up(admin)
        hers = stranger(admin)
        assert refused_as(signed_in_by(hers, idp, "olga")) == ""
        mine = hers.get("/api/v1/session").json()["user"]
        assert mine["role"] == "operator" and mine["name"] != "olga@example.org" and mine["name"].startswith("olga@example.org-")
        twin = stranger(admin, 51060)
        assert refused_as(signed_in_by(twin, idp, "twin")) == ""
        theirs = twin.get("/api/v1/session").json()["user"]
        assert theirs["id"] != mine["id"] and theirs["role"] == "viewer"
        # The same person again is the same account.
        again = stranger(admin, 51061)
        assert refused_as(signed_in_by(again, idp, "olga")) == ""
        assert again.get("/api/v1/session").json()["user"]["id"] == mine["id"]
        assert sum(1 for user in admin.get("/api/v1/users").json()["users"] if user["provider"]) == 2
