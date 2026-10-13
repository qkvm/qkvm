"""Every route of the wall, and which of the rules that go by the path it falls under: one written list.

Five rules in server.py decide by the path of a request: who may make it (_VIEWER, _OPERATOR; whatever
is in neither takes an admin), what an account that still has to set up two-factor sign-in may do
(_ENROLLING), what a token may not do (_OWN_ACCOUNT) and what is handled one at a time (_CHANGES). The
first three refuse what they no longer match. The last two let it through: a route that slips out of
_CHANGES is changed two at once, and nothing fails. A reviewer who took eight routes out of that rule
found 141 tests beside them still passing. So here is the list as it is meant, written down, and the
app is asked whether it agrees: a route that is added, or renamed, or whose rule was touched, has to be
put here on purpose.

And what the rules are asked about is the path the router serves: one with a line feed after it was
served as the path without, and matched no rule.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

import pytest

from qkvm import server, update
from qkvm.core import Core
from tests.test_wall import fast, wall  # noqa: F401

# (method, path): (the least role that may ask, its marks).
#   C  one of the changes handled one at a time (_CHANGES)
#   T  takes that turn itself, in its handler, for the part that changes what is saved (it talks to a device first)
#   O  what an account does for itself, and a token may not (_OWN_ACCOUNT)
#   E  all that an account may do before its two-factor sign-in is set up (_ENROLLING)
#   F  carries a file (_FILES)
# A POST, PUT or DELETE with neither C nor T changes nothing that is saved, and says below why not.
ROUTES: dict[tuple[str, str], tuple[str, str]] = {
    ("GET", "/"): ("nobody", ""),
    ("GET", "/healthz"): ("nobody", ""),
    ("GET", "/metrics"): ("nobody", ""),  # (asks for a token of its own)
    ("GET", "/static/{name}"): ("nobody", ""),
    ("GET", "/api/v1/session"): ("nobody", ""),
    ("POST", "/api/v1/setup"): ("nobody", "C"),
    ("POST", "/api/v1/login"): ("nobody", "T"),  # (for a code that is used up; the session itself is kept in memory)
    ("POST", "/api/v1/recover"): ("nobody", "C"),
    ("POST", "/api/v1/display"): ("nobody", ""),  # a session, in memory
    ("POST", "/api/v1/logout"): ("viewer", "E"),  # a session, in memory
    ("POST", "/api/v1/password"): ("viewer", "CO"),
    ("POST", "/api/v1/totp/begin"): ("viewer", "OE"),  # what is begun is kept in memory until it is enabled
    ("POST", "/api/v1/totp/enable"): ("viewer", "COE"),
    ("POST", "/api/v1/totp/codes"): ("viewer", "CO"),
    ("POST", "/api/v1/totp/disable"): ("viewer", "CO"),
    ("GET", "/api/v1/about"): ("viewer", ""),
    ("GET", "/api/v1/wall"): ("viewer", ""),
    ("GET", "/api/v1/status"): ("viewer", ""),
    ("GET", "/api/v1/devices/{device_id}/snapshot"): ("viewer", ""),
    ("GET", "/api/v1/actions"): ("operator", ""),
    ("GET", "/api/v1/devices/{device_id}/wol"): ("operator", ""),
    ("POST", "/api/v1/devices/{device_id}/actions"): ("operator", ""),  # done on the device; nothing of the wall's is saved
    ("POST", "/api/v1/devices/{device_id}/console"): ("operator", ""),  # asks the device for a way in
    ("PUT", "/api/v1/wall/order"): ("admin", "C"),
    ("POST", "/api/v1/devices"): ("admin", "T"),
    ("PUT", "/api/v1/devices/{device_id}"): ("admin", "T"),
    ("DELETE", "/api/v1/devices/{device_id}"): ("admin", "C"),
    ("GET", "/api/v1/devices/{device_id}/certificate"): ("admin", ""),
    ("POST", "/api/v1/devices/{device_id}/trust"): ("admin", "T"),
    ("POST", "/api/v1/discover"): ("admin", ""),  # looks, and saves nothing
    ("POST", "/api/v1/actions"): ("admin", "C"),
    ("PUT", "/api/v1/actions/{action_id}"): ("admin", "C"),
    ("DELETE", "/api/v1/actions/{action_id}"): ("admin", "C"),
    ("GET", "/api/v1/users"): ("admin", ""),
    ("POST", "/api/v1/users"): ("admin", "C"),
    ("PUT", "/api/v1/users/{user_id}"): ("admin", "C"),
    ("DELETE", "/api/v1/users/{user_id}"): ("admin", "C"),
    ("POST", "/api/v1/users/{user_id}/logout"): ("admin", ""),  # sessions, in memory
    ("GET", "/api/v1/tokens"): ("admin", ""),
    ("POST", "/api/v1/tokens"): ("admin", "C"),
    ("DELETE", "/api/v1/tokens/{token_id}"): ("admin", "C"),
    ("GET", "/api/v1/security"): ("admin", ""),
    ("PUT", "/api/v1/security"): ("admin", "C"),
    ("POST", "/api/v1/recovery"): ("admin", "C"),
    ("GET", "/api/v1/settings"): ("admin", ""),
    ("PUT", "/api/v1/settings"): ("admin", "C"),
    ("GET", "/api/v1/alerts"): ("admin", ""),
    ("PUT", "/api/v1/alerts"): ("admin", "C"),
    ("POST", "/api/v1/alerts/pause"): ("admin", "C"),
    ("POST", "/api/v1/alerts/test"): ("admin", ""),  # sends one, and saves nothing
    ("GET", "/api/v1/metrics"): ("admin", ""),
    ("POST", "/api/v1/metrics/token"): ("admin", "C"),
    ("DELETE", "/api/v1/metrics/token"): ("admin", "C"),
    ("GET", "/api/v1/update"): ("admin", ""),
    ("PUT", "/api/v1/update"): ("admin", "C"),
    ("POST", "/api/v1/update/check"): ("admin", ""),  # asks, and saves nothing of the settings
    ("POST", "/api/v1/update/install"): ("admin", ""),  # puts the new version beside the settings, which it leaves alone
    ("GET", "/api/v1/audit"): ("admin", ""),
    ("GET", "/api/v1/audit/export"): ("admin", ""),
    ("POST", "/api/v1/export"): ("admin", ""),  # reads
    ("POST", "/api/v1/import/read"): ("admin", "F"),  # reads the file, and saves nothing
    ("POST", "/api/v1/import"): ("admin", "TF"),
}


NAMED = re.compile("{[^}]+}")  # where a path has a name in it: {device_id}


@pytest.fixture
def app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> object:
    monkeypatch.setattr(update, "DEFAULT_REPO", "")
    return server.create_app(Core(tmp_path))


def test_every_route_falls_under_the_rule_it_is_meant_to(app: object) -> None:
    found: dict[tuple[str, str], tuple[str, str]] = {}
    handlers: dict[tuple[str, str], object] = {}
    for route in app.routes:  # type: ignore[attr-defined]
        sample = NAMED.sub("ab12cd34", route.path)
        for method in route.methods:
            call = f"{method} {sample}"
            role = "nobody" if sample in server.PUBLIC or sample.startswith("/static/") else server.required_role(method, sample)
            marks = "".join(
                letter
                for letter, holds in (
                    ("C", server._CHANGES.fullmatch(call)),
                    ("T", "one_change" in inspect.getsource(route.endpoint) and not server._CHANGES.fullmatch(call)),
                    ("O", server._OWN_ACCOUNT.fullmatch(call)),
                    ("E", server._ENROLLING.fullmatch(call)),
                    ("F", sample in server._FILES),
                )
                if holds
            )
            found[(method, route.path)] = (role, marks)
            handlers[(method, route.path)] = route.endpoint
    assert found == ROUTES, {key: (found.get(key), ROUTES.get(key)) for key in found.keys() | ROUTES.keys() if found.get(key) != ROUTES.get(key)}
    # Everything of the wall's own is under the one version, and nothing without one.
    api = [path for _, path in found if path.startswith("/api/")]
    assert len(api) == 58 and all(path.startswith("/api/v1/") for path in api)
    # What was public before a sign-in, and no more than that.
    assert {path for (_, path), (role, _) in ROUTES.items() if role == "nobody" and not path.startswith("/static/")} == server.PUBLIC


def test_what_the_rules_are_asked_is_the_same_whatever_stands_for_a_name(app: object) -> None:
    # The list above was made with one stand-in for every {name} in a path. A rule that took only some
    # names (a letter it does not expect in an id) would let the others fall to the next rule.
    for (method, path), (role, marks) in ROUTES.items():
        if "{" not in path or role == "nobody":
            continue
        for name in ("0", "a" * 64, "Ab_9-x"):
            asked = NAMED.sub(name, path)
            assert server.required_role(method, asked) == role, (method, asked)
            assert bool(server._CHANGES.fullmatch(method + " " + asked)) == ("C" in marks), (method, asked)


@pytest.mark.parametrize("odd", ["%0A", "%0D", "%09", "%00", "%7F", "%1F", "%0A%0A", "%0D%0A"])
def test_a_path_with_a_character_that_is_none_in_it_is_no_path(tmp_path: Path, odd: str) -> None:
    with wall(tmp_path) as admin:
        assert admin.get("/api/v1/wall").status_code == 200
        users = admin.get("/api/v1/users").json()
        for method, path, body in (
            ("GET", f"/api/v1/wall{odd}", None),
            ("GET", f"/api/v1{odd}/wall", None),
            ("GET", f"/healthz{odd}", None),
            ("GET", f"/{odd}", None),
            ("POST", f"/api/v1/users{odd}", {"name": "twin", "role": "viewer", "password": "a password for twin 1"}),
            ("PUT", f"/api/v1/alerts{odd}", {}),
            ("POST", f"/api/v1/logout{odd}", {}),
        ):
            reply = admin.request(method, path, json=body)
            assert (reply.status_code, reply.json()["code"]) == (404, "not_found"), (method, path, reply.status_code)
            assert reply.headers["x-content-type-options"] == "nosniff"  # (it leaves like every other answer)
        assert admin.get("/api/v1/users").json() == users  # nobody was made, and nobody signed out
        # A letter written as its number is the letter, and is served as before.
        assert admin.get("/api/v1/%77all").status_code == 200
        admin.cookies.clear()
        assert admin.get(f"/api/v1/wall{odd}").status_code == 404  # to nobody, the same as to an admin
