"""A live line does not keep the sign-in it was opened with alive by itself (the review of 850745e, L-W4).

Whether the one who holds a live line may still be on it is asked at its start, before input and pictures, and every few
seconds: that asking used the sign-in, as a request of the person's would, and so kept it from ever ending while the line
was open. A sign-in by the identity proxy in front of qKVM (--sso-header) holds only while each request carries the
proxy's word for the same person; a line makes no requests, and went on, and kept its sign-in alive, for as long as it was
open, also once the proxy no longer vouched for that person. Now the line asks without using the sign-in, and a line of a
sign-in by the proxy ends once the proxy has not vouched for it on a request for SSO_LIVE_UNCONFIRMED (the page asks
every few seconds while it is shown).
"""
from __future__ import annotations

import gc
import time
from pathlib import Path

from fastapi.testclient import TestClient

from qkvm import live, security
from qkvm.security import COOKIE
from tests.test_sso import STARTED, fast, through_proxy  # noqa: F401  (fast: the fixture of those tests, for these too)
from tests.test_wall import wait_until, wall


def the_lines(core: object) -> live.Lines:
    """This wall's own live lines (to ask what a line asks), and not those of a wall an earlier test made."""
    return next(o for o in gc.get_objects() if type(o) is live.Lines and o.manager.core is core)


def session_of(core: object, client: TestClient) -> security.Session:
    """The sign-in behind this browser's cookie, as the wall keeps it."""
    token = client.cookies.get(COOKIE)
    assert token
    sessions = core.sessions  # type: ignore[attr-defined]
    session = sessions._sessions.get(sessions._key(token))
    assert session is not None
    return session


def test_asking_whether_a_line_may_go_on_does_not_use_the_sign_in(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        session = session_of(admin.core, admin)  # type: ignore[attr-defined]
        session.seen -= 3600.0  # (an hour since this browser last asked anything)
        seen = session.seen
        holder = live.Holder("admin", "admin", True, "127.0.0.1", admin.cookies.get(COOKIE))
        for _ in range(3):
            the_lines(admin.core).standing(holder, "no-such-machine")  # type: ignore[attr-defined]
        assert session.seen == seen, "the line's asking kept the sign-in alive"
        admin.get("/api/v1/wall")  # (a request of the person's does)
        assert session.seen > seen


def test_a_line_of_a_sign_in_by_the_proxy_ends_once_the_proxy_has_not_vouched_for_it_for_a_while(tmp_path: Path) -> None:
    with wall(tmp_path, **STARTED) as admin:
        wait_until(lambda: admin.core.store.unlock is not None, "never made to fit")  # type: ignore[attr-defined]
        assert admin.post("/api/v1/users", json={"name": "olga@example.org", "role": "operator"}).status_code == 201
        hers = through_proxy(admin, "olga@example.org")
        said = hers.get("/api/v1/session").json()
        assert said["authenticated"] is True
        holder = live.Holder(said["user"]["id"], "olga@example.org", True, "192.0.2.9", hers.cookies.get(COOKIE))
        lines = the_lines(admin.core)  # type: ignore[attr-defined]
        assert lines.standing(holder, "no-such-machine")[0] != "unconfirmed"  # (just vouched for: the machine is the matter)
        session = session_of(admin.core, hers)  # type: ignore[attr-defined]
        session.vouched = time.monotonic() - security.SSO_LIVE_UNCONFIRMED - 1  # (nothing through the proxy for that long)
        assert lines.standing(holder, "no-such-machine") == ("unconfirmed", False)
        assert hers.get("/api/v1/wall").status_code == 200  # the proxy names her again: so does the line
        assert lines.standing(holder, "no-such-machine")[0] != "unconfirmed"


def test_the_bound_is_minutes_and_shorter_than_a_sign_in_left_alone() -> None:
    assert 60 <= security.SSO_LIVE_UNCONFIRMED < security.IDLE_TTL
