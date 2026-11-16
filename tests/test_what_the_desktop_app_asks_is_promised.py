"""Every request the qKVM Desktop App makes of a wall is promised in the README's API, and served.

The Desktop App is a client of a wall's API, through a qKVM server: what it asks of a wall has to stay as it is within
v1, and the README's table of "The requests" is what is promised that way (what is named under "The page's own" may
change with the page). This is the list of what it asks, written down here by hand from the desktop's client (its
server_client.cpp, as released in 0.1.2) and from the brief of qKVM 0.3.2: each request with the parameters it sends
in its address. A request the Desktop App begins to make is added here, and to the table, before it is released.
"""

from __future__ import annotations

import re
from pathlib import Path

from qkvm import server
from qkvm.core import Core
from tests.test_the_api_as_promised import TABLE, rows, served

# (method, path with each name in braces, the parameters it sends in the address)
DESKTOP_ASKS: list[tuple[str, str, tuple[str, ...]]] = [
    ("GET", "/healthz", ()),
    ("GET", "/api/v1/session", ()),
    ("POST", "/api/v1/login", ()),
    ("POST", "/api/v1/logout", ()),
    ("POST", "/api/v1/display", ()),
    ("GET", "/api/v1/status", ()),
    ("GET", "/api/v1/wall", ()),
    ("PUT", "/api/v1/wall/order", ()),
    ("GET", "/api/v1/actions", ()),
    ("POST", "/api/v1/devices/{id}/actions", ()),
    ("GET", "/api/v1/devices/{id}/snapshot", ("w", "age")),
    ("POST", "/api/v1/devices/{id}/live", ()),  # ...and the WebSocket at the same path, below
    ("POST", "/api/v1/devices/{id}/console", ()),
    ("GET", "/api/v1/devices/{id}/history", ("what", "every", "limit")),
    ("PUT", "/api/v1/devices/{id}/view", ()),
    ("GET", "/api/v1/devices/{id}/wol", ()),
    ("GET", "/api/v1/devices/{id}/media", ()),
    ("POST", "/api/v1/devices/{id}/media", ()),
    ("POST", "/api/v1/devices/{id}/media/unmount", ()),
    ("POST", "/api/v1/devices/{id}/media/delete", ()),
    ("GET", "/api/v1/devices/{id}/media/upload", ()),
    ("POST", "/api/v1/devices/{id}/media/upload", ("name", "machine")),
    ("POST", "/api/v1/export", ()),
    ("POST", "/api/v1/import", ()),
    ("POST", "/api/v1/import/read", ()),
    ("GET", "/api/v1/audit", ("device", "limit")),  # a machine's activity, in its Details
    ("GET", "/api/v1/devices/{id}/alert-picture/{stamp}", ()),  # the picture of a screen alert, as that activity names it
]
LIVE = "/api/v1/devices/{device_id}/live"  # the live line, a WebSocket: let in by a pass, and so named by no method in the table
NAMED = re.compile(r"{[^}]+}")


def test_every_request_of_the_desktop_app_is_promised_and_served(tmp_path: Path) -> None:
    promised = rows()
    there = served(server.create_app(Core(tmp_path)))
    unpromised, unserved, unnamed = [], [], []
    for method, path, parameters in DESKTOP_ASKS:
        asked = (method, NAMED.sub("{}", path))
        if asked not in promised:
            unpromised.append(f"{method} {path}")
            continue
        if asked not in there:
            unserved.append(f"{method} {path}")
        row = promised[asked][1]
        first = row.split("|")[1]  # (the request, as the row writes it)
        # Each parameter it sends is named in its row: in the address the row gives (?name=), or in backticks.
        unnamed += [f"{method} {path}: {name}" for name in parameters if not re.search(rf"[?&]{name}=", first) and f"`{name}`" not in row]
    assert not unpromised, f"the Desktop App asks these, which the README does not promise: {unpromised}"
    assert not unserved, f"the Desktop App asks these, which the wall does not serve: {unserved}"
    assert not unnamed, f"parameters the Desktop App sends that the row does not name: {unnamed}"


def test_the_live_line_the_desktop_app_opens_is_promised_and_served(tmp_path: Path) -> None:
    app = server.create_app(Core(tmp_path))
    assert any(getattr(route, "methods", None) is None and route.path == LIVE for route in app.routes), "no WebSocket for the live line"  # type: ignore[attr-defined]
    assert "| a WebSocket at `/api/v1/devices/{id}/live`" in TABLE, "the live line is not in the README's table"


def test_the_list_says_each_request_once() -> None:
    assert len({(method, path) for method, path, _ in DESKTOP_ASKS}) == len(DESKTOP_ASKS) == 27
