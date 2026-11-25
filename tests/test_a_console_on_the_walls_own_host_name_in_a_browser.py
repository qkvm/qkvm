"""The enlarged view's "Open console", where the server's own page is on the host name the wall is looked at under.

A browser keeps what signs it in to the wall by host name and not by port: a device whose page is on another port of the
wall's own name would be handed the wall's session cookie (SECURITY.md, "qKVM has a host name of its own"). The tile and
its actions offer no link to such a console and say why. The enlarged view's button was always there, and its click asked
the wall for a pass into the console and opened the device's page with it: the review of 0.2.0 saw the cookie go along
(web\\probe_page_focus_open_console.py). Now the button is not there where no link is offered, its click does nothing if it
comes all the same, and the wall itself makes out no pass to such a page.

Needs Playwright and a browser for it, as tests/test_in_a_browser.py does.
"""

from __future__ import annotations

import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

pytest.importorskip("playwright.sync_api", reason="the browser tests need Playwright (pip install playwright)")

from playwright.sync_api import Browser, expect

from tests.fake_redfish import FakeBmc
from tests.test_in_a_browser import a_wall, browser, fast, looking, sign_in, tile  # noqa: F401

ASK_FOR_A_PASS = """async id => {
  const reply = await fetch(`api/v1/devices/${id}/console`, {method: 'POST', headers: {'X-QKVM': '1', 'Content-Type': 'application/json'}, body: '{}'});
  return [reply.status, (await reply.json()).code || ''];
}"""


def offers_its_console(admin: httpx.Client, device: str) -> None:
    deadline = time.monotonic() + 40
    while not (admin.get("/api/v1/status").json().get(device) or {}).get("console"):
        assert time.monotonic() < deadline, "the controller never offered its console"
        time.sleep(0.3)


def test_the_enlarged_view_offers_no_console_on_the_walls_own_host_name(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    server = FakeBmc().start()  # on 127.0.0.1, where the wall is looked at too: at another port
    try:
        with a_wall(tmp_path, ("A server", server)) as (live, admin), looking(browser, live) as page:
            device = admin.get("/api/v1/wall").json()["devices"][0]["id"]
            offers_its_console(admin, device)
            sign_in(page, live)
            expect(tile(page, "A server")).to_have_attribute("data-state", "online", timeout=40_000)
            asked: list[str] = []
            page.on("request", lambda request: asked.append(request.method) if urlsplit(request.url).path.endswith("/console") else None)
            tile(page, "A server").click()
            expect(page.locator("#focus-name")).to_have_text("A server")
            expect(page.locator("#focus-open")).to_be_hidden()
            # A click that comes all the same (a key, a script, a button left over from before): nothing is asked, nothing opens.
            page.locator("#focus-open").dispatch_event("click")
            page.wait_for_timeout(600)
            assert asked == [] and len(page.context.pages) == 1 and server.state.passes == []
            # And the wall makes out no pass to that page, whoever asks it.
            assert page.evaluate(ASK_FOR_A_PASS, device) == [409, "same_host"]
            assert server.state.passes == []

            # Reached by the browser under another name, the same server's console is offered, and leads straight in.
            elsewhere = server.url.replace("127.0.0.1", "localhost") + "/"
            moved = admin.put(f"/api/v1/devices/{device}", json={"url": server.url, "open_url": elsewhere})
            assert moved.status_code == 200, moved.text
            page.reload()
            expect(tile(page, "A server")).to_have_attribute("data-state", "online", timeout=40_000)
            tile(page, "A server").click()
            expect(page.locator("#focus-name")).to_have_text("A server")
            opener = page.locator("#focus-open")
            expect(opener).to_be_visible()
            expect(opener).to_have_attribute("href", elsewhere)
            with page.expect_response(lambda reply: urlsplit(reply.url).path.endswith("/console")) as answered:
                opener.click()
            assert answered.value.status == 200
            assert answered.value.json()["url"].startswith(elsewhere) and len(server.state.passes) == 1
            for other in page.context.pages[1:]:
                other.close()
    finally:
        server.stop()


def test_the_enlarged_views_console_is_the_servers_it_shows_and_none_of_the_one_an_edit_put_in_its_place(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    # (The fresh review of the HA round, L1.) The way into a server's console was asked by the tile's id alone: a page with the wall as
    # it was got a signed-in way into the console of the server an admin had put under the tile meanwhile. It names the server
    # it shows (`target`); refused (409 `machine_changed`), nothing is made out there, and the wall is fetched again.
    server, other = FakeBmc().start(), FakeBmc().start()
    try:
        with a_wall(tmp_path, ("A server", server)) as (live, admin), looking(browser, live) as page:
            shown = admin.get("/api/v1/wall").json()["devices"][0]
            # (Reached by the browser under another name than the wall's, as above, so that its console is offered.)
            assert admin.put(f"/api/v1/devices/{shown['id']}", json={"url": server.url, "open_url": server.url.replace("127.0.0.1", "localhost") + "/"}).status_code == 200
            offers_its_console(admin, shown["id"])
            sign_in(page, live)
            expect(tile(page, "A server")).to_have_attribute("data-state", "online", timeout=40_000)
            tile(page, "A server").click()
            opener = page.locator("#focus-open")
            expect(opener).to_be_visible()
            target = page.evaluate(f"tiles.get('{shown['id']}').device.target")
            fetched: list[object] = []
            page.route("**/api/v1/wall", lambda route: fetched.append(route))  # (the wall as it was stays on the page until let through)
            moved = admin.put(f"/api/v1/devices/{shown['id']}", json={"url": other.url, "username": "admin", "password": "secret", "open_url": other.url.replace("127.0.0.1", "localhost") + "/"})
            assert moved.status_code == 200 and moved.json()["device"]["target"] != target, moved.text
            offers_its_console(admin, shown["id"])
            with page.expect_response(lambda reply: urlsplit(reply.url).path.endswith("/console")) as answered:
                opener.click()
            assert (answered.value.status, parse_qs(urlsplit(answered.value.url).query).get("target")) == (409, [target]), answered.value.url
            page.wait_for_timeout(300)
            assert other.state.passes == [] and server.state.passes == [] and len(page.context.pages) == 1
            for _ in range(100):
                if fetched:
                    break
                page.wait_for_timeout(100)
            assert fetched, "the page never fetched the wall again"
            for route in fetched:
                route.continue_()  # type: ignore[attr-defined]
    finally:
        server.stop()
        other.stop()
