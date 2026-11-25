"""NetBird's management API set up in a browser, under Settings > Network: asked once before it is saved, the token never
shown again, and turned off again.

Needs Playwright and a browser for it, as tests/test_in_a_browser.py does; skipped where they are missing. The management
API is tests/fake_netbird.py's, on loopback.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api", reason="the browser tests need Playwright (pip install playwright)")

from playwright.sync_api import Browser, expect

from qkvm import tailnet, update
from tests.fake_netbird import TOKEN, URL, FakeNetbird, peer
from tests.test_in_a_browser import a_wall, browser, looking, settings, sign_in, told, top  # noqa: F401  (fixtures, by name)


@pytest.fixture
def management(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeNetbird]:
    monkeypatch.setattr(update, "DEFAULT_REPO", "")
    monkeypatch.setattr(tailnet, "netbird_command", lambda: None)  # (in a container: no client)
    fake = FakeNetbird(tmp_path / "netbird", monkeypatch)
    fake.peers = [peer("rack-kvm", "100.92.0.7"), peer("office-kvm", "100.92.0.8")]
    yield fake
    fake.stop()


def test_netbird_is_set_up_and_turned_off_under_settings(tmp_path: Path, browser: Browser, management: FakeNetbird) -> None:  # noqa: F811
    with a_wall(tmp_path / "wall") as (live, admin), looking(browser, live) as page:
        sign_in(page, live)
        pane = settings(page, "network")
        nb = pane.locator("section.block", has=page.get_by_role("heading", name="NetBird"))
        expect(nb).to_contain_text("Off")
        nb.get_by_role("button", name="Set up").click()
        box = top(page)
        box.get_by_role("textbox", name="Management API").fill(URL)
        box.locator("input[type=password]").fill("nbp_NotTheRightOne")
        box.get_by_role("button", name="Save").click()
        expect(box.locator("p.error")).to_contain_text("NetBird's management API did not take the token (401)")
        assert admin.get("/api/v1/netbird").json()["url"] == ""  # (refused, and nothing saved)

        box.locator("input[type=password]").fill(TOKEN)
        box.get_by_role("button", name="Save").click()
        told(page, "Saved: NetBird lists 2 connected machines")
        expect(nb).to_contain_text("On: netbird.example.org")

        nb.get_by_role("button", name="Change").click()
        box = top(page)
        expect(box.get_by_role("textbox", name="Management API")).to_have_value(URL)
        expect(box.locator("input[type=password]")).to_have_value("")  # (never shown again)
        expect(box.locator("input[type=password]")).to_have_attribute("placeholder", "Saved. Enter another to replace it.")
        assert TOKEN not in page.content()
        box.get_by_role("button", name="Turn off").click()
        told(page, "NetBird turned off")
        expect(nb).to_contain_text("Off")
        assert admin.get("/api/v1/netbird").json() == {"url": "", "has_token": False, "private": False, "client": False}
