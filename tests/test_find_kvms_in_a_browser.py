""""Find KVMs on my network" in a browser: what the search says, and why a tailnet that is there was not in it.

Needs Playwright and a browser for it, as tests/test_in_a_browser.py does; skipped where they are missing. Nothing is
asked on any network: the search's list of addresses and the asking of each are stood in for.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("playwright.sync_api", reason="the browser tests need Playwright (pip install playwright)")

from playwright.sync_api import Browser, expect

from qkvm import discover
from qkvm.discover import Target, Wanted
from tests.test_in_a_browser import a_wall, browser, looking, sign_in, top  # noqa: F401  (fixtures, by name)

REFUSED = "Tailscale's local API did not say who is in the tailnet (403: status access denied)"


def test_a_search_that_finds_nothing_says_so_and_why_a_tailnet_was_not_asked(tmp_path: Path, browser: Browser, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    async def targets(netbird: object = None) -> Wanted:
        return Wanted([Target("127.0.0.9", "http://127.0.0.1:9", "http://127.0.0.1:9")], ["test network"], [REFUSED])

    async def nothing_there(client: Any, target: Target) -> None:
        return None

    monkeypatch.setattr(discover, "targets", targets)
    monkeypatch.setattr(discover, "_what_is", nothing_there)
    with a_wall(tmp_path / "wall") as (live, _), looking(browser, live) as page:
        sign_in(page, live)
        page.locator("#add-device").click()
        dialog = top(page)
        dialog.get_by_role("button", name="Find KVMs on my network").click()
        found = dialog.locator("div.found")
        expect(found).to_contain_text("Asked 1 addresses on test network. No KVM was found that is not on the wall already.")
        expect(found.locator("p.muted", has_text=REFUSED)).to_have_count(1)
        # Nothing of what was not to be shown stands there as a word ("false", where a part had nothing to show).
        assert "false" not in found.inner_text()
