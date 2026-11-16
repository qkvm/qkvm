"""A KVM whose plain address sends everybody on to HTTPS, added and edited in a browser: the address it names is offered,
and taken only when the person takes it (test_a_kvm_that_sends_plain_http_on_to_https.py has the wall's side).

Needs Playwright and a browser for it, as tests/test_in_a_browser.py does; skipped where they are missing.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api", reason="the browser tests need Playwright (pip install playwright)")

from playwright.sync_api import Browser, expect

from tests.fake_kvm import FakeKvm, FakeState
from tests.test_in_a_browser import DEVICE_PASSWORD, a_wall, browser, looking, sign_in, tile, top  # noqa: F401  (fixtures, by name)


@pytest.fixture
def secure(tmp_path: Path) -> Iterator[FakeKvm]:
    fake = FakeKvm(FakeState(), tls_dir=tmp_path / "tls").start()
    yield fake
    fake.stop()


def test_an_add_at_the_plain_address_offers_the_https_one_and_takes_it_when_asked(tmp_path: Path, browser: Browser, secure: FakeKvm) -> None:  # noqa: F811
    front = FakeKvm(FakeState(https_at=secure.url)).start()
    try:
        with a_wall(tmp_path / "wall") as (live, admin), looking(browser, live) as page:
            sign_in(page, live)
            page.locator("#add-device").click()
            form = top(page)
            form.locator("textarea").fill(front.url)
            form.locator("input[type=password]").fill(DEVICE_PASSWORD)
            form.get_by_role("button", name="Check and add").click()
            asked = form.locator("ul.results li.ask")
            expect(asked).to_contain_text(f"This KVM answers on HTTPS: its plain address sends everybody to {secure.url}")
            assert admin.get("/api/v1/wall").json()["devices"] == [] and secure.state.logins == 0  # (offered, not taken)
            asked.get_by_role("button", name=f"Use {secure.url}").click()
            expect(form.locator("ul.results li.ok")).to_contain_text("added")
            devices = admin.get("/api/v1/wall").json()["devices"]
            assert [device["url"] for device in devices] == [secure.url]
    finally:
        front.stop()


def test_an_edit_of_a_tile_whose_kvm_answers_on_https_since_offers_that_address(tmp_path: Path, browser: Browser, secure: FakeKvm) -> None:  # noqa: F811
    plain = FakeKvm(FakeState()).start()
    try:
        with a_wall(tmp_path / "wall", ("Comet", plain)) as (live, admin), looking(browser, live) as page:
            sign_in(page, live)
            shown = tile(page, "Comet")
            expect(shown).to_have_attribute("data-state", "online", timeout=30_000)
            plain.state.https_at = secure.url  # (HTTPS made its only way in since)
            shown.hover()
            shown.get_by_role("button", name="Actions for Comet").click()
            top(page).get_by_role("button", name="Edit...").click()
            form = top(page)
            form.get_by_role("button", name="Save", exact=True).click()
            expect(form.locator("p.error")).to_contain_text("This KVM answers on HTTPS")
            offered = form.get_by_role("button", name=f"Use {secure.url}")
            offered.click()
            expect(form.get_by_role("textbox", name=re.compile(r"^Address"))).to_have_value(secure.url)  # (put in the box: saved only as any other address is)
            assert admin.get("/api/v1/wall").json()["devices"][0]["url"] == plain.url
            form.locator("input[type=password]").fill(DEVICE_PASSWORD)
            form.get_by_role("button", name="Save", exact=True).click()
            expect(page.locator("#toasts .toast", has_text="Comet saved").first).to_be_visible()
            assert admin.get("/api/v1/wall").json()["devices"][0]["url"] == secure.url
    finally:
        plain.stop()
