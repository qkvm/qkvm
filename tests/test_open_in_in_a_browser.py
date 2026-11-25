""""Open in" on a tile's menu, in a real browser: an admin sets a machine's links in a box of their own, the menu offers
them as plain links (MeshCentral in a new tab, RustDesk by its rustdesk:// link) and a small .rdp file holding the host
and nothing else; an operator sees them and sets none.

Beside tests/test_in_a_browser.py, whose helpers it borrows. Playwright and a browser, or the test is skipped; the page
throws nothing, breaks none of its rules and asks nobody but its wall (the helpers see to that).
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api", reason="the browser tests need Playwright (pip install playwright)")

from playwright.sync_api import Browser, expect

from tests.fake_kvm import FakeKvm
from tests.test_in_a_browser import a_wall, browser, fast, looking, sign_in, top, until  # noqa: F401  (fixtures, by name)

OLGA = "a password for olga, long enough"
MESH = "https://mesh.example.org/?gotonode=AbCd12@$Ef&viewmode=10"


def test_an_admin_sets_a_machines_links_and_an_operator_opens_them(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    fake = FakeKvm().start()
    try:
        with a_wall(tmp_path, ("Build server", fake)) as (live, admin):
            assert admin.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": OLGA}).status_code == 201
            with looking(browser, live, accept_downloads=True) as page:
                sign_in(page, live, name="admin")
                page.get_by_role("button", name="Actions for Build server").click()
                menu = top(page)
                expect(menu.locator("[data-open-in]")).to_have_count(0)
                menu.get_by_role("button", name="Open in...").click()
                box = top(page)
                expect(box.locator("h2")).to_have_text("Open in: Build server")
                # One that is no such link: said in the box, and nothing is saved.
                box.get_by_label("MeshCentral").fill("http://mesh.example.org/")
                box.get_by_role("button", name="Save").click()
                expect(box.locator("p.error")).to_contain_text("https:// address")
                assert "open_in" not in admin.get("/api/v1/wall").json()["devices"][0]
                box.get_by_label("MeshCentral").fill(MESH)
                box.get_by_label("RustDesk").fill("123 456 789")
                box.get_by_label("Remote Desktop").fill("PC-7.example.org")
                box.get_by_role("button", name="Save").click()
                expect(page.locator("dialog[open]")).to_have_count(0)
                assert admin.get("/api/v1/wall").json()["devices"][0]["open_in"] == {"meshcentral": MESH, "rustdesk": "123456789", "rdp": "pc-7.example.org"}

                page.get_by_role("button", name="Actions for Build server").click()
                menu = top(page)
                mesh = menu.locator("a[data-open-in=meshcentral]")
                expect(mesh).to_have_attribute("href", MESH)
                expect(mesh).to_have_attribute("target", "_blank")
                expect(mesh).to_have_attribute("rel", "noopener noreferrer")
                expect(menu.locator("a[data-open-in=rustdesk]")).to_have_attribute("href", "rustdesk://connection/new/123456789")
                with page.expect_download() as got:
                    menu.locator("button[data-open-in=rdp]").click()
                download = got.value
                assert download.suggested_filename == "Build-server.rdp"
                # The host, and nothing else: no account, no password, no other setting.
                assert Path(download.path()).read_bytes() == b"full address:s:pc-7.example.org\r\n"
                # Opened again, the box shows them as they are kept.
                menu.get_by_role("button", name="Open in...").click()
                expect(top(page).get_by_label("RustDesk")).to_have_value("123456789")

            with looking(browser, live) as page:
                sign_in(page, live, password=OLGA, name="olga")
                page.get_by_role("button", name="Actions for Build server").click()
                menu = top(page)
                expect(menu.locator("[data-open-in]")).to_have_count(3)
                expect(menu.get_by_role("button", name="Open in...")).to_be_hidden()
                # A MeshCentral on the host name this wall is looked at under (another port of it): not offered, as a console
                # link there is not, since a browser would hand that page the sign-in to qKVM.
                device = admin.get("/api/v1/wall").json()["devices"][0]["id"]
                assert admin.put(f"/api/v1/devices/{device}/open-in", json={"meshcentral": "https://127.0.0.1:4443/", "rdp": "pc-7.example.org"}).status_code == 200
                page.keyboard.press("Escape")
                page.reload()
                page.get_by_role("button", name="Actions for Build server").click()
                menu = top(page)
                expect(menu.locator("[data-open-in=rdp]")).to_have_count(1)
                expect(menu.locator("[data-open-in=meshcentral]")).to_have_count(0)
    finally:
        fake.stop()


def test_links_typed_for_the_machine_the_box_was_opened_for_are_not_saved_on_the_one_put_in_its_place(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    # (The fresh review of the HA round, L1.) The box saved by the tile's id alone: links typed for one machine landed on the tile of
    # the machine an admin had put there meanwhile. It names the machine it was opened for (`target`): refused, nothing saved,
    # said in the box, and the wall is fetched again.
    first, second = FakeKvm().start(), FakeKvm().start()
    try:
        with a_wall(tmp_path, ("Build server", first)) as (live, admin), looking(browser, live) as page:
            sign_in(page, live)
            device = admin.get("/api/v1/wall").json()["devices"][0]
            page.get_by_role("button", name="Actions for Build server").click()
            top(page).get_by_role("button", name="Open in...").click()
            box = top(page)
            box.get_by_label("RustDesk").fill("123 456 789")
            edited = admin.put(f"/api/v1/devices/{device['id']}", json={"name": "Build server", "url": second.url, "username": "admin", "password": "secret"})
            assert edited.status_code == 200 and edited.json()["device"]["target"] != device["target"], edited.text
            box.get_by_role("button", name="Save").click()
            expect(box.locator("p.error")).to_contain_text("is not the machine you saw any more")
            assert not admin.get("/api/v1/wall").json()["devices"][0].get("open_in")
            now = edited.json()["device"]["target"]
            until(page, lambda: page.evaluate(f"tiles.get('{device['id']}').device.target") == now, "the page never fetched the wall again")
    finally:
        first.stop()
        second.stop()
