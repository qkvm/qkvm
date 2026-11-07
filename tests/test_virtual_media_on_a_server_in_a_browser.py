"""The Media box of a server, in a browser (0.3.0, A4): an ISO image of the folder qKVM serves them from, in the server's
virtual CD-ROM drive; the box holding still as for every other machine, saying where the controller reads the image from;
asked first, naming the machine and the image; and the folder and the address in Settings, Server images.

Needs Playwright and a browser for it, as tests/test_in_a_browser.py does; skipped where they are missing.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("playwright.sync_api", reason="the browser tests need Playwright (pip install playwright)")

from playwright.sync_api import Browser, Page, expect

from qkvm import kvm, redfish
from tests.fake_redfish import BmcState, FakeBmc
from tests.test_in_a_browser import a_wall, browser, looking, settings, sign_in, tile, told, top  # noqa: F401  (fixtures, by name)
from tests.test_virtual_media_in_a_browser import where_everything_stands
from tests.test_virtual_media_on_a_server import DEBIAN, iso


@pytest.fixture(autouse=True)
def quick(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "STATUS_TTL", 0.2)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(redfish, "LOOK_EVERY", 0.3)
    monkeypatch.setattr(redfish, "MEDIA_LOOK_EVERY", 0.3)
    monkeypatch.setattr(redfish, "FOLLOW_UP", ())
    monkeypatch.setattr(redfish, "CONFIRM_EVERY", 0.05)


@pytest.fixture
def bmc() -> Iterator[FakeBmc]:
    fake = FakeBmc(BmcState(virtual_media="standard", hostname="db-01")).start()
    yield fake
    fake.stop()


@pytest.fixture
def images(tmp_path: Path) -> Path:
    folder = tmp_path / "images"
    folder.mkdir()
    (folder / DEBIAN).write_bytes(iso(DEBIAN))
    for n in range(30):  # (enough for the list to scroll)
        (folder / f"rescue-{n:02}.iso").write_bytes(iso(str(n), 4096))
    return folder


def add_the_server(admin: Any, fake: FakeBmc) -> None:
    reply = admin.post("/api/v1/devices", json={"url": fake.url, "password": "secret", "name": "db-01"})
    assert reply.status_code == 201, reply.text


def open_the_box(page: Page) -> Any:
    tile(page, "db-01").get_by_role("button", name="Actions for db-01").click()
    top(page).get_by_role("button", name="Media...").click()
    box = top(page)
    expect(box.locator("h2")).to_have_text("Virtual media of db-01")
    return box


def test_a_servers_media_box_holds_still_says_where_its_image_is_read_from_and_mounts_what_it_named(tmp_path: Path, browser: Browser, bmc: FakeBmc, images: Path) -> None:  # noqa: F811
    with a_wall(tmp_path / "wall") as (live, admin), looking(browser, live, viewport={"width": 1280, "height": 860}) as page:
        add_the_server(admin, bmc)
        sign_in(page, live)
        expect(tile(page, "db-01")).to_have_attribute("data-state", "online", timeout=30_000)

        # Settings, Server images: the folder and the address, its Save at the right of its first line.
        pane = settings(page, "media")
        save = top(page).locator(".section-does").get_by_role("button", name=re.compile("Save"))
        head = top(page).locator(".section-head").bounding_box()
        assert head is not None and save.bounding_box() is not None and save.bounding_box()["x"] > head["x"] + head["width"] / 2  # type: ignore[index]
        expect(pane).to_contain_text("Nowhere: qKVM listens on this computer alone")
        pane.get_by_label("Folder").fill(str(images))
        pane.get_by_label("Address servers reach qKVM at").fill(live.url)
        save.click()
        told(page, "Server image settings saved")
        expect(pane).to_contain_text(live.url)
        top(page).get_by_role("button", name="Close").click()

        expect(tile(page, "db-01")).to_have_attribute("data-state", "online")
        box = open_the_box(page)
        mount = box.get_by_role("button", name="Mount", exact=True)
        expect(box.get_by_role("button", name="Unmount", exact=True)).to_be_disabled()
        debian = box.get_by_role("radio", name=re.compile(r"^debian-13\.iso"))
        expect(debian).to_be_visible(timeout=20_000)
        listed = where_everything_stands(page, box)
        assert listed["mount"][0] > listed["box"][0] + listed["box"][2] / 2 and listed["mount"][1] < listed["unmount"][1] < listed["list"][1]
        assert box.locator(".media-list").evaluate("list => list.scrollHeight > list.clientHeight + 100")
        expect(box.locator(".media-head")).to_contain_text("In the folder qKVM serves them from")
        expect(box.locator(".media-foot")).to_contain_text(f"Its controller reads it from qKVM at {live.url} for as long as it is mounted")
        # A CD-ROM drive is all a server takes them as; nothing to upload or delete; once and until unmounted both offered.
        expect(box.get_by_role("button", name="Upload...")).to_be_disabled()
        expect(box.get_by_role("button", name="Delete", exact=True)).to_be_disabled()
        assert box.get_by_label("Mount as").evaluate("select => [...select.options].filter(option => !option.disabled).map(option => option.value)") == ["cd"]
        assert box.get_by_label("Start from it").evaluate("select => [...select.options].filter(option => !option.disabled).map(option => option.value)") == ["none", "once", "until_unmounted"]

        debian.check()
        mount.click()
        question = top(page)
        expect(question.locator("h2")).to_have_text("Mount debian-13.iso")
        expect(question).to_contain_text("db-01 gets debian-13.iso in its CD-ROM drive, read-only, and its boot order is left as it is.")
        question.get_by_role("button", name="Cancel").click()
        assert bmc.state.media_said == []
        mount.click()
        top(page).get_by_role("button", name="Mount", exact=True).click()
        told(page, "db-01: Mount debian-13.iso done")
        expect(box.locator(".media-now")).to_contain_text("debian-13.iso on qKVM · read-only · mounted by admin at")
        assert bmc.state.media_inserted and [status for status, _, _ in bmc.state.media_read] == [206, 206]
        assert where_everything_stands(page, box) == listed
        box.get_by_role("button", name="Close").click()
        expect(tile(page, "db-01").locator(".meta")).to_contain_text("CD: debian-13.iso")

        box = open_the_box(page)
        expect(box.locator(".media-now")).to_contain_text("debian-13.iso on qKVM", timeout=20_000)
        box.get_by_role("button", name="Unmount", exact=True).click()
        question = top(page)
        expect(question).to_contain_text("debian-13.iso is taken out of the drive of db-01.")
        question.get_by_role("button", name="Unmount", exact=True).click()
        told(page, "db-01: Unmount debian-13.iso done")
        expect(box.locator(".media-now")).to_have_text("Nothing is mounted.")
        assert not bmc.state.media_inserted and bmc.state.media_ejects == 1
        assert where_everything_stands(page, box) == listed


def test_a_mount_the_controller_took_and_does_not_show_is_said_in_the_walls_words(tmp_path: Path, browser: Browser, images: Path, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    # (A trial on a real AMI board before the release of 0.3.0: the wall answered "The controller took the mount, and does
    # not show the image in its drive" with the code of a timeout, and the page said "No answer ... it may have been
    # done" in place of it. An answer the wall gave is said as it gave it.)
    monkeypatch.setattr(redfish, "CONFIRM_WITHIN", 1.0)
    fake = FakeBmc(BmcState(virtual_media="standard", hostname="db-01", media_ignored=True)).start()
    try:
        with a_wall(tmp_path / "wall") as (live, admin), looking(browser, live) as page:
            add_the_server(admin, fake)
            assert admin.put("/api/v1/settings/media", json={"folder": str(images), "address": live.url}).status_code == 200
            sign_in(page, live)
            expect(tile(page, "db-01")).to_have_attribute("data-state", "online", timeout=30_000)
            box = open_the_box(page)
            box.get_by_role("radio", name=re.compile(r"^debian-13\.iso")).check()
            box.get_by_role("button", name="Mount", exact=True).click()
            top(page).get_by_role("button", name="Mount", exact=True).click()
            said = box.locator(".media-said")
            expect(said).to_contain_text("The controller took the mount, and does not show the image in its drive", timeout=30_000)
            expect(said).not_to_contain_text("No answer")
    finally:
        fake.stop()


def test_a_look_that_gets_no_answer_after_an_unmount_keeps_the_box_and_asks_again(tmp_path: Path, browser: Browser, bmc: FakeBmc, images: Path) -> None:  # noqa: F811
    # (The owner's trial on a real AMI board, 2026-11-04: its unmount was done in about a second, the spinner hardly seen;
    # the box's next look met the one in many that the controller did not answer in time, and the box said only "Device did
    # not respond in time" over "No images to show": whether it was unmounted could not be told.)
    with a_wall(tmp_path / "wall") as (live, admin), looking(browser, live) as page:
        add_the_server(admin, bmc)
        assert admin.put("/api/v1/settings/media", json={"folder": str(images), "address": live.url}).status_code == 200
        sign_in(page, live)
        expect(tile(page, "db-01")).to_have_attribute("data-state", "online", timeout=30_000)
        box = open_the_box(page)
        box.get_by_role("radio", name=re.compile(r"^debian-13\.iso")).check()
        box.get_by_role("button", name="Mount", exact=True).click()
        top(page).get_by_role("button", name="Mount", exact=True).click()
        said = box.locator(".media-said")
        expect(said).to_have_text("Mount debian-13.iso: done.", timeout=30_000)
        expect(box.locator(".media-now")).to_contain_text("debian-13.iso on qKVM")

        missed: list[str] = []

        def once_no_answer(route: Any) -> None:
            if route.request.method == "GET" and not missed:
                missed.append(route.request.url)
                route.fulfill(status=504, content_type="application/json", body='{"code": "timeout", "message": "Device did not respond in time"}')
                return
            route.continue_()

        page.route(re.compile(r".*/api/v1/devices/[^/]+/media$"), once_no_answer)
        box.get_by_role("button", name="Unmount", exact=True).click()
        top(page).get_by_role("button", name="Unmount", exact=True).click()
        expect(said).to_have_text("Unmount debian-13.iso: done. Device did not respond in time. Asked again in a moment.", timeout=30_000)
        expect(said).to_have_class(re.compile(r"\berror\b"))
        expect(box.locator(".media-now")).to_have_text("Not known just now: its controller did not answer.")
        expect(box.get_by_role("radio", name=re.compile(r"^debian-13\.iso"))).to_be_visible()  # (the images stay)
        expect(box.get_by_role("radio", name=re.compile(r"^debian-13\.iso"))).not_to_contain_text("mounted now")
        expect(box.get_by_role("button", name="Unmount", exact=True)).to_be_disabled()
        # Asked again by itself: what is so, and nothing of the look that got no answer.
        expect(box.locator(".media-now")).to_have_text("Nothing is mounted.", timeout=15_000)
        expect(said).not_to_contain_text("did not respond")
        assert len(missed) == 1 and not bmc.state.media_inserted
