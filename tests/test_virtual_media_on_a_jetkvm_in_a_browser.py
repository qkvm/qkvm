"""The Media box of a JetKVM, in a browser (0.3.0, A3): what an image goes in as (a CD-ROM drive or a disk, read-only either
way), the question saying first that a change between the two drops its keyboard and mouse for a moment, and an upload.

Needs Playwright and a browser for it, as tests/test_in_a_browser.py does; skipped where they are missing.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api", reason="the browser tests need Playwright (pip install playwright)")

from playwright.sync_api import Browser, expect

from qkvm import kvm
from qkvm.kvm import MEDIA_NOTES
from tests.fake_jetkvm import FakeJetKvm, JetState
from tests.test_in_a_browser import a_wall, browser, looking, sign_in, tile, told, top, until  # noqa: F401  (fixtures, by name)
from tests.test_virtual_media_in_a_browser import where_everything_stands
from tests.test_virtual_media_on_a_kvm_in_a_browser import an_image, enabled, open_the_box

DEBIAN = "debian-13.iso"


@pytest.fixture(autouse=True)
def quick(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "STATUS_TTL", 0.2)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    MEDIA_NOTES.mounted.clear()
    MEDIA_NOTES.hashes.clear()


@pytest.fixture
def jet() -> Iterator[FakeJetKvm]:
    fake = FakeJetKvm(JetState(files={DEBIAN: {"size": 700_000_000, "createdAt": "2026-10-30T09:12:44Z", "sha256": ""}}, upload_pause=0.02)).start()
    yield fake
    fake.stop()


def test_a_jetkvms_media_box_says_first_that_its_keyboard_drops_and_mounts_as_a_disk(tmp_path: Path, browser: Browser, jet: FakeJetKvm) -> None:  # noqa: F811
    upload_path, sha = an_image(tmp_path, "tools.img", 2_000_000)
    with a_wall(tmp_path / "wall", ("jet", jet)) as (live, admin), looking(browser, live, viewport={"width": 1280, "height": 860}) as page:
        sign_in(page, live)
        expect(tile(page, "jet")).to_have_attribute("data-state", "online", timeout=40_000)
        device = admin.get("/api/v1/wall").json()["devices"][0]["id"]
        until(page, lambda: "media" in admin.get("/api/v1/status").json()[device].get("can", []), "the JetKVM's storage was never found")
        page.wait_for_timeout(2500)  # (the page's next look at the tiles has it too)
        box = open_the_box(page, "jet")
        debian = box.get_by_role("radio", name=re.compile(r"^debian-13\.iso"))
        expect(debian).to_be_visible(timeout=30_000)
        listed = where_everything_stands(page, box)
        # A CD-ROM drive or a disk, read-only either way: nothing writable, no flash drive.
        assert enabled(box.get_by_label("Mount as")) == ["cd", "disk"]
        expect(box.locator(".media-foot")).to_contain_text("A switch between the two drops its keyboard and mouse for a moment.")
        debian.check()
        box.get_by_label("Mount as").select_option("disk")
        box.get_by_role("button", name="Mount", exact=True).click()
        question = top(page)
        expect(question).to_contain_text("jet gets debian-13.iso as a disk, read-only, and nothing else is done")
        expect(question).to_contain_text("Its keyboard and mouse drop for a moment if this switches its drive between CD-ROM and disk.")
        question.get_by_role("button", name="Mount", exact=True).click()
        told(page, "jet: Mount debian-13.iso done")
        expect(box.locator(".media-now")).to_contain_text("debian-13.iso · disk · read-only · mounted by admin at")
        assert jet.state.mounted == {"source": "Storage", "mode": "Disk", "filename": DEBIAN, "size": 700_000_000} and jet.state.rebinds == 1
        assert where_everything_stands(page, box) == listed
        # An unmount says it too.
        box.get_by_role("button", name="Unmount", exact=True).click()
        expect(top(page)).to_contain_text("Its keyboard and mouse may drop for a moment.")
        top(page).get_by_role("button", name="Unmount", exact=True).click()
        told(page, "jet: Unmount debian-13.iso done")
        # An upload, into its own storage, with its hash said after it.
        with page.expect_file_chooser() as chooser:
            box.get_by_role("button", name="Upload...").click()
        chooser.value.set_files(str(upload_path))
        top(page).get_by_role("button", name="Upload", exact=True).click()
        told(page, "jet: Upload tools.img done")
        expect(box.locator(".media-said")).to_have_text(f"tools.img is on the KVM, SHA-256 {sha}")
        assert jet.state.files["tools.img"]["sha256"] == sha
        assert where_everything_stands(page, box) == listed
        assert jet.state.media_never == []
