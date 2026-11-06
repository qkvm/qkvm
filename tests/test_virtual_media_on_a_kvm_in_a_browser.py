"""The Media box of a kvmd KVM (a GL.iNet Comet, a PiKVM), in a browser (0.3.0, A2): what an image goes in as (a CD-ROM
drive, a USB flash drive read-only or writable as chosen), an image uploaded from this computer with its progress said in
place, one deleted; and the box holding still through all of it (one size and place, its controls where they stood, only
its list scrolling).

Needs Playwright and a browser for it, as tests/test_in_a_browser.py does; skipped where they are missing.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api", reason="the browser tests need Playwright (pip install playwright)")

from playwright.sync_api import Browser, Locator, Page, expect

from qkvm import kvm
from qkvm.kvm import MEDIA_NOTES
from tests.fake_kvm import FakeKvm, FakeState
from tests.test_in_a_browser import a_wall, browser, looking, sign_in, tile, told, top, until  # noqa: F401  (fixtures, by name)
from tests.test_virtual_media_in_a_browser import where_everything_stands

DEBIAN = "debian-13.iso"


@pytest.fixture(autouse=True)
def quick(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kvm, "STATUS_TTL", 0.2)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "MSD_EVERY", 0.5)
    MEDIA_NOTES.mounted.clear()
    MEDIA_NOTES.hashes.clear()


@pytest.fixture
def comet() -> Iterator[FakeKvm]:
    images = {DEBIAN: 700_000_000, **{f"rescue-{n:02}.iso": 50_000_000 + n for n in range(30)}}
    state = FakeState(msd=True, msd_images={name: {"complete": True, "removable": True, "size": size, "mod_ts": 1.0, "sha256": ""} for name, size in images.items()})
    fake = FakeKvm(state).start()
    yield fake
    fake.stop()


def open_the_box(page: Page, name: str = "comet") -> Locator:
    tile(page, name).get_by_role("button", name=f"Actions for {name}").click()
    top(page).get_by_role("button", name="Media...").click()
    box = top(page)
    expect(box.locator("h2")).to_have_text(f"Virtual media of {name}")
    return box


def enabled(select: Locator) -> list[str]:
    return list(select.evaluate("select => [...select.options].filter(option => !option.disabled).map(option => option.value)"))


def an_image(tmp_path: Path, name: str, size: int) -> tuple[Path, str]:
    path = tmp_path / name
    data = (hashlib.sha256(name.encode()).digest() * (size // 32 + 1))[:size]
    path.write_bytes(data)
    return path, hashlib.sha256(data).hexdigest()


def test_a_kvms_media_box_mounts_as_chosen_uploads_with_its_progress_in_place_and_deletes(tmp_path: Path, browser: Browser, comet: FakeKvm) -> None:  # noqa: F811
    comet.state.msd_write_pause = 0.05  # (an upload slow enough for its progress to be seen)
    upload_path, sha = an_image(tmp_path, "rescue-new.iso", 6_000_000)
    with a_wall(tmp_path / "wall", ("comet", comet)) as (live, admin), looking(browser, live, viewport={"width": 1280, "height": 860}) as page:
        sign_in(page, live)
        expect(tile(page, "comet")).to_have_attribute("data-state", "online", timeout=30_000)
        box = open_the_box(page)
        debian = box.get_by_role("radio", name=re.compile(r"^debian-13\.iso"))
        expect(debian).to_be_visible(timeout=20_000)
        listed = where_everything_stands(page, box)
        assert listed["mount"][0] > listed["upload"][0] and listed["mount"][1] == listed["upload"][1] == listed["delete"][1]
        assert listed["upload"][1] < listed["unmount"][1] < listed["mount as"][1] < listed["start from it"][1] < listed["list"][1]
        expect(box.locator(".media-head .muted")).to_contain_text("On the KVM's own storage · 6.0 GB free of 8.0 GB")
        expect(box.locator(".media-foot")).to_contain_text("pick the KVM's drive in the machine's boot menu")
        # What it goes in as: a CD-ROM drive, or a USB flash drive, read-only or writable; a disk is no kvmd KVM's. A KVM cannot be
        # told to start from it, and without a power board it is not restarted from here.
        mount_as, how = box.get_by_label("Mount as"), box.get_by_label("Start from it")
        assert enabled(mount_as) == ["cd", "flash", "flash_rw"] and enabled(how) == ["none"]
        expect(box.get_by_role("checkbox", name=re.compile(r"^Restart it now"))).to_be_disabled()
        expect(box.get_by_role("button", name="Upload...")).to_be_enabled()

        # Mounted as a USB flash drive, writable as chosen: the question says what that means, and the KVM has it so.
        debian.check()
        mount_as.select_option("flash_rw")
        box.get_by_role("button", name="Mount", exact=True).click()
        question = top(page)
        expect(question.locator("h2")).to_have_text("Mount debian-13.iso")
        expect(question).to_contain_text("comet gets debian-13.iso as a USB flash drive, writable: the machine can change and delete what is on it, and nothing else is done: pick the KVM's drive in its boot menu at its next start.")
        question.get_by_role("button", name="Mount", exact=True).click()
        told(page, "comet: Mount debian-13.iso done")
        expect(box.locator(".media-now")).to_contain_text("debian-13.iso · USB flash drive · writable · mounted by admin at")
        assert comet.state.msd_drive == {"image": DEBIAN, "connected": True, "cdrom": False, "rw": True}
        # Mounted, it is not deleted: its Delete is disabled while it is picked.
        expect(box.get_by_role("button", name="Delete", exact=True)).to_be_disabled()
        assert where_everything_stands(page, box) == listed

        # An upload: asked first, its progress said in its line as it comes, and the box still where it was meanwhile.
        with page.expect_file_chooser() as chooser:
            box.get_by_role("button", name="Upload...").click()
        chooser.value.set_files(str(upload_path))
        question = top(page)
        expect(question.locator("h2")).to_have_text("Upload rescue-new.iso")
        expect(question).to_contain_text("rescue-new.iso (6.0 MB) is carried through qKVM to the KVM's own storage of comet")
        question.get_by_role("button", name="Upload", exact=True).click()
        expect(box.locator(".media-said")).to_contain_text(re.compile(r"Uploading rescue-new\.iso: [0-9.]+ (kB|MB) of 6\.0 MB \([0-9]+ %\)"))
        assert where_everything_stands(page, box) == listed
        told(page, "comet: Upload rescue-new.iso done")
        expect(box.locator(".media-said")).to_have_text(f"rescue-new.iso is on the KVM, SHA-256 {sha}")
        assert comet.state.msd_images["rescue-new.iso"]["sha256"] == sha
        new = box.get_by_role("radio", name=re.compile(r"^rescue-new\.iso"))
        expect(new).to_be_visible()
        expect(box.locator(".media-list label", has_text="rescue-new.iso")).to_contain_text(f"uploaded from qKVM, SHA-256 {sha[:16]}")
        assert where_everything_stands(page, box) == listed

        # Deleted: asked first, naming it and the machine; gone from the KVM and from the list.
        new.check()
        box.get_by_role("button", name="Delete", exact=True).click()
        question = top(page)
        expect(question).to_contain_text("rescue-new.iso is deleted from the KVM's own storage of comet.")
        question.get_by_role("button", name="Delete", exact=True).click()
        told(page, "comet: Delete rescue-new.iso done")
        expect(new).to_have_count(0)
        assert "rescue-new.iso" not in comet.state.msd_images
        assert where_everything_stands(page, box) == listed

        # The tile says what is in the drive, to whoever looks at it.
        box.get_by_role("button", name="Close").click()
        expect(tile(page, "comet").locator(".meta")).to_contain_text("Flash: debian-13.iso")
        activity = admin.get("/api/v1/audit", params={"q": "rescue-new.iso"}).json()["entries"]
        assert {entry["event"] for entry in activity} == {"media_uploaded", "media_deleted"}
        assert next(entry for entry in activity if entry["event"] == "media_uploaded")["sha256"] == sha


def test_closing_the_box_stops_its_upload_and_leaves_nothing_on_the_kvm(tmp_path: Path, browser: Browser, comet: FakeKvm) -> None:  # noqa: F811
    comet.state.msd_write_pause = 0.05  # (slow: it is closed in the middle)
    # (Larger than what the network's buffers between the browser, the wall and the KVM hold: on GitHub's Linux runner
    # 8 MB was all in flight when the box closed, and the KVM got it whole. At 4 MB/s, what is buffered drains in time.)
    comet.state.msd_write_rate = 4_000_000
    upload_path, _ = an_image(tmp_path, "stopped.iso", 64_000_000)
    with a_wall(tmp_path / "wall", ("comet", comet)) as (live, admin), looking(browser, live) as page:
        sign_in(page, live)
        expect(tile(page, "comet")).to_have_attribute("data-state", "online", timeout=30_000)
        box = open_the_box(page)
        expect(box.get_by_role("radio", name=re.compile(r"^debian-13\.iso"))).to_be_visible(timeout=20_000)
        with page.expect_file_chooser() as chooser:
            box.get_by_role("button", name="Upload...").click()
        chooser.value.set_files(str(upload_path))
        expect(top(page)).to_contain_text("closing it stops the upload")
        top(page).get_by_role("button", name="Upload", exact=True).click()
        expect(box.locator(".media-said")).to_contain_text("Uploading stopped.iso", timeout=20_000)
        until(page, lambda: any(write["name"] == "stopped.iso" and write["received"] > 0 for write in comet.state.msd_writes), "the upload never reached the KVM")
        box.get_by_role("button", name="Close").click()
        until(page, lambda: "stopped.iso" not in comet.state.msd_images and comet.state.msd_writing is None, "what the stopped upload wrote is on the KVM still")
        until(page, lambda: bool(admin.get("/api/v1/audit", params={"q": "media_upload_failed"}).json()["entries"]), "the stopped upload was not written down")
        assert comet.state.msd_writes[-1]["complete"] is False


def test_a_media_box_that_is_too_small_for_its_buttons_still_holds_still(tmp_path: Path, browser: Browser, comet: FakeKvm) -> None:  # noqa: F811
    # A phone's width: the first line's three buttons stay on it, and nothing moves as the images come.
    with a_wall(tmp_path / "wall", ("comet", comet)) as (live, _), looking(browser, live, viewport={"width": 390, "height": 760}) as page:
        sign_in(page, live)
        expect(tile(page, "comet")).to_have_attribute("data-state", "online", timeout=30_000)
        box = open_the_box(page)
        looking_for_them = where_everything_stands(page, box)
        expect(box.get_by_role("radio", name=re.compile(r"^debian-13\.iso"))).to_be_visible(timeout=20_000)
        listed = where_everything_stands(page, box)
        assert listed == looking_for_them
        assert listed["box"][0] >= 0 and listed["box"][0] + listed["box"][2] <= 390
        for name in ("upload", "delete", "mount"):
            assert listed[name][0] + listed[name][2] <= listed["box"][0] + listed["box"][2], name
        assert listed["upload"][1] == listed["mount"][1], listed
        # (Upload and Delete keep only their icons there, named by their tooltips; the box's first line keeps its title.)
        assert listed["upload"][2] == listed["delete"][2] == 32, listed
        assert box.locator(".media-head strong").evaluate("title => title.scrollWidth <= title.clientWidth")


def test_what_the_kvm_would_refuse_at_once_is_said_before_a_byte_of_it_goes(tmp_path: Path, browser: Browser, comet: FakeKvm) -> None:  # noqa: F811
    # (The requalification of 0.3.0, Windows 3.11: an upload the wall refuses before it reads it is answered at once, and
    # the connection closed under a browser still sending, which may then see it reset, and not the answer. So what the
    # box knows the wall would refuse is said there, and nothing is sent: the wall still refuses it where it comes anyway.)
    comet.state.msd_free = 1_000_000
    named_so, _ = an_image(tmp_path, DEBIAN, 1000)
    too_big, _ = an_image(tmp_path, "big.iso", 2_000_000)
    empty = tmp_path / "empty.iso"
    empty.write_bytes(b"")
    with a_wall(tmp_path / "wall", ("comet", comet)) as (live, _), looking(browser, live) as page:
        sign_in(page, live)
        expect(tile(page, "comet")).to_have_attribute("data-state", "online", timeout=30_000)
        sent: list[str] = []
        page.on("request", lambda request: sent.append(request.url) if "/media/upload" in request.url and request.method == "POST" else None)
        box = open_the_box(page)
        expect(box.get_by_role("radio", name=re.compile(r"^debian-13\.iso"))).to_be_visible(timeout=20_000)
        expect(box.locator(".media-head .muted")).to_contain_text("1.0 MB free of 8.0 GB")
        for path, words in (
            (named_so, "debian-13.iso is on the KVM's own storage already: delete it first, or upload it under another name."),
            (too_big, "The KVM's own storage has 1.0 MB free, and big.iso is 2.0 MB: delete an image there first."),
            (empty, "An empty file is no image."),
        ):
            with page.expect_file_chooser() as chooser:
                box.get_by_role("button", name="Upload...").click()
            chooser.value.set_files(str(path))
            expect(box.locator(".media-said")).to_have_text(words)
            expect(box.locator(".media-said")).to_have_class(re.compile(r"\berror\b"))
            expect(top(page).locator("h2")).to_have_text("Virtual media of comet")  # (no question: nothing to upload)
    assert sent == [] and comet.state.msd_writes == []


def test_an_image_larger_than_a_cd_rom_drive_reads_is_said_so_at_its_mount(tmp_path: Path, browser: Browser, comet: FakeKvm) -> None:  # noqa: F811
    # (Linux's USB gadget, a kvmd KVM's and a JetKVM's drive, gives a CD-ROM drive's machine only the start of an image
    # larger than 256*60*75 sectors, and says so in the kernel's log alone: a Windows image is larger.)
    comet.state.msd_images["windows-11.iso"] = {"complete": True, "removable": True, "size": 5_800_000_000, "mod_ts": 1.0, "sha256": ""}
    with a_wall(tmp_path / "wall", ("comet", comet)) as (live, _), looking(browser, live) as page:
        sign_in(page, live)
        expect(tile(page, "comet")).to_have_attribute("data-state", "online", timeout=30_000)
        box = open_the_box(page)
        large = box.get_by_role("radio", name=re.compile(r"^windows-11\.iso"))
        expect(large).to_be_visible(timeout=20_000)
        warning = "Linux's USB gadget, which KVMs such as this one are built on, gives the machine only the first 2.36 GB of an image in a CD-ROM drive, so one this large may not be read whole. As a USB flash drive it is (whether the machine starts from it there is the image's to say)."
        for drive, warned in (("cd", True), ("flash", False)):
            large.check()
            box.get_by_label("Mount as").select_option(drive)
            box.get_by_role("button", name="Mount", exact=True).click()
            question = top(page)
            expect(question.locator("h2")).to_have_text("Mount windows-11.iso")
            if warned:
                expect(question).to_contain_text(warning)
            else:
                expect(question).not_to_contain_text("2.36 GB")
            question.get_by_role("button", name="Cancel").click()
        # (One that a CD-ROM drive reads whole is not warned about.)
        box.get_by_role("radio", name=re.compile(r"^debian-13\.iso")).check()
        box.get_by_label("Mount as").select_option("cd")
        box.get_by_role("button", name="Mount", exact=True).click()
        expect(top(page).locator("h2")).to_have_text("Mount debian-13.iso")
        expect(top(page)).not_to_contain_text("2.36 GB")
    assert comet.state.msd_drive["connected"] is False


def test_what_is_under_way_in_the_box_spins_and_counts_its_seconds(tmp_path: Path, browser: Browser, comet: FakeKvm) -> None:  # noqa: F811
    # (The owner, at the trial on test server .23: a mount that took its time showed "Mounting..." alone, and nothing
    # said it was still going. Now the line spins while it is, and says for how long.)
    comet.state.msd_write_pause = 0.05
    comet.state.msd_write_rate = 2_000_000  # (3 s for it, however large the pieces: long enough to count a second)
    upload_path, _ = an_image(tmp_path, "slow.iso", 6_000_000)
    with a_wall(tmp_path / "wall", ("comet", comet)) as (live, _), looking(browser, live) as page:
        sign_in(page, live)
        expect(tile(page, "comet")).to_have_attribute("data-state", "online", timeout=30_000)
        box = open_the_box(page)
        expect(box.get_by_role("radio", name=re.compile(r"^debian-13\.iso"))).to_be_visible(timeout=20_000)
        expect(box.locator(".media-said.working")).to_have_count(0)
        with page.expect_file_chooser() as chooser:
            box.get_by_role("button", name="Upload...").click()
        chooser.value.set_files(str(upload_path))
        top(page).get_by_role("button", name="Upload", exact=True).click()
        working = box.locator(".media-said.working")
        expect(working).to_be_visible()
        expect(working).to_have_attribute("data-waited", re.compile(r"^[1-9][0-9]* s$"), timeout=5_000)
        assert working.evaluate("line => getComputedStyle(line, '::before').animationName") == "spin"
        page.emulate_media(reduced_motion="reduce")  # (the owner's PC keeps motion down: it turns there too)
        assert working.evaluate("line => getComputedStyle(line, '::before').animationIterationCount") == "infinite"
        page.emulate_media(reduced_motion="no-preference")
        told(page, "comet: Upload slow.iso done")
        expect(box.locator(".media-said.working")).to_have_count(0)
        assert box.locator(".media-said").get_attribute("data-waited") is None
