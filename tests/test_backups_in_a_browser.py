"""Settings > Backups in a browser (0.4.0): the key made with the password and its kit shown once, saved as a file that
restores, and gone from the page once it is closed; backups switched on, made now, and verified.

Needs Playwright and a browser for it, as tests/test_in_a_browser.py does; skipped where they are missing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api", reason="the browser tests need Playwright (pip install playwright)")

from playwright.sync_api import Browser, expect

from qkvm import backup
from qkvm._version import __version__
from tests.test_in_a_browser import PASSWORD, a_wall, browser, looking, settings, sign_in, told, top  # noqa: F401  (fixtures, by name)


def test_the_key_is_shown_once_as_a_kit_that_restores_and_backups_are_made_and_verified(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    folder = tmp_path / "backups"
    with a_wall(tmp_path / "data") as (live, _), looking(browser, live, accept_downloads=True) as page:
        sign_in(page, live)
        pane = settings(page, "backups")
        # The section is one shape as the others: its main buttons at the right of its first line, its lines framed.
        does = pane.locator(".section-head .section-does")
        expect(does.get_by_role("button", name="Save")).to_be_visible()
        expect(does.get_by_role("button", name="Back up now")).to_be_disabled()  # (no key, no folder yet)
        assert pane.locator(".block .lines").count() >= 3
        expect(does.get_by_role("button")).to_have_text(["Back up now", "Save"])  # (and the same once there is a key: below)
        expect(pane.locator("button.primary")).to_have_count(1)  # (Save, in the first line: the key's button is its line's own)
        expect(pane.get_by_role("checkbox", name="Back up every day")).to_be_disabled()
        pane.get_by_role("button", name="Make the backup key").click()
        box = top(page)
        box.locator("input[type=password]").fill(PASSWORD)
        box.get_by_role("button", name="Make the key").click()
        kit = box.locator("pre.kit")
        expect(kit).to_contain_text("qKVM backup recovery kit")
        text = kit.inner_text()
        key = backup.key_in_kit(text)
        with page.expect_download() as saved:
            box.get_by_role("button", name="Save as a file").click()
        downloaded = Path(saved.value.path()).read_text(encoding="utf-8")
        assert backup.key_in_kit(downloaded) == key and downloaded.startswith("qKVM backup recovery kit") and "--restore" in downloaded
        expect(box.get_by_role("button", name="Print")).to_be_visible()
        box.get_by_role("button", name="I have kept it").click()
        expect(page.locator("dialog[open] pre.kit")).to_have_count(0)
        # Gone from the page once it is closed: nothing it shows or keeps holds it, and the line says only which key it is.
        written = backup.written(key)
        expect(pane.locator(".setting", has_text="Backup key")).to_contain_text(backup.key_id(key))
        expect(does.get_by_role("button")).to_have_text(["Back up now", "Save"])  # (in the same place as before the key)
        assert written not in page.content() and key.hex() not in page.content()
        assert written not in page.evaluate("() => JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage })")
        # Switched on, made now, and read back: in a folder that holds another wall's backup as well, which is left as it is
        # and said.
        theirs = backup.make(folder, backup.new_key(), settings={}, data_key=bytes(32), logs=[], history=None, program=__version__, keep=7)
        expect(pane.locator(".note.warn")).to_have_count(0)
        pane.get_by_role("textbox", name="Folder").fill(str(folder))
        pane.get_by_role("checkbox", name="Back up every day").check()
        does.get_by_role("button", name="Save").click()
        told(page, "Backup settings saved")
        expect(pane.locator(".setting", has_text="Next")).not_to_contain_text("backups are off")
        does.get_by_role("button", name="Back up now").click()
        told(page, "Backup made")
        [made] = backup.listed(folder, backup.key_id(key))
        expect(pane.locator(".setting", has_text="Last run")).to_contain_text(made.name)
        expect(pane.locator(".note.warn")).to_contain_text("The folder also holds 1 backup of another key")
        assert (folder / theirs.name).exists()
        pane.locator(".setting", has_text="Latest backup").get_by_role("button", name="Verify").click()
        expect(pane.locator(".made")).to_contain_text(f"{made.name} reads back whole")
        # The kit as the page saved it opens it: it is all it takes.
        assert backup.verify(made, backup.key_in_kit(downloaded)).accounts == 1
        # And after the page is opened again, still nowhere.
        page.reload()
        pane = settings(page, "backups")
        expect(pane.locator(".setting", has_text="Backup key")).to_contain_text(backup.key_id(key))
        assert written not in page.content()


def test_a_run_waiting_for_a_folder_that_never_answers_is_said_with_what_frees_it(tmp_path: Path, browser: Browser) -> None:  # noqa: F811
    # (The last look of wave 3, 1.) While a run its hour cut off waits for its folder, Settings > Backups says what waits, since
    # when, and that a restart of qKVM frees it; the section keeps its shape.
    with a_wall(tmp_path / "data") as (live, admin), looking(browser, live) as page:
        state = admin.get("/api/v1/backups").json()
        said = {**state, "waiting": [{"folder": "/mnt/nas/qkvm-backups", "since": 1_763_350_000.0}]}
        page.route("**/api/v1/backups", lambda route: route.fulfill(json=said) if route.request.method == "GET" else route.continue_())
        sign_in(page, live)
        pane = settings(page, "backups")
        note = pane.locator(".note.warn", has_text="still waiting")
        expect(note).to_contain_text("/mnt/nas/qkvm-backups")
        expect(note).to_contain_text("A restart of qKVM frees it")
        expect(pane.locator(".section-head .section-does").get_by_role("button")).to_have_text(["Back up now", "Save"])


def test_verify_and_back_up_now_have_the_time_the_wall_gives_them(tmp_path: Path, browser: Browser, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    # (The outside review of 0.4.0, bugs round, M7.) Both buttons asked with the page's ordinary patience, 30 s, while the wall
    # gives Verify ten minutes, and Back up now a minute before it answers that the run goes on: a Verify of 31 s was said
    # as "qKVM took too long to answer" and what it found was lost, and "Still being made" was never reached. Each asks with
    # the time the wall gives it, and more. (Each wait here is past the page's ordinary patience: this test takes a minute.)
    import threading
    import time

    from qkvm import server
    from tests.test_backups import made_key, set_up

    real_verify, real_make = backup.verify, backup.make
    let_go = threading.Event()

    def slow_verify(*given: object) -> backup.Held:
        time.sleep(31)
        return real_verify(*given)  # type: ignore[arg-type]

    def slow_make(*given: object, **said: object) -> backup.Made:
        let_go.wait(60)
        return real_make(*given, **said)  # type: ignore[arg-type]

    with a_wall(tmp_path / "data") as (live, admin), looking(browser, live) as page:
        try:
            made_key(admin)
            set_up(admin, tmp_path / "backups")
            done = admin.post("/api/v1/backups/run").json()
            assert done["ok"] is True
            sign_in(page, live)
            pane = settings(page, "backups")
            monkeypatch.setattr(backup, "verify", slow_verify)
            pane.locator(".setting", has_text="Latest backup").get_by_role("button", name="Verify").click()
            expect(pane.locator(".made")).to_contain_text(f"{done['name']} reads back whole", timeout=60_000)
            monkeypatch.setattr(server, "RUN_WAIT", 31.0)  # (the wall's minute, shortened to just past the page's ordinary patience)
            monkeypatch.setattr(backup, "make", slow_make)
            pane.locator(".section-head .section-does").get_by_role("button", name="Back up now").click()
            expect(page.locator("#toasts .toast", has_text="Still being made").first).to_be_visible(timeout=60_000)
        finally:
            let_go.set()
