#!/usr/bin/env python3
"""Regression tests for which moving image tags a publication may move; stdlib only."""

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("newest_release", Path(__file__).with_name("newest-release.py"))
NEWEST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NEWEST)


def published(*tags, draft=(), prerelease=()):
    return [{"tag_name": tag, "draft": tag in draft, "prerelease": tag in prerelease} for tag in tags]


class Newest(unittest.TestCase):
    def test_the_newest_version_moves_latest_and_its_line(self):
        self.assertEqual(NEWEST.moves(published("v0.1.1", "v0.2.0", "v0.2.1"), "v0.2.1"), {"latest": True, "minor": True})

    def test_a_fix_to_an_older_line_moves_its_line_only(self):
        releases = published("v0.2.0", "v0.3.0", "v0.2.1")
        self.assertEqual(NEWEST.moves(releases, "v0.2.1"), {"latest": False, "minor": True})

    def test_an_older_version_of_the_same_line_moves_nothing(self):
        releases = published("v0.2.0", "v0.2.2", "v0.2.1")
        self.assertEqual(NEWEST.moves(releases, "v0.2.1"), {"latest": False, "minor": False})

    def test_versions_compare_as_numbers(self):
        self.assertEqual(NEWEST.moves(published("v0.9.0", "v0.10.0"), "v0.10.0"), {"latest": True, "minor": True})
        self.assertEqual(NEWEST.moves(published("v0.9.0", "v0.10.0"), "v0.9.0"), {"latest": False, "minor": True})

    def test_drafts_prereleases_and_other_tags_are_not_released_versions(self):
        releases = published("v0.2.0", "v0.3.0", "v9.9.9-rc1", "nightly", "v0.4.0", draft=("v0.3.0",), prerelease=("v0.4.0",))
        self.assertEqual(NEWEST.moves(releases, "v0.2.1"), {"latest": True, "minor": True})

    def test_the_release_being_published_counts_even_before_the_list_shows_it(self):
        self.assertEqual(NEWEST.moves(published("v0.2.0"), "v0.2.1"), {"latest": True, "minor": True})

    def test_pages_as_gh_slurps_them(self):
        pages = [published("v0.2.0", "v0.5.0"), published("v0.3.0")]
        self.assertEqual(NEWEST.moves(pages, "v0.3.0"), {"latest": False, "minor": True})

    def test_what_cannot_be_read_is_refused(self):
        for releases, tag in ((published("v0.2.0"), "v0.2"), (published("v0.2.0"), "0.2.1"), ({"tag_name": "v0.2.0"}, "v0.2.1"),
                              ([{"tag_name": 5, "draft": False, "prerelease": False}], "v0.2.1"),
                              ([{"tag_name": "v0.2.0", "draft": "no", "prerelease": False}], "v0.2.1")):
            with self.subTest(releases=releases, tag=tag):
                with self.assertRaises(NEWEST.Refused):
                    NEWEST.moves(releases, tag)

    def test_the_command_writes_outputs_and_warns_of_a_latest_label_elsewhere(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "releases.json"
            path.write_text(json.dumps([published("v0.2.0", "v0.3.0", "v0.2.1")]), encoding="utf-8")
            output = io.StringIO()
            warned = io.StringIO()
            with redirect_stdout(output), redirect_stderr(warned):
                self.assertEqual(NEWEST.main([str(path), "v0.2.1", "--github-latest", "v0.2.1"]), 0)
            self.assertEqual(output.getvalue().split(), ["latest=false", "minor=true"])
            self.assertIn("::warning::", output.getvalue() + warned.getvalue())
            output = io.StringIO()
            with redirect_stdout(output), redirect_stderr(io.StringIO()):
                self.assertEqual(NEWEST.main([str(path), "v0.2"]), 1)


if __name__ == "__main__":
    unittest.main()
