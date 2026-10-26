#!/usr/bin/env python3
"""Release decisions must not inherit allowed failures from workflow conclusions."""
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("required_ci", Path(__file__).with_name("check-required-ci.py"))
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)
SHA = "a" * 40


def passing():
    run = {"id": 12, "run_attempt": 2, "head_sha": SHA, "status": "completed",
           "conclusion": "success", "event": "push", "path": ".github/workflows/tests.yml"}
    jobs = [{"name": name, "head_sha": SHA, "run_id": 12, "run_attempt": 1,
             "status": "completed", "conclusion": "success",
             "steps": [{"status": "completed", "conclusion": "success"}]}
            for name in sorted(POLICY.REQUIRED)]
    return run, [{"jobs": jobs[:9]}, {"jobs": jobs[9:]}]


class RequiredCI(unittest.TestCase):
    def test_passes_complete_paginated_matrix_including_retained_rerun_successes(self):
        POLICY.verify(*passing(), SHA)

    def test_rejects_ineligible_runs(self):
        for key, value in [("head_sha", "b" * 40), ("status", "in_progress"),
                           ("conclusion", "failure"), ("event", "pull_request"),
                           ("path", ".github/workflows/other.yml")]:
            with self.subTest(key=key):
                run, pages = passing()
                run[key] = value
                with self.assertRaises(ValueError):
                    POLICY.verify(run, pages, SHA)

    def test_requires_exact_job_set(self):
        for change in ("missing", "duplicate", "unexpected"):
            with self.subTest(change=change):
                run, pages = passing()
                if change == "missing":
                    pages[0]["jobs"].pop()
                elif change == "duplicate":
                    pages[0]["jobs"][0] = deepcopy(pages[0]["jobs"][1])
                else:
                    pages[0]["jobs"][0]["name"] = "unexpected"
                with self.assertRaises(ValueError):
                    POLICY.verify(run, pages, SHA)

    def test_workflow_success_cannot_hide_failed_or_wrong_job(self):
        for key, value in [("conclusion", "failure"), ("conclusion", "skipped"),
                           ("conclusion", "cancelled"), ("status", "in_progress"),
                           ("head_sha", "b" * 40), ("run_id", 13), ("run_attempt", 3)]:
            with self.subTest(key=key, value=value):
                run, pages = passing()
                pages[0]["jobs"][0][key] = value
                with self.assertRaises(ValueError):
                    POLICY.verify(run, pages, SHA)

    def test_job_success_cannot_hide_failed_step(self):
        for conclusion in ("failure", "cancelled", "timed_out", None):
            with self.subTest(conclusion=conclusion):
                run, pages = passing()
                pages[0]["jobs"][0]["steps"][0]["conclusion"] = conclusion
                with self.assertRaises(ValueError):
                    POLICY.verify(run, pages, SHA)

    def test_missing_steps_are_rejected(self):
        run, pages = passing()
        pages[0]["jobs"][0]["steps"] = []
        with self.assertRaises(ValueError):
            POLICY.verify(run, pages, SHA)


MAIN = "c" * 40


def on_main():
    """GitHub's answers for a tagged commit three commits behind main: the branch, then main...commit."""
    branch = {"ref": "refs/heads/main", "object": {"type": "commit", "sha": MAIN}}
    compare = {"status": "behind", "ahead_by": 0, "behind_by": 3,
               "base_commit": {"sha": MAIN}, "merge_base_commit": {"sha": SHA}}
    return branch, compare


class ReleaseCommitOnMain(unittest.TestCase):
    def test_a_commit_in_mains_history_passes(self):
        POLICY.verify_on_main(*on_main(), SHA)
        branch, compare = on_main()  # main itself
        branch["object"]["sha"] = compare["base_commit"]["sha"] = SHA
        compare.update(status="identical", behind_by=0)
        POLICY.verify_on_main(branch, compare, SHA)

    def test_a_commit_off_main_is_refused(self):
        for status, ahead in (("ahead", 1), ("diverged", 2)):
            with self.subTest(status=status):
                branch, compare = on_main()
                compare.update(status=status, ahead_by=ahead)
                compare["merge_base_commit"]["sha"] = "d" * 40
                with self.assertRaises(ValueError):
                    POLICY.verify_on_main(branch, compare, SHA)

    def test_only_the_branch_itself_is_main(self):
        # Anyone who may write can make a tag; one named main must not stand in for the protected branch.
        for change in ("tag", "other branch", "tag object", "base is not main"):
            with self.subTest(change=change):
                branch, compare = on_main()
                if change == "tag":
                    branch["ref"] = "refs/tags/main"
                elif change == "other branch":
                    branch["ref"] = "refs/heads/main-before"
                elif change == "tag object":
                    branch["object"]["type"] = "tag"
                else:
                    compare["base_commit"]["sha"] = "e" * 40
                with self.assertRaises(ValueError):
                    POLICY.verify_on_main(branch, compare, SHA)

    def test_every_part_of_the_answer_must_agree(self):
        mutations = [
            lambda branch, compare: compare["merge_base_commit"].update(sha="d" * 40),
            lambda branch, compare: compare.update(ahead_by=1),
            lambda branch, compare: compare.update(ahead_by="0"),
            lambda branch, compare: compare.update(ahead_by=False),
            lambda branch, compare: compare.update(status="Behind"),
            lambda branch, compare: compare.pop("merge_base_commit"),
            lambda branch, compare: compare.update(merge_base_commit=None),
            lambda branch, compare: branch.pop("object"),
            lambda branch, compare: branch["object"].update(sha=SHA.upper()),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                branch, compare = on_main()
                mutate(branch, compare)
                with self.assertRaises(ValueError):
                    POLICY.verify_on_main(branch, compare, SHA)

    def test_answers_that_are_not_objects_are_refused(self):
        for branch, compare in (([], on_main()[1]), (on_main()[0], []), (None, None)):
            with self.subTest(branch=type(branch).__name__, compare=type(compare).__name__):
                with self.assertRaises(ValueError):
                    POLICY.verify_on_main(branch, compare, SHA)

    def test_the_command_says_no_with_its_exit_status(self):
        with tempfile.TemporaryDirectory() as directory:
            branch_file, compare_file = Path(directory) / "main.json", Path(directory) / "compare.json"
            for expected in (0, 1):
                with self.subTest(expected=expected):
                    branch, compare = on_main()
                    if expected:
                        compare.update(status="diverged", ahead_by=1)
                    branch_file.write_text(json.dumps(branch), encoding="utf-8")
                    compare_file.write_text(json.dumps(compare), encoding="utf-8")
                    argv = ["check-required-ci.py", "--on-main", str(branch_file), str(compare_file), SHA]
                    output = io.StringIO()
                    with mock.patch.object(sys, "argv", argv), redirect_stdout(output), redirect_stderr(output):
                        self.assertEqual(POLICY.main(), expected)
                    self.assertIn("Release refused" if expected else "is on main", output.getvalue())


if __name__ == "__main__":
    unittest.main()
