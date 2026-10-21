#!/usr/bin/env python3
"""Release decisions must not inherit allowed failures from workflow conclusions."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest

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


if __name__ == "__main__":
    unittest.main()
