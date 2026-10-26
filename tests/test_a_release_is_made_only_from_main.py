"""A release is made only of a commit that is on the protected branch main (the review of 850745e, P2).

The tags v* may only not be moved or deleted: whoever may write to the repository may make one, on any commit. The
release workflow asked for nothing but a green test run of the tagged commit, and a push to any branch runs the tests:
a commit that never went through main (its required checks, its review, its linear history) could be released. Now
the first thing a release does, before it waits for the tests and before anything is built, signed or published, is
to ask GitHub where main is (by the branch's own name, so that a tag called main is not taken for it) and whether the
tagged commit lies in its history; check-required-ci.py --on-main decides, and test-required-ci.py tries its answers.
"""
from __future__ import annotations

import re

from tests.workflow_text import WORKFLOWS, jobs, steps, waits_for

RELEASE = WORKFLOWS / "release.yml"


def test_the_first_thing_a_release_asks_is_whether_its_commit_is_on_main() -> None:
    gate = steps(jobs(RELEASE)["tested_commit"])
    checks = [index for index, step in enumerate(gate) if "check-required-ci.py --on-main" in step]
    assert checks, "the release asks whether the tagged commit is on main"
    step = gate[checks[0]]
    # main itself, by the branch's full name: a tag named main, which anyone who may write can make, is not main.
    assert re.search(r"gh api [^\n]*repos/\$GITHUB_REPOSITORY/git/ref/heads/main\b", step), step
    assert re.search(r"gh api [^\n]*repos/\$GITHUB_REPOSITORY/compare/\$main\.\.\.\$GITHUB_SHA\b", step), step
    assert "$GITHUB_SHA" in step.split("check-required-ci.py --on-main", 1)[1].split("\n", 1)[0]
    waiting = [index for index, step in enumerate(gate) if "gh run list" in step]
    assert waiting and checks[0] < waiting[0], "asked before the release waits up to 95 minutes for the tests"
    assert all("uses: actions/checkout@" in earlier or earlier.startswith("name: The tag is a version of three numbers\n")
               for earlier in gate[: checks[0]]), "nothing but the checkout (and the tag's shape) before it"


def test_nothing_is_built_signed_or_published_before_that_answer() -> None:
    every = jobs(RELEASE)
    on_the_tag = {name for name, job in every.items() if "if: github.event_name == 'push'" in job}
    assert {"tested_commit", "build", "images_amd64", "images_arm64", "sign", "signature", "draft"} <= on_the_tag
    for name in on_the_tag - {"tested_commit"}:
        assert "tested_commit" in waits_for(every, name), name
    # A publication is a run of its own (a person publishing the draft): it can wait for no job of the tag's run, and
    # publishes only what it has held to the signature, which only the sign job makes, after the answer.
    signers = {name for name, job in every.items() if "-m qkvm.release publish" in job}
    assert signers == {"sign"}
    checkers = {name for name, job in every.items() if name not in on_the_tag and re.search(r"/usr/bin/python3 -m qkvm\.release verify\b[^\n]*--signed", job)}
    assert checkers, "the publication checks the signature"
    for name, job in every.items():
        if name not in on_the_tag:
            assert "if: github.event_name == 'release'" in job, name
            # Each checks the signature itself, or waits for a job that did and holds its files to the list it checked.
            if name not in checkers:
                assert waits_for(every, name) & checkers, name
                assert "SUMS: ${{ needs.published.outputs.sums }}" in job and '= "$SUMS"' in job, name
