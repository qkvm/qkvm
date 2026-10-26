#!/usr/bin/env python3
"""Fail closed unless every required CI job passed for the release commit.

    check-required-ci.py RUN.json JOBS.json SHA
        Every one of the required Tests jobs passed in that run, for that commit.
    check-required-ci.py --on-main BRANCH.json COMPARE.json SHA
        The commit is in the history of the protected branch main. BRANCH.json is GitHub's answer for
        git/ref/heads/main (the branch by its full name, never a tag that is called main), COMPARE.json its
        answer for compare/<that branch's commit>...SHA.
"""
import json
from pathlib import Path
import re
import sys

REQUIRED = {"checks", "audit", "package", "vnc", "browser", "controllers",
            "controllers-libvirt", "controllers-openbmc", "image (amd64)", "image (arm64)"}
REQUIRED.update(f"tests ({os}, {version})" for os in ("ubuntu-latest", "windows-latest")
                for version in ("3.11", "3.12", "3.13", "3.14"))
COMMIT = re.compile(r"[0-9a-f]{40}")


def verify(run, pages, sha):
    if (run.get("head_sha") != sha or run.get("status") != "completed"
            or run.get("conclusion") != "success"
            or run.get("event") not in ("push", "workflow_dispatch")
            or run.get("path") != ".github/workflows/tests.yml"):
        raise ValueError("No successful eligible Tests run for the release commit")
    jobs = [job for page in pages for job in page["jobs"]]
    if len(jobs) != len(REQUIRED) or {job.get("name") for job in jobs} != REQUIRED:
        raise ValueError("Required CI jobs are missing, duplicated or unexpected")
    for job in jobs:
        if (job.get("head_sha") != sha or job.get("run_id") != run["id"]
                or not 1 <= job.get("run_attempt", 0) <= run["run_attempt"]
                or job.get("status") != "completed" or job.get("conclusion") != "success"):
            raise ValueError("A required job did not pass for this run and commit")
        steps = job.get("steps", [])
        if not steps or any(step.get("status") != "completed"
                            or step.get("conclusion") not in ("success", "skipped") for step in steps):
            raise ValueError("A required job has missing, unfinished or failed steps")


def commit_of(value, label):
    if not isinstance(value, dict) or not isinstance(value.get("sha"), str) or not COMMIT.fullmatch(value["sha"]):
        raise ValueError(f"{label} names no commit")
    return value["sha"]


def verify_on_main(branch, compare, sha):
    """The release commit lies in the history of main: main is that commit, or a descendant of it."""
    if not isinstance(branch, dict) or not isinstance(compare, dict):
        raise ValueError("GitHub's answers about main are not what was asked for")
    if not COMMIT.fullmatch(sha):
        raise ValueError("The release commit is not a full commit id")
    # Only the branch itself: a tag called main (anyone who may write can make one) is not the protected branch.
    target = branch.get("object")
    if branch.get("ref") != "refs/heads/main" or not isinstance(target, dict) or target.get("type") != "commit":
        raise ValueError("The answer is not the branch main")
    main = commit_of(target, "The branch main")
    if commit_of(compare.get("base_commit"), "The comparison's base") != main:
        raise ValueError("The comparison was not made with main as it is")
    # The commit is an ancestor of main (or main itself) exactly when it is where the two meet, and main has
    # nothing of it that main lacks.
    ahead = compare.get("ahead_by")
    if (compare.get("status") not in ("identical", "behind") or type(ahead) is not int or ahead != 0
            or commit_of(compare.get("merge_base_commit"), "The comparison's merge base") != sha):
        raise ValueError(f"{sha} is not in the history of main: only commits on main are released")


def main():
    try:
        if sys.argv[1] == "--on-main":
            verify_on_main(json.loads(Path(sys.argv[2]).read_text()),
                           json.loads(Path(sys.argv[3]).read_text()), sys.argv[4])
            print(f"{sys.argv[4]} is on main")
            return 0
        verify(json.loads(Path(sys.argv[1]).read_text()),
               json.loads(Path(sys.argv[2]).read_text()), sys.argv[3])
    except (ValueError, KeyError, TypeError, OSError, IndexError) as error:
        print(f"Release refused: {error}", file=sys.stderr)
        return 1
    print(f"All {len(REQUIRED)} required CI jobs passed for {sys.argv[3]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
