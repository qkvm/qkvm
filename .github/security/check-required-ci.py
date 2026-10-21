#!/usr/bin/env python3
"""Fail closed unless every required CI job passed for the release commit."""
import json
from pathlib import Path
import sys

REQUIRED = {"checks", "audit", "package", "vnc", "browser", "controllers",
            "controllers-libvirt", "controllers-openbmc", "image (amd64)", "image (arm64)"}
REQUIRED.update(f"tests ({os}, {version})" for os in ("ubuntu-latest", "windows-latest")
                for version in ("3.11", "3.12", "3.13", "3.14"))


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


def main():
    try:
        verify(json.loads(Path(sys.argv[1]).read_text()),
               json.loads(Path(sys.argv[2]).read_text()), sys.argv[3])
    except (ValueError, KeyError, TypeError, OSError, IndexError) as error:
        print(f"Release refused: {error}", file=sys.stderr)
        return 1
    print(f"All {len(REQUIRED)} required CI jobs passed for {sys.argv[3]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
