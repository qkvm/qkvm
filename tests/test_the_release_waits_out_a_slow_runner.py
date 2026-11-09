"""The release workflow waits as long as its slowest runner needs, and out a moment's outage of what it downloads.

0.3.1's second rehearsal: a try on Windows (the whole suite, against what an update installed in place) was cancelled at
its 90 minutes, after the others had taken 79 to 88; and the image scan on ARM failed in a minute, where the pinned
scanner's download from GitHub's release page answered 504 to each of three tries in some seven seconds.
"""

from __future__ import annotations

import re

from tests.workflow_text import SECURITY, WORKFLOWS, jobs, uncommented


def minutes(job: str) -> int | None:
    found = re.findall(r"^    timeout-minutes: (\d+)", uncommented(job), flags=re.M)
    return int(found[0]) if found else None


def test_a_job_of_the_release_that_runs_the_whole_suite_is_given_the_time_the_tests_job_is() -> None:
    suite = minutes(jobs(WORKFLOWS / "tests.yml")["tests"])
    assert suite is not None and suite >= 150
    every = jobs(WORKFLOWS / "release.yml")
    whole = [name for name, job in every.items() if "pytest" in job and "tests" in job]
    assert {"libraries_tested", "packages"} <= set(whole), whole
    for name in whole:
        given = minutes(every[name])
        assert given is None or given >= suite, (name, given, suite)  # (None: GitHub's own six hours)


def test_the_scanners_download_waits_out_a_minute_and_more_of_refusals() -> None:
    script = uncommented((SECURITY / "scan-image.sh").read_text(encoding="utf-8"))
    [download] = re.findall(r"^curl [^\n]*trivy[^\n]*$|^curl [^\n]*\\\n[^\n]*trivy", script, flags=re.M)
    tries = re.search(r"--retry (\d+)", download)
    delay = re.search(r"--retry-delay (\d+)", download)
    assert tries and delay, download
    assert int(tries.group(1)) * int(delay.group(1)) >= 90, download
    assert "--fail" in download  # (a refusal is no file: the checksum below is checked all the same)
