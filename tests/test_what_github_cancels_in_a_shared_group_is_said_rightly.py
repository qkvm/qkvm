"""What GitHub cancels in the image jobs' shared concurrency group is said rightly (third review of web-020-pipe, 3).

GitHub keeps one waiting job per concurrency group: when another is queued, the one that was already waiting is
cancelled and the new one waits in its place. The comment and the README said the newest one was cancelled. Now both
say which one to look for (an image job cancelled before it started, the one that was waiting) and what mends it
(Re-run all jobs of that publication's run).
"""
from __future__ import annotations

from tests.workflow_text import APP, WORKFLOWS, jobs


def flat(text: str) -> str:
    return " ".join(text.replace("#", " ").split())


def test_the_comment_and_the_readme_name_the_job_that_was_waiting() -> None:
    image = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    comment = flat(image[image.index("\n  image:\n") : image.index("    concurrency:\n", image.index("\n  image:\n"))])
    readme = APP.joinpath("README.md").read_text(encoding="utf-8")
    publishing = flat(readme[readme.index("### Publishing releases") : readme.index("## Command line")])
    for text in (comment, publishing):
        assert "a third that waits behind it is cancelled" not in text and "A third one that waits behind a waiting one" not in text
        assert "the one that was waiting is cancelled" in text, text[:500]
        assert "Re-run all jobs" in text
    assert "concurrency:" in jobs(WORKFLOWS / "release.yml")["image"]
