"""The draft is made with exactly the five files that were checked, and nothing else (fresh review of web-020-pipe, 4).

`gh release create ... release/*` attaches everything in the folder. The folder was held only by what the signed list
names (and the signature by its hash): a sixth file in it, however it got there, would have gone onto the draft, and
only the read-back after the draft existed would have refused it. Now the step before the draft is made requires the
folder to hold exactly SHA256SUMS, SHA256SUMS.sig and the three files of this version the list names, each a plain file.
"""
from __future__ import annotations

from tests.workflow_text import WORKFLOWS, jobs, steps

RELEASE = WORKFLOWS / "release.yml"
FIVE = 'test "$held" = "SHA256SUMS SHA256SUMS.sig qkvm-${TAG#v}-image.json qkvm-${TAG#v}-py3-none-any.whl qkvm-${TAG#v}.tar.gz "'


def test_the_folder_attached_is_exactly_the_checked_files_before_the_draft_is_made() -> None:
    order = steps(jobs(RELEASE)["draft"])
    made = next(index for index, step in enumerate(order) if "gh release create" in step)
    assert order[made].count(" release/*") == 1, "the folder is what is attached"
    held = next(index for index, step in enumerate(order) if FIVE in step)
    assert held < made
    step = order[held]
    assert "held=$(ls -A release | LC_ALL=C sort | tr '\\n' ' ')" in step
    assert step.index("held=$(ls -A release") < step.index(FIVE)
    assert 'test -z "$(find release -mindepth 1 ! -type f)"' in step, "plain files only, no folder or link"
