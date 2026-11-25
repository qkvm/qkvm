"""A new push of a release-X.Y.Z rehearsal branch cancels that branch's older runs; a tag's and a publication's never.

Rehearsal 4's runs queued half an hour behind rehearsal 3's, which a newer push had made stale (the 0.4.0 cycle), and
rehearsal 12's Release run was cancelled by hand lest it hold 13's for three hours. The Release and Tests workflows now
cancel a run of a release-* branch when the same branch is pushed again. A run of a v* tag, of a publication, of main,
of a pull request or of the Monday schedule is cancelled by nothing: its group is one no other run shares.

The expressions are read from the workflows and worked out here for each kind of run, as GitHub works them out (the
operators && and || give one of their sides, as in JavaScript; a missing property is null). What GitHub itself does with
them is tried by the coordinator's rehearsal; these tests hold the text to what was decided.
"""

from __future__ import annotations

import re
from types import SimpleNamespace
from typing import Any

from tests.workflow_text import WORKFLOWS


def concurrency(name: str) -> tuple[str, str]:
    """The workflow's own concurrency group and cancel-in-progress, as written (the expressions inside ${{ }})."""
    text = (WORKFLOWS / name).read_text(encoding="utf-8")
    found = re.search(r"^concurrency:\n  group: (.+)\n(?:  #.*\n)*  cancel-in-progress: (.+)\n", text, flags=re.M)
    assert found, f"{name} has no concurrency of its own"
    return found.group(1), found.group(2)


def worked_out(written: str, github: Any) -> Any:
    """`written` (a value with ${{ }} in it, or the whole of it one), worked out for a run with the context `github`."""

    def value(expression: str) -> Any:
        python = expression.replace("&&", " and ").replace("||", " or ").replace("!", " not ").replace(" not =", "!=")
        python = re.sub(r"\bstartsWith\(", "starts_with(", python)
        return eval(python, {"__builtins__": {}}, {"github": github, "starts_with": lambda text, start: str(text or "").lower().startswith(start.lower()), "format": lambda pattern, *values: re.sub(r"\{(\d+)\}", lambda m: str(values[int(m.group(1))]), pattern), "true": True, "false": False})

    if written.strip() in ("true", "false"):
        return written.strip() == "true"
    whole = re.fullmatch(r"\$\{\{(.*)\}\}", written.strip())
    if whole:
        return value(whole.group(1))
    return re.sub(r"\$\{\{(.*?)\}\}", lambda m: str(value(m.group(1)) if value(m.group(1)) is not None else ""), written)


def run(event: str, ref: str, number: int, tag: str | None = None) -> SimpleNamespace:
    """The github context of one run, as far as these expressions ask it."""
    name = ref.split("/", 2)[2] if ref.startswith(("refs/heads/", "refs/tags/")) else ref
    release = SimpleNamespace(tag_name=tag if event == "release" else None)  # (null where the run is of no release)
    return SimpleNamespace(event_name=event, ref=ref, ref_name=name, run_id=number, event=SimpleNamespace(release=release))


RUNS = {
    "the rehearsal, pushed": run("push", "refs/heads/release-0.4.0", 101),
    "the rehearsal, pushed again": run("push", "refs/heads/release-0.4.0", 102),
    "another rehearsal": run("push", "refs/heads/release-0.4.1", 103),
    "the tag": run("push", "refs/tags/v0.4.0", 104),
    "the tag, run again by hand": run("push", "refs/tags/v0.4.0", 105),
    "the publication": run("release", "refs/tags/v0.4.0", 106, tag="v0.4.0"),
    "main": run("push", "refs/heads/main", 107),
    "main again": run("push", "refs/heads/main", 108),
    "a pull request": run("pull_request", "refs/pull/7/merge", 109),
    "the Monday run": run("schedule", "refs/heads/main", 110),
    "a run by hand on the rehearsal": run("workflow_dispatch", "refs/heads/release-0.4.0", 111),
}


def cancels(name: str, newer: str, older: str) -> bool:
    """Whether a run that starts (`newer`) cancels one that runs (`older`) of the workflow `name`: GitHub cancels a run of the
    same group where the newer one's cancel-in-progress is true (and only a waiting one, never a running one, otherwise)."""
    group, cancel = concurrency(name)
    same = worked_out(group, RUNS[newer]) == worked_out(group, RUNS[older])
    return bool(same and worked_out(cancel, RUNS[newer]) is True)


# The runs each workflow has (release.yml: a push of a tag or of a release-* branch, and a publication; tests.yml: all).
HAS = {"release.yml": ["the rehearsal, pushed", "the rehearsal, pushed again", "another rehearsal", "the tag", "the tag, run again by hand", "the publication"], "tests.yml": list(RUNS)}
PUSHES = ("the rehearsal, pushed", "the rehearsal, pushed again")  # (of one branch: either may be the newer)


def test_a_rehearsal_pushed_again_cancels_its_older_runs_and_nothing_else_is_ever_cancelled() -> None:
    for name, runs in HAS.items():
        assert cancels(name, "the rehearsal, pushed again", "the rehearsal, pushed"), name
        for newer in runs:
            for older in runs:
                if newer != older and not (newer in PUSHES and older in PUSHES):
                    assert not cancels(name, newer, older), (name, newer, older)


def test_the_release_runs_keep_their_groups_and_a_tags_run_waits_for_its_publication() -> None:
    group, cancel = concurrency("release.yml")
    assert group == "release-${{ github.event.release.tag_name || github.ref_name }}"  # (the tag's run and its publication: one group)
    assert cancel == "${{ github.event_name == 'push' && startsWith(github.ref, 'refs/heads/release-') }}"
    assert worked_out(group, RUNS["the tag"]) == worked_out(group, RUNS["the publication"]) == "release-v0.4.0"
    assert worked_out(cancel, RUNS["the tag"]) is False and worked_out(cancel, RUNS["the publication"]) is False


def test_every_run_of_tests_but_a_rehearsals_push_has_a_group_of_its_own() -> None:
    group, cancel = concurrency("tests.yml")
    groups = [worked_out(group, RUNS[name]) for name in RUNS if name not in ("the rehearsal, pushed", "the rehearsal, pushed again")]
    assert len(set(groups)) == len(groups), groups  # (so that no run of main, a tag or a pull request ever waits for another)
    assert worked_out(cancel, RUNS["the tag"]) is True  # (true for every run: none shares a group but a rehearsal's pushes)


def test_the_comment_on_the_group_says_what_github_cancels() -> None:
    # (The review of this round.) It said a tag's run and its publication are never cancelled: GitHub cancels a run that
    # waits in a group once a third joins it, and a superseded rehearsal's run started again cancels the branch's newer one.
    text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    comment = " ".join(text[: text.index("\nconcurrency:\n")].rsplit("\n\n", 1)[-1].replace("#", " ").split())
    assert "ever cancelled" not in comment and "never cancelled" not in comment, comment
    assert "a run that waits, once a third joins the group" in comment, comment
    assert "started again by hand cancels the branch's newer run" in comment, comment
