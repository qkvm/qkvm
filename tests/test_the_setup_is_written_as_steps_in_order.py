"""The release's one-time setup is written as the steps to take, in order (final review of web-020-pipe, 1).

The README and the notes at the top of the workflow said what each environment holds; the owner needs what to do,
from today's state on: make `registries` (one rule of type Tag, v*, no branch rule; the maintainer as required
reviewer, with self-review allowed, as the maintainer both pushes the tag and approves), put the two Docker Hub
secrets there, take them out of `release` so that it holds the signing key only, keep none of the three secrets at
repository or organisation level, keep DOCKERHUB_IMAGE a repository variable, turn on immutable releases before the
first draft is published, and only then push the tag.
"""
from __future__ import annotations

from tests.workflow_text import APP, WORKFLOWS

STEPS = (
    "Create the environment registries",
    "one rule of type Tag, pattern v*, and no branch rule",
    "required reviewer pypv",
    "Prevent self-review off",
    "Add the secrets DOCKERHUB_USERNAME and DOCKERHUB_TOKEN to registries",
    "Read & Write",
    "Delete DOCKERHUB_USERNAME and DOCKERHUB_TOKEN from release, leaving only RELEASE_SIGNING_KEY",
    "no repository- or organization-level copy",
    "DOCKERHUB_IMAGE stays a repository variable",
    "Turn on immutable releases before the first draft is published",
    "Then push the tag",
)


def flat(text: str) -> str:
    return " ".join(text.replace("#", " ").replace("`", "").replace('"', "").split())


def in_order(text: str) -> None:
    # Each phrase after the one before (a phrase may also be said earlier, as "Prevent self-review" off is said of all
    # three environments before the steps).
    place = 0
    for step in STEPS:
        assert step in text[place:], (step, text[place : place + 200])
        place = text.index(step, place) + len(step)


def test_the_workflows_notes_give_the_steps_in_order() -> None:
    in_order(flat((WORKFLOWS / "release.yml").read_text(encoding="utf-8").split("\nname: Release\n", 1)[0]))


def test_the_readme_gives_the_steps_in_order() -> None:
    readme = APP.joinpath("README.md").read_text(encoding="utf-8")
    in_order(flat(readme[readme.index("### Publishing releases") : readme.index("## Command line")]))
