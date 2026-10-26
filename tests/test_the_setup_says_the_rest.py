"""The ordered setup says the rest of what is to be set (delta review of web-020-pipe, the further points).

That "Prevent self-review" is off on all three environments (it is on release and pypi today; the maintainer pushes
the tag and approves), that the ghcr.io package must give this repository write access unless this repository's
workflow made it, and which account DOCKERHUB_USERNAME is. And which token DOCKERHUB_TOKEN is, right whether `qkvm` on
Docker Hub is a personal account or an organization, and for an organization whose plan has no organization access
tokens too: a personal access token of an account that may push to the repository, with that account's name, or an
organization access token with the organization's name where the plan has them; no "(qkvm today)" that may then not
hold (fresh review of web-020-pipe, the setup point; delta-g review, 4).
"""
from __future__ import annotations

from tests.workflow_text import APP, WORKFLOWS

SAID = (
    "Prevent self-review off on all three",
    "Manage Actions access",
    "a personal access token, with Read & Write, of an account that may push to that repository",
    "with that account's name as DOCKERHUB_USERNAME",
    # (delta-i review, a nit) A personal access token reaches all its account may, not one repository.
    "such a token reaches everything its account may, so make it an account kept for this alone, with write access to "
    "that repository only",
    "where the repository belongs to an organization whose Docker plan has them, an organization access token that may "
    "push to and pull from that repository only, with the organization's name as DOCKERHUB_USERNAME",
)
UNSAID = ("qkvm today",)


def flat(text: str) -> str:
    return " ".join(text.replace("#", " ").replace("`", "").replace('"', "").split())


def test_the_readme_says_it() -> None:
    readme = APP.joinpath("README.md").read_text(encoding="utf-8")
    publishing = flat(readme[readme.index("### Publishing releases") : readme.index("## Command line")])
    for said in SAID:
        assert said in publishing, said
    for unsaid in UNSAID:
        assert unsaid not in publishing, unsaid
    assert "ghcr.io package qkvm/qkvm" in publishing and "write" in publishing[publishing.index("Manage Actions access") - 300 :][:400]


def test_the_workflows_notes_say_it() -> None:
    top = flat((WORKFLOWS / "release.yml").read_text(encoding="utf-8").split("\nname: Release\n", 1)[0])
    for said in SAID:
        assert said in top, said
    for unsaid in UNSAID:
        assert unsaid not in top, unsaid
