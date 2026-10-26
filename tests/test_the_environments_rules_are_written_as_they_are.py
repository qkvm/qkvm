"""The notes say exactly how each environment is protected (third review of web-020-pipe, 2).

The workflow's setup notes and the README said to limit the environment to tags "and, if you like, to your own
approval". On GitHub both release and pypi are limited to tags matching v* and require the maintainer's review; the
notes now say exactly that, for each of the three environments, as what must be set, not as a choice.
"""
from __future__ import annotations

from tests.workflow_text import APP, WORKFLOWS

RULE = "tags matching v* only"
REVIEW = "a required reviewer"


def flat(text: str) -> str:
    return " ".join(text.replace("#", " ").replace("`", "").split())


def test_the_workflows_notes_say_each_environments_rules() -> None:
    top = flat((WORKFLOWS / "release.yml").read_text(encoding="utf-8").split("\nname: Release\n", 1)[0])
    assert "if you like" not in top
    rules = top[top.index("Every one of the three environments, release, registries and pypi:") :]
    assert RULE in rules[:400] and REVIEW in rules[:400], rules[:400]


def test_the_readme_says_each_environments_rules() -> None:
    readme = APP.joinpath("README.md").read_text(encoding="utf-8")
    publishing = flat(readme[readme.index("### Publishing releases") : readme.index("## Command line")])
    assert "if you like" not in publishing
    rules = publishing[publishing.index("Every one of the three environments, release, registries and pypi:") :]
    assert RULE in rules[:400] and REVIEW in rules[:400], rules[:400]
