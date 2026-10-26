"""The workflow's notes and the security README claim what the hash holds make true, and no more (delta review of
web-020-pipe, 5).

They said the tools that build come from PyPI "with whatever they bring along" (now true only of the image's own
`pip install .`; the packages' build tools are pinned by hash), and that code in the jobs that try the packages
"cannot change what is signed": it can change an artifact; what it cannot do is have that signed, as `sign` holds
everything it signs to hashes the jobs that made it handed on.
"""
from __future__ import annotations

import re

from tests.workflow_text import SECURITY, WORKFLOWS


def flat(text: str) -> str:
    return " ".join(text.replace("#", " ").split())


def test_only_the_image_takes_from_pypi_what_comes_along() -> None:
    top = flat((WORKFLOWS / "release.yml").read_text(encoding="utf-8").split("\nname: Release\n", 1)[0])
    assert "come from PyPI, with whatever they bring along, and run there" not in top
    assert "pip install ." in top and "pinned by hash" in top


def test_no_claim_that_code_cannot_change_what_is_signed_without_saying_how() -> None:
    for path in (WORKFLOWS / "release.yml", SECURITY / "README.md"):
        text = flat(path.read_text(encoding="utf-8"))
        assert "cannot change what is signed" not in text, path.name
        for found in re.finditer(r"change what is signed", text):
            assert "refus" in text[found.start() : found.start() + 200], (path.name, text[found.start() - 100 : found.start() + 200])
