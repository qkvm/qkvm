"""The security README says who checks what before PyPI gets anything (final review of web-020-pipe, 3).

Since the publishing jobs install nothing, the PyPI job no longer checks the signature: the publication's first job
(`published`) does, over every file of the published release, and the PyPI job holds both packages, by sha256sum, to
the list whose signature was checked (handed on by its hash). The security README still said the PyPI job runs
`python -m qkvm.release verify --all-packages --signed`.
"""
from __future__ import annotations

from tests.workflow_text import SECURITY, WORKFLOWS, jobs


def test_the_security_readme_says_published_checks_and_pypi_compares() -> None:
    text = " ".join((SECURITY / "README.md").read_text(encoding="utf-8").split())
    assert "the PyPI job runs `python -m qkvm.release verify" not in text
    assert "`published` runs `python -m qkvm.release verify --all --signed`" in text
    assert "the PyPI job holds both packages to that list, by its hash, with `sha256sum`" in text
    every = jobs(WORKFLOWS / "release.yml")
    assert "qkvm.release verify --all --signed" in every["published"] and "qkvm.release" not in every["pypi"]
