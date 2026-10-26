"""Each secret is in an environment of its own, named by the one job that uses it (third review of web-020-pipe, 1).

`sign` and `image` both named the environment `release`, which held RELEASE_SIGNING_KEY and the Docker Hub secrets:
`image`, the job with the most code of others in it (the docker actions, BuildKit, skopeo), could reach the signing
key, and `sign` the Docker Hub token. Now `release` holds the signing key only and is named by `sign` only; `image`
names `registries`, which holds DOCKERHUB_USERNAME and DOCKERHUB_TOKEN; `pypi` names `pypi`, which holds nothing (PyPI
trusts the workflow and that environment by name). The notes at the top of the workflow and the README say how each
is set up.
"""
from __future__ import annotations

import re

from tests.workflow_text import APP, WORKFLOWS, jobs

RELEASE = WORKFLOWS / "release.yml"


def environment_of(job: str) -> str | None:
    found = re.search(r"^    environment:(?: *([\w-]+)| *\n\s+name: *([\w-]+))", job, flags=re.M)
    return (found.group(1) or found.group(2)) if found else None


def test_no_job_but_sign_names_release_and_no_job_but_image_names_registries() -> None:
    every = jobs(RELEASE)
    named = {name: environment_of(job) for name, job in every.items()}
    assert {name for name, environment in named.items() if environment == "release"} == {"sign"}
    assert {name for name, environment in named.items() if environment == "registries"} == {"image"}
    assert {name for name, environment in named.items() if environment == "pypi"} == {"pypi"}
    for name, job in every.items():
        used = set(re.findall(r"secrets\.([A-Z_]+)", job))
        expected = {"sign": {"RELEASE_SIGNING_KEY"}, "image": {"DOCKERHUB_USERNAME", "DOCKERHUB_TOKEN"}}.get(name, set())
        assert used == expected, f"{name}: {sorted(used)}"


def test_the_notes_and_the_readme_say_what_each_environment_holds() -> None:
    top = RELEASE.read_text(encoding="utf-8").split("\nname: Release\n", 1)[0]
    readme = APP.joinpath("README.md").read_text(encoding="utf-8")
    publishing = " ".join(readme[readme.index("### Publishing releases") : readme.index("## Command line")].split())
    for text in (" ".join(top.replace("#", " ").split()), publishing):
        assert "`registries`" in text or "registries" in text
        assert re.search(r"registries[^.]*DOCKERHUB_USERNAME and DOCKERHUB_TOKEN", text), text[:300]
        assert re.search(r"release[^.]*RELEASE_SIGNING_KEY", text)
