"""The updater takes exactly the wheel of the release's version, and the publication refuses a release with any other
file (review of web-020-pipe, F2).

A file added to a draft after the draft job read it back becomes part of the immutable release unchecked, and the
updater took the first `qkvm-*.whl` in the order GitHub lists the files: a second wheel attached by hand could be
the one every copy is offered. Now the updater takes `qkvm-<version>-py3-none-any.whl` of the release's own tag and
nothing else, and the publication's first job refuses a release whose signed list is not exactly the three files of
its version (and, by verify --all, any file the list does not name).
"""
from __future__ import annotations

import re
from pathlib import Path

from qkvm.update import Updater
from tests.workflow_text import WORKFLOWS, jobs, steps


def offered(tmp_path: Path, tag: str, names: list[str]) -> str | None:
    updater = Updater(tmp_path, "owner/wall")
    assets = [{"name": name, "browser_download_url": f"https://github.com/owner/wall/releases/download/{tag}/{name}"} for name in names]
    release = updater._release({"tag_name": tag, "assets": assets})
    return release.wheel_name if release else None


def test_the_wheel_of_the_tags_version_is_the_one_taken_whatever_the_order(tmp_path: Path) -> None:
    names = ["qkvm-0.0.1-py3-none-any.whl", "qkvm-9.9.9-py3-none-any.whl", "SHA256SUMS", "SHA256SUMS.sig"]
    assert offered(tmp_path, "v9.9.9", names) == "qkvm-9.9.9-py3-none-any.whl"
    assert offered(tmp_path, "v9.9.9", list(reversed(names))) == "qkvm-9.9.9-py3-none-any.whl"
    assert offered(tmp_path, "v1.2", ["qkvm-1.2-py3-none-any.whl"]) == "qkvm-1.2-py3-none-any.whl"


def test_a_release_without_the_wheel_of_its_version_offers_nothing(tmp_path: Path) -> None:
    for names in (["qkvm-0.0.1-py3-none-any.whl"], ["qkvm-9.9.9-cp313-cp313-linux_x86_64.whl"],
                  ["qkvm-9.9.9-py3-none-any.whl.whl"], ["other-9.9.9-py3-none-any.whl"], ["qkvm-9.9.9.tar.gz"]):
        assert offered(tmp_path, "v9.9.9", names) is None, names


def test_the_publication_refuses_a_release_that_is_not_exactly_the_files_of_its_version() -> None:
    first = steps(jobs(WORKFLOWS / "release.yml")["published"])
    step = next(item for item in first if "image-digests.py from-release" in item)
    listed = re.search(r"""listed=\$\(awk '\{print \$2\}' "\$RUNNER_TEMP/published/SHA256SUMS" \| LC_ALL=C sort \| tr '\\n' ' '\)""", step)
    exact = re.search(r'test "\$listed" = "qkvm-\$\{TAG#v\}-image\.json qkvm-\$\{TAG#v\}-py3-none-any\.whl qkvm-\$\{TAG#v\}\.tar\.gz "', step)
    assert listed and exact and listed.start() < exact.start() < step.index("image-digests.py from-release"), step
