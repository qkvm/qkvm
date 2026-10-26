"""The workflow's notes and the changelog say what decides the signed image, and claim no hold that is not made (fresh
review of web-020-pipe, 7).

release.yml said the image's own `pip install .` could "never" change what is signed: its dependencies come from PyPI
unpinned, and they are what the signed image holds. The changelog said every file one job hands another is held to its
maker's hash (`sign` holds two of the scan's evidence files, the ones that go into the signed record), and that a member
whose name is not plain is refused (not true of a zip entry's Unicode Path field on Python 3.12 and later until then).
"""
from __future__ import annotations

from tests.workflow_text import APP, WORKFLOWS


def flat(text: str) -> str:
    return " ".join(text.replace("#", " ").split())


def chapter() -> str:
    text = (APP / "CHANGELOG.md").read_text(encoding="utf-8")
    start = text.index("## 0.2.0")
    return flat(text[start : text.index("\n## ", start + 1)])


def test_the_notes_say_the_images_unpinned_dependencies_decide_what_is_signed() -> None:
    top = flat((WORKFLOWS / "release.yml").read_text(encoding="utf-8").split("\nname: Release\n", 1)[0])
    assert "never what is signed: the image's own `pip install .`" not in top
    assert "decide what the image holds, and so what is signed" in top
    # (delta-g review, a nit: skopeo comes from Ubuntu's archive, unpinned, before the image jobs' hashes.)
    assert "before anything unpinned runs on its runner outside a container" not in top
    assert ("takes the hash before anything runs on its runner, outside a container, that is neither pinned (by hash, "
            "digest or commit) nor from Ubuntu's own archive") in top


def test_the_notes_name_the_images_build_backend_as_unpinned() -> None:
    # (delta-i review, 3) `pip install .` builds the image's qKVM in an isolated environment with the hatchling it
    # fetches, unpinned; that hatchling decides which of qKVM's files the image holds.
    top = flat((WORKFLOWS / "release.yml").read_text(encoding="utf-8").split("\nname: Release\n", 1)[0])
    assert "Two things still come unpinned" not in top
    assert "its own build backend (hatchling and what it needs, which `pip install .` fetches for an isolated build" in top
    assert "not the hash-pinned and checked wheel of the packages" in top
    dockerfile = (APP / "Dockerfile").read_text(encoding="utf-8")
    assert "pip install . \\" in dockerfile and "--no-build-isolation" not in dockerfile, "as it is said: else say it anew"


def test_the_notes_say_which_files_are_held_and_which_are_for_a_person() -> None:
    # (delta-g review, a nit) Of each scan's evidence only scanned-image.json and native-versions.json are held (the
    # two that go into the signed record); the rest is kept for a person, and no job reads the dependency audit.
    top = flat((WORKFLOWS / "release.yml").read_text(encoding="utf-8").split("\nname: Release\n", 1)[0])
    assert "Every artifact passed between the tag run's jobs is held" not in top
    assert "Every file a job of the tag run takes from another's artifact and uses is held to a hash" in top
    assert ("the rest of the scan's evidence (the scanner's report and version, its database's date, the SBOM, the policy "
            "outputs) is kept for a person to read and is not held") in top


def test_the_changelog_claims_only_the_holds_that_are_made() -> None:
    text = chapter()
    assert "Every file one job of the release run hands another" not in text
    assert "each image's scan record (with its archive's checksum) and native versions to hashes its image job took" in text
    assert "the draft is made of exactly the files the signed list names" in text
    # (delta-g review, 2; delta-i review, 3) The three unpinned parts of the image's build, as release.yml's notes say:
    # the Debian updates (the libraries assemble-runtime.py copies into the image), the Python dependencies, and the
    # build backend that `pip install .` fetches for its isolated build of the image's own qKVM, which is therefore not
    # the hash-pinned, checked wheel; "pinned by hash" is said of the packages' build tools only.
    assert "The image's Debian updates, Python dependencies and build backend are not pinned" in text
    assert "the Dockerfile's `apt-get upgrade` and `pip install .` take them" in text
    assert "copied into the final image" in text
    assert "not taken from the checked wheel" in text
    assert "the packages' build tools are pinned by hash" in text
    assert "What is signed is what was built, tested and scanned: the build tools are pinned by hash" not in text
    assert "in a zip's Unicode name field too" in text
    assert "on the same runner" in text
