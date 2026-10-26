"""A release is made as a draft with every file attached and checked, and published by a person (draft first).

GitHub's immutable releases refuse any change to a release's files once it is published. The release workflow ran on
`release: published` and attached the wheel, SHA256SUMS and its signature afterwards (`gh release upload`): with
immutable releases on, every release would have failed there, with PyPI and the registries still to come.

Now pushing a v* tag (only the organisation's admins may make one) runs the checks, the build, the tests, the scans and
the signature, and makes a DRAFT release with every file attached, then reads them back from the draft and checks them
against the signature. A person reviews the draft and publishes it; publication runs the PyPI and image jobs, which
take what they publish from the published release (the packages) or from the archives the release's signed image
record names (the images, kept by the tag's run, held to the checksums the scan saw), and check it before uploading.
"""
from __future__ import annotations

import re

from tests.workflow_text import SECURITY, WORKFLOWS, jobs, steps, uncommented, waits_for

RELEASE = WORKFLOWS / "release.yml"
DRAFT_STAGE = {"tested_commit", "build", "packages", "images_amd64", "images_arm64", "sign", "signature", "draft"}
PUBLISH_STAGE = {"published", "image", "pypi"}


def trigger() -> str:
    text = uncommented(RELEASE.read_text(encoding="utf-8"))
    return text[text.index("\non:\n") : text.index("\npermissions:\n")]


def test_a_tag_makes_the_draft_and_a_publication_publishes_it() -> None:
    on = trigger()
    assert re.search(r"^  push:\n    tags: \[\"v\*\"\]\n", on, flags=re.M), on
    assert re.search(r"^  release:\n    types: \[published\]\n", on, flags=re.M), on
    assert set(re.findall(r"^  ([a-z_]+):", on, flags=re.M)) == {"push", "release"}, "nothing else starts a release"
    every = jobs(RELEASE)
    assert set(every) == DRAFT_STAGE | PUBLISH_STAGE
    for name in DRAFT_STAGE:
        assert re.search(r"^    if: github\.event_name == 'push'$", every[name], flags=re.M), name
        assert not (waits_for(every, name) & PUBLISH_STAGE), name
    for name in PUBLISH_STAGE:
        assert re.search(r"^    if: github\.event_name == 'release'$", every[name], flags=re.M), name
        assert not (waits_for(every, name) & DRAFT_STAGE), "a publication is another run: it can wait for no job of the tag's run"
    text = RELEASE.read_text(encoding="utf-8")
    assert "TAG: ${{ github.event_name == 'release' && github.event.release.tag_name || github.ref_name }}" in text
    assert re.search(r"^concurrency:\n  group: release-\$\{\{ github\.event\.release\.tag_name \|\| github\.ref_name \}\}\n  cancel-in-progress: false\n", text, flags=re.M)


def test_no_file_is_changed_on_a_release_after_it_is_published() -> None:
    text = uncommented(RELEASE.read_text(encoding="utf-8"))
    assert "gh release upload" not in text and "gh release edit" not in text and "gh release delete" not in text
    every = jobs(RELEASE)
    writers = {name for name, job in every.items() if re.search(r"^\s*contents: write\b", job, flags=re.M)}
    assert writers == {"draft"}, "only the job that makes the draft may write to the repository's releases"


def test_the_draft_is_made_only_once_everything_passed_and_its_files_are_read_back_and_checked() -> None:
    every = jobs(RELEASE)
    # (Signed in `sign`, the key's job, checked by the cryptography library in `signature`, then made a draft here.)
    assert waits_for(every, "draft") == {"tested_commit", "build", "packages", "images_amd64", "images_arm64", "sign", "signature"}
    assert re.search(r"^    environment: release\b", every["sign"], flags=re.M), "the signing key's environment, by its name"
    signing = steps(every["sign"])
    signed = {key: next(index for index, step in enumerate(signing) if key in step) for key in (
        "image-digests.py release-record", "-m qkvm.release publish --openssl release/SHA256SUMS")}
    assert list(signed.values()) == sorted(signed.values()), signed
    order = steps(every["draft"])
    position = {key: next(index for index, step in enumerate(order) if key in step) for key in (
        "select(.tag_name == $tag)", "gh release create", "-m qkvm.release verify --all",
    )}
    assert list(position.values()) == sorted(position.values()), position
    record = signing[signed["image-digests.py release-record"]]
    assert '--output "release/qkvm-${TAG#v}-image.json"' in record and '--run-id "$GITHUB_RUN_ID"' in record and '--commit "$GITHUB_SHA"' in record
    assert re.search(r'sha256sum -- "qkvm-\$\{TAG#v\}-image\.json" >> SHA256SUMS', record), "the image record is in what is signed"
    create = order[position["gh release create"]]
    assert re.search(r'gh release create "\$TAG" --repo "\$GITHUB_REPOSITORY" --draft --verify-tag [^\n]*\\?\n?[^\n]*release/\*', create), create
    readback = create[create.index("gh release create") :]
    assert 'repos/$GITHUB_REPOSITORY/releases/assets/$asset' in readback and "application/octet-stream" in readback
    assert re.search(r'/usr/bin/python3 -m qkvm\.release verify --all --signed --openssl "\$drafted/SHA256SUMS" "\$\{files\[@\]\}"', readback)
    existing = order[position["select(.tag_name == $tag)"]]
    assert "exit 1" in existing and "--paginate" in existing, "a tag that has a release (draft or published) is refused"


def test_pypi_takes_the_packages_from_the_published_release() -> None:
    order = steps(jobs(RELEASE)["pypi"])
    text = "\n".join(order)
    assert "download-artifact" not in text, "what PyPI gets is what the published release holds"
    fetch = next(step for step in order if "--dir dist" in step)
    assert re.search(r'gh release download "\$TAG" --repo "\$GITHUB_REPOSITORY" --pattern "qkvm-\$\{TAG#v\}-py3-none-any\.whl" --pattern "qkvm-\$\{TAG#v\}\.tar\.gz" --dir dist', fetch)
    assert 'test "$(ls dist | wc -l)" -eq 2' in fetch
    assert re.search(r"^\s*environment:\n\s*name: pypi\n", jobs(RELEASE)["pypi"], flags=re.M), "PyPI trusts this environment by its name"


def test_the_image_job_takes_the_archives_the_signed_record_names() -> None:
    image = jobs(RELEASE)["image"]
    assert re.search(r"^    environment: registries\b", image, flags=re.M), "the registries' credentials, not the signing key's"
    assert re.search(r"^\s*actions: read\b", image, flags=re.M), "to read the tag's run's archives"
    order = steps(image)
    signed = next(index for index, step in enumerate(order) if "image-digests.py from-release" in step)
    step = order[signed]
    assert re.search(r'gh release download "\$TAG" --repo "\$GITHUB_REPOSITORY" --pattern SHA256SUMS --pattern "qkvm-\$\{TAG#v\}-image\.json" --dir "\$RUNNER_TEMP/signed"', step)
    # The record is believed only as the list whose signature the publication's first job checked names it.
    held = step.index('(cd "$RUNNER_TEMP/signed" && sha256sum --check --strict "$RUNNER_TEMP/record.sums")')
    assert step.index('= "$SUMS"') < held < step.index("image-digests.py from-release")
    assert "published" in waits_for(jobs(RELEASE), "image")
    assert '--version "${TAG#v}" --commit "$GITHUB_SHA"' in step
    fetched = next(index for index, item in enumerate(order) if "actions/download-artifact@" in item)
    assert fetched > signed and "run-id: ${{ needs.published.outputs.run }}" in order[fetched] and "github-token: ${{ github.token }}" in order[fetched]


def test_the_archives_are_kept_until_a_person_can_have_published_the_draft() -> None:
    for arch in ("amd64", "arm64"):
        images = steps(jobs(RELEASE)[f"images_{arch}"])
        upload = next(step for step in images if f"name: release-image-{arch}\n" in step)
        assert "retention-days: 90" in upload


def test_every_action_is_named_by_its_full_commit() -> None:
    for path in [*WORKFLOWS.glob("*.yml"), SECURITY / "action.yml"]:
        for used in re.findall(r"^\s*(?:- )?uses: *(\S+)", uncommented(path.read_text(encoding="utf-8")), flags=re.M):
            assert used.startswith("./") or re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", used), f"{path.name}: {used}"
