"""Every artifact a job of the tag's run reads is held to a hash the job that made it handed on (delta review of
web-020-pipe, 1).

Since the build was split, `packages` (which runs code from PyPI that nothing pins: twine, the suite's dependencies,
pip-audit's) runs beside the image jobs, and nothing bound the image jobs' artifacts to `sign`: `images` handed nothing
on, and `sign` made the image record from whatever the container-security artifacts held, which the publication then
held the archives to. Code in `packages` that got at the run's artifact token could have put a forged, self-consistent
archive and scan record of its own in their place. Now each image job (one per architecture, so that no job output
overwrites another's) hands on the SHA-256 of its image.tar, scanned-image.json and native-versions.json, and `sign`
holds the evidence to them (and the record's archive checksum to the image.tar's) before it makes the record; `sign`
in turn hands on the hashes of what it signed, and `signature` and `draft` hold their copies to those; `packages` and
`sign` hold the packages to the build's.
"""
from __future__ import annotations

import re

from tests.workflow_text import SECURITY, WORKFLOWS, jobs, steps

RELEASE = WORKFLOWS / "release.yml"
# Who makes each artifact of the tag's run (the image jobs' container-security-<arch> through the shared action; each
# downloaded by its exact name: test_every_artifact_is_downloaded_by_its_exact_name).
MAKERS = {"release": {"build"}, "container-security-amd64": {"images_amd64"}, "container-security-arm64": {"images_arm64"}, "signed": {"sign"}}
OUTPUTS = {
    "build": {"sums"},
    "images_amd64": {"archive", "scan", "native"},
    "images_arm64": {"archive", "scan", "native"},
    "sign": {"sums", "sig"},
}


def downloads(job: str) -> set[str]:
    found = set()
    for step in steps(job):
        if "actions/download-artifact@" in step and "run-id:" not in step:
            named = re.search(r"^\s*(?:name|pattern): (\S+)$", step, flags=re.M)
            assert named, step
            found.add(named.group(1))
    return found


def test_each_maker_hands_on_the_hashes_of_what_it_made() -> None:
    every = jobs(RELEASE)
    assert "images" not in every, "one image job per architecture: a matrix's legs overwrite each other's outputs"
    for name, outputs in OUTPUTS.items():
        for output in outputs:
            assert re.search(rf"^      {output}: \$\{{\{{ steps\.\w+\.outputs\.{output} \}}\}}$", every[name], flags=re.M), f"{name}: {output}"
    # (Taken in the shared action the image jobs use, right after the scan and the native step:
    # test_the_image_evidence_is_hashed_before_anything_unpinned_runs. Into a variable first, so that a missing file
    # fails the step: test_a_hash_of_a_missing_file_fails_the_job.)
    made = "\n".join(steps((SECURITY / "action.yml").read_text(encoding="utf-8")))
    for output, path in (("archive", "image.tar"), ("scan", "evidence/scanned-image.json"), ("native", "evidence/native-versions.json")):
        assert f"{output}=$(sha256sum \"image-$ARCH/{path}\" | cut -d ' ' -f 1)" in made, output
        assert f'echo "{output}=${output}"' in made, output


def test_every_artifact_read_in_the_tags_run_is_held_to_its_makers_hash_before_it_is_used() -> None:
    every = jobs(RELEASE)
    readers = {name for name, job in every.items() if downloads(job)}
    assert readers == {"packages", "sign", "signature", "draft"}, readers
    for name in readers:
        order = steps(every[name])
        last_download = max(index for index, step in enumerate(order) if "actions/download-artifact@" in step)
        for artifact in downloads(every[name]):
            for maker in MAKERS[artifact]:
                held = [index for index, step in enumerate(order) if f"needs.{maker}.outputs." in step]
                assert held, f"{name} holds {artifact} to nothing of {maker}"
                # The hold comes right after the downloads, before anything else is run.
                between = order[last_download + 1 : held[0]]
                assert all(not re.search(r"^\s*run:", step, flags=re.M) or any(f"needs.{other}.outputs." in step for other in OUTPUTS) for step in between), (name, artifact)
                assert "sha256sum" in order[held[0]], (name, maker)


def test_sign_holds_the_scans_and_their_archives_to_the_image_jobs() -> None:
    signing = steps(jobs(RELEASE)["sign"])
    held = next(index for index, step in enumerate(signing) if "needs.images_amd64.outputs.scan" in step)
    record = next(index for index, step in enumerate(signing) if "image-digests.py release-record" in step)
    step = signing[held]
    assert held < record
    for arch in ("AMD64", "ARM64"):
        for kind in ("ARCHIVE", "SCAN", "NATIVE"):
            assert f"{arch}_{kind}: ${{{{ needs.images_{arch.lower()}.outputs.{kind.lower()} }}}}" in step, (arch, kind)
    assert 'test "$(sha256sum "evidence/container-security-$arch/scanned-image.json" | cut -d \' \' -f 1)" = "${!scan}"' in step
    assert 'test "$(sha256sum "evidence/container-security-$arch/native-versions.json" | cut -d \' \' -f 1)" = "${!native}"' in step
    assert 'test "$(jq --raw-output .archive.sha256 "evidence/container-security-$arch/scanned-image.json")" = "${!archive}"' in step
