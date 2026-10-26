"""What reaches the registries is the image the scan saw, and the tools that make it are pinned (the review of 850745e, P3).

The image was built once into an OCI archive, tested and scanned, and copied with its digests kept; but what tied the
copy to the scan was only SHA256SUMS, written in the same job after the scan and the tests, from the archive as it was
by then, in the same artifact; the digest the publisher expected was taken from the archive itself; the index that the
version tags (1.2.3, 1.2, latest) are moved to was made by `imagetools create` and never read back; and BuildKit and
the SBOM generator came from tags that can be moved (moby/buildkit:buildx-stable-1, docker/buildkit-syft-scanner:stable-1).

Now the scan writes what it saw (scanned-image.json: the archive's checksum, the digest that is pushed, every manifest
under it, and the image the scanner read, checked against the scanner's own report), the archive is held to it before
its checksum is written and again before anything is pushed, the publisher pushes the digest the scan saw and reads
every tag back, the index is checked before a tag is moved to it and after, and BuildKit and the generator are named
by digest. image-digests.py decides; test-image-digests.py tries it.
"""
from __future__ import annotations

import re

from tests.workflow_text import SECURITY, WORKFLOWS, jobs, steps, uncommented

ACTION = SECURITY / "action.yml"
DIGEST = r"@sha256:[0-9a-f]{64}\b"


def action_steps() -> list[str]:
    return steps(uncommented(ACTION.read_text(encoding="utf-8")))


def test_buildkit_and_the_sbom_generator_are_named_by_digest() -> None:
    every = action_steps() + [step for job in jobs(WORKFLOWS / "release.yml").values() for step in steps(job)]
    buildx = [step for step in every if "docker/setup-buildx-action@" in step]
    # (The build sets BuildKit up; the publisher needs none: test_the_image_job_names_its_tags_before_any_login.)
    assert len(buildx) >= 1, "the build sets BuildKit up"
    for step in buildx:
        assert re.search(r"driver-opts: *image=moby/buildkit:v[0-9.]+" + DIGEST, step), step
    build = [step for step in action_steps() if "docker/build-push-action@" in step]
    assert len(build) == 1
    assert not re.search(r"^\s*sbom:", build[0], flags=re.M), "the SBOM is made by the pinned generator, not the default one"
    assert re.search(r"attests: *type=sbom,generator=docker/buildkit-syft-scanner:[0-9.]+" + DIGEST, build[0]), build[0]
    assert re.search(r"^\s*provenance: *true\s*$", build[0], flags=re.M)


def test_the_scan_records_what_it_saw() -> None:
    scan = uncommented((SECURITY / "scan-image.sh").read_text(encoding="utf-8"))
    recording = re.search(r'image-digests\.py" record\b[^\n]*', scan)
    assert recording, "the scan writes down the digests it scanned"
    line = recording.group(0)
    for part in ('--layout "$scan_tmp/oci"', '--report "$out/trivy.json"', '--archive "$archive"', '--arch "$arch"', '--output "$out/scanned-image.json"'):
        assert part in line, part
    assert scan.index("--format json --output \"$out/trivy.json\"") < scan.index(line), "after the scanner's report exists"


def test_the_archive_is_held_to_the_scan_before_its_checksum_is_written() -> None:
    record = [step for step in action_steps() if "sha256sum image.tar > SHA256SUMS" in step]
    assert len(record) == 1
    step = record[0]
    held = re.search(r"image-digests\.py\"? check-archive --arch \"\$ARCH\" evidence/scanned-image\.json image\.tar", step)
    assert held and held.start() < step.index("sha256sum image.tar > SHA256SUMS"), step


def test_the_publisher_pushes_only_what_the_scan_saw_and_reads_every_tag_back() -> None:
    publish = jobs(WORKFLOWS / "release.yml")["image"]
    order = steps(publish)
    assert any("uses: actions/checkout@" in step for step in order), "the checks are the tagged commit's own"
    pushing = [step for step in order if "skopeo copy" in step]
    assert len(pushing) == 1
    push = pushing[0]
    before = "\n".join(order[: order.index(push)])
    # (Held to the record the release signed, which the draft made of what the scan saw; see
    # test_a_release_is_a_draft_until_a_person_publishes_it.py. Not to the copy that travels with the archive.)
    assert re.search(r'image-digests\.py check-archive --arch "\$arch" "\$RUNNER_TEMP/signed/scanned-image-\$arch\.json" "images/release-image-\$arch/image\.tar"', before)
    assert re.search(r'^\s*record="\$RUNNER_TEMP/signed/scanned-image-\$arch\.json"$', push, flags=re.M)
    assert 'records=("$RUNNER_TEMP/signed/scanned-image-amd64.json" "$RUNNER_TEMP/signed/scanned-image-arm64.json")' in push
    # The digest that is pushed is the one the scan saw, not one the archive says of itself.
    expected = re.search(r'expected=\$\(python3 \.github/security/image-digests\.py digest "\$record"\)', push)
    assert expected and expected.start() < push.index("skopeo copy")
    assert re.search(r'test "\$\(cat "digest-\$arch\.txt"\)" = "\$expected"', push)
    readback = re.search(r'skopeo inspect --raw --authfile "\$auth" "docker://\$image:\$\{TAG#v\}-\$arch"[^\n]*\n?[^\n]*"\$expected"', push)
    assert readback and readback.start() > push.index("skopeo copy"), "the per-architecture tag is read back"
    planned = push.index("imagetools create --dry-run")
    made = push.index('imagetools create "${tag_args[@]}"')
    first_check = push.index("image-digests.py check-index planned-index.json")
    assert planned < first_check < made, "the index is checked before any tag is moved to it"
    after = push[made:]
    assert re.search(r'for tag in "\$\{tags\[@\]\}"; do\s+skopeo inspect --raw --authfile "\$auth" "docker://\$tag" > published-index\.json\s+python3 \.github/security/image-digests\.py check-index published-index\.json "\$\{records\[@\]\}"', after), after


def test_the_checks_job_runs_every_policy_test() -> None:
    checks = "\n".join(steps(jobs(WORKFLOWS / "tests.yml")["checks"]))
    for test in sorted(SECURITY.glob("test-*.py")):
        assert f"python .github/security/{test.name}" in checks, test.name
