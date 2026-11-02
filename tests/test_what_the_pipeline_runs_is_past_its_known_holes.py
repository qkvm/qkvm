"""What the release and the tests run of other people's is named exactly, and at a version past every advisory known
against it when it was last looked at (the dependency audit of 2026-11-01).

An action is named by the commit it is at, with its version in a comment (a tag can be moved to other code, a commit
cannot), and one action is at one commit in every file. Where a version had a known hole, the version past it and the
commit its tag points to are written here as they were read from the action's own repository (gh api, read only, on
2026-11-01): a new pin is checked against its tag and written here in the same change, never taken on trust. So are the
scanner (its version and the SHA-256 of its archives, checked against its release's own asset digests) and the images
BuildKit runs (by the digest Docker Hub serves for their tags, read with `docker buildx imagetools inspect`).
"""
from __future__ import annotations

import re
from pathlib import Path

from tests.workflow_text import SECURITY, WORKFLOWS

FILES = (WORKFLOWS / "release.yml", WORKFLOWS / "tests.yml", SECURITY / "action.yml")
USES = re.compile(r"^\s*(?:- )?uses:\s*(\S+)(.*)$", re.M)

# action: (the version, the commit its tag points to, why no earlier one will do)
ACTIONS = {
    "pypa/gh-action-pypi-publish": (
        "v1.14.3",
        "7245906fb61fa33a13554f9d5fb856fe61758086",
        "GHSA-5xjx-3w67-w9x9 (critical): up to 1.14.2 it trusted the emSign roots, with their compromised intermediates, for the upload and its signing",
    ),
    "docker/login-action": (
        "v4.7.0",
        "81c6f93d4bc991e510b342a00b419b3bb4efc5c6",
        "v4.6.0 bundles undici 6.27.0 (GHSA-rfgv-xxqx-mfg5 and GHSA-2m5v-pch6-74hx among others, fixed by 6.28.1 and 6.29.1); v4.7.0 bundles 6.29.1",
    ),
    "actions/setup-python": (
        "v7.1.0",
        "6d4fd22b20465ccc0f7354476588e8df7c9ca0e0",
        "v7.0.0 bundles undici 6.27.0 (GHSA-rfgv-xxqx-mfg5, fixed by 6.28.1); v7.1.0 bundles 6.29.0, and is the newest release there is",
    ),
}

# The scanner the image is held to: its version, the SHA-256 of its archive for each runner, and why no earlier one.
TRIVY = (
    "0.76.1",
    {"64bit": "c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0", "ARM64": "e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f"},
    "0.76.0 is built with a Go that trusts the compromised eMudhra intermediates (CVE-2026-111943) when it fetches its database; 0.76.1 with Go 1.27.3, which refuses them",
)

# Python packages the pipeline installs by version, outside the wheel's own requirements: (where, the version, why no
# earlier one). pip-audit checks the release's dependencies; the others are libraries of the makers' emulators the
# controllers job runs on loopback.
PACKAGES = {
    "pip-audit": (
        SECURITY / "audit-wheel.sh",
        "2.10.1",
        "2.10.0 stops with a KeyError at an OSV record whose affected entry has no ranges, and a release's audit with it",
    ),
    "pyOpenSSL": (
        WORKFLOWS / "tests.yml",
        "26.4.0",
        "25.3.0 has GHSA-5pwr-322w-8jr4 (a DTLS cookie callback overflows its buffer) and GHSA-vp96-hxj8-p424, fixed in 26.0.0; 26.4.0 takes cryptography 50",
    ),
    "multipart": (WORKFLOWS / "tests.yml", "1.3.1", "1.3.0 has GHSA-p2m9-wcp5-6qw3 (ReDoS in parse_options_header()), fixed in 1.3.1"),
}

# image: (its tag, the digest of that tag's index, why no earlier one will do)
BUILD_IMAGES = {
    "moby/buildkit": (
        "v0.34.1",
        "sha256:99368f3e46177c6405b9740e4461d91cee004128daeecca78d4ceac50ec1da5c",
        "v0.33.1 is built with a Go that trusts the compromised eMudhra intermediates (CVE-2026-111943) for the registries it pulls from; v0.34.1 with Go 1.26.10",
    ),
    "docker/buildkit-syft-scanner": (
        "1.12.1",
        "sha256:873a7458c3c8ac8e32c7b796c10e1600b07b963d2aa000a72a2d97aaaa2d6315",
        "1.12.0 decodes archives with a brotli older than 1.2.7 (CVE-2026-111497)",
    ),
}


def uses(path: Path) -> list[tuple[str, str]]:
    """Every `uses:` of a file: what it names, and the rest of its line (the comment)."""
    return [(found.group(1), found.group(2)) for found in USES.finditer(path.read_text(encoding="utf-8"))]


def test_every_action_is_named_by_its_commit_with_its_version_beside_it() -> None:
    at: dict[str, set[str]] = {}
    for path in FILES:
        for named, rest in uses(path):
            if named.startswith("./"):
                continue  # (this repository's own, at the commit being run)
            action, _, commit = named.partition("@")
            assert re.fullmatch(r"[0-9a-f]{40}", commit), f"{path.name}: {named} is not named by a commit"
            assert re.fullmatch(r"\s*# v\d+(\.\d+)*\s*", rest), f"{path.name}: {named} has no version beside it"
            at.setdefault(action, set()).add(commit + rest.strip())
    # (One action, one commit: two would be two versions to keep up to date, and one of them forgotten.)
    assert {action: len(pins) for action, pins in at.items() if len(pins) > 1} == {}


def test_each_action_with_a_known_hole_is_at_the_commit_past_it() -> None:
    for action, (version, commit, why) in ACTIONS.items():
        found = [(path.name, named, rest.strip()) for path in FILES for named, rest in uses(path) if named.partition("@")[0] == action]
        assert found, f"{action} is not used any more: take it out of this list"
        for name, named, rest in found:
            assert (named, rest) == (f"{action}@{commit}", f"# {version}"), f"{name}: {named} {rest}, and {why}"


def test_the_scanner_is_the_version_past_its_known_hole_held_to_its_checksums() -> None:
    version, sums, why = TRIVY
    script = (SECURITY / "scan-image.sh").read_text(encoding="utf-8")
    assert re.findall(r"^version=(\S+)$", script, flags=re.M) == [version], why
    assert dict(re.findall(r"scanner_arch=(\w+); checksum=([0-9a-f]{64}) ;;", script)) == sums, why


def test_the_security_readme_names_the_scanner_that_runs() -> None:
    # (It said 0.76.0 after the scanner had moved on.)
    readme = (SECURITY / "README.md").read_text(encoding="utf-8")
    assert re.findall(r"Trivy (\d+\.\d+\.\d+)", readme) == [TRIVY[0]]


def test_buildkit_and_its_sbom_generator_are_named_by_the_digests_past_their_known_holes() -> None:
    action = (SECURITY / "action.yml").read_text(encoding="utf-8")
    for image, (tag, digest, why) in BUILD_IMAGES.items():
        named = re.findall(rf"{re.escape(image)}:([^@\s]+)@(sha256:[0-9a-f]{{64}})", action)
        assert named == [(tag, digest)], f"{image}: {named}, and {why}"
    # (Nothing else BuildKit runs is named by a tag alone: a tag moves.)
    assert re.findall(r"(?:image|generator)=([^,\s]+)", action) == [f"{image}:{tag}@{digest}" for image, (tag, digest, _) in BUILD_IMAGES.items()]


def test_each_package_the_pipeline_installs_by_version_is_past_its_known_holes() -> None:
    wrong = []
    for package, (path, version, why) in PACKAGES.items():
        pins = re.findall(rf"(?<![\w.-]){re.escape(package)}==(\S+)", path.read_text(encoding="utf-8"))
        if pins != [version]:
            wrong.append(f"{path.name}: {package} {pins}, and {why}")
    assert wrong == []
