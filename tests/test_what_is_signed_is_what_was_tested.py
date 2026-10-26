"""What is signed is what was built and tested: checksummed right after the build, tested on a copy held to that
checksum, and built with tools pinned by hash (final review of web-020-pipe, 5).

The build job took the checksum at its end, after code from PyPI that nothing pinned (build, twine, hatchling in its
own build environment, pytest, pip-audit and what each brings) had run in the same job, with write access to dist/:
any of it could have changed the wheel that was then signed. Now the build job installs only the build tools, each
pinned by hash, builds without fetching a build environment of its own, and checksums and hands on the packages at
once (the checksum list's own hash as a job output, not inside the artifact); the tests, the checks and the audit run
in a job of their own on a copy they first hold to that hash; and `sign` holds what it signs to it again.
"""
from __future__ import annotations

import re

from tests.workflow_text import SECURITY, WORKFLOWS, jobs, steps, waits_for

RELEASE = WORKFLOWS / "release.yml"
HELD = (
    'test "$(sha256sum release/SHA256SUMS | cut -d \' \' -f 1)" = "$SUMS"',
    "(cd release && sha256sum --check --strict SHA256SUMS)",
)


def test_the_build_job_builds_with_pinned_tools_and_checksums_at_once() -> None:
    build = jobs(RELEASE)["build"]
    assert re.search(r"^      sums: \$\{\{ steps\.sums\.outputs\.sums \}\}$", build, flags=re.M)
    order = steps(build)
    made = next(index for index, step in enumerate(order) if "python -m build" in step)
    step = order[made]
    assert "python -m pip install --require-hashes --no-deps --only-binary :all: -r .github/security/build-requirements.txt" in step
    assert "python -m build --no-isolation" in step, "no build environment fetched unpinned"
    assert order[made + 1].startswith("id: sums\n") and "sha256sum -- *.whl *.tar.gz > SHA256SUMS" in order[made + 1]
    assert "sums=$(sha256sum SHA256SUMS | cut -d ' ' -f 1)\n" in order[made + 1]
    assert 'echo "sums=$sums" >> "$GITHUB_OUTPUT"' in order[made + 1]
    assert "actions/upload-artifact@" in order[made + 2] and "name: release" in order[made + 2]
    assert len(order) == made + 3, "nothing runs after the packages are handed on"
    text = "\n".join(order)
    for other in ("pytest", "twine", "audit-wheel", "pip install .", "pip install dist", "/tmp/installed", "check-sdist"):
        assert other not in text, other
    installs = re.findall(r"pip install[^\n]*", text)
    assert installs == ["pip install --require-hashes --no-deps --only-binary :all: -r .github/security/build-requirements.txt"], installs


def test_the_build_tools_are_pinned_by_hash() -> None:
    lines = [line for line in (SECURITY / "build-requirements.txt").read_text(encoding="utf-8").splitlines() if line and not line.startswith("#")]
    names = set()
    for line in lines:
        found = re.fullmatch(r"([A-Za-z0-9_.-]+)==([0-9][0-9A-Za-z.]*) --hash=sha256:[0-9a-f]{64}", line)
        assert found, line
        names.add(found.group(1).lower().replace("_", "-"))
    assert {"build", "pyproject-hooks", "packaging", "hatchling", "pathspec", "pluggy", "tomlkit", "trove-classifiers"} == names


def test_the_tests_and_audits_run_on_a_copy_held_to_the_builds_checksum() -> None:
    every = jobs(RELEASE)
    checked = steps(every["packages"])
    held = next(index for index, step in enumerate(checked) if HELD[0] in step)
    assert "SUMS: ${{ needs.build.outputs.sums }}" in checked[held] and HELD[1] in checked[held]
    later = "\n".join(checked[held + 1 :])
    for work in ("twine check --strict", "/tmp/installed/bin/pip install dist/*.whl", "pytest.main(", "check-sdist.py", "audit-wheel.sh"):
        assert work in later, work
    assert all("pip install" not in step for step in checked[:held]), "nothing installed before the copy is held"


def test_sign_signs_only_what_the_build_checksummed_and_the_tests_passed() -> None:
    every = jobs(RELEASE)
    assert {"build", "packages", "images_amd64", "images_arm64"} <= waits_for(every, "sign")
    signing = steps(every["sign"])
    held = next(index for index, step in enumerate(signing) if HELD[0] in step)
    record = next(index for index, step in enumerate(signing) if "image-digests.py release-record" in step)
    signed = next(index for index, step in enumerate(signing) if "qkvm.release publish" in step)
    assert held < record < signed and "SUMS: ${{ needs.build.outputs.sums }}" in signing[held] and HELD[1] in signing[held]
