"""The release locks the libraries every update installed in place runs, tries that set on the three systems before it is
signed, signs it, and builds the image from it (the owner's decisions of 2026-11-03; design-updates-in-place.md, 3.13)."""

from __future__ import annotations

import os
import re

from qkvm import _libraries
from qkvm.release import libraries as read_lock
from tests.workflow_text import APP, SECURITY, WORKFLOWS, jobs, needs, steps, waits_for

RELEASE = WORKFLOWS / "release.yml"


def test_the_lock_is_made_by_pip_and_packaging_pinned_by_hash_and_read_back_by_the_programs_own_reader() -> None:
    pinned = [line for line in (SECURITY / "lock-requirements.txt").read_text(encoding="utf-8").splitlines() if line and not line.startswith("#")]
    assert {line.split("==")[0] for line in pinned} == {"pip", "packaging"}
    assert all(re.fullmatch(r"[a-z]+==[0-9.]+ --hash=sha256:[0-9a-f]{64}", line) for line in pinned), pinned
    job = jobs(RELEASE)["libraries"]
    assert needs(job) == {"build"} and "secrets." not in job and "environment:" not in job
    made = next(step for step in steps(job) if "make-libraries.py" in step)
    assert "-m pip install --require-hashes --no-deps --only-binary :all: -r .github/security/lock-requirements.txt" in made
    assert made.index("lock-requirements.txt") < made.index("make-libraries.py") < made.index("-m qkvm.release libraries") < made.index('echo "sums=$sums"')


def test_what_walls_run_is_tried_on_every_system_with_every_python_before_it_is_signed() -> None:
    # (Every Python of the lock since the final review of 0.3.0, core L1: 3.11 and 3.14 alone left 3.12 and 3.13 untried.)
    every = jobs(RELEASE)
    job = every["libraries_tested"]
    assert re.search(r"^        runner: \[ubuntu-24\.04, ubuntu-24\.04-arm, windows-2025\]$", job, flags=re.M)
    assert re.search(r'^        python: \["3\.11", "3\.12", "3\.13", "3\.14"\]$', job, flags=re.M)
    assert [f"3.{minor}" for minor in _libraries.PYTHONS] == ["3.11", "3.12", "3.13", "3.14"]
    text = "\n".join(steps(job))
    assert '-m pip install --require-hashes --no-deps --only-binary :all: -r "libraries/requirements/$target.txt"' in text
    assert 'target=$(python -c "from qkvm.__main__ import target; print(target())")' in text
    assert "pytest.main(" in text and "--wheels-only" in text
    assert {"libraries", "libraries_tested", "packages"} <= waits_for(every, "sign")
    packages = "\n".join(steps(every["packages"]))
    assert "bash .github/security/audit-lock.sh libraries dependency-audit" in packages  # (every library the lock names, audited)


def test_the_lock_is_signed_with_the_packages() -> None:
    signing = steps(jobs(RELEASE)["sign"])
    held = next(index for index, step in enumerate(signing) if "needs.libraries.outputs.sums" in step)
    signed = next(index for index, step in enumerate(signing) if "-m qkvm.release publish" in step)
    assert held < signed
    assert '(cd release && sha256sum -- "qkvm-${TAG#v}-libraries.json" >> SHA256SUMS)' in signing[held]
    # SHA256SUMS stays far under the 64,000 bytes every version since 0.1.0 reads of it: four lines.
    assert "sums = await self._download(client, release.sums_url, 64_000)" in (APP / "qkvm" / "update.py").read_text(encoding="utf-8")


def test_the_image_is_built_from_the_lock_of_its_own_python() -> None:
    dockerfile = (APP / "Dockerfile").read_text(encoding="utf-8")
    python = re.search(r"^FROM python:3\.(\d+)-slim@", dockerfile, flags=re.M)
    assert python, "the base image names its Python"
    every = jobs(RELEASE)
    for job, system in (("images_amd64", "linux-x86_64"), ("images_arm64", "linux-aarch64")):
        assert "libraries" in needs(every[job])
        assert f"libraries: libraries/requirements/cp3{python.group(1)}-{system}.txt" in every[job], job
    install = dockerfile.index("pip install --require-hashes --no-deps --only-binary :all: -r image-libraries.txt")
    assert install < dockerfile.index("pip install . \\") < dockerfile.index("pip check")
    kept = (SECURITY / "image-libraries.txt").read_text(encoding="utf-8")
    if os.environ.get("QKVM_CONTAINER") != "1":  # (inside the release's image it holds the lock for its Python: its point)
        assert all(line.startswith("#") for line in kept.splitlines()), "kept empty: a build from the source takes them from PyPI"
    assert "!.github/security/image-libraries.txt" in (APP / ".dockerignore").read_text(encoding="utf-8")


def test_the_release_command_reads_a_lock_as_every_copy_does(tmp_path) -> None:  # type: ignore[no-untyped-def]
    import json

    import pytest

    entry = {"file": "h11-0.16.0-py3-none-any.whl", "url": "https://files.pythonhosted.org/packages/ab/cd/" + "e" * 60 + "/h11-0.16.0-py3-none-any.whl", "sha256": "a" * 64, "size": 10, "unpacked": 20}
    lock = {"format": 1, "version": "9.9.9", "targets": {target: {"libraries": [{"name": "h11", "version": "0.16.0", "wheels": [entry]}]} for target in _libraries.TARGETS}}
    path = tmp_path / "qkvm-9.9.9-libraries.json"
    path.write_text(json.dumps(lock), encoding="utf-8")
    assert "12 targets, 1 wheels" in read_lock(path)
    del lock["targets"]["cp311-win-amd64"]
    path.write_text(json.dumps(lock), encoding="utf-8")
    with pytest.raises(SystemExit, match="has no build for cp311-win-amd64"):
        read_lock(path)
