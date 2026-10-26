"""PyPI gets only the packages the signed checksums name, and what is published was tested as built (the review of 850745e, P4).

The release signs SHA256SUMS and attaches it with the wheel, but the job that uploads to PyPI took the build's
artifact as it found it: nothing held the files PyPI gets to the signed list. The source archive went to PyPI too, and
was in no checksum and in no test; and the suite ran on the source tree (`python -m pytest` in the checkout imports
./qkvm), never on the wheel that is published.

Now SHA256SUMS lists the source archive beside the wheel (the README and the workflow say both are published); the
suite runs against the wheel installed in an environment of its own, from outside the tree, before anything is signed;
the source archive is held file for file to the tested wheel and installed by itself; and the PyPI job uploads nothing
before `python -m qkvm.release verify` (the system's Python and qkvm/release.py at the tag, as where the release is
signed) has checked the signature with the key built in and every file against the list, and that every package the
list names is among them.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from qkvm import release
from tests.workflow_text import WORKFLOWS, jobs, steps, waits_for

RELEASE = WORKFLOWS / "release.yml"


def signed_release(folder: Path, files: dict[str, bytes]) -> tuple[Path, str, str]:
    """A release as the workflow makes one: the files, SHA256SUMS of them, and its signature."""
    folder.mkdir()
    for name, data in files.items():
        (folder / name).write_bytes(data)
    sums = folder / "SHA256SUMS"
    sums.write_text("".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in files.items()), encoding="ascii")
    public = release.keygen(folder.parent / f"{folder.name}.key")
    key = (folder.parent / f"{folder.name}.key").read_text(encoding="ascii")
    release.publish(sums, key, (public,))
    return sums, public, key


PACKAGES = {"qkvm-9.9.9-py3-none-any.whl": b"the wheel", "qkvm-9.9.9.tar.gz": b"the source"}


def test_the_packages_the_signed_list_names_pass(tmp_path: Path) -> None:
    sums, public, _ = signed_release(tmp_path / "release", PACKAGES)
    files = [sums.parent / name for name in PACKAGES]
    said = release.verify(sums, files, (public,), complete="packages")
    assert "signed" in said
    release.verify(sums, files[:1], (public,))  # (one of them, where not all are asked for)


def test_a_file_that_is_not_the_signed_one_is_refused(tmp_path: Path) -> None:
    sums, public, _ = signed_release(tmp_path / "release", PACKAGES)
    wheel = sums.parent / "qkvm-9.9.9-py3-none-any.whl"
    wheel.write_bytes(b"another wheel")
    with pytest.raises(SystemExit, match="not the one the release lists"):
        release.verify(sums, [wheel], (public,))


def test_a_file_the_list_does_not_name_is_refused(tmp_path: Path) -> None:
    sums, public, _ = signed_release(tmp_path / "release", PACKAGES)
    stranger = sums.parent / "qkvm-9.9.9-py3-none-any.whl.extra"
    stranger.write_bytes(b"x")
    with pytest.raises(SystemExit, match="not in the release's checksums"):
        release.verify(sums, [stranger], (public,))


def test_a_package_the_list_names_and_that_is_not_there_is_refused(tmp_path: Path) -> None:
    sums, public, _ = signed_release(tmp_path / "release", {**PACKAGES, "qkvm-9.9.9-images.json": b"{}"})
    wheel = sums.parent / "qkvm-9.9.9-py3-none-any.whl"
    with pytest.raises(SystemExit, match=r"qkvm-9\.9\.9\.tar\.gz"):
        release.verify(sums, [wheel], (public,), complete="packages")
    # The packages are all that "packages" asks for; "all" asks for every file the list names.
    both = [sums.parent / name for name in PACKAGES]
    release.verify(sums, both, (public,), complete="packages")
    with pytest.raises(SystemExit, match=r"images\.json"):
        release.verify(sums, both, (public,), complete="all")


def test_the_list_must_be_signed_with_a_key_built_in(tmp_path: Path) -> None:
    sums, public, _ = signed_release(tmp_path / "release", PACKAGES)
    files = [sums.parent / name for name in PACKAGES]
    other = release.keygen(tmp_path / "other.key")
    with pytest.raises(SystemExit, match="not signed with a key built into this version"):
        release.verify(sums, files, (other,))
    signature = sums.with_name("SHA256SUMS.sig")
    signature.write_text("not base64 !\n", encoding="ascii")
    with pytest.raises(SystemExit, match="not signed with a key built into this version"):
        release.verify(sums, files, (public,))
    signature.unlink()
    with pytest.raises(SystemExit, match="no signature"):
        release.verify(sums, files, (public,))
    # A list changed after it was signed.
    sums2, public2, _ = signed_release(tmp_path / "second", PACKAGES)
    sums2.write_text(sums2.read_text(encoding="ascii") + "0" * 64 + "  qkvm-9.9.9-extra.whl\n", encoding="ascii")
    with pytest.raises(SystemExit, match="not signed with a key built into this version"):
        release.verify(sums2, [sums2.parent / name for name in PACKAGES], (public2,))


def test_a_copy_built_without_a_key_checks_the_checksums_and_says_so(tmp_path: Path) -> None:
    sums, _, _ = signed_release(tmp_path / "release", PACKAGES)
    sums.with_name("SHA256SUMS.sig").unlink()
    said = release.verify(sums, [sums.parent / name for name in PACKAGES], (), complete="packages")
    assert "checksums only" in said


def test_a_list_that_cannot_be_read_exactly_is_refused(tmp_path: Path) -> None:
    folder = tmp_path / "release"
    folder.mkdir()
    wheel = folder / "qkvm-9.9.9-py3-none-any.whl"
    wheel.write_bytes(b"w")
    digest = hashlib.sha256(b"w").hexdigest()
    for text in ("", f"{digest} qkvm-9.9.9-py3-none-any.whl\n", f"{digest.upper()}  qkvm-9.9.9-py3-none-any.whl\n",
                 f"{digest}  dist/qkvm-9.9.9-py3-none-any.whl\n", f"{digest}  qkvm-9.9.9-py3-none-any.whl\n" * 2,
                 f"\\{digest}  qkvm-9.9.9-py3-none-any.whl\n"):
        (folder / "SHA256SUMS").write_text(text, encoding="ascii")
        with pytest.raises(SystemExit):
            release.verify(folder / "SHA256SUMS", [wheel], ())


def test_the_command_is_what_the_workflow_runs(tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    sums, public, _ = signed_release(tmp_path / "release", PACKAGES)
    monkeypatch.setattr(release, "built_in_keys", lambda source=None: (public,))
    files = [str(sums.parent / name) for name in PACKAGES]
    assert release.main(["verify", "--all-packages", str(sums), *files]) == 0
    assert "signed" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        release.main(["verify", "--all-packages", str(sums), files[0]])


def test_the_build_tests_the_installed_wheel_and_the_source_archive_before_anything_is_signed() -> None:
    # (Tried in the job `packages` since the final review, on a copy held to the checksums the build job took right
    # after the build: test_what_is_signed_is_what_was_tested. What it holds here is unchanged: the suite on the wheel
    # installed by itself, the source archive checked, and nothing signed before they passed.)
    every = jobs(RELEASE)
    build = steps(every["packages"])
    text = "\n".join(build)
    assert not re.search(r"^\s*python -m pytest\b", text, flags=re.M), "not the source tree"
    installed = next(index for index, step in enumerate(build) if "/tmp/installed/bin/pip install dist/*.whl" in step)
    suite = [index for index, step in enumerate(build) if "pytest.main(" in step]
    assert len(suite) == 1 and suite[0] > installed
    step = build[suite[0]]
    assert "cd /tmp" in step and "/tmp/installed/bin/python -P -c" in step and "--import-mode=importlib" in step
    assert re.search(r'assert qkvm\.__file__\.startswith\(sys\.prefix \+ "/lib/"\)', step), "the wheel's copy, not the tree's"
    assert '"$GITHUB_WORKSPACE/tests"' in step
    # (check-sdist runs before anything is installed, isolated: test_the_packages_are_checked_before_anything_is_installed.)
    assert len([step for step in build if "check-sdist.py dist/*.whl dist/*.tar.gz" in step]) == 1
    source = [index for index, step in enumerate(build) if "/tmp/from-source/bin/pip install dist/*.tar.gz" in step]
    assert len(source) == 1
    assert re.search(r'test "\$\(/tmp/from-source/bin/qkvm --version\)" = "qkvm \$\{TAG#v\}"', build[source[0]])
    sums = [index for index, step in enumerate(steps(every["build"])) if "> SHA256SUMS" in step]
    assert len(sums) == 1 and "sha256sum -- *.whl *.tar.gz > SHA256SUMS" in steps(every["build"])[sums[0]]
    assert "cp dist/*.whl dist/*.tar.gz release/" in steps(every["build"])[sums[0]]
    signer = next(name for name, job in every.items() if "-m qkvm.release publish" in job)
    assert {"build", "packages"} <= waits_for(every, signer), "signed only after the packages, as checksummed, passed"


def test_pypi_gets_nothing_before_every_file_is_held_to_the_signed_list() -> None:
    # The signature is checked by the publication's first job (no secret there, and so no library installed where
    # PyPI's token is), over every file of the release, with the list required to name exactly this version's files;
    # the PyPI job is handed the hash of that very list and holds both packages to it before the upload.
    every = jobs(RELEASE)
    first = "\n".join(steps(every["published"]))
    assert re.search(r'/usr/bin/python3 -m qkvm\.release verify --all --signed "\$RUNNER_TEMP/published/SHA256SUMS" "\$\{files\[@\]\}"', first)
    assert 'test "$listed" = "qkvm-${TAG#v}-image.json qkvm-${TAG#v}-py3-none-any.whl qkvm-${TAG#v}.tar.gz "' in first, "every package listed goes"
    assert "published" in waits_for(every, "pypi")
    pypi = every["pypi"]
    order = steps(pypi)
    upload = next(index for index, step in enumerate(order) if "uses: pypa/gh-action-pypi-publish@" in step)
    assert re.search(r"^\s*packages-dir:", order[upload], flags=re.M) is None, "it uploads dist/, what was checked"
    checks = [index for index, step in enumerate(order) if "sha256sum --check --strict" in step]
    assert len(checks) == 1 and checks[0] < upload
    check = order[checks[0]]
    assert re.search(r'gh release download "\$TAG"[^\n]*--pattern SHA256SUMS --dir "\$RUNNER_TEMP/signed"', check)
    assert check.index('= "$SUMS"') < check.index('(cd dist && sha256sum --check --strict "$RUNNER_TEMP/packages.sums")')
    assert "pip install" not in "\n".join(order[:upload]), "nothing from PyPI runs before the upload"
    assert re.search(r"^\s*contents: read\b", pypi, flags=re.M) and re.search(r"^\s*id-token: write\b", pypi, flags=re.M)
