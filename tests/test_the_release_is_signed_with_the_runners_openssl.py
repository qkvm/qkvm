"""The release is signed with the runner's own openssl, and nothing is installed beside the signing key (review of
web-020-pipe, the draft job).

The draft job, where RELEASE_SIGNING_KEY is, ran `sudo apt-get install python3-cryptography` when the runner's Python
lacked the library: a package, of whatever version the mirror had, installed as root beside the key. Now
`python -m qkvm.release publish --openssl` signs with the openssl command the runner has (Ed25519, as qkvm.release
signs: deterministic, so the very bytes the cryptography library makes), checks first that openssl gives RFC 8032's
own signature for RFC 8032's own key and refuses with a plain message where it does not, and the draft's read-back
checks with openssl too. qkvm/release.py loads the cryptography library only where it uses it, so that this runs
where the library is not.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from qkvm import release, update
from tests.workflow_text import APP, WORKFLOWS, jobs, steps


def openssl_here() -> str | None:
    for candidate in (shutil.which("openssl"), r"C:\Program Files\Git\usr\bin\openssl.exe", r"C:\Program Files\Git\mingw64\bin\openssl.exe"):
        if candidate and Path(candidate).is_file():
            return candidate
    return None


OPENSSL = openssl_here()
needs_openssl = pytest.mark.skipif(OPENSSL is None, reason="no openssl command on this machine")


def a_release(folder: Path) -> tuple[Path, list[Path], str, str]:
    """SHA256SUMS of two packages, and a signing key as `qkvm.release keygen` writes it (what the secret holds)."""
    folder.mkdir()
    files = []
    for name, data in (("qkvm-9.9.9-py3-none-any.whl", b"the wheel"), ("qkvm-9.9.9.tar.gz", b"the source")):
        (folder / name).write_bytes(data)
        files.append(folder / name)
    sums = folder / "SHA256SUMS"
    sums.write_text("".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in files), encoding="ascii")
    public = release.keygen(folder.parent / f"{folder.name}.key")
    return sums, files, public, (folder.parent / f"{folder.name}.key").read_text(encoding="ascii")


@needs_openssl
def test_openssl_signs_the_very_bytes_qkvm_and_every_copy_take(tmp_path: Path) -> None:
    sums, files, public, key = a_release(tmp_path / "release")
    said = release.publish(sums, key, (public,), openssl=release.OpenSSL(OPENSSL))
    assert "openssl" in said
    signature = sums.with_name("SHA256SUMS.sig").read_bytes()
    assert signature == (release.sign(key, sums.read_bytes()) + "\n").encode("ascii"), "Ed25519 is deterministic: the same bytes"
    assert "signed" in release.verify(sums, files, (public,), complete="all", signed=True)  # the cryptography library's check
    update.verify_signature(sums.read_bytes(), signature, (public,))  # what every installed copy checks
    assert "signed" in release.verify(sums, files, (public,), complete="all", signed=True, openssl=release.OpenSSL(OPENSSL))


@needs_openssl
def test_the_openssl_check_refuses_what_is_not_signed_by_a_key_built_in(tmp_path: Path) -> None:
    sums, files, public, key = a_release(tmp_path / "release")
    other = release.keygen(tmp_path / "other.key")
    with pytest.raises(SystemExit, match="not one of the keys"):
        release.publish(sums, key, (other,), openssl=release.OpenSSL(OPENSSL))
    release.publish(sums, key, (public,), openssl=release.OpenSSL(OPENSSL))
    with pytest.raises(SystemExit, match="not signed with a key built into this version"):
        release.verify(sums, files, (other,), signed=True, openssl=release.OpenSSL(OPENSSL))
    sums.write_text(sums.read_text(encoding="ascii").replace("qkvm-9.9.9.tar.gz", "qkvm-9.9.8.tar.gz"), encoding="ascii")
    with pytest.raises(SystemExit, match="not signed with a key built into this version"):
        release.verify(sums, files[:1], (public,), signed=True, openssl=release.OpenSSL(OPENSSL))
    with pytest.raises(SystemExit, match="no signing key"):
        release.publish(sums, "", (public,), openssl=release.OpenSSL(OPENSSL))


def test_the_check_openssl_must_pass_is_rfc_8032s_own() -> None:
    # (Held against the cryptography library here, so that a wrong digit in the constants is found at once.)
    assert release.library_public(release.RFC8032_SECRET) == release.RFC8032_PUBLIC
    assert release.library_sign(release.RFC8032_SECRET, release.RFC8032_MESSAGE) == release.RFC8032_SIGNATURE


def test_on_linux_the_openssl_is_the_systems_own_whatever_the_path_says() -> None:
    # (Second review: an openssl taken from PATH is whatever lies first on it; the runner's own is /usr/bin/openssl.)
    assert release.default_openssl("posix") == "/usr/bin/openssl"
    assert release.default_openssl("nt") == shutil.which("openssl")


def test_an_openssl_that_cannot_do_it_is_refused_plainly(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="No openssl command"):
        release.OpenSSL(str(tmp_path / "no-openssl-here"))
    # A program that runs, and is no openssl (here Python itself): the check with RFC 8032's key fails, and says so.
    with pytest.raises(SystemExit, match="openssl"):
        release.OpenSSL(sys.executable)


@needs_openssl
def test_it_signs_where_the_cryptography_library_cannot_be_loaded(tmp_path: Path) -> None:
    sums, files, public, key = a_release(tmp_path / "release")
    blocked = (
        "import sys; sys.modules['cryptography'] = None; from qkvm import release; "
        f"release.built_in_keys = lambda source=None: ({public!r},); "
        "raise SystemExit(release.main(sys.argv[1:]))"
    )
    environment = {**os.environ, "RELEASE_SIGNING_KEY": key, "PATH": str(Path(OPENSSL).parent) + os.pathsep + os.environ.get("PATH", "")}
    done = subprocess.run([sys.executable, "-c", blocked, "publish", "--openssl", str(sums)], cwd=APP, env=environment, capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stdout + done.stderr
    done = subprocess.run([sys.executable, "-c", blocked, "verify", "--all", "--signed", "--openssl", str(sums), *map(str, files)],
                          cwd=APP, env=environment, capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stdout + done.stderr
    update.verify_signature(sums.read_bytes(), sums.with_name("SHA256SUMS.sig").read_bytes(), (public,))
    assert sums.with_name("SHA256SUMS.sig").read_bytes() == (release.sign(key, sums.read_bytes()) + "\n").encode("ascii")
    assert len(base64.b64decode(public)) == 32


def test_the_draft_job_installs_nothing_and_signs_with_openssl() -> None:
    # (The key's job is `sign`; the job that makes the draft has no key, and installs nothing either.)
    every = jobs(WORKFLOWS / "release.yml")
    signing, draft = steps(every["sign"]), steps(every["draft"])
    text = "\n".join(signing + draft)
    for forbidden in ("apt-get", "apt ", "pip install", "pip3 install", "import cryptography"):
        assert forbidden not in text, forbidden
    sign = next(step for step in signing if "RELEASE_SIGNING_KEY: ${{ secrets.RELEASE_SIGNING_KEY }}" in step)
    assert re.search(r"^\s*run: /usr/bin/python3 -m qkvm\.release publish --openssl release/SHA256SUMS$", sign, flags=re.M), sign
    assert re.search(r'/usr/bin/python3 -m qkvm\.release verify --all --signed --openssl "\$drafted/SHA256SUMS" "\$\{files\[@\]\}"', text)
    calls = re.findall(r"-m qkvm\.release (?:publish|verify)\b[^\n]*", text)
    assert calls and all("--openssl" in call for call in calls), calls
