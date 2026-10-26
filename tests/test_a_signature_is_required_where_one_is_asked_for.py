"""Where the publication checks a release, a signature is required, whatever keys the checking copy has (review of
web-020-pipe, F4).

`python -m qkvm.release verify` checked the checksums only, and said so, when the copy that runs it has no key built
in: right for a fork that publishes unsigned releases, wrong for the release workflow, where a copy built without a
key (a mistake in qkvm/update.py) would have let an unsigned release out. `--signed` requires a signature checked
with a key built in, and every check the release workflow makes passes it.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from qkvm import release
from tests.workflow_text import WORKFLOWS, uncommented


def signed_release(folder: Path) -> tuple[Path, str]:
    folder.mkdir()
    wheel = folder / "qkvm-9.9.9-py3-none-any.whl"
    wheel.write_bytes(b"the wheel")
    sums = folder / "SHA256SUMS"
    sums.write_text(f"{hashlib.sha256(b'the wheel').hexdigest()}  {wheel.name}\n", encoding="ascii")
    public = release.keygen(folder.parent / "signing.key")
    release.publish(sums, (folder.parent / "signing.key").read_text(encoding="ascii"), (public,))
    return sums, public


def test_without_a_key_built_in_a_signature_that_is_asked_for_is_not_there_to_check(tmp_path: Path) -> None:
    sums, public = signed_release(tmp_path / "release")
    files = [sums.parent / "qkvm-9.9.9-py3-none-any.whl"]
    assert "checksums only" in release.verify(sums, files, ())  # (a fork's unsigned release, as before)
    with pytest.raises(SystemExit, match="no key built in"):
        release.verify(sums, files, (), signed=True)
    assert "signed" in release.verify(sums, files, (public,), signed=True)
    sums.with_name("SHA256SUMS.sig").unlink()
    with pytest.raises(SystemExit, match="no signature"):
        release.verify(sums, files, (public,), signed=True)


def test_the_command_takes_the_flag_with_the_others(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    sums, public = signed_release(tmp_path / "release")
    wheel = str(sums.parent / "qkvm-9.9.9-py3-none-any.whl")
    monkeypatch.setattr(release, "built_in_keys", lambda source=None: ())
    with pytest.raises(SystemExit, match="no key built in"):
        release.main(["verify", "--signed", "--all", str(sums), wheel])
    assert release.main(["verify", "--all", str(sums), wheel]) == 0
    monkeypatch.setattr(release, "built_in_keys", lambda source=None: (public,))
    assert release.main(["verify", "--all", "--signed", str(sums), wheel]) == 0
    assert release.main(["verify", "--signed", "--all-packages", str(sums), wheel]) == 0
    capsys.readouterr()
    assert release.main(["verify", "--sgned", str(sums), wheel]) == 2  # (a flag misspelt is no check passed)
    assert release.main(["verify", "--all", "--all-packages", str(sums), wheel]) == 2


def test_every_check_the_release_workflow_makes_requires_the_signature() -> None:
    text = uncommented((WORKFLOWS / "release.yml").read_text(encoding="utf-8"))
    calls = re.findall(r"-m qkvm\.release verify\b[^\n]*", text)
    assert calls, "the workflow checks what it publishes"
    for call in calls:
        assert re.match(r"-m qkvm\.release verify(?: --all(?:-packages)?)? --signed\b|-m qkvm\.release verify --signed\b", call), call
