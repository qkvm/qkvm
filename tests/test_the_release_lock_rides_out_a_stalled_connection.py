"""The release's lock is made from PyPI's listings and wheels (.github/security/make-libraries.py), dozens of lookups and
downloads one after the other: one connection that stalls must not end the release's job.

(Before the release of 0.3.0, run here as the job runs it: pip's resolution for every target went through, and then a
TLS handshake with PyPI timed out in the listings, twice in three runs, while a single lookup took 0.06 s.)
"""

from __future__ import annotations

import importlib.util
import io
import json
import urllib.error
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / ".github" / "security" / "make-libraries.py"


def the_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("make_libraries", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Reply(io.BytesIO):
    def __enter__(self) -> Reply:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


def answering(*answers: Any) -> tuple[list[str], Any]:
    asked: list[str] = []
    left = list(answers)

    def urlopen(url: str, timeout: float) -> Reply:
        asked.append(url)
        answer = left.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return Reply(answer)

    return asked, urlopen


LISTED = json.dumps({"urls": [{"filename": "pip-26.0.1-py3-none-any.whl"}]}).encode()
STALLED = urllib.error.URLError(TimeoutError("_ssl.c:1015: The handshake operation timed out"))


def test_a_lookup_that_stalls_is_asked_again_after_a_pause(monkeypatch: pytest.MonkeyPatch) -> None:
    script = the_script()
    asked, urlopen = answering(STALLED, ConnectionResetError(104, "Connection reset by peer"), LISTED)
    paused: list[float] = []
    monkeypatch.setattr(script.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(script.time, "sleep", paused.append)
    assert script.listing("pip", "26.0.1") == [{"filename": "pip-26.0.1-py3-none-any.whl"}]
    assert asked == ["https://pypi.org/pypi/pip/26.0.1/json"] * 3 and len(paused) == 2 and all(pause > 0 for pause in paused)


def test_a_download_that_stalls_is_fetched_again_and_one_that_is_not_there_is_not(monkeypatch: pytest.MonkeyPatch) -> None:
    script = the_script()
    asked, urlopen = answering(STALLED, b"the wheel")
    monkeypatch.setattr(script.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(script.time, "sleep", lambda _: None)
    assert script.fetched("https://files.pythonhosted.org/packages/x.whl", 300) == b"the wheel" and len(asked) == 2
    # Not there, or refused: said at once, never asked again (PyPI does not change its mind about a 404).
    gone = urllib.error.HTTPError("https://pypi.org/pypi/nothing/1/json", 404, "Not Found", None, None)  # type: ignore[arg-type]
    asked, urlopen = answering(gone, LISTED)
    monkeypatch.setattr(script.urllib.request, "urlopen", urlopen)
    with pytest.raises(urllib.error.HTTPError):
        script.listing("nothing", "1")
    assert len(asked) == 1


def test_a_connection_that_never_comes_ends_the_job_after_a_few_tries(monkeypatch: pytest.MonkeyPatch) -> None:
    script = the_script()
    asked, urlopen = answering(*([STALLED] * 10))
    monkeypatch.setattr(script.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(script.time, "sleep", lambda _: None)
    with pytest.raises(urllib.error.URLError):
        script.listing("pip", "26.0.1")
    assert len(asked) == script.TRIES == 4
