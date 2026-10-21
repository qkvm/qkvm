"""Atomic settings writes tolerate brief Windows readers and keep permanent failures visible."""

from __future__ import annotations

import errno
import json
import os
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from qkvm import store


class Clock:
    def __init__(self) -> None:
        self.now = 0.0
        self.waits: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.waits.append(seconds)
        self.now += seconds


def blocked(winerror: int | None = 5) -> OSError:
    error = OSError(errno.EACCES, "replacement blocked")
    if winerror is not None:
        error.winerror = winerror
    return error


def saved(tmp_path: Path) -> tuple[store.Store, bytes, dict[str, Any]]:
    settings = store.Store(tmp_path / "qkvm.json")
    settings.save()
    before = settings.path.read_bytes()
    changed = settings.snapshot()
    changed["a_change"] = "kept in both copies"
    return settings, before, changed


def windows(monkeypatch: pytest.MonkeyPatch) -> Clock:
    clock = Clock()
    # Replace these module references only, without changing pytest's own clock or platform.
    monkeypatch.setattr(store, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(store, "time", clock)
    return clock


@pytest.mark.parametrize("winerror", [5, 32, 33])
@pytest.mark.parametrize("which", ["path", "backup"])
def test_brief_windows_replacement_failure_preserves_old_file_until_atomic_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, winerror: int, which: str,
) -> None:
    settings, before, changed = saved(tmp_path)
    destination = getattr(settings, which)
    replace = os.replace
    clock = windows(monkeypatch)
    attempts = 0

    def sometimes(source: Path, target: Path) -> None:
        nonlocal attempts
        if target == destination:
            attempts += 1
            assert target.read_bytes() == before
            assert json.loads(source.read_text()) == changed
            if attempts <= 2:
                raise blocked(winerror)
        replace(source, target)

    monkeypatch.setattr(store.os, "replace", sometimes)
    settings.write(changed)
    assert attempts == 3 and len(clock.waits) == 2
    assert json.loads(settings.path.read_text()) == changed
    assert settings.backup.read_bytes() == settings.path.read_bytes()
    assert not settings.backup_is_old
    assert not settings.path.with_suffix(".tmp").exists()
    assert not settings.backup.with_name("qkvm.bak.new").exists()


def test_permanent_windows_failure_is_bounded_and_leaves_both_old_copies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings, before, changed = saved(tmp_path)
    clock = windows(monkeypatch)
    failures: list[OSError] = []

    def denied(source: Path, target: Path) -> None:
        assert target == settings.path
        assert target.read_bytes() == before
        failure = blocked()
        failures.append(failure)
        raise failure

    monkeypatch.setattr(store.os, "replace", denied)
    with pytest.raises(OSError) as caught:
        settings.write(changed)
    assert caught.value is failures[-1]
    assert 1 < len(failures) <= 8
    assert len(clock.waits) == len(failures) - 1
    assert 0 < sum(clock.waits) <= 0.4
    assert settings.path.read_bytes() == settings.backup.read_bytes() == before


@pytest.mark.parametrize("platform,winerror", [("linux", 5), ("win32", None), ("win32", 2), ("win32", 3), ("win32", 112)])
def test_unrelated_replacement_errors_propagate_without_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str, winerror: int | None,
) -> None:
    settings, before, changed = saved(tmp_path)
    clock = windows(monkeypatch)
    monkeypatch.setattr(store, "sys", SimpleNamespace(platform=platform))
    failure = blocked(winerror)
    attempts = 0

    def denied(source: Path, target: Path) -> None:
        nonlocal attempts
        attempts += 1
        raise failure

    monkeypatch.setattr(store.os, "replace", denied)
    with pytest.raises(OSError) as caught:
        settings.write(changed)
    assert caught.value is failure and attempts == 1 and not clock.waits
    assert settings.path.read_bytes() == settings.backup.read_bytes() == before


def test_a_slow_failed_replace_does_not_start_another_retry_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings, before, changed = saved(tmp_path)
    clock = windows(monkeypatch)
    attempts = 0

    def denied(source: Path, target: Path) -> None:
        nonlocal attempts
        attempts += 1
        clock.now += 1.0
        raise blocked()

    monkeypatch.setattr(store.os, "replace", denied)
    with pytest.raises(OSError):
        settings.write(changed)
    assert attempts == 1 and not clock.waits
    assert settings.path.read_bytes() == settings.backup.read_bytes() == before


@pytest.mark.parametrize("cannot_remove", [False, True])
def test_exhausted_backup_retry_keeps_new_primary_and_does_not_silently_keep_old_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cannot_remove: bool,
) -> None:
    settings, before, changed = saved(tmp_path)
    clock = windows(monkeypatch)
    replace, unlink = os.replace, os.unlink
    attempts = 0

    def denied(source: Path, target: Path) -> None:
        nonlocal attempts
        if target == settings.backup:
            attempts += 1
            raise blocked(32)
        replace(source, target)

    def remove(path: Path) -> None:
        if path == settings.backup and cannot_remove:
            raise blocked()
        unlink(path)

    monkeypatch.setattr(store.os, "replace", denied)
    monkeypatch.setattr(store.os, "unlink", remove)
    settings.write(changed)
    assert 1 < attempts <= 8 and 0 < sum(clock.waits) <= 0.4
    assert json.loads(settings.path.read_text()) == changed
    assert settings.backup_is_old == cannot_remove
    if cannot_remove:
        assert settings.backup.read_bytes() == before
    else:
        assert not settings.backup.exists()
    assert not settings.backup.with_name("qkvm.bak.new").exists()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows readers can deny delete sharing")
def test_a_real_windows_reader_can_finish_before_atomic_settings_replacement_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings, before, changed = saved(tmp_path)
    opened, denied, released = threading.Event(), threading.Event(), threading.Event()
    errors: list[BaseException] = []
    failures: list[OSError] = []
    replace = os.replace

    def reader() -> None:
        try:
            with settings.path.open("rb") as handle:
                opened.set()
                assert denied.wait(5), "the writer did not try replacement"
                assert handle.read() == before
        except BaseException as error:
            errors.append(error)
        finally:
            released.set()

    def observed(source: Path, target: Path) -> None:
        try:
            replace(source, target)
        except OSError as error:
            if target == settings.path:
                failures.append(error)
                denied.set()
                assert released.wait(5), "the reader did not finish"
            raise

    thread = threading.Thread(target=reader)
    thread.start()
    try:
        assert opened.wait(5), "the reader did not open the file"
        monkeypatch.setattr(store.os, "replace", observed)
        settings.write(changed)
    finally:
        denied.set()
        thread.join(5)
    assert not thread.is_alive() and not errors
    assert failures and all(error.winerror in (5, 32, 33) for error in failures)
    assert json.loads(settings.path.read_text()) == changed
    assert settings.backup.read_bytes() == settings.path.read_bytes()
