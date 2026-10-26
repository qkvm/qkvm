"""The image job names its tags before any login, and runs nothing it does not need while credentials are there
(final review of web-020-pipe, 4).

The image job set up BuildKit (a privileged container that stayed up through the logins and the pushes) and ran
metadata-action after the logins, though `docker buildx imagetools create` needs no builder and three tag names need a
few lines of shell. Now the job checks that the runner's docker has buildx, names the tags in plain shell before the
first login, and has neither setup-buildx nor metadata-action.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.workflow_text import WORKFLOWS, jobs, steps

RELEASE = WORKFLOWS / "release.yml"


def image_steps() -> list[str]:
    return steps(jobs(RELEASE)["image"])


def test_nothing_the_push_does_not_need_runs_in_the_image_job() -> None:
    text = "\n".join(image_steps())
    assert "docker/setup-buildx-action@" not in text, "imagetools create needs no builder"
    assert "docker/metadata-action@" not in text, "three tag names need no action"
    assert "docker buildx imagetools create" in text


def test_the_tags_are_named_before_the_first_login() -> None:
    order = image_steps()
    checked = next(index for index, step in enumerate(order) if "docker buildx version > /dev/null" in step)
    newest = next(index for index, step in enumerate(order) if step.startswith("id: newest\n"))
    names = next(index for index, step in enumerate(order) if step.startswith("id: names\n"))
    login = next(index for index, step in enumerate(order) if "docker/login-action@" in step)
    push = next(index for index, step in enumerate(order) if "imagetools create" in step)
    assert checked < newest < names < login < push
    assert "uses:" not in order[names], "plain shell, no action of others' code"
    assert all("docker/login-action@" not in step and "secrets." not in step for step in order[:login]), "no credential before"


def a_bash() -> str | None:
    for candidate in (r"C:\Program Files\Git\bin\bash.exe", "/bin/bash", shutil.which("bash")):
        if candidate and Path(candidate).is_file():
            try:
                if subprocess.run([candidate, "-c", "echo ok"], capture_output=True, text=True, timeout=30).stdout.strip() == "ok":
                    return candidate
            except (OSError, subprocess.SubprocessError):
                continue
    return None


BASH = a_bash()


def named(tag: str, images: str, minor: str, latest: str, tmp_path: Path) -> list[str]:
    step = next(item for item in image_steps() if item.startswith("id: names\n"))
    script = step[step.index("run: |\n") + len("run: |\n") :]
    script = "\n".join(line[10:] if line.startswith(" " * 10) else line for line in script.splitlines())
    output = tmp_path / "output"
    output.write_text("", encoding="utf-8")
    environment = {**os.environ, "TAG": tag, "IMAGES": images, "MINOR": minor, "LATEST": latest, "GITHUB_OUTPUT": str(output)}
    assert BASH
    done = subprocess.run([BASH, "-c", script], env=environment, capture_output=True, text=True, timeout=60)
    if done.returncode:
        raise AssertionError(done.stderr)
    text = output.read_text(encoding="utf-8")
    assert text.startswith("tags<<END\n") and text.endswith("END\n"), text
    return text.splitlines()[1:-1]


@pytest.mark.skipif(BASH is None, reason="no bash here")
def test_the_names_are_the_version_and_only_the_moving_tags_it_may_take(tmp_path: Path) -> None:
    images = "ghcr.io/owner/wall\ndocker.io/owner/wall"
    assert named("v1.2.3", images, "true", "true", tmp_path) == [
        "ghcr.io/owner/wall:1.2.3", "ghcr.io/owner/wall:1.2", "ghcr.io/owner/wall:latest",
        "docker.io/owner/wall:1.2.3", "docker.io/owner/wall:1.2", "docker.io/owner/wall:latest",
    ]
    assert named("v0.2.1", "ghcr.io/owner/wall", "true", "false", tmp_path) == ["ghcr.io/owner/wall:0.2.1", "ghcr.io/owner/wall:0.2"]
    assert named("v0.2.1", "ghcr.io/owner/wall", "false", "false", tmp_path) == ["ghcr.io/owner/wall:0.2.1"]
    for tag, minor, latest in (("v0.2", "true", "true"), ("v0.2.1", "yes", "true"), ("v0.2.1", "true", "")):
        with pytest.raises(AssertionError):
            named(tag, "ghcr.io/owner/wall", minor, latest, tmp_path)
