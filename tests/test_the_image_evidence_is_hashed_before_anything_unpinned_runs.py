"""The image evidence is hashed before anything unpinned runs on the image runner, and the test tools are pinned
(fresh review of web-020-pipe, 1).

The image jobs ran `python3 -m pip install --target ... pytest`, unpinned, on the runner (where sudo needs no password)
after the scan and the native step and before the job's hashes were taken: a release of pytest or of what it needs
that came as a source archive only would have run its setup.py there and could have rewritten image.tar,
scanned-image.json, trivy.json and native-versions.json consistently, and the hashes would then have vouched for the
forgery. Now both: the hashes are taken inside the shared action right after the native step, before the suite's
tools are installed, and handed on as the action's outputs; and those tools are installed only as wheels pinned by
hash (image-test-requirements.txt), so that installing them runs no code of theirs.
"""
from __future__ import annotations

import re

from tests.workflow_text import SECURITY, WORKFLOWS, jobs, steps, uncommented

ACTION = SECURITY / "action.yml"


def action_steps() -> list[str]:
    return steps(uncommented(ACTION.read_text(encoding="utf-8")))


def test_the_hashes_are_taken_right_after_the_native_step_before_any_install() -> None:
    order = action_steps()
    native = next(index for index, step in enumerate(order) if "native-versions.py" in step)
    hashes = next(index for index, step in enumerate(order) if step.startswith("id: hashes\n"))
    installs = [index for index, step in enumerate(order) if "pip install" in step]
    assert hashes == native + 1 and installs and all(index > hashes for index in installs)
    text = ACTION.read_text(encoding="utf-8")
    for output in ("archive", "scan", "native"):
        assert re.search(rf"^  {output}:\n    description: [^\n]+\n    value: \$\{{\{{ steps\.hashes\.outputs\.{output} \}}\}}$", text, flags=re.M), output


def test_the_action_says_what_was_installed_before_the_hashes() -> None:
    # (delta-g review, a nit) skopeo is installed, from Ubuntu's own archive, before the build: the hashes are taken
    # before the suite's test tools are installed, not "before anything is installed here".
    order = action_steps()
    hashes = next(index for index, step in enumerate(order) if step.startswith("id: hashes\n"))
    skopeo = next(index for index, step in enumerate(order) if "apt-get install" in step and "skopeo" in step)
    assert skopeo < hashes
    assert "name: The hashes of the archive and its evidence, before the suite's test tools are installed\n" in order[hashes]
    text = " ".join(ACTION.read_text(encoding="utf-8").replace("#", " ").split())
    assert "before anything is installed here" not in text and "before anything the action installs" not in text
    assert "until then it has installed only skopeo, from Ubuntu's own archive" in text


def test_the_test_tools_are_installed_as_pinned_wheels_only() -> None:
    for step in action_steps():
        for install in re.findall(r"pip install[^\n]*", step):
            assert install == ('pip install --require-hashes --no-deps --only-binary :all: --target "$RUNNER_TEMP/qkvm-image-test-deps" '
                               "-r .github/security/image-test-requirements.txt"), install
    names = set()
    for line in (SECURITY / "image-test-requirements.txt").read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            found = re.fullmatch(r"([A-Za-z0-9_.-]+)==([0-9][0-9A-Za-z.]*) --hash=sha256:[0-9a-f]{64}", line)
            assert found, line
            names.add(found.group(1).lower())
    assert names == {"pytest", "iniconfig", "packaging", "pluggy", "pygments"}


def test_the_image_jobs_hand_on_the_actions_hashes() -> None:
    every = jobs(WORKFLOWS / "release.yml")
    for arch in ("amd64", "arm64"):
        job = every[f"images_{arch}"]
        for output in ("archive", "scan", "native"):
            assert f"      {output}: ${{{{ steps.image.outputs.{output} }}}}\n" in job, (arch, output)
        order = steps(job)
        assert any(step.startswith("id: image\n") and "uses: ./.github/security" in step for step in order)
        assert not any(step.startswith("id: hashes\n") for step in order), "taken in the action, before the suite's install"


def test_the_notes_say_who_writes_a_job_output() -> None:
    for path in (WORKFLOWS / "release.yml", SECURITY / "README.md"):
        text = " ".join(path.read_text(encoding="utf-8").replace("#", " ").split())
        assert "no job's code can write" not in text, path.name
        assert "written only by the job that made the artifact" in text, path.name
