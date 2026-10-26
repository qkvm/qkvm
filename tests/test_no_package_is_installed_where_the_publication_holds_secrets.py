"""The jobs that publish install nothing: the signature is checked where no secret is, and they are handed what was
checked (review of web-020-pipe, F5).

`pypi` (a token PyPI takes) and `image` (the registries' credentials, write access to packages) checked the signature
themselves, and so ran `sudo apt-get install python3-cryptography` where it was missing: a package, of whatever version
the mirror had, installed as root in a job holding those secrets; `image` installed skopeo the same way. Now the
publication's first job, with no secret, checks the signature and hands on the SHA-256 of the SHA256SUMS it checked
(and the run that keeps the archives); each publishing job takes SHA256SUMS from the published release again, requires
that very hash, and holds its files to it with sha256sum. Neither installs anything or runs code that would need it.
"""
from __future__ import annotations

import re

from tests.workflow_text import WORKFLOWS, jobs, steps

RELEASE = WORKFLOWS / "release.yml"
PUBLISHING = ("image", "pypi")


def test_the_publishing_jobs_install_nothing() -> None:
    every = jobs(RELEASE)
    for name in PUBLISHING:
        text = "\n".join(steps(every[name]))
        for forbidden in ("apt-get", "apt ", "pip install", "pip3 install", "qkvm.release", "import cryptography"):
            assert forbidden not in text, f"{name}: {forbidden}"
    image = "\n".join(steps(every["image"]))
    assert re.search(r"command -v skopeo > /dev/null \|\| \{ echo [^\n]*; exit 1; \}", image), "the runner's own, or no image"


def test_the_first_job_hands_on_the_hash_of_the_list_it_checked() -> None:
    first = jobs(RELEASE)["published"]
    assert re.search(r"^      sums: \$\{\{ steps\.checked\.outputs\.sums \}\}$", first, flags=re.M)
    step = next(item for item in steps(first) if item.startswith("id: checked\n"))
    verified = step.index("-m qkvm.release verify --all --signed")
    # (Into a variable first, checked, then written: test_every_hash_handed_on_fails_its_step_on_a_missing_file.)
    taken = re.search(r'sums=\$\(sha256sum "\$RUNNER_TEMP/published/SHA256SUMS" \| cut -d \' \' -f 1\)\n', step)
    handed = re.search(r'echo "sums=\$sums" >> "\$GITHUB_OUTPUT"', step)
    assert taken and handed and verified < taken.start() < handed.start()


def test_each_publishing_job_holds_its_files_to_that_very_list() -> None:
    every = jobs(RELEASE)
    for name in PUBLISHING:
        assert "published" in every[name].split("needs:", 1)[1].split("\n", 1)[0], name
        text = "\n".join(steps(every[name]))
        assert "SUMS: ${{ needs.published.outputs.sums }}" in text, name
        assert '[[ "$SUMS" =~ ^[0-9a-f]{64}$ ]]' in text, name
        assert 'test "$(sha256sum "$RUNNER_TEMP/signed/SHA256SUMS" | cut -d \' \' -f 1)" = "$SUMS"' in text, name
    pypi = steps(every["pypi"])
    upload = next(index for index, step in enumerate(pypi) if "uses: pypa/gh-action-pypi-publish@" in step)
    check = next(index for index, step in enumerate(pypi) if "sha256sum --check --strict" in step)
    assert check < upload
    step = pypi[check]
    assert re.search(r"""awk -v wheel="qkvm-\$\{TAG#v\}-py3-none-any\.whl" -v source="qkvm-\$\{TAG#v\}\.tar\.gz" '\$2 == wheel \|\| \$2 == source' "\$RUNNER_TEMP/signed/SHA256SUMS" > "\$RUNNER_TEMP/packages\.sums\"""", step)
    assert 'test "$(wc -l < "$RUNNER_TEMP/packages.sums")" -eq 2' in step
    assert '(cd dist && sha256sum --check --strict "$RUNNER_TEMP/packages.sums")' in step
    image = steps(every["image"])
    record = next(index for index, step in enumerate(image) if "image-digests.py from-release" in step)
    step = image[record]
    assert step.index("sha256sum --check --strict") < step.index("image-digests.py from-release")
    assert 'test "$run" = "$RUN"' in step and "RUN: ${{ needs.published.outputs.run }}" in step
    fetched = next(index for index, item in enumerate(image) if "actions/download-artifact@" in item)
    assert fetched > record and "run-id: ${{ needs.published.outputs.run }}" in image[fetched]
