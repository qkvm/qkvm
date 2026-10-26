"""The signature openssl makes is checked by another implementation before any draft exists (second review of
web-020-pipe).

The job that holds the key signs with the runner's openssl and checked the result with that same openssl: an openssl
that is wrong but agrees with itself would make a draft, and once published an immutable release, that no installed
copy takes (they check with the cryptography library). Now the tag's run signs in a job of its own (`sign`, the only
one with the key, which makes no release), checks the signature with the cryptography library in a job with no
secret (`signature`), and only then makes the draft (`draft`, which has no key), whose files are held byte for byte
to what was checked.
"""
from __future__ import annotations

import re

from tests.workflow_text import WORKFLOWS, jobs, steps, waits_for

RELEASE = WORKFLOWS / "release.yml"


def test_the_key_is_used_in_a_job_that_only_signs() -> None:
    every = jobs(RELEASE)
    holders = {name for name, job in every.items() if "secrets.RELEASE_SIGNING_KEY" in job}
    assert holders == {"sign"}
    sign = every["sign"]
    assert re.search(r"^    environment: release\b", sign, flags=re.M)
    assert "gh release" not in sign, "no release is made where the key is"
    assert re.search(r"^    permissions:\n      contents: read\n", sign, flags=re.M), "nothing to write with"
    text = "\n".join(steps(sign))
    assert "/usr/bin/python3 -m qkvm.release publish --openssl release/SHA256SUMS" in text
    upload = next(step for step in steps(sign) if "actions/upload-artifact@" in step)
    assert "name: signed" in upload and "path: release/" in upload


def test_another_implementation_checks_the_signature_before_any_draft_exists() -> None:
    every = jobs(RELEASE)
    signature = every["signature"]
    assert "sign" in waits_for(every, "signature")
    assert "environment:" not in signature and "secrets." not in signature
    text = "\n".join(steps(signature))
    assert "name: signed" in text and "path: signed/" in text
    check = re.search(r'/usr/bin/python3 -m qkvm\.release verify --all --signed signed/SHA256SUMS "\$\{files\[@\]\}"', text)
    assert check and "--openssl" not in check.group(0), "the cryptography library, not openssl again"
    draft = every["draft"]
    assert {"sign", "signature"} <= waits_for(every, "draft")
    assert "environment:" not in draft and "secrets." not in draft, "the draft is made where no key is"
    order = steps(draft)
    fetched = next(step for step in order if "actions/download-artifact@" in step)
    assert "name: signed" in fetched and "path: release/" in fetched
    made = "\n".join(order)
    for name in ("SHA256SUMS", "SHA256SUMS.sig"):
        assert f'cmp "$drafted/{name}" release/{name}' in made, f"the draft holds the {name} that was checked"
