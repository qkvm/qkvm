"""The native code that comes inside the image's wheels and its Python is recorded and gated (the review of 850745e, W5).

The scanner reads Debian package records and Python package metadata. FFmpeg and its codecs in PyAV, libsrtp and the
OpenSSL linked into pylibsrtp, the OpenSSL in cryptography, and the CPython the base image builds from source are in
neither, so the image's "0 CRITICAL / 0 HIGH" said nothing of them: an FFmpeg with a published hole would have passed.

Now each image is asked, inside itself and without a network, what each of them is (native-versions.py: each library's
own version function); the answers are kept with the scan's evidence of the release, and check-native-versions.py fails
the image below the minimum kept for each in native-minimums.json, with the reason for each. test-native-versions.py
tries the gate.
"""
from __future__ import annotations

import json
import re

from tests.workflow_text import SECURITY, steps, uncommented


def action_steps() -> list[str]:
    return steps(uncommented((SECURITY / "action.yml").read_text(encoding="utf-8")))


def test_every_image_is_asked_inside_itself_and_gated_before_it_can_be_published() -> None:
    every = action_steps()
    gate = [index for index, step in enumerate(every) if "check-native-versions.py" in step]
    assert len(gate) == 1
    step = every[gate[0]]
    asked = re.search(
        r"docker run --rm --pull=never --platform \"linux/\$ARCH\" -i --network none\s*\\?\s*"
        r"--read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true\s*\\?\s*"
        r"--entrypoint python qkvm:security -P -s - < \.github/security/native-versions\.py > \"image-\$ARCH/evidence/native-versions\.json\"",
        step,
    )
    assert asked, step
    judged = re.search(
        r"python3 \.github/security/check-native-versions\.py \"image-\$ARCH/evidence/native-versions\.json\"\s*\\?\s*"
        r"--minimums \.github/security/native-minimums\.json --arch \"\$ARCH\" \| tee \"image-\$ARCH/evidence/native-policy\.txt\"",
        step,
    )
    assert judged and judged.start() > asked.start(), step
    scan = next(index for index, item in enumerate(every) if "scan-image.sh" in item)
    marked = next(index for index, item in enumerate(every) if "sha256sum image.tar > SHA256SUMS" in item)
    kept = next(index for index, item in enumerate(every) if "path: image-${{ inputs.arch }}/evidence/" in item)
    assert scan < gate[0] < marked, "after the scan made the evidence folder, before the archive is marked for release"
    assert "if: always()" in every[kept], "kept with the scan's evidence of the release, passed or not"


def test_every_minimum_has_its_reason_and_says_where_the_library_comes_from() -> None:
    minimums = json.loads((SECURITY / "native-minimums.json").read_text(encoding="utf-8"))
    assert minimums["schema"] == 1
    assert set(minimums["components"]) == {
        "cpython", "ffmpeg", "libvpx", "libopus", "libdav1d", "cryptography-openssl", "pylibsrtp-libsrtp", "pylibsrtp-openssl",
    }
    for name, entry in minimums["components"].items():
        assert set(entry) == {"minimum", "source", "reason"}, name
        assert re.fullmatch(r"\d+(\.\d+)+", entry["minimum"]), name
        assert len(entry["reason"]) > 40 and len(entry["source"]) > 10, name


def test_the_advisories_say_what_is_now_recorded_and_gated() -> None:
    text = (SECURITY / "CONTAINER-ADVISORIES.md").read_text(encoding="utf-8")
    paragraph = text[text.index("What the scan cannot see:") :].split("\n\n", 1)[0]
    for part in ("native-versions.json", "native-minimums.json", "FFmpeg", "pylibsrtp", "cryptography", "CPython"):
        assert part in paragraph, part
    assert "would pass this gate" not in paragraph
