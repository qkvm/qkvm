from __future__ import annotations

import hashlib

import pytest

from qkvm import qr, totp

FINDER = ["1111111", "1000001", "1011101", "1011101", "1011101", "1000001", "1111111"]


def test_the_code_for_a_known_text_has_not_changed() -> None:
    # This exact pattern was read back with two independent QR readers when the generator was
    # written (all six sizes, all eight masks). The fingerprint keeps a later edit from quietly
    # producing codes that look fine and do not scan.
    text = "otpauth://totp/QKVM%3Aadmin?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=QKVM"
    rows = qr.matrix(text)
    assert hashlib.sha256("\n".join(rows).encode()).hexdigest() == (
        "84cdc9cf0f4748c153c128070db5d27f14cd79d8e891025ec19e8b631a8fc87a"
    )


@pytest.mark.parametrize(("length", "size"), [(1, 21), (17, 21), (18, 25), (53, 29), (78, 33), (106, 37), (134, 41)])
def test_size_grows_with_the_text(length: int, size: int) -> None:
    rows = qr.matrix("x" * length)
    assert len(rows) == size and all(len(row) == size and set(row) <= {"0", "1"} for row in rows)
    # The three corner squares a reader looks for, and the module that is always dark.
    assert [row[:7] for row in rows[:7]] == FINDER
    assert [row[-7:] for row in rows[:7]] == FINDER
    assert [row[:7] for row in rows[-7:]] == FINDER
    assert rows[size - 8][8] == "1"
    assert rows[6][8 : size - 8] == ("10" * size)[: size - 16]  # the timing line between them


def test_too_long_a_text_is_refused() -> None:
    with pytest.raises(ValueError):
        qr.matrix("x" * 135)


def test_the_longest_account_name_still_fits() -> None:
    uri = totp.setup_uri(totp.new_secret(), "a" * 32)
    assert len(uri) <= 134 and len(qr.matrix(uri)) <= 41
