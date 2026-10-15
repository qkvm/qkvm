"""The page takes every file that the wall writes and the server reads.

A person reads a file back through the page, and the page looks at the file's size before it sends
anything (static/app.js, `chosen.size`). That number was two million bytes while the server wrote plain
files of up to exchange.MAX_FILE (4,000,000) characters and sealed ones of up to exchange.MAX_SEALED:
a wall's own export was "larger than anything qKVM writes" to its own import dialog.
test_largest_file.py goes through the API, where the page's check is not in the way.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from qkvm import exchange, kvm, update, vault
from tests.test_largest_file import PASSPHRASE, a_wall_of, rsa_certificate
from tests.test_wall import PASSWORD, wall

PAGE = Path(exchange.__file__).parent / "static" / "app.js"
F = {"format": exchange.FORMAT, "version": 1}


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def the_most_the_page_takes() -> int:
    """The size above which the import dialog refuses a chosen file without sending it."""
    found = re.search(r"chosen\.size\s*>\s*([0-9_]+)\)\s*return fail\('The file is larger than anything qKVM writes", PAGE.read_text(encoding="utf-8"))
    assert found, "the import dialog no longer checks a file's size the way this test reads it: look at it again"
    return int(found.group(1).replace("_", ""))


def test_the_page_takes_every_file_the_server_writes() -> None:
    most = the_most_the_page_takes()
    print(f">>> the page refuses a file above {most} bytes; the server writes plain files up to {exchange.MAX_FILE} and sealed ones up to {exchange.MAX_SEALED}")
    assert most >= exchange.MAX_SEALED, f"a sealed file of {most + 1} to {exchange.MAX_SEALED} bytes is written by /api/v1/export and read by /api/v1/import, and refused by the page"


def test_a_wall_of_a_size_the_program_provides_for_exports_a_file_its_own_page_refuses(tmp_path: Path) -> None:
    # Two thousand devices is what a file may hold (exchange.MOST_DEVICES) and what test_largest_file.py
    # takes in and exports. Here: the smallest walls whose own export the import dialog turns away.
    most = the_most_the_page_takes()
    pem = rsa_certificate(2048)
    with wall(tmp_path) as admin:
        took = admin.post("/api/v1/import", json={"file": json.dumps({**F, "devices": a_wall_of(1200, pem)}), "take": ["devices"]})
        assert took.status_code == 200 and took.json()["devices"] == 1200, took.text[:300]
        sealed = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": PASSPHRASE, "parts": ["devices"]})
        plain = admin.post("/api/v1/export", json={"password": PASSWORD, "passphrase": "", "parts": ["devices"]})
        assert sealed.status_code == 200 and plain.status_code == 200
        # (The server itself reads both back: it is the page that does not.)
        assert admin.post("/api/v1/import/read", json={"file": sealed.text, "passphrase": PASSPHRASE}).status_code == 200
        assert admin.post("/api/v1/import/read", json={"file": plain.text}).status_code == 200
    print(f">>> 1200 devices with RSA-2048 certificates ({len(pem)} characters each): sealed export {len(sealed.content)} bytes, plain export {len(plain.content)} bytes; the page takes {most}")
    assert len(sealed.content) <= most, f"the wall's own sealed export ({len(sealed.content)} bytes) is 'larger than anything qKVM writes' to its import dialog ({most})"
    assert len(plain.content) <= most, f"the wall's own plain export ({len(plain.content)} bytes) is 'larger than anything qKVM writes' to its import dialog ({most})"
