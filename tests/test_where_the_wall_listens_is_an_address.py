"""The one list of texts a form still took unasked was where the wall listens.

`SettingsIn.bind` is a list of texts with no rule on each; `netbind.normalize` takes an IPv6 address with a
zone ("fe80::1%eth0"), and Python's `ipaddress` takes ANY text after the percent sign for a zone. So half a
character (a lone surrogate, which JSON can spell out) is saved into `server.bind`, into both copies of the
settings file. The check at a start refuses a text that is no UTF-8: the wall did not start
again, and its second copy is refused with it.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from qkvm.core import Core
from qkvm.store import Store, StoreError
from qkvm.vault_storage import key_path
from tests.test_wall import wall

HALF = "\\ud800"  # as JSON spells half a character out


def put_settings(admin, port: int, bind: str):  # type: ignore[no-untyped-def]
    body = '{"bind": [' + bind + '], "port": ' + str(port) + ', "https": false, "interval": 1}'
    return admin.put("/api/v1/settings", content=body.encode("ascii"), headers={"Content-Type": "application/json"})


def test_a_zone_of_half_a_character_is_not_saved_as_where_the_wall_listens(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Core, "request_restart", lambda self: None)  # (the listeners of a test are not reopened)
    folder = tmp_path / "data"
    with wall(folder) as admin:
        port = admin.core.store.server.port  # type: ignore[attr-defined]
        try:
            reply = put_settings(admin, port, f'"fe80::1%{HALF}"')
            answered = f"{reply.status_code} {reply.text[:120]}"
        except UnicodeEncodeError as ex:  # (the test's client hands an error inside the program on: a browser is answered 500)
            answered = f"an error inside the program ({type(ex).__name__}: the answer could not be written)"
        print(">>> PUT /api/v1/settings with a zone of half a character:", answered)
        print(">>> kept as where the wall listens:", [ascii(name) for name in admin.core.store.server.bind])  # type: ignore[attr-defined]
    # Whatever the form answered: what lies on disk now has to be a file a start reads.
    for name in ("qkvm.json", "qkvm.bak"):
        alone = tmp_path / f"alone-{name}"
        alone.mkdir()
        shutil.copy2(folder / name, alone / "qkvm.json")
        try:
            Store(alone / "qkvm.json", vault_key_file=key_path(folder), protected=True)
        except StoreError as ex:
            pytest.fail(f"the form answered {answered}, and {name} is refused at the next start: {str(ex)[-230:]}")
    # ...and the wall itself starts on its folder again.
    with wall(folder, sign_in=False) as again:
        assert again.core.store.restored is False  # type: ignore[attr-defined]


def test_a_zone_that_is_a_text_of_any_kind_is_not_where_the_wall_listens(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The same door without half a character: a zone with a line break and three thousand letters in it is
    # kept, shown on the settings page and written into the activity log, as "an IP address".
    monkeypatch.setattr(Core, "request_restart", lambda self: None)
    with wall(tmp_path) as admin:
        port = admin.core.store.server.port  # type: ignore[attr-defined]
        reply = put_settings(admin, port, '"::1%a\\nb' + "x" * 3000 + '"')
        print(">>> PUT /api/v1/settings with a zone of a line break and 3000 letters:", reply.status_code, reply.text[:120])
        kept = admin.core.store.server.bind  # type: ignore[attr-defined]
        assert all(len(name) < 64 and "\n" not in name for name in kept), f"kept as where the wall listens: {[name[:30] for name in kept]}"
