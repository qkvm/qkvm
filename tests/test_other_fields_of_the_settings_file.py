"""Every field of the settings file is asked what it holds, not nine of them.

One wrong value at a time, in fields where the file was still read and the program started, and then:

* the sign-in was an error for everybody (`server.require_totp` that is a list; an account's `name`
  that is no text, for every account that signs in by name);
* the start itself ended in a traceback that was no "cannot be read" (`recovery_created` that is a
  number too large to be a time);
* the alert settings were an error and the watcher fell over at every look (`paused_until` that is
  such a number);
* reading any file was an error (a saved action's `name` that is no text); the list of accounts was
  (an account's `totp_codes` that is no list).

Each is a file that cannot be used (then the second copy is, or the start says which value), or it
does no harm: what it is not, is a 500 for everybody from a wall that started.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from qkvm import exchange, kvm, update, vault
from qkvm.store import Store, StoreError
from tests.test_wall import PASSWORD, add, closed_port, wall

OTHER = "another good password"
F = {"format": exchange.FORMAT, "version": 1}


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 2)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 2)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def a_wall(folder: Path) -> None:
    with wall(folder) as admin:
        add(admin, f"http://127.0.0.1:{closed_port()}", force=True, kind="kvmd", name="The one device")
        assert admin.post("/api/v1/users", json={"name": "olga", "role": "operator", "password": OTHER}).status_code == 201
        assert admin.post("/api/v1/actions", json={"name": "Lock", "kind": "keys", "keys": "MetaLeft,KeyL"}).status_code == 201


def edited(folder: Path, change: Any) -> None:
    saved = json.loads((folder / "qkvm.json").read_text(encoding="utf-8"))
    change(saved)
    (folder / "qkvm.json").write_text(json.dumps(saved), encoding="utf-8")
    (folder / "qkvm.bak").unlink()  # (so that what is read is this file, or nothing)


def asked(folder: Path, requests: list[tuple[str, str, Any]]) -> list[str]:
    """What went wrong on a wall started on `folder`: a line each. Empty where the start said the file cannot be used."""
    try:
        Store(folder / "qkvm.json")
    except StoreError:
        return []  # refused, in a sentence: that is an answer
    except Exception as ex:
        return [f"the start ended in {type(ex).__name__}: {ex}"]
    wrong = []
    with wall(folder, sign_in=False) as browser:
        for method, path, body in requests:
            reply = browser.request(method, path, json=body)
            if reply.status_code >= 500:
                wrong.append(f"{method} {path} answered {reply.status_code}")
    return wrong


SIGN_IN = [("POST", "/api/v1/login", {"name": "olga", "password": OTHER})]
AS_ADMIN = [("POST", "/api/v1/login", {"name": "admin", "password": PASSWORD})]

CASES: dict[str, tuple[Any, list[tuple[str, str, Any]]]] = {
    "require_totp that is a list": (lambda saved: saved["server"].__setitem__("require_totp", []), SIGN_IN),
    "the first account's name that is a number": (lambda saved: saved["users"][0].__setitem__("name", 5), SIGN_IN),
    "recovery_created that is too large a number": (lambda saved: saved.__setitem__("recovery_created", 10**400), SIGN_IN),
    "paused_until that is too large a number": (lambda saved: saved["alerts"].__setitem__("paused_until", 10**400), [*AS_ADMIN, ("GET", "/api/v1/alerts", None)]),
    "a saved action's name that is a number": (lambda saved: saved["actions"][0].__setitem__("name", 5), [*AS_ADMIN, ("POST", "/api/v1/import/read", {"file": json.dumps({**F, "actions": []})})]),
    "an account's one-time codes that are a number": (lambda saved: saved["users"][1].__setitem__("totp_codes", 5), [*AS_ADMIN, ("GET", "/api/v1/users", None)]),
}


@pytest.mark.parametrize("what", list(CASES))
def test_a_wrong_value_in_another_field_is_refused_at_start_or_does_no_harm(tmp_path: Path, what: str) -> None:
    change, requests = CASES[what]
    a_wall(tmp_path)
    edited(tmp_path, change)
    wrong = asked(tmp_path, requests)
    print(f">>> {what}: {wrong or 'refused at start, or no harm'}")
    assert not wrong, f"{what}: {wrong}"


def test_every_kind_of_field_a_record_has_is_one_the_check_knows() -> None:
    # The check goes by what a field is declared as. A field of a kind it has never heard of (the next one
    # somebody adds) would be an error at every start: found here instead.
    from dataclasses import fields

    from qkvm import store

    for record in (store.ServerSettings, store.AlertSettings, store.DeviceRecord, store.UserRecord, store.TokenRecord, store.ActionRecord):
        for each in fields(record):
            for kind in (part.strip() for part in str(each.type).split("|")):
                assert kind == "None" or (kind in store._HOLDS and kind in store._CALLED), (record.__name__, each.name, kind)


def test_what_the_check_makes_of_nothing_in_each_kind_of_field() -> None:
    # The empty one of its kind (off, no text, none), which is what the program took nothing for while it
    # did not ask. Not what the field is when it is not written: except where empty is of no use and what
    # is declared gives nothing away; and for what somebody may do, the least there is.
    from qkvm import store
    from qkvm.store import DEFAULT_PORT, ActionRecord, AlertSettings, DeviceRecord, ServerSettings, TokenRecord, UserRecord

    nothing: Any = None
    device = DeviceRecord(id="ab12cd34", name=nothing, url="https://192.168.1.20", username=nothing, open_url=nothing, tls=nothing, kind=nothing, group=nothing, ident=nothing, alerts=nothing)
    store._as_declared(device, "the device")
    assert (device.name, device.username, device.open_url, device.tls, device.kind, device.group, device.ident, device.alerts) == ("", "admin", "", "pinned", "kvmd", "", "", False)
    user = UserRecord(id="admin", name="admin", role=nothing, auth=nothing, groups=nothing, suspended=nothing, created=nothing, totp_codes=nothing, totp_step=nothing, totp_changes=nothing)
    store._as_declared(user, "the account")
    assert (user.role, user.auth, user.devices, user.groups, user.suspended, user.created, user.totp_codes, user.totp_step, user.totp_changes) == ("viewer", {}, None, [], False, 0.0, [], 0, 0)
    token = TokenRecord(id="t1", name=nothing, kind=nothing, role=nothing, groups=nothing, kept=nothing, created=nothing)
    store._as_declared(token, "the token")
    assert (token.name, token.kind, token.role, token.groups, token.kept, token.created, token.expires, token.used) == ("", "", "viewer", [], "", 0.0, None, None)
    action = ActionRecord(id="a1", name=nothing, kind=nothing, keys=nothing, enter=nothing, danger=nothing, changed=nothing)
    store._as_declared(action, "the saved action")
    assert (action.name, action.kind, action.keys, action.enter, action.danger, action.changed) == ("", "", "", False, False, 0)
    server = ServerSettings(bind=nothing, port=nothing, https=nothing, interval=nothing, allowed_hosts=nothing, update_check=nothing, metrics_token=nothing, require_totp=nothing)
    store._as_declared(server, "server")
    assert (server.bind, server.port, server.https, server.interval, server.allowed_hosts, server.update_check, server.metrics_token, server.metrics_created, server.require_totp) == (
        ["local"], DEFAULT_PORT, False, 1.0, [], False, "", None, "",
    )  # fmt: skip
    alerts = AlertSettings(enabled=nothing, format=nothing, offline=nothing, no_signal=nothing, problem=nothing, recovered=nothing, link=nothing, paused_until=nothing)
    store._as_declared(alerts, "alerts")
    assert (alerts.enabled, alerts.format, alerts.offline, alerts.no_signal, alerts.problem, alerts.recovered, alerts.link, alerts.paused_until) == (False, "auto", False, False, False, False, "", 0.0)


def test_what_the_check_takes_and_refuses_one_rule_at_a_time() -> None:
    from qkvm import store
    from qkvm.store import AlertSettings, DeviceRecord, UserRecord

    def device(**fields: Any) -> DeviceRecord:
        return DeviceRecord(**{"id": "ab12cd34", "name": "A KVM", "url": "https://192.168.1.20", **fields})

    def refused(record: Any) -> str:
        with pytest.raises(ValueError) as said:
            store._as_declared(record, "this one")
        return str(said.value)

    # 0 and 1 where yes or no belongs are no and yes; any other number is none of the two.
    for written, meant in ((0, False), (1, True)):
        one = device(alerts=written)
        store._as_declared(one, "the device")
        assert one.alerts is meant
    assert '"alerts" has to be true or false' in refused(device(alerts=2))
    assert '"alerts" has to be true or false' in refused(device(alerts="yes"))
    # Yes is no whole number, and a whole number has an end.
    assert '"totp_step" has to be a whole number' in refused(UserRecord(id="admin", name="admin", totp_step=True))  # type: ignore[arg-type]
    assert '"totp_step" has to be a whole number' in refused(UserRecord(id="admin", name="admin", totp_step=2**63))
    assert '"totp_step" has to be a whole number' in refused(UserRecord(id="admin", name="admin", totp_step=1.5))  # type: ignore[arg-type]
    # A number has an end as well, and is neither endless nor "not a number".
    for no_time in (1e301, float("inf"), float("nan"), True):
        assert '"paused_until" has to be a number' in refused(AlertSettings(paused_until=no_time))
    # Half a character is no text, in a text or in a list of them.
    assert '"group" has to be a text' in refused(device(group="Rack " + chr(0xD800)))
    assert '"groups" has to be a list of texts' in refused(UserRecord(id="admin", name="admin", groups=["Rack 1", chr(0xD800)]))
    # What is saved encrypted, and a remembered certificate, are not asked here, whatever they are made of.
    odd: Any = 5
    for name in ("secret", "cert_pem"):
        store._as_declared(device(**{name: odd}), "the device")
    store._as_declared(UserRecord(id="admin", name="admin", totp=odd), "the account")
    store._as_declared(AlertSettings(webhook=odd), "alerts")
    # And the refusal says which field of which record, and what belongs there.
    assert refused(device(open_url=7)) == 'this one: "open_url" has to be a text'
    assert refused(UserRecord(id="admin", name="admin", devices=7)) == 'this one: "devices" has to be a list of texts, or null'  # type: ignore[arg-type]
