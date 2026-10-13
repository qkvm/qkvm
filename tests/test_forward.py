"""The activity log, sent on to a collector as it is written (--audit-syslog)."""

from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from qkvm import cli, forward, kvm, update, vault
from tests.test_wall import closed_port, wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def test_the_activity_log_is_sent_on_as_it_is_written(tmp_path: Path) -> None:
    # "Who did what" kept only on the computer it was done on is no evidence against whoever has that
    # computer. A security team wants it in their own collector, as it happens.
    collector = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    collector.bind(("127.0.0.1", 0))
    collector.settimeout(10)
    try:
        # (Started locked: as it comes, "carries on by itself from the next start on" is an entry of its own, a moment after the first.)
        with wall(tmp_path / "udp", locked_start=True, audit_syslog=f"127.0.0.1:{collector.getsockname()[1]}") as admin:
            first = collector.recvfrom(65535)[0].decode("utf-8")
            # RFC 5424: <facility "log audit", severity notice>, version 1, when, this host, the program, -, what, -, the entry.
            head, _, entry = first.partition(" - {")
            assert head.startswith("<109>1 20") and head.endswith(" qkvm - setup") and "T" in head.split()[1] and head.split()[1].endswith("Z")
            said = json.loads("{" + entry)
            assert (said["event"], said["user"], said["ip"]) == ("setup", "admin", "127.0.0.1")
            assert admin.post("/api/v1/login", json={"password": "not the password"}).status_code == 401
            assert collector.recvfrom(65535)[0].startswith(b"<108>1 ")  # what went wrong is a warning there
            assert '"event": "setup"' in (tmp_path / "udp" / "audit.log").read_text()  # and the file is written as ever
    finally:
        collector.close()


def test_over_tcp_and_with_a_collector_that_is_not_there(tmp_path: Path) -> None:
    listener = socket.create_server(("127.0.0.1", 0))
    received: list[bytes] = []

    def collect() -> None:
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(10)
            while not b"".join(received).count(b"\n"):
                received.append(connection.recv(65535))

    reader = threading.Thread(target=collect, daemon=True)
    reader.start()
    try:
        with wall(tmp_path / "tcp", locked_start=True, audit_syslog=f"tcp://127.0.0.1:{listener.getsockname()[1]}"):
            reader.join(timeout=10)
            assert b"".join(received).startswith(b"<109>1 ") and b" qkvm - setup - {" in b"".join(received)
    finally:
        listener.close()

    # Nobody listening: nothing waits for it, nothing fails for it, and the log on disk is complete.
    began = time.monotonic()
    with wall(tmp_path / "gone", audit_syslog=f"tcp://127.0.0.1:{closed_port()}") as admin:
        for _ in range(20):
            assert admin.post("/api/v1/logout", json={"scope": "others"}).status_code == 200
        assert admin.get("/api/v1/audit").status_code == 200
    assert time.monotonic() - began < 8
    assert '"event": "setup"' in (tmp_path / "gone" / "audit.log").read_text()


def test_where_to_send_it_is_checked_at_start(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert forward.where("collector.example") == ("udp", "collector.example", 514)
    assert forward.where("udp://10.0.0.9:5514") == ("udp", "10.0.0.9", 5514)
    assert forward.where("tcp://[2001:db8::9]:601") == ("tcp", "2001:db8::9", 601)
    for nonsense in ("", "tcp://", "http://collector.example", "collector.example:port", "collector.example/path", "user@collector.example", "a b"):
        with pytest.raises(ValueError):
            forward.where(nonsense)
    assert cli.main(["--data-dir", str(tmp_path), "--audit-syslog", "http://collector.example", "--disable-2fa", "nobody"]) == 2
    assert "--audit-syslog" in capsys.readouterr().err


@pytest.mark.parametrize("target", ["a..invalid", "a" * 64 + ".invalid:5514", "tcp://a..invalid:601", ".invalid", "udp://collector..example:514"])
def test_a_collector_whose_name_no_lookup_takes_is_refused_at_the_start(target: str) -> None:
    # A name with an empty part, or one longer than a name's part may be, was taken at the start. The first
    # entry then ended the thread that sends, with an error nobody saw, and nothing was sent on from then.
    with pytest.raises(ValueError):
        forward.where(target)


def test_the_sending_goes_on_after_an_entry_that_could_not_be_looked_up(monkeypatch: pytest.MonkeyPatch) -> None:
    # (Whatever a lookup raises for a name it will not take: it is said in the log, and the next entry is sent.)
    real = socket.getaddrinfo
    asked: list[Any] = []

    def lookup(host: Any, *more: Any, **how: Any) -> Any:
        asked.append(host)
        if len(asked) == 1:
            raise UnicodeError("label empty or too long")
        return real(host, *more, **how)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as heard:
        heard.bind(("127.0.0.1", 0))
        heard.settimeout(5)
        collector = forward.Syslog(f"127.0.0.1:{heard.getsockname()[1]}")
        monkeypatch.setattr(forward.socket, "getaddrinfo", lookup)
        collector.send('{"time": 1700000000, "event": "first", "ip": ""}\n')
        collector.send('{"time": 1700000001, "event": "second", "ip": ""}\n')
        assert b" second " in heard.recvfrom(4096)[0]
        assert collector._sender is not None and collector._sender.is_alive()


@pytest.mark.parametrize("line", ['{"time": 1e400}', '{"time": NaN}', '{"time": 1e300}', '{"time": -1e300}', '{"time": true}', '{"time": "now"}'])
def test_an_entry_whose_time_is_no_time_is_sent_with_the_time_of_now(line: str) -> None:
    year = time.strftime("%Y", time.gmtime()).encode()
    message = forward.Syslog("127.0.0.1:5514").message(line)
    assert message.startswith(b"<") and (b" " + year + b"-" in message or b" 1970-01-01T00:00:01" in message), message[:60]
