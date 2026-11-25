"""Mail by SMTP, by the wall's outbound rules (egress.send_mail): TLS always, the certificate checked for the server's
name, a password never sent over a line that is not encrypted, the server's own words when it says no, and an end to
every send. Against a stand-in on loopback (fake_smtp.py)."""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Iterator
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import pytest

from qkvm import egress
from tests.fake_smtp import Behaviour, FakeSmtp

OWN = frozenset({"203.0.113.40"})


def message() -> EmailMessage:
    said = EmailMessage()
    said["Subject"] = "Build server is offline"
    said["From"] = "qkvm@example.com"
    said["To"] = "ops@example.com, oncall@example.com"
    said.set_content("The KVM stopped answering.")
    return said


def send(host: str = "smtp.example.com", port: int = 587, login: tuple[str, str] | None = ("alerts@example.com", "app pass word"), **rules: Any) -> str:
    rules = {"private_ok": False, "own": OWN, **rules}
    return asyncio.run(egress.send_mail(host, port, login, message(), "qkvm@example.com", ["ops@example.com", "oncall@example.com"], **rules))


@pytest.fixture
def smtp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeSmtp]:
    server = FakeSmtp(tmp_path)
    server.put_in_place(monkeypatch)
    yield server
    server.close()


def test_mail_goes_by_starttls_on_587_and_the_login_only_once_it_is_encrypted(smtp: FakeSmtp) -> None:
    said = send()
    assert said.startswith("250")
    assert smtp.seen.commands[:3] == ["EHLO", "STARTTLS", "EHLO"]
    assert smtp.seen.logins == [("alerts@example.com", "app pass word", True)]
    assert smtp.seen.sni == ["smtp.example.com"]
    sent = smtp.seen.messages[0]
    assert (sent.sender, sent.to) == ("qkvm@example.com", ["ops@example.com", "oncall@example.com"])
    assert b"Subject: Build server is offline" in sent.data and b"The KVM stopped answering." in sent.data
    # What the wall calls itself to a mail server: not its own name, which would tell the server where it is.
    assert smtp.seen.commands.count("EHLO") == 2


def test_mail_goes_by_implicit_tls_on_465(smtp: FakeSmtp) -> None:
    smtp.behaviour = Behaviour(implicit_tls=True, starttls=False)
    assert send(port=465).startswith("250")
    assert smtp.seen.logins == [("alerts@example.com", "app pass word", True)] and smtp.seen.sni == ["smtp.example.com"]


def test_a_server_that_offers_no_starttls_is_sent_nothing(smtp: FakeSmtp) -> None:
    smtp.behaviour = Behaviour(starttls=False)
    with pytest.raises(egress.Refused) as refused:
        send()
    assert "STARTTLS" in str(refused.value)
    assert smtp.seen.logins == [] and smtp.seen.messages == []


def test_what_comes_in_the_clear_after_starttls_is_not_taken_for_the_servers(smtp: FakeSmtp) -> None:
    # An attacker on the line answers STARTTLS and pushes a line in after it, hoping it is read as said inside TLS.
    smtp.behaviour = Behaviour(inject=True)
    with pytest.raises(egress.Refused):
        send()
    assert smtp.seen.logins == [] and smtp.seen.messages == []


def test_a_certificate_for_another_name_is_refused(smtp: FakeSmtp) -> None:
    with pytest.raises(egress.NotReached) as refused:
        send(host="other.example.net")
    assert "certificate" in str(refused.value) and refused.value.again is False
    assert smtp.seen.logins == []


def test_a_refused_login_says_the_servers_own_words(smtp: FakeSmtp) -> None:
    smtp.behaviour = Behaviour(login_ok=False)
    with pytest.raises(egress.MailRefused) as refused:
        send()
    assert refused.value.code == 535 and refused.value.again is False
    assert "Username and Password not accepted" in str(refused.value)


def test_a_password_said_back_without_the_blanks_at_its_ends_is_taken_out(smtp: FakeSmtp) -> None:
    # (The outside review of 0.4.0, round 6.2, M8.) A password is sent as it was typed, blanks at its ends too; a
    # server that says it back without them has said the password.
    smtp.behaviour = Behaviour(login_ok=False, refusal=b"535 5.7.8 password abcd not accepted")
    with pytest.raises(egress.MailRefused) as refused:
        send(login=("alerts@example.com", "  abcd  "))
    assert str(refused.value) == "535 5.7.8 password [hidden] not accepted"
    assert smtp.seen.logins == [("alerts@example.com", "  abcd  ", True)]


def test_a_recipient_refused_for_now_is_tried_again_later(smtp: FakeSmtp) -> None:
    smtp.behaviour = Behaviour(refuse_rcpt=b"451 4.3.0 Mailbox temporarily unavailable")
    with pytest.raises(egress.MailRefused) as refused:
        send()
    assert refused.value.code == 451 and refused.value.again is True


def test_a_message_refused_for_some_of_its_addresses_says_which_and_is_not_tried_again(smtp: FakeSmtp) -> None:
    # (The outside review of 0.4.0, round 6.2, M5.) What smtplib hands back of the addresses a server refused was
    # left unread: one address took the message, the other did not, and the send was said as a success ("250 2.0.0 OK").
    # Said now: which were refused, in the server's words with the login taken out; and never tried again, whatever the
    # refusal (a 4xx too), as those that took it have it.
    for refusal, shown in (
        (b"550 5.1.1 <oncall@example.com>: no such user here, app pass word", "550 5.1.1 <oncall@example.com>: no such user here, [hidden]"),
        (b"452 4.2.2 Mailbox full", "452 4.2.2 Mailbox full"),
    ):
        smtp.seen.messages.clear()
        smtp.behaviour = Behaviour(refuse_rcpt_for={"oncall@example.com": refusal})
        with pytest.raises(egress.PartlyRefused) as partly:
            send()
        assert [sent.to for sent in smtp.seen.messages] == [["ops@example.com"]]
        assert str(partly.value) == f"Delivered to 1 of 2 addresses, not tried again: refused for oncall@example.com ({shown})"
        assert (partly.value.code, partly.value.again) == (int(refusal[:3]), False)
    # Refused for every one of them: nobody has it, and a "not now" is tried again as before (below).
    smtp.behaviour = Behaviour(refuse_rcpt_for={"ops@example.com": b"550 5.1.1 no", "oncall@example.com": b"550 5.1.1 no"})
    with pytest.raises(egress.MailRefused) as refused:
        send()
    assert not isinstance(refused.value, egress.PartlyRefused) and refused.value.code == 550


@pytest.mark.parametrize("not_now", ["ops@example.com", "oncall@example.com"], ids=["first", "second"])
def test_a_message_refused_for_every_address_is_tried_again_where_any_of_them_said_not_now(smtp: FakeSmtp, not_now: str) -> None:
    # (The outside review 6.2 second re-check, M5.) Nobody took it: one address refused for good, the other for now. The first refusal
    # said how it went, so in one order of the two the send was given up on, and the mailbox that was busy for a moment never
    # had its alert. A "not now" of any of them is tried again, whatever the order (nobody has it: nobody has it twice).
    refusals = {"ops@example.com": b"550 5.1.1 no such user", "oncall@example.com": b"550 5.1.1 no such user"}
    refusals[not_now] = b"451 4.2.2 Mailbox busy"
    smtp.behaviour = Behaviour(refuse_rcpt_for=refusals)
    with pytest.raises(egress.MailRefused) as refused:
        send()
    assert not isinstance(refused.value, egress.PartlyRefused) and smtp.seen.messages == []
    assert (refused.value.code, refused.value.again) == (451, True), str(refused.value)


def test_a_message_the_server_took_stays_sent_whatever_comes_after_it(smtp: FakeSmtp, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The outside review 6.2, M6.) The server's 250 to the message's end is its acceptance. A NOOP was sent after it, and its answer
    # taken for how the send went: a server that took the message and hung up was said as not reached, and an alert was
    # sent again, four times. The answer to the message's end is what is said now; the line closed after it, or no answer
    # to QUIT until the send's time is up, undoes nothing.
    smtp.behaviour = Behaviour(hang_up_after_data=True)
    assert send() == "250 2.0.0 OK queued as 12345"
    assert len(smtp.seen.messages) == 1 and "NOOP" not in smtp.seen.commands
    smtp.behaviour = Behaviour(quiet_after_data=True)
    monkeypatch.setattr(egress, "SEND_TIMEOUT", 6.0)  # (the time a send has, start to finish: it ends the wait for QUIT here)
    monkeypatch.setattr(egress, "STEP_TIMEOUT", 60.0)  # (...and not a step's own time first)
    started = time.monotonic()
    assert send() == "250 2.0.0 OK queued as 12345"
    assert len(smtp.seen.messages) == 2 and smtp.seen.commands[-1] == "QUIT" and time.monotonic() - started < 6.0 + 5
    deadline = time.monotonic() + 5
    while egress.under_way():
        assert time.monotonic() < deadline, "the send's thread is still held"
        time.sleep(0.05)


def test_a_message_the_server_took_stays_sent_where_its_time_is_up_while_its_refusals_are_written_up(smtp: FakeSmtp, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The outside review 6.2 re-check, R7.) Taken for one address and refused for now for the other, the server's words of that
    # refusal were still being made fit to show when the send's time was up: what the event loop knew had no 250 in it yet,
    # the send was said as not answered in time, and the address that had the message was sent it again. The 250 is known
    # the moment it is read now: the send is over, and delivered to the addresses that took it, whatever comes after.
    writing, said, real = threading.Event(), threading.Event(), egress._refusal

    def slow(*given: Any) -> str:
        writing.set()
        said.wait(30)  # (until the send has been said: its time is up meanwhile, however slow the computer)
        return real(*given)

    monkeypatch.setattr(egress, "_refusal", slow)
    monkeypatch.setattr(egress, "SEND_TIMEOUT", 6.0)  # (the time a send has, start to finish: its end comes while the words are made)
    smtp.behaviour = Behaviour(refuse_rcpt_for={"oncall@example.com": b"451 4.2.2 Mailbox busy"})
    try:
        with pytest.raises(egress.PartlyRefused) as partly:
            send()
    finally:
        said.set()
    assert writing.is_set()
    assert str(partly.value) == "Delivered to 1 of 2 addresses, not tried again: refused for oncall@example.com (451)"
    assert partly.value.again is False and [sent.to for sent in smtp.seen.messages] == [["ops@example.com"]]
    deadline = time.monotonic() + 35
    while egress.under_way():
        assert time.monotonic() < deadline, "the send's thread is still held"
        time.sleep(0.05)


def test_only_the_ports_of_tls(smtp: FakeSmtp) -> None:
    for port in (25, 2525, 22, 6379):
        with pytest.raises(egress.Refused):
            send(port=port)
    assert smtp.seen.commands == []


def test_a_mail_server_inside_the_network_only_with_its_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    async def resolve(host: str, port: int) -> list[str]:
        return {"mail.lan.example": ["192.168.1.25"], "metadata.example": ["169.254.169.254"]}[host]

    monkeypatch.setattr(egress, "resolve", resolve)
    with pytest.raises(egress.Refused) as refused:
        send(host="mail.lan.example")
    assert "private" in str(refused.value)
    with pytest.raises(egress.Refused):
        send(host="metadata.example", private_ok=True)
    with pytest.raises(egress.Refused):
        send(host="127.0.0.1", private_ok=False)


@pytest.mark.parametrize("host", ["fd00:ec2::254%1", "fd00:ec2::254%25eth0", "2003:db8::8888%1"])
def test_a_mail_server_at_an_address_that_names_an_interface_is_refused(host: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The second outside review of 0.4.0, M1, for mail.) An IPv6 zone is refused where a mail server is typed, and where it
    # is judged before anything is sent.
    from qkvm import destinations
    from tests.test_egress import no_connection

    tried = no_connection(monkeypatch)
    with pytest.raises(egress.Refused, match="interface"):
        send(host=host, private_ok=True, own={"2003:db8::8888"})
    assert tried == []
    with pytest.raises(ValueError, match="interface"):
        destinations.check("email", {"host": host, "port": 587, "sender": "qkvm@example.com", "to": ["ops@example.com"]}, {})


def test_an_answer_that_never_ends_is_not_read_for_ever(smtp: FakeSmtp) -> None:
    smtp.behaviour = Behaviour(endless=True)
    started = time.monotonic()
    with pytest.raises((egress.MailRefused, egress.NotReached)):
        send()
    assert time.monotonic() - started < 10


def test_a_server_that_never_answers_is_let_go_of(smtp: FakeSmtp, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(egress, "SEND_TIMEOUT", 0.5)
    smtp.behaviour = Behaviour(silent=True)
    started = time.monotonic()
    with pytest.raises(egress.NotReached) as late:
        send()
    assert late.value.again is True and time.monotonic() - started < 5
    deadline = time.monotonic() + 5
    while egress.under_way():
        assert time.monotonic() < deadline, "the send's thread is still held"
        time.sleep(0.05)


def test_what_else_goes_wrong_before_a_mail_is_sent_is_said_as_not_reached(smtp: FakeSmtp, monkeypatch: pytest.MonkeyPatch) -> None:
    # (The review of 0.4.0's first wave, L2.) An authorities' file that cannot be read (SSL_CERT_FILE) raised out of the
    # send as an error of its own kind, and every mail of a burst was dropped with a line in the program's log only.
    async def unreadable() -> Any:
        raise OSError("no such file: the authorities")

    monkeypatch.setattr(egress, "public_context", unreadable)
    with pytest.raises(egress.NotReached) as late:
        send()
    assert "smtp.example.com" in str(late.value) and smtp.seen.commands == []


def test_mails_waiting_for_a_thread_do_not_spend_their_time_waiting(smtp: FakeSmtp, monkeypatch: pytest.MonkeyPatch) -> None:
    # Four mails go at once; the others wait for one of them to be done. Their time was counted from before that wait: a
    # burst to many mail destinations ran out of time in the queue, and was tried again.
    monkeypatch.setattr(egress, "SEND_TIMEOUT", 2.5)
    smtp.behaviour = Behaviour(delay=1.5)

    async def burst() -> list[Any]:
        jobs = [
            egress.send_mail("smtp.example.com", 587, ("u", "p"), message(), "qkvm@example.com", ["ops@example.com"], private_ok=False, own=OWN)
            for _ in range(2 * egress.MAIL_AT_ONCE)
        ]  # fmt: skip
        return await asyncio.gather(*jobs, return_exceptions=True)

    said = asyncio.run(burst())
    assert all(isinstance(each, str) and each.startswith("250") for each in said), said


def test_a_mail_server_whose_name_leads_to_both_families_is_reached_at_whichever_answers(smtp: FakeSmtp, monkeypatch: pytest.MonkeyPatch) -> None:
    # (As for the web: the stand-in listens on 127.0.0.1 alone, and the name leads to ::1 first.)
    async def vetted(host: str, port: int, **rules: Any) -> tuple[list[str], int]:
        return ["::1", "127.0.0.1"], smtp.port

    monkeypatch.setattr(egress, "vetted", vetted)
    assert send().startswith("250") and smtp.seen.logins == [("alerts@example.com", "app pass word", True)]
