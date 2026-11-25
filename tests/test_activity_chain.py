"""The activity log's chain (chain.py): each way a log can be quietly edited, and that each is caught by a check.

A log is made here as the wall's writer makes it (each line stamped with its number, the head before it and its signature;
seals where the writer writes them), handed to the check as a download hands it over, oldest first, and then changed the
way somebody with the data folder would change it: a field, a line taken out, two swapped, one put in, the end written
anew with the chain worked out again (without the key, and with it). The writer itself, the files and the page are in
test_activity_chain_written.py.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
from typing import Any

from qkvm import chain
from qkvm.chain import ZERO, Walk

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))  # somebody's own, who has the data folder and not the vault


class Log:
    """A log as the writer makes it: entries oldest first, each as a download hands it over (the line read back)."""

    def __init__(self, key: bytes = KEY, number: int = 0, head: bytes = ZERO) -> None:
        self.key, self.number, self.head = key, number, head
        self.entries: list[dict[str, Any]] = []
        self.heads: dict[int, bytes] = {}  # what a collector kept of each line (syslog)
        self.clock = 1763300000.0

    def write(self, event: str, **detail: Any) -> dict[str, Any]:
        self.clock += 1.5
        line = json.dumps({"time": self.clock, "event": event, "ip": "192.0.2.10", **detail}) + "\n"
        self.number += 1
        stamped, self.head = chain.stamp(line, json.loads(line), self.number, self.head, self.key)
        entry = json.loads(stamped)
        self.entries.append(entry)
        self.heads[self.number] = self.head
        return entry

    def seal(self, why: str, **detail: Any) -> dict[str, Any]:
        return self.write(chain.SEALED, why=why, **detail)

    def busy(self, count: int) -> None:
        for number in range(count):
            self.write(("login", "action", "device_changed", "alert")[number % 4], user="olga", device="rack1-node02", device_id="0a1b2c3d")


def check(entries: list[dict[str, Any]], key: bytes | None = KEY, anchors: dict[int, bytes] | None = None, part: bool = False) -> chain.Verdict:
    walk = Walk(key, anchors, part=part)
    for entry in entries:
        walk.take(entry)
    return walk.end()


def problems(verdict: chain.Verdict) -> list[tuple[int | None, str]]:
    return [(problem.line, problem.what) for problem in verdict.problems]


def plain(count: int, start: float = 1700000000.0) -> list[dict[str, Any]]:
    """Lines an earlier version wrote: no chain."""
    return [{"time": start + number, "event": "login", "ip": "192.0.2.20", "user": f"user{number % 3}"} for number in range(count)]


def a_log(lines: int = 40) -> Log:
    """A wall's log from its first line: the genesis seal (nothing before it), a start, lines, a stop."""
    log = Log()
    log.seal("genesis", before=0, files=[], key=chain.key_id(KEY))
    log.seal("start", key=chain.key_id(KEY))
    log.busy(lines)
    log.seal("stop")
    return log


# --- the canonical form -------------------------------------------------------------------------------------------


def test_the_same_line_hashes_the_same_on_every_system_and_python() -> None:
    # Written down once (on Windows, Python 3.14) and asked of every system and Python the tests run on: the canonical form
    # and the head after a line are part of the format, and a log written on one has to check on another.
    entry = {"time": 1763300000.123456, "event": "login", "ip": "192.0.2.1", "user": chr(0xD6) + "lga " + chr(0x1F512), "zeta": [1, 2.5, None, True], "alpha": {"b": 1e-07, "a": -0.0}}
    form = b'{"alpha":{"a":-0.0,"b":1e-07},"event":"login","ip":"192.0.2.1","time":1763300000.123456,"user":"\\u00d6lga \\ud83d\\udd12","zeta":[1,2.5,null,true]}'
    assert chain.canonical(entry) == form
    assert chain.canonical({**entry, "chain": {"n": 1, "prev": "00" * 32, "mac": "00" * 16}}) == form  # (its own place is not part of it)
    # The head as the guide says it is made, by hand: a label, the head before (32 bytes), the number (8 bytes), the SHA-256
    # of the canonical form.
    by_hand = hashlib.sha256(b"qkvm activity log link 1\n" + bytes(32) + (1).to_bytes(8, "big") + hashlib.sha256(form).digest()).digest()
    head = chain.link(ZERO, 1, chain.digest(entry))
    assert head == by_hand and head.hex() == "2b1eae8c27384202b963a1db44d1220b3a5d643e729662d551020476afa7b3a4"
    assert chain.signature(KEY, head) == hmac.new(KEY, b"qkvm activity log mac 1\n" + head, hashlib.sha256).hexdigest()[:32] == "2ab1631e1b3da275a7eeb8a759c97844"
    assert chain.key_id(KEY) == "d2d59f5cf3e62266"


def test_a_line_reads_back_the_same_from_the_file_and_from_a_download() -> None:
    # A download writes each entry again its own way (json.dumps with ensure_ascii=False, the fields as they were read), and
    # the head is to be the one the writer worked out.
    log = Log()
    written = log.write("login", user=chr(0xD6) + "lga", note="a \"quoted\" word\tand a tab", count=3, share=0.1)
    again = json.loads(json.dumps(written, ensure_ascii=False))
    assert list(again) == list(written) and chain.digest(again) == chain.digest(written)
    assert check([again]).intact


# --- a log as the wall writes it ------------------------------------------------------------------------------------


def test_a_log_nobody_touched_checks_intact() -> None:
    log = a_log()
    verdict = check(log.entries, anchors=log.heads)
    assert verdict.intact, verdict.summary()
    assert (verdict.first, verdict.last, verdict.chained, verdict.matched) == (1, 43, 43, 43)
    assert verdict.head == log.head.hex() and verdict.key_fits is True
    assert verdict.summary().startswith("Intact: lines 1 to 43, with their signatures")
    assert check(log.entries, key=None).intact  # (without the key, how the lines hang together)


def test_a_changed_field_is_caught() -> None:
    log = a_log()
    changed = copy.deepcopy(log.entries)
    changed[20]["user"] = "ivan"  # who did it
    verdict = check(changed)
    assert problems(verdict) == [(21, "unsigned")], verdict.summary()
    assert verdict.summary().startswith("Broken at line 21: line 21 is not as the wall wrote it")
    # Without the key, by the link of the line after it.
    assert problems(check(changed, key=None)) == [(21, "changed")]
    # The time, a number: to the millionth of a second.
    changed = copy.deepcopy(log.entries)
    changed[30]["time"] += 0.000001
    assert problems(check(changed)) == [(31, "unsigned")]
    # A field added.
    changed = copy.deepcopy(log.entries)
    changed[10]["note"] = "nothing happened"
    assert problems(check(changed)) == [(11, "unsigned")]
    # Its number changed, to make it another line.
    changed = copy.deepcopy(log.entries)
    changed[10]["chain"]["n"] = 99
    assert problems(check(changed)) == [(11, "missing"), (99, "unsigned")]


def test_a_line_taken_out_is_caught() -> None:
    log = a_log()
    taken = log.entries[:20] + log.entries[21:]
    assert problems(check(taken)) == [(21, "missing")]
    assert problems(check(taken, key=None)) == [(21, "missing")]
    several = log.entries[:20] + log.entries[25:]
    assert problems(check(several)) == [(21, "missing")] and "lines 21 to 25 are missing" in check(several).summary()


def test_two_lines_swapped_are_caught() -> None:
    log = a_log()
    swapped = list(log.entries)
    swapped[20], swapped[21] = swapped[21], swapped[20]
    verdict = check(swapped)
    assert problems(verdict) == [(21, "order")], verdict.summary()
    assert "out of its order" in verdict.summary()


def test_a_line_put_in_is_caught() -> None:
    log = a_log()
    # Without the chain: as an earlier version wrote, or by hand.
    put_in = log.entries[:20] + [{"time": log.entries[19]["time"] + 0.5, "event": "login", "ip": "192.0.2.66", "user": "admin"}] + log.entries[20:]
    assert problems(check(put_in)) == [(21, "inserted")]
    assert problems(check(put_in, key=None)) == [(21, "inserted")]
    # With the chain, made up by somebody without the key: its link fits, and its signature does not.
    forged = Log(OTHER_KEY, number=20, head=log.heads[20])
    made_up = forged.write("login", user="admin")
    verdict = check([*log.entries[:20], made_up, *log.entries[20:]])
    assert problems(verdict)[:1] == [(21, "unsigned")] and not verdict.intact


def test_the_end_written_anew_without_the_key_is_caught() -> None:
    # Somebody with the data folder and not the vault rewrites the log from line 21 on: lines changed, taken out, put in,
    # and the chain worked out again from there, so that every link fits. It checks without the key; with it, it does not.
    log = a_log()
    again = Log(OTHER_KEY, number=20, head=log.heads[20])
    for entry in log.entries[20:]:
        if entry["event"] == "action":
            continue  # what was done to the machines, gone
        detail = {key: value for key, value in entry.items() if key not in ("time", "event", "ip", "chain")}
        again.write(entry["event"], **detail)
    rewritten = log.entries[:20] + again.entries
    assert check(rewritten, key=None).intact  # (this is what the key is for)
    verdict = check(rewritten)
    assert problems(verdict)[0] == (21, "unsigned") and not verdict.intact
    assert verdict.key_fits is True  # (the key given is the log's: its seals before line 21 say so)


def test_a_log_written_anew_with_the_key_is_caught_by_a_head_kept_outside() -> None:
    # Whoever holds the vault as well can write the log anew from any line, and sign it: it checks with the key. The heads
    # that went out as it was written (syslog, the daily seal) do not fit it.
    log = a_log()
    kept = dict(log.heads)
    again = Log(KEY, number=20, head=log.heads[20])
    for entry in log.entries[20:]:
        detail = {key: value for key, value in entry.items() if key not in ("time", "event", "ip", "chain")}
        if detail.get("user") == "olga":
            detail["user"] = "ivan"
        again.write(entry["event"], **detail)
    rewritten = log.entries[:20] + again.entries
    assert check(rewritten).intact
    verdict = check(rewritten, anchors=kept)
    assert problems(verdict)[0] == (21, "anchor"), verdict.summary()
    # One head kept, the last one written: enough.
    assert problems(check(rewritten, anchors={43: kept[43]})) == [(43, "anchor")]
    # The end cut off, the last lines taken away and nothing put in their place: the log ends before a head kept outside. Of
    # the whole log, that is lines cut off its end. A download ends where it was made, and lines written after it are kept
    # outside too: checked as a part of the log (the person's word, never the order of its lines: the outside review of
    # 0.4.0, M3), that is said, with how far the log is known to go, and is not broken.
    assert problems(check(log.entries[:30], anchors={43: kept[43]})) == [(31, "cut")]
    verdict = check(log.entries[:30], anchors={43: kept[43]}, part=True)
    assert verdict.intact and "name lines after this log's last line (30), up to line 43" in verdict.notes[0]
    assert (verdict.part, verdict.later) == (True, 43) and "not proved complete" in verdict.summary()
    # Once the wall writes on after such a cut (at its next start, from the last line left), the numbers it gives again do
    # not fit the heads kept outside.
    on = Log(KEY, number=30, head=log.heads[30])
    on.seal("start", key=chain.key_id(KEY))
    on.busy(5)
    assert problems(check(log.entries[:30] + on.entries, anchors=kept))[0] == (31, "anchor")


def test_the_end_cut_off_while_the_wall_runs_is_caught_by_its_own_head() -> None:
    log = a_log()
    walk = Walk(KEY, own=(43, log.heads[43]))
    for entry in log.entries[:35]:
        walk.take(entry)
    assert problems(walk.end()) == [(36, "cut")]


# --- what was there before the chain, and what the log lets go ------------------------------------------------------


def from_before(files: list[list[dict[str, Any]]]) -> Log:
    """A log whose files an earlier version wrote (oldest first), taken in by the genesis seal of 0.4.0's first line."""
    cuts: list[list[Any]] = []
    number, head = 1, ZERO
    for file in files:
        number, head = chain.virtual(head, number, (chain.digest(entry) for entry in file))
        cuts.append([number - 1, head.hex()])
    log = Log(number=number - 1, head=head)
    log.seal("genesis", before=number - 1, files=cuts, key=chain.key_id(KEY))
    log.seal("start", key=chain.key_id(KEY))
    log.busy(10)
    return log


def test_lines_from_before_the_chain_are_from_before_it_and_never_broken() -> None:
    files = [plain(30), plain(25, 1700001000.0), plain(5, 1700002000.0)]
    log = from_before(files)
    entries = [*files[0], *files[1], *files[2], *log.entries]
    verdict = check(entries)
    assert verdict.intact, verdict.summary()
    assert (verdict.before, verdict.first, verdict.last) == (60, 61, 72)
    assert "60 from before the chain" in verdict.summary()
    # One of them changed since: said, and of all of them (they carry no chain of their own).
    changed = copy.deepcopy(entries)
    changed[7]["user"] = "admin"
    assert problems(check(changed)) == [(61, "before")]
    # One taken out.
    assert problems(check(entries[:7] + entries[8:])) == [(61, "before")]


def test_files_from_before_the_chain_let_go_as_the_log_grows_are_not_missing() -> None:
    files = [plain(30), plain(25, 1700001000.0), plain(5, 1700002000.0)]
    log = from_before(files)
    # The oldest file went, and the seal of pruning said so (written before it went: see AuditLog._append).
    log.seal("pruned", let_go=30, to=None, head=None)
    verdict = check([*files[1], *files[2], *log.entries])
    assert verdict.intact, verdict.summary()
    assert (verdict.before, verdict.let_go) == (30, 30)
    # Gone without a seal (removed by hand): said.
    unsealed = from_before(files)
    assert problems(check([*files[1], *files[2], *unsealed.entries])) == [(1, "pruned")]
    # Half of a file gone: no file of them ended there.
    assert problems(check([*files[0][15:], *files[1], *files[2], *log.entries])) == [(61, "before")]


def test_lines_with_the_chain_let_go_as_the_log_grows_are_not_missing() -> None:
    log = a_log(60)
    # The oldest file held lines 1 to 25; the seal of pruning names its last line and the head after it.
    log.seal("pruned", let_go=25, to=25, head=log.heads[25].hex())
    kept = log.entries[25:]
    verdict = check(kept)
    assert verdict.intact, verdict.summary()
    assert (verdict.first, verdict.let_go) == (26, 25)
    assert "lines 1 to 25 let go as the log grew" in verdict.summary()
    # Without that seal: the oldest lines are gone, and nothing says why.
    unsealed = a_log(60)
    assert problems(check(unsealed.entries[25:])) == [(26, "pruned")]
    # A seal that does not fit what is left.
    wrong = a_log(60)
    wrong.seal("pruned", let_go=25, to=25, head=wrong.heads[24].hex())
    assert problems(check(wrong.entries[25:])) == [(26, "seal")]
    # More taken away than the seal let go.
    assert problems(check(log.entries[30:])) == [(31, "pruned")]


def test_lines_without_the_chain_taken_in_at_a_later_start_are_not_put_in() -> None:
    # An earlier version run in between (an update rolled back, `qkvm --roll-back`) wrote lines without the chain after it;
    # the next start of this one took them in with a seal of their own.
    log = a_log(10)
    between = plain(4, log.clock + 10)
    after, head = chain.virtual(log.head, log.number + 1, (chain.digest(entry) for entry in between))
    later = Log(number=after - 1, head=head)
    later.seal("unchained", count=4, key=chain.key_id(KEY))
    later.seal("start", key=chain.key_id(KEY))
    later.busy(3)
    entries = [*log.entries, *between, *later.entries]
    verdict = check(entries)
    assert verdict.intact, verdict.summary()
    assert verdict.unchained == 4 and verdict.last == later.number
    # One of them changed since it was taken in.
    changed = copy.deepcopy(entries)
    changed[len(log.entries) + 1]["user"] = "admin"
    assert problems(check(changed)) == [(log.number + 5, "seal")]


def test_a_run_that_ended_without_its_stop_seal_is_said_and_is_not_broken() -> None:
    log = Log()
    log.seal("genesis", before=0, files=[], key=chain.key_id(KEY))
    log.seal("start", key=chain.key_id(KEY))
    log.busy(5)
    log.seal("start", key=chain.key_id(KEY))  # (a power cut before it)
    log.busy(5)
    verdict = check(log.entries)
    assert verdict.intact and len(verdict.notes) == 1 and "line 2 ended without its stop seal" in verdict.notes[0]


def test_a_key_that_is_not_the_logs_is_told_apart() -> None:
    log = a_log()
    verdict = check(log.entries, key=OTHER_KEY)
    assert verdict.key_fits is False and not verdict.intact


def test_heads_kept_outside_are_read_from_what_a_collector_kept() -> None:
    log = a_log(5)
    syslog = "\n".join(f"<109>1 2026-11-16T10:00:00.000Z wall qkvm - {entry['event']} - {json.dumps(entry)}" for entry in log.entries)
    assert chain.anchors_in(syslog) == log.heads
    said = f"qKVM activity log seal: line 7 head {log.heads[7].hex()}\n8 {log.heads[8].hex()}\nsomething else entirely\n"
    assert chain.anchors_in(said) == {7: log.heads[7], 8: log.heads[8]}


# --- what is taken in without the chain (the review of wave 2, H1) -------------------------------------------------


def test_lines_without_the_chain_are_taken_in_only_after_a_stop_and_never_seals() -> None:
    # Whoever holds the key can sign anything (the writer never takes such lines in now: test_activity_chain_written); the
    # check holds a seal that takes lines in to the same rules all the same.
    log = Log()
    log.seal("genesis", before=0, files=[], key=chain.key_id(KEY))
    log.seal("start", key=chain.key_id(KEY))
    log.busy(5)  # (no stop seal: the run did not stop here)
    between = plain(2, log.clock + 10)
    after, head = chain.virtual(log.head, log.number + 1, (chain.digest(entry) for entry in between))
    later = Log(number=after - 1, head=head)
    later.seal("unchained", count=2, key=chain.key_id(KEY))
    later.busy(2)
    verdict = check([*log.entries, *between, *later.entries])
    assert problems(verdict) == [(10, "seal")] and "where the wall did not stop" in verdict.problems[0].said
    # After a stop seal, and one of them a seal with its chain taken away.
    log.seal("stop")
    stripped = {key: value for key, value in log.seal("hourly").items() if key != "chain"}
    log.entries.pop()
    log.number -= 1
    log.head = chain.link(bytes.fromhex(log.entries[-1]["chain"]["prev"]), log.number, chain.digest(log.entries[-1]))
    between = [stripped, *plain(1, log.clock + 10)]
    after, head = chain.virtual(log.head, log.number + 1, (chain.digest(entry) for entry in between))
    later = Log(number=after - 1, head=head)
    later.seal("unchained", count=2, key=chain.key_id(KEY))
    verdict = check([*log.entries, *between, *later.entries])
    assert [what for _, what in problems(verdict)] == ["seal"] and "seals of the chain with their chain taken away" in verdict.problems[0].said


def test_a_genesis_over_seals_whose_chain_was_taken_away_is_broken() -> None:
    before = plain(3)
    before.insert(1, {"time": 1700000000.5, "event": chain.SEALED, "ip": "", "why": "stop"})
    after, head = chain.virtual(ZERO, 1, (chain.digest(entry) for entry in before))
    log = Log(number=after - 1, head=head)
    log.seal("genesis", before=4, files=[[4, head.hex()]], key=chain.key_id(KEY))
    verdict = check([*before, *log.entries])
    assert [what for _, what in problems(verdict)] == ["before"] and "the chain was begun again over a log that had one" in verdict.summary()


def test_what_the_writer_found_wrong_at_its_start_is_a_problem_and_what_follows_is_checked() -> None:
    log = a_log(5)
    stripped = [{key: value for key, value in entry.items() if key != "chain"} for entry in plain(2, log.clock + 5)]
    after, head = chain.virtual(log.head, log.number + 1, (chain.digest(entry) for entry in stripped))
    later = Log(number=after - 1, head=head)
    later.seal("broken", count=2, said="the chain ends at line 8, and the wall had written it up to line 9", key=chain.key_id(KEY))
    later.busy(3)
    entries = [*log.entries, *stripped, *later.entries]
    verdict = check(entries)
    assert problems(verdict) == [(11, "found")] and "the wall had written it up to line 9" in verdict.problems[0].said
    # (What follows it is checked as ever: a line changed after it is said too.)
    changed = copy.deepcopy(entries)
    changed[-1]["user"] = "ivan"
    assert problems(check(changed)) == [(11, "found"), (14, "unsigned")]
