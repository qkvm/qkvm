"""The activity log's chain (0.4.0): a line that is changed, taken out, moved or put in shows, and so does a log cut short.

Every line the wall writes carries, in a field of its own (`chain`), its number, the head of the chain before it and a
signature:

    "chain": {"n": 1234, "prev": "<64 hex digits>", "mac": "<32 hex digits>"}

The head after a line is SHA-256 over what came before and the line itself (`link`): the head before it (32 bytes), the
line's number (8 bytes, the highest first) and the SHA-256 of the line in its canonical form (`canonical`), with a label
before them all. The canonical form is the line's fields without `chain`, as JSON with the names in the order of their
characters (Unicode code points), no blanks, every character beyond ASCII written as a \\u escape (two for one beyond
\\uffff), integers in decimal and other numbers in the shortest form that reads back the same (as Python and every JSON
writer of the last decade writes them: 1763300000.123456, 0.1, 1e-07). So the same line hashes the same, whichever
system and whichever Python 3.11 to 3.14 wrote or reads it, and whether it is read from the file or from a download
(JSON lines), which writes the fields again its own way.

The signature is HMAC-SHA256 over the head, with a key that is not in the data folder: it is kept in the wall's
settings, which are sealed with the vault key (outside the data folder: vault_storage). A chain alone can be worked out
again by whoever rewrites the file; signed, rewriting it needs the vault as well. The first 16 bytes of it are kept:
whoever does not have the key has one chance in 2**128 of guessing one.

What came before the chain (the lines an earlier version wrote) is chained as it is found, without being written again:
numbered from the first line of the oldest file, its head worked out the same way, and named in the first line the chain
has, its genesis seal (`log_sealed`, why "genesis"), with the head after each of its files (so that the oldest files can
go, as the log lets them go, without the rest looking changed). Lines without the chain found after it (an earlier
version run in between) are taken in the same way at the next start, in a seal of their own (why "unchained").

Seals (`log_sealed`) are lines of the chain like any other, written by the wall: at its start and its end, every hour
something was written, before the oldest file goes (why "pruned": what is let go, and the head the rest goes on from),
and once a day for the alert destinations that asked for it. Their heads, and every line's, go where the log is sent
(syslog); kept there, they show even a log that was written anew with the key.

The wall keeps where its chain had come to (the line and head of its last seal) in its sealed settings as well, and its
writer holds the files to that before its first line. What it finds wrong there (the chain ending earlier, another line at
that place, no chain left, lines without the chain where the wall did not stop, seals with their chain taken away) it says
in a seal of its own (why "broken"), which every check counts as a problem: whoever edits the files without the vault key
cannot have the wall take an edit in. Lines without the chain are taken in ("unchained") only right after a stop seal, and
only where none of them is a seal (an earlier version run while this one was stopped); a genesis only where the settings
know of no chain. Lines taken in so are said as such, never as plainly intact: nothing proves who wrote them.

`Walk` checks a log, its lines oldest first, from the files or from a download: nothing here reads or writes a file.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

FIELD = "chain"  # the field of a line that holds its place in the chain
SEALED = "log_sealed"  # the event of a seal
CHECKED = "log_checked"  # the event of a check of the log made on the page
ZERO = bytes(32)  # the head before the first line there ever was
KEY_BYTES = 32
MAC_HEX = 32  # hex digits of a line's signature that are kept (16 bytes)
_LINK = b"qkvm activity log link 1\n"
_MAC = b"qkvm activity log mac 1\n"
_KEY_ID = b"qkvm activity log key id 1\n"
_HEX = re.compile(r"[0-9a-f]+")
MOST_KEPT = 1000  # problems a check keeps; beyond that they are counted
MOST_GAPS = 10_000  # runs of numbers not seen (yet) that a check keeps


def new_key() -> bytes:
    return secrets.token_bytes(KEY_BYTES)


def key_id(key: bytes) -> str:
    """What a key is known by in the seals: of no use to whoever has it and not the key (an HMAC of a label)."""
    return hmac.new(key, _KEY_ID, hashlib.sha256).hexdigest()[:16]


def canonical(entry: Mapping[str, Any]) -> bytes:
    """A line's fields but `chain`, in the one form that is hashed (see the module's words)."""
    fields = {name: value for name, value in entry.items() if name != FIELD}
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(entry: Mapping[str, Any]) -> bytes:
    return hashlib.sha256(canonical(entry)).digest()


def link(prev: bytes, number: int, entry_digest: bytes) -> bytes:
    """The head of the chain after line `number`, which follows `prev` and whose canonical form has `entry_digest`."""
    return hashlib.sha256(_LINK + prev + number.to_bytes(8, "big") + entry_digest).digest()


def signature(key: bytes, head: bytes) -> str:
    return hmac.new(key, _MAC + head, hashlib.sha256).hexdigest()[:MAC_HEX]


def virtual(head: bytes, first: int, digests: Iterable[bytes]) -> tuple[int, bytes]:
    """Lines without the chain, chained from `head` as they are, numbered from `first`: (the number after them, the head)."""
    number = first
    for one in digests:
        head = link(head, number, one)
        number += 1
    return number, head


def hex_head(text: Any) -> bytes | None:
    """A head as a seal or an anchor writes it (64 hex digits), or None where it is none."""
    if isinstance(text, str) and len(text) == 64 and _HEX.fullmatch(text):
        return bytes.fromhex(text)
    return None


def _number(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2**63 else None


@dataclass(frozen=True)
class Link:
    """A line's `chain` field, read. `number` 0: the field is there and is none the wall writes (damaged, or made up)."""

    number: int
    prev: bytes
    mac: str

    @staticmethod
    def of(entry: Mapping[str, Any]) -> Link | None:
        said = entry.get(FIELD)
        if said is None:
            return None
        if isinstance(said, dict):
            number, prev, mac = _number(said.get("n")), hex_head(said.get("prev")), said.get("mac")
            if number and prev is not None and isinstance(mac, str) and len(mac) == MAC_HEX and _HEX.fullmatch(mac):
                return Link(number, prev, mac)
        return Link(0, ZERO, "")


def stamp(line: str, entry: Mapping[str, Any], number: int, prev: bytes, key: bytes) -> tuple[str, bytes]:
    """A line as the writer made it (one JSON object and its line feed) with its place in the chain added at its end, and
    the head after it. `entry`: the line as it is read back (store.entry_of), which is what is hashed."""
    head = link(prev, number, digest(entry))
    said = json.dumps({"n": number, "prev": prev.hex(), "mac": signature(key, head)}, separators=(",", ":"))
    body = line.rstrip("\n")
    return f'{body[:-1]}, "{FIELD}": {said}}}\n', head


# --- checking -------------------------------------------------------------------------------------------------------


@dataclass
class Problem:
    line: int | None  # the number of the line it is about, where there is one
    what: str  # changed, unsigned, missing, order, inserted, before, pruned, seal, anchor, cut
    said: str

    def as_dict(self) -> dict[str, Any]:
        return {"line": self.line, "what": self.what, "said": self.said}


@dataclass
class Verdict:
    """What a check found. Intact where it found nothing wrong."""

    entries: int = 0  # entries read
    chained: int = 0  # ...of them with the chain
    before: int = 0  # ...from before the chain, held to its genesis seal
    unchained: int = 0  # ...without the chain after it, taken in by a seal at the next start (an earlier version ran): not proved
    unchained_after: int | None = None  # the stop seal after which the first of those came
    first: int | None = None  # the number of the first line there is
    last: int | None = None  # ...and of the last
    head: str | None = None  # the head after the last line (hex)
    let_go: int = 0  # lines before the first that the log let go of, as its seals say
    keyed: bool = False  # the signatures were checked (a key was given)
    key_ids: list[str] = field(default_factory=list)  # the keys the log's seals name (key_id), the first first
    key_fits: bool | None = None  # whether the key given is one of those (None: no key given, or no seal names one)
    anchors: int = 0  # heads given from outside the log (and the wall's own, on the page) that fall within it
    matched: int = 0  # ...of them, the ones the log holds
    problems: list[Problem] = field(default_factory=list)  # the first MOST_KEPT, by line
    more: int = 0  # problems beyond those
    notes: list[str] = field(default_factory=list)  # nothing wrong, and worth knowing
    part: bool = False  # checked as a part of the log (a download: Walk's part), as the person asked; else as the whole of it
    later: int | None = None  # (a part) the last line known to come after its last (the wall's settings, a head kept outside)

    @property
    def intact(self) -> bool:
        return not self.problems and not self.more

    def as_dict(self, most: int = MOST_KEPT) -> dict[str, Any]:
        return {
            "intact": self.intact, "entries": self.entries, "chained": self.chained, "before": self.before, "unchained": self.unchained,
            "unproved": self.unchained,  # (lines taken in without proof: where not 0, never plainly intact)
            "first": self.first, "last": self.last, "head": self.head, "let_go": self.let_go, "keyed": self.keyed,
            "key_fits": self.key_fits, "anchors": self.anchors, "matched": self.matched,
            "problems": [problem.as_dict() for problem in self.problems[:most]], "more": self.more + max(0, len(self.problems) - most),
            "notes": self.notes[:20],
            "part": self.part, "later": self.later,  # (where `later` is a number, not proved complete: never plainly intact)
        }  # fmt: skip

    def summary(self) -> str:
        """In a sentence."""
        if not self.chained:
            return "No line of this log has the chain: it was written before 0.4.0, or is no activity log of qKVM's"
        span = f"lines {self.first} to {self.last}" if self.first != self.last else f"line {self.first}"
        if self.intact:
            how = "with their signatures" if self.keyed else "their links only (no key was given: signatures not checked)"
            besides = []
            if self.before:
                besides.append(f"{self.before} from before the chain, as they were when it began")
            if self.let_go:
                besides.append(f"lines 1 to {self.let_go} let go as the log grew, as its seals say")
            more = f" ({'; '.join(besides)})" if besides else ""
            # (A part of the log, where more of it is known: intact as far as it goes, never said to be the whole.)
            goes_on = (
                f"; the log is known to go on to line {self.later}, which this part does not hold (written after it was made, or cut off its end)"
                if self.later is not None else ""
            )  # fmt: skip
            if self.unchained:
                # (Not plainly intact: nothing proves who wrote them, only that they are as they were when the wall started again.)
                return (
                    f"Intact where it is chained, and not all of it proved: {self.unchained} {'line' if self.unchained == 1 else 'lines'} written "
                    f"without the chain after the wall stopped at line {self.unchained_after} (an earlier version of qKVM run in between, or put in "
                    f"by somebody while it was stopped) were taken in at its next start as they were found. {span[0].upper()}{span[1:]}, {how}{more}; head {self.head}{goes_on}"
                )
            if self.later is not None:
                return f"Intact as far as it goes, and not proved complete: {span}, {how}{more}; head {self.head}{goes_on}"
            return f"Intact: {span}, {how}{more}; head {self.head}"
        first = self.problems[0] if self.problems else None
        at = f" at line {first.line}" if first is not None and first.line is not None else ""
        count = len(self.problems) + self.more
        others = f" ({count - 1} more {'problem' if count == 2 else 'problems'} below)" if count > 1 else ""
        return f"Broken{at}: {first.said if first else 'see below'}{others}"


class Walk:
    """A check of an activity log: its entries handed over one at a time, the oldest first (`take`), and then `end`.

    `key`: the log's key, to check each line's signature (without it, only how the lines hang together is checked).
    `anchors`: heads kept outside the log (number -> head), each held to the line of that number; and `own`, the wall's
    own head as its writer last wrote it, held to the log the same way (on the page). Memory: the lines without the chain
    between two chained ones, 32 bytes each, and so many problems and gaps at the most."""

    def __init__(
        self,
        key: bytes | None = None,
        anchors: Mapping[int, bytes] | None = None,
        own: tuple[int, bytes] | None = None,
        kept: tuple[int, bytes] | None = None,
        part: bool = False,
    ) -> None:
        self.key = key
        self.anchors = dict(anchors or {})
        self.own = own
        # Where the wall's sealed settings say its chain had come to (its last seal): the log is held to it, as the wall holds
        # it at its start (checklog --data-dir, and the page's check; the re-review of wave 2, N2).
        self.kept = kept
        # ...and whether the log given is a part of it, which ends where it was made (a download), as the person checking it
        # says (checklog --part), never as its lines say: a line known to come after its last (the kept place, a head kept
        # outside) is then said (Verdict.later), and the verdict is not that it is complete. Otherwise the log given is the
        # whole of it, and lines known to come after its end are lines cut off it, a problem, in whatever order its lines came:
        # the order of a download was taken from the lines themselves, and a log cut back and turned round checked intact
        # against its data folder (the outside review of 0.4.0, M3).
        self.part = part
        self.verdict = Verdict(keyed=key is not None, part=part)
        self._pending: list[bytes] = []  # digests of the lines without the chain since the last chained one
        self._expect: tuple[int, bytes] | None = None  # (the number the next line should have, the head it should follow)
        self._top = 0  # the highest number seen
        self._gaps: dict[int, int] = {}  # numbers jumped over, not seen since: first -> last
        self._reported: int | None = None  # the last line found wrong itself: the next one's link to it is not said again
        self._start: tuple[int, bytes, int] | None = None  # the first chained line: its number, prev, and lines without the chain before it
        self._start_digests: list[bytes] = []  # ...those lines, where they are to be held to a seal found later (see end)
        self._genesis_let_go: int | None = None  # lines from before the chain that are gone, by the genesis seal
        self._pruned: dict[int, bytes] = {}  # what the seals of pruning say: the last line let go -> the head after it
        self._pruned_before = 0  # ...and how many lines from before the chain they let go
        self._run: int | None = None  # the line of the last start seal with no stop seal after it
        self._pending_seals = 0  # of the lines without the chain since the last chained one, those that are seals (their chain taken away)
        self._stopped: int | None = None  # the last chained line, where it is a stop seal

    # --- what is found --------------------------------------------------------------------------------------------

    def _problem(self, line: int | None, what: str, said: str) -> None:
        if len(self.verdict.problems) < MOST_KEPT:
            self.verdict.problems.append(Problem(line, what, said))
        else:
            self.verdict.more += 1

    def _gap(self, first: int, last: int) -> None:
        if len(self._gaps) < MOST_GAPS:
            self._gaps[first] = last
        else:
            self._problem(first, "missing", f"lines {first} to {last} are missing" if last > first else f"line {first} is missing")

    def _filled(self, number: int) -> bool:
        """Whether `number` was jumped over before: it is then no longer missing, only out of its order."""
        for first, last in self._gaps.items():
            if first <= number <= last:
                del self._gaps[first]
                if first < number:
                    self._gaps[first] = number - 1
                if number < last:
                    self._gaps[number + 1] = last
                return True
        return False

    # --- reading ----------------------------------------------------------------------------------------------------

    def take(self, entry: Mapping[str, Any]) -> None:
        """The next entry of the log (as store.entry_of reads a line)."""
        verdict = self.verdict
        verdict.entries += 1
        found = Link.of(entry)
        if found is None:
            self._pending.append(digest(entry))
            if entry.get("event") == SEALED:
                self._pending_seals += 1
            return
        if not found.number:
            at = self._expect[0] if self._expect is not None else None
            self._problem(at, "changed", f"a line{f' where line {at} belongs' if at else ''} has chain fields the wall never writes (changed, or made up)")
            self._reported = at
            return
        number = found.number
        head = link(found.prev, number, digest(entry))
        signed = True
        if self.key is not None and not hmac.compare_digest(signature(self.key, head), found.mac):
            signed = False
            self._problem(number, "unsigned", f"line {number} is not as the wall wrote it: its signature does not match (changed, or written by someone without the key)")
            if self._expect is not None and number != self._expect[0] and not self._pending:
                verdict.chained += 1
                return  # (a number the wall would not have given it here: what comes next is held to the line before it)
        if self._pending:
            self._unchained(entry, number, found.prev)
        elif self._expect is None:
            self._start = (number, found.prev, 0)
        else:
            if not self._follow(number, found.prev):
                return  # (out of its order: what comes next is held to the line before it, not to this one)
        if entry.get("event") == SEALED:
            self._seal(entry, number)
        if number in self.anchors:
            verdict.anchors += 1
            if self.anchors[number] == head:
                verdict.matched += 1
            else:
                self._problem(number, "anchor", f"line {number} is not as it was when its head was kept outside the wall (the log was written anew from there on)")
        if self.kept is not None and number == self.kept[0] and self.kept[1] != head:
            self._problem(number, "found", f"line {number} is not the line the wall's settings say it wrote there (changed, or the log written anew from there on)")
        if self.own is not None and number == self.own[0] and self.own[1] != head:
            self._problem(number, "changed", f"line {number} is not the line this wall wrote as its last (changed while it ran)")
        verdict.chained += 1
        if verdict.first is None:
            verdict.first = number
        self._expect = (number + 1, head)
        self._top = max(self._top, number)
        verdict.last, verdict.head = number, head.hex()
        self._reported = None if signed else number
        self._stopped = number if entry.get("event") == SEALED and entry.get("why") == "stop" else None

    def _follow(self, number: int, prev: bytes) -> bool:
        """A chained line after a chained one: its number and its link. False where it is out of its order."""
        assert self._expect is not None
        expected, head = self._expect
        if number == expected:
            if prev != head and self._reported != number - 1:
                self._problem(number - 1, "changed", f"line {number - 1} is not as the wall wrote it: line {number} follows another")
            return True
        if number > expected:
            self._gap(expected, number - 1)  # (missing, or out of its order: told at the end)
            return True
        if self._filled(number):
            self._problem(number, "order", f"line {number} is out of its order: it comes after line {self._top}")
        else:
            self._problem(number, "order", f"line {number} is there twice, or out of its order (it comes after line {self._top})")
        return False

    def _unchained(self, entry: Mapping[str, Any], number: int, prev: bytes) -> None:
        """Lines without the chain came before this chained one: before the chain began (its genesis seal), taken in at a
        start after an earlier version ran (a seal "unchained"), or put in by somebody."""
        pending, self._pending = self._pending, []
        seals, self._pending_seals = self._pending_seals, 0
        count = len(pending)
        why = entry.get("why") if entry.get("event") == SEALED else None
        stripped = f"{seals} of the {count} lines without the chain before line {number} are seals of the chain with their chain taken away"
        if why == "broken":
            # What the writer found at its start (a problem: see _seal), and the lines without the chain it took in with it, so
            # that what comes after is checked as before.
            # (Where they are not as it says, lines with a chain it did not sign were among them: said by those lines and by this
            # seal itself. Nothing more is asked of it: what comes after it is held to it.)
            if self._expect is None:
                self._start = (number, prev, -1)
            self._expect = (number, prev)
            return
        if self._expect is None:
            if why == "genesis":
                if seals:
                    self._problem(number, "before", f"{stripped}: the chain was begun again over a log that had one")
                self._genesis(entry, number, prev, pending)
                return
            if why == "unchained":
                said = _number(entry.get("count"))
                if said is None or count > said:
                    self._problem(number, "seal", f"line {number} says {said} lines without the chain came before it, and {count} do")
                if seals:
                    self._problem(number, "seal", stripped)
                # (The rest of them may have gone as the log grew: held to the seal of pruning that says so, at the end.)
                self._start, self._start_digests = (number, prev, count), pending
                return
            self._problem(number, "inserted", f"{count} {'line' if count == 1 else 'lines'} without the chain at the beginning, before line {number}: put in by somebody")
            self._start = (number, prev, 0)
            return
        expected, head = self._expect
        said = _number(entry.get("count"))
        if why == "unchained" and said == count and number == expected + count:
            after, made = virtual(head, expected, pending)
            if made != prev:
                self._problem(number, "seal", f"the {count} lines without the chain before line {number} are not as they were when it took them in")
            if self._stopped is None:
                self._problem(number, "seal", f"line {number} takes in {count} lines without the chain after line {expected - 1}, where the wall did not stop")
            if seals:
                self._problem(number, "seal", stripped)
            self.verdict.unchained += count
            if self.verdict.unchained_after is None:
                self.verdict.unchained_after = expected - 1
            self._expect = (after, made)
            return
        if why == "unchained":
            self._problem(number, "seal", f"line {number} says {said} lines without the chain came before it, and {count} do")
        else:
            self._problem(expected, "inserted", f"{count} {'line' if count == 1 else 'lines'} without the chain between line {expected - 1} and line {number}: put in by somebody")
        self._follow(number, prev)

    def _genesis(self, entry: Mapping[str, Any], number: int, prev: bytes, pending: list[bytes]) -> None:
        """The lines from before the chain, held to the genesis seal that took them in (the first line of the chain)."""
        verdict = self.verdict
        total = _number(entry.get("before"))
        cuts: dict[int, bytes] = {}
        said = entry.get("files")
        for each in said if isinstance(said, list) else []:
            if isinstance(each, list) and len(each) == 2 and _number(each[0]) is not None and (cut := hex_head(each[1])) is not None:
                cuts[each[0]] = cut
        if total is None or len(pending) > total:
            self._problem(number, "before", f"there are {len(pending)} lines from before the chain, and its genesis seal (line {number}) says {total}")
        else:
            gone = total - len(pending)
            base = ZERO if gone == 0 else cuts.get(gone)
            if base is None:
                self._problem(number, "before", f"{gone} of the {total} lines from before the chain are gone, and they were not a whole file of them: lines were taken out, or put in")
            else:
                if virtual(base, gone + 1, pending)[1] != prev:
                    self._problem(number, "before", f"the lines from before the chain are not as they were when it began (its genesis seal, line {number})")
                self._genesis_let_go = gone
                verdict.let_go = gone
            if number != total + 1:
                self._problem(number, "seal", f"the genesis seal says {total} lines came before it, and it is line {number}")
        verdict.before += len(pending)
        self._start = (number, prev, -1)  # (its beginning is the genesis's: nothing more is asked of it at the end)

    def _seal(self, entry: Mapping[str, Any], number: int) -> None:
        why = entry.get("why")
        key = entry.get("key")
        if isinstance(key, str) and key not in self.verdict.key_ids and len(self.verdict.key_ids) < 20:
            self.verdict.key_ids.append(key)
        if why == "pruned":
            to, head, gone = _number(entry.get("to")), hex_head(entry.get("head")), _number(entry.get("let_go"))
            if to is not None and head is not None:
                self._pruned[to] = head
            elif entry.get("to") is None and gone is not None:
                self._pruned_before += gone
        elif why == "genesis" and self._start is not None and self._start[0] != number:
            self._problem(number, "seal", f"line {number} begins the chain again (a second genesis seal): what came before it was not taken in by it")
        elif why == "broken":
            found = entry.get("said")
            self._problem(number, "found", f"at its start the wall found the log not as it had left it: {found[:500] if isinstance(found, str) else 'see line ' + str(number)}")
        elif why == "start":
            if self._run is not None:
                self.verdict.notes.append(
                    f"The run of the wall that began at line {self._run} ended without its stop seal: a crash, a power cut or the program killed (or lines cut off where it ended)."
                )
            self._run = number
        elif why == "stop":
            self._run = None

    def end(self) -> Verdict:
        """What was found, once every entry is in."""
        verdict = self.verdict
        self._pending_seals = 0
        if self._pending:
            if verdict.chained:
                count = len(self._pending)
                at = self._expect[0] if self._expect is not None else None
                self._problem(at, "inserted", f"{count} {'line' if count == 1 else 'lines'} without the chain after the last line ({verdict.last}): put in by somebody")
            self._pending = []
        for first, last in sorted(self._gaps.items()):
            self._problem(first, "missing", f"lines {first} to {last} are missing" if last > first else f"line {first} is missing")
        self._gaps = {}
        self._beginning()
        if self.key is not None and verdict.key_ids:
            verdict.key_fits = key_id(self.key) in verdict.key_ids
        beyond = [number for number in self.anchors if verdict.last is not None and number > verdict.last]
        if beyond:
            # Lines after this log's last that were kept outside. Of the whole log: cut off its end. Of a part (a download, which
            # ends where it was made): written after it was made, or cut off its end, which cannot be told from here. A log cut
            # short shows there once the wall has written after it: the numbers it then gives again do not fit the heads kept.
            heads = f"{len(beyond)} {'head' if len(beyond) == 1 else 'heads'} kept outside the wall name lines after this log's last line ({verdict.last}), up to line {max(beyond)}"
            if self.part:
                verdict.later = max(beyond)
                verdict.notes.append(f"{heads}: written after it was downloaded, or cut off its end. Compare with when it was downloaded.")
            else:
                self._problem((verdict.last or 0) + 1, "cut", f"{heads}: lines were cut off its end")
        if self.kept is not None and (verdict.last is None or self.kept[0] > verdict.last):
            said = f"the log ends at line {verdict.last}, and the wall's settings say its chain had come to line {self.kept[0]}"
            if self.part:
                verdict.later = max(verdict.later or 0, self.kept[0])
                verdict.notes.append(f"{said[0].upper()}{said[1:]}: lines written after it was downloaded, or cut off its end. Compare with when it was downloaded.")
            else:
                self._problem((verdict.last or 0) + 1, "cut", f"{said}: lines were cut off its end, or their chain taken away")
        if self.own is not None and verdict.last is not None and self.own[0] > verdict.last:
            self._problem(verdict.last + 1, "cut", f"the log ends at line {verdict.last}, and this wall has written up to line {self.own[0]}: lines were cut off its end")
        verdict.problems.sort(key=lambda problem: (problem.line is None, problem.line or 0))
        return verdict

    def _beginning(self) -> None:
        """How the log begins: the first line there ever was, or after lines let go as the log grew, as a seal says."""
        verdict = self.verdict
        if self._start is None:
            return
        number, prev, before = self._start
        if before < 0:  # the genesis seal
            if self._genesis_let_go and self._pruned_before < self._genesis_let_go:
                gone = self._genesis_let_go - self._pruned_before
                self._problem(1, "pruned", f"{gone} lines from before the chain are gone, and no seal says they were let go")
            return
        first = number - before  # (the first line there is, with the lines without the chain before the first chained one)
        if first == 1:
            if before == 0 and prev != ZERO:
                self._problem(number, "seal", f"line {number} says it is the first line there was, and follows another")
            return
        kept = self._pruned.get(first - 1)
        if kept is None:
            self._problem(first, "pruned", f"the log begins at line {first}: the lines before it are gone, and no seal says they were let go")
            return
        if virtual(kept, first, self._start_digests)[1] != prev:
            self._problem(first, "seal", f"the seal that let lines 1 to {first - 1} go says the log goes on from another head than line {first} holds")
            return
        verdict.let_go = first - 1
        verdict.unchained += before
        if before and verdict.unchained_after is None:
            verdict.unchained_after = first - 1
        verdict.first = first if before else verdict.first


def anchors_in(text: str) -> dict[int, bytes]:
    """The heads kept outside the wall in a text (`checklog --heads`): each line one of what a collector kept of the log
    (its entry, as syslog carries it), "line N head HEX" (as the daily seal says it) or "N HEX". Lines that are none of
    those are passed over."""
    found: dict[int, bytes] = {}
    decoder = json.JSONDecoder()
    said = re.compile(r"(?:line\s+)?(\d{1,18})\s*(?:head\s+|[:=,\s]\s*)([0-9a-f]{64})\b")
    for line in text.splitlines():
        brace = line.find("{")
        if brace >= 0:
            try:
                entry, _ = decoder.raw_decode(line, brace)
            except (ValueError, RecursionError):
                entry = None
            if isinstance(entry, dict) and (each := Link.of(entry)) is not None and each.number:
                found[each.number] = link(each.prev, each.number, digest(entry))
                continue
        for match in said.finditer(line):
            found[int(match.group(1))] = bytes.fromhex(match.group(2))
    return found
