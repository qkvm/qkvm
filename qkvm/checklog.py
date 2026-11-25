"""Check the activity log away from the wall, its own files or a download: `python -m qkvm.checklog`.

    python -m qkvm.checklog FILE... [--key-file KEY] [--heads HEADS] [--part] [--json]
    python -m qkvm.checklog FILE... --data-dir DATA [--vault-key-file VAULT_KEY] [--part]
    python -m qkvm.checklog --save-key KEY --data-dir DATA [--vault-key-file VAULT_KEY]

FILE: the log's own files (audit.log.9 to audit.log, the oldest first, in that order), or the activity log as JSON lines, as
the page downloads it (newest first); several are read one after the other. Which way round they are is told from their
lines, and decides nothing else. The check reads them and nothing else: it changes nothing, writes nothing, and asks
nothing of any address.

Without a key, how the lines hang together is checked; with it (`--key-file`, or the wall's own settings with `--data-dir`),
each line's signature too. With `--data-dir` the log is held to the place the wall's sealed settings keep for its chain as
well. `--heads`: heads kept outside the wall (what a syslog collector kept of the log, or the daily seal messages): each is
held to the line it names. `--save-key` writes the log's key into a file of its own, for a check elsewhere: whoever has
that file can write lines that check, so it is kept as the vault key is.

What is given is checked as the whole log: a line known to come after its last (by the settings, or a head kept outside)
means lines cut off its end, whatever order the lines are in. `--part` checks it as what a download is, a part of the log
that ends where it was made: such lines are said, and the verdict is that it is intact as far as it goes and not proved
complete (exit status 4). Only the person checking says so: the order of the lines never does (the outside review of 0.4.0,
M3).

Intact cannot show an older copy of the whole data folder put back (the settings and the log together, from a backup or
a copy of the disk): it is as the wall wrote it then. Heads kept outside the wall (`--heads`) show that.

Exit status: 0 intact, 1 broken, 2 could not check (a file that cannot be read, a table (CSV), a log without the chain, a
key that is not the log's), 3 intact where it is chained, with lines not proved (taken in after the wall stopped: an
earlier version run in between, or lines put in while it was stopped), 4 (--part) intact as far as it goes, and not
proved complete: lines are known to come after it. Where more than one holds, the first of 1, 4, 3, 0 (a part known to go
on that holds lines not proved is 4; its words and its JSON say both).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Iterator
from pathlib import Path

from . import chain
from ._folders import open_private
from .store import Store, entry_of, position_of
from .vault_storage import StorageError

KEY_MAGIC = "QKVM-ACTIVITY-KEY-1:"
MOST_SHOWN = 50  # problems written out; the rest are counted


class CannotCheck(Exception):
    """What keeps a check from being made: said, and the exit status is 2."""


def _lines(paths: list[Path]) -> list[bytes]:
    """The lines of the files, one after the other. (Held in memory, as bytes: a download is newest first, and is checked the
    other way round.)"""
    lines: list[bytes] = []
    for path in paths:
        try:
            data = path.read_bytes()
        except OSError as ex:
            raise CannotCheck(f"{path} cannot be read: {ex.strerror or ex}") from None
        start = data[:200].lstrip()
        if start and not start.startswith(b"{"):
            raise CannotCheck(f"{path} is not the activity log as JSON lines (a table, CSV, cannot be checked: download the JSON lines)")
        lines.extend(data.split(b"\n"))
    return lines


def _newest_first(lines: list[bytes]) -> bool:
    """Whether the lines are newest first (as a download writes them) and not oldest first (as the log's own files are): by
    the numbers of the first and last chained lines. Which way they are read, and nothing more: what the log is held to, and
    whether it is the whole or a part, is the same either way (the outside review of 0.4.0, M3). (Read the wrong way round,
    nothing would hang together: no log is passed as intact for it.)"""

    def numbers(order: Iterator[bytes]) -> int | None:
        for line in order:
            if b'"chain"' in line and (entry := entry_of(line)) is not None and (found := chain.Link.of(entry)) is not None and found.number:
                return found.number
        return None

    first, last = numbers(iter(lines)), numbers(reversed(lines))
    if first is None or last is None:
        raise CannotCheck("no line of it has the chain: it was written before 0.4.0, or is no activity log of qKVM's")
    return first > last


def _ordered(lines: list[bytes], newest_first: bool) -> Iterator[dict[str, object]]:
    """The entries, the oldest first: a download (newest first) is turned round, the log's own files are read as they are."""
    for line in reversed(lines) if newest_first else lines:
        entry = entry_of(line) if line.strip() else None
        if entry is not None:
            yield entry


def read_key(path: Path) -> bytes:
    try:
        text = path.read_bytes()[:300].decode("ascii").strip()
    except (OSError, UnicodeError) as ex:
        raise CannotCheck(f"the key file {path} cannot be read: {getattr(ex, 'strerror', None) or ex}") from None
    text = text.removeprefix(KEY_MAGIC)
    try:
        key = bytes.fromhex(text)
    except ValueError:
        key = b""
    if len(key) != chain.KEY_BYTES:
        raise CannotCheck(f"{path} is no key of the activity log (it holds {KEY_MAGIC} and 64 hex digits)")
    return key


def key_of_wall(data_dir: Path, vault_key_file: str | None) -> bytes:
    """The log's key, read from the wall's sealed settings (with its vault key, which the settings need to be opened)."""
    return wall_settings(data_dir, vault_key_file)[0]


def wall_settings(data_dir: Path, vault_key_file: str | None) -> tuple[bytes, tuple[int, bytes] | None]:
    """The log's key and where its chain had come to, as the wall's sealed settings keep them."""
    settings = data_dir / "qkvm.json"
    if not settings.exists():
        raise CannotCheck(f"there are no settings of a wall in {data_dir}")
    try:
        store = Store(settings, vault_key_file=Path(vault_key_file) if vault_key_file else None, read_only=True)
    except (StorageError, OSError, ValueError) as ex:
        raise CannotCheck(f"the wall's settings in {data_dir} cannot be opened: {ex}") from None
    if not store.activity_key:
        raise CannotCheck(f"the wall in {data_dir} has no key for its activity log yet (it has not run 0.4.0)")
    return bytes.fromhex(store.activity_key), position_of(store.activity_position)


def save_key(key: bytes, path: Path) -> None:
    """The key into a file of its own, private from its first moment, never over one that is there."""
    try:
        descriptor = open_private(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    except FileExistsError:
        raise CannotCheck(f"{path} is there already: nothing was written over it") from None
    except OSError as ex:
        raise CannotCheck(f"{path} cannot be made: {ex.strerror or ex}") from None
    with os.fdopen(descriptor, "wb") as file:
        file.write(f"{KEY_MAGIC}{key.hex()}\n".encode("ascii"))


def check(paths: list[Path], key: bytes | None, heads: Path | None, kept: tuple[int, bytes] | None = None, part: bool = False) -> chain.Verdict:
    """The files checked as the whole log (held to `kept` and to `heads` past their last line), or as a part of it where the
    person says so (`part`: what comes after its last is said, chain.Walk)."""
    anchors: dict[int, bytes] = {}
    if heads is not None:
        try:
            anchors = chain.anchors_in(heads.read_text(encoding="utf-8", errors="replace"))
        except OSError as ex:
            raise CannotCheck(f"{heads} cannot be read: {ex.strerror or ex}") from None
        if not anchors:
            raise CannotCheck(f"{heads} names no head of the log (lines as syslog keeps them, 'line N head HEX', or 'N HEX')")
    read = _lines(paths)
    walk = chain.Walk(key, anchors, kept=kept, part=part)  # (whole or part by the person's word, never by the order of the lines)
    for entry in _ordered(read, _newest_first(read)):
        walk.take(entry)
    verdict = walk.end()
    if key is not None and verdict.key_fits is False:
        raise CannotCheck(
            f"the key given is not the one this log was signed with (its seals name the key {', '.join(verdict.key_ids)}; this one is {chain.key_id(key)})"
        )
    return verdict


def said(verdict: chain.Verdict, heads: bool) -> str:
    lines = [verdict.summary()]
    for problem in verdict.problems[:MOST_SHOWN]:
        lines.append(f"  {f'line {problem.line}' if problem.line is not None else 'a line'}: {problem.said}")
    more = verdict.more + max(0, len(verdict.problems) - MOST_SHOWN)
    if more:
        lines.append(f"  and {more} more")
    lines.extend(f"  note: {note}" for note in verdict.notes)
    if heads:
        lines.append(f"Heads kept outside the wall: {verdict.anchors} fall within the log, {verdict.matched} of them hold")
    if verdict.last is not None:
        lines.append(f"Head: line {verdict.last} head {verdict.head}")
    if not verdict.part and any(problem.what == "cut" for problem in verdict.problems):
        lines.append(CUT_OR_PART)
    if verdict.intact:
        lines.append(WHAT_INTACT_CANNOT_SHOW)
    return "\n".join(lines)


CUT_OR_PART = (
    "Checked as the whole log. A download ends where it was made, and the wall writes on: check it with --part, which says how "
    "far it goes and that it does not prove the log complete."
)
WHAT_INTACT_CANNOT_SHOW = (
    "Intact cannot show an older copy of the whole data folder put back (the settings and the log together, from a backup or a "
    "copy of the disk): it checks as the wall wrote it then. Heads kept outside the wall (--heads: syslog, the daily seal) show that."
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m qkvm.checklog",
        description="Check the activity log of qKVM: intact (0), broken (1), could not check (2), intact where it is chained with lines not "
        "proved (3), a part (--part) intact as far as it goes and not proved complete (4).",
    )
    parser.add_argument("files", nargs="*", metavar="FILE", help="the log's own files, the oldest first, or the log as JSON lines as the page downloads it")
    parser.add_argument("--key-file", metavar="KEY", help="the log's key, as --save-key writes it: its signatures are checked too")
    parser.add_argument("--data-dir", metavar="DATA", help="the wall's data folder: the key is read from its sealed settings")
    parser.add_argument("--vault-key-file", metavar="VAULT_KEY", help="the wall's vault key, where it is not beside the data folder (or QKVM_VAULT_KEY_FILE)")
    parser.add_argument("--heads", metavar="HEADS", help="heads kept outside the wall: what a syslog collector kept, or the daily seal messages")
    parser.add_argument("--save-key", metavar="KEY", help="write the log's key (from --data-dir) into a new file KEY, for a check elsewhere")
    parser.add_argument(
        "--part", action="store_true",
        help="the files are a part of the log that ends where it was made (a download): lines known to come after it are said, and it is not proved complete (4)",
    )  # fmt: skip
    parser.add_argument("--json", action="store_true", help="say what was found as JSON")
    args = parser.parse_args(argv)
    try:
        if args.key_file and args.data_dir:
            raise CannotCheck("--key-file and --data-dir both give a key: one of them")
        vault_key = args.vault_key_file or os.environ.get("QKVM_VAULT_KEY_FILE") or None
        key, kept = (read_key(Path(args.key_file)), None) if args.key_file else wall_settings(Path(args.data_dir), vault_key) if args.data_dir else (None, None)
        if args.save_key:
            if key is None or args.key_file:
                raise CannotCheck("--save-key takes the key from the wall's settings: give --data-dir")
            save_key(key, Path(args.save_key))
            print(f"The activity log's key (it is known as {chain.key_id(key)}) is in {args.save_key}. Keep it as the vault key is kept: whoever has it can write lines that check.")
            if not args.files:
                return 0
        if not args.files:
            raise CannotCheck("name the file to check: the activity log as JSON lines, as the page downloads it")
        verdict = check([Path(name) for name in args.files], key, Path(args.heads) if args.heads else None, kept, part=args.part)
    except CannotCheck as ex:
        if args.json:
            print(json.dumps({"checked": False, "said": str(ex)}))
        else:
            print(f"Could not check: {ex}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"checked": True, **verdict.as_dict(), "said": verdict.summary()}))
    else:
        print(said(verdict, args.heads is not None))
    return status(verdict)


def status(verdict: chain.Verdict) -> int:
    """The exit status, the first that holds: 1 broken; 4 a part, intact as far as it goes and known to go on (not proved
    complete); 3 intact where it is chained, not all of it proved; 0 intact. (A part known to go on that holds lines not
    proved as well ended with 3, and that it is not the whole was said in its words alone: the fresh review of the fixes,
    N6. Its words and its JSON say both.)"""
    if not verdict.intact:
        return 1
    return 4 if verdict.later is not None else 3 if verdict.unchained else 0


if __name__ == "__main__":
    sys.exit(main())
