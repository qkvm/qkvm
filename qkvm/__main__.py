"""Start-up: python -m qkvm [--bind local,tailscale] [--port 8787].

Two small jobs happen here before the program proper (qkvm.cli) is loaded:

* An update installed from inside the app lives in the data folder. Its files are put in
  front of the ones this copy shipped with.
* The wall runs as a child of this process, so that it can be started again after an
  update, and put back on the previous version when a new one will not start.

This file uses nothing but the standard library and is kept as small as it can be: with
_where, which says where the data folder is, it is the part of the program that an in-app
update cannot replace.
"""

# (No "from __future__" line here, which every other file of the program begins with: it is an import like
# any other, and would be looked for in the current folder before the lines below have run.)
import os
import sys


def _here() -> str:
    try:
        return os.getcwd()
    except OSError:  # started in a folder that is gone by now
        return ""


if __name__ == "__main__" and not sys.flags.safe_path and sys.path and sys.path[0] in ("", _here()):
    # Typed as `python -m qkvm`, the folder it is typed in is the first place Python looks in for everything
    # that is imported from here on: a file called json.py lying there (in Downloads, on a share) would be
    # run in its place, by this part of the program, before it had done anything at all. This program is
    # found already; nothing else it needs lies in that folder. (`python -P -m qkvm` does not look there in
    # the first place, and is what the README says to type. Only that keeps out a file that Python itself
    # loads to find a module named with -m, before the first line here has run: types.py on every version,
    # and more on the older ones. From here on, nothing is taken from that folder.)
    del sys.path[0]

import json  # noqa: E402
import re  # noqa: E402
import signal  # noqa: E402
import subprocess  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402

from ._where import default_data_dir  # noqa: E402

RESTART = 75  # exit status with which the wall asks to be started again
CHILD = "QKVM_CHILD"  # set in the environment of the process that actually serves
QUICK = 30.0  # a new version that dies within this many seconds of starting is rolled back
ASKS = ("stop", "restart", "status")  # about the copy that runs already (see cli.py): no wall of their own is started
CONTAINER = "QKVM_CONTAINER"  # set in the image, where a new version is a new image and nothing in the volume is run
VERSION = re.compile(r"\d+\.\d+(\.\d+)?")  # what an installed update is called, and so the name of its folder


def data_dir(argv: list[str]) -> Path:
    """Where settings (and installed updates) live: the value of -d / --data-dir, or the folder QKVM keeps at home."""
    # (Read the way the program itself reads its options, which takes no shortened names: an option the two
    # understood differently sent this part to another folder than the program.)
    said = None
    for i, arg in enumerate(argv):
        if arg in ("-d", "--data-dir") and i + 1 < len(argv):
            said = argv[i + 1]
        elif arg.startswith("--data-dir="):
            said = arg.split("=", 1)[1]
        elif arg.startswith("-d") and not arg.startswith("--") and len(arg) > 2:
            said = arg[2:].removeprefix("=")
        else:
            continue
        break
    # (Given and empty, it is the folder at home to the program: so it is here, and not "this folder".)
    return Path(said) if said else default_data_dir()


def own(path: Path) -> bool:
    """Whether what is at `path` is this user's, and nobody else's to write. (Always, where the system keeps no such thing.)"""
    return not_own(path) is None


def not_own(path: Path) -> str | None:
    """Why what is at `path` is not this user's alone to write, in a few words; None where it is."""
    if sys.platform == "win32":
        return None
    try:
        found = path.stat()
    except OSError:
        return "cannot be looked at"
    if found.st_uid != os.getuid():
        return "belongs to another user"
    return "can be written to by others" if found.st_mode & 0o022 else None


def written(file: Path, text: str) -> None:
    """Put `text` in `file`: in one piece or not at all, and its owner's alone, whatever the shell this was started from lets others do."""
    being_written = file.with_name(file.name + ".new")
    descriptor = os.open(being_written, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as fh:
        fh.write(text)
    if sys.platform != "win32":
        os.chmod(being_written, 0o600)  # (it may have been there already, from a start that was cut off, as somebody else's to write)
    os.replace(being_written, file)


def version_of(package: Path) -> tuple[int, ...] | None:
    """The version a copy of the qkvm package says it is, without importing it."""
    try:
        text = (package / "_version.py").read_text(encoding="utf-8")
    except OSError:
        return None
    match = re.search(r'__version__\s*=\s*"(\d+)\.(\d+)(?:\.(\d+))?"', text)
    return tuple(int(part or 0) for part in match.groups()) if match else None


def note(data: Path) -> dict[str, object] | None:
    """What `updates/current.json` says, as far as it is plain values; None where it cannot be read ({}: read, and no record).

    Only what is a text, a number, yes, no or nothing is handed on. The note is compared and written again
    by whoever asks for it, and something nested deep beside a proper version can be read and then neither
    compared nor written: that was an error in the starter half a minute into a start, and the wall
    stopped with it.
    """
    try:
        current = json.loads((data / "updates" / "current.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return None
    if not isinstance(current, dict):
        return {}
    return {key: value for key, value in current.items() if value is None or isinstance(value, (str, int, float, bool))}


def pointer(data: Path) -> dict[str, object] | None:
    """What `updates/current.json` says, where it names a version as one is named; None otherwise."""
    current = note(data)
    if current is None or not isinstance(current.get("version"), str) or not VERSION.fullmatch(str(current["version"])):
        return None  # "../elsewhere", or "1.2.3.tmp" (what a half-unpacked one is called): not a version, and not run
    return current


def active_update(data: Path, tell: bool = False) -> Path | None:
    """The qkvm folder of the installed update, if there is one, it is newer than this copy, and it is to be run.

    Not in a container: there a new version is a new image, the program installs none, and what lies in
    the volume is not code. And only where the folders it lies in are this user's own and nobody else's to
    write: `sudo qkvm --disable-2fa NAME`, typed by an administrator about a service's data folder, would
    otherwise run, as root, what the service's account (or whoever got to write there) put in it. `tell`:
    say so where an update is passed over for that.
    """
    current = pointer(data)
    if current is None or os.environ.get(CONTAINER) == "1":
        return None
    updates = data / "updates"
    package = updates / str(current["version"]) / "qkvm"
    installed, shipped = version_of(package), version_of(Path(__file__).parent)
    if installed is None or shipped is None or installed <= shipped:
        return None  # nothing usable, or this copy has since been replaced by something newer
    for path in (updates, updates / "current.json", package.parent, package):
        why = not_own(path)
        if why is not None:
            if tell:
                print(
                    f"qkvm: the update in {updates} is not used: {path} {why}. This runs the version that was installed with the program.",
                    file=sys.stderr, flush=True,
                )  # fmt: skip
            return None
    return package


def proven(data: Path, version: object) -> None:
    """Note with the installed update that it has started and stayed up: from here on, a start that ends badly is not its doing."""
    file = data / "updates" / "current.json"
    current = pointer(data)
    if current is None or current["version"] != version or current.get("proven") is True:
        return
    try:
        # (Looked at once more, as late as can be: the program may have installed a newer one in this very
        # moment, and what it wrote is not to be put back to what was read before.)
        if pointer(data) == current:
            written(file, json.dumps({**current, "proven": True}))
    except OSError:
        pass  # then it is on trial once more at the next start: nothing worse


def noted(data: Path, line: str) -> None:
    """Say it where the program is started from, and in its log: who looks for why the version changed looks there."""
    print(f"qkvm: {line}", file=sys.stderr, flush=True)
    try:
        with (data / "qkvm.log").open("a", encoding="utf-8") as log:
            log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')},000 WARNING qkvm: {line}\n")
    except OSError:
        pass


def roll_back(data: Path) -> bool:
    """Go back to the version that ran before the last update. False if there was no update."""
    file = data / "updates" / "current.json"
    current = note(data)
    if not current:
        # It cannot be read, or what is read is no record: no update is noted, and there is nothing to go back
        # from. (Which of the two a note of brackets nested a hundred thousand deep is depends on the Python: most
        # give up on it, the newest on Linux reads it without a word, as a list. Taken for a note with nothing in
        # it, it was deleted and "gone back" was said, on that Python alone.)
        return False
    previous = current.get("previous")
    if isinstance(previous, str) and VERSION.fullmatch(previous):
        # In one piece or not at all: cut off halfway, it would name no version, and the next start would run neither.
        # The one gone back to is on trial again only if it never got through one: a version that ran is
        # not taken back for a start that ends badly, and one that never did is, as far as the shipped files.
        written(file, json.dumps({"version": previous, "previous": None, "proven": current.get("previous_proven") is True}))
    else:
        file.unlink(missing_ok=True)  # back to the files this copy shipped with
    return True


def gone_back(data: Path) -> bool:
    """`roll_back`, for the starter itself: where it cannot be written down (a full disk), that is said, and the version stays."""
    try:
        return roll_back(data)
    except OSError as ex:
        print(f"qkvm: the updated version did not start, and going back to the previous one could not be written down ({ex.strerror or ex})", file=sys.stderr, flush=True)
        return False


def supervise(argv: list[str]) -> int:
    """Run the wall as a child process, starting it again whenever it asks for that."""
    # The child is this program, from the folder this copy of it lies in, and from nowhere else: `python -m`
    # by itself looks in the folder the command was typed in first, and a file called json.py lying there
    # (in Downloads, in /tmp, on a share) was run as the account that holds every device password.
    if sys.platform != "win32":
        os.umask(0o077)  # what this part writes into the data folder is its owner's alone, like what the program writes
    here = str(Path(__file__).resolve().parent.parent)
    path = os.pathsep.join(part for part in (here, os.environ.get("PYTHONPATH", "")) if part)
    environment = {**os.environ, CHILD: "1", "PYTHONPATH": path}
    data = data_dir(argv)
    told_to_stop: list[int] = []  # not empty once somebody has said so: a service manager, or a person with Ctrl+C
    # Started without a window (pythonw, a scheduled task) this process has nowhere to print to, and a child
    # that inherits "nowhere" from it gets a handle that fails on the first line. It is given a real nowhere.
    stdout = subprocess.DEVNULL if sys.stdout is None else None
    stderr = subprocess.DEVNULL if sys.stderr is None else None
    while True:
        started = time.monotonic()
        # stdin is a pipe that is never written to: the child watches it to notice if this process dies.
        child = subprocess.Popen([sys.executable, "-P", "-m", "qkvm", *argv], env=environment, stdin=subprocess.PIPE, stdout=stdout, stderr=stderr)
        on_trial = pointer(data) if active_update(data) else None  # the update this start runs, where it runs one

        # (Its type is written as text: without the "from __future__" line a type is worked out where it
        # stands, here at every start of the wall, and nothing in this part is to depend on that going well.)
        def stop(number: int, _frame: object, child: "subprocess.Popen[bytes]" = child) -> None:
            # `docker stop` sends SIGTERM to this process only, a service manager to both; hand it to the
            # child so it can close its listeners properly instead of being cut off when we exit.
            told_to_stop.append(number)
            child.terminate()

        signal.signal(signal.SIGTERM, stop)
        try:
            if on_trial is not None and on_trial.get("proven") is not True:
                try:
                    status = child.wait(QUICK)
                except subprocess.TimeoutExpired:
                    # It started and stayed up. What ends a later start badly (no memory left, a full disk,
                    # a crash somebody can cause) is not this version failing to start: it is kept.
                    proven(data, on_trial["version"])
                    status = child.wait()
            else:
                status = child.wait()
        except KeyboardInterrupt:
            # Ctrl+C reaches the child as well; let it shut down cleanly.
            told_to_stop.append(signal.SIGINT)
            status = child.wait()
        if told_to_stop:
            # The child then ends as a process does that a signal ended, with a status that says so. That is
            # what was asked for: not a failure to report, not a reason to start again or to undo an update.
            return 0
        if status == RESTART:
            continue
        crashed = status not in (0, 2)  # 2 is "could not start": bad option, port taken, already running
        now = pointer(data) if active_update(data) else None
        if crashed and time.monotonic() - started < QUICK and now is not None and now.get("proven") is not True and gone_back(data):
            noted(data, f"the updated version ({now['version']}) did not start; going back to the previous one")
            continue
        return status


def main() -> int:
    argv = sys.argv[1:]
    passthrough = {"-h", "--help", "--version", "--reset-password", "--disable-2fa", "--roll-back"}
    if os.environ.get(CHILD) != "1" and not passthrough.intersection(argv) and argv[:1] not in ([word] for word in ASKS):
        return supervise(argv)

    if "--roll-back" in argv:
        if sys.platform != "win32":
            os.umask(0o077)
        went_back = roll_back(data_dir(argv))
        print("Back on the previous version." if went_back else "No update is installed; nothing to roll back.")
        return 0

    # A question about the copy that runs is answered by this copy's own files, and so is one about the
    # program itself (--help, --version). Nothing that lies in the folder it is asked about is run: whoever
    # asks may be more than whoever owns that folder.
    asking = argv[:1] in ([word] for word in ASKS) or bool({"-h", "--help", "--version"}.intersection(argv))
    update = None if asking else active_update(data_dir(argv), tell=True)
    if update is not None:
        import qkvm

        qkvm.__path__.insert(0, str(update))
    from qkvm.cli import main as run

    return run(argv)


if __name__ == "__main__":
    sys.exit(main())
