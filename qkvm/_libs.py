"""An update's own libraries, put first on the path before anything outside the standard library is loaded.

An update installed in place brings the libraries its release was tested with, in updates/<version>/lib, named in
updates/<version>/libraries.json (update.py, _libraries.py). The starter puts the update's package in front of the one
it shipped with and imports the update's cli, whose first import is this module: here the version judges its lib/ as
the starter judges an update's package, and only then puts it first on sys.path. It is the version's own code that
does this, as the starter is the copy that was installed and cannot learn anything new.

The rules it judges by are this version's own: its own __main__.py, loaded from beside this file under a name of its
own (what the starter loaded under the package's names may be an older version's, which has none of the new ones). Where
any of it fails (a link, a file others may write, libraries brought for another Python, a library that was loaded
before this could put its own in place), the version steps back by itself: the pointer goes back as `qkvm --roll-back`
sets it, the log says why, and the process ends with 75, which every starter since 0.2.0 takes for "start me again".

Standard library only, and nothing of the package but files beside this one: it runs before the libraries are there.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any

from ._version import __version__

STEP_BACK = 75  # what the starter takes for "start me again" (its RESTART)
LIBRARIES = "libraries.json"
MAX_NOTE = 1_000_000  # bytes of libraries.json; it names some thirty libraries in a few kilobytes
# Names no library of an update may have at its top: the standard library's (a folder first on the path comes before
# it), and those Python or this program loads by name.
NEVER = frozenset({"qkvm", "__main__", "sitecustomize", "usercustomize"})

placed: Path | None = None  # the lib/ this version put first on the path, where it did
recorded: dict[str, Any] | None = None  # what its libraries.json says, where it put one in place
_rules: list[Any] = []


def rules() -> Any:
    """This version's own __main__.py, loaded from beside this file under a name of its own (as the starter loads its
    _folders.py): the starter's rules (not_own, not_whole, a_link, not_own_way, target, roll_back, noted) as this version
    has them."""
    if not _rules:
        spec = importlib.util.spec_from_file_location("qkvm-libs-rules", Path(__file__).with_name("__main__.py"))
        if spec is None or spec.loader is None:
            raise ImportError("__main__.py is not beside _libs.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _rules.append(module)
    return _rules[0]


def where() -> tuple[Path, Path] | None:
    """(the data folder, this version's folder) where this package is an update that a starter put in front of the copy it
    shipped with; None otherwise (a pip install, a source checkout, an editable install: nothing to do)."""
    package = sys.modules.get("qkvm")
    paths = list(getattr(package, "__path__", None) or [])
    here = Path(os.path.abspath(Path(__file__).parent))
    if len(paths) < 2 or Path(os.path.abspath(paths[0])) != here:
        return None
    folder = here.parent
    if folder.name != __version__ or folder.parent.name != "updates":
        return None
    return folder.parent.parent, folder


def note(folder: Path) -> dict[str, Any] | None:
    """What `folder`/libraries.json says, read as it is written (update.py); None where there is none. ValueError where it
    cannot be read, or says what no update says."""
    try:
        with open(folder / LIBRARIES, "rb") as stream:
            text = stream.read(MAX_NOTE + 1)
    except FileNotFoundError:
        return None
    except OSError:
        raise ValueError(f"{folder / LIBRARIES} cannot be read") from None
    try:
        said = json.loads(text) if len(text) <= MAX_NOTE else None
    except (ValueError, RecursionError):
        said = None
    libraries = said.get("libraries") if isinstance(said, dict) else None
    if (
        not isinstance(said, dict)
        or said.get("format") != 1
        or not isinstance(said.get("target"), str)
        or not isinstance(libraries, list)
        or not all(isinstance(each, dict) and isinstance(each.get("top"), list) and all(isinstance(name, str) for name in each["top"]) for each in libraries)
    ):
        raise ValueError(f"{folder / LIBRARIES} cannot be read")
    return said


def judged(data: Path, folder: Path) -> tuple[str | None, dict[str, Any] | None]:
    """Why this version's libraries may not be put in place, in a few words, or None; and what its note says.

    By the starter's rules, in this version's copy: the data folder and the way to it, updates/, the version's folder, its
    note and every file and folder of lib/ (none a link, all this user's alone); then that they were brought for this
    Python, that none is named like a module of the standard library, and that none was loaded before (a .pth file of the
    Python this runs under can have loaded one: that would be the base's, and the version would run a mix never tested)."""
    starter = rules()
    refused = starter.not_own_way(data)
    if refused is None:
        for path in (data / "updates", folder, folder / LIBRARIES):
            try:
                found = os.lstat(path)
            except FileNotFoundError:
                if path.name == LIBRARIES:
                    return None, None  # (installed by an updater that brings no libraries: nothing to put in place)
                return f"{path} cannot be looked at", None
            except OSError:
                return f"{path} cannot be looked at", None
            why = "is a link" if starter.a_link(found) else starter.not_own(path)
            if why is not None:
                return f"{path} {why}", None
    else:
        return f"{refused[0]} {refused[1]}", None
    try:
        said = note(folder)
    except ValueError as ex:
        return str(ex), None
    if said is None:
        return None, None
    here = starter.target()
    if said["target"] != here:
        return f"its libraries were brought for {said['target']}, and this Python is {here}", said
    names = sorted({name for each in said["libraries"] for name in each["top"]})
    if said["libraries"]:
        lib = folder / "lib"
        try:
            found = os.lstat(lib)
        except OSError:
            return f"{lib} cannot be looked at", said
        why = "is a link" if starter.a_link(found) else starter.not_own(lib)
        if why is not None:
            return f"{lib} {why}", said
        refused = starter.not_whole(lib)
        if refused is not None:
            return f"{refused[0]} {refused[1]}", said
    for name in names:
        if not name.isidentifier() or name in NEVER or name in sys.stdlib_module_names:
            return f"its libraries hold a module named {name!r}, which no library may be called", said
    loaded = {module.partition(".")[0] for module in list(sys.modules)}
    early = [name for name in names if name in loaded]
    if early:
        return f"{', '.join(early)} was loaded before this version could put its own in place (by a .pth file of this Python?)", said
    return None, said


def put_in_place(folder: Path, said: dict[str, Any]) -> None:
    global placed, recorded
    lib = folder / "lib"
    if said["libraries"]:
        # First of all: before the shipped copy's folder that the starter's PYTHONPATH put first, and before the standard
        # library. (.pth files are read from site folders only, and lib/ is never made one.)
        sys.path.insert(0, str(lib))
        placed = lib
    recorded = said


def step_back(data: Path, folder: Path, why: str) -> None:
    """Point the next start at the version before this one (as `qkvm --roll-back` does), say why, and end with STEP_BACK.
    (Only where the pointer still names this version, `folder`: one named meanwhile is not gone back from.)"""
    line = f"version {folder.name} is not started on this computer: {why}. Going back to the version before it."
    try:
        starter = rules()
        current = starter.pointer(data)
        if current is not None and current.get("version") == folder.name:
            starter.roll_back(data)
        starter.noted(data, line)
    except OSError as ex:
        # (Not gone back: a start again would run this version again, and again. Ended as a version ends that does not start:
        # within its first half minute the starter goes back by itself, and later it stops with what it said.)
        print(f"qkvm: {line} That could not be written down ({ex.strerror or ex}).", file=sys.stderr, flush=True)
        raise SystemExit(1) from None
    raise SystemExit(STEP_BACK)


def load() -> None:
    """Run at this module's first import, from cli.py: put this update's libraries in place, or step back."""
    found = where()
    if found is None:
        return
    data, folder = found
    try:
        why, said = judged(data, folder)
    except Exception as ex:  # (this version's own rules not loading, or failing when asked: nothing is run on their word)
        why, said = f"its libraries could not be judged ({type(ex).__name__}: {ex})", None
    if why is not None:
        step_back(data, folder, why)
    elif said is not None:
        put_in_place(folder, said)


def trial(folder: Path) -> None:
    """For the updater's trial of a version before it is named (update.py): judge the staged `folder` as a start judges a
    named one, and put its libraries in place. RuntimeError, saying why, where a start would step back."""
    why, said = judged(folder.parent.parent, folder)
    if why is not None:
        raise RuntimeError(why)
    if said is not None:
        put_in_place(folder, said)


load()
