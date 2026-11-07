"""Where qKVM keeps its settings when nothing says otherwise.

In a file of its own because two parts of the program have to agree on it without one loading
the other: the starter (__main__), which looks there for an installed update before anything
else is loaded, and the program proper (cli). Like the starter it uses nothing but the
standard library, and like the starter it is not replaced by an in-app update: the copy that
was installed is loaded first, and decides for as long as it is installed.
"""

from __future__ import annotations

import sys
from pathlib import Path


def default_data_dir() -> Path:
    """The folder .qkvm in the home folder of whoever runs it.

    One place, whatever folder the command is typed in: a wall that comes up empty because it
    was started somewhere else is what this is for. Where "whoever runs it" has no home to
    speak of (a service, a container), the folder is given with --data-dir.
    """
    try:
        return Path.home() / ".qkvm"
    except RuntimeError:  # no home folder is known for this user: a container started under a number nobody has
        print("qkvm: there is no home folder to keep settings in. Say where with --data-dir.", file=sys.stderr, flush=True)
        raise SystemExit(2) from None
