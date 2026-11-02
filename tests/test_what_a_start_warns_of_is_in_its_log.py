"""What a start warns of is written into qkvm.log as well, once the log is set up (the round 5 review, a LOW;
review-core5\\probes\\p6_update_in_open_folder.py).

The warnings of a start (an installed update not used, a data folder others may write, files others may read, the key of
the HTTPS certificate) were printed only: a wall started without a console (a task at log-on, a service) never said why it
runs the version that was installed with the program, nor what its folder lets others do. On both systems.
"""

from __future__ import annotations

from pathlib import Path

from tests.test_update import an_update_that_leaves_a_mark, typed
from tests.test_what_another_account_planted import open_folder


def test_an_update_not_used_and_a_folder_others_may_write_are_said_in_the_log_as_well(tmp_path: Path) -> None:
    data = open_folder(tmp_path / "data")
    mark = an_update_that_leaves_a_mark(data)
    said = typed(["--data-dir", str(data), "--reset-password"], tmp_path, tmp_path)
    assert not mark.exists(), said.stderr
    assert "is not used" in said.stderr and "can be written to by other users of this computer" in said.stderr, said.stderr
    written = (data / "qkvm.log").read_text(encoding="utf-8")
    assert f"WARNING qkvm: the update in {data / 'updates'} is not used: " in written, written
    assert "can be written to by other users of this computer. Whoever can write there can stop qKVM and change its files" in written, written
