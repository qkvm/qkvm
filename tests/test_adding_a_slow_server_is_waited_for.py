"""The page waits for an addition as long as a slow server controller takes to be told apart and signed in to.

Seen on a real board on 2026-11-02 (the slow AMI test server, 0.2.1's requalification): the wall added it, but after the
page had given up at its usual 30 s and said "qKVM took too long to answer"; a person then adds it again.
"""

import re
from pathlib import Path

from qkvm import kvm


def test_the_add_box_waits_minutes_not_the_usual_thirty_seconds() -> None:
    script = (Path(kvm.__file__).parent / "static" / "app.js").read_text(encoding="utf-8")
    patience = re.search(r"const ADD_PATIENCE = (\d+);", script)
    assert patience is not None and int(patience.group(1)) >= 120_000
    call = re.search(r"await api\('POST', 'api/v1/devices', \{.*?\}, ADD_PATIENCE\);", script, re.S)
    assert call is not None, "the add box's request is not given ADD_PATIENCE"
