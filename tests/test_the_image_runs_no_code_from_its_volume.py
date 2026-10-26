"""The image never runs Python code that lies on its data volume (the review of 850745e, L-W12).

The account qKVM runs as in the image has /data as its home, and /data is the writable volume: Python looks for the
user's own packages in /data/.local at every start, and a `.pth` file there runs code before qKVM does. Whatever could
write a file on the volume (a defect, a hostile backup put back) would have qKVM run it at the next start, the health
check every thirty seconds. Python is told not to look there now, by the image's environment and by the commands it
runs; and the bundled pip that `ensurepip` keeps, a way to install packages again where pip was taken out, is left out.
"""
from __future__ import annotations

import json
from pathlib import Path
import re

APP = Path(__file__).resolve().parent.parent
SECURITY = APP / ".github" / "security"


def final_stage() -> str:
    dockerfile = (APP / "Dockerfile").read_text(encoding="utf-8")
    return dockerfile[dockerfile.index("\nFROM scratch") :]


def test_python_in_the_image_never_looks_in_the_users_own_folder_on_the_volume() -> None:
    final = final_stage()
    assert re.search(r"^\s*PYTHONNOUSERSITE=1\b", final, flags=re.M), "the image's environment turns the user's folder off"
    entry = json.loads(re.search(r"^ENTRYPOINT (\[.+\])$", final, flags=re.M).group(1))  # type: ignore[union-attr]
    health = json.loads(re.search(r"CMD (\[.+\])\s*$", final[final.index("HEALTHCHECK") :].split("\n\n", 1)[0], flags=re.M).group(1))  # type: ignore[union-attr]
    for command in (entry, health):
        assert command[0] == "python" and "-s" in command[1 : command.index("-m")], command


def test_the_image_carries_no_way_to_install_packages_again_and_its_check_says_so() -> None:
    assemble = (SECURITY / "assemble-runtime.py").read_text(encoding="utf-8")
    assert re.search(r'glob\("python\*/ensurepip"\):\s+shutil\.rmtree\(path\)', assemble), "the runtime is assembled without ensurepip"
    check = (SECURITY / "check-image-runtime.py").read_text(encoding="utf-8")
    tooling = re.search(r'for module in \(([^)]*)\):\n\s+if importlib\.util\.find_spec\(module\) is not None:', check)
    assert tooling and '"ensurepip"' in tooling.group(1)
    assert "site.ENABLE_USER_SITE" in check
