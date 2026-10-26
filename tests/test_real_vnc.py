"""The reader against real VNC servers: TigerVNC's Xvnc with a terminal in it, and QEMU's own server showing its firmware.

Written for the CI job "vnc" in .github/workflows/tests.yml, which installs the two servers for itself and sets
QKVM_REAL_VNC=1; anywhere else these tests skip themselves. What is checked is checked from the other side
where that side can tell: what was typed into the terminal is read back from the file it wrote, the pointer's
place is asked of the X server, and QEMU's screen is compared with the screenshot QEMU takes of itself.

Not yet run by its author: this machine has neither server, and installing them was not for this track to decide.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from qkvm import rfb
from qkvm.rfb import Client, open_tcp

pytestmark = pytest.mark.skipif(os.environ.get("QKVM_REAL_VNC") != "1", reason="real VNC servers are tried in the CI job that installs them (QKVM_REAL_VNC=1)")

PASSWORD = "secret12"  # (eight characters: what QEMU reads, and what VNC authentication uses of any password)
DISPLAY = 77
QEMU_DISPLAY = 78


def needs(*programs: str) -> None:
    missing = [program for program in programs if shutil.which(program) is None]
    if missing:
        pytest.fail(f"not installed, though this job installs it: {', '.join(missing)}")


def wait_for_port(port: int, within: float = 20.0) -> None:
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        with socket.socket() as sock:
            sock.settimeout(0.5)
            try:
                sock.connect(("127.0.0.1", port))
                return
            except OSError:
                time.sleep(0.2)
    raise AssertionError(f"nothing listens on {port}")


async def first_frame(client: Client, within: float = 20.0) -> None:
    """Serve until one update has been drawn; the reading loop is stopped then."""
    serving = asyncio.create_task(client.serve())
    try:
        await client.request(incremental=False)
        before = client.frames
        async with asyncio.timeout(within):
            while client.frames == before:
                client.updated.clear()
                waiting = asyncio.create_task(client.updated.wait())
                done, _ = await asyncio.wait({waiting, serving}, return_when=asyncio.FIRST_COMPLETED)
                if serving in done:
                    waiting.cancel()
                    serving.result()
    finally:
        serving.cancel()
        await asyncio.gather(serving, return_exceptions=True)


@pytest.fixture
def xvnc(tmp_path: Path) -> Iterator[int]:
    """TigerVNC's Xvnc on a port of its own, with VNC authentication, and a terminal that writes what it is typed to a file."""
    needs("Xvnc", "vncpasswd", "xterm", "xdotool")
    passwd = tmp_path / "passwd"
    made = subprocess.run(["vncpasswd", "-f"], input=f"{PASSWORD}\n".encode(), capture_output=True, check=True)
    passwd.write_bytes(made.stdout)
    port = 5900 + DISPLAY
    server = subprocess.Popen(
        ["Xvnc", f":{DISPLAY}", "-geometry", "640x480", "-depth", "24", "-rfbport", str(port), "-localhost", "-rfbauth", str(passwd), "-SecurityTypes", "VncAuth", "-desktop", "qkvm-test"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )  # fmt: skip
    try:
        wait_for_port(port)
        env = {**os.environ, "DISPLAY": f":{DISPLAY}"}
        typed = tmp_path / "typed.txt"
        terminal = subprocess.Popen(["xterm", "-geometry", "80x24+0+0", "-e", "sh", "-c", f"cat > {typed}"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            time.sleep(2)  # the terminal draws itself
            yield port
        finally:
            terminal.terminate()
            terminal.wait(timeout=10)
    finally:
        server.terminate()
        server.wait(timeout=10)


def test_tigervnc_shows_its_screen_takes_keys_and_moves_the_pointer(xvnc: int, tmp_path: Path) -> None:
    typed = tmp_path / "typed.txt"

    async def go() -> None:
        stream = await open_tcp("127.0.0.1", xvnc, None, 5.0)
        client = Client(stream, PASSWORD)
        await client.handshake()
        assert client.security == rfb.SECURITY_VNC and client.version == (3, 8)
        assert (client.width, client.height) == (640, 480) and client.name == "qkvm-test"
        await first_frame(client)
        before = bytes(client.rgb)
        assert len(set(before[i : i + 3] for i in range(0, len(before), 3))) > 1  # a terminal was drawn: not one colour
        # Without a window manager the keyboard follows the pointer: into the terminal first.
        await client.pointer(100, 100, 0)
        for char in "hello from qkvm\n":
            keysym = rfb.keysym_of(char)
            assert keysym is not None
            await client.keys([(keysym, True), (keysym, False)])
        await asyncio.sleep(1.0)
        await first_frame(client)  # the typed line is on the screen now
        assert bytes(client.rgb) != before
        await client.pointer(321, 123, 0)
        await asyncio.sleep(0.5)
        await client.close()

    asyncio.run(go())
    assert typed.read_text() == "hello from qkvm\n"
    where = subprocess.run(["xdotool", "getmouselocation", "--shell"], env={**os.environ, "DISPLAY": f":{DISPLAY}"}, capture_output=True, text=True, check=True).stdout
    assert "X=321\n" in where and "Y=123\n" in where


@pytest.fixture
def qemu(tmp_path: Path) -> Iterator[tuple[int, Path]]:
    """QEMU with no disk (its firmware's screen is what it shows), its VNC server behind a password, and its monitor on a socket."""
    needs("qemu-system-x86_64")
    monitor = tmp_path / "monitor.sock"
    port = 5900 + QEMU_DISPLAY
    server = subprocess.Popen(
        ["qemu-system-x86_64", "-machine", "accel=tcg", "-m", "128", "-display", "none", "-net", "none",
         "-vnc", f"127.0.0.1:{QEMU_DISPLAY},password=on", "-monitor", f"unix:{monitor},server,nowait"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )  # fmt: skip
    try:
        wait_for_port(port)
        deadline = time.monotonic() + 20
        while not monitor.exists() and time.monotonic() < deadline:
            time.sleep(0.2)
        monitor_command(monitor, f"set_password vnc {PASSWORD}")
        time.sleep(3)  # the firmware writes its screen
        yield port, monitor
    finally:
        server.terminate()
        server.wait(timeout=10)


def monitor_command(monitor: Path, command: str) -> str:
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(10)
        sock.connect(str(monitor))
        time.sleep(0.5)
        sock.recv(65536)  # the banner and the prompt
        sock.sendall(f"{command}\n".encode())
        time.sleep(1.0)
        return sock.recv(65536).decode("utf-8", "replace")


def read_ppm(data: bytes) -> tuple[int, int, bytes]:
    """A binary PPM (P6) as (width, height, three bytes a pixel)."""
    parts: list[bytes] = []
    at = 0
    while len(parts) < 4:
        while data[at : at + 1].isspace():
            at += 1
        if data[at : at + 1] == b"#":
            at = data.index(b"\n", at) + 1
            continue
        end = at
        while not data[end : end + 1].isspace():
            end += 1
        parts.append(data[at:end])
        at = end
    assert parts[0] == b"P6" and parts[3] == b"255", parts
    width, height = int(parts[1]), int(parts[2])
    return width, height, data[at + 1 : at + 1 + 3 * width * height]


def test_qemu_shows_its_firmware_screen_as_its_own_screenshot_has_it_and_takes_input(qemu: tuple[int, Path], tmp_path: Path) -> None:
    port, monitor = qemu
    shot = tmp_path / "shot.ppm"

    async def go() -> bytes:
        stream = await open_tcp("127.0.0.1", port, None, 5.0)
        client = Client(stream, PASSWORD)
        await client.handshake()
        assert client.security == rfb.SECURITY_VNC
        await first_frame(client)
        monitor_command(monitor, f"screendump {shot}")
        await first_frame(client)  # the screen as it is at the time of the screenshot, give or take a cursor
        screen = bytes(client.rgb)
        # Input is taken: the connection goes on afterwards.
        await client.keys([(0xFF0D, True), (0xFF0D, False)])
        await client.pointer(10, 10, 1)
        await client.pointer(10, 10, 0)
        await first_frame(client)
        await client.close()
        return screen

    screen = asyncio.run(go())
    deadline = time.monotonic() + 10
    while not shot.exists() and time.monotonic() < deadline:
        time.sleep(0.2)
    width, height, pixels = read_ppm(shot.read_bytes())
    assert len(screen) == 3 * width * height, (width, height, len(screen))
    differing = sum(1 for i in range(0, len(pixels), 3) if pixels[i : i + 3] != screen[i : i + 3])
    assert differing < width * height // 100, f"{differing} of {width * height} pixels differ from QEMU's own screenshot"
