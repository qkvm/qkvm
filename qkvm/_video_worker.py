"""Credential-free video worker. Only this module processes native video frames.

Started by video.py in a fresh isolated interpreter, with a minimal environment and
three pipe/null handles. No input is consumed until the kernel sandbox is active.
The wire format is fixed integers and bounded bytes, never Python serialization.
"""
from __future__ import annotations

import ctypes
import os
import platform
import struct
import sys
from collections import OrderedDict
from fractions import Fraction
from typing import Any

HEADER = struct.Struct("!4sIIIIII")
MAGIC = b"QKV1"
MAX_SIDE = 8192
MAX_PIXELS = 16_000_000
MAX_BYTES = 3 * MAX_PIXELS
MAX_COMPRESSED = 16 * 1024 * 1024
JPEG, H264, ENCODE_RGB, ENCODE_FRAME = 1, 2, 3, 4


def dimensions(width: int, height: int) -> None:
    if not (0 < width <= MAX_SIDE and 0 < height <= MAX_SIDE and width * height <= MAX_PIXELS):
        raise ValueError("video dimensions exceed limit")


def linux_lockdown() -> None:
    """Allow only in-memory computation and existing pipe IO, with no escape hatch."""
    import importlib

    resource = importlib.import_module("resource")

    machine = platform.machine().lower()
    # An architecture check prevents alternate syscall ABIs bypassing this list.
    if machine in {"x86_64", "amd64"}:
        arch = 0xC000003E
        calls = [0, 1, 3, 5, 9, 10, 11, 12, 13, 14, 15, 19, 20, 24, 25, 28,
                 35, 39, 60, 96, 98, 131, 186, 202, 228, 230, 231, 318]
    elif machine in {"aarch64", "arm64"}:
        arch = 0xC00000B7
        calls = [57, 63, 64, 65, 66, 80, 93, 94, 98, 101, 113, 115, 124, 132,
                 134, 135, 139, 165, 169, 172, 178, 214, 215, 216, 222, 226, 233, 278]
    else:
        raise RuntimeError("unsupported Linux sandbox architecture")
    if len(os.listdir("/proc/self/task")) != 1:
        raise RuntimeError("video worker must enter its sandbox before creating threads")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))
    # Imported libraries must not leave a file, socket, or directory handle behind.
    os.closerange(3, 1_048_576)
    resource.setrlimit(resource.RLIMIT_NOFILE, (3, 3))
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(4, 0, 0, 0, 0) != 0:  # PR_SET_DUMPABLE
        raise OSError(ctypes.get_errno(), "cannot disable worker dumps")
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), "cannot restrict worker privileges")

    class Filter(ctypes.Structure):
        _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]

    class Program(ctypes.Structure):
        _fields_ = [("length", ctypes.c_ushort), ("filters", ctypes.POINTER(Filter))]

    # Unknown syscalls return EPERM; a different ABI kills the process. In particular
    # open*, socket*, clone*, exec*, ptrace, process_vm*, pidfd*, io_uring*, signal
    # delivery, prctl and seccomp itself are not allowed. No filesystem allowlist.
    rules = [(0x20, 0, 0, 4), (0x15, 1, 0, arch), (0x06, 0, 0, 0x80000000), (0x20, 0, 0, 0)]
    for number in calls:
        rules.extend([(0x15, 0, 1, number), (0x06, 0, 0, 0x7FFF0000)])
    rules.append((0x06, 0, 0, 0x00050001))
    array = (Filter * len(rules))(*(Filter(*r) for r in rules))
    program = Program(len(rules), array)
    if libc.prctl(22, 2, ctypes.byref(program), 0, 0) != 0:  # PR_SET_SECCOMP
        raise OSError(ctypes.get_errno(), "cannot install worker syscall filter")


def windows_lockdown() -> None:
    """Verify the launcher supplied a capability-free AppContainer token."""
    if sys.platform != "win32":
        raise RuntimeError("AppContainer verification is Windows-only")
    from ctypes import wintypes as wt
    # This entry point is imported for Linux checks too; WinDLL exists only on Windows.
    windows_ctypes: Any = ctypes
    windows_dll = windows_ctypes.WinDLL
    kernel = windows_dll("kernel32", use_last_error=True)
    advapi = windows_dll("advapi32", use_last_error=True)
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    advapi.OpenProcessToken.argtypes = [ctypes.c_void_p, wt.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    advapi.GetTokenInformation.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD)]
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    token = ctypes.c_void_p()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise OSError("cannot inspect worker token")
    try:
        value, size = wt.DWORD(), wt.DWORD()
        if not advapi.GetTokenInformation(token, 29, ctypes.byref(value), 4, ctypes.byref(size)) or value.value != 1:
            raise RuntimeError("video worker is not an AppContainer")
        advapi.GetTokenInformation(token, 30, None, 0, ctypes.byref(size))
        capabilities = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token, 30, capabilities, size.value, ctypes.byref(size)):
            raise OSError("cannot inspect worker capabilities")
        if ctypes.cast(capabilities, ctypes.POINTER(wt.DWORD))[0] != 0:
            raise RuntimeError("video worker has unexpected capabilities")
        # Prevent crash dialogs and system error-reporting UI.
        kernel.SetErrorMode(0x0001 | 0x0002 | 0x8000)
    finally:
        kernel.CloseHandle(token)


def rgb_frame(av: Any, data: bytes, width: int, height: int) -> Any:
    dimensions(width, height)
    if len(data) != width * height * 3:
        raise ValueError("incorrect RGB size")
    frame = av.VideoFrame(width, height, "rgb24")
    plane = frame.planes[0]
    row = width * 3
    if plane.line_size == row:
        plane.update(data)
    else:
        padded = bytearray(plane.line_size * height)
        for y in range(height):
            padded[y * plane.line_size : y * plane.line_size + row] = data[y * row : (y + 1) * row]
        plane.update(padded)
    return frame


def jpeg(av: Any, frame: Any, target: int, quality: int) -> bytes:
    dimensions(frame.width, frame.height)
    if not 0 <= target <= MAX_SIDE or not 2 <= quality <= 31:
        raise ValueError("incorrect encoder settings")
    if target and target < frame.width:
        height = max(2, round(frame.height * target / frame.width / 2) * 2)
        frame = frame.reformat(width=target, height=height, format="yuvj420p", interpolation="LANCZOS", threads=1)
    else:
        frame = frame.reformat(format="yuvj420p", threads=1)
    codec = av.CodecContext.create("mjpeg", "w")
    codec.thread_count = 1
    codec.width, codec.height, codec.pix_fmt = frame.width, frame.height, "yuvj420p"
    codec.time_base = Fraction(1, 30)
    codec.options = {"qmin": str(quality), "qmax": str(quality)}
    frame.pts = 0
    packets = codec.encode(frame) + codec.encode(None)
    output = b"".join(bytes(p) for p in packets)
    if not 0 < len(output) <= MAX_COMPRESSED:
        raise ValueError("encoded image exceeds limit")
    return output


def decode_jpeg(av: Any, data: bytes, width: int, height: int) -> bytes:
    dimensions(width, height)
    codec = av.CodecContext.create("mjpeg", "r")
    codec.thread_count = 1
    codec.options = {"max_pixels": str(((width + 255) // 256 * 256) * ((height + 63) // 64 * 64))}
    frames = codec.decode(av.Packet(data)) + codec.decode(None)
    if len(frames) != 1 or (frames[0].width, frames[0].height) != (width, height):
        raise ValueError("decoded dimensions differ from rectangle")
    frame = frames[0].reformat(format="rgb24", threads=1)
    plane = frame.planes[0]
    raw, row = bytes(plane), 3 * width
    return b"".join(raw[y * plane.line_size : y * plane.line_size + row] for y in range(height))


def read_exact(size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        part = sys.stdin.buffer.read(size - len(data))
        if not part:
            raise EOFError
        data.extend(part)
    return bytes(data)


def reply(op: int, width: int = 0, height: int = 0, ident: int = 0, data: bytes = b"") -> None:
    sys.stdout.buffer.write(HEADER.pack(MAGIC, op, width, height, ident, 0, len(data)))
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def main() -> None:
    # -I -S ignores environment, user site and .pth startup code. The parent supplies
    # only the trusted installed PyAV location, never a device URL or credentials.
    sys.path.insert(0, sys.argv[1])
    import av

    av.logging.set_level(av.logging.PANIC)
    # Exercise trusted synthetic input before lockdown, resolving lazy codec imports.
    seed = rgb_frame(av, bytes(16 * 16 * 3), 16, 16)
    decode_jpeg(av, jpeg(av, seed, 8, 2), 8, 8)
    decoder = av.CodecContext.create("h264", "r")
    decoder.thread_count = 1
    decoder.options = {"max_pixels": str(MAX_PIXELS)}
    decoder.open()
    if sys.platform == "linux":
        linux_lockdown()
    elif sys.platform == "win32":
        windows_lockdown()
    else:
        raise RuntimeError("verified video isolation is unavailable on this platform")
    reply(0, ident=1)  # no device-controlled bytes have been read before this point
    frames: OrderedDict[int, Any] = OrderedDict()
    sequence = 0
    while True:
        try:
            magic, op, width, height, target, quality, length = HEADER.unpack(read_exact(HEADER.size))
            if magic != MAGIC or op not in {JPEG, H264, ENCODE_RGB, ENCODE_FRAME}:
                return
            if length > (MAX_BYTES if op == ENCODE_RGB else MAX_COMPRESSED):
                return
            if op in {JPEG, ENCODE_RGB}:
                dimensions(width, height)
            if op == ENCODE_RGB and length != width * height * 3:
                return
            if op == ENCODE_FRAME and length:
                return
            data = read_exact(length)
            if op == JPEG:
                reply(op, width, height, data=decode_jpeg(av, data, width, height))
            elif op == H264:
                packet = av.Packet(data)
                packet.pts, packet.time_base = target, Fraction(1, 90000)
                try:
                    decoded = decoder.decode(packet)
                except av.FFmpegError:
                    decoded = []
                if not decoded:
                    reply(op)
                    continue
                frame = decoded[-1]
                dimensions(frame.width, frame.height)
                sequence = sequence % 0xFFFFFFFF + 1
                frames[sequence] = frame
                while len(frames) > 4:
                    frames.popitem(last=False)
                reply(op, frame.width, frame.height, sequence)
            elif op == ENCODE_RGB:
                reply(op, width, height, data=jpeg(av, rgb_frame(av, data, width, height), target, quality))
            else:
                frame = frames.get(width) or next(reversed(frames.values()))
                reply(op, frame.width, frame.height, data=jpeg(av, frame, target, quality))
        except EOFError:
            return
        except Exception:
            # No native exception strings or process paths cross the boundary.
            reply(255)


if __name__ == "__main__":
    main()
