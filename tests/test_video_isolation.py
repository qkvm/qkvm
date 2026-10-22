"""Exercise the operating-system boundary as well as the untrusted wire protocol."""
from __future__ import annotations

import asyncio
import ctypes
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest

from qkvm import _video_worker, video


def test_real_sandboxes_are_separate_and_closed_sessions_cannot_restart() -> None:
    frame = video.RGBFrame(17, 33, bytes([31, 64, 127]) * 17 * 33)
    first, second = video.VideoSession(), video.VideoSession()
    try:
        encoded = video.encode_jpeg(frame, None, 2, first)
        assert len(video.decode_jpeg(encoded, 17, 33, second)) == 17 * 33 * 3
        assert first._worker is not None and second._worker is not None
        assert first._worker._process.pid != second._worker._process.pid
        first.close()
        with pytest.raises(video.VideoError, match="session is closed"):
            video.encode_jpeg(frame, None, 2, first)
        assert len(video.decode_jpeg(encoded, 17, 33, second)) == 17 * 33 * 3
    finally:
        first.close()
        second.close()


def test_rfb_connections_never_share_native_decoder_state() -> None:
    from qkvm import rfb

    jpeg = video.encode_jpeg(video.RGBFrame(16, 16, bytes([40, 80, 120]) * 256), None, 2)
    async def close_stream() -> None:
        pass

    clients = [rfb.Client(SimpleNamespace(close=close_stream)) for _ in range(2)]
    try:
        for client in clients:
            client.width = client.height = 16
            client.rgb = bytearray(16 * 16 * 3)
            list(client._draw_tight(0, 0, 16, 16, rfb._Bytes(b"\x90" + jpeg)))
        workers = [client._video_decoder._worker for client in clients]
        assert all(worker is not None for worker in workers)
        assert workers[0]._process.pid != workers[1]._process.pid
        # A compromised/terminated decoder for one server cannot poison the other.
        workers[0].close()
        with pytest.raises(rfb.RfbError):
            list(clients[0]._draw_tight(0, 0, 16, 16, rfb._Bytes(b"\x90" + jpeg)))
        list(clients[1]._draw_tight(0, 0, 16, 16, rfb._Bytes(b"\x90" + jpeg)))
    finally:
        for client in clients:
            asyncio.run(client.close())
            with pytest.raises(video.VideoError, match="session is closed"):
                video.decode_jpeg(jpeg, 16, 16, client._video_decoder)


def test_native_frames_are_never_accepted_by_parent() -> None:
    with pytest.raises(video.VideoError, match="native frames"):
        video.encode_jpeg(SimpleNamespace(width=16, height=16), None, 2)


@pytest.mark.parametrize("header", [
    video.HEADER.pack(b"BAD!", 1, 1, 1, 0, 0, 3),
    video.HEADER.pack(video.MAGIC, 1, 1, 1, 0, 1, 3),
    video.HEADER.pack(video.MAGIC, 1, 1, 1, 0, 0, video.MAX_BYTES + 1),
    b"short",
])
def test_bad_worker_header_is_rejected_before_payload_read(header: bytes) -> None:
    reads: list[int] = []

    class Output(io.BytesIO):
        def read(self, size: int = -1) -> bytes:
            reads.append(size)
            assert len(reads) == 1
            return header

    process = SimpleNamespace(stdin=io.BytesIO(), stdout=Output(), kill=lambda: None, wait=lambda timeout: 0)
    worker = video.Worker.__new__(video.Worker)
    worker._lock = threading.Lock()
    worker._process = process
    with pytest.raises(video.VideoError):
        worker.request(1, 1, 1, data=b"invalid")
    assert worker._process is None
    assert reads == [video.HEADER.size]


def test_decoder_backlog_ends_without_blocking() -> None:
    pending = video.BoundedDecoderQueue()
    task = (SimpleNamespace(mimeType="video/h264"), SimpleNamespace(data=b"x"))
    for _ in range(100):
        pending.put(task)
    assert pending.stopped and pending.qsize() == 1
    assert pending.get_nowait() is None


def test_codec_hook_has_no_fallback() -> None:
    video.install_aiortc_boundary()
    import aiortc.rtcrtpreceiver as receiver

    assert receiver.get_decoder is video.isolated_decoder
    assert receiver.decoder_worker is video.decoder_worker
    with pytest.raises(video.VideoError):
        receiver.get_decoder(SimpleNamespace(mimeType="video/VP8"))


def test_unsupported_platform_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(video.sys, "platform", "unsupported")
    with pytest.raises(video.VideoError, match="isolation is unavailable"):
        video.Worker()


def test_kernel_boundary_cannot_reach_credentials_or_parent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Run hostile operations after the same real kernel boundary used for video."""
    canary = tmp_path / "dummy-credential"
    canary.write_text("synthetic test credential", encoding="utf-8")
    canary.chmod(0o644)  # Linux filter must deny even otherwise-readable files.
    secret = ctypes.create_string_buffer(b"synthetic parent memory")
    monkeypatch.setenv("QKVM_TEST_SECRET", "synthetic environment")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    with socket.create_connection(listener.getsockname(), timeout=2):
        connection, _ = listener.accept()
        connection.close()
    source = Path(_video_worker.__file__).read_text(encoding="utf-8").replace('if __name__ == "__main__":\n    main()', '')
    source += f"\nCANARY={str(canary)!r}\nPARENT={os.getpid()}\nADDRESS={ctypes.addressof(secret)}\nPORT={listener.getsockname()[1]}\n"
    source += '''
import socket, subprocess, json, errno, encodings.idna
results = {}
if sys.platform == "win32":
    windows_lockdown()
else:
    linux_lockdown()
try:
    open(CANARY, "rb").read()
    results["credential_file_denied"] = False
except PermissionError:
    results["credential_file_denied"] = True
results["environment_secret_absent"] = "QKVM_TEST_SECRET" not in os.environ
try:
    with socket.create_connection(("127.0.0.1", PORT), timeout=2):
        results["network_denied"] = False
except OSError as error:
    results["network_denied"] = isinstance(error, TimeoutError) or error.errno in (errno.EPERM, errno.EACCES) or getattr(error, "winerror", None) == 10013
try:
    subprocess.run([sys.executable, "-c", "pass"], check=True, timeout=3)
    results["child_process_denied"] = False
except OSError:
    results["child_process_denied"] = True
try:
    open(__file__, "ab").write(b"#")
    results["runtime_write_denied"] = False
except PermissionError:
    results["runtime_write_denied"] = True
if sys.platform == "win32":
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel.OpenProcess.restype = ctypes.c_void_p
    for label, rights in [("parent_memory_denied", 0x10), ("parent_handles_denied", 0x40), ("parent_termination_denied", 1)]:
        handle = kernel.OpenProcess(rights, False, PARENT)
        results[label] = not handle and ctypes.get_last_error() == 5
        if handle:
            kernel.CloseHandle(ctypes.c_void_p(handle))
else:
    libc = ctypes.CDLL(None, use_errno=True)
    class Iovec(ctypes.Structure):
        _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]
    destination = ctypes.create_string_buffer(32)
    local = Iovec(ctypes.addressof(destination), 16)
    remote = Iovec(ADDRESS, 16)
    result = libc.process_vm_readv(PARENT, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
    results["parent_memory_denied"] = result == -1 and ctypes.get_errno() == errno.EPERM
    try:
        os.kill(PARENT, 0)
        results["parent_signal_denied"] = False
    except PermissionError:
        results["parent_signal_denied"] = True
print(json.dumps(results), flush=True)
'''
    script = tmp_path / "boundary.py"
    script.write_text(source, encoding="utf-8")
    process = None
    windows = None
    try:
        if sys.platform == "win32":
            from qkvm import _video_windows as windows

            # A separate trusted probe bundle, never replacing a running worker's code.
            with monkeypatch.context() as context:
                context.setattr(windows, "_bundle", None)
                spec = importlib.util.find_spec("av")
                assert spec is not None and spec.origin is not None
                process = windows.AppProcess(Path(spec.origin).parent.parent, script)
                result = read_probe(process)
                windows.cleanup_runtime()
        else:
            process = subprocess.Popen([sys.executable, "-I", "-S", str(script)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={"LANG": "C.UTF-8"}, close_fds=True)
            result = read_probe(process)
        import select

        assert not select.select([listener], [], [], 0)[0], "sandbox reached the listener"
        assert result and all(result.values()), result
    finally:
        listener.close()
        if process is not None:
            process.kill()
            process.wait(timeout=2)
            for stream in (process.stdin, process.stdout):
                stream.close()


def read_probe(process: object) -> dict[str, bool]:
    from typing import Any, cast

    child = cast(Any, process)
    timer = threading.Timer(15, child.kill)
    timer.start()
    try:
        result = child.stdout.read(4096)
        code = child.wait(timeout=2)
        errors = child.stderr.read() if code and getattr(child, "stderr", None) else b""
        assert code == 0, (result, errors)
        return json.loads(result)
    finally:
        timer.cancel()


def test_stalled_worker_is_killed_and_reaped() -> None:
    stopped = threading.Event()
    reaped: list[bool] = []

    class Output(io.BytesIO):
        def read(self, size: int = -1) -> bytes:
            assert stopped.wait(2), "deadline did not stop the worker"
            return b""

    worker = video.Worker.__new__(video.Worker)
    worker._lock = threading.Lock()
    worker._process = SimpleNamespace(stdin=io.BytesIO(), stdout=Output(), kill=stopped.set, wait=lambda timeout: reaped.append(True))
    with pytest.raises(video.VideoError):
        worker._exchange(None, 0.03)
    assert stopped.is_set() and reaped and worker._process is None


def test_unreviewed_receiver_version_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(video.importlib.metadata, "version", lambda name: "99.0.0")
    with pytest.raises(video.VideoError, match="not been verified"):
        video.install_aiortc_boundary()

def test_production_worker_has_kernel_restrictions() -> None:
    """Check the production launch itself, not just the standalone boundary probe."""
    worker = video.Worker()
    try:
        if sys.platform == "linux":
            def status(pid: str) -> dict[str, str]:
                return dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)

            parent = status("self")
            child = status(str(worker._process.pid))
            assert int(child["NoNewPrivs"]) == 1
            assert int(child["Seccomp"]) == 2
            assert int(child["Seccomp_filters"]) > int(parent["Seccomp_filters"])
            assert int(child["Threads"]) == 1
        elif sys.platform == "win32":
            from qkvm import _video_windows as windows

            token = windows.P()
            windows.checked(windows.api(windows.advapi, "OpenProcessToken", [windows.P, windows.wt.DWORD, ctypes.POINTER(windows.P)])(worker._process._handle, 8, ctypes.byref(token)))
            try:
                value, size = windows.wt.DWORD(), windows.wt.DWORD()
                info = windows.api(windows.advapi, "GetTokenInformation", [windows.P, ctypes.c_int, windows.P, windows.wt.DWORD, ctypes.POINTER(windows.wt.DWORD)])
                windows.checked(info(token, 29, ctypes.byref(value), 4, ctypes.byref(size)))
                assert value.value == 1
                info(token, 30, None, 0, ctypes.byref(size))
                groups = ctypes.create_string_buffer(size.value)
                windows.checked(info(token, 30, groups, size.value, ctypes.byref(size)))
                assert ctypes.cast(groups, ctypes.POINTER(windows.wt.DWORD))[0] == 0
                limits = windows.ExtendedLimits()
                query = windows.api(windows.kernel, "QueryInformationJobObject", [windows.P, ctypes.c_int, windows.P, windows.wt.DWORD, windows.P])
                windows.checked(query(worker._process._job, 9, ctypes.byref(limits), ctypes.sizeof(limits), None))
                assert limits.basic.active_processes == 1
                assert limits.process_memory == 1024**3
                assert limits.basic.flags & 0x2108 == 0x2108
            finally:
                windows.close_handle(token)
    finally:
        worker.close()


def test_jpeg_path_never_invokes_native_decoder_in_parent(monkeypatch: pytest.MonkeyPatch) -> None:
    import av
    from qkvm import rfb

    jpeg = video.encode_jpeg(video.RGBFrame(16, 16, bytes(16 * 16 * 3)), None, 2)

    def forbidden(*args: object) -> None:
        raise AssertionError("native decoding attempted in credential-holding parent")

    monkeypatch.setattr(av, "CodecContext", SimpleNamespace(create=forbidden))
    assert len(rfb.decode_jpeg(jpeg, 16, 16)) == 16 * 16 * 3


def test_decoder_preserves_parent_queue_time_through_slow_decoding(monkeypatch: pytest.MonkeyPatch) -> None:
    import queue

    clock = [10.0]
    monkeypatch.setattr(video, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    pending = video.BoundedDecoderQueue()
    codec = SimpleNamespace(mimeType="video/H264")
    pending.put((codec, SimpleNamespace(data=b"encoded", timestamp=7)))
    queued = pending.get_nowait()
    clock[0] = 20.0  # screen returned while the encoded frame waited
    inputs = queue.Queue()
    inputs.put(queued)
    inputs.put(None)
    delivered = []
    worker = SimpleNamespace(close=lambda: None)

    class Decoder:
        def __init__(self, unused: object) -> None:
            self.worker = worker

        def decode(self, encoded: object) -> list[video.VideoFrame]:
            clock[0] = 30.0  # isolated decoding took more time
            return [video.VideoFrame(16, 16, worker, 1)]

    monkeypatch.setattr(video, "H264Decoder", Decoder)
    loop = SimpleNamespace(call_soon_threadsafe=lambda callback, frame: callback(frame))
    output = SimpleNamespace(empty=lambda: True, put_nowait=delivered.append)
    video.decoder_worker(loop, inputs, output)
    assert len(delivered) == 2 and delivered[-1] is None
    assert delivered[0].received_at == 10.0
