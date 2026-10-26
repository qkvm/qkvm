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
from typing import Any

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
        old0, keep1 = workers[0]._process.pid, workers[1]._process.pid
        assert old0 != keep1
        # A terminated decoder for one server never poisons the other. The server whose worker died
        # gets a fresh isolated worker of its own on the next frame (it does not keep failing), with
        # a new process that is neither the dead one nor the other server's.
        workers[0].close()
        list(clients[0]._draw_tight(0, 0, 16, 16, rfb._Bytes(b"\x90" + jpeg)))
        respawned = clients[0]._video_decoder._worker._process.pid
        assert respawned not in (old0, keep1)
        list(clients[1]._draw_tight(0, 0, 16, 16, rfb._Bytes(b"\x90" + jpeg)))
        assert clients[1]._video_decoder._worker._process.pid == keep1  # the other server's worker is untouched
    finally:
        for client in clients:
            asyncio.run(client.close())
            with pytest.raises(video.VideoError, match="session is closed"):
                video.decode_jpeg(jpeg, 16, 16, client._video_decoder)


def test_native_frames_are_never_accepted_by_parent() -> None:
    with pytest.raises(video.VideoError, match="native frames"):
        video.encode_jpeg(SimpleNamespace(width=16, height=16), None, 2)


def test_a_video_session_respawns_a_worker_that_died_mid_session() -> None:
    """A long-lived encoder or decoder whose worker dies (a deadline kill, out of memory) starts a fresh worker for
    the next request instead of giving VideoError until the console cycles."""
    frame = video.RGBFrame(16, 16, bytes(16 * 16 * 3))
    session = video.VideoSession()
    try:
        first = video.encode_jpeg(frame, None, 2, session)
        assert session._worker is not None
        gone = session._worker._process.pid
        session._worker.close()  # a transient death in the middle of the session
        assert session._worker._process is None
        again = video.encode_jpeg(frame, None, 2, session)  # heals by itself: a new worker
        assert session._worker._process is not None and session._worker._process.pid != gone
        assert again == first
    finally:
        session.close()


def test_a_repeatedly_dying_session_worker_is_not_respawned_in_a_tight_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    """A worker that dies again and again is restarted after a growing pause, not on every call, and the restart is
    logged once."""
    clock = [1000.0]
    monkeypatch.setattr(video, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    starts: list[float] = []
    warnings: list[str] = []
    monkeypatch.setattr(video.log, "warning", lambda message, *a, **k: warnings.append(message))

    class Dying:
        def __init__(self) -> None:
            starts.append(clock[0])
            self._process = object()

        def request(self, *args: object, **kwargs: object) -> tuple[int, int, int, bytes]:
            self._process = None  # dies on use, as Worker.request does when it closes itself
            raise video.VideoError("video worker failed")

        def close(self) -> None:
            self._process = None

    monkeypatch.setattr(video, "Worker", Dying)
    session = video.VideoSession()
    try:
        for _ in range(3):  # within the first pause: one start, no tight-loop respawns
            with pytest.raises(video.VideoError):
                session.request(1, 16, 16, data=b"")
        assert len(starts) == 1
        clock[0] += video.RESPAWN_PAUSE + 0.01  # past the pause: one more start, which dies again
        with pytest.raises(video.VideoError):
            session.request(1, 16, 16, data=b"")
        assert len(starts) == 2
        clock[0] += video.RESPAWN_PAUSE + 0.01  # the pause has grown: not yet allowed
        with pytest.raises(video.VideoError, match="recovering"):
            session.request(1, 16, 16, data=b"")
        assert len(starts) == 2
        assert warnings == [STOPPED]
    finally:
        session.close()


STOPPED = "a video worker stopped mid-session or could not be started; it is started again after a pause"


def test_a_worker_that_dies_every_other_request_is_not_restarted_every_half_second(monkeypatch: pytest.MonkeyPatch) -> None:
    """The pause and the once-a-run warning were reset by every request that got through, so a worker dying on every
    other request was started again 0.5 s after each death, and every death was a warning, without end (3600 starts
    and 3600 warnings in two hours). The pause now comes down only after a while without deaths, and the warning is
    said once a run and at most every so often."""
    clock = [1000.0]
    monkeypatch.setattr(video, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    warnings: list[str] = []
    monkeypatch.setattr(video.log, "warning", lambda message, *a, **k: warnings.append(message))
    starts: list[float] = []
    dying, calls = [True], [0]

    class Flaky:
        def __init__(self) -> None:
            starts.append(clock[0])
            self._process = object()

        def request(self, *args: object, **kwargs: object) -> tuple[int, int, int, bytes]:
            calls[0] += 1
            if dying[0] and calls[0] % 2 == 0:
                self._process = None
                raise video.VideoError("video worker failed, timed out, or returned invalid data")
            return 0, 0, 0, b""

        def close(self) -> None:
            self._process = None

    monkeypatch.setattr(video, "Worker", Flaky)
    session = video.VideoSession()

    def ask_for(seconds: int) -> None:
        for _ in range(seconds):  # one request a second
            try:
                session.request(3, 16, 16, data=b"")
            except video.VideoError:
                pass
            clock[0] += 1.0

    try:
        ask_for(2 * 3600)
        assert len(starts) < 300, len(starts)
        assert warnings == [STOPPED]
        dying[0] = False  # the trouble ends
        ask_for(15 * 60)  # a quarter of an hour without a death
        dying[0], calls[0] = True, 1  # the next request is the one that dies
        before = len(starts)
        ask_for(2)  # one death more, then a start: a fresh run, with the shortest pause again
        assert len(starts) == before + 1
        assert session._retry_at - session._last_death == video.RESPAWN_PAUSE
        assert warnings == [STOPPED, STOPPED]  # a new run, long after the last warning
    finally:
        session.close()


def test_a_request_refused_before_it_reaches_the_worker_is_no_death(monkeypatch: pytest.MonkeyPatch) -> None:
    """A request the parent refuses before the worker sees it (an RGB size that no longer matches: a screen that
    changed size) leaves the worker running. It was counted as a death and logged as one."""
    warnings: list[str] = []
    monkeypatch.setattr(video.log, "warning", lambda message, *a, **k: warnings.append(message))
    starts: list[object] = []

    class Alive:
        def __init__(self) -> None:
            starts.append(self)
            self._process = object()

        def request(self, *args: object, **kwargs: object) -> tuple[int, int, int, bytes]:
            raise video.VideoError("incorrect RGB size")  # raised before the worker is reached: it lives on

        def close(self) -> None:
            self._process = None

    monkeypatch.setattr(video, "Worker", Alive)
    session = video.VideoSession()
    try:
        for _ in range(3):
            with pytest.raises(video.VideoError, match="incorrect RGB size"):
                session.request(3, 16, 16, data=b"")
        assert len(starts) == 1 and session._worker is starts[0]
        assert session._deaths == 0 and warnings == []
    finally:
        session.close()


def test_a_worker_that_cannot_start_waits_out_the_same_pause(monkeypatch: pytest.MonkeyPatch) -> None:
    """An OSError while starting a worker (its AppContainer cannot be made) was outside the pause and tried again at
    every request."""
    clock = [50.0]
    monkeypatch.setattr(video, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(video.log, "warning", lambda *a, **k: None)
    tries: list[float] = []

    def cannot_start(**kwargs: object) -> object:
        tries.append(clock[0])
        raise OSError("Cannot create video AppContainer (0x80070005)")

    monkeypatch.setattr(video, "Worker", cannot_start)
    session = video.VideoSession()
    with pytest.raises(OSError):
        session.request(1, 16, 16, data=b"")
    for _ in range(5):
        with pytest.raises(video.VideoError, match="recovering"):
            session.request(1, 16, 16, data=b"")
    assert len(tries) == 1
    clock[0] += video.RESPAWN_PAUSE + 0.01
    with pytest.raises(OSError):
        session.request(1, 16, 16, data=b"")
    assert len(tries) == 2


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


def test_a_worker_slow_to_die_is_reaped_not_dropped() -> None:
    """A worker that does not exit within close()'s 2 s wait (a thread it raised to a high priority can delay
    teardown) must not be dropped with its AppContainer profile, job and handles unfreed: a reaper finishes the
    cleanup, which for a real worker is its wait() freeing handles, job, profile and processor pair, when it ends."""
    freed = threading.Event()

    class Slow:
        def __init__(self) -> None:
            self.stdin, self.stdout = io.BytesIO(), io.BytesIO()
            self.kills, self.cleaned = 0, False

        def kill(self) -> None:
            self.kills += 1

        def wait(self, timeout: float | None = None) -> int:
            if timeout == 2:  # close()'s quick wait: the worker is still alive
                raise subprocess.TimeoutExpired("isolated video worker", 2)
            self.cleaned = True  # the reaper's later wait: it has now died and is freed
            freed.set()
            return 0

    worker = video.Worker.__new__(video.Worker)
    worker._lock = threading.Lock()
    worker._process = slow = Slow()
    worker.close()
    assert worker._process is None
    assert freed.wait(5), "a worker slow to die was dropped without finishing its cleanup"
    assert slow.cleaned and slow.kills >= 1


def test_shutdown_closes_every_worker_and_the_runtime_where_no_thread_can_start(monkeypatch: pytest.MonkeyPatch) -> None:
    """Python 3.12.0 to 3.12.2 start no thread in atexit. A worker slow to die then made close() start its reaper,
    whose RuntimeError ("can't create new thread at interpreter shutdown") left the other workers open and the runtime
    bundle in place. It is now reaped in place for a bounded time, and no worker's close stops the others' or the
    runtime's cleanup."""

    class NoThreads:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def start(self) -> None:
            raise RuntimeError("can't create new thread at interpreter shutdown")

    reaped: list[tuple[str, float | None]] = []

    class Slow:
        def __init__(self, name: str) -> None:
            self.name, self.stdin, self.stdout = name, io.BytesIO(), io.BytesIO()

        def kill(self) -> None:
            pass

        def wait(self, timeout: float | None = None) -> int:
            if timeout == 2:  # close()'s own wait: not ended yet
                raise subprocess.TimeoutExpired("isolated video worker", 2)
            reaped.append((self.name, timeout))
            return 0

    class Broken(Slow):
        def kill(self) -> None:
            raise RuntimeError("a close that fails for a reason of its own")

    workers = []
    for process in (Slow("first"), Broken("broken"), Slow("second")):
        worker = video.Worker.__new__(video.Worker)
        worker._lock, worker._process = threading.Lock(), process
        workers.append(worker)
    runtime: list[bool] = []
    monkeypatch.setattr(video, "threading", SimpleNamespace(Thread=NoThreads))
    monkeypatch.setattr(video, "_reaping", set())
    monkeypatch.setattr(video, "_shutdown_deadline", None, raising=False)
    # Outside shutdown too: a reaper thread that cannot be started is replaced by a bounded wait in place.
    alone = video.Worker.__new__(video.Worker)
    alone._lock, alone._process = threading.Lock(), Slow("alone")
    alone.close()
    assert [name for name, _ in reaped] == ["alone"]
    reaped.clear()
    monkeypatch.setattr(video, "_workers", workers)
    monkeypatch.setitem(sys.modules, "qkvm._video_windows", SimpleNamespace(cleanup_runtime=lambda: runtime.append(True)))
    video.shutdown()
    assert sorted(name for name, _ in reaped) == ["first", "second"], reaped
    assert all(timeout is not None and timeout <= 10 for _, timeout in reaped)  # a bounded wait, never forever
    assert runtime == [True], "the runtime bundle was not cleaned up"
    assert video._reaping == set()


def test_shutdown_waits_for_all_slow_workers_within_one_shared_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only the kills happened together at shutdown; each worker's waits (2 s in close, 3 s more in place) came one
    after another, so three workers that would not end took 15 s. They now share one deadline."""
    import time

    class Slow:
        def __init__(self) -> None:
            self.stdin, self.stdout = io.BytesIO(), io.BytesIO()

        def kill(self) -> None:
            pass

        def wait(self, timeout: float | None = None) -> int:
            time.sleep(timeout or 0)  # never ends within the wait
            raise subprocess.TimeoutExpired("isolated video worker", timeout or 0)

    workers = []
    for _ in range(3):
        worker = video.Worker.__new__(video.Worker)
        worker._lock, worker._process = threading.Lock(), Slow()
        workers.append(worker)
    monkeypatch.setattr(video, "SHUTDOWN_WITHIN", 0.6, raising=False)
    monkeypatch.setattr(video, "_shutdown_deadline", None, raising=False)
    monkeypatch.setattr(video, "_shutting_down", False, raising=False)
    monkeypatch.setattr(video, "_reaping", set())
    monkeypatch.setattr(video, "_workers", workers)
    monkeypatch.setitem(sys.modules, "qkvm._video_windows", SimpleNamespace(cleanup_runtime=lambda: None))
    began = time.monotonic()
    video.shutdown()
    took = time.monotonic() - began
    assert took < 0.6 + 1.0, f"three slow workers held shutdown for {took:.1f} s, not one shared deadline"


def test_shutdown_also_waits_for_a_worker_its_reaper_was_still_waiting_for(monkeypatch: pytest.MonkeyPatch) -> None:
    """In a normal stop qKVM closes every device before atexit, so a worker slow to die is already with a daemon
    reaper, which shutdown() ignored and which is cut off at exit, leaving the worker's AppContainer profile behind.
    shutdown() now reaps those too, in place, within the same deadline."""
    import time

    began = time.monotonic()

    class EndsLater:
        def __init__(self) -> None:
            self.stdin, self.stdout = io.BytesIO(), io.BytesIO()
            self.cleaned = False

        def kill(self) -> None:
            pass

        def wait(self, timeout: float | None = None) -> int:
            left = 2.5 - (time.monotonic() - began)  # it ends 2.5 s after the test begins
            if left > 0 and timeout is not None and timeout < left:
                time.sleep(timeout)
                raise subprocess.TimeoutExpired("isolated video worker", timeout)
            time.sleep(max(0.0, left))
            self.cleaned = True  # a real worker's wait() frees its handles, job, profile and pair here
            return 0

    monkeypatch.setattr(video, "_shutdown_deadline", None, raising=False)
    monkeypatch.setattr(video, "_shutting_down", False, raising=False)
    monkeypatch.setattr(video, "_reaping", set())
    monkeypatch.setattr(video, "_workers", [])
    monkeypatch.setitem(sys.modules, "qkvm._video_windows", SimpleNamespace(cleanup_runtime=lambda: None))
    worker = video.Worker.__new__(video.Worker)
    worker._lock, worker._process = threading.Lock(), (process := EndsLater())
    worker.close()  # the device is closed in qKVM's own stop: 2 s, then it goes to a reaper
    assert video._reaping == {process} and not process.cleaned
    video.shutdown()  # atexit
    assert process.cleaned, "the worker a reaper was waiting for was left to be cut off at exit"
    assert video._reaping == set()


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


def _own_processors() -> list[int]:
    """The processors this process may run on, as the worker's parent sees them."""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined,unused-ignore]
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.GetProcessAffinityMask.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_size_t)]
    mine, system = ctypes.c_size_t(), ctypes.c_size_t()
    assert kernel32.GetProcessAffinityMask(kernel32.GetCurrentProcess(), ctypes.byref(mine), ctypes.byref(system))
    return [bit for bit in range(64) if mine.value >> bit & 1]


def _processors() -> int:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined,unused-ignore]
    kernel32.GetActiveProcessorCount.argtypes = [ctypes.c_ushort]
    kernel32.GetActiveProcessorCount.restype = ctypes.c_ulong
    return int(kernel32.GetActiveProcessorCount(0xFFFF))  # every processor group


def _job_limits(windows: Any, job: object) -> tuple[Any, Any]:
    """The job's basic and extended limits, and its CPU rate control (flags, rate)."""
    query = windows.api(windows.kernel, "QueryInformationJobObject", [windows.P, ctypes.c_int, windows.P, windows.wt.DWORD, windows.P])
    limits = windows.ExtendedLimits()
    windows.checked(query(job, 9, ctypes.byref(limits), ctypes.sizeof(limits), None))
    rate = (ctypes.c_ulong * 2)()
    windows.checked(query(job, 15, ctypes.byref(rate), ctypes.sizeof(rate), None))  # JobObjectCpuRateControlInformation
    return limits, rate


@pytest.mark.skipif(sys.platform != "win32", reason="the Windows worker's job")
def test_a_windows_workers_job_holds_it_to_two_processors() -> None:
    """The Linux worker runs one thread (its filter allows no clone): one processor at a time. Windows cannot forbid a
    second thread, so the job holds all the worker's threads to two of qKVM's processors (one where it has fewer than
    four), which the worker cannot change. Not a CPU rate cap: Windows gives a rate-capped job's threads less time than
    others on busy processors, and 4K video fell far behind under one on busy slow cores."""
    from qkvm import _video_windows as windows

    if getattr(windows, "processor_groups", lambda: 1)() > 1:
        pytest.skip("more than 64 processors: test_with_processor_groups_the_job_caps_cpu_time_instead")
    own = _own_processors()
    worker = video.Worker()
    try:
        limits, rate = _job_limits(windows, worker._process._job)
    finally:
        worker.close()
    assert limits.basic.flags & 0x10, "the worker's processors are not limited (JOB_OBJECT_LIMIT_AFFINITY)"
    assert limits.basic.affinity & ~sum(1 << bit for bit in own) == 0, hex(limits.basic.affinity)
    assert bin(limits.basic.affinity).count("1") == max(1, min(2, len(own) // 2)), hex(limits.basic.affinity)
    assert rate[0] == 0, "a CPU rate cap slows the worker's own thread on busy processors"


@pytest.mark.skipif(sys.platform != "win32", reason="the Windows worker's job")
def test_workers_are_spread_over_qkvms_processors() -> None:
    """Two processors half of them apart (not one core's two hyperthreads), one where there are fewer than four, each
    worker the next ones, and only the processors qKVM itself may run on."""
    from qkvm._video_windows import processors_for

    assert [processors_for([5], index) for index in range(3)] == [1 << 5] * 3
    assert [processors_for([0, 1], index) for index in range(3)] == [0b01, 0b10, 0b01]
    assert [processors_for([0, 1, 2], index) for index in range(4)] == [0b001, 0b010, 0b100, 0b001]
    assert [processors_for([0, 1, 2, 3], index) for index in range(3)] == [0b0101, 0b1010, 0b0101]
    assert [processors_for(list(range(16)), index) for index in range(9)] == [1 << i | 1 << (i + 8) for i in range(8)] + [1 << 8 | 1]
    held = [3, 5, 9, 12, 20]  # qKVM started held to some processors: the workers get only those
    masks = [processors_for(held, index) for index in range(10)]
    assert all(mask & ~sum(1 << bit for bit in held) == 0 and bin(mask).count("1") == 2 for mask in masks)
    assert len(set(masks)) == 5
    with pytest.raises(OSError):
        processors_for([], 0)


@pytest.mark.skipif(sys.platform != "win32", reason="the Windows worker's job")
def test_a_new_worker_takes_the_pair_with_the_fewest_live_workers(monkeypatch: pytest.MonkeyPatch) -> None:
    """The placement follows which workers are alive, not a count that only ever grows: a pair that falls empty is
    taken before any pair is shared. Before, the Nth worker's pair was N mod pairs, so with 16 processors the 9th
    worker was put on the 1st's pair even though a pair had since fallen empty, and a worker taken over there could
    stall the worker it shared with."""
    from qkvm import _video_windows as windows

    monkeypatch.setattr(windows, "own_processors", lambda: list(range(16)))  # 8 pairs
    monkeypatch.setattr(windows, "_pair_load", {}, raising=False)
    placed = [windows.next_processors()[0] for _ in range(8)]
    assert sorted(placed) == list(range(8)), placed  # one worker on each pair, none shared
    windows.release_processors(3)  # the worker on pair 3 ends
    assert windows.next_processors()[0] == 3, "the freed pair was not reused"
    windows.release_processors(6)
    windows.release_processors(6)  # a second release of a pair that holds none must not go negative
    assert windows.next_processors()[0] == 6
    assert windows.next_processors()[0] == 0  # all pairs full again: the least loaded, lowest index first
    assert windows._pair_load[0] == 2 and sum(windows._pair_load.values()) == 9 and len(windows._pair_load) == 8


@pytest.mark.skipif(sys.platform != "win32", reason="the Windows worker's job")
def test_a_worker_restarted_after_a_death_is_not_put_back_beside_what_stalled_it(monkeypatch: pytest.MonkeyPatch) -> None:
    """With two workers on every pair, a worker that missed its deadline (stalled by one taken over beside it) was
    started again on its own pair: its death made that pair the least crowded. A pair whose worker missed its
    deadline is now passed over by every placement for a while, and a restart avoids the pair its worker died on
    while another pair is as free."""
    from qkvm import _video_windows as windows

    clock = [500.0]
    monkeypatch.setattr(windows, "time", SimpleNamespace(monotonic=lambda: clock[0]), raising=False)
    monkeypatch.setattr(windows, "own_processors", lambda: list(range(16)))  # 8 pairs
    monkeypatch.setattr(windows, "_pair_load", {})
    monkeypatch.setattr(windows, "_suspect", {}, raising=False)
    for _ in range(16):
        windows.next_processors()  # two workers on every pair
    windows.mark_stalled(3)  # the legitimate worker on pair 3 missed its deadline and is killed
    assert windows.next_processors(avoid=3)[0] != 3  # not yet reaped: its replacement goes elsewhere
    windows.release_processors(3)  # reaped: pair 3 now holds one worker, the one taken over
    assert windows.next_processors()[0] != 3, "a new worker was put beside the worker that stalled the last one"
    clock[0] += windows.SUSPECT_FOR + 1  # long after: pair 3 is an ordinary pair again
    assert windows.next_processors()[0] == 3
    # A death that was no stall (a picture that killed the worker): its pair loses ties only.
    monkeypatch.setattr(windows, "_pair_load", {})
    for _ in range(8):
        windows.next_processors()  # one on each pair
    assert windows.next_processors(avoid=0)[0] == 1  # pair 0 not yet given back: as free as pair 1, so pair 1
    windows.release_processors(5)
    assert windows.next_processors(avoid=5)[0] == 5  # strictly the freest: it is used


@pytest.mark.skipif(sys.platform != "win32", reason="the Windows worker's job")
def test_an_empty_pair_is_used_first_even_when_its_worker_missed_its_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    """A pair marked after a missed deadline was passed over for a minute even when it was empty, so new workers were
    put beside others while a pair stood free, against "shared only when live workers outnumber pairs", and a worker
    taken over could move itself next to a decoder by getting itself killed. A mark counts only while a live worker
    still holds the pair."""
    from qkvm import _video_windows as windows

    monkeypatch.setattr(windows, "own_processors", lambda: list(range(8)))  # 4 pairs
    monkeypatch.setattr(windows, "_pair_load", {})
    monkeypatch.setattr(windows, "_suspect", {})
    assert [windows.next_processors()[0] for _ in range(4)] == [0, 1, 2, 3]  # one worker on each pair
    windows.mark_stalled(2)  # the worker on pair 2 missed its deadline (a slow frame, or one that ended itself)
    windows.release_processors(2)  # and was reaped: pair 2 is empty
    assert windows.next_processors(avoid=2)[0] == 2, "its session's restart was put beside another worker"
    windows.release_processors(2)
    assert windows.next_processors()[0] == 2, "a new worker was put beside another while pair 2 stood empty"
    assert sorted(windows._pair_load.values()) == [1, 1, 1, 1]  # nobody shares
    windows.mark_stalled(2)  # this time a worker stays on pair 2 (the one that may have done the stalling)
    assert windows.next_processors()[0] == 0  # the marked pair that still holds a worker is passed over


def test_a_missed_deadline_marks_the_workers_pair_and_its_restart_avoids_that_pair(monkeypatch: pytest.MonkeyPatch) -> None:
    """The deadline kill tells the placement which pair to pass over, and a session restarting its worker passes
    the pair the dead worker ran on, so the replacement is not started back beside it."""
    stopped = threading.Event()
    stalls: list[bool] = []

    class Output(io.BytesIO):
        def read(self, size: int = -1) -> bytes:
            stopped.wait(2)
            return b""

    worker = video.Worker.__new__(video.Worker)
    worker._lock = threading.Lock()
    worker._process = SimpleNamespace(stdin=io.BytesIO(), stdout=Output(), kill=stopped.set, wait=lambda timeout: 0,
                                      mark_stalled=lambda: stalls.append(True))
    with pytest.raises(video.VideoError):
        worker._exchange(None, 0.03)
    assert stalls == [True]

    made: list[dict[str, object]] = []

    class Placed:
        def __init__(self, **kwargs: object) -> None:
            made.append(kwargs)
            self.pair, self._process = 4, object()

        def request(self, *args: object, **kwargs: object) -> tuple[int, int, int, bytes]:
            self._process = None  # it dies on its first request
            raise video.VideoError("video worker failed, timed out, or returned invalid data")

        def close(self) -> None:
            self._process = None

    monkeypatch.setattr(video, "Worker", Placed)
    clock = [100.0]
    monkeypatch.setattr(video, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    session = video.VideoSession()
    try:
        with pytest.raises(video.VideoError):
            session.request(1, 16, 16, data=b"")
        clock[0] += 60  # past any pause
        with pytest.raises(video.VideoError):
            session.request(1, 16, 16, data=b"")
    finally:
        session.close()
    assert made == [{}, {"avoid": 4}]


@pytest.mark.skipif(sys.platform != "win32", reason="the Windows worker's job")
def test_with_processor_groups_the_job_caps_cpu_time_instead(monkeypatch: pytest.MonkeyPatch) -> None:
    """More than 64 processors are split into groups, and a job's affinity covers one: there the job caps the CPU time
    of all the worker's threads together, two processors' worth (half the machine where that is less)."""
    from qkvm import _video_windows as windows

    monkeypatch.setattr(windows, "processor_groups", lambda: 2)
    worker = video.Worker()
    try:
        limits, rate = _job_limits(windows, worker._process._job)
    finally:
        worker.close()
    assert not limits.basic.flags & 0x10
    assert rate[0] == 0x1 | 0x4, "the CPU rate is not capped (enable and hard cap)"
    counts = (1, 2, 3, 4, 9, 24, 200)
    assert [windows.cpu_rate(n) for n in counts] == [10000, 5000, 5000, 5000, 2223, 834, 100]
    assert rate[1] == windows.cpu_rate(_processors())


@pytest.mark.skipif(sys.platform != "win32", reason="the Windows worker's job")
def test_a_windows_worker_made_to_spin_is_held_to_its_processors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A decoder taken over runs what it likes in the worker: here it tries to widen its processors to all of them and
    starts four threads spinning in native code (outside the GIL), after the same lockdown as the worker's. Unlimited
    they took four processors; the job holds them to its two, and the worker could not widen them."""
    import time

    from qkvm import _video_windows as windows

    source = Path(_video_worker.__file__).read_text(encoding="utf-8").replace('if __name__ == "__main__":\n    main()', '')
    source += '''
import threading
windows_lockdown()
kernel = ctypes.WinDLL("kernel32", use_last_error=True)
kernel.GetCurrentProcess.restype = ctypes.c_void_p
kernel.GetProcessAffinityMask.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_size_t)]
kernel.SetProcessAffinityMask.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
mine, system = ctypes.c_size_t(), ctypes.c_size_t()
kernel.GetProcessAffinityMask(kernel.GetCurrentProcess(), ctypes.byref(mine), ctypes.byref(system))
kernel.SetProcessAffinityMask(kernel.GetCurrentProcess(), system.value)  # every processor (said to succeed in a job)
kernel.VirtualAlloc.restype = ctypes.c_void_p
kernel.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
code = kernel.VirtualAlloc(None, 4096, 0x3000, 0x40)
ctypes.memmove(code, bytes([0xEB, 0xFE]), 2)  # jmp $: native code that never returns
spin = ctypes.CFUNCTYPE(None)(code)
for _ in range(4):
    threading.Thread(target=spin, daemon=True).start()
sys.stdout.buffer.write(b"spinning\\n")
sys.stdout.buffer.flush()
sys.stdin.buffer.read()
'''
    script = tmp_path / "spin.py"
    script.write_text(source, encoding="utf-8")
    times = windows.api(windows.kernel, "GetProcessTimes", [windows.P] + [ctypes.POINTER(ctypes.c_uint64)] * 4)

    def spent(handle: object) -> float:
        created, ended, kernel_time, user_time = (ctypes.c_uint64() for _ in range(4))
        windows.checked(times(handle, ctypes.byref(created), ctypes.byref(ended), ctypes.byref(kernel_time), ctypes.byref(user_time)))
        return (kernel_time.value + user_time.value) / 1e7

    process: Any = None
    try:
        with monkeypatch.context() as context:
            # A separate trusted probe bundle, never replacing a running worker's code.
            context.setattr(windows, "_bundle", None)
            try:
                spec = importlib.util.find_spec("av")
                assert spec is not None and spec.origin is not None
                process = windows.AppProcess(Path(spec.origin).parent.parent, script)
                timer = threading.Timer(15, process.kill)
                timer.start()
                try:
                    assert process.stdout.readline() == b"spinning\n"
                finally:
                    timer.cancel()
                time.sleep(0.5)  # the threads are under way
                began, used = time.perf_counter(), spent(process._handle)
                time.sleep(2.0)
                processors = (spent(process._handle) - used) / (time.perf_counter() - began)
                mask, system = ctypes.c_size_t(), ctypes.c_size_t()
                affinity = windows.api(windows.kernel, "GetProcessAffinityMask", [windows.P, ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_size_t)])
                windows.checked(affinity(process._handle, ctypes.byref(mask), ctypes.byref(system)))
                limits, _ = _job_limits(windows, process._job)
            finally:
                if process is not None:
                    process.kill()
                    process.wait(timeout=5)
                windows.cleanup_runtime()
        bound = max(1, min(2, len(_own_processors()) // 2))
        assert processors < bound + 0.5, f"a spinning worker used {processors:.2f} processors (it may have {bound})"
        assert mask.value & ~limits.basic.affinity == 0 and bin(mask.value).count("1") == bound, (hex(mask.value), hex(limits.basic.affinity))
    finally:
        if process is not None:
            for stream in (process.stdin, process.stdout):
                stream.close()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows handle inheritance")
def test_a_workers_pipe_ends_are_inheritable_only_inside_its_own_creation(monkeypatch: pytest.MonkeyPatch) -> None:
    """A process started with inherited handles and no list of them takes every handle that can be inherited at that
    moment: one started by anything in qKVM while a worker is being made would take the worker's pipe ends and keep
    its pipes open (a dead worker's output never ends; whatever holds them can write into it). Looked at before and
    after every kernel32 call that making a worker makes: no new handle can be inherited outside the lock held for the
    worker's own CreateProcessW, and the child's three ends (input, output, null error) can be, for that call."""
    from qkvm import _video_windows as windows

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined,unused-ignore]
    information = kernel32.GetHandleInformation
    information.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    count = kernel32.GetProcessHandleCount
    count.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p

    def inheritable() -> set[int]:
        error = ctypes.get_last_error()  # what the call looked at said, kept for whoever reads it next
        try:
            total = ctypes.c_ulong()
            assert count(kernel32.GetCurrentProcess(), ctypes.byref(total))
            found: set[int] = set()
            seen, flags, value = 0, ctypes.c_ulong(), 4
            while seen < total.value and value < 1 << 22:
                if information(value, ctypes.byref(flags)):
                    seen += 1
                    if flags.value & 1:  # HANDLE_FLAG_INHERIT
                        found.add(value)
                value += 4
            return found
        finally:
            ctypes.set_last_error(error)

    lock = getattr(windows, "inheriting", None)
    real = windows.kernel
    looks: list[tuple[str, frozenset[int], bool]] = []

    class Watched:
        def __init__(self, name: str, function: object) -> None:
            object.__setattr__(self, "name", name)
            object.__setattr__(self, "function", function)

        def __setattr__(self, key: str, value: object) -> None:
            setattr(self.function, key, value)  # argtypes and restype, set by api()

        def __call__(self, *args: object) -> object:
            looks.append(("before " + self.name, frozenset(inheritable() - baseline), lock is not None and lock.locked()))
            try:
                return self.function(*args)  # type: ignore[operator]
            finally:
                looks.append(("after " + self.name, frozenset(inheritable() - baseline), lock is not None and lock.locked()))

    class Kernel:
        def __getattr__(self, name: str) -> Watched:
            return Watched(name, getattr(real, name))

    baseline = inheritable()
    monkeypatch.setattr(windows, "kernel", Kernel())
    monkeypatch.setattr(windows, "close_handle", Watched("CloseHandle", windows.close_handle))
    worker = video.Worker()
    try:
        left = inheritable() - baseline
    finally:
        worker.close()
    assert any(point == "before CreateProcessW" for point, _, _ in looks), "the worker was not made through the calls looked at"
    outside = [(point, sorted(handles)) for point, handles, locked in looks if handles and not locked]
    assert not outside, f"a worker's handles could be inherited by any other process started then: {outside[:4]}"
    creation = [handles for point, handles, _ in looks if point == "before CreateProcessW"]
    assert [len(handles) for handles in creation] == [3], creation
    assert not left


def test_qkvm_starts_no_process_that_takes_every_inheritable_handle() -> None:
    """On Windows, CPython's subprocess gives a child the handles it lists (PROC_THREAD_ATTRIBUTE_HANDLE_LIST) or none at
    all, unless it is told close_fds=False; os.system, os.spawn*, os.exec* and os.startfile give the new process every
    handle that can be inherited. A worker's pipe ends can be inherited for the moment of its own creation: nothing in
    qKVM starts a process in a way that would take them then, other than that CreateProcessW, which lists its three."""
    import ast

    found = []
    for path in sorted(Path(video.__file__).parent.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), str(path))):
            name = None
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "os":
                name = "os." + node.attr
            elif isinstance(node, ast.ImportFrom) and node.module == "os":
                name = ", ".join("os." + alias.name for alias in node.names)
            if name and any(word in name for word in ("os.system", "os.startfile", "os.spawn", "os.exec")):
                found.append(f"{path.name}:{node.lineno}: {name}")
            if isinstance(node, ast.keyword) and node.arg == "close_fds" and not (isinstance(node.value, ast.Constant) and node.value.value is True):
                found.append(f"{path.name}:{node.value.lineno}: close_fds not True")
            if path.name != "_video_windows.py" and (
                (isinstance(node, ast.Attribute) and node.attr.startswith("CreateProcess"))
                or (isinstance(node, ast.Constant) and isinstance(node.value, str) and "CreateProcess" in node.value)
            ):
                found.append(f"{path.name}:{node.lineno}: CreateProcess")
    assert not found, found
