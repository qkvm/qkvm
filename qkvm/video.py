"""Bounded IPC to a native-video worker with no access to application credentials."""
from __future__ import annotations

import atexit
import asyncio
import importlib.metadata
import queue
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import threading
import time
import weakref
from dataclasses import dataclass
from typing import Any

HEADER = struct.Struct("!4sIIIIII")
MAGIC = b"QKV1"
MAX_SIDE, MAX_PIXELS = 8192, 16_000_000
MAX_BYTES, MAX_COMPRESSED = 48_000_000, 16 * 1024 * 1024
START_WITHIN, WORK_WITHIN = 15.0, 5.0


class VideoError(ValueError):
    """The sandbox is unavailable, stopped, or returned invalid video data."""


def dimensions(width: int, height: int) -> None:
    if type(width) is not int or type(height) is not int or not (0 < width <= MAX_SIDE and 0 < height <= MAX_SIDE and width * height <= MAX_PIXELS):
        raise VideoError("video dimensions exceed limit")


@dataclass(frozen=True)
class RGBFrame:
    width: int
    height: int
    rgb: bytes


@dataclass(frozen=True)
class VideoFrame:
    width: int
    height: int
    worker: Worker
    ident: int
    received_at: float = 0.0  # parent clock, before waiting for isolated decoding


_workers: weakref.WeakSet[Worker] = weakref.WeakSet()
_workers_lock = threading.Lock()


class Worker:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._process: Any = None
        spec = importlib.util.find_spec("av")
        if spec is None or spec.origin is None:
            raise VideoError("native video dependency is unavailable")
        script = Path(__file__).with_name("_video_worker.py").resolve()
        package = str(Path(spec.origin).resolve().parent.parent)
        # A fresh exec, not a forked Python worker: application memory is not copied
        # into the interpreter which will ever handle device-controlled video.
        if sys.platform == "win32":
            from ._video_windows import AppProcess
            self._process = AppProcess(Path(package), script)
        elif sys.platform == "linux":
            environment = {"LANG": "C.UTF-8", "OPENBLAS_NUM_THREADS": "1", "OMP_NUM_THREADS": "1"}
            self._process = subprocess.Popen(
                [sys.executable, "-I", "-S", "-u", str(script), package],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                cwd="/", env=environment, close_fds=True, start_new_session=True,
            )
        else:
            raise VideoError("verified video isolation is unavailable on this platform")
        try:
            if self._exchange(None, START_WITHIN) != (0, 0, 0, 1, b""):
                raise VideoError("video isolation handshake failed")
        except BaseException:
            self.close()
            raise
        with _workers_lock:
            _workers.add(self)

    def _exchange(self, request: bytes | None, within: float) -> tuple[int, int, int, int, bytes]:
        process = self._process
        if process is None:
            raise VideoError("video worker is closed")
        expired = threading.Event()

        def expire() -> None:
            expired.set()
            try:
                process.kill()
            except OSError:
                pass

        timer = threading.Timer(within, expire)
        timer.daemon = True
        timer.start()
        try:
            if request is not None:
                process.stdin.write(request)
                process.stdin.flush()
            header = process.stdout.read(HEADER.size)
            if len(header) != HEADER.size:
                raise VideoError("video worker stopped or isolation could not be established")
            magic, op, width, height, ident, reserved, length = HEADER.unpack(header)
            if op == 1:
                dimensions(width, height)
                limit = width * height * 3
            elif op in {3, 4}:
                limit = MAX_COMPRESSED
            elif op in {0, 2, 255}:
                limit = 0
            else:
                raise VideoError("invalid video worker operation")
            if magic != MAGIC or reserved or length > limit:
                raise VideoError("invalid video worker response")
            # A compromised worker is untrusted: validate length before allocating.
            data = process.stdout.read(length)
            if len(data) != length:
                raise VideoError("truncated video worker response")
            if expired.is_set():
                raise VideoError("video worker exceeded its deadline")
            return op, width, height, ident, data
        except (OSError, ValueError):
            self.close()
            raise VideoError("video worker failed, timed out, or returned invalid data") from None
        finally:
            timer.cancel()
            timer.join(timeout=1)

    def request(self, op: int, width: int = 0, height: int = 0, target: int = 0, quality: int = 0, data: bytes = b"") -> tuple[int, int, int, bytes]:
        if op not in {1, 2, 3, 4} or len(data) > (MAX_BYTES if op == 3 else MAX_COMPRESSED):
            raise VideoError("video request exceeds limit")
        if op in {1, 3}:
            dimensions(width, height)
        if op == 3 and len(data) != width * height * 3:
            raise VideoError("incorrect RGB size")
        if any(type(v) is not int or not 0 <= v <= 0xFFFFFFFF for v in (width, height, target, quality)):
            raise VideoError("invalid video request")
        if not self._lock.acquire(timeout=WORK_WITHIN):
            raise VideoError("video worker is busy")
        try:
            answer, w, h, ident, output = self._exchange(HEADER.pack(MAGIC, op, width, height, target, quality, len(data)) + data, WORK_WITHIN)
            if answer != op:
                raise VideoError("video frame could not be processed")
            if op == 2 and (w, h, ident, output) == (0, 0, 0, b""):
                return w, h, ident, output
            dimensions(w, h)
            if op == 1 and ((w, h) != (width, height) or len(output) != width * height * 3 or ident):
                raise VideoError("invalid decoded rectangle")
            if op == 2 and (not ident or output):
                raise VideoError("invalid decoded video handle")
            if op in {3, 4} and (ident or not 4 <= len(output) <= MAX_COMPRESSED or not output.startswith(b"\xff\xd8") or not output.endswith(b"\xff\xd9")):
                raise VideoError("invalid encoded image")
            return w, h, ident, output
        except VideoError:
            self.close()
            raise
        finally:
            self._lock.release()

    def close(self) -> None:
        process, self._process = getattr(self, "_process", None), None
        if process is not None:
            try:
                process.kill()
            except OSError:
                pass
            try:
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                pass
            for stream in (process.stdin, process.stdout):
                if stream is not None:
                    stream.close()

    def __del__(self) -> None:
        self.close()


class VideoSession:
    """A lazy worker owned by one device or stream, never a process-wide pool."""
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._worker: Worker | None = None
        self._closed = False

    def request(self, *args: Any, **kwargs: Any) -> tuple[int, int, int, bytes]:
        if not self._lock.acquire(timeout=WORK_WITHIN):
            raise VideoError("video session is busy")
        try:
            if self._closed:
                raise VideoError("video session is closed")
            if self._worker is None:
                self._worker = Worker()
            return self._worker.request(*args, **kwargs)
        finally:
            self._lock.release()

    def close(self) -> None:
        with self._lock:
            self._closed = True
            if self._worker is not None:
                self._worker.close()

    def __del__(self) -> None:
        self.close()


def decode_jpeg(data: bytes, width: int, height: int, session: VideoSession | None = None) -> bytes:
    owned = session if session is not None else VideoSession()
    try:
        return owned.request(1, width, height, data=data)[3]
    finally:
        if session is None:
            owned.close()


def encode_jpeg(frame: RGBFrame | VideoFrame, width: int | None, quantizer: int, session: VideoSession | None = None) -> bytes:
    if isinstance(frame, RGBFrame):
        owned = session if session is not None else VideoSession()
        try:
            return owned.request(3, frame.width, frame.height, width or 0, quantizer, frame.rgb)[3]
        finally:
            if session is None:
                owned.close()
    if isinstance(frame, VideoFrame):
        return frame.worker.request(4, frame.ident, 0, width or 0, quantizer)[3]
    raise VideoError("native frames must remain inside the video worker")


class H264Decoder:
    def __init__(self, worker: Worker | None = None) -> None:
        self.worker = worker if worker is not None else Worker()

    def decode(self, encoded: Any) -> list[VideoFrame]:
        w, h, ident, _ = self.worker.request(2, target=int(encoded.timestamp) & 0xFFFFFFFF, data=encoded.data)
        return [VideoFrame(w, h, self.worker, ident)] if ident else []

    def __del__(self) -> None:
        if hasattr(self, "worker"):
            self.worker.close()


def install_aiortc_boundary() -> None:
    """aiortc has no public decoder factory hook; fail closed for every video codec."""
    receiver: Any = importlib.import_module("aiortc.rtcrtpreceiver")

    if importlib.metadata.version("aiortc") != "1.15.0":
        raise VideoError("this WebRTC version has not been verified for video isolation")

    # Never preserve an alternate video fallback, including a future codec added by
    # aiortc. qKVM only negotiates H.264; no audio receiver is configured here.
    receiver.get_decoder = isolated_decoder
    receiver.decoder_worker = decoder_worker


def isolated_decoder(codec: Any) -> H264Decoder:
    if codec.mimeType.lower() != "video/h264":
        raise VideoError("video codec is not permitted")
    return H264Decoder()


class BoundedDecoderQueue(queue.Queue[Any]):
    """Never block the event loop: overload ends decoding instead of queuing forever."""
    def __init__(self, worker: Worker | None = None) -> None:
        self.worker = worker
        super().__init__(maxsize=4)
        self.stopped = False

    def put(self, item: Any, block: bool = True, timeout: float | None = None) -> None:
        with self.not_full:
            if self.stopped:
                return
            if item is None or self._qsize() >= self.maxsize or len(item[1].data) > MAX_COMPRESSED:
                self.stopped = True
                self.queue.clear()
                item = None
            else:
                item = (*item, time.monotonic())
            self._put(item)
            self.unfinished_tasks += 1
            self.not_empty.notify()


def decoder_worker(loop: asyncio.AbstractEventLoop, input_q: Any, output_q: Any) -> None:
    decoder = None

    def deliver(frame: VideoFrame | None) -> None:
        # Only the newest screen matters. Never let a slow viewer retain a backlog.
        while not output_q.empty():
            output_q.get_nowait()
        output_q.put_nowait(frame)

    try:
        while True:
            task = input_q.get()
            if task is None:
                break
            codec, encoded, received_at = task
            if codec.mimeType.lower() != "video/h264":
                raise VideoError("video codec is not permitted")
            if decoder is None:
                decoder = H264Decoder(getattr(input_q, "worker", None))
            for frame in decoder.decode(encoded):
                stamped = VideoFrame(frame.width, frame.height, frame.worker, frame.ident, received_at)
                loop.call_soon_threadsafe(deliver, stamped)
    except (VideoError, OSError, RuntimeError):
        pass  # fail closed and tell the track it ended; no alternate native decoder
    finally:
        if decoder is not None:
            decoder.worker.close()
        try:
            loop.call_soon_threadsafe(deliver, None)
        except RuntimeError:
            pass  # event loop already closed during application shutdown


def close_workers() -> None:
    with _workers_lock:
        workers = list(_workers)
    for worker in workers:
        worker.close()


def shutdown() -> None:
    close_workers()
    windows = sys.modules.get("qkvm._video_windows")
    if windows is not None:
        windows.cleanup_runtime()


atexit.register(shutdown)
