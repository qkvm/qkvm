"""A JetKVM's video connection that is closing when its connection's end is stopped (the review of 850745e, L-W11).

The end of a connection gives the video connection a few seconds to close and then leaves it to finish by itself
(`asyncio.shield`). Nothing kept that close: once whoever waited for it was stopped (a tile edited or removed, the wall
stopping) or gave up, the unfinished close could be thrown away by the garbage collector halfway through ("Task was
destroyed but it is pending"), and the connection was never closed to the end. It is held now until it is done.
"""
from __future__ import annotations

import asyncio
import gc
import logging
import time
import weakref
from typing import Any

import pytest

from qkvm import jetkvm
from qkvm.kvm import DeviceSpec


class SlowToClose:
    """A video connection whose close waits on something that only the close itself holds, as the real one may."""

    def __init__(self) -> None:
        self.begun = asyncio.Event()
        self.waiting: weakref.ref[asyncio.Future[None]] | None = None
        self.closed = False

    async def close(self) -> None:
        waiting: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self.waiting = weakref.ref(waiting)
        self.begun.set()
        await waiting
        self.closed = True


def test_a_close_left_to_finish_by_itself_is_kept_until_it_has() -> None:
    destroyed: list[str] = []

    async def run() -> None:
        loop = asyncio.get_running_loop()
        loop.set_exception_handler(lambda _loop, context: destroyed.append(str(context.get("message"))))
        device = jetkvm.JetKvmDevice(DeviceSpec("j", "wall", "http://127.0.0.1:9", "", "secret", kind="jetkvm"))
        pc = SlowToClose()

        async def hold(session: Any) -> None:
            session.pc = pc  # (connected, and then ended at once: the end closes the video connection)

        device._hold = hold  # type: ignore[method-assign]
        ending = asyncio.create_task(device._run(jetkvm._Session()))
        await asyncio.wait_for(pc.begun.wait(), 5)
        ending.cancel()  # (whoever waits for the end is stopped: the tile edited, or the wall stopping)
        await asyncio.gather(ending, return_exceptions=True)
        del ending
        for _ in range(3):
            gc.collect()
            await asyncio.sleep(0)
        waiting = pc.waiting() if pc.waiting is not None else None
        assert waiting is not None, "the close was thrown away before it had finished"
        waiting.set_result(None)
        del waiting
        for _ in range(5):
            await asyncio.sleep(0)
        assert pc.closed

    asyncio.run(run())
    assert not [said for said in destroyed if "destroyed" in said], destroyed


def test_a_stop_that_comes_again_while_the_video_worker_closes_still_closes_the_video_connection() -> None:
    # (The fresh review of b2dac8c, its L6: the video worker was closed first, in a thread, and only then the connection. A
    # stop that came again meanwhile, as the wall's way of stopping a task does every half second, ended the end there,
    # and the video connection was never closed at all.)
    class Started:
        def __init__(self) -> None:
            self.started = False

        async def close(self) -> None:
            self.started = True

    class SlowWorker:
        def close(self) -> None:
            time.sleep(0.5)  # (a decoder process taking its time to end)

    async def run() -> None:
        device = jetkvm.JetKvmDevice(DeviceSpec("j", "wall", "http://127.0.0.1:9", "", "secret", kind="jetkvm"))
        pc = Started()

        async def hold(session: Any) -> None:
            session.pc, session.video_worker = pc, SlowWorker()

        device._hold = hold  # type: ignore[method-assign]
        ending = asyncio.create_task(device._run(jetkvm._Session()))
        await asyncio.sleep(0.1)  # (the end is closing the worker now)
        ending.cancel()
        await asyncio.gather(ending, return_exceptions=True)
        await asyncio.sleep(0.6)
        assert pc.started, "the video connection was never closed"

    asyncio.run(run())


def test_a_video_connection_torn_down_under_its_sctp_tasks_leaves_no_error_nobody_took(caplog: pytest.LogCaptureFixture) -> None:
    # (The soak farm, under overload: "Task exception was never retrieved" and a traceback, at ERROR, from the WebRTC
    # library's SCTP transport.) The tasks that transport sets going by itself (a timer's resend, a flush of what a data
    # channel was given, a transmission) are kept by nothing: one under way as the connection was torn down ended in a
    # ConnectionError, its DTLS transport gone, that nobody took, and asyncio said so once it was collected. It is taken
    # at the boundary the wall sets up before it connects to a JetKVM, and said at debug.
    from aiortc import RTCConfiguration, RTCPeerConnection
    from aiortc.rtcsctptransport import InitChunk

    from qkvm.video import install_aiortc_boundary

    said: list[dict[str, Any]] = []

    async def run() -> None:
        loop = asyncio.get_running_loop()
        loop.set_exception_handler(lambda _loop, context: said.append(context))
        install_aiortc_boundary()  # (as the wall does before it connects to a JetKVM)
        pc = RTCPeerConnection(RTCConfiguration(iceServers=[]))
        pc.createDataChannel("rpc")
        sctp = pc.sctp
        assert sctp is not None
        sctp._remote_port = 5000  # (as an association under way has it, from the answer)
        await pc.close()  # (torn down: its DTLS transport is closed)
        # Its INIT's timer, which fired in the moment before (on a busy computer the loop came to it late): the resend it sets
        # going by itself finds no DTLS transport to send over.
        sctp._t1_chunk = InitChunk()
        sctp._t1_expired()
        sctp._t1_cancel()
        for _ in range(5):
            await asyncio.sleep(0)
        gc.collect()
        await asyncio.sleep(0)

    caplog.set_level(logging.DEBUG, logger="qkvm")
    asyncio.run(run())
    gc.collect()
    assert not said, [context.get("message") for context in said]
    assert "SCTP transport was cut off as its connection closed" in caplog.text  # (it did end so, and was taken)


@pytest.mark.parametrize("kind", [RuntimeError, ConnectionError])
def test_any_other_error_of_a_task_the_sctp_transport_set_going_is_still_said(kind: type[Exception]) -> None:
    # (What the boundary takes is the WebRTC library's own word that the transport under the SCTP one is not connected, and
    # nothing else: any other error is said as asyncio says one nobody took. A ConnectionError too, where something else
    # raised it, as a handler of qKVM's that runs in such a task might: the review of the hold round, L5.)
    from aiortc import RTCConfiguration, RTCPeerConnection
    from aiortc.rtcsctptransport import InitChunk

    from qkvm.video import install_aiortc_boundary

    said: list[dict[str, Any]] = []

    async def run() -> None:
        loop = asyncio.get_running_loop()
        loop.set_exception_handler(lambda _loop, context: said.append(context))
        install_aiortc_boundary()
        pc = RTCPeerConnection(RTCConfiguration(iceServers=[]))
        pc.createDataChannel("rpc")
        sctp = pc.sctp
        assert sctp is not None
        sctp._remote_port = 5000

        async def broken(data: bytes) -> None:
            raise kind("not a connection cut off")

        sctp.transport._send_data = broken  # type: ignore[method-assign]
        sctp._t1_chunk = InitChunk()
        sctp._t1_expired()
        sctp._t1_cancel()
        for _ in range(5):
            await asyncio.sleep(0)
        gc.collect()
        await asyncio.sleep(0)
        del sctp.transport._send_data  # (its own again)
        await pc.close()

    asyncio.run(run())
    gc.collect()
    errors = [context.get("exception") for context in said]
    assert len(errors) == 1 and type(errors[0]) is kind and str(errors[0]) == "not a connection cut off", said
