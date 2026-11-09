"""Reads of a served image whose files are opened and let go of by the reader threads, under faults made on purpose: an
opening and a cut-off in each order, a pool replaced, a pool stopped with its queue cancelled, an opening that raises
what is no OSError. The outside review's third round (Codex) wrote these; two failed until 0.3.1: the cancelled queue's
jobs that close the files and give back the places were dropped (eight of each left), and a ValueError while opening
kept its place.
"""
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from starlette.requests import ClientDisconnect

from qkvm import served, server
from tests.test_served_images_as_the_outside_review_read_them import (
    a_wall_lending, asked, route,
)


WAIT = 8


def ready(event):
    assert event.wait(WAIT), "bounded probe event timed out"


def fixture(tmp_path):
    _, app, _, lending = a_wall_lending(tmp_path, b"round three")
    return app, lending


@pytest.mark.parametrize("worker_first", [False, True], ids=["abandon-first", "open-first"])
@pytest.mark.parametrize("fail", [False, True], ids=["success", "io-error"])
def test_running_open_races(tmp_path, monkeypatch, worker_first, fail):
    _, lending = fixture(tmp_path)
    # A second active slot makes any duplicate subtraction visible.
    assert lending.take(2) and lending.take(2)
    other = served.Slot(lending)
    entered, proceed = threading.Event(), threading.Event()
    closing, close_allowed = threading.Event(), threading.Event()
    closed = []
    real_open = lending.opened

    class TrackedFile:
        def __init__(self, actual):
            self.actual = actual

        def close(self):
            closing.set()
            ready(close_allowed)
            self.actual.close()
            closed.append(self.actual.closed)

    def gated_open():
        entered.set()
        ready(proceed)
        if fail:
            raise OSError("bounded simulated share error")
        return TrackedFile(real_open())

    monkeypatch.setattr(lending, "opened", gated_open)
    with ThreadPoolExecutor(max_workers=2) as readers:
        op = served.Opening(lending, served.Slot(lending), lambda: readers)
        try:
            op.pending = readers.submit(op.run)
            ready(entered)
            if worker_first:
                proceed.set()
                if fail:
                    with pytest.raises(OSError):
                        op.pending.result(WAIT)
                else:
                    assert op.pending.result(WAIT) is not None
            op.abandon()
            op.abandon()
            if not worker_first:
                assert lending.at_once == 2
            proceed.set()
            if not fail:
                ready(closing)
                assert lending.at_once == 2
                # An extra abandon during close cannot release either place early.
                op.abandon()
                assert lending.at_once == 2
            close_allowed.set()
        finally:
            proceed.set()
            close_allowed.set()
    assert closed == ([] if fail else [True])
    assert lending.at_once == 1
    op.abandon()
    assert lending.at_once == 1
    other.give_back()
    assert lending.at_once == 0


@pytest.mark.parametrize("who", ["abandon", "asyncio", "pool"])
def test_queued_open_cancellation(tmp_path, monkeypatch, who):
    _, lending = fixture(tmp_path)
    assert lending.take(1)
    started, release = threading.Event(), threading.Event()
    attempts = []
    monkeypatch.setattr(lending, "opened", lambda: attempts.append(1))

    def occupy():
        started.set()
        ready(release)

    with ThreadPoolExecutor(max_workers=1) as readers:
        readers.submit(occupy)
        try:
            ready(started)
            op = served.Opening(lending, served.Slot(lending), lambda: readers)
            op.pending = readers.submit(op.run)
            if who == "abandon":
                op.abandon()
            else:
                async def cancelling_task():
                    async def await_open():
                        try:
                            await asyncio.wrap_future(op.pending)
                        except asyncio.CancelledError:
                            # Differentiate actual wrap_future propagation from
                            # independent cancellation by Opening.abandon.
                            assert op.pending.cancelled()
                            assert lending.at_once == 1
                            op.abandon()
                            raise

                    task = asyncio.create_task(await_open())
                    await asyncio.sleep(0)
                    if who == "asyncio":
                        task.cancel()
                    else:
                        readers.shutdown(wait=False, cancel_futures=True)
                    with pytest.raises(asyncio.CancelledError):
                        await task

                asyncio.run(cancelling_task())
            op.abandon()
            assert op.pending.cancelled()
            assert lending.at_once == 0 and not attempts
        finally:
            release.set()
    assert not attempts


@pytest.mark.parametrize("mode", ["pool-already-stopped", "replacement"])
def test_completed_open_cleanup_uses_current_pool(tmp_path, monkeypatch, mode):
    _, lending = fixture(tmp_path)
    assert lending.take(1)
    closed_on = []
    real_open = lending.opened

    class TrackedFile:
        def __init__(self):
            self.actual = real_open()

        def close(self):
            self.actual.close()
            closed_on.append(threading.current_thread().name)

    monkeypatch.setattr(lending, "opened", TrackedFile)
    with ThreadPoolExecutor(max_workers=1) as old, ThreadPoolExecutor(
        max_workers=1, thread_name_prefix="review-replacement"
    ) as replacement:
        current = old
        op = served.Opening(lending, served.Slot(lending), lambda: current)
        op.pending = old.submit(op.run)
        handle = op.pending.result(WAIT)
        old.shutdown()
        if mode == "replacement":
            current = replacement
        op.abandon()
        op.abandon()
    assert len(closed_on) == 1 and handle.actual.closed and lending.at_once == 0
    if mode == "replacement":
        assert closed_on[0].startswith("review-replacement")
    else:
        assert closed_on == [threading.current_thread().name]


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_executor_cancels_already_accepted_cleanup(tmp_path, monkeypatch, method):
    app, lending = fixture(tmp_path)
    real_open = lending.opened
    allow_opens, blocker_started, release_blocker = (
        threading.Event(), threading.Event(), threading.Event()
    )
    handles = []
    pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="review-queued")
    fresh_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="review-fresh")
    monkeypatch.setattr(server, "SERVED_READERS", pool)

    def hold_opens():
        ready(allow_opens)
        held = real_open()
        handles.append(held)  # Inspect explicit close even if GC might otherwise close it.
        return held

    def occupy_worker():
        blocker_started.set()
        ready(release_blocker)

    monkeypatch.setattr(lending, "opened", hold_opens)
    image = route(app, "/media/{token}/{name}", method)
    path = f"/media/{lending.token}/{lending.url_name}"

    async def run():
        # All opens enter the queue before the blocker. All file-close jobs will
        # be accepted behind it, then selectively cancelled by the old pool.
        jobs = [
            asyncio.create_task(image(lending.token, lending.url_name, asked(app, method, path)))
            for _ in range(served.MOST_AT_ONCE)
        ]
        await asyncio.sleep(0)
        assert lending.at_once == served.MOST_AT_ONCE
        blocker = pool.submit(occupy_worker)
        allow_opens.set()
        replies = await asyncio.wait_for(asyncio.gather(*jobs), WAIT)
        assert all(reply.status_code == 200 for reply in replies)
        ready(blocker_started)
        if method == "GET":
            async def receive():
                return {"type": "http.request"}

            async def cut_off(message):
                # Normal ASGI 2.4 peer disconnect at response start. Handed
                # gives the handle to the reader queue in its finally clause.
                raise OSError("bounded client disconnect")

            for reply in replies:
                with pytest.raises(ClientDisconnect):
                    await reply(asked(app, method, path).scope, receive, cut_off)
        assert len(handles) == served.MOST_AT_ONCE
        assert lending.at_once == served.MOST_AT_ONCE
        pool.shutdown(wait=False, cancel_futures=True)
        monkeypatch.setattr(server, "SERVED_READERS", fresh_pool)
        release_blocker.set()
        blocker.result(WAIT)
        pool.shutdown()
        occupied = lending.at_once
        closed = sum(h.closed for h in handles)
        reply = await image(lending.token, lending.url_name, asked(app, method, path))
        status = reply.status_code
        if getattr(reply, "_done", None):
            reply._done()
        print(f"{method}: after cancelled cleanup and pool replacement: at_once={occupied}, "
              f"explicitly closed={closed}/{served.MOST_AT_ONCE}, next status={status}")
        assert (occupied, closed, status) == (0, served.MOST_AT_ONCE, 200)

    try:
        asyncio.run(run())
    finally:
        allow_opens.set()
        release_blocker.set()
        pool.shutdown()
        fresh_pool.shutdown()
        for handle in handles:
            handle.close()


@pytest.mark.parametrize("exception", [OSError, ValueError], ids=["expected-oserror", "unexpected-valueerror"])
def test_open_exception_returns_slot(tmp_path, monkeypatch, exception):
    app, lending = fixture(tmp_path)
    image = route(app, "/media/{token}/{name}", "HEAD")

    def fail():
        raise exception("bounded injected open error")

    monkeypatch.setattr(lending, "opened", fail)
    async def run():
        request = asked(app, "HEAD", f"/media/{lending.token}/{lending.url_name}")
        if exception is OSError:
            assert (await image(lending.token, lending.url_name, request)).status_code == 410
        else:
            with pytest.raises(ValueError):
                await image(lending.token, lending.url_name, request)
        print(f"{exception.__name__} from opening without cancellation: at_once={lending.at_once}")
        assert lending.at_once == 0

    with ThreadPoolExecutor(max_workers=1) as readers:
        monkeypatch.setattr(server, "SERVED_READERS", readers)
        asyncio.run(run())
