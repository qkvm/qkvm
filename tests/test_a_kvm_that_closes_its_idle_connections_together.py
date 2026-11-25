"""A KVM that closes the connections the wall keeps to it, all together, is not shown offline for it (the fake farm of
2026-11-22, likely defect 2).

The wall keeps up to four connections to a kvmd KVM between looks. A KVM (its web server's keep-alive running out) closes
them together; a look that goes out on one of them at that moment gets no answer, and was tried once more, on the next kept
one, which was closed too: the KVM was taken to be down, and its tile flashed offline for six to eight seconds. Such a look
is now tried again until it goes out on a connection made for it. A request that may have been taken (keys, a power button
and the like) is never sent twice.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from qkvm import kvm
from tests.fake_kvm import FakeKvm, FakeState


class Closer:
    """Forwards each connection to the stand-in KVM. `close_kept()` makes every connection open now end at the next request
    that comes on it, unanswered: closed (`reset` False) or with a reset, as a KVM that closed its idle connections together
    leaves a request that went out on one of them at that moment. Connections made after it pass."""

    def __init__(self, port: int, reset: bool) -> None:
        self.port, self.reset = port, reset
        self.flows: list[list[bool]] = []
        self.ended = 0  # requests that came on a connection closed so, each ended unanswered
        self.tasks: set[asyncio.Task[Any]] = set()
        self.transports: list[asyncio.BaseTransport] = []

    async def start(self) -> int:
        self.server = await asyncio.start_server(self.flow, "127.0.0.1", 0)
        return int(self.server.sockets[0].getsockname()[1])

    def close_kept(self) -> None:
        for flow in self.flows:
            flow[0] = True

    async def close(self) -> None:
        self.server.close()
        for transport in self.transports:
            transport.abort()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        await self.server.wait_closed()

    async def flow(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        assert task is not None
        self.tasks.add(task)
        closed = [False]
        self.flows.append(closed)
        self.transports.append(writer.transport)
        up_reader, up_writer = await asyncio.open_connection("127.0.0.1", self.port)
        self.transports.append(up_writer.transport)

        async def pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter, from_the_wall: bool) -> None:
            try:
                while data := await src.read(65536):
                    if from_the_wall and closed[0]:
                        self.ended += 1
                        if self.reset:
                            writer.transport.abort()
                        else:
                            writer.close()
                        up_writer.transport.abort()
                        return
                    dst.write(data)
                    await dst.drain()
                dst.close()  # (one side closed its connection: so is the other)
            except (ConnectionError, OSError):
                pass

        await asyncio.gather(pipe(reader, up_writer, True), pipe(up_reader, writer, False))
        writer.close()
        up_writer.close()


def behind_a_closer(reset: bool, test: Any, state: FakeState | None = None) -> FakeKvm:
    fake = FakeKvm(state or FakeState()).start()

    async def inside() -> None:
        box = Closer(fake.port, reset)
        port = await box.start()
        device = kvm.KvmDevice(kvm.DeviceSpec("desk", "desk", f"http://127.0.0.1:{port}", "admin", "secret"))
        try:
            await test(device, box)
        finally:
            await device.close()
            await box.close()

    try:
        asyncio.run(inside())
    finally:
        fake.stop()
    return fake


@pytest.mark.parametrize("reset", [False, True], ids=["closed", "reset"])
def test_a_look_after_the_kvm_closed_its_kept_connections_together_finds_it_there(reset: bool) -> None:
    async def test(device: kvm.KvmDevice, box: Closer) -> None:
        assert (await device._read_status())["state"] == "online"
        assert len(box.flows) >= 3, "the look's questions went out together, each on a connection kept from then on"
        box.close_kept()
        said = await device._read_status()
        assert said["state"] == "online", said
        assert box.ended >= 3, f"{box.ended} kept connections were tried"  # (several of them, one after another)
        assert (await device._read_status())["state"] == "online"  # (and nothing is held against the KVM for it)

    behind_a_closer(reset, test)


@pytest.mark.parametrize("reset", [False, True], ids=["closed", "reset"])
def test_keys_on_a_connection_the_kvm_closed_while_it_was_kept_are_never_sent_twice(reset: bool) -> None:
    async def test(device: kvm.KvmDevice, box: Closer) -> None:
        assert (await device._read_status())["state"] == "online"
        box.close_kept()
        with pytest.raises(kvm.KvmError) as failed:
            await device.act("keys", keys="ShiftLeft")
        assert failed.value.code == "dropped"
        assert box.ended == 1  # (tried once: it may have been taken)

    fake = behind_a_closer(reset, test)
    assert fake.state.actions == []


def test_a_look_whose_answer_breaks_off_on_its_way_is_tried_once_more_only() -> None:
    # Not a connection closed as it sat kept: the KVM answered, and the answer broke off. Tried once more, as before; not
    # again and again on each connection kept.
    state = FakeState(ports=[(150, 80, 40), (40, 110, 130)])  # (two inputs: its switch is asked at every look)

    async def test(device: kvm.KvmDevice, box: Closer) -> None:
        assert (await device._read_status())["state"] == "online"
        assert len(box.flows) >= 3, "the look's questions went out together, each on a connection kept from then on"
        state.switch_reply = "cut"
        before = list(state.asked).count("GET /api/switch")
        with pytest.raises(kvm.KvmError) as failed:
            await device._read_ports()
        assert failed.value.code == "dropped"
        assert list(state.asked).count("GET /api/switch") == before + 2

    behind_a_closer(False, test, state)
