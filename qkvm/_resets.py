"""On Windows, no ERROR line and traceback in the log for a connection the other end reset as it was being closed.

Windows' event loop closes a connection with a shutdown() of its socket first (its connection-lost callback), and that
raises WinError 10054 where the other end had reset it already: a browser or a device that dropped it. The loop then logs
the error that nobody did anything about, with its traceback, three times an hour in a soak. Exactly that case is let pass;
every other error of the loop is logged as before.

The starter of 0.4.0 puts this on as the wall's process starts (__main__.quiet_resets, the same code). A wall that came to
0.4.0 from inside the app runs the starter it was installed with, which an in-app update cannot replace and which has none:
so the wall puts it on itself as well (cli.main), as it does malloc's settings (_allocator). It is not taken from the
starter: what the program takes from it must be in every starter an update can start from (test_an_update_from_0_2_0).
Put on by both, it is one: whichever comes first marks its handler, and the second sees the mark.
"""

from __future__ import annotations

from typing import Any

WSAECONNRESET = 10054  # Windows: "An existing connection was forcibly closed by the remote host"
MARK = "qkvm_quiets_resets"  # (the same name the starter's own marks its handler with)


def quiet_resets() -> None:
    """Put the quieting on Windows' event loop (on the loop, not as a filter of its logger: the program's logging clears
    those as it sets itself up), once. A Python whose loop has no such callback is left as it is."""
    try:
        from asyncio import proactor_events

        the_callback = proactor_events._ProactorBasePipeTransport._call_connection_lost.__code__  # type: ignore[attr-defined]
        loop = proactor_events.BaseProactorEventLoop
        logged = loop.default_exception_handler
    except Exception:  # (named otherwise in some later Python: nothing is changed, and the line is logged as it was)
        return
    if getattr(logged, MARK, False):
        return  # (put on already, by the starter)

    def handler(self: Any, context: dict[str, Any]) -> None:
        found = context.get("exception")
        # (Only where it replaced nothing: the callback runs the program's own connection_lost() first, and an error there
        # becomes the 10054's __context__ when the shutdown in its `finally` then fails too. That error is the program's.)
        if isinstance(found, ConnectionResetError) and getattr(found, "winerror", None) == WSAECONNRESET and found.__context__ is None and found.__cause__ is None:
            last = found.__traceback__
            while last is not None and last.tb_next is not None:
                last = last.tb_next
            if last is not None and last.tb_frame.f_code is the_callback:
                return  # (raised by the callback's own shutdown(): nothing of the program's was under way)
        logged(self, context)

    setattr(handler, MARK, True)
    loop.default_exception_handler = handler  # type: ignore[method-assign]
