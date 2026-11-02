"""The wall tells OpenTelemetry nothing, whatever the environment it is started in says.

FastAPI (0.148 and later at least; qKVM asks for 0.142 or later) traces, measures and logs every request through
OpenTelemetry wherever something in the process has set a provider up, and sets exporters up itself where the environment
says FASTAPI_OTEL_AUTO_CONFIGURE=true and names an endpoint (the dependency audit of 0.2.0). A request's path and query,
the address it came from and, to whatever processes the spans, what it carried (a password) would then go where an
environment variable or another library says. qKVM writes down what it does itself, in its own activity log: FastAPI's
telemetry is switched off when the app is made (`telemetry=`), where this FastAPI has any.
"""

from __future__ import annotations

import inspect
import logging
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI

from tests.test_wall import PASSWORD, closed_port, wall

trace = pytest.importorskip("opentelemetry.trace", reason="this FastAPI has no OpenTelemetry of its own")


def test_the_wall_tells_opentelemetry_nothing_whatever_the_environment_says(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    if "telemetry" not in inspect.signature(FastAPI.__init__).parameters:
        pytest.skip("this FastAPI has no telemetry of its own to switch off")
    started: list[tuple[str, Any]] = []

    class Recording(trace.NoOpTracer):  # type: ignore[misc,name-defined]
        def start_span(self, name: str, *args: Any, **kwargs: Any) -> Any:
            started.append((name, kwargs.get("attributes")))
            return super().start_span(name, *args, **kwargs)

    class SetUpElsewhere(trace.TracerProvider):  # type: ignore[misc,name-defined]
        """A provider another library in the process set up (an agent, an instrumentation): not FastAPI's own."""

        def get_tracer(self, *args: Any, **kwargs: Any) -> Any:
            return Recording()

    monkeypatch.setattr(trace, "get_tracer_provider", SetUpElsewhere)
    monkeypatch.setenv("FASTAPI_OTEL_AUTO_CONFIGURE", "true")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", f"http://127.0.0.1:{closed_port()}")
    with caplog.at_level(logging.INFO), wall(tmp_path) as admin:
        assert admin.post("/api/v1/login", json={"password": PASSWORD}).status_code == 200
        assert admin.get("/api/v1/wall").status_code == 200
    assert started == [], f"FastAPI told a tracer of every request: {started[:3]}"
    tried = [record.getMessage() for record in caplog.records if "telemetry" in record.getMessage().lower()]
    assert tried == [], f"FastAPI set up exporters of its own, as the environment said: {tried}"
