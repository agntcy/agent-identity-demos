# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""OpenTelemetry tracing setup — exports spans to the local Jaeger
all-in-one container via OTLP.

Duplicated per service rather than shared from one package: no service in
this repo currently imports from a shared lib (webapp even vendors its own
copy of the proto/ tree), so a new shared package would be a bigger,
separate structural change than adding tracing itself.
"""

import os

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

_OTLP_ENDPOINT = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://jaeger:4317")


def setup_tracing(service_name: str) -> None:
    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=_OTLP_ENDPOINT, insecure=True))
    )
    trace.set_tracer_provider(provider)
    HTTPXClientInstrumentor().instrument()


def current_trace_id() -> str | None:
    """32-char hex trace id for the currently active span, or None."""
    ctx = trace.get_current_span().get_span_context()
    if not ctx.is_valid:
        return None
    return format(ctx.trace_id, "032x")


def step_span(step_id: str):
    """Named child span for one demo step (e.g. "step:resolve-badge").

    Lets the webapp UI jump straight to this step's span from the sequence
    diagram via Jaeger's `uiFind=step:<id>` search, instead of just opening
    the trace at its root.
    """
    return trace.get_tracer(__name__).start_as_current_span(f"step:{step_id}")
