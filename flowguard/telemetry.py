"""OpenTelemetry-compatible JSONL span recorder for FlowGuard."""

from __future__ import annotations

import json
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from flowguard.models import ExecutionModeLabel, TelemetrySpan

DEFAULT_TELEMETRY_PATH = Path(__file__).resolve().parent.parent / "results" / "telemetry_events.jsonl"


class TelemetryRecorder:
    """Thread-safe OpenTelemetry span emitter writing JSONL records."""

    def __init__(self, log_path: Optional[Path] = None, persist_to_disk: bool = True) -> None:
        self.log_path = Path(log_path) if log_path is not None else DEFAULT_TELEMETRY_PATH
        self.persist_to_disk = persist_to_disk
        self._lock = threading.RLock()
        self._spans: List[TelemetrySpan] = []

    def new_trace_id(self) -> str:
        return uuid.uuid4().hex

    def new_span_id(self) -> str:
        return uuid.uuid4().hex[:16]

    def record_span(
        self,
        name: str,
        workflow_id: str,
        domain: str,
        status: str,
        duration_ms: float,
        trace_id: Optional[str] = None,
        parent_span_id: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
        execution_mode_label: str = ExecutionModeLabel.DETERMINISTIC_HARNESS.value,
    ) -> TelemetrySpan:
        """Record a span (`flowguard.step.verify`, `flowguard.recovery`, `flowguard.idempotency`)."""
        span = TelemetrySpan(
            trace_id=trace_id or self.new_trace_id(),
            span_id=self.new_span_id(),
            name=name,
            workflow_id=workflow_id,
            domain=domain,
            status=status,
            duration_ms=round(max(0.0, float(duration_ms)), 4),
            timestamp_iso=datetime.now(timezone.utc).isoformat(),
            parent_span_id=parent_span_id,
            attributes=attributes or {},
            execution_mode_label=execution_mode_label,
        )
        with self._lock:
            self._spans.append(span)
            if self.persist_to_disk:
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
                with self.log_path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(span.to_dict(), sort_keys=True) + "\n")
        return span

    def get_recorded_spans(self, name_filter: Optional[str] = None) -> List[TelemetrySpan]:
        with self._lock:
            if name_filter is None:
                return list(self._spans)
            return [s for s in self._spans if s.name == name_filter]

    def clear_memory_buffer(self) -> None:
        with self._lock:
            self._spans.clear()


class SpanTimer:
    """Context manager helper for measuring span latency in milliseconds."""

    def __init__(self) -> None:
        self.start_ns = 0
        self.elapsed_ms = 0.0

    def __enter__(self) -> "SpanTimer":
        self.start_ns = time.perf_counter_ns()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.elapsed_ms = (time.perf_counter_ns() - self.start_ns) / 1_000_000.0
