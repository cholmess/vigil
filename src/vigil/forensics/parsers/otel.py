from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, TextIO

from vigil.forensics.models import ConversationTurn

ROLE_MAP = {
    "gen_ai.system.message": "system",
    "gen_ai.user.message": "user",
    "gen_ai.assistant.message": "assistant",
    "gen_ai.tool.message": "tool",
    "gen_ai.choice": "assistant",
}

CONTENT_FIELDS = ["content", "gen_ai.content", "input", "output", "body"]


@dataclass
class _NormalizedEvent:
    role: str
    content: str
    timestamp: datetime
    span_id: str
    trace_id: str
    span_name: str
    event_name: str


class OTELParser:
    """Parser for OTLP JSON and MLflow native trace payloads."""

    def parse_file(self, path: str | Path) -> Iterator[ConversationTurn]:
        p = Path(path)
        with p.open("r", encoding="utf-8") as f:
            yield from self.parse_stream(f)

    def parse_directory(self, path: str | Path) -> Iterator[ConversationTurn]:
        root = Path(path)
        for file_path in sorted(root.rglob("*.json")):
            yield from self.parse_file(file_path)

    def parse_stream(self, stream: TextIO) -> Iterator[ConversationTurn]:
        data = json.load(stream)
        turns = self._parse_payload(data)
        for idx, turn in enumerate(turns):
            yield ConversationTurn(
                conversation_id=turn.conversation_id,
                turn_index=idx,
                role=turn.role,
                content=turn.content,
                timestamp=turn.timestamp,
                metadata=turn.metadata,
                source_format=turn.source_format,
            )

    def _parse_payload(self, data: Any) -> list[ConversationTurn]:
        if self._looks_like_mlflow(data):
            return self._parse_mlflow_payload(data)
        return self._parse_otlp_payload(data)

    def _parse_otlp_payload(self, data: Any) -> list[ConversationTurn]:
        spans = self._extract_otlp_spans(data)
        events: list[_NormalizedEvent] = []
        for span in spans:
            trace_id = self._str_or(span.get("trace_id"), "unknown-trace")
            span_id = self._str_or(span.get("span_id"), "")
            span_name = self._str_or(span.get("name"), "")
            span_start = self._parse_any_timestamp(
                span.get("start_time") or span.get("startTimeUnixNano") or span.get("start_time_unix_nano")
            )
            for raw_event in span.get("events", []):
                event_name = self._str_or(raw_event.get("name"), "")
                role = ROLE_MAP.get(event_name)
                if not role:
                    continue
                attrs = raw_event.get("attributes", {})
                content = self._extract_content(attrs)
                if not content:
                    continue
                ev_ts = self._parse_any_timestamp(
                    raw_event.get("timestamp")
                    or raw_event.get("time_unix_nano")
                    or raw_event.get("timeUnixNano")
                )
                events.append(
                    _NormalizedEvent(
                        role=role,
                        content=content,
                        timestamp=ev_ts or span_start or datetime.now(timezone.utc),
                        span_id=span_id,
                        trace_id=trace_id,
                        span_name=span_name,
                        event_name=event_name,
                    )
                )

        events.sort(key=lambda e: e.timestamp)
        return [
            ConversationTurn(
                conversation_id=e.trace_id,
                turn_index=i,
                role=e.role,
                content=e.content,
                timestamp=e.timestamp,
                metadata={"span_id": e.span_id, "span_name": e.span_name, "event_name": e.event_name},
                source_format="otel",
            )
            for i, e in enumerate(events)
        ]

    def _parse_mlflow_payload(self, data: Any) -> list[ConversationTurn]:
        trace_obj = data.get("trace", {}) if isinstance(data, dict) else {}
        data_obj = trace_obj.get("data", {}) if isinstance(trace_obj, dict) else {}
        spans = data_obj.get("spans", []) if isinstance(data_obj, dict) else []
        trace_id = self._str_or(
            data.get("request_id") if isinstance(data, dict) else None,
            self._str_or(
                (trace_obj.get("info", {}) if isinstance(trace_obj, dict) else {}).get("request_id"),
                "mlflow-trace",
            ),
        )

        events: list[_NormalizedEvent] = []
        for span in spans:
            span_id = self._str_or(span.get("span_id") or span.get("spanId"), "")
            span_name = self._str_or(span.get("name"), "")
            span_start = self._parse_any_timestamp(span.get("start_time") or span.get("startTimeUnixNano"))
            for raw_event in span.get("events", []):
                event_name = self._str_or(raw_event.get("name"), "")
                role = ROLE_MAP.get(event_name)
                if not role:
                    continue
                attrs = raw_event.get("attributes", {})
                content = self._extract_content(attrs)
                if not content:
                    continue
                ev_ts = self._parse_any_timestamp(
                    raw_event.get("timestamp") or raw_event.get("time_unix_nano") or raw_event.get("timeUnixNano")
                )
                events.append(
                    _NormalizedEvent(
                        role=role,
                        content=content,
                        timestamp=ev_ts or span_start or datetime.now(timezone.utc),
                        span_id=span_id,
                        trace_id=trace_id,
                        span_name=span_name,
                        event_name=event_name,
                    )
                )

        events.sort(key=lambda e: e.timestamp)
        return [
            ConversationTurn(
                conversation_id=e.trace_id,
                turn_index=i,
                role=e.role,
                content=e.content,
                timestamp=e.timestamp,
                metadata={"span_id": e.span_id, "span_name": e.span_name, "event_name": e.event_name},
                source_format="mlflow",
            )
            for i, e in enumerate(events)
        ]

    def _extract_otlp_spans(self, data: Any) -> list[dict[str, Any]]:
        spans: list[dict[str, Any]] = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and "events" in item:
                    spans.append(item)
            return spans

        if not isinstance(data, dict):
            return spans

        if "spans" in data and isinstance(data["spans"], list):
            for span in data["spans"]:
                if isinstance(span, dict):
                    spans.append(span)
            return spans

        for resource_span in data.get("resourceSpans", []):
            scope_spans = resource_span.get("scopeSpans", []) or resource_span.get("instrumentationLibrarySpans", [])
            for scope_span in scope_spans:
                for span in scope_span.get("spans", []):
                    if not isinstance(span, dict):
                        continue
                    normalized = {
                        "trace_id": span.get("traceId") or span.get("trace_id"),
                        "span_id": span.get("spanId") or span.get("span_id"),
                        "name": span.get("name"),
                        "start_time": span.get("startTimeUnixNano") or span.get("start_time"),
                        "events": [],
                    }
                    for event in span.get("events", []):
                        attrs = {}
                        raw_attrs = event.get("attributes", [])
                        if isinstance(raw_attrs, list):
                            for pair in raw_attrs:
                                key = pair.get("key")
                                if key is None:
                                    continue
                                attrs[key] = self._unwrap_otlp_value(pair.get("value", {}))
                        elif isinstance(raw_attrs, dict):
                            attrs = raw_attrs
                        normalized["events"].append(
                            {
                                "name": event.get("name"),
                                "time_unix_nano": event.get("timeUnixNano") or event.get("time_unix_nano"),
                                "attributes": attrs,
                            }
                        )
                    spans.append(normalized)

        return spans

    def _unwrap_otlp_value(self, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        for key in ("stringValue", "intValue", "doubleValue", "boolValue", "bytesValue"):
            if key in value:
                return value[key]
        if "arrayValue" in value:
            vals = value["arrayValue"].get("values", [])
            return [self._unwrap_otlp_value(v) for v in vals]
        if "kvlistValue" in value:
            out: dict[str, Any] = {}
            for pair in value["kvlistValue"].get("values", []):
                k = pair.get("key")
                if k is not None:
                    out[k] = self._unwrap_otlp_value(pair.get("value", {}))
            return out
        return value

    def _looks_like_mlflow(self, data: Any) -> bool:
        return isinstance(data, dict) and "trace" in data and isinstance(data.get("trace"), dict)

    def _extract_content(self, attributes: Any) -> str:
        if not isinstance(attributes, dict):
            return ""
        for field in CONTENT_FIELDS:
            val = attributes.get(field)
            if isinstance(val, str) and val.strip():
                return val
            if val is not None and not isinstance(val, (dict, list)):
                text = str(val).strip()
                if text:
                    return text
        return ""

    def _parse_any_timestamp(self, value: Any) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, (int, float)):
            if value > 10_000_000_000:
                return datetime.fromtimestamp(float(value) / 1_000_000_000, tz=timezone.utc)
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return None
            if stripped.isdigit():
                return self._parse_any_timestamp(int(stripped))
            try:
                if stripped.endswith("Z"):
                    stripped = stripped[:-1] + "+00:00"
                return datetime.fromisoformat(stripped)
            except ValueError:
                return None
        return None

    def _str_or(self, value: Any, default: str = "") -> str:
        if value is None:
            return default
        text = str(value).strip()
        return text if text else default
