"""Langfuse observation export parser."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from vigil.forensics.models import ConversationTurn


class LangfuseParser:
    """
    Parses Langfuse observation/trace exports.

    Langfuse exports traces as JSON arrays or JSONL where each item is::

        {
          "id": "trace-uuid",
          "name": "...",
          "input": "..." or {...},
          "output": "..." or {...},
          "startTime": "2026-01-01T00:00:00Z",
          "observations": [
            {
              "id": "...",
              "type": "GENERATION",
              "input": [...],
              "output": "...",
              "startTime": "..."
            }
          ]
        }
    """

    def parse_file(self, path: str | Path) -> Iterator[ConversationTurn]:
        p = Path(path)
        text = p.read_text(encoding="utf-8")
        try:
            data = json.loads(text)
            yield from self._dispatch(data, source=str(p))
            return
        except json.JSONDecodeError:
            pass
        turn_index = 0
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                for turn in self._dispatch_list(obj, source=str(p), start_index=turn_index):
                    yield turn
                    turn_index += 1
            except json.JSONDecodeError:
                continue

    def parse_directory(self, path: str | Path) -> Iterator[ConversationTurn]:
        root = Path(path)
        for file_path in sorted(root.rglob("*.json")):
            yield from self.parse_file(file_path)
        for file_path in sorted(root.rglob("*.jsonl")):
            yield from self.parse_file(file_path)

    def _dispatch(self, data: Any, source: str) -> Iterator[ConversationTurn]:
        if isinstance(data, list):
            turn_index = 0
            for item in data:
                for turn in self._parse_trace(item, source=source, start_index=turn_index):
                    yield turn
                    turn_index += 1
        elif isinstance(data, dict):
            yield from self._parse_trace(data, source=source)

    def _dispatch_list(self, obj: Any, source: str, start_index: int) -> list[ConversationTurn]:
        return self._parse_trace(obj, source=source, start_index=start_index)

    def _parse_trace(self, obj: Any, source: str, start_index: int = 0) -> list[ConversationTurn]:
        if not isinstance(obj, dict):
            return []

        trace_id = str(obj.get("id") or source)
        ts = self._parse_ts(obj.get("startTime") or obj.get("start_time") or obj.get("timestamp"))
        if ts is None:
            ts = datetime.now(timezone.utc)

        turns = []

        # Top-level input/output
        input_text = self._coerce_text(obj.get("input"))
        if input_text:
            turns.append(
                ConversationTurn(
                    conversation_id=trace_id,
                    turn_index=start_index + len(turns),
                    role="user",
                    content=input_text,
                    timestamp=ts,
                    metadata={"source": source},
                    source_format="langfuse",
                )
            )

        output_text = self._coerce_text(obj.get("output"))
        if output_text:
            turns.append(
                ConversationTurn(
                    conversation_id=trace_id,
                    turn_index=start_index + len(turns),
                    role="assistant",
                    content=output_text,
                    timestamp=ts,
                    metadata={"source": source},
                    source_format="langfuse",
                )
            )

        # Observations (child spans)
        for obs in obj.get("observations", []):
            if not isinstance(obs, dict):
                continue
            obs_ts = self._parse_ts(obs.get("startTime") or obs.get("start_time")) or ts
            obs_input = self._coerce_observation_messages(obs.get("input"))
            for role, content in obs_input:
                turns.append(
                    ConversationTurn(
                        conversation_id=trace_id,
                        turn_index=start_index + len(turns),
                        role=role,
                        content=content,
                        timestamp=obs_ts,
                        metadata={"obs_type": obs.get("type", ""), "source": source},
                        source_format="langfuse",
                    )
                )
            obs_output = self._coerce_text(obs.get("output"))
            if obs_output:
                turns.append(
                    ConversationTurn(
                        conversation_id=trace_id,
                        turn_index=start_index + len(turns),
                        role="assistant",
                        content=obs_output,
                        timestamp=obs_ts,
                        metadata={"obs_type": obs.get("type", ""), "source": source},
                        source_format="langfuse",
                    )
                )

        return turns

    def _coerce_observation_messages(self, value: Any) -> list[tuple[str, str]]:
        if isinstance(value, list):
            pairs = []
            for item in value:
                if isinstance(item, dict):
                    role = str(item.get("role", "user"))
                    content = self._coerce_text(item.get("content") or item.get("text") or "")
                    if content:
                        pairs.append((role, content))
            return pairs
        text = self._coerce_text(value)
        return [("user", text)] if text else []

    def _coerce_text(self, value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            for key in ("text", "content", "output", "answer", "result"):
                v = value.get(key)
                if isinstance(v, str) and v:
                    return v
        if isinstance(value, list):
            parts = [self._coerce_text(item) for item in value if item]
            return " ".join(p for p in parts if p)
        return str(value)

    def _parse_ts(self, value: Any) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, str):
            try:
                v = value.strip()
                if v.endswith("Z"):
                    v = v[:-1] + "+00:00"
                return datetime.fromisoformat(v)
            except ValueError:
                return None
        if isinstance(value, (int, float)):
            try:
                return datetime.fromtimestamp(float(value), tz=timezone.utc)
            except (ValueError, OSError):
                return None
        return None
