"""LangSmith trace export parser."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from vigil.forensics.models import ConversationTurn


class LangSmithParser:
    """
    Parses LangSmith trace exports.

    LangSmith exports runs as JSON with this shape::

        {
          "id": "run-uuid",
          "run_type": "chain",
          "inputs": {"messages": [...]},
          "outputs": {"output": "..."},
          "start_time": "2026-01-01T00:00:00Z",
          ...
        }

    or as JSONL where each line is one run.
    """

    def parse_file(self, path: str | Path) -> Iterator[ConversationTurn]:
        p = Path(path)
        text = p.read_text(encoding="utf-8")
        try:
            data = json.loads(text)
            yield from self._parse_object(data, source=str(p))
            return
        except json.JSONDecodeError:
            pass
        # Try JSONL
        turn_index = 0
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                for turn in self._parse_object(obj, source=str(p), start_index=turn_index):
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

    def _parse_object(self, obj: Any, source: str, start_index: int = 0) -> list[ConversationTurn]:
        if isinstance(obj, list):
            turns = []
            for item in obj:
                turns.extend(self._parse_object(item, source, start_index + len(turns)))
            return turns

        if not isinstance(obj, dict):
            return []

        run_id = str(obj.get("id") or obj.get("run_id") or source)
        ts = self._parse_ts(obj.get("start_time") or obj.get("created_at")) or datetime.now(timezone.utc)
        turns = []

        # Extract input messages
        inputs = obj.get("inputs") or {}
        if isinstance(inputs, dict):
            messages = inputs.get("messages") or inputs.get("input") or []
            if isinstance(messages, list):
                for msg in messages:
                    if isinstance(msg, dict):
                        role = str(msg.get("role", "user"))
                        content = self._extract_content(msg)
                        if content:
                            turns.append(
                                ConversationTurn(
                                    conversation_id=run_id,
                                    turn_index=start_index + len(turns),
                                    role=role,
                                    content=content,
                                    timestamp=ts,
                                    metadata={"run_type": obj.get("run_type", ""), "source": source},
                                    source_format="langsmith",
                                )
                            )
            elif isinstance(messages, str) and messages:
                turns.append(
                    ConversationTurn(
                        conversation_id=run_id,
                        turn_index=start_index + len(turns),
                        role="user",
                        content=messages,
                        timestamp=ts,
                        metadata={"source": source},
                        source_format="langsmith",
                    )
                )

        # Extract output
        outputs = obj.get("outputs") or {}
        output_text = None
        if isinstance(outputs, dict):
            output_text = (
                outputs.get("output")
                or outputs.get("text")
                or outputs.get("content")
                or outputs.get("answer")
            )
        elif isinstance(outputs, str):
            output_text = outputs

        if output_text and isinstance(output_text, str):
            turns.append(
                ConversationTurn(
                    conversation_id=run_id,
                    turn_index=start_index + len(turns),
                    role="assistant",
                    content=output_text,
                    timestamp=ts,
                    metadata={"source": source},
                    source_format="langsmith",
                )
            )

        return turns

    def _extract_content(self, msg: dict) -> str:
        content = msg.get("content") or msg.get("text") or ""
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts = []
            for item in content:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    parts.append(str(item.get("text", "")))
            return " ".join(parts)
        return str(content) if content else ""

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
