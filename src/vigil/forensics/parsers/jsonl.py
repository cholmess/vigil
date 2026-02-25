"""JSONL parser — handles OpenAI/Anthropic export format and generic JSONL logs."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from vigil.forensics.models import ConversationTurn


class JSONLParser:
    """
    Parses JSONL files where each line is a JSON object representing one
    conversation turn or a full conversation.

    Supported line shapes:
    - {"role": "user", "content": "...", "conversation_id": "...", "timestamp": "..."}
    - {"messages": [...], "id": "...", "created": 1234567890}   (OpenAI format)
    - {"input": {...}, "output": {...}}                         (generic)
    """

    def parse_file(self, path: str | Path) -> Iterator[ConversationTurn]:
        p = Path(path)
        with p.open("r", encoding="utf-8") as f:
            yield from self._parse_lines(f, source=str(p))

    def parse_directory(self, path: str | Path) -> Iterator[ConversationTurn]:
        root = Path(path)
        for file_path in sorted(root.rglob("*.jsonl")):
            yield from self.parse_file(file_path)
        for file_path in sorted(root.rglob("*.json")):
            yield from self.parse_file(file_path)

    def _parse_lines(self, lines, source: str) -> Iterator[ConversationTurn]:
        turn_index = 0
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            for turn in self._extract_turns(obj, source, turn_index):
                yield turn
                turn_index += 1

    def _extract_turns(self, obj: Any, source: str, start_index: int) -> list[ConversationTurn]:
        if not isinstance(obj, dict):
            return []

        # OpenAI batch export: {"messages": [...], "id": "...", "created": ...}
        if "messages" in obj and isinstance(obj["messages"], list):
            conv_id = str(obj.get("id", source))
            created = obj.get("created")
            ts = self._parse_timestamp(created) or datetime.now(timezone.utc)
            turns = []
            for i, msg in enumerate(obj["messages"]):
                role = str(msg.get("role", "user"))
                content = str(msg.get("content", ""))
                turns.append(
                    ConversationTurn(
                        conversation_id=conv_id,
                        turn_index=start_index + i,
                        role=role,
                        content=content,
                        timestamp=ts,
                        metadata={"source": source},
                        source_format="jsonl",
                    )
                )
            return turns

        # Single turn with role/content
        role = obj.get("role")
        content = obj.get("content") or obj.get("text") or obj.get("message", "")
        if role and content:
            conv_id = str(obj.get("conversation_id") or obj.get("trace_id") or source)
            ts = self._parse_timestamp(obj.get("timestamp") or obj.get("created_at")) or datetime.now(timezone.utc)
            return [
                ConversationTurn(
                    conversation_id=conv_id,
                    turn_index=start_index,
                    role=str(role),
                    content=str(content),
                    timestamp=ts,
                    metadata={"source": source},
                    source_format="jsonl",
                )
            ]

        # input/output pair
        if "input" in obj or "output" in obj:
            conv_id = str(obj.get("id") or obj.get("conversation_id") or source)
            ts = self._parse_timestamp(obj.get("timestamp") or obj.get("created_at")) or datetime.now(timezone.utc)
            turns = []
            if obj.get("input"):
                inp = obj["input"]
                content = inp if isinstance(inp, str) else json.dumps(inp)
                turns.append(
                    ConversationTurn(
                        conversation_id=conv_id,
                        turn_index=start_index,
                        role="user",
                        content=content,
                        timestamp=ts,
                        metadata={"source": source},
                        source_format="jsonl",
                    )
                )
            if obj.get("output"):
                out = obj["output"]
                content = out if isinstance(out, str) else json.dumps(out)
                turns.append(
                    ConversationTurn(
                        conversation_id=conv_id,
                        turn_index=start_index + len(turns),
                        role="assistant",
                        content=content,
                        timestamp=ts,
                        metadata={"source": source},
                        source_format="jsonl",
                    )
                )
            return turns

        return []

    def _parse_timestamp(self, value: Any) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, (int, float)):
            try:
                return datetime.fromtimestamp(float(value), tz=timezone.utc)
            except (ValueError, OSError):
                return None
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return None
            try:
                if stripped.endswith("Z"):
                    stripped = stripped[:-1] + "+00:00"
                return datetime.fromisoformat(stripped)
            except ValueError:
                return None
        return None
