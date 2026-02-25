"""Plain text parser with conversation boundary detection."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from vigil.forensics.models import ConversationTurn

_BOUNDARY_RE = re.compile(
    r"(?m)^(?P<role>(?:human|user|assistant|system|ai))\s*(?::|>)\s*",
    re.IGNORECASE,
)

_TIMESTAMP_RE = re.compile(
    r"\[?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\]?"
)

_ROLE_NORMALIZE = {
    "human": "user",
    "ai": "assistant",
    "user": "user",
    "assistant": "assistant",
    "system": "system",
}


class PlainTextParser:
    """
    Parses plain text conversation files with simple role prefixes.

    Supported formats::

        User: Hello, what is 2+2?
        Assistant: 4.

        Human: Tell me a secret.
        AI: Sure, here it is...

    Each file is treated as one conversation.
    """

    def parse_file(self, path: str | Path) -> Iterator[ConversationTurn]:
        p = Path(path)
        text = p.read_text(encoding="utf-8", errors="replace")
        yield from self._parse_text(text, source=str(p))

    def parse_directory(self, path: str | Path) -> Iterator[ConversationTurn]:
        root = Path(path)
        for file_path in sorted(root.rglob("*.txt")):
            yield from self.parse_file(file_path)

    def _parse_text(self, text: str, source: str) -> Iterator[ConversationTurn]:
        matches = list(_BOUNDARY_RE.finditer(text))
        if not matches:
            # No role markers: treat whole file as one assistant turn
            if text.strip():
                yield ConversationTurn(
                    conversation_id=source,
                    turn_index=0,
                    role="assistant",
                    content=text.strip(),
                    timestamp=datetime.now(timezone.utc),
                    metadata={"source": source},
                    source_format="plain",
                )
            return

        conv_id = source
        for i, match in enumerate(matches):
            raw_role = match.group("role").lower()
            role = _ROLE_NORMALIZE.get(raw_role, "user")
            start = match.end()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            content = text[start:end].strip()
            ts = self._extract_timestamp(content) or datetime.now(timezone.utc)
            content = _TIMESTAMP_RE.sub("", content).strip()

            if not content:
                continue

            yield ConversationTurn(
                conversation_id=conv_id,
                turn_index=i,
                role=role,
                content=content,
                timestamp=ts,
                metadata={"source": source},
                source_format="plain",
            )

    def _extract_timestamp(self, text: str) -> datetime | None:
        m = _TIMESTAMP_RE.search(text)
        if not m:
            return None
        raw = m.group(1).strip()
        try:
            if raw.endswith("Z"):
                raw = raw[:-1] + "+00:00"
            raw = raw.replace(" ", "T")
            return datetime.fromisoformat(raw)
        except ValueError:
            return None
