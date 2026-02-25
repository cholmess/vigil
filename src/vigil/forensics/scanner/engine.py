"""Aho-Corasick and regex scan engine for forensic log analysis."""

from __future__ import annotations

from datetime import timezone

from vigil.forensics.models import ConversationTurn, Finding
from vigil.forensics.patterns import PATTERNS
from vigil.forensics.patterns.canari_tokens import DetectionPattern


def _redact(secret: str) -> str:
    if len(secret) <= 8:
        return "****"
    return f"{secret[:4]}****{secret[-4:]}"


def _context_snippet(text: str, start: int, end: int, radius: int = 40) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    return text[left:right]


def _recommended_action(pattern: DetectionPattern) -> str:
    if "credential" in pattern.kind or "canary" in pattern.kind:
        return "Rotate immediately. Assume compromise until proven otherwise."
    if "prompt_injection" in pattern.kind:
        return "Review prompt defenses and affected conversation history."
    if "pii" in pattern.kind:
        return "Review PII handling and data minimization policies."
    return "Review finding context and remediate as needed."


class ForensicScanner:
    """
    Scans ConversationTurn objects for pattern matches.

    Uses simple regex scanning; for very large datasets consider the streaming
    engine in scanner/stream.py which processes files without loading them
    fully into memory.
    """

    def __init__(self, patterns: list[DetectionPattern] | None = None):
        self._patterns = patterns if patterns is not None else PATTERNS

    def detect_findings(
        self,
        turns: list[ConversationTurn],
        patterns: list[DetectionPattern] | None = None,
    ) -> list[Finding]:
        active = patterns if patterns is not None else self._patterns
        findings: list[Finding] = []
        idx = 1

        for turn in turns:
            if turn.role not in ("assistant", "user"):
                continue
            for pattern in active:
                for match in pattern.regex.finditer(turn.content):
                    matched = match.group(0)
                    findings.append(
                        Finding(
                            finding_id=f"F-{idx:04d}",
                            severity=pattern.severity,
                            kind=pattern.kind,
                            pattern_id=pattern.pattern_id,
                            pattern_name=pattern.name,
                            confidence=pattern.confidence,
                            trace_id=turn.conversation_id,
                            timestamp=turn.timestamp.astimezone(timezone.utc).isoformat(),
                            matched_value=_redact(matched),
                            context=_context_snippet(turn.content, match.start(), match.end()),
                            action=_recommended_action(pattern),
                        )
                    )
                    idx += 1

        findings.sort(key=lambda f: f.timestamp)
        return findings
