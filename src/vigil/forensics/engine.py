"""Forensic audit engine — fully internal, no external dependencies."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import TypedDict

from vigil.forensics.models import ConversationTurn, Finding
from vigil.forensics.parsers.jsonl import JSONLParser
from vigil.forensics.parsers.langfuse import LangfuseParser
from vigil.forensics.parsers.langsmith import LangSmithParser
from vigil.forensics.parsers.otel import OTELParser
from vigil.forensics.parsers.plain import PlainTextParser
from vigil.forensics.patterns import PATTERNS
from vigil.forensics.patterns.canari_tokens import DetectionPattern
from vigil.forensics.scanner.engine import ForensicScanner
from vigil.models import Attack, AttackSnapshot, Canary, Message, SnapshotMetadata


class AuditSummary(TypedDict):
    log_file: str
    format: str
    turns_parsed: int
    findings: int
    saved: list[str]
    errors: int


class VigilForensicsWrapper:
    """
    Runs a forensic audit over LLM log files using Vigil's internal scanner.

    For every Finding detected the wrapper converts it into an AttackSnapshot
    (.bp.json) so that BreakPoint-style replay can verify the system prompt.
    """

    def run_audit(
        self,
        log_file: str | Path,
        format: str = "otel",
        *,
        patterns: list[DetectionPattern] | None = None,
        attacks_dir: str | Path = Path("./attacks"),
    ) -> AuditSummary:
        turns = self._parse(log_file, format)
        scanner = ForensicScanner(patterns=patterns if patterns is not None else PATTERNS)
        findings = scanner.detect_findings(turns)

        turns_by_trace: dict[str, list[ConversationTurn]] = defaultdict(list)
        for turn in turns:
            turns_by_trace[turn.conversation_id].append(turn)

        saved: list[str] = []
        errors = 0
        out_dir = Path(attacks_dir)

        for finding in findings:
            try:
                snapshot = self._finding_to_snapshot(
                    finding, turns_by_trace.get(finding.trace_id, [])
                )
                path = snapshot.save_to_file(out_dir / finding.finding_id)
                saved.append(str(path))
            except Exception:
                errors += 1

        return AuditSummary(
            log_file=str(log_file),
            format=format,
            turns_parsed=len(turns),
            findings=len(findings),
            saved=saved,
            errors=errors,
        )

    def _parse(self, log_file: str | Path, format: str) -> list[ConversationTurn]:
        _parsers: dict[str, type] = {
            "mlflow": OTELParser,
            "jsonl": JSONLParser,
            "openai": JSONLParser,
            "anthropic": JSONLParser,
            "langsmith": LangSmithParser,
            "langfuse": LangfuseParser,
            "plain": PlainTextParser,
            "text": PlainTextParser,
        }
        parser_cls = _parsers.get(format, OTELParser)
        parser = parser_cls()
        path = Path(log_file)
        if path.is_dir():
            return list(parser.parse_directory(path))
        return list(parser.parse_file(path))

    def _finding_to_snapshot(
        self,
        finding: Finding,
        trace_turns: list[ConversationTurn],
    ) -> AttackSnapshot:
        if trace_turns:
            conversation = [
                Message(role=t.role, content=t.content)
                for t in sorted(trace_turns, key=lambda t: t.turn_index)
            ]
        else:
            conversation = [Message(role="assistant", content=finding.context)]

        return AttackSnapshot(
            vigil_version="0.1.0",
            snapshot_type="attack",
            metadata=SnapshotMetadata(
                snapshot_id=finding.finding_id,
                source="forensics",
            ),
            attack=Attack(conversation=conversation),
            canary=Canary(token_type=finding.pattern_id),
        )
