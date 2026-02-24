"""Forensic audit wrapper using canari-forensics."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import TypedDict

from canari_forensics import ConversationTurn, Finding, OTELParser, detect_findings
from canari_forensics.parsers import (
    JSONLParser,
    LangfuseParser,
    LangSmithParser,
    MLflowGatewayParser,
    PlainTextParser,
)
from canari_forensics.patterns import PATTERNS, DetectionPattern

from vigil.models import Attack, AttackSnapshot, Canary, Message, SnapshotMetadata


class AuditSummary(TypedDict):
    log_file: str
    format: str
    turns_parsed: int
    findings: int
    saved: list[str]   # absolute paths of written .bp.json files
    errors: int


class VigilForensicsWrapper:
    """
    Wraps canari-forensics to run a forensic audit over LLM log files.

    For every Finding detected, the wrapper converts it into an AttackSnapshot
    (vigil.models) and persists it as a .bp.json file so that BreakPoint can
    later replay it in vigil.loop.replayer.

    metadata.source is always set to "forensics" so consumers can tell these
    snapshots apart from live Canari detections.
    """

    def run_audit(
        self,
        log_file: str | Path,
        format: str = "otel",
        *,
        patterns: list[DetectionPattern] | None = None,
        attacks_dir: str | Path = Path("./attacks"),
    ) -> AuditSummary:
        """
        Parse log_file with canari-forensics then scan for findings.

        Parameters
        ----------
        log_file:
            Path to a single log file or a directory. Directories are walked
            recursively for *.json files.
        format:
            "otel" (default) for OTLP JSON / exported MLflow traces.
            "mlflow" for files produced by the MLflow Gateway parser.
        patterns:
            Optional custom list of DetectionPattern objects; falls back to
            canari-forensics built-in PATTERNS.
        attacks_dir:
            Directory to write .bp.json snapshots into (created if absent).

        Returns
        -------
        AuditSummary with counts and the list of saved file paths.
        """
        # Step 1 — parse: log file → list[ConversationTurn]
        turns = self._parse(log_file, format)

        # Step 2 — detect: turns → list[Finding]
        active_patterns = patterns if patterns is not None else PATTERNS
        findings = detect_findings(turns, patterns=active_patterns)

        # Group turns by conversation_id so each finding can get its full context
        turns_by_trace: dict[str, list[ConversationTurn]] = defaultdict(list)
        for turn in turns:
            turns_by_trace[turn.conversation_id].append(turn)

        saved: list[str] = []
        errors = 0
        out_dir = Path(attacks_dir)

        for finding in findings:
            try:
                snapshot = self._finding_to_snapshot(
                    finding,
                    turns_by_trace.get(finding.trace_id, []),
                )
                # save_to_file always enforces .bp.json; finding_id used as stem
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

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _parse(self, log_file: str | Path, format: str) -> list[ConversationTurn]:
        """Instantiate the right parser and return all turns as a flat list."""
        _parsers: dict[str, type] = {
            "mlflow": MLflowGatewayParser,
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
        """
        Map one canari-forensics Finding to an AttackSnapshot.

        Conversation is rebuilt from all ConversationTurn objects that share
        the finding's trace_id, sorted by turn_index, so the full
        system → user → assistant exchange is preserved.

        If no turns exist for the trace (edge case), falls back to a single
        assistant message containing Finding.context (the matched snippet).
        """
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
                source="forensics",            # always "forensics" for this wrapper
            ),
            attack=Attack(conversation=conversation),
            # finding.pattern_id is the closest analog to canary token_type:
            # e.g. "cred_stripe_live", "aws_access_key", "prompt_injection_indicator"
            canary=Canary(token_type=finding.pattern_id),
        )
