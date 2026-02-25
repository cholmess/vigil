"""Vigil forensics — internal log scanner with no external dependencies."""

from vigil.forensics.engine import AuditSummary, VigilForensicsWrapper
from vigil.forensics.models import ConversationTurn, Finding
from vigil.forensics.parsers import (
    JSONLParser,
    LangfuseParser,
    LangSmithParser,
    OTELParser,
    PlainTextParser,
)
from vigil.forensics.patterns import PATTERNS
from vigil.forensics.patterns.canari_tokens import DetectionPattern
from vigil.forensics.reporting import (
    build_evidence_pack,
    load_turns_from_scan_report,
    write_bp_snapshots,
    write_evidence_pack,
)
from vigil.forensics.scanner.engine import ForensicScanner

__all__ = [
    "AuditSummary",
    "ConversationTurn",
    "DetectionPattern",
    "Finding",
    "ForensicScanner",
    "JSONLParser",
    "LangSmithParser",
    "LangfuseParser",
    "OTELParser",
    "PATTERNS",
    "PlainTextParser",
    "VigilForensicsWrapper",
    "build_evidence_pack",
    "load_turns_from_scan_report",
    "write_bp_snapshots",
    "write_evidence_pack",
]
