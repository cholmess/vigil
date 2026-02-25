"""Forensics reporting helpers — evidence packs and BreakPoint snapshot export."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vigil.forensics.models import ConversationTurn, Finding


def build_evidence_pack(
    client: str,
    application: str,
    turns: list[ConversationTurn],
    findings: list[Finding],
) -> dict[str, Any]:
    utc_now = datetime.now(timezone.utc).isoformat()
    turn_times = [t.timestamp for t in turns]
    start = min(turn_times).astimezone(timezone.utc).isoformat() if turn_times else None
    end = max(turn_times).astimezone(timezone.utc).isoformat() if turn_times else None

    return {
        "generated_at": utc_now,
        "client": client,
        "application": application,
        "audit_period": {"start": start, "end": end},
        "traces_scanned": len({t.conversation_id for t in turns}),
        "turns_analyzed": len(turns),
        "findings": [asdict(f) for f in findings],
        "methodology": {
            "detector": "Vigil deterministic pattern matching",
            "llm_calls": False,
            "notes": "Tiered credential, canary token, PII, and prompt injection indicators.",
        },
    }


def write_evidence_pack(path: str | Path, payload: dict[str, Any]) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_bp_snapshots(dir_path: str | Path, findings: list[Finding]) -> int:
    out_dir = Path(dir_path)
    out_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    for finding in findings:
        snapshot = {
            "name": finding.finding_id,
            "tags": ["forensics", finding.severity.lower(), finding.pattern_id],
            "description": f"{finding.pattern_name} detected in trace {finding.trace_id}",
            "expected": {"contains": finding.matched_value},
            "metadata": {
                "trace_id": finding.trace_id,
                "timestamp": finding.timestamp,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "kind": finding.kind,
            },
        }
        out = out_dir / f"{finding.finding_id}.bp.json"
        out.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
        written += 1
    return written


def load_turns_from_scan_report(path: str | Path) -> list[ConversationTurn]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    turns: list[ConversationTurn] = []
    for t in payload.get("turns", []):
        turns.append(
            ConversationTurn(
                conversation_id=t["conversation_id"],
                turn_index=int(t["turn_index"]),
                role=t["role"],
                content=t["content"],
                timestamp=datetime.fromisoformat(t["timestamp"]),
                metadata=t.get("metadata", {}),
                source_format=t.get("source_format", "unknown"),
            )
        )
    return turns
