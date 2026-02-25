"""Audit report generation — JSON evidence pack and PDF report."""

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


def generate_json_report(path: str | Path, payload: dict[str, Any]) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def generate_pdf_report(path: str | Path, evidence: dict[str, Any]) -> bool:
    """
    Generate a PDF audit report.

    Requires fpdf2 (optional dependency). Returns True if successful,
    False if fpdf2 is not installed (falls back gracefully to JSON only).
    """
    try:
        from fpdf import FPDF  # type: ignore
    except ImportError:
        return False

    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Vigil Security Audit Report", ln=True)

    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, f"Generated: {evidence.get('generated_at', '')}", ln=True)
    pdf.cell(0, 6, f"Client: {evidence.get('client', '')}  Application: {evidence.get('application', '')}", ln=True)
    period = evidence.get("audit_period") or {}
    pdf.cell(0, 6, f"Period: {period.get('start', 'N/A')} — {period.get('end', 'N/A')}", ln=True)
    pdf.cell(0, 6, f"Traces scanned: {evidence.get('traces_scanned', 0)}  Turns analyzed: {evidence.get('turns_analyzed', 0)}", ln=True)
    pdf.ln(4)

    findings = evidence.get("findings", [])
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, f"Findings ({len(findings)} total)", ln=True)
    pdf.set_font("Helvetica", "", 9)

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "LOW"), 99))

    for i, f in enumerate(sorted_findings[:50], 1):
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(0, 6, f"[{f.get('severity', '')}] {f.get('finding_id', '')} — {f.get('pattern_name', '')}", ln=True)
        pdf.set_font("Helvetica", "", 8)
        pdf.cell(0, 5, f"  Trace: {f.get('trace_id', '')}  Time: {f.get('timestamp', '')}", ln=True)
        pdf.cell(0, 5, f"  Match: {f.get('matched_value', '')}  Confidence: {f.get('confidence', '')}", ln=True)
        pdf.multi_cell(0, 5, f"  Action: {f.get('action', '')}")
        pdf.ln(2)

    if len(sorted_findings) > 50:
        pdf.set_font("Helvetica", "I", 9)
        pdf.cell(0, 5, f"... and {len(sorted_findings) - 50} more findings (see evidence.json)", ln=True)

    if not findings:
        pdf.set_font("Helvetica", "I", 10)
        pdf.cell(0, 8, "No findings detected. Audit period appears clean.", ln=True)

    pdf.output(str(out))
    return True
