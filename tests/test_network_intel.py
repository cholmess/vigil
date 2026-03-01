"""Tests for network threat intel helpers."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from vigil.network.intel import (
    build_intel_report,
    build_threat_alert,
    build_threat_feed,
    class_trends,
    load_manifest_records,
    technique_trends,
)


def _write_manifest(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


def test_load_manifest_records_reads_jsonl(tmp_path: Path) -> None:
    manifest = tmp_path / "network" / "exchange" / "manifest.jsonl"
    _write_manifest(
        manifest,
        [
            {"network_id": "VN-2026-00001", "technique": "jailbreak", "submitted_at": "2026-03-01T00:00:00Z"}
        ],
    )
    records = load_manifest_records(tmp_path / "network")
    assert len(records) == 1
    assert records[0]["technique"] == "jailbreak"


def test_technique_trends_computes_delta(tmp_path: Path) -> None:
    now = datetime(2026, 3, 15, tzinfo=timezone.utc)
    records = [
        {"technique": "indirect_rag", "submitted_at": "2026-03-14T00:00:00Z"},
        {"technique": "indirect_rag", "submitted_at": "2026-03-13T00:00:00Z"},
        {"technique": "indirect_rag", "submitted_at": "2026-03-02T00:00:00Z"},
        {"technique": "jailbreak", "submitted_at": "2026-03-03T00:00:00Z"},
    ]
    trends = technique_trends(records, days=7, now=now)
    by_name = {t["technique"]: t for t in trends}
    assert by_name["indirect_rag"]["current"] == 2
    assert by_name["indirect_rag"]["previous"] == 1
    assert by_name["indirect_rag"]["delta"] == 1


def test_class_trends_computes_delta(tmp_path: Path) -> None:
    now = datetime(2026, 3, 15, tzinfo=timezone.utc)
    records = [
        {"attack_class": "tool-result-injection", "submitted_at": "2026-03-14T00:00:00Z"},
        {"attack_class": "tool-result-injection", "submitted_at": "2026-03-03T00:00:00Z"},
        {"attack_class": "other", "submitted_at": "2026-03-13T00:00:00Z"},
    ]
    trends = class_trends(records, days=7, now=now)
    by_name = {t["attack_class"]: t for t in trends}
    assert by_name["tool-result-injection"]["current"] == 1
    assert by_name["tool-result-injection"]["previous"] == 1
    assert by_name["tool-result-injection"]["delta"] == 0


def test_build_intel_report_includes_top_fields() -> None:
    records = [
        {"technique": "jailbreak", "attack_class": "tool-result-injection", "submitted_at": "2026-03-14T00:00:00Z"},
        {"technique": "jailbreak", "attack_class": "tool-result-injection", "submitted_at": "2026-03-13T00:00:00Z"},
    ]
    report = build_intel_report(records, days=7, now=datetime(2026, 3, 15, tzinfo=timezone.utc))
    assert report["records"] == 2
    assert report["top_technique"] == "jailbreak"
    assert report["top_class"] == "tool-result-injection"


def test_build_threat_alert_selects_top_class() -> None:
    records = [
        {
            "attack_class": "tool-result-injection",
            "technique": "tool_injection",
            "frameworks": ["langchain"],
            "org_ref": "org-a",
            "submitted_at": "2026-03-14T00:00:00Z",
        },
        {
            "attack_class": "tool-result-injection",
            "technique": "tool_injection",
            "frameworks": ["langgraph"],
            "org_ref": "org-b",
            "submitted_at": "2026-03-13T00:00:00Z",
        },
        {
            "attack_class": "other",
            "technique": "jailbreak",
            "frameworks": ["generic"],
            "submitted_at": "2026-03-03T00:00:00Z",
        },
    ]
    alert = build_threat_alert(records, days=7, now=datetime(2026, 3, 15, tzinfo=timezone.utc))
    assert alert["found"] is True
    assert alert["attack_class"] == "tool-result-injection"
    assert alert["current_window_occurrences"] == 2
    assert alert["previous_window_occurrences"] == 0
    assert alert["delta"] == 2
    assert alert["frameworks"] == {"langchain": 1, "langgraph": 1}
    assert alert["organizations_affected"] == 2


def test_build_threat_alert_respects_requested_class() -> None:
    records = [
        {
            "attack_class": "tool-result-injection",
            "frameworks": ["langchain"],
            "org_ref": "org-a",
            "submitted_at": "2026-03-14T00:00:00Z",
        },
        {
            "attack_class": "indirect-prompt-injection",
            "frameworks": ["llamaindex"],
            "org_ref": "org-b",
            "submitted_at": "2026-03-14T00:00:00Z",
        },
    ]
    alert = build_threat_alert(
        records,
        days=7,
        attack_class="indirect-prompt-injection",
        now=datetime(2026, 3, 15, tzinfo=timezone.utc),
    )
    assert alert["found"] is True
    assert alert["attack_class"] == "indirect-prompt-injection"
    assert alert["frameworks"] == {"llamaindex": 1}
    assert alert["organizations_affected"] == 1


def test_build_threat_alert_returns_not_found_when_no_match() -> None:
    alert = build_threat_alert(
        [{"attack_class": "tool-result-injection", "submitted_at": "2026-03-14T00:00:00Z"}],
        days=7,
        attack_class="missing-class",
        now=datetime(2026, 3, 15, tzinfo=timezone.utc),
    )
    assert alert["found"] is False
    assert alert["attack_class"] is None


def test_build_threat_feed_returns_top_alerts() -> None:
    records = [
        {
            "attack_class": "tool-result-injection",
            "frameworks": ["langchain"],
            "org_ref": "org-a",
            "submitted_at": "2026-03-14T00:00:00Z",
        },
        {
            "attack_class": "indirect-prompt-injection",
            "frameworks": ["langgraph"],
            "org_ref": "org-b",
            "submitted_at": "2026-03-14T00:00:00Z",
        },
    ]
    payload = build_threat_feed(records, days=7, top=1, now=datetime(2026, 3, 15, tzinfo=timezone.utc))
    assert payload["records"] == 2
    assert len(payload["alerts"]) == 1
