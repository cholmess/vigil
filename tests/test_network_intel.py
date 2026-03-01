"""Tests for network threat intel helpers."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from vigil.network.intel import class_trends, load_manifest_records, technique_trends


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
