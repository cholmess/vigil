"""Tests for network digest helper."""

from __future__ import annotations

from pathlib import Path

from vigil.models import Attack, AttackSnapshot, Canary, Message, SnapshotMetadata
from vigil.network.digest import summarize_pulled_snapshots


def _snapshot(tmp_path: Path, name: str, technique: str, severity: str) -> Path:
    snap = AttackSnapshot(
        vigil_version="0.1.0",
        metadata=SnapshotMetadata(
            snapshot_id=name,
            source="community",
            severity=severity,
            technique=technique,
        ),
        canary=Canary(token_type="api_key"),
        attack=Attack(conversation=[Message(role="user", content="x")]),
    )
    return snap.save_to_file(tmp_path / name)


def test_summarize_pulled_snapshots_counts_technique_and_severity(tmp_path: Path) -> None:
    _snapshot(tmp_path, "a", "jailbreak", "high")
    _snapshot(tmp_path, "b", "jailbreak", "critical")
    _snapshot(tmp_path, "c", "indirect_rag", "high")

    summary = summarize_pulled_snapshots(tmp_path)
    assert summary["total"] == 3
    assert summary["by_technique"]["jailbreak"] == 2
    assert summary["by_technique"]["indirect_rag"] == 1
    assert summary["by_severity"]["high"] == 2
