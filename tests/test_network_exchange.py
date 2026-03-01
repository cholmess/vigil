"""Tests for local network exchange storage."""

from __future__ import annotations

from pathlib import Path

from vigil.models import Attack, AttackSnapshot, Canary, Message, SnapshotMetadata
from vigil.network.exchange import store_exchange_snapshot


def _snapshot(tmp_path: Path, name: str) -> Path:
    snap = AttackSnapshot(
        vigil_version="0.1.0",
        metadata=SnapshotMetadata(
            snapshot_id=name,
            source="community",
            severity="high",
            technique="direct_injection",
        ),
        canary=Canary(token_type="api_key"),
        attack=Attack(conversation=[Message(role="user", content="x")]),
    )
    return snap.save_to_file(tmp_path / name)


def test_store_exchange_snapshot_assigns_network_id(tmp_path: Path) -> None:
    snap_path = _snapshot(tmp_path, "a")
    network_id, stored = store_exchange_snapshot(snap_path, network_dir=tmp_path / "network")
    assert network_id.startswith("VN-")
    assert stored.exists()
    manifest = tmp_path / "network" / "exchange" / "manifest.jsonl"
    assert manifest.exists()


def test_store_exchange_snapshot_increments_sequence(tmp_path: Path) -> None:
    p1 = _snapshot(tmp_path, "a")
    p2 = _snapshot(tmp_path, "b")
    id1, _ = store_exchange_snapshot(p1, network_dir=tmp_path / "network")
    id2, _ = store_exchange_snapshot(p2, network_dir=tmp_path / "network")
    assert id1 != id2
