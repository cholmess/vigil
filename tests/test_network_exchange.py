"""Tests for local network exchange storage."""

from __future__ import annotations

from pathlib import Path

from vigil.models import Attack, AttackSnapshot, Canary, Message, SnapshotMetadata
from vigil.network.exchange import (
    pull_exchange_snapshots,
    read_network_state,
    read_last_pull_since,
    store_exchange_snapshot,
    write_network_state,
    write_last_pull_since,
)


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


def _snapshot_with_framework(tmp_path: Path, name: str, framework: str) -> Path:
    snap = AttackSnapshot(
        vigil_version="0.1.0",
        metadata=SnapshotMetadata(
            snapshot_id=name,
            source="community",
            severity="high",
            technique="direct_injection",
            tags=[f"framework:{framework}"],
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


def test_pull_exchange_snapshots_copies_to_out_dir(tmp_path: Path) -> None:
    snap_path = _snapshot(tmp_path, "a")
    network_dir = tmp_path / "network"
    network_id, _ = store_exchange_snapshot(snap_path, network_dir=network_dir)
    pulled = pull_exchange_snapshots(network_dir=network_dir, out_dir=tmp_path / "pulled")
    assert len(pulled) == 1
    assert pulled[0].name == f"{network_id}.bp.json"


def test_pull_exchange_snapshots_respects_since_filter(tmp_path: Path) -> None:
    snap_path = _snapshot(tmp_path, "a")
    network_dir = tmp_path / "network"
    store_exchange_snapshot(snap_path, network_dir=network_dir)
    pulled = pull_exchange_snapshots(
        network_dir=network_dir,
        out_dir=tmp_path / "pulled",
        since="2999-01-01",
    )
    assert pulled == []


def test_pull_exchange_snapshots_framework_filter(tmp_path: Path) -> None:
    n = tmp_path / "network"
    p1 = _snapshot_with_framework(tmp_path, "a", "langchain")
    p2 = _snapshot_with_framework(tmp_path, "b", "langgraph")
    store_exchange_snapshot(p1, network_dir=n)
    store_exchange_snapshot(p2, network_dir=n)

    pulled = pull_exchange_snapshots(
        network_dir=n,
        out_dir=tmp_path / "pulled",
        framework="langgraph",
    )
    assert len(pulled) == 1
    assert pulled[0].name.endswith(".bp.json")


def test_write_and_read_last_pull_since(tmp_path: Path) -> None:
    network_dir = tmp_path / "network"
    write_last_pull_since(network_dir=network_dir, timestamp="2026-03-01T00:00:00Z")
    assert read_last_pull_since(network_dir=network_dir) == "2026-03-01T00:00:00Z"


def test_write_network_state_merges_updates(tmp_path: Path) -> None:
    network_dir = tmp_path / "network"
    write_network_state(network_dir=network_dir, updates={"last_pull_count": 3})
    write_network_state(network_dir=network_dir, updates={"last_pull_since": "2026-03-01T00:00:00Z"})
    state = read_network_state(network_dir=network_dir)
    assert state["last_pull_count"] == 3
    assert state["last_pull_since"] == "2026-03-01T00:00:00Z"
