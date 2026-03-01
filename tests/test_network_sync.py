"""Tests for exchange export/import sync helpers."""

from __future__ import annotations

from pathlib import Path

from vigil.models import Attack, AttackSnapshot, Canary, Message, SnapshotMetadata
from vigil.network.exchange import store_exchange_snapshot
from vigil.network.sync import export_exchange_bundle, import_exchange_bundle, merge_exchange_dirs


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


def test_export_exchange_bundle_copies_manifest_and_snapshots(tmp_path: Path) -> None:
    network = tmp_path / "network"
    snap = _snapshot(tmp_path, "a")
    store_exchange_snapshot(snap, network_dir=network)

    out, copied = export_exchange_bundle(network_dir=network, out_dir=tmp_path / "bundle")
    assert copied == 1
    assert (out / "exchange" / "manifest.jsonl").exists()
    assert len(list((out / "exchange" / "snapshots").glob("*.bp.json"))) == 1


def test_import_exchange_bundle_merges_and_skips_duplicates(tmp_path: Path) -> None:
    source_network = tmp_path / "source_network"
    target_network = tmp_path / "target_network"
    snap = _snapshot(tmp_path, "a")
    store_exchange_snapshot(snap, network_dir=source_network)

    bundle, _ = export_exchange_bundle(network_dir=source_network, out_dir=tmp_path / "bundle")
    first = import_exchange_bundle(source_dir=bundle, network_dir=target_network)
    second = import_exchange_bundle(source_dir=bundle, network_dir=target_network)

    assert first["imported"] == 1
    assert second["imported"] == 0
    assert second["skipped"] >= 1


def test_merge_exchange_dirs_merges_directories(tmp_path: Path) -> None:
    source_network = tmp_path / "source_network"
    target_network = tmp_path / "target_network"
    snap = _snapshot(tmp_path, "a")
    store_exchange_snapshot(snap, network_dir=source_network)

    result = merge_exchange_dirs(
        source_exchange_dir=source_network / "exchange",
        target_exchange_dir=target_network / "exchange",
    )
    assert result["imported"] == 1
    assert (target_network / "exchange" / "manifest.jsonl").exists()
