"""Tests for corpus export from local exchange."""

from __future__ import annotations

import json
import tarfile
from pathlib import Path

from vigil.models import Attack, AttackSnapshot, BreakPointTest, Canary, Message, SnapshotMetadata
from vigil.network.corpus import (
    build_corpus_stats,
    build_train_bundle_manifest,
    export_corpus_jsonl,
    package_train_bundle,
    split_corpus_jsonl,
    validate_corpus_jsonl,
)
from vigil.network.exchange import store_exchange_snapshot


def _snapshot(tmp_path: Path, name: str, *, tags: list[str]) -> Path:
    snap = AttackSnapshot(
        vigil_version="0.1.0",
        metadata=SnapshotMetadata(
            snapshot_id=name,
            source="community",
            severity="high",
            technique="tool_injection",
            tags=tags,
        ),
        canary=Canary(token_type="api_key"),
        attack=Attack(
            conversation=[
                Message(role="system", content="sys"),
                Message(role="user", content="attack"),
            ],
            attack_pattern="tool_result_injection",
            attack_prompt="attack prompt",
        ),
        breakpoint_test=BreakPointTest(
            block_conditions=["url_with_secret_detected"],
            hardening_suggestion="Sanitize tool outputs.",
        ),
    )
    return snap.save_to_file(tmp_path / name)


def test_export_corpus_jsonl_writes_rows(tmp_path: Path) -> None:
    network = tmp_path / "network"
    s1 = _snapshot(tmp_path, "a", tags=["framework:langchain", "class:tool-result-injection"])
    s2 = _snapshot(tmp_path, "b", tags=["framework:langgraph", "class:other"])
    store_exchange_snapshot(s1, network_dir=network)
    store_exchange_snapshot(s2, network_dir=network)

    out, rows = export_corpus_jsonl(network_dir=network, out_file=tmp_path / "corpus.jsonl")
    assert out.exists()
    assert rows == 2

    lines = out.read_text(encoding="utf-8").strip().splitlines()
    parsed = [json.loads(line) for line in lines]
    assert parsed[0]["technique"] == "tool_injection"
    assert isinstance(parsed[0]["conversation"], list)


def test_export_corpus_jsonl_respects_framework_filter(tmp_path: Path) -> None:
    network = tmp_path / "network"
    s1 = _snapshot(tmp_path, "a", tags=["framework:langchain", "class:tool-result-injection"])
    s2 = _snapshot(tmp_path, "b", tags=["framework:langgraph", "class:other"])
    store_exchange_snapshot(s1, network_dir=network)
    store_exchange_snapshot(s2, network_dir=network)

    _, rows = export_corpus_jsonl(
        network_dir=network,
        out_file=tmp_path / "corpus.jsonl",
        framework="langchain",
    )
    assert rows == 1


def test_build_corpus_stats_summarizes_records(tmp_path: Path) -> None:
    network = tmp_path / "network"
    s1 = _snapshot(tmp_path, "a", tags=["framework:langchain", "class:tool-result-injection"])
    s2 = _snapshot(tmp_path, "b", tags=["framework:langgraph", "class:other"])
    store_exchange_snapshot(s1, network_dir=network)
    store_exchange_snapshot(s2, network_dir=network)

    payload = build_corpus_stats(network_dir=network)
    assert payload["total_records"] == 2
    assert payload["distributions"]["techniques"]["tool_injection"] == 2
    assert payload["distributions"]["frameworks"]["langchain"] == 1


def test_build_corpus_stats_respects_class_filter(tmp_path: Path) -> None:
    network = tmp_path / "network"
    s1 = _snapshot(tmp_path, "a", tags=["framework:langchain", "class:tool-result-injection"])
    s2 = _snapshot(tmp_path, "b", tags=["framework:langgraph", "class:other"])
    store_exchange_snapshot(s1, network_dir=network)
    store_exchange_snapshot(s2, network_dir=network)

    payload = build_corpus_stats(network_dir=network, attack_class="tool-result-injection")
    assert payload["total_records"] == 1
    assert payload["distributions"]["attack_classes"]["tool-result-injection"] == 1


def test_split_corpus_jsonl_writes_train_and_val(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus.jsonl"
    corpus.write_text('{"id":1}\n{"id":2}\n{"id":3}\n{"id":4}\n', encoding="utf-8")
    train_file, val_file, train_rows, val_rows = split_corpus_jsonl(
        corpus_file=corpus,
        out_dir=tmp_path,
        val_ratio=0.25,
        seed=123,
    )
    assert train_file.exists()
    assert val_file.exists()
    assert train_rows + val_rows == 4
    assert val_rows >= 1


def test_validate_corpus_jsonl_flags_missing_fields(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus.jsonl"
    corpus.write_text('{"snapshot_id":"a","technique":"jailbreak","conversation":[]}\n{"snapshot_id":"b"}\n', encoding="utf-8")
    payload = validate_corpus_jsonl(corpus_file=corpus)
    assert payload["rows"] == 2
    assert payload["invalid_rows"] == 2
    assert payload["ok"] is False


def test_package_train_bundle_writes_manifest_and_tar(tmp_path: Path) -> None:
    train_dir = tmp_path / "train"
    train_dir.mkdir(parents=True, exist_ok=True)
    (train_dir / "corpus.jsonl").write_text('{"snapshot_id":"a","technique":"jailbreak","conversation":[{}]}\n', encoding="utf-8")
    (train_dir / "prepare-report.json").write_text('{"rows":1}', encoding="utf-8")

    manifest = build_train_bundle_manifest(train_dir=train_dir)
    assert len(manifest["files"]) >= 2

    out, manifest_path = package_train_bundle(train_dir=train_dir, out_file=train_dir / "bundle.tar.gz")
    assert out.exists()
    assert manifest_path.exists()

    with tarfile.open(out, "r:gz") as tar:
        names = set(tar.getnames())
    assert "corpus.jsonl" in names
    assert "prepare-report.json" in names
    assert "bundle-manifest.json" in names
