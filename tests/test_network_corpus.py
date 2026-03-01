"""Tests for corpus export from local exchange."""

from __future__ import annotations

import json
from pathlib import Path

from vigil.models import Attack, AttackSnapshot, BreakPointTest, Canary, Message, SnapshotMetadata
from vigil.network.corpus import export_corpus_jsonl
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
