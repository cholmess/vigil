"""Corpus export helpers for Phase 3 model training workflows."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vigil.network.exchange import pull_exchange_snapshots
from vigil.models import AttackSnapshot


def export_corpus_jsonl(
    *,
    network_dir: str | Path = ".vigil-data/network",
    out_file: str | Path = ".vigil-data/network/corpus/corpus.jsonl",
    since: str | None = None,
    framework: str | None = None,
    attack_class: str | None = None,
) -> tuple[Path, int]:
    """
    Export exchange snapshots as normalized JSONL rows.

    Returns `(path, row_count)`.
    """
    root = Path(network_dir)
    stage = root / "corpus" / "_tmp"
    pulled = pull_exchange_snapshots(
        network_dir=root,
        out_dir=stage,
        since=since,
        framework=framework,
        attack_class=attack_class,
    )

    out = Path(out_file)
    out.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with out.open("w", encoding="utf-8") as fh:
        for path in pulled:
            try:
                snap = AttackSnapshot.load_from_file(path)
            except Exception:
                continue
            record: dict[str, Any] = {
                "snapshot_id": snap.metadata.snapshot_id,
                "source": snap.metadata.source,
                "severity": snap.metadata.severity,
                "technique": snap.metadata.technique.value,
                "tags": list(snap.metadata.tags),
                "attack_pattern": snap.attack.attack_pattern,
                "attack_prompt": snap.attack.attack_prompt,
                "block_conditions": (
                    list(snap.breakpoint_test.block_conditions)
                    if snap.breakpoint_test is not None
                    else []
                ),
                "hardening_suggestion": (
                    snap.breakpoint_test.hardening_suggestion
                    if snap.breakpoint_test is not None
                    else None
                ),
                "conversation": [m.model_dump() for m in snap.attack.conversation],
            }
            fh.write(json.dumps(record, ensure_ascii=True) + "\n")
            count += 1

    return out, count
