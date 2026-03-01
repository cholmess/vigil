"""Digest helpers for network update summaries."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from vigil.models import AttackSnapshot


def summarize_pulled_snapshots(attacks_dir: str | Path) -> dict[str, Any]:
    """Summarize pulled snapshot counts by technique and severity."""
    root = Path(attacks_dir)
    rows = []
    for bp in sorted(root.glob("*.bp.json")):
        try:
            snap = AttackSnapshot.load_from_file(bp)
        except Exception:
            continue
        rows.append(snap)

    by_technique = Counter(s.metadata.technique.value for s in rows)
    by_severity = Counter((s.metadata.severity or "unknown").lower() for s in rows)
    return {
        "total": len(rows),
        "by_technique": dict(sorted(by_technique.items())),
        "by_severity": dict(sorted(by_severity.items())),
    }
