"""Hardening suggestion helpers for blocked attack snapshots."""

from __future__ import annotations

from pathlib import Path

from vigil.models import AttackSnapshot


def hardening_suggestions_for_files(
    attacks_dir: str | Path,
    blocked_files: list[str],
) -> list[dict[str, str]]:
    """Return hardening suggestions for blocked snapshot file names."""
    attacks_path = Path(attacks_dir)
    suggestions: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for file_name in blocked_files:
        path = attacks_path / file_name
        if not path.exists():
            continue
        try:
            snapshot = AttackSnapshot.load_from_file(path)
        except Exception:
            continue

        suggestion = (
            snapshot.breakpoint_test.hardening_suggestion
            if snapshot.breakpoint_test is not None
            else None
        )
        if not suggestion:
            continue

        key = (snapshot.metadata.snapshot_id, suggestion)
        if key in seen:
            continue
        seen.add(key)
        suggestions.append(
            {
                "file": file_name,
                "snapshot_id": snapshot.metadata.snapshot_id,
                "severity": (snapshot.metadata.severity or "unknown").lower(),
                "technique": snapshot.metadata.technique.value,
                "suggestion": suggestion,
            }
        )

    return suggestions
