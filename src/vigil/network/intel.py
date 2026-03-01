"""Threat intel helpers over local exchange manifest."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def _parse_iso8601(value: str | None) -> datetime | None:
    if not value:
        return None
    raw = value.strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def load_manifest_records(network_dir: str | Path = ".vigil-data/network") -> list[dict[str, Any]]:
    """Load exchange manifest records."""
    manifest = Path(network_dir) / "exchange" / "manifest.jsonl"
    if not manifest.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        row = line.strip()
        if not row:
            continue
        try:
            data = json.loads(row)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            records.append(data)
    return records


def technique_trends(
    records: list[dict[str, Any]],
    *,
    days: int = 7,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Return technique trend deltas for current vs previous period."""
    ref = now.astimezone(timezone.utc) if now else datetime.now(timezone.utc)
    current_start = ref - timedelta(days=days)
    previous_start = current_start - timedelta(days=days)

    current = Counter()
    previous = Counter()

    for row in records:
        technique = str(row.get("technique") or "unknown")
        submitted = _parse_iso8601(str(row.get("submitted_at", "")))
        if submitted is None:
            continue
        if submitted >= current_start:
            current[technique] += 1
        elif previous_start <= submitted < current_start:
            previous[technique] += 1

    keys = sorted(set(current) | set(previous))
    trends: list[dict[str, Any]] = []
    for key in keys:
        c = int(current.get(key, 0))
        p = int(previous.get(key, 0))
        trends.append(
            {
                "technique": key,
                "current": c,
                "previous": p,
                "delta": c - p,
            }
        )
    trends.sort(key=lambda r: (r["delta"], r["current"]), reverse=True)
    return trends
