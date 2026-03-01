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


def class_trends(
    records: list[dict[str, Any]],
    *,
    days: int = 7,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Return attack-class trend deltas for current vs previous period."""
    ref = now.astimezone(timezone.utc) if now else datetime.now(timezone.utc)
    current_start = ref - timedelta(days=days)
    previous_start = current_start - timedelta(days=days)

    current = Counter()
    previous = Counter()

    for row in records:
        attack_class = str(row.get("attack_class") or "").strip().lower()
        if not attack_class:
            continue
        submitted = _parse_iso8601(str(row.get("submitted_at", "")))
        if submitted is None:
            continue
        if submitted >= current_start:
            current[attack_class] += 1
        elif previous_start <= submitted < current_start:
            previous[attack_class] += 1

    keys = sorted(set(current) | set(previous))
    trends: list[dict[str, Any]] = []
    for key in keys:
        c = int(current.get(key, 0))
        p = int(previous.get(key, 0))
        trends.append(
            {
                "attack_class": key,
                "current": c,
                "previous": p,
                "delta": c - p,
            }
        )
    trends.sort(key=lambda r: (r["delta"], r["current"]), reverse=True)
    return trends


def build_intel_report(
    records: list[dict[str, Any]],
    *,
    days: int = 7,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build a normalized threat-intel report payload."""
    t_trends = technique_trends(records, days=days, now=now)
    c_trends = class_trends(records, days=days, now=now)
    top_technique = next((r["technique"] for r in t_trends if r["current"] > 0), None)
    top_class = next((r["attack_class"] for r in c_trends if r["current"] > 0), None)
    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "window_days": days,
        "records": len(records),
        "top_technique": top_technique,
        "top_class": top_class,
        "technique_trends": t_trends,
        "class_trends": c_trends,
    }


def build_threat_alert(
    records: list[dict[str, Any]],
    *,
    days: int = 7,
    attack_class: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build threat alert payload for a rising attack class."""
    ref = now.astimezone(timezone.utc) if now else datetime.now(timezone.utc)
    c_trends = class_trends(records, days=days, now=ref)
    if attack_class:
        chosen = next((r for r in c_trends if r["attack_class"] == attack_class.lower()), None)
    else:
        chosen = next((r for r in c_trends if r["current"] > 0), None)
    if not chosen:
        return {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "window_days": days,
            "attack_class": None,
            "found": False,
        }

    cls = chosen["attack_class"]
    class_records = [r for r in records if str(r.get("attack_class") or "").lower() == cls]
    first_seen_dt = None
    frameworks = Counter()
    for row in class_records:
        submitted = _parse_iso8601(str(row.get("submitted_at", "")))
        if submitted is not None and (first_seen_dt is None or submitted < first_seen_dt):
            first_seen_dt = submitted
        for fw in row.get("frameworks") or []:
            frameworks[str(fw).lower()] += 1

    first_seen_days_ago = None
    if first_seen_dt is not None:
        first_seen_days_ago = max(0, int((ref - first_seen_dt).total_seconds() // 86400))

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "window_days": days,
        "attack_class": cls,
        "found": True,
        "first_seen_days_ago": first_seen_days_ago,
        "current_window_occurrences": int(chosen["current"]),
        "previous_window_occurrences": int(chosen["previous"]),
        "delta": int(chosen["delta"]),
        "frameworks": dict(sorted(frameworks.items())),
    }
