"""Corpus export helpers for Phase 3 model training workflows."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vigil.network.exchange import pull_exchange_snapshots
from vigil.models import AttackSnapshot


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


def _load_manifest_records(network_dir: str | Path) -> list[dict[str, Any]]:
    manifest = Path(network_dir) / "exchange" / "manifest.jsonl"
    if not manifest.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        raw = line.strip()
        if not raw:
            continue
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            records.append(data)
    return records


def build_corpus_stats(
    *,
    network_dir: str | Path = ".vigil-data/network",
    since: str | None = None,
    framework: str | None = None,
    attack_class: str | None = None,
) -> dict[str, Any]:
    """Compute high-level corpus stats from exchange manifest records."""
    records = _load_manifest_records(network_dir)
    since_dt = _parse_iso8601(since)

    filtered: list[dict[str, Any]] = []
    for row in records:
        submitted = _parse_iso8601(str(row.get("submitted_at", "")))
        if since_dt is not None and (submitted is None or submitted < since_dt):
            continue
        if framework:
            frameworks = {str(x).lower() for x in (row.get("frameworks") or [])}
            if framework.lower() not in frameworks:
                continue
        if attack_class:
            cls = str(row.get("attack_class") or "").lower()
            if cls != attack_class.lower():
                continue
        filtered.append(row)

    techniques = Counter()
    severities = Counter()
    classes = Counter()
    frameworks = Counter()
    org_refs: set[str] = set()
    submitted_times: list[datetime] = []
    for row in filtered:
        technique = str(row.get("technique") or "unknown")
        severity = str(row.get("severity") or "unknown")
        attack_cls = str(row.get("attack_class") or "unknown")
        techniques[technique] += 1
        severities[severity] += 1
        classes[attack_cls] += 1
        for fw in row.get("frameworks") or []:
            frameworks[str(fw).lower()] += 1
        org_ref = str(row.get("org_ref") or "").strip().lower()
        if org_ref:
            org_refs.add(org_ref)
        submitted = _parse_iso8601(str(row.get("submitted_at", "")))
        if submitted is not None:
            submitted_times.append(submitted)

    first_submitted = min(submitted_times).strftime("%Y-%m-%dT%H:%M:%SZ") if submitted_times else None
    last_submitted = max(submitted_times).strftime("%Y-%m-%dT%H:%M:%SZ") if submitted_times else None

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "filters": {
            "since": since,
            "framework": framework,
            "attack_class": attack_class,
        },
        "total_records": len(filtered),
        "time_range": {
            "first_submitted_at": first_submitted,
            "last_submitted_at": last_submitted,
        },
        "distributions": {
            "techniques": dict(sorted(techniques.items())),
            "severities": dict(sorted(severities.items())),
            "attack_classes": dict(sorted(classes.items())),
            "frameworks": dict(sorted(frameworks.items())),
        },
        "organizations": {
            "known_org_refs": len(org_refs),
        },
    }


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
