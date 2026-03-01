"""Local exchange store for network snapshot submission."""

from __future__ import annotations

import json
import shutil
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vigil.models import AttackSnapshot


def _org_ref_from_snapshot(snapshot: AttackSnapshot) -> str | None:
    """Return a non-reversible organization reference for shared intel stats."""
    tenant = None
    if snapshot.origin is not None:
        tenant = snapshot.origin.tenant
    raw = str(tenant or "").strip().lower()
    if not raw:
        return None
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return f"org-{digest}"


def _next_network_id(manifest: Path) -> str:
    year = datetime.now(timezone.utc).year
    seq = 1
    if manifest.exists():
        seq = sum(1 for _ in manifest.read_text(encoding="utf-8").splitlines() if _.strip()) + 1
    return f"VN-{year}-{seq:05d}"


def store_exchange_snapshot(snapshot_file: str | Path, *, network_dir: str | Path = ".vigil-data/network") -> tuple[str, Path]:
    """
    Store sanitized snapshot in local exchange and append manifest record.

    Returns `(network_id, destination_path)`.
    """
    src = Path(snapshot_file)
    snapshot = AttackSnapshot.load_from_file(src)

    root = Path(network_dir)
    snapshots_dir = root / "exchange" / "snapshots"
    snapshots_dir.mkdir(parents=True, exist_ok=True)
    manifest = root / "exchange" / "manifest.jsonl"

    network_id = _next_network_id(manifest)
    dest = snapshots_dir / f"{network_id}.bp.json"
    shutil.copy2(src, dest)

    record = {
        "network_id": network_id,
        "submitted_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "file": str(dest),
        "snapshot_id": snapshot.metadata.snapshot_id,
        "severity": snapshot.metadata.severity,
        "technique": snapshot.metadata.technique.value,
        "frameworks": [
            str(tag).split("framework:", 1)[1]
            for tag in snapshot.metadata.tags
            if str(tag).startswith("framework:")
        ],
        "attack_class": next(
            (
                str(tag).split("class:", 1)[1]
                for tag in snapshot.metadata.tags
                if str(tag).startswith("class:")
            ),
            None,
        ),
        "org_ref": _org_ref_from_snapshot(snapshot),
    }
    with manifest.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")

    return network_id, dest


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


def pull_exchange_snapshots(
    *,
    network_dir: str | Path = ".vigil-data/network",
    out_dir: str | Path = ".vigil-data/network/pulled",
    since: str | None = None,
    framework: str | None = None,
    attack_class: str | None = None,
) -> list[Path]:
    """
    Pull snapshots from local exchange manifest into out_dir.

    If ``since`` is set, only records with submitted_at >= since are copied.
    """
    root = Path(network_dir)
    manifest = root / "exchange" / "manifest.jsonl"
    if not manifest.exists():
        return []

    since_dt = _parse_iso8601(since)
    dst = Path(out_dir)
    dst.mkdir(parents=True, exist_ok=True)

    pulled: list[Path] = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        row = line.strip()
        if not row:
            continue
        try:
            record: dict[str, Any] = json.loads(row)
        except json.JSONDecodeError:
            continue

        submitted = _parse_iso8601(str(record.get("submitted_at", "")))
        if since_dt is not None and (submitted is None or submitted < since_dt):
            continue
        if framework:
            frameworks = {str(x).lower() for x in (record.get("frameworks") or [])}
            if framework.lower() not in frameworks:
                continue
        if attack_class:
            cls = str(record.get("attack_class") or "").lower()
            if cls != attack_class.lower():
                continue

        src = Path(str(record.get("file", "")))
        if not src.exists():
            continue
        dest = dst / src.name
        shutil.copy2(src, dest)
        pulled.append(dest)

    return pulled


def read_network_state(*, network_dir: str | Path = ".vigil-data/network") -> dict[str, Any]:
    """Read local network state metadata."""
    state = Path(network_dir) / "state.json"
    if not state.exists():
        return {}
    try:
        payload = json.loads(state.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    if not isinstance(payload, dict):
        return {}
    return payload


def write_network_state(
    *,
    network_dir: str | Path = ".vigil-data/network",
    updates: dict[str, Any],
) -> Path:
    """Merge and persist network state updates."""
    current = read_network_state(network_dir=network_dir)
    current.update(updates or {})
    state = Path(network_dir) / "state.json"
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(json.dumps(current, indent=2), encoding="utf-8")
    return state


def read_last_pull_since(*, network_dir: str | Path = ".vigil-data/network") -> str | None:
    """Read last pull timestamp from local network state."""
    payload = read_network_state(network_dir=network_dir)
    raw = payload.get("last_pull_since")
    return str(raw) if raw else None


def write_last_pull_since(
    *,
    network_dir: str | Path = ".vigil-data/network",
    timestamp: str | None = None,
) -> Path:
    """Persist last pull timestamp in local network state."""
    value = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return write_network_state(network_dir=network_dir, updates={"last_pull_since": value})
