"""Exchange sync helpers for private network sharing."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any


def export_exchange_bundle(
    *,
    network_dir: str | Path = ".vigil-data/network",
    out_dir: str | Path = ".vigil-data/network/export",
) -> tuple[Path, int]:
    """Export exchange manifest + snapshots to a portable directory."""
    src_root = Path(network_dir) / "exchange"
    src_manifest = src_root / "manifest.jsonl"
    src_snapshots = src_root / "snapshots"

    dst = Path(out_dir)
    dst_exchange = dst / "exchange"
    dst_snapshots = dst_exchange / "snapshots"
    dst_snapshots.mkdir(parents=True, exist_ok=True)

    copied = 0
    if src_manifest.exists():
        shutil.copy2(src_manifest, dst_exchange / "manifest.jsonl")
    for snap in sorted(src_snapshots.glob("*.bp.json")) if src_snapshots.exists() else []:
        shutil.copy2(snap, dst_snapshots / snap.name)
        copied += 1
    return dst, copied


def import_exchange_bundle(
    *,
    source_dir: str | Path,
    network_dir: str | Path = ".vigil-data/network",
) -> dict[str, int]:
    """Merge an exported exchange bundle into local exchange store."""
    src = Path(source_dir) / "exchange"
    dst_root = Path(network_dir) / "exchange"
    return merge_exchange_dirs(source_exchange_dir=src, target_exchange_dir=dst_root)


def merge_exchange_dirs(
    *,
    source_exchange_dir: str | Path,
    target_exchange_dir: str | Path,
) -> dict[str, int]:
    """Merge one exchange directory into another by network_id."""
    src_root = Path(source_exchange_dir)
    src_manifest = src_root / "manifest.jsonl"
    src_snapshots = src_root / "snapshots"

    dst_root = Path(target_exchange_dir)
    dst_manifest = dst_root / "manifest.jsonl"
    dst_snapshots = dst_root / "snapshots"
    dst_snapshots.mkdir(parents=True, exist_ok=True)

    existing_ids: set[str] = set()
    if dst_manifest.exists():
        for row in dst_manifest.read_text(encoding="utf-8").splitlines():
            if not row.strip():
                continue
            try:
                data: dict[str, Any] = json.loads(row)
            except json.JSONDecodeError:
                continue
            nid = str(data.get("network_id") or "")
            if nid:
                existing_ids.add(nid)

    imported = 0
    skipped = 0
    if src_manifest.exists():
        with dst_manifest.open("a", encoding="utf-8") as out:
            for row in src_manifest.read_text(encoding="utf-8").splitlines():
                if not row.strip():
                    continue
                try:
                    data = json.loads(row)
                except json.JSONDecodeError:
                    skipped += 1
                    continue
                nid = str(data.get("network_id") or "")
                if not nid or nid in existing_ids:
                    skipped += 1
                    continue

                src_file = src_snapshots / f"{nid}.bp.json"
                if not src_file.exists():
                    skipped += 1
                    continue

                shutil.copy2(src_file, dst_snapshots / src_file.name)
                out.write(json.dumps(data) + "\n")
                existing_ids.add(nid)
                imported += 1

    return {"imported": imported, "skipped": skipped}
