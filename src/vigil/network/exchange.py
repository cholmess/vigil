"""Local exchange store for network snapshot submission."""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from vigil.models import AttackSnapshot


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
    }
    with manifest.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")

    return network_id, dest
