"""Attack library management — list, import, and run community attack snapshots."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Optional

_COMMUNITY_DIR = Path(__file__).parent.parent / "attacks"


def list_attacks(attacks_dir: str | Path) -> list[dict]:
    """Return metadata for all .bp.json files in *attacks_dir*."""
    results = []
    for path in sorted(Path(attacks_dir).glob("*.bp.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            meta = data.get("metadata") or {}
            results.append(
                {
                    "file": path.name,
                    "path": str(path),
                    "snapshot_id": meta.get("snapshot_id", "?"),
                    "source": meta.get("source", "?"),
                    "severity": meta.get("severity", "?"),
                    "tags": meta.get("tags", []),
                    "description": (data.get("breakpoint_test") or {}).get("description", ""),
                }
            )
        except Exception:
            results.append({"file": path.name, "path": str(path), "error": "parse error"})
    return results


def import_attacks(
    source_dir: str | Path,
    attacks_dir: str | Path,
    *,
    source_label: Optional[str] = None,
) -> list[str]:
    """Copy all .bp.json files from *source_dir* into *attacks_dir*.

    If *source_label* is set, the ``metadata.source`` field is rewritten to
    that value in the copied files (useful for tagging community imports).

    Returns list of destination file paths.
    """
    src = Path(source_dir)
    dst = Path(attacks_dir)
    dst.mkdir(parents=True, exist_ok=True)

    copied: list[str] = []
    for path in sorted(src.glob("*.bp.json")):
        try:
            if source_label is not None:
                data = json.loads(path.read_text(encoding="utf-8"))
                meta = data.setdefault("metadata", {})
                meta["source"] = source_label
                dest_path = dst / path.name
                dest_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            else:
                dest_path = dst / path.name
                shutil.copy2(path, dest_path)
            copied.append(str(dest_path))
        except Exception:
            pass
    return copied


def community_attacks_dir() -> Path:
    """Return the path to the built-in community attack patterns directory."""
    return _COMMUNITY_DIR


def import_community_attacks(attacks_dir: str | Path) -> list[str]:
    """Copy the built-in community attack patterns into *attacks_dir*."""
    return import_attacks(_COMMUNITY_DIR, attacks_dir, source_label="community")
