"""Audit lifecycle management — init, ingest, scan, report."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _slug(value: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    return text or "audit"


@dataclass(frozen=True)
class AuditPaths:
    root: Path
    metadata: Path
    scan_report: Path
    evidence: Path
    pdf: Path
    bp_dir: Path


class AuditManager:
    def __init__(self, base_dir: str | Path = ".vigil/audits") -> None:
        self.base_dir = Path(base_dir)

    def init_audit(
        self,
        name: str,
        *,
        source: str = "otel",
        provider: str = "vigil",
        logs: str | None = None,
        client: str = "",
        application: str = "",
        patterns_file: str | None = None,
    ) -> AuditPaths:
        audit_id = _slug(name)
        root = self.base_dir / audit_id
        root.mkdir(parents=True, exist_ok=True)
        paths = self._paths(root)

        payload: dict[str, Any] = {
            "audit_id": audit_id,
            "name": name,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "source": source,
            "provider": provider,
            "logs": logs,
            "client": client,
            "application": application,
            "patterns_file": patterns_file,
            "scan_report": str(paths.scan_report),
            "evidence": str(paths.evidence),
            "pdf": str(paths.pdf),
            "bp_dir": str(paths.bp_dir),
        }
        paths.metadata.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return paths

    def load_metadata(self, audit_id: str) -> dict[str, Any]:
        root = self.base_dir / audit_id
        paths = self._paths(root)
        if not paths.metadata.exists():
            raise FileNotFoundError(f"Audit not found: {audit_id}")
        return json.loads(paths.metadata.read_text(encoding="utf-8"))

    def list_audits(self) -> list[dict[str, Any]]:
        if not self.base_dir.exists():
            return []
        audits = []
        for child in sorted(self.base_dir.iterdir()):
            meta_path = child / "audit.json"
            if meta_path.exists():
                try:
                    audits.append(json.loads(meta_path.read_text(encoding="utf-8")))
                except Exception:
                    continue
        return audits

    def _paths(self, root: Path) -> AuditPaths:
        return AuditPaths(
            root=root,
            metadata=root / "audit.json",
            scan_report=root / "scan-report.json",
            evidence=root / "evidence.json",
            pdf=root / "audit-report.pdf",
            bp_dir=root / "bp-snapshots",
        )
