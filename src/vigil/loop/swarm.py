"""Swarm test helpers for multi-agent workflow attack attribution."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from vigil.loop.replayer import VigilBreakPointRunner
from vigil.models import AttackSnapshot

_EDGE_PATTERNS = (
    re.compile(r'add_edge\(\s*["\']([^"\']+)["\']\s*,\s*["\']([^"\']+)["\']\s*\)'),
    re.compile(r'["\']?([A-Za-z_][\w\-]*)["\']?\s*->\s*["\']?([A-Za-z_][\w\-]*)["\']?'),
    re.compile(r"\b([A-Za-z_][\w\-]*)\s*>>\s*([A-Za-z_][\w\-]*)\b"),
)


def parse_workflow_handoffs(workflow_file: str | Path) -> list[tuple[str, str]]:
    """Extract ordered agent handoffs from a workflow definition file."""
    path = Path(workflow_file)
    if not path.exists():
        return [("entry", "worker")]
    text = path.read_text(encoding="utf-8")
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for pattern in _EDGE_PATTERNS:
        for src, dst in pattern.findall(text):
            pair = (src.strip(), dst.strip())
            if pair[0] and pair[1] and pair not in seen:
                seen.add(pair)
                pairs.append(pair)

    if not pairs:
        return [("entry", "worker")]
    return pairs


def create_swarm_snapshot(
    source_snapshot: str | Path,
    *,
    out_dir: str | Path,
    handoff: tuple[str, str],
    framework: str,
) -> Path:
    """Copy a blocked snapshot into swarm-test namespace with handoff tags."""
    src = Path(source_snapshot)
    snap = AttackSnapshot.load_from_file(src)

    src_agent, dst_agent = handoff
    new_tags = list(snap.metadata.tags)
    framework_tag = f"framework:{framework.lower()}"
    handoff_tag = f"handoff:{src_agent}->{dst_agent}"
    for tag in ("swarm_test", framework_tag, handoff_tag):
        if tag not in {str(t).lower() for t in new_tags}:
            new_tags.append(tag)

    updated = snap.model_copy(
        update={
            "metadata": snap.metadata.model_copy(
                update={
                    "snapshot_id": f"swarm-{snap.metadata.snapshot_id}",
                    "tags": new_tags,
                }
            )
        }
    )
    out_name = f"swarm-{src.name}"
    out_path = Path(out_dir) / out_name
    return updated.save_to_file(out_path)


def run_swarm_test(
    *,
    workflow_file: str | Path,
    attacks_dir: str | Path,
    prompt: str,
    framework: str,
    out_dir: str | Path,
    runner: VigilBreakPointRunner | None = None,
) -> dict[str, Any]:
    """Run blocked-attack attribution across workflow handoffs."""
    handoffs = parse_workflow_handoffs(workflow_file)
    engine = runner or VigilBreakPointRunner()
    summary = engine.run_regression_suite(attacks_dir, prompt)

    blocked = [r for r in summary["results"] if r["status"] == "BLOCK"]
    findings: list[dict[str, Any]] = []
    for i, row in enumerate(blocked):
        handoff = handoffs[i % len(handoffs)]
        saved = create_swarm_snapshot(
            Path(attacks_dir) / row["file"],
            out_dir=out_dir,
            handoff=handoff,
            framework=framework,
        )
        findings.append(
            {
                "handoff": handoff,
                "snapshot_id": row["snapshot_id"],
                "severity": row.get("severity", "unknown"),
                "technique": row.get("technique", "unknown"),
                "status": row["status"],
                "saved_snapshot": str(saved),
            }
        )

    return {
        "summary": summary,
        "handoffs": handoffs,
        "findings": findings,
    }
