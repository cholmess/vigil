"""Tests for swarm-test helpers."""

from __future__ import annotations

from pathlib import Path

from vigil.loop.swarm import create_swarm_snapshot, parse_workflow_handoffs, run_swarm_test
from vigil.models import Attack, AttackSnapshot, BreakPointTest, Canary, Message, SnapshotMetadata


def _write_snapshot(tmp_path: Path, name: str) -> Path:
    snap = AttackSnapshot(
        vigil_version="0.1.0",
        metadata=SnapshotMetadata(
            snapshot_id=name,
            source="community",
            severity="critical",
            technique="indirect_rag",
        ),
        canary=Canary(token_type="api_key"),
        attack=Attack(
            conversation=[
                Message(role="system", content="sys"),
                Message(role="user", content="attack"),
                Message(role="assistant", content="sk_live_XXXXXXXXXXXXXXXXXXXXXXXX"),
            ]
        ),
        breakpoint_test=BreakPointTest(hardening_suggestion="Treat retrieved content as data."),
    )
    return snap.save_to_file(tmp_path / name)


def test_parse_workflow_handoffs_extracts_edges(tmp_path: Path) -> None:
    wf = tmp_path / "workflow.py"
    wf.write_text(
        'graph.add_edge("researcher", "summarizer")\n'
        'graph.add_edge("summarizer", "critic")\n',
        encoding="utf-8",
    )
    handoffs = parse_workflow_handoffs(wf)
    assert ("researcher", "summarizer") in handoffs
    assert ("summarizer", "critic") in handoffs


def test_create_swarm_snapshot_adds_handoff_and_framework_tags(tmp_path: Path) -> None:
    src = _write_snapshot(tmp_path, "attack-a")
    out = create_swarm_snapshot(
        src,
        out_dir=tmp_path / "out",
        handoff=("researcher", "summarizer"),
        framework="langgraph",
    )
    assert out.exists()
    loaded = AttackSnapshot.load_from_file(out)
    tags = {str(t).lower() for t in loaded.metadata.tags}
    assert "swarm_test" in tags
    assert "framework:langgraph" in tags
    assert "handoff:researcher->summarizer" in tags
    assert loaded.metadata.snapshot_id.startswith("swarm-")


def test_run_swarm_test_builds_findings_with_mock_runner(tmp_path: Path) -> None:
    wf = tmp_path / "workflow.py"
    wf.write_text('graph.add_edge("a", "b")\n', encoding="utf-8")
    src = _write_snapshot(tmp_path, "attack-a")

    class _FakeRunner:
        def run_regression_suite(self, attacks_dir, prompt):
            return {
                "total": 1,
                "allowed": 0,
                "warned": 0,
                "blocked": 1,
                "errors": 0,
                "results": [
                    {
                        "file": src.name,
                        "snapshot_id": "attack-a",
                        "severity": "critical",
                        "technique": "indirect_rag",
                        "attack_prompt": "attack",
                        "candidate_output": "leak",
                        "status": "BLOCK",
                        "reason_codes": ["credential_pattern_present"],
                    }
                ],
            }

    result = run_swarm_test(
        workflow_file=wf,
        attacks_dir=tmp_path,
        prompt="safe prompt",
        framework="langgraph",
        out_dir=tmp_path / "out",
        runner=_FakeRunner(),
    )
    assert len(result["findings"]) == 1
    assert Path(result["findings"][0]["saved_snapshot"]).exists()
