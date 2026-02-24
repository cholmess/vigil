"""Tests for vigil.loop.replayer — VigilBreakPointRunner."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from vigil.loop.replayer import (
    VigilBreakPointRunner,
    _build_baseline,
    _extract_assistant_output,
    _extract_user_input,
)
from vigil.models import (
    Attack,
    AttackSnapshot,
    BreakPointBaseline,
    BreakPointTest,
    Canary,
    Message,
    SnapshotMetadata,
)

# --------------------------------------------------------------------------- #
# Helper to write a snapshot file                                              #
# --------------------------------------------------------------------------- #

def _write_snap(
    tmp_path: Path,
    name: str,
    conversation: list[dict],
    attack_prompt: str | None = None,
    bp_baseline_output: str | None = None,
) -> Path:
    snap = AttackSnapshot(
        vigil_version="0.1.0",
        metadata=SnapshotMetadata(snapshot_id=name, source="canari"),
        canary=Canary(token_type="api_key"),
        attack=Attack(
            conversation=[Message(**m) for m in conversation],
            attack_prompt=attack_prompt,
        ),
        breakpoint_test=BreakPointTest(
            baseline=BreakPointBaseline(output=bp_baseline_output) if bp_baseline_output else None
        ),
    )
    return snap.save_to_file(tmp_path / name)


def _make_decision(status: str = "ALLOW", reason_codes: list[str] | None = None) -> MagicMock:
    d = MagicMock()
    d.status = status
    d.reason_codes = reason_codes or []
    return d


# --------------------------------------------------------------------------- #
# Unit tests for helper functions                                              #
# --------------------------------------------------------------------------- #

class TestExtractHelpers:
    def test_extract_user_input_from_attack_prompt(self) -> None:
        snap = AttackSnapshot(
            vigil_version="0.1.0",
            metadata=SnapshotMetadata(snapshot_id="x", source="canari"),
            canary=Canary(token_type="api_key"),
            attack=Attack(
                conversation=[Message(role="user", content="from conversation")],
                attack_prompt="from attack_prompt",
            ),
        )
        assert _extract_user_input(snap) == "from attack_prompt"

    def test_extract_user_input_falls_back_to_conversation(self) -> None:
        snap = AttackSnapshot(
            vigil_version="0.1.0",
            metadata=SnapshotMetadata(snapshot_id="x", source="canari"),
            canary=Canary(token_type="api_key"),
            attack=Attack(
                conversation=[
                    Message(role="system", content="sys"),
                    Message(role="user", content="user msg"),
                ]
            ),
        )
        assert _extract_user_input(snap) == "user msg"

    def test_extract_user_input_empty_when_no_user_turn(self) -> None:
        snap = AttackSnapshot(
            vigil_version="0.1.0",
            metadata=SnapshotMetadata(snapshot_id="x", source="canari"),
            canary=Canary(token_type="api_key"),
            attack=Attack(conversation=[Message(role="system", content="sys")]),
        )
        assert _extract_user_input(snap) == ""

    def test_extract_assistant_output(self) -> None:
        snap = AttackSnapshot(
            vigil_version="0.1.0",
            metadata=SnapshotMetadata(snapshot_id="x", source="canari"),
            canary=Canary(token_type="api_key"),
            attack=Attack(
                conversation=[
                    Message(role="system", content="sys"),
                    Message(role="user", content="attack"),
                    Message(role="assistant", content="leaked: canari_test_abc"),
                ]
            ),
        )
        assert _extract_assistant_output(snap) == "leaked: canari_test_abc"

    def test_extract_assistant_falls_back_to_user_input(self) -> None:
        snap = AttackSnapshot(
            vigil_version="0.1.0",
            metadata=SnapshotMetadata(snapshot_id="x", source="canari"),
            canary=Canary(token_type="api_key"),
            attack=Attack(
                conversation=[Message(role="user", content="attack prompt")],
                attack_prompt="attack prompt",
            ),
        )
        # No assistant message → falls back to user input
        result = _extract_assistant_output(snap)
        assert result == "attack prompt"

    def test_build_baseline_from_breakpoint_test(self) -> None:
        snap = AttackSnapshot(
            vigil_version="0.1.0",
            metadata=SnapshotMetadata(snapshot_id="x", source="canari"),
            canary=Canary(token_type="api_key"),
            attack=Attack(),
            breakpoint_test=BreakPointTest(
                baseline=BreakPointBaseline(output="Safe response from spec.")
            ),
        )
        assert _build_baseline(snap, "system prompt") == "Safe response from spec."

    def test_build_baseline_falls_back_to_system_prompt(self) -> None:
        snap = AttackSnapshot(
            vigil_version="0.1.0",
            metadata=SnapshotMetadata(snapshot_id="x", source="canari"),
            canary=Canary(token_type="api_key"),
            attack=Attack(),
        )
        assert _build_baseline(snap, "my system prompt") == "my system prompt"

    def test_build_baseline_last_resort(self) -> None:
        snap = AttackSnapshot(
            vigil_version="0.1.0",
            metadata=SnapshotMetadata(snapshot_id="x", source="canari"),
            canary=Canary(token_type="api_key"),
            attack=Attack(),
        )
        result = _build_baseline(snap, "")
        assert "sorry" in result.lower() or len(result) > 0


# --------------------------------------------------------------------------- #
# Integration tests for VigilBreakPointRunner                                 #
# --------------------------------------------------------------------------- #

class TestVigilBreakPointRunner:
    def test_empty_dir_returns_zero_totals(self, tmp_path: Path) -> None:
        runner = VigilBreakPointRunner()
        result = runner.run_regression_suite(tmp_path, "system prompt")
        assert result["total"] == 0
        assert result["allowed"] == 0
        assert result["blocked"] == 0
        assert result["errors"] == 0
        assert result["results"] == []

    @patch("vigil.loop.replayer.evaluate")
    def test_single_allow(self, mock_eval, tmp_path: Path) -> None:
        mock_eval.return_value = _make_decision("ALLOW")
        _write_snap(
            tmp_path, "snap1",
            [
                {"role": "system", "content": "sys"},
                {"role": "user", "content": "attack"},
                {"role": "assistant", "content": "safe response"},
            ],
        )
        runner = VigilBreakPointRunner()
        result = runner.run_regression_suite(tmp_path, "system prompt")
        assert result["total"] == 1
        assert result["allowed"] == 1
        assert result["blocked"] == 0
        assert result["warned"] == 0

    @patch("vigil.loop.replayer.evaluate")
    def test_single_block(self, mock_eval, tmp_path: Path) -> None:
        mock_eval.return_value = _make_decision("BLOCK", ["PII_BLOCK_EMAIL"])
        _write_snap(
            tmp_path, "snap1",
            [{"role": "assistant", "content": "leaked: api_canari_abc"}],
        )
        runner = VigilBreakPointRunner()
        result = runner.run_regression_suite(tmp_path, "safe baseline")
        assert result["blocked"] == 1
        assert result["results"][0]["reason_codes"] == ["PII_BLOCK_EMAIL"]

    @patch("vigil.loop.replayer.evaluate")
    def test_mixed_verdicts(self, mock_eval, tmp_path: Path) -> None:
        mock_eval.side_effect = [
            _make_decision("ALLOW"),
            _make_decision("BLOCK"),
            _make_decision("WARN"),
        ]
        for name in ["s1", "s2", "s3"]:
            _write_snap(
                tmp_path, name,
                [{"role": "assistant", "content": f"output-{name}"}],
            )
        runner = VigilBreakPointRunner()
        result = runner.run_regression_suite(tmp_path, "prompt")
        assert result["total"] == 3
        assert result["allowed"] == 1
        assert result["blocked"] == 1
        assert result["warned"] == 1

    def test_corrupt_file_counted_as_error(self, tmp_path: Path) -> None:
        bad = tmp_path / "corrupt.bp.json"
        bad.write_text("not valid json", encoding="utf-8")
        runner = VigilBreakPointRunner()
        result = runner.run_regression_suite(tmp_path, "prompt")
        assert result["errors"] == 1
        assert result["total"] == 1
        assert result["allowed"] == 0

    @patch("vigil.loop.replayer.evaluate")
    def test_evaluate_called_in_full_mode(self, mock_eval, tmp_path: Path) -> None:
        mock_eval.return_value = _make_decision("ALLOW")
        _write_snap(
            tmp_path, "s1",
            [{"role": "assistant", "content": "response"}],
        )
        runner = VigilBreakPointRunner()
        runner.run_regression_suite(tmp_path, "prompt")
        call_kwargs = mock_eval.call_args.kwargs
        assert call_kwargs.get("mode") == "full"

    @patch("vigil.loop.replayer.evaluate")
    def test_result_contains_file_and_snapshot_id(self, mock_eval, tmp_path: Path) -> None:
        mock_eval.return_value = _make_decision("ALLOW")
        _write_snap(
            tmp_path, "my-snap",
            [{"role": "assistant", "content": "response"}],
        )
        runner = VigilBreakPointRunner()
        result = runner.run_regression_suite(tmp_path, "prompt")
        r = result["results"][0]
        assert r["file"] == "my-snap.bp.json"
        assert r["snapshot_id"] == "my-snap"
        assert r["status"] == "ALLOW"

    @patch("vigil.loop.replayer.evaluate")
    def test_baseline_from_breakpoint_test_used(self, mock_eval, tmp_path: Path) -> None:
        mock_eval.return_value = _make_decision("ALLOW")
        _write_snap(
            tmp_path, "s1",
            [{"role": "assistant", "content": "response"}],
            bp_baseline_output="Safe rejection response.",
        )
        runner = VigilBreakPointRunner()
        runner.run_regression_suite(tmp_path, "fallback prompt")
        call_kwargs = mock_eval.call_args.kwargs
        assert call_kwargs["baseline"]["output"] == "Safe rejection response."
