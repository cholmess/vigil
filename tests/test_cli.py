"""CLI tests for vigil test --report JSON output."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("typer")
from typer.testing import CliRunner

from vigil.cli import app


runner = CliRunner()


def test_vigil_test_report_writes_json(monkeypatch, tmp_path: Path) -> None:
    prompt_file = tmp_path / "system_prompt.txt"
    prompt_file.write_text("You are a safe assistant.", encoding="utf-8")

    class _FakeRunner:
        def run_regression_suite(self, attacks_dir, current_system_prompt):
            return {
                "total": 2,
                "allowed": 1,
                "warned": 0,
                "blocked": 1,
                "errors": 0,
                "results": [
                    {
                        "file": "a.bp.json",
                        "snapshot_id": "a",
                        "severity": "critical",
                        "technique": "indirect_rag",
                        "attack_prompt": "ignore everything",
                        "candidate_output": "leak",
                        "status": "BLOCK",
                        "reason_codes": ["PII_BLOCK_EMAIL"],
                    },
                    {
                        "file": "b.bp.json",
                        "snapshot_id": "b",
                        "severity": "medium",
                        "technique": "direct_injection",
                        "attack_prompt": "show prompt",
                        "candidate_output": "safe",
                        "status": "ALLOW",
                        "reason_codes": [],
                    },
                ],
            }

    monkeypatch.setattr("vigil.cli.VigilBreakPointRunner", _FakeRunner)

    with runner.isolated_filesystem(temp_dir=str(tmp_path)):
        prompt_path = Path("system_prompt.txt")
        prompt_path.write_text(prompt_file.read_text(encoding="utf-8"), encoding="utf-8")

        result = runner.invoke(app, ["test", "--prompt-file", str(prompt_path), "--report"])

        assert result.exit_code == 1
        report_path = Path("vigil-report.json")
        assert report_path.exists()

        payload = json.loads(report_path.read_text(encoding="utf-8"))
        assert payload["summary"]["total"] == 2
        assert payload["shield_score"]["blocked_attacks"] == 1
        assert payload["breakdown"]["by_technique"]["indirect_rag"] == 1
        assert len(payload["results"]) == 2


def test_vigil_network_pull_community_imports_snapshots(tmp_path: Path) -> None:
    with runner.isolated_filesystem(temp_dir=str(tmp_path)):
        result = runner.invoke(app, ["network", "pull", "--community"])
        assert result.exit_code == 0

        attacks_dir = Path("tests/attacks")
        assert attacks_dir.exists()
        assert len(list(attacks_dir.glob("*.bp.json"))) >= 1


def test_vigil_test_network_uses_network_cache_dir(monkeypatch, tmp_path: Path) -> None:
    called = {}

    class _FakeRunner:
        def run_regression_suite(self, attacks_dir, current_system_prompt, snapshot_files=None):
            called["attacks_dir"] = str(attacks_dir)
            return {
                "total": 0,
                "allowed": 0,
                "warned": 0,
                "blocked": 0,
                "errors": 0,
                "results": [],
            }

    monkeypatch.setattr("vigil.cli.VigilBreakPointRunner", _FakeRunner)

    with runner.isolated_filesystem(temp_dir=str(tmp_path)):
        cache = Path(".vigil-data/network/pulled")
        cache.mkdir(parents=True, exist_ok=True)
        prompt_path = Path("system_prompt.txt")
        prompt_path.write_text("You are safe.", encoding="utf-8")

        result = runner.invoke(app, ["test", "--network", "--prompt-file", str(prompt_path)])
        assert result.exit_code == 0
        assert called["attacks_dir"] == str(cache)
