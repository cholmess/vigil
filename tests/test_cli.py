"""CLI tests for vigil test --report JSON output."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("typer")
from typer.testing import CliRunner

from vigil.cli import app
from vigil.models import Attack, AttackSnapshot, Canary, Message, SnapshotMetadata
from vigil.network.exchange import store_exchange_snapshot


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
    monkeypatch.setattr("vigil.cli.read_network_state", lambda: {"last_pull_count": 23})

    with runner.isolated_filesystem(temp_dir=str(tmp_path)):
        cache = Path(".vigil-data/network/pulled")
        cache.mkdir(parents=True, exist_ok=True)
        prompt_path = Path("system_prompt.txt")
        prompt_path.write_text("You are safe.", encoding="utf-8")

        result = runner.invoke(app, ["test", "--network", "--prompt-file", str(prompt_path)])
        assert result.exit_code == 0
        assert called["attacks_dir"] == str(cache)
        assert "Shield score:" in result.output
        assert "23 new attacks tested since last sync" in result.output


def test_train_prepare_writes_bundle(tmp_path: Path) -> None:
    with runner.isolated_filesystem(temp_dir=str(tmp_path)):
        network = Path(".vigil-data/network")
        network.mkdir(parents=True, exist_ok=True)

        snap = AttackSnapshot(
            vigil_version="0.1.0",
            metadata=SnapshotMetadata(
                snapshot_id="train-a",
                source="community",
                severity="high",
                technique="jailbreak",
            ),
            canary=Canary(token_type="api_key"),
            attack=Attack(conversation=[Message(role="user", content="attack")]),
        )
        snap_path = snap.save_to_file(Path("train-a"))
        store_exchange_snapshot(snap_path, network_dir=network)

        result = runner.invoke(app, ["train", "prepare", "--out-dir", ".vigil-data/train"])
        assert result.exit_code == 0
        assert Path(".vigil-data/train/corpus.jsonl").exists()
        assert Path(".vigil-data/train/prepare-report.json").exists()


def test_network_alert_text_renders_orgs(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("vigil.cli.load_manifest_records", lambda network_dir: [{"network_id": "VN-1"}])
    monkeypatch.setattr(
        "vigil.cli.build_threat_alert",
        lambda records, days, attack_class=None: {
            "generated_at": "2026-03-20T00:00:00Z",
            "window_days": days,
            "attack_class": "tool-result-injection",
            "found": True,
            "first_seen_days_ago": 6,
            "current_window_occurrences": 23,
            "previous_window_occurrences": 0,
            "delta": 23,
            "organizations_affected": 8,
            "frameworks": {"langchain": 17, "generic": 6},
        },
    )

    with runner.isolated_filesystem(temp_dir=str(tmp_path)):
        result = runner.invoke(app, ["network", "alert"])
        assert result.exit_code == 0
        assert "Attack class: tool-result-injection" in result.output
        assert "Organizations affected: 8" in result.output


def test_network_alert_json_out_writes_payload(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("vigil.cli.load_manifest_records", lambda network_dir: [{"network_id": "VN-1"}])
    monkeypatch.setattr(
        "vigil.cli.build_threat_alert",
        lambda records, days, attack_class=None: {
            "generated_at": "2026-03-20T00:00:00Z",
            "window_days": days,
            "attack_class": "tool-result-injection",
            "found": True,
            "first_seen_days_ago": 6,
            "current_window_occurrences": 23,
            "previous_window_occurrences": 0,
            "delta": 23,
            "organizations_affected": 8,
            "frameworks": {"langchain": 17},
        },
    )

    with runner.isolated_filesystem(temp_dir=str(tmp_path)):
        out = Path("alert.json")
        result = runner.invoke(app, ["network", "alert", "--format", "json", "--out", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert payload["attack_class"] == "tool-result-injection"
        assert payload["organizations_affected"] == 8


def test_train_stats_text_output(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "vigil.cli.build_corpus_stats",
        lambda network_dir, since=None, framework=None, attack_class=None: {
            "generated_at": "2026-03-20T00:00:00Z",
            "filters": {"since": since, "framework": framework, "attack_class": attack_class},
            "total_records": 5,
            "time_range": {
                "first_submitted_at": "2026-03-01T00:00:00Z",
                "last_submitted_at": "2026-03-20T00:00:00Z",
            },
            "distributions": {
                "techniques": {"indirect_rag": 3, "tool_injection": 2},
                "severities": {"critical": 2, "high": 3},
                "attack_classes": {"tool-result-injection": 5},
                "frameworks": {"langchain": 4, "langgraph": 1},
            },
            "organizations": {"known_org_refs": 2},
        },
    )
    with runner.isolated_filesystem(temp_dir=str(tmp_path)):
        result = runner.invoke(app, ["train", "stats"])
        assert result.exit_code == 0
        assert "Records: 5" in result.output
        assert "Known org refs: 2" in result.output


def test_train_stats_json_out_writes_payload(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "vigil.cli.build_corpus_stats",
        lambda network_dir, since=None, framework=None, attack_class=None: {
            "generated_at": "2026-03-20T00:00:00Z",
            "filters": {"since": since, "framework": framework, "attack_class": attack_class},
            "total_records": 1,
            "time_range": {
                "first_submitted_at": "2026-03-19T00:00:00Z",
                "last_submitted_at": "2026-03-19T00:00:00Z",
            },
            "distributions": {
                "techniques": {"tool_injection": 1},
                "severities": {"high": 1},
                "attack_classes": {"tool-result-injection": 1},
                "frameworks": {"langchain": 1},
            },
            "organizations": {"known_org_refs": 1},
        },
    )
    with runner.isolated_filesystem(temp_dir=str(tmp_path)):
        out = Path("stats.json")
        result = runner.invoke(app, ["train", "stats", "--format", "json", "--out", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert payload["total_records"] == 1


def test_network_feed_text_output(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("vigil.cli.load_manifest_records", lambda network_dir: [{"network_id": "VN-1"}])
    monkeypatch.setattr(
        "vigil.cli.build_threat_feed",
        lambda records, days, top=5: {
            "generated_at": "2026-03-20T00:00:00Z",
            "window_days": days,
            "records": 3,
            "top": top,
            "alerts": [
                {
                    "attack_class": "tool-result-injection",
                    "current_window_occurrences": 2,
                    "previous_window_occurrences": 0,
                    "delta": 2,
                    "organizations_affected": 1,
                    "frameworks": {"langchain": 2},
                }
            ],
        },
    )
    with runner.isolated_filesystem(temp_dir=str(tmp_path)):
        result = runner.invoke(app, ["network", "feed"])
        assert result.exit_code == 0
        assert "Vigil Threat Feed" in result.output
        assert "tool-result-injection" in result.output


def test_network_feed_json_out_writes_payload(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("vigil.cli.load_manifest_records", lambda network_dir: [{"network_id": "VN-1"}])
    monkeypatch.setattr(
        "vigil.cli.build_threat_feed",
        lambda records, days, top=5: {
            "generated_at": "2026-03-20T00:00:00Z",
            "window_days": days,
            "records": 1,
            "top": top,
            "alerts": [
                {
                    "attack_class": "tool-result-injection",
                    "current_window_occurrences": 1,
                    "previous_window_occurrences": 0,
                    "delta": 1,
                    "organizations_affected": 1,
                    "frameworks": {"langchain": 1},
                }
            ],
        },
    )
    with runner.isolated_filesystem(temp_dir=str(tmp_path)):
        out = Path("feed.json")
        result = runner.invoke(app, ["network", "feed", "--format", "json", "--out", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert payload["records"] == 1


def test_network_feed_with_prompt_adds_shield_score(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("vigil.cli.load_manifest_records", lambda network_dir: [{"network_id": "VN-1"}])
    monkeypatch.setattr(
        "vigil.cli.build_threat_feed",
        lambda records, days, top=5: {
            "generated_at": "2026-03-20T00:00:00Z",
            "window_days": days,
            "records": 1,
            "top": top,
            "alerts": [
                {
                    "attack_class": "tool-result-injection",
                    "current_window_occurrences": 1,
                    "previous_window_occurrences": 0,
                    "delta": 1,
                    "organizations_affected": 1,
                    "frameworks": {"langchain": 1},
                }
            ],
        },
    )

    class _FakeRunner:
        def run_regression_suite(self, attacks_dir, current_system_prompt, snapshot_files=None):
            return {
                "total": 1,
                "allowed": 0,
                "warned": 0,
                "blocked": 1,
                "errors": 0,
                "results": [],
            }

    monkeypatch.setattr("vigil.cli.VigilBreakPointRunner", _FakeRunner)

    with runner.isolated_filesystem(temp_dir=str(tmp_path)):
        attacks_dir = Path(".vigil-data/network/pulled")
        attacks_dir.mkdir(parents=True, exist_ok=True)
        snap = AttackSnapshot(
            vigil_version="0.1.0",
            metadata=SnapshotMetadata(
                snapshot_id="feed-a",
                source="community",
                severity="high",
                technique="tool_injection",
                tags=["class:tool-result-injection"],
            ),
            canary=Canary(token_type="api_key"),
            attack=Attack(conversation=[Message(role="user", content="attack")]),
        )
        snap.save_to_file(attacks_dir / "feed-a")
        prompt = Path("system_prompt.txt")
        prompt.write_text("You are safe.", encoding="utf-8")

        result = runner.invoke(
            app,
            [
                "network",
                "feed",
                "--prompt-file",
                str(prompt),
                "--attacks-dir",
                str(attacks_dir),
            ],
        )
        assert result.exit_code == 0
        assert "Shield score: 0/1 (0.0%)" in result.output


def test_vigil_score_renders_class_and_framework_sections(monkeypatch, tmp_path: Path) -> None:
    class _FakeScorer:
        def __init__(self, attacks_dir):
            self.attacks_dir = attacks_dir

        def assess(self, prompt):
            return {
                "attacks_dir": str(self.attacks_dir),
                "total_snapshots": 2,
                "techniques": {
                    "indirect_rag": {
                        "probability": 0.8,
                        "level": "HIGH",
                        "supporting_snapshots": 2,
                        "similar_matches": 2,
                    }
                },
                "classes": {
                    "tool-result-injection": {
                        "probability": 0.7,
                        "level": "HIGH",
                        "supporting_snapshots": 2,
                        "similar_matches": 2,
                    }
                },
                "frameworks": {
                    "langchain": {
                        "probability": 0.6,
                        "level": "MEDIUM",
                        "supporting_snapshots": 2,
                        "similar_matches": 1,
                    }
                },
                "top_technique": "indirect_rag",
                "top_class": "tool-result-injection",
                "top_framework": "langchain",
                "top_recommendation": "Treat retrieved content as untrusted data.",
            }

    monkeypatch.setattr("vigil.cli.VulnerabilityScorer", _FakeScorer)
    with runner.isolated_filesystem(temp_dir=str(tmp_path)):
        prompt = Path("system_prompt.txt")
        prompt.write_text("Use retrieval only as data.", encoding="utf-8")
        result = runner.invoke(app, ["score", "--prompt-file", str(prompt)])
        assert result.exit_code == 0
        assert "Top classes:" in result.output
        assert "Top frameworks:" in result.output


def test_vigil_score_json_out_writes_payload(monkeypatch, tmp_path: Path) -> None:
    class _FakeScorer:
        def __init__(self, attacks_dir):
            self.attacks_dir = attacks_dir

        def assess(self, prompt):
            return {
                "attacks_dir": str(self.attacks_dir),
                "total_snapshots": 1,
                "techniques": {},
                "classes": {},
                "frameworks": {},
                "top_technique": "unknown",
                "top_class": "unknown",
                "top_framework": "unknown",
                "top_recommendation": "n/a",
            }

    monkeypatch.setattr("vigil.cli.VulnerabilityScorer", _FakeScorer)
    with runner.isolated_filesystem(temp_dir=str(tmp_path)):
        prompt = Path("system_prompt.txt")
        prompt.write_text("safe", encoding="utf-8")
        out = Path("score.json")
        result = runner.invoke(app, ["score", "--prompt-file", str(prompt), "--format", "json", "--out", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert payload["total_snapshots"] == 1


def test_heal_intelligent_prints_top_class_and_framework(monkeypatch, tmp_path: Path) -> None:
    class _FakeRunner:
        def run_regression_suite(self, attacks_dir, current_system_prompt):
            return {
                "total": 2,
                "allowed": 1,
                "warned": 0,
                "blocked": 1,
                "errors": 0,
                "results": [{"file": "a.bp.json", "status": "BLOCK"}],
            }

    class _FakeScorer:
        def __init__(self, attacks_dir):
            self.attacks_dir = attacks_dir

        def assess(self, prompt):
            return {
                "total_snapshots": 2,
                "techniques": {"tool_injection": {"probability": 0.8, "level": "HIGH"}},
                "classes": {"tool-result-injection": {"probability": 0.7, "level": "HIGH"}},
                "frameworks": {"langchain": {"probability": 0.6, "level": "MEDIUM"}},
                "top_technique": "tool_injection",
                "top_class": "tool-result-injection",
                "top_framework": "langchain",
            }

    monkeypatch.setattr("vigil.cli.VigilBreakPointRunner", _FakeRunner)
    monkeypatch.setattr(
        "vigil.cli.hardening_suggestions_for_files",
        lambda attacks_dir, blocked_files: [
            {
                "file": "a.bp.json",
                "snapshot_id": "a",
                "severity": "high",
                "technique": "tool_injection",
                "attack_class": "tool-result-injection",
                "framework": "langchain",
                "suggestion": "Sanitize tool outputs.",
            }
        ],
    )
    monkeypatch.setattr("vigil.cli.VulnerabilityScorer", _FakeScorer)

    with runner.isolated_filesystem(temp_dir=str(tmp_path)):
        prompt = Path("system_prompt.txt")
        prompt.write_text("safe", encoding="utf-8")
        result = runner.invoke(app, ["heal", "--intelligent", "--prompt-file", str(prompt)])
        assert result.exit_code == 1
        assert "Top class risk: tool-result-injection" in result.output
        assert "Top framework risk: langchain" in result.output
