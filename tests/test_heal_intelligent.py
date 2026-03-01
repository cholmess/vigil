"""Tests for intelligent heal helpers."""

from __future__ import annotations

from vigil.loop.heal_intelligent import (
    estimate_shield_score_after_changes,
    rank_suggestions_with_profile,
)


def test_rank_suggestions_with_profile_orders_by_probability_then_severity() -> None:
    suggestions = [
        {"technique": "jailbreak", "severity": "high", "file": "a", "suggestion": "s1"},
        {"technique": "indirect_rag", "severity": "medium", "file": "b", "suggestion": "s2"},
        {"technique": "jailbreak", "severity": "critical", "file": "c", "suggestion": "s3"},
    ]
    profile = {
        "techniques": {
            "jailbreak": {"probability": 0.8},
            "indirect_rag": {"probability": 0.6},
        }
    }
    ranked = rank_suggestions_with_profile(suggestions, profile)
    assert ranked[0]["file"] == "c"  # same technique, higher severity first
    assert ranked[1]["file"] == "a"
    assert ranked[2]["file"] == "b"


def test_estimate_shield_score_after_changes_increases_score() -> None:
    ranked = [
        {"technique": "jailbreak", "severity": "high"},
        {"technique": "indirect_rag", "severity": "critical"},
    ]
    profile = {
        "techniques": {
            "jailbreak": {"probability": 0.8},
            "indirect_rag": {"probability": 0.7},
        }
    }
    before, after = estimate_shield_score_after_changes(
        total=10,
        allowed=6,
        ranked_suggestions=ranked,
        scorer_report=profile,
    )
    assert before == 0.6
    assert after > before
