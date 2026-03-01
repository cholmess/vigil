"""Tests for intelligent heal helpers."""

from __future__ import annotations

from vigil.loop.heal_intelligent import (
    estimate_shield_score_after_changes,
    rank_suggestions_with_profile,
)


def test_rank_suggestions_with_profile_orders_by_probability_then_severity() -> None:
    suggestions = [
        {"technique": "jailbreak", "attack_class": "c1", "framework": "f1", "severity": "high", "file": "a", "suggestion": "s1"},
        {"technique": "indirect_rag", "attack_class": "c2", "framework": "f2", "severity": "medium", "file": "b", "suggestion": "s2"},
        {"technique": "jailbreak", "attack_class": "c1", "framework": "f1", "severity": "critical", "file": "c", "suggestion": "s3"},
    ]
    profile = {
        "techniques": {
            "jailbreak": {"probability": 0.8},
            "indirect_rag": {"probability": 0.6},
        },
        "classes": {"c1": {"probability": 0.7}, "c2": {"probability": 0.2}},
        "frameworks": {"f1": {"probability": 0.6}, "f2": {"probability": 0.2}},
    }
    ranked = rank_suggestions_with_profile(suggestions, profile)
    assert ranked[0]["file"] == "c"  # same technique, higher severity first
    assert ranked[1]["file"] == "a"
    assert ranked[2]["file"] == "b"


def test_estimate_shield_score_after_changes_increases_score() -> None:
    ranked = [
        {"technique": "jailbreak", "attack_class": "c1", "framework": "f1", "severity": "high"},
        {"technique": "indirect_rag", "attack_class": "c2", "framework": "f2", "severity": "critical"},
    ]
    profile = {
        "techniques": {
            "jailbreak": {"probability": 0.8},
            "indirect_rag": {"probability": 0.7},
        },
        "classes": {"c1": {"probability": 0.7}, "c2": {"probability": 0.5}},
        "frameworks": {"f1": {"probability": 0.6}, "f2": {"probability": 0.4}},
    }
    before, after = estimate_shield_score_after_changes(
        total=10,
        allowed=6,
        ranked_suggestions=ranked,
        scorer_report=profile,
    )
    assert before == 0.6
    assert after > before
