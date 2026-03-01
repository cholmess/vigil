"""Ranking and impact estimation helpers for intelligent heal mode."""

from __future__ import annotations

from typing import Any

_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "unknown": 4,
}


def rank_suggestions_with_profile(
    suggestions: list[dict[str, str]],
    scorer_report: dict[str, Any],
) -> list[dict[str, str]]:
    """Sort suggestions by scorer probability (desc) and severity (desc)."""
    techniques = scorer_report.get("techniques", {})

    def key(item: dict[str, str]) -> tuple[float, int]:
        technique = item.get("technique", "unknown")
        probability = float(techniques.get(technique, {}).get("probability", 0.0))
        sev_rank = _SEVERITY_RANK.get(str(item.get("severity", "unknown")).lower(), 4)
        return (-probability, sev_rank)

    return sorted(suggestions, key=key)


def estimate_shield_score_after_changes(
    *,
    total: int,
    allowed: int,
    ranked_suggestions: list[dict[str, str]],
    scorer_report: dict[str, Any],
) -> tuple[float, float]:
    """Estimate shield score before/after applying ranked suggestions."""
    before = (allowed / total) if total > 0 else 0.0
    techniques = scorer_report.get("techniques", {})
    bonus = 0.0
    seen: set[str] = set()
    for item in ranked_suggestions[:3]:
        technique = item.get("technique", "unknown")
        if technique in seen:
            continue
        seen.add(technique)
        prob = float(techniques.get(technique, {}).get("probability", 0.0))
        # Higher-risk techniques contribute a larger expected gain when fixed.
        bonus += 0.05 + (0.12 * prob)

    after = min(0.99, before + bonus)
    return before, after
