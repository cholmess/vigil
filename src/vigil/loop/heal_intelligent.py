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
    """Sort suggestions by risk profile (technique/class/framework) then severity."""
    techniques = scorer_report.get("techniques", {})
    classes = scorer_report.get("classes", {})
    frameworks = scorer_report.get("frameworks", {})

    def key(item: dict[str, str]) -> tuple[float, int]:
        technique = item.get("technique", "unknown")
        attack_class = item.get("attack_class", "unknown")
        framework = item.get("framework", "unknown")
        t_prob = float(techniques.get(technique, {}).get("probability", 0.0))
        c_prob = float(classes.get(attack_class, {}).get("probability", 0.0))
        f_prob = float(frameworks.get(framework, {}).get("probability", 0.0))
        probability = (0.7 * t_prob) + (0.2 * c_prob) + (0.1 * f_prob)
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
    classes = scorer_report.get("classes", {})
    frameworks = scorer_report.get("frameworks", {})
    bonus = 0.0
    seen: set[tuple[str, str, str]] = set()
    for item in ranked_suggestions[:3]:
        technique = item.get("technique", "unknown")
        attack_class = item.get("attack_class", "unknown")
        framework = item.get("framework", "unknown")
        marker = (technique, attack_class, framework)
        if marker in seen:
            continue
        seen.add(marker)
        t_prob = float(techniques.get(technique, {}).get("probability", 0.0))
        c_prob = float(classes.get(attack_class, {}).get("probability", 0.0))
        f_prob = float(frameworks.get(framework, {}).get("probability", 0.0))
        # Higher-risk techniques contribute a larger expected gain when fixed.
        bonus += 0.04 + (0.10 * t_prob) + (0.05 * c_prob) + (0.03 * f_prob)

    after = min(0.99, before + bonus)
    return before, after
