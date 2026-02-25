"""Tier 1 patterns — Vigil/Canari canary token formats (exact match, zero false positives)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern


@dataclass(frozen=True)
class DetectionPattern:
    pattern_id: str
    name: str
    severity: str
    confidence: str
    kind: str
    regex: Pattern[str]


CANARI_TOKEN_PATTERNS: list[DetectionPattern] = [
    DetectionPattern(
        pattern_id="canari_stripe_test",
        name="Canari stripe test canary token",
        severity="HIGH",
        confidence="HIGH",
        kind="canary_token_leak",
        regex=re.compile(r"\bsk_test_CANARI_[a-z0-9]+\b"),
    ),
    DetectionPattern(
        pattern_id="canari_api_key",
        name="Canari API key canary token",
        severity="HIGH",
        confidence="HIGH",
        kind="canary_token_leak",
        regex=re.compile(r"\bapi_canari_[a-z0-9]+\b"),
    ),
    DetectionPattern(
        pattern_id="canari_document_id",
        name="Canari document ID canary token",
        severity="MEDIUM",
        confidence="HIGH",
        kind="canary_token_leak",
        regex=re.compile(r"\bDOC-CANARI-[A-Z0-9]+\b"),
    ),
    DetectionPattern(
        pattern_id="canari_email",
        name="Canari email canary token",
        severity="MEDIUM",
        confidence="HIGH",
        kind="canary_token_leak",
        regex=re.compile(r"\bcanari-canary-[a-f0-9-]+@sandbox\.invalid\b"),
    ),
    DetectionPattern(
        pattern_id="canari_github_token",
        name="Canari GitHub token canary",
        severity="HIGH",
        confidence="HIGH",
        kind="canary_token_leak",
        regex=re.compile(r"\bghp_[a-z0-9]{36,}\b"),
    ),
]
