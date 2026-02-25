"""Tier 3 patterns — PII detection (credit cards, SSN, email, phone)."""

from __future__ import annotations

import re

from vigil.forensics.patterns.canari_tokens import DetectionPattern

PII_PATTERNS: list[DetectionPattern] = [
    DetectionPattern(
        pattern_id="pii_credit_card",
        name="Credit card number (Luhn-validated in scanner)",
        severity="HIGH",
        confidence="MEDIUM",
        kind="pii_leak",
        regex=re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    ),
    DetectionPattern(
        pattern_id="pii_ssn",
        name="US Social Security Number",
        severity="HIGH",
        confidence="HIGH",
        kind="pii_leak",
        regex=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    ),
    DetectionPattern(
        pattern_id="pii_email",
        name="Email address",
        severity="MEDIUM",
        confidence="HIGH",
        kind="pii_leak",
        regex=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    DetectionPattern(
        pattern_id="pii_phone_us",
        name="US phone number",
        severity="MEDIUM",
        confidence="MEDIUM",
        kind="pii_leak",
        regex=re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b"),
    ),
]
