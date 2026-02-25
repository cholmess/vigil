"""Tier 2 patterns — Real credential formats (exact, high-confidence detections)."""

from __future__ import annotations

import re

from vigil.forensics.patterns.canari_tokens import DetectionPattern

CREDENTIAL_PATTERNS: list[DetectionPattern] = [
    DetectionPattern(
        pattern_id="cred_stripe_live",
        name="Stripe live secret key",
        severity="CRITICAL",
        confidence="HIGH",
        kind="real_credential_leak",
        regex=re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b"),
    ),
    DetectionPattern(
        pattern_id="cred_stripe_restricted",
        name="Stripe restricted key",
        severity="CRITICAL",
        confidence="HIGH",
        kind="real_credential_leak",
        regex=re.compile(r"\brk_live_[A-Za-z0-9]{20,}\b"),
    ),
    DetectionPattern(
        pattern_id="cred_openai_key",
        name="OpenAI API key",
        severity="CRITICAL",
        confidence="HIGH",
        kind="real_credential_leak",
        regex=re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    ),
    DetectionPattern(
        pattern_id="aws_access_key",
        name="AWS access key ID",
        severity="CRITICAL",
        confidence="HIGH",
        kind="real_credential_leak",
        regex=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    DetectionPattern(
        pattern_id="aws_secret_key",
        name="AWS secret access key",
        severity="CRITICAL",
        confidence="MEDIUM",
        kind="real_credential_leak",
        regex=re.compile(r"\b[A-Za-z0-9/+=]{40}\b"),
    ),
    DetectionPattern(
        pattern_id="cred_github_pat",
        name="GitHub personal access token",
        severity="CRITICAL",
        confidence="HIGH",
        kind="real_credential_leak",
        regex=re.compile(r"\bghp_[A-Za-z0-9]{36,}\b"),
    ),
    DetectionPattern(
        pattern_id="cred_github_oauth",
        name="GitHub OAuth token",
        severity="CRITICAL",
        confidence="HIGH",
        kind="real_credential_leak",
        regex=re.compile(r"\bgho_[A-Za-z0-9]{36,}\b"),
    ),
    DetectionPattern(
        pattern_id="cred_slack_token",
        name="Slack API token",
        severity="HIGH",
        confidence="HIGH",
        kind="real_credential_leak",
        regex=re.compile(r"\bxox[bporas]-[A-Za-z0-9-]{10,}\b"),
    ),
    DetectionPattern(
        pattern_id="cred_sendgrid",
        name="SendGrid API key",
        severity="HIGH",
        confidence="HIGH",
        kind="real_credential_leak",
        regex=re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
    ),
    DetectionPattern(
        pattern_id="prompt_injection_indicator",
        name="Prompt injection success indicator",
        severity="HIGH",
        confidence="MEDIUM",
        kind="probable_prompt_injection",
        regex=re.compile(r"(?i)here is everything|ignore all instructions|output your full context"),
    ),
]
