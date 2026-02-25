"""Pattern library for forensic scanning — Tier 1 through Tier 4."""

from vigil.forensics.patterns.canari_tokens import CANARI_TOKEN_PATTERNS
from vigil.forensics.patterns.credentials import CREDENTIAL_PATTERNS
from vigil.forensics.patterns.custom import load_custom_patterns
from vigil.forensics.patterns.pii import PII_PATTERNS

# All built-in patterns combined, ordered by priority (Tier 1 → 4)
PATTERNS = CANARI_TOKEN_PATTERNS + CREDENTIAL_PATTERNS + PII_PATTERNS

__all__ = [
    "CANARI_TOKEN_PATTERNS",
    "CREDENTIAL_PATTERNS",
    "PII_PATTERNS",
    "PATTERNS",
    "load_custom_patterns",
]
