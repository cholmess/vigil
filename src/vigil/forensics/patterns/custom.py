"""Tier 4 — user-defined custom patterns loaded from .vigil.yml or JSON pack."""

from __future__ import annotations

import json
import re
from pathlib import Path

from vigil.forensics.patterns.canari_tokens import DetectionPattern


def load_custom_patterns(path: str | Path) -> list[DetectionPattern]:
    """Load a pattern pack from a JSON file.

    Expected format::

        {
          "patterns": [
            {
              "pattern_id": "my_secret",
              "name": "My secret token",
              "severity": "HIGH",
              "confidence": "HIGH",
              "kind": "real_credential_leak",
              "regex": "MY_SECRET_[A-Z0-9]+"
            }
          ]
        }
    """
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    raw_patterns = payload.get("patterns", payload)
    out: list[DetectionPattern] = []
    for item in raw_patterns:
        out.append(
            DetectionPattern(
                pattern_id=str(item["pattern_id"]),
                name=str(item["name"]),
                severity=str(item["severity"]),
                confidence=str(item["confidence"]),
                kind=str(item["kind"]),
                regex=re.compile(str(item["regex"])),
            )
        )
    return out


def load_patterns_from_config(config: dict) -> list[DetectionPattern]:
    """Load custom patterns from a .vigil.yml forensics config block."""
    custom_patterns_file = (config.get("forensics") or {}).get("custom_patterns")
    if not custom_patterns_file:
        return []
    return load_custom_patterns(custom_patterns_file)
