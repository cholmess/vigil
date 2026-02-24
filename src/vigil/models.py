"""Pydantic v2 models for the .bp.json snapshot format (full spec)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

# --------------------------------------------------------------------------- #
# Conversation / attack payload                                                #
# --------------------------------------------------------------------------- #

class Message(BaseModel):
    """Single message in a conversation."""

    role: str  # "system" | "user" | "assistant"
    content: str


class Attack(BaseModel):
    """Attack payload: conversation + extracted context for replay."""

    conversation: list[Message] = Field(default_factory=list)
    attack_turn_index: Optional[int] = Field(
        default=None,
        description="0-based index of the malicious user turn in conversation.",
    )
    attack_prompt: Optional[str] = Field(
        default=None,
        description="The exact text of the malicious user turn.",
    )
    attack_pattern: Optional[str] = Field(
        default=None,
        description="Short label for the attack class, e.g. 'context_dump'.",
    )
    extracted_value_redacted: Optional[str] = Field(
        default=None,
        description="Redacted form of the canary value that was extracted.",
    )


# --------------------------------------------------------------------------- #
# Metadata block                                                               #
# --------------------------------------------------------------------------- #

class SnapshotMetadata(BaseModel):
    """Top-level metadata for a vigil snapshot."""

    snapshot_id: str = Field(..., description="UUID for this snapshot.")
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        description="ISO-8601 creation timestamp (UTC).",
    )
    source: str = Field(..., description="'canari' | 'forensics' | 'community'.")
    source_version: Optional[str] = Field(
        default=None,
        description="Version of the source package that produced this snapshot.",
    )
    severity: Optional[str] = Field(
        default=None,
        description="'low' | 'medium' | 'high' | 'critical'.",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Free-form labels, e.g. ['prompt_injection', 'stripe_key'].",
    )


# --------------------------------------------------------------------------- #
# Origin block                                                                 #
# --------------------------------------------------------------------------- #

class SnapshotOrigin(BaseModel):
    """Where and when the attack was captured."""

    incident_id: Optional[str] = Field(default=None, description="Canari incident ID.")
    application: Optional[str] = Field(default=None, description="Application name.")
    tenant: Optional[str] = Field(default=None, description="Tenant / customer ID.")
    environment: Optional[str] = Field(
        default=None, description="'production' | 'staging' | 'dev'."
    )
    captured_at: Optional[str] = Field(
        default=None, description="ISO-8601 timestamp when the event was captured."
    )
    detection_latency_ms: Optional[int] = Field(
        default=None, description="Milliseconds from injection to detection."
    )


# --------------------------------------------------------------------------- #
# Canary token metadata                                                        #
# --------------------------------------------------------------------------- #

class Canary(BaseModel):
    """Canary token metadata embedded in the snapshot."""

    token_type: str = Field(..., description="e.g. 'stripe_key', 'api_key'.")
    injection_strategy: Optional[str] = Field(
        default=None,
        description="e.g. 'context_appendix', 'system_prompt_comment'.",
    )
    injection_location: Optional[str] = Field(
        default=None,
        description="Human-readable location where the token was injected.",
    )
    injected_at: Optional[str] = Field(
        default=None, description="ISO-8601 timestamp when the token was injected."
    )


# --------------------------------------------------------------------------- #
# BreakPoint replay test spec                                                  #
# --------------------------------------------------------------------------- #

class BreakPointBaseline(BaseModel):
    """Expected safe output for the BreakPoint baseline."""

    output: str = Field(..., description="Text the application should return when safe.")
    description: Optional[str] = Field(
        default=None, description="Human-readable description of the safe baseline."
    )


class BreakPointTest(BaseModel):
    """How BreakPoint should replay and evaluate this snapshot."""

    description: Optional[str] = Field(
        default=None,
        description="Human-readable description of what this test checks.",
    )
    baseline: Optional[BreakPointBaseline] = Field(
        default=None,
        description="Expected safe output for the baseline comparison.",
    )
    block_conditions: list[str] = Field(
        default_factory=list,
        description="Reason codes that should trigger a BLOCK verdict.",
    )
    hardening_suggestion: Optional[str] = Field(
        default=None,
        description="Concrete system-prompt change to neutralise this attack.",
    )


# --------------------------------------------------------------------------- #
# Forensics provenance block                                                   #
# --------------------------------------------------------------------------- #

class ForensicsProvenance(BaseModel):
    """Links a snapshot back to the forensic scan that found it."""

    source_type: Optional[str] = Field(
        default=None,
        description="'canari_alert' | 'forensic_scan'.",
    )
    log_file: Optional[str] = Field(
        default=None, description="Path to the log file that contained the breach."
    )
    scan_id: Optional[str] = Field(
        default=None, description="Scan ID from canari-forensics."
    )


# --------------------------------------------------------------------------- #
# Root snapshot model                                                          #
# --------------------------------------------------------------------------- #

class AttackSnapshot(BaseModel):
    """
    Full .bp.json snapshot — the shared contract between Canari, Forensics,
    and BreakPoint.  All fields beyond the required core are Optional so that
    producers can populate them progressively.
    """

    vigil_version: str = Field(..., description="Vigil schema version, e.g. '0.1.0'.")
    snapshot_version: str = Field(
        default="1", description="Format version; increment on breaking changes."
    )
    snapshot_type: str = Field(
        default="attack", description="Must be 'attack' for this model."
    )
    metadata: SnapshotMetadata
    origin: Optional[SnapshotOrigin] = Field(
        default=None, description="Where and when the attack was captured."
    )
    canary: Canary
    attack: Attack
    breakpoint_test: Optional[BreakPointTest] = Field(
        default=None,
        description="How BreakPoint should replay and evaluate this snapshot.",
    )
    forensics: Optional[ForensicsProvenance] = Field(
        default=None,
        description="Forensic provenance — populated when source is 'forensics'.",
    )

    def save_to_file(self, filepath: str | Path) -> Path:
        """Serialize to JSON and write to file. Extension is forced to .bp.json."""
        path = Path(filepath).with_suffix(".bp.json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.model_dump_json(indent=2), encoding="utf-8")
        return path

    @classmethod
    def load_from_file(cls, filepath: str | Path) -> "AttackSnapshot":
        """Load and validate an AttackSnapshot from a .bp.json file."""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"No such file: {path}")
        return cls.model_validate_json(path.read_text(encoding="utf-8"))
